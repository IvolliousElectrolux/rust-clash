use std::pin::Pin;
use std::task::{Context, Poll};

use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce};
use chacha20poly1305::ChaCha20Poly1305;
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::BoxedStream;
use crate::error::ProxyError;
use crate::reality::hs_err;
use crate::reality::schedule::{HashKind, build_nonce, traffic_keys};

pub const MAX_PLAINTEXT: usize = 16384;
pub const MAX_CIPHERTEXT: usize = MAX_PLAINTEXT + 256;
pub const TAG_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;
const HEADER_LEN: usize = 5;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContentType {
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23,
}

impl ContentType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            20 => Some(Self::ChangeCipherSpec),
            21 => Some(Self::Alert),
            22 => Some(Self::Handshake),
            23 => Some(Self::ApplicationData),
            _ => None,
        }
    }
}

#[derive(Clone, Copy)]
pub struct CipherSuite {
    pub hash: HashKind,
    pub key_len: usize,
    pub chacha: bool,
}

impl CipherSuite {
    pub fn from_id(id: u16) -> Option<Self> {
        match id {
            0x1301 => Some(Self {
                hash: HashKind::Sha256,
                key_len: 16,
                chacha: false,
            }),
            0x1302 => Some(Self {
                hash: HashKind::Sha384,
                key_len: 32,
                chacha: false,
            }),
            0x1303 => Some(Self {
                hash: HashKind::Sha256,
                key_len: 32,
                chacha: true,
            }),
            _ => None,
        }
    }
}

enum Aead {
    Aes128(Aes128Gcm),
    Aes256(Aes256Gcm),
    ChaCha(ChaCha20Poly1305),
}

pub struct RecordProtection {
    iv: [u8; NONCE_LEN],
    aead: Aead,
    seq: u64,
}

impl RecordProtection {
    pub fn new(suite: CipherSuite, traffic: &[u8]) -> Self {
        let mut key = vec![0u8; suite.key_len];
        let mut iv = [0u8; NONCE_LEN];
        traffic_keys(suite.hash, traffic, &mut key, &mut iv);
        let aead = if suite.chacha {
            Aead::ChaCha(ChaCha20Poly1305::new_from_slice(&key).expect("chacha"))
        } else if suite.key_len == 16 {
            Aead::Aes128(Aes128Gcm::new_from_slice(&key).expect("aes128"))
        } else {
            Aead::Aes256(Aes256Gcm::new_from_slice(&key).expect("aes256"))
        };
        Self { iv, aead, seq: 0 }
    }

    pub fn protect(&mut self, plaintext: &[u8], header: &[u8], out: &mut [u8]) {
        let mut nonce = [0u8; NONCE_LEN];
        build_nonce(&mut nonce, &self.iv, self.seq);
        self.seq += 1;
        let mut buf = plaintext.to_vec();
        match &self.aead {
            Aead::Aes128(c) => c
                .encrypt_in_place(Nonce::from_slice(&nonce), header, &mut buf)
                .expect("enc"),
            Aead::Aes256(c) => c
                .encrypt_in_place(Nonce::from_slice(&nonce), header, &mut buf)
                .expect("enc"),
            Aead::ChaCha(c) => c
                .encrypt_in_place(Nonce::from_slice(&nonce), header, &mut buf)
                .expect("enc"),
        }
        out[..buf.len()].copy_from_slice(&buf);
    }

    pub fn unprotect(&mut self, ciphertext_and_tag: &[u8], header: &[u8]) -> Result<Vec<u8>, ProxyError> {
        let mut nonce = [0u8; NONCE_LEN];
        build_nonce(&mut nonce, &self.iv, self.seq);
        self.seq += 1;
        let mut buf = ciphertext_and_tag.to_vec();
        let r = match &self.aead {
            Aead::Aes128(c) => c.decrypt_in_place(Nonce::from_slice(&nonce), header, &mut buf),
            Aead::Aes256(c) => c.decrypt_in_place(Nonce::from_slice(&nonce), header, &mut buf),
            Aead::ChaCha(c) => c.decrypt_in_place(Nonce::from_slice(&nonce), header, &mut buf),
        };
        r.map_err(|_| {
            crate::reality::auth_err(
                "A TLS record from the peer failed authentication, so it was not produced under this session's keys.",
            )
        })?;
        Ok(buf)
    }
}

pub struct Record {
    pub ty: ContentType,
    pub payload: Vec<u8>,
}

pub struct TlsRecordStream {
    transport: BoxedStream,
    inbound: Vec<u8>,
    start: usize,
    end: usize,
    plaintext_scratch: Vec<u8>,
    outbound: Vec<u8>,
    outbound_off: usize,
    outbound_plain: usize,
    pub write: Option<RecordProtection>,
    pub read: Option<RecordProtection>,
}

impl TlsRecordStream {
    pub fn new(transport: BoxedStream) -> Self {
        Self {
            transport,
            inbound: vec![0u8; 64 * 1024],
            start: 0,
            end: 0,
            plaintext_scratch: Vec::new(),
            outbound: Vec::new(),
            outbound_off: 0,
            outbound_plain: 0,
            write: None,
            read: None,
        }
    }

    pub async fn read_record(&mut self) -> Result<Record, ProxyError> {
        if let Some(r) = self.try_read_buffered()? {
            return Ok(r);
        }
        loop {
            if self.start > 0 {
                self.inbound.copy_within(self.start..self.end, 0);
                self.end -= self.start;
                self.start = 0;
            }
            let n = self
                .transport
                .read(&mut self.inbound[self.end..])
                .await
                .map_err(|e| {
                    if e.kind() == std::io::ErrorKind::UnexpectedEof || e.kind() == std::io::ErrorKind::ConnectionReset {
                        ProxyError::new(
                            crate::error::ProxyErrorCode::ConnectionFailed,
                            "The peer closed the connection mid-record.",
                        )
                    } else {
                        e.into()
                    }
                })?;
            if n == 0 {
                return Err(ProxyError::new(
                    crate::error::ProxyErrorCode::ConnectionFailed,
                    "The peer closed the connection mid-record.",
                ));
            }
            self.end += n;
            if let Some(r) = self.try_read_buffered()? {
                return Ok(r);
            }
        }
    }

    fn try_read_buffered(&mut self) -> Result<Option<Record>, ProxyError> {
        let available = self.end - self.start;
        if available < HEADER_LEN {
            return Ok(None);
        }
        let header = self.inbound[self.start..self.start + HEADER_LEN].to_vec();
        let length = ((header[3] as usize) << 8) | header[4] as usize;
        if length > MAX_CIPHERTEXT {
            return Err(hs_err(format!(
                "The peer sent a {length}-byte TLS record, over the {MAX_CIPHERTEXT}-byte limit of RFC 8446."
            )));
        }
        if available < HEADER_LEN + length {
            return Ok(None);
        }
        let ty = ContentType::from_u8(header[0]).ok_or_else(|| hs_err("bad content type"))?;
        let body_start = self.start + HEADER_LEN;
        self.start += HEADER_LEN + length;
        if self.read.is_none() || ty == ContentType::ChangeCipherSpec {
            return Ok(Some(Record {
                ty,
                payload: self.inbound[body_start..body_start + length].to_vec(),
            }));
        }
        if length < TAG_LEN {
            return Err(hs_err("The peer sent an encrypted TLS record shorter than its own tag."));
        }
        let ct = &self.inbound[body_start..body_start + length];
        let mut inner = self.read.as_mut().unwrap().unprotect(ct, &header)?;
        let end = inner
            .iter()
            .rposition(|&b| b != 0)
            .ok_or_else(|| hs_err("The peer sent a TLS record with no content type."))?;
        let real = ContentType::from_u8(inner[end]).ok_or_else(|| hs_err("bad inner type"))?;
        inner.truncate(end);
        self.plaintext_scratch = inner.clone();
        Ok(Some(Record {
            ty: real,
            payload: inner,
        }))
    }

    pub async fn write_record(&mut self, ty: ContentType, payload: &[u8]) -> Result<(), ProxyError> {
        if payload.len() > MAX_PLAINTEXT {
            return Err(hs_err("record too large"));
        }
        let staged = self.stage(ty, payload);
        self.transport.write_all(&staged).await?;
        self.transport.flush().await?;
        Ok(())
    }

    fn stage(&mut self, ty: ContentType, payload: &[u8]) -> Vec<u8> {
        if self.write.is_none() {
            let mut out = vec![0u8; HEADER_LEN + payload.len()];
            out[0] = ty as u8;
            out[1] = 3;
            out[2] = if !payload.is_empty() && ty == ContentType::Handshake {
                1
            } else {
                3
            };
            out[3] = (payload.len() >> 8) as u8;
            out[4] = payload.len() as u8;
            out[HEADER_LEN..].copy_from_slice(payload);
            return out;
        }
        let inner = payload.len() + 1;
        let mut out = vec![0u8; HEADER_LEN + inner + TAG_LEN];
        out[0] = ContentType::ApplicationData as u8;
        out[1] = 3;
        out[2] = 3;
        out[3] = ((inner + TAG_LEN) >> 8) as u8;
        out[4] = (inner + TAG_LEN) as u8;
        let mut plain = Vec::with_capacity(inner);
        plain.extend_from_slice(payload);
        plain.push(ty as u8);
        let header = out[..HEADER_LEN].to_vec();
        self.write
            .as_mut()
            .unwrap()
            .protect(&plain, &header, &mut out[HEADER_LEN..]);
        out
    }

    pub(crate) fn try_read_buffered_pub(&mut self) -> Result<Option<Record>, ProxyError> {
        self.try_read_buffered()
    }

    pub(crate) fn push_inbound(&mut self, data: &[u8]) {
        if self.start > 0 {
            self.inbound.copy_within(self.start..self.end, 0);
            self.end -= self.start;
            self.start = 0;
        }
        let need = self.end + data.len();
        if need > self.inbound.len() {
            self.inbound.resize(need, 0);
        }
        self.inbound[self.end..self.end + data.len()].copy_from_slice(data);
        self.end += data.len();
    }

    pub fn steal_inbound_leftover(&mut self) -> Vec<u8> {
        let n = self.end - self.start;
        if n == 0 {
            return Vec::new();
        }
        let copy = self.inbound[self.start..self.end].to_vec();
        self.start = 0;
        self.end = 0;
        copy
    }

    pub fn transport_mut(&mut self) -> &mut BoxedStream {
        &mut self.transport
    }

    pub(crate) fn poll_write_app(
        &mut self,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.outbound_off >= self.outbound.len() {
            if !self.outbound.is_empty() {
                let plain = self.outbound_plain;
                self.outbound.clear();
                self.outbound_off = 0;
                self.outbound_plain = 0;
                return Poll::Ready(Ok(plain));
            }
            if buf.is_empty() {
                return Poll::Ready(Ok(0));
            }
            let n = buf.len().min(MAX_PLAINTEXT);
            self.outbound = self.stage(ContentType::ApplicationData, &buf[..n]);
            self.outbound_off = 0;
            self.outbound_plain = n;
        }
        loop {
            if self.outbound_off >= self.outbound.len() {
                let plain = self.outbound_plain;
                self.outbound.clear();
                self.outbound_off = 0;
                self.outbound_plain = 0;
                return Poll::Ready(Ok(plain));
            }
            let TlsRecordStream {
                transport,
                outbound,
                outbound_off,
                ..
            } = self;
            match Pin::new(transport).poll_write(cx, &outbound[*outbound_off..]) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "TLS record write returned zero",
                    )));
                }
                Poll::Ready(Ok(n)) => *outbound_off += n,
            }
        }
    }

    pub(crate) fn poll_flush_app(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        while self.outbound_off < self.outbound.len() {
            let TlsRecordStream {
                transport,
                outbound,
                outbound_off,
                ..
            } = self;
            match Pin::new(transport).poll_write(cx, &outbound[*outbound_off..]) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "TLS record flush returned zero",
                    )));
                }
                Poll::Ready(Ok(n)) => *outbound_off += n,
            }
        }
        Pin::new(&mut self.transport).poll_flush(cx)
    }
}
