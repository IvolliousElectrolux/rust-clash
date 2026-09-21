use std::cmp::min;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce};
use bytes::{BufMut, BytesMut};
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use md5::{Digest, Md5};
use rand::RngCore;
use sha1::Sha1;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::address::ProxyAddress;
use crate::error::{ProxyError, ProxyErrorCode};
use crate::options::SsOptions;
use crate::{AsyncIo, BoxedStream};

const MAX_PAYLOAD: usize = 0x3FFF;
const TAG_LEN: usize = 16;
const NONCE_LEN: usize = 12;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SsCipher {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
}

impl SsCipher {
    fn parse(name: &str) -> Option<Self> {
        match name.trim().to_ascii_lowercase().as_str() {
            "aes-128-gcm" | "aead_aes_128_gcm" => Some(Self::Aes128Gcm),
            "aes-256-gcm" | "aead_aes_256_gcm" => Some(Self::Aes256Gcm),
            "chacha20-ietf-poly1305" | "chacha20-poly1305" | "aead_chacha20_ietf_poly1305" => {
                Some(Self::ChaCha20Poly1305)
            }
            _ => None,
        }
    }

    fn key_len(self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            Self::Aes256Gcm | Self::ChaCha20Poly1305 => 32,
        }
    }
}

#[derive(Clone)]
enum Aead {
    Aes128(Aes128Gcm),
    Aes256(Aes256Gcm),
    ChaCha(ChaCha20Poly1305),
}

impl Aead {
    fn new(kind: SsCipher, key: &[u8]) -> Self {
        match kind {
            SsCipher::Aes128Gcm => Self::Aes128(Aes128Gcm::new_from_slice(key).expect("aes-128 key")),
            SsCipher::Aes256Gcm => Self::Aes256(Aes256Gcm::new_from_slice(key).expect("aes-256 key")),
            SsCipher::ChaCha20Poly1305 => {
                Self::ChaCha(ChaCha20Poly1305::new_from_slice(key).expect("chacha key"))
            }
        }
    }

    fn seal(&self, nonce: &[u8], buf: &mut BytesMut) -> io::Result<()> {
        let n = Nonce::from_slice(nonce);
        let tag = match self {
            Self::Aes128(c) => c.encrypt_in_place_detached(n, b"", buf),
            Self::Aes256(c) => c.encrypt_in_place_detached(n, b"", buf),
            Self::ChaCha(c) => c.encrypt_in_place_detached(n, b"", buf),
        }
        .map_err(|_| io::Error::other("ss encrypt"))?;
        buf.extend_from_slice(&tag);
        Ok(())
    }

    fn open(&self, nonce: &[u8], buf: &mut BytesMut) -> io::Result<()> {
        if buf.len() < TAG_LEN {
            return Err(io::Error::other("ss short packet"));
        }
        let tag = buf.split_off(buf.len() - TAG_LEN);
        let n = Nonce::from_slice(nonce);
        match self {
            Self::Aes128(c) => c.decrypt_in_place_detached(n, b"", buf, tag.as_ref().into()),
            Self::Aes256(c) => c.decrypt_in_place_detached(n, b"", buf, tag.as_ref().into()),
            Self::ChaCha(c) => c.decrypt_in_place_detached(n, b"", buf, tag.as_ref().into()),
        }
        .map_err(|_| io::Error::other("ss decrypt"))?;
        Ok(())
    }
}

struct NonceSeq {
    buf: [u8; NONCE_LEN],
}

impl NonceSeq {
    fn new() -> Self {
        Self { buf: [0; NONCE_LEN] }
    }

    fn next(&mut self) -> [u8; NONCE_LEN] {
        let out = self.buf;
        for b in &mut self.buf {
            *b = b.wrapping_add(1);
            if *b != 0 {
                break;
            }
        }
        out
    }
}

enum ReadState {
    Salt,
    Length,
    Data(usize),
    Pending(usize),
}

enum WriteState {
    Salt,
    Chunk,
    Flush { consumed: usize, total: usize, written: usize },
}

pub struct ShadowedStream<T> {
    inner: T,
    kind: SsCipher,
    psk: Vec<u8>,
    enc: Option<Aead>,
    dec: Option<Aead>,
    enc_nonce: NonceSeq,
    dec_nonce: NonceSeq,
    read_buf: BytesMut,
    write_buf: BytesMut,
    read_state: ReadState,
    write_state: WriteState,
    read_pos: usize,
}

impl<T> ShadowedStream<T> {
    pub fn new(inner: T, method: &str, password: &str) -> io::Result<Self> {
        let kind = SsCipher::parse(method).ok_or_else(|| {
            io::Error::other(format!("unsupported shadowsocks cipher {method}"))
        })?;
        Ok(Self {
            inner,
            kind,
            psk: evp_bytes_to_key(password.as_bytes(), kind.key_len()),
            enc: None,
            dec: None,
            enc_nonce: NonceSeq::new(),
            dec_nonce: NonceSeq::new(),
            read_buf: BytesMut::new(),
            write_buf: BytesMut::new(),
            read_state: ReadState::Salt,
            write_state: WriteState::Salt,
            read_pos: 0,
        })
    }
}

fn evp_bytes_to_key(pass: &[u8], size: usize) -> Vec<u8> {
    let mut key = Vec::new();
    let mut last = Vec::new();
    while key.len() < size {
        let mut h = Md5::new();
        h.update(&last);
        h.update(pass);
        last = h.finalize().to_vec();
        key.extend_from_slice(&last);
    }
    key.truncate(size);
    key
}

fn hkdf_sha1(psk: &[u8], salt: &[u8], out_len: usize) -> io::Result<Vec<u8>> {
    let hk = Hkdf::<Sha1>::new(Some(salt), psk);
    let mut okm = vec![0u8; out_len];
    hk.expand(b"ss-subkey", &mut okm)
        .map_err(|_| io::Error::other("ss hkdf"))?;
    Ok(okm)
}

fn early_eof() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "ss eof")
}

impl<T: AsyncRead + Unpin> ShadowedStream<T> {
    fn poll_read_exact(&mut self, cx: &mut Context<'_>, size: usize) -> Poll<io::Result<()>> {
        self.read_buf.resize(size, 0);
        while self.read_pos < size {
            let mut buf = ReadBuf::new(&mut self.read_buf[self.read_pos..size]);
            ready!(Pin::new(&mut self.inner).poll_read(cx, &mut buf))?;
            let n = buf.filled().len();
            if n == 0 {
                return Poll::Ready(Err(early_eof()));
            }
            self.read_pos += n;
        }
        self.read_pos = 0;
        Poll::Ready(Ok(()))
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for ShadowedStream<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            match self.read_state {
                ReadState::Salt => {
                    let salt_len = self.kind.key_len();
                    ready!(self.poll_read_exact(cx, salt_len))?;
                    let salt = self.read_buf.split().freeze();
                    let key = hkdf_sha1(&self.psk, &salt, salt_len)?;
                    self.dec = Some(Aead::new(self.kind, &key));
                    self.read_state = ReadState::Length;
                }
                ReadState::Length => {
                    let n = 2 + TAG_LEN;
                    match ready!(self.poll_read_exact(cx, n)) {
                        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                            return Poll::Ready(Ok(()));
                        }
                        Err(e) => return Poll::Ready(Err(e)),
                        Ok(()) => {}
                    }
                    let nonce = self.dec_nonce.next();
                    let dec = self.dec.clone().expect("ss dec");
                    dec.open(&nonce, &mut self.read_buf)?;
                    let payload_len = u16::from_be_bytes(self.read_buf[..2].try_into().unwrap()) as usize;
                    self.read_state = ReadState::Data(payload_len);
                }
                ReadState::Data(n) => {
                    ready!(self.poll_read_exact(cx, n + TAG_LEN))?;
                    let nonce = self.dec_nonce.next();
                    let dec = self.dec.clone().expect("ss dec");
                    dec.open(&nonce, &mut self.read_buf)?;
                    self.read_state = ReadState::Pending(n);
                }
                ReadState::Pending(n) => {
                    let take = min(buf.remaining(), n);
                    buf.put_slice(&self.read_buf.split_to(take));
                    if take < n {
                        self.read_state = ReadState::Pending(n - take);
                    } else {
                        self.read_state = ReadState::Length;
                    }
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for ShadowedStream<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        loop {
            match self.write_state {
                WriteState::Salt => {
                    let salt_len = self.kind.key_len();
                    self.write_buf.resize(salt_len, 0);
                    rand::thread_rng().fill_bytes(&mut self.write_buf[..salt_len]);
                    let key = hkdf_sha1(&self.psk, &self.write_buf[..salt_len], salt_len)?;
                    self.enc = Some(Aead::new(self.kind, &key));
                    self.write_state = WriteState::Chunk;
                }
                WriteState::Chunk => {
                    let consume = min(buf.len(), MAX_PAYLOAD);
                    let salt_len = self.write_buf.len();
                    let mut piece = self.write_buf.split_off(salt_len);
                    piece.reserve(2 + TAG_LEN + consume + TAG_LEN);
                    piece.put_u16(consume as u16);
                    let nonce = self.enc_nonce.next();
                    self.enc.as_ref().expect("ss enc").seal(&nonce, &mut piece)?;
                    let mut payload = BytesMut::with_capacity(consume + TAG_LEN);
                    payload.put_slice(&buf[..consume]);
                    let nonce = self.enc_nonce.next();
                    self.enc.as_ref().expect("ss enc").seal(&nonce, &mut payload)?;
                    piece.unsplit(payload);
                    self.write_buf.unsplit(piece);
                    let total = self.write_buf.len();
                    self.write_state = WriteState::Flush {
                        consumed: consume,
                        total,
                        written: 0,
                    };
                }
                WriteState::Flush {
                    consumed,
                    total,
                    written,
                } => {
                    let this = &mut *self;
                    let n = ready!(Pin::new(&mut this.inner).poll_write(cx, &this.write_buf))?;
                    if n == 0 {
                        return Poll::Ready(Err(early_eof()));
                    }
                    let _ = this.write_buf.split_to(n);
                    let written = written + n;
                    if written >= total {
                        this.write_state = WriteState::Chunk;
                        return Poll::Ready(Ok(consumed));
                    }
                    this.write_state = WriteState::Flush {
                        consumed,
                        total,
                        written,
                    };
                }
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncIo for ShadowedStream<T> {}

pub async fn dial_ss(
    stream: BoxedStream,
    options: &SsOptions,
    dest_host: &str,
    dest_port: u16,
) -> Result<BoxedStream, ProxyError> {
    let mut layered = stream;
    if let Some(plugin) = options.plugin.as_deref() {
        layered = crate::obfs::apply_plugin(layered, plugin, options.plugin_opts.as_deref(), options)?;
    }
    let mut shadowed = ShadowedStream::new(layered, &options.method, &options.password)
        .map_err(|e| ProxyError::new(ProxyErrorCode::AuthRequired, e.to_string()))?;
    let mut header = [0u8; 2 + ProxyAddress::MAX_LENGTH];
    let n = ProxyAddress::write_socks_port_last(dest_host, dest_port, &mut header)?;
    shadowed.write_all(&header[..n]).await?;
    shadowed.flush().await?;
    Ok(Box::pin(shadowed))
}

pub fn supported_cipher(name: &str) -> bool {
    SsCipher::parse(name).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, duplex};

    #[tokio::test]
    async fn aead_roundtrip_chacha() {
        let (a, b) = duplex(64 * 1024);
        let mut client = ShadowedStream::new(a, "chacha20-ietf-poly1305", "secret").unwrap();
        let mut server = ShadowedStream::new(b, "chacha20-ietf-poly1305", "secret").unwrap();
        let payload = b"hello-shadowsocks";
        client.write_all(payload).await.unwrap();
        client.flush().await.unwrap();
        let mut buf = vec![0u8; payload.len()];
        server.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, payload);
    }

    #[tokio::test]
    async fn aead_roundtrip_aes256() {
        let (a, b) = duplex(64 * 1024);
        let mut client = ShadowedStream::new(a, "aes-256-gcm", "pw").unwrap();
        let mut server = ShadowedStream::new(b, "aes-256-gcm", "pw").unwrap();
        let payload = vec![7u8; 4000];
        client.write_all(&payload).await.unwrap();
        let mut buf = vec![0u8; payload.len()];
        server.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, payload);
    }

    #[test]
    fn rejects_stream_cipher() {
        assert!(SsCipher::parse("aes-256-cfb").is_none());
        assert!(supported_cipher("aes-128-gcm"));
    }

    async fn skip_socks_addr<R: AsyncRead + Unpin>(r: &mut R) {
        let mut atyp = [0u8; 1];
        r.read_exact(&mut atyp).await.unwrap();
        let n = match atyp[0] {
            0x01 => 4,
            0x04 => 16,
            0x03 => {
                let mut len = [0u8; 1];
                r.read_exact(&mut len).await.unwrap();
                len[0] as usize
            }
            other => panic!("atyp {other}"),
        };
        let mut rest = vec![0u8; n + 2];
        r.read_exact(&mut rest).await.unwrap();
    }

    async fn ss_tcp_echo(method: &str) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let method_s = method.to_string();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut ss = ShadowedStream::new(socket, &method_s, "secret").unwrap();
            skip_socks_addr(&mut ss).await;
            let mut buf = [0u8; 64];
            let n = ss.read(&mut buf).await.unwrap();
            ss.write_all(&buf[..n]).await.unwrap();
            ss.flush().await.unwrap();
            let _ = ss.shutdown().await;
            let mut hold = [0u8; 1];
            let _ = ss.read(&mut hold).await;
        });
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let opts = SsOptions {
            method: method.into(),
            password: "secret".into(),
            host: addr.ip().to_string(),
            port: addr.port(),
            plugin: None,
            plugin_opts: None,
            transport: "tcp".into(),
            path: None,
            host_header: None,
            sni: None,
            alpn: Vec::new(),
            allow_insecure: false,
            tls: false,
        };
        let mut client = dial_ss(Box::pin(tcp), &opts, "1.2.3.4", 80).await.unwrap();
        client.write_all(b"ping-ss").await.unwrap();
        client.flush().await.unwrap();
        let mut buf = [0u8; 7];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping-ss");
        let _ = client.shutdown().await;
        server.await.unwrap();
    }

    #[tokio::test]
    async fn ss_tcp_echo_chacha_and_aes() {
        ss_tcp_echo("chacha20-ietf-poly1305").await;
        ss_tcp_echo("aes-128-gcm").await;
        ss_tcp_echo("aes-256-gcm").await;
    }
}
