use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes128Gcm, Nonce};
use chacha20poly1305::ChaCha20Poly1305;
use digest::{ExtendableOutput, Update, XofReader};
use md5::{Digest, Md5};
use sha3::Shake128;

use crate::error::{ProxyError, ProxyErrorCode};

#[derive(Clone)]
pub enum BodyAead {
    Aes128(Aes128Gcm),
    ChaCha(ChaCha20Poly1305),
}

impl BodyAead {
    pub fn new(name: &str, key: &[u8]) -> Result<Self, ProxyError> {
        match name.to_ascii_lowercase().as_str() {
            "aes-128-gcm" => {
                let c = Aes128Gcm::new_from_slice(key)
                    .map_err(|_| ProxyError::new(ProxyErrorCode::AuthRequired, "vmess aes key"))?;
                Ok(Self::Aes128(c))
            }
            "chacha20-poly1305" | "chacha20-ietf-poly1305" => {
                let derived = chacha_key(key);
                let c = ChaCha20Poly1305::new_from_slice(&derived).map_err(|_| {
                    ProxyError::new(ProxyErrorCode::AuthRequired, "vmess chacha key")
                })?;
                Ok(Self::ChaCha(c))
            }
            other => Err(ProxyError::new(
                ProxyErrorCode::AuthRequired,
                format!("unsupported vmess cipher {other}"),
            )),
        }
    }

    pub fn tag_len(&self) -> usize {
        16
    }

    pub fn seal(&self, nonce: &[u8], buf: &mut Vec<u8>) -> Result<(), ProxyError> {
        let n = Nonce::from_slice(nonce);
        let tag = match self {
            Self::Aes128(c) => c.encrypt_in_place_detached(n, b"", buf),
            Self::ChaCha(c) => c.encrypt_in_place_detached(n, b"", buf),
        }
        .map_err(|_| ProxyError::new(ProxyErrorCode::InvalidResponse, "vmess encrypt"))?;
        buf.extend_from_slice(&tag);
        Ok(())
    }

    pub fn open(&self, nonce: &[u8], buf: &mut Vec<u8>) -> Result<(), ProxyError> {
        if buf.len() < 16 {
            return Err(ProxyError::new(
                ProxyErrorCode::InvalidResponse,
                "vmess short chunk",
            ));
        }
        let tag = buf.split_off(buf.len() - 16);
        let n = Nonce::from_slice(nonce);
        match self {
            Self::Aes128(c) => c.decrypt_in_place_detached(n, b"", buf, tag.as_slice().into()),
            Self::ChaCha(c) => c.decrypt_in_place_detached(n, b"", buf, tag.as_slice().into()),
        }
        .map_err(|_| ProxyError::new(ProxyErrorCode::InvalidResponse, "vmess decrypt"))?;
        Ok(())
    }
}

fn chacha_key(key: &[u8]) -> Vec<u8> {
    let k1 = Md5::digest(key);
    let k2 = Md5::digest(k1);
    let mut out = Vec::with_capacity(32);
    out.extend_from_slice(&k1);
    out.extend_from_slice(&k2);
    out
}

pub struct VmessNonce {
    nonce: Vec<u8>,
    size: usize,
    count: u16,
}

impl VmessNonce {
    pub fn new(iv: &[u8], size: usize) -> Self {
        let mut nonce = iv.to_vec();
        if nonce.len() < size {
            nonce.resize(size, 0);
        }
        Self {
            nonce,
            size,
            count: 0xffff,
        }
    }

    pub fn next(&mut self) -> Vec<u8> {
        self.count = self.count.wrapping_add(1);
        self.nonce[..2].copy_from_slice(&self.count.to_be_bytes());
        self.nonce[..self.size].to_vec()
    }
}

pub struct ShakeSizeParser {
    reader: <Shake128 as ExtendableOutput>::Reader,
    buf: [u8; 2],
}

impl ShakeSizeParser {
    pub fn new(nonce: &[u8]) -> Self {
        let mut hasher = Shake128::default();
        hasher.update(nonce);
        Self {
            reader: hasher.finalize_xof(),
            buf: [0, 0],
        }
    }

    pub fn size_bytes(&self) -> usize {
        2
    }

    fn next_u16(&mut self) -> u16 {
        XofReader::read(&mut self.reader, &mut self.buf);
        u16::from_be_bytes(self.buf)
    }

    pub fn decode(&mut self, b: &[u8]) -> u16 {
        self.next_u16() ^ u16::from_be_bytes([b[0], b[1]])
    }

    pub fn encode(&mut self, size: u16) -> [u8; 2] {
        (self.next_u16() ^ size).to_be_bytes()
    }

    pub fn next_padding_len(&mut self) -> u16 {
        self.next_u16() % 64
    }
}
