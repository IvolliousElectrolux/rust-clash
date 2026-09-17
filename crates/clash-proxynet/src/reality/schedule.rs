use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha384};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum HashKind {
    Sha256,
    Sha384,
}

impl HashKind {
    pub fn len(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
        }
    }

    pub fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha256 => Sha256::digest(data).to_vec(),
            Self::Sha384 => Sha384::digest(data).to_vec(),
        }
    }

    pub fn empty(self) -> Vec<u8> {
        self.digest(b"")
    }
}

pub fn extract(hash: HashKind, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
    let salt_v = if salt.is_empty() {
        vec![0u8; hash.len()]
    } else {
        salt.to_vec()
    };
    match hash {
        HashKind::Sha256 => {
            type H = Hmac<Sha256>;
            let mut mac = <H as Mac>::new_from_slice(&salt_v).expect("hmac");
            mac.update(ikm);
            mac.finalize().into_bytes().to_vec()
        }
        HashKind::Sha384 => {
            type H = Hmac<Sha384>;
            let mut mac = <H as Mac>::new_from_slice(&salt_v).expect("hmac");
            mac.update(ikm);
            mac.finalize().into_bytes().to_vec()
        }
    }
}

pub fn expand_label(hash: HashKind, secret: &[u8], label: &[u8], context: &[u8], out: &mut [u8]) {
    let prefix = b"tls13 ";
    let label_len = prefix.len() + label.len();
    let mut info = Vec::with_capacity(2 + 1 + label_len + 1 + context.len());
    info.extend_from_slice(&(out.len() as u16).to_be_bytes());
    info.push(label_len as u8);
    info.extend_from_slice(prefix);
    info.extend_from_slice(label);
    info.push(context.len() as u8);
    info.extend_from_slice(context);
    hkdf_expand(hash, secret, &info, out);
}

fn hkdf_expand(hash: HashKind, prk: &[u8], info: &[u8], out: &mut [u8]) {
    match hash {
        HashKind::Sha256 => {
            let hk = hkdf::Hkdf::<Sha256>::from_prk(prk).expect("prk");
            hk.expand(info, out).expect("expand");
        }
        HashKind::Sha384 => {
            let hk = hkdf::Hkdf::<Sha384>::from_prk(prk).expect("prk");
            hk.expand(info, out).expect("expand");
        }
    }
}

pub fn derive_secret(hash: HashKind, secret: &[u8], label: &[u8], transcript: &[u8], out: &mut [u8]) {
    expand_label(hash, secret, label, transcript, out);
}

pub fn traffic_keys(hash: HashKind, traffic: &[u8], key: &mut [u8], iv: &mut [u8]) {
    expand_label(hash, traffic, b"key", b"", key);
    expand_label(hash, traffic, b"iv", b"", iv);
}

pub fn finished_verify(hash: HashKind, base_key: &[u8], transcript: &[u8], out: &mut [u8]) {
    let mut finished_key = vec![0u8; out.len()];
    expand_label(hash, base_key, b"finished", b"", &mut finished_key);
    match hash {
        HashKind::Sha256 => {
            type H = Hmac<Sha256>;
            let mut mac = <H as Mac>::new_from_slice(&finished_key).expect("hmac");
            mac.update(transcript);
            out.copy_from_slice(&mac.finalize().into_bytes());
        }
        HashKind::Sha384 => {
            type H = Hmac<Sha384>;
            let mut mac = <H as Mac>::new_from_slice(&finished_key).expect("hmac");
            mac.update(transcript);
            out.copy_from_slice(&mac.finalize().into_bytes());
        }
    }
}

pub fn build_nonce(nonce: &mut [u8], iv: &[u8], seq: u64) {
    nonce.copy_from_slice(iv);
    let mut tail = [0u8; 8];
    tail.copy_from_slice(&nonce[4..12]);
    let v = u64::from_be_bytes(tail) ^ seq;
    nonce[4..12].copy_from_slice(&v.to_be_bytes());
}
