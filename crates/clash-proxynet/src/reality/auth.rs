use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha512};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::error::ProxyError;
use crate::reality::hs_err;

pub const SESSION_ID_SIZE: usize = 32;
pub const AUTH_KEY_SIZE: usize = 32;
pub const SHORT_ID_SIZE: usize = 8;
pub const SESSION_ID_OFFSET: usize = 39;

type HmacSha512 = Hmac<Sha512>;

pub fn derive_auth_key(
    auth_key: &mut [u8; AUTH_KEY_SIZE],
    client_private: &[u8; 32],
    server_public: &[u8; 32],
    client_random: &[u8],
) -> Result<(), ProxyError> {
    if client_random.len() != 32 {
        return Err(hs_err("The client random is 32 bytes."));
    }
    let secret = StaticSecret::from(*client_private);
    let shared = secret.diffie_hellman(&PublicKey::from(*server_public));
    let hk = hkdf::Hkdf::<Sha256>::new(Some(&client_random[..20]), shared.as_bytes());
    hk.expand(b"REALITY", auth_key)
        .map_err(|_| hs_err("HKDF expand failed"))?;
    Ok(())
}

pub fn seal_session_id(
    client_hello: &mut [u8],
    auth_key: &[u8; AUTH_KEY_SIZE],
    short_id: &[u8; SHORT_ID_SIZE],
    unix_time: u32,
    client_version: [u8; 3],
) -> Result<(), ProxyError> {
    if client_hello.len() < SESSION_ID_OFFSET + SESSION_ID_SIZE {
        return Err(hs_err("The ClientHello is too short to contain a session id."));
    }
    if client_hello[SESSION_ID_OFFSET - 1] != SESSION_ID_SIZE as u8 {
        return Err(hs_err(format!(
            "REALITY requires a {SESSION_ID_SIZE}-byte session id; this ClientHello declares {}.",
            client_hello[SESSION_ID_OFFSET - 1]
        )));
    }
    let client_random = client_hello[6..38].to_vec();
    let mut plaintext = [0u8; 16];
    plaintext[..3].copy_from_slice(&client_version);
    plaintext[4..8].copy_from_slice(&unix_time.to_be_bytes());
    plaintext[8..16].copy_from_slice(short_id);

    client_hello[SESSION_ID_OFFSET..SESSION_ID_OFFSET + SESSION_ID_SIZE].fill(0);

    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&client_random[20..]);

    let cipher = Aes256Gcm::new_from_slice(auth_key).map_err(|_| hs_err("AES-GCM key"))?;
    let mut sealed = plaintext.to_vec();
    cipher
        .encrypt_in_place(Nonce::from_slice(&nonce), client_hello, &mut sealed)
        .map_err(|_| hs_err("AES-GCM seal failed"))?;
    if sealed.len() != SESSION_ID_SIZE {
        return Err(hs_err(format!(
            "sealed session id is {} bytes",
            sealed.len()
        )));
    }
    client_hello[SESSION_ID_OFFSET..SESSION_ID_OFFSET + SESSION_ID_SIZE].copy_from_slice(&sealed);
    Ok(())
}

pub fn verify_certificate(auth_key: &[u8], ed25519_pk: &[u8], signature: &[u8]) -> bool {
    if signature.len() != 64 {
        return false;
    }
    let Ok(mut mac) = <HmacSha512 as Mac>::new_from_slice(auth_key) else {
        return false;
    };
    mac.update(ed25519_pk);
    mac.verify_slice(signature).is_ok()
}

pub fn parse_short_id(hex: Option<&str>) -> Result<[u8; SHORT_ID_SIZE], ProxyError> {
    let mut out = [0u8; SHORT_ID_SIZE];
    let Some(hex) = hex.filter(|s| !s.is_empty()) else {
        return Ok(out);
    };
    if hex.len() % 2 != 0 {
        return Err(hs_err(format!(
            "A REALITY short id is an even number of hex digits; '{hex}' is not."
        )));
    }
    if hex.len() > SHORT_ID_SIZE * 2 {
        return Err(hs_err(format!(
            "A REALITY short id is at most {SHORT_ID_SIZE} bytes; '{hex}' is {}.",
            hex.len() / 2
        )));
    }
    let bytes = hex::decode(hex).map_err(|_| hs_err(format!("'{hex}' is not hex")))?;
    out[..bytes.len()].copy_from_slice(&bytes);
    Ok(out)
}

pub fn decode_pbk(value: &str) -> Result<[u8; 32], ProxyError> {
    let mut padded = value.replace('-', "+").replace('_', "/");
    padded.push_str(match padded.len() % 4 {
        2 => "==",
        3 => "=",
        _ => "",
    });
    use base64::Engine;
    let key = base64::engine::general_purpose::STANDARD
        .decode(padded)
        .map_err(|_| hs_err(format!("REALITY public key '{value}' is not valid base64url.")))?;
    if key.len() != 32 {
        return Err(hs_err(format!(
            "REALITY public key decodes to {} bytes; need 32.",
            key.len()
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&key);
    Ok(arr)
}

pub fn x25519_generate() -> ([u8; 32], [u8; 32]) {
    let secret = StaticSecret::random_from_rng(rand::thread_rng());
    let public = PublicKey::from(&secret);
    (secret.to_bytes(), public.to_bytes())
}

pub fn x25519_agree(private: &[u8; 32], public: &[u8; 32]) -> [u8; 32] {
    let secret = StaticSecret::from(*private);
    *secret.diffie_hellman(&PublicKey::from(*public)).as_bytes()
}
