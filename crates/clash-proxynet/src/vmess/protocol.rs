use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;
use aes_gcm::aead::AeadInPlace;
use aes_gcm::{Aes128Gcm, Nonce};
use bytes::{BufMut, BytesMut};
use cfb_mode::cipher::{AsyncStreamCipher, KeyIvInit};
use hmac::{Hmac, Mac};
use md5::{Digest, Md5};
use rand::RngCore;
use sha2::Sha256;

use crate::address::ProxyAddress;
use crate::crypto::{uuid_write_be, UUID_SIZE};
use crate::error::{ProxyError, ProxyErrorCode};

use super::kdf::{self, *};

pub const CMD_TCP: u8 = 0x01;
pub const SECURITY_AES128_GCM: u8 = 0x03;
pub const SECURITY_CHACHA20: u8 = 0x04;
pub const OPT_CHUNK_STREAM: u8 = 0x01;
pub const OPT_CHUNK_MASKING: u8 = 0x04;
pub const OPT_GLOBAL_PADDING: u8 = 0x08;

pub struct ClientSession {
    pub request_body_key: [u8; 16],
    pub request_body_iv: [u8; 16],
    pub response_body_key: [u8; 16],
    pub response_body_iv: [u8; 16],
    pub response_header: u8,
    pub aead: bool,
}

impl ClientSession {
    pub fn new(aead: bool) -> Self {
        let mut rnd = [0u8; 33];
        rand::thread_rng().fill_bytes(&mut rnd);
        let mut request_body_key = [0u8; 16];
        let mut request_body_iv = [0u8; 16];
        request_body_key.copy_from_slice(&rnd[..16]);
        request_body_iv.copy_from_slice(&rnd[16..32]);
        let response_header = rnd[32];
        let (response_body_key, response_body_iv) = if aead {
            let kh = Sha256::digest(request_body_key);
            let ih = Sha256::digest(request_body_iv);
            let mut rk = [0u8; 16];
            let mut ri = [0u8; 16];
            rk.copy_from_slice(&kh[..16]);
            ri.copy_from_slice(&ih[..16]);
            (rk, ri)
        } else {
            let kh = Md5::digest(request_body_key);
            let ih = Md5::digest(request_body_iv);
            let mut rk = [0u8; 16];
            let mut ri = [0u8; 16];
            rk.copy_from_slice(&kh);
            ri.copy_from_slice(&ih);
            (rk, ri)
        };
        Self {
            request_body_key,
            request_body_iv,
            response_body_key,
            response_body_iv,
            response_header,
            aead,
        }
    }
}

fn fnv1a32(data: &[u8]) -> u32 {
    let mut h = 0x811c9dc5u32;
    for b in data {
        h ^= u32::from(*b);
        h = h.wrapping_mul(0x01000193);
    }
    h
}

fn cmd_key(uuid: &[u8]) -> [u8; 16] {
    let mut h = Md5::new();
    h.update(uuid);
    h.update(b"c48619fe-8f02-49e0-b9e9-edf763e17e21");
    h.finalize().into()
}

fn create_auth_id(key: &[u8], ts: i64) -> Result<[u8; 16], ProxyError> {
    let mut buf = [0u8; 16];
    buf[..8].copy_from_slice(&ts.to_be_bytes());
    rand::thread_rng().fill_bytes(&mut buf[8..12]);
    let crc = crc32fast::hash(&buf[..12]);
    buf[12..16].copy_from_slice(&crc.to_be_bytes());
    let k = &kdf::vmess_kdf_1_one_shot(key, KDF_SALT_CONST_AUTH_ID_ENCRYPTION_KEY)[..16];
    let cipher = Aes128::new_from_slice(k)
        .map_err(|_| ProxyError::new(ProxyErrorCode::AuthRequired, "vmess auth id key"))?;
    cipher.encrypt_block((&mut buf).into());
    Ok(buf)
}

fn seal_aead_header(key: &[u8], data: &[u8]) -> Result<Vec<u8>, ProxyError> {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let auth_id = create_auth_id(key, ts)?;
    let mut nonce8 = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut nonce8);

    let mut len_plain = (data.len() as u16).to_be_bytes().to_vec();
    let len_key = &kdf::vmess_kdf_3_one_shot(
        key,
        KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_KEY,
        &auth_id,
        &nonce8,
    )[..16];
    let len_iv = &kdf::vmess_kdf_3_one_shot(
        key,
        KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_IV,
        &auth_id,
        &nonce8,
    )[..12];
    let cipher = Aes128Gcm::new_from_slice(len_key)
        .map_err(|_| ProxyError::new(ProxyErrorCode::AuthRequired, "vmess header len key"))?;
    let tag = cipher
        .encrypt_in_place_detached(Nonce::from_slice(len_iv), &auth_id, &mut len_plain)
        .map_err(|_| ProxyError::new(ProxyErrorCode::InvalidResponse, "vmess header len"))?;
    len_plain.extend_from_slice(&tag);

    let mut payload = data.to_vec();
    let pkey = &kdf::vmess_kdf_3_one_shot(
        key,
        KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_KEY,
        &auth_id,
        &nonce8,
    )[..16];
    let piv = &kdf::vmess_kdf_3_one_shot(
        key,
        KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_IV,
        &auth_id,
        &nonce8,
    )[..12];
    let cipher = Aes128Gcm::new_from_slice(pkey)
        .map_err(|_| ProxyError::new(ProxyErrorCode::AuthRequired, "vmess header key"))?;
    let tag = cipher
        .encrypt_in_place_detached(Nonce::from_slice(piv), &auth_id, &mut payload)
        .map_err(|_| ProxyError::new(ProxyErrorCode::InvalidResponse, "vmess header"))?;
    payload.extend_from_slice(&tag);

    let mut out = Vec::with_capacity(16 + len_plain.len() + 8 + payload.len());
    out.extend_from_slice(&auth_id);
    out.extend_from_slice(&len_plain);
    out.extend_from_slice(&nonce8);
    out.extend_from_slice(&payload);
    Ok(out)
}

pub fn encode_request(
    uuid: &str,
    dest_host: &str,
    dest_port: u16,
    security: u8,
    sess: &ClientSession,
) -> Result<Vec<u8>, ProxyError> {
    let mut id = [0u8; UUID_SIZE];
    if !uuid_write_be(uuid, &mut id) {
        return Err(ProxyError::new(
            ProxyErrorCode::AuthRequired,
            "VMess uuid is unusable",
        ));
    }
    let mut buf = BytesMut::new();
    let mut auth_len = 0;
    let mut timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if !sess.aead {
        let delta: i32 = (rand::random::<u32>() % 60) as i32 - 30;
        timestamp = timestamp.wrapping_add(delta as u64);
        let mut mac = <Hmac<Md5> as hmac::Mac>::new_from_slice(&id)
            .map_err(|_| ProxyError::new(ProxyErrorCode::AuthRequired, "vmess md5 hmac"))?;
        mac.update(&timestamp.to_be_bytes());
        let auth = mac.finalize().into_bytes();
        buf.put_slice(&auth);
        auth_len = auth.len();
    }

    buf.put_u8(0x01);
    buf.put_slice(&sess.request_body_iv);
    buf.put_slice(&sess.request_body_key);
    buf.put_u8(sess.response_header);
    buf.put_u8(OPT_CHUNK_STREAM | OPT_CHUNK_MASKING | OPT_GLOBAL_PADDING);
    let padding_len = (rand::random::<u8>() % 16) as usize;
    buf.put_u8(((padding_len as u8) << 4) | security);
    buf.put_u8(0);
    buf.put_u8(CMD_TCP);
    let mut addr = [0u8; 2 + ProxyAddress::MAX_LENGTH];
    let n = ProxyAddress::write_socks_port_first(dest_host, dest_port, &mut addr)?;
    buf.put_slice(&addr[..n]);
    if padding_len > 0 {
        let mut pad = vec![0u8; padding_len];
        rand::thread_rng().fill_bytes(&mut pad);
        buf.put_slice(&pad);
    }
    let sum = fnv1a32(&buf[auth_len..]);
    buf.put_u32(sum);

    let key = cmd_key(&id);
    if sess.aead {
        return seal_aead_header(&key, &buf);
    }
    let mut iv_src = [0u8; 8];
    iv_src.copy_from_slice(&timestamp.to_be_bytes());
    let mut hasher = Md5::new();
    hasher.update(iv_src);
    hasher.update(iv_src);
    hasher.update(iv_src);
    hasher.update(iv_src);
    let iv = hasher.finalize();
    cfb_mode::Encryptor::<Aes128>::new((&key).into(), (&iv[..]).into())
        .encrypt(&mut buf[auth_len..]);
    Ok(buf.to_vec())
}

#[cfg(test)]
pub(crate) const AEAD_HEADER_PREFIX: usize = 16 + 18 + 8;

#[cfg(test)]
pub(crate) fn cmd_key_from_uuid(uuid: &str) -> Result<[u8; 16], ProxyError> {
    let mut id = [0u8; UUID_SIZE];
    if !uuid_write_be(uuid, &mut id) {
        return Err(ProxyError::new(
            ProxyErrorCode::AuthRequired,
            "VMess uuid is unusable",
        ));
    }
    Ok(cmd_key(&id))
}

#[cfg(test)]
pub(crate) fn aead_header_payload_len(cmd_key: &[u8], prefix: &[u8]) -> Result<usize, ProxyError> {
    if prefix.len() < AEAD_HEADER_PREFIX {
        return Err(ProxyError::new(
            ProxyErrorCode::InvalidResponse,
            "vmess header too short",
        ));
    }
    let auth_id = &prefix[..16];
    let mut len_ct = prefix[16..34].to_vec();
    let nonce8 = &prefix[34..42];
    let tag = len_ct.split_off(2);
    let len_key = &kdf::vmess_kdf_3_one_shot(
        cmd_key,
        KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_KEY,
        auth_id,
        nonce8,
    )[..16];
    let len_iv = &kdf::vmess_kdf_3_one_shot(
        cmd_key,
        KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_IV,
        auth_id,
        nonce8,
    )[..12];
    let cipher = Aes128Gcm::new_from_slice(len_key)
        .map_err(|_| ProxyError::new(ProxyErrorCode::AuthRequired, "vmess header len key"))?;
    cipher
        .decrypt_in_place_detached(Nonce::from_slice(len_iv), auth_id, &mut len_ct, tag.as_slice().into())
        .map_err(|_| ProxyError::new(ProxyErrorCode::InvalidResponse, "vmess header len"))?;
    Ok(u16::from_be_bytes([len_ct[0], len_ct[1]]) as usize)
}

#[cfg(test)]
pub(crate) fn decode_aead_header(
    uuid: &str,
    packet: &[u8],
) -> Result<(ClientSession, String, u16, u8), ProxyError> {
    let key = cmd_key_from_uuid(uuid)?;
    let payload_len = aead_header_payload_len(&key, packet)?;
    if packet.len() < AEAD_HEADER_PREFIX + payload_len + 16 {
        return Err(ProxyError::new(
            ProxyErrorCode::InvalidResponse,
            "vmess header truncated",
        ));
    }
    let auth_id = &packet[..16];
    let nonce8 = &packet[34..42];
    let mut payload = packet[AEAD_HEADER_PREFIX..AEAD_HEADER_PREFIX + payload_len + 16].to_vec();
    let tag = payload.split_off(payload_len);
    let pkey = &kdf::vmess_kdf_3_one_shot(
        &key,
        KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_KEY,
        auth_id,
        nonce8,
    )[..16];
    let piv = &kdf::vmess_kdf_3_one_shot(
        &key,
        KDF_SALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_IV,
        auth_id,
        nonce8,
    )[..12];
    let cipher = Aes128Gcm::new_from_slice(pkey)
        .map_err(|_| ProxyError::new(ProxyErrorCode::AuthRequired, "vmess header key"))?;
    cipher
        .decrypt_in_place_detached(Nonce::from_slice(piv), auth_id, &mut payload, tag.as_slice().into())
        .map_err(|_| ProxyError::new(ProxyErrorCode::InvalidResponse, "vmess header"))?;

    if payload.len() < 42 || payload[0] != 0x01 {
        return Err(ProxyError::new(
            ProxyErrorCode::InvalidResponse,
            "vmess header version",
        ));
    }
    let mut request_body_iv = [0u8; 16];
    let mut request_body_key = [0u8; 16];
    request_body_iv.copy_from_slice(&payload[1..17]);
    request_body_key.copy_from_slice(&payload[17..33]);
    let response_header = payload[33];
    let security = payload[35] & 0x0f;
    let port = u16::from_be_bytes([payload[38], payload[39]]);
    let (host, _) = parse_socks_host(&payload[40..])?;
    let kh = Sha256::digest(request_body_key);
    let ih = Sha256::digest(request_body_iv);
    let mut response_body_key = [0u8; 16];
    let mut response_body_iv = [0u8; 16];
    response_body_key.copy_from_slice(&kh[..16]);
    response_body_iv.copy_from_slice(&ih[..16]);
    Ok((
        ClientSession {
            request_body_key,
            request_body_iv,
            response_body_key,
            response_body_iv,
            response_header,
            aead: true,
        },
        host,
        port,
        security,
    ))
}

#[cfg(test)]
fn parse_socks_host(buf: &[u8]) -> Result<(String, usize), ProxyError> {
    if buf.is_empty() {
        return Err(ProxyError::new(
            ProxyErrorCode::InvalidResponse,
            "vmess address empty",
        ));
    }
    match buf[0] {
        0x01 if buf.len() >= 5 => Ok((
            format!("{}.{}.{}.{}", buf[1], buf[2], buf[3], buf[4]),
            5,
        )),
        0x03 if buf.len() >= 2 => {
            let n = buf[1] as usize;
            if buf.len() < 2 + n {
                return Err(ProxyError::new(
                    ProxyErrorCode::InvalidResponse,
                    "vmess domain truncated",
                ));
            }
            Ok((String::from_utf8_lossy(&buf[2..2 + n]).into_owned(), 2 + n))
        }
        0x04 if buf.len() >= 17 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[1..17]);
            Ok((std::net::Ipv6Addr::from(octets).to_string(), 17))
        }
        _ => Err(ProxyError::new(
            ProxyErrorCode::InvalidResponse,
            "vmess address type",
        )),
    }
}

#[cfg(test)]
pub(crate) fn encode_aead_response(sess: &ClientSession) -> Result<Vec<u8>, ProxyError> {
    let mut payload = vec![sess.response_header, 0, 0, 0];
    let mut len_plain = (payload.len() as u16).to_be_bytes().to_vec();
    let len_key = &kdf::vmess_kdf_1_one_shot(
        &sess.response_body_key,
        KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_KEY,
    )[..16];
    let len_iv = &kdf::vmess_kdf_1_one_shot(
        &sess.response_body_iv,
        KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_IV,
    )[..12];
    let cipher = Aes128Gcm::new_from_slice(len_key)
        .map_err(|_| ProxyError::new(ProxyErrorCode::AuthRequired, "vmess resp len key"))?;
    let tag = cipher
        .encrypt_in_place_detached(Nonce::from_slice(len_iv), b"", &mut len_plain)
        .map_err(|_| ProxyError::new(ProxyErrorCode::InvalidResponse, "vmess resp len"))?;
    len_plain.extend_from_slice(&tag);

    let pkey = &kdf::vmess_kdf_1_one_shot(
        &sess.response_body_key,
        KDF_SALT_CONST_AEAD_RESP_HEADER_PAYLOAD_KEY,
    )[..16];
    let piv = &kdf::vmess_kdf_1_one_shot(
        &sess.response_body_iv,
        KDF_SALT_CONST_AEAD_RESP_HEADER_PAYLOAD_IV,
    )[..12];
    let cipher = Aes128Gcm::new_from_slice(pkey)
        .map_err(|_| ProxyError::new(ProxyErrorCode::AuthRequired, "vmess resp key"))?;
    let tag = cipher
        .encrypt_in_place_detached(Nonce::from_slice(piv), b"", &mut payload)
        .map_err(|_| ProxyError::new(ProxyErrorCode::InvalidResponse, "vmess resp header"))?;
    payload.extend_from_slice(&tag);

    let mut out = len_plain;
    out.extend_from_slice(&payload);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aead_header_is_nonempty() {
        let sess = ClientSession::new(true);
        let bytes = encode_request(
            "11111111-1111-1111-1111-111111111111",
            "example.com",
            443,
            SECURITY_AES128_GCM,
            &sess,
        )
        .unwrap();
        assert!(bytes.len() > 16 + 18 + 8);
        let (decoded, host, port, security) =
            decode_aead_header("11111111-1111-1111-1111-111111111111", &bytes).unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 443);
        assert_eq!(security, SECURITY_AES128_GCM);
        assert_eq!(decoded.response_header, sess.response_header);
        assert_eq!(decoded.request_body_key, sess.request_body_key);
    }
}
