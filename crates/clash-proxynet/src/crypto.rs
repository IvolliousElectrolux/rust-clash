use sha1::{Digest, Sha1};
use sha2::Sha224;

pub const UUID_SIZE: usize = 16;
const MAX_DERIVED: usize = 30;
const MIN_CANONICAL: usize = 32;
const MAX_CANONICAL: usize = 36;

pub fn uuid_write_be(id: &str, dest: &mut [u8]) -> bool {
    if dest.len() < UUID_SIZE {
        return false;
    }
    let id = id.trim();
    if (MIN_CANONICAL..=MAX_CANONICAL).contains(&id.len()) {
        return parse_canonical(id, dest);
    }
    if !id.is_empty() && id.len() <= MAX_DERIVED {
        return derive_uuid(id, dest);
    }
    false
}

fn parse_canonical(id: &str, dest: &mut [u8]) -> bool {
    let hex: String = id.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if hex.len() != 32 {
        return false;
    }
    match hex::decode(hex) {
        Ok(bytes) if bytes.len() == 16 => {
            dest[..16].copy_from_slice(&bytes);
            true
        }
        _ => false,
    }
}

fn derive_uuid(id: &str, dest: &mut [u8]) -> bool {
    let mut input = [0u8; UUID_SIZE + MAX_DERIVED * 4];
    let name = id.as_bytes();
    if name.len() > MAX_DERIVED * 4 {
        return false;
    }
    input[UUID_SIZE..UUID_SIZE + name.len()].copy_from_slice(name);
    let hash = Sha1::digest(&input[..UUID_SIZE + name.len()]);
    dest[..UUID_SIZE].copy_from_slice(&hash[..UUID_SIZE]);
    dest[6] = (dest[6] & 0x0F) | 0x50;
    dest[8] = (dest[8] & 0x3F) | 0x80;
    true
}

pub fn sha224_hex_lower(data: &[u8], dest: &mut [u8]) {
    use sha2::Digest;
    let digest = Sha224::digest(data);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for (i, b) in digest.iter().enumerate() {
        dest[2 * i] = HEX[(b >> 4) as usize];
        dest[2 * i + 1] = HEX[(b & 0x0F) as usize];
    }
}

pub const SHA224_HEX_SIZE: usize = 56;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha224_password_hex() {
        let mut dest = [0u8; SHA224_HEX_SIZE];
        sha224_hex_lower(b"password", &mut dest);
        assert_eq!(
            std::str::from_utf8(&dest).unwrap(),
            "d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"
        );
    }

    #[test]
    fn uuid_canonical() {
        let mut dest = [0u8; UUID_SIZE];
        assert!(uuid_write_be("11111111-1111-1111-1111-111111111111", &mut dest));
        assert_eq!(dest, [0x11; 16]);
    }
}
