use std::net::IpAddr;

use crate::error::{ProxyError, ProxyErrorCode};

pub struct ProxyAddress;

impl ProxyAddress {
    pub const MAX_LENGTH: usize = 1 + 1 + 255;

    pub fn write_type_and_address(
        host: &str,
        dest: &mut [u8],
        ipv4_type: u8,
        domain_type: u8,
        ipv6_type: u8,
    ) -> Result<usize, ProxyError> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return match ip {
                IpAddr::V4(v4) => {
                    dest[0] = ipv4_type;
                    dest[1..5].copy_from_slice(&v4.octets());
                    Ok(5)
                }
                IpAddr::V6(v6) => {
                    dest[0] = ipv6_type;
                    dest[1..17].copy_from_slice(&v6.octets());
                    Ok(17)
                }
            };
        }

        dest[0] = domain_type;
        let bytes = host.as_bytes();
        if bytes.len() > 255 {
            return Err(ProxyError::new(
                ProxyErrorCode::StringTooLong,
                "Target host name exceeds the maximum of 255 bytes.",
            ));
        }
        dest[1] = bytes.len() as u8;
        dest[2..2 + bytes.len()].copy_from_slice(bytes);
        Ok(2 + bytes.len())
    }
}
