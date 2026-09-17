use tokio::io::AsyncWriteExt;

use crate::BoxedStream;
use crate::address::ProxyAddress;
use crate::crypto::{SHA224_HEX_SIZE, sha224_hex_lower};
use crate::error::ProxyError;
use crate::options::TrojanOptions;

const CMD_TCP: u8 = 0x01;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

pub async fn establish_trojan(
    mut stream: BoxedStream,
    options: &TrojanOptions,
    host: &str,
    port: u16,
) -> Result<BoxedStream, ProxyError> {
    let mut req = [0u8; SHA224_HEX_SIZE + 2 + 1 + ProxyAddress::MAX_LENGTH + 2 + 2];
    let n = build_request(&mut req, &options.password, host, port)?;
    stream.write_all(&req[..n]).await?;
    Ok(stream)
}

pub fn build_request(
    buffer: &mut [u8],
    password: &str,
    host: &str,
    port: u16,
) -> Result<usize, ProxyError> {
    sha224_hex_lower(password.as_bytes(), &mut buffer[..SHA224_HEX_SIZE]);
    buffer[SHA224_HEX_SIZE] = b'\r';
    buffer[SHA224_HEX_SIZE + 1] = b'\n';
    let mut offset = SHA224_HEX_SIZE + 2;
    buffer[offset] = CMD_TCP;
    offset += 1;
    offset += ProxyAddress::write_type_and_address(
        host,
        &mut buffer[offset..],
        ATYP_IPV4,
        ATYP_DOMAIN,
        ATYP_IPV6,
    )?;
    buffer[offset..offset + 2].copy_from_slice(&port.to_be_bytes());
    offset += 2;
    buffer[offset] = b'\r';
    buffer[offset + 1] = b'\n';
    Ok(offset + 2)
}
