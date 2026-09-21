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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    #[tokio::test]
    async fn trojan_tcp_tunnels_payload() {
        let password = "trojan-secret";
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let expect_hash = {
            let mut h = [0u8; SHA224_HEX_SIZE];
            sha224_hex_lower(password.as_bytes(), &mut h);
            h
        };
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut hash = [0u8; SHA224_HEX_SIZE + 2];
            socket.read_exact(&mut hash).await.unwrap();
            assert_eq!(&hash[..SHA224_HEX_SIZE], &expect_hash);
            assert_eq!(&hash[SHA224_HEX_SIZE..], b"\r\n");
            let mut cmd = [0u8; 1];
            socket.read_exact(&mut cmd).await.unwrap();
            assert_eq!(cmd[0], CMD_TCP);
            let mut atyp = [0u8; 1];
            socket.read_exact(&mut atyp).await.unwrap();
            let n = match atyp[0] {
                ATYP_IPV4 => 4,
                ATYP_IPV6 => 16,
                ATYP_DOMAIN => {
                    let mut len = [0u8; 1];
                    socket.read_exact(&mut len).await.unwrap();
                    len[0] as usize
                }
                other => panic!("{other}"),
            };
            let mut rest = vec![0u8; n + 2 + 2];
            socket.read_exact(&mut rest).await.unwrap();
            assert_eq!(&rest[n + 2..], b"\r\n");
            let mut buf = [0u8; 32];
            let n = socket.read(&mut buf).await.unwrap();
            socket.write_all(&buf[..n]).await.unwrap();
            socket.flush().await.unwrap();
            let _ = tokio::io::AsyncWriteExt::shutdown(&mut socket).await;
            let mut hold = [0u8; 1];
            let _ = socket.read(&mut hold).await;
        });
        let tcp = TcpStream::connect(addr).await.unwrap();
        let opts = TrojanOptions {
            password: password.into(),
            host: addr.ip().to_string(),
            port: addr.port(),
            transport: "tcp".into(),
            path: None,
            host_header: None,
            sni: None,
            alpn: Vec::new(),
            allow_insecure: false,
        };
        let mut stream = establish_trojan(Box::pin(tcp), &opts, "example.com", 443)
            .await
            .unwrap();
        stream.write_all(b"ping-trojan").await.unwrap();
        stream.flush().await.unwrap();
        let mut buf = [0u8; 11];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping-trojan");
        let _ = stream.shutdown().await;
        server.await.unwrap();
    }
}
