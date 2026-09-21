use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::address::ProxyAddress;
use crate::error::{ProxyError, ProxyErrorCode};
use crate::options::SocksOptions;
use crate::BoxedStream;

pub async fn dial_socks5(
    mut stream: BoxedStream,
    options: &SocksOptions,
    dest_host: &str,
    dest_port: u16,
) -> Result<BoxedStream, ProxyError> {
    let user = options.username.as_deref().unwrap_or("");
    let pass = options.password.as_deref().unwrap_or("");
    if user.is_empty() {
        stream.write_all(&[0x05, 0x01, 0x00]).await?;
    } else {
        stream.write_all(&[0x05, 0x02, 0x00, 0x02]).await?;
    }
    stream.flush().await?;
    let mut sel = [0u8; 2];
    stream.read_exact(&mut sel).await?;
    if sel[0] != 0x05 {
        return Err(ProxyError::new(
            ProxyErrorCode::InvalidResponse,
            "SOCKS5 version mismatch",
        ));
    }
    match sel[1] {
        0x00 => {}
        0x02 => {
            if user.is_empty() {
                return Err(ProxyError::new(
                    ProxyErrorCode::AuthRequired,
                    "SOCKS5 server requested username/password",
                ));
            }
            let mut auth = Vec::with_capacity(3 + user.len() + pass.len());
            auth.push(0x01);
            auth.push(user.len() as u8);
            auth.extend_from_slice(user.as_bytes());
            auth.push(pass.len() as u8);
            auth.extend_from_slice(pass.as_bytes());
            stream.write_all(&auth).await?;
            stream.flush().await?;
            let mut resp = [0u8; 2];
            stream.read_exact(&mut resp).await?;
            if resp[1] != 0x00 {
                return Err(ProxyError::new(
                    ProxyErrorCode::AuthFailed,
                    "SOCKS5 authentication failed",
                ));
            }
        }
        0xff => {
            return Err(ProxyError::new(
                ProxyErrorCode::AuthFailed,
                "SOCKS5 no acceptable auth method",
            ));
        }
        other => {
            return Err(ProxyError::new(
                ProxyErrorCode::InvalidResponse,
                format!("SOCKS5 auth method {other}"),
            ));
        }
    }

    let mut req = vec![0x05, 0x01, 0x00];
    let mut addr = [0u8; 2 + ProxyAddress::MAX_LENGTH];
    let n = ProxyAddress::write_socks_port_last(dest_host, dest_port, &mut addr)?;
    req.extend_from_slice(&addr[..n]);
    stream.write_all(&req).await?;
    stream.flush().await?;

    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    if head[0] != 0x05 || head[1] != 0x00 {
        return Err(ProxyError::new(
            ProxyErrorCode::InvalidResponse,
            format!("SOCKS5 connect failed status {}", head[1]),
        ));
    }
    let rest = match head[3] {
        0x01 => 4 + 2,
        0x04 => 16 + 2,
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            len[0] as usize + 2
        }
        other => {
            return Err(ProxyError::new(
                ProxyErrorCode::InvalidResponse,
                format!("SOCKS5 bind atyp {other}"),
            ));
        }
    };
    let mut skip = vec![0u8; rest];
    stream.read_exact(&mut skip).await?;
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::options::SocksOptions;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    #[tokio::test]
    async fn socks5_noauth_handshake() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut greeting = [0u8; 2];
            socket.read_exact(&mut greeting).await.unwrap();
            let mut methods = vec![0u8; greeting[1] as usize];
            socket.read_exact(&mut methods).await.unwrap();
            socket.write_all(&[0x05, 0x00]).await.unwrap();
            let mut request = [0u8; 4];
            socket.read_exact(&mut request).await.unwrap();
            let address_len = match request[3] {
                0x01 => 4,
                0x04 => 16,
                0x03 => {
                    let mut len = [0u8; 1];
                    socket.read_exact(&mut len).await.unwrap();
                    len[0] as usize
                }
                other => panic!("{other}"),
            };
            let mut rest = vec![0u8; address_len + 2];
            socket.read_exact(&mut rest).await.unwrap();
            socket
                .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
        });
        let tcp = TcpStream::connect(addr).await.unwrap();
        let opts = SocksOptions {
            username: None,
            password: None,
        };
        dial_socks5(Box::pin(tcp), &opts, "example.com", 80)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn socks5_userpass_tunnels_payload() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut greeting = [0u8; 2];
            socket.read_exact(&mut greeting).await.unwrap();
            let mut methods = vec![0u8; greeting[1] as usize];
            socket.read_exact(&mut methods).await.unwrap();
            assert!(methods.contains(&0x02));
            socket.write_all(&[0x05, 0x02]).await.unwrap();
            let mut ulen = [0u8; 2];
            socket.read_exact(&mut ulen).await.unwrap();
            assert_eq!(ulen[0], 0x01);
            let mut user = vec![0u8; ulen[1] as usize];
            socket.read_exact(&mut user).await.unwrap();
            let mut plen = [0u8; 1];
            socket.read_exact(&mut plen).await.unwrap();
            let mut pass = vec![0u8; plen[0] as usize];
            socket.read_exact(&mut pass).await.unwrap();
            assert_eq!(user, b"alice");
            assert_eq!(pass, b"secret");
            socket.write_all(&[0x01, 0x00]).await.unwrap();
            let mut request = [0u8; 4];
            socket.read_exact(&mut request).await.unwrap();
            let address_len = match request[3] {
                0x01 => 4,
                0x04 => 16,
                0x03 => {
                    let mut len = [0u8; 1];
                    socket.read_exact(&mut len).await.unwrap();
                    len[0] as usize
                }
                other => panic!("{other}"),
            };
            let mut rest = vec![0u8; address_len + 2];
            socket.read_exact(&mut rest).await.unwrap();
            socket
                .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            let mut buf = [0u8; 32];
            let n = socket.read(&mut buf).await.unwrap();
            socket.write_all(&buf[..n]).await.unwrap();
            socket.flush().await.unwrap();
            let _ = tokio::io::AsyncWriteExt::shutdown(&mut socket).await;
            let mut hold = [0u8; 1];
            let _ = socket.read(&mut hold).await;
        });
        let tcp = TcpStream::connect(addr).await.unwrap();
        let opts = SocksOptions {
            username: Some("alice".into()),
            password: Some("secret".into()),
        };
        let mut stream = dial_socks5(Box::pin(tcp), &opts, "example.com", 80)
            .await
            .unwrap();
        stream.write_all(b"ping-socks").await.unwrap();
        stream.flush().await.unwrap();
        let mut buf = [0u8; 10];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping-socks");
        let _ = stream.shutdown().await;
        server.await.unwrap();
    }
}
