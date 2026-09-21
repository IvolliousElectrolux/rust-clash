use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::error::{ProxyError, ProxyErrorCode};
use crate::options::HttpProxyOptions;
use crate::BoxedStream;

pub async fn dial_http_connect(
    mut stream: BoxedStream,
    options: &HttpProxyOptions,
    dest_host: &str,
    dest_port: u16,
) -> Result<BoxedStream, ProxyError> {
    let host_port = if dest_host.contains(':') {
        format!("[{dest_host}]:{dest_port}")
    } else {
        format!("{dest_host}:{dest_port}")
    };
    let mut req = format!("CONNECT {host_port} HTTP/1.1\r\nHost: {host_port}\r\n");
    if let (Some(user), Some(pass)) = (&options.username, &options.password) {
        if !user.is_empty() {
            let token = base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                format!("{user}:{pass}"),
            );
            req.push_str(&format!("Proxy-Authorization: Basic {token}\r\n"));
        }
    }
    req.push_str("Proxy-Connection: Keep-Alive\r\n\r\n");
    stream.write_all(req.as_bytes()).await?;
    stream.flush().await?;

    let mut buf = Vec::with_capacity(256);
    loop {
        let mut b = [0u8; 1];
        stream.read_exact(&mut b).await?;
        buf.push(b[0]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if buf.len() > 8192 {
            return Err(ProxyError::new(
                ProxyErrorCode::InvalidResponse,
                "HTTP CONNECT response too large",
            ));
        }
    }
    let head = String::from_utf8_lossy(&buf);
    let status = head.lines().next().unwrap_or("");
    if !status.contains(" 200") {
        return Err(ProxyError::new(
            ProxyErrorCode::InvalidResponse,
            format!("HTTP CONNECT failed: {status}"),
        ));
    }
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::options::HttpProxyOptions;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    #[tokio::test]
    async fn http_connect_200() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 512];
            let n = socket.read(&mut buf).await.unwrap();
            let text = String::from_utf8_lossy(&buf[..n]);
            assert!(text.starts_with("CONNECT example.com:443"));
            socket
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .unwrap();
        });
        let tcp = TcpStream::connect(addr).await.unwrap();
        let opts = HttpProxyOptions {
            username: None,
            password: None,
        };
        dial_http_connect(Box::pin(tcp), &opts, "example.com", 443)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn http_connect_tunnels_payload() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut acc = Vec::new();
            let mut tmp = [0u8; 1];
            loop {
                socket.read_exact(&mut tmp).await.unwrap();
                acc.push(tmp[0]);
                if acc.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let text = String::from_utf8_lossy(&acc);
            assert!(text.contains("CONNECT 1.2.3.4:80"));
            assert!(text.contains("Proxy-Authorization: Basic "));
            socket
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
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
        let opts = HttpProxyOptions {
            username: Some("user".into()),
            password: Some("pass".into()),
        };
        let mut stream = dial_http_connect(Box::pin(tcp), &opts, "1.2.3.4", 80)
            .await
            .unwrap();
        stream.write_all(b"ping-http").await.unwrap();
        stream.flush().await.unwrap();
        let mut buf = [0u8; 9];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping-http");
        let _ = stream.shutdown().await;
        server.await.unwrap();
    }
}
