use std::io::Cursor;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use base64::Engine;
use rand::RngCore;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::io::poll_write_buf;

use crate::error::{ProxyError, ProxyErrorCode};
use crate::options::SsOptions;
use crate::{AsyncIo, BoxedStream};

pub fn apply_plugin(
    stream: BoxedStream,
    plugin: &str,
    plugin_opts: Option<&str>,
    options: &SsOptions,
) -> Result<BoxedStream, ProxyError> {
    let plugin = plugin.trim().to_ascii_lowercase();
    if plugin.is_empty() || plugin == "none" {
        return Ok(stream);
    }
    let opts = parse_opts(plugin_opts.unwrap_or(""));
    match plugin.as_str() {
        "obfs" | "obfs-local" | "simple-obfs" => {
            let mode = opts
                .get("obfs")
                .or_else(|| opts.get("mode"))
                .map(|s| s.to_ascii_lowercase())
                .unwrap_or_else(|| "http".into());
            let host = opts
                .get("obfs-host")
                .or_else(|| opts.get("host"))
                .cloned()
                .unwrap_or_else(|| options.host.clone());
            let path = opts
                .get("obfs-uri")
                .or_else(|| opts.get("path"))
                .cloned()
                .unwrap_or_else(|| "/".into());
            match mode.as_str() {
                "http" => Ok(Box::pin(HttpObfsStream::new(stream, path, host))),
                "tls" => Ok(Box::pin(TlsObfsStream::new(stream, host))),
                other => Err(ProxyError::new(
                    ProxyErrorCode::TransportUpgradeFailed,
                    format!("unsupported simple-obfs mode {other}"),
                )),
            }
        }
        other => Err(ProxyError::new(
            ProxyErrorCode::TransportUpgradeFailed,
            format!("unsupported shadowsocks plugin {other}"),
        )),
    }
}

fn parse_opts(s: &str) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    for part in s.split([';', '&']).filter(|p| !p.is_empty()) {
        if let Some((k, v)) = part.split_once('=') {
            map.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        } else if let Some((k, v)) = part.split_once(':') {
            map.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }
    map
}

enum HttpRead {
    Header { buf: Vec<u8> },
    Leftover { data: Cursor<Vec<u8>> },
    Transfer,
}

enum HttpWrite {
    First,
    Flush(Cursor<Vec<u8>>),
    Transfer,
}

pub struct HttpObfsStream {
    inner: BoxedStream,
    path: String,
    host: String,
    read: HttpRead,
    write: HttpWrite,
}

impl HttpObfsStream {
    pub fn new(inner: BoxedStream, path: String, host: String) -> Self {
        Self {
            inner,
            path,
            host,
            read: HttpRead::Header {
                buf: Vec::with_capacity(1024),
            },
            write: HttpWrite::First,
        }
    }
}

impl AsyncIo for HttpObfsStream {}

impl AsyncRead for HttpObfsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        loop {
            match std::mem::replace(&mut self.read, HttpRead::Transfer) {
                HttpRead::Header { buf: mut acc } => {
                    if acc.len() > 4096 {
                        self.read = HttpRead::Header { buf: acc };
                        return Poll::Ready(Err(std::io::Error::other("obfs http response too large")));
                    }
                    let mut tmp = [0u8; 256];
                    let mut rbuf = ReadBuf::new(&mut tmp);
                    match Pin::new(&mut self.inner).poll_read(cx, &mut rbuf) {
                        Poll::Pending => {
                            self.read = HttpRead::Header { buf: acc };
                            return Poll::Pending;
                        }
                        Poll::Ready(Err(e)) => {
                            self.read = HttpRead::Header { buf: acc };
                            return Poll::Ready(Err(e));
                        }
                        Poll::Ready(Ok(())) => {
                            if rbuf.filled().is_empty() {
                                self.read = HttpRead::Header { buf: acc };
                                return Poll::Ready(Err(std::io::Error::new(
                                    std::io::ErrorKind::UnexpectedEof,
                                    "obfs http eof",
                                )));
                            }
                            acc.extend_from_slice(rbuf.filled());
                            if let Some(pos) = find_header_end(&acc) {
                                let leftover = acc.split_off(pos);
                                self.read = HttpRead::Leftover {
                                    data: Cursor::new(leftover),
                                };
                            } else {
                                self.read = HttpRead::Header { buf: acc };
                            }
                        }
                    }
                }
                HttpRead::Leftover { mut data } => {
                    let remaining = data.get_ref().len() - data.position() as usize;
                    if remaining == 0 {
                        self.read = HttpRead::Transfer;
                        continue;
                    }
                    let n = remaining.min(buf.remaining());
                    let start = data.position() as usize;
                    buf.put_slice(&data.get_ref()[start..start + n]);
                    data.set_position((start + n) as u64);
                    if data.position() as usize == data.get_ref().len() {
                        self.read = HttpRead::Transfer;
                    } else {
                        self.read = HttpRead::Leftover { data };
                    }
                    return Poll::Ready(Ok(()));
                }
                HttpRead::Transfer => {
                    self.read = HttpRead::Transfer;
                    return Pin::new(&mut self.inner).poll_read(cx, buf);
                }
            }
        }
    }
}

impl AsyncWrite for HttpObfsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        loop {
            match std::mem::replace(&mut self.write, HttpWrite::Transfer) {
                HttpWrite::First => {
                    let req = build_http_request(&self.path, &self.host, buf);
                    self.write = HttpWrite::Flush(Cursor::new(req));
                }
                HttpWrite::Flush(mut cur) => {
                    match poll_write_buf(Pin::new(&mut self.inner), cx, &mut cur) {
                        Poll::Pending => {
                            self.write = HttpWrite::Flush(cur);
                            return Poll::Pending;
                        }
                        Poll::Ready(Err(e)) => {
                            self.write = HttpWrite::Flush(cur);
                            return Poll::Ready(Err(e));
                        }
                        Poll::Ready(Ok(_)) => {
                            if cur.position() as usize >= cur.get_ref().len() {
                                self.write = HttpWrite::Transfer;
                                return Poll::Ready(Ok(buf.len()));
                            }
                            self.write = HttpWrite::Flush(cur);
                        }
                    }
                }
                HttpWrite::Transfer => {
                    self.write = HttpWrite::Transfer;
                    break;
                }
            }
        }
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

fn build_http_request(path: &str, host: &str, body: &[u8]) -> Vec<u8> {
    let mut key = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut key);
    let ws = base64::engine::general_purpose::STANDARD.encode(key);
    let path = if path.is_empty() { "/" } else { path };
    format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: curl/7.{}.{}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {ws}\r\nContent-Length: {}\r\n\r\n",
        rand::random::<u32>() % 51,
        rand::random::<u32>() % 2,
        body.len()
    )
    .into_bytes()
    .into_iter()
    .chain(body.iter().copied())
    .collect()
}

const TLS_RECORD: [u8; 3] = [0x17, 0x03, 0x03];
const HELLO_SKIP: usize = 96 + 6 + 3;

#[derive(Clone, Copy)]
enum TlsRead {
    Skip { left: usize },
    Hdr { got: usize, hdr: [u8; 5] },
    Body { left: usize },
}

enum TlsWrite {
    Hello,
    Flush(Cursor<Vec<u8>>),
    RecHdr { payload: u16, off: usize },
    RecBody { left: usize },
}

pub struct TlsObfsStream {
    inner: BoxedStream,
    host: String,
    read: TlsRead,
    write: TlsWrite,
}

impl TlsObfsStream {
    pub fn new(inner: BoxedStream, host: String) -> Self {
        Self {
            inner,
            host,
            read: TlsRead::Skip { left: HELLO_SKIP },
            write: TlsWrite::Hello,
        }
    }
}

impl AsyncIo for TlsObfsStream {}

impl AsyncRead for TlsObfsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        loop {
            match self.read {
                TlsRead::Skip { left } => {
                    let mut tmp = [0u8; 128];
                    let n = left.min(tmp.len());
                    let mut rbuf = ReadBuf::new(&mut tmp[..n]);
                    ready!(Pin::new(&mut self.inner).poll_read(cx, &mut rbuf))?;
                    let got = rbuf.filled().len();
                    if got == 0 {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "obfs tls hello eof",
                        )));
                    }
                    let left = left - got;
                    self.read = if left == 0 {
                        TlsRead::Hdr {
                            got: 0,
                            hdr: [0; 5],
                        }
                    } else {
                        TlsRead::Skip { left }
                    };
                }
                TlsRead::Hdr { got, mut hdr } => {
                    let mut rbuf = ReadBuf::new(&mut hdr[got..]);
                    ready!(Pin::new(&mut self.inner).poll_read(cx, &mut rbuf))?;
                    let n = rbuf.filled().len();
                    if n == 0 {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "obfs tls header eof",
                        )));
                    }
                    let got = got + n;
                    if got < 5 {
                        self.read = TlsRead::Hdr { got, hdr };
                        continue;
                    }
                    let len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
                    self.read = TlsRead::Body { left: len };
                }
                TlsRead::Body { left } => {
                    let take = left.min(buf.remaining());
                    let unfilled = buf.initialize_unfilled();
                    let n = take.min(unfilled.len());
                    let mut rbuf = ReadBuf::new(&mut unfilled[..n]);
                    ready!(Pin::new(&mut self.inner).poll_read(cx, &mut rbuf))?;
                    let got = rbuf.filled().len();
                    if got == 0 {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "obfs tls body eof",
                        )));
                    }
                    buf.advance(got);
                    let left = left - got;
                    self.read = if left == 0 {
                        TlsRead::Hdr {
                            got: 0,
                            hdr: [0; 5],
                        }
                    } else {
                        TlsRead::Body { left }
                    };
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}

impl AsyncWrite for TlsObfsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        const MAX: usize = 16 * 1024;
        loop {
            match std::mem::replace(&mut self.write, TlsWrite::RecBody { left: 0 }) {
                TlsWrite::Hello => {
                    let chunk = &buf[..buf.len().min(MAX)];
                    let hello = build_tls_client_hello(self.host.as_bytes(), chunk);
                    self.write = TlsWrite::Flush(Cursor::new(hello));
                }
                TlsWrite::Flush(mut cur) => {
                    match poll_write_buf(Pin::new(&mut self.inner), cx, &mut cur) {
                        Poll::Pending => {
                            self.write = TlsWrite::Flush(cur);
                            return Poll::Pending;
                        }
                        Poll::Ready(Err(e)) => {
                            self.write = TlsWrite::Flush(cur);
                            return Poll::Ready(Err(e));
                        }
                        Poll::Ready(Ok(_)) => {
                            if cur.position() as usize >= cur.get_ref().len() {
                                self.write = TlsWrite::RecBody { left: 0 };
                                return Poll::Ready(Ok(buf.len().min(MAX)));
                            }
                            self.write = TlsWrite::Flush(cur);
                        }
                    }
                }
                TlsWrite::RecHdr { payload, mut off } => {
                    let mut hdr = [TLS_RECORD[0], TLS_RECORD[1], TLS_RECORD[2], 0, 0];
                    hdr[3..].copy_from_slice(&payload.to_be_bytes());
                    match Pin::new(&mut self.inner).poll_write(cx, &hdr[off..]) {
                        Poll::Pending => {
                            self.write = TlsWrite::RecHdr { payload, off };
                            return Poll::Pending;
                        }
                        Poll::Ready(Err(e)) => {
                            self.write = TlsWrite::RecHdr { payload, off };
                            return Poll::Ready(Err(e));
                        }
                        Poll::Ready(Ok(0)) => {
                            self.write = TlsWrite::RecHdr { payload, off };
                            return Poll::Ready(Err(std::io::Error::new(
                                std::io::ErrorKind::WriteZero,
                                "obfs tls header",
                            )));
                        }
                        Poll::Ready(Ok(n)) => {
                            off += n;
                            if off >= 5 {
                                self.write = TlsWrite::RecBody {
                                    left: payload as usize,
                                };
                            } else {
                                self.write = TlsWrite::RecHdr { payload, off };
                            }
                        }
                    }
                }
                TlsWrite::RecBody { left: 0 } => {
                    let n = buf.len().min(MAX) as u16;
                    self.write = TlsWrite::RecHdr {
                        payload: n,
                        off: 0,
                    };
                }
                TlsWrite::RecBody { left } => {
                    match Pin::new(&mut self.inner).poll_write(cx, &buf[..buf.len().min(left)]) {
                        Poll::Pending => {
                            self.write = TlsWrite::RecBody { left };
                            return Poll::Pending;
                        }
                        Poll::Ready(Err(e)) => {
                            self.write = TlsWrite::RecBody { left };
                            return Poll::Ready(Err(e));
                        }
                        Poll::Ready(Ok(0)) => {
                            self.write = TlsWrite::RecBody { left };
                            return Poll::Ready(Err(std::io::Error::new(
                                std::io::ErrorKind::WriteZero,
                                "obfs tls body",
                            )));
                        }
                        Poll::Ready(Ok(n)) => {
                            self.write = TlsWrite::RecBody { left: left - n };
                            return Poll::Ready(Ok(n));
                        }
                    }
                }
            }
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

fn build_tls_client_hello(host: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut random = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut random);
    let unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32;
    random[..4].copy_from_slice(&unix.to_be_bytes());
    let mut session = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut session);

    let mut hello_body = Vec::new();
    hello_body.extend_from_slice(&0x0303u16.to_be_bytes());
    hello_body.extend_from_slice(&random);
    hello_body.push(32);
    hello_body.extend_from_slice(&session);
    let suites: [u8; 56] = [
        0xc0, 0x2c, 0xc0, 0x30, 0x00, 0x9f, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0xaa, 0xc0, 0x2b, 0xc0,
        0x2f, 0x00, 0x9e, 0xc0, 0x24, 0xc0, 0x28, 0x00, 0x6b, 0xc0, 0x23, 0xc0, 0x27, 0x00, 0x67,
        0xc0, 0x0a, 0xc0, 0x14, 0x00, 0x39, 0xc0, 0x09, 0xc0, 0x13, 0x00, 0x33, 0x00, 0x9d, 0x00,
        0x9c, 0x00, 0x3d, 0x00, 0x3c, 0x00, 0x35, 0x00, 0x2f, 0x00, 0xff,
    ];
    hello_body.extend_from_slice(&(suites.len() as u16).to_be_bytes());
    hello_body.extend_from_slice(&suites);
    hello_body.push(1);
    hello_body.push(0);

    let mut ticket = Vec::new();
    ticket.extend_from_slice(&0x0023u16.to_be_bytes());
    ticket.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    ticket.extend_from_slice(payload);

    let mut sni = Vec::new();
    sni.extend_from_slice(&0x0000u16.to_be_bytes());
    let sni_inner_len = 3 + host.len();
    sni.extend_from_slice(&((sni_inner_len + 2) as u16).to_be_bytes());
    sni.extend_from_slice(&(sni_inner_len as u16).to_be_bytes());
    sni.push(0);
    sni.extend_from_slice(&(host.len() as u16).to_be_bytes());
    sni.extend_from_slice(host);

    let others = [
        0x00, 0x0b, 0x00, 0x04, 0x03, 0x01, 0x00, 0x02, 0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x00,
        0x1d, 0x00, 0x17, 0x00, 0x19, 0x00, 0x18, 0x00, 0x0d, 0x00, 0x20, 0x00, 0x1e, 0x06, 0x01,
        0x06, 0x02, 0x06, 0x03, 0x05, 0x01, 0x05, 0x02, 0x05, 0x03, 0x04, 0x01, 0x04, 0x02, 0x04,
        0x03, 0x03, 0x01, 0x03, 0x02, 0x03, 0x03, 0x02, 0x01, 0x02, 0x02, 0x02, 0x03, 0x00, 0x16,
        0x00, 0x00, 0x00, 0x17, 0x00, 0x00,
    ];

    let ext_len = ticket.len() + sni.len() + others.len();
    hello_body.extend_from_slice(&(ext_len as u16).to_be_bytes());
    hello_body.extend_from_slice(&ticket);
    hello_body.extend_from_slice(&sni);
    hello_body.extend_from_slice(&others);

    let hs_len = hello_body.len();
    let rec_len = 4 + hs_len;
    let mut out = Vec::with_capacity(5 + rec_len);
    out.push(0x16);
    out.extend_from_slice(&0x0301u16.to_be_bytes());
    out.extend_from_slice(&(rec_len as u16).to_be_bytes());
    out.push(0x01);
    out.push(((hs_len >> 16) & 0xff) as u8);
    out.extend_from_slice(&(hs_len as u16).to_be_bytes());
    out.extend_from_slice(&hello_body);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    #[tokio::test]
    async fn http_obfs_tunnels_payload() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut acc = Vec::new();
            let mut tmp = [0u8; 256];
            loop {
                let n = socket.read(&mut tmp).await.unwrap();
                acc.extend_from_slice(&tmp[..n]);
                if let Some(pos) = find_header_end(&acc) {
                    let body = acc[pos..].to_vec();
                    socket
                        .write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
                        .await
                        .unwrap();
                    socket.write_all(&body).await.unwrap();
                    socket.flush().await.unwrap();
                    let _ = socket.shutdown().await;
                    let mut hold = [0u8; 1];
                    let _ = socket.read(&mut hold).await;
                    break;
                }
            }
        });
        let tcp = TcpStream::connect(addr).await.unwrap();
        let mut stream = HttpObfsStream::new(Box::pin(tcp), "/".into(), "download.windowsupdate.com".into());
        stream.write_all(b"ping-obfs").await.unwrap();
        stream.flush().await.unwrap();
        let mut buf = [0u8; 9];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping-obfs");
        let _ = stream.shutdown().await;
        server.await.unwrap();
    }
}
