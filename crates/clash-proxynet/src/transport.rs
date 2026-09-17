use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use rand::RngCore;
use sha1::{Digest, Sha1};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::BoxedStream;
use crate::error::{ProxyError, ProxyErrorCode};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportKind {
    RawTcp,
    WebSocket,
    HttpUpgrade,
    Unsupported,
}

pub fn resolve_transport(transport: &str) -> TransportKind {
    if transport.is_empty() {
        return TransportKind::RawTcp;
    }
    match transport.to_ascii_lowercase().as_str() {
        "tcp" | "raw" => TransportKind::RawTcp,
        "ws" | "websocket" => TransportKind::WebSocket,
        "httpupgrade" => TransportKind::HttpUpgrade,
        _ => TransportKind::Unsupported,
    }
}

pub fn normalize_path(path: Option<&str>) -> String {
    match path {
        None | Some("") => "/".into(),
        Some(p) if p.starts_with('/') => p.to_string(),
        Some(p) => format!("/{p}"),
    }
}

pub fn resolve_host_header(host_header: Option<&str>, sni: Option<&str>, server_host: &str) -> String {
    if let Some(h) = host_header.filter(|s| !s.is_empty()) {
        return h.to_string();
    }
    if let Some(s) = sni.filter(|s| !s.is_empty()) {
        return s.to_string();
    }
    server_host.to_string()
}

pub async fn apply_transport(
    kind: TransportKind,
    mut stream: BoxedStream,
    path: Option<&str>,
    host_header: &str,
) -> Result<BoxedStream, ProxyError> {
    match kind {
        TransportKind::RawTcp => Ok(stream),
        TransportKind::WebSocket => {
            let leftover = http_upgrade(&mut stream, &normalize_path(path), host_header, true).await?;
            let ws = WebSocketStream::new(stream, leftover);
            Ok(Box::pin(ws))
        }
        TransportKind::HttpUpgrade => {
            let leftover = http_upgrade(&mut stream, &normalize_path(path), host_header, false).await?;
            if leftover.is_empty() {
                Ok(stream)
            } else {
                Ok(Box::pin(PrefixedStream { prefix: leftover, pos: 0, inner: stream }))
            }
        }
        TransportKind::Unsupported => Err(ProxyError::new(
            ProxyErrorCode::TransportUpgradeFailed,
            "unsupported transport",
        )),
    }
}

const WS_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

async fn http_upgrade(
    stream: &mut BoxedStream,
    path: &str,
    host: &str,
    websocket: bool,
) -> Result<Vec<u8>, ProxyError> {
    let mut key = [0u8; 16];
    let mut expected_accept = None;
    let mut req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
    );
    if websocket {
        rand::thread_rng().fill_bytes(&mut key);
        let key_b64 = STANDARD.encode(key);
        let mut challenge = Vec::with_capacity(24 + WS_GUID.len());
        challenge.extend_from_slice(key_b64.as_bytes());
        challenge.extend_from_slice(WS_GUID);
        let digest = Sha1::digest(&challenge);
        expected_accept = Some(STANDARD.encode(digest));
        req.push_str(&format!("Sec-WebSocket-Key: {key_b64}\r\nSec-WebSocket-Version: 13\r\n"));
    }
    req.push_str("\r\n");
    stream.write_all(req.as_bytes()).await?;

    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    loop {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return Err(ProxyError::new(
                ProxyErrorCode::TransportUpgradeFailed,
                "The proxy closed the connection during the HTTP upgrade handshake.",
            ));
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = find_header_end(&buf) {
            let header = &buf[..pos];
            let leftover = buf[pos..].to_vec();
            let status = parse_status(header).unwrap_or(-1);
            if status != 101 {
                return Err(ProxyError::new(
                    ProxyErrorCode::TransportUpgradeFailed,
                    if status < 0 {
                        "The proxy returned a malformed HTTP response to the upgrade request.".into()
                    } else {
                        format!(
                            "The proxy refused the HTTP upgrade with status {status} (expected 101). The configured path is the usual cause."
                        )
                    },
                ));
            }
            if let Some(expected) = expected_accept {
                let actual = header_value(header, b"sec-websocket-accept").ok_or_else(|| {
                    ProxyError::new(
                        ProxyErrorCode::TransportUpgradeFailed,
                        "The proxy accepted the upgrade but sent no Sec-WebSocket-Accept header.",
                    )
                })?;
                if actual != expected.as_bytes() {
                    return Err(ProxyError::new(
                        ProxyErrorCode::TransportUpgradeFailed,
                        "The proxy's Sec-WebSocket-Accept did not match the challenge.",
                    ));
                }
            }
            return Ok(leftover);
        }
        if buf.len() > 64 * 1024 {
            return Err(ProxyError::new(
                ProxyErrorCode::TransportUpgradeFailed,
                "HTTP upgrade response too large",
            ));
        }
    }
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

fn parse_status(header: &[u8]) -> Option<i32> {
    let line = header.split(|&b| b == b'\n').next()?;
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    let mut parts = line.split(|&b| b == b' ');
    parts.next()?;
    let code = parts.next()?;
    std::str::from_utf8(code).ok()?.parse().ok()
}

fn header_value<'a>(headers: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    let rest = headers.split(|&b| b == b'\n').skip(1);
    for line in rest {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            break;
        }
        let colon = line.iter().position(|&b| b == b':')?;
        if colon != name.len() {
            continue;
        }
        if !eq_ignore_ascii(&line[..colon], name) {
            continue;
        }
        let mut v = &line[colon + 1..];
        while v.first().is_some_and(|c| *c == b' ' || *c == b'\t') {
            v = &v[1..];
        }
        while v.last().is_some_and(|c| *c == b' ' || *c == b'\t') {
            v = &v[..v.len() - 1];
        }
        return Some(v);
    }
    None
}

fn eq_ignore_ascii(a: &[u8], lower: &[u8]) -> bool {
    a.len() == lower.len()
        && a.iter()
            .zip(lower)
            .all(|(x, y)| x.to_ascii_lowercase() == *y)
}

pub struct PrefixedStream {
    prefix: Vec<u8>,
    pos: usize,
    inner: BoxedStream,
}

impl PrefixedStream {
    pub fn wrap_if_needed(prefix: Vec<u8>, inner: BoxedStream) -> BoxedStream {
        if prefix.is_empty() {
            inner
        } else {
            Box::pin(Self { prefix, pos: 0, inner })
        }
    }
}

impl tokio::io::AsyncRead for PrefixedStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if self.pos < self.prefix.len() {
            let rem = &self.prefix[self.pos..];
            let n = rem.len().min(buf.remaining());
            buf.put_slice(&rem[..n]);
            self.pos += n;
            return std::task::Poll::Ready(Ok(()));
        }
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for PrefixedStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

pub(crate) struct WebSocketStream {
    inner: PrefixedStream,
    rx: Vec<u8>,
    decoded: Vec<u8>,
    decoded_pos: usize,
    empty_frames: u32,
    write_buf: Vec<u8>,
    write_pos: usize,
    write_payload: usize,
}

impl WebSocketStream {
    fn new(inner: BoxedStream, leftover: Vec<u8>) -> Self {
        Self {
            inner: PrefixedStream {
                prefix: leftover,
                pos: 0,
                inner,
            },
            rx: Vec::new(),
            decoded: Vec::new(),
            decoded_pos: 0,
            empty_frames: 0,
            write_buf: Vec::new(),
            write_pos: 0,
            write_payload: 0,
        }
    }
}

const MAX_EMPTY_FRAMES: u32 = 64;

enum WsEvent {
    Payload(Vec<u8>),
    Skip,
    Close,
}

fn parse_ws_frame(buf: &[u8]) -> Result<Option<(usize, WsEvent)>, std::io::Error> {
    if buf.len() < 2 {
        return Ok(None);
    }
    let b0 = buf[0];
    let b1 = buf[1];
    let opcode = b0 & 0x0F;
    let mut len = (b1 & 0x7F) as usize;
    let masked = b1 & 0x80 != 0;
    let mut off = 2usize;
    if len == 126 {
        if buf.len() < off + 2 {
            return Ok(None);
        }
        len = u16::from_be_bytes([buf[off], buf[off + 1]]) as usize;
        off += 2;
    } else if len == 127 {
        if buf.len() < off + 8 {
            return Ok(None);
        }
        let mut n = [0u8; 8];
        n.copy_from_slice(&buf[off..off + 8]);
        len = u64::from_be_bytes(n) as usize;
        off += 8;
    }
    let mut mask = [0u8; 4];
    if masked {
        if buf.len() < off + 4 {
            return Ok(None);
        }
        mask.copy_from_slice(&buf[off..off + 4]);
        off += 4;
    }
    if buf.len() < off + len {
        return Ok(None);
    }
    let mut payload = buf[off..off + len].to_vec();
    if masked {
        for (i, b) in payload.iter_mut().enumerate() {
            *b ^= mask[i % 4];
        }
    }
    let consumed = off + len;
    let event = match opcode {
        0x8 => WsEvent::Close,
        0x9 | 0xA => WsEvent::Skip,
        _ => WsEvent::Payload(payload),
    };
    Ok(Some((consumed, event)))
}

fn encode_client_binary_frame(payload: &[u8]) -> Vec<u8> {
    let mask = mask_key();
    let mut frame = Vec::with_capacity(14 + payload.len());
    frame.push(0x82);
    let n = payload.len();
    if n < 126 {
        frame.push(0x80 | n as u8);
    } else if n <= 65535 {
        frame.push(0x80 | 126);
        frame.extend_from_slice(&(n as u16).to_be_bytes());
    } else {
        frame.push(0x80 | 127);
        frame.extend_from_slice(&(n as u64).to_be_bytes());
    }
    frame.extend_from_slice(&mask);
    for (i, b) in payload.iter().enumerate() {
        frame.push(b ^ mask[i % 4]);
    }
    frame
}

fn mask_key() -> [u8; 4] {
    let mut k = [0u8; 4];
    rand::thread_rng().fill_bytes(&mut k);
    k
}

impl tokio::io::AsyncRead for WebSocketStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use std::task::Poll;
        loop {
            if self.decoded_pos < self.decoded.len() {
                let n = (self.decoded.len() - self.decoded_pos).min(buf.remaining());
                buf.put_slice(&self.decoded[self.decoded_pos..self.decoded_pos + n]);
                self.decoded_pos += n;
                if self.decoded_pos == self.decoded.len() {
                    self.decoded.clear();
                    self.decoded_pos = 0;
                }
                return Poll::Ready(Ok(()));
            }
            while let Some((n, ev)) = parse_ws_frame(&self.rx)? {
                self.rx.drain(..n);
                match ev {
                    WsEvent::Close => return Poll::Ready(Ok(())),
                    WsEvent::Skip => continue,
                    WsEvent::Payload(p) if p.is_empty() => {
                        self.empty_frames += 1;
                        if self.empty_frames > MAX_EMPTY_FRAMES {
                            return Poll::Ready(Err(std::io::Error::other(format!(
                                "The WebSocket peer sent {MAX_EMPTY_FRAMES} consecutive frames carrying no data."
                            ))));
                        }
                    }
                    WsEvent::Payload(p) => {
                        self.empty_frames = 0;
                        self.decoded = p;
                        self.decoded_pos = 0;
                        break;
                    }
                }
            }
            if self.decoded_pos < self.decoded.len() {
                continue;
            }
            let mut tmp = [0u8; 4096];
            let mut rb = tokio::io::ReadBuf::new(&mut tmp);
            match std::pin::Pin::new(&mut self.inner).poll_read(cx, &mut rb) {
                Poll::Ready(Ok(())) => {
                    let n = rb.filled().len();
                    if n == 0 {
                        return Poll::Ready(Ok(()));
                    }
                    self.rx.extend_from_slice(&tmp[..n]);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl tokio::io::AsyncWrite for WebSocketStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        use std::task::Poll;
        if buf.is_empty() && self.write_buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let this = self.as_mut().get_mut();
        if this.write_buf.is_empty() {
            if buf.is_empty() {
                return Poll::Ready(Ok(0));
            }
            this.write_payload = buf.len();
            this.write_buf = encode_client_binary_frame(buf);
            this.write_pos = 0;
        }
        while this.write_pos < this.write_buf.len() {
            match std::pin::Pin::new(&mut this.inner).poll_write(cx, &this.write_buf[this.write_pos..])
            {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "websocket write zero",
                    )));
                }
                Poll::Ready(Ok(n)) => this.write_pos += n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        let n = this.write_payload;
        this.write_buf.clear();
        this.write_pos = 0;
        this.write_payload = 0;
        Poll::Ready(Ok(n))
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_unmasked_binary_frame() {
        let mut frame = vec![0x82, 0x05];
        frame.extend_from_slice(b"hello");
        let (n, ev) = parse_ws_frame(&frame).unwrap().unwrap();
        assert_eq!(n, 7);
        match ev {
            WsEvent::Payload(p) => assert_eq!(p, b"hello"),
            _ => panic!("expected payload"),
        }
    }

    #[test]
    fn incomplete_frame_returns_none() {
        assert!(parse_ws_frame(&[0x82, 0x05, b'h']).unwrap().is_none());
    }
}
