use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::BoxedStream;
use crate::address::ProxyAddress;
use crate::crypto::{UUID_SIZE, uuid_write_be};
use crate::error::{ProxyError, ProxyErrorCode};
use crate::options::VlessOptions;
use crate::vision::{VISION_FLOW, VisionStream};

const VERSION: u8 = 0x00;
const CMD_TCP: u8 = 0x01;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x02;
const ATYP_IPV6: u8 = 0x03;
const ADDONS_FLOW_TAG: u8 = 0x0A;

pub async fn establish_vless(
    mut stream: BoxedStream,
    options: &VlessOptions,
    host: &str,
    port: u16,
) -> Result<BoxedStream, ProxyError> {
    let vision = options
        .flow
        .as_deref()
        .is_some_and(|f| f.eq_ignore_ascii_case(VISION_FLOW));
    let mut req = [0u8; 1 + UUID_SIZE + 1 + 2 + VISION_FLOW.len() + 1 + 2 + ProxyAddress::MAX_LENGTH];
    let n = build_request(&mut req, &options.id, host, port, vision)?;
    stream.write_all(&req[..n]).await?;
    stream.flush().await?;

    let session = VlessResponseStream {
        inner: stream,
        host: host.to_string(),
        port,
        header_read: false,
        pending: Vec::new(),
        addons_left: None,
    };
    if !vision {
        return Ok(Box::pin(session));
    }
    let mut uuid = [0u8; UUID_SIZE];
    if !uuid_write_be(&options.id, &mut uuid) {
        return Err(ProxyError::new(
            ProxyErrorCode::AuthRequired,
            "VLESS user id is unusable",
        ));
    }
    Ok(Box::pin(VisionStream::new(Box::pin(session), uuid)))
}

fn build_request(
    buffer: &mut [u8],
    id: &str,
    host: &str,
    port: u16,
    vision: bool,
) -> Result<usize, ProxyError> {
    buffer[0] = VERSION;
    if !uuid_write_be(id, &mut buffer[1..1 + UUID_SIZE]) {
        return Err(ProxyError::new(
            ProxyErrorCode::AuthRequired,
            format!("VLESS user id '{id}' is unusable"),
        ));
    }
    let mut offset = 1 + UUID_SIZE;
    if vision {
        let flow = VISION_FLOW.as_bytes();
        buffer[offset] = (2 + flow.len()) as u8;
        offset += 1;
        buffer[offset] = ADDONS_FLOW_TAG;
        offset += 1;
        buffer[offset] = flow.len() as u8;
        offset += 1;
        buffer[offset..offset + flow.len()].copy_from_slice(flow);
        offset += flow.len();
    } else {
        buffer[offset] = 0;
        offset += 1;
    }
    buffer[offset] = CMD_TCP;
    offset += 1;
    buffer[offset..offset + 2].copy_from_slice(&port.to_be_bytes());
    offset += 2;
    offset += ProxyAddress::write_type_and_address(
        host,
        &mut buffer[offset..],
        ATYP_IPV4,
        ATYP_DOMAIN,
        ATYP_IPV6,
    )?;
    Ok(offset)
}

pub struct VlessResponseStream {
    pub inner: BoxedStream,
    host: String,
    port: u16,
    header_read: bool,
    pending: Vec<u8>,
    addons_left: Option<usize>,
}

impl VlessResponseStream {
    pub(crate) fn take_pending(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.pending)
    }

    fn handshake_eof(&self) -> std::io::Error {
        std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            format!(
                "VLESS server closed the connection before completing the handshake for {}:{} (wrong UUID or rejected request?).",
                self.host, self.port
            ),
        )
    }
}

impl AsyncRead for VlessResponseStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use std::task::Poll;
        loop {
            if self.header_read {
                if !self.pending.is_empty() {
                    let n = self.pending.len().min(buf.remaining());
                    buf.put_slice(&self.pending[..n]);
                    self.pending.drain(..n);
                    return Poll::Ready(Ok(()));
                }
                return std::pin::Pin::new(&mut self.inner).poll_read(cx, buf);
            }
            if let Some(left) = self.addons_left {
                if self.pending.len() >= left {
                    self.pending.drain(..left);
                    self.header_read = true;
                    continue;
                }
            } else if self.pending.len() >= 2 {
                if self.pending[0] != VERSION {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "Unexpected VLESS response version. Expected 0x00, got 0x{:02X}.",
                            self.pending[0]
                        ),
                    )));
                }
                self.addons_left = Some(self.pending[1] as usize);
                self.pending.drain(..2);
                continue;
            }
            let mut tmp = [0u8; 256];
            let mut rb = tokio::io::ReadBuf::new(&mut tmp);
            match std::pin::Pin::new(&mut self.inner).poll_read(cx, &mut rb) {
                Poll::Ready(Ok(())) => {
                    let n = rb.filled().len();
                    if n == 0 {
                        return Poll::Ready(Err(self.handshake_eof()));
                    }
                    self.pending.extend_from_slice(&tmp[..n]);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for VlessResponseStream {
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

