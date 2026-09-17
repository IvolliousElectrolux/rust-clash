use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::BoxedStream;
use crate::error::ProxyError;
use crate::reality::record::{ContentType, TlsRecordStream};
use crate::shared::SharedStream;

const HANDSHAKE_NEW_SESSION_TICKET: u8 = 4;
const HANDSHAKE_KEY_UPDATE: u8 = 24;

pub struct RealityTlsStream {
    records: TlsRecordStream,
    shared: SharedStream,
    pending: Vec<u8>,
    pending_off: usize,
    owns_transport: bool,
    received_close: bool,
    empty_records: u32,
}

impl RealityTlsStream {
    pub(crate) fn new(records: TlsRecordStream, leftover: Vec<u8>, shared: SharedStream) -> Self {
        Self {
            records,
            shared,
            pending: leftover,
            pending_off: 0,
            owns_transport: true,
            received_close: false,
            empty_records: 0,
        }
    }

    pub fn steal_pending(&mut self) -> Vec<u8> {
        if self.pending_off >= self.pending.len() {
            return Vec::new();
        }
        let out = self.pending[self.pending_off..].to_vec();
        self.pending.clear();
        self.pending_off = 0;
        out
    }

    pub fn steal_inbound_leftover(&mut self) -> Vec<u8> {
        self.records.steal_inbound_leftover()
    }

    pub fn detach_transport(&mut self) -> BoxedStream {
        self.mark_transport_shared();
        let leftover = self.records.steal_inbound_leftover();
        crate::transport::PrefixedStream::wrap_if_needed(leftover, Box::pin(self.shared.clone()))
    }

    pub(crate) fn mark_transport_shared(&mut self) {
        self.owns_transport = false;
    }

    pub(crate) fn shared_handle(&self) -> SharedStream {
        self.shared.clone()
    }

    fn take_pending(&mut self, buf: &mut ReadBuf<'_>) -> usize {
        if self.pending_off >= self.pending.len() {
            return 0;
        }
        let rem = &self.pending[self.pending_off..];
        let n = rem.len().min(buf.remaining());
        buf.put_slice(&rem[..n]);
        self.pending_off += n;
        n
    }
}

impl AsyncRead for RealityTlsStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if self.take_pending(buf) > 0 {
            return Poll::Ready(Ok(()));
        }
        if self.received_close {
            return Poll::Ready(Ok(()));
        }
        poll_fill(&mut *self, cx, buf)
    }
}

fn poll_fill(
    this: &mut RealityTlsStream,
    cx: &mut Context<'_>,
    buf: &mut ReadBuf<'_>,
) -> Poll<std::io::Result<()>> {
    // TLS 1.3 servers send NewSessionTicket / CCS after the handshake. Those
    // records carry no application data. Returning Ready(Ok(())) with an empty
    // ReadBuf is EOF to tokio — Relay would tear down the download half and
    // new TLS (Google) would hang. C# FillAsync loops until it has payload.
    loop {
        match this.records.poll_read_record(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => {
                if e.code == crate::error::ProxyErrorCode::ConnectionFailed {
                    this.received_close = true;
                    return Poll::Ready(Ok(()));
                }
                return Poll::Ready(Err(std::io::Error::other(e.to_string())));
            }
            Poll::Ready(Ok(rec)) => match rec.ty {
                ContentType::ApplicationData if !rec.payload.is_empty() => {
                    this.empty_records = 0;
                    this.pending = rec.payload;
                    this.pending_off = 0;
                    this.take_pending(buf);
                    return Poll::Ready(Ok(()));
                }
                ContentType::ApplicationData | ContentType::ChangeCipherSpec => {
                    if let Err(e) = count_empty(this) {
                        return Poll::Ready(Err(e));
                    }
                }
                ContentType::Handshake => {
                    match rec.payload.first().copied() {
                        Some(HANDSHAKE_KEY_UPDATE) => {
                            return Poll::Ready(Err(std::io::Error::other(
                                "The server asked for a key update, which this client does not implement yet.",
                            )));
                        }
                        Some(HANDSHAKE_NEW_SESSION_TICKET) | None => {
                            if let Err(e) = count_empty(this) {
                                return Poll::Ready(Err(e));
                            }
                        }
                        Some(other) => {
                            return Poll::Ready(Err(std::io::Error::other(format!(
                                "Unexpected post-handshake message {other}."
                            ))));
                        }
                    }
                }
                ContentType::Alert => {
                    if rec.payload.len() >= 2 && rec.payload[1] == 0 {
                        this.received_close = true;
                        return Poll::Ready(Ok(()));
                    }
                    return Poll::Ready(Err(std::io::Error::other("The server sent a TLS alert.")));
                }
            },
        }
    }
}

fn count_empty(this: &mut RealityTlsStream) -> std::io::Result<()> {
    this.empty_records += 1;
    if this.empty_records > 64 {
        Err(std::io::Error::other(
            "The server sent 64 consecutive TLS records carrying no application data.",
        ))
    } else {
        Ok(())
    }
}

impl AsyncWrite for RealityTlsStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        self.records.poll_write_app(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.records.poll_flush_app(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.records.poll_flush_app(cx) {
            Poll::Ready(Ok(())) => Pin::new(self.records.transport_mut()).poll_shutdown(cx),
            other => other,
        }
    }
}


impl TlsRecordStream {
    pub(crate) fn poll_read_record(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<crate::reality::record::Record, ProxyError>> {
        match self.try_poll_buffered() {
            Ok(Some(r)) => return Poll::Ready(Ok(r)),
            Ok(None) => {}
            Err(e) => return Poll::Ready(Err(e)),
        }
        let mut tmp = [0u8; 8192];
        let mut rb = ReadBuf::new(&mut tmp);
        match Pin::new(self.transport_mut()).poll_read(cx, &mut rb) {
            Poll::Ready(Ok(())) => {
                let n = rb.filled().len();
                if n == 0 {
                    return Poll::Ready(Err(ProxyError::new(
                        crate::error::ProxyErrorCode::ConnectionFailed,
                        "The peer closed the connection mid-record.",
                    )));
                }
                self.push_inbound(rb.filled());
                match self.try_poll_buffered() {
                    Ok(Some(r)) => Poll::Ready(Ok(r)),
                    Ok(None) => {
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                    Err(e) => Poll::Ready(Err(e)),
                }
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e.into())),
            Poll::Pending => Poll::Pending,
        }
    }

    fn try_poll_buffered(&mut self) -> Result<Option<crate::reality::record::Record>, ProxyError> {
        self.try_read_buffered_pub()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    struct Scripted {
        to_read: Vec<u8>,
        read_off: usize,
        written: Arc<Mutex<Vec<u8>>>,
        write_max: usize,
        pending_writes: usize,
    }

    impl AsyncRead for Scripted {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            let this = self.get_mut();
            if this.read_off >= this.to_read.len() {
                return Poll::Ready(Ok(()));
            }
            let n = (this.to_read.len() - this.read_off).min(buf.remaining());
            buf.put_slice(&this.to_read[this.read_off..this.read_off + n]);
            this.read_off += n;
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for Scripted {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            let this = self.get_mut();
            if this.pending_writes > 0 {
                this.pending_writes -= 1;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            if buf.is_empty() {
                return Poll::Ready(Ok(0));
            }
            let n = buf.len().min(this.write_max.max(1));
            this.written.lock().unwrap().extend_from_slice(&buf[..n]);
            Poll::Ready(Ok(n))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl crate::AsyncIo for Scripted {}

    fn tls_record(ty: u8, payload: &[u8]) -> Vec<u8> {
        let mut out = vec![ty, 3, 3, (payload.len() >> 8) as u8, payload.len() as u8];
        out.extend_from_slice(payload);
        out
    }

    #[tokio::test]
    async fn skips_new_session_ticket_and_ccs() {
        let mut wire = tls_record(20, &[1]);
        wire.extend(tls_record(22, &[4, 0, 0, 0]));
        wire.extend(tls_record(23, b"hello"));
        let io = SharedStream::new(Box::pin(Scripted {
            to_read: wire,
            read_off: 0,
            written: Arc::new(Mutex::new(Vec::new())),
            write_max: 4096,
            pending_writes: 0,
        }));
        let records = TlsRecordStream::new(Box::pin(io.clone()));
        let mut stream = RealityTlsStream::new(records, Vec::new(), io);
        let mut buf = [0u8; 16];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello");
    }

    #[tokio::test]
    async fn write_survives_pending_and_partial() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let io = SharedStream::new(Box::pin(Scripted {
            to_read: Vec::new(),
            read_off: 0,
            written: written.clone(),
            write_max: 5,
            pending_writes: 2,
        }));
        let records = TlsRecordStream::new(Box::pin(io.clone()));
        let mut stream = RealityTlsStream::new(records, Vec::new(), io);
        let payload = vec![0xAAu8; 30];
        stream.write_all(&payload).await.unwrap();
        stream.flush().await.unwrap();
        let out = written.lock().unwrap().clone();
        assert_eq!(out.len(), 5 + 30, "expected one TLS record, got {}", out.len());
        assert_eq!(out[0], ContentType::ApplicationData as u8);
        assert_eq!(u16::from_be_bytes([out[3], out[4]]) as usize, 30);
        assert_eq!(&out[5..], payload.as_slice());
    }
}
