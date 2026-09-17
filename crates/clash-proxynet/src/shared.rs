use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::BoxedStream;

/// Shared TCP (or layered) handle so Vision Direct can read raw bytes while REALITY still writes.
#[derive(Clone)]
pub struct SharedStream {
    inner: Arc<Mutex<BoxedStream>>,
}

impl SharedStream {
    pub fn new(inner: BoxedStream) -> Self {
        Self {
            inner: Arc::new(Mutex::new(inner)),
        }
    }
}

impl AsyncRead for SharedStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let mut g = self.inner.lock();
        Pin::new(&mut *g).poll_read(cx, buf)
    }
}

impl AsyncWrite for SharedStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        let mut g = self.inner.lock();
        Pin::new(&mut *g).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let mut g = self.inner.lock();
        Pin::new(&mut *g).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let mut g = self.inner.lock();
        Pin::new(&mut *g).poll_shutdown(cx)
    }
}
