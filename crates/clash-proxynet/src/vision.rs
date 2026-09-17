use std::pin::Pin;
use std::task::{Context, Poll};

use rand::Rng;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::BoxedStream;
use crate::error::{ProxyError, ProxyErrorCode};

pub const VISION_FLOW: &str = "xtls-rprx-vision";
const UUID_SIZE: usize = 16;
const HEADER_SIZE: usize = 5;
const CMD_CONTINUE: u8 = 0x00;
const CMD_END: u8 = 0x01;
const CMD_DIRECT: u8 = 0x02;
const MAX_FRAME: usize = 8192;
const MAX_PADDING_ONLY: u32 = 64;
const TLS_APP: u8 = 0x17;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Undecided,
    Framed,
    Raw,
}

pub struct VisionStream {
    session: BoxedStream,
    /// After server Direct: reads come from raw TCP. Writes stay on `session`
    /// (REALITY). Replacing `session` was why TUN HTTPS died after the last fix.
    read_source: Option<BoxedStream>,
    uuid: [u8; UUID_SIZE],
    buffer: Vec<u8>,
    start: usize,
    end: usize,
    mode: Mode,
    command: u8,
    remaining_content: usize,
    remaining_padding: usize,
    padding_only: u32,
    uuid_sent: bool,
    uplink_raw: bool,
    write_buf: Vec<u8>,
    write_off: usize,
    write_plain: usize,
    pending_end: bool,
}

impl VisionStream {
    pub fn new(session: BoxedStream, uuid: [u8; UUID_SIZE]) -> Self {
        Self {
            session,
            read_source: None,
            uuid,
            buffer: vec![0u8; MAX_FRAME],
            start: 0,
            end: 0,
            mode: Mode::Undecided,
            command: CMD_CONTINUE,
            remaining_content: 0,
            remaining_padding: 0,
            padding_only: 0,
            uuid_sent: false,
            uplink_raw: false,
            write_buf: Vec::new(),
            write_off: 0,
            write_plain: 0,
            pending_end: false,
        }
    }

    fn buffered(&self) -> usize {
        self.end - self.start
    }

    fn compact(&mut self, need: usize) {
        if self.start == self.end {
            self.start = 0;
            self.end = 0;
            return;
        }
        if self.end + need <= self.buffer.len() {
            return;
        }
        self.buffer.copy_within(self.start..self.end, 0);
        self.end -= self.start;
        self.start = 0;
    }

    fn try_decide(&mut self) -> bool {
        let compared = self.buffered().min(UUID_SIZE);
        if compared > 0 && self.buffer[self.start..self.start + compared] != self.uuid[..compared] {
            self.mode = Mode::Raw;
            return true;
        }
        if self.buffered() < UUID_SIZE + HEADER_SIZE {
            return false;
        }
        self.start += UUID_SIZE;
        self.mode = Mode::Framed;
        true
    }

    fn read_frame_header(&mut self) -> Result<(), ProxyError> {
        let h = &self.buffer[self.start..self.start + HEADER_SIZE];
        self.command = h[0];
        self.remaining_content = u16::from_be_bytes([h[1], h[2]]) as usize;
        self.remaining_padding = u16::from_be_bytes([h[3], h[4]]) as usize;
        if self.remaining_content + self.remaining_padding + HEADER_SIZE > MAX_FRAME {
            return Err(ProxyError::new(
                ProxyErrorCode::InvalidResponse,
                format!(
                    "xtls-rprx-vision frame too large ({}+{}).",
                    self.remaining_content, self.remaining_padding
                ),
            ));
        }
        self.start += HEADER_SIZE;
        if self.remaining_content > 0 {
            self.padding_only = 0;
        } else {
            self.padding_only += 1;
            if self.padding_only > MAX_PADDING_ONLY {
                return Err(ProxyError::new(
                    ProxyErrorCode::InvalidResponse,
                    format!(
                        "The VLESS server sent {MAX_PADDING_ONLY} consecutive xtls-rprx-vision frames with no content."
                    ),
                ));
            }
        }
        Ok(())
    }

    fn finish_framing(&mut self) {
        if self.command == CMD_DIRECT {
            let extra = if self.buffered() > 0 {
                let extra = self.buffer[self.start..self.end].to_vec();
                self.start = self.end;
                extra
            } else {
                Vec::new()
            };
            // C# Vision: Direct splices _readSource to raw TCP; _writeTarget
            // stays on REALITY. Switching writes to raw makes the server see
            // plaintext TLS on a still-encrypted uplink — TUN "opens but nothing
            // loads".
            if let Some(raw) = self.session.as_mut().get_mut().vision_detach(extra) {
                self.read_source = Some(raw);
            }
        }
        self.mode = Mode::Raw;
    }

    fn fill_from_session(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<usize>> {
        self.compact(1);
        let spare = self.buffer.len().saturating_sub(self.end);
        if spare == 0 {
            return Poll::Ready(Ok(0));
        }
        let mut tmp = [0u8; 2048];
        let n = tmp.len().min(spare);
        let mut rb = ReadBuf::new(&mut tmp[..n]);
        match Pin::new(&mut self.session).poll_read(cx, &mut rb) {
            Poll::Ready(Ok(())) => {
                let n = rb.filled().len();
                let end = self.end;
                self.buffer[end..end + n].copy_from_slice(&rb.filled()[..n]);
                self.end += n;
                Poll::Ready(Ok(n))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn pad_frame(&self, content: &[u8], command: u8) -> Option<Vec<u8>> {
        let uuid_over = if self.uuid_sent { 0 } else { UUID_SIZE };
        if content.len() > MAX_FRAME.saturating_sub(HEADER_SIZE + uuid_over) {
            return None;
        }
        let padding = padding_len(content.len(), uuid_over);
        let mut frame = Vec::with_capacity(uuid_over + HEADER_SIZE + content.len() + padding);
        if uuid_over > 0 {
            frame.extend_from_slice(&self.uuid);
        }
        frame.push(command);
        frame.extend_from_slice(&(content.len() as u16).to_be_bytes());
        frame.extend_from_slice(&(padding as u16).to_be_bytes());
        frame.extend_from_slice(content);
        frame.resize(frame.len() + padding, 0);
        Some(frame)
    }

    fn stage_uplink(&mut self, buf: &[u8]) {
        let uuid_over = if self.uuid_sent { 0 } else { UUID_SIZE };
        let mut max_content = MAX_FRAME.saturating_sub(HEADER_SIZE + uuid_over + 900);
        if max_content < 1 {
            max_content = MAX_FRAME - HEADER_SIZE - uuid_over - 1;
        }
        let chunk_len = buf.len().min(max_content);
        let chunk = &buf[..chunk_len];
        let command = if !chunk.is_empty() && chunk[0] == TLS_APP {
            CMD_END
        } else {
            CMD_CONTINUE
        };
        match self.pad_frame(chunk, command) {
            Some(frame) => {
                self.write_buf = frame;
                self.write_off = 0;
                self.write_plain = chunk_len;
                self.pending_end = command == CMD_END;
            }
            None => {
                self.uplink_raw = true;
            }
        }
    }

    fn finish_uplink_frame(&mut self) -> usize {
        let plain = self.write_plain;
        self.write_buf.clear();
        self.write_off = 0;
        self.write_plain = 0;
        self.uuid_sent = true;
        if self.pending_end {
            self.uplink_raw = true;
        }
        self.pending_end = false;
        plain
    }

    fn poll_write_pending(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        while self.write_off < self.write_buf.len() {
            match Pin::new(&mut self.session).poll_write(cx, &self.write_buf[self.write_off..]) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "xtls-rprx-vision write returned zero",
                    )));
                }
                Poll::Ready(Ok(n)) => self.write_off += n,
            }
        }
        Poll::Ready(Ok(()))
    }
}

fn padding_len(content: usize, uuid_over: usize) -> usize {
    let mut rng = rand::thread_rng();
    let padding = if content < 900 {
        rng.gen_range(0..500) + 900 - content
    } else {
        rng.gen_range(0..256)
    };
    padding.min(MAX_FRAME - uuid_over - HEADER_SIZE - content)
}

impl AsyncRead for VisionStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        loop {
            match self.mode {
                Mode::Raw => {
                    if self.buffered() > 0 {
                        let n = self.buffered().min(buf.remaining());
                        buf.put_slice(&self.buffer[self.start..self.start + n]);
                        self.start += n;
                        return Poll::Ready(Ok(()));
                    }
                    if let Some(src) = self.read_source.as_mut() {
                        return Pin::new(src).poll_read(cx, buf);
                    }
                    return Pin::new(&mut self.session).poll_read(cx, buf);
                }
                Mode::Undecided => {
                    if !self.try_decide() {
                        match self.fill_from_session(cx) {
                            Poll::Ready(Ok(0)) => {
                                self.mode = Mode::Raw;
                                continue;
                            }
                            Poll::Ready(Ok(_)) => continue,
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Pending => return Poll::Pending,
                        }
                    }
                }
                Mode::Framed => {
                    if self.remaining_content == 0 && self.remaining_padding == 0 {
                        if self.command == CMD_END || self.command == CMD_DIRECT {
                            self.finish_framing();
                            continue;
                        }
                        if self.buffered() < HEADER_SIZE {
                            match self.fill_from_session(cx) {
                                Poll::Ready(Ok(0)) => {
                                    if self.buffered() == 0 {
                                        return Poll::Ready(Ok(()));
                                    }
                                    return Poll::Ready(Err(std::io::Error::new(
                                        std::io::ErrorKind::UnexpectedEof,
                                        "The VLESS server closed the connection inside an xtls-rprx-vision frame header, mid-response.",
                                    )));
                                }
                                Poll::Ready(Ok(_)) => continue,
                                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                                Poll::Pending => return Poll::Pending,
                            }
                        }
                        if let Err(e) = self.read_frame_header() {
                            return Poll::Ready(Err(std::io::Error::other(e.to_string())));
                        }
                        continue;
                    }
                    if self.buffered() == 0 {
                        match self.fill_from_session(cx) {
                            Poll::Ready(Ok(0)) => {
                                return Poll::Ready(Err(std::io::Error::new(
                                    std::io::ErrorKind::UnexpectedEof,
                                    "The VLESS server closed the connection inside an xtls-rprx-vision frame, mid-response.",
                                )));
                            }
                            Poll::Ready(Ok(_)) => continue,
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Pending => return Poll::Pending,
                        }
                    }
                    if self.remaining_content > 0 {
                        let n = self.remaining_content.min(self.buffered()).min(buf.remaining());
                        buf.put_slice(&self.buffer[self.start..self.start + n]);
                        self.start += n;
                        self.remaining_content -= n;
                        return Poll::Ready(Ok(()));
                    }
                    let skip = self.remaining_padding.min(self.buffered());
                    self.start += skip;
                    self.remaining_padding -= skip;
                }
            }
        }
    }
}

impl AsyncWrite for VisionStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        let this = &mut *self;
        if !this.write_buf.is_empty() {
            match this.poll_write_pending(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => return Poll::Ready(Ok(this.finish_uplink_frame())),
            }
        }
        if this.uplink_raw {
            if buf.is_empty() {
                return Poll::Ready(Ok(0));
            }
            return Pin::new(&mut this.session).poll_write(cx, buf);
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        this.stage_uplink(buf);
        if this.uplink_raw {
            return Pin::new(&mut this.session).poll_write(cx, buf);
        }
        match this.poll_write_pending(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => Poll::Ready(Ok(this.finish_uplink_frame())),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = &mut *self;
        match this.poll_write_pending(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => Pin::new(&mut this.session).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = &mut *self;
        match this.poll_write_pending(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => Pin::new(&mut this.session).poll_shutdown(cx),
        }
    }
}

// Vision Direct splice uses leftover drain; RealityTlsStream shares the TCP via SharedStream.

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

    struct Scripted {
        to_read: Vec<u8>,
        read_off: usize,
        written: Arc<Mutex<Vec<u8>>>,
        write_max: usize,
        pending_writes: usize,
        splice_rest: Vec<u8>,
        splice_written: Arc<Mutex<Vec<u8>>>,
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

    impl crate::AsyncIo for Scripted {
        fn vision_detach(&mut self, leftover: Vec<u8>) -> Option<crate::BoxedStream> {
            let mut rest = leftover;
            rest.extend_from_slice(&self.splice_rest);
            Some(Box::pin(Scripted {
                to_read: rest,
                read_off: 0,
                written: self.splice_written.clone(),
                write_max: usize::MAX,
                pending_writes: 0,
                splice_rest: Vec::new(),
                splice_written: self.splice_written.clone(),
            }))
        }
    }

    #[tokio::test]
    async fn vision_write_survives_pending_and_partial() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let uuid = [7u8; 16];
        let mut stream = VisionStream::new(
            Box::pin(Scripted {
                to_read: Vec::new(),
                read_off: 0,
                written: written.clone(),
                write_max: 11,
                pending_writes: 2,
                splice_rest: Vec::new(),
                splice_written: Arc::new(Mutex::new(Vec::new())),
            }),
            uuid,
        );
        let payload = vec![0x16u8; 40];
        stream.write_all(&payload).await.unwrap();
        stream.flush().await.unwrap();
        let out = written.lock().unwrap().clone();
        assert!(out.len() > 16 + 5 + 40, "frame too short: {}", out.len());
        assert_eq!(&out[..16], &uuid);
        assert_eq!(out[16], CMD_CONTINUE);
        let content_len = u16::from_be_bytes([out[17], out[18]]) as usize;
        assert_eq!(content_len, 40);
        assert_eq!(&out[21..61], payload.as_slice());
        let uuid_hits = out.windows(16).filter(|w| *w == uuid).count();
        assert_eq!(uuid_hits, 1, "partial write restaged the Vision frame");
    }

    #[tokio::test]
    async fn first_uplink_write_of_full_hello_is_one_vision_frame() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let uuid = [3u8; 16];
        let mut stream = VisionStream::new(
            Box::pin(Scripted {
                to_read: Vec::new(),
                read_off: 0,
                written: written.clone(),
                write_max: usize::MAX,
                pending_writes: 0,
                splice_rest: Vec::new(),
                splice_written: Arc::new(Mutex::new(Vec::new())),
            }),
            uuid,
        );
        let mut hello = vec![0x16, 0x03, 0x01];
        hello.extend_from_slice(&(1500u16).to_be_bytes());
        hello.extend(vec![9u8; 1500]);
        stream.write_all(&hello).await.unwrap();
        stream.flush().await.unwrap();
        let out = written.lock().unwrap().clone();
        assert_eq!(&out[..16], &uuid);
        assert_eq!(out[16], CMD_CONTINUE);
        let content_len = u16::from_be_bytes([out[17], out[18]]) as usize;
        assert_eq!(content_len, hello.len());
        assert_eq!(&out[21..21 + hello.len()], hello.as_slice());
    }

    #[tokio::test]
    async fn first_uplink_write_of_517_prefix_frames_an_incomplete_record() {
        let written = Arc::new(Mutex::new(Vec::new()));
        let uuid = [4u8; 16];
        let mut stream = VisionStream::new(
            Box::pin(Scripted {
                to_read: Vec::new(),
                read_off: 0,
                written: written.clone(),
                write_max: usize::MAX,
                pending_writes: 0,
                splice_rest: Vec::new(),
                splice_written: Arc::new(Mutex::new(Vec::new())),
            }),
            uuid,
        );
        let mut hello = vec![0x16, 0x03, 0x01];
        hello.extend_from_slice(&(1500u16).to_be_bytes());
        hello.extend(vec![9u8; 1500]);
        stream.write_all(&hello[..517]).await.unwrap();
        stream.flush().await.unwrap();
        let out = written.lock().unwrap().clone();
        let content_len = u16::from_be_bytes([out[17], out[18]]) as usize;
        assert_eq!(content_len, 517);
        assert!(complete_tls_record_len(&out[21..21 + 517]).is_none());
    }

    fn complete_tls_record_len(data: &[u8]) -> Option<usize> {
        if data.len() < 5 || data[0] != 0x16 {
            return None;
        }
        let frag = ((data[3] as usize) << 8) | data[4] as usize;
        let rec = 5 + frag;
        (data.len() >= rec).then_some(rec)
    }

    #[tokio::test]
    async fn direct_splices_reads_keeps_writes_on_session() {
        let uuid = [9u8; 16];
        let mut to_read = uuid.to_vec();
        to_read.extend([CMD_DIRECT, 0, 0, 0, 0]);
        to_read.extend(b"FROM-FRAME");
        let session_written = Arc::new(Mutex::new(Vec::new()));
        let splice_written = Arc::new(Mutex::new(Vec::new()));
        let mut stream = VisionStream::new(
            Box::pin(Scripted {
                to_read,
                read_off: 0,
                written: session_written.clone(),
                write_max: 4096,
                pending_writes: 0,
                splice_rest: b"FROM-TCP".to_vec(),
                splice_written: splice_written.clone(),
            }),
            uuid,
        );
        let mut buf = [0u8; 32];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"FROM-FRAMEFROM-TCP");

        let payload = vec![0x16u8; 20];
        stream.write_all(&payload).await.unwrap();
        stream.flush().await.unwrap();
        assert!(
            splice_written.lock().unwrap().is_empty(),
            "Direct must not divert uplink onto the raw splice"
        );
        let out = session_written.lock().unwrap().clone();
        assert_eq!(&out[..16], &uuid);
        assert_eq!(out[16], CMD_CONTINUE);
        let content_len = u16::from_be_bytes([out[17], out[18]]) as usize;
        assert_eq!(content_len, 20);
        assert_eq!(&out[21..41], payload.as_slice());
    }
}
