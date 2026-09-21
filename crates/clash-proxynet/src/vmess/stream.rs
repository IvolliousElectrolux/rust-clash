use std::cmp::min;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use aes::Aes128;
use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes128Gcm, Nonce};
use bytes::BytesMut;
use cfb_mode::cipher::{AsyncStreamCipher, KeyIvInit};
use rand::RngCore;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::error::{ProxyError, ProxyErrorCode};
use crate::options::VmessOptions;
use crate::{AsyncIo, BoxedStream};

use super::crypto::{BodyAead, ShakeSizeParser, VmessNonce};
use super::kdf::{self, *};
use super::protocol::{
    encode_request, ClientSession, SECURITY_AES128_GCM, SECURITY_CHACHA20,
};

enum ReadState {
    Header,
    Length,
    Data { size: usize, padding: usize },
    Pending(usize),
}

enum WriteState {
    Chunk,
    Flush { consumed: usize, total: usize, written: usize },
}

pub struct VmessAuthStream<T> {
    inner: T,
    sess: ClientSession,
    enc: BodyAead,
    dec: BodyAead,
    enc_nonce: VmessNonce,
    dec_nonce: VmessNonce,
    enc_size: ShakeSizeParser,
    dec_size: ShakeSizeParser,
    tag_len: usize,
    read_buf: BytesMut,
    write_buf: BytesMut,
    read_state: ReadState,
    write_state: WriteState,
    read_pos: usize,
}

impl<T> VmessAuthStream<T> {
    fn new(inner: T, sess: ClientSession, security: &str) -> Result<Self, ProxyError> {
        let enc = BodyAead::new(security, &sess.request_body_key)?;
        let dec = BodyAead::new(security, &sess.response_body_key)?;
        let tag_len = enc.tag_len();
        let enc_nonce = VmessNonce::new(&sess.request_body_iv, 12);
        let dec_nonce = VmessNonce::new(&sess.response_body_iv, 12);
        let enc_size = ShakeSizeParser::new(&sess.request_body_iv);
        let dec_size = ShakeSizeParser::new(&sess.response_body_iv);
        Ok(Self {
            inner,
            sess,
            enc,
            dec,
            enc_nonce,
            dec_nonce,
            enc_size,
            dec_size,
            tag_len,
            read_buf: BytesMut::new(),
            write_buf: BytesMut::new(),
            read_state: ReadState::Header,
            write_state: WriteState::Chunk,
            read_pos: 0,
        })
    }
}

fn early_eof() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "vmess eof")
}

impl<T: AsyncRead + Unpin> VmessAuthStream<T> {
    fn poll_read_exact(&mut self, cx: &mut Context<'_>, size: usize) -> Poll<io::Result<()>> {
        self.read_buf.resize(size, 0);
        while self.read_pos < size {
            let mut buf = ReadBuf::new(&mut self.read_buf[self.read_pos..size]);
            ready!(Pin::new(&mut self.inner).poll_read(cx, &mut buf))?;
            let n = buf.filled().len();
            if n == 0 {
                return Poll::Ready(Err(early_eof()));
            }
            self.read_pos += n;
        }
        self.read_pos = 0;
        Poll::Ready(Ok(()))
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for VmessAuthStream<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            match self.read_state {
                ReadState::Header => {
                    if !self.sess.aead {
                        ready!(self.poll_read_exact(cx, 4))?;
                        cfb_mode::Decryptor::<Aes128>::new(
                            self.sess.response_body_key.as_slice().into(),
                            self.sess.response_body_iv.as_slice().into(),
                        )
                        .decrypt(&mut self.read_buf[..4]);
                    } else {
                        let key = &kdf::vmess_kdf_1_one_shot(
                            &self.sess.response_body_key,
                            KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_KEY,
                        )[..16];
                        let iv = &kdf::vmess_kdf_1_one_shot(
                            &self.sess.response_body_iv,
                            KDF_SALT_CONST_AEAD_RESP_HEADER_LEN_IV,
                        )[..12];
                        ready!(self.poll_read_exact(cx, 18))?;
                        let mut tmp = self.read_buf[..18].to_vec();
                        Aes128Gcm::new_from_slice(key)
                            .map_err(|_| io::Error::other("vmess resp key"))?
                            .decrypt_in_place(Nonce::from_slice(iv), b"", &mut tmp)
                            .map_err(|_| io::Error::other("vmess resp len"))?;
                        let len = u16::from_be_bytes([tmp[0], tmp[1]]) as usize;
                        let pkey = &kdf::vmess_kdf_1_one_shot(
                            &self.sess.response_body_key,
                            KDF_SALT_CONST_AEAD_RESP_HEADER_PAYLOAD_KEY,
                        )[..16];
                        let piv = &kdf::vmess_kdf_1_one_shot(
                            &self.sess.response_body_iv,
                            KDF_SALT_CONST_AEAD_RESP_HEADER_PAYLOAD_IV,
                        )[..12];
                        ready!(self.poll_read_exact(cx, len + 16))?;
                        let mut payload = self.read_buf[..len + 16].to_vec();
                        Aes128Gcm::new_from_slice(pkey)
                            .map_err(|_| io::Error::other("vmess resp key"))?
                            .decrypt_in_place(Nonce::from_slice(piv), b"", &mut payload)
                            .map_err(|_| io::Error::other("vmess resp header"))?;
                        self.read_buf.clear();
                        self.read_buf.extend_from_slice(&payload);
                    }
                    if self.read_buf.first().copied() != Some(self.sess.response_header) {
                        return Poll::Ready(Err(io::Error::other("vmess response header mismatch")));
                    }
                    self.read_state = ReadState::Length;
                }
                ReadState::Length => {
                    let n = self.dec_size.size_bytes();
                    ready!(self.poll_read_exact(cx, n))?;
                    let hdr = self.read_buf[..n].to_vec();
                    let padding = self.dec_size.next_padding_len() as usize;
                    let size = self.dec_size.decode(&hdr) as usize;
                    self.read_state = ReadState::Data { size, padding };
                }
                ReadState::Data { size, padding } => {
                    ready!(self.poll_read_exact(cx, size))?;
                    let encrypted = size.saturating_sub(padding);
                    self.read_buf.truncate(encrypted);
                    let nonce = self.dec_nonce.next();
                    let mut tmp = self.read_buf.to_vec();
                    self.dec
                        .open(&nonce, &mut tmp)
                        .map_err(|e| io::Error::other(e.to_string()))?;
                    self.read_buf.clear();
                    self.read_buf.extend_from_slice(&tmp);
                    self.read_state = ReadState::Pending(tmp.len());
                }
                ReadState::Pending(n) => {
                    let take = min(buf.remaining(), n);
                    buf.put_slice(&self.read_buf.split_to(take));
                    if take < n {
                        self.read_state = ReadState::Pending(n - take);
                    } else {
                        self.read_state = ReadState::Length;
                    }
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for VmessAuthStream<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        loop {
            match self.write_state {
                WriteState::Chunk => {
                    let padding = self.enc_size.next_padding_len() as usize;
                    let max_payload = 0x4000 - self.tag_len - padding;
                    let consume = min(buf.len(), max_payload);
                    let payload_len = consume + self.tag_len + padding;
                    let masked = self.enc_size.encode(payload_len as u16);
                    self.write_buf.clear();
                    self.write_buf.extend_from_slice(&masked);
                    let mut piece = buf[..consume].to_vec();
                    let nonce = self.enc_nonce.next();
                    self.enc
                        .seal(&nonce, &mut piece)
                        .map_err(|e| io::Error::other(e.to_string()))?;
                    self.write_buf.extend_from_slice(&piece);
                    if padding > 0 {
                        let mut pad = vec![0u8; padding];
                        rand::thread_rng().fill_bytes(&mut pad);
                        self.write_buf.extend_from_slice(&pad);
                    }
                    let total = self.write_buf.len();
                    self.write_state = WriteState::Flush {
                        consumed: consume,
                        total,
                        written: 0,
                    };
                }
                WriteState::Flush {
                    consumed,
                    total,
                    written,
                } => {
                    let this = &mut *self;
                    let n = ready!(Pin::new(&mut this.inner).poll_write(cx, &this.write_buf))?;
                    if n == 0 {
                        return Poll::Ready(Err(early_eof()));
                    }
                    let _ = this.write_buf.split_to(n);
                    let written = written + n;
                    if written >= total {
                        this.write_state = WriteState::Chunk;
                        return Poll::Ready(Ok(consumed));
                    }
                    this.write_state = WriteState::Flush {
                        consumed,
                        total,
                        written,
                    };
                }
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncIo for VmessAuthStream<T> {}

pub async fn dial_vmess(
    mut stream: BoxedStream,
    options: &VmessOptions,
    dest_host: &str,
    dest_port: u16,
) -> Result<BoxedStream, ProxyError> {
    let security_name = options.body_security();
    let security = match security_name.as_str() {
        "aes-128-gcm" => SECURITY_AES128_GCM,
        "chacha20-poly1305" => SECURITY_CHACHA20,
        other => {
            return Err(ProxyError::new(
                ProxyErrorCode::AuthRequired,
                format!("unsupported vmess cipher {other}"),
            ));
        }
    };
    let sess = ClientSession::new(options.aead());
    let header = encode_request(&options.id, dest_host, dest_port, security, &sess)?;
    stream.write_all(&header).await?;
    stream.flush().await?;
    Ok(Box::pin(VmessAuthStream::new(stream, sess, &security_name)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::options::VmessOptions;
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    use super::super::crypto::{BodyAead, ShakeSizeParser, VmessNonce};
    use super::super::protocol::{
        aead_header_payload_len, cmd_key_from_uuid, decode_aead_header, encode_aead_response,
        ClientSession, AEAD_HEADER_PREFIX, SECURITY_AES128_GCM, SECURITY_CHACHA20,
    };

    async fn echo_one_chunk<S: AsyncRead + AsyncWrite + Unpin>(
        socket: &mut S,
        sess: &ClientSession,
        security: &str,
    ) {
        let dec = BodyAead::new(security, &sess.request_body_key).unwrap();
        let enc = BodyAead::new(security, &sess.response_body_key).unwrap();
        let mut dec_nonce = VmessNonce::new(&sess.request_body_iv, 12);
        let mut enc_nonce = VmessNonce::new(&sess.response_body_iv, 12);
        let mut dec_size = ShakeSizeParser::new(&sess.request_body_iv);
        let mut enc_size = ShakeSizeParser::new(&sess.response_body_iv);
        let mut hdr = [0u8; 2];
        socket.read_exact(&mut hdr).await.unwrap();
        let padding = dec_size.next_padding_len() as usize;
        let size = dec_size.decode(&hdr) as usize;
        let mut data = vec![0u8; size];
        socket.read_exact(&mut data).await.unwrap();
        data.truncate(size.saturating_sub(padding));
        let nonce = dec_nonce.next();
        dec.open(&nonce, &mut data).unwrap();

        let padding = enc_size.next_padding_len() as usize;
        let payload_len = data.len() + 16 + padding;
        let masked = enc_size.encode(payload_len as u16);
        let nonce = enc_nonce.next();
        enc.seal(&nonce, &mut data).unwrap();
        socket.write_all(&masked).await.unwrap();
        socket.write_all(&data).await.unwrap();
        if padding > 0 {
            socket.write_all(&vec![0u8; padding]).await.unwrap();
        }
        socket.flush().await.unwrap();
        let _ = socket.shutdown().await;
        let mut hold = [0u8; 1];
        let _ = socket.read(&mut hold).await;
    }

    async fn vmess_tcp_echo(security: &str) {
        let uuid = "11111111-1111-1111-1111-111111111111";
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let uuid_s = uuid.to_string();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut prefix = vec![0u8; AEAD_HEADER_PREFIX];
            socket.read_exact(&mut prefix).await.unwrap();
            let key = cmd_key_from_uuid(&uuid_s).unwrap();
            let payload_len = aead_header_payload_len(&key, &prefix).unwrap();
            let mut rest = vec![0u8; payload_len + 16];
            socket.read_exact(&mut rest).await.unwrap();
            prefix.extend_from_slice(&rest);
            let (sess, host, port, sec) = decode_aead_header(&uuid_s, &prefix).unwrap();
            assert_eq!(host, "example.com");
            assert_eq!(port, 80);
            let name = match sec {
                SECURITY_AES128_GCM => "aes-128-gcm",
                SECURITY_CHACHA20 => "chacha20-poly1305",
                other => panic!("sec {other}"),
            };
            socket
                .write_all(&encode_aead_response(&sess).unwrap())
                .await
                .unwrap();
            echo_one_chunk(&mut socket, &sess, name).await;
        });
        let tcp = TcpStream::connect(addr).await.unwrap();
        let opts = VmessOptions {
            id: uuid.into(),
            security: security.into(),
            alter_id: 0,
            host: addr.ip().to_string(),
            port: addr.port(),
            transport: "tcp".into(),
            path: None,
            host_header: None,
            sni: None,
            alpn: Vec::new(),
            allow_insecure: false,
            tls: false,
        };
        let mut stream = dial_vmess(Box::pin(tcp), &opts, "example.com", 80)
            .await
            .unwrap();
        stream.write_all(b"ping-vmess").await.unwrap();
        stream.flush().await.unwrap();
        let mut buf = [0u8; 10];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping-vmess");
        let _ = stream.shutdown().await;
        server.await.unwrap();
    }

    #[tokio::test]
    async fn vmess_aead_tcp_echo_aes_and_chacha() {
        vmess_tcp_echo("aes-128-gcm").await;
        vmess_tcp_echo("chacha20-poly1305").await;
    }
}
