use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;

use crate::net::InterfaceBinder;
use crate::outbound::OutboundDialer;
use crate::rules::try_split_host_port;

pub struct TrafficCounters;

static UPLOAD: AtomicI64 = AtomicI64::new(0);
static DOWNLOAD: AtomicI64 = AtomicI64::new(0);
static WIN_UP: AtomicI64 = AtomicI64::new(0);
static WIN_DOWN: AtomicI64 = AtomicI64::new(0);
static WIN_START: AtomicI64 = AtomicI64::new(0);

impl TrafficCounters {
    pub fn add_upload(n: usize) {
        UPLOAD.fetch_add(n as i64, Ordering::Relaxed);
        WIN_UP.fetch_add(n as i64, Ordering::Relaxed);
    }
    pub fn add_download(n: usize) {
        DOWNLOAD.fetch_add(n as i64, Ordering::Relaxed);
        WIN_DOWN.fetch_add(n as i64, Ordering::Relaxed);
    }
    pub fn snapshot_total_kbps() -> i32 {
        let now = tick();
        let start = WIN_START.swap(now, Ordering::Relaxed);
        let elapsed = (now - start).max(1);
        let up = WIN_UP.swap(0, Ordering::Relaxed);
        let down = WIN_DOWN.swap(0, Ordering::Relaxed);
        let up_k = (up * 1000 / elapsed / 1000) as i32;
        let down_k = (down * 1000 / elapsed / 1000) as i32;
        up_k.saturating_add(down_k)
    }
}

fn tick() -> i64 {
    static START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_millis() as i64
}

pub struct Relay;

impl Relay {
    /// Bidirectional copy matching C# Relay: half-close on EOF, abort the peer
    /// on error, and idle-timeout from the last read on *either* half.
    /// Per-write flush is intentionally omitted (C# does not flush; it was
    /// forcing Vision to emit a padded frame from a partial ClientHello).
    pub async fn copy_bidirectional<A, B>(a: &mut A, b: &mut B) -> std::io::Result<()>
    where
        A: AsyncRead + AsyncWrite + Unpin,
        B: AsyncRead + AsyncWrite + Unpin,
    {
        let stop = CancellationToken::new();
        let last = Arc::new(AtomicU64::new(tick() as u64));
        let (mut ar, mut aw) = tokio::io::split(a);
        let (mut br, mut bw) = tokio::io::split(b);
        let t1 = copy_half(&mut ar, &mut bw, true, stop.clone(), last.clone());
        let t2 = copy_half(&mut br, &mut aw, false, stop.clone(), last.clone());
        let copies = async {
            match tokio::join!(t1, t2) {
                (Ok(()), Ok(())) => {}
                _ => {}
            }
        };
        tokio::pin!(copies);
        tokio::select! {
            _ = &mut copies => {}
            _ = idle_until(&last, &stop) => {
                stop.cancel();
                copies.await;
            }
        }
        Ok(())
    }

    pub async fn write_http_error(client: &mut (impl AsyncWrite + Unpin), status: u16, reason: &str) {
        let body = format!("{reason}\n");
        let phrase = match status {
            400 => "Bad Request",
            403 => "Forbidden",
            503 => "Service Unavailable",
            500 => "Internal Server Error",
            _ => "Error",
        };
        let head = format!(
            "HTTP/1.1 {status} {phrase}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let _ = client.write_all(head.as_bytes()).await;
        let _ = client.write_all(body.as_bytes()).await;
    }
}

const IDLE_MS: u64 = 600_000;

async fn idle_until(last: &AtomicU64, stop: &CancellationToken) {
    loop {
        tokio::select! {
            _ = stop.cancelled() => return,
            _ = tokio::time::sleep(Duration::from_secs(5)) => {
                if (tick() as u64).saturating_sub(last.load(Ordering::Relaxed)) >= IDLE_MS {
                    return;
                }
            }
        }
    }
}

async fn copy_half<R, W>(
    src: &mut R,
    dst: &mut W,
    upload: bool,
    stop: CancellationToken,
    last: Arc<AtomicU64>,
) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = tokio::select! {
            _ = stop.cancelled() => {
                let _ = dst.shutdown().await;
                return Ok(());
            }
            r = src.read(&mut buf) => match r {
                Ok(0) => {
                    let _ = dst.shutdown().await;
                    return Ok(());
                }
                Ok(n) => n,
                Err(_) => {
                    stop.cancel();
                    let _ = dst.shutdown().await;
                    return Ok(());
                }
            },
        };
        last.store(tick() as u64, Ordering::Relaxed);
        if dst.write_all(&buf[..n]).await.is_err() {
            stop.cancel();
            return Ok(());
        }
        if upload {
            TrafficCounters::add_upload(n);
        } else {
            TrafficCounters::add_download(n);
        }
    }
}

pub struct DirectDial;

impl DirectDial {
    pub async fn connect(host_port: &str) -> std::io::Result<TcpStream> {
        Self::connect_with(host_port, None).await
    }

    pub async fn connect_with(
        host_port: &str,
        via: Option<&OutboundDialer>,
    ) -> std::io::Result<TcpStream> {
        let (host, port) = try_split_host_port(host_port)
            .or_else(|| {
                let idx = host_port.rfind(':')?;
                Some((host_port[..idx].to_string(), host_port[idx + 1..].to_string()))
            })
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid host:port"))?;
        let port: u16 = port.parse().map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid port")
        })?;
        let host = host.trim_matches(['[', ']']).to_string();
        if let Ok(ip) = host.parse::<IpAddr>() {
            return dial_ip(ip, port).await;
        }
        if let Some(via) = via {
            if let Ok(ips) = via.resolve_host(&host).await {
                if !ips.is_empty() {
                    return happy_eyeballs(&ips, port).await;
                }
            }
        }
        let mut ips = tokio::net::lookup_host((host.as_str(), port))
            .await?
            .map(|s| s.ip())
            .collect::<Vec<_>>();
        if ips.is_empty() {
            return Err(std::io::Error::new(std::io::ErrorKind::NotFound, "host not found"));
        }
        ips.sort_by_key(|ip| ip.is_ipv6());
        happy_eyeballs(&ips, port).await
    }
}

async fn dial_ip(ip: IpAddr, port: u16) -> std::io::Result<TcpStream> {
    tokio::time::timeout(
        Duration::from_secs(15),
        InterfaceBinder::connect(SocketAddr::new(ip, port)),
    )
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "dial timeout"))?
}

async fn happy_eyeballs(ips: &[IpAddr], port: u16) -> std::io::Result<TcpStream> {
    if ips.len() == 1 {
        return dial_ip(ips[0], port).await;
    }
    use tokio::sync::Semaphore;
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<std::io::Result<TcpStream>>();
    let gate = std::sync::Arc::new(Semaphore::new(2));
    let mut joins = Vec::with_capacity(ips.len());
    for (i, ip) in ips.iter().copied().enumerate() {
        let tx = tx.clone();
        let gate = gate.clone();
        let delay = Duration::from_millis(250 * i as u64);
        joins.push(tokio::spawn(async move {
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            let Ok(_permit) = gate.acquire().await else {
                return;
            };
            let _ = tx.send(dial_ip(ip, port).await);
        }));
    }
    drop(tx);
    let mut last = None;
    let mut left = joins.len();
    while left > 0 {
        match rx.recv().await {
            Some(Ok(stream)) => {
                for j in joins {
                    j.abort();
                }
                return Ok(stream);
            }
            Some(Err(e)) => {
                last = Some(e);
                left -= 1;
            }
            None => break,
        }
    }
    Err(last.unwrap_or_else(|| std::io::Error::new(std::io::ErrorKind::HostUnreachable, "unreachable")))
}

pub struct TlsHelloCoalesce;

impl TlsHelloCoalesce {
    pub const VISION_MAX: usize = 8192 - 16 - 5;

    pub async fn flush_first_record(
        client: &mut (impl AsyncRead + Unpin),
        dest: &mut (impl AsyncWrite + Unpin),
        seed: &[u8],
    ) -> std::io::Result<(usize, bool)> {
        let mut ms = seed.to_vec();
        if !ms.is_empty() && ms[0] != 0x16 {
            dest.write_all(&ms).await?;
            dest.flush().await?;
            let n = ms.len();
            return Ok((n, n > 0 && n <= Self::VISION_MAX));
        }
        let mut buf = [0u8; 8192];
        loop {
            if let Some(rec) = complete_record_len(&ms) {
                dest.write_all(&ms[..rec]).await?;
                if ms.len() > rec {
                    dest.write_all(&ms[rec..]).await?;
                }
                dest.flush().await?;
                return Ok((rec, rec <= Self::VISION_MAX));
            }
            if ms.len() >= 16 * 1024 {
                dest.write_all(&ms).await?;
                dest.flush().await?;
                return Ok((ms.len(), ms.len() <= Self::VISION_MAX));
            }
            match tokio::time::timeout(Duration::from_secs(5), client.read(&mut buf)).await {
                Ok(Ok(0)) | Err(_) => {
                    dest.write_all(&ms).await?;
                    dest.flush().await?;
                    return Ok((ms.len(), ms.len() > 0 && ms.len() <= Self::VISION_MAX));
                }
                Ok(Ok(n)) => {
                    ms.extend_from_slice(&buf[..n]);
                    if !ms.is_empty() && ms[0] != 0x16 {
                        dest.write_all(&ms).await?;
                        dest.flush().await?;
                        return Ok((ms.len(), ms.len() <= Self::VISION_MAX));
                    }
                }
                Ok(Err(e)) => return Err(e),
            }
        }
    }
}

fn complete_record_len(data: &[u8]) -> Option<usize> {
    if data.len() < 5 || data[0] != 0x16 {
        return None;
    }
    let frag = ((data[3] as usize) << 8) | data[4] as usize;
    if frag > 16 * 1024 {
        return None;
    }
    let rec = 5 + frag;
    (data.len() >= rec).then_some(rec)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn incomplete_pq_hello_is_not_a_full_record() {
        // Chrome PQ ClientHello is ~1500B; a 517B TCP segment is not a record.
        let mut hello = vec![0x16, 0x03, 0x01, 0x05, 0xdc];
        hello.extend(vec![0u8; 512]);
        assert_eq!(hello.len(), 517);
        assert_eq!(complete_record_len(&hello), None);
        hello.extend(vec![0u8; 1500 - 512]);
        assert_eq!(complete_record_len(&hello), Some(5 + 1500));
    }

    #[tokio::test]
    async fn tun_waits_for_dial_then_relay_keeps_fragmented_hello() {
        // System TCP: PQ ClientHello is split across MTU-sized segments and sits
        // in the kernel while REALITY dials. One 64KiB Relay read must see it all.
        let (mut client, mut peer) = tokio::io::duplex(8192);
        let (mut dest, mut dest_peer) = tokio::io::duplex(8192);
        let mut hello = vec![0x16, 0x03, 0x01];
        hello.extend_from_slice(&(1500u16).to_be_bytes());
        hello.extend(vec![7u8; 1500]);
        peer.write_all(&hello[..517]).await.unwrap();
        peer.write_all(&hello[517..]).await.unwrap();

        tokio::time::sleep(Duration::from_millis(1)).await;

        let expected = hello.clone();
        let relay = tokio::spawn(async move {
            Relay::copy_bidirectional(&mut client, &mut dest).await.unwrap();
        });
        let mut got = vec![0u8; expected.len()];
        dest_peer.read_exact(&mut got).await.unwrap();
        assert_eq!(got, expected);
        drop(peer);
        dest_peer.shutdown().await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), relay)
            .await
            .expect("relay should finish")
            .unwrap();
    }

    #[tokio::test]
    async fn tun_tcp_accept_after_slow_dial_sees_full_fragmented_hello() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut hello = vec![0x16, 0x03, 0x01];
        hello.extend_from_slice(&(1500u16).to_be_bytes());
        hello.extend(vec![9u8; 1500]);
        let sent = hello.clone();

        let client = tokio::spawn(async move {
            let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
            let _ = s.set_nodelay(true);
            s.write_all(&sent[..517]).await.unwrap();
            tokio::time::sleep(Duration::from_millis(5)).await;
            s.write_all(&sent[517..]).await.unwrap();
            s
        });

        let (mut server, _) = listener.accept().await.unwrap();
        let _ = server.set_nodelay(true);
        tokio::time::sleep(Duration::from_millis(40)).await;

        let (mut dest, mut dest_peer) = tokio::io::duplex(8192);
        let copy = tokio::spawn(async move {
            Relay::copy_bidirectional(&mut server, &mut dest).await.unwrap();
        });
        let mut got = vec![0u8; hello.len()];
        dest_peer.read_exact(&mut got).await.unwrap();
        assert_eq!(got, hello);
        drop(client);
        dest_peer.shutdown().await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), copy)
            .await
            .expect("relay should finish")
            .unwrap();
    }

    #[tokio::test]
    async fn relay_eof_sends_fin_to_peer() {
        let (mut a, mut a_peer) = tokio::io::duplex(64);
        let (mut b, mut b_peer) = tokio::io::duplex(64);
        let relay = tokio::spawn(async move {
            Relay::copy_bidirectional(&mut a, &mut b).await.unwrap();
        });
        a_peer.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 8];
        let n = b_peer.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello");
        a_peer.shutdown().await.unwrap();
        let n = tokio::time::timeout(Duration::from_secs(2), b_peer.read(&mut buf))
            .await
            .expect("FIN should arrive; old Relay leaked the write half until the 10min idle timer")
            .unwrap();
        assert_eq!(n, 0);
        b_peer.shutdown().await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), relay)
            .await
            .expect("relay should finish after both halves close")
            .unwrap();
    }
}
