use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::Duration;

use parking_lot::RwLock;
use tokio::net::{TcpSocket, TcpStream};

#[derive(Clone, Debug)]
pub struct PhysicalEndpoint {
    pub interface_index: i32,
    pub local_address: Ipv4Addr,
    pub gateway: Ipv4Addr,
    pub name: String,
    pub dns_servers: Vec<IpAddr>,
}

static PHYSICAL: RwLock<Option<PhysicalEndpoint>> = RwLock::new(None);
static UNICAST_IF: AtomicI32 = AtomicI32::new(0);

pub struct InterfaceBinder;

impl InterfaceBinder {
    pub fn is_bound() -> bool {
        PHYSICAL.read().is_some()
    }

    pub fn current() -> Option<PhysicalEndpoint> {
        PHYSICAL.read().clone()
    }

    pub fn set_physical(ep: Option<PhysicalEndpoint>) {
        if let Some(ref e) = ep {
            UNICAST_IF.store(e.interface_index, Ordering::Relaxed);
        } else {
            UNICAST_IF.store(0, Ordering::Relaxed);
        }
        *PHYSICAL.write() = ep;
    }

    pub fn clear() {
        Self::set_physical(None);
    }

    /// Connect after binding the physical NIC. Must happen *before* connect:
    /// IP_UNICAST_IF on an already-connected socket does not move the route,
    /// and with TUN split-default the SYN would re-enter WinTUN.
    pub async fn connect(addr: SocketAddr) -> std::io::Result<TcpStream> {
        let sock = if addr.is_ipv4() {
            TcpSocket::new_v4()?
        } else {
            TcpSocket::new_v6()?
        };
        Self::prepare_socket(&sock, addr.is_ipv4());
        let s = sock.connect(addr).await?;
        let _ = s.set_nodelay(true);
        Ok(s)
    }

    /// RFC 8305-style race: stagger connects 250ms, keep the first success.
    pub async fn connect_happy(
        ips: &[IpAddr],
        port: u16,
        time_limit: Duration,
    ) -> std::io::Result<TcpStream> {
        let mut addrs: Vec<SocketAddr> = Vec::with_capacity(ips.len().min(4));
        for ip in ips.iter().copied().filter(IpAddr::is_ipv4) {
            addrs.push(SocketAddr::new(ip, port));
            if addrs.len() == 4 {
                break;
            }
        }
        if addrs.len() < 4 {
            for ip in ips.iter().copied().filter(|ip| ip.is_ipv6()) {
                addrs.push(SocketAddr::new(ip, port));
                if addrs.len() == 4 {
                    break;
                }
            }
        }
        if addrs.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "no addresses",
            ));
        }
        if addrs.len() == 1 {
            return tokio::time::timeout(time_limit, Self::connect(addrs[0]))
                .await
                .map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::TimedOut, "tcp connect timeout")
                })?;
        }
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<std::io::Result<TcpStream>>();
        let mut joins = Vec::with_capacity(addrs.len());
        for (i, addr) in addrs.into_iter().enumerate() {
            let tx = tx.clone();
            let delay = Duration::from_millis(250 * i as u64);
            joins.push(tokio::spawn(async move {
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                let r = tokio::time::timeout(time_limit, InterfaceBinder::connect(addr))
                    .await
                    .map_err(|_| {
                        std::io::Error::new(std::io::ErrorKind::TimedOut, "tcp connect timeout")
                    });
                let _ = tx.send(match r {
                    Ok(inner) => inner,
                    Err(e) => Err(e),
                });
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
        Err(last.unwrap_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::HostUnreachable, "unreachable")
        }))
    }

    pub async fn bind_udp_v4() -> std::io::Result<tokio::net::UdpSocket> {
        let bind_addr = if let Some(phy) = Self::current() {
            SocketAddr::new(IpAddr::V4(phy.local_address), 0)
        } else {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
        };
        let std_sock = std::net::UdpSocket::bind(bind_addr)?;
        std_sock.set_nonblocking(true)?;
        if let Some(phy) = Self::current() {
            set_unicast_if_udp(&std_sock, phy.interface_index);
        }
        tokio::net::UdpSocket::from_std(std_sock)
    }

    fn prepare_socket(sock: &TcpSocket, ipv4: bool) {
        let Some(phy) = Self::current() else {
            return;
        };
        if ipv4 {
            let _ = sock.bind(SocketAddr::new(IpAddr::V4(phy.local_address), 0));
            set_unicast_if(sock, phy.interface_index);
        }
    }

    pub fn bind_std(stream: &TcpStream) {
        let Some(phy) = Self::current() else {
            return;
        };
        let local = SocketAddr::new(IpAddr::V4(phy.local_address), 0);
        let _ = stream.bind_device_ignored(local, phy.interface_index);
    }
}

fn set_unicast_if(sock: &TcpSocket, ifindex: i32) {
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawSocket;
        set_unicast_if_raw(sock.as_raw_socket() as usize, ifindex);
    }
    let _ = (sock, ifindex);
}

fn set_unicast_if_udp(sock: &std::net::UdpSocket, ifindex: i32) {
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawSocket;
        set_unicast_if_raw(sock.as_raw_socket() as usize, ifindex);
    }
    let _ = (sock, ifindex);
}

#[cfg(windows)]
fn set_unicast_if_raw(raw: usize, ifindex: i32) {
    let idx = (ifindex as u32).to_be();
    unsafe {
        windows_sys::Win32::Networking::WinSock::setsockopt(
            raw,
            windows_sys::Win32::Networking::WinSock::IPPROTO_IP as i32,
            31, // IP_UNICAST_IF
            &idx as *const u32 as *const u8,
            4,
        );
    }
}

pub trait SocketExt {
    fn set_nodelay_ok(&self);
    fn bind_device_ignored(&self, local: SocketAddr, ifindex: i32) -> std::io::Result<()>;
}

impl SocketExt for TcpStream {
    fn set_nodelay_ok(&self) {
        let _ = self.set_nodelay(true);
    }

    fn bind_device_ignored(&self, _local: SocketAddr, ifindex: i32) -> std::io::Result<()> {
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawSocket;
            let sock = self.as_raw_socket();
            let idx = (ifindex as u32).to_be();
            unsafe {
                windows_sys::Win32::Networking::WinSock::setsockopt(
                    sock as usize,
                    windows_sys::Win32::Networking::WinSock::IPPROTO_IP as i32,
                    31, // IP_UNICAST_IF
                    &idx as *const u32 as *const u8,
                    4,
                );
            }
        }
        let _ = ifindex;
        Ok(())
    }
}

pub struct DirectNetwork;

impl DirectNetwork {
    pub fn configure() {
        for name in [
            "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
            "http_proxy", "https_proxy", "all_proxy", "no_proxy",
        ] {
            unsafe { std::env::remove_var(name) };
        }
    }
}
