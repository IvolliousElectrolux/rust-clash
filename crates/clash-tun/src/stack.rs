use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use clash_core::{
    action_for_ip, build_empty_dns, build_named_a_response, parse_dns_query, DirectDial, DohBlocklist,
    FakeIpPool, OutboundDialer, Relay, RuleAction, RuleDb,
};
use parking_lot::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

use crate::nat::TcpNat;
use crate::packet;
use crate::routes::{TUN_CLIENT, TUN_SERVER};
use crate::wintun::{WintunDevice, MAX_IP};

pub struct SystemTcpStack {
    device: Arc<WintunDevice>,
    rules: Arc<RuleDb>,
    outbound: Arc<OutboundDialer>,
    fake_ip: Arc<Mutex<FakeIpPool>>,
    nat: Arc<TcpNat>,
    doh: DohBlocklist,
    listen_port: u16,
    generation: Arc<AtomicU64>,
    cancel: CancellationToken,
    relay_cancel: Arc<parking_lot::Mutex<CancellationToken>>,
    closed: AtomicBool,
}

impl SystemTcpStack {
    pub async fn start(
        device: WintunDevice,
        rules: Arc<RuleDb>,
        outbound: Arc<OutboundDialer>,
    ) -> Result<Self> {
        crate::routes::allow_firewall();
        let mut listener = None;
        let mut last = None;
        for _ in 0..10 {
            match TcpListener::bind((TUN_SERVER, 0)).await {
                Ok(l) => {
                    listener = Some(l);
                    last = None;
                    break;
                }
                Err(e) => {
                    last = Some(e);
                    tokio::time::sleep(Duration::from_millis(300)).await;
                }
            }
        }
        let listener = listener.ok_or_else(|| {
            anyhow::anyhow!("Failed to listen on {TUN_SERVER}: {:?}", last)
        })?;
        let listen_port = listener.local_addr()?.port();
        let cancel = CancellationToken::new();
        let stack = Self {
            device: Arc::new(device),
            rules,
            outbound,
            fake_ip: Arc::new(Mutex::new(FakeIpPool::new())),
            nat: Arc::new(TcpNat::new(Duration::from_secs(300))),
            doh: DohBlocklist::new(),
            listen_port,
            generation: Arc::new(AtomicU64::new(0)),
            cancel: cancel.clone(),
            relay_cancel: Arc::new(parking_lot::Mutex::new(cancel.child_token())),
            closed: AtomicBool::new(false),
        };
        let packet_dev = stack.device.clone();
        let packet_self = PacketCtx {
            device: stack.device.clone(),
            nat: stack.nat.clone(),
            fake_ip: stack.fake_ip.clone(),
            listen_port: stack.listen_port,
        };
        let ct = cancel.clone();
        std::thread::spawn(move || packet_loop(packet_dev, packet_self, ct));
        let accept_ct = cancel.clone();
        let accept_ctx = AcceptCtx {
            rules: stack.rules.clone(),
            outbound: stack.outbound.clone(),
            fake_ip: stack.fake_ip.clone(),
            nat: stack.nat.clone(),
            doh: stack.doh.clone(),
            generation: stack.generation.clone(),
            relay: stack.relay_cancel.clone(),
        };
        tokio::spawn(async move {
            accept_loop(listener, accept_ctx, accept_ct).await;
        });
        let nat = stack.nat.clone();
        let sweep_ct = cancel.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = sweep_ct.cancelled() => break,
                    _ = tokio::time::sleep(Duration::from_secs(30)) => nat.sweep(),
                }
            }
        });
        Ok(stack)
    }

    pub fn bump_generation(&self) {
        self.generation.fetch_add(1, Ordering::Relaxed);
        let child = self.cancel.child_token();
        let old = {
            let mut g = self.relay_cancel.lock();
            let old = g.clone();
            *g = child;
            old
        };
        old.cancel();
    }

    pub fn request_stop(&self) {
        self.closed.store(true, Ordering::Relaxed);
        self.cancel.cancel();
        self.relay_cancel.lock().cancel();
    }
}

impl Drop for SystemTcpStack {
    fn drop(&mut self) {
        self.request_stop();
    }
}

#[derive(Clone)]
struct PacketCtx {
    device: Arc<WintunDevice>,
    nat: Arc<TcpNat>,
    fake_ip: Arc<Mutex<FakeIpPool>>,
    listen_port: u16,
}

fn packet_loop(_dev: Arc<WintunDevice>, ctx: PacketCtx, ct: CancellationToken) {
    let mut buf = vec![0u8; MAX_IP];
    while !ct.is_cancelled() {
        match ctx.device.try_receive(&mut buf) {
            Ok(None) => break,
            Ok(Some(0)) => {
                ctx.device.wait(250);
                continue;
            }
            Ok(Some(n)) => process_packet(&ctx, &mut buf[..n]),
            Err(_) => {
                if ct.is_cancelled() {
                    break;
                }
                ctx.device.wait(250);
            }
        }
    }
}

fn process_packet(ctx: &PacketCtx, packet: &mut [u8]) {
    let Some((ip_hdr, proto, src, dst, total)) = packet::parse_ipv4(packet) else {
        return;
    };
    if proto == packet::PROTO_UDP {
        let udp = &packet[ip_hdr..total];
        let Some((src_port, dst_port, payload_len)) = packet::parse_udp(udp) else {
            return;
        };
        if dst_port == 53 {
            handle_dns(ctx, src, dst, src_port, &udp[packet::UDP_HDR..packet::UDP_HDR + payload_len]);
        }
        // Drop other UDP (QUIC/HTTP3). ICMP Port Unreachable on Fake-IP poisons
        // Windows' destination cache and stalls TCP to the same host — NanoClash
        // silently drops; Clash Party proxies UDP instead.
        return;
    }
    if proto != packet::PROTO_TCP {
        return;
    }
    let tcp = &mut packet[ip_hdr..total];
    let Some((tcp_src, tcp_dst, _, _)) = packet::parse_tcp(tcp) else {
        return;
    };
    if src == TUN_SERVER && tcp_src == ctx.listen_port {
        let Some((sess_src, sess_dst)) = ctx.nat.lookup_back(tcp_dst) else {
            return;
        };
        packet::set_addresses(packet, ip_hdr, *sess_dst.ip(), *sess_src.ip());
        packet::set_tcp_ports(&mut packet[ip_hdr..total], sess_dst.port(), sess_src.port());
        packet::update_tcp_checksum(packet, ip_hdr, *sess_dst.ip(), *sess_src.ip());
        ctx.device.send(&packet[..total]);
        return;
    }
    if dst == TUN_SERVER && tcp_dst == ctx.listen_port {
        return;
    }
    if !is_global_unicast(dst) || is_tun_prefix(dst) {
        return;
    }
    let source = SocketAddrV4::new(src, tcp_src);
    let dest = SocketAddrV4::new(dst, tcp_dst);
    let Some(nat_port) = ctx.nat.lookup(source, dest) else {
        return;
    };
    packet::set_addresses(packet, ip_hdr, TUN_CLIENT, TUN_SERVER);
    packet::set_tcp_ports(&mut packet[ip_hdr..total], nat_port, ctx.listen_port);
    packet::update_tcp_checksum(packet, ip_hdr, TUN_CLIENT, TUN_SERVER);
    ctx.device.send(&packet[..total]);
}

fn handle_dns(ctx: &PacketCtx, src: Ipv4Addr, dst: Ipv4Addr, src_port: u16, payload: &[u8]) {
    let Some((id, qname, qtype)) = parse_dns_query(payload) else {
        return;
    };
    let answer = if qtype == 1 {
        let fake = {
            let nat = ctx.nat.clone();
            ctx.fake_ip
                .lock()
                .lookup_avoiding(&qname, |ip| nat.has_destination(ip))
        };
        build_named_a_response(id, &qname, fake)
    } else {
        build_empty_dns(id, &qname, qtype)
    };
    let mut out = vec![0u8; 20 + packet::UDP_HDR + answer.len()];
    out[0] = 0x45;
    out[8] = 64;
    out[9] = packet::PROTO_UDP;
    packet::set_addresses(&mut out, 20, dst, src);
    packet::set_total_length(&mut out, (20 + packet::UDP_HDR + answer.len()) as u16);
    packet::write_udp(
        &mut out[20..],
        53,
        src_port,
        &answer,
        dst,
        src,
    );
    ctx.device.send(&out[..20 + packet::UDP_HDR + answer.len()]);
}

fn is_tun_prefix(ip: Ipv4Addr) -> bool {
    let b = ip.octets();
    b[0] == 172 && b[1] == 19 && b[2] == 0 && b[3] <= 3
}

fn is_global_unicast(ip: Ipv4Addr) -> bool {
    let b = ip.octets();
    if b[0] == 0 || b[0] == 127 {
        return false;
    }
    if b[0] == 169 && b[1] == 254 {
        return false;
    }
    if b[0] >= 224 {
        return false;
    }
    true
}

#[derive(Clone)]
struct AcceptCtx {
    rules: Arc<RuleDb>,
    outbound: Arc<OutboundDialer>,
    fake_ip: Arc<Mutex<FakeIpPool>>,
    nat: Arc<TcpNat>,
    doh: DohBlocklist,
    generation: Arc<AtomicU64>,
    relay: Arc<parking_lot::Mutex<CancellationToken>>,
}

async fn accept_loop(listener: TcpListener, ctx: AcceptCtx, ct: CancellationToken) {
    loop {
        let (client, peer) = tokio::select! {
            _ = ct.cancelled() => break,
            r = listener.accept() => match r {
                Ok(x) => x,
                Err(_) => continue,
            },
        };
        let _ = client.set_nodelay(true);
        let gen_id = ctx.generation.load(Ordering::Relaxed);
        let relay = ctx.relay.lock().clone();
        let ctx = ctx.clone();
        tokio::spawn(async move {
            let _ = handle_accepted(client, peer, gen_id, relay, ctx).await;
        });
    }
}

async fn handle_accepted(
    mut client: tokio::net::TcpStream,
    peer: std::net::SocketAddr,
    generation: u64,
    relay: CancellationToken,
    ctx: AcceptCtx,
) -> Result<()> {
    let port = peer.port();
    let Some((_, dest)) = ctx.nat.lookup_back(port) else {
        return Ok(());
    };
    if generation != ctx.generation.load(Ordering::Relaxed) || relay.is_cancelled() {
        return Ok(());
    }
    let dst_ip = *dest.ip();
    let dst_port = dest.port();
    if dst_port == 53 {
        return handle_dns_tcp(&mut client, &ctx).await;
    }
    if (dst_port == 443 || dst_port == 853) && ctx.doh.is_blocked(IpAddr::V4(dst_ip)) {
        return Ok(());
    }
    let host = ctx.fake_ip.lock().lookback(dst_ip);
    if host.is_none() && FakeIpPool::is_fake_ip_v4(dst_ip) {
        return Ok(());
    }
    let action = if let Some(ref h) = host {
        ctx.rules.match_domain(h)
    } else {
        action_for_ip(IpAddr::V4(dst_ip))
    };
    match action {
        RuleAction::Reject => return Ok(()),
        RuleAction::Direct => {
            let mut remote = tokio::select! {
                _ = relay.cancelled() => return Ok(()),
                r = dial_direct(&ctx, host.as_deref(), dst_ip, dst_port) => r?,
            };
            relay_until_cancel(&mut client, &mut remote, &relay).await;
        }
        RuleAction::Proxy => {
            let target = if let Some(h) = host {
                format!("{h}:{dst_port}")
            } else {
                format!("{dst_ip}:{dst_port}")
            };
            let mut remote = tokio::select! {
                _ = relay.cancelled() => return Ok(()),
                r = ctx.outbound.dial_async(&target) => r?,
            };
            relay_until_cancel(&mut client, &mut remote, &relay).await;
        }
    }
    Ok(())
}

/// System TCP must not read the client while REALITY dials, and must not run
/// `TlsHelloCoalesce` here (same as NanoClash `SystemTcpStack`).
///
/// Chrome's PQ ClientHello is larger than the TUN MTU (1400), so the first
/// application read is often a 517-byte prefix. Feeding that prefix to Vision
/// (coalesce mis-detect, or a flush of a partial record) leaves the TLS
/// handshake half-open until a node switch bumps generation. A playing
/// YouTube stream never hits this path. Wait for Dial, then Relay's 64KiB
/// read picks up the complete hello that has been sitting in the kernel.
async fn relay_until_cancel<R>(
    client: &mut tokio::net::TcpStream,
    remote: &mut R,
    relay: &CancellationToken,
) where
    R: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    tokio::select! {
        _ = relay.cancelled() => {}
        _ = Relay::copy_bidirectional(client, remote) => {}
    }
}

async fn dial_direct(
    ctx: &AcceptCtx,
    host: Option<&str>,
    dst_ip: Ipv4Addr,
    dst_port: u16,
) -> anyhow::Result<tokio::net::TcpStream> {
    if let Some(host) = host.filter(|_| FakeIpPool::is_fake_ip_v4(dst_ip)) {
        let real = ctx
            .outbound
            .resolve_host_ipv4(host)
            .await
            .ok_or_else(|| anyhow::anyhow!("Direct DoH failed for {host}"))?;
        Ok(DirectDial::connect(&format!("{real}:{dst_port}")).await?)
    } else {
        Ok(DirectDial::connect(&format!("{dst_ip}:{dst_port}")).await?)
    }
}

async fn handle_dns_tcp(stream: &mut tokio::net::TcpStream, ctx: &AcceptCtx) -> Result<()> {
    loop {
        let mut lenb = [0u8; 2];
        if stream.read_exact(&mut lenb).await.is_err() {
            return Ok(());
        }
        let msg_len = u16::from_be_bytes(lenb) as usize;
        if !(12..=4096).contains(&msg_len) {
            return Ok(());
        }
        let mut msg = vec![0u8; msg_len];
        if stream.read_exact(&mut msg).await.is_err() {
            return Ok(());
        }
        let Some((id, qname, qtype)) = parse_dns_query(&msg) else {
            return Ok(());
        };
        let answer = if qtype == 1 {
            let nat = ctx.nat.clone();
            let fake = ctx
                .fake_ip
                .lock()
                .lookup_avoiding(&qname, |ip| nat.has_destination(ip));
            build_named_a_response(id, &qname, fake)
        } else {
            build_empty_dns(id, &qname, qtype)
        };
        let mut frame = Vec::with_capacity(2 + answer.len());
        frame.extend_from_slice(&(answer.len() as u16).to_be_bytes());
        frame.extend_from_slice(&answer);
        stream.write_all(&frame).await?;
    }
}
