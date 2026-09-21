use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use parking_lot::RwLock;

use clash_proxynet::{
    HttpProxyOptions, OutboundKind, SocksOptions, SsOptions, TrojanOptions, VlessOptions,
    VlessSecurity, VmessOptions, dial,
};

use crate::config::ProxyNode;
use crate::dns::DohResolver;
use crate::net::InterfaceBinder;
use crate::rules::try_split_host_port;

pub struct OutboundDialer {
    doh: DohResolver,
    current: RwLock<Option<ProxyNode>>,
}

impl OutboundDialer {
    pub fn new(doh: DohResolver) -> Self {
        Self {
            doh,
            current: RwLock::new(None),
        }
    }

    pub fn current(&self) -> Option<ProxyNode> {
        self.current.read().clone()
    }

    pub fn set_current(&self, node: Option<ProxyNode>) {
        *self.current.write() = node;
    }

    pub async fn dial_async(
        &self,
        host_port: &str,
    ) -> anyhow::Result<clash_proxynet::BoxedStream> {
        let node = self
            .current()
            .ok_or_else(|| anyhow::anyhow!("No proxy node selected"))?;
        let (dest_host, port_str) = try_split_host_port(host_port).unwrap_or_else(|| {
            let idx = host_port.rfind(':').unwrap_or(0);
            (host_port[..idx].trim_matches(['[', ']']).to_string(), host_port[idx + 1..].to_string())
        });
        let dest_host = dest_host.trim_matches(['[', ']']).to_string();
        let dest_port: u16 = port_str.parse()?;
        self.dial_via(&node, &dest_host, dest_port).await
    }

    pub async fn dial_via(
        &self,
        node: &ProxyNode,
        host: &str,
        port: u16,
    ) -> anyhow::Result<clash_proxynet::BoxedStream> {
        let ips = self.resolve_host(&node.server).await?;
        self.dial_via_ips(node, &ips, host, port).await
    }

    pub async fn dial_via_ips(
        &self,
        node: &ProxyNode,
        ips: &[IpAddr],
        host: &str,
        port: u16,
    ) -> anyhow::Result<clash_proxynet::BoxedStream> {
        let tcp = InterfaceBinder::connect_happy(ips, node.port, Duration::from_secs(8)).await?;
        let dial_host = ips
            .iter()
            .find(|i| i.is_ipv4())
            .or_else(|| ips.first())
            .ok_or_else(|| anyhow::anyhow!("DoH no A record for node {}", node.server))?
            .to_string();
        let ty = node.type_name.to_ascii_lowercase();
        let kind = to_kind(node, &dial_host, &ty)?;
        Ok(dial(&kind, tcp, host, port, Duration::from_secs(15)).await?)
    }

    pub async fn resolve_host(&self, host: &str) -> anyhow::Result<Vec<IpAddr>> {
        let host = host.trim().trim_end_matches('.');
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }
        let mut ips = self.doh.resolve(host).await?;
        ips.sort_by_key(|ip| ip.is_ipv6());
        Ok(ips)
    }

    pub async fn resolve_host_ipv4(&self, host: &str) -> Option<IpAddr> {
        self.resolve_host(host)
            .await
            .ok()
            .and_then(|ips| ips.into_iter().find(|i| i.is_ipv4()))
    }

    pub async fn resolve_node_ipv4(&self, node: Option<&ProxyNode>) -> Option<IpAddr> {
        let node = node?;
        if node.is_subscription_info() {
            return None;
        }
        self.resolve_host_ipv4(&node.server).await
    }
}

fn to_kind(node: &ProxyNode, dial_host: &str, ty: &str) -> anyhow::Result<OutboundKind> {
    match ty {
        "vless" => Ok(OutboundKind::Vless(to_vless(node, dial_host))),
        "trojan" => Ok(OutboundKind::Trojan(to_trojan(node, dial_host))),
        "ss" | "shadowsocks" => Ok(OutboundKind::Shadowsocks(to_ss(node, dial_host))),
        "vmess" => Ok(OutboundKind::Vmess(to_vmess(node, dial_host))),
        "socks" | "socks5" => Ok(OutboundKind::Socks5(to_socks(node))),
        "http" | "https" => Ok(OutboundKind::Http(to_http(node))),
        other => Err(anyhow::anyhow!("unsupported outbound type {other}")),
    }
}

fn to_vless(node: &ProxyNode, dial_host: &str) -> VlessOptions {
    let security = if node.reality_public_key.as_deref().is_some_and(|s| !s.is_empty()) {
        VlessSecurity::Reality
    } else if node.tls {
        VlessSecurity::Tls
    } else {
        VlessSecurity::None
    };
    VlessOptions {
        id: node.uuid.clone().unwrap_or_default(),
        host: dial_host.to_string(),
        port: node.port,
        security,
        transport: if node.network.is_empty() {
            "tcp".into()
        } else {
            node.network.clone()
        },
        path: node.ws_path.clone(),
        host_header: node.ws_host.clone(),
        sni: node.server_name.clone(),
        alpn: Vec::new(),
        flow: node.flow.clone(),
        fingerprint: node.client_fingerprint.clone(),
        reality_public_key: node.reality_public_key.clone(),
        reality_short_id: node.reality_short_id.clone(),
        allow_insecure: node.skip_cert_verify,
    }
}

fn to_trojan(node: &ProxyNode, dial_host: &str) -> TrojanOptions {
    TrojanOptions {
        password: node.password.clone().unwrap_or_default(),
        host: dial_host.to_string(),
        port: node.port,
        transport: if node.network.is_empty() {
            "tcp".into()
        } else {
            node.network.clone()
        },
        path: node.ws_path.clone(),
        host_header: node.ws_host.clone(),
        sni: node.server_name.clone(),
        alpn: Vec::new(),
        allow_insecure: node.skip_cert_verify,
    }
}

fn net(node: &ProxyNode) -> String {
    if node.network.is_empty() {
        "tcp".into()
    } else {
        node.network.clone()
    }
}

fn to_ss(node: &ProxyNode, dial_host: &str) -> SsOptions {
    SsOptions {
        method: node
            .cipher
            .clone()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "aes-256-gcm".into()),
        password: node.password.clone().unwrap_or_default(),
        host: dial_host.to_string(),
        port: node.port,
        plugin: node.plugin.clone(),
        plugin_opts: node.plugin_opts.clone(),
        transport: net(node),
        path: node.ws_path.clone(),
        host_header: node.ws_host.clone(),
        sni: node.server_name.clone(),
        alpn: Vec::new(),
        allow_insecure: node.skip_cert_verify,
        tls: node.tls,
    }
}

fn to_vmess(node: &ProxyNode, dial_host: &str) -> VmessOptions {
    VmessOptions {
        id: node.uuid.clone().unwrap_or_default(),
        security: node
            .cipher
            .clone()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "auto".into()),
        alter_id: node.alter_id,
        host: dial_host.to_string(),
        port: node.port,
        transport: net(node),
        path: node.ws_path.clone(),
        host_header: node.ws_host.clone(),
        sni: node.server_name.clone(),
        alpn: Vec::new(),
        allow_insecure: node.skip_cert_verify,
        tls: node.tls,
    }
}

fn to_socks(node: &ProxyNode) -> SocksOptions {
    SocksOptions {
        username: node.username.clone(),
        password: node.password.clone(),
    }
}

fn to_http(node: &ProxyNode) -> HttpProxyOptions {
    HttpProxyOptions {
        username: node.username.clone(),
        password: node.password.clone(),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HealthStatus {
    Idle,
    Checking,
    Ok,
    Slow,
    LatencyFailed,
}

#[derive(Clone, Debug)]
pub struct HealthCheckResult {
    pub latency_ok: bool,
    pub latency_ms: Option<i32>,
    pub status: HealthStatus,
}

pub struct HealthChecker {
    dialer: Arc<OutboundDialer>,
}

impl HealthChecker {
    pub const TIMEOUT_MS: u64 = 3000;
    pub const SLOW_MS: i32 = 400;
    pub const MAX_CONCURRENCY: usize = 30;

    pub fn new(dialer: Arc<OutboundDialer>) -> Self {
        Self { dialer }
    }

    pub async fn check(&self, node: &ProxyNode) -> HealthCheckResult {
        let work = async {
            let ips = self.dialer.resolve_host(&node.server).await?;
            let start = std::time::Instant::now();
            let ok = self.probe_resolved(node, &ips).await?;
            Ok::<_, anyhow::Error>((ok, start.elapsed().as_millis() as i32))
        };
        match tokio::time::timeout(Duration::from_millis(Self::TIMEOUT_MS), work).await {
            Ok(Ok((true, ms))) => HealthCheckResult {
                latency_ok: true,
                latency_ms: Some(ms),
                status: if ms >= Self::SLOW_MS {
                    HealthStatus::Slow
                } else {
                    HealthStatus::Ok
                },
            },
            _ => HealthCheckResult {
                latency_ok: false,
                latency_ms: None,
                status: HealthStatus::LatencyFailed,
            },
        }
    }

    async fn probe_resolved(&self, node: &ProxyNode, ips: &[IpAddr]) -> anyhow::Result<bool> {
        let mut stream = self
            .dialer
            .dial_via_ips(node, ips, "www.gstatic.com", 80)
            .await?;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        stream
            .write_all(b"GET /generate_204 HTTP/1.1\r\nHost: www.gstatic.com\r\nConnection: close\r\nUser-Agent: rust-clash\r\n\r\n")
            .await?;
        stream.flush().await?;
        let mut buf = [0u8; 512];
        let mut total = 0usize;
        while total < buf.len() {
            let n = stream.read(&mut buf[total..]).await.unwrap_or(0);
            if n == 0 {
                break;
            }
            total += n;
            if buf[..total].windows(2).any(|w| w == b"\r\n") {
                break;
            }
        }
        if total == 0 {
            return Ok(false);
        }
        let head = String::from_utf8_lossy(&buf[..total]);
        let status = head.split("\r\n").next().unwrap_or("");
        Ok(status.contains(" 204"))
    }

    pub async fn check_all(
        &self,
        nodes: &[ProxyNode],
        cancel: Option<&std::sync::atomic::AtomicBool>,
    ) -> Vec<Option<HealthCheckResult>> {
        use tokio::sync::Semaphore;
        let sem = Arc::new(Semaphore::new(Self::MAX_CONCURRENCY));
        let mut futs = Vec::with_capacity(nodes.len());
        for n in nodes {
            if n.is_subscription_info() {
                futs.push(futures_or_none());
                continue;
            }
            let permit = sem.clone();
            let node = n.clone();
            let this = self.dialer.clone();
            futs.push(tokio::spawn(async move {
                let _g = permit.acquire_owned().await.ok();
                let checker = HealthChecker { dialer: this };
                Some(checker.check(&node).await)
            }));
        }
        let mut out = Vec::with_capacity(futs.len());
        for f in futs {
            if cancel.is_some_and(|c| c.load(std::sync::atomic::Ordering::Relaxed)) {
                f.abort();
                out.push(None);
                continue;
            }
            out.push(match f.await {
                Ok(v) => v,
                Err(_) => Some(HealthCheckResult {
                    latency_ok: false,
                    latency_ms: None,
                    status: HealthStatus::LatencyFailed,
                }),
            });
        }
        out
    }

    pub async fn check_stream(
        &self,
        nodes: Vec<ProxyNode>,
        cancel: Arc<AtomicBool>,
        tx: tokio::sync::mpsc::UnboundedSender<(String, String, u16, HealthCheckResult)>,
    ) {
        use tokio::sync::Semaphore;
        let sem = Arc::new(Semaphore::new(Self::MAX_CONCURRENCY));
        let mut joins = Vec::new();
        for n in nodes {
            if n.is_subscription_info() {
                continue;
            }
            let permit = sem.clone();
            let dialer = self.dialer.clone();
            let cancel = cancel.clone();
            let tx = tx.clone();
            joins.push(tokio::spawn(async move {
                let _g = permit.acquire_owned().await.ok();
                if cancel.load(std::sync::atomic::Ordering::Relaxed) {
                    return;
                }
                let r = HealthChecker { dialer }.check(&n).await;
                if cancel.load(std::sync::atomic::Ordering::Relaxed) {
                    return;
                }
                let _ = tx.send((n.name, n.server, n.port, r));
            }));
        }
        for j in joins {
            let _ = j.await;
        }
    }
}

fn futures_or_none() -> tokio::task::JoinHandle<Option<HealthCheckResult>> {
    tokio::spawn(async { None })
}
