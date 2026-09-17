use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsConnector;

use crate::net::InterfaceBinder;
use crate::utils::{TtlLru, domain_to_ascii};

pub struct FakeIpPool {
    host_to_ip: HashMap<String, Ipv4Addr>,
    ip_to_host: HashMap<Ipv4Addr, String>,
    lru: VecDeque<String>,
    next: u32,
}

impl FakeIpPool {
    pub const DNS: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 2);
    const FIRST: u32 = 4;
    const LAST: u32 = 0xFFFE;
    const MAX: usize = 8192;

    pub fn new() -> Self {
        Self {
            host_to_ip: HashMap::new(),
            ip_to_host: HashMap::new(),
            lru: VecDeque::new(),
            next: Self::FIRST,
        }
    }

    pub fn is_fake_ip(ip: IpAddr) -> bool {
        let IpAddr::V4(v) = ip else { return false };
        let b = v.octets();
        if b[0] != 198 || b[1] != 18 {
            return false;
        }
        let host = ((b[2] as u32) << 8) | b[3] as u32;
        host >= Self::FIRST
    }

    pub fn is_fake_ip_v4(ip: Ipv4Addr) -> bool {
        Self::is_fake_ip(IpAddr::V4(ip))
    }

    pub fn lookup(&mut self, host: &str) -> Ipv4Addr {
        self.lookup_avoiding(host, |_| false)
    }

    pub fn lookup_avoiding(&mut self, host: &str, in_use: impl Fn(Ipv4Addr) -> bool) -> Ipv4Addr {
        let host = domain_to_ascii(host);
        if let Some(ip) = self.host_to_ip.get(&host).copied() {
            self.touch(&host);
            return ip;
        }
        if self.host_to_ip.len() >= Self::MAX {
            self.evict();
        }
        for _ in 0..65530 {
            let ip = host_to_ip(self.next);
            self.next += 1;
            if self.next > Self::LAST {
                self.next = Self::FIRST;
            }
            let b = ip.octets();
            if b[3] == 0 || b[3] == 255 {
                continue;
            }
            if self.ip_to_host.contains_key(&ip) || in_use(ip) {
                continue;
            }
            self.host_to_ip.insert(host.clone(), ip);
            self.ip_to_host.insert(ip, host.clone());
            self.lru.push_front(host);
            return ip;
        }
        Ipv4Addr::new(198, 18, 0, 4)
    }

    pub fn lookback(&mut self, ip: Ipv4Addr) -> Option<String> {
        let host = self.ip_to_host.get(&ip)?.clone();
        self.touch(&host);
        Some(host)
    }

    fn touch(&mut self, host: &str) {
        if let Some(i) = self.lru.iter().position(|h| h == host) {
            let h = self.lru.remove(i).unwrap();
            self.lru.push_front(h);
        }
    }

    fn evict(&mut self) {
        if let Some(host) = self.lru.pop_back() {
            if let Some(ip) = self.host_to_ip.remove(&host) {
                self.ip_to_host.remove(&ip);
            }
        }
    }
}

fn host_to_ip(bits: u32) -> Ipv4Addr {
    Ipv4Addr::new(198, 18, (bits >> 8) as u8, bits as u8)
}

pub struct DohBlocklist {
    blocked: HashSet<u32>,
}

impl Clone for DohBlocklist {
    fn clone(&self) -> Self {
        Self {
            blocked: self.blocked.clone(),
        }
    }
}

impl DohBlocklist {
    pub fn new() -> Self {
        let hosts = [
            "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112",
            "208.67.222.222", "208.67.220.220", "94.140.14.14", "94.140.15.15",
            "1.12.12.12", "120.53.53.53", "223.5.5.5", "223.6.6.6", "76.76.21.21",
            "185.222.222.222", "45.90.28.167", "45.90.30.167",
        ];
        let mut blocked = HashSet::new();
        for h in hosts {
            if let Ok(IpAddr::V4(v)) = h.parse() {
                let b = v.octets();
                blocked.insert(u32::from_be_bytes(b));
            }
        }
        Self { blocked }
    }

    pub fn is_blocked(&self, ip: IpAddr) -> bool {
        let IpAddr::V4(v) = ip else { return false };
        self.blocked.contains(&u32::from_be_bytes(v.octets()))
    }
}

pub struct DohResolver {
    cache: TtlLru<Option<Vec<IpAddr>>>,
}

impl DohResolver {
    pub fn new() -> Self {
        Self {
            cache: TtlLru::new(4096),
        }
    }

    pub async fn resolve(&self, host: &str) -> anyhow::Result<Vec<IpAddr>> {
        if let Some(Some(ips)) = self.cache.get(host) {
            return Ok(ips);
        }
        match self.resolve_uncached(host).await {
            Ok(ips) => {
                self.cache.set(host.to_string(), Some(ips.clone()), Some(Duration::from_secs(300)));
                Ok(ips)
            }
            Err(e) => {
                self.cache.set(host.to_string(), None, Some(Duration::from_secs(30)));
                Err(e)
            }
        }
    }

    async fn resolve_uncached(&self, host: &str) -> anyhow::Result<Vec<IpAddr>> {
        if let Ok(r) = lookup_a("223.5.5.5:443", "dns.alidns.com", "https://223.5.5.5/resolve", host).await {
            if !r.is_empty() {
                return Ok(r);
            }
        }
        lookup_a("1.12.12.12:443", "doh.pub", "https://doh.pub/dns-query", host).await
    }
}

async fn lookup_a(dial: &str, sni: &str, base: &str, host: &str) -> anyhow::Result<Vec<IpAddr>> {
    let url = format!("{base}?name={host}&type=A");
    let ips = query(dial, sni, &url).await?;
    if ips.is_empty() {
        anyhow::bail!("DoH empty for {host}");
    }
    Ok(ips)
}

async fn query(dial: &str, sni: &str, url: &str) -> anyhow::Result<Vec<IpAddr>> {
    tokio::time::timeout(Duration::from_secs(5), query_inner(dial, sni, url))
        .await
        .map_err(|_| anyhow::anyhow!("DoH timeout"))?
}

async fn query_inner(dial: &str, sni: &str, url: &str) -> anyhow::Result<Vec<IpAddr>> {
    let addr: SocketAddr = dial.parse()?;
    let tcp = InterfaceBinder::connect(addr).await?;
    clash_proxynet::install_crypto_provider();
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let cfg = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_root_certificates(roots)
    .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(cfg));
    let name = rustls_pki_types::ServerName::try_from(sni.to_string())?;
    let mut tls = connector.connect(name, tcp).await?;
    let uri = url::Url::parse(url)?;
    let path = format!("{}?{}", uri.path(), uri.query().unwrap_or(""));
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {sni}\r\nAccept: application/dns-json\r\nConnection: close\r\n\r\n"
    );
    tls.write_all(req.as_bytes()).await?;
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        let n = tls.read(&mut tmp).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(body) = http_body_if_complete(&buf) {
            return parse_doh_ips(body);
        }
        if buf.len() > 64 * 1024 {
            anyhow::bail!("DoH response too large");
        }
    }
    let text = String::from_utf8_lossy(&buf);
    let body = text.split("\r\n\r\n").nth(1).unwrap_or(&text);
    parse_doh_ips(body)
}

fn http_body_if_complete(buf: &[u8]) -> Option<&str> {
    let idx = buf.windows(4).position(|w| w == b"\r\n\r\n")?;
    let headers = std::str::from_utf8(&buf[..idx]).ok()?;
    let body = &buf[idx + 4..];
    let mut content_len = None;
    for line in headers.split("\r\n").skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("Content-Length") {
            content_len = value.trim().parse::<usize>().ok();
            break;
        }
    }
    match content_len {
        Some(n) if body.len() >= n => std::str::from_utf8(&body[..n]).ok(),
        _ => None,
    }
}

fn parse_doh_ips(body: &str) -> anyhow::Result<Vec<IpAddr>> {
    let v: serde_json::Value = serde_json::from_str(body)?;
    let mut ips = Vec::new();
    if let Some(ans) = v.get("Answer").and_then(|a| a.as_array()) {
        for a in ans {
            let ty = a
                .get("type")
                .and_then(|t| t.as_i64().or_else(|| t.as_str()?.parse().ok()));
            if ty == Some(1) || ty == Some(28) {
                if let Some(data) = a.get("data").and_then(|d| d.as_str()) {
                    if let Ok(ip) = data.parse::<IpAddr>() {
                        ips.push(ip);
                    }
                }
            }
        }
    }
    Ok(ips)
}

pub fn parse_dns_query(payload: &[u8]) -> Option<(u16, String, u16)> {
    if payload.len() < 12 {
        return None;
    }
    let id = u16::from_be_bytes([payload[0], payload[1]]);
    let flags = u16::from_be_bytes([payload[2], payload[3]]);
    if flags & 0x8000 != 0 {
        return None;
    }
    let qd = u16::from_be_bytes([payload[4], payload[5]]);
    if qd < 1 {
        return None;
    }
    let mut off = 12usize;
    let qname = read_dns_name(payload, &mut off)?;
    if off + 4 > payload.len() || qname.is_empty() {
        return None;
    }
    let qtype = u16::from_be_bytes([payload[off], payload[off + 1]]);
    let qclass = u16::from_be_bytes([payload[off + 2], payload[off + 3]]);
    (qclass == 1).then_some((id, qname, qtype))
}

fn read_dns_name(msg: &[u8], off: &mut usize) -> Option<String> {
    let mut labels = Vec::new();
    let mut jumped = false;
    let mut end = *off;
    for _ in 0..64 {
        if *off >= msg.len() {
            return None;
        }
        let len = msg[*off];
        if len == 0 {
            *off += 1;
            if !jumped {
                end = *off;
            }
            *off = end;
            return Some(labels.join("."));
        }
        if len & 0xC0 == 0xC0 {
            if *off + 1 >= msg.len() {
                return None;
            }
            let ptr = (((len & 0x3F) as usize) << 8) | msg[*off + 1] as usize;
            if !jumped {
                end = *off + 2;
            }
            *off = ptr;
            jumped = true;
            continue;
        }
        *off += 1;
        if *off + len as usize > msg.len() {
            return None;
        }
        labels.push(String::from_utf8_lossy(&msg[*off..*off + len as usize]).into_owned());
        *off += len as usize;
    }
    None
}

fn encode_dns_name(name: &str) -> Vec<u8> {
    let name = domain_to_ascii(name);
    let mut out = Vec::new();
    for label in name.split('.').filter(|s| !s.is_empty()) {
        let b = label.as_bytes();
        out.push(b.len() as u8);
        out.extend_from_slice(b);
    }
    out.push(0);
    out
}

pub fn build_named_a_response(id: u16, qname: &str, ip: Ipv4Addr) -> Vec<u8> {
    let name = encode_dns_name(qname);
    let mut buf = vec![0u8; 12 + name.len() + 4 + 16];
    buf[0..2].copy_from_slice(&id.to_be_bytes());
    buf[2..4].copy_from_slice(&0x8580u16.to_be_bytes());
    buf[4..6].copy_from_slice(&1u16.to_be_bytes());
    buf[6..8].copy_from_slice(&1u16.to_be_bytes());
    let mut o = 12;
    buf[o..o + name.len()].copy_from_slice(&name);
    o += name.len();
    buf[o..o + 2].copy_from_slice(&1u16.to_be_bytes());
    o += 2;
    buf[o..o + 2].copy_from_slice(&1u16.to_be_bytes());
    o += 2;
    buf[o..o + 2].copy_from_slice(&0xC00Cu16.to_be_bytes());
    o += 2;
    buf[o..o + 2].copy_from_slice(&1u16.to_be_bytes());
    o += 2;
    buf[o..o + 2].copy_from_slice(&1u16.to_be_bytes());
    o += 2;
    buf[o..o + 4].copy_from_slice(&300u32.to_be_bytes());
    o += 4;
    buf[o..o + 2].copy_from_slice(&4u16.to_be_bytes());
    o += 2;
    buf[o..o + 4].copy_from_slice(&ip.octets());
    buf.truncate(o + 4);
    buf
}

pub fn build_empty_dns(id: u16, qname: &str, qtype: u16) -> Vec<u8> {
    let name = encode_dns_name(qname);
    let mut buf = vec![0u8; 12 + name.len() + 4];
    buf[0..2].copy_from_slice(&id.to_be_bytes());
    buf[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
    buf[4..6].copy_from_slice(&1u16.to_be_bytes());
    let mut o = 12;
    buf[o..o + name.len()].copy_from_slice(&name);
    o += name.len();
    buf[o..o + 2].copy_from_slice(&qtype.to_be_bytes());
    o += 2;
    buf[o..o + 2].copy_from_slice(&1u16.to_be_bytes());
    buf
}

pub fn build_a_response(query: &[u8], ip: Ipv4Addr) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }
    let mut out = Vec::from(&query[..12]);
    out[2] = 0x81;
    out[3] = 0x80;
    out[6] = 0;
    out[7] = 1;
    // copy question
    let mut i = 12;
    while i < query.len() && query[i] != 0 {
        i += 1 + query[i] as usize;
    }
    i += 5; // 0 + type + class
    if i > query.len() {
        return None;
    }
    out.extend_from_slice(&query[12..i]);
    out.extend_from_slice(&[0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04]);
    out.extend_from_slice(&ip.octets());
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_body_waits_for_content_length() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhelloEXTRA";
        assert_eq!(http_body_if_complete(raw), Some("hello"));
        let partial = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhel";
        assert_eq!(http_body_if_complete(partial), None);
    }

    #[test]
    fn parse_doh_accepts_numeric_and_string_types() {
        let body = r#"{"Answer":[{"type":1,"data":"1.2.3.4"},{"type":"1","data":"5.6.7.8"}]}"#;
        let ips = parse_doh_ips(body).unwrap();
        assert_eq!(ips.len(), 2);
        assert!(ips.contains(&"1.2.3.4".parse().unwrap()));
        assert!(ips.contains(&"5.6.7.8".parse().unwrap()));
    }

    #[test]
    fn empty_aaaa_is_success_not_nxdomain() {
        let msg = build_empty_dns(7, "www.google.com", 28);
        assert_eq!(&msg[2..4], &0x8180u16.to_be_bytes());
        assert_eq!(u16::from_be_bytes([msg[6], msg[7]]), 0);
    }
}
