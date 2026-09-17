use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;

use flate2::read::GzDecoder;

use crate::paths::AppPaths;
use crate::utils::{TtlLru, domain_to_ascii};
use crate::RULES_GZ;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuleAction {
    Reject = 1,
    Direct = 2,
    Proxy = 3,
}

impl RuleAction {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Reject),
            2 => Some(Self::Direct),
            3 => Some(Self::Proxy),
            _ => None,
        }
    }
}

const FLAG_SUFFIX: u8 = 0x80;
const SEP: u8 = 0x01;

pub struct RuleDb {
    records: HashMap<String, u8>,
    cache: TtlLru<RuleAction>,
}

impl RuleDb {
    pub fn load_default() -> anyhow::Result<Self> {
        let sidecar = AppPaths::rules_bin_sidecar();
        if sidecar.exists() {
            return Self::load_file(&sidecar);
        }
        let path = ensure_extracted()?;
        Self::load_file(&path)
    }

    pub fn load_file(path: &Path) -> anyhow::Result<Self> {
        let raw = fs::read(path)?;
        Self::load_bytes(&raw)
    }

    pub fn load_bytes(raw: &[u8]) -> anyhow::Result<Self> {
        if raw.len() < 9 || raw[..4] != *b"CFWR" || raw[4] != 1 {
            anyhow::bail!("rules.bin: bad magic");
        }
        let count = u32::from_le_bytes(raw[5..9].try_into().unwrap());
        let mut records = HashMap::with_capacity(count as usize);
        let mut off = 9usize;
        for _ in 0..count {
            if off + 2 > raw.len() {
                anyhow::bail!("rules.bin truncated");
            }
            let key_len = u16::from_le_bytes(raw[off..off + 2].try_into().unwrap()) as usize;
            off += 2;
            if off + key_len + 1 > raw.len() {
                anyhow::bail!("rules.bin truncated key");
            }
            let key = String::from_utf8_lossy(&raw[off..off + key_len]).into_owned();
            off += key_len;
            records.insert(key, raw[off]);
            off += 1;
        }
        let db = Self {
            records,
            cache: TtlLru::new(4096),
        };
        db.self_check()?;
        Ok(db)
    }

    fn self_check(&self) -> anyhow::Result<()> {
        self.check("www.baidu.com", RuleAction::Direct)?;
        self.check("www.google.com", RuleAction::Proxy)?;
        self.check("www.gstatic.com", RuleAction::Proxy)?;
        self.check("fonts.gstatic.com", RuleAction::Proxy)?;
        Ok(())
    }

    fn check(&self, host: &str, want: RuleAction) -> anyhow::Result<()> {
        let got = self.match_domain_uncached(host);
        if got != want {
            anyhow::bail!("rules self-check: {host} got {got:?} want {want:?}");
        }
        Ok(())
    }

    pub fn decide_route(&self, host_port: &str) -> RuleAction {
        let host = if let Some((h, _)) = try_split_host_port(host_port) {
            h
        } else {
            host_port.to_string()
        };
        let host = host.trim().trim_matches(['[', ']']);
        if let Ok(ip) = host.parse::<IpAddr>() {
            return action_for_ip(ip);
        }
        self.match_domain(host)
    }

    pub fn match_domain(&self, domain: &str) -> RuleAction {
        let domain = domain_to_ascii(domain);
        if domain.is_empty() {
            return RuleAction::Proxy;
        }
        if let Ok(ip) = domain.parse::<IpAddr>() {
            return action_for_ip(ip);
        }
        if let Some(c) = self.cache.get(&domain) {
            return c;
        }
        let a = self.match_domain_uncached(&domain);
        self.cache.set(domain, a, None);
        a
    }

    fn match_domain_uncached(&self, domain: &str) -> RuleAction {
        let labels: Vec<&str> = domain.split('.').filter(|p| !p.is_empty()).collect();
        if labels.is_empty() {
            return RuleAction::Proxy;
        }
        let mut best = None;
        let mut sb = String::new();
        let mut acc = 0;
        for i in (0..labels.len()).rev() {
            if !sb.is_empty() {
                sb.push(SEP as char);
            }
            sb.push_str(labels[i]);
            acc += 1;
            if let Some(packed) = self.records.get(&sb) {
                let action = RuleAction::from_u8(packed & 0x7F);
                let is_suffix = packed & FLAG_SUFFIX != 0;
                if is_suffix || acc == labels.len() {
                    best = action;
                }
            }
        }
        match best {
            Some(a @ (RuleAction::Reject | RuleAction::Direct | RuleAction::Proxy)) => a,
            _ => RuleAction::Proxy,
        }
    }
}

pub fn action_for_ip(ip: IpAddr) -> RuleAction {
    match ip {
        IpAddr::V4(v4) => {
            let b = v4.octets();
            if v4.is_loopback()
                || v4.is_private()
                || (b[0] == 169 && b[1] == 254)
                || (b[0] == 100 && (64..=127).contains(&b[1]))
                || v4 == Ipv4Addr::UNSPECIFIED
            {
                RuleAction::Direct
            } else {
                RuleAction::Proxy
            }
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback() || v6.is_unicast_link_local() || v6.is_multicast() || {
                let b = v6.octets();
                (b[0] & 0xfe) == 0xfc
            } {
                RuleAction::Direct
            } else {
                RuleAction::Proxy
            }
        }
    }
}

pub fn try_split_host_port(authority: &str) -> Option<(String, String)> {
    if authority.starts_with('[') || authority.chars().filter(|c| *c == ':').count() == 1 {
        if authority.starts_with('[') {
            if let Some(end) = authority.find(']') {
                if end + 1 < authority.len() && authority.as_bytes()[end + 1] == b':' {
                    let host = authority[1..end].to_string();
                    let port = authority[end + 2..].to_string();
                    if !port.is_empty() {
                        return Some((host, port));
                    }
                }
            }
        } else if let Some(idx) = authority.rfind(':') {
            if idx > 0 {
                let host = authority[..idx].to_string();
                let port = authority[idx + 1..].to_string();
                if !port.is_empty() {
                    return Some((host, port));
                }
            }
        }
    }
    None
}

pub fn join_host_port(host: &str, port: &str) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

pub fn with_port(authority: &str, default_port: &str) -> Option<String> {
    let authority = authority.trim();
    if authority.is_empty() {
        return None;
    }
    if let Some((h, p)) = try_split_host_port(authority) {
        return Some(join_host_port(&h, &p));
    }
    let host = authority.trim_matches(['[', ']']);
    if host.is_empty() {
        return None;
    }
    Some(join_host_port(host, default_port))
}

fn ensure_extracted() -> anyhow::Result<std::path::PathBuf> {
    let mut gz = GzDecoder::new(RULES_GZ);
    let mut plain = Vec::new();
    gz.read_to_end(&mut plain)?;
    if plain.is_empty() {
        anyhow::bail!("Embedded rules database is empty after GZip decompress.");
    }
    fs::create_dir_all(AppPaths::user_data_dir())?;
    let path = AppPaths::user_rules_bin();
    if path.exists() {
        if let Ok(on_disk) = fs::read(&path) {
            if on_disk == plain {
                return Ok(path);
            }
        }
    }
    let tmp = path.with_extension("bin.tmp");
    fs::write(&tmp, &plain)?;
    fs::rename(&tmp, &path)?;
    Ok(path)
}
