use std::fs;
use std::path::Path;

use base64::Engine;
use sha2::{Digest, Sha256};

use crate::net::InterfaceBinder;
use crate::paths::AppPaths;

#[derive(Debug, Clone)]
pub struct ProxyNode {
    pub name: String,
    pub type_name: String,
    pub server: String,
    pub port: u16,
    pub uuid: Option<String>,
    pub password: Option<String>,
    pub tls: bool,
    pub server_name: Option<String>,
    pub flow: Option<String>,
    pub network: String,
    pub client_fingerprint: Option<String>,
    pub reality_public_key: Option<String>,
    pub reality_short_id: Option<String>,
    pub skip_cert_verify: bool,
    pub ws_path: Option<String>,
    pub ws_host: Option<String>,
    pub security: Option<String>,
    pub cipher: Option<String>,
    pub username: Option<String>,
    pub plugin: Option<String>,
    pub plugin_opts: Option<String>,
    pub alter_id: u16,
}

impl Default for ProxyNode {
    fn default() -> Self {
        Self {
            name: String::new(),
            type_name: String::new(),
            server: String::new(),
            port: 0,
            uuid: None,
            password: None,
            tls: false,
            server_name: None,
            flow: None,
            network: "tcp".into(),
            client_fingerprint: None,
            reality_public_key: None,
            reality_short_id: None,
            skip_cert_verify: false,
            ws_path: None,
            ws_host: None,
            security: None,
            cipher: None,
            username: None,
            plugin: None,
            plugin_opts: None,
            alter_id: 0,
        }
    }
}

impl ProxyNode {
    pub fn is_subscription_info(&self) -> bool {
        self.name.contains("剩余流量")
            || self.name.contains("距离下次重置")
            || self.name.contains("套餐到期")
            || self.name.contains("官网")
    }
}

pub struct NodeFilter;

impl NodeFilter {
    pub fn accept(node: &ProxyNode) -> bool {
        let ty = normalize_type(&node.type_name);
        let mut network = node.network.trim().to_ascii_lowercase();
        if network == "websocket" {
            network = "ws".into();
        }
        if matches!(network.as_str(), "grpc" | "xhttp" | "h2" | "quic") {
            return false;
        }
        if !matches!(network.as_str(), "tcp" | "ws" | "httpupgrade" | "raw" | "") {
            return false;
        }
        match ty.as_str() {
            "vless" => {
                let security = Self::resolve_security(node);
                if !matches!(security.as_str(), "none" | "tls" | "reality") {
                    return false;
                }
                let flow = node.flow.as_deref().unwrap_or("").trim();
                if !flow.is_empty() && !flow.eq_ignore_ascii_case("xtls-rprx-vision") {
                    return false;
                }
                !node.uuid.as_deref().unwrap_or("").trim().is_empty()
            }
            "trojan" => !node.password.as_deref().unwrap_or("").trim().is_empty(),
            "ss" => {
                if node.password.as_deref().unwrap_or("").trim().is_empty() {
                    return false;
                }
                let method = node.cipher.as_deref().unwrap_or("aes-256-gcm").trim();
                clash_proxynet::ss_supported_cipher(method) && Self::ss_plugin_ok(node)
            }
            "vmess" => !node.uuid.as_deref().unwrap_or("").trim().is_empty(),
            "socks5" | "http" => true,
            _ => false,
        }
    }

    fn ss_plugin_ok(node: &ProxyNode) -> bool {
        let plugin = node.plugin.as_deref().unwrap_or("").trim().to_ascii_lowercase();
        plugin.is_empty()
            || plugin == "none"
            || matches!(
                plugin.as_str(),
                "obfs" | "obfs-local" | "simple-obfs" | "v2ray-plugin"
            )
    }

    pub fn resolve_security(node: &ProxyNode) -> String {
        if let Some(s) = &node.security {
            if !s.is_empty() {
                return s.trim().to_ascii_lowercase();
            }
        }
        if node.reality_public_key.as_deref().is_some_and(|s| !s.is_empty()) {
            return "reality".into();
        }
        if node.tls {
            "tls".into()
        } else {
            "none".into()
        }
    }
}

pub struct ContentStore;

impl ContentStore {
    pub fn sha256_hex(data: &[u8]) -> String {
        hex::encode(Sha256::digest(data))
    }

    pub fn save(data: &[u8]) -> String {
        let _ = fs::create_dir_all(AppPaths::data_dir());
        let hash = Self::sha256_hex(data);
        let path = AppPaths::data_dir().join(&hash);
        if !path.exists() {
            let _ = fs::write(path, data);
        }
        hash
    }

    pub fn try_read(hash: &str) -> Option<Vec<u8>> {
        if !Self::is_safe(hash) {
            return None;
        }
        let path = AppPaths::data_dir().join(hash);
        let root = AppPaths::data_dir();
        let path_c = path.canonicalize().ok()?;
        let root_c = root.canonicalize().ok()?;
        if !path_c.starts_with(&root_c) {
            return None;
        }
        fs::read(path).ok()
    }

    pub fn delete_if_unreferenced(hash: &str, referenced: &[String]) {
        if !Self::is_safe(hash) {
            return;
        }
        if referenced.iter().any(|h| h.eq_ignore_ascii_case(hash)) {
            return;
        }
        let _ = fs::remove_file(AppPaths::data_dir().join(hash));
    }

    pub fn is_safe(hash: &str) -> bool {
        hash.len() == 64
            && !hash.contains("..")
            && !hash.contains('/')
            && !hash.contains('\\')
            && !hash.contains(':')
            && hash.chars().all(|c| c.is_ascii_hexdigit())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileKind {
    Cloud,
    Local,
}

#[derive(Debug, Clone)]
pub struct ProfileEntry {
    pub name: String,
    pub hash: String,
    pub kind: ProfileKind,
    pub url: Option<String>,
    pub used_bytes: Option<i64>,
    pub total_bytes: Option<i64>,
    pub expire_unix: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct SubscriptionUserInfo {
    pub upload: Option<i64>,
    pub download: Option<i64>,
    pub total: Option<i64>,
    pub expire_unix: Option<i64>,
}

pub struct ProfileStore {
    profiles: Vec<ProfileEntry>,
    default_name: Option<String>,
    pub load_error: Option<String>,
}

impl ProfileStore {
    pub fn new() -> Self {
        Self {
            profiles: Vec::new(),
            default_name: None,
            load_error: None,
        }
    }

    pub fn profiles(&self) -> &[ProfileEntry] {
        &self.profiles
    }

    pub fn default_name(&self) -> Option<&str> {
        self.default_name.as_deref()
    }

    pub fn active(&self) -> Option<&ProfileEntry> {
        if let Some(n) = &self.default_name {
            if let Some(p) = self.profiles.iter().find(|p| p.name == *n) {
                return Some(p);
            }
        }
        self.profiles.first()
    }

    pub fn load_or_migrate(&mut self) {
        self.profiles.clear();
        self.default_name = None;
        self.load_error = None;
        if AppPaths::app_config_yaml().exists() {
            self.load_from_file(&AppPaths::app_config_yaml());
        }
    }

    pub fn save(&self) {
        let _ = fs::create_dir_all(AppPaths::data_dir());
        let mut sb = String::new();
        if let Some(d) = &self.default_name {
            sb.push_str("default: ");
            sb.push_str(&yaml_escape(d));
            sb.push('\n');
        }
        sb.push_str("profiles:\n");
        for p in &self.profiles {
            sb.push_str("  - name: ");
            sb.push_str(&yaml_escape(&p.name));
            sb.push('\n');
            sb.push_str("    hash: ");
            sb.push_str(&p.hash);
            sb.push('\n');
            sb.push_str("    type: ");
            sb.push_str(if p.kind == ProfileKind::Cloud {
                "cloud"
            } else {
                "local"
            });
            sb.push('\n');
            if p.kind == ProfileKind::Cloud {
                if let Some(u) = &p.url {
                    sb.push_str("    url: ");
                    sb.push_str(&yaml_escape(u));
                    sb.push('\n');
                }
                if let Some(used) = p.used_bytes {
                    sb.push_str(&format!("    used: {used}\n"));
                }
                if let Some(total) = p.total_bytes.filter(|t| *t > 0) {
                    sb.push_str(&format!("    total: {total}\n"));
                }
                if let Some(exp) = p.expire_unix.filter(|t| *t > 0) {
                    sb.push_str(&format!("    expire: {exp}\n"));
                }
            }
        }
        let _ = fs::write(AppPaths::app_config_yaml(), sb);
    }

    pub fn set_default(&mut self, name: &str) {
        if self.profiles.iter().any(|p| p.name == name) {
            self.default_name = Some(name.to_string());
            self.save();
        }
    }

    pub fn name_exists(&self, name: &str) -> bool {
        self.profiles.iter().any(|p| p.name == name)
    }

    pub fn allocate_unique_name(&self, preferred: Option<&str>) -> String {
        let base = preferred
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("Proxy")
            .to_string();
        if !self.name_exists(&base) {
            return base;
        }
        for i in 1..10_000 {
            let c = format!("{base}#{i}");
            if !self.name_exists(&c) {
                return c;
            }
        }
        format!("{base}#{}", uuid::Uuid::new_v4().simple())
    }

    pub fn add_local(&mut self, name: Option<&str>, content: &[u8]) -> ProfileEntry {
        let name = self.allocate_unique_name(name);
        let hash = ContentStore::save(content);
        let entry = ProfileEntry {
            name: name.clone(),
            hash,
            kind: ProfileKind::Local,
            url: None,
            used_bytes: None,
            total_bytes: None,
            expire_unix: None,
        };
        self.profiles.push(entry.clone());
        self.default_name = Some(name);
        self.save();
        entry
    }

    pub fn add_cloud(
        &mut self,
        name: Option<&str>,
        url: &str,
        content: &[u8],
        info: Option<&SubscriptionUserInfo>,
    ) -> Result<ProfileEntry, String> {
        if url.trim().is_empty() {
            return Err("订阅地址不能为空".into());
        }
        let name = self.allocate_unique_name(name);
        let hash = ContentStore::save(content);
        let mut entry = ProfileEntry {
            name: name.clone(),
            hash,
            kind: ProfileKind::Cloud,
            url: Some(url.trim().to_string()),
            used_bytes: None,
            total_bytes: None,
            expire_unix: None,
        };
        apply_user_info(&mut entry, info);
        self.profiles.push(entry.clone());
        self.default_name = Some(name);
        self.save();
        Ok(entry)
    }

    pub fn update_cloud(
        &mut self,
        name: &str,
        content: &[u8],
        info: Option<&SubscriptionUserInfo>,
    ) -> Result<(), String> {
        let idx = self
            .profiles
            .iter()
            .position(|p| p.name == name)
            .ok_or("not found")?;
        if self.profiles[idx].kind != ProfileKind::Cloud {
            return Err("本地订阅不支持更新".into());
        }
        let old = self.profiles[idx].hash.clone();
        self.profiles[idx].hash = ContentStore::save(content);
        let info_owned = info.cloned();
        apply_user_info(&mut self.profiles[idx], info_owned.as_ref());
        self.save();
        let refs: Vec<String> = self.profiles.iter().map(|p| p.hash.clone()).collect();
        ContentStore::delete_if_unreferenced(&old, &refs);
        Ok(())
    }

    pub fn remove(&mut self, name: &str) -> bool {
        let Some(idx) = self.profiles.iter().position(|p| p.name == name) else {
            return false;
        };
        let old = self.profiles[idx].hash.clone();
        let was_default = self.default_name.as_deref() == Some(name);
        self.profiles.remove(idx);
        if self.profiles.is_empty() {
            self.default_name = None;
        } else if was_default
            || self.default_name.as_ref().is_none_or(|d| self.profiles.iter().all(|p| p.name != *d))
        {
            self.default_name = Some(
                if idx < self.profiles.len() {
                    self.profiles[idx].name.clone()
                } else {
                    self.profiles[0].name.clone()
                },
            );
        }
        self.save();
        let refs: Vec<String> = self.profiles.iter().map(|p| p.hash.clone()).collect();
        ContentStore::delete_if_unreferenced(&old, &refs);
        true
    }

    fn load_from_file(&mut self, path: &Path) {
        let Ok(text) = fs::read_to_string(path) else {
            self.load_error = Some("配置读取失败".into());
            return;
        };
        let mut current: Option<ProfileEntry> = None;
        for raw in text.lines() {
            if raw.trim().is_empty() || raw.trim_start().starts_with('#') {
                continue;
            }
            let line = raw.trim_end();
            if let Some(rest) = line.strip_prefix("default:") {
                self.default_name = Some(unquote(rest.trim()));
                continue;
            }
            if line.trim_start().starts_with("- ") {
                if let Some(c) = current.take() {
                    if !c.name.is_empty() && !c.hash.is_empty() {
                        self.profiles.push(c);
                    }
                }
                current = Some(ProfileEntry {
                    name: String::new(),
                    hash: String::new(),
                    kind: ProfileKind::Local,
                    url: None,
                    used_bytes: None,
                    total_bytes: None,
                    expire_unix: None,
                });
                let rest = line.trim_start()[2..].trim();
                if let Some(v) = rest.strip_prefix("name:") {
                    if let Some(c) = &mut current {
                        c.name = unquote(v.trim());
                    }
                }
                continue;
            }
            let Some(c) = current.as_mut() else {
                continue;
            };
            let t = line.trim();
            let Some(colon) = t.find(':') else {
                continue;
            };
            let key = t[..colon].trim();
            let val = unquote(t[colon + 1..].trim());
            match key {
                "name" => c.name = val,
                "hash" if ContentStore::is_safe(&val) => c.hash = val,
                "type" => {
                    c.kind = if val.eq_ignore_ascii_case("cloud") {
                        ProfileKind::Cloud
                    } else {
                        ProfileKind::Local
                    }
                }
                "url" if c.kind == ProfileKind::Cloud => c.url = Some(val),
                "used" if c.kind == ProfileKind::Cloud => c.used_bytes = val.parse().ok(),
                "total" if c.kind == ProfileKind::Cloud => c.total_bytes = val.parse().ok(),
                "expire" if c.kind == ProfileKind::Cloud => c.expire_unix = val.parse().ok(),
                _ => {}
            }
        }
        if let Some(c) = current.take() {
            if !c.name.is_empty() && !c.hash.is_empty() {
                self.profiles.push(c);
            }
        }
        for p in &mut self.profiles {
            if p.kind == ProfileKind::Local {
                p.url = None;
                p.used_bytes = None;
                p.total_bytes = None;
                p.expire_unix = None;
            }
        }
        if self.default_name.is_none() {
            self.default_name = self.profiles.first().map(|p| p.name.clone());
        }
    }
}

fn apply_user_info(entry: &mut ProfileEntry, info: Option<&SubscriptionUserInfo>) {
    let Some(info) = info else {
        return;
    };
    if info.upload.is_some() || info.download.is_some() {
        entry.used_bytes = Some(info.upload.unwrap_or(0) + info.download.unwrap_or(0));
    }
    if info.total.is_some() {
        entry.total_bytes = info.total;
    }
    if info.expire_unix.is_some() {
        entry.expire_unix = info.expire_unix;
    }
}

fn yaml_escape(s: &str) -> String {
    if s.is_empty() {
        return "\"\"".into();
    }
    if s.contains(':')
        || s.contains('#')
        || s.contains('"')
        || s.contains('\'')
        || s.contains('\n')
        || s.contains('\r')
        || s.starts_with(' ')
        || s.ends_with(' ')
    {
        format!(
            "\"{}\"",
            s.replace('\\', "\\\\")
                .replace('"', "\\\"")
                .replace('\r', "\\r")
                .replace('\n', "\\n")
        )
    } else {
        s.to_string()
    }
}

fn unquote(s: &str) -> String {
    if s.len() >= 2
        && ((s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')))
    {
        s[1..s.len() - 1].replace("\\\"", "\"").replace("\\\\", "\\")
    } else {
        s.to_string()
    }
}

// ---- YAML proxies ----

struct YamlMap(std::collections::HashMap<String, String>);

impl YamlMap {
    fn new() -> Self {
        Self(std::collections::HashMap::new())
    }
    fn set(&mut self, k: impl Into<String>, v: impl Into<String>) {
        self.0.insert(k.into(), v.into());
    }
    fn get(&self, k: &str) -> Option<&str> {
        self.0.get(k).map(|s| s.as_str())
    }
}

pub fn load_proxies_yaml(text: &str) -> Vec<ProxyNode> {
    let normalized = text.replace("\r\n", "\n").replace('\r', "\n");
    let lines: Vec<&str> = normalized.split('\n').collect();
    let entries = parse_proxies_section(&lines);
    let mut nodes = Vec::new();
    for p in entries {
        if let Some(node) = yaml_to_node(&p) {
            nodes.push(node);
        }
    }
    nodes
}

fn yaml_to_node(p: &YamlMap) -> Option<ProxyNode> {
    let ty = normalize_type(p.get("type").unwrap_or(""));
    if !matches!(ty.as_str(), "vless" | "trojan" | "ss" | "vmess" | "socks5" | "http") {
        return None;
    }
    let mut network = p.get("network").unwrap_or("tcp").trim().to_ascii_lowercase();
    if network == "websocket" {
        network = "ws".into();
    }
    let name = p.get("name")?;
    let server = p.get("server")?;
    let port: u16 = p.get("port").and_then(|s| s.parse().ok()).unwrap_or(0);
    if name.trim().is_empty() || server.trim().is_empty() || port == 0 {
        return None;
    }
    let has_reality = p.get("reality-opts.public-key").is_some_and(|s| !s.is_empty());
    let mut tls = parse_bool(p.get("tls")) || ty == "trojan" || has_reality;
    let security = if has_reality {
        "reality"
    } else if tls {
        "tls"
    } else {
        "none"
    };
    let mut plugin = p.get("plugin").map(|s| s.to_string());
    let mut plugin_opts = plugin_opts_from_yaml(p);
    let mut ws_path = p
        .get("ws-opts.path")
        .or_else(|| p.get("http-opts.path"))
        .map(|s| s.to_string());
    let mut ws_host = p
        .get("ws-opts.headers.Host")
        .or_else(|| p.get("ws-opts.headers.host"))
        .map(|s| s.to_string());
    if plugin
        .as_deref()
        .is_some_and(|s| s.eq_ignore_ascii_case("v2ray-plugin"))
    {
        network = "ws".into();
        tls = tls
            || plugin_opts
                .as_deref()
                .is_some_and(|s| s.contains("tls=true") || s.contains("tls=1"));
        if ws_path.is_none() {
            ws_path = opt_from_plugin(plugin_opts.as_deref(), "path");
        }
        if ws_host.is_none() {
            ws_host = opt_from_plugin(plugin_opts.as_deref(), "host");
        }
        plugin = None;
        plugin_opts = None;
    }
    Some(ProxyNode {
        name: name.to_string(),
        type_name: ty,
        server: server.to_string(),
        port,
        uuid: p.get("uuid").or_else(|| p.get("id")).map(|s| s.to_string()),
        password: p.get("password").map(|s| s.to_string()),
        tls,
        server_name: p.get("servername").or_else(|| p.get("sni")).map(|s| s.to_string()),
        flow: p.get("flow").map(|s| s.to_string()),
        network,
        client_fingerprint: p.get("client-fingerprint").map(|s| s.to_string()),
        reality_public_key: p.get("reality-opts.public-key").map(|s| s.to_string()),
        reality_short_id: p.get("reality-opts.short-id").map(|s| s.to_string()),
        skip_cert_verify: parse_bool(p.get("skip-cert-verify")),
        ws_path,
        ws_host,
        security: Some(security.into()),
        cipher: p
            .get("cipher")
            .or_else(|| p.get("method"))
            .map(|s| s.to_string()),
        username: p.get("username").map(|s| s.to_string()),
        plugin,
        plugin_opts,
        alter_id: p
            .get("alterId")
            .or_else(|| p.get("alter-id"))
            .and_then(|s| s.parse().ok())
            .unwrap_or(0),
    })
}

fn plugin_opts_from_yaml(p: &YamlMap) -> Option<String> {
    if let Some(raw) = p.get("plugin-opts") {
        if !raw.is_empty() && !raw.starts_with('{') {
            return Some(raw.to_string());
        }
    }
    let mut parts = Vec::new();
    for key in [
        "plugin-opts.mode",
        "plugin-opts.obfs",
        "plugin-opts.host",
        "plugin-opts.obfs-host",
        "plugin-opts.path",
        "plugin-opts.tls",
        "plugin-opts.mux",
    ] {
        if let Some(v) = p.get(key) {
            let short = key.trim_start_matches("plugin-opts.");
            let mapped = match short {
                "mode" => "obfs",
                "host" => "obfs-host",
                other => other,
            };
            parts.push(format!("{mapped}={v}"));
        }
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join(";"))
    }
}

fn opt_from_plugin(opts: Option<&str>, key: &str) -> Option<String> {
    let opts = opts?;
    for part in opts.split([';', '&']) {
        if let Some((k, v)) = part.split_once('=') {
            if k.eq_ignore_ascii_case(key) {
                return Some(v.to_string());
            }
        }
    }
    None
}

fn normalize_type(ty: &str) -> String {
    match ty.trim().to_ascii_lowercase().as_str() {
        "shadowsocks" | "ss" => "ss".into(),
        "socks" | "socks5" => "socks5".into(),
        "https" => "http".into(),
        other => other.to_string(),
    }
}

fn parse_bool(s: Option<&str>) -> bool {
    s.is_some_and(|s| s.eq_ignore_ascii_case("true") || s == "1" || s.eq_ignore_ascii_case("yes"))
}

fn parse_proxies_section(lines: &[&str]) -> Vec<YamlMap> {
    let mut i = 0;
    while i < lines.len() && lines[i].trim_end() != "proxies:" {
        i += 1;
    }
    if i >= lines.len() {
        return Vec::new();
    }
    i += 1;
    let mut result = Vec::new();
    let mut current: Option<YamlMap> = None;
    let mut nest: Vec<(usize, String)> = Vec::new();
    while i < lines.len() {
        let raw = lines[i];
        i += 1;
        if raw.trim().is_empty() || raw.trim_start().starts_with('#') {
            continue;
        }
        if !raw.is_empty()
            && !raw.starts_with([' ', '\t'])
            && raw.trim_end().ends_with(':')
            && !raw.trim_start().starts_with('-')
        {
            break;
        }
        let indent = raw.chars().take_while(|c| *c == ' ').count();
        let content = raw.trim();
        if let Some(rest) = content.strip_prefix("- ") {
            if let Some(c) = current.take() {
                result.push(c);
            }
            current = Some(YamlMap::new());
            nest.clear();
            let rest = rest.trim();
            if !rest.is_empty() {
                if rest.starts_with('{') {
                    if let Some(c) = current.as_mut() {
                        apply_flow_map(c, rest);
                    }
                } else if let Some(c) = current.as_mut() {
                    apply_pair(c, &mut nest, indent + 2, rest);
                }
            }
            continue;
        }
        if let Some(c) = current.as_mut() {
            apply_pair(c, &mut nest, indent, content);
        }
    }
    if let Some(c) = current {
        result.push(c);
    }
    result
}

fn apply_pair(map: &mut YamlMap, nest: &mut Vec<(usize, String)>, indent: usize, content: &str) {
    let Some(colon) = content.find(':') else {
        return;
    };
    let key = content[..colon].trim();
    let val = unquote(content[colon + 1..].trim());
    while nest.last().is_some_and(|(i, _)| indent <= *i) {
        nest.pop();
    }
    let prefix = nest.last().map(|(_, p)| format!("{p}.")).unwrap_or_default();
    let full = format!("{prefix}{key}");
    if val.is_empty() {
        nest.push((indent, full));
    } else {
        map.set(full, val);
    }
}

fn apply_flow_map(map: &mut YamlMap, flow: &str) {
    let mut s = flow.trim();
    if s.starts_with('{') {
        s = &s[1..];
    }
    if s.ends_with('}') {
        s = &s[..s.len() - 1];
    }
    for part in split_flow(s) {
        let Some(colon) = index_top_colon(&part) else {
            continue;
        };
        let key = part[..colon].trim();
        let val = unquote(part[colon + 1..].trim());
        if key.is_empty() {
            continue;
        }
        if val.starts_with('{') && val.ends_with('}') {
            let mut inner = YamlMap::new();
            apply_flow_map(&mut inner, &val);
            for (ik, iv) in inner.0 {
                map.set(format!("{key}.{ik}"), iv);
            }
        } else {
            map.set(key, val);
        }
    }
}

fn split_flow(s: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut cur = String::new();
    let mut depth = 0i32;
    let mut quote = None;
    let chars: Vec<char> = s.chars().collect();
    for (i, c) in chars.iter().enumerate() {
        if let Some(q) = quote {
            cur.push(*c);
            if *c == q && (i == 0 || chars[i - 1] != '\\') {
                quote = None;
            }
            continue;
        }
        if *c == '\'' || *c == '"' {
            quote = Some(*c);
            cur.push(*c);
            continue;
        }
        if *c == '{' {
            depth += 1;
            cur.push(*c);
            continue;
        }
        if *c == '}' {
            if depth > 0 {
                depth -= 1;
            }
            cur.push(*c);
            continue;
        }
        if *c == ',' && depth == 0 {
            let piece = cur.trim().to_string();
            if !piece.is_empty() {
                parts.push(piece);
            }
            cur.clear();
            continue;
        }
        cur.push(*c);
    }
    let last = cur.trim().to_string();
    if !last.is_empty() {
        parts.push(last);
    }
    parts
}

fn index_top_colon(s: &str) -> Option<usize> {
    let mut depth = 0i32;
    let mut quote = None;
    let chars: Vec<char> = s.chars().collect();
    for (i, c) in chars.iter().enumerate() {
        if let Some(q) = quote {
            if *c == q && (i == 0 || chars[i - 1] != '\\') {
                quote = None;
            }
            continue;
        }
        if *c == '\'' || *c == '"' {
            quote = Some(*c);
            continue;
        }
        if *c == '{' {
            depth += 1;
            continue;
        }
        if *c == '}' {
            if depth > 0 {
                depth -= 1;
            }
            continue;
        }
        if *c == ':' && depth == 0 {
            return Some(i);
        }
    }
    None
}

// ---- share links ----

pub fn parse_share_link(line: &str) -> Option<ProxyNode> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }
    if line.to_ascii_lowercase().starts_with("vless://") {
        return parse_vless(line);
    }
    if line.to_ascii_lowercase().starts_with("trojan://") {
        return parse_trojan(line);
    }
    if line.to_ascii_lowercase().starts_with("ss://") {
        return parse_ss(line);
    }
    if line.to_ascii_lowercase().starts_with("vmess://") {
        return parse_vmess(line);
    }
    if line.to_ascii_lowercase().starts_with("socks5://")
        || line.to_ascii_lowercase().starts_with("socks://")
    {
        return parse_socks_link(line);
    }
    if line.to_ascii_lowercase().starts_with("http://")
        || line.to_ascii_lowercase().starts_with("https://")
    {
        return parse_http_link(line);
    }
    None
}

fn parse_query(q: &str) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    let q = q.strip_prefix('?').unwrap_or(q);
    for part in q.split('&').filter(|s| !s.is_empty()) {
        if let Some((k, v)) = part.split_once('=') {
            map.insert(
                url_decode(k).to_ascii_lowercase(),
                url_decode(v),
            );
        } else {
            map.insert(
                url_decode(part),
                String::new(),
            );
        }
    }
    map
}

fn parse_vless(url: &str) -> Option<ProxyNode> {
    let uri = url::Url::parse(url).ok()?;
    let uuid = uri.username();
    let qs = parse_query(uri.query().unwrap_or(""));
    let mut security = qs.get("security").cloned().unwrap_or_else(|| "none".into());
    security = security.trim().to_ascii_lowercase();
    let mut network = qs
        .get("type")
        .or_else(|| qs.get("network"))
        .cloned()
        .unwrap_or_else(|| "tcp".into())
        .to_ascii_lowercase();
    if network == "websocket" {
        network = "ws".into();
    }
    let name = uri
        .fragment()
        .map(|f| url_decode(f))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| uri.host_str().unwrap_or("").to_string());
    let pbk = qs.get("pbk").cloned();
    if pbk.as_deref().is_some_and(|s| !s.is_empty()) {
        security = "reality".into();
    }
    let tls = security == "tls" || security == "reality";
    Some(ProxyNode {
        name: if name.trim().is_empty() {
            uri.host_str().unwrap_or("").to_string()
        } else {
            name
        },
        type_name: "vless".into(),
        server: uri.host_str()?.to_string(),
        port: if uri.port().unwrap_or(0) > 0 {
            uri.port().unwrap()
        } else {
            443
        },
        uuid: Some(url_decode(uuid)),
        password: None,
        tls,
        server_name: qs.get("sni").or_else(|| qs.get("servername")).cloned(),
        flow: qs.get("flow").cloned(),
        network,
        client_fingerprint: qs.get("fp").cloned(),
        reality_public_key: pbk,
        reality_short_id: qs.get("sid").cloned(),
        skip_cert_verify: is_truthy(qs.get("allowinsecure").or_else(|| qs.get("insecure"))),
        ws_path: qs.get("path").cloned(),
        ws_host: qs.get("host").cloned(),
        security: Some(security),
        ..Default::default()
    })
}

fn parse_trojan(url: &str) -> Option<ProxyNode> {
    let uri = url::Url::parse(url).ok()?;
    let password = url_decode(uri.username());
    let qs = parse_query(uri.query().unwrap_or(""));
    let security = qs
        .get("security")
        .cloned()
        .unwrap_or_else(|| "tls".into())
        .to_ascii_lowercase();
    let mut network = qs
        .get("type")
        .or_else(|| qs.get("network"))
        .cloned()
        .unwrap_or_else(|| "tcp".into())
        .to_ascii_lowercase();
    if network == "websocket" {
        network = "ws".into();
    }
    let name = uri
        .fragment()
        .map(|f| url_decode(f))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| uri.host_str().unwrap_or("").to_string());
    Some(ProxyNode {
        name,
        type_name: "trojan".into(),
        server: uri.host_str()?.to_string(),
        port: if uri.port().unwrap_or(0) > 0 {
            uri.port().unwrap()
        } else {
            443
        },
        uuid: None,
        password: Some(password),
        tls: security != "none",
        server_name: qs.get("sni").or_else(|| qs.get("servername")).cloned(),
        flow: None,
        network,
        client_fingerprint: qs.get("fp").cloned(),
        reality_public_key: None,
        reality_short_id: None,
        skip_cert_verify: is_truthy(qs.get("allowinsecure").or_else(|| qs.get("insecure"))),
        ws_path: qs.get("path").cloned(),
        ws_host: qs.get("host").cloned(),
        security: Some(security),
        ..Default::default()
    })
}

fn parse_ss(url: &str) -> Option<ProxyNode> {
    let hash = url.find('#').map(|i| url_decode(&url[i + 1..]));
    let rest = url.split('#').next().unwrap_or(url);
    let body = rest
        .trim_start_matches("ss://")
        .trim_start_matches("SS://");
    let (userinfo, hostport, plugin) = if let Some(at) = body.rfind('@') {
        let (left, right) = body.split_at(at);
        let right = &right[1..];
        let (hp, q) = right.split_once('?').unwrap_or((right, ""));
        (decode_ss_userinfo(left)?, hp.to_string(), q.to_string())
    } else {
        let compact: String = body.chars().filter(|c| !c.is_whitespace()).collect();
        let decoded = decode_b64_url(&compact)?;
        let (left, right) = decoded.split_once('@')?;
        (left.to_string(), right.to_string(), String::new())
    };
    let (method, password) = userinfo.split_once(':')?;
    let (host, port) = split_host_port_str(&hostport)?;
    let qs = parse_query(&plugin);
    let mut plugin_name = qs.get("plugin").cloned();
    let mut plugin_opts = None;
    if let Some(p) = plugin_name.clone() {
        if let Some((name, opts)) = p.split_once(';') {
            plugin_name = Some(name.to_string());
            plugin_opts = Some(opts.to_string());
        } else {
            plugin_opts = qs
                .iter()
                .filter(|(k, _)| *k != "plugin")
                .map(|(k, v)| format!("{k}={v}"))
                .reduce(|a, b| format!("{a};{b}"));
        }
    }
    Some(ProxyNode {
        name: hash.filter(|s| !s.is_empty()).unwrap_or_else(|| host.clone()),
        type_name: "ss".into(),
        server: host,
        port,
        password: Some(password.to_string()),
        cipher: Some(method.to_string()),
        plugin: plugin_name,
        plugin_opts,
        ..Default::default()
    })
}

fn decode_ss_userinfo(left: &str) -> Option<String> {
    if left.contains(':') {
        return Some(url_decode(left));
    }
    decode_b64_url(left)
}

fn decode_b64_url(s: &str) -> Option<String> {
    let pad = |s: &str| {
        let m = s.len() % 4;
        if m == 0 {
            s.to_string()
        } else {
            format!("{s}{}", "=".repeat(4 - m))
        }
    };
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(pad(s))
        .or_else(|_| {
            let alt = s.replace('-', "+").replace('_', "/");
            base64::engine::general_purpose::STANDARD.decode(pad(&alt))
        })
        .ok()?;
    String::from_utf8(bytes).ok()
}

fn split_host_port_str(s: &str) -> Option<(String, u16)> {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix('[') {
        let (host, rest) = rest.split_once(']')?;
        let port = rest.trim_start_matches(':').parse().ok()?;
        return Some((host.to_string(), port));
    }
    let (host, port) = s.rsplit_once(':')?;
    Some((host.to_string(), port.parse().ok()?))
}

fn parse_vmess(url: &str) -> Option<ProxyNode> {
    let body = url
        .trim_start_matches("vmess://")
        .trim_start_matches("VMESS://");
    let json = decode_b64_url(body)?;
    let v: serde_json::Value = serde_json::from_str(&json).ok()?;
    let server = v.get("add")?.as_str()?.to_string();
    let port = v
        .get("port")
        .and_then(|p| p.as_u64().or_else(|| p.as_str().and_then(|s| s.parse().ok())))
        .unwrap_or(0) as u16;
    if server.is_empty() || port == 0 {
        return None;
    }
    let tls = v
        .get("tls")
        .and_then(|t| t.as_str())
        .is_some_and(|s| !s.is_empty() && !s.eq_ignore_ascii_case("none"));
    let mut network = v
        .get("net")
        .and_then(|n| n.as_str())
        .unwrap_or("tcp")
        .to_ascii_lowercase();
    if network == "websocket" {
        network = "ws".into();
    }
    Some(ProxyNode {
        name: v
            .get("ps")
            .and_then(|p| p.as_str())
            .filter(|s| !s.is_empty())
            .unwrap_or(server.as_str())
            .to_string(),
        type_name: "vmess".into(),
        server,
        port,
        uuid: v.get("id").and_then(|i| i.as_str()).map(|s| s.to_string()),
        tls,
        server_name: v.get("sni").and_then(|s| s.as_str()).map(|s| s.to_string()),
        network,
        ws_path: v.get("path").and_then(|p| p.as_str()).map(|s| s.to_string()),
        ws_host: v.get("host").and_then(|h| h.as_str()).map(|s| s.to_string()),
        security: Some(if tls { "tls".into() } else { "none".into() }),
        cipher: v.get("scy").and_then(|s| s.as_str()).map(|s| s.to_string()),
        alter_id: v
            .get("aid")
            .and_then(|a| a.as_u64().or_else(|| a.as_str().and_then(|s| s.parse().ok())))
            .unwrap_or(0) as u16,
        ..Default::default()
    })
}

fn parse_socks_link(url: &str) -> Option<ProxyNode> {
    let uri = url::Url::parse(url).ok()?;
    let host = uri.host_str()?.to_string();
    let port = uri.port().unwrap_or(1080);
    let user = url_decode(uri.username());
    Some(ProxyNode {
        name: uri
            .fragment()
            .map(url_decode)
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| host.clone()),
        type_name: "socks5".into(),
        server: host,
        port,
        username: if user.is_empty() { None } else { Some(user) },
        password: uri.password().map(url_decode),
        ..Default::default()
    })
}

fn parse_http_link(url: &str) -> Option<ProxyNode> {
    let uri = url::Url::parse(url).ok()?;
    if uri.path() != "/" && !uri.path().is_empty() {
        return None;
    }
    let host = uri.host_str()?.to_string();
    let port = uri.port().unwrap_or(if uri.scheme() == "https" { 443 } else { 80 });
    let user = url_decode(uri.username());
    Some(ProxyNode {
        name: uri
            .fragment()
            .map(url_decode)
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| host.clone()),
        type_name: "http".into(),
        server: host,
        port,
        username: if user.is_empty() { None } else { Some(user) },
        password: uri.password().map(url_decode),
        tls: uri.scheme() == "https",
        ..Default::default()
    })
}

fn is_truthy(s: Option<&String>) -> bool {
    s.is_some_and(|s| s == "1" || s == "true" || s == "True" || s == "yes")
}

pub struct NodeCatalog;

impl NodeCatalog {
    pub fn parse(raw: &[u8]) -> Vec<ProxyNode> {
        let text = decode_utf8(raw);
        parse_text(&text, true)
    }

    pub fn parse_file(path: &Path) -> Vec<ProxyNode> {
        fs::read(path).map(|b| Self::parse(&b)).unwrap_or_default()
    }
}

fn parse_text(text: &str, allow_b64: bool) -> Vec<ProxyNode> {
    let text = text.trim().trim_start_matches('\u{feff}');
    if text.is_empty() {
        return Vec::new();
    }
    if text.contains("proxies:") {
        return filter_all(load_proxies_yaml(text));
    }
    let trimmed = text.trim_start();
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        let from_json = try_parse_json(trimmed);
        if !from_json.is_empty() {
            return from_json;
        }
    }
    if looks_like_uri_list(text) {
        return filter_all(parse_uri_list(text));
    }
    if allow_b64 {
        if let Some(decoded) = try_decode_b64(text) {
            let inner = parse_text(&decoded, false);
            if !inner.is_empty() {
                return inner;
            }
            if looks_like_uri_list(&decoded) {
                return filter_all(parse_uri_list(&decoded));
            }
            if decoded.contains("proxies:") {
                return filter_all(load_proxies_yaml(&decoded));
            }
        }
    }
    Vec::new()
}

fn filter_all(nodes: Vec<ProxyNode>) -> Vec<ProxyNode> {
    nodes
        .into_iter()
        .filter(NodeFilter::accept)
        .map(normalize_network)
        .map(normalize_ss_plugin)
        .collect()
}

fn normalize_ss_plugin(mut n: ProxyNode) -> ProxyNode {
    let plugin = n.plugin.as_deref().unwrap_or("").to_ascii_lowercase();
    if plugin != "v2ray-plugin" {
        return n;
    }
    n.network = "ws".into();
    if opt_from_plugin(n.plugin_opts.as_deref(), "tls").is_some_and(|v| v == "true" || v == "1") {
        n.tls = true;
    }
    if n.ws_path.is_none() {
        n.ws_path = opt_from_plugin(n.plugin_opts.as_deref(), "path");
    }
    if n.ws_host.is_none() {
        n.ws_host = opt_from_plugin(n.plugin_opts.as_deref(), "host").or_else(|| opt_from_plugin(n.plugin_opts.as_deref(), "obfs-host"));
    }
    n.plugin = None;
    n.plugin_opts = None;
    n
}

fn normalize_network(mut n: ProxyNode) -> ProxyNode {
    let mut net = n.network.trim().to_ascii_lowercase();
    if net == "websocket" {
        net = "ws".into();
    }
    if net == "httpupgrade" {
        n.network = "httpupgrade".into();
        return n;
    }
    if net != "ws" {
        net = "tcp".into();
    }
    n.network = net;
    n
}

fn parse_uri_list(text: &str) -> Vec<ProxyNode> {
    let mut nodes = Vec::new();
    for raw in text.split(['\r', '\n']) {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = if line.contains("://") && (line.contains(' ') || line.contains('\t')) {
            line.split([' ', '\t']).filter(|s| !s.is_empty()).collect()
        } else {
            vec![line]
        };
        for p in parts {
            if let Some(n) = parse_share_link(p) {
                nodes.push(n);
            }
        }
    }
    nodes
}

fn looks_like_uri_list(text: &str) -> bool {
    text.split(['\r', '\n']).any(|l| {
        let t = l.trim();
        !t.is_empty() && !t.starts_with('#') && t.contains("://")
    })
}

fn try_decode_b64(text: &str) -> Option<String> {
    let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    if compact.len() < 16 {
        return None;
    }
    let pad = |s: &str| {
        let m = s.len() % 4;
        if m == 0 {
            s.to_string()
        } else {
            format!("{s}{}", "=".repeat(4 - m))
        }
    };
    let try_one = |s: &str| {
        let bytes = base64::engine::general_purpose::STANDARD.decode(pad(s)).ok()?;
        let decoded = String::from_utf8(bytes).ok()?;
        if decoded.contains("://") || decoded.contains("proxies:") || decoded.trim_start().starts_with('{')
        {
            Some(decoded)
        } else {
            None
        }
    };
    try_one(&compact).or_else(|| {
        let alt = compact.replace('-', "+").replace('_', "/");
        base64::engine::general_purpose::STANDARD
            .decode(pad(&alt))
            .ok()
            .and_then(|b| String::from_utf8(b).ok())
            .filter(|s| !s.is_empty())
    })
}

fn decode_utf8(raw: &[u8]) -> String {
    if raw.len() >= 3 && raw[..3] == [0xEF, 0xBB, 0xBF] {
        String::from_utf8_lossy(&raw[3..]).into_owned()
    } else {
        String::from_utf8_lossy(raw).into_owned()
    }
}

fn try_parse_json(text: &str) -> Vec<ProxyNode> {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(text) else {
        return Vec::new();
    };
    let Some(obs) = v.get("outbounds").and_then(|o| o.as_array()) else {
        if v.get("servers").and_then(|s| s.as_array()).is_some() {
            return filter_all(parse_sip008(&v));
        }
        return Vec::new();
    };
    let mut list = Vec::new();
    for ob in obs {
        let n = if ob.get("protocol").is_some() {
            map_xray(ob)
        } else if ob.get("type").is_some() {
            map_singbox(ob)
        } else {
            None
        };
        if let Some(n) = n {
            list.push(n);
        }
    }
    filter_all(list)
}

fn jstr(v: &serde_json::Value, k: &str) -> Option<String> {
    v.get(k)?.as_str().map(|s| s.to_string())
}

fn jint(v: &serde_json::Value, k: &str) -> i64 {
    v.get(k).and_then(|x| x.as_i64()).unwrap_or(0)
}

fn map_xray(ob: &serde_json::Value) -> Option<ProxyNode> {
    let protocol = normalize_type(&jstr(ob, "protocol")?);
    if !matches!(protocol.as_str(), "vless" | "trojan" | "ss" | "vmess" | "socks5" | "http") {
        return None;
    }
    let settings = ob.get("settings")?;
    let tag = jstr(ob, "tag");
    let (server, port, uuid, password, flow, cipher, alter_id, username) = if protocol == "vless" || protocol == "vmess" {
        let v = settings.get("vnext")?.as_array()?.first()?;
        let server = jstr(v, "address")?;
        let port = jint(v, "port") as u16;
        let u = v.get("users")?.as_array()?.first()?;
        (
            server,
            port,
            jstr(u, "id"),
            None,
            jstr(u, "flow"),
            jstr(u, "security").or_else(|| jstr(u, "encryption")),
            u.get("alterId").and_then(|x| x.as_u64()).unwrap_or(0) as u16,
            None,
        )
    } else if protocol == "ss" {
        let s = settings.get("servers").and_then(|a| a.as_array()).and_then(|a| a.first()).unwrap_or(settings);
        (
            jstr(s, "address")?,
            jint(s, "port") as u16,
            None,
            jstr(s, "password"),
            None,
            jstr(s, "method"),
            0,
            None,
        )
    } else if protocol == "socks5" || protocol == "http" {
        let s = settings.get("servers").and_then(|a| a.as_array()).and_then(|a| a.first()).unwrap_or(settings);
        let users = s.get("users").and_then(|a| a.as_array()).and_then(|a| a.first());
        (
            jstr(s, "address")?,
            jint(s, "port") as u16,
            None,
            users.and_then(|u| jstr(u, "pass")).or_else(|| jstr(s, "password")),
            None,
            None,
            0,
            users.and_then(|u| jstr(u, "user")).or_else(|| jstr(s, "user")),
        )
    } else {
        let s = settings.get("servers")?.as_array()?.first()?;
        (
            jstr(s, "address")?,
            jint(s, "port") as u16,
            None,
            jstr(s, "password"),
            None,
            None,
            0,
            None,
        )
    };
    if server.trim().is_empty() || port == 0 {
        return None;
    }
    let mut network = "tcp".to_string();
    let mut sni = None;
    let mut fp = None;
    let mut pbk = None;
    let mut sid = None;
    let mut security = "none".to_string();
    let mut tls = false;
    let mut ws_path = None;
    let mut ws_host = None;
    let mut skip = false;
    if let Some(stream) = ob.get("streamSettings") {
        network = jstr(stream, "network").unwrap_or_else(|| "tcp".into());
        security = jstr(stream, "security").unwrap_or_else(|| "none".into()).to_ascii_lowercase();
        tls = security == "tls" || security == "reality";
        if security == "reality" {
            if let Some(rs) = stream.get("realitySettings") {
                sni = jstr(rs, "serverName");
                fp = jstr(rs, "fingerprint");
                pbk = jstr(rs, "publicKey");
                sid = jstr(rs, "shortId");
            }
        } else if security == "tls" {
            if let Some(ts) = stream.get("tlsSettings") {
                sni = jstr(ts, "serverName");
                fp = jstr(ts, "fingerprint");
                skip = ts.get("allowInsecure").and_then(|x| x.as_bool()).unwrap_or(false);
            }
        }
        if (network == "ws" || network == "websocket") && let Some(ws) = stream.get("wsSettings") {
            network = "ws".into();
            ws_path = jstr(ws, "path");
            ws_host = ws.get("headers").and_then(|h| jstr(h, "Host"));
        }
    }
    Some(ProxyNode {
        name: tag.filter(|s| !s.trim().is_empty()).unwrap_or(server.clone()),
        type_name: protocol,
        server,
        port,
        uuid,
        password,
        tls,
        server_name: sni,
        flow,
        network,
        client_fingerprint: fp,
        reality_public_key: pbk,
        reality_short_id: sid,
        skip_cert_verify: skip,
        ws_path,
        ws_host,
        security: Some(security),
        cipher,
        username,
        alter_id,
        ..Default::default()
    })
}

fn map_singbox(ob: &serde_json::Value) -> Option<ProxyNode> {
    let ty = normalize_type(&jstr(ob, "type")?);
    if !matches!(ty.as_str(), "vless" | "trojan" | "ss" | "vmess" | "socks5" | "http") {
        return None;
    }
    let server = jstr(ob, "server")?;
    let port = jint(ob, "server_port") as u16;
    if server.trim().is_empty() || port == 0 {
        return None;
    }
    let mut network = "tcp".to_string();
    let mut ws_path = None;
    let mut ws_host = None;
    if let Some(tr) = ob.get("transport") {
        network = jstr(tr, "type").unwrap_or_else(|| "tcp".into()).to_ascii_lowercase();
        if network == "ws" || network == "websocket" {
            network = "ws".into();
            ws_path = jstr(tr, "path");
            ws_host = tr.get("headers").and_then(|h| jstr(h, "Host"));
        }
    }
    let mut security = "none".to_string();
    let mut tls = false;
    let mut sni = None;
    let mut fp = None;
    let mut pbk = None;
    let mut sid = None;
    let mut skip = false;
    if let Some(tls_el) = ob.get("tls") {
        let enabled = tls_el.get("enabled").and_then(|x| x.as_bool()) != Some(false);
        if enabled {
            tls = true;
            security = "tls".into();
            sni = jstr(tls_el, "server_name");
            fp = tls_el.get("utls").and_then(|u| jstr(u, "fingerprint"));
            skip = tls_el.get("insecure").and_then(|x| x.as_bool()).unwrap_or(false);
            if let Some(r) = tls_el.get("reality") {
                if r.get("enabled").and_then(|x| x.as_bool()) != Some(false) {
                    security = "reality".into();
                    pbk = jstr(r, "public_key");
                    sid = jstr(r, "short_id");
                }
            }
        }
    }
    Some(ProxyNode {
        name: jstr(ob, "tag")
            .filter(|s| !s.trim().is_empty())
            .unwrap_or(server.clone()),
        type_name: ty,
        server,
        port,
        uuid: jstr(ob, "uuid"),
        password: jstr(ob, "password"),
        tls,
        server_name: sni,
        flow: jstr(ob, "flow"),
        network,
        client_fingerprint: fp,
        reality_public_key: pbk,
        reality_short_id: sid,
        skip_cert_verify: skip,
        ws_path,
        ws_host,
        security: Some(security),
        cipher: jstr(ob, "method").or_else(|| jstr(ob, "cipher")),
        username: jstr(ob, "username"),
        alter_id: ob.get("alter_id").and_then(|x| x.as_u64()).unwrap_or(0) as u16,
        plugin: jstr(ob, "plugin"),
        plugin_opts: jstr(ob, "plugin_opts"),
        ..Default::default()
    })
}

fn parse_sip008(v: &serde_json::Value) -> Vec<ProxyNode> {
    let Some(servers) = v.get("servers").and_then(|s| s.as_array()) else {
        return Vec::new();
    };
    let mut nodes = Vec::new();
    for s in servers {
        let Some(server) = jstr(s, "server") else { continue };
        let port = jint(s, "server_port") as u16;
        let Some(password) = jstr(s, "password") else { continue };
        if server.is_empty() || port == 0 {
            continue;
        }
        nodes.push(ProxyNode {
            name: jstr(s, "remarks").filter(|n| !n.is_empty()).unwrap_or_else(|| server.clone()),
            type_name: "ss".into(),
            server,
            port,
            password: Some(password),
            cipher: jstr(s, "method"),
            plugin: jstr(s, "plugin"),
            plugin_opts: jstr(s, "plugin_opts"),
            ..Default::default()
        });
    }
    nodes
}

// ---- subscription client ----

pub struct SubscriptionFetchResult {
    pub body: Vec<u8>,
    pub user_info: Option<SubscriptionUserInfo>,
    pub suggested_name: Option<String>,
}

pub struct SubscriptionClient;

impl SubscriptionClient {
    pub const USER_AGENT: &'static str = "clash.meta";
    pub const MAX_BODY: usize = 16 * 1024 * 1024;

    pub async fn fetch(&self, url: &str) -> Result<SubscriptionFetchResult, String> {
        let _ = InterfaceBinder::current();
        let client = reqwest_direct()?;
        let resp = client
            .get(url)
            .header("User-Agent", Self::USER_AGENT)
            .header("Accept", "*/*")
            .timeout(std::time::Duration::from_secs(45))
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if !resp.status().is_success() {
            return Err(format!("HTTP {}", resp.status()));
        }
        let headers = resp.headers().clone();
        let body = resp.bytes().await.map_err(|e| e.to_string())?;
        if body.len() > Self::MAX_BODY {
            return Err("订阅内容超过 16 MB".into());
        }
        let body = body.to_vec();
        let info = parse_userinfo_header(&headers).or_else(|| parse_userinfo_body(&body));
        let suggested = parse_cd_name(&headers)
            .or_else(|| parse_profile_title(&headers))
            .or_else(|| suggest_from_url(url));
        Ok(SubscriptionFetchResult {
            body,
            user_info: info,
            suggested_name: suggested,
        })
    }
}

fn reqwest_direct() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::limited(10))
        .build()
        .map_err(|e| e.to_string())
}

fn header_str(h: &reqwest::header::HeaderMap, name: &str) -> Option<String> {
    h.get(name)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .filter(|s| !s.trim().is_empty())
}

fn parse_userinfo_header(h: &reqwest::header::HeaderMap) -> Option<SubscriptionUserInfo> {
    parse_userinfo_string(&header_str(h, "subscription-userinfo")?)
}

fn parse_userinfo_body(body: &[u8]) -> Option<SubscriptionUserInfo> {
    let text = String::from_utf8_lossy(body);
    for line in text.lines().take(12) {
        let line = line.trim();
        if let Some(rest) = line
            .strip_prefix("#subscription-userinfo:")
            .or_else(|| line.strip_prefix("# subscription-userinfo:"))
        {
            return parse_userinfo_string(rest.trim());
        }
    }
    None
}

pub fn parse_userinfo_string(raw: &str) -> Option<SubscriptionUserInfo> {
    if raw.trim().is_empty() {
        return None;
    }
    let mut upload = None;
    let mut download = None;
    let mut total = None;
    let mut expire = None;
    for part in raw.replace(' ', "").split(';').filter(|s| !s.is_empty()) {
        let Some((k, v)) = part.split_once('=') else {
            continue;
        };
        let n = v.parse::<i64>().ok().or_else(|| v.parse::<f64>().ok().map(|d| d as i64));
        let Some(n) = n else {
            continue;
        };
        match k.trim().to_ascii_lowercase().as_str() {
            "upload" => upload = Some(n),
            "download" => download = Some(n),
            "total" => total = Some(n),
            "expire" => expire = Some(n),
            _ => {}
        }
    }
    if upload.is_none() && download.is_none() && total.is_none() && expire.is_none() {
        return None;
    }
    Some(SubscriptionUserInfo {
        upload,
        download,
        total,
        expire_unix: expire,
    })
}

fn parse_cd_name(h: &reqwest::header::HeaderMap) -> Option<String> {
    let raw = header_str(h, "content-disposition")?;
    if let Some(idx) = raw.to_ascii_lowercase().find("filename*=") {
        let mut part = raw[idx + 10..].trim();
        if let Some(s) = part.split(';').next() {
            part = s.trim().trim_matches('"');
        }
        if let Some(ticks) = part.find("''") {
            part = &part[ticks + 2..];
            return Some(sanitize(&url_decode(part)));
        }
        return Some(sanitize(part));
    }
    if let Some(idx) = raw.to_ascii_lowercase().find("filename=") {
        let mut fnm = raw[idx + 9..].trim();
        if let Some(end) = fnm.find(';') {
            fnm = &fnm[..end];
        }
        return Some(sanitize(fnm.trim().trim_matches('"')));
    }
    None
}

fn parse_profile_title(h: &reqwest::header::HeaderMap) -> Option<String> {
    let raw = header_str(h, "profile-title")?.trim().to_string();
    if let Some(rest) = raw.strip_prefix("base64:") {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(rest.trim())
            .ok()?;
        return Some(sanitize(&String::from_utf8_lossy(&bytes)));
    }
    Some(sanitize(&raw))
}

fn suggest_from_url(url: &str) -> Option<String> {
    let uri = url::Url::parse(url).ok()?;
    let seg = uri.path_segments()?.next_back()?.trim_matches('/');
    if seg.is_empty() || seg == "." {
        return None;
    }
    Some(sanitize(&url_decode(seg)))
}

fn sanitize(name: &str) -> String {
    let name = Path::new(name.trim())
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(name);
    let mut out: String = name
        .chars()
        .map(|c| if r#"<>:"/\|?*"#.contains(c) { '_' } else { c })
        .collect();
    out = out.trim().to_string();
    if out.is_empty() {
        "Proxy".into()
    } else {
        out
    }
}

fn url_decode(s: &str) -> String {
    urlencoding_decode(s)
}

fn urlencoding_decode(s: &str) -> String {
    let mut out = String::new();
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Ok(v) = u8::from_str_radix(std::str::from_utf8(&b[i + 1..i + 3]).unwrap_or(""), 16) {
                out.push(v as char);
                i += 3;
                continue;
            }
        }
        out.push(b[i] as char);
        i += 1;
    }
    out
}
