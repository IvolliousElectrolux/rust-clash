#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VlessSecurity {
    None,
    Tls,
    Reality,
}

#[derive(Debug, Clone)]
pub struct VlessOptions {
    pub id: String,
    pub host: String,
    pub port: u16,
    pub security: VlessSecurity,
    pub transport: String,
    pub path: Option<String>,
    pub host_header: Option<String>,
    pub sni: Option<String>,
    pub alpn: Vec<String>,
    pub flow: Option<String>,
    pub fingerprint: Option<String>,
    pub reality_public_key: Option<String>,
    pub reality_short_id: Option<String>,
    pub allow_insecure: bool,
}

impl VlessOptions {
    pub fn sni_or_host(&self) -> &str {
        self.sni
            .as_deref()
            .or(self.host_header.as_deref())
            .unwrap_or(&self.host)
    }
}

#[derive(Debug, Clone)]
pub struct TrojanOptions {
    pub password: String,
    pub host: String,
    pub port: u16,
    pub transport: String,
    pub path: Option<String>,
    pub host_header: Option<String>,
    pub sni: Option<String>,
    pub alpn: Vec<String>,
    pub allow_insecure: bool,
}

impl TrojanOptions {
    pub fn sni_or_host(&self) -> &str {
        self.sni
            .as_deref()
            .or(self.host_header.as_deref())
            .unwrap_or(&self.host)
    }
}

#[derive(Debug, Clone)]
pub struct SsOptions {
    pub method: String,
    pub password: String,
    pub host: String,
    pub port: u16,
    pub plugin: Option<String>,
    pub plugin_opts: Option<String>,
    pub transport: String,
    pub path: Option<String>,
    pub host_header: Option<String>,
    pub sni: Option<String>,
    pub alpn: Vec<String>,
    pub allow_insecure: bool,
    pub tls: bool,
}

impl SsOptions {
    pub fn sni_or_host(&self) -> &str {
        self.sni
            .as_deref()
            .or(self.host_header.as_deref())
            .unwrap_or(&self.host)
    }
}

#[derive(Debug, Clone)]
pub struct VmessOptions {
    pub id: String,
    pub security: String,
    pub alter_id: u16,
    pub host: String,
    pub port: u16,
    pub transport: String,
    pub path: Option<String>,
    pub host_header: Option<String>,
    pub sni: Option<String>,
    pub alpn: Vec<String>,
    pub allow_insecure: bool,
    pub tls: bool,
}

impl VmessOptions {
    pub fn sni_or_host(&self) -> &str {
        self.sni
            .as_deref()
            .or(self.host_header.as_deref())
            .unwrap_or(&self.host)
    }

    pub fn aead(&self) -> bool {
        self.alter_id == 0
    }

    pub fn body_security(&self) -> String {
        match self.security.trim().to_ascii_lowercase().as_str() {
            "aes-128-gcm" | "auto" | "" => "aes-128-gcm".into(),
            "chacha20-poly1305" | "chacha20-ietf-poly1305" => "chacha20-poly1305".into(),
            other => other.to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SocksOptions {
    pub username: Option<String>,
    pub password: Option<String>,
}

#[derive(Debug, Clone)]
pub struct HttpProxyOptions {
    pub username: Option<String>,
    pub password: Option<String>,
}

#[derive(Debug, Clone)]
pub enum OutboundKind {
    Vless(VlessOptions),
    Trojan(TrojanOptions),
    Shadowsocks(SsOptions),
    Vmess(VmessOptions),
    Socks5(SocksOptions),
    Http(HttpProxyOptions),
}
