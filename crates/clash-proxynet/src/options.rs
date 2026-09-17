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
