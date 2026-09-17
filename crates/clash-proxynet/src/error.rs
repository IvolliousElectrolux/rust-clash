use std::fmt;
use std::io;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyErrorCode {
    AuthRequired,
    AuthFailed,
    ConnectionFailed,
    InvalidResponse,
    Timeout,
    StringTooLong,
    TransportUpgradeFailed,
}

#[derive(Debug)]
pub struct ProxyError {
    pub code: ProxyErrorCode,
    pub message: String,
    pub source: Option<io::Error>,
}

impl ProxyError {
    pub fn new(code: ProxyErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            source: None,
        }
    }

    pub fn with_io(code: ProxyErrorCode, message: impl Into<String>, err: io::Error) -> Self {
        Self {
            code,
            message: message.into(),
            source: Some(err),
        }
    }
}

impl fmt::Display for ProxyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for ProxyError {}

impl From<io::Error> for ProxyError {
    fn from(value: io::Error) -> Self {
        Self::with_io(ProxyErrorCode::ConnectionFailed, value.to_string(), value)
    }
}
