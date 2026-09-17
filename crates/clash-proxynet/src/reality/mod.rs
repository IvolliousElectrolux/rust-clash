mod auth;
mod handshake;
mod hello;
mod record;
mod schedule;
mod stream;
mod writer;

pub use handshake::handshake;
pub use stream::RealityTlsStream;

use crate::error::{ProxyError, ProxyErrorCode};

pub(crate) fn hs_err(msg: impl Into<String>) -> ProxyError {
    ProxyError::new(ProxyErrorCode::InvalidResponse, msg)
}

pub(crate) fn auth_err(msg: impl Into<String>) -> ProxyError {
    ProxyError::new(ProxyErrorCode::AuthFailed, msg)
}
