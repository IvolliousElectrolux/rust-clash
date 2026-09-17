//! Embedded outbound stack: VLESS / Trojan / REALITY / Vision.

mod address;
mod crypto;
mod error;
mod options;
mod reality;
mod shared;
mod tls;
mod transport;
mod trojan;
mod vision;
mod vless;

pub use address::ProxyAddress;
pub use crypto::{sha224_hex_lower, uuid_write_be, UUID_SIZE};
pub use error::{ProxyError, ProxyErrorCode};
pub use options::{TrojanOptions, VlessOptions, VlessSecurity};
pub use reality::RealityTlsStream;
pub use shared::SharedStream;
pub use tls::install_crypto_provider;
pub use transport::{TransportKind, resolve_host_header, resolve_transport};
pub use vision::VISION_FLOW;

use std::pin::Pin;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::tls::TlsConnector;
use crate::transport::apply_transport;
use crate::trojan::establish_trojan;
use crate::vless::establish_vless;

pub trait AsyncIo: AsyncRead + AsyncWrite + Unpin + Send {
    fn vision_detach(&mut self, leftover: Vec<u8>) -> Option<BoxedStream> {
        let _ = leftover;
        None
    }
}

impl AsyncIo for TcpStream {}
impl AsyncIo for SharedStream {}
impl AsyncIo for crate::transport::PrefixedStream {}
impl AsyncIo for crate::transport::WebSocketStream {}
impl AsyncIo for crate::vision::VisionStream {}
impl AsyncIo for tokio_rustls::client::TlsStream<BoxedStream> {}

impl AsyncIo for crate::vless::VlessResponseStream {
    fn vision_detach(&mut self, leftover: Vec<u8>) -> Option<BoxedStream> {
        let mut extra = leftover;
        extra.extend(self.take_pending());
        self.inner.as_mut().get_mut().vision_detach(extra)
    }
}

impl AsyncIo for RealityTlsStream {
    fn vision_detach(&mut self, leftover: Vec<u8>) -> Option<BoxedStream> {
        // Direct splices READS onto raw TCP. Writes stay on this REALITY
        // stream — Xray/QPN never switch the uplink to raw on Direct.
        self.mark_transport_shared();
        let mut extra = leftover;
        extra.extend(self.steal_pending());
        extra.extend(self.steal_inbound_leftover());
        Some(crate::transport::PrefixedStream::wrap_if_needed(
            extra,
            Box::pin(self.shared_handle()),
        ))
    }
}

pub type BoxedStream = Pin<Box<dyn AsyncIo>>;

pub async fn connect_tcp(host: &str, port: u16, bind: Option<BindHint>) -> Result<TcpStream, ProxyError> {
    let stream = if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        TcpStream::connect((ip, port)).await?
    } else {
        TcpStream::connect((host, port)).await?
    };
    let _ = stream.set_nodelay(true);
    if let Some(hint) = bind {
        hint.apply(&stream);
    }
    Ok(stream)
}

#[derive(Clone, Debug)]
pub struct BindHint {
    pub local: std::net::SocketAddr,
    pub unicast_if: Option<i32>,
}

impl BindHint {
    fn apply(&self, _stream: &TcpStream) {
        // Interface bind is applied by clash-core::InterfaceBinder after connect.
        let _ = (self.local, self.unicast_if);
    }
}

pub async fn dial_vless(
    tcp: TcpStream,
    options: &VlessOptions,
    dest_host: &str,
    dest_port: u16,
) -> Result<BoxedStream, ProxyError> {
    let kind = resolve_transport(&options.transport);
    if kind == TransportKind::Unsupported {
        return Err(ProxyError::new(
            ProxyErrorCode::TransportUpgradeFailed,
            format!("VLESS transport '{}' is not supported", options.transport),
        ));
    }
    if options.security == VlessSecurity::Reality && options.reality_public_key.is_none() {
        return Err(ProxyError::new(
            ProxyErrorCode::AuthRequired,
            "VLESS REALITY needs pbk",
        ));
    }
    if let Some(flow) = &options.flow {
        if !flow.is_empty() && !flow.eq_ignore_ascii_case(VISION_FLOW) {
            return Err(ProxyError::new(
                ProxyErrorCode::InvalidResponse,
                format!("VLESS flow '{flow}' is not supported"),
            ));
        }
    }

    let mut layered: BoxedStream = Box::pin(tcp);
    match options.security {
        VlessSecurity::Tls => {
            layered = tls_wrap(layered, options.sni_or_host(), options.allow_insecure, &options.alpn).await?;
        }
        VlessSecurity::Reality => {
            let pbk = options.reality_public_key.as_deref().unwrap();
            let default_alpn = ["h2".to_string(), "http/1.1".to_string()];
            let alpn = if options.alpn.is_empty() {
                default_alpn.as_slice()
            } else {
                options.alpn.as_slice()
            };
            layered = Box::pin(
                reality::handshake(
                    layered,
                    options.sni_or_host(),
                    pbk,
                    options.reality_short_id.as_deref(),
                    alpn,
                )
                .await?,
            );
        }
        VlessSecurity::None => {}
    }

    let host_header = resolve_host_header(
        options.host_header.as_deref(),
        options.sni.as_deref(),
        &options.host,
    );
    layered = apply_transport(kind, layered, options.path.as_deref(), &host_header).await?;
    establish_vless(layered, options, dest_host, dest_port).await
}

pub async fn dial_trojan(
    tcp: TcpStream,
    options: &TrojanOptions,
    dest_host: &str,
    dest_port: u16,
) -> Result<BoxedStream, ProxyError> {
    let kind = resolve_transport(&options.transport);
    if kind == TransportKind::Unsupported {
        return Err(ProxyError::new(
            ProxyErrorCode::TransportUpgradeFailed,
            format!("Trojan transport '{}' is not supported", options.transport),
        ));
    }
    let mut layered = tls_wrap(
        Box::pin(tcp),
        options.sni_or_host(),
        options.allow_insecure,
        &options.alpn,
    )
    .await?;
    let host_header = resolve_host_header(
        options.host_header.as_deref(),
        options.sni.as_deref(),
        &options.host,
    );
    layered = apply_transport(kind, layered, options.path.as_deref(), &host_header).await?;
    establish_trojan(layered, options, dest_host, dest_port).await
}

pub async fn dial(
    node_type: &str,
    tcp: TcpStream,
    vless: Option<&VlessOptions>,
    trojan: Option<&TrojanOptions>,
    dest_host: &str,
    dest_port: u16,
    time_limit: Duration,
) -> Result<BoxedStream, ProxyError> {
    let work = async {
        match node_type.to_ascii_lowercase().as_str() {
            "vless" => {
                let opts = vless.ok_or_else(|| {
                    ProxyError::new(ProxyErrorCode::AuthRequired, "VLESS node missing uuid")
                })?;
                dial_vless(tcp, opts, dest_host, dest_port).await
            }
            "trojan" => {
                let opts = trojan.ok_or_else(|| {
                    ProxyError::new(ProxyErrorCode::AuthRequired, "Trojan node missing password")
                })?;
                dial_trojan(tcp, opts, dest_host, dest_port).await
            }
            other => Err(ProxyError::new(
                ProxyErrorCode::InvalidResponse,
                format!("Outbound type {other}"),
            )),
        }
    };
    match timeout(time_limit, work).await {
        Ok(r) => r,
        Err(_) => Err(ProxyError::new(
            ProxyErrorCode::Timeout,
            "proxy dial timed out",
        )),
    }
}

async fn tls_wrap(
    stream: BoxedStream,
    sni: &str,
    insecure: bool,
    alpn: &[String],
) -> Result<BoxedStream, ProxyError> {
    let connector = TlsConnector::new(insecure, alpn)?;
    let tls = connector.connect(sni, stream).await?;
    Ok(Box::pin(tls))
}
