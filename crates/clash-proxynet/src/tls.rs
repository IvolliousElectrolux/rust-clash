use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::TlsConnector as TokioTls;
use tokio_rustls::client::TlsStream;

use crate::error::{ProxyError, ProxyErrorCode};

/// rustls 0.23 + reqwest 会同时拉 ring 和 aws-lc-rs, 不手动指定就会在握手时 panic.
pub fn install_crypto_provider() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

fn client_builder() -> Result<rustls::ConfigBuilder<ClientConfig, rustls::WantsVerifier>, ProxyError> {
    install_crypto_provider();
    ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|e| ProxyError::new(ProxyErrorCode::ConnectionFailed, e.to_string()))
}

#[derive(Debug)]
struct InsecureVerifier;

impl ServerCertVerifier for InsecureVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

pub struct TlsConnector {
    inner: TokioTls,
}

impl TlsConnector {
    pub fn new(insecure: bool, alpn: &[String]) -> Result<Self, ProxyError> {
        use parking_lot::Mutex;
        use std::collections::HashMap;
        static CACHE: std::sync::OnceLock<Mutex<HashMap<(bool, Vec<u8>), TokioTls>>> =
            std::sync::OnceLock::new();
        let key = (
            insecure,
            alpn.iter().flat_map(|s| {
                let mut v = s.as_bytes().to_vec();
                v.push(0);
                v
            }).collect::<Vec<_>>(),
        );
        let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
        if let Some(inner) = cache.lock().get(&key).cloned() {
            return Ok(Self { inner });
        }
        let config = if insecure {
            client_builder()?
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(InsecureVerifier))
                .with_no_client_auth()
        } else {
            let mut roots = RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            client_builder()?
                .with_root_certificates(roots)
                .with_no_client_auth()
        };
        let mut config = config;
        if !alpn.is_empty() {
            config.alpn_protocols = alpn.iter().map(|s| s.as_bytes().to_vec()).collect();
        }
        let inner = TokioTls::from(Arc::new(config));
        cache.lock().insert(key, inner.clone());
        Ok(Self { inner })
    }

    pub async fn connect<S>(
        &self,
        sni: &str,
        stream: S,
    ) -> Result<TlsStream<S>, ProxyError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let name = ServerName::try_from(sni.to_string()).map_err(|_| {
            ProxyError::new(ProxyErrorCode::InvalidResponse, format!("bad SNI {sni}"))
        })?;
        self.inner
            .connect(name, stream)
            .await
            .map_err(|e| ProxyError::new(ProxyErrorCode::ConnectionFailed, e.to_string()))
    }
}
