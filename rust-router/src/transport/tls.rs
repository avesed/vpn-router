//! TLS transport implementation using tokio-rustls
//!
//! This module provides a TLS transport for establishing secure connections
//! using the rustls library with Mozilla's root certificates.
//!
//! # Features
//!
//! - TLS 1.2 and 1.3 support
//! - Server Name Indication (SNI)
//! - ALPN protocol negotiation
//! - Certificate verification via webpki-roots
//! - Optional certificate verification skip (for testing)
//!
//! # Example
//!
//! ```no_run
//! use rust_router::transport::{TransportConfig, TlsConfig, TlsTransport, Transport};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let transport = TlsTransport;
//! let config = TransportConfig::tcp("example.com", 443)
//!     .with_tls(TlsConfig::new("example.com"));
//! let stream = transport.connect(&config).await?;
//! # Ok(())
//! # }
//! ```

use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error as RustlsError, SignatureScheme};
use socket2::{SockRef, TcpKeepalive};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

use super::{TlsConfig, Transport, TransportConfig, TransportError, TransportStream};

/// TLS transport for secure connections
///
/// This transport establishes TLS connections using tokio-rustls.
/// It supports SNI, ALPN, and certificate verification.
///
/// # Thread Safety
///
/// `TlsTransport` is `Send + Sync` and can be shared across threads.
#[derive(Debug, Clone, Copy, Default)]
pub struct TlsTransport;

impl TlsTransport {
    /// Create a new TLS transport
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Resolve hostname to socket addresses
    fn resolve_address(address: &str, port: u16) -> Result<Vec<SocketAddr>, TransportError> {
        let addr_str = format!("{address}:{port}");

        // Try to parse as socket address first
        if let Ok(addr) = addr_str.parse::<SocketAddr>() {
            return Ok(vec![addr]);
        }

        // Use DNS resolution
        let addrs: Vec<SocketAddr> = addr_str
            .to_socket_addrs()
            .map_err(|e| TransportError::dns_failed(&addr_str, e.to_string()))?
            .collect();

        if addrs.is_empty() {
            return Err(TransportError::dns_failed(
                &addr_str,
                "no addresses returned",
            ));
        }

        Ok(addrs)
    }

    /// Configure TCP socket options
    fn configure_socket(
        stream: &TcpStream,
        config: &TransportConfig,
    ) -> Result<(), TransportError> {
        // Set TCP_NODELAY
        if config.tcp_nodelay {
            stream
                .set_nodelay(true)
                .map_err(|e| TransportError::socket_option("TCP_NODELAY", e.to_string()))?;
        }

        // Set TCP keepalive
        if config.tcp_keepalive {
            let socket_ref = SockRef::from(stream);
            let keepalive = TcpKeepalive::new()
                .with_time(Duration::from_secs(60))
                .with_interval(Duration::from_secs(20));

            #[cfg(target_os = "linux")]
            let keepalive = keepalive.with_retries(3);

            socket_ref
                .set_tcp_keepalive(&keepalive)
                .map_err(|e| TransportError::socket_option("TCP_KEEPALIVE", e.to_string()))?;
        }

        Ok(())
    }

    /// Create TLS client configuration
    fn create_tls_config(tls_config: &TlsConfig) -> Result<ClientConfig, TransportError> {
        // Build the base config
        let config = if tls_config.skip_verify {
            // WARNING: Insecure - for testing only
            ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(InsecureServerCertVerifier))
                .with_no_client_auth()
        } else {
            // Secure configuration with Mozilla's root certificates
            let root_store =
                rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

            ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth()
        };

        // Set ALPN protocols if specified
        let config = if !tls_config.alpn.is_empty() {
            let alpn_protocols: Vec<Vec<u8>> =
                tls_config.alpn.iter().map(|s| s.as_bytes().to_vec()).collect();

            let mut config = config;
            config.alpn_protocols = alpn_protocols;
            config
        } else {
            config
        };

        Ok(config)
    }

    /// Connect to a single address with TLS
    async fn connect_to_addr(
        addr: SocketAddr,
        server_name: ServerName<'static>,
        tls_connector: &TlsConnector,
        config: &TransportConfig,
    ) -> Result<tokio_rustls::client::TlsStream<TcpStream>, TransportError> {
        let connect_timeout = config.connect_timeout;

        // Establish TCP connection
        let tcp_connect = TcpStream::connect(addr);
        let tcp_stream = timeout(connect_timeout, tcp_connect)
            .await
            .map_err(|_| {
                TransportError::timeout(addr.to_string(), connect_timeout.as_millis() as u64)
            })?
            .map_err(|e| TransportError::connection_failed(addr.to_string(), e.to_string()))?;

        // Configure TCP socket options before TLS handshake
        Self::configure_socket(&tcp_stream, config)?;

        // Perform TLS handshake
        let tls_connect = tls_connector.connect(server_name.clone(), tcp_stream);
        let tls_stream = timeout(connect_timeout, tls_connect)
            .await
            .map_err(|_| {
                TransportError::timeout(
                    format!("TLS handshake to {addr}"),
                    connect_timeout.as_millis() as u64,
                )
            })?
            .map_err(|e| {
                TransportError::tls_handshake(server_name.to_str().to_string(), e.to_string())
            })?;

        Ok(tls_stream)
    }
}

#[async_trait]
impl Transport for TlsTransport {
    /// Connect to a remote server over TLS
    ///
    /// This method establishes a TCP connection, performs TLS handshake,
    /// and configures socket options.
    ///
    /// # Arguments
    ///
    /// * `config` - Transport configuration with address and TLS settings
    ///
    /// # Errors
    ///
    /// Returns `TransportError` if:
    /// - DNS resolution fails
    /// - TCP connection fails
    /// - TLS handshake fails
    /// - Socket configuration fails
    async fn connect(&self, config: &TransportConfig) -> Result<TransportStream, TransportError> {
        // TLS configuration is required
        let tls_config = config
            .tls
            .as_ref()
            .ok_or_else(|| TransportError::tls_config("TLS configuration required"))?;

        // Parse server name for SNI
        let server_name: ServerName<'static> = tls_config
            .server_name
            .clone()
            .try_into()
            .map_err(|_| TransportError::invalid_server_name(&tls_config.server_name))?;

        // Create TLS configuration and connector
        let client_config = Self::create_tls_config(tls_config)?;
        let tls_connector = TlsConnector::from(Arc::new(client_config));

        // Resolve address
        let addrs = Self::resolve_address(&config.address, config.port)?;

        // Try connecting to each address
        let mut last_error = None;

        for addr in addrs {
            match Self::connect_to_addr(addr, server_name.clone(), &tls_connector, config).await {
                Ok(tls_stream) => {
                    tracing::debug!(
                        addr = %addr,
                        server_name = %tls_config.server_name,
                        alpn = ?tls_config.alpn,
                        "TLS connection established"
                    );

                    return Ok(TransportStream::Tls(tls_stream));
                }
                Err(e) => {
                    tracing::debug!(
                        addr = %addr,
                        server_name = %tls_config.server_name,
                        error = %e,
                        "TLS connection attempt failed"
                    );
                    last_error = Some(e);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            TransportError::connection_failed(
                config.address_string(),
                "no addresses to connect to",
            )
        }))
    }
}

/// Insecure certificate verifier that accepts any certificate
///
/// # Warning
///
/// This verifier should ONLY be used for testing purposes. It completely
/// disables certificate verification, making the connection vulnerable to
/// man-in-the-middle attacks.
#[derive(Debug)]
struct InsecureServerCertVerifier;

impl ServerCertVerifier for InsecureServerCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        // Accept any certificate - INSECURE!
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Once;

    static INIT_CRYPTO: Once = Once::new();

    fn init_crypto_provider() {
        INIT_CRYPTO.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
    }

    #[test]
    fn test_tls_transport_new() {
        let transport = TlsTransport::new();
        assert_eq!(std::mem::size_of_val(&transport), 0);
    }

    #[test]
    fn test_tls_transport_default() {
        let transport = TlsTransport::default();
        assert_eq!(std::mem::size_of_val(&transport), 0);
    }

    #[test]
    fn test_create_tls_config_default() {
        init_crypto_provider();
        let tls_config = TlsConfig::new("example.com");
        let result = TlsTransport::create_tls_config(&tls_config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_create_tls_config_with_alpn() {
        init_crypto_provider();
        let tls_config = TlsConfig::new("example.com").with_alpn(vec!["h2", "http/1.1"]);
        let result = TlsTransport::create_tls_config(&tls_config);
        assert!(result.is_ok());

        let client_config = result.unwrap();
        assert_eq!(client_config.alpn_protocols.len(), 2);
        assert_eq!(client_config.alpn_protocols[0], b"h2");
        assert_eq!(client_config.alpn_protocols[1], b"http/1.1");
    }

    #[test]
    fn test_create_tls_config_insecure() {
        init_crypto_provider();
        let tls_config = TlsConfig::new("example.com").insecure_skip_verify();
        let result = TlsTransport::create_tls_config(&tls_config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_resolve_ipv4() {
        let addrs = TlsTransport::resolve_address("127.0.0.1", 443).unwrap();
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0].port(), 443);
    }

    #[test]
    fn test_resolve_hostname() {
        let addrs = TlsTransport::resolve_address("localhost", 443).unwrap();
        assert!(!addrs.is_empty());
    }

    #[test]
    fn test_tls_config_builder() {
        let config = TlsConfig::new("example.com")
            .with_alpn(vec!["h2"])
            .insecure_skip_verify();

        assert_eq!(config.server_name, "example.com");
        assert_eq!(config.alpn, vec!["h2"]);
        assert!(config.skip_verify);
    }

    #[tokio::test]
    async fn test_connect_no_tls_config() {
        let transport = TlsTransport::new();
        // Config without TLS should fail
        let config = TransportConfig::tcp("example.com", 443);

        let result = transport.connect(&config).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, TransportError::TlsConfigError(_)));
    }

    #[tokio::test]
    async fn test_connect_invalid_server_name() {
        init_crypto_provider();
        let transport = TlsTransport::new();
        // Invalid server name should fail
        let config = TransportConfig::tcp("127.0.0.1", 443)
            .with_tls(TlsConfig::new("invalid\x00name"));

        let result = transport.connect(&config).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_connect_connection_refused() {
        init_crypto_provider();
        let transport = TlsTransport::new();
        // Port 1 should be refused
        let config = TransportConfig::tcp("127.0.0.1", 1)
            .with_tls(TlsConfig::new("localhost"))
            .with_timeout(Duration::from_millis(100));

        let result = transport.connect(&config).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    #[ignore = "requires network access"]
    async fn test_connect_real_server() {
        init_crypto_provider();
        let transport = TlsTransport::new();
        let config = TransportConfig::tcp("1.1.1.1", 443)
            .with_tls(TlsConfig::new("cloudflare-dns.com"));

        let result = transport.connect(&config).await;
        assert!(result.is_ok());
    }
}
