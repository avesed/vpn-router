//! QUIC transport implementation using quinn
//!
//! This module provides a QUIC transport for establishing secure, multiplexed
//! connections using the QUIC protocol. It implements a multi-endpoint pool
//! with round-robin load balancing for optimal performance.
//!
//! # Architecture
//!
//! The QUIC transport uses multiple UDP endpoints (up to 8 by default) to
//! distribute connections across different local ports. This improves
//! throughput and reduces head-of-line blocking.
//!
//! ```text
//! QuicEndpointPool
//!       |
//!       +-> Endpoint 1 (UDP socket on port A)
//!       +-> Endpoint 2 (UDP socket on port B)
//!       +-> ... (round-robin selection)
//!       +-> Endpoint N
//!       |
//!       v
//!   Connection -> BiStream (SendStream + RecvStream)
//!       |
//!       v
//!   QuicStream (AsyncRead + AsyncWrite)
//! ```
//!
//! # Features
//!
//! - Multi-endpoint pool for parallel connections
//! - Round-robin endpoint selection
//! - Configurable idle timeout and keep-alive
//! - ALPN protocol negotiation
//! - Optional certificate verification skip (for testing)
//!
//! # Example
//!
//! ```no_run
//! use rust_router::transport::quic::{QuicClientConfig, QuicEndpointPool};
//! use std::net::SocketAddr;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = QuicClientConfig::new("example.com")
//!     .with_alpn(vec!["h3"]);
//!
//! let pool = QuicEndpointPool::new(&config).await?;
//! let addr: SocketAddr = "93.184.216.34:443".parse()?;
//! let stream = pool.connect(addr, "example.com").await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Security
//!
//! - Uses Mozilla's root certificates via `webpki-roots`
//! - TLS 1.3 only (QUIC requirement)
//! - Certificate verification enabled by default

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use quinn::{Connection, Endpoint, RecvStream, SendStream, VarInt};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as RustlsError, SignatureScheme};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::TransportError;

/// Default number of endpoints (auto-detected based on CPU count)
const DEFAULT_NUM_ENDPOINTS: usize = 0;

/// Maximum number of endpoints in the pool
const MAX_ENDPOINTS: usize = 8;

/// Default idle timeout in seconds
const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 30;

/// Default keep-alive interval in seconds
const DEFAULT_KEEP_ALIVE_INTERVAL_SECS: u64 = 15;

/// QUIC client configuration
///
/// This struct holds all configuration options for QUIC client connections,
/// including server name, ALPN protocols, timeouts, and endpoint pool size.
///
/// # Example
///
/// ```
/// use rust_router::transport::quic::QuicClientConfig;
///
/// let config = QuicClientConfig::new("example.com")
///     .with_alpn(vec!["h3"])
///     .with_idle_timeout(60)
///     .with_keep_alive_interval(20)
///     .with_num_endpoints(4);
/// ```
#[derive(Debug, Clone)]
pub struct QuicClientConfig {
    /// Server name for SNI (Server Name Indication)
    pub server_name: String,

    /// ALPN protocols (e.g., ["h3"])
    pub alpn_protocols: Vec<String>,

    /// Skip certificate verification (INSECURE - for testing only)
    pub skip_verify: bool,

    /// Idle timeout in seconds
    pub idle_timeout_secs: u64,

    /// Keep-alive interval in seconds
    pub keep_alive_interval_secs: u64,

    /// Number of endpoints in the pool (0 = auto-detect based on CPU count)
    pub num_endpoints: usize,
}

impl QuicClientConfig {
    /// Create a new QUIC client configuration with server name
    ///
    /// # Arguments
    ///
    /// * `server_name` - Server name for SNI
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::transport::quic::QuicClientConfig;
    ///
    /// let config = QuicClientConfig::new("example.com");
    /// assert_eq!(config.server_name, "example.com");
    /// assert!(config.alpn_protocols.is_empty());
    /// assert!(!config.skip_verify);
    /// ```
    #[must_use]
    pub fn new(server_name: impl Into<String>) -> Self {
        Self {
            server_name: server_name.into(),
            alpn_protocols: Vec::new(),
            skip_verify: false,
            idle_timeout_secs: DEFAULT_IDLE_TIMEOUT_SECS,
            keep_alive_interval_secs: DEFAULT_KEEP_ALIVE_INTERVAL_SECS,
            num_endpoints: DEFAULT_NUM_ENDPOINTS,
        }
    }

    /// Set ALPN protocols
    ///
    /// # Arguments
    ///
    /// * `protocols` - List of ALPN protocol names (e.g., ["h3"])
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::transport::quic::QuicClientConfig;
    ///
    /// let config = QuicClientConfig::new("example.com")
    ///     .with_alpn(vec!["h3", "h3-29"]);
    /// assert_eq!(config.alpn_protocols, vec!["h3", "h3-29"]);
    /// ```
    #[must_use]
    pub fn with_alpn<I, S>(mut self, protocols: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.alpn_protocols = protocols.into_iter().map(Into::into).collect();
        self
    }

    /// Skip certificate verification (INSECURE)
    ///
    /// # Warning
    ///
    /// This disables certificate verification and should ONLY be used for
    /// testing or development purposes. Never use this in production.
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::transport::quic::QuicClientConfig;
    ///
    /// // For testing only!
    /// let config = QuicClientConfig::new("localhost")
    ///     .insecure_skip_verify();
    /// assert!(config.skip_verify);
    /// ```
    #[must_use]
    pub fn insecure_skip_verify(mut self) -> Self {
        self.skip_verify = true;
        self
    }

    /// Set idle timeout in seconds
    ///
    /// The connection will be closed if no data is transferred for this duration.
    ///
    /// # Arguments
    ///
    /// * `secs` - Idle timeout in seconds
    #[must_use]
    pub fn with_idle_timeout(mut self, secs: u64) -> Self {
        self.idle_timeout_secs = secs;
        self
    }

    /// Set keep-alive interval in seconds
    ///
    /// PING frames will be sent at this interval to keep the connection alive.
    ///
    /// # Arguments
    ///
    /// * `secs` - Keep-alive interval in seconds
    #[must_use]
    pub fn with_keep_alive_interval(mut self, secs: u64) -> Self {
        self.keep_alive_interval_secs = secs;
        self
    }

    /// Set the number of endpoints in the pool
    ///
    /// Setting this to 0 will auto-detect based on CPU count (min 1, max 8).
    ///
    /// # Arguments
    ///
    /// * `num` - Number of endpoints (0 for auto-detect)
    #[must_use]
    pub fn with_num_endpoints(mut self, num: usize) -> Self {
        self.num_endpoints = num;
        self
    }
}

impl Default for QuicClientConfig {
    fn default() -> Self {
        Self {
            server_name: String::new(),
            alpn_protocols: Vec::new(),
            skip_verify: false,
            idle_timeout_secs: DEFAULT_IDLE_TIMEOUT_SECS,
            keep_alive_interval_secs: DEFAULT_KEEP_ALIVE_INTERVAL_SECS,
            num_endpoints: DEFAULT_NUM_ENDPOINTS,
        }
    }
}

/// QUIC bidirectional stream wrapper
///
/// This struct wraps a QUIC bidirectional stream (SendStream + RecvStream)
/// and implements `AsyncRead` and `AsyncWrite` for seamless integration
/// with tokio's async I/O primitives.
///
/// # Connection Lifetime
///
/// The `QuicStream` holds an `Arc<Connection>` to keep the underlying QUIC
/// connection alive as long as the stream is in use. When the last stream
/// is dropped, the connection may be closed.
pub struct QuicStream {
    /// Send half of the bidirectional stream
    send: SendStream,

    /// Receive half of the bidirectional stream
    recv: RecvStream,

    /// Reference to keep the connection alive
    _connection: Arc<Connection>,
}

impl QuicStream {
    /// Create a new QUIC stream from send/receive streams
    ///
    /// # Arguments
    ///
    /// * `send` - Send stream for writing data
    /// * `recv` - Receive stream for reading data
    /// * `connection` - Arc reference to the QUIC connection
    #[must_use]
    pub fn new(send: SendStream, recv: RecvStream, connection: Arc<Connection>) -> Self {
        Self {
            send,
            recv,
            _connection: connection,
        }
    }

    /// Get the connection's stable ID
    #[must_use]
    pub fn stable_id(&self) -> usize {
        self._connection.stable_id()
    }

    /// Get the remote address of the connection
    #[must_use]
    pub fn remote_address(&self) -> SocketAddr {
        self._connection.remote_address()
    }

    /// Check if the connection is still open
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self._connection.close_reason().is_some()
    }

    /// Get connection statistics
    #[must_use]
    pub fn stats(&self) -> quinn::ConnectionStats {
        self._connection.stats()
    }
}

impl std::fmt::Debug for QuicStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicStream")
            .field("stable_id", &self.stable_id())
            .field("remote_address", &self.remote_address())
            .field("is_closed", &self.is_closed())
            .finish()
    }
}

impl AsyncRead for QuicStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        use std::future::Future;

        // Get the unfilled portion length first
        let max_len = buf.remaining();
        if max_len == 0 {
            return Poll::Ready(Ok(()));
        }

        // Use read_chunk which returns owned bytes (Chunk)
        let recv = &mut self.recv;
        let read_fut = recv.read_chunk(max_len, true);

        // Use std::pin::pin! macro for safe pinning (stabilized in Rust 1.68)
        let mut pinned = std::pin::pin!(read_fut);

        match pinned.as_mut().poll(cx) {
            Poll::Ready(Ok(Some(chunk))) => {
                // Copy chunk data to the buffer
                buf.put_slice(&chunk.bytes);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Ok(None)) => {
                // Stream finished (EOF)
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::Other,
                format!("QUIC read error: {e}"),
            ))),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for QuicStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match Pin::new(&mut self.send).poll_write(cx, buf) {
            Poll::Ready(Ok(n)) => Poll::Ready(Ok(n)),
            Poll::Ready(Err(e)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::Other,
                format!("QUIC write error: {e}"),
            ))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match Pin::new(&mut self.send).poll_flush(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::Other,
                format!("QUIC flush error: {e}"),
            ))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match Pin::new(&mut self.send).poll_shutdown(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::Other,
                format!("QUIC shutdown error: {e}"),
            ))),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// QUIC endpoint pool for client connections
///
/// This struct manages a pool of QUIC endpoints, each bound to a different
/// local UDP port. Connections are distributed across endpoints using
/// round-robin selection for improved throughput.
///
/// # Thread Safety
///
/// `QuicEndpointPool` is `Send + Sync` and can be shared across threads.
/// The atomic counter ensures lock-free round-robin selection.
pub struct QuicEndpointPool {
    /// Pool of QUIC endpoints
    endpoints: Vec<Arc<Endpoint>>,

    /// Round-robin counter for endpoint selection
    next_index: AtomicU64,

    /// Shared client configuration
    client_config: Arc<quinn::ClientConfig>,

    /// Server name for SNI
    server_name: String,
}

impl QuicEndpointPool {
    /// Create a new QUIC endpoint pool
    ///
    /// This method creates multiple UDP endpoints and binds them to
    /// ephemeral ports. The number of endpoints is determined by the
    /// configuration or auto-detected based on CPU count.
    ///
    /// # Arguments
    ///
    /// * `config` - QUIC client configuration
    ///
    /// # Errors
    ///
    /// Returns `TransportError` if:
    /// - TLS configuration fails
    /// - UDP socket binding fails
    /// - Endpoint creation fails
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rust_router::transport::quic::{QuicClientConfig, QuicEndpointPool};
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let config = QuicClientConfig::new("example.com");
    /// let pool = QuicEndpointPool::new(&config).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn new(config: &QuicClientConfig) -> Result<Self, TransportError> {
        // Determine number of endpoints
        let num_endpoints = if config.num_endpoints == 0 {
            std::cmp::min(num_cpus::get(), MAX_ENDPOINTS).max(1)
        } else {
            std::cmp::min(config.num_endpoints, MAX_ENDPOINTS)
        };

        // Build QUIC client configuration
        let client_config = build_client_config(config)?;
        let client_config = Arc::new(client_config);

        // Create endpoints
        let mut endpoints = Vec::with_capacity(num_endpoints);

        for i in 0..num_endpoints {
            // Bind to ephemeral port
            let socket = std::net::UdpSocket::bind("0.0.0.0:0").map_err(|e| {
                TransportError::connection_failed(
                    format!("endpoint {i}"),
                    format!("failed to bind UDP socket: {e}"),
                )
            })?;

            socket.set_nonblocking(true).map_err(|e| {
                TransportError::socket_option(
                    "UDP_NONBLOCK",
                    format!("failed to set non-blocking: {e}"),
                )
            })?;

            // Create quinn endpoint
            let runtime = Arc::new(quinn::TokioRuntime);
            let endpoint = Endpoint::new(
                quinn::EndpointConfig::default(),
                None, // Client-only, no server config
                socket,
                runtime,
            )
            .map_err(|e| {
                TransportError::connection_failed(
                    format!("endpoint {i}"),
                    format!("failed to create QUIC endpoint: {e}"),
                )
            })?;

            // Set default client config
            let mut endpoint = endpoint;
            endpoint.set_default_client_config((*client_config).clone());

            endpoints.push(Arc::new(endpoint));
        }

        tracing::debug!(
            num_endpoints = endpoints.len(),
            server_name = %config.server_name,
            "QUIC endpoint pool created"
        );

        Ok(Self {
            endpoints,
            next_index: AtomicU64::new(0),
            client_config,
            server_name: config.server_name.clone(),
        })
    }

    /// Get the number of endpoints in the pool
    #[must_use]
    pub fn num_endpoints(&self) -> usize {
        self.endpoints.len()
    }

    /// Select the next endpoint using round-robin
    fn next_endpoint(&self) -> &Arc<Endpoint> {
        let idx = self.next_index.fetch_add(1, Ordering::Relaxed) as usize;
        &self.endpoints[idx % self.endpoints.len()]
    }

    /// Connect to a remote server and open a bidirectional stream
    ///
    /// This method establishes a QUIC connection to the specified address
    /// and opens a bidirectional stream for data transfer.
    ///
    /// # Arguments
    ///
    /// * `addr` - Remote socket address
    /// * `server_name` - Server name for SNI (overrides config if provided)
    ///
    /// # Errors
    ///
    /// Returns `TransportError` if:
    /// - Connection establishment fails
    /// - Stream opening fails
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rust_router::transport::quic::{QuicClientConfig, QuicEndpointPool};
    /// use std::net::SocketAddr;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let config = QuicClientConfig::new("example.com");
    /// let pool = QuicEndpointPool::new(&config).await?;
    ///
    /// let addr: SocketAddr = "93.184.216.34:443".parse()?;
    /// let stream = pool.connect(addr, "example.com").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn connect(
        &self,
        addr: SocketAddr,
        server_name: &str,
    ) -> Result<QuicStream, TransportError> {
        let endpoint = self.next_endpoint();

        // Establish QUIC connection
        let connecting = endpoint
            .connect_with((*self.client_config).clone(), addr, server_name)
            .map_err(|e| {
                TransportError::connection_failed(addr.to_string(), format!("QUIC connect: {e}"))
            })?;

        let conn = connecting.await.map_err(|e| {
            TransportError::connection_failed(addr.to_string(), format!("QUIC handshake: {e}"))
        })?;

        let conn = Arc::new(conn);

        // Open bidirectional stream
        let (send, recv) = conn.open_bi().await.map_err(|e| {
            TransportError::connection_failed(
                addr.to_string(),
                format!("failed to open bidirectional stream: {e}"),
            )
        })?;

        tracing::debug!(
            addr = %addr,
            server_name = %server_name,
            stable_id = conn.stable_id(),
            "QUIC connection established"
        );

        Ok(QuicStream::new(send, recv, conn))
    }

    /// Connect using the configured server name
    ///
    /// Convenience method that uses the server name from the configuration.
    pub async fn connect_default(&self, addr: SocketAddr) -> Result<QuicStream, TransportError> {
        self.connect(addr, &self.server_name).await
    }

    /// Close all endpoints gracefully
    ///
    /// This method closes all connections on all endpoints with the given
    /// error code and reason.
    pub fn close_all(&self, error_code: VarInt, reason: &[u8]) {
        for endpoint in &self.endpoints {
            endpoint.close(error_code, reason);
        }
    }

    /// Wait for all connections on all endpoints to close
    pub async fn wait_idle(&self) {
        for endpoint in &self.endpoints {
            endpoint.wait_idle().await;
        }
    }
}

impl std::fmt::Debug for QuicEndpointPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicEndpointPool")
            .field("num_endpoints", &self.endpoints.len())
            .field("server_name", &self.server_name)
            .finish()
    }
}

/// Build QUIC client configuration from our config struct
fn build_client_config(config: &QuicClientConfig) -> Result<quinn::ClientConfig, TransportError> {
    // Build rustls client config
    let tls_config = if config.skip_verify {
        // WARNING: Insecure - for testing only
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(InsecureServerCertVerifier))
            .with_no_client_auth()
    } else {
        // Secure configuration with Mozilla's root certificates
        let root_store =
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    };

    // Set ALPN protocols if specified
    let mut tls_config = tls_config;
    if !config.alpn_protocols.is_empty() {
        tls_config.alpn_protocols = config
            .alpn_protocols
            .iter()
            .map(|s| s.as_bytes().to_vec())
            .collect();
    }

    // Create quinn crypto config from rustls config
    let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls_config).map_err(|e| {
        TransportError::TlsConfigError(format!("failed to create QUIC crypto config: {e}"))
    })?;

    // Configure transport settings
    let mut transport = quinn::TransportConfig::default();

    // Set idle timeout
    let idle_timeout = Duration::from_secs(config.idle_timeout_secs);
    transport.max_idle_timeout(Some(
        idle_timeout
            .try_into()
            .map_err(|_| TransportError::TlsConfigError("invalid idle timeout".to_string()))?,
    ));

    // Set keep-alive interval
    transport.keep_alive_interval(Some(Duration::from_secs(config.keep_alive_interval_secs)));

    // Create final client config
    let mut client_config = quinn::ClientConfig::new(Arc::new(quic_crypto));
    client_config.transport_config(Arc::new(transport));

    Ok(client_config)
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

// ============================================================================
// QUIC Server (Inbound) Support
// ============================================================================

/// Default maximum concurrent bidirectional streams per connection
const DEFAULT_MAX_CONCURRENT_STREAMS: u32 = 100;

/// Default server idle timeout in seconds
const DEFAULT_SERVER_IDLE_TIMEOUT_SECS: u64 = 60;

/// QUIC server configuration
///
/// This struct holds all configuration options for QUIC server endpoints,
/// including TLS certificates, ALPN protocols, and connection limits.
///
/// # Example
///
/// ```no_run
/// use rust_router::transport::quic::QuicServerConfig;
/// use std::net::SocketAddr;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let config = QuicServerConfig::new("0.0.0.0:443".parse()?)
///     .with_cert_pem(include_bytes!("cert.pem").to_vec())
///     .with_key_pem(include_bytes!("key.pem").to_vec())
///     .with_alpn(vec!["h3"]);
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct QuicServerConfig {
    /// Address to listen on
    pub listen_addr: SocketAddr,

    /// TLS certificate chain (PEM bytes)
    pub tls_cert_pem: Vec<u8>,

    /// TLS private key (PEM bytes)
    pub tls_key_pem: Vec<u8>,

    /// ALPN protocols (e.g., ["h3"])
    pub alpn_protocols: Vec<String>,

    /// Idle timeout in seconds
    pub idle_timeout_secs: u64,

    /// Maximum concurrent bidirectional streams per connection
    pub max_concurrent_streams: u32,
}

impl QuicServerConfig {
    /// Create a new QUIC server configuration with listen address
    ///
    /// # Arguments
    ///
    /// * `listen_addr` - Address to bind the server to
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::transport::quic::QuicServerConfig;
    /// use std::net::SocketAddr;
    ///
    /// let addr: SocketAddr = "0.0.0.0:443".parse().unwrap();
    /// let config = QuicServerConfig::new(addr);
    /// assert_eq!(config.listen_addr, addr);
    /// ```
    #[must_use]
    pub fn new(listen_addr: SocketAddr) -> Self {
        Self {
            listen_addr,
            tls_cert_pem: Vec::new(),
            tls_key_pem: Vec::new(),
            alpn_protocols: Vec::new(),
            idle_timeout_secs: DEFAULT_SERVER_IDLE_TIMEOUT_SECS,
            max_concurrent_streams: DEFAULT_MAX_CONCURRENT_STREAMS,
        }
    }

    /// Set the certificate from PEM data
    ///
    /// # Arguments
    ///
    /// * `pem` - PEM-encoded certificate data
    #[must_use]
    pub fn with_cert_pem(mut self, pem: Vec<u8>) -> Self {
        self.tls_cert_pem = pem;
        self
    }

    /// Set the private key from PEM data
    ///
    /// # Arguments
    ///
    /// * `pem` - PEM-encoded private key data
    #[must_use]
    pub fn with_key_pem(mut self, pem: Vec<u8>) -> Self {
        self.tls_key_pem = pem;
        self
    }

    /// Load certificate from file path
    ///
    /// # Arguments
    ///
    /// * `path` - Path to PEM certificate file
    ///
    /// # Errors
    ///
    /// Returns `TransportError` if file reading fails
    pub fn with_cert_file(mut self, path: impl AsRef<std::path::Path>) -> Result<Self, TransportError> {
        let pem = std::fs::read(path.as_ref()).map_err(|e| {
            TransportError::TlsConfigError(format!("failed to read certificate file: {e}"))
        })?;
        self.tls_cert_pem = pem;
        Ok(self)
    }

    /// Load private key from file path
    ///
    /// # Arguments
    ///
    /// * `path` - Path to PEM private key file
    ///
    /// # Errors
    ///
    /// Returns `TransportError` if file reading fails
    pub fn with_key_file(mut self, path: impl AsRef<std::path::Path>) -> Result<Self, TransportError> {
        let pem = std::fs::read(path.as_ref()).map_err(|e| {
            TransportError::TlsConfigError(format!("failed to read key file: {e}"))
        })?;
        self.tls_key_pem = pem;
        Ok(self)
    }

    /// Set ALPN protocols
    ///
    /// # Arguments
    ///
    /// * `protocols` - List of ALPN protocol names (e.g., ["h3"])
    #[must_use]
    pub fn with_alpn<I, S>(mut self, protocols: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.alpn_protocols = protocols.into_iter().map(Into::into).collect();
        self
    }

    /// Set idle timeout in seconds
    ///
    /// # Arguments
    ///
    /// * `secs` - Idle timeout in seconds
    #[must_use]
    pub fn with_idle_timeout(mut self, secs: u64) -> Self {
        self.idle_timeout_secs = secs;
        self
    }

    /// Set maximum concurrent bidirectional streams per connection
    ///
    /// # Arguments
    ///
    /// * `max` - Maximum number of concurrent streams
    #[must_use]
    pub fn with_max_concurrent_streams(mut self, max: u32) -> Self {
        self.max_concurrent_streams = max;
        self
    }

    /// Validate the configuration
    ///
    /// # Errors
    ///
    /// Returns `TransportError` if:
    /// - No certificate is provided
    /// - No private key is provided
    pub fn validate(&self) -> Result<(), TransportError> {
        if self.tls_cert_pem.is_empty() {
            return Err(TransportError::TlsConfigError(
                "no TLS certificate provided".to_string(),
            ));
        }
        if self.tls_key_pem.is_empty() {
            return Err(TransportError::TlsConfigError(
                "no TLS private key provided".to_string(),
            ));
        }
        Ok(())
    }
}

impl Default for QuicServerConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:443".parse().unwrap(),
            tls_cert_pem: Vec::new(),
            tls_key_pem: Vec::new(),
            alpn_protocols: Vec::new(),
            idle_timeout_secs: DEFAULT_SERVER_IDLE_TIMEOUT_SECS,
            max_concurrent_streams: DEFAULT_MAX_CONCURRENT_STREAMS,
        }
    }
}

/// Load certificates from PEM data
///
/// # Arguments
///
/// * `pem` - PEM-encoded certificate data
///
/// # Errors
///
/// Returns `TransportError` if parsing fails or no certificates found
pub fn load_certs_from_pem(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>, TransportError> {
    use rustls_pemfile::certs;
    use std::io::BufReader;

    let mut reader = BufReader::new(pem);
    let certs: Vec<CertificateDer<'static>> = certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| TransportError::TlsConfigError(format!("failed to parse PEM certificates: {e}")))?;

    if certs.is_empty() {
        return Err(TransportError::TlsConfigError(
            "no certificates found in PEM data".to_string(),
        ));
    }

    Ok(certs)
}

/// Load a private key from PEM data
///
/// Supports PKCS#8, RSA, and EC private key formats.
///
/// # Arguments
///
/// * `pem` - PEM-encoded private key data
///
/// # Errors
///
/// Returns `TransportError` if parsing fails or no key found
pub fn load_key_from_pem(pem: &[u8]) -> Result<PrivateKeyDer<'static>, TransportError> {
    use rustls_pemfile::{pkcs8_private_keys, rsa_private_keys, ec_private_keys};
    use std::io::BufReader;

    let mut reader = BufReader::new(pem);

    // Try PKCS#8 format first
    let keys: Vec<_> = pkcs8_private_keys(&mut reader)
        .filter_map(Result::ok)
        .collect();
    if !keys.is_empty() {
        return Ok(PrivateKeyDer::Pkcs8(keys.into_iter().next().unwrap()));
    }

    // Try RSA format
    reader = BufReader::new(pem);
    let keys: Vec<_> = rsa_private_keys(&mut reader)
        .filter_map(Result::ok)
        .collect();
    if !keys.is_empty() {
        return Ok(PrivateKeyDer::Pkcs1(keys.into_iter().next().unwrap()));
    }

    // Try EC format
    reader = BufReader::new(pem);
    let keys: Vec<_> = ec_private_keys(&mut reader)
        .filter_map(Result::ok)
        .collect();
    if !keys.is_empty() {
        return Ok(PrivateKeyDer::Sec1(keys.into_iter().next().unwrap()));
    }

    Err(TransportError::TlsConfigError(
        "no private key found in PEM data (tried PKCS#8, RSA, and EC formats)".to_string(),
    ))
}

/// Build QUIC server configuration from our config struct
///
/// # Arguments
///
/// * `config` - QUIC server configuration
///
/// # Errors
///
/// Returns `TransportError` if TLS configuration fails
pub fn build_server_config(config: &QuicServerConfig) -> Result<quinn::ServerConfig, TransportError> {
    config.validate()?;

    // Parse certificates and key from PEM
    let certs = load_certs_from_pem(&config.tls_cert_pem)?;
    let key = load_key_from_pem(&config.tls_key_pem)?;

    // Build rustls server config
    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| TransportError::TlsConfigError(format!("failed to create TLS config: {e}")))?;

    // Set ALPN protocols if specified
    if !config.alpn_protocols.is_empty() {
        tls_config.alpn_protocols = config
            .alpn_protocols
            .iter()
            .map(|s| s.as_bytes().to_vec())
            .collect();
    }

    // Create quinn crypto config from rustls config
    let quic_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls_config).map_err(|e| {
        TransportError::TlsConfigError(format!("failed to create QUIC crypto config: {e}"))
    })?;

    // Configure transport settings
    let mut transport = quinn::TransportConfig::default();

    // Set idle timeout
    let idle_timeout = Duration::from_secs(config.idle_timeout_secs);
    transport.max_idle_timeout(Some(
        idle_timeout
            .try_into()
            .map_err(|_| TransportError::TlsConfigError("invalid idle timeout".to_string()))?,
    ));

    // Set max concurrent bidirectional streams
    transport.max_concurrent_bidi_streams(VarInt::from_u32(config.max_concurrent_streams));

    // Create final server config
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_crypto));
    server_config.transport_config(Arc::new(transport));

    Ok(server_config)
}

/// QUIC inbound listener for accepting QUIC connections
///
/// This listener binds to a UDP socket and accepts incoming QUIC connections.
/// Each connection can have multiple bidirectional streams.
///
/// # Example
///
/// ```no_run
/// use rust_router::transport::quic::{QuicServerConfig, QuicInboundListener};
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let config = QuicServerConfig::new("0.0.0.0:443".parse()?)
///     .with_cert_file("cert.pem")?
///     .with_key_file("key.pem")?
///     .with_alpn(vec!["h3"]);
///
/// let listener = QuicInboundListener::bind(&config).await?;
///
/// loop {
///     if let Some(stream) = listener.accept().await {
///         // Handle stream
///         println!("Accepted stream from {}", stream.remote_address());
///     }
/// }
/// # }
/// ```
pub struct QuicInboundListener {
    /// Quinn endpoint
    endpoint: Endpoint,

    /// Server configuration
    config: QuicServerConfig,

    /// Statistics
    stats: Arc<QuicInboundStats>,

    /// Shutdown flag
    shutdown: AtomicBool,
}

impl QuicInboundListener {
    /// Bind to the configured address and start listening
    ///
    /// # Arguments
    ///
    /// * `config` - QUIC server configuration
    ///
    /// # Errors
    ///
    /// Returns `TransportError` if:
    /// - Configuration validation fails
    /// - UDP socket binding fails
    /// - Endpoint creation fails
    pub async fn bind(config: &QuicServerConfig) -> Result<Self, TransportError> {
        // Build server configuration
        let server_config = build_server_config(config)?;

        // Bind UDP socket
        let socket = std::net::UdpSocket::bind(config.listen_addr).map_err(|e| {
            TransportError::connection_failed(
                config.listen_addr.to_string(),
                format!("failed to bind UDP socket: {e}"),
            )
        })?;

        socket.set_nonblocking(true).map_err(|e| {
            TransportError::socket_option("UDP_NONBLOCK", format!("failed to set non-blocking: {e}"))
        })?;

        // Create quinn endpoint with server config
        let runtime = Arc::new(quinn::TokioRuntime);
        let endpoint = Endpoint::new(
            quinn::EndpointConfig::default(),
            Some(server_config),
            socket,
            runtime,
        )
        .map_err(|e| {
            TransportError::quic_endpoint(format!("failed to create QUIC endpoint: {e}"))
        })?;

        tracing::info!(
            listen = %config.listen_addr,
            alpn = ?config.alpn_protocols,
            "QUIC inbound listener started"
        );

        Ok(Self {
            endpoint,
            config: config.clone(),
            stats: Arc::new(QuicInboundStats::new()),
            shutdown: AtomicBool::new(false),
        })
    }

    /// Accept a new QUIC stream from any connection
    ///
    /// This method waits for a new incoming connection, accepts it,
    /// and opens a bidirectional stream.
    ///
    /// Returns `None` if the listener has been shut down.
    pub async fn accept(&self) -> Option<QuicStream> {
        loop {
            if self.shutdown.load(Ordering::SeqCst) {
                return None;
            }

            // Accept incoming connection
            let incoming = self.endpoint.accept().await?;

            self.stats.connections_accepted.fetch_add(1, Ordering::Relaxed);
            self.stats.active_connections.fetch_add(1, Ordering::Relaxed);

            let remote = incoming.remote_address();

            tracing::debug!(
                remote = %remote,
                "Accepting QUIC connection"
            );

            // Complete the handshake
            let conn = match incoming.await {
                Ok(conn) => conn,
                Err(e) => {
                    self.stats.active_connections.fetch_sub(1, Ordering::Relaxed);
                    self.stats.handshake_errors.fetch_add(1, Ordering::Relaxed);
                    tracing::warn!(
                        remote = %remote,
                        error = %e,
                        "QUIC handshake failed"
                    );
                    continue; // Try next connection
                }
            };

            let conn = Arc::new(conn);

            // Accept a bidirectional stream
            match conn.accept_bi().await {
                Ok((send, recv)) => {
                    self.stats.streams_accepted.fetch_add(1, Ordering::Relaxed);

                    tracing::debug!(
                        remote = %remote,
                        stable_id = conn.stable_id(),
                        "QUIC stream accepted"
                    );

                    return Some(QuicStream::new(send, recv, conn));
                }
                Err(e) => {
                    self.stats.active_connections.fetch_sub(1, Ordering::Relaxed);
                    self.stats.stream_errors.fetch_add(1, Ordering::Relaxed);
                    tracing::warn!(
                        remote = %remote,
                        error = %e,
                        "Failed to accept QUIC stream"
                    );
                    continue; // Try next connection
                }
            }
        }
    }

    /// Accept a new QUIC connection (returning the connection itself)
    ///
    /// Use this when you need to handle multiple streams per connection.
    ///
    /// Returns `None` if the listener has been shut down.
    pub async fn accept_connection(&self) -> Option<QuicConnection> {
        loop {
            if self.shutdown.load(Ordering::SeqCst) {
                return None;
            }

            let incoming = self.endpoint.accept().await?;

            self.stats.connections_accepted.fetch_add(1, Ordering::Relaxed);
            self.stats.active_connections.fetch_add(1, Ordering::Relaxed);

            let remote = incoming.remote_address();

            let conn = match incoming.await {
                Ok(conn) => conn,
                Err(e) => {
                    self.stats.active_connections.fetch_sub(1, Ordering::Relaxed);
                    self.stats.handshake_errors.fetch_add(1, Ordering::Relaxed);
                    tracing::warn!(
                        remote = %remote,
                        error = %e,
                        "QUIC handshake failed"
                    );
                    continue; // Try next connection
                }
            };

            return Some(QuicConnection {
                connection: Arc::new(conn),
                stats: Arc::clone(&self.stats),
            });
        }
    }

    /// Get the local address the listener is bound to
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.endpoint.local_addr()
    }

    /// Get the configured listen address
    #[must_use]
    pub fn listen_addr(&self) -> SocketAddr {
        self.config.listen_addr
    }

    /// Get listener statistics
    #[must_use]
    pub fn stats(&self) -> &QuicInboundStats {
        &self.stats
    }

    /// Get a snapshot of statistics
    #[must_use]
    pub fn stats_snapshot(&self) -> QuicInboundStatsSnapshot {
        self.stats.snapshot()
    }

    /// Check if the listener is active
    #[must_use]
    pub fn is_active(&self) -> bool {
        !self.shutdown.load(Ordering::SeqCst)
    }

    /// Graceful shutdown
    ///
    /// This stops accepting new connections and closes existing ones.
    pub fn shutdown(&self) {
        tracing::info!(listen = %self.config.listen_addr, "Shutting down QUIC listener");
        self.shutdown.store(true, Ordering::SeqCst);
        self.endpoint.close(VarInt::from_u32(0), b"shutdown");
    }

    /// Wait for all connections to close
    pub async fn wait_idle(&self) {
        self.endpoint.wait_idle().await;
    }
}

impl std::fmt::Debug for QuicInboundListener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicInboundListener")
            .field("listen_addr", &self.config.listen_addr)
            .field("alpn", &self.config.alpn_protocols)
            .field("active", &self.is_active())
            .finish()
    }
}

/// QUIC connection wrapper for multi-stream handling
///
/// This struct wraps a QUIC connection and provides methods for
/// accepting multiple bidirectional streams from a single connection.
pub struct QuicConnection {
    /// The underlying QUIC connection
    connection: Arc<Connection>,

    /// Reference to listener stats
    stats: Arc<QuicInboundStats>,
}

impl QuicConnection {
    /// Get the remote address of the connection
    #[must_use]
    pub fn remote_address(&self) -> SocketAddr {
        self.connection.remote_address()
    }

    /// Get the connection's stable ID
    #[must_use]
    pub fn stable_id(&self) -> usize {
        self.connection.stable_id()
    }

    /// Check if the connection is still open
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.connection.close_reason().is_some()
    }

    /// Accept a bidirectional stream from this connection
    ///
    /// Returns `None` if the connection is closed.
    pub async fn accept_bi(&self) -> Option<QuicStream> {
        match self.connection.accept_bi().await {
            Ok((send, recv)) => {
                self.stats.streams_accepted.fetch_add(1, Ordering::Relaxed);
                Some(QuicStream::new(send, recv, Arc::clone(&self.connection)))
            }
            Err(e) => {
                self.stats.stream_errors.fetch_add(1, Ordering::Relaxed);
                tracing::debug!(
                    stable_id = self.stable_id(),
                    error = %e,
                    "Failed to accept bidirectional stream"
                );
                None
            }
        }
    }

    /// Open a bidirectional stream on this connection
    pub async fn open_bi(&self) -> Result<QuicStream, TransportError> {
        let (send, recv) = self.connection.open_bi().await.map_err(|e| {
            TransportError::QuicStreamError(format!("failed to open bidirectional stream: {e}"))
        })?;
        Ok(QuicStream::new(send, recv, Arc::clone(&self.connection)))
    }

    /// Close the connection gracefully
    pub fn close(&self, error_code: VarInt, reason: &[u8]) {
        self.connection.close(error_code, reason);
        self.stats.active_connections.fetch_sub(1, Ordering::Relaxed);
    }

    /// Get connection statistics
    #[must_use]
    pub fn conn_stats(&self) -> quinn::ConnectionStats {
        self.connection.stats()
    }
}

impl Drop for QuicConnection {
    fn drop(&mut self) {
        // Decrement active connections if the connection is being dropped
        // without explicit close
        if self.connection.close_reason().is_none() {
            self.stats.active_connections.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

impl std::fmt::Debug for QuicConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicConnection")
            .field("remote_address", &self.remote_address())
            .field("stable_id", &self.stable_id())
            .field("is_closed", &self.is_closed())
            .finish()
    }
}

/// Statistics for the QUIC inbound listener
#[derive(Debug)]
pub struct QuicInboundStats {
    /// Total connections accepted
    pub connections_accepted: AtomicU64,

    /// Currently active connections
    pub active_connections: AtomicU64,

    /// Total streams accepted
    pub streams_accepted: AtomicU64,

    /// Handshake errors
    pub handshake_errors: AtomicU64,

    /// Stream errors
    pub stream_errors: AtomicU64,
}

impl QuicInboundStats {
    /// Create new empty stats
    #[must_use]
    pub fn new() -> Self {
        Self {
            connections_accepted: AtomicU64::new(0),
            active_connections: AtomicU64::new(0),
            streams_accepted: AtomicU64::new(0),
            handshake_errors: AtomicU64::new(0),
            stream_errors: AtomicU64::new(0),
        }
    }

    /// Get a snapshot of the statistics
    #[must_use]
    pub fn snapshot(&self) -> QuicInboundStatsSnapshot {
        QuicInboundStatsSnapshot {
            connections_accepted: self.connections_accepted.load(Ordering::Relaxed),
            active_connections: self.active_connections.load(Ordering::Relaxed),
            streams_accepted: self.streams_accepted.load(Ordering::Relaxed),
            handshake_errors: self.handshake_errors.load(Ordering::Relaxed),
            stream_errors: self.stream_errors.load(Ordering::Relaxed),
        }
    }
}

impl Default for QuicInboundStats {
    fn default() -> Self {
        Self::new()
    }
}

/// Snapshot of QUIC inbound statistics
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct QuicInboundStatsSnapshot {
    /// Total connections accepted
    pub connections_accepted: u64,

    /// Currently active connections
    pub active_connections: u64,

    /// Total streams accepted
    pub streams_accepted: u64,

    /// Handshake errors
    pub handshake_errors: u64,

    /// Stream errors
    pub stream_errors: u64,
}

/// RAII guard for tracking active QUIC connections
///
/// When this guard is dropped, it automatically decrements the active connection
/// counter in the associated stats.
#[derive(Debug)]
pub struct QuicConnectionGuard {
    stats: Arc<QuicInboundStats>,
}

impl QuicConnectionGuard {
    /// Create a new connection guard
    ///
    /// This increments the active connection counter.
    #[must_use]
    pub fn new(stats: Arc<QuicInboundStats>) -> Self {
        stats.active_connections.fetch_add(1, Ordering::Relaxed);
        Self { stats }
    }

    /// Get a reference to the associated stats
    #[must_use]
    pub fn stats(&self) -> &QuicInboundStats {
        &self.stats
    }
}

impl Drop for QuicConnectionGuard {
    fn drop(&mut self) {
        self.stats.active_connections.fetch_sub(1, Ordering::Relaxed);
    }
}

impl Clone for QuicConnectionGuard {
    fn clone(&self) -> Self {
        self.stats.active_connections.fetch_add(1, Ordering::Relaxed);
        Self {
            stats: Arc::clone(&self.stats),
        }
    }
}

// ============================================================================
// Helper imports for server functionality
// ============================================================================

use rustls::pki_types::PrivateKeyDer;
use std::sync::atomic::AtomicBool;

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
    fn test_quic_client_config_new() {
        let config = QuicClientConfig::new("example.com");
        assert_eq!(config.server_name, "example.com");
        assert!(config.alpn_protocols.is_empty());
        assert!(!config.skip_verify);
        assert_eq!(config.idle_timeout_secs, DEFAULT_IDLE_TIMEOUT_SECS);
        assert_eq!(
            config.keep_alive_interval_secs,
            DEFAULT_KEEP_ALIVE_INTERVAL_SECS
        );
        assert_eq!(config.num_endpoints, DEFAULT_NUM_ENDPOINTS);
    }

    #[test]
    fn test_quic_client_config_default() {
        let config = QuicClientConfig::default();
        assert!(config.server_name.is_empty());
        assert!(config.alpn_protocols.is_empty());
        assert!(!config.skip_verify);
    }

    #[test]
    fn test_quic_client_config_builder() {
        let config = QuicClientConfig::new("example.com")
            .with_alpn(vec!["h3", "h3-29"])
            .with_idle_timeout(60)
            .with_keep_alive_interval(20)
            .with_num_endpoints(4)
            .insecure_skip_verify();

        assert_eq!(config.server_name, "example.com");
        assert_eq!(config.alpn_protocols, vec!["h3", "h3-29"]);
        assert!(config.skip_verify);
        assert_eq!(config.idle_timeout_secs, 60);
        assert_eq!(config.keep_alive_interval_secs, 20);
        assert_eq!(config.num_endpoints, 4);
    }

    #[test]
    fn test_quic_client_config_with_string_alpn() {
        let alpn = vec!["h3".to_string(), "h3-29".to_string()];
        let config = QuicClientConfig::new("example.com").with_alpn(alpn);
        assert_eq!(config.alpn_protocols, vec!["h3", "h3-29"]);
    }

    #[test]
    fn test_build_client_config_default() {
        init_crypto_provider();
        let config = QuicClientConfig::new("example.com");
        let result = build_client_config(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_build_client_config_with_alpn() {
        init_crypto_provider();
        let config = QuicClientConfig::new("example.com").with_alpn(vec!["h3"]);
        let result = build_client_config(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_build_client_config_insecure() {
        init_crypto_provider();
        let config = QuicClientConfig::new("localhost").insecure_skip_verify();
        let result = build_client_config(&config);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_quic_endpoint_pool_creation() {
        init_crypto_provider();
        let config = QuicClientConfig::new("example.com").with_num_endpoints(2);

        let pool = QuicEndpointPool::new(&config).await;
        assert!(pool.is_ok());

        let pool = pool.unwrap();
        assert_eq!(pool.num_endpoints(), 2);
    }

    #[tokio::test]
    async fn test_quic_endpoint_pool_auto_endpoints() {
        init_crypto_provider();
        let config = QuicClientConfig::new("example.com");

        let pool = QuicEndpointPool::new(&config).await;
        assert!(pool.is_ok());

        let pool = pool.unwrap();
        assert!(pool.num_endpoints() >= 1);
        assert!(pool.num_endpoints() <= MAX_ENDPOINTS);
    }

    #[tokio::test]
    async fn test_quic_endpoint_pool_max_endpoints() {
        init_crypto_provider();
        // Request more than max
        let config = QuicClientConfig::new("example.com").with_num_endpoints(100);

        let pool = QuicEndpointPool::new(&config).await;
        assert!(pool.is_ok());

        let pool = pool.unwrap();
        assert_eq!(pool.num_endpoints(), MAX_ENDPOINTS);
    }

    #[tokio::test]
    async fn test_quic_endpoint_pool_debug() {
        init_crypto_provider();
        let config = QuicClientConfig::new("example.com").with_num_endpoints(2);

        let pool = QuicEndpointPool::new(&config).await.unwrap();
        let debug = format!("{:?}", pool);
        assert!(debug.contains("QuicEndpointPool"));
        assert!(debug.contains("num_endpoints"));
        assert!(debug.contains("example.com"));
    }

    #[tokio::test]
    async fn test_quic_connect_unreachable() {
        init_crypto_provider();
        let config = QuicClientConfig::new("example.com")
            .with_num_endpoints(1)
            .insecure_skip_verify();

        let pool = QuicEndpointPool::new(&config).await.unwrap();

        // Try to connect to an unreachable address
        // Use a non-routable address that will fail quickly
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let result = pool.connect(addr, "localhost").await;

        // Connection should fail
        assert!(result.is_err());
    }

    #[tokio::test]
    #[ignore = "requires network access to Cloudflare"]
    async fn test_quic_connect_cloudflare() {
        init_crypto_provider();
        let config = QuicClientConfig::new("cloudflare-dns.com")
            .with_alpn(vec!["h3"])
            .with_num_endpoints(1);

        let pool = QuicEndpointPool::new(&config).await.unwrap();

        // Cloudflare DNS over QUIC
        let addr: SocketAddr = "1.1.1.1:443".parse().unwrap();
        let result = pool.connect(addr, "cloudflare-dns.com").await;

        assert!(result.is_ok());
        let stream = result.unwrap();
        assert!(!stream.is_closed());
    }

    #[test]
    fn test_insecure_verifier_schemes() {
        let verifier = InsecureServerCertVerifier;
        let schemes = verifier.supported_verify_schemes();
        assert!(!schemes.is_empty());
        assert!(schemes.contains(&SignatureScheme::ED25519));
        assert!(schemes.contains(&SignatureScheme::ECDSA_NISTP256_SHA256));
    }

    // ========================================================================
    // QUIC Server Tests
    // ========================================================================

    #[test]
    fn test_quic_server_config_new() {
        let addr: SocketAddr = "0.0.0.0:443".parse().unwrap();
        let config = QuicServerConfig::new(addr);
        assert_eq!(config.listen_addr, addr);
        assert!(config.tls_cert_pem.is_empty());
        assert!(config.tls_key_pem.is_empty());
        assert!(config.alpn_protocols.is_empty());
        assert_eq!(config.idle_timeout_secs, DEFAULT_SERVER_IDLE_TIMEOUT_SECS);
        assert_eq!(config.max_concurrent_streams, DEFAULT_MAX_CONCURRENT_STREAMS);
    }

    #[test]
    fn test_quic_server_config_default() {
        let config = QuicServerConfig::default();
        assert_eq!(config.listen_addr.port(), 443);
        assert!(config.tls_cert_pem.is_empty());
        assert!(config.tls_key_pem.is_empty());
    }

    #[test]
    fn test_quic_server_config_builder() {
        let addr: SocketAddr = "127.0.0.1:8443".parse().unwrap();
        let config = QuicServerConfig::new(addr)
            .with_alpn(vec!["h3", "h3-29"])
            .with_idle_timeout(120)
            .with_max_concurrent_streams(50);

        assert_eq!(config.listen_addr, addr);
        assert_eq!(config.alpn_protocols, vec!["h3", "h3-29"]);
        assert_eq!(config.idle_timeout_secs, 120);
        assert_eq!(config.max_concurrent_streams, 50);
    }

    #[test]
    fn test_quic_server_config_validate_no_cert() {
        let config = QuicServerConfig::default();
        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("certificate"));
    }

    #[test]
    fn test_quic_server_config_validate_no_key() {
        init_crypto_provider();
        // Create a self-signed cert for testing
        let cert_pem = generate_test_cert_pem();
        let config = QuicServerConfig::default()
            .with_cert_pem(cert_pem);
        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("key"));
    }

    #[test]
    fn test_load_certs_from_pem_empty() {
        let result = load_certs_from_pem(b"");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("no certificates"));
    }

    #[test]
    fn test_load_key_from_pem_empty() {
        let result = load_key_from_pem(b"");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("no private key"));
    }

    #[test]
    fn test_load_certs_from_pem_valid() {
        let pem = generate_test_cert_pem();
        let result = load_certs_from_pem(&pem);
        assert!(result.is_ok());
        assert!(!result.unwrap().is_empty());
    }

    #[test]
    fn test_load_key_from_pem_valid() {
        let pem = generate_test_key_pem();
        let result = load_key_from_pem(&pem);
        assert!(result.is_ok());
    }

    #[test]
    fn test_quic_inbound_stats_new() {
        let stats = QuicInboundStats::new();
        assert_eq!(stats.connections_accepted.load(Ordering::Relaxed), 0);
        assert_eq!(stats.active_connections.load(Ordering::Relaxed), 0);
        assert_eq!(stats.streams_accepted.load(Ordering::Relaxed), 0);
        assert_eq!(stats.handshake_errors.load(Ordering::Relaxed), 0);
        assert_eq!(stats.stream_errors.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_quic_inbound_stats_snapshot() {
        let stats = QuicInboundStats::new();
        stats.connections_accepted.fetch_add(10, Ordering::Relaxed);
        stats.active_connections.fetch_add(5, Ordering::Relaxed);
        stats.streams_accepted.fetch_add(20, Ordering::Relaxed);

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.connections_accepted, 10);
        assert_eq!(snapshot.active_connections, 5);
        assert_eq!(snapshot.streams_accepted, 20);
    }

    #[test]
    fn test_quic_inbound_stats_snapshot_serialization() {
        let snapshot = QuicInboundStatsSnapshot {
            connections_accepted: 100,
            active_connections: 5,
            streams_accepted: 200,
            handshake_errors: 2,
            stream_errors: 3,
        };

        let json = serde_json::to_string(&snapshot).unwrap();
        assert!(json.contains("100"));
        assert!(json.contains("200"));

        let deserialized: QuicInboundStatsSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.connections_accepted, 100);
        assert_eq!(deserialized.streams_accepted, 200);
    }

    #[test]
    fn test_quic_connection_guard_increment_on_create() {
        let stats = Arc::new(QuicInboundStats::new());
        assert_eq!(stats.active_connections.load(Ordering::Relaxed), 0);

        let _guard = QuicConnectionGuard::new(Arc::clone(&stats));
        assert_eq!(stats.active_connections.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_quic_connection_guard_decrement_on_drop() {
        let stats = Arc::new(QuicInboundStats::new());

        {
            let _guard = QuicConnectionGuard::new(Arc::clone(&stats));
            assert_eq!(stats.active_connections.load(Ordering::Relaxed), 1);
        }

        assert_eq!(stats.active_connections.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_quic_connection_guard_multiple() {
        let stats = Arc::new(QuicInboundStats::new());

        let guard1 = QuicConnectionGuard::new(Arc::clone(&stats));
        assert_eq!(stats.active_connections.load(Ordering::Relaxed), 1);

        let guard2 = QuicConnectionGuard::new(Arc::clone(&stats));
        assert_eq!(stats.active_connections.load(Ordering::Relaxed), 2);

        drop(guard1);
        assert_eq!(stats.active_connections.load(Ordering::Relaxed), 1);

        drop(guard2);
        assert_eq!(stats.active_connections.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_quic_connection_guard_clone() {
        let stats = Arc::new(QuicInboundStats::new());

        let guard1 = QuicConnectionGuard::new(Arc::clone(&stats));
        assert_eq!(stats.active_connections.load(Ordering::Relaxed), 1);

        let guard2 = guard1.clone();
        assert_eq!(stats.active_connections.load(Ordering::Relaxed), 2);

        drop(guard1);
        assert_eq!(stats.active_connections.load(Ordering::Relaxed), 1);

        drop(guard2);
        assert_eq!(stats.active_connections.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_quic_connection_guard_stats_access() {
        let stats = Arc::new(QuicInboundStats::new());
        stats.connections_accepted.fetch_add(10, Ordering::Relaxed);

        let guard = QuicConnectionGuard::new(Arc::clone(&stats));

        assert_eq!(guard.stats().connections_accepted.load(Ordering::Relaxed), 10);
        assert_eq!(guard.stats().active_connections.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn test_quic_server_bind_with_valid_config() {
        init_crypto_provider();

        let cert_pem = generate_test_cert_pem();
        let key_pem = generate_test_key_pem();

        let config = QuicServerConfig::new("127.0.0.1:0".parse().unwrap())
            .with_cert_pem(cert_pem)
            .with_key_pem(key_pem)
            .with_alpn(vec!["h3"]);

        let listener = QuicInboundListener::bind(&config).await;
        assert!(listener.is_ok());

        let listener = listener.unwrap();
        assert!(listener.is_active());

        let local_addr = listener.local_addr().unwrap();
        assert!(local_addr.port() > 0);

        listener.shutdown();
        assert!(!listener.is_active());
    }

    #[tokio::test]
    async fn test_quic_server_debug() {
        init_crypto_provider();

        let cert_pem = generate_test_cert_pem();
        let key_pem = generate_test_key_pem();

        let config = QuicServerConfig::new("127.0.0.1:0".parse().unwrap())
            .with_cert_pem(cert_pem)
            .with_key_pem(key_pem)
            .with_alpn(vec!["test-proto"]);

        let listener = QuicInboundListener::bind(&config).await.unwrap();
        let debug_str = format!("{:?}", listener);
        assert!(debug_str.contains("QuicInboundListener"));
        assert!(debug_str.contains("127.0.0.1"));
        assert!(debug_str.contains("test-proto"));
    }

    #[tokio::test]
    async fn test_quic_server_stats_snapshot() {
        init_crypto_provider();

        let cert_pem = generate_test_cert_pem();
        let key_pem = generate_test_key_pem();

        let config = QuicServerConfig::new("127.0.0.1:0".parse().unwrap())
            .with_cert_pem(cert_pem)
            .with_key_pem(key_pem);

        let listener = QuicInboundListener::bind(&config).await.unwrap();
        let stats = listener.stats_snapshot();

        assert_eq!(stats.connections_accepted, 0);
        assert_eq!(stats.active_connections, 0);
        assert_eq!(stats.streams_accepted, 0);
    }

    #[test]
    fn test_build_server_config_with_valid_config() {
        init_crypto_provider();

        let cert_pem = generate_test_cert_pem();
        let key_pem = generate_test_key_pem();

        let config = QuicServerConfig::new("127.0.0.1:443".parse().unwrap())
            .with_cert_pem(cert_pem)
            .with_key_pem(key_pem)
            .with_alpn(vec!["h3"])
            .with_idle_timeout(60)
            .with_max_concurrent_streams(100);

        let result = build_server_config(&config);
        assert!(result.is_ok());
    }

    // Helper function to generate a self-signed certificate PEM for testing
    // This uses a valid EC P-256 key pair that rustls supports
    fn generate_test_cert_pem() -> Vec<u8> {
        // Valid self-signed certificate with EC P-256 key
        // Generated with: openssl ecparam -genkey -name prime256v1 -noout -out key.pem
        //                 openssl req -new -x509 -key key.pem -out cert.pem -days 3650 -subj "/CN=test"
        b"-----BEGIN CERTIFICATE-----
MIIBdDCCARmgAwIBAgIUD03a2Olf9h4dAKq4JZ0wvvdyVy8wCgYIKoZIzj0EAwIw
DzENMAsGA1UEAwwEdGVzdDAeFw0yNjAxMjQwMzU2MTJaFw0zNjAxMjIwMzU2MTJa
MA8xDTALBgNVBAMMBHRlc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARqAX7m
glRxBt1WVkeu6Xv1DZgQ6auVD6DXsPR4mV5qERVBux0V17EH8+u2f8G7/g5q+kjt
zegGuc0ES6Am/yh1o1MwUTAdBgNVHQ4EFgQUHSw86X0pO16Fimg2rwu9TbSKuE0w
HwYDVR0jBBgwFoAUHSw86X0pO16Fimg2rwu9TbSKuE0wDwYDVR0TAQH/BAUwAwEB
/zAKBggqhkjOPQQDAgNJADBGAiEAlBG5Mg/0+lwJG6NXRBaYyAwPrXmfsdn4Xu4M
DlV6WPACIQDfEQFhvHY+GwxJtD4VwLr9wLomdF8bx8nyE69ttA3QVg==
-----END CERTIFICATE-----
".to_vec()
    }

    // Helper function to generate a private key PEM for testing
    fn generate_test_key_pem() -> Vec<u8> {
        // EC P-256 private key matching the certificate above
        b"-----BEGIN EC PRIVATE KEY-----
MHcCAQEEINqlpC+I/zCwt3mMtoL76ZRT/gjmCAQ2K0RoeR0RpTJmoAoGCCqGSM49
AwEHoUQDQgAEagF+5oJUcQbdVlZHrul79Q2YEOmrlQ+g17D0eJleahEVQbsdFdex
B/Prtn/Bu/4OavpI7c3oBrnNBEugJv8odQ==
-----END EC PRIVATE KEY-----
".to_vec()
    }
}
