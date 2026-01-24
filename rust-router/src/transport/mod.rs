//! Transport layer abstraction for rust-router
//!
//! This module provides a unified transport layer for establishing connections
//! over TCP, TLS, and WebSocket protocols. The transport layer is designed to
//! work with the VLESS protocol implementation, providing a clean abstraction
//! over different transport types.
//!
//! # Architecture
//!
//! ```text
//! TransportConfig
//!       |
//!       v
//!   Transport::connect()
//!       |
//!       v
//!   TransportStream (enum)
//!       |
//!       +-> TcpStream (plain TCP)
//!       +-> TlsStream<TcpStream> (TLS over TCP)
//!       +-> WebSocketStream (WebSocket, optionally over TLS)
//! ```
//!
//! # Features
//!
//! - **TCP Transport**: Plain TCP connections with keepalive and nodelay options
//! - **TLS Transport**: Secure connections using tokio-rustls with SNI support
//! - **WebSocket Transport**: WebSocket protocol with custom path and headers
//!
//! # Example
//!
//! ```no_run
//! use rust_router::transport::{TransportConfig, TlsConfig, connect};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Plain TCP connection
//! let config = TransportConfig::tcp("example.com", 443);
//! let stream = connect(&config).await?;
//!
//! // TLS connection with SNI
//! let config = TransportConfig::tcp("example.com", 443)
//!     .with_tls(TlsConfig::new("example.com"));
//! let stream = connect(&config).await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Transport Types
//!
//! The module supports three transport types:
//!
//! | Type | Feature Flag | Use Case |
//! |------|--------------|----------|
//! | TCP | (always) | Plain connections, internal services |
//! | TLS | `transport-tls` | Encrypted connections to servers |
//! | WebSocket | `transport-ws` | WebSocket-based tunneling |
//!
//! # Security Considerations
//!
//! - TLS connections use Mozilla's root certificates via `webpki-roots`
//! - Certificate verification can be disabled for testing (not recommended)
//! - SNI is required for proper TLS server identification

mod error;
mod tcp;

#[cfg(feature = "transport-tls")]
mod tls;

#[cfg(feature = "transport-ws")]
mod websocket;

#[cfg(feature = "transport-quic")]
pub mod quic;

// Re-exports
pub use error::TransportError;
pub use tcp::TcpTransport;

#[cfg(feature = "transport-tls")]
pub use tls::TlsTransport;

#[cfg(feature = "transport-ws")]
pub use websocket::WebSocketTransport;

#[cfg(feature = "transport-quic")]
pub use quic::{
    // Client types
    QuicClientConfig, QuicEndpointPool, QuicStream,
    // Server types
    QuicServerConfig, QuicInboundListener, QuicConnection, QuicConnectionGuard,
    QuicInboundStats, QuicInboundStatsSnapshot,
    // Helper functions
    build_server_config, load_certs_from_pem, load_key_from_pem,
};

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

#[cfg(feature = "transport-tls")]
use tokio_rustls::client::TlsStream;

/// Configuration for establishing a transport connection
///
/// This struct holds all the information needed to connect to a remote server,
/// including optional TLS, WebSocket, and QUIC configurations.
///
/// # Example
///
/// ```
/// use rust_router::transport::{TransportConfig, TlsConfig, WebSocketConfig};
///
/// // Plain TCP
/// let tcp = TransportConfig::tcp("example.com", 80);
///
/// // TCP with TLS
/// let tls = TransportConfig::tcp("example.com", 443)
///     .with_tls(TlsConfig::new("example.com"));
///
/// // WebSocket with TLS
/// let wss = TransportConfig::tcp("example.com", 443)
///     .with_tls(TlsConfig::new("example.com"))
///     .with_websocket(WebSocketConfig::new("/ws"));
/// ```
#[derive(Debug, Clone)]
pub struct TransportConfig {
    /// Remote host (hostname or IP address)
    pub address: String,

    /// Remote port
    pub port: u16,

    /// TLS configuration (None for plain TCP)
    pub tls: Option<TlsConfig>,

    /// WebSocket configuration (None for raw TCP/TLS)
    pub websocket: Option<WebSocketConfig>,

    /// QUIC configuration (None for TCP-based transports)
    #[cfg(feature = "transport-quic")]
    pub quic: Option<QuicClientConfig>,

    /// Connection timeout
    pub connect_timeout: Duration,

    /// Enable TCP keepalive
    pub tcp_keepalive: bool,

    /// Enable TCP_NODELAY (disable Nagle's algorithm)
    pub tcp_nodelay: bool,
}

impl TransportConfig {
    /// Create a new TCP transport configuration
    ///
    /// # Arguments
    ///
    /// * `address` - Hostname or IP address
    /// * `port` - Port number
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::transport::TransportConfig;
    ///
    /// let config = TransportConfig::tcp("example.com", 443);
    /// assert_eq!(config.address, "example.com");
    /// assert_eq!(config.port, 443);
    /// assert!(config.tls.is_none());
    /// ```
    #[must_use]
    pub fn tcp(address: impl Into<String>, port: u16) -> Self {
        Self {
            address: address.into(),
            port,
            tls: None,
            websocket: None,
            #[cfg(feature = "transport-quic")]
            quic: None,
            connect_timeout: Duration::from_secs(30),
            tcp_keepalive: true,
            tcp_nodelay: true,
        }
    }

    /// Add TLS configuration
    ///
    /// # Arguments
    ///
    /// * `tls` - TLS configuration including server name and ALPN
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::transport::{TransportConfig, TlsConfig};
    ///
    /// let config = TransportConfig::tcp("example.com", 443)
    ///     .with_tls(TlsConfig::new("example.com"));
    /// assert!(config.tls.is_some());
    /// ```
    #[must_use]
    pub fn with_tls(mut self, tls: TlsConfig) -> Self {
        self.tls = Some(tls);
        self
    }

    /// Add WebSocket configuration
    ///
    /// # Arguments
    ///
    /// * `websocket` - WebSocket configuration including path and headers
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::transport::{TransportConfig, WebSocketConfig};
    ///
    /// let config = TransportConfig::tcp("example.com", 80)
    ///     .with_websocket(WebSocketConfig::new("/ws"));
    /// assert!(config.websocket.is_some());
    /// ```
    #[must_use]
    pub fn with_websocket(mut self, websocket: WebSocketConfig) -> Self {
        self.websocket = Some(websocket);
        self
    }

    /// Add QUIC configuration
    ///
    /// When QUIC is configured, it takes priority over other transport types.
    /// QUIC provides encrypted, multiplexed connections over UDP.
    ///
    /// # Arguments
    ///
    /// * `quic` - QUIC client configuration
    ///
    /// # Example
    ///
    /// ```ignore
    /// use rust_router::transport::{TransportConfig, QuicClientConfig};
    ///
    /// let config = TransportConfig::tcp("example.com", 443)
    ///     .with_quic(QuicClientConfig::new("example.com").with_alpn(vec!["h3"]));
    /// assert!(config.is_quic());
    /// ```
    #[cfg(feature = "transport-quic")]
    #[must_use]
    pub fn with_quic(mut self, quic: QuicClientConfig) -> Self {
        self.quic = Some(quic);
        self
    }

    /// Set connection timeout
    ///
    /// # Arguments
    ///
    /// * `timeout` - Connection timeout duration
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Set TCP keepalive option
    #[must_use]
    pub fn with_keepalive(mut self, enabled: bool) -> Self {
        self.tcp_keepalive = enabled;
        self
    }

    /// Set TCP_NODELAY option
    #[must_use]
    pub fn with_nodelay(mut self, enabled: bool) -> Self {
        self.tcp_nodelay = enabled;
        self
    }

    /// Check if this configuration uses TLS
    #[must_use]
    pub fn is_tls(&self) -> bool {
        self.tls.is_some()
    }

    /// Check if this configuration uses WebSocket
    #[must_use]
    pub fn is_websocket(&self) -> bool {
        self.websocket.is_some()
    }

    /// Check if this configuration uses QUIC
    #[cfg(feature = "transport-quic")]
    #[must_use]
    pub fn is_quic(&self) -> bool {
        self.quic.is_some()
    }

    /// Get the full address string (host:port)
    #[must_use]
    pub fn address_string(&self) -> String {
        format!("{}:{}", self.address, self.port)
    }
}

/// TLS configuration for transport connections
///
/// # Example
///
/// ```
/// use rust_router::transport::TlsConfig;
///
/// let config = TlsConfig::new("example.com")
///     .with_alpn(vec!["h2", "http/1.1"]);
/// ```
#[derive(Debug, Clone)]
pub struct TlsConfig {
    /// Server name for SNI (Server Name Indication)
    pub server_name: String,

    /// ALPN protocols (e.g., ["h2", "http/1.1"])
    pub alpn: Vec<String>,

    /// Skip certificate verification (INSECURE - for testing only)
    pub skip_verify: bool,
}

impl TlsConfig {
    /// Create a new TLS configuration with server name
    ///
    /// # Arguments
    ///
    /// * `server_name` - Server name for SNI
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::transport::TlsConfig;
    ///
    /// let config = TlsConfig::new("example.com");
    /// assert_eq!(config.server_name, "example.com");
    /// assert!(config.alpn.is_empty());
    /// assert!(!config.skip_verify);
    /// ```
    #[must_use]
    pub fn new(server_name: impl Into<String>) -> Self {
        Self {
            server_name: server_name.into(),
            alpn: Vec::new(),
            skip_verify: false,
        }
    }

    /// Set ALPN protocols
    ///
    /// # Arguments
    ///
    /// * `protocols` - List of ALPN protocol names
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::transport::TlsConfig;
    ///
    /// let config = TlsConfig::new("example.com")
    ///     .with_alpn(vec!["h2", "http/1.1"]);
    /// assert_eq!(config.alpn, vec!["h2", "http/1.1"]);
    /// ```
    #[must_use]
    pub fn with_alpn<I, S>(mut self, protocols: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.alpn = protocols.into_iter().map(Into::into).collect();
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
    /// use rust_router::transport::TlsConfig;
    ///
    /// // For testing only!
    /// let config = TlsConfig::new("localhost")
    ///     .insecure_skip_verify();
    /// assert!(config.skip_verify);
    /// ```
    #[must_use]
    pub fn insecure_skip_verify(mut self) -> Self {
        self.skip_verify = true;
        self
    }
}

/// WebSocket configuration for transport connections
///
/// # Example
///
/// ```
/// use rust_router::transport::WebSocketConfig;
///
/// let config = WebSocketConfig::new("/ws")
///     .with_host("example.com")
///     .with_header("X-Custom-Header", "value");
/// ```
#[derive(Debug, Clone)]
pub struct WebSocketConfig {
    /// WebSocket path (e.g., "/ws", "/tunnel")
    pub path: String,

    /// Host header override (if different from connection address)
    pub host: Option<String>,

    /// Additional HTTP headers for the WebSocket handshake
    pub headers: Vec<(String, String)>,
}

impl WebSocketConfig {
    /// Create a new WebSocket configuration with path
    ///
    /// # Arguments
    ///
    /// * `path` - WebSocket endpoint path
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::transport::WebSocketConfig;
    ///
    /// let config = WebSocketConfig::new("/ws");
    /// assert_eq!(config.path, "/ws");
    /// assert!(config.host.is_none());
    /// assert!(config.headers.is_empty());
    /// ```
    #[must_use]
    pub fn new(path: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            host: None,
            headers: Vec::new(),
        }
    }

    /// Set the Host header override
    ///
    /// # Arguments
    ///
    /// * `host` - Host header value
    #[must_use]
    pub fn with_host(mut self, host: impl Into<String>) -> Self {
        self.host = Some(host.into());
        self
    }

    /// Add a custom header
    ///
    /// # Arguments
    ///
    /// * `name` - Header name
    /// * `value` - Header value
    #[must_use]
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// Add multiple headers at once
    #[must_use]
    pub fn with_headers<I, N, V>(mut self, headers: I) -> Self
    where
        I: IntoIterator<Item = (N, V)>,
        N: Into<String>,
        V: Into<String>,
    {
        self.headers
            .extend(headers.into_iter().map(|(n, v)| (n.into(), v.into())));
        self
    }
}

/// Unified transport stream that wraps different transport types
///
/// This enum provides a unified interface for reading and writing data
/// regardless of the underlying transport (TCP, TLS, WebSocket).
///
/// # Implementation
///
/// `TransportStream` implements both `AsyncRead` and `AsyncWrite` by
/// delegating to the underlying stream type.
pub enum TransportStream {
    /// Plain TCP connection
    Tcp(TcpStream),

    /// TLS over TCP
    #[cfg(feature = "transport-tls")]
    Tls(TlsStream<TcpStream>),

    /// WebSocket over TCP or TLS
    #[cfg(feature = "transport-ws")]
    WebSocket(websocket::WebSocketWrapper),

    /// QUIC bidirectional stream
    #[cfg(feature = "transport-quic")]
    Quic(QuicStream),
}

impl std::fmt::Debug for TransportStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tcp(s) => f
                .debug_struct("TransportStream::Tcp")
                .field("local_addr", &s.local_addr().ok())
                .field("peer_addr", &s.peer_addr().ok())
                .finish(),
            #[cfg(feature = "transport-tls")]
            Self::Tls(_s) => f
                .debug_struct("TransportStream::Tls")
                .field("inner", &"TlsStream<TcpStream>")
                .finish(),
            #[cfg(feature = "transport-ws")]
            Self::WebSocket(_) => f
                .debug_struct("TransportStream::WebSocket")
                .field("inner", &"WebSocketWrapper")
                .finish(),
            #[cfg(feature = "transport-quic")]
            Self::Quic(s) => f
                .debug_struct("TransportStream::Quic")
                .field("remote_address", &s.remote_address())
                .field("stable_id", &s.stable_id())
                .finish(),
        }
    }
}

impl AsyncRead for TransportStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_read(cx, buf),
            #[cfg(feature = "transport-tls")]
            Self::Tls(stream) => Pin::new(stream).poll_read(cx, buf),
            #[cfg(feature = "transport-ws")]
            Self::WebSocket(stream) => Pin::new(stream).poll_read(cx, buf),
            #[cfg(feature = "transport-quic")]
            Self::Quic(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for TransportStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_write(cx, buf),
            #[cfg(feature = "transport-tls")]
            Self::Tls(stream) => Pin::new(stream).poll_write(cx, buf),
            #[cfg(feature = "transport-ws")]
            Self::WebSocket(stream) => Pin::new(stream).poll_write(cx, buf),
            #[cfg(feature = "transport-quic")]
            Self::Quic(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_flush(cx),
            #[cfg(feature = "transport-tls")]
            Self::Tls(stream) => Pin::new(stream).poll_flush(cx),
            #[cfg(feature = "transport-ws")]
            Self::WebSocket(stream) => Pin::new(stream).poll_flush(cx),
            #[cfg(feature = "transport-quic")]
            Self::Quic(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_shutdown(cx),
            #[cfg(feature = "transport-tls")]
            Self::Tls(stream) => Pin::new(stream).poll_shutdown(cx),
            #[cfg(feature = "transport-ws")]
            Self::WebSocket(stream) => Pin::new(stream).poll_shutdown(cx),
            #[cfg(feature = "transport-quic")]
            Self::Quic(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

/// Transport trait for establishing connections
///
/// This trait defines the interface for different transport implementations.
/// Each implementation handles connection establishment for its specific
/// transport type (TCP, TLS, WebSocket).
#[async_trait]
pub trait Transport: Send + Sync {
    /// Connect to a remote server using the given configuration
    ///
    /// # Arguments
    ///
    /// * `config` - Transport configuration specifying address, TLS, etc.
    ///
    /// # Errors
    ///
    /// Returns `TransportError` if the connection fails.
    async fn connect(&self, config: &TransportConfig) -> Result<TransportStream, TransportError>;
}

/// Connect to a remote server using the appropriate transport
///
/// This function automatically selects the correct transport based on
/// the configuration. The priority order is: QUIC > WebSocket > TLS > TCP.
///
/// # Arguments
///
/// * `config` - Transport configuration
///
/// # Errors
///
/// Returns `TransportError` if the connection fails.
///
/// # Example
///
/// ```no_run
/// use rust_router::transport::{TransportConfig, TlsConfig, connect};
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Plain TCP
/// let stream = connect(&TransportConfig::tcp("example.com", 80)).await?;
///
/// // TLS
/// let config = TransportConfig::tcp("example.com", 443)
///     .with_tls(TlsConfig::new("example.com"));
/// let stream = connect(&config).await?;
/// # Ok(())
/// # }
/// ```
pub async fn connect(config: &TransportConfig) -> Result<TransportStream, TransportError> {
    // Priority: QUIC > WebSocket > TLS > TCP
    #[cfg(feature = "transport-quic")]
    if let Some(ref quic_config) = config.quic {
        return connect_quic(config, quic_config).await;
    }

    #[cfg(feature = "transport-ws")]
    if config.websocket.is_some() {
        return WebSocketTransport.connect(config).await;
    }

    #[cfg(feature = "transport-tls")]
    if config.tls.is_some() {
        return TlsTransport.connect(config).await;
    }

    TcpTransport.connect(config).await
}

/// Connect using QUIC transport
///
/// This function establishes a QUIC connection and opens a bidirectional stream.
#[cfg(feature = "transport-quic")]
async fn connect_quic(
    config: &TransportConfig,
    quic_config: &QuicClientConfig,
) -> Result<TransportStream, TransportError> {
    use std::net::ToSocketAddrs;

    // Resolve the address
    let addr_str = format!("{}:{}", config.address, config.port);
    let addr = addr_str
        .to_socket_addrs()
        .map_err(|e| TransportError::dns_failed(&addr_str, e.to_string()))?
        .next()
        .ok_or_else(|| TransportError::dns_failed(&addr_str, "no addresses returned"))?;

    // Create endpoint pool (single endpoint for simple connect)
    let pool_config = QuicClientConfig {
        server_name: quic_config.server_name.clone(),
        alpn_protocols: quic_config.alpn_protocols.clone(),
        skip_verify: quic_config.skip_verify,
        idle_timeout_secs: quic_config.idle_timeout_secs,
        keep_alive_interval_secs: quic_config.keep_alive_interval_secs,
        num_endpoints: 1, // Use single endpoint for simple connect
    };

    let pool = QuicEndpointPool::new(&pool_config).await?;
    let stream = pool.connect(addr, &quic_config.server_name).await?;

    tracing::debug!(
        addr = %addr,
        server_name = %quic_config.server_name,
        "QUIC transport connection established"
    );

    Ok(TransportStream::Quic(stream))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transport_config_tcp() {
        let config = TransportConfig::tcp("example.com", 443);
        assert_eq!(config.address, "example.com");
        assert_eq!(config.port, 443);
        assert!(config.tls.is_none());
        assert!(config.websocket.is_none());
        assert!(!config.is_tls());
        assert!(!config.is_websocket());
        assert_eq!(config.address_string(), "example.com:443");
    }

    #[test]
    fn test_transport_config_with_tls() {
        let config = TransportConfig::tcp("example.com", 443).with_tls(TlsConfig::new("example.com"));
        assert!(config.is_tls());
        assert!(!config.is_websocket());
        assert_eq!(config.tls.as_ref().unwrap().server_name, "example.com");
    }

    #[test]
    fn test_transport_config_with_websocket() {
        let config = TransportConfig::tcp("example.com", 80).with_websocket(WebSocketConfig::new("/ws"));
        assert!(!config.is_tls());
        assert!(config.is_websocket());
        assert_eq!(config.websocket.as_ref().unwrap().path, "/ws");
    }

    #[test]
    fn test_transport_config_full() {
        let config = TransportConfig::tcp("example.com", 443)
            .with_tls(TlsConfig::new("example.com").with_alpn(vec!["h2"]))
            .with_websocket(
                WebSocketConfig::new("/tunnel")
                    .with_host("cdn.example.com")
                    .with_header("X-Auth", "token"),
            )
            .with_timeout(Duration::from_secs(60))
            .with_keepalive(false)
            .with_nodelay(false);

        assert!(config.is_tls());
        assert!(config.is_websocket());
        assert_eq!(config.connect_timeout, Duration::from_secs(60));
        assert!(!config.tcp_keepalive);
        assert!(!config.tcp_nodelay);

        let tls = config.tls.as_ref().unwrap();
        assert_eq!(tls.alpn, vec!["h2"]);

        let ws = config.websocket.as_ref().unwrap();
        assert_eq!(ws.path, "/tunnel");
        assert_eq!(ws.host, Some("cdn.example.com".to_string()));
        assert_eq!(ws.headers.len(), 1);
    }

    #[test]
    fn test_tls_config() {
        let config = TlsConfig::new("example.com")
            .with_alpn(vec!["h2", "http/1.1"])
            .insecure_skip_verify();

        assert_eq!(config.server_name, "example.com");
        assert_eq!(config.alpn, vec!["h2", "http/1.1"]);
        assert!(config.skip_verify);
    }

    #[test]
    fn test_websocket_config() {
        let config = WebSocketConfig::new("/ws")
            .with_host("cdn.example.com")
            .with_header("X-Auth", "token")
            .with_headers(vec![("X-Custom", "value"), ("X-Another", "data")]);

        assert_eq!(config.path, "/ws");
        assert_eq!(config.host, Some("cdn.example.com".to_string()));
        assert_eq!(config.headers.len(), 3);
        assert_eq!(config.headers[0], ("X-Auth".to_string(), "token".to_string()));
    }
}
