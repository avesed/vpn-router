//! WebSocket transport implementation using tokio-tungstenite
//!
//! This module provides a WebSocket transport for establishing WebSocket connections
//! that can be used for tunneling. It supports both plain WebSocket (ws://) and
//! secure WebSocket (wss://) connections.
//!
//! # Features
//!
//! - WebSocket over TCP (ws://)
//! - WebSocket over TLS (wss://)
//! - Custom path and headers
//! - `AsyncRead`/`AsyncWrite` wrapper for binary messages
//!
//! # Example
//!
//! ```no_run
//! use rust_router::transport::{TransportConfig, TlsConfig, WebSocketConfig, WebSocketTransport, Transport};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let transport = WebSocketTransport;
//!
//! // Plain WebSocket
//! let config = TransportConfig::tcp("example.com", 80)
//!     .with_websocket(WebSocketConfig::new("/ws"));
//!
//! // Secure WebSocket with TLS
//! let config = TransportConfig::tcp("example.com", 443)
//!     .with_tls(TlsConfig::new("example.com"))
//!     .with_websocket(WebSocketConfig::new("/ws"));
//!
//! let stream = transport.connect(&config).await?;
//! # Ok(())
//! # }
//! ```

use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use async_trait::async_trait;
use bytes::{Buf, BytesMut};
use futures::stream::Stream;
use futures::sink::Sink;
use socket2::{SockRef, TcpKeepalive};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_tungstenite::tungstenite::http::Request;
use tokio_tungstenite::tungstenite::protocol::Message;
use tokio_tungstenite::WebSocketStream;

use super::{TlsConfig, Transport, TransportConfig, TransportError, TransportStream};

/// Type alias for WebSocket stream over TLS TCP
type WsStreamTls = WebSocketStream<tokio_rustls::client::TlsStream<TcpStream>>;

/// Type alias for WebSocket stream over plain TCP
type WsStreamPlain = WebSocketStream<TcpStream>;

/// Enum to hold either plain or TLS WebSocket stream
enum WsStreamInner {
    Plain(WsStreamPlain),
    Tls(WsStreamTls),
}

/// WebSocket transport for WebSocket-based tunneling
///
/// This transport establishes WebSocket connections with optional TLS.
/// The resulting stream implements `AsyncRead` and `AsyncWrite` for
/// transparent use with tunnel protocols.
///
/// # Thread Safety
///
/// `WebSocketTransport` is `Send + Sync` and can be shared across threads.
#[derive(Debug, Clone, Copy, Default)]
pub struct WebSocketTransport;

impl WebSocketTransport {
    /// Create a new WebSocket transport
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
    fn create_tls_config(
        tls_config: &TlsConfig,
    ) -> Result<rustls::ClientConfig, TransportError> {
        use rustls::client::danger::{
            HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
        };
        use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
        use rustls::{DigitallySignedStruct, Error as RustlsError, SignatureScheme};

        /// Insecure certificate verifier for testing
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

        let config = if tls_config.skip_verify {
            rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(InsecureServerCertVerifier))
                .with_no_client_auth()
        } else {
            let root_store =
                rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

            rustls::ClientConfig::builder()
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

    /// Build WebSocket request with custom headers
    fn build_request(config: &TransportConfig) -> Result<Request<()>, TransportError> {
        let ws_config = config
            .websocket
            .as_ref()
            .ok_or_else(|| TransportError::websocket_protocol("WebSocket configuration required"))?;

        // Determine scheme
        let scheme = if config.tls.is_some() { "wss" } else { "ws" };

        // Build URL
        let host = ws_config.host.as_ref().unwrap_or(&config.address);
        let url = format!("{scheme}://{host}:{}{}", config.port, ws_config.path);

        // Build request
        let mut builder = Request::builder()
            .uri(&url)
            .header("Host", host)
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Version", "13")
            .header(
                "Sec-WebSocket-Key",
                tokio_tungstenite::tungstenite::handshake::client::generate_key(),
            );

        // Add custom headers
        for (name, value) in &ws_config.headers {
            builder = builder.header(name.as_str(), value.as_str());
        }

        builder
            .body(())
            .map_err(|e| TransportError::invalid_websocket_url(e.to_string()))
    }

    /// Connect to WebSocket server with TLS at specific address
    async fn connect_tls(
        addr: SocketAddr,
        config: &TransportConfig,
        tls_config: &TlsConfig,
        request: Request<()>,
    ) -> Result<WsStreamInner, TransportError> {
        let connect_timeout = config.connect_timeout;

        // Establish TCP connection
        let tcp_connect = TcpStream::connect(addr);
        let tcp_stream = timeout(connect_timeout, tcp_connect)
            .await
            .map_err(|_| {
                TransportError::timeout(addr.to_string(), connect_timeout.as_millis() as u64)
            })?
            .map_err(|e| TransportError::connection_failed(addr.to_string(), e.to_string()))?;

        // Configure socket
        Self::configure_socket(&tcp_stream, config)?;

        // Create TLS connector
        let client_config = Self::create_tls_config(tls_config)?;
        let connector = TlsConnector::from(Arc::new(client_config));

        // Parse server name
        let server_name: rustls::pki_types::ServerName<'static> = tls_config
            .server_name
            .clone()
            .try_into()
            .map_err(|_| TransportError::invalid_server_name(&tls_config.server_name))?;

        // Perform TLS handshake
        let tls_connect = connector.connect(server_name, tcp_stream);
        let tls_stream = timeout(connect_timeout, tls_connect)
            .await
            .map_err(|_| {
                TransportError::timeout(
                    format!("TLS handshake to {addr}"),
                    connect_timeout.as_millis() as u64,
                )
            })?
            .map_err(|e| TransportError::tls_handshake(&tls_config.server_name, e.to_string()))?;

        // Perform WebSocket handshake
        let ws_connect = tokio_tungstenite::client_async(request, tls_stream);
        let (ws_stream, _response) = timeout(connect_timeout, ws_connect)
            .await
            .map_err(|_| {
                TransportError::timeout(
                    format!("WebSocket handshake to {addr}"),
                    connect_timeout.as_millis() as u64,
                )
            })?
            .map_err(|e| TransportError::websocket_handshake(e.to_string()))?;

        Ok(WsStreamInner::Tls(ws_stream))
    }

    /// Connect to WebSocket server without TLS at specific address
    async fn connect_plain(
        addr: SocketAddr,
        config: &TransportConfig,
        request: Request<()>,
    ) -> Result<WsStreamInner, TransportError> {
        let connect_timeout = config.connect_timeout;

        // Establish TCP connection
        let tcp_connect = TcpStream::connect(addr);
        let tcp_stream = timeout(connect_timeout, tcp_connect)
            .await
            .map_err(|_| {
                TransportError::timeout(addr.to_string(), connect_timeout.as_millis() as u64)
            })?
            .map_err(|e| TransportError::connection_failed(addr.to_string(), e.to_string()))?;

        // Configure socket
        Self::configure_socket(&tcp_stream, config)?;

        // Perform WebSocket handshake
        let ws_connect = tokio_tungstenite::client_async(request, tcp_stream);
        let (ws_stream, _response) = timeout(connect_timeout, ws_connect)
            .await
            .map_err(|_| {
                TransportError::timeout(
                    format!("WebSocket handshake to {addr}"),
                    connect_timeout.as_millis() as u64,
                )
            })?
            .map_err(|e| TransportError::websocket_handshake(e.to_string()))?;

        Ok(WsStreamInner::Plain(ws_stream))
    }
}

#[async_trait]
impl Transport for WebSocketTransport {
    /// Connect to a remote server over WebSocket
    ///
    /// This method establishes a WebSocket connection with optional TLS.
    ///
    /// # Arguments
    ///
    /// * `config` - Transport configuration with WebSocket settings
    ///
    /// # Errors
    ///
    /// Returns `TransportError` if:
    /// - WebSocket configuration is missing
    /// - DNS resolution fails
    /// - TCP connection fails
    /// - TLS handshake fails (if TLS is configured)
    /// - WebSocket handshake fails
    async fn connect(&self, config: &TransportConfig) -> Result<TransportStream, TransportError> {
        // Resolve address
        let addrs = Self::resolve_address(&config.address, config.port)?;

        // Try connecting to each address
        let mut last_error = None;

        for addr in addrs {
            // Build request for this attempt
            let request = Self::build_request(config)?;

            let result = if let Some(tls_config) = &config.tls {
                Self::connect_tls(addr, config, tls_config, request).await
            } else {
                Self::connect_plain(addr, config, request).await
            };

            match result {
                Ok(ws_inner) => {
                    let ws_config = config.websocket.as_ref().unwrap();

                    tracing::debug!(
                        addr = %addr,
                        path = %ws_config.path,
                        tls = config.tls.is_some(),
                        "WebSocket connection established"
                    );

                    let wrapper = WebSocketWrapper::new(ws_inner);
                    return Ok(TransportStream::WebSocket(wrapper));
                }
                Err(e) => {
                    tracing::debug!(
                        addr = %addr,
                        error = %e,
                        "WebSocket connection attempt failed"
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

/// Wrapper around WebSocket stream that implements `AsyncRead` and `AsyncWrite`
///
/// This wrapper converts WebSocket binary messages to a byte stream interface,
/// allowing the WebSocket to be used transparently with protocols that expect
/// a raw byte stream.
///
/// # Message Handling
///
/// - **Read**: Binary messages are buffered and returned as bytes
/// - **Write**: Bytes are sent as binary messages
/// - **Close/Ping/Pong**: Handled automatically
pub struct WebSocketWrapper {
    /// WebSocket stream (either plain or TLS)
    inner: Arc<Mutex<WsStreamInner>>,
    /// Read buffer for partial message consumption
    read_buffer: BytesMut,
}

impl WebSocketWrapper {
    /// Create a new WebSocket wrapper (internal use only)
    fn new(stream: WsStreamInner) -> Self {
        Self {
            inner: Arc::new(Mutex::new(stream)),
            read_buffer: BytesMut::with_capacity(8192),
        }
    }
}

impl std::fmt::Debug for WebSocketWrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebSocketWrapper")
            .field("read_buffer_len", &self.read_buffer.len())
            .finish()
    }
}

impl AsyncRead for WebSocketWrapper {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // First, drain any buffered data
        if !self.read_buffer.is_empty() {
            let to_copy = std::cmp::min(self.read_buffer.len(), buf.remaining());
            buf.put_slice(&self.read_buffer[..to_copy]);
            self.read_buffer.advance(to_copy);
            return Poll::Ready(Ok(()));
        }

        // Try to receive next message
        let inner = self.inner.clone();

        // Try to lock
        let mut guard = match inner.try_lock() {
            Ok(g) => g,
            Err(_) => {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        };

        // Poll the stream for next message
        let poll_result = match &mut *guard {
            WsStreamInner::Plain(stream) => Pin::new(stream).poll_next(cx),
            WsStreamInner::Tls(stream) => Pin::new(stream).poll_next(cx),
        };

        match poll_result {
            Poll::Ready(Some(Ok(message))) => {
                drop(guard); // Release lock before processing

                match message {
                    Message::Binary(data) => {
                        if data.len() <= buf.remaining() {
                            buf.put_slice(&data);
                        } else {
                            // Buffer excess data
                            let to_copy = buf.remaining();
                            buf.put_slice(&data[..to_copy]);
                            self.read_buffer.extend_from_slice(&data[to_copy..]);
                        }
                        Poll::Ready(Ok(()))
                    }
                    Message::Text(text) => {
                        // Treat text as binary
                        let data = text.into_bytes();
                        if data.len() <= buf.remaining() {
                            buf.put_slice(&data);
                        } else {
                            let to_copy = buf.remaining();
                            buf.put_slice(&data[..to_copy]);
                            self.read_buffer.extend_from_slice(&data[to_copy..]);
                        }
                        Poll::Ready(Ok(()))
                    }
                    Message::Ping(_) | Message::Pong(_) => {
                        // Ignore ping/pong, try again
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                    Message::Close(_) => {
                        // Connection closed
                        Poll::Ready(Ok(()))
                    }
                    Message::Frame(_) => {
                        // Raw frame, ignore
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                }
            }
            Poll::Ready(Some(Err(e))) => {
                Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e.to_string())))
            }
            Poll::Ready(None) => {
                // Stream ended
                Poll::Ready(Ok(()))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for WebSocketWrapper {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let inner = self.inner.clone();

        // Try to lock
        let mut guard = match inner.try_lock() {
            Ok(g) => g,
            Err(_) => {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        };

        // First, ensure the sink is ready
        let ready_result = match &mut *guard {
            WsStreamInner::Plain(stream) => Pin::new(stream).poll_ready(cx),
            WsStreamInner::Tls(stream) => Pin::new(stream).poll_ready(cx),
        };

        match ready_result {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => {
                return Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e.to_string())));
            }
            Poll::Pending => return Poll::Pending,
        }

        // Send the message
        let message = Message::Binary(buf.to_vec());
        let send_result = match &mut *guard {
            WsStreamInner::Plain(stream) => Pin::new(stream).start_send(message),
            WsStreamInner::Tls(stream) => Pin::new(stream).start_send(message),
        };

        match send_result {
            Ok(()) => Poll::Ready(Ok(buf.len())),
            Err(e) => Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e.to_string()))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let inner = self.inner.clone();

        let mut guard = match inner.try_lock() {
            Ok(g) => g,
            Err(_) => {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        };

        let flush_result = match &mut *guard {
            WsStreamInner::Plain(stream) => Pin::new(stream).poll_flush(cx),
            WsStreamInner::Tls(stream) => Pin::new(stream).poll_flush(cx),
        };

        match flush_result {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => {
                Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e.to_string())))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let inner = self.inner.clone();

        let mut guard = match inner.try_lock() {
            Ok(g) => g,
            Err(_) => {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        };

        let close_result = match &mut *guard {
            WsStreamInner::Plain(stream) => Pin::new(stream).poll_close(cx),
            WsStreamInner::Tls(stream) => Pin::new(stream).poll_close(cx),
        };

        match close_result {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => {
                Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e.to_string())))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::WebSocketConfig;
    use std::sync::Once;

    static INIT_CRYPTO: Once = Once::new();

    fn init_crypto_provider() {
        INIT_CRYPTO.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
    }

    #[test]
    fn test_websocket_transport_new() {
        let transport = WebSocketTransport::new();
        assert_eq!(std::mem::size_of_val(&transport), 0);
    }

    #[test]
    fn test_websocket_transport_default() {
        let transport = WebSocketTransport::default();
        assert_eq!(std::mem::size_of_val(&transport), 0);
    }

    #[test]
    fn test_build_request_plain() {
        let config = TransportConfig::tcp("example.com", 80)
            .with_websocket(WebSocketConfig::new("/ws"));

        let request = WebSocketTransport::build_request(&config).unwrap();
        let uri = request.uri().to_string();
        assert!(uri.starts_with("ws://"));
        assert!(uri.contains("/ws"));
    }

    #[test]
    fn test_build_request_tls() {
        init_crypto_provider();
        let config = TransportConfig::tcp("example.com", 443)
            .with_tls(TlsConfig::new("example.com"))
            .with_websocket(WebSocketConfig::new("/tunnel"));

        let request = WebSocketTransport::build_request(&config).unwrap();
        let uri = request.uri().to_string();
        assert!(uri.starts_with("wss://"));
        assert!(uri.contains("/tunnel"));
    }

    #[test]
    fn test_build_request_with_headers() {
        let config = TransportConfig::tcp("example.com", 80).with_websocket(
            WebSocketConfig::new("/ws")
                .with_host("cdn.example.com")
                .with_header("X-Auth", "token123"),
        );

        let request = WebSocketTransport::build_request(&config).unwrap();

        // Check custom header is present
        let auth_header = request.headers().get("X-Auth");
        assert!(auth_header.is_some());
        assert_eq!(auth_header.unwrap().to_str().unwrap(), "token123");
    }

    #[test]
    fn test_build_request_no_ws_config() {
        let config = TransportConfig::tcp("example.com", 80);
        let result = WebSocketTransport::build_request(&config);
        assert!(result.is_err());
    }

    #[test]
    fn test_websocket_config_builder() {
        let config = WebSocketConfig::new("/path")
            .with_host("override.com")
            .with_header("X-Header1", "value1")
            .with_headers(vec![("X-Header2", "value2")]);

        assert_eq!(config.path, "/path");
        assert_eq!(config.host, Some("override.com".to_string()));
        assert_eq!(config.headers.len(), 2);
    }

    #[tokio::test]
    async fn test_connect_no_ws_config() {
        let transport = WebSocketTransport::new();
        // Config without WebSocket should fail
        let config = TransportConfig::tcp("example.com", 80);

        let result = transport.connect(&config).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_connect_connection_refused() {
        let transport = WebSocketTransport::new();
        // Port 1 should be refused
        let config = TransportConfig::tcp("127.0.0.1", 1)
            .with_websocket(WebSocketConfig::new("/ws"))
            .with_timeout(Duration::from_millis(100));

        let result = transport.connect(&config).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_resolve_address() {
        let addrs = WebSocketTransport::resolve_address("127.0.0.1", 8080).unwrap();
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0].port(), 8080);
    }
}
