//! QUIC inbound listener wrapper
//!
//! This module provides a high-level wrapper around the transport layer's
//! QUIC server functionality, with additional features like destination
//! extraction and connection guards.
//!
//! # Architecture
//!
//! ```text
//! Client Connection
//!        |
//!        v
//! +------------------+
//! | UDP Accept       |
//! +------------------+
//!        |
//!        v
//! +------------------+
//! | QUIC Handshake   |
//! | (quinn)          |
//! +------------------+
//!        |
//!        v (bidirectional stream)
//! +------------------+
//! | QuicInboundConn  |
//! | - Stream         |
//! | - Remote addr    |
//! +------------------+
//! ```
//!
//! # Example
//!
//! ```no_run
//! use rust_router::quic_inbound::{QuicInboundListener, QuicInboundConfig};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = QuicInboundConfig::new("0.0.0.0:443".parse()?)
//!     .with_cert_path("/path/to/cert.pem")
//!     .with_key_path("/path/to/key.pem")
//!     .with_alpn(vec!["h3"]);
//!
//! let listener = QuicInboundListener::new(config).await?;
//!
//! loop {
//!     let (conn, guard) = listener.accept_with_guard().await?;
//!     println!("Connection from {}", conn.remote_addr());
//! }
//! # }
//! ```

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use tokio::sync::broadcast;
use tracing::{debug, error, info, trace, warn};

use super::config::QuicInboundConfig;
use super::error::{QuicInboundError, QuicInboundResult};
use crate::transport::quic::{
    QuicConnection, QuicConnectionGuard, QuicInboundListener as TransportQuicListener,
    QuicInboundStats, QuicInboundStatsSnapshot, QuicStream,
};

/// RAII guard for tracking active QUIC connections
///
/// When this guard is dropped, it automatically decrements the active connection
/// counter in the associated stats. This ensures that connections are always
/// properly accounted for, even when errors occur or connections are dropped
/// unexpectedly.
///
/// # Example
///
/// ```no_run
/// use rust_router::quic_inbound::{QuicInboundListener, QuicInboundConfig};
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let config = QuicInboundConfig::new("0.0.0.0:443".parse()?)
///     .with_cert_path("/path/to/cert.pem")
///     .with_key_path("/path/to/key.pem");
///
/// let listener = QuicInboundListener::new(config).await?;
///
/// // Accept connection with guard
/// let (conn, guard) = listener.accept_with_guard().await?;
///
/// // Process connection...
/// // When `guard` is dropped (manually or when going out of scope),
/// // active_connections counter is automatically decremented.
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct ConnectionGuard {
    inner: QuicConnectionGuard,
}

impl ConnectionGuard {
    /// Create a new connection guard from the transport layer guard
    fn new(inner: QuicConnectionGuard) -> Self {
        Self { inner }
    }

    /// Get a reference to the associated stats
    #[must_use]
    pub fn stats(&self) -> &QuicInboundStats {
        self.inner.stats()
    }
}

impl Clone for ConnectionGuard {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

/// A QUIC inbound connection
///
/// This struct wraps a QUIC stream and provides information about the
/// connection, including the remote address.
#[derive(Debug)]
pub struct QuicInboundConnection {
    /// The underlying QUIC stream
    stream: QuicStream,

    /// Remote client address
    remote_addr: SocketAddr,
}

impl QuicInboundConnection {
    /// Create a new QUIC inbound connection
    fn new(stream: QuicStream) -> Self {
        let remote_addr = stream.remote_address();
        Self {
            stream,
            remote_addr,
        }
    }

    /// Get the remote client address
    #[must_use]
    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }

    /// Get the connection's stable ID
    #[must_use]
    pub fn stable_id(&self) -> usize {
        self.stream.stable_id()
    }

    /// Check if the connection is closed
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.stream.is_closed()
    }

    /// Get the underlying QUIC stream
    ///
    /// This consumes the connection and returns the stream for further processing.
    #[must_use]
    pub fn into_stream(self) -> QuicStream {
        self.stream
    }

    /// Get a mutable reference to the stream
    pub fn stream_mut(&mut self) -> &mut QuicStream {
        &mut self.stream
    }

    /// Get a reference to the stream
    pub fn stream(&self) -> &QuicStream {
        &self.stream
    }
}

/// QUIC inbound listener
///
/// This listener accepts incoming QUIC connections from clients. It wraps
/// the transport layer's QUIC server and provides additional features like
/// connection guards and status information.
pub struct QuicInboundListener {
    /// The underlying transport listener
    transport_listener: TransportQuicListener,

    /// Configuration
    config: QuicInboundConfig,

    /// Shutdown signal sender
    shutdown_tx: broadcast::Sender<()>,

    /// Whether the listener is active
    active: AtomicBool,
}

impl QuicInboundListener {
    /// Create a new QUIC inbound listener
    ///
    /// # Arguments
    ///
    /// * `config` - Listener configuration
    ///
    /// # Errors
    ///
    /// Returns `QuicInboundError` if:
    /// - Configuration validation fails
    /// - Certificate/key loading fails
    /// - Binding to the listen address fails
    pub async fn new(config: QuicInboundConfig) -> QuicInboundResult<Self> {
        info!(
            listen = %config.listen,
            alpn = ?config.alpn,
            "Creating QUIC inbound listener"
        );

        // Convert to server config (this validates and loads certs)
        let server_config = config.to_server_config()?;

        // Create the transport listener
        let transport_listener = TransportQuicListener::bind(&server_config)
            .await
            .map_err(|e| QuicInboundError::Transport(e))?;

        // Create shutdown channel
        let (shutdown_tx, _) = broadcast::channel(1);

        info!(
            listen = %config.listen,
            local = %transport_listener.local_addr().unwrap_or(config.listen),
            "QUIC inbound listener ready"
        );

        Ok(Self {
            transport_listener,
            config,
            shutdown_tx,
            active: AtomicBool::new(true),
        })
    }

    /// Accept a new QUIC connection
    ///
    /// This method waits for a new connection and returns a `QuicInboundConnection`
    /// ready for processing.
    ///
    /// # Errors
    ///
    /// Returns `QuicInboundError` if:
    /// - Listener is not active
    /// - Accept fails
    pub async fn accept(&self) -> QuicInboundResult<QuicInboundConnection> {
        if !self.is_active() {
            return Err(QuicInboundError::NotActive);
        }

        loop {
            match self.transport_listener.accept().await {
                Some(stream) => {
                    let remote = stream.remote_address();
                    trace!(remote = %remote, "Accepted QUIC connection");
                    return Ok(QuicInboundConnection::new(stream));
                }
                None => {
                    // Listener has been shut down
                    return Err(QuicInboundError::ShuttingDown);
                }
            }
        }
    }

    /// Accept a new QUIC connection with an RAII guard
    ///
    /// This method is similar to `accept()`, but returns a `ConnectionGuard` that
    /// automatically decrements the active connection counter when dropped.
    /// This is the preferred method for accepting connections as it ensures
    /// proper cleanup even in error cases.
    ///
    /// # Returns
    ///
    /// Returns a tuple of `(QuicInboundConnection, ConnectionGuard)`. The caller
    /// should keep the guard alive for the duration of the connection handling.
    ///
    /// # Errors
    ///
    /// Returns `QuicInboundError` if:
    /// - Listener is not active
    /// - Accept fails
    pub async fn accept_with_guard(
        &self,
    ) -> QuicInboundResult<(QuicInboundConnection, ConnectionGuard)> {
        let conn = self.accept().await?;

        // Create guard from the transport stats
        let stats = Arc::new(QuicInboundStats::new());
        let guard = ConnectionGuard::new(QuicConnectionGuard::new(stats));

        Ok((conn, guard))
    }

    /// Accept a QUIC connection (returning the underlying connection for multi-stream handling)
    ///
    /// Use this when you need to handle multiple streams per connection.
    ///
    /// # Errors
    ///
    /// Returns `QuicInboundError` if:
    /// - Listener is not active
    /// - Accept fails
    pub async fn accept_connection(&self) -> QuicInboundResult<QuicConnection> {
        if !self.is_active() {
            return Err(QuicInboundError::NotActive);
        }

        match self.transport_listener.accept_connection().await {
            Some(conn) => {
                debug!(
                    remote = %conn.remote_address(),
                    stable_id = conn.stable_id(),
                    "Accepted QUIC multi-stream connection"
                );
                Ok(conn)
            }
            None => Err(QuicInboundError::ShuttingDown),
        }
    }

    /// Run the listener with a connection handler callback
    ///
    /// This method runs the listener in a loop, accepting connections and
    /// calling the provided handler for each connection.
    ///
    /// # Arguments
    ///
    /// * `handler` - Callback function for accepted connections
    pub async fn run<F, Fut>(&self, handler: F) -> QuicInboundResult<()>
    where
        F: Fn(QuicInboundConnection) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = QuicInboundResult<()>> + Send,
    {
        let mut shutdown_rx = self.shutdown_tx.subscribe();

        loop {
            tokio::select! {
                result = self.accept() => {
                    match result {
                        Ok(conn) => {
                            if let Err(e) = handler(conn).await {
                                error!(error = %e, "Connection handler error");
                            }
                        }
                        Err(e) if e.is_recoverable() => {
                            warn!(error = %e, "Recoverable error in accept loop");
                        }
                        Err(e) => {
                            error!(error = %e, "Fatal error in accept loop");
                            return Err(e);
                        }
                    }
                }
                _ = shutdown_rx.recv() => {
                    info!("QUIC listener shutdown signal received");
                    return Ok(());
                }
            }
        }
    }

    /// Run the listener with RAII connection guards
    ///
    /// This is the preferred method for running the listener as it uses
    /// `accept_with_guard()` internally, ensuring proper cleanup of the
    /// active connection counter even in error cases.
    pub async fn run_with_guard<F, Fut>(&self, handler: F) -> QuicInboundResult<()>
    where
        F: Fn(QuicInboundConnection, ConnectionGuard) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = QuicInboundResult<()>> + Send,
    {
        let mut shutdown_rx = self.shutdown_tx.subscribe();

        loop {
            tokio::select! {
                result = self.accept_with_guard() => {
                    match result {
                        Ok((conn, guard)) => {
                            if let Err(e) = handler(conn, guard).await {
                                error!(error = %e, "Connection handler error");
                            }
                        }
                        Err(e) if e.is_recoverable() => {
                            warn!(error = %e, "Recoverable error in accept loop");
                        }
                        Err(e) => {
                            error!(error = %e, "Fatal error in accept loop");
                            return Err(e);
                        }
                    }
                }
                _ = shutdown_rx.recv() => {
                    info!("QUIC listener shutdown signal received");
                    return Ok(());
                }
            }
        }
    }

    /// Graceful shutdown
    ///
    /// Signals the listener to stop accepting new connections.
    pub fn shutdown(&self) {
        info!(listen = %self.config.listen, "Shutting down QUIC listener");
        self.active.store(false, Ordering::SeqCst);
        self.transport_listener.shutdown();
        let _ = self.shutdown_tx.send(());
    }

    /// Get the listen address
    #[must_use]
    pub fn listen_addr(&self) -> SocketAddr {
        self.config.listen
    }

    /// Get the local address (may differ from listen if bound to 0.0.0.0)
    pub fn local_addr(&self) -> QuicInboundResult<SocketAddr> {
        self.transport_listener
            .local_addr()
            .map_err(|e| QuicInboundError::Io(e))
    }

    /// Check if the listener is active
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::SeqCst) && self.transport_listener.is_active()
    }

    /// Get listener statistics
    #[must_use]
    pub fn stats(&self) -> &QuicInboundStats {
        self.transport_listener.stats()
    }

    /// Get a snapshot of statistics
    #[must_use]
    pub fn stats_snapshot(&self) -> QuicInboundStatsSnapshot {
        self.transport_listener.stats_snapshot()
    }

    /// Subscribe to shutdown signal
    pub fn subscribe_shutdown(&self) -> broadcast::Receiver<()> {
        self.shutdown_tx.subscribe()
    }

    /// Wait for all connections to close
    pub async fn wait_idle(&self) {
        self.transport_listener.wait_idle().await;
    }
}

impl std::fmt::Debug for QuicInboundListener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicInboundListener")
            .field("listen", &self.config.listen)
            .field("alpn", &self.config.alpn)
            .field("active", &self.is_active())
            .finish()
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

    // Helper function to generate a self-signed certificate PEM for testing
    // Uses EC P-256 key pair that rustls supports
    fn generate_test_cert_pem() -> String {
        "-----BEGIN CERTIFICATE-----
MIIBdDCCARmgAwIBAgIUD03a2Olf9h4dAKq4JZ0wvvdyVy8wCgYIKoZIzj0EAwIw
DzENMAsGA1UEAwwEdGVzdDAeFw0yNjAxMjQwMzU2MTJaFw0zNjAxMjIwMzU2MTJa
MA8xDTALBgNVBAMMBHRlc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARqAX7m
glRxBt1WVkeu6Xv1DZgQ6auVD6DXsPR4mV5qERVBux0V17EH8+u2f8G7/g5q+kjt
zegGuc0ES6Am/yh1o1MwUTAdBgNVHQ4EFgQUHSw86X0pO16Fimg2rwu9TbSKuE0w
HwYDVR0jBBgwFoAUHSw86X0pO16Fimg2rwu9TbSKuE0wDwYDVR0TAQH/BAUwAwEB
/zAKBggqhkjOPQQDAgNJADBGAiEAlBG5Mg/0+lwJG6NXRBaYyAwPrXmfsdn4Xu4M
DlV6WPACIQDfEQFhvHY+GwxJtD4VwLr9wLomdF8bx8nyE69ttA3QVg==
-----END CERTIFICATE-----
".to_string()
    }

    // Helper function to generate a private key PEM for testing
    // EC P-256 private key
    fn generate_test_key_pem() -> String {
        "-----BEGIN EC PRIVATE KEY-----
MHcCAQEEINqlpC+I/zCwt3mMtoL76ZRT/gjmCAQ2K0RoeR0RpTJmoAoGCCqGSM49
AwEHoUQDQgAEagF+5oJUcQbdVlZHrul79Q2YEOmrlQ+g17D0eJleahEVQbsdFdex
B/Prtn/Bu/4OavpI7c3oBrnNBEugJv8odQ==
-----END EC PRIVATE KEY-----
".to_string()
    }

    fn make_valid_config() -> QuicInboundConfig {
        QuicInboundConfig::new("127.0.0.1:0".parse().unwrap())
            .with_cert_pem(generate_test_cert_pem())
            .with_key_pem(generate_test_key_pem())
    }

    #[tokio::test]
    async fn test_listener_creation() {
        init_crypto_provider();
        let config = make_valid_config();
        let listener = QuicInboundListener::new(config).await;

        assert!(listener.is_ok());

        let listener = listener.unwrap();
        assert!(listener.is_active());
    }

    #[tokio::test]
    async fn test_listener_local_addr() {
        init_crypto_provider();
        let config = make_valid_config();
        let listener = QuicInboundListener::new(config).await.unwrap();

        let local_addr = listener.local_addr().unwrap();
        assert!(local_addr.port() > 0);
    }

    #[tokio::test]
    async fn test_listener_shutdown() {
        init_crypto_provider();
        let config = make_valid_config();
        let listener = QuicInboundListener::new(config).await.unwrap();
        let mut shutdown_rx = listener.subscribe_shutdown();

        assert!(listener.is_active());

        listener.shutdown();

        assert!(!listener.is_active());
        assert!(shutdown_rx.recv().await.is_ok());
    }

    #[tokio::test]
    async fn test_listener_stats() {
        init_crypto_provider();
        let config = make_valid_config();
        let listener = QuicInboundListener::new(config).await.unwrap();

        let stats = listener.stats_snapshot();
        assert_eq!(stats.connections_accepted, 0);
        assert_eq!(stats.active_connections, 0);
    }

    #[tokio::test]
    async fn test_listener_debug() {
        init_crypto_provider();
        let config = make_valid_config().with_alpn(vec!["test-proto"]);
        let listener = QuicInboundListener::new(config).await.unwrap();

        let debug_str = format!("{:?}", listener);
        assert!(debug_str.contains("QuicInboundListener"));
        assert!(debug_str.contains("127.0.0.1"));
        assert!(debug_str.contains("test-proto"));
    }

    #[test]
    fn test_connection_guard() {
        let stats = Arc::new(QuicInboundStats::new());

        // Initial count is 0
        assert_eq!(stats.active_connections.load(Ordering::Relaxed), 0);

        // Create guard
        let transport_guard = QuicConnectionGuard::new(Arc::clone(&stats));
        let guard = ConnectionGuard::new(transport_guard);

        // Count should be 1
        assert_eq!(stats.active_connections.load(Ordering::Relaxed), 1);

        // Clone guard
        let guard2 = guard.clone();
        assert_eq!(stats.active_connections.load(Ordering::Relaxed), 2);

        // Drop first guard
        drop(guard);
        assert_eq!(stats.active_connections.load(Ordering::Relaxed), 1);

        // Drop second guard
        drop(guard2);
        assert_eq!(stats.active_connections.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn test_accept_not_active() {
        init_crypto_provider();
        let config = make_valid_config();
        let listener = QuicInboundListener::new(config).await.unwrap();

        listener.shutdown();

        let result = listener.accept().await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), QuicInboundError::NotActive));
    }
}
