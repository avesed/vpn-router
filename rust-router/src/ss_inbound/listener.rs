//! Shadowsocks inbound listener
//!
//! This module provides the main Shadowsocks inbound listener that accepts connections
//! from Shadowsocks clients. It uses the shadowsocks crate's `ProxyListener` for
//! protocol handling.
//!
//! # Architecture
//!
//! ```text
//! Client Connection
//!        |
//!        v
//! +------------------+
//! | TCP Accept       |
//! +------------------+
//!        |
//!        v
//! +------------------+
//! | ProxyListener    |
//! | (shadowsocks)    |
//! +------------------+
//!        |
//!        v (decrypted stream)
//! +------------------+
//! | Handshake        |
//! | - Read target    |
//! +------------------+
//!        |
//!        v
//! +------------------+
//! | Shadowsocks      |
//! | Connection       |
//! +------------------+
//! ```
//!
//! # Example
//!
//! ```no_run
//! use rust_router::ss_inbound::{ShadowsocksInboundListener, ShadowsocksInboundConfig};
//! use rust_router::shadowsocks::ShadowsocksMethod;
//! use std::net::SocketAddr;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = ShadowsocksInboundConfig::new(
//!     "0.0.0.0:8388".parse()?,
//!     "my-secret-password",
//! ).with_method(ShadowsocksMethod::Aes256Gcm);
//!
//! let listener = ShadowsocksInboundListener::new(config).await?;
//!
//! loop {
//!     let conn = listener.accept().await?;
//!     println!("Connection from {} to {}",
//!         conn.client_addr(),
//!         conn.destination());
//! }
//! # }
//! ```

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use tokio::net::TcpStream;
use tokio::sync::broadcast;
use tracing::{debug, error, info, trace, warn};

use super::config::ShadowsocksInboundConfig;
use super::error::{ShadowsocksInboundError, ShadowsocksInboundResult};
use super::handler::{ShadowsocksConnection, ShadowsocksDestination};

/// RAII guard for tracking active connections
///
/// When this guard is dropped, it automatically decrements the active connection
/// counter in the associated stats. This ensures that connections are always
/// properly accounted for, even when errors occur or connections are dropped
/// unexpectedly.
///
/// # Example
///
/// ```no_run
/// use rust_router::ss_inbound::{ShadowsocksInboundListener, ShadowsocksInboundConfig};
/// use rust_router::shadowsocks::ShadowsocksMethod;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let config = ShadowsocksInboundConfig::new(
///     "0.0.0.0:8388".parse()?,
///     "password",
/// ).with_method(ShadowsocksMethod::Aes256Gcm);
///
/// let listener = ShadowsocksInboundListener::new(config).await?;
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
    stats: Arc<ShadowsocksInboundStats>,
}

impl ConnectionGuard {
    /// Create a new connection guard
    ///
    /// This increments the active connection counter.
    fn new(stats: Arc<ShadowsocksInboundStats>) -> Self {
        stats.active_connections.fetch_add(1, Ordering::Relaxed);
        Self { stats }
    }

    /// Get a reference to the associated stats
    #[must_use]
    pub fn stats(&self) -> &ShadowsocksInboundStats {
        &self.stats
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.stats.active_connections.fetch_sub(1, Ordering::Relaxed);
    }
}

impl Clone for ConnectionGuard {
    fn clone(&self) -> Self {
        // Incrementing on clone to maintain correct count
        self.stats.active_connections.fetch_add(1, Ordering::Relaxed);
        Self {
            stats: Arc::clone(&self.stats),
        }
    }
}

#[cfg(feature = "shadowsocks")]
use shadowsocks::{
    config::ServerConfig,
    context::SharedContext,
    relay::tcprelay::{
        proxy_listener::ProxyListener,
        proxy_stream::server::ProxyServerStream,
    },
};

/// Shadowsocks inbound listener
///
/// This listener accepts incoming connections from Shadowsocks clients, performs
/// decryption and protocol parsing, and returns connections ready for forwarding.
#[cfg(feature = "shadowsocks")]
pub struct ShadowsocksInboundListener {
    /// The underlying proxy listener from shadowsocks crate
    proxy_listener: ProxyListener,

    /// Shadowsocks context
    context: SharedContext,

    /// Configuration
    config: ShadowsocksInboundConfig,

    /// Shutdown signal sender
    shutdown_tx: broadcast::Sender<()>,

    /// Whether the listener is active
    active: AtomicBool,

    /// Statistics
    stats: Arc<ShadowsocksInboundStats>,
}

#[cfg(feature = "shadowsocks")]
impl ShadowsocksInboundListener {
    /// Create a new Shadowsocks inbound listener
    ///
    /// # Arguments
    ///
    /// * `config` - Listener configuration
    ///
    /// # Errors
    ///
    /// Returns `ShadowsocksInboundError` if:
    /// - Configuration validation fails
    /// - Binding to the listen address fails
    /// - Cipher configuration fails
    pub async fn new(config: ShadowsocksInboundConfig) -> ShadowsocksInboundResult<Self> {
        // Validate configuration
        config.validate()?;

        info!(
            listen = %config.listen,
            method = %config.method,
            udp = config.udp_enabled,
            "Creating Shadowsocks inbound listener"
        );

        // Build context and server config
        let context = ShadowsocksInboundConfig::build_context();
        let server_config = config.build_server_config()?;

        // Create the proxy listener
        let proxy_listener = ProxyListener::bind(context.clone(), &server_config)
            .await
            .map_err(|e| ShadowsocksInboundError::bind_failed(config.listen, e.to_string()))?;

        // Create shutdown channel
        let (shutdown_tx, _) = broadcast::channel(1);

        info!(
            listen = %config.listen,
            local = %proxy_listener.local_addr().unwrap_or(config.listen),
            "Shadowsocks inbound listener ready"
        );

        Ok(Self {
            proxy_listener,
            context,
            config,
            shutdown_tx,
            active: AtomicBool::new(true),
            stats: Arc::new(ShadowsocksInboundStats::new()),
        })
    }

    /// Accept a new Shadowsocks connection
    ///
    /// This method waits for a new connection, performs decryption and handshake,
    /// and returns a connection ready for forwarding.
    ///
    /// # Errors
    ///
    /// Returns `ShadowsocksInboundError` if:
    /// - Listener is not active
    /// - TCP accept fails
    /// - Decryption fails
    /// - Handshake fails
    pub async fn accept(
        &self,
    ) -> ShadowsocksInboundResult<ShadowsocksConnection<ProxyServerStream<TcpStream>>> {
        if !self.is_active() {
            return Err(ShadowsocksInboundError::NotActive);
        }

        loop {
            // Accept a connection (this also creates the encrypted stream)
            let (mut stream, client_addr) = self
                .proxy_listener
                .accept()
                .await
                .map_err(|e| ShadowsocksInboundError::accept(e.to_string()))?;

            trace!(client = %client_addr, "Accepted Shadowsocks connection");
            self.stats.connections_accepted.fetch_add(1, Ordering::Relaxed);
            self.stats.active_connections.fetch_add(1, Ordering::Relaxed);

            // Perform handshake to get target address
            match stream.handshake().await {
                Ok(target_addr) => {
                    let destination = ShadowsocksDestination::from(target_addr);

                    debug!(
                        client = %client_addr,
                        destination = %destination,
                        "Shadowsocks handshake completed"
                    );

                    return Ok(ShadowsocksConnection::new(stream, destination, client_addr));
                }
                Err(e) => {
                    self.stats.active_connections.fetch_sub(1, Ordering::Relaxed);
                    self.stats.protocol_errors.fetch_add(1, Ordering::Relaxed);

                    warn!(
                        client = %client_addr,
                        error = %e,
                        "Shadowsocks handshake failed"
                    );

                    // Continue accepting new connections
                    continue;
                }
            }
        }
    }

    /// Accept a new Shadowsocks connection with an RAII guard
    ///
    /// This method is similar to `accept()`, but returns a `ConnectionGuard` that
    /// automatically decrements the active connection counter when dropped.
    /// This is the preferred method for accepting connections as it ensures
    /// proper cleanup even in error cases.
    ///
    /// # Returns
    ///
    /// Returns a tuple of `(ShadowsocksConnection, ConnectionGuard)`. The caller
    /// should keep the guard alive for the duration of the connection handling.
    ///
    /// # Errors
    ///
    /// Returns `ShadowsocksInboundError` if:
    /// - Listener is not active
    /// - TCP accept fails
    /// - Decryption fails
    /// - Handshake fails
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rust_router::ss_inbound::{ShadowsocksInboundListener, ShadowsocksInboundConfig};
    /// use rust_router::shadowsocks::ShadowsocksMethod;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let config = ShadowsocksInboundConfig::new(
    ///     "0.0.0.0:8388".parse()?,
    ///     "password",
    /// ).with_method(ShadowsocksMethod::Aes256Gcm);
    ///
    /// let listener = ShadowsocksInboundListener::new(config).await?;
    ///
    /// loop {
    ///     let (conn, _guard) = listener.accept_with_guard().await?;
    ///
    ///     tokio::spawn(async move {
    ///         // _guard is moved into the spawned task
    ///         // It will be dropped when the task completes
    ///         println!("Connection to {}", conn.destination());
    ///     });
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn accept_with_guard(
        &self,
    ) -> ShadowsocksInboundResult<(
        ShadowsocksConnection<ProxyServerStream<TcpStream>>,
        ConnectionGuard,
    )> {
        if !self.is_active() {
            return Err(ShadowsocksInboundError::NotActive);
        }

        loop {
            // Accept a connection (this also creates the encrypted stream)
            let (mut stream, client_addr) = self
                .proxy_listener
                .accept()
                .await
                .map_err(|e| ShadowsocksInboundError::accept(e.to_string()))?;

            trace!(client = %client_addr, "Accepted Shadowsocks connection");
            self.stats.connections_accepted.fetch_add(1, Ordering::Relaxed);

            // Create guard BEFORE handshake - it will clean up if handshake fails
            // Note: We don't increment here because ConnectionGuard::new does it
            let guard = ConnectionGuard::new(Arc::clone(&self.stats));

            // Perform handshake to get target address
            match stream.handshake().await {
                Ok(target_addr) => {
                    let destination = ShadowsocksDestination::from(target_addr);

                    debug!(
                        client = %client_addr,
                        destination = %destination,
                        "Shadowsocks handshake completed"
                    );

                    return Ok((
                        ShadowsocksConnection::new(stream, destination, client_addr),
                        guard,
                    ));
                }
                Err(e) => {
                    // Guard will be dropped here, automatically decrementing active_connections
                    drop(guard);
                    self.stats.protocol_errors.fetch_add(1, Ordering::Relaxed);

                    warn!(
                        client = %client_addr,
                        error = %e,
                        "Shadowsocks handshake failed"
                    );

                    // Continue accepting new connections
                    continue;
                }
            }
        }
    }

    /// Run the listener with a connection handler callback
    ///
    /// This method runs the listener in a loop, accepting connections and
    /// calling the provided handler for each authenticated connection.
    ///
    /// # Arguments
    ///
    /// * `handler` - Callback function for authenticated connections
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use rust_router::ss_inbound::{ShadowsocksInboundListener, ShadowsocksInboundConfig};
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let config = ShadowsocksInboundConfig::new("0.0.0.0:8388".parse()?, "password");
    /// let listener = ShadowsocksInboundListener::new(config).await?;
    ///
    /// listener.run(|conn| async move {
    ///     println!("Connection to {}", conn.destination());
    ///     Ok(())
    /// }).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn run<F, Fut>(&self, handler: F) -> ShadowsocksInboundResult<()>
    where
        F: Fn(ShadowsocksConnection<ProxyServerStream<TcpStream>>) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = ShadowsocksInboundResult<()>> + Send,
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
                            self.stats.active_connections.fetch_sub(1, Ordering::Relaxed);
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
                    info!("Shadowsocks listener shutdown signal received");
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
    ///
    /// The handler receives both the connection and the guard. The guard
    /// should be kept alive for the duration of connection handling.
    ///
    /// # Arguments
    ///
    /// * `handler` - Callback function for authenticated connections
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use rust_router::ss_inbound::{ShadowsocksInboundListener, ShadowsocksInboundConfig};
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let config = ShadowsocksInboundConfig::new("0.0.0.0:8388".parse()?, "password");
    /// let listener = ShadowsocksInboundListener::new(config).await?;
    ///
    /// listener.run_with_guard(|conn, _guard| async move {
    ///     println!("Connection to {}", conn.destination());
    ///     // _guard is automatically dropped when this closure completes
    ///     Ok(())
    /// }).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn run_with_guard<F, Fut>(&self, handler: F) -> ShadowsocksInboundResult<()>
    where
        F: Fn(ShadowsocksConnection<ProxyServerStream<TcpStream>>, ConnectionGuard) -> Fut
            + Send
            + Sync
            + 'static,
        Fut: std::future::Future<Output = ShadowsocksInboundResult<()>> + Send,
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
                            // Guard is automatically dropped when handler completes
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
                    info!("Shadowsocks listener shutdown signal received");
                    return Ok(());
                }
            }
        }
    }

    /// Graceful shutdown
    ///
    /// Signals the listener to stop accepting new connections.
    pub fn shutdown(&self) {
        info!(listen = %self.config.listen, "Shutting down Shadowsocks listener");
        self.active.store(false, Ordering::SeqCst);
        let _ = self.shutdown_tx.send(());
    }

    /// Get the listen address
    #[must_use]
    pub fn listen_addr(&self) -> SocketAddr {
        self.config.listen
    }

    /// Get the local address (may differ from listen if bound to 0.0.0.0)
    pub fn local_addr(&self) -> ShadowsocksInboundResult<SocketAddr> {
        self.proxy_listener
            .local_addr()
            .map_err(|e| ShadowsocksInboundError::Io(e))
    }

    /// Check if the listener is active
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::SeqCst)
    }

    /// Get listener statistics
    #[must_use]
    pub fn stats(&self) -> &ShadowsocksInboundStats {
        &self.stats
    }

    /// Get a snapshot of statistics
    #[must_use]
    pub fn stats_snapshot(&self) -> ShadowsocksInboundStatsSnapshot {
        self.stats.snapshot()
    }

    /// Check if UDP is enabled
    #[must_use]
    pub fn is_udp_enabled(&self) -> bool {
        self.config.is_udp_enabled()
    }

    /// Subscribe to shutdown signal
    pub fn subscribe_shutdown(&self) -> broadcast::Receiver<()> {
        self.shutdown_tx.subscribe()
    }
}

#[cfg(feature = "shadowsocks")]
impl std::fmt::Debug for ShadowsocksInboundListener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShadowsocksInboundListener")
            .field("listen", &self.config.listen)
            .field("method", &self.config.method)
            .field("active", &self.is_active())
            .field("udp_enabled", &self.config.udp_enabled)
            .finish()
    }
}

/// Statistics for the Shadowsocks inbound listener
#[derive(Debug)]
pub struct ShadowsocksInboundStats {
    /// Total connections accepted
    pub connections_accepted: AtomicU64,

    /// Currently active connections
    pub active_connections: AtomicU64,

    /// Total protocol errors (handshake failures, etc.)
    pub protocol_errors: AtomicU64,

    /// Total bytes received
    pub bytes_received: AtomicU64,

    /// Total bytes sent
    pub bytes_sent: AtomicU64,
}

impl ShadowsocksInboundStats {
    /// Create new empty stats
    #[must_use]
    pub fn new() -> Self {
        Self {
            connections_accepted: AtomicU64::new(0),
            active_connections: AtomicU64::new(0),
            protocol_errors: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
        }
    }

    /// Get a snapshot of the statistics
    #[must_use]
    pub fn snapshot(&self) -> ShadowsocksInboundStatsSnapshot {
        ShadowsocksInboundStatsSnapshot {
            connections_accepted: self.connections_accepted.load(Ordering::Relaxed),
            active_connections: self.active_connections.load(Ordering::Relaxed),
            protocol_errors: self.protocol_errors.load(Ordering::Relaxed),
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
        }
    }

    /// Record bytes received
    pub fn record_bytes_received(&self, bytes: u64) {
        self.bytes_received.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Record bytes sent
    pub fn record_bytes_sent(&self, bytes: u64) {
        self.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
    }
}

impl Default for ShadowsocksInboundStats {
    fn default() -> Self {
        Self::new()
    }
}

/// Snapshot of Shadowsocks inbound statistics
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ShadowsocksInboundStatsSnapshot {
    /// Total connections accepted
    pub connections_accepted: u64,

    /// Currently active connections
    pub active_connections: u64,

    /// Total protocol errors
    pub protocol_errors: u64,

    /// Total bytes received
    pub bytes_received: u64,

    /// Total bytes sent
    pub bytes_sent: u64,
}

#[cfg(all(test, feature = "shadowsocks"))]
mod tests {
    use super::*;
    use crate::shadowsocks::ShadowsocksMethod;

    fn make_valid_config() -> ShadowsocksInboundConfig {
        // Use legacy AEAD which accepts plaintext passwords
        ShadowsocksInboundConfig::new("127.0.0.1:0".parse().unwrap(), "test-password")
            .with_method(ShadowsocksMethod::Aes256Gcm)
    }

    #[tokio::test]
    async fn test_listener_creation() {
        let config = make_valid_config();
        let listener = ShadowsocksInboundListener::new(config).await;

        assert!(listener.is_ok());

        let listener = listener.unwrap();
        assert!(listener.is_active());
        assert!(!listener.is_udp_enabled());
    }

    #[tokio::test]
    async fn test_listener_local_addr() {
        let config = make_valid_config();
        let listener = ShadowsocksInboundListener::new(config).await.unwrap();

        let local_addr = listener.local_addr().unwrap();
        assert!(local_addr.port() > 0);
    }

    #[tokio::test]
    async fn test_listener_shutdown() {
        let config = make_valid_config();
        let listener = ShadowsocksInboundListener::new(config).await.unwrap();
        let mut shutdown_rx = listener.subscribe_shutdown();

        assert!(listener.is_active());

        listener.shutdown();

        assert!(!listener.is_active());
        assert!(shutdown_rx.recv().await.is_ok());
    }

    #[test]
    fn test_stats() {
        let stats = ShadowsocksInboundStats::new();

        assert_eq!(stats.connections_accepted.load(Ordering::Relaxed), 0);
        assert_eq!(stats.active_connections.load(Ordering::Relaxed), 0);

        stats.connections_accepted.fetch_add(5, Ordering::Relaxed);
        stats.record_bytes_received(1000);
        stats.record_bytes_sent(500);

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.connections_accepted, 5);
        assert_eq!(snapshot.bytes_received, 1000);
        assert_eq!(snapshot.bytes_sent, 500);
    }

    #[test]
    fn test_stats_snapshot_serialization() {
        let snapshot = ShadowsocksInboundStatsSnapshot {
            connections_accepted: 100,
            active_connections: 5,
            protocol_errors: 2,
            bytes_received: 10000,
            bytes_sent: 5000,
        };

        let json = serde_json::to_string(&snapshot).unwrap();
        assert!(json.contains("100"));
        assert!(json.contains("10000"));

        let deserialized: ShadowsocksInboundStatsSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.connections_accepted, snapshot.connections_accepted);
    }

    #[tokio::test]
    async fn test_listener_debug() {
        let config = make_valid_config();
        let listener = ShadowsocksInboundListener::new(config).await.unwrap();

        let debug_str = format!("{:?}", listener);
        assert!(debug_str.contains("ShadowsocksInboundListener"));
        assert!(debug_str.contains("127.0.0.1"));
    }

    #[test]
    fn test_connection_guard_increment_on_create() {
        let stats = Arc::new(ShadowsocksInboundStats::new());
        assert_eq!(stats.active_connections.load(Ordering::Relaxed), 0);

        let _guard = ConnectionGuard::new(Arc::clone(&stats));
        assert_eq!(stats.active_connections.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_connection_guard_decrement_on_drop() {
        let stats = Arc::new(ShadowsocksInboundStats::new());

        {
            let _guard = ConnectionGuard::new(Arc::clone(&stats));
            assert_eq!(stats.active_connections.load(Ordering::Relaxed), 1);
        }

        // After guard is dropped, count should be decremented
        assert_eq!(stats.active_connections.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_connection_guard_multiple() {
        let stats = Arc::new(ShadowsocksInboundStats::new());

        let guard1 = ConnectionGuard::new(Arc::clone(&stats));
        assert_eq!(stats.active_connections.load(Ordering::Relaxed), 1);

        let guard2 = ConnectionGuard::new(Arc::clone(&stats));
        assert_eq!(stats.active_connections.load(Ordering::Relaxed), 2);

        drop(guard1);
        assert_eq!(stats.active_connections.load(Ordering::Relaxed), 1);

        drop(guard2);
        assert_eq!(stats.active_connections.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_connection_guard_clone() {
        let stats = Arc::new(ShadowsocksInboundStats::new());

        let guard1 = ConnectionGuard::new(Arc::clone(&stats));
        assert_eq!(stats.active_connections.load(Ordering::Relaxed), 1);

        let guard2 = guard1.clone();
        assert_eq!(stats.active_connections.load(Ordering::Relaxed), 2);

        drop(guard1);
        assert_eq!(stats.active_connections.load(Ordering::Relaxed), 1);

        drop(guard2);
        assert_eq!(stats.active_connections.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_connection_guard_stats_access() {
        let stats = Arc::new(ShadowsocksInboundStats::new());
        stats.connections_accepted.fetch_add(10, Ordering::Relaxed);

        let guard = ConnectionGuard::new(Arc::clone(&stats));

        assert_eq!(guard.stats().connections_accepted.load(Ordering::Relaxed), 10);
        assert_eq!(guard.stats().active_connections.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_connection_guard_debug() {
        let stats = Arc::new(ShadowsocksInboundStats::new());
        let guard = ConnectionGuard::new(stats);

        let debug_str = format!("{:?}", guard);
        assert!(debug_str.contains("ConnectionGuard"));
    }
}
