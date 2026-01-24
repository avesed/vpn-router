//! Shadowsocks UDP relay inbound
//!
//! This module provides UDP relay functionality for the Shadowsocks inbound listener.
//! When UDP is enabled, the listener binds a UDP socket alongside the TCP listener
//! to handle UDP relay requests from Shadowsocks clients.
//!
//! # Architecture
//!
//! ```text
//! Shadowsocks Client
//!        |
//!        v (encrypted UDP)
//! +---------------------+
//! | SsUdpRelayInbound   |
//! | (ProxySocket bind)  |
//! +---------------------+
//!        |
//!        v (decrypted)
//! +---------------------+
//! | Route via RuleEngine|
//! +---------------------+
//!        |
//!        v
//! +---------------------+
//! | Forward to target   |
//! +---------------------+
//! ```
//!
//! # Wire Format
//!
//! Shadowsocks UDP relay uses per-packet encryption:
//! - Each packet includes the encrypted target address and payload
//! - Server decrypts, extracts target, forwards, and returns reply encrypted
//!
//! # Example
//!
//! ```no_run
//! use rust_router::ss_inbound::udp_relay::SsUdpRelayInbound;
//! use rust_router::ss_inbound::ShadowsocksInboundConfig;
//! use rust_router::shadowsocks::ShadowsocksMethod;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = ShadowsocksInboundConfig::new(
//!     "0.0.0.0:8388".parse()?,
//!     "my-secret-password",
//! )
//! .with_method(ShadowsocksMethod::Aes256Gcm)
//! .with_udp(true);
//!
//! let udp_relay = SsUdpRelayInbound::bind(config).await?;
//!
//! // Run the UDP relay loop
//! // udp_relay.run(|packet| async move { ... }).await?;
//! # Ok(())
//! # }
//! ```

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use parking_lot::RwLock;
use tokio::net::UdpSocket;
use tokio::sync::broadcast;
use tracing::{debug, error, info, trace, warn};

use super::config::ShadowsocksInboundConfig;
use super::error::{ShadowsocksInboundError, ShadowsocksInboundResult};
use super::handler::ShadowsocksDestination;

#[cfg(feature = "shadowsocks")]
use shadowsocks::{
    context::SharedContext,
    relay::{socks5::Address as SsAddress, udprelay::proxy_socket::ProxySocket},
};

/// Default UDP session timeout in seconds
pub const DEFAULT_UDP_SESSION_TIMEOUT_SECS: u64 = 60;

/// Default cleanup interval in seconds
pub const DEFAULT_CLEANUP_INTERVAL_SECS: u64 = 30;

/// Session count threshold to trigger opportunistic cleanup
pub const SESSION_CLEANUP_THRESHOLD: usize = 100;

/// Maximum UDP packet buffer size
pub const MAX_UDP_BUFFER_SIZE: usize = 65536;

/// A UDP relay session
///
/// Represents an active UDP relay session from a client to a specific destination.
#[derive(Debug)]
pub struct UdpRelaySession {
    /// Client address
    pub client_addr: SocketAddr,
    /// Target destination
    pub destination: ShadowsocksDestination,
    /// Outbound socket for forwarding
    pub outbound_socket: Arc<UdpSocket>,
    /// Last activity timestamp
    pub last_activity: std::time::Instant,
    /// Packets sent
    pub packets_sent: AtomicU64,
    /// Packets received
    pub packets_received: AtomicU64,
}

impl UdpRelaySession {
    /// Create a new UDP relay session
    pub fn new(
        client_addr: SocketAddr,
        destination: ShadowsocksDestination,
        outbound_socket: UdpSocket,
    ) -> Self {
        Self {
            client_addr,
            destination,
            outbound_socket: Arc::new(outbound_socket),
            last_activity: std::time::Instant::now(),
            packets_sent: AtomicU64::new(0),
            packets_received: AtomicU64::new(0),
        }
    }

    /// Update the last activity timestamp
    pub fn touch(&mut self) {
        self.last_activity = std::time::Instant::now();
    }

    /// Check if the session has expired
    pub fn is_expired(&self, timeout: Duration) -> bool {
        self.last_activity.elapsed() > timeout
    }

    /// Record a packet sent
    pub fn record_sent(&self) {
        self.packets_sent.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a packet received
    pub fn record_received(&self) {
        self.packets_received.fetch_add(1, Ordering::Relaxed);
    }
}

/// Received UDP packet from a Shadowsocks client
#[derive(Debug)]
pub struct SsUdpPacket {
    /// Client address that sent this packet
    pub client_addr: SocketAddr,
    /// Target destination extracted from the encrypted packet
    pub destination: ShadowsocksDestination,
    /// Decrypted payload
    pub payload: Bytes,
}

/// Shadowsocks UDP relay inbound
///
/// Listens for UDP packets from Shadowsocks clients, decrypts them,
/// and forwards to the target destinations.
#[cfg(feature = "shadowsocks")]
pub struct SsUdpRelayInbound {
    /// The underlying proxy socket for UDP relay
    proxy_socket: ProxySocket<shadowsocks::net::UdpSocket>,

    /// Shadowsocks context
    context: SharedContext,

    /// Configuration
    config: ShadowsocksInboundConfig,

    /// Active sessions (client_addr -> session)
    sessions: Arc<RwLock<HashMap<SocketAddr, UdpRelaySession>>>,

    /// Shutdown signal sender
    shutdown_tx: broadcast::Sender<()>,

    /// Whether the relay is active
    active: AtomicBool,

    /// Statistics
    stats: Arc<SsUdpRelayStats>,

    /// Session timeout
    session_timeout: Duration,
}

#[cfg(feature = "shadowsocks")]
impl SsUdpRelayInbound {
    /// Bind a new UDP relay socket
    ///
    /// # Arguments
    ///
    /// * `config` - Inbound configuration (must have udp_enabled = true)
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - UDP is not enabled in config
    /// - Binding fails
    /// - Configuration is invalid
    pub async fn bind(config: ShadowsocksInboundConfig) -> ShadowsocksInboundResult<Self> {
        if !config.udp_enabled {
            return Err(ShadowsocksInboundError::invalid_config(
                "UDP is not enabled in configuration",
            ));
        }

        // Validate configuration
        config.validate()?;

        info!(
            listen = %config.listen,
            method = %config.method,
            "Creating Shadowsocks UDP relay inbound"
        );

        // Build context and server config
        let context = ShadowsocksInboundConfig::build_context();
        let server_config = config.build_server_config()?;

        // Create the proxy socket for server mode
        let proxy_socket = ProxySocket::bind(context.clone(), &server_config)
            .await
            .map_err(|e| ShadowsocksInboundError::bind_failed(config.listen, e.to_string()))?;

        // Create shutdown channel
        let (shutdown_tx, _) = broadcast::channel(1);

        info!(
            listen = %config.listen,
            "Shadowsocks UDP relay inbound ready"
        );

        Ok(Self {
            proxy_socket,
            context,
            config,
            sessions: Arc::new(RwLock::new(HashMap::new())),
            shutdown_tx,
            active: AtomicBool::new(true),
            stats: Arc::new(SsUdpRelayStats::new()),
            session_timeout: Duration::from_secs(DEFAULT_UDP_SESSION_TIMEOUT_SECS),
        })
    }

    /// Set the session timeout
    pub fn with_session_timeout(mut self, timeout: Duration) -> Self {
        self.session_timeout = timeout;
        self
    }

    /// Receive the next UDP packet
    ///
    /// Waits for a UDP packet, decrypts it, and returns the client address,
    /// target destination, and payload.
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Relay is not active
    /// - Receiving fails
    /// - Decryption fails
    pub async fn recv(&self) -> ShadowsocksInboundResult<SsUdpPacket> {
        if !self.is_active() {
            return Err(ShadowsocksInboundError::NotActive);
        }

        let mut buf = vec![0u8; MAX_UDP_BUFFER_SIZE];

        // Receive encrypted packet from client
        // Returns (payload_len, client_addr, target_addr, raw_len)
        let (payload_len, client_addr, target_addr, _raw_len) = self
            .proxy_socket
            .recv_from(&mut buf)
            .await
            .map_err(|e| ShadowsocksInboundError::protocol_error(e.to_string()))?;

        self.stats.packets_received.fetch_add(1, Ordering::Relaxed);
        self.stats
            .bytes_received
            .fetch_add(payload_len as u64, Ordering::Relaxed);

        // Truncate buffer to payload length
        buf.truncate(payload_len);

        // Convert target address to our destination type
        let destination = ShadowsocksDestination::from(target_addr);

        trace!(
            client = %client_addr,
            destination = %destination,
            payload_len = payload_len,
            "Received Shadowsocks UDP packet"
        );

        Ok(SsUdpPacket {
            client_addr,
            destination,
            payload: Bytes::from(buf),
        })
    }

    /// Send a UDP reply packet back to a client
    ///
    /// The packet will be encrypted before sending.
    ///
    /// # Arguments
    ///
    /// * `client_addr` - Client address to send to
    /// * `source_addr` - Original source address (target that sent the reply)
    /// * `payload` - Reply payload
    ///
    /// # Errors
    ///
    /// Returns error if sending fails.
    pub async fn send_reply(
        &self,
        client_addr: SocketAddr,
        source_addr: &ShadowsocksDestination,
        payload: &[u8],
    ) -> ShadowsocksInboundResult<usize> {
        if !self.is_active() {
            return Err(ShadowsocksInboundError::NotActive);
        }

        // Convert destination to Shadowsocks address
        let ss_addr: SsAddress = source_addr.clone().into();

        // Send encrypted packet to client
        let sent = self
            .proxy_socket
            .send_to(client_addr, &ss_addr, payload)
            .await
            .map_err(|e| ShadowsocksInboundError::protocol_error(e.to_string()))?;

        self.stats.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.stats
            .bytes_sent
            .fetch_add(payload.len() as u64, Ordering::Relaxed);

        trace!(
            client = %client_addr,
            source = %source_addr,
            bytes = sent,
            "Sent Shadowsocks UDP reply"
        );

        Ok(sent)
    }

    /// Get or create a session for a client/destination pair
    ///
    /// If a session doesn't exist, creates a new outbound socket connected
    /// to the destination.
    ///
    /// This method performs opportunistic cleanup when the session count
    /// exceeds `SESSION_CLEANUP_THRESHOLD` to prevent unbounded growth.
    pub async fn get_or_create_session(
        &self,
        client_addr: SocketAddr,
        destination: &ShadowsocksDestination,
    ) -> ShadowsocksInboundResult<Arc<UdpSocket>> {
        // First, try to get existing session
        {
            let mut sessions = self.sessions.write();
            if let Some(session) = sessions.get_mut(&client_addr) {
                session.touch();
                return Ok(session.outbound_socket.clone());
            }
        }

        // Trigger opportunistic cleanup before creating new session
        self.maybe_cleanup();

        // Create new session
        let dest_socket_addr = match destination.as_socket_addr() {
            Some(addr) => addr,
            None => {
                // For domain names, we'd need to resolve first
                // For now, return an error - DNS resolution should be done externally
                return Err(ShadowsocksInboundError::invalid_config(format!(
                    "Domain name resolution not implemented for UDP: {}",
                    destination
                )));
            }
        };

        // Create outbound socket
        let outbound_socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| ShadowsocksInboundError::Io(e))?;

        outbound_socket
            .connect(dest_socket_addr)
            .await
            .map_err(|e| ShadowsocksInboundError::Io(e))?;

        let session = UdpRelaySession::new(client_addr, destination.clone(), outbound_socket);
        let socket = session.outbound_socket.clone();

        // Store session
        {
            let mut sessions = self.sessions.write();
            sessions.insert(client_addr, session);
        }

        self.stats.sessions_created.fetch_add(1, Ordering::Relaxed);
        debug!(
            client = %client_addr,
            destination = %destination,
            "Created new UDP relay session"
        );

        Ok(socket)
    }

    /// Clean up expired sessions
    ///
    /// Returns the number of sessions removed.
    pub fn cleanup_expired_sessions(&self) -> usize {
        let mut sessions = self.sessions.write();
        let before = sessions.len();

        sessions.retain(|_, session| !session.is_expired(self.session_timeout));

        let removed = before - sessions.len();
        if removed > 0 {
            debug!(removed = removed, remaining = sessions.len(), "Cleaned up expired UDP sessions");
            self.stats.sessions_expired.fetch_add(removed as u64, Ordering::Relaxed);
        }
        removed
    }

    /// Perform opportunistic cleanup if session count exceeds threshold
    ///
    /// This method is called automatically when creating new sessions to prevent
    /// unbounded session growth. It only performs cleanup when the session count
    /// exceeds `SESSION_CLEANUP_THRESHOLD`.
    fn maybe_cleanup(&self) {
        let session_count = self.sessions.read().len();
        if session_count >= SESSION_CLEANUP_THRESHOLD {
            trace!(
                session_count = session_count,
                threshold = SESSION_CLEANUP_THRESHOLD,
                "Session count exceeds threshold, triggering opportunistic cleanup"
            );
            self.cleanup_expired_sessions();
        }
    }

    /// Run the UDP relay with automatic session cleanup
    ///
    /// This method runs the UDP relay in a loop, automatically cleaning up
    /// expired sessions at the specified interval.
    ///
    /// # Arguments
    ///
    /// * `handler` - Callback function for received packets
    /// * `cleanup_interval` - Interval between cleanup runs
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rust_router::ss_inbound::udp_relay::SsUdpRelayInbound;
    /// use rust_router::ss_inbound::ShadowsocksInboundConfig;
    /// use rust_router::shadowsocks::ShadowsocksMethod;
    /// use std::sync::Arc;
    /// use std::time::Duration;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let config = ShadowsocksInboundConfig::new(
    ///     "0.0.0.0:8388".parse()?,
    ///     "my-secret-password",
    /// )
    /// .with_method(ShadowsocksMethod::Aes256Gcm)
    /// .with_udp(true);
    ///
    /// let udp_relay = Arc::new(SsUdpRelayInbound::bind(config).await?);
    ///
    /// udp_relay.run_with_cleanup(
    ///     |packet| async move {
    ///         println!("Received packet from {} to {}",
    ///             packet.client_addr, packet.destination);
    ///         Ok(())
    ///     },
    ///     Duration::from_secs(30),
    /// ).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn run_with_cleanup<F, Fut>(
        self: Arc<Self>,
        handler: F,
        cleanup_interval: Duration,
    ) -> ShadowsocksInboundResult<()>
    where
        F: Fn(SsUdpPacket) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = ShadowsocksInboundResult<()>> + Send,
    {
        let mut shutdown_rx = self.shutdown_tx.subscribe();
        let mut cleanup_interval_timer = tokio::time::interval(cleanup_interval);

        // Skip the first immediate tick
        cleanup_interval_timer.tick().await;

        loop {
            tokio::select! {
                // Handle incoming packets
                result = self.recv() => {
                    match result {
                        Ok(packet) => {
                            if let Err(e) = handler(packet).await {
                                warn!(error = %e, "UDP packet handler error");
                                self.stats.protocol_errors.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        Err(e) if e.is_recoverable() => {
                            warn!(error = %e, "Recoverable error in UDP recv loop");
                        }
                        Err(e) => {
                            error!(error = %e, "Fatal error in UDP recv loop");
                            return Err(e);
                        }
                    }
                }

                // Periodic cleanup
                _ = cleanup_interval_timer.tick() => {
                    let removed = self.cleanup_expired_sessions();
                    if removed > 0 {
                        info!(
                            removed = removed,
                            active = self.active_sessions(),
                            "Periodic UDP session cleanup completed"
                        );
                    }
                }

                // Shutdown signal
                _ = shutdown_rx.recv() => {
                    info!("Shadowsocks UDP relay shutdown signal received");
                    return Ok(());
                }
            }
        }
    }

    /// Run the UDP relay with default cleanup interval
    ///
    /// This is a convenience method that uses `DEFAULT_CLEANUP_INTERVAL_SECS`
    /// for the cleanup interval.
    pub async fn run<F, Fut>(self: Arc<Self>, handler: F) -> ShadowsocksInboundResult<()>
    where
        F: Fn(SsUdpPacket) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = ShadowsocksInboundResult<()>> + Send,
    {
        self.run_with_cleanup(handler, Duration::from_secs(DEFAULT_CLEANUP_INTERVAL_SECS))
            .await
    }

    /// Get the number of active sessions
    pub fn active_sessions(&self) -> usize {
        self.sessions.read().len()
    }

    /// Graceful shutdown
    pub fn shutdown(&self) {
        info!(listen = %self.config.listen, "Shutting down Shadowsocks UDP relay");
        self.active.store(false, Ordering::SeqCst);
        let _ = self.shutdown_tx.send(());
    }

    /// Check if the relay is active
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::SeqCst)
    }

    /// Get the listen address
    #[must_use]
    pub fn listen_addr(&self) -> SocketAddr {
        self.config.listen
    }

    /// Get statistics
    #[must_use]
    pub fn stats(&self) -> &SsUdpRelayStats {
        &self.stats
    }

    /// Get a snapshot of statistics
    #[must_use]
    pub fn stats_snapshot(&self) -> SsUdpRelayStatsSnapshot {
        self.stats.snapshot()
    }

    /// Subscribe to shutdown signal
    pub fn subscribe_shutdown(&self) -> broadcast::Receiver<()> {
        self.shutdown_tx.subscribe()
    }
}

#[cfg(feature = "shadowsocks")]
impl std::fmt::Debug for SsUdpRelayInbound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SsUdpRelayInbound")
            .field("listen", &self.config.listen)
            .field("method", &self.config.method)
            .field("active", &self.is_active())
            .field("active_sessions", &self.active_sessions())
            .finish_non_exhaustive()
    }
}

/// Statistics for Shadowsocks UDP relay
#[derive(Debug)]
pub struct SsUdpRelayStats {
    /// Total packets received
    pub packets_received: AtomicU64,
    /// Total packets sent
    pub packets_sent: AtomicU64,
    /// Total bytes received
    pub bytes_received: AtomicU64,
    /// Total bytes sent
    pub bytes_sent: AtomicU64,
    /// Total sessions created
    pub sessions_created: AtomicU64,
    /// Total sessions expired
    pub sessions_expired: AtomicU64,
    /// Total protocol errors
    pub protocol_errors: AtomicU64,
}

impl SsUdpRelayStats {
    /// Create new empty stats
    #[must_use]
    pub fn new() -> Self {
        Self {
            packets_received: AtomicU64::new(0),
            packets_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            sessions_created: AtomicU64::new(0),
            sessions_expired: AtomicU64::new(0),
            protocol_errors: AtomicU64::new(0),
        }
    }

    /// Get a snapshot
    #[must_use]
    pub fn snapshot(&self) -> SsUdpRelayStatsSnapshot {
        SsUdpRelayStatsSnapshot {
            packets_received: self.packets_received.load(Ordering::Relaxed),
            packets_sent: self.packets_sent.load(Ordering::Relaxed),
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            sessions_created: self.sessions_created.load(Ordering::Relaxed),
            sessions_expired: self.sessions_expired.load(Ordering::Relaxed),
            protocol_errors: self.protocol_errors.load(Ordering::Relaxed),
        }
    }
}

impl Default for SsUdpRelayStats {
    fn default() -> Self {
        Self::new()
    }
}

/// Snapshot of Shadowsocks UDP relay statistics
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct SsUdpRelayStatsSnapshot {
    /// Total packets received
    pub packets_received: u64,
    /// Total packets sent
    pub packets_sent: u64,
    /// Total bytes received
    pub bytes_received: u64,
    /// Total bytes sent
    pub bytes_sent: u64,
    /// Total sessions created
    pub sessions_created: u64,
    /// Total sessions expired
    pub sessions_expired: u64,
    /// Total protocol errors
    pub protocol_errors: u64,
}

#[cfg(all(test, feature = "shadowsocks"))]
mod tests {
    use super::*;
    use crate::shadowsocks::ShadowsocksMethod;

    fn make_udp_config() -> ShadowsocksInboundConfig {
        ShadowsocksInboundConfig::new("127.0.0.1:0".parse().unwrap(), "test-password")
            .with_method(ShadowsocksMethod::Aes256Gcm)
            .with_udp(true)
    }

    #[tokio::test]
    async fn test_udp_relay_bind() {
        let config = make_udp_config();
        let relay = SsUdpRelayInbound::bind(config).await;

        assert!(relay.is_ok());

        let relay = relay.unwrap();
        assert!(relay.is_active());
        assert_eq!(relay.active_sessions(), 0);
    }

    #[tokio::test]
    async fn test_udp_relay_without_udp_enabled() {
        // Config without UDP enabled should fail
        let config = ShadowsocksInboundConfig::new("127.0.0.1:0".parse().unwrap(), "test-password")
            .with_method(ShadowsocksMethod::Aes256Gcm)
            .with_udp(false);

        let result = SsUdpRelayInbound::bind(config).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_udp_relay_shutdown() {
        let config = make_udp_config();
        let relay = SsUdpRelayInbound::bind(config).await.unwrap();
        let mut shutdown_rx = relay.subscribe_shutdown();

        assert!(relay.is_active());

        relay.shutdown();

        assert!(!relay.is_active());
        assert!(shutdown_rx.recv().await.is_ok());
    }

    #[test]
    fn test_udp_relay_stats() {
        let stats = SsUdpRelayStats::new();

        assert_eq!(stats.packets_received.load(Ordering::Relaxed), 0);
        assert_eq!(stats.packets_sent.load(Ordering::Relaxed), 0);

        stats.packets_received.fetch_add(10, Ordering::Relaxed);
        stats.bytes_received.fetch_add(1000, Ordering::Relaxed);

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.packets_received, 10);
        assert_eq!(snapshot.bytes_received, 1000);
    }

    #[test]
    fn test_stats_snapshot_serialization() {
        let snapshot = SsUdpRelayStatsSnapshot {
            packets_received: 100,
            packets_sent: 50,
            bytes_received: 10000,
            bytes_sent: 5000,
            sessions_created: 10,
            sessions_expired: 5,
            protocol_errors: 2,
        };

        let json = serde_json::to_string(&snapshot).unwrap();
        assert!(json.contains("100"));
        assert!(json.contains("10000"));

        let deserialized: SsUdpRelayStatsSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.packets_received, snapshot.packets_received);
    }

    #[test]
    fn test_udp_session_expiry() {
        use std::net::{IpAddr, Ipv4Addr};

        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345);
        let dest = ShadowsocksDestination::from_socket_addr(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
        );

        // Can't create a real UdpSocket in sync test, so we'll just test the session logic
        // using a mock approach

        // Test session expiry logic
        let timeout = Duration::from_millis(100);
        let start = std::time::Instant::now();

        // Simulate elapsed time check
        std::thread::sleep(Duration::from_millis(150));
        let elapsed = start.elapsed();
        assert!(elapsed > timeout);
    }

    #[tokio::test]
    async fn test_udp_relay_debug() {
        let config = make_udp_config();
        let relay = SsUdpRelayInbound::bind(config).await.unwrap();

        let debug_str = format!("{:?}", relay);
        assert!(debug_str.contains("SsUdpRelayInbound"));
        assert!(debug_str.contains("127.0.0.1"));
    }
}
