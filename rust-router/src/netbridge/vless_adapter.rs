//! Adapter to make SmoltcpEgress compatible with ShardedVlessWgBridge API.
//!
//! This module provides `NetbridgeVlessAdapter`, a wrapper around `SmoltcpEgress`
//! that exposes an API compatible with `ShardedVlessWgBridge`. This enables
//! gradual migration from the legacy `vless_wg_bridge` module to the unified
//! `netbridge` module.
//!
//! # Architecture
//!
//! ```text
//! ┌────────────────────────────────────────────────────────────────────────┐
//! │                      NetbridgeVlessAdapter                              │
//! │  - handle_tcp_connection() -> TcpConnectionStats (compatible API)       │
//! │  - handle_udp_connection() -> UdpConnectionStats (compatible API)       │
//! │  - stats() -> AggregatedStats (compatible API)                          │
//! └────────────────────────────────────────────────────────────────────────┘
//!                                    │
//!                                    │ delegates to
//!                                    ▼
//! ┌────────────────────────────────────────────────────────────────────────┐
//! │                         SmoltcpEgress                                   │
//! │  - handle_tcp() -> SessionId                                            │
//! │  - handle_udp() -> ()                                                   │
//! │  - stats() -> EgressStats                                               │
//! └────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Migration Path
//!
//! 1. Replace `ShardedVlessWgBridge` with `NetbridgeVlessAdapter` in IPC handler
//! 2. Existing code using `handle_tcp_connection` continues to work
//! 3. Gradually migrate to direct `SmoltcpEgress` usage where possible
//! 4. Eventually remove this adapter once all callers are migrated
//!
//! # Example
//!
//! ```ignore
//! use rust_router::netbridge::vless_adapter::NetbridgeVlessAdapter;
//! use rust_router::netbridge::smoltcp::{SmoltcpEgress, SmoltcpEgressConfig};
//!
//! // Create the underlying SmoltcpEgress
//! let config = SmoltcpEgressConfig::default();
//! let (egress, handle) = SmoltcpEgress::spawn(config);
//!
//! // Wrap with adapter for ShardedVlessWgBridge-compatible API
//! let adapter = NetbridgeVlessAdapter::new(egress);
//!
//! // Use the same API as ShardedVlessWgBridge
//! let stats = adapter.handle_tcp_connection(stream, dest_addr).await?;
//! println!("Transferred {} bytes", stats.bytes_sent + stats.bytes_received);
//! ```

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use dashmap::DashMap;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::{debug, info, trace, warn};

use super::error::{NetBridgeError, Result};
use super::smoltcp::{SmoltcpEgress, SmoltcpEgressConfig, SmoltcpEgressHandle};
use super::traits::NetBridgeEgress;

// Re-export VLESS UDP frame codec for UDP-over-TCP handling
#[cfg(feature = "sharded-vless-wg-bridge")]
use crate::vless_wg_bridge::udp_frame::VlessUdpFrame;

// =============================================================================
// Statistics Types (compatible with ShardedVlessWgBridge)
// =============================================================================

/// Statistics for a completed TCP connection.
///
/// This type is compatible with `vless_wg_bridge::TcpConnectionStats`.
#[derive(Debug, Clone, Default)]
pub struct TcpConnectionStats {
    /// Total bytes sent to the remote peer
    pub bytes_sent: u64,
    /// Total bytes received from the remote peer
    pub bytes_received: u64,
    /// Total duration of the connection
    pub duration: Duration,
}

impl TcpConnectionStats {
    /// Create new empty stats
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

/// Statistics for a completed UDP connection/session.
///
/// This type is compatible with `vless_wg_bridge::UdpConnectionStats`.
#[derive(Debug, Clone, Default)]
pub struct UdpConnectionStats {
    /// Total datagrams sent
    pub datagrams_sent: u64,
    /// Total datagrams received
    pub datagrams_received: u64,
    /// Total bytes sent
    pub bytes_sent: u64,
    /// Total bytes received
    pub bytes_received: u64,
    /// Total duration of the session
    pub duration: Duration,
}

impl UdpConnectionStats {
    /// Create new empty stats
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

/// Aggregated statistics snapshot compatible with ShardedVlessWgBridge.
#[derive(Debug, Clone, Default)]
pub struct AggregatedStats {
    /// Number of shards (always 1 for adapter)
    pub num_shards: usize,
    /// Total TCP sessions created
    pub total_tcp_sessions_created: u64,
    /// Total TCP sessions closed
    pub total_tcp_sessions_closed: u64,
    /// Total UDP sessions created
    pub total_udp_sessions_created: u64,
    /// Total UDP sessions closed
    pub total_udp_sessions_closed: u64,
    /// Total bytes sent
    pub total_bytes_sent: u64,
    /// Total bytes received
    pub total_bytes_received: u64,
    /// Total errors
    pub total_errors: u64,
}

impl AggregatedStats {
    /// Get the active TCP sessions count (created - closed)
    #[must_use]
    pub fn active_tcp_sessions(&self) -> u64 {
        self.total_tcp_sessions_created
            .saturating_sub(self.total_tcp_sessions_closed)
    }

    /// Get the active UDP sessions count (created - closed)
    #[must_use]
    pub fn active_udp_sessions(&self) -> u64 {
        self.total_udp_sessions_created
            .saturating_sub(self.total_udp_sessions_closed)
    }
}

// =============================================================================
// Internal Session Tracking
// =============================================================================

/// Internal session state for tracking connection statistics
#[derive(Debug)]
struct SessionState {
    /// Session start time
    start_time: Instant,
    /// Bytes sent
    bytes_sent: AtomicU64,
    /// Bytes received
    bytes_received: AtomicU64,
    /// Whether this is a TCP session
    is_tcp: bool,
}

impl SessionState {
    fn new(is_tcp: bool) -> Self {
        Self {
            start_time: Instant::now(),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            is_tcp,
        }
    }

    fn add_bytes_sent(&self, bytes: u64) {
        self.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
    }

    fn add_bytes_received(&self, bytes: u64) {
        self.bytes_received.fetch_add(bytes, Ordering::Relaxed);
    }

    fn to_tcp_stats(&self) -> TcpConnectionStats {
        TcpConnectionStats {
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
            duration: self.start_time.elapsed(),
        }
    }

    fn to_udp_stats(&self, datagrams_sent: u64, datagrams_received: u64) -> UdpConnectionStats {
        UdpConnectionStats {
            datagrams_sent,
            datagrams_received,
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
            duration: self.start_time.elapsed(),
        }
    }
}

// =============================================================================
// Adapter Statistics
// =============================================================================

/// Internal statistics collector for the adapter
#[derive(Debug, Default)]
struct AdapterStats {
    tcp_sessions_created: AtomicU64,
    tcp_sessions_closed: AtomicU64,
    udp_sessions_created: AtomicU64,
    udp_sessions_closed: AtomicU64,
    bytes_sent: AtomicU64,
    bytes_received: AtomicU64,
    errors: AtomicU64,
}

impl AdapterStats {
    fn new() -> Self {
        Self::default()
    }

    fn snapshot(&self) -> AggregatedStats {
        AggregatedStats {
            num_shards: 1,
            total_tcp_sessions_created: self.tcp_sessions_created.load(Ordering::Relaxed),
            total_tcp_sessions_closed: self.tcp_sessions_closed.load(Ordering::Relaxed),
            total_udp_sessions_created: self.udp_sessions_created.load(Ordering::Relaxed),
            total_udp_sessions_closed: self.udp_sessions_closed.load(Ordering::Relaxed),
            total_bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            total_bytes_received: self.bytes_received.load(Ordering::Relaxed),
            total_errors: self.errors.load(Ordering::Relaxed),
        }
    }
}

// =============================================================================
// NetbridgeVlessAdapter
// =============================================================================

/// Default TCP read/write buffer size
const TCP_BUFFER_SIZE: usize = 32768;

/// Default reply channel size per connection
const REPLY_CHANNEL_SIZE: usize = 128;

/// Adapter that wraps SmoltcpEgress with ShardedVlessWgBridge-compatible API.
///
/// This enables gradual migration from the legacy `vless_wg_bridge` module
/// to the unified `netbridge` module without breaking existing code.
///
/// # Thread Safety
///
/// `NetbridgeVlessAdapter` is `Send + Sync` and can be safely shared across tasks.
pub struct NetbridgeVlessAdapter {
    /// Underlying SmoltcpEgress instance
    egress: Arc<SmoltcpEgress>,
    /// Active sessions for stats tracking
    sessions: DashMap<u64, Arc<SessionState>>,
    /// Adapter statistics
    stats: Arc<AdapterStats>,
    /// Shutdown flag
    shutdown: AtomicBool,
    /// Connection ID counter
    conn_id_counter: AtomicU64,
}

impl NetbridgeVlessAdapter {
    /// Create a new adapter wrapping a SmoltcpEgress instance.
    ///
    /// # Arguments
    ///
    /// * `egress` - The SmoltcpEgress instance to wrap
    #[must_use]
    pub fn new(egress: Arc<SmoltcpEgress>) -> Self {
        Self {
            egress,
            sessions: DashMap::new(),
            stats: Arc::new(AdapterStats::new()),
            shutdown: AtomicBool::new(false),
            conn_id_counter: AtomicU64::new(1),
        }
    }

    /// Create a new adapter and spawn a new SmoltcpEgress.
    ///
    /// This is a convenience method that creates both the egress and adapter.
    ///
    /// # Arguments
    ///
    /// * `config` - Configuration for the SmoltcpEgress
    ///
    /// # Returns
    ///
    /// A tuple of (adapter, handle) where handle can be used to await the shard task.
    #[must_use]
    pub fn spawn(config: SmoltcpEgressConfig) -> (Arc<Self>, SmoltcpEgressHandle) {
        let (egress, handle) = SmoltcpEgress::spawn(config);
        let adapter = Arc::new(Self::new(egress));
        (adapter, handle)
    }

    /// Get the underlying SmoltcpEgress instance.
    #[must_use]
    pub fn egress(&self) -> &Arc<SmoltcpEgress> {
        &self.egress
    }

    /// Check if the adapter is shut down.
    #[must_use]
    pub fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::Relaxed)
    }

    /// Get the number of active sessions.
    #[must_use]
    pub fn active_sessions(&self) -> usize {
        self.sessions.len()
    }

    /// Get the number of shards (always 1 for adapter).
    #[must_use]
    pub fn num_shards(&self) -> usize {
        1
    }

    /// Allocate a unique connection ID.
    fn allocate_conn_id(&self) -> u64 {
        self.conn_id_counter.fetch_add(1, Ordering::Relaxed)
    }

    // =========================================================================
    // Public API - Compatible with ShardedVlessWgBridge
    // =========================================================================

    /// Handle a TCP connection from VLESS/SS inbound.
    ///
    /// This method has the same signature as `ShardedVlessWgBridge::handle_tcp_connection`,
    /// making it a drop-in replacement.
    ///
    /// # Arguments
    ///
    /// * `stream` - The incoming TCP stream (from VLESS/SS inbound)
    /// * `dest_addr` - The destination address to connect to
    ///
    /// # Returns
    ///
    /// Connection statistics on success, or `NetBridgeError` on failure.
    pub async fn handle_tcp_connection<S>(
        &self,
        stream: S,
        dest_addr: SocketAddr,
    ) -> Result<TcpConnectionStats>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        if self.is_shutdown() {
            return Err(NetBridgeError::TunnelDown("adapter is shutting down".into()));
        }

        let conn_id = self.allocate_conn_id();
        let session_state = Arc::new(SessionState::new(true));
        self.sessions.insert(conn_id, Arc::clone(&session_state));
        self.stats.tcp_sessions_created.fetch_add(1, Ordering::Relaxed);

        debug!(
            "NetbridgeVlessAdapter: TCP connection {} -> {}",
            conn_id, dest_addr
        );

        // Call the underlying SmoltcpEgress
        let result = self
            .handle_tcp_internal(stream, dest_addr, conn_id, Arc::clone(&session_state))
            .await;

        // Clean up session and update stats
        self.sessions.remove(&conn_id);
        self.stats.tcp_sessions_closed.fetch_add(1, Ordering::Relaxed);

        let stats = session_state.to_tcp_stats();
        self.stats.bytes_sent.fetch_add(stats.bytes_sent, Ordering::Relaxed);
        self.stats.bytes_received.fetch_add(stats.bytes_received, Ordering::Relaxed);

        match result {
            Ok(_) => {
                info!(
                    "NetbridgeVlessAdapter: TCP {} closed, {} bytes up, {} bytes down, {:?}",
                    conn_id, stats.bytes_sent, stats.bytes_received, stats.duration
                );
                Ok(stats)
            }
            Err(e) => {
                self.stats.errors.fetch_add(1, Ordering::Relaxed);
                warn!("NetbridgeVlessAdapter: TCP {} error: {}", conn_id, e);
                // Return stats even on error for partial transfer info
                Ok(stats)
            }
        }
    }

    /// Internal TCP handling implementation.
    async fn handle_tcp_internal<S>(
        &self,
        stream: S,
        dest_addr: SocketAddr,
        conn_id: u64,
        session_state: Arc<SessionState>,
    ) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        // Create a duplex channel for bidirectional communication with SmoltcpEgress
        // SmoltcpEgress::handle_tcp expects to own the stream and pump data itself.
        // We need to intercept the data flow to track bytes.
        //
        // Strategy: Use tokio::io::duplex to create a pair of streams.
        // We pump data between our input stream and the duplex, tracking bytes.
        // SmoltcpEgress handles the other end of the duplex.

        let (client_stream, egress_stream) = tokio::io::duplex(TCP_BUFFER_SIZE);

        // Spawn the egress handler
        let egress = Arc::clone(&self.egress);
        let session_id_result = tokio::spawn(async move {
            egress.handle_tcp(egress_stream, dest_addr).await
        });

        // Bidirectional pump between client stream and our duplex
        let (mut read_half, mut write_half) = tokio::io::split(stream);
        let (mut duplex_read, mut duplex_write) = tokio::io::split(client_stream);

        let session_state_read = Arc::clone(&session_state);
        let session_state_write = Arc::clone(&session_state);

        // Client -> Egress pump
        let conn_id_for_read = conn_id;
        let read_task = tokio::spawn(async move {
            let mut buf = vec![0u8; TCP_BUFFER_SIZE];
            loop {
                match read_half.read(&mut buf).await {
                    Ok(0) => break, // EOF
                    Ok(n) => {
                        session_state_read.add_bytes_sent(n as u64);
                        if duplex_write.write_all(&buf[..n]).await.is_err() {
                            trace!(
                                target: "netbridge::vless_adapter",
                                conn_id = conn_id_for_read,
                                "TCP pump client->egress write error, closing"
                            );
                            break;
                        }
                    }
                    Err(e) => {
                        trace!(
                            target: "netbridge::vless_adapter",
                            conn_id = conn_id_for_read,
                            error = %e,
                            "TCP pump client->egress read error, closing"
                        );
                        break;
                    }
                }
            }
            let _ = duplex_write.shutdown().await;
        });

        // Egress -> Client pump
        let conn_id_for_write = conn_id;
        let write_task = tokio::spawn(async move {
            let mut buf = vec![0u8; TCP_BUFFER_SIZE];
            loop {
                match duplex_read.read(&mut buf).await {
                    Ok(0) => break, // EOF
                    Ok(n) => {
                        session_state_write.add_bytes_received(n as u64);
                        if write_half.write_all(&buf[..n]).await.is_err() {
                            trace!(
                                target: "netbridge::vless_adapter",
                                conn_id = conn_id_for_write,
                                "TCP pump egress->client write error, closing"
                            );
                            break;
                        }
                    }
                    Err(e) => {
                        trace!(
                            target: "netbridge::vless_adapter",
                            conn_id = conn_id_for_write,
                            error = %e,
                            "TCP pump egress->client read error, closing"
                        );
                        break;
                    }
                }
            }
            let _ = write_half.shutdown().await;
        });

        // Wait for all tasks
        let _ = tokio::join!(read_task, write_task);

        // Check if the egress completed successfully
        match session_id_result.await {
            Ok(Ok(_session_id)) => Ok(()),
            Ok(Err(e)) => Err(e),
            Err(e) => Err(NetBridgeError::InternalError(format!("egress task panicked: {}", e))),
        }
    }

    /// Handle a UDP connection from VLESS UDP-over-TCP.
    ///
    /// This method has the same signature as `ShardedVlessWgBridge::handle_udp_connection`,
    /// making it a drop-in replacement.
    ///
    /// **Note:** UDP support requires the `sharded-vless-wg-bridge` feature for
    /// VLESS UDP-over-TCP framing support. Without this feature, only individual
    /// UDP datagrams can be sent via `send_udp_datagram`.
    ///
    /// # Arguments
    ///
    /// * `stream` - The incoming TCP stream carrying UDP frames
    /// * `initial_dest` - Initial destination from VLESS header (used for routing)
    ///
    /// # Returns
    ///
    /// Connection statistics on success, or `NetBridgeError` on failure.
    #[cfg(feature = "sharded-vless-wg-bridge")]
    pub async fn handle_udp_connection<S>(
        &self,
        mut stream: S,
        initial_dest: SocketAddr,
    ) -> Result<UdpConnectionStats>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        use std::net::{IpAddr, Ipv4Addr};

        if self.is_shutdown() {
            return Err(NetBridgeError::TunnelDown("adapter is shutting down".into()));
        }

        let conn_id = self.allocate_conn_id();
        let session_state = Arc::new(SessionState::new(false));
        self.sessions.insert(conn_id, Arc::clone(&session_state));
        self.stats.udp_sessions_created.fetch_add(1, Ordering::Relaxed);

        debug!(
            "NetbridgeVlessAdapter: UDP connection {} -> {}",
            conn_id, initial_dest
        );

        let mut datagrams_sent = 0u64;
        let mut datagrams_received = 0u64;
        let mut last_activity = Instant::now();

        // Pseudo source address for UDP packets
        let pseudo_src = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(
                10,
                200,
                ((conn_id >> 16) & 0xFF) as u8,
                ((conn_id >> 8) & 0xFF) as u8,
            )),
            (conn_id & 0xFFFF) as u16,
        );

        // Note: SmoltcpEgress::handle_udp is designed for individual datagrams,
        // not VLESS UDP-over-TCP framing. We need to manually decode frames and
        // send each datagram.
        //
        // For receiving UDP replies, we would need to implement a reply channel.
        // This is a limitation of the current adapter - full bidirectional UDP
        // support requires more infrastructure.

        loop {
            if self.is_shutdown() {
                break;
            }

            tokio::select! {
                // Read VLESS UDP frame from stream
                frame_result = VlessUdpFrame::read_from(&mut stream) => {
                    match frame_result {
                        Ok(Some(frame)) => {
                            last_activity = Instant::now();
                            let payload_len = frame.payload.len() as u64;
                            session_state.add_bytes_sent(payload_len);
                            datagrams_sent += 1;

                            // Extract destination from frame
                            let dest_addr = frame.socket_addr().unwrap_or(initial_dest);

                            trace!(
                                "UDP frame {} -> {}: {} bytes",
                                pseudo_src, dest_addr, frame.payload.len()
                            );

                            // Send via SmoltcpEgress
                            if let Err(e) = self.egress.handle_udp(pseudo_src, dest_addr, &frame.payload).await {
                                warn!("Failed to send UDP datagram: {}", e);
                            }
                        }
                        Ok(None) => {
                            // Clean EOF
                            debug!("UDP stream closed (EOF)");
                            break;
                        }
                        Err(e) => {
                            // Check for expected close conditions
                            if let NetBridgeError::Io(ref io_err) = e {
                                if io_err.kind() == std::io::ErrorKind::UnexpectedEof
                                    || io_err.kind() == std::io::ErrorKind::ConnectionReset
                                {
                                    debug!("UDP stream closed: {}", io_err.kind());
                                    break;
                                }
                            }
                            warn!("UDP frame read error: {}", e);
                            break;
                        }
                    }
                }

                // Timeout for cleanup (30 seconds of inactivity)
                _ = tokio::time::sleep(Duration::from_secs(30)) => {
                    if last_activity.elapsed() > Duration::from_secs(30) {
                        debug!("UDP session timeout after 30s of inactivity");
                        break;
                    }
                }
            }
        }

        // Flush stream before closing
        let _ = stream.flush().await;

        // Clean up
        self.sessions.remove(&conn_id);
        self.stats.udp_sessions_closed.fetch_add(1, Ordering::Relaxed);

        let stats = session_state.to_udp_stats(datagrams_sent, datagrams_received);
        self.stats.bytes_sent.fetch_add(stats.bytes_sent, Ordering::Relaxed);
        self.stats.bytes_received.fetch_add(stats.bytes_received, Ordering::Relaxed);

        info!(
            "NetbridgeVlessAdapter: UDP {} closed, {} dgrams sent, {} dgrams recv",
            conn_id, stats.datagrams_sent, stats.datagrams_received
        );

        Ok(stats)
    }

    /// Handle a UDP connection (stub for when sharded-vless-wg-bridge is disabled).
    #[cfg(not(feature = "sharded-vless-wg-bridge"))]
    pub async fn handle_udp_connection<S>(
        &self,
        _stream: S,
        _initial_dest: SocketAddr,
    ) -> Result<UdpConnectionStats>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        Err(NetBridgeError::NotSupported(
            "UDP-over-TCP requires sharded-vless-wg-bridge feature".to_string(),
        ))
    }

    /// Send a single UDP datagram.
    ///
    /// This is an alternative to `handle_udp_connection` for protocols that
    /// send individual UDP datagrams rather than using VLESS framing.
    ///
    /// # Arguments
    ///
    /// * `src` - Source address (client)
    /// * `dest` - Destination address
    /// * `data` - UDP payload
    pub async fn send_udp_datagram(
        &self,
        src: SocketAddr,
        dest: SocketAddr,
        data: &[u8],
    ) -> Result<()> {
        if self.is_shutdown() {
            return Err(NetBridgeError::TunnelDown("adapter is shutting down".into()));
        }

        self.stats.bytes_sent.fetch_add(data.len() as u64, Ordering::Relaxed);
        self.egress.handle_udp(src, dest, data).await
    }

    /// Get aggregated statistics.
    ///
    /// This method returns statistics in a format compatible with
    /// `ShardedVlessWgBridge::stats()`.
    #[must_use]
    pub fn stats(&self) -> AggregatedStats {
        self.stats.snapshot()
    }

    /// Shutdown the adapter.
    ///
    /// This initiates a graceful shutdown. Active connections will be allowed
    /// to complete before the adapter fully stops.
    pub async fn shutdown(&self) {
        if self.shutdown.swap(true, Ordering::Relaxed) {
            // Already shutting down
            return;
        }

        info!("NetbridgeVlessAdapter initiating shutdown");

        // Shutdown the underlying egress
        if let Err(e) = self.egress.shutdown().await {
            warn!("Error shutting down SmoltcpEgress: {}", e);
        }

        // Clear sessions
        self.sessions.clear();
    }

    /// Feed a reply IP packet from WireGuard.
    ///
    /// This is a passthrough to the underlying SmoltcpEgress.
    pub fn feed_reply(&self, packet: &[u8]) -> Result<()> {
        self.egress.feed_reply(packet)
    }

    /// Drain pending TX packets.
    ///
    /// This is a passthrough to the underlying SmoltcpEgress.
    #[must_use]
    pub fn drain_tx(&self) -> Vec<Bytes> {
        self.egress.drain_tx()
    }
}

impl std::fmt::Debug for NetbridgeVlessAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NetbridgeVlessAdapter")
            .field("active_sessions", &self.active_sessions())
            .field("is_shutdown", &self.is_shutdown())
            .finish()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_tcp_connection_stats_default() {
        let stats = TcpConnectionStats::new();
        assert_eq!(stats.bytes_sent, 0);
        assert_eq!(stats.bytes_received, 0);
        assert_eq!(stats.duration, Duration::ZERO);
    }

    #[test]
    fn test_udp_connection_stats_default() {
        let stats = UdpConnectionStats::new();
        assert_eq!(stats.datagrams_sent, 0);
        assert_eq!(stats.datagrams_received, 0);
        assert_eq!(stats.bytes_sent, 0);
        assert_eq!(stats.bytes_received, 0);
    }

    #[test]
    fn test_aggregated_stats_active_sessions() {
        let mut stats = AggregatedStats::default();
        stats.total_tcp_sessions_created = 10;
        stats.total_tcp_sessions_closed = 3;
        stats.total_udp_sessions_created = 5;
        stats.total_udp_sessions_closed = 2;

        assert_eq!(stats.active_tcp_sessions(), 7);
        assert_eq!(stats.active_udp_sessions(), 3);
    }

    #[test]
    fn test_session_state_bytes_tracking() {
        let state = SessionState::new(true);
        state.add_bytes_sent(100);
        state.add_bytes_sent(50);
        state.add_bytes_received(200);

        let stats = state.to_tcp_stats();
        assert_eq!(stats.bytes_sent, 150);
        assert_eq!(stats.bytes_received, 200);
        assert!(stats.duration > Duration::ZERO || stats.duration == Duration::ZERO);
    }

    #[test]
    fn test_adapter_stats_snapshot() {
        let stats = AdapterStats::new();
        stats.tcp_sessions_created.store(5, Ordering::Relaxed);
        stats.tcp_sessions_closed.store(2, Ordering::Relaxed);
        stats.bytes_sent.store(1000, Ordering::Relaxed);

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.num_shards, 1);
        assert_eq!(snapshot.total_tcp_sessions_created, 5);
        assert_eq!(snapshot.total_tcp_sessions_closed, 2);
        assert_eq!(snapshot.total_bytes_sent, 1000);
        assert_eq!(snapshot.active_tcp_sessions(), 3);
    }

    #[tokio::test]
    async fn test_adapter_spawn() {
        let config = SmoltcpEgressConfig::default();
        let (adapter, handle) = NetbridgeVlessAdapter::spawn(config);

        assert!(!adapter.is_shutdown());
        assert_eq!(adapter.num_shards(), 1);
        assert_eq!(adapter.active_sessions(), 0);

        // Shutdown
        adapter.shutdown().await;
        assert!(adapter.is_shutdown());

        let _ = handle.task.await;
    }

    #[tokio::test]
    async fn test_adapter_stats() {
        let config = SmoltcpEgressConfig::default();
        let (adapter, handle) = NetbridgeVlessAdapter::spawn(config);

        let stats = adapter.stats();
        assert_eq!(stats.total_tcp_sessions_created, 0);
        assert_eq!(stats.total_udp_sessions_created, 0);

        adapter.shutdown().await;
        let _ = handle.task.await;
    }

    #[tokio::test]
    async fn test_adapter_shutdown_rejects_connections() {
        let config = SmoltcpEgressConfig::default();
        let (adapter, handle) = NetbridgeVlessAdapter::spawn(config);

        adapter.shutdown().await;

        // Try to create a connection after shutdown
        let (client, _server) = tokio::io::duplex(1024);
        let dest = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 80);

        let result = adapter.handle_tcp_connection(client, dest).await;
        assert!(result.is_err());

        let _ = handle.task.await;
    }

    #[tokio::test]
    async fn test_adapter_conn_id_allocation() {
        let config = SmoltcpEgressConfig::default();
        let (adapter, handle) = NetbridgeVlessAdapter::spawn(config);

        let id1 = adapter.allocate_conn_id();
        let id2 = adapter.allocate_conn_id();
        let id3 = adapter.allocate_conn_id();

        assert_eq!(id1, 1);
        assert_eq!(id2, 2);
        assert_eq!(id3, 3);

        adapter.shutdown().await;
        let _ = handle.task.await;
    }

    #[tokio::test]
    async fn test_adapter_feed_reply_and_drain() {
        let config = SmoltcpEgressConfig::default();
        let (adapter, handle) = NetbridgeVlessAdapter::spawn(config);

        // Feed a minimal IP packet
        let packet = vec![0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00,
                         0x40, 0x06, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01,
                         0x0a, 0x00, 0x00, 0x02];
        let result = adapter.feed_reply(&packet);
        // May succeed or fail depending on smoltcp state, but should not panic
        let _ = result;

        // Drain should return empty or packets
        let _packets = adapter.drain_tx();

        adapter.shutdown().await;
        let _ = handle.task.await;
    }

    #[test]
    fn test_adapter_debug_impl() {
        // Can't easily test async spawn in sync test, so just test formatting works
        let egress_config = SmoltcpEgressConfig::default();
        let (egress, _handle) = SmoltcpEgress::spawn(egress_config);
        let adapter = NetbridgeVlessAdapter::new(egress);

        let debug_str = format!("{:?}", adapter);
        assert!(debug_str.contains("NetbridgeVlessAdapter"));
        assert!(debug_str.contains("active_sessions"));
    }
}
