//! SmoltcpEgress - Implementation of NetBridgeEgress using smoltcp
//!
//! This module provides `SmoltcpEgress`, which implements the `NetBridgeEgress` trait
//! using the smoltcp userspace TCP/IP stack. It bridges TCP/UDP streams from
//! VLESS/Shadowsocks inbound to WireGuard outbound.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                        SmoltcpEgress (Public API)                       │
//! ├─────────────────────────────────────────────────────────────────────────┤
//! │  - handle_tcp(): Sends TcpConnect command to shard                      │
//! │  - handle_udp(): Sends UdpSend command to shard                         │
//! │  - feed_reply(): Sends reply packet to shard                            │
//! │  - drain_tx(): Returns pending TX packets                               │
//! └─────────────────────────────────────────────────────────────────────────┘
//!                            │ Channels
//!                            ▼
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                        SmoltcpShard (Task)                              │
//! │  - Owns smoltcp Interface + SocketSet                                   │
//! │  - Processes commands and WG replies                                    │
//! │  - Generates TX packets for WG                                          │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Thread Safety
//!
//! `SmoltcpEgress` is `Send + Sync`. It communicates with the internal
//! `SmoltcpShard` via channels, so no mutexes are needed.
//!
//! # Example
//!
//! ```ignore
//! use rust_router::netbridge::smoltcp::{SmoltcpEgress, SmoltcpEgressConfig};
//! use rust_router::netbridge::NetBridgeEgress;
//!
//! // Create egress
//! let config = SmoltcpEgressConfig::default();
//! let (egress, handle) = SmoltcpEgress::spawn(config);
//!
//! // Handle TCP connection
//! let stream = tokio::net::TcpStream::connect("127.0.0.1:8080").await?;
//! let session_id = egress.handle_tcp(stream, "93.184.216.34:443".parse()?).await?;
//!
//! // Feed reply packets from WireGuard
//! egress.feed_reply(&wg_packet)?;
//!
//! // Drain packets to send to WireGuard
//! for packet in egress.drain_tx() {
//!     wg_tunnel.send(&packet).await?;
//! }
//! ```

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use parking_lot::Mutex;
use smoltcp::wire::IpAddress;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot, Notify};
use tokio::task::JoinHandle;
use tracing::{debug, info, trace, warn};

use super::shard::{ShardCommand, SmoltcpShard, SmoltcpShardConfig, SmoltcpShardStats};
use crate::netbridge::error::{NetBridgeError, Result};
use crate::netbridge::traits::NetBridgeEgress;
use crate::netbridge::types::{EgressStats, SessionId};

// =============================================================================
// Configuration
// =============================================================================

/// Configuration for SmoltcpEgress
#[derive(Debug, Clone)]
pub struct SmoltcpEgressConfig {
    /// Local IP address for the smoltcp interface
    pub local_ip: IpAddress,
    /// Maximum transmission unit
    pub mtu: usize,
    /// Command channel buffer size
    pub command_channel_size: usize,
    /// WG reply channel buffer size
    pub wg_reply_channel_size: usize,
    /// WG TX channel buffer size
    pub wg_tx_channel_size: usize,
    /// TCP data channel buffer size
    pub tcp_data_channel_size: usize,
}

impl SmoltcpEgressConfig {
    /// Create a new configuration with the given local IP
    #[must_use]
    pub fn new(local_ip: IpAddress) -> Self {
        Self {
            local_ip,
            mtu: super::WG_MTU,
            command_channel_size: 1024,
            wg_reply_channel_size: 2048,
            wg_tx_channel_size: 2048,
            tcp_data_channel_size: 16,
        }
    }

    /// Create a configuration with IPv4 address
    #[must_use]
    pub fn with_ipv4(a: u8, b: u8, c: u8, d: u8) -> Self {
        Self::new(IpAddress::v4(a, b, c, d))
    }
}

impl Default for SmoltcpEgressConfig {
    fn default() -> Self {
        Self::with_ipv4(10, 200, 200, 2)
    }
}

// =============================================================================
// Statistics
// =============================================================================

/// Statistics for SmoltcpEgress
#[derive(Debug, Default)]
pub struct SmoltcpEgressStats {
    /// TCP connections handled
    pub tcp_connections: AtomicU64,
    /// TCP connections currently active
    pub tcp_active: AtomicUsize,
    /// UDP datagrams sent
    pub udp_datagrams_sent: AtomicU64,
    /// UDP sessions created
    pub udp_sessions: AtomicU64,
    /// Reply packets fed
    pub reply_packets_fed: AtomicU64,
    /// TX packets drained
    pub tx_packets_drained: AtomicU64,
    /// Errors encountered
    pub errors: AtomicU64,
}

impl SmoltcpEgressStats {
    /// Create new zeroed statistics
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Get a snapshot of statistics
    #[must_use]
    pub fn snapshot(&self) -> EgressStats {
        EgressStats {
            tcp_sessions: self.tcp_connections.load(Ordering::Relaxed),
            udp_sessions: self.udp_sessions.load(Ordering::Relaxed),
            bytes_sent: 0, // Would need to track in shard
            bytes_received: 0,
            reply_packets: self.reply_packets_fed.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
        }
    }
}

// =============================================================================
// SmoltcpEgress
// =============================================================================

/// SmoltcpEgress - Implementation of NetBridgeEgress using smoltcp
///
/// This struct provides the public API for bridging TCP/UDP streams to
/// WireGuard via the smoltcp userspace TCP/IP stack.
///
/// # Thread Safety
///
/// `SmoltcpEgress` is `Send + Sync` and can be safely shared across tasks.
/// All communication with the internal shard happens through channels.
pub struct SmoltcpEgress {
    /// Command sender to the shard
    command_tx: mpsc::Sender<ShardCommand>,
    /// WG reply sender (for feed_reply)
    wg_reply_tx: mpsc::Sender<Vec<u8>>,
    /// WG TX receiver (for drain_tx / take_tx_receiver)
    wg_tx_rx: Mutex<Option<mpsc::Receiver<Bytes>>>,
    /// Upload notification -- shared with shard for wakeup signaling
    upload_notify: Arc<Notify>,
    /// Statistics
    stats: Arc<SmoltcpEgressStats>,
    /// Active session count
    active_sessions: AtomicUsize,
    /// Configuration
    config: SmoltcpEgressConfig,
}

/// Handle to the shard task
pub struct SmoltcpEgressHandle {
    /// The task join handle
    pub task: JoinHandle<()>,
}

impl SmoltcpEgress {
    /// Create a new SmoltcpEgress and spawn the internal shard task
    ///
    /// # Arguments
    ///
    /// * `config` - Egress configuration
    ///
    /// # Returns
    ///
    /// A tuple of (egress, handle) where handle can be used to await the shard task.
    #[must_use]
    pub fn spawn(config: SmoltcpEgressConfig) -> (Arc<Self>, SmoltcpEgressHandle) {
        // Create channels
        let (command_tx, command_rx) = mpsc::channel(config.command_channel_size);
        let (wg_reply_tx, wg_reply_rx) = mpsc::channel::<Vec<u8>>(config.wg_reply_channel_size);
        let (wg_tx_tx, wg_tx_rx) = mpsc::channel(config.wg_tx_channel_size);

        // Create shard config
        let shard_config = SmoltcpShardConfig {
            shard_index: 0,
            total_shards: 1,
            local_ip: config.local_ip,
            mtu: config.mtu,
            tcp_idle_timeout: Duration::from_secs(300),
            udp_idle_timeout: Duration::from_secs(30),
            cleanup_interval: Duration::from_secs(30),
        };

        // Create upload notify for shard wakeup signaling
        let upload_notify = Arc::new(Notify::new());

        // Create and spawn shard
        let shard = SmoltcpShard::new(shard_config, command_rx, wg_reply_rx, wg_tx_tx, upload_notify.clone());
        let task = tokio::spawn(shard.run());

        let egress = Arc::new(Self {
            command_tx,
            wg_reply_tx,
            wg_tx_rx: Mutex::new(Some(wg_tx_rx)),
            upload_notify,
            stats: Arc::new(SmoltcpEgressStats::new()),
            active_sessions: AtomicUsize::new(0),
            config,
        });

        info!(
            local_ip = %egress.config.local_ip,
            "SmoltcpEgress spawned"
        );

        (egress, SmoltcpEgressHandle { task })
    }

    /// Create egress with custom channels (for testing)
    #[cfg(test)]
    pub fn with_channels(
        config: SmoltcpEgressConfig,
        command_tx: mpsc::Sender<ShardCommand>,
        wg_reply_tx: mpsc::Sender<Vec<u8>>,
        wg_tx_rx: mpsc::Receiver<Bytes>,
        upload_notify: Arc<Notify>,
    ) -> Arc<Self> {
        Arc::new(Self {
            command_tx,
            wg_reply_tx,
            wg_tx_rx: Mutex::new(Some(wg_tx_rx)),
            upload_notify,
            stats: Arc::new(SmoltcpEgressStats::new()),
            active_sessions: AtomicUsize::new(0),
            config,
        })
    }

    /// Take the WG TX receiver for event-driven forwarding.
    ///
    /// After calling this, `drain_tx()` will return empty results.
    /// The caller is responsible for receiving packets from the returned receiver
    /// and forwarding them to the WireGuard tunnel.
    ///
    /// This enables zero-latency TX forwarding (recv() loop) instead of polling.
    pub fn take_tx_receiver(&self) -> Option<mpsc::Receiver<Bytes>> {
        self.wg_tx_rx.lock().take()
    }

    /// Get a clone of the WG reply sender for direct registration.
    ///
    /// This allows registering the shard's reply channel directly with the
    /// `ShardedBridgeReplyRegistry`, eliminating an intermediate feeder task
    /// and an extra `Bytes::copy_from_slice` copy on the reply path.
    ///
    /// The returned sender feeds packets directly to the shard's `wg_reply_rx`.
    pub fn wg_reply_sender(&self) -> mpsc::Sender<Vec<u8>> {
        self.wg_reply_tx.clone()
    }

    /// Get the upload notify handle for pump tasks to signal data arrival
    pub fn upload_notify(&self) -> Arc<Notify> {
        self.upload_notify.clone()
    }

    /// Shutdown the egress bridge
    pub async fn shutdown(&self) -> Result<()> {
        info!(
            target: "netbridge::egress",
            local_ip = %self.config.local_ip,
            "SmoltcpEgress initiating shutdown"
        );
        self.command_tx
            .send(ShardCommand::Shutdown)
            .await
            .map_err(|_| NetBridgeError::ChannelClosed)?;
        Ok(())
    }

    /// Get statistics from the shard
    pub async fn shard_stats(&self) -> Result<SmoltcpShardStats> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.command_tx
            .send(ShardCommand::GetStats { reply: reply_tx })
            .await
            .map_err(|_| NetBridgeError::ChannelClosed)?;

        reply_rx.await.map_err(|_| NetBridgeError::ChannelClosed)
    }
}

impl NetBridgeEgress for SmoltcpEgress {
    /// Handle a TCP connection
    ///
    /// Creates a smoltcp TCP socket, initiates connection to the destination,
    /// and spawns a task to pump data between the stream and the socket.
    fn handle_tcp<S>(
        &self,
        stream: S,
        dest: SocketAddr,
    ) -> impl std::future::Future<Output = Result<SessionId>> + Send
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let command_tx = self.command_tx.clone();
        let stats = Arc::clone(&self.stats);
        let tcp_data_channel_size = self.config.tcp_data_channel_size;
        let upload_notify = self.upload_notify.clone();

        async move {
            // Create data channels for the TCP pump
            let (data_tx, data_rx) = mpsc::channel(tcp_data_channel_size);
            let (reply_data_tx, mut reply_data_rx) = mpsc::channel(tcp_data_channel_size);

            // Create reply channel for the session ID
            let (reply_tx, reply_rx) = oneshot::channel();

            // Send connect command
            command_tx
                .send(ShardCommand::TcpConnect {
                    dest,
                    reply: reply_tx,
                    data_tx: reply_data_tx, // Shard sends received data here
                    data_rx,                 // Shard receives data to send from here
                })
                .await
                .map_err(|_| NetBridgeError::ChannelClosed)?;

            // Wait for session ID or error
            let session_id = reply_rx
                .await
                .map_err(|_| NetBridgeError::ChannelClosed)??;

            stats.tcp_connections.fetch_add(1, Ordering::Relaxed);

            debug!(
                target: "netbridge::egress",
                session_id,
                %dest,
                "TCP session created via SmoltcpEgress"
            );

            // Spawn a task to pump data between stream and shard
            let close_tx = command_tx.clone();
            let session_id_copy = session_id;
            tokio::spawn(async move {
                let (mut read_half, mut write_half) = tokio::io::split(stream);

                // Read from stream, send to shard via per-session channel
                let read_task = {
                    let close_tx = close_tx.clone();
                    async move {
                        let mut buf = BytesMut::with_capacity(65536);
                        loop {
                            // Zero-copy read: read_buf appends directly into BytesMut
                            match read_half.read_buf(&mut buf).await {
                                Ok(0) => {
                                    // EOF - send close via shared command channel
                                    trace!(session_id = session_id_copy, "TCP pump: stream EOF, closing session");
                                    let _ = close_tx
                                        .send(ShardCommand::TcpClose {
                                            session_id: session_id_copy,
                                        })
                                        .await;
                                    break;
                                }
                                Ok(_) => {
                                    // Zero-copy: freeze() converts BytesMut -> Bytes without copying
                                    let data = buf.split().freeze();
                                    // Send via per-session channel (not shared command_tx!)
                                    if data_tx.send(data).await.is_err() {
                                        break;
                                    }
                                    // Signal the shard that upload data is available
                                    upload_notify.notify_one();
                                }
                                Err(e) => {
                                    debug!(session_id = session_id_copy, ?e, "TCP pump: read error, closing session");
                                    let _ = close_tx
                                        .send(ShardCommand::TcpClose {
                                            session_id: session_id_copy,
                                        })
                                        .await;
                                    break;
                                }
                            }
                        }
                    }
                };

                // Write to stream from shard data
                let write_task = async move {
                    while let Some(data) = reply_data_rx.recv().await {
                        if write_half.write_all(&data).await.is_err() {
                            break;
                        }
                    }
                };

                // Run both tasks; when one finishes, the other is cancelled
                tokio::select! {
                    _ = read_task => {}
                    _ = write_task => {}
                }

                // Ensure session is closed regardless of which side finished.
                // If read_task already sent TcpClose (EOF/error path), this is
                // a no-op in the shard (session already removed). But if write_task
                // finished first (remote closed download), read_task was cancelled
                // without sending TcpClose — this guarantees cleanup.
                debug!(session_id = session_id_copy, "TCP pump: safety cleanup TcpClose sent");
                let _ = close_tx
                    .send(ShardCommand::TcpClose {
                        session_id: session_id_copy,
                    })
                    .await;
            });

            Ok(SessionId::new(session_id))
        }
    }

    /// Handle a UDP datagram
    ///
    /// Sends the datagram through smoltcp to the WireGuard tunnel.
    fn handle_udp(
        &self,
        src: SocketAddr,
        dest: SocketAddr,
        data: &[u8],
    ) -> impl std::future::Future<Output = Result<()>> + Send {
        let command_tx = self.command_tx.clone();
        let data = Bytes::copy_from_slice(data);
        let stats = Arc::clone(&self.stats);

        async move {
            command_tx
                .send(ShardCommand::UdpSend {
                    src,
                    dest,
                    data,
                    reply: None,
                })
                .await
                .map_err(|_| NetBridgeError::ChannelClosed)?;

            stats.udp_datagrams_sent.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    /// Feed a reply IP packet into the bridge
    ///
    /// The packet is sent to the shard for processing by smoltcp.
    fn feed_reply(&self, packet: &[u8]) -> Result<()> {
        let data = packet.to_vec();

        self.wg_reply_tx
            .try_send(data)
            .map_err(|e| match e {
                mpsc::error::TrySendError::Full(_) => {
                    warn!(
                        target: "netbridge::egress",
                        packet_len = packet.len(),
                        "WG reply channel full, dropping packet"
                    );
                    NetBridgeError::ChannelSendFailed("WG reply channel full".to_string())
                }
                mpsc::error::TrySendError::Closed(_) => NetBridgeError::ChannelClosed,
            })?;

        self.stats.reply_packets_fed.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Drain pending TX packets
    ///
    /// Returns all IP packets waiting to be sent to WireGuard.
    /// Note: This only works if the TX receiver hasn't been taken via `take_tx_receiver()`.
    fn drain_tx(&self) -> Vec<Bytes> {
        let mut guard = self.wg_tx_rx.lock();
        let mut packets = Vec::new();

        if let Some(rx) = guard.as_mut() {
            // Non-blocking drain
            loop {
                match rx.try_recv() {
                    Ok(packet) => {
                        self.stats.tx_packets_drained.fetch_add(1, Ordering::Relaxed);
                        packets.push(packet);
                    }
                    Err(mpsc::error::TryRecvError::Empty) => break,
                    Err(mpsc::error::TryRecvError::Disconnected) => break,
                }
            }
        }

        packets
    }

    /// Poll the smoltcp stack
    ///
    /// Note: In this implementation, the shard handles polling internally.
    /// This method returns immediately with a suggested poll delay.
    fn poll(&self) -> impl std::future::Future<Output = Option<Duration>> + Send {
        async move {
            // Shard polls internally, so we return a reasonable delay
            Some(Duration::from_millis(super::DEFAULT_POLL_INTERVAL_MS))
        }
    }

    /// Close a specific session
    fn close_session(
        &self,
        session_id: SessionId,
    ) -> impl std::future::Future<Output = Result<()>> + Send {
        let command_tx = self.command_tx.clone();
        let id = session_id.as_u64();

        async move {
            // Try TCP close first, then UDP
            if command_tx
                .send(ShardCommand::TcpClose { session_id: id })
                .await
                .is_ok()
            {
                return Ok(());
            }

            command_tx
                .send(ShardCommand::UdpClose { session_id: id })
                .await
                .map_err(|_| NetBridgeError::ChannelClosed)
        }
    }

    /// Get current statistics
    fn stats(&self) -> EgressStats {
        self.stats.snapshot()
    }

    /// Get the number of active sessions
    fn active_sessions(&self) -> usize {
        self.active_sessions.load(Ordering::Relaxed)
    }
}

impl std::fmt::Debug for SmoltcpEgress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SmoltcpEgress")
            .field("local_ip", &self.config.local_ip)
            .field("active_sessions", &self.active_sessions())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_egress_config_default() {
        let config = SmoltcpEgressConfig::default();
        assert_eq!(config.local_ip, IpAddress::v4(10, 200, 200, 2));
        assert_eq!(config.mtu, super::super::WG_MTU);
    }

    #[test]
    fn test_egress_config_with_ipv4() {
        let config = SmoltcpEgressConfig::with_ipv4(192, 168, 1, 1);
        assert_eq!(config.local_ip, IpAddress::v4(192, 168, 1, 1));
    }

    #[test]
    fn test_egress_stats_new() {
        let stats = SmoltcpEgressStats::new();
        assert_eq!(stats.tcp_connections.load(Ordering::Relaxed), 0);
        assert_eq!(stats.udp_datagrams_sent.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_egress_stats_snapshot() {
        let stats = SmoltcpEgressStats::new();
        stats.tcp_connections.store(5, Ordering::Relaxed);
        stats.udp_sessions.store(3, Ordering::Relaxed);

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.tcp_sessions, 5);
        assert_eq!(snapshot.udp_sessions, 3);
    }

    #[tokio::test]
    async fn test_egress_spawn() {
        let config = SmoltcpEgressConfig::default();
        let (egress, handle) = SmoltcpEgress::spawn(config);

        assert_eq!(egress.active_sessions(), 0);

        // Shutdown
        egress.shutdown().await.expect("shutdown should succeed");
        let _ = handle.task.await;
    }

    #[tokio::test]
    async fn test_egress_feed_reply() {
        let config = SmoltcpEgressConfig::default();
        let (egress, handle) = SmoltcpEgress::spawn(config);

        // Feed a packet
        let packet = vec![0x45, 0x00, 0x00, 0x14]; // Minimal IPv4 header
        let result = egress.feed_reply(&packet);
        assert!(result.is_ok());

        assert_eq!(
            egress.stats.reply_packets_fed.load(Ordering::Relaxed),
            1
        );

        // Cleanup
        egress.shutdown().await.unwrap();
        let _ = handle.task.await;
    }

    #[tokio::test]
    async fn test_egress_drain_tx() {
        let config = SmoltcpEgressConfig::default();
        let (egress, handle) = SmoltcpEgress::spawn(config);

        // Initially empty
        let packets = egress.drain_tx();
        assert!(packets.is_empty());

        // Cleanup
        egress.shutdown().await.unwrap();
        let _ = handle.task.await;
    }

    #[tokio::test]
    async fn test_egress_handle_udp() {
        let config = SmoltcpEgressConfig::default();
        let (egress, handle) = SmoltcpEgress::spawn(config);

        let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 25, 0, 2)), 12345);
        let dest = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53);
        let data = b"DNS query";

        let result = egress.handle_udp(src, dest, data).await;
        assert!(result.is_ok());

        assert_eq!(
            egress.stats.udp_datagrams_sent.load(Ordering::Relaxed),
            1
        );

        // Cleanup
        egress.shutdown().await.unwrap();
        let _ = handle.task.await;
    }

    #[tokio::test]
    async fn test_egress_get_shard_stats() {
        let config = SmoltcpEgressConfig::default();
        let (egress, handle) = SmoltcpEgress::spawn(config);

        // Small delay to let shard start
        tokio::time::sleep(Duration::from_millis(10)).await;

        let _stats = egress.shard_stats().await.expect("should get stats");

        // Cleanup
        egress.shutdown().await.unwrap();
        let _ = handle.task.await;
    }

    #[tokio::test]
    async fn test_egress_close_session() {
        let config = SmoltcpEgressConfig::default();
        let (egress, handle) = SmoltcpEgress::spawn(config);

        // Close a non-existent session (should not error, just no-op)
        let result = egress.close_session(SessionId::new(12345)).await;
        // The channel might be open even if session doesn't exist
        assert!(result.is_ok());

        // Cleanup
        egress.shutdown().await.unwrap();
        let _ = handle.task.await;
    }

    #[tokio::test]
    async fn test_egress_poll() {
        let config = SmoltcpEgressConfig::default();
        let (egress, handle) = SmoltcpEgress::spawn(config);

        let delay = egress.poll().await;
        assert!(delay.is_some());
        assert!(delay.unwrap().as_millis() > 0);

        // Cleanup
        egress.shutdown().await.unwrap();
        let _ = handle.task.await;
    }
}
