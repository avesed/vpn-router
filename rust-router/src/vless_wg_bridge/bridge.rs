//! VLESS to WireGuard bridge implementation
//!
//! This module provides `VlessWgBridge`, which bridges VLESS TCP/UDP connections
//! to WireGuard tunnels using smoltcp as the userspace TCP/IP stack.
//!
//! # Architecture
//!
//! The bridge solves the protocol layer mismatch between VLESS (Layer 4 TCP streams)
//! and WireGuard (Layer 3 IP packets). When a VLESS client sends TCP data, we must:
//!
//! 1. Create a corresponding TCP socket in the smoltcp userspace stack
//! 2. Forward the TCP data through smoltcp to generate IP packets
//! 3. Send those IP packets through the WireGuard tunnel
//! 4. Route reply packets back through smoltcp to the original VLESS connection
//!
//! # Key Features
//!
//! - **Channel-based WG reply handling** - Avoids blocking_lock deadlocks
//! - **RAII resource management** - PortGuard and proper socket cleanup
//! - **TCP half-close handling** - Tracks vless_closed and smoltcp_closed separately
//! - **Tunnel health checking** - Monitors WG tunnel state
//!
//! # Example
//!
//! ```ignore
//! use std::sync::Arc;
//! use std::net::IpAddr;
//! use rust_router::vless_wg_bridge::VlessWgBridge;
//! use rust_router::egress::WgEgressManager;
//!
//! // Create bridge
//! let bridge = VlessWgBridge::new(
//!     wg_egress_manager,
//!     "wg-tunnel-1".to_string(),
//!     "10.200.200.2".parse().unwrap(),
//! );
//!
//! // Handle a VLESS TCP connection
//! bridge.handle_tcp_connection(
//!     client_addr,
//!     tcp_stream,
//!     dest_ip,
//!     dest_port,
//! ).await?;
//! ```

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use smoltcp::iface::SocketHandle;
use smoltcp::socket::tcp::State as TcpState;
use smoltcp::wire::IpAddress;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, info, trace, warn};

use crate::egress::config::EgressState;
use crate::egress::manager::WgEgressManager;
use crate::tunnel::smoltcp_bridge::SmoltcpBridge;

use super::config::{
    MAX_SOCKETS, TCP_IDLE_TIMEOUT_SECS, TCP_RX_BUFFER, TCP_TX_BUFFER, UDP_DEFAULT_TIMEOUT_SECS,
    UDP_DNS_TIMEOUT_SECS, UDP_RX_BUFFER, WG_MTU, WG_REPLY_CHANNEL_SIZE,
};
use super::error::{BridgeError, Result};
use super::port_allocator::PortAllocator;
use super::reply_registry::{VlessReplyKey, VlessReplyRegistry};
use super::session::{SessionKey, SessionTracker, VlessConnectionId};
use super::socket_guard::TcpSocketGuard;
use super::udp_frame::{address_type, UdpFrameAddress, VlessUdpFrame};

/// WireGuard reply packet
#[derive(Debug)]
pub struct WgReplyPacket {
    /// Tunnel tag
    pub tag: String,
    /// IP packet data
    pub packet: Vec<u8>,
}

/// VLESS UDP protocol mode
///
/// Xray supports two UDP modes:
/// - **Basic**: `[Length(2)][Payload]` - single destination in VLESS header
/// - **XUDP**: `[Length(2)][AddrType][Address][Port][Payload]` - per-packet addressing
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VlessUdpMode {
    /// Basic VLESS UDP: single destination, payload only in frames
    Basic,
    /// XUDP mode: each frame contains destination address
    Xudp,
}

impl VlessUdpMode {
    /// Detect UDP mode by examining the first byte after the length
    ///
    /// If it's 0x01/0x02/0x03 (VLESS address types), it's XUDP mode.
    /// Otherwise, it's basic UDP with raw payload.
    ///
    /// Note: This heuristic could have false positives if the first byte
    /// of a UDP payload happens to be 0x01-0x03, but in practice:
    /// - DNS queries start with transaction ID (random, 2 bytes)
    /// - Most protocols don't start with these specific bytes
    #[must_use]
    pub fn detect(first_byte: u8) -> Self {
        match first_byte {
            address_type::IPV4 | address_type::DOMAIN | address_type::IPV6 => Self::Xudp,
            _ => Self::Basic,
        }
    }
}

/// Bridge statistics
#[derive(Debug, Default)]
pub struct BridgeStats {
    /// Total TCP connections handled
    pub tcp_connections: AtomicU64,
    /// Total UDP sessions handled
    pub udp_sessions: AtomicU64,
    /// Total bytes sent to WG
    pub bytes_to_wg: AtomicU64,
    /// Total bytes received from WG
    pub bytes_from_wg: AtomicU64,
    /// Active TCP connections
    pub active_tcp: AtomicU64,
    /// Active UDP sessions
    pub active_udp: AtomicU64,
    /// Connection errors
    pub errors: AtomicU64,
}

impl BridgeStats {
    /// Create new bridge statistics
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Get a snapshot of the current statistics
    #[must_use]
    pub fn snapshot(&self) -> BridgeStatsSnapshot {
        BridgeStatsSnapshot {
            tcp_connections: self.tcp_connections.load(Ordering::Relaxed),
            udp_sessions: self.udp_sessions.load(Ordering::Relaxed),
            bytes_to_wg: self.bytes_to_wg.load(Ordering::Relaxed),
            bytes_from_wg: self.bytes_from_wg.load(Ordering::Relaxed),
            active_tcp: self.active_tcp.load(Ordering::Relaxed),
            active_udp: self.active_udp.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of bridge statistics
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct BridgeStatsSnapshot {
    /// Total TCP connections handled
    pub tcp_connections: u64,
    /// Total UDP sessions handled
    pub udp_sessions: u64,
    /// Total bytes sent to WG
    pub bytes_to_wg: u64,
    /// Total bytes received from WG
    pub bytes_from_wg: u64,
    /// Active TCP connections
    pub active_tcp: u64,
    /// Active UDP sessions
    pub active_udp: u64,
    /// Connection errors
    pub errors: u64,
}

/// VLESS to WireGuard Bridge
///
/// Bridges VLESS TCP/UDP inbound connections to WireGuard outbound tunnels
/// using smoltcp as the userspace TCP/IP stack.
///
/// # Thread Safety
///
/// `VlessWgBridge` is `Send + Sync` and designed to be shared across
/// async tasks. Internal state is protected by appropriate synchronization.
///
/// # Socket Management
///
/// The bridge uses `Arc<Mutex<SmoltcpBridge>>` to share the smoltcp bridge
/// with socket guards (`TcpSocketGuard`, `UdpSocketGuard`). These guards
/// implement RAII to ensure sockets are properly cleaned up on all code paths.
/// Raw UDP session key for external callers (e.g., Shadowsocks UDP relay)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RawUdpSessionKey {
    /// Client address
    pub client_addr: SocketAddr,
    /// Destination IP
    pub dest_ip: IpAddr,
    /// Destination port
    pub dest_port: u16,
}

impl RawUdpSessionKey {
    /// Create a new raw UDP session key
    #[must_use]
    pub fn new(client_addr: SocketAddr, dest_ip: IpAddr, dest_port: u16) -> Self {
        Self {
            client_addr,
            dest_ip,
            dest_port,
        }
    }
}

/// Raw UDP reply for external callers
#[derive(Debug)]
pub struct RawUdpReply {
    /// Session key identifying which client/destination this is for
    pub session_key: RawUdpSessionKey,
    /// Source IP of the reply
    pub source_ip: IpAddr,
    /// Source port of the reply
    pub source_port: u16,
    /// Reply payload
    pub payload: bytes::Bytes,
}

pub struct VlessWgBridge {
    /// smoltcp bridge (TCP/IP stack) - Arc for sharing with socket guards
    smoltcp: Arc<Mutex<SmoltcpBridge>>,

    /// Session tracker
    sessions: SessionTracker,

    /// WireGuard egress manager
    wg_egress: Arc<WgEgressManager>,

    /// WG reply packet receiver (channel mode to avoid blocking_lock)
    wg_reply_rx: Mutex<mpsc::Receiver<WgReplyPacket>>,

    /// WG reply packet sender (pass to WgReplyHandler)
    wg_reply_tx: mpsc::Sender<WgReplyPacket>,

    /// Local tunnel IP (assigned by WG peer)
    local_ip: IpAddr,

    /// Target WG tunnel tag
    wg_tag: String,

    /// Statistics
    stats: BridgeStats,

    /// Shutdown flag
    shutdown: AtomicBool,

    /// Global VLESS reply registry (for routing WG replies back to this bridge)
    reply_registry: Option<Arc<VlessReplyRegistry>>,

    /// Raw UDP sessions for external callers (Shadowsocks, etc.)
    /// Key: (client_addr, dest_ip, dest_port) -> session state
    raw_udp_sessions: parking_lot::RwLock<HashMap<RawUdpSessionKey, RawUdpSessionState>>,

    /// Channel for raw UDP replies
    raw_udp_reply_tx: mpsc::Sender<RawUdpReply>,
    raw_udp_reply_rx: Mutex<mpsc::Receiver<RawUdpReply>>,
}

impl VlessWgBridge {
    /// Create a new VLESS-WG bridge
    ///
    /// # Arguments
    ///
    /// * `wg_egress` - WireGuard egress manager
    /// * `wg_tag` - Target WireGuard tunnel tag
    /// * `local_ip` - Local IP assigned to this bridge (from WG tunnel config)
    ///
    /// # Example
    ///
    /// ```ignore
    /// let bridge = VlessWgBridge::new(
    ///     wg_egress_manager,
    ///     "wg-tunnel-1".to_string(),
    ///     "10.200.200.2".parse().unwrap(),
    /// );
    /// ```
    #[must_use]
    pub fn new(wg_egress: Arc<WgEgressManager>, wg_tag: String, local_ip: IpAddr) -> Self {
        Self::with_registry(wg_egress, wg_tag, local_ip, None)
    }

    /// Create a new VLESS-WG bridge with a reply registry
    ///
    /// The reply registry allows the global WgReplyHandler to route decrypted
    /// WireGuard packets back to this bridge, solving the reply routing problem.
    ///
    /// # Arguments
    ///
    /// * `wg_egress` - WireGuard egress manager
    /// * `wg_tag` - Target WireGuard tunnel tag
    /// * `local_ip` - Local IP assigned to this bridge (from WG tunnel config)
    /// * `reply_registry` - Global VLESS reply registry for routing replies
    ///
    /// # Example
    ///
    /// ```ignore
    /// let registry = Arc::new(VlessReplyRegistry::new());
    /// let bridge = VlessWgBridge::with_registry(
    ///     wg_egress_manager,
    ///     "wg-tunnel-1".to_string(),
    ///     "10.200.200.2".parse().unwrap(),
    ///     Some(registry),
    /// );
    /// ```
    #[must_use]
    pub fn with_registry(
        wg_egress: Arc<WgEgressManager>,
        wg_tag: String,
        local_ip: IpAddr,
        reply_registry: Option<Arc<VlessReplyRegistry>>,
    ) -> Self {
        let (tx, rx) = mpsc::channel(WG_REPLY_CHANNEL_SIZE);

        // Create smoltcp bridge with local IP
        let smoltcp = match local_ip {
            IpAddr::V4(v4) => SmoltcpBridge::new(v4, WG_MTU),
            IpAddr::V6(_) => {
                // For now, use a dummy IPv4 - IPv6 support would need smoltcp changes
                warn!("IPv6 local IP not fully supported, using dummy IPv4");
                SmoltcpBridge::new(std::net::Ipv4Addr::new(10, 200, 200, 2), WG_MTU)
            }
        };

        // Create port allocator for session tracker
        let port_allocator = PortAllocator::new();

        // Create channel for raw UDP replies (for Shadowsocks and similar protocols)
        let (raw_udp_tx, raw_udp_rx) = mpsc::channel(WG_REPLY_CHANNEL_SIZE);

        info!(
            "VlessWgBridge created: wg_tag={}, local_ip={}, registry={}",
            wg_tag, local_ip, reply_registry.is_some()
        );

        Self {
            smoltcp: Arc::new(Mutex::new(smoltcp)),
            sessions: SessionTracker::new(port_allocator),
            wg_egress,
            wg_reply_rx: Mutex::new(rx),
            wg_reply_tx: tx,
            local_ip,
            wg_tag,
            stats: BridgeStats::new(),
            shutdown: AtomicBool::new(false),
            reply_registry,
            raw_udp_sessions: parking_lot::RwLock::new(HashMap::new()),
            raw_udp_reply_tx: raw_udp_tx,
            raw_udp_reply_rx: Mutex::new(raw_udp_rx),
        }
    }

    /// Get a clone of the smoltcp bridge Arc
    ///
    /// This is used internally to create socket guards that need
    /// shared ownership of the bridge.
    fn smoltcp_arc(&self) -> Arc<Mutex<SmoltcpBridge>> {
        Arc::clone(&self.smoltcp)
    }

    /// Get the WG reply sender for registering with WgReplyHandler
    ///
    /// The returned sender should be used to forward decrypted WG packets
    /// back to this bridge.
    #[must_use]
    pub fn reply_sender(&self) -> mpsc::Sender<WgReplyPacket> {
        self.wg_reply_tx.clone()
    }

    /// Create a reply handler closure for WgReplyHandler
    ///
    /// This closure can be used with WgReplyHandler to forward replies.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let handler = bridge.create_reply_handler();
    /// // Use handler with WgReplyHandler
    /// ```
    #[must_use]
    pub fn create_reply_handler(&self) -> impl Fn(Vec<u8>, String) + Send + Sync + 'static {
        let tx = self.wg_reply_tx.clone();
        let wg_tag = self.wg_tag.clone();
        move |packet: Vec<u8>, tag: String| {
            if tag == wg_tag {
                // Non-blocking send - drop if channel is full
                if let Err(e) = tx.try_send(WgReplyPacket { tag, packet }) {
                    trace!("WG reply channel full, dropping packet: {}", e);
                }
            }
        }
    }

    /// Check if the bridge is shutting down
    #[must_use]
    pub fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::Acquire)
    }

    /// Initiate shutdown
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Release);
        info!(
            "VlessWgBridge shutdown initiated for tunnel '{}'",
            self.wg_tag
        );
    }

    /// Get bridge statistics
    #[must_use]
    pub fn stats(&self) -> BridgeStatsSnapshot {
        self.stats.snapshot()
    }

    /// Check WG tunnel health
    async fn check_tunnel_health(&self) -> bool {
        self.wg_egress
            .get_tunnel_status(&self.wg_tag)
            .map(|status| status.state == EgressState::Running && status.connected)
            .unwrap_or(false)
    }

    /// Handle a VLESS TCP connection
    ///
    /// This is the main entry point for handling VLESS TCP connections.
    /// It bridges the TCP stream to the WireGuard tunnel using smoltcp.
    ///
    /// # Arguments
    ///
    /// * `client_addr` - Client's source address (for tracking)
    /// * `stream` - The VLESS TCP stream (after protocol negotiation)
    /// * `dest_ip` - Destination IP address
    /// * `dest_port` - Destination port
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The bridge is shutting down
    /// - The WG tunnel is not healthy
    /// - Port allocation fails
    /// - Socket creation fails
    /// - Connection fails
    pub async fn handle_tcp_connection<S>(
        &self,
        client_addr: SocketAddr,
        stream: S,
        dest_ip: IpAddr,
        dest_port: u16,
    ) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        if self.is_shutdown() {
            return Err(BridgeError::TunnelDown("bridge is shutting down".into()));
        }

        // Check tunnel health first
        if !self.check_tunnel_health().await {
            return Err(BridgeError::TunnelDown(format!(
                "WG tunnel '{}' is not healthy",
                self.wg_tag
            )));
        }

        // Create connection ID
        let conn_id = VlessConnectionId::new(client_addr);
        debug!(
            "Handling TCP connection: client={}, dest={}:{}, conn_id={}",
            client_addr, dest_ip, dest_port, conn_id
        );

        // Allocate local port (RAII)
        let port_guard = self
            .sessions
            .port_allocator()
            .allocate()
            .ok_or(BridgeError::PortExhausted)?;
        let local_port = port_guard.port();

        // Create smoltcp TCP socket with RAII guard for automatic cleanup
        let socket_handle = {
            let mut bridge = self.smoltcp.lock().await;
            bridge
                .create_tcp_socket(TCP_RX_BUFFER, TCP_TX_BUFFER)
                .ok_or(BridgeError::SocketLimitReached(MAX_SOCKETS))?
        };

        // Create socket guard - ensures cleanup on all code paths (H1 fix)
        let mut socket_guard = TcpSocketGuard::new(self.smoltcp_arc(), socket_handle);

        // Connect the socket (IPv4 only - smoltcp is not compiled with IPv6 support)
        let smoltcp_dest = match dest_ip {
            IpAddr::V4(v4) => IpAddress::Ipv4(smoltcp::wire::Ipv4Address::from_bytes(&v4.octets())),
            IpAddr::V6(_) => {
                // Socket guard will clean up automatically on early return
                return Err(BridgeError::SmoltcpTcp("IPv6 not supported".into()));
            }
        };

        {
            let mut bridge = self.smoltcp.lock().await;
            if let Err(e) = bridge.tcp_connect(socket_handle, smoltcp_dest, dest_port, local_port) {
                // Socket guard will clean up automatically on early return
                return Err(BridgeError::SmoltcpTcp(format!("connect failed: {e:?}")));
            }
        }

        // Register session
        let session_key = SessionKey::new(self.local_ip, local_port, dest_ip, dest_port);

        // Note: we register for tracking but don't use the result directly
        let _session = self
            .sessions
            .register_tcp(conn_id.clone(), socket_handle, session_key.clone())
            .map_err(|e| {
                // Socket guard will clean up automatically on early return
                BridgeError::SmoltcpTcp(format!("session registration failed: {e}"))
            })?;

        // Create per-connection channel for WG replies (performance optimization)
        // This allows event-driven reply handling instead of polling
        let (conn_reply_tx, conn_reply_rx) = mpsc::channel::<WgReplyPacket>(64);

        // Register with the global reply registry so WgReplyHandler can route replies to us
        let reply_key = VlessReplyKey::new(
            self.wg_tag.clone(),
            self.local_ip,
            local_port,
            dest_ip,
            dest_port,
        );
        if let Some(ref registry) = self.reply_registry {
            // Use per-connection sender for event-driven reply handling
            registry.register(reply_key.clone(), conn_reply_tx, client_addr);
            debug!(
                "Registered VLESS session with reply registry: tunnel={} {}:{} -> {}:{}",
                self.wg_tag, self.local_ip, local_port, dest_ip, dest_port
            );
        }

        // Update stats
        self.stats.tcp_connections.fetch_add(1, Ordering::Relaxed);
        self.stats.active_tcp.fetch_add(1, Ordering::Relaxed);

        // Run the forwarding loop with per-connection reply channel
        let result = self
            .tcp_forward_loop(&conn_id, stream, socket_handle, &session_key, conn_reply_rx)
            .await;

        // Cleanup stats
        self.stats.active_tcp.fetch_sub(1, Ordering::Relaxed);

        // Handle result - close gracefully on success, abort on error
        match &result {
            Ok(()) => {
                debug!("TCP connection completed gracefully, sending FIN");
                // Configure for graceful close and let the guard handle cleanup
                socket_guard.set_graceful_close();
            }
            Err(e) => {
                warn!("TCP connection error, sending RST: {}", e);
                self.stats.errors.fetch_add(1, Ordering::Relaxed);
                // Default is abort on drop, which is what we want for errors
            }
        }

        // Send any pending packets before cleanup
        self.drain_and_send_packets().await?;

        // Unregister from the global reply registry
        if let Some(ref registry) = self.reply_registry {
            registry.unregister(&reply_key);
            debug!(
                "Unregistered VLESS session from reply registry: tunnel={} {}:{} -> {}:{}",
                self.wg_tag, self.local_ip, local_port, dest_ip, dest_port
            );
        }

        // Remove session from tracker
        self.sessions.remove_tcp(&session_key);

        // Socket guard handles cleanup here via explicit call or drop
        // For graceful close, we use the async method; for abort, drop handles it
        if result.is_ok() {
            socket_guard.close_gracefully().await;
        } else {
            socket_guard.abort().await;
        }

        // Port guard drops here, entering TIME_WAIT
        drop(port_guard);

        debug!(
            "TCP connection ended: conn_id={}, result={:?}",
            conn_id,
            result.is_ok()
        );
        result
    }

    /// TCP forwarding loop
    ///
    /// Handles bidirectional data transfer between VLESS stream and smoltcp socket.
    /// Uses event-driven architecture with per-connection reply channel for optimal throughput.
    async fn tcp_forward_loop<S>(
        &self,
        _conn_id: &VlessConnectionId,
        stream: S,
        socket_handle: SocketHandle,
        _session_key: &SessionKey,
        mut conn_reply_rx: mpsc::Receiver<WgReplyPacket>,
    ) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let (mut reader, mut writer) = tokio::io::split(stream);
        // Use larger buffers for better throughput (64KB instead of 16KB)
        let mut vless_buf = vec![0u8; 65536];
        let mut smoltcp_buf = vec![0u8; 65536];

        // Half-close tracking
        let mut vless_closed = false;
        let mut smoltcp_closed = false;

        // Wait for connection to establish (using per-connection reply channel)
        let connected = self
            .wait_for_tcp_connect_with_rx(socket_handle, &mut conn_reply_rx)
            .await?;
        if !connected {
            return Err(BridgeError::ConnectionTimeout);
        }

        // TCP timer interval - check state and handle retransmissions
        // Using 5ms for better responsiveness while keeping event-driven benefits
        let timer_interval = Duration::from_millis(5);

        loop {
            // Check shutdown (no lock needed - atomic check)
            if self.is_shutdown() {
                return Err(BridgeError::TunnelDown("bridge shutdown".into()));
            }

            // OPTIMIZATION: Only lock smoltcp when we have actual work to do!
            // The select! below is event-driven - we only process when data arrives
            // TCP timers are handled in the timeout branch (every 50ms)

            // Event-driven select! with biased priority (data first, then timeout)
            tokio::select! {
                biased;
                // VLESS -> smoltcp (forward direction, event-driven)
                result = reader.read(&mut vless_buf), if !vless_closed => {
                    match result {
                        Ok(0) => {
                            debug!("VLESS client half-closed, continuing to receive from remote");
                            vless_closed = true;
                        }
                        Ok(n) => {
                            trace!("Read {} bytes from VLESS", n);
                            self.stats.bytes_to_wg.fetch_add(n as u64, Ordering::Relaxed);

                            // Write to smoltcp, poll to generate IP packets, and send IMMEDIATELY
                            let tx_packets = {
                                let mut bridge = self.smoltcp.lock().await;
                                let socket = bridge.get_tcp_socket_mut(socket_handle);
                                if socket.can_send() {
                                    if let Err(e) = socket.send_slice(&vless_buf[..n]) {
                                        warn!("Failed to send to smoltcp: {:?}", e);
                                        return Err(BridgeError::SmoltcpTcp(format!("send failed: {e:?}")));
                                    }
                                } else {
                                    warn!("smoltcp socket cannot send");
                                }
                                // CRITICAL: Poll immediately to generate IP packets!
                                bridge.poll();
                                bridge.drain_tx_packets()
                            };

                            // Send generated packets to WG in batch (reduces lock overhead)
                            if !tx_packets.is_empty() {
                                if let Err(e) = self.wg_egress.send_batch(&self.wg_tag, tx_packets).await {
                                    trace!("WG batch send error: {}", e);
                                }
                            }
                        }
                        Err(e) => {
                            warn!("VLESS read error: {}", e);
                            return Err(e.into());
                        }
                    }
                }

                // WG reply -> smoltcp -> VLESS (event-driven with batch processing!)
                Some(reply) = conn_reply_rx.recv(), if !smoltcp_closed => {
                    // Batch process all available WG replies for better throughput
                    let (total_read, tx_packets) = {
                        let mut bridge = self.smoltcp.lock().await;
                        bridge.feed_rx_packet(reply.packet);

                        // Drain any additional pending replies (non-blocking)
                        while let Ok(additional) = conn_reply_rx.try_recv() {
                            bridge.feed_rx_packet(additional.packet);
                        }

                        // Process all fed packets at once
                        bridge.poll();

                        // Read all available data from the socket
                        let socket = bridge.get_tcp_socket_mut(socket_handle);
                        let mut read_total = 0;
                        while socket.can_recv() {
                            match socket.recv_slice(&mut smoltcp_buf[read_total..]) {
                                Ok(n) if n > 0 => {
                                    read_total += n;
                                    // If buffer is full, write it out
                                    if read_total >= smoltcp_buf.len() - 1500 {
                                        break;
                                    }
                                }
                                Ok(_) => break,
                                Err(_) => break,
                            }
                        }

                        // CRITICAL: Get ACK packets to send immediately!
                        let packets = bridge.drain_tx_packets();
                        (read_total, packets)
                    };

                    // Send ACK packets to WG in batch (outside lock)
                    if !tx_packets.is_empty() {
                        if let Err(e) = self.wg_egress.send_batch(&self.wg_tag, tx_packets).await {
                            trace!("WG batch send error: {}", e);
                        }
                    }

                    if total_read > 0 {
                        trace!("Read {} bytes from smoltcp (batch)", total_read);
                        self.stats.bytes_from_wg.fetch_add(total_read as u64, Ordering::Relaxed);

                        if let Err(e) = writer.write_all(&smoltcp_buf[..total_read]).await {
                            warn!("VLESS write error: {}", e);
                            return Err(e.into());
                        }
                        // CRITICAL: Flush immediately to avoid Nagle/buffering delays!
                        if let Err(e) = writer.flush().await {
                            warn!("VLESS flush error: {}", e);
                            return Err(e.into());
                        }
                    }
                }

                // Timer for TCP state machine, retransmissions, and keepalives
                _ = tokio::time::sleep(timer_interval), if !vless_closed || !smoltcp_closed => {
                    // Poll smoltcp and handle TCP timers/state
                    let (socket_state, can_recv_data, bytes_read, tx_packets) = {
                        let mut bridge = self.smoltcp.lock().await;
                        bridge.poll(); // Handle retransmissions and TCP timers

                        let socket = bridge.get_tcp_socket_mut(socket_handle);
                        let state = socket.state();
                        let can_recv = socket.can_recv();

                        // Read any available data
                        let n = if can_recv {
                            match socket.recv_slice(&mut smoltcp_buf) {
                                Ok(n) if n > 0 => n,
                                _ => 0,
                            }
                        } else {
                            0
                        };

                        let packets = bridge.drain_tx_packets();
                        (state, can_recv, n, packets)
                    };

                    // Send retransmission/keepalive packets in batch
                    if !tx_packets.is_empty() {
                        if let Err(e) = self.wg_egress.send_batch(&self.wg_tag, tx_packets).await {
                            trace!("WG batch send error: {}", e);
                        }
                    }

                    // Write any data we read
                    if bytes_read > 0 {
                        trace!("Read {} bytes from smoltcp on timeout poll", bytes_read);
                        self.stats.bytes_from_wg.fetch_add(bytes_read as u64, Ordering::Relaxed);
                        if let Err(e) = writer.write_all(&smoltcp_buf[..bytes_read]).await {
                            warn!("VLESS write error: {}", e);
                            return Err(e.into());
                        }
                        // CRITICAL: Flush immediately!
                        if let Err(e) = writer.flush().await {
                            warn!("VLESS flush error: {}", e);
                            return Err(e.into());
                        }
                    }

                    // Handle TCP states (moved from top of loop)
                    match socket_state {
                        TcpState::Closed | TcpState::TimeWait => {
                            debug!("TCP socket closed/timewait, ending loop");
                            smoltcp_closed = true;
                            if vless_closed {
                                break;
                            }
                        }
                        TcpState::CloseWait => {
                            if !can_recv_data {
                                debug!("TCP socket in CloseWait, receive buffer drained");
                                smoltcp_closed = true;
                            }
                        }
                        TcpState::LastAck | TcpState::Closing => {
                            if vless_closed {
                                break;
                            }
                        }
                        _ => {}
                    }
                }
            }

            // Exit if both sides closed
            if vless_closed && smoltcp_closed {
                debug!("Both sides closed, exiting loop");
                let mut bridge = self.smoltcp.lock().await;
                bridge.tcp_close(socket_handle);
                break;
            }

            // Proactive close check when VLESS client has closed
            if vless_closed && !smoltcp_closed {
                let bridge = self.smoltcp.lock().await;
                let socket = bridge.get_tcp_socket(socket_handle);
                if !socket.can_recv() && !socket.may_recv() {
                    debug!("VLESS closed and no more data from remote, closing TCP");
                    drop(bridge);
                    let mut bridge = self.smoltcp.lock().await;
                    bridge.tcp_close(socket_handle);
                    smoltcp_closed = true;
                }
            }
        }

        Ok(())
    }

    /// Wait for TCP connection to establish (using per-connection reply channel)
    async fn wait_for_tcp_connect_with_rx(
        &self,
        socket_handle: SocketHandle,
        conn_reply_rx: &mut mpsc::Receiver<WgReplyPacket>,
    ) -> Result<bool> {
        let timeout = Duration::from_secs(TCP_IDLE_TIMEOUT_SECS / 10); // 30 seconds for connect
        let start = std::time::Instant::now();

        loop {
            // Poll and send packets
            self.poll_and_send().await?;

            // Check state
            let state = {
                let mut bridge = self.smoltcp.lock().await;
                bridge.poll();
                bridge.tcp_socket_state(socket_handle)
            };

            match state {
                TcpState::Established => {
                    debug!("TCP connection established");
                    return Ok(true);
                }
                TcpState::Closed => {
                    return Err(BridgeError::ConnectionRefused);
                }
                TcpState::SynSent | TcpState::SynReceived => {
                    // Still connecting, wait for reply
                }
                _ => {
                    trace!("Unexpected state during connect: {:?}", state);
                }
            }

            if start.elapsed() > timeout {
                return Ok(false);
            }

            // Wait for WG reply or timeout (event-driven!)
            tokio::select! {
                Some(reply) = conn_reply_rx.recv() => {
                    trace!("Received {} byte WG reply during connect", reply.packet.len());
                    let mut bridge = self.smoltcp.lock().await;
                    bridge.feed_rx_packet(reply.packet);
                    bridge.poll();
                }
                _ = tokio::time::sleep(Duration::from_millis(50)) => {
                    // Timeout poll for retransmissions
                }
            }
        }
    }

    /// Wait for TCP connection to establish (legacy, uses shared channel)
    #[allow(dead_code)]
    async fn wait_for_tcp_connect(&self, socket_handle: SocketHandle) -> Result<bool> {
        let timeout = Duration::from_secs(TCP_IDLE_TIMEOUT_SECS / 10); // 30 seconds for connect
        let start = std::time::Instant::now();

        loop {
            // Poll and send packets
            self.poll_and_send().await?;

            // Receive replies
            self.receive_wg_replies().await;

            // Check state
            let state = {
                let mut bridge = self.smoltcp.lock().await;
                bridge.poll();
                bridge.tcp_socket_state(socket_handle)
            };

            match state {
                TcpState::Established => {
                    debug!("TCP connection established");
                    return Ok(true);
                }
                TcpState::Closed => {
                    return Err(BridgeError::ConnectionRefused);
                }
                TcpState::SynSent | TcpState::SynReceived => {
                    // Still connecting
                }
                _ => {
                    trace!("Unexpected state during connect: {:?}", state);
                }
            }

            if start.elapsed() > timeout {
                return Ok(false);
            }

            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// Poll smoltcp and send generated packets to WG
    async fn poll_and_send(&self) -> Result<()> {
        let packets = {
            let mut bridge = self.smoltcp.lock().await;
            bridge.poll();
            bridge.drain_tx_packets()
        };

        for packet in packets {
            trace!(
                "Sending {} byte packet to WG tunnel '{}'",
                packet.len(),
                self.wg_tag
            );
            if let Err(e) = self.wg_egress.send(&self.wg_tag, packet).await {
                warn!("Failed to send packet to WG: {}", e);
                // Don't fail the connection for transient send errors
            }
        }

        Ok(())
    }

    /// Drain TX packets and send to WG
    async fn drain_and_send_packets(&self) -> Result<()> {
        self.poll_and_send().await
    }

    /// Receive WG reply packets and feed to smoltcp
    ///
    /// NOTE: This method currently reads from wg_reply_rx channel which must be
    /// fed by an external mechanism. In the current architecture, the WgEgressManager's
    /// reply handler sends packets to IngressForwarder. For VlessWgBridge to receive
    /// replies, it needs to be registered with the reply routing mechanism.
    ///
    /// TODO: Integrate with IngressForwarder's session tracker or implement
    /// a shared reply routing mechanism based on destination IP.
    async fn receive_wg_replies(&self) {
        let mut rx = self.wg_reply_rx.lock().await;

        // Non-blocking receive of all available packets
        loop {
            match rx.try_recv() {
                Ok(reply) => {
                    if reply.tag == self.wg_tag {
                        trace!("Received {} byte reply from WG", reply.packet.len());
                        let bridge = self.smoltcp.lock().await;
                        bridge.feed_rx_packet(reply.packet);
                    }
                }
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    warn!("WG reply channel disconnected");
                    break;
                }
            }
        }
    }

    /// Get local IP address
    #[must_use]
    pub fn local_ip(&self) -> IpAddr {
        self.local_ip
    }

    /// Get WG tunnel tag
    #[must_use]
    pub fn wg_tag(&self) -> &str {
        &self.wg_tag
    }

    // =========================================================================
    // UDP Connection Handling
    // =========================================================================

    /// Handle a VLESS UDP connection
    ///
    /// VLESS UDP mode encapsulates UDP datagrams over TCP using length-prefixed
    /// framing (`VlessUdpFrame`).
    ///
    /// # Arguments
    ///
    /// * `client_addr` - Client's source address
    /// * `stream` - The VLESS TCP stream carrying UDP frames
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The bridge is shutting down
    /// - The WG tunnel is not healthy
    /// - I/O errors occur
    /// Handle a VLESS UDP connection
    ///
    /// In VLESS, the destination is specified ONCE in the header, and UDP frames
    /// are just `[Length(2)][Payload]` - no per-packet addressing.
    ///
    /// # Arguments
    ///
    /// * `client_addr` - Client's source address
    /// * `stream` - The VLESS TCP stream carrying UDP frames
    /// * `dest_ip` - Destination IP (from VLESS header)
    /// * `dest_port` - Destination port (from VLESS header)
    pub async fn handle_udp_connection<S>(
        &self,
        client_addr: SocketAddr,
        mut stream: S,
        dest_ip: IpAddr,
        dest_port: u16,
    ) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        if self.is_shutdown() {
            return Err(BridgeError::TunnelDown("bridge is shutting down".into()));
        }

        // Check tunnel health
        if !self.check_tunnel_health().await {
            return Err(BridgeError::TunnelDown(format!(
                "WG tunnel '{}' is not healthy",
                self.wg_tag
            )));
        }

        let conn_id = VlessConnectionId::new(client_addr);
        debug!(
            "Handling UDP connection: client={}, conn_id={}",
            client_addr, conn_id
        );

        // Track active UDP sessions for this connection
        // Key: (dest_ip, dest_port) -> smoltcp socket handle and metadata
        let mut udp_sessions: HashMap<(IpAddr, u16), UdpSessionState> = HashMap::new();

        // Update stats
        self.stats.udp_sessions.fetch_add(1, Ordering::Relaxed);
        self.stats.active_udp.fetch_add(1, Ordering::Relaxed);

        let result = self
            .udp_forward_loop(&conn_id, &mut stream, &mut udp_sessions, dest_ip, dest_port)
            .await;

        // Cleanup all UDP sessions
        {
            let mut bridge = self.smoltcp.lock().await;
            for (_, session) in udp_sessions.drain() {
                // Unregister from reply registry first
                if let Some(ref reply_key) = session.reply_key {
                    if let Some(ref registry) = self.reply_registry {
                        registry.unregister(reply_key);
                        debug!(
                            "Unregistered UDP session from reply registry: {}:{} -> {}:{}",
                            self.local_ip, session.local_port, session.dest_ip, session.dest_port
                        );
                    }
                }
                bridge.udp_close(session.socket_handle);
                bridge.remove_socket(session.socket_handle);
                // Return port to allocator for TIME_WAIT
                self.sessions.return_port(session.local_port);
            }
        }

        self.stats.active_udp.fetch_sub(1, Ordering::Relaxed);

        if result.is_err() {
            self.stats.errors.fetch_add(1, Ordering::Relaxed);
        }

        debug!(
            "UDP connection ended: conn_id={}, result={:?}",
            conn_id,
            result.is_ok()
        );
        result
    }

    /// UDP forwarding loop
    ///
    /// Supports both VLESS UDP modes:
    /// - **Basic**: `[Length(2)][Payload]` - uses dest_ip/dest_port from VLESS header
    /// - **XUDP**: `[Length(2)][AddrType][Address][Port][Payload]` - per-packet addressing
    ///
    /// The mode is auto-detected on the first frame by examining the first byte after length.
    async fn udp_forward_loop<S>(
        &self,
        conn_id: &VlessConnectionId,
        stream: &mut S,
        sessions: &mut HashMap<(IpAddr, u16), UdpSessionState>,
        header_dest_ip: IpAddr,
        header_dest_port: u16,
    ) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let (mut reader, mut writer) = tokio::io::split(stream);
        let mut frame_buf = vec![0u8; UDP_RX_BUFFER];
        let mut detected_mode: Option<VlessUdpMode> = None;

        loop {
            if self.is_shutdown() {
                return Err(BridgeError::TunnelDown("bridge shutdown".into()));
            }

            // Poll smoltcp and send packets
            self.poll_and_send().await?;

            // Receive WG replies
            self.receive_wg_replies().await;

            // Check for UDP data to send back to VLESS
            // Pass the detected mode so we know how to format replies
            self.check_udp_replies_with_mode(&mut writer, sessions, detected_mode)
                .await?;

            // Cleanup expired sessions
            self.cleanup_expired_udp_sessions(sessions).await;

            tokio::select! {
                biased;

                // Read UDP frame length
                length_result = reader.read_u16() => {
                    match length_result {
                        Ok(length) => {
                            let length = length as usize;
                            if length == 0 {
                                debug!("VLESS UDP stream closed (zero length)");
                                return Ok(());
                            }
                            if length > frame_buf.len() {
                                warn!("UDP frame too large: {} bytes", length);
                                return Err(BridgeError::SmoltcpUdp(format!(
                                    "UDP frame too large: {} bytes", length
                                )));
                            }

                            // Read the frame content (could be [Payload] or [AddrType][Address][Port][Payload])
                            if let Err(e) = reader.read_exact(&mut frame_buf[..length]).await {
                                if e.kind() == std::io::ErrorKind::UnexpectedEof {
                                    debug!("VLESS UDP stream closed (EOF reading frame)");
                                    return Ok(());
                                }
                                return Err(e.into());
                            }

                            // Detect mode on first packet
                            let mode = *detected_mode.get_or_insert_with(|| {
                                let mode = VlessUdpMode::detect(frame_buf[0]);
                                debug!(
                                    "Detected VLESS UDP mode: {:?} (first_byte=0x{:02x})",
                                    mode, frame_buf[0]
                                );
                                mode
                            });

                            // Parse frame based on mode
                            let (dest_ip, dest_port, payload) = match mode {
                                VlessUdpMode::Basic => {
                                    // Basic mode: entire frame is payload
                                    // Destination is from VLESS header
                                    (header_dest_ip, header_dest_port, &frame_buf[..length])
                                }
                                VlessUdpMode::Xudp => {
                                    // XUDP mode: [AddrType][Address][Port][Payload]
                                    // Parse the frame to extract destination
                                    match self.parse_xudp_frame(&frame_buf[..length]) {
                                        Ok((ip, port, payload_start)) => {
                                            (ip, port, &frame_buf[payload_start..length])
                                        }
                                        Err(e) => {
                                            warn!("Failed to parse XUDP frame: {}", e);
                                            continue;
                                        }
                                    }
                                }
                            };

                            trace!(
                                "Received UDP frame ({:?}): {}:{}, {} bytes payload",
                                mode,
                                dest_ip,
                                dest_port,
                                payload.len()
                            );

                            self.stats
                                .bytes_to_wg
                                .fetch_add(payload.len() as u64, Ordering::Relaxed);

                            // Get or create UDP session for this destination
                            let session = self
                                .get_or_create_udp_session(conn_id, sessions, dest_ip, dest_port)
                                .await?;

                            // Send through smoltcp UDP socket
                            let smoltcp_dest = match dest_ip {
                                IpAddr::V4(v4) => smoltcp::wire::IpEndpoint {
                                    addr: smoltcp::wire::IpAddress::Ipv4(
                                        smoltcp::wire::Ipv4Address::from_bytes(&v4.octets()),
                                    ),
                                    port: dest_port,
                                },
                                IpAddr::V6(_) => {
                                    warn!("IPv6 not supported in smoltcp bridge");
                                    continue;
                                }
                            };

                            {
                                let mut bridge = self.smoltcp.lock().await;
                                if let Err(e) =
                                    bridge.udp_send(session.socket_handle, payload, smoltcp_dest)
                                {
                                    warn!("UDP send failed: {:?}", e);
                                }
                            }

                            // Update activity timestamp
                            session.last_activity.store(
                                std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_secs(),
                                Ordering::Relaxed,
                            );
                        }
                        Err(e) => {
                            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                                debug!("VLESS UDP stream closed (EOF reading length)");
                                return Ok(());
                            }
                            warn!("Error reading UDP frame length: {}", e);
                            return Err(e.into());
                        }
                    }
                }

                // Poll timeout
                _ = tokio::time::sleep(Duration::from_millis(50)) => {}
            }
        }
    }

    /// Parse XUDP frame: [AddrType][Address][Port][Payload]
    ///
    /// Returns (dest_ip, dest_port, payload_start_offset) on success.
    fn parse_xudp_frame(&self, frame: &[u8]) -> Result<(IpAddr, u16, usize)> {
        if frame.is_empty() {
            return Err(BridgeError::SmoltcpUdp("empty XUDP frame".into()));
        }

        let addr_type = frame[0];
        let (addr, addr_end) = match addr_type {
            address_type::IPV4 => {
                if frame.len() < 1 + 4 + 2 {
                    return Err(BridgeError::SmoltcpUdp("XUDP frame too short for IPv4".into()));
                }
                let ip = IpAddr::V4(std::net::Ipv4Addr::new(
                    frame[1], frame[2], frame[3], frame[4],
                ));
                (ip, 5) // 1 (type) + 4 (IPv4)
            }
            address_type::DOMAIN => {
                if frame.len() < 2 {
                    return Err(BridgeError::SmoltcpUdp("XUDP frame too short for domain".into()));
                }
                let domain_len = frame[1] as usize;
                let domain_end = 2 + domain_len;
                if frame.len() < domain_end + 2 {
                    return Err(BridgeError::SmoltcpUdp("XUDP domain truncated".into()));
                }
                let domain = std::str::from_utf8(&frame[2..domain_end])
                    .map_err(|e| BridgeError::SmoltcpUdp(format!("invalid domain: {}", e)))?;

                // For XUDP domains, we need DNS resolution
                // For now, log a warning and skip (or could implement async DNS)
                warn!("XUDP domain addressing not fully supported: {}", domain);
                return Err(BridgeError::SmoltcpUdp(format!(
                    "XUDP domain {} requires DNS resolution (not implemented)", domain
                )));
            }
            address_type::IPV6 => {
                if frame.len() < 1 + 16 + 2 {
                    return Err(BridgeError::SmoltcpUdp("XUDP frame too short for IPv6".into()));
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&frame[1..17]);
                let ip = IpAddr::V6(std::net::Ipv6Addr::from(octets));
                (ip, 17) // 1 (type) + 16 (IPv6)
            }
            _ => {
                return Err(BridgeError::SmoltcpUdp(format!(
                    "invalid XUDP address type: 0x{:02x}", addr_type
                )));
            }
        };

        // Read port (2 bytes after address)
        if frame.len() < addr_end + 2 {
            return Err(BridgeError::SmoltcpUdp("XUDP frame missing port".into()));
        }
        let port = u16::from_be_bytes([frame[addr_end], frame[addr_end + 1]]);

        let payload_start = addr_end + 2;
        Ok((addr, port, payload_start))
    }

    /// Get or create a UDP session for the given destination
    async fn get_or_create_udp_session<'a>(
        &self,
        conn_id: &VlessConnectionId,
        sessions: &'a mut HashMap<(IpAddr, u16), UdpSessionState>,
        dest_ip: IpAddr,
        dest_port: u16,
    ) -> Result<&'a mut UdpSessionState> {
        let key = (dest_ip, dest_port);

        if !sessions.contains_key(&key) {
            // Allocate port
            let port_guard = self
                .sessions
                .allocate_port()
                .ok_or(BridgeError::PortExhausted)?;
            let local_port = port_guard.take(); // Take ownership, we'll manage cleanup

            // Create UDP socket
            let socket_handle = {
                let mut bridge = self.smoltcp.lock().await;
                let handle = bridge
                    .create_udp_socket()
                    .ok_or(BridgeError::SocketLimitReached(MAX_SOCKETS))?;

                // Bind to local port
                if let Err(e) = bridge.udp_bind(handle, local_port) {
                    bridge.remove_socket(handle);
                    self.sessions.return_port(local_port);
                    return Err(BridgeError::SmoltcpUdp(format!("bind failed: {e:?}")));
                }

                handle
            };

            // Register with reply registry for WG reply routing
            let reply_key = if self.reply_registry.is_some() {
                let key = VlessReplyKey::new(
                    self.wg_tag.clone(),
                    self.local_ip,
                    local_port,
                    dest_ip,
                    dest_port,
                );
                if let Some(ref registry) = self.reply_registry {
                    registry.register(key.clone(), self.wg_reply_tx.clone(), conn_id.client_addr);
                    debug!(
                        "Registered UDP session with reply registry: tunnel={} {}:{} -> {}:{}",
                        self.wg_tag, self.local_ip, local_port, dest_ip, dest_port
                    );
                }
                Some(key)
            } else {
                None
            };

            debug!(
                "Created UDP session: local_port={}, dest={}:{}",
                local_port, dest_ip, dest_port
            );

            let session = UdpSessionState {
                socket_handle,
                local_port,
                dest_ip,
                dest_port,
                last_activity: AtomicU64::new(
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                ),
                reply_key,
            };

            sessions.insert(key, session);
        }

        Ok(sessions.get_mut(&key).expect("session was just inserted"))
    }

    /// Check for UDP replies and write them back to VLESS client
    ///
    /// Writes in the appropriate VLESS UDP format based on detected mode:
    /// - **Basic**: `[Length(2)][Payload]`
    /// - **XUDP**: `[Length(2)][AddrType][Address][Port][Payload]`
    async fn check_udp_replies_with_mode<W>(
        &self,
        writer: &mut W,
        sessions: &HashMap<(IpAddr, u16), UdpSessionState>,
        mode: Option<VlessUdpMode>,
    ) -> Result<()>
    where
        W: AsyncWrite + Unpin,
    {
        let mut bridge = self.smoltcp.lock().await;
        bridge.poll();

        for session in sessions.values() {
            if bridge.udp_can_recv(session.socket_handle) {
                match bridge.udp_recv(session.socket_handle) {
                    Ok((data, endpoint)) => {
                        trace!("UDP reply: {} bytes from {:?}", data.len(), endpoint);
                        self.stats
                            .bytes_from_wg
                            .fetch_add(data.len() as u64, Ordering::Relaxed);

                        // Release lock before async write
                        drop(bridge);

                        // Write in appropriate format based on mode
                        match mode.unwrap_or(VlessUdpMode::Basic) {
                            VlessUdpMode::Basic => {
                                // Basic: [Length(2)][Payload]
                                let length = data.len() as u16;
                                writer.write_u16(length).await?;
                                writer.write_all(&data).await?;
                            }
                            VlessUdpMode::Xudp => {
                                // XUDP: [Length(2)][AddrType][Address][Port][Payload]
                                // Use VlessUdpFrame for proper formatting
                                let frame = VlessUdpFrame::from_ip(
                                    session.dest_ip,
                                    session.dest_port,
                                    data,
                                );
                                let encoded = frame.encode();
                                writer.write_all(&encoded).await?;
                            }
                        }

                        // Re-acquire lock for next iteration
                        bridge = self.smoltcp.lock().await;
                    }
                    Err(e) => {
                        trace!("UDP recv error: {:?}", e);
                    }
                }
            }
        }

        Ok(())
    }

    /// Cleanup expired UDP sessions
    async fn cleanup_expired_udp_sessions(
        &self,
        sessions: &mut HashMap<(IpAddr, u16), UdpSessionState>,
    ) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut expired = Vec::new();

        for (key, session) in sessions.iter() {
            let last = session.last_activity.load(Ordering::Relaxed);
            let timeout = if session.dest_port == 53 {
                UDP_DNS_TIMEOUT_SECS
            } else {
                UDP_DEFAULT_TIMEOUT_SECS
            };

            if now.saturating_sub(last) > timeout {
                expired.push(*key);
            }
        }

        if !expired.is_empty() {
            let mut bridge = self.smoltcp.lock().await;
            for key in expired {
                if let Some(session) = sessions.remove(&key) {
                    debug!("Expiring UDP session: dest={}:{}", key.0, key.1);
                    // Unregister from reply registry first
                    if let Some(ref reply_key) = session.reply_key {
                        if let Some(ref registry) = self.reply_registry {
                            registry.unregister(reply_key);
                            debug!(
                                "Unregistered expired UDP session from reply registry: {}:{} -> {}:{}",
                                self.local_ip, session.local_port, session.dest_ip, session.dest_port
                            );
                        }
                    }
                    bridge.udp_close(session.socket_handle);
                    bridge.remove_socket(session.socket_handle);
                    // Return port to allocator for TIME_WAIT
                    self.sessions.return_port(session.local_port);
                }
            }
        }
    }

    // ========================================================================
    // Raw UDP API for Shadowsocks and similar protocols
    // ========================================================================

    /// Send a raw UDP packet through the WireGuard tunnel
    ///
    /// This is designed for protocols like Shadowsocks that send individual
    /// UDP packets rather than using VLESS UDP framing.
    ///
    /// # Arguments
    ///
    /// * `client_addr` - Original client address (for reply routing)
    /// * `dest_ip` - Destination IP address
    /// * `dest_port` - Destination port
    /// * `payload` - UDP payload to send
    ///
    /// # Returns
    ///
    /// Returns Ok(()) if the packet was queued for sending.
    /// Replies can be received via `try_recv_raw_udp_reply()`.
    pub async fn send_raw_udp_packet(
        &self,
        client_addr: SocketAddr,
        dest_ip: IpAddr,
        dest_port: u16,
        payload: &[u8],
    ) -> Result<()> {
        if self.is_shutdown() {
            return Err(BridgeError::TunnelDown("bridge is shutting down".into()));
        }

        // Check tunnel health
        if !self.check_tunnel_health().await {
            return Err(BridgeError::TunnelDown(format!(
                "WG tunnel '{}' is not healthy",
                self.wg_tag
            )));
        }

        let session_key = RawUdpSessionKey::new(client_addr, dest_ip, dest_port);

        // Get or create session
        let socket_handle = {
            let sessions = self.raw_udp_sessions.read();
            if let Some(session) = sessions.get(&session_key) {
                // Update activity timestamp
                session.last_activity.store(
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                    Ordering::Relaxed,
                );
                Some(session.socket_handle)
            } else {
                None
            }
        };

        let socket_handle = match socket_handle {
            Some(h) => h,
            None => {
                // Create new session
                self.create_raw_udp_session(session_key).await?
            }
        };

        // Send through smoltcp UDP socket
        let smoltcp_dest = match dest_ip {
            IpAddr::V4(v4) => smoltcp::wire::IpEndpoint {
                addr: smoltcp::wire::IpAddress::Ipv4(
                    smoltcp::wire::Ipv4Address::from_bytes(&v4.octets()),
                ),
                port: dest_port,
            },
            IpAddr::V6(_) => {
                warn!("IPv6 not supported in smoltcp bridge");
                return Err(BridgeError::SmoltcpUdp("IPv6 not supported".into()));
            }
        };

        {
            let mut bridge = self.smoltcp.lock().await;
            if let Err(e) = bridge.udp_send(socket_handle, payload, smoltcp_dest) {
                warn!("UDP send failed: {:?}", e);
                return Err(BridgeError::SmoltcpUdp(format!("send failed: {:?}", e)));
            }
        }

        self.stats
            .bytes_to_wg
            .fetch_add(payload.len() as u64, Ordering::Relaxed);

        trace!(
            "Sent raw UDP packet: client={}, dest={}:{}, {} bytes",
            client_addr,
            dest_ip,
            dest_port,
            payload.len()
        );

        Ok(())
    }

    /// Create a raw UDP session
    async fn create_raw_udp_session(&self, key: RawUdpSessionKey) -> Result<SocketHandle> {
        // Allocate port
        let port_guard = self
            .sessions
            .allocate_port()
            .ok_or(BridgeError::PortExhausted)?;
        let local_port = port_guard.take();

        // Create UDP socket
        let socket_handle = {
            let mut bridge = self.smoltcp.lock().await;
            let handle = bridge
                .create_udp_socket()
                .ok_or(BridgeError::SocketLimitReached(MAX_SOCKETS))?;

            // Bind to local port
            if let Err(e) = bridge.udp_bind(handle, local_port) {
                bridge.remove_socket(handle);
                self.sessions.return_port(local_port);
                return Err(BridgeError::SmoltcpUdp(format!("bind failed: {e:?}")));
            }

            handle
        };

        // Register with reply registry for WG reply routing
        let reply_key = if self.reply_registry.is_some() {
            let rk = VlessReplyKey::new(
                self.wg_tag.clone(),
                self.local_ip,
                local_port,
                key.dest_ip,
                key.dest_port,
            );
            if let Some(ref registry) = self.reply_registry {
                registry.register(rk.clone(), self.wg_reply_tx.clone(), key.client_addr);
                debug!(
                    "Registered raw UDP session with reply registry: tunnel={} {}:{} -> {}:{}",
                    self.wg_tag, self.local_ip, local_port, key.dest_ip, key.dest_port
                );
            }
            Some(rk)
        } else {
            None
        };

        let session = RawUdpSessionState {
            socket_handle,
            local_port,
            dest_ip: key.dest_ip,
            dest_port: key.dest_port,
            client_addr: key.client_addr,
            last_activity: AtomicU64::new(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            ),
            reply_key,
        };

        debug!(
            "Created raw UDP session: client={}, local_port={}, dest={}:{}",
            key.client_addr, local_port, key.dest_ip, key.dest_port
        );

        let mut sessions = self.raw_udp_sessions.write();
        sessions.insert(key, session);

        self.stats.udp_sessions.fetch_add(1, Ordering::Relaxed);
        self.stats.active_udp.fetch_add(1, Ordering::Relaxed);

        Ok(socket_handle)
    }

    /// Poll for raw UDP replies and queue them
    ///
    /// This should be called periodically to:
    /// 1. Poll smoltcp and send outgoing WG packets
    /// 2. Receive WG replies
    /// 3. Check smoltcp sockets for incoming data
    /// 4. Queue replies for retrieval via `try_recv_raw_udp_reply()`
    pub async fn poll_raw_udp(&self) -> Result<()> {
        if self.is_shutdown() {
            return Ok(());
        }

        // Poll smoltcp and send packets
        self.poll_and_send().await?;

        // Receive WG replies
        self.receive_wg_replies().await;

        // Check for UDP data from smoltcp sockets
        self.check_raw_udp_socket_replies().await?;

        // Cleanup expired sessions
        self.cleanup_raw_udp_sessions().await;

        Ok(())
    }

    /// Check smoltcp UDP sockets for replies and queue them
    async fn check_raw_udp_socket_replies(&self) -> Result<()> {
        // Collect session info first to avoid holding the RwLock guard across await
        let session_info: Vec<(RawUdpSessionKey, SocketHandle)> = {
            let sessions = self.raw_udp_sessions.read();
            sessions
                .iter()
                .map(|(k, s)| (*k, s.socket_handle))
                .collect()
        };

        // Now lock the bridge (this is async)
        let mut bridge = self.smoltcp.lock().await;

        for (key, socket_handle) in session_info {
            // Try to receive data from this socket
            match bridge.udp_recv(socket_handle) {
                Ok((data, endpoint)) => {
                    if !data.is_empty() {
                        let source_ip = match endpoint.addr {
                            smoltcp::wire::IpAddress::Ipv4(v4) => {
                                IpAddr::V4(std::net::Ipv4Addr::from(v4.0))
                            }
                        };

                        let n = data.len();
                        let reply = RawUdpReply {
                            session_key: key,
                            source_ip,
                            source_port: endpoint.port,
                            payload: bytes::Bytes::from(data),
                        };

                        self.stats
                            .bytes_from_wg
                            .fetch_add(n as u64, Ordering::Relaxed);

                        trace!(
                            "Received raw UDP reply: from {}:{} -> client {}, {} bytes",
                            source_ip,
                            endpoint.port,
                            key.client_addr,
                            n
                        );

                        // Queue the reply
                        if let Err(e) = self.raw_udp_reply_tx.try_send(reply) {
                            warn!("Failed to queue raw UDP reply: {:?}", e);
                        }
                    }
                }
                Err(smoltcp::socket::udp::RecvError::Exhausted) => {
                    // No data available, that's fine
                }
                Err(e) => {
                    trace!("UDP recv error (non-fatal): {:?}", e);
                }
            }
        }

        Ok(())
    }

    /// Try to receive a raw UDP reply (non-blocking)
    ///
    /// Returns the next reply if available, or None if no replies are pending.
    pub fn try_recv_raw_udp_reply(&self) -> Option<RawUdpReply> {
        // We need to use try_lock since this might be called from sync context
        if let Ok(mut rx) = self.raw_udp_reply_rx.try_lock() {
            rx.try_recv().ok()
        } else {
            None
        }
    }

    /// Receive a raw UDP reply (async, blocking)
    ///
    /// Returns the next reply when available.
    pub async fn recv_raw_udp_reply(&self) -> Option<RawUdpReply> {
        let mut rx = self.raw_udp_reply_rx.lock().await;
        rx.recv().await
    }

    /// Cleanup expired raw UDP sessions
    async fn cleanup_raw_udp_sessions(&self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // First pass: find expired session keys (sync lock)
        let expired: Vec<RawUdpSessionKey> = {
            let sessions = self.raw_udp_sessions.read();
            sessions
                .iter()
                .filter(|(_, session)| {
                    let last = session.last_activity.load(Ordering::Relaxed);
                    let timeout = if session.dest_port == 53 {
                        UDP_DNS_TIMEOUT_SECS
                    } else {
                        UDP_DEFAULT_TIMEOUT_SECS
                    };
                    now.saturating_sub(last) > timeout
                })
                .map(|(k, _)| *k)
                .collect()
        };

        if expired.is_empty() {
            return;
        }

        // Lock smoltcp first (async) - before acquiring the sync lock
        let mut bridge = self.smoltcp.lock().await;

        // Now lock sessions (sync) and do cleanup
        let mut sessions = self.raw_udp_sessions.write();
        for key in expired {
            if let Some(session) = sessions.remove(&key) {
                debug!(
                    "Expiring raw UDP session: client={}, dest={}:{}",
                    key.client_addr, key.dest_ip, key.dest_port
                );

                // Unregister from reply registry first
                if let Some(ref reply_key) = session.reply_key {
                    if let Some(ref registry) = self.reply_registry {
                        registry.unregister(reply_key);
                    }
                }

                bridge.udp_close(session.socket_handle);
                bridge.remove_socket(session.socket_handle);
                self.sessions.return_port(session.local_port);
                self.stats.active_udp.fetch_sub(1, Ordering::Relaxed);
            }
        }
    }

    /// Close all raw UDP sessions
    ///
    /// Call this when shutting down the bridge.
    pub async fn close_all_raw_udp_sessions(&self) {
        // Lock smoltcp first (async), then acquire sync lock
        let mut bridge = self.smoltcp.lock().await;
        let mut sessions = self.raw_udp_sessions.write();

        for (key, session) in sessions.drain() {
            debug!(
                "Closing raw UDP session: client={}, dest={}:{}",
                key.client_addr, key.dest_ip, key.dest_port
            );

            // Unregister from reply registry
            if let Some(ref reply_key) = session.reply_key {
                if let Some(ref registry) = self.reply_registry {
                    registry.unregister(reply_key);
                }
            }

            bridge.udp_close(session.socket_handle);
            bridge.remove_socket(session.socket_handle);
            self.sessions.return_port(session.local_port);
            self.stats.active_udp.fetch_sub(1, Ordering::Relaxed);
        }

        info!("Closed all raw UDP sessions");
    }
}

/// Internal UDP session state
///
/// Tracks a single UDP "session" - a destination endpoint that we're
/// proxying UDP traffic to/from through the WireGuard tunnel.
struct UdpSessionState {
    /// smoltcp socket handle
    socket_handle: SocketHandle,
    /// Local port (allocated from port allocator)
    local_port: u16,
    /// Destination IP address (used for logging/debugging)
    #[allow(dead_code)]
    dest_ip: IpAddr,
    /// Destination port
    dest_port: u16,
    /// Last activity timestamp (Unix timestamp in seconds)
    last_activity: AtomicU64,
    /// Reply registry key (for unregistration on cleanup)
    reply_key: Option<VlessReplyKey>,
}

/// Raw UDP session state for external callers (Shadowsocks, etc.)
///
/// Similar to UdpSessionState but designed for packet-at-a-time operation
/// rather than continuous stream processing.
struct RawUdpSessionState {
    /// smoltcp socket handle
    socket_handle: SocketHandle,
    /// Local port (allocated from port allocator)
    local_port: u16,
    /// Destination IP address
    dest_ip: IpAddr,
    /// Destination port
    dest_port: u16,
    /// Client address (for reply routing)
    client_addr: SocketAddr,
    /// Last activity timestamp (Unix timestamp in seconds)
    last_activity: AtomicU64,
    /// Reply registry key (for unregistration on cleanup)
    reply_key: Option<VlessReplyKey>,
}

impl Drop for VlessWgBridge {
    fn drop(&mut self) {
        info!("VlessWgBridge dropped for tunnel '{}'", self.wg_tag);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bridge_stats() {
        let stats = BridgeStats::new();
        stats.tcp_connections.fetch_add(5, Ordering::Relaxed);
        stats.bytes_to_wg.fetch_add(1000, Ordering::Relaxed);

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.tcp_connections, 5);
        assert_eq!(snapshot.bytes_to_wg, 1000);
    }

    #[test]
    fn test_bridge_stats_snapshot_default() {
        let snapshot = BridgeStatsSnapshot::default();
        assert_eq!(snapshot.tcp_connections, 0);
        assert_eq!(snapshot.udp_sessions, 0);
        assert_eq!(snapshot.bytes_to_wg, 0);
        assert_eq!(snapshot.bytes_from_wg, 0);
        assert_eq!(snapshot.active_tcp, 0);
        assert_eq!(snapshot.active_udp, 0);
        assert_eq!(snapshot.errors, 0);
    }

    #[test]
    fn test_wg_reply_packet() {
        let packet = WgReplyPacket {
            tag: "test-tunnel".to_string(),
            packet: vec![1, 2, 3, 4],
        };
        assert_eq!(packet.tag, "test-tunnel");
        assert_eq!(packet.packet.len(), 4);
    }

    #[test]
    fn test_wg_reply_packet_debug() {
        let packet = WgReplyPacket {
            tag: "test".to_string(),
            packet: vec![1, 2, 3],
        };
        let debug_str = format!("{:?}", packet);
        assert!(debug_str.contains("WgReplyPacket"));
        assert!(debug_str.contains("test"));
    }

    #[test]
    fn test_bridge_stats_all_fields() {
        let stats = BridgeStats::new();
        stats.tcp_connections.fetch_add(10, Ordering::Relaxed);
        stats.udp_sessions.fetch_add(5, Ordering::Relaxed);
        stats.bytes_to_wg.fetch_add(1000, Ordering::Relaxed);
        stats.bytes_from_wg.fetch_add(2000, Ordering::Relaxed);
        stats.active_tcp.fetch_add(3, Ordering::Relaxed);
        stats.active_udp.fetch_add(2, Ordering::Relaxed);
        stats.errors.fetch_add(1, Ordering::Relaxed);

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.tcp_connections, 10);
        assert_eq!(snapshot.udp_sessions, 5);
        assert_eq!(snapshot.bytes_to_wg, 1000);
        assert_eq!(snapshot.bytes_from_wg, 2000);
        assert_eq!(snapshot.active_tcp, 3);
        assert_eq!(snapshot.active_udp, 2);
        assert_eq!(snapshot.errors, 1);
    }

    #[test]
    fn test_bridge_stats_snapshot_serialization() {
        let snapshot = BridgeStatsSnapshot {
            tcp_connections: 100,
            udp_sessions: 50,
            bytes_to_wg: 10000,
            bytes_from_wg: 20000,
            active_tcp: 10,
            active_udp: 5,
            errors: 2,
        };

        let json = serde_json::to_string(&snapshot).expect("Should serialize");
        assert!(json.contains("100"));
        assert!(json.contains("10000"));
        assert!(json.contains("20000"));
    }

    // Note: Full integration tests require mocking WgEgressManager
    // which would be done in a separate integration test file
}
