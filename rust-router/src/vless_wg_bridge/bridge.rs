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

use super::udp_frame::{UdpFrameAddress, VlessUdpFrame};

use crate::egress::config::EgressState;
use crate::egress::manager::WgEgressManager;
use crate::tunnel::smoltcp_bridge::SmoltcpBridge;

use super::config::{
    MAX_SOCKETS, TCP_IDLE_TIMEOUT_SECS, TCP_RX_BUFFER, TCP_TX_BUFFER, UDP_DEFAULT_TIMEOUT_SECS,
    UDP_DNS_TIMEOUT_SECS, UDP_RX_BUFFER, WG_MTU, WG_REPLY_CHANNEL_SIZE,
};
use super::error::{BridgeError, Result};
use super::port_allocator::PortAllocator;
use super::session::{SessionKey, SessionTracker, VlessConnectionId};
use super::socket_guard::TcpSocketGuard;

/// WireGuard reply packet
#[derive(Debug)]
pub struct WgReplyPacket {
    /// Tunnel tag
    pub tag: String,
    /// IP packet data
    pub packet: Vec<u8>,
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

        info!(
            "VlessWgBridge created: wg_tag={}, local_ip={}",
            wg_tag, local_ip
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

        // Update stats
        self.stats.tcp_connections.fetch_add(1, Ordering::Relaxed);
        self.stats.active_tcp.fetch_add(1, Ordering::Relaxed);

        // Run the forwarding loop
        let result = self
            .tcp_forward_loop(&conn_id, stream, socket_handle, &session_key)
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
    async fn tcp_forward_loop<S>(
        &self,
        _conn_id: &VlessConnectionId,
        stream: S,
        socket_handle: SocketHandle,
        _session_key: &SessionKey,
    ) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let (mut reader, mut writer) = tokio::io::split(stream);
        let mut vless_buf = vec![0u8; TCP_RX_BUFFER];
        let mut smoltcp_buf = vec![0u8; TCP_TX_BUFFER];

        // Half-close tracking
        let mut vless_closed = false;
        let mut smoltcp_closed = false;

        // Wait for connection to establish
        let connected = self.wait_for_tcp_connect(socket_handle).await?;
        if !connected {
            return Err(BridgeError::ConnectionTimeout);
        }

        loop {
            // Check shutdown
            if self.is_shutdown() {
                return Err(BridgeError::TunnelDown("bridge shutdown".into()));
            }

            // Poll smoltcp and send generated packets
            self.poll_and_send().await?;

            // Receive WG replies and feed to smoltcp
            self.receive_wg_replies().await;

            // Poll again after feeding replies
            {
                let mut bridge = self.smoltcp.lock().await;
                bridge.poll();
            }

            // Check socket state
            let socket_state = {
                let bridge = self.smoltcp.lock().await;
                bridge.tcp_socket_state(socket_handle)
            };

            // Handle various TCP states
            match socket_state {
                TcpState::Closed | TcpState::TimeWait => {
                    debug!("TCP socket closed/timewait, ending loop");
                    smoltcp_closed = true;
                    if vless_closed {
                        break;
                    }
                }
                TcpState::CloseWait => {
                    // Remote closed, but we can still send
                    smoltcp_closed = true;
                }
                TcpState::LastAck | TcpState::Closing => {
                    // Connection is closing
                    if vless_closed {
                        break;
                    }
                }
                _ => {}
            }

            // Calculate poll delay
            let poll_delay = {
                let mut bridge = self.smoltcp.lock().await;
                bridge.poll_delay().unwrap_or(Duration::from_millis(10))
            };
            let poll_delay = poll_delay.min(Duration::from_millis(100));

            tokio::select! {
                biased;

                // VLESS -> smoltcp (forward direction)
                result = reader.read(&mut vless_buf), if !vless_closed => {
                    match result {
                        Ok(0) => {
                            // VLESS client closed - send FIN
                            debug!("VLESS client closed, sending FIN to remote");
                            vless_closed = true;
                            let mut bridge = self.smoltcp.lock().await;
                            bridge.tcp_close(socket_handle);
                        }
                        Ok(n) => {
                            trace!("Read {} bytes from VLESS", n);
                            self.stats.bytes_to_wg.fetch_add(n as u64, Ordering::Relaxed);

                            // Send to smoltcp socket
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
                        }
                        Err(e) => {
                            warn!("VLESS read error: {}", e);
                            return Err(e.into());
                        }
                    }
                }

                // smoltcp -> VLESS (reverse direction)
                _ = tokio::time::sleep(Duration::from_millis(1)), if !smoltcp_closed => {
                    let mut bridge = self.smoltcp.lock().await;
                    let socket = bridge.get_tcp_socket_mut(socket_handle);

                    if socket.can_recv() {
                        match socket.recv_slice(&mut smoltcp_buf) {
                            Ok(n) if n > 0 => {
                                trace!("Read {} bytes from smoltcp", n);
                                self.stats.bytes_from_wg.fetch_add(n as u64, Ordering::Relaxed);

                                // Release lock before async write
                                drop(bridge);

                                if let Err(e) = writer.write_all(&smoltcp_buf[..n]).await {
                                    warn!("VLESS write error: {}", e);
                                    return Err(e.into());
                                }
                            }
                            Ok(_) => {}
                            Err(e) => {
                                trace!("smoltcp recv error: {:?}", e);
                            }
                        }
                    }
                }

                // Poll timeout
                _ = tokio::time::sleep(poll_delay) => {}
            }

            // Exit if both sides closed
            if vless_closed && smoltcp_closed {
                debug!("Both sides closed, exiting loop");
                break;
            }
        }

        Ok(())
    }

    /// Wait for TCP connection to establish
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
    pub async fn handle_udp_connection<S>(
        &self,
        client_addr: SocketAddr,
        mut stream: S,
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
            .udp_forward_loop(&conn_id, &mut stream, &mut udp_sessions)
            .await;

        // Cleanup all UDP sessions
        {
            let mut bridge = self.smoltcp.lock().await;
            for (_, session) in udp_sessions.drain() {
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
    async fn udp_forward_loop<S>(
        &self,
        conn_id: &VlessConnectionId,
        stream: &mut S,
        sessions: &mut HashMap<(IpAddr, u16), UdpSessionState>,
    ) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let (mut reader, mut writer) = tokio::io::split(stream);
        let mut _read_buf = vec![0u8; UDP_RX_BUFFER];

        loop {
            if self.is_shutdown() {
                return Err(BridgeError::TunnelDown("bridge shutdown".into()));
            }

            // Poll smoltcp and send packets
            self.poll_and_send().await?;

            // Receive WG replies
            self.receive_wg_replies().await;

            // Check for UDP data to send back to VLESS
            self.check_udp_replies(&mut writer, sessions).await?;

            // Cleanup expired sessions
            self.cleanup_expired_udp_sessions(sessions).await;

            tokio::select! {
                biased;

                // Read UDP frame from VLESS (with timeout)
                result = VlessUdpFrame::read_from(&mut reader) => {
                    match result {
                        Ok(Some(frame)) => {
                            trace!(
                                "Received UDP frame: {}:{}, {} bytes",
                                frame.address,
                                frame.port,
                                frame.payload.len()
                            );

                            self.stats
                                .bytes_to_wg
                                .fetch_add(frame.payload.len() as u64, Ordering::Relaxed);

                            // Resolve destination IP
                            let dest_ip = match &frame.address {
                                UdpFrameAddress::Ipv4(ip) => IpAddr::V4(*ip),
                                UdpFrameAddress::Ipv6(ip) => IpAddr::V6(*ip),
                                UdpFrameAddress::Domain(domain) => {
                                    // For now, skip domain resolution - would need DNS resolver
                                    warn!("Domain resolution not implemented: {}", domain);
                                    continue;
                                }
                            };

                            // Get or create UDP session for this destination
                            let session = self
                                .get_or_create_udp_session(conn_id, sessions, dest_ip, frame.port)
                                .await?;

                            // Send through smoltcp UDP socket
                            let smoltcp_dest = match dest_ip {
                                IpAddr::V4(v4) => smoltcp::wire::IpEndpoint {
                                    addr: smoltcp::wire::IpAddress::Ipv4(
                                        smoltcp::wire::Ipv4Address::from_bytes(&v4.octets()),
                                    ),
                                    port: frame.port,
                                },
                                IpAddr::V6(_) => {
                                    warn!("IPv6 not supported in smoltcp bridge");
                                    continue;
                                }
                            };

                            {
                                let mut bridge = self.smoltcp.lock().await;
                                if let Err(e) =
                                    bridge.udp_send(session.socket_handle, &frame.payload, smoltcp_dest)
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
                        Ok(None) => {
                            // Clean EOF from VLESS
                            debug!("VLESS UDP stream closed");
                            return Ok(());
                        }
                        Err(e) => {
                            warn!("Error reading UDP frame: {}", e);
                            return Err(e);
                        }
                    }
                }

                // Poll timeout
                _ = tokio::time::sleep(Duration::from_millis(50)) => {}
            }
        }
    }

    /// Get or create a UDP session for the given destination
    async fn get_or_create_udp_session<'a>(
        &self,
        _conn_id: &VlessConnectionId,
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
            };

            sessions.insert(key, session);
        }

        Ok(sessions.get_mut(&key).expect("session was just inserted"))
    }

    /// Check for UDP replies and send back to VLESS
    async fn check_udp_replies<W>(
        &self,
        writer: &mut W,
        sessions: &HashMap<(IpAddr, u16), UdpSessionState>,
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

                        // Convert endpoint to address
                        let address = match endpoint.addr {
                            smoltcp::wire::IpAddress::Ipv4(v4) => {
                                UdpFrameAddress::Ipv4(std::net::Ipv4Addr::from(v4.0))
                            }
                            // smoltcp IPv6 is optional, handle if present
                            #[allow(unreachable_patterns)]
                            _ => {
                                warn!("Unsupported IP address type in UDP reply");
                                continue;
                            }
                        };

                        let frame = VlessUdpFrame::new(address, endpoint.port, data);

                        // Release lock before async write
                        drop(bridge);

                        frame.write_to(writer).await?;

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
                    bridge.udp_close(session.socket_handle);
                    bridge.remove_socket(session.socket_handle);
                    // Return port to allocator for TIME_WAIT
                    self.sessions.return_port(session.local_port);
                }
            }
        }
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
