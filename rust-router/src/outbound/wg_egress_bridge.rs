//! WireGuard Egress Bridge
//!
//! This module provides `WgEgressBridge`, which bridges TCP/UDP streams from
//! ipstack to WireGuard egress tunnels using smoltcp as the userspace TCP/IP stack.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────────┐
//! │                          WgEgressBridge                                     │
//! ├─────────────────────────────────────────────────────────────────────────────┤
//! │                                                                             │
//! │  TCP/UDP Stream (from ipstack)                                             │
//! │         │                                                                   │
//! │         ▼                                                                   │
//! │  ┌─────────────────┐                                                       │
//! │  │  forward_tcp()  │  Uses tokio::select! loop pattern                     │
//! │  │  forward_udp()  │  (similar to VlessWgBridge)                           │
//! │  └────────┬────────┘                                                       │
//! │           │                                                                 │
//! │           ▼                                                                 │
//! │  ┌─────────────────────────────────────────────────────────────────────┐   │
//! │  │                    SmoltcpBridge                                     │   │
//! │  │  - TCP socket management                                            │   │
//! │  │  - UDP socket management                                            │   │
//! │  │  - IP packet generation                                             │   │
//! │  └─────────────────────────────────────────────────────────────────────┘   │
//! │           │                                                                 │
//! │           ▼ (IP packets)                                                   │
//! │  ┌─────────────────────────────────────────────────────────────────────┐   │
//! │  │                    WgEgressManager                                   │   │
//! │  │  - Encrypts packets via boringtun                                   │   │
//! │  │  - Sends to WireGuard peer                                          │   │
//! │  └─────────────────────────────────────────────────────────────────────┘   │
//! │           │                                                                 │
//! │           ▼                                                                 │
//! │  Reply packets flow back via reply_channels                                │
//! │                                                                             │
//! └─────────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Usage
//!
//! ```ignore
//! use std::sync::Arc;
//! use std::net::{IpAddr, Ipv4Addr, SocketAddr};
//! use rust_router::outbound::wg_egress_bridge::WgEgressBridge;
//! use rust_router::egress::WgEgressManager;
//!
//! // Create bridge for a specific WG egress tunnel
//! let bridge = WgEgressBridge::new(
//!     "wg-pia-nyc".to_string(),
//!     wg_egress_manager,
//!     Ipv4Addr::new(10, 200, 200, 2),
//! );
//!
//! // Forward a TCP stream
//! let dest = "1.1.1.1:443".parse().unwrap();
//! bridge.forward_tcp(tcp_stream, dest).await?;
//! ```
//!
//! # Thread Safety
//!
//! `WgEgressBridge` is `Send + Sync` and designed to be shared across async tasks.
//! The internal smoltcp bridge is protected by `tokio::sync::Mutex`.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use smoltcp::iface::SocketHandle;
use smoltcp::socket::tcp::State as TcpState;
use smoltcp::wire::IpAddress;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, info, trace, warn};

use crate::egress::config::EgressState;
use crate::egress::manager::WgEgressManager;
use crate::smoltcp_utils::{
    BridgeError, PortAllocator, Result, SessionTracker, TcpSocketGuard, UdpSocketGuard,
    MAX_SOCKETS, TCP_RX_BUFFER, TCP_TX_BUFFER, UDP_DEFAULT_TIMEOUT_SECS, UDP_DNS_TIMEOUT_SECS,
    WG_MTU, WG_REPLY_CHANNEL_SIZE,
};
use crate::tunnel::smoltcp_bridge::SmoltcpBridge;

// =============================================================================
// Configuration Constants (module-specific)
// =============================================================================

/// Timer interval for TCP state machine polling (ms)
/// This is module-specific and not shared with other modules.
const TCP_TIMER_INTERVAL_MS: u64 = 5;

/// Connect timeout in seconds
/// This is module-specific for TCP connection establishment.
const CONNECT_TIMEOUT_SECS: u64 = 30;

// =============================================================================
// Statistics
// =============================================================================

/// Statistics for the WG egress bridge
#[derive(Debug, Default)]
pub struct WgEgressBridgeStats {
    /// Total TCP connections handled
    pub tcp_connections: AtomicU64,
    /// Total UDP sessions handled
    pub udp_sessions: AtomicU64,
    /// Total bytes sent to WG tunnel
    pub bytes_to_wg: AtomicU64,
    /// Total bytes received from WG tunnel
    pub bytes_from_wg: AtomicU64,
    /// Active TCP connections
    pub active_tcp: AtomicU64,
    /// Active UDP sessions
    pub active_udp: AtomicU64,
    /// Connection errors
    pub errors: AtomicU64,
}

impl WgEgressBridgeStats {
    /// Create new statistics
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Get a snapshot of current statistics
    #[must_use]
    pub fn snapshot(&self) -> WgEgressBridgeStatsSnapshot {
        WgEgressBridgeStatsSnapshot {
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

/// Snapshot of bridge statistics (for serialization)
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct WgEgressBridgeStatsSnapshot {
    /// Total TCP connections handled
    pub tcp_connections: u64,
    /// Total UDP sessions handled
    pub udp_sessions: u64,
    /// Total bytes sent to WG tunnel
    pub bytes_to_wg: u64,
    /// Total bytes received from WG tunnel
    pub bytes_from_wg: u64,
    /// Active TCP connections
    pub active_tcp: u64,
    /// Active UDP sessions
    pub active_udp: u64,
    /// Connection errors
    pub errors: u64,
}

// =============================================================================
// Reply Packet
// =============================================================================

/// WireGuard reply packet from the tunnel
#[derive(Debug)]
pub struct WgReplyPacket {
    /// Tunnel tag
    pub tag: String,
    /// IP packet data
    pub packet: Vec<u8>,
}

// =============================================================================
// Reply Key
// =============================================================================

/// Key for routing WG replies back to the correct session
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ReplyKey {
    /// Tunnel tag
    pub tunnel_tag: String,
    /// Local IP (bridge IP in the WG tunnel)
    pub local_ip: IpAddr,
    /// Local port (ephemeral port allocated by the bridge)
    pub local_port: u16,
    /// Remote IP (destination)
    pub remote_ip: IpAddr,
    /// Remote port (destination)
    pub remote_port: u16,
}

impl ReplyKey {
    /// Create a new reply key
    #[must_use]
    pub fn new(
        tunnel_tag: String,
        local_ip: IpAddr,
        local_port: u16,
        remote_ip: IpAddr,
        remote_port: u16,
    ) -> Self {
        Self {
            tunnel_tag,
            local_ip,
            local_port,
            remote_ip,
            remote_port,
        }
    }
}

// =============================================================================
// WgEgressBridge
// =============================================================================

/// Bridge for forwarding TCP/UDP streams to WireGuard egress tunnels
///
/// This bridge uses smoltcp to convert TCP/UDP streams into IP packets
/// that can be sent through WireGuard tunnels via `WgEgressManager`.
///
/// # Features
///
/// - TCP stream forwarding with proper half-close handling
/// - UDP datagram forwarding with session tracking
/// - Event-driven reply handling via per-connection channels
/// - Automatic port allocation with TIME_WAIT tracking
/// - RAII socket guards for guaranteed cleanup
///
/// # Thread Safety
///
/// `WgEgressBridge` is `Send + Sync` and can be safely shared across tasks.
pub struct WgEgressBridge {
    /// Tunnel tag (identifies the WG egress tunnel)
    tunnel_tag: String,

    /// smoltcp bridge (TCP/IP stack) - Arc for sharing with socket guards
    smoltcp: Arc<Mutex<SmoltcpBridge>>,

    /// Session tracker for port allocation and session management
    sessions: SessionTracker,

    /// WireGuard egress manager for sending packets
    wg_egress: Arc<WgEgressManager>,

    /// Local tunnel IP (assigned IP within the WG tunnel)
    local_ip: Ipv4Addr,

    /// Reply channels by reply key
    /// Each connection gets its own channel for reply packets
    reply_channels: DashMap<ReplyKey, mpsc::Sender<WgReplyPacket>>,

    /// Statistics
    stats: Arc<WgEgressBridgeStats>,

    /// Running flag (set to false to stop the bridge)
    running: AtomicBool,
}

impl WgEgressBridge {
    /// Create a new WG egress bridge
    ///
    /// # Arguments
    ///
    /// * `tunnel_tag` - Tag identifying the WG egress tunnel
    /// * `wg_egress` - WireGuard egress manager for sending packets
    /// * `local_ip` - Local IP assigned within the WG tunnel
    ///
    /// # Example
    ///
    /// ```ignore
    /// let bridge = WgEgressBridge::new(
    ///     "wg-pia-nyc".to_string(),
    ///     wg_egress_manager,
    ///     Ipv4Addr::new(10, 200, 200, 2),
    /// );
    /// ```
    #[must_use]
    pub fn new(
        tunnel_tag: String,
        wg_egress: Arc<WgEgressManager>,
        local_ip: Ipv4Addr,
    ) -> Self {
        let smoltcp = SmoltcpBridge::new(local_ip, WG_MTU);
        let port_allocator = PortAllocator::new();

        info!(
            "WgEgressBridge created: tunnel={}, local_ip={}",
            tunnel_tag, local_ip
        );

        Self {
            tunnel_tag,
            smoltcp: Arc::new(Mutex::new(smoltcp)),
            sessions: SessionTracker::with_port_allocator(port_allocator),
            wg_egress,
            local_ip,
            reply_channels: DashMap::new(),
            stats: Arc::new(WgEgressBridgeStats::new()),
            running: AtomicBool::new(true),
        }
    }

    /// Get the tunnel tag
    #[must_use]
    pub fn tunnel_tag(&self) -> &str {
        &self.tunnel_tag
    }

    /// Get the local IP address
    #[must_use]
    pub fn local_ip(&self) -> Ipv4Addr {
        self.local_ip
    }

    /// Get a clone of the smoltcp bridge Arc
    ///
    /// This is used internally to create socket guards that need
    /// shared ownership of the bridge.
    fn smoltcp_arc(&self) -> Arc<Mutex<SmoltcpBridge>> {
        Arc::clone(&self.smoltcp)
    }

    /// Check if the bridge is running
    #[must_use]
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Acquire)
    }

    /// Stop the bridge
    pub fn stop(&self) {
        self.running.store(false, Ordering::Release);
        info!("WgEgressBridge stopped for tunnel '{}'", self.tunnel_tag);
    }

    /// Get bridge statistics
    #[must_use]
    pub fn stats(&self) -> WgEgressBridgeStatsSnapshot {
        self.stats.snapshot()
    }

    /// Check WG tunnel health
    async fn check_tunnel_health(&self) -> bool {
        self.wg_egress
            .get_tunnel_status(&self.tunnel_tag)
            .map(|status| status.state == EgressState::Running && status.connected)
            .unwrap_or(false)
    }

    // =========================================================================
    // TCP Forwarding
    // =========================================================================

    /// Forward a TCP stream to the WG tunnel
    ///
    /// This method bridges a TCP stream from ipstack to the WireGuard tunnel
    /// using smoltcp for TCP/IP packet generation.
    ///
    /// # Arguments
    ///
    /// * `stream` - The TCP stream to forward
    /// * `dest_addr` - Destination address (IP:port)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The bridge is not running
    /// - The WG tunnel is not healthy
    /// - Port allocation fails
    /// - Socket creation fails
    /// - Connection fails or times out
    ///
    /// # Example
    ///
    /// ```ignore
    /// let dest = "1.1.1.1:443".parse().unwrap();
    /// bridge.forward_tcp(stream, dest).await?;
    /// ```
    pub async fn forward_tcp<S>(&self, stream: S, dest_addr: SocketAddr) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        if !self.is_running() {
            return Err(BridgeError::TunnelDown("bridge is not running".into()));
        }

        // Check tunnel health
        if !self.check_tunnel_health().await {
            return Err(BridgeError::TunnelDown(format!(
                "WG tunnel '{}' is not healthy",
                self.tunnel_tag
            )));
        }

        let dest_ip = dest_addr.ip();
        let dest_port = dest_addr.port();

        debug!(
            "Forwarding TCP to {}:{} via tunnel '{}'",
            dest_ip, dest_port, self.tunnel_tag
        );

        // Allocate local port (RAII)
        let port_guard = self
            .sessions
            .port_allocator()
            .allocate()
            .ok_or(BridgeError::PortExhausted)?;
        let local_port = port_guard.port();

        // Create smoltcp TCP socket with RAII guard
        let socket_handle = {
            let mut bridge = self.smoltcp.lock().await;
            bridge
                .create_tcp_socket(TCP_RX_BUFFER, TCP_TX_BUFFER)
                .ok_or(BridgeError::SocketLimitReached(MAX_SOCKETS))?
        };

        // Create socket guard for automatic cleanup
        let mut socket_guard = TcpSocketGuard::new(self.smoltcp_arc(), socket_handle);

        // Connect the socket (IPv4 only)
        let smoltcp_dest = match dest_ip {
            IpAddr::V4(v4) => IpAddress::Ipv4(smoltcp::wire::Ipv4Address::from_bytes(&v4.octets())),
            IpAddr::V6(_) => {
                return Err(BridgeError::SmoltcpTcp("IPv6 not supported".into()));
            }
        };

        {
            let mut bridge = self.smoltcp.lock().await;
            if let Err(e) = bridge.tcp_connect(socket_handle, smoltcp_dest, dest_port, local_port) {
                return Err(BridgeError::SmoltcpTcp(format!("connect failed: {e:?}")));
            }
        }

        // Create per-connection reply channel
        let (reply_tx, reply_rx) = mpsc::channel::<WgReplyPacket>(WG_REPLY_CHANNEL_SIZE);

        // Register reply channel
        let reply_key = ReplyKey::new(
            self.tunnel_tag.clone(),
            IpAddr::V4(self.local_ip),
            local_port,
            dest_ip,
            dest_port,
        );
        self.reply_channels.insert(reply_key.clone(), reply_tx);

        debug!(
            "Registered TCP session: {}:{} -> {}:{}",
            self.local_ip, local_port, dest_ip, dest_port
        );

        // Update stats
        self.stats.tcp_connections.fetch_add(1, Ordering::Relaxed);
        self.stats.active_tcp.fetch_add(1, Ordering::Relaxed);

        // Run the forwarding loop
        let result = self
            .tcp_forward_loop(stream, socket_handle, dest_ip, dest_port, reply_rx)
            .await;

        // Cleanup stats
        self.stats.active_tcp.fetch_sub(1, Ordering::Relaxed);

        // Handle result
        match &result {
            Ok(()) => {
                debug!("TCP connection completed gracefully");
                socket_guard.set_graceful_close();
            }
            Err(e) => {
                warn!("TCP connection error: {}", e);
                self.stats.errors.fetch_add(1, Ordering::Relaxed);
            }
        }

        // Send any pending packets
        self.drain_and_send_packets().await?;

        // Unregister reply channel
        self.reply_channels.remove(&reply_key);

        // Socket guard handles cleanup
        if result.is_ok() {
            socket_guard.close_gracefully().await;
        } else {
            socket_guard.abort().await;
        }

        // Port guard drops here, entering TIME_WAIT
        drop(port_guard);

        debug!(
            "TCP forward ended: {}:{} -> {}:{}, success={}",
            self.local_ip,
            local_port,
            dest_ip,
            dest_port,
            result.is_ok()
        );

        result
    }

    /// TCP forwarding loop
    ///
    /// Uses tokio::select! for event-driven bidirectional data transfer.
    /// Optimized to minimize lock contention by consolidating lock operations.
    async fn tcp_forward_loop<S>(
        &self,
        stream: S,
        socket_handle: SocketHandle,
        _dest_ip: IpAddr,
        _dest_port: u16,
        mut reply_rx: mpsc::Receiver<WgReplyPacket>,
    ) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let (mut reader, mut writer) = tokio::io::split(stream);

        // Larger buffers for better throughput
        let mut stream_buf = vec![0u8; 65536];
        let mut smoltcp_buf = vec![0u8; 65536];

        // Half-close tracking
        let mut stream_closed = false;
        let mut smoltcp_closed = false;

        // Wait for connection to establish
        let connected = self
            .wait_for_tcp_connect(socket_handle, &mut reply_rx)
            .await?;
        if !connected {
            return Err(BridgeError::ConnectionTimeout);
        }

        let timer_interval = Duration::from_millis(TCP_TIMER_INTERVAL_MS);

        loop {
            // Check if bridge is still running
            if !self.is_running() {
                return Err(BridgeError::TunnelDown("bridge stopped".into()));
            }

            tokio::select! {
                biased;

                // Stream -> smoltcp (forward direction)
                result = reader.read(&mut stream_buf), if !stream_closed => {
                    match result {
                        Ok(0) => {
                            debug!("Stream half-closed");
                            stream_closed = true;
                        }
                        Ok(n) => {
                            trace!("Read {} bytes from stream", n);
                            self.stats.bytes_to_wg.fetch_add(n as u64, Ordering::Relaxed);

                            // Write to smoltcp, poll, and send immediately
                            let tx_packets = {
                                let mut bridge = self.smoltcp.lock().await;
                                let socket = bridge.get_tcp_socket_mut(socket_handle);
                                if socket.can_send() {
                                    if let Err(e) = socket.send_slice(&stream_buf[..n]) {
                                        warn!("smoltcp send failed: {:?}", e);
                                        return Err(BridgeError::SmoltcpTcp(format!("send failed: {e:?}")));
                                    }
                                } else {
                                    warn!("smoltcp socket cannot send");
                                }
                                bridge.poll();
                                bridge.drain_tx_packets()
                            };

                            // Send generated packets to WG
                            if !tx_packets.is_empty() {
                                if let Err(e) = self.wg_egress.send_batch(&self.tunnel_tag, tx_packets).await {
                                    trace!("WG batch send error: {}", e);
                                }
                            }
                        }
                        Err(e) => {
                            warn!("Stream read error: {}", e);
                            return Err(e.into());
                        }
                    }
                }

                // WG reply -> smoltcp -> stream (reverse direction)
                Some(reply) = reply_rx.recv(), if !smoltcp_closed => {
                    // Batch process all available replies
                    let (total_read, tx_packets) = {
                        let mut bridge = self.smoltcp.lock().await;
                        bridge.feed_rx_packet(reply.packet);

                        // Drain any additional pending replies
                        while let Ok(additional) = reply_rx.try_recv() {
                            bridge.feed_rx_packet(additional.packet);
                        }

                        bridge.poll();

                        // Read all available data from socket
                        let socket = bridge.get_tcp_socket_mut(socket_handle);
                        let mut read_total = 0;
                        while socket.can_recv() {
                            match socket.recv_slice(&mut smoltcp_buf[read_total..]) {
                                Ok(n) if n > 0 => {
                                    read_total += n;
                                    if read_total >= smoltcp_buf.len() - 1500 {
                                        break;
                                    }
                                }
                                Ok(_) => break,
                                Err(_) => break,
                            }
                        }

                        let packets = bridge.drain_tx_packets();
                        (read_total, packets)
                    };

                    // Send ACK packets
                    if !tx_packets.is_empty() {
                        if let Err(e) = self.wg_egress.send_batch(&self.tunnel_tag, tx_packets).await {
                            trace!("WG batch send error: {}", e);
                        }
                    }

                    if total_read > 0 {
                        trace!("Read {} bytes from smoltcp", total_read);
                        self.stats.bytes_from_wg.fetch_add(total_read as u64, Ordering::Relaxed);

                        if let Err(e) = writer.write_all(&smoltcp_buf[..total_read]).await {
                            warn!("Stream write error: {}", e);
                            return Err(e.into());
                        }
                        if let Err(e) = writer.flush().await {
                            warn!("Stream flush error: {}", e);
                            return Err(e.into());
                        }
                    }
                }

                // Timer for TCP state machine - consolidated lock acquisition
                _ = tokio::time::sleep(timer_interval), if !stream_closed || !smoltcp_closed => {
                    // Single lock acquisition for all timer operations
                    let (socket_state, can_recv_data, _may_recv_data, bytes_read, tx_packets, should_close) = {
                        let mut bridge = self.smoltcp.lock().await;
                        bridge.poll();

                        let socket = bridge.get_tcp_socket_mut(socket_handle);
                        let state = socket.state();
                        let can_recv = socket.can_recv();
                        let may_recv = socket.may_recv();

                        let n = if can_recv {
                            match socket.recv_slice(&mut smoltcp_buf) {
                                Ok(n) if n > 0 => n,
                                _ => 0,
                            }
                        } else {
                            0
                        };

                        // Check if we should close (stream closed and no more data)
                        let should_close_now = stream_closed && !smoltcp_closed && !can_recv && !may_recv;
                        if should_close_now {
                            bridge.tcp_close(socket_handle);
                        }

                        let packets = bridge.drain_tx_packets();
                        (state, can_recv, may_recv, n, packets, should_close_now)
                    };

                    // Send retransmission/keepalive packets
                    if !tx_packets.is_empty() {
                        if let Err(e) = self.wg_egress.send_batch(&self.tunnel_tag, tx_packets).await {
                            trace!("WG batch send error: {}", e);
                        }
                    }

                    // Write any data we read
                    if bytes_read > 0 {
                        trace!("Read {} bytes from smoltcp on timer poll", bytes_read);
                        self.stats.bytes_from_wg.fetch_add(bytes_read as u64, Ordering::Relaxed);
                        if let Err(e) = writer.write_all(&smoltcp_buf[..bytes_read]).await {
                            warn!("Stream write error: {}", e);
                            return Err(e.into());
                        }
                        if let Err(e) = writer.flush().await {
                            warn!("Stream flush error: {}", e);
                            return Err(e.into());
                        }
                    }

                    // Handle proactive close
                    if should_close {
                        debug!("Stream closed and no more data from remote");
                        smoltcp_closed = true;
                    }

                    // Handle TCP states
                    match socket_state {
                        TcpState::Closed | TcpState::TimeWait => {
                            debug!("TCP socket closed/timewait");
                            smoltcp_closed = true;
                            if stream_closed {
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
                            if stream_closed {
                                break;
                            }
                        }
                        _ => {}
                    }
                }
            }

            // Exit if both sides closed - single lock acquisition
            if stream_closed && smoltcp_closed {
                debug!("Both sides closed, exiting loop");
                let mut bridge = self.smoltcp.lock().await;
                bridge.tcp_close(socket_handle);
                break;
            }
        }

        Ok(())
    }

    /// Wait for TCP connection to establish
    async fn wait_for_tcp_connect(
        &self,
        socket_handle: SocketHandle,
        reply_rx: &mut mpsc::Receiver<WgReplyPacket>,
    ) -> Result<bool> {
        let timeout = Duration::from_secs(CONNECT_TIMEOUT_SECS);
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
                    // Still connecting
                }
                _ => {
                    trace!("Unexpected state during connect: {:?}", state);
                }
            }

            if start.elapsed() > timeout {
                return Ok(false);
            }

            // Wait for WG reply or timeout
            tokio::select! {
                Some(reply) = reply_rx.recv() => {
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

    // =========================================================================
    // UDP Forwarding
    // =========================================================================

    /// Forward UDP datagrams to the WG tunnel
    ///
    /// This method bridges UDP datagrams from ipstack to the WireGuard tunnel.
    /// The stream is expected to carry length-prefixed UDP frames.
    ///
    /// # Arguments
    ///
    /// * `stream` - The stream carrying UDP frames
    /// * `dest_addr` - Default destination address (may be overridden per-packet)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The bridge is not running
    /// - The WG tunnel is not healthy
    /// - Port allocation fails
    /// - Socket creation fails
    pub async fn forward_udp<S>(&self, stream: S, dest_addr: SocketAddr) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        if !self.is_running() {
            return Err(BridgeError::TunnelDown("bridge is not running".into()));
        }

        if !self.check_tunnel_health().await {
            return Err(BridgeError::TunnelDown(format!(
                "WG tunnel '{}' is not healthy",
                self.tunnel_tag
            )));
        }

        let dest_ip = dest_addr.ip();
        let dest_port = dest_addr.port();

        debug!(
            "Forwarding UDP to {}:{} via tunnel '{}'",
            dest_ip, dest_port, self.tunnel_tag
        );

        // Allocate local port
        let port_guard = self
            .sessions
            .port_allocator()
            .allocate()
            .ok_or(BridgeError::PortExhausted)?;
        let local_port = port_guard.port();

        // Create UDP socket with guard
        let socket_handle = {
            let mut bridge = self.smoltcp.lock().await;
            let handle = bridge
                .create_udp_socket()
                .ok_or(BridgeError::SocketLimitReached(MAX_SOCKETS))?;

            if let Err(e) = bridge.udp_bind(handle, local_port) {
                bridge.remove_socket(handle);
                return Err(BridgeError::SmoltcpUdp(format!("bind failed: {e:?}")));
            }

            handle
        };

        let socket_guard = UdpSocketGuard::new(self.smoltcp_arc(), socket_handle);

        // Create reply channel
        let (reply_tx, reply_rx) = mpsc::channel::<WgReplyPacket>(WG_REPLY_CHANNEL_SIZE);

        // Register reply channel
        let reply_key = ReplyKey::new(
            self.tunnel_tag.clone(),
            IpAddr::V4(self.local_ip),
            local_port,
            dest_ip,
            dest_port,
        );
        self.reply_channels.insert(reply_key.clone(), reply_tx);

        // Update stats
        self.stats.udp_sessions.fetch_add(1, Ordering::Relaxed);
        self.stats.active_udp.fetch_add(1, Ordering::Relaxed);

        // Run the forwarding loop
        let result = self
            .udp_forward_loop(stream, socket_handle, dest_ip, dest_port, reply_rx)
            .await;

        // Cleanup
        self.stats.active_udp.fetch_sub(1, Ordering::Relaxed);
        self.reply_channels.remove(&reply_key);

        if result.is_err() {
            self.stats.errors.fetch_add(1, Ordering::Relaxed);
        }

        // Socket guard handles cleanup
        socket_guard.close().await;

        // Port guard drops here
        drop(port_guard);

        debug!(
            "UDP forward ended: {}:{} -> {}:{}, success={}",
            self.local_ip,
            local_port,
            dest_ip,
            dest_port,
            result.is_ok()
        );

        result
    }

    /// UDP forwarding loop
    async fn udp_forward_loop<S>(
        &self,
        stream: S,
        socket_handle: SocketHandle,
        dest_ip: IpAddr,
        dest_port: u16,
        mut reply_rx: mpsc::Receiver<WgReplyPacket>,
    ) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let (mut reader, mut writer) = tokio::io::split(stream);
        let mut frame_buf = vec![0u8; 65536];

        let timeout = if dest_port == 53 {
            Duration::from_secs(UDP_DNS_TIMEOUT_SECS)
        } else {
            Duration::from_secs(UDP_DEFAULT_TIMEOUT_SECS)
        };

        let smoltcp_dest = match dest_ip {
            IpAddr::V4(v4) => smoltcp::wire::IpEndpoint {
                addr: smoltcp::wire::IpAddress::Ipv4(
                    smoltcp::wire::Ipv4Address::from_bytes(&v4.octets()),
                ),
                port: dest_port,
            },
            IpAddr::V6(_) => {
                return Err(BridgeError::SmoltcpUdp("IPv6 not supported".into()));
            }
        };

        loop {
            if !self.is_running() {
                return Err(BridgeError::TunnelDown("bridge stopped".into()));
            }

            // Poll smoltcp
            self.poll_and_send().await?;

            tokio::select! {
                biased;

                // Read UDP frame (length-prefixed)
                length_result = reader.read_u16() => {
                    match length_result {
                        Ok(length) => {
                            let length = length as usize;
                            if length == 0 {
                                debug!("UDP stream closed (zero length)");
                                return Ok(());
                            }
                            if length > frame_buf.len() {
                                warn!("UDP frame too large: {} bytes", length);
                                return Err(BridgeError::SmoltcpUdp(format!(
                                    "UDP frame too large: {} bytes", length
                                )));
                            }

                            if let Err(e) = reader.read_exact(&mut frame_buf[..length]).await {
                                if e.kind() == std::io::ErrorKind::UnexpectedEof {
                                    debug!("UDP stream closed (EOF)");
                                    return Ok(());
                                }
                                return Err(e.into());
                            }

                            trace!("Received UDP frame: {} bytes", length);
                            self.stats.bytes_to_wg.fetch_add(length as u64, Ordering::Relaxed);

                            // Send through smoltcp
                            {
                                let mut bridge = self.smoltcp.lock().await;
                                if let Err(e) = bridge.udp_send(socket_handle, &frame_buf[..length], smoltcp_dest) {
                                    warn!("UDP send failed: {:?}", e);
                                }
                            }

                            // Poll and send immediately
                            self.poll_and_send().await?;
                        }
                        Err(e) => {
                            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                                debug!("UDP stream closed (EOF reading length)");
                                return Ok(());
                            }
                            return Err(e.into());
                        }
                    }
                }

                // WG reply
                Some(reply) = reply_rx.recv() => {
                    let mut bridge = self.smoltcp.lock().await;
                    bridge.feed_rx_packet(reply.packet);
                    bridge.poll();

                    // Check for UDP data
                    if bridge.udp_can_recv(socket_handle) {
                        match bridge.udp_recv(socket_handle) {
                            Ok((data, _endpoint)) => {
                                trace!("UDP reply: {} bytes", data.len());
                                self.stats.bytes_from_wg.fetch_add(data.len() as u64, Ordering::Relaxed);

                                // Write length-prefixed frame
                                let length = data.len() as u16;
                                drop(bridge);
                                writer.write_u16(length).await?;
                                writer.write_all(&data).await?;
                            }
                            Err(e) => {
                                trace!("UDP recv error: {:?}", e);
                            }
                        }
                    }
                }

                // Timeout
                _ = tokio::time::sleep(timeout) => {
                    debug!("UDP session timeout");
                    return Ok(());
                }
            }
        }
    }

    // =========================================================================
    // Reply Handling
    // =========================================================================

    /// Feed a reply packet from the WG tunnel
    ///
    /// This method should be called when a decrypted IP packet is received
    /// from the WireGuard tunnel. The packet will be routed to the appropriate
    /// session based on the IP headers.
    ///
    /// # Arguments
    ///
    /// * `packet` - The decrypted IP packet
    ///
    /// # Returns
    ///
    /// `true` if the packet was routed to a session, `false` otherwise
    pub fn feed_reply(&self, packet: &[u8]) -> bool {
        // Parse IP header to extract src/dst
        if packet.len() < 20 {
            return false;
        }

        let version = (packet[0] >> 4) & 0x0F;
        if version != 4 {
            // Only IPv4 supported
            return false;
        }

        let ihl = (packet[0] & 0x0F) as usize * 4;
        if packet.len() < ihl {
            return false;
        }

        let protocol = packet[9];
        let src_ip = IpAddr::V4(Ipv4Addr::new(
            packet[12], packet[13], packet[14], packet[15],
        ));
        let dst_ip = IpAddr::V4(Ipv4Addr::new(
            packet[16], packet[17], packet[18], packet[19],
        ));

        // Extract ports based on protocol
        let (src_port, dst_port) = if protocol == 6 || protocol == 17 {
            // TCP or UDP
            if packet.len() < ihl + 4 {
                return false;
            }
            let src_port = u16::from_be_bytes([packet[ihl], packet[ihl + 1]]);
            let dst_port = u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]]);
            (src_port, dst_port)
        } else {
            return false;
        };

        // Look for matching reply channel
        // Reply packets have src=remote, dst=local, so we reverse for lookup
        let reply_key = ReplyKey::new(
            self.tunnel_tag.clone(),
            dst_ip,      // local (destination of reply)
            dst_port,    // local port
            src_ip,      // remote (source of reply)
            src_port,    // remote port
        );

        if let Some(sender) = self.reply_channels.get(&reply_key) {
            let reply = WgReplyPacket {
                tag: self.tunnel_tag.clone(),
                packet: packet.to_vec(),
            };
            if let Err(e) = sender.try_send(reply) {
                trace!("Reply channel send failed: {:?}", e);
                return false;
            }
            return true;
        }

        false
    }

    // =========================================================================
    // Internal Methods
    // =========================================================================

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
                self.tunnel_tag
            );
            if let Err(e) = self.wg_egress.send(&self.tunnel_tag, packet).await {
                warn!("Failed to send packet to WG: {}", e);
            }
        }

        Ok(())
    }

    /// Drain TX packets and send to WG
    async fn drain_and_send_packets(&self) -> Result<()> {
        self.poll_and_send().await
    }

    /// Run the smoltcp poll loop
    ///
    /// This method should be called periodically to process TCP timers
    /// and handle retransmissions. It's typically not needed when using
    /// `forward_tcp` or `forward_udp` as they handle polling internally.
    pub async fn run_poll_loop(&self) {
        let poll_interval = Duration::from_millis(50);

        while self.is_running() {
            if let Err(e) = self.poll_and_send().await {
                warn!("Poll loop error: {}", e);
            }
            tokio::time::sleep(poll_interval).await;
        }

        debug!(
            "Poll loop stopped for WgEgressBridge '{}'",
            self.tunnel_tag
        );
    }
}

impl Drop for WgEgressBridge {
    fn drop(&mut self) {
        info!(
            "WgEgressBridge dropped for tunnel '{}', stats: {:?}",
            self.tunnel_tag,
            self.stats.snapshot()
        );
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stats_default() {
        let stats = WgEgressBridgeStats::new();
        let snapshot = stats.snapshot();

        assert_eq!(snapshot.tcp_connections, 0);
        assert_eq!(snapshot.udp_sessions, 0);
        assert_eq!(snapshot.bytes_to_wg, 0);
        assert_eq!(snapshot.bytes_from_wg, 0);
        assert_eq!(snapshot.active_tcp, 0);
        assert_eq!(snapshot.active_udp, 0);
        assert_eq!(snapshot.errors, 0);
    }

    #[test]
    fn test_stats_increment() {
        let stats = WgEgressBridgeStats::new();

        stats.tcp_connections.fetch_add(5, Ordering::Relaxed);
        stats.bytes_to_wg.fetch_add(1000, Ordering::Relaxed);
        stats.bytes_from_wg.fetch_add(2000, Ordering::Relaxed);

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.tcp_connections, 5);
        assert_eq!(snapshot.bytes_to_wg, 1000);
        assert_eq!(snapshot.bytes_from_wg, 2000);
    }

    #[test]
    fn test_stats_snapshot_serialization() {
        let snapshot = WgEgressBridgeStatsSnapshot {
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

    #[test]
    fn test_reply_key() {
        let key = ReplyKey::new(
            "wg-pia-nyc".to_string(),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            50000,
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            443,
        );

        assert_eq!(key.tunnel_tag, "wg-pia-nyc");
        assert_eq!(key.local_port, 50000);
        assert_eq!(key.remote_port, 443);
    }

    #[test]
    fn test_reply_key_equality() {
        let key1 = ReplyKey::new(
            "tunnel1".to_string(),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            50000,
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            443,
        );

        let key2 = ReplyKey::new(
            "tunnel1".to_string(),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            50000,
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            443,
        );

        let key3 = ReplyKey::new(
            "tunnel2".to_string(),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            50000,
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            443,
        );

        assert_eq!(key1, key2);
        assert_ne!(key1, key3);
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

    // Integration tests would require mocking WgEgressManager
    // which would be done in a separate integration test file
}
