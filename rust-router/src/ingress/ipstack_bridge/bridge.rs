//! IpStack Bridge - Main bridge implementation
//!
//! This module provides the core bridge that connects WireGuard ingress
//! packets to TCP outbound connections using ipstack.
//!
//! # Architecture
//!
//! ```text
//! WireGuard Ingress (IP packets)
//!         |
//!         v
//! +---------------------+
//! |   IpStackBridge     |
//! |  - PacketChannel    | <-- IP packets in/out via async channels
//! |  - ipstack::IpStack |
//! |  - SessionTracker   | <-- 5-tuple -> peer mapping
//! +---------------------+
//!         |
//!         v
//!   IpStackTcpStream <-> OutboundStream (copy_bidirectional)
//! ```
//!
//! # Usage
//!
//! ```ignore
//! use rust_router::ingress::ipstack_bridge::IpStackBridge;
//!
//! // Create the bridge
//! let mut bridge = IpStackBridge::new();
//!
//! // Take the reply receiver for routing packets back to WireGuard
//! let reply_rx = bridge.take_reply_rx().unwrap();
//!
//! // Start the bridge
//! bridge.start().await?;
//!
//! // Inject IP packets from WireGuard
//! bridge.inject_packet(packet, peer_key).await?;
//! ```

use super::config::*;
use super::packet_channel::PacketChannel;
use super::session_tracker::{FiveTuple, SessionTracker};
use bytes::BytesMut;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::{debug, info, trace, warn};

/// Statistics for the IpStack bridge
///
/// All counters use relaxed atomic ordering for performance,
/// as exact accuracy is not required for statistics.
#[derive(Debug, Default)]
pub struct IpStackBridgeStats {
    /// Total IP packets received from WireGuard
    pub packets_received: AtomicU64,
    /// Total IP packets sent to WireGuard
    pub packets_sent: AtomicU64,
    /// TCP connections successfully accepted by ipstack
    pub tcp_connections_accepted: AtomicU64,
    /// TCP connections that failed to establish
    pub tcp_connections_failed: AtomicU64,
    /// UDP packets forwarded
    pub udp_packets_forwarded: AtomicU64,
    /// Total bytes sent to outbound connections
    pub bytes_to_outbound: AtomicU64,
    /// Total bytes received from outbound connections
    pub bytes_from_outbound: AtomicU64,
}

impl IpStackBridgeStats {
    /// Create a snapshot of the current statistics
    pub fn snapshot(&self) -> IpStackBridgeStatsSnapshot {
        IpStackBridgeStatsSnapshot {
            packets_received: self.packets_received.load(Ordering::Relaxed),
            packets_sent: self.packets_sent.load(Ordering::Relaxed),
            tcp_connections_accepted: self.tcp_connections_accepted.load(Ordering::Relaxed),
            tcp_connections_failed: self.tcp_connections_failed.load(Ordering::Relaxed),
            udp_packets_forwarded: self.udp_packets_forwarded.load(Ordering::Relaxed),
            bytes_to_outbound: self.bytes_to_outbound.load(Ordering::Relaxed),
            bytes_from_outbound: self.bytes_from_outbound.load(Ordering::Relaxed),
        }
    }

    /// Reset all statistics to zero
    pub fn reset(&self) {
        self.packets_received.store(0, Ordering::Relaxed);
        self.packets_sent.store(0, Ordering::Relaxed);
        self.tcp_connections_accepted.store(0, Ordering::Relaxed);
        self.tcp_connections_failed.store(0, Ordering::Relaxed);
        self.udp_packets_forwarded.store(0, Ordering::Relaxed);
        self.bytes_to_outbound.store(0, Ordering::Relaxed);
        self.bytes_from_outbound.store(0, Ordering::Relaxed);
    }
}

/// Snapshot of IpStack bridge statistics
///
/// This is a serializable copy of the statistics at a point in time.
#[derive(Debug, Clone, serde::Serialize)]
pub struct IpStackBridgeStatsSnapshot {
    /// Total IP packets received from WireGuard
    pub packets_received: u64,
    /// Total IP packets sent to WireGuard
    pub packets_sent: u64,
    /// TCP connections successfully accepted
    pub tcp_connections_accepted: u64,
    /// TCP connections that failed
    pub tcp_connections_failed: u64,
    /// UDP packets forwarded
    pub udp_packets_forwarded: u64,
    /// Total bytes sent to outbound
    pub bytes_to_outbound: u64,
    /// Total bytes received from outbound
    pub bytes_from_outbound: u64,
}

/// IpStack Bridge for handling TCP/UDP over WireGuard
///
/// This bridge:
/// 1. Receives IP packets from WireGuard ingress
/// 2. Feeds them to ipstack's TCP/IP stack
/// 3. Accepts TCP connections from ipstack
/// 4. Bridges them to outbound connections
/// 5. Routes reply packets back to the correct WireGuard peer
///
/// # Thread Safety
///
/// The bridge is designed for concurrent access:
/// - Statistics use atomic counters
/// - Session tracker uses DashMap for lock-free access
/// - Packet channels use tokio::mpsc for async communication
pub struct IpStackBridge {
    /// Channel to inject IP packets into the bridge
    packet_tx: mpsc::Sender<BytesMut>,
    /// Internal packet receiver (used by the bridge loop)
    packet_rx: Option<mpsc::Receiver<BytesMut>>,
    /// Channel to receive reply packets for WireGuard
    /// The tuple contains (packet, peer_key)
    reply_rx: Option<mpsc::Receiver<(BytesMut, [u8; 32])>>,
    /// Sender for reply packets (used internally)
    reply_tx: mpsc::Sender<(BytesMut, [u8; 32])>,
    /// Session tracker
    session_tracker: Arc<SessionTracker>,
    /// Statistics
    stats: Arc<IpStackBridgeStats>,
    /// Running flag
    running: Arc<AtomicBool>,
    /// Accept loop task handle
    accept_task: Option<JoinHandle<()>>,
    /// Reply routing task handle
    reply_task: Option<JoinHandle<()>>,
    /// Periodic cleanup task handle
    cleanup_task: Option<JoinHandle<()>>,
}

impl IpStackBridge {
    /// Create a new IpStack bridge
    ///
    /// Returns the bridge with all channels initialized. Call `take_reply_rx()`
    /// to get the receiver for reply packets that should be sent back through
    /// WireGuard to the client.
    pub fn new() -> Self {
        let (packet_tx, packet_rx) = mpsc::channel(PACKET_CHANNEL_SIZE);
        let (reply_tx, reply_rx) = mpsc::channel::<(BytesMut, [u8; 32])>(REPLY_CHANNEL_SIZE);

        Self {
            packet_tx,
            packet_rx: Some(packet_rx),
            reply_rx: Some(reply_rx),
            reply_tx,
            session_tracker: Arc::new(SessionTracker::new()),
            stats: Arc::new(IpStackBridgeStats::default()),
            running: Arc::new(AtomicBool::new(false)),
            accept_task: None,
            reply_task: None,
            cleanup_task: None,
        }
    }

    /// Take the reply receiver (can only be called once)
    ///
    /// The reply receiver yields `(packet, peer_key)` tuples where:
    /// - `packet` is the IP packet to send
    /// - `peer_key` is the WireGuard peer public key to send it to
    ///
    /// # Returns
    ///
    /// `Some(receiver)` on first call, `None` on subsequent calls.
    pub fn take_reply_rx(&mut self) -> Option<mpsc::Receiver<(BytesMut, [u8; 32])>> {
        self.reply_rx.take()
    }

    /// Inject an IP packet into the bridge
    ///
    /// This is called from the forwarder when a packet should be handled
    /// by ipstack instead of the manual TCP state machine.
    ///
    /// # Arguments
    ///
    /// * `packet` - The IP packet (IPv4 or IPv6)
    /// * `peer_key` - The WireGuard peer's public key (for routing replies)
    ///
    /// # Errors
    ///
    /// Returns an error if the packet channel is closed.
    pub async fn inject_packet(&self, packet: BytesMut, peer_key: [u8; 32]) -> anyhow::Result<()> {
        self.stats.packets_received.fetch_add(1, Ordering::Relaxed);

        // Parse the packet to extract 5-tuple for session tracking
        let five_tuple = Self::parse_packet_five_tuple(&packet);

        // Register with session tracker for reply routing (forward-only, no reverse index)
        // Session is registered BEFORE send to ensure reply routing works immediately
        if let Some(ref ft) = five_tuple {
            self.session_tracker.register_forward_only(peer_key, ft.clone());
        }

        // Try to send the packet
        match self.packet_tx.send(packet).await {
            Ok(()) => Ok(()),
            Err(_) => {
                // Clean up session on send failure to prevent leak
                if let Some(ref ft) = five_tuple {
                    self.session_tracker.remove(ft);
                }
                Err(anyhow::anyhow!("packet channel closed"))
            }
        }
    }

    /// Try to inject an IP packet without blocking
    ///
    /// This is useful when called from synchronous code.
    ///
    /// # Arguments
    ///
    /// * `packet` - The IP packet (IPv4 or IPv6)
    /// * `peer_key` - The WireGuard peer's public key
    ///
    /// # Returns
    ///
    /// `true` if the packet was successfully queued, `false` if the channel is full or closed.
    pub fn try_inject_packet(&self, packet: BytesMut, peer_key: [u8; 32]) -> bool {
        self.stats.packets_received.fetch_add(1, Ordering::Relaxed);

        // Parse the packet to extract 5-tuple for session tracking
        let five_tuple = Self::parse_packet_five_tuple(&packet);

        // Register with session tracker for reply routing (forward-only, no reverse index)
        if let Some(ref ft) = five_tuple {
            self.session_tracker.register_forward_only(peer_key, ft.clone());
        }

        // Try to send the packet
        if self.packet_tx.try_send(packet).is_ok() {
            true
        } else {
            // Clean up session on send failure to prevent leak
            if let Some(ref ft) = five_tuple {
                self.session_tracker.remove(ft);
            }
            false
        }
    }

    /// Parse an IP packet to extract the 5-tuple
    ///
    /// Returns None if the packet is malformed or not TCP/UDP.
    fn parse_packet_five_tuple(packet: &[u8]) -> Option<FiveTuple> {
        if packet.is_empty() {
            return None;
        }

        let version = packet[0] >> 4;

        match version {
            4 => Self::parse_ipv4_five_tuple(packet),
            6 => Self::parse_ipv6_five_tuple(packet),
            _ => None,
        }
    }

    /// Parse an IPv4 packet to extract the 5-tuple
    fn parse_ipv4_five_tuple(packet: &[u8]) -> Option<FiveTuple> {
        // Minimum IPv4 header is 20 bytes
        if packet.len() < 20 {
            return None;
        }

        let ihl = (packet[0] & 0x0f) as usize * 4;
        if packet.len() < ihl {
            return None;
        }

        let protocol = packet[9];
        let src_ip = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
        let dst_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);

        // Need at least 4 more bytes for ports (TCP/UDP)
        if packet.len() < ihl + 4 {
            return None;
        }

        let src_port = u16::from_be_bytes([packet[ihl], packet[ihl + 1]]);
        let dst_port = u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]]);

        let src_addr = SocketAddr::new(IpAddr::V4(src_ip), src_port);
        let dst_addr = SocketAddr::new(IpAddr::V4(dst_ip), dst_port);

        match protocol {
            6 => Some(FiveTuple::tcp(src_addr, dst_addr)),
            17 => Some(FiveTuple::udp(src_addr, dst_addr)),
            _ => None,
        }
    }

    /// Parse an IPv6 packet to extract the 5-tuple
    fn parse_ipv6_five_tuple(packet: &[u8]) -> Option<FiveTuple> {
        // Minimum IPv6 header is 40 bytes
        if packet.len() < 40 {
            return None;
        }

        let protocol = packet[6]; // Next Header field

        let mut src_octets = [0u8; 16];
        let mut dst_octets = [0u8; 16];
        src_octets.copy_from_slice(&packet[8..24]);
        dst_octets.copy_from_slice(&packet[24..40]);

        let src_ip = Ipv6Addr::from(src_octets);
        let dst_ip = Ipv6Addr::from(dst_octets);

        // Need at least 4 more bytes for ports
        if packet.len() < 44 {
            return None;
        }

        let src_port = u16::from_be_bytes([packet[40], packet[41]]);
        let dst_port = u16::from_be_bytes([packet[42], packet[43]]);

        let src_addr = SocketAddr::new(IpAddr::V6(src_ip), src_port);
        let dst_addr = SocketAddr::new(IpAddr::V6(dst_ip), dst_port);

        match protocol {
            6 => Some(FiveTuple::tcp(src_addr, dst_addr)),
            17 => Some(FiveTuple::udp(src_addr, dst_addr)),
            _ => None,
        }
    }

    /// Start the bridge
    ///
    /// This spawns the ipstack accept loop and packet processing tasks.
    ///
    /// # Errors
    ///
    /// Returns an error if the bridge is already running or if packet_rx was already taken.
    pub async fn start(&mut self) -> anyhow::Result<()> {
        if self.running.swap(true, Ordering::SeqCst) {
            return Err(anyhow::anyhow!("bridge already running"));
        }

        let packet_rx = self
            .packet_rx
            .take()
            .ok_or_else(|| anyhow::anyhow!("packet_rx already taken"))?;

        info!("IpStack bridge starting...");

        // Create the PacketChannel pair for ipstack
        // - ipstack_packet_tx: used to send packets TO ipstack (from WireGuard)
        // - ipstack_packet_rx: used to receive packets FROM ipstack (to WireGuard)
        let (packet_channel, ipstack_packet_tx, ipstack_packet_rx) =
            PacketChannel::create_pair(PACKET_CHANNEL_SIZE);

        // Create ipstack configuration
        let mut ipstack_config = ipstack::IpStackConfig::default();
        ipstack_config.mtu(WG_MTU as u16);

        // Create the ipstack instance
        let ip_stack = ipstack::IpStack::new(ipstack_config, packet_channel);

        // Spawn task to forward packets from WireGuard to ipstack
        let running = Arc::clone(&self.running);
        let stats = Arc::clone(&self.stats);
        tokio::spawn(Self::packet_forwarder_task(
            packet_rx,
            ipstack_packet_tx,
            running,
            stats,
        ));

        // Spawn task to route reply packets from ipstack back to WireGuard
        let reply_tx = self.reply_tx.clone();
        let session_tracker = Arc::clone(&self.session_tracker);
        let running = Arc::clone(&self.running);
        let stats = Arc::clone(&self.stats);
        let reply_task = tokio::spawn(Self::reply_router_task(
            ipstack_packet_rx,
            reply_tx,
            session_tracker,
            running,
            stats,
        ));
        self.reply_task = Some(reply_task);

        // Spawn the accept loop task
        let running = Arc::clone(&self.running);
        let stats = Arc::clone(&self.stats);
        let session_tracker = Arc::clone(&self.session_tracker);
        let accept_task = tokio::spawn(Self::accept_loop_task(
            ip_stack,
            running,
            stats,
            session_tracker,
        ));
        self.accept_task = Some(accept_task);

        // Spawn the periodic cleanup task
        let running = Arc::clone(&self.running);
        let session_tracker = Arc::clone(&self.session_tracker);
        let cleanup_task = tokio::spawn(Self::session_cleanup_task(running, session_tracker));
        self.cleanup_task = Some(cleanup_task);

        info!("IpStack bridge started successfully");
        Ok(())
    }

    /// Periodic task to clean up idle sessions
    ///
    /// Runs at the configured interval to remove sessions that have been idle
    /// for longer than the timeout. This prevents resource leaks from sessions
    /// that were not properly cleaned up (e.g., due to packet loss or crashes).
    async fn session_cleanup_task(running: Arc<AtomicBool>, session_tracker: Arc<SessionTracker>) {
        debug!("Session cleanup task started");

        let cleanup_interval = session_cleanup_interval();
        let tcp_timeout = tcp_idle_timeout();
        let udp_timeout = udp_session_timeout();

        while running.load(Ordering::SeqCst) {
            tokio::time::sleep(cleanup_interval).await;

            if !running.load(Ordering::SeqCst) {
                break;
            }

            let removed = session_tracker.remove_if(|session| {
                let timeout = if session.five_tuple.is_tcp() {
                    tcp_timeout
                } else {
                    udp_timeout
                };
                session.idle_time() > timeout
            });

            if removed > 0 {
                info!(
                    removed,
                    active = session_tracker.total_sessions(),
                    "Cleaned up idle sessions"
                );
            } else {
                trace!(active = session_tracker.total_sessions(), "Cleanup cycle completed");
            }
        }

        debug!("Session cleanup task stopped");
    }

    /// Task that forwards packets from WireGuard to ipstack
    async fn packet_forwarder_task(
        mut packet_rx: mpsc::Receiver<BytesMut>,
        ipstack_tx: mpsc::Sender<BytesMut>,
        running: Arc<AtomicBool>,
        _stats: Arc<IpStackBridgeStats>,
    ) {
        debug!("Packet forwarder task started");

        while running.load(Ordering::SeqCst) {
            match packet_rx.recv().await {
                Some(packet) => {
                    trace!("Forwarding {} byte packet to ipstack", packet.len());
                    if let Err(e) = ipstack_tx.send(packet).await {
                        warn!("Failed to send packet to ipstack: {}", e);
                        break;
                    }
                }
                None => {
                    debug!("Packet channel closed, stopping forwarder");
                    break;
                }
            }
        }

        debug!("Packet forwarder task stopped");
    }

    /// Task that routes reply packets from ipstack back to WireGuard peers
    async fn reply_router_task(
        mut ipstack_rx: mpsc::Receiver<BytesMut>,
        reply_tx: mpsc::Sender<(BytesMut, [u8; 32])>,
        session_tracker: Arc<SessionTracker>,
        running: Arc<AtomicBool>,
        stats: Arc<IpStackBridgeStats>,
    ) {
        debug!("Reply router task started");

        while running.load(Ordering::SeqCst) {
            match ipstack_rx.recv().await {
                Some(packet) => {
                    stats.packets_sent.fetch_add(1, Ordering::Relaxed);

                    // Parse the reply packet to find the reverse 5-tuple
                    if let Some(five_tuple) = Self::parse_packet_five_tuple(&packet) {
                        // For reply packets, we need to look up the reverse tuple
                        // (dst becomes src, src becomes dst)
                        let reverse_tuple = five_tuple.reverse();

                        if let Some(session) = session_tracker.lookup(&reverse_tuple) {
                            trace!(
                                "Routing {} byte reply to peer {}",
                                packet.len(),
                                hex::encode(&session.peer_key[..8])
                            );

                            if let Err(e) = reply_tx.send((packet, session.peer_key)).await {
                                warn!("Failed to send reply to WireGuard: {}", e);
                                break;
                            }
                        } else {
                            trace!(
                                "No session found for reply packet: {} -> {}",
                                five_tuple.src_addr,
                                five_tuple.dst_addr
                            );
                        }
                    } else {
                        trace!("Could not parse reply packet 5-tuple");
                    }
                }
                None => {
                    debug!("ipstack output channel closed, stopping reply router");
                    break;
                }
            }
        }

        debug!("Reply router task stopped");
    }

    /// Accept loop task that handles incoming connections from ipstack
    async fn accept_loop_task(
        mut ip_stack: ipstack::IpStack,
        running: Arc<AtomicBool>,
        stats: Arc<IpStackBridgeStats>,
        session_tracker: Arc<SessionTracker>,
    ) {
        debug!("Accept loop task started");

        while running.load(Ordering::SeqCst) {
            match ip_stack.accept().await {
                Ok(stream) => {
                    Self::handle_stream(
                        stream,
                        Arc::clone(&stats),
                        Arc::clone(&session_tracker),
                    );
                }
                Err(e) => {
                    // Check if we should continue
                    if !running.load(Ordering::SeqCst) {
                        break;
                    }
                    warn!("ipstack accept error: {:?}", e);
                    // Brief pause to prevent busy loop on persistent errors
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            }
        }

        debug!("Accept loop task stopped");
    }

    /// Handle a stream from ipstack
    fn handle_stream(
        stream: ipstack::stream::IpStackStream,
        stats: Arc<IpStackBridgeStats>,
        session_tracker: Arc<SessionTracker>,
    ) {
        match stream {
            ipstack::stream::IpStackStream::Tcp(tcp_stream) => {
                let local_addr = tcp_stream.local_addr();
                let peer_addr = tcp_stream.peer_addr();

                debug!(
                    "TCP connection accepted: {} -> {}",
                    local_addr, peer_addr
                );
                stats.tcp_connections_accepted.fetch_add(1, Ordering::Relaxed);

                // Spawn a task to handle the TCP connection
                tokio::spawn(Self::handle_tcp_connection(
                    tcp_stream,
                    local_addr,
                    peer_addr,
                    stats,
                    session_tracker,
                ));
            }
            ipstack::stream::IpStackStream::Udp(udp_stream) => {
                let local_addr = udp_stream.local_addr();
                let peer_addr = udp_stream.peer_addr();

                debug!(
                    "UDP stream accepted: {} -> {}",
                    local_addr, peer_addr
                );
                stats.udp_packets_forwarded.fetch_add(1, Ordering::Relaxed);

                // Spawn a task to handle the UDP stream
                tokio::spawn(Self::handle_udp_stream(
                    udp_stream,
                    local_addr,
                    peer_addr,
                    stats,
                    session_tracker,
                ));
            }
            ipstack::stream::IpStackStream::UnknownTransport(unknown) => {
                trace!(
                    "Unknown transport packet: {} -> {}",
                    unknown.src_addr(),
                    unknown.dst_addr()
                );
            }
            ipstack::stream::IpStackStream::UnknownNetwork(packet) => {
                trace!("Unknown network packet: {} bytes", packet.len());
            }
        }
    }

    /// Handle a TCP connection from ipstack
    async fn handle_tcp_connection(
        mut tcp_stream: ipstack::stream::IpStackTcpStream,
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
        stats: Arc<IpStackBridgeStats>,
        session_tracker: Arc<SessionTracker>,
    ) {
        debug!(
            "Handling TCP connection: local={}, peer={}",
            local_addr, peer_addr
        );

        // Connect to the destination
        // For now, we connect directly. Later this will be integrated with OutboundManager.
        let outbound = match TcpStream::connect(peer_addr).await {
            Ok(stream) => stream,
            Err(e) => {
                warn!("Failed to connect to {}: {}", peer_addr, e);
                stats.tcp_connections_failed.fetch_add(1, Ordering::Relaxed);
                return;
            }
        };

        // Set TCP_NODELAY to reduce latency (disable Nagle's algorithm)
        // This helps avoid the "speed up -> slow down -> speed up" pattern
        // caused by delayed ACKs interacting with Nagle's algorithm
        if let Err(e) = outbound.set_nodelay(true) {
            debug!("Failed to set TCP_NODELAY: {}", e);
        }

        debug!("Connected to outbound: {}", peer_addr);

        // Bridge the streams using copy_bidirectional with larger buffers
        // Default is 8KB which can cause performance issues with high-throughput
        let mut outbound = outbound;
        match copy_bidirectional_with_sizes(
            &mut tcp_stream,
            &mut outbound,
            TCP_COPY_BUFFER_SIZE,
            TCP_COPY_BUFFER_SIZE,
        ).await {
            Ok((to_outbound, from_outbound)) => {
                stats
                    .bytes_to_outbound
                    .fetch_add(to_outbound, Ordering::Relaxed);
                stats
                    .bytes_from_outbound
                    .fetch_add(from_outbound, Ordering::Relaxed);
                debug!(
                    "TCP connection completed: {} -> {}, sent={}, recv={}",
                    local_addr, peer_addr, to_outbound, from_outbound
                );
            }
            Err(e) => {
                // Connection errors are common (RST, etc.), only log at debug level
                debug!(
                    "TCP connection error: {} -> {}: {}",
                    local_addr, peer_addr, e
                );
            }
        }

        // Clean up session from tracker
        let five_tuple = FiveTuple::tcp(local_addr, peer_addr);
        session_tracker.remove(&five_tuple);

        debug!("TCP connection closed: {} -> {}", local_addr, peer_addr);
    }

    /// Handle a UDP stream from ipstack
    async fn handle_udp_stream(
        mut udp_stream: ipstack::stream::IpStackUdpStream,
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
        stats: Arc<IpStackBridgeStats>,
        session_tracker: Arc<SessionTracker>,
    ) {
        debug!(
            "Handling UDP stream: local={}, peer={}",
            local_addr, peer_addr
        );

        // Create a UDP socket to the destination
        let outbound = match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
            Ok(socket) => socket,
            Err(e) => {
                warn!("Failed to bind UDP socket: {}", e);
                return;
            }
        };

        if let Err(e) = outbound.connect(peer_addr).await {
            warn!("Failed to connect UDP socket to {}: {}", peer_addr, e);
            return;
        }

        debug!("UDP socket connected to: {}", peer_addr);

        // Bridge UDP traffic
        // For UDP, we read from ipstack stream and send to outbound, and vice versa
        let timeout = if peer_addr.port() == 53 {
            udp_dns_timeout()
        } else {
            udp_session_timeout()
        };

        let mut buf = vec![0u8; 65535];
        let mut recv_buf = vec![0u8; 65535];

        loop {
            tokio::select! {
                // Read from ipstack UDP stream
                result = tokio::io::AsyncReadExt::read(&mut udp_stream, &mut buf) => {
                    match result {
                        Ok(0) => {
                            debug!("UDP stream closed by client");
                            break;
                        }
                        Ok(n) => {
                            trace!("UDP: {} bytes from client to {}", n, peer_addr);
                            stats.bytes_to_outbound.fetch_add(n as u64, Ordering::Relaxed);
                            stats.udp_packets_forwarded.fetch_add(1, Ordering::Relaxed);

                            if let Err(e) = outbound.send(&buf[..n]).await {
                                warn!("UDP send error: {}", e);
                                break;
                            }
                        }
                        Err(e) => {
                            debug!("UDP read error: {}", e);
                            break;
                        }
                    }
                }

                // Read from outbound UDP socket
                result = outbound.recv(&mut recv_buf) => {
                    match result {
                        Ok(n) => {
                            trace!("UDP: {} bytes from {} to client", n, peer_addr);
                            stats.bytes_from_outbound.fetch_add(n as u64, Ordering::Relaxed);

                            if let Err(e) = tokio::io::AsyncWriteExt::write_all(&mut udp_stream, &recv_buf[..n]).await {
                                warn!("UDP write error: {}", e);
                                break;
                            }
                        }
                        Err(e) => {
                            debug!("UDP recv error: {}", e);
                            break;
                        }
                    }
                }

                // Timeout for UDP session
                _ = tokio::time::sleep(timeout) => {
                    debug!("UDP session timeout: {} -> {}", local_addr, peer_addr);
                    break;
                }
            }
        }

        // Clean up session from tracker
        let five_tuple = FiveTuple::udp(local_addr, peer_addr);
        session_tracker.remove(&five_tuple);

        debug!("UDP stream closed: {} -> {}", local_addr, peer_addr);
    }

    /// Stop the bridge
    ///
    /// This signals all tasks to stop and waits for them to complete.
    pub async fn stop(&mut self) {
        if !self.running.swap(false, Ordering::SeqCst) {
            debug!("IpStack bridge already stopped");
            return;
        }

        info!(
            sessions = self.session_tracker.total_sessions(),
            stats = ?self.stats.snapshot(),
            "IpStack bridge stopping..."
        );

        // Wait for tasks to complete
        if let Some(task) = self.accept_task.take() {
            task.abort();
            let _ = task.await;
        }
        if let Some(task) = self.reply_task.take() {
            task.abort();
            let _ = task.await;
        }
        if let Some(task) = self.cleanup_task.take() {
            task.abort();
            let _ = task.await;
        }

        info!("IpStack bridge stopped");
    }

    /// Check if bridge is running
    #[inline]
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Get statistics reference
    #[inline]
    pub fn stats(&self) -> &Arc<IpStackBridgeStats> {
        &self.stats
    }

    /// Get session tracker reference
    #[inline]
    pub fn session_tracker(&self) -> &Arc<SessionTracker> {
        &self.session_tracker
    }

    /// Get total active sessions
    #[inline]
    pub fn active_sessions(&self) -> usize {
        self.session_tracker.total_sessions()
    }

    /// Get TCP session count
    #[inline]
    pub fn tcp_sessions(&self) -> usize {
        self.session_tracker.tcp_session_count()
    }

    /// Get UDP session count
    #[inline]
    pub fn udp_sessions(&self) -> usize {
        self.session_tracker.udp_session_count()
    }

    /// Clean up idle sessions
    ///
    /// Removes sessions that have been idle for longer than the configured timeout.
    ///
    /// # Returns
    ///
    /// The number of sessions removed.
    pub fn cleanup_idle_sessions(&self) -> usize {
        let tcp_timeout = tcp_idle_timeout();
        let udp_timeout = udp_session_timeout();

        let removed = self.session_tracker.remove_if(|session| {
            let timeout = if session.five_tuple.is_tcp() {
                tcp_timeout
            } else {
                udp_timeout
            };
            session.idle_time() > timeout
        });

        if removed > 0 {
            debug!(removed, "Cleaned up idle sessions");
        }

        removed
    }

    /// Get a snapshot of the current state for diagnostics
    pub fn diagnostic_snapshot(&self) -> DiagnosticSnapshot {
        DiagnosticSnapshot {
            running: self.is_running(),
            active_sessions: self.active_sessions(),
            tcp_sessions: self.tcp_sessions(),
            udp_sessions: self.udp_sessions(),
            stats: self.stats.snapshot(),
        }
    }
}

impl Default for IpStackBridge {
    fn default() -> Self {
        Self::new()
    }
}

/// Diagnostic snapshot of the bridge state
#[derive(Debug, Clone, serde::Serialize)]
pub struct DiagnosticSnapshot {
    /// Whether the bridge is running
    pub running: bool,
    /// Total active sessions
    pub active_sessions: usize,
    /// Active TCP sessions
    pub tcp_sessions: usize,
    /// Active UDP sessions
    pub udp_sessions: usize,
    /// Statistics snapshot
    pub stats: IpStackBridgeStatsSnapshot,
}

/// Copy data bidirectionally between two async streams with custom buffer sizes.
///
/// This function is similar to `tokio::io::copy_bidirectional` but allows specifying
/// the buffer sizes for each direction. Larger buffers improve throughput by reducing
/// the number of syscalls and allowing more data to be transferred per operation.
///
/// # Arguments
///
/// * `a` - First async stream (both readable and writable)
/// * `b` - Second async stream (both readable and writable)
/// * `a_to_b_buf_size` - Buffer size for copying from `a` to `b`
/// * `b_to_a_buf_size` - Buffer size for copying from `b` to `a`
///
/// # Returns
///
/// A tuple of `(bytes_a_to_b, bytes_b_to_a)` on success, or an error.
async fn copy_bidirectional_with_sizes<A, B>(
    a: &mut A,
    b: &mut B,
    a_to_b_buf_size: usize,
    b_to_a_buf_size: usize,
) -> std::io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (mut a_reader, mut a_writer) = tokio::io::split(a);
    let (mut b_reader, mut b_writer) = tokio::io::split(b);

    // Copy from a to b
    let a_to_b = async {
        let mut buf = vec![0u8; a_to_b_buf_size];
        let mut total: u64 = 0;
        loop {
            let n = a_reader.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            b_writer.write_all(&buf[..n]).await?;
            total += n as u64;
        }
        b_writer.shutdown().await?;
        Ok::<_, std::io::Error>(total)
    };

    // Copy from b to a
    let b_to_a = async {
        let mut buf = vec![0u8; b_to_a_buf_size];
        let mut total: u64 = 0;
        loop {
            let n = b_reader.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            a_writer.write_all(&buf[..n]).await?;
            total += n as u64;
        }
        a_writer.shutdown().await?;
        Ok::<_, std::io::Error>(total)
    };

    // Run both directions concurrently
    let (a_to_b_result, b_to_a_result) = tokio::join!(a_to_b, b_to_a);

    // Handle results - if both fail, return the first error
    // Otherwise, return bytes transferred (0 for failed direction)
    match (a_to_b_result, b_to_a_result) {
        (Ok(a_to_b), Ok(b_to_a)) => Ok((a_to_b, b_to_a)),
        (Ok(a_to_b), Err(_)) => Ok((a_to_b, 0)),
        (Err(_), Ok(b_to_a)) => Ok((0, b_to_a)),
        (Err(e), Err(_)) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_bridge_creation() {
        let bridge = IpStackBridge::new();
        assert!(!bridge.is_running());
        assert_eq!(bridge.active_sessions(), 0);
    }

    #[tokio::test]
    async fn test_take_reply_rx_once() {
        let mut bridge = IpStackBridge::new();
        let rx1 = bridge.take_reply_rx();
        assert!(rx1.is_some());
        let rx2 = bridge.take_reply_rx();
        assert!(rx2.is_none());
    }

    #[tokio::test]
    async fn test_inject_packet() {
        let bridge = IpStackBridge::new();
        // Valid IPv4 TCP SYN packet header (minimal)
        let mut packet = vec![
            0x45, 0x00, 0x00, 0x28, // Version, IHL, DSCP, Total Length (40 bytes)
            0x00, 0x00, 0x00, 0x00, // ID, Flags, Fragment Offset
            0x40, 0x06, 0x00, 0x00, // TTL, Protocol (TCP=6), Checksum
            0x0a, 0x19, 0x00, 0x02, // Source IP: 10.25.0.2
            0x5d, 0xb8, 0xd8, 0x22, // Dest IP: 93.184.216.34
            0x30, 0x39, 0x00, 0x50, // Source Port: 12345, Dest Port: 80
            0x00, 0x00, 0x00, 0x00, // Seq number
            0x00, 0x00, 0x00, 0x00, // Ack number
            0x50, 0x02, 0xff, 0xff, // Data offset, flags (SYN), window
            0x00, 0x00, 0x00, 0x00, // Checksum, urgent pointer
        ];
        let packet = BytesMut::from(&packet[..]);
        let peer_key = [0u8; 32];

        let result = bridge.inject_packet(packet, peer_key).await;
        assert!(result.is_ok());

        let stats = bridge.stats.snapshot();
        assert_eq!(stats.packets_received, 1);

        // Session should be registered
        assert_eq!(bridge.session_tracker.total_sessions(), 1);
    }

    #[tokio::test]
    async fn test_try_inject_packet() {
        let bridge = IpStackBridge::new();
        let packet = BytesMut::from(&[0x45, 0x00, 0x00, 0x20][..]);
        let peer_key = [0u8; 32];

        let success = bridge.try_inject_packet(packet, peer_key);
        assert!(success);

        let stats = bridge.stats.snapshot();
        assert_eq!(stats.packets_received, 1);
    }

    #[tokio::test]
    async fn test_stats_snapshot() {
        let bridge = IpStackBridge::new();
        bridge.stats.packets_received.fetch_add(10, Ordering::Relaxed);
        bridge.stats.packets_sent.fetch_add(5, Ordering::Relaxed);
        bridge
            .stats
            .tcp_connections_accepted
            .fetch_add(3, Ordering::Relaxed);
        bridge
            .stats
            .bytes_to_outbound
            .fetch_add(1000, Ordering::Relaxed);
        bridge
            .stats
            .bytes_from_outbound
            .fetch_add(2000, Ordering::Relaxed);

        let snapshot = bridge.stats.snapshot();
        assert_eq!(snapshot.packets_received, 10);
        assert_eq!(snapshot.packets_sent, 5);
        assert_eq!(snapshot.tcp_connections_accepted, 3);
        assert_eq!(snapshot.bytes_to_outbound, 1000);
        assert_eq!(snapshot.bytes_from_outbound, 2000);
    }

    #[tokio::test]
    async fn test_stats_reset() {
        let bridge = IpStackBridge::new();
        bridge.stats.packets_received.fetch_add(10, Ordering::Relaxed);
        bridge.stats.reset();

        let snapshot = bridge.stats.snapshot();
        assert_eq!(snapshot.packets_received, 0);
    }

    #[tokio::test]
    async fn test_diagnostic_snapshot() {
        let bridge = IpStackBridge::new();

        let diag = bridge.diagnostic_snapshot();
        assert!(!diag.running);
        assert_eq!(diag.active_sessions, 0);
        assert_eq!(diag.tcp_sessions, 0);
        assert_eq!(diag.udp_sessions, 0);
    }

    #[test]
    fn test_stats_snapshot_serialization() {
        let snapshot = IpStackBridgeStatsSnapshot {
            packets_received: 100,
            packets_sent: 50,
            tcp_connections_accepted: 10,
            tcp_connections_failed: 2,
            udp_packets_forwarded: 30,
            bytes_to_outbound: 5000,
            bytes_from_outbound: 10000,
        };

        let json = serde_json::to_string(&snapshot).unwrap();
        assert!(json.contains("packets_received"));
        assert!(json.contains("100"));
    }

    #[test]
    fn test_parse_ipv4_tcp_packet() {
        // IPv4 TCP packet: 10.25.0.2:12345 -> 93.184.216.34:80
        let packet = vec![
            0x45, 0x00, 0x00, 0x28, // Version, IHL, DSCP, Total Length
            0x00, 0x00, 0x00, 0x00, // ID, Flags, Fragment Offset
            0x40, 0x06, 0x00, 0x00, // TTL, Protocol (TCP=6), Checksum
            0x0a, 0x19, 0x00, 0x02, // Source IP: 10.25.0.2
            0x5d, 0xb8, 0xd8, 0x22, // Dest IP: 93.184.216.34
            0x30, 0x39, 0x00, 0x50, // Source Port: 12345, Dest Port: 80
        ];

        let five_tuple = IpStackBridge::parse_packet_five_tuple(&packet);
        assert!(five_tuple.is_some());

        let ft = five_tuple.unwrap();
        assert!(ft.is_tcp());
        assert_eq!(ft.src_addr.port(), 12345);
        assert_eq!(ft.dst_addr.port(), 80);
    }

    #[test]
    fn test_parse_ipv4_udp_packet() {
        // IPv4 UDP packet: 10.25.0.2:54321 -> 8.8.8.8:53
        let packet = vec![
            0x45, 0x00, 0x00, 0x1c, // Version, IHL, DSCP, Total Length
            0x00, 0x00, 0x00, 0x00, // ID, Flags, Fragment Offset
            0x40, 0x11, 0x00, 0x00, // TTL, Protocol (UDP=17), Checksum
            0x0a, 0x19, 0x00, 0x02, // Source IP: 10.25.0.2
            0x08, 0x08, 0x08, 0x08, // Dest IP: 8.8.8.8
            0xd4, 0x31, 0x00, 0x35, // Source Port: 54321, Dest Port: 53
        ];

        let five_tuple = IpStackBridge::parse_packet_five_tuple(&packet);
        assert!(five_tuple.is_some());

        let ft = five_tuple.unwrap();
        assert!(ft.is_udp());
        assert_eq!(ft.src_addr.port(), 54321);
        assert_eq!(ft.dst_addr.port(), 53);
    }

    #[test]
    fn test_parse_malformed_packet() {
        // Too short
        let packet = vec![0x45, 0x00];
        assert!(IpStackBridge::parse_packet_five_tuple(&packet).is_none());

        // Empty
        assert!(IpStackBridge::parse_packet_five_tuple(&[]).is_none());

        // Invalid version
        let packet = vec![0x00; 40];
        assert!(IpStackBridge::parse_packet_five_tuple(&packet).is_none());
    }
}
