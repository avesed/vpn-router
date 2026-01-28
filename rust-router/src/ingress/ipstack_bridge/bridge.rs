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
use crate::outbound::{OutboundManager, OutboundStream};
use bytes::BytesMut;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, info, trace, warn};

#[cfg(feature = "fakedns")]
use crate::fakedns::FakeDnsManager;

#[cfg(any(feature = "sni-sniffing", feature = "fakedns"))]
use super::domain_resolver::{resolve_domain, DomainSource};

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
    /// Reply channel backpressure events (channel was full)
    pub reply_backpressure: AtomicU64,
    /// Packets dropped due to reply channel timeout
    pub reply_drops: AtomicU64,
    // Domain routing statistics (Phase 0)
    /// DNS queries hijacked by FakeDNS
    pub dns_queries_hijacked: AtomicU64,
    /// Successful FakeDNS reverse lookups
    pub fakedns_reverse_hits: AtomicU64,
    /// Successful SNI extractions
    pub sni_extractions: AtomicU64,
    /// Successful HTTP Host extractions
    pub http_host_extractions: AtomicU64,
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
            reply_backpressure: self.reply_backpressure.load(Ordering::Relaxed),
            reply_drops: self.reply_drops.load(Ordering::Relaxed),
            dns_queries_hijacked: self.dns_queries_hijacked.load(Ordering::Relaxed),
            fakedns_reverse_hits: self.fakedns_reverse_hits.load(Ordering::Relaxed),
            sni_extractions: self.sni_extractions.load(Ordering::Relaxed),
            http_host_extractions: self.http_host_extractions.load(Ordering::Relaxed),
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
        self.reply_backpressure.store(0, Ordering::Relaxed);
        self.reply_drops.store(0, Ordering::Relaxed);
        self.dns_queries_hijacked.store(0, Ordering::Relaxed);
        self.fakedns_reverse_hits.store(0, Ordering::Relaxed);
        self.sni_extractions.store(0, Ordering::Relaxed);
        self.http_host_extractions.store(0, Ordering::Relaxed);
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
    /// Reply channel backpressure events (channel was full)
    pub reply_backpressure: u64,
    /// Packets dropped due to reply channel timeout
    pub reply_drops: u64,
    // Domain routing statistics (Phase 0)
    /// DNS queries hijacked by FakeDNS
    pub dns_queries_hijacked: u64,
    /// Successful FakeDNS reverse lookups
    pub fakedns_reverse_hits: u64,
    /// Successful SNI extractions
    pub sni_extractions: u64,
    /// Successful HTTP Host extractions
    pub http_host_extractions: u64,
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
    /// Outbound manager for routing decisions
    outbound_manager: Option<Arc<OutboundManager>>,
    /// FakeDNS manager for domain-based routing
    #[cfg(feature = "fakedns")]
    fakedns_manager: Option<Arc<FakeDnsManager>>,
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
            outbound_manager: None,
            #[cfg(feature = "fakedns")]
            fakedns_manager: None,
        }
    }

    /// Set the FakeDNS manager for DNS hijacking
    ///
    /// When set, DNS queries (port 53) will be intercepted and resolved
    /// using FakeDNS, enabling domain-based routing.
    #[cfg(feature = "fakedns")]
    pub fn set_fakedns_manager(&mut self, manager: Arc<FakeDnsManager>) {
        self.fakedns_manager = Some(manager);
    }

    /// Get the FakeDNS manager reference
    #[cfg(feature = "fakedns")]
    pub fn fakedns_manager(&self) -> Option<&Arc<FakeDnsManager>> {
        self.fakedns_manager.as_ref()
    }

    /// Set the outbound manager for routing decisions
    ///
    /// Must be called before `start()` to enable outbound routing.
    /// If not set, all connections will use direct TCP connection.
    pub fn set_outbound_manager(&mut self, manager: Arc<OutboundManager>) {
        self.outbound_manager = Some(manager);
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
    /// * `peer_endpoint` - The WireGuard peer's endpoint (IP:port) for reply routing
    /// * `outbound_tag` - The outbound tag for routing (e.g., "direct", "vless-xxx")
    ///
    /// # Errors
    ///
    /// Returns an error if the packet channel is closed.
    pub async fn inject_packet(
        &self,
        packet: BytesMut,
        peer_key: [u8; 32],
        peer_endpoint: SocketAddr,
        outbound_tag: &str,
    ) -> anyhow::Result<()> {
        self.stats.packets_received.fetch_add(1, Ordering::Relaxed);

        // Parse the packet to extract 5-tuple for session tracking
        let five_tuple = Self::parse_packet_five_tuple(&packet);

        // Register with session tracker for reply routing (forward-only, no reverse index)
        // Session is registered BEFORE send to ensure reply routing works immediately
        // The outbound_tag is stored in the session for later use by handle_tcp_connection
        if let Some(ref ft) = five_tuple {
            self.session_tracker
                .register_forward_only(peer_key, peer_endpoint, ft.clone(), outbound_tag.to_string());
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
    /// * `peer_endpoint` - The WireGuard peer's endpoint (IP:port) for reply routing
    ///
    /// # Returns
    ///
    /// `true` if the packet was successfully queued, `false` if the channel is full or closed.
    pub fn try_inject_packet(
        &self,
        packet: BytesMut,
        peer_key: [u8; 32],
        peer_endpoint: SocketAddr,
        outbound_tag: &str,
    ) -> bool {
        self.stats.packets_received.fetch_add(1, Ordering::Relaxed);

        // Parse the packet to extract 5-tuple for session tracking
        let five_tuple = Self::parse_packet_five_tuple(&packet);

        // Register with session tracker for reply routing (forward-only, no reverse index)
        // The outbound_tag is stored in the session for later use by handle_tcp_connection
        if let Some(ref ft) = five_tuple {
            self.session_tracker
                .register_forward_only(peer_key, peer_endpoint, ft.clone(), outbound_tag.to_string());
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
    ///
    /// Handles IPv6 extension headers by skipping through them to find the
    /// actual transport protocol (TCP/UDP). Supported extension headers:
    /// - Hop-by-Hop Options (0)
    /// - Routing (43)
    /// - Fragment (44)
    /// - Destination Options (60)
    /// - Mobility (135)
    fn parse_ipv6_five_tuple(packet: &[u8]) -> Option<FiveTuple> {
        // Minimum IPv6 header is 40 bytes
        if packet.len() < 40 {
            return None;
        }

        // Extract addresses from the fixed header first
        let mut src_octets = [0u8; 16];
        let mut dst_octets = [0u8; 16];
        src_octets.copy_from_slice(&packet[8..24]);
        dst_octets.copy_from_slice(&packet[24..40]);

        let src_ip = Ipv6Addr::from(src_octets);
        let dst_ip = Ipv6Addr::from(dst_octets);

        // Skip extension headers to find the transport protocol
        let mut next_header = packet[6];
        let mut offset = 40; // Start after fixed IPv6 header

        loop {
            match next_header {
                // TCP (6) or UDP (17) - we found the transport layer
                6 | 17 => break,

                // Hop-by-Hop Options (0), Routing (43), Destination Options (60), Mobility (135)
                // These headers have their length in the second byte (in 8-byte units, not including first 8)
                0 | 43 | 60 | 135 => {
                    if packet.len() < offset + 2 {
                        return None;
                    }
                    next_header = packet[offset];
                    let ext_len = (packet[offset + 1] as usize + 1) * 8;
                    offset += ext_len;
                }

                // Fragment header (44) - fixed 8 bytes
                44 => {
                    if packet.len() < offset + 8 {
                        return None;
                    }
                    next_header = packet[offset];
                    offset += 8;
                }

                // No Next Header (59), or unknown/unsupported extension header
                // Can't parse further - return None to use content-based hashing fallback
                _ => return None,
            }

            // Safety check to prevent infinite loops on malformed packets
            if offset > packet.len() {
                return None;
            }
        }

        // Need at least 4 more bytes for ports (TCP/UDP header starts at offset)
        if packet.len() < offset + 4 {
            return None;
        }

        let src_port = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
        let dst_port = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]);

        let src_addr = SocketAddr::new(IpAddr::V6(src_ip), src_port);
        let dst_addr = SocketAddr::new(IpAddr::V6(dst_ip), dst_port);

        match next_header {
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
        // Using mtu_unchecked() since WG_MTU (1420) is a known-valid value
        let mut ipstack_config = ipstack::IpStackConfig::default();
        ipstack_config.mtu_unchecked(WG_MTU as u16);

        // Configure TCP parameters for high throughput
        // The default MAX_UNACK and READ_BUFFER_SIZE of 16KB severely limits throughput
        // We use configurable values (default 256KB) for better BDP support
        //
        // Critical: max_unacked_bytes controls SEND throughput (download to client)
        //           read_buffer_size controls RECEIVE window (upload from client)
        // Both must be increased for bidirectional high throughput!
        let max_unack = configured_max_unack();
        let mut tcp_config = ipstack::TcpConfig::default();
        tcp_config.max_unacked_bytes = max_unack;
        tcp_config.read_buffer_size = max_unack as usize; // Same BDP applies to both directions
        ipstack_config.with_tcp_config(tcp_config);

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
        let outbound_manager = self.outbound_manager.clone();
        #[cfg(feature = "fakedns")]
        let fakedns_manager = self.fakedns_manager.clone();
        let accept_task = tokio::spawn(Self::accept_loop_task(
            ip_stack,
            running,
            stats,
            session_tracker,
            outbound_manager,
            #[cfg(feature = "fakedns")]
            fakedns_manager,
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
    ///
    /// This task reads packets from ipstack's output channel, looks up the session
    /// to get peer info, and sends (packet, peer_key) to the reply channel.
    ///
    /// Uses non-blocking try_send with timeout fallback to prevent TCP stack stalls
    /// when the reply channel is full. The 50ms timeout is chosen to be less than
    /// TCP's typical RTO (200ms+), so dropped packets will be retransmitted.
    async fn reply_router_task(
        mut ipstack_rx: mpsc::Receiver<BytesMut>,
        reply_tx: mpsc::Sender<(BytesMut, [u8; 32])>,
        session_tracker: Arc<SessionTracker>,
        running: Arc<AtomicBool>,
        stats: Arc<IpStackBridgeStats>,
    ) {
        use std::time::Duration;

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

                            // Fast path: try non-blocking send first
                            match reply_tx.try_send((packet.clone(), session.peer_key)) {
                                Ok(()) => { /* success */ }
                                Err(mpsc::error::TrySendError::Full(_)) => {
                                    // Channel full - record backpressure event
                                    stats.reply_backpressure.fetch_add(1, Ordering::Relaxed);

                                    // Slow path: wait with timeout (50ms < TCP RTO)
                                    match tokio::time::timeout(
                                        Duration::from_millis(50),
                                        reply_tx.send((packet, session.peer_key)),
                                    )
                                    .await
                                    {
                                        Ok(Ok(())) => { /* sent after wait */ }
                                        Ok(Err(_)) => break, // Channel closed
                                        Err(_) => {
                                            // Timeout - drop packet, TCP will retransmit
                                            stats.reply_drops.fetch_add(1, Ordering::Relaxed);
                                            debug!(
                                                "Reply channel timeout, packet dropped (TCP will retransmit)"
                                            );
                                        }
                                    }
                                }
                                Err(mpsc::error::TrySendError::Closed(_)) => break,
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
        outbound_manager: Option<Arc<OutboundManager>>,
        #[cfg(feature = "fakedns")] fakedns_manager: Option<Arc<FakeDnsManager>>,
    ) {
        debug!("Accept loop task started");

        while running.load(Ordering::SeqCst) {
            match ip_stack.accept().await {
                Ok(stream) => {
                    Self::handle_stream(
                        stream,
                        Arc::clone(&stats),
                        Arc::clone(&session_tracker),
                        outbound_manager.clone(),
                        #[cfg(feature = "fakedns")]
                        fakedns_manager.clone(),
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
        stream: ipstack::IpStackStream,
        stats: Arc<IpStackBridgeStats>,
        session_tracker: Arc<SessionTracker>,
        outbound_manager: Option<Arc<OutboundManager>>,
        #[cfg(feature = "fakedns")] fakedns_manager: Option<Arc<FakeDnsManager>>,
    ) {
        match stream {
            ipstack::IpStackStream::Tcp(tcp_stream) => {
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
                    outbound_manager,
                    #[cfg(feature = "fakedns")]
                    fakedns_manager,
                ));
            }
            ipstack::IpStackStream::Udp(udp_stream) => {
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
                    outbound_manager,
                    #[cfg(feature = "fakedns")]
                    fakedns_manager,
                ));
            }
            ipstack::IpStackStream::UnknownTransport(unknown) => {
                trace!(
                    "Unknown transport packet: {} -> {}",
                    unknown.src_addr(),
                    unknown.dst_addr()
                );
            }
            ipstack::IpStackStream::UnknownNetwork(packet) => {
                trace!("Unknown network packet: {} bytes", packet.len());
            }
        }
    }

    /// Handle a TCP connection from ipstack
    ///
    /// Routes the connection through the appropriate outbound based on
    /// the outbound_tag stored in the session tracker.
    async fn handle_tcp_connection(
        tcp_stream: ipstack::IpStackTcpStream,
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
        stats: Arc<IpStackBridgeStats>,
        session_tracker: Arc<SessionTracker>,
        outbound_manager: Option<Arc<OutboundManager>>,
        #[cfg(feature = "fakedns")] fakedns_manager: Option<Arc<FakeDnsManager>>,
    ) {
        // Wrap stream in BufReader for peek functionality (needed for SNI sniffing)
        // We do this early so we can use it for both DNS hijack and domain resolution
        use tokio::io::BufReader;
        let mut buffered = BufReader::with_capacity(configured_sni_buffer_size(), tcp_stream);

        // TCP DNS hijack for port 53
        #[cfg(feature = "fakedns")]
        if peer_addr.port() == 53 {
            if let Some(ref fakedns) = fakedns_manager {
                use super::dns_hijack::handle_tcp_dns_query;

                match handle_tcp_dns_query(&mut buffered, fakedns.as_ref()).await {
                    Ok(()) => {
                        stats.dns_queries_hijacked.fetch_add(1, Ordering::Relaxed);
                        trace!("TCP DNS query hijacked via FakeDNS");
                    }
                    Err(e) => {
                        warn!(error = %e, "TCP DNS hijack failed");
                    }
                }
                // DNS handled, remove session and return
                let five_tuple = FiveTuple::tcp(local_addr, peer_addr);
                session_tracker.remove(&five_tuple);
                return;
            }
        }

        // Phase 2: Domain resolution using hybrid approach (FakeDNS + SNI + HTTP Host)
        #[cfg(any(feature = "sni-sniffing", feature = "fakedns"))]
        let domain_resolution = {
            use tokio::io::AsyncBufReadExt;

            // Peek first packet for SNI/HTTP sniffing (with timeout)
            let first_packet: Option<Vec<u8>> = match tokio::time::timeout(
                sni_peek_timeout(),
                buffered.fill_buf(),
            )
            .await
            {
                Ok(Ok(data)) if !data.is_empty() => Some(data.to_vec()),
                _ => None,
            };

            resolve_domain(
                peer_addr.ip(),
                peer_addr.port(),
                first_packet.as_deref(),
                #[cfg(feature = "fakedns")]
                fakedns_manager.as_ref().map(|m| m.as_ref()),
                #[cfg(not(feature = "fakedns"))]
                None,
            )
        };

        // Update statistics based on resolution source
        #[cfg(any(feature = "sni-sniffing", feature = "fakedns"))]
        match domain_resolution.source {
            DomainSource::FakeDns => {
                stats.fakedns_reverse_hits.fetch_add(1, Ordering::Relaxed);
            }
            DomainSource::TlsSni => {
                stats.sni_extractions.fetch_add(1, Ordering::Relaxed);
            }
            DomainSource::HttpHost => {
                stats.http_host_extractions.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }

        // Log domain resolution result
        #[cfg(any(feature = "sni-sniffing", feature = "fakedns"))]
        debug!(
            local = %local_addr,
            peer = %peer_addr,
            domain = ?domain_resolution.domain,
            source = %domain_resolution.source,
            "TCP connection with domain resolution"
        );

        // Look up the session to get the outbound_tag
        let five_tuple = FiveTuple::tcp(local_addr, peer_addr);
        let outbound_tag = session_tracker
            .lookup(&five_tuple)
            .map(|s| s.outbound_tag.clone())
            .unwrap_or_else(|| "direct".to_string());

        // Log for non-domain-routing case
        #[cfg(not(any(feature = "sni-sniffing", feature = "fakedns")))]
        debug!(
            "Handling TCP connection: local={}, peer={}, outbound={}",
            local_addr, peer_addr, outbound_tag
        );

        // Log outbound tag for domain-routing case (already logged domain above)
        #[cfg(any(feature = "sni-sniffing", feature = "fakedns"))]
        trace!(
            local = %local_addr,
            peer = %peer_addr,
            outbound = %outbound_tag,
            "TCP connection outbound selection"
        );

        // Handle block outbound
        if outbound_tag == "block" || outbound_tag == "adblock" {
            debug!("Blocking TCP connection: {} -> {}", local_addr, peer_addr);
            session_tracker.remove(&five_tuple);
            return;
        }

        // Connect to the destination using the appropriate outbound
        let connect_timeout = tcp_connect_timeout();

        // Try to use OutboundManager if available and outbound_tag is not "direct"
        let outbound_stream: Option<OutboundStream> = if outbound_tag != "direct" {
            if let Some(ref manager) = outbound_manager {
                if let Some(outbound) = manager.get(&outbound_tag) {
                    match outbound.connect(peer_addr, connect_timeout).await {
                        Ok(conn) => {
                            debug!(
                                "Connected via outbound '{}' to {}",
                                outbound_tag, peer_addr
                            );
                            Some(conn.into_outbound_stream())
                        }
                        Err(e) => {
                            warn!(
                                "Failed to connect via outbound '{}' to {}: {}",
                                outbound_tag, peer_addr, e
                            );
                            stats.tcp_connections_failed.fetch_add(1, Ordering::Relaxed);
                            session_tracker.remove(&five_tuple);
                            return;
                        }
                    }
                } else {
                    warn!(
                        "Outbound '{}' not found, falling back to direct for {}",
                        outbound_tag, peer_addr
                    );
                    None
                }
            } else {
                debug!(
                    "OutboundManager not set, using direct connection for {}",
                    peer_addr
                );
                None
            }
        } else {
            None
        };

        // If no OutboundStream from manager, use direct TCP connection
        let mut outbound_stream = match outbound_stream {
            Some(stream) => stream,
            None => {
                // Direct TCP connection
                let outbound = match tokio::time::timeout(
                    connect_timeout,
                    TcpStream::connect(peer_addr),
                )
                .await
                {
                    Ok(Ok(stream)) => stream,
                    Ok(Err(e)) => {
                        warn!("Failed to connect directly to {}: {}", peer_addr, e);
                        stats.tcp_connections_failed.fetch_add(1, Ordering::Relaxed);
                        session_tracker.remove(&five_tuple);
                        return;
                    }
                    Err(_) => {
                        warn!("Connection timeout to {}", peer_addr);
                        stats.tcp_connections_failed.fetch_add(1, Ordering::Relaxed);
                        session_tracker.remove(&five_tuple);
                        return;
                    }
                };

                // Set TCP_NODELAY to reduce latency (disable Nagle's algorithm)
                if let Err(e) = outbound.set_nodelay(true) {
                    debug!("Failed to set TCP_NODELAY: {}", e);
                }

                // Set larger socket buffer sizes for better throughput
                {
                    use socket2::SockRef;
                    let sock_ref = SockRef::from(&outbound);
                    if let Err(e) = sock_ref.set_recv_buffer_size(TCP_SOCKET_BUFFER_SIZE) {
                        debug!("Failed to set SO_RCVBUF: {}", e);
                    }
                    if let Err(e) = sock_ref.set_send_buffer_size(TCP_SOCKET_BUFFER_SIZE) {
                        debug!("Failed to set SO_SNDBUF: {}", e);
                    }
                }

                debug!("Connected directly to {}", peer_addr);
                OutboundStream::tcp(outbound)
            }
        };

        // Bridge the streams using tokio's copy_bidirectional_with_sizes
        // Using configurable buffers (default 64KB) instead of default 8KB for better
        // throughput on high-bandwidth connections (reduces syscall overhead by 8x)
        // Buffer size can be tuned via IPSTACK_TCP_BUFFER_KB environment variable
        // IMPORTANT: Use `buffered` stream (BufReader) instead of raw tcp_stream
        // to preserve the peeked data from SNI/HTTP sniffing
        let buffer_size = configured_tcp_buffer_size();
        match tokio::io::copy_bidirectional_with_sizes(
            &mut buffered,
            &mut outbound_stream,
            buffer_size,
            buffer_size,
        )
        .await
        {
            Ok((to_outbound, from_outbound)) => {
                stats
                    .bytes_to_outbound
                    .fetch_add(to_outbound, Ordering::Relaxed);
                stats
                    .bytes_from_outbound
                    .fetch_add(from_outbound, Ordering::Relaxed);
                debug!(
                    "TCP connection completed: {} -> {} (via {}), sent={}, recv={}",
                    local_addr, peer_addr, outbound_tag, to_outbound, from_outbound
                );
            }
            Err(e) => {
                // Connection errors are common (RST, etc.), only log at debug level
                debug!(
                    "TCP connection error: {} -> {} (via {}): {}",
                    local_addr, peer_addr, outbound_tag, e
                );
            }
        }

        // Clean up session from tracker
        session_tracker.remove(&five_tuple);

        debug!("TCP connection closed: {} -> {}", local_addr, peer_addr);
    }

    /// Handle a UDP stream from ipstack
    ///
    /// Routes UDP traffic through the appropriate outbound based on
    /// the outbound_tag stored in the session tracker.
    async fn handle_udp_stream(
        mut udp_stream: ipstack::IpStackUdpStream,
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
        stats: Arc<IpStackBridgeStats>,
        session_tracker: Arc<SessionTracker>,
        outbound_manager: Option<Arc<OutboundManager>>,
        #[cfg(feature = "fakedns")] fakedns_manager: Option<Arc<FakeDnsManager>>,
    ) {
        // DNS hijack for port 53
        #[cfg(feature = "fakedns")]
        if peer_addr.port() == 53 {
            if let Some(ref fakedns) = fakedns_manager {
                use super::dns_hijack::handle_udp_dns_query;

                match handle_udp_dns_query(&mut udp_stream, fakedns.as_ref()).await {
                    Ok(()) => {
                        stats.dns_queries_hijacked.fetch_add(1, Ordering::Relaxed);
                        trace!("UDP DNS query hijacked via FakeDNS");
                    }
                    Err(e) => {
                        warn!(error = %e, "UDP DNS hijack failed");
                    }
                }
                // DNS handled, remove session and return
                let five_tuple = FiveTuple::udp(local_addr, peer_addr);
                session_tracker.remove(&five_tuple);
                return;
            }
        }

        // Phase 2: For non-DNS UDP, try FakeDNS reverse lookup
        // UDP does not have protocol-level sniffing like TCP (no SNI/HTTP headers)
        // so we can only use FakeDNS reverse lookup for domain resolution
        #[cfg(feature = "fakedns")]
        let resolved_domain = if let Some(ref fakedns) = fakedns_manager {
            if fakedns.is_fake_ip(peer_addr.ip()) {
                let domain = fakedns.map_ip_domain(peer_addr.ip());
                if domain.is_some() {
                    stats.fakedns_reverse_hits.fetch_add(1, Ordering::Relaxed);
                }
                domain
            } else {
                None
            }
        } else {
            None
        };

        #[cfg(feature = "fakedns")]
        debug!(
            local = %local_addr,
            peer = %peer_addr,
            domain = ?resolved_domain,
            "UDP stream with FakeDNS lookup"
        );

        // Look up the session to get the outbound_tag
        let five_tuple = FiveTuple::udp(local_addr, peer_addr);
        let outbound_tag = session_tracker
            .lookup(&five_tuple)
            .map(|s| s.outbound_tag.clone())
            .unwrap_or_else(|| "direct".to_string());

        // Log for non-fakedns case
        #[cfg(not(feature = "fakedns"))]
        debug!(
            "Handling UDP stream: local={}, peer={}, outbound={}",
            local_addr, peer_addr, outbound_tag
        );

        // Log outbound tag for fakedns case (already logged domain above)
        #[cfg(feature = "fakedns")]
        trace!(
            local = %local_addr,
            peer = %peer_addr,
            outbound = %outbound_tag,
            "UDP stream outbound selection"
        );

        // Handle block outbound
        if outbound_tag == "block" || outbound_tag == "adblock" {
            debug!("Blocking UDP stream: {} -> {}", local_addr, peer_addr);
            session_tracker.remove(&five_tuple);
            return;
        }

        let connect_timeout = tcp_connect_timeout();

        // Try to use OutboundManager UDP if available and outbound_tag is not "direct"
        let udp_handle = if outbound_tag != "direct" {
            if let Some(ref manager) = outbound_manager {
                if let Some(outbound) = manager.get(&outbound_tag) {
                    if outbound.supports_udp() {
                        match outbound.connect_udp(peer_addr, connect_timeout).await {
                            Ok(handle) => {
                                debug!(
                                    "UDP connected via outbound '{}' to {}",
                                    outbound_tag, peer_addr
                                );
                                Some(handle)
                            }
                            Err(e) => {
                                warn!(
                                    "Failed to connect UDP via outbound '{}' to {}: {}",
                                    outbound_tag, peer_addr, e
                                );
                                // Fall back to direct
                                None
                            }
                        }
                    } else {
                        debug!(
                            "Outbound '{}' does not support UDP, using direct for {}",
                            outbound_tag, peer_addr
                        );
                        None
                    }
                } else {
                    warn!(
                        "Outbound '{}' not found, falling back to direct for UDP {}",
                        outbound_tag, peer_addr
                    );
                    None
                }
            } else {
                None
            }
        } else {
            None
        };

        // If using OutboundManager UDP handle
        if let Some(handle) = udp_handle {
            Self::handle_udp_via_outbound(
                udp_stream,
                local_addr,
                peer_addr,
                &outbound_tag,
                handle,
                stats,
                session_tracker,
            )
            .await;
            return;
        }

        // Fall back to direct UDP connection
        let outbound = match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
            Ok(socket) => socket,
            Err(e) => {
                warn!("Failed to bind UDP socket: {}", e);
                session_tracker.remove(&five_tuple);
                return;
            }
        };

        if let Err(e) = outbound.connect(peer_addr).await {
            warn!("Failed to connect UDP socket to {}: {}", peer_addr, e);
            session_tracker.remove(&five_tuple);
            return;
        }

        debug!("UDP socket connected directly to: {}", peer_addr);

        // Bridge UDP traffic
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
        session_tracker.remove(&five_tuple);

        debug!("UDP stream closed: {} -> {}", local_addr, peer_addr);
    }

    /// Handle UDP via OutboundManager's UDP handle
    async fn handle_udp_via_outbound(
        mut udp_stream: ipstack::IpStackUdpStream,
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
        outbound_tag: &str,
        handle: crate::outbound::UdpOutboundHandle,
        stats: Arc<IpStackBridgeStats>,
        session_tracker: Arc<SessionTracker>,
    ) {
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
                            trace!("UDP via {}: {} bytes from client to {}", outbound_tag, n, peer_addr);
                            stats.bytes_to_outbound.fetch_add(n as u64, Ordering::Relaxed);
                            stats.udp_packets_forwarded.fetch_add(1, Ordering::Relaxed);

                            if let Err(e) = handle.send(&buf[..n]).await {
                                warn!("UDP send error via {}: {}", outbound_tag, e);
                                break;
                            }
                        }
                        Err(e) => {
                            debug!("UDP read error: {}", e);
                            break;
                        }
                    }
                }

                // Read from outbound UDP handle
                result = handle.recv(&mut recv_buf) => {
                    match result {
                        Ok(n) => {
                            trace!("UDP via {}: {} bytes from {} to client", outbound_tag, n, peer_addr);
                            stats.bytes_from_outbound.fetch_add(n as u64, Ordering::Relaxed);

                            if let Err(e) = tokio::io::AsyncWriteExt::write_all(&mut udp_stream, &recv_buf[..n]).await {
                                warn!("UDP write error: {}", e);
                                break;
                            }
                        }
                        Err(e) => {
                            debug!("UDP recv error via {}: {}", outbound_tag, e);
                            break;
                        }
                    }
                }

                // Timeout for UDP session
                _ = tokio::time::sleep(timeout) => {
                    debug!("UDP session timeout: {} -> {} (via {})", local_addr, peer_addr, outbound_tag);
                    break;
                }
            }
        }

        // Clean up session from tracker
        let five_tuple = FiveTuple::udp(local_addr, peer_addr);
        session_tracker.remove(&five_tuple);

        debug!("UDP stream closed: {} -> {} (via {})", local_addr, peer_addr, outbound_tag);
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
        use std::net::{IpAddr, Ipv4Addr};

        let bridge = IpStackBridge::new();
        // Valid IPv4 TCP SYN packet header (minimal)
        let packet = vec![
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
        let peer_endpoint = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 51820);

        let result = bridge.inject_packet(packet, peer_key, peer_endpoint).await;
        assert!(result.is_ok());

        let stats = bridge.stats.snapshot();
        assert_eq!(stats.packets_received, 1);

        // Session should be registered
        assert_eq!(bridge.session_tracker.total_sessions(), 1);
    }

    #[tokio::test]
    async fn test_try_inject_packet() {
        use std::net::{IpAddr, Ipv4Addr};

        let bridge = IpStackBridge::new();
        let packet = BytesMut::from(&[0x45, 0x00, 0x00, 0x20][..]);
        let peer_key = [0u8; 32];
        let peer_endpoint = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 51820);

        let success = bridge.try_inject_packet(packet, peer_key, peer_endpoint);
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
        bridge.stats.reply_backpressure.fetch_add(5, Ordering::Relaxed);
        bridge.stats.reply_drops.fetch_add(2, Ordering::Relaxed);
        bridge.stats.reset();

        let snapshot = bridge.stats.snapshot();
        assert_eq!(snapshot.packets_received, 0);
        assert_eq!(snapshot.reply_backpressure, 0);
        assert_eq!(snapshot.reply_drops, 0);
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
            reply_backpressure: 5,
            reply_drops: 1,
            dns_queries_hijacked: 15,
            fakedns_reverse_hits: 12,
            sni_extractions: 8,
            http_host_extractions: 3,
        };

        let json = serde_json::to_string(&snapshot).unwrap();
        assert!(json.contains("packets_received"));
        assert!(json.contains("100"));
        assert!(json.contains("reply_backpressure"));
        assert!(json.contains("reply_drops"));
        assert!(json.contains("dns_queries_hijacked"));
        assert!(json.contains("fakedns_reverse_hits"));
        assert!(json.contains("sni_extractions"));
        assert!(json.contains("http_host_extractions"));
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
