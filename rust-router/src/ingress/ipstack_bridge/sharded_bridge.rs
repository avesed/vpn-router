//! Sharded IpStack Bridge - Parallel packet processing across multiple ipstack instances
//!
//! This module provides a sharded version of the IpStackBridge that distributes
//! packets across N ipstack instances using 5-tuple hashing for parallel processing.
//!
//! # Architecture
//!
//! ```text
//!                         WireGuard Packet
//!                               |
//!                               v
//!                       5-tuple hash sharding
//!                               |
//!           +-------------------+-------------------+
//!           |                   |                   |
//!           v                   v                   v
//!     +-----------+       +-----------+       +-----------+
//!     |  Shard 0  |       |  Shard 1  |       |  Shard N  |
//!     |  ipstack  |       |  ipstack  |       |  ipstack  |
//!     |  accept   |       |  accept   |       |  accept   |
//!     |  reply    |       |  reply    |       |  reply    |
//!     +-----+-----+       +-----+-----+       +-----+-----+
//!           |                   |                   |
//!           +-------------------+-------------------+
//!                               |
//!                               v
//!                     Shared SessionTracker (reply routing)
//!                               |
//!                               v
//!                     WgIngressManager.send_to_peer()
//! ```
//!
//! # Benefits
//!
//! - Parallel packet processing across CPU cores
//! - Consistent hashing ensures all packets from same connection go to same shard
//! - Shared session tracker allows reply routing across all shards
//! - Aggregated statistics for monitoring
//!
//! # Usage
//!
//! ```ignore
//! use rust_router::ingress::ipstack_bridge::ShardedIpStackBridge;
//!
//! // Create with default shard count (based on CPU cores)
//! let mut bridge = ShardedIpStackBridge::new_default();
//!
//! // Or specify shard count explicitly
//! let mut bridge = ShardedIpStackBridge::new(4);
//!
//! // Take the reply receiver for routing packets back to WireGuard
//! let reply_rx = bridge.take_reply_rx().unwrap();
//!
//! // Start all shards
//! bridge.start().await?;
//!
//! // Inject packets - automatically routes to correct shard
//! bridge.inject_packet(packet, peer_key).await?;
//! ```

use super::config::*;
use super::packet_channel::PacketChannel;
use super::session_tracker::{FiveTuple, SessionTracker};
use crate::outbound::{OutboundManager, OutboundStream};
use crate::rules::engine::{ConnectionInfo, RuleEngine};
use ahash::AHasher;
use bytes::BytesMut;
use std::hash::{Hash, Hasher};
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

/// Aggregated statistics across all shards
///
/// Provides both per-shard stats for debugging uneven distribution
/// and global aggregated stats for monitoring.
#[derive(Debug)]
pub struct ShardedBridgeStats {
    /// Per-shard statistics for debugging
    pub per_shard_stats: Vec<Arc<ShardStats>>,
    /// Global stats (aggregate counters)
    pub packets_received: AtomicU64,
    pub packets_sent: AtomicU64,
    pub tcp_connections_accepted: AtomicU64,
    pub tcp_connections_failed: AtomicU64,
    pub udp_packets_forwarded: AtomicU64,
    pub bytes_to_outbound: AtomicU64,
    pub bytes_from_outbound: AtomicU64,
    pub reply_backpressure: AtomicU64,
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
    /// Connections re-routed based on domain rules (SNI/FakeDNS override)
    pub domain_reroutes: AtomicU64,
}

impl ShardedBridgeStats {
    /// Create new stats container with specified shard count
    fn new(shard_count: usize) -> Self {
        let mut per_shard_stats = Vec::with_capacity(shard_count);
        for shard_id in 0..shard_count {
            per_shard_stats.push(Arc::new(ShardStats::new(shard_id)));
        }
        Self {
            per_shard_stats,
            packets_received: AtomicU64::new(0),
            packets_sent: AtomicU64::new(0),
            tcp_connections_accepted: AtomicU64::new(0),
            tcp_connections_failed: AtomicU64::new(0),
            udp_packets_forwarded: AtomicU64::new(0),
            bytes_to_outbound: AtomicU64::new(0),
            bytes_from_outbound: AtomicU64::new(0),
            reply_backpressure: AtomicU64::new(0),
            reply_drops: AtomicU64::new(0),
            dns_queries_hijacked: AtomicU64::new(0),
            fakedns_reverse_hits: AtomicU64::new(0),
            sni_extractions: AtomicU64::new(0),
            http_host_extractions: AtomicU64::new(0),
            domain_reroutes: AtomicU64::new(0),
        }
    }

    /// Create a snapshot of the current statistics
    pub fn snapshot(&self) -> ShardedBridgeStatsSnapshot {
        ShardedBridgeStatsSnapshot {
            shard_count: self.per_shard_stats.len(),
            per_shard_packets: self
                .per_shard_stats
                .iter()
                .map(|s| s.packets_received.load(Ordering::Relaxed))
                .collect(),
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
            domain_reroutes: self.domain_reroutes.load(Ordering::Relaxed),
        }
    }

    /// Reset all statistics to zero
    pub fn reset(&self) {
        for shard in &self.per_shard_stats {
            shard.reset();
        }
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
        self.domain_reroutes.store(0, Ordering::Relaxed);
    }
}

/// Per-shard statistics
#[derive(Debug, Default)]
pub struct ShardStats {
    /// Shard identifier
    pub shard_id: usize,
    /// Packets received by this shard
    pub packets_received: AtomicU64,
    /// Packets sent by this shard
    pub packets_sent: AtomicU64,
    /// TCP connections accepted
    pub tcp_connections_accepted: AtomicU64,
    /// TCP connections failed
    pub tcp_connections_failed: AtomicU64,
    /// UDP packets forwarded
    pub udp_packets_forwarded: AtomicU64,
    /// Bytes to outbound
    pub bytes_to_outbound: AtomicU64,
    /// Bytes from outbound
    pub bytes_from_outbound: AtomicU64,
}

impl ShardStats {
    fn new(shard_id: usize) -> Self {
        Self {
            shard_id,
            packets_received: AtomicU64::new(0),
            packets_sent: AtomicU64::new(0),
            tcp_connections_accepted: AtomicU64::new(0),
            tcp_connections_failed: AtomicU64::new(0),
            udp_packets_forwarded: AtomicU64::new(0),
            bytes_to_outbound: AtomicU64::new(0),
            bytes_from_outbound: AtomicU64::new(0),
        }
    }

    fn reset(&self) {
        self.packets_received.store(0, Ordering::Relaxed);
        self.packets_sent.store(0, Ordering::Relaxed);
        self.tcp_connections_accepted.store(0, Ordering::Relaxed);
        self.tcp_connections_failed.store(0, Ordering::Relaxed);
        self.udp_packets_forwarded.store(0, Ordering::Relaxed);
        self.bytes_to_outbound.store(0, Ordering::Relaxed);
        self.bytes_from_outbound.store(0, Ordering::Relaxed);
    }
}

/// Snapshot of sharded bridge statistics
#[derive(Debug, Clone, serde::Serialize)]
pub struct ShardedBridgeStatsSnapshot {
    /// Number of shards
    pub shard_count: usize,
    /// Per-shard packet counts (for distribution analysis)
    pub per_shard_packets: Vec<u64>,
    /// Total packets received
    pub packets_received: u64,
    /// Total packets sent
    pub packets_sent: u64,
    /// TCP connections accepted
    pub tcp_connections_accepted: u64,
    /// TCP connections failed
    pub tcp_connections_failed: u64,
    /// UDP packets forwarded
    pub udp_packets_forwarded: u64,
    /// Bytes to outbound
    pub bytes_to_outbound: u64,
    /// Bytes from outbound
    pub bytes_from_outbound: u64,
    /// Reply backpressure events
    pub reply_backpressure: u64,
    /// Reply drops
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
    /// Connections re-routed based on domain rules (SNI/FakeDNS override)
    pub domain_reroutes: u64,
}

impl ShardedBridgeStatsSnapshot {
    /// Calculate distribution skew (standard deviation of per-shard packets)
    ///
    /// Lower values indicate more even distribution.
    pub fn distribution_skew(&self) -> f64 {
        if self.per_shard_packets.is_empty() {
            return 0.0;
        }
        let mean = self.packets_received as f64 / self.shard_count as f64;
        let variance: f64 = self
            .per_shard_packets
            .iter()
            .map(|&count| {
                let diff = count as f64 - mean;
                diff * diff
            })
            .sum::<f64>()
            / self.shard_count as f64;
        variance.sqrt()
    }
}

/// Individual shard state
struct IpStackShard {
    /// Shard identifier (kept for debugging, prefixed with _ to suppress warning)
    #[allow(dead_code)]
    id: usize,
    /// Channel to inject packets into this shard
    packet_tx: mpsc::Sender<BytesMut>,
    /// Accept loop task handle
    accept_task: Option<JoinHandle<()>>,
    /// Reply routing task handle
    reply_task: Option<JoinHandle<()>>,
}

/// Sharded IpStack bridge for parallel packet processing
///
/// Distributes packets across N ipstack instances using 5-tuple hashing.
/// All packets from the same connection are guaranteed to go to the same shard,
/// ensuring correct TCP sequencing.
///
/// # Thread Safety
///
/// The bridge is designed for concurrent access:
/// - Statistics use atomic counters
/// - Session tracker is shared across all shards (DashMap is lock-free)
/// - Packet channels use tokio::mpsc for async communication
pub struct ShardedIpStackBridge {
    /// Number of shards
    shard_count: usize,
    /// Individual shards
    shards: Vec<IpStackShard>,
    /// Shared session tracker (for reply routing across all shards)
    session_tracker: Arc<SessionTracker>,
    /// Merged reply channel receiver (all shards send here)
    reply_rx: Option<mpsc::Receiver<(BytesMut, [u8; 32])>>,
    /// Reply channel sender (cloned to each shard)
    reply_tx: mpsc::Sender<(BytesMut, [u8; 32])>,
    /// Running flag
    running: Arc<AtomicBool>,
    /// Aggregated statistics
    stats: Arc<ShardedBridgeStats>,
    /// Periodic cleanup task handle
    cleanup_task: Option<JoinHandle<()>>,
    /// Packet receivers for each shard (taken during start())
    packet_rxs: Option<Vec<mpsc::Receiver<BytesMut>>>,
    /// Outbound manager for routing decisions
    outbound_manager: Option<Arc<OutboundManager>>,
    /// Rule engine for domain-based routing decisions (SNI/FakeDNS)
    rule_engine: Option<Arc<RuleEngine>>,
    /// FakeDNS manager for domain-based routing (shared across all shards)
    #[cfg(feature = "fakedns")]
    fakedns_manager: Option<Arc<FakeDnsManager>>,
}

impl ShardedIpStackBridge {
    /// Create a new sharded bridge with specified shard count
    ///
    /// # Arguments
    ///
    /// * `shard_count` - Number of shards (ipstack instances) to create
    ///
    /// # Panics
    ///
    /// Panics if shard_count is 0.
    pub fn new(shard_count: usize) -> Self {
        assert!(shard_count > 0, "shard_count must be at least 1");

        let (reply_tx, reply_rx) = mpsc::channel::<(BytesMut, [u8; 32])>(REPLY_CHANNEL_SIZE);
        let session_tracker = Arc::new(SessionTracker::new());
        let stats = Arc::new(ShardedBridgeStats::new(shard_count));

        // Create shards with their packet channels
        // The channels are kept open until start() creates the ipstack instances
        let mut shards = Vec::with_capacity(shard_count);
        let mut packet_rxs = Vec::with_capacity(shard_count);
        for id in 0..shard_count {
            let (packet_tx, packet_rx) = mpsc::channel(PACKET_CHANNEL_SIZE);
            packet_rxs.push(packet_rx);
            shards.push(IpStackShard {
                id,
                packet_tx,
                accept_task: None,
                reply_task: None,
            });
        }

        Self {
            shard_count,
            shards,
            session_tracker,
            reply_rx: Some(reply_rx),
            reply_tx,
            running: Arc::new(AtomicBool::new(false)),
            stats,
            cleanup_task: None,
            packet_rxs: Some(packet_rxs),
            outbound_manager: None,
            rule_engine: None,
            #[cfg(feature = "fakedns")]
            fakedns_manager: None,
        }
    }

    /// Set the outbound manager for routing decisions
    ///
    /// Must be called before `start()` to enable outbound routing.
    /// If not set, all connections will use direct TCP connection.
    pub fn set_outbound_manager(&mut self, manager: Arc<OutboundManager>) {
        self.outbound_manager = Some(manager);
    }

    /// Set the rule engine for domain-based routing decisions
    ///
    /// When set, connections with resolved domains (from SNI/FakeDNS)
    /// will be routed based on domain rules instead of IP-only rules.
    /// This enables features like domain-based routing for encrypted traffic.
    pub fn set_rule_engine(&mut self, engine: Arc<RuleEngine>) {
        self.rule_engine = Some(engine);
    }

    /// Get the rule engine reference
    pub fn rule_engine(&self) -> Option<&Arc<RuleEngine>> {
        self.rule_engine.as_ref()
    }

    /// Set the FakeDNS manager for DNS hijacking
    ///
    /// When set, DNS queries (port 53) will be intercepted and resolved
    /// using FakeDNS, enabling domain-based routing.
    /// The manager is shared across all shards.
    #[cfg(feature = "fakedns")]
    pub fn set_fakedns_manager(&mut self, manager: Arc<FakeDnsManager>) {
        self.fakedns_manager = Some(manager);
    }

    /// Get the FakeDNS manager reference
    #[cfg(feature = "fakedns")]
    pub fn fakedns_manager(&self) -> Option<&Arc<FakeDnsManager>> {
        self.fakedns_manager.as_ref()
    }

    /// Create a new sharded bridge with default shard count
    ///
    /// Uses `configured_shard_count()` to determine the number of shards,
    /// which defaults to cores/2 clamped to [2, 8], but can be overridden
    /// by the `IPSTACK_SHARDS` environment variable.
    pub fn new_default() -> Self {
        Self::new(configured_shard_count())
    }

    /// Get the number of shards
    #[inline]
    pub fn shard_count(&self) -> usize {
        self.shard_count
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
    /// by ipstack. The packet is routed to the appropriate shard based on
    /// its 5-tuple hash.
    ///
    /// # Arguments
    ///
    /// * `packet` - The IP packet (IPv4 or IPv6)
    /// * `peer_key` - The WireGuard peer's public key (for routing replies)
    /// * `peer_endpoint` - The WireGuard peer's endpoint (IP:port) for reply routing
    ///
    /// # Errors
    ///
    /// Returns an error if the packet channel is closed or session limits are exceeded.
    pub async fn inject_packet(
        &self,
        packet: BytesMut,
        peer_key: [u8; 32],
        peer_endpoint: SocketAddr,
        outbound_tag: &str,
    ) -> anyhow::Result<()> {
        self.stats.packets_received.fetch_add(1, Ordering::Relaxed);

        // Parse the packet to extract 5-tuple for session tracking and shard selection
        let five_tuple = Self::parse_packet_five_tuple(&packet);

        // Register with session tracker for reply routing (forward-only, no reverse index)
        // Session is registered BEFORE send to ensure reply routing works immediately
        // If registration fails due to session limits, drop the packet to prevent sending
        // packets that we can't route replies for
        // The outbound_tag is stored in the session for later use by handle_tcp_connection
        if let Some(ref ft) = five_tuple {
            if self
                .session_tracker
                .register_forward_only(peer_key, peer_endpoint, ft.clone(), outbound_tag.to_string())
                .is_none()
            {
                warn!("Session limit reached, dropping packet");
                return Err(anyhow::anyhow!("session limit reached"));
            }
        }

        // Select shard based on 5-tuple hash
        let shard_idx = self.select_shard(&packet, &five_tuple);
        self.stats.per_shard_stats[shard_idx]
            .packets_received
            .fetch_add(1, Ordering::Relaxed);

        // Try to send the packet to the selected shard
        match self.shards[shard_idx].packet_tx.send(packet).await {
            Ok(()) => Ok(()),
            Err(_) => {
                // Clean up session on send failure to prevent leak
                if let Some(ref ft) = five_tuple {
                    self.session_tracker.remove(ft);
                }
                Err(anyhow::anyhow!("packet channel closed for shard {}", shard_idx))
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
    /// * `outbound_tag` - The outbound tag for routing (e.g., "direct", "vless-xxx")
    ///
    /// # Returns
    ///
    /// `true` if the packet was successfully queued, `false` if the channel is full,
    /// closed, or session limits are exceeded.
    pub fn try_inject_packet(
        &self,
        packet: BytesMut,
        peer_key: [u8; 32],
        peer_endpoint: SocketAddr,
        outbound_tag: &str,
    ) -> bool {
        self.stats.packets_received.fetch_add(1, Ordering::Relaxed);

        // Parse the packet to extract 5-tuple for session tracking and shard selection
        let five_tuple = Self::parse_packet_five_tuple(&packet);

        // Register with session tracker for reply routing (forward-only, no reverse index)
        // If registration fails due to session limits, drop the packet to prevent sending
        // packets that we can't route replies for
        // The outbound_tag is stored in the session for later use by handle_tcp_connection
        if let Some(ref ft) = five_tuple {
            if self
                .session_tracker
                .register_forward_only(peer_key, peer_endpoint, ft.clone(), outbound_tag.to_string())
                .is_none()
            {
                warn!("Session limit reached, dropping packet");
                return false;
            }
        }

        // Select shard based on 5-tuple hash
        let shard_idx = self.select_shard(&packet, &five_tuple);
        self.stats.per_shard_stats[shard_idx]
            .packets_received
            .fetch_add(1, Ordering::Relaxed);

        // Try to send the packet to the selected shard
        if self.shards[shard_idx].packet_tx.try_send(packet).is_ok() {
            true
        } else {
            // Clean up session on send failure to prevent leak
            if let Some(ref ft) = five_tuple {
                self.session_tracker.remove(ft);
            }
            false
        }
    }

    /// Select a shard based on 5-tuple hash
    ///
    /// Uses consistent hashing to ensure all packets from the same connection
    /// go to the same shard, which is essential for TCP sequencing.
    fn select_shard(&self, packet: &[u8], five_tuple: &Option<FiveTuple>) -> usize {
        if let Some(ref ft) = five_tuple {
            let mut hasher = AHasher::default();
            ft.src_addr.hash(&mut hasher);
            ft.dst_addr.hash(&mut hasher);
            ft.protocol.hash(&mut hasher);
            (hasher.finish() as usize) % self.shard_count
        } else {
            // Fallback for malformed packets: hash the first 40 bytes
            let mut hasher = AHasher::default();
            let len = packet.len().min(40);
            packet[..len].hash(&mut hasher);
            (hasher.finish() as usize) % self.shard_count
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

    /// Start the sharded bridge
    ///
    /// This spawns all ipstack instances and their associated tasks.
    ///
    /// # Errors
    ///
    /// Returns an error if the bridge is already running or if packet_rxs was already taken.
    pub async fn start(&mut self) -> anyhow::Result<()> {
        if self.running.swap(true, Ordering::SeqCst) {
            return Err(anyhow::anyhow!("sharded bridge already running"));
        }

        // Take the packet receivers
        let packet_rxs = self
            .packet_rxs
            .take()
            .ok_or_else(|| anyhow::anyhow!("packet_rxs already taken (bridge was already started)"))?;

        info!(
            shard_count = self.shard_count,
            "ShardedIpStackBridge starting..."
        );

        // Start tasks for each shard
        for (shard_id, packet_rx) in packet_rxs.into_iter().enumerate() {
            // Create the PacketChannel pair for this shard's ipstack
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

            // Create the ipstack instance for this shard
            let ip_stack = ipstack::IpStack::new(ipstack_config, packet_channel);

            // Spawn task to forward packets from the shard channel to ipstack
            let running = Arc::clone(&self.running);
            let shard_stats = Arc::clone(&self.stats.per_shard_stats[shard_id]);
            tokio::spawn(Self::packet_forwarder_task(
                shard_id,
                packet_rx,
                ipstack_packet_tx,
                running,
                shard_stats,
            ));

            // Spawn task to route reply packets from ipstack to the shared reply channel
            let reply_tx = self.reply_tx.clone();
            let session_tracker = Arc::clone(&self.session_tracker);
            let running = Arc::clone(&self.running);
            let shard_stats = Arc::clone(&self.stats.per_shard_stats[shard_id]);
            let global_stats = Arc::clone(&self.stats);
            let reply_task = tokio::spawn(Self::reply_router_task(
                shard_id,
                ipstack_packet_rx,
                reply_tx,
                session_tracker,
                running,
                shard_stats,
                global_stats,
            ));

            // Spawn the accept loop task for this shard
            let running = Arc::clone(&self.running);
            let shard_stats = Arc::clone(&self.stats.per_shard_stats[shard_id]);
            let global_stats = Arc::clone(&self.stats);
            let session_tracker = Arc::clone(&self.session_tracker);
            let outbound_manager = self.outbound_manager.clone();
            let rule_engine = self.rule_engine.clone();
            #[cfg(feature = "fakedns")]
            let fakedns_manager = self.fakedns_manager.clone();
            let accept_task = tokio::spawn(Self::accept_loop_task(
                shard_id,
                ip_stack,
                running,
                shard_stats,
                global_stats,
                session_tracker,
                outbound_manager,
                rule_engine,
                #[cfg(feature = "fakedns")]
                fakedns_manager,
            ));

            // Update shard with task handles
            self.shards[shard_id].accept_task = Some(accept_task);
            self.shards[shard_id].reply_task = Some(reply_task);
        }

        // Spawn the periodic cleanup task (shared across all shards)
        let running = Arc::clone(&self.running);
        let session_tracker = Arc::clone(&self.session_tracker);
        let cleanup_task = tokio::spawn(Self::session_cleanup_task(running, session_tracker));
        self.cleanup_task = Some(cleanup_task);

        info!(
            shard_count = self.shard_count,
            "ShardedIpStackBridge started successfully"
        );
        Ok(())
    }

    /// Task that forwards packets from the shard channel to ipstack
    async fn packet_forwarder_task(
        shard_id: usize,
        mut packet_rx: mpsc::Receiver<BytesMut>,
        ipstack_tx: mpsc::Sender<BytesMut>,
        running: Arc<AtomicBool>,
        _stats: Arc<ShardStats>,
    ) {
        debug!(shard_id, "Packet forwarder task started");

        while running.load(Ordering::SeqCst) {
            match packet_rx.recv().await {
                Some(packet) => {
                    trace!(
                        shard_id,
                        len = packet.len(),
                        "Forwarding packet to ipstack"
                    );
                    if let Err(e) = ipstack_tx.send(packet).await {
                        warn!(shard_id, error = %e, "Failed to send packet to ipstack");
                        break;
                    }
                }
                None => {
                    debug!(shard_id, "Packet channel closed, stopping forwarder");
                    break;
                }
            }
        }

        debug!(shard_id, "Packet forwarder task stopped");
    }

    /// Task that routes reply packets from ipstack to the shared reply channel
    async fn reply_router_task(
        shard_id: usize,
        mut ipstack_rx: mpsc::Receiver<BytesMut>,
        reply_tx: mpsc::Sender<(BytesMut, [u8; 32])>,
        session_tracker: Arc<SessionTracker>,
        running: Arc<AtomicBool>,
        shard_stats: Arc<ShardStats>,
        global_stats: Arc<ShardedBridgeStats>,
    ) {
        use std::time::Duration;

        debug!(shard_id, "Reply router task started");

        while running.load(Ordering::SeqCst) {
            match ipstack_rx.recv().await {
                Some(packet) => {
                    shard_stats.packets_sent.fetch_add(1, Ordering::Relaxed);
                    global_stats.packets_sent.fetch_add(1, Ordering::Relaxed);

                    // Parse the reply packet to find the reverse 5-tuple
                    if let Some(five_tuple) = Self::parse_packet_five_tuple(&packet) {
                        // For reply packets, we need to look up the reverse tuple
                        // (dst becomes src, src becomes dst)
                        let reverse_tuple = five_tuple.reverse();

                        if let Some(session) = session_tracker.lookup(&reverse_tuple) {
                            trace!(
                                shard_id,
                                len = packet.len(),
                                peer = hex::encode(&session.peer_key[..8]),
                                "Routing reply to peer"
                            );

                            // Fast path: try non-blocking send first
                            match reply_tx.try_send((packet.clone(), session.peer_key)) {
                                Ok(()) => { /* success */ }
                                Err(mpsc::error::TrySendError::Full(_)) => {
                                    // Channel full - record backpressure event
                                    global_stats
                                        .reply_backpressure
                                        .fetch_add(1, Ordering::Relaxed);

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
                                            global_stats.reply_drops.fetch_add(1, Ordering::Relaxed);
                                            debug!(
                                                shard_id,
                                                "Reply channel timeout, packet dropped (TCP will retransmit)"
                                            );
                                        }
                                    }
                                }
                                Err(mpsc::error::TrySendError::Closed(_)) => break,
                            }
                        } else {
                            trace!(
                                shard_id,
                                src = %five_tuple.src_addr,
                                dst = %five_tuple.dst_addr,
                                "No session found for reply packet"
                            );
                        }
                    } else {
                        trace!(shard_id, "Could not parse reply packet 5-tuple");
                    }
                }
                None => {
                    debug!(shard_id, "ipstack output channel closed, stopping reply router");
                    break;
                }
            }
        }

        debug!(shard_id, "Reply router task stopped");
    }

    /// Accept loop task that handles incoming connections from a shard's ipstack
    async fn accept_loop_task(
        shard_id: usize,
        mut ip_stack: ipstack::IpStack,
        running: Arc<AtomicBool>,
        shard_stats: Arc<ShardStats>,
        global_stats: Arc<ShardedBridgeStats>,
        session_tracker: Arc<SessionTracker>,
        outbound_manager: Option<Arc<OutboundManager>>,
        rule_engine: Option<Arc<RuleEngine>>,
        #[cfg(feature = "fakedns")] fakedns_manager: Option<Arc<FakeDnsManager>>,
    ) {
        debug!(shard_id, "Accept loop task started");

        while running.load(Ordering::SeqCst) {
            match ip_stack.accept().await {
                Ok(stream) => {
                    Self::handle_stream(
                        shard_id,
                        stream,
                        Arc::clone(&shard_stats),
                        Arc::clone(&global_stats),
                        Arc::clone(&session_tracker),
                        outbound_manager.clone(),
                        rule_engine.clone(),
                        #[cfg(feature = "fakedns")]
                        fakedns_manager.clone(),
                    );
                }
                Err(e) => {
                    if !running.load(Ordering::SeqCst) {
                        break;
                    }
                    warn!(shard_id, error = ?e, "ipstack accept error");
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            }
        }

        debug!(shard_id, "Accept loop task stopped");
    }

    /// Handle a stream from ipstack
    fn handle_stream(
        shard_id: usize,
        stream: ipstack::IpStackStream,
        shard_stats: Arc<ShardStats>,
        global_stats: Arc<ShardedBridgeStats>,
        session_tracker: Arc<SessionTracker>,
        outbound_manager: Option<Arc<OutboundManager>>,
        rule_engine: Option<Arc<RuleEngine>>,
        #[cfg(feature = "fakedns")] fakedns_manager: Option<Arc<FakeDnsManager>>,
    ) {
        match stream {
            ipstack::IpStackStream::Tcp(tcp_stream) => {
                let local_addr = tcp_stream.local_addr();
                let peer_addr = tcp_stream.peer_addr();

                debug!(
                    shard_id,
                    local = %local_addr,
                    peer = %peer_addr,
                    "TCP connection accepted"
                );
                shard_stats
                    .tcp_connections_accepted
                    .fetch_add(1, Ordering::Relaxed);
                global_stats
                    .tcp_connections_accepted
                    .fetch_add(1, Ordering::Relaxed);

                tokio::spawn(Self::handle_tcp_connection(
                    shard_id,
                    tcp_stream,
                    local_addr,
                    peer_addr,
                    shard_stats,
                    global_stats,
                    session_tracker,
                    outbound_manager,
                    rule_engine,
                    #[cfg(feature = "fakedns")]
                    fakedns_manager,
                ));
            }
            ipstack::IpStackStream::Udp(udp_stream) => {
                let local_addr = udp_stream.local_addr();
                let peer_addr = udp_stream.peer_addr();

                debug!(
                    shard_id,
                    local = %local_addr,
                    peer = %peer_addr,
                    "UDP stream accepted"
                );
                shard_stats
                    .udp_packets_forwarded
                    .fetch_add(1, Ordering::Relaxed);
                global_stats
                    .udp_packets_forwarded
                    .fetch_add(1, Ordering::Relaxed);

                tokio::spawn(Self::handle_udp_stream(
                    shard_id,
                    udp_stream,
                    local_addr,
                    peer_addr,
                    shard_stats,
                    global_stats,
                    session_tracker,
                    outbound_manager,
                    #[cfg(feature = "fakedns")]
                    fakedns_manager,
                ));
            }
            ipstack::IpStackStream::UnknownTransport(unknown) => {
                trace!(
                    shard_id,
                    src = %unknown.src_addr(),
                    dst = %unknown.dst_addr(),
                    "Unknown transport packet"
                );
            }
            ipstack::IpStackStream::UnknownNetwork(packet) => {
                trace!(shard_id, len = packet.len(), "Unknown network packet");
            }
        }
    }

    /// Handle a TCP connection from ipstack
    ///
    /// Routes the connection through the appropriate outbound based on:
    /// 1. Domain-based rules (if domain was resolved via SNI/FakeDNS and rule_engine is set)
    /// 2. IP-based rules from session tracker (fallback)
    async fn handle_tcp_connection(
        shard_id: usize,
        tcp_stream: ipstack::IpStackTcpStream,
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
        shard_stats: Arc<ShardStats>,
        global_stats: Arc<ShardedBridgeStats>,
        session_tracker: Arc<SessionTracker>,
        outbound_manager: Option<Arc<OutboundManager>>,
        rule_engine: Option<Arc<RuleEngine>>,
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
                        global_stats.dns_queries_hijacked.fetch_add(1, Ordering::Relaxed);
                        trace!(shard_id, "TCP DNS query hijacked via FakeDNS");
                    }
                    Err(e) => {
                        warn!(shard_id, error = %e, "TCP DNS hijack failed");
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
                global_stats
                    .fakedns_reverse_hits
                    .fetch_add(1, Ordering::Relaxed);
            }
            DomainSource::TlsSni => {
                global_stats
                    .sni_extractions
                    .fetch_add(1, Ordering::Relaxed);
            }
            DomainSource::HttpHost => {
                global_stats
                    .http_host_extractions
                    .fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }

        // Log domain resolution result
        #[cfg(any(feature = "sni-sniffing", feature = "fakedns"))]
        debug!(
            shard_id,
            local = %local_addr,
            peer = %peer_addr,
            domain = ?domain_resolution.domain,
            source = %domain_resolution.source,
            "TCP connection with domain resolution"
        );

        // Look up the session to get the initial outbound_tag (from IP-based routing)
        let five_tuple = FiveTuple::tcp(local_addr, peer_addr);
        let ip_based_tag = session_tracker
            .lookup(&five_tuple)
            .map(|s| s.outbound_tag.clone())
            .unwrap_or_else(|| "direct".to_string());

        // Domain-based re-routing: if we have a domain and rule_engine, use domain rules
        // This allows SNI/FakeDNS resolved domains to override IP-based routing decisions
        #[cfg(any(feature = "sni-sniffing", feature = "fakedns"))]
        let (outbound_tag, routing_source) = if let Some(domain) = domain_resolution.domain.as_ref()
        {
            if let Some(ref engine) = rule_engine {
                // Build ConnectionInfo with the resolved domain
                let conn_info = ConnectionInfo {
                    domain: Some(domain.clone()),
                    dest_ip: Some(peer_addr.ip()),
                    dest_port: peer_addr.port(),
                    source_ip: Some(local_addr.ip()),
                    protocol: "tcp",
                    sniffed_protocol: match domain_resolution.source {
                        DomainSource::TlsSni => Some("tls"),
                        DomainSource::HttpHost => Some("http"),
                        _ => None,
                    },
                };

                // Match using domain rules
                let match_result = engine.match_connection(&conn_info);

                // If domain rule matched and gave a different outbound, use it
                if match_result.matched_rule.is_some() {
                    global_stats.domain_reroutes.fetch_add(1, Ordering::Relaxed);
                    debug!(
                        shard_id,
                        domain = %domain,
                        ip_tag = %ip_based_tag,
                        domain_tag = %match_result.outbound,
                        rule = ?match_result.matched_rule,
                        "Domain-based routing override"
                    );
                    (match_result.outbound, "domain")
                } else {
                    // No domain rule matched, use IP-based tag
                    (ip_based_tag, "ip")
                }
            } else {
                // No rule_engine, use IP-based tag
                (ip_based_tag, "ip")
            }
        } else {
            // No domain resolved, use IP-based tag
            (ip_based_tag, "ip")
        };

        // For non-domain-routing builds, just use IP-based tag
        #[cfg(not(any(feature = "sni-sniffing", feature = "fakedns")))]
        let (outbound_tag, routing_source) = (ip_based_tag, "ip");

        // Log for non-domain-routing case
        #[cfg(not(any(feature = "sni-sniffing", feature = "fakedns")))]
        debug!(
            shard_id,
            local = %local_addr,
            peer = %peer_addr,
            outbound = %outbound_tag,
            "Handling TCP connection"
        );

        // Log outbound tag for domain-routing case
        #[cfg(any(feature = "sni-sniffing", feature = "fakedns"))]
        trace!(
            shard_id,
            local = %local_addr,
            peer = %peer_addr,
            outbound = %outbound_tag,
            routing_source = %routing_source,
            "TCP connection outbound selection"
        );

        // Handle block outbound
        if outbound_tag == "block" || outbound_tag == "adblock" {
            debug!(shard_id, local = %local_addr, peer = %peer_addr, "Blocking TCP connection");
            session_tracker.remove(&five_tuple);
            return;
        }

        let connect_timeout = tcp_connect_timeout();

        // Try to use OutboundManager if available and outbound_tag is not "direct"
        let outbound_stream: Option<OutboundStream> = if outbound_tag != "direct" {
            if let Some(ref manager) = outbound_manager {
                if let Some(outbound) = manager.get(&outbound_tag) {
                    match outbound.connect(peer_addr, connect_timeout).await {
                        Ok(conn) => {
                            debug!(
                                shard_id,
                                outbound = %outbound_tag,
                                peer = %peer_addr,
                                "Connected via outbound"
                            );
                            Some(conn.into_outbound_stream())
                        }
                        Err(e) => {
                            warn!(
                                shard_id,
                                outbound = %outbound_tag,
                                peer = %peer_addr,
                                error = %e,
                                "Failed to connect via outbound"
                            );
                            shard_stats.tcp_connections_failed.fetch_add(1, Ordering::Relaxed);
                            global_stats.tcp_connections_failed.fetch_add(1, Ordering::Relaxed);
                            session_tracker.remove(&five_tuple);
                            return;
                        }
                    }
                } else {
                    warn!(
                        shard_id,
                        outbound = %outbound_tag,
                        peer = %peer_addr,
                        "Outbound not found, falling back to direct"
                    );
                    None
                }
            } else {
                debug!(
                    shard_id,
                    peer = %peer_addr,
                    "OutboundManager not set, using direct connection"
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
                        warn!(shard_id, peer = %peer_addr, error = %e, "Failed to connect directly");
                        shard_stats.tcp_connections_failed.fetch_add(1, Ordering::Relaxed);
                        global_stats.tcp_connections_failed.fetch_add(1, Ordering::Relaxed);
                        session_tracker.remove(&five_tuple);
                        return;
                    }
                    Err(_) => {
                        warn!(shard_id, peer = %peer_addr, "Connection timeout");
                        shard_stats.tcp_connections_failed.fetch_add(1, Ordering::Relaxed);
                        global_stats.tcp_connections_failed.fetch_add(1, Ordering::Relaxed);
                        session_tracker.remove(&five_tuple);
                        return;
                    }
                };

                // Set TCP_NODELAY to reduce latency
                if let Err(e) = outbound.set_nodelay(true) {
                    debug!(shard_id, error = %e, "Failed to set TCP_NODELAY");
                }

                // Set larger socket buffer sizes
                {
                    use socket2::SockRef;
                    let sock_ref = SockRef::from(&outbound);
                    if let Err(e) = sock_ref.set_recv_buffer_size(TCP_SOCKET_BUFFER_SIZE) {
                        debug!(shard_id, error = %e, "Failed to set SO_RCVBUF");
                    }
                    if let Err(e) = sock_ref.set_send_buffer_size(TCP_SOCKET_BUFFER_SIZE) {
                        debug!(shard_id, error = %e, "Failed to set SO_SNDBUF");
                    }
                }

                debug!(shard_id, peer = %peer_addr, "Connected directly");
                OutboundStream::tcp(outbound)
            }
        };

        // Bridge the streams using copy_bidirectional_with_sizes
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
                shard_stats.bytes_to_outbound.fetch_add(to_outbound, Ordering::Relaxed);
                shard_stats.bytes_from_outbound.fetch_add(from_outbound, Ordering::Relaxed);
                global_stats.bytes_to_outbound.fetch_add(to_outbound, Ordering::Relaxed);
                global_stats.bytes_from_outbound.fetch_add(from_outbound, Ordering::Relaxed);
                debug!(
                    shard_id,
                    local = %local_addr,
                    peer = %peer_addr,
                    outbound = %outbound_tag,
                    sent = to_outbound,
                    recv = from_outbound,
                    "TCP connection completed"
                );
            }
            Err(e) => {
                debug!(
                    shard_id,
                    local = %local_addr,
                    peer = %peer_addr,
                    outbound = %outbound_tag,
                    error = %e,
                    "TCP connection error"
                );
            }
        }

        // Clean up session
        session_tracker.remove(&five_tuple);

        debug!(shard_id, local = %local_addr, peer = %peer_addr, "TCP connection closed");
    }

    /// Handle a UDP stream from ipstack
    ///
    /// Routes UDP traffic through the appropriate outbound based on
    /// the outbound_tag stored in the session tracker.
    async fn handle_udp_stream(
        shard_id: usize,
        mut udp_stream: ipstack::IpStackUdpStream,
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
        shard_stats: Arc<ShardStats>,
        global_stats: Arc<ShardedBridgeStats>,
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
                        global_stats.dns_queries_hijacked.fetch_add(1, Ordering::Relaxed);
                        trace!(shard_id, "UDP DNS query hijacked via FakeDNS");
                    }
                    Err(e) => {
                        warn!(shard_id, error = %e, "UDP DNS hijack failed");
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
                    global_stats
                        .fakedns_reverse_hits
                        .fetch_add(1, Ordering::Relaxed);
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
            shard_id,
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
            shard_id,
            local = %local_addr,
            peer = %peer_addr,
            outbound = %outbound_tag,
            "Handling UDP stream"
        );

        // Log outbound tag for fakedns case (already logged domain above)
        #[cfg(feature = "fakedns")]
        trace!(
            shard_id,
            local = %local_addr,
            peer = %peer_addr,
            outbound = %outbound_tag,
            "UDP stream outbound selection"
        );

        // Handle block outbound
        if outbound_tag == "block" || outbound_tag == "adblock" {
            debug!(shard_id, local = %local_addr, peer = %peer_addr, "Blocking UDP stream");
            session_tracker.remove(&five_tuple);
            return;
        }

        let connect_timeout = tcp_connect_timeout();

        // Try to use OutboundManager UDP if available and outbound_tag is not "direct"
        // For simplicity in sharded bridge, fall back to direct for UDP (OutboundManager UDP is complex)
        // TODO: Add full UDP outbound support similar to bridge.rs if needed

        // Direct UDP connection
        let outbound = match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
            Ok(socket) => socket,
            Err(e) => {
                warn!(shard_id, error = %e, "Failed to bind UDP socket");
                session_tracker.remove(&five_tuple);
                return;
            }
        };

        if let Err(e) = outbound.connect(peer_addr).await {
            warn!(shard_id, peer = %peer_addr, error = %e, "Failed to connect UDP socket");
            session_tracker.remove(&five_tuple);
            return;
        }

        debug!(shard_id, peer = %peer_addr, "UDP socket connected directly");

        let timeout = if peer_addr.port() == 53 {
            udp_dns_timeout()
        } else {
            udp_session_timeout()
        };

        let mut buf = vec![0u8; 65535];
        let mut recv_buf = vec![0u8; 65535];

        loop {
            tokio::select! {
                result = tokio::io::AsyncReadExt::read(&mut udp_stream, &mut buf) => {
                    match result {
                        Ok(0) => {
                            debug!(shard_id, "UDP stream closed by client");
                            break;
                        }
                        Ok(n) => {
                            trace!(shard_id, len = n, peer = %peer_addr, "UDP: client -> outbound");
                            shard_stats.bytes_to_outbound.fetch_add(n as u64, Ordering::Relaxed);
                            global_stats.bytes_to_outbound.fetch_add(n as u64, Ordering::Relaxed);
                            shard_stats.udp_packets_forwarded.fetch_add(1, Ordering::Relaxed);
                            global_stats.udp_packets_forwarded.fetch_add(1, Ordering::Relaxed);

                            if let Err(e) = outbound.send(&buf[..n]).await {
                                warn!(shard_id, error = %e, "UDP send error");
                                break;
                            }
                        }
                        Err(e) => {
                            debug!(shard_id, error = %e, "UDP read error");
                            break;
                        }
                    }
                }

                result = outbound.recv(&mut recv_buf) => {
                    match result {
                        Ok(n) => {
                            trace!(shard_id, len = n, peer = %peer_addr, "UDP: outbound -> client");
                            shard_stats.bytes_from_outbound.fetch_add(n as u64, Ordering::Relaxed);
                            global_stats.bytes_from_outbound.fetch_add(n as u64, Ordering::Relaxed);

                            if let Err(e) = tokio::io::AsyncWriteExt::write_all(&mut udp_stream, &recv_buf[..n]).await {
                                warn!(shard_id, error = %e, "UDP write error");
                                break;
                            }
                        }
                        Err(e) => {
                            debug!(shard_id, error = %e, "UDP recv error");
                            break;
                        }
                    }
                }

                _ = tokio::time::sleep(timeout) => {
                    debug!(shard_id, local = %local_addr, peer = %peer_addr, "UDP session timeout");
                    break;
                }
            }
        }

        // Clean up session
        session_tracker.remove(&five_tuple);

        debug!(shard_id, local = %local_addr, peer = %peer_addr, "UDP stream closed");
    }

    /// Periodic task to clean up idle sessions (shared across all shards)
    async fn session_cleanup_task(running: Arc<AtomicBool>, session_tracker: Arc<SessionTracker>) {
        debug!("Session cleanup task started (shared)");

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
                trace!(
                    active = session_tracker.total_sessions(),
                    "Cleanup cycle completed"
                );
            }
        }

        debug!("Session cleanup task stopped");
    }

    /// Stop the sharded bridge
    ///
    /// This signals all tasks to stop and waits for them to complete.
    pub async fn stop(&mut self) {
        if !self.running.swap(false, Ordering::SeqCst) {
            debug!("ShardedIpStackBridge already stopped");
            return;
        }

        info!(
            shard_count = self.shard_count,
            sessions = self.session_tracker.total_sessions(),
            stats = ?self.stats.snapshot(),
            "ShardedIpStackBridge stopping..."
        );

        // Stop cleanup task
        if let Some(task) = self.cleanup_task.take() {
            task.abort();
            let _ = task.await;
        }

        // Stop all shard tasks
        for shard in &mut self.shards {
            if let Some(task) = shard.accept_task.take() {
                task.abort();
                let _ = task.await;
            }
            if let Some(task) = shard.reply_task.take() {
                task.abort();
                let _ = task.await;
            }
        }

        info!("ShardedIpStackBridge stopped");
    }

    /// Check if bridge is running
    #[inline]
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Get statistics reference
    #[inline]
    pub fn stats(&self) -> &Arc<ShardedBridgeStats> {
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
    pub fn diagnostic_snapshot(&self) -> ShardedDiagnosticSnapshot {
        ShardedDiagnosticSnapshot {
            running: self.is_running(),
            shard_count: self.shard_count,
            active_sessions: self.active_sessions(),
            tcp_sessions: self.tcp_sessions(),
            udp_sessions: self.udp_sessions(),
            stats: self.stats.snapshot(),
        }
    }
}

impl Default for ShardedIpStackBridge {
    fn default() -> Self {
        Self::new_default()
    }
}

/// Diagnostic snapshot of the sharded bridge state
#[derive(Debug, Clone, serde::Serialize)]
pub struct ShardedDiagnosticSnapshot {
    /// Whether the bridge is running
    pub running: bool,
    /// Number of shards
    pub shard_count: usize,
    /// Total active sessions
    pub active_sessions: usize,
    /// Active TCP sessions
    pub tcp_sessions: usize,
    /// Active UDP sessions
    pub udp_sessions: usize,
    /// Statistics snapshot
    pub stats: ShardedBridgeStatsSnapshot,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_sharded_bridge_creation() {
        let bridge = ShardedIpStackBridge::new(4);
        assert_eq!(bridge.shard_count(), 4);
        assert!(!bridge.is_running());
        assert_eq!(bridge.active_sessions(), 0);
    }

    #[test]
    fn test_sharded_bridge_creation_default() {
        let bridge = ShardedIpStackBridge::new_default();
        assert!(bridge.shard_count() >= 2);
        assert!(bridge.shard_count() <= 8);
        assert!(!bridge.is_running());
    }

    #[test]
    #[should_panic(expected = "shard_count must be at least 1")]
    fn test_sharded_bridge_zero_shards_panics() {
        let _ = ShardedIpStackBridge::new(0);
    }

    #[test]
    fn test_shard_selection_consistency() {
        let bridge = ShardedIpStackBridge::new(4);

        // Create a test packet
        let packet = create_test_tcp_packet(
            Ipv4Addr::new(10, 25, 0, 2),
            12345,
            Ipv4Addr::new(93, 184, 216, 34),
            80,
        );
        let five_tuple = ShardedIpStackBridge::parse_packet_five_tuple(&packet);

        // Same packet should always go to the same shard
        let shard1 = bridge.select_shard(&packet, &five_tuple);
        let shard2 = bridge.select_shard(&packet, &five_tuple);
        let shard3 = bridge.select_shard(&packet, &five_tuple);

        assert_eq!(shard1, shard2);
        assert_eq!(shard2, shard3);
    }

    #[test]
    fn test_shard_selection_distribution() {
        let bridge = ShardedIpStackBridge::new(4);
        let mut shard_counts = [0u32; 4];

        // Generate many different 5-tuples and check distribution
        for src_port in 10000..10100 {
            for dst_port in [80, 443, 8080, 8443] {
                let packet = create_test_tcp_packet(
                    Ipv4Addr::new(10, 25, 0, 2),
                    src_port,
                    Ipv4Addr::new(93, 184, 216, 34),
                    dst_port,
                );
                let five_tuple = ShardedIpStackBridge::parse_packet_five_tuple(&packet);
                let shard = bridge.select_shard(&packet, &five_tuple);
                shard_counts[shard] += 1;
            }
        }

        // Each shard should have received some packets (distribution check)
        // With 400 total packets across 4 shards, each should have at least 50
        for (i, &count) in shard_counts.iter().enumerate() {
            assert!(
                count >= 50,
                "Shard {} only received {} packets, expected at least 50",
                i,
                count
            );
        }
    }

    #[test]
    fn test_same_connection_same_shard() {
        let bridge = ShardedIpStackBridge::new(8);

        // Different packets from the same connection should go to the same shard
        let src_ip = Ipv4Addr::new(10, 25, 0, 2);
        let dst_ip = Ipv4Addr::new(93, 184, 216, 34);
        let src_port = 12345u16;
        let dst_port = 443u16;

        // SYN packet
        let syn = create_test_tcp_packet(src_ip, src_port, dst_ip, dst_port);
        let syn_ft = ShardedIpStackBridge::parse_packet_five_tuple(&syn);
        let syn_shard = bridge.select_shard(&syn, &syn_ft);

        // Data packet (same 5-tuple)
        let data = create_test_tcp_packet(src_ip, src_port, dst_ip, dst_port);
        let data_ft = ShardedIpStackBridge::parse_packet_five_tuple(&data);
        let data_shard = bridge.select_shard(&data, &data_ft);

        assert_eq!(syn_shard, data_shard);
    }

    #[test]
    fn test_reverse_connection_different_shard_possible() {
        let bridge = ShardedIpStackBridge::new(8);

        // Forward direction
        let forward = create_test_tcp_packet(
            Ipv4Addr::new(10, 25, 0, 2),
            12345,
            Ipv4Addr::new(93, 184, 216, 34),
            80,
        );
        let forward_ft = ShardedIpStackBridge::parse_packet_five_tuple(&forward);

        // Reverse direction (reply packet)
        let reverse = create_test_tcp_packet(
            Ipv4Addr::new(93, 184, 216, 34),
            80,
            Ipv4Addr::new(10, 25, 0, 2),
            12345,
        );
        let reverse_ft = ShardedIpStackBridge::parse_packet_five_tuple(&reverse);

        // Note: Forward and reverse may or may not go to the same shard
        // This is by design - reply routing uses the session tracker
        let _forward_shard = bridge.select_shard(&forward, &forward_ft);
        let _reverse_shard = bridge.select_shard(&reverse, &reverse_ft);

        // Just verify both are valid shards
        assert!(bridge.select_shard(&forward, &forward_ft) < 8);
        assert!(bridge.select_shard(&reverse, &reverse_ft) < 8);
    }

    #[tokio::test]
    async fn test_take_reply_rx_once() {
        let mut bridge = ShardedIpStackBridge::new(2);
        let rx1 = bridge.take_reply_rx();
        assert!(rx1.is_some());
        let rx2 = bridge.take_reply_rx();
        assert!(rx2.is_none());
    }

    #[tokio::test]
    async fn test_inject_packet() {
        let bridge = ShardedIpStackBridge::new(2);
        let packet = create_test_tcp_packet(
            Ipv4Addr::new(10, 25, 0, 2),
            12345,
            Ipv4Addr::new(93, 184, 216, 34),
            80,
        );
        let peer_key = [0u8; 32];
        let peer_endpoint = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 51820);

        let result = bridge.inject_packet(BytesMut::from(&packet[..]), peer_key, peer_endpoint).await;
        assert!(result.is_ok());

        let stats = bridge.stats.snapshot();
        assert_eq!(stats.packets_received, 1);
        assert_eq!(bridge.session_tracker.total_sessions(), 1);
    }

    #[tokio::test]
    async fn test_try_inject_packet() {
        let bridge = ShardedIpStackBridge::new(2);
        let packet = create_test_tcp_packet(
            Ipv4Addr::new(10, 25, 0, 2),
            12345,
            Ipv4Addr::new(93, 184, 216, 34),
            80,
        );
        let peer_key = [0u8; 32];
        let peer_endpoint = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 51820);

        let success = bridge.try_inject_packet(BytesMut::from(&packet[..]), peer_key, peer_endpoint);
        assert!(success);

        let stats = bridge.stats.snapshot();
        assert_eq!(stats.packets_received, 1);
    }

    #[test]
    fn test_stats_aggregation() {
        let stats = ShardedBridgeStats::new(4);

        // Simulate activity on different shards
        stats.per_shard_stats[0]
            .packets_received
            .fetch_add(100, Ordering::Relaxed);
        stats.per_shard_stats[1]
            .packets_received
            .fetch_add(150, Ordering::Relaxed);
        stats.per_shard_stats[2]
            .packets_received
            .fetch_add(120, Ordering::Relaxed);
        stats.per_shard_stats[3]
            .packets_received
            .fetch_add(130, Ordering::Relaxed);

        // Update global stats
        stats.packets_received.store(500, Ordering::Relaxed);

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.shard_count, 4);
        assert_eq!(snapshot.per_shard_packets[0], 100);
        assert_eq!(snapshot.per_shard_packets[1], 150);
        assert_eq!(snapshot.per_shard_packets[2], 120);
        assert_eq!(snapshot.per_shard_packets[3], 130);
        assert_eq!(snapshot.packets_received, 500);
    }

    #[test]
    fn test_stats_distribution_skew() {
        // Even distribution
        let stats1 = ShardedBridgeStats::new(4);
        for shard in &stats1.per_shard_stats {
            shard.packets_received.store(100, Ordering::Relaxed);
        }
        stats1.packets_received.store(400, Ordering::Relaxed);
        let snapshot1 = stats1.snapshot();
        assert!((snapshot1.distribution_skew() - 0.0).abs() < 0.001);

        // Uneven distribution
        let stats2 = ShardedBridgeStats::new(4);
        stats2.per_shard_stats[0]
            .packets_received
            .store(0, Ordering::Relaxed);
        stats2.per_shard_stats[1]
            .packets_received
            .store(100, Ordering::Relaxed);
        stats2.per_shard_stats[2]
            .packets_received
            .store(200, Ordering::Relaxed);
        stats2.per_shard_stats[3]
            .packets_received
            .store(300, Ordering::Relaxed);
        stats2.packets_received.store(600, Ordering::Relaxed);
        let snapshot2 = stats2.snapshot();
        assert!(snapshot2.distribution_skew() > 100.0);
    }

    #[test]
    fn test_session_tracker_shared() {
        let bridge = ShardedIpStackBridge::new(4);
        let peer_key = [1u8; 32];

        // Register sessions that would hash to different shards
        let tuple1 = FiveTuple::tcp(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 25, 0, 2)), 12345),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 80),
        );
        let tuple2 = FiveTuple::tcp(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 25, 0, 3)), 12346),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 35)), 443),
        );
        let peer_endpoint = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 51820);

        // Register sessions through the shared tracker
        bridge
            .session_tracker
            .register_forward_only(peer_key, peer_endpoint, tuple1.clone());
        bridge
            .session_tracker
            .register_forward_only(peer_key, peer_endpoint, tuple2.clone());

        // Both should be visible from the shared tracker
        assert_eq!(bridge.session_tracker.total_sessions(), 2);
        assert!(bridge.session_tracker.lookup(&tuple1).is_some());
        assert!(bridge.session_tracker.lookup(&tuple2).is_some());
    }

    #[test]
    fn test_diagnostic_snapshot() {
        let bridge = ShardedIpStackBridge::new(3);
        let diag = bridge.diagnostic_snapshot();

        assert!(!diag.running);
        assert_eq!(diag.shard_count, 3);
        assert_eq!(diag.active_sessions, 0);
        assert_eq!(diag.tcp_sessions, 0);
        assert_eq!(diag.udp_sessions, 0);
    }

    #[test]
    fn test_stats_snapshot_serialization() {
        let snapshot = ShardedBridgeStatsSnapshot {
            shard_count: 4,
            per_shard_packets: vec![100, 110, 90, 100],
            packets_received: 400,
            packets_sent: 380,
            tcp_connections_accepted: 50,
            tcp_connections_failed: 2,
            udp_packets_forwarded: 100,
            bytes_to_outbound: 50000,
            bytes_from_outbound: 100000,
            reply_backpressure: 5,
            reply_drops: 1,
            dns_queries_hijacked: 25,
            fakedns_reverse_hits: 20,
            sni_extractions: 15,
            http_host_extractions: 5,
            domain_reroutes: 10,
        };

        let json = serde_json::to_string(&snapshot).unwrap();
        assert!(json.contains("shard_count"));
        assert!(json.contains("per_shard_packets"));
        assert!(json.contains("400"));
        assert!(json.contains("dns_queries_hijacked"));
        assert!(json.contains("fakedns_reverse_hits"));
        assert!(json.contains("sni_extractions"));
        assert!(json.contains("http_host_extractions"));
        assert!(json.contains("domain_reroutes"));
    }

    #[test]
    fn test_parse_ipv4_tcp_packet() {
        let packet = create_test_tcp_packet(
            Ipv4Addr::new(10, 25, 0, 2),
            12345,
            Ipv4Addr::new(93, 184, 216, 34),
            80,
        );

        let five_tuple = ShardedIpStackBridge::parse_packet_five_tuple(&packet);
        assert!(five_tuple.is_some());

        let ft = five_tuple.unwrap();
        assert!(ft.is_tcp());
        assert_eq!(ft.src_addr.port(), 12345);
        assert_eq!(ft.dst_addr.port(), 80);
    }

    #[test]
    fn test_parse_ipv4_udp_packet() {
        let packet = create_test_udp_packet(
            Ipv4Addr::new(10, 25, 0, 2),
            54321,
            Ipv4Addr::new(8, 8, 8, 8),
            53,
        );

        let five_tuple = ShardedIpStackBridge::parse_packet_five_tuple(&packet);
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
        assert!(ShardedIpStackBridge::parse_packet_five_tuple(&packet).is_none());

        // Empty
        assert!(ShardedIpStackBridge::parse_packet_five_tuple(&[]).is_none());

        // Invalid version
        let packet = vec![0x00; 40];
        assert!(ShardedIpStackBridge::parse_packet_five_tuple(&packet).is_none());
    }

    #[test]
    fn test_malformed_packet_fallback_shard() {
        let bridge = ShardedIpStackBridge::new(4);

        // Malformed packet (invalid version)
        let packet = vec![0x30; 40]; // Version 3 is invalid
        let five_tuple = ShardedIpStackBridge::parse_packet_five_tuple(&packet);
        assert!(five_tuple.is_none());

        // Should still get a valid shard via fallback
        let shard = bridge.select_shard(&packet, &five_tuple);
        assert!(shard < 4);
    }

    // Helper function to create a test TCP packet
    fn create_test_tcp_packet(
        src_ip: Ipv4Addr,
        src_port: u16,
        dst_ip: Ipv4Addr,
        dst_port: u16,
    ) -> Vec<u8> {
        let mut packet = vec![0u8; 40];
        // IPv4 header
        packet[0] = 0x45; // Version 4, IHL 5
        packet[9] = 6; // Protocol: TCP
        packet[12..16].copy_from_slice(&src_ip.octets());
        packet[16..20].copy_from_slice(&dst_ip.octets());
        // TCP header
        packet[20..22].copy_from_slice(&src_port.to_be_bytes());
        packet[22..24].copy_from_slice(&dst_port.to_be_bytes());
        packet
    }

    // Helper function to create a test UDP packet
    fn create_test_udp_packet(
        src_ip: Ipv4Addr,
        src_port: u16,
        dst_ip: Ipv4Addr,
        dst_port: u16,
    ) -> Vec<u8> {
        let mut packet = vec![0u8; 28];
        // IPv4 header
        packet[0] = 0x45; // Version 4, IHL 5
        packet[9] = 17; // Protocol: UDP
        packet[12..16].copy_from_slice(&src_ip.octets());
        packet[16..20].copy_from_slice(&dst_ip.octets());
        // UDP header
        packet[20..22].copy_from_slice(&src_port.to_be_bytes());
        packet[22..24].copy_from_slice(&dst_port.to_be_bytes());
        packet
    }

    // Helper function to create a test IPv6 TCP packet without extension headers
    fn create_test_ipv6_tcp_packet(src_port: u16, dst_port: u16) -> Vec<u8> {
        let mut packet = vec![0u8; 60]; // 40 byte IPv6 header + 20 byte TCP header
        // IPv6 header
        packet[0] = 0x60; // Version 6
        packet[6] = 6; // Next Header: TCP
        packet[7] = 64; // Hop Limit
        // Source IP: 2001:db8::1 (simplified)
        packet[8..24].copy_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ]);
        // Dest IP: 2001:db8::2
        packet[24..40].copy_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x02,
        ]);
        // TCP header
        packet[40..42].copy_from_slice(&src_port.to_be_bytes());
        packet[42..44].copy_from_slice(&dst_port.to_be_bytes());
        packet
    }

    // Helper function to create IPv6 TCP packet with Hop-by-Hop extension header
    fn create_test_ipv6_tcp_with_hop_by_hop(src_port: u16, dst_port: u16) -> Vec<u8> {
        let mut packet = vec![0u8; 68]; // 40 byte IPv6 + 8 byte ext header + 20 byte TCP
        // IPv6 header
        packet[0] = 0x60; // Version 6
        packet[6] = 0; // Next Header: Hop-by-Hop Options
        packet[7] = 64; // Hop Limit
        // Source IP: 2001:db8::1
        packet[8..24].copy_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ]);
        // Dest IP: 2001:db8::2
        packet[24..40].copy_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x02,
        ]);
        // Hop-by-Hop Options header (8 bytes min)
        packet[40] = 6; // Next Header: TCP
        packet[41] = 0; // Hdr Ext Len: 0 (means 8 bytes total)
        // Padding to fill 8 bytes
        packet[42..48].copy_from_slice(&[0x01, 0x04, 0x00, 0x00, 0x00, 0x00]); // PadN option
        // TCP header
        packet[48..50].copy_from_slice(&src_port.to_be_bytes());
        packet[50..52].copy_from_slice(&dst_port.to_be_bytes());
        packet
    }

    // Helper function to create IPv6 TCP packet with Fragment extension header
    fn create_test_ipv6_tcp_with_fragment(src_port: u16, dst_port: u16) -> Vec<u8> {
        let mut packet = vec![0u8; 68]; // 40 byte IPv6 + 8 byte fragment header + 20 byte TCP
        // IPv6 header
        packet[0] = 0x60; // Version 6
        packet[6] = 44; // Next Header: Fragment
        packet[7] = 64; // Hop Limit
        // Source IP: 2001:db8::1
        packet[8..24].copy_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ]);
        // Dest IP: 2001:db8::2
        packet[24..40].copy_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x02,
        ]);
        // Fragment header (always 8 bytes)
        packet[40] = 6; // Next Header: TCP
        packet[41] = 0; // Reserved
        packet[42..44].copy_from_slice(&[0x00, 0x00]); // Fragment Offset + M flag
        packet[44..48].copy_from_slice(&[0x00, 0x00, 0x00, 0x01]); // Identification
        // TCP header
        packet[48..50].copy_from_slice(&src_port.to_be_bytes());
        packet[50..52].copy_from_slice(&dst_port.to_be_bytes());
        packet
    }

    #[test]
    fn test_parse_ipv6_tcp_no_extension() {
        let packet = create_test_ipv6_tcp_packet(12345, 443);
        let five_tuple = ShardedIpStackBridge::parse_packet_five_tuple(&packet);
        assert!(five_tuple.is_some());

        let ft = five_tuple.unwrap();
        assert!(ft.is_tcp());
        assert_eq!(ft.src_addr.port(), 12345);
        assert_eq!(ft.dst_addr.port(), 443);
    }

    #[test]
    fn test_parse_ipv6_tcp_with_hop_by_hop() {
        let packet = create_test_ipv6_tcp_with_hop_by_hop(54321, 80);
        let five_tuple = ShardedIpStackBridge::parse_packet_five_tuple(&packet);
        assert!(five_tuple.is_some());

        let ft = five_tuple.unwrap();
        assert!(ft.is_tcp());
        assert_eq!(ft.src_addr.port(), 54321);
        assert_eq!(ft.dst_addr.port(), 80);
    }

    #[test]
    fn test_parse_ipv6_tcp_with_fragment() {
        let packet = create_test_ipv6_tcp_with_fragment(11111, 8080);
        let five_tuple = ShardedIpStackBridge::parse_packet_five_tuple(&packet);
        assert!(five_tuple.is_some());

        let ft = five_tuple.unwrap();
        assert!(ft.is_tcp());
        assert_eq!(ft.src_addr.port(), 11111);
        assert_eq!(ft.dst_addr.port(), 8080);
    }

    #[test]
    fn test_parse_ipv6_no_next_header() {
        // IPv6 packet with No Next Header (59)
        let mut packet = vec![0u8; 44];
        packet[0] = 0x60; // Version 6
        packet[6] = 59; // Next Header: No Next Header
        // Fill addresses
        packet[8..24].copy_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ]);
        packet[24..40].copy_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x02,
        ]);

        // Should return None for unsupported protocol
        let five_tuple = ShardedIpStackBridge::parse_packet_five_tuple(&packet);
        assert!(five_tuple.is_none());
    }

    #[test]
    fn test_parse_ipv6_truncated_extension() {
        // IPv6 packet claiming to have Hop-by-Hop but truncated
        let mut packet = vec![0u8; 42]; // Only 2 bytes after fixed header
        packet[0] = 0x60; // Version 6
        packet[6] = 0; // Next Header: Hop-by-Hop Options
        // Fill addresses
        packet[8..24].copy_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ]);
        packet[24..40].copy_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x02,
        ]);
        packet[40] = 6; // Next Header: TCP
        packet[41] = 0; // Hdr Ext Len: 0 (needs 8 bytes but packet is truncated)

        // Should return None due to truncated packet
        let five_tuple = ShardedIpStackBridge::parse_packet_five_tuple(&packet);
        assert!(five_tuple.is_none());
    }
}
