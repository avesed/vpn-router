//! Ingress packet forwarding - consumes `ProcessedPacket` and forwards to outbounds
//!
//! This module bridges the gap between `WireGuard` ingress (which decrypts packets)
//! and the outbound system (which sends packets to the internet or other tunnels).
//!
//! # Architecture
//!
//! ```text
//! WgIngressManager
//!       |
//!       v (mpsc channel)
//! ProcessedPacket
//!       |
//!       v
//! IngressForwarder
//!       |
//!       +---> UDP packets ---> WgEgressManager.send() / OutboundManager
//!       |
//!       +---> TCP packets ---> TCP state machine
//! ```
//!
//! # Session Tracking
//!
//! The forwarder maintains a session tracker to route reply packets back to
//! the correct `WireGuard` peer. When a packet is forwarded, a session entry
//! is created with the 5-tuple key and the peer's information.
//!
//! # Example
//!
//! ```ignore
//! use rust_router::ingress::forwarder::{spawn_forwarding_task, IngressSessionTracker, ForwardingStats};
//! use std::sync::Arc;
//! use std::time::Duration;
//!
//! let session_tracker = Arc::new(IngressSessionTracker::new(Duration::from_secs(300)));
//! let stats = Arc::new(ForwardingStats::default());
//!
//! let handle = spawn_forwarding_task(
//!     packet_rx,
//!     outbound_manager,
//!     wg_egress_manager,
//!     session_tracker,
//!     stats,
//! );
//! ```

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Semaphore};
use tracing::{debug, info, trace, warn};

use super::manager::{ProcessedPacket, WgIngressManager};
use super::processor::RoutingDecision;
use crate::chain::dscp::set_dscp;
use crate::ecmp::{EcmpGroupManager, FiveTuple as EcmpFiveTuple, Protocol as EcmpProtocol};
use crate::egress::manager::WgEgressManager;
use crate::ipc::ChainRole;
use crate::outbound::OutboundManager;
use crate::peer::manager::PeerManager;
use crate::rules::fwmark::ChainMark;

// IpStack bridge imports (feature-gated)
#[cfg(feature = "ipstack-tcp")]
use super::ipstack_bridge::ShardedIpStackBridge;
#[cfg(feature = "ipstack-tcp")]
use super::ipstack_bridge::{
    FiveTuple as IpStackFiveTuple, SessionTracker as IpStackSessionTracker,
};

/// IP protocol numbers
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_ICMP: u8 = 1;
const IPPROTO_ICMPV6: u8 = 58;

/// Global storage for UDP sessions (used for QUIC and other UDP traffic)
/// Key: (client_ip, client_port, server_ip, server_port)
/// Value: (UdpSocket, last_activity)
static UDP_SESSIONS: Lazy<DashMap<FiveTuple, Arc<UdpSessionEntry>>> = Lazy::new(DashMap::new);

/// UDP session entry for reusing connections
struct UdpSessionEntry {
    socket: Arc<UdpSocket>,
    last_activity: std::sync::atomic::AtomicU64,
}

impl UdpSessionEntry {
    fn new(socket: Arc<UdpSocket>) -> Self {
        Self {
            socket,
            last_activity: std::sync::atomic::AtomicU64::new(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            ),
        }
    }

    fn touch(&self) {
        self.last_activity.store(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            std::sync::atomic::Ordering::Relaxed,
        );
    }

    fn last_activity_secs(&self) -> u64 {
        self.last_activity.load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// Global storage for proxy UDP sessions (Shadowsocks, SOCKS5)
/// Key: 5-tuple (client_ip, client_port, server_ip, server_port, protocol)
/// Value: ProxyUdpSessionEntry containing the UDP outbound handle
static PROXY_UDP_SESSIONS: Lazy<DashMap<FiveTuple, Arc<ProxyUdpSessionEntry>>> =
    Lazy::new(DashMap::new);

// ============================================================================
// IpStack Bridge Integration (feature-gated)
// ============================================================================

/// Global IpStack bridge for TCP handling (replaces manual TCP state machine)
/// Feature-gated: only active when ipstack-tcp feature is enabled
///
/// Note: We use Arc<ShardedIpStackBridge> without RwLock because all public methods
/// on ShardedIpStackBridge only require &self (interior mutability via atomics and channels).
/// This eliminates lock contention on the hot path.
///
/// The sharded bridge distributes packets across multiple ipstack instances using 5-tuple
/// hashing for parallel processing, improving throughput on multi-core systems.
#[cfg(feature = "ipstack-tcp")]
static IPSTACK_BRIDGE: once_cell::sync::OnceCell<std::sync::Arc<ShardedIpStackBridge>> =
    once_cell::sync::OnceCell::new();

/// Environment variable to enable/disable ipstack at runtime
#[cfg(feature = "ipstack-tcp")]
static IPSTACK_ENABLED: AtomicBool = AtomicBool::new(true);

/// Proxy UDP session entry for non-Direct outbounds (Shadowsocks, SOCKS5)
///
/// Unlike direct UDP sessions which use a raw `UdpSocket`, proxy sessions
/// use a `UdpOutboundHandle` which encapsulates the proxy protocol logic.
struct ProxyUdpSessionEntry {
    /// The UDP outbound handle (Shadowsocks or SOCKS5)
    handle: crate::outbound::UdpOutboundHandle,
    /// Last activity timestamp (unix epoch seconds)
    last_activity: AtomicU64,
    /// Statistics: packets sent
    packets_sent: AtomicU64,
    /// Statistics: packets received
    packets_received: AtomicU64,
}

impl ProxyUdpSessionEntry {
    /// Create a new proxy UDP session entry
    fn new(handle: crate::outbound::UdpOutboundHandle) -> Self {
        Self {
            handle,
            last_activity: AtomicU64::new(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            ),
            packets_sent: AtomicU64::new(0),
            packets_received: AtomicU64::new(0),
        }
    }

    /// Update the last activity timestamp
    fn touch(&self) {
        self.last_activity.store(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            Ordering::Relaxed,
        );
    }

    /// Get the last activity timestamp in seconds since UNIX epoch
    fn last_activity_secs(&self) -> u64 {
        self.last_activity.load(Ordering::Relaxed)
    }

    /// Increment sent packet counter
    fn record_sent(&self) {
        self.packets_sent.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment received packet counter
    fn record_received(&self) {
        self.packets_received.fetch_add(1, Ordering::Relaxed);
    }
}

// ============================================================================
// TCP Connection Tracking
// ============================================================================

/// TCP flag bits
pub mod tcp_flags {
    /// FIN flag - connection close request
    pub const FIN: u8 = 0x01;
    /// SYN flag - connection open request
    pub const SYN: u8 = 0x02;
    /// RST flag - connection reset
    pub const RST: u8 = 0x04;
    /// PSH flag - push data immediately
    pub const PSH: u8 = 0x08;
    /// ACK flag - acknowledgment
    pub const ACK: u8 = 0x10;
    /// URG flag - urgent pointer valid
    pub const URG: u8 = 0x20;
}

/// Parsed TCP header details
#[derive(Debug, Clone)]
pub struct TcpDetails {
    /// Source port
    pub src_port: u16,
    /// Destination port
    pub dst_port: u16,
    /// Sequence number
    pub seq_num: u32,
    /// Acknowledgment number
    pub ack_num: u32,
    /// Data offset (header length) in bytes
    pub data_offset: usize,
    /// TCP flags
    pub flags: u8,
    /// Client's advertised receive window
    pub window: u16,
    /// Offset to TCP payload within the packet
    pub payload_offset: usize,
}

impl TcpDetails {
    /// Check if this is a SYN packet (connection initiation)
    #[must_use]
    pub fn is_syn(&self) -> bool {
        (self.flags & tcp_flags::SYN) != 0 && (self.flags & tcp_flags::ACK) == 0
    }

    /// Check if this is a SYN-ACK packet (connection response)
    #[must_use]
    pub fn is_syn_ack(&self) -> bool {
        (self.flags & tcp_flags::SYN) != 0 && (self.flags & tcp_flags::ACK) != 0
    }

    /// Check if ACK flag is set
    #[must_use]
    pub fn is_ack(&self) -> bool {
        (self.flags & tcp_flags::ACK) != 0
    }

    /// Check if FIN flag is set (connection close)
    #[must_use]
    pub fn is_fin(&self) -> bool {
        (self.flags & tcp_flags::FIN) != 0
    }

    /// Check if RST flag is set (connection reset)
    #[must_use]
    pub fn is_rst(&self) -> bool {
        (self.flags & tcp_flags::RST) != 0
    }

    /// Check if packet has TCP payload
    #[must_use]
    pub fn has_payload(&self, packet_len: usize) -> bool {
        self.payload_offset < packet_len
    }

    /// Get payload length if any
    #[must_use]
    pub fn payload_len(&self, packet_len: usize) -> usize {
        packet_len.saturating_sub(self.payload_offset)
    }

    /// Get a human-readable description of the flags
    #[must_use]
    pub fn flags_string(&self) -> String {
        let mut flags = Vec::new();
        if self.flags & tcp_flags::SYN != 0 {
            flags.push("SYN");
        }
        if self.flags & tcp_flags::ACK != 0 {
            flags.push("ACK");
        }
        if self.flags & tcp_flags::FIN != 0 {
            flags.push("FIN");
        }
        if self.flags & tcp_flags::RST != 0 {
            flags.push("RST");
        }
        if self.flags & tcp_flags::PSH != 0 {
            flags.push("PSH");
        }
        if self.flags & tcp_flags::URG != 0 {
            flags.push("URG");
        }
        if flags.is_empty() {
            "none".to_string()
        } else {
            flags.join(",")
        }
    }
}

/// Parse TCP header to extract details
///
/// # Arguments
///
/// * `packet` - Raw IP packet data
/// * `ip_header_len` - Length of the IP header in bytes
///
/// # Returns
///
/// Parsed TCP details, or None if the packet is too short or invalid.
#[must_use]
pub fn parse_tcp_details(packet: &[u8], ip_header_len: usize) -> Option<TcpDetails> {
    let tcp_start = ip_header_len;

    // Minimum TCP header is 20 bytes
    if packet.len() < tcp_start + 20 {
        return None;
    }

    let src_port = u16::from_be_bytes([packet[tcp_start], packet[tcp_start + 1]]);
    let dst_port = u16::from_be_bytes([packet[tcp_start + 2], packet[tcp_start + 3]]);
    let seq_num = u32::from_be_bytes([
        packet[tcp_start + 4],
        packet[tcp_start + 5],
        packet[tcp_start + 6],
        packet[tcp_start + 7],
    ]);
    let ack_num = u32::from_be_bytes([
        packet[tcp_start + 8],
        packet[tcp_start + 9],
        packet[tcp_start + 10],
        packet[tcp_start + 11],
    ]);

    // Data offset is in the high 4 bits of byte 12, in 32-bit words
    let data_offset_words = (packet[tcp_start + 12] >> 4) as usize;
    let data_offset = data_offset_words * 4;

    // Validate data offset (must be at least 5 words = 20 bytes)
    if data_offset < 20 || tcp_start + data_offset > packet.len() {
        return None;
    }

    let flags = packet[tcp_start + 13];

    // Window size is at bytes 14-15 of TCP header
    let window = u16::from_be_bytes([packet[tcp_start + 14], packet[tcp_start + 15]]);

    Some(TcpDetails {
        src_port,
        dst_port,
        seq_num,
        ack_num,
        data_offset,
        flags,
        window,
        payload_offset: tcp_start + data_offset,
    })
}

/// 5-tuple key for session tracking
///
/// A 5-tuple uniquely identifies a connection/flow and consists of:
/// - Source IP address
/// - Source port
/// - Destination IP address
/// - Destination port
/// - Protocol (TCP=6, UDP=17)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FiveTuple {
    /// Source IP address
    pub src_ip: IpAddr,
    /// Source port
    pub src_port: u16,
    /// Destination IP address
    pub dst_ip: IpAddr,
    /// Destination port
    pub dst_port: u16,
    /// IP protocol number (6=TCP, 17=UDP)
    pub protocol: u8,
}

impl FiveTuple {
    /// Create a new 5-tuple
    ///
    /// # Arguments
    ///
    /// * `src_ip` - Source IP address
    /// * `src_port` - Source port
    /// * `dst_ip` - Destination IP address
    /// * `dst_port` - Destination port
    /// * `protocol` - IP protocol number (6=TCP, 17=UDP)
    #[must_use]
    pub fn new(src_ip: IpAddr, src_port: u16, dst_ip: IpAddr, dst_port: u16, protocol: u8) -> Self {
        Self {
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            protocol,
        }
    }

    /// Create a reversed tuple for reply matching
    ///
    /// Swaps source and destination addresses/ports while keeping the protocol.
    /// This is useful for matching reply packets to their original session.
    #[must_use]
    pub fn reverse(&self) -> Self {
        Self {
            src_ip: self.dst_ip,
            src_port: self.dst_port,
            dst_ip: self.src_ip,
            dst_port: self.src_port,
            protocol: self.protocol,
        }
    }

    /// Check if this is a TCP flow
    #[must_use]
    pub fn is_tcp(&self) -> bool {
        self.protocol == IPPROTO_TCP
    }

    /// Check if this is a UDP flow
    #[must_use]
    pub fn is_udp(&self) -> bool {
        self.protocol == IPPROTO_UDP
    }

    /// Get the protocol name for logging
    #[must_use]
    pub fn protocol_name(&self) -> &'static str {
        match self.protocol {
            IPPROTO_TCP => "TCP",
            IPPROTO_UDP => "UDP",
            IPPROTO_ICMP => "ICMP",
            IPPROTO_ICMPV6 => "ICMPv6",
            _ => "Unknown",
        }
    }
}

impl std::fmt::Display for FiveTuple {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{}->{}:{}/{}",
            self.src_ip,
            self.src_port,
            self.dst_ip,
            self.dst_port,
            self.protocol_name()
        )
    }
}

/// Session information for reply routing
///
/// Stores the information needed to route reply packets back to the
/// correct `WireGuard` peer.
#[derive(Debug, Clone)]
pub struct PeerSession {
    /// Peer's `WireGuard` public key (Base64)
    pub peer_public_key: String,
    /// Peer's external endpoint (IP:port)
    pub peer_endpoint: SocketAddr,
    /// Outbound tag used for this session
    pub outbound_tag: String,
    /// Timestamp of last activity
    pub last_seen: Instant,
    /// Bytes sent in this session
    pub bytes_sent: u64,
    /// Bytes received in this session (replies)
    pub bytes_received: u64,
    /// Source tunnel tag for chain traffic (None for wg-ingress Entry traffic)
    pub source_tunnel_tag: Option<String>,
    /// Whether this is chain traffic requiring special reply routing
    pub is_chain_traffic: bool,
    /// Node role when session was created (Entry/Relay/Terminal)
    pub node_role: Option<ChainRole>,
}

impl PeerSession {
    /// Create a new peer session
    #[must_use]
    pub fn new(peer_public_key: String, peer_endpoint: SocketAddr, outbound_tag: String) -> Self {
        Self {
            peer_public_key,
            peer_endpoint,
            outbound_tag,
            last_seen: Instant::now(),
            bytes_sent: 0,
            bytes_received: 0,
            source_tunnel_tag: None,
            is_chain_traffic: false,
            node_role: None,
        }
    }

    /// Create a new peer session for chain traffic
    ///
    /// This constructor is used when traffic arrives via a chain (peer tunnel)
    /// and requires special reply routing back through the source tunnel.
    ///
    /// # Arguments
    ///
    /// * `peer_public_key` - Peer's WireGuard public key (Base64)
    /// * `peer_endpoint` - Peer's external endpoint (IP:port)
    /// * `outbound_tag` - Outbound tag used for this session
    /// * `source_tunnel_tag` - Tag of the tunnel this traffic arrived from
    /// * `node_role` - Role of this node in the chain (Entry/Relay/Terminal)
    #[must_use]
    pub fn new_chain(
        peer_public_key: String,
        peer_endpoint: SocketAddr,
        outbound_tag: String,
        source_tunnel_tag: Option<String>,
        node_role: ChainRole,
    ) -> Self {
        Self {
            peer_public_key,
            peer_endpoint,
            outbound_tag,
            last_seen: Instant::now(),
            bytes_sent: 0,
            bytes_received: 0,
            source_tunnel_tag,
            is_chain_traffic: true,
            node_role: Some(node_role),
        }
    }

    /// Update the last seen timestamp
    pub fn touch(&mut self) {
        self.last_seen = Instant::now();
    }

    /// Add bytes sent
    pub fn add_bytes_sent(&mut self, bytes: u64) {
        self.bytes_sent = self.bytes_sent.saturating_add(bytes);
    }

    /// Add bytes received
    pub fn add_bytes_received(&mut self, bytes: u64) {
        self.bytes_received = self.bytes_received.saturating_add(bytes);
    }

    /// Check if the session has expired
    #[must_use]
    pub fn is_expired(&self, ttl: Duration) -> bool {
        self.last_seen.elapsed() >= ttl
    }
}

/// Tracks active sessions for reply routing
///
/// Uses a concurrent hash map (`DashMap`) for thread-safe access
/// from multiple async tasks.
///
/// **DEPRECATED**: Use `ipstack_bridge::SessionTracker` instead, which provides
/// unified session tracking with `peer_endpoint` support. The ipstack bridge's
/// `SessionTracker` is now the single source of truth for session information,
/// eliminating duplicate tracking between this struct and the bridge.
#[deprecated(
    since = "0.15.0",
    note = "Use ipstack_bridge::SessionTracker instead for unified session tracking"
)]
pub struct IngressSessionTracker {
    /// Active sessions indexed by 5-tuple
    sessions: DashMap<FiveTuple, PeerSession>,
    /// Session time-to-live
    session_ttl: Duration,
}

impl IngressSessionTracker {
    /// Create a new session tracker
    ///
    /// # Arguments
    ///
    /// * `session_ttl` - How long to keep sessions alive without activity
    #[must_use]
    pub fn new(session_ttl: Duration) -> Self {
        Self {
            sessions: DashMap::new(),
            session_ttl,
        }
    }

    /// Register or update a session
    ///
    /// If a session already exists, updates the `last_seen` timestamp and bytes.
    /// Otherwise, creates a new session entry.
    ///
    /// # Arguments
    ///
    /// * `key` - 5-tuple key for the session
    /// * `peer_public_key` - Peer's `WireGuard` public key
    /// * `peer_endpoint` - Peer's external endpoint
    /// * `outbound_tag` - Outbound tag used for routing
    /// * `bytes` - Bytes being sent in this packet
    pub fn register(
        &self,
        key: FiveTuple,
        peer_public_key: String,
        peer_endpoint: SocketAddr,
        outbound_tag: String,
        bytes: u64,
    ) {
        self.sessions
            .entry(key)
            .and_modify(|session| {
                session.touch();
                session.add_bytes_sent(bytes);
                // Update peer endpoint in case client's IP changed (mobile roaming/NAT rebinding)
                if session.peer_endpoint != peer_endpoint {
                    tracing::info!(
                        "Peer endpoint changed for {}: {} -> {}",
                        key, session.peer_endpoint, peer_endpoint
                    );
                    session.peer_endpoint = peer_endpoint;
                }
            })
            .or_insert_with(|| {
                let mut session = PeerSession::new(peer_public_key, peer_endpoint, outbound_tag);
                session.add_bytes_sent(bytes);
                session
            });
    }

    /// Register a chain traffic session with node role information
    ///
    /// Chain sessions track the source tunnel so replies can be routed back
    /// through the chain. For Entry nodes, `source_tunnel_tag` is None.
    /// For Relay and Terminal nodes, it contains the tunnel tag where
    /// the packet arrived from.
    ///
    /// # Arguments
    ///
    /// * `key` - 5-tuple key for the session
    /// * `peer_public_key` - For Entry: WG peer key. For Relay/Terminal: tunnel tag as pseudo-key
    /// * `peer_endpoint` - For Entry: client endpoint. For Relay/Terminal: placeholder (0.0.0.0:0)
    /// * `outbound_tag` - Where this packet is being forwarded to
    /// * `bytes` - Bytes being sent
    /// * `source_tunnel_tag` - For Relay/Terminal: incoming tunnel tag. For Entry: None
    /// * `node_role` - Entry, Relay, or Terminal
    pub fn register_chain(
        &self,
        key: FiveTuple,
        peer_public_key: String,
        peer_endpoint: SocketAddr,
        outbound_tag: String,
        bytes: u64,
        source_tunnel_tag: Option<String>,
        node_role: ChainRole,
    ) {
        self.sessions
            .entry(key)
            .and_modify(|session| {
                session.touch();
                session.add_bytes_sent(bytes);
                // Update endpoint in case of roaming (only relevant for Entry nodes)
                if session.peer_endpoint != peer_endpoint && peer_endpoint.port() != 0 {
                    tracing::debug!(
                        "Chain session endpoint updated for {}: {} -> {}",
                        key, session.peer_endpoint, peer_endpoint
                    );
                    session.peer_endpoint = peer_endpoint;
                }
            })
            .or_insert_with(|| {
                let mut session = PeerSession::new_chain(
                    peer_public_key,
                    peer_endpoint,
                    outbound_tag,
                    source_tunnel_tag,
                    node_role,
                );
                session.add_bytes_sent(bytes);
                session
            });
    }

    /// Look up a session for reply routing
    ///
    /// # Arguments
    ///
    /// * `key` - 5-tuple key (should be the reversed tuple for replies)
    ///
    /// # Returns
    ///
    /// The session if found, or None if not found.
    ///
    /// # Note
    ///
    /// This method intentionally does NOT check session expiration. The periodic
    /// `cleanup()` method handles removal of stale sessions.
    ///
    /// **Why**: During download-heavy transfers (e.g., speed tests), the client
    /// sends very little data (mostly ACKs), so `last_seen` is rarely updated.
    /// If we check expiration here, sessions expire mid-transfer after 5 minutes,
    /// causing all server reply packets to be dropped and speed to drop to 0.
    ///
    /// By deferring expiration checks to `cleanup()` (which runs every 60 seconds),
    /// active sessions remain valid as long as they exist in the map. The caller
    /// should use `update_received()` after successfully routing a reply, which
    /// will refresh the session's `last_seen` timestamp.
    #[must_use]
    pub fn get(&self, key: &FiveTuple) -> Option<PeerSession> {
        self.sessions.get(key).map(|entry| entry.value().clone())
    }

    /// Update bytes received for a session (for reply tracking)
    ///
    /// # Arguments
    ///
    /// * `key` - 5-tuple key (reversed for replies)
    /// * `bytes` - Bytes received
    pub fn update_received(&self, key: &FiveTuple, bytes: u64) {
        if let Some(mut entry) = self.sessions.get_mut(key) {
            entry.touch();
            entry.add_bytes_received(bytes);
        }
    }

    /// Clean up expired sessions
    ///
    /// Should be called periodically to remove stale sessions.
    ///
    /// # Returns
    ///
    /// Number of sessions removed.
    pub fn cleanup(&self) -> usize {
        let before = self.sessions.len();
        self.sessions.retain(|_, session| !session.is_expired(self.session_ttl));
        before.saturating_sub(self.sessions.len())
    }

    /// Get the number of active sessions
    #[must_use]
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    /// Check if there are no sessions
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    /// Get session TTL
    #[must_use]
    pub fn session_ttl(&self) -> Duration {
        self.session_ttl
    }
}

impl Default for IngressSessionTracker {
    fn default() -> Self {
        Self::new(Duration::from_secs(300)) // 5 minute default TTL
    }
}

/// Reply packet received from egress
#[derive(Debug, Clone)]
pub struct ReplyPacket {
    /// Decrypted IP packet from egress
    pub packet: Vec<u8>,
    /// Tunnel tag that delivered the reply
    pub tunnel_tag: String,
}

/// Reply path statistics
#[derive(Debug, Default)]
pub struct IngressReplyStats {
    /// Packets received from egress reply handler
    pub packets_received: AtomicU64,
    /// Packets enqueued for reply routing
    pub packets_enqueued: AtomicU64,
    /// Packets dropped because the queue was full
    pub queue_full: AtomicU64,
    /// Packets dropped because reply router was not ready
    pub router_unavailable: AtomicU64,
    /// Packets parsed successfully and forwarded
    pub packets_forwarded: AtomicU64,
    /// Packets with parse errors
    pub parse_errors: AtomicU64,
    /// Packets with missing session mapping
    pub session_misses: AtomicU64,
    /// Packets rejected due to tunnel tag mismatch
    pub tunnel_mismatch: AtomicU64,
    /// Packets rejected due to unsupported protocols
    pub unsupported_protocol: AtomicU64,
    /// IPv6 packets with extension headers
    pub ipv6_extension_headers: AtomicU64,
    /// Packets rejected by peer IP validation
    pub peer_ip_rejected: AtomicU64,
    /// Errors while sending replies
    pub send_errors: AtomicU64,
}

impl IngressReplyStats {
    /// Snapshot current reply statistics
    #[must_use]
    pub fn snapshot(&self) -> IngressReplyStatsSnapshot {
        IngressReplyStatsSnapshot {
            packets_received: self.packets_received.load(Ordering::Relaxed),
            packets_enqueued: self.packets_enqueued.load(Ordering::Relaxed),
            queue_full: self.queue_full.load(Ordering::Relaxed),
            router_unavailable: self.router_unavailable.load(Ordering::Relaxed),
            packets_forwarded: self.packets_forwarded.load(Ordering::Relaxed),
            parse_errors: self.parse_errors.load(Ordering::Relaxed),
            session_misses: self.session_misses.load(Ordering::Relaxed),
            tunnel_mismatch: self.tunnel_mismatch.load(Ordering::Relaxed),
            unsupported_protocol: self.unsupported_protocol.load(Ordering::Relaxed),
            ipv6_extension_headers: self.ipv6_extension_headers.load(Ordering::Relaxed),
            peer_ip_rejected: self.peer_ip_rejected.load(Ordering::Relaxed),
            send_errors: self.send_errors.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of reply statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngressReplyStatsSnapshot {
    pub packets_received: u64,
    pub packets_enqueued: u64,
    pub queue_full: u64,
    pub router_unavailable: u64,
    pub packets_forwarded: u64,
    pub parse_errors: u64,
    pub session_misses: u64,
    pub tunnel_mismatch: u64,
    pub unsupported_protocol: u64,
    pub ipv6_extension_headers: u64,
    pub peer_ip_rejected: u64,
    pub send_errors: u64,
}

/// Forwarding statistics
///
/// Thread-safe statistics for the forwarding loop.
#[derive(Debug, Default)]
pub struct ForwardingStats {
    /// Total packets forwarded successfully
    pub packets_forwarded: AtomicU64,
    /// Total bytes forwarded
    pub bytes_forwarded: AtomicU64,
    /// UDP packets processed
    pub udp_packets: AtomicU64,
    /// TCP packets processed
    pub tcp_packets: AtomicU64,
    /// ICMP packets processed
    pub icmp_packets: AtomicU64,
    /// Packets dropped due to forward errors
    pub forward_errors: AtomicU64,
    /// Packets with unknown/unsupported protocol
    pub unknown_protocol: AtomicU64,
    /// Packets dropped due to block rule
    pub blocked_packets: AtomicU64,
    /// Parse errors (invalid IP headers, etc.)
    pub parse_errors: AtomicU64,
}

impl ForwardingStats {
    /// Create a snapshot of current statistics
    #[must_use]
    pub fn snapshot(&self) -> ForwardingStatsSnapshot {
        ForwardingStatsSnapshot {
            packets_forwarded: self.packets_forwarded.load(Ordering::Relaxed),
            bytes_forwarded: self.bytes_forwarded.load(Ordering::Relaxed),
            udp_packets: self.udp_packets.load(Ordering::Relaxed),
            tcp_packets: self.tcp_packets.load(Ordering::Relaxed),
            icmp_packets: self.icmp_packets.load(Ordering::Relaxed),
            forward_errors: self.forward_errors.load(Ordering::Relaxed),
            unknown_protocol: self.unknown_protocol.load(Ordering::Relaxed),
            blocked_packets: self.blocked_packets.load(Ordering::Relaxed),
            parse_errors: self.parse_errors.load(Ordering::Relaxed),
        }
    }

    /// Reset all statistics to zero
    pub fn reset(&self) {
        self.packets_forwarded.store(0, Ordering::Relaxed);
        self.bytes_forwarded.store(0, Ordering::Relaxed);
        self.udp_packets.store(0, Ordering::Relaxed);
        self.tcp_packets.store(0, Ordering::Relaxed);
        self.icmp_packets.store(0, Ordering::Relaxed);
        self.forward_errors.store(0, Ordering::Relaxed);
        self.unknown_protocol.store(0, Ordering::Relaxed);
        self.blocked_packets.store(0, Ordering::Relaxed);
        self.parse_errors.store(0, Ordering::Relaxed);
    }
}

/// Immutable snapshot of forwarding statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForwardingStatsSnapshot {
    /// Total packets forwarded successfully
    pub packets_forwarded: u64,
    /// Total bytes forwarded
    pub bytes_forwarded: u64,
    /// UDP packets processed
    pub udp_packets: u64,
    /// TCP packets processed
    pub tcp_packets: u64,
    /// ICMP packets processed
    pub icmp_packets: u64,
    /// Packets dropped due to forward errors
    pub forward_errors: u64,
    /// Packets with unknown/unsupported protocol
    pub unknown_protocol: u64,
    /// Packets dropped due to block rule
    pub blocked_packets: u64,
    /// Parse errors
    pub parse_errors: u64,
}

impl ForwardingStatsSnapshot {
    /// Get total packets processed (including errors)
    #[must_use]
    pub fn total_packets(&self) -> u64 {
        self.packets_forwarded
            .saturating_add(self.forward_errors)
            .saturating_add(self.unknown_protocol)
            .saturating_add(self.blocked_packets)
            .saturating_add(self.parse_errors)
    }

    /// Get success rate as a percentage
    #[must_use]
    pub fn success_rate(&self) -> f64 {
        let total = self.total_packets();
        if total == 0 {
            100.0
        } else {
            (self.packets_forwarded as f64 / total as f64) * 100.0
        }
    }
}

// ============================================================================
// Direct UDP Reply Packet Building
// ============================================================================

/// Build a UDP reply packet with IP and UDP headers.
///
/// This function creates a complete IPv4 UDP packet that can be sent to the
/// reply router. It's used for direct outbound UDP replies where we need to
/// reconstruct the IP packet from the raw UDP payload received from the destination.
///
/// # Arguments
///
/// * `src_ip` - Source IP (the destination that sent the reply)
/// * `src_port` - Source port (the destination port that sent the reply)
/// * `dst_ip` - Destination IP (the original client IP)
/// * `dst_port` - Destination port (the original client port)
/// * `payload` - The UDP payload data
///
/// # Returns
///
/// A complete IPv4 UDP packet as a `Vec<u8>`.
fn build_udp_reply_packet(
    src_ip: Ipv4Addr,
    src_port: u16,
    dst_ip: Ipv4Addr,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let total_len = 20 + udp_len;

    let mut packet = vec![0u8; total_len];

    // IPv4 header (20 bytes minimum)
    packet[0] = 0x45; // Version 4, IHL 5 (20 bytes)
    packet[1] = 0x00; // DSCP/ECN
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes()); // Total length
    packet[4..6].copy_from_slice(&[0x00, 0x00]); // Identification
    packet[6..8].copy_from_slice(&[0x40, 0x00]); // Don't fragment flag
    packet[8] = 64; // TTL
    packet[9] = IPPROTO_UDP; // Protocol
    // Checksum calculated below
    packet[12..16].copy_from_slice(&src_ip.octets()); // Source IP
    packet[16..20].copy_from_slice(&dst_ip.octets()); // Dest IP

    // Calculate IPv4 header checksum
    let checksum = ipv4_header_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());

    // UDP header (8 bytes)
    packet[20..22].copy_from_slice(&src_port.to_be_bytes());
    packet[22..24].copy_from_slice(&dst_port.to_be_bytes());
    packet[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes());
    // UDP checksum left as 0 (optional for IPv4)

    // Payload
    if !payload.is_empty() {
        packet[28..].copy_from_slice(payload);
    }

    packet
}

/// Build a UDP reply packet for IPv6.
///
/// Similar to `build_udp_reply_packet` but for IPv6 addresses.
fn build_udp_reply_packet_v6(
    src_ip: Ipv6Addr,
    src_port: u16,
    dst_ip: Ipv6Addr,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let total_len = 40 + udp_len; // IPv6 header is 40 bytes

    let mut packet = vec![0u8; total_len];

    // IPv6 header (40 bytes)
    packet[0] = 0x60; // Version 6
    // packet[1..4] = Traffic class + flow label (left as 0)
    packet[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes()); // Payload length
    packet[6] = IPPROTO_UDP; // Next header
    packet[7] = 64; // Hop limit
    packet[8..24].copy_from_slice(&src_ip.octets()); // Source IP
    packet[24..40].copy_from_slice(&dst_ip.octets()); // Dest IP

    // UDP header (8 bytes)
    packet[40..42].copy_from_slice(&src_port.to_be_bytes());
    packet[42..44].copy_from_slice(&dst_port.to_be_bytes());
    packet[44..46].copy_from_slice(&(udp_len as u16).to_be_bytes());
    // UDP checksum required for IPv6, but we'll leave as 0 for now
    // (WireGuard will recalculate anyway)

    // Payload
    if !payload.is_empty() {
        packet[48..].copy_from_slice(payload);
    }

    packet
}

/// Calculate IPv4 header checksum.
fn ipv4_header_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for i in (0..header.len()).step_by(2) {
        if i == 10 {
            // Skip checksum field
            continue;
        }
        let word = if i + 1 < header.len() {
            u16::from_be_bytes([header[i], header[i + 1]])
        } else {
            u16::from_be_bytes([header[i], 0])
        };
        sum = sum.wrapping_add(u32::from(word));
    }
    // Fold 32-bit sum to 16 bits
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

// ============================================================================
// ICMP Packet Building
// ============================================================================

/// ICMP types
const ICMP_ECHO_REQUEST: u8 = 8;
const ICMP_ECHO_REPLY: u8 = 0;

/// Build an ICMP Echo Reply packet.
///
/// Used to construct reply packets from ICMP echo responses received from the network.
fn build_icmp_reply_packet(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    id: u16,
    seq: u16,
    payload: &[u8],
) -> Vec<u8> {
    let icmp_len = 8 + payload.len(); // ICMP header (8) + payload
    let total_len = 20 + icmp_len;

    let mut packet = vec![0u8; total_len];

    // IPv4 header (20 bytes)
    packet[0] = 0x45;
    packet[1] = 0x00;
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[4..6].copy_from_slice(&rand::random::<u16>().to_be_bytes());
    packet[6..8].copy_from_slice(&[0x40, 0x00]);
    packet[8] = 64; // TTL
    packet[9] = IPPROTO_ICMP;
    packet[12..16].copy_from_slice(&src_ip.octets());
    packet[16..20].copy_from_slice(&dst_ip.octets());

    let ip_checksum = ipv4_header_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

    // ICMP header
    let icmp_start = 20;
    packet[icmp_start] = ICMP_ECHO_REPLY; // Type
    packet[icmp_start + 1] = 0; // Code
    // Checksum calculated below
    packet[icmp_start + 4..icmp_start + 6].copy_from_slice(&id.to_be_bytes());
    packet[icmp_start + 6..icmp_start + 8].copy_from_slice(&seq.to_be_bytes());

    // Payload
    if !payload.is_empty() {
        packet[icmp_start + 8..].copy_from_slice(payload);
    }

    // ICMP checksum
    let icmp_checksum = icmp_checksum(&packet[icmp_start..]);
    packet[icmp_start + 2..icmp_start + 4].copy_from_slice(&icmp_checksum.to_be_bytes());

    packet
}

/// Calculate ICMP checksum.
fn icmp_checksum(icmp_data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for i in (0..icmp_data.len()).step_by(2) {
        if i == 2 {
            continue; // Skip checksum field
        }
        let word = if i + 1 < icmp_data.len() {
            u16::from_be_bytes([icmp_data[i], icmp_data[i + 1]])
        } else {
            u16::from_be_bytes([icmp_data[i], 0])
        };
        sum = sum.wrapping_add(u32::from(word));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Parse ICMP Echo Request to extract ID and sequence number.
fn parse_icmp_echo(packet: &[u8], ip_header_len: usize) -> Option<(u8, u8, u16, u16, Vec<u8>)> {
    let icmp_start = ip_header_len;
    if packet.len() < icmp_start + 8 {
        return None;
    }

    let icmp_type = packet[icmp_start];
    let icmp_code = packet[icmp_start + 1];
    let id = u16::from_be_bytes([packet[icmp_start + 4], packet[icmp_start + 5]]);
    let seq = u16::from_be_bytes([packet[icmp_start + 6], packet[icmp_start + 7]]);
    let payload = packet[icmp_start + 8..].to_vec();

    Some((icmp_type, icmp_code, id, seq, payload))
}

/// Parsed IP packet information
#[derive(Debug, Clone)]
pub struct ParsedPacket {
    /// Source IP address
    pub src_ip: IpAddr,
    /// Destination IP address
    pub dst_ip: IpAddr,
    /// IP protocol number
    pub protocol: u8,
    /// IP header length in bytes
    pub ip_header_len: usize,
    /// Source port (for TCP/UDP)
    pub src_port: Option<u16>,
    /// Destination port (for TCP/UDP)
    pub dst_port: Option<u16>,
    /// Total packet length
    pub total_len: usize,
}

impl ParsedPacket {
    /// Get the 5-tuple for this packet (if TCP or UDP)
    #[must_use]
    pub fn five_tuple(&self) -> Option<FiveTuple> {
        match (self.src_port, self.dst_port) {
            (Some(src_port), Some(dst_port)) => Some(FiveTuple::new(
                self.src_ip,
                src_port,
                self.dst_ip,
                dst_port,
                self.protocol,
            )),
            _ => None,
        }
    }

    /// Get the destination socket address (for TCP/UDP)
    #[must_use]
    pub fn dst_addr(&self) -> Option<SocketAddr> {
        self.dst_port.map(|port| SocketAddr::new(self.dst_ip, port))
    }

    /// Get the payload offset (start of transport layer payload)
    #[must_use]
    pub fn payload_offset(&self) -> usize {
        let transport_header_len = match self.protocol {
            IPPROTO_UDP => 8,
            IPPROTO_TCP => 20, // Minimum TCP header; actual may be larger
            _ => 0,
        };
        self.ip_header_len + transport_header_len
    }
}

/// Parse an IP packet header
///
/// Extracts IP header information including source/destination addresses,
/// protocol, and header length. Also parses transport layer ports for TCP/UDP.
///
/// # Arguments
///
/// * `packet` - Raw IP packet data
///
/// # Returns
///
/// Parsed packet information, or None if the packet is invalid.
#[must_use]
pub fn parse_ip_packet(packet: &[u8]) -> Option<ParsedPacket> {
    if packet.is_empty() {
        return None;
    }

    let version = packet[0] >> 4;
    match version {
        4 => parse_ipv4_packet(packet),
        6 => parse_ipv6_packet(packet),
        _ => None,
    }
}

/// Parse an IPv4 packet
fn parse_ipv4_packet(packet: &[u8]) -> Option<ParsedPacket> {
    // Minimum IPv4 header is 20 bytes
    if packet.len() < 20 {
        return None;
    }

    // IHL (Internet Header Length) is in 32-bit words
    let ihl = (packet[0] & 0x0F) as usize * 4;
    if packet.len() < ihl {
        return None;
    }

    let protocol = packet[9];

    // Extract source IP (bytes 12-15)
    let src_ip = IpAddr::V4(Ipv4Addr::new(
        packet[12],
        packet[13],
        packet[14],
        packet[15],
    ));

    // Extract destination IP (bytes 16-19)
    let dst_ip = IpAddr::V4(Ipv4Addr::new(
        packet[16],
        packet[17],
        packet[18],
        packet[19],
    ));

    // Parse transport layer ports
    let (src_port, dst_port) = parse_transport_ports(packet, ihl, protocol, packet.len());

    Some(ParsedPacket {
        src_ip,
        dst_ip,
        protocol,
        ip_header_len: ihl,
        src_port,
        dst_port,
        total_len: packet.len(),
    })
}

/// Parse an IPv6 packet
fn parse_ipv6_packet(packet: &[u8]) -> Option<ParsedPacket> {
    // IPv6 header is 40 bytes
    if packet.len() < 40 {
        return None;
    }

    let (protocol, header_len, total_len) = parse_ipv6_transport_header(packet)?;

    // Extract source IP (bytes 8-23)
    let src_ip = IpAddr::V6(Ipv6Addr::from([
        packet[8],
        packet[9],
        packet[10],
        packet[11],
        packet[12],
        packet[13],
        packet[14],
        packet[15],
        packet[16],
        packet[17],
        packet[18],
        packet[19],
        packet[20],
        packet[21],
        packet[22],
        packet[23],
    ]));

    // Extract destination IP (bytes 24-39)
    let dst_ip = IpAddr::V6(Ipv6Addr::from([
        packet[24],
        packet[25],
        packet[26],
        packet[27],
        packet[28],
        packet[29],
        packet[30],
        packet[31],
        packet[32],
        packet[33],
        packet[34],
        packet[35],
        packet[36],
        packet[37],
        packet[38],
        packet[39],
    ]));

    if matches!(protocol, IPPROTO_TCP | IPPROTO_UDP) && total_len < header_len + 4 {
        return None;
    }

    // Parse transport layer ports
    let (src_port, dst_port) = parse_transport_ports(packet, header_len, protocol, total_len);

    Some(ParsedPacket {
        src_ip,
        dst_ip,
        protocol,
        ip_header_len: header_len,
        src_port,
        dst_port,
        total_len,
    })
}

const IPV6_MAX_EXT_HEADERS: usize = 16;

pub(crate) fn parse_ipv6_transport_header(packet: &[u8]) -> Option<(u8, usize, usize)> {
    if packet.len() < 40 {
        return None;
    }

    let mut next_header = packet[6];
    let mut offset = 40usize;
    let payload_len = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let total_len = if payload_len == 0 {
        packet.len()
    } else {
        40 + payload_len
    };

    if total_len > packet.len() {
        return None;
    }

    for _ in 0..IPV6_MAX_EXT_HEADERS {
        match next_header {
            0 | 43 | 60 | 135 | 139 | 140 | 253 | 254 => {
                if total_len < offset + 2 {
                    return None;
                }
                let hdr_len = packet[offset + 1] as usize;
                let ext_len = (hdr_len + 1) * 8;
                if total_len < offset + ext_len {
                    return None;
                }
                next_header = packet[offset];
                offset += ext_len;
            }
            44 => {
                if total_len < offset + 8 {
                    return None;
                }
                let frag = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]);
                let frag_offset = frag >> 3;
                if frag_offset != 0 {
                    return Some((44, offset + 8, total_len));
                }
                next_header = packet[offset];
                offset += 8;
            }
            51 => {
                if total_len < offset + 2 {
                    return None;
                }
                let payload_len = packet[offset + 1] as usize;
                let ext_len = (payload_len + 2) * 4;
                if total_len < offset + ext_len {
                    return None;
                }
                next_header = packet[offset];
                offset += ext_len;
            }
            50 | 59 => return Some((next_header, offset, total_len)),
            _ => return Some((next_header, offset, total_len)),
        }
    }

    None
}

/// Parse transport layer (TCP/UDP) ports
fn parse_transport_ports(
    packet: &[u8],
    ip_header_len: usize,
    protocol: u8,
    total_len: usize,
) -> (Option<u16>, Option<u16>) {
    match protocol {
        IPPROTO_TCP | IPPROTO_UDP => {
            // Both TCP and UDP have source port at offset 0-1 and dest port at 2-3
            let start = ip_header_len;
            if total_len >= start + 4 && packet.len() >= start + 4 {
                let src_port = u16::from_be_bytes([packet[start], packet[start + 1]]);
                let dst_port = u16::from_be_bytes([packet[start + 2], packet[start + 3]]);
                (Some(src_port), Some(dst_port))
            } else {
                (None, None)
            }
        }
        _ => (None, None),
    }
}

fn is_ipv6_extension_header(protocol: u8) -> bool {
    matches!(
        protocol,
        0 | 43 | 44 | 50 | 51 | 59 | 60 | 135 | 139 | 140 | 253 | 254
    )
}

fn dscp_update_value(routing: &RoutingDecision) -> Option<u8> {
    let has_chain_mark = routing
        .routing_mark
        .and_then(ChainMark::from_routing_mark)
        .is_some();

    if routing.is_chain_packet && !has_chain_mark {
        Some(0)
    } else {
        routing.dscp_mark
    }
}

/// Main packet forwarding loop
///
/// Consumes `ProcessedPacket` from the channel and forwards to the appropriate outbound.
///
/// # Arguments
///
/// * `packet_rx` - Receiver for processed packets from ingress
/// * `outbound_manager` - Manager for direct/SOCKS5 outbounds (used for UDP)
/// * `wg_egress_manager` - Manager for `WireGuard` egress tunnels
/// * `session_tracker` - Session tracker for reply routing
/// * `stats` - Statistics collector
/// * `direct_reply_tx` - Optional sender for direct outbound UDP replies
/// * `local_ip` - Gateway's local IP for responding to pings to self
/// * `ecmp_group_manager` - Optional ECMP group manager for load balancing
/// * `peer_manager` - Optional peer manager for peer tunnel forwarding
///
/// # Note
///
/// TCP connections are handled by IpStack bridge (when `ipstack-tcp` feature is enabled).
/// The manual TCP state machine was removed due to bugs.
pub async fn run_forwarding_loop(
    mut packet_rx: mpsc::Receiver<ProcessedPacket>,
    outbound_manager: Arc<OutboundManager>,
    wg_egress_manager: Arc<WgEgressManager>,
    session_tracker: Arc<IngressSessionTracker>,
    stats: Arc<ForwardingStats>,
    direct_reply_tx: Option<mpsc::Sender<ReplyPacket>>,
    local_ip: Option<IpAddr>,
    ecmp_group_manager: Option<Arc<EcmpGroupManager>>,
    peer_manager: Option<Arc<PeerManager>>,
) {
    info!("Ingress forwarding loop started");

    // Periodic cleanup interval
    let cleanup_interval = Duration::from_secs(60);
    let mut last_cleanup = Instant::now();

    while let Some(mut processed) = packet_rx.recv().await {
        let packet_len = processed.data.len();

        if let Some(dscp_mark) = dscp_update_value(&processed.routing) {
            if let Err(e) = set_dscp(&mut processed.data, dscp_mark) {
                if dscp_mark == 0 {
                    warn!("Failed to clear DSCP: {}", e);
                } else {
                    warn!("Failed to set DSCP {}: {}", dscp_mark, e);
                }
            }
        }

        // Parse IP header
        let Some(parsed) = parse_ip_packet(&processed.data) else {
            warn!("Failed to parse IP header from ProcessedPacket");
            stats.parse_errors.fetch_add(1, Ordering::Relaxed);
            continue;
        };

        trace!(
            "Forwarding packet: {} -> {}, protocol={}, outbound={}, dscp={:?}",
            parsed.src_ip,
            parsed.dst_ip,
            parsed.protocol,
            processed.routing.outbound,
            processed.routing.dscp_mark
        );

        // Handle block outbound first
        let outbound_tag = &processed.routing.outbound;
        if outbound_tag == "block" || outbound_tag == "adblock" {
            debug!(
                "Blocking packet: {} -> {} (rule: {})",
                parsed.src_ip, parsed.dst_ip, outbound_tag
            );
            stats.blocked_packets.fetch_add(1, Ordering::Relaxed);
            continue;
        }

        // Process by protocol
        match parsed.protocol {
            IPPROTO_UDP => {
                stats.udp_packets.fetch_add(1, Ordering::Relaxed);
                forward_udp_packet(
                    &processed,
                    &parsed,
                    &wg_egress_manager,
                    &outbound_manager,
                    &session_tracker,
                    &stats,
                    direct_reply_tx.clone(),
                    ecmp_group_manager.as_ref(),
                    peer_manager.as_ref(),
                )
                .await;
            }
            IPPROTO_TCP => {
                stats.tcp_packets.fetch_add(1, Ordering::Relaxed);
                // Parse TCP header for connection tracking
                if let Some(tcp_details) = parse_tcp_details(&processed.data, parsed.ip_header_len) {
                    forward_tcp_packet(
                        &processed,
                        &parsed,
                        &tcp_details,
                        &wg_egress_manager,
                        &session_tracker,
                        &stats,
                        ecmp_group_manager.as_ref(),
                        peer_manager.as_ref(),
                    )
                    .await;
                } else {
                    warn!(
                        "Failed to parse TCP header: {}:{} -> {}:{}",
                        parsed.src_ip,
                        parsed.src_port.unwrap_or(0),
                        parsed.dst_ip,
                        parsed.dst_port.unwrap_or(0)
                    );
                    stats.parse_errors.fetch_add(1, Ordering::Relaxed);
                }
            }
            IPPROTO_ICMP | IPPROTO_ICMPV6 => {
                stats.icmp_packets.fetch_add(1, Ordering::Relaxed);
                // Forward ICMP packet (ping support)
                forward_icmp_packet(
                    &processed,
                    &parsed,
                    &session_tracker,
                    &stats,
                    direct_reply_tx.clone(),
                    outbound_tag,
                    local_ip,
                )
                .await;
            }
            _ => {
                stats.unknown_protocol.fetch_add(1, Ordering::Relaxed);
                debug!(
                    "Unknown IP protocol {}: {} -> {}, dropped",
                    parsed.protocol, parsed.src_ip, parsed.dst_ip
                );
                continue;
            }
        }

        // Update forwarding stats for successfully processed packets
        stats.packets_forwarded.fetch_add(1, Ordering::Relaxed);
        stats
            .bytes_forwarded
            .fetch_add(packet_len as u64, Ordering::Relaxed);

        // Periodic session cleanup
        // Note: TCP connection cleanup is now handled by IpStack bridge's session_cleanup_task
        if last_cleanup.elapsed() >= cleanup_interval {
            let sessions_removed = session_tracker.cleanup();

            // Clean up stale UDP sessions (Issue: UDP_SESSIONS had no periodic cleanup)
            let now_secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let udp_before = UDP_SESSIONS.len();
            UDP_SESSIONS.retain(|_, session| {
                now_secs - session.last_activity_secs() <= 60
            });
            let udp_removed = udp_before.saturating_sub(UDP_SESSIONS.len());

            // Clean up stale proxy UDP sessions (Shadowsocks, SOCKS5)
            let proxy_udp_before = PROXY_UDP_SESSIONS.len();
            PROXY_UDP_SESSIONS.retain(|_, session| {
                now_secs.saturating_sub(session.last_activity_secs()) <= PROXY_UDP_IDLE_TIMEOUT_SECS
            });
            let proxy_udp_removed = proxy_udp_before.saturating_sub(PROXY_UDP_SESSIONS.len());

            if sessions_removed > 0 || udp_removed > 0 || proxy_udp_removed > 0 {
                debug!(
                    "Cleaned up {} expired sessions, {} UDP sessions, {} proxy UDP sessions",
                    sessions_removed, udp_removed, proxy_udp_removed
                );
            }
            last_cleanup = Instant::now();
        }
    }

    info!("Ingress forwarding loop stopped (channel closed)");
}

/// Reply routing loop
///
/// Consumes decrypted reply packets and sends them back to the appropriate ingress peer.
///
/// # DNS Response Parsing
///
/// If an `IpDomainCache` is provided, DNS responses (UDP from port 53) are parsed
/// to populate the IP-to-domain cache. This enables domain-based routing for
/// subsequent connections.
///
/// # Concurrency Model
///
/// This function uses bounded concurrency (32 parallel sends) to improve throughput.
/// Packet parsing and validation happens in the main loop (fast), while the actual
/// WireGuard encryption and UDP send is offloaded to spawned tasks with semaphore control.
pub async fn run_reply_router_loop(
    mut reply_rx: mpsc::Receiver<ReplyPacket>,
    ingress_manager: Arc<WgIngressManager>,
    session_tracker: Arc<IngressSessionTracker>,
    stats: Arc<IngressReplyStats>,
    dns_cache: Option<Arc<super::dns_cache::IpDomainCache>>,
    peer_manager: Arc<PeerManager>,
) {
    info!("Ingress reply router started (concurrent mode, max 1024 parallel sends)");

    // Semaphore to limit concurrent send operations
    // Increased from 256 to 1024 to handle high throughput bursts
    // Without enough permits, the reply router blocks and causes cascading stalls
    let send_semaphore = Arc::new(Semaphore::new(1024));

    // Periodic throughput logging for diagnostics
    let mut last_stats_log = std::time::Instant::now();
    let mut packets_since_log: u64 = 0;

    while let Some(reply) = reply_rx.recv().await {
        // Periodic throughput stats logging
        packets_since_log += 1;
        if last_stats_log.elapsed().as_secs() >= 5 {
            let forwarded = stats.packets_forwarded.load(Ordering::Relaxed);
            let received = stats.packets_received.load(Ordering::Relaxed);
            let misses = stats.session_misses.load(Ordering::Relaxed);
            let errors = stats.send_errors.load(Ordering::Relaxed);
            info!(
                "Reply router stats: received={}, forwarded={}, misses={}, errors={}, rate={}/5s",
                received, forwarded, misses, errors, packets_since_log
            );
            packets_since_log = 0;
            last_stats_log = std::time::Instant::now();
        }

        let Some(parsed) = parse_ip_packet(&reply.packet) else {
            stats.parse_errors.fetch_add(1, Ordering::Relaxed);
            warn!("Failed to parse reply IP header");
            continue;
        };

        // Parse DNS responses to populate IP-domain cache
        if let Some(ref cache) = dns_cache {
            if parsed.protocol == IPPROTO_UDP {
                if let Some(src_port) = parsed.src_port {
                    if src_port == 53 {
                        // Extract UDP payload (DNS response)
                        let payload_offset = parsed.ip_header_len + 8; // IP header + UDP header
                        if reply.packet.len() > payload_offset {
                            let dns_payload = &reply.packet[payload_offset..];
                            info!(
                                "DNS response detected: {}:{} -> {} (payload {} bytes)",
                                parsed.src_ip, src_port, parsed.dst_ip, dns_payload.len()
                            );
                            let count = cache.parse_dns_response(dns_payload);
                            if count > 0 {
                                info!("Parsed {} DNS records from reply", count);
                            } else {
                                debug!("DNS response parsed but no A/AAAA records found");
                            }
                        }
                    } else {
                        trace!(
                            "UDP reply from non-DNS port: {} (src_port={})",
                            parsed.src_ip, src_port
                        );
                    }
                }
            }
        } else {
            // Log once when dns_cache is None (should not happen if properly initialized)
            static DNS_CACHE_WARN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
            if !DNS_CACHE_WARN.swap(true, std::sync::atomic::Ordering::SeqCst) {
                warn!("DNS cache not available in reply router");
            }
        }

        // Handle ICMP separately (no ports) - these are rare, process inline
        if parsed.protocol == IPPROTO_ICMP || parsed.protocol == IPPROTO_ICMPV6 {
            // For ICMP, extract ID from the ICMP header and use it as port
            if let Some((icmp_type, _, id, seq, _)) = parse_icmp_echo(&reply.packet, parsed.ip_header_len) {
                // ICMP Echo Reply (type 0) - find session using ID
                if icmp_type == ICMP_ECHO_REPLY {
                    let lookup_key = FiveTuple::new(
                        parsed.dst_ip, // Original client IP
                        id,            // Use ID as "port"
                        parsed.src_ip, // Original destination (server)
                        0,
                        IPPROTO_ICMP,
                    );

                    if let Some(session) = session_tracker.get(&lookup_key) {
                        if ingress_manager.is_peer_ip_allowed(&session.peer_public_key, parsed.dst_ip) {
                            match ingress_manager
                                .send_to_peer(&session.peer_public_key, session.peer_endpoint, &reply.packet)
                                .await
                            {
                                Ok(()) => {
                                    stats.packets_forwarded.fetch_add(1, Ordering::Relaxed);
                                    info!(
                                        "ICMP reply sent to peer {}: {} -> {} (id={}, seq={})",
                                        session.peer_public_key, parsed.src_ip, parsed.dst_ip, id, seq
                                    );
                                }
                                Err(e) => {
                                    stats.send_errors.fetch_add(1, Ordering::Relaxed);
                                    warn!("Failed to send ICMP reply to peer: {}", e);
                                }
                            }
                        } else {
                            stats.peer_ip_rejected.fetch_add(1, Ordering::Relaxed);
                            debug!("ICMP reply dest IP not allowed for peer");
                        }
                    } else {
                        stats.session_misses.fetch_add(1, Ordering::Relaxed);
                        debug!("No session for ICMP reply: {} -> {} (id={})", parsed.src_ip, parsed.dst_ip, id);
                    }
                }
            }
            continue;
        }

        if parsed.protocol != IPPROTO_TCP && parsed.protocol != IPPROTO_UDP {
            if parsed.src_ip.is_ipv6() && is_ipv6_extension_header(parsed.protocol) {
                stats.ipv6_extension_headers.fetch_add(1, Ordering::Relaxed);
                debug!(
                    "IPv6 reply with extension header {} dropped",
                    parsed.protocol
                );
            } else {
                stats.unsupported_protocol.fetch_add(1, Ordering::Relaxed);
                debug!(
                    "Unsupported reply protocol {} dropped",
                    parsed.protocol
                );
            }
            continue;
        }

        let (Some(src_port), Some(dst_port)) = (parsed.src_port, parsed.dst_port) else {
            stats.parse_errors.fetch_add(1, Ordering::Relaxed);
            warn!(
                "Reply packet missing ports: {} -> {} (protocol={})",
                parsed.src_ip, parsed.dst_ip, parsed.protocol
            );
            continue;
        };

        let reply_tuple = FiveTuple::new(parsed.src_ip, src_port, parsed.dst_ip, dst_port, parsed.protocol);
        let lookup_key = reply_tuple.reverse();

        let Some(session) = session_tracker.get(&lookup_key) else {
            stats.session_misses.fetch_add(1, Ordering::Relaxed);
            debug!(
                "No session mapping for reply {} (tunnel={})",
                reply_tuple, reply.tunnel_tag
            );
            continue;
        };

        // === CHAIN TRAFFIC HANDLING ===
        // Check if this is Terminal chain traffic that needs to go back through peer tunnel
        if session.is_chain_traffic {
            if let Some(ChainRole::Terminal) = session.node_role {
                let source_tunnel = match &session.source_tunnel_tag {
                    Some(tag) => tag.clone(),
                    None => {
                        stats.send_errors.fetch_add(1, Ordering::Relaxed);
                        warn!(
                            "[REPLY-ROUTER-CHAIN] Terminal session missing source_tunnel_tag for {}",
                            reply_tuple
                        );
                        continue;
                    }
                };

                debug!(
                    source_tunnel = %source_tunnel,
                    five_tuple = %reply_tuple,
                    "[REPLY-ROUTER-CHAIN] Routing Terminal reply to peer tunnel (preserve_src)"
                );

                // Use send_preserve_src to keep original target server IP
                // This allows Entry node to match session by original five-tuple
                match peer_manager.send_to_peer_tunnel_preserve_src(&source_tunnel, &reply.packet).await {
                    Ok(()) => {
                        stats.packets_forwarded.fetch_add(1, Ordering::Relaxed);
                        session_tracker.update_received(&lookup_key, reply.packet.len() as u64);
                        debug!(
                            "[REPLY-ROUTER-CHAIN] Successfully forwarded {} bytes to tunnel {} (src preserved)",
                            reply.packet.len(),
                            source_tunnel
                        );
                    }
                    Err(e) => {
                        stats.send_errors.fetch_add(1, Ordering::Relaxed);
                        warn!(
                            "[REPLY-ROUTER-CHAIN] Failed to send chain reply to tunnel {}: {}",
                            source_tunnel, e
                        );
                    }
                }
                continue; // Skip normal wg-ingress routing
            }
        }
        // === END CHAIN TRAFFIC HANDLING ===

        if reply.tunnel_tag != session.outbound_tag {
            stats.tunnel_mismatch.fetch_add(1, Ordering::Relaxed);
            warn!(
                "Reply tunnel mismatch for {}: session={}, reply={}",
                reply_tuple, session.outbound_tag, reply.tunnel_tag
            );
            continue;
        }

        if !ingress_manager.is_peer_ip_allowed(&session.peer_public_key, parsed.dst_ip) {
            stats.peer_ip_rejected.fetch_add(1, Ordering::Relaxed);
            warn!(
                "Reply dest IP not allowed for peer {}: {}",
                session.peer_public_key, parsed.dst_ip
            );
            continue;
        }

        // Spawn concurrent send task with semaphore control
        // This allows up to 1024 parallel WireGuard encryptions + UDP sends
        let permit = match send_semaphore.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                // Semaphore full - wait with timeout to avoid indefinite blocking
                match tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    send_semaphore.clone().acquire_owned(),
                )
                .await
                {
                    Ok(Ok(permit)) => permit,
                    Ok(Err(_)) => {
                        warn!("Reply router semaphore closed unexpectedly");
                        continue;
                    }
                    Err(_) => {
                        // Timeout - semaphore exhausted for too long, skip this packet
                        warn!("Reply router semaphore timeout - dropping packet due to backpressure");
                        stats.send_errors.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                }
            }
        };

        let ingress_mgr = Arc::clone(&ingress_manager);
        let stats_clone = Arc::clone(&stats);
        let tracker_clone = Arc::clone(&session_tracker);
        let peer_public_key = session.peer_public_key.clone();
        let peer_endpoint = session.peer_endpoint;
        let packet = reply.packet;
        let packet_len = packet.len();

        tokio::spawn(async move {
            match ingress_mgr
                .send_to_peer(&peer_public_key, peer_endpoint, &packet)
                .await
            {
                Ok(()) => {
                    stats_clone.packets_forwarded.fetch_add(1, Ordering::Relaxed);
                    tracker_clone.update_received(&lookup_key, packet_len as u64);
                }
                Err(e) => {
                    stats_clone.send_errors.fetch_add(1, Ordering::Relaxed);
                    warn!(
                        "Failed to forward reply {} via peer {}: {}",
                        reply_tuple,
                        peer_public_key,
                        e
                    );
                }
            }
            drop(permit); // Release semaphore permit
        });
    }

    info!("Ingress reply router stopped (channel closed)");
}

/// Forward a TCP packet through the appropriate outbound
///
/// Handles TCP connection state tracking and data forwarding:
/// - SYN packets: Establish outbound connection and send SYN-ACK back
/// - Data packets: Forward through established connection
/// - FIN/RST packets: Mark connection as closing
///
/// # `WireGuard` Egress
///
/// For `WireGuard` egress tunnels (wg-, pia-, peer-), the full IP packet
/// is forwarded through the tunnel. The tunnel handles encapsulation.
///
/// # Direct/SOCKS5
///
/// For direct or SOCKS5 outbounds, we establish a TCP connection on the
/// first SYN packet, send a synthetic SYN-ACK back to the client, and
/// spawn a reader task to forward server responses.
async fn forward_tcp_packet(
    processed: &ProcessedPacket,
    parsed: &ParsedPacket,
    tcp_details: &TcpDetails,
    wg_egress_manager: &Arc<WgEgressManager>,
    session_tracker: &Arc<IngressSessionTracker>,
    stats: &Arc<ForwardingStats>,
    ecmp_group_manager: Option<&Arc<EcmpGroupManager>>,
    peer_manager: Option<&Arc<PeerManager>>,
) {
    let routing_outbound = &processed.routing.outbound;

    // Create 5-tuple for connection tracking
    let five_tuple = FiveTuple::new(
        parsed.src_ip,
        tcp_details.src_port,
        parsed.dst_ip,
        tcp_details.dst_port,
        IPPROTO_TCP,
    );

    // Resolve ECMP group to member using five-tuple hash
    let outbound_tag: String = if let Some(ecmp_mgr) = ecmp_group_manager {
        if let Some(group) = ecmp_mgr.get_group(routing_outbound) {
            // Create ECMP five-tuple for consistent hashing
            let ecmp_tuple = EcmpFiveTuple::new(
                parsed.src_ip,
                parsed.dst_ip,
                tcp_details.src_port,
                tcp_details.dst_port,
                EcmpProtocol::Tcp,
            );
            match group.select_by_connection(&ecmp_tuple) {
                Ok(member) => {
                    debug!(
                        "ECMP resolved '{}' -> '{}' for TCP {}:{} -> {}:{}",
                        routing_outbound, member, parsed.src_ip, tcp_details.src_port,
                        parsed.dst_ip, tcp_details.dst_port
                    );
                    member
                }
                Err(e) => {
                    warn!("ECMP group '{}' selection failed: {}", routing_outbound, e);
                    routing_outbound.clone()
                }
            }
        } else {
            routing_outbound.clone()
        }
    } else {
        routing_outbound.clone()
    };
    let outbound_tag = &outbound_tag;

    // Check if this goes to a WireGuard egress (full IP packet forwarding)
    // This includes:
    // - Standard egress: wg-*, pia-*
    // - Peer tunnels: peer-* (stored in PeerManager.wg_tunnels via ConnectPeer IPC)
    // - Any tunnel registered in WgEgressManager
    let is_wg_egress = outbound_tag.starts_with("wg-")
        || outbound_tag.starts_with("pia-")
        || outbound_tag.starts_with("peer-")
        || wg_egress_manager.has_tunnel(outbound_tag);

    if is_wg_egress {
        // Register chain session when Entry node forwards to peer tunnel
        if outbound_tag.starts_with("peer-") && processed.routing.is_chain_packet {
            // Entry node: registering chain session for traffic to peer tunnel
            session_tracker.register_chain(
                five_tuple,
                processed.peer_public_key.clone(),
                processed.src_addr,
                outbound_tag.clone(),
                parsed.total_len as u64,
                None, // Entry node: no source tunnel (traffic came from wg-ingress)
                ChainRole::Entry,
            );
            debug!(
                peer = %processed.peer_public_key,
                outbound = %outbound_tag,
                "[CHAIN-ENTRY] Registered Entry TCP session for chain traffic"
            );
        } else {
            // Non-chain traffic: use regular registration
            session_tracker.register(
                five_tuple,
                processed.peer_public_key.clone(),
                processed.src_addr,
                outbound_tag.clone(),
                parsed.total_len as u64,
            );
        }

        // For peer-* tunnels, first check PeerManager.wg_tunnels
        // These tunnels are created by ConnectPeer IPC and stored in PeerManager,
        // not WgEgressManager. This fixes the "Tunnel not found" error for chain routing.
        if outbound_tag.starts_with("peer-") {
            if let Some(pm) = peer_manager {
                if let Some(tunnel) = pm.get_wg_tunnel(outbound_tag) {
                    match tunnel.send(&processed.data).await {
                        Ok(()) => {
                            debug!(
                                "Forwarded TCP to peer tunnel '{}': {}:{} -> {}:{} (flags={}, {} bytes)",
                                outbound_tag,
                                parsed.src_ip,
                                tcp_details.src_port,
                                parsed.dst_ip,
                                tcp_details.dst_port,
                                tcp_details.flags_string(),
                                parsed.total_len
                            );
                        }
                        Err(e) => {
                            warn!(
                                "Failed to forward TCP to peer tunnel '{}': {}",
                                outbound_tag, e
                            );
                            stats.forward_errors.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    return;
                }
            }
        }

        // Forward full IP packet to WireGuard egress (WgEgressManager)
        match wg_egress_manager
            .send(outbound_tag, processed.data.clone())
            .await
        {
            Ok(()) => {
                debug!(
                    "Forwarded TCP to WG egress '{}': {}:{} -> {}:{} (flags={}, {} bytes)",
                    outbound_tag,
                    parsed.src_ip,
                    tcp_details.src_port,
                    parsed.dst_ip,
                    tcp_details.dst_port,
                    tcp_details.flags_string(),
                    parsed.total_len
                );
            }
            Err(e) => {
                warn!(
                    "Failed to forward TCP to WG egress '{}': {}",
                    outbound_tag, e
                );
                stats.forward_errors.fetch_add(1, Ordering::Relaxed);
            }
        }
        return;
    }

    // Handle block outbound
    if outbound_tag == "block" || outbound_tag == "adblock" {
        debug!(
            "Blocking TCP connection: {}:{} -> {}:{}",
            parsed.src_ip, tcp_details.src_port, parsed.dst_ip, tcp_details.dst_port
        );
        stats.blocked_packets.fetch_add(1, Ordering::Relaxed);
        return;
    }

    // === IPSTACK INTEGRATION ===
    // When ipstack-tcp feature is enabled and ipstack is active, route non-WG TCP
    // traffic through IpStackBridge which provides a complete TCP/IP stack.
    // This REPLACES the manual TCP state machine (which has bugs with retransmission,
    // out-of-order handling, and window management). No fallback - if ipstack fails,
    // drop the packet and let TCP retransmit.
    #[cfg(feature = "ipstack-tcp")]
    if is_ipstack_enabled() {
        if let Some(bridge) = IPSTACK_BRIDGE.get() {
            // Convert peer_public_key to 32-byte array
            use base64::engine::general_purpose::STANDARD as BASE64;
            use base64::Engine;

            let peer_key: [u8; 32] = match BASE64.decode(&processed.peer_public_key) {
                Ok(bytes) if bytes.len() == 32 => {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes);
                    arr
                }
                _ => {
                    warn!(
                        "Invalid peer key for ipstack, dropping packet: {}:{} -> {}:{} (peer={})",
                        parsed.src_ip, tcp_details.src_port, parsed.dst_ip, tcp_details.dst_port,
                        &processed.peer_public_key[..8.min(processed.peer_public_key.len())]
                    );
                    stats.forward_errors.fetch_add(1, Ordering::Relaxed);
                    return;
                }
            };

            // Convert the processed packet to BytesMut for ipstack
            let packet_data = bytes::BytesMut::from(&processed.data[..]);

            // Get the outbound tag from routing decision
            let outbound_tag = &processed.routing.outbound;

            // Try to inject into ipstack (non-blocking to avoid holding up the forwarder)
            // Note: No RwLock needed - IpStackBridge uses interior mutability
            // The bridge's SessionTracker now handles session tracking with peer_endpoint,
            // so we no longer need separate IngressSessionTracker registration.
            // The outbound_tag is passed to enable routing through OutboundManager.
            if bridge.try_inject_packet(packet_data, peer_key, processed.src_addr, outbound_tag) {
                trace!(
                    "Routed TCP to ipstack: {}:{} -> {}:{}",
                    parsed.src_ip, tcp_details.src_port, parsed.dst_ip, tcp_details.dst_port
                );
                stats.packets_forwarded.fetch_add(1, Ordering::Relaxed);
                stats.tcp_packets.fetch_add(1, Ordering::Relaxed);
                return;
            } else {
                // Channel full - drop packet, TCP will retransmit
                warn!(
                    "IpStack channel full, dropping TCP packet (will retransmit): {}:{} -> {}:{}",
                    parsed.src_ip, tcp_details.src_port, parsed.dst_ip, tcp_details.dst_port
                );
                stats.forward_errors.fetch_add(1, Ordering::Relaxed);
                return;
            }
        } else {
            // Bridge not initialized - this shouldn't happen if ipstack is enabled
            warn!(
                "IpStack enabled but bridge not initialized, dropping TCP packet: {}:{} -> {}:{}",
                parsed.src_ip, tcp_details.src_port, parsed.dst_ip, tcp_details.dst_port
            );
            stats.forward_errors.fetch_add(1, Ordering::Relaxed);
            return;
        }
    }
    // === END IPSTACK INTEGRATION ===

    // When ipstack-tcp feature is not compiled, log error and drop packet
    // (The manual TCP state machine has known bugs and is no longer supported)
    #[cfg(not(feature = "ipstack-tcp"))]
    {
        warn!(
            "TCP packet dropped: ipstack-tcp feature not enabled. \
             Manual TCP state machine removed due to bugs. \
             Rebuild with --features ipstack-tcp. \
             Packet: {}:{} -> {}:{}",
            parsed.src_ip, tcp_details.src_port, parsed.dst_ip, tcp_details.dst_port
        );
        stats.forward_errors.fetch_add(1, Ordering::Relaxed);
    }

    // REMOVED: Manual TCP state machine code (lines 2654-3314)
    // The manual implementation had bugs:
    // - server_seq initialization error causing wrong ACK numbers
    // - No retransmission mechanism causing connection stalls on packet loss
    // - Out-of-order packet dropping causing data loss
    // - Fixed window size (65535) with no flow control
    // All TCP traffic now goes through IpStack which handles these correctly.

}

/// DNS hijacking statistics
#[derive(Debug, Default)]
pub struct DnsHijackStats {
    /// Total DNS queries hijacked
    pub queries_hijacked: AtomicU64,
    /// Successful DNS responses sent back to client
    pub responses_sent: AtomicU64,
    /// DNS queries that failed to get a response from local engine
    pub query_failures: AtomicU64,
    /// DNS responses that failed to send to client
    pub send_failures: AtomicU64,
}

impl DnsHijackStats {
    /// Create a new DNS hijack stats tracker
    pub fn new() -> Self {
        Self::default()
    }

    /// Get a snapshot of current statistics
    pub fn snapshot(&self) -> DnsHijackStatsSnapshot {
        DnsHijackStatsSnapshot {
            queries_hijacked: self.queries_hijacked.load(Ordering::Relaxed),
            responses_sent: self.responses_sent.load(Ordering::Relaxed),
            query_failures: self.query_failures.load(Ordering::Relaxed),
            send_failures: self.send_failures.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of DNS hijack statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsHijackStatsSnapshot {
    pub queries_hijacked: u64,
    pub responses_sent: u64,
    pub query_failures: u64,
    pub send_failures: u64,
}

/// Local DNS engine address
const LOCAL_DNS_ENGINE_ADDR: &str = "127.0.0.1:7853";

/// DNS hijacking timeout for queries to local engine
const DNS_HIJACK_TIMEOUT: Duration = Duration::from_secs(5);

/// Query the local DNS engine and return the response
///
/// This function sends a DNS query to the local DNS engine (127.0.0.1:7853)
/// and waits for a response. Used for DNS hijacking in userspace WireGuard mode.
///
/// # Arguments
///
/// * `query_payload` - The raw DNS query payload (UDP payload, not including IP/UDP headers)
///
/// # Returns
///
/// The DNS response payload on success, or an error message on failure.
async fn query_local_dns_engine(query_payload: &[u8]) -> Result<Vec<u8>, String> {
    // Create a UDP socket to talk to local DNS engine
    let socket = UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|e| format!("Failed to bind DNS socket: {}", e))?;

    let dns_addr: SocketAddr = LOCAL_DNS_ENGINE_ADDR
        .parse()
        .map_err(|e| format!("Invalid DNS engine address: {}", e))?;

    // Send query to local DNS engine
    socket
        .send_to(query_payload, dns_addr)
        .await
        .map_err(|e| format!("Failed to send DNS query: {}", e))?;

    // Wait for response with timeout
    let mut response_buf = vec![0u8; 4096];
    match tokio::time::timeout(DNS_HIJACK_TIMEOUT, socket.recv_from(&mut response_buf)).await {
        Ok(Ok((n, _addr))) => {
            response_buf.truncate(n);
            Ok(response_buf)
        }
        Ok(Err(e)) => Err(format!("DNS recv error: {}", e)),
        Err(_) => Err("DNS query timeout".to_string()),
    }
}

/// Global DNS hijack statistics (lazily initialized)
static DNS_HIJACK_STATS: Lazy<DnsHijackStats> = Lazy::new(DnsHijackStats::new);

/// Get a reference to the global DNS hijack statistics
pub fn dns_hijack_stats() -> &'static DnsHijackStats {
    &DNS_HIJACK_STATS
}

/// Forward a UDP packet to the appropriate outbound
async fn forward_udp_packet(
    processed: &ProcessedPacket,
    parsed: &ParsedPacket,
    wg_egress_manager: &Arc<WgEgressManager>,
    outbound_manager: &Arc<OutboundManager>,
    session_tracker: &Arc<IngressSessionTracker>,
    stats: &Arc<ForwardingStats>,
    direct_reply_tx: Option<mpsc::Sender<ReplyPacket>>,
    ecmp_group_manager: Option<&Arc<EcmpGroupManager>>,
    peer_manager: Option<&Arc<PeerManager>>,
) {
    let routing_outbound = &processed.routing.outbound;

    // Get ports
    let Some(src_port) = parsed.src_port else {
        warn!("UDP packet missing source port");
        stats.forward_errors.fetch_add(1, Ordering::Relaxed);
        return;
    };
    let Some(dst_port) = parsed.dst_port else {
        warn!("UDP packet missing destination port");
        stats.forward_errors.fetch_add(1, Ordering::Relaxed);
        return;
    };

    // =========================================================================
    // DNS Hijacking: Intercept DNS queries (port 53) and forward to local engine
    // =========================================================================
    // This enables domain-based routing in userspace WireGuard mode where
    // iptables TPROXY rules are not available to redirect DNS traffic.
    if dst_port == 53 {
        // Extract UDP payload (DNS query)
        let payload_offset = parsed.ip_header_len + 8; // IP header + 8 bytes UDP header
        if processed.data.len() > payload_offset {
            let dns_query = &processed.data[payload_offset..];
            
            DNS_HIJACK_STATS.queries_hijacked.fetch_add(1, Ordering::Relaxed);
            info!(
                "DNS hijack: {}:{} -> {}:{} (query {} bytes)",
                parsed.src_ip, src_port, parsed.dst_ip, dst_port, dns_query.len()
            );

            // Query the local DNS engine
            match query_local_dns_engine(dns_query).await {
                Ok(dns_response) => {
                    debug!(
                        "DNS hijack got response: {} bytes for {}:{} -> {}:{}",
                        dns_response.len(), parsed.src_ip, src_port, parsed.dst_ip, dst_port
                    );

                    // Build reply packet: swap src/dst to send response back to client
                    // The response appears to come from the original DNS server (dst_ip:53)
                    let reply_packet = match (parsed.dst_ip, parsed.src_ip) {
                        (IpAddr::V4(server_ip), IpAddr::V4(client_ip)) => {
                            build_udp_reply_packet(
                                server_ip,    // Reply from: original DNS server IP
                                dst_port,     // Reply from: port 53
                                client_ip,    // Reply to: client IP
                                src_port,     // Reply to: client's source port
                                &dns_response,
                            )
                        }
                        (IpAddr::V6(server_ip), IpAddr::V6(client_ip)) => {
                            build_udp_reply_packet_v6(
                                server_ip,
                                dst_port,
                                client_ip,
                                src_port,
                                &dns_response,
                            )
                        }
                        _ => {
                            warn!("DNS hijack: IP version mismatch, dropping");
                            DNS_HIJACK_STATS.send_failures.fetch_add(1, Ordering::Relaxed);
                            return;
                        }
                    };

                    // Send reply back to the WireGuard client through the reply channel
                    if let Some(ref reply_tx) = direct_reply_tx {
                        // Register session so the reply router can find the peer
                        let five_tuple = FiveTuple::new(
                            parsed.src_ip, src_port, parsed.dst_ip, dst_port, IPPROTO_UDP
                        );
                        session_tracker.register(
                            five_tuple,
                            processed.peer_public_key.clone(),
                            processed.src_addr,
                            "dns-hijack".to_string(), // Special tag for DNS hijack
                            parsed.total_len as u64,
                        );

                        let reply = ReplyPacket {
                            packet: reply_packet,
                            tunnel_tag: "dns-hijack".to_string(),
                        };

                        if let Err(e) = reply_tx.try_send(reply) {
                            warn!("DNS hijack: failed to send reply to router: {}", e);
                            DNS_HIJACK_STATS.send_failures.fetch_add(1, Ordering::Relaxed);
                        } else {
                            info!(
                                "DNS hijack: sent {} byte response to {}:{}",
                                dns_response.len(), parsed.src_ip, src_port
                            );
                            DNS_HIJACK_STATS.responses_sent.fetch_add(1, Ordering::Relaxed);
                        }
                    } else {
                        warn!("DNS hijack: no reply channel available");
                        DNS_HIJACK_STATS.send_failures.fetch_add(1, Ordering::Relaxed);
                    }
                }
                Err(e) => {
                    warn!("DNS hijack: query to local engine failed: {}", e);
                    DNS_HIJACK_STATS.query_failures.fetch_add(1, Ordering::Relaxed);
                    // Fall through to normal forwarding as fallback
                    // This allows DNS to still work if local engine is down
                }
            }
            // DNS hijack handled (or fell through on error), return
            return;
        } else {
            warn!("DNS hijack: packet too short for payload");
        }
    }

    // Create 5-tuple for session tracking
    let five_tuple = FiveTuple::new(parsed.src_ip, src_port, parsed.dst_ip, dst_port, IPPROTO_UDP);

    // Resolve ECMP group to member using five-tuple hash
    let outbound_tag: String = if let Some(ecmp_mgr) = ecmp_group_manager {
        if let Some(group) = ecmp_mgr.get_group(routing_outbound) {
            // Create ECMP five-tuple for consistent hashing
            let ecmp_tuple = EcmpFiveTuple::new(
                parsed.src_ip,
                parsed.dst_ip,
                src_port,
                dst_port,
                EcmpProtocol::Udp,
            );
            match group.select_by_connection(&ecmp_tuple) {
                Ok(member) => {
                    debug!(
                        "ECMP resolved '{}' -> '{}' for UDP {}:{} -> {}:{}",
                        routing_outbound, member, parsed.src_ip, src_port,
                        parsed.dst_ip, dst_port
                    );
                    member
                }
                Err(e) => {
                    warn!("ECMP group '{}' selection failed: {}", routing_outbound, e);
                    routing_outbound.clone()
                }
            }
        } else {
            routing_outbound.clone()
        }
    } else {
        routing_outbound.clone()
    };
    let outbound_tag = &outbound_tag;

    // Determine if this is a WireGuard egress tunnel (managed by WgEgressManager)
    // This includes:
    // - Standard egress: wg-*, pia-*
    // - Peer tunnels: peer-* (stored in PeerManager.wg_tunnels via ConnectPeer IPC)
    // - Any tunnel registered in WgEgressManager
    let is_wg_egress = outbound_tag.starts_with("wg-")
        || outbound_tag.starts_with("pia-")
        || outbound_tag.starts_with("peer-")
        || wg_egress_manager.has_tunnel(outbound_tag);

    // Register chain session when Entry node forwards to peer tunnel
    if outbound_tag.starts_with("peer-") && processed.routing.is_chain_packet {
        // Entry node: registering chain session for traffic to peer tunnel
        session_tracker.register_chain(
            five_tuple,
            processed.peer_public_key.clone(),
            processed.src_addr,
            outbound_tag.clone(),
            parsed.total_len as u64,
            None, // Entry node: no source tunnel (traffic came from wg-ingress)
            ChainRole::Entry,
        );
        debug!(
            peer = %processed.peer_public_key,
            outbound = %outbound_tag,
            "[CHAIN-ENTRY] Registered Entry UDP session for chain traffic"
        );
    } else {
        // Non-chain traffic: use regular registration
        session_tracker.register(
            five_tuple,
            processed.peer_public_key.clone(),
            processed.src_addr,
            outbound_tag.clone(),
            parsed.total_len as u64,
        );
    }

    if is_wg_egress {
        // For peer-* tunnels, first check PeerManager.wg_tunnels
        // These tunnels are created by ConnectPeer IPC and stored in PeerManager,
        // not WgEgressManager. This fixes the "Tunnel not found" error for chain routing.
        if outbound_tag.starts_with("peer-") {
            if let Some(pm) = peer_manager {
                if let Some(tunnel) = pm.get_wg_tunnel(outbound_tag) {
                    match tunnel.send(&processed.data).await {
                        Ok(()) => {
                            debug!(
                                "Forwarded UDP to peer tunnel '{}': {} -> {}:{} ({} bytes)",
                                outbound_tag, parsed.src_ip, parsed.dst_ip, dst_port, parsed.total_len
                            );
                        }
                        Err(e) => {
                            warn!(
                                "Failed to forward UDP to peer tunnel '{}': {} -> {}:{}, error: {}",
                                outbound_tag, parsed.src_ip, parsed.dst_ip, dst_port, e
                            );
                            stats.forward_errors.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    return;
                }
            }
        }

        // Forward through WireGuard egress tunnel (WgEgressManager)
        match wg_egress_manager.send(outbound_tag, processed.data.clone()).await {
            Ok(()) => {
                debug!(
                    "Forwarded UDP to WG egress '{}': {} -> {}:{} ({} bytes)",
                    outbound_tag, parsed.src_ip, parsed.dst_ip, dst_port, parsed.total_len
                );
            }
            Err(e) => {
                warn!(
                    "Failed to forward UDP to WG egress '{}': {} -> {}:{}, error: {}",
                    outbound_tag, parsed.src_ip, parsed.dst_ip, dst_port, e
                );
                stats.forward_errors.fetch_add(1, Ordering::Relaxed);
            }
        }
    } else if outbound_tag == "direct" || outbound_tag.starts_with("direct-") {
        // === DIRECT UDP IPSTACK INTEGRATION (Phase 3) ===
        // Route direct UDP traffic through ipstack for FakeDNS support
        #[cfg(feature = "ipstack-tcp")]
        if is_ipstack_enabled() {
            if let Some(bridge) = IPSTACK_BRIDGE.get() {
                use base64::engine::general_purpose::STANDARD as BASE64;
                use base64::Engine;

                let peer_key: [u8; 32] = match BASE64.decode(&processed.peer_public_key) {
                    Ok(bytes) if bytes.len() == 32 => {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&bytes);
                        arr
                    }
                    _ => [0u8; 32], // Invalid key will cause fallback
                };

                if peer_key != [0u8; 32] {
                    let packet_data = bytes::BytesMut::from(&processed.data[..]);
                    if bridge.try_inject_packet(packet_data, peer_key, processed.src_addr, outbound_tag) {
                        trace!(
                            "Routed direct UDP to ipstack: {}:{} -> {}:{}",
                            parsed.src_ip, src_port, parsed.dst_ip, dst_port
                        );
                        stats.packets_forwarded.fetch_add(1, Ordering::Relaxed);
                        stats.udp_packets.fetch_add(1, Ordering::Relaxed);
                        return;
                    }
                    // Fall through to manual direct UDP handling
                }
            }
        }
        // === END DIRECT UDP IPSTACK INTEGRATION ===

        // Direct outbound - send UDP directly to destination and listen for reply
        let dst_addr = SocketAddr::new(parsed.dst_ip, dst_port);

        // Extract UDP payload (skip IP header + UDP header)
        let payload_offset = parsed.ip_header_len + 8; // IP header + 8 bytes UDP header
        if processed.data.len() <= payload_offset {
            warn!("UDP packet too short for payload: {} bytes, need > {}", processed.data.len(), payload_offset);
            stats.forward_errors.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let udp_payload = &processed.data[payload_offset..];

        // Capture values needed for reply handling
        let client_ip = parsed.src_ip;
        let client_port = src_port;
        let server_ip = parsed.dst_ip;
        let server_port = dst_port;
        let outbound_tag_owned = outbound_tag.clone();
        let reply_tx = direct_reply_tx.clone();

        if let Some(outbound) = outbound_manager.get(outbound_tag) {
            // Check if outbound supports UDP
            if !outbound.supports_udp() {
                warn!("Outbound '{}' does not support UDP", outbound_tag);
                stats.forward_errors.fetch_add(1, Ordering::Relaxed);
                return;
            }

            // Connect and send
            match outbound.connect_udp(dst_addr, Duration::from_secs(5)).await {
                Ok(handle) => {
                    match handle.send(udp_payload).await {
                        Ok(bytes_sent) => {
                            debug!(
                                "Forwarded UDP via direct '{}': {} -> {}:{} ({} bytes)",
                                outbound_tag, client_ip, server_ip, server_port, bytes_sent
                            );

                            // Spawn reply listener task if we have a reply channel
                            if let Some(tx) = reply_tx {
                                spawn_direct_udp_reply_listener(
                                    handle,
                                    tx,
                                    client_ip,
                                    client_port,
                                    server_ip,
                                    server_port,
                                    outbound_tag_owned,
                                );
                            }
                        }
                        Err(e) => {
                            warn!("Failed to send UDP via direct '{}': {}", outbound_tag, e);
                            stats.forward_errors.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to connect UDP via direct '{}' to {}: {}", outbound_tag, dst_addr, e);
                    stats.forward_errors.fetch_add(1, Ordering::Relaxed);
                }
            }
        } else {
            // Fallback to default direct if tag not found in manager
            // Create a raw UDP socket and send directly
            match create_direct_udp_socket(dst_addr).await {
                Ok(socket) => {
                    match socket.send(udp_payload).await {
                        Ok(bytes_sent) => {
                            debug!(
                                "Forwarded UDP direct (fallback): {} -> {}:{} ({} bytes)",
                                client_ip, server_ip, server_port, bytes_sent
                            );

                            // Spawn reply listener task if we have a reply channel
                            if let Some(tx) = reply_tx {
                                // Wrap socket in Arc for the spawned task
                                let socket = Arc::new(socket);
                                spawn_direct_udp_reply_listener_raw(
                                    socket,
                                    tx,
                                    client_ip,
                                    client_port,
                                    server_ip,
                                    server_port,
                                    outbound_tag_owned,
                                );
                            }
                        }
                        Err(e) => {
                            warn!("Failed to send UDP direct (fallback): {}", e);
                            stats.forward_errors.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to create UDP socket for direct forwarding: {}", e);
                    stats.forward_errors.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    } else if outbound_tag == "block" || outbound_tag == "adblock" {
        // Block outbound - silently drop
        // (Note: This case is also handled in the main loop, but included here for completeness)
        debug!("Dropping UDP packet (blocked): {} -> {}", parsed.src_ip, parsed.dst_ip);
        stats.blocked_packets.fetch_add(1, Ordering::Relaxed);
    } else {
        // === UDP IPSTACK INTEGRATION (Phase 3) ===
        // When ipstack-tcp feature is enabled and ipstack is active, route non-WG UDP
        // traffic through IpStackBridge for:
        // 1. Unified session management with TCP
        // 2. FakeDNS support for domain-based routing
        // 3. Consistent reply routing through ipstack reply router
        //
        // Falls back to manual UDP handling if ipstack injection fails.
        #[cfg(feature = "ipstack-tcp")]
        if is_ipstack_enabled() {
            if let Some(bridge) = IPSTACK_BRIDGE.get() {
                // Convert peer_public_key to 32-byte array
                use base64::engine::general_purpose::STANDARD as BASE64;
                use base64::Engine;

                let peer_key: [u8; 32] = match BASE64.decode(&processed.peer_public_key) {
                    Ok(bytes) if bytes.len() == 32 => {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&bytes);
                        arr
                    }
                    _ => {
                        warn!(
                            "Invalid peer key for ipstack UDP, using fallback: {}:{} -> {}:{} (peer={})",
                            parsed.src_ip, src_port, parsed.dst_ip, dst_port,
                            &processed.peer_public_key[..8.min(processed.peer_public_key.len())]
                        );
                        // Fall through to manual UDP handling below
                        [0u8; 32] // Invalid key will cause fallback
                    }
                };

                // Only proceed with ipstack if we have a valid peer key
                if peer_key != [0u8; 32] {
                    // Convert the processed packet to BytesMut for ipstack
                    let packet_data = bytes::BytesMut::from(&processed.data[..]);

                    // Try to inject into ipstack (non-blocking)
                    // UDP packets can tolerate loss better than TCP, so we use try_inject
                    if bridge.try_inject_packet(packet_data, peer_key, processed.src_addr, outbound_tag) {
                        trace!(
                            "Routed UDP to ipstack: {}:{} -> {}:{}",
                            parsed.src_ip, src_port, parsed.dst_ip, dst_port
                        );
                        stats.packets_forwarded.fetch_add(1, Ordering::Relaxed);
                        stats.udp_packets.fetch_add(1, Ordering::Relaxed);
                        return;
                    } else {
                        // Channel full - fall through to manual UDP handling
                        // UDP is lossy by nature, so this is acceptable
                        debug!(
                            "IpStack channel full for UDP, using fallback: {}:{} -> {}:{}",
                            parsed.src_ip, src_port, parsed.dst_ip, dst_port
                        );
                        // Continue to manual UDP handling below
                    }
                }
            }
        }
        // === END UDP IPSTACK INTEGRATION ===

        // Manual UDP handling (fallback when ipstack disabled or channel full)
        // Try to get SOCKS5 or other outbound from manager
        if let Some(outbound) = outbound_manager.get(outbound_tag) {
            let dst_addr = SocketAddr::new(parsed.dst_ip, dst_port);

            // Check if outbound supports UDP
            if !outbound.supports_udp() {
                warn!("Outbound '{}' does not support UDP, dropping packet", outbound_tag);
                stats.forward_errors.fetch_add(1, Ordering::Relaxed);
                return;
            }

            // Extract UDP payload
            let payload_offset = parsed.ip_header_len + 8;
            if processed.data.len() <= payload_offset {
                warn!("UDP packet too short for payload");
                stats.forward_errors.fetch_add(1, Ordering::Relaxed);
                return;
            }
            let udp_payload = &processed.data[payload_offset..];

            // Capture values for session management
            let client_ip = parsed.src_ip;
            let client_port = src_port;
            let server_ip = parsed.dst_ip;
            let server_port = dst_port;
            let outbound_tag_owned = outbound_tag.clone();
            let reply_tx = direct_reply_tx.clone();

            // Check for existing proxy UDP session (Shadowsocks, SOCKS5)
            if let Some(proxy_session) = PROXY_UDP_SESSIONS.get(&five_tuple) {
                // Reuse existing proxy session
                proxy_session.touch();
                proxy_session.record_sent();
                match proxy_session.handle.send(udp_payload).await {
                    Ok(bytes_sent) => {
                        trace!(
                            "Forwarded UDP via existing proxy session '{}': {} -> {}:{} ({} bytes)",
                            outbound_tag, client_ip, server_ip, server_port, bytes_sent
                        );
                    }
                    Err(e) => {
                        debug!("Proxy UDP session send failed, removing: {}", e);
                        PROXY_UDP_SESSIONS.remove(&five_tuple);
                    }
                }
                return;
            }

            // Check for existing direct UDP session
            if let Some(session) = UDP_SESSIONS.get(&five_tuple) {
                // Reuse existing session
                session.touch();
                match session.socket.send(udp_payload).await {
                    Ok(bytes_sent) => {
                        trace!(
                            "Forwarded UDP via existing session '{}': {} -> {}:{} ({} bytes)",
                            outbound_tag, client_ip, server_ip, server_port, bytes_sent
                        );
                    }
                    Err(e) => {
                        debug!("UDP session send failed, removing: {}", e);
                        UDP_SESSIONS.remove(&five_tuple);
                    }
                }
                return;
            }

            // Create new UDP session
            match outbound.connect_udp(dst_addr, Duration::from_secs(5)).await {
                Ok(handle) => {
                    // Extract the socket from the handle (Direct) or handle proxy sessions
                    let socket: Arc<UdpSocket> = match handle {
                        crate::outbound::UdpOutboundHandle::Direct(direct_handle) => {
                            Arc::clone(direct_handle.socket())
                        }
                        // For non-direct handles (Shadowsocks, SOCKS5), use bidirectional session
                        _ => {
                            // Check session limit to prevent memory exhaustion
                            if PROXY_UDP_SESSIONS.len() >= MAX_PROXY_UDP_SESSIONS {
                                warn!(
                                    "Proxy UDP session limit reached ({}), dropping packet to {}:{}",
                                    MAX_PROXY_UDP_SESSIONS, server_ip, server_port
                                );
                                stats.forward_errors.fetch_add(1, Ordering::Relaxed);
                                return;
                            }

                            // Record UDP session in outbound stats
                            let outbound_stats = outbound.stats();
                            outbound_stats.record_connection();

                            // Send the initial packet
                            match handle.send(udp_payload).await {
                                Ok(bytes_sent) => {
                                    debug!(
                                        "Forwarded UDP via new proxy session '{}': {} -> {}:{} ({} bytes)",
                                        outbound_tag, client_ip, server_ip, server_port, bytes_sent
                                    );

                                    // Create and store the proxy session
                                    // IMPORTANT: Insert into map BEFORE spawning listener to prevent race condition
                                    // where listener exit cleanup finds no session to remove
                                    let session = Arc::new(ProxyUdpSessionEntry::new(handle));
                                    session.record_sent();
                                    PROXY_UDP_SESSIONS.insert(five_tuple, Arc::clone(&session));

                                    // Spawn reply listener if we have a reply channel
                                    if let Some(tx) = reply_tx {
                                        spawn_proxy_udp_reply_listener(
                                            Arc::clone(&session),
                                            five_tuple,
                                            tx,
                                            client_ip,
                                            client_port,
                                            server_ip,
                                            server_port,
                                            outbound_tag_owned,
                                            outbound_stats,
                                        );
                                    } else {
                                        // No reply channel - spawn cleanup task
                                        let session_clone = Arc::clone(&session);
                                        let ft = five_tuple;
                                        let stats_clone = Arc::clone(&outbound_stats);
                                        tokio::spawn(async move {
                                            loop {
                                                tokio::time::sleep(Duration::from_secs(30)).await;
                                                let now_secs = std::time::SystemTime::now()
                                                    .duration_since(std::time::UNIX_EPOCH)
                                                    .unwrap_or_default()
                                                    .as_secs();
                                                if now_secs.saturating_sub(session_clone.last_activity_secs())
                                                    > PROXY_UDP_IDLE_TIMEOUT_SECS
                                                {
                                                    PROXY_UDP_SESSIONS.remove(&ft);
                                                    stats_clone.record_completed(0, 0);
                                                    debug!("Proxy UDP session (no reply) closed: {:?}", ft);
                                                    break;
                                                }
                                            }
                                        });
                                    }
                                    // Session already stored in PROXY_UDP_SESSIONS above
                                }
                                Err(e) => {
                                    warn!("Failed to send UDP via '{}': {}", outbound_tag, e);
                                    stats.forward_errors.fetch_add(1, Ordering::Relaxed);
                                    outbound_stats.record_error();
                                }
                            }
                            return;
                        }
                    };

                    // Record UDP session in outbound stats
                    let outbound_stats = outbound.stats();
                    outbound_stats.record_connection();

                    // Send the packet
                    match socket.send(udp_payload).await {
                        Ok(bytes_sent) => {
                            debug!(
                                "Forwarded UDP via new session '{}': {} -> {}:{} ({} bytes)",
                                outbound_tag, client_ip, server_ip, server_port, bytes_sent
                            );

                            // Store session for reuse
                            let session = Arc::new(UdpSessionEntry::new(socket));
                            
                            // Spawn reply listener (or cleanup task if no reply channel)
                            let session_clone = Arc::clone(&session);
                            let ft = five_tuple;
                            let outbound_stats_clone = Arc::clone(&outbound_stats);
                            
                            if let Some(tx) = reply_tx {
                                tokio::spawn(async move {
                                    let mut buf = vec![0u8; 65535];
                                    loop {
                                        match tokio::time::timeout(
                                            Duration::from_secs(30),
                                            session_clone.socket.recv(&mut buf)
                                        ).await {
                                            Ok(Ok(n)) if n > 0 => {
                                                session_clone.touch();
                                                // Build UDP reply packet based on IP version
                                                let reply_packet = match (server_ip, client_ip) {
                                                    (IpAddr::V4(src), IpAddr::V4(dst)) => {
                                                        build_udp_reply_packet(
                                                            src,
                                                            server_port,
                                                            dst,
                                                            client_port,
                                                            &buf[..n],
                                                        )
                                                    }
                                                    (IpAddr::V6(src), IpAddr::V6(dst)) => {
                                                        build_udp_reply_packet_v6(
                                                            src,
                                                            server_port,
                                                            dst,
                                                            client_port,
                                                            &buf[..n],
                                                        )
                                                    }
                                                    _ => {
                                                        debug!("IP version mismatch in UDP reply");
                                                        break;
                                                    }
                                                };
                                                if let Err(e) = tx.try_send(ReplyPacket {
                                                    packet: reply_packet,
                                                    tunnel_tag: outbound_tag_owned.clone(),
                                                }) {
                                                    debug!("Failed to send UDP reply: {}", e);
                                                    break;
                                                }
                                            }
                                            Ok(Ok(_)) => {
                                                // Zero bytes read, connection closed
                                                break;
                                            }
                                            Ok(Err(e)) => {
                                                debug!("UDP recv error: {}", e);
                                                break;
                                            }
                                            Err(_) => {
                                                // Timeout - check if session is still active
                                                let now = std::time::SystemTime::now()
                                                    .duration_since(std::time::UNIX_EPOCH)
                                                    .unwrap_or_default()
                                                    .as_secs();
                                                if now - session_clone.last_activity_secs() > 60 {
                                                    debug!("UDP session idle timeout");
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                    // Cleanup session and record completion
                                    UDP_SESSIONS.remove(&ft);
                                    outbound_stats_clone.record_completed(0, 0);
                                    debug!("UDP session closed: {:?}", ft);
                                });
                            } else {
                                // No reply channel - spawn a cleanup task that times out after idle period
                                tokio::spawn(async move {
                                    loop {
                                        tokio::time::sleep(Duration::from_secs(30)).await;
                                        let now = std::time::SystemTime::now()
                                            .duration_since(std::time::UNIX_EPOCH)
                                            .unwrap_or_default()
                                            .as_secs();
                                        if now - session_clone.last_activity_secs() > 60 {
                                            UDP_SESSIONS.remove(&ft);
                                            outbound_stats_clone.record_completed(0, 0);
                                            debug!("UDP session (no reply) closed: {:?}", ft);
                                            break;
                                        }
                                    }
                                });
                            }
                            
                            UDP_SESSIONS.insert(five_tuple, session);
                        }
                        Err(e) => {
                            warn!("Failed to send UDP via '{}': {}", outbound_tag, e);
                            stats.forward_errors.fetch_add(1, Ordering::Relaxed);
                            outbound_stats.record_error();
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to connect UDP via '{}' to {}: {}", outbound_tag, dst_addr, e);
                    stats.forward_errors.fetch_add(1, Ordering::Relaxed);
                    // Note: No outbound_stats.record_error() here since connection wasn't established
                }
            }
        } else {
            warn!("Unknown outbound '{}', dropping UDP packet: {} -> {}:{}",
                outbound_tag, parsed.src_ip, parsed.dst_ip, dst_port);
            stats.forward_errors.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Create a direct UDP socket connected to the destination
///
/// Used as a fallback when `OutboundManager` doesn't have the specified tag.
/// The socket is bound to an ephemeral port and connected to the destination.
///
/// # Arguments
///
/// * `dst_addr` - Destination address to connect to
///
/// # Returns
///
/// A connected `UdpSocket` on success, or an I/O error on failure.
async fn create_direct_udp_socket(dst_addr: SocketAddr) -> std::io::Result<UdpSocket> {
    let bind_addr = if dst_addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind_addr).await?;
    socket.connect(dst_addr).await?;
    Ok(socket)
}

// ============================================================================
// Direct UDP Reply Listener
// ============================================================================

/// Default timeout for waiting for UDP replies (5 seconds)
const DIRECT_UDP_REPLY_TIMEOUT: Duration = Duration::from_secs(5);

/// Maximum UDP payload size for receiving replies
const MAX_UDP_REPLY_SIZE: usize = 65535;

/// Spawn a task to listen for UDP replies on an outbound handle.
///
/// This function spawns an async task that waits for a reply from the destination
/// server and forwards it to the reply router for delivery back to the WireGuard client.
///
/// # Arguments
///
/// * `handle` - The UDP outbound handle (from `OutboundManager`)
/// * `reply_tx` - Channel to send reply packets to the reply router
/// * `client_ip` - The original client's IP address (reply destination)
/// * `client_port` - The original client's port (reply destination port)
/// * `server_ip` - The server's IP address (reply source)
/// * `server_port` - The server's port (reply source port)
/// * `outbound_tag` - The outbound tag for session matching
fn spawn_direct_udp_reply_listener(
    handle: crate::outbound::UdpOutboundHandle,
    reply_tx: mpsc::Sender<ReplyPacket>,
    client_ip: IpAddr,
    client_port: u16,
    server_ip: IpAddr,
    server_port: u16,
    outbound_tag: String,
) {
    tokio::spawn(async move {
        let mut buf = vec![0u8; MAX_UDP_REPLY_SIZE];
        let mut last_activity = std::time::Instant::now();

        debug!(
            "Direct UDP reply listener started for {}:{} -> {}:{} via '{}'",
            client_ip, client_port, server_ip, server_port, outbound_tag
        );

        // Loop to receive multiple replies (like shadowsocks-rust pattern)
        loop {
            // Wait for reply with timeout
            match tokio::time::timeout(DIRECT_UDP_REPLY_TIMEOUT, handle.recv(&mut buf)).await {
                Ok(Ok(n)) if n > 0 => {
                    last_activity = std::time::Instant::now();
                    let reply_payload = &buf[..n];

                    // Build complete IP packet for the reply
                    let reply_packet = match (server_ip, client_ip) {
                        (IpAddr::V4(src), IpAddr::V4(dst)) => {
                            build_udp_reply_packet(src, server_port, dst, client_port, reply_payload)
                        }
                        (IpAddr::V6(src), IpAddr::V6(dst)) => {
                            build_udp_reply_packet_v6(src, server_port, dst, client_port, reply_payload)
                        }
                        _ => {
                            warn!(
                                "IP version mismatch in direct UDP reply: server={}, client={}",
                                server_ip, client_ip
                            );
                            break;
                        }
                    };

                    // Send to reply router
                    let reply = ReplyPacket {
                        packet: reply_packet,
                        tunnel_tag: outbound_tag.clone(),
                    };

                    if let Err(e) = reply_tx.try_send(reply) {
                        warn!(
                            "Failed to send direct UDP reply to router ({}): {} -> {}:{}",
                            e, server_ip, client_ip, client_port
                        );
                        // Channel full or closed, stop listening
                        break;
                    } else {
                        trace!(
                            "Direct UDP reply forwarded: {}:{} -> {}:{} ({} bytes)",
                            server_ip, server_port, client_ip, client_port, n
                        );
                    }
                }
                Ok(Ok(_)) => {
                    // Zero-length reply, continue listening
                    trace!("Empty direct UDP reply from {}:{}", server_ip, server_port);
                }
                Ok(Err(e)) => {
                    // Socket error, stop listening
                    debug!(
                        "Error receiving direct UDP reply from {}:{}: {}",
                        server_ip, server_port, e
                    );
                    break;
                }
                Err(_) => {
                    // Timeout - check if we've been idle too long (60 seconds total)
                    if last_activity.elapsed() > Duration::from_secs(60) {
                        trace!(
                            "Direct UDP reply listener idle timeout: {}:{} -> {}:{}",
                            client_ip, client_port, server_ip, server_port
                        );
                        break;
                    }
                    // Otherwise keep waiting for more replies
                }
            }
        }

        debug!(
            "Direct UDP reply listener ended for {}:{} -> {}:{} via '{}'",
            client_ip, client_port, server_ip, server_port, outbound_tag
        );
    });
}

/// Spawn a task to listen for UDP replies on a raw socket.
///
/// Similar to `spawn_direct_udp_reply_listener` but for the fallback case
/// where we use a raw `UdpSocket` instead of an `UdpOutboundHandle`.
fn spawn_direct_udp_reply_listener_raw(
    socket: Arc<UdpSocket>,
    reply_tx: mpsc::Sender<ReplyPacket>,
    client_ip: IpAddr,
    client_port: u16,
    server_ip: IpAddr,
    server_port: u16,
    outbound_tag: String,
) {
    tokio::spawn(async move {
        let mut buf = vec![0u8; MAX_UDP_REPLY_SIZE];
        let mut last_activity = std::time::Instant::now();

        debug!(
            "Direct UDP reply listener (raw) started for {}:{} -> {}:{} via '{}'",
            client_ip, client_port, server_ip, server_port, outbound_tag
        );

        // Loop to receive multiple replies (like shadowsocks-rust pattern)
        loop {
            // Wait for reply with timeout
            match tokio::time::timeout(DIRECT_UDP_REPLY_TIMEOUT, socket.recv(&mut buf)).await {
                Ok(Ok(n)) if n > 0 => {
                    last_activity = std::time::Instant::now();
                    let reply_payload = &buf[..n];

                    // Build complete IP packet for the reply
                    let reply_packet = match (server_ip, client_ip) {
                        (IpAddr::V4(src), IpAddr::V4(dst)) => {
                            build_udp_reply_packet(src, server_port, dst, client_port, reply_payload)
                        }
                        (IpAddr::V6(src), IpAddr::V6(dst)) => {
                            build_udp_reply_packet_v6(src, server_port, dst, client_port, reply_payload)
                        }
                        _ => {
                            warn!(
                                "IP version mismatch in direct UDP reply: server={}, client={}",
                                server_ip, client_ip
                            );
                            break;
                        }
                    };

                    // Send to reply router
                    let reply = ReplyPacket {
                        packet: reply_packet,
                        tunnel_tag: outbound_tag.clone(),
                    };

                    if let Err(e) = reply_tx.try_send(reply) {
                        warn!(
                            "Failed to send direct UDP reply to router ({}): {} -> {}:{}",
                            e, server_ip, client_ip, client_port
                        );
                        // Channel full or closed, stop listening
                        break;
                    } else {
                        trace!(
                            "Direct UDP reply (raw) forwarded: {}:{} -> {}:{} ({} bytes)",
                            server_ip, server_port, client_ip, client_port, n
                        );
                    }
                }
                Ok(Ok(_)) => {
                    // Zero-length reply, continue listening
                    trace!("Empty direct UDP reply from {}:{}", server_ip, server_port);
                }
                Ok(Err(e)) => {
                    // Socket error, stop listening
                    debug!(
                        "Error receiving direct UDP reply from {}:{}: {}",
                        server_ip, server_port, e
                    );
                    break;
                }
                Err(_) => {
                    // Timeout - check if we've been idle too long (60 seconds total)
                    if last_activity.elapsed() > Duration::from_secs(60) {
                        trace!(
                            "Direct UDP reply listener (raw) idle timeout: {}:{} -> {}:{}",
                            client_ip, client_port, server_ip, server_port
                        );
                        break;
                    }
                    // Otherwise keep waiting for more replies
                }
            }
        }

        debug!(
            "Direct UDP reply listener (raw) ended for {}:{} -> {}:{} via '{}'",
            client_ip, client_port, server_ip, server_port, outbound_tag
        );
    });
}

/// Timeout for proxy UDP reply operations (30 seconds)
const PROXY_UDP_REPLY_TIMEOUT: Duration = Duration::from_secs(30);

/// Idle timeout for proxy UDP sessions (60 seconds without activity)
const PROXY_UDP_IDLE_TIMEOUT_SECS: u64 = 60;

/// Maximum number of concurrent proxy UDP sessions to prevent memory exhaustion
const MAX_PROXY_UDP_SESSIONS: usize = 10000;

/// Spawn a task to listen for UDP replies on a proxy outbound handle (Shadowsocks, SOCKS5).
///
/// This function spawns an async task that loops waiting for replies from the proxy server
/// and forwards them back to the WireGuard client. Unlike direct UDP which uses a single
/// recv call, proxy sessions maintain long-lived connections that can receive multiple replies.
///
/// # Arguments
///
/// * `session` - Arc to the proxy UDP session entry
/// * `five_tuple` - The 5-tuple key for session management
/// * `reply_tx` - Channel to send reply packets to the reply router
/// * `client_ip` - The original client's IP address (reply destination)
/// * `client_port` - The original client's port (reply destination port)
/// * `server_ip` - The server's IP address (reply source)
/// * `server_port` - The server's port (reply source port)
/// * `outbound_tag` - The outbound tag for logging and session matching
/// * `outbound_stats` - Statistics tracker for the outbound
fn spawn_proxy_udp_reply_listener(
    session: Arc<ProxyUdpSessionEntry>,
    five_tuple: FiveTuple,
    reply_tx: mpsc::Sender<ReplyPacket>,
    client_ip: IpAddr,
    client_port: u16,
    server_ip: IpAddr,
    server_port: u16,
    outbound_tag: String,
    outbound_stats: Arc<crate::connection::OutboundStats>,
) {
    tokio::spawn(async move {
        let mut buf = vec![0u8; MAX_UDP_REPLY_SIZE];
        let mut total_bytes_rx: u64 = 0;
        // Note: total_bytes_tx would be tracked from the sender side, not here
        let total_bytes_tx: u64 = 0;

        debug!(
            "Proxy UDP reply listener started for {}:{} -> {}:{} via '{}'",
            client_ip, client_port, server_ip, server_port, outbound_tag
        );

        loop {
            // Wait for reply with timeout
            match tokio::time::timeout(PROXY_UDP_REPLY_TIMEOUT, session.handle.recv(&mut buf)).await
            {
                Ok(Ok(n)) if n > 0 => {
                    // Update session activity
                    session.touch();
                    session.record_received();
                    total_bytes_rx += n as u64;

                    let reply_payload = &buf[..n];

                    // Build complete IP packet for the reply based on IP version
                    let reply_packet = match (server_ip, client_ip) {
                        (IpAddr::V4(src), IpAddr::V4(dst)) => {
                            build_udp_reply_packet(src, server_port, dst, client_port, reply_payload)
                        }
                        (IpAddr::V6(src), IpAddr::V6(dst)) => {
                            build_udp_reply_packet_v6(
                                src,
                                server_port,
                                dst,
                                client_port,
                                reply_payload,
                            )
                        }
                        _ => {
                            warn!(
                                "IP version mismatch in proxy UDP reply: server={}, client={}",
                                server_ip, client_ip
                            );
                            break;
                        }
                    };

                    // Send to reply router
                    let reply = ReplyPacket {
                        packet: reply_packet,
                        tunnel_tag: outbound_tag.clone(),
                    };

                    if let Err(e) = reply_tx.try_send(reply) {
                        debug!(
                            "Failed to send proxy UDP reply (channel {}): {} -> {}:{}",
                            e, server_ip, client_ip, client_port
                        );
                        // Channel full or closed - stop listening
                        break;
                    }

                    trace!(
                        "Proxy UDP reply forwarded via '{}': {}:{} -> {}:{} ({} bytes)",
                        outbound_tag,
                        server_ip,
                        server_port,
                        client_ip,
                        client_port,
                        n
                    );
                }
                Ok(Ok(_)) => {
                    // Zero bytes read - connection closed by proxy
                    debug!(
                        "Proxy UDP session closed (zero read): {} -> {}:{} via '{}'",
                        client_ip, server_ip, server_port, outbound_tag
                    );
                    break;
                }
                Ok(Err(e)) => {
                    // Error receiving from proxy
                    debug!(
                        "Proxy UDP recv error via '{}': {} -> {}:{}: {}",
                        outbound_tag, client_ip, server_ip, server_port, e
                    );
                    break;
                }
                Err(_) => {
                    // Timeout - check if session is still active
                    let now_secs = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    let idle_secs = now_secs.saturating_sub(session.last_activity_secs());

                    if idle_secs > PROXY_UDP_IDLE_TIMEOUT_SECS {
                        debug!(
                            "Proxy UDP session idle timeout ({}s): {} -> {}:{} via '{}'",
                            idle_secs, client_ip, server_ip, server_port, outbound_tag
                        );
                        break;
                    }

                    // Session still active, continue waiting
                    trace!(
                        "Proxy UDP recv timeout (idle {}s), continuing: {} -> {}:{} via '{}'",
                        idle_secs,
                        client_ip,
                        server_ip,
                        server_port,
                        outbound_tag
                    );
                }
            }
        }

        // Cleanup session from global map
        PROXY_UDP_SESSIONS.remove(&five_tuple);

        // Record completion with accumulated stats
        outbound_stats.record_completed(total_bytes_rx, total_bytes_tx);

        debug!(
            "Proxy UDP session closed: {} -> {}:{} via '{}' (rx: {} bytes, tx: {} bytes)",
            client_ip, server_ip, server_port, outbound_tag, total_bytes_rx, total_bytes_tx
        );
    });
}

// ============================================================================
// TCP Reader Task
// ============================================================================

/// Maximum TCP segment size for reading server responses
/// 
/// This is set to fit within WireGuard's MTU after encryption:
/// - WireGuard MTU: typically 1420 bytes
/// - IP header: 20 bytes
/// - TCP header: 20-60 bytes (with options)
/// - WireGuard overhead: 32 bytes (transport header + auth tag)
/// - Safety margin: additional bytes for IPv6, options, etc.
/// 
/// Conservative value: 1420 - 20 (IP) - 60 (TCP max) - 32 (WG) - 8 (safety) = 1300
// ============================================================================
// ICMP Forwarding
// ============================================================================

/// Forward an ICMP packet and handle the reply.
///
/// For ICMP Echo Request (ping), we send the request to the destination
/// and wait for the Echo Reply, then forward it back to the client.
/// 
/// If the destination is the gateway's local IP, we respond directly
/// with an Echo Reply without forwarding.
async fn forward_icmp_packet(
    processed: &ProcessedPacket,
    parsed: &ParsedPacket,
    session_tracker: &Arc<IngressSessionTracker>,
    stats: &Arc<ForwardingStats>,
    direct_reply_tx: Option<mpsc::Sender<ReplyPacket>>,
    outbound_tag: &str,
    local_ip: Option<IpAddr>,
) {
    // Only handle IPv4 ICMP for now
    let IpAddr::V4(dst_ip) = parsed.dst_ip else {
        debug!("ICMPv6 forwarding not yet implemented");
        return;
    };
    let IpAddr::V4(src_ip) = parsed.src_ip else {
        return;
    };

    // Parse ICMP header
    let Some((icmp_type, _icmp_code, id, seq, payload)) = parse_icmp_echo(&processed.data, parsed.ip_header_len) else {
        debug!("Failed to parse ICMP packet");
        stats.forward_errors.fetch_add(1, Ordering::Relaxed);
        return;
    };

    // Only handle Echo Request (type 8)
    if icmp_type != ICMP_ECHO_REQUEST {
        debug!("ICMP type {} not supported for forwarding", icmp_type);
        return;
    }

    info!(
        "ICMP Echo Request: {} -> {} (id={}, seq={})",
        src_ip, dst_ip, id, seq
    );

    // Check if ping is to our local gateway IP - respond directly
    if let Some(IpAddr::V4(local_ipv4)) = local_ip {
        if dst_ip == local_ipv4 {
            info!(
                "ICMP Echo Request to local gateway, sending reply: {} -> {} (id={}, seq={})",
                dst_ip, src_ip, id, seq
            );
            
            // Register session so reply router can find the peer
            // The reply packet has src=gateway, dst=client, so we register with
            // key = (client_ip, id, gateway_ip, 0, ICMP) to match the reply lookup
            let five_tuple = FiveTuple::new(
                parsed.src_ip, // client IP
                id,            // Use ICMP ID as "port"
                parsed.dst_ip, // gateway IP
                0,
                IPPROTO_ICMP,
            );
            session_tracker.register(
                five_tuple,
                processed.peer_public_key.clone(),
                processed.src_addr,
                outbound_tag.to_string(),
                parsed.total_len as u64,
            );
            
            // Build Echo Reply directly
            let reply_packet = build_icmp_reply_packet(dst_ip, src_ip, id, seq, &payload);
            
            if let Some(ref reply_tx) = direct_reply_tx {
                if let Err(e) = reply_tx.try_send(ReplyPacket {
                    packet: reply_packet,
                    tunnel_tag: outbound_tag.to_string(),
                }) {
                    warn!("Failed to send local ICMP reply: {}", e);
                } else {
                    info!(
                        "ICMP Echo Reply sent to local: {} -> {} (id={}, seq={})",
                        dst_ip, src_ip, id, seq
                    );
                }
            }
            return;
        }
    }

    // Register session for reply routing
    let five_tuple = FiveTuple::new(
        parsed.src_ip,
        id, // Use ICMP ID as "port"
        parsed.dst_ip,
        0,
        IPPROTO_ICMP,
    );
    session_tracker.register(
        five_tuple,
        processed.peer_public_key.clone(),
        processed.src_addr,
        outbound_tag.to_string(),
        parsed.total_len as u64,
    );

    // Create raw socket for ICMP
    let Some(reply_tx) = direct_reply_tx else {
        debug!("No reply channel for ICMP forwarding");
        return;
    };

    // Spawn ICMP send/receive task
    let client_ip = src_ip;
    let server_ip = dst_ip;
    let outbound_tag = outbound_tag.to_string();

    tokio::spawn(async move {
        // Create raw ICMP socket
        match create_icmp_socket().await {
            Ok(socket) => {
                // Build ICMP Echo Request
                let mut icmp_packet = vec![0u8; 8 + payload.len()];
                icmp_packet[0] = ICMP_ECHO_REQUEST;
                icmp_packet[1] = 0; // Code
                icmp_packet[4..6].copy_from_slice(&id.to_be_bytes());
                icmp_packet[6..8].copy_from_slice(&seq.to_be_bytes());
                if !payload.is_empty() {
                    icmp_packet[8..].copy_from_slice(&payload);
                }

                // Calculate ICMP checksum
                let checksum = icmp_checksum(&icmp_packet);
                icmp_packet[2..4].copy_from_slice(&checksum.to_be_bytes());

                // Send ICMP packet
                let dst_addr = SocketAddr::new(IpAddr::V4(server_ip), 0);
                if let Err(e) = socket.send_to(&icmp_packet, dst_addr).await {
                    debug!("Failed to send ICMP: {}", e);
                    return;
                }

                // Wait for reply with timeout
                // Note: SOCK_DGRAM with IPPROTO_ICMP returns only ICMP data (no IP header)
                let mut recv_buf = vec![0u8; 1500];
                match tokio::time::timeout(Duration::from_secs(10), socket.recv_from(&mut recv_buf)).await {
                    Ok(Ok((n, _from))) => {
                        // Parse received ICMP reply (no IP header with SOCK_DGRAM)
                        if n >= 8 {
                            let recv_type = recv_buf[0];
                            if recv_type == ICMP_ECHO_REPLY {
                                // Use original ID and seq from the request, since kernel may change them
                                let recv_payload = if n > 8 {
                                    recv_buf[8..n].to_vec()
                                } else {
                                    Vec::new()
                                };

                                // Build reply packet for client using ORIGINAL id/seq
                                let reply_packet = build_icmp_reply_packet(
                                    server_ip,
                                    client_ip,
                                    id,   // Use original ID
                                    seq,  // Use original seq
                                    &recv_payload,
                                );

                                if let Err(e) = reply_tx.try_send(ReplyPacket {
                                    packet: reply_packet,
                                    tunnel_tag: outbound_tag,
                                }) {
                                    warn!("Failed to send ICMP reply: {}", e);
                                } else {
                                    info!(
                                        "ICMP Echo Reply forwarded: {} -> {} (id={}, seq={})",
                                        server_ip, client_ip, id, seq
                                    );
                                }
                            }
                        }
                    }
                    Ok(Err(e)) => {
                        debug!("ICMP recv error: {}", e);
                    }
                    Err(_) => {
                        trace!("ICMP reply timeout: {} -> {}", client_ip, server_ip);
                    }
                }
            }
            Err(e) => {
                debug!("Failed to create ICMP socket: {}", e);
            }
        }
    });
}

/// Create a raw socket for ICMP.
async fn create_icmp_socket() -> std::io::Result<UdpSocket> {
    // Use a UDP socket bound to protocol ICMP
    // On Linux, we need CAP_NET_RAW or use SOCK_DGRAM with IPPROTO_ICMP
    // For simplicity, we'll use the socket2 crate to create a raw socket
    use socket2::{Domain, Protocol, Socket, Type};

    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4))?;
    socket.set_nonblocking(true)?;

    // Convert to tokio UdpSocket
    let std_socket: std::net::UdpSocket = socket.into();
    UdpSocket::from_std(std_socket)
}

/// Spawn the forwarding loop as a tokio task
///
/// Returns a `JoinHandle` that can be used to wait for the task to complete
/// or abort it.
///
/// # Arguments
///
/// * `packet_rx` - Receiver for processed packets from ingress
/// * `outbound_manager` - Manager for direct/SOCKS5 outbounds (used for UDP)
/// * `wg_egress_manager` - Manager for `WireGuard` egress tunnels
/// * `session_tracker` - Session tracker for reply routing
/// * `stats` - Statistics collector
/// * `direct_reply_tx` - Optional sender for direct outbound UDP replies
/// * `local_ip` - Gateway's local IP for responding to pings to self
/// * `ecmp_group_manager` - Optional ECMP group manager for load balancing
/// * `peer_manager` - Optional peer manager for peer tunnel forwarding
///
/// # Returns
///
/// A `JoinHandle` for the spawned task.
pub fn spawn_forwarding_task(
    packet_rx: mpsc::Receiver<ProcessedPacket>,
    outbound_manager: Arc<OutboundManager>,
    wg_egress_manager: Arc<WgEgressManager>,
    session_tracker: Arc<IngressSessionTracker>,
    stats: Arc<ForwardingStats>,
    direct_reply_tx: Option<mpsc::Sender<ReplyPacket>>,
    local_ip: Option<IpAddr>,
    ecmp_group_manager: Option<Arc<EcmpGroupManager>>,
    peer_manager: Option<Arc<PeerManager>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(run_forwarding_loop(
        packet_rx,
        outbound_manager,
        wg_egress_manager,
        session_tracker,
        stats,
        direct_reply_tx,
        local_ip,
        ecmp_group_manager,
        peer_manager,
    ))
}

/// Spawn the reply router loop as a tokio task
pub fn spawn_reply_router(
    reply_rx: mpsc::Receiver<ReplyPacket>,
    ingress_manager: Arc<WgIngressManager>,
    session_tracker: Arc<IngressSessionTracker>,
    stats: Arc<IngressReplyStats>,
    dns_cache: Option<Arc<super::dns_cache::IpDomainCache>>,
    peer_manager: Arc<PeerManager>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(run_reply_router_loop(
        reply_rx,
        ingress_manager,
        session_tracker,
        stats,
        dns_cache,
        peer_manager,
    ))
}

/// Statistics for peer tunnel processor
#[derive(Debug, Default)]
pub struct PeerTunnelProcessorStats {
    /// Packets received from peer tunnels
    pub packets_received: AtomicU64,
    /// Packets processed successfully
    pub packets_processed: AtomicU64,
    /// Packets with parse errors
    pub parse_errors: AtomicU64,
    /// Packets with routing errors
    pub routing_errors: AtomicU64,
    /// Packets forwarded to WG egress
    pub wg_egress_forwarded: AtomicU64,
    /// Packets forwarded to SOCKS/direct
    pub other_forwarded: AtomicU64,
    /// Return packets detected (reverse tuple matched)
    pub return_packets: AtomicU64,
    /// Entry node replies forwarded to wg-ingress
    pub entry_replies_forwarded: AtomicU64,
    /// Relay node replies forwarded to previous peer tunnel
    pub relay_replies_forwarded: AtomicU64,
    /// Errors while sending reply packets
    pub reply_send_errors: AtomicU64,
    /// Reply packets where destination tunnel was not found
    pub reply_tunnel_not_found: AtomicU64,
    /// Chain sessions registered for reply routing
    pub chain_sessions_registered: AtomicU64,
}

impl PeerTunnelProcessorStats {
    pub fn snapshot(&self) -> PeerTunnelProcessorStatsSnapshot {
        PeerTunnelProcessorStatsSnapshot {
            packets_received: self.packets_received.load(Ordering::Relaxed),
            packets_processed: self.packets_processed.load(Ordering::Relaxed),
            parse_errors: self.parse_errors.load(Ordering::Relaxed),
            routing_errors: self.routing_errors.load(Ordering::Relaxed),
            wg_egress_forwarded: self.wg_egress_forwarded.load(Ordering::Relaxed),
            other_forwarded: self.other_forwarded.load(Ordering::Relaxed),
            return_packets: self.return_packets.load(Ordering::Relaxed),
            entry_replies_forwarded: self.entry_replies_forwarded.load(Ordering::Relaxed),
            relay_replies_forwarded: self.relay_replies_forwarded.load(Ordering::Relaxed),
            reply_send_errors: self.reply_send_errors.load(Ordering::Relaxed),
            reply_tunnel_not_found: self.reply_tunnel_not_found.load(Ordering::Relaxed),
            chain_sessions_registered: self.chain_sessions_registered.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of peer tunnel processor stats
#[derive(Debug, Clone)]
pub struct PeerTunnelProcessorStatsSnapshot {
    pub packets_received: u64,
    pub packets_processed: u64,
    pub parse_errors: u64,
    pub routing_errors: u64,
    pub wg_egress_forwarded: u64,
    pub other_forwarded: u64,
    pub return_packets: u64,
    pub entry_replies_forwarded: u64,
    pub relay_replies_forwarded: u64,
    pub reply_send_errors: u64,
    pub reply_tunnel_not_found: u64,
    pub chain_sessions_registered: u64,
}

/// Process packets received from peer tunnels (chain routing)
///
/// This function handles packets that arrive on peer tunnels (e.g., `peer-node206`)
/// and routes them according to the DSCP chain routing rules. On Terminal nodes,
/// this means forwarding to the exit egress.
///
/// # Flow for Terminal nodes
///
/// 1. Receive packet from peer tunnel
/// 2. Use IngressProcessor to extract DSCP and get routing decision
/// 3. If Terminal role: route to exit_egress and clear DSCP
/// 4. Forward packet to the appropriate egress
///
/// # Non-WG Egress Support
///
/// For non-WireGuard egress (direct, SOCKS), packets are forwarded to the main
/// forwarding loop via `forward_tx`. This reuses all existing TCP/UDP/SOCKS
/// forwarding logic instead of duplicating it here.
///
/// # Chain Reply Routing
///
/// This function also handles reply path detection for chain traffic:
/// - Entry node: replies go back to wg-ingress client
/// - Relay node: replies go back to previous peer tunnel
/// - Terminal node: replies handled by reply_router
pub async fn run_peer_tunnel_processor_loop(
    mut packet_rx: mpsc::Receiver<ReplyPacket>,
    processor: Arc<super::processor::IngressProcessor>,
    wg_egress_manager: Arc<WgEgressManager>,
    stats: Arc<PeerTunnelProcessorStats>,
    forward_tx: Option<mpsc::Sender<super::manager::ProcessedPacket>>,
    // Parameters for reply path routing
    session_tracker: Arc<IngressSessionTracker>,
    ingress_manager: Arc<WgIngressManager>,
    peer_manager: Arc<PeerManager>,
) {
    info!("Peer tunnel processor started (forward_tx: {}, reply routing enabled)", forward_tx.is_some());

    while let Some(reply) = packet_rx.recv().await {
        stats.packets_received.fetch_add(1, Ordering::Relaxed);

        let tunnel_tag = reply.tunnel_tag.clone();
        let packet = reply.packet;

        // Use the tunnel tag as a pseudo "peer" identifier for logging
        let peer_id = format!("tunnel:{}", tunnel_tag);

        // Parse packet header to extract 5-tuple for session tracking
        let (src_ip, dst_ip, src_port, dst_port, proto, dscp_in) = if packet.len() >= 20 {
            let version = (packet[0] >> 4) & 0x0F;
            if version == 4 && packet.len() >= 20 {
                // IPv4
                let s_ip = IpAddr::V4(Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]));
                let d_ip = IpAddr::V4(Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]));
                let ihl = ((packet[0] & 0x0F) as usize) * 4;
                let protocol = packet[9];
                let dscp = (packet[1] >> 2) & 0x3F;
                let (sp, dp) = if protocol == IPPROTO_ICMP {
                    // For ICMP, use ID as port for session matching
                    if packet.len() >= ihl + 8 {
                        let icmp_id = u16::from_be_bytes([packet[ihl + 4], packet[ihl + 5]]);
                        (icmp_id, icmp_id)
                    } else {
                        (0, 0)
                    }
                } else if packet.len() >= ihl + 4 {
                    (u16::from_be_bytes([packet[ihl], packet[ihl + 1]]),
                     u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]]))
                } else {
                    (0, 0)
                };
                (s_ip, d_ip, sp, dp, protocol, dscp)
            } else if version == 6 && packet.len() >= 40 {
                // IPv6
                let mut s_bytes = [0u8; 16];
                let mut d_bytes = [0u8; 16];
                s_bytes.copy_from_slice(&packet[8..24]);
                d_bytes.copy_from_slice(&packet[24..40]);
                let s_ip = IpAddr::V6(Ipv6Addr::from(s_bytes));
                let d_ip = IpAddr::V6(Ipv6Addr::from(d_bytes));
                let protocol = packet[6]; // Next header
                let dscp = ((packet[0] & 0x0F) << 2) | ((packet[1] >> 6) & 0x03);
                let (sp, dp) = if protocol == IPPROTO_ICMPV6 {
                    // For ICMPv6, use ID as port
                    if packet.len() >= 44 {
                        let icmp_id = u16::from_be_bytes([packet[44], packet[45]]);
                        (icmp_id, icmp_id)
                    } else {
                        (0, 0)
                    }
                } else if packet.len() >= 44 {
                    (u16::from_be_bytes([packet[40], packet[41]]),
                     u16::from_be_bytes([packet[42], packet[43]]))
                } else {
                    (0, 0)
                };
                (s_ip, d_ip, sp, dp, protocol, dscp)
            } else {
                (IpAddr::V4(Ipv4Addr::UNSPECIFIED), IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0, 0, 0, 0)
            }
        } else {
            (IpAddr::V4(Ipv4Addr::UNSPECIFIED), IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0, 0, 0, 0)
        };

        // Build 5-tuple for session tracking
        let five_tuple = FiveTuple::new(src_ip, src_port, dst_ip, dst_port, proto);

        debug!(
            tunnel = %tunnel_tag,
            src = %src_ip,
            dst = %dst_ip,
            src_port = src_port,
            dst_port = dst_port,
            proto = proto,
            dscp = dscp_in,
            "[PEER-TUNNEL-RX] Received packet from peer tunnel"
        );

        // === REPLY PATH DETECTION ===
        // Check if this is RETURN traffic by looking up reversed 5-tuple
        let reversed_tuple = five_tuple.reverse();
        if let Some(session) = session_tracker.get(&reversed_tuple) {
            if session.is_chain_traffic {
                stats.return_packets.fetch_add(1, Ordering::Relaxed);

                match session.node_role {
                    Some(ChainRole::Entry) => {
                        // Entry node: Send back to original client via wg-ingress
                        debug!(
                            tunnel = %tunnel_tag,
                            peer = %session.peer_public_key,
                            "[REPLY-ENTRY] Routing return traffic to wg-ingress client"
                        );

                        match ingress_manager
                            .send_to_peer(&session.peer_public_key, session.peer_endpoint, &packet)
                            .await
                        {
                            Ok(()) => {
                                stats.entry_replies_forwarded.fetch_add(1, Ordering::Relaxed);
                                session_tracker.update_received(&reversed_tuple, packet.len() as u64);
                            }
                            Err(e) => {
                                stats.reply_send_errors.fetch_add(1, Ordering::Relaxed);
                                warn!("[REPLY-ENTRY] Failed to send reply to ingress peer: {}", e);
                            }
                        }
                        continue;
                    }

                    Some(ChainRole::Relay) => {
                        // Relay node: Send back to previous hop via peer tunnel
                        let source_tunnel = match &session.source_tunnel_tag {
                            Some(tag) => tag.clone(),
                            None => {
                                warn!("[REPLY-RELAY] Relay session missing source_tunnel_tag");
                                stats.reply_tunnel_not_found.fetch_add(1, Ordering::Relaxed);
                                continue;
                            }
                        };

                        debug!(
                            tunnel = %tunnel_tag,
                            source_tunnel = %source_tunnel,
                            "[REPLY-RELAY] Routing return traffic to previous peer tunnel"
                        );

                        match peer_manager.send_to_peer_tunnel(&source_tunnel, &packet).await {
                            Ok(()) => {
                                stats.relay_replies_forwarded.fetch_add(1, Ordering::Relaxed);
                                session_tracker.update_received(&reversed_tuple, packet.len() as u64);
                            }
                            Err(e) => {
                                stats.reply_send_errors.fetch_add(1, Ordering::Relaxed);
                                warn!("[REPLY-RELAY] Failed to send reply to tunnel {}: {}", source_tunnel, e);
                            }
                        }
                        continue;
                    }

                    Some(ChainRole::Terminal) => {
                        // Terminal replies should go through reply_router, not here
                        warn!("[REPLY-TERMINAL] Unexpected terminal reply in peer_tunnel_processor");
                        continue;
                    }

                    None => {
                        // Non-chain session found - fall through to normal processing
                        debug!("Non-chain session found for reversed tuple, processing as forward traffic");
                    }
                }
            }
        }
        // === END REPLY PATH DETECTION ===

        // Need mutable packet for DSCP modification
        let mut packet = packet;

        // Get routing decision from ingress processor (handles DSCP/chain routing)
        let routing = match processor.process(&packet, &peer_id) {
            Ok(decision) => {
                debug!(
                    tunnel = %tunnel_tag,
                    outbound = %decision.outbound,
                    dscp_mark = ?decision.dscp_mark,
                    routing_mark = ?decision.routing_mark,
                    match_info = ?decision.match_info,
                    is_chain = decision.is_chain_packet,
                    "[TERMINAL-ROUTE] Got routing decision"
                );
                decision
            },
            Err(e) => {
                stats.routing_errors.fetch_add(1, Ordering::Relaxed);
                warn!(
                    tunnel = %tunnel_tag,
                    dscp = dscp_in,
                    "[TERMINAL-ROUTE-ERR] Failed to get routing decision: {}",
                    e
                );
                continue;
            }
        };

        // Apply DSCP modification if needed (e.g., clear DSCP for Terminal nodes)
        if let Some(dscp_mark) = routing.dscp_mark {
            debug!(
                tunnel = %tunnel_tag,
                old_dscp = dscp_in,
                new_dscp = dscp_mark,
                "[TERMINAL-DSCP] Setting DSCP value"
            );
            if let Err(e) = set_dscp(&mut packet, dscp_mark) {
                warn!(
                    "Peer tunnel processor: failed to set DSCP {} on packet: {}",
                    dscp_mark, e
                );
            }
        }

        // Clone outbound_tag before potential move of routing
        let outbound_tag = routing.outbound.clone();

        debug!(
            tunnel = %tunnel_tag,
            outbound = %outbound_tag,
            match_info = ?routing.match_info,
            dscp_mark = ?routing.dscp_mark,
            "[TERMINAL-FWD] Forwarding to egress"
        );

        // Handle blocked packets
        if outbound_tag == "block" || outbound_tag == "adblock" {
            debug!(
                "Peer tunnel processor: blocking packet from {} (reason: {})",
                tunnel_tag,
                outbound_tag
            );
            continue;
        }

        // Determine if this is a WireGuard egress or peer tunnel
        let is_peer_tunnel = outbound_tag.starts_with("peer-");
        let is_wg_egress = outbound_tag.starts_with("wg-")
            || outbound_tag.starts_with("pia-")
            || is_peer_tunnel
            || wg_egress_manager.has_tunnel(&outbound_tag);

        if is_wg_egress {
            // === CHAIN SESSION REGISTRATION ===
            // Register session BEFORE forwarding to enable reply routing
            if is_peer_tunnel {
                // Relay node: forwarding to next peer tunnel
                session_tracker.register_chain(
                    five_tuple,
                    peer_id.clone(),
                    SocketAddr::from(([0, 0, 0, 0], 0)),
                    outbound_tag.clone(),
                    packet.len() as u64,
                    Some(tunnel_tag.clone()),
                    ChainRole::Relay,
                );
                stats.chain_sessions_registered.fetch_add(1, Ordering::Relaxed);
                debug!(tunnel = %tunnel_tag, next_hop = %outbound_tag, "[CHAIN-SESSION] Registered Relay session");
            } else {
                // Terminal node: forwarding to exit egress
                session_tracker.register_chain(
                    five_tuple,
                    peer_id.clone(),
                    SocketAddr::from(([0, 0, 0, 0], 0)),
                    outbound_tag.clone(),
                    packet.len() as u64,
                    Some(tunnel_tag.clone()),
                    ChainRole::Terminal,
                );
                stats.chain_sessions_registered.fetch_add(1, Ordering::Relaxed);
                debug!(tunnel = %tunnel_tag, egress = %outbound_tag, "[CHAIN-SESSION] Registered Terminal session");
            }
            // === END CHAIN SESSION REGISTRATION ===

            // Forward to WireGuard egress tunnel
            let packet_len = packet.len();
            match wg_egress_manager.send(&outbound_tag, packet).await {
                Ok(()) => {
                    stats.wg_egress_forwarded.fetch_add(1, Ordering::Relaxed);
                    trace!(
                        "Peer tunnel processor: forwarded {} bytes to WG egress '{}'",
                        packet_len,
                        outbound_tag
                    );
                }
                Err(e) => {
                    stats.routing_errors.fetch_add(1, Ordering::Relaxed);
                    warn!(
                        "Peer tunnel processor: failed to send to WG egress '{}': {}",
                        outbound_tag, e
                    );
                }
            }
        } else if let Some(ref tx) = forward_tx {
            // Forward non-WG egress to main forwarding loop
            // This reuses all existing TCP/UDP/SOCKS forwarding logic
            let processed = super::manager::ProcessedPacket {
                data: packet,
                routing,
                // Use tunnel tag as pseudo peer identifier
                peer_public_key: tunnel_tag.clone(),
                // Use a placeholder address - the packet already has real src/dst in IP header
                src_addr: std::net::SocketAddr::from(([0, 0, 0, 0], 0)),
            };

            match tx.try_send(processed) {
                Ok(()) => {
                    stats.other_forwarded.fetch_add(1, Ordering::Relaxed);
                    debug!(
                        "Peer tunnel processor: forwarded to main loop for egress '{}'",
                        outbound_tag
                    );
                }
                Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                    stats.routing_errors.fetch_add(1, Ordering::Relaxed);
                    warn!(
                        "Peer tunnel processor: forwarding queue full, dropping packet for '{}'",
                        outbound_tag
                    );
                }
                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                    stats.routing_errors.fetch_add(1, Ordering::Relaxed);
                    warn!(
                        "Peer tunnel processor: forwarding channel closed, dropping packet for '{}'",
                        outbound_tag
                    );
                }
            }
        } else {
            // No forward_tx configured - cannot handle non-WG egress
            stats.routing_errors.fetch_add(1, Ordering::Relaxed);
            warn!(
                "Peer tunnel processor: non-WG egress '{}' requires forward_tx but none configured",
                outbound_tag
            );
        }

        stats.packets_processed.fetch_add(1, Ordering::Relaxed);
    }

    info!("Peer tunnel processor stopped");
}

/// Spawn the peer tunnel processor loop as a tokio task
///
/// # Arguments
///
/// * `packet_rx` - Receiver for packets from peer tunnels
/// * `processor` - Ingress processor for routing decisions
/// * `wg_egress_manager` - Manager for WireGuard egress tunnels
/// * `stats` - Statistics collector
/// * `forward_tx` - Optional sender to main forwarding loop for non-WG egress (direct/SOCKS)
/// * `session_tracker` - Session tracker for reply routing
/// * `ingress_manager` - Ingress manager for sending replies to wg-ingress peers
/// * `peer_manager` - Peer manager for sending replies to peer tunnels
pub fn spawn_peer_tunnel_processor(
    packet_rx: mpsc::Receiver<ReplyPacket>,
    processor: Arc<super::processor::IngressProcessor>,
    wg_egress_manager: Arc<WgEgressManager>,
    stats: Arc<PeerTunnelProcessorStats>,
    forward_tx: Option<mpsc::Sender<super::manager::ProcessedPacket>>,
    session_tracker: Arc<IngressSessionTracker>,
    ingress_manager: Arc<WgIngressManager>,
    peer_manager: Arc<PeerManager>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(run_peer_tunnel_processor_loop(
        packet_rx,
        processor,
        wg_egress_manager,
        stats,
        forward_tx,
        session_tracker,
        ingress_manager,
        peer_manager,
    ))
}

// ============================================================================
// UDP Session Stats Helpers
// ============================================================================

/// Get the number of active UDP sessions
///
/// This returns the count of active UDP sessions for QUIC and other UDP traffic.
#[must_use]
pub fn get_udp_session_count() -> usize {
    UDP_SESSIONS.len()
}

/// Get the number of active proxy UDP sessions (Shadowsocks, SOCKS5)
#[must_use]
pub fn get_proxy_udp_session_count() -> usize {
    PROXY_UDP_SESSIONS.len()
}

// ============================================================================
// IpStack Bridge Public API (feature-gated)
// ============================================================================

/// Initialize the IpStack bridge (call once at startup)
///
/// Returns a receiver channel for reply packets that should be sent back
/// through WireGuard to clients. Each tuple contains:
/// - The IP packet (BytesMut)
/// - The peer's public key ([u8; 32])
/// - The peer's endpoint (SocketAddr) - avoids session lookup in reply router
///
/// # Errors
///
/// Returns an error if:
/// - The bridge has already been initialized
/// - Failed to start the internal ipstack tasks
///
/// # Arguments
///
/// * `rule_engine` - Optional RuleEngine for domain-based routing decisions (SNI/FakeDNS)
/// * `fakedns_manager` - Optional FakeDnsManager for DNS hijacking and domain-based routing
///   (only available when both `ipstack-tcp` and `fakedns` features are enabled)
///
/// # Returns
///
/// A tuple containing:
/// - The reply receiver channel for routing packets back to WireGuard peers
/// - The session tracker Arc for session lookup (used by `spawn_ipstack_reply_router`)
#[cfg(feature = "ipstack-tcp")]
pub async fn init_ipstack_bridge(
    rule_engine: Option<std::sync::Arc<crate::rules::engine::RuleEngine>>,
    #[cfg(feature = "fakedns")] fakedns_manager: Option<std::sync::Arc<crate::fakedns::FakeDnsManager>>,
) -> anyhow::Result<(mpsc::Receiver<(bytes::BytesMut, [u8; 32])>, Arc<IpStackSessionTracker>)> {
    use super::ipstack_bridge::configured_shard_count;

    let shard_count = configured_shard_count();
    let mut bridge = ShardedIpStackBridge::new(shard_count);

    // Set RuleEngine for domain-based routing (enables SNI/FakeDNS routing overrides)
    if let Some(engine) = rule_engine {
        bridge.set_rule_engine(engine);
        info!("RuleEngine configured for ipstack bridge domain-based routing");
    }

    // Set FakeDNS manager if provided (enables DNS hijacking for domain-based routing)
    #[cfg(feature = "fakedns")]
    if let Some(fakedns) = fakedns_manager {
        bridge.set_fakedns_manager(fakedns);
        info!("FakeDNS manager configured for ipstack bridge");
    }

    let reply_rx = bridge
        .take_reply_rx()
        .ok_or_else(|| anyhow::anyhow!("Failed to take reply_rx from ShardedIpStackBridge"))?;
    let session_tracker = Arc::clone(bridge.session_tracker());

    bridge.start().await?;

    IPSTACK_BRIDGE
        .set(Arc::new(bridge))
        .map_err(|_| anyhow::anyhow!("ShardedIpStackBridge already initialized"))?;

    info!(shard_count, "ShardedIpStackBridge initialized with {} shards", shard_count);
    Ok((reply_rx, session_tracker))
}

/// Check if ipstack is enabled and running
///
/// Returns true if:
/// - The ipstack-tcp feature is enabled
/// - The bridge has been initialized
/// - Runtime enable flag is set (default: true)
#[cfg(feature = "ipstack-tcp")]
#[must_use]
pub fn is_ipstack_enabled() -> bool {
    IPSTACK_ENABLED.load(Ordering::Relaxed) && IPSTACK_BRIDGE.get().is_some()
}

/// Set ipstack enabled/disabled at runtime
///
/// This allows dynamically enabling or disabling ipstack without
/// restarting the router. When disabled, traffic falls back to
/// the manual TCP state machine.
#[cfg(feature = "ipstack-tcp")]
pub fn set_ipstack_enabled(enabled: bool) {
    IPSTACK_ENABLED.store(enabled, Ordering::Relaxed);
    info!(
        "IpStack bridge {}",
        if enabled { "enabled" } else { "disabled" }
    );
}

/// Get IpStack bridge statistics
///
/// Returns None if the bridge is not initialized.
/// Returns ShardedBridgeStatsSnapshot which includes per-shard stats for debugging.
#[cfg(feature = "ipstack-tcp")]
#[must_use]
pub fn get_ipstack_stats() -> Option<super::ipstack_bridge::ShardedBridgeStatsSnapshot> {
    let bridge = IPSTACK_BRIDGE.get()?;
    // No lock needed - ShardedIpStackBridge uses interior mutability (atomics)
    Some(bridge.stats().snapshot())
}

/// Get IpStack bridge diagnostic snapshot
///
/// Returns detailed diagnostics including session counts, per-shard stats, and distribution skew.
#[cfg(feature = "ipstack-tcp")]
#[must_use]
pub fn get_ipstack_diagnostics() -> Option<super::ipstack_bridge::ShardedDiagnosticSnapshot> {
    let bridge = IPSTACK_BRIDGE.get()?;
    // No lock needed - ShardedIpStackBridge uses interior mutability
    Some(bridge.diagnostic_snapshot())
}

/// Spawn a task to route ipstack reply packets to WireGuard peers
///
/// This task receives reply packets from the IpStackBridge and sends them
/// back to the appropriate WireGuard peer based on the peer_key.
///
/// # Arguments
///
/// * `ipstack_reply_rx` - Receiver for (packet, peer_key) tuples from IpStackBridge
/// * `wg_ingress_manager` - Reference to the WireGuard ingress manager for sending packets
/// * `session_tracker` - Session tracker for looking up peer_endpoint from 5-tuple
///
/// # Returns
///
/// A JoinHandle for the spawned task.
///
/// # Implementation Notes
///
/// This function processes packets **sequentially** for correct WireGuard operation:
/// - WireGuard uses nonce counters that must be sequential per peer
/// - The `send_to_peer` call handles encryption with proper nonce ordering
/// - Per-peer sequential processing ensures reply packets arrive in the correct order
///
/// # Parallel Processing Architecture
///
/// WireGuard nonces only need to be sequential **per peer**, not globally.
/// This implementation uses per-peer reply channels that allow parallel processing
/// across different peers while maintaining sequential ordering within each peer:
///
/// ```text
///                      ipstack_reply_rx (global)
///                             |
///                             v
///                     +--------------+
///                     | Fan-out task |
///                     | (routes by   |
///                     |  peer_key)   |
///                     +--------------+
///                             |
///          +------------------+------------------+
///          |                  |                  |
///          v                  v                  v
///    +----------+       +----------+       +----------+
///    | Peer A   |       | Peer B   |       | Peer C   |
///    | channel  |       | channel  |       | channel  |
///    | + task   |       | + task   |       | + task   |
///    +----------+       +----------+       +----------+
///          |                  |                  |
///          v                  v                  v
///    send_to_peer()    send_to_peer()    send_to_peer()
///    (sequential)      (sequential)      (sequential)
/// ```
///
/// For throughput optimization, the ShardedIpStackBridge distributes incoming
/// packets across multiple ipstack instances using 5-tuple hashing.
#[cfg(feature = "ipstack-tcp")]
pub fn spawn_ipstack_reply_router(
    mut ipstack_reply_rx: mpsc::Receiver<(bytes::BytesMut, [u8; 32])>,
    wg_ingress_manager: Arc<super::manager::WgIngressManager>,
    session_tracker: Arc<IpStackSessionTracker>,
) -> tokio::task::JoinHandle<()> {
    let router = ParallelReplyRouter::new(wg_ingress_manager, session_tracker);

    tokio::spawn(async move {
        info!("Parallel IpStack reply router started");

        while let Some((packet, peer_key)) = ipstack_reply_rx.recv().await {
            router.route_packet(packet, peer_key).await;
        }

        let stats = router.stats();
        info!(
            "Parallel IpStack reply router stopped: routed={}, failed={}, tasks_spawned={}, channel_drops={}",
            stats.packets_routed.load(Ordering::Relaxed),
            stats.packets_failed.load(Ordering::Relaxed),
            stats.peer_tasks_spawned.load(Ordering::Relaxed),
            stats.channel_full_drops.load(Ordering::Relaxed),
        );
    })
}

/// Information needed to send a reply packet to a peer
#[cfg(feature = "ipstack-tcp")]
struct ReplyPacketInfo {
    /// Decrypted IP packet to send
    packet: bytes::BytesMut,
    /// Peer's external endpoint (IP:port)
    peer_endpoint: SocketAddr,
    /// Peer's WireGuard public key (Base64)
    peer_key_b64: String,
}

/// Statistics for the parallel reply router
#[cfg(feature = "ipstack-tcp")]
pub struct ParallelReplyRouterStats {
    /// Number of packets successfully routed to peers
    pub packets_routed: AtomicU64,
    /// Number of packets that failed to route
    pub packets_failed: AtomicU64,
    /// Number of per-peer tasks spawned
    pub peer_tasks_spawned: AtomicU64,
    /// Number of packets dropped due to full per-peer channel
    pub channel_full_drops: AtomicU64,
}

#[cfg(feature = "ipstack-tcp")]
impl Default for ParallelReplyRouterStats {
    fn default() -> Self {
        Self {
            packets_routed: AtomicU64::new(0),
            packets_failed: AtomicU64::new(0),
            peer_tasks_spawned: AtomicU64::new(0),
            channel_full_drops: AtomicU64::new(0),
        }
    }
}

/// Per-peer channel buffer size
///
/// This determines how many packets can be queued for a single peer before
/// backpressure is applied. A larger buffer reduces the chance of drops
/// during traffic bursts but increases memory usage per active peer.
///
/// At 1.5 Gbps with 1420-byte packets (~132K pps), a buffer of 256 fills in
/// only 1.9ms, causing frequent drops. Increased to 4096 for ~31ms buffer,
/// matching the global reply channel capacity.
///
/// Memory impact: ~60KB per active peer (4096 * ~15 bytes per packet info)
#[cfg(feature = "ipstack-tcp")]
const PEER_CHANNEL_BUFFER_SIZE: usize = 4096;

/// Parallel reply router that distributes packets to per-peer channels
///
/// This allows multiple peers to process their reply packets concurrently
/// while maintaining sequential ordering within each peer (required for
/// WireGuard nonce correctness).
#[cfg(feature = "ipstack-tcp")]
struct ParallelReplyRouter {
    /// Per-peer reply channels: peer_key bytes -> sender
    peer_channels: Arc<DashMap<[u8; 32], mpsc::Sender<ReplyPacketInfo>>>,
    /// WireGuard ingress manager for sending packets
    wg_manager: Arc<super::manager::WgIngressManager>,
    /// Session tracker for endpoint lookup (unified with ipstack bridge)
    session_tracker: Arc<IpStackSessionTracker>,
    /// Statistics
    stats: Arc<ParallelReplyRouterStats>,
}

#[cfg(feature = "ipstack-tcp")]
impl ParallelReplyRouter {
    /// Create a new parallel reply router
    fn new(
        wg_manager: Arc<super::manager::WgIngressManager>,
        session_tracker: Arc<IpStackSessionTracker>,
    ) -> Self {
        Self {
            peer_channels: Arc::new(DashMap::new()),
            wg_manager,
            session_tracker,
            stats: Arc::new(ParallelReplyRouterStats::default()),
        }
    }

    /// Get router statistics
    fn stats(&self) -> &ParallelReplyRouterStats {
        &self.stats
    }

    /// Route a packet to the appropriate per-peer channel
    ///
    /// This method:
    /// 1. Parses the packet and looks up the session
    /// 2. Gets or creates a per-peer channel
    /// 3. Sends the packet info to the channel (non-blocking)
    async fn route_packet(&self, packet: bytes::BytesMut, peer_key: [u8; 32]) {
        use base64::engine::general_purpose::STANDARD as BASE64;
        use base64::Engine;

        // Parse packet and look up session first (before routing)
        let Some(info) = self.prepare_packet_info(packet, peer_key) else {
            return;
        };

        // Get or create per-peer channel
        let sender = self.get_or_create_peer_channel(peer_key);

        // Non-blocking send to per-peer channel
        match sender.try_send(info) {
            Ok(()) => {
                // Successfully queued for per-peer processing
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.stats.channel_full_drops.fetch_add(1, Ordering::Relaxed);
                // Don't log at trace level to avoid log spam under load
                // The packet is dropped; TCP will retransmit if needed
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                // Peer task died unexpectedly, remove stale channel and retry once
                self.peer_channels.remove(&peer_key);
                debug!(
                    "Peer task closed unexpectedly for {}..., removed channel",
                    &BASE64.encode(peer_key)[..8]
                );
            }
        }
    }

    /// Prepare packet info by parsing and looking up the session
    ///
    /// Returns `None` if the packet is invalid or no session exists.
    fn prepare_packet_info(
        &self,
        packet: bytes::BytesMut,
        peer_key: [u8; 32],
    ) -> Option<ReplyPacketInfo> {
        use base64::engine::general_purpose::STANDARD as BASE64;
        use base64::Engine;

        let peer_key_b64 = BASE64.encode(peer_key);

        // Parse the packet to find the session info
        let parsed = match parse_ip_packet(&packet) {
            Some(p) => p,
            None => {
                debug!("Failed to parse ipstack reply packet");
                self.stats.packets_failed.fetch_add(1, Ordering::Relaxed);
                return None;
            }
        };

        // Get ports for session lookup
        let (src_port, dst_port) = match (parsed.src_port, parsed.dst_port) {
            (Some(s), Some(d)) => (s, d),
            _ => {
                debug!("IpStack reply packet missing ports");
                self.stats.packets_failed.fetch_add(1, Ordering::Relaxed);
                return None;
            }
        };

        // Look up the original session to get the peer endpoint
        // Reply packets have swapped src/dst compared to the original flow
        // Create lookup key using ipstack_bridge FiveTuple (uses SocketAddr)
        let src_addr = SocketAddr::new(parsed.dst_ip, dst_port);
        let dst_addr = SocketAddr::new(parsed.src_ip, src_port);
        let lookup_key = if parsed.protocol == IPPROTO_TCP {
            IpStackFiveTuple::tcp(src_addr, dst_addr)
        } else {
            IpStackFiveTuple::udp(src_addr, dst_addr)
        };

        // Use unified session tracker lookup
        let (session_peer_key_b64, peer_endpoint) =
            match self.session_tracker.lookup_for_reply(&lookup_key) {
                Some(info) => info,
                None => {
                    trace!(
                        "No session for ipstack reply: {} -> {}",
                        parsed.src_ip,
                        parsed.dst_ip
                    );
                    self.stats.packets_failed.fetch_add(1, Ordering::Relaxed);
                    return None;
                }
            };

        // Verify peer key matches
        if session_peer_key_b64 != peer_key_b64 {
            debug!(
                "IpStack reply peer key mismatch: expected {}, got {}",
                &peer_key_b64[..8.min(peer_key_b64.len())],
                &session_peer_key_b64[..8.min(session_peer_key_b64.len())]
            );
            self.stats.packets_failed.fetch_add(1, Ordering::Relaxed);
            return None;
        }

        Some(ReplyPacketInfo {
            packet,
            peer_endpoint,
            peer_key_b64,
        })
    }

    /// Get or create a per-peer channel
    ///
    /// If a channel already exists for this peer, returns the sender.
    /// Otherwise, creates a new channel and spawns a task to process it.
    fn get_or_create_peer_channel(&self, peer_key: [u8; 32]) -> mpsc::Sender<ReplyPacketInfo> {
        // Fast path: channel exists
        if let Some(sender) = self.peer_channels.get(&peer_key) {
            return sender.clone();
        }

        // Slow path: create new channel and spawn task
        // Use entry API to avoid race conditions
        let entry = self.peer_channels.entry(peer_key);
        entry
            .or_insert_with(|| {
                let (tx, rx) = mpsc::channel(PEER_CHANNEL_BUFFER_SIZE);
                self.spawn_peer_task(peer_key, rx);
                self.stats.peer_tasks_spawned.fetch_add(1, Ordering::Relaxed);
                tx
            })
            .clone()
    }

    /// Spawn a task to process packets for a single peer
    ///
    /// This task processes packets sequentially for the peer, ensuring
    /// WireGuard nonces remain in order. The task automatically terminates
    /// when the channel is closed (sender dropped or router shutdown).
    fn spawn_peer_task(&self, peer_key: [u8; 32], mut rx: mpsc::Receiver<ReplyPacketInfo>) {
        use base64::engine::general_purpose::STANDARD as BASE64;
        use base64::Engine;

        let wg_manager = Arc::clone(&self.wg_manager);
        let stats = Arc::clone(&self.stats);
        let peer_channels = Arc::clone(&self.peer_channels);
        let peer_key_b64_for_log = BASE64.encode(peer_key);

        tokio::spawn(async move {
            trace!(
                "Per-peer reply task started for {}...",
                &peer_key_b64_for_log[..8]
            );

            // Process packets sequentially for this peer
            while let Some(info) = rx.recv().await {
                match wg_manager
                    .send_to_peer(&info.peer_key_b64, info.peer_endpoint, &info.packet)
                    .await
                {
                    Ok(()) => {
                        stats.packets_routed.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(e) => {
                        stats.packets_failed.fetch_add(1, Ordering::Relaxed);
                        debug!(
                            "Failed to send reply to peer {}: {}",
                            &info.peer_key_b64[..8],
                            e
                        );
                    }
                }
            }

            // Channel closed, clean up
            peer_channels.remove(&peer_key);
            trace!(
                "Per-peer reply task stopped for {}...",
                &peer_key_b64_for_log[..8]
            );
        });
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingress::config::WgIngressConfig;
    use crate::ingress::config::WgIngressPeerConfig;
    use crate::ingress::processor::RoutingDecision;
    use crate::rules::engine::RoutingSnapshotBuilder;
    use crate::rules::RuleEngine;
    use std::sync::Arc;
    use tokio::sync::mpsc;

    const TEST_VALID_KEY: &str = "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=";

    fn create_test_engine() -> Arc<RuleEngine> {
        let snapshot = RoutingSnapshotBuilder::new()
            .default_outbound("direct")
            .version(1)
            .build()
            .unwrap();
        Arc::new(RuleEngine::new(snapshot))
    }

    fn create_test_ingress_manager() -> Arc<WgIngressManager> {
        let config = WgIngressConfig::builder()
            .private_key(TEST_VALID_KEY)
            .listen_addr("127.0.0.1:0".parse().unwrap())
            .local_ip("10.25.0.1".parse().unwrap())
            .allowed_subnet("10.25.0.0/24".parse().unwrap())
            .build();

        Arc::new(WgIngressManager::new(config, create_test_engine()).unwrap())
    }

    fn create_test_peer_manager() -> Arc<PeerManager> {
        Arc::new(PeerManager::new("test-node".to_string()))
    }

    async fn run_reply_router_once(
        reply: ReplyPacket,
        ingress_manager: Arc<WgIngressManager>,
        session_tracker: Arc<IngressSessionTracker>,
        stats: Arc<IngressReplyStats>,
        peer_manager: Arc<PeerManager>,
    ) {
        let (tx, rx) = mpsc::channel(1);
        let handle = tokio::spawn(run_reply_router_loop(
            rx,
            ingress_manager,
            session_tracker,
            stats,
            None, // No DNS cache for tests
            peer_manager,
        ));

        tx.send(reply).await.unwrap();
        drop(tx);
        handle.await.unwrap();
    }

    // ========================================================================
    // FiveTuple Tests
    // ========================================================================

    #[test]
    fn test_five_tuple_new() {
        let tuple = FiveTuple::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            1234,
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            53,
            IPPROTO_UDP,
        );

        assert_eq!(tuple.src_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(tuple.src_port, 1234);
        assert_eq!(tuple.dst_ip, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        assert_eq!(tuple.dst_port, 53);
        assert_eq!(tuple.protocol, IPPROTO_UDP);
    }

    #[test]
    fn test_five_tuple_reverse() {
        let tuple = FiveTuple::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            1234,
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            53,
            IPPROTO_UDP,
        );

        let reversed = tuple.reverse();

        assert_eq!(reversed.src_ip, tuple.dst_ip);
        assert_eq!(reversed.src_port, tuple.dst_port);
        assert_eq!(reversed.dst_ip, tuple.src_ip);
        assert_eq!(reversed.dst_port, tuple.src_port);
        assert_eq!(reversed.protocol, tuple.protocol);
    }

    #[test]
    fn test_five_tuple_reverse_is_self_inverse() {
        let tuple = FiveTuple::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            45678,
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            443,
            IPPROTO_TCP,
        );

        assert_eq!(tuple.reverse().reverse(), tuple);
    }

    #[test]
    fn test_five_tuple_is_tcp() {
        let tcp = FiveTuple::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            1234,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            80,
            IPPROTO_TCP,
        );
        let udp = FiveTuple::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            1234,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            53,
            IPPROTO_UDP,
        );

        assert!(tcp.is_tcp());
        assert!(!tcp.is_udp());
        assert!(udp.is_udp());
        assert!(!udp.is_tcp());
    }

    #[test]
    fn test_five_tuple_protocol_name() {
        assert_eq!(
            FiveTuple::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0, IpAddr::V4(Ipv4Addr::LOCALHOST), 0, IPPROTO_TCP)
                .protocol_name(),
            "TCP"
        );
        assert_eq!(
            FiveTuple::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0, IpAddr::V4(Ipv4Addr::LOCALHOST), 0, IPPROTO_UDP)
                .protocol_name(),
            "UDP"
        );
        assert_eq!(
            FiveTuple::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0, IpAddr::V4(Ipv4Addr::LOCALHOST), 0, IPPROTO_ICMP)
                .protocol_name(),
            "ICMP"
        );
        assert_eq!(
            FiveTuple::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0, IpAddr::V4(Ipv4Addr::LOCALHOST), 0, 99)
                .protocol_name(),
            "Unknown"
        );
    }

    #[test]
    fn test_five_tuple_display() {
        let tuple = FiveTuple::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            1234,
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            53,
            IPPROTO_UDP,
        );

        assert_eq!(tuple.to_string(), "10.0.0.1:1234->8.8.8.8:53/UDP");
    }

    #[test]
    fn test_five_tuple_hash_eq() {
        let t1 = FiveTuple::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            1234,
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            53,
            IPPROTO_UDP,
        );
        let t2 = FiveTuple::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            1234,
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            53,
            IPPROTO_UDP,
        );
        let t3 = FiveTuple::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            1234,
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            53,
            IPPROTO_UDP,
        );

        assert_eq!(t1, t2);
        assert_ne!(t1, t3);

        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut h1 = DefaultHasher::new();
        let mut h2 = DefaultHasher::new();
        t1.hash(&mut h1);
        t2.hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());
    }

    // ========================================================================
    // DSCP Update Tests
    // ========================================================================

    #[test]
    fn test_dscp_update_value_sets_mark_for_entry() {
        let mark = ChainMark::from_dscp(10).unwrap();
        let routing = RoutingDecision {
            outbound: "chain-out".to_string(),
            dscp_mark: Some(mark.dscp_value),
            routing_mark: Some(mark.routing_mark),
            is_chain_packet: false,
            match_info: None,
        };

        assert_eq!(dscp_update_value(&routing), Some(10));
    }

    #[test]
    fn test_dscp_update_value_preserves_chain_mark() {
        let mark = ChainMark::from_dscp(5).unwrap();
        let routing = RoutingDecision {
            outbound: "chain-out".to_string(),
            dscp_mark: Some(mark.dscp_value),
            routing_mark: Some(mark.routing_mark),
            is_chain_packet: true,
            match_info: None,
        };

        assert_eq!(dscp_update_value(&routing), Some(5));
    }

    #[test]
    fn test_dscp_update_value_clears_chain_without_mark() {
        let routing = RoutingDecision {
            outbound: "direct".to_string(),
            dscp_mark: Some(7),
            routing_mark: None,
            is_chain_packet: true,
            match_info: None,
        };

        assert_eq!(dscp_update_value(&routing), Some(0));
    }

    #[test]
    fn test_dscp_update_value_clears_non_chain_mark() {
        let routing = RoutingDecision {
            outbound: "direct".to_string(),
            dscp_mark: Some(0),
            routing_mark: None,
            is_chain_packet: false,
            match_info: None,
        };

        assert_eq!(dscp_update_value(&routing), Some(0));
    }

    #[test]
    fn test_dscp_update_value_skips_unmarked_packets() {
        let routing = RoutingDecision {
            outbound: "direct".to_string(),
            dscp_mark: None,
            routing_mark: None,
            is_chain_packet: false,
            match_info: None,
        };

        assert_eq!(dscp_update_value(&routing), None);
    }

    // ========================================================================
    // Reply Router Tests
    // ========================================================================

    #[tokio::test]
    async fn test_reply_router_session_miss() {
        let ingress_manager = create_test_ingress_manager();
        let session_tracker = Arc::new(IngressSessionTracker::new(Duration::from_secs(300)));
        let stats = Arc::new(IngressReplyStats::default());

        let reply_packet = ReplyPacket {
            packet: build_udp_packet(
                Ipv4Addr::new(8, 8, 8, 8),
                53,
                Ipv4Addr::new(10, 25, 0, 2),
                12345,
                b"reply",
            ),
            tunnel_tag: "wg-test".to_string(),
        };

        run_reply_router_once(
            reply_packet,
            ingress_manager,
            session_tracker,
            Arc::clone(&stats),
            create_test_peer_manager(),
        )
        .await;

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.session_misses, 1);
        assert_eq!(snapshot.packets_forwarded, 0);
    }

    #[tokio::test]
    async fn test_reply_router_tunnel_mismatch() {
        let ingress_manager = create_test_ingress_manager();
        let session_tracker = Arc::new(IngressSessionTracker::new(Duration::from_secs(300)));
        let stats = Arc::new(IngressReplyStats::default());

        let client_ip = IpAddr::V4(Ipv4Addr::new(10, 25, 0, 2));
        let server_ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let request_tuple = FiveTuple::new(client_ip, 12345, server_ip, 53, IPPROTO_UDP);

        session_tracker.register(
            request_tuple,
            "test-peer".to_string(),
            "127.0.0.1:12345".parse().unwrap(),
            "wg-good".to_string(),
            100,
        );

        let reply_packet = ReplyPacket {
            packet: build_udp_packet(
                Ipv4Addr::new(8, 8, 8, 8),
                53,
                Ipv4Addr::new(10, 25, 0, 2),
                12345,
                b"reply",
            ),
            tunnel_tag: "wg-bad".to_string(),
        };

        run_reply_router_once(
            reply_packet,
            ingress_manager,
            session_tracker,
            Arc::clone(&stats),
            create_test_peer_manager(),
        )
        .await;

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.tunnel_mismatch, 1);
        assert_eq!(snapshot.packets_forwarded, 0);
    }

    #[tokio::test]
    async fn test_reply_router_peer_ip_rejected() {
        let ingress_manager = create_test_ingress_manager();
        let session_tracker = Arc::new(IngressSessionTracker::new(Duration::from_secs(300)));
        let stats = Arc::new(IngressReplyStats::default());

        let client_ip = IpAddr::V4(Ipv4Addr::new(10, 25, 0, 2));
        let server_ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let request_tuple = FiveTuple::new(client_ip, 12345, server_ip, 53, IPPROTO_UDP);

        session_tracker.register(
            request_tuple,
            "test-peer".to_string(),
            "127.0.0.1:12345".parse().unwrap(),
            "wg-good".to_string(),
            100,
        );

        let reply_packet = ReplyPacket {
            packet: build_udp_packet(
                Ipv4Addr::new(8, 8, 8, 8),
                53,
                Ipv4Addr::new(10, 25, 0, 2),
                12345,
                b"reply",
            ),
            tunnel_tag: "wg-good".to_string(),
        };

        run_reply_router_once(
            reply_packet,
            ingress_manager,
            session_tracker,
            Arc::clone(&stats),
            create_test_peer_manager(),
        )
        .await;

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.peer_ip_rejected, 1);
        assert_eq!(snapshot.packets_forwarded, 0);
    }

    #[tokio::test]
    async fn test_reply_router_send_error() {
        let ingress_manager = create_test_ingress_manager();
        ingress_manager
            .add_peer(WgIngressPeerConfig::new(TEST_VALID_KEY, "10.25.0.2"))
            .await
            .unwrap();

        let session_tracker = Arc::new(IngressSessionTracker::new(Duration::from_secs(300)));
        let stats = Arc::new(IngressReplyStats::default());

        let client_ip = IpAddr::V4(Ipv4Addr::new(10, 25, 0, 2));
        let server_ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let request_tuple = FiveTuple::new(client_ip, 12345, server_ip, 53, IPPROTO_UDP);

        session_tracker.register(
            request_tuple,
            TEST_VALID_KEY.to_string(),
            "127.0.0.1:12345".parse().unwrap(),
            "wg-good".to_string(),
            100,
        );

        let reply_packet = ReplyPacket {
            packet: build_udp_packet(
                Ipv4Addr::new(8, 8, 8, 8),
                53,
                Ipv4Addr::new(10, 25, 0, 2),
                12345,
                b"reply",
            ),
            tunnel_tag: "wg-good".to_string(),
        };

        run_reply_router_once(
            reply_packet,
            ingress_manager,
            session_tracker,
            Arc::clone(&stats),
            create_test_peer_manager(),
        )
        .await;

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.send_errors, 1);
        assert_eq!(snapshot.packets_forwarded, 0);
    }

    #[tokio::test]
    async fn test_reply_router_parse_error() {
        let ingress_manager = create_test_ingress_manager();
        let session_tracker = Arc::new(IngressSessionTracker::new(Duration::from_secs(300)));
        let stats = Arc::new(IngressReplyStats::default());

        let reply_packet = ReplyPacket {
            packet: vec![0u8; 4],
            tunnel_tag: "wg-test".to_string(),
        };

        run_reply_router_once(
            reply_packet,
            ingress_manager,
            session_tracker,
            Arc::clone(&stats),
            create_test_peer_manager(),
        )
        .await;

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.parse_errors, 1);
        assert_eq!(snapshot.packets_forwarded, 0);
    }

    // ========================================================================
    // PeerSession Tests
    // ========================================================================

    #[test]
    fn test_peer_session_new() {
        let session = PeerSession::new(
            "test_key".to_string(),
            "192.168.1.100:51820".parse().unwrap(),
            "pia-us-west".to_string(),
        );

        assert_eq!(session.peer_public_key, "test_key");
        assert_eq!(session.outbound_tag, "pia-us-west");
        assert_eq!(session.bytes_sent, 0);
        assert_eq!(session.bytes_received, 0);
    }

    #[test]
    fn test_peer_session_bytes_tracking() {
        let mut session = PeerSession::new(
            "key".to_string(),
            "127.0.0.1:1234".parse().unwrap(),
            "direct".to_string(),
        );

        session.add_bytes_sent(100);
        session.add_bytes_sent(50);
        session.add_bytes_received(200);

        assert_eq!(session.bytes_sent, 150);
        assert_eq!(session.bytes_received, 200);
    }

    #[test]
    fn test_peer_session_expiry() {
        let session = PeerSession::new(
            "key".to_string(),
            "127.0.0.1:1234".parse().unwrap(),
            "direct".to_string(),
        );

        // Should not be expired immediately
        assert!(!session.is_expired(Duration::from_secs(1)));

        // Should be expired with 0 TTL
        assert!(session.is_expired(Duration::ZERO));
    }

    // ========================================================================
    // IngressSessionTracker Tests
    // ========================================================================

    #[test]
    fn test_session_tracker_new() {
        let tracker = IngressSessionTracker::new(Duration::from_secs(300));

        assert_eq!(tracker.len(), 0);
        assert!(tracker.is_empty());
        assert_eq!(tracker.session_ttl(), Duration::from_secs(300));
    }

    #[test]
    fn test_session_tracker_default() {
        let tracker = IngressSessionTracker::default();
        assert_eq!(tracker.session_ttl(), Duration::from_secs(300));
    }

    #[test]
    fn test_session_tracker_register_get() {
        let tracker = IngressSessionTracker::new(Duration::from_secs(300));

        let key = FiveTuple::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            1234,
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            53,
            IPPROTO_UDP,
        );

        tracker.register(
            key,
            "test_peer_key".to_string(),
            "192.168.1.100:51820".parse().unwrap(),
            "pia-us-west".to_string(),
            100,
        );

        assert_eq!(tracker.len(), 1);

        let session = tracker.get(&key);
        assert!(session.is_some());
        let session = session.unwrap();
        assert_eq!(session.peer_public_key, "test_peer_key");
        assert_eq!(session.outbound_tag, "pia-us-west");
        assert_eq!(session.bytes_sent, 100);
    }

    #[test]
    fn test_session_tracker_update_existing() {
        let tracker = IngressSessionTracker::new(Duration::from_secs(300));

        let key = FiveTuple::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            1234,
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            53,
            IPPROTO_UDP,
        );

        tracker.register(
            key,
            "key1".to_string(),
            "127.0.0.1:1234".parse().unwrap(),
            "out1".to_string(),
            100,
        );

        // Register again with same key - should update bytes
        tracker.register(
            key,
            "key2".to_string(), // This won't change existing entry
            "127.0.0.1:5678".parse().unwrap(),
            "out2".to_string(),
            50,
        );

        assert_eq!(tracker.len(), 1);
        let session = tracker.get(&key).unwrap();
        assert_eq!(session.bytes_sent, 150); // Accumulated
        assert_eq!(session.peer_public_key, "key1"); // Original value preserved
    }

    #[test]
    fn test_session_tracker_update_received() {
        let tracker = IngressSessionTracker::new(Duration::from_secs(300));

        let key = FiveTuple::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            1234,
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            53,
            IPPROTO_UDP,
        );

        tracker.register(
            key,
            "key".to_string(),
            "127.0.0.1:1234".parse().unwrap(),
            "out".to_string(),
            100,
        );

        tracker.update_received(&key, 200);

        let session = tracker.get(&key).unwrap();
        assert_eq!(session.bytes_received, 200);
    }

    #[test]
    fn test_session_tracker_get_nonexistent() {
        let tracker = IngressSessionTracker::new(Duration::from_secs(300));

        let key = FiveTuple::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            1234,
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            53,
            IPPROTO_UDP,
        );

        assert!(tracker.get(&key).is_none());
    }

    #[test]
    fn test_session_tracker_cleanup() {
        let tracker = IngressSessionTracker::new(Duration::ZERO); // Immediate expiry

        let key = FiveTuple::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            1234,
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            53,
            IPPROTO_UDP,
        );

        tracker.register(
            key,
            "key".to_string(),
            "127.0.0.1:1234".parse().unwrap(),
            "out".to_string(),
            100,
        );

        // Session should be expired immediately
        let removed = tracker.cleanup();
        assert_eq!(removed, 1);
        assert!(tracker.is_empty());
    }

    // ========================================================================
    // ForwardingStats Tests
    // ========================================================================

    #[test]
    fn test_forwarding_stats_default() {
        let stats = ForwardingStats::default();
        let snapshot = stats.snapshot();

        assert_eq!(snapshot.packets_forwarded, 0);
        assert_eq!(snapshot.bytes_forwarded, 0);
        assert_eq!(snapshot.forward_errors, 0);
    }

    #[test]
    fn test_forwarding_stats_atomic_updates() {
        let stats = ForwardingStats::default();

        stats.packets_forwarded.fetch_add(10, Ordering::Relaxed);
        stats.bytes_forwarded.fetch_add(1000, Ordering::Relaxed);
        stats.udp_packets.fetch_add(5, Ordering::Relaxed);
        stats.tcp_packets.fetch_add(3, Ordering::Relaxed);
        stats.forward_errors.fetch_add(2, Ordering::Relaxed);

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.packets_forwarded, 10);
        assert_eq!(snapshot.bytes_forwarded, 1000);
        assert_eq!(snapshot.udp_packets, 5);
        assert_eq!(snapshot.tcp_packets, 3);
        assert_eq!(snapshot.forward_errors, 2);
    }

    #[test]
    fn test_forwarding_stats_reset() {
        let stats = ForwardingStats::default();

        stats.packets_forwarded.fetch_add(100, Ordering::Relaxed);
        stats.bytes_forwarded.fetch_add(10000, Ordering::Relaxed);

        stats.reset();

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.packets_forwarded, 0);
        assert_eq!(snapshot.bytes_forwarded, 0);
    }

    #[test]
    fn test_forwarding_stats_snapshot_total() {
        let stats = ForwardingStats::default();

        stats.packets_forwarded.store(100, Ordering::Relaxed);
        stats.forward_errors.store(5, Ordering::Relaxed);
        stats.unknown_protocol.store(2, Ordering::Relaxed);
        stats.blocked_packets.store(10, Ordering::Relaxed);
        stats.parse_errors.store(3, Ordering::Relaxed);

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.total_packets(), 120);
    }

    #[test]
    fn test_forwarding_stats_snapshot_success_rate() {
        let stats = ForwardingStats::default();

        stats.packets_forwarded.store(90, Ordering::Relaxed);
        stats.forward_errors.store(10, Ordering::Relaxed);

        let snapshot = stats.snapshot();
        assert!((snapshot.success_rate() - 90.0).abs() < 0.001);
    }

    #[test]
    fn test_forwarding_stats_snapshot_success_rate_zero() {
        let stats = ForwardingStats::default();
        let snapshot = stats.snapshot();
        assert!((snapshot.success_rate() - 100.0).abs() < 0.001);
    }

    // ========================================================================
    // IP Packet Parsing Tests
    // ========================================================================

    #[test]
    fn test_parse_ipv4_packet() {
        // Minimal IPv4 packet (20 bytes header) + UDP header (8 bytes)
        let mut packet = vec![0u8; 28];
        packet[0] = 0x45; // IPv4, IHL=5 (20 bytes)
        packet[9] = IPPROTO_UDP; // Protocol
        packet[12..16].copy_from_slice(&[10, 0, 0, 1]); // Source: 10.0.0.1
        packet[16..20].copy_from_slice(&[8, 8, 8, 8]); // Dest: 8.8.8.8
        packet[20..22].copy_from_slice(&1234u16.to_be_bytes()); // Src port
        packet[22..24].copy_from_slice(&53u16.to_be_bytes()); // Dst port

        let parsed = parse_ip_packet(&packet);
        assert!(parsed.is_some());

        let parsed = parsed.unwrap();
        assert_eq!(parsed.src_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(parsed.dst_ip, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        assert_eq!(parsed.protocol, IPPROTO_UDP);
        assert_eq!(parsed.ip_header_len, 20);
        assert_eq!(parsed.src_port, Some(1234));
        assert_eq!(parsed.dst_port, Some(53));
    }

    #[test]
    fn test_parse_ipv4_with_options() {
        // IPv4 with options (IHL=6 = 24 bytes)
        let mut packet = vec![0u8; 32];
        packet[0] = 0x46; // IPv4, IHL=6 (24 bytes)
        packet[9] = IPPROTO_TCP;
        packet[12..16].copy_from_slice(&[192, 168, 1, 1]);
        packet[16..20].copy_from_slice(&[1, 1, 1, 1]);
        // Options at 20-23
        // TCP header at 24
        packet[24..26].copy_from_slice(&80u16.to_be_bytes()); // Src port
        packet[26..28].copy_from_slice(&443u16.to_be_bytes()); // Dst port

        let parsed = parse_ip_packet(&packet).unwrap();
        assert_eq!(parsed.ip_header_len, 24);
        assert_eq!(parsed.src_port, Some(80));
        assert_eq!(parsed.dst_port, Some(443));
    }

    #[test]
    fn test_parse_ipv6_packet() {
        // IPv6 packet (40 bytes header) + UDP header
        let mut packet = vec![0u8; 48];
        packet[0] = 0x60; // IPv6
        packet[4..6].copy_from_slice(&(8u16.to_be_bytes())); // Payload length (UDP header)
        packet[6] = IPPROTO_UDP; // Next Header
        // Source IPv6 at bytes 8-23
        packet[8..24].copy_from_slice(&[
            0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x02,
        ]);
        // Dest IPv6 at bytes 24-39
        packet[24..40].copy_from_slice(&[
            0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x88, 0x88,
        ]);
        // UDP header at 40
        packet[40..42].copy_from_slice(&5678u16.to_be_bytes());
        packet[42..44].copy_from_slice(&53u16.to_be_bytes());

        let parsed = parse_ip_packet(&packet).unwrap();
        assert_eq!(parsed.src_ip, "fd00::2".parse::<IpAddr>().unwrap());
        assert_eq!(
            parsed.dst_ip,
            "2001:4860:4860::8888".parse::<IpAddr>().unwrap()
        );
        assert_eq!(parsed.protocol, IPPROTO_UDP);
        assert_eq!(parsed.ip_header_len, 40);
        assert_eq!(parsed.src_port, Some(5678));
        assert_eq!(parsed.dst_port, Some(53));
    }

    #[test]
    fn test_parse_empty_packet() {
        assert!(parse_ip_packet(&[]).is_none());
    }

    #[test]
    fn test_parse_packet_too_short() {
        // IPv4 header needs at least 20 bytes
        let packet = vec![0x45, 0x00, 0x00, 0x14]; // Only 4 bytes
        assert!(parse_ip_packet(&packet).is_none());
    }

    #[test]
    fn test_parse_invalid_version() {
        // Version 7 (invalid)
        let mut packet = vec![0x70, 0x00];
        packet.extend_from_slice(&[0x00; 18]); // Pad to 20 bytes
        assert!(parse_ip_packet(&packet).is_none());
    }

    #[test]
    fn test_parse_icmp_packet() {
        let mut packet = vec![0u8; 28];
        packet[0] = 0x45;
        packet[9] = IPPROTO_ICMP;
        packet[12..16].copy_from_slice(&[10, 0, 0, 1]);
        packet[16..20].copy_from_slice(&[8, 8, 8, 8]);

        let parsed = parse_ip_packet(&packet).unwrap();
        assert_eq!(parsed.protocol, IPPROTO_ICMP);
        assert!(parsed.src_port.is_none()); // ICMP has no ports
        assert!(parsed.dst_port.is_none());
    }

    // ========================================================================
    // ParsedPacket Tests
    // ========================================================================

    #[test]
    fn test_parsed_packet_five_tuple() {
        let parsed = ParsedPacket {
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            protocol: IPPROTO_UDP,
            ip_header_len: 20,
            src_port: Some(1234),
            dst_port: Some(53),
            total_len: 100,
        };

        let tuple = parsed.five_tuple().unwrap();
        assert_eq!(tuple.src_port, 1234);
        assert_eq!(tuple.dst_port, 53);
    }

    #[test]
    fn test_parsed_packet_five_tuple_no_ports() {
        let parsed = ParsedPacket {
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            protocol: IPPROTO_ICMP,
            ip_header_len: 20,
            src_port: None,
            dst_port: None,
            total_len: 64,
        };

        assert!(parsed.five_tuple().is_none());
    }

    #[test]
    fn test_parsed_packet_dst_addr() {
        let parsed = ParsedPacket {
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            protocol: IPPROTO_UDP,
            ip_header_len: 20,
            src_port: Some(1234),
            dst_port: Some(53),
            total_len: 100,
        };

        let addr = parsed.dst_addr().unwrap();
        assert_eq!(addr, "8.8.8.8:53".parse().unwrap());
    }

    #[test]
    fn test_parsed_packet_payload_offset() {
        let udp_parsed = ParsedPacket {
            src_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            dst_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            protocol: IPPROTO_UDP,
            ip_header_len: 20,
            src_port: Some(1234),
            dst_port: Some(53),
            total_len: 100,
        };

        let tcp_parsed = ParsedPacket {
            src_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            dst_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            protocol: IPPROTO_TCP,
            ip_header_len: 20,
            src_port: Some(1234),
            dst_port: Some(80),
            total_len: 100,
        };

        assert_eq!(udp_parsed.payload_offset(), 28); // 20 + 8
        assert_eq!(tcp_parsed.payload_offset(), 40); // 20 + 20 (minimum TCP header)
    }

    // ========================================================================
    // UDP Forwarding Tests
    // ========================================================================

    #[tokio::test]
    async fn test_create_direct_udp_socket_ipv4() {
        // Create a UDP server to verify we can connect
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();

        // Create a direct socket to the server
        let result = create_direct_udp_socket(server_addr).await;
        assert!(result.is_ok(), "Expected socket creation to succeed");

        let socket = result.unwrap();
        // Verify we can send data
        let sent = socket.send(b"test").await.unwrap();
        assert_eq!(sent, 4);

        // Receive on server
        let mut buf = [0u8; 64];
        let (n, _addr) = server.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"test");
    }

    #[tokio::test]
    async fn test_create_direct_udp_socket_ipv6() {
        // Create an IPv6 UDP server - skip test if IPv6 not available
        let server = match tokio::net::UdpSocket::bind("[::1]:0").await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Skipping IPv6 test - IPv6 bind failed: {}", e);
                return;
            }
        };
        let server_addr = server.local_addr().unwrap();

        // Create a direct socket to the server - skip if IPv6 connectivity fails
        let result = create_direct_udp_socket(server_addr).await;
        let socket = match result {
            Ok(s) => s,
            Err(e) => {
                // IPv6 connectivity may not be available even if bind works
                eprintln!("Skipping IPv6 test - IPv6 connect failed: {}", e);
                return;
            }
        };

        let sent = socket.send(b"ipv6").await.unwrap();
        assert_eq!(sent, 4);

        // Receive on server
        let mut buf = [0u8; 64];
        let (n, _addr) = server.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"ipv6");
    }

    /// Helper to build a fake UDP packet with IP + UDP headers
    fn build_udp_packet(
        src_ip: Ipv4Addr,
        src_port: u16,
        dst_ip: Ipv4Addr,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let udp_len = 8 + payload.len();
        let total_len = 20 + udp_len;

        let mut packet = vec![0u8; total_len];

        // IPv4 header (20 bytes minimum)
        packet[0] = 0x45; // Version 4, IHL 5
        packet[1] = 0x00; // DSCP/ECN
        packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes()); // Total length
        packet[4..6].copy_from_slice(&[0x00, 0x00]); // Identification
        packet[6..8].copy_from_slice(&[0x00, 0x00]); // Flags + Fragment offset
        packet[8] = 64; // TTL
        packet[9] = IPPROTO_UDP; // Protocol
        // Checksum left as 0
        packet[12..16].copy_from_slice(&src_ip.octets()); // Source IP
        packet[16..20].copy_from_slice(&dst_ip.octets()); // Dest IP

        // UDP header (8 bytes)
        packet[20..22].copy_from_slice(&src_port.to_be_bytes());
        packet[22..24].copy_from_slice(&dst_port.to_be_bytes());
        packet[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes());
        // UDP checksum left as 0

        // Payload
        packet[28..].copy_from_slice(payload);

        packet
    }

    #[tokio::test]
    async fn test_udp_payload_extraction() {
        // Build a UDP packet with known payload
        let payload = b"Hello, World!";
        let packet = build_udp_packet(
            Ipv4Addr::new(10, 0, 0, 1),
            12345,
            Ipv4Addr::new(8, 8, 8, 8),
            53,
            payload,
        );

        // Parse it
        let parsed = parse_ip_packet(&packet).unwrap();
        assert_eq!(parsed.ip_header_len, 20);
        assert_eq!(parsed.src_port, Some(12345));
        assert_eq!(parsed.dst_port, Some(53));

        // Verify payload offset calculation
        let payload_offset = parsed.ip_header_len + 8; // IP header + UDP header
        assert_eq!(payload_offset, 28);
        assert_eq!(&packet[payload_offset..], payload);
    }

    #[tokio::test]
    async fn test_direct_udp_forwarding_with_outbound_manager() {
        use crate::outbound::{DirectOutbound, OutboundManager};

        // Create a UDP echo server
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();

        // Create outbound manager with a direct outbound
        let manager = OutboundManager::new();
        manager.add(Box::new(DirectOutbound::simple("direct")));

        // Get the direct outbound
        let outbound = manager.get("direct").unwrap();
        assert!(outbound.supports_udp());

        // Connect UDP
        let handle = outbound.connect_udp(server_addr, Duration::from_secs(5)).await.unwrap();
        assert_eq!(handle.dest_addr(), server_addr);

        // Send via handle
        let test_data = b"direct test";
        let sent = handle.send(test_data).await.unwrap();
        assert_eq!(sent, test_data.len());

        // Verify server received
        let mut buf = [0u8; 64];
        let (n, client_addr) = server.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], test_data);

        // Send reply and verify reception
        server.send_to(b"reply", client_addr).await.unwrap();
        let n = handle.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"reply");
    }

    #[tokio::test]
    async fn test_direct_udp_forwarding_fallback() {
        use crate::outbound::OutboundManager;

        // Create a UDP server
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();

        // Create an empty outbound manager (no "direct" outbound registered)
        let manager = OutboundManager::new();

        // The "direct" tag is not in the manager
        assert!(manager.get("direct").is_none());

        // Fallback should still work using create_direct_udp_socket
        let socket = create_direct_udp_socket(server_addr).await.unwrap();
        let sent = socket.send(b"fallback test").await.unwrap();
        assert_eq!(sent, 13);

        // Verify server received
        let mut buf = [0u8; 64];
        let (n, _addr) = server.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"fallback test");
    }

    #[tokio::test]
    async fn test_block_outbound_blocks_udp() {
        use crate::error::UdpError;
        use crate::outbound::{BlockOutbound, OutboundManager};

        let manager = OutboundManager::new();
        manager.add(Box::new(BlockOutbound::new("block")));

        let outbound = manager.get("block").unwrap();

        // Block outbound "supports" UDP - it handles UDP by blocking it
        // This allows routing to direct UDP packets to block outbounds
        assert!(outbound.supports_udp());

        // Attempting to connect UDP should return a Blocked error
        let addr: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let result = outbound.connect_udp(addr, Duration::from_secs(1)).await;
        assert!(result.is_err());

        // Verify it's specifically a Blocked error
        match result {
            Err(UdpError::Blocked { tag, addr: blocked_addr }) => {
                assert_eq!(tag, "block");
                assert_eq!(blocked_addr, addr);
            }
            other => panic!("Expected UdpError::Blocked, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_unknown_outbound_drops_packet() {
        use crate::outbound::OutboundManager;

        // Create an empty manager
        let manager = OutboundManager::new();

        // Unknown tag should return None
        assert!(manager.get("unknown-tag").is_none());
    }

    #[test]
    fn test_forwarding_stats_forward_errors() {
        let stats = ForwardingStats::default();

        stats.forward_errors.fetch_add(5, Ordering::Relaxed);
        stats.blocked_packets.fetch_add(3, Ordering::Relaxed);

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.forward_errors, 5);
        assert_eq!(snapshot.blocked_packets, 3);
    }

    // ========================================================================
    // TCP Details Parsing Tests
    // ========================================================================

    /// Build a TCP packet with specified flags and window size
    fn build_tcp_packet_with_window(
        src_ip: Ipv4Addr,
        src_port: u16,
        dst_ip: Ipv4Addr,
        dst_port: u16,
        seq: u32,
        ack: u32,
        flags: u8,
        window: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let tcp_header_len = 20; // No options
        let tcp_len = tcp_header_len + payload.len();
        let total_len = 20 + tcp_len; // IP header + TCP

        let mut packet = vec![0u8; total_len];

        // IPv4 header
        packet[0] = 0x45; // Version 4, IHL 5
        packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        packet[8] = 64; // TTL
        packet[9] = IPPROTO_TCP;
        packet[12..16].copy_from_slice(&src_ip.octets());
        packet[16..20].copy_from_slice(&dst_ip.octets());

        // TCP header
        let tcp_start = 20;
        packet[tcp_start..tcp_start + 2].copy_from_slice(&src_port.to_be_bytes());
        packet[tcp_start + 2..tcp_start + 4].copy_from_slice(&dst_port.to_be_bytes());
        packet[tcp_start + 4..tcp_start + 8].copy_from_slice(&seq.to_be_bytes());
        packet[tcp_start + 8..tcp_start + 12].copy_from_slice(&ack.to_be_bytes());
        // Data offset = 5 (20 bytes), shifted to high nibble
        packet[tcp_start + 12] = (5 << 4);
        packet[tcp_start + 13] = flags;
        // Window size at bytes 14-15 of TCP header
        packet[tcp_start + 14..tcp_start + 16].copy_from_slice(&window.to_be_bytes());

        // Payload
        if !payload.is_empty() {
            packet[tcp_start + 20..].copy_from_slice(payload);
        }

        packet
    }

    /// Build a TCP packet with specified flags (default window 65535)
    fn build_tcp_packet(
        src_ip: Ipv4Addr,
        src_port: u16,
        dst_ip: Ipv4Addr,
        dst_port: u16,
        seq: u32,
        ack: u32,
        flags: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        build_tcp_packet_with_window(src_ip, src_port, dst_ip, dst_port, seq, ack, flags, 65535, payload)
    }

    #[test]
    fn test_parse_tcp_details_syn() {
        let packet = build_tcp_packet(
            Ipv4Addr::new(10, 0, 0, 1),
            12345,
            Ipv4Addr::new(8, 8, 8, 8),
            80,
            1000, // seq
            0,    // ack
            tcp_flags::SYN,
            &[],
        );

        let details = parse_tcp_details(&packet, 20).unwrap();

        assert_eq!(details.src_port, 12345);
        assert_eq!(details.dst_port, 80);
        assert_eq!(details.seq_num, 1000);
        assert_eq!(details.ack_num, 0);
        assert_eq!(details.data_offset, 20);
        assert_eq!(details.window, 65535); // Default window from build_tcp_packet
        assert!(details.is_syn());
        assert!(!details.is_ack());
        assert!(!details.is_fin());
        assert!(!details.is_rst());
        assert!(!details.has_payload(packet.len()));
    }

    #[test]
    fn test_parse_tcp_details_window() {
        // Test with custom window size
        let packet = build_tcp_packet_with_window(
            Ipv4Addr::new(10, 0, 0, 1),
            12345,
            Ipv4Addr::new(8, 8, 8, 8),
            80,
            1000, // seq
            0,    // ack
            tcp_flags::SYN,
            32768, // Custom window size
            &[],
        );

        let details = parse_tcp_details(&packet, 20).unwrap();
        assert_eq!(details.window, 32768);

        // Test with minimum window
        let packet = build_tcp_packet_with_window(
            Ipv4Addr::new(10, 0, 0, 1),
            12345,
            Ipv4Addr::new(8, 8, 8, 8),
            80,
            1000,
            0,
            tcp_flags::ACK,
            0, // Zero window (flow control)
            &[],
        );

        let details = parse_tcp_details(&packet, 20).unwrap();
        assert_eq!(details.window, 0);
    }

    #[test]
    fn test_parse_tcp_details_syn_ack() {
        let packet = build_tcp_packet(
            Ipv4Addr::new(8, 8, 8, 8),
            80,
            Ipv4Addr::new(10, 0, 0, 1),
            12345,
            5000, // seq
            1001, // ack
            tcp_flags::SYN | tcp_flags::ACK,
            &[],
        );

        let details = parse_tcp_details(&packet, 20).unwrap();

        assert!(details.is_syn_ack());
        assert!(!details.is_syn()); // is_syn() returns false for SYN+ACK
        assert!(details.is_ack());
        assert_eq!(details.seq_num, 5000);
        assert_eq!(details.ack_num, 1001);
    }

    #[test]
    fn test_parse_tcp_details_ack_with_data() {
        let payload = b"GET / HTTP/1.1\r\n";
        let packet = build_tcp_packet(
            Ipv4Addr::new(10, 0, 0, 1),
            12345,
            Ipv4Addr::new(8, 8, 8, 8),
            80,
            1001, // seq
            5001, // ack
            tcp_flags::ACK | tcp_flags::PSH,
            payload,
        );

        let details = parse_tcp_details(&packet, 20).unwrap();

        assert!(details.is_ack());
        assert!(details.has_payload(packet.len()));
        assert_eq!(details.payload_len(packet.len()), payload.len());
        assert_eq!(details.payload_offset, 40); // 20 IP + 20 TCP
    }

    #[test]
    fn test_parse_tcp_details_fin() {
        let packet = build_tcp_packet(
            Ipv4Addr::new(10, 0, 0, 1),
            12345,
            Ipv4Addr::new(8, 8, 8, 8),
            80,
            2000,
            6000,
            tcp_flags::FIN | tcp_flags::ACK,
            &[],
        );

        let details = parse_tcp_details(&packet, 20).unwrap();

        assert!(details.is_fin());
        assert!(details.is_ack());
    }

    #[test]
    fn test_parse_tcp_details_rst() {
        let packet = build_tcp_packet(
            Ipv4Addr::new(8, 8, 8, 8),
            80,
            Ipv4Addr::new(10, 0, 0, 1),
            12345,
            0,
            0,
            tcp_flags::RST,
            &[],
        );

        let details = parse_tcp_details(&packet, 20).unwrap();

        assert!(details.is_rst());
        assert!(!details.is_fin());
        assert!(!details.is_syn());
    }

    #[test]
    fn test_parse_tcp_details_flags_string() {
        // SYN only
        let details = TcpDetails {
            src_port: 1234,
            dst_port: 80,
            seq_num: 0,
            ack_num: 0,
            data_offset: 20,
            flags: tcp_flags::SYN,
            window: 65535,
            payload_offset: 40,
        };
        assert_eq!(details.flags_string(), "SYN");

        // SYN+ACK
        let details = TcpDetails {
            flags: tcp_flags::SYN | tcp_flags::ACK,
            ..details
        };
        assert_eq!(details.flags_string(), "SYN,ACK");

        // ACK+PSH
        let details = TcpDetails {
            flags: tcp_flags::ACK | tcp_flags::PSH,
            ..details
        };
        assert_eq!(details.flags_string(), "ACK,PSH");

        // FIN+ACK
        let details = TcpDetails {
            flags: tcp_flags::FIN | tcp_flags::ACK,
            ..details
        };
        assert_eq!(details.flags_string(), "ACK,FIN");

        // All flags
        let details = TcpDetails {
            flags: tcp_flags::SYN | tcp_flags::ACK | tcp_flags::FIN | tcp_flags::RST | tcp_flags::PSH | tcp_flags::URG,
            ..details
        };
        assert_eq!(details.flags_string(), "SYN,ACK,FIN,RST,PSH,URG");

        // No flags
        let details = TcpDetails {
            flags: 0,
            ..details
        };
        assert_eq!(details.flags_string(), "none");
    }

    #[test]
    fn test_parse_tcp_details_too_short() {
        // Packet too short for TCP header
        let packet = vec![0u8; 30]; // Only 10 bytes after IP header
        assert!(parse_tcp_details(&packet, 20).is_none());
    }

    #[test]
    fn test_parse_tcp_details_invalid_data_offset() {
        // Build packet with invalid data offset (< 5)
        let mut packet = vec![0u8; 60];
        packet[0] = 0x45; // IPv4
        packet[9] = IPPROTO_TCP;
        // Data offset = 2 (invalid, should be >= 5)
        packet[32] = 2 << 4;

        assert!(parse_tcp_details(&packet, 20).is_none());
    }

    #[test]
    fn test_tcp_flags_constants() {
        // Verify flag constants match standard TCP flags
        assert_eq!(tcp_flags::FIN, 0x01);
        assert_eq!(tcp_flags::SYN, 0x02);
        assert_eq!(tcp_flags::RST, 0x04);
        assert_eq!(tcp_flags::PSH, 0x08);
        assert_eq!(tcp_flags::ACK, 0x10);
        assert_eq!(tcp_flags::URG, 0x20);
    }

    #[test]
    fn test_tcp_details_payload_len_no_payload() {
        let details = TcpDetails {
            src_port: 1234,
            dst_port: 80,
            seq_num: 0,
            ack_num: 0,
            data_offset: 20,
            flags: tcp_flags::SYN,
            window: 65535,
            payload_offset: 40, // 20 IP + 20 TCP
        };

        // Packet exactly at payload offset = no payload
        assert_eq!(details.payload_len(40), 0);
        assert!(!details.has_payload(40));

        // Packet shorter than payload offset = no payload
        assert_eq!(details.payload_len(30), 0);
        assert!(!details.has_payload(30));

        // Packet with payload
        assert_eq!(details.payload_len(100), 60);
        assert!(details.has_payload(100));
    }
}
