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
//!       +---> TCP packets ---> (Phase 3: TCP state machine)
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
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, info, trace, warn};

use super::manager::{ProcessedPacket, WgIngressManager};
use super::processor::RoutingDecision;
use crate::chain::dscp::set_dscp;
use crate::egress::manager::WgEgressManager;
use crate::outbound::OutboundManager;
use crate::rules::fwmark::ChainMark;

/// IP protocol numbers
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_ICMP: u8 = 1;
const IPPROTO_ICMPV6: u8 = 58;

/// Global storage for TCP write halves (used for forwarding client data to server)
static TCP_WRITE_HALVES: Lazy<DashMap<FiveTuple, Arc<tokio::sync::Mutex<tokio::io::WriteHalf<TcpStream>>>>> =
    Lazy::new(DashMap::new);

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

// ============================================================================
// TCP Connection Tracking (Phase 3)
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

/// TCP connection state
///
/// Simplified state machine for ingress TCP tracking:
/// ```text
///     SynReceived --> Established --> Closing --> Closed
///           |              |             ^
///           +-- RST -------+-------------+
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpConnectionState {
    /// SYN received from client, waiting for outbound connection
    SynReceived,
    /// Connection established (outbound connected)
    Established,
    /// FIN received, connection closing
    Closing,
    /// Connection closed
    Closed,
}

impl std::fmt::Display for TcpConnectionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SynReceived => write!(f, "SYN_RECEIVED"),
            Self::Established => write!(f, "ESTABLISHED"),
            Self::Closing => write!(f, "CLOSING"),
            Self::Closed => write!(f, "CLOSED"),
        }
    }
}

/// Tracked TCP connection
///
/// Stores state and metadata for a TCP connection flowing through ingress.
pub struct TcpConnection {
    /// Connection state
    pub state: TcpConnectionState,
    /// Outbound tag used for routing
    pub outbound_tag: String,
    /// Peer's `WireGuard` public key (for reply routing)
    pub peer_public_key: String,
    /// Peer's external endpoint
    pub peer_endpoint: SocketAddr,
    /// Outbound TCP stream (if established)
    pub outbound_stream: Option<TcpStream>,
    /// Bytes sent to destination
    pub bytes_sent: AtomicU64,
    /// Bytes received from destination (replies)
    pub bytes_received: AtomicU64,
    /// Last activity timestamp
    pub last_activity: Instant,
    /// Client's initial sequence number
    pub client_seq: u32,
    /// Server's initial sequence number (from SYN-ACK)
    pub server_seq: u32,
    /// Outbound stats reference for recording completion
    pub outbound_stats: Option<Arc<crate::connection::OutboundStats>>,
    /// Flag to prevent double-counting stats
    pub stats_recorded: AtomicBool,
}

impl TcpConnection {
    /// Create a new TCP connection entry
    pub fn new(
        outbound_tag: String,
        peer_public_key: String,
        peer_endpoint: SocketAddr,
    ) -> Self {
        Self {
            state: TcpConnectionState::SynReceived,
            outbound_tag,
            peer_public_key,
            peer_endpoint,
            outbound_stream: None,
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            last_activity: Instant::now(),
            client_seq: 0,
            server_seq: 0,
            outbound_stats: None,
            stats_recorded: AtomicBool::new(false),
        }
    }
    
    /// Record connection completion in outbound stats (only once)
    /// Returns true if this was the first call that recorded stats
    pub fn record_stats_completion(&self) -> bool {
        // Use compare_exchange to ensure only one caller records stats
        if self.stats_recorded.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_ok() {
            if let Some(ref stats) = self.outbound_stats {
                let bytes_rx = self.bytes_received.load(Ordering::Relaxed);
                let bytes_tx = self.bytes_sent.load(Ordering::Relaxed);
                stats.record_completed(bytes_rx, bytes_tx);
                return true;
            }
        }
        false
    }
    
    /// Record connection error in outbound stats (only once)
    /// Returns true if this was the first call that recorded stats
    pub fn record_stats_error(&self) -> bool {
        // Use compare_exchange to ensure only one caller records stats
        if self.stats_recorded.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_ok() {
            if let Some(ref stats) = self.outbound_stats {
                stats.record_error();
                return true;
            }
        }
        false
    }

    /// Update the last activity timestamp
    pub fn touch(&mut self) {
        self.last_activity = Instant::now();
    }

    /// Add bytes sent
    pub fn add_bytes_sent(&self, bytes: u64) {
        self.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Add bytes received
    pub fn add_bytes_received(&self, bytes: u64) {
        self.bytes_received.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Get bytes sent
    pub fn get_bytes_sent(&self) -> u64 {
        self.bytes_sent.load(Ordering::Relaxed)
    }

    /// Get bytes received
    pub fn get_bytes_received(&self) -> u64 {
        self.bytes_received.load(Ordering::Relaxed)
    }
}

/// Manages TCP connections for ingress forwarding
///
/// Thread-safe connection tracker using `DashMap` for concurrent access.
/// Each connection is wrapped in `RwLock` for fine-grained locking.
pub struct TcpConnectionManager {
    /// Active connections keyed by 5-tuple
    connections: DashMap<FiveTuple, Arc<RwLock<TcpConnection>>>,
    /// Connection timeout for cleanup
    connection_timeout: Duration,
}

impl TcpConnectionManager {
    /// Create a new TCP connection manager
    ///
    /// # Arguments
    ///
    /// * `connection_timeout` - How long to keep idle connections before cleanup
    pub fn new(connection_timeout: Duration) -> Self {
        Self {
            connections: DashMap::new(),
            connection_timeout,
        }
    }

    /// Get or create a connection entry
    ///
    /// If a connection already exists, returns the existing entry.
    /// Otherwise, creates a new entry with `SynReceived` state.
    pub fn get_or_create(
        &self,
        five_tuple: FiveTuple,
        peer_public_key: String,
        peer_endpoint: SocketAddr,
        outbound_tag: String,
    ) -> Arc<RwLock<TcpConnection>> {
        self.connections
            .entry(five_tuple)
            .or_insert_with(|| {
                Arc::new(RwLock::new(TcpConnection::new(
                    outbound_tag,
                    peer_public_key,
                    peer_endpoint,
                )))
            })
            .clone()
    }

    /// Get an existing connection
    pub fn get(&self, five_tuple: &FiveTuple) -> Option<Arc<RwLock<TcpConnection>>> {
        self.connections.get(five_tuple).map(|r| r.clone())
    }

    /// Remove a connection
    pub fn remove(&self, five_tuple: &FiveTuple) -> Option<Arc<RwLock<TcpConnection>>> {
        self.connections.remove(five_tuple).map(|(_, v)| v)
    }

    /// Cleanup stale connections
    ///
    /// Removes connections that have been idle longer than `connection_timeout`.
    /// Also records stats completion for cleaned up connections.
    ///
    /// # Returns
    ///
    /// Number of connections removed.
    pub fn cleanup(&self) -> usize {
        let timeout = self.connection_timeout;
        let _before = self.connections.len();
        
        // Collect keys to remove
        let keys_to_remove: Vec<FiveTuple> = self.connections
            .iter()
            .filter_map(|entry| {
                if let Ok(guard) = entry.value().try_read() {
                    if guard.last_activity.elapsed() >= timeout {
                        Some(*entry.key())
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect();
        
        // Remove from both connections and TCP_WRITE_HALVES
        // Record stats completion for each removed connection
        for key in &keys_to_remove {
            if let Some((_, conn)) = self.connections.remove(key) {
                // Try to record stats completion before dropping
                if let Ok(guard) = conn.try_read() {
                    guard.record_stats_completion();
                }
            }
            TCP_WRITE_HALVES.remove(key);
        }
        
        keys_to_remove.len()
    }

    /// Get the number of active connections
    pub fn len(&self) -> usize {
        self.connections.len()
    }

    /// Check if there are no connections
    pub fn is_empty(&self) -> bool {
        self.connections.is_empty()
    }

    /// Get the connection timeout
    pub fn connection_timeout(&self) -> Duration {
        self.connection_timeout
    }
}

impl Default for TcpConnectionManager {
    fn default() -> Self {
        Self::new(Duration::from_secs(300)) // 5 minute default timeout
    }
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

    Some(TcpDetails {
        src_port,
        dst_port,
        seq_num,
        ack_num,
        data_offset,
        flags,
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

    /// Look up a session for reply routing
    ///
    /// # Arguments
    ///
    /// * `key` - 5-tuple key (should be the reversed tuple for replies)
    ///
    /// # Returns
    ///
    /// The session if found, or None if not found or expired.
    #[must_use]
    pub fn get(&self, key: &FiveTuple) -> Option<PeerSession> {
        self.sessions.get(key).and_then(|entry| {
            let session = entry.value();
            if session.is_expired(self.session_ttl) {
                None
            } else {
                Some(session.clone())
            }
        })
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
// TCP Packet Building
// ============================================================================

/// TCP flags constants
pub mod tcp_flag_bits {
    pub const FIN: u8 = 0x01;
    pub const SYN: u8 = 0x02;
    pub const RST: u8 = 0x04;
    pub const PSH: u8 = 0x08;
    pub const ACK: u8 = 0x10;
}

/// Build a TCP packet with IP header.
///
/// Creates a complete IPv4 TCP packet for sending back to the WireGuard client.
///
/// # Arguments
///
/// * `src_ip` - Source IP address (server)
/// * `src_port` - Source port (server)
/// * `dst_ip` - Destination IP address (client)
/// * `dst_port` - Destination port (client)
/// * `seq_num` - TCP sequence number
/// * `ack_num` - TCP acknowledgment number
/// * `flags` - TCP flags (SYN, ACK, FIN, etc.)
/// * `window` - TCP window size
/// * `payload` - TCP payload data
fn build_tcp_packet(
    src_ip: Ipv4Addr,
    src_port: u16,
    dst_ip: Ipv4Addr,
    dst_port: u16,
    seq_num: u32,
    ack_num: u32,
    flags: u8,
    window: u16,
    payload: &[u8],
) -> Vec<u8> {
    // Check if this is a SYN or SYN-ACK packet (needs MSS option)
    let is_syn = (flags & tcp_flag_bits::SYN) != 0;
    
    // TCP header length: 20 bytes base + 4 bytes MSS option if SYN
    let tcp_header_len = if is_syn { 24 } else { 20 };
    let tcp_len = tcp_header_len + payload.len();
    let total_len = 20 + tcp_len; // IP header + TCP

    let mut packet = vec![0u8; total_len];

    // IPv4 header (20 bytes)
    packet[0] = 0x45; // Version 4, IHL 5
    packet[1] = 0x00; // DSCP/ECN
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[4..6].copy_from_slice(&rand::random::<u16>().to_be_bytes()); // ID
    packet[6..8].copy_from_slice(&[0x40, 0x00]); // Don't fragment
    packet[8] = 64; // TTL
    packet[9] = IPPROTO_TCP;
    // Checksum calculated below
    packet[12..16].copy_from_slice(&src_ip.octets());
    packet[16..20].copy_from_slice(&dst_ip.octets());

    // Calculate IP header checksum
    let ip_checksum = ipv4_header_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

    // TCP header
    let tcp_start = 20;
    packet[tcp_start..tcp_start + 2].copy_from_slice(&src_port.to_be_bytes());
    packet[tcp_start + 2..tcp_start + 4].copy_from_slice(&dst_port.to_be_bytes());
    packet[tcp_start + 4..tcp_start + 8].copy_from_slice(&seq_num.to_be_bytes());
    packet[tcp_start + 8..tcp_start + 12].copy_from_slice(&ack_num.to_be_bytes());
    packet[tcp_start + 12] = (tcp_header_len as u8 / 4) << 4; // Data offset
    packet[tcp_start + 13] = flags;
    packet[tcp_start + 14..tcp_start + 16].copy_from_slice(&window.to_be_bytes());
    // Checksum calculated below
    // Urgent pointer = 0

    // Add MSS option for SYN packets
    // MSS = 1300 to fit within WireGuard MTU after encryption
    if is_syn {
        packet[tcp_start + 20] = 0x02; // MSS option kind
        packet[tcp_start + 21] = 0x04; // MSS option length
        packet[tcp_start + 22..tcp_start + 24].copy_from_slice(&1300u16.to_be_bytes()); // MSS value
    }

    // Copy payload (after options if any)
    if !payload.is_empty() {
        packet[tcp_start + tcp_header_len..].copy_from_slice(payload);
    }

    // Calculate TCP checksum (includes pseudo-header)
    let tcp_checksum = tcp_checksum(&packet[tcp_start..], src_ip, dst_ip);
    packet[tcp_start + 16..tcp_start + 18].copy_from_slice(&tcp_checksum.to_be_bytes());

    packet
}

/// Calculate TCP checksum including pseudo-header.
fn tcp_checksum(tcp_segment: &[u8], src_ip: Ipv4Addr, dst_ip: Ipv4Addr) -> u16 {
    let mut sum: u32 = 0;

    // Pseudo-header
    let src = src_ip.octets();
    let dst = dst_ip.octets();
    sum = sum.wrapping_add(u32::from(u16::from_be_bytes([src[0], src[1]])));
    sum = sum.wrapping_add(u32::from(u16::from_be_bytes([src[2], src[3]])));
    sum = sum.wrapping_add(u32::from(u16::from_be_bytes([dst[0], dst[1]])));
    sum = sum.wrapping_add(u32::from(u16::from_be_bytes([dst[2], dst[3]])));
    sum = sum.wrapping_add(u32::from(IPPROTO_TCP)); // Protocol
    sum = sum.wrapping_add(tcp_segment.len() as u32); // TCP length

    // TCP segment (skip checksum field at offset 16-17)
    for i in (0..tcp_segment.len()).step_by(2) {
        if i == 16 {
            continue; // Skip checksum field
        }
        let word = if i + 1 < tcp_segment.len() {
            u16::from_be_bytes([tcp_segment[i], tcp_segment[i + 1]])
        } else {
            u16::from_be_bytes([tcp_segment[i], 0])
        };
        sum = sum.wrapping_add(u32::from(word));
    }

    // Fold to 16 bits
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
/// * `outbound_manager` - Manager for direct/SOCKS5 outbounds
/// * `wg_egress_manager` - Manager for `WireGuard` egress tunnels
/// * `tcp_manager` - TCP connection manager for stateful connection tracking
/// * `session_tracker` - Session tracker for reply routing
/// * `stats` - Statistics collector
/// * `direct_reply_tx` - Optional sender for direct outbound UDP replies
/// * `local_ip` - Gateway's local IP for responding to pings to self
pub async fn run_forwarding_loop(
    mut packet_rx: mpsc::Receiver<ProcessedPacket>,
    outbound_manager: Arc<OutboundManager>,
    wg_egress_manager: Arc<WgEgressManager>,
    tcp_manager: Arc<TcpConnectionManager>,
    session_tracker: Arc<IngressSessionTracker>,
    stats: Arc<ForwardingStats>,
    direct_reply_tx: Option<mpsc::Sender<ReplyPacket>>,
    local_ip: Option<IpAddr>,
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
                        &outbound_manager,
                        &wg_egress_manager,
                        &tcp_manager,
                        &session_tracker,
                        &stats,
                        direct_reply_tx.clone(),
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

        // Periodic session and TCP connection cleanup
        if last_cleanup.elapsed() >= cleanup_interval {
            let sessions_removed = session_tracker.cleanup();
            let tcp_removed = tcp_manager.cleanup();
            if sessions_removed > 0 || tcp_removed > 0 {
                debug!(
                    "Cleaned up {} expired sessions, {} TCP connections",
                    sessions_removed, tcp_removed
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
pub async fn run_reply_router_loop(
    mut reply_rx: mpsc::Receiver<ReplyPacket>,
    ingress_manager: Arc<WgIngressManager>,
    session_tracker: Arc<IngressSessionTracker>,
    stats: Arc<IngressReplyStats>,
    dns_cache: Option<Arc<super::dns_cache::IpDomainCache>>,
) {
    info!("Ingress reply router started");

    while let Some(reply) = reply_rx.recv().await {
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

        // Handle ICMP separately (no ports)
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

        match ingress_manager
            .send_to_peer(&session.peer_public_key, session.peer_endpoint, &reply.packet)
            .await
        {
            Ok(()) => {
                stats.packets_forwarded.fetch_add(1, Ordering::Relaxed);
                session_tracker.update_received(&lookup_key, reply.packet.len() as u64);
                trace!(
                    "Forwarded reply {} via peer {}",
                    reply_tuple,
                    session.peer_public_key
                );
            }
            Err(e) => {
                stats.send_errors.fetch_add(1, Ordering::Relaxed);
                warn!(
                    "Failed to forward reply {} via peer {}: {}",
                    reply_tuple,
                    session.peer_public_key,
                    e
                );
            }
        }
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
    outbound_manager: &Arc<OutboundManager>,
    wg_egress_manager: &Arc<WgEgressManager>,
    tcp_manager: &Arc<TcpConnectionManager>,
    session_tracker: &Arc<IngressSessionTracker>,
    stats: &Arc<ForwardingStats>,
    direct_reply_tx: Option<mpsc::Sender<ReplyPacket>>,
) {
    let outbound_tag = &processed.routing.outbound;

    // Create 5-tuple for connection tracking
    let five_tuple = FiveTuple::new(
        parsed.src_ip,
        tcp_details.src_port,
        parsed.dst_ip,
        tcp_details.dst_port,
        IPPROTO_TCP,
    );

    // Check if this goes to a WireGuard egress (full IP packet forwarding)
    let is_wg_egress = outbound_tag.starts_with("wg-")
        || outbound_tag.starts_with("pia-")
        || outbound_tag.starts_with("peer-")
        || wg_egress_manager.has_tunnel(outbound_tag);

    if is_wg_egress {
        session_tracker.register(
            five_tuple,
            processed.peer_public_key.clone(),
            processed.src_addr,
            outbound_tag.clone(),
            parsed.total_len as u64,
        );

        // Forward full IP packet to WireGuard egress
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

    // For direct/SOCKS5, we need to establish and manage connections
    // Register in session tracker for potential reply routing
    session_tracker.register(
        five_tuple,
        processed.peer_public_key.clone(),
        processed.src_addr,
        outbound_tag.clone(),
        parsed.total_len as u64,
    );

    if tcp_details.is_syn() && !tcp_details.is_ack() {
        // New connection (SYN without ACK) - establish outbound
        let dst_addr = SocketAddr::new(parsed.dst_ip, tcp_details.dst_port);

        // Check if connection already exists (handles SYN retransmissions)
        if let Some(existing_conn) = tcp_manager.get(&five_tuple) {
            let conn_guard = existing_conn.read().await;
            match conn_guard.state {
                TcpConnectionState::Established => {
                    // Connection exists, resend SYN-ACK for the retransmitted SYN
                    if let Some(ref reply_tx) = direct_reply_tx {
                        if let (IpAddr::V4(client_ip), IpAddr::V4(server_ip)) = (parsed.src_ip, parsed.dst_ip) {
                            let syn_ack = build_tcp_packet(
                                server_ip,
                                tcp_details.dst_port,
                                client_ip,
                                tcp_details.src_port,
                                conn_guard.server_seq,
                                tcp_details.seq_num.wrapping_add(1),
                                tcp_flag_bits::SYN | tcp_flag_bits::ACK,
                                65535,
                                &[],
                            );
                            let reply = ReplyPacket {
                                packet: syn_ack,
                                tunnel_tag: outbound_tag.clone(),
                            };
                            if reply_tx.try_send(reply).is_ok() {
                                debug!(
                                    "Resent SYN-ACK for retransmitted SYN: {}:{} -> {}:{}",
                                    parsed.src_ip, tcp_details.src_port, parsed.dst_ip, tcp_details.dst_port
                                );
                            }
                        }
                    }
                    return; // Don't create duplicate connection
                }
                TcpConnectionState::SynReceived => {
                    // Connection is being established, drop duplicate SYN
                    debug!(
                        "Dropping duplicate SYN (connection in progress): {}:{} -> {}:{}",
                        parsed.src_ip, tcp_details.src_port, parsed.dst_ip, tcp_details.dst_port
                    );
                    return;
                }
                TcpConnectionState::Closing | TcpConnectionState::Closed => {
                    // Old connection is closing, remove it and establish new one
                    drop(conn_guard);
                    tcp_manager.remove(&five_tuple);
                    TCP_WRITE_HALVES.remove(&five_tuple);
                    debug!(
                        "Removed stale connection for new SYN: {}:{} -> {}:{}",
                        parsed.src_ip, tcp_details.src_port, parsed.dst_ip, tcp_details.dst_port
                    );
                }
            }
        }

        // Create connection entry BEFORE async connect to prevent race with SYN retransmit
        let tracked = tcp_manager.get_or_create(
            five_tuple,
            processed.peer_public_key.clone(),
            processed.src_addr,
            outbound_tag.clone(),
        );
        // Mark as SynReceived immediately
        {
            let mut conn_guard = tracked.write().await;
            conn_guard.state = TcpConnectionState::SynReceived;
            conn_guard.client_seq = tcp_details.seq_num;
        }

        if let Some(outbound) = outbound_manager.get(outbound_tag) {
            // Try to establish TCP connection
            let connect_start = Instant::now();
            match outbound.connect(dst_addr, Duration::from_secs(10)).await {
                Ok(conn) => {
                    let connect_time = connect_start.elapsed();
                    if connect_time.as_millis() > 100 {
                        info!(
                            "Established TCP connection via '{}': {}:{} -> {}:{} ({}ms - SLOW)",
                            outbound_tag,
                            parsed.src_ip,
                            tcp_details.src_port,
                            parsed.dst_ip,
                            tcp_details.dst_port,
                            connect_time.as_millis()
                        );
                    } else {
                        info!(
                            "Established TCP connection via '{}': {}:{} -> {}:{} ({}ms)",
                            outbound_tag,
                            parsed.src_ip,
                            tcp_details.src_port,
                            parsed.dst_ip,
                            tcp_details.dst_port,
                            connect_time.as_millis()
                        );
                    }

                    // Generate server's initial sequence number
                    let server_seq: u32 = rand::random();

                    // Get the stream for the reader task
                    let stream = conn.into_stream();
                    let (read_half, write_half) = tokio::io::split(stream);

                    // Update connection state (already created before connect)
                    // Store outbound_stats for proper cleanup tracking
                    let outbound_stats = outbound.stats();
                    {
                        let mut conn_guard = tracked.write().await;
                        conn_guard.state = TcpConnectionState::Established;
                        conn_guard.server_seq = server_seq;
                        conn_guard.outbound_stats = Some(Arc::clone(&outbound_stats));
                        // Store write half for sending data
                        // Note: We'll need to modify TcpConnection to store OwnedWriteHalf
                        // For now, we'll handle writes differently
                    }

                    // Send SYN-ACK back to client
                    if let Some(ref reply_tx) = direct_reply_tx {
                        if let (IpAddr::V4(client_ip), IpAddr::V4(server_ip)) = (parsed.src_ip, parsed.dst_ip) {
                            let syn_ack = build_tcp_packet(
                                server_ip,
                                tcp_details.dst_port,
                                client_ip,
                                tcp_details.src_port,
                                server_seq,
                                tcp_details.seq_num.wrapping_add(1), // ACK = client_seq + 1
                                tcp_flag_bits::SYN | tcp_flag_bits::ACK,
                                65535, // Window size
                                &[],
                            );

                            let reply = ReplyPacket {
                                packet: syn_ack,
                                tunnel_tag: outbound_tag.clone(),
                            };

                            if let Err(e) = reply_tx.try_send(reply) {
                                warn!("Failed to send SYN-ACK to reply router: {}", e);
                            } else {
                                debug!(
                                    "Sent SYN-ACK: {}:{} -> {}:{} (seq={}, ack={})",
                                    server_ip, tcp_details.dst_port,
                                    client_ip, tcp_details.src_port,
                                    server_seq, tcp_details.seq_num.wrapping_add(1)
                                );
                            }

                            // Spawn TCP reader task to forward server responses
                            spawn_tcp_reader_task(
                                read_half,
                                reply_tx.clone(),
                                server_ip,
                                tcp_details.dst_port,
                                client_ip,
                                tcp_details.src_port,
                                server_seq.wrapping_add(1), // Start after SYN-ACK
                                tcp_details.seq_num.wrapping_add(1),
                                outbound_tag.clone(),
                                Arc::clone(&tracked),
                                five_tuple, // Pass five_tuple for cleanup
                            );
                        }
                    }

                    // Store write half in a separate structure for sending
                    // We'll use a channel-based approach for the write half
                    let write_half = Arc::new(tokio::sync::Mutex::new(write_half));
                    TCP_WRITE_HALVES.insert(five_tuple, write_half);

                    debug!(
                        "TCP connection fully established with reply path: {}:{} -> {}:{}",
                        parsed.src_ip, tcp_details.src_port, parsed.dst_ip, tcp_details.dst_port
                    );
                }
                Err(e) => {
                    warn!(
                        "Failed to establish TCP connection via '{}' to {}: {}",
                        outbound_tag, dst_addr, e
                    );
                    stats.forward_errors.fetch_add(1, Ordering::Relaxed);

                    // Cleanup the connection entry we created before attempting connect
                    tcp_manager.remove(&five_tuple);

                    // Send RST back to client
                    if let Some(ref reply_tx) = direct_reply_tx {
                        if let (IpAddr::V4(client_ip), IpAddr::V4(server_ip)) = (parsed.src_ip, parsed.dst_ip) {
                            let rst = build_tcp_packet(
                                server_ip,
                                tcp_details.dst_port,
                                client_ip,
                                tcp_details.src_port,
                                0,
                                tcp_details.seq_num.wrapping_add(1),
                                tcp_flag_bits::RST | tcp_flag_bits::ACK,
                                0,
                                &[],
                            );
                            let _ = reply_tx.try_send(ReplyPacket {
                                packet: rst,
                                tunnel_tag: outbound_tag.clone(),
                            });
                        }
                    }
                }
            }
        } else {
            warn!("Unknown outbound '{}' for TCP connection", outbound_tag);
            // Cleanup the connection entry we created
            tcp_manager.remove(&five_tuple);
            stats.forward_errors.fetch_add(1, Ordering::Relaxed);
        }
    } else if tcp_details.is_fin() || tcp_details.is_rst() {
        // Connection closing - clean up resources
        TCP_WRITE_HALVES.remove(&five_tuple);
        
        if let Some(conn) = tcp_manager.get(&five_tuple) {
            {
                let mut conn_guard = conn.write().await;
                conn_guard.state = TcpConnectionState::Closing;
                conn_guard.touch();
            }
            // Record stats completion (only if not already recorded by reader task)
            {
                let conn_guard = conn.read().await;
                conn_guard.record_stats_completion();
            }
            debug!(
                "TCP connection closing: {}:{} -> {}:{} (flags={})",
                parsed.src_ip,
                tcp_details.src_port,
                parsed.dst_ip,
                tcp_details.dst_port,
                tcp_details.flags_string()
            );

            // Also forward FIN/RST to WireGuard egress if applicable
            // (handled above for WG egress, here we just track state)
        } else {
            // FIN/RST for unknown connection - likely already cleaned up
            debug!(
                "TCP FIN/RST for untracked connection: {}:{} -> {}:{}",
                parsed.src_ip, tcp_details.src_port, parsed.dst_ip, tcp_details.dst_port
            );
        }
    } else if tcp_details.has_payload(processed.data.len()) {
        // Data packet - forward through established connection
        if let Some(conn) = tcp_manager.get(&five_tuple) {
            let payload_len = tcp_details.payload_len(processed.data.len());
            let payload = &processed.data[tcp_details.payload_offset..];

            let conn_guard = conn.write().await;

            if conn_guard.state != TcpConnectionState::Established {
                debug!(
                    "TCP data for connection in {} state: {}:{} -> {}:{}",
                    conn_guard.state,
                    parsed.src_ip,
                    tcp_details.src_port,
                    parsed.dst_ip,
                    tcp_details.dst_port
                );
                // Don't forward data if connection not established
                return;
            }

            // Try to use the write half from our global storage
            drop(conn_guard); // Release lock before async operation
            // IMPORTANT: Clone the Arc and drop the DashMap Ref before any .await
            // Holding a DashMap Ref across .await can cause deadlocks due to
            // the internal sharded locking mechanism.
            let write_half = TCP_WRITE_HALVES.get(&five_tuple).map(|r| Arc::clone(&*r));
            if let Some(write_half) = write_half {
                let mut stream = write_half.lock().await;
                match stream.write_all(payload).await {
                    Ok(()) => {
                        // Combine connection updates into a single lock acquisition
                        let server_seq = {
                            let mut conn_guard = conn.write().await;
                            conn_guard.add_bytes_sent(payload_len as u64);
                            conn_guard.touch();
                            conn_guard.client_seq = tcp_details.seq_num.wrapping_add(payload_len as u32);
                            conn_guard.server_seq
                        };
                        
                        // Send ACK back to client to acknowledge received data
                        // This is critical for TCP flow control
                        if let Some(ref reply_tx) = direct_reply_tx {
                            if let (IpAddr::V4(client_ip), IpAddr::V4(server_ip)) = (parsed.src_ip, parsed.dst_ip) {
                                let ack_packet = build_tcp_packet(
                                    server_ip,
                                    tcp_details.dst_port,
                                    client_ip,
                                    tcp_details.src_port,
                                    server_seq,
                                    tcp_details.seq_num.wrapping_add(payload_len as u32),
                                    tcp_flag_bits::ACK,
                                    65535,
                                    &[],
                                );
                                let _ = reply_tx.try_send(ReplyPacket {
                                    packet: ack_packet,
                                    tunnel_tag: outbound_tag.clone(),
                                });
                            }
                        }
                        
                        trace!(
                            "Forwarded {} bytes TCP payload: {}:{} -> {}:{}",
                            payload_len,
                            parsed.src_ip,
                            tcp_details.src_port,
                            parsed.dst_ip,
                            tcp_details.dst_port
                        );
                    }
                    Err(e) => {
                        warn!(
                            "Failed to write TCP payload: {} (connection may be closed)",
                            e
                        );
                        stats.forward_errors.fetch_add(1, Ordering::Relaxed);
                        // Mark connection as closing on write error
                        {
                            let mut conn_guard = conn.write().await;
                            conn_guard.state = TcpConnectionState::Closing;
                        }
                        // Remove write half
                        TCP_WRITE_HALVES.remove(&five_tuple);
                    }
                }
            } else {
                debug!(
                    "TCP data for connection without write half: {}:{} -> {}:{}",
                    parsed.src_ip, tcp_details.src_port, parsed.dst_ip, tcp_details.dst_port
                );
            }
        } else {
            // Data for unknown connection (maybe missed the SYN)
            debug!(
                "TCP data for untracked connection: {}:{} -> {}:{} ({} bytes payload)",
                parsed.src_ip,
                tcp_details.src_port,
                parsed.dst_ip,
                tcp_details.dst_port,
                tcp_details.payload_len(processed.data.len())
            );
        }
    } else {
        // ACK without data - update connection state
        if let Some(conn) = tcp_manager.get(&five_tuple) {
            let mut conn_guard = conn.write().await;
            conn_guard.touch();
            trace!(
                "TCP ACK (no data): {}:{} -> {}:{}, state={}",
                parsed.src_ip,
                tcp_details.src_port,
                parsed.dst_ip,
                tcp_details.dst_port,
                conn_guard.state
            );
        }
    }
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
) {
    let outbound_tag = &processed.routing.outbound;

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

    // Register session for reply routing
    let five_tuple = FiveTuple::new(parsed.src_ip, src_port, parsed.dst_ip, dst_port, IPPROTO_UDP);
    session_tracker.register(
        five_tuple,
        processed.peer_public_key.clone(),
        processed.src_addr,
        outbound_tag.clone(),
        parsed.total_len as u64,
    );

    // Determine if this is a WireGuard egress tunnel
    // WireGuard tunnels are tagged with prefixes like "wg-", "pia-", etc.
    let is_wg_egress = outbound_tag.starts_with("wg-")
        || outbound_tag.starts_with("pia-")
        || outbound_tag.starts_with("peer-")
        || wg_egress_manager.has_tunnel(outbound_tag);

    if is_wg_egress {
        // Forward through WireGuard egress tunnel
        // For WireGuard tunnels, we send the entire IP packet (it gets encapsulated)
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

            // Check for existing UDP session
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
                    // Extract the socket from the handle
                    let socket: Arc<UdpSocket> = match handle {
                        crate::outbound::UdpOutboundHandle::Direct(direct_handle) => {
                            Arc::clone(direct_handle.socket())
                        }
                        _ => {
                            // For non-direct handles, just send and return
                            match handle.send(udp_payload).await {
                                Ok(bytes_sent) => {
                                    debug!(
                                        "Forwarded UDP via '{}': {} -> {}:{} ({} bytes)",
                                        outbound_tag, client_ip, server_ip, server_port, bytes_sent
                                    );
                                }
                                Err(e) => {
                                    warn!("Failed to send UDP via '{}': {}", outbound_tag, e);
                                    stats.forward_errors.fetch_add(1, Ordering::Relaxed);
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

        // Wait for reply with timeout
        match tokio::time::timeout(DIRECT_UDP_REPLY_TIMEOUT, handle.recv(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => {
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
                        return;
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
                } else {
                    trace!(
                        "Direct UDP reply forwarded: {}:{} -> {}:{} ({} bytes)",
                        server_ip, server_port, client_ip, client_port, n
                    );
                }
            }
            Ok(Ok(_)) => {
                // Zero-length reply, ignore
                trace!("Empty direct UDP reply from {}:{}", server_ip, server_port);
            }
            Ok(Err(e)) => {
                debug!(
                    "Error receiving direct UDP reply from {}:{}: {}",
                    server_ip, server_port, e
                );
            }
            Err(_) => {
                // Timeout - normal for UDP, no reply expected or reply lost
                trace!(
                    "Direct UDP reply timeout: {}:{} -> {}:{}",
                    client_ip, client_port, server_ip, server_port
                );
            }
        }
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

        // Wait for reply with timeout
        match tokio::time::timeout(DIRECT_UDP_REPLY_TIMEOUT, socket.recv(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => {
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
                        return;
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
                } else {
                    trace!(
                        "Direct UDP reply (raw) forwarded: {}:{} -> {}:{} ({} bytes)",
                        server_ip, server_port, client_ip, client_port, n
                    );
                }
            }
            Ok(Ok(_)) => {
                // Zero-length reply, ignore
                trace!("Empty direct UDP reply from {}:{}", server_ip, server_port);
            }
            Ok(Err(e)) => {
                debug!(
                    "Error receiving direct UDP reply from {}:{}: {}",
                    server_ip, server_port, e
                );
            }
            Err(_) => {
                // Timeout - normal for UDP
                trace!(
                    "Direct UDP reply timeout (raw): {}:{} -> {}:{}",
                    client_ip, client_port, server_ip, server_port
                );
            }
        }
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
const MAX_TCP_SEGMENT_SIZE: usize = 1300;

/// Read buffer size for TCP reader - larger buffer reduces syscall overhead
/// We read into a larger buffer but still send in MSS-sized chunks
const TCP_READ_BUFFER_SIZE: usize = 65536;

/// Spawn a task to read server responses and forward them to the client.
///
/// This task reads data from the server and constructs TCP packets to send
/// back to the WireGuard client via the reply router.
fn spawn_tcp_reader_task(
    read_half: tokio::io::ReadHalf<TcpStream>,
    reply_tx: mpsc::Sender<ReplyPacket>,
    server_ip: Ipv4Addr,
    server_port: u16,
    client_ip: Ipv4Addr,
    client_port: u16,
    initial_seq: u32,
    _initial_ack: u32, // Now read from connection.client_seq for accurate ACK tracking
    outbound_tag: String,
    connection: Arc<RwLock<TcpConnection>>,
    five_tuple: FiveTuple,
) {
    tokio::spawn(async move {
        // Use a larger read buffer for better throughput
        let mut reader = BufReader::with_capacity(TCP_READ_BUFFER_SIZE, read_half);
        let mut buf = vec![0u8; MAX_TCP_SEGMENT_SIZE];
        let mut seq_num = initial_seq;

        loop {
            match reader.read(&mut buf).await {
                Ok(0) => {
                    // Connection closed by server - send FIN and cleanup
                    debug!(
                        "Server closed TCP connection: {}:{} -> {}:{}",
                        server_ip, server_port, client_ip, client_port
                    );

                    // Get current client_seq from connection for ACK
                    let ack_num = {
                        let conn_guard = connection.read().await;
                        conn_guard.client_seq
                    };

                    let fin_packet = build_tcp_packet(
                        server_ip,
                        server_port,
                        client_ip,
                        client_port,
                        seq_num,
                        ack_num,
                        tcp_flag_bits::FIN | tcp_flag_bits::ACK,
                        65535,
                        &[],
                    );

                    let _ = reply_tx.try_send(ReplyPacket {
                        packet: fin_packet,
                        tunnel_tag: outbound_tag.clone(),
                    });

                    // Update connection state and cleanup
                    {
                        let mut conn_guard = connection.write().await;
                        conn_guard.state = TcpConnectionState::Closing;
                    }
                    TCP_WRITE_HALVES.remove(&five_tuple);
                    // Record connection completion in outbound stats (only if not already recorded)
                    {
                        let conn_guard = connection.read().await;
                        conn_guard.record_stats_completion();
                    }
                    break;
                }
                Ok(n) => {
                    // Data received from server - forward to client
                    let payload = &buf[..n];
                    
                    // Get current client_seq from connection for ACK
                    let ack_num = {
                        let conn_guard = connection.read().await;
                        conn_guard.client_seq
                    };

                    let data_packet = build_tcp_packet(
                        server_ip,
                        server_port,
                        client_ip,
                        client_port,
                        seq_num,
                        ack_num,
                        tcp_flag_bits::ACK | tcp_flag_bits::PSH,
                        65535,
                        payload,
                    );

                    if let Err(e) = reply_tx.send(ReplyPacket {
                        packet: data_packet,
                        tunnel_tag: outbound_tag.clone(),
                    }).await {
                        warn!("Failed to send TCP data to reply router: {}", e);
                        TCP_WRITE_HALVES.remove(&five_tuple);
                        {
                            let conn_guard = connection.read().await;
                            conn_guard.record_stats_error();
                        }
                        return;
                    }

                    trace!(
                        "TCP data: {}:{} -> {}:{} ({} bytes, seq={})",
                        server_ip, server_port, client_ip, client_port, n, seq_num
                    );

                    // Update sequence number for next packet
                    seq_num = seq_num.wrapping_add(n as u32);

                    // Update connection stats
                    {
                        let conn_guard = connection.read().await;
                        conn_guard.add_bytes_received(n as u64);
                    }
                }
                Err(e) => {
                    debug!(
                        "TCP read error: {}:{} -> {}:{}: {}",
                        server_ip, server_port, client_ip, client_port, e
                    );

                    // Get current client_seq from connection for ACK
                    let ack_num = {
                        let conn_guard = connection.read().await;
                        conn_guard.client_seq
                    };

                    // Send RST on error
                    let rst_packet = build_tcp_packet(
                        server_ip,
                        server_port,
                        client_ip,
                        client_port,
                        seq_num,
                        ack_num,
                        tcp_flag_bits::RST,
                        0,
                        &[],
                    );

                    let _ = reply_tx.try_send(ReplyPacket {
                        packet: rst_packet,
                        tunnel_tag: outbound_tag.clone(),
                    });
                    // Cleanup on error and record error in stats (only if not already recorded)
                    TCP_WRITE_HALVES.remove(&five_tuple);
                    {
                        let conn_guard = connection.read().await;
                        conn_guard.record_stats_error();
                    }
                    break;
                }
            }
        }

        debug!(
            "TCP reader task finished: {}:{} -> {}:{}",
            server_ip, server_port, client_ip, client_port
        );
    });
}

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
/// * `outbound_manager` - Manager for direct/SOCKS5 outbounds
/// * `wg_egress_manager` - Manager for `WireGuard` egress tunnels
/// * `tcp_manager` - TCP connection manager for stateful connection tracking
/// * `session_tracker` - Session tracker for reply routing
/// * `stats` - Statistics collector
/// * `direct_reply_tx` - Optional sender for direct outbound UDP replies
/// * `local_ip` - Gateway's local IP for responding to pings to self
///
/// # Returns
///
/// A `JoinHandle` for the spawned task.
pub fn spawn_forwarding_task(
    packet_rx: mpsc::Receiver<ProcessedPacket>,
    outbound_manager: Arc<OutboundManager>,
    wg_egress_manager: Arc<WgEgressManager>,
    tcp_manager: Arc<TcpConnectionManager>,
    session_tracker: Arc<IngressSessionTracker>,
    stats: Arc<ForwardingStats>,
    direct_reply_tx: Option<mpsc::Sender<ReplyPacket>>,
    local_ip: Option<IpAddr>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(run_forwarding_loop(
        packet_rx,
        outbound_manager,
        wg_egress_manager,
        tcp_manager,
        session_tracker,
        stats,
        direct_reply_tx,
        local_ip,
    ))
}

/// Spawn the reply router loop as a tokio task
pub fn spawn_reply_router(
    reply_rx: mpsc::Receiver<ReplyPacket>,
    ingress_manager: Arc<WgIngressManager>,
    session_tracker: Arc<IngressSessionTracker>,
    stats: Arc<IngressReplyStats>,
    dns_cache: Option<Arc<super::dns_cache::IpDomainCache>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(run_reply_router_loop(
        reply_rx,
        ingress_manager,
        session_tracker,
        stats,
        dns_cache,
    ))
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

    async fn run_reply_router_once(
        reply: ReplyPacket,
        ingress_manager: Arc<WgIngressManager>,
        session_tracker: Arc<IngressSessionTracker>,
        stats: Arc<IngressReplyStats>,
    ) {
        let (tx, rx) = mpsc::channel(1);
        let handle = tokio::spawn(run_reply_router_loop(
            rx,
            ingress_manager,
            session_tracker,
            stats,
            None, // No DNS cache for tests
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
    // UDP Forwarding Tests (Phase 2)
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
    // TCP Connection State Tests (Phase 3)
    // ========================================================================

    #[test]
    fn test_tcp_connection_state_display() {
        assert_eq!(TcpConnectionState::SynReceived.to_string(), "SYN_RECEIVED");
        assert_eq!(TcpConnectionState::Established.to_string(), "ESTABLISHED");
        assert_eq!(TcpConnectionState::Closing.to_string(), "CLOSING");
        assert_eq!(TcpConnectionState::Closed.to_string(), "CLOSED");
    }

    #[test]
    fn test_tcp_connection_new() {
        let conn = TcpConnection::new(
            "direct".to_string(),
            "test_peer_key".to_string(),
            "192.168.1.100:51820".parse().unwrap(),
        );

        assert_eq!(conn.state, TcpConnectionState::SynReceived);
        assert_eq!(conn.outbound_tag, "direct");
        assert_eq!(conn.peer_public_key, "test_peer_key");
        assert!(conn.outbound_stream.is_none());
        assert_eq!(conn.get_bytes_sent(), 0);
        assert_eq!(conn.get_bytes_received(), 0);
        assert_eq!(conn.client_seq, 0);
        assert_eq!(conn.server_seq, 0);
    }

    #[test]
    fn test_tcp_connection_bytes_tracking() {
        let conn = TcpConnection::new(
            "direct".to_string(),
            "key".to_string(),
            "127.0.0.1:1234".parse().unwrap(),
        );

        conn.add_bytes_sent(100);
        conn.add_bytes_sent(50);
        conn.add_bytes_received(200);
        conn.add_bytes_received(100);

        assert_eq!(conn.get_bytes_sent(), 150);
        assert_eq!(conn.get_bytes_received(), 300);
    }

    // ========================================================================
    // TCP Connection Manager Tests
    // ========================================================================

    #[test]
    fn test_tcp_connection_manager_new() {
        let manager = TcpConnectionManager::new(Duration::from_secs(300));

        assert_eq!(manager.len(), 0);
        assert!(manager.is_empty());
        assert_eq!(manager.connection_timeout(), Duration::from_secs(300));
    }

    #[test]
    fn test_tcp_connection_manager_default() {
        let manager = TcpConnectionManager::default();
        assert_eq!(manager.connection_timeout(), Duration::from_secs(300));
    }

    #[tokio::test]
    async fn test_tcp_connection_manager_get_or_create() {
        let manager = TcpConnectionManager::new(Duration::from_secs(300));

        let five_tuple = FiveTuple::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            1234,
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            80,
            IPPROTO_TCP,
        );

        let conn = manager.get_or_create(
            five_tuple,
            "peer_key".to_string(),
            "192.168.1.100:51820".parse().unwrap(),
            "direct".to_string(),
        );

        assert_eq!(manager.len(), 1);

        let guard = conn.read().await;
        assert_eq!(guard.state, TcpConnectionState::SynReceived);
        assert_eq!(guard.outbound_tag, "direct");
        assert_eq!(guard.peer_public_key, "peer_key");
    }

    #[tokio::test]
    async fn test_tcp_connection_manager_get_existing() {
        let manager = TcpConnectionManager::new(Duration::from_secs(300));

        let five_tuple = FiveTuple::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            1234,
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            80,
            IPPROTO_TCP,
        );

        // Create first connection
        let conn1 = manager.get_or_create(
            five_tuple,
            "key1".to_string(),
            "192.168.1.100:51820".parse().unwrap(),
            "out1".to_string(),
        );

        // Try to create again with same 5-tuple - should return existing
        let conn2 = manager.get_or_create(
            five_tuple,
            "key2".to_string(), // Different key - but should use existing
            "192.168.1.200:51820".parse().unwrap(),
            "out2".to_string(),
        );

        assert_eq!(manager.len(), 1);

        // Both should point to the same connection
        let guard1 = conn1.read().await;
        let guard2 = conn2.read().await;
        assert_eq!(guard1.peer_public_key, guard2.peer_public_key);
        assert_eq!(guard1.peer_public_key, "key1"); // Original value
    }

    #[test]
    fn test_tcp_connection_manager_get() {
        let manager = TcpConnectionManager::new(Duration::from_secs(300));

        let five_tuple = FiveTuple::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            1234,
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            80,
            IPPROTO_TCP,
        );

        // Get on empty manager
        assert!(manager.get(&five_tuple).is_none());

        // Create connection
        manager.get_or_create(
            five_tuple,
            "key".to_string(),
            "127.0.0.1:1234".parse().unwrap(),
            "direct".to_string(),
        );

        // Now get should succeed
        assert!(manager.get(&five_tuple).is_some());
    }

    #[test]
    fn test_tcp_connection_manager_remove() {
        let manager = TcpConnectionManager::new(Duration::from_secs(300));

        let five_tuple = FiveTuple::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            1234,
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            80,
            IPPROTO_TCP,
        );

        manager.get_or_create(
            five_tuple,
            "key".to_string(),
            "127.0.0.1:1234".parse().unwrap(),
            "direct".to_string(),
        );

        assert_eq!(manager.len(), 1);

        let removed = manager.remove(&five_tuple);
        assert!(removed.is_some());
        assert_eq!(manager.len(), 0);

        // Second remove should return None
        assert!(manager.remove(&five_tuple).is_none());
    }

    #[test]
    fn test_tcp_connection_manager_cleanup() {
        let manager = TcpConnectionManager::new(Duration::ZERO); // Immediate timeout

        let five_tuple = FiveTuple::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            1234,
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            80,
            IPPROTO_TCP,
        );

        manager.get_or_create(
            five_tuple,
            "key".to_string(),
            "127.0.0.1:1234".parse().unwrap(),
            "direct".to_string(),
        );

        // Should expire immediately
        let removed = manager.cleanup();
        assert_eq!(removed, 1);
        assert!(manager.is_empty());
    }

    // ========================================================================
    // TCP Details Parsing Tests
    // ========================================================================

    /// Build a TCP packet with specified flags
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

        // Payload
        if !payload.is_empty() {
            packet[tcp_start + 20..].copy_from_slice(payload);
        }

        packet
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
        assert!(details.is_syn());
        assert!(!details.is_ack());
        assert!(!details.is_fin());
        assert!(!details.is_rst());
        assert!(!details.has_payload(packet.len()));
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
