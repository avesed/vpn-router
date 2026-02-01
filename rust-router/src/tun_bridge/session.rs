//! Session tracking for TUN + TPROXY bridge
//!
//! This module tracks TCP/UDP sessions and maps them back to WireGuard peers
//! for reply packet routing.
//!
//! # Design
//!
//! Unlike the ipstack bridge which needs bidirectional lookup (forward and reverse
//! by port), the TUN + TPROXY bridge only needs:
//! - Forward lookup: 5-tuple (from reply packets) → peer info
//!
//! When the kernel sends reply packets out through the TUN device, we parse
//! the IP header to extract the 5-tuple, reverse it (dst becomes src), and
//! look up the session to find which WireGuard peer to send the packet to.
//!
//! # Thread Safety
//!
//! Uses `DashMap` for lock-free concurrent access, allowing:
//! - `inject_packet()` to register sessions
//! - `run_tun_read_loop()` to look up sessions for reply routing
//! - `run_accept_loop()` to update session activity
//! - Cleanup task to remove idle sessions

use ahash::RandomState;
use dashmap::DashMap;
use parking_lot::Mutex;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, trace, warn};

/// Type alias for DashMap with ahash for faster lookups
type AHashMap<K, V> = DashMap<K, V, RandomState>;

/// 5-tuple identifying a TCP/UDP session
///
/// A 5-tuple uniquely identifies a network session based on:
/// - Source address (IP + port) - the WireGuard client
/// - Destination address (IP + port) - the target server
/// - Protocol (TCP = 6, UDP = 17)
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct FiveTuple {
    /// Source socket address (WireGuard client)
    pub src_addr: SocketAddr,
    /// Destination socket address (target server)
    pub dst_addr: SocketAddr,
    /// IP protocol number (6 = TCP, 17 = UDP)
    pub protocol: u8,
}

impl FiveTuple {
    /// Create a new TCP 5-tuple
    ///
    /// # Arguments
    ///
    /// * `src` - Source socket address (client)
    /// * `dst` - Destination socket address (server)
    #[must_use]
    pub fn tcp(src: SocketAddr, dst: SocketAddr) -> Self {
        Self {
            src_addr: src,
            dst_addr: dst,
            protocol: 6,
        }
    }

    /// Create a new UDP 5-tuple
    ///
    /// # Arguments
    ///
    /// * `src` - Source socket address (client)
    /// * `dst` - Destination socket address (server)
    #[must_use]
    pub fn udp(src: SocketAddr, dst: SocketAddr) -> Self {
        Self {
            src_addr: src,
            dst_addr: dst,
            protocol: 17,
        }
    }

    /// Create the reverse tuple (for reply packets)
    ///
    /// Returns a new 5-tuple with source and destination swapped.
    /// This is used to match reply packets from the kernel back
    /// to the original client session.
    #[must_use]
    pub fn reverse(&self) -> Self {
        Self {
            src_addr: self.dst_addr,
            dst_addr: self.src_addr,
            protocol: self.protocol,
        }
    }

    /// Check if this is a TCP session
    #[inline]
    #[must_use]
    pub fn is_tcp(&self) -> bool {
        self.protocol == 6
    }

    /// Check if this is a UDP session
    #[inline]
    #[must_use]
    pub fn is_udp(&self) -> bool {
        self.protocol == 17
    }

    /// Parse a 5-tuple from an IP packet
    ///
    /// Returns `None` if the packet is malformed or not TCP/UDP.
    #[must_use]
    pub fn from_packet(packet: &[u8]) -> Option<Self> {
        if packet.is_empty() {
            return None;
        }

        let version = packet[0] >> 4;

        match version {
            4 => Self::parse_ipv4(packet),
            6 => Self::parse_ipv6(packet),
            _ => None,
        }
    }

    /// Parse an IPv4 packet to extract the 5-tuple
    fn parse_ipv4(packet: &[u8]) -> Option<Self> {
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
            6 => Some(Self::tcp(src_addr, dst_addr)),
            17 => Some(Self::udp(src_addr, dst_addr)),
            _ => None,
        }
    }

    /// Parse an IPv6 packet to extract the 5-tuple
    ///
    /// Handles IPv6 extension headers by skipping through them to find the
    /// actual transport protocol (TCP/UDP).
    fn parse_ipv6(packet: &[u8]) -> Option<Self> {
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
            6 => Some(Self::tcp(src_addr, dst_addr)),
            17 => Some(Self::udp(src_addr, dst_addr)),
            _ => None,
        }
    }
}

impl std::fmt::Display for FiveTuple {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let proto = match self.protocol {
            6 => "TCP",
            17 => "UDP",
            n => return write!(f, "{}:{} -> {} (proto={})", self.src_addr, self.dst_addr, n, n),
        };
        write!(f, "{}:{} -> {}", proto, self.src_addr, self.dst_addr)
    }
}

/// Information about a session
///
/// Contains all metadata needed to track a session and route
/// reply packets back to the correct WireGuard peer.
#[derive(Debug)]
pub struct SessionInfo {
    /// Unique session ID (monotonically increasing)
    pub session_id: u64,
    /// WireGuard peer public key (for routing replies)
    pub peer_key: [u8; 32],
    /// Peer's WireGuard endpoint (IP:port) for reply routing
    /// Uses Mutex to allow updates on NAT rebinding/roaming
    peer_endpoint: Mutex<SocketAddr>,
    /// Original 5-tuple from client
    pub five_tuple: FiveTuple,
    /// Outbound tag for routing (e.g., "direct", "vless-xxx", "ss-xxx")
    pub outbound_tag: String,
    /// Session creation time
    pub created_at: Instant,
    /// Last activity time (updated on packet send/receive)
    last_active: Mutex<Instant>,
    /// Bytes sent to outbound
    pub bytes_sent: AtomicU64,
    /// Bytes received from outbound
    pub bytes_received: AtomicU64,
}

impl SessionInfo {
    /// Create a new session info
    ///
    /// # Arguments
    ///
    /// * `session_id` - Unique session identifier
    /// * `peer_key` - WireGuard peer public key
    /// * `peer_endpoint` - Peer's WireGuard endpoint (IP:port)
    /// * `five_tuple` - Client's 5-tuple
    /// * `outbound_tag` - Outbound tag for routing
    #[must_use]
    pub fn new(
        session_id: u64,
        peer_key: [u8; 32],
        peer_endpoint: SocketAddr,
        five_tuple: FiveTuple,
        outbound_tag: String,
    ) -> Self {
        let now = Instant::now();
        Self {
            session_id,
            peer_key,
            peer_endpoint: Mutex::new(peer_endpoint),
            five_tuple,
            outbound_tag,
            created_at: now,
            last_active: Mutex::new(now),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
        }
    }

    /// Get the peer's WireGuard endpoint
    #[inline]
    #[must_use]
    pub fn peer_endpoint(&self) -> SocketAddr {
        *self.peer_endpoint.lock()
    }

    /// Update the peer's WireGuard endpoint (for NAT rebinding/roaming)
    ///
    /// Returns true if the endpoint changed, false if it was the same.
    pub fn update_peer_endpoint(&self, new_endpoint: SocketAddr) -> bool {
        let mut endpoint = self.peer_endpoint.lock();
        if *endpoint != new_endpoint {
            debug!(
                session_id = self.session_id,
                old = %*endpoint,
                new = %new_endpoint,
                "Peer endpoint changed (NAT rebinding/roaming)"
            );
            *endpoint = new_endpoint;
            true
        } else {
            false
        }
    }

    /// Update the last activity time to now
    ///
    /// This should be called whenever there is activity on the session
    /// (packet sent/received) to prevent premature cleanup.
    #[inline]
    pub fn touch(&self) {
        *self.last_active.lock() = Instant::now();
    }

    /// Add bytes sent to the counter
    pub fn add_bytes_sent(&self, bytes: u64) {
        self.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Add bytes received to the counter
    pub fn add_bytes_received(&self, bytes: u64) {
        self.bytes_received.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Get total bytes sent
    #[must_use]
    pub fn total_bytes_sent(&self) -> u64 {
        self.bytes_sent.load(Ordering::Relaxed)
    }

    /// Get total bytes received
    #[must_use]
    pub fn total_bytes_received(&self) -> u64 {
        self.bytes_received.load(Ordering::Relaxed)
    }

    /// Get session duration
    #[must_use]
    pub fn duration(&self) -> Duration {
        self.created_at.elapsed()
    }

    /// Get time since last activity
    #[must_use]
    pub fn idle_time(&self) -> Duration {
        self.last_active.lock().elapsed()
    }

    /// Get the last active time
    #[must_use]
    pub fn last_active(&self) -> Instant {
        *self.last_active.lock()
    }
}

impl Clone for SessionInfo {
    fn clone(&self) -> Self {
        Self {
            session_id: self.session_id,
            peer_key: self.peer_key,
            peer_endpoint: Mutex::new(*self.peer_endpoint.lock()),
            five_tuple: self.five_tuple.clone(),
            outbound_tag: self.outbound_tag.clone(),
            created_at: self.created_at,
            last_active: Mutex::new(*self.last_active.lock()),
            bytes_sent: AtomicU64::new(self.bytes_sent.load(Ordering::Relaxed)),
            bytes_received: AtomicU64::new(self.bytes_received.load(Ordering::Relaxed)),
        }
    }
}

/// Tracks sessions for the TUN + TPROXY bridge
///
/// Provides lookup by 5-tuple for routing reply packets back to
/// the correct WireGuard peer.
///
/// # Thread Safety
///
/// All operations are thread-safe and lock-free using `DashMap`.
///
/// # Performance
///
/// Uses ahash instead of SipHash for 2-3x faster lookups on the hot path.
pub struct SessionTracker {
    /// Forward index: client 5-tuple -> session info
    sessions: AHashMap<FiveTuple, Arc<SessionInfo>>,
    /// Session ID counter (monotonically increasing)
    next_session_id: AtomicU64,
    /// Per-peer session counts for rate limiting
    peer_session_counts: AHashMap<[u8; 32], AtomicU64>,
    /// Maximum sessions per peer
    max_sessions_per_peer: usize,
    /// Maximum total sessions
    max_total_sessions: usize,
}

impl SessionTracker {
    /// Create a new session tracker with default limits
    #[must_use]
    pub fn new() -> Self {
        Self::with_limits(
            super::MAX_SESSIONS_PER_PEER,
            super::MAX_TOTAL_SESSIONS,
        )
    }

    /// Create a new session tracker with custom limits
    #[must_use]
    pub fn with_limits(max_per_peer: usize, max_total: usize) -> Self {
        Self {
            sessions: DashMap::with_hasher(RandomState::new()),
            next_session_id: AtomicU64::new(1),
            peer_session_counts: DashMap::with_hasher(RandomState::new()),
            max_sessions_per_peer: max_per_peer,
            max_total_sessions: max_total,
        }
    }

    /// Register a new session
    ///
    /// # Arguments
    ///
    /// * `peer_key` - WireGuard peer public key
    /// * `peer_endpoint` - Peer's WireGuard endpoint (IP:port) for reply routing
    /// * `five_tuple` - Client's 5-tuple
    /// * `outbound_tag` - Outbound tag for routing (e.g., "direct", "vless-xxx")
    ///
    /// # Returns
    ///
    /// `Some(session)` if registration succeeded, `None` if limits exceeded.
    pub fn register(
        &self,
        peer_key: [u8; 32],
        peer_endpoint: SocketAddr,
        five_tuple: FiveTuple,
        outbound_tag: String,
    ) -> Option<Arc<SessionInfo>> {
        // Check if session already exists (common for ongoing connections)
        if let Some(existing) = self.sessions.get(&five_tuple) {
            // Update last_active on existing session
            existing.touch();
            // Update peer endpoint in case of NAT rebinding/roaming
            existing.update_peer_endpoint(peer_endpoint);
            return Some(Arc::clone(existing.value()));
        }

        // Check per-peer limit
        let count = self
            .peer_session_counts
            .entry(peer_key)
            .or_insert_with(|| AtomicU64::new(0));

        let current = count.fetch_add(1, Ordering::SeqCst);
        if current >= self.max_sessions_per_peer as u64 {
            count.fetch_sub(1, Ordering::SeqCst);
            warn!(
                peer = hex::encode(&peer_key[..8]),
                limit = self.max_sessions_per_peer,
                "Per-peer session limit exceeded"
            );
            return None;
        }

        // Check total limit
        if self.sessions.len() >= self.max_total_sessions {
            count.fetch_sub(1, Ordering::SeqCst);
            warn!(
                limit = self.max_total_sessions,
                "Total session limit exceeded"
            );
            return None;
        }

        let session_id = self.next_session_id.fetch_add(1, Ordering::SeqCst);
        let session = Arc::new(SessionInfo::new(
            session_id,
            peer_key,
            peer_endpoint,
            five_tuple.clone(),
            outbound_tag.clone(),
        ));

        self.sessions.insert(five_tuple, Arc::clone(&session));

        trace!(
            session_id,
            peer = hex::encode(&peer_key[..8]),
            peer_endpoint = %peer_endpoint,
            five_tuple = %session.five_tuple,
            outbound = %outbound_tag,
            "Session registered"
        );

        Some(session)
    }

    /// Look up session by client 5-tuple
    ///
    /// # Arguments
    ///
    /// * `five_tuple` - The client's 5-tuple to look up
    ///
    /// # Returns
    ///
    /// The session info if found.
    #[must_use]
    pub fn lookup(&self, five_tuple: &FiveTuple) -> Option<Arc<SessionInfo>> {
        self.sessions.get(five_tuple).map(|r| Arc::clone(r.value()))
    }

    /// Look up session by reversed 5-tuple (for reply packets)
    ///
    /// When the kernel sends a reply packet, the source and destination
    /// are swapped compared to the original client packet. This method
    /// takes the reply packet's 5-tuple and reverses it to find the
    /// original session.
    ///
    /// # Arguments
    ///
    /// * `reply_tuple` - The 5-tuple from the reply packet
    ///
    /// # Returns
    ///
    /// The session info if found.
    #[must_use]
    pub fn lookup_by_reply(&self, reply_tuple: &FiveTuple) -> Option<Arc<SessionInfo>> {
        let forward_tuple = reply_tuple.reverse();
        self.lookup(&forward_tuple)
    }

    /// Remove a session
    ///
    /// # Arguments
    ///
    /// * `five_tuple` - The client's 5-tuple to remove
    ///
    /// # Returns
    ///
    /// The removed session info if it existed.
    pub fn remove(&self, five_tuple: &FiveTuple) -> Option<Arc<SessionInfo>> {
        if let Some((_, session)) = self.sessions.remove(five_tuple) {
            // Decrement peer count
            if let Some(count) = self.peer_session_counts.get(&session.peer_key) {
                count.fetch_sub(1, Ordering::SeqCst);
            }

            debug!(
                session_id = session.session_id,
                peer = hex::encode(&session.peer_key[..8]),
                five_tuple = %session.five_tuple,
                bytes_sent = session.total_bytes_sent(),
                bytes_received = session.total_bytes_received(),
                duration_secs = session.duration().as_secs(),
                "Session removed"
            );

            Some(session)
        } else {
            None
        }
    }

    /// Get session count for a peer
    ///
    /// # Arguments
    ///
    /// * `peer_key` - The WireGuard peer public key
    ///
    /// # Returns
    ///
    /// The number of active sessions for this peer.
    #[must_use]
    pub fn peer_session_count(&self, peer_key: &[u8; 32]) -> u64 {
        self.peer_session_counts
            .get(peer_key)
            .map(|c| c.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    /// Get total session count
    #[must_use]
    pub fn total_sessions(&self) -> usize {
        self.sessions.len()
    }

    /// Get TCP session count
    #[must_use]
    pub fn tcp_session_count(&self) -> usize {
        self.sessions
            .iter()
            .filter(|entry| entry.value().five_tuple.is_tcp())
            .count()
    }

    /// Get UDP session count
    #[must_use]
    pub fn udp_session_count(&self) -> usize {
        self.sessions
            .iter()
            .filter(|entry| entry.value().five_tuple.is_udp())
            .count()
    }

    /// Iterate over all sessions
    ///
    /// # Arguments
    ///
    /// * `f` - Closure to call for each session
    pub fn for_each<F>(&self, mut f: F)
    where
        F: FnMut(&Arc<SessionInfo>),
    {
        for entry in self.sessions.iter() {
            f(entry.value());
        }
    }

    /// Remove sessions that match a predicate
    ///
    /// # Arguments
    ///
    /// * `predicate` - Returns true for sessions that should be removed
    ///
    /// # Returns
    ///
    /// The number of sessions removed.
    pub fn remove_if<F>(&self, mut predicate: F) -> usize
    where
        F: FnMut(&SessionInfo) -> bool,
    {
        let mut removed = 0;
        let mut to_remove = Vec::new();

        // Collect sessions to remove (can't remove while iterating)
        for entry in self.sessions.iter() {
            if predicate(entry.value()) {
                to_remove.push(entry.key().clone());
            }
        }

        // Remove them
        for five_tuple in to_remove {
            if self.remove(&five_tuple).is_some() {
                removed += 1;
            }
        }

        removed
    }

    /// Remove idle sessions based on timeouts
    ///
    /// # Arguments
    ///
    /// * `tcp_timeout` - Timeout for TCP sessions
    /// * `udp_timeout` - Timeout for UDP sessions
    ///
    /// # Returns
    ///
    /// The number of sessions removed.
    pub fn cleanup_idle(&self, tcp_timeout: Duration, udp_timeout: Duration) -> usize {
        self.remove_if(|session| {
            let timeout = if session.five_tuple.is_tcp() {
                tcp_timeout
            } else {
                udp_timeout
            };
            session.idle_time() > timeout
        })
    }
}

impl Default for SessionTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn make_test_tuple(src_port: u16, dst_port: u16) -> FiveTuple {
        FiveTuple::tcp(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 25, 0, 2)), src_port),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), dst_port),
        )
    }

    fn test_peer_endpoint() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 51820)
    }

    #[test]
    fn test_five_tuple_tcp() {
        let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 25, 0, 2)), 12345);
        let dst = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 443);
        let tuple = FiveTuple::tcp(src, dst);

        assert!(tuple.is_tcp());
        assert!(!tuple.is_udp());
        assert_eq!(tuple.protocol, 6);
    }

    #[test]
    fn test_five_tuple_udp() {
        let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 25, 0, 2)), 12345);
        let dst = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53);
        let tuple = FiveTuple::udp(src, dst);

        assert!(!tuple.is_tcp());
        assert!(tuple.is_udp());
        assert_eq!(tuple.protocol, 17);
    }

    #[test]
    fn test_five_tuple_reverse() {
        let tuple = FiveTuple::tcp(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 25, 0, 2)), 12345),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 80),
        );
        let reversed = tuple.reverse();

        assert_eq!(reversed.src_addr.port(), 80);
        assert_eq!(reversed.dst_addr.port(), 12345);
        assert_eq!(reversed.protocol, 6);
    }

    #[test]
    fn test_five_tuple_display() {
        let tcp = FiveTuple::tcp(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 25, 0, 2)), 12345),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 80),
        );
        let display = format!("{}", tcp);
        assert!(display.contains("TCP"));
        assert!(display.contains("10.25.0.2:12345"));
        assert!(display.contains("93.184.216.34:80"));

        let udp = FiveTuple::udp(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 25, 0, 2)), 12345),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
        );
        let display = format!("{}", udp);
        assert!(display.contains("UDP"));
    }

    #[test]
    fn test_five_tuple_from_ipv4_tcp_packet() {
        // IPv4 TCP packet: 10.25.0.2:12345 -> 93.184.216.34:80
        let packet = vec![
            0x45, 0x00, 0x00, 0x28, // Version, IHL, DSCP, Total Length
            0x00, 0x00, 0x00, 0x00, // ID, Flags, Fragment Offset
            0x40, 0x06, 0x00, 0x00, // TTL, Protocol (TCP=6), Checksum
            0x0a, 0x19, 0x00, 0x02, // Source IP: 10.25.0.2
            0x5d, 0xb8, 0xd8, 0x22, // Dest IP: 93.184.216.34
            0x30, 0x39, 0x00, 0x50, // Source Port: 12345, Dest Port: 80
        ];

        let five_tuple = FiveTuple::from_packet(&packet);
        assert!(five_tuple.is_some());

        let ft = five_tuple.unwrap();
        assert!(ft.is_tcp());
        assert_eq!(ft.src_addr.port(), 12345);
        assert_eq!(ft.dst_addr.port(), 80);
    }

    #[test]
    fn test_five_tuple_from_ipv4_udp_packet() {
        // IPv4 UDP packet: 10.25.0.2:54321 -> 8.8.8.8:53
        let packet = vec![
            0x45, 0x00, 0x00, 0x1c, // Version, IHL, DSCP, Total Length
            0x00, 0x00, 0x00, 0x00, // ID, Flags, Fragment Offset
            0x40, 0x11, 0x00, 0x00, // TTL, Protocol (UDP=17), Checksum
            0x0a, 0x19, 0x00, 0x02, // Source IP: 10.25.0.2
            0x08, 0x08, 0x08, 0x08, // Dest IP: 8.8.8.8
            0xd4, 0x31, 0x00, 0x35, // Source Port: 54321, Dest Port: 53
        ];

        let five_tuple = FiveTuple::from_packet(&packet);
        assert!(five_tuple.is_some());

        let ft = five_tuple.unwrap();
        assert!(ft.is_udp());
        assert_eq!(ft.src_addr.port(), 54321);
        assert_eq!(ft.dst_addr.port(), 53);
    }

    #[test]
    fn test_five_tuple_from_malformed_packet() {
        // Too short
        assert!(FiveTuple::from_packet(&[0x45, 0x00]).is_none());

        // Empty
        assert!(FiveTuple::from_packet(&[]).is_none());

        // Invalid version
        assert!(FiveTuple::from_packet(&[0x00; 40]).is_none());
    }

    #[test]
    fn test_session_tracker_basic() {
        let tracker = SessionTracker::new();
        let peer_key = [0u8; 32];
        let peer_endpoint = test_peer_endpoint();
        let five_tuple = make_test_tuple(12345, 80);

        let session = tracker
            .register(peer_key, peer_endpoint, five_tuple.clone(), "direct".to_string())
            .unwrap();
        assert_eq!(session.session_id, 1);
        assert_eq!(session.peer_endpoint(), peer_endpoint);

        let found = tracker.lookup(&five_tuple).unwrap();
        assert_eq!(found.session_id, 1);

        assert_eq!(tracker.total_sessions(), 1);
        assert_eq!(tracker.peer_session_count(&peer_key), 1);
    }

    #[test]
    fn test_session_tracker_lookup_by_reply() {
        let tracker = SessionTracker::new();
        let peer_key = [0u8; 32];
        let peer_endpoint = test_peer_endpoint();
        let five_tuple = make_test_tuple(12345, 80);

        tracker
            .register(peer_key, peer_endpoint, five_tuple.clone(), "direct".to_string())
            .unwrap();

        // Create a reply tuple (reversed)
        let reply_tuple = five_tuple.reverse();
        let found = tracker.lookup_by_reply(&reply_tuple).unwrap();
        assert_eq!(found.five_tuple, five_tuple);
    }

    #[test]
    fn test_session_tracker_remove() {
        let tracker = SessionTracker::new();
        let peer_key = [2u8; 32];
        let peer_endpoint = test_peer_endpoint();
        let five_tuple = make_test_tuple(12345, 80);

        tracker
            .register(peer_key, peer_endpoint, five_tuple.clone(), "direct".to_string())
            .unwrap();
        assert_eq!(tracker.total_sessions(), 1);

        let removed = tracker.remove(&five_tuple).unwrap();
        assert_eq!(removed.session_id, 1);
        assert_eq!(tracker.total_sessions(), 0);
        assert_eq!(tracker.peer_session_count(&peer_key), 0);
    }

    #[test]
    fn test_session_tracker_multiple_peers() {
        let tracker = SessionTracker::new();
        let peer1 = [1u8; 32];
        let peer2 = [2u8; 32];
        let peer_endpoint1 = test_peer_endpoint();
        let peer_endpoint2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 101)), 51820);

        let tuple1 = make_test_tuple(12345, 80);
        let tuple2 = make_test_tuple(12346, 443);
        let tuple3 = make_test_tuple(12347, 8080);

        tracker.register(peer1, peer_endpoint1, tuple1, "direct".to_string()).unwrap();
        tracker.register(peer1, peer_endpoint1, tuple2, "direct".to_string()).unwrap();
        tracker.register(peer2, peer_endpoint2, tuple3, "direct".to_string()).unwrap();

        assert_eq!(tracker.peer_session_count(&peer1), 2);
        assert_eq!(tracker.peer_session_count(&peer2), 1);
        assert_eq!(tracker.total_sessions(), 3);
    }

    #[test]
    fn test_session_tracker_tcp_udp_counts() {
        let tracker = SessionTracker::new();
        let peer_key = [0u8; 32];
        let peer_endpoint = test_peer_endpoint();

        // Add TCP sessions
        let tcp1 = FiveTuple::tcp(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 25, 0, 2)), 12345),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 80),
        );
        let tcp2 = FiveTuple::tcp(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 25, 0, 2)), 12346),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 443),
        );

        // Add UDP session
        let udp1 = FiveTuple::udp(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 25, 0, 2)), 12347),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
        );

        tracker.register(peer_key, peer_endpoint, tcp1, "direct".to_string()).unwrap();
        tracker.register(peer_key, peer_endpoint, tcp2, "direct".to_string()).unwrap();
        tracker.register(peer_key, peer_endpoint, udp1, "direct".to_string()).unwrap();

        assert_eq!(tracker.tcp_session_count(), 2);
        assert_eq!(tracker.udp_session_count(), 1);
        assert_eq!(tracker.total_sessions(), 3);
    }

    #[test]
    fn test_session_info_stats() {
        let peer_key = [0u8; 32];
        let peer_endpoint = test_peer_endpoint();
        let five_tuple = make_test_tuple(12345, 80);
        let session = SessionInfo::new(1, peer_key, peer_endpoint, five_tuple, "direct".to_string());

        session.add_bytes_sent(100);
        session.add_bytes_sent(200);
        assert_eq!(session.total_bytes_sent(), 300);

        session.add_bytes_received(500);
        assert_eq!(session.total_bytes_received(), 500);
    }

    #[test]
    fn test_session_tracker_cleanup_idle() {
        let tracker = SessionTracker::new();
        let peer_key = [0u8; 32];
        let peer_endpoint = test_peer_endpoint();

        // Add a session
        let five_tuple = make_test_tuple(12345, 80);
        tracker.register(peer_key, peer_endpoint, five_tuple, "direct".to_string()).unwrap();

        // Immediately cleaning with 0 timeout should remove it
        let removed = tracker.cleanup_idle(Duration::ZERO, Duration::ZERO);
        assert_eq!(removed, 1);
        assert_eq!(tracker.total_sessions(), 0);
    }

    #[test]
    fn test_session_tracker_per_peer_limit() {
        let tracker = SessionTracker::with_limits(2, 100);
        let peer_key = [0u8; 32];
        let peer_endpoint = test_peer_endpoint();

        // Register 2 sessions (within limit)
        let tuple1 = make_test_tuple(12345, 80);
        let tuple2 = make_test_tuple(12346, 443);
        let tuple3 = make_test_tuple(12347, 8080);

        assert!(tracker.register(peer_key, peer_endpoint, tuple1, "direct".to_string()).is_some());
        assert!(tracker.register(peer_key, peer_endpoint, tuple2, "direct".to_string()).is_some());

        // Third should fail (exceeds per-peer limit)
        assert!(tracker.register(peer_key, peer_endpoint, tuple3, "direct".to_string()).is_none());
    }

    #[test]
    fn test_session_tracker_total_limit() {
        let tracker = SessionTracker::with_limits(100, 2);
        let peer_endpoint = test_peer_endpoint();

        // Register 2 sessions (within limit)
        let peer1 = [1u8; 32];
        let peer2 = [2u8; 32];
        let peer3 = [3u8; 32];

        let tuple1 = make_test_tuple(12345, 80);
        let tuple2 = make_test_tuple(12346, 443);
        let tuple3 = make_test_tuple(12347, 8080);

        assert!(tracker.register(peer1, peer_endpoint, tuple1, "direct".to_string()).is_some());
        assert!(tracker.register(peer2, peer_endpoint, tuple2, "direct".to_string()).is_some());

        // Third should fail (exceeds total limit)
        assert!(tracker.register(peer3, peer_endpoint, tuple3, "direct".to_string()).is_none());
    }

    #[test]
    fn test_session_endpoint_update() {
        let tracker = SessionTracker::new();
        let peer_key = [0u8; 32];
        let peer_endpoint1 = test_peer_endpoint();
        let peer_endpoint2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200)), 51820);
        let five_tuple = make_test_tuple(12345, 80);

        // Register with initial endpoint
        let session = tracker
            .register(peer_key, peer_endpoint1, five_tuple.clone(), "direct".to_string())
            .unwrap();
        assert_eq!(session.peer_endpoint(), peer_endpoint1);

        // Register same session again with different endpoint (NAT rebinding)
        let session2 = tracker
            .register(peer_key, peer_endpoint2, five_tuple.clone(), "direct".to_string())
            .unwrap();

        // Endpoint should be updated
        assert_eq!(session2.peer_endpoint(), peer_endpoint2);

        // Original Arc should also see the update
        assert_eq!(session.peer_endpoint(), peer_endpoint2);
    }
}
