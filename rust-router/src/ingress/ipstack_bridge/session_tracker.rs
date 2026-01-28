//! Session tracking for IpStack bridge
//!
//! Tracks TCP/UDP sessions and maps them back to WireGuard peers
//! for reply packet routing.
//!
//! # Design
//!
//! The session tracker provides bidirectional lookup:
//! - Forward: client 5-tuple -> session info (for new packets from client)
//! - Reverse: local port + protocol -> session info (for reply routing)
//!
//! # Thread Safety
//!
//! Uses `DashMap` for lock-free concurrent access, allowing the forwarder
//! and multiple connection handlers to access the tracker simultaneously.
//!
//! # Resource Limits
//!
//! The tracker enforces per-peer and total session limits to prevent
//! resource exhaustion:
//!
//! - `MAX_SESSIONS_PER_PEER`: Limits sessions per WireGuard peer
//! - `MAX_TOTAL_SESSIONS`: Hard limit on total concurrent sessions

use ahash::RandomState;
use dashmap::DashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

/// Type alias for DashMap with ahash for faster lookups
/// ahash is ~2-3x faster than the default SipHash for small keys
type AHashMap<K, V> = DashMap<K, V, RandomState>;

/// 5-tuple identifying a TCP/UDP session
///
/// A 5-tuple uniquely identifies a network session based on:
/// - Source address (IP + port)
/// - Destination address (IP + port)
/// - Protocol (TCP = 6, UDP = 17)
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct FiveTuple {
    /// Source socket address (client)
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
    /// This is used to match reply packets from the server back
    /// to the original client session.
    pub fn reverse(&self) -> Self {
        Self {
            src_addr: self.dst_addr,
            dst_addr: self.src_addr,
            protocol: self.protocol,
        }
    }

    /// Check if this is a TCP session
    #[inline]
    pub fn is_tcp(&self) -> bool {
        self.protocol == 6
    }

    /// Check if this is a UDP session
    #[inline]
    pub fn is_udp(&self) -> bool {
        self.protocol == 17
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
    /// Uses parking_lot::Mutex to allow updates on NAT rebinding/roaming
    peer_endpoint: parking_lot::Mutex<SocketAddr>,
    /// Original 5-tuple from client
    pub five_tuple: FiveTuple,
    /// Local ephemeral port allocated for this session
    pub local_port: u16,
    /// Outbound tag for routing (e.g., "direct", "vless-xxx", "ss-xxx")
    /// Determined by RuleEngine before packet injection
    pub outbound_tag: String,
    /// Session creation time
    pub created_at: Instant,
    /// Last activity time (updated on packet send/receive)
    /// Uses parking_lot::Mutex for interior mutability with minimal overhead
    last_active: parking_lot::Mutex<Instant>,
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
    /// * `local_port` - Allocated ephemeral port
    /// * `outbound_tag` - Outbound tag for routing
    pub fn new(
        session_id: u64,
        peer_key: [u8; 32],
        peer_endpoint: SocketAddr,
        five_tuple: FiveTuple,
        local_port: u16,
        outbound_tag: String,
    ) -> Self {
        let now = Instant::now();
        Self {
            session_id,
            peer_key,
            peer_endpoint: parking_lot::Mutex::new(peer_endpoint),
            five_tuple,
            local_port,
            outbound_tag,
            created_at: now,
            last_active: parking_lot::Mutex::new(now),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
        }
    }

    /// Get the peer's WireGuard endpoint
    #[inline]
    pub fn peer_endpoint(&self) -> SocketAddr {
        *self.peer_endpoint.lock()
    }

    /// Update the peer's WireGuard endpoint (for NAT rebinding/roaming)
    ///
    /// Returns true if the endpoint changed, false if it was the same.
    pub fn update_peer_endpoint(&self, new_endpoint: SocketAddr) -> bool {
        let mut endpoint = self.peer_endpoint.lock();
        if *endpoint != new_endpoint {
            tracing::debug!(
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
    pub fn total_bytes_sent(&self) -> u64 {
        self.bytes_sent.load(Ordering::Relaxed)
    }

    /// Get total bytes received
    pub fn total_bytes_received(&self) -> u64 {
        self.bytes_received.load(Ordering::Relaxed)
    }

    /// Get session duration
    pub fn duration(&self) -> std::time::Duration {
        self.created_at.elapsed()
    }

    /// Get time since last activity
    pub fn idle_time(&self) -> std::time::Duration {
        self.last_active.lock().elapsed()
    }

    /// Get the last active time
    pub fn last_active(&self) -> Instant {
        *self.last_active.lock()
    }
}

impl Clone for SessionInfo {
    fn clone(&self) -> Self {
        Self {
            session_id: self.session_id,
            peer_key: self.peer_key,
            peer_endpoint: parking_lot::Mutex::new(*self.peer_endpoint.lock()),
            five_tuple: self.five_tuple.clone(),
            local_port: self.local_port,
            outbound_tag: self.outbound_tag.clone(),
            created_at: self.created_at,
            last_active: parking_lot::Mutex::new(*self.last_active.lock()),
            bytes_sent: AtomicU64::new(self.bytes_sent.load(Ordering::Relaxed)),
            bytes_received: AtomicU64::new(self.bytes_received.load(Ordering::Relaxed)),
        }
    }
}

/// Tracks sessions for the IpStack bridge
///
/// Provides bidirectional lookup:
/// - Forward: client 5-tuple -> session info
/// - Reverse: (local_port, protocol) -> session info (for reply routing)
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
    forward: AHashMap<FiveTuple, Arc<SessionInfo>>,
    /// Reverse index: (local_port, protocol) -> session info
    /// Used for routing reply packets back to the correct peer
    reverse: AHashMap<(u16, u8), Arc<SessionInfo>>,
    /// Session ID counter (monotonically increasing)
    next_session_id: AtomicU64,
    /// Per-peer session counts for rate limiting
    peer_session_counts: AHashMap<[u8; 32], AtomicU64>,
}

impl SessionTracker {
    /// Create a new session tracker
    pub fn new() -> Self {
        Self {
            forward: DashMap::with_hasher(RandomState::new()),
            reverse: DashMap::with_hasher(RandomState::new()),
            next_session_id: AtomicU64::new(1),
            peer_session_counts: DashMap::with_hasher(RandomState::new()),
        }
    }

    /// Register a new session
    ///
    /// # Arguments
    ///
    /// * `peer_key` - WireGuard peer public key
    /// * `peer_endpoint` - Peer's WireGuard endpoint (IP:port) for reply routing
    /// * `five_tuple` - Client's 5-tuple
    /// * `local_port` - Allocated ephemeral port for this session
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
        local_port: u16,
        outbound_tag: String,
    ) -> Option<Arc<SessionInfo>> {
        // Check per-peer limit
        let count = self
            .peer_session_counts
            .entry(peer_key)
            .or_insert_with(|| AtomicU64::new(0));

        let current = count.fetch_add(1, Ordering::SeqCst);
        if current >= super::config::MAX_SESSIONS_PER_PEER as u64 {
            count.fetch_sub(1, Ordering::SeqCst);
            tracing::warn!(
                peer = hex::encode(&peer_key[..8]),
                limit = super::config::MAX_SESSIONS_PER_PEER,
                "Per-peer session limit exceeded"
            );
            return None;
        }

        // Check total limit
        if self.forward.len() >= super::config::MAX_TOTAL_SESSIONS {
            count.fetch_sub(1, Ordering::SeqCst);
            tracing::warn!(
                limit = super::config::MAX_TOTAL_SESSIONS,
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
            local_port,
            outbound_tag.clone(),
        ));

        self.forward.insert(five_tuple, Arc::clone(&session));
        // Only add to reverse index if we have a valid local port
        // (inject_packet uses register_forward_only instead to avoid port=0 collisions)
        if local_port != 0 {
            self.reverse
                .insert((local_port, session.five_tuple.protocol), Arc::clone(&session));
        }

        tracing::debug!(
            session_id,
            peer = hex::encode(&peer_key[..8]),
            peer_endpoint = %peer_endpoint,
            five_tuple = %session.five_tuple,
            local_port,
            outbound = %outbound_tag,
            "Session registered"
        );

        Some(session)
    }

    /// Register a session for forward lookup only (no reverse index)
    ///
    /// This is used by `inject_packet` where we don't have a local ephemeral port yet.
    /// The session is tracked only in the forward index for reply routing.
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
    /// `Some(session)` if registration succeeded or session already exists, `None` if limits exceeded.
    pub fn register_forward_only(
        &self,
        peer_key: [u8; 32],
        peer_endpoint: SocketAddr,
        five_tuple: FiveTuple,
        outbound_tag: String,
    ) -> Option<Arc<SessionInfo>> {
        // Check if session already exists (common for ongoing connections)
        if let Some(existing) = self.forward.get(&five_tuple) {
            // Update last_active on existing session
            existing.touch();
            // Update peer endpoint in case of NAT rebinding/roaming
            existing.update_peer_endpoint(peer_endpoint);
            // Note: We don't update outbound_tag - the first registration determines the route
            return Some(Arc::clone(existing.value()));
        }

        // Check per-peer limit
        let count = self
            .peer_session_counts
            .entry(peer_key)
            .or_insert_with(|| AtomicU64::new(0));

        let current = count.fetch_add(1, Ordering::SeqCst);
        if current >= super::config::MAX_SESSIONS_PER_PEER as u64 {
            count.fetch_sub(1, Ordering::SeqCst);
            tracing::warn!(
                peer = hex::encode(&peer_key[..8]),
                limit = super::config::MAX_SESSIONS_PER_PEER,
                "Per-peer session limit exceeded"
            );
            return None;
        }

        // Check total limit
        if self.forward.len() >= super::config::MAX_TOTAL_SESSIONS {
            count.fetch_sub(1, Ordering::SeqCst);
            tracing::warn!(
                limit = super::config::MAX_TOTAL_SESSIONS,
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
            0, // No local port for forward-only registration
            outbound_tag.clone(),
        ));

        // Only add to forward index (no reverse index)
        self.forward.insert(five_tuple, Arc::clone(&session));

        tracing::trace!(
            session_id,
            peer = hex::encode(&peer_key[..8]),
            peer_endpoint = %peer_endpoint,
            five_tuple = %session.five_tuple,
            outbound = %outbound_tag,
            "Session registered (forward-only)"
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
    pub fn lookup(&self, five_tuple: &FiveTuple) -> Option<Arc<SessionInfo>> {
        self.forward.get(five_tuple).map(|r| Arc::clone(r.value()))
    }

    /// Look up session by local port (for reply routing)
    ///
    /// # Arguments
    ///
    /// * `local_port` - The local ephemeral port
    /// * `protocol` - The IP protocol (6 = TCP, 17 = UDP)
    ///
    /// # Returns
    ///
    /// The session info if found.
    pub fn lookup_by_port(&self, local_port: u16, protocol: u8) -> Option<Arc<SessionInfo>> {
        self.reverse
            .get(&(local_port, protocol))
            .map(|r| Arc::clone(r.value()))
    }

    /// Look up session by 5-tuple for reply routing
    ///
    /// This is a convenience method that returns the peer key (as Base64) and endpoint
    /// needed for routing reply packets back to the WireGuard peer.
    ///
    /// # Arguments
    ///
    /// * `five_tuple` - The client's 5-tuple to look up
    ///
    /// # Returns
    ///
    /// `Some((peer_key_base64, peer_endpoint))` if found, `None` otherwise.
    pub fn lookup_for_reply(&self, five_tuple: &FiveTuple) -> Option<(String, SocketAddr)> {
        use base64::engine::general_purpose::STANDARD as BASE64;
        use base64::Engine;

        self.forward.get(five_tuple).map(|session| {
            let peer_key_b64 = BASE64.encode(session.peer_key);
            (peer_key_b64, session.peer_endpoint())
        })
    }

    /// Expose the forward index for direct access
    ///
    /// This is useful for the ipstack reply router which needs to access sessions
    /// by 5-tuple without the overhead of Arc cloning.
    #[inline]
    pub fn forward(&self) -> &AHashMap<FiveTuple, Arc<SessionInfo>> {
        &self.forward
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
        if let Some((_, session)) = self.forward.remove(five_tuple) {
            // Clean up reverse index
            self.reverse
                .remove(&(session.local_port, session.five_tuple.protocol));

            // Decrement peer count
            if let Some(count) = self.peer_session_counts.get(&session.peer_key) {
                count.fetch_sub(1, Ordering::SeqCst);
            }

            tracing::debug!(
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

    /// Remove a session by local port
    ///
    /// # Arguments
    ///
    /// * `local_port` - The local ephemeral port
    /// * `protocol` - The IP protocol (6 = TCP, 17 = UDP)
    ///
    /// # Returns
    ///
    /// The removed session info if it existed.
    pub fn remove_by_port(&self, local_port: u16, protocol: u8) -> Option<Arc<SessionInfo>> {
        if let Some((_, session)) = self.reverse.remove(&(local_port, protocol)) {
            // Clean up forward index
            self.forward.remove(&session.five_tuple);

            // Decrement peer count
            if let Some(count) = self.peer_session_counts.get(&session.peer_key) {
                count.fetch_sub(1, Ordering::SeqCst);
            }

            tracing::debug!(
                session_id = session.session_id,
                local_port,
                "Session removed by port"
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
    pub fn peer_session_count(&self, peer_key: &[u8; 32]) -> u64 {
        self.peer_session_counts
            .get(peer_key)
            .map(|c| c.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    /// Get total session count
    pub fn total_sessions(&self) -> usize {
        self.forward.len()
    }

    /// Get TCP session count
    pub fn tcp_session_count(&self) -> usize {
        self.forward
            .iter()
            .filter(|entry| entry.value().five_tuple.is_tcp())
            .count()
    }

    /// Get UDP session count
    pub fn udp_session_count(&self) -> usize {
        self.forward
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
        for entry in self.forward.iter() {
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
        for entry in self.forward.iter() {
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

    /// Default test peer endpoint (WireGuard client endpoint)
    fn test_peer_endpoint() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 51820)
    }

    #[test]
    fn test_session_tracker_basic() {
        let tracker = SessionTracker::new();
        let peer_key = [0u8; 32];
        let peer_endpoint = test_peer_endpoint();
        let five_tuple = make_test_tuple(12345, 80);

        let session = tracker
            .register(peer_key, peer_endpoint, five_tuple.clone(), 50000)
            .unwrap();
        assert_eq!(session.session_id, 1);
        assert_eq!(session.peer_endpoint(), peer_endpoint);

        let found = tracker.lookup(&five_tuple).unwrap();
        assert_eq!(found.session_id, 1);

        assert_eq!(tracker.total_sessions(), 1);
        assert_eq!(tracker.peer_session_count(&peer_key), 1);
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
    fn test_session_tracker_lookup_by_port() {
        let tracker = SessionTracker::new();
        let peer_key = [1u8; 32];
        let peer_endpoint = test_peer_endpoint();
        let five_tuple = make_test_tuple(12345, 443);

        tracker
            .register(peer_key, peer_endpoint, five_tuple.clone(), 50001)
            .unwrap();

        let found = tracker.lookup_by_port(50001, 6).unwrap();
        assert_eq!(found.five_tuple, five_tuple);
        assert_eq!(found.local_port, 50001);
    }

    #[test]
    fn test_session_tracker_remove() {
        let tracker = SessionTracker::new();
        let peer_key = [2u8; 32];
        let peer_endpoint = test_peer_endpoint();
        let five_tuple = make_test_tuple(12345, 80);

        tracker
            .register(peer_key, peer_endpoint, five_tuple.clone(), 50002)
            .unwrap();
        assert_eq!(tracker.total_sessions(), 1);

        let removed = tracker.remove(&five_tuple).unwrap();
        assert_eq!(removed.local_port, 50002);
        assert_eq!(tracker.total_sessions(), 0);
        assert_eq!(tracker.peer_session_count(&peer_key), 0);
    }

    #[test]
    fn test_session_tracker_remove_by_port() {
        let tracker = SessionTracker::new();
        let peer_key = [3u8; 32];
        let peer_endpoint = test_peer_endpoint();
        let five_tuple = make_test_tuple(12345, 80);

        tracker
            .register(peer_key, peer_endpoint, five_tuple.clone(), 50003)
            .unwrap();

        let removed = tracker.remove_by_port(50003, 6).unwrap();
        assert_eq!(removed.five_tuple, five_tuple);
        assert_eq!(tracker.total_sessions(), 0);
    }

    #[test]
    fn test_session_info_stats() {
        let peer_key = [0u8; 32];
        let peer_endpoint = test_peer_endpoint();
        let five_tuple = make_test_tuple(12345, 80);
        let session = SessionInfo::new(1, peer_key, peer_endpoint, five_tuple, 50000);

        session.add_bytes_sent(100);
        session.add_bytes_sent(200);
        assert_eq!(session.total_bytes_sent(), 300);

        session.add_bytes_received(500);
        assert_eq!(session.total_bytes_received(), 500);
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

        tracker.register(peer1, peer_endpoint1, tuple1, 50001).unwrap();
        tracker.register(peer1, peer_endpoint1, tuple2, 50002).unwrap();
        tracker.register(peer2, peer_endpoint2, tuple3, 50003).unwrap();

        assert_eq!(tracker.peer_session_count(&peer1), 2);
        assert_eq!(tracker.peer_session_count(&peer2), 1);
        assert_eq!(tracker.total_sessions(), 3);
    }

    #[test]
    fn test_tcp_udp_session_counts() {
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

        tracker.register(peer_key, peer_endpoint, tcp1, 50001).unwrap();
        tracker.register(peer_key, peer_endpoint, tcp2, 50002).unwrap();
        tracker.register(peer_key, peer_endpoint, udp1, 50003).unwrap();

        assert_eq!(tracker.tcp_session_count(), 2);
        assert_eq!(tracker.udp_session_count(), 1);
        assert_eq!(tracker.total_sessions(), 3);
    }

    #[test]
    fn test_remove_if() {
        let tracker = SessionTracker::new();
        let peer_key = [0u8; 32];
        let peer_endpoint = test_peer_endpoint();

        // Add sessions with different ports
        for port in 12345..12355 {
            let tuple = make_test_tuple(port, 80);
            tracker.register(peer_key, peer_endpoint, tuple, 50000 + port).unwrap();
        }

        assert_eq!(tracker.total_sessions(), 10);

        // Remove sessions with even source ports
        let removed = tracker.remove_if(|session| session.five_tuple.src_addr.port() % 2 == 0);

        assert_eq!(removed, 5);
        assert_eq!(tracker.total_sessions(), 5);
    }

    #[test]
    fn test_lookup_for_reply() {
        let tracker = SessionTracker::new();
        let peer_key = [0u8; 32];
        let peer_endpoint = test_peer_endpoint();
        let five_tuple = make_test_tuple(12345, 80);

        tracker
            .register(peer_key, peer_endpoint, five_tuple.clone(), 50000)
            .unwrap();

        // Look up session using the forward tuple
        let (peer_key_b64, found_endpoint) = tracker.lookup_for_reply(&five_tuple).unwrap();

        use base64::engine::general_purpose::STANDARD as BASE64;
        use base64::Engine;
        assert_eq!(peer_key_b64, BASE64.encode(peer_key));
        assert_eq!(found_endpoint, peer_endpoint);
    }

    #[test]
    fn test_peer_endpoint_update() {
        let tracker = SessionTracker::new();
        let peer_key = [0u8; 32];
        let peer_endpoint1 = test_peer_endpoint();
        let peer_endpoint2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200)), 51820);
        let five_tuple = make_test_tuple(12345, 80);

        // Register with initial endpoint
        let session = tracker
            .register(peer_key, peer_endpoint1, five_tuple.clone(), 50000)
            .unwrap();
        assert_eq!(session.peer_endpoint(), peer_endpoint1);

        // Register same session again with different endpoint (NAT rebinding)
        let session2 = tracker
            .register_forward_only(peer_key, peer_endpoint2, five_tuple.clone())
            .unwrap();

        // Endpoint should be updated
        assert_eq!(session2.peer_endpoint(), peer_endpoint2);

        // Original Arc should also see the update
        assert_eq!(session.peer_endpoint(), peer_endpoint2);
    }
}
