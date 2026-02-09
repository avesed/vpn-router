//! Session tracking for the netbridge module
//!
//! This module provides thread-safe session tracking with support for:
//!
//! - Forward lookup: 5-tuple → session info
//! - Reverse lookup: reply 5-tuple → original session
//! - Per-peer session counting and rate limiting
//! - Automatic cleanup of idle sessions
//!
//! # Thread Safety
//!
//! All types use `DashMap` for lock-free concurrent access, allowing:
//! - Packet injection to register sessions
//! - Reply routing to look up sessions
//! - Cleanup tasks to remove idle sessions
//!
//! # Performance
//!
//! Uses `ahash` instead of `SipHash` for 2-3x faster hash lookups on the hot path.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ahash::RandomState;
use dashmap::DashMap;
use parking_lot::Mutex;
use tracing::{debug, trace, warn};

use super::config::{MAX_SESSIONS_PER_PEER, MAX_TOTAL_SESSIONS};
use super::types::{FiveTuple, SessionId, SessionIdGenerator};

/// Type alias for DashMap with ahash for faster lookups
type AHashMap<K, V> = DashMap<K, V, RandomState>;

// =============================================================================
// Session Info
// =============================================================================

/// Information about an active session
///
/// Contains all metadata needed to track a session and route reply packets
/// back to the correct WireGuard peer.
#[derive(Debug)]
pub struct Session {
    /// Unique session ID (monotonically increasing)
    pub id: SessionId,
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
    bytes_sent: AtomicU64,
    /// Bytes received from outbound
    bytes_received: AtomicU64,
    /// Packets sent to outbound
    packets_sent: AtomicU64,
    /// Packets received from outbound
    packets_received: AtomicU64,
}

impl Session {
    /// Create a new session
    ///
    /// # Arguments
    ///
    /// * `id` - Unique session identifier
    /// * `peer_key` - WireGuard peer public key
    /// * `peer_endpoint` - Peer's WireGuard endpoint (IP:port)
    /// * `five_tuple` - Client's 5-tuple
    /// * `outbound_tag` - Outbound tag for routing
    #[must_use]
    pub fn new(
        id: SessionId,
        peer_key: [u8; 32],
        peer_endpoint: SocketAddr,
        five_tuple: FiveTuple,
        outbound_tag: String,
    ) -> Self {
        let now = Instant::now();
        Self {
            id,
            peer_key,
            peer_endpoint: Mutex::new(peer_endpoint),
            five_tuple,
            outbound_tag,
            created_at: now,
            last_active: Mutex::new(now),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            packets_sent: AtomicU64::new(0),
            packets_received: AtomicU64::new(0),
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
                session_id = %self.id,
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
    #[inline]
    pub fn touch(&self) {
        *self.last_active.lock() = Instant::now();
    }

    /// Add bytes sent to the counter
    #[inline]
    pub fn add_bytes_sent(&self, bytes: u64) {
        self.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
        self.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.touch();
    }

    /// Add bytes received to the counter
    #[inline]
    pub fn add_bytes_received(&self, bytes: u64) {
        self.bytes_received.fetch_add(bytes, Ordering::Relaxed);
        self.packets_received.fetch_add(1, Ordering::Relaxed);
        self.touch();
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

    /// Get total packets sent
    #[must_use]
    pub fn total_packets_sent(&self) -> u64 {
        self.packets_sent.load(Ordering::Relaxed)
    }

    /// Get total packets received
    #[must_use]
    pub fn total_packets_received(&self) -> u64 {
        self.packets_received.load(Ordering::Relaxed)
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

    /// Check if this is a TCP session
    #[inline]
    #[must_use]
    pub fn is_tcp(&self) -> bool {
        self.five_tuple.is_tcp()
    }

    /// Check if this is a UDP session
    #[inline]
    #[must_use]
    pub fn is_udp(&self) -> bool {
        self.five_tuple.is_udp()
    }

    /// Get a short representation of the peer key (first 8 bytes as hex)
    #[must_use]
    pub fn peer_key_short(&self) -> String {
        hex::encode(&self.peer_key[..8])
    }
}

impl Clone for Session {
    fn clone(&self) -> Self {
        Self {
            id: self.id,
            peer_key: self.peer_key,
            peer_endpoint: Mutex::new(*self.peer_endpoint.lock()),
            five_tuple: self.five_tuple,
            outbound_tag: self.outbound_tag.clone(),
            created_at: self.created_at,
            last_active: Mutex::new(*self.last_active.lock()),
            bytes_sent: AtomicU64::new(self.bytes_sent.load(Ordering::Relaxed)),
            bytes_received: AtomicU64::new(self.bytes_received.load(Ordering::Relaxed)),
            packets_sent: AtomicU64::new(self.packets_sent.load(Ordering::Relaxed)),
            packets_received: AtomicU64::new(self.packets_received.load(Ordering::Relaxed)),
        }
    }
}

// =============================================================================
// Register Result
// =============================================================================

/// Result of a session registration operation
///
/// Distinguishes between creating a new session and updating an existing one.
/// This enables callers to fire callbacks only when a session is first created.
#[derive(Debug)]
pub enum RegisterResult {
    /// A new session was created
    Created(Arc<Session>),
    /// An existing session was updated (touched + endpoint updated)
    Updated(Arc<Session>),
}

impl RegisterResult {
    /// Get a reference to the session
    #[inline]
    #[must_use]
    pub fn session(&self) -> &Arc<Session> {
        match self {
            Self::Created(s) | Self::Updated(s) => s,
        }
    }

    /// Check if this was a new session creation
    #[inline]
    #[must_use]
    pub fn is_new(&self) -> bool {
        matches!(self, Self::Created(_))
    }

    /// Check if this was an update to an existing session
    #[inline]
    #[must_use]
    pub fn is_update(&self) -> bool {
        matches!(self, Self::Updated(_))
    }

    /// Consume the result and return the session
    #[inline]
    #[must_use]
    pub fn into_session(self) -> Arc<Session> {
        match self {
            Self::Created(s) | Self::Updated(s) => s,
        }
    }
}

// =============================================================================
// Session Tracker
// =============================================================================

/// Configuration for the session tracker
#[derive(Debug, Clone)]
pub struct SessionTrackerConfig {
    /// Maximum sessions per peer
    pub max_per_peer: usize,
    /// Maximum total sessions
    pub max_total: usize,
    /// Maximum session creation rate per peer per second
    pub max_rate_per_peer: usize,
    /// Rate limit window duration
    pub rate_window: Duration,
}

impl Default for SessionTrackerConfig {
    fn default() -> Self {
        Self {
            max_per_peer: MAX_SESSIONS_PER_PEER,
            max_total: MAX_TOTAL_SESSIONS,
            max_rate_per_peer: super::config::MAX_SESSIONS_PER_PEER_PER_SECOND,
            rate_window: Duration::from_secs(super::config::RATE_LIMIT_WINDOW_SECS),
        }
    }
}

/// Thread-safe session tracker
///
/// Provides lookup by 5-tuple for routing reply packets back to the
/// correct WireGuard peer.
///
/// # Thread Safety
///
/// All operations are thread-safe and lock-free using `DashMap`.
///
/// # Performance
///
/// Uses ahash instead of SipHash for 2-3x faster lookups on the hot path.
pub struct SessionTracker {
    // Note: Manually implement Debug to avoid printing all session data
    /// Forward index: client 5-tuple -> session info
    sessions: AHashMap<FiveTuple, Arc<Session>>,
    /// Session ID -> 5-tuple reverse index for ID-based lookup
    id_index: AHashMap<SessionId, FiveTuple>,
    /// Session ID generator
    id_generator: SessionIdGenerator,
    /// Per-peer session counts for rate limiting
    peer_session_counts: AHashMap<[u8; 32], AtomicU64>,
    /// Per-peer rate limiting: peer_key -> (window_start, count)
    peer_rate_limits: AHashMap<[u8; 32], Mutex<(Instant, usize)>>,
    /// Configuration
    config: SessionTrackerConfig,
}

impl SessionTracker {
    /// Create a new session tracker with default configuration
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(SessionTrackerConfig::default())
    }

    /// Create a new session tracker with custom configuration
    #[must_use]
    pub fn with_config(config: SessionTrackerConfig) -> Self {
        Self {
            sessions: DashMap::with_hasher(RandomState::new()),
            id_index: DashMap::with_hasher(RandomState::new()),
            id_generator: SessionIdGenerator::new(),
            peer_session_counts: DashMap::with_hasher(RandomState::new()),
            peer_rate_limits: DashMap::with_hasher(RandomState::new()),
            config,
        }
    }

    /// Register a new session
    ///
    /// # Arguments
    ///
    /// * `peer_key` - WireGuard peer public key
    /// * `peer_endpoint` - Peer's WireGuard endpoint (IP:port) for reply routing
    /// * `five_tuple` - Client's 5-tuple
    /// * `outbound_tag` - Outbound tag for routing
    ///
    /// # Returns
    ///
    /// `Ok(session)` if registration succeeded, `Err` if limits exceeded.
    pub fn register(
        &self,
        peer_key: [u8; 32],
        peer_endpoint: SocketAddr,
        five_tuple: FiveTuple,
        outbound_tag: String,
    ) -> Result<Arc<Session>, SessionError> {
        // Check if session already exists (common for ongoing connections)
        if let Some(existing) = self.sessions.get(&five_tuple) {
            // Update last_active on existing session
            existing.touch();
            // Update peer endpoint in case of NAT rebinding/roaming
            existing.update_peer_endpoint(peer_endpoint);
            return Ok(Arc::clone(existing.value()));
        }

        // Check rate limit
        if !self.check_rate_limit(&peer_key) {
            return Err(SessionError::RateLimitExceeded {
                limit: self.config.max_rate_per_peer,
            });
        }

        // Check per-peer limit
        let count = self
            .peer_session_counts
            .entry(peer_key)
            .or_insert_with(|| AtomicU64::new(0));

        let current = count.fetch_add(1, Ordering::SeqCst);
        if current >= self.config.max_per_peer as u64 {
            count.fetch_sub(1, Ordering::SeqCst);
            return Err(SessionError::PerPeerLimitExceeded {
                peer: hex::encode(&peer_key[..8]),
                limit: self.config.max_per_peer,
            });
        }

        // Check total limit
        if self.sessions.len() >= self.config.max_total {
            count.fetch_sub(1, Ordering::SeqCst);
            return Err(SessionError::TotalLimitExceeded {
                limit: self.config.max_total,
            });
        }

        let session_id = self.id_generator.next();
        let session = Arc::new(Session::new(
            session_id,
            peer_key,
            peer_endpoint,
            five_tuple,
            outbound_tag.clone(),
        ));

        self.sessions.insert(five_tuple, Arc::clone(&session));
        self.id_index.insert(session_id, five_tuple);

        trace!(
            session_id = %session_id,
            peer = hex::encode(&peer_key[..8]),
            peer_endpoint = %peer_endpoint,
            five_tuple = %five_tuple,
            outbound = %outbound_tag,
            "Session registered"
        );

        Ok(session)
    }

    /// Register a new session with a result indicating whether it was created or updated
    ///
    /// This method is identical to `register()` but returns a `RegisterResult` that
    /// distinguishes between creating a new session and updating an existing one.
    /// This enables callers to fire callbacks only when a session is first created.
    ///
    /// # Arguments
    ///
    /// * `peer_key` - WireGuard peer public key
    /// * `peer_endpoint` - Peer's WireGuard endpoint (IP:port) for reply routing
    /// * `five_tuple` - Client's 5-tuple
    /// * `outbound_tag` - Outbound tag for routing
    ///
    /// # Returns
    ///
    /// `Ok(RegisterResult::Created(session))` if a new session was created,
    /// `Ok(RegisterResult::Updated(session))` if an existing session was updated,
    /// `Err` if limits exceeded.
    pub fn register_with_result(
        &self,
        peer_key: [u8; 32],
        peer_endpoint: SocketAddr,
        five_tuple: FiveTuple,
        outbound_tag: String,
    ) -> Result<RegisterResult, SessionError> {
        // Check if session already exists (common for ongoing connections)
        if let Some(existing) = self.sessions.get(&five_tuple) {
            // Update last_active on existing session
            existing.touch();
            // Update peer endpoint in case of NAT rebinding/roaming
            existing.update_peer_endpoint(peer_endpoint);
            return Ok(RegisterResult::Updated(Arc::clone(existing.value())));
        }

        // Check rate limit
        if !self.check_rate_limit(&peer_key) {
            return Err(SessionError::RateLimitExceeded {
                limit: self.config.max_rate_per_peer,
            });
        }

        // Check per-peer limit
        let count = self
            .peer_session_counts
            .entry(peer_key)
            .or_insert_with(|| AtomicU64::new(0));

        let current = count.fetch_add(1, Ordering::SeqCst);
        if current >= self.config.max_per_peer as u64 {
            count.fetch_sub(1, Ordering::SeqCst);
            return Err(SessionError::PerPeerLimitExceeded {
                peer: hex::encode(&peer_key[..8]),
                limit: self.config.max_per_peer,
            });
        }

        // Check total limit
        if self.sessions.len() >= self.config.max_total {
            count.fetch_sub(1, Ordering::SeqCst);
            return Err(SessionError::TotalLimitExceeded {
                limit: self.config.max_total,
            });
        }

        let session_id = self.id_generator.next();
        let session = Arc::new(Session::new(
            session_id,
            peer_key,
            peer_endpoint,
            five_tuple,
            outbound_tag.clone(),
        ));

        self.sessions.insert(five_tuple, Arc::clone(&session));
        self.id_index.insert(session_id, five_tuple);

        trace!(
            session_id = %session_id,
            peer = hex::encode(&peer_key[..8]),
            peer_endpoint = %peer_endpoint,
            five_tuple = %five_tuple,
            outbound = %outbound_tag,
            "Session created (new)"
        );

        Ok(RegisterResult::Created(session))
    }

    /// Check rate limit for a peer
    fn check_rate_limit(&self, peer_key: &[u8; 32]) -> bool {
        let now = Instant::now();

        let entry = self
            .peer_rate_limits
            .entry(*peer_key)
            .or_insert_with(|| Mutex::new((now, 0)));

        let mut guard = entry.lock();
        let (window_start, count) = &mut *guard;

        if now.duration_since(*window_start) >= self.config.rate_window {
            // New window
            *window_start = now;
            *count = 1;
            true
        } else if *count < self.config.max_rate_per_peer {
            *count += 1;
            true
        } else {
            warn!(
                peer = hex::encode(&peer_key[..8]),
                limit = self.config.max_rate_per_peer,
                "Rate limit exceeded"
            );
            false
        }
    }

    /// Look up session by client 5-tuple
    #[must_use]
    pub fn lookup(&self, five_tuple: &FiveTuple) -> Option<Arc<Session>> {
        self.sessions.get(five_tuple).map(|r| Arc::clone(r.value()))
    }

    /// Look up session by ID
    #[must_use]
    pub fn lookup_by_id(&self, session_id: SessionId) -> Option<Arc<Session>> {
        self.id_index
            .get(&session_id)
            .and_then(|five_tuple| self.sessions.get(five_tuple.value()))
            .map(|r| Arc::clone(r.value()))
    }

    /// Look up session by reversed 5-tuple (for reply packets)
    ///
    /// When the kernel sends a reply packet, the source and destination
    /// are swapped compared to the original client packet.
    #[must_use]
    pub fn lookup_by_reply(&self, reply_tuple: &FiveTuple) -> Option<Arc<Session>> {
        let forward_tuple = reply_tuple.reverse();
        self.lookup(&forward_tuple)
    }

    /// Remove a session by 5-tuple
    ///
    /// # Returns
    ///
    /// The removed session if it existed.
    pub fn remove(&self, five_tuple: &FiveTuple) -> Option<Arc<Session>> {
        if let Some((_, session)) = self.sessions.remove(five_tuple) {
            // Remove from ID index
            self.id_index.remove(&session.id);

            // Decrement peer count
            if let Some(count) = self.peer_session_counts.get(&session.peer_key) {
                count.fetch_sub(1, Ordering::SeqCst);
            }

            debug!(
                session_id = %session.id,
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

    /// Remove a session by ID
    pub fn remove_by_id(&self, session_id: SessionId) -> Option<Arc<Session>> {
        if let Some((_, five_tuple)) = self.id_index.remove(&session_id) {
            self.remove(&five_tuple)
        } else {
            None
        }
    }

    /// Get session count for a peer
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
            .filter(|entry| entry.value().is_tcp())
            .count()
    }

    /// Get UDP session count
    #[must_use]
    pub fn udp_session_count(&self) -> usize {
        self.sessions
            .iter()
            .filter(|entry| entry.value().is_udp())
            .count()
    }

    /// Iterate over all sessions
    pub fn for_each<F>(&self, mut f: F)
    where
        F: FnMut(&Arc<Session>),
    {
        for entry in self.sessions.iter() {
            f(entry.value());
        }
    }

    /// Remove sessions that match a predicate
    ///
    /// # Returns
    ///
    /// The number of sessions removed.
    pub fn remove_if<F>(&self, mut predicate: F) -> usize
    where
        F: FnMut(&Session) -> bool,
    {
        let mut to_remove = Vec::new();

        // Collect sessions to remove
        for entry in self.sessions.iter() {
            if predicate(entry.value()) {
                to_remove.push(*entry.key());
            }
        }

        // Remove them
        let removed = to_remove.len();
        for five_tuple in to_remove {
            self.remove(&five_tuple);
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
            let timeout = if session.is_tcp() {
                tcp_timeout
            } else {
                udp_timeout
            };
            session.idle_time() > timeout
        })
    }

    /// Get tracker statistics
    #[must_use]
    pub fn stats(&self) -> SessionTrackerStats {
        SessionTrackerStats {
            total_sessions: self.total_sessions(),
            tcp_sessions: self.tcp_session_count(),
            udp_sessions: self.udp_session_count(),
            unique_peers: self.peer_session_counts.len(),
        }
    }
}

impl Default for SessionTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for SessionTracker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionTracker")
            .field("total_sessions", &self.sessions.len())
            .field("unique_peers", &self.peer_session_counts.len())
            .field("config", &self.config)
            .finish()
    }
}

// =============================================================================
// Session Errors
// =============================================================================

/// Errors that can occur during session operations
#[derive(Debug, Clone, thiserror::Error)]
pub enum SessionError {
    /// Total session limit exceeded
    #[error("total session limit exceeded: max {limit} sessions")]
    TotalLimitExceeded {
        /// The limit that was exceeded
        limit: usize,
    },

    /// Per-peer session limit exceeded
    #[error("per-peer session limit exceeded for {peer}: max {limit} sessions")]
    PerPeerLimitExceeded {
        /// Short peer key hex
        peer: String,
        /// The limit that was exceeded
        limit: usize,
    },

    /// Rate limit exceeded
    #[error("session creation rate limit exceeded: max {limit} per second")]
    RateLimitExceeded {
        /// The limit that was exceeded
        limit: usize,
    },

    /// Session not found
    #[error("session not found: {0}")]
    NotFound(String),
}

// =============================================================================
// Statistics
// =============================================================================

/// Session tracker statistics
#[derive(Debug, Clone, Default)]
pub struct SessionTrackerStats {
    /// Total active sessions
    pub total_sessions: usize,
    /// TCP sessions
    pub tcp_sessions: usize,
    /// UDP sessions
    pub udp_sessions: usize,
    /// Unique peers with sessions
    pub unique_peers: usize,
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
    fn test_session_creation() {
        let session = Session::new(
            SessionId::new(1),
            [0u8; 32],
            test_peer_endpoint(),
            make_test_tuple(12345, 80),
            "direct".to_string(),
        );

        assert_eq!(session.id.as_u64(), 1);
        assert!(session.is_tcp());
        assert!(!session.is_udp());
        assert_eq!(session.total_bytes_sent(), 0);
        assert_eq!(session.total_bytes_received(), 0);
    }

    #[test]
    fn test_session_stats() {
        let session = Session::new(
            SessionId::new(1),
            [0u8; 32],
            test_peer_endpoint(),
            make_test_tuple(12345, 80),
            "direct".to_string(),
        );

        session.add_bytes_sent(100);
        session.add_bytes_sent(200);
        assert_eq!(session.total_bytes_sent(), 300);
        assert_eq!(session.total_packets_sent(), 2);

        session.add_bytes_received(500);
        assert_eq!(session.total_bytes_received(), 500);
        assert_eq!(session.total_packets_received(), 1);
    }

    #[test]
    fn test_session_endpoint_update() {
        let session = Session::new(
            SessionId::new(1),
            [0u8; 32],
            test_peer_endpoint(),
            make_test_tuple(12345, 80),
            "direct".to_string(),
        );

        let new_endpoint = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200)), 51820);
        assert!(session.update_peer_endpoint(new_endpoint));
        assert_eq!(session.peer_endpoint(), new_endpoint);

        // Same endpoint should return false
        assert!(!session.update_peer_endpoint(new_endpoint));
    }

    #[test]
    fn test_tracker_basic() {
        let tracker = SessionTracker::new();
        let peer_key = [0u8; 32];
        let peer_endpoint = test_peer_endpoint();
        let five_tuple = make_test_tuple(12345, 80);

        let session = tracker
            .register(peer_key, peer_endpoint, five_tuple, "direct".to_string())
            .unwrap();
        assert_eq!(session.id.as_u64(), 1);

        let found = tracker.lookup(&five_tuple).unwrap();
        assert_eq!(found.id, session.id);

        assert_eq!(tracker.total_sessions(), 1);
        assert_eq!(tracker.peer_session_count(&peer_key), 1);
    }

    #[test]
    fn test_tracker_lookup_by_id() {
        let tracker = SessionTracker::new();
        let peer_key = [0u8; 32];
        let peer_endpoint = test_peer_endpoint();
        let five_tuple = make_test_tuple(12345, 80);

        let session = tracker
            .register(peer_key, peer_endpoint, five_tuple, "direct".to_string())
            .unwrap();

        let found = tracker.lookup_by_id(session.id).unwrap();
        assert_eq!(found.five_tuple, five_tuple);
    }

    #[test]
    fn test_tracker_lookup_by_reply() {
        let tracker = SessionTracker::new();
        let peer_key = [0u8; 32];
        let peer_endpoint = test_peer_endpoint();
        let five_tuple = make_test_tuple(12345, 80);

        tracker
            .register(peer_key, peer_endpoint, five_tuple, "direct".to_string())
            .unwrap();

        // Create a reply tuple (reversed)
        let reply_tuple = five_tuple.reverse();
        let found = tracker.lookup_by_reply(&reply_tuple).unwrap();
        assert_eq!(found.five_tuple, five_tuple);
    }

    #[test]
    fn test_tracker_remove() {
        let tracker = SessionTracker::new();
        let peer_key = [2u8; 32];
        let peer_endpoint = test_peer_endpoint();
        let five_tuple = make_test_tuple(12345, 80);

        let session = tracker
            .register(peer_key, peer_endpoint, five_tuple, "direct".to_string())
            .unwrap();
        assert_eq!(tracker.total_sessions(), 1);

        let removed = tracker.remove(&five_tuple).unwrap();
        assert_eq!(removed.id, session.id);
        assert_eq!(tracker.total_sessions(), 0);
        assert_eq!(tracker.peer_session_count(&peer_key), 0);

        // lookup_by_id should also fail now
        assert!(tracker.lookup_by_id(session.id).is_none());
    }

    #[test]
    fn test_tracker_remove_by_id() {
        let tracker = SessionTracker::new();
        let peer_key = [0u8; 32];
        let peer_endpoint = test_peer_endpoint();
        let five_tuple = make_test_tuple(12345, 80);

        let session = tracker
            .register(peer_key, peer_endpoint, five_tuple, "direct".to_string())
            .unwrap();

        let removed = tracker.remove_by_id(session.id).unwrap();
        assert_eq!(removed.five_tuple, five_tuple);
        assert_eq!(tracker.total_sessions(), 0);
    }

    #[test]
    fn test_tracker_per_peer_limit() {
        let config = SessionTrackerConfig {
            max_per_peer: 2,
            max_total: 100,
            ..Default::default()
        };
        let tracker = SessionTracker::with_config(config);
        let peer_key = [0u8; 32];
        let peer_endpoint = test_peer_endpoint();

        let tuple1 = make_test_tuple(12345, 80);
        let tuple2 = make_test_tuple(12346, 443);
        let tuple3 = make_test_tuple(12347, 8080);

        assert!(tracker.register(peer_key, peer_endpoint, tuple1, "direct".to_string()).is_ok());
        assert!(tracker.register(peer_key, peer_endpoint, tuple2, "direct".to_string()).is_ok());

        // Third should fail
        let result = tracker.register(peer_key, peer_endpoint, tuple3, "direct".to_string());
        assert!(matches!(result, Err(SessionError::PerPeerLimitExceeded { .. })));
    }

    #[test]
    fn test_tracker_total_limit() {
        let config = SessionTrackerConfig {
            max_per_peer: 100,
            max_total: 2,
            ..Default::default()
        };
        let tracker = SessionTracker::with_config(config);
        let peer_endpoint = test_peer_endpoint();

        let peer1 = [1u8; 32];
        let peer2 = [2u8; 32];
        let peer3 = [3u8; 32];

        let tuple1 = make_test_tuple(12345, 80);
        let tuple2 = make_test_tuple(12346, 443);
        let tuple3 = make_test_tuple(12347, 8080);

        assert!(tracker.register(peer1, peer_endpoint, tuple1, "direct".to_string()).is_ok());
        assert!(tracker.register(peer2, peer_endpoint, tuple2, "direct".to_string()).is_ok());

        // Third should fail
        let result = tracker.register(peer3, peer_endpoint, tuple3, "direct".to_string());
        assert!(matches!(result, Err(SessionError::TotalLimitExceeded { .. })));
    }

    #[test]
    fn test_tracker_cleanup_idle() {
        let tracker = SessionTracker::new();
        let peer_key = [0u8; 32];
        let peer_endpoint = test_peer_endpoint();
        let five_tuple = make_test_tuple(12345, 80);

        tracker.register(peer_key, peer_endpoint, five_tuple, "direct".to_string()).unwrap();

        // Immediately cleaning with 0 timeout should remove it
        let removed = tracker.cleanup_idle(Duration::ZERO, Duration::ZERO);
        assert_eq!(removed, 1);
        assert_eq!(tracker.total_sessions(), 0);
    }

    #[test]
    fn test_tracker_stats() {
        let tracker = SessionTracker::new();
        let peer1 = [1u8; 32];
        let peer2 = [2u8; 32];
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

        tracker.register(peer1, peer_endpoint, tcp1, "direct".to_string()).unwrap();
        tracker.register(peer1, peer_endpoint, tcp2, "direct".to_string()).unwrap();
        tracker.register(peer2, peer_endpoint, udp1, "direct".to_string()).unwrap();

        let stats = tracker.stats();
        assert_eq!(stats.total_sessions, 3);
        assert_eq!(stats.tcp_sessions, 2);
        assert_eq!(stats.udp_sessions, 1);
        assert_eq!(stats.unique_peers, 2);
    }

    #[test]
    fn test_session_reuse() {
        let tracker = SessionTracker::new();
        let peer_key = [0u8; 32];
        let peer_endpoint1 = test_peer_endpoint();
        let peer_endpoint2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200)), 51820);
        let five_tuple = make_test_tuple(12345, 80);

        // First registration
        let session1 = tracker
            .register(peer_key, peer_endpoint1, five_tuple, "direct".to_string())
            .unwrap();

        // Second registration should return same session with updated endpoint
        let session2 = tracker
            .register(peer_key, peer_endpoint2, five_tuple, "direct".to_string())
            .unwrap();

        assert_eq!(session1.id, session2.id);
        assert_eq!(session2.peer_endpoint(), peer_endpoint2);
        assert_eq!(tracker.total_sessions(), 1); // Still just one session
    }

    #[test]
    fn test_register_result_methods() {
        let session = Arc::new(Session::new(
            SessionId::new(1),
            [0u8; 32],
            test_peer_endpoint(),
            make_test_tuple(12345, 80),
            "direct".to_string(),
        ));

        let created = RegisterResult::Created(Arc::clone(&session));
        assert!(created.is_new());
        assert!(!created.is_update());
        assert_eq!(created.session().id, SessionId::new(1));

        let updated = RegisterResult::Updated(Arc::clone(&session));
        assert!(!updated.is_new());
        assert!(updated.is_update());
        assert_eq!(updated.session().id, SessionId::new(1));
    }

    #[test]
    fn test_register_result_into_session() {
        let session = Arc::new(Session::new(
            SessionId::new(42),
            [0u8; 32],
            test_peer_endpoint(),
            make_test_tuple(12345, 80),
            "direct".to_string(),
        ));

        let created = RegisterResult::Created(Arc::clone(&session));
        let consumed = created.into_session();
        assert_eq!(consumed.id, SessionId::new(42));
    }

    #[test]
    fn test_register_with_result_new_session() {
        let tracker = SessionTracker::new();
        let peer_key = [0u8; 32];
        let peer_endpoint = test_peer_endpoint();
        let five_tuple = make_test_tuple(12345, 80);

        let result = tracker
            .register_with_result(peer_key, peer_endpoint, five_tuple, "direct".to_string())
            .unwrap();

        assert!(result.is_new());
        assert!(!result.is_update());
        assert_eq!(result.session().id.as_u64(), 1);
        assert_eq!(tracker.total_sessions(), 1);
    }

    #[test]
    fn test_register_with_result_update_session() {
        let tracker = SessionTracker::new();
        let peer_key = [0u8; 32];
        let peer_endpoint1 = test_peer_endpoint();
        let peer_endpoint2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200)), 51820);
        let five_tuple = make_test_tuple(12345, 80);

        // First registration creates a new session
        let result1 = tracker
            .register_with_result(peer_key, peer_endpoint1, five_tuple, "direct".to_string())
            .unwrap();
        assert!(result1.is_new());
        let session_id = result1.session().id;

        // Second registration should update existing session
        let result2 = tracker
            .register_with_result(peer_key, peer_endpoint2, five_tuple, "direct".to_string())
            .unwrap();
        assert!(result2.is_update());
        assert!(!result2.is_new());

        // Same session ID
        assert_eq!(result2.session().id, session_id);
        // Endpoint updated
        assert_eq!(result2.session().peer_endpoint(), peer_endpoint2);
        // Still just one session
        assert_eq!(tracker.total_sessions(), 1);
    }

    #[test]
    fn test_register_with_result_rate_limit() {
        let config = SessionTrackerConfig {
            max_rate_per_peer: 1,
            rate_window: Duration::from_secs(60),
            ..Default::default()
        };
        let tracker = SessionTracker::with_config(config);
        let peer_key = [0u8; 32];
        let peer_endpoint = test_peer_endpoint();

        let tuple1 = make_test_tuple(12345, 80);
        let tuple2 = make_test_tuple(12346, 443);

        // First should succeed
        let result1 = tracker.register_with_result(
            peer_key,
            peer_endpoint,
            tuple1,
            "direct".to_string(),
        );
        assert!(result1.is_ok());
        assert!(result1.unwrap().is_new());

        // Second should fail (rate limit)
        let result2 = tracker.register_with_result(
            peer_key,
            peer_endpoint,
            tuple2,
            "direct".to_string(),
        );
        assert!(matches!(result2, Err(SessionError::RateLimitExceeded { .. })));
    }
}
