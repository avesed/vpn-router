//! Session tracking for smoltcp bridge implementations
//!
//! This module provides session tracking utilities for bridges that convert
//! between TCP/UDP streams and IP packets using smoltcp.
//!
//! # Architecture
//!
//! ```text
//! ┌───────────────────────────────────────────────────────────────────┐
//! │                     SessionTracker                                │
//! ├───────────────────────────────────────────────────────────────────┤
//! │                                                                   │
//! │  PortAllocator ─────────────────────────────────────────────────┐ │
//! │  │ - Manages ephemeral port allocation                          │ │
//! │  │ - Tracks TIME_WAIT ports                                     │ │
//! │  └──────────────────────────────────────────────────────────────┘ │
//! │                                                                   │
//! │  TCP Sessions (DashMap) ────────────────────────────────────────┐ │
//! │  │ Key: SessionKey (local_ip:port -> remote_ip:port)            │ │
//! │  │ Value: TcpSession (handle, stats, state)                     │ │
//! │  └──────────────────────────────────────────────────────────────┘ │
//! │                                                                   │
//! │  UDP Sessions (DashMap) ────────────────────────────────────────┐ │
//! │  │ Key: SessionKey                                              │ │
//! │  │ Value: UdpSession (handle, stats, timeout)                   │ │
//! │  └──────────────────────────────────────────────────────────────┘ │
//! │                                                                   │
//! │  Indices (DashMap) ─────────────────────────────────────────────┐ │
//! │  │ - handle_to_session: SocketHandle -> SessionKey              │ │
//! │  │ - client_session_count: ConnectionId -> count                │ │
//! │  └──────────────────────────────────────────────────────────────┘ │
//! │                                                                   │
//! └───────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Usage
//!
//! ```ignore
//! use rust_router::smoltcp_utils::{SessionTracker, SessionKey, ConnectionId};
//!
//! // Create tracker
//! let tracker = SessionTracker::new();
//!
//! // Allocate a port
//! let port_guard = tracker.allocate_port().expect("port available");
//! let local_port = port_guard.take(); // Take ownership
//!
//! // Create session key
//! let session_key = SessionKey::new(local_ip, local_port, remote_ip, remote_port);
//!
//! // Register TCP session
//! let connection_id = ConnectionId::new(client_addr);
//! let session = tracker.register_tcp(connection_id, socket_handle, session_key)?;
//! ```
//!
//! # Thread Safety
//!
//! `SessionTracker` uses `DashMap` for lock-free concurrent access.
//! All operations are thread-safe and can be called from multiple async tasks.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use smoltcp::iface::SocketHandle;
use tracing::{debug, warn};

use super::config::{
    MAX_SESSIONS_PER_CLIENT, MAX_SESSIONS_PER_CLIENT_PER_SECOND, MAX_TOTAL_SESSIONS,
    RATE_LIMIT_WINDOW_SECS, TCP_IDLE_TIMEOUT_SECS, UDP_DEFAULT_TIMEOUT_SECS, UDP_DNS_TIMEOUT_SECS,
};
use super::error::{BridgeError, Result};
use super::port_allocator::{PortAllocator, PortAllocatorConfig, PortGuard};

/// Unique identifier for a connection/client
///
/// Used to track per-client session limits and correlate sessions
/// with their originating client.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ConnectionId {
    /// Unique ID generated from client address
    id: u64,
    /// Original client address (for debugging/logging)
    client_addr: SocketAddr,
}

impl ConnectionId {
    /// Create a new connection ID from a client address
    ///
    /// Uses monotonic counter to ensure uniqueness even if the same
    /// client address connects multiple times.
    #[must_use]
    pub fn new(client_addr: SocketAddr) -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);

        Self { id, client_addr }
    }

    /// Create a connection ID from an existing ID value
    ///
    /// Used when reconstructing IDs from serialized data.
    #[must_use]
    pub fn from_id(id: u64, client_addr: SocketAddr) -> Self {
        Self { id, client_addr }
    }

    /// Get the unique ID
    #[must_use]
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Get the client address
    #[must_use]
    pub fn client_addr(&self) -> SocketAddr {
        self.client_addr
    }
}

impl std::fmt::Display for ConnectionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "conn-{}-{}", self.id, self.client_addr)
    }
}

/// Key identifying a unique session (5-tuple without protocol)
///
/// Used to track sessions in the session maps. The key uniquely identifies
/// a bidirectional flow between local and remote endpoints.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SessionKey {
    /// Local IP address
    pub local_ip: IpAddr,
    /// Local port
    pub local_port: u16,
    /// Remote IP address
    pub remote_ip: IpAddr,
    /// Remote port
    pub remote_port: u16,
}

impl SessionKey {
    /// Create a new session key
    #[must_use]
    pub fn new(local_ip: IpAddr, local_port: u16, remote_ip: IpAddr, remote_port: u16) -> Self {
        Self {
            local_ip,
            local_port,
            remote_ip,
            remote_port,
        }
    }

    /// Create the reverse key (for reply matching)
    #[must_use]
    pub fn reverse(&self) -> Self {
        Self {
            local_ip: self.remote_ip,
            local_port: self.remote_port,
            remote_ip: self.local_ip,
            remote_port: self.local_port,
        }
    }
}

impl std::fmt::Display for SessionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{} -> {}:{}",
            self.local_ip, self.local_port, self.remote_ip, self.remote_port
        )
    }
}

/// Statistics for a session
#[derive(Debug)]
pub struct SessionStats {
    /// Bytes sent (to remote)
    pub bytes_tx: AtomicU64,
    /// Bytes received (from remote)
    pub bytes_rx: AtomicU64,
    /// Packets sent
    pub packets_tx: AtomicU64,
    /// Packets received
    pub packets_rx: AtomicU64,
    /// Session start time
    pub created_at: Instant,
    /// Last activity time
    pub last_activity: AtomicU64,
}

impl Default for SessionStats {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionStats {
    /// Create new session statistics
    #[must_use]
    pub fn new() -> Self {
        let now = Instant::now();
        Self {
            bytes_tx: AtomicU64::new(0),
            bytes_rx: AtomicU64::new(0),
            packets_tx: AtomicU64::new(0),
            packets_rx: AtomicU64::new(0),
            created_at: now,
            last_activity: AtomicU64::new(0),
        }
    }

    /// Record bytes sent
    pub fn record_tx(&self, bytes: usize) {
        self.bytes_tx.fetch_add(bytes as u64, Ordering::Relaxed);
        self.packets_tx.fetch_add(1, Ordering::Relaxed);
        self.touch();
    }

    /// Record bytes received
    pub fn record_rx(&self, bytes: usize) {
        self.bytes_rx.fetch_add(bytes as u64, Ordering::Relaxed);
        self.packets_rx.fetch_add(1, Ordering::Relaxed);
        self.touch();
    }

    /// Update last activity timestamp
    fn touch(&self) {
        let elapsed = self.created_at.elapsed().as_secs();
        self.last_activity.store(elapsed, Ordering::Relaxed);
    }

    /// Get the age of this session in seconds
    #[must_use]
    pub fn age_secs(&self) -> u64 {
        self.created_at.elapsed().as_secs()
    }

    /// Get seconds since last activity
    #[must_use]
    pub fn idle_secs(&self) -> u64 {
        let age = self.age_secs();
        let last = self.last_activity.load(Ordering::Relaxed);
        age.saturating_sub(last)
    }

    /// Get a snapshot of the statistics
    #[must_use]
    pub fn snapshot(&self) -> SessionStatsSnapshot {
        SessionStatsSnapshot {
            bytes_tx: self.bytes_tx.load(Ordering::Relaxed),
            bytes_rx: self.bytes_rx.load(Ordering::Relaxed),
            packets_tx: self.packets_tx.load(Ordering::Relaxed),
            packets_rx: self.packets_rx.load(Ordering::Relaxed),
            age_secs: self.age_secs(),
            idle_secs: self.idle_secs(),
        }
    }
}

/// Snapshot of session statistics (for serialization)
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct SessionStatsSnapshot {
    /// Bytes sent (to remote)
    pub bytes_tx: u64,
    /// Bytes received (from remote)
    pub bytes_rx: u64,
    /// Packets sent
    pub packets_tx: u64,
    /// Packets received
    pub packets_rx: u64,
    /// Session age in seconds
    pub age_secs: u64,
    /// Seconds since last activity
    pub idle_secs: u64,
}

/// Configuration for session timeouts
#[derive(Debug, Clone)]
pub struct TimeoutConfig {
    /// TCP idle timeout
    pub tcp_idle: Duration,
    /// UDP default timeout
    pub udp_default: Duration,
    /// UDP DNS timeout (shorter for DNS queries)
    pub udp_dns: Duration,
}

impl Default for TimeoutConfig {
    fn default() -> Self {
        Self {
            tcp_idle: Duration::from_secs(TCP_IDLE_TIMEOUT_SECS),
            udp_default: Duration::from_secs(UDP_DEFAULT_TIMEOUT_SECS),
            udp_dns: Duration::from_secs(UDP_DNS_TIMEOUT_SECS),
        }
    }
}

/// Rate limit entry for tracking session creation rate per client
#[derive(Debug)]
struct RateLimitEntry {
    /// Start of the current rate window
    window_start: Instant,
    /// Number of sessions created in the current window
    count: usize,
}

impl RateLimitEntry {
    /// Create a new rate limit entry starting now
    fn new() -> Self {
        Self {
            window_start: Instant::now(),
            count: 1,
        }
    }

    /// Check if the current window has expired
    fn is_window_expired(&self) -> bool {
        self.window_start.elapsed() >= Duration::from_secs(RATE_LIMIT_WINDOW_SECS)
    }

    /// Increment the count or reset if window expired
    /// Returns the current count after increment
    fn increment(&mut self) -> usize {
        if self.is_window_expired() {
            // Reset the window
            self.window_start = Instant::now();
            self.count = 1;
        } else {
            self.count += 1;
        }
        self.count
    }
}

/// TCP session state
#[derive(Debug)]
pub struct TcpSession {
    /// smoltcp socket handle
    pub handle: SocketHandle,
    /// Session key
    pub key: SessionKey,
    /// Connection ID (client identifier)
    pub connection_id: ConnectionId,
    /// Session statistics
    pub stats: SessionStats,
}

impl TcpSession {
    /// Create a new TCP session
    #[must_use]
    pub fn new(handle: SocketHandle, key: SessionKey, connection_id: ConnectionId) -> Self {
        Self {
            handle,
            key,
            connection_id,
            stats: SessionStats::new(),
        }
    }
}

/// UDP session state
#[derive(Debug)]
pub struct UdpSession {
    /// smoltcp socket handle
    pub handle: SocketHandle,
    /// Session key
    pub key: SessionKey,
    /// Connection ID (client identifier)
    pub connection_id: ConnectionId,
    /// Session statistics
    pub stats: SessionStats,
    /// Whether this is a DNS session (port 53)
    pub is_dns: bool,
}

impl UdpSession {
    /// Create a new UDP session
    #[must_use]
    pub fn new(handle: SocketHandle, key: SessionKey, connection_id: ConnectionId) -> Self {
        let is_dns = key.remote_port == 53;
        Self {
            handle,
            key,
            connection_id,
            stats: SessionStats::new(),
            is_dns,
        }
    }

    /// Get the timeout for this session
    #[must_use]
    pub fn timeout(&self, config: &TimeoutConfig) -> Duration {
        if self.is_dns {
            config.udp_dns
        } else {
            config.udp_default
        }
    }

    /// Check if this session is expired
    #[must_use]
    pub fn is_expired(&self, config: &TimeoutConfig) -> bool {
        let timeout = self.timeout(config);
        Duration::from_secs(self.stats.idle_secs()) > timeout
    }
}

/// Session tracker for managing bridge sessions
///
/// Thread-safe session management with:
/// - Port allocation with TIME_WAIT tracking
/// - TCP and UDP session tracking
/// - Per-client session limits
/// - Session creation rate limiting
/// - Session timeout tracking
pub struct SessionTracker {
    /// Port allocator
    port_allocator: PortAllocator,
    /// TCP sessions by key
    tcp_sessions: DashMap<SessionKey, TcpSession>,
    /// UDP sessions by key
    udp_sessions: DashMap<SessionKey, UdpSession>,
    /// Socket handle to session key mapping (for reverse lookup)
    handle_to_session: DashMap<SocketHandle, SessionKey>,
    /// Per-client session count
    client_session_count: DashMap<u64, usize>,
    /// Per-client session creation rate tracking
    client_session_rate: DashMap<u64, RateLimitEntry>,
    /// Timeout configuration
    timeout_config: TimeoutConfig,
}

impl SessionTracker {
    /// Create a new session tracker with default configuration
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(PortAllocatorConfig::default(), TimeoutConfig::default())
    }

    /// Create a new session tracker with a specific port allocator
    #[must_use]
    pub fn with_port_allocator(port_allocator: PortAllocator) -> Self {
        Self {
            port_allocator,
            tcp_sessions: DashMap::new(),
            udp_sessions: DashMap::new(),
            handle_to_session: DashMap::new(),
            client_session_count: DashMap::new(),
            client_session_rate: DashMap::new(),
            timeout_config: TimeoutConfig::default(),
        }
    }

    /// Create a new session tracker with custom configuration
    #[must_use]
    pub fn with_config(port_config: PortAllocatorConfig, timeout_config: TimeoutConfig) -> Self {
        Self {
            port_allocator: PortAllocator::with_config(port_config),
            tcp_sessions: DashMap::new(),
            udp_sessions: DashMap::new(),
            handle_to_session: DashMap::new(),
            client_session_count: DashMap::new(),
            client_session_rate: DashMap::new(),
            timeout_config,
        }
    }

    /// Get a reference to the port allocator
    #[must_use]
    pub fn port_allocator(&self) -> &PortAllocator {
        &self.port_allocator
    }

    /// Allocate a port, returning a RAII guard
    pub fn allocate_port(&self) -> Option<PortGuard<'_>> {
        self.port_allocator.allocate()
    }

    /// Return a port to the allocator (enters TIME_WAIT)
    pub fn return_port(&self, port: u16) {
        self.port_allocator.release(port);
    }

    /// Check if we can create a new session for a client
    fn check_limits(&self, connection_id: &ConnectionId) -> Result<()> {
        // Check total session count
        let total = self.tcp_sessions.len() + self.udp_sessions.len();
        if total >= MAX_TOTAL_SESSIONS {
            return Err(BridgeError::SessionLimitReached(MAX_TOTAL_SESSIONS));
        }

        // Check per-client limit
        let client_count = self
            .client_session_count
            .get(&connection_id.id())
            .map(|r| *r)
            .unwrap_or(0);
        if client_count >= MAX_SESSIONS_PER_CLIENT {
            return Err(BridgeError::PerClientSessionLimitReached(
                MAX_SESSIONS_PER_CLIENT,
            ));
        }

        // Check rate limit
        self.check_rate_limit(connection_id)?;

        Ok(())
    }

    /// Check if the client is creating sessions too fast
    fn check_rate_limit(&self, connection_id: &ConnectionId) -> Result<()> {
        let client_id = connection_id.id();

        // Try to get existing entry or create a new one
        let rate_count = self
            .client_session_rate
            .entry(client_id)
            .or_insert_with(RateLimitEntry::new)
            .increment();

        if rate_count > MAX_SESSIONS_PER_CLIENT_PER_SECOND {
            warn!(
                "Rate limit exceeded for client {}: {} sessions/sec (max {})",
                connection_id, rate_count, MAX_SESSIONS_PER_CLIENT_PER_SECOND
            );
            return Err(BridgeError::SessionRateLimitExceeded(
                MAX_SESSIONS_PER_CLIENT_PER_SECOND,
            ));
        }

        Ok(())
    }

    /// Increment the session count for a client
    fn increment_client_count(&self, connection_id: &ConnectionId) {
        self.client_session_count
            .entry(connection_id.id())
            .and_modify(|c| *c += 1)
            .or_insert(1);
    }

    /// Decrement the session count for a client
    fn decrement_client_count(&self, connection_id: &ConnectionId) {
        if let Some(mut entry) = self.client_session_count.get_mut(&connection_id.id()) {
            if *entry > 0 {
                *entry -= 1;
            }
            if *entry == 0 {
                drop(entry);
                self.client_session_count.remove(&connection_id.id());
            }
        }
    }

    /// Register a new TCP session
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Session limit is reached
    /// - Per-client limit is reached
    /// - Session key already exists
    pub fn register_tcp(
        &self,
        connection_id: ConnectionId,
        handle: SocketHandle,
        key: SessionKey,
    ) -> Result<()> {
        // Check limits first
        self.check_limits(&connection_id)?;

        // Check if session already exists
        if self.tcp_sessions.contains_key(&key) {
            return Err(BridgeError::SessionAlreadyExists(key.to_string()));
        }

        // Create and insert session
        let session = TcpSession::new(handle, key.clone(), connection_id.clone());
        self.tcp_sessions.insert(key.clone(), session);
        self.handle_to_session.insert(handle, key.clone());
        self.increment_client_count(&connection_id);

        debug!("Registered TCP session: {}", key);
        Ok(())
    }

    /// Register a new UDP session
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Session limit is reached
    /// - Per-client limit is reached
    /// - Session key already exists
    pub fn register_udp(
        &self,
        connection_id: ConnectionId,
        handle: SocketHandle,
        key: SessionKey,
    ) -> Result<()> {
        // Check limits first
        self.check_limits(&connection_id)?;

        // Check if session already exists
        if self.udp_sessions.contains_key(&key) {
            return Err(BridgeError::SessionAlreadyExists(key.to_string()));
        }

        // Create and insert session
        let session = UdpSession::new(handle, key.clone(), connection_id.clone());
        self.udp_sessions.insert(key.clone(), session);
        self.handle_to_session.insert(handle, key.clone());
        self.increment_client_count(&connection_id);

        debug!("Registered UDP session: {}", key);
        Ok(())
    }

    /// Remove a TCP session
    pub fn remove_tcp(&self, key: &SessionKey) -> Option<TcpSession> {
        if let Some((_, session)) = self.tcp_sessions.remove(key) {
            self.handle_to_session.remove(&session.handle);
            self.decrement_client_count(&session.connection_id);
            debug!("Removed TCP session: {}", key);
            Some(session)
        } else {
            None
        }
    }

    /// Remove a UDP session
    pub fn remove_udp(&self, key: &SessionKey) -> Option<UdpSession> {
        if let Some((_, session)) = self.udp_sessions.remove(key) {
            self.handle_to_session.remove(&session.handle);
            self.decrement_client_count(&session.connection_id);
            debug!("Removed UDP session: {}", key);
            Some(session)
        } else {
            None
        }
    }

    /// Get a TCP session by key
    #[must_use]
    pub fn get_tcp(&self, key: &SessionKey) -> Option<dashmap::mapref::one::Ref<'_, SessionKey, TcpSession>> {
        self.tcp_sessions.get(key)
    }

    /// Get a UDP session by key
    #[must_use]
    pub fn get_udp(&self, key: &SessionKey) -> Option<dashmap::mapref::one::Ref<'_, SessionKey, UdpSession>> {
        self.udp_sessions.get(key)
    }

    /// Get session key by socket handle
    #[must_use]
    pub fn get_key_by_handle(&self, handle: SocketHandle) -> Option<SessionKey> {
        self.handle_to_session.get(&handle).map(|r| r.clone())
    }

    /// Get the number of TCP sessions
    #[must_use]
    pub fn tcp_count(&self) -> usize {
        self.tcp_sessions.len()
    }

    /// Get the number of UDP sessions
    #[must_use]
    pub fn udp_count(&self) -> usize {
        self.udp_sessions.len()
    }

    /// Get the total session count
    #[must_use]
    pub fn total_count(&self) -> usize {
        self.tcp_count() + self.udp_count()
    }

    /// Get the number of sessions for a specific client
    #[must_use]
    pub fn client_count(&self, connection_id: &ConnectionId) -> usize {
        self.client_session_count
            .get(&connection_id.id())
            .map(|r| *r)
            .unwrap_or(0)
    }

    /// Find and remove expired UDP sessions
    ///
    /// Returns the list of expired session keys and their socket handles.
    pub fn expire_udp_sessions(&self) -> Vec<(SessionKey, SocketHandle, ConnectionId)> {
        let mut expired = Vec::new();

        self.udp_sessions.retain(|key, session| {
            if session.is_expired(&self.timeout_config) {
                expired.push((key.clone(), session.handle, session.connection_id.clone()));
                false
            } else {
                true
            }
        });

        // Clean up indices for expired sessions
        for (key, handle, connection_id) in &expired {
            self.handle_to_session.remove(handle);
            self.decrement_client_count(connection_id);
            debug!("Expired UDP session: {}", key);
        }

        expired
    }

    /// Find TCP sessions that have been idle too long
    ///
    /// Note: This doesn't remove them - TCP sessions should be closed
    /// gracefully by the bridge based on socket state.
    pub fn find_idle_tcp_sessions(&self) -> Vec<SessionKey> {
        let timeout = self.timeout_config.tcp_idle;
        let mut idle = Vec::new();

        for entry in self.tcp_sessions.iter() {
            if Duration::from_secs(entry.stats.idle_secs()) > timeout {
                idle.push(entry.key().clone());
            }
        }

        idle
    }

    /// Clear all sessions
    ///
    /// Used during shutdown.
    pub fn clear(&self) {
        let tcp_count = self.tcp_sessions.len();
        let udp_count = self.udp_sessions.len();

        self.tcp_sessions.clear();
        self.udp_sessions.clear();
        self.handle_to_session.clear();
        self.client_session_count.clear();
        self.client_session_rate.clear();

        if tcp_count > 0 || udp_count > 0 {
            warn!(
                "Cleared {} TCP and {} UDP sessions during shutdown",
                tcp_count, udp_count
            );
        }
    }

    /// Get the timeout configuration
    #[must_use]
    pub fn timeout_config(&self) -> &TimeoutConfig {
        &self.timeout_config
    }

    /// Get a snapshot of tracker statistics
    #[must_use]
    pub fn stats_snapshot(&self) -> TrackerStats {
        TrackerStats {
            tcp_sessions: self.tcp_count(),
            udp_sessions: self.udp_count(),
            ports_allocated: self.port_allocator.allocated_count(),
            ports_in_time_wait: self.port_allocator.time_wait_count(),
            client_count: self.client_session_count.len(),
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
            .field("tcp_sessions", &self.tcp_count())
            .field("udp_sessions", &self.udp_count())
            .field("ports_allocated", &self.port_allocator.allocated_count())
            .field("ports_time_wait", &self.port_allocator.time_wait_count())
            .finish()
    }
}

/// Snapshot of tracker statistics
#[derive(Debug, Clone, serde::Serialize)]
pub struct TrackerStats {
    /// Number of TCP sessions
    pub tcp_sessions: usize,
    /// Number of UDP sessions
    pub udp_sessions: usize,
    /// Number of allocated ports
    pub ports_allocated: usize,
    /// Number of ports in TIME_WAIT
    pub ports_in_time_wait: usize,
    /// Number of unique clients
    pub client_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    fn make_client_addr(port: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), port))
    }

    fn make_session_key(local_port: u16, remote_port: u16) -> SessionKey {
        SessionKey::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            local_port,
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            remote_port,
        )
    }

    /// Create a mock socket handle for testing
    /// This is a workaround since SocketHandle doesn't have a public constructor
    fn mock_socket_handle(id: usize) -> SocketHandle {
        // SAFETY: SocketHandle is a transparent wrapper around usize
        // This is only used in tests and is the same approach used in vless_wg_bridge
        unsafe { std::mem::transmute(id) }
    }

    #[test]
    fn test_connection_id() {
        let addr = make_client_addr(12345);
        let id1 = ConnectionId::new(addr);
        let id2 = ConnectionId::new(addr);

        // Same address should produce different IDs (monotonic counter)
        assert_ne!(id1.id(), id2.id());
        assert_eq!(id1.client_addr(), addr);
    }

    #[test]
    fn test_connection_id_display() {
        let addr = make_client_addr(12345);
        let id = ConnectionId::new(addr);
        let s = id.to_string();
        assert!(s.contains("conn-"));
        assert!(s.contains("12345"));
    }

    #[test]
    fn test_session_key() {
        let key = make_session_key(50000, 80);

        assert_eq!(key.local_port, 50000);
        assert_eq!(key.remote_port, 80);

        let reversed = key.reverse();
        assert_eq!(reversed.local_port, 80);
        assert_eq!(reversed.remote_port, 50000);
        assert_eq!(reversed.local_ip, key.remote_ip);
        assert_eq!(reversed.remote_ip, key.local_ip);
    }

    #[test]
    fn test_session_key_display() {
        let key = make_session_key(50000, 80);
        let s = key.to_string();
        assert!(s.contains("50000"));
        assert!(s.contains("80"));
        assert!(s.contains("->"));
    }

    #[test]
    fn test_session_stats() {
        let stats = SessionStats::new();

        stats.record_tx(100);
        stats.record_rx(200);

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.bytes_tx, 100);
        assert_eq!(snapshot.bytes_rx, 200);
        assert_eq!(snapshot.packets_tx, 1);
        assert_eq!(snapshot.packets_rx, 1);
    }

    #[test]
    fn test_session_stats_multiple_records() {
        let stats = SessionStats::new();

        for _ in 0..10 {
            stats.record_tx(100);
        }
        for _ in 0..5 {
            stats.record_rx(200);
        }

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.bytes_tx, 1000);
        assert_eq!(snapshot.bytes_rx, 1000);
        assert_eq!(snapshot.packets_tx, 10);
        assert_eq!(snapshot.packets_rx, 5);
    }

    #[test]
    fn test_tracker_basic() {
        let tracker = SessionTracker::new();

        assert_eq!(tracker.tcp_count(), 0);
        assert_eq!(tracker.udp_count(), 0);
        assert_eq!(tracker.total_count(), 0);
    }

    #[test]
    fn test_tracker_register_tcp() {
        let tracker = SessionTracker::new();
        let client_addr = make_client_addr(12345);
        let connection_id = ConnectionId::new(client_addr);
        let handle = mock_socket_handle(0);
        let key = make_session_key(50000, 80);

        let result = tracker.register_tcp(connection_id.clone(), handle, key.clone());
        assert!(result.is_ok());

        assert_eq!(tracker.tcp_count(), 1);
        assert!(tracker.get_tcp(&key).is_some());
        assert_eq!(tracker.get_key_by_handle(handle), Some(key.clone()));
        assert_eq!(tracker.client_count(&connection_id), 1);
    }

    #[test]
    fn test_tracker_register_udp() {
        let tracker = SessionTracker::new();
        let client_addr = make_client_addr(12345);
        let connection_id = ConnectionId::new(client_addr);
        let handle = mock_socket_handle(1);
        let key = make_session_key(50001, 53);

        let result = tracker.register_udp(connection_id.clone(), handle, key.clone());
        assert!(result.is_ok());

        assert_eq!(tracker.udp_count(), 1);
        assert!(tracker.get_udp(&key).is_some());

        // Check if it's detected as DNS
        let session = tracker.get_udp(&key).unwrap();
        assert!(session.is_dns);
    }

    #[test]
    fn test_tracker_remove_tcp() {
        let tracker = SessionTracker::new();
        let client_addr = make_client_addr(12345);
        let connection_id = ConnectionId::new(client_addr);
        let handle = mock_socket_handle(0);
        let key = make_session_key(50000, 80);

        tracker.register_tcp(connection_id.clone(), handle, key.clone()).unwrap();
        assert_eq!(tracker.tcp_count(), 1);

        let removed = tracker.remove_tcp(&key);
        assert!(removed.is_some());
        assert_eq!(tracker.tcp_count(), 0);
        assert!(tracker.get_tcp(&key).is_none());
        assert_eq!(tracker.client_count(&connection_id), 0);
    }

    #[test]
    fn test_tracker_duplicate_session() {
        let tracker = SessionTracker::new();
        let client_addr = make_client_addr(12345);
        let connection_id = ConnectionId::new(client_addr);
        let handle1 = mock_socket_handle(0);
        let handle2 = mock_socket_handle(1);
        let key = make_session_key(50000, 80);

        // First registration should succeed
        tracker.register_tcp(connection_id.clone(), handle1, key.clone()).unwrap();

        // Duplicate should fail
        let result = tracker.register_tcp(connection_id, handle2, key);
        assert!(matches!(result, Err(BridgeError::SessionAlreadyExists(_))));
    }

    #[test]
    fn test_tracker_per_client_limit() {
        let tracker = SessionTracker::new();
        let client_addr = make_client_addr(12345);
        let connection_id = ConnectionId::new(client_addr);

        // Register up to the limit
        for i in 0..MAX_SESSIONS_PER_CLIENT {
            let handle = mock_socket_handle(i as usize);
            let key = make_session_key(50000 + i as u16, 80);
            tracker.register_tcp(connection_id.clone(), handle, key).unwrap();
        }

        assert_eq!(tracker.client_count(&connection_id), MAX_SESSIONS_PER_CLIENT);

        // Next should fail
        let handle = mock_socket_handle(MAX_SESSIONS_PER_CLIENT);
        let key = make_session_key(60000, 80);
        let result = tracker.register_tcp(connection_id, handle, key);
        assert!(matches!(
            result,
            Err(BridgeError::PerClientSessionLimitReached(_))
        ));
    }

    #[test]
    fn test_tracker_clear() {
        let tracker = SessionTracker::new();
        let client_addr = make_client_addr(12345);

        // Register some sessions
        for i in 0..5 {
            let connection_id = ConnectionId::new(client_addr);
            let handle = mock_socket_handle(i as usize);
            let key = make_session_key(50000 + i as u16, 80);
            tracker.register_tcp(connection_id, handle, key).unwrap();
        }

        assert_eq!(tracker.total_count(), 5);

        tracker.clear();

        assert_eq!(tracker.total_count(), 0);
    }

    #[test]
    fn test_tracker_stats_snapshot() {
        let tracker = SessionTracker::new();
        let stats = tracker.stats_snapshot();

        assert_eq!(stats.tcp_sessions, 0);
        assert_eq!(stats.udp_sessions, 0);
    }

    #[test]
    fn test_timeout_config_default() {
        let config = TimeoutConfig::default();
        assert_eq!(config.tcp_idle, Duration::from_secs(TCP_IDLE_TIMEOUT_SECS));
        assert_eq!(
            config.udp_default,
            Duration::from_secs(UDP_DEFAULT_TIMEOUT_SECS)
        );
        assert_eq!(config.udp_dns, Duration::from_secs(UDP_DNS_TIMEOUT_SECS));
    }

    #[test]
    fn test_udp_session_timeout() {
        let config = TimeoutConfig::default();

        // Regular UDP session
        let key_regular = make_session_key(50000, 8080);
        let session_regular = UdpSession::new(
            mock_socket_handle(0),
            key_regular,
            ConnectionId::new(make_client_addr(12345)),
        );
        assert_eq!(session_regular.timeout(&config), config.udp_default);
        assert!(!session_regular.is_dns);

        // DNS session
        let key_dns = make_session_key(50001, 53);
        let session_dns = UdpSession::new(
            mock_socket_handle(1),
            key_dns,
            ConnectionId::new(make_client_addr(12345)),
        );
        assert_eq!(session_dns.timeout(&config), config.udp_dns);
        assert!(session_dns.is_dns);
    }

    #[test]
    fn test_port_allocation_integration() {
        let tracker = SessionTracker::new();

        // Allocate a port
        let guard = tracker.allocate_port().expect("should allocate");
        let port = guard.port();

        assert!(port >= 49152);
        assert!(port <= 65535);

        // Take ownership
        let port = guard.take();

        // Return it
        tracker.return_port(port);
    }

    #[test]
    fn test_tracker_debug() {
        let tracker = SessionTracker::new();
        let debug_str = format!("{:?}", tracker);
        assert!(debug_str.contains("SessionTracker"));
        assert!(debug_str.contains("tcp_sessions"));
    }

    #[test]
    fn test_session_stats_snapshot_serialization() {
        let snapshot = SessionStatsSnapshot {
            bytes_tx: 1000,
            bytes_rx: 2000,
            packets_tx: 10,
            packets_rx: 20,
            age_secs: 60,
            idle_secs: 5,
        };

        let json = serde_json::to_string(&snapshot).expect("should serialize");
        assert!(json.contains("1000"));
        assert!(json.contains("2000"));
    }

    #[test]
    fn test_tracker_stats_serialization() {
        let stats = TrackerStats {
            tcp_sessions: 10,
            udp_sessions: 5,
            ports_allocated: 15,
            ports_in_time_wait: 3,
            client_count: 8,
        };

        let json = serde_json::to_string(&stats).expect("should serialize");
        assert!(json.contains("10"));
        assert!(json.contains("tcp_sessions"));
    }
}
