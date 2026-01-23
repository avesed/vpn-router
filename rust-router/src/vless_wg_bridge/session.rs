//! Session tracking for the VLESS-WG Bridge
//!
//! This module provides the session tracking infrastructure for mapping between
//! VLESS connections and smoltcp sockets. It maintains bidirectional indices
//! for efficient lookup in both directions:
//!
//! - Forward: `SessionKey` (4-tuple) -> Session
//! - Reverse: `VlessConnectionId` -> Sessions
//! - Socket: `SocketHandle` -> `SessionKey`
//!
//! # Connection Identification
//!
//! Each VLESS connection is assigned a unique `VlessConnectionId` using a
//! monotonic counter. This ensures stable identification even across system
//! clock adjustments.
//!
//! # Session Types
//!
//! - `TcpSession`: Tracks a TCP connection through smoltcp
//! - `UdpSession`: Tracks a UDP "session" (request-response pair)
//!
//! # Usage
//!
//! ```ignore
//! use std::net::SocketAddr;
//! use rust_router::vless_wg_bridge::{
//!     VlessConnectionId, SessionKey, SessionTracker, PortAllocator,
//! };
//!
//! // Create session tracker
//! let allocator = PortAllocator::new();
//! let tracker = SessionTracker::new(allocator);
//!
//! // Create connection ID for a VLESS client
//! let client_addr: SocketAddr = "192.168.1.100:12345".parse().unwrap();
//! let conn_id = VlessConnectionId::new(client_addr);
//!
//! // Register a TCP session
//! let session_key = SessionKey {
//!     local_ip: "10.200.200.2".parse().unwrap(),
//!     local_port: 50000,
//!     remote_ip: "93.184.216.34".parse().unwrap(),
//!     remote_port: 80,
//! };
//! tracker.register_tcp(conn_id, socket_handle, session_key);
//! ```

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use smoltcp::iface::SocketHandle;
use tracing::{debug, trace};

use super::config::{
    MAX_SESSIONS_PER_CLIENT, MAX_TOTAL_SESSIONS, TCP_IDLE_TIMEOUT_SECS, UDP_DEFAULT_TIMEOUT_SECS,
    UDP_DNS_TIMEOUT_SECS,
};
use super::error::{BridgeError, Result};
use super::port_allocator::PortAllocator;

// =============================================================================
// Connection Identification
// =============================================================================

/// Global connection counter for unique connection IDs
static CONNECTION_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Unique identifier for a VLESS connection
///
/// This combines the client's socket address with a monotonic counter to
/// ensure unique identification even if the same client reconnects.
///
/// Using a counter instead of `Instant` ensures the ID is hashable and
/// remains stable across system clock adjustments.
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct VlessConnectionId {
    /// VLESS client's TCP socket address
    pub client_addr: SocketAddr,
    /// Monotonically increasing connection ID
    pub connection_id: u64,
}

impl VlessConnectionId {
    /// Create a new unique connection ID
    ///
    /// Each call to this function generates a unique ID using an atomic counter.
    #[must_use]
    pub fn new(client_addr: SocketAddr) -> Self {
        let connection_id = CONNECTION_COUNTER.fetch_add(1, Ordering::Relaxed);
        Self {
            client_addr,
            connection_id,
        }
    }

    /// Create a connection ID from existing parts (for testing/restoration)
    #[must_use]
    pub fn from_parts(client_addr: SocketAddr, connection_id: u64) -> Self {
        Self {
            client_addr,
            connection_id,
        }
    }
}

impl std::fmt::Display for VlessConnectionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}#{}", self.client_addr, self.connection_id)
    }
}

// =============================================================================
// Session Key
// =============================================================================

/// Four-tuple key identifying a network session
///
/// This is used as the primary key for session lookup in both TCP and UDP
/// session maps.
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct SessionKey {
    /// Local IP address (tunnel IP)
    pub local_ip: IpAddr,
    /// Local port (allocated by `PortAllocator`)
    pub local_port: u16,
    /// Remote IP address (destination server)
    pub remote_ip: IpAddr,
    /// Remote port (destination port)
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

// =============================================================================
// Session Statistics
// =============================================================================

/// Statistics for a session
#[derive(Debug)]
pub struct SessionStats {
    /// Bytes sent through this session
    pub bytes_sent: AtomicU64,
    /// Bytes received through this session
    pub bytes_recv: AtomicU64,
    /// When the session was created
    pub created_at: Instant,
}

impl SessionStats {
    /// Create new session statistics
    #[must_use]
    pub fn new() -> Self {
        Self {
            bytes_sent: AtomicU64::new(0),
            bytes_recv: AtomicU64::new(0),
            created_at: Instant::now(),
        }
    }

    /// Add to bytes sent counter
    pub fn add_sent(&self, bytes: u64) {
        self.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Add to bytes received counter
    pub fn add_recv(&self, bytes: u64) {
        self.bytes_recv.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Get total bytes sent
    #[must_use]
    pub fn total_sent(&self) -> u64 {
        self.bytes_sent.load(Ordering::Relaxed)
    }

    /// Get total bytes received
    #[must_use]
    pub fn total_recv(&self) -> u64 {
        self.bytes_recv.load(Ordering::Relaxed)
    }

    /// Get session age
    #[must_use]
    pub fn age(&self) -> Duration {
        self.created_at.elapsed()
    }
}

impl Default for SessionStats {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Session Types
// =============================================================================

/// A TCP session through the smoltcp stack
pub struct TcpSession {
    /// VLESS connection this session belongs to
    pub vless_conn_id: VlessConnectionId,
    /// smoltcp socket handle
    pub socket_handle: SocketHandle,
    /// Session key (4-tuple)
    pub key: SessionKey,
    /// Session statistics
    pub stats: SessionStats,
}

impl TcpSession {
    /// Create a new TCP session
    #[must_use]
    pub fn new(
        vless_conn_id: VlessConnectionId,
        socket_handle: SocketHandle,
        key: SessionKey,
    ) -> Self {
        Self {
            vless_conn_id,
            socket_handle,
            key,
            stats: SessionStats::new(),
        }
    }
}

impl std::fmt::Debug for TcpSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TcpSession")
            .field("vless_conn_id", &self.vless_conn_id)
            .field("socket_handle", &self.socket_handle)
            .field("key", &self.key)
            .field("bytes_sent", &self.stats.total_sent())
            .field("bytes_recv", &self.stats.total_recv())
            .field("age_secs", &self.stats.age().as_secs())
            .finish()
    }
}

/// A UDP session through the smoltcp stack
pub struct UdpSession {
    /// VLESS connection this session belongs to
    pub vless_conn_id: VlessConnectionId,
    /// smoltcp socket handle
    pub socket_handle: SocketHandle,
    /// Session key (4-tuple)
    pub key: SessionKey,
    /// Last activity timestamp (Unix timestamp in seconds for atomic update)
    pub last_activity: AtomicU64,
    /// Session statistics
    pub stats: SessionStats,
}

impl UdpSession {
    /// Create a new UDP session
    #[must_use]
    pub fn new(
        vless_conn_id: VlessConnectionId,
        socket_handle: SocketHandle,
        key: SessionKey,
    ) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            vless_conn_id,
            socket_handle,
            key,
            last_activity: AtomicU64::new(now),
            stats: SessionStats::new(),
        }
    }

    /// Update the last activity timestamp
    pub fn touch(&self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.last_activity.store(now, Ordering::Relaxed);
    }

    /// Get seconds since last activity
    #[must_use]
    pub fn idle_seconds(&self) -> u64 {
        let last = self.last_activity.load(Ordering::Relaxed);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now.saturating_sub(last)
    }
}

impl std::fmt::Debug for UdpSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpSession")
            .field("vless_conn_id", &self.vless_conn_id)
            .field("socket_handle", &self.socket_handle)
            .field("key", &self.key)
            .field("idle_seconds", &self.idle_seconds())
            .field("bytes_sent", &self.stats.total_sent())
            .field("bytes_recv", &self.stats.total_recv())
            .finish()
    }
}

// =============================================================================
// Timeout Configuration
// =============================================================================

/// Timeout configuration for sessions
#[derive(Debug, Clone, Copy)]
pub struct TimeoutConfig {
    /// TCP idle timeout
    pub tcp_idle: Duration,
    /// UDP default timeout
    pub udp_default: Duration,
    /// UDP DNS timeout (shorter for DNS queries)
    pub udp_dns: Duration,
}

impl TimeoutConfig {
    /// Create new timeout configuration
    #[must_use]
    pub fn new(tcp_idle: Duration, udp_default: Duration, udp_dns: Duration) -> Self {
        Self {
            tcp_idle,
            udp_default,
            udp_dns,
        }
    }
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

// =============================================================================
// Session Tracker
// =============================================================================

/// Central session management for the VLESS-WG bridge
///
/// This struct maintains multiple indices for efficient session lookup:
/// - TCP sessions by `SessionKey`
/// - UDP sessions by `SessionKey`
/// - Reverse index from `VlessConnectionId` to all its sessions
/// - Socket handle to `SessionKey` mapping
pub struct SessionTracker {
    /// TCP sessions: SessionKey -> TcpSession
    tcp_sessions: DashMap<SessionKey, Arc<TcpSession>>,

    /// UDP sessions: SessionKey -> UdpSession
    udp_sessions: DashMap<SessionKey, Arc<UdpSession>>,

    /// Reverse index: VlessConnectionId -> Vec<SessionKey>
    conn_sessions: DashMap<VlessConnectionId, Vec<SessionKey>>,

    /// Socket handle to session key mapping
    socket_to_session: DashMap<SocketHandle, SessionKey>,

    /// Port allocator
    port_allocator: PortAllocator,

    /// Timeout configuration
    timeouts: TimeoutConfig,
}

impl SessionTracker {
    /// Create a new session tracker
    #[must_use]
    pub fn new(port_allocator: PortAllocator) -> Self {
        Self {
            tcp_sessions: DashMap::new(),
            udp_sessions: DashMap::new(),
            conn_sessions: DashMap::new(),
            socket_to_session: DashMap::new(),
            port_allocator,
            timeouts: TimeoutConfig::default(),
        }
    }

    /// Create a new session tracker with custom timeouts
    #[must_use]
    pub fn with_timeouts(port_allocator: PortAllocator, timeouts: TimeoutConfig) -> Self {
        Self {
            tcp_sessions: DashMap::new(),
            udp_sessions: DashMap::new(),
            conn_sessions: DashMap::new(),
            socket_to_session: DashMap::new(),
            port_allocator,
            timeouts,
        }
    }

    /// Get a reference to the port allocator
    #[must_use]
    pub fn port_allocator(&self) -> &PortAllocator {
        &self.port_allocator
    }

    /// Allocate a new ephemeral port
    ///
    /// This is a convenience method that wraps `port_allocator().allocate()`.
    ///
    /// # Returns
    ///
    /// - `Some(PortGuard)` if a port was successfully allocated
    /// - `None` if all ports are in use or in TIME_WAIT
    pub fn allocate_port(&self) -> Option<super::port_allocator::PortGuard<'_>> {
        self.port_allocator.allocate()
    }

    /// Return a port to the allocator (for manual cleanup)
    ///
    /// This is used when ports are managed manually (e.g., via `PortGuard::take()`)
    /// and need to be explicitly released into TIME_WAIT.
    ///
    /// # Arguments
    ///
    /// * `port` - The port to return to the allocator
    pub fn return_port(&self, port: u16) {
        self.port_allocator.release(port);
    }

    /// Get the timeout configuration
    #[must_use]
    pub fn timeouts(&self) -> &TimeoutConfig {
        &self.timeouts
    }

    // -------------------------------------------------------------------------
    // TCP Session Management
    // -------------------------------------------------------------------------

    /// Register a new TCP session
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The session key already exists
    /// - The maximum total sessions has been reached
    /// - The per-client session limit has been reached
    pub fn register_tcp(
        &self,
        vless_conn_id: VlessConnectionId,
        socket_handle: SocketHandle,
        key: SessionKey,
    ) -> Result<Arc<TcpSession>> {
        // Check total session limit
        let total = self.tcp_sessions.len() + self.udp_sessions.len();
        if total >= MAX_TOTAL_SESSIONS {
            return Err(BridgeError::SessionLimitReached(MAX_TOTAL_SESSIONS));
        }

        // Check per-client limit
        if let Some(sessions) = self.conn_sessions.get(&vless_conn_id) {
            if sessions.len() >= MAX_SESSIONS_PER_CLIENT {
                return Err(BridgeError::PerClientSessionLimitReached(
                    MAX_SESSIONS_PER_CLIENT,
                ));
            }
        }

        // Check for duplicate
        if self.tcp_sessions.contains_key(&key) {
            return Err(BridgeError::SessionAlreadyExists(key.to_string()));
        }

        // Create session
        let session = Arc::new(TcpSession::new(vless_conn_id.clone(), socket_handle, key.clone()));

        // Insert into all indices
        self.tcp_sessions.insert(key.clone(), Arc::clone(&session));
        self.socket_to_session.insert(socket_handle, key.clone());

        self.conn_sessions
            .entry(vless_conn_id.clone())
            .or_default()
            .push(key);

        debug!(
            "Registered TCP session: conn_id={}, socket={:?}",
            vless_conn_id, socket_handle
        );

        Ok(session)
    }

    /// Look up a TCP session by session key
    #[must_use]
    pub fn lookup_tcp(&self, key: &SessionKey) -> Option<Arc<TcpSession>> {
        self.tcp_sessions.get(key).map(|r| Arc::clone(r.value()))
    }

    /// Look up a TCP session by socket handle
    #[must_use]
    pub fn lookup_tcp_by_socket(&self, handle: SocketHandle) -> Option<Arc<TcpSession>> {
        self.socket_to_session
            .get(&handle)
            .and_then(|key| self.tcp_sessions.get(key.value()).map(|r| Arc::clone(r.value())))
    }

    /// Remove a TCP session
    pub fn remove_tcp(&self, key: &SessionKey) -> Option<Arc<TcpSession>> {
        if let Some((_, session)) = self.tcp_sessions.remove(key) {
            // Remove from socket index
            self.socket_to_session.remove(&session.socket_handle);

            // Remove from connection index
            if let Some(mut sessions) = self.conn_sessions.get_mut(&session.vless_conn_id) {
                sessions.retain(|k| k != key);
            }

            debug!("Removed TCP session: {}", key);
            Some(session)
        } else {
            None
        }
    }

    // -------------------------------------------------------------------------
    // UDP Session Management
    // -------------------------------------------------------------------------

    /// Register a new UDP session
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The session key already exists
    /// - The maximum total sessions has been reached
    /// - The per-client session limit has been reached
    pub fn register_udp(
        &self,
        vless_conn_id: VlessConnectionId,
        socket_handle: SocketHandle,
        key: SessionKey,
    ) -> Result<Arc<UdpSession>> {
        // Check total session limit
        let total = self.tcp_sessions.len() + self.udp_sessions.len();
        if total >= MAX_TOTAL_SESSIONS {
            return Err(BridgeError::SessionLimitReached(MAX_TOTAL_SESSIONS));
        }

        // Check per-client limit
        if let Some(sessions) = self.conn_sessions.get(&vless_conn_id) {
            if sessions.len() >= MAX_SESSIONS_PER_CLIENT {
                return Err(BridgeError::PerClientSessionLimitReached(
                    MAX_SESSIONS_PER_CLIENT,
                ));
            }
        }

        // Check for duplicate
        if self.udp_sessions.contains_key(&key) {
            return Err(BridgeError::SessionAlreadyExists(key.to_string()));
        }

        // Create session
        let session = Arc::new(UdpSession::new(vless_conn_id.clone(), socket_handle, key.clone()));

        // Insert into all indices
        self.udp_sessions.insert(key.clone(), Arc::clone(&session));
        self.socket_to_session.insert(socket_handle, key.clone());

        self.conn_sessions
            .entry(vless_conn_id.clone())
            .or_default()
            .push(key);

        debug!(
            "Registered UDP session: conn_id={}, socket={:?}",
            vless_conn_id, socket_handle
        );

        Ok(session)
    }

    /// Look up a UDP session by session key
    #[must_use]
    pub fn lookup_udp(&self, key: &SessionKey) -> Option<Arc<UdpSession>> {
        self.udp_sessions.get(key).map(|r| Arc::clone(r.value()))
    }

    /// Look up a UDP session by socket handle
    #[must_use]
    pub fn lookup_udp_by_socket(&self, handle: SocketHandle) -> Option<Arc<UdpSession>> {
        self.socket_to_session
            .get(&handle)
            .and_then(|key| self.udp_sessions.get(key.value()).map(|r| Arc::clone(r.value())))
    }

    /// Remove a UDP session
    pub fn remove_udp(&self, key: &SessionKey) -> Option<Arc<UdpSession>> {
        if let Some((_, session)) = self.udp_sessions.remove(key) {
            // Remove from socket index
            self.socket_to_session.remove(&session.socket_handle);

            // Remove from connection index
            if let Some(mut sessions) = self.conn_sessions.get_mut(&session.vless_conn_id) {
                sessions.retain(|k| k != key);
            }

            debug!("Removed UDP session: {}", key);
            Some(session)
        } else {
            None
        }
    }

    // -------------------------------------------------------------------------
    // Lookup by Socket Handle
    // -------------------------------------------------------------------------

    /// Look up session key by socket handle
    #[must_use]
    pub fn lookup_by_socket(&self, handle: SocketHandle) -> Option<SessionKey> {
        self.socket_to_session.get(&handle).map(|r| r.value().clone())
    }

    // -------------------------------------------------------------------------
    // Connection Cleanup
    // -------------------------------------------------------------------------

    /// Clean up all sessions associated with a VLESS connection
    ///
    /// This should be called when a VLESS connection is closed to release
    /// all associated resources.
    ///
    /// Returns the list of session keys that were cleaned up.
    pub fn cleanup_connection(&self, conn_id: &VlessConnectionId) -> Vec<SessionKey> {
        if let Some((_, keys)) = self.conn_sessions.remove(conn_id) {
            for key in &keys {
                // Remove from TCP sessions
                if let Some((_, session)) = self.tcp_sessions.remove(key) {
                    self.socket_to_session.remove(&session.socket_handle);
                }
                // Remove from UDP sessions
                if let Some((_, session)) = self.udp_sessions.remove(key) {
                    self.socket_to_session.remove(&session.socket_handle);
                }
            }

            debug!(
                "Cleaned up {} sessions for connection {}",
                keys.len(),
                conn_id
            );
            keys
        } else {
            Vec::new()
        }
    }

    // -------------------------------------------------------------------------
    // Timeout Helpers
    // -------------------------------------------------------------------------

    /// Get UDP timeout for a given port
    ///
    /// Returns a shorter timeout for DNS queries (port 53).
    #[must_use]
    pub fn udp_timeout_for_port(&self, port: u16) -> Duration {
        match port {
            53 => self.timeouts.udp_dns,
            _ => self.timeouts.udp_default,
        }
    }

    /// Clean up expired UDP sessions
    ///
    /// Returns the number of sessions cleaned up.
    pub fn cleanup_expired_udp(&self) -> usize {
        let mut cleaned = 0;

        // Collect expired sessions
        let expired: Vec<SessionKey> = self
            .udp_sessions
            .iter()
            .filter(|entry| {
                let session = entry.value();
                let timeout = self.udp_timeout_for_port(session.key.remote_port);
                session.idle_seconds() >= timeout.as_secs()
            })
            .map(|entry| entry.key().clone())
            .collect();

        // Remove expired sessions
        for key in expired {
            if self.remove_udp(&key).is_some() {
                cleaned += 1;
            }
        }

        if cleaned > 0 {
            trace!("Cleaned up {} expired UDP sessions", cleaned);
        }

        cleaned
    }

    // -------------------------------------------------------------------------
    // Statistics
    // -------------------------------------------------------------------------

    /// Get the total number of TCP sessions
    #[must_use]
    pub fn tcp_session_count(&self) -> usize {
        self.tcp_sessions.len()
    }

    /// Get the total number of UDP sessions
    #[must_use]
    pub fn udp_session_count(&self) -> usize {
        self.udp_sessions.len()
    }

    /// Get the total number of tracked VLESS connections
    #[must_use]
    pub fn connection_count(&self) -> usize {
        self.conn_sessions.len()
    }

    /// Get the number of sessions for a specific connection
    #[must_use]
    pub fn sessions_for_connection(&self, conn_id: &VlessConnectionId) -> usize {
        self.conn_sessions
            .get(conn_id)
            .map(|r| r.value().len())
            .unwrap_or(0)
    }
}

impl std::fmt::Debug for SessionTracker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionTracker")
            .field("tcp_sessions", &self.tcp_session_count())
            .field("udp_sessions", &self.udp_session_count())
            .field("connections", &self.connection_count())
            .field("timeouts", &self.timeouts)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    // Helper to create a mock socket handle
    fn mock_socket_handle(id: usize) -> SocketHandle {
        // This is a bit of a hack, but works for testing
        unsafe { std::mem::transmute(id) }
    }

    #[test]
    fn test_vless_connection_id_uniqueness() {
        let addr: SocketAddr = "192.168.1.100:12345".parse().unwrap();

        let id1 = VlessConnectionId::new(addr);
        let id2 = VlessConnectionId::new(addr);
        let id3 = VlessConnectionId::new(addr);

        // Same address, different IDs
        assert_ne!(id1.connection_id, id2.connection_id);
        assert_ne!(id2.connection_id, id3.connection_id);

        // IDs should be monotonically increasing
        assert!(id1.connection_id < id2.connection_id);
        assert!(id2.connection_id < id3.connection_id);

        // Different addresses
        let addr2: SocketAddr = "192.168.1.101:12345".parse().unwrap();
        let id4 = VlessConnectionId::new(addr2);
        assert_ne!(id3.client_addr, id4.client_addr);
    }

    #[test]
    fn test_vless_connection_id_display() {
        let addr: SocketAddr = "192.168.1.100:12345".parse().unwrap();
        let id = VlessConnectionId::from_parts(addr, 42);

        let display = format!("{}", id);
        assert!(display.contains("192.168.1.100:12345"));
        assert!(display.contains("#42"));
    }

    #[test]
    fn test_session_key() {
        let key = SessionKey::new(
            IpAddr::V4(Ipv4Addr::new(10, 200, 200, 2)),
            50000,
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            80,
        );

        assert_eq!(
            key.local_ip,
            IpAddr::V4(Ipv4Addr::new(10, 200, 200, 2))
        );
        assert_eq!(key.local_port, 50000);
        assert_eq!(
            key.remote_ip,
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))
        );
        assert_eq!(key.remote_port, 80);

        let display = format!("{}", key);
        assert!(display.contains("10.200.200.2:50000"));
        assert!(display.contains("93.184.216.34:80"));
    }

    #[test]
    fn test_session_key_ipv6() {
        let key = SessionKey::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            50000,
            IpAddr::V6(Ipv6Addr::new(0x2606, 0x2800, 0x220, 1, 0, 0, 0, 1)),
            443,
        );

        assert!(matches!(key.local_ip, IpAddr::V6(_)));
        assert!(matches!(key.remote_ip, IpAddr::V6(_)));
    }

    #[test]
    fn test_session_stats() {
        let stats = SessionStats::new();

        assert_eq!(stats.total_sent(), 0);
        assert_eq!(stats.total_recv(), 0);

        stats.add_sent(100);
        stats.add_recv(200);

        assert_eq!(stats.total_sent(), 100);
        assert_eq!(stats.total_recv(), 200);

        stats.add_sent(50);
        stats.add_recv(75);

        assert_eq!(stats.total_sent(), 150);
        assert_eq!(stats.total_recv(), 275);

        // Age should be non-negative
        assert!(stats.age() >= Duration::ZERO);
    }

    #[test]
    fn test_timeout_config() {
        let config = TimeoutConfig::default();

        assert_eq!(config.tcp_idle, Duration::from_secs(300));
        assert_eq!(config.udp_default, Duration::from_secs(30));
        assert_eq!(config.udp_dns, Duration::from_secs(10));

        let custom = TimeoutConfig::new(
            Duration::from_secs(60),
            Duration::from_secs(15),
            Duration::from_secs(5),
        );
        assert_eq!(custom.tcp_idle, Duration::from_secs(60));
        assert_eq!(custom.udp_default, Duration::from_secs(15));
        assert_eq!(custom.udp_dns, Duration::from_secs(5));
    }

    #[test]
    fn test_session_tracker_creation() {
        let allocator = PortAllocator::new();
        let tracker = SessionTracker::new(allocator);

        assert_eq!(tracker.tcp_session_count(), 0);
        assert_eq!(tracker.udp_session_count(), 0);
        assert_eq!(tracker.connection_count(), 0);
    }

    #[test]
    fn test_register_tcp_session() {
        let allocator = PortAllocator::new();
        let tracker = SessionTracker::new(allocator);

        let client_addr: SocketAddr = "192.168.1.100:12345".parse().unwrap();
        let conn_id = VlessConnectionId::new(client_addr);
        let handle = mock_socket_handle(1);
        let key = SessionKey::new(
            IpAddr::V4(Ipv4Addr::new(10, 200, 200, 2)),
            50000,
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            80,
        );

        let session = tracker
            .register_tcp(conn_id.clone(), handle, key.clone())
            .expect("should register");

        assert_eq!(session.key, key);
        assert_eq!(session.vless_conn_id, conn_id);
        assert_eq!(tracker.tcp_session_count(), 1);
        assert_eq!(tracker.sessions_for_connection(&conn_id), 1);
    }

    #[test]
    fn test_lookup_tcp_session() {
        let allocator = PortAllocator::new();
        let tracker = SessionTracker::new(allocator);

        let client_addr: SocketAddr = "192.168.1.100:12345".parse().unwrap();
        let conn_id = VlessConnectionId::new(client_addr);
        let handle = mock_socket_handle(1);
        let key = SessionKey::new(
            IpAddr::V4(Ipv4Addr::new(10, 200, 200, 2)),
            50000,
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            80,
        );

        tracker
            .register_tcp(conn_id.clone(), handle, key.clone())
            .unwrap();

        // Lookup by key
        let session = tracker.lookup_tcp(&key).expect("should find");
        assert_eq!(session.key, key);

        // Lookup by socket handle
        let session = tracker.lookup_tcp_by_socket(handle).expect("should find");
        assert_eq!(session.key, key);

        // Lookup by socket handle via generic method
        let found_key = tracker.lookup_by_socket(handle).expect("should find");
        assert_eq!(found_key, key);
    }

    #[test]
    fn test_remove_tcp_session() {
        let allocator = PortAllocator::new();
        let tracker = SessionTracker::new(allocator);

        let client_addr: SocketAddr = "192.168.1.100:12345".parse().unwrap();
        let conn_id = VlessConnectionId::new(client_addr);
        let handle = mock_socket_handle(1);
        let key = SessionKey::new(
            IpAddr::V4(Ipv4Addr::new(10, 200, 200, 2)),
            50000,
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            80,
        );

        tracker.register_tcp(conn_id.clone(), handle, key.clone()).unwrap();
        assert_eq!(tracker.tcp_session_count(), 1);

        // Remove session
        let removed = tracker.remove_tcp(&key).expect("should remove");
        assert_eq!(removed.key, key);
        assert_eq!(tracker.tcp_session_count(), 0);

        // Should no longer be found
        assert!(tracker.lookup_tcp(&key).is_none());
        assert!(tracker.lookup_tcp_by_socket(handle).is_none());
    }

    #[test]
    fn test_register_udp_session() {
        let allocator = PortAllocator::new();
        let tracker = SessionTracker::new(allocator);

        let client_addr: SocketAddr = "192.168.1.100:12345".parse().unwrap();
        let conn_id = VlessConnectionId::new(client_addr);
        let handle = mock_socket_handle(1);
        let key = SessionKey::new(
            IpAddr::V4(Ipv4Addr::new(10, 200, 200, 2)),
            50000,
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            53,
        );

        let session = tracker
            .register_udp(conn_id.clone(), handle, key.clone())
            .expect("should register");

        assert_eq!(session.key, key);
        assert_eq!(tracker.udp_session_count(), 1);
    }

    #[test]
    fn test_udp_session_touch() {
        let client_addr: SocketAddr = "192.168.1.100:12345".parse().unwrap();
        let conn_id = VlessConnectionId::new(client_addr);
        let handle = mock_socket_handle(1);
        let key = SessionKey::new(
            IpAddr::V4(Ipv4Addr::new(10, 200, 200, 2)),
            50000,
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            53,
        );

        let session = UdpSession::new(conn_id, handle, key);

        // Initial idle time should be 0 or very small
        assert!(session.idle_seconds() <= 1);

        // Touch and verify it updated
        session.touch();
        assert!(session.idle_seconds() <= 1);
    }

    #[test]
    fn test_cleanup_connection() {
        let allocator = PortAllocator::new();
        let tracker = SessionTracker::new(allocator);

        let client_addr: SocketAddr = "192.168.1.100:12345".parse().unwrap();
        let conn_id = VlessConnectionId::new(client_addr);

        // Register multiple sessions for same connection
        for i in 0..5 {
            let handle = mock_socket_handle(i);
            let key = SessionKey::new(
                IpAddr::V4(Ipv4Addr::new(10, 200, 200, 2)),
                50000 + i as u16,
                IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
                80,
            );
            tracker.register_tcp(conn_id.clone(), handle, key).unwrap();
        }

        assert_eq!(tracker.tcp_session_count(), 5);
        assert_eq!(tracker.sessions_for_connection(&conn_id), 5);

        // Cleanup
        let cleaned = tracker.cleanup_connection(&conn_id);
        assert_eq!(cleaned.len(), 5);
        assert_eq!(tracker.tcp_session_count(), 0);
        assert_eq!(tracker.sessions_for_connection(&conn_id), 0);
    }

    #[test]
    fn test_duplicate_session_error() {
        let allocator = PortAllocator::new();
        let tracker = SessionTracker::new(allocator);

        let client_addr: SocketAddr = "192.168.1.100:12345".parse().unwrap();
        let conn_id = VlessConnectionId::new(client_addr);
        let handle1 = mock_socket_handle(1);
        let handle2 = mock_socket_handle(2);
        let key = SessionKey::new(
            IpAddr::V4(Ipv4Addr::new(10, 200, 200, 2)),
            50000,
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            80,
        );

        // First registration should succeed
        tracker.register_tcp(conn_id.clone(), handle1, key.clone()).unwrap();

        // Second registration with same key should fail
        let result = tracker.register_tcp(conn_id, handle2, key);
        assert!(matches!(result, Err(BridgeError::SessionAlreadyExists(_))));
    }

    #[test]
    fn test_udp_timeout_for_port() {
        let allocator = PortAllocator::new();
        let tracker = SessionTracker::new(allocator);

        // DNS port should have shorter timeout
        assert_eq!(tracker.udp_timeout_for_port(53), Duration::from_secs(10));

        // Other ports should have default timeout
        assert_eq!(tracker.udp_timeout_for_port(80), Duration::from_secs(30));
        assert_eq!(tracker.udp_timeout_for_port(443), Duration::from_secs(30));
        assert_eq!(tracker.udp_timeout_for_port(8080), Duration::from_secs(30));
    }

    #[test]
    fn test_debug_impls() {
        let allocator = PortAllocator::new();
        let tracker = SessionTracker::new(allocator);

        let debug = format!("{:?}", tracker);
        assert!(debug.contains("SessionTracker"));
        assert!(debug.contains("tcp_sessions"));
        assert!(debug.contains("udp_sessions"));

        let client_addr: SocketAddr = "192.168.1.100:12345".parse().unwrap();
        let conn_id = VlessConnectionId::new(client_addr);
        let handle = mock_socket_handle(1);
        let key = SessionKey::new(
            IpAddr::V4(Ipv4Addr::new(10, 200, 200, 2)),
            50000,
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            80,
        );

        let tcp_session = TcpSession::new(conn_id.clone(), handle, key.clone());
        let debug = format!("{:?}", tcp_session);
        assert!(debug.contains("TcpSession"));

        let udp_session = UdpSession::new(conn_id, handle, key);
        let debug = format!("{:?}", udp_session);
        assert!(debug.contains("UdpSession"));
    }
}
