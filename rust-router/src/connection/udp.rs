//! UDP session management with LRU eviction.
//!
//! This module provides UDP session tracking using a moka cache with
//! automatic LRU eviction, idle timeout, and TTL expiration.
//!
//! # Design
//!
//! UDP is connectionless, so we need to track "sessions" based on the
//! 5-tuple (protocol, `src_addr`, `src_port`, `dst_addr`, `dst_port`). For
//! transparent proxying, we use the client address and original destination.
//!
//! Sessions are cached with:
//! - **LRU eviction**: When max capacity is reached, least recently used sessions are evicted
//! - **Idle timeout**: Sessions expire after a period of inactivity
//! - **TTL**: Sessions have a maximum lifetime regardless of activity
//!
//! # Example
//!
//! ```
//! use rust_router::connection::udp::{UdpSessionManager, UdpSessionConfig, UdpSessionKey, UdpSession};
//! use std::net::{SocketAddr, IpAddr, Ipv4Addr};
//! use std::time::Instant;
//!
//! // Create session manager with default config
//! let manager = UdpSessionManager::new(UdpSessionConfig::default());
//!
//! // Create a session key
//! let client = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 12345);
//! let dest = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 443);
//! let key = UdpSessionKey::new(client, dest);
//!
//! // Get or create a session
//! let session = manager.get_or_create(key, || {
//!     UdpSession::new(key, "direct".to_string())
//! });
//!
//! assert_eq!(session.outbound, "direct");
//! ```

use std::hash::{Hash, Hasher};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use moka::sync::Cache;
use serde::{Deserialize, Serialize};

/// Key for UDP session lookup.
///
/// A session is uniquely identified by the client address (source)
/// and the original destination address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpSessionKey {
    /// Client address (source)
    pub client_addr: SocketAddr,
    /// Original destination address
    pub dest_addr: SocketAddr,
}

impl UdpSessionKey {
    /// Create a new UDP session key.
    #[must_use]
    pub const fn new(client_addr: SocketAddr, dest_addr: SocketAddr) -> Self {
        Self {
            client_addr,
            dest_addr,
        }
    }
}

impl Hash for UdpSessionKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.client_addr.hash(state);
        self.dest_addr.hash(state);
    }
}

/// UDP session state.
///
/// Contains routing information and statistics for a UDP session.
#[derive(Debug)]
pub struct UdpSession {
    /// Session key
    pub key: UdpSessionKey,
    /// Resolved outbound tag
    pub outbound: String,
    /// Routing mark (for chain routing / DSCP)
    pub routing_mark: Option<u32>,
    /// Sniffed domain (from QUIC SNI)
    pub sniffed_domain: Option<String>,
    /// Creation timestamp
    pub created_at: Instant,
    /// Bytes sent (client -> upstream)
    bytes_sent: AtomicU64,
    /// Bytes received (upstream -> client)
    bytes_recv: AtomicU64,
    /// Packet count sent
    packets_sent: AtomicU64,
    /// Packet count received
    packets_recv: AtomicU64,
}

impl UdpSession {
    /// Create a new UDP session.
    #[must_use]
    pub fn new(key: UdpSessionKey, outbound: String) -> Self {
        Self {
            key,
            outbound,
            routing_mark: None,
            sniffed_domain: None,
            created_at: Instant::now(),
            bytes_sent: AtomicU64::new(0),
            bytes_recv: AtomicU64::new(0),
            packets_sent: AtomicU64::new(0),
            packets_recv: AtomicU64::new(0),
        }
    }

    /// Create a new UDP session with routing mark.
    #[must_use]
    pub fn with_routing_mark(key: UdpSessionKey, outbound: String, routing_mark: u32) -> Self {
        Self {
            routing_mark: Some(routing_mark),
            ..Self::new(key, outbound)
        }
    }

    /// Create a new UDP session with sniffed domain.
    #[must_use]
    pub fn with_domain(key: UdpSessionKey, outbound: String, domain: String) -> Self {
        Self {
            sniffed_domain: Some(domain),
            ..Self::new(key, outbound)
        }
    }

    /// Update bytes sent (client -> upstream).
    pub fn add_bytes_sent(&self, bytes: u64) {
        self.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
        self.packets_sent.fetch_add(1, Ordering::Relaxed);
    }

    /// Update bytes received (upstream -> client).
    pub fn add_bytes_recv(&self, bytes: u64) {
        self.bytes_recv.fetch_add(bytes, Ordering::Relaxed);
        self.packets_recv.fetch_add(1, Ordering::Relaxed);
    }

    /// Get total bytes sent.
    #[must_use]
    pub fn bytes_sent(&self) -> u64 {
        self.bytes_sent.load(Ordering::Relaxed)
    }

    /// Get total bytes received.
    #[must_use]
    pub fn bytes_recv(&self) -> u64 {
        self.bytes_recv.load(Ordering::Relaxed)
    }

    /// Get total packets sent.
    #[must_use]
    pub fn packets_sent(&self) -> u64 {
        self.packets_sent.load(Ordering::Relaxed)
    }

    /// Get total packets received.
    #[must_use]
    pub fn packets_recv(&self) -> u64 {
        self.packets_recv.load(Ordering::Relaxed)
    }

    /// Get session age.
    #[must_use]
    pub fn age(&self) -> Duration {
        self.created_at.elapsed()
    }

    /// Get a snapshot of session statistics.
    #[must_use]
    pub fn snapshot(&self) -> UdpSessionSnapshot {
        UdpSessionSnapshot {
            client_addr: self.key.client_addr,
            dest_addr: self.key.dest_addr,
            outbound: self.outbound.clone(),
            routing_mark: self.routing_mark,
            sniffed_domain: self.sniffed_domain.clone(),
            bytes_sent: self.bytes_sent(),
            bytes_recv: self.bytes_recv(),
            packets_sent: self.packets_sent(),
            packets_recv: self.packets_recv(),
            age_secs: self.age().as_secs(),
        }
    }
}

/// Snapshot of UDP session state for serialization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UdpSessionSnapshot {
    /// Client address
    pub client_addr: SocketAddr,
    /// Destination address
    pub dest_addr: SocketAddr,
    /// Outbound tag
    pub outbound: String,
    /// Routing mark
    pub routing_mark: Option<u32>,
    /// Sniffed domain
    pub sniffed_domain: Option<String>,
    /// Bytes sent
    pub bytes_sent: u64,
    /// Bytes received
    pub bytes_recv: u64,
    /// Packets sent
    pub packets_sent: u64,
    /// Packets received
    pub packets_recv: u64,
    /// Session age in seconds
    pub age_secs: u64,
}

impl UdpSessionSnapshot {
    /// Get total bytes transferred.
    #[must_use]
    pub const fn total_bytes(&self) -> u64 {
        self.bytes_sent + self.bytes_recv
    }

    /// Get total packets transferred.
    #[must_use]
    pub const fn total_packets(&self) -> u64 {
        self.packets_sent + self.packets_recv
    }
}

/// Configuration for UDP session manager.
#[derive(Debug, Clone)]
pub struct UdpSessionConfig {
    /// Maximum number of sessions (LRU eviction when exceeded).
    pub max_sessions: u64,
    /// Session idle timeout.
    pub idle_timeout: Duration,
    /// Time-to-live for sessions.
    pub ttl: Duration,
}

impl Default for UdpSessionConfig {
    fn default() -> Self {
        Self {
            max_sessions: 65536,
            idle_timeout: Duration::from_secs(300), // 5 minutes
            ttl: Duration::from_secs(600),          // 10 minutes
        }
    }
}

impl UdpSessionConfig {
    /// Create a new configuration with custom values.
    #[must_use]
    pub const fn new(max_sessions: u64, idle_timeout: Duration, ttl: Duration) -> Self {
        Self {
            max_sessions,
            idle_timeout,
            ttl,
        }
    }

    /// Create a configuration for high-throughput scenarios.
    #[must_use]
    pub fn high_throughput() -> Self {
        Self {
            max_sessions: 262_144,                   // 256K sessions
            idle_timeout: Duration::from_secs(120), // 2 minutes
            ttl: Duration::from_secs(300),          // 5 minutes
        }
    }

    /// Create a configuration for low-memory scenarios.
    #[must_use]
    pub fn low_memory() -> Self {
        Self {
            max_sessions: 8192,
            idle_timeout: Duration::from_secs(60),
            ttl: Duration::from_secs(120),
        }
    }
}

/// UDP session manager using moka cache for LRU eviction.
///
/// This manager provides:
/// - O(1) session lookup
/// - Automatic LRU eviction when max capacity is reached
/// - Idle timeout for inactive sessions
/// - TTL expiration for all sessions
/// - Thread-safe concurrent access
pub struct UdpSessionManager {
    /// Session cache with LRU eviction
    sessions: Cache<UdpSessionKey, Arc<UdpSession>>,
    /// Configuration
    config: UdpSessionConfig,
    /// Total sessions created
    total_created: AtomicU64,
    /// Total sessions evicted
    total_evicted: AtomicU64,
}

impl UdpSessionManager {
    /// Create a new UDP session manager.
    #[must_use]
    pub fn new(config: UdpSessionConfig) -> Self {
        let evicted_counter = Arc::new(AtomicU64::new(0));
        let evicted_counter_clone = Arc::clone(&evicted_counter);

        let sessions = Cache::builder()
            .max_capacity(config.max_sessions)
            .time_to_idle(config.idle_timeout)
            .time_to_live(config.ttl)
            .eviction_listener(move |_key, _value, _cause| {
                evicted_counter_clone.fetch_add(1, Ordering::Relaxed);
            })
            .build();

        Self {
            sessions,
            config,
            total_created: AtomicU64::new(0),
            total_evicted: evicted_counter.load(Ordering::Relaxed).into(),
        }
    }

    /// Get or create a session for the given key.
    ///
    /// If a session exists, it is returned and its idle timer is reset.
    /// If no session exists, the `create` function is called to create one.
    pub fn get_or_create<F>(&self, key: UdpSessionKey, create: F) -> Arc<UdpSession>
    where
        F: FnOnce() -> UdpSession,
    {
        self.sessions.get_with(key, || {
            self.total_created.fetch_add(1, Ordering::Relaxed);
            Arc::new(create())
        })
    }

    /// Get an existing session without creating a new one.
    #[must_use]
    pub fn get(&self, key: &UdpSessionKey) -> Option<Arc<UdpSession>> {
        self.sessions.get(key)
    }

    /// Check if a session exists.
    #[must_use]
    pub fn contains(&self, key: &UdpSessionKey) -> bool {
        self.sessions.contains_key(key)
    }

    /// Remove a session explicitly.
    pub fn remove(&self, key: &UdpSessionKey) {
        self.sessions.invalidate(key);
    }

    /// Get current session count.
    ///
    /// Note: This is an estimate due to concurrent access.
    #[must_use]
    pub fn session_count(&self) -> u64 {
        self.sessions.entry_count()
    }

    /// Get weighted session count (if using weighted capacity).
    #[must_use]
    pub fn weighted_size(&self) -> u64 {
        self.sessions.weighted_size()
    }

    /// Get session manager statistics.
    #[must_use]
    pub fn stats(&self) -> UdpSessionStats {
        UdpSessionStats {
            session_count: self.sessions.entry_count(),
            max_sessions: self.config.max_sessions,
            total_created: self.total_created.load(Ordering::Relaxed),
            total_evicted: self.total_evicted.load(Ordering::Relaxed),
            idle_timeout_secs: self.config.idle_timeout.as_secs(),
            ttl_secs: self.config.ttl.as_secs(),
        }
    }

    /// Iterate over all sessions (for diagnostic purposes).
    ///
    /// Warning: This creates a snapshot and may be expensive for large caches.
    pub fn for_each<F>(&self, f: F)
    where
        F: FnMut(Arc<UdpSession>),
    {
        self.sessions.iter().map(|(_, v)| v).for_each(f);
    }

    /// Get snapshots of all sessions.
    #[must_use]
    pub fn all_sessions(&self) -> Vec<UdpSessionSnapshot> {
        self.sessions
            .iter()
            .map(|(_, session)| session.snapshot())
            .collect()
    }

    /// Run pending maintenance tasks.
    ///
    /// This triggers eviction of expired entries. Normally this happens
    /// automatically, but can be called manually if needed.
    pub fn run_pending_tasks(&self) {
        self.sessions.run_pending_tasks();
    }

    /// Invalidate all sessions.
    pub fn clear(&self) {
        self.sessions.invalidate_all();
    }
}

impl std::fmt::Debug for UdpSessionManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpSessionManager")
            .field("session_count", &self.session_count())
            .field("total_created", &self.total_created.load(std::sync::atomic::Ordering::Relaxed))
            .field("total_evicted", &self.total_evicted.load(std::sync::atomic::Ordering::Relaxed))
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

/// Statistics for UDP session manager.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UdpSessionStats {
    /// Current number of sessions
    pub session_count: u64,
    /// Maximum allowed sessions
    pub max_sessions: u64,
    /// Total sessions created
    pub total_created: u64,
    /// Total sessions evicted (by LRU, idle timeout, or TTL)
    pub total_evicted: u64,
    /// Idle timeout in seconds
    pub idle_timeout_secs: u64,
    /// TTL in seconds
    pub ttl_secs: u64,
}

impl UdpSessionStats {
    /// Get cache utilization as a percentage.
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn utilization(&self) -> f64 {
        if self.max_sessions == 0 {
            0.0
        } else {
            (self.session_count as f64 / self.max_sessions as f64) * 100.0
        }
    }

    /// Check if cache is at capacity.
    #[must_use]
    pub const fn is_at_capacity(&self) -> bool {
        self.session_count >= self.max_sessions
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::thread;

    fn test_addr_v4(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), port)
    }

    fn test_addr_v6(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)), port)
    }

    fn dest_addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 443)
    }

    // === UdpSessionKey Tests ===

    #[test]
    fn test_session_key_creation() {
        let client = test_addr_v4(12345);
        let dest = dest_addr();
        let key = UdpSessionKey::new(client, dest);

        assert_eq!(key.client_addr, client);
        assert_eq!(key.dest_addr, dest);
    }

    #[test]
    fn test_session_key_equality() {
        let client = test_addr_v4(12345);
        let dest = dest_addr();

        let key1 = UdpSessionKey::new(client, dest);
        let key2 = UdpSessionKey::new(client, dest);

        assert_eq!(key1, key2);
    }

    #[test]
    fn test_session_key_inequality_different_client() {
        let dest = dest_addr();
        let key1 = UdpSessionKey::new(test_addr_v4(12345), dest);
        let key2 = UdpSessionKey::new(test_addr_v4(12346), dest);

        assert_ne!(key1, key2);
    }

    #[test]
    fn test_session_key_inequality_different_dest() {
        let client = test_addr_v4(12345);
        let key1 = UdpSessionKey::new(client, dest_addr());
        let key2 = UdpSessionKey::new(
            client,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 443),
        );

        assert_ne!(key1, key2);
    }

    #[test]
    fn test_session_key_hash_consistency() {
        use std::collections::hash_map::DefaultHasher;

        let client = test_addr_v4(12345);
        let dest = dest_addr();
        let key1 = UdpSessionKey::new(client, dest);
        let key2 = UdpSessionKey::new(client, dest);

        let mut hasher1 = DefaultHasher::new();
        let mut hasher2 = DefaultHasher::new();
        key1.hash(&mut hasher1);
        key2.hash(&mut hasher2);

        assert_eq!(hasher1.finish(), hasher2.finish());
    }

    #[test]
    fn test_session_key_ipv6() {
        let client = test_addr_v6(12345);
        let dest = test_addr_v6(443);
        let key = UdpSessionKey::new(client, dest);

        assert_eq!(key.client_addr, client);
        assert_eq!(key.dest_addr, dest);
    }

    // === UdpSession Tests ===

    #[test]
    fn test_session_creation() {
        let key = UdpSessionKey::new(test_addr_v4(12345), dest_addr());
        let session = UdpSession::new(key, "direct".to_string());

        assert_eq!(session.outbound, "direct");
        assert!(session.routing_mark.is_none());
        assert!(session.sniffed_domain.is_none());
        assert_eq!(session.bytes_sent(), 0);
        assert_eq!(session.bytes_recv(), 0);
    }

    #[test]
    fn test_session_with_routing_mark() {
        let key = UdpSessionKey::new(test_addr_v4(12345), dest_addr());
        let session = UdpSession::with_routing_mark(key, "chain".to_string(), 200);

        assert_eq!(session.outbound, "chain");
        assert_eq!(session.routing_mark, Some(200));
    }

    #[test]
    fn test_session_with_domain() {
        let key = UdpSessionKey::new(test_addr_v4(12345), dest_addr());
        let session = UdpSession::with_domain(key, "direct".to_string(), "example.com".to_string());

        assert_eq!(session.sniffed_domain, Some("example.com".to_string()));
    }

    #[test]
    fn test_session_bytes_tracking() {
        let key = UdpSessionKey::new(test_addr_v4(12345), dest_addr());
        let session = UdpSession::new(key, "direct".to_string());

        session.add_bytes_sent(100);
        session.add_bytes_sent(200);
        session.add_bytes_recv(50);

        assert_eq!(session.bytes_sent(), 300);
        assert_eq!(session.bytes_recv(), 50);
        assert_eq!(session.packets_sent(), 2);
        assert_eq!(session.packets_recv(), 1);
    }

    #[test]
    fn test_session_snapshot() {
        let key = UdpSessionKey::new(test_addr_v4(12345), dest_addr());
        let session = UdpSession::with_domain(key, "us-west".to_string(), "google.com".to_string());
        session.add_bytes_sent(1000);
        session.add_bytes_recv(500);

        let snapshot = session.snapshot();

        assert_eq!(snapshot.client_addr, key.client_addr);
        assert_eq!(snapshot.dest_addr, key.dest_addr);
        assert_eq!(snapshot.outbound, "us-west");
        assert_eq!(snapshot.sniffed_domain, Some("google.com".to_string()));
        assert_eq!(snapshot.bytes_sent, 1000);
        assert_eq!(snapshot.bytes_recv, 500);
        assert_eq!(snapshot.total_bytes(), 1500);
        assert_eq!(snapshot.packets_sent, 1);
        assert_eq!(snapshot.packets_recv, 1);
        assert_eq!(snapshot.total_packets(), 2);
    }

    // === UdpSessionConfig Tests ===

    #[test]
    fn test_config_default() {
        let config = UdpSessionConfig::default();

        assert_eq!(config.max_sessions, 65536);
        assert_eq!(config.idle_timeout, Duration::from_secs(300));
        assert_eq!(config.ttl, Duration::from_secs(600));
    }

    #[test]
    fn test_config_high_throughput() {
        let config = UdpSessionConfig::high_throughput();

        assert_eq!(config.max_sessions, 262_144);
        assert_eq!(config.idle_timeout, Duration::from_secs(120));
        assert_eq!(config.ttl, Duration::from_secs(300));
    }

    #[test]
    fn test_config_low_memory() {
        let config = UdpSessionConfig::low_memory();

        assert_eq!(config.max_sessions, 8192);
        assert_eq!(config.idle_timeout, Duration::from_secs(60));
        assert_eq!(config.ttl, Duration::from_secs(120));
    }

    #[test]
    fn test_config_custom() {
        let config = UdpSessionConfig::new(1000, Duration::from_secs(30), Duration::from_secs(60));

        assert_eq!(config.max_sessions, 1000);
        assert_eq!(config.idle_timeout, Duration::from_secs(30));
        assert_eq!(config.ttl, Duration::from_secs(60));
    }

    // === UdpSessionManager Tests ===

    #[test]
    fn test_manager_creation() {
        let manager = UdpSessionManager::new(UdpSessionConfig::default());

        assert_eq!(manager.session_count(), 0);
    }

    #[test]
    fn test_manager_get_or_create() {
        let manager = UdpSessionManager::new(UdpSessionConfig::default());
        let key = UdpSessionKey::new(test_addr_v4(12345), dest_addr());

        let session = manager.get_or_create(key, || UdpSession::new(key, "direct".to_string()));

        assert_eq!(session.outbound, "direct");
        // Sync pending tasks for accurate count
        manager.run_pending_tasks();
        assert_eq!(manager.session_count(), 1);
    }

    #[test]
    fn test_manager_get_existing() {
        let manager = UdpSessionManager::new(UdpSessionConfig::default());
        let key = UdpSessionKey::new(test_addr_v4(12345), dest_addr());

        // Create session
        let session1 = manager.get_or_create(key, || UdpSession::new(key, "direct".to_string()));

        // Get existing session
        let session2 = manager.get(&key);

        assert!(session2.is_some());
        assert!(Arc::ptr_eq(&session1, &session2.unwrap()));
    }

    #[test]
    fn test_manager_get_nonexistent() {
        let manager = UdpSessionManager::new(UdpSessionConfig::default());
        let key = UdpSessionKey::new(test_addr_v4(12345), dest_addr());

        assert!(manager.get(&key).is_none());
    }

    #[test]
    fn test_manager_contains() {
        let manager = UdpSessionManager::new(UdpSessionConfig::default());
        let key = UdpSessionKey::new(test_addr_v4(12345), dest_addr());

        assert!(!manager.contains(&key));

        manager.get_or_create(key, || UdpSession::new(key, "direct".to_string()));

        assert!(manager.contains(&key));
    }

    #[test]
    fn test_manager_remove() {
        let manager = UdpSessionManager::new(UdpSessionConfig::default());
        let key = UdpSessionKey::new(test_addr_v4(12345), dest_addr());

        manager.get_or_create(key, || UdpSession::new(key, "direct".to_string()));
        assert!(manager.contains(&key));

        manager.remove(&key);
        // Run pending tasks to ensure removal is processed
        manager.run_pending_tasks();

        assert!(!manager.contains(&key));
    }

    #[test]
    fn test_manager_multiple_sessions() {
        let manager = UdpSessionManager::new(UdpSessionConfig::default());

        // Create multiple sessions
        for i in 0..100 {
            let key = UdpSessionKey::new(test_addr_v4(12345 + i), dest_addr());
            manager.get_or_create(key, || UdpSession::new(key, format!("out-{i}")));
        }

        // Sync pending tasks for accurate count
        manager.run_pending_tasks();
        assert_eq!(manager.session_count(), 100);
    }

    #[test]
    fn test_manager_lru_eviction() {
        // Small cache to test eviction
        let config = UdpSessionConfig::new(
            10,
            Duration::from_secs(300),
            Duration::from_secs(600),
        );
        let manager = UdpSessionManager::new(config);

        // Create 20 sessions (exceeds capacity)
        for i in 0..20u16 {
            let key = UdpSessionKey::new(test_addr_v4(12345 + i), dest_addr());
            manager.get_or_create(key, || UdpSession::new(key, format!("out-{i}")));
        }

        // Run pending tasks to ensure eviction is processed
        manager.run_pending_tasks();

        // Should have at most max_sessions
        assert!(manager.session_count() <= 10);
    }

    #[test]
    fn test_manager_stats() {
        let config = UdpSessionConfig::new(
            100,
            Duration::from_secs(60),
            Duration::from_secs(120),
        );
        let manager = UdpSessionManager::new(config);

        let key = UdpSessionKey::new(test_addr_v4(12345), dest_addr());
        manager.get_or_create(key, || UdpSession::new(key, "direct".to_string()));

        // Sync pending tasks for accurate count
        manager.run_pending_tasks();
        let stats = manager.stats();

        assert_eq!(stats.session_count, 1);
        assert_eq!(stats.max_sessions, 100);
        assert_eq!(stats.total_created, 1);
        assert_eq!(stats.idle_timeout_secs, 60);
        assert_eq!(stats.ttl_secs, 120);
    }

    #[test]
    fn test_manager_clear() {
        let manager = UdpSessionManager::new(UdpSessionConfig::default());

        // Create some sessions
        for i in 0..10u16 {
            let key = UdpSessionKey::new(test_addr_v4(12345 + i), dest_addr());
            manager.get_or_create(key, || UdpSession::new(key, format!("out-{i}")));
        }

        // Sync pending tasks for accurate count
        manager.run_pending_tasks();
        assert_eq!(manager.session_count(), 10);

        manager.clear();
        manager.run_pending_tasks();

        assert_eq!(manager.session_count(), 0);
    }

    #[test]
    fn test_manager_all_sessions() {
        let manager = UdpSessionManager::new(UdpSessionConfig::default());

        // Create sessions
        for i in 0..5u16 {
            let key = UdpSessionKey::new(test_addr_v4(12345 + i), dest_addr());
            manager.get_or_create(key, || UdpSession::new(key, format!("out-{i}")));
        }

        let sessions = manager.all_sessions();

        assert_eq!(sessions.len(), 5);
    }

    #[test]
    fn test_manager_debug_impl() {
        let manager = UdpSessionManager::new(UdpSessionConfig::default());
        let debug_str = format!("{manager:?}");

        assert!(debug_str.contains("UdpSessionManager"));
        assert!(debug_str.contains("session_count"));
    }

    // === UdpSessionStats Tests ===

    #[test]
    fn test_stats_utilization() {
        let stats = UdpSessionStats {
            session_count: 50,
            max_sessions: 100,
            total_created: 50,
            total_evicted: 0,
            idle_timeout_secs: 300,
            ttl_secs: 600,
        };

        assert!((stats.utilization() - 50.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_stats_utilization_zero_max() {
        let stats = UdpSessionStats {
            session_count: 0,
            max_sessions: 0,
            total_created: 0,
            total_evicted: 0,
            idle_timeout_secs: 300,
            ttl_secs: 600,
        };

        assert!((stats.utilization() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_stats_at_capacity() {
        let stats = UdpSessionStats {
            session_count: 100,
            max_sessions: 100,
            total_created: 150,
            total_evicted: 50,
            idle_timeout_secs: 300,
            ttl_secs: 600,
        };

        assert!(stats.is_at_capacity());
    }

    #[test]
    fn test_stats_not_at_capacity() {
        let stats = UdpSessionStats {
            session_count: 50,
            max_sessions: 100,
            total_created: 50,
            total_evicted: 0,
            idle_timeout_secs: 300,
            ttl_secs: 600,
        };

        assert!(!stats.is_at_capacity());
    }

    // === Concurrent Access Tests ===

    #[test]
    fn test_concurrent_access() {
        let manager = Arc::new(UdpSessionManager::new(UdpSessionConfig::default()));
        let mut handles = vec![];

        // Spawn multiple threads accessing the manager
        for thread_id in 0..4 {
            let manager_clone = Arc::clone(&manager);
            let handle = thread::spawn(move || {
                for i in 0..100u16 {
                    let port = (thread_id * 1000 + i) as u16 + 10000;
                    let key = UdpSessionKey::new(test_addr_v4(port), dest_addr());
                    let session =
                        manager_clone.get_or_create(key, || UdpSession::new(key, "direct".into()));
                    session.add_bytes_sent(100);
                }
            });
            handles.push(handle);
        }

        // Wait for all threads
        for handle in handles {
            handle.join().unwrap();
        }

        // Sync pending tasks for accurate count
        manager.run_pending_tasks();
        // Should have all sessions
        assert_eq!(manager.session_count(), 400);
    }

    // === Serialization Tests ===

    #[test]
    fn test_session_snapshot_serialization() {
        let snapshot = UdpSessionSnapshot {
            client_addr: test_addr_v4(12345),
            dest_addr: dest_addr(),
            outbound: "direct".to_string(),
            routing_mark: Some(200),
            sniffed_domain: Some("example.com".to_string()),
            bytes_sent: 1000,
            bytes_recv: 500,
            packets_sent: 10,
            packets_recv: 5,
            age_secs: 60,
        };

        let json = serde_json::to_string(&snapshot).unwrap();
        let parsed: UdpSessionSnapshot = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.outbound, snapshot.outbound);
        assert_eq!(parsed.routing_mark, snapshot.routing_mark);
        assert_eq!(parsed.bytes_sent, snapshot.bytes_sent);
    }

    #[test]
    fn test_stats_serialization() {
        let stats = UdpSessionStats {
            session_count: 100,
            max_sessions: 1000,
            total_created: 150,
            total_evicted: 50,
            idle_timeout_secs: 300,
            ttl_secs: 600,
        };

        let json = serde_json::to_string(&stats).unwrap();
        let parsed: UdpSessionStats = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.session_count, stats.session_count);
        assert_eq!(parsed.max_sessions, stats.max_sessions);
    }
}
