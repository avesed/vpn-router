//! Per-client DNS Rate Limiting
//!
//! This module implements per-client rate limiting using the governor crate's
//! token bucket algorithm. Each client IP address gets its own rate limiter
//! with configurable QPS and burst limits.
//!
//! # Architecture
//!
//! ```text
//! Client Request
//!     |
//!     v
//! DnsRateLimiter
//!     |
//!     +-- DashMap<IpAddr, RateLimiter>
//!     |       |
//!     |       +-- Per-client token bucket
//!     |
//!     v
//! check() -> Ok(()) or Err(RateLimitExceeded)
//! ```
//!
//! # Features
//!
//! - **Per-client limiting**: Each client IP gets independent rate limits
//! - **Token bucket algorithm**: Allows short bursts while enforcing average rate
//! - **Automatic cleanup**: Stale entries can be removed to prevent memory growth
//! - **Lock-free reads**: Using DashMap for high concurrency
//!
//! # Example
//!
//! ```
//! use rust_router::dns::server::DnsRateLimiter;
//! use rust_router::dns::RateLimitConfig;
//! use std::net::IpAddr;
//!
//! let config = RateLimitConfig::default()
//!     .with_qps(100)
//!     .with_burst(200);
//!
//! let limiter = DnsRateLimiter::new(&config);
//!
//! let client: IpAddr = "192.168.1.100".parse().unwrap();
//!
//! // First request should succeed
//! assert!(limiter.check(client).is_ok());
//! ```

use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use governor::clock::DefaultClock;
use governor::state::{InMemoryState, NotKeyed};
use governor::{Quota, RateLimiter};

use crate::dns::config::RateLimitConfig;
use crate::dns::error::{DnsError, DnsResult};

/// Type alias for a single-key rate limiter
type ClientRateLimiter = RateLimiter<NotKeyed, InMemoryState, DefaultClock>;

/// Per-client entry in the rate limiter map
struct RateLimiterEntry {
    /// The rate limiter for this client
    limiter: ClientRateLimiter,
    /// Last access time for cleanup and LRU eviction
    last_access: std::sync::atomic::AtomicU64,
    /// Total requests from this client
    request_count: AtomicU64,
    /// Rejected requests from this client
    rejected_count: AtomicU64,
    /// Creation timestamp (for age calculation)
    created_at: Instant,
}

impl RateLimiterEntry {
    /// Create a new rate limiter entry with the given quota
    fn new(quota: Quota) -> Self {
        let now = Instant::now();
        Self {
            limiter: RateLimiter::direct(quota),
            last_access: std::sync::atomic::AtomicU64::new(0),
            request_count: AtomicU64::new(0),
            rejected_count: AtomicU64::new(0),
            created_at: now,
        }
    }

    /// Update last access time
    fn touch(&self) {
        let elapsed = self.created_at.elapsed().as_millis() as u64;
        self.last_access.store(elapsed, Ordering::Relaxed);
    }

    /// Get elapsed time since last access in milliseconds
    fn last_access_elapsed_ms(&self) -> u64 {
        let current = self.created_at.elapsed().as_millis() as u64;
        let last = self.last_access.load(Ordering::Relaxed);
        current.saturating_sub(last)
    }

    /// Check if this entry is stale
    fn is_stale(&self, max_age: Duration) -> bool {
        self.last_access_elapsed_ms() > max_age.as_millis() as u64
    }
}

/// Default maximum number of tracked clients
const DEFAULT_MAX_CLIENTS: usize = 100_000;

/// Default cleanup interval in seconds
const DEFAULT_CLEANUP_INTERVAL_SECS: u64 = 300;

/// Per-client DNS rate limiter
///
/// Uses a `DashMap` to store per-client rate limiters, providing
/// lock-free reads and fine-grained locking for writes.
///
/// # Thread Safety
///
/// This struct is `Send` and `Sync`, safe to share across threads.
///
/// # Memory Management
///
/// The rate limiter enforces a maximum number of tracked clients (`max_clients`).
/// When this limit is exceeded, the oldest entries are evicted (LRU-style).
/// Call [`cleanup_stale`](Self::cleanup_stale) periodically to remove
/// entries for clients that haven't made requests recently.
pub struct DnsRateLimiter {
    /// Per-client rate limiters
    limiters: DashMap<IpAddr, RateLimiterEntry>,
    /// Quota for new clients
    quota: Quota,
    /// Whether rate limiting is enabled
    enabled: bool,
    /// Statistics
    stats: RateLimiterStats,
    /// QPS limit (for error messages)
    qps_limit: u32,
    /// Maximum number of tracked clients (prevents unbounded memory growth)
    max_clients: usize,
    /// Cleanup interval in seconds (for periodic stale entry removal)
    cleanup_interval_secs: u64,
}

/// Statistics for the rate limiter
#[derive(Debug, Default)]
pub struct RateLimiterStats {
    /// Total requests checked
    total_requests: AtomicU64,
    /// Requests that passed rate limiting
    allowed_requests: AtomicU64,
    /// Requests that were rejected
    rejected_requests: AtomicU64,
    /// Number of unique clients seen
    unique_clients: AtomicU64,
    /// Stale entries cleaned up
    entries_cleaned: AtomicU64,
    /// Entries evicted due to max_clients limit (LRU eviction)
    entries_evicted: AtomicU64,
}

impl RateLimiterStats {
    /// Create new stats instance
    pub fn new() -> Self {
        Self::default()
    }

    /// Get total requests checked
    #[must_use]
    pub fn total_requests(&self) -> u64 {
        self.total_requests.load(Ordering::Relaxed)
    }

    /// Get allowed requests count
    #[must_use]
    pub fn allowed_requests(&self) -> u64 {
        self.allowed_requests.load(Ordering::Relaxed)
    }

    /// Get rejected requests count
    #[must_use]
    pub fn rejected_requests(&self) -> u64 {
        self.rejected_requests.load(Ordering::Relaxed)
    }

    /// Get unique clients count
    #[must_use]
    pub fn unique_clients(&self) -> u64 {
        self.unique_clients.load(Ordering::Relaxed)
    }

    /// Get cleaned entries count
    #[must_use]
    pub fn entries_cleaned(&self) -> u64 {
        self.entries_cleaned.load(Ordering::Relaxed)
    }

    /// Get evicted entries count (LRU eviction when max_clients exceeded)
    #[must_use]
    pub fn entries_evicted(&self) -> u64 {
        self.entries_evicted.load(Ordering::Relaxed)
    }

    /// Get rejection rate (rejected / total)
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn rejection_rate(&self) -> f64 {
        let total = self.total_requests();
        if total == 0 {
            return 0.0;
        }
        self.rejected_requests() as f64 / total as f64
    }

    /// Get a snapshot of all stats
    #[must_use]
    pub fn snapshot(&self) -> RateLimiterStatsSnapshot {
        RateLimiterStatsSnapshot {
            total_requests: self.total_requests(),
            allowed_requests: self.allowed_requests(),
            rejected_requests: self.rejected_requests(),
            unique_clients: self.unique_clients(),
            entries_cleaned: self.entries_cleaned(),
            entries_evicted: self.entries_evicted(),
        }
    }
}

/// Snapshot of rate limiter statistics
#[derive(Debug, Clone, Copy)]
pub struct RateLimiterStatsSnapshot {
    /// Total requests checked
    pub total_requests: u64,
    /// Requests that passed
    pub allowed_requests: u64,
    /// Requests that were rejected
    pub rejected_requests: u64,
    /// Unique clients seen
    pub unique_clients: u64,
    /// Stale entries cleaned
    pub entries_cleaned: u64,
    /// Entries evicted due to max_clients limit
    pub entries_evicted: u64,
}

impl RateLimiterStatsSnapshot {
    /// Get rejection rate
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn rejection_rate(&self) -> f64 {
        if self.total_requests == 0 {
            return 0.0;
        }
        self.rejected_requests as f64 / self.total_requests as f64
    }
}

impl DnsRateLimiter {
    /// Create a new rate limiter from configuration
    ///
    /// # Arguments
    ///
    /// * `config` - Rate limit configuration
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::dns::server::DnsRateLimiter;
    /// use rust_router::dns::RateLimitConfig;
    ///
    /// let config = RateLimitConfig::default();
    /// let limiter = DnsRateLimiter::new(&config);
    /// ```
    #[must_use]
    pub fn new(config: &RateLimitConfig) -> Self {
        Self::with_limits(config, DEFAULT_MAX_CLIENTS, DEFAULT_CLEANUP_INTERVAL_SECS)
    }

    /// Create a new rate limiter with custom memory limits
    ///
    /// # Arguments
    ///
    /// * `config` - Rate limit configuration
    /// * `max_clients` - Maximum number of tracked clients (LRU eviction when exceeded)
    /// * `cleanup_interval_secs` - Cleanup interval in seconds
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::dns::server::DnsRateLimiter;
    /// use rust_router::dns::RateLimitConfig;
    ///
    /// // Limit to 10000 clients with 60 second cleanup interval
    /// let limiter = DnsRateLimiter::with_limits(
    ///     &RateLimitConfig::default(),
    ///     10000,
    ///     60
    /// );
    /// ```
    #[must_use]
    pub fn with_limits(config: &RateLimitConfig, max_clients: usize, cleanup_interval_secs: u64) -> Self {
        // Create quota from config
        // NonZeroU32 requires the value to be at least 1
        let qps = NonZeroU32::new(config.qps_per_client.max(1)).expect("qps must be at least 1");
        let burst = NonZeroU32::new(config.burst_size.max(1)).expect("burst must be at least 1");

        let quota = Quota::per_second(qps).allow_burst(burst);

        Self {
            limiters: DashMap::new(),
            quota,
            enabled: config.enabled,
            stats: RateLimiterStats::new(),
            qps_limit: config.qps_per_client,
            max_clients: max_clients.max(1), // Ensure at least 1
            cleanup_interval_secs,
        }
    }

    /// Create a disabled rate limiter (always allows requests)
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::dns::server::DnsRateLimiter;
    /// use std::net::IpAddr;
    ///
    /// let limiter = DnsRateLimiter::disabled();
    /// let client: IpAddr = "192.168.1.1".parse().unwrap();
    ///
    /// // Always succeeds when disabled
    /// assert!(limiter.check(client).is_ok());
    /// ```
    #[must_use]
    pub fn disabled() -> Self {
        let config = RateLimitConfig::default().disabled();
        Self::new(&config)
    }

    /// Check if a client is within their rate limit
    ///
    /// If the rate limit is exceeded, returns `DnsError::RateLimitExceeded`.
    ///
    /// # Arguments
    ///
    /// * `client` - Client IP address
    ///
    /// # Returns
    ///
    /// - `Ok(())` if the request is allowed
    /// - `Err(DnsError::RateLimitExceeded)` if rate limit exceeded
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::dns::server::DnsRateLimiter;
    /// use rust_router::dns::RateLimitConfig;
    /// use std::net::IpAddr;
    ///
    /// let limiter = DnsRateLimiter::new(&RateLimitConfig::default());
    /// let client: IpAddr = "10.0.0.1".parse().unwrap();
    ///
    /// match limiter.check(client) {
    ///     Ok(()) => println!("Request allowed"),
    ///     Err(e) => println!("Rate limited: {}", e),
    /// }
    /// ```
    pub fn check(&self, client: IpAddr) -> DnsResult<()> {
        self.stats.total_requests.fetch_add(1, Ordering::Relaxed);

        // Skip checking if rate limiting is disabled
        if !self.enabled {
            self.stats.allowed_requests.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }

        // Check if we need LRU eviction before adding a new client
        let is_new = !self.limiters.contains_key(&client);
        if is_new && self.limiters.len() >= self.max_clients {
            self.evict_oldest_entry();
        }

        let entry = self.limiters.entry(client).or_insert_with(|| {
            self.stats.unique_clients.fetch_add(1, Ordering::Relaxed);
            RateLimiterEntry::new(self.quota)
        });

        // Update access time (for LRU tracking) and request count
        entry.touch();
        entry.request_count.fetch_add(1, Ordering::Relaxed);

        // Check rate limit
        match entry.limiter.check() {
            Ok(()) => {
                self.stats.allowed_requests.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Err(_) => {
                self.stats.rejected_requests.fetch_add(1, Ordering::Relaxed);
                entry.rejected_count.fetch_add(1, Ordering::Relaxed);

                // Create a socket address for error reporting
                // Use port 0 since we only have IP
                let socket_addr = std::net::SocketAddr::new(client, 0);

                Err(DnsError::rate_limit(
                    socket_addr,
                    self.qps_limit, // Current rate (approximate)
                    self.qps_limit,
                ))
            }
        }
    }

    /// Evict the oldest (least recently used) entry to make room for new clients
    ///
    /// This method finds the entry with the oldest last_access time and removes it.
    fn evict_oldest_entry(&self) {
        let mut oldest_ip: Option<IpAddr> = None;
        let mut oldest_time: u64 = 0;

        // Find the oldest entry
        for entry in self.limiters.iter() {
            let elapsed = entry.value().last_access_elapsed_ms();
            if oldest_ip.is_none() || elapsed > oldest_time {
                oldest_ip = Some(*entry.key());
                oldest_time = elapsed;
            }
        }

        // Remove the oldest entry
        if let Some(ip) = oldest_ip {
            if self.limiters.remove(&ip).is_some() {
                self.stats.entries_evicted.fetch_add(1, Ordering::Relaxed);
                tracing::debug!(
                    evicted_ip = %ip,
                    idle_ms = oldest_time,
                    "Evicted oldest rate limiter entry (LRU)"
                );
            }
        }
    }

    /// Check if a client is within their rate limit (async version)
    ///
    /// This is a convenience wrapper for async contexts.
    pub async fn check_async(&self, client: IpAddr) -> DnsResult<()> {
        self.check(client)
    }

    /// Remove stale entries from the rate limiter map
    ///
    /// Entries that haven't been accessed for longer than `max_age` are removed.
    /// This should be called periodically to prevent memory growth.
    ///
    /// # Arguments
    ///
    /// * `max_age` - Maximum age for entries before cleanup
    ///
    /// # Returns
    ///
    /// Number of entries removed
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::dns::server::DnsRateLimiter;
    /// use rust_router::dns::RateLimitConfig;
    /// use std::time::Duration;
    ///
    /// let limiter = DnsRateLimiter::new(&RateLimitConfig::default());
    ///
    /// // Clean up entries older than 5 minutes
    /// let removed = limiter.cleanup_stale(Duration::from_secs(300));
    /// println!("Removed {} stale entries", removed);
    /// ```
    pub fn cleanup_stale(&self, max_age: Duration) -> usize {
        let mut removed = 0;

        // Collect stale keys first to avoid holding locks
        let stale_keys: Vec<IpAddr> = self
            .limiters
            .iter()
            .filter(|entry| entry.value().is_stale(max_age))
            .map(|entry| *entry.key())
            .collect();

        // Remove stale entries
        for key in stale_keys {
            if self.limiters.remove(&key).is_some() {
                removed += 1;
            }
        }

        self.stats
            .entries_cleaned
            .fetch_add(removed as u64, Ordering::Relaxed);

        removed
    }

    /// Get the number of tracked clients
    #[must_use]
    pub fn client_count(&self) -> usize {
        self.limiters.len()
    }

    /// Check if rate limiting is enabled
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Get statistics for the rate limiter
    #[must_use]
    pub fn stats(&self) -> &RateLimiterStats {
        &self.stats
    }

    /// Get the configured QPS limit
    #[must_use]
    pub fn qps_limit(&self) -> u32 {
        self.qps_limit
    }

    /// Get the maximum number of tracked clients
    #[must_use]
    pub fn max_clients(&self) -> usize {
        self.max_clients
    }

    /// Get the cleanup interval in seconds
    #[must_use]
    pub fn cleanup_interval_secs(&self) -> u64 {
        self.cleanup_interval_secs
    }

    /// Get request stats for a specific client
    #[must_use]
    pub fn client_stats(&self, client: IpAddr) -> Option<ClientStats> {
        self.limiters.get(&client).map(|entry| ClientStats {
            request_count: entry.request_count.load(Ordering::Relaxed),
            rejected_count: entry.rejected_count.load(Ordering::Relaxed),
        })
    }

    /// Clear all rate limiter entries
    ///
    /// This resets all client tracking. Useful for testing or
    /// when configuration changes.
    pub fn clear(&self) {
        self.limiters.clear();
    }
}

/// Statistics for a specific client
#[derive(Debug, Clone, Copy)]
pub struct ClientStats {
    /// Total requests from this client
    pub request_count: u64,
    /// Rejected requests from this client
    pub rejected_count: u64,
}

impl ClientStats {
    /// Get rejection rate for this client
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn rejection_rate(&self) -> f64 {
        if self.request_count == 0 {
            return 0.0;
        }
        self.rejected_count as f64 / self.request_count as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::thread;
    use std::time::Duration;

    fn test_ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, last))
    }

    // ========================================================================
    // Creation Tests
    // ========================================================================

    #[test]
    fn test_new_with_default_config() {
        let config = RateLimitConfig::default();
        let limiter = DnsRateLimiter::new(&config);

        assert!(limiter.is_enabled());
        assert_eq!(limiter.qps_limit(), 100);
        assert_eq!(limiter.client_count(), 0);
    }

    #[test]
    fn test_new_with_custom_config() {
        let config = RateLimitConfig::default().with_qps(50).with_burst(100);

        let limiter = DnsRateLimiter::new(&config);

        assert!(limiter.is_enabled());
        assert_eq!(limiter.qps_limit(), 50);
    }

    #[test]
    fn test_disabled_limiter() {
        let limiter = DnsRateLimiter::disabled();

        assert!(!limiter.is_enabled());
    }

    #[test]
    fn test_disabled_from_config() {
        let config = RateLimitConfig::default().disabled();
        let limiter = DnsRateLimiter::new(&config);

        assert!(!limiter.is_enabled());
    }

    // ========================================================================
    // Basic Check Tests
    // ========================================================================

    #[test]
    fn test_check_first_request_allowed() {
        let config = RateLimitConfig::default();
        let limiter = DnsRateLimiter::new(&config);
        let client = test_ip(1);

        let result = limiter.check(client);
        assert!(result.is_ok());
    }

    #[test]
    fn test_check_disabled_always_allows() {
        let limiter = DnsRateLimiter::disabled();
        let client = test_ip(1);

        // Should always succeed when disabled
        for _ in 0..1000 {
            assert!(limiter.check(client).is_ok());
        }
    }

    #[test]
    fn test_check_creates_client_entry() {
        let config = RateLimitConfig::default();
        let limiter = DnsRateLimiter::new(&config);

        assert_eq!(limiter.client_count(), 0);

        let client = test_ip(1);
        let _ = limiter.check(client);

        assert_eq!(limiter.client_count(), 1);
    }

    #[test]
    fn test_check_multiple_clients() {
        let config = RateLimitConfig::default();
        let limiter = DnsRateLimiter::new(&config);

        for i in 1..=10 {
            let client = test_ip(i);
            let _ = limiter.check(client);
        }

        assert_eq!(limiter.client_count(), 10);
    }

    // ========================================================================
    // Rate Limiting Tests
    // ========================================================================

    #[test]
    fn test_burst_allowed() {
        // Allow 10 qps with burst of 20
        let config = RateLimitConfig::default().with_qps(10).with_burst(20);

        let limiter = DnsRateLimiter::new(&config);
        let client = test_ip(1);

        // First 20 requests (burst) should succeed
        let mut allowed = 0;
        for _ in 0..20 {
            if limiter.check(client).is_ok() {
                allowed += 1;
            }
        }

        // Should have allowed the burst amount
        assert!(allowed >= 10, "Expected at least 10 allowed, got {}", allowed);
    }

    #[test]
    fn test_rate_limit_exceeded() {
        // Very low limit: 1 qps with burst of 2
        let config = RateLimitConfig::default().with_qps(1).with_burst(2);

        let limiter = DnsRateLimiter::new(&config);
        let client = test_ip(1);

        // Exhaust burst
        let _ = limiter.check(client);
        let _ = limiter.check(client);

        // Third request should fail
        let result = limiter.check(client);

        assert!(result.is_err());
        if let Err(DnsError::RateLimitExceeded { .. }) = result {
            // Expected
        } else {
            panic!("Expected RateLimitExceeded error");
        }
    }

    #[test]
    fn test_independent_client_limits() {
        let config = RateLimitConfig::default().with_qps(1).with_burst(1);

        let limiter = DnsRateLimiter::new(&config);
        let client1 = test_ip(1);
        let client2 = test_ip(2);

        // Exhaust client1's limit
        let _ = limiter.check(client1);
        assert!(limiter.check(client1).is_err());

        // Client2 should still work
        assert!(limiter.check(client2).is_ok());
    }

    // ========================================================================
    // Statistics Tests
    // ========================================================================

    #[test]
    fn test_stats_total_requests() {
        let config = RateLimitConfig::default();
        let limiter = DnsRateLimiter::new(&config);
        let client = test_ip(1);

        for _ in 0..5 {
            let _ = limiter.check(client);
        }

        assert_eq!(limiter.stats().total_requests(), 5);
    }

    #[test]
    fn test_stats_allowed_requests() {
        let config = RateLimitConfig::default();
        let limiter = DnsRateLimiter::new(&config);
        let client = test_ip(1);

        for _ in 0..5 {
            let _ = limiter.check(client);
        }

        assert!(limiter.stats().allowed_requests() >= 5);
    }

    #[test]
    fn test_stats_rejected_requests() {
        let config = RateLimitConfig::default().with_qps(1).with_burst(2);

        let limiter = DnsRateLimiter::new(&config);
        let client = test_ip(1);

        // Send more than burst allows
        for _ in 0..10 {
            let _ = limiter.check(client);
        }

        assert!(
            limiter.stats().rejected_requests() > 0,
            "Expected some rejections"
        );
    }

    #[test]
    fn test_stats_unique_clients() {
        let config = RateLimitConfig::default();
        let limiter = DnsRateLimiter::new(&config);

        for i in 1..=5 {
            let client = test_ip(i);
            let _ = limiter.check(client);
        }

        assert_eq!(limiter.stats().unique_clients(), 5);
    }

    #[test]
    fn test_stats_snapshot() {
        let config = RateLimitConfig::default();
        let limiter = DnsRateLimiter::new(&config);
        let client = test_ip(1);

        let _ = limiter.check(client);

        let snapshot = limiter.stats().snapshot();
        assert_eq!(snapshot.total_requests, 1);
        assert!(snapshot.allowed_requests >= 1);
    }

    #[test]
    fn test_rejection_rate() {
        let config = RateLimitConfig::default().with_qps(1).with_burst(5);

        let limiter = DnsRateLimiter::new(&config);
        let client = test_ip(1);

        // 5 allowed, then some rejected
        for _ in 0..10 {
            let _ = limiter.check(client);
        }

        let rate = limiter.stats().rejection_rate();
        assert!(rate > 0.0, "Expected some rejections");
        assert!(rate < 1.0, "Not all should be rejected");
    }

    #[test]
    fn test_rejection_rate_zero_requests() {
        let config = RateLimitConfig::default();
        let limiter = DnsRateLimiter::new(&config);

        assert_eq!(limiter.stats().rejection_rate(), 0.0);
    }

    // ========================================================================
    // Client Stats Tests
    // ========================================================================

    #[test]
    fn test_client_stats_found() {
        let config = RateLimitConfig::default();
        let limiter = DnsRateLimiter::new(&config);
        let client = test_ip(1);

        for _ in 0..5 {
            let _ = limiter.check(client);
        }

        let stats = limiter.client_stats(client);
        assert!(stats.is_some());
        assert_eq!(stats.unwrap().request_count, 5);
    }

    #[test]
    fn test_client_stats_not_found() {
        let config = RateLimitConfig::default();
        let limiter = DnsRateLimiter::new(&config);
        let client = test_ip(1);

        assert!(limiter.client_stats(client).is_none());
    }

    #[test]
    fn test_client_stats_rejection_rate() {
        let config = RateLimitConfig::default().with_qps(1).with_burst(2);

        let limiter = DnsRateLimiter::new(&config);
        let client = test_ip(1);

        for _ in 0..5 {
            let _ = limiter.check(client);
        }

        let stats = limiter.client_stats(client).unwrap();
        assert!(stats.rejected_count > 0);
        assert!(stats.rejection_rate() > 0.0);
    }

    // ========================================================================
    // Cleanup Tests
    // ========================================================================

    #[test]
    fn test_cleanup_no_stale_entries() {
        let config = RateLimitConfig::default();
        let limiter = DnsRateLimiter::new(&config);
        let client = test_ip(1);

        let _ = limiter.check(client);
        assert_eq!(limiter.client_count(), 1);

        // Cleanup with very short max_age shouldn't remove fresh entry
        let removed = limiter.cleanup_stale(Duration::from_secs(3600));
        assert_eq!(removed, 0);
        assert_eq!(limiter.client_count(), 1);
    }

    #[test]
    fn test_cleanup_stats_updated() {
        let config = RateLimitConfig::default();
        let limiter = DnsRateLimiter::new(&config);
        let client = test_ip(1);

        let _ = limiter.check(client);

        // Wait a bit to ensure the entry becomes stale
        std::thread::sleep(std::time::Duration::from_millis(10));

        // Cleanup with a short duration should remove entries not accessed recently
        let removed = limiter.cleanup_stale(Duration::from_millis(5));
        assert_eq!(removed, 1);
        assert_eq!(limiter.stats().entries_cleaned(), 1);
    }

    // ========================================================================
    // Clear Tests
    // ========================================================================

    #[test]
    fn test_clear() {
        let config = RateLimitConfig::default();
        let limiter = DnsRateLimiter::new(&config);

        for i in 1..=5 {
            let client = test_ip(i);
            let _ = limiter.check(client);
        }

        assert_eq!(limiter.client_count(), 5);

        limiter.clear();

        assert_eq!(limiter.client_count(), 0);
    }

    // ========================================================================
    // Concurrency Tests
    // ========================================================================

    #[test]
    fn test_concurrent_clients() {
        use std::sync::Arc;

        let config = RateLimitConfig::default();
        let limiter = Arc::new(DnsRateLimiter::new(&config));

        let handles: Vec<_> = (0..8)
            .map(|i| {
                let limiter = Arc::clone(&limiter);
                thread::spawn(move || {
                    let client = test_ip(i + 1);
                    for _ in 0..100 {
                        let _ = limiter.check(client);
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }

        assert_eq!(limiter.client_count(), 8);
        assert_eq!(limiter.stats().total_requests(), 800);
    }

    #[test]
    fn test_concurrent_same_client() {
        use std::sync::Arc;

        let config = RateLimitConfig::default().with_qps(100).with_burst(200);
        let limiter = Arc::new(DnsRateLimiter::new(&config));
        let client = test_ip(1);

        let handles: Vec<_> = (0..4)
            .map(|_| {
                let limiter = Arc::clone(&limiter);
                thread::spawn(move || {
                    for _ in 0..50 {
                        let _ = limiter.check(client);
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }

        assert_eq!(limiter.client_count(), 1);
        assert_eq!(limiter.stats().total_requests(), 200);
    }

    // ========================================================================
    // IPv6 Tests
    // ========================================================================

    #[test]
    fn test_ipv6_client() {
        use std::net::Ipv6Addr;

        let config = RateLimitConfig::default();
        let limiter = DnsRateLimiter::new(&config);

        let client = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let result = limiter.check(client);

        assert!(result.is_ok());
        assert_eq!(limiter.client_count(), 1);
    }

    #[test]
    fn test_mixed_ipv4_ipv6() {
        use std::net::Ipv6Addr;

        let config = RateLimitConfig::default();
        let limiter = DnsRateLimiter::new(&config);

        let ipv4 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let ipv6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));

        let _ = limiter.check(ipv4);
        let _ = limiter.check(ipv6);

        assert_eq!(limiter.client_count(), 2);
    }

    // ========================================================================
    // Async Tests
    // ========================================================================

    #[tokio::test]
    async fn test_check_async() {
        let config = RateLimitConfig::default();
        let limiter = DnsRateLimiter::new(&config);
        let client = test_ip(1);

        let result = limiter.check_async(client).await;
        assert!(result.is_ok());
    }

    // ========================================================================
    // Edge Case Tests
    // ========================================================================

    #[test]
    fn test_zero_qps_clamped_to_one() {
        // Zero QPS should be clamped to 1
        let mut config = RateLimitConfig::default();
        config.qps_per_client = 0;
        config.burst_size = 1;

        // This should not panic - zero is clamped to 1
        let limiter = DnsRateLimiter::new(&config);

        let client = test_ip(1);
        let result = limiter.check(client);
        assert!(result.is_ok());
    }

    #[test]
    fn test_snapshot_rejection_rate_zero_total() {
        let snapshot = RateLimiterStatsSnapshot {
            total_requests: 0,
            allowed_requests: 0,
            rejected_requests: 0,
            unique_clients: 0,
            entries_cleaned: 0,
            entries_evicted: 0,
        };

        assert_eq!(snapshot.rejection_rate(), 0.0);
    }

    #[test]
    fn test_client_stats_rejection_rate_zero() {
        let stats = ClientStats {
            request_count: 0,
            rejected_count: 0,
        };

        assert_eq!(stats.rejection_rate(), 0.0);
    }

    // ========================================================================
    // Memory Management Tests (LRU Eviction)
    // ========================================================================

    #[test]
    fn test_max_clients_limit() {
        let config = RateLimitConfig::default();
        // Create limiter with max 5 clients
        let limiter = DnsRateLimiter::with_limits(&config, 5, 300);

        // Add 5 clients
        for i in 1..=5 {
            let client = test_ip(i);
            let _ = limiter.check(client);
        }
        assert_eq!(limiter.client_count(), 5);

        // Add 6th client - should trigger eviction
        let client6 = test_ip(6);
        let _ = limiter.check(client6);

        // Should still have 5 clients (one evicted)
        assert_eq!(limiter.client_count(), 5);
        assert_eq!(limiter.stats().entries_evicted(), 1);
    }

    #[test]
    fn test_lru_eviction_order() {
        let config = RateLimitConfig::default();
        // Create limiter with max 3 clients
        let limiter = DnsRateLimiter::with_limits(&config, 3, 300);

        let client1 = test_ip(1);
        let client2 = test_ip(2);
        let client3 = test_ip(3);
        let client4 = test_ip(4);

        // Add 3 clients in order
        let _ = limiter.check(client1);
        std::thread::sleep(std::time::Duration::from_millis(10));
        let _ = limiter.check(client2);
        std::thread::sleep(std::time::Duration::from_millis(10));
        let _ = limiter.check(client3);

        // Touch client1 to make it most recent
        std::thread::sleep(std::time::Duration::from_millis(10));
        let _ = limiter.check(client1);

        // Add client4 - should evict client2 (oldest)
        std::thread::sleep(std::time::Duration::from_millis(10));
        let _ = limiter.check(client4);

        // client1 should still exist (was touched)
        assert!(limiter.client_stats(client1).is_some());
        // client2 should be evicted (oldest)
        assert!(limiter.client_stats(client2).is_none());
        // client3 and client4 should exist
        assert!(limiter.client_stats(client3).is_some());
        assert!(limiter.client_stats(client4).is_some());
    }

    #[test]
    fn test_with_limits_constructor() {
        let config = RateLimitConfig::default();
        let limiter = DnsRateLimiter::with_limits(&config, 10_000, 120);

        assert_eq!(limiter.max_clients(), 10_000);
        assert_eq!(limiter.cleanup_interval_secs(), 120);
    }

    #[test]
    fn test_max_clients_clamped_to_one() {
        let config = RateLimitConfig::default();
        // Even 0 should be clamped to 1
        let limiter = DnsRateLimiter::with_limits(&config, 0, 300);

        assert_eq!(limiter.max_clients(), 1);
    }

    #[test]
    fn test_entries_evicted_stat() {
        let config = RateLimitConfig::default();
        let limiter = DnsRateLimiter::with_limits(&config, 2, 300);

        // Add 5 clients
        for i in 1..=5 {
            let client = test_ip(i);
            let _ = limiter.check(client);
        }

        // Should have evicted 3 clients
        assert_eq!(limiter.stats().entries_evicted(), 3);
        assert_eq!(limiter.client_count(), 2);
    }

    #[test]
    fn test_last_access_updated_on_check() {
        let config = RateLimitConfig::default();
        let limiter = DnsRateLimiter::with_limits(&config, 10, 300);

        let client = test_ip(1);
        let _ = limiter.check(client);

        // Wait and check again
        std::thread::sleep(std::time::Duration::from_millis(50));
        let _ = limiter.check(client);

        // Client should not be cleaned up even with short max_age
        // because last_access was updated
        let removed = limiter.cleanup_stale(std::time::Duration::from_millis(30));
        assert_eq!(removed, 0);
    }

    #[test]
    fn test_existing_client_no_eviction() {
        let config = RateLimitConfig::default();
        let limiter = DnsRateLimiter::with_limits(&config, 2, 300);

        let client1 = test_ip(1);
        let client2 = test_ip(2);

        // Add 2 clients
        let _ = limiter.check(client1);
        let _ = limiter.check(client2);

        // Check existing client - should not trigger eviction
        for _ in 0..10 {
            let _ = limiter.check(client1);
        }

        // Should still have 2 clients, no evictions
        assert_eq!(limiter.client_count(), 2);
        assert_eq!(limiter.stats().entries_evicted(), 0);
    }
}
