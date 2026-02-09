//! FakeDNS configuration types
//!
//! This module provides configuration for the FakeDNS manager.

use std::time::Duration;

use ipnet::{Ipv4Net, Ipv6Net};

/// Configuration for the FakeDNS manager
#[derive(Debug, Clone)]
pub struct FakeDnsConfig {
    /// Whether FakeDNS is enabled
    pub enabled: bool,
    /// IPv4 address pool for fake IPs
    ///
    /// Default: 198.18.0.0/15 (RFC 5737 test range)
    /// This provides 131,072 addresses for domain mapping
    pub ipv4_pool: Ipv4Net,
    /// Optional IPv6 address pool for fake IPs
    ///
    /// Default: None (IPv6 disabled)
    /// When enabled, use fc00::/7 (Unique Local Addresses)
    pub ipv6_pool: Option<Ipv6Net>,
    /// Maximum number of entries in the cache
    ///
    /// When the cache is full, the oldest expired entries are evicted.
    /// Default: 65536
    pub max_entries: usize,
    /// Time-to-live for cache entries
    ///
    /// Entries are refreshed when accessed within TTL.
    /// Default: 600 seconds (10 minutes)
    pub ttl: Duration,
    /// Interval for the background cleanup task
    ///
    /// The cleanup task removes expired entries.
    /// Default: 60 seconds
    pub cleanup_interval: Duration,
}

impl Default for FakeDnsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            // RFC 5737: 198.18.0.0/15 is reserved for benchmarking
            // This gives us 2^17 = 131,072 addresses
            ipv4_pool: "198.18.0.0/15".parse().expect("valid IPv4 CIDR"),
            ipv6_pool: None,
            max_entries: 65536,
            ttl: Duration::from_secs(600),
            cleanup_interval: Duration::from_secs(60),
        }
    }
}

impl FakeDnsConfig {
    /// Create a new FakeDnsConfig with default values
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the IPv4 address pool
    #[must_use]
    pub fn with_ipv4_pool(mut self, pool: Ipv4Net) -> Self {
        self.ipv4_pool = pool;
        self
    }

    /// Set the IPv6 address pool (enables IPv6 FakeDNS)
    #[must_use]
    pub fn with_ipv6_pool(mut self, pool: Ipv6Net) -> Self {
        self.ipv6_pool = Some(pool);
        self
    }

    /// Disable IPv6 FakeDNS
    #[must_use]
    pub fn without_ipv6(mut self) -> Self {
        self.ipv6_pool = None;
        self
    }

    /// Set the maximum number of cache entries
    #[must_use]
    pub fn with_max_entries(mut self, max: usize) -> Self {
        self.max_entries = max;
        self
    }

    /// Set the TTL for cache entries
    #[must_use]
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }

    /// Set the cleanup interval
    #[must_use]
    pub fn with_cleanup_interval(mut self, interval: Duration) -> Self {
        self.cleanup_interval = interval;
        self
    }

    /// Enable or disable FakeDNS
    #[must_use]
    pub fn enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    /// Check if IPv6 is enabled
    #[must_use]
    pub fn ipv6_enabled(&self) -> bool {
        self.ipv6_pool.is_some()
    }

    /// Get the number of available IPv4 addresses in the pool
    #[must_use]
    pub fn ipv4_pool_size(&self) -> u64 {
        self.ipv4_pool.hosts().count() as u64
    }

    /// Get the number of available IPv6 addresses in the pool (if enabled)
    #[must_use]
    pub fn ipv6_pool_size(&self) -> Option<u128> {
        self.ipv6_pool.as_ref().map(|pool| {
            // For large IPv6 pools, this could overflow, so we cap at u128::MAX
            let prefix_len = pool.prefix_len();
            if prefix_len >= 128 {
                1
            } else {
                1u128 << (128 - prefix_len)
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = FakeDnsConfig::default();
        assert!(config.enabled);
        assert_eq!(config.ipv4_pool, "198.18.0.0/15".parse().unwrap());
        assert!(config.ipv6_pool.is_none());
        assert_eq!(config.max_entries, 65536);
        assert_eq!(config.ttl, Duration::from_secs(600));
        assert_eq!(config.cleanup_interval, Duration::from_secs(60));
    }

    #[test]
    fn test_builder_pattern() {
        let config = FakeDnsConfig::new()
            .with_ipv4_pool("10.0.0.0/8".parse().unwrap())
            .with_ipv6_pool("fc00::/7".parse().unwrap())
            .with_max_entries(10000)
            .with_ttl(Duration::from_secs(300))
            .with_cleanup_interval(Duration::from_secs(30))
            .enabled(true);

        assert_eq!(config.ipv4_pool, "10.0.0.0/8".parse().unwrap());
        assert_eq!(config.ipv6_pool, Some("fc00::/7".parse().unwrap()));
        assert_eq!(config.max_entries, 10000);
        assert_eq!(config.ttl, Duration::from_secs(300));
        assert_eq!(config.cleanup_interval, Duration::from_secs(30));
    }

    #[test]
    fn test_ipv6_enabled() {
        let config = FakeDnsConfig::new();
        assert!(!config.ipv6_enabled());

        let config = config.with_ipv6_pool("fc00::/7".parse().unwrap());
        assert!(config.ipv6_enabled());

        let config = config.without_ipv6();
        assert!(!config.ipv6_enabled());
    }

    #[test]
    fn test_pool_sizes() {
        let config = FakeDnsConfig::new();
        // 198.18.0.0/15 has 2^17 = 131,072 addresses
        assert_eq!(config.ipv4_pool_size(), 131072);

        let config = config.with_ipv6_pool("fc00::/120".parse().unwrap());
        // /120 has 2^8 = 256 addresses
        assert_eq!(config.ipv6_pool_size(), Some(256));
    }
}
