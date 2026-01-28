//! FakeDNS manager - DashMap-based in-memory implementation
//!
//! This module provides a high-performance, thread-safe FakeDNS manager that maps
//! domain names to fake IP addresses and maintains bidirectional lookups.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use thiserror::Error;
use tracing::{trace, warn};

use super::cache::FakeDnsCache;
use super::config::FakeDnsConfig;
use super::pool::{Ipv4Pool, Ipv6Pool};

/// Error type for FakeDNS operations
#[derive(Error, Debug)]
pub enum FakeDnsError {
    /// IP pool exhausted: no available addresses
    #[error("IP pool exhausted: no available addresses")]
    PoolExhausted,
    /// IPv6 not enabled
    #[error("IPv6 not enabled")]
    Ipv6NotEnabled,
}

/// Result type for FakeDNS operations
pub type FakeDnsResult<T> = Result<T, FakeDnsError>;

/// FakeDNS manager for domain-to-IP mapping
///
/// This manager uses a DashMap-based cache for high-performance concurrent access
/// and IP pools for address allocation.
pub struct FakeDnsManager {
    /// Bidirectional cache for domain-IP mappings
    cache: FakeDnsCache,
    /// IPv4 address pool
    ipv4_pool: Ipv4Pool,
    /// Optional IPv6 address pool
    ipv6_pool: Option<Ipv6Pool>,
    /// TTL for cache entries
    ttl: Duration,
}

impl FakeDnsManager {
    /// Create a new FakeDNS manager with the given configuration
    #[must_use]
    pub fn new(config: &FakeDnsConfig) -> Self {
        let ipv6_pool = config.ipv6_pool.map(Ipv6Pool::new);
        Self {
            cache: FakeDnsCache::new(config.max_entries),
            ipv4_pool: Ipv4Pool::new(config.ipv4_pool),
            ipv6_pool,
            ttl: config.ttl,
        }
    }

    /// Map a domain name to an IPv4 address
    ///
    /// If the domain already has a mapping, returns the existing IP.
    /// Otherwise, allocates a new IP from the pool.
    ///
    /// # Returns
    /// A tuple of (IPv4 address, remaining TTL)
    pub fn map_domain_ipv4(&self, domain: &str) -> FakeDnsResult<(Ipv4Addr, Duration)> {
        // Check cache first
        if let Some(entry) = self.cache.get_domain(domain) {
            if let Some(ipv4) = entry.ipv4 {
                self.cache.refresh_domain(domain, self.ttl);
                trace!("fakedns cache hit: {} -> {}", domain, ipv4);
                return Ok((ipv4, entry.remaining_ttl()));
            }
        }

        // Allocate new IP
        self.cache.record_miss();
        let ipv4 = self.allocate_ipv4(domain)?;
        trace!("fakedns allocated: {} -> {}", domain, ipv4);
        Ok((ipv4, self.ttl))
    }

    /// Map a domain name to an IPv6 address
    ///
    /// If the domain already has a mapping, returns the existing IP.
    /// Otherwise, allocates a new IP from the pool.
    ///
    /// # Returns
    /// A tuple of (IPv6 address, remaining TTL)
    ///
    /// # Errors
    /// Returns `FakeDnsError::Ipv6NotEnabled` if IPv6 is not configured.
    pub fn map_domain_ipv6(&self, domain: &str) -> FakeDnsResult<(Ipv6Addr, Duration)> {
        let pool = self.ipv6_pool.as_ref().ok_or(FakeDnsError::Ipv6NotEnabled)?;

        // Check cache first
        if let Some(entry) = self.cache.get_domain(domain) {
            if let Some(ipv6) = entry.ipv6 {
                self.cache.refresh_domain(domain, self.ttl);
                return Ok((ipv6, entry.remaining_ttl()));
            }
        }

        // Allocate new IP
        self.cache.record_miss();
        let ipv6 = self.allocate_ipv6(domain, pool)?;
        Ok((ipv6, self.ttl))
    }

    /// Look up the domain name for a given IP address
    ///
    /// # Returns
    /// The domain name if found, or `None` if the IP is not in the cache.
    #[must_use]
    pub fn map_ip_domain(&self, ip: IpAddr) -> Option<String> {
        self.cache.get_domain_by_ip(&ip)
    }

    /// Check if an IP address belongs to the FakeDNS pool
    #[must_use]
    pub fn is_fake_ip(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => self.ipv4_pool.contains(v4),
            IpAddr::V6(v6) => self.ipv6_pool.as_ref().is_some_and(|p| p.contains(v6)),
        }
    }

    /// Get the underlying cache for statistics
    #[must_use]
    pub fn cache(&self) -> &FakeDnsCache {
        &self.cache
    }

    /// Get the TTL for cache entries
    #[must_use]
    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// Run cleanup to remove expired entries
    ///
    /// # Returns
    /// The number of entries removed.
    pub fn cleanup(&self) -> usize {
        self.cache.cleanup_expired()
    }

    /// Allocate a new IPv4 address for a domain
    fn allocate_ipv4(&self, domain: &str) -> FakeDnsResult<Ipv4Addr> {
        // Try to allocate, with max attempts equal to pool size
        let max_attempts = self.ipv4_pool.size() as usize;
        for _ in 0..max_attempts {
            let ip = self.ipv4_pool.next();

            // Check if this IP is already in use
            if !self.cache.has_ipv4(&ip) {
                // IP is free, allocate it
                self.cache.insert_ipv4(domain.to_string(), ip, self.ttl);
                return Ok(ip);
            }

            // IP is in use, check if it's for the same domain
            if let Some(existing_domain) = self.cache.get_domain_by_ip(&IpAddr::V4(ip)) {
                if existing_domain == domain {
                    // Same domain, refresh TTL
                    self.cache.refresh_domain(domain, self.ttl);
                    return Ok(ip);
                }
            }

            // IP is in use by another domain, try next
        }

        warn!("FakeDNS IPv4 pool exhausted for domain: {}", domain);
        Err(FakeDnsError::PoolExhausted)
    }

    /// Allocate a new IPv6 address for a domain
    fn allocate_ipv6(&self, domain: &str, pool: &Ipv6Pool) -> FakeDnsResult<Ipv6Addr> {
        // For IPv6, we also need to ensure there's an IPv4 mapping
        let max_attempts = pool.size().min(65536) as usize;
        for _ in 0..max_attempts {
            let ip = pool.next();

            // Check if this IP is already in use
            if !self.cache.has_ipv6(&ip) {
                // Ensure IPv4 is also allocated
                let ipv4 = self.allocate_ipv4(domain)?;
                self.cache.insert_dual(domain.to_string(), ipv4, ip, self.ttl);
                return Ok(ip);
            }

            // IP is in use, check if it's for the same domain
            if let Some(existing_domain) = self.cache.get_domain_by_ip(&IpAddr::V6(ip)) {
                if existing_domain == domain {
                    // Same domain, refresh TTL
                    self.cache.refresh_domain(domain, self.ttl);
                    return Ok(ip);
                }
            }
        }

        warn!("FakeDNS IPv6 pool exhausted for domain: {}", domain);
        Err(FakeDnsError::PoolExhausted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> FakeDnsConfig {
        FakeDnsConfig::new()
            .with_ipv4_pool("10.0.0.0/24".parse().unwrap())
            .with_max_entries(1000)
            .with_ttl(Duration::from_secs(60))
    }

    fn test_config_with_ipv6() -> FakeDnsConfig {
        test_config().with_ipv6_pool("fc00::/120".parse().unwrap())
    }

    #[test]
    fn test_manager_creation() {
        let config = test_config();
        let manager = FakeDnsManager::new(&config);
        assert_eq!(manager.ttl(), Duration::from_secs(60));
    }

    #[test]
    fn test_map_domain_ipv4() {
        let config = test_config();
        let manager = FakeDnsManager::new(&config);

        let (ip1, _ttl1) = manager.map_domain_ipv4("example.com").unwrap();
        assert!(manager.is_fake_ip(IpAddr::V4(ip1)));

        // Same domain should return same IP
        let (ip2, _ttl2) = manager.map_domain_ipv4("example.com").unwrap();
        assert_eq!(ip1, ip2);

        // Different domain should return different IP
        let (ip3, _ttl3) = manager.map_domain_ipv4("other.com").unwrap();
        assert_ne!(ip1, ip3);
    }

    #[test]
    fn test_map_ip_domain() {
        let config = test_config();
        let manager = FakeDnsManager::new(&config);

        let (ip, _ttl) = manager.map_domain_ipv4("example.com").unwrap();
        let domain = manager.map_ip_domain(IpAddr::V4(ip)).unwrap();
        assert_eq!(domain, "example.com");
    }

    #[test]
    fn test_ipv6_not_enabled() {
        let config = test_config();
        let manager = FakeDnsManager::new(&config);

        let result = manager.map_domain_ipv6("example.com");
        assert!(matches!(result, Err(FakeDnsError::Ipv6NotEnabled)));
    }

    #[test]
    fn test_map_domain_ipv6() {
        let config = test_config_with_ipv6();
        let manager = FakeDnsManager::new(&config);

        let (ipv6, _ttl) = manager.map_domain_ipv6("example.com").unwrap();
        assert!(manager.is_fake_ip(IpAddr::V6(ipv6)));

        // Should also have IPv4 mapping
        let domain = manager.map_ip_domain(IpAddr::V6(ipv6)).unwrap();
        assert_eq!(domain, "example.com");
    }

    #[test]
    fn test_is_fake_ip() {
        let config = test_config();
        let manager = FakeDnsManager::new(&config);

        // IP in pool should return true after allocation
        let (ip, _) = manager.map_domain_ipv4("example.com").unwrap();
        assert!(manager.is_fake_ip(IpAddr::V4(ip)));

        // IP outside pool should return false
        assert!(!manager.is_fake_ip(IpAddr::V4("192.168.1.1".parse().unwrap())));
    }

    #[test]
    fn test_cleanup() {
        let config = FakeDnsConfig::new()
            .with_ipv4_pool("10.0.0.0/24".parse().unwrap())
            .with_max_entries(1000)
            .with_ttl(Duration::from_millis(10));
        let manager = FakeDnsManager::new(&config);

        // Add some entries
        manager.map_domain_ipv4("example.com").unwrap();
        manager.map_domain_ipv4("other.com").unwrap();

        // Wait for expiration
        std::thread::sleep(Duration::from_millis(20));

        // Cleanup should remove expired entries
        let removed = manager.cleanup();
        assert!(removed > 0);
    }

    #[test]
    fn test_concurrent_access() {
        use std::sync::Arc;
        use std::thread;

        let config = test_config();
        let manager = Arc::new(FakeDnsManager::new(&config));
        let mut handles = vec![];

        // Spawn multiple threads accessing the manager
        for i in 0..4 {
            let manager = Arc::clone(&manager);
            handles.push(thread::spawn(move || {
                for j in 0..50 {
                    let domain = format!("domain-{}-{}.com", i, j);
                    let (ip, _) = manager.map_domain_ipv4(&domain).unwrap();
                    let resolved = manager.map_ip_domain(IpAddr::V4(ip)).unwrap();
                    assert_eq!(resolved, domain);
                }
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }
    }
}
