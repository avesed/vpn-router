//! Bidirectional cache for FakeDNS mappings
//!
//! This module provides a thread-safe, lock-free bidirectional cache using DashMap.
//! It maintains mappings in both directions:
//! - Domain -> IP (for allocating/looking up fake IPs for domains)
//! - IP -> Domain (for resolving domains from fake IPs)

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use dashmap::DashMap;

/// Entry in the domain-to-IP cache
#[derive(Debug, Clone)]
pub struct DomainEntry {
    /// Mapped IPv4 address
    pub ipv4: Option<Ipv4Addr>,
    /// Mapped IPv6 address (if IPv6 is enabled)
    pub ipv6: Option<Ipv6Addr>,
    /// When this entry expires
    pub expires_at: Instant,
}

impl DomainEntry {
    /// Create a new domain entry with IPv4 only
    #[must_use]
    pub fn new_ipv4(ipv4: Ipv4Addr, ttl: Duration) -> Self {
        Self {
            ipv4: Some(ipv4),
            ipv6: None,
            expires_at: Instant::now() + ttl,
        }
    }

    /// Create a new domain entry with both IPv4 and IPv6
    #[must_use]
    pub fn new_dual(ipv4: Ipv4Addr, ipv6: Ipv6Addr, ttl: Duration) -> Self {
        Self {
            ipv4: Some(ipv4),
            ipv6: Some(ipv6),
            expires_at: Instant::now() + ttl,
        }
    }

    /// Check if this entry has expired
    #[must_use]
    pub fn is_expired(&self) -> bool {
        Instant::now() > self.expires_at
    }

    /// Refresh the expiration time
    pub fn refresh(&mut self, ttl: Duration) {
        self.expires_at = Instant::now() + ttl;
    }

    /// Get the remaining TTL (or zero if expired)
    #[must_use]
    pub fn remaining_ttl(&self) -> Duration {
        self.expires_at.saturating_duration_since(Instant::now())
    }
}

/// Entry in the IP-to-domain cache
#[derive(Debug, Clone)]
pub struct IpEntry {
    /// The domain name
    pub domain: String,
    /// When this entry expires
    pub expires_at: Instant,
}

impl IpEntry {
    /// Create a new IP entry
    #[must_use]
    pub fn new(domain: String, ttl: Duration) -> Self {
        Self {
            domain,
            expires_at: Instant::now() + ttl,
        }
    }

    /// Check if this entry has expired
    #[must_use]
    pub fn is_expired(&self) -> bool {
        Instant::now() > self.expires_at
    }

    /// Refresh the expiration time
    pub fn refresh(&mut self, ttl: Duration) {
        self.expires_at = Instant::now() + ttl;
    }
}

/// Statistics for the FakeDNS cache
#[derive(Debug, Default)]
pub struct FakeDnsCacheStats {
    /// Total number of allocations
    pub allocations: AtomicU64,
    /// Total number of lookups (IP -> domain)
    pub lookups: AtomicU64,
    /// Cache hits (existing mapping found)
    pub cache_hits: AtomicU64,
    /// Cache misses (new allocation needed)
    pub cache_misses: AtomicU64,
    /// Number of expired entries evicted
    pub evictions: AtomicU64,
    /// Number of entries evicted due to IP collision
    pub ip_collisions: AtomicU64,
}

impl FakeDnsCacheStats {
    /// Create new stats
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Get a snapshot of current stats
    #[must_use]
    pub fn snapshot(&self) -> FakeDnsCacheStatsSnapshot {
        FakeDnsCacheStatsSnapshot {
            allocations: self.allocations.load(Ordering::Relaxed),
            lookups: self.lookups.load(Ordering::Relaxed),
            cache_hits: self.cache_hits.load(Ordering::Relaxed),
            cache_misses: self.cache_misses.load(Ordering::Relaxed),
            evictions: self.evictions.load(Ordering::Relaxed),
            ip_collisions: self.ip_collisions.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of cache statistics
#[derive(Debug, Clone, Copy)]
pub struct FakeDnsCacheStatsSnapshot {
    /// Total number of allocations
    pub allocations: u64,
    /// Total number of lookups
    pub lookups: u64,
    /// Cache hits
    pub cache_hits: u64,
    /// Cache misses
    pub cache_misses: u64,
    /// Evictions
    pub evictions: u64,
    /// IP collisions
    pub ip_collisions: u64,
}

/// Bidirectional cache for FakeDNS mappings
///
/// Uses DashMap for lock-free concurrent access.
#[derive(Debug)]
pub struct FakeDnsCache {
    /// Domain to IP mapping (domain -> DomainEntry)
    domain_to_ip: DashMap<String, DomainEntry>,
    /// IPv4 to domain mapping (IPv4 -> IpEntry)
    ipv4_to_domain: DashMap<Ipv4Addr, IpEntry>,
    /// IPv6 to domain mapping (IPv6 -> IpEntry)
    ipv6_to_domain: DashMap<Ipv6Addr, IpEntry>,
    /// Maximum number of domain entries
    max_entries: usize,
    /// Statistics
    stats: FakeDnsCacheStats,
}

impl FakeDnsCache {
    /// Create a new cache with the specified maximum entries
    #[must_use]
    pub fn new(max_entries: usize) -> Self {
        Self {
            domain_to_ip: DashMap::new(),
            ipv4_to_domain: DashMap::new(),
            ipv6_to_domain: DashMap::new(),
            max_entries,
            stats: FakeDnsCacheStats::new(),
        }
    }

    /// Get the domain entry for a domain, if it exists and is not expired
    #[must_use]
    pub fn get_domain(&self, domain: &str) -> Option<DomainEntry> {
        self.domain_to_ip.get(domain).and_then(|entry| {
            if entry.is_expired() {
                None
            } else {
                Some(entry.clone())
            }
        })
    }

    /// Get the domain for an IP address, if it exists and is not expired
    #[must_use]
    pub fn get_domain_by_ip(&self, ip: &IpAddr) -> Option<String> {
        self.stats.lookups.fetch_add(1, Ordering::Relaxed);
        match ip {
            IpAddr::V4(v4) => self.ipv4_to_domain.get(v4).and_then(|entry| {
                if entry.is_expired() {
                    None
                } else {
                    Some(entry.domain.clone())
                }
            }),
            IpAddr::V6(v6) => self.ipv6_to_domain.get(v6).and_then(|entry| {
                if entry.is_expired() {
                    None
                } else {
                    Some(entry.domain.clone())
                }
            }),
        }
    }

    /// Insert or update a domain -> IPv4 mapping
    ///
    /// Returns the previous entry if one existed.
    pub fn insert_ipv4(&self, domain: String, ipv4: Ipv4Addr, ttl: Duration) -> Option<DomainEntry> {
        self.stats.allocations.fetch_add(1, Ordering::Relaxed);

        // Insert into IP -> domain map
        self.ipv4_to_domain
            .insert(ipv4, IpEntry::new(domain.clone(), ttl));

        // Insert or update domain -> IP map
        let entry = DomainEntry::new_ipv4(ipv4, ttl);
        self.domain_to_ip.insert(domain, entry)
    }

    /// Insert or update a domain -> IPv4 + IPv6 mapping
    pub fn insert_dual(
        &self,
        domain: String,
        ipv4: Ipv4Addr,
        ipv6: Ipv6Addr,
        ttl: Duration,
    ) -> Option<DomainEntry> {
        self.stats.allocations.fetch_add(1, Ordering::Relaxed);

        // Insert into IP -> domain maps
        self.ipv4_to_domain
            .insert(ipv4, IpEntry::new(domain.clone(), ttl));
        self.ipv6_to_domain
            .insert(ipv6, IpEntry::new(domain.clone(), ttl));

        // Insert or update domain -> IP map
        let entry = DomainEntry::new_dual(ipv4, ipv6, ttl);
        self.domain_to_ip.insert(domain, entry)
    }

    /// Refresh the TTL for a domain entry
    ///
    /// Returns true if the entry was found and refreshed.
    pub fn refresh_domain(&self, domain: &str, ttl: Duration) -> bool {
        if let Some(mut entry) = self.domain_to_ip.get_mut(domain) {
            entry.refresh(ttl);

            // Also refresh the IP entries
            if let Some(ipv4) = entry.ipv4 {
                if let Some(mut ip_entry) = self.ipv4_to_domain.get_mut(&ipv4) {
                    ip_entry.refresh(ttl);
                }
            }
            if let Some(ipv6) = entry.ipv6 {
                if let Some(mut ip_entry) = self.ipv6_to_domain.get_mut(&ipv6) {
                    ip_entry.refresh(ttl);
                }
            }

            self.stats.cache_hits.fetch_add(1, Ordering::Relaxed);
            true
        } else {
            false
        }
    }

    /// Check if an IPv4 address is in the cache and not expired
    #[must_use]
    pub fn has_ipv4(&self, ip: &Ipv4Addr) -> bool {
        self.ipv4_to_domain
            .get(ip)
            .is_some_and(|entry| !entry.is_expired())
    }

    /// Check if an IPv6 address is in the cache and not expired
    #[must_use]
    pub fn has_ipv6(&self, ip: &Ipv6Addr) -> bool {
        self.ipv6_to_domain
            .get(ip)
            .is_some_and(|entry| !entry.is_expired())
    }

    /// Remove expired entries from all maps
    ///
    /// Returns the number of entries removed.
    pub fn cleanup_expired(&self) -> usize {
        let mut removed = 0;

        // Clean up domain -> IP map
        self.domain_to_ip.retain(|_, entry| {
            if entry.is_expired() {
                removed += 1;
                false
            } else {
                true
            }
        });

        // Clean up IPv4 -> domain map
        self.ipv4_to_domain.retain(|_, entry| {
            if entry.is_expired() {
                removed += 1;
                false
            } else {
                true
            }
        });

        // Clean up IPv6 -> domain map
        self.ipv6_to_domain.retain(|_, entry| {
            if entry.is_expired() {
                removed += 1;
                false
            } else {
                true
            }
        });

        if removed > 0 {
            self.stats.evictions.fetch_add(removed as u64, Ordering::Relaxed);
        }

        removed
    }

    /// Get the current number of domain entries
    #[must_use]
    pub fn len(&self) -> usize {
        self.domain_to_ip.len()
    }

    /// Check if the cache is empty
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.domain_to_ip.is_empty()
    }

    /// Check if the cache is at capacity
    #[must_use]
    pub fn is_full(&self) -> bool {
        self.domain_to_ip.len() >= self.max_entries
    }

    /// Get the maximum number of entries
    #[must_use]
    pub fn max_entries(&self) -> usize {
        self.max_entries
    }

    /// Get statistics
    #[must_use]
    pub fn stats(&self) -> &FakeDnsCacheStats {
        &self.stats
    }

    /// Record a cache miss
    pub fn record_miss(&self) {
        self.stats.cache_misses.fetch_add(1, Ordering::Relaxed);
    }

    /// Record an IP collision (existing IP was remapped)
    pub fn record_ip_collision(&self) {
        self.stats.ip_collisions.fetch_add(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_entry_expiration() {
        let entry = DomainEntry::new_ipv4(Ipv4Addr::new(10, 0, 0, 1), Duration::from_millis(10));
        assert!(!entry.is_expired());

        std::thread::sleep(Duration::from_millis(20));
        assert!(entry.is_expired());
    }

    #[test]
    fn test_domain_entry_refresh() {
        let mut entry = DomainEntry::new_ipv4(Ipv4Addr::new(10, 0, 0, 1), Duration::from_millis(10));
        std::thread::sleep(Duration::from_millis(20));
        assert!(entry.is_expired());

        entry.refresh(Duration::from_secs(60));
        assert!(!entry.is_expired());
    }

    #[test]
    fn test_cache_insert_and_get() {
        let cache = FakeDnsCache::new(100);

        cache.insert_ipv4(
            "example.com".to_string(),
            Ipv4Addr::new(198, 18, 0, 1),
            Duration::from_secs(60),
        );

        let entry = cache.get_domain("example.com").unwrap();
        assert_eq!(entry.ipv4, Some(Ipv4Addr::new(198, 18, 0, 1)));
        assert!(entry.ipv6.is_none());

        let domain = cache
            .get_domain_by_ip(&IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1)))
            .unwrap();
        assert_eq!(domain, "example.com");
    }

    #[test]
    fn test_cache_insert_dual() {
        let cache = FakeDnsCache::new(100);

        cache.insert_dual(
            "example.com".to_string(),
            Ipv4Addr::new(198, 18, 0, 1),
            Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1),
            Duration::from_secs(60),
        );

        let entry = cache.get_domain("example.com").unwrap();
        assert_eq!(entry.ipv4, Some(Ipv4Addr::new(198, 18, 0, 1)));
        assert_eq!(
            entry.ipv6,
            Some(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1))
        );

        // Both IPs should resolve to the domain
        let domain4 = cache
            .get_domain_by_ip(&IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1)))
            .unwrap();
        assert_eq!(domain4, "example.com");

        let domain6 = cache
            .get_domain_by_ip(&IpAddr::V6(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1)))
            .unwrap();
        assert_eq!(domain6, "example.com");
    }

    #[test]
    fn test_cache_expiration() {
        let cache = FakeDnsCache::new(100);

        cache.insert_ipv4(
            "example.com".to_string(),
            Ipv4Addr::new(198, 18, 0, 1),
            Duration::from_millis(10),
        );

        assert!(cache.get_domain("example.com").is_some());

        std::thread::sleep(Duration::from_millis(20));

        assert!(cache.get_domain("example.com").is_none());
        assert!(cache
            .get_domain_by_ip(&IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1)))
            .is_none());
    }

    #[test]
    fn test_cache_refresh() {
        let cache = FakeDnsCache::new(100);

        cache.insert_ipv4(
            "example.com".to_string(),
            Ipv4Addr::new(198, 18, 0, 1),
            Duration::from_millis(50),
        );

        std::thread::sleep(Duration::from_millis(30));

        // Refresh before expiration
        assert!(cache.refresh_domain("example.com", Duration::from_secs(60)));

        std::thread::sleep(Duration::from_millis(30));

        // Should still be valid after refresh
        assert!(cache.get_domain("example.com").is_some());
    }

    #[test]
    fn test_cache_cleanup() {
        let cache = FakeDnsCache::new(100);

        cache.insert_ipv4(
            "expire.com".to_string(),
            Ipv4Addr::new(198, 18, 0, 1),
            Duration::from_millis(10),
        );
        cache.insert_ipv4(
            "keep.com".to_string(),
            Ipv4Addr::new(198, 18, 0, 2),
            Duration::from_secs(60),
        );

        std::thread::sleep(Duration::from_millis(20));

        let removed = cache.cleanup_expired();
        // expire.com should be removed (domain + ipv4 entries)
        assert!(removed >= 1);

        assert!(cache.get_domain("expire.com").is_none());
        assert!(cache.get_domain("keep.com").is_some());
    }

    #[test]
    fn test_cache_stats() {
        let cache = FakeDnsCache::new(100);

        cache.insert_ipv4(
            "example.com".to_string(),
            Ipv4Addr::new(198, 18, 0, 1),
            Duration::from_secs(60),
        );

        let _ = cache.get_domain_by_ip(&IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1)));
        let _ = cache.get_domain_by_ip(&IpAddr::V4(Ipv4Addr::new(198, 18, 0, 2)));

        let stats = cache.stats().snapshot();
        assert_eq!(stats.allocations, 1);
        assert_eq!(stats.lookups, 2);
    }

    #[test]
    fn test_concurrent_access() {
        use std::sync::Arc;
        use std::thread;

        let cache = Arc::new(FakeDnsCache::new(1000));
        let mut handles = vec![];

        // Spawn writers
        for i in 0..4 {
            let cache = Arc::clone(&cache);
            handles.push(thread::spawn(move || {
                for j in 0..100 {
                    let domain = format!("domain-{}-{}.com", i, j);
                    let ip = Ipv4Addr::new(198, 18, i as u8, j as u8);
                    cache.insert_ipv4(domain, ip, Duration::from_secs(60));
                }
            }));
        }

        // Spawn readers
        for _ in 0..4 {
            let cache = Arc::clone(&cache);
            handles.push(thread::spawn(move || {
                for _ in 0..100 {
                    let _ = cache.get_domain("domain-0-0.com");
                    let _ = cache.get_domain_by_ip(&IpAddr::V4(Ipv4Addr::new(198, 18, 0, 0)));
                }
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        // Cache should have entries
        assert!(!cache.is_empty());
    }
}
