//! IP-to-Domain reverse DNS cache for ingress routing
//!
//! This module provides a cache that maps IP addresses to domain names,
//! populated by parsing DNS responses. This enables domain-based routing
//! rules to work for WireGuard ingress traffic where we only have IP addresses.
//!
//! # How It Works
//!
//! 1. When DNS queries are forwarded through the router, we capture the responses
//! 2. We parse A/AAAA records from the responses and cache IP → domain mappings
//! 3. When routing decisions are made, we look up the destination IP to find the domain
//! 4. The domain is then used for rule matching
//!
//! # Example
//!
//! ```ignore
//! use rust_router::ingress::dns_cache::IpDomainCache;
//! use std::net::IpAddr;
//!
//! let cache = IpDomainCache::new(10000, 300);
//!
//! // After a DNS response for "example.com" with IP 93.184.216.34 is seen:
//! cache.insert(IpAddr::from([93, 184, 216, 34]), "example.com".to_string(), 300);
//!
//! // Later, when routing a packet to 93.184.216.34:
//! if let Some(domain) = cache.get(&IpAddr::from([93, 184, 216, 34])) {
//!     println!("Destination domain: {}", domain); // "example.com"
//! }
//! ```

use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tracing::{debug, trace};

/// Entry in the IP-to-domain cache
#[derive(Debug, Clone)]
struct CacheEntry {
    /// The domain name
    domain: String,
    /// When this entry was inserted
    inserted_at: Instant,
    /// TTL in seconds
    ttl: u32,
}

impl CacheEntry {
    fn new(domain: String, ttl: u32) -> Self {
        Self {
            domain,
            inserted_at: Instant::now(),
            ttl,
        }
    }

    fn is_expired(&self) -> bool {
        self.inserted_at.elapsed().as_secs() >= u64::from(self.ttl)
    }

    fn remaining_ttl(&self) -> u32 {
        let elapsed = self.inserted_at.elapsed().as_secs();
        if elapsed >= u64::from(self.ttl) {
            0
        } else {
            self.ttl - elapsed as u32
        }
    }
}

/// Statistics for the IP-to-domain cache
#[derive(Debug, Default)]
pub struct IpDomainCacheStats {
    /// Number of cache hits
    hits: AtomicU64,
    /// Number of cache misses
    misses: AtomicU64,
    /// Number of entries inserted
    inserts: AtomicU64,
    /// Number of entries updated (IP already existed)
    updates: AtomicU64,
    /// Number of entries evicted due to expiration
    expirations: AtomicU64,
}

impl IpDomainCacheStats {
    /// Record a cache hit
    pub fn record_hit(&self) {
        self.hits.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a cache miss
    pub fn record_miss(&self) {
        self.misses.fetch_add(1, Ordering::Relaxed);
    }

    /// Record an insertion
    pub fn record_insert(&self) {
        self.inserts.fetch_add(1, Ordering::Relaxed);
    }

    /// Record an update
    pub fn record_update(&self) {
        self.updates.fetch_add(1, Ordering::Relaxed);
    }

    /// Record an expiration
    pub fn record_expiration(&self) {
        self.expirations.fetch_add(1, Ordering::Relaxed);
    }

    /// Get hit count
    #[must_use]
    pub fn hits(&self) -> u64 {
        self.hits.load(Ordering::Relaxed)
    }

    /// Get miss count
    #[must_use]
    pub fn misses(&self) -> u64 {
        self.misses.load(Ordering::Relaxed)
    }

    /// Get insert count
    #[must_use]
    pub fn inserts(&self) -> u64 {
        self.inserts.load(Ordering::Relaxed)
    }

    /// Get update count
    #[must_use]
    pub fn updates(&self) -> u64 {
        self.updates.load(Ordering::Relaxed)
    }

    /// Get expiration count
    #[must_use]
    pub fn expirations(&self) -> u64 {
        self.expirations.load(Ordering::Relaxed)
    }

    /// Calculate hit rate as a percentage
    #[must_use]
    pub fn hit_rate(&self) -> f64 {
        let hits = self.hits();
        let total = hits + self.misses();
        if total == 0 {
            0.0
        } else {
            (hits as f64 / total as f64) * 100.0
        }
    }

    /// Create a snapshot of all statistics
    #[must_use]
    pub fn snapshot(&self) -> IpDomainCacheStatsSnapshot {
        IpDomainCacheStatsSnapshot {
            hits: self.hits(),
            misses: self.misses(),
            inserts: self.inserts(),
            updates: self.updates(),
            expirations: self.expirations(),
        }
    }
}

/// Snapshot of cache statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpDomainCacheStatsSnapshot {
    pub hits: u64,
    pub misses: u64,
    pub inserts: u64,
    pub updates: u64,
    pub expirations: u64,
}

impl IpDomainCacheStatsSnapshot {
    /// Calculate hit rate as a percentage
    #[must_use]
    pub fn hit_rate(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 {
            0.0
        } else {
            (self.hits as f64 / total as f64) * 100.0
        }
    }
}

/// IP-to-domain reverse DNS cache
///
/// Thread-safe cache that maps IP addresses to domain names.
/// Used for enabling domain-based routing for WireGuard ingress traffic.
pub struct IpDomainCache {
    /// The underlying cache
    cache: DashMap<IpAddr, CacheEntry>,
    /// Maximum number of entries
    max_entries: usize,
    /// Default TTL for entries without explicit TTL
    default_ttl: u32,
    /// Statistics
    stats: IpDomainCacheStats,
}

impl IpDomainCache {
    /// Create a new IP-to-domain cache
    ///
    /// # Arguments
    ///
    /// * `max_entries` - Maximum number of entries to store
    /// * `default_ttl` - Default TTL in seconds for entries without explicit TTL
    #[must_use]
    pub fn new(max_entries: usize, default_ttl: u32) -> Self {
        Self {
            cache: DashMap::with_capacity(max_entries),
            max_entries,
            default_ttl,
            stats: IpDomainCacheStats::default(),
        }
    }

    /// Insert an IP-to-domain mapping
    ///
    /// # Arguments
    ///
    /// * `ip` - The IP address
    /// * `domain` - The domain name
    /// * `ttl` - TTL in seconds (use 0 for default TTL)
    pub fn insert(&self, ip: IpAddr, domain: String, ttl: u32) {
        let ttl = if ttl == 0 { self.default_ttl } else { ttl };
        let entry = CacheEntry::new(domain.clone(), ttl);

        // Evict if at capacity before inserting
        if self.cache.len() >= self.max_entries {
            self.evict_expired();
            // If still at capacity, evict oldest entries
            if self.cache.len() >= self.max_entries {
                self.evict_oldest(self.max_entries / 10);
            }
        }

        if self.cache.insert(ip, entry).is_some() {
            self.stats.record_update();
            trace!("Updated IP-domain mapping: {} -> {}", ip, domain);
        } else {
            self.stats.record_insert();
            trace!("Inserted IP-domain mapping: {} -> {}", ip, domain);
        }
    }

    /// Look up a domain by IP address
    ///
    /// # Arguments
    ///
    /// * `ip` - The IP address to look up
    ///
    /// # Returns
    ///
    /// The domain name if found and not expired, `None` otherwise.
    #[must_use]
    pub fn get(&self, ip: &IpAddr) -> Option<String> {
        if let Some(entry) = self.cache.get(ip) {
            if entry.is_expired() {
                drop(entry); // Release the reference before removing
                self.cache.remove(ip);
                self.stats.record_expiration();
                self.stats.record_miss();
                None
            } else {
                self.stats.record_hit();
                Some(entry.domain.clone())
            }
        } else {
            self.stats.record_miss();
            None
        }
    }

    /// Check if an IP has a cached domain (without removing if expired)
    #[must_use]
    pub fn contains(&self, ip: &IpAddr) -> bool {
        self.cache.get(ip).map_or(false, |e| !e.is_expired())
    }

    /// Get the number of entries in the cache
    #[must_use]
    pub fn len(&self) -> usize {
        self.cache.len()
    }

    /// Check if the cache is empty
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }

    /// Get cache statistics
    #[must_use]
    pub fn stats(&self) -> &IpDomainCacheStats {
        &self.stats
    }

    /// Get a snapshot of cache statistics
    #[must_use]
    pub fn stats_snapshot(&self) -> IpDomainCacheStatsSnapshot {
        self.stats.snapshot()
    }

    /// Remove expired entries
    ///
    /// # Returns
    ///
    /// Number of entries removed.
    pub fn evict_expired(&self) -> usize {
        let before = self.cache.len();
        self.cache.retain(|_, entry| {
            let expired = entry.is_expired();
            if expired {
                self.stats.record_expiration();
            }
            !expired
        });
        before.saturating_sub(self.cache.len())
    }

    /// Evict oldest entries (by remaining TTL)
    fn evict_oldest(&self, count: usize) {
        // Collect entries sorted by remaining TTL
        let mut entries: Vec<_> = self
            .cache
            .iter()
            .map(|r| (*r.key(), r.remaining_ttl()))
            .collect();

        entries.sort_by_key(|(_, ttl)| *ttl);

        // Remove the entries with lowest TTL
        for (ip, _) in entries.into_iter().take(count) {
            self.cache.remove(&ip);
        }
    }

    /// Clear all entries
    pub fn clear(&self) {
        self.cache.clear();
    }

    /// Parse DNS response bytes and extract IP-to-domain mappings
    ///
    /// This is a lightweight parser that extracts A and AAAA records
    /// from DNS response packets.
    ///
    /// # Arguments
    ///
    /// * `data` - Raw DNS response bytes
    ///
    /// # Returns
    ///
    /// Number of mappings extracted and inserted.
    pub fn parse_dns_response(&self, data: &[u8]) -> usize {
        // Minimum DNS header size is 12 bytes
        if data.len() < 12 {
            return 0;
        }

        // Check if this is a response (QR bit set)
        let flags = u16::from_be_bytes([data[2], data[3]]);
        if flags & 0x8000 == 0 {
            // Not a response
            return 0;
        }

        // Check for successful response (RCODE = 0)
        if flags & 0x000F != 0 {
            return 0;
        }

        let qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;
        let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;

        if ancount == 0 {
            return 0;
        }

        // Skip the header (12 bytes)
        let mut offset = 12;

        // Skip the question section
        for _ in 0..qdcount {
            // Skip QNAME
            let Some(new_offset) = skip_dns_name(data, offset) else {
                return 0;
            };
            offset = new_offset;
            // Skip QTYPE (2) + QCLASS (2)
            offset += 4;
            if offset > data.len() {
                return 0;
            }
        }

        // Parse answer section
        let mut count = 0;
        for _ in 0..ancount {
            if offset >= data.len() {
                break;
            }

            // Parse resource record
            // Name
            let name_start = offset;
            let Some(name_end) = skip_dns_name(data, offset) else {
                break;
            };
            let Some(domain) = parse_dns_name(data, name_start) else {
                break;
            };

            offset = name_end;
            if offset + 10 > data.len() {
                break;
            }

            let rtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
            let _rclass = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
            let ttl = u32::from_be_bytes([data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7]]);
            let rdlength = u16::from_be_bytes([data[offset + 8], data[offset + 9]]) as usize;

            offset += 10;

            if offset + rdlength > data.len() {
                break;
            }

            // Parse A record (type 1)
            if rtype == 1 && rdlength == 4 {
                let ip = IpAddr::V4(std::net::Ipv4Addr::new(
                    data[offset],
                    data[offset + 1],
                    data[offset + 2],
                    data[offset + 3],
                ));
                self.insert(ip, domain.clone(), ttl);
                count += 1;
                debug!("DNS cache: {} -> {} (TTL={})", ip, domain, ttl);
            }
            // Parse AAAA record (type 28)
            else if rtype == 28 && rdlength == 16 {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&data[offset..offset + 16]);
                let ip = IpAddr::V6(std::net::Ipv6Addr::from(octets));
                self.insert(ip, domain.clone(), ttl);
                count += 1;
                debug!("DNS cache: {} -> {} (TTL={})", ip, domain, ttl);
            }

            offset += rdlength;
        }

        count
    }
}

impl Default for IpDomainCache {
    fn default() -> Self {
        Self::new(10000, 300) // 10k entries, 5 minute default TTL
    }
}

impl std::fmt::Debug for IpDomainCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IpDomainCache")
            .field("entries", &self.cache.len())
            .field("max_entries", &self.max_entries)
            .field("default_ttl", &self.default_ttl)
            .field("stats", &self.stats.snapshot())
            .finish()
    }
}

// Helper function to skip a DNS name (handles compression)
fn skip_dns_name(data: &[u8], mut offset: usize) -> Option<usize> {
    loop {
        if offset >= data.len() {
            return None;
        }

        let len = data[offset] as usize;

        // Compression pointer
        if len & 0xC0 == 0xC0 {
            return Some(offset + 2);
        }

        // End of name
        if len == 0 {
            return Some(offset + 1);
        }

        offset += len + 1;
    }
}

// Helper function to parse a DNS name (handles compression)
fn parse_dns_name(data: &[u8], mut offset: usize) -> Option<String> {
    let mut parts = Vec::new();
    let mut visited = std::collections::HashSet::new();

    loop {
        if offset >= data.len() || visited.contains(&offset) {
            return None;
        }
        visited.insert(offset);

        let len = data[offset] as usize;

        // Compression pointer
        if len & 0xC0 == 0xC0 {
            if offset + 1 >= data.len() {
                return None;
            }
            let ptr = ((len & 0x3F) << 8 | data[offset + 1] as usize) as usize;
            offset = ptr;
            continue;
        }

        // End of name
        if len == 0 {
            break;
        }

        if offset + len + 1 > data.len() {
            return None;
        }

        let label = std::str::from_utf8(&data[offset + 1..offset + 1 + len]).ok()?;
        parts.push(label.to_lowercase());
        offset += len + 1;
    }

    if parts.is_empty() {
        None
    } else {
        Some(parts.join("."))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_cache_insert_and_get() {
        let cache = IpDomainCache::new(100, 300);
        let ip = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));

        cache.insert(ip, "example.com".to_string(), 300);
        assert_eq!(cache.get(&ip), Some("example.com".to_string()));
    }

    #[test]
    fn test_cache_miss() {
        let cache = IpDomainCache::new(100, 300);
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));

        assert_eq!(cache.get(&ip), None);
        assert_eq!(cache.stats().misses(), 1);
    }

    #[test]
    fn test_cache_update() {
        let cache = IpDomainCache::new(100, 300);
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));

        cache.insert(ip, "first.com".to_string(), 300);
        cache.insert(ip, "second.com".to_string(), 300);

        assert_eq!(cache.get(&ip), Some("second.com".to_string()));
        assert_eq!(cache.stats().updates(), 1);
    }

    #[test]
    fn test_cache_ipv6() {
        let cache = IpDomainCache::new(100, 300);
        let ip = IpAddr::V6(Ipv6Addr::new(0x2606, 0x2800, 0x220, 0x1, 0x248, 0x1893, 0x25c8, 0x1946));

        cache.insert(ip, "example.com".to_string(), 300);
        assert_eq!(cache.get(&ip), Some("example.com".to_string()));
    }

    #[test]
    fn test_cache_contains() {
        let cache = IpDomainCache::new(100, 300);
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));

        assert!(!cache.contains(&ip));
        cache.insert(ip, "test.com".to_string(), 300);
        assert!(cache.contains(&ip));
    }

    #[test]
    fn test_cache_len() {
        let cache = IpDomainCache::new(100, 300);

        assert_eq!(cache.len(), 0);
        assert!(cache.is_empty());

        cache.insert(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), "a.com".to_string(), 300);
        cache.insert(IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)), "b.com".to_string(), 300);

        assert_eq!(cache.len(), 2);
        assert!(!cache.is_empty());
    }

    #[test]
    fn test_cache_clear() {
        let cache = IpDomainCache::new(100, 300);

        cache.insert(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), "a.com".to_string(), 300);
        cache.insert(IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)), "b.com".to_string(), 300);

        cache.clear();
        assert!(cache.is_empty());
    }

    #[test]
    fn test_stats_hit_rate() {
        let cache = IpDomainCache::new(100, 300);
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));

        cache.insert(ip, "test.com".to_string(), 300);

        // 1 miss
        let _ = cache.get(&IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)));
        // 3 hits
        let _ = cache.get(&ip);
        let _ = cache.get(&ip);
        let _ = cache.get(&ip);

        // 3 hits / 4 total = 75%
        let stats = cache.stats_snapshot();
        assert_eq!(stats.hits, 3);
        assert_eq!(stats.misses, 1);
        assert!((stats.hit_rate() - 75.0).abs() < 0.01);
    }

    #[test]
    fn test_dns_name_parsing() {
        // Test simple name parsing
        let name = parse_dns_name(b"\x07example\x03com\x00", 0);
        assert_eq!(name, Some("example.com".to_string()));

        // Test with offset
        let data = b"\x00\x00\x07example\x03com\x00";
        let name = parse_dns_name(data, 2);
        assert_eq!(name, Some("example.com".to_string()));
    }

    #[test]
    fn test_skip_dns_name() {
        let data = b"\x07example\x03com\x00rest";
        let end = skip_dns_name(data, 0);
        assert_eq!(end, Some(13)); // 1 + 7 + 1 + 3 + 1 = 13
    }

    #[test]
    fn test_parse_dns_response() {
        // Simple DNS response for example.com -> 93.184.216.34
        let response: &[u8] = &[
            // Header
            0x12, 0x34, // ID
            0x81, 0x80, // Flags: Response, Recursion Desired, Recursion Available
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x01, // ANCOUNT = 1
            0x00, 0x00, // NSCOUNT = 0
            0x00, 0x00, // ARCOUNT = 0
            // Question section
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            0x03, b'c', b'o', b'm',
            0x00,       // End of name
            0x00, 0x01, // QTYPE = A
            0x00, 0x01, // QCLASS = IN
            // Answer section
            0xc0, 0x0c, // Name pointer to offset 12
            0x00, 0x01, // TYPE = A
            0x00, 0x01, // CLASS = IN
            0x00, 0x00, 0x01, 0x2c, // TTL = 300
            0x00, 0x04, // RDLENGTH = 4
            93, 184, 216, 34, // RDATA = 93.184.216.34
        ];

        let cache = IpDomainCache::new(100, 300);
        let count = cache.parse_dns_response(response);

        assert_eq!(count, 1);
        let ip = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        assert_eq!(cache.get(&ip), Some("example.com".to_string()));
    }

    #[test]
    fn test_default_cache() {
        let cache = IpDomainCache::default();
        assert_eq!(cache.max_entries, 10000);
        assert_eq!(cache.default_ttl, 300);
    }

    #[test]
    fn test_debug_format() {
        let cache = IpDomainCache::new(100, 300);
        let debug = format!("{:?}", cache);
        assert!(debug.contains("IpDomainCache"));
        assert!(debug.contains("max_entries"));
    }
}
