//! DNS Cache Key Implementation
//!
//! This module provides the `CacheKey` type used for indexing DNS responses
//! in the cache. Keys are normalized for case-insensitive domain name matching.
//!
//! # Design Decisions
//!
//! - Domain names are normalized to lowercase per RFC 4343 (DNS Case Insensitivity)
//! - Query type and class are included for precise cache lookup
//! - Trailing dots are preserved (normalized during comparison)
//!
//! # Example
//!
//! ```
//! use rust_router::dns::cache::CacheKey;
//!
//! let key1 = CacheKey::new("Example.COM", 1, 1);
//! let key2 = CacheKey::new("example.com", 1, 1);
//! assert_eq!(key1, key2);
//! ```

use std::hash::{Hash, Hasher};

use hickory_proto::op::Message;
use hickory_proto::rr::{DNSClass, RecordType};

/// Cache key for DNS response lookup
///
/// This structure uniquely identifies a DNS query for caching purposes.
/// Domain names are normalized to lowercase for case-insensitive matching.
///
/// # Fields
///
/// - `qname`: The query name (domain), normalized to lowercase
/// - `qtype`: The query type (A=1, AAAA=28, MX=15, etc.)
/// - `qclass`: The query class (IN=1, CH=3, etc.)
///
/// # Example
///
/// ```
/// use rust_router::dns::cache::CacheKey;
///
/// // Create a key for an A record query
/// let key = CacheKey::new("example.com", 1, 1);
/// assert_eq!(key.qname(), "example.com");
/// assert_eq!(key.qtype(), 1);  // A record
/// assert_eq!(key.qclass(), 1); // IN class
/// ```
#[derive(Debug, Clone)]
pub struct CacheKey {
    /// Query name, normalized to lowercase
    qname: String,
    /// Query type (e.g., A=1, AAAA=28, CNAME=5, MX=15)
    qtype: u16,
    /// Query class (e.g., IN=1, CH=3, HS=4)
    qclass: u16,
}

impl CacheKey {
    /// Create a new cache key
    ///
    /// The domain name is normalized to lowercase for case-insensitive matching.
    ///
    /// # Arguments
    ///
    /// * `qname` - The query name (domain)
    /// * `qtype` - The query type (A=1, AAAA=28, etc.)
    /// * `qclass` - The query class (IN=1, etc.)
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::dns::cache::CacheKey;
    ///
    /// let key = CacheKey::new("Example.COM.", 1, 1);
    /// assert_eq!(key.qname(), "example.com.");
    /// ```
    #[must_use]
    pub fn new(qname: impl Into<String>, qtype: u16, qclass: u16) -> Self {
        let qname: String = qname.into();
        Self {
            qname: qname.to_lowercase(),
            qtype,
            qclass,
        }
    }

    /// Create a cache key from a `hickory_proto::rr::RecordType`
    ///
    /// # Arguments
    ///
    /// * `qname` - The query name (domain)
    /// * `record_type` - The record type
    /// * `dns_class` - The DNS class
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::dns::cache::CacheKey;
    /// use hickory_proto::rr::{RecordType, DNSClass};
    ///
    /// let key = CacheKey::from_record_type("example.com", RecordType::A, DNSClass::IN);
    /// assert_eq!(key.qtype(), 1);
    /// ```
    #[must_use]
    pub fn from_record_type(
        qname: impl Into<String>,
        record_type: RecordType,
        dns_class: DNSClass,
    ) -> Self {
        Self::new(qname, record_type.into(), u16::from(dns_class))
    }

    /// Extract a cache key from a DNS query message
    ///
    /// Returns `None` if the message has no questions.
    ///
    /// # Arguments
    ///
    /// * `query` - The DNS query message
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rust_router::dns::cache::CacheKey;
    /// use hickory_proto::op::Message;
    ///
    /// let query: Message = todo!("parse query");
    /// if let Some(key) = CacheKey::from_query(&query) {
    ///     println!("Cache key: {:?}", key);
    /// }
    /// ```
    #[must_use]
    pub fn from_query(query: &Message) -> Option<Self> {
        let q = query.queries().first()?;
        Some(Self::new(
            q.name().to_string(),
            q.query_type().into(),
            u16::from(q.query_class()),
        ))
    }

    /// Get the query name (domain)
    #[must_use]
    pub fn qname(&self) -> &str {
        &self.qname
    }

    /// Get the query type
    #[must_use]
    pub fn qtype(&self) -> u16 {
        self.qtype
    }

    /// Get the query class
    #[must_use]
    pub fn qclass(&self) -> u16 {
        self.qclass
    }

    /// Check if this key is for an A record query
    #[must_use]
    pub fn is_a_record(&self) -> bool {
        self.qtype == u16::from(RecordType::A)
    }

    /// Check if this key is for an AAAA record query
    #[must_use]
    pub fn is_aaaa_record(&self) -> bool {
        self.qtype == u16::from(RecordType::AAAA)
    }

    /// Check if this key is for the IN (Internet) class
    #[must_use]
    pub fn is_in_class(&self) -> bool {
        self.qclass == u16::from(DNSClass::IN)
    }

    /// Get the record type as a `RecordType` enum
    #[must_use]
    pub fn record_type(&self) -> RecordType {
        RecordType::from(self.qtype)
    }

    /// Get the DNS class as a `DNSClass` enum
    #[must_use]
    pub fn dns_class(&self) -> DNSClass {
        DNSClass::from(self.qclass)
    }

    /// Normalize a domain name for comparison
    ///
    /// This removes trailing dots and converts to lowercase.
    #[must_use]
    pub fn normalize_domain(domain: &str) -> String {
        let domain = domain.to_lowercase();
        if domain.ends_with('.') && domain.len() > 1 {
            domain[..domain.len() - 1].to_string()
        } else {
            domain
        }
    }
}

impl PartialEq for CacheKey {
    fn eq(&self, other: &Self) -> bool {
        // Compare qtype and qclass first (cheaper)
        if self.qtype != other.qtype || self.qclass != other.qclass {
            return false;
        }

        // Normalize trailing dots for comparison
        let self_name = Self::normalize_domain(&self.qname);
        let other_name = Self::normalize_domain(&other.qname);

        self_name == other_name
    }
}

impl Eq for CacheKey {}

impl Hash for CacheKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // Normalize the domain for consistent hashing
        let normalized = Self::normalize_domain(&self.qname);
        normalized.hash(state);
        self.qtype.hash(state);
        self.qclass.hash(state);
    }
}

/// Common DNS record types as constants
pub mod record_types {
    /// A record (IPv4 address)
    pub const A: u16 = 1;
    /// NS record (nameserver)
    pub const NS: u16 = 2;
    /// CNAME record (canonical name)
    pub const CNAME: u16 = 5;
    /// SOA record (start of authority)
    pub const SOA: u16 = 6;
    /// PTR record (pointer)
    pub const PTR: u16 = 12;
    /// MX record (mail exchange)
    pub const MX: u16 = 15;
    /// TXT record (text)
    pub const TXT: u16 = 16;
    /// AAAA record (IPv6 address)
    pub const AAAA: u16 = 28;
    /// SRV record (service)
    pub const SRV: u16 = 33;
    /// ANY query (all records)
    pub const ANY: u16 = 255;
}

/// Common DNS classes as constants
pub mod dns_classes {
    /// Internet class
    pub const IN: u16 = 1;
    /// Chaos class
    pub const CH: u16 = 3;
    /// Hesiod class
    pub const HS: u16 = 4;
    /// Any class (query only)
    pub const ANY: u16 = 255;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    // ========================================================================
    // CacheKey Creation Tests
    // ========================================================================

    #[test]
    fn test_cache_key_new() {
        let key = CacheKey::new("example.com", 1, 1);
        assert_eq!(key.qname(), "example.com");
        assert_eq!(key.qtype(), 1);
        assert_eq!(key.qclass(), 1);
    }

    #[test]
    fn test_cache_key_lowercase_normalization() {
        let key = CacheKey::new("EXAMPLE.COM", 1, 1);
        assert_eq!(key.qname(), "example.com");
    }

    #[test]
    fn test_cache_key_mixed_case_normalization() {
        let key = CacheKey::new("ExAmPlE.CoM", 1, 1);
        assert_eq!(key.qname(), "example.com");
    }

    #[test]
    fn test_cache_key_with_trailing_dot() {
        let key = CacheKey::new("example.com.", 1, 1);
        assert_eq!(key.qname(), "example.com.");
    }

    #[test]
    fn test_cache_key_from_record_type() {
        let key = CacheKey::from_record_type("example.com", RecordType::A, DNSClass::IN);
        assert_eq!(key.qtype(), 1);
        assert_eq!(key.qclass(), 1);
    }

    #[test]
    fn test_cache_key_from_record_type_aaaa() {
        let key = CacheKey::from_record_type("example.com", RecordType::AAAA, DNSClass::IN);
        assert_eq!(key.qtype(), 28);
    }

    #[test]
    fn test_cache_key_from_record_type_mx() {
        let key = CacheKey::from_record_type("example.com", RecordType::MX, DNSClass::IN);
        assert_eq!(key.qtype(), 15);
    }

    // ========================================================================
    // CacheKey Classification Tests
    // ========================================================================

    #[test]
    fn test_is_a_record() {
        let key = CacheKey::new("example.com", 1, 1);
        assert!(key.is_a_record());
        assert!(!key.is_aaaa_record());
    }

    #[test]
    fn test_is_aaaa_record() {
        let key = CacheKey::new("example.com", 28, 1);
        assert!(key.is_aaaa_record());
        assert!(!key.is_a_record());
    }

    #[test]
    fn test_is_in_class() {
        let key = CacheKey::new("example.com", 1, 1);
        assert!(key.is_in_class());

        let key_ch = CacheKey::new("example.com", 1, 3);
        assert!(!key_ch.is_in_class());
    }

    #[test]
    fn test_record_type_conversion() {
        let key = CacheKey::new("example.com", 1, 1);
        assert_eq!(key.record_type(), RecordType::A);

        let key_aaaa = CacheKey::new("example.com", 28, 1);
        assert_eq!(key_aaaa.record_type(), RecordType::AAAA);
    }

    #[test]
    fn test_dns_class_conversion() {
        let key = CacheKey::new("example.com", 1, 1);
        assert_eq!(key.dns_class(), DNSClass::IN);

        let key_ch = CacheKey::new("example.com", 1, 3);
        assert_eq!(key_ch.dns_class(), DNSClass::CH);
    }

    // ========================================================================
    // CacheKey Equality Tests
    // ========================================================================

    #[test]
    fn test_cache_key_equality_same() {
        let key1 = CacheKey::new("example.com", 1, 1);
        let key2 = CacheKey::new("example.com", 1, 1);
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_cache_key_equality_case_insensitive() {
        let key1 = CacheKey::new("EXAMPLE.COM", 1, 1);
        let key2 = CacheKey::new("example.com", 1, 1);
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_cache_key_equality_trailing_dot() {
        let key1 = CacheKey::new("example.com", 1, 1);
        let key2 = CacheKey::new("example.com.", 1, 1);
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_cache_key_inequality_different_domain() {
        let key1 = CacheKey::new("example.com", 1, 1);
        let key2 = CacheKey::new("example.org", 1, 1);
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_cache_key_inequality_different_qtype() {
        let key1 = CacheKey::new("example.com", 1, 1);
        let key2 = CacheKey::new("example.com", 28, 1);
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_cache_key_inequality_different_qclass() {
        let key1 = CacheKey::new("example.com", 1, 1);
        let key2 = CacheKey::new("example.com", 1, 3);
        assert_ne!(key1, key2);
    }

    // ========================================================================
    // CacheKey Hash Tests
    // ========================================================================

    #[test]
    fn test_cache_key_hash_same() {
        use std::hash::{DefaultHasher, Hash, Hasher};

        let key1 = CacheKey::new("example.com", 1, 1);
        let key2 = CacheKey::new("example.com", 1, 1);

        let mut hasher1 = DefaultHasher::new();
        let mut hasher2 = DefaultHasher::new();
        key1.hash(&mut hasher1);
        key2.hash(&mut hasher2);

        assert_eq!(hasher1.finish(), hasher2.finish());
    }

    #[test]
    fn test_cache_key_hash_case_insensitive() {
        use std::hash::{DefaultHasher, Hash, Hasher};

        let key1 = CacheKey::new("EXAMPLE.COM", 1, 1);
        let key2 = CacheKey::new("example.com", 1, 1);

        let mut hasher1 = DefaultHasher::new();
        let mut hasher2 = DefaultHasher::new();
        key1.hash(&mut hasher1);
        key2.hash(&mut hasher2);

        assert_eq!(hasher1.finish(), hasher2.finish());
    }

    #[test]
    fn test_cache_key_hash_trailing_dot() {
        use std::hash::{DefaultHasher, Hash, Hasher};

        let key1 = CacheKey::new("example.com", 1, 1);
        let key2 = CacheKey::new("example.com.", 1, 1);

        let mut hasher1 = DefaultHasher::new();
        let mut hasher2 = DefaultHasher::new();
        key1.hash(&mut hasher1);
        key2.hash(&mut hasher2);

        assert_eq!(hasher1.finish(), hasher2.finish());
    }

    #[test]
    fn test_cache_key_hashmap_insert_lookup() {
        let mut map: HashMap<CacheKey, String> = HashMap::new();

        let key = CacheKey::new("example.com", 1, 1);
        map.insert(key.clone(), "cached_response".to_string());

        // Lookup with same key
        assert_eq!(map.get(&key), Some(&"cached_response".to_string()));

        // Lookup with case-different key
        let key_upper = CacheKey::new("EXAMPLE.COM", 1, 1);
        assert_eq!(map.get(&key_upper), Some(&"cached_response".to_string()));

        // Lookup with trailing dot
        let key_dot = CacheKey::new("example.com.", 1, 1);
        assert_eq!(map.get(&key_dot), Some(&"cached_response".to_string()));
    }

    #[test]
    fn test_cache_key_hashmap_different_qtype() {
        let mut map: HashMap<CacheKey, String> = HashMap::new();

        let key_a = CacheKey::new("example.com", 1, 1);
        let key_aaaa = CacheKey::new("example.com", 28, 1);

        map.insert(key_a.clone(), "A_response".to_string());
        map.insert(key_aaaa.clone(), "AAAA_response".to_string());

        assert_eq!(map.get(&key_a), Some(&"A_response".to_string()));
        assert_eq!(map.get(&key_aaaa), Some(&"AAAA_response".to_string()));
        assert_eq!(map.len(), 2);
    }

    // ========================================================================
    // Domain Normalization Tests
    // ========================================================================

    #[test]
    fn test_normalize_domain_lowercase() {
        assert_eq!(CacheKey::normalize_domain("EXAMPLE.COM"), "example.com");
    }

    #[test]
    fn test_normalize_domain_trailing_dot() {
        assert_eq!(CacheKey::normalize_domain("example.com."), "example.com");
    }

    #[test]
    fn test_normalize_domain_single_dot() {
        // Root zone should not be modified
        assert_eq!(CacheKey::normalize_domain("."), ".");
    }

    #[test]
    fn test_normalize_domain_empty() {
        assert_eq!(CacheKey::normalize_domain(""), "");
    }

    #[test]
    fn test_normalize_domain_mixed_case_trailing_dot() {
        assert_eq!(CacheKey::normalize_domain("ExAmPlE.CoM."), "example.com");
    }

    // ========================================================================
    // Clone and Debug Tests
    // ========================================================================

    #[test]
    fn test_cache_key_clone() {
        let key1 = CacheKey::new("example.com", 1, 1);
        let key2 = key1.clone();
        assert_eq!(key1, key2);
        assert_eq!(key1.qname(), key2.qname());
    }

    #[test]
    fn test_cache_key_debug() {
        let key = CacheKey::new("example.com", 1, 1);
        let debug = format!("{:?}", key);
        assert!(debug.contains("example.com"));
        assert!(debug.contains("qtype: 1"));
        assert!(debug.contains("qclass: 1"));
    }

    // ========================================================================
    // Record Type Constants Tests
    // ========================================================================

    #[test]
    fn test_record_type_constants() {
        assert_eq!(record_types::A, 1);
        assert_eq!(record_types::NS, 2);
        assert_eq!(record_types::CNAME, 5);
        assert_eq!(record_types::SOA, 6);
        assert_eq!(record_types::PTR, 12);
        assert_eq!(record_types::MX, 15);
        assert_eq!(record_types::TXT, 16);
        assert_eq!(record_types::AAAA, 28);
        assert_eq!(record_types::SRV, 33);
        assert_eq!(record_types::ANY, 255);
    }

    #[test]
    fn test_dns_class_constants() {
        assert_eq!(dns_classes::IN, 1);
        assert_eq!(dns_classes::CH, 3);
        assert_eq!(dns_classes::HS, 4);
        assert_eq!(dns_classes::ANY, 255);
    }

    // ========================================================================
    // Edge Case Tests
    // ========================================================================

    #[test]
    fn test_cache_key_subdomain() {
        let key1 = CacheKey::new("www.example.com", 1, 1);
        let key2 = CacheKey::new("example.com", 1, 1);
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_cache_key_unicode_domain() {
        // IDN domains are case-insensitive
        let key1 = CacheKey::new("xn--nxasmq5b.com", 1, 1);
        let key2 = CacheKey::new("xn--nxasmq5b.com", 1, 1);
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_cache_key_long_domain() {
        let long_domain = "a".repeat(63) + ".example.com";
        let key = CacheKey::new(&long_domain, 1, 1);
        assert_eq!(key.qname(), long_domain.to_lowercase());
    }

    #[test]
    fn test_cache_key_deep_subdomain() {
        let key = CacheKey::new("a.b.c.d.e.f.example.com", 1, 1);
        assert_eq!(key.qname(), "a.b.c.d.e.f.example.com");
    }
}
