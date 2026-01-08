//! DNS engine module for rust-router
//!
//! This module provides a high-performance DNS resolver with caching,
//! blocking, and multiple upstream protocol support. It is designed to
//! replace sing-box's DNS functionality with a native Rust implementation.
//!
//! # Features
//!
//! - **Multiple protocols**: UDP, TCP, `DoH`, `DoT`, `DoQ`
//! - **Caching**: Positive and negative response caching with TTL management
//! - **Blocking**: Domain blocking with CNAME chain detection
//! - **Rate limiting**: Per-client query rate limiting
//! - **Query logging**: Configurable logging in JSON, TSV, or binary format
//!
//! # Architecture
//!
//! ```text
//! Client Query
//!     │
//!     ▼
//! ┌─────────────────┐
//! │  Rate Limiter   │ ─── Exceeded ──▶ RateLimitExceeded
//! └────────┬────────┘
//!          │
//!          ▼
//! ┌─────────────────┐
//! │  Block Checker  │ ─── Blocked ──▶ Blocked Response
//! └────────┬────────┘
//!          │
//!          ▼
//! ┌─────────────────┐
//! │     Cache       │ ─── Hit ──▶ Cached Response
//! └────────┬────────┘
//!          │ Miss
//!          ▼
//! ┌─────────────────┐
//! │    Upstream     │ ─── Query ──▶ Upstream Server
//! └────────┬────────┘
//!          │
//!          ▼
//!   Response (+ Cache Store)
//! ```
//!
//! # Example
//!
//! ```no_run
//! use rust_router::dns::{DnsConfig, UpstreamConfig, UpstreamProtocol};
//!
//! // Create DNS configuration
//! let config = DnsConfig::new()
//!     .with_upstream(UpstreamConfig::new(
//!         "cloudflare",
//!         "1.1.1.1:53",
//!         UpstreamProtocol::Udp,
//!     ))
//!     .with_upstream(UpstreamConfig::new(
//!         "cloudflare-doh",
//!         "https://cloudflare-dns.com/dns-query",
//!         UpstreamProtocol::Doh,
//!     ).with_bootstrap(vec!["1.1.1.1".to_string()]));
//!
//! // Validate configuration
//! config.validate().expect("Invalid DNS config");
//! ```
//!
//! # Phase 7.0 Deliverables
//!
//! This is the foundation phase establishing:
//!
//! - Module skeleton and public interface
//! - Error types with 12 variants
//! - Configuration types with serde support
//! - hickory-proto integration and performance validation
//!
//! # Phase 7.1 Deliverables
//!
//! This phase adds the DNS server module:
//!
//! - [`server::DnsRateLimiter`]: Per-client rate limiting with token bucket
//! - [`server::UdpDnsServer`]: UDP DNS listener with batch I/O support
//! - [`server::TcpDnsServer`]: TCP DNS listener with connection limits
//! - [`server::DnsHandler`]: Core query processing and validation
//!
//! # Phase 7.2 Deliverables
//!
//! This phase adds the DNS cache module:
//!
//! - [`cache::DnsCache`]: High-performance LRU cache with moka backend
//! - [`cache::CacheKey`]: Case-insensitive domain key with qtype/qclass
//! - [`cache::CacheEntry`]: Cached response with TTL management
//! - [`cache::CacheStats`]: Atomic cache statistics (hits, misses, etc.)
//! - Negative caching support for NXDOMAIN/NODATA per RFC 2308
//!
//! # Phase 7.3 Deliverables
//!
//! This phase adds the DNS client module:
//!
//! - [`client::DnsUpstream`]: Core trait for all upstream clients
//! - [`client::UdpClient`]: UDP DNS client with retry logic
//! - [`client::TcpClient`]: TCP DNS client with deadpool connection pooling
//! - [`client::DohClient`]: DNS-over-HTTPS client (RFC 8484) - requires `dns-doh`
//! - [`client::DotClient`]: DNS-over-TLS client (RFC 7858) - requires `dns-dot`
//! - [`client::HealthChecker`]: Health state machine with configurable thresholds
//! - [`client::UpstreamPool`]: Multi-upstream pool with failover and selection strategies
//!
//! # Phase 7.4 Deliverables
//!
//! This phase adds the DNS blocking/filtering module:
//!
//! - [`filter::BlockFilter`]: High-performance domain blocker with ArcSwap hot-reload
//! - [`filter::CnameDetector`]: CNAME chain detection for bypass prevention
//! - [`filter::BlockedResponseBuilder`]: Response generator for blocked queries
//!
//! Future phases will add:
//! - Phase 7.5: DNS splitting (per-domain routing)
//! - Phase 7.6: Query logging
//! - Phase 7.7: Integration and testing

pub mod cache;
pub mod client;
pub mod config;
pub mod error;
pub mod filter;
pub mod server;

// Re-export commonly used types at module level
pub use config::{
    BlockResponseType, BlockingConfig, CacheConfig, DnsConfig, LogFormat, LoggingConfig,
    NegativeCacheConfig, RateLimitConfig, TcpServerConfig, UpstreamConfig, UpstreamProtocol,
};
pub use error::{DnsError, DnsResult};

// Re-export cache types
pub use cache::{
    analyze_negative_response, dns_classes, extract_soa_minimum, get_negative_cache_ttl,
    is_negative_response, record_types, CacheEntry, CacheKey, CacheStats, CacheStatsSnapshot,
    DnsCache, NegativeAnalysis, NegativeResponseType,
};

// Re-export client types
pub use client::{
    DnsUpstream, HealthCheckConfig, HealthChecker, HealthStats, PoolStats, SelectionStrategy,
    TcpClient, UdpClient, UpstreamInfo, UpstreamPool, UpstreamPoolBuilder,
};

#[cfg(feature = "dns-doh")]
pub use client::DohClient;

#[cfg(feature = "dns-dot")]
pub use client::DotClient;

// Re-export filter types
pub use filter::{BlockFilter, BlockFilterStats, BlockReason, BlockedResponseBuilder, CnameBlockReason, CnameDetector};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_exports() {
        // Verify all public types are accessible
        let _config = DnsConfig::default();
        let _upstream = UpstreamConfig::new("test", "8.8.8.8:53", UpstreamProtocol::Udp);
        let _cache = CacheConfig::default();
        let _blocking = BlockingConfig::default();
        let _logging = LoggingConfig::default();
        let _tcp = TcpServerConfig::default();
        let _rate_limit = RateLimitConfig::default();

        // Verify error types
        let _err = DnsError::timeout("test", std::time::Duration::from_secs(1));
    }

    #[test]
    fn test_default_config_creation() {
        let config = DnsConfig::default();
        assert!(config.enabled);
        assert_eq!(config.listen_udp.port(), 7853);
        assert_eq!(config.listen_tcp.port(), 7853);
    }

    #[test]
    fn test_config_with_multiple_upstreams() {
        let config = DnsConfig::new()
            .with_upstream(UpstreamConfig::new("google-udp", "8.8.8.8:53", UpstreamProtocol::Udp))
            .with_upstream(UpstreamConfig::new("google-tcp", "8.8.8.8:53", UpstreamProtocol::Tcp))
            .with_upstream(UpstreamConfig::new(
                "cloudflare-doh",
                "https://cloudflare-dns.com/dns-query",
                UpstreamProtocol::Doh,
            ).with_bootstrap(vec!["1.1.1.1".to_string()]));

        assert_eq!(config.upstreams.len(), 3);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_error_creation_and_classification() {
        // Recoverable errors
        let timeout = DnsError::timeout("query", std::time::Duration::from_secs(5));
        assert!(timeout.is_recoverable());
        assert!(timeout.is_timeout());

        let upstream = DnsError::upstream("8.8.8.8:53", "connection reset");
        assert!(upstream.is_recoverable());
        assert!(upstream.is_upstream_error());

        // Non-recoverable errors
        let blocked = DnsError::blocked("ads.example.com", "adblock-list");
        assert!(!blocked.is_recoverable());
        assert!(blocked.is_blocked());

        let config_err = DnsError::config("invalid address");
        assert!(!config_err.is_recoverable());
    }

    #[test]
    fn test_config_serialization_roundtrip() {
        let config = DnsConfig::new()
            .with_upstream(UpstreamConfig::new("test", "8.8.8.8:53", UpstreamProtocol::Udp))
            .with_cache(CacheConfig::default().with_max_entries(5000))
            .with_blocking(BlockingConfig::default().with_response_type(BlockResponseType::Nxdomain));

        let json = serde_json::to_string_pretty(&config).expect("serialize");
        let parsed: DnsConfig = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(parsed.upstreams.len(), 1);
        assert_eq!(parsed.cache.max_entries, 5000);
        assert_eq!(parsed.blocking.response_type, BlockResponseType::Nxdomain);
    }

    // ========================================================================
    // Phase 7.2: Cache Module Tests
    // ========================================================================

    #[test]
    fn test_cache_module_exports() {
        // Verify cache types are accessible
        let _cache = DnsCache::new(CacheConfig::default());
        let _key = CacheKey::new("example.com", 1, 1);
        let _stats = CacheStats::new();
        let _snapshot = CacheStatsSnapshot::default();

        // Verify record type constants
        assert_eq!(record_types::A, 1);
        assert_eq!(record_types::AAAA, 28);
        assert_eq!(record_types::CNAME, 5);

        // Verify DNS class constants
        assert_eq!(dns_classes::IN, 1);
        assert_eq!(dns_classes::CH, 3);
    }

    #[test]
    fn test_cache_key_case_insensitive() {
        let key1 = CacheKey::new("EXAMPLE.COM", 1, 1);
        let key2 = CacheKey::new("example.com", 1, 1);
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_cache_entry_creation() {
        let entry = CacheEntry::new_with_ttl(vec![1, 2, 3], 300, "upstream-1", false);
        assert_eq!(entry.original_ttl(), 300);
        assert_eq!(entry.upstream(), "upstream-1");
        assert!(!entry.is_negative());
        assert!(!entry.is_expired());
    }

    #[test]
    fn test_cache_stats_atomic() {
        let stats = CacheStats::new();
        stats.record_hit();
        stats.record_miss();
        assert_eq!(stats.hits(), 1);
        assert_eq!(stats.misses(), 1);
        assert!((stats.hit_rate() - 50.0).abs() < 0.01);
    }

    #[test]
    fn test_dns_cache_basic_operations() {
        use hickory_proto::op::{Message, MessageType, Query, ResponseCode};
        use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
        use std::net::Ipv4Addr;
        use std::str::FromStr;

        let cache = DnsCache::new(CacheConfig::default());
        assert!(cache.is_enabled());
        assert!(cache.is_empty());

        // Create query and response
        let mut query = Message::new();
        query.set_id(0x1234);
        let name = Name::from_str("test.example.com.").unwrap();
        query.add_query(Query::query(name.clone(), RecordType::A));

        let mut response = Message::new();
        response.set_id(0x1234);
        response.set_message_type(MessageType::Response);
        response.set_response_code(ResponseCode::NoError);
        response.add_query(Query::query(name.clone(), RecordType::A));

        let mut record = Record::new();
        record.set_name(name);
        record.set_record_type(RecordType::A);
        record.set_dns_class(DNSClass::IN);
        record.set_ttl(300);
        record.set_data(Some(RData::A(hickory_proto::rr::rdata::A(Ipv4Addr::new(
            1, 2, 3, 4,
        )))));
        response.add_answer(record);

        // Insert and retrieve
        cache.insert(&query, &response, "test-upstream");
        assert_eq!(cache.stats().inserts(), 1);
        assert!(cache.contains(&query));

        let cached = cache.get(&query);
        assert!(cached.is_some());
        assert_eq!(cache.stats().hits(), 1);
    }

    #[test]
    fn test_negative_response_type() {
        let nxdomain = NegativeResponseType::NxDomain;
        assert!(nxdomain.is_nxdomain());
        assert!(!nxdomain.is_nodata());
        assert_eq!(format!("{}", nxdomain), "NXDOMAIN");

        let nodata = NegativeResponseType::NoData;
        assert!(nodata.is_nodata());
        assert!(!nodata.is_nxdomain());
        assert_eq!(format!("{}", nodata), "NODATA");
    }

    // ========================================================================
    // Phase 7.4: Filter Module Tests
    // ========================================================================

    #[test]
    fn test_filter_module_exports() {
        // Verify filter types are accessible
        let config = BlockingConfig::default();
        let filter = BlockFilter::new(config.clone());
        let _detector = CnameDetector::new(config.cname_max_depth);
        let _builder = BlockedResponseBuilder::new(BlockResponseType::ZeroIp);

        // Verify filter stats
        let _stats = filter.stats();
    }

    #[test]
    fn test_block_filter_basic() {
        let filter = BlockFilter::new(BlockingConfig::default());

        // Load some domains
        let domains = vec![
            "ads.example.com".to_string(),
            "tracker.net".to_string(),
        ];
        let count = filter.load_from_domains(&domains).unwrap();
        assert_eq!(count, 2);

        // Test blocking
        assert!(filter.is_blocked("ads.example.com").is_some());
        assert!(filter.is_blocked("www.ads.example.com").is_some()); // subdomain
        assert!(filter.is_blocked("tracker.net").is_some());
        assert!(filter.is_blocked("google.com").is_none());
    }

    #[test]
    fn test_blocked_response_builder() {
        use hickory_proto::op::{Message, Query, ResponseCode};
        use hickory_proto::rr::{Name, RecordType};
        use std::str::FromStr;

        let builder = BlockedResponseBuilder::new(BlockResponseType::ZeroIp);

        // Create a query
        let mut query = Message::new();
        query.set_id(0x1234);
        let name = Name::from_str("blocked.example.com.").unwrap();
        query.add_query(Query::query(name, RecordType::A));

        // Build response
        let response = builder.build_response(&query);

        assert_eq!(response.id(), 0x1234);
        assert_eq!(response.response_code(), ResponseCode::NoError);
        assert!(!response.answers().is_empty());
    }

    #[test]
    fn test_cname_detector_creation() {
        let detector = CnameDetector::new(5);
        assert_eq!(detector.max_depth(), 5);

        // Depth is clamped to minimum of 1
        let detector_zero = CnameDetector::new(0);
        assert_eq!(detector_zero.max_depth(), 1);
    }
}
