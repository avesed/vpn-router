//! DNS splitting (per-domain routing) module
//!
//! This module enables routing DNS queries to different upstream servers based on
//! domain rules. For example, you might route Chinese domains (`.cn`) to Chinese DNS
//! servers while routing global domains to Cloudflare or Google DNS.
//!
//! # Features
//!
//! - **Per-domain routing**: Route queries to specific upstreams based on domain patterns
//! - **Multiple match types**: Exact, suffix, keyword, and regex matching
//! - **Hot reload**: Update routing rules without restart via `ArcSwap`
//! - **Health-aware**: Integrates with `UpstreamPool` for failover
//!
//! # Architecture
//!
//! ```text
//! DNS Query (domain: "www.baidu.cn")
//!     |
//!     v
//! +----------------+
//! |   DnsRouter    | --- Match Rule ---> "china" upstream pool
//! +----------------+                             |
//!     |                                          v
//!     | No Match                          China DNS Server
//!     v
//! Default Upstream
//!     |
//!     v
//! Global DNS Server
//! ```
//!
//! # Example
//!
//! ```no_run
//! use rust_router::dns::split::{DnsRouter, DomainMatchType, RouteInfo};
//! use rust_router::dns::client::UpstreamPool;
//!
//! // Create router with "direct" as default upstream
//! let router = DnsRouter::new("direct".to_string());
//!
//! // Add upstreams (in real code, these would be actual pools)
//! // router.add_upstream("china", china_dns_pool);
//! // router.add_upstream("global", global_dns_pool);
//!
//! // Add routing rules
//! router.add_route("cn", DomainMatchType::Suffix, "china").unwrap();
//! router.add_route("google.com", DomainMatchType::Suffix, "global").unwrap();
//!
//! // Route queries
//! // let upstream = router.route("www.baidu.cn");
//! // assert_eq!(upstream.map(|u| u.tag()), Some("china"));
//! ```
//!
//! # Performance
//!
//! - Domain matching: < 1 microsecond (via Aho-Corasick)
//! - Hot reload: < 10ms for rule updates
//! - Lock-free reads via `ArcSwap`
//!
//! # Thread Safety
//!
//! The `DnsRouter` is fully thread-safe:
//! - Reads are lock-free via `ArcSwap`
//! - Upstream pool access uses `RwLock` (read-heavy workload)
//! - Statistics use atomic counters

mod router;

pub use router::{
    DnsRouter, DnsRouterStats, DnsRouterStatsSnapshot, DomainMatchType, RouteInfo,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_exports() {
        // Verify all public types are accessible
        let router = DnsRouter::new("default".to_string());
        assert_eq!(router.default_upstream(), "default");
    }

    #[test]
    fn test_domain_match_type_variants() {
        // Verify all match types are accessible
        let _exact = DomainMatchType::Exact;
        let _suffix = DomainMatchType::Suffix;
        let _keyword = DomainMatchType::Keyword;
        let _regex = DomainMatchType::Regex;
    }

    #[test]
    fn test_route_info_creation() {
        let info = RouteInfo::new("example.com", DomainMatchType::Suffix, "global");
        assert_eq!(info.pattern, "example.com");
        assert_eq!(info.match_type, DomainMatchType::Suffix);
        assert_eq!(info.upstream_tag, "global");
    }

    #[test]
    fn test_stats_snapshot() {
        let snapshot = DnsRouterStatsSnapshot::default();
        assert_eq!(snapshot.routes_evaluated, 0);
        assert_eq!(snapshot.default_fallbacks, 0);
        assert_eq!(snapshot.rule_count, 0);
    }

    #[test]
    fn test_router_creation() {
        let router = DnsRouter::new("primary".to_string());
        assert_eq!(router.default_upstream(), "primary");
        assert_eq!(router.route_count(), 0);
        assert!(router.is_empty());
    }

    #[test]
    fn test_domain_match_type_display() {
        assert_eq!(format!("{}", DomainMatchType::Exact), "exact");
        assert_eq!(format!("{}", DomainMatchType::Suffix), "suffix");
        assert_eq!(format!("{}", DomainMatchType::Keyword), "keyword");
        assert_eq!(format!("{}", DomainMatchType::Regex), "regex");
    }

    #[test]
    fn test_domain_match_type_debug() {
        let exact = DomainMatchType::Exact;
        let debug = format!("{:?}", exact);
        assert!(debug.contains("Exact"));
    }
}
