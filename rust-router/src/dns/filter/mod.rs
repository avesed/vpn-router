//! DNS ad blocking and domain filtering module
//!
//! This module provides high-performance domain blocking for the DNS engine,
//! leveraging the existing `DomainMatcher` from the rules module for efficient
//! pattern matching.
//!
//! # Features
//!
//! - **Domain blocking**: Block ads, trackers, and malware domains
//! - **CNAME detection**: Detect blocked domains in CNAME chains
//! - **Configurable responses**: Return `0.0.0.0`, `NXDOMAIN`, or `REFUSED`
//! - **Hot reload**: Update blocklists without restart via `ArcSwap`
//!
//! # Architecture
//!
//! ```text
//! DNS Query
//!     |
//!     v
//! +----------------+
//! |  BlockFilter   | --- Blocked ---> BlockedResponseBuilder
//! +----------------+                           |
//!     |                                        v
//!     | Not Blocked                    Blocked Response
//!     v                               (0.0.0.0 / NXDOMAIN / REFUSED)
//! Upstream Query
//!     |
//!     v
//! +----------------+
//! | CnameDetector  | --- CNAME Blocked ---> BlockedResponseBuilder
//! +----------------+
//!     |
//!     v
//! Normal Response
//! ```
//!
//! # Example
//!
//! ```
//! use rust_router::dns::filter::{BlockFilter, BlockedResponseBuilder};
//! use rust_router::dns::{BlockingConfig, BlockResponseType};
//!
//! // Create a block filter
//! let config = BlockingConfig::default();
//! let filter = BlockFilter::new(config);
//!
//! // Load blocklist
//! let domains = vec!["ads.example.com".to_string(), "tracker.net".to_string()];
//! filter.load_from_domains(&domains).unwrap();
//!
//! // Check if domain is blocked
//! if let Some(reason) = filter.is_blocked("ads.example.com") {
//!     println!("Blocked: {} by rule {}", reason.domain, reason.matched_rule);
//! }
//! ```
//!
//! # Performance
//!
//! - Blocklist loading: < 1s for 100k domains
//! - Domain matching: < 500ns (via Aho-Corasick)
//! - Hot reload: < 10ms

mod blocklist;
mod cname;
mod response;

pub use blocklist::{BlockFilter, BlockFilterStats, BlockReason, MAX_RULES};
pub use cname::{CnameBlockReason, CnameDetector};
pub use response::BlockedResponseBuilder;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::{BlockingConfig, BlockResponseType};

    #[test]
    fn test_module_exports() {
        // Verify all public types are accessible
        let config = BlockingConfig::default();
        let _filter = BlockFilter::new(config.clone());
        let _detector = CnameDetector::new(config.cname_max_depth);
        let _builder = BlockedResponseBuilder::new(BlockResponseType::ZeroIp);
    }

    #[test]
    fn test_filter_with_blocklist() {
        let config = BlockingConfig::default();
        let filter = BlockFilter::new(config);

        let domains = vec![
            "ads.example.com".to_string(),
            "tracker.net".to_string(),
            "malware.org".to_string(),
        ];

        let loaded = filter.load_from_domains(&domains).unwrap();
        assert_eq!(loaded, 3);

        // Should be blocked
        assert!(filter.is_blocked("ads.example.com").is_some());
        assert!(filter.is_blocked("tracker.net").is_some());

        // Should not be blocked
        assert!(filter.is_blocked("google.com").is_none());
    }

    #[test]
    fn test_response_builder_types() {
        let builder_zero = BlockedResponseBuilder::new(BlockResponseType::ZeroIp);
        assert_eq!(builder_zero.response_type(), BlockResponseType::ZeroIp);

        let builder_nx = BlockedResponseBuilder::new(BlockResponseType::Nxdomain);
        assert_eq!(builder_nx.response_type(), BlockResponseType::Nxdomain);

        let builder_refused = BlockedResponseBuilder::new(BlockResponseType::Refused);
        assert_eq!(builder_refused.response_type(), BlockResponseType::Refused);
    }

    #[test]
    fn test_cname_detector_creation() {
        let detector = CnameDetector::new(5);
        assert_eq!(detector.max_depth(), 5);

        let detector_zero = CnameDetector::new(0);
        assert_eq!(detector_zero.max_depth(), 1); // Clamped to minimum
    }

    #[test]
    fn test_block_reason_fields() {
        let reason = BlockReason {
            domain: "ads.example.com".to_string(),
            matched_rule: "ads.example.com".to_string(),
            rule_type: "exact".to_string(),
        };

        assert_eq!(reason.domain, "ads.example.com");
        assert_eq!(reason.matched_rule, "ads.example.com");
        assert_eq!(reason.rule_type, "exact");
    }

    #[test]
    fn test_filter_stats() {
        let config = BlockingConfig::default();
        let filter = BlockFilter::new(config);

        let domains = vec!["blocked.com".to_string()];
        filter.load_from_domains(&domains).unwrap();

        // Initial stats
        let stats = filter.stats();
        assert_eq!(stats.blocked_count, 0);
        assert_eq!(stats.total_queries, 0);

        // Check a blocked domain
        filter.is_blocked("blocked.com");
        let stats = filter.stats();
        assert_eq!(stats.blocked_count, 1);
        assert_eq!(stats.total_queries, 1);

        // Check a non-blocked domain
        filter.is_blocked("allowed.com");
        let stats = filter.stats();
        assert_eq!(stats.blocked_count, 1);
        assert_eq!(stats.total_queries, 2);
    }
}
