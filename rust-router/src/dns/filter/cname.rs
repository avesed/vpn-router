//! CNAME chain detection for ad blocking bypass prevention
//!
//! This module detects when a DNS response contains CNAME records that
//! point to blocked domains, preventing CNAME cloaking techniques used
//! by trackers to bypass domain-based blocking.
//!
//! # CNAME Cloaking
//!
//! Some trackers use CNAME cloaking to evade DNS-based blocking:
//!
//! ```text
//! User queries: tracker.example.com
//! Response: CNAME -> evil-tracker.adtech.com
//!
//! Without CNAME detection:
//!   - tracker.example.com is not in blocklist
//!   - Request goes through, tracker works
//!
//! With CNAME detection:
//!   - CNAME chain is followed
//!   - evil-tracker.adtech.com is found in blocklist
//!   - Request is blocked
//! ```
//!
//! # Example
//!
//! ```
//! use rust_router::dns::filter::{BlockFilter, CnameDetector};
//! use rust_router::dns::BlockingConfig;
//!
//! let config = BlockingConfig::default();
//! let filter = BlockFilter::new(config.clone());
//! filter.load_from_domains(&["adtech.com".to_string()]).unwrap();
//!
//! let detector = CnameDetector::new(config.cname_max_depth);
//!
//! // Use detector to check CNAME chains in DNS responses
//! // See check_cname_chain method for details
//! ```

use hickory_proto::op::Message;
use hickory_proto::rr::{RData, RecordType};

use super::blocklist::{BlockFilter, BlockReason};

/// Reason for blocking due to CNAME chain detection
///
/// Contains details about which CNAME in the chain was blocked
/// and at what depth it was found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CnameBlockReason {
    /// The original domain that was queried
    pub original_domain: String,

    /// The CNAME target that was blocked
    pub blocked_cname: String,

    /// Depth in the CNAME chain where the block was found (1-indexed)
    pub depth: u8,

    /// The underlying block reason
    pub block_reason: BlockReason,
}

impl CnameBlockReason {
    /// Create a new CNAME block reason
    #[must_use]
    pub fn new(
        original_domain: impl Into<String>,
        blocked_cname: impl Into<String>,
        depth: u8,
        block_reason: BlockReason,
    ) -> Self {
        Self {
            original_domain: original_domain.into(),
            blocked_cname: blocked_cname.into(),
            depth,
            block_reason,
        }
    }
}

/// CNAME chain detector for blocking bypass prevention
///
/// Follows CNAME chains in DNS responses and checks each target
/// against the block filter to detect CNAME cloaking.
///
/// # Depth Limit
///
/// To prevent infinite loops and excessive processing, the detector
/// has a configurable maximum depth (default: 5). This is typically
/// sufficient as real-world CNAME chains rarely exceed 3-4 levels.
///
/// # Example
///
/// ```
/// use rust_router::dns::filter::CnameDetector;
///
/// // Create detector with max depth of 5
/// let detector = CnameDetector::new(5);
/// assert_eq!(detector.max_depth(), 5);
///
/// // Depth is clamped to minimum of 1
/// let detector_zero = CnameDetector::new(0);
/// assert_eq!(detector_zero.max_depth(), 1);
/// ```
#[derive(Debug, Clone)]
pub struct CnameDetector {
    /// Maximum CNAME chain depth to follow
    max_depth: u8,
}

impl CnameDetector {
    /// Minimum allowed depth (prevents infinite loops)
    const MIN_DEPTH: u8 = 1;

    /// Maximum allowed depth (prevents excessive processing)
    const MAX_DEPTH: u8 = 20;

    /// Create a new CNAME detector with the specified maximum depth
    ///
    /// # Arguments
    ///
    /// * `max_depth` - Maximum number of CNAME levels to follow.
    ///   Will be clamped to the range [1, 20].
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::dns::filter::CnameDetector;
    ///
    /// let detector = CnameDetector::new(5);
    /// assert_eq!(detector.max_depth(), 5);
    /// ```
    #[must_use]
    pub fn new(max_depth: u8) -> Self {
        Self {
            max_depth: max_depth.clamp(Self::MIN_DEPTH, Self::MAX_DEPTH),
        }
    }

    /// Get the configured maximum depth
    #[must_use]
    pub fn max_depth(&self) -> u8 {
        self.max_depth
    }

    /// Check a DNS response for blocked CNAMEs in the chain
    ///
    /// Follows CNAME records in the response and checks each target
    /// against the block filter. Returns the first blocked CNAME found.
    ///
    /// # Arguments
    ///
    /// * `response` - The DNS response message to check
    /// * `block_filter` - The block filter to check domains against
    ///
    /// # Returns
    ///
    /// `Some(CnameBlockReason)` if a blocked CNAME was found, `None` otherwise.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rust_router::dns::filter::{BlockFilter, CnameDetector};
    /// use rust_router::dns::BlockingConfig;
    /// use hickory_proto::op::Message;
    ///
    /// let config = BlockingConfig::default();
    /// let filter = BlockFilter::new(config.clone());
    /// filter.load_from_domains(&["blocked.com".to_string()]).unwrap();
    ///
    /// let detector = CnameDetector::new(5);
    ///
    /// // Check a DNS response for blocked CNAMEs
    /// let response = Message::new();
    /// if let Some(reason) = detector.check_cname_chain(&response, &filter) {
    ///     println!("CNAME blocked: {} at depth {}", reason.blocked_cname, reason.depth);
    /// }
    /// ```
    #[must_use]
    pub fn check_cname_chain(&self, response: &Message, block_filter: &BlockFilter) -> Option<CnameBlockReason> {
        if !block_filter.is_enabled() || block_filter.is_empty() {
            return None;
        }

        // Get the original query domain
        let original_domain = response.queries().first().map(|q| q.name().to_string())?;

        // Collect all CNAME records from the answer section
        let cname_records: Vec<_> = response
            .answers()
            .iter()
            .filter(|r| r.record_type() == RecordType::CNAME)
            .collect();

        if cname_records.is_empty() {
            return None;
        }

        // Follow the CNAME chain
        let mut current_name = original_domain.clone();
        let mut depth: u8 = 0;

        while depth < self.max_depth {
            depth += 1;

            // Find CNAME record for current name
            let cname_target = cname_records.iter().find_map(|record| {
                let record_name = record.name().to_string().trim_end_matches('.').to_ascii_lowercase();
                let current_normalized = current_name.trim_end_matches('.').to_ascii_lowercase();

                if record_name == current_normalized {
                    // Extract CNAME target
                    if let Some(RData::CNAME(cname)) = record.data() {
                        return Some(cname.0.to_string());
                    }
                }
                None
            });

            match cname_target {
                Some(target) => {
                    // Normalize the CNAME target
                    let target_normalized = target.trim_end_matches('.').to_ascii_lowercase();

                    // Check if the CNAME target is blocked
                    if let Some(block_reason) = block_filter.is_blocked(&target_normalized) {
                        return Some(CnameBlockReason::new(
                            &original_domain,
                            &target_normalized,
                            depth,
                            block_reason,
                        ));
                    }

                    // Continue following the chain
                    current_name = target_normalized;
                }
                None => {
                    // No more CNAMEs to follow
                    break;
                }
            }
        }

        None
    }

    /// Check a list of CNAME targets directly
    ///
    /// This is a simpler alternative when you already have the CNAME
    /// targets extracted from a response.
    ///
    /// # Arguments
    ///
    /// * `original_domain` - The original queried domain
    /// * `cname_targets` - List of CNAME targets in order
    /// * `block_filter` - The block filter to check against
    ///
    /// # Returns
    ///
    /// `Some(CnameBlockReason)` if a blocked CNAME was found, `None` otherwise.
    #[must_use]
    pub fn check_targets(
        &self,
        original_domain: &str,
        cname_targets: &[String],
        block_filter: &BlockFilter,
    ) -> Option<CnameBlockReason> {
        if !block_filter.is_enabled() || block_filter.is_empty() {
            return None;
        }

        for (idx, target) in cname_targets.iter().take(self.max_depth as usize).enumerate() {
            let depth = (idx + 1) as u8;
            let target_normalized = target.trim_end_matches('.').to_ascii_lowercase();

            if let Some(block_reason) = block_filter.is_blocked(&target_normalized) {
                return Some(CnameBlockReason::new(
                    original_domain,
                    &target_normalized,
                    depth,
                    block_reason,
                ));
            }
        }

        None
    }
}

impl Default for CnameDetector {
    fn default() -> Self {
        Self::new(5)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::BlockingConfig;
    use hickory_proto::op::{MessageType, Query, ResponseCode};
    use hickory_proto::rr::{DNSClass, Name, Record};
    use std::str::FromStr;

    // ========================================================================
    // CnameBlockReason Tests
    // ========================================================================

    #[test]
    fn test_cname_block_reason_new() {
        let block_reason = BlockReason::new("evil.com", "evil.com", "suffix");
        let reason = CnameBlockReason::new("original.com", "evil.com", 2, block_reason);

        assert_eq!(reason.original_domain, "original.com");
        assert_eq!(reason.blocked_cname, "evil.com");
        assert_eq!(reason.depth, 2);
        assert_eq!(reason.block_reason.domain, "evil.com");
    }

    #[test]
    fn test_cname_block_reason_equality() {
        let br1 = BlockReason::new("evil.com", "evil.com", "suffix");
        let br2 = BlockReason::new("evil.com", "evil.com", "suffix");

        let reason1 = CnameBlockReason::new("original.com", "evil.com", 2, br1);
        let reason2 = CnameBlockReason::new("original.com", "evil.com", 2, br2);

        assert_eq!(reason1, reason2);
    }

    #[test]
    fn test_cname_block_reason_debug() {
        let block_reason = BlockReason::new("evil.com", "evil.com", "suffix");
        let reason = CnameBlockReason::new("original.com", "evil.com", 2, block_reason);

        let debug = format!("{:?}", reason);
        assert!(debug.contains("original.com"));
        assert!(debug.contains("evil.com"));
        assert!(debug.contains("2"));
    }

    // ========================================================================
    // CnameDetector Creation Tests
    // ========================================================================

    #[test]
    fn test_detector_new() {
        let detector = CnameDetector::new(5);
        assert_eq!(detector.max_depth(), 5);
    }

    #[test]
    fn test_detector_default() {
        let detector = CnameDetector::default();
        assert_eq!(detector.max_depth(), 5);
    }

    #[test]
    fn test_detector_clamp_min() {
        let detector = CnameDetector::new(0);
        assert_eq!(detector.max_depth(), 1);
    }

    #[test]
    fn test_detector_clamp_max() {
        let detector = CnameDetector::new(255);
        assert_eq!(detector.max_depth(), 20);
    }

    #[test]
    fn test_detector_debug() {
        let detector = CnameDetector::new(5);
        let debug = format!("{:?}", detector);
        assert!(debug.contains("CnameDetector"));
        assert!(debug.contains("5"));
    }

    #[test]
    fn test_detector_clone() {
        let detector = CnameDetector::new(7);
        let cloned = detector.clone();
        assert_eq!(cloned.max_depth(), 7);
    }

    // ========================================================================
    // CnameDetector Target Checking Tests
    // ========================================================================

    #[test]
    fn test_check_targets_no_blocked() {
        let filter = BlockFilter::new(BlockingConfig::default());
        filter.load_from_domains(&["blocked.com".to_string()]).unwrap();

        let detector = CnameDetector::new(5);
        let targets = vec!["allowed1.com".to_string(), "allowed2.com".to_string()];

        let result = detector.check_targets("original.com", &targets, &filter);
        assert!(result.is_none());
    }

    #[test]
    fn test_check_targets_first_blocked() {
        let filter = BlockFilter::new(BlockingConfig::default());
        filter.load_from_domains(&["blocked.com".to_string()]).unwrap();

        let detector = CnameDetector::new(5);
        let targets = vec!["blocked.com".to_string(), "allowed.com".to_string()];

        let result = detector.check_targets("original.com", &targets, &filter);
        assert!(result.is_some());

        let reason = result.unwrap();
        assert_eq!(reason.original_domain, "original.com");
        assert_eq!(reason.blocked_cname, "blocked.com");
        assert_eq!(reason.depth, 1);
    }

    #[test]
    fn test_check_targets_deep_blocked() {
        let filter = BlockFilter::new(BlockingConfig::default());
        filter.load_from_domains(&["blocked.com".to_string()]).unwrap();

        let detector = CnameDetector::new(5);
        let targets = vec![
            "hop1.com".to_string(),
            "hop2.com".to_string(),
            "blocked.com".to_string(),
        ];

        let result = detector.check_targets("original.com", &targets, &filter);
        assert!(result.is_some());

        let reason = result.unwrap();
        assert_eq!(reason.blocked_cname, "blocked.com");
        assert_eq!(reason.depth, 3);
    }

    #[test]
    fn test_check_targets_respects_depth_limit() {
        let filter = BlockFilter::new(BlockingConfig::default());
        filter.load_from_domains(&["blocked.com".to_string()]).unwrap();

        let detector = CnameDetector::new(2);
        let targets = vec![
            "hop1.com".to_string(),
            "hop2.com".to_string(),
            "blocked.com".to_string(), // Beyond depth limit
        ];

        let result = detector.check_targets("original.com", &targets, &filter);
        // blocked.com is at depth 3, but limit is 2
        assert!(result.is_none());
    }

    #[test]
    fn test_check_targets_empty_list() {
        let filter = BlockFilter::new(BlockingConfig::default());
        filter.load_from_domains(&["blocked.com".to_string()]).unwrap();

        let detector = CnameDetector::new(5);
        let targets: Vec<String> = Vec::new();

        let result = detector.check_targets("original.com", &targets, &filter);
        assert!(result.is_none());
    }

    #[test]
    fn test_check_targets_disabled_filter() {
        let config = BlockingConfig::default().disabled();
        let filter = BlockFilter::new(config);
        filter.load_from_domains(&["blocked.com".to_string()]).unwrap();

        let detector = CnameDetector::new(5);
        let targets = vec!["blocked.com".to_string()];

        let result = detector.check_targets("original.com", &targets, &filter);
        assert!(result.is_none());
    }

    #[test]
    fn test_check_targets_empty_filter() {
        let filter = BlockFilter::new(BlockingConfig::default());
        // No domains loaded

        let detector = CnameDetector::new(5);
        let targets = vec!["any.com".to_string()];

        let result = detector.check_targets("original.com", &targets, &filter);
        assert!(result.is_none());
    }

    #[test]
    fn test_check_targets_normalizes_trailing_dot() {
        let filter = BlockFilter::new(BlockingConfig::default());
        filter.load_from_domains(&["blocked.com".to_string()]).unwrap();

        let detector = CnameDetector::new(5);
        let targets = vec!["blocked.com.".to_string()]; // Trailing dot

        let result = detector.check_targets("original.com", &targets, &filter);
        assert!(result.is_some());
    }

    #[test]
    fn test_check_targets_case_insensitive() {
        let filter = BlockFilter::new(BlockingConfig::default());
        filter.load_from_domains(&["blocked.com".to_string()]).unwrap();

        let detector = CnameDetector::new(5);
        let targets = vec!["BLOCKED.COM".to_string()];

        let result = detector.check_targets("original.com", &targets, &filter);
        assert!(result.is_some());
    }

    // ========================================================================
    // CnameDetector Message Checking Tests
    // ========================================================================

    /// Helper function to create a DNS response with CNAME records
    fn create_cname_response(query_name: &str, cname_chain: &[(&str, &str)]) -> Message {
        let mut response = Message::new();
        response.set_id(0x1234);
        response.set_message_type(MessageType::Response);
        response.set_response_code(ResponseCode::NoError);

        // Add query
        let query_name_parsed = Name::from_str(&format!("{}.", query_name)).unwrap();
        response.add_query(Query::query(query_name_parsed, RecordType::A));

        // Add CNAME records
        for (name, target) in cname_chain {
            let record_name = Name::from_str(&format!("{}.", name)).unwrap();
            let target_name = Name::from_str(&format!("{}.", target)).unwrap();

            let mut record = Record::new();
            record.set_name(record_name);
            record.set_record_type(RecordType::CNAME);
            record.set_dns_class(DNSClass::IN);
            record.set_ttl(300);
            record.set_data(Some(RData::CNAME(hickory_proto::rr::rdata::CNAME(target_name))));
            response.add_answer(record);
        }

        response
    }

    #[test]
    fn test_check_cname_chain_no_cnames() {
        let filter = BlockFilter::new(BlockingConfig::default());
        filter.load_from_domains(&["blocked.com".to_string()]).unwrap();

        let detector = CnameDetector::new(5);

        // Response without CNAME records
        let mut response = Message::new();
        response.set_id(0x1234);
        response.set_message_type(MessageType::Response);
        let query_name = Name::from_str("example.com.").unwrap();
        response.add_query(Query::query(query_name, RecordType::A));

        let result = detector.check_cname_chain(&response, &filter);
        assert!(result.is_none());
    }

    #[test]
    fn test_check_cname_chain_blocked_first() {
        let filter = BlockFilter::new(BlockingConfig::default());
        filter.load_from_domains(&["blocked.com".to_string()]).unwrap();

        let detector = CnameDetector::new(5);

        let response = create_cname_response(
            "example.com",
            &[("example.com", "blocked.com")],
        );

        let result = detector.check_cname_chain(&response, &filter);
        assert!(result.is_some());

        let reason = result.unwrap();
        assert_eq!(reason.blocked_cname, "blocked.com");
        assert_eq!(reason.depth, 1);
    }

    #[test]
    fn test_check_cname_chain_blocked_deep() {
        let filter = BlockFilter::new(BlockingConfig::default());
        filter.load_from_domains(&["evil.adtech.com".to_string()]).unwrap();

        let detector = CnameDetector::new(5);

        let response = create_cname_response(
            "tracker.example.com",
            &[
                ("tracker.example.com", "hop1.example.com"),
                ("hop1.example.com", "hop2.example.com"),
                ("hop2.example.com", "evil.adtech.com"),
            ],
        );

        let result = detector.check_cname_chain(&response, &filter);
        assert!(result.is_some());

        let reason = result.unwrap();
        assert!(reason.original_domain.contains("tracker.example.com"));
        assert_eq!(reason.blocked_cname, "evil.adtech.com");
        assert_eq!(reason.depth, 3);
    }

    #[test]
    fn test_check_cname_chain_not_blocked() {
        let filter = BlockFilter::new(BlockingConfig::default());
        filter.load_from_domains(&["blocked.com".to_string()]).unwrap();

        let detector = CnameDetector::new(5);

        let response = create_cname_response(
            "example.com",
            &[
                ("example.com", "hop1.example.net"),
                ("hop1.example.net", "hop2.example.org"),
            ],
        );

        let result = detector.check_cname_chain(&response, &filter);
        assert!(result.is_none());
    }

    #[test]
    fn test_check_cname_chain_depth_limit() {
        let filter = BlockFilter::new(BlockingConfig::default());
        filter.load_from_domains(&["blocked.com".to_string()]).unwrap();

        let detector = CnameDetector::new(2); // Only check 2 levels

        let response = create_cname_response(
            "example.com",
            &[
                ("example.com", "hop1.com"),
                ("hop1.com", "hop2.com"),
                ("hop2.com", "blocked.com"), // Beyond depth limit
            ],
        );

        let result = detector.check_cname_chain(&response, &filter);
        // blocked.com is at depth 3, but limit is 2
        assert!(result.is_none());
    }

    #[test]
    fn test_check_cname_chain_empty_response() {
        let filter = BlockFilter::new(BlockingConfig::default());
        filter.load_from_domains(&["blocked.com".to_string()]).unwrap();

        let detector = CnameDetector::new(5);
        let response = Message::new();

        let result = detector.check_cname_chain(&response, &filter);
        assert!(result.is_none());
    }

    #[test]
    fn test_check_cname_chain_disabled_filter() {
        let config = BlockingConfig::default().disabled();
        let filter = BlockFilter::new(config);
        filter.load_from_domains(&["blocked.com".to_string()]).unwrap();

        let detector = CnameDetector::new(5);

        let response = create_cname_response(
            "example.com",
            &[("example.com", "blocked.com")],
        );

        let result = detector.check_cname_chain(&response, &filter);
        assert!(result.is_none());
    }

    #[test]
    fn test_check_cname_chain_suffix_blocking() {
        let filter = BlockFilter::new(BlockingConfig::default());
        filter.load_from_domains(&["adtech.com".to_string()]).unwrap();

        let detector = CnameDetector::new(5);

        let response = create_cname_response(
            "tracker.example.com",
            &[("tracker.example.com", "subdomain.adtech.com")],
        );

        let result = detector.check_cname_chain(&response, &filter);
        assert!(result.is_some());

        let reason = result.unwrap();
        assert_eq!(reason.blocked_cname, "subdomain.adtech.com");
    }
}
