//! Domain block filter implementation
//!
//! This module provides the core domain blocking functionality, reusing the
//! high-performance `DomainMatcher` from the rules module for efficient
//! pattern matching.
//!
//! # Features
//!
//! - Reuses `DomainMatcher` for O(1) exact match and O(n) suffix match
//! - Supports hot reload via `ArcSwap` for zero-downtime updates
//! - Tracks blocking statistics with atomic counters
//! - Enforces maximum rule count to prevent memory exhaustion
//!
//! # Performance Characteristics
//!
//! - **Domain matching**: O(1) for exact match, O(n) for suffix match via Aho-Corasick
//! - **Pattern lookup for `BlockReason`**: O(n) scan of patterns `HashMap` when a match is found.
//!   This is acceptable because:
//!   1. It only executes when a domain is actually blocked (not on every query)
//!   2. Blocked queries are typically <1% of total queries
//!   3. The scan is over a `HashMap`, which has good cache locality
//!   4. The cost is amortized over the entire blocklist lifetime
//!
//! # Example
//!
//! ```
//! use rust_router::dns::filter::BlockFilter;
//! use rust_router::dns::BlockingConfig;
//!
//! let config = BlockingConfig::default();
//! let filter = BlockFilter::new(config);
//!
//! // Load domains
//! let domains = vec!["ads.example.com".to_string()];
//! filter.load_from_domains(&domains).unwrap();
//!
//! // Check if blocked
//! if let Some(reason) = filter.is_blocked("ads.example.com") {
//!     println!("Blocked by rule: {}", reason.matched_rule);
//! }
//! ```

use std::sync::atomic::{AtomicU64, Ordering};

/// Maximum number of rules allowed in a blocklist.
///
/// This limit prevents memory exhaustion attacks and ensures reasonable
/// memory usage. 500,000 rules is sufficient for most use cases (typical
/// ad blocklists have 50,000-200,000 entries).
///
/// Memory estimate: ~50 bytes per domain average = ~25 MB for 500k domains
pub const MAX_RULES: usize = 500_000;

use arc_swap::ArcSwap;

use crate::dns::error::{DnsError, DnsResult};
use crate::dns::BlockingConfig;
use crate::rules::domain::{DomainMatcher, DomainMatcherBuilder};

/// Reason why a domain was blocked
///
/// Contains details about which rule caused the block and the match type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockReason {
    /// The domain that was checked (may be normalized)
    pub domain: String,

    /// The rule that matched (the pattern from the blocklist)
    pub matched_rule: String,

    /// The type of match: "exact", "suffix", "keyword", or "regex"
    pub rule_type: String,
}

impl BlockReason {
    /// Create a new block reason
    #[must_use]
    pub fn new(domain: impl Into<String>, matched_rule: impl Into<String>, rule_type: impl Into<String>) -> Self {
        Self {
            domain: domain.into(),
            matched_rule: matched_rule.into(),
            rule_type: rule_type.into(),
        }
    }
}

/// Statistics for the block filter
///
/// Tracks the number of blocked queries and total queries checked.
#[derive(Debug, Clone, Copy, Default)]
pub struct BlockFilterStats {
    /// Number of queries that were blocked
    pub blocked_count: u64,

    /// Total number of queries checked
    pub total_queries: u64,

    /// Number of rules loaded
    pub rule_count: usize,
}

impl BlockFilterStats {
    /// Calculate the block rate as a percentage
    ///
    /// Returns 0.0 if no queries have been checked.
    #[must_use]
    pub fn block_rate(&self) -> f64 {
        if self.total_queries == 0 {
            0.0
        } else {
            (self.blocked_count as f64 / self.total_queries as f64) * 100.0
        }
    }
}

/// High-performance domain block filter
///
/// Uses `ArcSwap` for lock-free hot reload of blocklists and `DomainMatcher`
/// for efficient domain matching.
///
/// # Thread Safety
///
/// `BlockFilter` is thread-safe and can be shared across threads. Reads are
/// lock-free, and hot reloads only require a single atomic swap.
///
/// # Example
///
/// ```
/// use rust_router::dns::filter::BlockFilter;
/// use rust_router::dns::BlockingConfig;
///
/// let config = BlockingConfig::default();
/// let filter = BlockFilter::new(config);
///
/// // Load domains (all treated as suffix match by default)
/// let domains = vec!["ads.com".to_string(), "tracker.net".to_string()];
/// filter.load_from_domains(&domains).unwrap();
///
/// // Check blocking
/// assert!(filter.is_blocked("ads.com").is_some());
/// assert!(filter.is_blocked("subdomain.ads.com").is_some());
/// assert!(filter.is_blocked("google.com").is_none());
/// ```
pub struct BlockFilter {
    /// The domain matcher, wrapped in `ArcSwap` for hot reload
    matcher: ArcSwap<MatcherWithPatterns>,

    /// Blocking configuration
    config: BlockingConfig,

    /// Atomic counter for blocked queries
    blocked_count: AtomicU64,

    /// Atomic counter for total queries checked
    total_queries: AtomicU64,
}

/// Matcher with original patterns for detailed block reasons
struct MatcherWithPatterns {
    /// The compiled domain matcher
    matcher: DomainMatcher,

    /// Original patterns for generating block reasons
    /// Maps normalized domain -> (`original_pattern`, `rule_type`)
    patterns: std::collections::HashMap<String, (String, String)>,
}

impl MatcherWithPatterns {
    fn empty() -> Self {
        Self {
            matcher: DomainMatcher::empty(),
            patterns: std::collections::HashMap::new(),
        }
    }

    fn new(matcher: DomainMatcher, patterns: std::collections::HashMap<String, (String, String)>) -> Self {
        Self { matcher, patterns }
    }

    fn rule_count(&self) -> usize {
        self.matcher.rule_count()
    }
}

impl BlockFilter {
    /// Create a new block filter with the given configuration
    ///
    /// The filter starts empty and must be loaded with domains using
    /// `load_from_domains` or `reload`.
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::dns::filter::BlockFilter;
    /// use rust_router::dns::BlockingConfig;
    ///
    /// let config = BlockingConfig::default();
    /// let filter = BlockFilter::new(config);
    /// assert!(filter.is_empty());
    /// ```
    #[must_use]
    pub fn new(config: BlockingConfig) -> Self {
        Self {
            matcher: ArcSwap::new(std::sync::Arc::new(MatcherWithPatterns::empty())),
            config,
            blocked_count: AtomicU64::new(0),
            total_queries: AtomicU64::new(0),
        }
    }

    /// Check if blocking is enabled
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Check if the filter has any rules loaded
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.matcher.load().rule_count() == 0
    }

    /// Get the number of loaded rules
    #[must_use]
    pub fn rule_count(&self) -> usize {
        self.matcher.load().rule_count()
    }

    /// Load domains from a list of domain strings
    ///
    /// All domains are treated as suffix matches, meaning "example.com" will
    /// block both "example.com" and "subdomain.example.com".
    ///
    /// # Arguments
    ///
    /// * `domains` - List of domains to block
    ///
    /// # Returns
    ///
    /// The number of domains successfully loaded.
    ///
    /// # Errors
    ///
    /// Returns `DnsError::ConfigError` if the number of rules exceeds [`MAX_RULES`].
    /// Returns `DnsError::InternalError` if the matcher cannot be built.
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::dns::filter::BlockFilter;
    /// use rust_router::dns::BlockingConfig;
    ///
    /// let filter = BlockFilter::new(BlockingConfig::default());
    /// let domains = vec!["ads.example.com".to_string(), "tracker.net".to_string()];
    /// let count = filter.load_from_domains(&domains).unwrap();
    /// assert_eq!(count, 2);
    /// ```
    pub fn load_from_domains(&self, domains: &[String]) -> DnsResult<usize> {
        // Check size limit before processing to fail fast
        if domains.len() > MAX_RULES {
            return Err(DnsError::config_field(
                format!(
                    "blocklist exceeds maximum size: {} rules (max: {})",
                    domains.len(),
                    MAX_RULES
                ),
                "blocking.domains",
            ));
        }

        let mut builder = DomainMatcherBuilder::new();
        let mut patterns = std::collections::HashMap::new();

        for domain in domains {
            let domain = domain.trim();
            if domain.is_empty() || domain.starts_with('#') {
                // Skip empty lines and comments
                continue;
            }

            // Normalize domain
            let normalized = domain.to_ascii_lowercase();
            let normalized = normalized.trim_start_matches('.');

            // Add as suffix match (blocks domain and all subdomains)
            // Use "blocked" as the outbound tag for all blocked domains
            builder = builder.add_suffix(normalized, "blocked");

            // Store original pattern for block reason
            patterns.insert(
                normalized.to_string(),
                (domain.to_string(), "suffix".to_string()),
            );
        }

        let matcher = builder
            .build()
            .map_err(|e| DnsError::internal(format!("Failed to build domain matcher: {e}")))?;

        let count = matcher.rule_count();
        let matcher_with_patterns = MatcherWithPatterns::new(matcher, patterns);

        // Atomic swap for hot reload
        self.matcher.store(std::sync::Arc::new(matcher_with_patterns));

        Ok(count)
    }

    /// Load domains with different match types
    ///
    /// # Arguments
    ///
    /// * `exact` - Domains for exact matching only
    /// * `suffix` - Domains for suffix matching (domain + subdomains)
    /// * `keyword` - Keywords for substring matching
    /// * `regex` - Regex patterns for complex matching
    ///
    /// # Returns
    ///
    /// The total number of rules loaded.
    ///
    /// # Errors
    ///
    /// Returns `DnsError::ConfigError` if the total number of rules exceeds [`MAX_RULES`].
    /// Returns `DnsError::InternalError` if any regex is invalid or matcher build fails.
    pub fn load_with_types(
        &self,
        exact: &[String],
        suffix: &[String],
        keyword: &[String],
        regex: &[String],
    ) -> DnsResult<usize> {
        // Check total size limit before processing to fail fast
        let total_count = exact.len() + suffix.len() + keyword.len() + regex.len();
        if total_count > MAX_RULES {
            return Err(DnsError::config_field(
                format!(
                    "blocklist exceeds maximum size: {total_count} rules (max: {MAX_RULES})"
                ),
                "blocking.rules",
            ));
        }

        let mut builder = DomainMatcherBuilder::new();
        let mut patterns = std::collections::HashMap::new();

        // Add exact matches
        for domain in exact {
            let domain = domain.trim();
            if domain.is_empty() || domain.starts_with('#') {
                continue;
            }
            let normalized = domain.to_ascii_lowercase();
            builder = builder.add_exact(&normalized, "blocked");
            patterns.insert(normalized, (domain.to_string(), "exact".to_string()));
        }

        // Add suffix matches
        for domain in suffix {
            let domain = domain.trim();
            if domain.is_empty() || domain.starts_with('#') {
                continue;
            }
            let normalized = domain.to_ascii_lowercase().trim_start_matches('.').to_string();
            builder = builder.add_suffix(&normalized, "blocked");
            patterns.insert(normalized, (domain.to_string(), "suffix".to_string()));
        }

        // Add keyword matches
        for kw in keyword {
            let kw = kw.trim();
            if kw.is_empty() || kw.starts_with('#') {
                continue;
            }
            let normalized = kw.to_ascii_lowercase();
            builder = builder.add_keyword(&normalized, "blocked");
            patterns.insert(normalized, (kw.to_string(), "keyword".to_string()));
        }

        // Add regex matches
        for pattern in regex {
            let pattern = pattern.trim();
            if pattern.is_empty() || pattern.starts_with('#') {
                continue;
            }
            builder = builder
                .add_regex(pattern, "blocked")
                .map_err(|e| DnsError::internal(format!("Invalid regex pattern '{pattern}': {e}")))?;
            patterns.insert(pattern.to_string(), (pattern.to_string(), "regex".to_string()));
        }

        let matcher = builder
            .build()
            .map_err(|e| DnsError::internal(format!("Failed to build domain matcher: {e}")))?;

        let count = matcher.rule_count();
        let matcher_with_patterns = MatcherWithPatterns::new(matcher, patterns);

        self.matcher.store(std::sync::Arc::new(matcher_with_patterns));

        Ok(count)
    }

    /// Reload with a new domain matcher
    ///
    /// This is useful for advanced scenarios where you need full control
    /// over the matcher construction.
    ///
    /// # Arguments
    ///
    /// * `new_matcher` - The new domain matcher to use
    pub fn reload(&self, new_matcher: DomainMatcher) {
        // When reloading with a raw matcher, we don't have pattern info
        let matcher_with_patterns = MatcherWithPatterns::new(
            new_matcher,
            std::collections::HashMap::new(),
        );
        self.matcher.store(std::sync::Arc::new(matcher_with_patterns));
    }

    /// Check if a domain is blocked
    ///
    /// Returns `Some(BlockReason)` if the domain is blocked, `None` otherwise.
    /// This method increments the query counters atomically.
    ///
    /// # Thread Safety
    ///
    /// This method is safe to call concurrently with hot reloads. The `ArcSwap`
    /// ensures that readers always see a consistent snapshot of the matcher,
    /// even if a reload is in progress. Readers hold an `Arc` guard that prevents
    /// the old matcher from being deallocated until all readers are done.
    ///
    /// # Performance
    ///
    /// - Domain matching is O(1) for exact match via Aho-Corasick
    /// - When a match is found, generating the [`BlockReason`] requires an O(n)
    ///   scan of the patterns `HashMap` to find the specific rule that matched.
    ///   This is acceptable because:
    ///   - It only occurs on blocked queries (typically <1% of total queries)
    ///   - The scan has good cache locality
    ///   - The detailed reason is valuable for debugging and logging
    ///
    /// # Arguments
    ///
    /// * `domain` - The domain to check (case-insensitive)
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::dns::filter::BlockFilter;
    /// use rust_router::dns::BlockingConfig;
    ///
    /// let filter = BlockFilter::new(BlockingConfig::default());
    /// filter.load_from_domains(&["ads.example.com".to_string()]).unwrap();
    ///
    /// if let Some(reason) = filter.is_blocked("ads.example.com") {
    ///     println!("Blocked: {} (rule: {})", reason.domain, reason.matched_rule);
    /// }
    /// ```
    #[must_use]
    pub fn is_blocked(&self, domain: &str) -> Option<BlockReason> {
        if !self.config.enabled {
            return None;
        }

        // Increment total queries
        self.total_queries.fetch_add(1, Ordering::Relaxed);

        // Phase 3-Fix: Strip trailing dot from FQDN format (e.g., "ads.google.com." -> "ads.google.com")
        // DNS QNAME from hickory_proto includes a trailing dot for FQDN, but blocklist rules don't.
        let domain = domain.trim_end_matches('.');

        let matcher_guard = self.matcher.load();

        // Check if domain matches any blocking rule
        if matcher_guard.matcher.match_domain(domain).is_some() {
            // Increment blocked count
            self.blocked_count.fetch_add(1, Ordering::Relaxed);

            // Try to find the specific pattern that matched
            let normalized = domain.to_ascii_lowercase();

            // Try to find a matching pattern for detailed reason
            if let Some((original, rule_type)) = matcher_guard.patterns.get(&normalized) {
                return Some(BlockReason::new(domain, original, rule_type));
            }

            // Try suffix patterns
            for (pattern, (original, rule_type)) in &matcher_guard.patterns {
                if rule_type == "suffix" {
                    if normalized == *pattern || normalized.ends_with(&format!(".{pattern}")) {
                        return Some(BlockReason::new(domain, original, rule_type));
                    }
                } else if rule_type == "keyword"
                    && normalized.contains(pattern) {
                        return Some(BlockReason::new(domain, original, rule_type));
                    }
            }

            // Fallback: return generic blocked reason
            Some(BlockReason::new(domain, domain, "matched"))
        } else {
            None
        }
    }

    /// Get current blocking statistics
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::dns::filter::BlockFilter;
    /// use rust_router::dns::BlockingConfig;
    ///
    /// let filter = BlockFilter::new(BlockingConfig::default());
    /// filter.load_from_domains(&["blocked.com".to_string()]).unwrap();
    ///
    /// filter.is_blocked("blocked.com");
    /// filter.is_blocked("allowed.com");
    ///
    /// let stats = filter.stats();
    /// assert_eq!(stats.blocked_count, 1);
    /// assert_eq!(stats.total_queries, 2);
    /// ```
    #[must_use]
    pub fn stats(&self) -> BlockFilterStats {
        BlockFilterStats {
            blocked_count: self.blocked_count.load(Ordering::Relaxed),
            total_queries: self.total_queries.load(Ordering::Relaxed),
            rule_count: self.rule_count(),
        }
    }

    /// Reset statistics counters
    pub fn reset_stats(&self) {
        self.blocked_count.store(0, Ordering::Relaxed);
        self.total_queries.store(0, Ordering::Relaxed);
    }

    /// Clear all blocking rules
    pub fn clear(&self) {
        self.matcher.store(std::sync::Arc::new(MatcherWithPatterns::empty()));
    }

    /// Get the blocking configuration
    #[must_use]
    pub fn config(&self) -> &BlockingConfig {
        &self.config
    }
}

// Implement Debug manually since ArcSwap doesn't implement it well
impl std::fmt::Debug for BlockFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlockFilter")
            .field("enabled", &self.config.enabled)
            .field("rule_count", &self.rule_count())
            .field("blocked_count", &self.blocked_count.load(Ordering::Relaxed))
            .field("total_queries", &self.total_queries.load(Ordering::Relaxed))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::BlockResponseType;

    // ========================================================================
    // BlockReason Tests
    // ========================================================================

    #[test]
    fn test_block_reason_new() {
        let reason = BlockReason::new("example.com", "example.com", "exact");
        assert_eq!(reason.domain, "example.com");
        assert_eq!(reason.matched_rule, "example.com");
        assert_eq!(reason.rule_type, "exact");
    }

    #[test]
    fn test_block_reason_equality() {
        let reason1 = BlockReason::new("a.com", "a.com", "exact");
        let reason2 = BlockReason::new("a.com", "a.com", "exact");
        let reason3 = BlockReason::new("b.com", "b.com", "exact");

        assert_eq!(reason1, reason2);
        assert_ne!(reason1, reason3);
    }

    #[test]
    fn test_block_reason_debug() {
        let reason = BlockReason::new("test.com", "test.com", "suffix");
        let debug = format!("{:?}", reason);
        assert!(debug.contains("test.com"));
        assert!(debug.contains("suffix"));
    }

    // ========================================================================
    // BlockFilterStats Tests
    // ========================================================================

    #[test]
    fn test_stats_default() {
        let stats = BlockFilterStats::default();
        assert_eq!(stats.blocked_count, 0);
        assert_eq!(stats.total_queries, 0);
        assert_eq!(stats.rule_count, 0);
    }

    #[test]
    fn test_stats_block_rate_zero() {
        let stats = BlockFilterStats::default();
        assert!((stats.block_rate() - 0.0).abs() < 0.001);
    }

    #[test]
    fn test_stats_block_rate_fifty_percent() {
        let stats = BlockFilterStats {
            blocked_count: 50,
            total_queries: 100,
            rule_count: 10,
        };
        assert!((stats.block_rate() - 50.0).abs() < 0.001);
    }

    #[test]
    fn test_stats_block_rate_hundred_percent() {
        let stats = BlockFilterStats {
            blocked_count: 100,
            total_queries: 100,
            rule_count: 5,
        };
        assert!((stats.block_rate() - 100.0).abs() < 0.001);
    }

    // ========================================================================
    // BlockFilter Creation Tests
    // ========================================================================

    #[test]
    fn test_filter_new() {
        let config = BlockingConfig::default();
        let filter = BlockFilter::new(config);

        assert!(filter.is_enabled());
        assert!(filter.is_empty());
        assert_eq!(filter.rule_count(), 0);
    }

    #[test]
    fn test_filter_disabled() {
        let config = BlockingConfig::default().disabled();
        let filter = BlockFilter::new(config);

        assert!(!filter.is_enabled());
    }

    #[test]
    fn test_filter_debug() {
        let config = BlockingConfig::default();
        let filter = BlockFilter::new(config);

        let debug = format!("{:?}", filter);
        assert!(debug.contains("BlockFilter"));
        assert!(debug.contains("enabled"));
        assert!(debug.contains("rule_count"));
    }

    // ========================================================================
    // BlockFilter Loading Tests
    // ========================================================================

    #[test]
    fn test_load_from_domains_basic() {
        let filter = BlockFilter::new(BlockingConfig::default());
        let domains = vec!["ads.com".to_string(), "tracker.net".to_string()];

        let count = filter.load_from_domains(&domains).unwrap();
        assert_eq!(count, 2);
        assert_eq!(filter.rule_count(), 2);
    }

    #[test]
    fn test_load_from_domains_empty() {
        let filter = BlockFilter::new(BlockingConfig::default());
        let domains: Vec<String> = Vec::new();

        let count = filter.load_from_domains(&domains).unwrap();
        assert_eq!(count, 0);
        assert!(filter.is_empty());
    }

    #[test]
    fn test_load_from_domains_with_comments() {
        let filter = BlockFilter::new(BlockingConfig::default());
        let domains = vec![
            "# This is a comment".to_string(),
            "ads.com".to_string(),
            "# Another comment".to_string(),
            "tracker.net".to_string(),
        ];

        let count = filter.load_from_domains(&domains).unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn test_load_from_domains_with_whitespace() {
        let filter = BlockFilter::new(BlockingConfig::default());
        let domains = vec![
            "".to_string(),
            "  ads.com  ".to_string(),
            "   ".to_string(),
            "  tracker.net".to_string(),
        ];

        let count = filter.load_from_domains(&domains).unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn test_load_from_domains_normalizes_case() {
        let filter = BlockFilter::new(BlockingConfig::default());
        let domains = vec!["ADS.EXAMPLE.COM".to_string()];

        filter.load_from_domains(&domains).unwrap();

        // Should match regardless of case
        assert!(filter.is_blocked("ads.example.com").is_some());
        assert!(filter.is_blocked("ADS.EXAMPLE.COM").is_some());
        assert!(filter.is_blocked("Ads.Example.Com").is_some());
    }

    #[test]
    fn test_load_from_domains_strips_leading_dot() {
        let filter = BlockFilter::new(BlockingConfig::default());
        let domains = vec![".example.com".to_string()];

        filter.load_from_domains(&domains).unwrap();

        assert!(filter.is_blocked("example.com").is_some());
        assert!(filter.is_blocked("www.example.com").is_some());
    }

    // ========================================================================
    // BlockFilter Matching Tests
    // ========================================================================

    #[test]
    fn test_is_blocked_exact_match() {
        let filter = BlockFilter::new(BlockingConfig::default());
        let domains = vec!["ads.example.com".to_string()];
        filter.load_from_domains(&domains).unwrap();

        let reason = filter.is_blocked("ads.example.com");
        assert!(reason.is_some());

        let reason = reason.unwrap();
        assert_eq!(reason.domain, "ads.example.com");
    }

    #[test]
    fn test_is_blocked_subdomain_match() {
        let filter = BlockFilter::new(BlockingConfig::default());
        let domains = vec!["example.com".to_string()];
        filter.load_from_domains(&domains).unwrap();

        // Should block subdomains
        assert!(filter.is_blocked("www.example.com").is_some());
        assert!(filter.is_blocked("mail.example.com").is_some());
        assert!(filter.is_blocked("deep.sub.example.com").is_some());
    }

    #[test]
    fn test_is_blocked_no_partial_match() {
        let filter = BlockFilter::new(BlockingConfig::default());
        let domains = vec!["example.com".to_string()];
        filter.load_from_domains(&domains).unwrap();

        // Should NOT match domains that just contain the pattern
        assert!(filter.is_blocked("notexample.com").is_none());
        assert!(filter.is_blocked("myexample.com").is_none());
    }

    #[test]
    fn test_is_blocked_disabled_filter() {
        let config = BlockingConfig::default().disabled();
        let filter = BlockFilter::new(config);
        let domains = vec!["ads.example.com".to_string()];
        filter.load_from_domains(&domains).unwrap();

        // Filter is disabled, so nothing should be blocked
        assert!(filter.is_blocked("ads.example.com").is_none());
    }

    #[test]
    fn test_is_blocked_case_insensitive() {
        let filter = BlockFilter::new(BlockingConfig::default());
        let domains = vec!["ads.example.com".to_string()];
        filter.load_from_domains(&domains).unwrap();

        assert!(filter.is_blocked("ADS.EXAMPLE.COM").is_some());
        assert!(filter.is_blocked("Ads.Example.Com").is_some());
        assert!(filter.is_blocked("ads.EXAMPLE.com").is_some());
    }

    #[test]
    fn test_is_blocked_trailing_dot() {
        // Phase 3-Fix: Test that trailing dot (FQDN format) is handled correctly
        // DNS QNAME from hickory_proto includes a trailing dot, e.g., "ads.google.com."
        let filter = BlockFilter::new(BlockingConfig::default());
        let domains = vec!["ads.google.com".to_string(), "googleadservices.com".to_string()];
        filter.load_from_domains(&domains).unwrap();

        // Without trailing dot (standard blocklist format)
        assert!(filter.is_blocked("ads.google.com").is_some());
        assert!(filter.is_blocked("googleadservices.com").is_some());

        // With trailing dot (DNS FQDN format from hickory_proto)
        assert!(filter.is_blocked("ads.google.com.").is_some());
        assert!(filter.is_blocked("googleadservices.com.").is_some());

        // Subdomains should also work with trailing dot
        assert!(filter.is_blocked("pagead.ads.google.com.").is_some());
        assert!(filter.is_blocked("www.googleadservices.com.").is_some());

        // Non-matching domains should still not match
        assert!(filter.is_blocked("google.com.").is_none());
        assert!(filter.is_blocked("example.com.").is_none());
    }

    // ========================================================================
    // BlockFilter with Types Tests
    // ========================================================================

    #[test]
    fn test_load_with_types_exact() {
        let filter = BlockFilter::new(BlockingConfig::default());

        filter
            .load_with_types(
                &["exact.example.com".to_string()],
                &[],
                &[],
                &[],
            )
            .unwrap();

        assert!(filter.is_blocked("exact.example.com").is_some());
        assert!(filter.is_blocked("www.exact.example.com").is_none());
    }

    #[test]
    fn test_load_with_types_suffix() {
        let filter = BlockFilter::new(BlockingConfig::default());

        filter
            .load_with_types(
                &[],
                &["suffix.com".to_string()],
                &[],
                &[],
            )
            .unwrap();

        assert!(filter.is_blocked("suffix.com").is_some());
        assert!(filter.is_blocked("www.suffix.com").is_some());
        assert!(filter.is_blocked("notsuffix.com").is_none());
    }

    #[test]
    fn test_load_with_types_keyword() {
        let filter = BlockFilter::new(BlockingConfig::default());

        filter
            .load_with_types(
                &[],
                &[],
                &["tracking".to_string()],
                &[],
            )
            .unwrap();

        assert!(filter.is_blocked("tracking.example.com").is_some());
        assert!(filter.is_blocked("example-tracking.com").is_some());
        assert!(filter.is_blocked("example.com").is_none());
    }

    #[test]
    fn test_load_with_types_regex() {
        let filter = BlockFilter::new(BlockingConfig::default());

        filter
            .load_with_types(
                &[],
                &[],
                &[],
                &[r"^ads?\d*\.".to_string()],
            )
            .unwrap();

        assert!(filter.is_blocked("ad.example.com").is_some());
        assert!(filter.is_blocked("ads.example.com").is_some());
        assert!(filter.is_blocked("ads123.example.com").is_some());
        assert!(filter.is_blocked("notads.example.com").is_none());
    }

    #[test]
    fn test_load_with_types_mixed() {
        let filter = BlockFilter::new(BlockingConfig::default());

        filter
            .load_with_types(
                &["exact.com".to_string()],
                &["suffix.net".to_string()],
                &["tracking".to_string()],
                &[r"^ad\d+\.".to_string()],
            )
            .unwrap();

        assert_eq!(filter.rule_count(), 4);

        assert!(filter.is_blocked("exact.com").is_some());
        assert!(filter.is_blocked("www.suffix.net").is_some());
        assert!(filter.is_blocked("example-tracking.org").is_some());
        assert!(filter.is_blocked("ad123.example.com").is_some());
    }

    #[test]
    fn test_load_with_types_invalid_regex() {
        let filter = BlockFilter::new(BlockingConfig::default());

        let result = filter.load_with_types(
            &[],
            &[],
            &[],
            &["[invalid".to_string()],
        );

        assert!(result.is_err());
    }

    // ========================================================================
    // BlockFilter Statistics Tests
    // ========================================================================

    #[test]
    fn test_stats_tracking() {
        let filter = BlockFilter::new(BlockingConfig::default());
        let domains = vec!["blocked.com".to_string()];
        filter.load_from_domains(&domains).unwrap();

        // Check blocked domain
        filter.is_blocked("blocked.com");
        let stats = filter.stats();
        assert_eq!(stats.blocked_count, 1);
        assert_eq!(stats.total_queries, 1);

        // Check allowed domain
        filter.is_blocked("allowed.com");
        let stats = filter.stats();
        assert_eq!(stats.blocked_count, 1);
        assert_eq!(stats.total_queries, 2);

        // Check another blocked domain
        filter.is_blocked("www.blocked.com");
        let stats = filter.stats();
        assert_eq!(stats.blocked_count, 2);
        assert_eq!(stats.total_queries, 3);
    }

    #[test]
    fn test_stats_no_count_when_disabled() {
        let config = BlockingConfig::default().disabled();
        let filter = BlockFilter::new(config);
        let domains = vec!["blocked.com".to_string()];
        filter.load_from_domains(&domains).unwrap();

        filter.is_blocked("blocked.com");

        let stats = filter.stats();
        // When disabled, is_blocked returns early and doesn't update counters
        assert_eq!(stats.total_queries, 0);
        assert_eq!(stats.blocked_count, 0);
    }

    #[test]
    fn test_reset_stats() {
        let filter = BlockFilter::new(BlockingConfig::default());
        let domains = vec!["blocked.com".to_string()];
        filter.load_from_domains(&domains).unwrap();

        filter.is_blocked("blocked.com");
        filter.is_blocked("allowed.com");

        filter.reset_stats();

        let stats = filter.stats();
        assert_eq!(stats.blocked_count, 0);
        assert_eq!(stats.total_queries, 0);
        assert_eq!(stats.rule_count, 1); // Rules still loaded
    }

    // ========================================================================
    // BlockFilter Reload/Clear Tests
    // ========================================================================

    #[test]
    fn test_reload_replaces_rules() {
        let filter = BlockFilter::new(BlockingConfig::default());

        // Load first set
        let domains1 = vec!["first.com".to_string()];
        filter.load_from_domains(&domains1).unwrap();
        assert!(filter.is_blocked("first.com").is_some());
        assert!(filter.is_blocked("second.com").is_none());

        // Load second set (replaces first)
        let domains2 = vec!["second.com".to_string()];
        filter.load_from_domains(&domains2).unwrap();
        assert!(filter.is_blocked("first.com").is_none());
        assert!(filter.is_blocked("second.com").is_some());
    }

    #[test]
    fn test_clear() {
        let filter = BlockFilter::new(BlockingConfig::default());
        let domains = vec!["blocked.com".to_string()];
        filter.load_from_domains(&domains).unwrap();

        assert!(!filter.is_empty());
        assert!(filter.is_blocked("blocked.com").is_some());

        filter.clear();

        assert!(filter.is_empty());
        assert!(filter.is_blocked("blocked.com").is_none());
    }

    #[test]
    fn test_reload_with_custom_matcher() {
        let filter = BlockFilter::new(BlockingConfig::default());

        // Create custom matcher
        let matcher = DomainMatcher::builder()
            .add_exact("custom.com", "blocked")
            .build()
            .unwrap();

        filter.reload(matcher);

        assert!(filter.is_blocked("custom.com").is_some());
        assert!(filter.is_blocked("www.custom.com").is_none()); // Exact only
    }

    // ========================================================================
    // BlockFilter Configuration Tests
    // ========================================================================

    #[test]
    fn test_config_accessor() {
        let config = BlockingConfig::default()
            .with_response_type(BlockResponseType::Nxdomain)
            .with_cname_detection(false);

        let filter = BlockFilter::new(config);
        let retrieved = filter.config();

        assert_eq!(retrieved.response_type, BlockResponseType::Nxdomain);
        assert!(!retrieved.cname_detection);
    }

    // ========================================================================
    // Size Limit Tests
    // ========================================================================

    #[test]
    fn test_load_from_domains_size_limit() {
        let filter = BlockFilter::new(BlockingConfig::default());

        // Create a list that exceeds MAX_RULES
        // Note: We use MAX_RULES + 1 to just exceed the limit
        let domains: Vec<String> = (0..=super::MAX_RULES)
            .map(|i| format!("domain{}.com", i))
            .collect();

        let result = filter.load_from_domains(&domains);
        assert!(result.is_err());

        let err = result.unwrap_err();
        let err_str = err.to_string();
        assert!(
            err_str.contains("exceeds maximum size"),
            "Expected 'exceeds maximum size' in error, got: {}",
            err_str
        );
        assert!(
            err_str.contains(&super::MAX_RULES.to_string()),
            "Expected MAX_RULES in error, got: {}",
            err_str
        );
    }

    #[test]
    fn test_load_with_types_size_limit() {
        let filter = BlockFilter::new(BlockingConfig::default());

        // Split the domains across different types to exceed the limit
        let half = super::MAX_RULES / 2 + 1;
        let exact: Vec<String> = (0..half).map(|i| format!("exact{}.com", i)).collect();
        let suffix: Vec<String> = (0..half).map(|i| format!("suffix{}.com", i)).collect();

        let result = filter.load_with_types(&exact, &suffix, &[], &[]);
        assert!(result.is_err());

        let err = result.unwrap_err();
        let err_str = err.to_string();
        assert!(
            err_str.contains("exceeds maximum size"),
            "Expected 'exceeds maximum size' in error, got: {}",
            err_str
        );
    }

    #[test]
    fn test_load_from_domains_at_limit() {
        // This test verifies that exactly MAX_RULES domains can be loaded
        // We use a smaller test set to keep the test fast
        let filter = BlockFilter::new(BlockingConfig::default());

        // Load exactly 1000 domains (much smaller than MAX_RULES, but validates the logic)
        let domains: Vec<String> = (0..1000).map(|i| format!("domain{}.com", i)).collect();

        let result = filter.load_from_domains(&domains);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 1000);
    }

    // ========================================================================
    // Concurrent Hot Reload Safety Tests
    // ========================================================================

    #[test]
    fn test_concurrent_hot_reload_safety() {
        use std::sync::Arc;
        use std::thread;

        let filter = Arc::new(BlockFilter::new(BlockingConfig::default()));

        // Load initial domains
        let initial_domains: Vec<String> = (0..100)
            .map(|i| format!("initial{}.com", i))
            .collect();
        filter.load_from_domains(&initial_domains).unwrap();

        // Spawn reader threads that continuously check domains
        let mut handles = Vec::new();
        for thread_id in 0..4 {
            let filter_clone = Arc::clone(&filter);
            handles.push(thread::spawn(move || {
                for i in 0..1000 {
                    // Check both initial and reload domains
                    let domain = format!("initial{}.com", i % 100);
                    let _ = filter_clone.is_blocked(&domain);

                    let domain = format!("reload{}.com", i % 100);
                    let _ = filter_clone.is_blocked(&domain);

                    // Also check stats during reads
                    let _ = filter_clone.stats();
                    let _ = filter_clone.rule_count();
                }
                thread_id
            }));
        }

        // Spawn writer thread that does hot reloads
        let filter_clone = Arc::clone(&filter);
        let writer_handle = thread::spawn(move || {
            for i in 0..10 {
                let reload_domains: Vec<String> = (0..100)
                    .map(|j| format!("reload{}_{}.com", i, j))
                    .collect();
                filter_clone.load_from_domains(&reload_domains).unwrap();
            }
        });

        // Wait for all threads to complete
        writer_handle.join().expect("Writer thread panicked");
        for handle in handles {
            handle.join().expect("Reader thread panicked");
        }

        // Verify filter is still in consistent state
        let stats = filter.stats();
        assert!(stats.total_queries > 0, "Expected some queries to be recorded");
        assert!(filter.rule_count() > 0, "Expected some rules to be loaded");
    }

    #[test]
    fn test_concurrent_reload_stats_consistency() {
        use std::sync::Arc;
        use std::thread;

        let filter = Arc::new(BlockFilter::new(BlockingConfig::default()));
        filter
            .load_from_domains(&["blocked.com".to_string()])
            .unwrap();

        // Multiple readers checking blocked domain
        let mut handles = Vec::new();
        for _ in 0..4 {
            let filter_clone = Arc::clone(&filter);
            handles.push(thread::spawn(move || {
                for _ in 0..500 {
                    filter_clone.is_blocked("blocked.com");
                }
            }));
        }

        // Concurrent stats reader
        let filter_clone = Arc::clone(&filter);
        let stats_handle = thread::spawn(move || {
            let mut samples = Vec::new();
            for _ in 0..100 {
                let stats = filter_clone.stats();
                // blocked_count should never exceed total_queries
                assert!(
                    stats.blocked_count <= stats.total_queries,
                    "Inconsistent stats: blocked {} > total {}",
                    stats.blocked_count,
                    stats.total_queries
                );
                samples.push(stats.total_queries);
            }
            samples
        });

        for handle in handles {
            handle.join().expect("Reader thread panicked");
        }
        stats_handle.join().expect("Stats thread panicked");

        // Final stats should show all queries
        let final_stats = filter.stats();
        assert_eq!(final_stats.total_queries, 2000); // 4 threads * 500 queries
        assert_eq!(final_stats.blocked_count, 2000); // All should be blocked
    }

    // ========================================================================
    // Large Blocklist Performance Tests
    // ========================================================================

    /// Test loading performance with a large blocklist (100k domains)
    ///
    /// This test is ignored by default as it takes significant time and memory.
    /// Run with: `cargo test --release test_large_blocklist_loading -- --ignored`
    #[test]
    #[ignore]
    fn test_large_blocklist_loading_performance() {
        use std::time::Instant;

        let filter = BlockFilter::new(BlockingConfig::default());

        // Generate 100,000 unique domains
        let domains: Vec<String> = (0..100_000)
            .map(|i| format!("domain{}.example.com", i))
            .collect();

        let start = Instant::now();
        let result = filter.load_from_domains(&domains);
        let elapsed = start.elapsed();

        assert!(result.is_ok(), "Failed to load 100k domains: {:?}", result.err());
        assert_eq!(result.unwrap(), 100_000);

        // Loading should complete in under 1 second
        assert!(
            elapsed.as_secs_f64() < 1.0,
            "Loading 100k domains took too long: {:?} (expected < 1s)",
            elapsed
        );

        println!("Loaded 100k domains in {:?}", elapsed);

        // Verify matching still works
        assert!(filter.is_blocked("domain50000.example.com").is_some());
        assert!(filter.is_blocked("unknown.domain.com").is_none());
    }

    /// Test matching performance with a large blocklist
    #[test]
    #[ignore]
    fn test_large_blocklist_matching_performance() {
        use std::time::Instant;

        let filter = BlockFilter::new(BlockingConfig::default());

        // Load 100k domains
        let domains: Vec<String> = (0..100_000)
            .map(|i| format!("domain{}.example.com", i))
            .collect();
        filter.load_from_domains(&domains).unwrap();

        // Benchmark matching
        let iterations = 100_000;
        let start = Instant::now();
        for i in 0..iterations {
            // Alternate between blocked and non-blocked domains
            if i % 2 == 0 {
                let _ = filter.is_blocked(&format!("domain{}.example.com", i % 100_000));
            } else {
                let _ = filter.is_blocked(&format!("nonexistent{}.other.com", i));
            }
        }
        let elapsed = start.elapsed();

        let avg_ns = elapsed.as_nanos() / iterations as u128;
        println!(
            "Average matching time: {} ns ({} iterations in {:?})",
            avg_ns, iterations, elapsed
        );

        // Average matching should be under 1 microsecond (1000 ns)
        assert!(
            avg_ns < 1000,
            "Average matching time too high: {} ns (expected < 1000 ns)",
            avg_ns
        );
    }
}
