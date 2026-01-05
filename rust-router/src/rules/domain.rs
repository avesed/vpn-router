//! High-performance domain matcher using Aho-Corasick algorithm
//!
//! This module provides efficient domain matching for routing decisions.
//! It supports four match types with different performance characteristics:
//!
//! - **Exact match**: O(1) hash lookup
//! - **Suffix match**: O(n) where n is domain length (Aho-Corasick)
//! - **Keyword match**: O(n) substring search (Aho-Corasick)
//! - **Regex match**: O(n*m) where m is pattern complexity
//!
//! # Architecture
//!
//! The matcher is built using a builder pattern and optimized for the common
//! case of suffix matching with ~20,000+ domain rules from domain-catalog.json.
//!
//! # Example
//!
//! ```
//! use rust_router::rules::domain::DomainMatcher;
//!
//! let matcher = DomainMatcher::builder()
//!     .add_exact("example.com", "direct")
//!     .add_suffix("google.com", "proxy")
//!     .add_keyword("ads", "block")
//!     .build()
//!     .unwrap();
//!
//! assert_eq!(matcher.match_domain("example.com"), Some("direct"));
//! assert_eq!(matcher.match_domain("mail.google.com"), Some("proxy"));
//! assert_eq!(matcher.match_domain("ads.example.org"), Some("block"));
//! ```

use std::collections::HashMap;

use aho_corasick::AhoCorasick;
use regex::Regex;

use crate::error::RuleError;

/// High-performance domain matcher supporting multiple match types
///
/// The matcher processes domains in priority order:
/// 1. Exact match (highest priority)
/// 2. Suffix match
/// 3. Keyword match
/// 4. Regex match (lowest priority)
///
/// This ordering ensures that more specific rules take precedence
/// over more general patterns.
#[derive(Debug)]
pub struct DomainMatcher {
    /// Exact domain to outbound mapping (O(1) lookup)
    exact_domains: HashMap<String, String>,

    /// Aho-Corasick automaton for suffix matching
    /// Stores reversed domain patterns for efficient suffix search
    suffix_automaton: Option<AhoCorasick>,
    /// Outbound tags indexed by pattern ID in the suffix automaton
    suffix_outbounds: Vec<String>,
    /// Original suffix patterns (reversed and with dot prefix) for validation
    suffix_patterns: Vec<String>,

    /// Aho-Corasick automaton for keyword matching
    keyword_automaton: Option<AhoCorasick>,
    /// Outbound tags indexed by pattern ID in the keyword automaton
    keyword_outbounds: Vec<String>,

    /// Compiled regex patterns with their outbound tags
    regex_patterns: Vec<(Regex, String)>,

    /// Total count of all rules
    rule_count: usize,
}

impl DomainMatcher {
    /// Create a new builder for constructing a `DomainMatcher`
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::rules::domain::DomainMatcher;
    ///
    /// let matcher = DomainMatcher::builder()
    ///     .add_exact("example.com", "direct")
    ///     .build()
    ///     .unwrap();
    /// ```
    #[must_use]
    pub fn builder() -> DomainMatcherBuilder {
        DomainMatcherBuilder::new()
    }

    /// Create an empty domain matcher
    ///
    /// An empty matcher will return `None` for all domain lookups.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            exact_domains: HashMap::new(),
            suffix_automaton: None,
            suffix_outbounds: Vec::new(),
            suffix_patterns: Vec::new(),
            keyword_automaton: None,
            keyword_outbounds: Vec::new(),
            regex_patterns: Vec::new(),
            rule_count: 0,
        }
    }

    /// Match a domain against all patterns
    ///
    /// Returns the outbound tag of the first matching rule, or `None` if
    /// no rules match.
    ///
    /// # Priority Order
    ///
    /// 1. Exact match (highest priority)
    /// 2. Suffix match
    /// 3. Keyword match
    /// 4. Regex match (lowest priority)
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::rules::domain::DomainMatcher;
    ///
    /// let matcher = DomainMatcher::builder()
    ///     .add_exact("example.com", "direct")
    ///     .add_suffix("example.com", "proxy") // Lower priority than exact
    ///     .build()
    ///     .unwrap();
    ///
    /// // Exact match takes precedence
    /// assert_eq!(matcher.match_domain("example.com"), Some("direct"));
    /// // Suffix match for subdomain
    /// assert_eq!(matcher.match_domain("www.example.com"), Some("proxy"));
    /// ```
    #[must_use]
    pub fn match_domain(&self, domain: &str) -> Option<&str> {
        if domain.is_empty() {
            return None;
        }

        // Normalize domain to lowercase
        let domain_lower = domain.to_ascii_lowercase();

        // Priority 1: Exact match (O(1))
        if let Some(outbound) = self.exact_domains.get(&domain_lower) {
            return Some(outbound.as_str());
        }

        // Priority 2: Suffix match
        if let Some(outbound) = self.match_suffix(&domain_lower) {
            return Some(outbound);
        }

        // Priority 3: Keyword match
        if let Some(outbound) = self.match_keyword(&domain_lower) {
            return Some(outbound);
        }

        // Priority 4: Regex match
        self.match_regex(&domain_lower)
    }

    /// Match using suffix patterns
    ///
    /// Uses reversed domain matching with Aho-Corasick:
    /// - Pattern "google.com" is stored as ".moc.elgoog"
    /// - Domain "mail.google.com" is searched as "moc.elgoog.liam"
    /// - If the reversed pattern is found at position 0, it's a suffix match
    fn match_suffix(&self, domain: &str) -> Option<&str> {
        let automaton = self.suffix_automaton.as_ref()?;

        // Reverse the domain and add leading dot for proper suffix matching
        // "mail.google.com" -> ".moc.elgoog.liam"
        let reversed: String = format!(".{}", domain.chars().rev().collect::<String>());

        // Find all matches and check if any match at position 0
        for mat in automaton.find_iter(&reversed) {
            if mat.start() == 0 {
                // Verify it's a complete match (ends at dot boundary or end of string)
                let pattern = &self.suffix_patterns[mat.pattern().as_usize()];
                let match_end = mat.end();

                // Valid suffix match if:
                // 1. Pattern matches the entire reversed domain, OR
                // 2. Pattern ends at a dot boundary (the character after the match is a dot or end)
                if match_end == reversed.len() || reversed.as_bytes().get(match_end) == Some(&b'.') {
                    // Also verify exact pattern length match to avoid partial matches
                    if pattern.len() == mat.len() {
                        return Some(&self.suffix_outbounds[mat.pattern().as_usize()]);
                    }
                }
            }
        }

        None
    }

    /// Match using keyword patterns (substring search)
    fn match_keyword(&self, domain: &str) -> Option<&str> {
        let automaton = self.keyword_automaton.as_ref()?;

        // Find first match
        if let Some(mat) = automaton.find(domain) {
            return Some(&self.keyword_outbounds[mat.pattern().as_usize()]);
        }

        None
    }

    /// Match using regex patterns
    fn match_regex(&self, domain: &str) -> Option<&str> {
        for (regex, outbound) in &self.regex_patterns {
            if regex.is_match(domain) {
                return Some(outbound.as_str());
            }
        }

        None
    }

    /// Check if the matcher has any rules
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::rules::domain::DomainMatcher;
    ///
    /// let empty = DomainMatcher::empty();
    /// assert!(empty.is_empty());
    ///
    /// let matcher = DomainMatcher::builder()
    ///     .add_exact("example.com", "direct")
    ///     .build()
    ///     .unwrap();
    /// assert!(!matcher.is_empty());
    /// ```
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rule_count == 0
    }

    /// Get the total number of rules
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::rules::domain::DomainMatcher;
    ///
    /// let matcher = DomainMatcher::builder()
    ///     .add_exact("a.com", "direct")
    ///     .add_suffix("b.com", "proxy")
    ///     .add_keyword("ads", "block")
    ///     .build()
    ///     .unwrap();
    ///
    /// assert_eq!(matcher.rule_count(), 3);
    /// ```
    #[must_use]
    pub fn rule_count(&self) -> usize {
        self.rule_count
    }

    /// Get the number of exact match rules
    #[must_use]
    pub fn exact_count(&self) -> usize {
        self.exact_domains.len()
    }

    /// Get the number of suffix match rules
    #[must_use]
    pub fn suffix_count(&self) -> usize {
        self.suffix_outbounds.len()
    }

    /// Get the number of keyword match rules
    #[must_use]
    pub fn keyword_count(&self) -> usize {
        self.keyword_outbounds.len()
    }

    /// Get the number of regex match rules
    #[must_use]
    pub fn regex_count(&self) -> usize {
        self.regex_patterns.len()
    }
}

/// Builder for constructing a `DomainMatcher`
///
/// The builder collects all rules and compiles them into an efficient
/// matcher when `build()` is called.
///
/// # Example
///
/// ```
/// use rust_router::rules::domain::DomainMatcherBuilder;
///
/// let matcher = DomainMatcherBuilder::new()
///     .add_exact("example.com", "direct")
///     .add_suffix("google.com", "proxy")
///     .add_keyword("facebook", "social")
///     .add_regex(r".*\.cn$", "cn-proxy")
///     .unwrap()
///     .build()
///     .unwrap();
/// ```
#[derive(Debug, Default)]
pub struct DomainMatcherBuilder {
    exact: Vec<(String, String)>,
    suffix: Vec<(String, String)>,
    keyword: Vec<(String, String)>,
    regex: Vec<(String, String)>,
}

impl DomainMatcherBuilder {
    /// Create a new empty builder
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an exact domain match rule
    ///
    /// The domain is matched exactly (case-insensitive).
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::rules::domain::DomainMatcherBuilder;
    ///
    /// let matcher = DomainMatcherBuilder::new()
    ///     .add_exact("example.com", "direct")
    ///     .build()
    ///     .unwrap();
    ///
    /// assert!(matcher.match_domain("example.com").is_some());
    /// assert!(matcher.match_domain("EXAMPLE.COM").is_some());
    /// assert!(matcher.match_domain("www.example.com").is_none());
    /// ```
    #[must_use]
    pub fn add_exact(mut self, domain: impl Into<String>, outbound: impl Into<String>) -> Self {
        let domain = domain.into().to_ascii_lowercase();
        self.exact.push((domain, outbound.into()));
        self
    }

    /// Add a suffix match rule
    ///
    /// Matches any domain that ends with the given suffix.
    /// The suffix "google.com" matches:
    /// - "google.com" (exact)
    /// - "www.google.com"
    /// - "mail.google.com"
    ///
    /// But NOT:
    /// - "notgoogle.com" (must be at domain boundary)
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::rules::domain::DomainMatcherBuilder;
    ///
    /// let matcher = DomainMatcherBuilder::new()
    ///     .add_suffix("google.com", "proxy")
    ///     .build()
    ///     .unwrap();
    ///
    /// assert!(matcher.match_domain("google.com").is_some());
    /// assert!(matcher.match_domain("www.google.com").is_some());
    /// assert!(matcher.match_domain("notgoogle.com").is_none());
    /// ```
    #[must_use]
    pub fn add_suffix(mut self, suffix: impl Into<String>, outbound: impl Into<String>) -> Self {
        let suffix = suffix.into().to_ascii_lowercase();
        // Remove leading dot if present (we'll add it during matching)
        let suffix = suffix.trim_start_matches('.').to_string();
        self.suffix.push((suffix, outbound.into()));
        self
    }

    /// Add a keyword match rule
    ///
    /// Matches any domain containing the keyword as a substring.
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::rules::domain::DomainMatcherBuilder;
    ///
    /// let matcher = DomainMatcherBuilder::new()
    ///     .add_keyword("google", "proxy")
    ///     .build()
    ///     .unwrap();
    ///
    /// assert!(matcher.match_domain("google.com").is_some());
    /// assert!(matcher.match_domain("www.google.com").is_some());
    /// assert!(matcher.match_domain("googleapis.com").is_some());
    /// ```
    #[must_use]
    pub fn add_keyword(mut self, keyword: impl Into<String>, outbound: impl Into<String>) -> Self {
        let keyword = keyword.into().to_ascii_lowercase();
        self.keyword.push((keyword, outbound.into()));
        self
    }

    /// Add a regex pattern match rule
    ///
    /// Matches domains that match the regular expression pattern.
    /// Regex matching is slower than other match types, so use sparingly.
    ///
    /// # Errors
    ///
    /// Returns `RuleError::InvalidRegex` if the pattern is invalid.
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::rules::domain::DomainMatcherBuilder;
    ///
    /// let matcher = DomainMatcherBuilder::new()
    ///     .add_regex(r".*\.google\.(com|co\.uk)$", "proxy")
    ///     .unwrap()
    ///     .build()
    ///     .unwrap();
    ///
    /// assert!(matcher.match_domain("www.google.com").is_some());
    /// assert!(matcher.match_domain("mail.google.co.uk").is_some());
    /// assert!(matcher.match_domain("google.de").is_none());
    /// ```
    pub fn add_regex(
        mut self,
        pattern: impl Into<String>,
        outbound: impl Into<String>,
    ) -> Result<Self, RuleError> {
        let pattern_str = pattern.into();

        // Validate the regex pattern
        Regex::new(&pattern_str).map_err(|_| RuleError::InvalidRegex(pattern_str.clone()))?;

        self.regex.push((pattern_str, outbound.into()));
        Ok(self)
    }

    /// Build the `DomainMatcher` from collected rules
    ///
    /// Compiles all rules into optimized data structures for fast matching.
    ///
    /// # Errors
    ///
    /// Returns `RuleError::CompilationError` if compilation fails.
    ///
    /// # Panics
    ///
    /// This method will not panic under normal use. It may panic if a regex
    /// pattern that was previously validated becomes invalid (which should
    /// never happen in practice).
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::rules::domain::DomainMatcherBuilder;
    ///
    /// let matcher = DomainMatcherBuilder::new()
    ///     .add_exact("example.com", "direct")
    ///     .build()
    ///     .unwrap();
    /// ```
    pub fn build(self) -> Result<DomainMatcher, RuleError> {
        let rule_count = self.exact.len()
            + self.suffix.len()
            + self.keyword.len()
            + self.regex.len();

        // Build exact domain map
        let exact_domains: HashMap<String, String> = self.exact.into_iter().collect();

        // Build suffix automaton with reversed patterns
        let (suffix_automaton, suffix_outbounds, suffix_patterns) = if self.suffix.is_empty() {
            (None, Vec::new(), Vec::new())
        } else {
            let mut patterns = Vec::with_capacity(self.suffix.len());
            let mut outbounds = Vec::with_capacity(self.suffix.len());
            let mut reversed_patterns = Vec::with_capacity(self.suffix.len());

            for (suffix, outbound) in self.suffix {
                // Reverse the suffix and add leading dot
                // "google.com" -> ".moc.elgoog"
                let reversed: String =
                    format!(".{}", suffix.chars().rev().collect::<String>());
                reversed_patterns.push(reversed.clone());
                patterns.push(reversed);
                outbounds.push(outbound);
            }

            let automaton = AhoCorasick::builder()
                .ascii_case_insensitive(true)
                .build(&patterns)
                .map_err(|e| RuleError::CompilationError(format!("suffix automaton: {e}")))?;

            (Some(automaton), outbounds, reversed_patterns)
        };

        // Build keyword automaton
        let (keyword_automaton, keyword_outbounds) = if self.keyword.is_empty() {
            (None, Vec::new())
        } else {
            let mut patterns = Vec::with_capacity(self.keyword.len());
            let mut outbounds = Vec::with_capacity(self.keyword.len());

            for (keyword, outbound) in self.keyword {
                patterns.push(keyword);
                outbounds.push(outbound);
            }

            let automaton = AhoCorasick::builder()
                .ascii_case_insensitive(true)
                .build(&patterns)
                .map_err(|e| RuleError::CompilationError(format!("keyword automaton: {e}")))?;

            (Some(automaton), outbounds)
        };

        // Compile regex patterns
        let regex_patterns: Vec<(Regex, String)> = self
            .regex
            .into_iter()
            .map(|(pattern, outbound)| {
                // We already validated in add_regex, so unwrap is safe
                let regex = Regex::new(&pattern).expect("regex was already validated");
                (regex, outbound)
            })
            .collect();

        Ok(DomainMatcher {
            exact_domains,
            suffix_automaton,
            suffix_outbounds,
            suffix_patterns,
            keyword_automaton,
            keyword_outbounds,
            regex_patterns,
            rule_count,
        })
    }

    /// Check if the builder has any rules
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.exact.is_empty()
            && self.suffix.is_empty()
            && self.keyword.is_empty()
            && self.regex.is_empty()
    }

    /// Get the total number of rules added
    #[must_use]
    pub fn rule_count(&self) -> usize {
        self.exact.len() + self.suffix.len() + self.keyword.len() + self.regex.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== Exact Match Tests ====================

    #[test]
    fn test_exact_match_basic() {
        let matcher = DomainMatcher::builder()
            .add_exact("example.com", "direct")
            .build()
            .unwrap();

        assert_eq!(matcher.match_domain("example.com"), Some("direct"));
    }

    #[test]
    fn test_exact_match_case_insensitive() {
        let matcher = DomainMatcher::builder()
            .add_exact("Example.COM", "direct")
            .build()
            .unwrap();

        assert_eq!(matcher.match_domain("example.com"), Some("direct"));
        assert_eq!(matcher.match_domain("EXAMPLE.COM"), Some("direct"));
        assert_eq!(matcher.match_domain("ExAmPlE.cOm"), Some("direct"));
    }

    #[test]
    fn test_exact_match_no_subdomain() {
        let matcher = DomainMatcher::builder()
            .add_exact("example.com", "direct")
            .build()
            .unwrap();

        assert_eq!(matcher.match_domain("www.example.com"), None);
        assert_eq!(matcher.match_domain("mail.example.com"), None);
    }

    #[test]
    fn test_exact_match_multiple_domains() {
        let matcher = DomainMatcher::builder()
            .add_exact("a.com", "outbound-a")
            .add_exact("b.com", "outbound-b")
            .add_exact("c.com", "outbound-c")
            .build()
            .unwrap();

        assert_eq!(matcher.match_domain("a.com"), Some("outbound-a"));
        assert_eq!(matcher.match_domain("b.com"), Some("outbound-b"));
        assert_eq!(matcher.match_domain("c.com"), Some("outbound-c"));
        assert_eq!(matcher.match_domain("d.com"), None);
    }

    #[test]
    fn test_exact_match_duplicate_overwrites() {
        let matcher = DomainMatcher::builder()
            .add_exact("example.com", "first")
            .add_exact("example.com", "second")
            .build()
            .unwrap();

        // Last one wins (HashMap behavior)
        assert_eq!(matcher.match_domain("example.com"), Some("second"));
    }

    // ==================== Suffix Match Tests ====================

    #[test]
    fn test_suffix_match_basic() {
        let matcher = DomainMatcher::builder()
            .add_suffix("google.com", "proxy")
            .build()
            .unwrap();

        assert_eq!(matcher.match_domain("google.com"), Some("proxy"));
        assert_eq!(matcher.match_domain("www.google.com"), Some("proxy"));
        assert_eq!(matcher.match_domain("mail.google.com"), Some("proxy"));
    }

    #[test]
    fn test_suffix_match_with_leading_dot() {
        // Leading dot should be handled correctly
        let matcher = DomainMatcher::builder()
            .add_suffix(".google.com", "proxy")
            .build()
            .unwrap();

        assert_eq!(matcher.match_domain("google.com"), Some("proxy"));
        assert_eq!(matcher.match_domain("www.google.com"), Some("proxy"));
    }

    #[test]
    fn test_suffix_match_boundary() {
        let matcher = DomainMatcher::builder()
            .add_suffix("google.com", "proxy")
            .build()
            .unwrap();

        // Should NOT match - not a domain boundary
        assert_eq!(matcher.match_domain("notgoogle.com"), None);
        assert_eq!(matcher.match_domain("fakegoogle.com"), None);
    }

    #[test]
    fn test_suffix_match_deep_subdomain() {
        let matcher = DomainMatcher::builder()
            .add_suffix("google.com", "proxy")
            .build()
            .unwrap();

        assert_eq!(
            matcher.match_domain("very.deep.subdomain.google.com"),
            Some("proxy")
        );
    }

    #[test]
    fn test_suffix_match_case_insensitive() {
        let matcher = DomainMatcher::builder()
            .add_suffix("Google.COM", "proxy")
            .build()
            .unwrap();

        assert_eq!(matcher.match_domain("www.google.com"), Some("proxy"));
        assert_eq!(matcher.match_domain("WWW.GOOGLE.COM"), Some("proxy"));
    }

    #[test]
    fn test_suffix_match_multiple() {
        let matcher = DomainMatcher::builder()
            .add_suffix("google.com", "google-proxy")
            .add_suffix("facebook.com", "fb-proxy")
            .add_suffix("twitter.com", "tw-proxy")
            .build()
            .unwrap();

        assert_eq!(
            matcher.match_domain("www.google.com"),
            Some("google-proxy")
        );
        assert_eq!(matcher.match_domain("m.facebook.com"), Some("fb-proxy"));
        assert_eq!(matcher.match_domain("api.twitter.com"), Some("tw-proxy"));
        assert_eq!(matcher.match_domain("example.com"), None);
    }

    // ==================== Keyword Match Tests ====================

    #[test]
    fn test_keyword_match_basic() {
        let matcher = DomainMatcher::builder()
            .add_keyword("google", "proxy")
            .build()
            .unwrap();

        assert_eq!(matcher.match_domain("google.com"), Some("proxy"));
        assert_eq!(matcher.match_domain("www.google.com"), Some("proxy"));
        assert_eq!(matcher.match_domain("googleapis.com"), Some("proxy"));
    }

    #[test]
    fn test_keyword_match_anywhere() {
        let matcher = DomainMatcher::builder()
            .add_keyword("ads", "block")
            .build()
            .unwrap();

        assert_eq!(matcher.match_domain("ads.example.com"), Some("block"));
        assert_eq!(matcher.match_domain("example-ads.com"), Some("block"));
        assert_eq!(matcher.match_domain("example.com/ads"), Some("block"));
    }

    #[test]
    fn test_keyword_match_case_insensitive() {
        let matcher = DomainMatcher::builder()
            .add_keyword("Google", "proxy")
            .build()
            .unwrap();

        assert_eq!(matcher.match_domain("google.com"), Some("proxy"));
        assert_eq!(matcher.match_domain("GOOGLE.COM"), Some("proxy"));
    }

    #[test]
    fn test_keyword_match_no_match() {
        let matcher = DomainMatcher::builder()
            .add_keyword("facebook", "proxy")
            .build()
            .unwrap();

        assert_eq!(matcher.match_domain("google.com"), None);
        assert_eq!(matcher.match_domain("twitter.com"), None);
    }

    #[test]
    fn test_keyword_match_multiple() {
        let matcher = DomainMatcher::builder()
            .add_keyword("google", "google-proxy")
            .add_keyword("facebook", "fb-proxy")
            .build()
            .unwrap();

        assert_eq!(
            matcher.match_domain("www.google.com"),
            Some("google-proxy")
        );
        assert_eq!(matcher.match_domain("m.facebook.com"), Some("fb-proxy"));
    }

    // ==================== Regex Match Tests ====================

    #[test]
    fn test_regex_match_basic() {
        let matcher = DomainMatcher::builder()
            .add_regex(r".*\.google\.com$", "proxy")
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(matcher.match_domain("www.google.com"), Some("proxy"));
        assert_eq!(matcher.match_domain("mail.google.com"), Some("proxy"));
    }

    #[test]
    fn test_regex_match_complex() {
        let matcher = DomainMatcher::builder()
            .add_regex(r".*\.(cn|ru|ir)$", "geo-proxy")
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(matcher.match_domain("example.cn"), Some("geo-proxy"));
        assert_eq!(matcher.match_domain("test.ru"), Some("geo-proxy"));
        assert_eq!(matcher.match_domain("site.ir"), Some("geo-proxy"));
        assert_eq!(matcher.match_domain("example.com"), None);
    }

    #[test]
    fn test_regex_match_invalid_pattern() {
        let result = DomainMatcher::builder().add_regex(r"[invalid", "proxy");

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), RuleError::InvalidRegex(_)));
    }

    #[test]
    fn test_regex_match_with_anchors() {
        let matcher = DomainMatcher::builder()
            .add_regex(r"^www\.example\.com$", "proxy")
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(matcher.match_domain("www.example.com"), Some("proxy"));
        assert_eq!(matcher.match_domain("mail.example.com"), None);
        assert_eq!(matcher.match_domain("www.example.com.cn"), None);
    }

    // ==================== Priority/Precedence Tests ====================

    #[test]
    fn test_priority_exact_over_suffix() {
        let matcher = DomainMatcher::builder()
            .add_suffix("example.com", "suffix-outbound")
            .add_exact("example.com", "exact-outbound")
            .build()
            .unwrap();

        // Exact should win
        assert_eq!(
            matcher.match_domain("example.com"),
            Some("exact-outbound")
        );
        // But subdomain should use suffix
        assert_eq!(
            matcher.match_domain("www.example.com"),
            Some("suffix-outbound")
        );
    }

    #[test]
    fn test_priority_suffix_over_keyword() {
        let matcher = DomainMatcher::builder()
            .add_keyword("example", "keyword-outbound")
            .add_suffix("example.com", "suffix-outbound")
            .build()
            .unwrap();

        // Suffix should win for exact suffix match
        assert_eq!(
            matcher.match_domain("example.com"),
            Some("suffix-outbound")
        );
        assert_eq!(
            matcher.match_domain("www.example.com"),
            Some("suffix-outbound")
        );
        // But keyword should match other domains
        assert_eq!(
            matcher.match_domain("example.org"),
            Some("keyword-outbound")
        );
    }

    #[test]
    fn test_priority_keyword_over_regex() {
        let matcher = DomainMatcher::builder()
            .add_regex(r".*google.*", "regex-outbound")
            .unwrap()
            .add_keyword("google", "keyword-outbound")
            .build()
            .unwrap();

        // Keyword should win
        assert_eq!(
            matcher.match_domain("www.google.com"),
            Some("keyword-outbound")
        );
    }

    #[test]
    fn test_priority_full_chain() {
        let matcher = DomainMatcher::builder()
            .add_exact("exact.example.com", "exact")
            .add_suffix("example.com", "suffix")
            .add_keyword("example", "keyword")
            .add_regex(r".*", "regex")
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(matcher.match_domain("exact.example.com"), Some("exact"));
        assert_eq!(matcher.match_domain("www.example.com"), Some("suffix"));
        assert_eq!(matcher.match_domain("example.org"), Some("keyword"));
        assert_eq!(matcher.match_domain("other.com"), Some("regex"));
    }

    // ==================== Edge Cases ====================

    #[test]
    fn test_empty_domain() {
        let matcher = DomainMatcher::builder()
            .add_exact("example.com", "direct")
            .build()
            .unwrap();

        assert_eq!(matcher.match_domain(""), None);
    }

    #[test]
    fn test_empty_matcher() {
        let matcher = DomainMatcher::empty();

        assert!(matcher.is_empty());
        assert_eq!(matcher.rule_count(), 0);
        assert_eq!(matcher.match_domain("example.com"), None);
    }

    #[test]
    fn test_very_long_domain() {
        let matcher = DomainMatcher::builder()
            .add_suffix("example.com", "proxy")
            .build()
            .unwrap();

        let long_domain = format!(
            "{}.{}.{}.{}.example.com",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(63)
        );

        assert_eq!(matcher.match_domain(&long_domain), Some("proxy"));
    }

    #[test]
    fn test_special_characters_in_domain() {
        let matcher = DomainMatcher::builder()
            .add_exact("example-test.com", "direct")
            .add_suffix("test-domain.com", "proxy")
            .build()
            .unwrap();

        assert_eq!(matcher.match_domain("example-test.com"), Some("direct"));
        assert_eq!(
            matcher.match_domain("www.test-domain.com"),
            Some("proxy")
        );
    }

    #[test]
    fn test_numeric_domain() {
        let matcher = DomainMatcher::builder()
            .add_exact("123.456.789", "direct")
            .add_suffix("100.com", "proxy")
            .build()
            .unwrap();

        assert_eq!(matcher.match_domain("123.456.789"), Some("direct"));
        assert_eq!(matcher.match_domain("www.100.com"), Some("proxy"));
    }

    #[test]
    fn test_unicode_domain() {
        // Note: This tests ASCII conversion behavior
        let matcher = DomainMatcher::builder()
            .add_keyword("test", "proxy")
            .build()
            .unwrap();

        // ASCII domain should work
        assert_eq!(matcher.match_domain("test.com"), Some("proxy"));
    }

    // ==================== Builder Tests ====================

    #[test]
    fn test_builder_is_empty() {
        let builder = DomainMatcherBuilder::new();
        assert!(builder.is_empty());
        assert_eq!(builder.rule_count(), 0);
    }

    #[test]
    fn test_builder_rule_count() {
        let builder = DomainMatcherBuilder::new()
            .add_exact("a.com", "direct")
            .add_suffix("b.com", "proxy")
            .add_keyword("test", "block");

        assert!(!builder.is_empty());
        assert_eq!(builder.rule_count(), 3);
    }

    #[test]
    fn test_builder_regex_validation() {
        // Valid regex
        let result = DomainMatcherBuilder::new().add_regex(r".*\.com$", "proxy");
        assert!(result.is_ok());

        // Invalid regex
        let result = DomainMatcherBuilder::new().add_regex(r"[unclosed", "proxy");
        assert!(result.is_err());
    }

    // ==================== Count Tests ====================

    #[test]
    fn test_matcher_counts() {
        let matcher = DomainMatcher::builder()
            .add_exact("a.com", "direct")
            .add_exact("b.com", "direct")
            .add_suffix("c.com", "proxy")
            .add_suffix("d.com", "proxy")
            .add_suffix("e.com", "proxy")
            .add_keyword("test", "block")
            .add_regex(r".*", "fallback")
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(matcher.exact_count(), 2);
        assert_eq!(matcher.suffix_count(), 3);
        assert_eq!(matcher.keyword_count(), 1);
        assert_eq!(matcher.regex_count(), 1);
        assert_eq!(matcher.rule_count(), 7);
    }

    // ==================== Performance Sanity Check ====================

    #[test]
    fn test_performance_many_suffix_rules() {
        // Build a matcher with many suffix rules (similar to domain-catalog.json)
        let mut builder = DomainMatcher::builder();

        // Add 1000 suffix rules
        for i in 0..1000 {
            builder = builder.add_suffix(format!("domain{i}.com"), "proxy");
        }

        let matcher = builder.build().unwrap();
        assert_eq!(matcher.suffix_count(), 1000);

        // Perform 10000 lookups
        let start = std::time::Instant::now();
        for i in 0..10000 {
            let domain = format!("www.domain{}.com", i % 1000);
            let _ = matcher.match_domain(&domain);
        }
        let elapsed = start.elapsed();

        // Should complete in reasonable time (< 1 second for 10K lookups)
        assert!(
            elapsed.as_secs() < 1,
            "10K lookups took too long: {:?}",
            elapsed
        );
    }

    #[test]
    fn test_performance_mixed_rules() {
        let matcher = DomainMatcher::builder()
            .add_exact("exact1.com", "direct")
            .add_exact("exact2.com", "direct")
            .add_suffix("google.com", "proxy")
            .add_suffix("facebook.com", "proxy")
            .add_suffix("twitter.com", "proxy")
            .add_keyword("ads", "block")
            .add_keyword("tracking", "block")
            .add_regex(r".*\.cn$", "geo")
            .unwrap()
            .build()
            .unwrap();

        // Warmup and verify correctness
        assert_eq!(matcher.match_domain("exact1.com"), Some("direct"));
        assert_eq!(matcher.match_domain("www.google.com"), Some("proxy"));
        assert_eq!(matcher.match_domain("ads-server.com"), Some("block"));
        assert_eq!(matcher.match_domain("example.cn"), Some("geo"));

        // Benchmark
        let start = std::time::Instant::now();
        for _ in 0..10000 {
            let _ = matcher.match_domain("www.google.com");
            let _ = matcher.match_domain("exact1.com");
            let _ = matcher.match_domain("ads-tracker.com");
            let _ = matcher.match_domain("example.cn");
            let _ = matcher.match_domain("unknown.org");
        }
        let elapsed = start.elapsed();

        // 50K lookups should complete quickly
        assert!(
            elapsed.as_millis() < 1000,
            "50K lookups took too long: {:?}",
            elapsed
        );
    }

    // ==================== Debug Trait Test ====================

    #[test]
    fn test_debug_impl() {
        let matcher = DomainMatcher::builder()
            .add_exact("example.com", "direct")
            .build()
            .unwrap();

        let debug_str = format!("{:?}", matcher);
        assert!(debug_str.contains("DomainMatcher"));
    }

    #[test]
    fn test_builder_debug_impl() {
        let builder = DomainMatcherBuilder::new().add_exact("example.com", "direct");

        let debug_str = format!("{:?}", builder);
        assert!(debug_str.contains("DomainMatcherBuilder"));
    }
}
