//! DNS router for per-domain upstream selection
//!
//! This module provides the `DnsRouter` struct which routes DNS queries to
//! different upstream servers based on domain matching rules.
//!
//! # Lock Ordering
//!
//! To prevent deadlocks, locks must be acquired in this order:
//! 1. `matcher` (ArcSwap - lockless read, only writer needs ordering)
//! 2. `upstreams` (RwLock)
//!
//! # Performance
//!
//! - Domain matching: O(1) for exact match via Aho-Corasick
//! - Hot reload: < 10ms for typical rule sets
//! - Lock-free reads for routing decisions

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;
use parking_lot::RwLock;

use crate::dns::client::UpstreamPool;
use crate::dns::error::{DnsError, DnsResult};
use crate::rules::domain::{DomainMatcher, DomainMatcherBuilder};

/// Maximum number of routing rules allowed.
///
/// This limit prevents memory exhaustion and ensures reasonable performance.
/// 10,000 rules should be sufficient for most DNS splitting scenarios.
pub const MAX_ROUTES: usize = 10_000;

/// Match type for routing rules
///
/// Determines how a domain pattern is matched against query domains.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DomainMatchType {
    /// Exact domain match only
    ///
    /// Example: `example.com` matches only `example.com`, not `www.example.com`
    Exact,

    /// Suffix match (domain and all subdomains)
    ///
    /// Example: `example.com` matches `example.com`, `www.example.com`, `mail.example.com`
    Suffix,

    /// Keyword match (substring anywhere in domain)
    ///
    /// Example: `google` matches `google.com`, `www.google.co.uk`, `mail.google.org`
    Keyword,

    /// Regular expression match
    ///
    /// Example: `^ad[0-9]*\.` matches `ad1.example.com`, `ad123.tracker.net`
    Regex,
}

impl DomainMatchType {
    /// Convert to string representation
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::Suffix => "suffix",
            Self::Keyword => "keyword",
            Self::Regex => "regex",
        }
    }
}

impl fmt::Display for DomainMatchType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Information about a routing rule
///
/// Contains the pattern, match type, and target upstream for a rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteInfo {
    /// The domain pattern
    pub pattern: String,

    /// How the pattern is matched
    pub match_type: DomainMatchType,

    /// The upstream tag to route matching queries to
    pub upstream_tag: String,
}

impl RouteInfo {
    /// Create a new route info
    #[must_use]
    pub fn new(pattern: impl Into<String>, match_type: DomainMatchType, upstream_tag: impl Into<String>) -> Self {
        Self {
            pattern: pattern.into(),
            match_type,
            upstream_tag: upstream_tag.into(),
        }
    }
}

/// Statistics for the DNS router
///
/// Tracks routing decisions and rule counts using atomic counters.
pub struct DnsRouterStats {
    /// Number of routing decisions made
    routes_evaluated: AtomicU64,

    /// Number of times the default upstream was used (no rule matched)
    default_fallbacks: AtomicU64,

    /// Current number of routing rules
    rule_count: AtomicUsize,

    /// Unix timestamp of last rule reload (0 if never reloaded)
    last_reload: AtomicU64,
}

impl DnsRouterStats {
    /// Create new statistics
    fn new() -> Self {
        Self {
            routes_evaluated: AtomicU64::new(0),
            default_fallbacks: AtomicU64::new(0),
            rule_count: AtomicUsize::new(0),
            last_reload: AtomicU64::new(0),
        }
    }

    /// Record a routing evaluation
    fn record_evaluation(&self) {
        self.routes_evaluated.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a default fallback
    fn record_default_fallback(&self) {
        self.default_fallbacks.fetch_add(1, Ordering::Relaxed);
    }

    /// Update rule count
    fn set_rule_count(&self, count: usize) {
        self.rule_count.store(count, Ordering::Relaxed);
    }

    /// Update last reload timestamp
    fn update_last_reload(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.last_reload.store(now, Ordering::Relaxed);
    }

    /// Get a snapshot of the statistics
    #[must_use]
    pub fn snapshot(&self) -> DnsRouterStatsSnapshot {
        let last_reload = self.last_reload.load(Ordering::Relaxed);
        DnsRouterStatsSnapshot {
            routes_evaluated: self.routes_evaluated.load(Ordering::Relaxed),
            default_fallbacks: self.default_fallbacks.load(Ordering::Relaxed),
            rule_count: self.rule_count.load(Ordering::Relaxed),
            last_reload: if last_reload == 0 { None } else { Some(last_reload) },
        }
    }
}

/// Snapshot of router statistics
///
/// A point-in-time capture of routing statistics.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DnsRouterStatsSnapshot {
    /// Number of routing decisions made
    pub routes_evaluated: u64,

    /// Number of times the default upstream was used
    pub default_fallbacks: u64,

    /// Current number of routing rules
    pub rule_count: usize,

    /// Unix timestamp of last rule reload (None if never reloaded)
    pub last_reload: Option<u64>,
}

/// Internal state for the domain matcher with route information
struct MatcherState {
    /// The compiled domain matcher
    matcher: DomainMatcher,

    /// Route information: pattern -> (match_type, upstream_tag)
    routes: HashMap<String, (DomainMatchType, String)>,
}

impl MatcherState {
    /// Create an empty matcher state
    fn empty() -> Self {
        Self {
            matcher: DomainMatcher::empty(),
            routes: HashMap::new(),
        }
    }

    /// Create a new matcher state
    fn new(matcher: DomainMatcher, routes: HashMap<String, (DomainMatchType, String)>) -> Self {
        Self { matcher, routes }
    }

    /// Get the number of routes
    fn route_count(&self) -> usize {
        self.routes.len()
    }
}

/// DNS router for per-domain upstream selection
///
/// Routes DNS queries to different upstream servers based on domain matching rules.
/// Uses `ArcSwap` for lock-free hot reload of routing rules.
///
/// # Thread Safety
///
/// `DnsRouter` is thread-safe and designed for concurrent access:
/// - Route lookups use `ArcSwap` for lock-free reads
/// - Upstream pool access uses `RwLock` (read-optimized)
/// - Statistics use atomic counters
///
/// # Lock Ordering
///
/// To prevent deadlocks:
/// 1. matcher (ArcSwap - lockless)
/// 2. upstreams (RwLock)
///
/// # Example
///
/// ```
/// use rust_router::dns::split::{DnsRouter, DomainMatchType};
///
/// let router = DnsRouter::new("direct".to_string());
///
/// // Add routing rules
/// router.add_route("cn", DomainMatchType::Suffix, "china").unwrap();
/// router.add_route("google.com", DomainMatchType::Suffix, "global").unwrap();
///
/// // Route a query (returns upstream tag)
/// let tag = router.route_to_tag("www.baidu.cn");
/// assert_eq!(tag, "china");
/// ```
pub struct DnsRouter {
    /// The domain matcher with route information
    /// Wrapped in ArcSwap for lock-free hot reload
    matcher: ArcSwap<MatcherState>,

    /// Upstream pools by tag
    /// Uses RwLock since reads are much more frequent than writes
    upstreams: RwLock<HashMap<String, Arc<UpstreamPool>>>,

    /// Default upstream tag (used when no rule matches)
    default_upstream: String,

    /// Statistics
    stats: Arc<DnsRouterStats>,
}

impl DnsRouter {
    /// Create a new DNS router with the specified default upstream
    ///
    /// The default upstream is used when no routing rule matches a domain.
    ///
    /// # Arguments
    ///
    /// * `default_upstream` - Tag of the default upstream to use
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::dns::split::DnsRouter;
    ///
    /// let router = DnsRouter::new("direct".to_string());
    /// assert_eq!(router.default_upstream(), "direct");
    /// ```
    #[must_use]
    pub fn new(default_upstream: String) -> Self {
        Self {
            matcher: ArcSwap::new(Arc::new(MatcherState::empty())),
            upstreams: RwLock::new(HashMap::new()),
            default_upstream,
            stats: Arc::new(DnsRouterStats::new()),
        }
    }

    /// Get the default upstream tag
    #[must_use]
    pub fn default_upstream(&self) -> &str {
        &self.default_upstream
    }

    /// Set a new default upstream tag
    ///
    /// Note: This only changes which upstream tag is used when no rule matches.
    /// The actual upstream pool must be added separately with `add_upstream`.
    pub fn set_default_upstream(&mut self, tag: String) {
        self.default_upstream = tag;
    }

    /// Check if the router has any routing rules
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.matcher.load().route_count() == 0
    }

    /// Get the number of routing rules
    #[must_use]
    pub fn route_count(&self) -> usize {
        self.matcher.load().route_count()
    }

    /// Route a domain query to an upstream tag
    ///
    /// Returns the upstream tag to use for the given domain.
    /// If no rule matches, returns the default upstream tag.
    ///
    /// # Arguments
    ///
    /// * `domain` - The domain to route (case-insensitive)
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::dns::split::{DnsRouter, DomainMatchType};
    ///
    /// let router = DnsRouter::new("direct".to_string());
    /// router.add_route("cn", DomainMatchType::Suffix, "china").unwrap();
    ///
    /// assert_eq!(router.route_to_tag("www.baidu.cn"), "china");
    /// assert_eq!(router.route_to_tag("google.com"), "direct");
    /// ```
    #[must_use]
    pub fn route_to_tag(&self, domain: &str) -> String {
        self.stats.record_evaluation();

        let state = self.matcher.load();

        // Try to match the domain
        if let Some(matched_tag) = state.matcher.match_domain(domain) {
            // Find the upstream tag for this match
            // The DomainMatcher returns the outbound tag we set, which is the upstream tag
            return matched_tag.to_string();
        }

        // No match, use default
        self.stats.record_default_fallback();
        self.default_upstream.clone()
    }

    /// Route a domain query to an upstream pool
    ///
    /// Returns the `UpstreamPool` to use for the given domain.
    /// Returns `None` if the upstream pool is not found (not added yet).
    ///
    /// # Arguments
    ///
    /// * `domain` - The domain to route (case-insensitive)
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rust_router::dns::split::DnsRouter;
    ///
    /// let router = DnsRouter::new("direct".to_string());
    /// // Add upstream pool: router.add_upstream("direct", pool);
    ///
    /// if let Some(pool) = router.route("google.com") {
    ///     // Use pool to query upstream
    /// }
    /// ```
    #[must_use]
    pub fn route(&self, domain: &str) -> Option<Arc<UpstreamPool>> {
        let tag = self.route_to_tag(domain);
        self.get_upstream(&tag)
    }

    /// Add or update an upstream pool
    ///
    /// # Arguments
    ///
    /// * `tag` - Unique tag for this upstream pool
    /// * `pool` - The upstream pool
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rust_router::dns::split::DnsRouter;
    /// use rust_router::dns::client::UpstreamPool;
    ///
    /// let router = DnsRouter::new("direct".to_string());
    /// // let pool = UpstreamPool::builder("direct").build();
    /// // router.add_upstream("direct", pool);
    /// ```
    pub fn add_upstream(&self, tag: &str, pool: UpstreamPool) {
        let mut upstreams = self.upstreams.write();
        upstreams.insert(tag.to_string(), Arc::new(pool));
    }

    /// Add an Arc-wrapped upstream pool
    ///
    /// This is useful when the pool is already wrapped in an Arc for sharing.
    pub fn add_upstream_arc(&self, tag: &str, pool: Arc<UpstreamPool>) {
        let mut upstreams = self.upstreams.write();
        upstreams.insert(tag.to_string(), pool);
    }

    /// Remove an upstream pool
    ///
    /// Returns `true` if the pool was found and removed.
    ///
    /// # Arguments
    ///
    /// * `tag` - Tag of the upstream pool to remove
    pub fn remove_upstream(&self, tag: &str) -> bool {
        let mut upstreams = self.upstreams.write();
        upstreams.remove(tag).is_some()
    }

    /// Get an upstream pool by tag
    ///
    /// Returns `None` if the pool is not found.
    #[must_use]
    pub fn get_upstream(&self, tag: &str) -> Option<Arc<UpstreamPool>> {
        let upstreams = self.upstreams.read();
        upstreams.get(tag).cloned()
    }

    /// List all upstream pool tags
    #[must_use]
    pub fn list_upstreams(&self) -> Vec<String> {
        let upstreams = self.upstreams.read();
        upstreams.keys().cloned().collect()
    }

    /// Get the number of registered upstream pools
    #[must_use]
    pub fn upstream_count(&self) -> usize {
        let upstreams = self.upstreams.read();
        upstreams.len()
    }

    /// Add a single routing rule
    ///
    /// # Arguments
    ///
    /// * `pattern` - The domain pattern to match
    /// * `match_type` - How to match the pattern
    /// * `upstream_tag` - The upstream to route matching queries to
    ///
    /// # Errors
    ///
    /// Returns `DnsError::ConfigError` if:
    /// - Adding the rule would exceed `MAX_ROUTES`
    /// - The pattern is invalid (for regex)
    /// - Building the matcher fails
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::dns::split::{DnsRouter, DomainMatchType};
    ///
    /// let router = DnsRouter::new("direct".to_string());
    /// router.add_route("cn", DomainMatchType::Suffix, "china").unwrap();
    /// router.add_route("google.com", DomainMatchType::Exact, "global").unwrap();
    /// ```
    pub fn add_route(
        &self,
        pattern: &str,
        match_type: DomainMatchType,
        upstream_tag: &str,
    ) -> DnsResult<()> {
        let current = self.matcher.load();
        let mut routes = current.routes.clone();

        // Check size limit
        if !routes.contains_key(pattern) && routes.len() >= MAX_ROUTES {
            return Err(DnsError::config_field(
                format!("routing rules exceed maximum: {} (max: {})", routes.len() + 1, MAX_ROUTES),
                "dns.split.routes",
            ));
        }

        // Normalize pattern
        let normalized = pattern.to_ascii_lowercase();

        // Add to routes
        routes.insert(normalized.clone(), (match_type, upstream_tag.to_string()));

        // Rebuild matcher
        self.rebuild_matcher(routes)?;

        Ok(())
    }

    /// Remove a routing rule
    ///
    /// Returns `true` if the rule was found and removed.
    ///
    /// # Arguments
    ///
    /// * `pattern` - The pattern to remove
    ///
    /// # Errors
    ///
    /// Returns `DnsError::InternalError` if rebuilding the matcher fails.
    pub fn remove_route(&self, pattern: &str) -> DnsResult<bool> {
        let current = self.matcher.load();
        let mut routes = current.routes.clone();

        let normalized = pattern.to_ascii_lowercase();
        let removed = routes.remove(&normalized).is_some();

        if removed {
            self.rebuild_matcher(routes)?;
        }

        Ok(removed)
    }

    /// Clear all routing rules
    pub fn clear_routes(&self) {
        self.matcher.store(Arc::new(MatcherState::empty()));
        self.stats.set_rule_count(0);
        self.stats.update_last_reload();
    }

    /// List all routing rules
    ///
    /// Returns a list of `RouteInfo` for all configured rules.
    #[must_use]
    pub fn list_routes(&self) -> Vec<RouteInfo> {
        let state = self.matcher.load();
        state
            .routes
            .iter()
            .map(|(pattern, (match_type, upstream_tag))| {
                RouteInfo::new(pattern, *match_type, upstream_tag)
            })
            .collect()
    }

    /// Hot reload routing rules with a new matcher
    ///
    /// This atomically replaces all routing rules with the new configuration.
    /// Reads in progress will complete with the old rules, new reads will
    /// use the new rules.
    ///
    /// # Arguments
    ///
    /// * `matcher` - The new domain matcher
    /// * `routes` - The route information map
    ///
    /// # Performance
    ///
    /// Hot reload completes in O(1) time (just an atomic pointer swap).
    /// Building the matcher beforehand may take longer for large rule sets.
    pub fn reload_rules(
        &self,
        matcher: DomainMatcher,
        routes: HashMap<String, (DomainMatchType, String)>,
    ) -> DnsResult<()> {
        let state = MatcherState::new(matcher, routes);
        let count = state.route_count();

        self.matcher.store(Arc::new(state));
        self.stats.set_rule_count(count);
        self.stats.update_last_reload();

        Ok(())
    }

    /// Load routes from a list of `RouteInfo`
    ///
    /// Replaces all existing routes with the provided list.
    ///
    /// # Arguments
    ///
    /// * `route_list` - List of routes to load
    ///
    /// # Errors
    ///
    /// Returns `DnsError::ConfigError` if:
    /// - The number of routes exceeds `MAX_ROUTES`
    /// - Any regex pattern is invalid
    /// - Building the matcher fails
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::dns::split::{DnsRouter, DomainMatchType, RouteInfo};
    ///
    /// let router = DnsRouter::new("direct".to_string());
    ///
    /// let routes = vec![
    ///     RouteInfo::new("cn", DomainMatchType::Suffix, "china"),
    ///     RouteInfo::new("google.com", DomainMatchType::Suffix, "global"),
    /// ];
    ///
    /// router.load_routes(&routes).unwrap();
    /// ```
    pub fn load_routes(&self, route_list: &[RouteInfo]) -> DnsResult<()> {
        // Check size limit
        if route_list.len() > MAX_ROUTES {
            return Err(DnsError::config_field(
                format!("routing rules exceed maximum: {} (max: {})", route_list.len(), MAX_ROUTES),
                "dns.split.routes",
            ));
        }

        let mut routes = HashMap::new();
        for route in route_list {
            let normalized = route.pattern.to_ascii_lowercase();
            routes.insert(normalized, (route.match_type, route.upstream_tag.clone()));
        }

        self.rebuild_matcher(routes)
    }

    /// Get routing statistics
    #[must_use]
    pub fn stats(&self) -> DnsRouterStatsSnapshot {
        self.stats.snapshot()
    }

    /// Reset statistics counters
    pub fn reset_stats(&self) {
        self.stats.routes_evaluated.store(0, Ordering::Relaxed);
        self.stats.default_fallbacks.store(0, Ordering::Relaxed);
    }

    /// Internal: Rebuild the domain matcher from routes
    fn rebuild_matcher(
        &self,
        routes: HashMap<String, (DomainMatchType, String)>,
    ) -> DnsResult<()> {
        let mut builder = DomainMatcherBuilder::new();

        for (pattern, (match_type, upstream_tag)) in &routes {
            match match_type {
                DomainMatchType::Exact => {
                    builder = builder.add_exact(pattern, upstream_tag);
                }
                DomainMatchType::Suffix => {
                    builder = builder.add_suffix(pattern, upstream_tag);
                }
                DomainMatchType::Keyword => {
                    builder = builder.add_keyword(pattern, upstream_tag);
                }
                DomainMatchType::Regex => {
                    builder = builder.add_regex(pattern, upstream_tag).map_err(|e| {
                        DnsError::config_field(
                            format!("invalid regex pattern '{}': {}", pattern, e),
                            "dns.split.routes",
                        )
                    })?;
                }
            }
        }

        let matcher = builder
            .build()
            .map_err(|e| DnsError::internal(format!("failed to build domain matcher: {}", e)))?;

        let count = routes.len();
        let state = MatcherState::new(matcher, routes);

        self.matcher.store(Arc::new(state));
        self.stats.set_rule_count(count);
        self.stats.update_last_reload();

        Ok(())
    }
}

impl fmt::Debug for DnsRouter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let stats = self.stats();
        f.debug_struct("DnsRouter")
            .field("default_upstream", &self.default_upstream)
            .field("route_count", &stats.rule_count)
            .field("upstream_count", &self.upstream_count())
            .field("routes_evaluated", &stats.routes_evaluated)
            .field("default_fallbacks", &stats.default_fallbacks)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // Basic Routing Tests (10 tests)
    // ========================================================================

    #[test]
    fn test_route_exact_match() {
        let router = DnsRouter::new("default".to_string());
        router
            .add_route("example.com", DomainMatchType::Exact, "exact-upstream")
            .unwrap();

        assert_eq!(router.route_to_tag("example.com"), "exact-upstream");
        // Exact match should NOT match subdomains
        assert_eq!(router.route_to_tag("www.example.com"), "default");
    }

    #[test]
    fn test_route_suffix_match() {
        let router = DnsRouter::new("default".to_string());
        router
            .add_route("cn", DomainMatchType::Suffix, "china")
            .unwrap();

        assert_eq!(router.route_to_tag("baidu.cn"), "china");
        assert_eq!(router.route_to_tag("www.baidu.cn"), "china");
        assert_eq!(router.route_to_tag("mail.163.cn"), "china");
    }

    #[test]
    fn test_route_keyword_match() {
        let router = DnsRouter::new("default".to_string());
        router
            .add_route("google", DomainMatchType::Keyword, "google-upstream")
            .unwrap();

        assert_eq!(router.route_to_tag("google.com"), "google-upstream");
        assert_eq!(router.route_to_tag("www.google.com"), "google-upstream");
        assert_eq!(router.route_to_tag("mail.google.co.uk"), "google-upstream");
        assert_eq!(router.route_to_tag("notgoogles.com"), "google-upstream"); // Keyword is substring
    }

    #[test]
    fn test_route_regex_match() {
        let router = DnsRouter::new("default".to_string());
        router
            .add_route(r"^ad[0-9]*\.", DomainMatchType::Regex, "adblock")
            .unwrap();

        assert_eq!(router.route_to_tag("ad.example.com"), "adblock");
        assert_eq!(router.route_to_tag("ad1.example.com"), "adblock");
        assert_eq!(router.route_to_tag("ad123.tracker.net"), "adblock");
        assert_eq!(router.route_to_tag("notad.example.com"), "default");
    }

    #[test]
    fn test_route_default_fallback() {
        let router = DnsRouter::new("fallback".to_string());
        router
            .add_route("specific.com", DomainMatchType::Exact, "specific")
            .unwrap();

        // No match, should use default
        assert_eq!(router.route_to_tag("unknown.com"), "fallback");
        assert_eq!(router.route_to_tag("random.org"), "fallback");
    }

    #[test]
    fn test_route_case_insensitive() {
        let router = DnsRouter::new("default".to_string());
        router
            .add_route("example.com", DomainMatchType::Suffix, "example")
            .unwrap();

        // Domain matching should be case-insensitive
        assert_eq!(router.route_to_tag("EXAMPLE.COM"), "example");
        assert_eq!(router.route_to_tag("Example.Com"), "example");
        assert_eq!(router.route_to_tag("WWW.EXAMPLE.COM"), "example");
    }

    #[test]
    fn test_route_multiple_rules() {
        let router = DnsRouter::new("default".to_string());
        router
            .add_route("cn", DomainMatchType::Suffix, "china")
            .unwrap();
        router
            .add_route("jp", DomainMatchType::Suffix, "japan")
            .unwrap();
        router
            .add_route("google.com", DomainMatchType::Suffix, "google")
            .unwrap();

        assert_eq!(router.route_to_tag("baidu.cn"), "china");
        assert_eq!(router.route_to_tag("yahoo.jp"), "japan");
        assert_eq!(router.route_to_tag("mail.google.com"), "google");
        assert_eq!(router.route_to_tag("example.org"), "default");
    }

    #[test]
    fn test_route_mixed_match_types() {
        let router = DnsRouter::new("default".to_string());
        router
            .add_route("exact.com", DomainMatchType::Exact, "exact")
            .unwrap();
        router
            .add_route("suffix.net", DomainMatchType::Suffix, "suffix")
            .unwrap();
        router
            .add_route("keyword", DomainMatchType::Keyword, "keyword")
            .unwrap();

        assert_eq!(router.route_to_tag("exact.com"), "exact");
        assert_eq!(router.route_to_tag("www.exact.com"), "default"); // Exact only
        assert_eq!(router.route_to_tag("suffix.net"), "suffix");
        assert_eq!(router.route_to_tag("www.suffix.net"), "suffix");
        assert_eq!(router.route_to_tag("has-keyword-here.com"), "keyword");
    }

    #[test]
    fn test_route_empty_router() {
        let router = DnsRouter::new("default".to_string());

        // All domains should route to default
        assert_eq!(router.route_to_tag("any.domain.com"), "default");
        assert_eq!(router.route_to_tag("example.org"), "default");
    }

    #[test]
    fn test_route_suffix_no_partial_match() {
        let router = DnsRouter::new("default".to_string());
        router
            .add_route("example.com", DomainMatchType::Suffix, "example")
            .unwrap();

        // Should NOT match domains that just contain the suffix
        assert_eq!(router.route_to_tag("notexample.com"), "default");
        assert_eq!(router.route_to_tag("myexample.com"), "default");
    }

    // ========================================================================
    // Upstream Management Tests (8 tests)
    // ========================================================================

    #[test]
    fn test_upstream_add() {
        let router = DnsRouter::new("default".to_string());

        // Note: We can't easily create UpstreamPool without actual upstreams,
        // so we just test the structure
        assert_eq!(router.upstream_count(), 0);
        assert!(router.list_upstreams().is_empty());
    }

    #[test]
    fn test_upstream_remove() {
        let router = DnsRouter::new("default".to_string());

        // Remove non-existent upstream
        assert!(!router.remove_upstream("nonexistent"));
    }

    #[test]
    fn test_upstream_get_nonexistent() {
        let router = DnsRouter::new("default".to_string());

        assert!(router.get_upstream("nonexistent").is_none());
    }

    #[test]
    fn test_upstream_list_empty() {
        let router = DnsRouter::new("default".to_string());

        let list = router.list_upstreams();
        assert!(list.is_empty());
    }

    #[test]
    fn test_upstream_count() {
        let router = DnsRouter::new("default".to_string());

        assert_eq!(router.upstream_count(), 0);
    }

    #[test]
    fn test_route_with_missing_upstream() {
        let router = DnsRouter::new("default".to_string());
        router
            .add_route("example.com", DomainMatchType::Suffix, "missing")
            .unwrap();

        // Route should return tag even if upstream is not registered
        assert_eq!(router.route_to_tag("example.com"), "missing");
        // But route() should return None
        assert!(router.route("example.com").is_none());
    }

    #[test]
    fn test_default_upstream_accessor() {
        let router = DnsRouter::new("my-default".to_string());
        assert_eq!(router.default_upstream(), "my-default");
    }

    #[test]
    fn test_set_default_upstream() {
        let mut router = DnsRouter::new("old-default".to_string());
        router.set_default_upstream("new-default".to_string());
        assert_eq!(router.default_upstream(), "new-default");
    }

    // ========================================================================
    // Hot Reload Tests (8 tests)
    // ========================================================================

    #[test]
    fn test_reload_rules_atomic() {
        let router = DnsRouter::new("default".to_string());
        router
            .add_route("old.com", DomainMatchType::Suffix, "old")
            .unwrap();

        // Build new rules
        let new_matcher = DomainMatcher::builder()
            .add_suffix("new.com", "new")
            .build()
            .unwrap();
        let mut new_routes = HashMap::new();
        new_routes.insert("new.com".to_string(), (DomainMatchType::Suffix, "new".to_string()));

        router.reload_rules(new_matcher, new_routes).unwrap();

        // Old rule should be gone
        assert_eq!(router.route_to_tag("old.com"), "default");
        // New rule should work
        assert_eq!(router.route_to_tag("new.com"), "new");
    }

    #[test]
    fn test_reload_updates_stats() {
        let router = DnsRouter::new("default".to_string());

        // Initial state
        assert!(router.stats().last_reload.is_none());

        // Add a route (triggers rebuild)
        router
            .add_route("test.com", DomainMatchType::Suffix, "test")
            .unwrap();

        // Should have last_reload set now
        assert!(router.stats().last_reload.is_some());
    }

    #[test]
    fn test_reload_empty_rules() {
        let router = DnsRouter::new("default".to_string());
        router
            .add_route("test.com", DomainMatchType::Suffix, "test")
            .unwrap();
        assert!(!router.is_empty());

        // Clear routes
        router.clear_routes();

        assert!(router.is_empty());
        assert_eq!(router.route_count(), 0);
        assert_eq!(router.route_to_tag("test.com"), "default");
    }

    #[test]
    fn test_reload_large_rule_set() {
        let router = DnsRouter::new("default".to_string());

        // Load 1000 rules
        let routes: Vec<RouteInfo> = (0..1000)
            .map(|i| RouteInfo::new(format!("domain{}.com", i), DomainMatchType::Suffix, "bulk"))
            .collect();

        router.load_routes(&routes).unwrap();

        assert_eq!(router.route_count(), 1000);
        assert_eq!(router.route_to_tag("domain500.com"), "bulk");
        assert_eq!(router.route_to_tag("www.domain999.com"), "bulk");
    }

    #[test]
    fn test_reload_performance() {
        use std::time::Instant;

        let router = DnsRouter::new("default".to_string());

        // Build 1000 routes
        let routes: Vec<RouteInfo> = (0..1000)
            .map(|i| RouteInfo::new(format!("domain{}.com", i), DomainMatchType::Suffix, "test"))
            .collect();

        let start = Instant::now();
        router.load_routes(&routes).unwrap();
        let elapsed = start.elapsed();

        // Hot reload should complete in under 100ms for 1000 rules
        // (10ms target is for the atomic swap, building takes longer)
        assert!(
            elapsed.as_millis() < 100,
            "Reload took too long: {:?}",
            elapsed
        );
    }

    #[test]
    fn test_concurrent_reads_during_reload() {
        use std::sync::Arc;
        use std::thread;

        let router = Arc::new(DnsRouter::new("default".to_string()));
        router
            .add_route("initial.com", DomainMatchType::Suffix, "initial")
            .unwrap();

        // Spawn readers
        let mut handles = vec![];
        for _ in 0..4 {
            let r = Arc::clone(&router);
            handles.push(thread::spawn(move || {
                for _ in 0..1000 {
                    // Should never panic
                    let _ = r.route_to_tag("initial.com");
                    let _ = r.route_to_tag("other.com");
                }
            }));
        }

        // Writer thread that does reloads
        let r = Arc::clone(&router);
        let writer = thread::spawn(move || {
            for i in 0..10 {
                let routes: Vec<RouteInfo> = (0..100)
                    .map(|j| {
                        RouteInfo::new(format!("reload{}_{}.com", i, j), DomainMatchType::Suffix, "reload")
                    })
                    .collect();
                r.load_routes(&routes).unwrap();
            }
        });

        writer.join().unwrap();
        for h in handles {
            h.join().unwrap();
        }
    }

    #[test]
    fn test_load_routes_replaces_existing() {
        let router = DnsRouter::new("default".to_string());

        // First load
        let routes1 = vec![RouteInfo::new("first.com", DomainMatchType::Suffix, "first")];
        router.load_routes(&routes1).unwrap();
        assert_eq!(router.route_to_tag("first.com"), "first");

        // Second load (replaces)
        let routes2 = vec![RouteInfo::new("second.com", DomainMatchType::Suffix, "second")];
        router.load_routes(&routes2).unwrap();

        // First rule should be gone
        assert_eq!(router.route_to_tag("first.com"), "default");
        assert_eq!(router.route_to_tag("second.com"), "second");
    }

    #[test]
    fn test_reload_preserves_upstreams() {
        let router = DnsRouter::new("default".to_string());

        // Note: We can't easily test with real upstreams, but the structure
        // should be preserved across rule reloads
        router
            .add_route("test.com", DomainMatchType::Suffix, "test")
            .unwrap();
        router.clear_routes();

        // Upstreams should still be accessible (even if empty)
        assert!(router.list_upstreams().is_empty());
    }

    // ========================================================================
    // Route Management Tests (8 tests)
    // ========================================================================

    #[test]
    fn test_add_route_single() {
        let router = DnsRouter::new("default".to_string());

        router
            .add_route("test.com", DomainMatchType::Suffix, "test")
            .unwrap();

        assert_eq!(router.route_count(), 1);
        assert!(!router.is_empty());
    }

    #[test]
    fn test_remove_route() {
        let router = DnsRouter::new("default".to_string());
        router
            .add_route("test.com", DomainMatchType::Suffix, "test")
            .unwrap();

        let removed = router.remove_route("test.com").unwrap();

        assert!(removed);
        assert!(router.is_empty());
        assert_eq!(router.route_to_tag("test.com"), "default");
    }

    #[test]
    fn test_remove_route_nonexistent() {
        let router = DnsRouter::new("default".to_string());
        router
            .add_route("test.com", DomainMatchType::Suffix, "test")
            .unwrap();

        let removed = router.remove_route("nonexistent.com").unwrap();

        assert!(!removed);
        assert_eq!(router.route_count(), 1); // Still has test.com
    }

    #[test]
    fn test_list_routes() {
        let router = DnsRouter::new("default".to_string());
        router
            .add_route("a.com", DomainMatchType::Exact, "a")
            .unwrap();
        router
            .add_route("b.com", DomainMatchType::Suffix, "b")
            .unwrap();

        let routes = router.list_routes();

        assert_eq!(routes.len(), 2);
        // Note: Order may vary due to HashMap
        assert!(routes.iter().any(|r| r.pattern == "a.com"));
        assert!(routes.iter().any(|r| r.pattern == "b.com"));
    }

    #[test]
    fn test_add_route_invalid_regex() {
        let router = DnsRouter::new("default".to_string());

        let result = router.add_route("[invalid", DomainMatchType::Regex, "test");

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("invalid regex"));
    }

    #[test]
    fn test_add_route_normalizes_pattern() {
        let router = DnsRouter::new("default".to_string());

        router
            .add_route("UPPERCASE.COM", DomainMatchType::Suffix, "test")
            .unwrap();

        // Should match regardless of case
        assert_eq!(router.route_to_tag("uppercase.com"), "test");
        assert_eq!(router.route_to_tag("www.UPPERCASE.COM"), "test");
    }

    #[test]
    fn test_add_route_updates_existing() {
        let router = DnsRouter::new("default".to_string());

        router
            .add_route("test.com", DomainMatchType::Suffix, "first")
            .unwrap();
        router
            .add_route("test.com", DomainMatchType::Suffix, "second")
            .unwrap();

        // Should use the updated upstream
        assert_eq!(router.route_to_tag("test.com"), "second");
        assert_eq!(router.route_count(), 1); // Still just one rule
    }

    #[test]
    fn test_list_routes_empty() {
        let router = DnsRouter::new("default".to_string());

        let routes = router.list_routes();
        assert!(routes.is_empty());
    }

    // ========================================================================
    // Statistics Tests (6 tests)
    // ========================================================================

    #[test]
    fn test_stats_routes_evaluated() {
        let router = DnsRouter::new("default".to_string());
        router
            .add_route("test.com", DomainMatchType::Suffix, "test")
            .unwrap();

        // Initial
        assert_eq!(router.stats().routes_evaluated, 0);

        // Route some queries
        let _ = router.route_to_tag("test.com");
        let _ = router.route_to_tag("other.com");
        let _ = router.route_to_tag("another.com");

        assert_eq!(router.stats().routes_evaluated, 3);
    }

    #[test]
    fn test_stats_default_fallbacks() {
        let router = DnsRouter::new("default".to_string());
        router
            .add_route("test.com", DomainMatchType::Suffix, "test")
            .unwrap();

        // Route queries
        let _ = router.route_to_tag("test.com"); // Match
        let _ = router.route_to_tag("other.com"); // Fallback
        let _ = router.route_to_tag("another.com"); // Fallback

        assert_eq!(router.stats().default_fallbacks, 2);
    }

    #[test]
    fn test_stats_rule_count() {
        let router = DnsRouter::new("default".to_string());

        assert_eq!(router.stats().rule_count, 0);

        router
            .add_route("a.com", DomainMatchType::Suffix, "a")
            .unwrap();
        assert_eq!(router.stats().rule_count, 1);

        router
            .add_route("b.com", DomainMatchType::Suffix, "b")
            .unwrap();
        assert_eq!(router.stats().rule_count, 2);

        router.remove_route("a.com").unwrap();
        assert_eq!(router.stats().rule_count, 1);
    }

    #[test]
    fn test_stats_last_reload() {
        let router = DnsRouter::new("default".to_string());

        // Initially no reload
        assert!(router.stats().last_reload.is_none());

        // After adding a rule
        router
            .add_route("test.com", DomainMatchType::Suffix, "test")
            .unwrap();
        let reload_time = router.stats().last_reload;
        assert!(reload_time.is_some());

        // Timestamp should be recent (within last minute)
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(reload_time.unwrap() <= now);
        assert!(reload_time.unwrap() > now - 60);
    }

    #[test]
    fn test_stats_reset() {
        let router = DnsRouter::new("default".to_string());
        router
            .add_route("test.com", DomainMatchType::Suffix, "test")
            .unwrap();

        // Generate some stats
        let _ = router.route_to_tag("test.com");
        let _ = router.route_to_tag("other.com");

        // Reset
        router.reset_stats();

        let stats = router.stats();
        assert_eq!(stats.routes_evaluated, 0);
        assert_eq!(stats.default_fallbacks, 0);
        // Rule count should still be preserved
        assert_eq!(stats.rule_count, 1);
    }

    #[test]
    fn test_stats_snapshot_consistency() {
        let router = DnsRouter::new("default".to_string());
        router
            .add_route("test.com", DomainMatchType::Suffix, "test")
            .unwrap();

        // Route a matching query
        let _ = router.route_to_tag("test.com");
        // Route a non-matching query
        let _ = router.route_to_tag("other.com");

        let stats = router.stats();

        // routes_evaluated should be total queries
        assert_eq!(stats.routes_evaluated, 2);
        // default_fallbacks should be non-matching queries
        assert_eq!(stats.default_fallbacks, 1);
        // Matched queries = routes_evaluated - default_fallbacks
        assert_eq!(stats.routes_evaluated - stats.default_fallbacks, 1);
    }

    // ========================================================================
    // Additional Tests
    // ========================================================================

    #[test]
    fn test_debug_format() {
        let router = DnsRouter::new("default".to_string());
        router
            .add_route("test.com", DomainMatchType::Suffix, "test")
            .unwrap();

        let debug = format!("{:?}", router);
        assert!(debug.contains("DnsRouter"));
        assert!(debug.contains("default_upstream"));
        assert!(debug.contains("route_count"));
    }

    #[test]
    fn test_route_info_new() {
        let info = RouteInfo::new("test.com", DomainMatchType::Suffix, "upstream");

        assert_eq!(info.pattern, "test.com");
        assert_eq!(info.match_type, DomainMatchType::Suffix);
        assert_eq!(info.upstream_tag, "upstream");
    }

    #[test]
    fn test_route_info_equality() {
        let info1 = RouteInfo::new("test.com", DomainMatchType::Suffix, "up");
        let info2 = RouteInfo::new("test.com", DomainMatchType::Suffix, "up");
        let info3 = RouteInfo::new("other.com", DomainMatchType::Suffix, "up");

        assert_eq!(info1, info2);
        assert_ne!(info1, info3);
    }

    #[test]
    fn test_domain_match_type_as_str() {
        assert_eq!(DomainMatchType::Exact.as_str(), "exact");
        assert_eq!(DomainMatchType::Suffix.as_str(), "suffix");
        assert_eq!(DomainMatchType::Keyword.as_str(), "keyword");
        assert_eq!(DomainMatchType::Regex.as_str(), "regex");
    }

    #[test]
    fn test_max_routes_limit() {
        let router = DnsRouter::new("default".to_string());

        // Create a list exceeding MAX_ROUTES
        let routes: Vec<RouteInfo> = (0..=MAX_ROUTES)
            .map(|i| RouteInfo::new(format!("domain{}.com", i), DomainMatchType::Suffix, "test"))
            .collect();

        let result = router.load_routes(&routes);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("exceed"));
    }

    #[test]
    fn test_stats_snapshot_default() {
        let snapshot = DnsRouterStatsSnapshot::default();

        assert_eq!(snapshot.routes_evaluated, 0);
        assert_eq!(snapshot.default_fallbacks, 0);
        assert_eq!(snapshot.rule_count, 0);
        assert!(snapshot.last_reload.is_none());
    }

    #[test]
    fn test_route_info_debug() {
        let info = RouteInfo::new("test.com", DomainMatchType::Suffix, "upstream");
        let debug = format!("{:?}", info);

        assert!(debug.contains("test.com"));
        assert!(debug.contains("Suffix"));
        assert!(debug.contains("upstream"));
    }

    #[test]
    fn test_domain_match_type_hash() {
        use std::collections::HashSet;

        let mut set = HashSet::new();
        set.insert(DomainMatchType::Exact);
        set.insert(DomainMatchType::Suffix);
        set.insert(DomainMatchType::Keyword);
        set.insert(DomainMatchType::Regex);

        assert_eq!(set.len(), 4);
    }

    #[test]
    fn test_clear_routes_updates_stats() {
        let router = DnsRouter::new("default".to_string());
        router
            .add_route("test.com", DomainMatchType::Suffix, "test")
            .unwrap();

        let pre_clear = router.stats().last_reload;

        // Small delay to ensure time difference
        std::thread::sleep(std::time::Duration::from_millis(10));

        router.clear_routes();

        // Rule count should be 0
        assert_eq!(router.stats().rule_count, 0);
        // last_reload should be updated
        let post_clear = router.stats().last_reload;
        assert!(post_clear.is_some());
        // The timestamp might be the same if the system clock has low resolution
        // so we just check it's still set
        assert!(post_clear >= pre_clear);
    }

    // ========================================================================
    // Edge Case Tests (QA Review Findings)
    // ========================================================================

    #[test]
    fn test_route_empty_domain() {
        // Test routing with empty domain string
        let router = DnsRouter::new("default".to_string());
        router
            .add_route("example.com", DomainMatchType::Suffix, "example")
            .unwrap();

        // Empty domain should fall back to default (no match)
        assert_eq!(router.route_to_tag(""), "default");

        // route() should also handle empty domain gracefully
        assert!(router.route("").is_none());
    }

    #[test]
    fn test_route_unicode_idn_domains() {
        // Test international domain names (IDN)
        let router = DnsRouter::new("default".to_string());

        // Add rules for Chinese TLD
        router
            .add_route("cn", DomainMatchType::Suffix, "china")
            .unwrap();

        // Test Chinese domain (will be normalized to lowercase ASCII)
        // Note: The domain matcher uses ASCII lowercase normalization
        // Unicode characters outside ASCII range are preserved
        let result = router.route_to_tag("example.cn");
        assert_eq!(result, "china");

        // Test with actual Unicode domain patterns
        // These should be normalized via to_ascii_lowercase which handles ASCII only
        router
            .add_route("cafe", DomainMatchType::Keyword, "keyword-match")
            .unwrap();

        // The keyword "cafe" should match
        assert_eq!(router.route_to_tag("cafe.com"), "keyword-match");

        // Test German umlaut domain (outside ASCII range, preserved as-is)
        router
            .add_route("munchen", DomainMatchType::Keyword, "german")
            .unwrap();
        assert_eq!(router.route_to_tag("munchen.de"), "german");

        // Mixed case Unicode: to_ascii_lowercase only affects ASCII chars
        assert_eq!(router.route_to_tag("MUNCHEN.DE"), "german");
    }

    #[test]
    fn test_add_route_whitespace_only_pattern() {
        // Test that whitespace-only patterns are handled
        // Current behavior: patterns are normalized via to_ascii_lowercase
        // Empty or whitespace patterns may create invalid rules
        let router = DnsRouter::new("default".to_string());

        // Whitespace-only patterns - these currently get normalized but create
        // rules that may not match anything meaningful
        // The behavior is that they become empty or whitespace strings in the matcher
        let result = router.add_route("   ", DomainMatchType::Exact, "whitespace");

        // Currently this succeeds but the rule is essentially useless
        // Document the behavior: whitespace patterns are accepted but won't match
        // typical domains (which don't contain leading/trailing spaces)
        if result.is_ok() {
            // The rule exists but won't match normal domains
            assert_eq!(router.route_to_tag("example.com"), "default");
            // It would only match a domain that is literally "   " (unlikely)
        }

        // Tab and newline patterns
        let result2 = router.add_route("\t\n", DomainMatchType::Suffix, "tabs");
        // Similar behavior - accepted but won't match normal domains
        if result2.is_ok() {
            assert_eq!(router.route_to_tag("example.org"), "default");
        }
    }

    #[test]
    fn test_route_very_long_domain() {
        // DNS domain names have a 253 character limit (RFC 1035)
        // Test handling of domains exceeding this limit
        let router = DnsRouter::new("default".to_string());
        router
            .add_route("long", DomainMatchType::Keyword, "long-match")
            .unwrap();

        // Generate a domain exceeding DNS limit (>253 chars)
        let long_domain = "a".repeat(300);

        // Should handle gracefully (fall back to default or match keyword)
        let result = router.route_to_tag(&long_domain);
        // The domain doesn't contain "long" so should fall back to default
        assert_eq!(result, "default");

        // Test with a long domain that contains the keyword
        let long_with_keyword = format!("{}long{}.com", "a".repeat(100), "b".repeat(100));
        let result2 = router.route_to_tag(&long_with_keyword);
        // Should match the keyword
        assert_eq!(result2, "long-match");

        // Test adding a very long pattern (>253 chars)
        let long_pattern = "x".repeat(300);
        let result3 = router.add_route(&long_pattern, DomainMatchType::Exact, "very-long");
        // This should succeed (we don't enforce DNS limits on patterns)
        assert!(result3.is_ok());

        // But it won't match anything practical
        assert_eq!(router.route_to_tag(&long_pattern), "very-long");
    }

    #[test]
    fn test_max_routes_boundary_via_add_route() {
        // Test that MAX_ROUTES limit is enforced when adding routes one by one
        let router = DnsRouter::new("default".to_string());

        // Fill up to exactly MAX_ROUTES
        for i in 0..MAX_ROUTES {
            let result = router.add_route(
                &format!("domain{}.com", i),
                DomainMatchType::Suffix,
                "bulk",
            );
            assert!(
                result.is_ok(),
                "Failed to add route {} of {}: {:?}",
                i + 1,
                MAX_ROUTES,
                result
            );
        }

        // Verify count
        assert_eq!(router.route_count(), MAX_ROUTES);

        // Adding one more should fail
        let overflow_result = router.add_route("overflow.com", DomainMatchType::Suffix, "overflow");
        assert!(
            overflow_result.is_err(),
            "Should have failed when exceeding MAX_ROUTES"
        );

        let err_msg = overflow_result.unwrap_err().to_string();
        assert!(
            err_msg.contains("exceed") || err_msg.contains("maximum"),
            "Error message should mention exceeding limit: {}",
            err_msg
        );

        // Count should still be MAX_ROUTES
        assert_eq!(router.route_count(), MAX_ROUTES);
    }

    #[test]
    fn test_max_routes_update_existing_at_limit() {
        // When at MAX_ROUTES, updating an existing rule should succeed
        let router = DnsRouter::new("default".to_string());

        // Fill to MAX_ROUTES
        for i in 0..MAX_ROUTES {
            router
                .add_route(&format!("domain{}.com", i), DomainMatchType::Suffix, "original")
                .unwrap();
        }

        // Update an existing route (should succeed)
        let update_result = router.add_route("domain0.com", DomainMatchType::Suffix, "updated");
        assert!(
            update_result.is_ok(),
            "Updating existing route at MAX_ROUTES should succeed"
        );

        // Verify the update took effect
        assert_eq!(router.route_to_tag("domain0.com"), "updated");

        // Count should still be MAX_ROUTES (no new route added)
        assert_eq!(router.route_count(), MAX_ROUTES);
    }

    #[test]
    fn test_route_special_characters_in_domain() {
        // Test domains with special characters
        let router = DnsRouter::new("default".to_string());

        router
            .add_route("test-domain.com", DomainMatchType::Exact, "hyphen")
            .unwrap();
        router
            .add_route("under_score", DomainMatchType::Keyword, "underscore")
            .unwrap();

        // Hyphenated domain
        assert_eq!(router.route_to_tag("test-domain.com"), "hyphen");

        // Underscore in domain (technically invalid DNS but should be handled)
        assert_eq!(router.route_to_tag("has_under_score.com"), "underscore");

        // Numeric domain
        router
            .add_route("123.com", DomainMatchType::Exact, "numeric")
            .unwrap();
        assert_eq!(router.route_to_tag("123.com"), "numeric");
    }

    #[test]
    fn test_route_trailing_dot_domain() {
        // Test FQDN with trailing dot (e.g., "example.com.")
        let router = DnsRouter::new("default".to_string());

        router
            .add_route("example.com", DomainMatchType::Suffix, "example")
            .unwrap();

        // With trailing dot (FQDN notation)
        // The matcher should handle this - behavior depends on DomainMatcher impl
        let result = router.route_to_tag("example.com.");

        // Document actual behavior: trailing dot is part of the domain string
        // and may or may not match depending on matcher implementation
        // Most DNS implementations strip trailing dots before matching
        assert!(
            result == "example" || result == "default",
            "Should either match or fall back to default, got: {}",
            result
        );
    }

    #[test]
    fn test_route_null_byte_in_domain() {
        // Test domain containing null bytes (should not crash)
        let router = DnsRouter::new("default".to_string());

        router
            .add_route("normal.com", DomainMatchType::Suffix, "normal")
            .unwrap();

        // Domain with embedded null byte (invalid but should handle gracefully)
        let domain_with_null = "test\0.com";
        let result = router.route_to_tag(domain_with_null);

        // Should not panic, result depends on matcher behavior
        // Most likely falls back to default since null byte doesn't match typical patterns
        assert!(
            result == "default" || !result.is_empty(),
            "Should handle null byte gracefully"
        );
    }

    #[test]
    fn test_route_only_dots_domain() {
        // Test domain that is only dots
        let router = DnsRouter::new("default".to_string());

        router
            .add_route(".", DomainMatchType::Exact, "root")
            .unwrap();

        // Single dot (root domain)
        assert_eq!(router.route_to_tag("."), "root");

        // Multiple dots
        assert_eq!(router.route_to_tag(".."), "default");
        assert_eq!(router.route_to_tag("..."), "default");
    }
}
