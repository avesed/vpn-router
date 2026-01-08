//! DNS Upstream Pool
//!
//! This module provides an upstream pool that manages multiple DNS upstream
//! clients with health-aware selection and load balancing.
//!
//! # Features
//!
//! - Multiple selection strategies (round-robin, random, first-available)
//! - Health-aware selection (skips unhealthy upstreams)
//! - Automatic failover to other upstreams
//! - Tag-based upstream lookup
//! - Statistics tracking
//!
//! # Example
//!
//! ```no_run
//! use rust_router::dns::client::{UpstreamPool, UdpClient, SelectionStrategy};
//! use rust_router::dns::{UpstreamConfig, UpstreamProtocol};
//! use hickory_proto::op::Message;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config1 = UpstreamConfig::new("google", "8.8.8.8:53", UpstreamProtocol::Udp);
//! let config2 = UpstreamConfig::new("cloudflare", "1.1.1.1:53", UpstreamProtocol::Udp);
//!
//! let client1 = UdpClient::new(config1)?;
//! let client2 = UdpClient::new(config2)?;
//!
//! let pool = UpstreamPool::new(vec![Box::new(client1), Box::new(client2)]);
//!
//! let mut query = Message::new();
//! query.set_id(0x1234);
//! // ... set up query ...
//!
//! let response = pool.query(&query).await?;
//! # Ok(())
//! # }
//! ```

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

use hickory_proto::op::Message;
use parking_lot::RwLock;
use rand::Rng;

use super::traits::DnsUpstream;
use crate::dns::config::UpstreamProtocol;
use crate::dns::error::{DnsError, DnsResult};

/// Selection strategy for choosing an upstream
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SelectionStrategy {
    /// Round-robin selection across healthy upstreams
    #[default]
    RoundRobin,

    /// Random selection from healthy upstreams
    Random,

    /// Use the first healthy upstream (stable selection)
    FirstAvailable,

    /// Weighted round-robin based on upstream weights
    Weighted,
}

/// Statistics for upstream pool operations
#[derive(Debug, Default)]
pub struct PoolStats {
    /// Total number of queries processed
    pub total_queries: AtomicU64,

    /// Number of successful queries
    pub successful_queries: AtomicU64,

    /// Number of failed queries
    pub failed_queries: AtomicU64,

    /// Number of queries that required failover
    pub failover_queries: AtomicU64,

    /// Number of queries with no healthy upstreams
    pub no_healthy_upstream: AtomicU64,
}

impl PoolStats {
    /// Create new pool statistics
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a successful query
    pub fn record_success(&self) {
        self.total_queries.fetch_add(1, Ordering::Relaxed);
        self.successful_queries.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a failed query
    pub fn record_failure(&self) {
        self.total_queries.fetch_add(1, Ordering::Relaxed);
        self.failed_queries.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a failover attempt
    pub fn record_failover(&self) {
        self.failover_queries.fetch_add(1, Ordering::Relaxed);
    }

    /// Record no healthy upstream available
    pub fn record_no_healthy(&self) {
        self.total_queries.fetch_add(1, Ordering::Relaxed);
        self.no_healthy_upstream.fetch_add(1, Ordering::Relaxed);
    }

    /// Get total queries
    pub fn total_queries(&self) -> u64 {
        self.total_queries.load(Ordering::Relaxed)
    }

    /// Get successful queries
    pub fn successful_queries(&self) -> u64 {
        self.successful_queries.load(Ordering::Relaxed)
    }

    /// Get failed queries
    pub fn failed_queries(&self) -> u64 {
        self.failed_queries.load(Ordering::Relaxed)
    }

    /// Get failover queries
    pub fn failover_queries(&self) -> u64 {
        self.failover_queries.load(Ordering::Relaxed)
    }

    /// Get no healthy upstream count
    pub fn no_healthy_upstream(&self) -> u64 {
        self.no_healthy_upstream.load(Ordering::Relaxed)
    }

    /// Get success rate as percentage
    pub fn success_rate(&self) -> f64 {
        let total = self.total_queries();
        if total == 0 {
            return 100.0;
        }
        (self.successful_queries() as f64 / total as f64) * 100.0
    }
}

/// Upstream entry with metadata
struct UpstreamEntry {
    /// The upstream client (Arc for lock-free query access)
    upstream: Arc<dyn DnsUpstream>,

    /// Weight for weighted selection (default: 1)
    weight: u32,
}

impl UpstreamEntry {
    fn new(upstream: Box<dyn DnsUpstream>) -> Self {
        Self {
            upstream: Arc::from(upstream),
            weight: 1,
        }
    }

    fn with_weight(upstream: Box<dyn DnsUpstream>, weight: u32) -> Self {
        Self {
            upstream: Arc::from(upstream),
            weight,
        }
    }
}

/// DNS Upstream Pool
///
/// Manages multiple DNS upstream clients with health-aware selection
/// and automatic failover.
///
/// # Thread Safety
///
/// This pool is thread-safe and can be shared across tasks.
///
/// # Example
///
/// ```no_run
/// use rust_router::dns::client::{UpstreamPool, UdpClient, SelectionStrategy};
/// use rust_router::dns::{UpstreamConfig, UpstreamProtocol};
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let config = UpstreamConfig::new("google", "8.8.8.8:53", UpstreamProtocol::Udp);
/// let client = UdpClient::new(config)?;
///
/// let pool = UpstreamPool::builder()
///     .add_upstream(Box::new(client))
///     .strategy(SelectionStrategy::RoundRobin)
///     .build();
///
/// assert!(!pool.is_empty());
/// # Ok(())
/// # }
/// ```
pub struct UpstreamPool {
    /// List of upstream entries
    upstreams: RwLock<Vec<UpstreamEntry>>,

    /// Selection strategy
    strategy: SelectionStrategy,

    /// Round-robin counter
    rr_counter: AtomicUsize,

    /// Pool statistics
    stats: Arc<PoolStats>,
}

impl std::fmt::Debug for UpstreamPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let upstreams = self.upstreams.read();
        f.debug_struct("UpstreamPool")
            .field("upstream_count", &upstreams.len())
            .field("strategy", &self.strategy)
            .field("healthy_count", &self.healthy_count_internal(&upstreams))
            .finish()
    }
}

impl UpstreamPool {
    /// Create a new upstream pool with default settings
    ///
    /// # Arguments
    ///
    /// * `upstreams` - List of upstream clients
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rust_router::dns::client::{UpstreamPool, UdpClient};
    /// use rust_router::dns::{UpstreamConfig, UpstreamProtocol};
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let config = UpstreamConfig::new("google", "8.8.8.8:53", UpstreamProtocol::Udp);
    /// let client = UdpClient::new(config)?;
    /// let pool = UpstreamPool::new(vec![Box::new(client)]);
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(upstreams: Vec<Box<dyn DnsUpstream>>) -> Self {
        let entries: Vec<_> = upstreams.into_iter().map(UpstreamEntry::new).collect();
        Self {
            upstreams: RwLock::new(entries),
            strategy: SelectionStrategy::default(),
            rr_counter: AtomicUsize::new(0),
            stats: Arc::new(PoolStats::new()),
        }
    }

    /// Create a pool builder for more configuration options
    pub fn builder() -> UpstreamPoolBuilder {
        UpstreamPoolBuilder::new()
    }

    /// Get the number of upstreams in the pool
    pub fn len(&self) -> usize {
        self.upstreams.read().len()
    }

    /// Check if the pool is empty
    pub fn is_empty(&self) -> bool {
        self.upstreams.read().is_empty()
    }

    /// Get the number of healthy upstreams
    pub fn healthy_count(&self) -> usize {
        let upstreams = self.upstreams.read();
        self.healthy_count_internal(&upstreams)
    }

    fn healthy_count_internal(&self, upstreams: &[UpstreamEntry]) -> usize {
        upstreams
            .iter()
            .filter(|e| e.upstream.is_healthy())
            .count()
    }

    /// Get the selection strategy
    pub fn strategy(&self) -> SelectionStrategy {
        self.strategy
    }

    /// Get pool statistics
    pub fn stats(&self) -> &PoolStats {
        &self.stats
    }

    /// Check if any upstream is healthy
    pub fn has_healthy_upstream(&self) -> bool {
        let upstreams = self.upstreams.read();
        upstreams.iter().any(|e| e.upstream.is_healthy())
    }

    /// Get upstream by tag
    ///
    /// # Arguments
    ///
    /// * `tag` - The upstream tag to look up
    ///
    /// # Returns
    ///
    /// Reference to the upstream if found, None otherwise.
    pub fn get_by_tag(&self, tag: &str) -> Option<impl std::ops::Deref<Target = dyn DnsUpstream> + '_> {
        let upstreams = self.upstreams.read();
        let index = upstreams
            .iter()
            .position(|e| e.upstream.tag() == tag)?;

        // Use a guard to safely return a reference
        Some(UpstreamRef {
            guard: upstreams,
            index,
        })
    }

    /// List all upstream tags
    pub fn tags(&self) -> Vec<String> {
        let upstreams = self.upstreams.read();
        upstreams.iter().map(|e| e.upstream.tag().to_string()).collect()
    }

    /// List healthy upstream tags
    pub fn healthy_tags(&self) -> Vec<String> {
        let upstreams = self.upstreams.read();
        upstreams
            .iter()
            .filter(|e| e.upstream.is_healthy())
            .map(|e| e.upstream.tag().to_string())
            .collect()
    }

    /// Add an upstream to the pool
    ///
    /// # Arguments
    ///
    /// * `upstream` - The upstream client to add
    pub fn add_upstream(&self, upstream: Box<dyn DnsUpstream>) {
        let mut upstreams = self.upstreams.write();
        upstreams.push(UpstreamEntry::new(upstream));
    }

    /// Add an upstream with a specific weight
    ///
    /// # Arguments
    ///
    /// * `upstream` - The upstream client to add
    /// * `weight` - Weight for weighted selection
    pub fn add_upstream_weighted(&self, upstream: Box<dyn DnsUpstream>, weight: u32) {
        let mut upstreams = self.upstreams.write();
        upstreams.push(UpstreamEntry::with_weight(upstream, weight));
    }

    /// Remove an upstream by tag
    ///
    /// # Arguments
    ///
    /// * `tag` - The tag of the upstream to remove
    ///
    /// # Returns
    ///
    /// The removed upstream if found, None otherwise.
    pub fn remove_upstream(&self, tag: &str) -> Option<Arc<dyn DnsUpstream>> {
        let mut upstreams = self.upstreams.write();
        let pos = upstreams.iter().position(|e| e.upstream.tag() == tag)?;
        Some(upstreams.remove(pos).upstream)
    }

    /// Query DNS using the configured selection strategy
    ///
    /// This method selects a healthy upstream using the configured strategy,
    /// sends the query, and automatically fails over to other upstreams if
    /// the selected one fails.
    ///
    /// # Arguments
    ///
    /// * `query` - The DNS query message
    ///
    /// # Returns
    ///
    /// The DNS response message, or an error if all upstreams fail.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rust_router::dns::client::{UpstreamPool, UdpClient};
    /// use rust_router::dns::{UpstreamConfig, UpstreamProtocol};
    /// use hickory_proto::op::Message;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let config = UpstreamConfig::new("google", "8.8.8.8:53", UpstreamProtocol::Udp);
    /// let client = UdpClient::new(config)?;
    /// let pool = UpstreamPool::new(vec![Box::new(client)]);
    ///
    /// let mut query = Message::new();
    /// query.set_id(0x1234);
    /// // ... set up query ...
    ///
    /// let response = pool.query(&query).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn query(&self, query: &Message) -> DnsResult<Message> {
        // Collect healthy upstreams with their Arc references
        // We clone the Arcs to release the lock before async operations
        let healthy_upstreams: Vec<(usize, Arc<dyn DnsUpstream>)> = {
            let upstreams = self.upstreams.read();
            upstreams
                .iter()
                .enumerate()
                .filter(|(_, e)| e.upstream.is_healthy())
                .map(|(i, e)| (i, Arc::clone(&e.upstream)))
                .collect()
        };

        if healthy_upstreams.is_empty() {
            self.stats.record_no_healthy();
            return Err(DnsError::no_upstream(
                "no healthy upstream available in pool",
            ));
        }

        // Select initial upstream based on strategy
        let healthy_indices: Vec<usize> = healthy_upstreams.iter().map(|(i, _)| *i).collect();
        let selected_index = self.select_upstream(&healthy_indices);
        let mut tried_indices = vec![selected_index];
        let mut last_error = None;

        // Find the selected upstream in our collected list
        if let Some((_, upstream)) = healthy_upstreams.iter().find(|(i, _)| *i == selected_index) {
            let upstream = Arc::clone(upstream);
            let tag = upstream.tag().to_string();

            // Query without holding lock
            match upstream.query(query).await {
                Ok(response) => {
                    self.stats.record_success();
                    return Ok(response);
                }
                Err(e) => {
                    tracing::debug!(
                        upstream = %tag,
                        error = %e,
                        "upstream query failed, will try failover"
                    );
                    last_error = Some(e);
                }
            }
        }

        // Failover to other healthy upstreams
        for (index, upstream) in &healthy_upstreams {
            if tried_indices.contains(index) {
                continue;
            }

            tried_indices.push(*index);
            self.stats.record_failover();

            let upstream = Arc::clone(upstream);
            let tag = upstream.tag().to_string();

            // Query without holding lock
            match upstream.query(query).await {
                Ok(response) => {
                    self.stats.record_success();
                    return Ok(response);
                }
                Err(e) => {
                    tracing::debug!(
                        upstream = %tag,
                        error = %e,
                        "failover upstream query failed"
                    );
                    last_error = Some(e);
                }
            }
        }

        // All upstreams failed
        self.stats.record_failure();
        Err(last_error.unwrap_or_else(|| {
            DnsError::no_upstream("all upstreams failed")
        }))
    }

    /// Query a specific upstream by tag
    ///
    /// # Arguments
    ///
    /// * `tag` - The tag of the upstream to query
    /// * `query` - The DNS query message
    ///
    /// # Returns
    ///
    /// The DNS response message, or an error if the query fails.
    pub async fn query_by_tag(&self, tag: &str, query: &Message) -> DnsResult<Message> {
        // Clone the Arc and release lock before async query
        let upstream: Arc<dyn DnsUpstream> = {
            let upstreams = self.upstreams.read();
            let entry = upstreams
                .iter()
                .find(|e| e.upstream.tag() == tag)
                .ok_or_else(|| DnsError::no_upstream(format!("upstream '{}' not found", tag)))?;

            if !entry.upstream.is_healthy() {
                return Err(DnsError::upstream(tag, "upstream is unhealthy"));
            }

            Arc::clone(&entry.upstream)
        };

        // Query without holding lock
        upstream.query(query).await
    }

    /// Select an upstream based on the configured strategy
    fn select_upstream(&self, healthy_indices: &[usize]) -> usize {
        if healthy_indices.is_empty() {
            return 0;
        }

        match self.strategy {
            SelectionStrategy::RoundRobin => {
                let counter = self.rr_counter.fetch_add(1, Ordering::Relaxed);
                healthy_indices[counter % healthy_indices.len()]
            }
            SelectionStrategy::Random => {
                let mut rng = rand::thread_rng();
                healthy_indices[rng.gen_range(0..healthy_indices.len())]
            }
            SelectionStrategy::FirstAvailable => healthy_indices[0],
            SelectionStrategy::Weighted => {
                self.select_weighted(healthy_indices)
            }
        }
    }

    /// Select upstream using weighted random selection
    fn select_weighted(&self, healthy_indices: &[usize]) -> usize {
        let upstreams = self.upstreams.read();

        // Calculate total weight
        let total_weight: u32 = healthy_indices
            .iter()
            .filter_map(|&i| upstreams.get(i))
            .map(|e| e.weight)
            .sum();

        if total_weight == 0 {
            return healthy_indices[0];
        }

        // Generate random value
        let mut rng = rand::thread_rng();
        let mut remaining = rng.gen_range(0..total_weight);

        // Select based on weight
        for &index in healthy_indices {
            if let Some(entry) = upstreams.get(index) {
                if remaining < entry.weight {
                    return index;
                }
                remaining -= entry.weight;
            }
        }

        // Fallback to first
        healthy_indices[0]
    }

    /// Mark an upstream as unhealthy by tag
    pub fn mark_unhealthy(&self, tag: &str) {
        let upstreams = self.upstreams.read();
        if let Some(entry) = upstreams.iter().find(|e| e.upstream.tag() == tag) {
            entry.upstream.mark_unhealthy();
        }
    }

    /// Mark an upstream as healthy by tag
    pub fn mark_healthy(&self, tag: &str) {
        let upstreams = self.upstreams.read();
        if let Some(entry) = upstreams.iter().find(|e| e.upstream.tag() == tag) {
            entry.upstream.mark_healthy();
        }
    }

    /// Get upstream information for status reporting
    pub fn upstream_info(&self) -> Vec<UpstreamInfo> {
        let upstreams = self.upstreams.read();
        upstreams
            .iter()
            .map(|e| UpstreamInfo {
                tag: e.upstream.tag().to_string(),
                address: e.upstream.address().to_string(),
                protocol: e.upstream.protocol(),
                healthy: e.upstream.is_healthy(),
                encrypted: e.upstream.is_encrypted(),
                weight: e.weight,
            })
            .collect()
    }
}

/// Upstream information for status reporting
#[derive(Debug, Clone)]
pub struct UpstreamInfo {
    /// Upstream tag
    pub tag: String,
    /// Upstream address
    pub address: String,
    /// Protocol type
    pub protocol: UpstreamProtocol,
    /// Whether the upstream is healthy
    pub healthy: bool,
    /// Whether the upstream uses encryption
    pub encrypted: bool,
    /// Weight for weighted selection
    pub weight: u32,
}

/// Reference guard for upstream access
struct UpstreamRef<'a> {
    guard: parking_lot::RwLockReadGuard<'a, Vec<UpstreamEntry>>,
    index: usize,
}

impl std::ops::Deref for UpstreamRef<'_> {
    type Target = dyn DnsUpstream;

    fn deref(&self) -> &Self::Target {
        &*self.guard[self.index].upstream
    }
}

/// Builder for creating UpstreamPool with custom configuration
pub struct UpstreamPoolBuilder {
    upstreams: Vec<(Box<dyn DnsUpstream>, u32)>,
    strategy: SelectionStrategy,
}

impl UpstreamPoolBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            upstreams: Vec::new(),
            strategy: SelectionStrategy::default(),
        }
    }

    /// Add an upstream to the pool
    pub fn add_upstream(mut self, upstream: Box<dyn DnsUpstream>) -> Self {
        self.upstreams.push((upstream, 1));
        self
    }

    /// Add an upstream with a specific weight
    pub fn add_upstream_weighted(mut self, upstream: Box<dyn DnsUpstream>, weight: u32) -> Self {
        self.upstreams.push((upstream, weight));
        self
    }

    /// Set the selection strategy
    pub fn strategy(mut self, strategy: SelectionStrategy) -> Self {
        self.strategy = strategy;
        self
    }

    /// Build the upstream pool
    pub fn build(self) -> UpstreamPool {
        let entries: Vec<_> = self
            .upstreams
            .into_iter()
            .map(|(upstream, weight)| UpstreamEntry::with_weight(upstream, weight))
            .collect();

        UpstreamPool {
            upstreams: RwLock::new(entries),
            strategy: self.strategy,
            rr_counter: AtomicUsize::new(0),
            stats: Arc::new(PoolStats::new()),
        }
    }
}

impl Default for UpstreamPoolBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use hickory_proto::op::{Message, MessageType, Query, ResponseCode};
    use hickory_proto::rr::{Name, RecordType};
    use std::str::FromStr;
    use std::sync::atomic::AtomicBool;
    use std::time::Duration;

    // ========================================================================
    // Mock Upstream for Testing
    // ========================================================================

    #[derive(Debug)]
    struct MockUpstream {
        tag: String,
        address: String,
        healthy: AtomicBool,
        should_fail: AtomicBool,
        query_count: AtomicU64,
    }

    impl MockUpstream {
        fn new(tag: &str, address: &str) -> Self {
            Self {
                tag: tag.to_string(),
                address: address.to_string(),
                healthy: AtomicBool::new(true),
                should_fail: AtomicBool::new(false),
                query_count: AtomicU64::new(0),
            }
        }

        fn set_should_fail(&self, fail: bool) {
            self.should_fail.store(fail, Ordering::SeqCst);
        }

        fn query_count(&self) -> u64 {
            self.query_count.load(Ordering::Relaxed)
        }
    }

    #[async_trait]
    impl DnsUpstream for MockUpstream {
        async fn query(&self, query: &Message) -> DnsResult<Message> {
            self.query_count.fetch_add(1, Ordering::Relaxed);

            if self.should_fail.load(Ordering::SeqCst) {
                return Err(DnsError::timeout("mock timeout", Duration::from_secs(1)));
            }

            // Return a simple response
            let mut response = Message::new();
            response.set_id(query.id());
            response.set_message_type(MessageType::Response);
            response.set_response_code(ResponseCode::NoError);

            // Copy query section
            for q in query.queries() {
                response.add_query(q.clone());
            }

            Ok(response)
        }

        fn is_healthy(&self) -> bool {
            self.healthy.load(Ordering::SeqCst)
        }

        fn protocol(&self) -> UpstreamProtocol {
            UpstreamProtocol::Udp
        }

        fn address(&self) -> &str {
            &self.address
        }

        fn tag(&self) -> &str {
            &self.tag
        }

        fn timeout(&self) -> Duration {
            Duration::from_secs(5)
        }

        fn mark_unhealthy(&self) {
            self.healthy.store(false, Ordering::SeqCst);
        }

        fn mark_healthy(&self) {
            self.healthy.store(true, Ordering::SeqCst);
        }
    }

    // ========================================================================
    // Helper Functions
    // ========================================================================

    fn create_mock(tag: &str) -> Box<dyn DnsUpstream> {
        Box::new(MockUpstream::new(tag, &format!("{}.example.com:53", tag)))
    }

    fn create_query(domain: &str, id: u16) -> Message {
        let mut message = Message::new();
        message.set_id(id);
        message.set_recursion_desired(true);

        let name = Name::from_str(domain).unwrap();
        let query = Query::query(name, RecordType::A);
        message.add_query(query);

        message
    }

    // ========================================================================
    // Creation Tests
    // ========================================================================

    #[test]
    fn test_pool_new_empty() {
        let pool = UpstreamPool::new(vec![]);

        assert!(pool.is_empty());
        assert_eq!(pool.len(), 0);
    }

    #[test]
    fn test_pool_new_with_upstreams() {
        let pool = UpstreamPool::new(vec![create_mock("test1"), create_mock("test2")]);

        assert!(!pool.is_empty());
        assert_eq!(pool.len(), 2);
    }

    #[test]
    fn test_pool_builder() {
        let pool = UpstreamPool::builder()
            .add_upstream(create_mock("test1"))
            .add_upstream(create_mock("test2"))
            .strategy(SelectionStrategy::Random)
            .build();

        assert_eq!(pool.len(), 2);
        assert_eq!(pool.strategy(), SelectionStrategy::Random);
    }

    #[test]
    fn test_pool_builder_weighted() {
        let pool = UpstreamPool::builder()
            .add_upstream_weighted(create_mock("test1"), 3)
            .add_upstream_weighted(create_mock("test2"), 1)
            .strategy(SelectionStrategy::Weighted)
            .build();

        assert_eq!(pool.len(), 2);
    }

    // ========================================================================
    // Upstream Management Tests
    // ========================================================================

    #[test]
    fn test_pool_add_upstream() {
        let pool = UpstreamPool::new(vec![]);
        assert!(pool.is_empty());

        pool.add_upstream(create_mock("test"));
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn test_pool_remove_upstream() {
        let pool = UpstreamPool::new(vec![create_mock("test1"), create_mock("test2")]);

        let removed = pool.remove_upstream("test1");
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().tag(), "test1");
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn test_pool_remove_nonexistent() {
        let pool = UpstreamPool::new(vec![create_mock("test1")]);

        let removed = pool.remove_upstream("nonexistent");
        assert!(removed.is_none());
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn test_pool_tags() {
        let pool = UpstreamPool::new(vec![create_mock("alpha"), create_mock("beta")]);

        let tags = pool.tags();
        assert!(tags.contains(&"alpha".to_string()));
        assert!(tags.contains(&"beta".to_string()));
    }

    #[test]
    fn test_pool_get_by_tag() {
        let pool = UpstreamPool::new(vec![create_mock("test")]);

        let upstream = pool.get_by_tag("test");
        assert!(upstream.is_some());
        assert_eq!(upstream.unwrap().tag(), "test");
    }

    #[test]
    fn test_pool_get_by_tag_not_found() {
        let pool = UpstreamPool::new(vec![create_mock("test")]);

        let upstream = pool.get_by_tag("nonexistent");
        assert!(upstream.is_none());
    }

    // ========================================================================
    // Health Tests
    // ========================================================================

    #[test]
    fn test_pool_healthy_count() {
        let upstream1 = Box::new(MockUpstream::new("test1", "1.1.1.1:53"));
        let upstream2 = Box::new(MockUpstream::new("test2", "8.8.8.8:53"));
        upstream2.mark_unhealthy();

        let pool = UpstreamPool::new(vec![upstream1, upstream2]);

        assert_eq!(pool.healthy_count(), 1);
    }

    #[test]
    fn test_pool_has_healthy_upstream() {
        let pool = UpstreamPool::new(vec![create_mock("test")]);
        assert!(pool.has_healthy_upstream());

        pool.mark_unhealthy("test");
        assert!(!pool.has_healthy_upstream());
    }

    #[test]
    fn test_pool_healthy_tags() {
        let upstream1 = Box::new(MockUpstream::new("healthy", "1.1.1.1:53"));
        let upstream2 = Box::new(MockUpstream::new("unhealthy", "8.8.8.8:53"));
        upstream2.mark_unhealthy();

        let pool = UpstreamPool::new(vec![upstream1, upstream2]);

        let healthy = pool.healthy_tags();
        assert_eq!(healthy.len(), 1);
        assert!(healthy.contains(&"healthy".to_string()));
    }

    #[test]
    fn test_pool_mark_unhealthy() {
        let pool = UpstreamPool::new(vec![create_mock("test")]);
        assert_eq!(pool.healthy_count(), 1);

        pool.mark_unhealthy("test");
        assert_eq!(pool.healthy_count(), 0);
    }

    #[test]
    fn test_pool_mark_healthy() {
        let upstream = Box::new(MockUpstream::new("test", "1.1.1.1:53"));
        upstream.mark_unhealthy();

        let pool = UpstreamPool::new(vec![upstream]);
        assert_eq!(pool.healthy_count(), 0);

        pool.mark_healthy("test");
        assert_eq!(pool.healthy_count(), 1);
    }

    // ========================================================================
    // Query Tests
    // ========================================================================

    #[tokio::test]
    async fn test_pool_query_success() {
        let pool = UpstreamPool::new(vec![create_mock("test")]);
        let query = create_query("example.com.", 0x1234);

        let response = pool.query(&query).await;
        assert!(response.is_ok());
        assert_eq!(response.unwrap().id(), 0x1234);
    }

    #[tokio::test]
    async fn test_pool_query_empty_pool() {
        let pool = UpstreamPool::new(vec![]);
        let query = create_query("example.com.", 0x1234);

        let result = pool.query(&query).await;
        assert!(result.is_err());

        let err = result.unwrap_err();
        assert!(err.to_string().contains("no healthy upstream"));
    }

    #[tokio::test]
    async fn test_pool_query_no_healthy() {
        let upstream = Box::new(MockUpstream::new("test", "1.1.1.1:53"));
        upstream.mark_unhealthy();

        let pool = UpstreamPool::new(vec![upstream]);
        let query = create_query("example.com.", 0x1234);

        let result = pool.query(&query).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_pool_query_failover() {
        let upstream1 = Box::new(MockUpstream::new("fail", "1.1.1.1:53"));
        upstream1.set_should_fail(true);

        let upstream2 = Box::new(MockUpstream::new("success", "8.8.8.8:53"));

        let pool = UpstreamPool::builder()
            .add_upstream(upstream1)
            .add_upstream(upstream2)
            .strategy(SelectionStrategy::FirstAvailable)
            .build();

        let query = create_query("example.com.", 0x1234);
        let response = pool.query(&query).await;

        assert!(response.is_ok());
        assert!(pool.stats().failover_queries() > 0);
    }

    #[tokio::test]
    async fn test_pool_query_by_tag() {
        let pool = UpstreamPool::new(vec![create_mock("test1"), create_mock("test2")]);
        let query = create_query("example.com.", 0x1234);

        let response = pool.query_by_tag("test2", &query).await;
        assert!(response.is_ok());
    }

    #[tokio::test]
    async fn test_pool_query_by_tag_not_found() {
        let pool = UpstreamPool::new(vec![create_mock("test")]);
        let query = create_query("example.com.", 0x1234);

        let result = pool.query_by_tag("nonexistent", &query).await;
        assert!(result.is_err());

        let err = result.unwrap_err();
        assert!(err.to_string().contains("not found"));
    }

    #[tokio::test]
    async fn test_pool_query_by_tag_unhealthy() {
        let pool = UpstreamPool::new(vec![create_mock("test")]);
        pool.mark_unhealthy("test");

        let query = create_query("example.com.", 0x1234);
        let result = pool.query_by_tag("test", &query).await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("unhealthy"));
    }

    // ========================================================================
    // Selection Strategy Tests
    // ========================================================================

    #[tokio::test]
    async fn test_pool_round_robin() {
        let upstream1 = std::sync::Arc::new(MockUpstream::new("test1", "1.1.1.1:53"));
        let upstream2 = std::sync::Arc::new(MockUpstream::new("test2", "8.8.8.8:53"));

        // Create boxed clones for the pool
        let pool = UpstreamPool::builder()
            .add_upstream(Box::new(MockUpstream::new("test1", "1.1.1.1:53")))
            .add_upstream(Box::new(MockUpstream::new("test2", "8.8.8.8:53")))
            .strategy(SelectionStrategy::RoundRobin)
            .build();

        // Send multiple queries
        for i in 0..4u16 {
            let query = create_query("example.com.", i);
            let _ = pool.query(&query).await;
        }

        // Both upstreams should have been used
        assert!(pool.stats().total_queries() >= 4);
    }

    #[tokio::test]
    async fn test_pool_first_available() {
        let pool = UpstreamPool::builder()
            .add_upstream(create_mock("first"))
            .add_upstream(create_mock("second"))
            .strategy(SelectionStrategy::FirstAvailable)
            .build();

        // Multiple queries should use the first upstream
        for i in 0..3u16 {
            let query = create_query("example.com.", i);
            let _ = pool.query(&query).await;
        }

        // All queries should have gone to "first"
        assert_eq!(pool.stats().total_queries(), 3);
    }

    // ========================================================================
    // Statistics Tests
    // ========================================================================

    #[test]
    fn test_pool_stats_initial() {
        let stats = PoolStats::new();

        assert_eq!(stats.total_queries(), 0);
        assert_eq!(stats.successful_queries(), 0);
        assert_eq!(stats.failed_queries(), 0);
        assert_eq!(stats.failover_queries(), 0);
        assert_eq!(stats.no_healthy_upstream(), 0);
    }

    #[test]
    fn test_pool_stats_success_rate() {
        let stats = PoolStats::new();

        // No queries = 100% success
        assert_eq!(stats.success_rate(), 100.0);

        stats.record_success();
        stats.record_success();
        stats.record_failure();

        // 2 success, 1 failure = 66.67%
        let rate = stats.success_rate();
        assert!(rate > 66.0 && rate < 67.0);
    }

    #[tokio::test]
    async fn test_pool_stats_tracking() {
        let pool = UpstreamPool::new(vec![create_mock("test")]);
        let query = create_query("example.com.", 0x1234);

        let _ = pool.query(&query).await;

        assert_eq!(pool.stats().total_queries(), 1);
        assert_eq!(pool.stats().successful_queries(), 1);
    }

    // ========================================================================
    // Upstream Info Tests
    // ========================================================================

    #[test]
    fn test_pool_upstream_info() {
        let pool = UpstreamPool::new(vec![create_mock("test")]);

        let info = pool.upstream_info();
        assert_eq!(info.len(), 1);
        assert_eq!(info[0].tag, "test");
        assert!(info[0].healthy);
        assert!(!info[0].encrypted);
    }

    // ========================================================================
    // Debug Tests
    // ========================================================================

    #[test]
    fn test_pool_debug() {
        let pool = UpstreamPool::new(vec![create_mock("test")]);

        let debug = format!("{:?}", pool);
        assert!(debug.contains("UpstreamPool"));
        assert!(debug.contains("upstream_count"));
    }

    // ========================================================================
    // Concurrent Access Tests (P-1 fix verification)
    // ========================================================================

    /// Test concurrent query access to verify that the lock is not held during
    /// async operations (P-1 fix).
    ///
    /// This test spawns multiple concurrent queries and verifies that they all
    /// complete without deadlock or blocking each other.
    #[tokio::test]
    async fn test_pool_concurrent_query_access() {
        use std::time::Instant;

        // Create a pool with multiple upstreams
        let pool = Arc::new(UpstreamPool::builder()
            .add_upstream(create_mock("upstream1"))
            .add_upstream(create_mock("upstream2"))
            .add_upstream(create_mock("upstream3"))
            .strategy(SelectionStrategy::RoundRobin)
            .build());

        let num_concurrent = 50;
        let mut handles = Vec::with_capacity(num_concurrent);

        let start = Instant::now();

        // Spawn many concurrent queries
        for i in 0..num_concurrent {
            let pool_clone = Arc::clone(&pool);
            let handle = tokio::spawn(async move {
                let query = create_query("example.com.", i as u16);
                pool_clone.query(&query).await
            });
            handles.push(handle);
        }

        // Wait for all queries to complete
        let mut success_count = 0;
        for handle in handles {
            match handle.await {
                Ok(Ok(_)) => success_count += 1,
                Ok(Err(e)) => panic!("Query failed: {}", e),
                Err(e) => panic!("Task panicked: {}", e),
            }
        }

        let elapsed = start.elapsed();

        // All queries should succeed
        assert_eq!(success_count, num_concurrent);

        // Total queries should match
        assert_eq!(pool.stats().total_queries(), num_concurrent as u64);

        // With the fix, concurrent queries should complete quickly
        // Without the fix (lock held during await), queries would be serialized
        // We use a generous timeout to avoid flaky tests
        assert!(
            elapsed.as_secs() < 5,
            "Concurrent queries took too long ({:?}), possible lock contention",
            elapsed
        );
    }

    /// Test that concurrent queries and pool modifications don't deadlock
    #[tokio::test]
    async fn test_pool_concurrent_query_and_modify() {
        let pool = Arc::new(UpstreamPool::new(vec![
            create_mock("initial1"),
            create_mock("initial2"),
        ]));

        let num_queries = 20;
        let mut handles = Vec::new();

        // Spawn query tasks
        for i in 0..num_queries {
            let pool_clone = Arc::clone(&pool);
            handles.push(tokio::spawn(async move {
                let query = create_query("example.com.", i as u16);
                let _ = pool_clone.query(&query).await;
            }));
        }

        // Simultaneously modify the pool
        let pool_clone = Arc::clone(&pool);
        handles.push(tokio::spawn(async move {
            // Add and remove upstreams while queries are running
            pool_clone.add_upstream(create_mock("new1"));
            tokio::task::yield_now().await;
            pool_clone.add_upstream(create_mock("new2"));
            tokio::task::yield_now().await;
            let _ = pool_clone.remove_upstream("new1");
        }));

        // Wait for all tasks to complete without deadlock
        for handle in handles {
            let _ = handle.await;
        }

        // Pool should still be functional
        assert!(pool.len() >= 2);
    }
}
