//! ECMP Traffic Testing Infrastructure
//!
//! This module provides infrastructure for testing ECMP load balancing algorithms
//! with simulated traffic patterns. It includes mock outbounds, traffic generators,
//! and result analysis utilities.
//!
//! # Overview
//!
//! - [`MockTrafficOutbound`]: Tracks connections per member for verification
//! - [`EcmpTrafficGenerator`]: Generates test traffic with configurable patterns
//! - [`EcmpTrafficResults`]: Statistics and distribution analysis
//!
//! # Example
//!
//! ```
//! use rust_router::ecmp::traffic_test::{
//!     MockTrafficOutbound, EcmpTrafficGenerator, TrafficPattern,
//! };
//! use rust_router::ecmp::{EcmpGroup, EcmpGroupConfig, EcmpMember, LbAlgorithm};
//!
//! // Create a group with round-robin algorithm
//! let config = EcmpGroupConfig {
//!     tag: "test-group".to_string(),
//!     members: vec![
//!         EcmpMember::new("member-0".to_string()),
//!         EcmpMember::new("member-1".to_string()),
//!         EcmpMember::new("member-2".to_string()),
//!     ],
//!     algorithm: LbAlgorithm::RoundRobin,
//!     ..Default::default()
//! };
//! let group = EcmpGroup::new(config).unwrap();
//!
//! // Create traffic generator and run test
//! let mut generator = EcmpTrafficGenerator::new(&group);
//! let results = generator.run_round_robin_test(1000);
//!
//! // Verify even distribution (within 5% tolerance)
//! assert!(results.is_evenly_distributed(0.05));
//! ```

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crate::ecmp::lb::{DestKey, FiveTuple, Protocol};
use crate::ecmp::{EcmpGroup, EcmpGroupConfig, EcmpMember, LbAlgorithm};

/// Default number of iterations for traffic tests
pub const DEFAULT_ITERATIONS: usize = 10_000;

/// Default tolerance for distribution checks (5%)
pub const DEFAULT_TOLERANCE: f64 = 0.05;

/// Weighted tolerance for distribution checks (10%)
pub const WEIGHTED_TOLERANCE: f64 = 0.10;

// =============================================================================
// MockTrafficOutbound
// =============================================================================

/// Mock outbound that tracks connection counts per member.
///
/// This is used for testing ECMP algorithms without actual network traffic.
/// It maintains atomic counters for thread-safe concurrent testing.
#[derive(Debug)]
pub struct MockTrafficOutbound {
    /// Member tag
    pub tag: String,
    /// Total connections routed to this member
    connections: AtomicU64,
    /// Bytes transferred (simulated)
    bytes: AtomicU64,
    /// Whether this outbound is healthy
    healthy: AtomicU64, // Using u64 for AtomicBool semantics (0=unhealthy, 1=healthy)
}

impl MockTrafficOutbound {
    /// Create a new mock outbound
    #[must_use]
    pub fn new(tag: String) -> Self {
        Self {
            tag,
            connections: AtomicU64::new(0),
            bytes: AtomicU64::new(0),
            healthy: AtomicU64::new(1), // healthy by default
        }
    }

    /// Record a connection to this outbound
    pub fn record_connection(&self) {
        self.connections.fetch_add(1, Ordering::Relaxed);
    }

    /// Record bytes transferred
    pub fn record_bytes(&self, bytes: u64) {
        self.bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Get total connection count
    #[must_use]
    pub fn connection_count(&self) -> u64 {
        self.connections.load(Ordering::Relaxed)
    }

    /// Get total bytes transferred
    #[must_use]
    pub fn bytes_transferred(&self) -> u64 {
        self.bytes.load(Ordering::Relaxed)
    }

    /// Check if healthy
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::Relaxed) != 0
    }

    /// Set health status
    pub fn set_healthy(&self, healthy: bool) {
        self.healthy
            .store(if healthy { 1 } else { 0 }, Ordering::Relaxed);
    }

    /// Reset counters
    pub fn reset(&self) {
        self.connections.store(0, Ordering::Relaxed);
        self.bytes.store(0, Ordering::Relaxed);
    }
}

impl Clone for MockTrafficOutbound {
    fn clone(&self) -> Self {
        Self {
            tag: self.tag.clone(),
            connections: AtomicU64::new(self.connections.load(Ordering::Relaxed)),
            bytes: AtomicU64::new(self.bytes.load(Ordering::Relaxed)),
            healthy: AtomicU64::new(self.healthy.load(Ordering::Relaxed)),
        }
    }
}

// =============================================================================
// Traffic Pattern
// =============================================================================

/// Traffic pattern for testing
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrafficPattern {
    /// Sequential source ports (simulates connections from single client)
    SequentialPorts,
    /// Random source ports
    RandomPorts,
    /// Fixed source port (same 5-tuple)
    FixedPort,
    /// Multiple clients (different source IPs)
    MultipleClients,
    /// Multiple destinations (different domains)
    MultipleDomains,
    /// Mixed traffic pattern
    Mixed,
}

impl Default for TrafficPattern {
    fn default() -> Self {
        Self::SequentialPorts
    }
}

// =============================================================================
// EcmpTrafficGenerator
// =============================================================================

/// Generates test traffic for ECMP algorithm verification.
///
/// The generator creates mock connections and routes them through
/// an ECMP group, tracking which member handles each connection.
pub struct EcmpTrafficGenerator<'a> {
    /// The ECMP group under test
    group: &'a EcmpGroup,
    /// Mock outbounds for tracking
    outbounds: HashMap<String, Arc<MockTrafficOutbound>>,
    /// Base source IP for generated traffic
    source_ip: IpAddr,
    /// Base destination IP for generated traffic
    dest_ip: IpAddr,
    /// Base source port
    base_port: u16,
    /// Destination port
    dest_port: u16,
    /// Current iteration counter
    iteration: u64,
}

impl<'a> EcmpTrafficGenerator<'a> {
    /// Create a new traffic generator for an ECMP group
    #[must_use]
    pub fn new(group: &'a EcmpGroup) -> Self {
        let mut outbounds = HashMap::new();
        for tag in group.member_tags() {
            outbounds.insert(tag.clone(), Arc::new(MockTrafficOutbound::new(tag)));
        }

        Self {
            group,
            outbounds,
            source_ip: "10.0.0.1".parse().unwrap(),
            dest_ip: "8.8.8.8".parse().unwrap(),
            base_port: 10000,
            dest_port: 443,
            iteration: 0,
        }
    }

    /// Set the base source IP
    #[must_use]
    pub fn with_source_ip(mut self, ip: IpAddr) -> Self {
        self.source_ip = ip;
        self
    }

    /// Set the base destination IP
    #[must_use]
    pub fn with_dest_ip(mut self, ip: IpAddr) -> Self {
        self.dest_ip = ip;
        self
    }

    /// Get mock outbound by tag
    #[must_use]
    pub fn get_outbound(&self, tag: &str) -> Option<Arc<MockTrafficOutbound>> {
        self.outbounds.get(tag).cloned()
    }

    /// Get all mock outbounds
    #[must_use]
    pub fn outbounds(&self) -> &HashMap<String, Arc<MockTrafficOutbound>> {
        &self.outbounds
    }

    /// Reset all counters
    pub fn reset(&mut self) {
        for outbound in self.outbounds.values() {
            outbound.reset();
        }
        self.iteration = 0;
    }

    /// Generate a five-tuple for testing
    #[must_use]
    pub fn generate_five_tuple(&mut self, pattern: TrafficPattern) -> FiveTuple {
        self.iteration += 1;

        let src_port = match pattern {
            TrafficPattern::FixedPort => self.base_port,
            TrafficPattern::SequentialPorts => self.base_port + (self.iteration as u16 % 50000),
            TrafficPattern::RandomPorts => {
                // Pseudo-random using xorshift
                let mut x = self.iteration;
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x % 50000) as u16 + self.base_port
            }
            TrafficPattern::MultipleClients | TrafficPattern::MultipleDomains => {
                self.base_port + (self.iteration as u16 % 50000)
            }
            TrafficPattern::Mixed => {
                if self.iteration % 3 == 0 {
                    self.base_port
                } else {
                    self.base_port + (self.iteration as u16 % 50000)
                }
            }
        };

        let src_ip = match pattern {
            TrafficPattern::MultipleClients => {
                let octet = (self.iteration % 254 + 1) as u8;
                format!("10.0.0.{}", octet).parse().unwrap()
            }
            _ => self.source_ip,
        };

        FiveTuple::new(src_ip, self.dest_ip, src_port, self.dest_port, Protocol::Tcp)
    }

    /// Generate a destination key for testing
    #[must_use]
    pub fn generate_dest_key(&mut self, pattern: TrafficPattern) -> DestKey {
        self.iteration += 1;

        let src_ip = match pattern {
            TrafficPattern::MultipleClients => {
                let octet = (self.iteration % 254 + 1) as u8;
                format!("10.0.0.{}", octet).parse().unwrap()
            }
            _ => self.source_ip,
        };

        let domain = match pattern {
            TrafficPattern::MultipleDomains => {
                let domains = [
                    "youtube.com",
                    "netflix.com",
                    "twitch.tv",
                    "amazon.com",
                    "google.com",
                    "facebook.com",
                    "twitter.com",
                    "github.com",
                ];
                Some(domains[(self.iteration as usize) % domains.len()])
            }
            TrafficPattern::FixedPort => Some("example.com"),
            _ => None,
        };

        DestKey::new(src_ip, domain, self.dest_ip)
    }

    /// Run round-robin traffic test
    pub fn run_round_robin_test(&mut self, iterations: usize) -> EcmpTrafficResults {
        self.reset();

        for _ in 0..iterations {
            if let Ok(member) = self.group.next_member() {
                if let Some(outbound) = self.outbounds.get(&member) {
                    outbound.record_connection();
                }
            }
        }

        self.collect_results(iterations)
    }

    /// Run five-tuple hash traffic test
    pub fn run_five_tuple_test(
        &mut self,
        iterations: usize,
        pattern: TrafficPattern,
    ) -> EcmpTrafficResults {
        self.reset();

        for _ in 0..iterations {
            let tuple = self.generate_five_tuple(pattern);
            if let Ok(member) = self.group.select_by_connection(&tuple) {
                if let Some(outbound) = self.outbounds.get(&member) {
                    outbound.record_connection();
                }
            }
        }

        self.collect_results(iterations)
    }

    /// Run weighted traffic test
    pub fn run_weighted_test(&mut self, iterations: usize) -> EcmpTrafficResults {
        self.reset();

        for _ in 0..iterations {
            if let Ok(member) = self.group.next_member() {
                if let Some(outbound) = self.outbounds.get(&member) {
                    outbound.record_connection();
                }
            }
        }

        self.collect_results(iterations)
    }

    /// Run least-connections traffic test
    pub fn run_least_connections_test(&mut self, iterations: usize) -> EcmpTrafficResults {
        self.reset();

        for _ in 0..iterations {
            if let Ok(member) = self.group.next_member() {
                if let Some(outbound) = self.outbounds.get(&member) {
                    outbound.record_connection();
                }
                // Simulate connection tracking
                let _ = self.group.increment_connections(&member);
            }
        }

        self.collect_results(iterations)
    }

    /// Run destination hash traffic test
    pub fn run_dest_hash_test(
        &mut self,
        iterations: usize,
        pattern: TrafficPattern,
    ) -> EcmpTrafficResults {
        self.reset();

        for _ in 0..iterations {
            let key = self.generate_dest_key(pattern);
            if let Ok(member) = self.group.select_by_dest(&key) {
                if let Some(outbound) = self.outbounds.get(&member) {
                    outbound.record_connection();
                }
            }
        }

        self.collect_results(iterations)
    }

    /// Run Ketama consistent hash test
    pub fn run_ketama_test(&mut self, iterations: usize) -> EcmpTrafficResults {
        self.reset();

        for i in 0..iterations {
            let key = format!("key-{}", i);
            if let Ok(member) = self.group.select_ketama(&key) {
                if let Some(outbound) = self.outbounds.get(&member) {
                    outbound.record_connection();
                }
            }
        }

        self.collect_results(iterations)
    }

    /// Collect results from mock outbounds
    fn collect_results(&self, total_iterations: usize) -> EcmpTrafficResults {
        let mut member_counts: HashMap<String, u64> = HashMap::new();

        for (tag, outbound) in &self.outbounds {
            member_counts.insert(tag.clone(), outbound.connection_count());
        }

        let total_connections: u64 = member_counts.values().sum();
        let member_count = member_counts.len();

        // Calculate expected distribution (assuming equal weights for simple case)
        let expected_per_member = if member_count > 0 {
            total_connections as f64 / member_count as f64
        } else {
            0.0
        };

        // Calculate variance
        let variance: f64 = if member_count > 0 {
            let mean = expected_per_member;
            let sum_sq_diff: f64 = member_counts
                .values()
                .map(|&count| {
                    let diff = count as f64 - mean;
                    diff * diff
                })
                .sum();
            sum_sq_diff / member_count as f64
        } else {
            0.0
        };

        EcmpTrafficResults {
            total_iterations,
            total_connections,
            member_counts,
            expected_per_member,
            variance,
            std_dev: variance.sqrt(),
        }
    }
}

// =============================================================================
// EcmpTrafficResults
// =============================================================================

/// Results from ECMP traffic testing.
///
/// Contains statistics and analysis methods for verifying
/// load balancing algorithm behavior.
#[derive(Debug, Clone)]
pub struct EcmpTrafficResults {
    /// Total iterations run
    pub total_iterations: usize,
    /// Total connections made
    pub total_connections: u64,
    /// Connection counts per member
    pub member_counts: HashMap<String, u64>,
    /// Expected connections per member (for equal distribution)
    pub expected_per_member: f64,
    /// Variance in distribution
    pub variance: f64,
    /// Standard deviation
    pub std_dev: f64,
}

impl EcmpTrafficResults {
    /// Check if traffic is evenly distributed within tolerance.
    ///
    /// # Arguments
    ///
    /// * `tolerance` - Maximum allowed deviation from expected (e.g., 0.05 for 5%)
    ///
    /// # Returns
    ///
    /// `true` if all members are within tolerance of expected distribution.
    #[must_use]
    pub fn is_evenly_distributed(&self, tolerance: f64) -> bool {
        if self.expected_per_member == 0.0 {
            return self.member_counts.is_empty();
        }

        let min_expected = self.expected_per_member * (1.0 - tolerance);
        let max_expected = self.expected_per_member * (1.0 + tolerance);

        self.member_counts
            .values()
            .all(|&count| count as f64 >= min_expected && count as f64 <= max_expected)
    }

    /// Check if distribution matches expected weights.
    ///
    /// # Arguments
    ///
    /// * `weights` - Expected weights per member (tag -> weight)
    /// * `tolerance` - Maximum allowed deviation (e.g., 0.10 for 10%)
    ///
    /// # Returns
    ///
    /// `true` if all members are within tolerance of their weighted expectation.
    #[must_use]
    pub fn matches_weights(&self, weights: &HashMap<String, u32>, tolerance: f64) -> bool {
        let total_weight: u32 = weights.values().sum();
        if total_weight == 0 {
            return self.member_counts.is_empty();
        }

        for (tag, &count) in &self.member_counts {
            let weight = weights.get(tag).copied().unwrap_or(1);
            let expected_ratio = weight as f64 / total_weight as f64;
            let _expected_count = self.total_connections as f64 * expected_ratio;
            let actual_ratio = count as f64 / self.total_connections as f64;
            let expected_ratio_normalized = expected_ratio;

            if (actual_ratio - expected_ratio_normalized).abs() > tolerance {
                return false;
            }
        }

        true
    }

    /// Get the coefficient of variation (CV).
    ///
    /// CV = std_dev / mean, a normalized measure of dispersion.
    /// Lower values indicate more even distribution.
    #[must_use]
    pub fn coefficient_of_variation(&self) -> f64 {
        if self.expected_per_member == 0.0 {
            return 0.0;
        }
        self.std_dev / self.expected_per_member
    }

    /// Get the maximum deviation from expected.
    #[must_use]
    pub fn max_deviation(&self) -> f64 {
        if self.expected_per_member == 0.0 {
            return 0.0;
        }

        self.member_counts
            .values()
            .map(|&count| ((count as f64 - self.expected_per_member) / self.expected_per_member).abs())
            .fold(0.0, f64::max)
    }

    /// Get the minimum count across all members.
    #[must_use]
    pub fn min_count(&self) -> u64 {
        self.member_counts.values().copied().min().unwrap_or(0)
    }

    /// Get the maximum count across all members.
    #[must_use]
    pub fn max_count(&self) -> u64 {
        self.member_counts.values().copied().max().unwrap_or(0)
    }

    /// Get count for a specific member.
    #[must_use]
    pub fn get_count(&self, tag: &str) -> u64 {
        self.member_counts.get(tag).copied().unwrap_or(0)
    }

    /// Check if a specific member received zero traffic.
    #[must_use]
    pub fn member_excluded(&self, tag: &str) -> bool {
        self.get_count(tag) == 0
    }

    /// Get a human-readable summary.
    #[must_use]
    pub fn summary(&self) -> String {
        let mut lines = vec![
            format!("Total iterations: {}", self.total_iterations),
            format!("Total connections: {}", self.total_connections),
            format!("Expected per member: {:.2}", self.expected_per_member),
            format!("Std deviation: {:.2}", self.std_dev),
            format!("CV: {:.4}", self.coefficient_of_variation()),
            format!("Max deviation: {:.2}%", self.max_deviation() * 100.0),
            String::new(),
            "Member distribution:".to_string(),
        ];

        let mut sorted: Vec<_> = self.member_counts.iter().collect();
        sorted.sort_by_key(|(tag, _)| *tag);

        for (tag, count) in sorted {
            let pct = if self.total_connections > 0 {
                *count as f64 / self.total_connections as f64 * 100.0
            } else {
                0.0
            };
            lines.push(format!("  {}: {} ({:.2}%)", tag, count, pct));
        }

        lines.join("\n")
    }
}

// =============================================================================
// Test Helper Functions
// =============================================================================

/// Create an ECMP group with the specified number of members.
#[must_use]
pub fn create_test_group(member_count: usize, algorithm: LbAlgorithm) -> EcmpGroup {
    let members: Vec<EcmpMember> = (0..member_count)
        .map(|i| EcmpMember::new(format!("member-{}", i)))
        .collect();

    EcmpGroup::new(EcmpGroupConfig {
        tag: "test-group".to_string(),
        members,
        algorithm,
        ..Default::default()
    })
    .expect("Failed to create test group")
}

/// Create an ECMP group with weighted members.
#[must_use]
pub fn create_weighted_group(weights: &[(String, u32)], algorithm: LbAlgorithm) -> EcmpGroup {
    let members: Vec<EcmpMember> = weights
        .iter()
        .map(|(tag, weight)| EcmpMember::with_weight(tag.clone(), *weight))
        .collect();

    EcmpGroup::new(EcmpGroupConfig {
        tag: "weighted-group".to_string(),
        members,
        algorithm,
        ..Default::default()
    })
    .expect("Failed to create weighted group")
}

/// Verify five-tuple affinity: same tuple should always select same member.
pub fn verify_five_tuple_affinity(group: &EcmpGroup, iterations: usize) -> bool {
    let tuple = FiveTuple::new(
        "10.0.0.1".parse().unwrap(),
        "8.8.8.8".parse().unwrap(),
        12345,
        443,
        Protocol::Tcp,
    );

    let first = match group.select_by_connection(&tuple) {
        Ok(member) => member,
        Err(_) => return false,
    };

    for _ in 0..iterations {
        match group.select_by_connection(&tuple) {
            Ok(member) if member == first => continue,
            _ => return false,
        }
    }

    true
}

/// Verify destination affinity: same client+domain should select same member.
pub fn verify_dest_affinity(group: &EcmpGroup, iterations: usize) -> bool {
    let key = DestKey::new(
        "10.0.0.1".parse().unwrap(),
        Some("youtube.com"),
        "142.250.185.142".parse().unwrap(),
    );

    let first = match group.select_by_dest(&key) {
        Ok(member) => member,
        Err(_) => return false,
    };

    for _ in 0..iterations {
        // Different CDN IPs should still select same member
        let key = DestKey::new(
            "10.0.0.1".parse().unwrap(),
            Some("youtube.com"),
            format!("142.250.185.{}", 142 + (iterations % 10))
                .parse()
                .unwrap(),
        );

        match group.select_by_dest(&key) {
            Ok(member) if member == first => continue,
            _ => return false,
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_outbound() {
        let outbound = MockTrafficOutbound::new("test".to_string());

        assert_eq!(outbound.connection_count(), 0);
        assert!(outbound.is_healthy());

        outbound.record_connection();
        outbound.record_connection();
        assert_eq!(outbound.connection_count(), 2);

        outbound.record_bytes(1000);
        assert_eq!(outbound.bytes_transferred(), 1000);

        outbound.set_healthy(false);
        assert!(!outbound.is_healthy());

        outbound.reset();
        assert_eq!(outbound.connection_count(), 0);
        assert_eq!(outbound.bytes_transferred(), 0);
    }

    #[test]
    fn test_traffic_generator_creation() {
        let group = create_test_group(3, LbAlgorithm::RoundRobin);
        let generator = EcmpTrafficGenerator::new(&group);

        assert_eq!(generator.outbounds().len(), 3);
        assert!(generator.get_outbound("member-0").is_some());
        assert!(generator.get_outbound("member-1").is_some());
        assert!(generator.get_outbound("member-2").is_some());
        assert!(generator.get_outbound("nonexistent").is_none());
    }

    #[test]
    fn test_traffic_results_even_distribution() {
        let mut member_counts = HashMap::new();
        member_counts.insert("m0".to_string(), 333);
        member_counts.insert("m1".to_string(), 334);
        member_counts.insert("m2".to_string(), 333);

        let results = EcmpTrafficResults {
            total_iterations: 1000,
            total_connections: 1000,
            member_counts,
            expected_per_member: 333.33,
            variance: 0.22,
            std_dev: 0.47,
        };

        assert!(results.is_evenly_distributed(0.05));
        assert!(!results.member_excluded("m0"));
    }

    #[test]
    fn test_traffic_results_uneven_distribution() {
        let mut member_counts = HashMap::new();
        member_counts.insert("m0".to_string(), 100);
        member_counts.insert("m1".to_string(), 900);

        let results = EcmpTrafficResults {
            total_iterations: 1000,
            total_connections: 1000,
            member_counts,
            expected_per_member: 500.0,
            variance: 160000.0,
            std_dev: 400.0,
        };

        assert!(!results.is_evenly_distributed(0.05));
    }

    #[test]
    fn test_create_test_group() {
        let group = create_test_group(5, LbAlgorithm::RoundRobin);
        assert_eq!(group.member_count(), 5);
        assert_eq!(group.tag(), "test-group");
    }

    #[test]
    fn test_create_weighted_group() {
        let weights = vec![
            ("heavy".to_string(), 3),
            ("medium".to_string(), 2),
            ("light".to_string(), 1),
        ];
        let group = create_weighted_group(&weights, LbAlgorithm::Weighted);
        assert_eq!(group.member_count(), 3);
    }
}
