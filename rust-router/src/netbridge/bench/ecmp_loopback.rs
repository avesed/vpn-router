//! ECMP Loopback Test Framework Extension
//!
//! This module extends the loopback testing framework to support end-to-end ECMP
//! testing. It allows verification of ECMP load balancing behavior through the
//! full data path, including the control plane and netbridge.
//!
//! # Overview
//!
//! - [`EcmpLoopbackConfig`]: Configuration for ECMP-aware loopback tests
//! - [`EcmpBenchResults`]: ECMP-specific benchmark results with member distribution
//! - [`EcmpLoopbackTest`]: Framework for end-to-end ECMP testing
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │                      EcmpLoopbackTest                               │
//! ├─────────────────────────────────────────────────────────────────────┤
//! │                                                                     │
//! │  Traffic Generator                                                  │
//! │       │                                                             │
//! │       │ Generate test connections                                   │
//! │       ▼                                                             │
//! │  ┌─────────────────────────────────────────────────────────────┐  │
//! │  │                  EcmpGroupManager                            │  │
//! │  │  - Algorithm selection (RoundRobin, FiveTupleHash, etc.)    │  │
//! │  │  - Member tracking                                           │  │
//! │  └─────────────────────────────────────────────────────────────┘  │
//! │       │                                                             │
//! │       │ Route to selected member                                    │
//! │       ▼                                                             │
//! │  ┌─────────────────────────────────────────────────────────────┐  │
//! │  │               MockMemberOutbound[]                           │  │
//! │  │  - Track connections per member                              │  │
//! │  │  - Simulate member health                                    │  │
//! │  └─────────────────────────────────────────────────────────────┘  │
//! │       │                                                             │
//! │       │ Process through loopback                                    │
//! │       ▼                                                             │
//! │   EcmpBenchResults                                                  │
//! │   - Total throughput                                                │
//! │   - Per-member distribution                                         │
//! │   - Algorithm verification                                          │
//! │                                                                     │
//! └─────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Example
//!
//! ```ignore
//! use rust_router::netbridge::bench::ecmp_loopback::{
//!     EcmpLoopbackTest, EcmpLoopbackConfig,
//! };
//! use rust_router::ecmp::LbAlgorithm;
//!
//! // Create test with 4 members using round-robin
//! let config = EcmpLoopbackConfig::new(4)
//!     .with_algorithm(LbAlgorithm::RoundRobin)
//!     .with_iterations(10_000);
//!
//! let test = EcmpLoopbackTest::new(config);
//! let results = test.run().await;
//!
//! // Verify even distribution
//! assert!(results.is_evenly_distributed(0.05));
//! ```

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::ecmp::lb::{DestKey, FiveTuple, Protocol};
use crate::ecmp::{EcmpGroup, EcmpGroupConfig, EcmpGroupManager, EcmpMember, LbAlgorithm};

// =============================================================================
// Configuration
// =============================================================================

/// Configuration for ECMP loopback tests
#[derive(Debug, Clone)]
pub struct EcmpLoopbackConfig {
    /// Number of ECMP members
    pub member_count: usize,
    /// Load balancing algorithm to test
    pub algorithm: LbAlgorithm,
    /// Number of test iterations
    pub iterations: usize,
    /// Duration limit (if reached before iterations complete)
    pub max_duration: Duration,
    /// Weights for weighted algorithms (member_index -> weight)
    pub weights: Option<Vec<u32>>,
    /// Members to mark as unhealthy (for health check testing)
    pub unhealthy_members: Vec<usize>,
    /// Whether to track per-connection latency
    pub track_latency: bool,
    /// Simulate concurrent access
    pub concurrency: usize,
}

impl EcmpLoopbackConfig {
    /// Create a new configuration with the specified number of members
    #[must_use]
    pub fn new(member_count: usize) -> Self {
        Self {
            member_count,
            algorithm: LbAlgorithm::RoundRobin,
            iterations: 10_000,
            max_duration: Duration::from_secs(30),
            weights: None,
            unhealthy_members: Vec::new(),
            track_latency: false,
            concurrency: 1,
        }
    }

    /// Set the load balancing algorithm
    #[must_use]
    pub fn with_algorithm(mut self, algorithm: LbAlgorithm) -> Self {
        self.algorithm = algorithm;
        self
    }

    /// Set the number of iterations
    #[must_use]
    pub fn with_iterations(mut self, iterations: usize) -> Self {
        self.iterations = iterations;
        self
    }

    /// Set the maximum duration
    #[must_use]
    pub fn with_max_duration(mut self, duration: Duration) -> Self {
        self.max_duration = duration;
        self
    }

    /// Set member weights for weighted algorithms
    #[must_use]
    pub fn with_weights(mut self, weights: Vec<u32>) -> Self {
        self.weights = Some(weights);
        self
    }

    /// Mark specific members as unhealthy
    #[must_use]
    pub fn with_unhealthy_members(mut self, members: Vec<usize>) -> Self {
        self.unhealthy_members = members;
        self
    }

    /// Enable latency tracking
    #[must_use]
    pub fn with_latency_tracking(mut self) -> Self {
        self.track_latency = true;
        self
    }

    /// Set concurrency level for parallel testing
    #[must_use]
    pub fn with_concurrency(mut self, concurrency: usize) -> Self {
        self.concurrency = concurrency;
        self
    }

    /// Create a quick test configuration
    #[must_use]
    pub fn quick() -> Self {
        Self::new(4).with_iterations(1000)
    }

    /// Create a stress test configuration
    #[must_use]
    pub fn stress() -> Self {
        Self::new(8)
            .with_iterations(100_000)
            .with_concurrency(4)
            .with_latency_tracking()
    }
}

impl Default for EcmpLoopbackConfig {
    fn default() -> Self {
        Self::new(4)
    }
}

// =============================================================================
// Results
// =============================================================================

/// ECMP-specific benchmark results
#[derive(Debug, Clone)]
pub struct EcmpBenchResults {
    /// Total iterations completed
    pub iterations: u64,
    /// Total duration
    pub duration: Duration,
    /// Selections per second
    pub selections_per_second: f64,
    /// Connection counts per member (tag -> count)
    pub member_counts: HashMap<String, u64>,
    /// Expected count per member (for even distribution)
    pub expected_per_member: f64,
    /// Variance in distribution
    pub variance: f64,
    /// Standard deviation
    pub std_dev: f64,
    /// Errors encountered
    pub errors: u64,
    /// Latency measurements (if enabled)
    pub latencies: Option<LatencyStats>,
    /// Algorithm used
    pub algorithm: LbAlgorithm,
    /// Number of healthy members
    pub healthy_members: usize,
}

impl EcmpBenchResults {
    /// Check if traffic is evenly distributed within tolerance
    ///
    /// # Arguments
    ///
    /// * `tolerance` - Maximum allowed deviation from expected (e.g., 0.05 for 5%)
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

    /// Check if distribution matches expected weights
    #[must_use]
    pub fn matches_weights(&self, weights: &HashMap<String, u32>, tolerance: f64) -> bool {
        let total_weight: u32 = weights.values().sum();
        if total_weight == 0 {
            return self.member_counts.is_empty();
        }

        let total_counts: u64 = self.member_counts.values().sum();

        for (tag, &count) in &self.member_counts {
            let weight = weights.get(tag).copied().unwrap_or(1);
            let expected_ratio = weight as f64 / total_weight as f64;
            let actual_ratio = count as f64 / total_counts as f64;

            if (actual_ratio - expected_ratio).abs() > tolerance {
                return false;
            }
        }

        true
    }

    /// Get coefficient of variation (CV)
    #[must_use]
    pub fn coefficient_of_variation(&self) -> f64 {
        if self.expected_per_member == 0.0 {
            return 0.0;
        }
        self.std_dev / self.expected_per_member
    }

    /// Get maximum deviation from expected
    #[must_use]
    pub fn max_deviation(&self) -> f64 {
        if self.expected_per_member == 0.0 {
            return 0.0;
        }

        self.member_counts
            .values()
            .map(|&count| {
                ((count as f64 - self.expected_per_member) / self.expected_per_member).abs()
            })
            .fold(0.0, f64::max)
    }

    /// Check if a specific member received zero traffic
    #[must_use]
    pub fn member_excluded(&self, tag: &str) -> bool {
        self.member_counts.get(tag).map_or(true, |&c| c == 0)
    }

    /// Get a human-readable summary
    #[must_use]
    pub fn summary(&self) -> String {
        let mut lines = vec![
            format!("Algorithm: {:?}", self.algorithm),
            format!("Iterations: {}", self.iterations),
            format!("Duration: {:?}", self.duration),
            format!("Selections/sec: {:.2}", self.selections_per_second),
            format!("Healthy members: {}", self.healthy_members),
            format!("Max deviation: {:.2}%", self.max_deviation() * 100.0),
            format!("CV: {:.4}", self.coefficient_of_variation()),
            format!("Errors: {}", self.errors),
            String::new(),
            "Member distribution:".to_string(),
        ];

        let mut sorted: Vec<_> = self.member_counts.iter().collect();
        sorted.sort_by_key(|(tag, _)| *tag);

        let total: u64 = self.member_counts.values().sum();
        for (tag, count) in sorted {
            let pct = if total > 0 {
                *count as f64 / total as f64 * 100.0
            } else {
                0.0
            };
            lines.push(format!("  {}: {} ({:.2}%)", tag, count, pct));
        }

        if let Some(ref latencies) = self.latencies {
            lines.push(String::new());
            lines.push("Latency:".to_string());
            lines.push(format!("  Avg: {} us", latencies.avg_us));
            lines.push(format!("  P50: {} us", latencies.p50_us));
            lines.push(format!("  P99: {} us", latencies.p99_us));
            lines.push(format!("  Max: {} us", latencies.max_us));
        }

        lines.join("\n")
    }
}

impl Default for EcmpBenchResults {
    fn default() -> Self {
        Self {
            iterations: 0,
            duration: Duration::ZERO,
            selections_per_second: 0.0,
            member_counts: HashMap::new(),
            expected_per_member: 0.0,
            variance: 0.0,
            std_dev: 0.0,
            errors: 0,
            latencies: None,
            algorithm: LbAlgorithm::RoundRobin,
            healthy_members: 0,
        }
    }
}

/// Latency statistics
#[derive(Debug, Clone, Default)]
pub struct LatencyStats {
    /// Minimum latency in microseconds
    pub min_us: u64,
    /// Maximum latency in microseconds
    pub max_us: u64,
    /// Average latency in microseconds
    pub avg_us: u64,
    /// P50 latency
    pub p50_us: u64,
    /// P95 latency
    pub p95_us: u64,
    /// P99 latency
    pub p99_us: u64,
}

impl LatencyStats {
    /// Calculate statistics from a vector of latencies
    pub fn from_samples(mut samples: Vec<u64>) -> Self {
        if samples.is_empty() {
            return Self::default();
        }

        samples.sort();
        let len = samples.len();

        Self {
            min_us: samples[0],
            max_us: samples[len - 1],
            avg_us: samples.iter().sum::<u64>() / len as u64,
            p50_us: samples[len / 2],
            p95_us: samples[len * 95 / 100],
            p99_us: samples[len * 99 / 100],
        }
    }
}

// =============================================================================
// Mock Member Outbound
// =============================================================================

/// Mock outbound that tracks connections for benchmarking
#[derive(Debug)]
pub struct MockMemberOutbound {
    /// Member tag
    pub tag: String,
    /// Connection count
    connections: AtomicU64,
    /// Bytes processed
    bytes: AtomicU64,
    /// Whether healthy
    healthy: bool,
}

impl MockMemberOutbound {
    /// Create a new mock member outbound
    pub fn new(tag: String) -> Self {
        Self {
            tag,
            connections: AtomicU64::new(0),
            bytes: AtomicU64::new(0),
            healthy: true,
        }
    }

    /// Record a connection
    pub fn record_connection(&self) {
        self.connections.fetch_add(1, Ordering::Relaxed);
    }

    /// Record bytes
    pub fn record_bytes(&self, bytes: u64) {
        self.bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Get connection count
    pub fn connection_count(&self) -> u64 {
        self.connections.load(Ordering::Relaxed)
    }

    /// Get bytes processed
    pub fn bytes_processed(&self) -> u64 {
        self.bytes.load(Ordering::Relaxed)
    }

    /// Set health status
    pub fn set_healthy(&mut self, healthy: bool) {
        self.healthy = healthy;
    }

    /// Check if healthy
    pub fn is_healthy(&self) -> bool {
        self.healthy
    }

    /// Reset counters
    pub fn reset(&self) {
        self.connections.store(0, Ordering::Relaxed);
        self.bytes.store(0, Ordering::Relaxed);
    }
}

// =============================================================================
// ECMP Loopback Test
// =============================================================================

/// Framework for end-to-end ECMP testing through the loopback path
pub struct EcmpLoopbackTest {
    /// Configuration
    config: EcmpLoopbackConfig,
    /// ECMP group manager
    ecmp_manager: Arc<EcmpGroupManager>,
    /// Mock member outbounds
    members: Vec<Arc<MockMemberOutbound>>,
    /// Iteration counter
    iteration: AtomicU64,
}

impl EcmpLoopbackTest {
    /// Create a new ECMP loopback test
    pub fn new(config: EcmpLoopbackConfig) -> Self {
        let ecmp_manager = Arc::new(EcmpGroupManager::new());

        // Create members with optional weights
        let members: Vec<EcmpMember> = (0..config.member_count)
            .map(|i| {
                let weight = config
                    .weights
                    .as_ref()
                    .and_then(|w| w.get(i).copied())
                    .unwrap_or(1);
                EcmpMember::with_weight(format!("member-{}", i), weight)
            })
            .collect();

        // Create ECMP group
        let group_config = EcmpGroupConfig {
            tag: "test-group".to_string(),
            members,
            algorithm: config.algorithm.clone(),
            ..Default::default()
        };

        ecmp_manager
            .add_group(group_config)
            .expect("Failed to create ECMP group");

        // Mark unhealthy members
        if let Some(group) = ecmp_manager.get_group("test-group") {
            for &idx in &config.unhealthy_members {
                let tag = format!("member-{}", idx);
                let _ = group.update_member_health(&tag, false);
            }
        }

        // Create mock outbounds
        let mock_members: Vec<Arc<MockMemberOutbound>> = (0..config.member_count)
            .map(|i| Arc::new(MockMemberOutbound::new(format!("member-{}", i))))
            .collect();

        Self {
            config,
            ecmp_manager,
            members: mock_members,
            iteration: AtomicU64::new(0),
        }
    }

    /// Get the ECMP group
    fn group(&self) -> Option<Arc<EcmpGroup>> {
        self.ecmp_manager.get_group("test-group")
    }

    /// Generate a five-tuple for testing
    fn generate_five_tuple(&self) -> FiveTuple {
        let iteration = self.iteration.fetch_add(1, Ordering::Relaxed);
        let src_port = 10000 + (iteration as u16 % 50000);

        FiveTuple::new(
            "10.0.0.1".parse().unwrap(),
            "8.8.8.8".parse().unwrap(),
            src_port,
            443,
            Protocol::Tcp,
        )
    }

    /// Generate a destination key for testing
    fn generate_dest_key(&self, domain: Option<&str>) -> DestKey {
        let iteration = self.iteration.load(Ordering::Relaxed);
        let src_ip = format!("10.0.0.{}", (iteration % 254 + 1) as u8)
            .parse()
            .unwrap();

        DestKey::new(src_ip, domain, "8.8.8.8".parse().unwrap())
    }

    /// Run the ECMP loopback test
    pub fn run(&self) -> EcmpBenchResults {
        let start = Instant::now();
        let mut errors = 0u64;
        let mut latencies: Vec<u64> = Vec::new();

        let group = match self.group() {
            Some(g) => g,
            None => {
                return EcmpBenchResults {
                    errors: 1,
                    ..Default::default()
                };
            }
        };

        // Reset counters
        for member in &self.members {
            member.reset();
        }
        self.iteration.store(0, Ordering::Relaxed);

        // Run iterations
        let iterations = self.config.iterations;
        for _ in 0..iterations {
            if start.elapsed() > self.config.max_duration {
                break;
            }

            let iter_start = if self.config.track_latency {
                Some(Instant::now())
            } else {
                None
            };

            // Select member based on algorithm
            let member_tag = match self.config.algorithm {
                LbAlgorithm::RoundRobin
                | LbAlgorithm::Weighted
                | LbAlgorithm::LeastConnections
                | LbAlgorithm::Random => group.next_member(),
                LbAlgorithm::FiveTupleHash => {
                    let tuple = self.generate_five_tuple();
                    group.select_by_connection(&tuple)
                }
                LbAlgorithm::DestHash | LbAlgorithm::DestHashLeastLoad => {
                    let key = self.generate_dest_key(Some("example.com"));
                    group.select_by_dest(&key)
                }
                LbAlgorithm::Ketama => {
                    let iteration = self.iteration.load(Ordering::Relaxed);
                    group.select_ketama(&format!("key-{}", iteration))
                }
            };

            match member_tag {
                Ok(tag) => {
                    // Record on mock member
                    if let Some(member) = self.members.iter().find(|m| m.tag == tag) {
                        member.record_connection();
                    }

                    // Track latency
                    if let Some(iter_start) = iter_start {
                        latencies.push(iter_start.elapsed().as_micros() as u64);
                    }
                }
                Err(_) => {
                    errors += 1;
                }
            }
        }

        let duration = start.elapsed();
        let actual_iterations = self.iteration.load(Ordering::Relaxed);

        // Collect results
        let mut member_counts: HashMap<String, u64> = HashMap::new();
        for member in &self.members {
            member_counts.insert(member.tag.clone(), member.connection_count());
        }

        let total_connections: u64 = member_counts.values().sum();
        let healthy_count = self.config.member_count - self.config.unhealthy_members.len();

        let expected_per_member = if healthy_count > 0 {
            total_connections as f64 / healthy_count as f64
        } else {
            0.0
        };

        // Calculate variance
        let variance: f64 = if healthy_count > 0 {
            let mean = expected_per_member;
            let sum_sq_diff: f64 = member_counts
                .iter()
                .filter(|(tag, _)| {
                    // Only include healthy members in variance calculation
                    let idx: usize = tag.trim_start_matches("member-").parse().unwrap_or(0);
                    !self.config.unhealthy_members.contains(&idx)
                })
                .map(|(_, &count)| {
                    let diff = count as f64 - mean;
                    diff * diff
                })
                .sum();
            sum_sq_diff / healthy_count as f64
        } else {
            0.0
        };

        EcmpBenchResults {
            iterations: actual_iterations,
            duration,
            selections_per_second: actual_iterations as f64 / duration.as_secs_f64(),
            member_counts,
            expected_per_member,
            variance,
            std_dev: variance.sqrt(),
            errors,
            latencies: if self.config.track_latency && !latencies.is_empty() {
                Some(LatencyStats::from_samples(latencies))
            } else {
                None
            },
            algorithm: self.config.algorithm.clone(),
            healthy_members: healthy_count,
        }
    }

    /// Run concurrent ECMP test
    pub fn run_concurrent(&self) -> EcmpBenchResults {
        use std::thread;

        let start = Instant::now();
        let errors = Arc::new(AtomicU64::new(0));
        let group = match self.group() {
            Some(g) => g,
            None => {
                return EcmpBenchResults {
                    errors: 1,
                    ..Default::default()
                };
            }
        };

        // Reset counters
        for member in &self.members {
            member.reset();
        }

        let iterations_per_thread = self.config.iterations / self.config.concurrency;

        let handles: Vec<_> = (0..self.config.concurrency)
            .map(|_| {
                let group_clone = group.clone();
                let errors_clone = Arc::clone(&errors);
                let members_clone: Vec<Arc<MockMemberOutbound>> = self.members.iter().cloned().collect();
                let algorithm = self.config.algorithm.clone();

                thread::spawn(move || {
                    let mut iteration = 0u64;

                    for i in 0..iterations_per_thread {
                        iteration = i as u64;

                        let member_tag = match algorithm {
                            LbAlgorithm::RoundRobin
                            | LbAlgorithm::Weighted
                            | LbAlgorithm::LeastConnections
                            | LbAlgorithm::Random => group_clone.next_member(),
                            LbAlgorithm::FiveTupleHash => {
                                let src_port = 10000 + (iteration as u16 % 50000);
                                let tuple = FiveTuple::new(
                                    "10.0.0.1".parse().unwrap(),
                                    "8.8.8.8".parse().unwrap(),
                                    src_port,
                                    443,
                                    Protocol::Tcp,
                                );
                                group_clone.select_by_connection(&tuple)
                            }
                            LbAlgorithm::DestHash | LbAlgorithm::DestHashLeastLoad => {
                                let src_ip = format!("10.0.0.{}", (iteration % 254 + 1) as u8)
                                    .parse()
                                    .unwrap();
                                let key =
                                    DestKey::new(src_ip, Some("example.com"), "8.8.8.8".parse().unwrap());
                                group_clone.select_by_dest(&key)
                            }
                            LbAlgorithm::Ketama => {
                                group_clone.select_ketama(&format!("key-{}", iteration))
                            }
                        };

                        match member_tag {
                            Ok(tag) => {
                                if let Some(member) = members_clone.iter().find(|m| m.tag == tag) {
                                    member.record_connection();
                                }
                            }
                            Err(_) => {
                                errors_clone.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }

                    iteration
                })
            })
            .collect();

        // Wait for all threads
        let total_iterations: u64 = handles.into_iter().map(|h| h.join().unwrap_or(0)).sum();

        let duration = start.elapsed();

        // Collect results
        let mut member_counts: HashMap<String, u64> = HashMap::new();
        for member in &self.members {
            member_counts.insert(member.tag.clone(), member.connection_count());
        }

        let total_connections: u64 = member_counts.values().sum();
        let healthy_count = self.config.member_count - self.config.unhealthy_members.len();

        let expected_per_member = if healthy_count > 0 {
            total_connections as f64 / healthy_count as f64
        } else {
            0.0
        };

        let variance: f64 = if healthy_count > 0 {
            let mean = expected_per_member;
            let sum_sq_diff: f64 = member_counts
                .iter()
                .filter(|(tag, _)| {
                    let idx: usize = tag.trim_start_matches("member-").parse().unwrap_or(0);
                    !self.config.unhealthy_members.contains(&idx)
                })
                .map(|(_, &count)| {
                    let diff = count as f64 - mean;
                    diff * diff
                })
                .sum();
            sum_sq_diff / healthy_count as f64
        } else {
            0.0
        };

        EcmpBenchResults {
            iterations: total_iterations,
            duration,
            selections_per_second: total_connections as f64 / duration.as_secs_f64(),
            member_counts,
            expected_per_member,
            variance,
            std_dev: variance.sqrt(),
            errors: errors.load(Ordering::Relaxed),
            latencies: None,
            algorithm: self.config.algorithm.clone(),
            healthy_members: healthy_count,
        }
    }

    /// Verify five-tuple affinity
    pub fn verify_five_tuple_affinity(&self, iterations: usize) -> bool {
        let group = match self.group() {
            Some(g) => g,
            None => return false,
        };

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

    /// Verify destination affinity
    pub fn verify_dest_affinity(&self, iterations: usize) -> bool {
        let group = match self.group() {
            Some(g) => g,
            None => return false,
        };

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
            // Different CDN IPs
            let key = DestKey::new(
                "10.0.0.1".parse().unwrap(),
                Some("youtube.com"),
                "142.250.185.143".parse().unwrap(),
            );
            match group.select_by_dest(&key) {
                Ok(member) if member == first => continue,
                _ => return false,
            }
        }

        true
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ecmp_loopback_config_default() {
        let config = EcmpLoopbackConfig::default();
        assert_eq!(config.member_count, 4);
        assert_eq!(config.iterations, 10_000);
        assert!(matches!(config.algorithm, LbAlgorithm::RoundRobin));
    }

    #[test]
    fn test_ecmp_loopback_config_builder() {
        let config = EcmpLoopbackConfig::new(8)
            .with_algorithm(LbAlgorithm::FiveTupleHash)
            .with_iterations(5000)
            .with_concurrency(4)
            .with_latency_tracking();

        assert_eq!(config.member_count, 8);
        assert_eq!(config.iterations, 5000);
        assert_eq!(config.concurrency, 4);
        assert!(config.track_latency);
    }

    #[test]
    fn test_ecmp_loopback_round_robin() {
        let config = EcmpLoopbackConfig::new(4)
            .with_algorithm(LbAlgorithm::RoundRobin)
            .with_iterations(1000);

        let test = EcmpLoopbackTest::new(config);
        let results = test.run();

        // Round-robin should be evenly distributed
        assert!(
            results.is_evenly_distributed(0.10),
            "Distribution not even: {:?}",
            results.member_counts
        );
        assert_eq!(results.errors, 0);
    }

    #[test]
    fn test_ecmp_loopback_five_tuple_affinity() {
        let config = EcmpLoopbackConfig::new(4).with_algorithm(LbAlgorithm::FiveTupleHash);

        let test = EcmpLoopbackTest::new(config);

        assert!(
            test.verify_five_tuple_affinity(100),
            "Five-tuple affinity violated"
        );
    }

    #[test]
    fn test_ecmp_loopback_unhealthy_exclusion() {
        let config = EcmpLoopbackConfig::new(4)
            .with_algorithm(LbAlgorithm::RoundRobin)
            .with_iterations(1000)
            .with_unhealthy_members(vec![1, 2]);

        let test = EcmpLoopbackTest::new(config);
        let results = test.run();

        // Members 1 and 2 should receive no traffic
        assert!(
            results.member_excluded("member-1"),
            "Unhealthy member-1 received traffic"
        );
        assert!(
            results.member_excluded("member-2"),
            "Unhealthy member-2 received traffic"
        );

        // Members 0 and 3 should receive traffic
        assert!(
            !results.member_excluded("member-0"),
            "Healthy member-0 excluded"
        );
        assert!(
            !results.member_excluded("member-3"),
            "Healthy member-3 excluded"
        );
    }

    #[test]
    fn test_ecmp_loopback_weighted() {
        let config = EcmpLoopbackConfig::new(3)
            .with_algorithm(LbAlgorithm::Weighted)
            .with_weights(vec![1, 2, 3])
            .with_iterations(6000);

        let test = EcmpLoopbackTest::new(config);
        let results = test.run();

        // Verify weights are approximately respected
        let count_0 = *results.member_counts.get("member-0").unwrap_or(&0);
        let count_1 = *results.member_counts.get("member-1").unwrap_or(&0);
        let count_2 = *results.member_counts.get("member-2").unwrap_or(&0);

        // member-2 (weight 3) should have more than member-1 (weight 2)
        // member-1 (weight 2) should have more than member-0 (weight 1)
        assert!(
            count_2 > count_1,
            "Weight ordering violated: member-2 ({}) should > member-1 ({})",
            count_2,
            count_1
        );
        assert!(
            count_1 > count_0,
            "Weight ordering violated: member-1 ({}) should > member-0 ({})",
            count_1,
            count_0
        );
    }

    #[test]
    fn test_ecmp_bench_results_summary() {
        let mut member_counts = HashMap::new();
        member_counts.insert("member-0".to_string(), 250);
        member_counts.insert("member-1".to_string(), 250);
        member_counts.insert("member-2".to_string(), 250);
        member_counts.insert("member-3".to_string(), 250);

        let results = EcmpBenchResults {
            iterations: 1000,
            duration: Duration::from_secs(1),
            selections_per_second: 1000.0,
            member_counts,
            expected_per_member: 250.0,
            variance: 0.0,
            std_dev: 0.0,
            errors: 0,
            latencies: None,
            algorithm: LbAlgorithm::RoundRobin,
            healthy_members: 4,
        };

        let summary = results.summary();
        assert!(summary.contains("RoundRobin"));
        assert!(summary.contains("member-0"));
        assert!(summary.contains("250"));
    }

    #[test]
    fn test_latency_stats_from_samples() {
        let samples = vec![100, 200, 300, 400, 500, 600, 700, 800, 900, 1000];
        let stats = LatencyStats::from_samples(samples);

        assert_eq!(stats.min_us, 100);
        assert_eq!(stats.max_us, 1000);
        assert_eq!(stats.avg_us, 550);
        // P50 is the middle element: index 10/2 = 5, which is 600
        assert_eq!(stats.p50_us, 600);
    }

    #[test]
    fn test_mock_member_outbound() {
        let member = MockMemberOutbound::new("test".to_string());

        assert_eq!(member.connection_count(), 0);
        assert!(member.is_healthy());

        member.record_connection();
        member.record_connection();
        assert_eq!(member.connection_count(), 2);

        member.record_bytes(1000);
        assert_eq!(member.bytes_processed(), 1000);

        member.reset();
        assert_eq!(member.connection_count(), 0);
        assert_eq!(member.bytes_processed(), 0);
    }

    #[test]
    fn test_ecmp_loopback_concurrent() {
        let config = EcmpLoopbackConfig::new(4)
            .with_algorithm(LbAlgorithm::RoundRobin)
            .with_iterations(4000)
            .with_concurrency(4);

        let test = EcmpLoopbackTest::new(config);
        let results = test.run_concurrent();

        // Should complete without errors
        assert_eq!(results.errors, 0, "Concurrent test had errors");

        // All members should receive some traffic
        for i in 0..4 {
            let tag = format!("member-{}", i);
            assert!(
                !results.member_excluded(&tag),
                "Member {} was excluded in concurrent test",
                i
            );
        }
    }
}
