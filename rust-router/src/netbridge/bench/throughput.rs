//! Throughput testing utilities for netbridge
//!
//! This module provides functions and types for measuring throughput
//! performance of netbridge implementations.
//!
//! # Scenarios
//!
//! - **Single TCP**: Single long-lived connection, max throughput
//! - **Concurrent TCP**: Multiple parallel TCP connections
//! - **UDP Stream**: Sustained UDP traffic
//! - **UDP Burst**: High-rate UDP bursts
//!
//! # Example
//!
//! ```ignore
//! use rust_router::netbridge::bench::throughput::{
//!     ThroughputTest, ThroughputConfig, ThroughputResults,
//! };
//!
//! let config = ThroughputConfig::default();
//! let results = ThroughputTest::run_tcp_single(&config).await;
//! println!("Throughput: {} Mbps", results.mbps());
//! ```

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tracing::info;

use super::loopback::{LoopbackTest, LoopbackTestConfig};
use super::{BenchConfig, TrafficPattern};

// =============================================================================
// ThroughputConfig
// =============================================================================

/// Configuration for throughput tests
#[derive(Debug, Clone)]
pub struct ThroughputConfig {
    /// Test duration in seconds
    pub duration_secs: u64,
    /// Number of concurrent connections (for concurrent tests)
    pub concurrency: usize,
    /// Data block size in bytes
    pub block_size: usize,
    /// Target throughput in Mbps (0 = unlimited)
    pub target_mbps: u64,
    /// Whether to measure both directions (bidirectional)
    pub bidirectional: bool,
    /// Warmup duration in seconds (not counted in results)
    pub warmup_secs: u64,
}

impl Default for ThroughputConfig {
    fn default() -> Self {
        Self {
            duration_secs: 10,
            concurrency: 1,
            block_size: 65536,
            target_mbps: 0,
            bidirectional: false,
            warmup_secs: 1,
        }
    }
}

impl ThroughputConfig {
    /// Create a configuration for single connection test
    #[must_use]
    pub fn single_connection() -> Self {
        Self {
            concurrency: 1,
            ..Default::default()
        }
    }

    /// Create a configuration for concurrent connection test
    #[must_use]
    pub fn concurrent(n: usize) -> Self {
        Self {
            concurrency: n,
            ..Default::default()
        }
    }

    /// Create a configuration for quick benchmark
    #[must_use]
    pub fn quick() -> Self {
        Self {
            duration_secs: 2,
            warmup_secs: 0,
            ..Default::default()
        }
    }

    /// Set the test duration
    #[must_use]
    pub fn with_duration(mut self, secs: u64) -> Self {
        self.duration_secs = secs;
        self
    }

    /// Set the block size
    #[must_use]
    pub fn with_block_size(mut self, size: usize) -> Self {
        self.block_size = size;
        self
    }

    /// Enable bidirectional testing
    #[must_use]
    pub fn bidirectional(mut self) -> Self {
        self.bidirectional = true;
        self
    }
}

// =============================================================================
// ThroughputResults
// =============================================================================

/// Results from a throughput test
#[derive(Debug, Clone, Default)]
pub struct ThroughputResults {
    /// Total bytes transferred
    pub bytes_transferred: u64,
    /// Test duration in milliseconds
    pub duration_ms: u64,
    /// Calculated throughput in Mbps
    pub throughput_mbps: f64,
    /// Number of connections used
    pub connections: usize,
    /// Per-connection throughput in Mbps
    pub per_connection_mbps: f64,
    /// Packets sent
    pub packets_sent: u64,
    /// Packets per second
    pub packets_per_second: f64,
    /// Errors encountered
    pub errors: u64,
    /// Goodput (useful data / total data)
    pub goodput_ratio: f64,
}

impl ThroughputResults {
    /// Calculate throughput from bytes and duration
    pub fn calculate(&mut self) {
        if self.duration_ms > 0 {
            // Mbps = (bytes * 8) / (ms * 1000)
            self.throughput_mbps =
                (self.bytes_transferred as f64 * 8.0) / (self.duration_ms as f64 * 1000.0);

            if self.connections > 0 {
                self.per_connection_mbps = self.throughput_mbps / self.connections as f64;
            }

            if self.packets_sent > 0 {
                self.packets_per_second =
                    self.packets_sent as f64 / (self.duration_ms as f64 / 1000.0);
            }
        }
    }

    /// Get throughput in Mbps
    #[must_use]
    pub fn mbps(&self) -> f64 {
        self.throughput_mbps
    }

    /// Get throughput in MB/s
    #[must_use]
    pub fn megabytes_per_second(&self) -> f64 {
        self.throughput_mbps / 8.0
    }

    /// Check if throughput meets target
    #[must_use]
    pub fn meets_target(&self, target_mbps: f64) -> bool {
        self.throughput_mbps >= target_mbps
    }
}

// =============================================================================
// ThroughputTest
// =============================================================================

/// Throughput test runner
pub struct ThroughputTest {
    loopback: LoopbackTest,
}

impl ThroughputTest {
    /// Create a new throughput test
    #[must_use]
    pub fn new() -> Self {
        Self {
            loopback: LoopbackTest::new(),
        }
    }

    /// Create with custom loopback configuration
    #[must_use]
    pub fn with_loopback_config(config: LoopbackTestConfig) -> Self {
        Self {
            loopback: LoopbackTest::with_config(config),
        }
    }

    /// Run a single TCP connection throughput test
    pub async fn run_tcp_single(&self, config: &ThroughputConfig) -> ThroughputResults {
        info!(
            duration_secs = config.duration_secs,
            block_size = config.block_size,
            "Starting single TCP throughput test"
        );

        let bench_config = BenchConfig {
            pattern: TrafficPattern::SingleTcp,
            duration_secs: config.duration_secs,
            target_mbps: config.target_mbps,
            concurrency: 1,
            udp_packet_size: config.block_size,
        };

        let results = self.loopback.run_throughput(&bench_config).await;

        let mut throughput = ThroughputResults {
            bytes_transferred: results.bytes_transferred,
            duration_ms: results.duration_ms,
            connections: 1,
            packets_sent: results.sessions_created,
            errors: results.errors,
            goodput_ratio: 1.0, // Assume all transferred data is useful
            ..Default::default()
        };

        throughput.calculate();

        info!(
            throughput_mbps = %format!("{:.2}", throughput.throughput_mbps),
            bytes = throughput.bytes_transferred,
            duration_ms = throughput.duration_ms,
            "Single TCP throughput test complete"
        );

        throughput
    }

    /// Run concurrent TCP connections throughput test
    pub async fn run_tcp_concurrent(&self, config: &ThroughputConfig) -> ThroughputResults {
        info!(
            duration_secs = config.duration_secs,
            concurrency = config.concurrency,
            "Starting concurrent TCP throughput test"
        );

        let bench_config = BenchConfig {
            pattern: TrafficPattern::ManyShortTcp,
            duration_secs: config.duration_secs,
            target_mbps: config.target_mbps,
            concurrency: config.concurrency,
            udp_packet_size: config.block_size,
        };

        let results = self.loopback.run_throughput(&bench_config).await;

        let mut throughput = ThroughputResults {
            bytes_transferred: results.bytes_transferred,
            duration_ms: results.duration_ms,
            connections: config.concurrency,
            packets_sent: results.sessions_created,
            errors: results.errors,
            goodput_ratio: 1.0,
            ..Default::default()
        };

        throughput.calculate();

        info!(
            throughput_mbps = %format!("{:.2}", throughput.throughput_mbps),
            per_conn_mbps = %format!("{:.2}", throughput.per_connection_mbps),
            connections = throughput.connections,
            "Concurrent TCP throughput test complete"
        );

        throughput
    }

    /// Run UDP stream throughput test
    pub async fn run_udp_stream(&self, config: &ThroughputConfig) -> ThroughputResults {
        info!(
            duration_secs = config.duration_secs,
            block_size = config.block_size,
            "Starting UDP stream throughput test"
        );

        let bench_config = BenchConfig {
            pattern: TrafficPattern::UdpStream,
            duration_secs: config.duration_secs,
            target_mbps: config.target_mbps,
            concurrency: config.concurrency,
            udp_packet_size: config.block_size,
        };

        let results = self.loopback.run_throughput(&bench_config).await;

        let mut throughput = ThroughputResults {
            bytes_transferred: results.bytes_transferred,
            duration_ms: results.duration_ms,
            connections: 1,
            packets_sent: results.sessions_created,
            errors: results.errors,
            goodput_ratio: 1.0,
            ..Default::default()
        };

        throughput.calculate();

        info!(
            throughput_mbps = %format!("{:.2}", throughput.throughput_mbps),
            pps = %format!("{:.0}", throughput.packets_per_second),
            "UDP stream throughput test complete"
        );

        throughput
    }

    /// Run DNS-like UDP throughput test (small packets, high rate)
    pub async fn run_udp_dns_like(&self, config: &ThroughputConfig) -> ThroughputResults {
        info!(
            duration_secs = config.duration_secs,
            "Starting DNS-like UDP throughput test"
        );

        let bench_config = BenchConfig {
            pattern: TrafficPattern::DnsLikeUdp,
            duration_secs: config.duration_secs,
            target_mbps: config.target_mbps,
            concurrency: config.concurrency,
            udp_packet_size: 64, // DNS-like small packets
        };

        let results = self.loopback.run_throughput(&bench_config).await;

        let mut throughput = ThroughputResults {
            bytes_transferred: results.bytes_transferred,
            duration_ms: results.duration_ms,
            connections: 1,
            packets_sent: results.sessions_created,
            errors: results.errors,
            goodput_ratio: 1.0,
            ..Default::default()
        };

        throughput.calculate();

        info!(
            throughput_mbps = %format!("{:.2}", throughput.throughput_mbps),
            pps = %format!("{:.0}", throughput.packets_per_second),
            "DNS-like UDP throughput test complete"
        );

        throughput
    }

    /// Run mixed TCP/UDP throughput test
    pub async fn run_mixed(&self, config: &ThroughputConfig) -> ThroughputResults {
        info!(
            duration_secs = config.duration_secs,
            "Starting mixed TCP/UDP throughput test"
        );

        let bench_config = BenchConfig {
            pattern: TrafficPattern::Mixed,
            duration_secs: config.duration_secs,
            target_mbps: config.target_mbps,
            concurrency: config.concurrency,
            udp_packet_size: config.block_size,
        };

        let results = self.loopback.run_throughput(&bench_config).await;

        let mut throughput = ThroughputResults {
            bytes_transferred: results.bytes_transferred,
            duration_ms: results.duration_ms,
            connections: config.concurrency,
            packets_sent: results.sessions_created,
            errors: results.errors,
            goodput_ratio: 1.0,
            ..Default::default()
        };

        throughput.calculate();

        info!(
            throughput_mbps = %format!("{:.2}", throughput.throughput_mbps),
            "Mixed TCP/UDP throughput test complete"
        );

        throughput
    }

    /// Run a quick benchmark and return results
    pub async fn run_quick(&self) -> ThroughputResults {
        let config = ThroughputConfig::quick();
        self.run_udp_stream(&config).await
    }
}

impl Default for ThroughputTest {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Throughput Calculator
// =============================================================================

/// Calculator for real-time throughput tracking
#[derive(Debug)]
pub struct ThroughputCalculator {
    /// Start time
    start: Instant,
    /// Total bytes transferred
    bytes: AtomicU64,
    /// Sample history (bytes, timestamp_ms)
    samples: parking_lot::Mutex<Vec<(u64, u64)>>,
    /// Sample interval
    sample_interval_ms: u64,
    /// Last sample time
    last_sample: parking_lot::Mutex<Instant>,
}

impl ThroughputCalculator {
    /// Create a new calculator
    #[must_use]
    pub fn new() -> Self {
        Self {
            start: Instant::now(),
            bytes: AtomicU64::new(0),
            samples: parking_lot::Mutex::new(Vec::new()),
            sample_interval_ms: 100,
            last_sample: parking_lot::Mutex::new(Instant::now()),
        }
    }

    /// Record bytes transferred
    pub fn record(&self, bytes: u64) {
        self.bytes.fetch_add(bytes, Ordering::Relaxed);

        // Take a sample if interval elapsed
        let mut last = self.last_sample.lock();
        if last.elapsed().as_millis() >= self.sample_interval_ms as u128 {
            let total = self.bytes.load(Ordering::Relaxed);
            let elapsed_ms = self.start.elapsed().as_millis() as u64;

            let mut samples = self.samples.lock();
            samples.push((total, elapsed_ms));

            // Keep only last 100 samples
            if samples.len() > 100 {
                samples.remove(0);
            }

            *last = Instant::now();
        }
    }

    /// Get current throughput in Mbps
    #[must_use]
    pub fn current_mbps(&self) -> f64 {
        let samples = self.samples.lock();
        if samples.len() < 2 {
            return 0.0;
        }

        let (bytes1, time1) = samples[samples.len() - 2];
        let (bytes2, time2) = samples[samples.len() - 1];

        let bytes_diff = bytes2 - bytes1;
        let time_diff = time2 - time1;

        if time_diff > 0 {
            (bytes_diff as f64 * 8.0) / (time_diff as f64 * 1000.0)
        } else {
            0.0
        }
    }

    /// Get average throughput in Mbps
    #[must_use]
    pub fn average_mbps(&self) -> f64 {
        let bytes = self.bytes.load(Ordering::Relaxed);
        let elapsed_ms = self.start.elapsed().as_millis() as u64;

        if elapsed_ms > 0 {
            (bytes as f64 * 8.0) / (elapsed_ms as f64 * 1000.0)
        } else {
            0.0
        }
    }

    /// Get total bytes transferred
    #[must_use]
    pub fn total_bytes(&self) -> u64 {
        self.bytes.load(Ordering::Relaxed)
    }

    /// Get elapsed time
    #[must_use]
    pub fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }

    /// Get final results
    #[must_use]
    pub fn results(&self) -> ThroughputResults {
        let mut results = ThroughputResults {
            bytes_transferred: self.bytes.load(Ordering::Relaxed),
            duration_ms: self.start.elapsed().as_millis() as u64,
            connections: 1,
            ..Default::default()
        };
        results.calculate();
        results
    }
}

impl Default for ThroughputCalculator {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_throughput_config_default() {
        let config = ThroughputConfig::default();
        assert_eq!(config.duration_secs, 10);
        assert_eq!(config.concurrency, 1);
        assert_eq!(config.block_size, 65536);
    }

    #[test]
    fn test_throughput_config_single() {
        let config = ThroughputConfig::single_connection();
        assert_eq!(config.concurrency, 1);
    }

    #[test]
    fn test_throughput_config_concurrent() {
        let config = ThroughputConfig::concurrent(4);
        assert_eq!(config.concurrency, 4);
    }

    #[test]
    fn test_throughput_config_quick() {
        let config = ThroughputConfig::quick();
        assert_eq!(config.duration_secs, 2);
        assert_eq!(config.warmup_secs, 0);
    }

    #[test]
    fn test_throughput_results_calculate() {
        let mut results = ThroughputResults {
            bytes_transferred: 125_000_000, // 125 MB
            duration_ms: 1000,               // 1 second
            connections: 1,
            ..Default::default()
        };

        results.calculate();

        // 125 MB/s = 1000 Mbps
        assert!((results.throughput_mbps - 1000.0).abs() < 0.01);
        assert!((results.megabytes_per_second() - 125.0).abs() < 0.01);
    }

    #[test]
    fn test_throughput_results_per_connection() {
        let mut results = ThroughputResults {
            bytes_transferred: 125_000_000,
            duration_ms: 1000,
            connections: 4,
            ..Default::default()
        };

        results.calculate();

        // 1000 Mbps total, 250 Mbps per connection
        assert!((results.per_connection_mbps - 250.0).abs() < 0.01);
    }

    #[test]
    fn test_throughput_results_meets_target() {
        let mut results = ThroughputResults {
            bytes_transferred: 125_000_000,
            duration_ms: 1000,
            connections: 1,
            ..Default::default()
        };
        results.calculate();

        assert!(results.meets_target(500.0));
        assert!(!results.meets_target(2000.0));
    }

    #[test]
    fn test_throughput_calculator_new() {
        let calc = ThroughputCalculator::new();
        assert_eq!(calc.total_bytes(), 0);
    }

    #[test]
    fn test_throughput_calculator_record() {
        let calc = ThroughputCalculator::new();

        calc.record(1000);
        assert_eq!(calc.total_bytes(), 1000);

        calc.record(500);
        assert_eq!(calc.total_bytes(), 1500);
    }

    #[test]
    fn test_throughput_calculator_results() {
        let calc = ThroughputCalculator::new();
        calc.record(125_000);

        // Wait a bit for duration
        std::thread::sleep(Duration::from_millis(10));

        let results = calc.results();
        assert!(results.bytes_transferred >= 125_000);
        assert!(results.duration_ms >= 10);
    }

    #[tokio::test]
    async fn test_throughput_test_new() {
        let _test = ThroughputTest::new();
        // Just verify it creates successfully
        assert!(true);
    }

    #[tokio::test]
    async fn test_throughput_test_quick() {
        let test = ThroughputTest::new();
        let results = test.run_quick().await;

        // Basic sanity checks
        assert!(results.duration_ms > 0);
        // Throughput may be low in test environment
    }
}
