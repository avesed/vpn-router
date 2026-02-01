//! Benchmarking utilities for netbridge
//!
//! This module provides comprehensive benchmarking tools for measuring
//! netbridge performance, including throughput, latency, and session
//! creation rate tests.
//!
//! # Key Features
//!
//! - **Loopback Testing**: Pure in-memory testing without network dependencies
//! - **Throughput Tests**: TCP and UDP throughput measurement
//! - **Latency Tests**: RTT and percentile latency analysis
//! - **Report Generation**: JSON, Markdown, and human-readable reports
//!
//! # Target Performance
//!
//! The netbridge module aims to achieve:
//! - **Throughput**: 500+ Mbps (TCP and UDP)
//! - **Latency**: Sub-millisecond P99 for UDP
//! - **Session Rate**: 10,000+ sessions/second
//!
//! # Quick Start
//!
//! ```ignore
//! use rust_router::netbridge::bench::{
//!     run_benchmark, run_full_suite, BenchConfig, TrafficPattern,
//! };
//!
//! // Quick benchmark
//! let results = run_benchmark(BenchConfig::default()).await;
//! println!("Throughput: {} Mbps", results.throughput_mbps);
//!
//! // Full test suite
//! let all_results = run_full_suite().await;
//! for result in all_results {
//!     println!("{}: {} Mbps", result.0, result.1.throughput_mbps);
//! }
//! ```
//!
//! # Modules
//!
//! - [`loopback`]: In-memory loopback testing
//! - [`throughput`]: Throughput measurement utilities
//! - [`latency`]: Latency measurement utilities
//! - [`report`]: Report generation utilities
//!
//! # Testing Without Network
//!
//! The [`loopback::LoopbackTest`] allows testing netbridge performance
//! without any real network setup. Egress packets are transformed by
//! a mock responder and fed back as replies, creating a closed loop.
//!
//! ```ignore
//! use rust_router::netbridge::bench::loopback::LoopbackTest;
//!
//! let test = LoopbackTest::new();
//! let results = test.run_throughput(&config).await;
//! ```

pub mod latency;
pub mod loopback;
pub mod report;
pub mod throughput;

// Re-export key types
pub use latency::{LatencyConfig, LatencyHistogram, LatencyRecorder, LatencyResults, LatencyTest};
pub use loopback::{LoopbackTest, LoopbackTestConfig, MockResponder};
pub use report::{BenchmarkReport, ReportFormat};
pub use throughput::{ThroughputCalculator, ThroughputConfig, ThroughputResults, ThroughputTest};

// =============================================================================
// Traffic Patterns
// =============================================================================

/// Traffic pattern for benchmarking
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrafficPattern {
    /// Single long-lived TCP connection
    SingleTcp,
    /// Many short TCP connections
    ManyShortTcp,
    /// Sustained UDP stream
    UdpStream,
    /// DNS-like UDP (small packets, many sessions)
    DnsLikeUdp,
    /// Mixed TCP and UDP
    Mixed,
}

impl std::fmt::Display for TrafficPattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SingleTcp => write!(f, "single_tcp"),
            Self::ManyShortTcp => write!(f, "many_short_tcp"),
            Self::UdpStream => write!(f, "udp_stream"),
            Self::DnsLikeUdp => write!(f, "dns_like_udp"),
            Self::Mixed => write!(f, "mixed"),
        }
    }
}

// =============================================================================
// Benchmark Configuration
// =============================================================================

/// Benchmark configuration
#[derive(Debug, Clone)]
pub struct BenchConfig {
    /// Traffic pattern to generate
    pub pattern: TrafficPattern,
    /// Duration in seconds
    pub duration_secs: u64,
    /// Target throughput in Mbps (0 = unlimited)
    pub target_mbps: u64,
    /// Number of concurrent connections
    pub concurrency: usize,
    /// Packet size for UDP
    pub udp_packet_size: usize,
}

impl Default for BenchConfig {
    fn default() -> Self {
        Self {
            pattern: TrafficPattern::SingleTcp,
            duration_secs: 10,
            target_mbps: 0,
            concurrency: 1,
            udp_packet_size: 1400,
        }
    }
}

impl BenchConfig {
    /// Create a quick benchmark configuration
    #[must_use]
    pub fn quick() -> Self {
        Self {
            duration_secs: 2,
            ..Default::default()
        }
    }

    /// Create a configuration for throughput testing
    #[must_use]
    pub fn for_throughput() -> Self {
        Self {
            pattern: TrafficPattern::SingleTcp,
            duration_secs: 10,
            target_mbps: 0,
            concurrency: 1,
            udp_packet_size: 65536,
        }
    }

    /// Create a configuration for latency testing
    #[must_use]
    pub fn for_latency() -> Self {
        Self {
            pattern: TrafficPattern::DnsLikeUdp,
            duration_secs: 5,
            target_mbps: 0,
            concurrency: 1,
            udp_packet_size: 64,
        }
    }

    /// Create a configuration for stress testing
    #[must_use]
    pub fn for_stress() -> Self {
        Self {
            pattern: TrafficPattern::Mixed,
            duration_secs: 30,
            target_mbps: 0,
            concurrency: 10,
            udp_packet_size: 1400,
        }
    }

    /// Set the traffic pattern
    #[must_use]
    pub fn with_pattern(mut self, pattern: TrafficPattern) -> Self {
        self.pattern = pattern;
        self
    }

    /// Set the duration
    #[must_use]
    pub fn with_duration(mut self, secs: u64) -> Self {
        self.duration_secs = secs;
        self
    }

    /// Set the concurrency
    #[must_use]
    pub fn with_concurrency(mut self, n: usize) -> Self {
        self.concurrency = n;
        self
    }
}

// =============================================================================
// Benchmark Results
// =============================================================================

/// Benchmark results
#[derive(Debug, Clone, Default)]
pub struct BenchResults {
    /// Total bytes transferred
    pub bytes_transferred: u64,
    /// Duration in milliseconds
    pub duration_ms: u64,
    /// Average throughput in Mbps
    pub throughput_mbps: f64,
    /// Average latency in microseconds
    pub avg_latency_us: u64,
    /// P99 latency in microseconds
    pub p99_latency_us: u64,
    /// Total sessions created
    pub sessions_created: u64,
    /// Sessions per second
    pub sessions_per_second: f64,
    /// Errors encountered
    pub errors: u64,
}

impl BenchResults {
    /// Calculate throughput from bytes and duration
    pub fn calculate_throughput(&mut self) {
        if self.duration_ms > 0 {
            self.throughput_mbps =
                (self.bytes_transferred as f64 * 8.0) / (self.duration_ms as f64 * 1000.0);
        }
    }

    /// Calculate sessions per second
    pub fn calculate_session_rate(&mut self) {
        if self.duration_ms > 0 {
            self.sessions_per_second =
                self.sessions_created as f64 / (self.duration_ms as f64 / 1000.0);
        }
    }

    /// Check if throughput meets target
    #[must_use]
    pub fn meets_throughput_target(&self, target_mbps: f64) -> bool {
        self.throughput_mbps >= target_mbps
    }

    /// Check if latency meets target
    #[must_use]
    pub fn meets_latency_target(&self, target_p99_us: u64) -> bool {
        self.p99_latency_us <= target_p99_us
    }

    /// Get a human-readable summary
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "Throughput: {:.2} Mbps, Latency P99: {} us, Sessions: {}/s, Errors: {}",
            self.throughput_mbps,
            self.p99_latency_us,
            self.sessions_per_second as u64,
            self.errors
        )
    }
}

// =============================================================================
// Main API Functions
// =============================================================================

/// Run a single benchmark with the given configuration
///
/// This is the main entry point for running benchmarks.
///
/// # Arguments
///
/// * `config` - Benchmark configuration
///
/// # Returns
///
/// Benchmark results including throughput, latency, and error counts.
///
/// # Example
///
/// ```ignore
/// use rust_router::netbridge::bench::{run_benchmark, BenchConfig, TrafficPattern};
///
/// let config = BenchConfig {
///     pattern: TrafficPattern::UdpStream,
///     duration_secs: 10,
///     ..Default::default()
/// };
///
/// let results = run_benchmark(config).await;
/// println!("Throughput: {} Mbps", results.throughput_mbps);
/// ```
pub async fn run_benchmark(config: BenchConfig) -> BenchResults {
    let test = LoopbackTest::new();
    test.run_throughput(&config).await
}

/// Run a quick benchmark using default settings
///
/// Useful for quick sanity checks. Runs for 2 seconds with UDP traffic.
pub async fn run_quick_benchmark() -> BenchResults {
    let test = LoopbackTest::new();
    test.run_quick_benchmark().await
}

/// Run the full benchmark suite
///
/// Runs all benchmark scenarios and returns results for each.
///
/// # Returns
///
/// A vector of (test_name, results) pairs.
///
/// # Example
///
/// ```ignore
/// let results = run_full_suite().await;
/// for (name, result) in results {
///     println!("{}: {} Mbps", name, result.throughput_mbps);
/// }
/// ```
pub async fn run_full_suite() -> Vec<(String, BenchResults)> {
    let mut results = Vec::new();
    let test = LoopbackTest::new();

    // Single TCP throughput
    let tcp_single = BenchConfig {
        pattern: TrafficPattern::SingleTcp,
        duration_secs: 5,
        ..Default::default()
    };
    results.push(("tcp_single".to_string(), test.run_throughput(&tcp_single).await));

    // Concurrent TCP
    let tcp_concurrent = BenchConfig {
        pattern: TrafficPattern::ManyShortTcp,
        duration_secs: 5,
        concurrency: 4,
        ..Default::default()
    };
    results.push(("tcp_concurrent".to_string(), test.run_throughput(&tcp_concurrent).await));

    // UDP stream
    let udp_stream = BenchConfig {
        pattern: TrafficPattern::UdpStream,
        duration_secs: 5,
        udp_packet_size: 1400,
        ..Default::default()
    };
    results.push(("udp_stream".to_string(), test.run_throughput(&udp_stream).await));

    // DNS-like UDP
    let dns_udp = BenchConfig {
        pattern: TrafficPattern::DnsLikeUdp,
        duration_secs: 5,
        udp_packet_size: 64,
        ..Default::default()
    };
    results.push(("dns_like_udp".to_string(), test.run_throughput(&dns_udp).await));

    // Mixed traffic
    let mixed = BenchConfig {
        pattern: TrafficPattern::Mixed,
        duration_secs: 5,
        concurrency: 2,
        ..Default::default()
    };
    results.push(("mixed".to_string(), test.run_throughput(&mixed).await));

    // Latency test
    let latency_config = BenchConfig::for_latency();
    results.push(("latency".to_string(), test.run_latency(&latency_config).await));

    results
}

/// Run benchmarks and generate a report
///
/// Runs the full benchmark suite and generates a comprehensive report.
///
/// # Arguments
///
/// * `name` - Report name/identifier
///
/// # Returns
///
/// A `BenchmarkReport` containing all results and analysis.
pub async fn run_benchmarks_with_report(name: &str) -> BenchmarkReport {
    let mut report = BenchmarkReport::new(name);

    // Run throughput tests
    let throughput_test = ThroughputTest::new();

    let tcp_single = throughput_test
        .run_tcp_single(&ThroughputConfig::single_connection().with_duration(5))
        .await;
    report.add_throughput_with_desc(
        "tcp_single",
        "Single TCP connection throughput",
        tcp_single.clone(),
    );

    let tcp_concurrent = throughput_test
        .run_tcp_concurrent(&ThroughputConfig::concurrent(4).with_duration(5))
        .await;
    report.add_throughput_with_desc(
        "tcp_concurrent",
        "4 concurrent TCP connections",
        tcp_concurrent.clone(),
    );

    let udp_stream = throughput_test
        .run_udp_stream(&ThroughputConfig::default().with_duration(5))
        .await;
    report.add_throughput_with_desc(
        "udp_stream",
        "Sustained UDP stream throughput",
        udp_stream.clone(),
    );

    // Run latency tests
    let latency_test = LatencyTest::new();

    let udp_latency = latency_test.run_udp_rtt(&LatencyConfig::quick()).await;
    report.add_latency_with_desc("udp_rtt", "UDP round-trip time", udp_latency.clone());

    // Add performance targets
    report.add_target(
        "throughput_500mbps",
        "Minimum throughput target",
        500.0,
        tcp_single.throughput_mbps.max(udp_stream.throughput_mbps),
        "Mbps",
        true,
    );

    report.add_target(
        "latency_1ms_p99",
        "Maximum P99 latency target",
        1000.0,
        udp_latency.p99_us as f64,
        "us",
        false,
    );

    report
}

// =============================================================================
// Performance Targets
// =============================================================================

/// Performance target definitions
pub mod targets {
    /// Minimum throughput target in Mbps
    pub const THROUGHPUT_MBPS: f64 = 500.0;

    /// Maximum P99 latency target in microseconds
    pub const LATENCY_P99_US: u64 = 1000;

    /// Minimum session creation rate per second
    pub const SESSIONS_PER_SECOND: f64 = 10000.0;

    /// Check if throughput meets target
    #[must_use]
    pub fn throughput_ok(mbps: f64) -> bool {
        mbps >= THROUGHPUT_MBPS
    }

    /// Check if latency meets target
    #[must_use]
    pub fn latency_ok(p99_us: u64) -> bool {
        p99_us <= LATENCY_P99_US
    }

    /// Check if session rate meets target
    #[must_use]
    pub fn sessions_ok(rate: f64) -> bool {
        rate >= SESSIONS_PER_SECOND
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bench_config_default() {
        let config = BenchConfig::default();
        assert_eq!(config.pattern, TrafficPattern::SingleTcp);
        assert_eq!(config.duration_secs, 10);
        assert_eq!(config.concurrency, 1);
    }

    #[test]
    fn test_bench_config_quick() {
        let config = BenchConfig::quick();
        assert_eq!(config.duration_secs, 2);
    }

    #[test]
    fn test_bench_config_for_throughput() {
        let config = BenchConfig::for_throughput();
        assert_eq!(config.pattern, TrafficPattern::SingleTcp);
        assert_eq!(config.udp_packet_size, 65536);
    }

    #[test]
    fn test_bench_config_for_latency() {
        let config = BenchConfig::for_latency();
        assert_eq!(config.pattern, TrafficPattern::DnsLikeUdp);
        assert_eq!(config.udp_packet_size, 64);
    }

    #[test]
    fn test_bench_config_builder() {
        let config = BenchConfig::default()
            .with_pattern(TrafficPattern::UdpStream)
            .with_duration(20)
            .with_concurrency(4);

        assert_eq!(config.pattern, TrafficPattern::UdpStream);
        assert_eq!(config.duration_secs, 20);
        assert_eq!(config.concurrency, 4);
    }

    #[test]
    fn test_bench_results_throughput() {
        let mut results = BenchResults {
            bytes_transferred: 125_000_000, // 125 MB
            duration_ms: 1000,              // 1 second
            ..Default::default()
        };

        results.calculate_throughput();

        // 125 MB/s = 1000 Mbps
        assert!((results.throughput_mbps - 1000.0).abs() < 0.01);
    }

    #[test]
    fn test_bench_results_session_rate() {
        let mut results = BenchResults {
            sessions_created: 10000,
            duration_ms: 1000,
            ..Default::default()
        };

        results.calculate_session_rate();

        assert!((results.sessions_per_second - 10000.0).abs() < 0.01);
    }

    #[test]
    fn test_bench_results_meets_target() {
        let mut results = BenchResults::default();
        results.throughput_mbps = 600.0;
        results.p99_latency_us = 500;

        assert!(results.meets_throughput_target(500.0));
        assert!(!results.meets_throughput_target(700.0));
        assert!(results.meets_latency_target(1000));
        assert!(!results.meets_latency_target(100));
    }

    #[test]
    fn test_bench_results_summary() {
        let results = BenchResults {
            throughput_mbps: 500.0,
            p99_latency_us: 100,
            sessions_per_second: 1000.0,
            errors: 5,
            ..Default::default()
        };

        let summary = results.summary();
        assert!(summary.contains("500"));
        assert!(summary.contains("100"));
    }

    #[test]
    fn test_traffic_pattern_display() {
        assert_eq!(format!("{}", TrafficPattern::SingleTcp), "single_tcp");
        assert_eq!(format!("{}", TrafficPattern::UdpStream), "udp_stream");
    }

    #[test]
    fn test_targets() {
        assert!(targets::throughput_ok(600.0));
        assert!(!targets::throughput_ok(400.0));

        assert!(targets::latency_ok(500));
        assert!(!targets::latency_ok(2000));

        assert!(targets::sessions_ok(15000.0));
        assert!(!targets::sessions_ok(5000.0));
    }

    #[tokio::test]
    async fn test_run_quick_benchmark() {
        let results = run_quick_benchmark().await;

        // Basic sanity checks
        assert!(results.duration_ms > 0);
        // Note: Throughput may be low in testing environment
    }

    #[tokio::test]
    async fn test_run_benchmark() {
        let config = BenchConfig::quick().with_pattern(TrafficPattern::UdpStream);
        let results = run_benchmark(config).await;

        assert!(results.duration_ms > 0);
    }
}
