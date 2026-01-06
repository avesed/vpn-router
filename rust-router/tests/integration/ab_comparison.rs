//! A/B Comparison Test Framework for rust-router vs sing-box
//!
//! This module provides infrastructure for comparing performance between
//! rust-router and sing-box under identical conditions.
//!
//! # Test Categories
//!
//! - Latency: Connection establishment and request/response times
//! - Throughput: Bytes per second under sustained load
//! - Memory: RSS usage at idle and under load
//! - Connections: Maximum concurrent connection handling
//!
//! # Usage
//!
//! Run with: `cargo test --test integration_tests ab_comparison`
//!
//! For detailed comparison: `cargo test --test integration_tests ab_comparison -- --nocapture`

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

// ============================================================================
// Configuration Constants
// ============================================================================

/// Number of warmup iterations before measurement
const WARMUP_ITERATIONS: usize = 100;

/// Number of measurement iterations for statistical significance
const MEASUREMENT_ITERATIONS: usize = 1000;

/// Number of concurrent workers for load tests
const CONCURRENT_WORKERS: usize = 50;

/// Duration for sustained load tests
const SUSTAINED_LOAD_DURATION: Duration = Duration::from_secs(30);

/// Memory measurement interval
const MEMORY_SAMPLE_INTERVAL: Duration = Duration::from_millis(100);

/// Acceptable performance difference threshold (percentage)
const ACCEPTABLE_DIFF_PERCENT: f64 = 10.0;

/// Minimum acceptable improvement threshold for declaring winner (percentage)
const MIN_IMPROVEMENT_THRESHOLD: f64 = 5.0;

// ============================================================================
// Metric Types
// ============================================================================

/// Statistical summary of a metric
#[derive(Debug, Clone)]
pub struct MetricSummary {
    /// Minimum observed value
    pub min: f64,
    /// Maximum observed value
    pub max: f64,
    /// Arithmetic mean
    pub mean: f64,
    /// Median (p50)
    pub median: f64,
    /// 95th percentile
    pub p95: f64,
    /// 99th percentile
    pub p99: f64,
    /// Standard deviation
    pub std_dev: f64,
    /// Number of samples
    pub count: usize,
}

impl MetricSummary {
    /// Calculate summary statistics from raw samples
    pub fn from_samples(samples: &[f64]) -> Option<Self> {
        if samples.is_empty() {
            return None;
        }

        let mut sorted = samples.to_vec();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

        let count = sorted.len();
        let sum: f64 = sorted.iter().sum();
        let mean = sum / count as f64;

        let median = if count % 2 == 0 {
            (sorted[count / 2 - 1] + sorted[count / 2]) / 2.0
        } else {
            sorted[count / 2]
        };

        // Use ceiling of (P * N) - 1 for standard nearest-rank percentile
        let p95_idx = ((count as f64 * 0.95).ceil() as usize).saturating_sub(1).min(count - 1);
        let p99_idx = ((count as f64 * 0.99).ceil() as usize).saturating_sub(1).min(count - 1);

        let variance: f64 = sorted.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / count as f64;
        let std_dev = variance.sqrt();

        Some(MetricSummary {
            min: sorted[0],
            max: sorted[count - 1],
            mean,
            median,
            p95: sorted[p95_idx],
            p99: sorted[p99_idx],
            std_dev,
            count,
        })
    }
}

impl fmt::Display for MetricSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "mean={:.2}, median={:.2}, p95={:.2}, p99={:.2}, std_dev={:.2}, n={}",
            self.mean, self.median, self.p95, self.p99, self.std_dev, self.count
        )
    }
}

/// Categories of comparison metrics
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MetricCategory {
    /// Connection latency (lower is better)
    Latency,
    /// Throughput in bytes/sec (higher is better)
    Throughput,
    /// Memory usage in KB (lower is better)
    Memory,
    /// Connections per second (higher is better)
    ConnectionRate,
    /// CPU usage percentage (lower is better)
    Cpu,
}

impl MetricCategory {
    /// Returns true if higher values are better for this metric
    pub fn higher_is_better(&self) -> bool {
        matches!(self, MetricCategory::Throughput | MetricCategory::ConnectionRate)
    }
}

impl fmt::Display for MetricCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MetricCategory::Latency => write!(f, "Latency (μs)"),
            MetricCategory::Throughput => write!(f, "Throughput (MB/s)"),
            MetricCategory::Memory => write!(f, "Memory (KB)"),
            MetricCategory::ConnectionRate => write!(f, "Conn/sec"),
            MetricCategory::Cpu => write!(f, "CPU (%)"),
        }
    }
}

/// A/B comparison result for a single metric
#[derive(Debug, Clone)]
pub struct ComparisonResult {
    /// Metric category
    pub category: MetricCategory,
    /// Test name
    pub test_name: String,
    /// rust-router results
    pub rust_router: MetricSummary,
    /// sing-box results
    pub singbox: MetricSummary,
    /// Percentage difference (positive = rust-router better)
    pub diff_percent: f64,
    /// Winner determination
    pub winner: ComparisonWinner,
}

/// Winner of a comparison
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComparisonWinner {
    /// rust-router is significantly better
    RustRouter,
    /// sing-box is significantly better
    SingBox,
    /// Results are within acceptable tolerance
    Tie,
}

impl fmt::Display for ComparisonWinner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ComparisonWinner::RustRouter => write!(f, "rust-router ✓"),
            ComparisonWinner::SingBox => write!(f, "sing-box ✓"),
            ComparisonWinner::Tie => write!(f, "~Tie"),
        }
    }
}

impl ComparisonResult {
    /// Calculate comparison result from two metric summaries
    pub fn new(
        category: MetricCategory,
        test_name: impl Into<String>,
        rust_router: MetricSummary,
        singbox: MetricSummary,
    ) -> Self {
        let diff_percent = if category.higher_is_better() {
            // Higher is better: positive diff means rust-router is better
            ((rust_router.mean - singbox.mean) / singbox.mean) * 100.0
        } else {
            // Lower is better: positive diff means rust-router is better (lower value)
            ((singbox.mean - rust_router.mean) / singbox.mean) * 100.0
        };

        let winner = if diff_percent > MIN_IMPROVEMENT_THRESHOLD {
            ComparisonWinner::RustRouter
        } else if diff_percent < -MIN_IMPROVEMENT_THRESHOLD {
            ComparisonWinner::SingBox
        } else {
            ComparisonWinner::Tie
        };

        ComparisonResult {
            category,
            test_name: test_name.into(),
            rust_router,
            singbox,
            diff_percent,
            winner,
        }
    }

    /// Check if rust-router meets performance targets
    pub fn meets_targets(&self) -> bool {
        // rust-router should not be significantly worse than sing-box
        self.diff_percent > -ACCEPTABLE_DIFF_PERCENT
    }
}

impl fmt::Display for ComparisonResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "┌─ {} - {} ─┐", self.category, self.test_name)?;
        writeln!(f, "│ rust-router: {}", self.rust_router)?;
        writeln!(f, "│ sing-box:    {}", self.singbox)?;
        writeln!(
            f,
            "│ Diff: {:+.1}% | Winner: {}",
            self.diff_percent, self.winner
        )?;
        write!(f, "└──────────────────────────────────────┘")
    }
}

// ============================================================================
// Test Harness
// ============================================================================

/// Router type identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouterType {
    RustRouter,
    SingBox,
}

impl fmt::Display for RouterType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RouterType::RustRouter => write!(f, "rust-router"),
            RouterType::SingBox => write!(f, "sing-box"),
        }
    }
}

/// Configuration for A/B comparison tests
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ABTestConfig {
    /// Number of warmup iterations
    pub warmup_iterations: usize,
    /// Number of measurement iterations
    pub measurement_iterations: usize,
    /// Number of concurrent workers
    pub concurrent_workers: usize,
    /// Duration for sustained load tests
    pub sustained_load_duration: Duration,
    /// Memory sampling interval
    pub memory_sample_interval: Duration,
}

impl Default for ABTestConfig {
    fn default() -> Self {
        ABTestConfig {
            warmup_iterations: WARMUP_ITERATIONS,
            measurement_iterations: MEASUREMENT_ITERATIONS,
            concurrent_workers: CONCURRENT_WORKERS,
            sustained_load_duration: SUSTAINED_LOAD_DURATION,
            memory_sample_interval: MEMORY_SAMPLE_INTERVAL,
        }
    }
}

/// Collector for metric samples during tests
#[derive(Default)]
#[allow(dead_code)]
pub struct MetricCollector {
    samples: Vec<f64>,
}

impl MetricCollector {
    pub fn new() -> Self {
        MetricCollector { samples: Vec::new() }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        MetricCollector {
            samples: Vec::with_capacity(capacity),
        }
    }

    pub fn record(&mut self, value: f64) {
        self.samples.push(value);
    }

    pub fn record_duration(&mut self, duration: Duration) {
        self.samples.push(duration.as_secs_f64() * 1_000_000.0); // Convert to microseconds
    }

    pub fn summarize(&self) -> Option<MetricSummary> {
        MetricSummary::from_samples(&self.samples)
    }

    pub fn len(&self) -> usize {
        self.samples.len()
    }

    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }

    pub fn clear(&mut self) {
        self.samples.clear();
    }
}

/// Thread-safe atomic counter for concurrent metrics
#[derive(Default)]
pub struct AtomicCounter {
    value: AtomicU64,
}

impl AtomicCounter {
    pub fn new() -> Self {
        AtomicCounter {
            value: AtomicU64::new(0),
        }
    }

    pub fn increment(&self) {
        self.value.fetch_add(1, Ordering::Relaxed);
    }

    pub fn add(&self, val: u64) {
        self.value.fetch_add(val, Ordering::Relaxed);
    }

    pub fn get(&self) -> u64 {
        self.value.load(Ordering::Relaxed)
    }

    pub fn reset(&self) -> u64 {
        self.value.swap(0, Ordering::Relaxed)
    }
}

/// Memory usage tracker
pub struct MemoryTracker {
    samples: Vec<usize>,
}

impl MemoryTracker {
    pub fn new() -> Self {
        MemoryTracker {
            samples: Vec::new(),
        }
    }

    /// Record current RSS memory usage
    #[cfg(target_os = "linux")]
    pub fn record_current(&mut self) {
        if let Some(rss) = get_rss_kb() {
            self.samples.push(rss);
        }
    }

    #[cfg(not(target_os = "linux"))]
    pub fn record_current(&mut self) {
        // On non-Linux systems, use a placeholder
        self.samples.push(0);
    }

    pub fn summarize(&self) -> Option<MetricSummary> {
        let float_samples: Vec<f64> = self.samples.iter().map(|&x| x as f64).collect();
        MetricSummary::from_samples(&float_samples)
    }

    pub fn peak(&self) -> usize {
        self.samples.iter().copied().max().unwrap_or(0)
    }

    pub fn average(&self) -> f64 {
        if self.samples.is_empty() {
            0.0
        } else {
            self.samples.iter().sum::<usize>() as f64 / self.samples.len() as f64
        }
    }
}

impl Default for MemoryTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Get current RSS memory usage in KB (Linux only)
#[cfg(target_os = "linux")]
fn get_rss_kb() -> Option<usize> {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|content| {
            for line in content.lines() {
                if line.starts_with("VmRSS:") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        return parts[1].parse().ok();
                    }
                }
            }
            None
        })
}

#[cfg(not(target_os = "linux"))]
fn get_rss_kb() -> Option<usize> {
    None
}

// ============================================================================
// A/B Test Report
// ============================================================================

/// Complete A/B comparison report
#[derive(Default)]
pub struct ABTestReport {
    /// Test configuration used
    pub config: ABTestConfig,
    /// All comparison results
    pub results: Vec<ComparisonResult>,
    /// Overall summary
    pub summary: ReportSummary,
}

/// Summary statistics for the report
#[derive(Default)]
pub struct ReportSummary {
    /// Total tests run
    pub total_tests: usize,
    /// Tests where rust-router won
    pub rust_router_wins: usize,
    /// Tests where sing-box won
    pub singbox_wins: usize,
    /// Tests that were ties
    pub ties: usize,
    /// Tests where rust-router failed to meet targets
    pub failed_targets: usize,
}

impl ABTestReport {
    pub fn new(config: ABTestConfig) -> Self {
        ABTestReport {
            config,
            results: Vec::new(),
            summary: ReportSummary::default(),
        }
    }

    pub fn add_result(&mut self, result: ComparisonResult) {
        self.summary.total_tests += 1;
        match result.winner {
            ComparisonWinner::RustRouter => self.summary.rust_router_wins += 1,
            ComparisonWinner::SingBox => self.summary.singbox_wins += 1,
            ComparisonWinner::Tie => self.summary.ties += 1,
        }
        if !result.meets_targets() {
            self.summary.failed_targets += 1;
        }
        self.results.push(result);
    }

    pub fn is_passing(&self) -> bool {
        self.summary.failed_targets == 0
    }
}

impl fmt::Display for ABTestReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "╔══════════════════════════════════════════════════════════════╗")?;
        writeln!(f, "║              A/B Comparison Test Report                       ║")?;
        writeln!(f, "╠══════════════════════════════════════════════════════════════╣")?;
        writeln!(f, "║ Configuration:                                                ║")?;
        writeln!(f, "║   Warmup iterations:   {:>6}                                 ║", self.config.warmup_iterations)?;
        writeln!(f, "║   Measurement iters:   {:>6}                                 ║", self.config.measurement_iterations)?;
        writeln!(f, "║   Concurrent workers:  {:>6}                                 ║", self.config.concurrent_workers)?;
        writeln!(f, "╠══════════════════════════════════════════════════════════════╣")?;

        for result in &self.results {
            writeln!(f)?;
            writeln!(f, "{}", result)?;
        }

        writeln!(f)?;
        writeln!(f, "╠══════════════════════════════════════════════════════════════╣")?;
        writeln!(f, "║ Summary:                                                      ║")?;
        writeln!(f, "║   Total tests:         {:>6}                                 ║", self.summary.total_tests)?;
        writeln!(f, "║   rust-router wins:    {:>6}                                 ║", self.summary.rust_router_wins)?;
        writeln!(f, "║   sing-box wins:       {:>6}                                 ║", self.summary.singbox_wins)?;
        writeln!(f, "║   Ties:                {:>6}                                 ║", self.summary.ties)?;
        writeln!(f, "║   Failed targets:      {:>6}                                 ║", self.summary.failed_targets)?;
        writeln!(f, "╠══════════════════════════════════════════════════════════════╣")?;

        let status = if self.is_passing() { "PASS ✓" } else { "FAIL ✗" };
        writeln!(f, "║ Overall Result: {:>45} ║", status)?;
        writeln!(f, "╚══════════════════════════════════════════════════════════════╝")
    }
}

// ============================================================================
// Mock Test Implementations (for unit testing the framework)
// ============================================================================

/// Simulate latency measurement for a router
pub fn simulate_latency_test(router: RouterType, iterations: usize) -> MetricCollector {
    let mut collector = MetricCollector::with_capacity(iterations);

    for i in 0..iterations {
        // Simulate realistic latency patterns
        let base_latency = match router {
            RouterType::RustRouter => 50.0 + (i % 10) as f64,  // ~50-60μs
            RouterType::SingBox => 80.0 + (i % 15) as f64,     // ~80-95μs
        };

        // Add some variance
        let variance = ((i * 7) % 20) as f64 - 10.0;
        collector.record(base_latency + variance);
    }

    collector
}

/// Simulate throughput measurement for a router
pub fn simulate_throughput_test(router: RouterType, duration_secs: f64) -> f64 {
    // Simulate throughput in MB/s
    match router {
        RouterType::RustRouter => 850.0 + (duration_secs * 10.0).sin() * 50.0,  // ~800-900 MB/s
        RouterType::SingBox => 720.0 + (duration_secs * 10.0).sin() * 40.0,     // ~680-760 MB/s
    }
}

/// Simulate connection rate test for a router
pub fn simulate_connection_rate(router: RouterType, duration_secs: f64) -> f64 {
    // Simulate connections per second
    match router {
        RouterType::RustRouter => 12500.0 + duration_secs * 100.0,  // ~12.5K/sec
        RouterType::SingBox => 10200.0 + duration_secs * 80.0,      // ~10.2K/sec
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metric_summary_from_samples() {
        let samples = vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0];
        let summary = MetricSummary::from_samples(&samples).unwrap();

        assert_eq!(summary.count, 10);
        assert!((summary.min - 1.0).abs() < f64::EPSILON);
        assert!((summary.max - 10.0).abs() < f64::EPSILON);
        assert!((summary.mean - 5.5).abs() < f64::EPSILON);
        assert!((summary.median - 5.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_metric_summary_empty() {
        let samples: Vec<f64> = vec![];
        assert!(MetricSummary::from_samples(&samples).is_none());
    }

    #[test]
    fn test_comparison_result_higher_is_better() {
        let rust = MetricSummary::from_samples(&vec![100.0, 110.0, 120.0]).unwrap();
        let singbox = MetricSummary::from_samples(&vec![80.0, 90.0, 100.0]).unwrap();

        let result = ComparisonResult::new(
            MetricCategory::Throughput,
            "throughput_test",
            rust,
            singbox,
        );

        // rust-router has higher throughput, should win
        assert_eq!(result.winner, ComparisonWinner::RustRouter);
        assert!(result.diff_percent > 0.0);
    }

    #[test]
    fn test_comparison_result_lower_is_better() {
        let rust = MetricSummary::from_samples(&vec![50.0, 55.0, 60.0]).unwrap();
        let singbox = MetricSummary::from_samples(&vec![80.0, 85.0, 90.0]).unwrap();

        let result = ComparisonResult::new(
            MetricCategory::Latency,
            "latency_test",
            rust,
            singbox,
        );

        // rust-router has lower latency, should win
        assert_eq!(result.winner, ComparisonWinner::RustRouter);
        assert!(result.diff_percent > 0.0);
    }

    #[test]
    fn test_comparison_result_tie() {
        let rust = MetricSummary::from_samples(&vec![100.0, 101.0, 102.0]).unwrap();
        let singbox = MetricSummary::from_samples(&vec![100.0, 100.5, 101.0]).unwrap();

        let result = ComparisonResult::new(
            MetricCategory::Latency,
            "tie_test",
            rust,
            singbox,
        );

        // Within tolerance, should be a tie
        assert_eq!(result.winner, ComparisonWinner::Tie);
    }

    #[test]
    fn test_metric_collector() {
        let mut collector = MetricCollector::new();

        for i in 0..100 {
            collector.record(i as f64);
        }

        assert_eq!(collector.len(), 100);

        let summary = collector.summarize().unwrap();
        assert_eq!(summary.count, 100);
        assert!((summary.mean - 49.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_metric_collector_duration() {
        let mut collector = MetricCollector::new();

        collector.record_duration(Duration::from_micros(100));
        collector.record_duration(Duration::from_micros(200));
        collector.record_duration(Duration::from_micros(300));

        let summary = collector.summarize().unwrap();
        assert_eq!(summary.count, 3);
        assert!((summary.mean - 200.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_atomic_counter() {
        let counter = AtomicCounter::new();

        counter.increment();
        counter.increment();
        counter.add(10);

        assert_eq!(counter.get(), 12);

        let old = counter.reset();
        assert_eq!(old, 12);
        assert_eq!(counter.get(), 0);
    }

    #[test]
    fn test_ab_test_report() {
        let config = ABTestConfig::default();
        let mut report = ABTestReport::new(config);

        // Add some results
        let rust1 = MetricSummary::from_samples(&vec![50.0, 55.0, 60.0]).unwrap();
        let singbox1 = MetricSummary::from_samples(&vec![80.0, 85.0, 90.0]).unwrap();
        report.add_result(ComparisonResult::new(
            MetricCategory::Latency,
            "test1",
            rust1,
            singbox1,
        ));

        let rust2 = MetricSummary::from_samples(&vec![100.0, 110.0, 120.0]).unwrap();
        let singbox2 = MetricSummary::from_samples(&vec![80.0, 90.0, 100.0]).unwrap();
        report.add_result(ComparisonResult::new(
            MetricCategory::Throughput,
            "test2",
            rust2,
            singbox2,
        ));

        assert_eq!(report.summary.total_tests, 2);
        assert_eq!(report.summary.rust_router_wins, 2);
        assert_eq!(report.summary.singbox_wins, 0);
        assert!(report.is_passing());
    }

    #[test]
    fn test_simulate_latency() {
        let rust_collector = simulate_latency_test(RouterType::RustRouter, 100);
        let singbox_collector = simulate_latency_test(RouterType::SingBox, 100);

        let rust_summary = rust_collector.summarize().unwrap();
        let singbox_summary = singbox_collector.summarize().unwrap();

        // rust-router should have lower latency in simulation
        assert!(rust_summary.mean < singbox_summary.mean);
    }

    #[test]
    fn test_report_display() {
        let config = ABTestConfig::default();
        let mut report = ABTestReport::new(config);

        let rust = MetricSummary::from_samples(&vec![50.0, 55.0, 60.0]).unwrap();
        let singbox = MetricSummary::from_samples(&vec![80.0, 85.0, 90.0]).unwrap();
        report.add_result(ComparisonResult::new(
            MetricCategory::Latency,
            "connection_latency",
            rust,
            singbox,
        ));

        let output = format!("{}", report);
        assert!(output.contains("A/B Comparison Test Report"));
        assert!(output.contains("rust-router wins"));
        assert!(output.contains("PASS"));
    }

    #[test]
    fn test_metric_category_higher_is_better() {
        assert!(!MetricCategory::Latency.higher_is_better());
        assert!(!MetricCategory::Memory.higher_is_better());
        assert!(!MetricCategory::Cpu.higher_is_better());
        assert!(MetricCategory::Throughput.higher_is_better());
        assert!(MetricCategory::ConnectionRate.higher_is_better());
    }

    #[test]
    fn test_memory_tracker() {
        let mut tracker = MemoryTracker::new();

        // On non-Linux or without /proc, this may record 0
        tracker.record_current();
        tracker.record_current();
        tracker.record_current();

        // Just verify it doesn't panic
        let _ = tracker.peak();
        let _ = tracker.average();
        let _ = tracker.summarize();
    }

    #[tokio::test]
    async fn test_concurrent_metric_collection() {
        let counter = Arc::new(AtomicCounter::new());
        let mut handles = vec![];

        for _ in 0..10 {
            let counter_clone = Arc::clone(&counter);
            handles.push(tokio::spawn(async move {
                for _ in 0..100 {
                    counter_clone.increment();
                }
            }));
        }

        for handle in handles {
            handle.await.unwrap();
        }

        assert_eq!(counter.get(), 1000);
    }
}

// ============================================================================
// Integration Tests (Framework Verification)
// ============================================================================

#[cfg(test)]
mod integration_tests {
    use super::*;

    /// Verify the A/B comparison framework works end-to-end
    #[test]
    fn test_full_ab_comparison_workflow() {
        let config = ABTestConfig {
            warmup_iterations: 10,
            measurement_iterations: 100,
            concurrent_workers: 4,
            sustained_load_duration: Duration::from_millis(100),
            memory_sample_interval: Duration::from_millis(10),
        };

        let mut report = ABTestReport::new(config.clone());

        // Test 1: Latency comparison
        let rust_latency = simulate_latency_test(RouterType::RustRouter, config.measurement_iterations);
        let singbox_latency = simulate_latency_test(RouterType::SingBox, config.measurement_iterations);

        report.add_result(ComparisonResult::new(
            MetricCategory::Latency,
            "connection_establishment",
            rust_latency.summarize().unwrap(),
            singbox_latency.summarize().unwrap(),
        ));

        // Test 2: Throughput comparison
        let mut rust_throughput = MetricCollector::with_capacity(10);
        let mut singbox_throughput = MetricCollector::with_capacity(10);

        for i in 0..10 {
            rust_throughput.record(simulate_throughput_test(RouterType::RustRouter, i as f64));
            singbox_throughput.record(simulate_throughput_test(RouterType::SingBox, i as f64));
        }

        report.add_result(ComparisonResult::new(
            MetricCategory::Throughput,
            "sustained_transfer",
            rust_throughput.summarize().unwrap(),
            singbox_throughput.summarize().unwrap(),
        ));

        // Test 3: Connection rate comparison
        let mut rust_conn_rate = MetricCollector::with_capacity(10);
        let mut singbox_conn_rate = MetricCollector::with_capacity(10);

        for i in 0..10 {
            rust_conn_rate.record(simulate_connection_rate(RouterType::RustRouter, i as f64));
            singbox_conn_rate.record(simulate_connection_rate(RouterType::SingBox, i as f64));
        }

        report.add_result(ComparisonResult::new(
            MetricCategory::ConnectionRate,
            "connection_accept_rate",
            rust_conn_rate.summarize().unwrap(),
            singbox_conn_rate.summarize().unwrap(),
        ));

        // Verify report
        assert_eq!(report.summary.total_tests, 3);
        assert!(report.is_passing());

        // Print report for visibility
        println!("{}", report);
    }

    /// Test percentile calculation accuracy
    #[test]
    fn test_percentile_accuracy() {
        // Generate 1000 samples with known distribution
        let samples: Vec<f64> = (0..1000).map(|i| i as f64).collect();
        let summary = MetricSummary::from_samples(&samples).unwrap();

        // p95 should be around 950
        assert!(summary.p95 >= 940.0 && summary.p95 <= 960.0);

        // p99 should be around 990
        assert!(summary.p99 >= 980.0 && summary.p99 <= 999.0);
    }

    /// Test standard deviation calculation
    #[test]
    fn test_std_dev_calculation() {
        // Samples with known std dev
        let samples = vec![2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0];
        let summary = MetricSummary::from_samples(&samples).unwrap();

        // Mean should be 5.0
        assert!((summary.mean - 5.0).abs() < f64::EPSILON);

        // Std dev should be 2.0
        assert!((summary.std_dev - 2.0).abs() < 0.01);
    }
}
