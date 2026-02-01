//! Benchmark report generation
//!
//! This module provides utilities for generating benchmark reports in
//! various formats including JSON and human-readable text.
//!
//! # Example
//!
//! ```ignore
//! use rust_router::netbridge::bench::report::{BenchmarkReport, ReportFormat};
//! use rust_router::netbridge::bench::throughput::ThroughputResults;
//! use rust_router::netbridge::bench::latency::LatencyResults;
//!
//! let mut report = BenchmarkReport::new("netbridge-performance");
//!
//! report.add_throughput("tcp_single", throughput_results);
//! report.add_latency("udp_rtt", latency_results);
//!
//! // Generate JSON
//! let json = report.to_json();
//!
//! // Generate human-readable
//! let summary = report.to_summary();
//! ```

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use super::latency::LatencyResults;
use super::throughput::ThroughputResults;
use super::BenchResults;

// =============================================================================
// ReportFormat
// =============================================================================

/// Output format for reports
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportFormat {
    /// JSON format
    Json,
    /// Pretty-printed JSON
    JsonPretty,
    /// Human-readable summary
    Summary,
    /// Markdown format
    Markdown,
    /// CSV format
    Csv,
}

// =============================================================================
// BenchmarkReport
// =============================================================================

/// Comprehensive benchmark report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkReport {
    /// Report name/identifier
    pub name: String,
    /// Report version
    pub version: String,
    /// Timestamp (Unix epoch seconds)
    pub timestamp: u64,
    /// System information
    pub system_info: SystemInfo,
    /// Configuration used for benchmarks
    pub config: BenchmarkConfig,
    /// Throughput test results
    pub throughput: HashMap<String, ThroughputReport>,
    /// Latency test results
    pub latency: HashMap<String, LatencyReport>,
    /// General benchmark results
    pub general: HashMap<String, GeneralReport>,
    /// Performance targets and whether they were met
    pub targets: Vec<PerformanceTarget>,
    /// Summary statistics
    pub summary: ReportSummary,
}

/// System information for the report
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SystemInfo {
    /// Operating system
    pub os: String,
    /// CPU architecture
    pub arch: String,
    /// Number of CPU cores
    pub cpu_cores: usize,
    /// Total memory in bytes
    pub memory_bytes: u64,
    /// Rust version
    pub rust_version: String,
}

/// Benchmark configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BenchmarkConfig {
    /// TCP buffer size
    pub tcp_buffer_size: usize,
    /// UDP buffer size
    pub udp_buffer_size: usize,
    /// Maximum sockets
    pub max_sockets: usize,
    /// WireGuard MTU
    pub wg_mtu: usize,
}

/// Throughput report entry
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ThroughputReport {
    /// Test name
    pub name: String,
    /// Description
    pub description: String,
    /// Throughput in Mbps
    pub throughput_mbps: f64,
    /// Per-connection throughput if applicable
    pub per_connection_mbps: Option<f64>,
    /// Bytes transferred
    pub bytes_transferred: u64,
    /// Duration in milliseconds
    pub duration_ms: u64,
    /// Number of connections
    pub connections: usize,
    /// Packets per second
    pub packets_per_second: f64,
    /// Errors
    pub errors: u64,
    /// Pass/fail based on target
    pub passed: Option<bool>,
}

/// Latency report entry
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LatencyReport {
    /// Test name
    pub name: String,
    /// Description
    pub description: String,
    /// Number of samples
    pub samples: usize,
    /// Minimum latency in microseconds
    pub min_us: u64,
    /// Maximum latency in microseconds
    pub max_us: u64,
    /// Average latency in microseconds
    pub avg_us: u64,
    /// P50 latency
    pub p50_us: u64,
    /// P90 latency
    pub p90_us: u64,
    /// P95 latency
    pub p95_us: u64,
    /// P99 latency
    pub p99_us: u64,
    /// P99.9 latency
    pub p999_us: u64,
    /// Standard deviation
    pub stddev_us: u64,
    /// Jitter
    pub jitter_us: u64,
    /// Errors
    pub errors: u64,
    /// Pass/fail based on target
    pub passed: Option<bool>,
}

/// General benchmark report entry
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GeneralReport {
    /// Test name
    pub name: String,
    /// Description
    pub description: String,
    /// Bytes transferred
    pub bytes_transferred: u64,
    /// Duration in milliseconds
    pub duration_ms: u64,
    /// Throughput in Mbps
    pub throughput_mbps: f64,
    /// Average latency in microseconds
    pub avg_latency_us: u64,
    /// P99 latency in microseconds
    pub p99_latency_us: u64,
    /// Sessions created
    pub sessions_created: u64,
    /// Sessions per second
    pub sessions_per_second: f64,
    /// Errors
    pub errors: u64,
}

/// Performance target
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceTarget {
    /// Target name
    pub name: String,
    /// Target description
    pub description: String,
    /// Target value
    pub target_value: f64,
    /// Unit (e.g., "Mbps", "us")
    pub unit: String,
    /// Actual measured value
    pub actual_value: f64,
    /// Whether the target was met
    pub met: bool,
}

/// Summary of the benchmark report
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReportSummary {
    /// Total tests run
    pub total_tests: usize,
    /// Tests passed
    pub tests_passed: usize,
    /// Tests failed
    pub tests_failed: usize,
    /// Total bytes transferred across all tests
    pub total_bytes: u64,
    /// Total duration across all tests
    pub total_duration_ms: u64,
    /// Peak throughput observed
    pub peak_throughput_mbps: f64,
    /// Best P99 latency
    pub best_p99_latency_us: u64,
    /// Overall status
    pub status: String,
}

impl BenchmarkReport {
    /// Create a new benchmark report
    #[must_use]
    pub fn new(name: &str) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        Self {
            name: name.to_string(),
            version: "1.0.0".to_string(),
            timestamp,
            system_info: Self::collect_system_info(),
            config: Self::collect_config(),
            throughput: HashMap::new(),
            latency: HashMap::new(),
            general: HashMap::new(),
            targets: Vec::new(),
            summary: ReportSummary::default(),
        }
    }

    /// Collect system information
    fn collect_system_info() -> SystemInfo {
        SystemInfo {
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            cpu_cores: std::thread::available_parallelism()
                .map(|p| p.get())
                .unwrap_or(1),
            memory_bytes: 0, // Would need platform-specific API
            rust_version: env!("CARGO_PKG_RUST_VERSION").to_string(),
        }
    }

    /// Collect benchmark configuration
    fn collect_config() -> BenchmarkConfig {
        use crate::netbridge::config;

        BenchmarkConfig {
            tcp_buffer_size: config::TCP_RX_BUFFER,
            udp_buffer_size: config::UDP_RX_BUFFER,
            max_sockets: config::MAX_SOCKETS,
            wg_mtu: config::WG_MTU,
        }
    }

    /// Add throughput results
    pub fn add_throughput(&mut self, name: &str, results: ThroughputResults) {
        let report = ThroughputReport {
            name: name.to_string(),
            description: String::new(),
            throughput_mbps: results.throughput_mbps,
            per_connection_mbps: if results.connections > 1 {
                Some(results.per_connection_mbps)
            } else {
                None
            },
            bytes_transferred: results.bytes_transferred,
            duration_ms: results.duration_ms,
            connections: results.connections,
            packets_per_second: results.packets_per_second,
            errors: results.errors,
            passed: None,
        };

        self.throughput.insert(name.to_string(), report);
        self.update_summary();
    }

    /// Add throughput results with description
    pub fn add_throughput_with_desc(
        &mut self,
        name: &str,
        description: &str,
        results: ThroughputResults,
    ) {
        let report = ThroughputReport {
            name: name.to_string(),
            description: description.to_string(),
            throughput_mbps: results.throughput_mbps,
            per_connection_mbps: if results.connections > 1 {
                Some(results.per_connection_mbps)
            } else {
                None
            },
            bytes_transferred: results.bytes_transferred,
            duration_ms: results.duration_ms,
            connections: results.connections,
            packets_per_second: results.packets_per_second,
            errors: results.errors,
            passed: None,
        };

        self.throughput.insert(name.to_string(), report);
        self.update_summary();
    }

    /// Add latency results
    pub fn add_latency(&mut self, name: &str, results: LatencyResults) {
        let report = LatencyReport {
            name: name.to_string(),
            description: String::new(),
            samples: results.samples,
            min_us: results.min_us,
            max_us: results.max_us,
            avg_us: results.avg_us,
            p50_us: results.p50_us,
            p90_us: results.p90_us,
            p95_us: results.p95_us,
            p99_us: results.p99_us,
            p999_us: results.p999_us,
            stddev_us: results.stddev_us,
            jitter_us: results.jitter_us,
            errors: results.errors,
            passed: None,
        };

        self.latency.insert(name.to_string(), report);
        self.update_summary();
    }

    /// Add latency results with description
    pub fn add_latency_with_desc(
        &mut self,
        name: &str,
        description: &str,
        results: LatencyResults,
    ) {
        let report = LatencyReport {
            name: name.to_string(),
            description: description.to_string(),
            samples: results.samples,
            min_us: results.min_us,
            max_us: results.max_us,
            avg_us: results.avg_us,
            p50_us: results.p50_us,
            p90_us: results.p90_us,
            p95_us: results.p95_us,
            p99_us: results.p99_us,
            p999_us: results.p999_us,
            stddev_us: results.stddev_us,
            jitter_us: results.jitter_us,
            errors: results.errors,
            passed: None,
        };

        self.latency.insert(name.to_string(), report);
        self.update_summary();
    }

    /// Add general benchmark results
    pub fn add_general(&mut self, name: &str, results: BenchResults) {
        let report = GeneralReport {
            name: name.to_string(),
            description: String::new(),
            bytes_transferred: results.bytes_transferred,
            duration_ms: results.duration_ms,
            throughput_mbps: results.throughput_mbps,
            avg_latency_us: results.avg_latency_us,
            p99_latency_us: results.p99_latency_us,
            sessions_created: results.sessions_created,
            sessions_per_second: results.sessions_per_second,
            errors: results.errors,
        };

        self.general.insert(name.to_string(), report);
        self.update_summary();
    }

    /// Add a performance target
    pub fn add_target(
        &mut self,
        name: &str,
        description: &str,
        target: f64,
        actual: f64,
        unit: &str,
        higher_is_better: bool,
    ) {
        let met = if higher_is_better {
            actual >= target
        } else {
            actual <= target
        };

        self.targets.push(PerformanceTarget {
            name: name.to_string(),
            description: description.to_string(),
            target_value: target,
            unit: unit.to_string(),
            actual_value: actual,
            met,
        });

        self.update_summary();
    }

    /// Update the summary section
    fn update_summary(&mut self) {
        let mut total_tests = 0;
        let mut total_bytes = 0u64;
        let mut total_duration = 0u64;
        let mut peak_throughput = 0.0f64;
        let mut best_p99 = u64::MAX;

        // Throughput tests
        for (_, report) in &self.throughput {
            total_tests += 1;
            total_bytes += report.bytes_transferred;
            total_duration += report.duration_ms;
            if report.throughput_mbps > peak_throughput {
                peak_throughput = report.throughput_mbps;
            }
        }

        // Latency tests
        for (_, report) in &self.latency {
            total_tests += 1;
            if report.p99_us < best_p99 {
                best_p99 = report.p99_us;
            }
        }

        // General tests
        for (_, report) in &self.general {
            total_tests += 1;
            total_bytes += report.bytes_transferred;
            total_duration += report.duration_ms;
            if report.throughput_mbps > peak_throughput {
                peak_throughput = report.throughput_mbps;
            }
            if report.p99_latency_us < best_p99 {
                best_p99 = report.p99_latency_us;
            }
        }

        // Count passed/failed targets
        let targets_met = self.targets.iter().filter(|t| t.met).count();
        let targets_failed = self.targets.len() - targets_met;

        self.summary = ReportSummary {
            total_tests,
            tests_passed: targets_met,
            tests_failed: targets_failed,
            total_bytes,
            total_duration_ms: total_duration,
            peak_throughput_mbps: peak_throughput,
            best_p99_latency_us: if best_p99 == u64::MAX { 0 } else { best_p99 },
            status: if targets_failed == 0 {
                "PASSED".to_string()
            } else {
                "FAILED".to_string()
            },
        };
    }

    /// Convert to JSON string
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{}".to_string())
    }

    /// Convert to pretty JSON string
    pub fn to_json_pretty(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".to_string())
    }

    /// Convert to human-readable summary
    pub fn to_summary(&self) -> String {
        let mut output = String::new();

        // Header
        output.push_str(&format!("Benchmark Report: {}\n", self.name));
        output.push_str(&format!("Version: {}\n", self.version));
        output.push_str(&"=".repeat(60));
        output.push('\n');
        output.push('\n');

        // System info
        output.push_str("System Information:\n");
        output.push_str(&format!("  OS: {}\n", self.system_info.os));
        output.push_str(&format!("  Arch: {}\n", self.system_info.arch));
        output.push_str(&format!("  CPU Cores: {}\n", self.system_info.cpu_cores));
        output.push('\n');

        // Configuration
        output.push_str("Configuration:\n");
        output.push_str(&format!(
            "  TCP Buffer: {} KB\n",
            self.config.tcp_buffer_size / 1024
        ));
        output.push_str(&format!(
            "  UDP Buffer: {} KB\n",
            self.config.udp_buffer_size / 1024
        ));
        output.push_str(&format!("  Max Sockets: {}\n", self.config.max_sockets));
        output.push_str(&format!("  WG MTU: {}\n", self.config.wg_mtu));
        output.push('\n');

        // Throughput results
        if !self.throughput.is_empty() {
            output.push_str("Throughput Results:\n");
            output.push_str(&"-".repeat(60));
            output.push('\n');

            for (name, report) in &self.throughput {
                output.push_str(&format!("  {}:\n", name));
                output.push_str(&format!("    Throughput: {:.2} Mbps\n", report.throughput_mbps));
                if let Some(per_conn) = report.per_connection_mbps {
                    output.push_str(&format!(
                        "    Per-connection: {:.2} Mbps ({} connections)\n",
                        per_conn, report.connections
                    ));
                }
                output.push_str(&format!(
                    "    Data: {:.2} MB in {} ms\n",
                    report.bytes_transferred as f64 / (1024.0 * 1024.0),
                    report.duration_ms
                ));
                if report.packets_per_second > 0.0 {
                    output.push_str(&format!(
                        "    Packets: {:.0} pps\n",
                        report.packets_per_second
                    ));
                }
                if report.errors > 0 {
                    output.push_str(&format!("    Errors: {}\n", report.errors));
                }
                output.push('\n');
            }
        }

        // Latency results
        if !self.latency.is_empty() {
            output.push_str("Latency Results:\n");
            output.push_str(&"-".repeat(60));
            output.push('\n');

            for (name, report) in &self.latency {
                output.push_str(&format!("  {}:\n", name));
                output.push_str(&format!("    Samples: {}\n", report.samples));
                output.push_str(&format!(
                    "    Min/Avg/Max: {} / {} / {} us\n",
                    report.min_us, report.avg_us, report.max_us
                ));
                output.push_str(&format!(
                    "    Percentiles: P50={} P90={} P95={} P99={} P99.9={} us\n",
                    report.p50_us, report.p90_us, report.p95_us, report.p99_us, report.p999_us
                ));
                if report.stddev_us > 0 {
                    output.push_str(&format!("    Stddev: {} us\n", report.stddev_us));
                }
                if report.jitter_us > 0 {
                    output.push_str(&format!("    Jitter: {} us\n", report.jitter_us));
                }
                if report.errors > 0 {
                    output.push_str(&format!("    Errors: {}\n", report.errors));
                }
                output.push('\n');
            }
        }

        // Targets
        if !self.targets.is_empty() {
            output.push_str("Performance Targets:\n");
            output.push_str(&"-".repeat(60));
            output.push('\n');

            for target in &self.targets {
                let status = if target.met { "PASS" } else { "FAIL" };
                output.push_str(&format!(
                    "  [{}] {}: {:.2} {} (target: {:.2} {})\n",
                    status,
                    target.name,
                    target.actual_value,
                    target.unit,
                    target.target_value,
                    target.unit
                ));
            }
            output.push('\n');
        }

        // Summary
        output.push_str("Summary:\n");
        output.push_str(&"-".repeat(60));
        output.push('\n');
        output.push_str(&format!("  Total tests: {}\n", self.summary.total_tests));
        output.push_str(&format!(
            "  Passed/Failed: {}/{}\n",
            self.summary.tests_passed, self.summary.tests_failed
        ));
        output.push_str(&format!(
            "  Peak throughput: {:.2} Mbps\n",
            self.summary.peak_throughput_mbps
        ));
        output.push_str(&format!(
            "  Best P99 latency: {} us\n",
            self.summary.best_p99_latency_us
        ));
        output.push_str(&format!(
            "  Total data: {:.2} MB\n",
            self.summary.total_bytes as f64 / (1024.0 * 1024.0)
        ));
        output.push_str(&format!("  Status: {}\n", self.summary.status));

        output
    }

    /// Convert to Markdown format
    pub fn to_markdown(&self) -> String {
        let mut output = String::new();

        // Header
        output.push_str(&format!("# Benchmark Report: {}\n\n", self.name));
        output.push_str(&format!("**Version:** {}  \n", self.version));
        output.push_str(&format!(
            "**Date:** {}  \n\n",
            chrono_from_timestamp(self.timestamp)
        ));

        // System info
        output.push_str("## System Information\n\n");
        output.push_str("| Property | Value |\n");
        output.push_str("|----------|-------|\n");
        output.push_str(&format!("| OS | {} |\n", self.system_info.os));
        output.push_str(&format!("| Architecture | {} |\n", self.system_info.arch));
        output.push_str(&format!("| CPU Cores | {} |\n", self.system_info.cpu_cores));
        output.push('\n');

        // Throughput table
        if !self.throughput.is_empty() {
            output.push_str("## Throughput Results\n\n");
            output.push_str("| Test | Throughput (Mbps) | Data (MB) | Duration (ms) |\n");
            output.push_str("|------|-------------------|-----------|---------------|\n");

            for (name, report) in &self.throughput {
                output.push_str(&format!(
                    "| {} | {:.2} | {:.2} | {} |\n",
                    name,
                    report.throughput_mbps,
                    report.bytes_transferred as f64 / (1024.0 * 1024.0),
                    report.duration_ms
                ));
            }
            output.push('\n');
        }

        // Latency table
        if !self.latency.is_empty() {
            output.push_str("## Latency Results\n\n");
            output.push_str("| Test | P50 (us) | P95 (us) | P99 (us) | Avg (us) |\n");
            output.push_str("|------|----------|----------|----------|----------|\n");

            for (name, report) in &self.latency {
                output.push_str(&format!(
                    "| {} | {} | {} | {} | {} |\n",
                    name, report.p50_us, report.p95_us, report.p99_us, report.avg_us
                ));
            }
            output.push('\n');
        }

        // Targets
        if !self.targets.is_empty() {
            output.push_str("## Performance Targets\n\n");
            output.push_str("| Target | Required | Actual | Status |\n");
            output.push_str("|--------|----------|--------|--------|\n");

            for target in &self.targets {
                let status = if target.met { "PASS" } else { "**FAIL**" };
                output.push_str(&format!(
                    "| {} | {:.2} {} | {:.2} {} | {} |\n",
                    target.name,
                    target.target_value,
                    target.unit,
                    target.actual_value,
                    target.unit,
                    status
                ));
            }
            output.push('\n');
        }

        // Summary
        output.push_str("## Summary\n\n");
        output.push_str(&format!(
            "- **Status:** {}\n",
            if self.summary.tests_failed == 0 {
                "All targets met"
            } else {
                "Some targets not met"
            }
        ));
        output.push_str(&format!(
            "- **Peak Throughput:** {:.2} Mbps\n",
            self.summary.peak_throughput_mbps
        ));
        output.push_str(&format!(
            "- **Best P99 Latency:** {} us\n",
            self.summary.best_p99_latency_us
        ));

        output
    }

    /// Format report according to specified format
    pub fn format(&self, format: ReportFormat) -> String {
        match format {
            ReportFormat::Json => self.to_json(),
            ReportFormat::JsonPretty => self.to_json_pretty(),
            ReportFormat::Summary => self.to_summary(),
            ReportFormat::Markdown => self.to_markdown(),
            ReportFormat::Csv => self.to_csv(),
        }
    }

    /// Convert to CSV format
    pub fn to_csv(&self) -> String {
        let mut output = String::new();

        // Header
        output.push_str("test_type,test_name,metric,value,unit\n");

        // Throughput
        for (name, report) in &self.throughput {
            output.push_str(&format!(
                "throughput,{},throughput_mbps,{:.2},Mbps\n",
                name, report.throughput_mbps
            ));
            output.push_str(&format!(
                "throughput,{},bytes_transferred,{},bytes\n",
                name, report.bytes_transferred
            ));
            output.push_str(&format!(
                "throughput,{},duration_ms,{},ms\n",
                name, report.duration_ms
            ));
        }

        // Latency
        for (name, report) in &self.latency {
            output.push_str(&format!(
                "latency,{},p50_us,{},us\n",
                name, report.p50_us
            ));
            output.push_str(&format!(
                "latency,{},p95_us,{},us\n",
                name, report.p95_us
            ));
            output.push_str(&format!(
                "latency,{},p99_us,{},us\n",
                name, report.p99_us
            ));
            output.push_str(&format!(
                "latency,{},avg_us,{},us\n",
                name, report.avg_us
            ));
        }

        output
    }
}

impl Default for BenchmarkReport {
    fn default() -> Self {
        Self::new("netbridge-benchmark")
    }
}

/// Helper function to format timestamp
fn chrono_from_timestamp(timestamp: u64) -> String {
    // Simple formatting without chrono dependency
    format!("Unix timestamp: {}", timestamp)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_benchmark_report_new() {
        let report = BenchmarkReport::new("test-report");
        assert_eq!(report.name, "test-report");
        assert!(report.timestamp > 0);
    }

    #[test]
    fn test_benchmark_report_add_throughput() {
        let mut report = BenchmarkReport::new("test");

        let results = ThroughputResults {
            throughput_mbps: 500.0,
            bytes_transferred: 1_000_000,
            duration_ms: 16,
            connections: 1,
            ..Default::default()
        };

        report.add_throughput("tcp_single", results);

        assert!(report.throughput.contains_key("tcp_single"));
        assert_eq!(report.summary.total_tests, 1);
    }

    #[test]
    fn test_benchmark_report_add_latency() {
        let mut report = BenchmarkReport::new("test");

        let results = LatencyResults {
            samples: 1000,
            p50_us: 100,
            p99_us: 500,
            avg_us: 150,
            ..Default::default()
        };

        report.add_latency("udp_rtt", results);

        assert!(report.latency.contains_key("udp_rtt"));
        assert_eq!(report.summary.total_tests, 1);
    }

    #[test]
    fn test_benchmark_report_add_target() {
        let mut report = BenchmarkReport::new("test");

        // Passing target
        report.add_target(
            "throughput",
            "Minimum throughput",
            500.0,
            600.0,
            "Mbps",
            true,
        );

        // Failing target
        report.add_target(
            "latency",
            "Maximum P99 latency",
            100.0,
            200.0,
            "us",
            false,
        );

        assert_eq!(report.targets.len(), 2);
        assert!(report.targets[0].met);
        assert!(!report.targets[1].met);
    }

    #[test]
    fn test_benchmark_report_to_json() {
        let mut report = BenchmarkReport::new("test");
        report.add_throughput(
            "test",
            ThroughputResults {
                throughput_mbps: 500.0,
                ..Default::default()
            },
        );

        let json = report.to_json();
        assert!(json.contains("test"));
        assert!(json.contains("500"));
    }

    #[test]
    fn test_benchmark_report_to_summary() {
        let mut report = BenchmarkReport::new("test");
        report.add_throughput(
            "tcp_single",
            ThroughputResults {
                throughput_mbps: 500.0,
                bytes_transferred: 1_000_000,
                duration_ms: 16,
                ..Default::default()
            },
        );

        let summary = report.to_summary();
        assert!(summary.contains("tcp_single"));
        assert!(summary.contains("500"));
        assert!(summary.contains("Throughput"));
    }

    #[test]
    fn test_benchmark_report_to_markdown() {
        let mut report = BenchmarkReport::new("test");
        report.add_throughput(
            "tcp",
            ThroughputResults {
                throughput_mbps: 500.0,
                ..Default::default()
            },
        );

        let md = report.to_markdown();
        assert!(md.contains("# Benchmark Report"));
        assert!(md.contains("| tcp |"));
    }

    #[test]
    fn test_benchmark_report_to_csv() {
        let mut report = BenchmarkReport::new("test");
        report.add_throughput(
            "tcp",
            ThroughputResults {
                throughput_mbps: 500.0,
                ..Default::default()
            },
        );

        let csv = report.to_csv();
        assert!(csv.contains("throughput,tcp,throughput_mbps,500"));
    }

    #[test]
    fn test_performance_target() {
        let target = PerformanceTarget {
            name: "throughput".to_string(),
            description: "Min throughput".to_string(),
            target_value: 500.0,
            unit: "Mbps".to_string(),
            actual_value: 600.0,
            met: true,
        };

        assert!(target.met);
    }

    #[test]
    fn test_report_summary_status() {
        let mut report = BenchmarkReport::new("test");

        // All passed
        report.add_target("t1", "desc", 100.0, 150.0, "Mbps", true);
        assert_eq!(report.summary.status, "PASSED");

        // One failed
        report.add_target("t2", "desc", 200.0, 100.0, "Mbps", true);
        assert_eq!(report.summary.status, "FAILED");
    }
}
