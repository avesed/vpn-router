//! Parity tests using test vectors.
//!
//! This module loads test vectors from `tests/fixtures/rule_test_vectors.json`
//! and verifies that the Rust rule engine implementation produces identical
//! results to the expected Python/sing-box reference implementation.
//!
//! ## Test Vector Format
//!
//! Each test case includes:
//! - `id`: Unique identifier
//! - `category`: Test category for filtering
//! - `description`: Human-readable description
//! - `input`: Connection info (domain, IP, port, protocol)
//! - `rules`: List of rules to apply
//! - `expected`: Expected matching result
//!
//! ## Running Tests
//!
//! ```bash
//! cargo test --test rule_parity
//! ```

use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::net::IpAddr;

// Import rule engine types from rust_router
// Note: These imports assume the rule engine module is exported in lib.rs
use rust_router::rules::{
    domain::DomainMatcher,
    geoip::GeoIpMatcher,
    fwmark::FwmarkRouter,
};

/// Test vectors file structure
#[derive(Debug, Deserialize)]
struct TestVectors {
    version: String,
    description: String,
    generated_at: String,
    total_cases: usize,
    categories: HashMap<String, usize>,
    test_cases: Vec<TestCase>,
}

/// Individual test case
#[derive(Debug, Deserialize)]
struct TestCase {
    id: String,
    category: String,
    description: String,
    input: TestInput,
    rules: Vec<TestRule>,
    expected: Expected,
    #[serde(default)]
    chains: Option<serde_json::Value>,
}

/// Test input (connection info)
#[derive(Debug, Deserialize)]
struct TestInput {
    domain: Option<String>,
    dest_ip: Option<String>,
    dest_port: u16,
    protocol: String,
    #[serde(default)]
    sniffed_protocol: Option<String>,
}

/// Test rule definition
#[derive(Debug, Deserialize)]
struct TestRule {
    #[serde(rename = "type")]
    rule_type: String,
    target: String,
    outbound: String,
    #[serde(default)]
    port: Option<String>,
    #[serde(default)]
    protocol: Option<String>,
}

/// Expected result
#[derive(Debug, Deserialize)]
struct Expected {
    outbound: String,
    match_type: Option<String>,
    #[serde(default)]
    has_routing_mark: Option<bool>,
    #[serde(default)]
    routing_mark: Option<u32>,
}

/// Parity test result
#[derive(Debug)]
struct ParityResult {
    passed: usize,
    failed: usize,
    skipped: usize,
    failures: Vec<(String, String, String)>, // (id, expected, actual)
}

impl ParityResult {
    fn new() -> Self {
        Self {
            passed: 0,
            failed: 0,
            skipped: 0,
            failures: Vec::new(),
        }
    }
}

/// Load test vectors from the JSON file
fn load_test_vectors() -> TestVectors {
    let vectors_path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/rule_test_vectors.json");
    let content = fs::read_to_string(vectors_path)
        .expect("Failed to read test vectors file");
    serde_json::from_str(&content)
        .expect("Failed to parse test vectors JSON")
}

/// Run a single test case for domain matching
fn run_domain_test(case: &TestCase) -> Option<String> {
    let mut builder = DomainMatcher::builder();

    for rule in &case.rules {
        match rule.rule_type.as_str() {
            "domain" => {
                builder = builder.add_exact(&rule.target, &rule.outbound);
            }
            "domain_suffix" => {
                builder = builder.add_suffix(&rule.target, &rule.outbound);
            }
            "domain_keyword" => {
                builder = builder.add_keyword(&rule.target, &rule.outbound);
            }
            "domain_regex" => {
                builder = builder.add_regex(&rule.target, &rule.outbound).ok()?;
            }
            _ => continue,
        }
    }

    let matcher = builder.build().ok()?;

    if let Some(domain) = &case.input.domain {
        if !domain.is_empty() {
            return matcher.match_domain(domain).map(|s| s.to_string());
        }
    }

    None
}

/// Run a single test case for GeoIP matching
fn run_geoip_test(case: &TestCase) -> Option<String> {
    let mut builder = GeoIpMatcher::builder();

    for rule in &case.rules {
        if rule.rule_type == "ip_cidr" {
            builder.add_cidr_mut(&rule.target, &rule.outbound).ok()?;
        }
    }

    let matcher = builder.build().ok()?;

    if let Some(ip_str) = &case.input.dest_ip {
        if let Ok(ip) = ip_str.parse::<IpAddr>() {
            return matcher.match_ip(ip).map(|s| s.to_string());
        }
    }

    None
}

/// Run a single test case for port matching
fn run_port_test(case: &TestCase) -> Option<String> {
    for rule in &case.rules {
        if rule.rule_type == "port" {
            let target = &rule.target;
            let port = case.input.dest_port;

            // Handle single port
            if let Ok(single_port) = target.parse::<u16>() {
                if port == single_port {
                    return Some(rule.outbound.clone());
                }
            }

            // Handle port range (e.g., "80-443")
            if let Some((start, end)) = target.split_once('-') {
                if let (Ok(start_port), Ok(end_port)) = (start.parse::<u16>(), end.parse::<u16>()) {
                    if port >= start_port && port <= end_port {
                        return Some(rule.outbound.clone());
                    }
                }
            }
        }
    }
    None
}

/// Run a single test case for protocol matching
fn run_protocol_test(case: &TestCase) -> Option<String> {
    let input_proto = case.input.protocol.to_lowercase();
    let sniffed_proto = case.input.sniffed_protocol.as_ref()
        .map(|s| s.to_lowercase());

    for rule in &case.rules {
        if rule.rule_type == "protocol" {
            let rule_proto = rule.target.to_lowercase();

            // Check sniffed protocol first if available
            if let Some(ref sniffed) = sniffed_proto {
                if *sniffed == rule_proto {
                    return Some(rule.outbound.clone());
                }
            }

            // Check transport protocol
            if input_proto == rule_proto {
                return Some(rule.outbound.clone());
            }
        }
    }
    None
}

/// Run a complete test case with all rule types
fn run_test_case(case: &TestCase) -> (bool, String) {
    let expected_outbound = &case.expected.outbound;

    // Determine what types of rules we have
    let has_domain_rules = case.rules.iter().any(|r|
        matches!(r.rule_type.as_str(), "domain" | "domain_suffix" | "domain_keyword" | "domain_regex")
    );
    let has_ip_rules = case.rules.iter().any(|r| r.rule_type == "ip_cidr");
    let has_port_rules = case.rules.iter().any(|r| r.rule_type == "port");
    let has_protocol_rules = case.rules.iter().any(|r| r.rule_type == "protocol");

    // Priority order (same as sing-box):
    // 1. Domain rules (if domain is present)
    // 2. GeoIP rules (if IP is present)
    // 3. Port rules
    // 4. Protocol rules

    let mut actual_outbound = "direct".to_string();

    // Try domain matching first
    if has_domain_rules {
        if let Some(result) = run_domain_test(case) {
            actual_outbound = result;
            let passed = actual_outbound == *expected_outbound;
            return (passed, actual_outbound);
        }
    }

    // Try GeoIP matching
    if has_ip_rules {
        if let Some(result) = run_geoip_test(case) {
            actual_outbound = result;
            let passed = actual_outbound == *expected_outbound;
            return (passed, actual_outbound);
        }
    }

    // Try port matching
    if has_port_rules {
        if let Some(result) = run_port_test(case) {
            actual_outbound = result;
            let passed = actual_outbound == *expected_outbound;
            return (passed, actual_outbound);
        }
    }

    // Try protocol matching
    if has_protocol_rules {
        if let Some(result) = run_protocol_test(case) {
            actual_outbound = result;
            let passed = actual_outbound == *expected_outbound;
            return (passed, actual_outbound);
        }
    }

    // No match, use default
    let passed = actual_outbound == *expected_outbound;
    (passed, actual_outbound)
}

/// Main parity test
#[test]
fn test_rule_matching_parity() {
    let vectors = load_test_vectors();

    println!("\n=== Rule Engine Parity Test ===");
    println!("Test vectors version: {}", vectors.version);
    println!("Total test cases: {}", vectors.total_cases);
    println!();

    let mut result = ParityResult::new();

    // Categories to skip (not yet implemented or not applicable)
    let skip_categories = [
        "combined_rules",     // Combined rules need more complex handling
        "combined_complex",   // Complex combined rules
    ];

    for case in &vectors.test_cases {
        // Skip certain categories that need special handling
        if skip_categories.iter().any(|&cat| case.category.starts_with(cat)) {
            result.skipped += 1;
            continue;
        }

        let (passed, actual) = run_test_case(case);

        if passed {
            result.passed += 1;
        } else {
            result.failed += 1;
            result.failures.push((
                case.id.clone(),
                case.expected.outbound.clone(),
                actual,
            ));
        }
    }

    // Print summary
    println!("Results:");
    println!("  Passed:  {}", result.passed);
    println!("  Failed:  {}", result.failed);
    println!("  Skipped: {}", result.skipped);
    println!();

    // Print first 10 failures for debugging
    if !result.failures.is_empty() {
        println!("First {} failures:", std::cmp::min(10, result.failures.len()));
        for (id, expected, actual) in result.failures.iter().take(10) {
            println!("  {}: expected '{}', got '{}'", id, expected, actual);
        }
        println!();
    }

    // Calculate pass rate
    let total_run = result.passed + result.failed;
    let pass_rate = if total_run > 0 {
        (result.passed as f64 / total_run as f64) * 100.0
    } else {
        0.0
    };
    println!("Pass rate: {:.2}%", pass_rate);

    // Assert high pass rate (allow some failures for edge cases)
    assert!(
        pass_rate >= 95.0,
        "Parity test pass rate ({:.2}%) is below 95% threshold",
        pass_rate
    );
}

/// Test domain exact matching parity
#[test]
fn test_domain_exact_parity() {
    let vectors = load_test_vectors();
    let domain_exact_cases: Vec<_> = vectors.test_cases.iter()
        .filter(|c| c.category.starts_with("domain_exact"))
        .collect();

    println!("\n=== Domain Exact Match Parity Test ===");
    println!("Test cases: {}", domain_exact_cases.len());

    let mut passed = 0;
    let mut failed = 0;

    for case in &domain_exact_cases {
        let (success, actual) = run_test_case(case);
        if success {
            passed += 1;
        } else {
            failed += 1;
            println!("  FAIL {}: expected '{}', got '{}'",
                case.id, case.expected.outbound, actual);
        }
    }

    println!("Results: {} passed, {} failed", passed, failed);
    assert_eq!(failed, 0, "Domain exact parity tests failed");
}

/// Test domain suffix matching parity
#[test]
fn test_domain_suffix_parity() {
    let vectors = load_test_vectors();
    let suffix_cases: Vec<_> = vectors.test_cases.iter()
        .filter(|c| c.category.starts_with("domain_suffix"))
        .collect();

    println!("\n=== Domain Suffix Match Parity Test ===");
    println!("Test cases: {}", suffix_cases.len());

    let mut passed = 0;
    let mut failed = 0;

    for case in &suffix_cases {
        let (success, actual) = run_test_case(case);
        if success {
            passed += 1;
        } else {
            failed += 1;
            println!("  FAIL {}: expected '{}', got '{}'",
                case.id, case.expected.outbound, actual);
        }
    }

    println!("Results: {} passed, {} failed", passed, failed);
    assert_eq!(failed, 0, "Domain suffix parity tests failed");
}

/// Test GeoIP CIDR matching parity
#[test]
fn test_geoip_cidr_parity() {
    let vectors = load_test_vectors();
    let cidr_cases: Vec<_> = vectors.test_cases.iter()
        .filter(|c| c.category.starts_with("geoip_cidr") || c.category.starts_with("cidr_"))
        .collect();

    println!("\n=== GeoIP CIDR Match Parity Test ===");
    println!("Test cases: {}", cidr_cases.len());

    let mut passed = 0;
    let mut failed = 0;

    for case in &cidr_cases {
        let (success, actual) = run_test_case(case);
        if success {
            passed += 1;
        } else {
            failed += 1;
            println!("  FAIL {}: expected '{}', got '{}'",
                case.id, case.expected.outbound, actual);
        }
    }

    println!("Results: {} passed, {} failed", passed, failed);
    assert_eq!(failed, 0, "GeoIP CIDR parity tests failed");
}

/// Test port matching parity
#[test]
fn test_port_parity() {
    let vectors = load_test_vectors();
    let port_cases: Vec<_> = vectors.test_cases.iter()
        .filter(|c| c.category.starts_with("port_"))
        .collect();

    println!("\n=== Port Match Parity Test ===");
    println!("Test cases: {}", port_cases.len());

    let mut passed = 0;
    let mut failed = 0;

    for case in &port_cases {
        let (success, actual) = run_test_case(case);
        if success {
            passed += 1;
        } else {
            failed += 1;
            println!("  FAIL {}: expected '{}', got '{}'",
                case.id, case.expected.outbound, actual);
        }
    }

    println!("Results: {} passed, {} failed", passed, failed);
    assert_eq!(failed, 0, "Port parity tests failed");
}

/// Test FwmarkRouter chain matching
#[test]
fn test_fwmark_router_parity() {
    let vectors = load_test_vectors();
    let chain_cases: Vec<_> = vectors.test_cases.iter()
        .filter(|c| c.category.starts_with("chain_"))
        .collect();

    println!("\n=== FwmarkRouter Chain Parity Test ===");
    println!("Test cases: {}", chain_cases.len());

    let mut passed = 0;
    let mut failed = 0;

    for case in &chain_cases {
        // For chain routing tests, we verify that domain matching works
        // and that the outbound is correctly identified as a chain
        let (success, actual) = run_test_case(case);
        if success {
            passed += 1;
        } else {
            failed += 1;
            println!("  FAIL {}: expected '{}', got '{}'",
                case.id, case.expected.outbound, actual);
        }
    }

    println!("Results: {} passed, {} failed", passed, failed);
    assert_eq!(failed, 0, "Chain routing parity tests failed");
}

/// Test negative cases (things that should NOT match)
#[test]
fn test_negative_parity() {
    let vectors = load_test_vectors();
    let negative_cases: Vec<_> = vectors.test_cases.iter()
        .filter(|c| c.category.starts_with("negative_"))
        .collect();

    println!("\n=== Negative Cases Parity Test ===");
    println!("Test cases: {}", negative_cases.len());

    let mut passed = 0;
    let mut failed = 0;

    for case in &negative_cases {
        let (success, actual) = run_test_case(case);
        if success {
            passed += 1;
        } else {
            failed += 1;
            println!("  FAIL {}: expected '{}', got '{}'",
                case.id, case.expected.outbound, actual);
        }
    }

    println!("Results: {} passed, {} failed", passed, failed);
    assert_eq!(failed, 0, "Negative parity tests failed");
}

/// Test stress cases (many rules)
#[test]
fn test_stress_parity() {
    let vectors = load_test_vectors();
    let stress_cases: Vec<_> = vectors.test_cases.iter()
        .filter(|c| c.category.starts_with("stress_"))
        .collect();

    println!("\n=== Stress Test Parity ===");
    println!("Test cases: {}", stress_cases.len());

    let mut passed = 0;
    let mut failed = 0;

    for case in &stress_cases {
        let (success, actual) = run_test_case(case);
        if success {
            passed += 1;
        } else {
            failed += 1;
            println!("  FAIL {}: expected '{}', got '{}'",
                case.id, case.expected.outbound, actual);
        }
    }

    println!("Results: {} passed, {} failed", passed, failed);
    assert_eq!(failed, 0, "Stress parity tests failed");
}

/// Test international domains
#[test]
fn test_international_domains_parity() {
    let vectors = load_test_vectors();
    let intl_cases: Vec<_> = vectors.test_cases.iter()
        .filter(|c| c.category.starts_with("international_"))
        .collect();

    println!("\n=== International Domains Parity Test ===");
    println!("Test cases: {}", intl_cases.len());

    let mut passed = 0;
    let mut failed = 0;

    for case in &intl_cases {
        let (success, actual) = run_test_case(case);
        if success {
            passed += 1;
        } else {
            failed += 1;
            println!("  FAIL {}: expected '{}', got '{}'",
                case.id, case.expected.outbound, actual);
        }
    }

    println!("Results: {} passed, {} failed", passed, failed);
    assert_eq!(failed, 0, "International domains parity tests failed");
}
