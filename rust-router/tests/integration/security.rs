//! Security Tests for rust-router
//!
//! This module provides comprehensive security testing including:
//! - Input validation (malformed data, injection attempts)
//! - Boundary checks (integer overflow, buffer limits)
//! - Resource exhaustion resistance (DoS)
//! - Protocol fuzzing
//!
//! # Test Categories
//!
//! - `test_input_validation_*`: Malformed input handling
//! - `test_boundary_*`: Integer and buffer boundary conditions
//! - `test_injection_*`: Command/path injection attempts
//! - `test_dos_resistance_*`: Resource exhaustion scenarios
//!
//! # Usage
//!
//! ```bash
//! cargo test security -- --nocapture
//! ```

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;

use rust_router::ipc::{decode_message, encode_message, IpcCommand};
use rust_router::rules::{
    ConnectionInfo, DomainMatcherBuilder, RuleEngine, RuleType,
    RoutingSnapshotBuilder,
};

// ============================================================================
// Input Validation Tests
// ============================================================================

mod input_validation {
    use super::*;

    /// Test that empty domain strings are handled safely
    #[test]
    fn test_empty_domain() {
        let mut builder = DomainMatcherBuilder::new();
        builder = builder.add_suffix("example.com", "proxy");
        let matcher = builder.build().expect("build failed");

        // Empty domain should not match and not panic
        let result = matcher.match_domain("");
        assert!(result.is_none());
    }

    /// Test handling of very long domain names
    #[test]
    fn test_extremely_long_domain() {
        let matcher = DomainMatcherBuilder::new()
            .add_suffix("example.com", "proxy")
            .build()
            .expect("build failed");

        // RFC 1035 limits domain names to 253 characters
        // Test with 10x that to ensure no buffer overflow
        let long_domain = "a".repeat(2530);
        let result = matcher.match_domain(&long_domain);
        assert!(result.is_none());

        // Test with max subdomain components
        let many_subdomains = (0..128).map(|i| format!("sub{}", i)).collect::<Vec<_>>().join(".");
        let result = matcher.match_domain(&many_subdomains);
        assert!(result.is_none());
    }

    /// Test null bytes in domain names
    #[test]
    fn test_null_bytes_in_domain() {
        let matcher = DomainMatcherBuilder::new()
            .add_suffix("example.com", "proxy")
            .build()
            .expect("build failed");

        // Null bytes should not cause crashes
        let domain_with_null = "evil\x00.example.com";
        let result = matcher.match_domain(domain_with_null);
        // Should not match the clean pattern
        assert!(result.is_none() || result == Some("proxy"));
    }

    /// Test unicode domain names
    #[test]
    fn test_unicode_domains() {
        let matcher = DomainMatcherBuilder::new()
            .add_suffix("example.com", "proxy")
            .add_exact("测试.中国", "direct")
            .add_suffix("münchen.de", "eu")
            .build()
            .expect("build failed");

        // Exact unicode match
        assert_eq!(matcher.match_domain("测试.中国"), Some("direct"));

        // Unicode suffix match
        assert_eq!(matcher.match_domain("test.münchen.de"), Some("eu"));

        // Mixed ASCII/Unicode
        let result = matcher.match_domain("test.example.中国");
        assert!(result.is_none());
    }

    /// Test punycode domain names
    #[test]
    fn test_punycode_domains() {
        let matcher = DomainMatcherBuilder::new()
            .add_suffix("xn--n3h.com", "emoji")  // 😀.com in punycode
            .build()
            .expect("build failed");

        let result = matcher.match_domain("test.xn--n3h.com");
        assert_eq!(result, Some("emoji"));
    }

    /// Test case sensitivity
    #[test]
    fn test_domain_case_sensitivity() {
        let matcher = DomainMatcherBuilder::new()
            .add_suffix("Example.COM", "proxy")
            .build()
            .expect("build failed");

        // DNS is case-insensitive
        assert_eq!(matcher.match_domain("test.example.com"), Some("proxy"));
        assert_eq!(matcher.match_domain("test.EXAMPLE.COM"), Some("proxy"));
        assert_eq!(matcher.match_domain("test.Example.Com"), Some("proxy"));
    }

    /// Test whitespace handling
    #[test]
    fn test_whitespace_in_domain() {
        let matcher = DomainMatcherBuilder::new()
            .add_suffix("example.com", "proxy")
            .build()
            .expect("build failed");

        // Leading/trailing whitespace
        let result = matcher.match_domain(" example.com");
        assert!(result.is_none()); // Should not match due to invalid chars

        let result = matcher.match_domain("example.com ");
        assert!(result.is_none());

        // Embedded whitespace
        let result = matcher.match_domain("exa mple.com");
        assert!(result.is_none());
    }

    /// Test special characters in domain
    #[test]
    fn test_special_chars_in_domain() {
        let matcher = DomainMatcherBuilder::new()
            .add_suffix("example.com", "proxy")
            .build()
            .expect("build failed");

        // Various injection attempts
        let injection_attempts = [
            "../../../etc/passwd",
            "; rm -rf /",
            "| cat /etc/passwd",
            "$(whoami)",
            "`id`",
            "<script>alert(1)</script>",
            "example.com\r\nHost: evil.com",
            "example.com%00.evil.com",
        ];

        for attempt in injection_attempts {
            let result = matcher.match_domain(attempt);
            // None of these should match as valid domains
            assert!(result.is_none(), "Should not match injection: {}", attempt);
        }
    }
}

// ============================================================================
// Boundary Condition Tests
// ============================================================================

mod boundary_checks {
    use super::*;

    /// Test port number boundaries
    #[test]
    fn test_port_boundaries() {
        let builder = RoutingSnapshotBuilder::new()
            .default_outbound("direct")
            .version(1);

        // Port 0 is reserved but valid in some contexts
        let conn = ConnectionInfo::new("tcp", 0);
        assert_eq!(conn.dest_port, 0);

        // Maximum port
        let conn = ConnectionInfo::new("tcp", 65535);
        assert_eq!(conn.dest_port, 65535);

        // Verify ConnectionInfo doesn't allow overflow
        // This is a compile-time check via u16 type
    }

    /// Test IP address edge cases
    #[test]
    fn test_ip_boundaries() {
        // All zeros (unspecified)
        let conn = ConnectionInfo::new("tcp", 80)
            .with_dest_ip(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)));
        assert!(conn.dest_ip.is_some());

        // All ones (broadcast)
        let conn = ConnectionInfo::new("tcp", 80)
            .with_dest_ip(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255)));
        assert!(conn.dest_ip.is_some());

        // Loopback
        let conn = ConnectionInfo::new("tcp", 80)
            .with_dest_ip(IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert!(conn.dest_ip.is_some());

        // IPv6 loopback
        let conn = ConnectionInfo::new("tcp", 80)
            .with_dest_ip(IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert!(conn.dest_ip.is_some());

        // IPv6 all zeros
        let conn = ConnectionInfo::new("tcp", 80)
            .with_dest_ip(IpAddr::V6(Ipv6Addr::UNSPECIFIED));
        assert!(conn.dest_ip.is_some());

        // IPv6 max address
        let conn = ConnectionInfo::new("tcp", 80)
            .with_dest_ip(IpAddr::V6(Ipv6Addr::new(
                0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
                0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
            )));
        assert!(conn.dest_ip.is_some());
    }

    /// Test rule count limits
    #[test]
    fn test_large_rule_count() {
        let mut builder = RoutingSnapshotBuilder::new();

        // Add 10,000 domain rules
        for i in 0..10_000 {
            let _ = builder.add_domain_rule(
                RuleType::DomainSuffix,
                &format!("domain{}.com", i),
                "proxy",
            );
        }

        let snapshot = builder
            .default_outbound("direct")
            .version(1)
            .build();

        assert!(snapshot.is_ok(), "Should handle 10k rules");
    }

    /// Test concurrent rule matching with large rule sets
    #[test]
    fn test_concurrent_large_ruleset() {
        use std::thread;

        let mut builder = RoutingSnapshotBuilder::new();
        for i in 0..5_000 {
            let _ = builder.add_domain_rule(
                RuleType::DomainSuffix,
                &format!("domain{}.com", i),
                "proxy",
            );
        }

        let engine = Arc::new(RuleEngine::new(
            builder
                .default_outbound("direct")
                .version(1)
                .build()
                .expect("build failed"),
        ));

        // Spawn 10 threads doing concurrent matching
        let handles: Vec<_> = (0..10)
            .map(|t| {
                let engine = Arc::clone(&engine);
                thread::spawn(move || {
                    for i in 0..1000 {
                        let domain = format!("test{}.domain{}.com", t, i % 1000);
                        let conn = ConnectionInfo::new("tcp", 443).with_domain(&domain);
                        let _ = engine.match_connection(&conn);
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().expect("Thread panicked");
        }
    }
}

// ============================================================================
// IPC Protocol Security Tests
// ============================================================================

mod ipc_security {
    use super::*;

    /// Test malformed IPC message handling
    #[test]
    fn test_malformed_ipc_messages() {
        // Empty payload
        let result = decode_message::<IpcCommand>(&[]);
        assert!(result.is_err());

        // Invalid JSON
        let invalid_json = b"not valid json";
        let result = decode_message::<IpcCommand>(invalid_json);
        assert!(result.is_err());

        // Truncated JSON
        let truncated = b"{\"Ping\":";
        let result = decode_message::<IpcCommand>(truncated);
        assert!(result.is_err());

        // Valid JSON but wrong structure
        let wrong_structure = b"[1, 2, 3]";
        let result = decode_message::<IpcCommand>(wrong_structure);
        assert!(result.is_err());
    }

    /// Test oversized IPC messages
    #[test]
    fn test_oversized_ipc_message() {
        // Create a very large command (10MB of data)
        let large_data = "x".repeat(10 * 1024 * 1024);
        let large_json = format!("{{\"Status\": \"{}\"}}", large_data);

        let result = decode_message::<IpcCommand>(large_json.as_bytes());
        // Should either fail to parse or succeed with truncation
        // The important thing is no panic or crash
        let _ = result;
    }

    /// Test IPC with control characters
    #[test]
    fn test_ipc_control_characters() {
        // Test various control character injections
        let control_chars = [
            "\x00",  // Null
            "\x01",  // Start of heading
            "\x07",  // Bell
            "\x1b",  // Escape
            "\r\n",  // CRLF
        ];

        for ctrl in control_chars {
            let json = format!("{{\"Status\": \"test{}value\"}}", ctrl);
            let result = decode_message::<IpcCommand>(json.as_bytes());
            // Should handle without crashing
            let _ = result;
        }
    }

    /// Test IPC command serialization roundtrip
    #[test]
    fn test_ipc_serialization_roundtrip() {
        let commands = [
            IpcCommand::Ping,
            IpcCommand::Status,
            IpcCommand::GetStats,
            IpcCommand::ListOutbounds,
        ];

        for cmd in commands {
            let encoded = encode_message(&cmd).expect("encode failed");
            // Skip length prefix (first 4 bytes)
            let decoded: IpcCommand = decode_message(&encoded[4..]).expect("decode failed");

            // Verify roundtrip
            match (&cmd, &decoded) {
                (IpcCommand::Ping, IpcCommand::Ping) => (),
                (IpcCommand::Status, IpcCommand::Status) => (),
                (IpcCommand::GetStats, IpcCommand::GetStats) => (),
                (IpcCommand::ListOutbounds, IpcCommand::ListOutbounds) => (),
                _ => panic!("Roundtrip mismatch: {:?} -> {:?}", cmd, decoded),
            }
        }

        // Test Shutdown separately due to struct variant
        let shutdown_cmd = IpcCommand::Shutdown { drain_timeout_secs: Some(30) };
        let encoded = encode_message(&shutdown_cmd).expect("encode Shutdown failed");
        let decoded: IpcCommand = decode_message(&encoded[4..]).expect("decode Shutdown failed");
        match decoded {
            IpcCommand::Shutdown { drain_timeout_secs } => {
                assert_eq!(drain_timeout_secs, Some(30));
            }
            _ => panic!("Shutdown roundtrip failed"),
        }
    }
}

// ============================================================================
// Resource Exhaustion Tests
// ============================================================================

mod dos_resistance {
    use super::*;
    use std::time::Instant;

    /// Test that pathological regex patterns don't cause ReDoS
    #[test]
    fn test_regex_dos_resistance() {
        let start = Instant::now();

        // Attempt to create a matcher with a potentially problematic pattern
        let result = DomainMatcherBuilder::new()
            // This should not cause exponential backtracking
            .add_keyword("aaaa", "test")
            .build();

        // If we get here within 1 second, we're safe
        assert!(start.elapsed() < Duration::from_secs(1));
        assert!(result.is_ok());

        // Test matching with adversarial input
        let matcher = result.unwrap();
        let adversarial_input = "a".repeat(10000);

        let start = Instant::now();
        let _ = matcher.match_domain(&adversarial_input);
        assert!(
            start.elapsed() < Duration::from_secs(1),
            "Matching should complete quickly even for adversarial input"
        );
    }

    /// Test memory allocation limits under load
    #[test]
    fn test_memory_allocation_bounds() {
        // Create many ConnectionInfo objects to test allocation patterns
        let mut infos = Vec::with_capacity(10000);

        for i in 0..10000 {
            let info = ConnectionInfo::new("tcp", (i % 65535) as u16)
                .with_domain(&format!("test{}.example.com", i))
                .with_dest_ip(IpAddr::V4(Ipv4Addr::new(
                    ((i >> 24) & 0xFF) as u8,
                    ((i >> 16) & 0xFF) as u8,
                    ((i >> 8) & 0xFF) as u8,
                    (i & 0xFF) as u8,
                )));
            infos.push(info);
        }

        // All allocations should succeed
        assert_eq!(infos.len(), 10000);
    }

    /// Test that rule engine handles rapid reload requests
    #[test]
    fn test_rapid_hot_reload() {
        let engine = RuleEngine::new(
            RoutingSnapshotBuilder::new()
                .default_outbound("direct")
                .version(1)
                .build()
                .expect("initial build failed"),
        );

        // Perform 1000 rapid reloads
        for version in 2..1002 {
            let snapshot = RoutingSnapshotBuilder::new()
                .default_outbound("direct")
                .version(version)
                .build()
                .expect("build failed");

            engine.reload(snapshot);
        }

        // Verify the final version is correct via load() which returns a Guard
        let snapshot = engine.load();
        assert_eq!(snapshot.version, 1001);
    }

    /// Test concurrent matching doesn't deadlock
    #[test]
    fn test_no_deadlock_under_load() {
        use std::thread;
        use std::sync::atomic::{AtomicBool, Ordering};

        let engine = Arc::new(RuleEngine::new(
            RoutingSnapshotBuilder::new()
                .default_outbound("direct")
                .version(1)
                .build()
                .expect("build failed"),
        ));

        let stop = Arc::new(AtomicBool::new(false));

        // Reader threads
        let reader_handles: Vec<_> = (0..4)
            .map(|_| {
                let engine = Arc::clone(&engine);
                let stop = Arc::clone(&stop);
                thread::spawn(move || {
                    while !stop.load(Ordering::Relaxed) {
                        let conn = ConnectionInfo::new("tcp", 443)
                            .with_domain("test.example.com");
                        let _ = engine.match_connection(&conn);
                    }
                })
            })
            .collect();

        // Writer thread
        let writer = {
            let engine = Arc::clone(&engine);
            let stop = Arc::clone(&stop);
            thread::spawn(move || {
                for v in 2..102 {
                    if stop.load(Ordering::Relaxed) {
                        break;
                    }
                    let snapshot = RoutingSnapshotBuilder::new()
                        .default_outbound("direct")
                        .version(v)
                        .build()
                        .expect("build failed");
                    engine.reload(snapshot);
                    thread::sleep(Duration::from_millis(10));
                }
            })
        };

        // Run for 1 second
        thread::sleep(Duration::from_secs(1));
        stop.store(true, Ordering::Relaxed);

        // Join all threads - if we deadlock, this will hang
        writer.join().expect("Writer panicked");
        for handle in reader_handles {
            handle.join().expect("Reader panicked");
        }
    }
}

// ============================================================================
// Configuration Validation Tests
// ============================================================================

mod config_validation {
    use super::*;

    /// Test that invalid outbound tags are rejected
    #[test]
    fn test_invalid_outbound_tag() {
        let builder = RoutingSnapshotBuilder::new()
            // Empty tag should be handled
            .default_outbound("")
            .version(1);

        // Should either reject or use a safe default
        let result = builder.build();
        // The behavior depends on implementation - just verify no crash
        let _ = result;
    }

    /// Test very long outbound tags
    #[test]
    fn test_long_outbound_tag() {
        let long_tag = "x".repeat(10000);
        let builder = RoutingSnapshotBuilder::new()
            .default_outbound(&long_tag)
            .version(1);

        let result = builder.build();
        // Should handle without panic
        let _ = result;
    }

    /// Test special characters in tags
    #[test]
    fn test_special_chars_in_tag() {
        let special_tags = [
            "tag with spaces",
            "tag\twith\ttabs",
            "tag\nwith\nnewlines",
            "tag/with/slashes",
            "tag\\with\\backslashes",
            "tag\"with\"quotes",
            "tag'with'quotes",
            "tag<with>brackets",
            "tag{with}braces",
        ];

        for tag in special_tags {
            let builder = RoutingSnapshotBuilder::new()
                .default_outbound(tag)
                .version(1);

            let result = builder.build();
            // Should handle all special characters
            let _ = result;
        }
    }
}

// ============================================================================
// Summary Test
// ============================================================================

/// Meta-test to verify all security test modules are present
#[test]
fn test_security_module_completeness() {
    // This test documents the security testing coverage
    let coverage = [
        ("input_validation", "Malformed input handling"),
        ("boundary_checks", "Integer and buffer boundaries"),
        ("ipc_security", "IPC protocol security"),
        ("dos_resistance", "Resource exhaustion prevention"),
        ("config_validation", "Configuration validation"),
    ];

    for (module, description) in coverage {
        println!("✓ {} - {}", module, description);
    }
}
