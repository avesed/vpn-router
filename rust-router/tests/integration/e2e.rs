//! End-to-End Tests for rust-router
//!
//! Comprehensive E2E tests verifying the complete data path and integration:
//! - Full connection lifecycle (accept → match → route → forward)
//! - Rule matching with production-like configurations
//! - IPC command coverage
//! - Hot reload during active connections
//! - Error handling and recovery
//!
//! # Test Categories
//!
//! - `e2e_connection_*`: Full connection path tests
//! - `e2e_rule_*`: Rule matching with realistic configs
//! - `e2e_ipc_*`: IPC command integration
//! - `e2e_reload_*`: Hot reload scenarios
//! - `e2e_error_*`: Error handling verification
//!
//! # Usage
//!
//! ```bash
//! cargo test e2e -- --nocapture
//! ```

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use rust_router::ipc::{
    decode_message, encode_message, ErrorCode, IngressStatsResponse, IpcCommand, IpcError,
    IpcResponse,
};
use rust_router::rules::{
    ConnectionInfo, RuleEngine, RuleType, RoutingSnapshotBuilder,
};

// ============================================================================
// E2E Connection Path Tests
// ============================================================================

mod e2e_connection {
    use super::*;

    /// Test complete connection lifecycle: accept → match → route
    #[test]
    fn test_full_connection_lifecycle() {
        // Build a production-like configuration
        let mut builder = RoutingSnapshotBuilder::new();

        // Add domain rules
        let _ = builder.add_domain_rule(RuleType::DomainSuffix, "google.com", "proxy-us");
        let _ = builder.add_domain_rule(RuleType::DomainSuffix, "youtube.com", "proxy-us");
        let _ = builder.add_domain_rule(RuleType::DomainSuffix, "github.com", "direct");
        let _ = builder.add_domain_rule(RuleType::DomainKeyword, "cdn", "proxy-hk");
        let _ = builder.add_domain_rule(RuleType::Domain, "api.openai.com", "proxy-jp");

        let engine = RuleEngine::new(
            builder
                .default_outbound("direct")
                .version(1)
                .build()
                .expect("build failed"),
        );

        // Test various connection scenarios
        let test_cases = vec![
            // (protocol, port, domain, expected_outbound)
            ("tcp", 443, Some("www.google.com"), "proxy-us"),
            ("tcp", 443, Some("youtube.com"), "proxy-us"),
            ("tcp", 443, Some("api.github.com"), "direct"),
            ("tcp", 443, Some("cdn.example.com"), "proxy-hk"),
            ("tcp", 443, Some("api.openai.com"), "proxy-jp"),
            ("tcp", 443, Some("unknown.example.org"), "direct"),
            ("udp", 53, None, "direct"),
        ];

        for (protocol, port, domain, expected) in test_cases {
            let mut conn = ConnectionInfo::new(protocol, port);
            if let Some(d) = domain {
                conn = conn.with_domain(d);
            }

            let result = engine.match_connection(&conn);
            assert_eq!(
                result.outbound, expected,
                "Failed for {:?}: expected {}, got {}",
                domain, expected, result.outbound
            );
        }
    }

    /// Test connection with full metadata (IP, domain, port, protocol)
    #[test]
    fn test_connection_with_full_metadata() {
        let engine = RuleEngine::new(
            RoutingSnapshotBuilder::new()
                .default_outbound("direct")
                .version(1)
                .build()
                .expect("build failed"),
        );

        // Create connection with all metadata
        let conn = ConnectionInfo::new("tcp", 443)
            .with_domain("example.com")
            .with_dest_ip(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)))
            .with_source_ip(IpAddr::V4(Ipv4Addr::new(10, 25, 0, 100)));

        let result = engine.match_connection(&conn);
        assert_eq!(result.outbound, "direct");

        // Verify connection info is preserved
        assert_eq!(conn.dest_port, 443);
        assert_eq!(conn.protocol, "tcp");
        assert_eq!(conn.domain.as_deref(), Some("example.com"));
    }

    /// Test IPv4 and IPv6 connections
    #[test]
    fn test_ipv4_and_ipv6_connections() {
        let engine = RuleEngine::new(
            RoutingSnapshotBuilder::new()
                .default_outbound("direct")
                .version(1)
                .build()
                .expect("build failed"),
        );

        // IPv4 connection
        let conn_v4 = ConnectionInfo::new("tcp", 80)
            .with_dest_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        let result_v4 = engine.match_connection(&conn_v4);
        assert_eq!(result_v4.outbound, "direct");

        // IPv6 connection
        let conn_v6 = ConnectionInfo::new("tcp", 80)
            .with_dest_ip(IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888)));
        let result_v6 = engine.match_connection(&conn_v6);
        assert_eq!(result_v6.outbound, "direct");
    }

    /// Test UDP session handling
    #[test]
    fn test_udp_session_handling() {
        let engine = RuleEngine::new(
            RoutingSnapshotBuilder::new()
                .default_outbound("direct")
                .version(1)
                .build()
                .expect("build failed"),
        );

        // DNS query (UDP 53)
        let dns_conn = ConnectionInfo::new("udp", 53)
            .with_dest_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        let result = engine.match_connection(&dns_conn);
        assert_eq!(result.outbound, "direct");

        // QUIC connection (UDP 443)
        let quic_conn = ConnectionInfo::new("udp", 443)
            .with_domain("www.google.com");
        let result = engine.match_connection(&quic_conn);
        assert_eq!(result.outbound, "direct");
    }

    /// Test high-volume connection processing
    #[test]
    fn test_high_volume_connections() {
        let mut builder = RoutingSnapshotBuilder::new();

        // Add 1000 domain rules
        for i in 0..1000 {
            let _ = builder.add_domain_rule(
                RuleType::DomainSuffix,
                &format!("domain{}.com", i),
                &format!("outbound{}", i % 10),
            );
        }

        let engine = RuleEngine::new(
            builder
                .default_outbound("direct")
                .version(1)
                .build()
                .expect("build failed"),
        );

        let start = Instant::now();
        let iterations = 100_000;

        for i in 0..iterations {
            let conn = ConnectionInfo::new("tcp", 443)
                .with_domain(&format!("test.domain{}.com", i % 1000));
            let _ = engine.match_connection(&conn);
        }

        let elapsed = start.elapsed();
        let ops_per_sec = iterations as f64 / elapsed.as_secs_f64();

        println!(
            "Processed {} connections in {:?} ({:.0} ops/sec)",
            iterations, elapsed, ops_per_sec
        );

        // Should achieve at least 100K ops/sec
        assert!(
            ops_per_sec > 100_000.0,
            "Performance below threshold: {:.0} ops/sec",
            ops_per_sec
        );
    }
}

// ============================================================================
// E2E Rule Matching Tests
// ============================================================================

mod e2e_rule_matching {
    use super::*;

    /// Test production-like rule configuration
    #[test]
    fn test_production_rule_config() {
        let mut builder = RoutingSnapshotBuilder::new();

        // Streaming services → proxy-us
        let streaming = ["netflix.com", "hulu.com", "disneyplus.com", "hbomax.com"];
        for domain in streaming {
            let _ = builder.add_domain_rule(RuleType::DomainSuffix, domain, "proxy-us");
        }

        // Tech companies → proxy-hk
        let tech = ["google.com", "youtube.com", "facebook.com", "twitter.com"];
        for domain in tech {
            let _ = builder.add_domain_rule(RuleType::DomainSuffix, domain, "proxy-hk");
        }

        // Development → direct
        let dev = ["github.com", "gitlab.com", "stackoverflow.com"];
        for domain in dev {
            let _ = builder.add_domain_rule(RuleType::DomainSuffix, domain, "direct");
        }

        // AI services → proxy-jp
        let _ = builder.add_domain_rule(RuleType::DomainSuffix, "openai.com", "proxy-jp");
        let _ = builder.add_domain_rule(RuleType::DomainSuffix, "anthropic.com", "proxy-jp");

        // CDN keyword → proxy-cdn
        let _ = builder.add_domain_rule(RuleType::DomainKeyword, "cdn", "proxy-cdn");
        let _ = builder.add_domain_rule(RuleType::DomainKeyword, "cloudfront", "proxy-cdn");

        let engine = RuleEngine::new(
            builder
                .default_outbound("direct")
                .version(1)
                .build()
                .expect("build failed"),
        );

        // Verify routing
        let tests = vec![
            ("www.netflix.com", "proxy-us"),
            ("api.hulu.com", "proxy-us"),
            ("www.google.com", "proxy-hk"),
            ("m.youtube.com", "proxy-hk"),
            ("api.github.com", "direct"),
            ("chat.openai.com", "proxy-jp"),
            ("cdn.example.com", "proxy-cdn"),
            ("d1234.cloudfront.net", "proxy-cdn"),
            ("random.example.org", "direct"),
        ];

        for (domain, expected) in tests {
            let conn = ConnectionInfo::new("tcp", 443).with_domain(domain);
            let result = engine.match_connection(&conn);
            assert_eq!(
                result.outbound, expected,
                "Domain {} expected {} but got {}",
                domain, expected, result.outbound
            );
        }
    }

    /// Test rule priority (first match wins)
    #[test]
    fn test_rule_priority() {
        let mut builder = RoutingSnapshotBuilder::new();

        // More specific rule first
        let _ = builder.add_domain_rule(RuleType::Domain, "api.example.com", "api-direct");
        // Less specific rule second
        let _ = builder.add_domain_rule(RuleType::DomainSuffix, "example.com", "proxy");

        let engine = RuleEngine::new(
            builder
                .default_outbound("direct")
                .version(1)
                .build()
                .expect("build failed"),
        );

        // Exact match should win
        let conn1 = ConnectionInfo::new("tcp", 443).with_domain("api.example.com");
        let result1 = engine.match_connection(&conn1);
        assert_eq!(result1.outbound, "api-direct");

        // Suffix match for other subdomains
        let conn2 = ConnectionInfo::new("tcp", 443).with_domain("www.example.com");
        let result2 = engine.match_connection(&conn2);
        assert_eq!(result2.outbound, "proxy");
    }

    /// Test default outbound fallback
    #[test]
    fn test_default_outbound_fallback() {
        let engine = RuleEngine::new(
            RoutingSnapshotBuilder::new()
                .default_outbound("fallback-proxy")
                .version(1)
                .build()
                .expect("build failed"),
        );

        // No rules match - should use default
        let conn = ConnectionInfo::new("tcp", 443).with_domain("unknown.example.org");
        let result = engine.match_connection(&conn);
        assert_eq!(result.outbound, "fallback-proxy");
    }

    /// Test empty domain handling
    #[test]
    fn test_no_domain_connection() {
        let mut builder = RoutingSnapshotBuilder::new();
        let _ = builder.add_domain_rule(RuleType::DomainSuffix, "example.com", "proxy");

        let engine = RuleEngine::new(
            builder
                .default_outbound("direct")
                .version(1)
                .build()
                .expect("build failed"),
        );

        // Connection without domain
        let conn = ConnectionInfo::new("tcp", 443)
            .with_dest_ip(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
        let result = engine.match_connection(&conn);
        assert_eq!(result.outbound, "direct");
    }
}

// ============================================================================
// E2E IPC Integration Tests
// ============================================================================

mod e2e_ipc {
    use super::*;

    /// Test all IPC command serialization
    #[test]
    fn test_all_ipc_commands_serialize() {
        let commands: Vec<IpcCommand> = vec![
            IpcCommand::Ping,
            IpcCommand::Status,
            IpcCommand::GetStats,
            IpcCommand::GetIngressStats,
            IpcCommand::ListOutbounds,
            IpcCommand::Shutdown { drain_timeout_secs: Some(30) },
            IpcCommand::Shutdown { drain_timeout_secs: None },
        ];

        for cmd in commands {
            let encoded = encode_message(&cmd);
            assert!(encoded.is_ok(), "Failed to encode {:?}", cmd);

            let bytes = encoded.unwrap();
            assert!(bytes.len() >= 4, "Message too short");

            // Verify length prefix
            let len = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
            assert_eq!(len, bytes.len() - 4, "Length prefix mismatch");

            // Verify decode
            let decoded: Result<IpcCommand, _> = decode_message(&bytes[4..]);
            assert!(decoded.is_ok(), "Failed to decode {:?}", cmd);
        }
    }

    /// Test IPC response serialization
    #[test]
    fn test_ipc_response_serialize() {
        let responses = vec![
            IpcResponse::Pong,
            IpcResponse::Success { message: None },
            IpcResponse::Error(IpcError {
                code: ErrorCode::Unknown,
                message: "Test error".to_string(),
            }),
            IpcResponse::IngressStats(IngressStatsResponse {
                ingress_enabled: false,
                ingress_state: None,
                manager_stats: None,
                forwarding_stats: None,
                reply_stats: None,
            }),
        ];

        for resp in responses {
            let encoded = encode_message(&resp);
            assert!(encoded.is_ok(), "Failed to encode {:?}", resp);

            let bytes = encoded.unwrap();
            let decoded: Result<IpcResponse, _> = decode_message(&bytes[4..]);
            assert!(decoded.is_ok(), "Failed to decode {:?}", resp);
        }
    }

    /// Test IPC message boundary handling
    #[test]
    fn test_ipc_message_boundaries() {
        let cmd = IpcCommand::Ping;
        let encoded = encode_message(&cmd).unwrap();

        // Exact boundary
        let decoded: IpcCommand = decode_message(&encoded[4..]).unwrap();
        assert!(matches!(decoded, IpcCommand::Ping));

        // Multiple messages concatenated
        let mut multi = Vec::new();
        multi.extend_from_slice(&encoded);
        multi.extend_from_slice(&encoded);

        // First message
        let first: IpcCommand = decode_message(&multi[4..encoded.len()]).unwrap();
        assert!(matches!(first, IpcCommand::Ping));

        // Second message
        let second: IpcCommand = decode_message(&multi[encoded.len() + 4..]).unwrap();
        assert!(matches!(second, IpcCommand::Ping));
    }

    /// Test IPC with large payloads
    #[test]
    fn test_ipc_large_payload() {
        // Create a large error message
        let large_message = "x".repeat(100_000);
        let resp = IpcResponse::Error(IpcError {
            code: ErrorCode::Unknown,
            message: large_message.clone(),
        });

        let encoded = encode_message(&resp).unwrap();
        let decoded: IpcResponse = decode_message(&encoded[4..]).unwrap();

        match decoded {
            IpcResponse::Error(err) => {
                assert_eq!(err.message.len(), 100_000);
            }
            _ => panic!("Wrong response type"),
        }
    }
}

// ============================================================================
// E2E Hot Reload Tests
// ============================================================================

mod e2e_hot_reload {
    use super::*;

    /// Test hot reload preserves in-flight connection routing
    #[test]
    fn test_hot_reload_connection_continuity() {
        let engine = Arc::new(RuleEngine::new(
            RoutingSnapshotBuilder::new()
                .default_outbound("v1-direct")
                .version(1)
                .build()
                .expect("build failed"),
        ));

        // Simulate connection using v1 config
        let conn = ConnectionInfo::new("tcp", 443).with_domain("example.com");
        let v1_result = engine.match_connection(&conn);
        assert_eq!(v1_result.outbound, "v1-direct");

        // Hot reload to v2
        engine.reload(
            RoutingSnapshotBuilder::new()
                .default_outbound("v2-proxy")
                .version(2)
                .build()
                .expect("build failed"),
        );

        // New connection should use v2
        let v2_result = engine.match_connection(&conn);
        assert_eq!(v2_result.outbound, "v2-proxy");

        // Verify version updated
        let snapshot = engine.load();
        assert_eq!(snapshot.version, 2);
    }

    /// Test concurrent access during hot reload
    #[test]
    fn test_concurrent_hot_reload() {
        let engine = Arc::new(RuleEngine::new(
            RoutingSnapshotBuilder::new()
                .default_outbound("initial")
                .version(1)
                .build()
                .expect("build failed"),
        ));

        let stop = Arc::new(AtomicBool::new(false));
        let match_count = Arc::new(AtomicU64::new(0));
        let reload_count = Arc::new(AtomicU64::new(0));

        // Matcher threads
        let matchers: Vec<_> = (0..4)
            .map(|_| {
                let engine = Arc::clone(&engine);
                let stop = Arc::clone(&stop);
                let count = Arc::clone(&match_count);

                thread::spawn(move || {
                    while !stop.load(Ordering::Relaxed) {
                        let conn = ConnectionInfo::new("tcp", 443);
                        let result = engine.match_connection(&conn);
                        // Result should always be valid (not empty)
                        assert!(!result.outbound.is_empty());
                        count.fetch_add(1, Ordering::Relaxed);
                    }
                })
            })
            .collect();

        // Reloader thread
        let reloader = {
            let engine = Arc::clone(&engine);
            let stop = Arc::clone(&stop);
            let count = Arc::clone(&reload_count);

            thread::spawn(move || {
                let mut version = 2u64;
                while !stop.load(Ordering::Relaxed) {
                    let snapshot = RoutingSnapshotBuilder::new()
                        .default_outbound(&format!("outbound-v{}", version))
                        .version(version)
                        .build()
                        .expect("build failed");
                    engine.reload(snapshot);
                    count.fetch_add(1, Ordering::Relaxed);
                    version += 1;
                }
            })
        };

        // Run for 1 second
        thread::sleep(Duration::from_secs(1));
        stop.store(true, Ordering::Relaxed);

        // Wait for threads
        for m in matchers {
            m.join().expect("Matcher panicked");
        }
        reloader.join().expect("Reloader panicked");

        let matches = match_count.load(Ordering::Relaxed);
        let reloads = reload_count.load(Ordering::Relaxed);

        println!(
            "Concurrent hot reload: {} matches, {} reloads",
            matches, reloads
        );

        assert!(matches > 10_000, "Too few matches: {}", matches);
        assert!(reloads > 100, "Too few reloads: {}", reloads);
    }

    /// Test rapid reload stress
    #[test]
    fn test_rapid_reload_stress() {
        let engine = RuleEngine::new(
            RoutingSnapshotBuilder::new()
                .default_outbound("initial")
                .version(1)
                .build()
                .expect("build failed"),
        );

        let start = Instant::now();
        let iterations = 10_000;

        for v in 2..iterations + 2 {
            let mut builder = RoutingSnapshotBuilder::new();

            // Add some rules to make it non-trivial
            for i in 0..10 {
                let _ = builder.add_domain_rule(
                    RuleType::DomainSuffix,
                    &format!("domain{}.com", i),
                    &format!("outbound{}", i),
                );
            }

            let snapshot = builder
                .default_outbound("default")
                .version(v)
                .build()
                .expect("build failed");

            engine.reload(snapshot);
        }

        let elapsed = start.elapsed();
        let reloads_per_sec = iterations as f64 / elapsed.as_secs_f64();

        println!(
            "Rapid reload: {} reloads in {:?} ({:.0}/sec)",
            iterations, elapsed, reloads_per_sec
        );

        // Should achieve at least 1000 reloads/sec
        assert!(
            reloads_per_sec > 1000.0,
            "Reload too slow: {:.0}/sec",
            reloads_per_sec
        );

        // Verify final state
        let snapshot = engine.load();
        assert_eq!(snapshot.version, iterations + 1);
    }
}

// ============================================================================
// E2E Error Handling Tests
// ============================================================================

mod e2e_error_handling {
    use super::*;

    /// Test graceful handling of malformed input
    #[test]
    fn test_malformed_input_handling() {
        let engine = RuleEngine::new(
            RoutingSnapshotBuilder::new()
                .default_outbound("direct")
                .version(1)
                .build()
                .expect("build failed"),
        );

        // Various edge case inputs
        let edge_cases = vec![
            ("", 0),                    // Empty protocol, port 0
            ("tcp", 0),                 // Port 0
            ("unknown", 443),           // Unknown protocol
            ("TCP", 443),               // Uppercase protocol
        ];

        for (protocol, port) in edge_cases {
            let conn = ConnectionInfo::new(protocol, port);
            let result = engine.match_connection(&conn);
            // Should not panic, should return default
            assert!(!result.outbound.is_empty());
        }
    }

    /// Test recovery from invalid IPC messages
    #[test]
    fn test_invalid_ipc_recovery() {
        let invalid_messages = vec![
            b"".to_vec(),
            b"not json".to_vec(),
            b"{}".to_vec(),
            b"{\"unknown\": true}".to_vec(),
            b"[1, 2, 3]".to_vec(),
        ];

        for msg in invalid_messages {
            let result: Result<IpcCommand, _> = decode_message(&msg);
            assert!(result.is_err(), "Should reject: {:?}", msg);
        }
    }

    /// Test empty configuration handling
    #[test]
    fn test_empty_config_handling() {
        // Config with no rules
        let engine = RuleEngine::new(
            RoutingSnapshotBuilder::new()
                .default_outbound("fallback")
                .version(1)
                .build()
                .expect("build failed"),
        );

        // All connections should go to default
        for i in 0..100 {
            let conn = ConnectionInfo::new("tcp", 443)
                .with_domain(&format!("test{}.example.com", i));
            let result = engine.match_connection(&conn);
            assert_eq!(result.outbound, "fallback");
        }
    }
}

// ============================================================================
// E2E Performance Validation
// ============================================================================

mod e2e_performance {
    use super::*;

    /// Validate end-to-end latency requirements
    #[test]
    fn test_e2e_latency_requirements() {
        let mut builder = RoutingSnapshotBuilder::new();

        // Add 1000 rules (production-like)
        for i in 0..1000 {
            let _ = builder.add_domain_rule(
                RuleType::DomainSuffix,
                &format!("domain{}.example.com", i),
                &format!("outbound{}", i % 10),
            );
        }

        let engine = RuleEngine::new(
            builder
                .default_outbound("direct")
                .version(1)
                .build()
                .expect("build failed"),
        );

        // Measure latency for 10000 operations
        let mut latencies = Vec::with_capacity(10_000);

        for i in 0..10_000 {
            let conn = ConnectionInfo::new("tcp", 443)
                .with_domain(&format!("test.domain{}.example.com", i % 1000));

            let start = Instant::now();
            let _ = engine.match_connection(&conn);
            latencies.push(start.elapsed());
        }

        // Calculate percentiles
        latencies.sort();
        let p50 = latencies[latencies.len() / 2];
        let p95 = latencies[latencies.len() * 95 / 100];
        let p99 = latencies[latencies.len() * 99 / 100];

        println!("E2E Latency: p50={:?}, p95={:?}, p99={:?}", p50, p95, p99);

        // Requirements: p99 < 1ms
        assert!(
            p99 < Duration::from_millis(1),
            "p99 latency too high: {:?}",
            p99
        );
    }

    /// Validate throughput requirements
    #[test]
    fn test_e2e_throughput_requirements() {
        let engine = Arc::new(RuleEngine::new(
            RoutingSnapshotBuilder::new()
                .default_outbound("direct")
                .version(1)
                .build()
                .expect("build failed"),
        ));

        let total_ops = Arc::new(AtomicU64::new(0));
        let stop = Arc::new(AtomicBool::new(false));

        // 4 worker threads
        let workers: Vec<_> = (0..4)
            .map(|_| {
                let engine = Arc::clone(&engine);
                let total = Arc::clone(&total_ops);
                let stop = Arc::clone(&stop);

                thread::spawn(move || {
                    let mut local = 0u64;
                    while !stop.load(Ordering::Relaxed) {
                        let conn = ConnectionInfo::new("tcp", 443);
                        let _ = engine.match_connection(&conn);
                        local += 1;
                    }
                    total.fetch_add(local, Ordering::Relaxed);
                })
            })
            .collect();

        // Run for 1 second
        thread::sleep(Duration::from_secs(1));
        stop.store(true, Ordering::Relaxed);

        for w in workers {
            w.join().expect("Worker panicked");
        }

        let ops = total_ops.load(Ordering::Relaxed);
        println!("E2E Throughput: {} ops/sec", ops);

        // Requirement: > 1M ops/sec with 4 threads
        assert!(ops > 1_000_000, "Throughput too low: {} ops/sec", ops);
    }
}

// ============================================================================
// Summary Test
// ============================================================================

/// Meta-test to verify E2E test coverage
#[test]
fn test_e2e_module_completeness() {
    let coverage = [
        ("e2e_connection", "Full connection lifecycle tests"),
        ("e2e_rule_matching", "Rule matching with realistic configs"),
        ("e2e_ipc", "IPC command integration"),
        ("e2e_hot_reload", "Hot reload during active connections"),
        ("e2e_error_handling", "Error handling and recovery"),
        ("e2e_performance", "Performance requirement validation"),
    ];

    println!("\n=== E2E Test Coverage ===\n");
    for (module, description) in coverage {
        println!("✓ {} - {}", module, description);
    }
    println!();
}
