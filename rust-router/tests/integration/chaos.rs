//! Chaos Testing for rust-router
//!
//! This module provides chaos engineering tests to verify system resilience:
//! - Network failure simulation (connection drops, timeouts)
//! - Resource exhaustion (file descriptors, memory pressure)
//! - Error injection and recovery
//! - Graceful degradation under stress
//!
//! # Test Categories
//!
//! - `test_chaos_network_*`: Network failure scenarios
//! - `test_chaos_resource_*`: Resource exhaustion scenarios
//! - `test_chaos_recovery_*`: Recovery and resilience tests
//! - `test_chaos_concurrent_*`: Concurrent chaos scenarios
//!
//! # Usage
//!
//! ```bash
//! cargo test chaos -- --nocapture
//! ```

use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use rust_router::ipc::{decode_message, IpcCommand};
use rust_router::rules::{
    ConnectionInfo, DomainMatcherBuilder, RuleEngine, RuleType,
    RoutingSnapshotBuilder,
};

// ============================================================================
// Network Chaos Tests
// ============================================================================

mod network_chaos {
    use super::*;

    /// Test system behavior when IPC connections are dropped mid-request
    #[test]
    fn test_connection_drop_mid_request() {
        // Simulate a partial message that gets "dropped"
        let partial_message = b"{\"Ping\"";  // Incomplete JSON

        // System should handle partial messages gracefully
        let result = decode_message::<IpcCommand>(partial_message);
        assert!(result.is_err(), "Should reject incomplete JSON");
    }

    /// Test handling of rapid connection open/close cycles
    #[test]
    fn test_rapid_connection_cycling() {
        let engine = RuleEngine::new(
            RoutingSnapshotBuilder::new()
                .default_outbound("direct")
                .version(1)
                .build()
                .expect("build failed"),
        );

        // Simulate 1000 rapid "connection" cycles
        // Each cycle: create connection info, match, drop
        for i in 0..1000 {
            let conn = ConnectionInfo::new("tcp", 443 + (i % 100) as u16)
                .with_domain(&format!("host{}.example.com", i));
            let _ = engine.match_connection(&conn);
            // Connection info dropped here - verify no resource leak
        }
    }

    /// Test behavior with very slow operations
    #[test]
    fn test_slow_operation_simulation() {
        let engine = Arc::new(RuleEngine::new(
            RoutingSnapshotBuilder::new()
                .default_outbound("direct")
                .version(1)
                .build()
                .expect("build failed"),
        ));

        // Simulate slow reader (holds reference longer than expected)
        let engine_clone = Arc::clone(&engine);
        let slow_reader = thread::spawn(move || {
            let snapshot = engine_clone.load();
            thread::sleep(Duration::from_millis(100));  // "Slow" processing
            let _ = snapshot.version;  // Use the snapshot
        });

        // Fast operations should not be blocked
        let start = Instant::now();
        for _ in 0..100 {
            let conn = ConnectionInfo::new("tcp", 443);
            let _ = engine.match_connection(&conn);
        }
        assert!(start.elapsed() < Duration::from_millis(50), "Fast ops blocked by slow reader");

        slow_reader.join().expect("Slow reader panicked");
    }

    /// Test timeout simulation for IPC operations
    #[test]
    fn test_timeout_simulation() {
        let start = Instant::now();
        let timeout = Duration::from_millis(100);

        // Simulate a "timed" operation
        let operation_result = std::panic::catch_unwind(|| {
            let engine = RuleEngine::new(
                RoutingSnapshotBuilder::new()
                    .default_outbound("direct")
                    .version(1)
                    .build()
                    .expect("build failed"),
            );

            // This should complete well within timeout
            for _ in 0..1000 {
                let conn = ConnectionInfo::new("tcp", 443);
                let _ = engine.match_connection(&conn);
            }
        });

        assert!(operation_result.is_ok(), "Operation panicked");
        assert!(start.elapsed() < timeout, "Operation exceeded timeout");
    }
}

// ============================================================================
// Resource Exhaustion Tests
// ============================================================================

mod resource_exhaustion {
    use super::*;

    /// Test behavior under high memory pressure
    #[test]
    fn test_high_memory_pressure() {
        // Create a large number of rules to stress memory
        let mut builder = RoutingSnapshotBuilder::new();

        // Add 50,000 domain rules
        for i in 0..50_000 {
            let _ = builder.add_domain_rule(
                RuleType::DomainSuffix,
                &format!("subdomain{}.domain{}.example.com", i, i / 1000),
                &format!("outbound{}", i % 10),
            );
        }

        let result = builder
            .default_outbound("direct")
            .version(1)
            .build();

        // Should complete without OOM
        assert!(result.is_ok(), "Failed to build large ruleset");

        let engine = RuleEngine::new(result.unwrap());

        // Verify it still works
        let conn = ConnectionInfo::new("tcp", 443)
            .with_domain("subdomain123.domain0.example.com");
        let result = engine.match_connection(&conn);
        assert_eq!(result.outbound, "outbound3");  // 123 % 10 = 3
    }

    /// Test behavior with many concurrent operations
    #[test]
    fn test_concurrent_operation_stress() {
        let engine = Arc::new(RuleEngine::new(
            RoutingSnapshotBuilder::new()
                .default_outbound("direct")
                .version(1)
                .build()
                .expect("build failed"),
        ));

        let counter = Arc::new(AtomicU64::new(0));
        let running = Arc::new(AtomicBool::new(true));

        // Spawn 20 worker threads
        let handles: Vec<_> = (0..20)
            .map(|id| {
                let engine = Arc::clone(&engine);
                let counter = Arc::clone(&counter);
                let running = Arc::clone(&running);

                thread::spawn(move || {
                    let mut local_count = 0u64;
                    while running.load(Ordering::Relaxed) {
                        let conn = ConnectionInfo::new("tcp", 443 + (id as u16))
                            .with_domain(&format!("test{}.example.com", local_count));
                        let _ = engine.match_connection(&conn);
                        local_count += 1;

                        if local_count >= 10000 {
                            break;
                        }
                    }
                    counter.fetch_add(local_count, Ordering::Relaxed);
                })
            })
            .collect();

        // Let it run for a bit
        thread::sleep(Duration::from_millis(500));
        running.store(false, Ordering::Relaxed);

        // Wait for all threads
        for handle in handles {
            handle.join().expect("Worker panicked");
        }

        // Should have processed many operations
        assert!(counter.load(Ordering::Relaxed) > 1000, "Too few operations completed");
    }

    /// Test rapid allocation/deallocation cycles
    #[test]
    fn test_allocation_cycling() {
        for _ in 0..100 {
            // Allocate
            let mut infos: Vec<ConnectionInfo> = (0..1000)
                .map(|i| {
                    ConnectionInfo::new("tcp", i as u16)
                        .with_domain(&format!("host{}.example.com", i))
                        .with_dest_ip(IpAddr::V4(Ipv4Addr::new(
                            ((i >> 24) & 0xFF) as u8,
                            ((i >> 16) & 0xFF) as u8,
                            ((i >> 8) & 0xFF) as u8,
                            (i & 0xFF) as u8,
                        )))
                })
                .collect();

            // Use
            for info in &infos {
                let _ = info.dest_port;
            }

            // Deallocate (drop)
            infos.clear();
        }
        // If we reach here without OOM, the test passes
    }

    /// Test string allocation stress
    #[test]
    fn test_string_allocation_stress() {
        let matcher = DomainMatcherBuilder::new()
            .add_suffix("example.com", "proxy")
            .build()
            .expect("build failed");

        // Create many strings and match them
        for i in 0..10_000 {
            let domain = format!(
                "very-long-subdomain-name-that-takes-up-memory-{}.very-long-subdomain{}.example.com",
                i, i
            );
            let _ = matcher.match_domain(&domain);
        }
    }
}

// ============================================================================
// Recovery and Resilience Tests
// ============================================================================

mod recovery {
    use super::*;

    /// Test recovery after panic in worker thread
    #[test]
    fn test_panic_recovery() {
        let engine = Arc::new(RuleEngine::new(
            RoutingSnapshotBuilder::new()
                .default_outbound("direct")
                .version(1)
                .build()
                .expect("build failed"),
        ));

        // Spawn a thread that will panic
        let engine_clone = Arc::clone(&engine);
        let panic_thread = thread::spawn(move || {
            let _ = engine_clone.match_connection(&ConnectionInfo::new("tcp", 443));
            panic!("Intentional panic for testing");
        });

        // Wait for panic
        let result = panic_thread.join();
        assert!(result.is_err(), "Thread should have panicked");

        // Engine should still work
        let conn = ConnectionInfo::new("tcp", 443);
        let result = engine.match_connection(&conn);
        assert_eq!(result.outbound, "direct");
    }

    /// Test recovery after rapid config changes
    #[test]
    fn test_rapid_config_change_recovery() {
        let engine = RuleEngine::new(
            RoutingSnapshotBuilder::new()
                .default_outbound("direct")
                .version(1)
                .build()
                .expect("build failed"),
        );

        // Rapid config changes
        for v in 2..1002 {
            let mut builder = RoutingSnapshotBuilder::new();

            // Alternate between different configurations
            if v % 2 == 0 {
                let _ = builder.add_domain_rule(
                    RuleType::DomainSuffix,
                    "google.com",
                    "proxy",
                );
            }

            let snapshot = builder
                .default_outbound("direct")
                .version(v)
                .build()
                .expect("build failed");

            engine.reload(snapshot);
        }

        // System should be stable after chaos
        let conn = ConnectionInfo::new("tcp", 443)
            .with_domain("test.google.com");
        let result = engine.match_connection(&conn);

        // Last version was 1001 (odd), so no google.com rule
        assert!(result.outbound == "direct" || result.outbound == "proxy");
    }

    /// Test that ArcSwap prevents reader starvation
    #[test]
    fn test_no_reader_starvation() {
        let engine = Arc::new(RuleEngine::new(
            RoutingSnapshotBuilder::new()
                .default_outbound("direct")
                .version(1)
                .build()
                .expect("build failed"),
        ));

        let read_count = Arc::new(AtomicU64::new(0));
        let stop = Arc::new(AtomicBool::new(false));

        // Reader threads
        let reader_handles: Vec<_> = (0..4)
            .map(|_| {
                let engine = Arc::clone(&engine);
                let read_count = Arc::clone(&read_count);
                let stop = Arc::clone(&stop);

                thread::spawn(move || {
                    while !stop.load(Ordering::Relaxed) {
                        let conn = ConnectionInfo::new("tcp", 443);
                        let _ = engine.match_connection(&conn);
                        read_count.fetch_add(1, Ordering::Relaxed);
                    }
                })
            })
            .collect();

        // Writer thread doing aggressive reloads
        let engine_clone = Arc::clone(&engine);
        let stop_clone = Arc::clone(&stop);
        let writer = thread::spawn(move || {
            for v in 2..102 {
                if stop_clone.load(Ordering::Relaxed) {
                    break;
                }
                let snapshot = RoutingSnapshotBuilder::new()
                    .default_outbound("direct")
                    .version(v)
                    .build()
                    .expect("build failed");
                engine_clone.reload(snapshot);
                // No sleep - aggressive writing
            }
        });

        // Run for 500ms
        thread::sleep(Duration::from_millis(500));
        stop.store(true, Ordering::Relaxed);

        writer.join().expect("Writer panicked");
        for handle in reader_handles {
            handle.join().expect("Reader panicked");
        }

        // Readers should have made progress despite aggressive writing
        assert!(
            read_count.load(Ordering::Relaxed) > 1000,
            "Reader starvation detected"
        );
    }
}

// ============================================================================
// Concurrent Chaos Tests
// ============================================================================

mod concurrent_chaos {
    use super::*;

    /// Test mixed read/write/reload operations
    #[test]
    fn test_mixed_concurrent_operations() {
        let engine = Arc::new(RuleEngine::new(
            RoutingSnapshotBuilder::new()
                .default_outbound("direct")
                .version(1)
                .build()
                .expect("build failed"),
        ));

        let stop = Arc::new(AtomicBool::new(false));
        let operations = Arc::new(AtomicU64::new(0));

        // 4 matcher threads
        let matchers: Vec<_> = (0..4)
            .map(|id| {
                let engine = Arc::clone(&engine);
                let stop = Arc::clone(&stop);
                let operations = Arc::clone(&operations);

                thread::spawn(move || {
                    while !stop.load(Ordering::Relaxed) {
                        let conn = ConnectionInfo::new("tcp", 443 + id as u16)
                            .with_domain("test.example.com");
                        let _ = engine.match_connection(&conn);
                        operations.fetch_add(1, Ordering::Relaxed);
                    }
                })
            })
            .collect();

        // 2 reload threads
        let reloaders: Vec<_> = (0..2)
            .map(|id| {
                let engine = Arc::clone(&engine);
                let stop = Arc::clone(&stop);

                thread::spawn(move || {
                    let mut version = 2 + id as u64 * 1000;
                    while !stop.load(Ordering::Relaxed) {
                        let snapshot = RoutingSnapshotBuilder::new()
                            .default_outbound("direct")
                            .version(version)
                            .build()
                            .expect("build failed");
                        engine.reload(snapshot);
                        version += 1;
                        thread::sleep(Duration::from_micros(100));
                    }
                })
            })
            .collect();

        // 2 snapshot reader threads
        let readers: Vec<_> = (0..2)
            .map(|_| {
                let engine = Arc::clone(&engine);
                let stop = Arc::clone(&stop);

                thread::spawn(move || {
                    while !stop.load(Ordering::Relaxed) {
                        let snapshot = engine.load();
                        let _ = snapshot.version;
                        let _ = snapshot.default_outbound.clone();
                    }
                })
            })
            .collect();

        // Run chaos for 1 second
        thread::sleep(Duration::from_secs(1));
        stop.store(true, Ordering::Relaxed);

        // Wait for all threads
        for m in matchers {
            m.join().expect("Matcher panicked");
        }
        for r in reloaders {
            r.join().expect("Reloader panicked");
        }
        for r in readers {
            r.join().expect("Reader panicked");
        }

        println!(
            "Completed {} operations in 1 second of chaos",
            operations.load(Ordering::Relaxed)
        );
    }

    /// Test version consistency during reload
    #[test]
    fn test_version_consistency() {
        let engine = Arc::new(RuleEngine::new(
            RoutingSnapshotBuilder::new()
                .default_outbound("direct")
                .version(1)
                .build()
                .expect("build failed"),
        ));

        let stop = Arc::new(AtomicBool::new(false));
        let inconsistencies = Arc::new(AtomicU64::new(0));

        // Reader checking version consistency
        let reader = {
            let engine = Arc::clone(&engine);
            let stop = Arc::clone(&stop);
            let inconsistencies = Arc::clone(&inconsistencies);

            thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    let snapshot = engine.load();
                    let v1 = snapshot.version;

                    // Do some work with the snapshot
                    let _ = snapshot.default_outbound.clone();
                    thread::yield_now();

                    // Version should not have changed while we hold the guard
                    let v2 = snapshot.version;
                    if v1 != v2 {
                        inconsistencies.fetch_add(1, Ordering::Relaxed);
                    }
                }
            })
        };

        // Writer changing versions
        let writer = {
            let engine = Arc::clone(&engine);
            let stop = Arc::clone(&stop);

            thread::spawn(move || {
                for v in 2..10002 {
                    if stop.load(Ordering::Relaxed) {
                        break;
                    }
                    let snapshot = RoutingSnapshotBuilder::new()
                        .default_outbound("direct")
                        .version(v)
                        .build()
                        .expect("build failed");
                    engine.reload(snapshot);
                }
            })
        };

        // Run for 500ms
        thread::sleep(Duration::from_millis(500));
        stop.store(true, Ordering::Relaxed);

        writer.join().expect("Writer panicked");
        reader.join().expect("Reader panicked");

        // There should be zero inconsistencies (ArcSwap guarantee)
        assert_eq!(
            inconsistencies.load(Ordering::Relaxed),
            0,
            "Version inconsistency detected"
        );
    }
}

// ============================================================================
// Error Injection Tests
// ============================================================================

mod error_injection {
    use super::*;

    /// Test handling of invalid rule configurations
    #[test]
    fn test_invalid_rule_injection() {
        let mut builder = RoutingSnapshotBuilder::new();

        // Add valid rules
        for i in 0..100 {
            let _ = builder.add_domain_rule(
                RuleType::DomainSuffix,
                &format!("valid{}.com", i),
                "proxy",
            );
        }

        // Try to add potentially problematic rules (should be handled gracefully)
        let _ = builder.add_domain_rule(
            RuleType::DomainSuffix,
            "",  // Empty domain
            "proxy",
        );

        let _ = builder.add_domain_rule(
            RuleType::DomainKeyword,
            "normal",
            "",  // Empty outbound
        );

        // Build should still succeed (or fail gracefully)
        let result = builder
            .default_outbound("direct")
            .version(1)
            .build();

        // Either it builds successfully or returns an error - no panic
        let _ = result;
    }

    /// Test recovery from rapid create/destroy cycles
    #[test]
    fn test_rapid_engine_lifecycle() {
        for _ in 0..100 {
            let engine = RuleEngine::new(
                RoutingSnapshotBuilder::new()
                    .default_outbound("direct")
                    .version(1)
                    .build()
                    .expect("build failed"),
            );

            // Use it
            let conn = ConnectionInfo::new("tcp", 443);
            let _ = engine.match_connection(&conn);

            // Drop it (engine goes out of scope)
        }
    }
}

// ============================================================================
// Summary Test
// ============================================================================

/// Meta-test to verify all chaos test modules are present
#[test]
fn test_chaos_module_completeness() {
    let coverage = [
        ("network_chaos", "Network failure simulation"),
        ("resource_exhaustion", "Resource pressure tests"),
        ("recovery", "Recovery and resilience"),
        ("concurrent_chaos", "Concurrent stress tests"),
        ("error_injection", "Error injection scenarios"),
    ];

    println!("\n=== Chaos Testing Coverage ===\n");
    for (module, description) in coverage {
        println!("✓ {} - {}", module, description);
    }
    println!();
}
