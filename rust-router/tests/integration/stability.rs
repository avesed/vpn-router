//! Stability Tests for rust-router
//!
//! This module contains stability and stress tests for production deployment verification.
//! These tests are designed for 1C1G VPS environment constraints.
//!
//! # Test Categories
//!
//! 1. **Connection Stability**: Verify connection lifecycle under sustained load
//! 2. **Memory Stability**: Detect memory leaks over time
//! 3. **Hot Reload Stability**: Test configuration reload under load
//! 4. **IPC Pressure**: High-frequency IPC command handling
//! 5. **Concurrent Operations**: Race condition and deadlock detection
//!
//! # Running Tests
//!
//! ```bash
//! # Run all stability tests
//! cargo test --test integration_tests stability
//!
//! # Run with timing output
//! cargo test --test integration_tests stability -- --nocapture
//!
//! # Run long-running stress tests (marked with #[ignore])
//! cargo test --test integration_tests stability -- --ignored
//! ```
//!
//! # 1C1G Resource Targets
//!
//! - Memory (idle): < 60 MB
//! - Memory (load): < 150 MB
//! - IPC latency: < 100 μs
//! - Connection overhead: < 20 KB per connection

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

// ============================================================================
// Constants for Test Configuration
// ============================================================================

/// Number of iterations for light stress tests
const LIGHT_ITERATIONS: usize = 1_000;

/// Number of iterations for medium stress tests
const MEDIUM_ITERATIONS: usize = 5_000;

/// Number of iterations for heavy stress tests
const HEAVY_ITERATIONS: usize = 10_000;

/// Number of concurrent tasks for parallel tests
const CONCURRENT_TASK_COUNT: usize = 20;

/// Default sniff timeout in milliseconds
const DEFAULT_SNIFF_TIMEOUT_MS: u64 = 300;

/// IPC latency threshold in nanoseconds (1μs)
const IPC_LATENCY_THRESHOLD_NS: u128 = 1000;

/// Extended IPC latency threshold for complex operations (10μs)
const IPC_EXTENDED_LATENCY_THRESHOLD_NS: u128 = 10_000;

use rust_router::config::ConnectionConfig;
use rust_router::connection::ConnectionManager;
use rust_router::ipc::{IpcCommand, IpcHandler, IpcResponse};
use rust_router::outbound::{BlockOutbound, DirectOutbound, OutboundManager};
use rust_router::rules::{RuleEngine, RuleType, RoutingSnapshotBuilder};

// ============================================================================
// Test Helpers
// ============================================================================

/// Create a test IPC handler with multiple outbounds for stress testing
fn create_stress_test_handler() -> IpcHandler {
    let outbound_manager = Arc::new(OutboundManager::new());

    // Add multiple outbounds for realistic testing
    outbound_manager.add(Box::new(DirectOutbound::simple("direct")));
    outbound_manager.add(Box::new(DirectOutbound::simple("proxy-1")));
    outbound_manager.add(Box::new(DirectOutbound::simple("proxy-2")));
    outbound_manager.add(Box::new(DirectOutbound::simple("proxy-3")));
    outbound_manager.add(Box::new(BlockOutbound::new("block")));

    let conn_config = ConnectionConfig::default();
    let connection_manager = Arc::new(ConnectionManager::new(
        &conn_config,
        Arc::clone(&outbound_manager),
        "direct".into(),
        Duration::from_millis(DEFAULT_SNIFF_TIMEOUT_MS),
    ));

    IpcHandler::new_with_default_rules(connection_manager, outbound_manager)
}

/// Create a handler with rule engine for hot reload testing
fn create_reload_test_handler() -> (IpcHandler, Arc<RuleEngine>) {
    let outbound_manager = Arc::new(OutboundManager::new());
    outbound_manager.add(Box::new(DirectOutbound::simple("direct")));
    outbound_manager.add(Box::new(DirectOutbound::simple("proxy")));
    outbound_manager.add(Box::new(BlockOutbound::new("block")));

    let conn_config = ConnectionConfig::default();
    let connection_manager = Arc::new(ConnectionManager::new(
        &conn_config,
        Arc::clone(&outbound_manager),
        "direct".into(),
        Duration::from_millis(300),
    ));

    // Create rule engine with some rules
    let mut builder = RoutingSnapshotBuilder::new();
    builder
        .add_domain_rule(RuleType::DomainSuffix, "example.com", "direct")
        .unwrap();
    let snapshot = builder.default_outbound("direct").version(1).build().unwrap();
    let rule_engine = Arc::new(RuleEngine::new(snapshot));

    let handler = IpcHandler::new(
        connection_manager,
        outbound_manager,
        Arc::clone(&rule_engine),
    );

    (handler, rule_engine)
}

// ============================================================================
// Connection Stability Tests
// ============================================================================

#[tokio::test]
async fn test_connection_manager_repeated_stats() {
    let outbound_manager = Arc::new(OutboundManager::new());
    outbound_manager.add(Box::new(DirectOutbound::simple("direct")));

    let config = ConnectionConfig::default();
    let manager = Arc::new(ConnectionManager::new(
        &config,
        outbound_manager,
        "direct".into(),
        Duration::from_millis(100),
    ));

    // Repeatedly get stats - should not leak memory or cause issues
    for i in 0..1000 {
        let stats = manager.stats_snapshot();
        assert!(stats.active <= i + 1000); // Sanity check
    }
}

#[tokio::test]
async fn test_connection_manager_concurrent_stats() {
    let outbound_manager = Arc::new(OutboundManager::new());
    outbound_manager.add(Box::new(DirectOutbound::simple("direct")));

    let config = ConnectionConfig::default();
    let manager = Arc::new(ConnectionManager::new(
        &config,
        outbound_manager,
        "direct".into(),
        Duration::from_millis(100),
    ));

    // Concurrent stats access
    let mut handles = vec![];
    for _ in 0..10 {
        let m = Arc::clone(&manager);
        handles.push(tokio::spawn(async move {
            for _ in 0..100 {
                let _ = m.stats_snapshot();
            }
        }));
    }

    for handle in handles {
        handle.await.unwrap();
    }
}

#[tokio::test]
async fn test_outbound_manager_add_remove_cycle() {
    let manager = Arc::new(OutboundManager::new());
    manager.add(Box::new(DirectOutbound::simple("base")));

    // Cycle add/remove
    for i in 0..100 {
        let tag = format!("temp-{}", i);
        manager.add(Box::new(DirectOutbound::simple(&tag)));

        // Verify added
        assert!(manager.get(&tag).is_some());

        // Remove - returns Option, so check is_some
        assert!(manager.remove(&tag).is_some(), "Failed to remove {}", tag);

        // Verify removed
        assert!(manager.get(&tag).is_none());
    }

    // Base should still exist
    assert!(manager.get("base").is_some());
}

// ============================================================================
// IPC Pressure Tests
// ============================================================================

#[tokio::test]
async fn test_ipc_high_frequency_ping() {
    let handler = create_stress_test_handler();

    let start = Instant::now();
    let count = 10_000;

    for _ in 0..count {
        let response = handler.handle(IpcCommand::Ping).await;
        assert!(matches!(response, IpcResponse::Pong));
    }

    let elapsed = start.elapsed();
    let per_op = elapsed.as_nanos() / count as u128;

    println!("IPC Ping: {} ops in {:?}, {} ns/op", count, elapsed, per_op);

    // Should be < 1μs per ping (target: 100 ns)
    assert!(per_op < 1000, "IPC ping too slow: {} ns", per_op);
}

#[tokio::test]
async fn test_ipc_high_frequency_status() {
    let handler = create_stress_test_handler();

    let start = Instant::now();
    let count = 5_000;

    for _ in 0..count {
        let response = handler.handle(IpcCommand::Status).await;
        assert!(matches!(response, IpcResponse::Status(_)));
    }

    let elapsed = start.elapsed();
    let per_op = elapsed.as_nanos() / count as u128;

    println!("IPC Status: {} ops in {:?}, {} ns/op", count, elapsed, per_op);

    // Should be < 10μs per status
    assert!(per_op < 10_000, "IPC status too slow: {} ns", per_op);
}

#[tokio::test]
async fn test_ipc_high_frequency_stats() {
    let handler = create_stress_test_handler();

    let start = Instant::now();
    let count = 5_000;

    for _ in 0..count {
        let response = handler.handle(IpcCommand::GetStats).await;
        assert!(matches!(response, IpcResponse::Stats(_)));
    }

    let elapsed = start.elapsed();
    let per_op = elapsed.as_nanos() / count as u128;

    println!("IPC GetStats: {} ops in {:?}, {} ns/op", count, elapsed, per_op);

    // Should be < 10μs per GetStats
    assert!(per_op < 10_000, "IPC GetStats too slow: {} ns", per_op);
}

#[tokio::test]
async fn test_ipc_concurrent_commands() {
    let handler = Arc::new(create_stress_test_handler());
    let success_count = Arc::new(AtomicU64::new(0));

    let start = Instant::now();
    let mut handles = vec![];

    // 20 concurrent tasks, 500 ops each = 10,000 total ops
    for task_id in 0..20 {
        let h = Arc::clone(&handler);
        let counter = Arc::clone(&success_count);

        handles.push(tokio::spawn(async move {
            for i in 0..500 {
                // Mix of different commands
                let cmd = match (task_id + i) % 4 {
                    0 => IpcCommand::Ping,
                    1 => IpcCommand::Status,
                    2 => IpcCommand::GetStats,
                    _ => IpcCommand::ListOutbounds,
                };

                let response = h.handle(cmd).await;
                if !response.is_error() {
                    counter.fetch_add(1, Ordering::Relaxed);
                }
            }
        }));
    }

    for handle in handles {
        handle.await.unwrap();
    }

    let elapsed = start.elapsed();
    let total = success_count.load(Ordering::Relaxed);

    println!("Concurrent IPC: {} successful ops in {:?}", total, elapsed);

    // All 10,000 operations should succeed
    assert_eq!(total, 10_000, "Some concurrent operations failed");

    // Should complete in reasonable time (< 5s on slow CI)
    assert!(elapsed < Duration::from_secs(5));
}

#[tokio::test]
async fn test_ipc_mixed_read_write() {
    let handler = Arc::new(create_stress_test_handler());
    let error_count = Arc::new(AtomicU64::new(0));

    let mut handles = vec![];

    // Read-heavy tasks
    for _ in 0..8 {
        let h = Arc::clone(&handler);
        handles.push(tokio::spawn(async move {
            for _ in 0..200 {
                let _ = h.handle(IpcCommand::ListOutbounds).await;
                let _ = h.handle(IpcCommand::GetStats).await;
            }
        }));
    }

    // Write tasks (enable/disable)
    for i in 0..2 {
        let h = Arc::clone(&handler);
        let tag = format!("proxy-{}", (i % 3) + 1);
        let err = Arc::clone(&error_count);

        handles.push(tokio::spawn(async move {
            for j in 0..100 {
                let cmd = if j % 2 == 0 {
                    IpcCommand::DisableOutbound { tag: tag.clone() }
                } else {
                    IpcCommand::EnableOutbound { tag: tag.clone() }
                };

                let response = h.handle(cmd).await;
                if response.is_error() {
                    err.fetch_add(1, Ordering::Relaxed);
                }
            }
        }));
    }

    for handle in handles {
        handle.await.unwrap();
    }

    // Should have no errors (reads and writes should not interfere)
    let errors = error_count.load(Ordering::Relaxed);
    assert_eq!(errors, 0, "Had {} errors in mixed read/write", errors);
}

// ============================================================================
// Hot Reload Stability Tests
// ============================================================================

#[tokio::test]
async fn test_hot_reload_single() {
    let (handler, _rule_engine) = create_reload_test_handler();

    let response = handler.handle(IpcCommand::ReloadRules { config_path: None }).await;

    assert!(!response.is_error(), "Reload failed: {:?}", response);
}

#[tokio::test]
async fn test_hot_reload_repeated() {
    let (handler, _rule_engine) = create_reload_test_handler();

    let start = Instant::now();

    // Repeated reloads
    for i in 0..100 {
        let response = handler.handle(IpcCommand::ReloadRules { config_path: None }).await;
        assert!(!response.is_error(), "Reload {} failed: {:?}", i, response);
    }

    let elapsed = start.elapsed();
    let per_reload = elapsed.as_micros() / 100;

    println!("Hot reload: 100 reloads in {:?}, {} μs/reload", elapsed, per_reload);

    // Target: < 1ms per reload
    assert!(per_reload < 1000, "Reload too slow: {} μs", per_reload);
}

#[tokio::test]
async fn test_hot_reload_concurrent_with_queries() {
    let (handler, _rule_engine) = create_reload_test_handler();
    let handler = Arc::new(handler);
    let error_count = Arc::new(AtomicU64::new(0));

    let mut handles = vec![];

    // Query tasks
    for _ in 0..5 {
        let h = Arc::clone(&handler);
        let err = Arc::clone(&error_count);

        handles.push(tokio::spawn(async move {
            for _ in 0..100 {
                let response = h.handle(IpcCommand::GetRuleStats).await;
                if response.is_error() {
                    err.fetch_add(1, Ordering::Relaxed);
                }
            }
        }));
    }

    // Reload tasks
    for _ in 0..2 {
        let h = Arc::clone(&handler);
        let err = Arc::clone(&error_count);

        handles.push(tokio::spawn(async move {
            for _ in 0..20 {
                let response = h.handle(IpcCommand::ReloadRules { config_path: None }).await;
                if response.is_error() {
                    err.fetch_add(1, Ordering::Relaxed);
                }
                // Small delay between reloads
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }));
    }

    for handle in handles {
        handle.await.unwrap();
    }

    let errors = error_count.load(Ordering::Relaxed);
    assert_eq!(errors, 0, "Had {} errors during concurrent reload", errors);
}

#[tokio::test]
async fn test_hot_reload_version_increment() {
    let (handler, _rule_engine) = create_reload_test_handler();

    // Get initial version
    let response = handler.handle(IpcCommand::GetRuleStats).await;
    let initial_version = if let IpcResponse::RuleStats(stats) = response {
        stats.config_version
    } else {
        panic!("Expected RuleStats response");
    };

    // Reload
    handler.handle(IpcCommand::ReloadRules { config_path: None }).await;

    // Version should increment
    let response = handler.handle(IpcCommand::GetRuleStats).await;
    if let IpcResponse::RuleStats(stats) = response {
        assert!(
            stats.config_version > initial_version,
            "Version did not increment: {} <= {}",
            stats.config_version,
            initial_version
        );
    }
}

// ============================================================================
// Outbound Health Stability Tests
// ============================================================================

#[tokio::test]
async fn test_outbound_health_repeated() {
    let handler = create_stress_test_handler();

    for _ in 0..100 {
        let response = handler.handle(IpcCommand::GetOutboundHealth).await;

        if let IpcResponse::OutboundHealth(health) = response {
            // Should always have consistent number of outbounds
            assert!(health.outbounds.len() >= 5);
        } else {
            panic!("Expected OutboundHealth response");
        }
    }
}

#[tokio::test]
async fn test_outbound_health_with_changes() {
    let handler = create_stress_test_handler();

    // Get initial health
    let response = handler.handle(IpcCommand::GetOutboundHealth).await;
    let initial_count = if let IpcResponse::OutboundHealth(health) = response {
        health.outbounds.len()
    } else {
        panic!("Expected OutboundHealth response");
    };

    // Remove an outbound
    handler.handle(IpcCommand::RemoveOutbound { tag: "proxy-3".into() }).await;

    // Health should reflect removal
    let response = handler.handle(IpcCommand::GetOutboundHealth).await;
    if let IpcResponse::OutboundHealth(health) = response {
        assert_eq!(health.outbounds.len(), initial_count - 1);
    }
}

// ============================================================================
// Prometheus Metrics Stability Tests
// ============================================================================

#[tokio::test]
async fn test_prometheus_metrics_repeated() {
    let handler = create_stress_test_handler();

    for _ in 0..100 {
        let response = handler.handle(IpcCommand::GetPrometheusMetrics).await;

        if let IpcResponse::PrometheusMetrics(metrics) = response {
            // Should always produce valid metrics
            assert!(!metrics.metrics_text.is_empty());
            assert!(metrics.timestamp_ms > 0);

            // Should contain expected metrics
            assert!(metrics.metrics_text.contains("rust_router_"));
        } else {
            panic!("Expected PrometheusMetrics response");
        }
    }
}

#[tokio::test]
async fn test_prometheus_metrics_concurrent() {
    let handler = Arc::new(create_stress_test_handler());
    let success_count = Arc::new(AtomicU64::new(0));

    let mut handles = vec![];

    for _ in 0..10 {
        let h = Arc::clone(&handler);
        let counter = Arc::clone(&success_count);

        handles.push(tokio::spawn(async move {
            for _ in 0..50 {
                let response = h.handle(IpcCommand::GetPrometheusMetrics).await;
                if matches!(response, IpcResponse::PrometheusMetrics(_)) {
                    counter.fetch_add(1, Ordering::Relaxed);
                }
            }
        }));
    }

    for handle in handles {
        handle.await.unwrap();
    }

    let total = success_count.load(Ordering::Relaxed);
    assert_eq!(total, 500, "Expected 500 successful metrics requests");
}

// ============================================================================
// Error Recovery Tests
// ============================================================================

#[tokio::test]
async fn test_recovery_after_many_errors() {
    let handler = create_stress_test_handler();

    // Generate many errors
    for i in 0..100 {
        let _ = handler.handle(IpcCommand::GetOutbound {
            tag: format!("nonexistent-{}", i)
        }).await;
    }

    // Should still work correctly
    let response = handler.handle(IpcCommand::Status).await;
    if let IpcResponse::Status(status) = response {
        assert!(!status.shutting_down);
        assert!(status.accepting);
    } else {
        panic!("Expected Status response after errors");
    }
}

#[tokio::test]
async fn test_concurrent_error_recovery() {
    let handler = Arc::new(create_stress_test_handler());

    let mut handles = vec![];

    // Error-generating tasks
    for _ in 0..5 {
        let h = Arc::clone(&handler);
        handles.push(tokio::spawn(async move {
            for _ in 0..50 {
                let _ = h.handle(IpcCommand::RemoveOutbound {
                    tag: "nonexistent".into()
                }).await;
            }
        }));
    }

    // Normal operation tasks
    for _ in 0..5 {
        let h = Arc::clone(&handler);
        handles.push(tokio::spawn(async move {
            for _ in 0..50 {
                let response = h.handle(IpcCommand::Ping).await;
                assert!(matches!(response, IpcResponse::Pong));
            }
        }));
    }

    for handle in handles {
        handle.await.unwrap();
    }
}

// ============================================================================
// Long-Running Stress Tests (marked #[ignore])
// ============================================================================

/// Extended stress test - run manually for stability verification
///
/// Uses AtomicBool for deterministic shutdown signaling to avoid race conditions
/// when multiple tasks check elapsed time independently.
#[tokio::test]
#[ignore]
async fn test_extended_ipc_stress() {
    let handler = Arc::new(create_stress_test_handler());
    let success_count = Arc::new(AtomicU64::new(0));
    let error_count = Arc::new(AtomicU64::new(0));
    // Use AtomicBool for deterministic shutdown (fixes H1 race condition)
    let shutdown = Arc::new(AtomicBool::new(false));

    let start = Instant::now();
    let target_duration = Duration::from_secs(60);

    let mut handles = vec![];

    // Shutdown timer task - signals all workers to stop after target duration
    {
        let shutdown_signal = Arc::clone(&shutdown);
        handles.push(tokio::spawn(async move {
            tokio::time::sleep(target_duration).await;
            shutdown_signal.store(true, Ordering::SeqCst);
        }));
    }

    // 50 concurrent workers
    for worker_id in 0..50 {
        let h = Arc::clone(&handler);
        let success = Arc::clone(&success_count);
        let errors = Arc::clone(&error_count);
        let shutdown_flag = Arc::clone(&shutdown);

        handles.push(tokio::spawn(async move {
            loop {
                // Check shutdown flag (deterministic, no race)
                if shutdown_flag.load(Ordering::SeqCst) {
                    break;
                }

                let cmd = match worker_id % 5 {
                    0 => IpcCommand::Ping,
                    1 => IpcCommand::Status,
                    2 => IpcCommand::GetStats,
                    3 => IpcCommand::GetOutboundHealth,
                    _ => IpcCommand::GetPrometheusMetrics,
                };

                let response = h.handle(cmd).await;
                // Relaxed ordering is sufficient for counters - we only need the final count,
                // not ordering with other operations
                if response.is_error() {
                    errors.fetch_add(1, Ordering::Relaxed);
                } else {
                    success.fetch_add(1, Ordering::Relaxed);
                }
            }
        }));
    }

    for handle in handles {
        handle.await.unwrap();
    }

    let total_success = success_count.load(Ordering::Relaxed);
    let total_errors = error_count.load(Ordering::Relaxed);
    let elapsed = start.elapsed();

    println!("Extended stress test:");
    println!("  Duration: {:?}", elapsed);
    println!("  Successful ops: {}", total_success);
    println!("  Errors: {}", total_errors);
    println!("  Ops/sec: {:.0}", total_success as f64 / elapsed.as_secs_f64());

    assert_eq!(total_errors, 0, "Had errors during stress test");
    assert!(total_success > 100_000, "Too few operations completed");
}

/// Hot reload under sustained load - run manually
///
/// Tests hot reload stability when concurrent query operations are in progress.
/// Uses AtomicBool for deterministic shutdown signaling.
#[tokio::test]
#[ignore]
async fn test_hot_reload_under_sustained_load() {
    let (handler, _rule_engine) = create_reload_test_handler();
    let handler = Arc::new(handler);

    let query_count = Arc::new(AtomicU64::new(0));
    let reload_count = Arc::new(AtomicU64::new(0));
    let error_count = Arc::new(AtomicU64::new(0));
    // Use AtomicBool for deterministic shutdown
    let shutdown = Arc::new(AtomicBool::new(false));

    let start = Instant::now();
    let target_duration = Duration::from_secs(30);

    let mut handles = vec![];

    // Shutdown timer task
    {
        let shutdown_signal = Arc::clone(&shutdown);
        handles.push(tokio::spawn(async move {
            tokio::time::sleep(target_duration).await;
            shutdown_signal.store(true, Ordering::SeqCst);
        }));
    }

    // Query workers
    for _ in 0..10 {
        let h = Arc::clone(&handler);
        let queries = Arc::clone(&query_count);
        let errors = Arc::clone(&error_count);
        let shutdown_flag = Arc::clone(&shutdown);

        handles.push(tokio::spawn(async move {
            loop {
                if shutdown_flag.load(Ordering::SeqCst) {
                    break;
                }

                let response = h.handle(IpcCommand::GetRuleStats).await;
                // Relaxed ordering sufficient for counters
                if response.is_error() {
                    errors.fetch_add(1, Ordering::Relaxed);
                } else {
                    queries.fetch_add(1, Ordering::Relaxed);
                }
            }
        }));
    }

    // Reload worker
    {
        let h = Arc::clone(&handler);
        let reloads = Arc::clone(&reload_count);
        let errors = Arc::clone(&error_count);
        let shutdown_flag = Arc::clone(&shutdown);

        handles.push(tokio::spawn(async move {
            loop {
                if shutdown_flag.load(Ordering::SeqCst) {
                    break;
                }

                let response = h.handle(IpcCommand::ReloadRules { config_path: None }).await;
                if response.is_error() {
                    errors.fetch_add(1, Ordering::Relaxed);
                } else {
                    reloads.fetch_add(1, Ordering::Relaxed);
                }

                // Reload every 100ms
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }));
    }

    for handle in handles {
        handle.await.unwrap();
    }

    let total_queries = query_count.load(Ordering::Relaxed);
    let total_reloads = reload_count.load(Ordering::Relaxed);
    let total_errors = error_count.load(Ordering::Relaxed);

    println!("Hot reload under load:");
    println!("  Queries: {}", total_queries);
    println!("  Reloads: {}", total_reloads);
    println!("  Errors: {}", total_errors);

    assert_eq!(total_errors, 0, "Had errors during reload test");
    assert!(total_reloads > 200, "Too few reloads completed");
}
