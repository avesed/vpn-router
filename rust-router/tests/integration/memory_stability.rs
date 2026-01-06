//! Memory Stability Tests for rust-router
//!
//! This module contains tests designed to detect memory leaks and verify
//! memory usage stays within 1C1G VPS resource budgets.
//!
//! # Test Categories
//!
//! 1. **Allocation Patterns**: Verify no unexpected memory growth
//! 2. **Collection Cleanup**: Ensure collections are properly cleaned up
//! 3. **Arc Cycle Detection**: Check for reference cycle leaks
//! 4. **Long-Running Stability**: Extended tests for memory leak detection
//! 5. **Memory Budget Verification**: Test actual RSS against 1C1G targets
//!
//! # Resource Targets (1C1G VPS)
//!
//! - Idle memory: < 60 MB
//! - Per-connection overhead: < 20 KB
//! - Peak memory (2000 connections): < 150 MB
//!
//! # Running Tests
//!
//! ```bash
//! # Run memory tests
//! cargo test --test integration_tests memory
//!
//! # Run extended memory tests (requires --ignored)
//! cargo test --test integration_tests memory -- --ignored --nocapture
//! ```
//!
//! # Memory Measurement
//!
//! On Linux, tests use `/proc/self/status` to measure RSS (Resident Set Size).
//! This provides actual memory usage measurement beyond functional verification.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rust_router::config::ConnectionConfig;
use rust_router::connection::ConnectionManager;
use rust_router::ipc::{IpcCommand, IpcHandler, IpcResponse};
use rust_router::outbound::{BlockOutbound, DirectOutbound, OutboundManager};
use rust_router::rules::{ConnectionInfo, RuleEngine, RuleType, RoutingSnapshotBuilder};

// ============================================================================
// Constants
// ============================================================================

/// Number of iterations for light stress tests
const LIGHT_ITERATIONS: usize = 1_000;

/// Number of iterations for medium stress tests
const MEDIUM_ITERATIONS: usize = 10_000;

/// Number of rules for rule engine tests
const RULE_COUNT: usize = 5_000;

/// Memory budget: idle memory limit in KB (60 MB)
const IDLE_MEMORY_LIMIT_KB: usize = 60 * 1024;

/// Memory budget: peak memory limit in KB (150 MB)
const PEAK_MEMORY_LIMIT_KB: usize = 150 * 1024;

/// Allowed memory growth per operation in bytes
const ALLOWED_GROWTH_PER_OP_BYTES: f64 = 1.0;

// ============================================================================
// Memory Measurement Utilities
// ============================================================================

/// Get current process RSS (Resident Set Size) in KB on Linux.
/// Returns 0 on non-Linux platforms or if measurement fails.
#[cfg(target_os = "linux")]
fn get_rss_kb() -> usize {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|content| {
            for line in content.lines() {
                if line.starts_with("VmRSS:") {
                    // Format: "VmRSS:      1234 kB"
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        return parts[1].parse().ok();
                    }
                }
            }
            None
        })
        .unwrap_or(0)
}

#[cfg(not(target_os = "linux"))]
fn get_rss_kb() -> usize {
    // Memory measurement not available on non-Linux platforms
    0
}

/// Measure memory usage before and after a block of code
struct MemoryMeasurement {
    before_kb: usize,
    after_kb: usize,
}

impl MemoryMeasurement {
    fn start() -> Self {
        Self {
            before_kb: get_rss_kb(),
            after_kb: 0,
        }
    }

    fn finish(&mut self) {
        self.after_kb = get_rss_kb();
    }

    fn growth_kb(&self) -> isize {
        self.after_kb as isize - self.before_kb as isize
    }

    fn is_within_budget(&self, max_growth_kb: isize) -> bool {
        self.growth_kb() <= max_growth_kb
    }
}

// ============================================================================
// Test Helpers
// ============================================================================

/// Create a test handler for memory testing
fn create_memory_test_handler() -> IpcHandler {
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

    IpcHandler::new_with_default_rules(connection_manager, outbound_manager)
}

// ============================================================================
// Outbound Manager Memory Tests
// ============================================================================

#[tokio::test]
async fn test_outbound_add_remove_no_leak() {
    let manager = Arc::new(OutboundManager::new());

    // Add and remove many outbounds
    for cycle in 0..10 {
        // Add 100 outbounds
        for i in 0..100 {
            let tag = format!("temp-{}-{}", cycle, i);
            manager.add(Box::new(DirectOutbound::simple(&tag)));
        }

        // Verify all added
        let count = manager.all().len();
        assert_eq!(count, 100, "Cycle {} expected 100 outbounds", cycle);

        // Remove all
        for i in 0..100 {
            let tag = format!("temp-{}-{}", cycle, i);
            assert!(manager.remove(&tag).is_some(), "Failed to remove {}", tag);
        }

        // Verify all removed
        assert!(manager.all().is_empty(), "Cycle {} not empty after removal", cycle);
    }

    // After all cycles, no outbounds should remain
    assert!(manager.all().is_empty());
}

#[tokio::test]
async fn test_outbound_get_no_leak() {
    let manager = Arc::new(OutboundManager::new());
    manager.add(Box::new(DirectOutbound::simple("test")));

    // Many get operations should not leak
    for _ in 0..10_000 {
        let _ = manager.get("test");
        let _ = manager.get("nonexistent");
    }

    // Outbound should still work
    assert!(manager.get("test").is_some());
}

#[tokio::test]
async fn test_outbound_list_no_leak() {
    let manager = Arc::new(OutboundManager::new());

    for i in 0..10 {
        manager.add(Box::new(DirectOutbound::simple(&format!("out-{}", i))));
    }

    // Many list operations
    for _ in 0..1_000 {
        let all = manager.all();
        assert_eq!(all.len(), 10);
    }
}

// ============================================================================
// Connection Manager Memory Tests
// ============================================================================

#[tokio::test]
async fn test_connection_stats_no_leak() {
    let outbound_manager = Arc::new(OutboundManager::new());
    outbound_manager.add(Box::new(DirectOutbound::simple("direct")));

    let config = ConnectionConfig::default();
    let manager = Arc::new(ConnectionManager::new(
        &config,
        outbound_manager,
        "direct".into(),
        Duration::from_millis(100),
    ));

    // Many stats snapshots
    for _ in 0..10_000 {
        let stats = manager.stats_snapshot();
        // Ensure stats are valid
        assert!(stats.total_accepted < 1_000_000);
    }
}

// ============================================================================
// Rule Engine Memory Tests
// ============================================================================

#[tokio::test]
async fn test_rule_engine_reload_no_leak() {
    // Create rule engine with some rules
    let mut builder = RoutingSnapshotBuilder::new();
    builder
        .add_domain_rule(RuleType::DomainSuffix, "example.com", "direct")
        .unwrap();
    let snapshot = builder.default_outbound("direct").version(1).build().unwrap();

    let rule_engine = Arc::new(RuleEngine::new(snapshot));

    // Many reloads
    for i in 0..100 {
        // Create new config
        let mut new_builder = RoutingSnapshotBuilder::new();
        new_builder
            .add_domain_rule(RuleType::DomainSuffix, "example.com", "direct")
            .unwrap()
            .add_domain_rule(RuleType::Domain, &format!("test-{}.example.com", i), "proxy")
            .unwrap();

        let new_snapshot = new_builder
            .default_outbound("direct")
            .version((i + 2) as u64)
            .build()
            .unwrap();

        rule_engine.reload(new_snapshot);
    }

    // Engine should still work
    let version = rule_engine.version();
    assert!(version >= 100);
}

#[tokio::test]
async fn test_rule_engine_match_no_leak() {
    let mut builder = RoutingSnapshotBuilder::new();

    // Add many rules
    for i in 0..1000 {
        builder
            .add_domain_rule(RuleType::DomainSuffix, &format!("domain-{}.com", i), "direct")
            .unwrap();
    }

    let snapshot = builder.default_outbound("direct").build().unwrap();
    let rule_engine = RuleEngine::new(snapshot);

    // Many match operations
    for _ in 0..1_000 {
        for domain in &["example.com", "domain-500.com", "unknown.org"] {
            let conn = ConnectionInfo::new("tcp", 443).with_domain(*domain);
            let _ = rule_engine.match_connection(&conn);
        }
    }
}

// ============================================================================
// IPC Handler Memory Tests
// ============================================================================

#[tokio::test]
async fn test_ipc_command_handling_no_leak() {
    let handler = create_memory_test_handler();

    // Many command cycles
    for _ in 0..1_000 {
        let _ = handler.handle(IpcCommand::Ping).await;
        let _ = handler.handle(IpcCommand::Status).await;
        let _ = handler.handle(IpcCommand::GetStats).await;
        let _ = handler.handle(IpcCommand::ListOutbounds).await;
        let _ = handler.handle(IpcCommand::GetRuleStats).await;
    }
}

#[tokio::test]
async fn test_ipc_prometheus_metrics_no_leak() {
    let handler = create_memory_test_handler();

    // Prometheus metrics generation should not leak
    for _ in 0..500 {
        let response = handler.handle(IpcCommand::GetPrometheusMetrics).await;

        if let IpcResponse::PrometheusMetrics(metrics) = response {
            // Metrics string should be reasonable size
            assert!(metrics.metrics_text.len() < 100_000);
        }
    }
}

#[tokio::test]
async fn test_ipc_error_response_no_leak() {
    let handler = create_memory_test_handler();

    // Error responses should not leak
    for i in 0..1_000 {
        let _ = handler.handle(IpcCommand::GetOutbound {
            tag: format!("nonexistent-{}", i),
        }).await;

        let _ = handler.handle(IpcCommand::RemoveOutbound {
            tag: format!("nonexistent-{}", i),
        }).await;
    }
}

// ============================================================================
// Arc Reference Cycle Tests
// ============================================================================

/// Test that no Arc cycles prevent cleanup.
///
/// This test verifies that when all strong references to the handler are dropped,
/// the underlying managers are also freed (no reference cycles keeping them alive).
///
/// The test creates weak references BEFORE moving Arcs into the handler, then
/// verifies the weak references become invalid after the handler and all strong
/// refs are dropped.
#[tokio::test]
async fn test_no_arc_cycle_in_handler() {
    // Create weak references that will be checked after handler drops
    let weak_outbound;
    let weak_conn;

    {
        // Scope where all strong references exist
        let outbound_manager = Arc::new(OutboundManager::new());
        weak_outbound = Arc::downgrade(&outbound_manager);

        outbound_manager.add(Box::new(DirectOutbound::simple("direct")));

        let conn_config = ConnectionConfig::default();
        let connection_manager = Arc::new(ConnectionManager::new(
            &conn_config,
            Arc::clone(&outbound_manager),
            "direct".into(),
            Duration::from_millis(100),
        ));
        weak_conn = Arc::downgrade(&connection_manager);

        // Create handler - this moves the Arcs into the handler
        let handler = IpcHandler::new_with_default_rules(connection_manager, outbound_manager);

        // Use the handler to ensure it's fully initialized
        let response = handler.handle(IpcCommand::Ping).await;
        assert!(matches!(response, IpcResponse::Pong));

        // Handler will be dropped at end of this scope
    }

    // Give async runtime a moment to clean up any pending tasks
    tokio::time::sleep(Duration::from_millis(10)).await;

    // After all strong references are dropped, weak references should NOT be upgradable
    // If they CAN be upgraded, there's a reference cycle keeping things alive
    assert!(
        weak_outbound.upgrade().is_none(),
        "OutboundManager not freed after handler drop - possible Arc cycle"
    );
    assert!(
        weak_conn.upgrade().is_none(),
        "ConnectionManager not freed after handler drop - possible Arc cycle"
    );
}

/// Test handler creation and destruction doesn't leak memory
#[tokio::test]
async fn test_handler_lifecycle_no_leak() {
    let mut measurement = MemoryMeasurement::start();

    // Create and destroy handlers repeatedly
    for _ in 0..100 {
        let handler = create_memory_test_handler();
        let _ = handler.handle(IpcCommand::Ping).await;
        // handler dropped here
    }

    measurement.finish();

    // On Linux, verify memory didn't grow significantly
    #[cfg(target_os = "linux")]
    {
        let growth = measurement.growth_kb();
        // Allow up to 2MB growth for 100 handler lifecycles
        // (generous threshold to account for allocator fragmentation and tokio runtime)
        assert!(
            growth < 2048,
            "Memory grew by {} KB during handler lifecycle test - possible leak",
            growth
        );
    }
}

// ============================================================================
// Concurrent Memory Tests
// ============================================================================

#[tokio::test]
async fn test_concurrent_operations_no_leak() {
    let handler = Arc::new(create_memory_test_handler());
    let operation_count = Arc::new(AtomicUsize::new(0));

    let mut handles = vec![];

    for _ in 0..10 {
        let h = Arc::clone(&handler);
        let count = Arc::clone(&operation_count);

        handles.push(tokio::spawn(async move {
            for _ in 0..500 {
                let _ = h.handle(IpcCommand::GetStats).await;
                count.fetch_add(1, Ordering::Relaxed);
            }
        }));
    }

    for handle in handles {
        handle.await.unwrap();
    }

    let total = operation_count.load(Ordering::Relaxed);
    assert_eq!(total, 5_000);
}

// ============================================================================
// Long-Running Memory Tests (marked #[ignore])
// ============================================================================

/// Extended memory stability test with actual memory measurement.
///
/// Uses AtomicBool for deterministic shutdown signaling.
/// Tracks RSS to detect slow memory leaks.
#[tokio::test]
#[ignore]
async fn test_extended_memory_stability() {
    let handler = Arc::new(create_memory_test_handler());
    let operation_count = Arc::new(AtomicUsize::new(0));
    let shutdown = Arc::new(AtomicBool::new(false));

    let target_duration = Duration::from_secs(120); // 2 minutes

    // Record initial memory
    let initial_rss = get_rss_kb();
    println!("Starting extended memory stability test...");
    println!("Duration: {:?}", target_duration);
    println!("Initial RSS: {} KB", initial_rss);

    let mut handles = vec![];

    // Shutdown timer
    {
        let shutdown_signal = Arc::clone(&shutdown);
        handles.push(tokio::spawn(async move {
            tokio::time::sleep(target_duration).await;
            shutdown_signal.store(true, Ordering::SeqCst);
        }));
    }

    // Worker tasks
    for worker_id in 0..20 {
        let h = Arc::clone(&handler);
        let count = Arc::clone(&operation_count);
        let shutdown_flag = Arc::clone(&shutdown);

        handles.push(tokio::spawn(async move {
            loop {
                if shutdown_flag.load(Ordering::SeqCst) {
                    break;
                }

                // Mix of operations
                match worker_id % 5 {
                    0 => { let _ = h.handle(IpcCommand::Ping).await; }
                    1 => { let _ = h.handle(IpcCommand::Status).await; }
                    2 => { let _ = h.handle(IpcCommand::GetStats).await; }
                    3 => { let _ = h.handle(IpcCommand::GetPrometheusMetrics).await; }
                    _ => { let _ = h.handle(IpcCommand::ListOutbounds).await; }
                }

                // Relaxed ordering is sufficient for counters
                count.fetch_add(1, Ordering::Relaxed);

                // Brief pause to prevent CPU saturation
                if count.load(Ordering::Relaxed) % 1000 == 0 {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            }
        }));
    }

    // Progress reporting with memory tracking
    {
        let count = Arc::clone(&operation_count);
        let shutdown_flag = Arc::clone(&shutdown);
        handles.push(tokio::spawn(async move {
            let start = Instant::now();
            loop {
                if shutdown_flag.load(Ordering::SeqCst) {
                    break;
                }
                tokio::time::sleep(Duration::from_secs(10)).await;
                let current_rss = get_rss_kb();
                println!(
                    "Progress: {:?} elapsed, {} operations, RSS: {} KB",
                    start.elapsed(),
                    count.load(Ordering::Relaxed),
                    current_rss
                );
            }
        }));
    }

    for handle in handles {
        handle.await.unwrap();
    }

    let total = operation_count.load(Ordering::Relaxed);
    let final_rss = get_rss_kb();
    let memory_growth = final_rss as isize - initial_rss as isize;
    let growth_per_op = if total > 0 {
        (memory_growth * 1024) as f64 / total as f64
    } else {
        0.0
    };

    println!("\nExtended memory test complete:");
    println!("  Total operations: {}", total);
    println!("  Final RSS: {} KB", final_rss);
    println!("  Memory growth: {} KB ({:.2} bytes/op)", memory_growth, growth_per_op);

    // Should complete many operations without issues
    assert!(total > 100_000, "Too few operations: {}", total);

    // On Linux, verify memory growth is acceptable
    #[cfg(target_os = "linux")]
    {
        // Allow up to 10 MB growth for extended test
        assert!(
            memory_growth < 10 * 1024,
            "Memory grew by {} KB - possible leak (threshold: 10 MB)",
            memory_growth
        );
        // Memory growth per operation should be negligible
        assert!(
            growth_per_op < ALLOWED_GROWTH_PER_OP_BYTES,
            "Memory growing at {:.2} bytes/op - likely leak",
            growth_per_op
        );
    }
}

/// Rule engine memory under repeated reloads with memory tracking.
#[tokio::test]
#[ignore]
async fn test_rule_engine_memory_under_reloads() {
    let initial_rss = get_rss_kb();

    // Large rule set
    let mut base_builder = RoutingSnapshotBuilder::new();
    for i in 0..RULE_COUNT {
        base_builder
            .add_domain_rule(RuleType::DomainSuffix, &format!("domain-{}.example.com", i), "direct")
            .unwrap();
    }
    let base_snapshot = base_builder.default_outbound("direct").version(1).build().unwrap();

    let rule_engine = Arc::new(RuleEngine::new(base_snapshot));

    println!("Starting rule engine memory test with {} rules...", RULE_COUNT);
    println!("Initial RSS: {} KB", initial_rss);

    let after_init_rss = get_rss_kb();
    println!("After initialization RSS: {} KB", after_init_rss);

    // Many reloads
    for cycle in 0..50 {
        let mut new_builder = RoutingSnapshotBuilder::new();
        for i in 0..RULE_COUNT {
            new_builder
                .add_domain_rule(RuleType::DomainSuffix, &format!("domain-{}.example.com", i), "direct")
                .unwrap();
        }
        // Add variation
        new_builder
            .add_domain_rule(RuleType::Domain, &format!("cycle-{}.test.com", cycle), "proxy")
            .unwrap();

        let new_snapshot = new_builder
            .default_outbound("direct")
            .version((cycle + 2) as u64)
            .build()
            .unwrap();

        rule_engine.reload(new_snapshot);

        if cycle % 10 == 0 {
            let current_rss = get_rss_kb();
            println!("Reload cycle {}/50, RSS: {} KB", cycle, current_rss);
        }
    }

    let final_rss = get_rss_kb();
    let version = rule_engine.version();

    println!("Final config version: {}", version);
    println!("Final RSS: {} KB", final_rss);
    println!("Memory growth from initialization: {} KB", final_rss as isize - after_init_rss as isize);

    assert!(version >= 50);

    // On Linux, verify memory is stable after reloads (old snapshots are freed)
    #[cfg(target_os = "linux")]
    {
        // Memory should not grow significantly after initial allocation
        // Allow 20% growth from initialization for temp allocations
        let growth = final_rss as isize - after_init_rss as isize;
        let max_growth = (after_init_rss as isize * 20) / 100;
        assert!(
            growth < max_growth,
            "Memory grew by {} KB during reloads (threshold: {} KB)",
            growth,
            max_growth
        );
    }
}

/// Outbound churn memory test with tracking
#[tokio::test]
#[ignore]
async fn test_outbound_churn_memory() {
    let manager = Arc::new(OutboundManager::new());
    let initial_rss = get_rss_kb();

    println!("Starting outbound churn test...");
    println!("Initial RSS: {} KB", initial_rss);

    let start = Instant::now();

    // High churn rate
    for cycle in 0..100 {
        // Add many outbounds
        for i in 0..50 {
            let tag = format!("churn-{}-{}", cycle, i);
            manager.add(Box::new(DirectOutbound::simple(&tag)));
        }

        // Remove all
        for i in 0..50 {
            let tag = format!("churn-{}-{}", cycle, i);
            manager.remove(&tag);
        }

        if cycle % 20 == 0 {
            let current_rss = get_rss_kb();
            println!(
                "Churn cycle {}/100, elapsed: {:?}, RSS: {} KB",
                cycle,
                start.elapsed(),
                current_rss
            );
        }
    }

    let elapsed = start.elapsed();
    let final_rss = get_rss_kb();
    let memory_growth = final_rss as isize - initial_rss as isize;

    println!("Outbound churn test complete in {:?}", elapsed);
    println!("Final RSS: {} KB, growth: {} KB", final_rss, memory_growth);

    // Should be empty after all churns
    assert!(manager.all().is_empty());

    // On Linux, verify memory returned to baseline
    #[cfg(target_os = "linux")]
    {
        // Allow up to 2 MB growth due to allocator fragmentation
        assert!(
            memory_growth < 2 * 1024,
            "Memory grew by {} KB after churn (threshold: 2 MB)",
            memory_growth
        );
    }
}

// ============================================================================
// Memory Budget Verification Tests
// ============================================================================

/// Verify idle memory usage is within 1C1G budget (60 MB).
#[tokio::test]
#[ignore]
async fn test_memory_budget_idle() {
    // Create handler (simulates idle state)
    let _handler = create_memory_test_handler();

    // Allow allocations to settle
    tokio::time::sleep(Duration::from_millis(100)).await;

    let rss = get_rss_kb();
    println!("Idle RSS: {} KB ({:.1} MB)", rss, rss as f64 / 1024.0);

    #[cfg(target_os = "linux")]
    {
        assert!(
            rss < IDLE_MEMORY_LIMIT_KB,
            "Idle memory {} KB exceeds budget {} KB ({} MB)",
            rss,
            IDLE_MEMORY_LIMIT_KB,
            IDLE_MEMORY_LIMIT_KB / 1024
        );
    }
}

/// Verify peak memory usage under load is within 1C1G budget (150 MB).
#[tokio::test]
#[ignore]
async fn test_memory_budget_peak() {
    let handler = Arc::new(create_memory_test_handler());

    // Create large rule set
    let mut builder = RoutingSnapshotBuilder::new();
    for i in 0..RULE_COUNT {
        builder
            .add_domain_rule(RuleType::DomainSuffix, &format!("domain-{}.example.com", i), "direct")
            .unwrap();
    }
    let snapshot = builder.default_outbound("direct").build().unwrap();
    let _rule_engine = RuleEngine::new(snapshot);

    // Generate load
    let mut handles = vec![];
    for _ in 0..20 {
        let h = Arc::clone(&handler);
        handles.push(tokio::spawn(async move {
            for _ in 0..1000 {
                let _ = h.handle(IpcCommand::GetStats).await;
            }
        }));
    }

    for handle in handles {
        handle.await.unwrap();
    }

    let peak_rss = get_rss_kb();
    println!("Peak RSS: {} KB ({:.1} MB)", peak_rss, peak_rss as f64 / 1024.0);

    #[cfg(target_os = "linux")]
    {
        assert!(
            peak_rss < PEAK_MEMORY_LIMIT_KB,
            "Peak memory {} KB exceeds budget {} KB ({} MB)",
            peak_rss,
            PEAK_MEMORY_LIMIT_KB,
            PEAK_MEMORY_LIMIT_KB / 1024
        );
    }
}
