//! A/B Comparison Benchmarks for rust-router vs sing-box
//!
//! Run with: `cargo bench --bench ab_comparison`
//!
//! This benchmark compares key performance characteristics:
//! - Connection establishment latency
//! - IPC command processing
//! - Rule matching performance
//! - Memory allocation patterns
//!
//! NOTE: For real A/B comparisons against sing-box, use the Python test script:
//! `python scripts/ab_comparison_test.py`

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use rust_router::config::ConnectionConfig;
use rust_router::connection::ConnectionManager;
use rust_router::ipc::{decode_message, encode_message, IpcCommand, IpcHandler};
use rust_router::outbound::{BlockOutbound, DirectOutbound, OutboundManager};
use rust_router::rules::{
    ConnectionInfo, DomainMatcher, DomainMatcherBuilder, RuleEngine, RoutingSnapshotBuilder,
};
use std::sync::Arc;
use std::time::Duration;
use tokio::runtime::Runtime;

// ============================================================================
// Helper Functions
// ============================================================================

fn create_runtime() -> Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("Failed to create runtime")
}

fn build_outbound_manager(count: usize) -> Arc<OutboundManager> {
    let manager = OutboundManager::new();

    manager.add(Box::new(DirectOutbound::simple("direct")));
    manager.add(Box::new(BlockOutbound::new("block")));

    for i in 0..(count.saturating_sub(2)) {
        manager.add(Box::new(DirectOutbound::simple(&format!("proxy-{}", i))));
    }

    Arc::new(manager)
}

fn build_connection_manager(outbound_manager: Arc<OutboundManager>) -> Arc<ConnectionManager> {
    let config = ConnectionConfig::default();
    Arc::new(ConnectionManager::new(
        &config,
        outbound_manager,
        "direct".into(),
        Duration::from_millis(300),
    ))
}

fn build_rule_engine(rule_count: usize) -> RuleEngine {
    let mut builder = RoutingSnapshotBuilder::new();

    // Add domain rules
    for i in 0..(rule_count / 2) {
        let _ = builder.add_domain_rule(
            rust_router::rules::RuleType::DomainSuffix,
            &format!("domain{}.com", i),
            "proxy",
        );
    }

    // Add port rules
    for i in 0..(rule_count / 2).min(65535) {
        let _ = builder.add_port_rule(&format!("{}", 1000 + i), "proxy");
    }

    // Add some test rules
    let _ = builder.add_domain_rule(
        rust_router::rules::RuleType::DomainSuffix,
        "google.com",
        "direct",
    );

    let snapshot = builder
        .default_outbound("direct")
        .version(1)
        .build()
        .expect("Failed to build snapshot");

    RuleEngine::new(snapshot)
}

fn build_domain_matcher(rule_count: usize) -> DomainMatcher {
    let mut builder = DomainMatcherBuilder::new();

    for i in 0..rule_count {
        builder = builder.add_suffix(&format!("domain{}.com", i), "proxy");
    }
    builder = builder.add_exact("google.com", "direct");
    builder = builder.add_suffix("example.com", "proxy");

    builder.build().expect("Failed to build domain matcher")
}

// ============================================================================
// Connection Establishment Benchmarks
// ============================================================================

/// Benchmark simulating connection accept overhead
fn bench_connection_accept(c: &mut Criterion) {
    let mut group = c.benchmark_group("ab_connection_accept");
    let runtime = create_runtime();

    group.bench_function("rust_router_accept", |b| {
        let outbound_manager = build_outbound_manager(10);
        let connection_manager = build_connection_manager(Arc::clone(&outbound_manager));

        b.to_async(&runtime).iter(|| async {
            // Simulate connection acceptance
            connection_manager.stats().record_accepted();
            black_box(())
        });
    });

    group.bench_function("rust_router_full_path", |b| {
        let outbound_manager = build_outbound_manager(10);
        let connection_manager = build_connection_manager(Arc::clone(&outbound_manager));
        let rule_engine = build_rule_engine(100);

        b.to_async(&runtime).iter(|| async {
            // Simulate full connection path
            connection_manager.stats().record_accepted();

            let conn_info = ConnectionInfo::new("tcp", 443).with_domain("www.google.com");
            let result = rule_engine.match_connection(&conn_info);

            let outbound = outbound_manager.get(&result.outbound);
            black_box(outbound)
        });
    });

    group.finish();
}

// ============================================================================
// IPC Command Benchmarks
// ============================================================================

/// Benchmark IPC command processing latency
fn bench_ipc_latency(c: &mut Criterion) {
    let mut group = c.benchmark_group("ab_ipc_latency");
    let runtime = create_runtime();

    group.bench_function("ping_roundtrip", |b| {
        let outbound_manager = build_outbound_manager(10);
        let connection_manager = build_connection_manager(Arc::clone(&outbound_manager));
        let handler =
            IpcHandler::new_with_default_rules(Arc::clone(&connection_manager), outbound_manager);

        b.to_async(&runtime).iter(|| async {
            let response = handler.handle(IpcCommand::Ping).await;
            black_box(response)
        });
    });

    group.bench_function("status_roundtrip", |b| {
        let outbound_manager = build_outbound_manager(10);
        let connection_manager = build_connection_manager(Arc::clone(&outbound_manager));
        let handler =
            IpcHandler::new_with_default_rules(Arc::clone(&connection_manager), outbound_manager);

        b.to_async(&runtime).iter(|| async {
            let response = handler.handle(IpcCommand::Status).await;
            black_box(response)
        });
    });

    group.bench_function("get_stats_roundtrip", |b| {
        let outbound_manager = build_outbound_manager(10);
        let connection_manager = build_connection_manager(Arc::clone(&outbound_manager));
        let handler =
            IpcHandler::new_with_default_rules(Arc::clone(&connection_manager), outbound_manager);

        // Pre-populate with some stats
        for _ in 0..1000 {
            connection_manager.stats().record_accepted();
        }
        for _ in 0..900 {
            connection_manager.stats().record_completed(1024, 2048);
        }

        b.to_async(&runtime).iter(|| async {
            let response = handler.handle(IpcCommand::GetStats).await;
            black_box(response)
        });
    });

    group.finish();
}

/// Benchmark IPC serialization/deserialization
fn bench_ipc_serialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("ab_ipc_serialization");

    // Ping command (minimal)
    group.bench_function("encode_ping", |b| {
        let cmd = IpcCommand::Ping;
        b.iter(|| black_box(encode_message(&cmd).unwrap()));
    });

    group.bench_function("decode_ping", |b| {
        let encoded = encode_message(&IpcCommand::Ping).unwrap();
        let data = &encoded[4..];
        b.iter(|| black_box(decode_message::<IpcCommand>(data).unwrap()));
    });

    // GetStats command
    group.bench_function("encode_get_stats", |b| {
        let cmd = IpcCommand::GetStats;
        b.iter(|| black_box(encode_message(&cmd).unwrap()));
    });

    // ListOutbounds command
    group.bench_function("encode_list_outbounds", |b| {
        let cmd = IpcCommand::ListOutbounds;
        b.iter(|| black_box(encode_message(&cmd).unwrap()));
    });

    group.finish();
}

// ============================================================================
// Rule Matching Benchmarks
// ============================================================================

/// Benchmark rule matching performance comparison
fn bench_rule_matching(c: &mut Criterion) {
    let mut group = c.benchmark_group("ab_rule_matching");

    // Different rule counts for scaling comparison
    for rule_count in [100, 1000, 10_000].iter() {
        let engine = build_rule_engine(*rule_count);

        // Domain match
        group.bench_with_input(
            BenchmarkId::new("domain_match", rule_count),
            rule_count,
            |b, _| {
                let conn = ConnectionInfo::new("tcp", 443).with_domain("www.google.com");
                b.iter(|| black_box(engine.match_connection(&conn)));
            },
        );

        // Port only match
        group.bench_with_input(
            BenchmarkId::new("port_match", rule_count),
            rule_count,
            |b, _| {
                let conn = ConnectionInfo::new("tcp", 443);
                b.iter(|| black_box(engine.match_connection(&conn)));
            },
        );

        // No match (fallback to default)
        group.bench_with_input(
            BenchmarkId::new("default_fallback", rule_count),
            rule_count,
            |b, _| {
                let conn = ConnectionInfo::new("tcp", 12345);
                b.iter(|| black_box(engine.match_connection(&conn)));
            },
        );
    }

    group.finish();
}

/// Benchmark domain matcher scaling
fn bench_domain_matcher_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("ab_domain_matcher");

    for rule_count in [1_000, 10_000, 22_000].iter() {
        let matcher = build_domain_matcher(*rule_count);

        group.bench_with_input(
            BenchmarkId::new("exact_match", rule_count),
            rule_count,
            |b, _| {
                b.iter(|| black_box(matcher.match_domain("google.com")));
            },
        );

        group.bench_with_input(
            BenchmarkId::new("suffix_match", rule_count),
            rule_count,
            |b, _| {
                b.iter(|| black_box(matcher.match_domain("www.example.com")));
            },
        );

        group.bench_with_input(
            BenchmarkId::new("no_match", rule_count),
            rule_count,
            |b, _| {
                b.iter(|| black_box(matcher.match_domain("nonexistent.test")));
            },
        );
    }

    group.finish();
}

// ============================================================================
// Memory Allocation Benchmarks
// ============================================================================

/// Benchmark memory allocation patterns
fn bench_memory_allocation(c: &mut Criterion) {
    let mut group = c.benchmark_group("ab_memory");

    // ConnectionInfo allocation
    group.bench_function("connection_info_minimal", |b| {
        b.iter(|| black_box(ConnectionInfo::new("tcp", 443)));
    });

    group.bench_function("connection_info_full", |b| {
        b.iter(|| {
            black_box(
                ConnectionInfo::new("tcp", 443)
                    .with_domain("www.google.com")
                    .with_dest_ip(std::net::IpAddr::V4(std::net::Ipv4Addr::new(142, 250, 80, 46)))
                    .with_source_ip(std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 100)))
                    .with_sniffed_protocol("tls"),
            )
        });
    });

    // String allocation (common in tag lookups)
    group.bench_function("string_tag_short", |b| {
        b.iter(|| black_box(String::from("direct")));
    });

    group.bench_function("string_tag_format", |b| {
        b.iter(|| black_box(format!("wg-pia-{}", "us-east")));
    });

    // Outbound manager lookup
    let manager = build_outbound_manager(100);
    group.bench_function("outbound_lookup", |b| {
        b.iter(|| black_box(manager.get("direct")));
    });

    group.finish();
}

// ============================================================================
// Throughput Simulation Benchmarks
// ============================================================================

/// Benchmark simulated throughput scenarios
fn bench_throughput_simulation(c: &mut Criterion) {
    let mut group = c.benchmark_group("ab_throughput");
    let runtime = create_runtime();

    // Simulate small request/response (e.g., DNS)
    group.throughput(Throughput::Bytes(512));
    group.bench_function("small_request", |b| {
        let data = vec![0u8; 512];
        b.to_async(&runtime).iter(|| async {
            // Simulate processing
            let sum: u64 = data.iter().map(|&x| x as u64).sum();
            black_box(sum)
        });
    });

    // Simulate medium request (e.g., HTTP header)
    group.throughput(Throughput::Bytes(4096));
    group.bench_function("medium_request", |b| {
        let data = vec![0u8; 4096];
        b.to_async(&runtime).iter(|| async {
            let sum: u64 = data.iter().map(|&x| x as u64).sum();
            black_box(sum)
        });
    });

    // Simulate large transfer chunk
    group.throughput(Throughput::Bytes(65536));
    group.bench_function("large_chunk", |b| {
        let data = vec![0u8; 65536];
        b.to_async(&runtime).iter(|| async {
            let sum: u64 = data.iter().map(|&x| x as u64).sum();
            black_box(sum)
        });
    });

    group.finish();
}

// ============================================================================
// Concurrent Load Benchmarks
// ============================================================================

/// Benchmark under concurrent load
fn bench_concurrent_load(c: &mut Criterion) {
    let mut group = c.benchmark_group("ab_concurrent");
    let runtime = create_runtime();

    // 10 concurrent operations
    group.bench_function("10_concurrent_matches", |b| {
        let engine = Arc::new(build_rule_engine(1000));

        b.to_async(&runtime).iter(|| async {
            let mut handles = vec![];

            for i in 0..10 {
                let engine_clone = Arc::clone(&engine);
                handles.push(tokio::spawn(async move {
                    let conn = ConnectionInfo::new("tcp", 443 + i as u16)
                        .with_domain(&format!("test{}.example.com", i));
                    engine_clone.match_connection(&conn)
                }));
            }

            for handle in handles {
                let _ = handle.await;
            }
        });
    });

    // 50 concurrent operations
    group.bench_function("50_concurrent_matches", |b| {
        let engine = Arc::new(build_rule_engine(1000));

        b.to_async(&runtime).iter(|| async {
            let mut handles = vec![];

            for i in 0..50 {
                let engine_clone = Arc::clone(&engine);
                handles.push(tokio::spawn(async move {
                    let conn = ConnectionInfo::new("tcp", 443 + i as u16)
                        .with_domain(&format!("test{}.example.com", i));
                    engine_clone.match_connection(&conn)
                }));
            }

            for handle in handles {
                let _ = handle.await;
            }
        });
    });

    group.finish();
}

// ============================================================================
// Hot Reload Benchmarks
// ============================================================================

/// Benchmark configuration hot reload
fn bench_hot_reload(c: &mut Criterion) {
    let mut group = c.benchmark_group("ab_hot_reload");

    group.bench_function("small_config_100_rules", |b| {
        let engine = build_rule_engine(100);
        b.iter(|| {
            let new_snapshot = RoutingSnapshotBuilder::new()
                .default_outbound("direct")
                .version(2)
                .build()
                .expect("Failed to build snapshot");
            engine.reload(black_box(new_snapshot));
        });
    });

    group.bench_function("medium_config_1000_rules", |b| {
        let engine = build_rule_engine(1000);
        b.iter(|| {
            let mut builder = RoutingSnapshotBuilder::new();
            for i in 0..100 {
                let _ = builder.add_domain_rule(
                    rust_router::rules::RuleType::DomainSuffix,
                    &format!("new{}.com", i),
                    "proxy",
                );
            }
            let new_snapshot = builder
                .default_outbound("direct")
                .version(2)
                .build()
                .expect("Failed to build snapshot");
            engine.reload(black_box(new_snapshot));
        });
    });

    group.finish();
}

// ============================================================================
// Criterion Configuration
// ============================================================================

criterion_group!(
    benches,
    bench_connection_accept,
    bench_ipc_latency,
    bench_ipc_serialization,
    bench_rule_matching,
    bench_domain_matcher_scaling,
    bench_memory_allocation,
    bench_throughput_simulation,
    bench_concurrent_load,
    bench_hot_reload,
);
criterion_main!(benches);
