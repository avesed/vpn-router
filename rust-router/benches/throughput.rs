//! Throughput benchmarks for the rust-router transparent proxy.
//!
//! Run with: `cargo bench --bench throughput`
//!
//! Performance targets (1C1G VPS):
//! - Memory: 60MB idle, 150MB under load
//! - Latency: <1ms overhead per connection
//! - Throughput: >= sing-box baseline
//!
//! Specific targets:
//! - IO bidirectional copy: >5Gbps with 64KB buffers
//! - Connection accept: >10K accepts/sec
//! - Stats snapshot: <1us
//! - IPC ping latency: <100us round-trip
//! - IPC stats: <500us
//! - Prometheus metrics: <5ms generation
//! - Outbound lookup: <500ns for 100 outbounds
//! - ConnectionInfo alloc: <100ns

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use rust_router::connection::{ConnectionStats, OutboundStats, StatsSnapshot};
use rust_router::io::DEFAULT_BUFFER_SIZE;
use rust_router::ipc::{
    decode_message, encode_message, IpcCommand, IpcResponse, ServerStatus,
};
use rust_router::outbound::{BlockOutbound, DirectOutbound, OutboundManager};
use rust_router::rules::ConnectionInfo;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};
use tokio::runtime::Runtime;

// ============================================================================
// Helper Functions
// ============================================================================

/// Create a tokio runtime for async benchmarks.
fn create_runtime() -> Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("Failed to create runtime")
}

/// Generate test data of specified size.
fn generate_test_data(size: usize) -> Vec<u8> {
    (0..size).map(|i| (i % 256) as u8).collect()
}

/// Create an OutboundManager with the specified number of outbounds.
fn build_outbound_manager(count: usize) -> OutboundManager {
    let manager = OutboundManager::new();

    // Add direct outbound (always present)
    manager.add(Box::new(DirectOutbound::simple("direct")));

    // Add block outbound for testing
    manager.add(Box::new(BlockOutbound::new("block")));

    // Add additional direct outbounds
    for i in 0..(count.saturating_sub(2)) {
        manager.add(Box::new(DirectOutbound::simple(&format!("proxy-{}", i))));
    }

    manager
}

/// Build a sample Prometheus metrics text for benchmarking.
fn build_sample_prometheus_metrics(outbound_count: usize) -> String {
    let mut output = String::with_capacity(16384);

    // Core metrics
    output.push_str("# HELP rust_router_connections_total Total number of connections accepted\n");
    output.push_str("# TYPE rust_router_connections_total counter\n");
    output.push_str("rust_router_connections_total 12345\n");

    output.push_str("# HELP rust_router_connections_active Currently active connections\n");
    output.push_str("# TYPE rust_router_connections_active gauge\n");
    output.push_str("rust_router_connections_active 42\n");

    output.push_str("# HELP rust_router_bytes_rx_total Total bytes received\n");
    output.push_str("# TYPE rust_router_bytes_rx_total counter\n");
    output.push_str("rust_router_bytes_rx_total 1234567890\n");

    output.push_str("# HELP rust_router_bytes_tx_total Total bytes transmitted\n");
    output.push_str("# TYPE rust_router_bytes_tx_total counter\n");
    output.push_str("rust_router_bytes_tx_total 9876543210\n");

    // Per-outbound metrics
    output.push_str("# HELP rust_router_outbound_connections_total Total connections per outbound\n");
    output.push_str("# TYPE rust_router_outbound_connections_total counter\n");
    for i in 0..outbound_count {
        output.push_str(&format!(
            "rust_router_outbound_connections_total{{outbound=\"proxy-{}\"}} {}\n",
            i,
            1000 + i
        ));
    }

    output.push_str("# HELP rust_router_outbound_health Outbound health status\n");
    output.push_str("# TYPE rust_router_outbound_health gauge\n");
    for i in 0..outbound_count {
        for status in &["healthy", "degraded", "unhealthy", "unknown"] {
            let value = if *status == "healthy" { 1 } else { 0 };
            output.push_str(&format!(
                "rust_router_outbound_health{{outbound=\"proxy-{}\",status=\"{}\"}} {}\n",
                i, status, value
            ));
        }
    }

    output
}

/// Build a sample StatsSnapshot for benchmarking.
fn build_sample_stats_snapshot() -> StatsSnapshot {
    StatsSnapshot {
        total_accepted: 100000,
        active: 500,
        completed: 95000,
        errored: 4500,
        rejected: 500,
        bytes_rx: 1024 * 1024 * 1024 * 10, // 10GB
        bytes_tx: 1024 * 1024 * 1024 * 50, // 50GB
        timestamp_ms: 1704067200000,
    }
}

// ============================================================================
// IO Layer Throughput Benchmarks
// ============================================================================

/// Benchmark bidirectional copy with varying buffer sizes.
///
/// Target: >5Gbps throughput with 64KB buffers
fn bench_bidirectional_copy(c: &mut Criterion) {
    let mut group = c.benchmark_group("io_throughput");
    let runtime = create_runtime();

    // Test different buffer sizes
    let buffer_sizes = [4 * 1024, 16 * 1024, 64 * 1024];
    let data_size = 1024 * 1024; // 1MB of data

    for buf_size in buffer_sizes.iter() {
        group.throughput(Throughput::Bytes(data_size as u64 * 2)); // bidirectional
        group.bench_with_input(
            BenchmarkId::new("bidirectional_copy", format!("{}KB", buf_size / 1024)),
            buf_size,
            |b, &buf_size| {
                let data = generate_test_data(data_size);

                b.to_async(&runtime).iter(|| async {
                    // Create duplex streams for testing
                    let (mut client_tx, mut client_rx) = duplex(buf_size);
                    let (mut server_tx, mut server_rx) = duplex(buf_size);

                    // Spawn task to write data to client side
                    let data_clone = data.clone();
                    let write_handle = tokio::spawn(async move {
                        client_tx.write_all(&data_clone).await.unwrap();
                        client_tx.shutdown().await.unwrap();
                    });

                    // Spawn task to write data from server side
                    let data_clone2 = data.clone();
                    let write_handle2 = tokio::spawn(async move {
                        server_tx.write_all(&data_clone2).await.unwrap();
                        server_tx.shutdown().await.unwrap();
                    });

                    // Read from both sides
                    let mut buf1 = vec![0u8; data_size];
                    let mut buf2 = vec![0u8; data_size];

                    let (r1, r2) = tokio::join!(
                        client_rx.read_exact(&mut buf1),
                        server_rx.read_exact(&mut buf2)
                    );
                    r1.unwrap();
                    r2.unwrap();

                    write_handle.await.unwrap();
                    write_handle2.await.unwrap();

                    black_box((buf1.len(), buf2.len()))
                });
            },
        );
    }

    group.finish();
}

/// Benchmark default buffer size copy (64KB).
fn bench_default_buffer_copy(c: &mut Criterion) {
    let mut group = c.benchmark_group("io_default_buffer");
    let runtime = create_runtime();

    // Test different data sizes
    let data_sizes = [64 * 1024, 256 * 1024, 1024 * 1024];

    for &data_size in &data_sizes {
        group.throughput(Throughput::Bytes(data_size as u64));
        group.bench_with_input(
            BenchmarkId::new("copy", format!("{}KB", data_size / 1024)),
            &data_size,
            |b, &size| {
                let data = generate_test_data(size);

                b.to_async(&runtime).iter(|| async {
                    let (mut tx, mut rx) = duplex(DEFAULT_BUFFER_SIZE);

                    let data_clone = data.clone();
                    let write_handle = tokio::spawn(async move {
                        tx.write_all(&data_clone).await.unwrap();
                        tx.shutdown().await.unwrap();
                    });

                    let mut result = Vec::with_capacity(size);
                    rx.read_to_end(&mut result).await.unwrap();
                    write_handle.await.unwrap();

                    black_box(result.len())
                });
            },
        );
    }

    group.finish();
}

// ============================================================================
// Connection Manager Benchmarks
// ============================================================================

/// Benchmark connection stats operations.
///
/// Target: <1us for stats snapshot
fn bench_connection_stats(c: &mut Criterion) {
    let mut group = c.benchmark_group("connection_stats");

    let stats = ConnectionStats::new();

    // Pre-populate with some data
    for _ in 0..1000 {
        stats.record_accepted();
    }
    for _ in 0..900 {
        stats.record_completed(1024, 2048);
    }
    for _ in 0..50 {
        stats.record_error();
    }
    for _ in 0..50 {
        stats.record_rejected();
    }

    group.bench_function("stats_snapshot", |b| {
        b.iter(|| black_box(stats.snapshot()));
    });

    group.bench_function("record_accepted", |b| {
        b.iter(|| {
            black_box(stats.record_accepted());
        });
    });

    group.bench_function("record_completed", |b| {
        b.iter(|| {
            black_box(stats.record_completed(1024, 2048));
        });
    });

    group.bench_function("record_error", |b| {
        b.iter(|| {
            black_box(stats.record_error());
        });
    });

    group.finish();
}

/// Benchmark per-outbound stats operations.
fn bench_outbound_stats(c: &mut Criterion) {
    let mut group = c.benchmark_group("outbound_stats");

    let stats = OutboundStats::new();

    // Pre-populate
    for _ in 0..500 {
        stats.record_connection();
    }
    for _ in 0..450 {
        stats.record_completed(512, 1024);
    }

    group.bench_function("snapshot", |b| {
        b.iter(|| black_box(stats.snapshot()));
    });

    group.bench_function("record_connection", |b| {
        b.iter(|| {
            black_box(stats.record_connection());
        });
    });

    group.bench_function("record_completed", |b| {
        b.iter(|| {
            black_box(stats.record_completed(512, 1024));
        });
    });

    group.finish();
}

// ============================================================================
// IPC Command Latency Benchmarks
// ============================================================================

/// Benchmark IPC message encoding/decoding.
///
/// Target: <100us round-trip for ping
fn bench_ipc_serialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("ipc_serialization");

    // Test Ping command (smallest)
    group.bench_function("encode_ping", |b| {
        let cmd = IpcCommand::Ping;
        b.iter(|| black_box(encode_message(&cmd).unwrap()));
    });

    group.bench_function("decode_ping", |b| {
        let encoded = encode_message(&IpcCommand::Ping).unwrap();
        let data = &encoded[4..]; // Skip length prefix
        b.iter(|| black_box(decode_message::<IpcCommand>(data).unwrap()));
    });

    group.bench_function("roundtrip_ping", |b| {
        b.iter(|| {
            let cmd = IpcCommand::Ping;
            let encoded = encode_message(&cmd).unwrap();
            let decoded: IpcCommand = decode_message(&encoded[4..]).unwrap();
            black_box(decoded)
        });
    });

    // Test Status response (medium)
    let status = ServerStatus {
        version: "0.1.0".into(),
        uptime_secs: 3600,
        active_connections: 100,
        total_connections: 10000,
        outbound_count: 10,
        accepting: true,
        shutting_down: false,
    };
    let status_response = IpcResponse::Status(status);

    group.bench_function("encode_status", |b| {
        b.iter(|| black_box(encode_message(&status_response).unwrap()));
    });

    group.bench_function("decode_status", |b| {
        let encoded = encode_message(&status_response).unwrap();
        let data = &encoded[4..];
        b.iter(|| black_box(decode_message::<IpcResponse>(data).unwrap()));
    });

    group.finish();
}

/// Benchmark IPC GetStats command serialization.
///
/// Target: <500us for stats command
fn bench_ipc_stats(c: &mut Criterion) {
    let mut group = c.benchmark_group("ipc_stats");

    // Create realistic stats snapshot
    let stats_snapshot = build_sample_stats_snapshot();
    let stats_response = IpcResponse::Stats(stats_snapshot);

    group.bench_function("encode_stats", |b| {
        b.iter(|| black_box(encode_message(&stats_response).unwrap()));
    });

    group.bench_function("decode_stats", |b| {
        let encoded = encode_message(&stats_response).unwrap();
        let data = &encoded[4..];
        b.iter(|| black_box(decode_message::<IpcResponse>(data).unwrap()));
    });

    group.bench_function("roundtrip_stats", |b| {
        b.iter(|| {
            let encoded = encode_message(&stats_response).unwrap();
            let decoded: IpcResponse = decode_message(&encoded[4..]).unwrap();
            black_box(decoded)
        });
    });

    group.finish();
}

/// Benchmark Prometheus metrics generation simulation.
///
/// Target: <5ms for full metrics generation
fn bench_ipc_prometheus_metrics(c: &mut Criterion) {
    let mut group = c.benchmark_group("ipc_prometheus");

    // Test with different outbound counts
    for outbound_count in [10, 50, 100].iter() {
        group.bench_with_input(
            BenchmarkId::new("generate_text", outbound_count),
            outbound_count,
            |b, &count| {
                b.iter(|| black_box(build_sample_prometheus_metrics(count)));
            },
        );

        let metrics_text = build_sample_prometheus_metrics(*outbound_count);
        group.bench_with_input(
            BenchmarkId::new("text_len", outbound_count),
            &metrics_text,
            |b, text| {
                b.iter(|| black_box(text.len()));
            },
        );
    }

    group.finish();
}

/// Benchmark GetStats command (simulating full handler path).
fn bench_ipc_get_stats_command(c: &mut Criterion) {
    let mut group = c.benchmark_group("ipc_get_stats_command");

    // Benchmark the GetStats command serialization
    let get_stats_cmd = IpcCommand::GetStats;

    group.bench_function("encode_command", |b| {
        b.iter(|| black_box(encode_message(&get_stats_cmd).unwrap()));
    });

    // Benchmark creating a response with stats
    group.bench_function("create_response", |b| {
        b.iter(|| {
            let snapshot = build_sample_stats_snapshot();
            black_box(IpcResponse::Stats(snapshot))
        });
    });

    group.finish();
}

// ============================================================================
// Outbound Manager Benchmarks
// ============================================================================

/// Benchmark outbound manager lookup operations.
///
/// Target: <500ns for 100 outbounds
fn bench_outbound_manager_lookup(c: &mut Criterion) {
    let mut group = c.benchmark_group("outbound_manager");

    for count in [10, 50, 100].iter() {
        let manager = build_outbound_manager(*count);

        // Benchmark lookup of existing outbound
        group.bench_with_input(
            BenchmarkId::new("lookup_existing", count),
            count,
            |b, _| {
                b.iter(|| black_box(manager.get("direct")));
            },
        );

        // Benchmark lookup of outbound in the middle
        let mid_tag = format!("proxy-{}", count / 2);
        group.bench_with_input(BenchmarkId::new("lookup_middle", count), count, |b, _| {
            b.iter(|| black_box(manager.get(&mid_tag)));
        });

        // Benchmark lookup of non-existing outbound
        group.bench_with_input(
            BenchmarkId::new("lookup_missing", count),
            count,
            |b, _| {
                b.iter(|| black_box(manager.get("nonexistent")));
            },
        );

        // Benchmark contains check
        group.bench_with_input(BenchmarkId::new("contains", count), count, |b, _| {
            b.iter(|| black_box(manager.contains("direct")));
        });
    }

    group.finish();
}

/// Benchmark listing all outbounds.
fn bench_outbound_manager_all(c: &mut Criterion) {
    let mut group = c.benchmark_group("outbound_manager_all");

    for count in [10, 50, 100].iter() {
        let manager = build_outbound_manager(*count);

        group.bench_with_input(BenchmarkId::new("all", count), count, |b, _| {
            b.iter(|| black_box(manager.all()));
        });

        group.bench_with_input(BenchmarkId::new("tags", count), count, |b, _| {
            b.iter(|| black_box(manager.tags()));
        });

        group.bench_with_input(BenchmarkId::new("len", count), count, |b, _| {
            b.iter(|| black_box(manager.len()));
        });

        group.bench_with_input(BenchmarkId::new("health_summary", count), count, |b, _| {
            b.iter(|| black_box(manager.health_summary()));
        });

        group.bench_with_input(BenchmarkId::new("stats_summary", count), count, |b, _| {
            b.iter(|| black_box(manager.stats_summary()));
        });
    }

    group.finish();
}

// ============================================================================
// Memory Allocation Benchmarks
// ============================================================================

/// Benchmark ConnectionInfo creation overhead.
///
/// Target: <100ns for allocation
fn bench_connection_info_alloc(c: &mut Criterion) {
    let mut group = c.benchmark_group("connection_info_alloc");

    group.bench_function("minimal", |b| {
        b.iter(|| black_box(ConnectionInfo::new("tcp", 443)));
    });

    group.bench_function("with_domain_short", |b| {
        b.iter(|| black_box(ConnectionInfo::new("tcp", 443).with_domain("google.com")));
    });

    group.bench_function("with_domain_long", |b| {
        b.iter(|| {
            black_box(
                ConnectionInfo::new("tcp", 443)
                    .with_domain("very.long.subdomain.chain.for.testing.example.com"),
            )
        });
    });

    group.bench_function("with_ip", |b| {
        let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        b.iter(|| black_box(ConnectionInfo::new("tcp", 443).with_dest_ip(ip)));
    });

    group.bench_function("full", |b| {
        let dest_ip = IpAddr::V4(Ipv4Addr::new(142, 250, 80, 46));
        let source_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 100));
        b.iter(|| {
            black_box(
                ConnectionInfo::new("tcp", 443)
                    .with_domain("www.google.com")
                    .with_dest_ip(dest_ip)
                    .with_source_ip(source_ip)
                    .with_sniffed_protocol("tls"),
            )
        });
    });

    group.finish();
}

/// Benchmark StatsSnapshot creation and operations.
fn bench_stats_snapshot_alloc(c: &mut Criterion) {
    let mut group = c.benchmark_group("stats_snapshot_alloc");

    let snapshot = build_sample_stats_snapshot();

    group.bench_function("clone", |b| {
        b.iter(|| black_box(snapshot.clone()));
    });

    group.bench_function("total_bytes", |b| {
        b.iter(|| black_box(snapshot.total_bytes()));
    });

    group.bench_function("success_rate", |b| {
        b.iter(|| black_box(snapshot.success_rate()));
    });

    group.finish();
}

/// Benchmark HashMap operations (used in stats_summary).
fn bench_hashmap_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("hashmap_ops");

    // Build a map similar to what stats_summary returns
    let sizes = [10, 50, 100];

    for &size in &sizes {
        let mut map: HashMap<String, u64> = HashMap::with_capacity(size);
        for i in 0..size {
            map.insert(format!("outbound-{}", i), i as u64 * 1000);
        }

        group.bench_with_input(BenchmarkId::new("lookup", size), &size, |b, _| {
            b.iter(|| black_box(map.get("outbound-50")));
        });

        group.bench_with_input(BenchmarkId::new("iterate", size), &size, |b, _| {
            b.iter(|| {
                let sum: u64 = map.values().sum();
                black_box(sum)
            });
        });

        group.bench_with_input(BenchmarkId::new("clone", size), &size, |b, _| {
            b.iter(|| black_box(map.clone()));
        });
    }

    group.finish();
}

/// Benchmark String allocation patterns.
fn bench_string_alloc(c: &mut Criterion) {
    let mut group = c.benchmark_group("string_alloc");

    // Benchmark tag string creation (common in outbound operations)
    group.bench_function("tag_short", |b| {
        b.iter(|| black_box(String::from("direct")));
    });

    group.bench_function("tag_with_format", |b| {
        b.iter(|| black_box(format!("proxy-{}", 42)));
    });

    group.bench_function("tag_with_prefix", |b| {
        let prefix = "wg-pia-";
        let suffix = "us-east";
        b.iter(|| black_box(format!("{}{}", prefix, suffix)));
    });

    // Benchmark domain string operations
    group.bench_function("domain_to_lowercase", |b| {
        let domain = "WWW.GOOGLE.COM";
        b.iter(|| black_box(domain.to_lowercase()));
    });

    group.bench_function("domain_trim_and_lower", |b| {
        let domain = "  WWW.GOOGLE.COM  ";
        b.iter(|| black_box(domain.trim().to_lowercase()));
    });

    group.finish();
}

/// Benchmark Vec allocation patterns (used in IPC responses).
fn bench_vec_alloc(c: &mut Criterion) {
    let mut group = c.benchmark_group("vec_alloc");

    group.bench_function("small_vec_10", |b| {
        b.iter(|| {
            let v: Vec<u64> = (0..10).collect();
            black_box(v)
        });
    });

    group.bench_function("preallocated_vec_100", |b| {
        b.iter(|| {
            let mut v: Vec<u64> = Vec::with_capacity(100);
            for i in 0..100 {
                v.push(i);
            }
            black_box(v)
        });
    });

    group.bench_function("string_vec_collect", |b| {
        let tags = ["direct", "proxy", "block", "wg-us", "wg-eu"];
        b.iter(|| {
            let v: Vec<String> = tags.iter().map(|s| (*s).to_string()).collect();
            black_box(v)
        });
    });

    group.finish();
}

// ============================================================================
// Criterion Configuration
// ============================================================================

criterion_group!(
    benches,
    bench_bidirectional_copy,
    bench_default_buffer_copy,
    bench_connection_stats,
    bench_outbound_stats,
    bench_ipc_serialization,
    bench_ipc_stats,
    bench_ipc_prometheus_metrics,
    bench_ipc_get_stats_command,
    bench_outbound_manager_lookup,
    bench_outbound_manager_all,
    bench_connection_info_alloc,
    bench_stats_snapshot_alloc,
    bench_hashmap_operations,
    bench_string_alloc,
    bench_vec_alloc,
);
criterion_main!(benches);
