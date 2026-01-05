//! Performance benchmarks for the rule matching engine.
//!
//! Run with: `cargo bench`
//!
//! Performance targets:
//! - Domain matching: <1us for exact match
//! - GeoIP matching: <10us for CIDR lookup
//! - Rule engine: <5us for full connection match
//! - UDP session lookup: <100ns
//! - QUIC detection: <50ns
//! - Hot reload: <1ms

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use rust_router::connection::{UdpSession, UdpSessionConfig, UdpSessionKey, UdpSessionManager};
use rust_router::rules::{
    ConnectionInfo, DomainMatcher, DomainMatcherBuilder, GeoIpMatcher, GeoIpMatcherBuilder,
    RoutingSnapshotBuilder, RuleEngine, RuleType,
};
use rust_router::sniff::quic::QuicSniffer;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

// ============================================================================
// Helper Functions
// ============================================================================

/// Build a domain matcher with the specified number of rules.
fn build_domain_matcher(rule_count: usize) -> DomainMatcher {
    let mut builder = DomainMatcherBuilder::new();
    for i in 0..rule_count {
        builder = builder.add_suffix(&format!("domain{}.com", i), "proxy");
    }
    // Add some known domains for testing
    builder = builder.add_exact("google.com", "direct");
    builder = builder.add_suffix("example.com", "proxy");
    builder.build().expect("Failed to build domain matcher")
}

/// Build a GeoIP matcher with the specified number of CIDR rules.
fn build_geoip_matcher(rule_count: usize) -> GeoIpMatcher {
    let mut builder = GeoIpMatcherBuilder::new();
    for i in 0..rule_count {
        let octet = (i % 256) as u8;
        let second_octet = ((i / 256) % 256) as u8;
        builder = builder
            .add_cidr(&format!("10.{}.{}.0/24", second_octet, octet), "proxy")
            .expect("valid CIDR");
    }
    // Add a known CIDR for testing
    builder = builder
        .add_cidr("192.168.0.0/16", "direct")
        .expect("valid CIDR");
    builder.build().expect("Failed to build GeoIP matcher")
}

/// Build a rule engine with the specified number of rules.
fn build_rule_engine(rule_count: usize) -> RuleEngine {
    let snapshot = build_routing_snapshot(rule_count);
    RuleEngine::new(snapshot)
}

/// Build a routing snapshot with rules.
fn build_routing_snapshot(rule_count: usize) -> rust_router::rules::RoutingSnapshot {
    let mut builder = RoutingSnapshotBuilder::new();

    // Add domain rules (1/3 of total)
    let domain_count = rule_count / 3;
    for i in 0..domain_count {
        builder
            .add_domain_rule(RuleType::DomainSuffix, &format!("domain{}.com", i), "proxy")
            .expect("valid domain rule");
    }

    // Add GeoIP rules (1/3 of total)
    let geoip_count = rule_count / 3;
    for i in 0..geoip_count {
        let octet = (i % 256) as u8;
        builder
            .add_geoip_rule(RuleType::IpCidr, &format!("10.0.{}.0/24", octet), "proxy")
            .expect("valid GeoIP rule");
    }

    // Add port rules (1/3 of total)
    let port_count = rule_count / 3;
    for i in 0..port_count.min(65535) {
        builder
            .add_port_rule(&format!("{}", 1000 + i), "proxy")
            .expect("valid port rule");
    }

    // Add known rules for testing
    builder
        .add_domain_rule(RuleType::DomainSuffix, "google.com", "google-proxy")
        .expect("valid rule")
        .add_geoip_rule(RuleType::IpCidr, "192.168.0.0/16", "local")
        .expect("valid rule")
        .add_port_rule("443", "https-proxy")
        .expect("valid rule");

    // Add some chains
    for i in 0..5 {
        builder.add_chain(&format!("chain-{}", i)).expect("valid chain");
    }

    builder
        .default_outbound("direct")
        .version(1)
        .build()
        .expect("Failed to build routing snapshot")
}

/// Build a minimal QUIC v1 Initial packet for benchmarking.
fn build_quic_initial_packet() -> Vec<u8> {
    let mut packet = vec![
        0xc3, // Long header, fixed bit, Initial type, PN length 4
        0x00, 0x00, 0x00, 0x01, // QUIC v1
        0x08, // DCID length
        0xba, 0xba, 0xba, 0xba, 0xba, 0xba, 0xba, 0xba, // DCID
        0x00, // SCID length
        0x00, // Token length (varint, 0)
    ];

    // Add length (varint) and payload
    packet.push(0x41); // Length prefix (2-byte varint)
    packet.push(0x00); // Length value low byte
    packet.extend_from_slice(&[0u8; 64]); // Payload

    packet
}

// ============================================================================
// Domain Matching Benchmarks
// ============================================================================

fn bench_domain_matching(c: &mut Criterion) {
    let mut group = c.benchmark_group("domain_matching");

    // Test with different rule counts
    for rule_count in [100, 1000, 10_000].iter() {
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

        group.bench_with_input(
            BenchmarkId::new("long_domain", rule_count),
            rule_count,
            |b, _| {
                b.iter(|| {
                    black_box(
                        matcher.match_domain("very.long.subdomain.chain.example.nonexistent.test"),
                    )
                });
            },
        );
    }

    group.finish();
}

// ============================================================================
// GeoIP Matching Benchmarks
// ============================================================================

fn bench_geoip_matching(c: &mut Criterion) {
    let mut group = c.benchmark_group("geoip_matching");

    // Build matcher with CIDR rules
    let matcher = build_geoip_matcher(1000);

    group.bench_function("cidr_match_local", |b| {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        b.iter(|| black_box(matcher.match_ip(ip)));
    });

    group.bench_function("cidr_match_first", |b| {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 100));
        b.iter(|| black_box(matcher.match_ip(ip)));
    });

    group.bench_function("cidr_match_middle", |b| {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 1, 128, 50));
        b.iter(|| black_box(matcher.match_ip(ip)));
    });

    group.bench_function("cidr_no_match", |b| {
        let ip = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        b.iter(|| black_box(matcher.match_ip(ip)));
    });

    group.bench_function("cidr_ipv6_no_match", |b| {
        let ip: IpAddr = "2001:db8::1".parse().unwrap();
        b.iter(|| black_box(matcher.match_ip(ip)));
    });

    group.finish();
}

// ============================================================================
// Rule Engine Benchmarks
// ============================================================================

fn bench_rule_engine(c: &mut Criterion) {
    let mut group = c.benchmark_group("rule_engine");

    let engine = build_rule_engine(1000);

    // Benchmark full connection matching with domain
    let conn_domain = ConnectionInfo::new("tcp", 443).with_domain("www.google.com");

    group.bench_function("match_with_domain", |b| {
        b.iter(|| black_box(engine.match_connection(&conn_domain)));
    });

    // Benchmark IP-only matching
    let conn_ip_only =
        ConnectionInfo::new("udp", 53).with_dest_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));

    group.bench_function("match_ip_only", |b| {
        b.iter(|| black_box(engine.match_connection(&conn_ip_only)));
    });

    // Benchmark local IP matching
    let conn_local =
        ConnectionInfo::new("tcp", 80).with_dest_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)));

    group.bench_function("match_local_ip", |b| {
        b.iter(|| black_box(engine.match_connection(&conn_local)));
    });

    // Benchmark port matching
    let conn_port = ConnectionInfo::new("tcp", 443);

    group.bench_function("match_port", |b| {
        b.iter(|| black_box(engine.match_connection(&conn_port)));
    });

    // Benchmark default fallback (no match)
    let conn_default =
        ConnectionInfo::new("tcp", 12345).with_dest_ip(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));

    group.bench_function("match_default_fallback", |b| {
        b.iter(|| black_box(engine.match_connection(&conn_default)));
    });

    // Benchmark combined domain + IP
    let conn_combined = ConnectionInfo::new("tcp", 443)
        .with_domain("www.google.com")
        .with_dest_ip(IpAddr::V4(Ipv4Addr::new(142, 250, 80, 46)));

    group.bench_function("match_domain_and_ip", |b| {
        b.iter(|| black_box(engine.match_connection(&conn_combined)));
    });

    // Benchmark hot reload
    group.bench_function("hot_reload", |b| {
        b.iter(|| {
            let new_snapshot = build_routing_snapshot(100);
            engine.reload(black_box(new_snapshot));
        });
    });

    // Benchmark snapshot load (lock-free read)
    group.bench_function("load_snapshot", |b| {
        b.iter(|| {
            let _ = black_box(engine.load());
        });
    });

    group.finish();
}

// ============================================================================
// UDP Session Benchmarks
// ============================================================================

fn bench_udp_sessions(c: &mut Criterion) {
    let mut group = c.benchmark_group("udp_sessions");

    let config = UdpSessionConfig::default();
    let manager = UdpSessionManager::new(config);

    // Pre-populate with sessions
    for i in 0..1000u16 {
        let key = UdpSessionKey::new(
            SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(192, 168, (i / 256) as u8, (i % 256) as u8)),
                10000 + i,
            ),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
        );
        manager.get_or_create(key, || UdpSession::new(key, "direct".to_string()));
    }

    // Ensure sessions are populated
    manager.run_pending_tasks();

    // Benchmark session lookup (hit)
    group.bench_function("session_lookup_hit", |b| {
        let key = UdpSessionKey::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 244)), 10500),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
        );
        b.iter(|| black_box(manager.get(&key)));
    });

    // Benchmark session lookup (miss)
    group.bench_function("session_lookup_miss", |b| {
        let key = UdpSessionKey::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 12345),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
        );
        b.iter(|| black_box(manager.get(&key)));
    });

    // Benchmark get_or_create (existing)
    group.bench_function("get_or_create_existing", |b| {
        let key = UdpSessionKey::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 244)), 10500),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
        );
        b.iter(|| {
            black_box(
                manager.get_or_create(key, || UdpSession::new(key, "direct".to_string())),
            )
        });
    });

    // Benchmark contains check
    group.bench_function("contains_check", |b| {
        let key = UdpSessionKey::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 244)), 10500),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
        );
        b.iter(|| black_box(manager.contains(&key)));
    });

    // Benchmark stats collection
    group.bench_function("stats_collection", |b| {
        b.iter(|| black_box(manager.stats()));
    });

    group.finish();
}

// ============================================================================
// QUIC Sniffing Benchmarks
// ============================================================================

fn bench_quic_sniffing(c: &mut Criterion) {
    let mut group = c.benchmark_group("quic_sniffing");

    // Valid QUIC Initial packet
    let quic_initial = build_quic_initial_packet();

    group.bench_function("is_quic_valid", |b| {
        b.iter(|| black_box(QuicSniffer::is_quic(&quic_initial)));
    });

    group.bench_function("is_initial_valid", |b| {
        b.iter(|| black_box(QuicSniffer::is_initial(&quic_initial)));
    });

    group.bench_function("sniff_initial", |b| {
        b.iter(|| black_box(QuicSniffer::sniff(&quic_initial)));
    });

    // Non-QUIC UDP packet
    let non_quic = vec![0u8; 100];

    group.bench_function("is_quic_invalid", |b| {
        b.iter(|| black_box(QuicSniffer::is_quic(&non_quic)));
    });

    group.bench_function("sniff_non_quic", |b| {
        b.iter(|| black_box(QuicSniffer::sniff(&non_quic)));
    });

    // HTTP-like packet
    let http_packet = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec();

    group.bench_function("is_quic_http", |b| {
        b.iter(|| black_box(QuicSniffer::is_quic(&http_packet)));
    });

    // TLS ClientHello-like packet
    let tls_packet = vec![0x16, 0x03, 0x01, 0x00, 0x05, 0x00, 0x00, 0x00];

    group.bench_function("is_quic_tls", |b| {
        b.iter(|| black_box(QuicSniffer::is_quic(&tls_packet)));
    });

    // Minimal packet (too short)
    let minimal = vec![0xc0, 0x00, 0x00];

    group.bench_function("sniff_too_short", |b| {
        b.iter(|| black_box(QuicSniffer::sniff(&minimal)));
    });

    group.finish();
}

// ============================================================================
// Connection Info Creation Benchmarks
// ============================================================================

fn bench_connection_info(c: &mut Criterion) {
    let mut group = c.benchmark_group("connection_info");

    group.bench_function("new_minimal", |b| {
        b.iter(|| black_box(ConnectionInfo::new("tcp", 443)));
    });

    group.bench_function("with_domain", |b| {
        b.iter(|| black_box(ConnectionInfo::new("tcp", 443).with_domain("www.google.com")));
    });

    group.bench_function("with_dest_ip", |b| {
        b.iter(|| {
            black_box(
                ConnectionInfo::new("tcp", 443)
                    .with_dest_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
            )
        });
    });

    group.bench_function("full_connection_info", |b| {
        b.iter(|| {
            black_box(
                ConnectionInfo::new("tcp", 443)
                    .with_domain("www.google.com")
                    .with_dest_ip(IpAddr::V4(Ipv4Addr::new(142, 250, 80, 46)))
                    .with_source_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 100)))
                    .with_sniffed_protocol("tls"),
            )
        });
    });

    group.finish();
}

// ============================================================================
// Criterion Configuration
// ============================================================================

criterion_group!(
    benches,
    bench_domain_matching,
    bench_geoip_matching,
    bench_rule_engine,
    bench_udp_sessions,
    bench_quic_sniffing,
    bench_connection_info,
);
criterion_main!(benches);
