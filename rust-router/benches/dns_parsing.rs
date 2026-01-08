//! Performance benchmarks for DNS message parsing using hickory-proto.
//!
//! Run with: `cargo bench --bench dns_parsing`
//!
//! Performance targets:
//! - A query parsing (80 bytes): <1 microsecond
//! - Response parsing (512 bytes): <2 microseconds
//!
//! These targets are critical for the DNS engine to achieve high throughput.
//! Each query/response must be parsed quickly to avoid becoming a bottleneck.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use hickory_proto::op::Message;
use hickory_proto::rr::{Name, RData, Record, RecordType};

// ============================================================================
// Test Data Generation
// ============================================================================

/// Generate a standard A query for example.com
///
/// This produces an approximately 80-byte DNS query packet.
fn generate_a_query() -> Vec<u8> {
    let mut message = Message::new();
    message.set_id(0x1234);
    message.set_recursion_desired(true);

    let name = Name::from_ascii("example.com").expect("valid name");
    let query = hickory_proto::op::Query::query(name, RecordType::A);
    message.add_query(query);

    message.to_vec().expect("serialize message")
}

/// Generate a standard AAAA query for a longer domain
fn generate_aaaa_query() -> Vec<u8> {
    let mut message = Message::new();
    message.set_id(0x5678);
    message.set_recursion_desired(true);

    let name = Name::from_ascii("subdomain.example.com").expect("valid name");
    let query = hickory_proto::op::Query::query(name, RecordType::AAAA);
    message.add_query(query);

    message.to_vec().expect("serialize message")
}

/// Generate a DNS response with multiple A records (approximately 207 bytes)
fn generate_response_with_records() -> Vec<u8> {
    let mut message = Message::new();
    message.set_id(0xabcd);
    message.set_recursion_desired(true);
    message.set_recursion_available(true);
    message.set_message_type(hickory_proto::op::MessageType::Response);

    // Add the query section
    let name = Name::from_ascii("example.com").expect("valid name");
    let query = hickory_proto::op::Query::query(name.clone(), RecordType::A);
    message.add_query(query);

    // Add multiple A records
    for i in 0..10 {
        let record = Record::from_rdata(
            name.clone(),
            300, // TTL
            RData::A(hickory_proto::rr::rdata::A::new(192, 168, 1, i)),
        );
        message.add_answer(record);
    }

    // Add an authority section record
    let ns_name = Name::from_ascii("ns1.example.com").expect("valid name");
    let ns_record = Record::from_rdata(
        name.clone(),
        3600,
        RData::NS(hickory_proto::rr::rdata::NS(ns_name)),
    );
    message.add_name_server(ns_record);

    message.to_vec().expect("serialize message")
}

/// Generate a DNS response with approximately 512 bytes
///
/// This function generates a realistic DNS response with multiple A records,
/// NS records, and additional records to reach the 512-byte target specified
/// in the Phase 7.0 plan for benchmark compliance.
fn generate_512_byte_response() -> Vec<u8> {
    let mut message = Message::new();
    message.set_id(0x512b);
    message.set_recursion_desired(true);
    message.set_recursion_available(true);
    message.set_message_type(hickory_proto::op::MessageType::Response);

    // Add the query section
    let name = Name::from_ascii("api.services.example.com").expect("valid name");
    let query = hickory_proto::op::Query::query(name.clone(), RecordType::A);
    message.add_query(query);

    // Add 25 A records to approach ~512 bytes
    // Each A record with name pointer is ~16 bytes, plus varying data
    for i in 0..25 {
        let octet3 = (i / 256) as u8;
        let octet4 = (i % 256) as u8;
        let record = Record::from_rdata(
            name.clone(),
            300, // TTL
            RData::A(hickory_proto::rr::rdata::A::new(10, 100, octet3, octet4)),
        );
        message.add_answer(record);
    }

    // Add authority section records
    let ns1_name = Name::from_ascii("ns1.example.com").expect("valid name");
    let ns2_name = Name::from_ascii("ns2.example.com").expect("valid name");
    let base_name = Name::from_ascii("example.com").expect("valid name");

    let ns1_record = Record::from_rdata(
        base_name.clone(),
        3600,
        RData::NS(hickory_proto::rr::rdata::NS(ns1_name.clone())),
    );
    message.add_name_server(ns1_record);

    let ns2_record = Record::from_rdata(
        base_name,
        3600,
        RData::NS(hickory_proto::rr::rdata::NS(ns2_name.clone())),
    );
    message.add_name_server(ns2_record);

    // Add glue records in additional section
    let ns1_a = Record::from_rdata(
        ns1_name,
        3600,
        RData::A(hickory_proto::rr::rdata::A::new(203, 0, 113, 1)),
    );
    message.add_additional(ns1_a);

    let ns2_a = Record::from_rdata(
        ns2_name,
        3600,
        RData::A(hickory_proto::rr::rdata::A::new(203, 0, 113, 2)),
    );
    message.add_additional(ns2_a);

    message.to_vec().expect("serialize message")
}

/// Generate a large response with many records
fn generate_large_response() -> Vec<u8> {
    let mut message = Message::new();
    message.set_id(0xdead);
    message.set_recursion_desired(true);
    message.set_recursion_available(true);
    message.set_message_type(hickory_proto::op::MessageType::Response);

    let name = Name::from_ascii("cdn.example.com").expect("valid name");
    let query = hickory_proto::op::Query::query(name.clone(), RecordType::A);
    message.add_query(query);

    // Add many A records
    for i in 0..50 {
        let octet3 = (i / 256) as u8;
        let octet4 = (i % 256) as u8;
        let record = Record::from_rdata(
            name.clone(),
            60,
            RData::A(hickory_proto::rr::rdata::A::new(10, 0, octet3, octet4)),
        );
        message.add_answer(record);
    }

    message.to_vec().expect("serialize message")
}

/// Generate an NXDOMAIN response
fn generate_nxdomain_response() -> Vec<u8> {
    let mut message = Message::new();
    message.set_id(0xbeef);
    message.set_recursion_desired(true);
    message.set_recursion_available(true);
    message.set_message_type(hickory_proto::op::MessageType::Response);
    message.set_response_code(hickory_proto::op::ResponseCode::NXDomain);

    let name = Name::from_ascii("nonexistent.example.com").expect("valid name");
    let query = hickory_proto::op::Query::query(name.clone(), RecordType::A);
    message.add_query(query);

    // Add SOA record in authority section
    let soa_name = Name::from_ascii("example.com").expect("valid name");
    let mname = Name::from_ascii("ns1.example.com").expect("valid name");
    let rname = Name::from_ascii("hostmaster.example.com").expect("valid name");
    let soa = hickory_proto::rr::rdata::SOA::new(
        mname,
        rname,
        2024010101, // serial
        3600,       // refresh
        1800,       // retry
        604800,     // expire
        300,        // minimum (negative TTL)
    );
    let soa_record = Record::from_rdata(soa_name, 300, RData::SOA(soa));
    message.add_name_server(soa_record);

    message.to_vec().expect("serialize message")
}

/// Generate raw bytes that look like a DNS query (for baseline comparison)
fn generate_raw_query_bytes() -> Vec<u8> {
    // Standard DNS query header (12 bytes) + question section
    // This is a manually constructed A query for "example.com"
    vec![
        // Header
        0x12, 0x34, // ID
        0x01, 0x00, // Flags: standard query, recursion desired
        0x00, 0x01, // QDCOUNT: 1 question
        0x00, 0x00, // ANCOUNT: 0
        0x00, 0x00, // NSCOUNT: 0
        0x00, 0x00, // ARCOUNT: 0
        // Question section
        0x07, // Label length: 7
        b'e', b'x', b'a', b'm', b'p', b'l', b'e', // "example"
        0x03, // Label length: 3
        b'c', b'o', b'm', // "com"
        0x00, // Root label (end of name)
        0x00, 0x01, // QTYPE: A (1)
        0x00, 0x01, // QCLASS: IN (1)
    ]
}

/// Generate a raw response packet (for baseline comparison)
fn generate_raw_response_bytes() -> Vec<u8> {
    // Standard DNS response with one A record
    let mut bytes = vec![
        // Header
        0x12, 0x34, // ID
        0x81, 0x80, // Flags: response, recursion desired, recursion available
        0x00, 0x01, // QDCOUNT: 1 question
        0x00, 0x01, // ANCOUNT: 1 answer
        0x00, 0x00, // NSCOUNT: 0
        0x00, 0x00, // ARCOUNT: 0
        // Question section (same as query)
        0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01,
        0x00, 0x01, // Answer section
        0xc0, 0x0c, // Name pointer to offset 12 (question name)
        0x00, 0x01, // TYPE: A
        0x00, 0x01, // CLASS: IN
        0x00, 0x00, 0x01, 0x2c, // TTL: 300 seconds
        0x00, 0x04, // RDLENGTH: 4 bytes
        0x5d, 0xb8, 0xd8, 0x22, // RDATA: 93.184.216.34 (example.com)
    ];

    // Pad to approximately 512 bytes with additional records
    while bytes.len() < 500 {
        // Add more answer records
        bytes.extend_from_slice(&[
            0xc0, 0x0c, // Name pointer
            0x00, 0x01, // TYPE: A
            0x00, 0x01, // CLASS: IN
            0x00, 0x00, 0x01, 0x2c, // TTL
            0x00, 0x04, // RDLENGTH
            0x5d, 0xb8, 0xd8, 0x23, // RDATA
        ]);
        // Update ANCOUNT
        bytes[7] = ((bytes[7] as u16 + 1) & 0xff) as u8;
    }

    bytes
}

// ============================================================================
// Query Parsing Benchmarks
// ============================================================================

fn bench_parse_queries(c: &mut Criterion) {
    let mut group = c.benchmark_group("dns_query_parsing");

    // Standard A query
    let a_query = generate_a_query();
    group.throughput(Throughput::Bytes(a_query.len() as u64));
    group.bench_with_input(
        BenchmarkId::new("a_query", a_query.len()),
        &a_query,
        |b, query| {
            b.iter(|| {
                let msg = Message::from_vec(black_box(query)).expect("parse query");
                black_box(msg)
            })
        },
    );

    // AAAA query (slightly longer domain)
    let aaaa_query = generate_aaaa_query();
    group.throughput(Throughput::Bytes(aaaa_query.len() as u64));
    group.bench_with_input(
        BenchmarkId::new("aaaa_query", aaaa_query.len()),
        &aaaa_query,
        |b, query| {
            b.iter(|| {
                let msg = Message::from_vec(black_box(query)).expect("parse query");
                black_box(msg)
            })
        },
    );

    // Raw bytes query (baseline)
    let raw_query = generate_raw_query_bytes();
    group.throughput(Throughput::Bytes(raw_query.len() as u64));
    group.bench_with_input(
        BenchmarkId::new("raw_query", raw_query.len()),
        &raw_query,
        |b, query| {
            b.iter(|| {
                let msg = Message::from_vec(black_box(query)).expect("parse query");
                black_box(msg)
            })
        },
    );

    group.finish();
}

// ============================================================================
// Response Parsing Benchmarks
// ============================================================================

fn bench_parse_responses(c: &mut Criterion) {
    let mut group = c.benchmark_group("dns_response_parsing");

    // Standard response with multiple records (~207 bytes)
    let response = generate_response_with_records();
    group.throughput(Throughput::Bytes(response.len() as u64));
    group.bench_with_input(
        BenchmarkId::new("multi_record_response", response.len()),
        &response,
        |b, resp| {
            b.iter(|| {
                let msg = Message::from_vec(black_box(resp)).expect("parse response");
                black_box(msg)
            })
        },
    );

    // 512-byte response (plan compliance target)
    let response_512 = generate_512_byte_response();
    group.throughput(Throughput::Bytes(response_512.len() as u64));
    group.bench_with_input(
        BenchmarkId::new("response_512_bytes", response_512.len()),
        &response_512,
        |b, resp| {
            b.iter(|| {
                let msg = Message::from_vec(black_box(resp)).expect("parse response");
                black_box(msg)
            })
        },
    );

    // NXDOMAIN response
    let nxdomain = generate_nxdomain_response();
    group.throughput(Throughput::Bytes(nxdomain.len() as u64));
    group.bench_with_input(
        BenchmarkId::new("nxdomain_response", nxdomain.len()),
        &nxdomain,
        |b, resp| {
            b.iter(|| {
                let msg = Message::from_vec(black_box(resp)).expect("parse response");
                black_box(msg)
            })
        },
    );

    // Large response with many records
    let large_response = generate_large_response();
    group.throughput(Throughput::Bytes(large_response.len() as u64));
    group.bench_with_input(
        BenchmarkId::new("large_response", large_response.len()),
        &large_response,
        |b, resp| {
            b.iter(|| {
                let msg = Message::from_vec(black_box(resp)).expect("parse response");
                black_box(msg)
            })
        },
    );

    // Raw bytes response (baseline)
    let raw_response = generate_raw_response_bytes();
    group.throughput(Throughput::Bytes(raw_response.len() as u64));
    group.bench_with_input(
        BenchmarkId::new("raw_response", raw_response.len()),
        &raw_response,
        |b, resp| {
            b.iter(|| {
                let msg = Message::from_vec(black_box(resp)).expect("parse response");
                black_box(msg)
            })
        },
    );

    group.finish();
}

// ============================================================================
// Message Serialization Benchmarks
// ============================================================================

fn bench_serialize(c: &mut Criterion) {
    let mut group = c.benchmark_group("dns_serialization");

    // Create a query message
    let mut query_msg = Message::new();
    query_msg.set_id(0x1234);
    query_msg.set_recursion_desired(true);
    let name = Name::from_ascii("example.com").expect("valid name");
    let query = hickory_proto::op::Query::query(name, RecordType::A);
    query_msg.add_query(query);

    group.bench_function("serialize_query", |b| {
        b.iter(|| {
            let bytes = black_box(&query_msg).to_vec().expect("serialize");
            black_box(bytes)
        })
    });

    // Create a response message
    let mut response_msg = Message::new();
    response_msg.set_id(0x1234);
    response_msg.set_recursion_desired(true);
    response_msg.set_recursion_available(true);
    response_msg.set_message_type(hickory_proto::op::MessageType::Response);

    let name = Name::from_ascii("example.com").expect("valid name");
    let query = hickory_proto::op::Query::query(name.clone(), RecordType::A);
    response_msg.add_query(query);

    for i in 0..5 {
        let record = Record::from_rdata(
            name.clone(),
            300,
            RData::A(hickory_proto::rr::rdata::A::new(192, 168, 1, i)),
        );
        response_msg.add_answer(record);
    }

    group.bench_function("serialize_response", |b| {
        b.iter(|| {
            let bytes = black_box(&response_msg).to_vec().expect("serialize");
            black_box(bytes)
        })
    });

    group.finish();
}

// ============================================================================
// Message Field Access Benchmarks
// ============================================================================

fn bench_message_access(c: &mut Criterion) {
    let mut group = c.benchmark_group("dns_message_access");

    // Parse a response once and benchmark field access
    let response = generate_response_with_records();
    let parsed = Message::from_vec(&response).expect("parse response");

    group.bench_function("get_id", |b| {
        b.iter(|| black_box(parsed.id()))
    });

    group.bench_function("get_queries", |b| {
        b.iter(|| black_box(parsed.queries()))
    });

    group.bench_function("get_answers", |b| {
        b.iter(|| black_box(parsed.answers()))
    });

    group.bench_function("iterate_answers", |b| {
        b.iter(|| {
            for record in parsed.answers() {
                black_box(record.name());
                black_box(record.ttl());
                black_box(record.data());
            }
        })
    });

    group.finish();
}

// ============================================================================
// Name Parsing Benchmarks
// ============================================================================

fn bench_name_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("dns_name_operations");

    group.bench_function("parse_simple_name", |b| {
        b.iter(|| {
            let name = Name::from_ascii(black_box("example.com")).expect("valid name");
            black_box(name)
        })
    });

    group.bench_function("parse_long_name", |b| {
        b.iter(|| {
            let name =
                Name::from_ascii(black_box("very.long.subdomain.chain.example.com")).expect("valid name");
            black_box(name)
        })
    });

    let name = Name::from_ascii("www.example.com").expect("valid name");
    group.bench_function("name_to_string", |b| {
        b.iter(|| {
            let s = black_box(&name).to_string();
            black_box(s)
        })
    });

    let parent = Name::from_ascii("example.com").expect("valid name");
    let child = Name::from_ascii("www.example.com").expect("valid name");
    group.bench_function("name_zone_of", |b| {
        b.iter(|| {
            let result = black_box(&parent).zone_of(black_box(&child));
            black_box(result)
        })
    });

    group.finish();
}

// ============================================================================
// Performance Target Validation
// ============================================================================

/// This test validates that our performance targets are achievable.
/// It is run as a benchmark but also serves as documentation.
///
/// Performance targets (from Phase 7.0 plan):
/// - A query parsing (~30 bytes): <1 microsecond
/// - Response parsing (~512 bytes): <2 microseconds
fn bench_validate_targets(c: &mut Criterion) {
    let mut group = c.benchmark_group("performance_targets");

    // Target: <1us for A query parsing
    // Note: Actual query size is ~29-30 bytes, not 80 bytes as originally estimated
    let a_query = generate_a_query();
    group.throughput(Throughput::Bytes(a_query.len() as u64));
    group.bench_with_input(
        BenchmarkId::new("target_query_lt_1us", a_query.len()),
        &a_query,
        |b, query| {
            b.iter(|| {
                let msg = Message::from_vec(black_box(query)).expect("parse query");
                black_box(msg)
            })
        },
    );

    // Target: <2us for 512-byte response parsing (plan compliance)
    let response = generate_512_byte_response();
    group.throughput(Throughput::Bytes(response.len() as u64));
    group.bench_with_input(
        BenchmarkId::new("target_response_lt_2us", response.len()),
        &response,
        |b, resp| {
            b.iter(|| {
                let msg = Message::from_vec(black_box(resp)).expect("parse response");
                black_box(msg)
            })
        },
    );

    group.finish();
}

// ============================================================================
// Criterion Configuration
// ============================================================================

criterion_group!(
    benches,
    bench_parse_queries,
    bench_parse_responses,
    bench_serialize,
    bench_message_access,
    bench_name_operations,
    bench_validate_targets,
);
criterion_main!(benches);
