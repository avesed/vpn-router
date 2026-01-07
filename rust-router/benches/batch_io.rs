//! Batch I/O benchmarks for Phase 6.8
//!
//! Run with: `cargo bench --bench batch_io`
//!
//! Performance targets:
//! - Batch receive: >20% improvement over single recv_from
//! - Batch send: >20% improvement over sequential sendto
//! - Zero-copy processing: <100ns per packet
//!
//! NOTE: These benchmarks require Linux for batch I/O functionality.
//! On other platforms, they will benchmark the fallback paths.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

// Only run actual batch I/O benchmarks on Linux
#[cfg(target_os = "linux")]
mod linux_benchmarks {
    use super::*;
    use rust_router::io::{BatchConfig, BatchReceiver, BatchSender};
    use std::net::{SocketAddr, UdpSocket};
    use std::os::unix::io::AsRawFd;

    // ============================================================================
    // Helper Functions
    // ============================================================================

    /// Generate test UDP packet data.
    fn generate_packet(size: usize) -> Vec<u8> {
        (0..size).map(|i| (i % 256) as u8).collect()
    }

    /// Create a pair of connected UDP sockets for testing.
    fn create_socket_pair() -> (UdpSocket, UdpSocket, SocketAddr, SocketAddr) {
        let sender = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
        let receiver = UdpSocket::bind("127.0.0.1:0").expect("bind receiver");

        sender.set_nonblocking(true).expect("nonblocking sender");
        receiver.set_nonblocking(true).expect("nonblocking receiver");

        let sender_addr = sender.local_addr().expect("sender addr");
        let receiver_addr = receiver.local_addr().expect("receiver addr");

        sender.connect(receiver_addr).expect("connect sender");

        (sender, receiver, sender_addr, receiver_addr)
    }

    // ============================================================================
    // BatchConfig Creation Benchmarks
    // ============================================================================

    /// Benchmark BatchConfig creation with various batch sizes.
    pub fn bench_batch_config_creation(c: &mut Criterion) {
        let mut group = c.benchmark_group("batch_config");

        group.bench_function("default", |b| {
            b.iter(|| black_box(BatchConfig::default()));
        });

        for batch_size in [16, 32, 64, 128, 256].iter() {
            group.bench_with_input(
                BenchmarkId::new("new", batch_size),
                batch_size,
                |b, &size| {
                    b.iter(|| black_box(BatchConfig::new(size)));
                },
            );
        }

        group.bench_function("with_buffer_size", |b| {
            b.iter(|| {
                black_box(
                    BatchConfig::new(64)
                        .with_buffer_size(2048)
                        .non_blocking(),
                )
            });
        });

        group.finish();
    }

    // ============================================================================
    // BatchReceiver Benchmarks
    // ============================================================================

    /// Benchmark BatchReceiver creation.
    pub fn bench_batch_receiver_creation(c: &mut Criterion) {
        let mut group = c.benchmark_group("batch_receiver_creation");

        for batch_size in [16, 32, 64, 128].iter() {
            let (_, receiver, _, _) = create_socket_pair();
            let fd = receiver.as_raw_fd();

            group.bench_with_input(
                BenchmarkId::new("new", batch_size),
                batch_size,
                |b, &size| {
                    b.iter(|| {
                        let config = BatchConfig::new(size).non_blocking();
                        black_box(BatchReceiver::new(fd, config))
                    });
                },
            );
        }

        group.finish();
    }

    /// Benchmark single-packet vs batch receive (simulated).
    ///
    /// This benchmark compares:
    /// - Single recv_from calls
    /// - Batch recvmmsg calls
    pub fn bench_receive_comparison(c: &mut Criterion) {
        let mut group = c.benchmark_group("recv_comparison");

        let packet_sizes = [512, 1024, 1500];
        let batch_sizes = [16, 32, 64, 128];

        for &packet_size in &packet_sizes {
            group.throughput(Throughput::Bytes(packet_size as u64));

            // Single recv_from baseline
            group.bench_with_input(
                BenchmarkId::new("single_recv", packet_size),
                &packet_size,
                |b, &size| {
                    let (sender, receiver, _, _) = create_socket_pair();
                    let packet = generate_packet(size);
                    let mut buf = vec![0u8; size + 100];

                    b.iter(|| {
                        // Send a packet
                        let _ = sender.send(&packet);
                        // Receive it
                        let result = receiver.recv_from(&mut buf);
                        black_box(result)
                    });
                },
            );
        }

        // Batch recvmmsg with different batch sizes
        for &batch_size in &batch_sizes {
            let packet_size = 1024;
            group.throughput(Throughput::Bytes((packet_size * batch_size) as u64));

            group.bench_with_input(
                BenchmarkId::new("batch_recv", batch_size),
                &batch_size,
                |b, &size| {
                    let (sender, receiver, _, _) = create_socket_pair();
                    let fd = receiver.as_raw_fd();
                    let config = BatchConfig::new(size).with_buffer_size(packet_size).non_blocking();
                    let mut batch_receiver = BatchReceiver::new(fd, config);

                    let packet = generate_packet(packet_size);

                    b.iter(|| {
                        // Send batch_size packets
                        for _ in 0..size {
                            let _ = sender.send(&packet);
                        }
                        // Receive batch
                        let result = batch_receiver.recv_batch();
                        black_box(result)
                    });
                },
            );
        }

        group.finish();
    }

    // ============================================================================
    // BatchSender Benchmarks
    // ============================================================================

    /// Benchmark BatchSender creation.
    pub fn bench_batch_sender_creation(c: &mut Criterion) {
        let mut group = c.benchmark_group("batch_sender_creation");

        let (sender, _, _, _) = create_socket_pair();
        let fd = sender.as_raw_fd();

        group.bench_function("new", |b| {
            b.iter(|| black_box(BatchSender::new(fd)));
        });

        group.finish();
    }

    /// Benchmark single-packet vs batch send.
    ///
    /// This benchmark compares:
    /// - Sequential send_to calls
    /// - Batch sendmmsg calls
    pub fn bench_send_comparison(c: &mut Criterion) {
        let mut group = c.benchmark_group("send_comparison");

        let packet_sizes = [512, 1024, 1500];
        let batch_sizes = [16, 32, 64, 128];

        // Single send baseline
        for &packet_size in &packet_sizes {
            group.throughput(Throughput::Bytes(packet_size as u64));

            group.bench_with_input(
                BenchmarkId::new("single_send", packet_size),
                &packet_size,
                |b, &size| {
                    let (sender, receiver, _, receiver_addr) = create_socket_pair();
                    let packet = generate_packet(size);

                    b.iter(|| {
                        let result = sender.send_to(&packet, receiver_addr);
                        // Drain the receiver to avoid buffer full
                        let mut buf = vec![0u8; size + 100];
                        let _ = receiver.recv_from(&mut buf);
                        black_box(result)
                    });
                },
            );
        }

        // Batch sendmmsg with different batch sizes
        for &batch_size in &batch_sizes {
            let packet_size = 1024;
            group.throughput(Throughput::Bytes((packet_size * batch_size) as u64));

            group.bench_with_input(
                BenchmarkId::new("batch_send", batch_size),
                &batch_size,
                |b, &size| {
                    let (sender, receiver, _, receiver_addr) = create_socket_pair();
                    let fd = sender.as_raw_fd();
                    let mut batch_sender = BatchSender::new(fd);

                    let packet = generate_packet(packet_size);
                    let packets: Vec<(&[u8], SocketAddr)> =
                        (0..size).map(|_| (packet.as_slice(), receiver_addr)).collect();

                    b.iter(|| {
                        let result = batch_sender.send_batch(&packets);
                        // Drain the receiver
                        let mut buf = vec![0u8; packet_size + 100];
                        for _ in 0..size {
                            let _ = receiver.recv_from(&mut buf);
                        }
                        black_box(result)
                    });
                },
            );
        }

        group.finish();
    }

    // ============================================================================
    // IPv4 vs IPv6 Benchmarks
    // ============================================================================

    /// Benchmark IPv4 vs IPv6 batch send performance.
    pub fn bench_ipv4_vs_ipv6(c: &mut Criterion) {
        let mut group = c.benchmark_group("ipv4_vs_ipv6");

        let packet_size = 1024;
        let batch_size = 64;

        group.throughput(Throughput::Bytes((packet_size * batch_size) as u64));

        // IPv4 batch send
        group.bench_function("ipv4_batch_send", |b| {
            let sender = UdpSocket::bind("127.0.0.1:0").expect("bind v4 sender");
            let receiver = UdpSocket::bind("127.0.0.1:0").expect("bind v4 receiver");
            sender.set_nonblocking(true).expect("nonblocking");
            receiver.set_nonblocking(true).expect("nonblocking");
            let receiver_addr = receiver.local_addr().expect("addr");

            let fd = sender.as_raw_fd();
            let mut batch_sender = BatchSender::new(fd);

            let packet = generate_packet(packet_size);
            let packets: Vec<(&[u8], SocketAddr)> = (0..batch_size)
                .map(|_| (packet.as_slice(), receiver_addr))
                .collect();

            b.iter(|| {
                let result = batch_sender.send_batch(&packets);
                // Drain receiver
                let mut buf = vec![0u8; packet_size + 100];
                for _ in 0..batch_size {
                    let _ = receiver.recv_from(&mut buf);
                }
                black_box(result)
            });
        });

        // IPv6 batch send
        group.bench_function("ipv6_batch_send", |b| {
            let sender = match UdpSocket::bind("[::1]:0") {
                Ok(s) => s,
                Err(_) => {
                    // IPv6 may not be available
                    eprintln!("IPv6 not available, skipping benchmark");
                    return;
                }
            };
            let receiver = UdpSocket::bind("[::1]:0").expect("bind v6 receiver");
            sender.set_nonblocking(true).expect("nonblocking");
            receiver.set_nonblocking(true).expect("nonblocking");
            let receiver_addr = receiver.local_addr().expect("addr");

            let fd = sender.as_raw_fd();
            let mut batch_sender = BatchSender::new(fd);

            let packet = generate_packet(packet_size);
            let packets: Vec<(&[u8], SocketAddr)> = (0..batch_size)
                .map(|_| (packet.as_slice(), receiver_addr))
                .collect();

            b.iter(|| {
                let result = batch_sender.send_batch(&packets);
                // Drain receiver
                let mut buf = vec![0u8; packet_size + 100];
                for _ in 0..batch_size {
                    let _ = receiver.recv_from(&mut buf);
                }
                black_box(result)
            });
        });

        group.finish();
    }

    // ============================================================================
    // Batch Size Optimization Benchmarks
    // ============================================================================

    /// Benchmark to find optimal batch size for the current system.
    ///
    /// Tests batch sizes from 8 to 256 to find the sweet spot between
    /// syscall reduction and buffer management overhead.
    pub fn bench_optimal_batch_size(c: &mut Criterion) {
        let mut group = c.benchmark_group("optimal_batch_size");
        group.sample_size(50); // Fewer samples for comprehensive test

        let packet_size = 1420; // Typical WireGuard MTU

        // Test a range of batch sizes
        for batch_size in [8, 16, 32, 48, 64, 96, 128, 192, 256].iter() {
            group.throughput(Throughput::Bytes((packet_size * batch_size) as u64));

            group.bench_with_input(
                BenchmarkId::new("send", batch_size),
                batch_size,
                |b, &size| {
                    let (sender, receiver, _, receiver_addr) = create_socket_pair();
                    let fd = sender.as_raw_fd();
                    let mut batch_sender = BatchSender::new(fd);

                    let packet = generate_packet(packet_size);
                    let packets: Vec<(&[u8], SocketAddr)> = (0..size)
                        .map(|_| (packet.as_slice(), receiver_addr))
                        .collect();

                    b.iter(|| {
                        let result = batch_sender.send_batch(&packets);
                        // Drain receiver
                        let mut buf = vec![0u8; packet_size + 100];
                        for _ in 0..size {
                            let _ = receiver.recv_from(&mut buf);
                        }
                        black_box(result)
                    });
                },
            );
        }

        group.finish();
    }

    // ============================================================================
    // Statistics Overhead Benchmarks
    // ============================================================================

    /// Benchmark statistics collection overhead.
    pub fn bench_stats_overhead(c: &mut Criterion) {
        let mut group = c.benchmark_group("batch_stats");

        let (sender, _, _, _) = create_socket_pair();
        let fd = sender.as_raw_fd();
        let batch_sender = BatchSender::new(fd);

        // Pre-populate some stats
        for _ in 0..100 {
            let _ = batch_sender.stats();
        }

        group.bench_function("stats_read", |b| {
            b.iter(|| black_box(batch_sender.stats()));
        });

        group.bench_function("avg_packets_per_batch", |b| {
            let stats = batch_sender.stats();
            b.iter(|| black_box(stats.avg_packets_per_batch()));
        });

        group.finish();
    }
}

// ============================================================================
// Fallback Benchmarks (Non-Linux)
// ============================================================================

#[cfg(not(target_os = "linux"))]
mod fallback_benchmarks {
    use super::*;

    /// Placeholder benchmark for non-Linux platforms.
    pub fn bench_fallback(c: &mut Criterion) {
        let mut group = c.benchmark_group("batch_io_fallback");

        group.bench_function("placeholder", |b| {
            b.iter(|| {
                // Batch I/O is not available on this platform
                black_box(())
            });
        });

        group.finish();
    }
}

// ============================================================================
// Cross-Platform Buffer Pool Benchmarks
// ============================================================================

mod buffer_pool_benchmarks {
    use super::*;
    use rust_router::io::{
        LocalBufferCache, UdpBufferPool,
        DEFAULT_LOCAL_CACHE_SIZE, DEFAULT_UDP_BUFFER_SIZE,
    };
    use std::sync::Arc;

    /// Benchmark buffer pool operations.
    pub fn bench_buffer_pool(c: &mut Criterion) {
        let mut group = c.benchmark_group("buffer_pool");

        // Test different pool sizes
        for capacity in [64, 128, 256, 512].iter() {
            let pool = Arc::new(UdpBufferPool::new(*capacity, DEFAULT_UDP_BUFFER_SIZE));

            group.bench_with_input(
                BenchmarkId::new("get_buffer", capacity),
                capacity,
                |b, _| {
                    b.iter(|| {
                        let buffer = pool.get();
                        black_box(buffer)
                    });
                },
            );

            group.bench_with_input(
                BenchmarkId::new("get_return_cycle", capacity),
                capacity,
                |b, _| {
                    b.iter(|| {
                        let buffer = pool.get();
                        let len = buffer.len();
                        drop(buffer); // Return to pool
                        black_box(len)
                    });
                },
            );
        }

        group.finish();
    }

    /// Benchmark local buffer cache (per-worker cache).
    pub fn bench_local_buffer_cache(c: &mut Criterion) {
        let mut group = c.benchmark_group("local_buffer_cache");

        let pool = Arc::new(UdpBufferPool::with_defaults());

        for cache_size in [4, 8, 16, 32].iter() {
            group.bench_with_input(
                BenchmarkId::new("get_buffer", cache_size),
                cache_size,
                |b, &size| {
                    let cache = LocalBufferCache::new(pool.clone(), size);

                    b.iter(|| {
                        let buffer = cache.get();
                        black_box(buffer)
                    });
                },
            );

            group.bench_with_input(
                BenchmarkId::new("get_return_cycle", cache_size),
                cache_size,
                |b, &size| {
                    let cache = LocalBufferCache::new(pool.clone(), size);

                    b.iter(|| {
                        let buffer = cache.get();
                        let len = buffer.len();
                        drop(buffer); // Return to cache
                        black_box(len)
                    });
                },
            );
        }

        // Benchmark stats collection
        let cache = LocalBufferCache::new(pool.clone(), DEFAULT_LOCAL_CACHE_SIZE);
        group.bench_function("cache_stats", |b| {
            b.iter(|| black_box(cache.stats()));
        });

        group.finish();
    }

    /// Benchmark pool vs cache comparison.
    pub fn bench_pool_vs_cache(c: &mut Criterion) {
        let mut group = c.benchmark_group("pool_vs_cache");

        let pool = Arc::new(UdpBufferPool::with_defaults());
        let cache = LocalBufferCache::new(pool.clone(), 16);

        // Direct pool access
        group.bench_function("direct_pool_get", |b| {
            b.iter(|| {
                let buffer = pool.get();
                black_box(buffer)
            });
        });

        // Local cache access (should be faster due to thread-local caching)
        group.bench_function("local_cache_get", |b| {
            b.iter(|| {
                let buffer = cache.get();
                black_box(buffer)
            });
        });

        // Hot path: multiple gets/returns
        group.bench_function("direct_pool_hot_path_10", |b| {
            b.iter(|| {
                for _ in 0..10 {
                    let buffer = pool.get();
                    black_box(&buffer);
                    drop(buffer);
                }
            });
        });

        group.bench_function("local_cache_hot_path_10", |b| {
            b.iter(|| {
                for _ in 0..10 {
                    let buffer = cache.get();
                    black_box(&buffer);
                    drop(buffer);
                }
            });
        });

        group.finish();
    }
}

// ============================================================================
// Criterion Configuration
// ============================================================================

#[cfg(target_os = "linux")]
criterion_group!(
    benches,
    linux_benchmarks::bench_batch_config_creation,
    linux_benchmarks::bench_batch_receiver_creation,
    linux_benchmarks::bench_receive_comparison,
    linux_benchmarks::bench_batch_sender_creation,
    linux_benchmarks::bench_send_comparison,
    linux_benchmarks::bench_ipv4_vs_ipv6,
    linux_benchmarks::bench_optimal_batch_size,
    linux_benchmarks::bench_stats_overhead,
    buffer_pool_benchmarks::bench_buffer_pool,
    buffer_pool_benchmarks::bench_local_buffer_cache,
    buffer_pool_benchmarks::bench_pool_vs_cache,
);

#[cfg(not(target_os = "linux"))]
criterion_group!(
    benches,
    fallback_benchmarks::bench_fallback,
    buffer_pool_benchmarks::bench_buffer_pool,
    buffer_pool_benchmarks::bench_local_buffer_cache,
    buffer_pool_benchmarks::bench_pool_vs_cache,
);

criterion_main!(benches);
