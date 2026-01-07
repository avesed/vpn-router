//! UDP Worker Pool for Multi-Core Scaling
//!
//! This module provides a multi-worker pool for UDP packet processing.
//! Each worker binds to the same address using `SO_REUSEPORT`, allowing the
//! Linux kernel to distribute incoming packets across workers.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────┐
//! │                     UDP Worker Pool                      │
//! ├─────────────────────────────────────────────────────────┤
//! │                                                          │
//! │  Worker 0 ──► TproxyUdpListener ──► UdpPacketProcessor  │
//! │       ▲                                                  │
//! │       │ SO_REUSEPORT                                     │
//! │       │                                                  │
//! │  Worker 1 ──► TproxyUdpListener ──► UdpPacketProcessor  │
//! │       ▲                                                  │
//! │       │                                                  │
//! │  Worker N ──► TproxyUdpListener ──► UdpPacketProcessor  │
//! │                                                          │
//! │  Kernel Load Distribution (4-tuple hash)                 │
//! │                                                          │
//! └─────────────────────────────────────────────────────────┘
//! ```
//!
//! # `SO_REUSEPORT` Benefits
//!
//! - Kernel distributes packets based on 4-tuple hash (src IP, src port, dst IP, dst port)
//! - Each flow (client) is handled by a single worker (consistent hashing)
//! - No lock contention on socket accept/recv
//! - Linear scaling with CPU cores
//!
//! # Example
//!
//! ```no_run
//! use rust_router::tproxy::UdpWorkerPool;
//! use rust_router::connection::UdpPacketProcessor;
//! use rust_router::outbound::OutboundManager;
//! use rust_router::rules::{RuleEngine, RoutingSnapshotBuilder};
//! use rust_router::config::ListenConfig;
//! use std::sync::Arc;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = ListenConfig::default();
//! let processor = Arc::new(UdpPacketProcessor::new_default());
//! let snapshot = RoutingSnapshotBuilder::new()
//!     .default_outbound("direct")
//!     .version(1)
//!     .build()
//!     .unwrap();
//! let rule_engine = Arc::new(RuleEngine::new(snapshot));
//! let outbound_manager = Arc::new(OutboundManager::new());
//!
//! // Create worker pool with rule engine (default: num_cpus workers)
//! let pool = UdpWorkerPool::new(&config, None, processor, rule_engine, outbound_manager)?;
//!
//! // Run until shutdown signal
//! // pool.shutdown().await;
//! # Ok(())
//! # }
//! ```

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;

use tokio::sync::broadcast;
use tokio::task::JoinHandle;
use tracing::{debug, error, info, trace, warn};

use super::TproxyUdpListener;
use crate::config::ListenConfig;
use crate::connection::{UdpPacketProcessor, UdpProcessorStatsSnapshot, UdpSessionKey};
use crate::error::UdpError;
use crate::io::{BufferPoolConfig, LocalBufferCache, UdpBufferPool};
use crate::outbound::OutboundManager;
use crate::rules::RuleEngine;

/// Default buffer pool capacity per worker
const DEFAULT_BUFFER_POOL_CAPACITY: usize = 256;

/// Default local buffer cache size per worker (PERF-4 FIX)
/// This reduces global pool contention under high load.
const DEFAULT_LOCAL_CACHE_SIZE: usize = 32;

/// Statistics for the UDP worker pool
#[derive(Debug)]
pub struct UdpWorkerPoolStats {
    /// Total packets processed across all workers
    packets_processed: AtomicU64,
    /// Total bytes received across all workers
    bytes_received: AtomicU64,
    /// Number of currently active workers
    workers_active: AtomicU32,
    /// Total number of workers spawned
    workers_total: AtomicU32,
    /// Number of worker errors
    worker_errors: AtomicU64,
}

impl UdpWorkerPoolStats {
    /// Create new stats instance
    fn new() -> Self {
        Self {
            packets_processed: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            workers_active: AtomicU32::new(0),
            workers_total: AtomicU32::new(0),
            worker_errors: AtomicU64::new(0),
        }
    }

    /// Get total packets processed
    #[must_use]
    pub fn packets_processed(&self) -> u64 {
        self.packets_processed.load(Ordering::Relaxed)
    }

    /// Get total bytes received
    #[must_use]
    pub fn bytes_received(&self) -> u64 {
        self.bytes_received.load(Ordering::Relaxed)
    }

    /// Get number of active workers
    #[must_use]
    pub fn workers_active(&self) -> u32 {
        self.workers_active.load(Ordering::Relaxed)
    }

    /// Get total workers spawned
    #[must_use]
    pub fn workers_total(&self) -> u32 {
        self.workers_total.load(Ordering::Relaxed)
    }

    /// Get number of worker errors
    #[must_use]
    pub fn worker_errors(&self) -> u64 {
        self.worker_errors.load(Ordering::Relaxed)
    }

    /// Get a snapshot of all stats
    #[must_use]
    pub fn snapshot(&self) -> UdpWorkerPoolStatsSnapshot {
        UdpWorkerPoolStatsSnapshot {
            packets_processed: self.packets_processed(),
            bytes_received: self.bytes_received(),
            workers_active: self.workers_active(),
            workers_total: self.workers_total(),
            worker_errors: self.worker_errors(),
        }
    }

    /// Record packet processing
    fn record_packet(&self, bytes: usize) {
        self.packets_processed.fetch_add(1, Ordering::Relaxed);
        self.bytes_received.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    /// Record worker started
    fn worker_started(&self) {
        self.workers_active.fetch_add(1, Ordering::Relaxed);
    }

    /// Record worker stopped
    fn worker_stopped(&self) {
        self.workers_active.fetch_sub(1, Ordering::Relaxed);
    }

    /// Record worker error
    fn record_error(&self) {
        self.worker_errors.fetch_add(1, Ordering::Relaxed);
    }
}

impl Default for UdpWorkerPoolStats {
    fn default() -> Self {
        Self::new()
    }
}

/// Snapshot of worker pool statistics
#[derive(Debug, Clone, Copy)]
pub struct UdpWorkerPoolStatsSnapshot {
    /// Total packets processed
    pub packets_processed: u64,
    /// Total bytes received
    pub bytes_received: u64,
    /// Active workers
    pub workers_active: u32,
    /// Total workers spawned
    pub workers_total: u32,
    /// Worker errors
    pub worker_errors: u64,
}

/// Configuration for the UDP worker pool
#[derive(Debug, Clone, Copy)]
pub struct UdpWorkerPoolConfig {
    /// Number of workers (default: `num_cpus`)
    pub num_workers: usize,
    /// Buffer pool capacity per worker
    pub buffer_pool_capacity: usize,
    /// Buffer size for UDP packets
    pub buffer_size: usize,
}

impl Default for UdpWorkerPoolConfig {
    fn default() -> Self {
        Self {
            num_workers: num_cpus::get(),
            buffer_pool_capacity: DEFAULT_BUFFER_POOL_CAPACITY,
            buffer_size: 65535,
        }
    }
}

impl UdpWorkerPoolConfig {
    /// Create config with specified number of workers
    #[must_use]
    pub fn with_workers(mut self, num: usize) -> Self {
        self.num_workers = num;
        self
    }

    /// Set buffer pool capacity
    #[must_use]
    pub fn with_buffer_pool_capacity(mut self, capacity: usize) -> Self {
        self.buffer_pool_capacity = capacity;
        self
    }
}

/// A pool of UDP workers for multi-core packet processing.
///
/// Each worker has its own TPROXY UDP listener bound to the same address
/// using `SO_REUSEPORT`. The kernel distributes packets across workers
/// based on a 4-tuple hash.
pub struct UdpWorkerPool {
    /// Worker task handles
    workers: Vec<JoinHandle<()>>,
    /// Shutdown signal sender
    shutdown_tx: broadcast::Sender<()>,
    /// Pool statistics
    stats: Arc<UdpWorkerPoolStats>,
    /// Shared buffer pool
    buffer_pool: Arc<UdpBufferPool>,
    /// Whether pool is running
    running: AtomicBool,
    /// Shared packet processor (for stats/session access via IPC)
    processor: Arc<UdpPacketProcessor>,
}

impl UdpWorkerPool {
    /// Create a new UDP worker pool with rule engine integration.
    ///
    /// # Arguments
    ///
    /// * `config` - Listen configuration (address, timeouts, etc.)
    /// * `num_workers` - Number of workers (None = `num_cpus`)
    /// * `processor` - Shared UDP packet processor
    /// * `rule_engine` - Rule engine for routing decisions
    /// * `outbound_manager` - Outbound manager for forwarding
    ///
    /// # Errors
    ///
    /// Returns `UdpError` if any worker fails to bind.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rust_router::tproxy::UdpWorkerPool;
    /// use rust_router::connection::UdpPacketProcessor;
    /// use rust_router::outbound::OutboundManager;
    /// use rust_router::rules::{RuleEngine, RoutingSnapshotBuilder};
    /// use rust_router::config::ListenConfig;
    /// use std::sync::Arc;
    ///
    /// # fn example() -> Result<(), rust_router::error::UdpError> {
    /// let config = ListenConfig::default();
    /// let processor = Arc::new(UdpPacketProcessor::new_default());
    /// let snapshot = RoutingSnapshotBuilder::new()
    ///     .default_outbound("direct")
    ///     .version(1)
    ///     .build()
    ///     .unwrap();
    /// let rule_engine = Arc::new(RuleEngine::new(snapshot));
    /// let outbound_manager = Arc::new(OutboundManager::new());
    ///
    /// // Use 4 workers with rule engine
    /// let pool = UdpWorkerPool::new(&config, Some(4), processor, rule_engine, outbound_manager)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(
        config: &ListenConfig,
        num_workers: Option<usize>,
        processor: Arc<UdpPacketProcessor>,
        rule_engine: Arc<RuleEngine>,
        outbound_manager: Arc<OutboundManager>,
    ) -> Result<Self, UdpError> {
        let pool_config = UdpWorkerPoolConfig {
            num_workers: num_workers.unwrap_or_else(num_cpus::get),
            ..Default::default()
        };

        Self::with_config(config, pool_config, processor, rule_engine, outbound_manager)
    }

    /// Create worker pool with custom configuration and rule engine.
    ///
    /// # Arguments
    ///
    /// * `listen_config` - Listen configuration
    /// * `pool_config` - Worker pool configuration
    /// * `processor` - Shared UDP packet processor
    /// * `rule_engine` - Rule engine for routing decisions
    /// * `outbound_manager` - Outbound manager for forwarding
    ///
    /// # Errors
    ///
    /// Returns `UdpError` if any worker fails to bind.
    #[allow(clippy::needless_pass_by_value)] // Arc is cloned per worker, pass by value is idiomatic
    pub fn with_config(
        listen_config: &ListenConfig,
        pool_config: UdpWorkerPoolConfig,
        processor: Arc<UdpPacketProcessor>,
        rule_engine: Arc<RuleEngine>,
        outbound_manager: Arc<OutboundManager>,
    ) -> Result<Self, UdpError> {
        let num_workers = pool_config.num_workers.max(1);
        let (shutdown_tx, _) = broadcast::channel(1);
        let stats = Arc::new(UdpWorkerPoolStats::new());

        // Create shared buffer pool
        let buffer_pool = BufferPoolConfig::new(
            pool_config.buffer_pool_capacity * num_workers,
            pool_config.buffer_size,
        )
        .with_prewarm(pool_config.buffer_pool_capacity)
        .build();

        let mut workers = Vec::with_capacity(num_workers);

        info!(
            "Creating UDP worker pool with {} workers on {}",
            num_workers, listen_config.address
        );

        for worker_id in 0..num_workers {
            // Each worker binds to the same address with SO_REUSEPORT
            let listener = TproxyUdpListener::bind(listen_config).map_err(|e| {
                error!("Worker {} failed to bind: {}", worker_id, e);
                e
            })?;

            let processor = Arc::clone(&processor);
            let rule_engine = Arc::clone(&rule_engine);
            let outbound_manager = Arc::clone(&outbound_manager);
            let shutdown_rx = shutdown_tx.subscribe();
            let worker_stats = Arc::clone(&stats);
            let worker_buffer_pool = Arc::clone(&buffer_pool);

            stats.workers_total.fetch_add(1, Ordering::Relaxed);

            workers.push(tokio::spawn(async move {
                Self::worker_loop(
                    worker_id,
                    listener,
                    processor,
                    rule_engine,
                    outbound_manager,
                    shutdown_rx,
                    worker_stats,
                    worker_buffer_pool,
                )
                .await;
            }));

            debug!("UDP worker {} started", worker_id);
        }

        info!(
            "UDP worker pool started with {} workers",
            stats.workers_total.load(Ordering::Relaxed)
        );

        // Store processor reference for IPC access
        Ok(Self {
            workers,
            shutdown_tx,
            stats,
            buffer_pool,
            running: AtomicBool::new(true),
            processor,
        })
    }

    /// The main worker loop with rule engine integration.
    ///
    /// Receives UDP packets and processes them through the rule engine
    /// for proper routing decisions.
    ///
    /// # Performance
    ///
    /// Uses `recv_pooled()` for zero-copy packet receive:
    /// - Gets buffer from local cache (fast path) or global pool (slow path)
    /// - Receives into pooled buffer
    /// - Converts to Bytes via `freeze()` (zero-copy)
    ///
    /// PERF-4 FIX: Uses `LocalBufferCache` per worker to reduce global pool
    /// contention. Under high load, this eliminates cache line bouncing
    /// when multiple workers compete for the shared `ArrayQueue`.
    async fn worker_loop(
        id: usize,
        listener: TproxyUdpListener,
        processor: Arc<UdpPacketProcessor>,
        rule_engine: Arc<RuleEngine>,
        outbound_manager: Arc<OutboundManager>,
        mut shutdown_rx: broadcast::Receiver<()>,
        stats: Arc<UdpWorkerPoolStats>,
        buffer_pool: Arc<UdpBufferPool>,
    ) {
        stats.worker_started();
        debug!("Worker {} starting receive loop with rule engine", id);

        // PERF-4 FIX: Create per-worker local buffer cache to reduce global pool contention
        let local_cache = LocalBufferCache::new(Arc::clone(&buffer_pool), DEFAULT_LOCAL_CACHE_SIZE);

        loop {
            // Get a buffer from the local cache (fast path) or global pool (slow path)
            // PERF-1 FIX + PERF-4 FIX: Zero-copy receive with local caching
            let buf = local_cache.get();

            tokio::select! {
                biased;

                // Shutdown signal has priority
                _ = shutdown_rx.recv() => {
                    debug!("Worker {} received shutdown signal", id);
                    break;
                }

                // Receive packet using zero-copy pooled buffer
                result = listener.recv_pooled(buf) => {
                    match result {
                        Ok(packet) => {
                            stats.record_packet(packet.len());
                            trace!(
                                "Worker {}: {} -> {} ({} bytes)",
                                id,
                                packet.client_addr,
                                packet.original_dst,
                                packet.len()
                            );

                            // Process packet with rule engine integration
                            // This enables QUIC SNI sniffing, domain/GeoIP rules, and DSCP chains
                            let _ = processor
                                .process_with_rules(&packet, &rule_engine, &outbound_manager)
                                .await;
                        }
                        Err(UdpError::NotReady) => {
                            // Listener was deactivated
                            debug!("Worker {} listener not ready", id);
                            break;
                        }
                        Err(e) => {
                            stats.record_error();
                            if !e.is_recoverable() {
                                error!("Worker {} fatal error: {}", id, e);
                                break;
                            }
                            warn!("Worker {} recoverable error: {}", id, e);
                        }
                    }
                }
            }
        }

        // PERF-4 FIX: Flush local cache back to global pool before worker exits
        // This ensures buffers are not lost and can be reused by other workers
        local_cache.flush();
        debug!(
            "Worker {} flushed local buffer cache (hit rate: {:.1}%)",
            id,
            local_cache.stats().local_hit_rate() * 100.0
        );

        stats.worker_stopped();
        info!("Worker {} stopped", id);
    }

    /// Shutdown the worker pool gracefully.
    ///
    /// Sends shutdown signal to all workers and waits for them to complete.
    pub async fn shutdown(&mut self) {
        if !self.running.swap(false, Ordering::SeqCst) {
            // Already shut down
            return;
        }

        info!("Shutting down UDP worker pool");

        // Send shutdown signal
        let _ = self.shutdown_tx.send(());

        // Wait for all workers to complete
        for (i, worker) in self.workers.drain(..).enumerate() {
            match worker.await {
                Ok(()) => debug!("Worker {} joined successfully", i),
                Err(e) => warn!("Worker {} join error: {}", i, e),
            }
        }

        info!(
            "UDP worker pool shutdown complete. Stats: packets={}, bytes={}",
            self.stats.packets_processed(),
            self.stats.bytes_received()
        );
    }

    /// Check if the pool is running
    #[must_use]
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    /// Get the number of workers
    #[must_use]
    pub fn num_workers(&self) -> usize {
        self.workers.len()
    }

    /// Get pool statistics
    #[must_use]
    pub fn stats(&self) -> &Arc<UdpWorkerPoolStats> {
        &self.stats
    }

    /// Get a stats snapshot
    #[must_use]
    pub fn stats_snapshot(&self) -> UdpWorkerPoolStatsSnapshot {
        self.stats.snapshot()
    }

    /// Get the buffer pool
    #[must_use]
    pub fn buffer_pool(&self) -> &Arc<UdpBufferPool> {
        &self.buffer_pool
    }

    // ========================================================================
    // Processor Access Methods (for IPC)
    // ========================================================================

    /// Get processor statistics snapshot.
    ///
    /// This provides detailed packet processing stats including QUIC detection,
    /// SNI extraction success rates, and rule match counts.
    #[must_use]
    pub fn processor_stats(&self) -> UdpProcessorStatsSnapshot {
        self.processor.stats_snapshot()
    }

    /// Get the number of active UDP sessions in the processor.
    #[must_use]
    pub fn active_sessions(&self) -> u64 {
        self.processor.active_sessions()
    }

    /// Check if a specific session exists.
    #[must_use]
    pub fn has_session(&self, key: &UdpSessionKey) -> bool {
        self.processor.get_handle(key).is_some()
    }

    /// Get processor reference for advanced IPC operations.
    ///
    /// This allows the IPC handler to access session details and perform
    /// operations like session invalidation.
    #[must_use]
    pub fn processor(&self) -> &Arc<UdpPacketProcessor> {
        &self.processor
    }
}

impl Drop for UdpWorkerPool {
    fn drop(&mut self) {
        if self.running.load(Ordering::Relaxed) {
            // Send shutdown signal if not already done
            let _ = self.shutdown_tx.send(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connection::UdpProcessorConfig;

    #[test]
    fn test_worker_pool_config_default() {
        let config = UdpWorkerPoolConfig::default();
        assert!(config.num_workers > 0);
        assert_eq!(config.buffer_pool_capacity, DEFAULT_BUFFER_POOL_CAPACITY);
        assert_eq!(config.buffer_size, 65535);
    }

    #[test]
    fn test_worker_pool_config_builder() {
        let config = UdpWorkerPoolConfig::default()
            .with_workers(8)
            .with_buffer_pool_capacity(512);

        assert_eq!(config.num_workers, 8);
        assert_eq!(config.buffer_pool_capacity, 512);
    }

    #[test]
    fn test_stats_new() {
        let stats = UdpWorkerPoolStats::new();
        assert_eq!(stats.packets_processed(), 0);
        assert_eq!(stats.bytes_received(), 0);
        assert_eq!(stats.workers_active(), 0);
        assert_eq!(stats.workers_total(), 0);
        assert_eq!(stats.worker_errors(), 0);
    }

    #[test]
    fn test_stats_record_packet() {
        let stats = UdpWorkerPoolStats::new();
        stats.record_packet(1000);
        stats.record_packet(500);

        assert_eq!(stats.packets_processed(), 2);
        assert_eq!(stats.bytes_received(), 1500);
    }

    #[test]
    fn test_stats_worker_lifecycle() {
        let stats = UdpWorkerPoolStats::new();

        stats.worker_started();
        stats.worker_started();
        assert_eq!(stats.workers_active(), 2);

        stats.worker_stopped();
        assert_eq!(stats.workers_active(), 1);

        stats.record_error();
        assert_eq!(stats.worker_errors(), 1);
    }

    #[test]
    fn test_stats_snapshot() {
        let stats = UdpWorkerPoolStats::new();
        stats.record_packet(100);
        stats.worker_started();
        stats.record_error();

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.packets_processed, 1);
        assert_eq!(snapshot.bytes_received, 100);
        assert_eq!(snapshot.workers_active, 1);
        assert_eq!(snapshot.worker_errors, 1);
    }

    // Note: Full integration tests require CAP_NET_ADMIN and are in tests/integration/

    #[tokio::test]
    async fn test_worker_pool_creation_fails_without_cap() {
        use crate::outbound::{DirectOutbound, OutboundManager};
        use crate::rules::{RoutingSnapshotBuilder, RuleEngine};

        // This test verifies graceful failure without CAP_NET_ADMIN
        let config = ListenConfig::default();
        let processor = Arc::new(UdpPacketProcessor::new(UdpProcessorConfig::default()));

        // Create rule engine and outbound manager for worker pool
        let snapshot = RoutingSnapshotBuilder::new()
            .default_outbound("direct")
            .version(1)
            .build()
            .unwrap();
        let rule_engine = Arc::new(RuleEngine::new(snapshot));
        let outbound_manager = Arc::new(OutboundManager::new());
        outbound_manager.add(Box::new(DirectOutbound::simple("direct")));

        let result = UdpWorkerPool::new(
            &config,
            Some(2),
            processor,
            rule_engine,
            outbound_manager,
        );

        match result {
            Ok(_pool) => {
                // Running with sufficient privileges (e.g., in container)
            }
            Err(UdpError::PermissionDenied) => {
                // Expected without CAP_NET_ADMIN
            }
            Err(e) => {
                // Other errors are acceptable (e.g., socket options)
                println!("Worker pool creation failed (expected without root): {}", e);
            }
        }
    }
}
