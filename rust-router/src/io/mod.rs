//! I/O utilities for rust-router
//!
//! This module provides efficient buffer management and bidirectional
//! copy operations for TCP and UDP proxying.
//!
//! # TCP Buffer
//!
//! The `IoBuffer` provides efficient TCP streaming with adaptive sizing.
//!
//! # UDP Buffer Pool
//!
//! The `UdpBufferPool` provides lock-free buffer reuse for UDP packet
//! processing to reduce allocation overhead.
//!
//! # Batch I/O (Phase 6.8)
//!
//! The `batch_io` module provides high-performance batch UDP send/receive
//! using Linux-specific `sendmmsg` and `recvmmsg` syscalls. This provides
//! 20%+ throughput improvement over single-packet I/O.

mod buffer;
mod buffer_pool;
mod copy;

// Batch I/O module (Linux only)
#[cfg(target_os = "linux")]
mod batch_io;

pub use buffer::{BufferStats, IoBuffer, DEFAULT_BUFFER_SIZE, MAX_BUFFER_SIZE, MIN_BUFFER_SIZE};
pub use buffer_pool::{
    BufferPoolConfig, BufferPoolStats, BufferPoolStatsSnapshot, PooledBuffer, UdpBufferPool,
    DEFAULT_POOL_CAPACITY, DEFAULT_UDP_BUFFER_SIZE,
    // PERF-4 FIX: Per-worker local buffer cache
    LocalBufferCache, LocalBufferCacheStats, LocalPooledBuffer,
    DEFAULT_LOCAL_CACHE_SIZE, MAX_LOCAL_CACHE_SIZE,
    // PERF-4 FIX: Generic buffer trait for recv_pooled
    UdpBuffer,
};
pub use copy::{bidirectional_copy, bidirectional_copy_with_buffer, CopyResult};

// Phase 6.8: Batch I/O exports (Linux only)
#[cfg(target_os = "linux")]
pub use batch_io::{
    BatchConfig, BatchReceiver, BatchSender, BatchStats, OutgoingPacket, ReceivedPacket,
    DEFAULT_BATCH_SIZE, DEFAULT_PACKET_BUFFER_SIZE, MAX_BATCH_SIZE,
};
