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

mod buffer;
mod buffer_pool;
mod copy;

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
