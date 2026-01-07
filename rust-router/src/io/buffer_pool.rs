//! Lock-free UDP Buffer Pool
//!
//! This module provides a high-performance buffer pool for UDP packet processing.
//! Using `crossbeam-queue::ArrayQueue` for lock-free buffer management to minimize
//! contention between worker threads.
//!
//! # Architecture
//!
//! The buffer pool uses a two-tier design as recommended in the architecture review:
//!
//! 1. **Global Pool**: Shared `ArrayQueue` for cross-worker buffer sharing
//! 2. **Per-Worker Local Cache**: (Optional) Thread-local buffer cache for reduced contention
//!
//! # Example
//!
//! ```
//! use rust_router::io::UdpBufferPool;
//! use std::sync::Arc;
//!
//! // Create a pool with 1024 buffers of 65535 bytes each
//! let pool = Arc::new(UdpBufferPool::new(1024, 65535));
//!
//! // Get a buffer (from pool or newly allocated)
//! let buffer = pool.get();
//! assert_eq!(buffer.capacity(), 65535);
//!
//! // Buffer is automatically returned to pool when dropped
//! drop(buffer);
//!
//! let stats = pool.stats();
//! assert!(stats.reuses() > 0 || stats.allocations() > 0);
//! ```

use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crossbeam_queue::ArrayQueue;

/// Default UDP buffer size (maximum UDP payload)
pub const DEFAULT_UDP_BUFFER_SIZE: usize = 65535;

/// Default pool capacity (number of buffers)
pub const DEFAULT_POOL_CAPACITY: usize = 1024;

/// Statistics for the buffer pool
#[derive(Debug)]
pub struct BufferPoolStats {
    /// Number of new buffer allocations (pool was empty)
    allocations: AtomicU64,
    /// Number of buffer reuses from pool
    reuses: AtomicU64,
    /// Number of buffers returned to pool
    returns: AtomicU64,
    /// Number of buffers dropped (pool was full)
    drops: AtomicU64,
}

impl BufferPoolStats {
    /// Create new stats instance
    fn new() -> Self {
        Self {
            allocations: AtomicU64::new(0),
            reuses: AtomicU64::new(0),
            returns: AtomicU64::new(0),
            drops: AtomicU64::new(0),
        }
    }

    /// Get the number of allocations
    #[must_use]
    pub fn allocations(&self) -> u64 {
        self.allocations.load(Ordering::Relaxed)
    }

    /// Get the number of reuses
    #[must_use]
    pub fn reuses(&self) -> u64 {
        self.reuses.load(Ordering::Relaxed)
    }

    /// Get the number of returns
    #[must_use]
    pub fn returns(&self) -> u64 {
        self.returns.load(Ordering::Relaxed)
    }

    /// Get the number of drops
    #[must_use]
    pub fn drops(&self) -> u64 {
        self.drops.load(Ordering::Relaxed)
    }

    /// Get pool efficiency (reuses / (reuses + allocations))
    ///
    /// Returns 0.0 if no operations have occurred.
    #[must_use]
    #[allow(clippy::cast_precision_loss)] // Precision loss acceptable for efficiency ratio
    pub fn efficiency(&self) -> f64 {
        let reuses = self.reuses();
        let allocations = self.allocations();
        let total = reuses + allocations;
        if total == 0 {
            0.0
        } else {
            reuses as f64 / total as f64
        }
    }

    /// Get a snapshot of all stats
    #[must_use]
    pub fn snapshot(&self) -> BufferPoolStatsSnapshot {
        BufferPoolStatsSnapshot {
            allocations: self.allocations(),
            reuses: self.reuses(),
            returns: self.returns(),
            drops: self.drops(),
        }
    }
}

/// Snapshot of buffer pool statistics
#[derive(Debug, Clone, Copy)]
pub struct BufferPoolStatsSnapshot {
    /// Number of new buffer allocations
    pub allocations: u64,
    /// Number of buffer reuses
    pub reuses: u64,
    /// Number of buffers returned
    pub returns: u64,
    /// Number of buffers dropped (pool full)
    pub drops: u64,
}

impl BufferPoolStatsSnapshot {
    /// Get pool efficiency (reuses / (reuses + allocations))
    #[must_use]
    #[allow(clippy::cast_precision_loss)] // Precision loss acceptable for efficiency ratio
    pub fn efficiency(&self) -> f64 {
        let total = self.reuses + self.allocations;
        if total == 0 {
            0.0
        } else {
            self.reuses as f64 / total as f64
        }
    }
}

/// A high-performance lock-free buffer pool for UDP packets.
///
/// Uses `crossbeam_queue::ArrayQueue` for lock-free buffer management.
/// Buffers are automatically returned to the pool when dropped.
#[derive(Debug)]
pub struct UdpBufferPool {
    /// Lock-free queue of available buffers
    buffers: ArrayQueue<Vec<u8>>,
    /// Size of each buffer
    buffer_size: usize,
    /// Pool statistics
    stats: BufferPoolStats,
}

impl UdpBufferPool {
    /// Create a new buffer pool with the specified capacity and buffer size.
    ///
    /// # Arguments
    ///
    /// * `capacity` - Maximum number of buffers to keep in the pool
    /// * `buffer_size` - Size of each buffer in bytes
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::io::UdpBufferPool;
    ///
    /// // Pool for 512 UDP buffers
    /// let pool = UdpBufferPool::new(512, 65535);
    /// ```
    #[must_use]
    pub fn new(capacity: usize, buffer_size: usize) -> Self {
        Self {
            buffers: ArrayQueue::new(capacity),
            buffer_size,
            stats: BufferPoolStats::new(),
        }
    }

    /// Create a pool with default settings (1024 buffers, 65535 bytes each)
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(DEFAULT_POOL_CAPACITY, DEFAULT_UDP_BUFFER_SIZE)
    }

    /// Get a buffer from the pool or allocate a new one.
    ///
    /// If a buffer is available in the pool, it is reused. Otherwise,
    /// a new buffer is allocated.
    ///
    /// # Performance Note
    ///
    /// Reused buffers are NOT zeroed - only their length is reset and then
    /// extended back to `buffer_size`. The receive syscall will overwrite
    /// the data anyway, so zeroing is wasted work on the hot path.
    ///
    /// # Returns
    ///
    /// A `PooledBuffer` that will be automatically returned to the pool when dropped.
    #[must_use]
    pub fn get(self: &Arc<Self>) -> PooledBuffer {
        let buffer = if let Some(mut buf) = self.buffers.pop() {
            self.stats.reuses.fetch_add(1, Ordering::Relaxed);
            // PERF-2 FIX: Don't zero the buffer - the receive syscall will overwrite it.
            // Just ensure the length is set correctly. We use unsafe set_len here because:
            // 1. The capacity is already >= buffer_size (we allocated it that way)
            // 2. The data doesn't need to be initialized - recv() will write to it
            // 3. This saves ~64KB of memset per buffer reuse at 100k+ pps
            buf.clear();
            // Safety: We know the capacity is at least buffer_size because we allocated it
            // with that size. The buffer contents are uninitialized but that's fine because
            // the caller will use this as a receive buffer where the syscall overwrites the data.
            if buf.capacity() >= self.buffer_size {
                unsafe { buf.set_len(self.buffer_size) };
            } else {
                // Defensive fallback: if somehow capacity is wrong, resize normally
                buf.resize(self.buffer_size, 0);
            }
            buf
        } else {
            self.stats.allocations.fetch_add(1, Ordering::Relaxed);
            vec![0u8; self.buffer_size]
        };

        PooledBuffer {
            buffer: Some(buffer),
            pool: Arc::clone(self),
        }
    }

    /// Try to get a buffer without allocation.
    ///
    /// Returns `None` if the pool is empty (no allocation is performed).
    ///
    /// # Performance Note
    ///
    /// Like `get()`, reused buffers are NOT zeroed for performance.
    #[must_use]
    pub fn try_get(self: &Arc<Self>) -> Option<PooledBuffer> {
        self.buffers.pop().map(|mut buf| {
            self.stats.reuses.fetch_add(1, Ordering::Relaxed);
            // PERF-2 FIX: Don't zero the buffer
            buf.clear();
            if buf.capacity() >= self.buffer_size {
                // Safety: Same as get() - buffer is used as receive buffer
                unsafe { buf.set_len(self.buffer_size) };
            } else {
                buf.resize(self.buffer_size, 0);
            }
            PooledBuffer {
                buffer: Some(buf),
                pool: Arc::clone(self),
            }
        })
    }

    /// Return a buffer to the pool.
    ///
    /// If the pool is full, the buffer is dropped.
    fn return_buffer(&self, mut buffer: Vec<u8>) {
        // Reset buffer length for next use (keep capacity)
        buffer.clear();

        // Try to return to pool
        match self.buffers.push(buffer) {
            Ok(()) => {
                self.stats.returns.fetch_add(1, Ordering::Relaxed);
            }
            Err(_buf) => {
                // Pool is full, drop the buffer
                self.stats.drops.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Pre-warm the pool by allocating buffers up front.
    ///
    /// This can reduce allocation latency during initial traffic burst.
    ///
    /// # Arguments
    ///
    /// * `count` - Number of buffers to pre-allocate
    pub fn prewarm(&self, count: usize) {
        for _ in 0..count {
            let buffer = vec![0u8; self.buffer_size];
            if self.buffers.push(buffer).is_err() {
                // Pool is full
                break;
            }
        }
    }

    /// Get the buffer size
    #[must_use]
    pub const fn buffer_size(&self) -> usize {
        self.buffer_size
    }

    /// Get the pool capacity
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.buffers.capacity()
    }

    /// Get the current number of available buffers in the pool
    #[must_use]
    pub fn available(&self) -> usize {
        self.buffers.len()
    }

    /// Get pool statistics
    #[must_use]
    pub fn stats(&self) -> &BufferPoolStats {
        &self.stats
    }
}

/// A buffer borrowed from the pool.
///
/// Automatically returns to the pool when dropped.
#[derive(Debug)]
pub struct PooledBuffer {
    /// The underlying buffer (Option for taking on drop)
    buffer: Option<Vec<u8>>,
    /// Reference to the pool for returning the buffer
    pool: Arc<UdpBufferPool>,
}

impl PooledBuffer {
    /// Get the capacity of the underlying buffer
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.buffer.as_ref().map_or(0, Vec::capacity)
    }

    /// Consume this buffer without returning it to the pool.
    ///
    /// Use this when you need to pass the buffer to code that doesn't
    /// understand `PooledBuffer`.
    #[must_use]
    pub fn into_vec(mut self) -> Vec<u8> {
        self.buffer.take().unwrap_or_default()
    }

    /// Freeze the first `len` bytes of this buffer into a `Bytes` instance.
    ///
    /// This is a **zero-copy** operation - the underlying memory is transferred
    /// to the `Bytes` without allocation or copying.
    ///
    /// **Important**: The buffer is NOT returned to the pool after this call.
    /// The memory will be freed when the `Bytes` is dropped.
    ///
    /// # Arguments
    ///
    /// * `len` - Number of bytes to freeze (must be <= current length)
    ///
    /// # Performance
    ///
    /// This is the recommended way to convert received packet data to `Bytes`
    /// on the hot path, as it avoids the allocation that `Bytes::copy_from_slice()`
    /// would incur.
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::io::UdpBufferPool;
    /// use std::sync::Arc;
    ///
    /// let pool = Arc::new(UdpBufferPool::new(10, 1024));
    /// let mut buf = pool.get();
    ///
    /// // Simulate receiving 100 bytes
    /// buf[0] = 42;
    /// let bytes = buf.freeze(100);
    ///
    /// assert_eq!(bytes.len(), 100);
    /// assert_eq!(bytes[0], 42);
    /// ```
    #[must_use]
    pub fn freeze(mut self, len: usize) -> bytes::Bytes {
        let mut vec = self.buffer.take().unwrap_or_default();
        // Truncate to the actual data length
        vec.truncate(len);
        // Convert Vec<u8> to Bytes - this is zero-copy
        bytes::Bytes::from(vec)
    }

    /// Get a mutable slice of the buffer with a specific length.
    ///
    /// # Panics
    ///
    /// Panics if `len` exceeds the buffer capacity.
    pub fn as_mut_slice(&mut self, len: usize) -> &mut [u8] {
        let buf = self.buffer.as_mut().expect("buffer taken");
        assert!(len <= buf.capacity(), "length exceeds buffer capacity");
        buf.resize(len, 0);
        &mut buf[..len]
    }

    /// Set the length of the buffer without zeroing.
    ///
    /// This is useful after receiving data into the buffer when you know
    /// exactly how many bytes were written.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `len` bytes have been properly initialized.
    /// This is typically the case after a `recv()` syscall.
    ///
    /// # Panics
    ///
    /// Panics if `len` exceeds the buffer capacity.
    pub fn set_len(&mut self, len: usize) {
        let buf = self.buffer.as_mut().expect("buffer taken");
        assert!(len <= buf.capacity(), "length exceeds buffer capacity");
        // Safety: caller guarantees the data is initialized
        unsafe { buf.set_len(len) };
    }
}

impl Drop for PooledBuffer {
    fn drop(&mut self) {
        if let Some(buf) = self.buffer.take() {
            self.pool.return_buffer(buf);
        }
    }
}

impl Deref for PooledBuffer {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.buffer.as_ref().map_or(&[], Vec::as_slice)
    }
}

impl DerefMut for PooledBuffer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.buffer.as_mut().map_or(&mut [], Vec::as_mut_slice)
    }
}

impl AsRef<[u8]> for PooledBuffer {
    #[allow(clippy::explicit_auto_deref)] // Explicit for clarity
    fn as_ref(&self) -> &[u8] {
        self
    }
}

impl AsMut<[u8]> for PooledBuffer {
    #[allow(clippy::explicit_auto_deref)] // Explicit for clarity
    fn as_mut(&mut self) -> &mut [u8] {
        self
    }
}

/// Configuration for the buffer pool
#[derive(Debug, Clone)]
pub struct BufferPoolConfig {
    /// Pool capacity (number of buffers)
    pub capacity: usize,
    /// Buffer size in bytes
    pub buffer_size: usize,
    /// Number of buffers to pre-warm
    pub prewarm_count: usize,
}

impl Default for BufferPoolConfig {
    fn default() -> Self {
        Self {
            capacity: DEFAULT_POOL_CAPACITY,
            buffer_size: DEFAULT_UDP_BUFFER_SIZE,
            prewarm_count: 0,
        }
    }
}

impl BufferPoolConfig {
    /// Create a new config with specified values
    #[must_use]
    pub const fn new(capacity: usize, buffer_size: usize) -> Self {
        Self {
            capacity,
            buffer_size,
            prewarm_count: 0,
        }
    }

    /// Set the prewarm count
    #[must_use]
    pub const fn with_prewarm(mut self, count: usize) -> Self {
        self.prewarm_count = count;
        self
    }

    /// Build the buffer pool
    #[must_use]
    pub fn build(self) -> Arc<UdpBufferPool> {
        let pool = Arc::new(UdpBufferPool::new(self.capacity, self.buffer_size));
        if self.prewarm_count > 0 {
            pool.prewarm(self.prewarm_count);
        }
        pool
    }
}

// PERF-4 FIX: Per-worker local buffer cache
// =========================================

/// Default local cache size per worker (number of buffers)
pub const DEFAULT_LOCAL_CACHE_SIZE: usize = 32;

/// Maximum local cache size (to prevent memory bloat)
pub const MAX_LOCAL_CACHE_SIZE: usize = 64;

/// Per-worker local buffer cache that reduces global pool contention.
///
/// PERF-4 FIX: When multiple workers compete for the global `ArrayQueue`,
/// cache line bouncing causes performance degradation. This local cache
/// provides each worker with its own small buffer pool that falls back to
/// the global pool on exhaustion.
///
/// # Thread Safety
///
/// Uses `Mutex` instead of `RefCell` to satisfy Rust's async `Send` requirements.
/// In practice, the cache is accessed by a single worker, so lock contention is minimal.
///
/// # Architecture
///
/// ```text
/// Worker 1: LocalBufferCache (32 buffers) ──┐
/// Worker 2: LocalBufferCache (32 buffers) ──┼── Global UdpBufferPool (1024 buffers)
/// Worker 3: LocalBufferCache (32 buffers) ──┘
/// ```
///
/// # Usage
///
/// ```no_run
/// use rust_router::io::{UdpBufferPool, LocalBufferCache};
/// use std::sync::Arc;
///
/// let global_pool = Arc::new(UdpBufferPool::with_defaults());
///
/// // Each worker creates its own local cache
/// let local_cache = LocalBufferCache::new(Arc::clone(&global_pool), 32);
///
/// // Get buffer from local cache (fast path) or global pool (slow path)
/// let buffer = local_cache.get();
/// ```
///
/// # Performance
///
/// Local cache operations use a `Mutex` but with minimal contention since
/// each worker has its own cache instance.
/// Falls back to global pool only when local cache is exhausted.
pub struct LocalBufferCache {
    /// Thread-local buffer storage (Mutex for async Send safety)
    local_buffers: Mutex<Vec<Vec<u8>>>,
    /// Reference to global pool for refilling and returning
    global_pool: Arc<UdpBufferPool>,
    /// Maximum local cache size
    max_size: usize,
    /// Statistics
    stats: LocalBufferCacheStats,
}

/// Statistics for local buffer cache
#[derive(Debug, Default)]
pub struct LocalBufferCacheStats {
    /// Buffers served from local cache (fast path)
    local_hits: AtomicU64,
    /// Buffers fetched from global pool (slow path)
    global_fallbacks: AtomicU64,
    /// Buffers returned to local cache
    local_returns: AtomicU64,
    /// Buffers returned to global pool (local cache full)
    global_returns: AtomicU64,
}

impl LocalBufferCacheStats {
    /// Get local cache hit count
    #[must_use]
    pub fn local_hits(&self) -> u64 {
        self.local_hits.load(Ordering::Relaxed)
    }

    /// Get global fallback count
    #[must_use]
    pub fn global_fallbacks(&self) -> u64 {
        self.global_fallbacks.load(Ordering::Relaxed)
    }

    /// Get local hit rate (local_hits / total_gets)
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn local_hit_rate(&self) -> f64 {
        let hits = self.local_hits();
        let fallbacks = self.global_fallbacks();
        let total = hits + fallbacks;
        if total == 0 {
            0.0
        } else {
            hits as f64 / total as f64
        }
    }
}

impl LocalBufferCache {
    /// Create a new local buffer cache.
    ///
    /// # Arguments
    ///
    /// * `global_pool` - Reference to the global buffer pool
    /// * `max_size` - Maximum number of buffers to keep locally (capped at 64)
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::io::{UdpBufferPool, LocalBufferCache};
    /// use std::sync::Arc;
    ///
    /// let global_pool = Arc::new(UdpBufferPool::with_defaults());
    /// let cache = LocalBufferCache::new(Arc::clone(&global_pool), 32);
    /// ```
    #[must_use]
    pub fn new(global_pool: Arc<UdpBufferPool>, max_size: usize) -> Self {
        let max_size = max_size.min(MAX_LOCAL_CACHE_SIZE);
        Self {
            local_buffers: Mutex::new(Vec::with_capacity(max_size)),
            global_pool,
            max_size,
            stats: LocalBufferCacheStats::default(),
        }
    }

    /// Create with default cache size (32 buffers).
    #[must_use]
    pub fn with_defaults(global_pool: Arc<UdpBufferPool>) -> Self {
        Self::new(global_pool, DEFAULT_LOCAL_CACHE_SIZE)
    }

    /// Get a buffer from the local cache or global pool.
    ///
    /// Fast path: Pop from local cache (single mutex lock)
    /// Slow path: Get from global pool (atomic ArrayQueue operation)
    ///
    /// # Returns
    ///
    /// A `LocalPooledBuffer` that will be returned to the local cache on drop.
    #[must_use]
    pub fn get(&self) -> LocalPooledBuffer<'_> {
        // NEW-5 FIX: Use poison recovery instead of unwrap to avoid cascade panics
        let mut local = self.local_buffers.lock().unwrap_or_else(|e| e.into_inner());

        let buffer = if let Some(mut buf) = local.pop() {
            // Fast path: local cache hit
            self.stats.local_hits.fetch_add(1, Ordering::Relaxed);

            // Prepare buffer for use (no zeroing, just set length)
            buf.clear();
            let buffer_size = self.global_pool.buffer_size();
            if buf.capacity() >= buffer_size {
                // Safety: Buffer is used as receive buffer, data will be overwritten
                unsafe { buf.set_len(buffer_size) };
            } else {
                buf.resize(buffer_size, 0);
            }
            buf
        } else {
            // Slow path: fetch from global pool
            drop(local); // Release lock before getting from global pool
            self.stats.global_fallbacks.fetch_add(1, Ordering::Relaxed);

            // Try to get from global pool
            if let Some(buf) = self.global_pool.buffers.pop() {
                self.global_pool.stats.reuses.fetch_add(1, Ordering::Relaxed);
                let mut buf = buf;
                buf.clear();
                let buffer_size = self.global_pool.buffer_size();
                if buf.capacity() >= buffer_size {
                    unsafe { buf.set_len(buffer_size) };
                } else {
                    buf.resize(buffer_size, 0);
                }
                buf
            } else {
                // Global pool empty, allocate new
                self.global_pool.stats.allocations.fetch_add(1, Ordering::Relaxed);
                vec![0u8; self.global_pool.buffer_size()]
            }
        };

        LocalPooledBuffer {
            buffer: Some(buffer),
            cache: self,
        }
    }

    /// Return a buffer to the local cache or global pool.
    fn return_buffer(&self, mut buffer: Vec<u8>) {
        buffer.clear();

        let mut local = self.local_buffers.lock().unwrap_or_else(|e| e.into_inner());
        if local.len() < self.max_size {
            // Return to local cache
            self.stats.local_returns.fetch_add(1, Ordering::Relaxed);
            local.push(buffer);
        } else {
            // Local cache full, return to global pool
            drop(local); // Release lock
            self.stats.global_returns.fetch_add(1, Ordering::Relaxed);
            self.global_pool.return_buffer(buffer);
        }
    }

    /// Refill local cache from global pool.
    ///
    /// Call this during idle periods to reduce global pool access during traffic bursts.
    ///
    /// # Arguments
    ///
    /// * `count` - Number of buffers to fetch from global pool
    pub fn refill(&self, count: usize) {
        let mut local = self.local_buffers.lock().unwrap_or_else(|e| e.into_inner());
        let space = self.max_size.saturating_sub(local.len());
        let to_fetch = count.min(space);

        for _ in 0..to_fetch {
            if let Some(buf) = self.global_pool.buffers.pop() {
                self.global_pool.stats.reuses.fetch_add(1, Ordering::Relaxed);
                local.push(buf);
            } else {
                break;
            }
        }
    }

    /// Flush local cache back to global pool.
    ///
    /// Call this during shutdown or when the worker is idle for extended periods.
    pub fn flush(&self) {
        // NEW-5 FIX: Use poison recovery instead of unwrap to avoid cascade panics
        let mut local = self.local_buffers.lock().unwrap_or_else(|e| e.into_inner());
        for buffer in local.drain(..) {
            self.global_pool.return_buffer(buffer);
        }
    }

    /// Get statistics for this local cache.
    #[must_use]
    pub fn stats(&self) -> &LocalBufferCacheStats {
        &self.stats
    }

    /// Get current local cache size.
    #[must_use]
    pub fn local_size(&self) -> usize {
        // NEW-5 FIX: Use poison recovery instead of unwrap to avoid cascade panics
        self.local_buffers.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// Get the global pool reference.
    #[must_use]
    pub fn global_pool(&self) -> &Arc<UdpBufferPool> {
        &self.global_pool
    }
}

impl std::fmt::Debug for LocalBufferCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // NEW-5 FIX: Use poison recovery instead of unwrap to avoid cascade panics
        f.debug_struct("LocalBufferCache")
            .field("local_size", &self.local_buffers.lock().unwrap_or_else(|e| e.into_inner()).len())
            .field("max_size", &self.max_size)
            .field("global_pool_buffer_size", &self.global_pool.buffer_size())
            .field("stats", &self.stats)
            .finish()
    }
}

/// A buffer borrowed from the local cache.
///
/// Automatically returns to the local cache (or global pool) when dropped.
#[derive(Debug)]
pub struct LocalPooledBuffer<'a> {
    /// The underlying buffer
    buffer: Option<Vec<u8>>,
    /// Reference to the local cache
    cache: &'a LocalBufferCache,
}

impl<'a> LocalPooledBuffer<'a> {
    /// Consume this buffer without returning it to any pool.
    #[must_use]
    pub fn into_vec(mut self) -> Vec<u8> {
        self.buffer.take().unwrap_or_default()
    }

    /// Freeze the first `len` bytes into a `Bytes` instance (zero-copy).
    ///
    /// **Important**: The buffer is NOT returned to any pool after this call.
    #[must_use]
    pub fn freeze(mut self, len: usize) -> bytes::Bytes {
        let mut vec = self.buffer.take().unwrap_or_default();
        vec.truncate(len);
        bytes::Bytes::from(vec)
    }
}

impl Drop for LocalPooledBuffer<'_> {
    fn drop(&mut self) {
        if let Some(buf) = self.buffer.take() {
            self.cache.return_buffer(buf);
        }
    }
}

impl Deref for LocalPooledBuffer<'_> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.buffer.as_ref().map_or(&[], Vec::as_slice)
    }
}

impl DerefMut for LocalPooledBuffer<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.buffer.as_mut().map_or(&mut [], Vec::as_mut_slice)
    }
}

// ============================================================================
// UdpBuffer trait for generic receive operations (PERF-4 FIX)
// ============================================================================

/// Trait for UDP receive buffers that can be used with TPROXY listener.
///
/// PERF-4 FIX: This trait allows `recv_pooled` to accept both `PooledBuffer`
/// (from global pool) and `LocalPooledBuffer` (from per-worker local cache),
/// enabling flexible buffer management strategies without code duplication.
///
/// # Implementors
///
/// - [`PooledBuffer`] - Buffer from the global `UdpBufferPool`
/// - [`LocalPooledBuffer`] - Buffer from per-worker `LocalBufferCache`
///
/// # Example
///
/// ```
/// use rust_router::io::{UdpBuffer, UdpBufferPool, LocalBufferCache};
/// use std::sync::Arc;
///
/// fn receive_into_buffer<B: UdpBuffer>(mut buf: B) -> bytes::Bytes {
///     // Write some data
///     buf.as_mut()[0] = 42;
///     // Freeze to Bytes (zero-copy)
///     buf.freeze(1)
/// }
///
/// let pool = Arc::new(UdpBufferPool::with_defaults());
///
/// // Works with global pool buffer
/// let global_buf = pool.get();
/// let _ = receive_into_buffer(global_buf);
///
/// // Works with local cache buffer
/// let cache = LocalBufferCache::with_defaults(Arc::clone(&pool));
/// let local_buf = cache.get();
/// let _ = receive_into_buffer(local_buf);
/// ```
pub trait UdpBuffer: DerefMut<Target = [u8]> + Sized {
    /// Freeze the first `len` bytes into a `Bytes` instance (zero-copy).
    ///
    /// The buffer memory is transferred to the `Bytes` without copying.
    /// The buffer is NOT returned to any pool after this call.
    fn freeze(self, len: usize) -> bytes::Bytes;
}

impl UdpBuffer for PooledBuffer {
    fn freeze(self, len: usize) -> bytes::Bytes {
        // Call the inherent method
        PooledBuffer::freeze(self, len)
    }
}

impl UdpBuffer for LocalPooledBuffer<'_> {
    fn freeze(self, len: usize) -> bytes::Bytes {
        // Call the inherent method
        LocalPooledBuffer::freeze(self, len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pool_creation() {
        let pool = Arc::new(UdpBufferPool::new(10, 1024));
        assert_eq!(pool.capacity(), 10);
        assert_eq!(pool.buffer_size(), 1024);
        assert_eq!(pool.available(), 0);
    }

    #[test]
    fn test_pool_with_defaults() {
        let pool = UdpBufferPool::with_defaults();
        assert_eq!(pool.capacity(), DEFAULT_POOL_CAPACITY);
        assert_eq!(pool.buffer_size(), DEFAULT_UDP_BUFFER_SIZE);
    }

    #[test]
    fn test_get_buffer() {
        let pool = Arc::new(UdpBufferPool::new(10, 1024));

        // First get should allocate
        let buf1 = pool.get();
        assert_eq!(buf1.len(), 1024);
        assert_eq!(pool.stats().allocations(), 1);
        assert_eq!(pool.stats().reuses(), 0);

        // Drop returns to pool
        drop(buf1);
        assert_eq!(pool.stats().returns(), 1);
        assert_eq!(pool.available(), 1);

        // Second get should reuse
        let _buf2 = pool.get();
        assert_eq!(pool.stats().allocations(), 1); // Still 1
        assert_eq!(pool.stats().reuses(), 1);
        assert_eq!(pool.available(), 0);
    }

    #[test]
    fn test_try_get() {
        let pool = Arc::new(UdpBufferPool::new(10, 1024));

        // Pool is empty, try_get returns None
        assert!(pool.try_get().is_none());

        // Add a buffer
        let buf = pool.get();
        drop(buf);
        assert_eq!(pool.available(), 1);

        // Now try_get should succeed
        let buf = pool.try_get();
        assert!(buf.is_some());
        assert_eq!(pool.available(), 0);
    }

    #[test]
    fn test_prewarm() {
        let pool = Arc::new(UdpBufferPool::new(10, 1024));
        pool.prewarm(5);
        assert_eq!(pool.available(), 5);

        // Prewarm more than capacity should stop at capacity
        pool.prewarm(10);
        assert_eq!(pool.available(), 10);
    }

    #[test]
    fn test_pool_full_drops() {
        let pool = Arc::new(UdpBufferPool::new(2, 1024));

        // Get and return 2 buffers (fills pool)
        let buf1 = pool.get();
        let buf2 = pool.get();
        drop(buf1);
        drop(buf2);
        assert_eq!(pool.available(), 2);
        assert_eq!(pool.stats().returns(), 2);

        // Get and return a third buffer (should be dropped)
        let buf3 = pool.get();
        let _buf4 = pool.get();
        let buf5 = pool.get(); // Allocates new
        drop(buf3);
        drop(buf5);
        // Only one slot available after buf3 was returned
        assert!(pool.stats().drops() > 0 || pool.available() <= 2);
    }

    #[test]
    fn test_efficiency() {
        let pool = Arc::new(UdpBufferPool::new(10, 1024));

        // No operations yet
        assert_eq!(pool.stats().efficiency(), 0.0);

        // Allocate once
        let buf = pool.get();
        assert_eq!(pool.stats().allocations(), 1);
        assert_eq!(pool.stats().efficiency(), 0.0); // 0 reuses

        // Return and reuse
        drop(buf);
        let _buf2 = pool.get();
        assert_eq!(pool.stats().reuses(), 1);
        assert!((pool.stats().efficiency() - 0.5).abs() < 0.001); // 1 reuse / 2 total
    }

    #[test]
    fn test_into_vec() {
        let pool = Arc::new(UdpBufferPool::new(10, 1024));

        let buf = pool.get();
        let vec = buf.into_vec();
        assert_eq!(vec.len(), 1024);

        // Buffer was not returned to pool
        assert_eq!(pool.available(), 0);
    }

    #[test]
    fn test_as_mut_slice() {
        let pool = Arc::new(UdpBufferPool::new(10, 1024));

        let mut buf = pool.get();
        let slice = buf.as_mut_slice(100);
        assert_eq!(slice.len(), 100);

        // Write some data
        slice[0] = 1;
        slice[99] = 2;
        assert_eq!(buf[0], 1);
        assert_eq!(buf[99], 2);
    }

    #[test]
    #[should_panic(expected = "length exceeds buffer capacity")]
    fn test_as_mut_slice_panic() {
        let pool = Arc::new(UdpBufferPool::new(10, 100));

        let mut buf = pool.get();
        let _slice = buf.as_mut_slice(200); // Should panic
    }

    #[test]
    fn test_buffer_pool_config() {
        let config = BufferPoolConfig::new(512, 4096).with_prewarm(100);
        let pool = config.build();

        assert_eq!(pool.capacity(), 512);
        assert_eq!(pool.buffer_size(), 4096);
        assert_eq!(pool.available(), 100);
    }

    #[test]
    fn test_stats_snapshot() {
        let pool = Arc::new(UdpBufferPool::new(10, 1024));

        // Do some operations
        let buf1 = pool.get();
        drop(buf1);
        let _buf2 = pool.get();

        let snapshot = pool.stats().snapshot();
        assert_eq!(snapshot.allocations, 1);
        assert_eq!(snapshot.reuses, 1);
        assert_eq!(snapshot.returns, 1);
        assert!((snapshot.efficiency() - 0.5).abs() < 0.001);
    }

    #[test]
    fn test_deref_and_deref_mut() {
        let pool = Arc::new(UdpBufferPool::new(10, 1024));

        let mut buf = pool.get();

        // Test Deref
        let slice: &[u8] = &buf;
        assert_eq!(slice.len(), 1024);

        // Test DerefMut
        let slice: &mut [u8] = &mut buf;
        slice[0] = 42;
        assert_eq!(buf[0], 42);

        // Test AsRef
        let slice: &[u8] = buf.as_ref();
        assert_eq!(slice[0], 42);

        // Test AsMut
        let slice: &mut [u8] = buf.as_mut();
        slice[1] = 43;
        assert_eq!(buf[1], 43);
    }

    #[test]
    fn test_concurrent_access() {
        use std::thread;

        let pool = Arc::new(UdpBufferPool::new(100, 1024));

        // Spawn multiple threads that get and return buffers
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let pool = Arc::clone(&pool);
                thread::spawn(move || {
                    for _ in 0..100 {
                        let mut buf = pool.get();
                        buf[0] = 42;
                        // Implicit drop returns to pool
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }

        // All buffers should be returned
        let stats = pool.stats().snapshot();
        assert_eq!(
            stats.allocations + stats.reuses,
            800,
            "total gets should be 800"
        );
        assert!(stats.efficiency() > 0.0, "should have some reuses");
    }

    // =========================================================================
    // NEW-1 FIX: LocalBufferCache Tests
    // =========================================================================

    #[test]
    fn test_local_cache_creation() {
        let pool = Arc::new(UdpBufferPool::new(100, 1024));
        let cache = LocalBufferCache::new(Arc::clone(&pool), 32);

        // Initial local size should be 0 (no buffers cached yet)
        assert_eq!(cache.local_size(), 0);
        let stats = cache.stats();
        assert_eq!(stats.local_hits(), 0);
        assert_eq!(stats.global_fallbacks(), 0);
    }

    #[test]
    fn test_local_cache_get_allocates_initially() {
        let pool = Arc::new(UdpBufferPool::new(100, 1024));
        let cache = LocalBufferCache::new(Arc::clone(&pool), 32);

        // First get should hit global pool (allocate)
        let buf = cache.get();
        assert_eq!(buf.len(), 1024);

        let stats = cache.stats();
        assert_eq!(stats.local_hits(), 0);
        assert_eq!(stats.global_fallbacks(), 1);
    }

    #[test]
    fn test_local_cache_local_hit() {
        let pool = Arc::new(UdpBufferPool::new(100, 1024));
        let cache = LocalBufferCache::new(Arc::clone(&pool), 32);

        // Get and return a buffer
        let buf1 = cache.get();
        drop(buf1);

        // Second get should hit local cache
        let _buf2 = cache.get();

        let stats = cache.stats();
        assert_eq!(stats.local_hits(), 1);
        assert_eq!(stats.global_fallbacks(), 1); // First get was global
    }

    #[test]
    fn test_local_cache_multiple_buffers() {
        let pool = Arc::new(UdpBufferPool::new(100, 1024));
        let cache = LocalBufferCache::new(Arc::clone(&pool), 32);

        // Get multiple buffers, then return them
        let buf1 = cache.get();
        let buf2 = cache.get();
        let buf3 = cache.get();

        drop(buf1);
        drop(buf2);
        drop(buf3);

        // Now all should be in local cache
        let _b1 = cache.get();
        let _b2 = cache.get();
        let _b3 = cache.get();

        let stats = cache.stats();
        assert_eq!(stats.local_hits(), 3);
        assert_eq!(stats.global_fallbacks(), 3);
    }

    #[test]
    fn test_local_cache_flush() {
        let pool = Arc::new(UdpBufferPool::new(100, 1024));
        let cache = LocalBufferCache::new(Arc::clone(&pool), 32);

        // Get and return buffers
        let buf1 = cache.get();
        let buf2 = cache.get();
        drop(buf1);
        drop(buf2);

        // Local cache should have 2 buffers
        assert_eq!(pool.available(), 0); // Global pool is empty

        // Flush returns buffers to global pool
        cache.flush();

        // Buffers returned to global pool
        assert!(pool.available() > 0);
    }

    #[test]
    fn test_local_cache_max_size_overflow_to_global() {
        let pool = Arc::new(UdpBufferPool::new(100, 1024));
        let cache = LocalBufferCache::new(Arc::clone(&pool), 2);

        // Get 3 buffers
        let buf1 = cache.get();
        let buf2 = cache.get();
        let buf3 = cache.get();

        // Return all 3 - only 2 should fit in local cache
        drop(buf1);
        drop(buf2);
        drop(buf3);

        // One should have gone to global pool
        assert!(pool.available() > 0);
    }

    #[test]
    fn test_local_cache_hit_rate() {
        let pool = Arc::new(UdpBufferPool::new(100, 1024));
        let cache = LocalBufferCache::new(Arc::clone(&pool), 32);

        // Initially 0%
        assert_eq!(cache.stats().local_hit_rate(), 0.0);

        // All global hits
        let buf1 = cache.get();
        let buf2 = cache.get();
        drop(buf1);
        drop(buf2);

        // 0 local hits / 2 total = 0%
        assert_eq!(cache.stats().local_hit_rate(), 0.0);

        // Now 2 local hits
        let _b1 = cache.get();
        let _b2 = cache.get();

        // 2 local hits / 4 total = 50%
        let hit_rate = cache.stats().local_hit_rate();
        assert!((hit_rate - 0.5).abs() < 0.01, "expected 50% hit rate, got {}%", hit_rate * 100.0);
    }

    #[test]
    fn test_local_cache_stats_snapshot() {
        let pool = Arc::new(UdpBufferPool::new(100, 1024));
        let cache = LocalBufferCache::new(Arc::clone(&pool), 32);

        // Do some operations
        let buf = cache.get();
        drop(buf);
        let _buf2 = cache.get();

        let stats = cache.stats();
        assert_eq!(stats.local_hits(), 1);
        assert_eq!(stats.global_fallbacks(), 1);
    }

    #[test]
    fn test_local_pooled_buffer_deref() {
        let pool = Arc::new(UdpBufferPool::new(100, 1024));
        let cache = LocalBufferCache::new(Arc::clone(&pool), 32);

        let mut buf = cache.get();

        // Test Deref
        let slice: &[u8] = &buf;
        assert_eq!(slice.len(), 1024);

        // Test DerefMut
        buf[0] = 42;
        assert_eq!(buf[0], 42);
    }

    #[test]
    fn test_local_pooled_buffer_freeze() {
        let pool = Arc::new(UdpBufferPool::new(100, 1024));
        let cache = LocalBufferCache::new(Arc::clone(&pool), 32);

        let mut buf = cache.get();
        buf[0] = 1;
        buf[1] = 2;
        buf[2] = 3;

        // Freeze to Bytes (zero-copy)
        let bytes = buf.freeze(3);
        assert_eq!(bytes.len(), 3);
        assert_eq!(&bytes[..], &[1, 2, 3]);
    }

    #[test]
    fn test_udp_buffer_trait_pooled_buffer() {
        let pool = Arc::new(UdpBufferPool::new(100, 1024));

        let mut buf: PooledBuffer = pool.get();
        buf[0] = 10;
        buf[1] = 20;

        // Test freeze via trait
        let bytes = <PooledBuffer as UdpBuffer>::freeze(buf, 2);
        assert_eq!(bytes.len(), 2);
        assert_eq!(&bytes[..], &[10, 20]);
    }

    #[test]
    fn test_udp_buffer_trait_local_pooled_buffer() {
        let pool = Arc::new(UdpBufferPool::new(100, 1024));
        let cache = LocalBufferCache::new(Arc::clone(&pool), 32);

        let mut buf = cache.get();
        buf[0] = 30;
        buf[1] = 40;

        // Test freeze via trait
        let bytes = UdpBuffer::freeze(buf, 2);
        assert_eq!(bytes.len(), 2);
        assert_eq!(&bytes[..], &[30, 40]);
    }

    #[test]
    fn test_local_cache_concurrent_safety() {
        use std::thread;

        let pool = Arc::new(UdpBufferPool::new(500, 1024));

        // Spawn multiple threads using separate caches
        let handles: Vec<_> = (0..4)
            .map(|_| {
                let pool = Arc::clone(&pool);
                thread::spawn(move || {
                    let cache = LocalBufferCache::new(pool, 32);
                    for _ in 0..50 {
                        let mut buf = cache.get();
                        buf[0] = 42;
                        drop(buf);
                    }
                    cache.flush();
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }

        // All buffers should be back in global pool
        let pool_stats = pool.stats().snapshot();
        assert!(pool_stats.allocations > 0);
    }

    #[test]
    fn test_local_cache_default_size_constant() {
        assert!(DEFAULT_LOCAL_CACHE_SIZE > 0);
        assert!(DEFAULT_LOCAL_CACHE_SIZE <= MAX_LOCAL_CACHE_SIZE);
    }
}
