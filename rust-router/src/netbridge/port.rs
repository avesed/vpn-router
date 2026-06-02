//! Ephemeral port allocator with TIME_WAIT tracking
//!
//! This module provides a thread-safe port allocator for netbridge implementations.
//! It manages ephemeral ports (49152-65535) and tracks TIME_WAIT state to prevent
//! port reuse issues.
//!
//! # Features
//!
//! - **Thread-safe**: Uses `DashSet` and `DashMap` for lock-free concurrent access
//! - **TIME_WAIT tracking**: Released ports enter a TIME_WAIT state before reuse
//! - **RAII guards**: `PortGuard` automatically releases ports when dropped
//! - **Sharding support**: Partition port ranges for multi-shard bridges
//! - **Random start**: Allocations start from a random port to distribute usage
//!
//! # Usage
//!
//! ```ignore
//! use rust_router::netbridge::{PortAllocator, PortAllocatorConfig};
//!
//! // Create allocator with default config
//! let allocator = PortAllocator::new();
//!
//! // Allocate a port - returns a RAII guard
//! if let Some(guard) = allocator.allocate() {
//!     let port = guard.port();
//!     println!("Allocated port: {}", port);
//!     // Port is automatically released when guard is dropped
//! }
//! ```
//!
//! # TIME_WAIT Behavior
//!
//! When a port is released, it enters TIME_WAIT state for 60 seconds (configurable).
//! This prevents issues with delayed packets from previous connections.

use std::ops::RangeInclusive;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use dashmap::DashSet;
use tracing::{debug, trace, warn};

use super::config::{PORT_RANGE_END, PORT_RANGE_START, PORT_TIME_WAIT_SECS};

// =============================================================================
// Configuration
// =============================================================================

/// Configuration for the port allocator
#[derive(Debug, Clone)]
pub struct PortAllocatorConfig {
    /// Ephemeral port range (IANA: 49152-65535)
    pub range: RangeInclusive<u16>,
    /// TIME_WAIT duration after port release (RFC recommends 2*MSL = 60s)
    pub time_wait_duration: Duration,
}

impl Default for PortAllocatorConfig {
    fn default() -> Self {
        Self {
            range: PORT_RANGE_START..=PORT_RANGE_END,
            time_wait_duration: Duration::from_secs(PORT_TIME_WAIT_SECS),
        }
    }
}

impl PortAllocatorConfig {
    /// Create a new configuration with custom settings
    #[must_use]
    pub fn new(range: RangeInclusive<u16>, time_wait_duration: Duration) -> Self {
        Self {
            range,
            time_wait_duration,
        }
    }

    /// Get the number of ports in the range
    #[must_use]
    pub fn port_count(&self) -> usize {
        (*self.range.end() - *self.range.start() + 1) as usize
    }

    /// Get the range start
    #[must_use]
    pub fn start(&self) -> u16 {
        *self.range.start()
    }

    /// Get the range end
    #[must_use]
    pub fn end(&self) -> u16 {
        *self.range.end()
    }
}

// =============================================================================
// Port Allocator
// =============================================================================

/// Thread-safe ephemeral port allocator with TIME_WAIT tracking
///
/// This allocator manages a range of ephemeral ports and ensures that:
/// 1. Ports are not reused while in TIME_WAIT state
/// 2. Allocations start from a random port to distribute usage
/// 3. Automatic cleanup of expired TIME_WAIT entries
///
/// # Thread Safety
///
/// `PortAllocator` is `Send + Sync` and can be safely shared across tasks.
/// It uses lock-free data structures internally for high concurrency.
pub struct PortAllocator {
    /// Set of currently allocated ports
    allocated: DashSet<u16>,
    /// Map of ports in TIME_WAIT state: port -> release timestamp
    time_wait: DashMap<u16, Instant>,
    /// Next candidate port (wraps around the range)
    next_port: AtomicU16,
    /// Configuration
    config: PortAllocatorConfig,
}

impl PortAllocator {
    /// Create a new port allocator with default configuration
    ///
    /// Uses the IANA ephemeral port range (49152-65535) and 60 second TIME_WAIT.
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(PortAllocatorConfig::default())
    }

    /// Create a new port allocator for a specific shard with partitioned port range
    ///
    /// This partitions the default ephemeral port range into equal-sized ranges
    /// for each shard, ensuring no port collisions between shards.
    ///
    /// # Arguments
    ///
    /// * `shard_index` - The index of this shard (0-based)
    /// * `total_shards` - Total number of shards
    ///
    /// # Example
    ///
    /// ```ignore
    /// // With 4 shards and default range (16384 ports):
    /// // Shard 0: 49152-53247 (4096 ports)
    /// // Shard 1: 53248-57343 (4096 ports)
    /// // Shard 2: 57344-61439 (4096 ports)
    /// // Shard 3: 61440-65535 (4096 ports)
    /// let allocator = PortAllocator::for_shard(0, 4);
    /// ```
    ///
    /// # Panics
    ///
    /// Panics if `total_shards` is 0 or if `shard_index >= total_shards`.
    #[must_use]
    pub fn for_shard(shard_index: u16, total_shards: u16) -> Self {
        assert!(total_shards > 0, "total_shards must be > 0");
        assert!(
            shard_index < total_shards,
            "shard_index {} must be < total_shards {}",
            shard_index,
            total_shards
        );

        let total_ports = PORT_RANGE_END - PORT_RANGE_START + 1; // 16384
        let ports_per_shard = total_ports / total_shards;

        // Calculate this shard's port range
        let shard_start = PORT_RANGE_START + (shard_index * ports_per_shard);
        let shard_end = if shard_index == total_shards - 1 {
            // Last shard gets any remaining ports
            PORT_RANGE_END
        } else {
            shard_start + ports_per_shard - 1
        };

        let config = PortAllocatorConfig {
            range: shard_start..=shard_end,
            time_wait_duration: Duration::from_secs(PORT_TIME_WAIT_SECS),
        };

        debug!(
            shard_index,
            total_shards,
            start = shard_start,
            end = shard_end,
            count = shard_end - shard_start + 1,
            "PortAllocator created for shard"
        );

        Self::with_config(config)
    }

    /// Get the shard index from a port number
    ///
    /// This is the inverse of `for_shard()` - given a port, determine which
    /// shard it belongs to.
    ///
    /// # Arguments
    ///
    /// * `port` - The port number to look up
    /// * `total_shards` - Total number of shards
    ///
    /// # Returns
    ///
    /// The shard index (0-based), or `None` if outside the ephemeral range.
    #[must_use]
    pub fn shard_for_port(port: u16, total_shards: u16) -> Option<usize> {
        if !(PORT_RANGE_START..=PORT_RANGE_END).contains(&port) {
            return None;
        }

        let total_ports = PORT_RANGE_END - PORT_RANGE_START + 1;
        let ports_per_shard = total_ports / total_shards;

        let offset = port - PORT_RANGE_START;
        let shard_index = (offset / ports_per_shard) as usize;

        // Clamp to valid shard range (for ports in the last shard's "extra" range)
        Some(shard_index.min((total_shards - 1) as usize))
    }

    /// Create a new port allocator with custom configuration
    #[must_use]
    pub fn with_config(config: PortAllocatorConfig) -> Self {
        // Start from a random port within the range
        let start_port =
            *config.range.start() + (rand::random::<u16>() % config.port_count() as u16);

        debug!(
            range_start = config.start(),
            range_end = config.end(),
            time_wait_secs = config.time_wait_duration.as_secs(),
            start_port,
            "PortAllocator created"
        );

        Self {
            allocated: DashSet::new(),
            time_wait: DashMap::new(),
            next_port: AtomicU16::new(start_port),
            config,
        }
    }

    /// Allocate a new port, returning a RAII guard
    ///
    /// The guard will automatically release the port when dropped, putting it
    /// into TIME_WAIT state.
    ///
    /// # Returns
    ///
    /// - `Some(PortGuard)` if a port was successfully allocated
    /// - `None` if all ports are in use or in TIME_WAIT
    pub fn allocate(&self) -> Option<PortGuard<'_>> {
        // Clean up expired TIME_WAIT entries first
        self.cleanup_time_wait();

        let range_start = self.config.start();
        let range_len = self.config.port_count();

        // Try each port in the range, starting from next_port
        let start = self.next_port.fetch_add(1, Ordering::Relaxed);

        for offset in 0..range_len {
            // Calculate port with wrapping within range
            let port = range_start
                + ((start.wrapping_sub(range_start) as usize + offset) % range_len) as u16;

            // Skip ports in TIME_WAIT
            if self.time_wait.contains_key(&port) {
                trace!(port, "Port is in TIME_WAIT, skipping");
                continue;
            }

            // Try to allocate this port
            if self.allocated.insert(port) {
                trace!(port, "Port allocated");
                return Some(PortGuard::new(self, port));
            }

            trace!(port, "Port already allocated, trying next");
        }

        warn!(
            range_len,
            allocated = self.allocated.len(),
            time_wait = self.time_wait.len(),
            "Port exhaustion: all ports in use or TIME_WAIT"
        );
        None
    }

    /// Release a port into TIME_WAIT state
    ///
    /// This is called automatically by `PortGuard::drop()`, but can also be
    /// called manually if the port was taken with `PortGuard::take()`.
    pub fn release(&self, port: u16) {
        if self.allocated.remove(&port).is_some() {
            self.time_wait.insert(port, Instant::now());
            trace!(port, "Port released into TIME_WAIT");
        } else {
            warn!(port, "Attempted to release unallocated port");
        }
    }

    /// Clean up expired TIME_WAIT entries
    fn cleanup_time_wait(&self) {
        let now = Instant::now();
        let duration = self.config.time_wait_duration;

        self.time_wait.retain(|port, released_at| {
            let expired = now.duration_since(*released_at) >= duration;
            if expired {
                trace!(port, "Port TIME_WAIT expired");
            }
            !expired
        });
    }

    /// Force immediate release of a port (skip TIME_WAIT)
    ///
    /// This should only be used when TIME_WAIT is not needed, such as when
    /// the connection was never established.
    pub fn release_immediate(&self, port: u16) {
        if self.allocated.remove(&port).is_some() {
            debug!(port, "Port immediately released (skipped TIME_WAIT)");
        } else if self.time_wait.remove(&port).is_some() {
            debug!(port, "Port removed from TIME_WAIT");
        }
    }

    // =========================================================================
    // Statistics
    // =========================================================================

    /// Get the number of currently allocated ports
    #[must_use]
    pub fn allocated_count(&self) -> usize {
        self.allocated.len()
    }

    /// Get the number of ports in TIME_WAIT state
    #[must_use]
    pub fn time_wait_count(&self) -> usize {
        self.time_wait.len()
    }

    /// Get the number of available ports (not allocated and not in TIME_WAIT)
    #[must_use]
    pub fn available_count(&self) -> usize {
        self.config
            .port_count()
            .saturating_sub(self.allocated_count())
            .saturating_sub(self.time_wait_count())
    }

    /// Check if a specific port is allocated
    #[must_use]
    pub fn is_allocated(&self, port: u16) -> bool {
        self.allocated.contains(&port)
    }

    /// Check if a specific port is in TIME_WAIT
    #[must_use]
    pub fn is_in_time_wait(&self, port: u16) -> bool {
        self.time_wait.contains_key(&port)
    }

    /// Get the configuration
    #[must_use]
    pub fn config(&self) -> &PortAllocatorConfig {
        &self.config
    }

    /// Get allocator statistics
    #[must_use]
    pub fn stats(&self) -> PortAllocatorStats {
        PortAllocatorStats {
            allocated: self.allocated_count(),
            time_wait: self.time_wait_count(),
            available: self.available_count(),
            total: self.config.port_count(),
            range_start: self.config.start(),
            range_end: self.config.end(),
        }
    }
}

impl Default for PortAllocator {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for PortAllocator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PortAllocator")
            .field("config", &self.config)
            .field("allocated", &self.allocated_count())
            .field("time_wait", &self.time_wait_count())
            .field("available", &self.available_count())
            .finish()
    }
}

// =============================================================================
// Port Guard
// =============================================================================

/// RAII guard for an allocated port
///
/// When this guard is dropped, the port is automatically released into
/// TIME_WAIT state. Use `take()` to consume the guard and take ownership
/// of the port for manual management.
pub struct PortGuard<'a> {
    /// Reference to the allocator
    allocator: &'a PortAllocator,
    /// The allocated port (None if taken)
    port: Option<u16>,
}

impl<'a> PortGuard<'a> {
    /// Create a new port guard
    fn new(allocator: &'a PortAllocator, port: u16) -> Self {
        Self {
            allocator,
            port: Some(port),
        }
    }

    /// Get the allocated port number
    ///
    /// # Panics
    ///
    /// Panics if `take()` was already called.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port.expect("port was already taken")
    }

    /// Take ownership of the port, consuming the guard
    ///
    /// After calling this method, the port will NOT be automatically released.
    /// You must manually call `PortAllocator::release()` when done.
    ///
    /// # Panics
    ///
    /// Panics if `take()` was already called.
    #[must_use]
    pub fn take(mut self) -> u16 {
        self.port.take().expect("port was already taken")
    }

    /// Release the port immediately without TIME_WAIT
    ///
    /// This consumes the guard and releases the port without entering TIME_WAIT.
    /// Useful when the connection was never established.
    pub fn release_immediate(mut self) {
        if let Some(port) = self.port.take() {
            self.allocator.release_immediate(port);
        }
    }
}

impl Drop for PortGuard<'_> {
    fn drop(&mut self) {
        if let Some(port) = self.port.take() {
            self.allocator.release(port);
        }
    }
}

impl std::fmt::Debug for PortGuard<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PortGuard")
            .field("port", &self.port)
            .finish()
    }
}

// =============================================================================
// Statistics
// =============================================================================

/// Port allocator statistics
#[derive(Debug, Clone, Default)]
pub struct PortAllocatorStats {
    /// Currently allocated ports
    pub allocated: usize,
    /// Ports in TIME_WAIT
    pub time_wait: usize,
    /// Available ports
    pub available: usize,
    /// Total ports in range
    pub total: usize,
    /// Range start
    pub range_start: u16,
    /// Range end
    pub range_end: u16,
}

impl PortAllocatorStats {
    /// Get utilization as a percentage
    #[must_use]
    pub fn utilization_percent(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            ((self.allocated + self.time_wait) as f64 / self.total as f64) * 100.0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_allocator_default() {
        let allocator = PortAllocator::new();
        assert_eq!(allocator.allocated_count(), 0);
        assert_eq!(allocator.time_wait_count(), 0);
    }

    #[test]
    fn test_basic_allocation() {
        let allocator = PortAllocator::new();

        let guard = allocator.allocate().expect("should allocate");
        let port = guard.port();

        assert!((PORT_RANGE_START..=PORT_RANGE_END).contains(&port));
        assert!(allocator.is_allocated(port));
        assert_eq!(allocator.allocated_count(), 1);
    }

    #[test]
    fn test_allocation_and_release() {
        let allocator = PortAllocator::new();

        let guard = allocator.allocate().expect("should allocate");
        let port = guard.port();

        assert!(allocator.is_allocated(port));
        assert!(!allocator.is_in_time_wait(port));

        drop(guard);

        assert!(!allocator.is_allocated(port));
        assert!(allocator.is_in_time_wait(port));
        assert_eq!(allocator.time_wait_count(), 1);
    }

    #[test]
    fn test_take_ownership() {
        let allocator = PortAllocator::new();

        let guard = allocator.allocate().expect("should allocate");
        let port = guard.take();

        // Port should still be allocated (not released)
        assert!(allocator.is_allocated(port));
        assert!(!allocator.is_in_time_wait(port));

        // Manually release
        allocator.release(port);

        assert!(!allocator.is_allocated(port));
        assert!(allocator.is_in_time_wait(port));
    }

    #[test]
    fn test_release_immediate() {
        let allocator = PortAllocator::new();

        let guard = allocator.allocate().expect("should allocate");
        let port = guard.port();

        guard.release_immediate();

        assert!(!allocator.is_allocated(port));
        assert!(!allocator.is_in_time_wait(port));
    }

    #[test]
    fn test_time_wait_expiry() {
        let config = PortAllocatorConfig {
            range: 50000..=50010,
            time_wait_duration: Duration::from_millis(50),
        };
        let allocator = PortAllocator::with_config(config);

        let guard = allocator.allocate().expect("should allocate");
        let port = guard.port();
        drop(guard);

        assert!(allocator.is_in_time_wait(port));

        thread::sleep(Duration::from_millis(100));

        // Trigger cleanup via allocation
        let _guard2 = allocator.allocate();

        assert!(!allocator.is_in_time_wait(port));
    }

    #[test]
    fn test_no_reuse_during_time_wait() {
        let config = PortAllocatorConfig {
            range: 50000..=50002, // Only 3 ports
            time_wait_duration: Duration::from_secs(60),
        };
        let allocator = PortAllocator::with_config(config);

        let guard1 = allocator.allocate().expect("should allocate 1");
        let guard2 = allocator.allocate().expect("should allocate 2");
        let guard3 = allocator.allocate().expect("should allocate 3");

        assert!(allocator.allocate().is_none());

        let port1 = guard1.port();
        drop(guard1);

        // Still should fail - port is in TIME_WAIT
        assert!(allocator.allocate().is_none());
        assert!(allocator.is_in_time_wait(port1));

        drop(guard2);
        drop(guard3);
    }

    #[test]
    fn test_port_exhaustion() {
        let config = PortAllocatorConfig {
            range: 50000..=50001, // Only 2 ports
            time_wait_duration: Duration::from_secs(60),
        };
        let allocator = PortAllocator::with_config(config);

        let _guard1 = allocator.allocate().expect("should allocate 1");
        let _guard2 = allocator.allocate().expect("should allocate 2");

        assert!(allocator.allocate().is_none());
        assert_eq!(allocator.allocated_count(), 2);
    }

    #[test]
    fn test_shard_allocation() {
        let a0 = PortAllocator::for_shard(0, 4);
        let a1 = PortAllocator::for_shard(1, 4);
        let a2 = PortAllocator::for_shard(2, 4);
        let a3 = PortAllocator::for_shard(3, 4);

        // Ranges should not overlap
        assert!(a0.config.end() < a1.config.start());
        assert!(a1.config.end() < a2.config.start());
        assert!(a2.config.end() < a3.config.start());

        // Last shard should end at PORT_RANGE_END
        assert_eq!(a3.config.end(), PORT_RANGE_END);
    }

    #[test]
    fn test_shard_for_port() {
        // Shard 0: 49152-53247
        assert_eq!(PortAllocator::shard_for_port(49152, 4), Some(0));
        assert_eq!(PortAllocator::shard_for_port(53247, 4), Some(0));

        // Shard 1: 53248-57343
        assert_eq!(PortAllocator::shard_for_port(53248, 4), Some(1));

        // Shard 3: 61440-65535
        assert_eq!(PortAllocator::shard_for_port(65535, 4), Some(3));

        // Outside range
        assert_eq!(PortAllocator::shard_for_port(80, 4), None);
        assert_eq!(PortAllocator::shard_for_port(443, 4), None);
    }

    #[test]
    fn test_stats() {
        let config = PortAllocatorConfig {
            range: 50000..=50009, // 10 ports
            time_wait_duration: Duration::from_secs(60),
        };
        let allocator = PortAllocator::with_config(config);

        assert_eq!(allocator.stats().total, 10);
        assert_eq!(allocator.stats().available, 10);

        let g1 = allocator.allocate();
        let g2 = allocator.allocate();
        let g3 = allocator.allocate();

        assert_eq!(allocator.stats().allocated, 3);
        assert_eq!(allocator.stats().available, 7);

        drop(g3);

        assert_eq!(allocator.stats().allocated, 2);
        assert_eq!(allocator.stats().time_wait, 1);
        assert_eq!(allocator.stats().available, 7);

        drop(g1);
        drop(g2);
    }

    #[test]
    fn test_utilization_percent() {
        let stats = PortAllocatorStats {
            allocated: 50,
            time_wait: 25,
            available: 25,
            total: 100,
            range_start: 50000,
            range_end: 50099,
        };

        assert!((stats.utilization_percent() - 75.0).abs() < 0.01);
    }

    #[test]
    #[should_panic(expected = "total_shards must be > 0")]
    fn test_for_shard_zero_shards() {
        let _ = PortAllocator::for_shard(0, 0);
    }

    #[test]
    #[should_panic(expected = "shard_index 5 must be < total_shards 4")]
    fn test_for_shard_invalid_index() {
        let _ = PortAllocator::for_shard(5, 4);
    }
}
