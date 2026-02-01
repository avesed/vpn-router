//! Ephemeral port allocator with TIME_WAIT tracking
//!
//! This module provides a thread-safe port allocator for smoltcp bridge
//! implementations. It manages ephemeral ports (49152-65535) and tracks
//! TIME_WAIT state to prevent port reuse issues.
//!
//! # Features
//!
//! - **Thread-safe**: Uses `DashSet` and `DashMap` for lock-free concurrent access
//! - **TIME_WAIT tracking**: Released ports enter a TIME_WAIT state before reuse
//! - **RAII guards**: `PortGuard` automatically releases ports when dropped
//! - **Random start**: Allocations start from a random port to distribute usage
//!
//! # Usage
//!
//! ```ignore
//! use rust_router::smoltcp_utils::{PortAllocator, PortAllocatorConfig};
//!
//! // Create allocator with default config (IANA ephemeral ports)
//! let allocator = PortAllocator::new();
//!
//! // Allocate a port - returns a RAII guard
//! if let Some(guard) = allocator.allocate() {
//!     let port = guard.port();
//!     println!("Allocated port: {}", port);
//!
//!     // Port is automatically released when guard is dropped
//! }
//!
//! // Or take ownership of the port for manual management
//! if let Some(guard) = allocator.allocate() {
//!     let port = guard.take(); // Consumes guard, port stays allocated
//!     // ... use port ...
//!     allocator.release(port); // Manual release into TIME_WAIT
//! }
//! ```
//!
//! # TIME_WAIT Behavior
//!
//! When a port is released (either by dropping `PortGuard` or calling `release()`),
//! it enters a TIME_WAIT state for 60 seconds (configurable). During this time,
//! the port cannot be reallocated. This prevents issues with delayed packets
//! from previous connections arriving at new connections using the same port.

use std::ops::RangeInclusive;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use dashmap::DashSet;
use tracing::{debug, trace, warn};

use super::config::{PORT_RANGE_END, PORT_RANGE_START, PORT_TIME_WAIT_SECS};

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
    ///
    /// # Arguments
    ///
    /// * `range` - The port range to allocate from
    /// * `time_wait_duration` - How long to keep ports in TIME_WAIT after release
    ///
    /// # Example
    ///
    /// ```ignore
    /// use std::time::Duration;
    /// use rust_router::smoltcp_utils::PortAllocatorConfig;
    ///
    /// let config = PortAllocatorConfig::new(
    ///     50000..=50099, // 100 ports
    ///     Duration::from_secs(30), // 30 second TIME_WAIT
    /// );
    /// ```
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
}

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
    /// This partitions the default ephemeral port range (49152-65535) into equal-sized
    /// ranges for each shard. This ensures no port collisions between shards when all
    /// shards use the same source IP.
    ///
    /// # Arguments
    ///
    /// * `shard_index` - The index of this shard (0-based)
    /// * `total_shards` - Total number of shards
    ///
    /// # Example
    ///
    /// ```ignore
    /// // With 4 shards and default range (49152-65535 = 16384 ports):
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
            "PortAllocator for shard {}/{}: port range {}..={} ({} ports)",
            shard_index,
            total_shards,
            shard_start,
            shard_end,
            shard_end - shard_start + 1
        );

        Self::with_config(config)
    }

    /// Get the shard index from a port number
    ///
    /// This is the inverse of `for_shard()` - given a port, determine which shard
    /// it belongs to. Used by the reply dispatcher to route packets to the correct shard.
    ///
    /// # Arguments
    ///
    /// * `port` - The port number to look up
    /// * `total_shards` - Total number of shards
    ///
    /// # Returns
    ///
    /// The shard index (0-based), or `None` if the port is outside the ephemeral range.
    ///
    /// # Example
    ///
    /// ```ignore
    /// // With 4 shards:
    /// assert_eq!(PortAllocator::shard_for_port(49152, 4), Some(0));
    /// assert_eq!(PortAllocator::shard_for_port(53248, 4), Some(1));
    /// assert_eq!(PortAllocator::shard_for_port(65535, 4), Some(3));
    /// ```
    #[must_use]
    pub fn shard_for_port(port: u16, total_shards: u16) -> Option<usize> {
        if port < PORT_RANGE_START || port > PORT_RANGE_END {
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
    ///
    /// # Arguments
    ///
    /// * `config` - Port allocator configuration
    ///
    /// # Example
    ///
    /// ```ignore
    /// use std::time::Duration;
    /// use rust_router::smoltcp_utils::{PortAllocator, PortAllocatorConfig};
    ///
    /// let config = PortAllocatorConfig::new(
    ///     50000..=50099,
    ///     Duration::from_secs(30),
    /// );
    /// let allocator = PortAllocator::with_config(config);
    /// ```
    #[must_use]
    pub fn with_config(config: PortAllocatorConfig) -> Self {
        // Start from a random port within the range
        let start_port =
            *config.range.start() + (rand::random::<u16>() % config.port_count() as u16);

        debug!(
            "PortAllocator created: range={:?}, time_wait={:?}, start={}",
            config.range, config.time_wait_duration, start_port
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
    ///
    /// # Example
    ///
    /// ```ignore
    /// let allocator = PortAllocator::new();
    /// if let Some(guard) = allocator.allocate() {
    ///     println!("Got port: {}", guard.port());
    ///     // Port released when guard drops
    /// } else {
    ///     println!("No ports available");
    /// }
    /// ```
    pub fn allocate(&self) -> Option<PortGuard<'_>> {
        // Clean up expired TIME_WAIT entries first
        self.cleanup_time_wait();

        let range_start = *self.config.range.start();
        let range_len = self.config.port_count();

        // Try each port in the range, starting from next_port
        let start = self.next_port.fetch_add(1, Ordering::Relaxed);

        for offset in 0..range_len {
            // Calculate port with wrapping within range
            let port = range_start
                + ((start.wrapping_sub(range_start) as usize + offset) % range_len) as u16;

            // Skip ports in TIME_WAIT
            if self.time_wait.contains_key(&port) {
                trace!("Port {} is in TIME_WAIT, skipping", port);
                continue;
            }

            // Try to allocate this port
            if self.allocated.insert(port) {
                debug!("Allocated port {}", port);
                return Some(PortGuard::new(self, port));
            }

            trace!("Port {} already allocated, trying next", port);
        }

        warn!(
            "Port exhaustion: all {} ports in use or TIME_WAIT",
            range_len
        );
        None
    }

    /// Release a port into TIME_WAIT state
    ///
    /// This is called automatically by `PortGuard::drop()`, but can also be
    /// called manually if the port was taken with `PortGuard::take()`.
    ///
    /// # Arguments
    ///
    /// * `port` - The port to release
    pub fn release(&self, port: u16) {
        if self.allocated.remove(&port).is_some() {
            self.time_wait.insert(port, Instant::now());
            debug!("Released port {} into TIME_WAIT", port);
        } else {
            warn!("Attempted to release unallocated port {}", port);
        }
    }

    /// Clean up expired TIME_WAIT entries
    fn cleanup_time_wait(&self) {
        let now = Instant::now();
        let duration = self.config.time_wait_duration;

        self.time_wait.retain(|port, released_at| {
            let expired = now.duration_since(*released_at) >= duration;
            if expired {
                trace!("Port {} TIME_WAIT expired", port);
            }
            !expired
        });
    }

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

    /// Force immediate release of a port (skip TIME_WAIT)
    ///
    /// This should only be used in special cases where TIME_WAIT is not needed,
    /// such as when the connection was never established.
    ///
    /// # Arguments
    ///
    /// * `port` - The port to release immediately
    pub fn release_immediate(&self, port: u16) {
        if self.allocated.remove(&port).is_some() {
            debug!("Immediately released port {} (skipped TIME_WAIT)", port);
        } else {
            // Maybe it's already in TIME_WAIT
            if self.time_wait.remove(&port).is_some() {
                debug!("Removed port {} from TIME_WAIT", port);
            }
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
            .field("allocated_count", &self.allocated_count())
            .field("time_wait_count", &self.time_wait_count())
            .field("available_count", &self.available_count())
            .finish()
    }
}

/// RAII guard for an allocated port
///
/// When this guard is dropped, the port is automatically released into
/// TIME_WAIT state. Use `take()` to consume the guard and take ownership
/// of the port for manual management.
///
/// # Example
///
/// ```ignore
/// let allocator = PortAllocator::new();
///
/// // Automatic release on drop
/// {
///     let guard = allocator.allocate().unwrap();
///     let port = guard.port();
///     // ... use port ...
/// } // Port released here
///
/// // Manual management
/// let guard = allocator.allocate().unwrap();
/// let port = guard.take(); // Consumes guard
/// // ... use port ...
/// allocator.release(port); // Manual release
/// ```
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
    /// After calling this method, the port will NOT be automatically released
    /// when the guard is dropped. You must manually call `PortAllocator::release()`
    /// when done with the port.
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_allocator_default() {
        let allocator = PortAllocator::new();
        assert_eq!(allocator.allocated_count(), 0);
        assert_eq!(allocator.time_wait_count(), 0);
    }

    #[test]
    fn test_basic_allocation() {
        let allocator = PortAllocator::new();

        // Allocate a port
        let guard = allocator.allocate().expect("should allocate");
        let port = guard.port();

        // Verify it's in the valid range
        assert!(port >= PORT_RANGE_START);
        assert!(port <= PORT_RANGE_END);

        // Verify it's marked as allocated
        assert!(allocator.is_allocated(port));
        assert_eq!(allocator.allocated_count(), 1);
    }

    #[test]
    fn test_allocation_and_release() {
        let allocator = PortAllocator::new();

        // Allocate a port
        let guard = allocator.allocate().expect("should allocate");
        let port = guard.port();

        assert!(allocator.is_allocated(port));
        assert!(!allocator.is_in_time_wait(port));

        // Drop the guard - port should enter TIME_WAIT
        drop(guard);

        assert!(!allocator.is_allocated(port));
        assert!(allocator.is_in_time_wait(port));
        assert_eq!(allocator.time_wait_count(), 1);
    }

    #[test]
    fn test_take_ownership() {
        let allocator = PortAllocator::new();

        // Allocate and take ownership
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

        // Allocate a port
        let guard = allocator.allocate().expect("should allocate");
        let port = guard.port();

        // Release immediately (skip TIME_WAIT)
        guard.release_immediate();

        assert!(!allocator.is_allocated(port));
        assert!(!allocator.is_in_time_wait(port));
    }

    #[test]
    fn test_time_wait_expiry() {
        // Use a very short TIME_WAIT for testing
        let config = PortAllocatorConfig {
            range: 50000..=50010,
            time_wait_duration: Duration::from_millis(50),
        };
        let allocator = PortAllocator::with_config(config);

        // Allocate and release
        let guard = allocator.allocate().expect("should allocate");
        let port = guard.port();
        drop(guard);

        assert!(allocator.is_in_time_wait(port));

        // Wait for TIME_WAIT to expire
        thread::sleep(Duration::from_millis(100));

        // Trigger cleanup via allocation
        let _guard2 = allocator.allocate();

        // Port should no longer be in TIME_WAIT
        assert!(!allocator.is_in_time_wait(port));
    }

    #[test]
    fn test_no_reuse_during_time_wait() {
        // Use a small range and moderate TIME_WAIT
        let config = PortAllocatorConfig {
            range: 50000..=50002, // Only 3 ports
            time_wait_duration: Duration::from_secs(60),
        };
        let allocator = PortAllocator::with_config(config);

        // Allocate all ports
        let guard1 = allocator.allocate().expect("should allocate 1");
        let port1 = guard1.port();
        let guard2 = allocator.allocate().expect("should allocate 2");
        let port2 = guard2.port();
        let guard3 = allocator.allocate().expect("should allocate 3");
        let port3 = guard3.port();

        // Should fail - all ports allocated
        assert!(allocator.allocate().is_none());

        // Release one into TIME_WAIT
        drop(guard1);

        // Still should fail - port is in TIME_WAIT
        assert!(allocator.allocate().is_none());
        assert!(allocator.is_in_time_wait(port1));

        // Verify other ports are still allocated
        assert!(allocator.is_allocated(port2));
        assert!(allocator.is_allocated(port3));
    }

    #[test]
    fn test_port_exhaustion() {
        // Use a tiny range
        let config = PortAllocatorConfig {
            range: 50000..=50001, // Only 2 ports
            time_wait_duration: Duration::from_secs(60),
        };
        let allocator = PortAllocator::with_config(config);

        // Allocate both ports
        let _guard1 = allocator.allocate().expect("should allocate 1");
        let _guard2 = allocator.allocate().expect("should allocate 2");

        // Third allocation should fail
        assert!(allocator.allocate().is_none());
        assert_eq!(allocator.allocated_count(), 2);
    }

    #[test]
    fn test_multiple_allocations() {
        let allocator = PortAllocator::new();

        // Allocate multiple ports
        let mut guards = Vec::new();
        let mut ports = Vec::new();

        for _ in 0..100 {
            let guard = allocator.allocate().expect("should allocate");
            ports.push(guard.port());
            guards.push(guard);
        }

        assert_eq!(allocator.allocated_count(), 100);

        // All ports should be unique
        ports.sort();
        ports.dedup();
        assert_eq!(ports.len(), 100);

        // Release all
        drop(guards);

        assert_eq!(allocator.allocated_count(), 0);
        assert_eq!(allocator.time_wait_count(), 100);
    }

    #[test]
    fn test_debug_impl() {
        let allocator = PortAllocator::new();
        let debug_str = format!("{:?}", allocator);
        assert!(debug_str.contains("PortAllocator"));
        assert!(debug_str.contains("allocated_count"));

        let guard = allocator.allocate().expect("should allocate");
        let debug_str = format!("{:?}", guard);
        assert!(debug_str.contains("PortGuard"));
    }

    #[test]
    fn test_config() {
        let config = PortAllocatorConfig::default();
        assert_eq!(config.port_count(), 16384); // 65535 - 49152 + 1

        let custom_config = PortAllocatorConfig::new(50000..=50099, Duration::from_secs(30));
        assert_eq!(custom_config.port_count(), 100);
        assert_eq!(custom_config.time_wait_duration, Duration::from_secs(30));
    }

    #[test]
    fn test_available_count() {
        let config = PortAllocatorConfig {
            range: 50000..=50009, // 10 ports
            time_wait_duration: Duration::from_secs(60),
        };
        let allocator = PortAllocator::with_config(config);

        assert_eq!(allocator.available_count(), 10);

        // Allocate 3
        let g1 = allocator.allocate();
        let g2 = allocator.allocate();
        let g3 = allocator.allocate();

        assert_eq!(allocator.available_count(), 7);
        assert_eq!(allocator.allocated_count(), 3);

        // Release 1 into TIME_WAIT
        drop(g3);

        assert_eq!(allocator.available_count(), 7); // 10 - 2 - 1 = 7
        assert_eq!(allocator.allocated_count(), 2);
        assert_eq!(allocator.time_wait_count(), 1);

        // Keep g1 and g2 alive to prevent early cleanup
        drop(g1);
        drop(g2);
    }

    #[test]
    fn test_concurrent_allocation() {
        use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
        use std::sync::Arc;

        let allocator = Arc::new(PortAllocator::new());
        let successful_allocations = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();

        // Spawn multiple threads allocating ports
        for _ in 0..10 {
            let alloc = Arc::clone(&allocator);
            let counter = Arc::clone(&successful_allocations);
            handles.push(thread::spawn(move || {
                let mut count = 0;
                for _ in 0..10 {
                    if let Some(guard) = alloc.allocate() {
                        count += 1;
                        // Take ownership so the port stays allocated
                        let _ = guard.take();
                    }
                }
                counter.fetch_add(count, AtomicOrdering::Relaxed);
                count
            }));
        }

        // Wait for all threads to complete
        for handle in handles {
            handle.join().unwrap();
        }

        // All allocations should succeed (100 ports from 16384 available)
        let total = successful_allocations.load(AtomicOrdering::Relaxed);
        assert_eq!(total, 100);
        assert_eq!(allocator.allocated_count(), 100);
    }

    #[test]
    fn test_port_guard_take_consumes() {
        let allocator = PortAllocator::new();
        let guard = allocator.allocate().expect("should allocate");
        let port = guard.port();

        // Take consumes the guard
        let taken_port = guard.take();
        assert_eq!(port, taken_port);

        // Port should still be allocated since we took it
        assert!(allocator.is_allocated(taken_port));

        // Manually release
        allocator.release(taken_port);
        assert!(!allocator.is_allocated(taken_port));
        assert!(allocator.is_in_time_wait(taken_port));
    }

    #[test]
    fn test_release_unallocated_port() {
        let allocator = PortAllocator::new();

        // Try to release a port that was never allocated
        allocator.release(50000);

        // Should not be in TIME_WAIT since it was never allocated
        assert!(!allocator.is_in_time_wait(50000));
    }

    // -------------------------------------------------------------------------
    // Sharded Port Allocation Tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_for_shard_basic() {
        // Test basic shard allocation with 4 shards
        let allocator = PortAllocator::for_shard(0, 4);

        // Shard 0 should have ports 49152-53247 (4096 ports)
        assert!(allocator.port_range_start >= 49152);
        assert!(allocator.port_range_end <= 53247);
    }

    #[test]
    fn test_for_shard_all_shards() {
        // Verify all 4 shards have non-overlapping ranges
        let a0 = PortAllocator::for_shard(0, 4);
        let a1 = PortAllocator::for_shard(1, 4);
        let a2 = PortAllocator::for_shard(2, 4);
        let a3 = PortAllocator::for_shard(3, 4);

        // Ranges should not overlap
        assert!(a0.port_range_end < a1.port_range_start);
        assert!(a1.port_range_end < a2.port_range_start);
        assert!(a2.port_range_end < a3.port_range_start);

        // Last shard should end at PORT_RANGE_END
        assert_eq!(a3.port_range_end, 65535);
    }

    #[test]
    fn test_for_shard_allocates_in_range() {
        // Test that allocated ports are within the shard's range
        let allocator = PortAllocator::for_shard(1, 4);
        let start = allocator.port_range_start;
        let end = allocator.port_range_end;

        // Allocate multiple ports and verify they're in range
        for _ in 0..10 {
            if let Some(guard) = allocator.allocate() {
                let port = guard.port();
                assert!(port >= start && port <= end, "Port {} not in range [{}, {}]", port, start, end);
            }
        }
    }

    #[test]
    fn test_shard_for_port_basic() {
        // Test shard_for_port with 4 shards
        // Ports 49152-65535 = 16384 ports, 4096 per shard

        // Shard 0: 49152-53247
        assert_eq!(PortAllocator::shard_for_port(49152, 4), Some(0));
        assert_eq!(PortAllocator::shard_for_port(53247, 4), Some(0));

        // Shard 1: 53248-57343
        assert_eq!(PortAllocator::shard_for_port(53248, 4), Some(1));
        assert_eq!(PortAllocator::shard_for_port(57343, 4), Some(1));

        // Shard 2: 57344-61439
        assert_eq!(PortAllocator::shard_for_port(57344, 4), Some(2));
        assert_eq!(PortAllocator::shard_for_port(61439, 4), Some(2));

        // Shard 3: 61440-65535
        assert_eq!(PortAllocator::shard_for_port(61440, 4), Some(3));
        assert_eq!(PortAllocator::shard_for_port(65535, 4), Some(3));
    }

    #[test]
    fn test_shard_for_port_outside_range() {
        // Ports outside ephemeral range should return None
        assert_eq!(PortAllocator::shard_for_port(80, 4), None);
        assert_eq!(PortAllocator::shard_for_port(443, 4), None);
        assert_eq!(PortAllocator::shard_for_port(49151, 4), None);
        assert_eq!(PortAllocator::shard_for_port(0, 4), None);
    }

    #[test]
    fn test_shard_for_port_roundtrip() {
        // Verify that for_shard and shard_for_port are inverses
        // Test using the port range boundaries instead of allocating
        for shard_idx in 0u16..4 {
            let allocator = PortAllocator::for_shard(shard_idx, 4);
            // Use the start of each shard's range as a representative port
            let port = allocator.port_range_start;
            let detected_shard = PortAllocator::shard_for_port(port, 4);
            assert_eq!(detected_shard, Some(shard_idx as usize),
                "Port {} from shard {} detected as shard {:?}", port, shard_idx, detected_shard);
        }
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
