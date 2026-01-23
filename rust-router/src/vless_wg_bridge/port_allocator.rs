//! Ephemeral port allocator with TIME_WAIT tracking
//!
//! This module provides a thread-safe port allocator for the VLESS-WG bridge.
//! It manages ephemeral ports (49152-65535) and tracks TIME_WAIT state to
//! prevent port reuse issues.
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
//! use rust_router::vless_wg_bridge::{PortAllocator, PortAllocatorConfig};
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
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(PortAllocatorConfig::default())
    }

    /// Create a new port allocator with custom configuration
    #[must_use]
    pub fn with_config(config: PortAllocatorConfig) -> Self {
        // Start from a random port within the range
        let start_port = *config.range.start() + (rand::random::<u16>() % config.port_count() as u16);

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
    pub fn allocate(&self) -> Option<PortGuard<'_>> {
        // Clean up expired TIME_WAIT entries first
        self.cleanup_time_wait();

        let range_start = *self.config.range.start();
        let range_len = self.config.port_count();

        // Try each port in the range, starting from next_port
        let start = self.next_port.fetch_add(1, Ordering::Relaxed);

        for offset in 0..range_len {
            // Calculate port with wrapping within range
            let port = range_start + ((start.wrapping_sub(range_start) as usize + offset) % range_len) as u16;

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
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

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
}
