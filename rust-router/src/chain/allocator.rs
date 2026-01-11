//! DSCP value allocator for Phase 6
//!
//! This module implements DSCP value allocation for chain routing,
//! ensuring each chain gets a unique DSCP value with conflict detection.
//!
//! # Phase 6 Implementation Status
//!
//! - [ ] 6.6.4 DSCP allocation
//! - [ ] 6.6.4 DSCP reservation
//! - [ ] 6.6.4 Conflict detection
//! - [ ] 6.6.4 Reserved `QoS` value protection
//!
//! # DSCP Value Range
//!
//! - Valid range: 1-63 (6-bit field)
//! - Value 0: Reserved (no DSCP marking)
//! - Standard `QoS` values: Protected from auto-allocation
//!
//! # Reserved DSCP Values (Standard `QoS`)
//!
//! The following DSCP values are reserved for standard `QoS` and cannot
//! be auto-allocated (but can be manually reserved):
//!
//! | DSCP | Name | Description |
//! |------|------|-------------|
//! | 0 | BE | Best Effort |
//! | 8 | CS1 | Class Selector 1 |
//! | 10 | AF11 | Assured Forwarding 11 |
//! | 46 | EF | Expedited Forwarding |
//!
//! # Thread Safety
//!
//! The allocator uses `RwLock` for thread-safe allocation and release
//! of DSCP values across concurrent operations.
//!
//! # References
//!
//! - RFC 2474: Definition of the Differentiated Services Field
//! - RFC 2597: Assured Forwarding PHB Group
//! - RFC 3246: Expedited Forwarding PHB
//! - Implementation Plan: `docs/PHASE6_IMPLEMENTATION_PLAN_v3.2.md` Section 6.6.4

use std::collections::HashSet;
use std::sync::RwLock;

/// Minimum DSCP value for chain routing
pub const MIN_DSCP: u8 = 1;

/// Maximum DSCP value (6-bit field)
pub const MAX_DSCP: u8 = 63;

/// Reserved DSCP values (standard `QoS` classes)
///
/// These values are protected from auto-allocation to avoid
/// interference with standard `QoS` mechanisms.
pub const RESERVED_DSCP: &[u8] = &[
    0,  // BE (Best Effort)
    8,  // CS1 (Class Selector 1)
    10, // AF11 (Assured Forwarding 11)
    12, // AF12
    14, // AF13
    16, // CS2 (Class Selector 2)
    18, // AF21
    20, // AF22
    22, // AF23
    24, // CS3 (Class Selector 3)
    26, // AF31
    28, // AF32
    30, // AF33
    32, // CS4 (Class Selector 4)
    34, // AF41
    36, // AF42
    38, // AF43
    40, // CS5 (Class Selector 5)
    46, // EF (Expedited Forwarding)
    48, // CS6 (Class Selector 6)
    56, // CS7 (Class Selector 7)
];

/// Error types for DSCP allocation
#[derive(Debug, Clone, thiserror::Error)]
pub enum DscpAllocatorError {
    /// No DSCP values available
    #[error("No available DSCP values")]
    Exhausted,

    /// DSCP value already allocated
    #[error("DSCP value {0} is already allocated")]
    AlreadyAllocated(u8),

    /// DSCP value is reserved
    #[error("DSCP value {0} is reserved for QoS")]
    Reserved(u8),

    /// DSCP value out of range
    #[error("DSCP value {0} is out of valid range (1-63)")]
    OutOfRange(u8),
}

/// DSCP value allocator with conflict detection
///
/// Manages allocation of unique DSCP values for chain routing
/// while protecting standard `QoS` values.
pub struct DscpAllocator {
    /// Currently allocated DSCP values
    allocated: RwLock<HashSet<u8>>,
    /// Reserved DSCP values (standard `QoS`)
    reserved: HashSet<u8>,
}

impl DscpAllocator {
    /// Create a new DSCP allocator
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::chain::allocator::DscpAllocator;
    ///
    /// let allocator = DscpAllocator::new();
    /// ```
    pub fn new() -> Self {
        Self {
            allocated: RwLock::new(HashSet::new()),
            reserved: RESERVED_DSCP.iter().copied().collect(),
        }
    }

    /// Allocate the next available DSCP value
    ///
    /// Automatically selects a DSCP value that is neither reserved
    /// for `QoS` nor already allocated to another chain.
    ///
    /// # Returns
    ///
    /// The allocated DSCP value, or an error if none available.
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::chain::allocator::DscpAllocator;
    ///
    /// let allocator = DscpAllocator::new();
    /// let dscp = allocator.allocate().expect("Should allocate DSCP");
    /// assert!(dscp >= 1 && dscp <= 63);
    /// ```
    #[must_use = "The allocated DSCP value must be stored and later released"]
    pub fn allocate(&self) -> Result<u8, DscpAllocatorError> {
        let mut allocated = self
            .allocated
            .write()
            .map_err(|_| DscpAllocatorError::Exhausted)?;

        for dscp in MIN_DSCP..=MAX_DSCP {
            if !allocated.contains(&dscp) && !self.reserved.contains(&dscp) {
                allocated.insert(dscp);
                return Ok(dscp);
            }
        }

        Err(DscpAllocatorError::Exhausted)
    }

    /// Reserve a specific DSCP value
    ///
    /// Allows manual reservation of a specific DSCP value for a chain.
    /// Reserved `QoS` values can be manually allocated if the user
    /// explicitly requests them.
    ///
    /// # Arguments
    ///
    /// * `dscp` - The DSCP value to reserve (1-63)
    ///
    /// # Returns
    ///
    /// Ok if successful, or an error if already allocated.
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::chain::allocator::DscpAllocator;
    ///
    /// let allocator = DscpAllocator::new();
    /// allocator.reserve(42).expect("Should reserve DSCP");
    /// ```
    #[must_use = "The reservation result should be checked for success or failure"]
    pub fn reserve(&self, dscp: u8) -> Result<(), DscpAllocatorError> {
        if !(MIN_DSCP..=MAX_DSCP).contains(&dscp) {
            return Err(DscpAllocatorError::OutOfRange(dscp));
        }

        let mut allocated = self
            .allocated
            .write()
            .map_err(|_| DscpAllocatorError::Exhausted)?;

        if allocated.contains(&dscp) {
            return Err(DscpAllocatorError::AlreadyAllocated(dscp));
        }

        allocated.insert(dscp);
        Ok(())
    }

    /// Release a previously allocated DSCP value
    ///
    /// # Arguments
    ///
    /// * `dscp` - The DSCP value to release
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::chain::allocator::DscpAllocator;
    ///
    /// let allocator = DscpAllocator::new();
    /// let dscp = allocator.allocate().unwrap();
    /// allocator.release(dscp);
    /// ```
    pub fn release(&self, dscp: u8) {
        if let Ok(mut allocated) = self.allocated.write() {
            allocated.remove(&dscp);
        }
    }

    /// Check if a DSCP value is currently allocated
    ///
    /// # Arguments
    ///
    /// * `dscp` - The DSCP value to check
    ///
    /// # Returns
    ///
    /// `true` if the value is allocated, `false` otherwise.
    pub fn is_allocated(&self, dscp: u8) -> bool {
        self.allocated
            .read()
            .map(|allocated| allocated.contains(&dscp))
            .unwrap_or(false)
    }

    /// Check if a DSCP value is reserved for `QoS`
    ///
    /// # Arguments
    ///
    /// * `dscp` - The DSCP value to check
    ///
    /// # Returns
    ///
    /// `true` if the value is reserved for `QoS`, `false` otherwise.
    pub fn is_reserved(&self, dscp: u8) -> bool {
        self.reserved.contains(&dscp)
    }

    /// Get the number of allocated DSCP values
    pub fn allocated_count(&self) -> usize {
        self.allocated
            .read()
            .map(|allocated| allocated.len())
            .unwrap_or(0)
    }

    /// Get the number of available DSCP values
    ///
    /// Returns the count of DSCP values that are neither allocated
    /// nor reserved for `QoS`.
    pub fn available_count(&self) -> usize {
        let total = (MAX_DSCP - MIN_DSCP + 1) as usize;
        let reserved = self.reserved.len();
        let allocated = self.allocated_count();

        // Some reserved values might be in the allocated set
        // (if manually reserved), so we need to be careful
        total.saturating_sub(reserved).saturating_sub(allocated)
            + self
                .allocated
                .read()
                .map(|alloc| alloc.iter().filter(|d| self.reserved.contains(d)).count())
                .unwrap_or(0)
    }

    /// Get all allocated DSCP values
    pub fn allocated_values(&self) -> Vec<u8> {
        self.allocated
            .read()
            .map(|allocated| allocated.iter().copied().collect())
            .unwrap_or_default()
    }
}

impl Default for DscpAllocator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allocate_sequential() {
        let allocator = DscpAllocator::new();

        // Should skip reserved values
        let dscp1 = allocator.allocate().unwrap();
        let dscp2 = allocator.allocate().unwrap();

        assert_ne!(dscp1, dscp2);
        assert!(!allocator.is_reserved(dscp1));
        assert!(!allocator.is_reserved(dscp2));
    }

    #[test]
    fn test_release_and_reallocate() {
        let allocator = DscpAllocator::new();

        let dscp = allocator.allocate().unwrap();
        allocator.release(dscp);

        // Should be able to allocate the same value again
        let dscp2 = allocator.allocate().unwrap();
        assert_eq!(dscp, dscp2);
    }

    #[test]
    fn test_reserve_specific() {
        let allocator = DscpAllocator::new();

        // Reserve a specific value
        allocator.reserve(42).unwrap();
        assert!(allocator.is_allocated(42));

        // Cannot reserve the same value again
        assert!(matches!(
            allocator.reserve(42),
            Err(DscpAllocatorError::AlreadyAllocated(42))
        ));
    }

    #[test]
    fn test_reserve_out_of_range() {
        let allocator = DscpAllocator::new();

        assert!(matches!(
            allocator.reserve(0),
            Err(DscpAllocatorError::OutOfRange(0))
        ));

        assert!(matches!(
            allocator.reserve(64),
            Err(DscpAllocatorError::OutOfRange(64))
        ));
    }

    #[test]
    fn test_reserved_values() {
        let allocator = DscpAllocator::new();

        // Check some known reserved values
        assert!(allocator.is_reserved(0)); // BE
        assert!(allocator.is_reserved(46)); // EF
        assert!(allocator.is_reserved(8)); // CS1

        // Non-reserved values
        assert!(!allocator.is_reserved(1));
        assert!(!allocator.is_reserved(42));
    }

    #[test]
    fn test_auto_allocate_skips_reserved() {
        let allocator = DscpAllocator::new();

        // Allocate many values and verify none are reserved
        for _ in 0..30 {
            let dscp = allocator.allocate().unwrap();
            assert!(
                !allocator.is_reserved(dscp),
                "Auto-allocated DSCP {} should not be reserved",
                dscp
            );
        }
    }

    #[test]
    fn test_manual_reserve_qos_value() {
        let allocator = DscpAllocator::new();

        // Manual reservation of QoS values should work
        // (user explicitly wants to use it)
        allocator.reserve(46).unwrap(); // EF
        assert!(allocator.is_allocated(46));
    }

    #[test]
    fn test_allocated_count() {
        let allocator = DscpAllocator::new();

        assert_eq!(allocator.allocated_count(), 0);

        allocator.allocate().unwrap();
        assert_eq!(allocator.allocated_count(), 1);

        allocator.allocate().unwrap();
        assert_eq!(allocator.allocated_count(), 2);
    }

    #[test]
    fn test_default() {
        let allocator = DscpAllocator::default();
        assert_eq!(allocator.allocated_count(), 0);
    }
}
