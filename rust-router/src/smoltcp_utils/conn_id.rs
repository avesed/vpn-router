//! Connection ID allocator for unique session identification
//!
//! This module provides a globally unique connection ID system optimized for
//! multi-shard bridge architectures. Each ID is a 64-bit value that can optionally
//! encode a shard index in the high 16 bits.
//!
//! # ID Layout
//!
//! ```text
//! Without shard (global allocator):
//! +----------------------------------------------------------------+
//! |                         64-bit sequence                         |
//! +----------------------------------------------------------------+
//!
//! With shard (per-shard allocator):
//! +----------------+------------------------------------------------+
//! | 16-bit shard   |              48-bit sequence                    |
//! +----------------+------------------------------------------------+
//! ```
//!
//! # Usage
//!
//! ```ignore
//! use rust_router::smoltcp_utils::conn_id::{ConnIdAllocator, ConnId};
//!
//! // Global allocator (no shard encoding)
//! let global_alloc = ConnIdAllocator::new();
//! let id1 = global_alloc.next();
//! let id2 = global_alloc.next();
//! assert!(id2.sequence() > id1.sequence());
//!
//! // Per-shard allocator
//! let shard_alloc = ConnIdAllocator::with_shard(5);
//! let id = shard_alloc.next();
//! assert_eq!(id.shard_index(), Some(5));
//! ```
//!
//! # Thread Safety
//!
//! `ConnIdAllocator` uses `AtomicU64` for lock-free, thread-safe allocation.
//! Multiple threads can safely call `next()` concurrently.

use std::sync::atomic::{AtomicU64, Ordering};

/// Number of bits reserved for the shard index
const SHARD_BITS: u32 = 16;

/// Number of bits for the sequence number
const SEQUENCE_BITS: u32 = 64 - SHARD_BITS;

/// Mask for extracting the sequence number (48 bits)
const SEQUENCE_MASK: u64 = (1 << SEQUENCE_BITS) - 1;

/// Mask for extracting the shard index (high 16 bits)
const SHARD_MASK: u64 = !SEQUENCE_MASK;

/// Maximum sequence value before wrapping (2^48 - 1)
const MAX_SEQUENCE: u64 = SEQUENCE_MASK;

/// Unique identifier for a connection/session
///
/// A 64-bit value that can optionally encode a shard index in the high 16 bits.
/// When created without a shard, the entire 64 bits are used for the sequence.
///
/// # Properties
///
/// - `Copy` and `Clone`: IDs are cheap to copy
/// - `Eq` and `Hash`: Can be used as map keys
/// - `Ord`: Sortable by raw value (shard-aware ordering)
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ConnId(u64);

impl ConnId {
    /// Create a connection ID from a raw 64-bit value
    #[must_use]
    pub const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    /// Get the raw 64-bit value
    #[must_use]
    pub const fn raw(&self) -> u64 {
        self.0
    }

    /// Create a connection ID with a specific shard index and sequence
    ///
    /// # Panics
    ///
    /// Panics in debug builds if sequence exceeds 48 bits.
    #[must_use]
    pub const fn with_shard_and_sequence(shard_index: u16, sequence: u64) -> Self {
        debug_assert!(
            sequence <= MAX_SEQUENCE,
            "sequence exceeds 48-bit limit"
        );
        let raw = ((shard_index as u64) << SEQUENCE_BITS) | (sequence & SEQUENCE_MASK);
        Self(raw)
    }

    /// Get the shard index if this ID was created with one
    ///
    /// Returns `Some(shard_index)` if the high 16 bits are non-zero,
    /// `None` otherwise. Note that shard index 0 is indistinguishable
    /// from a global ID.
    #[must_use]
    pub const fn shard_index(&self) -> Option<u16> {
        let shard = ((self.0 & SHARD_MASK) >> SEQUENCE_BITS) as u16;
        if shard == 0 {
            None
        } else {
            Some(shard)
        }
    }

    /// Get the shard index, returning 0 if not set
    #[must_use]
    pub const fn shard_index_or_zero(&self) -> u16 {
        ((self.0 & SHARD_MASK) >> SEQUENCE_BITS) as u16
    }

    /// Get the sequence number portion (low 48 bits for sharded IDs)
    ///
    /// For global IDs (no shard), this returns the full 64-bit value.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.0 & SEQUENCE_MASK
    }

    /// Check if this ID has a shard index encoded
    #[must_use]
    pub const fn has_shard(&self) -> bool {
        (self.0 & SHARD_MASK) != 0
    }
}

impl std::fmt::Debug for ConnId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(shard) = self.shard_index() {
            write!(f, "ConnId(shard={}, seq={})", shard, self.sequence())
        } else {
            write!(f, "ConnId({})", self.0)
        }
    }
}

impl std::fmt::Display for ConnId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(shard) = self.shard_index() {
            write!(f, "s{}-{}", shard, self.sequence())
        } else {
            write!(f, "c{}", self.0)
        }
    }
}

/// Thread-safe allocator for connection IDs
///
/// Can operate in two modes:
/// 1. **Global mode**: Creates IDs using the full 64-bit space
/// 2. **Shard mode**: Encodes a shard index in the high 16 bits
///
/// # Example
///
/// ```ignore
/// // Create allocators for different shards
/// let alloc_shard_1 = ConnIdAllocator::with_shard(1);
/// let alloc_shard_2 = ConnIdAllocator::with_shard(2);
///
/// // IDs from different shards are always unique
/// let id1 = alloc_shard_1.next();
/// let id2 = alloc_shard_2.next();
/// assert_ne!(id1, id2);
///
/// // Can identify which shard generated the ID
/// assert_eq!(id1.shard_index(), Some(1));
/// assert_eq!(id2.shard_index(), Some(2));
/// ```
pub struct ConnIdAllocator {
    /// Next sequence number (low 48 bits when sharded)
    next_seq: AtomicU64,
    /// Optional shard index (None for global allocator)
    shard_index: Option<u16>,
}

impl ConnIdAllocator {
    /// Create a global allocator (no shard encoding)
    ///
    /// IDs will use the full 64-bit space for the sequence number.
    #[must_use]
    pub fn new() -> Self {
        Self {
            next_seq: AtomicU64::new(1), // Start at 1, reserve 0 for "no ID"
            shard_index: None,
        }
    }

    /// Create a shard-specific allocator
    ///
    /// IDs will have the shard index encoded in the high 16 bits.
    ///
    /// # Note
    ///
    /// Using `shard_index = 0` is valid but the resulting IDs will be
    /// indistinguishable from global IDs when calling `shard_index()`.
    #[must_use]
    pub fn with_shard(shard_index: u16) -> Self {
        Self {
            next_seq: AtomicU64::new(1), // Start at 1
            shard_index: Some(shard_index),
        }
    }

    /// Allocate the next connection ID
    ///
    /// This operation is lock-free and thread-safe. The sequence number
    /// will wrap around after reaching the maximum value (2^48 - 1 for
    /// sharded allocators, 2^64 - 1 for global allocators).
    #[must_use]
    pub fn next(&self) -> ConnId {
        let seq = self.next_seq.fetch_add(1, Ordering::Relaxed);

        match self.shard_index {
            Some(shard) => {
                // Wrap sequence at 48 bits
                let seq = seq & SEQUENCE_MASK;
                ConnId::with_shard_and_sequence(shard, seq)
            }
            None => {
                // Use full 64-bit space
                ConnId::from_raw(seq)
            }
        }
    }

    /// Get the current allocation count (for debugging)
    ///
    /// Returns the number of IDs that have been allocated.
    /// Note: Due to concurrent access, this may be slightly stale.
    #[must_use]
    pub fn current_count(&self) -> u64 {
        self.next_seq.load(Ordering::Relaxed).saturating_sub(1)
    }

    /// Check if this allocator encodes shard indices
    #[must_use]
    pub fn is_sharded(&self) -> bool {
        self.shard_index.is_some()
    }

    /// Get the shard index for this allocator
    #[must_use]
    pub fn shard(&self) -> Option<u16> {
        self.shard_index
    }
}

impl Default for ConnIdAllocator {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for ConnIdAllocator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnIdAllocator")
            .field("shard_index", &self.shard_index)
            .field("allocated", &self.current_count())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn test_connection_id_from_raw() {
        let id = ConnId::from_raw(12345);
        assert_eq!(id.raw(), 12345);
    }

    #[test]
    fn test_connection_id_with_shard() {
        let id = ConnId::with_shard_and_sequence(5, 1000);
        assert_eq!(id.shard_index(), Some(5));
        assert_eq!(id.sequence(), 1000);
        assert!(id.has_shard());
    }

    #[test]
    fn test_connection_id_without_shard() {
        let id = ConnId::from_raw(12345);
        assert_eq!(id.shard_index(), None);
        assert_eq!(id.sequence(), 12345);
        assert!(!id.has_shard());
    }

    #[test]
    fn test_connection_id_shard_zero() {
        // Shard 0 is indistinguishable from global
        let id = ConnId::with_shard_and_sequence(0, 1000);
        assert_eq!(id.shard_index(), None);
        assert_eq!(id.shard_index_or_zero(), 0);
        assert_eq!(id.sequence(), 1000);
    }

    #[test]
    fn test_connection_id_display_with_shard() {
        let id = ConnId::with_shard_and_sequence(3, 42);
        let s = id.to_string();
        assert_eq!(s, "s3-42");
    }

    #[test]
    fn test_connection_id_display_without_shard() {
        let id = ConnId::from_raw(999);
        let s = id.to_string();
        assert_eq!(s, "c999");
    }

    #[test]
    fn test_connection_id_debug_with_shard() {
        let id = ConnId::with_shard_and_sequence(7, 123);
        let s = format!("{:?}", id);
        assert!(s.contains("shard=7"));
        assert!(s.contains("seq=123"));
    }

    #[test]
    fn test_connection_id_debug_without_shard() {
        let id = ConnId::from_raw(456);
        let s = format!("{:?}", id);
        assert!(s.contains("456"));
    }

    #[test]
    fn test_connection_id_eq_hash() {
        let id1 = ConnId::from_raw(100);
        let id2 = ConnId::from_raw(100);
        let id3 = ConnId::from_raw(200);

        assert_eq!(id1, id2);
        assert_ne!(id1, id3);

        // Test hashing
        let mut set = HashSet::new();
        set.insert(id1);
        assert!(set.contains(&id2));
        assert!(!set.contains(&id3));
    }

    #[test]
    fn test_connection_id_ordering() {
        let id1 = ConnId::with_shard_and_sequence(1, 100);
        let id2 = ConnId::with_shard_and_sequence(1, 200);
        let id3 = ConnId::with_shard_and_sequence(2, 50);

        // Same shard, different sequence
        assert!(id1 < id2);

        // Different shard (higher shard = higher ID)
        assert!(id2 < id3);
    }

    #[test]
    fn test_allocator_global_monotonic() {
        let alloc = ConnIdAllocator::new();

        let id1 = alloc.next();
        let id2 = alloc.next();
        let id3 = alloc.next();

        assert!(id1.raw() < id2.raw());
        assert!(id2.raw() < id3.raw());
        assert_eq!(alloc.current_count(), 3);
    }

    #[test]
    fn test_allocator_starts_at_one() {
        let alloc = ConnIdAllocator::new();
        let id = alloc.next();
        assert_eq!(id.raw(), 1); // 0 is reserved
    }

    #[test]
    fn test_allocator_sharded_monotonic() {
        let alloc = ConnIdAllocator::with_shard(5);

        let id1 = alloc.next();
        let id2 = alloc.next();

        assert_eq!(id1.shard_index(), Some(5));
        assert_eq!(id2.shard_index(), Some(5));
        assert!(id1.sequence() < id2.sequence());
    }

    #[test]
    fn test_allocator_different_shards_unique() {
        let alloc1 = ConnIdAllocator::with_shard(1);
        let alloc2 = ConnIdAllocator::with_shard(2);

        let id1 = alloc1.next();
        let id2 = alloc2.next();

        // Same sequence number but different shards
        assert_eq!(id1.sequence(), 1);
        assert_eq!(id2.sequence(), 1);

        // But IDs are different
        assert_ne!(id1, id2);
        assert_ne!(id1.raw(), id2.raw());
    }

    #[test]
    fn test_allocator_multithreaded_uniqueness() {
        const NUM_THREADS: usize = 8;
        const IDS_PER_THREAD: usize = 1000;

        let alloc = Arc::new(ConnIdAllocator::new());
        let mut handles = Vec::new();

        for _ in 0..NUM_THREADS {
            let alloc = Arc::clone(&alloc);
            handles.push(thread::spawn(move || {
                let mut ids = Vec::with_capacity(IDS_PER_THREAD);
                for _ in 0..IDS_PER_THREAD {
                    ids.push(alloc.next());
                }
                ids
            }));
        }

        let mut all_ids = HashSet::new();
        for handle in handles {
            let ids = handle.join().expect("thread panicked");
            for id in ids {
                assert!(all_ids.insert(id), "duplicate ID: {:?}", id);
            }
        }

        assert_eq!(all_ids.len(), NUM_THREADS * IDS_PER_THREAD);
    }

    #[test]
    fn test_allocator_multithreaded_sharded() {
        const NUM_SHARDS: u16 = 4;
        const IDS_PER_SHARD: usize = 500;

        let allocators: Vec<Arc<ConnIdAllocator>> = (1..=NUM_SHARDS)
            .map(|i| Arc::new(ConnIdAllocator::with_shard(i)))
            .collect();

        let mut handles = Vec::new();

        for alloc in allocators {
            let alloc = Arc::clone(&alloc);
            handles.push(thread::spawn(move || {
                let mut ids = Vec::with_capacity(IDS_PER_SHARD);
                for _ in 0..IDS_PER_SHARD {
                    ids.push(alloc.next());
                }
                ids
            }));
        }

        let mut all_ids = HashSet::new();
        for handle in handles {
            let ids = handle.join().expect("thread panicked");
            for id in ids {
                assert!(all_ids.insert(id), "duplicate ID: {:?}", id);
            }
        }

        assert_eq!(all_ids.len(), (NUM_SHARDS as usize) * IDS_PER_SHARD);
    }

    #[test]
    fn test_allocator_is_sharded() {
        let global = ConnIdAllocator::new();
        let sharded = ConnIdAllocator::with_shard(1);

        assert!(!global.is_sharded());
        assert!(sharded.is_sharded());
    }

    #[test]
    fn test_allocator_shard_getter() {
        let global = ConnIdAllocator::new();
        let sharded = ConnIdAllocator::with_shard(42);

        assert_eq!(global.shard(), None);
        assert_eq!(sharded.shard(), Some(42));
    }

    #[test]
    fn test_allocator_debug() {
        let alloc = ConnIdAllocator::with_shard(3);
        let _ = alloc.next();
        let _ = alloc.next();

        let s = format!("{:?}", alloc);
        assert!(s.contains("shard_index: Some(3)"));
        assert!(s.contains("allocated: 2"));
    }

    #[test]
    fn test_allocator_default() {
        let alloc = ConnIdAllocator::default();
        assert!(!alloc.is_sharded());
    }

    #[test]
    fn test_sequence_mask_values() {
        // Verify our constants are correct
        assert_eq!(SHARD_BITS, 16);
        assert_eq!(SEQUENCE_BITS, 48);
        assert_eq!(SEQUENCE_MASK, 0x0000_FFFF_FFFF_FFFF);
        assert_eq!(SHARD_MASK, 0xFFFF_0000_0000_0000);
        assert_eq!(MAX_SEQUENCE, 0x0000_FFFF_FFFF_FFFF);
    }

    #[test]
    fn test_shard_encoding() {
        // Test that shard is properly encoded in high bits
        let id = ConnId::with_shard_and_sequence(0xABCD, 0x1234_5678_9ABC);

        // Raw value should have shard in high 16 bits
        let raw = id.raw();
        assert_eq!((raw >> SEQUENCE_BITS) as u16, 0xABCD);
        assert_eq!(raw & SEQUENCE_MASK, 0x1234_5678_9ABC);
    }

    #[test]
    fn test_sequence_wrap_for_sharded() {
        // When sequence wraps at 48 bits, it should stay within bounds
        let alloc = ConnIdAllocator::with_shard(1);

        // Simulate near-max sequence
        alloc
            .next_seq
            .store(MAX_SEQUENCE, Ordering::Relaxed);
        let id = alloc.next();

        // Sequence should be MAX_SEQUENCE
        assert_eq!(id.sequence(), MAX_SEQUENCE);

        // Next one wraps to 0
        let id_wrapped = alloc.next();
        assert_eq!(id_wrapped.sequence(), 0);

        // Shard should still be correct
        assert_eq!(id_wrapped.shard_index(), Some(1));
    }

    #[test]
    fn test_connection_id_copy() {
        let id = ConnId::from_raw(42);
        let id_copy = id; // Copy
        assert_eq!(id, id_copy);
    }

    #[test]
    fn test_max_shard_value() {
        let id = ConnId::with_shard_and_sequence(u16::MAX, 1);
        assert_eq!(id.shard_index(), Some(u16::MAX));
    }

    #[test]
    fn test_zero_id_reserved() {
        // Allocator starts at 1, so 0 can be used as "no ID" sentinel
        let global = ConnIdAllocator::new();
        let sharded = ConnIdAllocator::with_shard(1);

        let id1 = global.next();
        let id2 = sharded.next();

        assert_ne!(id1.raw(), 0);
        assert_ne!(id2.sequence(), 0);
    }
}
