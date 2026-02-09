//! Buffer management for efficient I/O operations
//!
//! This module provides buffer allocation and pooling strategies
//! for zero-copy I/O where possible.

use bytes::{Bytes, BytesMut};

/// Default buffer size (64KB - optimal for most network operations)
pub const DEFAULT_BUFFER_SIZE: usize = 64 * 1024;

/// Minimum buffer size (4KB)
pub const MIN_BUFFER_SIZE: usize = 4 * 1024;

/// Maximum buffer size (1MB)
pub const MAX_BUFFER_SIZE: usize = 1024 * 1024;

/// I/O buffer for bidirectional copy operations
#[derive(Debug)]
pub struct IoBuffer {
    inner: BytesMut,
    capacity: usize,
}

impl IoBuffer {
    /// Create a new buffer with the specified capacity
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        let capacity = capacity.clamp(MIN_BUFFER_SIZE, MAX_BUFFER_SIZE);
        Self {
            inner: BytesMut::with_capacity(capacity),
            capacity,
        }
    }

    /// Create a new buffer with default capacity
    #[must_use]
    pub fn with_default_capacity() -> Self {
        Self::new(DEFAULT_BUFFER_SIZE)
    }

    /// Get a mutable reference to the underlying `BytesMut`
    #[must_use]
    pub fn as_mut(&mut self) -> &mut BytesMut {
        &mut self.inner
    }

    /// Get the buffer capacity
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Get the current length of data in the buffer
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Check if the buffer is empty
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Clear the buffer
    pub fn clear(&mut self) {
        self.inner.clear();
    }

    /// Reserve additional capacity
    pub fn reserve(&mut self, additional: usize) {
        self.inner.reserve(additional);
    }

    /// Split off the current data as frozen Bytes
    #[must_use]
    pub fn split(&mut self) -> Bytes {
        self.inner.split().freeze()
    }

    /// Get a slice of the underlying data
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.inner
    }

    /// Extend from a slice
    pub fn extend_from_slice(&mut self, data: &[u8]) {
        self.inner.extend_from_slice(data);
    }
}

impl Default for IoBuffer {
    fn default() -> Self {
        Self::with_default_capacity()
    }
}

impl AsRef<[u8]> for IoBuffer {
    fn as_ref(&self) -> &[u8] {
        &self.inner
    }
}

impl AsMut<[u8]> for IoBuffer {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.inner
    }
}

/// Statistics for buffer usage (for debugging/monitoring)
#[derive(Debug, Default, Clone)]
pub struct BufferStats {
    /// Total bytes read through this buffer
    pub bytes_read: u64,
    /// Total bytes written through this buffer
    pub bytes_written: u64,
    /// Number of read operations
    pub read_ops: u64,
    /// Number of write operations
    pub write_ops: u64,
}

impl BufferStats {
    /// Create new buffer stats
    #[must_use]
    pub const fn new() -> Self {
        Self {
            bytes_read: 0,
            bytes_written: 0,
            read_ops: 0,
            write_ops: 0,
        }
    }

    /// Record a read operation
    pub fn record_read(&mut self, bytes: usize) {
        self.bytes_read += bytes as u64;
        self.read_ops += 1;
    }

    /// Record a write operation
    pub fn record_write(&mut self, bytes: usize) {
        self.bytes_written += bytes as u64;
        self.write_ops += 1;
    }

    /// Get average read size
    #[must_use]
    pub fn avg_read_size(&self) -> f64 {
        if self.read_ops == 0 {
            0.0
        } else {
            self.bytes_read as f64 / self.read_ops as f64
        }
    }

    /// Get average write size
    #[must_use]
    pub fn avg_write_size(&self) -> f64 {
        if self.write_ops == 0 {
            0.0
        } else {
            self.bytes_written as f64 / self.write_ops as f64
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_buffer_creation() {
        let buf = IoBuffer::new(1024);
        assert_eq!(buf.capacity(), MIN_BUFFER_SIZE); // Clamped to min

        let buf = IoBuffer::new(DEFAULT_BUFFER_SIZE);
        assert_eq!(buf.capacity(), DEFAULT_BUFFER_SIZE);

        let buf = IoBuffer::with_default_capacity();
        assert_eq!(buf.capacity(), DEFAULT_BUFFER_SIZE);
    }

    #[test]
    fn test_buffer_capacity_clamping() {
        let buf = IoBuffer::new(100); // Below min
        assert_eq!(buf.capacity(), MIN_BUFFER_SIZE);

        let buf = IoBuffer::new(10 * 1024 * 1024); // Above max
        assert_eq!(buf.capacity(), MAX_BUFFER_SIZE);
    }

    #[test]
    fn test_buffer_operations() {
        let mut buf = IoBuffer::new(DEFAULT_BUFFER_SIZE);
        assert!(buf.is_empty());

        buf.extend_from_slice(b"hello");
        assert_eq!(buf.len(), 5);
        assert!(!buf.is_empty());

        buf.clear();
        assert!(buf.is_empty());
    }

    #[test]
    fn test_buffer_stats() {
        let mut stats = BufferStats::new();
        assert_eq!(stats.bytes_read, 0);

        stats.record_read(1024);
        stats.record_read(2048);
        assert_eq!(stats.bytes_read, 3072);
        assert_eq!(stats.read_ops, 2);
        assert!((stats.avg_read_size() - 1536.0).abs() < f64::EPSILON);

        stats.record_write(512);
        assert_eq!(stats.bytes_written, 512);
        assert_eq!(stats.write_ops, 1);
    }
}
