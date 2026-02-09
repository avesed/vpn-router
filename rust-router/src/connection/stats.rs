//! Connection statistics tracking
//!
//! This module provides statistics collection for connection management.

use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};

/// Atomic connection statistics
#[derive(Debug, Default)]
pub struct ConnectionStats {
    /// Total connections accepted
    total_accepted: AtomicU64,
    /// Currently active connections
    active: AtomicU64,
    /// Total connections completed successfully
    completed: AtomicU64,
    /// Total connections that errored
    errored: AtomicU64,
    /// Connections rejected due to limit
    rejected: AtomicU64,
    /// Total bytes received (client -> upstream)
    bytes_rx: AtomicU64,
    /// Total bytes transmitted (upstream -> client)
    bytes_tx: AtomicU64,
}

impl ConnectionStats {
    /// Create new connection statistics
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a new accepted connection
    pub fn record_accepted(&self) {
        self.total_accepted.fetch_add(1, Ordering::Relaxed);
        self.active.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a connection completion
    pub fn record_completed(&self, bytes_rx: u64, bytes_tx: u64) {
        self.active.fetch_sub(1, Ordering::Relaxed);
        self.completed.fetch_add(1, Ordering::Relaxed);
        self.bytes_rx.fetch_add(bytes_rx, Ordering::Relaxed);
        self.bytes_tx.fetch_add(bytes_tx, Ordering::Relaxed);
    }

    /// Record a connection error
    pub fn record_error(&self) {
        self.active.fetch_sub(1, Ordering::Relaxed);
        self.errored.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a rejected connection (due to limit)
    pub fn record_rejected(&self) {
        self.rejected.fetch_add(1, Ordering::Relaxed);
    }

    /// Get total accepted connections
    #[must_use]
    pub fn total_accepted(&self) -> u64 {
        self.total_accepted.load(Ordering::Relaxed)
    }

    /// Get currently active connections
    #[must_use]
    pub fn active(&self) -> u64 {
        self.active.load(Ordering::Relaxed)
    }

    /// Get completed connections
    #[must_use]
    pub fn completed(&self) -> u64 {
        self.completed.load(Ordering::Relaxed)
    }

    /// Get errored connections
    #[must_use]
    pub fn errored(&self) -> u64 {
        self.errored.load(Ordering::Relaxed)
    }

    /// Get rejected connections
    #[must_use]
    pub fn rejected(&self) -> u64 {
        self.rejected.load(Ordering::Relaxed)
    }

    /// Get total bytes received
    #[must_use]
    pub fn bytes_rx(&self) -> u64 {
        self.bytes_rx.load(Ordering::Relaxed)
    }

    /// Get total bytes transmitted
    #[must_use]
    pub fn bytes_tx(&self) -> u64 {
        self.bytes_tx.load(Ordering::Relaxed)
    }

    /// Get a snapshot of all statistics
    #[must_use]
    pub fn snapshot(&self) -> StatsSnapshot {
        StatsSnapshot {
            total_accepted: self.total_accepted(),
            active: self.active(),
            completed: self.completed(),
            errored: self.errored(),
            rejected: self.rejected(),
            bytes_rx: self.bytes_rx(),
            bytes_tx: self.bytes_tx(),
            timestamp_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
        }
    }

    /// Reset all statistics
    pub fn reset(&self) {
        self.total_accepted.store(0, Ordering::Relaxed);
        self.active.store(0, Ordering::Relaxed);
        self.completed.store(0, Ordering::Relaxed);
        self.errored.store(0, Ordering::Relaxed);
        self.rejected.store(0, Ordering::Relaxed);
        self.bytes_rx.store(0, Ordering::Relaxed);
        self.bytes_tx.store(0, Ordering::Relaxed);
    }
}

/// Snapshot of connection statistics at a point in time
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatsSnapshot {
    /// Total connections accepted
    pub total_accepted: u64,
    /// Currently active connections
    pub active: u64,
    /// Completed connections
    pub completed: u64,
    /// Errored connections
    pub errored: u64,
    /// Rejected connections
    pub rejected: u64,
    /// Total bytes received
    pub bytes_rx: u64,
    /// Total bytes transmitted
    pub bytes_tx: u64,
    /// Timestamp in milliseconds
    pub timestamp_ms: u64,
}

impl StatsSnapshot {
    /// Get total bytes transferred (both directions)
    #[must_use]
    pub const fn total_bytes(&self) -> u64 {
        self.bytes_rx + self.bytes_tx
    }

    /// Get success rate as a percentage (0-100)
    #[must_use]
    pub fn success_rate(&self) -> f64 {
        let total = self.completed + self.errored;
        if total == 0 {
            100.0
        } else {
            (self.completed as f64 / total as f64) * 100.0
        }
    }
}

/// Per-outbound statistics
#[derive(Debug, Default)]
pub struct OutboundStats {
    /// Total connections using this outbound
    connections: AtomicU64,
    /// Currently active connections
    active: AtomicU64,
    /// Total bytes received
    bytes_rx: AtomicU64,
    /// Total bytes transmitted
    bytes_tx: AtomicU64,
    /// Total errors
    errors: AtomicU64,
}

impl OutboundStats {
    /// Create new outbound statistics
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a new connection
    pub fn record_connection(&self) {
        self.connections.fetch_add(1, Ordering::Relaxed);
        self.active.fetch_add(1, Ordering::Relaxed);
    }

    /// Record connection completion
    pub fn record_completed(&self, bytes_rx: u64, bytes_tx: u64) {
        self.active.fetch_sub(1, Ordering::Relaxed);
        self.bytes_rx.fetch_add(bytes_rx, Ordering::Relaxed);
        self.bytes_tx.fetch_add(bytes_tx, Ordering::Relaxed);
    }

    /// Record an error
    pub fn record_error(&self) {
        self.active.fetch_sub(1, Ordering::Relaxed);
        self.errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Get total connections
    #[must_use]
    pub fn connections(&self) -> u64 {
        self.connections.load(Ordering::Relaxed)
    }

    /// Get active connections
    #[must_use]
    pub fn active(&self) -> u64 {
        self.active.load(Ordering::Relaxed)
    }

    /// Get total bytes received
    #[must_use]
    pub fn bytes_rx(&self) -> u64 {
        self.bytes_rx.load(Ordering::Relaxed)
    }

    /// Get total bytes transmitted
    #[must_use]
    pub fn bytes_tx(&self) -> u64 {
        self.bytes_tx.load(Ordering::Relaxed)
    }

    /// Get total errors
    #[must_use]
    pub fn errors(&self) -> u64 {
        self.errors.load(Ordering::Relaxed)
    }

    /// Get a snapshot
    #[must_use]
    pub fn snapshot(&self) -> OutboundStatsSnapshot {
        OutboundStatsSnapshot {
            connections: self.connections(),
            active: self.active(),
            bytes_rx: self.bytes_rx(),
            bytes_tx: self.bytes_tx(),
            errors: self.errors(),
        }
    }
}

/// Snapshot of outbound statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundStatsSnapshot {
    /// Total connections
    pub connections: u64,
    /// Active connections
    pub active: u64,
    /// Bytes received
    pub bytes_rx: u64,
    /// Bytes transmitted
    pub bytes_tx: u64,
    /// Errors
    pub errors: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_stats() {
        let stats = ConnectionStats::new();

        // Accept 3 connections
        stats.record_accepted();
        stats.record_accepted();
        stats.record_accepted();

        assert_eq!(stats.total_accepted(), 3);
        assert_eq!(stats.active(), 3);

        // Complete one with traffic
        stats.record_completed(1000, 2000);
        assert_eq!(stats.active(), 2);
        assert_eq!(stats.completed(), 1);
        assert_eq!(stats.bytes_rx(), 1000);
        assert_eq!(stats.bytes_tx(), 2000);

        // Error one
        stats.record_error();
        assert_eq!(stats.active(), 1);
        assert_eq!(stats.errored(), 1);

        // Reject one
        stats.record_rejected();
        assert_eq!(stats.rejected(), 1);
    }

    #[test]
    fn test_stats_snapshot() {
        let stats = ConnectionStats::new();
        stats.record_accepted();
        stats.record_completed(100, 200);

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.total_accepted, 1);
        assert_eq!(snapshot.completed, 1);
        assert_eq!(snapshot.total_bytes(), 300);
    }

    #[test]
    fn test_success_rate() {
        let mut snapshot = StatsSnapshot {
            total_accepted: 0,
            active: 0,
            completed: 0,
            errored: 0,
            rejected: 0,
            bytes_rx: 0,
            bytes_tx: 0,
            timestamp_ms: 0,
        };

        // No connections yet
        assert!((snapshot.success_rate() - 100.0).abs() < f64::EPSILON);

        // 80% success
        snapshot.completed = 80;
        snapshot.errored = 20;
        assert!((snapshot.success_rate() - 80.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_outbound_stats() {
        let stats = OutboundStats::new();

        stats.record_connection();
        assert_eq!(stats.connections(), 1);
        assert_eq!(stats.active(), 1);

        stats.record_completed(500, 1000);
        assert_eq!(stats.active(), 0);
        assert_eq!(stats.bytes_rx(), 500);
        assert_eq!(stats.bytes_tx(), 1000);
    }

    #[test]
    fn test_stats_reset() {
        let stats = ConnectionStats::new();
        stats.record_accepted();
        stats.record_completed(100, 200);

        stats.reset();

        assert_eq!(stats.total_accepted(), 0);
        assert_eq!(stats.completed(), 0);
        assert_eq!(stats.bytes_rx(), 0);
    }
}
