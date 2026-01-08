//! DNS query logging module
//!
//! This module provides async non-blocking query logging with batch writes
//! and automatic log rotation. It is designed to have zero impact on DNS
//! query latency.
//!
//! # Features
//!
//! - **Non-blocking writes**: Uses mpsc channel with `try_send` for zero-latency logging
//! - **Batch writes**: Flushes after 1000 entries OR 1 second (whichever comes first)
//! - **Multiple formats**: JSON, TSV, and Binary (bincode) formats
//! - **Automatic rotation**: Time-based rotation with configurable retention
//! - **Atomic statistics**: Track logged entries, dropped entries, bytes written
//!
//! # Architecture
//!
//! ```text
//! DNS Handler
//!     |
//!     | try_send (non-blocking)
//!     v
//! +------------------+
//! | mpsc Channel     | ---- Full? ----> Entry Dropped (stats incremented)
//! | (10K buffer)     |
//! +------------------+
//!     |
//!     | recv_many (batch)
//!     v
//! +------------------+
//! |   Log Writer     | ---- Format ----> JSON/TSV/Binary
//! +------------------+
//!     |
//!     v
//! +------------------+
//! |   LogRotator     | ---- Rotate ----> dns-queries.log.1, .2, etc.
//! +------------------+
//!     |
//!     v
//!   File (async write)
//! ```
//!
//! # Example
//!
//! ```no_run
//! use rust_router::dns::log::{QueryLogger, QueryLogEntry};
//! use rust_router::dns::LoggingConfig;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create logger from config
//! let config = LoggingConfig::default().enabled();
//! let logger = QueryLogger::new(config)?;
//!
//! // Log a query (non-blocking, returns immediately)
//! let entry = QueryLogEntry::new("example.com", 1)
//!     .with_upstream("cloudflare")
//!     .with_latency_us(1500)
//!     .with_response_code(0);
//! logger.log(entry);
//!
//! // Graceful shutdown
//! logger.shutdown().await;
//! # Ok(())
//! # }
//! ```
//!
//! # Performance
//!
//! - Entry creation: < 100ns
//! - Channel send: < 50ns (try_send)
//! - No impact on DNS query latency
//! - Memory: ~5MB for 10K entry buffer (configurable)
//!
//! # Thread Safety
//!
//! `QueryLogger` is fully thread-safe and can be shared across tasks
//! via `Arc<QueryLogger>`. The underlying channel handles synchronization.

mod rotation;
mod writer;

pub use rotation::{LogRotator, RotationStats, RotationStatsSnapshot};
pub use writer::{LogStats, LogStatsSnapshot, QueryLogEntry, QueryLogger};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_exports() {
        // Verify all public types are accessible
        let entry = QueryLogEntry::new("example.com", 1);
        assert_eq!(entry.domain, "example.com");
        assert_eq!(entry.qtype, 1);
    }

    #[test]
    fn test_query_log_entry_creation() {
        let entry = QueryLogEntry::new("test.example.com", 28)
            .with_upstream("google")
            .with_latency_us(2500)
            .with_response_code(0)
            .with_blocked(true)
            .with_cached(false);

        assert_eq!(entry.domain, "test.example.com");
        assert_eq!(entry.qtype, 28);
        assert_eq!(entry.upstream, "google");
        assert_eq!(entry.latency_us, 2500);
        assert_eq!(entry.response_code, 0);
        assert!(entry.blocked);
        assert!(!entry.cached);
    }

    #[test]
    fn test_log_stats_snapshot() {
        let snapshot = LogStatsSnapshot::default();
        assert_eq!(snapshot.entries_logged, 0);
        assert_eq!(snapshot.entries_dropped, 0);
        assert_eq!(snapshot.bytes_written, 0);
        assert_eq!(snapshot.batches_written, 0);
    }

    #[test]
    fn test_rotation_stats_snapshot() {
        let snapshot = RotationStatsSnapshot::default();
        assert_eq!(snapshot.rotations_performed, 0);
        assert_eq!(snapshot.files_deleted, 0);
    }

    #[test]
    fn test_query_log_entry_defaults() {
        let entry = QueryLogEntry::new("domain.com", 1);
        assert!(entry.timestamp > 0);
        assert_eq!(entry.upstream, "");
        assert_eq!(entry.response_code, 0);
        assert_eq!(entry.latency_us, 0);
        assert!(!entry.blocked);
        assert!(!entry.cached);
    }

    #[test]
    fn test_query_log_entry_builder_chain() {
        let entry = QueryLogEntry::new("chain.test", 5)
            .with_upstream("upstream1")
            .with_latency_us(100)
            .with_response_code(3)
            .with_blocked(false)
            .with_cached(true);

        assert_eq!(entry.domain, "chain.test");
        assert_eq!(entry.qtype, 5);
        assert_eq!(entry.upstream, "upstream1");
        assert_eq!(entry.latency_us, 100);
        assert_eq!(entry.response_code, 3);
        assert!(!entry.blocked);
        assert!(entry.cached);
    }
}
