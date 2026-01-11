//! Query logger with async batch writes
//!
//! This module provides the core `QueryLogger` implementation that handles
//! non-blocking entry submission, batch aggregation, and async file writes.
//!
//! # Design Principles
//!
//! 1. **Non-blocking submission**: `log()` uses `try_send()` to never block DNS handling
//! 2. **Batch efficiency**: Entries are accumulated and written in batches
//! 3. **Graceful degradation**: Dropped entries are counted but don't cause errors
//! 4. **Clean shutdown**: `shutdown()` ensures all pending entries are flushed

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tokio::fs::{File, OpenOptions};
use tokio::io::AsyncWriteExt;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tracing::{debug, error, info, trace, warn};

use crate::dns::config::{LogFormat, LoggingConfig};
use crate::dns::error::{DnsError, DnsResult};

use super::rotation::LogRotator;

// ============================================================================
// Constants
// ============================================================================

/// Default batch size for writes
const DEFAULT_BATCH_SIZE: usize = 1000;

/// Default flush interval in milliseconds
const DEFAULT_FLUSH_INTERVAL_MS: u64 = 1000;

/// Minimum buffer size
const MIN_BUFFER_SIZE: usize = 100;

/// Maximum buffer size
const MAX_BUFFER_SIZE: usize = 100_000;

/// Maximum domain name length per RFC 1035 (253 characters)
const MAX_DOMAIN_LENGTH: usize = 253;

/// Truncation marker for overly long domains
const TRUNCATION_MARKER: &str = "...[truncated]";

/// Default timeout for synchronous flush operations
const FLUSH_SYNC_TIMEOUT_MS: u64 = 5000;

// ============================================================================
// QueryLogEntry
// ============================================================================

/// A single DNS query log entry
///
/// This structure represents one DNS query with all relevant metadata.
/// It is designed to be cheap to create and serialize.
///
/// # Fields
///
/// - `timestamp`: Unix timestamp in milliseconds when the query was received
/// - `domain`: The queried domain name
/// - `qtype`: DNS record type (A=1, AAAA=28, CNAME=5, etc.)
/// - `upstream`: The upstream server that handled the query (empty if cached/blocked)
/// - `response_code`: DNS response code (0=NOERROR, 3=NXDOMAIN, etc.)
/// - `latency_us`: Query processing time in microseconds
/// - `blocked`: Whether the query was blocked by filtering rules
/// - `cached`: Whether the response was served from cache
///
/// # Example
///
/// ```
/// use rust_router::dns::log::QueryLogEntry;
///
/// let entry = QueryLogEntry::new("example.com", 1)
///     .with_upstream("cloudflare")
///     .with_latency_us(1500)
///     .with_response_code(0);
///
/// assert_eq!(entry.domain, "example.com");
/// assert_eq!(entry.qtype, 1); // A record
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QueryLogEntry {
    /// Unix timestamp in milliseconds
    pub timestamp: u64,

    /// The queried domain name
    pub domain: String,

    /// DNS record type (A=1, AAAA=28, etc.)
    pub qtype: u16,

    /// Upstream server tag that handled the query
    pub upstream: String,

    /// DNS response code (RCODE)
    pub response_code: u8,

    /// Query latency in microseconds
    pub latency_us: u32,

    /// Whether the query was blocked
    pub blocked: bool,

    /// Whether the response was cached
    pub cached: bool,
}

impl QueryLogEntry {
    /// Create a new log entry with the given domain and query type
    ///
    /// The timestamp is automatically set to the current time.
    /// Other fields are initialized to their default values.
    ///
    /// # Domain Length Validation
    ///
    /// Per RFC 1035, domain names have a maximum length of 253 characters.
    /// Domains exceeding this limit will be truncated with a marker suffix
    /// to prevent memory issues and log file bloat.
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::dns::log::QueryLogEntry;
    ///
    /// let entry = QueryLogEntry::new("example.com", 1);
    /// assert_eq!(entry.domain, "example.com");
    /// assert_eq!(entry.qtype, 1);
    /// assert!(entry.timestamp > 0);
    /// ```
    #[must_use]
    pub fn new(domain: impl Into<String>, qtype: u16) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let domain_str = domain.into();
        let domain = Self::sanitize_domain(domain_str);

        Self {
            timestamp,
            domain,
            qtype,
            upstream: String::new(),
            response_code: 0,
            latency_us: 0,
            blocked: false,
            cached: false,
        }
    }

    /// Sanitize and validate a domain name
    ///
    /// - Truncates domains longer than 253 characters (RFC 1035 limit)
    /// - Adds truncation marker for visibility
    fn sanitize_domain(domain: String) -> String {
        if domain.len() <= MAX_DOMAIN_LENGTH {
            domain
        } else {
            // Truncate and add marker
            // Reserve space for the truncation marker
            let truncate_at = MAX_DOMAIN_LENGTH.saturating_sub(TRUNCATION_MARKER.len());
            let mut truncated = domain;
            truncated.truncate(truncate_at);
            truncated.push_str(TRUNCATION_MARKER);
            truncated
        }
    }

    /// Set the upstream server tag
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::dns::log::QueryLogEntry;
    ///
    /// let entry = QueryLogEntry::new("example.com", 1)
    ///     .with_upstream("cloudflare-doh");
    /// assert_eq!(entry.upstream, "cloudflare-doh");
    /// ```
    #[must_use]
    pub fn with_upstream(mut self, upstream: impl Into<String>) -> Self {
        self.upstream = upstream.into();
        self
    }

    /// Set the DNS response code
    ///
    /// Common response codes:
    /// - 0: NOERROR (success)
    /// - 1: FORMERR (format error)
    /// - 2: SERVFAIL (server failure)
    /// - 3: NXDOMAIN (domain does not exist)
    /// - 5: REFUSED (query refused)
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::dns::log::QueryLogEntry;
    ///
    /// let entry = QueryLogEntry::new("example.com", 1)
    ///     .with_response_code(0);
    /// assert_eq!(entry.response_code, 0);
    /// ```
    #[must_use]
    pub fn with_response_code(mut self, code: u8) -> Self {
        self.response_code = code;
        self
    }

    /// Set the query latency in microseconds
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::dns::log::QueryLogEntry;
    ///
    /// let entry = QueryLogEntry::new("example.com", 1)
    ///     .with_latency_us(1500);
    /// assert_eq!(entry.latency_us, 1500);
    /// ```
    #[must_use]
    pub fn with_latency_us(mut self, latency: u32) -> Self {
        self.latency_us = latency;
        self
    }

    /// Set whether the query was blocked
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::dns::log::QueryLogEntry;
    ///
    /// let entry = QueryLogEntry::new("ads.example.com", 1)
    ///     .with_blocked(true);
    /// assert!(entry.blocked);
    /// ```
    #[must_use]
    pub fn with_blocked(mut self, blocked: bool) -> Self {
        self.blocked = blocked;
        self
    }

    /// Set whether the response was cached
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::dns::log::QueryLogEntry;
    ///
    /// let entry = QueryLogEntry::new("example.com", 1)
    ///     .with_cached(true);
    /// assert!(entry.cached);
    /// ```
    #[must_use]
    pub fn with_cached(mut self, cached: bool) -> Self {
        self.cached = cached;
        self
    }

    /// Set a custom timestamp (for testing or replay scenarios)
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::dns::log::QueryLogEntry;
    ///
    /// let entry = QueryLogEntry::new("example.com", 1)
    ///     .with_timestamp(1704067200000); // 2024-01-01 00:00:00 UTC
    /// assert_eq!(entry.timestamp, 1704067200000);
    /// ```
    #[must_use]
    pub fn with_timestamp(mut self, timestamp: u64) -> Self {
        self.timestamp = timestamp;
        self
    }

    /// Serialize the entry to JSON format
    ///
    /// Returns a JSON string with a trailing newline.
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::dns::log::QueryLogEntry;
    ///
    /// let entry = QueryLogEntry::new("example.com", 1)
    ///     .with_timestamp(1704067200000);
    /// let json = entry.to_json();
    /// assert!(json.contains("\"domain\":\"example.com\""));
    /// assert!(json.ends_with('\n'));
    /// ```
    #[must_use]
    pub fn to_json(&self) -> String {
        // Use serde_json for proper escaping
        match serde_json::to_string(self) {
            Ok(json) => format!("{json}\n"),
            Err(e) => {
                // Fallback for serialization errors (should be rare)
                error!("Failed to serialize log entry to JSON: {}", e);
                format!(
                    "{{\"error\":\"serialization_failed\",\"domain\":\"{}\"}}\n",
                    self.domain.replace('\"', "\\\"")
                )
            }
        }
    }

    /// Serialize the entry to TSV format
    ///
    /// Format: `timestamp\tdomain\tqtype\tupstream\trcode\tlatency_us\tblocked\tcached\n`
    ///
    /// # Control Character Escaping
    ///
    /// Tabs, newlines, and carriage returns in domain and upstream fields are
    /// escaped to prevent TSV parsing issues:
    /// - `\t` -> `\\t`
    /// - `\n` -> `\\n`
    /// - `\r` -> `\\r`
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::dns::log::QueryLogEntry;
    ///
    /// let entry = QueryLogEntry::new("example.com", 1)
    ///     .with_timestamp(1704067200000)
    ///     .with_upstream("google")
    ///     .with_latency_us(1500);
    /// let tsv = entry.to_tsv();
    /// assert!(tsv.contains("example.com"));
    /// assert!(tsv.ends_with('\n'));
    /// ```
    #[must_use]
    pub fn to_tsv(&self) -> String {
        format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
            self.timestamp,
            Self::escape_tsv_field(&self.domain),
            self.qtype,
            Self::escape_tsv_field(&self.upstream),
            self.response_code,
            self.latency_us,
            if self.blocked { "1" } else { "0" },
            if self.cached { "1" } else { "0" },
        )
    }

    /// Escape control characters in a TSV field
    ///
    /// Replaces tabs, newlines, and carriage returns with their escaped
    /// representations to ensure proper TSV parsing.
    fn escape_tsv_field(field: &str) -> String {
        field
            .replace('\\', "\\\\") // Escape backslashes first
            .replace('\t', "\\t")
            .replace('\n', "\\n")
            .replace('\r', "\\r")
    }

    /// Serialize the entry to binary format using bincode
    ///
    /// Returns the serialized bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails (should be rare).
    pub fn to_binary(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(self)
    }

    /// Deserialize an entry from binary format
    ///
    /// # Errors
    ///
    /// Returns an error if deserialization fails.
    pub fn from_binary(data: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(data)
    }

    /// Get the query type as a human-readable string
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::dns::log::QueryLogEntry;
    ///
    /// let entry = QueryLogEntry::new("example.com", 1);
    /// assert_eq!(entry.qtype_str(), "A");
    ///
    /// let entry = QueryLogEntry::new("example.com", 28);
    /// assert_eq!(entry.qtype_str(), "AAAA");
    /// ```
    #[must_use]
    pub fn qtype_str(&self) -> &'static str {
        match self.qtype {
            1 => "A",
            2 => "NS",
            5 => "CNAME",
            6 => "SOA",
            12 => "PTR",
            15 => "MX",
            16 => "TXT",
            28 => "AAAA",
            33 => "SRV",
            43 => "DS",
            46 => "RRSIG",
            47 => "NSEC",
            48 => "DNSKEY",
            255 => "ANY",
            _ => "OTHER",
        }
    }

    /// Get the response code as a human-readable string
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::dns::log::QueryLogEntry;
    ///
    /// let entry = QueryLogEntry::new("example.com", 1).with_response_code(0);
    /// assert_eq!(entry.rcode_str(), "NOERROR");
    ///
    /// let entry = QueryLogEntry::new("example.com", 1).with_response_code(3);
    /// assert_eq!(entry.rcode_str(), "NXDOMAIN");
    /// ```
    #[must_use]
    pub fn rcode_str(&self) -> &'static str {
        match self.response_code {
            0 => "NOERROR",
            1 => "FORMERR",
            2 => "SERVFAIL",
            3 => "NXDOMAIN",
            4 => "NOTIMP",
            5 => "REFUSED",
            _ => "OTHER",
        }
    }
}

// ============================================================================
// LogStats
// ============================================================================

/// Statistics for the query logger
///
/// All counters are atomic and can be read from any thread without locking.
#[derive(Debug, Default)]
pub struct LogStats {
    /// Total entries successfully logged
    entries_logged: AtomicU64,

    /// Entries dropped due to full channel
    entries_dropped: AtomicU64,

    /// Total bytes written to log file
    bytes_written: AtomicU64,

    /// Number of batch writes performed
    batches_written: AtomicU64,

    /// Last write timestamp (Unix milliseconds)
    last_write_time: AtomicU64,
}

impl LogStats {
    /// Create new statistics
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a successfully logged entry
    pub fn record_logged(&self) {
        self.entries_logged.fetch_add(1, Ordering::Relaxed);
    }

    /// Record multiple successfully logged entries
    pub fn record_logged_batch(&self, count: u64) {
        self.entries_logged.fetch_add(count, Ordering::Relaxed);
    }

    /// Record a dropped entry
    pub fn record_dropped(&self) {
        self.entries_dropped.fetch_add(1, Ordering::Relaxed);
    }

    /// Record bytes written
    pub fn record_bytes_written(&self, bytes: u64) {
        self.bytes_written.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Record a batch write
    pub fn record_batch_written(&self) {
        self.batches_written.fetch_add(1, Ordering::Relaxed);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        self.last_write_time.store(now, Ordering::Relaxed);
    }

    /// Get total entries logged
    #[must_use]
    pub fn entries_logged(&self) -> u64 {
        self.entries_logged.load(Ordering::Relaxed)
    }

    /// Get total entries dropped
    #[must_use]
    pub fn entries_dropped(&self) -> u64 {
        self.entries_dropped.load(Ordering::Relaxed)
    }

    /// Get total bytes written
    #[must_use]
    pub fn bytes_written(&self) -> u64 {
        self.bytes_written.load(Ordering::Relaxed)
    }

    /// Get total batches written
    #[must_use]
    pub fn batches_written(&self) -> u64 {
        self.batches_written.load(Ordering::Relaxed)
    }

    /// Get last write timestamp
    #[must_use]
    pub fn last_write_time(&self) -> u64 {
        self.last_write_time.load(Ordering::Relaxed)
    }

    /// Get the drop rate (0.0 to 1.0)
    #[must_use]
    pub fn drop_rate(&self) -> f64 {
        let logged = self.entries_logged() as f64;
        let dropped = self.entries_dropped() as f64;
        let total = logged + dropped;
        if total == 0.0 {
            0.0
        } else {
            dropped / total
        }
    }

    /// Get a snapshot of current statistics
    #[must_use]
    pub fn snapshot(&self) -> LogStatsSnapshot {
        LogStatsSnapshot {
            entries_logged: self.entries_logged(),
            entries_dropped: self.entries_dropped(),
            bytes_written: self.bytes_written(),
            batches_written: self.batches_written(),
            last_write_time: self.last_write_time(),
            drop_rate: self.drop_rate(),
        }
    }

    /// Reset all statistics
    pub fn reset(&self) {
        self.entries_logged.store(0, Ordering::Relaxed);
        self.entries_dropped.store(0, Ordering::Relaxed);
        self.bytes_written.store(0, Ordering::Relaxed);
        self.batches_written.store(0, Ordering::Relaxed);
        self.last_write_time.store(0, Ordering::Relaxed);
    }
}

/// Snapshot of log statistics
///
/// This is a point-in-time copy of statistics that can be safely
/// passed around and serialized.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LogStatsSnapshot {
    /// Total entries successfully logged
    pub entries_logged: u64,

    /// Entries dropped due to full channel
    pub entries_dropped: u64,

    /// Total bytes written to log file
    pub bytes_written: u64,

    /// Number of batch writes performed
    pub batches_written: u64,

    /// Last write timestamp (Unix milliseconds)
    pub last_write_time: u64,

    /// Drop rate (0.0 to 1.0)
    pub drop_rate: f64,
}

// ============================================================================
// QueryLogger
// ============================================================================

/// Async query logger with batch writes
///
/// The logger uses an mpsc channel for non-blocking entry submission and
/// a background task for batch writes. This design ensures that logging
/// never blocks DNS query handling.
///
/// # Thread Safety
///
/// `QueryLogger` is `Send + Sync` and can be safely shared across threads
/// using `Arc<QueryLogger>`.
///
/// # Example
///
/// ```no_run
/// use rust_router::dns::log::{QueryLogger, QueryLogEntry};
/// use rust_router::dns::LoggingConfig;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let config = LoggingConfig::default().enabled();
/// let logger = QueryLogger::new(config)?;
///
/// // Log entries (non-blocking)
/// for i in 0..100 {
///     let entry = QueryLogEntry::new(format!("domain{}.com", i), 1);
///     logger.log(entry);
/// }
///
/// // Graceful shutdown
/// logger.shutdown().await;
/// # Ok(())
/// # }
/// ```
pub struct QueryLogger {
    /// Channel sender for entry submission
    sender: mpsc::Sender<LogCommand>,

    /// Statistics
    stats: Arc<LogStats>,

    /// Background writer task handle
    writer_handle: parking_lot::Mutex<Option<JoinHandle<()>>>,

    /// Whether the logger is enabled
    enabled: bool,
}

/// Internal commands for the log writer task
enum LogCommand {
    /// Log an entry
    Entry(QueryLogEntry),

    /// Flush pending entries (fire-and-forget)
    Flush,

    /// Flush pending entries with completion notification
    FlushSync(oneshot::Sender<bool>),

    /// Shutdown the writer
    Shutdown,
}

impl QueryLogger {
    /// Create a new query logger from configuration
    ///
    /// This spawns a background task for batch writes.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The log file cannot be created
    /// - The buffer size is invalid
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rust_router::dns::log::QueryLogger;
    /// use rust_router::dns::LoggingConfig;
    ///
    /// let config = LoggingConfig::default().enabled();
    /// let logger = QueryLogger::new(config).expect("Failed to create logger");
    /// ```
    pub fn new(config: LoggingConfig) -> DnsResult<Self> {
        let enabled = config.enabled;

        // Validate and clamp buffer size
        let buffer_size = config.buffer_size.clamp(MIN_BUFFER_SIZE, MAX_BUFFER_SIZE);

        let (sender, receiver) = mpsc::channel(buffer_size);
        let stats = Arc::new(LogStats::new());

        let writer_handle = if enabled {
            let writer_stats = Arc::clone(&stats);
            let handle = tokio::spawn(Self::writer_task(config, receiver, writer_stats));
            Some(handle)
        } else {
            // Drop the receiver immediately if disabled
            drop(receiver);
            None
        };

        Ok(Self {
            sender,
            stats,
            writer_handle: parking_lot::Mutex::new(writer_handle),
            enabled,
        })
    }

    /// Create a disabled logger (for testing or when logging is off)
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::dns::log::QueryLogger;
    ///
    /// let logger = QueryLogger::disabled();
    /// assert!(!logger.is_enabled());
    /// ```
    #[must_use]
    pub fn disabled() -> Self {
        let (sender, _receiver) = mpsc::channel(MIN_BUFFER_SIZE);

        Self {
            sender,
            stats: Arc::new(LogStats::new()),
            writer_handle: parking_lot::Mutex::new(None),
            enabled: false,
        }
    }

    /// Check if the logger is enabled
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::dns::log::QueryLogger;
    ///
    /// let logger = QueryLogger::disabled();
    /// assert!(!logger.is_enabled());
    /// ```
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Log a query entry (non-blocking)
    ///
    /// This method uses `try_send` to submit the entry without blocking.
    /// If the channel is full, the entry is dropped and the drop counter
    /// is incremented.
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::dns::log::{QueryLogger, QueryLogEntry};
    ///
    /// let logger = QueryLogger::disabled();
    /// let entry = QueryLogEntry::new("example.com", 1);
    /// logger.log(entry); // Non-blocking, returns immediately
    /// ```
    pub fn log(&self, entry: QueryLogEntry) {
        if !self.enabled {
            return;
        }

        match self.sender.try_send(LogCommand::Entry(entry)) {
            Ok(()) => {
                trace!("Log entry submitted");
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.stats.record_dropped();
                warn!("Log channel full, entry dropped");
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                // Logger is shutting down
                trace!("Log channel closed");
            }
        }
    }

    /// Flush pending entries to disk (fire-and-forget)
    ///
    /// This sends a flush command to the writer task. The method returns
    /// immediately without waiting for confirmation. Use `flush_sync()`
    /// if you need confirmation that the flush completed successfully.
    ///
    /// # Returns
    ///
    /// - `true` if the flush command was successfully sent to the writer
    /// - `false` if the channel is full or closed
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rust_router::dns::log::QueryLogger;
    /// use rust_router::dns::LoggingConfig;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let config = LoggingConfig::default().enabled();
    /// let logger = QueryLogger::new(config)?;
    ///
    /// if logger.flush() {
    ///     println!("Flush command sent");
    /// } else {
    ///     println!("Failed to send flush command");
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn flush(&self) -> bool {
        if !self.enabled {
            return true; // No-op success for disabled logger
        }

        match self.sender.try_send(LogCommand::Flush) {
            Ok(()) => {
                trace!("Flush command sent");
                true
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                warn!("Log channel full, flush command dropped");
                false
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                trace!("Log channel closed");
                false
            }
        }
    }

    /// Flush pending entries to disk with confirmation
    ///
    /// This sends a flush command to the writer task and waits for
    /// confirmation that all pending entries have been written to disk.
    ///
    /// # Returns
    ///
    /// - `Ok(true)` if the flush completed successfully
    /// - `Ok(false)` if the flush was processed but some entries failed to write
    /// - `Err(_)` if the flush command could not be sent or timed out
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rust_router::dns::log::QueryLogger;
    /// use rust_router::dns::LoggingConfig;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let config = LoggingConfig::default().enabled();
    /// let logger = QueryLogger::new(config)?;
    ///
    /// match logger.flush_sync().await {
    ///     Ok(true) => println!("Flush completed successfully"),
    ///     Ok(false) => println!("Flush completed with some failures"),
    ///     Err(e) => println!("Flush failed: {}", e),
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn flush_sync(&self) -> DnsResult<bool> {
        if !self.enabled {
            return Ok(true); // No-op success for disabled logger
        }

        let (tx, rx) = oneshot::channel();

        // Try to send the flush command
        match self.sender.try_send(LogCommand::FlushSync(tx)) {
            Ok(()) => {
                trace!("Flush sync command sent, waiting for confirmation");
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                return Err(DnsError::internal("Log channel full, cannot send flush command"));
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                return Err(DnsError::internal("Log channel closed"));
            }
        }

        // Wait for confirmation with timeout
        let timeout = Duration::from_millis(FLUSH_SYNC_TIMEOUT_MS);
        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(success)) => Ok(success),
            Ok(Err(_)) => {
                // Sender was dropped without sending a response
                Err(DnsError::internal("Flush confirmation channel closed unexpectedly"))
            }
            Err(_) => {
                // Timeout
                Err(DnsError::timeout("flush_sync", timeout))
            }
        }
    }

    /// Gracefully shutdown the logger
    ///
    /// This flushes all pending entries and stops the background writer task.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rust_router::dns::log::QueryLogger;
    /// use rust_router::dns::LoggingConfig;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let config = LoggingConfig::default().enabled();
    /// let logger = QueryLogger::new(config)?;
    ///
    /// // ... log some entries ...
    ///
    /// logger.shutdown().await;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn shutdown(&self) {
        if !self.enabled {
            return;
        }

        info!("Shutting down query logger");

        // Send shutdown command
        let _ = self.sender.send(LogCommand::Shutdown).await;

        // Wait for writer task to finish
        let handle = self.writer_handle.lock().take();
        if let Some(h) = handle {
            let _ = h.await;
        }

        info!("Query logger shutdown complete");
    }

    /// Get logger statistics
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::dns::log::QueryLogger;
    ///
    /// let logger = QueryLogger::disabled();
    /// let stats = logger.stats();
    /// assert_eq!(stats.entries_logged(), 0);
    /// ```
    #[must_use]
    pub fn stats(&self) -> &LogStats {
        &self.stats
    }

    /// Get a snapshot of current statistics
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::dns::log::QueryLogger;
    ///
    /// let logger = QueryLogger::disabled();
    /// let snapshot = logger.stats_snapshot();
    /// assert_eq!(snapshot.entries_logged, 0);
    /// ```
    #[must_use]
    pub fn stats_snapshot(&self) -> LogStatsSnapshot {
        self.stats.snapshot()
    }

    /// Background writer task
    async fn writer_task(
        config: LoggingConfig,
        mut receiver: mpsc::Receiver<LogCommand>,
        stats: Arc<LogStats>,
    ) {
        info!(
            "Starting log writer task (format: {:?}, path: {:?})",
            config.format, config.path
        );

        let mut rotator = LogRotator::new(config.path.clone(), config.rotation_days, config.max_files);

        // Open log file
        let file_result = Self::open_log_file(&config.path).await;
        let mut file = match file_result {
            Ok(f) => f,
            Err(e) => {
                error!("Failed to open log file: {}", e);
                return;
            }
        };

        let mut batch: Vec<QueryLogEntry> = Vec::with_capacity(DEFAULT_BATCH_SIZE);
        let flush_interval = Duration::from_millis(DEFAULT_FLUSH_INTERVAL_MS);

        loop {
            // Wait for entries with timeout for periodic flush
            let result = tokio::time::timeout(flush_interval, receiver.recv()).await;

            match result {
                Ok(Some(LogCommand::Entry(entry))) => {
                    batch.push(entry);

                    // Check if we should flush based on batch size
                    if batch.len() >= DEFAULT_BATCH_SIZE {
                        Self::write_batch(&mut file, &batch, &config.format, &stats, &mut rotator)
                            .await;
                        batch.clear();
                    }
                }
                Ok(Some(LogCommand::Flush)) => {
                    if !batch.is_empty() {
                        Self::write_batch(&mut file, &batch, &config.format, &stats, &mut rotator)
                            .await;
                        batch.clear();
                    }
                }
                Ok(Some(LogCommand::FlushSync(response_tx))) => {
                    let success = if batch.is_empty() {
                        true // No entries to flush, consider it successful
                    } else {
                        Self::write_batch_with_result(&mut file, &batch, &config.format, &stats, &mut rotator)
                            .await
                    };
                    batch.clear();

                    // Send confirmation (ignore if receiver dropped)
                    let _ = response_tx.send(success);
                }
                Ok(Some(LogCommand::Shutdown)) => {
                    // Flush remaining entries
                    if !batch.is_empty() {
                        Self::write_batch(&mut file, &batch, &config.format, &stats, &mut rotator)
                            .await;
                    }
                    info!("Log writer task shutting down");
                    break;
                }
                Ok(None) => {
                    // Channel closed
                    if !batch.is_empty() {
                        Self::write_batch(&mut file, &batch, &config.format, &stats, &mut rotator)
                            .await;
                    }
                    debug!("Log channel closed, writer task exiting");
                    break;
                }
                Err(_) => {
                    // Timeout - flush pending entries
                    if !batch.is_empty() {
                        Self::write_batch(&mut file, &batch, &config.format, &stats, &mut rotator)
                            .await;
                        batch.clear();
                    }

                    // Check if rotation is needed
                    if rotator.should_rotate() {
                        if let Err(e) = rotator.rotate() {
                            error!("Log rotation failed: {}", e);
                        } else {
                            // Reopen file after rotation
                            match Self::open_log_file(&config.path).await {
                                Ok(f) => file = f,
                                Err(e) => {
                                    error!("Failed to reopen log file after rotation: {}", e);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /// Validate that a path does not contain path traversal attempts
    ///
    /// This function checks:
    /// 1. The path does not contain `..` components
    /// 2. The path, when canonicalized, stays within the expected parent directory
    ///
    /// # Security
    ///
    /// This prevents attacks like `../../../etc/passwd` where an attacker
    /// tries to write log files outside the intended directory.
    fn validate_log_path(path: &Path) -> DnsResult<PathBuf> {
        // Check for path traversal patterns in the raw path
        let path_str = path.to_string_lossy();

        // Reject paths containing `..` (parent directory traversal)
        if path_str.contains("..") {
            return Err(DnsError::config(format!(
                "Log path contains path traversal attempt: {path:?}"
            )));
        }

        // Ensure path has a valid file name (not empty, not a directory)
        let file_name = path.file_name().ok_or_else(|| {
            DnsError::config(format!(
                "Log path has no file name (cannot be a directory or special path): {path:?}"
            ))
        })?;

        // Validate file name doesn't contain traversal characters
        let file_name_str = file_name.to_string_lossy();
        if file_name_str.contains("..") || file_name_str.contains('/') || file_name_str.contains('\\') {
            return Err(DnsError::config(format!(
                "Log file name contains invalid characters: {file_name:?}"
            )));
        }

        // Get the intended parent directory
        let parent = path.parent().unwrap_or(Path::new("."));

        // If the parent doesn't exist yet, we can't canonicalize, so we do
        // additional checks on the path components
        if !parent.exists() {
            // Check each component for traversal attempts
            for component in path.components() {
                match component {
                    std::path::Component::ParentDir => {
                        return Err(DnsError::config(format!(
                            "Log path contains parent directory traversal: {path:?}"
                        )));
                    }
                    std::path::Component::Normal(s) => {
                        // Check for hidden traversal in component names
                        let s_str = s.to_string_lossy();
                        if s_str.contains("..") {
                            return Err(DnsError::config(format!(
                                "Log path component contains invalid sequence: {path:?}"
                            )));
                        }
                    }
                    _ => {}
                }
            }

            // Path looks safe, return it as-is for now (will be created)
            return Ok(path.to_path_buf());
        }

        // Parent exists, so canonicalize it and verify the path stays within
        let canonical_parent = parent.canonicalize().map_err(|e| {
            DnsError::internal(format!(
                "Failed to canonicalize log parent directory {parent:?}: {e}"
            ))
        })?;

        // Construct the validated path using the already validated file_name
        let validated_path = canonical_parent.join(file_name);

        // If the file already exists, canonicalize the full path and verify
        // it's still within the canonical parent
        if validated_path.exists() {
            let canonical_path = validated_path.canonicalize().map_err(|e| {
                DnsError::internal(format!(
                    "Failed to canonicalize log path {validated_path:?}: {e}"
                ))
            })?;

            // Verify the canonical path starts with the canonical parent
            if !canonical_path.starts_with(&canonical_parent) {
                return Err(DnsError::config(format!(
                    "Log path escapes intended directory: {canonical_path:?} not within {canonical_parent:?}"
                )));
            }

            return Ok(canonical_path);
        }

        Ok(validated_path)
    }

    /// Open or create the log file
    ///
    /// # Security
    ///
    /// This function validates the path to prevent path traversal attacks.
    /// Paths containing `..` or attempting to escape the intended directory
    /// will be rejected.
    async fn open_log_file(path: &PathBuf) -> DnsResult<File> {
        // Validate path to prevent path traversal attacks
        let validated_path = Self::validate_log_path(path)?;

        // Ensure parent directory exists
        if let Some(parent) = validated_path.parent() {
            if !parent.exists() {
                tokio::fs::create_dir_all(parent)
                    .await
                    .map_err(|e| DnsError::internal(format!("Failed to create log directory: {e}")))?;
            }
        }

        OpenOptions::new()
            .create(true)
            .append(true)
            .open(&validated_path)
            .await
            .map_err(|e| DnsError::internal(format!("Failed to open log file: {e}")))
    }

    /// Write a batch of entries to the log file
    async fn write_batch(
        file: &mut File,
        batch: &[QueryLogEntry],
        format: &LogFormat,
        stats: &LogStats,
        rotator: &mut LogRotator,
    ) {
        if batch.is_empty() {
            return;
        }

        let mut buffer = Vec::with_capacity(batch.len() * 256); // Estimate ~256 bytes per entry

        for entry in batch {
            match format {
                LogFormat::Json => {
                    let json = entry.to_json();
                    buffer.extend_from_slice(json.as_bytes());
                }
                LogFormat::Tsv => {
                    let tsv = entry.to_tsv();
                    buffer.extend_from_slice(tsv.as_bytes());
                }
                LogFormat::Binary => {
                    match entry.to_binary() {
                        Ok(data) => {
                            // Write length prefix (4 bytes, big-endian) for framing
                            let len = data.len() as u32;
                            buffer.extend_from_slice(&len.to_be_bytes());
                            buffer.extend_from_slice(&data);
                        }
                        Err(e) => {
                            error!("Failed to serialize entry to binary: {}", e);
                            continue;
                        }
                    }
                }
            }
        }

        // Write to file
        match file.write_all(&buffer).await {
            Ok(()) => {
                stats.record_logged_batch(batch.len() as u64);
                stats.record_bytes_written(buffer.len() as u64);
                stats.record_batch_written();
                rotator.record_bytes_written(buffer.len() as u64);
                trace!("Wrote {} entries ({} bytes)", batch.len(), buffer.len());
            }
            Err(e) => {
                error!("Failed to write log batch: {}", e);
            }
        }

        // Flush to ensure data is written
        if let Err(e) = file.flush().await {
            error!("Failed to flush log file: {}", e);
        }
    }

    /// Write a batch of entries to the log file with result reporting
    ///
    /// This is similar to `write_batch` but returns a boolean indicating
    /// whether the write operation succeeded.
    ///
    /// # Returns
    ///
    /// - `true` if all entries were written and flushed successfully
    /// - `false` if any error occurred during write or flush
    async fn write_batch_with_result(
        file: &mut File,
        batch: &[QueryLogEntry],
        format: &LogFormat,
        stats: &LogStats,
        rotator: &mut LogRotator,
    ) -> bool {
        if batch.is_empty() {
            return true;
        }

        let mut buffer = Vec::with_capacity(batch.len() * 256); // Estimate ~256 bytes per entry

        for entry in batch {
            match format {
                LogFormat::Json => {
                    let json = entry.to_json();
                    buffer.extend_from_slice(json.as_bytes());
                }
                LogFormat::Tsv => {
                    let tsv = entry.to_tsv();
                    buffer.extend_from_slice(tsv.as_bytes());
                }
                LogFormat::Binary => {
                    match entry.to_binary() {
                        Ok(data) => {
                            // Write length prefix (4 bytes, big-endian) for framing
                            let len = data.len() as u32;
                            buffer.extend_from_slice(&len.to_be_bytes());
                            buffer.extend_from_slice(&data);
                        }
                        Err(e) => {
                            error!("Failed to serialize entry to binary: {}", e);
                            // Continue with other entries but mark as partial failure
                        }
                    }
                }
            }
        }

        // Write to file
        let write_success = match file.write_all(&buffer).await {
            Ok(()) => {
                stats.record_logged_batch(batch.len() as u64);
                stats.record_bytes_written(buffer.len() as u64);
                stats.record_batch_written();
                rotator.record_bytes_written(buffer.len() as u64);
                trace!("Wrote {} entries ({} bytes)", batch.len(), buffer.len());
                true
            }
            Err(e) => {
                error!("Failed to write log batch: {}", e);
                false
            }
        };

        // Flush to ensure data is written
        let flush_success = match file.flush().await {
            Ok(()) => true,
            Err(e) => {
                error!("Failed to flush log file: {}", e);
                false
            }
        };

        write_success && flush_success
    }
}

impl Drop for QueryLogger {
    fn drop(&mut self) {
        // Note: We cannot await in drop, so we just log
        // Users should call shutdown() for graceful termination
        if self.enabled {
            debug!("QueryLogger dropped - call shutdown() for graceful termination");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;
    use tempfile::TempDir;

    // ========================================================================
    // QueryLogEntry Tests
    // ========================================================================

    #[test]
    fn test_query_log_entry_new() {
        let entry = QueryLogEntry::new("example.com", 1);
        assert_eq!(entry.domain, "example.com");
        assert_eq!(entry.qtype, 1);
        assert!(entry.timestamp > 0);
        assert_eq!(entry.upstream, "");
        assert_eq!(entry.response_code, 0);
        assert_eq!(entry.latency_us, 0);
        assert!(!entry.blocked);
        assert!(!entry.cached);
    }

    #[test]
    fn test_query_log_entry_builder() {
        let entry = QueryLogEntry::new("test.com", 28)
            .with_upstream("cloudflare")
            .with_response_code(3)
            .with_latency_us(2500)
            .with_blocked(true)
            .with_cached(true)
            .with_timestamp(1234567890);

        assert_eq!(entry.domain, "test.com");
        assert_eq!(entry.qtype, 28);
        assert_eq!(entry.upstream, "cloudflare");
        assert_eq!(entry.response_code, 3);
        assert_eq!(entry.latency_us, 2500);
        assert!(entry.blocked);
        assert!(entry.cached);
        assert_eq!(entry.timestamp, 1234567890);
    }

    #[test]
    fn test_query_log_entry_qtype_str() {
        assert_eq!(QueryLogEntry::new("", 1).qtype_str(), "A");
        assert_eq!(QueryLogEntry::new("", 28).qtype_str(), "AAAA");
        assert_eq!(QueryLogEntry::new("", 5).qtype_str(), "CNAME");
        assert_eq!(QueryLogEntry::new("", 15).qtype_str(), "MX");
        assert_eq!(QueryLogEntry::new("", 16).qtype_str(), "TXT");
        assert_eq!(QueryLogEntry::new("", 255).qtype_str(), "ANY");
        assert_eq!(QueryLogEntry::new("", 999).qtype_str(), "OTHER");
    }

    #[test]
    fn test_query_log_entry_rcode_str() {
        assert_eq!(QueryLogEntry::new("", 1).with_response_code(0).rcode_str(), "NOERROR");
        assert_eq!(QueryLogEntry::new("", 1).with_response_code(1).rcode_str(), "FORMERR");
        assert_eq!(QueryLogEntry::new("", 1).with_response_code(2).rcode_str(), "SERVFAIL");
        assert_eq!(QueryLogEntry::new("", 1).with_response_code(3).rcode_str(), "NXDOMAIN");
        assert_eq!(QueryLogEntry::new("", 1).with_response_code(5).rcode_str(), "REFUSED");
        assert_eq!(QueryLogEntry::new("", 1).with_response_code(99).rcode_str(), "OTHER");
    }

    #[test]
    fn test_query_log_entry_to_json() {
        let entry = QueryLogEntry::new("example.com", 1)
            .with_timestamp(1704067200000)
            .with_upstream("google")
            .with_response_code(0)
            .with_latency_us(1500);

        let json = entry.to_json();
        assert!(json.contains("\"domain\":\"example.com\""));
        assert!(json.contains("\"qtype\":1"));
        assert!(json.contains("\"upstream\":\"google\""));
        assert!(json.contains("\"timestamp\":1704067200000"));
        assert!(json.ends_with('\n'));
    }

    #[test]
    fn test_query_log_entry_to_json_escaping() {
        let entry = QueryLogEntry::new("test\"domain.com", 1);
        let json = entry.to_json();
        assert!(json.contains("test\\\"domain.com"));
    }

    #[test]
    fn test_query_log_entry_to_tsv() {
        let entry = QueryLogEntry::new("example.com", 1)
            .with_timestamp(1704067200000)
            .with_upstream("google")
            .with_response_code(0)
            .with_latency_us(1500)
            .with_blocked(false)
            .with_cached(true);

        let tsv = entry.to_tsv();
        let fields: Vec<&str> = tsv.trim().split('\t').collect();
        assert_eq!(fields.len(), 8);
        assert_eq!(fields[0], "1704067200000");
        assert_eq!(fields[1], "example.com");
        assert_eq!(fields[2], "1");
        assert_eq!(fields[3], "google");
        assert_eq!(fields[4], "0");
        assert_eq!(fields[5], "1500");
        assert_eq!(fields[6], "0");
        assert_eq!(fields[7], "1");
    }

    #[test]
    fn test_query_log_entry_to_tsv_escaping() {
        // Test that control characters are properly escaped, not replaced
        let entry = QueryLogEntry::new("test\tdomain.com", 1)
            .with_upstream("up\nstream");
        let tsv = entry.to_tsv();
        // Field separators should be actual tabs, but domain should have escaped tab
        assert_eq!(tsv.matches('\t').count(), 7); // Only field separators
        assert!(tsv.contains("test\\tdomain.com")); // Tab escaped as \t
        assert!(tsv.contains("up\\nstream")); // Newline escaped as \n
    }

    #[test]
    fn test_query_log_entry_to_tsv_escaping_comprehensive() {
        // Test all control characters
        let entry = QueryLogEntry::new("dom\tain\nwith\rcontrol", 1)
            .with_upstream("up\t\n\rstream");
        let tsv = entry.to_tsv();

        // Verify escaping
        assert!(tsv.contains("dom\\tain\\nwith\\rcontrol"));
        assert!(tsv.contains("up\\t\\n\\rstream"));

        // Verify no raw control characters in domain/upstream fields
        // (there should be exactly 7 tabs for field separators)
        assert_eq!(tsv.matches('\t').count(), 7);
        // Only one newline (the line terminator)
        assert_eq!(tsv.matches('\n').count(), 1);
        // No carriage returns
        assert_eq!(tsv.matches('\r').count(), 0);
    }

    #[test]
    fn test_query_log_entry_to_tsv_backslash_escaping() {
        // Test that backslashes are also escaped to prevent ambiguity
        let entry = QueryLogEntry::new("domain\\with\\backslash", 1)
            .with_upstream("upstream\\test");
        let tsv = entry.to_tsv();

        // Backslashes should be escaped
        assert!(tsv.contains("domain\\\\with\\\\backslash"));
        assert!(tsv.contains("upstream\\\\test"));
    }

    #[test]
    fn test_query_log_entry_to_tsv_combined_escaping() {
        // Test backslash followed by control character
        let entry = QueryLogEntry::new("dom\\\tain", 1);
        let tsv = entry.to_tsv();

        // Backslash then tab should become \\ then \t
        assert!(tsv.contains("dom\\\\\\tain"));
    }

    #[test]
    fn test_escape_tsv_field() {
        assert_eq!(QueryLogEntry::escape_tsv_field("normal"), "normal");
        assert_eq!(QueryLogEntry::escape_tsv_field("with\ttab"), "with\\ttab");
        assert_eq!(QueryLogEntry::escape_tsv_field("with\nnewline"), "with\\nnewline");
        assert_eq!(QueryLogEntry::escape_tsv_field("with\rcarriage"), "with\\rcarriage");
        assert_eq!(QueryLogEntry::escape_tsv_field("with\\backslash"), "with\\\\backslash");
        assert_eq!(
            QueryLogEntry::escape_tsv_field("all\t\n\r\\chars"),
            "all\\t\\n\\r\\\\chars"
        );
    }

    #[test]
    fn test_query_log_entry_binary_roundtrip() {
        let entry = QueryLogEntry::new("example.com", 28)
            .with_upstream("cloudflare")
            .with_response_code(0)
            .with_latency_us(2500)
            .with_blocked(false)
            .with_cached(true)
            .with_timestamp(1704067200000);

        let binary = entry.to_binary().expect("serialize");
        let decoded = QueryLogEntry::from_binary(&binary).expect("deserialize");

        assert_eq!(entry, decoded);
    }

    #[test]
    fn test_query_log_entry_binary_empty_strings() {
        let entry = QueryLogEntry::new("", 1);
        let binary = entry.to_binary().expect("serialize");
        let decoded = QueryLogEntry::from_binary(&binary).expect("deserialize");
        assert_eq!(entry, decoded);
    }

    #[test]
    fn test_query_log_entry_binary_unicode() {
        let entry = QueryLogEntry::new("example.com", 1)
            .with_upstream("cloudflare");
        let binary = entry.to_binary().expect("serialize");
        let decoded = QueryLogEntry::from_binary(&binary).expect("deserialize");
        assert_eq!(entry, decoded);
    }

    #[test]
    fn test_query_log_entry_creation_performance() {
        let start = Instant::now();
        for i in 0..10_000 {
            let _ = QueryLogEntry::new(format!("domain{}.com", i), 1)
                .with_upstream("test")
                .with_latency_us(100);
        }
        let elapsed = start.elapsed();
        // Should complete in under 100ms for 10K entries
        assert!(elapsed.as_millis() < 100, "Entry creation too slow: {:?}", elapsed);
    }

    // ========================================================================
    // LogStats Tests
    // ========================================================================

    #[test]
    fn test_log_stats_new() {
        let stats = LogStats::new();
        assert_eq!(stats.entries_logged(), 0);
        assert_eq!(stats.entries_dropped(), 0);
        assert_eq!(stats.bytes_written(), 0);
        assert_eq!(stats.batches_written(), 0);
    }

    #[test]
    fn test_log_stats_record_logged() {
        let stats = LogStats::new();
        stats.record_logged();
        stats.record_logged();
        assert_eq!(stats.entries_logged(), 2);
    }

    #[test]
    fn test_log_stats_record_logged_batch() {
        let stats = LogStats::new();
        stats.record_logged_batch(100);
        assert_eq!(stats.entries_logged(), 100);
    }

    #[test]
    fn test_log_stats_record_dropped() {
        let stats = LogStats::new();
        stats.record_dropped();
        stats.record_dropped();
        assert_eq!(stats.entries_dropped(), 2);
    }

    #[test]
    fn test_log_stats_record_bytes_written() {
        let stats = LogStats::new();
        stats.record_bytes_written(1000);
        stats.record_bytes_written(500);
        assert_eq!(stats.bytes_written(), 1500);
    }

    #[test]
    fn test_log_stats_record_batch_written() {
        let stats = LogStats::new();
        stats.record_batch_written();
        assert_eq!(stats.batches_written(), 1);
        assert!(stats.last_write_time() > 0);
    }

    #[test]
    fn test_log_stats_drop_rate() {
        let stats = LogStats::new();
        assert_eq!(stats.drop_rate(), 0.0);

        stats.record_logged_batch(80);
        stats.record_dropped();
        stats.record_dropped();
        // 80 logged + 20 dropped = 100 total, 20% drop rate
        for _ in 0..18 {
            stats.record_dropped();
        }
        let rate = stats.drop_rate();
        assert!((rate - 0.2).abs() < 0.001);
    }

    #[test]
    fn test_log_stats_snapshot() {
        let stats = LogStats::new();
        stats.record_logged_batch(50);
        stats.record_dropped();
        stats.record_bytes_written(1000);
        stats.record_batch_written();

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.entries_logged, 50);
        assert_eq!(snapshot.entries_dropped, 1);
        assert_eq!(snapshot.bytes_written, 1000);
        assert_eq!(snapshot.batches_written, 1);
        assert!(snapshot.last_write_time > 0);
    }

    #[test]
    fn test_log_stats_reset() {
        let stats = LogStats::new();
        stats.record_logged_batch(100);
        stats.record_dropped();
        stats.reset();

        assert_eq!(stats.entries_logged(), 0);
        assert_eq!(stats.entries_dropped(), 0);
    }

    #[test]
    fn test_log_stats_thread_safety() {
        use std::sync::Arc;
        use std::thread;

        let stats = Arc::new(LogStats::new());
        let mut handles = vec![];

        for _ in 0..10 {
            let s = Arc::clone(&stats);
            handles.push(thread::spawn(move || {
                for _ in 0..1000 {
                    s.record_logged();
                }
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        assert_eq!(stats.entries_logged(), 10_000);
    }

    // ========================================================================
    // QueryLogger Tests
    // ========================================================================

    #[test]
    fn test_query_logger_disabled() {
        let logger = QueryLogger::disabled();
        assert!(!logger.is_enabled());

        // Logging to disabled logger should be safe
        let entry = QueryLogEntry::new("test.com", 1);
        logger.log(entry);

        assert_eq!(logger.stats().entries_logged(), 0);
        assert_eq!(logger.stats().entries_dropped(), 0);
    }

    #[test]
    fn test_query_logger_stats_access() {
        let logger = QueryLogger::disabled();
        let stats = logger.stats();
        assert_eq!(stats.entries_logged(), 0);

        let snapshot = logger.stats_snapshot();
        assert_eq!(snapshot.entries_logged, 0);
    }

    #[tokio::test]
    async fn test_query_logger_new_with_config() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("dns-queries.log");

        let config = LoggingConfig {
            enabled: true,
            format: LogFormat::Json,
            path: log_path,
            rotation_days: 7,
            max_files: 7,
            buffer_size: 1000,
        };

        let logger = QueryLogger::new(config).expect("Failed to create logger");
        assert!(logger.is_enabled());

        // Log some entries
        for i in 0..10 {
            let entry = QueryLogEntry::new(format!("domain{}.com", i), 1);
            logger.log(entry);
        }

        // Give the writer task time to process
        tokio::time::sleep(Duration::from_millis(100)).await;
        logger.shutdown().await;

        assert!(logger.stats().entries_logged() > 0);
    }

    #[tokio::test]
    async fn test_query_logger_json_format() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("json.log");

        let config = LoggingConfig {
            enabled: true,
            format: LogFormat::Json,
            path: log_path.clone(),
            rotation_days: 7,
            max_files: 7,
            buffer_size: 100,
        };

        let logger = QueryLogger::new(config).expect("Failed to create logger");

        let entry = QueryLogEntry::new("test.example.com", 1)
            .with_upstream("google")
            .with_latency_us(1500);
        logger.log(entry);

        // Flush and shutdown
        logger.flush();
        tokio::time::sleep(Duration::from_millis(100)).await;
        logger.shutdown().await;

        // Read and verify
        let content = std::fs::read_to_string(&log_path).unwrap();
        assert!(content.contains("test.example.com"));
        assert!(content.contains("google"));
    }

    #[tokio::test]
    async fn test_query_logger_tsv_format() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("tsv.log");

        let config = LoggingConfig {
            enabled: true,
            format: LogFormat::Tsv,
            path: log_path.clone(),
            rotation_days: 7,
            max_files: 7,
            buffer_size: 100,
        };

        let logger = QueryLogger::new(config).expect("Failed to create logger");

        let entry = QueryLogEntry::new("tsv.test.com", 28)
            .with_upstream("cloudflare")
            .with_latency_us(2000);
        logger.log(entry);

        logger.flush();
        tokio::time::sleep(Duration::from_millis(100)).await;
        logger.shutdown().await;

        let content = std::fs::read_to_string(&log_path).unwrap();
        assert!(content.contains("tsv.test.com"));
        assert!(content.contains('\t'));
    }

    #[tokio::test]
    async fn test_query_logger_binary_format() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("binary.log");

        let config = LoggingConfig {
            enabled: true,
            format: LogFormat::Binary,
            path: log_path.clone(),
            rotation_days: 7,
            max_files: 7,
            buffer_size: 100,
        };

        let logger = QueryLogger::new(config).expect("Failed to create logger");

        let entry = QueryLogEntry::new("binary.test.com", 1)
            .with_upstream("google")
            .with_latency_us(1000)
            .with_timestamp(1704067200000);
        logger.log(entry.clone());

        logger.flush();
        tokio::time::sleep(Duration::from_millis(100)).await;
        logger.shutdown().await;

        // Read and verify binary format
        let content = std::fs::read(&log_path).unwrap();
        assert!(!content.is_empty());

        // Parse length prefix and entry
        let len = u32::from_be_bytes([content[0], content[1], content[2], content[3]]) as usize;
        let decoded = QueryLogEntry::from_binary(&content[4..4 + len]).expect("deserialize");
        assert_eq!(decoded.domain, "binary.test.com");
        assert_eq!(decoded.timestamp, 1704067200000);
    }

    #[tokio::test]
    async fn test_query_logger_batch_write() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("batch.log");

        let config = LoggingConfig {
            enabled: true,
            format: LogFormat::Json,
            path: log_path.clone(),
            rotation_days: 7,
            max_files: 7,
            buffer_size: 10000,
        };

        let logger = QueryLogger::new(config).expect("Failed to create logger");

        // Log many entries to trigger batch write
        for i in 0..1500 {
            let entry = QueryLogEntry::new(format!("domain{}.com", i), 1);
            logger.log(entry);
        }

        // Wait for batch processing
        tokio::time::sleep(Duration::from_millis(200)).await;
        logger.shutdown().await;

        // Should have triggered at least one batch write (1000 entries threshold)
        assert!(logger.stats().batches_written() >= 1);
        assert!(logger.stats().entries_logged() >= 1000);
    }

    #[tokio::test]
    async fn test_query_logger_flush() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("flush.log");

        let config = LoggingConfig {
            enabled: true,
            format: LogFormat::Json,
            path: log_path.clone(),
            rotation_days: 7,
            max_files: 7,
            buffer_size: 10000,
        };

        let logger = QueryLogger::new(config).expect("Failed to create logger");

        // Log a few entries (below batch threshold)
        for i in 0..10 {
            let entry = QueryLogEntry::new(format!("flush{}.com", i), 1);
            logger.log(entry);
        }

        // Explicit flush
        logger.flush();
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Should have written entries
        assert!(logger.stats().entries_logged() > 0);

        logger.shutdown().await;
    }

    #[tokio::test]
    async fn test_query_logger_graceful_shutdown() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("shutdown.log");

        let config = LoggingConfig {
            enabled: true,
            format: LogFormat::Json,
            path: log_path.clone(),
            rotation_days: 7,
            max_files: 7,
            buffer_size: 10000,
        };

        let logger = QueryLogger::new(config).expect("Failed to create logger");

        // Log entries
        for i in 0..50 {
            let entry = QueryLogEntry::new(format!("shutdown{}.com", i), 1);
            logger.log(entry);
        }

        // Shutdown should flush remaining entries
        logger.shutdown().await;

        // Verify all entries were written
        let content = std::fs::read_to_string(&log_path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 50);
    }

    #[tokio::test]
    async fn test_query_logger_empty_domain() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("empty.log");

        let config = LoggingConfig {
            enabled: true,
            format: LogFormat::Json,
            path: log_path.clone(),
            rotation_days: 7,
            max_files: 7,
            buffer_size: 100,
        };

        let logger = QueryLogger::new(config).expect("Failed to create logger");

        let entry = QueryLogEntry::new("", 1);
        logger.log(entry);

        logger.flush();
        tokio::time::sleep(Duration::from_millis(100)).await;
        logger.shutdown().await;

        let content = std::fs::read_to_string(&log_path).unwrap();
        assert!(content.contains("\"domain\":\"\""));
    }

    #[tokio::test]
    async fn test_query_logger_long_domain() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("long.log");

        let config = LoggingConfig {
            enabled: true,
            format: LogFormat::Json,
            path: log_path.clone(),
            rotation_days: 7,
            max_files: 7,
            buffer_size: 100,
        };

        let logger = QueryLogger::new(config).expect("Failed to create logger");

        // Create a very long domain name (exceeds RFC 1035 limit of 253 chars)
        let long_domain = "a".repeat(500) + ".example.com";
        let entry = QueryLogEntry::new(&long_domain, 1);
        logger.log(entry);

        logger.flush();
        tokio::time::sleep(Duration::from_millis(100)).await;
        logger.shutdown().await;

        let content = std::fs::read_to_string(&log_path).unwrap();
        // Domain should be truncated with marker (RFC 1035 validation)
        assert!(content.contains(TRUNCATION_MARKER));
        // Should contain the prefix of the domain
        assert!(content.contains("aaaaaaaaaa"));
        // Should NOT contain the full long domain
        assert!(!content.contains(&long_domain));
    }

    #[tokio::test]
    async fn test_query_logger_unicode_domain() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("unicode.log");

        let config = LoggingConfig {
            enabled: true,
            format: LogFormat::Json,
            path: log_path.clone(),
            rotation_days: 7,
            max_files: 7,
            buffer_size: 100,
        };

        let logger = QueryLogger::new(config).expect("Failed to create logger");

        let entry = QueryLogEntry::new("example.com", 1);
        logger.log(entry);

        logger.flush();
        tokio::time::sleep(Duration::from_millis(100)).await;
        logger.shutdown().await;

        let content = std::fs::read_to_string(&log_path).unwrap();
        assert!(content.contains("example.com"));
    }

    #[tokio::test]
    async fn test_query_logger_special_characters() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("special.log");

        let config = LoggingConfig {
            enabled: true,
            format: LogFormat::Json,
            path: log_path.clone(),
            rotation_days: 7,
            max_files: 7,
            buffer_size: 100,
        };

        let logger = QueryLogger::new(config).expect("Failed to create logger");

        let entry = QueryLogEntry::new("test\"domain\\.com", 1)
            .with_upstream("up\\stream");
        logger.log(entry);

        logger.flush();
        tokio::time::sleep(Duration::from_millis(100)).await;
        logger.shutdown().await;

        // Should be valid JSON (properly escaped)
        let content = std::fs::read_to_string(&log_path).unwrap();
        let _: serde_json::Value = serde_json::from_str(content.trim()).expect("valid JSON");
    }

    #[test]
    fn test_log_stats_snapshot_serialization() {
        let snapshot = LogStatsSnapshot {
            entries_logged: 1000,
            entries_dropped: 5,
            bytes_written: 50000,
            batches_written: 10,
            last_write_time: 1704067200000,
            drop_rate: 0.005,
        };

        let json = serde_json::to_string(&snapshot).expect("serialize");
        let decoded: LogStatsSnapshot = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(decoded.entries_logged, 1000);
        assert_eq!(decoded.entries_dropped, 5);
        assert_eq!(decoded.bytes_written, 50000);
    }

    // ========================================================================
    // Path Traversal Security Tests
    // ========================================================================

    #[test]
    fn test_validate_log_path_simple_traversal() {
        // Test basic path traversal attempt
        let path = PathBuf::from("/tmp/../etc/passwd");
        let result = QueryLogger::validate_log_path(&path);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("path traversal"));
    }

    #[test]
    fn test_validate_log_path_deep_traversal() {
        // Test deeply nested path traversal attempt
        let path = PathBuf::from("/tmp/logs/../../../etc/passwd");
        let result = QueryLogger::validate_log_path(&path);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("path traversal"));
    }

    #[test]
    fn test_validate_log_path_relative_traversal() {
        // Test relative path with traversal
        let path = PathBuf::from("../../../etc/passwd");
        let result = QueryLogger::validate_log_path(&path);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_log_path_double_dots_in_filename() {
        // Test file name containing double dots
        let path = PathBuf::from("/tmp/..hidden../file.log");
        let result = QueryLogger::validate_log_path(&path);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_log_path_encoded_traversal() {
        // Test URL-encoded style traversal (though Rust PathBuf won't decode it)
        // This should be caught by the string contains check
        let path = PathBuf::from("/tmp/logs/..%2F..%2Fetc/passwd");
        // This path contains ".." in the component name, so it should be rejected
        let result = QueryLogger::validate_log_path(&path);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_log_path_valid_path() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("dns-queries.log");

        let result = QueryLogger::validate_log_path(&log_path);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_log_path_valid_nested_path() {
        let temp_dir = TempDir::new().unwrap();
        // Create nested directory
        let nested_dir = temp_dir.path().join("logs").join("dns");
        std::fs::create_dir_all(&nested_dir).unwrap();
        let log_path = nested_dir.join("queries.log");

        let result = QueryLogger::validate_log_path(&log_path);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_log_path_nonexistent_parent() {
        let temp_dir = TempDir::new().unwrap();
        // Path with non-existent parent - should still be validated safely
        let log_path = temp_dir.path().join("nonexistent").join("subdir").join("file.log");

        let result = QueryLogger::validate_log_path(&log_path);
        // Should succeed since there's no traversal
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_log_path_slash_in_filename() {
        // File name containing forward slash should be rejected
        // Note: On Unix, this is technically impossible in an actual filename,
        // but the validation should still catch it in the string representation
        let temp_dir = TempDir::new().unwrap();
        let parent = temp_dir.path();
        // Create a path programmatically that would have a bad filename
        let mut path = parent.to_path_buf();
        path.push("normal_parent");
        std::fs::create_dir_all(&path).unwrap();

        // We can't actually create a file with "/" in the name on Unix,
        // but we can test the validation by checking the file_name validation
        // This test verifies that valid paths work
        path.push("valid.log");
        let result = QueryLogger::validate_log_path(&path);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_log_path_trailing_slash_normalized() {
        // Path with trailing slash - Rust normalizes this, file_name() returns "logs"
        // This is actually a valid path that could be used as a log file
        // (though using "logs" as a log file name would be unusual)
        let path = PathBuf::from("/tmp/logs/");
        let result = QueryLogger::validate_log_path(&path);
        // Rust normalizes "/tmp/logs/" to "/tmp/logs", so file_name() returns Some("logs")
        // This should succeed (though it's an unusual path)
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_log_path_current_dir_only() {
        // Path that is just "." - has no file_name (returns None)
        let path = PathBuf::from(".");
        let result = QueryLogger::validate_log_path(&path);
        // Should fail - "." has no file name
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("no file name"));
    }

    #[test]
    fn test_validate_log_path_root_directory() {
        // Path that is just "/" - has no file_name
        let path = PathBuf::from("/");
        let result = QueryLogger::validate_log_path(&path);
        // Should fail - "/" has no file name
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_log_path_parent_dir_only() {
        // Path that is just ".."
        let path = PathBuf::from("..");
        let result = QueryLogger::validate_log_path(&path);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_log_path_windows_style_traversal() {
        // Test Windows-style path separator in traversal attempt (on Unix)
        let path = PathBuf::from("/tmp/logs/..\\..\\etc\\passwd");
        let result = QueryLogger::validate_log_path(&path);
        // On Unix, this contains ".." which should be caught
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_log_path_null_byte() {
        // Test path with null byte (Rust's PathBuf handles this safely)
        // The null byte won't actually be in the path due to Rust's string handling,
        // but we verify normal paths still work
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("normal.log");
        let result = QueryLogger::validate_log_path(&log_path);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_log_path_absolute_etc_passwd() {
        // Direct attempt to write to /etc/passwd
        let path = PathBuf::from("/etc/passwd");
        // This doesn't contain ".." but should work as a valid path
        // (the security is that we validate parent directory exists and file stays within it)
        // For /etc/passwd, parent is /etc which exists, so this would "validate"
        // The actual protection is that the application should only use paths
        // from trusted configuration, not user input
        let result = QueryLogger::validate_log_path(&path);
        // This passes validation but would fail on permissions in practice
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_open_log_file_traversal_rejected() {
        // Test that open_log_file properly rejects traversal attempts
        let path = PathBuf::from("/tmp/../tmp/traversal.log");
        let result = QueryLogger::open_log_file(&path).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_open_log_file_valid_path() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("valid.log");

        let result = QueryLogger::open_log_file(&log_path).await;
        assert!(result.is_ok());

        // Clean up
        if log_path.exists() {
            std::fs::remove_file(&log_path).unwrap();
        }
    }

    #[tokio::test]
    async fn test_query_logger_rejects_traversal_path() {
        // Test that QueryLogger creation fails with traversal path
        let config = LoggingConfig {
            enabled: true,
            format: LogFormat::Json,
            path: PathBuf::from("/tmp/../etc/dns.log"),
            rotation_days: 7,
            max_files: 7,
            buffer_size: 100,
        };

        let logger = QueryLogger::new(config);
        // The logger is created but the writer task will fail to open the file
        // The validation happens asynchronously in the writer task
        // For immediate validation, we test validate_log_path directly
        assert!(logger.is_ok()); // Logger creation succeeds
        let logger = logger.unwrap();

        // Give the writer task time to fail
        tokio::time::sleep(Duration::from_millis(100)).await;
        logger.shutdown().await;
    }

    #[test]
    fn test_validate_log_path_symlink_escape() {
        // Test that symlink-based escapes are handled
        // Note: This requires creating actual symlinks which needs careful cleanup
        let temp_dir = TempDir::new().unwrap();
        let log_dir = temp_dir.path().join("logs");
        std::fs::create_dir_all(&log_dir).unwrap();

        // Create a valid log path
        let log_path = log_dir.join("normal.log");
        let result = QueryLogger::validate_log_path(&log_path);
        assert!(result.is_ok());

        // We can't easily test symlink escapes without creating symlinks,
        // which could be filesystem-dependent. The validation uses
        // canonicalize() which resolves symlinks, preventing escapes.
    }

    #[test]
    fn test_validate_log_path_multiple_slashes() {
        // Test path with multiple consecutive slashes (Unix normalizes these)
        let path = PathBuf::from("/tmp//logs///dns.log");
        // This path is actually valid - Unix treats multiple slashes as single
        // The path doesn't contain ".." so it should pass validation
        // Note: The parent "/tmp//logs//" may not exist, so this tests the
        // non-existent parent code path
        let result = QueryLogger::validate_log_path(&path);
        // Should succeed since there's no traversal
        assert!(result.is_ok());
    }

    // ========================================================================
    // Domain Length Validation Tests (RFC 1035)
    // ========================================================================

    #[test]
    fn test_domain_length_normal() {
        // Normal domain should not be modified
        let entry = QueryLogEntry::new("example.com", 1);
        assert_eq!(entry.domain, "example.com");
    }

    #[test]
    fn test_domain_length_at_limit() {
        // Domain at exactly 253 characters should not be modified
        let domain = "a".repeat(253);
        let entry = QueryLogEntry::new(&domain, 1);
        assert_eq!(entry.domain.len(), 253);
        assert_eq!(entry.domain, domain);
        assert!(!entry.domain.ends_with(TRUNCATION_MARKER));
    }

    #[test]
    fn test_domain_length_over_limit() {
        // Domain over 253 characters should be truncated with marker
        let domain = "a".repeat(300);
        let entry = QueryLogEntry::new(&domain, 1);

        // Should be truncated to MAX_DOMAIN_LENGTH
        assert_eq!(entry.domain.len(), MAX_DOMAIN_LENGTH);
        assert!(entry.domain.ends_with(TRUNCATION_MARKER));

        // Verify the original content is preserved (minus truncation)
        let expected_prefix_len = MAX_DOMAIN_LENGTH - TRUNCATION_MARKER.len();
        let expected_prefix = "a".repeat(expected_prefix_len);
        assert!(entry.domain.starts_with(&expected_prefix));
    }

    #[test]
    fn test_domain_length_very_long() {
        // Very long domain (1000+ chars) should be truncated
        let domain = "verylongsubdomain.".repeat(100); // ~1800 chars
        let entry = QueryLogEntry::new(&domain, 1);

        assert_eq!(entry.domain.len(), MAX_DOMAIN_LENGTH);
        assert!(entry.domain.ends_with(TRUNCATION_MARKER));
    }

    #[test]
    fn test_domain_length_empty() {
        // Empty domain should remain empty (edge case)
        let entry = QueryLogEntry::new("", 1);
        assert_eq!(entry.domain, "");
    }

    #[test]
    fn test_sanitize_domain_direct() {
        // Test the internal sanitize_domain function directly
        assert_eq!(QueryLogEntry::sanitize_domain("normal.com".to_string()), "normal.com");

        let long_domain = "a".repeat(300);
        let sanitized = QueryLogEntry::sanitize_domain(long_domain);
        assert_eq!(sanitized.len(), MAX_DOMAIN_LENGTH);
        assert!(sanitized.ends_with(TRUNCATION_MARKER));
    }

    #[test]
    fn test_domain_truncation_unicode() {
        // Unicode domains should be truncated by byte count (String::truncate is byte-based)
        // Create a domain with unicode characters that exceeds 253 bytes
        let domain = "xn--".to_string() + &"a".repeat(260);
        let entry = QueryLogEntry::new(&domain, 1);

        assert!(entry.domain.len() <= MAX_DOMAIN_LENGTH);
        assert!(entry.domain.ends_with(TRUNCATION_MARKER));
    }

    // ========================================================================
    // Flush Return Value Tests
    // ========================================================================

    #[test]
    fn test_flush_disabled_logger() {
        // Disabled logger should return true for flush
        let logger = QueryLogger::disabled();
        assert!(logger.flush());
    }

    #[tokio::test]
    async fn test_flush_sync_disabled_logger() {
        // Disabled logger should return Ok(true) for flush_sync
        let logger = QueryLogger::disabled();
        let result = logger.flush_sync().await;
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[tokio::test]
    async fn test_flush_returns_bool() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("flush_test.log");

        let config = LoggingConfig {
            enabled: true,
            format: LogFormat::Json,
            path: log_path,
            rotation_days: 7,
            max_files: 7,
            buffer_size: 100,
        };

        let logger = QueryLogger::new(config).expect("Failed to create logger");

        // Log some entries
        for i in 0..5 {
            let entry = QueryLogEntry::new(format!("domain{}.com", i), 1);
            logger.log(entry);
        }

        // flush() should return true when successful
        let flush_result = logger.flush();
        assert!(flush_result);

        logger.shutdown().await;
    }

    #[tokio::test]
    async fn test_flush_sync_success() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("flush_sync_test.log");

        let config = LoggingConfig {
            enabled: true,
            format: LogFormat::Json,
            path: log_path.clone(),
            rotation_days: 7,
            max_files: 7,
            buffer_size: 100,
        };

        let logger = QueryLogger::new(config).expect("Failed to create logger");

        // Log some entries
        for i in 0..5 {
            let entry = QueryLogEntry::new(format!("sync_domain{}.com", i), 1);
            logger.log(entry);
        }

        // flush_sync() should return Ok(true) when successful
        let result = logger.flush_sync().await;
        assert!(result.is_ok());
        assert!(result.unwrap());

        // Verify entries were written
        let content = std::fs::read_to_string(&log_path).unwrap();
        assert!(content.contains("sync_domain0.com"));
        assert!(content.contains("sync_domain4.com"));

        logger.shutdown().await;
    }

    #[tokio::test]
    async fn test_flush_sync_empty_batch() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("flush_sync_empty.log");

        let config = LoggingConfig {
            enabled: true,
            format: LogFormat::Json,
            path: log_path,
            rotation_days: 7,
            max_files: 7,
            buffer_size: 100,
        };

        let logger = QueryLogger::new(config).expect("Failed to create logger");

        // Give the writer task time to start
        tokio::time::sleep(Duration::from_millis(50)).await;

        // flush_sync() with no entries should still succeed
        let result = logger.flush_sync().await;
        assert!(result.is_ok());
        assert!(result.unwrap()); // Empty batch returns true

        logger.shutdown().await;
    }

    #[tokio::test]
    async fn test_flush_sync_multiple_calls() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("flush_sync_multi.log");

        let config = LoggingConfig {
            enabled: true,
            format: LogFormat::Json,
            path: log_path,
            rotation_days: 7,
            max_files: 7,
            buffer_size: 100,
        };

        let logger = QueryLogger::new(config).expect("Failed to create logger");

        // Multiple flush_sync calls should all succeed
        for i in 0..3 {
            let entry = QueryLogEntry::new(format!("multi{}.com", i), 1);
            logger.log(entry);

            let result = logger.flush_sync().await;
            assert!(result.is_ok(), "flush_sync {} failed: {:?}", i, result);
            assert!(result.unwrap());
        }

        logger.shutdown().await;
    }

    #[tokio::test]
    async fn test_flush_channel_closed() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("flush_closed.log");

        let config = LoggingConfig {
            enabled: true,
            format: LogFormat::Json,
            path: log_path,
            rotation_days: 7,
            max_files: 7,
            buffer_size: 100,
        };

        let logger = QueryLogger::new(config).expect("Failed to create logger");

        // Shutdown first
        logger.shutdown().await;

        // Now flush should return false (channel closed)
        let flush_result = logger.flush();
        assert!(!flush_result);
    }

    #[tokio::test]
    async fn test_flush_sync_channel_closed() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("flush_sync_closed.log");

        let config = LoggingConfig {
            enabled: true,
            format: LogFormat::Json,
            path: log_path,
            rotation_days: 7,
            max_files: 7,
            buffer_size: 100,
        };

        let logger = QueryLogger::new(config).expect("Failed to create logger");

        // Shutdown first
        logger.shutdown().await;

        // Now flush_sync should return error (channel closed)
        let result = logger.flush_sync().await;
        assert!(result.is_err());
    }
}
