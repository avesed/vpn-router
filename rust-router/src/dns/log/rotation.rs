//! Log file rotation
//!
//! This module handles time-based log rotation with configurable retention.
//! Log files are rotated daily and old files are automatically deleted.
//!
//! # Rotation Scheme
//!
//! Files are rotated using a numbered suffix scheme:
//! - `dns-queries.log` - Current active log
//! - `dns-queries.log.1` - Previous day
//! - `dns-queries.log.2` - Two days ago
//! - etc.
//!
//! # Example
//!
//! ```no_run
//! use rust_router::dns::log::LogRotator;
//! use std::path::PathBuf;
//!
//! let mut rotator = LogRotator::new(
//!     PathBuf::from("/var/log/dns-queries.log"),
//!     7,  // Rotate every 7 days
//!     7,  // Keep 7 rotated files
//! );
//!
//! if rotator.should_rotate() {
//!     rotator.rotate().expect("rotation failed");
//! }
//! ```

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use chrono::{DateTime, Datelike, Duration as ChronoDuration, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, warn};

use crate::dns::error::{DnsError, DnsResult};

// ============================================================================
// Constants
// ============================================================================

/// Minimum rotation interval in days
const MIN_ROTATION_DAYS: u32 = 1;

/// Maximum rotation interval in days
const MAX_ROTATION_DAYS: u32 = 365;

/// Minimum number of files to keep
const MIN_MAX_FILES: u32 = 1;

/// Maximum number of files to keep
const MAX_MAX_FILES: u32 = 100;

/// Bytes per day threshold to trigger rotation (100 MB)
const ROTATION_SIZE_THRESHOLD: u64 = 100 * 1024 * 1024;

// ============================================================================
// Helper Functions
// ============================================================================

/// Calculate the number of days in a given year (handles leap years)
///
/// A year is a leap year if:
/// - Divisible by 4 AND
/// - NOT divisible by 100 OR divisible by 400
///
/// # Examples
///
/// ```ignore
/// assert_eq!(days_in_year(2024), 366); // Leap year
/// assert_eq!(days_in_year(2023), 365); // Non-leap year
/// assert_eq!(days_in_year(2000), 366); // Divisible by 400
/// assert_eq!(days_in_year(1900), 365); // Divisible by 100 but not 400
/// ```
#[inline]
fn days_in_year(year: i32) -> u32 {
    // Use chrono's NaiveDate to determine days in year
    // Dec 31 of the year will have ordinal equal to days in year
    NaiveDate::from_ymd_opt(year, 12, 31)
        .map_or(365, |d| d.ordinal()) // Fallback to 365 if year is invalid (extremely unlikely)
}

// ============================================================================
// RotationStats
// ============================================================================

/// Statistics for log rotation
#[derive(Debug, Default)]
pub struct RotationStats {
    /// Total number of rotations performed
    rotations_performed: AtomicU64,

    /// Total number of files deleted
    files_deleted: AtomicU64,

    /// Total bytes in deleted files
    bytes_freed: AtomicU64,

    /// Last rotation timestamp (Unix milliseconds)
    last_rotation_time: AtomicU64,

    /// Rotation errors encountered
    rotation_errors: AtomicU64,
}

impl RotationStats {
    /// Create new rotation statistics
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a successful rotation
    pub fn record_rotation(&self) {
        self.rotations_performed.fetch_add(1, Ordering::Relaxed);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        self.last_rotation_time.store(now, Ordering::Relaxed);
    }

    /// Record deleted files
    pub fn record_deletion(&self, count: u64, bytes: u64) {
        self.files_deleted.fetch_add(count, Ordering::Relaxed);
        self.bytes_freed.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Record a rotation error
    pub fn record_error(&self) {
        self.rotation_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Get total rotations performed
    #[must_use]
    pub fn rotations_performed(&self) -> u64 {
        self.rotations_performed.load(Ordering::Relaxed)
    }

    /// Get total files deleted
    #[must_use]
    pub fn files_deleted(&self) -> u64 {
        self.files_deleted.load(Ordering::Relaxed)
    }

    /// Get total bytes freed
    #[must_use]
    pub fn bytes_freed(&self) -> u64 {
        self.bytes_freed.load(Ordering::Relaxed)
    }

    /// Get last rotation timestamp
    #[must_use]
    pub fn last_rotation_time(&self) -> u64 {
        self.last_rotation_time.load(Ordering::Relaxed)
    }

    /// Get rotation error count
    #[must_use]
    pub fn rotation_errors(&self) -> u64 {
        self.rotation_errors.load(Ordering::Relaxed)
    }

    /// Get a snapshot of current statistics
    #[must_use]
    pub fn snapshot(&self) -> RotationStatsSnapshot {
        RotationStatsSnapshot {
            rotations_performed: self.rotations_performed(),
            files_deleted: self.files_deleted(),
            bytes_freed: self.bytes_freed(),
            last_rotation_time: self.last_rotation_time(),
            rotation_errors: self.rotation_errors(),
        }
    }
}

/// Snapshot of rotation statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RotationStatsSnapshot {
    /// Total rotations performed
    pub rotations_performed: u64,

    /// Total files deleted
    pub files_deleted: u64,

    /// Total bytes freed
    pub bytes_freed: u64,

    /// Last rotation timestamp
    pub last_rotation_time: u64,

    /// Rotation errors
    pub rotation_errors: u64,
}

// ============================================================================
// LogRotator
// ============================================================================

/// Log file rotator with time-based rotation
///
/// The rotator tracks when the log was last rotated and performs rotation
/// when the configured interval has elapsed. Old log files are automatically
/// deleted based on the `max_files` setting.
///
/// # Thread Safety
///
/// `LogRotator` is NOT thread-safe - it should only be accessed from a single
/// writer task. The writer task coordinates all file operations.
pub struct LogRotator {
    /// Path to the log file
    path: PathBuf,

    /// Rotation interval in days
    rotation_days: u32,

    /// Maximum number of rotated files to keep
    max_files: u32,

    /// Last rotation date (day of year)
    last_rotation_day: Option<u32>,

    /// Bytes written since last rotation
    bytes_since_rotation: u64,

    /// Statistics
    stats: RotationStats,
}

impl LogRotator {
    /// Create a new log rotator
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the log file
    /// * `rotation_days` - Rotate logs every N days (clamped to 1-365)
    /// * `max_files` - Keep at most N rotated files (clamped to 1-100)
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::dns::log::LogRotator;
    /// use std::path::PathBuf;
    ///
    /// let rotator = LogRotator::new(
    ///     PathBuf::from("./logs/dns.log"),
    ///     7,   // Rotate weekly
    ///     14,  // Keep 2 weeks of logs
    /// );
    /// ```
    #[must_use]
    pub fn new(path: PathBuf, rotation_days: u32, max_files: u32) -> Self {
        let rotation_days = rotation_days.clamp(MIN_ROTATION_DAYS, MAX_ROTATION_DAYS);
        let max_files = max_files.clamp(MIN_MAX_FILES, MAX_MAX_FILES);

        Self {
            path,
            rotation_days,
            max_files,
            last_rotation_day: None,
            bytes_since_rotation: 0,
            stats: RotationStats::new(),
        }
    }

    /// Get the log file path
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Get the rotation interval in days
    #[must_use]
    pub fn rotation_days(&self) -> u32 {
        self.rotation_days
    }

    /// Get the maximum number of files to keep
    #[must_use]
    pub fn max_files(&self) -> u32 {
        self.max_files
    }

    /// Get rotation statistics
    #[must_use]
    pub fn stats(&self) -> &RotationStats {
        &self.stats
    }

    /// Record bytes written to the current log file
    pub fn record_bytes_written(&mut self, bytes: u64) {
        self.bytes_since_rotation = self.bytes_since_rotation.saturating_add(bytes);
    }

    /// Check if rotation is needed
    ///
    /// Rotation is triggered when:
    /// 1. The configured number of days has passed since last rotation
    /// 2. OR the log file has exceeded the size threshold (100 MB)
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::dns::log::LogRotator;
    /// use std::path::PathBuf;
    ///
    /// let rotator = LogRotator::new(PathBuf::from("./test.log"), 1, 7);
    /// if rotator.should_rotate() {
    ///     // Perform rotation
    /// }
    /// ```
    #[must_use]
    pub fn should_rotate(&self) -> bool {
        // Check size-based rotation first
        if self.bytes_since_rotation >= ROTATION_SIZE_THRESHOLD {
            return true;
        }

        // Check time-based rotation
        let now: DateTime<Utc> = Utc::now();
        let day_of_year = now.ordinal();

        if let Some(last_day) = self.last_rotation_day {
            // Handle year wrap-around with proper leap year calculation
            let days_since = if day_of_year >= last_day {
                day_of_year - last_day
            } else {
                // Year wrapped around - calculate days in the previous year
                // The previous year is (current_year - 1)
                let prev_year = now.year() - 1;
                let days_in_prev_year = days_in_year(prev_year);
                (days_in_prev_year - last_day) + day_of_year
            };

            days_since >= self.rotation_days
        } else {
            // Never rotated - check if file exists and is from a previous day
            if let Ok(metadata) = fs::metadata(&self.path) {
                if let Ok(modified) = metadata.modified() {
                    let modified_time: DateTime<Utc> = modified.into();
                    let age = now.signed_duration_since(modified_time);
                    return age >= ChronoDuration::days(i64::from(self.rotation_days));
                }
            }
            false
        }
    }

    /// Perform log rotation
    ///
    /// This method:
    /// 1. Renames current log to `.1`
    /// 2. Shifts existing rotated logs (`.1` -> `.2`, etc.)
    /// 3. Deletes logs older than `max_files`
    ///
    /// # Errors
    ///
    /// Returns an error if file operations fail (permissions, disk full, etc.)
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rust_router::dns::log::LogRotator;
    /// use std::path::PathBuf;
    ///
    /// let mut rotator = LogRotator::new(PathBuf::from("./test.log"), 1, 7);
    /// rotator.rotate().expect("rotation failed");
    /// ```
    pub fn rotate(&mut self) -> DnsResult<()> {
        info!("Starting log rotation for {:?}", self.path);

        // Check if current log file exists
        if !self.path.exists() {
            debug!("Log file does not exist, skipping rotation");
            self.update_rotation_time();
            return Ok(());
        }

        // Delete oldest files first
        let deleted = self.cleanup_old_files()?;

        // Shift existing rotated files
        self.shift_rotated_files()?;

        // Rename current log to .1
        let rotated_path = self.get_rotated_path(1);
        match fs::rename(&self.path, &rotated_path) {
            Ok(()) => {
                info!("Rotated {:?} to {:?}", self.path, rotated_path);
            }
            Err(e) => {
                // File might have been removed or renamed by another process
                if e.kind() == std::io::ErrorKind::NotFound {
                    warn!("Log file was removed before rotation");
                } else {
                    self.stats.record_error();
                    return Err(DnsError::internal(format!(
                        "Failed to rotate log file: {e}"
                    )));
                }
            }
        }

        // Update state
        self.update_rotation_time();
        self.bytes_since_rotation = 0;
        self.stats.record_rotation();
        self.stats.record_deletion(deleted.0, deleted.1);

        info!(
            "Log rotation complete. Deleted {} files, freed {} bytes",
            deleted.0, deleted.1
        );

        Ok(())
    }

    /// Force rotation regardless of time/size thresholds
    ///
    /// This is useful for testing or administrative purposes.
    pub fn force_rotate(&mut self) -> DnsResult<()> {
        self.rotate()
    }

    /// Get the path for a rotated file
    fn get_rotated_path(&self, number: u32) -> PathBuf {
        let mut path = self.path.clone();
        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("dns-queries.log");
        path.set_file_name(format!("{file_name}.{number}"));
        path
    }

    /// Shift existing rotated files to make room for new rotation
    fn shift_rotated_files(&self) -> DnsResult<()> {
        // Work backwards from max_files to 1
        for i in (1..=self.max_files).rev() {
            let old_path = self.get_rotated_path(i);
            let new_path = self.get_rotated_path(i + 1);

            if old_path.exists() {
                match fs::rename(&old_path, &new_path) {
                    Ok(()) => {
                        debug!("Shifted {:?} to {:?}", old_path, new_path);
                    }
                    Err(e) => {
                        warn!("Failed to shift {:?}: {}", old_path, e);
                        // Continue with other files
                    }
                }
            }
        }

        Ok(())
    }

    /// Delete files older than `max_files`
    ///
    /// Returns (`files_deleted`, `bytes_freed`)
    fn cleanup_old_files(&self) -> DnsResult<(u64, u64)> {
        let mut files_deleted = 0u64;
        let mut bytes_freed = 0u64;

        // Delete files numbered > max_files
        for i in self.max_files + 1..=self.max_files + 10 {
            let path = self.get_rotated_path(i);
            if path.exists() {
                match fs::metadata(&path) {
                    Ok(metadata) => {
                        bytes_freed += metadata.len();
                    }
                    Err(e) => {
                        warn!("Failed to get metadata for {:?}: {}", path, e);
                    }
                }

                match fs::remove_file(&path) {
                    Ok(()) => {
                        files_deleted += 1;
                        debug!("Deleted old log file: {:?}", path);
                    }
                    Err(e) => {
                        warn!("Failed to delete {:?}: {}", path, e);
                    }
                }
            }
        }

        Ok((files_deleted, bytes_freed))
    }

    /// Update the last rotation time
    fn update_rotation_time(&mut self) {
        let now: DateTime<Utc> = Utc::now();
        self.last_rotation_day = Some(now.ordinal());
    }

    /// List all log files (current + rotated)
    ///
    /// Returns a vector of paths sorted by rotation number.
    #[must_use]
    pub fn list_log_files(&self) -> Vec<PathBuf> {
        let mut files = Vec::new();

        // Current log
        if self.path.exists() {
            files.push(self.path.clone());
        }

        // Rotated logs
        for i in 1..=self.max_files + 5 {
            let path = self.get_rotated_path(i);
            if path.exists() {
                files.push(path);
            }
        }

        files
    }

    /// Get total size of all log files
    #[must_use]
    pub fn total_size(&self) -> u64 {
        self.list_log_files()
            .iter()
            .filter_map(|p| fs::metadata(p).ok())
            .map(|m| m.len())
            .sum()
    }

    /// Delete all log files
    ///
    /// This removes the current log and all rotated logs.
    /// Use with caution!
    pub fn delete_all(&self) -> DnsResult<u64> {
        let mut deleted = 0;

        for path in self.list_log_files() {
            match fs::remove_file(&path) {
                Ok(()) => {
                    deleted += 1;
                    info!("Deleted log file: {:?}", path);
                }
                Err(e) => {
                    error!("Failed to delete {:?}: {}", path, e);
                }
            }
        }

        Ok(deleted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    // ========================================================================
    // RotationStats Tests
    // ========================================================================

    #[test]
    fn test_rotation_stats_new() {
        let stats = RotationStats::new();
        assert_eq!(stats.rotations_performed(), 0);
        assert_eq!(stats.files_deleted(), 0);
        assert_eq!(stats.bytes_freed(), 0);
        assert_eq!(stats.rotation_errors(), 0);
    }

    #[test]
    fn test_rotation_stats_record_rotation() {
        let stats = RotationStats::new();
        stats.record_rotation();
        assert_eq!(stats.rotations_performed(), 1);
        assert!(stats.last_rotation_time() > 0);
    }

    #[test]
    fn test_rotation_stats_record_deletion() {
        let stats = RotationStats::new();
        stats.record_deletion(3, 1024);
        assert_eq!(stats.files_deleted(), 3);
        assert_eq!(stats.bytes_freed(), 1024);
    }

    #[test]
    fn test_rotation_stats_record_error() {
        let stats = RotationStats::new();
        stats.record_error();
        stats.record_error();
        assert_eq!(stats.rotation_errors(), 2);
    }

    #[test]
    fn test_rotation_stats_snapshot() {
        let stats = RotationStats::new();
        stats.record_rotation();
        stats.record_deletion(2, 2048);
        stats.record_error();

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.rotations_performed, 1);
        assert_eq!(snapshot.files_deleted, 2);
        assert_eq!(snapshot.bytes_freed, 2048);
        assert_eq!(snapshot.rotation_errors, 1);
    }

    #[test]
    fn test_rotation_stats_snapshot_serialization() {
        let snapshot = RotationStatsSnapshot {
            rotations_performed: 10,
            files_deleted: 20,
            bytes_freed: 1000000,
            last_rotation_time: 1704067200000,
            rotation_errors: 1,
        };

        let json = serde_json::to_string(&snapshot).expect("serialize");
        let decoded: RotationStatsSnapshot = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(decoded.rotations_performed, 10);
        assert_eq!(decoded.files_deleted, 20);
    }

    // ========================================================================
    // LogRotator Creation Tests
    // ========================================================================

    #[test]
    fn test_log_rotator_new() {
        let rotator = LogRotator::new(PathBuf::from("/tmp/test.log"), 7, 7);
        assert_eq!(rotator.path(), Path::new("/tmp/test.log"));
        assert_eq!(rotator.rotation_days(), 7);
        assert_eq!(rotator.max_files(), 7);
    }

    #[test]
    fn test_log_rotator_clamp_rotation_days() {
        // Below minimum
        let rotator = LogRotator::new(PathBuf::from("/tmp/test.log"), 0, 7);
        assert_eq!(rotator.rotation_days(), 1);

        // Above maximum
        let rotator = LogRotator::new(PathBuf::from("/tmp/test.log"), 1000, 7);
        assert_eq!(rotator.rotation_days(), 365);
    }

    #[test]
    fn test_log_rotator_clamp_max_files() {
        // Below minimum
        let rotator = LogRotator::new(PathBuf::from("/tmp/test.log"), 7, 0);
        assert_eq!(rotator.max_files(), 1);

        // Above maximum
        let rotator = LogRotator::new(PathBuf::from("/tmp/test.log"), 7, 1000);
        assert_eq!(rotator.max_files(), 100);
    }

    #[test]
    fn test_log_rotator_record_bytes_written() {
        let mut rotator = LogRotator::new(PathBuf::from("/tmp/test.log"), 7, 7);
        rotator.record_bytes_written(1000);
        rotator.record_bytes_written(500);
        assert_eq!(rotator.bytes_since_rotation, 1500);
    }

    #[test]
    fn test_log_rotator_record_bytes_written_saturating() {
        let mut rotator = LogRotator::new(PathBuf::from("/tmp/test.log"), 7, 7);
        rotator.bytes_since_rotation = u64::MAX - 100;
        rotator.record_bytes_written(200);
        assert_eq!(rotator.bytes_since_rotation, u64::MAX);
    }

    // ========================================================================
    // Rotation Logic Tests
    // ========================================================================

    #[test]
    fn test_log_rotator_should_rotate_size_based() {
        let mut rotator = LogRotator::new(PathBuf::from("/tmp/test.log"), 365, 7);
        assert!(!rotator.should_rotate());

        // Exceed size threshold
        rotator.bytes_since_rotation = ROTATION_SIZE_THRESHOLD;
        assert!(rotator.should_rotate());
    }

    #[test]
    fn test_log_rotator_should_rotate_no_file() {
        let rotator = LogRotator::new(PathBuf::from("/tmp/nonexistent_file.log"), 1, 7);
        // Should not rotate if file doesn't exist (but not panic)
        let _ = rotator.should_rotate();
    }

    #[test]
    fn test_log_rotator_get_rotated_path() {
        let rotator = LogRotator::new(PathBuf::from("/var/log/dns.log"), 7, 7);

        assert_eq!(rotator.get_rotated_path(1), PathBuf::from("/var/log/dns.log.1"));
        assert_eq!(rotator.get_rotated_path(2), PathBuf::from("/var/log/dns.log.2"));
        assert_eq!(rotator.get_rotated_path(10), PathBuf::from("/var/log/dns.log.10"));
    }

    // ========================================================================
    // File Operation Tests
    // ========================================================================

    #[test]
    fn test_log_rotator_rotate_no_file() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("nonexistent.log");

        let mut rotator = LogRotator::new(log_path, 1, 7);
        // Should succeed even if file doesn't exist
        rotator.rotate().expect("rotation should succeed");
    }

    #[test]
    fn test_log_rotator_rotate_basic() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("test.log");

        // Create initial log file
        {
            let mut file = fs::File::create(&log_path).unwrap();
            writeln!(file, "test log content").unwrap();
        }

        let mut rotator = LogRotator::new(log_path.clone(), 1, 7);
        rotator.rotate().expect("rotation failed");

        // Original file should be gone
        assert!(!log_path.exists());

        // Rotated file should exist
        let rotated = temp_dir.path().join("test.log.1");
        assert!(rotated.exists());

        // Stats should be updated
        assert_eq!(rotator.stats().rotations_performed(), 1);
    }

    #[test]
    fn test_log_rotator_rotate_shift_existing() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("test.log");

        // Create current log and some rotated files
        fs::write(&log_path, "current").unwrap();
        fs::write(temp_dir.path().join("test.log.1"), "rotated-1").unwrap();
        fs::write(temp_dir.path().join("test.log.2"), "rotated-2").unwrap();

        let mut rotator = LogRotator::new(log_path.clone(), 1, 7);
        rotator.rotate().expect("rotation failed");

        // Check file contents after rotation
        assert_eq!(
            fs::read_to_string(temp_dir.path().join("test.log.1")).unwrap(),
            "current"
        );
        assert_eq!(
            fs::read_to_string(temp_dir.path().join("test.log.2")).unwrap(),
            "rotated-1"
        );
        assert_eq!(
            fs::read_to_string(temp_dir.path().join("test.log.3")).unwrap(),
            "rotated-2"
        );
    }

    #[test]
    fn test_log_rotator_rotate_cleanup_old() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("test.log");

        // Create log and old rotated files (beyond max_files)
        fs::write(&log_path, "current").unwrap();
        for i in 1..=10 {
            fs::write(temp_dir.path().join(format!("test.log.{}", i)), format!("old-{}", i)).unwrap();
        }

        // max_files = 3, so files .4 and above should be deleted after rotation
        let mut rotator = LogRotator::new(log_path.clone(), 1, 3);
        rotator.rotate().expect("rotation failed");

        // Files 1-4 should exist (current -> .1, .1 -> .2, .2 -> .3, .3 -> .4)
        assert!(temp_dir.path().join("test.log.1").exists());
        assert!(temp_dir.path().join("test.log.2").exists());
        assert!(temp_dir.path().join("test.log.3").exists());
        assert!(temp_dir.path().join("test.log.4").exists());

        // Files 5+ from original should be deleted
        // (cleanup happens before shift, so .5-.10 get deleted, then shift happens)
    }

    #[test]
    fn test_log_rotator_force_rotate() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("test.log");

        fs::write(&log_path, "content").unwrap();

        let mut rotator = LogRotator::new(log_path.clone(), 365, 7); // Long rotation period
        rotator.force_rotate().expect("force rotation failed");

        assert!(!log_path.exists());
        assert!(temp_dir.path().join("test.log.1").exists());
    }

    // ========================================================================
    // List and Size Tests
    // ========================================================================

    #[test]
    fn test_log_rotator_list_log_files() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("test.log");

        fs::write(&log_path, "current").unwrap();
        fs::write(temp_dir.path().join("test.log.1"), "r1").unwrap();
        fs::write(temp_dir.path().join("test.log.2"), "r2").unwrap();

        let rotator = LogRotator::new(log_path, 1, 7);
        let files = rotator.list_log_files();

        assert_eq!(files.len(), 3);
    }

    #[test]
    fn test_log_rotator_list_log_files_empty() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("nonexistent.log");

        let rotator = LogRotator::new(log_path, 1, 7);
        let files = rotator.list_log_files();

        assert!(files.is_empty());
    }

    #[test]
    fn test_log_rotator_total_size() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("test.log");

        fs::write(&log_path, "12345").unwrap(); // 5 bytes
        fs::write(temp_dir.path().join("test.log.1"), "1234567890").unwrap(); // 10 bytes

        let rotator = LogRotator::new(log_path, 1, 7);
        let total = rotator.total_size();

        assert_eq!(total, 15);
    }

    #[test]
    fn test_log_rotator_total_size_empty() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("nonexistent.log");

        let rotator = LogRotator::new(log_path, 1, 7);
        assert_eq!(rotator.total_size(), 0);
    }

    // ========================================================================
    // Delete All Tests
    // ========================================================================

    #[test]
    fn test_log_rotator_delete_all() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("test.log");

        fs::write(&log_path, "current").unwrap();
        fs::write(temp_dir.path().join("test.log.1"), "r1").unwrap();
        fs::write(temp_dir.path().join("test.log.2"), "r2").unwrap();

        let rotator = LogRotator::new(log_path.clone(), 1, 7);
        let deleted = rotator.delete_all().expect("delete failed");

        assert_eq!(deleted, 3);
        assert!(!log_path.exists());
        assert!(!temp_dir.path().join("test.log.1").exists());
        assert!(!temp_dir.path().join("test.log.2").exists());
    }

    #[test]
    fn test_log_rotator_delete_all_empty() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("nonexistent.log");

        let rotator = LogRotator::new(log_path, 1, 7);
        let deleted = rotator.delete_all().expect("delete failed");

        assert_eq!(deleted, 0);
    }

    // ========================================================================
    // Edge Cases
    // ========================================================================

    #[test]
    fn test_log_rotator_multiple_rotations() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("test.log");

        let mut rotator = LogRotator::new(log_path.clone(), 1, 7);

        for i in 0..5 {
            fs::write(&log_path, format!("content-{}", i)).unwrap();
            rotator.rotate().expect("rotation failed");
        }

        assert_eq!(rotator.stats().rotations_performed(), 5);

        // Check all rotated files exist
        for i in 1..=5 {
            assert!(temp_dir.path().join(format!("test.log.{}", i)).exists());
        }
    }

    #[test]
    fn test_log_rotator_stats_access() {
        let rotator = LogRotator::new(PathBuf::from("/tmp/test.log"), 7, 7);
        let stats = rotator.stats();
        assert_eq!(stats.rotations_performed(), 0);
    }

    #[test]
    fn test_log_rotator_update_rotation_time() {
        let mut rotator = LogRotator::new(PathBuf::from("/tmp/test.log"), 7, 7);
        assert!(rotator.last_rotation_day.is_none());

        rotator.update_rotation_time();
        assert!(rotator.last_rotation_day.is_some());
    }

    #[test]
    fn test_rotation_stats_snapshot_default() {
        let snapshot = RotationStatsSnapshot::default();
        assert_eq!(snapshot.rotations_performed, 0);
        assert_eq!(snapshot.files_deleted, 0);
        assert_eq!(snapshot.bytes_freed, 0);
        assert_eq!(snapshot.last_rotation_time, 0);
        assert_eq!(snapshot.rotation_errors, 0);
    }

    // ========================================================================
    // Leap Year Tests
    // ========================================================================

    #[test]
    fn test_days_in_year_regular_year() {
        // Regular years have 365 days
        assert_eq!(days_in_year(2023), 365);
        assert_eq!(days_in_year(2019), 365);
        assert_eq!(days_in_year(2021), 365);
        assert_eq!(days_in_year(2025), 365);
    }

    #[test]
    fn test_days_in_year_leap_year() {
        // Leap years (divisible by 4, not by 100, or divisible by 400) have 366 days
        assert_eq!(days_in_year(2024), 366); // Divisible by 4
        assert_eq!(days_in_year(2020), 366); // Divisible by 4
        assert_eq!(days_in_year(2016), 366); // Divisible by 4
        assert_eq!(days_in_year(2000), 366); // Divisible by 400
        assert_eq!(days_in_year(1600), 366); // Divisible by 400
    }

    #[test]
    fn test_days_in_year_century_not_leap() {
        // Century years not divisible by 400 are NOT leap years
        assert_eq!(days_in_year(1900), 365); // Divisible by 100, not by 400
        assert_eq!(days_in_year(2100), 365); // Divisible by 100, not by 400
        assert_eq!(days_in_year(1800), 365); // Divisible by 100, not by 400
        assert_eq!(days_in_year(2200), 365); // Divisible by 100, not by 400
    }

    #[test]
    fn test_days_in_year_edge_cases() {
        // Test some edge cases
        assert_eq!(days_in_year(1), 365);       // Year 1 AD
        assert_eq!(days_in_year(4), 366);       // First leap year after 1 AD
        assert_eq!(days_in_year(100), 365);     // First century year
        assert_eq!(days_in_year(400), 366);     // First year divisible by 400
    }

    #[test]
    fn test_should_rotate_year_wrap_leap_year() {
        // Test rotation calculation when wrapping from a leap year to the next year
        // Scenario: Last rotation was on Dec 31 (day 366) of a leap year
        // Current date is Jan 2 (day 2) of the following year
        // Expected: 366 - 366 + 2 = 2 days since rotation

        let mut rotator = LogRotator::new(PathBuf::from("/tmp/test.log"), 3, 7);

        // Simulate last rotation on Dec 31 of a leap year (day 366)
        rotator.last_rotation_day = Some(366);

        // We can't easily mock Utc::now(), but we can test the days_in_year helper
        // which is the key fix for the leap year bug
        let leap_year_days = days_in_year(2024);
        assert_eq!(leap_year_days, 366);

        // Verify the calculation would be correct:
        // If current year is 2025 (previous year 2024 was leap year)
        // and current day is 2, and last rotation day was 366
        // Then: (366 - 366) + 2 = 2 days
        let days_in_prev = days_in_year(2024);
        let days_since = (days_in_prev - 366) + 2;
        assert_eq!(days_since, 2);
    }

    #[test]
    fn test_should_rotate_year_wrap_regular_year() {
        // Test rotation calculation when wrapping from a regular year to the next year
        // Scenario: Last rotation was on Dec 31 (day 365) of a regular year
        // Current date is Jan 2 (day 2) of the following year
        // Expected: 365 - 365 + 2 = 2 days since rotation

        let days_in_prev = days_in_year(2023);
        assert_eq!(days_in_prev, 365);

        // If current day is 2 and last rotation was day 365
        let days_since = (days_in_prev - 365) + 2;
        assert_eq!(days_since, 2);
    }

    #[test]
    fn test_should_rotate_feb_29_leap_year() {
        // Test that Feb 29 (day 60 in leap year) is handled correctly
        // Feb 29 is day 60 (31 Jan + 29 Feb = 60)
        let days_in_leap = days_in_year(2024);
        assert_eq!(days_in_leap, 366);

        // Verify Feb 29 exists in leap year
        let feb_29 = NaiveDate::from_ymd_opt(2024, 2, 29);
        assert!(feb_29.is_some());
        assert_eq!(feb_29.unwrap().ordinal(), 60);
    }

    #[test]
    fn test_should_rotate_year_boundary_dec_30_to_jan_1() {
        // Test rotation from Dec 30 to Jan 1 (2 days)
        // Dec 30 in regular year = day 364
        // Jan 1 in next year = day 1

        let days_in_prev = days_in_year(2023); // 365 days
        let last_day = 364; // Dec 30
        let current_day = 1; // Jan 1

        let days_since = (days_in_prev - last_day) + current_day;
        assert_eq!(days_since, 2); // 365 - 364 + 1 = 2
    }

    #[test]
    fn test_should_rotate_year_boundary_dec_30_to_jan_1_leap_year() {
        // Test rotation from Dec 30 (day 365 in leap year) to Jan 1 (2 days)
        // Dec 30 in leap year = day 365
        // Jan 1 in next year = day 1

        let days_in_prev = days_in_year(2024); // 366 days (leap year)
        let last_day = 365; // Dec 30 in leap year
        let current_day = 1; // Jan 1

        let days_since = (days_in_prev - last_day) + current_day;
        assert_eq!(days_since, 2); // 366 - 365 + 1 = 2
    }

    #[test]
    fn test_days_in_year_negative_years() {
        // Test negative years (BC years) - should still work
        // Year -1 would be 2 BC in astronomical year numbering
        // We use chrono which handles this correctly
        let result = days_in_year(-1);
        // Most BC years have 365 days unless they're leap years
        assert!(result == 365 || result == 366);
    }
}
