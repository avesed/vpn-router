//! Session Cleanup Module for the VLESS-WG Bridge
//!
//! This module provides configuration and utilities for periodic session cleanup.
//! Instead of running cleanup on every poll (which could happen 1000+ times/second),
//! the cleanup runs as a separate timer-based task at a configurable interval.
//!
//! # Performance Optimization
//!
//! The original architecture called `cleanup_raw_udp_sessions()` on every poll,
//! causing unnecessary overhead. This module introduces:
//!
//! - **Independent cleanup interval**: Cleanup runs every 30 seconds by default
//! - **Configurable timeouts**: TCP and UDP timeouts can be tuned per deployment
//! - **Statistics tracking**: Track cleanup runs and sessions cleaned up
//!
//! # Usage
//!
//! The cleanup is integrated into the `SmoltcpShard::run()` method using a
//! `tokio::time::interval`. The cleanup timer has the lowest priority in the
//! `biased select!` loop, ensuring it doesn't interfere with packet processing.
//!
//! ```ignore
//! // Inside SmoltcpShard::run():
//! let mut cleanup_interval = tokio::time::interval(Duration::from_secs(30));
//!
//! loop {
//!     tokio::select! {
//!         biased;
//!
//!         // ... higher priority branches ...
//!
//!         // Lowest priority: periodic cleanup
//!         _ = cleanup_interval.tick() => {
//!             self.cleanup_expired_sessions();
//!         }
//!     }
//! }
//! ```

use std::time::Duration;

// =============================================================================
// Configuration Constants
// =============================================================================

/// Default cleanup interval in seconds
///
/// Sessions are checked for expiration at this interval. The interval is a
/// balance between:
/// - Too short: Wasted CPU cycles checking sessions that aren't expired
/// - Too long: Dead sessions consume resources longer than necessary
///
/// 30 seconds is a good default because:
/// - UDP DNS sessions (10s timeout) will be cleaned up within ~40s
/// - UDP regular sessions (30s timeout) will be cleaned up within ~60s
/// - TCP idle sessions (300s timeout) will be cleaned up within ~330s
pub const CLEANUP_INTERVAL_SECS: u64 = 30;

/// Default TCP idle timeout in seconds (5 minutes)
///
/// TCP connections with no activity for this duration are considered dead
/// and will be cleaned up. This matches common TCP keepalive intervals.
pub const TCP_IDLE_TIMEOUT_SECS: u64 = 300;

/// Default UDP timeout in seconds (30 seconds)
///
/// UDP sessions with no activity for this duration are considered expired.
/// This is appropriate for most UDP applications (games, VoIP, etc.).
pub const UDP_DEFAULT_TIMEOUT_SECS: u64 = 30;

/// DNS UDP timeout in seconds (10 seconds)
///
/// DNS queries should complete quickly, so we use a shorter timeout.
/// This allows faster resource reclamation for DNS sessions.
pub const UDP_DNS_TIMEOUT_SECS: u64 = 10;

// =============================================================================
// Configuration Struct
// =============================================================================

/// Configuration for session cleanup behavior
///
/// This struct allows customization of cleanup timing and session timeouts.
/// Use `CleanupConfig::default()` for reasonable defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CleanupConfig {
    /// How often to run cleanup (in seconds)
    pub cleanup_interval_secs: u64,

    /// TCP idle timeout (in seconds)
    ///
    /// TCP connections with no activity for this duration are closed.
    pub tcp_idle_timeout_secs: u64,

    /// UDP default timeout (in seconds)
    ///
    /// Non-DNS UDP sessions expire after this duration of inactivity.
    pub udp_default_timeout_secs: u64,

    /// UDP DNS timeout (in seconds)
    ///
    /// DNS (port 53) UDP sessions expire after this shorter duration.
    pub udp_dns_timeout_secs: u64,
}

impl CleanupConfig {
    /// Create a new cleanup configuration with custom values
    #[must_use]
    pub const fn new(
        cleanup_interval_secs: u64,
        tcp_idle_timeout_secs: u64,
        udp_default_timeout_secs: u64,
        udp_dns_timeout_secs: u64,
    ) -> Self {
        Self {
            cleanup_interval_secs,
            tcp_idle_timeout_secs,
            udp_default_timeout_secs,
            udp_dns_timeout_secs,
        }
    }

    /// Get the cleanup interval as a Duration
    #[must_use]
    #[inline]
    pub const fn cleanup_interval(&self) -> Duration {
        Duration::from_secs(self.cleanup_interval_secs)
    }

    /// Get the TCP idle timeout as a Duration
    #[must_use]
    #[inline]
    pub const fn tcp_idle_timeout(&self) -> Duration {
        Duration::from_secs(self.tcp_idle_timeout_secs)
    }

    /// Get the UDP default timeout as a Duration
    #[must_use]
    #[inline]
    pub const fn udp_default_timeout(&self) -> Duration {
        Duration::from_secs(self.udp_default_timeout_secs)
    }

    /// Get the UDP DNS timeout as a Duration
    #[must_use]
    #[inline]
    pub const fn udp_dns_timeout(&self) -> Duration {
        Duration::from_secs(self.udp_dns_timeout_secs)
    }

    /// Create a configuration optimized for high-traffic scenarios
    ///
    /// Uses shorter cleanup intervals and timeouts to free resources faster.
    #[must_use]
    pub const fn high_traffic() -> Self {
        Self {
            cleanup_interval_secs: 15,      // More frequent cleanup
            tcp_idle_timeout_secs: 120,     // 2 minutes
            udp_default_timeout_secs: 15,   // 15 seconds
            udp_dns_timeout_secs: 5,        // 5 seconds
        }
    }

    /// Create a configuration optimized for low-memory systems
    ///
    /// Uses aggressive cleanup to minimize resource usage.
    #[must_use]
    pub const fn low_memory() -> Self {
        Self {
            cleanup_interval_secs: 10,      // Very frequent cleanup
            tcp_idle_timeout_secs: 60,      // 1 minute
            udp_default_timeout_secs: 10,   // 10 seconds
            udp_dns_timeout_secs: 5,        // 5 seconds
        }
    }

    /// Create a configuration optimized for long-lived connections
    ///
    /// Uses longer timeouts for scenarios with persistent connections.
    #[must_use]
    pub const fn long_lived() -> Self {
        Self {
            cleanup_interval_secs: 60,       // Less frequent cleanup
            tcp_idle_timeout_secs: 600,      // 10 minutes
            udp_default_timeout_secs: 120,   // 2 minutes
            udp_dns_timeout_secs: 30,        // 30 seconds
        }
    }
}

impl Default for CleanupConfig {
    fn default() -> Self {
        Self {
            cleanup_interval_secs: CLEANUP_INTERVAL_SECS,
            tcp_idle_timeout_secs: TCP_IDLE_TIMEOUT_SECS,
            udp_default_timeout_secs: UDP_DEFAULT_TIMEOUT_SECS,
            udp_dns_timeout_secs: UDP_DNS_TIMEOUT_SECS,
        }
    }
}

// =============================================================================
// Cleanup Statistics
// =============================================================================

/// Statistics tracked during cleanup operations
///
/// These statistics help monitor the health and efficiency of session cleanup.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct CleanupStats {
    /// Number of cleanup runs executed
    pub cleanup_runs: u64,

    /// TCP sessions that timed out (idle too long)
    pub tcp_sessions_timed_out: u64,

    /// UDP sessions that expired
    pub udp_sessions_expired: u64,

    /// TCP sessions cleaned up due to closed reply channel
    pub tcp_sessions_channel_closed: u64,

    /// UDP sessions cleaned up due to closed reply channel
    pub udp_sessions_channel_closed: u64,
}

impl CleanupStats {
    /// Create new cleanup statistics with all zeros
    #[must_use]
    pub const fn new() -> Self {
        Self {
            cleanup_runs: 0,
            tcp_sessions_timed_out: 0,
            udp_sessions_expired: 0,
            tcp_sessions_channel_closed: 0,
            udp_sessions_channel_closed: 0,
        }
    }

    /// Get the total number of sessions cleaned up
    #[must_use]
    pub const fn total_cleaned(&self) -> u64 {
        self.tcp_sessions_timed_out
            .saturating_add(self.udp_sessions_expired)
            .saturating_add(self.tcp_sessions_channel_closed)
            .saturating_add(self.udp_sessions_channel_closed)
    }

    /// Get the total TCP sessions cleaned up
    #[must_use]
    pub const fn tcp_total(&self) -> u64 {
        self.tcp_sessions_timed_out
            .saturating_add(self.tcp_sessions_channel_closed)
    }

    /// Get the total UDP sessions cleaned up
    #[must_use]
    pub const fn udp_total(&self) -> u64 {
        self.udp_sessions_expired
            .saturating_add(self.udp_sessions_channel_closed)
    }

    /// Merge another CleanupStats into this one
    pub fn merge(&mut self, other: &CleanupStats) {
        self.cleanup_runs = self.cleanup_runs.saturating_add(other.cleanup_runs);
        self.tcp_sessions_timed_out = self.tcp_sessions_timed_out.saturating_add(other.tcp_sessions_timed_out);
        self.udp_sessions_expired = self.udp_sessions_expired.saturating_add(other.udp_sessions_expired);
        self.tcp_sessions_channel_closed = self.tcp_sessions_channel_closed.saturating_add(other.tcp_sessions_channel_closed);
        self.udp_sessions_channel_closed = self.udp_sessions_channel_closed.saturating_add(other.udp_sessions_channel_closed);
    }

    /// Reset all statistics to zero
    pub fn reset(&mut self) {
        *self = Self::new();
    }
}

impl std::fmt::Display for CleanupStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "CleanupStats(runs={}, tcp_timeout={}, udp_expired={}, tcp_channel={}, udp_channel={})",
            self.cleanup_runs,
            self.tcp_sessions_timed_out,
            self.udp_sessions_expired,
            self.tcp_sessions_channel_closed,
            self.udp_sessions_channel_closed
        )
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -------------------------------------------------------------------------
    // CleanupConfig Tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_cleanup_config_default() {
        let config = CleanupConfig::default();

        assert_eq!(config.cleanup_interval_secs, CLEANUP_INTERVAL_SECS);
        assert_eq!(config.tcp_idle_timeout_secs, TCP_IDLE_TIMEOUT_SECS);
        assert_eq!(config.udp_default_timeout_secs, UDP_DEFAULT_TIMEOUT_SECS);
        assert_eq!(config.udp_dns_timeout_secs, UDP_DNS_TIMEOUT_SECS);
    }

    #[test]
    fn test_cleanup_config_new() {
        let config = CleanupConfig::new(10, 60, 15, 5);

        assert_eq!(config.cleanup_interval_secs, 10);
        assert_eq!(config.tcp_idle_timeout_secs, 60);
        assert_eq!(config.udp_default_timeout_secs, 15);
        assert_eq!(config.udp_dns_timeout_secs, 5);
    }

    #[test]
    fn test_cleanup_config_durations() {
        let config = CleanupConfig::default();

        assert_eq!(config.cleanup_interval(), Duration::from_secs(30));
        assert_eq!(config.tcp_idle_timeout(), Duration::from_secs(300));
        assert_eq!(config.udp_default_timeout(), Duration::from_secs(30));
        assert_eq!(config.udp_dns_timeout(), Duration::from_secs(10));
    }

    #[test]
    fn test_cleanup_config_high_traffic() {
        let config = CleanupConfig::high_traffic();

        // High traffic should have shorter intervals
        assert!(config.cleanup_interval_secs < CleanupConfig::default().cleanup_interval_secs);
        assert!(config.tcp_idle_timeout_secs < CleanupConfig::default().tcp_idle_timeout_secs);
    }

    #[test]
    fn test_cleanup_config_low_memory() {
        let config = CleanupConfig::low_memory();

        // Low memory should have very aggressive cleanup
        assert!(config.cleanup_interval_secs <= 10);
        assert!(config.tcp_idle_timeout_secs <= 60);
        assert!(config.udp_default_timeout_secs <= 10);
    }

    #[test]
    fn test_cleanup_config_long_lived() {
        let config = CleanupConfig::long_lived();

        // Long-lived should have longer timeouts
        assert!(config.tcp_idle_timeout_secs > CleanupConfig::default().tcp_idle_timeout_secs);
        assert!(config.udp_default_timeout_secs > CleanupConfig::default().udp_default_timeout_secs);
    }

    #[test]
    fn test_cleanup_config_eq() {
        let config1 = CleanupConfig::default();
        let config2 = CleanupConfig::default();
        let config3 = CleanupConfig::high_traffic();

        assert_eq!(config1, config2);
        assert_ne!(config1, config3);
    }

    // -------------------------------------------------------------------------
    // CleanupStats Tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_cleanup_stats_new() {
        let stats = CleanupStats::new();

        assert_eq!(stats.cleanup_runs, 0);
        assert_eq!(stats.tcp_sessions_timed_out, 0);
        assert_eq!(stats.udp_sessions_expired, 0);
        assert_eq!(stats.tcp_sessions_channel_closed, 0);
        assert_eq!(stats.udp_sessions_channel_closed, 0);
    }

    #[test]
    fn test_cleanup_stats_default() {
        let stats = CleanupStats::default();

        assert_eq!(stats, CleanupStats::new());
    }

    #[test]
    fn test_cleanup_stats_total_cleaned() {
        let stats = CleanupStats {
            cleanup_runs: 5,
            tcp_sessions_timed_out: 10,
            udp_sessions_expired: 20,
            tcp_sessions_channel_closed: 3,
            udp_sessions_channel_closed: 7,
        };

        assert_eq!(stats.total_cleaned(), 40); // 10 + 20 + 3 + 7
    }

    #[test]
    fn test_cleanup_stats_tcp_total() {
        let stats = CleanupStats {
            cleanup_runs: 5,
            tcp_sessions_timed_out: 10,
            udp_sessions_expired: 20,
            tcp_sessions_channel_closed: 3,
            udp_sessions_channel_closed: 7,
        };

        assert_eq!(stats.tcp_total(), 13); // 10 + 3
    }

    #[test]
    fn test_cleanup_stats_udp_total() {
        let stats = CleanupStats {
            cleanup_runs: 5,
            tcp_sessions_timed_out: 10,
            udp_sessions_expired: 20,
            tcp_sessions_channel_closed: 3,
            udp_sessions_channel_closed: 7,
        };

        assert_eq!(stats.udp_total(), 27); // 20 + 7
    }

    #[test]
    fn test_cleanup_stats_merge() {
        let mut stats1 = CleanupStats {
            cleanup_runs: 5,
            tcp_sessions_timed_out: 10,
            udp_sessions_expired: 20,
            tcp_sessions_channel_closed: 3,
            udp_sessions_channel_closed: 7,
        };

        let stats2 = CleanupStats {
            cleanup_runs: 3,
            tcp_sessions_timed_out: 5,
            udp_sessions_expired: 10,
            tcp_sessions_channel_closed: 2,
            udp_sessions_channel_closed: 3,
        };

        stats1.merge(&stats2);

        assert_eq!(stats1.cleanup_runs, 8);
        assert_eq!(stats1.tcp_sessions_timed_out, 15);
        assert_eq!(stats1.udp_sessions_expired, 30);
        assert_eq!(stats1.tcp_sessions_channel_closed, 5);
        assert_eq!(stats1.udp_sessions_channel_closed, 10);
    }

    #[test]
    fn test_cleanup_stats_reset() {
        let mut stats = CleanupStats {
            cleanup_runs: 100,
            tcp_sessions_timed_out: 50,
            udp_sessions_expired: 75,
            tcp_sessions_channel_closed: 10,
            udp_sessions_channel_closed: 15,
        };

        stats.reset();

        assert_eq!(stats, CleanupStats::new());
    }

    #[test]
    fn test_cleanup_stats_display() {
        let stats = CleanupStats {
            cleanup_runs: 10,
            tcp_sessions_timed_out: 5,
            udp_sessions_expired: 15,
            tcp_sessions_channel_closed: 2,
            udp_sessions_channel_closed: 3,
        };

        let display = format!("{}", stats);

        assert!(display.contains("runs=10"));
        assert!(display.contains("tcp_timeout=5"));
        assert!(display.contains("udp_expired=15"));
        assert!(display.contains("tcp_channel=2"));
        assert!(display.contains("udp_channel=3"));
    }

    #[test]
    fn test_cleanup_stats_saturating() {
        let stats = CleanupStats {
            cleanup_runs: 0,
            tcp_sessions_timed_out: u64::MAX,
            udp_sessions_expired: 1,
            tcp_sessions_channel_closed: u64::MAX,
            udp_sessions_channel_closed: 1,
        };

        // Should not overflow
        assert_eq!(stats.total_cleaned(), u64::MAX);
        assert_eq!(stats.tcp_total(), u64::MAX);
    }

    // -------------------------------------------------------------------------
    // Constant Tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_constants() {
        assert_eq!(CLEANUP_INTERVAL_SECS, 30);
        assert_eq!(TCP_IDLE_TIMEOUT_SECS, 300);
        assert_eq!(UDP_DEFAULT_TIMEOUT_SECS, 30);
        assert_eq!(UDP_DNS_TIMEOUT_SECS, 10);

        // DNS timeout should be shorter than default
        assert!(UDP_DNS_TIMEOUT_SECS < UDP_DEFAULT_TIMEOUT_SECS);

        // TCP timeout should be longer than UDP
        assert!(TCP_IDLE_TIMEOUT_SECS > UDP_DEFAULT_TIMEOUT_SECS);
    }
}
