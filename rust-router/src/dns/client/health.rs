//! DNS Upstream Health Checker
//!
//! This module provides health checking for DNS upstream servers,
//! tracking success/failure patterns and managing health state transitions.
//!
//! # Health State Machine
//!
//! ```text
//! Healthy ──[3 consecutive failures]──> Unhealthy ──[1 success]──> Healthy
//!    ^                                                  │
//!    └──────────────────────────────────────────────────┘
//! ```
//!
//! # Example
//!
//! ```
//! use rust_router::dns::client::HealthChecker;
//! use rust_router::dns::config::HealthCheckConfig;
//!
//! let config = HealthCheckConfig::default();
//! let checker = HealthChecker::new(&config);
//!
//! assert!(checker.is_healthy());
//!
//! // Record failures
//! checker.record_failure();
//! checker.record_failure();
//! checker.record_failure();
//!
//! // After 3 failures, upstream becomes unhealthy
//! assert!(!checker.is_healthy());
//!
//! // One success recovers it
//! checker.record_success();
//! assert!(checker.is_healthy());
//! ```

use std::sync::atomic::{AtomicU32, AtomicU64, AtomicU8, Ordering};
use std::time::{Duration, Instant};

use parking_lot::RwLock;

/// Health state values
const STATE_HEALTHY: u8 = 0;
const STATE_UNHEALTHY: u8 = 1;

/// Default failure threshold before marking unhealthy
pub const DEFAULT_FAILURE_THRESHOLD: u32 = 3;

/// Default success threshold for recovery
pub const DEFAULT_SUCCESS_THRESHOLD: u32 = 1;

/// Default health check interval in seconds
pub const DEFAULT_HEALTH_CHECK_INTERVAL_SECS: u64 = 30;

/// Default health check timeout in seconds
pub const DEFAULT_HEALTH_CHECK_TIMEOUT_SECS: u64 = 5;

/// Health check configuration
///
/// Controls how health is determined for upstream DNS servers.
#[derive(Debug, Clone)]
pub struct HealthCheckConfig {
    /// Health check interval in seconds
    ///
    /// How often to send health check probes.
    /// Default: 30 seconds
    pub interval_secs: u64,

    /// Health check timeout in seconds
    ///
    /// Maximum time to wait for a health check response.
    /// Default: 5 seconds
    pub timeout_secs: u64,

    /// Number of consecutive failures before marking unhealthy
    ///
    /// Default: 3
    pub failure_threshold: u32,

    /// Number of consecutive successes to recover from unhealthy state
    ///
    /// Default: 1
    pub success_threshold: u32,

    /// Domain to query for health checks
    ///
    /// Default: "health.check.local"
    pub probe_domain: String,
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        Self {
            interval_secs: DEFAULT_HEALTH_CHECK_INTERVAL_SECS,
            timeout_secs: DEFAULT_HEALTH_CHECK_TIMEOUT_SECS,
            failure_threshold: DEFAULT_FAILURE_THRESHOLD,
            success_threshold: DEFAULT_SUCCESS_THRESHOLD,
            probe_domain: "health.check.local".to_string(),
        }
    }
}

impl HealthCheckConfig {
    /// Create a new health check configuration
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the health check interval
    #[must_use]
    pub fn with_interval(mut self, interval_secs: u64) -> Self {
        self.interval_secs = interval_secs;
        self
    }

    /// Set the health check timeout
    #[must_use]
    pub fn with_timeout(mut self, timeout_secs: u64) -> Self {
        self.timeout_secs = timeout_secs;
        self
    }

    /// Set the failure threshold
    #[must_use]
    pub fn with_failure_threshold(mut self, threshold: u32) -> Self {
        self.failure_threshold = threshold;
        self
    }

    /// Set the success threshold
    #[must_use]
    pub fn with_success_threshold(mut self, threshold: u32) -> Self {
        self.success_threshold = threshold;
        self
    }

    /// Set the probe domain
    #[must_use]
    pub fn with_probe_domain(mut self, domain: impl Into<String>) -> Self {
        self.probe_domain = domain.into();
        self
    }

    /// Get the health check interval as a Duration
    pub fn interval(&self) -> Duration {
        Duration::from_secs(self.interval_secs)
    }

    /// Get the health check timeout as a Duration
    pub fn timeout(&self) -> Duration {
        Duration::from_secs(self.timeout_secs)
    }
}

/// Health statistics for an upstream
#[derive(Debug, Clone, Copy, Default)]
pub struct HealthStats {
    /// Total number of successful queries
    pub total_successes: u64,
    /// Total number of failed queries
    pub total_failures: u64,
    /// Current consecutive success count
    pub consecutive_successes: u32,
    /// Current consecutive failure count
    pub consecutive_failures: u32,
    /// Whether the upstream is currently healthy
    pub is_healthy: bool,
    /// Number of times the upstream transitioned to unhealthy
    pub unhealthy_transitions: u64,
    /// Number of times the upstream recovered from unhealthy
    pub recovery_transitions: u64,
}

impl HealthStats {
    /// Calculate the success rate as a percentage
    pub fn success_rate(&self) -> f64 {
        let total = self.total_successes + self.total_failures;
        if total == 0 {
            100.0
        } else {
            (self.total_successes as f64 / total as f64) * 100.0
        }
    }
}

/// Health checker for a DNS upstream
///
/// Tracks success/failure patterns and manages health state transitions.
/// Thread-safe with atomic operations.
///
/// # State Machine
///
/// - **Healthy**: Upstream is available for queries
/// - **Unhealthy**: Upstream should be avoided
///
/// Transitions:
/// - Healthy -> Unhealthy: After `failure_threshold` consecutive failures
/// - Unhealthy -> Healthy: After `success_threshold` consecutive successes
///
/// # Example
///
/// ```
/// use rust_router::dns::client::HealthChecker;
/// use rust_router::dns::config::HealthCheckConfig;
///
/// let config = HealthCheckConfig::default();
/// let checker = HealthChecker::new(&config);
///
/// // Initially healthy
/// assert!(checker.is_healthy());
///
/// // Track failures
/// for _ in 0..3 {
///     checker.record_failure();
/// }
///
/// // Now unhealthy
/// assert!(!checker.is_healthy());
///
/// // One success recovers
/// checker.record_success();
/// assert!(checker.is_healthy());
/// ```
#[derive(Debug)]
pub struct HealthChecker {
    /// Current health state (0 = healthy, 1 = unhealthy)
    state: AtomicU8,

    /// Consecutive failure count
    consecutive_failures: AtomicU32,

    /// Consecutive success count
    consecutive_successes: AtomicU32,

    /// Total successful queries
    total_successes: AtomicU64,

    /// Total failed queries
    total_failures: AtomicU64,

    /// Number of transitions to unhealthy state
    unhealthy_transitions: AtomicU64,

    /// Number of recovery transitions
    recovery_transitions: AtomicU64,

    /// Failure threshold before marking unhealthy
    failure_threshold: u32,

    /// Success threshold for recovery
    success_threshold: u32,

    /// Last state change time
    last_state_change: RwLock<Option<Instant>>,

    /// Last check time
    last_check_time: RwLock<Option<Instant>>,
}

impl HealthChecker {
    /// Create a new health checker with the given configuration
    ///
    /// # Arguments
    ///
    /// * `config` - Health check configuration
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::dns::client::HealthChecker;
    /// use rust_router::dns::config::HealthCheckConfig;
    ///
    /// let config = HealthCheckConfig::default()
    ///     .with_failure_threshold(5)
    ///     .with_success_threshold(2);
    ///
    /// let checker = HealthChecker::new(&config);
    /// ```
    pub fn new(config: &HealthCheckConfig) -> Self {
        Self {
            state: AtomicU8::new(STATE_HEALTHY),
            consecutive_failures: AtomicU32::new(0),
            consecutive_successes: AtomicU32::new(0),
            total_successes: AtomicU64::new(0),
            total_failures: AtomicU64::new(0),
            unhealthy_transitions: AtomicU64::new(0),
            recovery_transitions: AtomicU64::new(0),
            failure_threshold: config.failure_threshold,
            success_threshold: config.success_threshold,
            last_state_change: RwLock::new(None),
            last_check_time: RwLock::new(None),
        }
    }

    /// Check if the upstream is currently healthy
    ///
    /// # Returns
    ///
    /// `true` if healthy, `false` if unhealthy
    pub fn is_healthy(&self) -> bool {
        self.state.load(Ordering::Acquire) == STATE_HEALTHY
    }

    /// Record a successful query
    ///
    /// Increments the consecutive success counter and may transition
    /// from unhealthy to healthy if the success threshold is met.
    pub fn record_success(&self) {
        // Increment total successes
        self.total_successes.fetch_add(1, Ordering::Relaxed);

        // Reset consecutive failures
        self.consecutive_failures.store(0, Ordering::Release);

        // Increment consecutive successes
        let successes = self.consecutive_successes.fetch_add(1, Ordering::AcqRel) + 1;

        // Update last check time
        *self.last_check_time.write() = Some(Instant::now());

        // Check if we should transition to healthy
        if !self.is_healthy() && successes >= self.success_threshold {
            self.transition_to_healthy();
        }
    }

    /// Record a failed query
    ///
    /// Increments the consecutive failure counter and may transition
    /// from healthy to unhealthy if the failure threshold is met.
    pub fn record_failure(&self) {
        // Increment total failures
        self.total_failures.fetch_add(1, Ordering::Relaxed);

        // Reset consecutive successes
        self.consecutive_successes.store(0, Ordering::Release);

        // Increment consecutive failures
        let failures = self.consecutive_failures.fetch_add(1, Ordering::AcqRel) + 1;

        // Update last check time
        *self.last_check_time.write() = Some(Instant::now());

        // Check if we should transition to unhealthy
        if self.is_healthy() && failures >= self.failure_threshold {
            self.transition_to_unhealthy();
        }
    }

    /// Forcefully mark the upstream as unhealthy
    ///
    /// Used when an unrecoverable error occurs that should
    /// immediately mark the upstream as unavailable.
    pub fn force_unhealthy(&self) {
        if self.is_healthy() {
            self.transition_to_unhealthy();
        }
    }

    /// Forcefully mark the upstream as healthy
    ///
    /// Used to manually reset health state, e.g., after
    /// configuration changes or manual intervention.
    pub fn force_healthy(&self) {
        if !self.is_healthy() {
            self.transition_to_healthy();
        }
    }

    /// Reset all health state to initial values
    ///
    /// Resets counters and marks the upstream as healthy.
    pub fn reset(&self) {
        self.state.store(STATE_HEALTHY, Ordering::Release);
        self.consecutive_failures.store(0, Ordering::Release);
        self.consecutive_successes.store(0, Ordering::Release);
        self.total_successes.store(0, Ordering::Release);
        self.total_failures.store(0, Ordering::Release);
        *self.last_state_change.write() = None;
        *self.last_check_time.write() = None;
    }

    /// Get current health statistics
    ///
    /// # Returns
    ///
    /// A snapshot of current health statistics
    pub fn stats(&self) -> HealthStats {
        HealthStats {
            total_successes: self.total_successes.load(Ordering::Relaxed),
            total_failures: self.total_failures.load(Ordering::Relaxed),
            consecutive_successes: self.consecutive_successes.load(Ordering::Relaxed),
            consecutive_failures: self.consecutive_failures.load(Ordering::Relaxed),
            is_healthy: self.is_healthy(),
            unhealthy_transitions: self.unhealthy_transitions.load(Ordering::Relaxed),
            recovery_transitions: self.recovery_transitions.load(Ordering::Relaxed),
        }
    }

    /// Get the time since the last state change
    ///
    /// # Returns
    ///
    /// Duration since last state change, or `None` if no changes have occurred
    pub fn time_since_state_change(&self) -> Option<Duration> {
        self.last_state_change.read().map(|t| t.elapsed())
    }

    /// Get the time since the last health check
    ///
    /// # Returns
    ///
    /// Duration since last check, or `None` if no checks have occurred
    pub fn time_since_last_check(&self) -> Option<Duration> {
        self.last_check_time.read().map(|t| t.elapsed())
    }

    /// Get the consecutive failure count
    pub fn consecutive_failures(&self) -> u32 {
        self.consecutive_failures.load(Ordering::Relaxed)
    }

    /// Get the consecutive success count
    pub fn consecutive_successes(&self) -> u32 {
        self.consecutive_successes.load(Ordering::Relaxed)
    }

    /// Get the failure threshold
    pub fn failure_threshold(&self) -> u32 {
        self.failure_threshold
    }

    /// Get the success threshold
    pub fn success_threshold(&self) -> u32 {
        self.success_threshold
    }

    // ========================================================================
    // Private Methods
    // ========================================================================

    fn transition_to_unhealthy(&self) {
        self.state.store(STATE_UNHEALTHY, Ordering::Release);
        self.unhealthy_transitions.fetch_add(1, Ordering::Relaxed);
        *self.last_state_change.write() = Some(Instant::now());

        tracing::warn!(
            total_failures = self.total_failures.load(Ordering::Relaxed),
            consecutive_failures = self.consecutive_failures.load(Ordering::Relaxed),
            "Upstream transitioned to UNHEALTHY"
        );
    }

    fn transition_to_healthy(&self) {
        self.state.store(STATE_HEALTHY, Ordering::Release);
        self.recovery_transitions.fetch_add(1, Ordering::Relaxed);
        self.consecutive_failures.store(0, Ordering::Release);
        *self.last_state_change.write() = Some(Instant::now());

        tracing::info!(
            total_successes = self.total_successes.load(Ordering::Relaxed),
            consecutive_successes = self.consecutive_successes.load(Ordering::Relaxed),
            "Upstream transitioned to HEALTHY"
        );
    }
}

impl Clone for HealthChecker {
    fn clone(&self) -> Self {
        Self {
            state: AtomicU8::new(self.state.load(Ordering::Relaxed)),
            consecutive_failures: AtomicU32::new(self.consecutive_failures.load(Ordering::Relaxed)),
            consecutive_successes: AtomicU32::new(
                self.consecutive_successes.load(Ordering::Relaxed),
            ),
            total_successes: AtomicU64::new(self.total_successes.load(Ordering::Relaxed)),
            total_failures: AtomicU64::new(self.total_failures.load(Ordering::Relaxed)),
            unhealthy_transitions: AtomicU64::new(
                self.unhealthy_transitions.load(Ordering::Relaxed),
            ),
            recovery_transitions: AtomicU64::new(self.recovery_transitions.load(Ordering::Relaxed)),
            failure_threshold: self.failure_threshold,
            success_threshold: self.success_threshold,
            last_state_change: RwLock::new(*self.last_state_change.read()),
            last_check_time: RwLock::new(*self.last_check_time.read()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // HealthCheckConfig Tests
    // ========================================================================

    #[test]
    fn test_health_check_config_default() {
        let config = HealthCheckConfig::default();
        assert_eq!(config.interval_secs, 30);
        assert_eq!(config.timeout_secs, 5);
        assert_eq!(config.failure_threshold, 3);
        assert_eq!(config.success_threshold, 1);
        assert_eq!(config.probe_domain, "health.check.local");
    }

    #[test]
    fn test_health_check_config_builder() {
        let config = HealthCheckConfig::new()
            .with_interval(60)
            .with_timeout(10)
            .with_failure_threshold(5)
            .with_success_threshold(2)
            .with_probe_domain("test.local");

        assert_eq!(config.interval_secs, 60);
        assert_eq!(config.timeout_secs, 10);
        assert_eq!(config.failure_threshold, 5);
        assert_eq!(config.success_threshold, 2);
        assert_eq!(config.probe_domain, "test.local");
    }

    #[test]
    fn test_health_check_config_interval_duration() {
        let config = HealthCheckConfig::default().with_interval(45);
        assert_eq!(config.interval(), Duration::from_secs(45));
    }

    #[test]
    fn test_health_check_config_timeout_duration() {
        let config = HealthCheckConfig::default().with_timeout(8);
        assert_eq!(config.timeout(), Duration::from_secs(8));
    }

    // ========================================================================
    // HealthStats Tests
    // ========================================================================

    #[test]
    fn test_health_stats_success_rate() {
        let stats = HealthStats {
            total_successes: 80,
            total_failures: 20,
            ..Default::default()
        };
        assert!((stats.success_rate() - 80.0).abs() < 0.01);
    }

    #[test]
    fn test_health_stats_success_rate_zero() {
        let stats = HealthStats::default();
        assert_eq!(stats.success_rate(), 100.0);
    }

    #[test]
    fn test_health_stats_success_rate_all_failures() {
        let stats = HealthStats {
            total_successes: 0,
            total_failures: 100,
            ..Default::default()
        };
        assert_eq!(stats.success_rate(), 0.0);
    }

    // ========================================================================
    // HealthChecker Creation Tests
    // ========================================================================

    #[test]
    fn test_health_checker_new() {
        let config = HealthCheckConfig::default();
        let checker = HealthChecker::new(&config);

        assert!(checker.is_healthy());
        assert_eq!(checker.consecutive_failures(), 0);
        assert_eq!(checker.consecutive_successes(), 0);
        assert_eq!(checker.failure_threshold(), 3);
        assert_eq!(checker.success_threshold(), 1);
    }

    #[test]
    fn test_health_checker_custom_thresholds() {
        let config = HealthCheckConfig::default()
            .with_failure_threshold(5)
            .with_success_threshold(3);
        let checker = HealthChecker::new(&config);

        assert_eq!(checker.failure_threshold(), 5);
        assert_eq!(checker.success_threshold(), 3);
    }

    // ========================================================================
    // State Machine Tests
    // ========================================================================

    #[test]
    fn test_health_checker_initial_state() {
        let config = HealthCheckConfig::default();
        let checker = HealthChecker::new(&config);

        assert!(checker.is_healthy());
        let stats = checker.stats();
        assert!(stats.is_healthy);
        assert_eq!(stats.unhealthy_transitions, 0);
        assert_eq!(stats.recovery_transitions, 0);
    }

    #[test]
    fn test_health_checker_transition_to_unhealthy() {
        let config = HealthCheckConfig::default().with_failure_threshold(3);
        let checker = HealthChecker::new(&config);

        // First two failures - still healthy
        checker.record_failure();
        assert!(checker.is_healthy());
        assert_eq!(checker.consecutive_failures(), 1);

        checker.record_failure();
        assert!(checker.is_healthy());
        assert_eq!(checker.consecutive_failures(), 2);

        // Third failure - becomes unhealthy
        checker.record_failure();
        assert!(!checker.is_healthy());
        assert_eq!(checker.consecutive_failures(), 3);

        let stats = checker.stats();
        assert_eq!(stats.unhealthy_transitions, 1);
    }

    #[test]
    fn test_health_checker_recovery() {
        let config = HealthCheckConfig::default()
            .with_failure_threshold(3)
            .with_success_threshold(1);
        let checker = HealthChecker::new(&config);

        // Become unhealthy
        for _ in 0..3 {
            checker.record_failure();
        }
        assert!(!checker.is_healthy());

        // One success - should recover
        checker.record_success();
        assert!(checker.is_healthy());

        let stats = checker.stats();
        assert_eq!(stats.recovery_transitions, 1);
    }

    #[test]
    fn test_health_checker_recovery_with_higher_threshold() {
        let config = HealthCheckConfig::default()
            .with_failure_threshold(3)
            .with_success_threshold(2);
        let checker = HealthChecker::new(&config);

        // Become unhealthy
        for _ in 0..3 {
            checker.record_failure();
        }
        assert!(!checker.is_healthy());

        // First success - still unhealthy
        checker.record_success();
        assert!(!checker.is_healthy());
        assert_eq!(checker.consecutive_successes(), 1);

        // Second success - should recover
        checker.record_success();
        assert!(checker.is_healthy());
        assert_eq!(checker.consecutive_successes(), 2);
    }

    #[test]
    fn test_health_checker_success_resets_failures() {
        let config = HealthCheckConfig::default().with_failure_threshold(3);
        let checker = HealthChecker::new(&config);

        // Two failures
        checker.record_failure();
        checker.record_failure();
        assert_eq!(checker.consecutive_failures(), 2);

        // One success resets
        checker.record_success();
        assert_eq!(checker.consecutive_failures(), 0);
        assert_eq!(checker.consecutive_successes(), 1);
        assert!(checker.is_healthy());
    }

    #[test]
    fn test_health_checker_failure_resets_successes() {
        let config = HealthCheckConfig::default();
        let checker = HealthChecker::new(&config);

        // Some successes
        checker.record_success();
        checker.record_success();
        assert_eq!(checker.consecutive_successes(), 2);

        // One failure resets
        checker.record_failure();
        assert_eq!(checker.consecutive_successes(), 0);
        assert_eq!(checker.consecutive_failures(), 1);
    }

    // ========================================================================
    // Force State Tests
    // ========================================================================

    #[test]
    fn test_health_checker_force_unhealthy() {
        let config = HealthCheckConfig::default();
        let checker = HealthChecker::new(&config);

        assert!(checker.is_healthy());

        checker.force_unhealthy();
        assert!(!checker.is_healthy());

        let stats = checker.stats();
        assert_eq!(stats.unhealthy_transitions, 1);
    }

    #[test]
    fn test_health_checker_force_healthy() {
        let config = HealthCheckConfig::default().with_failure_threshold(3);
        let checker = HealthChecker::new(&config);

        // Become unhealthy
        for _ in 0..3 {
            checker.record_failure();
        }
        assert!(!checker.is_healthy());

        // Force healthy
        checker.force_healthy();
        assert!(checker.is_healthy());

        let stats = checker.stats();
        assert_eq!(stats.recovery_transitions, 1);
    }

    #[test]
    fn test_health_checker_force_unhealthy_when_already_unhealthy() {
        let config = HealthCheckConfig::default().with_failure_threshold(3);
        let checker = HealthChecker::new(&config);

        // Become unhealthy
        for _ in 0..3 {
            checker.record_failure();
        }

        // Force again - should not increment transition count
        checker.force_unhealthy();
        let stats = checker.stats();
        assert_eq!(stats.unhealthy_transitions, 1); // Still 1
    }

    #[test]
    fn test_health_checker_force_healthy_when_already_healthy() {
        let config = HealthCheckConfig::default();
        let checker = HealthChecker::new(&config);

        checker.force_healthy();
        let stats = checker.stats();
        assert_eq!(stats.recovery_transitions, 0); // No transition
    }

    // ========================================================================
    // Reset Tests
    // ========================================================================

    #[test]
    fn test_health_checker_reset() {
        let config = HealthCheckConfig::default().with_failure_threshold(3);
        let checker = HealthChecker::new(&config);

        // Accumulate some state
        for _ in 0..5 {
            checker.record_success();
        }
        for _ in 0..3 {
            checker.record_failure();
        }
        assert!(!checker.is_healthy());

        // Reset
        checker.reset();

        assert!(checker.is_healthy());
        assert_eq!(checker.consecutive_failures(), 0);
        assert_eq!(checker.consecutive_successes(), 0);

        let stats = checker.stats();
        assert_eq!(stats.total_successes, 0);
        assert_eq!(stats.total_failures, 0);
    }

    // ========================================================================
    // Statistics Tests
    // ========================================================================

    #[test]
    fn test_health_checker_stats_tracking() {
        let config = HealthCheckConfig::default();
        let checker = HealthChecker::new(&config);

        // Record some activity
        for _ in 0..10 {
            checker.record_success();
        }
        for _ in 0..5 {
            checker.record_failure();
        }

        let stats = checker.stats();
        assert_eq!(stats.total_successes, 10);
        assert_eq!(stats.total_failures, 5);
    }

    #[test]
    fn test_health_checker_time_since_state_change() {
        let config = HealthCheckConfig::default().with_failure_threshold(3);
        let checker = HealthChecker::new(&config);

        // No state change yet
        assert!(checker.time_since_state_change().is_none());

        // Trigger state change
        for _ in 0..3 {
            checker.record_failure();
        }

        // Now there should be a state change time
        let duration = checker.time_since_state_change();
        assert!(duration.is_some());
        assert!(duration.unwrap() < Duration::from_secs(1));
    }

    #[test]
    fn test_health_checker_time_since_last_check() {
        let config = HealthCheckConfig::default();
        let checker = HealthChecker::new(&config);

        // No check yet
        assert!(checker.time_since_last_check().is_none());

        // Record activity
        checker.record_success();

        // Now there should be a last check time
        let duration = checker.time_since_last_check();
        assert!(duration.is_some());
        assert!(duration.unwrap() < Duration::from_secs(1));
    }

    // ========================================================================
    // Clone Tests
    // ========================================================================

    #[test]
    fn test_health_checker_clone() {
        let config = HealthCheckConfig::default();
        let checker = HealthChecker::new(&config);

        checker.record_success();
        checker.record_success();
        checker.record_failure();

        let cloned = checker.clone();

        let stats1 = checker.stats();
        let stats2 = cloned.stats();

        assert_eq!(stats1.total_successes, stats2.total_successes);
        assert_eq!(stats1.total_failures, stats2.total_failures);
        assert_eq!(stats1.is_healthy, stats2.is_healthy);
    }

    #[test]
    fn test_health_checker_clone_independence() {
        let config = HealthCheckConfig::default();
        let checker = HealthChecker::new(&config);

        let cloned = checker.clone();

        // Modify original
        checker.record_failure();

        // Clone should not be affected
        assert_eq!(checker.consecutive_failures(), 1);
        assert_eq!(cloned.consecutive_failures(), 0);
    }

    // ========================================================================
    // Edge Case Tests
    // ========================================================================

    #[test]
    fn test_health_checker_threshold_of_one() {
        let config = HealthCheckConfig::default()
            .with_failure_threshold(1)
            .with_success_threshold(1);
        let checker = HealthChecker::new(&config);

        // One failure - immediately unhealthy
        checker.record_failure();
        assert!(!checker.is_healthy());

        // One success - immediately healthy
        checker.record_success();
        assert!(checker.is_healthy());
    }

    #[test]
    fn test_health_checker_many_failures() {
        let config = HealthCheckConfig::default().with_failure_threshold(3);
        let checker = HealthChecker::new(&config);

        // Many failures - should still only count one transition
        for _ in 0..100 {
            checker.record_failure();
        }

        assert!(!checker.is_healthy());
        let stats = checker.stats();
        assert_eq!(stats.unhealthy_transitions, 1);
        assert_eq!(stats.total_failures, 100);
    }

    #[test]
    fn test_health_checker_multiple_transitions() {
        let config = HealthCheckConfig::default()
            .with_failure_threshold(2)
            .with_success_threshold(1);
        let checker = HealthChecker::new(&config);

        // First cycle: healthy -> unhealthy -> healthy
        checker.record_failure();
        checker.record_failure();
        assert!(!checker.is_healthy());

        checker.record_success();
        assert!(checker.is_healthy());

        // Second cycle
        checker.record_failure();
        checker.record_failure();
        assert!(!checker.is_healthy());

        checker.record_success();
        assert!(checker.is_healthy());

        let stats = checker.stats();
        assert_eq!(stats.unhealthy_transitions, 2);
        assert_eq!(stats.recovery_transitions, 2);
    }

    // ========================================================================
    // Thread Safety Tests
    // ========================================================================

    #[test]
    fn test_health_checker_concurrent_access() {
        use std::sync::Arc;
        use std::thread;

        let config = HealthCheckConfig::default().with_failure_threshold(100);
        let checker = Arc::new(HealthChecker::new(&config));

        let handles: Vec<_> = (0..10)
            .map(|i| {
                let checker = Arc::clone(&checker);
                thread::spawn(move || {
                    for _ in 0..100 {
                        if i % 2 == 0 {
                            checker.record_success();
                        } else {
                            checker.record_failure();
                        }
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().expect("thread panicked");
        }

        let stats = checker.stats();
        // 5 threads * 100 = 500 successes
        // 5 threads * 100 = 500 failures
        assert_eq!(stats.total_successes, 500);
        assert_eq!(stats.total_failures, 500);
    }
}
