//! Shard Supervisor for the VLESS-WG Bridge
//!
//! This module provides a supervisor that monitors all smoltcp shards, handling
//! panic recovery and circuit breaker protection. The supervisor ensures system
//! resilience by automatically restarting crashed shards while preventing cascade
//! failures through circuit breaker patterns.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────────┐
//! │                           ShardSupervisor                                    │
//! ├─────────────────────────────────────────────────────────────────────────────┤
//! │                                                                             │
//! │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐       │
//! │  │  Shard 0    │  │  Shard 1    │  │  Shard 2    │  │  Shard N    │       │
//! │  │  JoinHandle │  │  JoinHandle │  │  JoinHandle │  │  JoinHandle │       │
//! │  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘       │
//! │         │                │                │                │               │
//! │         └────────────────┼────────────────┼────────────────┘               │
//! │                          ▼                                                  │
//! │                 ┌─────────────────────┐                                    │
//! │                 │  Health Check Loop  │                                    │
//! │                 │  (1s interval)      │                                    │
//! │                 └──────────┬──────────┘                                    │
//! │                            │                                               │
//! │                            ▼                                               │
//! │         ┌─────────────────────────────────────────┐                        │
//! │         │  Circuit Breaker Logic (per shard)      │                        │
//! │         │  - Track consecutive failures           │                        │
//! │         │  - Open breaker after max failures      │                        │
//! │         │  - Auto-reset after cooldown            │                        │
//! │         └─────────────────────────────────────────┘                        │
//! │                                                                             │
//! └─────────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Circuit Breaker Pattern
//!
//! The supervisor implements a circuit breaker pattern to prevent cascade failures:
//!
//! 1. **Closed (Normal)**: Shard is running, failures are counted
//! 2. **Open (Tripped)**: Shard has failed too many times, restarts are blocked
//! 3. **Half-Open (Recovery)**: After cooldown, one restart attempt is allowed
//!
//! ```text
//! ┌─────────┐  max failures  ┌─────────┐  cooldown  ┌───────────┐
//! │ Closed  │ ────────────► │  Open   │ ─────────► │ Half-Open │
//! └────┬────┘               └─────────┘            └─────┬─────┘
//!      │                         ▲                       │
//!      │                         │ failure               │ success
//!      │ restart                 └───────────────────────┤
//!      │ success                                         │
//!      └─────────────────────────────────────────────────┘
//! ```
//!
//! # Usage
//!
//! ```ignore
//! use rust_router::vless_wg_bridge::supervisor::{
//!     ShardSupervisor, SupervisorConfig, ShardFactory,
//! };
//!
//! // Create configuration
//! let config = SupervisorConfig::default();
//!
//! // Create shard factory
//! let factory = Arc::new(move |shard_index| {
//!     let config = ShardConfig::new(shard_index, local_ip, local_cidr);
//!     SmoltcpShard::new(config, event_rx, wg_reply_rx, wg_tx)
//! });
//!
//! // Create supervisor
//! let mut supervisor = ShardSupervisor::new(config, factory, num_shards);
//!
//! // Run supervisor (spawns and monitors all shards)
//! tokio::spawn(supervisor.run());
//! ```

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

// =============================================================================
// Constants
// =============================================================================

/// Default maximum consecutive failures before circuit breaker opens
pub const DEFAULT_MAX_CONSECUTIVE_FAILURES: u32 = 3;

/// Default circuit breaker reset time (30 seconds)
pub const DEFAULT_CIRCUIT_BREAKER_RESET_SECS: u64 = 30;

/// Default restart delay (1 second)
pub const DEFAULT_RESTART_DELAY_MS: u64 = 1000;

/// Health check interval (1 second)
pub const HEALTH_CHECK_INTERVAL_SECS: u64 = 1;

// =============================================================================
// Supervisor Configuration
// =============================================================================

/// Configuration for the shard supervisor
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SupervisorConfig {
    /// Maximum consecutive failures before circuit breaker opens
    pub max_consecutive_failures: u32,

    /// Duration after which the circuit breaker resets (allows retry)
    pub circuit_breaker_reset: Duration,

    /// Delay before restarting a crashed shard
    pub restart_delay: Duration,

    /// Health check interval
    pub health_check_interval: Duration,
}

impl SupervisorConfig {
    /// Create a new supervisor configuration
    #[must_use]
    pub const fn new(
        max_consecutive_failures: u32,
        circuit_breaker_reset: Duration,
        restart_delay: Duration,
    ) -> Self {
        Self {
            max_consecutive_failures,
            circuit_breaker_reset,
            restart_delay,
            health_check_interval: Duration::from_secs(HEALTH_CHECK_INTERVAL_SECS),
        }
    }

    /// Create a configuration with custom health check interval
    #[must_use]
    pub const fn with_health_check_interval(mut self, interval: Duration) -> Self {
        self.health_check_interval = interval;
        self
    }

    /// Create a configuration optimized for aggressive recovery
    ///
    /// Uses more frequent restarts and shorter circuit breaker timeouts.
    #[must_use]
    pub const fn aggressive() -> Self {
        Self {
            max_consecutive_failures: 5,
            circuit_breaker_reset: Duration::from_secs(15),
            restart_delay: Duration::from_millis(500),
            health_check_interval: Duration::from_millis(500),
        }
    }

    /// Create a configuration optimized for stability
    ///
    /// Uses longer delays and fewer restart attempts to prevent thrashing.
    #[must_use]
    pub const fn stable() -> Self {
        Self {
            max_consecutive_failures: 2,
            circuit_breaker_reset: Duration::from_secs(60),
            restart_delay: Duration::from_secs(5),
            health_check_interval: Duration::from_secs(2),
        }
    }
}

impl Default for SupervisorConfig {
    fn default() -> Self {
        Self {
            max_consecutive_failures: DEFAULT_MAX_CONSECUTIVE_FAILURES,
            circuit_breaker_reset: Duration::from_secs(DEFAULT_CIRCUIT_BREAKER_RESET_SECS),
            restart_delay: Duration::from_millis(DEFAULT_RESTART_DELAY_MS),
            health_check_interval: Duration::from_secs(HEALTH_CHECK_INTERVAL_SECS),
        }
    }
}

// =============================================================================
// Shard Health Status
// =============================================================================

/// Health status of a shard
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShardHealth {
    /// Shard is running normally
    Healthy,

    /// Shard completed normally (no error)
    Completed,

    /// Shard panicked
    Panicked,

    /// Shard crashed with an error
    Crashed(String),
}

impl ShardHealth {
    /// Check if the shard needs recovery
    #[must_use]
    pub fn needs_recovery(&self) -> bool {
        matches!(self, ShardHealth::Panicked | ShardHealth::Crashed(_))
    }

    /// Check if the shard is still running
    #[must_use]
    pub fn is_running(&self) -> bool {
        matches!(self, ShardHealth::Healthy)
    }
}

impl std::fmt::Display for ShardHealth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ShardHealth::Healthy => write!(f, "Healthy"),
            ShardHealth::Completed => write!(f, "Completed"),
            ShardHealth::Panicked => write!(f, "Panicked"),
            ShardHealth::Crashed(msg) => write!(f, "Crashed: {}", msg),
        }
    }
}

// =============================================================================
// Circuit Breaker State
// =============================================================================

/// Circuit breaker state for a single shard
#[derive(Debug, Clone)]
struct CircuitBreakerState {
    /// Whether the circuit is open (blocking restarts)
    is_open: bool,

    /// Consecutive failure count
    failure_count: u32,

    /// Time when the circuit was opened (for reset calculation)
    opened_at: Option<Instant>,

    /// Total restarts for this shard
    total_restarts: u64,
}

impl CircuitBreakerState {
    /// Create a new circuit breaker state
    fn new() -> Self {
        Self {
            is_open: false,
            failure_count: 0,
            opened_at: None,
            total_restarts: 0,
        }
    }

    /// Record a failure and return whether restart is allowed
    fn record_failure(&mut self, max_failures: u32) -> bool {
        self.failure_count = self.failure_count.saturating_add(1);

        if self.failure_count >= max_failures {
            self.is_open = true;
            self.opened_at = Some(Instant::now());
            false
        } else {
            true
        }
    }

    /// Check if the circuit breaker should reset based on cooldown
    fn should_reset(&self, cooldown: Duration) -> bool {
        if let Some(opened_at) = self.opened_at {
            opened_at.elapsed() >= cooldown
        } else {
            false
        }
    }

    /// Reset the circuit breaker to closed state
    fn reset(&mut self) {
        self.is_open = false;
        self.failure_count = 0;
        self.opened_at = None;
    }

    /// Record a successful restart
    fn record_restart(&mut self) {
        self.total_restarts = self.total_restarts.saturating_add(1);
    }

    /// Record a successful recovery (shard running again)
    fn record_recovery(&mut self) {
        self.failure_count = 0;
    }
}

// =============================================================================
// Supervisor Statistics
// =============================================================================

/// Statistics tracked by the supervisor
#[derive(Debug, Default, Clone)]
pub struct SupervisorStats {
    /// Restart counts per shard
    pub restarts: Vec<u64>,

    /// Total circuit breaker trips across all shards
    pub circuit_breaker_trips: u64,

    /// Total panics detected across all shards
    pub total_panics: u64,

    /// Total crashes (non-panic errors) across all shards
    pub total_crashes: u64,

    /// Health check count
    pub health_checks: u64,

    /// Number of shards currently in circuit breaker open state
    pub shards_circuit_open: usize,
}

impl SupervisorStats {
    /// Create new statistics for the given number of shards
    #[must_use]
    pub fn new(num_shards: usize) -> Self {
        Self {
            restarts: vec![0; num_shards],
            circuit_breaker_trips: 0,
            total_panics: 0,
            total_crashes: 0,
            health_checks: 0,
            shards_circuit_open: 0,
        }
    }

    /// Get the total number of restarts across all shards
    #[must_use]
    pub fn total_restarts(&self) -> u64 {
        self.restarts.iter().sum()
    }

    /// Get the restart count for a specific shard
    #[must_use]
    pub fn shard_restarts(&self, shard_idx: usize) -> Option<u64> {
        self.restarts.get(shard_idx).copied()
    }
}

impl std::fmt::Display for SupervisorStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "SupervisorStats(restarts={}, panics={}, crashes={}, breaker_trips={}, open={})",
            self.total_restarts(),
            self.total_panics,
            self.total_crashes,
            self.circuit_breaker_trips,
            self.shards_circuit_open
        )
    }
}

// =============================================================================
// Shard Factory Trait
// =============================================================================

/// Factory for creating shard tasks
///
/// This trait allows the supervisor to create new shard instances when
/// restarting crashed shards. Implementations should capture any necessary
/// context (channels, configuration) to create fully functional shards.
pub trait ShardFactory: Send + Sync + 'static {
    /// Create a new shard task that returns a `JoinHandle`
    ///
    /// The returned `JoinHandle` should be for a task that runs the shard's
    /// event loop. The supervisor will monitor this handle and restart the
    /// shard if it panics or crashes.
    ///
    /// # Arguments
    ///
    /// * `shard_index` - The index of the shard to create
    fn create_shard(&self, shard_index: u16) -> JoinHandle<()>;
}

/// Boxed shard factory type for convenient storage
pub type BoxedShardFactory = Box<dyn ShardFactory>;

/// Closure-based shard factory implementation
impl<F> ShardFactory for F
where
    F: Fn(u16) -> JoinHandle<()> + Send + Sync + 'static,
{
    fn create_shard(&self, shard_index: u16) -> JoinHandle<()> {
        self(shard_index)
    }
}

// =============================================================================
// Shard Supervisor
// =============================================================================

/// Supervisor that monitors and restarts shard tasks
///
/// The supervisor runs a health check loop that monitors all shard handles
/// and automatically restarts crashed shards according to the circuit breaker
/// policy.
pub struct ShardSupervisor {
    /// Shard factory for creating new shard instances
    shard_factory: Arc<dyn ShardFactory>,

    /// Join handles for each shard (None if shard is not running)
    handles: Vec<Option<JoinHandle<()>>>,

    /// Circuit breaker state per shard
    circuit_breakers: Vec<CircuitBreakerState>,

    /// Configuration
    config: SupervisorConfig,

    /// Statistics
    stats: SupervisorStats,

    /// Shutdown flag
    shutdown: bool,
}

impl ShardSupervisor {
    /// Create a new shard supervisor
    ///
    /// # Arguments
    ///
    /// * `config` - Supervisor configuration
    /// * `shard_factory` - Factory for creating shard tasks
    /// * `num_shards` - Number of shards to supervise
    #[must_use]
    pub fn new<F>(config: SupervisorConfig, shard_factory: F, num_shards: usize) -> Self
    where
        F: ShardFactory,
    {
        Self {
            shard_factory: Arc::new(shard_factory),
            handles: (0..num_shards).map(|_| None).collect(),
            circuit_breakers: (0..num_shards)
                .map(|_| CircuitBreakerState::new())
                .collect(),
            config,
            stats: SupervisorStats::new(num_shards),
            shutdown: false,
        }
    }

    /// Create a supervisor with a boxed factory
    #[must_use]
    pub fn with_boxed_factory(
        config: SupervisorConfig,
        shard_factory: Arc<dyn ShardFactory>,
        num_shards: usize,
    ) -> Self {
        Self {
            shard_factory,
            handles: (0..num_shards).map(|_| None).collect(),
            circuit_breakers: (0..num_shards)
                .map(|_| CircuitBreakerState::new())
                .collect(),
            config,
            stats: SupervisorStats::new(num_shards),
            shutdown: false,
        }
    }

    /// Get the number of shards being supervised
    #[must_use]
    pub fn num_shards(&self) -> usize {
        self.handles.len()
    }

    /// Get the current statistics
    #[must_use]
    pub fn stats(&self) -> &SupervisorStats {
        &self.stats
    }

    /// Get a snapshot of the current statistics
    #[must_use]
    pub fn stats_snapshot(&self) -> SupervisorStats {
        self.stats.clone()
    }

    /// Request shutdown
    pub fn shutdown(&mut self) {
        self.shutdown = true;
    }

    /// Start all shards
    ///
    /// This method spawns all shards using the factory. Call this before
    /// running the supervisor's main loop.
    pub fn start_all_shards(&mut self) {
        info!("Starting {} shards", self.handles.len());

        for shard_idx in 0..self.handles.len() {
            self.start_shard(shard_idx);
        }
    }

    /// Start a single shard
    fn start_shard(&mut self, shard_idx: usize) {
        let handle = self.shard_factory.create_shard(shard_idx as u16);
        self.handles[shard_idx] = Some(handle);
        info!("Started shard {}", shard_idx);
    }

    /// Run the supervisor's main monitoring loop
    ///
    /// This method runs indefinitely, monitoring all shards and restarting
    /// them according to the circuit breaker policy.
    pub async fn run(&mut self) {
        info!(
            "ShardSupervisor starting: {} shards, max_failures={}, reset={:?}",
            self.handles.len(),
            self.config.max_consecutive_failures,
            self.config.circuit_breaker_reset
        );

        let mut interval = tokio::time::interval(self.config.health_check_interval);

        loop {
            interval.tick().await;

            if self.shutdown {
                info!("ShardSupervisor shutting down");
                break;
            }

            self.stats.health_checks = self.stats.health_checks.saturating_add(1);

            // Check each shard's health
            for shard_idx in 0..self.handles.len() {
                self.check_and_recover_shard(shard_idx).await;
            }

            // Update circuit breaker open count
            self.stats.shards_circuit_open =
                self.circuit_breakers.iter().filter(|cb| cb.is_open).count();

            // Periodically log status (every 60 health checks = ~1 minute with default config)
            if self.stats.health_checks % 60 == 0 {
                debug!("Supervisor status: {}", self.stats);
            }
        }

        // Wait for all shards to complete on shutdown
        self.wait_for_shutdown().await;
    }

    /// Check a single shard's health and recover if needed
    async fn check_and_recover_shard(&mut self, shard_idx: usize) {
        let health = self.check_shard_health(shard_idx);

        match health {
            ShardHealth::Healthy => {
                // Shard is running, check if we can reset circuit breaker on recovery
                if self.circuit_breakers[shard_idx].failure_count > 0 {
                    // Shard recovered from previous failure
                    self.circuit_breakers[shard_idx].record_recovery();
                    debug!("Shard {} recovered, resetting failure count", shard_idx);
                }
            }
            ShardHealth::Completed => {
                // Shard completed normally, no restart needed
                debug!("Shard {} completed normally", shard_idx);
            }
            ShardHealth::Panicked => {
                self.stats.total_panics = self.stats.total_panics.saturating_add(1);
                warn!("Shard {} panicked", shard_idx);
                self.handle_shard_failure(shard_idx).await;
            }
            ShardHealth::Crashed(ref msg) => {
                self.stats.total_crashes = self.stats.total_crashes.saturating_add(1);
                warn!("Shard {} crashed: {}", shard_idx, msg);
                self.handle_shard_failure(shard_idx).await;
            }
        }
    }

    /// Check the health of a shard
    fn check_shard_health(&mut self, shard_idx: usize) -> ShardHealth {
        let handle = match &self.handles[shard_idx] {
            Some(h) => h,
            None => return ShardHealth::Completed, // No handle means not running
        };

        if !handle.is_finished() {
            return ShardHealth::Healthy;
        }

        // Task has finished, take the handle to get the result
        let handle = self.handles[shard_idx].take().expect("handle exists");

        // Use poll to check the result without blocking
        // Since we know it's finished, this should complete immediately
        match handle.now_or_never() {
            Some(Ok(())) => ShardHealth::Completed,
            Some(Err(e)) if e.is_panic() => ShardHealth::Panicked,
            Some(Err(e)) => ShardHealth::Crashed(e.to_string()),
            None => {
                // This shouldn't happen since is_finished() was true
                warn!("Shard {} handle not ready despite is_finished()", shard_idx);
                ShardHealth::Crashed("unexpected state".to_string())
            }
        }
    }

    /// Handle a shard failure (panic or crash)
    async fn handle_shard_failure(&mut self, shard_idx: usize) {
        // Check circuit breaker reset first
        if self.circuit_breakers[shard_idx].is_open {
            if self.circuit_breakers[shard_idx].should_reset(self.config.circuit_breaker_reset) {
                info!("Shard {} circuit breaker reset after cooldown", shard_idx);
                self.circuit_breakers[shard_idx].reset();
            } else {
                debug!(
                    "Shard {} circuit breaker still open, not restarting",
                    shard_idx
                );
                return;
            }
        }

        // Record failure and check if restart is allowed
        let can_restart =
            self.circuit_breakers[shard_idx].record_failure(self.config.max_consecutive_failures);

        if !can_restart {
            self.stats.circuit_breaker_trips = self.stats.circuit_breaker_trips.saturating_add(1);
            error!(
                "Shard {} circuit breaker opened after {} consecutive failures",
                shard_idx, self.config.max_consecutive_failures
            );
            return;
        }

        // Restart the shard after delay
        self.restart_shard(shard_idx).await;
    }

    /// Restart a shard after the configured delay
    async fn restart_shard(&mut self, shard_idx: usize) {
        info!(
            "Restarting shard {} after {:?} delay",
            shard_idx, self.config.restart_delay
        );

        tokio::time::sleep(self.config.restart_delay).await;

        // Create new shard
        self.start_shard(shard_idx);

        // Update statistics
        self.circuit_breakers[shard_idx].record_restart();
        if let Some(count) = self.stats.restarts.get_mut(shard_idx) {
            *count = count.saturating_add(1);
        }

        info!(
            "Shard {} restarted (total restarts: {})",
            shard_idx,
            self.stats.restarts.get(shard_idx).copied().unwrap_or(0)
        );
    }

    /// Check if a specific shard's circuit breaker is open
    #[must_use]
    pub fn is_circuit_open(&self, shard_idx: usize) -> bool {
        self.circuit_breakers
            .get(shard_idx)
            .map(|cb| cb.is_open)
            .unwrap_or(false)
    }

    /// Get the failure count for a specific shard
    #[must_use]
    pub fn shard_failure_count(&self, shard_idx: usize) -> Option<u32> {
        self.circuit_breakers
            .get(shard_idx)
            .map(|cb| cb.failure_count)
    }

    /// Manually reset a shard's circuit breaker
    ///
    /// This can be used to force-enable restarts for a shard after
    /// investigating the cause of failures.
    pub fn reset_circuit_breaker(&mut self, shard_idx: usize) {
        if let Some(cb) = self.circuit_breakers.get_mut(shard_idx) {
            cb.reset();
            info!("Manually reset circuit breaker for shard {}", shard_idx);
        }
    }

    /// Wait for all shards to complete during shutdown
    async fn wait_for_shutdown(&mut self) {
        info!("Waiting for shards to complete...");

        for (idx, handle) in self.handles.iter_mut().enumerate() {
            if let Some(h) = handle.take() {
                match h.await {
                    Ok(()) => debug!("Shard {} completed", idx),
                    Err(e) if e.is_panic() => warn!("Shard {} panicked during shutdown", idx),
                    Err(e) => warn!("Shard {} error during shutdown: {}", idx, e),
                }
            }
        }

        info!("All shards completed");
    }
}

// =============================================================================
// Extension Trait for JoinHandle
// =============================================================================

/// Extension trait for `JoinHandle` to provide `now_or_never` functionality
trait JoinHandleExt<T> {
    /// Try to get the result immediately without blocking
    fn now_or_never(self) -> Option<Result<T, tokio::task::JoinError>>;
}

impl<T> JoinHandleExt<T> for JoinHandle<T> {
    fn now_or_never(self) -> Option<Result<T, tokio::task::JoinError>> {
        use std::future::Future;
        use std::pin::Pin;
        use std::task::{Context, Poll};

        // Create a no-op waker
        let waker = futures::task::noop_waker();
        let mut cx = Context::from_waker(&waker);

        // Pin the handle
        let mut pinned = Box::pin(self);

        // Poll once
        match Pin::new(&mut pinned).poll(&mut cx) {
            Poll::Ready(result) => Some(result),
            Poll::Pending => {
                // Leak the handle since we can't do anything with it
                // This should never happen since we only call this when is_finished() is true
                std::mem::forget(pinned);
                None
            }
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    // -------------------------------------------------------------------------
    // SupervisorConfig Tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_supervisor_config_default() {
        let config = SupervisorConfig::default();

        assert_eq!(
            config.max_consecutive_failures,
            DEFAULT_MAX_CONSECUTIVE_FAILURES
        );
        assert_eq!(
            config.circuit_breaker_reset,
            Duration::from_secs(DEFAULT_CIRCUIT_BREAKER_RESET_SECS)
        );
        assert_eq!(
            config.restart_delay,
            Duration::from_millis(DEFAULT_RESTART_DELAY_MS)
        );
        assert_eq!(
            config.health_check_interval,
            Duration::from_secs(HEALTH_CHECK_INTERVAL_SECS)
        );
    }

    #[test]
    fn test_supervisor_config_new() {
        let config = SupervisorConfig::new(5, Duration::from_secs(60), Duration::from_millis(500));

        assert_eq!(config.max_consecutive_failures, 5);
        assert_eq!(config.circuit_breaker_reset, Duration::from_secs(60));
        assert_eq!(config.restart_delay, Duration::from_millis(500));
    }

    #[test]
    fn test_supervisor_config_with_health_check_interval() {
        let config =
            SupervisorConfig::default().with_health_check_interval(Duration::from_millis(500));

        assert_eq!(config.health_check_interval, Duration::from_millis(500));
    }

    #[test]
    fn test_supervisor_config_aggressive() {
        let config = SupervisorConfig::aggressive();

        // Aggressive config should have more allowed failures
        assert!(
            config.max_consecutive_failures > SupervisorConfig::default().max_consecutive_failures
        );
        // And shorter delays
        assert!(config.restart_delay < SupervisorConfig::default().restart_delay);
    }

    #[test]
    fn test_supervisor_config_stable() {
        let config = SupervisorConfig::stable();

        // Stable config should have fewer allowed failures
        assert!(
            config.max_consecutive_failures < SupervisorConfig::default().max_consecutive_failures
        );
        // And longer delays
        assert!(config.restart_delay > SupervisorConfig::default().restart_delay);
    }

    // -------------------------------------------------------------------------
    // ShardHealth Tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_shard_health_needs_recovery() {
        assert!(!ShardHealth::Healthy.needs_recovery());
        assert!(!ShardHealth::Completed.needs_recovery());
        assert!(ShardHealth::Panicked.needs_recovery());
        assert!(ShardHealth::Crashed("error".to_string()).needs_recovery());
    }

    #[test]
    fn test_shard_health_is_running() {
        assert!(ShardHealth::Healthy.is_running());
        assert!(!ShardHealth::Completed.is_running());
        assert!(!ShardHealth::Panicked.is_running());
        assert!(!ShardHealth::Crashed("error".to_string()).is_running());
    }

    #[test]
    fn test_shard_health_display() {
        assert_eq!(format!("{}", ShardHealth::Healthy), "Healthy");
        assert_eq!(format!("{}", ShardHealth::Completed), "Completed");
        assert_eq!(format!("{}", ShardHealth::Panicked), "Panicked");
        assert_eq!(
            format!("{}", ShardHealth::Crashed("test error".to_string())),
            "Crashed: test error"
        );
    }

    // -------------------------------------------------------------------------
    // CircuitBreakerState Tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_circuit_breaker_new() {
        let cb = CircuitBreakerState::new();

        assert!(!cb.is_open);
        assert_eq!(cb.failure_count, 0);
        assert!(cb.opened_at.is_none());
        assert_eq!(cb.total_restarts, 0);
    }

    #[test]
    fn test_circuit_breaker_record_failure() {
        let mut cb = CircuitBreakerState::new();

        // First two failures should allow restart (max = 3)
        assert!(cb.record_failure(3));
        assert_eq!(cb.failure_count, 1);
        assert!(!cb.is_open);

        assert!(cb.record_failure(3));
        assert_eq!(cb.failure_count, 2);
        assert!(!cb.is_open);

        // Third failure should open the circuit
        assert!(!cb.record_failure(3));
        assert_eq!(cb.failure_count, 3);
        assert!(cb.is_open);
        assert!(cb.opened_at.is_some());
    }

    #[test]
    fn test_circuit_breaker_reset() {
        let mut cb = CircuitBreakerState::new();

        // Open the circuit
        cb.record_failure(1);
        assert!(cb.is_open);

        // Reset
        cb.reset();
        assert!(!cb.is_open);
        assert_eq!(cb.failure_count, 0);
        assert!(cb.opened_at.is_none());
    }

    #[test]
    fn test_circuit_breaker_should_reset() {
        let mut cb = CircuitBreakerState::new();

        // Circuit not open
        assert!(!cb.should_reset(Duration::from_millis(1)));

        // Open the circuit
        cb.is_open = true;
        cb.opened_at = Some(Instant::now() - Duration::from_secs(10));

        // Should reset after cooldown
        assert!(cb.should_reset(Duration::from_secs(5)));
        assert!(!cb.should_reset(Duration::from_secs(20)));
    }

    #[test]
    fn test_circuit_breaker_record_restart() {
        let mut cb = CircuitBreakerState::new();

        cb.record_restart();
        assert_eq!(cb.total_restarts, 1);

        cb.record_restart();
        assert_eq!(cb.total_restarts, 2);
    }

    #[test]
    fn test_circuit_breaker_record_recovery() {
        let mut cb = CircuitBreakerState::new();

        cb.failure_count = 5;
        cb.record_recovery();
        assert_eq!(cb.failure_count, 0);
    }

    // -------------------------------------------------------------------------
    // SupervisorStats Tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_supervisor_stats_new() {
        let stats = SupervisorStats::new(4);

        assert_eq!(stats.restarts.len(), 4);
        assert!(stats.restarts.iter().all(|&r| r == 0));
        assert_eq!(stats.circuit_breaker_trips, 0);
        assert_eq!(stats.total_panics, 0);
        assert_eq!(stats.total_crashes, 0);
        assert_eq!(stats.health_checks, 0);
        assert_eq!(stats.shards_circuit_open, 0);
    }

    #[test]
    fn test_supervisor_stats_total_restarts() {
        let mut stats = SupervisorStats::new(3);
        stats.restarts = vec![5, 3, 2];

        assert_eq!(stats.total_restarts(), 10);
    }

    #[test]
    fn test_supervisor_stats_shard_restarts() {
        let mut stats = SupervisorStats::new(3);
        stats.restarts = vec![5, 3, 2];

        assert_eq!(stats.shard_restarts(0), Some(5));
        assert_eq!(stats.shard_restarts(1), Some(3));
        assert_eq!(stats.shard_restarts(2), Some(2));
        assert_eq!(stats.shard_restarts(3), None);
    }

    #[test]
    fn test_supervisor_stats_display() {
        let mut stats = SupervisorStats::new(2);
        stats.restarts = vec![3, 2];
        stats.total_panics = 4;
        stats.total_crashes = 1;
        stats.circuit_breaker_trips = 2;
        stats.shards_circuit_open = 1;

        let display = format!("{}", stats);

        assert!(display.contains("restarts=5"));
        assert!(display.contains("panics=4"));
        assert!(display.contains("crashes=1"));
        assert!(display.contains("breaker_trips=2"));
        assert!(display.contains("open=1"));
    }

    // -------------------------------------------------------------------------
    // ShardSupervisor Tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_supervisor_creation() {
        let factory = |_idx: u16| tokio::spawn(async {});
        let supervisor = ShardSupervisor::new(SupervisorConfig::default(), factory, 4);

        assert_eq!(supervisor.num_shards(), 4);
        assert_eq!(supervisor.stats.restarts.len(), 4);
    }

    #[test]
    fn test_supervisor_circuit_breaker_queries() {
        let factory = |_idx: u16| tokio::spawn(async {});
        let supervisor = ShardSupervisor::new(SupervisorConfig::default(), factory, 2);

        assert!(!supervisor.is_circuit_open(0));
        assert!(!supervisor.is_circuit_open(1));
        assert!(!supervisor.is_circuit_open(10)); // Out of bounds

        assert_eq!(supervisor.shard_failure_count(0), Some(0));
        assert_eq!(supervisor.shard_failure_count(10), None);
    }

    #[test]
    fn test_supervisor_reset_circuit_breaker() {
        let factory = |_idx: u16| tokio::spawn(async {});
        let mut supervisor = ShardSupervisor::new(SupervisorConfig::default(), factory, 2);

        // Open circuit breaker manually
        supervisor.circuit_breakers[0].is_open = true;
        supervisor.circuit_breakers[0].failure_count = 5;

        assert!(supervisor.is_circuit_open(0));

        // Reset it
        supervisor.reset_circuit_breaker(0);

        assert!(!supervisor.is_circuit_open(0));
        assert_eq!(supervisor.shard_failure_count(0), Some(0));
    }

    #[tokio::test]
    async fn test_supervisor_start_all_shards() {
        let call_count = Arc::new(AtomicU32::new(0));
        let call_count_clone = call_count.clone();

        let factory = move |_idx: u16| {
            call_count_clone.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async {
                // Simulate shard running
                tokio::time::sleep(Duration::from_millis(100)).await;
            })
        };

        let mut supervisor = ShardSupervisor::new(SupervisorConfig::default(), factory, 3);
        supervisor.start_all_shards();

        // Wait a bit for spawns
        tokio::time::sleep(Duration::from_millis(10)).await;

        assert_eq!(call_count.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn test_supervisor_detects_completed_shard() {
        let factory = |_idx: u16| {
            tokio::spawn(async {
                // Complete immediately
            })
        };

        let mut supervisor = ShardSupervisor::new(SupervisorConfig::default(), factory, 1);
        supervisor.start_all_shards();

        // Wait for shard to complete
        tokio::time::sleep(Duration::from_millis(50)).await;

        let health = supervisor.check_shard_health(0);
        assert_eq!(health, ShardHealth::Completed);
    }

    #[tokio::test]
    async fn test_supervisor_detects_panicked_shard() {
        let factory = |_idx: u16| {
            tokio::spawn(async {
                panic!("intentional panic for testing");
            })
        };

        let mut supervisor = ShardSupervisor::new(SupervisorConfig::default(), factory, 1);
        supervisor.start_all_shards();

        // Wait for shard to panic
        tokio::time::sleep(Duration::from_millis(50)).await;

        let health = supervisor.check_shard_health(0);
        assert_eq!(health, ShardHealth::Panicked);
    }

    #[tokio::test]
    async fn test_supervisor_run_with_shutdown() {
        let factory = |_idx: u16| {
            tokio::spawn(async {
                loop {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            })
        };

        let mut config = SupervisorConfig::default();
        config.health_check_interval = Duration::from_millis(50);

        let mut supervisor = ShardSupervisor::new(config, factory, 1);
        supervisor.start_all_shards();

        // Spawn supervisor task
        let supervisor_handle = tokio::spawn(async move {
            // Shutdown after a short delay
            tokio::time::sleep(Duration::from_millis(100)).await;
            supervisor.shutdown();
            supervisor.run().await;
            supervisor.stats.health_checks
        });

        // Wait for supervisor to complete
        let health_checks = supervisor_handle.await.unwrap();

        // Should have done at least one health check
        assert!(health_checks >= 1);
    }

    // -------------------------------------------------------------------------
    // Constants Tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_constants() {
        assert_eq!(DEFAULT_MAX_CONSECUTIVE_FAILURES, 3);
        assert_eq!(DEFAULT_CIRCUIT_BREAKER_RESET_SECS, 30);
        assert_eq!(DEFAULT_RESTART_DELAY_MS, 1000);
        assert_eq!(HEALTH_CHECK_INTERVAL_SECS, 1);
    }
}
