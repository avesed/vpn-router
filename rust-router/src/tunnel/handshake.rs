//! `WireGuard` handshake tracking with exponential backoff
//!
//! This module provides handshake state tracking and retry logic to prevent
//! busy loops when connecting to unreachable peers.
//!
//! # Problem
//!
//! When `UserspaceWgTunnel` connects to an unreachable peer, boringtun's
//! `update_timers()` returns `WriteToNetwork` continuously (handshake
//! initiation packets), causing a busy loop that consumes 30%+ CPU.
//!
//! # Solution
//!
//! The `HandshakeTracker` implements:
//! - Maximum retry limits
//! - Exponential backoff between retries
//! - Handshake timeout detection
//! - Completion signaling via watch channel
//!
//! # Example
//!
//! ```
//! use rust_router::tunnel::handshake::{HandshakeTracker, HandshakeConfig};
//! use std::time::Duration;
//!
//! let config = HandshakeConfig::default();
//! let tracker = HandshakeTracker::new(config);
//!
//! // Before sending handshake initiation
//! if tracker.can_initiate() {
//!     match tracker.on_initiate() {
//!         Ok(attempt) => {
//!             // Send handshake packet
//!             println!("Sending handshake attempt {}", attempt);
//!         }
//!         Err(e) => {
//!             eprintln!("Handshake failed: {:?}", e);
//!         }
//!     }
//! }
//!
//! // When handshake completes successfully
//! tracker.on_complete();
//!
//! // Wait for completion with timeout
//! // tracker.wait_completion(Duration::from_secs(5)).await;
//! ```
//!
//! # Configuration
//!
//! The tracker can be configured via environment variables:
//! - `WG_HANDSHAKE_MAX_RETRIES`: Maximum retry attempts (default: 5)
//! - `WG_HANDSHAKE_INITIAL_BACKOFF_MS`: Initial backoff in milliseconds (default: 500)
//! - `WG_HANDSHAKE_MAX_BACKOFF_MS`: Maximum backoff in milliseconds (default: 30000)
//! - `WG_HANDSHAKE_BACKOFF_MULTIPLIER`: Backoff multiplier (default: 2.0)
//! - `WG_HANDSHAKE_TIMEOUT_SECS`: Handshake timeout in seconds (default: 60)
//!
//! # References
//!
//! - `WireGuard` Protocol: <https://www.wireguard.com/protocol/>
//! - Issue #13: `WireGuard` busy loop on invalid egress

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use tokio::sync::watch;
use tracing::{debug, trace, warn};

/// Default maximum number of handshake retry attempts
/// Increased from 5 to 30 to handle bidirectional pairing scenarios where
/// the peer may not be ready yet
const DEFAULT_MAX_RETRIES: u32 = 30;

/// Default initial backoff duration in milliseconds
const DEFAULT_INITIAL_BACKOFF_MS: u64 = 500;

/// Default maximum backoff duration in milliseconds
const DEFAULT_MAX_BACKOFF_MS: u64 = 30_000;

/// Default backoff multiplier for exponential growth
const DEFAULT_BACKOFF_MULTIPLIER: f64 = 2.0;

/// Default handshake timeout in seconds
const DEFAULT_TIMEOUT_SECS: u64 = 60;

/// Handshake configuration with retry and backoff settings
///
/// Controls how the handshake tracker handles retries and backoff
/// when attempting to establish a `WireGuard` connection.
#[derive(Debug, Clone)]
pub struct HandshakeConfig {
    /// Maximum number of retry attempts before giving up
    pub max_retries: u32,

    /// Initial backoff duration in milliseconds
    pub initial_backoff_ms: u64,

    /// Maximum backoff duration in milliseconds
    pub max_backoff_ms: u64,

    /// Multiplier for exponential backoff (typically 2.0)
    pub backoff_multiplier: f64,

    /// Timeout for handshake completion in seconds
    pub timeout_secs: u64,
}

impl Default for HandshakeConfig {
    fn default() -> Self {
        Self {
            max_retries: DEFAULT_MAX_RETRIES,
            initial_backoff_ms: DEFAULT_INITIAL_BACKOFF_MS,
            max_backoff_ms: DEFAULT_MAX_BACKOFF_MS,
            backoff_multiplier: DEFAULT_BACKOFF_MULTIPLIER,
            timeout_secs: DEFAULT_TIMEOUT_SECS,
        }
    }
}

impl HandshakeConfig {
    /// Create a new handshake configuration with default values
    pub fn new() -> Self {
        Self::default()
    }

    /// Create configuration from environment variables
    ///
    /// Reads the following environment variables:
    /// - `WG_HANDSHAKE_MAX_RETRIES`
    /// - `WG_HANDSHAKE_INITIAL_BACKOFF_MS`
    /// - `WG_HANDSHAKE_MAX_BACKOFF_MS`
    /// - `WG_HANDSHAKE_BACKOFF_MULTIPLIER`
    /// - `WG_HANDSHAKE_TIMEOUT_SECS`
    pub fn from_env() -> Self {
        let mut config = Self::default();

        if let Ok(val) = std::env::var("WG_HANDSHAKE_MAX_RETRIES") {
            if let Ok(v) = val.parse() {
                config.max_retries = v;
            }
        }

        if let Ok(val) = std::env::var("WG_HANDSHAKE_INITIAL_BACKOFF_MS") {
            if let Ok(v) = val.parse() {
                config.initial_backoff_ms = v;
            }
        }

        if let Ok(val) = std::env::var("WG_HANDSHAKE_MAX_BACKOFF_MS") {
            if let Ok(v) = val.parse() {
                config.max_backoff_ms = v;
            }
        }

        if let Ok(val) = std::env::var("WG_HANDSHAKE_BACKOFF_MULTIPLIER") {
            if let Ok(v) = val.parse() {
                config.backoff_multiplier = v;
            }
        }

        if let Ok(val) = std::env::var("WG_HANDSHAKE_TIMEOUT_SECS") {
            if let Ok(v) = val.parse() {
                config.timeout_secs = v;
            }
        }

        config
    }

    /// Builder method to set max retries
    pub fn with_max_retries(mut self, max_retries: u32) -> Self {
        self.max_retries = max_retries;
        self
    }

    /// Builder method to set initial backoff
    pub fn with_initial_backoff_ms(mut self, ms: u64) -> Self {
        self.initial_backoff_ms = ms;
        self
    }

    /// Builder method to set max backoff
    pub fn with_max_backoff_ms(mut self, ms: u64) -> Self {
        self.max_backoff_ms = ms;
        self
    }

    /// Builder method to set backoff multiplier
    pub fn with_backoff_multiplier(mut self, multiplier: f64) -> Self {
        self.backoff_multiplier = multiplier;
        self
    }

    /// Builder method to set timeout
    pub fn with_timeout_secs(mut self, secs: u64) -> Self {
        self.timeout_secs = secs;
        self
    }

    /// Validate configuration values
    pub fn validate(&self) -> Result<(), HandshakeError> {
        if self.max_retries == 0 {
            return Err(HandshakeError::InvalidConfig(
                "max_retries must be greater than 0".into(),
            ));
        }

        if self.initial_backoff_ms == 0 {
            return Err(HandshakeError::InvalidConfig(
                "initial_backoff_ms must be greater than 0".into(),
            ));
        }

        if self.max_backoff_ms < self.initial_backoff_ms {
            return Err(HandshakeError::InvalidConfig(
                "max_backoff_ms must be >= initial_backoff_ms".into(),
            ));
        }

        if self.backoff_multiplier < 1.0 {
            return Err(HandshakeError::InvalidConfig(
                "backoff_multiplier must be >= 1.0".into(),
            ));
        }

        if self.timeout_secs == 0 {
            return Err(HandshakeError::InvalidConfig(
                "timeout_secs must be greater than 0".into(),
            ));
        }

        Ok(())
    }
}

/// Handshake error types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeError {
    /// Handshake timed out
    Timeout,

    /// Received invalid handshake response
    InvalidResponse,

    /// Cryptographic error during handshake
    CryptoError,

    /// Network error during handshake
    NetworkError,

    /// Maximum retries exhausted
    RetriesExhausted,

    /// Invalid configuration
    InvalidConfig(String),

    /// Handshake already in progress
    AlreadyInProgress,

    /// Tracker is in disconnecting state
    Disconnecting,
}

impl std::fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HandshakeError::Timeout => write!(f, "Handshake timed out"),
            HandshakeError::InvalidResponse => write!(f, "Invalid handshake response"),
            HandshakeError::CryptoError => write!(f, "Cryptographic error during handshake"),
            HandshakeError::NetworkError => write!(f, "Network error during handshake"),
            HandshakeError::RetriesExhausted => write!(f, "Maximum handshake retries exhausted"),
            HandshakeError::InvalidConfig(msg) => write!(f, "Invalid configuration: {msg}"),
            HandshakeError::AlreadyInProgress => write!(f, "Handshake already in progress"),
            HandshakeError::Disconnecting => write!(f, "Tunnel is disconnecting"),
        }
    }
}

impl std::error::Error for HandshakeError {}

/// Handshake state machine
///
/// Tracks the current state of the handshake process.
#[derive(Debug, Clone)]
#[derive(Default)]
pub enum HandshakeState {
    /// No handshake in progress
    #[default]
    Idle,

    /// Handshake initiated, waiting for response
    Initiated {
        /// Current attempt number (1-based)
        attempt: u32,
        /// When this attempt started
        started_at: Instant,
    },

    /// Handshake completed successfully
    Completed {
        /// When handshake completed
        completed_at: Instant,
    },

    /// Handshake failed after retries
    Failed {
        /// Last attempt number
        last_attempt: u32,
        /// Error that caused failure
        last_error: HandshakeError,
    },

    /// Tunnel is disconnecting
    Disconnecting,
}


impl HandshakeState {
    /// Check if handshake is complete
    pub fn is_completed(&self) -> bool {
        matches!(self, HandshakeState::Completed { .. })
    }

    /// Check if handshake failed
    pub fn is_failed(&self) -> bool {
        matches!(self, HandshakeState::Failed { .. })
    }

    /// Check if handshake is in progress
    pub fn is_in_progress(&self) -> bool {
        matches!(self, HandshakeState::Initiated { .. })
    }

    /// Check if in disconnecting state
    pub fn is_disconnecting(&self) -> bool {
        matches!(self, HandshakeState::Disconnecting)
    }
}

/// Handshake state tracker with backoff logic
///
/// Tracks handshake attempts and implements exponential backoff
/// to prevent busy loops when connecting to unreachable peers.
///
/// # Thread Safety
///
/// This struct is thread-safe and can be shared across async tasks.
/// The state is protected by `RwLock` and counters use atomics.
pub struct HandshakeTracker {
    /// Configuration settings
    config: HandshakeConfig,

    /// Current handshake state
    state: RwLock<HandshakeState>,

    /// Current attempt number (0 = no attempts yet)
    current_attempt: AtomicU32,

    /// Unix timestamp (ms) when next retry is allowed
    next_retry_at: AtomicU64,

    /// Completion signal sender
    completion_tx: watch::Sender<bool>,

    /// Completion signal receiver
    completion_rx: watch::Receiver<bool>,
}

impl std::fmt::Debug for HandshakeTracker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HandshakeTracker")
            .field("config", &self.config)
            .field("state", &*self.state.read())
            .field("current_attempt", &self.current_attempt)
            .field("next_retry_at", &self.next_retry_at)
            .finish()
    }
}

impl HandshakeTracker {
    /// Create a new handshake tracker with the given configuration
    ///
    /// # Arguments
    ///
    /// * `config` - Handshake configuration
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::tunnel::handshake::{HandshakeTracker, HandshakeConfig};
    ///
    /// let tracker = HandshakeTracker::new(HandshakeConfig::default());
    /// ```
    pub fn new(config: HandshakeConfig) -> Self {
        let (completion_tx, completion_rx) = watch::channel(false);

        Self {
            config,
            state: RwLock::new(HandshakeState::Idle),
            current_attempt: AtomicU32::new(0),
            next_retry_at: AtomicU64::new(0),
            completion_tx,
            completion_rx,
        }
    }

    /// Create a new handshake tracker with configuration from environment
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::tunnel::handshake::HandshakeTracker;
    ///
    /// let tracker = HandshakeTracker::from_env();
    /// ```
    pub fn from_env() -> Self {
        Self::new(HandshakeConfig::from_env())
    }

    /// Get the current configuration
    pub fn config(&self) -> &HandshakeConfig {
        &self.config
    }

    /// Get the current handshake state
    pub fn state(&self) -> HandshakeState {
        self.state.read().clone()
    }

    /// Get the current attempt number
    pub fn current_attempt(&self) -> u32 {
        self.current_attempt.load(Ordering::Acquire)
    }

    /// Calculate backoff duration for the given attempt
    ///
    /// Uses exponential backoff formula:
    /// `delay_ms = min(initial_backoff_ms * (backoff_multiplier ^ attempt), max_backoff_ms)`
    ///
    /// # Arguments
    ///
    /// * `attempt` - Attempt number (0-based)
    ///
    /// # Returns
    ///
    /// Backoff duration
    pub fn calculate_backoff(&self, attempt: u32) -> Duration {
        let base = self.config.initial_backoff_ms as f64;
        let multiplier = self.config.backoff_multiplier.powi(attempt as i32);
        let delay_ms = (base * multiplier).min(self.config.max_backoff_ms as f64) as u64;

        Duration::from_millis(delay_ms)
    }

    /// Check if a handshake initiation is allowed
    ///
    /// Returns `true` if:
    /// - Not in failed or disconnecting state
    /// - Current time is past the backoff period
    /// - Retries have not been exhausted
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::tunnel::handshake::{HandshakeTracker, HandshakeConfig};
    ///
    /// let tracker = HandshakeTracker::new(HandshakeConfig::default());
    /// if tracker.can_initiate() {
    ///     // Safe to send handshake
    /// }
    /// ```
    pub fn can_initiate(&self) -> bool {
        let state = self.state.read();

        // Cannot initiate if failed or disconnecting
        if state.is_failed() || state.is_disconnecting() {
            return false;
        }

        // Check retry limit
        let attempt = self.current_attempt.load(Ordering::Acquire);
        if attempt >= self.config.max_retries {
            return false;
        }

        // Check backoff period
        let now_ms = current_time_ms();
        let next_retry = self.next_retry_at.load(Ordering::Acquire);

        now_ms >= next_retry
    }

    /// Called before sending a handshake initiation
    ///
    /// Updates state to `Initiated` and returns the attempt number.
    /// Sets the next retry time based on exponential backoff.
    ///
    /// # Returns
    ///
    /// * `Ok(attempt)` - The attempt number (1-based)
    /// * `Err(HandshakeError)` - If initiation is not allowed
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::tunnel::handshake::{HandshakeTracker, HandshakeConfig};
    ///
    /// let tracker = HandshakeTracker::new(HandshakeConfig::default());
    /// match tracker.on_initiate() {
    ///     Ok(attempt) => println!("Starting attempt {}", attempt),
    ///     Err(e) => eprintln!("Cannot initiate: {:?}", e),
    /// }
    /// ```
    pub fn on_initiate(&self) -> Result<u32, HandshakeError> {
        let mut state = self.state.write();

        // Check state
        if state.is_disconnecting() {
            return Err(HandshakeError::Disconnecting);
        }

        if state.is_failed() {
            return Err(HandshakeError::RetriesExhausted);
        }

        // Check retry limit
        let current = self.current_attempt.load(Ordering::Acquire);
        if current >= self.config.max_retries {
            *state = HandshakeState::Failed {
                last_attempt: current,
                last_error: HandshakeError::RetriesExhausted,
            };
            return Err(HandshakeError::RetriesExhausted);
        }

        // Check backoff
        let now_ms = current_time_ms();
        let next_retry = self.next_retry_at.load(Ordering::Acquire);
        if now_ms < next_retry {
            trace!(
                "Handshake backoff active, {} ms remaining",
                next_retry - now_ms
            );
            return Err(HandshakeError::AlreadyInProgress);
        }

        // Increment attempt counter
        let attempt = self.current_attempt.fetch_add(1, Ordering::AcqRel) + 1;

        // Calculate next retry time
        let backoff = self.calculate_backoff(attempt);
        let next_retry_time = now_ms + backoff.as_millis() as u64;
        self.next_retry_at.store(next_retry_time, Ordering::Release);

        // Update state
        *state = HandshakeState::Initiated {
            attempt,
            started_at: Instant::now(),
        };

        debug!(
            "Handshake attempt {} initiated, next retry in {:?}",
            attempt, backoff
        );

        Ok(attempt)
    }

    /// Called when handshake completes successfully
    ///
    /// Updates state to `Completed` and signals completion.
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::tunnel::handshake::{HandshakeTracker, HandshakeConfig};
    ///
    /// let tracker = HandshakeTracker::new(HandshakeConfig::default());
    /// // ... handshake succeeds ...
    /// tracker.on_complete();
    /// assert!(tracker.state().is_completed());
    /// ```
    pub fn on_complete(&self) {
        let mut state = self.state.write();

        if state.is_disconnecting() {
            return;
        }

        let attempt = self.current_attempt.load(Ordering::Acquire);
        debug!("Handshake completed after {} attempt(s)", attempt);

        *state = HandshakeState::Completed {
            completed_at: Instant::now(),
        };

        // Signal completion
        let _ = self.completion_tx.send(true);
    }

    /// Called when handshake times out
    ///
    /// Marks the current attempt as failed. If retries are exhausted,
    /// transitions to `Failed` state.
    pub fn on_timeout(&self) {
        let mut state = self.state.write();

        if state.is_disconnecting() {
            return;
        }

        let attempt = self.current_attempt.load(Ordering::Acquire);
        warn!("Handshake attempt {} timed out", attempt);

        if attempt >= self.config.max_retries {
            *state = HandshakeState::Failed {
                last_attempt: attempt,
                last_error: HandshakeError::Timeout,
            };
            warn!("Handshake failed after {} retries", attempt);
        } else {
            // Stay in initiated state, but allow retry after backoff
            *state = HandshakeState::Idle;
        }
    }

    /// Called when a network error occurs during handshake
    pub fn on_network_error(&self) {
        let mut state = self.state.write();

        if state.is_disconnecting() {
            return;
        }

        let attempt = self.current_attempt.load(Ordering::Acquire);
        warn!("Network error during handshake attempt {}", attempt);

        if attempt >= self.config.max_retries {
            *state = HandshakeState::Failed {
                last_attempt: attempt,
                last_error: HandshakeError::NetworkError,
            };
        }
    }

    /// Wait for handshake completion with timeout
    ///
    /// # Arguments
    ///
    /// * `timeout` - Maximum time to wait
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Handshake completed
    /// * `Err(HandshakeError::Timeout)` - Timeout exceeded
    /// * `Err(HandshakeError::RetriesExhausted)` - Retries exhausted
    pub async fn wait_completion(&self, timeout: Duration) -> Result<(), HandshakeError> {
        let mut rx = self.completion_rx.clone();

        // Check if already completed
        if *rx.borrow() {
            return Ok(());
        }

        // Check if already failed
        {
            let state = self.state.read();
            if let HandshakeState::Failed { last_error, .. } = &*state {
                return Err(last_error.clone());
            }
        }

        // Wait for completion with timeout
        let wait_result = tokio::time::timeout(timeout, async {
            rx.wait_for(|&completed| completed).await
        })
        .await;

        match wait_result {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(_)) => {
                // Channel closed
                let state = self.state.read();
                if let HandshakeState::Failed { last_error, .. } = &*state {
                    Err(last_error.clone())
                } else {
                    Err(HandshakeError::NetworkError)
                }
            }
            Err(_) => {
                self.on_timeout();
                Err(HandshakeError::Timeout)
            }
        }
    }

    /// Check if handshake has permanently failed
    ///
    /// Returns `true` if in `Failed` or `Disconnecting` state.
    pub fn is_failed(&self) -> bool {
        let state = self.state.read();
        state.is_failed() || state.is_disconnecting()
    }

    /// Check if handshake is complete
    pub fn is_completed(&self) -> bool {
        self.state.read().is_completed()
    }

    /// Reset the tracker for a new connection attempt
    ///
    /// Resets state to `Idle`, clears attempt counter, and
    /// resets the completion signal.
    pub fn reset(&self) {
        let mut state = self.state.write();

        debug!("Resetting handshake tracker");

        *state = HandshakeState::Idle;
        self.current_attempt.store(0, Ordering::Release);
        self.next_retry_at.store(0, Ordering::Release);

        // Reset completion signal
        let _ = self.completion_tx.send(false);
    }

    /// Set disconnecting state
    ///
    /// Prevents further handshake attempts.
    pub fn set_disconnecting(&self) {
        let mut state = self.state.write();
        *state = HandshakeState::Disconnecting;
        debug!("Handshake tracker set to disconnecting");
    }

    /// Get remaining time until next retry is allowed
    ///
    /// Returns `None` if retry is currently allowed.
    pub fn time_until_next_retry(&self) -> Option<Duration> {
        let now_ms = current_time_ms();
        let next_retry = self.next_retry_at.load(Ordering::Acquire);

        if now_ms >= next_retry {
            None
        } else {
            Some(Duration::from_millis(next_retry - now_ms))
        }
    }

    /// Get a receiver for completion notifications
    ///
    /// Useful for integrating with select! loops.
    pub fn completion_receiver(&self) -> watch::Receiver<bool> {
        self.completion_rx.clone()
    }
}

/// Get current time in milliseconds since Unix epoch
fn current_time_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    // ========================================================================
    // HandshakeConfig Tests
    // ========================================================================

    #[test]
    fn test_config_default() {
        let config = HandshakeConfig::default();

        assert_eq!(config.max_retries, DEFAULT_MAX_RETRIES);
        assert_eq!(config.initial_backoff_ms, DEFAULT_INITIAL_BACKOFF_MS);
        assert_eq!(config.max_backoff_ms, DEFAULT_MAX_BACKOFF_MS);
        assert_eq!(config.backoff_multiplier, DEFAULT_BACKOFF_MULTIPLIER);
        assert_eq!(config.timeout_secs, DEFAULT_TIMEOUT_SECS);
    }

    #[test]
    fn test_config_new() {
        let config = HandshakeConfig::new();
        assert_eq!(config.max_retries, DEFAULT_MAX_RETRIES);
    }

    #[test]
    fn test_config_builder() {
        let config = HandshakeConfig::new()
            .with_max_retries(10)
            .with_initial_backoff_ms(100)
            .with_max_backoff_ms(10_000)
            .with_backoff_multiplier(1.5)
            .with_timeout_secs(30);

        assert_eq!(config.max_retries, 10);
        assert_eq!(config.initial_backoff_ms, 100);
        assert_eq!(config.max_backoff_ms, 10_000);
        assert_eq!(config.backoff_multiplier, 1.5);
        assert_eq!(config.timeout_secs, 30);
    }

    #[test]
    fn test_config_validate_success() {
        let config = HandshakeConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_validate_zero_retries() {
        let config = HandshakeConfig::default().with_max_retries(0);
        assert!(matches!(
            config.validate(),
            Err(HandshakeError::InvalidConfig(_))
        ));
    }

    #[test]
    fn test_config_validate_zero_backoff() {
        let config = HandshakeConfig::default().with_initial_backoff_ms(0);
        assert!(matches!(
            config.validate(),
            Err(HandshakeError::InvalidConfig(_))
        ));
    }

    #[test]
    fn test_config_validate_invalid_backoff_range() {
        let config = HandshakeConfig::default()
            .with_initial_backoff_ms(1000)
            .with_max_backoff_ms(500);
        assert!(matches!(
            config.validate(),
            Err(HandshakeError::InvalidConfig(_))
        ));
    }

    #[test]
    fn test_config_validate_invalid_multiplier() {
        let config = HandshakeConfig::default().with_backoff_multiplier(0.5);
        assert!(matches!(
            config.validate(),
            Err(HandshakeError::InvalidConfig(_))
        ));
    }

    #[test]
    fn test_config_validate_zero_timeout() {
        let config = HandshakeConfig::default().with_timeout_secs(0);
        assert!(matches!(
            config.validate(),
            Err(HandshakeError::InvalidConfig(_))
        ));
    }

    // ========================================================================
    // HandshakeError Tests
    // ========================================================================

    #[test]
    fn test_error_display() {
        assert_eq!(format!("{}", HandshakeError::Timeout), "Handshake timed out");
        assert_eq!(
            format!("{}", HandshakeError::InvalidResponse),
            "Invalid handshake response"
        );
        assert_eq!(
            format!("{}", HandshakeError::CryptoError),
            "Cryptographic error during handshake"
        );
        assert_eq!(
            format!("{}", HandshakeError::NetworkError),
            "Network error during handshake"
        );
        assert_eq!(
            format!("{}", HandshakeError::RetriesExhausted),
            "Maximum handshake retries exhausted"
        );
        assert_eq!(
            format!("{}", HandshakeError::InvalidConfig("test".into())),
            "Invalid configuration: test"
        );
        assert_eq!(
            format!("{}", HandshakeError::AlreadyInProgress),
            "Handshake already in progress"
        );
        assert_eq!(
            format!("{}", HandshakeError::Disconnecting),
            "Tunnel is disconnecting"
        );
    }

    #[test]
    fn test_error_equality() {
        assert_eq!(HandshakeError::Timeout, HandshakeError::Timeout);
        assert_ne!(HandshakeError::Timeout, HandshakeError::NetworkError);
    }

    // ========================================================================
    // HandshakeState Tests
    // ========================================================================

    #[test]
    fn test_state_default() {
        let state = HandshakeState::default();
        assert!(matches!(state, HandshakeState::Idle));
    }

    #[test]
    fn test_state_is_completed() {
        assert!(!HandshakeState::Idle.is_completed());
        assert!(!HandshakeState::Initiated {
            attempt: 1,
            started_at: Instant::now()
        }
        .is_completed());
        assert!(HandshakeState::Completed {
            completed_at: Instant::now()
        }
        .is_completed());
        assert!(!HandshakeState::Failed {
            last_attempt: 1,
            last_error: HandshakeError::Timeout
        }
        .is_completed());
        assert!(!HandshakeState::Disconnecting.is_completed());
    }

    #[test]
    fn test_state_is_failed() {
        assert!(!HandshakeState::Idle.is_failed());
        assert!(!HandshakeState::Initiated {
            attempt: 1,
            started_at: Instant::now()
        }
        .is_failed());
        assert!(!HandshakeState::Completed {
            completed_at: Instant::now()
        }
        .is_failed());
        assert!(HandshakeState::Failed {
            last_attempt: 1,
            last_error: HandshakeError::Timeout
        }
        .is_failed());
        assert!(!HandshakeState::Disconnecting.is_failed());
    }

    #[test]
    fn test_state_is_in_progress() {
        assert!(!HandshakeState::Idle.is_in_progress());
        assert!(HandshakeState::Initiated {
            attempt: 1,
            started_at: Instant::now()
        }
        .is_in_progress());
        assert!(!HandshakeState::Completed {
            completed_at: Instant::now()
        }
        .is_in_progress());
        assert!(!HandshakeState::Failed {
            last_attempt: 1,
            last_error: HandshakeError::Timeout
        }
        .is_in_progress());
        assert!(!HandshakeState::Disconnecting.is_in_progress());
    }

    #[test]
    fn test_state_is_disconnecting() {
        assert!(!HandshakeState::Idle.is_disconnecting());
        assert!(HandshakeState::Disconnecting.is_disconnecting());
    }

    // ========================================================================
    // HandshakeTracker Tests
    // ========================================================================

    #[test]
    fn test_tracker_new() {
        let config = HandshakeConfig::default();
        let tracker = HandshakeTracker::new(config);

        assert_eq!(tracker.current_attempt(), 0);
        assert!(matches!(tracker.state(), HandshakeState::Idle));
        assert!(!tracker.is_failed());
        assert!(!tracker.is_completed());
    }

    #[test]
    fn test_tracker_from_env() {
        // Just verify it doesn't panic
        let tracker = HandshakeTracker::from_env();
        assert_eq!(tracker.current_attempt(), 0);
    }

    #[test]
    fn test_tracker_calculate_backoff() {
        let config = HandshakeConfig::default()
            .with_initial_backoff_ms(100)
            .with_backoff_multiplier(2.0)
            .with_max_backoff_ms(10_000);

        let tracker = HandshakeTracker::new(config);

        // attempt 0: 100ms
        assert_eq!(tracker.calculate_backoff(0), Duration::from_millis(100));

        // attempt 1: 100 * 2 = 200ms
        assert_eq!(tracker.calculate_backoff(1), Duration::from_millis(200));

        // attempt 2: 100 * 4 = 400ms
        assert_eq!(tracker.calculate_backoff(2), Duration::from_millis(400));

        // attempt 3: 100 * 8 = 800ms
        assert_eq!(tracker.calculate_backoff(3), Duration::from_millis(800));

        // attempt 10: capped at max_backoff_ms
        assert_eq!(tracker.calculate_backoff(10), Duration::from_millis(10_000));
    }

    #[test]
    fn test_tracker_can_initiate_initial() {
        let tracker = HandshakeTracker::new(HandshakeConfig::default());
        assert!(tracker.can_initiate());
    }

    #[test]
    fn test_tracker_can_initiate_failed() {
        let tracker = HandshakeTracker::new(HandshakeConfig::default().with_max_retries(1));

        // First attempt succeeds
        assert!(tracker.on_initiate().is_ok());

        // Simulate timeout to mark as failed
        tracker.on_timeout();

        // Should not be able to initiate when failed
        assert!(!tracker.can_initiate());
    }

    #[test]
    fn test_tracker_can_initiate_disconnecting() {
        let tracker = HandshakeTracker::new(HandshakeConfig::default());

        tracker.set_disconnecting();
        assert!(!tracker.can_initiate());
    }

    #[test]
    fn test_tracker_on_initiate_success() {
        let tracker = HandshakeTracker::new(HandshakeConfig::default());

        let attempt = tracker.on_initiate().unwrap();
        assert_eq!(attempt, 1);
        assert_eq!(tracker.current_attempt(), 1);
        assert!(tracker.state().is_in_progress());
    }

    #[test]
    fn test_tracker_on_initiate_multiple() {
        let config = HandshakeConfig::default()
            .with_max_retries(5)
            .with_initial_backoff_ms(1); // Very short backoff for testing

        let tracker = HandshakeTracker::new(config);

        // First attempt
        assert_eq!(tracker.on_initiate().unwrap(), 1);

        // Wait for backoff
        std::thread::sleep(Duration::from_millis(10));

        // Second attempt
        assert_eq!(tracker.on_initiate().unwrap(), 2);
    }

    #[test]
    fn test_tracker_on_initiate_retries_exhausted() {
        let config = HandshakeConfig::default()
            .with_max_retries(2)
            .with_initial_backoff_ms(1);

        let tracker = HandshakeTracker::new(config);

        // First attempt
        tracker.on_initiate().unwrap();
        std::thread::sleep(Duration::from_millis(5));

        // Second attempt
        tracker.on_initiate().unwrap();
        std::thread::sleep(Duration::from_millis(5));

        // Third attempt should fail
        let result = tracker.on_initiate();
        assert!(matches!(result, Err(HandshakeError::RetriesExhausted)));
        assert!(tracker.is_failed());
    }

    #[test]
    fn test_tracker_on_initiate_disconnecting() {
        let tracker = HandshakeTracker::new(HandshakeConfig::default());

        tracker.set_disconnecting();

        let result = tracker.on_initiate();
        assert!(matches!(result, Err(HandshakeError::Disconnecting)));
    }

    #[test]
    fn test_tracker_on_complete() {
        let tracker = HandshakeTracker::new(HandshakeConfig::default());

        tracker.on_initiate().unwrap();
        tracker.on_complete();

        assert!(tracker.is_completed());
        assert!(tracker.state().is_completed());
    }

    #[test]
    fn test_tracker_on_complete_signals() {
        let tracker = HandshakeTracker::new(HandshakeConfig::default());
        let mut rx = tracker.completion_receiver();

        assert!(!*rx.borrow());

        tracker.on_initiate().unwrap();
        tracker.on_complete();

        assert!(*rx.borrow_and_update());
    }

    #[test]
    fn test_tracker_on_timeout() {
        let config = HandshakeConfig::default().with_max_retries(2);
        let tracker = HandshakeTracker::new(config);

        // First attempt
        tracker.on_initiate().unwrap();
        tracker.on_timeout();

        // Should transition to idle, allowing another attempt
        assert!(matches!(tracker.state(), HandshakeState::Idle));
    }

    #[test]
    fn test_tracker_on_timeout_exhausted() {
        let config = HandshakeConfig::default()
            .with_max_retries(1)
            .with_initial_backoff_ms(1);

        let tracker = HandshakeTracker::new(config);

        // Only one retry allowed
        tracker.on_initiate().unwrap();
        tracker.on_timeout();

        // Should be failed now
        assert!(tracker.is_failed());
    }

    #[test]
    fn test_tracker_on_network_error() {
        let config = HandshakeConfig::default().with_max_retries(1);
        let tracker = HandshakeTracker::new(config);

        tracker.on_initiate().unwrap();
        tracker.on_network_error();

        // With only 1 retry, should be failed
        assert!(tracker.is_failed());
    }

    #[test]
    fn test_tracker_reset() {
        let config = HandshakeConfig::default().with_initial_backoff_ms(1);
        let tracker = HandshakeTracker::new(config);

        // Make some progress
        tracker.on_initiate().unwrap();
        std::thread::sleep(Duration::from_millis(5));
        tracker.on_initiate().unwrap();

        // Reset
        tracker.reset();

        assert_eq!(tracker.current_attempt(), 0);
        assert!(matches!(tracker.state(), HandshakeState::Idle));
        assert!(!tracker.is_failed());
        assert!(!tracker.is_completed());
        assert!(tracker.can_initiate());
    }

    #[test]
    fn test_tracker_reset_completion_signal() {
        let tracker = HandshakeTracker::new(HandshakeConfig::default());
        let rx = tracker.completion_receiver();

        tracker.on_initiate().unwrap();
        tracker.on_complete();
        assert!(*rx.borrow());

        tracker.reset();
        assert!(!*rx.borrow());
    }

    #[test]
    fn test_tracker_time_until_next_retry() {
        let config = HandshakeConfig::default()
            .with_initial_backoff_ms(1000)
            .with_backoff_multiplier(2.0);

        let tracker = HandshakeTracker::new(config);

        // Initially no backoff
        assert!(tracker.time_until_next_retry().is_none());

        // After initiate, there should be backoff
        tracker.on_initiate().unwrap();

        let remaining = tracker.time_until_next_retry();
        assert!(remaining.is_some());
        assert!(remaining.unwrap() <= Duration::from_millis(2000));
    }

    #[test]
    fn test_tracker_debug() {
        let tracker = HandshakeTracker::new(HandshakeConfig::default());
        let debug = format!("{:?}", tracker);

        assert!(debug.contains("HandshakeTracker"));
        assert!(debug.contains("config"));
        assert!(debug.contains("state"));
    }

    #[tokio::test]
    async fn test_tracker_wait_completion_already_completed() {
        let tracker = HandshakeTracker::new(HandshakeConfig::default());

        tracker.on_initiate().unwrap();
        tracker.on_complete();

        let result = tracker.wait_completion(Duration::from_millis(100)).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_tracker_wait_completion_timeout() {
        let tracker = HandshakeTracker::new(HandshakeConfig::default());

        tracker.on_initiate().unwrap();

        let result = tracker.wait_completion(Duration::from_millis(50)).await;
        assert!(matches!(result, Err(HandshakeError::Timeout)));
    }

    #[tokio::test]
    async fn test_tracker_wait_completion_already_failed() {
        let config = HandshakeConfig::default().with_max_retries(1);
        let tracker = HandshakeTracker::new(config);

        tracker.on_initiate().unwrap();
        tracker.on_timeout();

        let result = tracker.wait_completion(Duration::from_millis(100)).await;
        assert!(matches!(result, Err(HandshakeError::Timeout)));
    }

    #[tokio::test]
    async fn test_tracker_wait_completion_success() {
        use std::sync::Arc;

        let tracker = Arc::new(HandshakeTracker::new(HandshakeConfig::default()));
        let tracker_bg = Arc::clone(&tracker);

        tracker.on_initiate().unwrap();

        // Complete in background
        let handle = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            tracker_bg.on_complete();
        });

        // Wait in foreground
        let result = tracker.wait_completion(Duration::from_millis(100)).await;

        handle.await.unwrap();
        assert!(result.is_ok());
    }

    // ========================================================================
    // Integration / Edge Case Tests
    // ========================================================================

    #[test]
    fn test_backoff_exponential_growth() {
        let config = HandshakeConfig::default()
            .with_initial_backoff_ms(100)
            .with_backoff_multiplier(2.0)
            .with_max_backoff_ms(100_000);

        let tracker = HandshakeTracker::new(config);

        let b0 = tracker.calculate_backoff(0).as_millis();
        let b1 = tracker.calculate_backoff(1).as_millis();
        let b2 = tracker.calculate_backoff(2).as_millis();
        let b3 = tracker.calculate_backoff(3).as_millis();

        // Verify exponential growth
        assert_eq!(b0, 100);
        assert_eq!(b1, 200);
        assert_eq!(b2, 400);
        assert_eq!(b3, 800);
    }

    #[test]
    fn test_backoff_caps_at_max() {
        let config = HandshakeConfig::default()
            .with_initial_backoff_ms(1000)
            .with_backoff_multiplier(10.0)
            .with_max_backoff_ms(5000);

        let tracker = HandshakeTracker::new(config);

        // After a few attempts, should cap at max
        assert!(tracker.calculate_backoff(5) <= Duration::from_millis(5000));
        assert_eq!(tracker.calculate_backoff(100), Duration::from_millis(5000));
    }

    #[test]
    fn test_concurrent_access_safety() {
        use std::sync::Arc;
        use std::thread;

        let config = HandshakeConfig::default()
            .with_max_retries(100)
            .with_initial_backoff_ms(1);

        let tracker = Arc::new(HandshakeTracker::new(config));

        let mut handles = vec![];

        // Spawn multiple threads accessing the tracker
        for _ in 0..10 {
            let t = Arc::clone(&tracker);
            handles.push(thread::spawn(move || {
                for _ in 0..10 {
                    let _ = t.can_initiate();
                    let _ = t.state();
                    let _ = t.current_attempt();
                    let _ = t.is_failed();
                }
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }
    }

    #[test]
    fn test_state_transitions() {
        let config = HandshakeConfig::default()
            .with_max_retries(3)
            .with_initial_backoff_ms(1);

        let tracker = HandshakeTracker::new(config);

        // Idle -> Initiated
        assert!(matches!(tracker.state(), HandshakeState::Idle));
        tracker.on_initiate().unwrap();
        assert!(matches!(tracker.state(), HandshakeState::Initiated { .. }));

        // Initiated -> Completed
        tracker.on_complete();
        assert!(matches!(tracker.state(), HandshakeState::Completed { .. }));

        // Reset -> Idle
        tracker.reset();
        assert!(matches!(tracker.state(), HandshakeState::Idle));

        // Idle -> Initiated -> timeout -> Idle (with retries left)
        tracker.on_initiate().unwrap();
        tracker.on_timeout();
        assert!(matches!(tracker.state(), HandshakeState::Idle));

        // Exhaust retries to reach Failed
        std::thread::sleep(Duration::from_millis(5));
        tracker.on_initiate().unwrap();
        std::thread::sleep(Duration::from_millis(5));
        tracker.on_initiate().unwrap();
        std::thread::sleep(Duration::from_millis(5));
        let result = tracker.on_initiate();
        assert!(matches!(result, Err(HandshakeError::RetriesExhausted)));
        assert!(matches!(tracker.state(), HandshakeState::Failed { .. }));
    }

    #[test]
    fn test_disconnecting_prevents_all_operations() {
        let tracker = HandshakeTracker::new(HandshakeConfig::default());

        tracker.set_disconnecting();

        // Cannot initiate
        assert!(!tracker.can_initiate());
        assert!(matches!(
            tracker.on_initiate(),
            Err(HandshakeError::Disconnecting)
        ));

        // is_failed returns true for disconnecting
        assert!(tracker.is_failed());
    }
}
