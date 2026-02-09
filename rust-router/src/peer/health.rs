//! Health checker with hysteresis
//!
//! This module implements health checking for peer tunnels with
//! hysteresis to prevent rapid state flapping.
//!
//! # Hysteresis Mechanism
//!
//! To prevent rapid state changes (flapping) due to transient
//! network issues, the health checker requires multiple consecutive
//! failures before marking a peer as unhealthy.
//!
//! - Success: Immediately resets the failure counter
//! - Failure: Increments counter; peer marked unhealthy only after threshold
//!
//! Default threshold: 3 consecutive failures
//!
//! # Thread Safety
//!
//! The health checker uses `RwLock` for thread-safe access to
//! failure counts across concurrent health check operations.
//!
//! # References
//!
//! - Implementation Plan: `docs/PHASE6_IMPLEMENTATION_PLAN_v3.2.md` Section 6.5.4

use std::collections::HashMap;
use std::sync::RwLock;

/// Default number of consecutive failures before marking unhealthy
pub const DEFAULT_FAILURE_THRESHOLD: u32 = 3;

/// Health checker with hysteresis support
///
/// Tracks consecutive health check failures per peer and provides
/// hysteresis to prevent rapid state changes.
pub struct HealthChecker {
    /// Number of consecutive failures required to mark unhealthy
    failure_threshold: u32,
    /// Map of peer tag to consecutive failure count
    peer_failures: RwLock<HashMap<String, u32>>,
}

impl HealthChecker {
    /// Create a new health checker
    ///
    /// # Arguments
    ///
    /// * `failure_threshold` - Number of consecutive failures before unhealthy
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::peer::health::HealthChecker;
    ///
    /// let checker = HealthChecker::new(3);
    /// ```
    pub fn new(failure_threshold: u32) -> Self {
        Self {
            failure_threshold,
            peer_failures: RwLock::new(HashMap::new()),
        }
    }

    /// Record a health check failure
    ///
    /// Increments the consecutive failure count for the peer.
    ///
    /// # Arguments
    ///
    /// * `peer_tag` - The peer's tag identifier
    ///
    /// # Returns
    ///
    /// `true` if the failure threshold has been exceeded (peer should be
    /// marked unhealthy), `false` otherwise.
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::peer::health::HealthChecker;
    ///
    /// let checker = HealthChecker::new(3);
    ///
    /// assert!(!checker.record_failure("peer-1")); // 1st failure
    /// assert!(!checker.record_failure("peer-1")); // 2nd failure
    /// assert!(checker.record_failure("peer-1"));  // 3rd failure - threshold exceeded
    /// ```
    pub fn record_failure(&self, peer_tag: &str) -> bool {
        // Recover from poisoned lock - the failure counts are still valid
        let mut failures = match self.peer_failures.write() {
            Ok(guard) => guard,
            Err(poisoned) => {
                tracing::warn!(
                    "HealthChecker lock was poisoned (prior panic), recovering for failure recording"
                );
                poisoned.into_inner()
            }
        };

        let count = failures.entry(peer_tag.to_string()).or_insert(0);
        *count += 1;
        *count >= self.failure_threshold
    }

    /// Record a health check success
    ///
    /// Resets the consecutive failure count for the peer to zero.
    ///
    /// # Arguments
    ///
    /// * `peer_tag` - The peer's tag identifier
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::peer::health::HealthChecker;
    ///
    /// let checker = HealthChecker::new(3);
    ///
    /// checker.record_failure("peer-1");
    /// checker.record_failure("peer-1");
    /// checker.record_success("peer-1"); // Resets counter
    /// assert_eq!(checker.get_failure_count("peer-1"), 0);
    /// ```
    pub fn record_success(&self, peer_tag: &str) {
        // Recover from poisoned lock if necessary
        let mut failures = match self.peer_failures.write() {
            Ok(guard) => guard,
            Err(poisoned) => {
                tracing::warn!(
                    "HealthChecker lock was poisoned (prior panic), recovering for success recording"
                );
                poisoned.into_inner()
            }
        };
        failures.remove(peer_tag);
    }

    /// Get the current failure count for a peer
    ///
    /// # Arguments
    ///
    /// * `peer_tag` - The peer's tag identifier
    ///
    /// # Returns
    ///
    /// The current consecutive failure count (0 if healthy or unknown).
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::peer::health::HealthChecker;
    ///
    /// let checker = HealthChecker::new(3);
    ///
    /// assert_eq!(checker.get_failure_count("peer-1"), 0);
    /// checker.record_failure("peer-1");
    /// assert_eq!(checker.get_failure_count("peer-1"), 1);
    /// ```
    pub fn get_failure_count(&self, peer_tag: &str) -> u32 {
        // Recover from poisoned lock if necessary
        let failures = match self.peer_failures.read() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        failures.get(peer_tag).copied().unwrap_or(0)
    }

    /// Check if a peer has exceeded the failure threshold
    ///
    /// # Arguments
    ///
    /// * `peer_tag` - The peer's tag identifier
    ///
    /// # Returns
    ///
    /// `true` if the peer has exceeded the failure threshold.
    pub fn is_unhealthy(&self, peer_tag: &str) -> bool {
        self.get_failure_count(peer_tag) >= self.failure_threshold
    }

    /// Get the failure threshold
    pub fn failure_threshold(&self) -> u32 {
        self.failure_threshold
    }

    /// Clear failure count for a specific peer
    ///
    /// # Arguments
    ///
    /// * `peer_tag` - The peer's tag identifier
    pub fn clear(&self, peer_tag: &str) {
        // Recover from poisoned lock if necessary
        let mut failures = match self.peer_failures.write() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        failures.remove(peer_tag);
    }

    /// Clear all failure counts
    pub fn clear_all(&self) {
        // Recover from poisoned lock if necessary
        let mut failures = match self.peer_failures.write() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        failures.clear();
    }

    /// Get the number of peers with recorded failures
    pub fn peers_with_failures(&self) -> usize {
        // Recover from poisoned lock if necessary
        let failures = match self.peer_failures.read() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        failures.len()
    }

    /// Get all peers currently marked as unhealthy
    ///
    /// # Returns
    ///
    /// List of peer tags that have exceeded the failure threshold.
    pub fn unhealthy_peers(&self) -> Vec<String> {
        // Recover from poisoned lock if necessary
        let failures = match self.peer_failures.read() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        failures
            .iter()
            .filter(|(_, &count)| count >= self.failure_threshold)
            .map(|(tag, _)| tag.clone())
            .collect()
    }
}

impl Default for HealthChecker {
    fn default() -> Self {
        Self::new(DEFAULT_FAILURE_THRESHOLD)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_checker() {
        let checker = HealthChecker::new(5);
        assert_eq!(checker.failure_threshold(), 5);
    }

    #[test]
    fn test_failure_threshold() {
        let checker = HealthChecker::new(3);

        // First two failures don't exceed threshold
        assert!(!checker.record_failure("peer-1"));
        assert!(!checker.record_failure("peer-1"));

        // Third failure exceeds threshold
        assert!(checker.record_failure("peer-1"));

        // Fourth failure also exceeds (already unhealthy)
        assert!(checker.record_failure("peer-1"));
    }

    #[test]
    fn test_success_resets_count() {
        let checker = HealthChecker::new(3);

        checker.record_failure("peer-1");
        checker.record_failure("peer-1");
        assert_eq!(checker.get_failure_count("peer-1"), 2);

        checker.record_success("peer-1");
        assert_eq!(checker.get_failure_count("peer-1"), 0);

        // Need 3 more failures to exceed threshold again
        assert!(!checker.record_failure("peer-1"));
        assert!(!checker.record_failure("peer-1"));
        assert!(checker.record_failure("peer-1"));
    }

    #[test]
    fn test_multiple_peers() {
        let checker = HealthChecker::new(2);

        checker.record_failure("peer-1");
        checker.record_failure("peer-2");

        assert_eq!(checker.get_failure_count("peer-1"), 1);
        assert_eq!(checker.get_failure_count("peer-2"), 1);

        assert!(checker.record_failure("peer-1")); // Threshold exceeded
        assert!(!checker.is_unhealthy("peer-2"));
        assert!(checker.is_unhealthy("peer-1"));
    }

    #[test]
    fn test_is_unhealthy() {
        let checker = HealthChecker::new(2);

        assert!(!checker.is_unhealthy("peer-1"));
        checker.record_failure("peer-1");
        assert!(!checker.is_unhealthy("peer-1"));
        checker.record_failure("peer-1");
        assert!(checker.is_unhealthy("peer-1"));
    }

    #[test]
    fn test_clear() {
        let checker = HealthChecker::new(2);

        checker.record_failure("peer-1");
        checker.record_failure("peer-1");
        assert!(checker.is_unhealthy("peer-1"));

        checker.clear("peer-1");
        assert!(!checker.is_unhealthy("peer-1"));
        assert_eq!(checker.get_failure_count("peer-1"), 0);
    }

    #[test]
    fn test_clear_all() {
        let checker = HealthChecker::new(2);

        checker.record_failure("peer-1");
        checker.record_failure("peer-2");

        assert_eq!(checker.peers_with_failures(), 2);

        checker.clear_all();
        assert_eq!(checker.peers_with_failures(), 0);
    }

    #[test]
    fn test_unhealthy_peers() {
        let checker = HealthChecker::new(2);

        checker.record_failure("peer-1");
        checker.record_failure("peer-1");
        checker.record_failure("peer-2");

        let unhealthy = checker.unhealthy_peers();
        assert_eq!(unhealthy.len(), 1);
        assert!(unhealthy.contains(&"peer-1".to_string()));
    }

    #[test]
    fn test_default() {
        let checker = HealthChecker::default();
        assert_eq!(checker.failure_threshold(), DEFAULT_FAILURE_THRESHOLD);
    }
}
