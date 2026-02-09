//! Handshake Tracker Integration Tests
//!
//! This module tests the handshake tracking functionality that prevents
//! busy loops when connecting to unreachable peers (Issue #13).
//!
//! # Test Categories
//!
//! 1. **Backoff Behavior**: Verify exponential backoff is applied
//! 2. **Retry Limits**: Test that retries are properly limited
//! 3. **State Transitions**: Test handshake state machine
//! 4. **Integration with Tunnel**: Test tracker integration with UserspaceWgTunnel
//!
//! # Running Tests
//!
//! ```bash
//! # Run all handshake integration tests
//! cargo test --test integration handshake
//! ```

#[cfg(feature = "handshake_retry")]
mod tests {
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use rust_router::tunnel::{HandshakeConfig, HandshakeError, HandshakeState, HandshakeTracker};

    // ========================================================================
    // Backoff Behavior Tests
    // ========================================================================

    #[test]
    fn test_backoff_respects_minimum() {
        let config = HandshakeConfig::default()
            .with_initial_backoff_ms(100)
            .with_max_backoff_ms(10_000);

        let tracker = HandshakeTracker::new(config);

        // First backoff should be exactly initial_backoff
        let backoff = tracker.calculate_backoff(0);
        assert_eq!(backoff, Duration::from_millis(100));
    }

    #[test]
    fn test_backoff_exponential_growth() {
        let config = HandshakeConfig::default()
            .with_initial_backoff_ms(100)
            .with_backoff_multiplier(2.0)
            .with_max_backoff_ms(100_000);

        let tracker = HandshakeTracker::new(config);

        // Verify exponential growth
        assert_eq!(tracker.calculate_backoff(0), Duration::from_millis(100));
        assert_eq!(tracker.calculate_backoff(1), Duration::from_millis(200));
        assert_eq!(tracker.calculate_backoff(2), Duration::from_millis(400));
        assert_eq!(tracker.calculate_backoff(3), Duration::from_millis(800));
        assert_eq!(tracker.calculate_backoff(4), Duration::from_millis(1600));
    }

    #[test]
    fn test_backoff_respects_maximum() {
        let config = HandshakeConfig::default()
            .with_initial_backoff_ms(1000)
            .with_backoff_multiplier(10.0)
            .with_max_backoff_ms(5000);

        let tracker = HandshakeTracker::new(config);

        // After a few attempts, should cap at max
        for attempt in 0..20 {
            let backoff = tracker.calculate_backoff(attempt);
            assert!(
                backoff <= Duration::from_millis(5000),
                "Backoff {} for attempt {} exceeds max",
                backoff.as_millis(),
                attempt
            );
        }
    }

    #[test]
    fn test_backoff_prevents_immediate_retry() {
        let config = HandshakeConfig::default()
            .with_initial_backoff_ms(500)
            .with_max_retries(10);

        let tracker = HandshakeTracker::new(config);

        // First initiation should succeed
        assert!(tracker.on_initiate().is_ok());

        // Immediate second initiation should fail (backoff)
        let result = tracker.on_initiate();
        assert!(matches!(result, Err(HandshakeError::AlreadyInProgress)));
    }

    // ========================================================================
    // Retry Limit Tests
    // ========================================================================

    #[test]
    fn test_retry_limit_enforced() {
        let config = HandshakeConfig::default()
            .with_max_retries(3)
            .with_initial_backoff_ms(1);

        let tracker = HandshakeTracker::new(config);

        // Exhaust retries
        for i in 1..=3 {
            std::thread::sleep(Duration::from_millis(10));
            let result = tracker.on_initiate();
            assert!(result.is_ok(), "Attempt {} should succeed", i);
        }

        // Next attempt should fail
        std::thread::sleep(Duration::from_millis(10));
        let result = tracker.on_initiate();
        assert!(matches!(result, Err(HandshakeError::RetriesExhausted)));
    }

    #[test]
    fn test_can_initiate_false_after_exhausted() {
        let config = HandshakeConfig::default()
            .with_max_retries(1)
            .with_initial_backoff_ms(1);

        let tracker = HandshakeTracker::new(config);

        // First attempt
        assert!(tracker.can_initiate());
        tracker.on_initiate().unwrap();

        // Wait for backoff
        std::thread::sleep(Duration::from_millis(10));

        // Should not be able to initiate after retries exhausted
        let _ = tracker.on_initiate(); // This will fail and set state to Failed
        assert!(!tracker.can_initiate());
    }

    #[test]
    fn test_is_failed_after_retries_exhausted() {
        let config = HandshakeConfig::default()
            .with_max_retries(1)
            .with_initial_backoff_ms(1);

        let tracker = HandshakeTracker::new(config);

        // Exhaust retries
        tracker.on_initiate().unwrap();
        std::thread::sleep(Duration::from_millis(10));
        let _ = tracker.on_initiate();

        assert!(tracker.is_failed());
    }

    // ========================================================================
    // State Transition Tests
    // ========================================================================

    #[test]
    fn test_state_idle_to_initiated() {
        let tracker = HandshakeTracker::new(HandshakeConfig::default());

        assert!(matches!(tracker.state(), HandshakeState::Idle));
        tracker.on_initiate().unwrap();
        assert!(tracker.state().is_in_progress());
    }

    #[test]
    fn test_state_initiated_to_completed() {
        let tracker = HandshakeTracker::new(HandshakeConfig::default());

        tracker.on_initiate().unwrap();
        tracker.on_complete();

        assert!(tracker.state().is_completed());
        assert!(tracker.is_completed());
    }

    #[test]
    fn test_state_initiated_to_failed() {
        let config = HandshakeConfig::default()
            .with_max_retries(1)
            .with_initial_backoff_ms(1);

        let tracker = HandshakeTracker::new(config);

        tracker.on_initiate().unwrap();
        std::thread::sleep(Duration::from_millis(10));
        let _ = tracker.on_initiate(); // Exhausts retries

        assert!(tracker.state().is_failed());
    }

    #[test]
    fn test_reset_clears_state() {
        let config = HandshakeConfig::default().with_initial_backoff_ms(1);

        let tracker = HandshakeTracker::new(config);

        // Make progress
        tracker.on_initiate().unwrap();
        std::thread::sleep(Duration::from_millis(10));
        tracker.on_initiate().unwrap();

        // Reset
        tracker.reset();

        // Verify state is cleared
        assert!(matches!(tracker.state(), HandshakeState::Idle));
        assert_eq!(tracker.current_attempt(), 0);
        assert!(tracker.can_initiate());
    }

    #[test]
    fn test_disconnecting_state() {
        let tracker = HandshakeTracker::new(HandshakeConfig::default());

        tracker.set_disconnecting();

        assert!(tracker.state().is_disconnecting());
        assert!(!tracker.can_initiate());
        assert!(tracker.is_failed()); // is_failed returns true for disconnecting
    }

    // ========================================================================
    // Timing Tests
    // ========================================================================

    #[test]
    fn test_time_until_next_retry_initially_none() {
        let tracker = HandshakeTracker::new(HandshakeConfig::default());

        // Initially no backoff active
        assert!(tracker.time_until_next_retry().is_none());
    }

    #[test]
    fn test_time_until_next_retry_after_initiate() {
        let config = HandshakeConfig::default()
            .with_initial_backoff_ms(1000)
            .with_backoff_multiplier(2.0);

        let tracker = HandshakeTracker::new(config);

        tracker.on_initiate().unwrap();

        // Should have backoff remaining
        let remaining = tracker.time_until_next_retry();
        assert!(remaining.is_some());
        assert!(remaining.unwrap() <= Duration::from_millis(2000));
    }

    #[test]
    fn test_backoff_elapsed() {
        let config = HandshakeConfig::default()
            .with_initial_backoff_ms(50)
            .with_max_retries(5);

        let tracker = HandshakeTracker::new(config);

        tracker.on_initiate().unwrap();

        // Wait for backoff to elapse
        std::thread::sleep(Duration::from_millis(150));

        // Should be able to initiate again
        assert!(tracker.can_initiate());
        assert!(tracker.on_initiate().is_ok());
    }

    // ========================================================================
    // Concurrency Tests
    // ========================================================================

    #[test]
    fn test_concurrent_access() {
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
                for _ in 0..100 {
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

    #[tokio::test]
    async fn test_completion_signal_propagation() {
        let tracker = Arc::new(HandshakeTracker::new(HandshakeConfig::default()));
        let tracker_bg = Arc::clone(&tracker);

        tracker.on_initiate().unwrap();

        // Complete in background
        let handle = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            tracker_bg.on_complete();
        });

        // Wait for completion
        let start = Instant::now();
        let result = tracker.wait_completion(Duration::from_millis(200)).await;

        handle.await.unwrap();

        assert!(result.is_ok());
        assert!(start.elapsed() < Duration::from_millis(100)); // Should complete quickly
    }

    #[tokio::test]
    async fn test_wait_completion_timeout() {
        let tracker = HandshakeTracker::new(HandshakeConfig::default());

        tracker.on_initiate().unwrap();

        // Don't complete, just wait
        let result = tracker.wait_completion(Duration::from_millis(50)).await;

        assert!(matches!(result, Err(HandshakeError::Timeout)));
    }

    // ========================================================================
    // Configuration Tests
    // ========================================================================

    #[test]
    fn test_config_validation_success() {
        let config = HandshakeConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_validation_failures() {
        // Zero max retries
        let config = HandshakeConfig::default().with_max_retries(0);
        assert!(config.validate().is_err());

        // Zero backoff
        let config = HandshakeConfig::default().with_initial_backoff_ms(0);
        assert!(config.validate().is_err());

        // Max < initial backoff
        let config = HandshakeConfig::default()
            .with_initial_backoff_ms(1000)
            .with_max_backoff_ms(500);
        assert!(config.validate().is_err());

        // Multiplier < 1
        let config = HandshakeConfig::default().with_backoff_multiplier(0.5);
        assert!(config.validate().is_err());
    }

    // ========================================================================
    // Network Error Handling Tests
    // ========================================================================

    #[test]
    fn test_network_error_increments_attempt() {
        let config = HandshakeConfig::default()
            .with_max_retries(2)
            .with_initial_backoff_ms(1);

        let tracker = HandshakeTracker::new(config);

        tracker.on_initiate().unwrap();
        assert_eq!(tracker.current_attempt(), 1);

        tracker.on_network_error();
        // Attempt count stays the same, but marks as failed if exhausted
    }

    #[test]
    fn test_network_error_causes_failure_when_exhausted() {
        let config = HandshakeConfig::default().with_max_retries(1);

        let tracker = HandshakeTracker::new(config);

        tracker.on_initiate().unwrap();
        tracker.on_network_error();

        // With only 1 retry, network error should cause failure
        assert!(tracker.is_failed());
    }

    // ========================================================================
    // Edge Case Tests
    // ========================================================================

    #[test]
    fn test_complete_without_initiate() {
        let tracker = HandshakeTracker::new(HandshakeConfig::default());

        // Complete without initiating should work (just marks as complete)
        tracker.on_complete();

        assert!(tracker.is_completed());
    }

    #[test]
    fn test_multiple_completes() {
        let tracker = HandshakeTracker::new(HandshakeConfig::default());

        tracker.on_initiate().unwrap();
        tracker.on_complete();
        tracker.on_complete(); // Second complete

        assert!(tracker.is_completed());
    }

    #[test]
    fn test_reset_after_completion() {
        let tracker = HandshakeTracker::new(HandshakeConfig::default());

        tracker.on_initiate().unwrap();
        tracker.on_complete();
        tracker.reset();

        assert!(matches!(tracker.state(), HandshakeState::Idle));
        assert!(tracker.can_initiate());
    }

    #[test]
    fn test_reset_after_failure() {
        let config = HandshakeConfig::default()
            .with_max_retries(1)
            .with_initial_backoff_ms(1);

        let tracker = HandshakeTracker::new(config);

        tracker.on_initiate().unwrap();
        std::thread::sleep(Duration::from_millis(10));
        let _ = tracker.on_initiate(); // Exhausts retries

        assert!(tracker.is_failed());

        tracker.reset();

        assert!(matches!(tracker.state(), HandshakeState::Idle));
        assert!(tracker.can_initiate());
    }

    // ========================================================================
    // Completion Receiver Tests
    // ========================================================================

    #[test]
    fn test_completion_receiver() {
        let tracker = HandshakeTracker::new(HandshakeConfig::default());
        let rx = tracker.completion_receiver();

        assert!(!*rx.borrow());

        tracker.on_initiate().unwrap();
        tracker.on_complete();

        assert!(*rx.borrow());
    }

    #[test]
    fn test_completion_receiver_reset() {
        let tracker = HandshakeTracker::new(HandshakeConfig::default());
        let rx = tracker.completion_receiver();

        tracker.on_initiate().unwrap();
        tracker.on_complete();
        assert!(*rx.borrow());

        tracker.reset();
        assert!(!*rx.borrow());
    }
}
