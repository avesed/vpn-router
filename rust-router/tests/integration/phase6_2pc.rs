//! Phase 6 Two-Phase Commit Integration Tests
//!
//! Integration tests for the Two-Phase Commit protocol used in
//! distributed chain activation.
//!
//! # Test Categories
//!
//! - 2PC coordinator creation
//! - PREPARE phase
//! - COMMIT phase
//! - ABORT/rollback
//! - Timeout handling
//!
//! # Phase 6 Implementation Status
//!
//! These tests are placeholders that will be implemented as Phase 6
//! features are completed.

use rust_router::chain::two_phase::{
    TwoPhaseCommit, TwoPhaseError, TwoPhaseState,
};
use rust_router::ipc::{ChainConfig, ChainHop, ChainRole, TunnelType};

// ============================================================================
// Two-Phase Commit State Tests
// ============================================================================

#[test]
fn test_two_phase_state_display() {
    assert_eq!(TwoPhaseState::Pending.to_string(), "pending");
    assert_eq!(TwoPhaseState::Preparing.to_string(), "preparing");
    assert_eq!(TwoPhaseState::Prepared.to_string(), "prepared");
    assert_eq!(TwoPhaseState::Committing.to_string(), "committing");
    assert_eq!(TwoPhaseState::Committed.to_string(), "committed");
    assert_eq!(TwoPhaseState::Aborted.to_string(), "aborted");
    assert_eq!(TwoPhaseState::Failed("test".to_string()).to_string(), "failed: test");
}

#[test]
fn test_two_phase_state_equality() {
    assert_eq!(TwoPhaseState::Pending, TwoPhaseState::Pending);
    assert_ne!(TwoPhaseState::Pending, TwoPhaseState::Prepared);

    // Failed states with different messages are not equal
    assert_ne!(
        TwoPhaseState::Failed("a".to_string()),
        TwoPhaseState::Failed("b".to_string())
    );
}

// ============================================================================
// Two-Phase Commit Coordinator Tests
// ============================================================================

#[test]
fn test_coordinator_creation() {
    let config = create_test_chain_config();
    let coordinator = TwoPhaseCommit::new(
        "test-chain".to_string(),
        config.clone(),
        vec!["node-a".to_string(), "node-b".to_string()],
    );

    assert_eq!(coordinator.chain_tag(), "test-chain");
    assert_eq!(*coordinator.transaction_state(), TwoPhaseState::Pending);
    assert_eq!(coordinator.participants().count(), 2);
}

#[test]
fn test_coordinator_all_prepared() {
    let config = create_test_chain_config();
    let mut coordinator = TwoPhaseCommit::new(
        "test-chain".to_string(),
        config,
        vec!["node-a".to_string(), "node-b".to_string()],
    );

    // Initially not all prepared
    assert!(!coordinator.all_prepared());

    // Prepare first node
    coordinator.record_prepare_success("node-a").unwrap();
    assert!(!coordinator.all_prepared());

    // Prepare second node
    coordinator.record_prepare_success("node-b").unwrap();
    assert!(coordinator.all_prepared());
}

#[test]
fn test_coordinator_any_failed() {
    let config = create_test_chain_config();
    let mut coordinator = TwoPhaseCommit::new(
        "test-chain".to_string(),
        config,
        vec!["node-a".to_string(), "node-b".to_string()],
    );

    // Initially no failures
    assert!(!coordinator.any_failed());

    // Record a failure
    coordinator
        .record_prepare_failure("node-a", "test error".to_string())
        .unwrap();
    assert!(coordinator.any_failed());
}

#[test]
fn test_coordinator_prepared_nodes() {
    let config = create_test_chain_config();
    let mut coordinator = TwoPhaseCommit::new(
        "test-chain".to_string(),
        config,
        vec!["node-a".to_string(), "node-b".to_string()],
    );

    // Initially no prepared nodes
    assert!(coordinator.prepared_nodes().is_empty());

    // Prepare one node
    coordinator.record_prepare_success("node-a").unwrap();
    let prepared = coordinator.prepared_nodes();
    assert_eq!(prepared.len(), 1);
    assert!(prepared.contains(&"node-a".to_string()));
}

#[test]
fn test_coordinator_record_commit() {
    let config = create_test_chain_config();
    let mut coordinator = TwoPhaseCommit::new(
        "test-chain".to_string(),
        config,
        vec!["node-a".to_string()],
    );

    coordinator.record_prepare_success("node-a").unwrap();
    coordinator.record_commit_success("node-a").unwrap();

    let participant = coordinator.get_participant("node-a").unwrap();
    assert_eq!(participant.state, TwoPhaseState::Committed);
}

#[test]
fn test_coordinator_participant_not_found() {
    let config = create_test_chain_config();
    let mut coordinator = TwoPhaseCommit::new(
        "test-chain".to_string(),
        config,
        vec!["node-a".to_string()],
    );

    let result = coordinator.record_prepare_success("nonexistent");
    assert!(matches!(result, Err(TwoPhaseError::ParticipantNotFound(_))));
}

#[test]
fn test_coordinator_with_timeout() {
    let config = create_test_chain_config();
    let coordinator = TwoPhaseCommit::new(
        "test-chain".to_string(),
        config,
        vec!["node-a".to_string()],
    )
    .with_timeout(60);

    // Timeout is set (we can't easily verify this without adding a getter)
    assert_eq!(coordinator.chain_tag(), "test-chain");
}

// ============================================================================
// Two-Phase Commit Protocol Tests (Placeholders)
// ============================================================================

#[test]
#[ignore = "Phase 6.6: 2PC not yet implemented"]
fn test_2pc_prepare_phase() {
    // TODO: Test PREPARE phase
    // 1. Create coordinator
    // 2. Send PREPARE to all participants
    // 3. Verify all respond with PREPARED
}

#[test]
#[ignore = "Phase 6.6: 2PC not yet implemented"]
fn test_2pc_commit_phase() {
    // TODO: Test COMMIT phase
    // 1. After successful PREPARE
    // 2. Send COMMIT to all participants
    // 3. Verify all respond with COMMITTED
}

#[test]
#[ignore = "Phase 6.6: 2PC not yet implemented"]
fn test_2pc_abort_on_prepare_failure() {
    // TODO: Test ABORT after PREPARE failure
    // 1. One participant fails PREPARE
    // 2. Coordinator sends ABORT to all
    // 3. Verify cleanup
}

#[test]
#[ignore = "Phase 6.6: 2PC not yet implemented"]
fn test_2pc_timeout_handling() {
    // TODO: Test timeout handling
    // 1. Participant doesn't respond within timeout
    // 2. Coordinator should abort transaction
}

// ============================================================================
// Helper Functions
// ============================================================================

fn create_test_chain_config() -> ChainConfig {
    ChainConfig {
        tag: "test-chain".to_string(),
        description: "Test chain".to_string(),
        dscp_value: 10,
        hops: vec![
            ChainHop {
                node_tag: "node-a".to_string(),
                role: ChainRole::Entry,
                tunnel_type: TunnelType::WireGuard,
            },
            ChainHop {
                node_tag: "node-b".to_string(),
                role: ChainRole::Terminal,
                tunnel_type: TunnelType::WireGuard,
            },
        ],
        rules: vec![],
        exit_egress: "pia-us-east".to_string(),
        allow_transitive: false,
    }
}
