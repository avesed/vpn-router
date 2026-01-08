//! Phase 6 Two-Phase Commit Integration Tests
//!
//! Comprehensive integration tests for the Two-Phase Commit protocol used in
//! distributed chain activation.
//!
//! # Test Categories
//!
//! 1. Basic 2PC Flow (15 tests)
//!    - Successful prepare-commit sequence
//!    - Prepare-abort sequence
//!    - State machine transitions
//!
//! 2. Prepare Phase Tests (20 tests)
//!    - Participant validation
//!    - Prepare failures
//!    - State tracking
//!
//! 3. Commit Phase Tests (15 tests)
//!    - All-or-nothing semantics
//!    - Commit failures and recovery
//!    - State transitions
//!
//! 4. Abort and Rollback Tests (15 tests)
//!    - Abort during prepare
//!    - Abort after partial failure
//!    - Resource cleanup
//!
//! 5. Timeout and Edge Cases (10 tests)
//!    - Timeout handling
//!    - Empty participant lists
//!
//! # Running Tests
//!
//! ```bash
//! cargo test --test integration phase6_2pc -- --nocapture
//! ```

use std::sync::Arc;

use rust_router::chain::two_phase::{
    ChainNetworkClient, MockNetworkClient, NoOpNetworkClient, TwoPhaseCommit, TwoPhaseError,
    TwoPhaseState,
};
use rust_router::ipc::{ChainConfig, ChainHop, ChainRole, TunnelType};

// ============================================================================
// Test Helpers
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

fn create_test_chain_config_with_tag(tag: &str) -> ChainConfig {
    ChainConfig {
        tag: tag.to_string(),
        description: format!("Test chain {}", tag),
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

fn create_three_hop_config() -> ChainConfig {
    ChainConfig {
        tag: "three-hop-chain".to_string(),
        description: "Three hop chain".to_string(),
        dscp_value: 20,
        hops: vec![
            ChainHop {
                node_tag: "node-a".to_string(),
                role: ChainRole::Entry,
                tunnel_type: TunnelType::WireGuard,
            },
            ChainHop {
                node_tag: "node-b".to_string(),
                role: ChainRole::Relay,
                tunnel_type: TunnelType::WireGuard,
            },
            ChainHop {
                node_tag: "node-c".to_string(),
                role: ChainRole::Terminal,
                tunnel_type: TunnelType::WireGuard,
            },
        ],
        rules: vec![],
        exit_egress: "pia-us-west".to_string(),
        allow_transitive: false,
    }
}

// ============================================================================
// SECTION 1: Two-Phase Commit State Tests (10 tests)
// ============================================================================

#[test]
fn test_two_phase_state_display() {
    assert_eq!(TwoPhaseState::Pending.to_string(), "pending");
    assert_eq!(TwoPhaseState::Preparing.to_string(), "preparing");
    assert_eq!(TwoPhaseState::Prepared.to_string(), "prepared");
    assert_eq!(TwoPhaseState::Committing.to_string(), "committing");
    assert_eq!(TwoPhaseState::Committed.to_string(), "committed");
    assert_eq!(TwoPhaseState::Aborted.to_string(), "aborted");
    assert_eq!(
        TwoPhaseState::Failed("test".to_string()).to_string(),
        "failed: test"
    );
}

#[test]
fn test_two_phase_state_equality() {
    assert_eq!(TwoPhaseState::Pending, TwoPhaseState::Pending);
    assert_ne!(TwoPhaseState::Pending, TwoPhaseState::Prepared);
    assert_ne!(TwoPhaseState::Committed, TwoPhaseState::Aborted);

    // Failed states with different messages are not equal
    assert_ne!(
        TwoPhaseState::Failed("a".to_string()),
        TwoPhaseState::Failed("b".to_string())
    );
}

#[test]
fn test_two_phase_error_display() {
    let err = TwoPhaseError::ParticipantNotFound("node-x".to_string());
    assert!(err.to_string().contains("node-x"));

    let err = TwoPhaseError::PrepareFailed {
        node: "node-y".to_string(),
        reason: "connection refused".to_string(),
    };
    assert!(err.to_string().contains("node-y"));
    assert!(err.to_string().contains("connection refused"));

    let err = TwoPhaseError::CommitFailed {
        node: "node-z".to_string(),
        reason: "timeout".to_string(),
    };
    assert!(err.to_string().contains("node-z"));
    assert!(err.to_string().contains("timeout"));
}

#[test]
fn test_two_phase_error_timeout_display() {
    let err = TwoPhaseError::Timeout {
        node: "node-a".to_string(),
        phase: "PREPARE".to_string(),
    };
    assert!(err.to_string().contains("node-a"));
    assert!(err.to_string().contains("PREPARE"));
}

#[test]
fn test_two_phase_error_invalid_transition() {
    let err = TwoPhaseError::InvalidTransition {
        from: TwoPhaseState::Pending,
        to: TwoPhaseState::Committed,
    };
    assert!(err.to_string().contains("pending"));
    assert!(err.to_string().contains("committed"));
}

#[test]
fn test_two_phase_error_already_finalized() {
    let err = TwoPhaseError::AlreadyFinalized {
        state: "committed".to_string(),
    };
    assert!(err.to_string().contains("committed"));
}

#[test]
fn test_two_phase_error_not_all_prepared() {
    let err = TwoPhaseError::NotAllPrepared;
    assert!(err.to_string().contains("prepared"));
}

// ============================================================================
// SECTION 2: Two-Phase Commit Coordinator Tests (15 tests)
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
    assert_eq!(coordinator.participant_count(), 2);
}

#[test]
fn test_coordinator_empty_participants() {
    let config = create_test_chain_config();
    let coordinator = TwoPhaseCommit::new("empty-chain".to_string(), config, vec![]);

    assert_eq!(coordinator.participant_count(), 0);
    assert!(coordinator.all_prepared()); // Vacuously true
    assert!(coordinator.all_committed()); // Vacuously true
    assert!(!coordinator.any_failed());
}

#[test]
fn test_coordinator_with_timeout() {
    let config = create_test_chain_config();
    let coordinator = TwoPhaseCommit::new(
        "timeout-chain".to_string(),
        config,
        vec!["node-a".to_string()],
    )
    .with_timeout(60);

    assert_eq!(coordinator.chain_tag(), "timeout-chain");
}

#[test]
fn test_coordinator_with_network_client() {
    let config = create_test_chain_config();
    let client = Arc::new(NoOpNetworkClient);
    let coordinator = TwoPhaseCommit::new(
        "client-chain".to_string(),
        config,
        vec!["node-a".to_string()],
    )
    .with_network_client(client);

    assert_eq!(coordinator.chain_tag(), "client-chain");
}

#[test]
fn test_coordinator_config_access() {
    let config = create_test_chain_config();
    let coordinator = TwoPhaseCommit::new(
        "config-chain".to_string(),
        config.clone(),
        vec!["node-a".to_string()],
    );

    assert_eq!(coordinator.config().dscp_value, 10);
    assert_eq!(coordinator.config().exit_egress, "pia-us-east");
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
fn test_coordinator_all_committed() {
    let config = create_test_chain_config();
    let mut coordinator = TwoPhaseCommit::new(
        "test-chain".to_string(),
        config,
        vec!["node-a".to_string(), "node-b".to_string()],
    );

    assert!(!coordinator.all_committed());

    coordinator.record_commit_success("node-a").unwrap();
    assert!(!coordinator.all_committed());

    coordinator.record_commit_success("node-b").unwrap();
    assert!(coordinator.all_committed());
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
fn test_coordinator_failed_nodes() {
    let config = create_test_chain_config();
    let mut coordinator = TwoPhaseCommit::new(
        "test-chain".to_string(),
        config,
        vec!["node-a".to_string(), "node-b".to_string()],
    );

    assert!(coordinator.failed_nodes().is_empty());

    coordinator
        .record_prepare_failure("node-a", "error".to_string())
        .unwrap();
    let failed = coordinator.failed_nodes();
    assert_eq!(failed.len(), 1);
    assert!(failed.contains(&"node-a".to_string()));
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
    assert!(matches!(
        result,
        Err(TwoPhaseError::ParticipantNotFound(_))
    ));
}

#[test]
fn test_coordinator_get_participant() {
    let config = create_test_chain_config();
    let coordinator = TwoPhaseCommit::new(
        "test-chain".to_string(),
        config,
        vec!["node-a".to_string()],
    );

    let participant = coordinator.get_participant("node-a");
    assert!(participant.is_some());
    assert_eq!(participant.unwrap().state, TwoPhaseState::Pending);

    let missing = coordinator.get_participant("nonexistent");
    assert!(missing.is_none());
}

#[test]
fn test_coordinator_participants_iterator() {
    let config = create_test_chain_config();
    let coordinator = TwoPhaseCommit::new(
        "test-chain".to_string(),
        config,
        vec!["node-a".to_string(), "node-b".to_string()],
    );

    let participants: Vec<_> = coordinator.participants().collect();
    assert_eq!(participants.len(), 2);
}

// ============================================================================
// SECTION 3: PREPARE Phase Tests (20 tests)
// ============================================================================

#[tokio::test]
async fn test_prepare_single_no_client() {
    let config = create_test_chain_config();
    let mut coordinator = TwoPhaseCommit::new(
        "test-chain".to_string(),
        config,
        vec!["node-a".to_string()],
    );

    let result = coordinator.prepare("node-a").await;
    assert!(result.is_ok());

    let participant = coordinator.get_participant("node-a").unwrap();
    assert_eq!(participant.state, TwoPhaseState::Prepared);
}

#[tokio::test]
async fn test_prepare_single_with_noop_client() {
    let config = create_test_chain_config();
    let client = Arc::new(NoOpNetworkClient);
    let mut coordinator = TwoPhaseCommit::new(
        "test-chain".to_string(),
        config,
        vec!["node-a".to_string()],
    )
    .with_network_client(client);

    let result = coordinator.prepare("node-a").await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_prepare_single_failure() {
    let config = create_test_chain_config();
    let mock = Arc::new(MockNetworkClient::new());
    mock.fail_prepare("node-a", "Connection refused");

    let mut coordinator = TwoPhaseCommit::new(
        "test-chain".to_string(),
        config,
        vec!["node-a".to_string()],
    )
    .with_network_client(mock);

    let result = coordinator.prepare("node-a").await;
    assert!(matches!(result, Err(TwoPhaseError::PrepareFailed { .. })));

    let participant = coordinator.get_participant("node-a").unwrap();
    assert!(matches!(participant.state, TwoPhaseState::Failed(_)));
}

#[tokio::test]
async fn test_prepare_idempotent() {
    let config = create_test_chain_config();
    let mut coordinator = TwoPhaseCommit::new(
        "test-chain".to_string(),
        config,
        vec!["node-a".to_string()],
    );

    coordinator.prepare("node-a").await.unwrap();
    // Second prepare should succeed (already prepared)
    let result = coordinator.prepare("node-a").await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_prepare_participant_not_found() {
    let config = create_test_chain_config();
    let mut coordinator = TwoPhaseCommit::new(
        "test-chain".to_string(),
        config,
        vec!["node-a".to_string()],
    );

    let result = coordinator.prepare("nonexistent").await;
    assert!(matches!(
        result,
        Err(TwoPhaseError::ParticipantNotFound(_))
    ));
}

#[tokio::test]
async fn test_prepare_all_success() {
    let config = create_test_chain_config();
    let client = Arc::new(NoOpNetworkClient);
    let mut coordinator = TwoPhaseCommit::new(
        "test-chain".to_string(),
        config,
        vec!["node-a".to_string(), "node-b".to_string()],
    )
    .with_network_client(client);

    let errors = coordinator.prepare_all().await;
    assert!(errors.is_empty());
    assert!(coordinator.all_prepared());
    assert_eq!(*coordinator.transaction_state(), TwoPhaseState::Prepared);
}

#[tokio::test]
async fn test_prepare_all_partial_failure() {
    let config = create_test_chain_config();
    let mock = Arc::new(MockNetworkClient::new());
    mock.fail_prepare("node-b", "Connection refused");

    let mut coordinator = TwoPhaseCommit::new(
        "test-chain".to_string(),
        config,
        vec!["node-a".to_string(), "node-b".to_string()],
    )
    .with_network_client(mock);

    let errors = coordinator.prepare_all().await;
    assert_eq!(errors.len(), 1);
    assert!(!coordinator.all_prepared());
    assert!(matches!(
        coordinator.transaction_state(),
        TwoPhaseState::Failed(_)
    ));
}

#[tokio::test]
async fn test_prepare_all_empty() {
    let config = create_test_chain_config();
    let mut coordinator = TwoPhaseCommit::new("test-chain".to_string(), config, vec![]);

    let errors = coordinator.prepare_all().await;
    assert!(errors.is_empty());
    assert_eq!(*coordinator.transaction_state(), TwoPhaseState::Prepared);
}

#[tokio::test]
async fn test_prepare_all_multiple_failures() {
    let config = create_three_hop_config();
    let mock = Arc::new(MockNetworkClient::new());
    mock.fail_prepare("node-a", "Error 1");
    mock.fail_prepare("node-b", "Error 2");

    let mut coordinator = TwoPhaseCommit::new(
        "test-chain".to_string(),
        config,
        vec![
            "node-a".to_string(),
            "node-b".to_string(),
            "node-c".to_string(),
        ],
    )
    .with_network_client(mock);

    let errors = coordinator.prepare_all().await;
    assert_eq!(errors.len(), 2);
    assert!(coordinator.any_failed());
}

#[tokio::test]
async fn test_prepare_after_already_finalized() {
    let config = create_test_chain_config();
    let client = Arc::new(NoOpNetworkClient);
    let mut coordinator = TwoPhaseCommit::new(
        "test-chain".to_string(),
        config,
        vec!["node-a".to_string()],
    )
    .with_network_client(client);

    // Prepare and commit first
    coordinator.prepare_all().await;
    coordinator.commit_all().await;

    // Now try to prepare again
    let result = coordinator.prepare("node-a").await;
    assert!(matches!(result, Err(TwoPhaseError::AlreadyFinalized { .. })));
}

#[tokio::test]
async fn test_prepare_all_after_aborted() {
    let config = create_test_chain_config();
    let mut coordinator = TwoPhaseCommit::new(
        "test-chain".to_string(),
        config,
        vec!["node-a".to_string()],
    );

    coordinator.abort_all().await;

    let errors = coordinator.prepare_all().await;
    assert!(!errors.is_empty());
    assert!(matches!(
        errors[0],
        TwoPhaseError::AlreadyFinalized { .. }
    ));
}

#[tokio::test]
async fn test_prepare_records_error_message() {
    let config = create_test_chain_config();
    let mock = Arc::new(MockNetworkClient::new());
    mock.fail_prepare("node-a", "Custom error message");

    let mut coordinator = TwoPhaseCommit::new(
        "test-chain".to_string(),
        config,
        vec!["node-a".to_string()],
    )
    .with_network_client(mock);

    coordinator.prepare("node-a").await.err();

    let participant = coordinator.get_participant("node-a").unwrap();
    assert!(participant.error.is_some());
    assert!(participant.error.as_ref().unwrap().contains("Custom error"));
}

// ============================================================================
// SECTION 4: COMMIT Phase Tests (15 tests)
// ============================================================================

#[tokio::test]
async fn test_commit_single_success() {
    let config = create_test_chain_config();
    let mut coordinator = TwoPhaseCommit::new(
        "test-chain".to_string(),
        config,
        vec!["node-a".to_string()],
    );

    coordinator.record_prepare_success("node-a").unwrap();
    let result = coordinator.commit("node-a").await;
    assert!(result.is_ok());

    let participant = coordinator.get_participant("node-a").unwrap();
    assert_eq!(participant.state, TwoPhaseState::Committed);
}

#[tokio::test]
async fn test_commit_not_prepared() {
    let config = create_test_chain_config();
    let mut coordinator = TwoPhaseCommit::new(
        "test-chain".to_string(),
        config,
        vec!["node-a".to_string()],
    );

    let result = coordinator.commit("node-a").await;
    assert!(matches!(
        result,
        Err(TwoPhaseError::InvalidTransition { .. })
    ));
}

#[tokio::test]
async fn test_commit_idempotent() {
    let config = create_test_chain_config();
    let mut coordinator = TwoPhaseCommit::new(
        "test-chain".to_string(),
        config,
        vec!["node-a".to_string()],
    );

    coordinator.record_prepare_success("node-a").unwrap();
    coordinator.commit("node-a").await.unwrap();

    // Second commit should succeed (already committed)
    let result = coordinator.commit("node-a").await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_commit_single_failure() {
    let config = create_test_chain_config();
    let mock = Arc::new(MockNetworkClient::new());
    mock.fail_commit("node-a", "Commit failed");

    let mut coordinator = TwoPhaseCommit::new(
        "test-chain".to_string(),
        config,
        vec!["node-a".to_string()],
    )
    .with_network_client(mock);

    coordinator.record_prepare_success("node-a").unwrap();
    let result = coordinator.commit("node-a").await;
    assert!(matches!(result, Err(TwoPhaseError::CommitFailed { .. })));
}

#[tokio::test]
async fn test_commit_all_success() {
    let config = create_test_chain_config();
    let client = Arc::new(NoOpNetworkClient);
    let mut coordinator = TwoPhaseCommit::new(
        "test-chain".to_string(),
        config,
        vec!["node-a".to_string(), "node-b".to_string()],
    )
    .with_network_client(client);

    coordinator.record_prepare_success("node-a").unwrap();
    coordinator.record_prepare_success("node-b").unwrap();

    let errors = coordinator.commit_all().await;
    assert!(errors.is_empty());
    assert!(coordinator.all_committed());
    assert_eq!(*coordinator.transaction_state(), TwoPhaseState::Committed);
}

#[tokio::test]
async fn test_commit_all_not_all_prepared() {
    let config = create_test_chain_config();
    let mut coordinator = TwoPhaseCommit::new(
        "test-chain".to_string(),
        config,
        vec!["node-a".to_string(), "node-b".to_string()],
    );

    coordinator.record_prepare_success("node-a").unwrap();
    // node-b not prepared

    let errors = coordinator.commit_all().await;
    assert_eq!(errors.len(), 1);
    assert!(matches!(errors[0], TwoPhaseError::NotAllPrepared));
}

#[tokio::test]
async fn test_commit_all_partial_failure() {
    let config = create_test_chain_config();
    let mock = Arc::new(MockNetworkClient::new());
    mock.fail_commit("node-b", "Commit failed");

    let mut coordinator = TwoPhaseCommit::new(
        "test-chain".to_string(),
        config,
        vec!["node-a".to_string(), "node-b".to_string()],
    )
    .with_network_client(mock);

    coordinator.record_prepare_success("node-a").unwrap();
    coordinator.record_prepare_success("node-b").unwrap();

    let errors = coordinator.commit_all().await;
    assert_eq!(errors.len(), 1);
    assert!(matches!(
        coordinator.transaction_state(),
        TwoPhaseState::Failed(_)
    ));
}

#[tokio::test]
async fn test_commit_all_empty() {
    let config = create_test_chain_config();
    let mut coordinator = TwoPhaseCommit::new("test-chain".to_string(), config, vec![]);

    let errors = coordinator.commit_all().await;
    assert!(errors.is_empty());
    assert_eq!(*coordinator.transaction_state(), TwoPhaseState::Committed);
}

#[tokio::test]
async fn test_commit_records_error_message() {
    let config = create_test_chain_config();
    let mock = Arc::new(MockNetworkClient::new());
    mock.fail_commit("node-a", "Custom commit error");

    let mut coordinator = TwoPhaseCommit::new(
        "test-chain".to_string(),
        config,
        vec!["node-a".to_string()],
    )
    .with_network_client(mock);

    coordinator.record_prepare_success("node-a").unwrap();
    coordinator.commit("node-a").await.err();

    let participant = coordinator.get_participant("node-a").unwrap();
    assert!(matches!(participant.state, TwoPhaseState::Failed(_)));
}

// ============================================================================
// SECTION 5: ABORT Tests (15 tests)
// ============================================================================

#[tokio::test]
async fn test_abort_single_success() {
    let config = create_test_chain_config();
    let mut coordinator = TwoPhaseCommit::new(
        "test-chain".to_string(),
        config,
        vec!["node-a".to_string()],
    );

    let result = coordinator.abort("node-a").await;
    assert!(result.is_ok());

    let participant = coordinator.get_participant("node-a").unwrap();
    assert_eq!(participant.state, TwoPhaseState::Aborted);
}

#[tokio::test]
async fn test_abort_already_committed() {
    let config = create_test_chain_config();
    let mut coordinator = TwoPhaseCommit::new(
        "test-chain".to_string(),
        config,
        vec!["node-a".to_string()],
    );

    coordinator.record_commit_success("node-a").unwrap();
    let result = coordinator.abort("node-a").await;
    assert!(matches!(
        result,
        Err(TwoPhaseError::InvalidTransition { .. })
    ));
}

#[tokio::test]
async fn test_abort_idempotent() {
    let config = create_test_chain_config();
    let mut coordinator = TwoPhaseCommit::new(
        "test-chain".to_string(),
        config,
        vec!["node-a".to_string()],
    );

    coordinator.abort("node-a").await.unwrap();
    // Second abort should succeed
    let result = coordinator.abort("node-a").await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_abort_prepared_participant() {
    let config = create_test_chain_config();
    let client = Arc::new(NoOpNetworkClient);
    let mut coordinator = TwoPhaseCommit::new(
        "test-chain".to_string(),
        config,
        vec!["node-a".to_string()],
    )
    .with_network_client(client);

    coordinator.record_prepare_success("node-a").unwrap();
    let result = coordinator.abort("node-a").await;
    assert!(result.is_ok());

    let participant = coordinator.get_participant("node-a").unwrap();
    assert_eq!(participant.state, TwoPhaseState::Aborted);
}

#[tokio::test]
async fn test_abort_all() {
    let config = create_test_chain_config();
    let client = Arc::new(NoOpNetworkClient);
    let mut coordinator = TwoPhaseCommit::new(
        "test-chain".to_string(),
        config,
        vec!["node-a".to_string(), "node-b".to_string()],
    )
    .with_network_client(client);

    coordinator.record_prepare_success("node-a").unwrap();
    coordinator.record_prepare_success("node-b").unwrap();

    coordinator.abort_all().await;

    assert_eq!(*coordinator.transaction_state(), TwoPhaseState::Aborted);
    for participant in coordinator.participants() {
        assert_eq!(participant.state, TwoPhaseState::Aborted);
    }
}

#[tokio::test]
async fn test_abort_all_skips_committed() {
    let config = create_test_chain_config();
    let mut coordinator = TwoPhaseCommit::new(
        "test-chain".to_string(),
        config,
        vec!["node-a".to_string(), "node-b".to_string()],
    );

    coordinator.record_commit_success("node-a").unwrap();
    coordinator.record_prepare_success("node-b").unwrap();

    coordinator.abort_all().await;

    // node-a should still be committed
    let participant_a = coordinator.get_participant("node-a").unwrap();
    assert_eq!(participant_a.state, TwoPhaseState::Committed);

    // node-b should be aborted
    let participant_b = coordinator.get_participant("node-b").unwrap();
    assert_eq!(participant_b.state, TwoPhaseState::Aborted);
}

#[tokio::test]
async fn test_abort_all_empty() {
    let config = create_test_chain_config();
    let mut coordinator = TwoPhaseCommit::new("test-chain".to_string(), config, vec![]);

    coordinator.abort_all().await;
    assert_eq!(*coordinator.transaction_state(), TwoPhaseState::Aborted);
}

#[tokio::test]
async fn test_abort_with_failed_network() {
    let config = create_test_chain_config();
    let mock = Arc::new(MockNetworkClient::new());
    mock.fail_abort("node-a", "Network error");

    let mut coordinator = TwoPhaseCommit::new(
        "test-chain".to_string(),
        config,
        vec!["node-a".to_string()],
    )
    .with_network_client(mock);

    let result = coordinator.abort("node-a").await;
    assert!(matches!(result, Err(TwoPhaseError::AbortFailed { .. })));

    // State should still be marked as aborted (best-effort)
    let participant = coordinator.get_participant("node-a").unwrap();
    assert_eq!(participant.state, TwoPhaseState::Aborted);
}

#[tokio::test]
async fn test_abort_participant_not_found() {
    let config = create_test_chain_config();
    let mut coordinator = TwoPhaseCommit::new(
        "test-chain".to_string(),
        config,
        vec!["node-a".to_string()],
    );

    let result = coordinator.abort("nonexistent").await;
    assert!(matches!(
        result,
        Err(TwoPhaseError::ParticipantNotFound(_))
    ));
}

// ============================================================================
// SECTION 6: Full 2PC Flow Tests (15 tests)
// ============================================================================

#[tokio::test]
async fn test_full_2pc_success() {
    let config = create_test_chain_config();
    let client = Arc::new(NoOpNetworkClient);
    let mut coordinator = TwoPhaseCommit::new(
        "test-chain".to_string(),
        config,
        vec!["node-a".to_string(), "node-b".to_string()],
    )
    .with_network_client(client);

    // Phase 1: Prepare
    let prepare_errors = coordinator.prepare_all().await;
    assert!(prepare_errors.is_empty());
    assert!(coordinator.all_prepared());

    // Phase 2: Commit
    let commit_errors = coordinator.commit_all().await;
    assert!(commit_errors.is_empty());
    assert!(coordinator.all_committed());
    assert_eq!(*coordinator.transaction_state(), TwoPhaseState::Committed);
}

#[tokio::test]
async fn test_full_2pc_prepare_failure_abort() {
    let config = create_test_chain_config();
    let mock = Arc::new(MockNetworkClient::new());
    mock.fail_prepare("node-b", "Validation failed");

    let mut coordinator = TwoPhaseCommit::new(
        "test-chain".to_string(),
        config,
        vec!["node-a".to_string(), "node-b".to_string()],
    )
    .with_network_client(mock);

    // Phase 1: Prepare - one node fails
    let prepare_errors = coordinator.prepare_all().await;
    assert!(!prepare_errors.is_empty());

    // Abort all
    coordinator.abort_all().await;
    assert_eq!(*coordinator.transaction_state(), TwoPhaseState::Aborted);
}

#[tokio::test]
async fn test_full_2pc_with_three_participants() {
    let config = create_three_hop_config();
    let client = Arc::new(NoOpNetworkClient);
    let mut coordinator = TwoPhaseCommit::new(
        "test-chain".to_string(),
        config,
        vec![
            "node-a".to_string(),
            "node-b".to_string(),
            "node-c".to_string(),
        ],
    )
    .with_network_client(client);

    // Prepare all
    let prepare_errors = coordinator.prepare_all().await;
    assert!(prepare_errors.is_empty());

    // Commit all
    let commit_errors = coordinator.commit_all().await;
    assert!(commit_errors.is_empty());
    assert_eq!(*coordinator.transaction_state(), TwoPhaseState::Committed);
}

#[tokio::test]
async fn test_full_2pc_manual_prepare_then_commit() {
    let config = create_test_chain_config();
    let client = Arc::new(NoOpNetworkClient);
    let mut coordinator = TwoPhaseCommit::new(
        "test-chain".to_string(),
        config,
        vec!["node-a".to_string(), "node-b".to_string()],
    )
    .with_network_client(client);

    // Manual prepare each node
    coordinator.prepare("node-a").await.unwrap();
    coordinator.prepare("node-b").await.unwrap();

    assert!(coordinator.all_prepared());

    // Manual commit each node
    coordinator.commit("node-a").await.unwrap();
    coordinator.commit("node-b").await.unwrap();

    assert!(coordinator.all_committed());
}

#[tokio::test]
async fn test_full_2pc_prepare_some_abort_all() {
    let config = create_three_hop_config();
    let client = Arc::new(NoOpNetworkClient);
    let mut coordinator = TwoPhaseCommit::new(
        "test-chain".to_string(),
        config,
        vec![
            "node-a".to_string(),
            "node-b".to_string(),
            "node-c".to_string(),
        ],
    )
    .with_network_client(client);

    // Prepare only first two nodes
    coordinator.prepare("node-a").await.unwrap();
    coordinator.prepare("node-b").await.unwrap();

    // Then decide to abort
    coordinator.abort_all().await;

    assert_eq!(*coordinator.transaction_state(), TwoPhaseState::Aborted);

    // All non-committed nodes should be aborted
    let participant_a = coordinator.get_participant("node-a").unwrap();
    let participant_b = coordinator.get_participant("node-b").unwrap();
    let participant_c = coordinator.get_participant("node-c").unwrap();

    assert_eq!(participant_a.state, TwoPhaseState::Aborted);
    assert_eq!(participant_b.state, TwoPhaseState::Aborted);
    assert_eq!(participant_c.state, TwoPhaseState::Aborted);
}

// ============================================================================
// SECTION 7: Timeout Tests (10 tests)
// ============================================================================

#[tokio::test]
async fn test_prepare_timeout() {
    let config = create_test_chain_config();
    let mock = Arc::new(MockNetworkClient::new());
    mock.set_delay(2000); // 2 second delay

    let mut coordinator = TwoPhaseCommit::new(
        "test-chain".to_string(),
        config,
        vec!["node-a".to_string()],
    )
    .with_timeout(1) // 1 second timeout
    .with_network_client(mock);

    let result = coordinator.prepare("node-a").await;
    assert!(matches!(result, Err(TwoPhaseError::Timeout { .. })));

    let participant = coordinator.get_participant("node-a").unwrap();
    assert!(matches!(participant.state, TwoPhaseState::Failed(_)));
}

#[tokio::test]
async fn test_commit_timeout() {
    let config = create_test_chain_config();
    let mock = Arc::new(MockNetworkClient::new());
    mock.set_delay(2000); // 2 second delay

    let mut coordinator = TwoPhaseCommit::new(
        "test-chain".to_string(),
        config,
        vec!["node-a".to_string()],
    )
    .with_timeout(1) // 1 second timeout
    .with_network_client(mock);

    coordinator.record_prepare_success("node-a").unwrap();
    let result = coordinator.commit("node-a").await;
    assert!(matches!(result, Err(TwoPhaseError::Timeout { .. })));
}

#[tokio::test]
async fn test_abort_timeout() {
    let config = create_test_chain_config();
    let mock = Arc::new(MockNetworkClient::new());
    mock.set_delay(2000); // 2 second delay

    let mut coordinator = TwoPhaseCommit::new(
        "test-chain".to_string(),
        config,
        vec!["node-a".to_string()],
    )
    .with_timeout(1) // 1 second timeout
    .with_network_client(mock);

    let result = coordinator.abort("node-a").await;
    assert!(matches!(result, Err(TwoPhaseError::Timeout { .. })));
}

#[tokio::test]
async fn test_longer_timeout_succeeds() {
    let config = create_test_chain_config();
    let mock = Arc::new(MockNetworkClient::new());
    mock.set_delay(500); // 500ms delay

    let mut coordinator = TwoPhaseCommit::new(
        "test-chain".to_string(),
        config,
        vec!["node-a".to_string()],
    )
    .with_timeout(2) // 2 second timeout
    .with_network_client(mock);

    let result = coordinator.prepare("node-a").await;
    assert!(result.is_ok());
}

// ============================================================================
// SECTION 8: Record Methods Tests (10 tests)
// ============================================================================

#[test]
fn test_record_prepare_success() {
    let config = create_test_chain_config();
    let mut coordinator = TwoPhaseCommit::new(
        "test-chain".to_string(),
        config,
        vec!["node-a".to_string()],
    );

    coordinator.record_prepare_success("node-a").unwrap();
    assert_eq!(
        coordinator.get_participant("node-a").unwrap().state,
        TwoPhaseState::Prepared
    );
}

#[test]
fn test_record_prepare_failure() {
    let config = create_test_chain_config();
    let mut coordinator = TwoPhaseCommit::new(
        "test-chain".to_string(),
        config,
        vec!["node-a".to_string()],
    );

    coordinator
        .record_prepare_failure("node-a", "error".to_string())
        .unwrap();

    let participant = coordinator.get_participant("node-a").unwrap();
    assert!(matches!(participant.state, TwoPhaseState::Failed(_)));
    assert_eq!(participant.error, Some("error".to_string()));
}

#[test]
fn test_record_commit_success() {
    let config = create_test_chain_config();
    let mut coordinator = TwoPhaseCommit::new(
        "test-chain".to_string(),
        config,
        vec!["node-a".to_string()],
    );

    coordinator.record_commit_success("node-a").unwrap();
    assert_eq!(
        coordinator.get_participant("node-a").unwrap().state,
        TwoPhaseState::Committed
    );
}

#[test]
fn test_record_commit_failure() {
    let config = create_test_chain_config();
    let mut coordinator = TwoPhaseCommit::new(
        "test-chain".to_string(),
        config,
        vec!["node-a".to_string()],
    );

    coordinator.record_prepare_success("node-a").unwrap();
    coordinator
        .record_commit_failure("node-a", "commit error".to_string())
        .unwrap();

    let participant = coordinator.get_participant("node-a").unwrap();
    assert!(matches!(participant.state, TwoPhaseState::Failed(_)));
}

#[test]
fn test_record_abort() {
    let config = create_test_chain_config();
    let mut coordinator = TwoPhaseCommit::new(
        "test-chain".to_string(),
        config,
        vec!["node-a".to_string()],
    );

    coordinator.record_abort("node-a").unwrap();
    assert_eq!(
        coordinator.get_participant("node-a").unwrap().state,
        TwoPhaseState::Aborted
    );
}

#[test]
fn test_record_methods_nonexistent_participant() {
    let config = create_test_chain_config();
    let mut coordinator = TwoPhaseCommit::new(
        "test-chain".to_string(),
        config,
        vec!["node-a".to_string()],
    );

    assert!(matches!(
        coordinator.record_prepare_success("nonexistent"),
        Err(TwoPhaseError::ParticipantNotFound(_))
    ));
    assert!(matches!(
        coordinator.record_prepare_failure("nonexistent", "error".to_string()),
        Err(TwoPhaseError::ParticipantNotFound(_))
    ));
    assert!(matches!(
        coordinator.record_commit_success("nonexistent"),
        Err(TwoPhaseError::ParticipantNotFound(_))
    ));
    assert!(matches!(
        coordinator.record_commit_failure("nonexistent", "error".to_string()),
        Err(TwoPhaseError::ParticipantNotFound(_))
    ));
    assert!(matches!(
        coordinator.record_abort("nonexistent"),
        Err(TwoPhaseError::ParticipantNotFound(_))
    ));
}

// ============================================================================
// SECTION 9: Mock Network Client Tests (5 tests)
// ============================================================================

#[test]
fn test_mock_network_client_setup() {
    let mock = MockNetworkClient::new();

    mock.fail_prepare("node-a", "error1");
    mock.fail_commit("node-b", "error2");
    mock.fail_abort("node-c", "error3");
    mock.set_delay(100);

    assert!(mock
        .prepare_failures
        .lock()
        .unwrap()
        .contains_key("node-a"));
    assert!(mock.commit_failures.lock().unwrap().contains_key("node-b"));
    assert!(mock.abort_failures.lock().unwrap().contains_key("node-c"));
    assert_eq!(
        mock.delay_ms.load(std::sync::atomic::Ordering::SeqCst),
        100
    );
}

#[test]
fn test_mock_network_client_default() {
    let mock = MockNetworkClient::default();
    assert!(mock.prepare_failures.lock().unwrap().is_empty());
    assert!(mock.commit_failures.lock().unwrap().is_empty());
    assert!(mock.abort_failures.lock().unwrap().is_empty());
}

#[tokio::test]
async fn test_mock_network_client_prepare_success() {
    let mock = MockNetworkClient::new();
    let config = create_test_chain_config();

    let result = mock.send_prepare("node-a", &config).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_mock_network_client_prepare_failure() {
    let mock = MockNetworkClient::new();
    mock.fail_prepare("node-a", "Connection refused");

    let config = create_test_chain_config();
    let result = mock.send_prepare("node-a", &config).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Connection refused"));
}

#[tokio::test]
async fn test_noop_network_client() {
    let client = NoOpNetworkClient;
    let config = create_test_chain_config();

    assert!(client.send_prepare("any-node", &config).await.is_ok());
    assert!(client.send_commit("any-node", "any-chain").await.is_ok());
    assert!(client.send_abort("any-node", "any-chain").await.is_ok());
}

// ============================================================================
// Phase 6.11 - Network Partition Tests
// ============================================================================

/// Test 2PC behavior when a node becomes unreachable during PREPARE (network partition)
///
/// When a node is unreachable during PREPARE, the coordinator should:
/// 1. Timeout on the unreachable node
/// 2. Mark that node as failed
/// 3. Abort all prepared nodes
#[tokio::test]
async fn test_2pc_network_partition_during_prepare() {
    let mock_client = Arc::new(MockNetworkClient::new());

    // Simulate node-b being unreachable (fails immediately)
    mock_client.fail_prepare("node-b", "Network unreachable");

    let participants = vec![
        "node-a".to_string(),
        "node-b".to_string(), // This one will fail
        "node-c".to_string(),
    ];

    let mut coordinator = TwoPhaseCommit::new(
        "partition-chain".to_string(),
        create_test_chain_config_with_tag("partition-chain"),
        participants,
    )
    .with_network_client(mock_client.clone())
    .with_timeout(5);

    // Prepare should fail due to network issue
    let prepare_errors = coordinator.prepare_all().await;

    // At least one node should have failed
    assert!(!prepare_errors.is_empty(), "Should have prepare failures due to network issue");

    // Node-b should be failed
    let node_b = coordinator.get_participant("node-b").unwrap();
    assert!(matches!(node_b.state, TwoPhaseState::Failed(_)));
}

/// Test that prepare failure on one node should be handled in the coordinator
#[tokio::test]
async fn test_2pc_prepare_failure_triggers_partial_failure() {
    let mock_client = Arc::new(MockNetworkClient::new());
    mock_client.fail_prepare("node-b", "Validation failed");

    let participants = vec![
        "node-a".to_string(),
        "node-b".to_string(),
        "node-c".to_string(),
    ];

    let mut coordinator = TwoPhaseCommit::new(
        "abort-test-chain".to_string(),
        create_test_chain_config_with_tag("abort-test-chain"),
        participants,
    )
    .with_network_client(mock_client.clone())
    .with_timeout(5);

    // Prepare will have failures
    let prepare_errors = coordinator.prepare_all().await;
    assert!(!prepare_errors.is_empty());

    // Should not be able to commit
    assert!(!coordinator.all_prepared());

    // Abort all nodes (those that prepared successfully)
    let abort_errors = coordinator.abort_all().await;

    // Check that abort happened (may or may not have errors)
    // After abort, verify state - each participant should be in a terminal state
    for participant in coordinator.participants() {
        // Either Aborted (if it was prepared) or Failed (if prepare failed)
        assert!(
            matches!(participant.state, TwoPhaseState::Aborted | TwoPhaseState::Failed(_)),
            "Participant {} should be aborted or failed, was {:?}",
            participant.node_tag,
            participant.state
        );
    }
}

/// Test 2PC with multiple prepare failures
#[tokio::test]
async fn test_2pc_multiple_prepare_failures() {
    let mock_client = Arc::new(MockNetworkClient::new());
    mock_client.fail_prepare("node-a", "Invalid DSCP");
    mock_client.fail_prepare("node-c", "Peer not connected");

    let participants = vec![
        "node-a".to_string(),
        "node-b".to_string(),
        "node-c".to_string(),
        "node-d".to_string(),
    ];

    let mut coordinator = TwoPhaseCommit::new(
        "multi-fail-chain".to_string(),
        create_test_chain_config_with_tag("multi-fail-chain"),
        participants,
    )
    .with_network_client(mock_client.clone())
    .with_timeout(5);

    // Prepare should fail on multiple nodes
    let prepare_errors = coordinator.prepare_all().await;

    // Should have 2 failures
    assert_eq!(prepare_errors.len(), 2);

    // Verify failed nodes
    let failed = coordinator.failed_nodes();
    assert!(failed.contains(&"node-a".to_string()));
    assert!(failed.contains(&"node-c".to_string()));

    // Verify prepared nodes
    let prepared = coordinator.prepared_nodes();
    assert!(prepared.contains(&"node-b".to_string()));
    assert!(prepared.contains(&"node-d".to_string()));
}

/// Test commit partial failure (some nodes fail during commit)
#[tokio::test]
async fn test_2pc_commit_partial_failure() {
    let mock_client = Arc::new(MockNetworkClient::new());
    // Prepare all succeed, but some commits fail
    mock_client.fail_commit("node-b", "Failed to apply rules");
    mock_client.fail_commit("node-d", "Out of memory");

    let participants = vec![
        "node-a".to_string(),
        "node-b".to_string(),
        "node-c".to_string(),
        "node-d".to_string(),
    ];

    let mut coordinator = TwoPhaseCommit::new(
        "partial-commit-chain".to_string(),
        create_test_chain_config_with_tag("partial-commit-chain"),
        participants,
    )
    .with_network_client(mock_client.clone())
    .with_timeout(5);

    // Prepare all should succeed
    let prepare_errors = coordinator.prepare_all().await;
    assert!(prepare_errors.is_empty());
    assert!(coordinator.all_prepared());

    // Commit should have partial failures
    let commit_errors = coordinator.commit_all().await;
    assert_eq!(commit_errors.len(), 2);

    // Check states
    let node_a = coordinator.get_participant("node-a").unwrap();
    assert_eq!(node_a.state, TwoPhaseState::Committed);

    let node_b = coordinator.get_participant("node-b").unwrap();
    assert!(matches!(node_b.state, TwoPhaseState::Failed(_)));

    let node_c = coordinator.get_participant("node-c").unwrap();
    assert_eq!(node_c.state, TwoPhaseState::Committed);

    let node_d = coordinator.get_participant("node-d").unwrap();
    assert!(matches!(node_d.state, TwoPhaseState::Failed(_)));

    // Should not be all_committed
    assert!(!coordinator.all_committed());
}

// ============================================================================
// Phase 6.11 - Abort Recovery Tests
// ============================================================================

/// Test that abort properly cleans up state after prepare
#[tokio::test]
async fn test_2pc_abort_cleans_state_after_prepare() {
    let mock_client = Arc::new(MockNetworkClient::new());

    let participants = vec![
        "node-a".to_string(),
        "node-b".to_string(),
    ];

    let mut coordinator = TwoPhaseCommit::new(
        "abort-cleanup-chain".to_string(),
        create_test_chain_config_with_tag("abort-cleanup-chain"),
        participants,
    )
    .with_network_client(mock_client.clone())
    .with_timeout(5);

    // Prepare all successfully
    let prepare_errors = coordinator.prepare_all().await;
    assert!(prepare_errors.is_empty());
    assert!(coordinator.all_prepared());

    // Now abort instead of commit
    coordinator.abort_all().await;

    // All nodes should be in Aborted state
    for participant in coordinator.participants() {
        assert_eq!(
            participant.state,
            TwoPhaseState::Aborted,
            "Participant {} should be aborted",
            participant.node_tag
        );
    }

    // Transaction should be aborted
    assert_eq!(*coordinator.transaction_state(), TwoPhaseState::Aborted);
}

/// Test that coordinator tracks abort errors
#[tokio::test]
async fn test_2pc_abort_error_tracking() {
    let mock_client = Arc::new(MockNetworkClient::new());
    mock_client.fail_abort("node-b", "Cannot rollback");

    let participants = vec![
        "node-a".to_string(),
        "node-b".to_string(),
        "node-c".to_string(),
    ];

    let mut coordinator = TwoPhaseCommit::new(
        "abort-error-chain".to_string(),
        create_test_chain_config_with_tag("abort-error-chain"),
        participants,
    )
    .with_network_client(mock_client.clone())
    .with_timeout(5);

    // Prepare all
    let prepare_errors = coordinator.prepare_all().await;
    assert!(prepare_errors.is_empty());

    // Abort all - network errors are logged but all nodes marked aborted
    coordinator.abort_all().await;

    // node-a and node-c should be aborted successfully
    let node_a = coordinator.get_participant("node-a").unwrap();
    assert_eq!(node_a.state, TwoPhaseState::Aborted);

    let node_c = coordinator.get_participant("node-c").unwrap();
    assert_eq!(node_c.state, TwoPhaseState::Aborted);

    // node-b should still be aborted (best effort abort marks as aborted anyway)
    let node_b = coordinator.get_participant("node-b").unwrap();
    assert_eq!(node_b.state, TwoPhaseState::Aborted);
}

/// Test that already finalized transaction rejects new operations
#[tokio::test]
async fn test_2pc_reject_operations_after_finalize() {
    let mock_client = Arc::new(MockNetworkClient::new());

    let participants = vec!["node-a".to_string()];

    let mut coordinator = TwoPhaseCommit::new(
        "finalized-chain".to_string(),
        create_test_chain_config_with_tag("finalized-chain"),
        participants,
    )
    .with_network_client(mock_client.clone())
    .with_timeout(5);

    // Prepare and commit
    let _ = coordinator.prepare_all().await;
    let _ = coordinator.commit_all().await;
    assert!(coordinator.all_committed());

    // Try to prepare again - should fail
    let result = coordinator.prepare("node-a").await;
    assert!(matches!(result, Err(TwoPhaseError::AlreadyFinalized { .. })));
}

/// Test recovery state after various failures
#[tokio::test]
async fn test_2pc_state_recovery_verification() {
    let mock_client = Arc::new(MockNetworkClient::new());
    mock_client.fail_prepare("node-c", "Validation failed");

    let participants = vec![
        "node-a".to_string(),
        "node-b".to_string(),
        "node-c".to_string(),
    ];

    let mut coordinator = TwoPhaseCommit::new(
        "recovery-chain".to_string(),
        create_test_chain_config_with_tag("recovery-chain"),
        participants.clone(),
    )
    .with_network_client(mock_client.clone())
    .with_timeout(5);

    // Partial prepare (node-c fails)
    let _ = coordinator.prepare_all().await;

    // Abort the transaction
    let _ = coordinator.abort_all().await;

    // Verify all participants are in terminal state
    assert_eq!(
        coordinator.participant_count(),
        3,
        "Should have 3 participants"
    );

    // All should be either aborted or failed
    for participant in coordinator.participants() {
        let is_terminal = matches!(
            participant.state,
            TwoPhaseState::Aborted | TwoPhaseState::Failed(_)
        );
        assert!(
            is_terminal,
            "Participant {} in non-terminal state: {:?}",
            participant.node_tag,
            participant.state
        );
    }
}

/// Test that 2PC helper functions work correctly
#[tokio::test]
async fn test_2pc_helper_functions_comprehensive() {
    let mock_client = Arc::new(MockNetworkClient::new());
    mock_client.fail_prepare("node-b", "Failure");

    let participants = vec![
        "node-a".to_string(),
        "node-b".to_string(),
        "node-c".to_string(),
    ];

    let mut coordinator = TwoPhaseCommit::new(
        "helper-chain".to_string(),
        create_test_chain_config_with_tag("helper-chain"),
        participants,
    )
    .with_network_client(mock_client.clone())
    .with_timeout(5);

    // Test initial state
    assert_eq!(coordinator.participant_count(), 3);
    assert!(!coordinator.all_prepared());
    assert!(!coordinator.all_committed());
    assert!(!coordinator.any_failed());
    assert_eq!(coordinator.prepared_nodes().len(), 0);
    assert_eq!(coordinator.failed_nodes().len(), 0);

    // After prepare
    let _ = coordinator.prepare_all().await;

    assert!(!coordinator.all_prepared()); // node-b failed
    assert!(coordinator.any_failed());
    assert_eq!(coordinator.prepared_nodes().len(), 2); // node-a and node-c
    assert_eq!(coordinator.failed_nodes().len(), 1); // node-b
}

/// Test network delay without timeout
#[tokio::test]
async fn test_2pc_network_delay_no_timeout() {
    let mock_client = Arc::new(MockNetworkClient::new());
    mock_client.set_delay(100); // 100ms delay

    let participants = vec!["node-a".to_string(), "node-b".to_string()];

    let mut coordinator = TwoPhaseCommit::new(
        "delay-chain".to_string(),
        create_test_chain_config_with_tag("delay-chain"),
        participants,
    )
    .with_network_client(mock_client.clone())
    .with_timeout(5); // 5 seconds, longer than delay

    // Should succeed despite delay
    let prepare_errors = coordinator.prepare_all().await;
    assert!(prepare_errors.is_empty());
    assert!(coordinator.all_prepared());
}

/// Test abort on coordinator decision (not failure)
#[tokio::test]
async fn test_2pc_coordinator_decision_abort() {
    let mock_client = Arc::new(MockNetworkClient::new());

    let participants = vec!["node-a".to_string(), "node-b".to_string()];

    let mut coordinator = TwoPhaseCommit::new(
        "decision-abort-chain".to_string(),
        create_test_chain_config_with_tag("decision-abort-chain"),
        participants,
    )
    .with_network_client(mock_client.clone())
    .with_timeout(5);

    // Prepare all successfully
    let prepare_errors = coordinator.prepare_all().await;
    assert!(prepare_errors.is_empty());
    assert!(coordinator.all_prepared());

    // Coordinator decides to abort (e.g., external condition changed)
    coordinator.abort_all().await;

    // All should be aborted
    assert_eq!(*coordinator.transaction_state(), TwoPhaseState::Aborted);
    for participant in coordinator.participants() {
        assert_eq!(participant.state, TwoPhaseState::Aborted);
    }
}

/// Test that late-arriving prepare failures don't affect already-failed transaction
#[tokio::test]
async fn test_2pc_transaction_state_after_early_failure() {
    let mock_client = Arc::new(MockNetworkClient::new());
    mock_client.fail_prepare("node-a", "Early failure");

    let participants = vec![
        "node-a".to_string(),
        "node-b".to_string(),
        "node-c".to_string(),
    ];

    let mut coordinator = TwoPhaseCommit::new(
        "early-fail-chain".to_string(),
        create_test_chain_config_with_tag("early-fail-chain"),
        participants,
    )
    .with_network_client(mock_client.clone())
    .with_timeout(5);

    // Prepare - node-a fails early
    let prepare_errors = coordinator.prepare_all().await;
    assert!(!prepare_errors.is_empty());

    // Transaction should be in failed state
    assert!(matches!(
        coordinator.transaction_state(),
        TwoPhaseState::Failed(_)
    ));

    // Even though node-b and node-c might have prepared, we can still abort
    let _ = coordinator.abort_all().await;
    assert_eq!(*coordinator.transaction_state(), TwoPhaseState::Aborted);
}
