//! Two-Phase Commit (2PC) protocol for Phase 6
//!
//! This module implements the Two-Phase Commit protocol for distributed
//! chain activation across multiple nodes.
//!
//! # Phase 6 Implementation Status
//!
//! - [ ] 6.6.3 PREPARE phase implementation
//! - [ ] 6.6.3 COMMIT phase implementation
//! - [ ] 6.6.3 ABORT/rollback implementation
//! - [ ] 6.6.3 Timeout handling
//!
//! # Protocol Overview
//!
//! Two-Phase Commit ensures atomic chain activation across all nodes:
//!
//! ## Phase 1: PREPARE
//! - Coordinator (entry node) sends PREPARE to all participants
//! - Each participant validates the chain configuration
//! - Participants respond with PREPARED or ABORT
//! - No state changes are applied during PREPARE
//!
//! ## Phase 2: COMMIT or ABORT
//! - If all participants respond PREPARED: Coordinator sends COMMIT
//! - If any participant fails PREPARE: Coordinator sends ABORT
//! - COMMIT applies routing rules atomically
//! - ABORT cleans up any pending state
//!
//! # Example
//!
//! ```ignore
//! use rust_router::chain::two_phase::TwoPhaseCommit;
//!
//! let coordinator = TwoPhaseCommit::new_coordinator(chain_config);
//!
//! // Phase 1: Prepare all nodes
//! for node in chain.nodes() {
//!     coordinator.prepare(node).await?;
//! }
//!
//! // Phase 2: Commit all nodes
//! if coordinator.all_prepared() {
//!     coordinator.commit_all().await?;
//! } else {
//!     coordinator.abort_all().await?;
//! }
//! ```
//!
//! # Failure Handling
//!
//! - **PREPARE failure**: Abort entire transaction
//! - **COMMIT failure**: Best-effort, some nodes may be active
//! - **Network partition**: Timeout-based abort
//!
//! # References
//!
//! - Implementation Plan: `docs/PHASE6_IMPLEMENTATION_PLAN_v3.2.md` Section 6.6.3

use std::collections::HashMap;

use crate::ipc::ChainConfig;

/// Default timeout for 2PC operations in seconds
pub const DEFAULT_2PC_TIMEOUT_SECS: u64 = 30;

/// Two-Phase Commit state for a participant
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TwoPhaseState {
    /// Initial state, not yet prepared
    Pending,
    /// PREPARE sent, waiting for response
    Preparing,
    /// PREPARE succeeded, ready to commit
    Prepared,
    /// COMMIT sent, waiting for confirmation
    Committing,
    /// Transaction committed successfully
    Committed,
    /// Transaction aborted
    Aborted,
    /// Operation failed with error
    Failed(String),
}

impl std::fmt::Display for TwoPhaseState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Preparing => write!(f, "preparing"),
            Self::Prepared => write!(f, "prepared"),
            Self::Committing => write!(f, "committing"),
            Self::Committed => write!(f, "committed"),
            Self::Aborted => write!(f, "aborted"),
            Self::Failed(msg) => write!(f, "failed: {}", msg),
        }
    }
}

/// Error types for 2PC operations
#[derive(Debug, thiserror::Error)]
pub enum TwoPhaseError {
    /// Participant not found
    #[error("Participant not found: {0}")]
    ParticipantNotFound(String),

    /// Invalid state transition
    #[error("Invalid state transition from {from} to {to}")]
    InvalidTransition { from: TwoPhaseState, to: TwoPhaseState },

    /// PREPARE failed
    #[error("PREPARE failed on {node}: {reason}")]
    PrepareFailed { node: String, reason: String },

    /// COMMIT failed
    #[error("COMMIT failed on {node}: {reason}")]
    CommitFailed { node: String, reason: String },

    /// Timeout waiting for response
    #[error("Timeout waiting for {node} during {phase}")]
    Timeout { node: String, phase: String },

    /// Transaction already finalized
    #[error("Transaction already {state}")]
    AlreadyFinalized { state: String },

    /// Not all participants prepared
    #[error("Cannot commit: not all participants prepared")]
    NotAllPrepared,

    /// Network error
    #[error("Network error communicating with {node}: {reason}")]
    NetworkError { node: String, reason: String },

    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),
}

/// Participant state in a 2PC transaction
#[derive(Debug, Clone)]
pub struct ParticipantState {
    /// Node tag
    pub node_tag: String,
    /// Current state
    pub state: TwoPhaseState,
    /// Error message if failed
    pub error: Option<String>,
}

/// Two-Phase Commit coordinator
///
/// Manages the 2PC protocol for a single chain activation transaction.
///
/// TODO(Phase 6.6): Implement full 2PC coordination
#[allow(dead_code)]
pub struct TwoPhaseCommit {
    /// Chain tag being activated
    chain_tag: String,
    /// Chain configuration
    config: ChainConfig,
    /// Map of node tag to participant state
    participants: HashMap<String, ParticipantState>,
    /// Overall transaction state
    transaction_state: TwoPhaseState,
    /// Timeout for operations in seconds
    timeout_secs: u64,
}

impl TwoPhaseCommit {
    /// Create a new 2PC coordinator
    ///
    /// # Arguments
    ///
    /// * `chain_tag` - Tag of the chain being activated
    /// * `config` - Chain configuration
    /// * `participant_tags` - List of participant node tags
    ///
    /// # Example
    ///
    /// ```ignore
    /// let coordinator = TwoPhaseCommit::new(
    ///     "my-chain".to_string(),
    ///     chain_config,
    ///     vec!["node-a", "node-b", "node-c"],
    /// );
    /// ```
    pub fn new(chain_tag: String, config: ChainConfig, participant_tags: Vec<String>) -> Self {
        let participants = participant_tags
            .into_iter()
            .map(|tag| {
                (
                    tag.clone(),
                    ParticipantState {
                        node_tag: tag,
                        state: TwoPhaseState::Pending,
                        error: None,
                    },
                )
            })
            .collect();

        Self {
            chain_tag,
            config,
            participants,
            transaction_state: TwoPhaseState::Pending,
            timeout_secs: DEFAULT_2PC_TIMEOUT_SECS,
        }
    }

    /// Set the operation timeout
    pub fn with_timeout(mut self, timeout_secs: u64) -> Self {
        self.timeout_secs = timeout_secs;
        self
    }

    /// Get the chain tag
    pub fn chain_tag(&self) -> &str {
        &self.chain_tag
    }

    /// Get the chain configuration
    pub fn config(&self) -> &ChainConfig {
        &self.config
    }

    /// Get the overall transaction state
    pub fn transaction_state(&self) -> &TwoPhaseState {
        &self.transaction_state
    }

    /// Get participant state
    pub fn get_participant(&self, node_tag: &str) -> Option<&ParticipantState> {
        self.participants.get(node_tag)
    }

    /// Get all participants
    pub fn participants(&self) -> impl Iterator<Item = &ParticipantState> {
        self.participants.values()
    }

    /// Check if all participants are prepared
    pub fn all_prepared(&self) -> bool {
        self.participants
            .values()
            .all(|p| p.state == TwoPhaseState::Prepared)
    }

    /// Check if any participant has failed
    pub fn any_failed(&self) -> bool {
        self.participants
            .values()
            .any(|p| matches!(p.state, TwoPhaseState::Failed(_) | TwoPhaseState::Aborted))
    }

    /// Get list of prepared nodes
    pub fn prepared_nodes(&self) -> Vec<String> {
        self.participants
            .values()
            .filter(|p| p.state == TwoPhaseState::Prepared)
            .map(|p| p.node_tag.clone())
            .collect()
    }

    /// Send PREPARE to a participant
    ///
    /// # Arguments
    ///
    /// * `node_tag` - Node to prepare
    ///
    /// TODO(Phase 6.6): Implement PREPARE sending
    pub async fn prepare(&mut self, _node_tag: &str) -> Result<(), TwoPhaseError> {
        unimplemented!("Phase 6.6: prepare not yet implemented")
    }

    /// Send PREPARE to all participants
    ///
    /// # Returns
    ///
    /// List of nodes that failed to prepare
    ///
    /// TODO(Phase 6.6): Implement PREPARE all
    pub async fn prepare_all(&mut self) -> Vec<TwoPhaseError> {
        unimplemented!("Phase 6.6: prepare_all not yet implemented")
    }

    /// Send COMMIT to a participant
    ///
    /// # Arguments
    ///
    /// * `node_tag` - Node to commit
    ///
    /// TODO(Phase 6.6): Implement COMMIT sending
    pub async fn commit(&mut self, _node_tag: &str) -> Result<(), TwoPhaseError> {
        unimplemented!("Phase 6.6: commit not yet implemented")
    }

    /// Send COMMIT to all prepared participants
    ///
    /// # Returns
    ///
    /// List of nodes that failed to commit
    ///
    /// TODO(Phase 6.6): Implement COMMIT all
    pub async fn commit_all(&mut self) -> Vec<TwoPhaseError> {
        unimplemented!("Phase 6.6: commit_all not yet implemented")
    }

    /// Send ABORT to a participant
    ///
    /// # Arguments
    ///
    /// * `node_tag` - Node to abort
    ///
    /// TODO(Phase 6.6): Implement ABORT sending
    pub async fn abort(&mut self, _node_tag: &str) -> Result<(), TwoPhaseError> {
        unimplemented!("Phase 6.6: abort not yet implemented")
    }

    /// Send ABORT to all participants
    ///
    /// Best-effort abort - continues even if some nodes fail.
    ///
    /// TODO(Phase 6.6): Implement ABORT all
    pub async fn abort_all(&mut self) {
        unimplemented!("Phase 6.6: abort_all not yet implemented")
    }

    /// Record PREPARE success for a participant
    pub fn record_prepare_success(&mut self, node_tag: &str) -> Result<(), TwoPhaseError> {
        let participant = self
            .participants
            .get_mut(node_tag)
            .ok_or_else(|| TwoPhaseError::ParticipantNotFound(node_tag.to_string()))?;

        participant.state = TwoPhaseState::Prepared;
        Ok(())
    }

    /// Record PREPARE failure for a participant
    pub fn record_prepare_failure(&mut self, node_tag: &str, reason: String) -> Result<(), TwoPhaseError> {
        let participant = self
            .participants
            .get_mut(node_tag)
            .ok_or_else(|| TwoPhaseError::ParticipantNotFound(node_tag.to_string()))?;

        participant.state = TwoPhaseState::Failed(reason.clone());
        participant.error = Some(reason);
        Ok(())
    }

    /// Record COMMIT success for a participant
    pub fn record_commit_success(&mut self, node_tag: &str) -> Result<(), TwoPhaseError> {
        let participant = self
            .participants
            .get_mut(node_tag)
            .ok_or_else(|| TwoPhaseError::ParticipantNotFound(node_tag.to_string()))?;

        participant.state = TwoPhaseState::Committed;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::{ChainHop, ChainRole, TunnelType};

    fn create_test_config() -> ChainConfig {
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

    #[test]
    fn test_new_coordinator() {
        let config = create_test_config();
        let coordinator = TwoPhaseCommit::new(
            "test-chain".to_string(),
            config,
            vec!["node-a".to_string(), "node-b".to_string()],
        );

        assert_eq!(coordinator.chain_tag(), "test-chain");
        assert_eq!(*coordinator.transaction_state(), TwoPhaseState::Pending);
        assert_eq!(coordinator.participants().count(), 2);
    }

    #[test]
    fn test_all_prepared() {
        let config = create_test_config();
        let mut coordinator = TwoPhaseCommit::new(
            "test-chain".to_string(),
            config,
            vec!["node-a".to_string(), "node-b".to_string()],
        );

        assert!(!coordinator.all_prepared());

        coordinator.record_prepare_success("node-a").unwrap();
        assert!(!coordinator.all_prepared());

        coordinator.record_prepare_success("node-b").unwrap();
        assert!(coordinator.all_prepared());
    }

    #[test]
    fn test_any_failed() {
        let config = create_test_config();
        let mut coordinator = TwoPhaseCommit::new(
            "test-chain".to_string(),
            config,
            vec!["node-a".to_string(), "node-b".to_string()],
        );

        assert!(!coordinator.any_failed());

        coordinator
            .record_prepare_failure("node-a", "test error".to_string())
            .unwrap();
        assert!(coordinator.any_failed());
    }

    #[test]
    fn test_prepared_nodes() {
        let config = create_test_config();
        let mut coordinator = TwoPhaseCommit::new(
            "test-chain".to_string(),
            config,
            vec!["node-a".to_string(), "node-b".to_string()],
        );

        assert!(coordinator.prepared_nodes().is_empty());

        coordinator.record_prepare_success("node-a").unwrap();
        let prepared = coordinator.prepared_nodes();
        assert_eq!(prepared.len(), 1);
        assert!(prepared.contains(&"node-a".to_string()));
    }

    #[test]
    fn test_participant_not_found() {
        let config = create_test_config();
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
    fn test_two_phase_state_display() {
        assert_eq!(TwoPhaseState::Pending.to_string(), "pending");
        assert_eq!(TwoPhaseState::Prepared.to_string(), "prepared");
        assert_eq!(TwoPhaseState::Committed.to_string(), "committed");
        assert_eq!(
            TwoPhaseState::Failed("error".to_string()).to_string(),
            "failed: error"
        );
    }
}
