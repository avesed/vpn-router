//! Two-Phase Commit (2PC) protocol for distributed chain activation
//!
//! This module implements the Two-Phase Commit protocol for distributed
//! chain activation across multiple nodes.
//!
//! # Features
//!
//! - PREPARE phase implementation
//! - COMMIT phase implementation
//! - ABORT/rollback implementation
//! - Timeout handling
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
//! use rust_router::chain::two_phase::{TwoPhaseCommit, NoOpNetworkClient};
//!
//! let client = Arc::new(NoOpNetworkClient);
//! let coordinator = TwoPhaseCommit::new(
//!     "my-chain".to_string(),
//!     chain_config,
//!     vec!["node-a".to_string(), "node-b".to_string()],
//! ).with_network_client(client);
//!
//! // Phase 1: Prepare all nodes
//! let errors = coordinator.prepare_all().await;
//! if errors.is_empty() {
//!     // Phase 2: Commit all nodes
//!     let errors = coordinator.commit_all().await;
//! } else {
//!     // Abort on failure
//!     coordinator.abort_all().await;
//! }
//! ```
//!
//! # Failure Handling
//!
//! - **PREPARE failure**: Abort entire transaction
//! - **COMMIT failure**: Best-effort, some nodes may be active
//! - **Network partition**: Timeout-based abort

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::oneshot;
use tokio::time::timeout;
use tracing::{debug, warn};

use crate::ipc::ChainConfig;
use crate::peer::manager::PeerManager;
use crate::tunnel::OutboundHttpRequest;

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
            Self::Failed(msg) => write!(f, "failed: {msg}"),
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

    /// ABORT failed
    #[error("ABORT failed on {node}: {reason}")]
    AbortFailed { node: String, reason: String },

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

/// Network client trait for 2PC operations
///
/// This trait abstracts network communication for the 2PC protocol,
/// allowing for mock implementations in tests and real network
/// implementations in production.
#[async_trait]
pub trait ChainNetworkClient: Send + Sync {
    /// Send PREPARE request to a node
    ///
    /// # Arguments
    ///
    /// * `node` - Node tag to send to
    /// * `config` - Chain configuration
    ///
    /// # Returns
    ///
    /// Ok if the node is prepared, Err with reason otherwise.
    async fn send_prepare(&self, node: &str, config: &ChainConfig) -> Result<(), String>;

    /// Send COMMIT request to a node
    ///
    /// # Arguments
    ///
    /// * `node` - Node tag to send to
    /// * `chain_tag` - Chain tag being committed
    ///
    /// # Returns
    ///
    /// Ok if commit successful, Err with reason otherwise.
    async fn send_commit(&self, node: &str, chain_tag: &str) -> Result<(), String>;

    /// Send ABORT request to a node
    ///
    /// # Arguments
    ///
    /// * `node` - Node tag to send to
    /// * `chain_tag` - Chain tag being aborted
    ///
    /// # Returns
    ///
    /// Ok if abort successful, Err with reason otherwise.
    async fn send_abort(&self, node: &str, chain_tag: &str) -> Result<(), String>;
}

/// No-op network client for single-node testing
///
/// This implementation always succeeds immediately, useful for
/// testing chain activation on a single node without network.
pub struct NoOpNetworkClient;

#[async_trait]
impl ChainNetworkClient for NoOpNetworkClient {
    async fn send_prepare(&self, _node: &str, _config: &ChainConfig) -> Result<(), String> {
        Ok(())
    }

    async fn send_commit(&self, _node: &str, _chain_tag: &str) -> Result<(), String> {
        Ok(())
    }

    async fn send_abort(&self, _node: &str, _chain_tag: &str) -> Result<(), String> {
        Ok(())
    }
}

/// Network client that sends 2PC messages through WireGuard tunnels via ForwardPeerRequest
///
/// This implementation uses the existing peer tunnel infrastructure to send
/// PREPARE, COMMIT, and ABORT messages to remote nodes.
///
/// Uses the unified pump pattern - requests are sent through the TCP proxy's
/// channel rather than creating a competing packet pump.
pub struct ForwardPeerNetworkClient {
    /// Reference to peer manager for getting tunnel info and request senders
    peer_manager: Arc<PeerManager>,
    /// Local node tag for source identification
    local_node_tag: String,
    /// Request timeout in seconds
    timeout_secs: u64,
}

impl ForwardPeerNetworkClient {
    /// Create a new ForwardPeerNetworkClient
    ///
    /// # Arguments
    ///
    /// * `peer_manager` - Reference to the peer manager
    /// * `local_node_tag` - Tag of the local node (used as source_node in requests)
    pub fn new(peer_manager: Arc<PeerManager>, local_node_tag: String) -> Self {
        Self {
            peer_manager,
            local_node_tag,
            timeout_secs: DEFAULT_2PC_TIMEOUT_SECS,
        }
    }

    /// Set the request timeout
    pub fn with_timeout(mut self, timeout_secs: u64) -> Self {
        self.timeout_secs = timeout_secs;
        self
    }

    /// Send an HTTP request through the peer's WireGuard tunnel
    ///
    /// # Arguments
    ///
    /// * `node` - Target peer node tag
    /// * `path` - API endpoint path (e.g., "/api/chain-routing/prepare")
    /// * `body` - JSON request body
    ///
    /// # Returns
    ///
    /// The response body on success, or an error message
    async fn send_request(&self, node: &str, path: &str, body: String) -> Result<String, String> {
        // Get peer config to find tunnel IPs
        let peer_config = self
            .peer_manager
            .get_peer_config(node)
            .ok_or_else(|| format!("Peer '{}' not found", node))?;

        // Get tunnel IPs
        let tunnel_local_ip: Ipv4Addr = peer_config
            .tunnel_local_ip
            .as_ref()
            .ok_or_else(|| format!("Peer '{}' has no tunnel_local_ip configured", node))?
            .parse()
            .map_err(|e| format!("Invalid tunnel_local_ip for peer '{}': {}", node, e))?;

        let tunnel_remote_ip: Ipv4Addr = peer_config
            .tunnel_remote_ip
            .as_ref()
            .ok_or_else(|| format!("Peer '{}' has no tunnel_remote_ip configured", node))?
            .parse()
            .map_err(|e| format!("Invalid tunnel_remote_ip for peer '{}': {}", node, e))?;

        // Get the outbound request sender
        let request_sender = self
            .peer_manager
            .get_outbound_request_sender(node)
            .ok_or_else(|| {
                format!(
                    "No outbound request channel for peer '{}' - tunnel may not be connected",
                    node
                )
            })?;

        debug!(
            node = %node,
            path = %path,
            local_ip = %tunnel_local_ip,
            remote_ip = %tunnel_remote_ip,
            "Sending 2PC request through WireGuard tunnel"
        );

        // Build request headers
        let mut headers = std::collections::HashMap::new();
        headers.insert("Content-Type".to_string(), "application/json".to_string());
        headers.insert("X-Tunnel-Source-IP".to_string(), tunnel_local_ip.to_string());
        headers.insert("X-Tunnel-Peer-Tag".to_string(), self.local_node_tag.clone());

        // Create oneshot channel for response
        let (response_tx, response_rx) = oneshot::channel();

        // Build the outbound request
        let outbound_request = OutboundHttpRequest {
            method: "POST".to_string(),
            path: path.to_string(),
            host: tunnel_remote_ip.to_string(),
            port: 36000,
            body: Some(body),
            headers: Some(headers),
            response_tx,
        };

        // Send the request
        request_sender
            .send(outbound_request)
            .await
            .map_err(|_| format!("Failed to send request to TCP proxy for peer '{}'", node))?;

        // Wait for response with timeout
        let timeout_duration = Duration::from_secs(self.timeout_secs);
        let response = timeout(timeout_duration, response_rx)
            .await
            .map_err(|_| format!("Request to peer '{}' timed out after {}s", node, self.timeout_secs))?
            .map_err(|_| format!("Response channel closed for peer '{}'", node))?;

        // Check response
        if response.success {
            let body = response.body.unwrap_or_default();
            debug!(
                node = %node,
                status = ?response.status_code,
                body_len = body.len(),
                "2PC request completed successfully"
            );
            Ok(body)
        } else {
            let error = response.error.unwrap_or_else(|| "Unknown error".to_string());
            warn!(node = %node, error = %error, "2PC request failed");
            Err(error)
        }
    }

    /// Parse JSON response to check for success
    fn parse_response(&self, response: &str) -> Result<(), String> {
        // Parse JSON response to check success field
        // Expected format: {"success": true, "message": "..."} or {"success": false, "message": "..."}
        let json: serde_json::Value = serde_json::from_str(response)
            .map_err(|e| format!("Failed to parse response JSON: {}", e))?;

        let success = json
            .get("success")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        if success {
            Ok(())
        } else {
            // Check both "message" (API format) and "error" (fallback) fields
            let error = json
                .get("message")
                .or_else(|| json.get("error"))
                .and_then(|v| v.as_str())
                .unwrap_or("Unknown error");
            Err(error.to_string())
        }
    }
}

#[async_trait]
impl ChainNetworkClient for ForwardPeerNetworkClient {
    async fn send_prepare(&self, node: &str, config: &ChainConfig) -> Result<(), String> {
        debug!(node = %node, chain = %config.tag, "Sending PREPARE to remote node");

        // Build request body
        let body = serde_json::json!({
            "chain_tag": config.tag,
            "config": config,
            "source_node": self.local_node_tag
        });

        let response = self
            .send_request(node, "/api/chain-routing/prepare", body.to_string())
            .await?;

        self.parse_response(&response)
    }

    async fn send_commit(&self, node: &str, chain_tag: &str) -> Result<(), String> {
        debug!(node = %node, chain = %chain_tag, "Sending COMMIT to remote node");

        // Build request body
        let body = serde_json::json!({
            "chain_tag": chain_tag,
            "source_node": self.local_node_tag
        });

        let response = self
            .send_request(node, "/api/chain-routing/commit", body.to_string())
            .await?;

        self.parse_response(&response)
    }

    async fn send_abort(&self, node: &str, chain_tag: &str) -> Result<(), String> {
        debug!(node = %node, chain = %chain_tag, "Sending ABORT to remote node");

        // Build request body
        let body = serde_json::json!({
            "chain_tag": chain_tag,
            "source_node": self.local_node_tag
        });

        let response = self
            .send_request(node, "/api/chain-routing/abort", body.to_string())
            .await?;

        self.parse_response(&response)
    }
}

/// Mock network client for testing failures
///
/// Allows configuring which nodes will fail at which phase.
#[derive(Default)]
pub struct MockNetworkClient {
    /// Nodes that will fail during PREPARE
    pub prepare_failures: std::sync::Mutex<HashMap<String, String>>,
    /// Nodes that will fail during COMMIT
    pub commit_failures: std::sync::Mutex<HashMap<String, String>>,
    /// Nodes that will fail during ABORT
    pub abort_failures: std::sync::Mutex<HashMap<String, String>>,
    /// Artificial delay for network operations (milliseconds)
    pub delay_ms: std::sync::atomic::AtomicU64,
}

impl MockNetworkClient {
    /// Create a new mock client
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a node that will fail PREPARE
    pub fn fail_prepare(&self, node: &str, reason: &str) {
        if let Ok(mut failures) = self.prepare_failures.lock() {
            failures.insert(node.to_string(), reason.to_string());
        }
    }

    /// Add a node that will fail COMMIT
    pub fn fail_commit(&self, node: &str, reason: &str) {
        if let Ok(mut failures) = self.commit_failures.lock() {
            failures.insert(node.to_string(), reason.to_string());
        }
    }

    /// Add a node that will fail ABORT
    pub fn fail_abort(&self, node: &str, reason: &str) {
        if let Ok(mut failures) = self.abort_failures.lock() {
            failures.insert(node.to_string(), reason.to_string());
        }
    }

    /// Set artificial delay for operations
    pub fn set_delay(&self, delay_ms: u64) {
        self.delay_ms.store(delay_ms, std::sync::atomic::Ordering::SeqCst);
    }
}

#[async_trait]
impl ChainNetworkClient for MockNetworkClient {
    async fn send_prepare(&self, node: &str, _config: &ChainConfig) -> Result<(), String> {
        let delay = self.delay_ms.load(std::sync::atomic::Ordering::SeqCst);
        if delay > 0 {
            tokio::time::sleep(Duration::from_millis(delay)).await;
        }

        if let Ok(failures) = self.prepare_failures.lock() {
            if let Some(reason) = failures.get(node) {
                return Err(reason.clone());
            }
        }
        Ok(())
    }

    async fn send_commit(&self, node: &str, _chain_tag: &str) -> Result<(), String> {
        let delay = self.delay_ms.load(std::sync::atomic::Ordering::SeqCst);
        if delay > 0 {
            tokio::time::sleep(Duration::from_millis(delay)).await;
        }

        if let Ok(failures) = self.commit_failures.lock() {
            if let Some(reason) = failures.get(node) {
                return Err(reason.clone());
            }
        }
        Ok(())
    }

    async fn send_abort(&self, node: &str, _chain_tag: &str) -> Result<(), String> {
        let delay = self.delay_ms.load(std::sync::atomic::Ordering::SeqCst);
        if delay > 0 {
            tokio::time::sleep(Duration::from_millis(delay)).await;
        }

        if let Ok(failures) = self.abort_failures.lock() {
            if let Some(reason) = failures.get(node) {
                return Err(reason.clone());
            }
        }
        Ok(())
    }
}

/// Two-Phase Commit coordinator
///
/// Manages the 2PC protocol for a single chain activation transaction.
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
    /// Network client for sending messages
    network_client: Option<Arc<dyn ChainNetworkClient>>,
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
            network_client: None,
        }
    }

    /// Set the operation timeout
    pub fn with_timeout(mut self, timeout_secs: u64) -> Self {
        self.timeout_secs = timeout_secs;
        self
    }

    /// Set the network client
    pub fn with_network_client(mut self, client: Arc<dyn ChainNetworkClient>) -> Self {
        self.network_client = Some(client);
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

    /// Get number of participants
    pub fn participant_count(&self) -> usize {
        self.participants.len()
    }

    /// Check if all participants are prepared
    pub fn all_prepared(&self) -> bool {
        self.participants
            .values()
            .all(|p| p.state == TwoPhaseState::Prepared)
    }

    /// Check if all participants are committed
    pub fn all_committed(&self) -> bool {
        self.participants
            .values()
            .all(|p| p.state == TwoPhaseState::Committed)
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

    /// Get list of failed nodes
    pub fn failed_nodes(&self) -> Vec<String> {
        self.participants
            .values()
            .filter(|p| matches!(p.state, TwoPhaseState::Failed(_)))
            .map(|p| p.node_tag.clone())
            .collect()
    }

    /// Check if transaction is finalized (committed or aborted)
    fn is_finalized(&self) -> bool {
        matches!(
            self.transaction_state,
            TwoPhaseState::Committed | TwoPhaseState::Aborted
        )
    }

    /// Send PREPARE to a participant
    ///
    /// Updates participant state through the prepare sequence:
    /// Pending -> Preparing -> Prepared/Failed
    ///
    /// # Arguments
    ///
    /// * `node_tag` - Node to prepare
    pub async fn prepare(&mut self, node_tag: &str) -> Result<(), TwoPhaseError> {
        // Check transaction not already finalized
        if self.is_finalized() {
            return Err(TwoPhaseError::AlreadyFinalized {
                state: self.transaction_state.to_string(),
            });
        }

        // Get participant
        let participant = self
            .participants
            .get_mut(node_tag)
            .ok_or_else(|| TwoPhaseError::ParticipantNotFound(node_tag.to_string()))?;

        // Check participant is in valid state
        match &participant.state {
            TwoPhaseState::Pending => {}
            TwoPhaseState::Prepared => return Ok(()), // Already prepared
            state => {
                return Err(TwoPhaseError::InvalidTransition {
                    from: state.clone(),
                    to: TwoPhaseState::Preparing,
                });
            }
        }

        // Update state to Preparing
        participant.state = TwoPhaseState::Preparing;

        // Send PREPARE via network client
        let result = if let Some(client) = &self.network_client {
            let timeout_duration = Duration::from_secs(self.timeout_secs);
            match timeout(timeout_duration, client.send_prepare(node_tag, &self.config)).await {
                Ok(Ok(())) => Ok(()),
                Ok(Err(reason)) => Err(TwoPhaseError::PrepareFailed {
                    node: node_tag.to_string(),
                    reason,
                }),
                Err(_) => Err(TwoPhaseError::Timeout {
                    node: node_tag.to_string(),
                    phase: "PREPARE".to_string(),
                }),
            }
        } else {
            // No network client - assume local operation succeeds
            Ok(())
        };

        // Update participant state based on result
        // Need to get participant again due to borrow checker
        let participant = self.participants.get_mut(node_tag).unwrap();
        match &result {
            Ok(()) => {
                participant.state = TwoPhaseState::Prepared;
            }
            Err(e) => {
                let reason = e.to_string();
                participant.state = TwoPhaseState::Failed(reason.clone());
                participant.error = Some(reason);
            }
        }

        result
    }

    /// Send PREPARE to all participants
    ///
    /// Runs PREPARE sequentially on all participants. Updates `transaction_state`
    /// to Preparing, then to Prepared if all succeed, or to Failed if any fail.
    ///
    /// Note: Sequential execution is used due to Rust's borrowing rules with
    /// `&mut self`. For production parallel execution, consider using message
    /// passing or restructuring to avoid mutable borrows.
    ///
    /// # Returns
    ///
    /// List of errors for nodes that failed to prepare.
    pub async fn prepare_all(&mut self) -> Vec<TwoPhaseError> {
        // Check transaction not already finalized
        if self.is_finalized() {
            return vec![TwoPhaseError::AlreadyFinalized {
                state: self.transaction_state.to_string(),
            }];
        }

        // Update transaction state
        self.transaction_state = TwoPhaseState::Preparing;

        // Get all participant tags to prepare
        let node_tags: Vec<String> = self.participants.keys().cloned().collect();

        // Prepare participants sequentially
        let mut errors = Vec::new();
        for tag in node_tags {
            if let Err(e) = self.prepare(&tag).await {
                errors.push(e);
            }
        }

        // Update transaction state based on results
        if errors.is_empty() && self.all_prepared() {
            self.transaction_state = TwoPhaseState::Prepared;
        } else {
            self.transaction_state = TwoPhaseState::Failed("Not all participants prepared".to_string());
        }

        errors
    }

    /// Send COMMIT to a participant
    ///
    /// Only allowed if participant is in Prepared state.
    /// Updates state: Prepared -> Committing -> Committed/Failed
    ///
    /// # Arguments
    ///
    /// * `node_tag` - Node to commit
    pub async fn commit(&mut self, node_tag: &str) -> Result<(), TwoPhaseError> {
        // Get participant
        let participant = self
            .participants
            .get_mut(node_tag)
            .ok_or_else(|| TwoPhaseError::ParticipantNotFound(node_tag.to_string()))?;

        // Check participant is Prepared
        match &participant.state {
            TwoPhaseState::Prepared => {}
            TwoPhaseState::Committed => return Ok(()), // Already committed
            state => {
                return Err(TwoPhaseError::InvalidTransition {
                    from: state.clone(),
                    to: TwoPhaseState::Committing,
                });
            }
        }

        // Update state to Committing
        participant.state = TwoPhaseState::Committing;

        // Send COMMIT via network client
        let result = if let Some(client) = &self.network_client {
            let timeout_duration = Duration::from_secs(self.timeout_secs);
            match timeout(timeout_duration, client.send_commit(node_tag, &self.chain_tag)).await {
                Ok(Ok(())) => Ok(()),
                Ok(Err(reason)) => Err(TwoPhaseError::CommitFailed {
                    node: node_tag.to_string(),
                    reason,
                }),
                Err(_) => Err(TwoPhaseError::Timeout {
                    node: node_tag.to_string(),
                    phase: "COMMIT".to_string(),
                }),
            }
        } else {
            // No network client - assume local operation succeeds
            Ok(())
        };

        // Update participant state based on result
        let participant = self.participants.get_mut(node_tag).unwrap();
        match &result {
            Ok(()) => {
                participant.state = TwoPhaseState::Committed;
            }
            Err(e) => {
                let reason = e.to_string();
                participant.state = TwoPhaseState::Failed(reason.clone());
                participant.error = Some(reason);
            }
        }

        result
    }

    /// Send COMMIT to all prepared participants
    ///
    /// Only proceeds if all participants are prepared.
    /// Commits sequentially on all prepared nodes.
    ///
    /// # Returns
    ///
    /// List of errors for nodes that failed to commit.
    pub async fn commit_all(&mut self) -> Vec<TwoPhaseError> {
        // Check all prepared first
        if !self.all_prepared() {
            return vec![TwoPhaseError::NotAllPrepared];
        }

        // Update transaction state
        self.transaction_state = TwoPhaseState::Committing;

        // Get all prepared participant tags
        let node_tags = self.prepared_nodes();

        // Commit sequentially
        let mut errors = Vec::new();
        for tag in node_tags {
            if let Err(e) = self.commit(&tag).await {
                errors.push(e);
            }
        }

        // Update transaction state
        if errors.is_empty() && self.all_committed() {
            self.transaction_state = TwoPhaseState::Committed;
        } else {
            // Partial commit - some nodes committed, some failed
            // Transaction is in inconsistent state
            self.transaction_state = TwoPhaseState::Failed("Partial commit".to_string());
        }

        errors
    }

    /// Send ABORT to a participant
    ///
    /// Marks the participant as Aborted. Can be called from any non-committed state.
    ///
    /// # Arguments
    ///
    /// * `node_tag` - Node to abort
    pub async fn abort(&mut self, node_tag: &str) -> Result<(), TwoPhaseError> {
        // Get participant
        let participant = self
            .participants
            .get_mut(node_tag)
            .ok_or_else(|| TwoPhaseError::ParticipantNotFound(node_tag.to_string()))?;

        // Can't abort if already committed
        match &participant.state {
            TwoPhaseState::Committed => {
                return Err(TwoPhaseError::InvalidTransition {
                    from: participant.state.clone(),
                    to: TwoPhaseState::Aborted,
                });
            }
            TwoPhaseState::Aborted => return Ok(()), // Already aborted
            _ => {}
        }

        // Send ABORT via network client
        let result = if let Some(client) = &self.network_client {
            let timeout_duration = Duration::from_secs(self.timeout_secs);
            match timeout(timeout_duration, client.send_abort(node_tag, &self.chain_tag)).await {
                Ok(Ok(())) => Ok(()),
                Ok(Err(reason)) => Err(TwoPhaseError::AbortFailed {
                    node: node_tag.to_string(),
                    reason,
                }),
                Err(_) => Err(TwoPhaseError::Timeout {
                    node: node_tag.to_string(),
                    phase: "ABORT".to_string(),
                }),
            }
        } else {
            Ok(())
        };

        // Always mark as Aborted (best-effort)
        let participant = self.participants.get_mut(node_tag).unwrap();
        participant.state = TwoPhaseState::Aborted;

        result
    }

    /// Send ABORT to all participants
    ///
    /// Best-effort abort - continues even if some nodes fail to respond.
    /// Updates `transaction_state` to Aborted.
    ///
    /// Note: Aborts are executed sequentially due to Rust's borrowing rules
    /// with `&mut self`. For abort operations, sequential execution is acceptable
    /// since abort is best-effort and we continue regardless of individual failures.
    pub async fn abort_all(&mut self) {
        // Get all participant tags (except already committed)
        let node_tags: Vec<String> = self
            .participants
            .iter()
            .filter(|(_, p)| p.state != TwoPhaseState::Committed)
            .map(|(tag, _)| tag.clone())
            .collect();

        // Abort sequentially (best-effort - ignore individual failures)
        for tag in node_tags {
            let _ = self.abort(&tag).await;
        }

        // Update transaction state
        self.transaction_state = TwoPhaseState::Aborted;
    }

    /// Record PREPARE success for a participant
    ///
    /// Used when handling incoming PREPARE responses without going through
    /// the network client.
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

    /// Record COMMIT failure for a participant
    pub fn record_commit_failure(&mut self, node_tag: &str, reason: String) -> Result<(), TwoPhaseError> {
        let participant = self
            .participants
            .get_mut(node_tag)
            .ok_or_else(|| TwoPhaseError::ParticipantNotFound(node_tag.to_string()))?;

        participant.state = TwoPhaseState::Failed(reason.clone());
        participant.error = Some(reason);
        Ok(())
    }

    /// Record ABORT for a participant
    pub fn record_abort(&mut self, node_tag: &str) -> Result<(), TwoPhaseError> {
        let participant = self
            .participants
            .get_mut(node_tag)
            .ok_or_else(|| TwoPhaseError::ParticipantNotFound(node_tag.to_string()))?;

        participant.state = TwoPhaseState::Aborted;
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

    // =========================================================================
    // Coordinator creation tests
    // =========================================================================

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
        assert_eq!(coordinator.participant_count(), 2);
    }

    #[test]
    fn test_coordinator_with_timeout() {
        let config = create_test_config();
        let coordinator = TwoPhaseCommit::new(
            "test-chain".to_string(),
            config,
            vec!["node-a".to_string()],
        )
        .with_timeout(60);

        assert_eq!(coordinator.timeout_secs, 60);
    }

    #[test]
    fn test_coordinator_with_network_client() {
        let config = create_test_config();
        let client = Arc::new(NoOpNetworkClient);
        let coordinator = TwoPhaseCommit::new(
            "test-chain".to_string(),
            config,
            vec!["node-a".to_string()],
        )
        .with_network_client(client);

        assert!(coordinator.network_client.is_some());
    }

    // =========================================================================
    // State query tests
    // =========================================================================

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
    fn test_all_committed() {
        let config = create_test_config();
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
    fn test_failed_nodes() {
        let config = create_test_config();
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
        assert_eq!(TwoPhaseState::Preparing.to_string(), "preparing");
        assert_eq!(TwoPhaseState::Prepared.to_string(), "prepared");
        assert_eq!(TwoPhaseState::Committing.to_string(), "committing");
        assert_eq!(TwoPhaseState::Committed.to_string(), "committed");
        assert_eq!(TwoPhaseState::Aborted.to_string(), "aborted");
        assert_eq!(
            TwoPhaseState::Failed("error".to_string()).to_string(),
            "failed: error"
        );
    }

    // =========================================================================
    // PREPARE tests
    // =========================================================================

    #[tokio::test]
    async fn test_prepare_single_no_client() {
        let config = create_test_config();
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
        let config = create_test_config();
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
        let config = create_test_config();
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
        let config = create_test_config();
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
    async fn test_prepare_all_success() {
        let config = create_test_config();
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
        let config = create_test_config();
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

    // =========================================================================
    // COMMIT tests
    // =========================================================================

    #[tokio::test]
    async fn test_commit_single_success() {
        let config = create_test_config();
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
        let config = create_test_config();
        let mut coordinator = TwoPhaseCommit::new(
            "test-chain".to_string(),
            config,
            vec!["node-a".to_string()],
        );

        let result = coordinator.commit("node-a").await;
        assert!(matches!(result, Err(TwoPhaseError::InvalidTransition { .. })));
    }

    #[tokio::test]
    async fn test_commit_idempotent() {
        let config = create_test_config();
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
        let config = create_test_config();
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
        let config = create_test_config();
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
        let config = create_test_config();
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
        let config = create_test_config();
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

    // =========================================================================
    // ABORT tests
    // =========================================================================

    #[tokio::test]
    async fn test_abort_single_success() {
        let config = create_test_config();
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
        let config = create_test_config();
        let mut coordinator = TwoPhaseCommit::new(
            "test-chain".to_string(),
            config,
            vec!["node-a".to_string()],
        );

        coordinator.record_commit_success("node-a").unwrap();
        let result = coordinator.abort("node-a").await;
        assert!(matches!(result, Err(TwoPhaseError::InvalidTransition { .. })));
    }

    #[tokio::test]
    async fn test_abort_idempotent() {
        let config = create_test_config();
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
    async fn test_abort_all() {
        let config = create_test_config();
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
        let config = create_test_config();
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

    // =========================================================================
    // Full 2PC flow tests
    // =========================================================================

    #[tokio::test]
    async fn test_full_2pc_success() {
        let config = create_test_config();
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
        let config = create_test_config();
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

    // =========================================================================
    // Timeout tests
    // =========================================================================

    #[tokio::test]
    async fn test_prepare_timeout() {
        let config = create_test_config();
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
    }

    // =========================================================================
    // Record methods tests
    // =========================================================================

    #[test]
    fn test_record_methods() {
        let config = create_test_config();
        let mut coordinator = TwoPhaseCommit::new(
            "test-chain".to_string(),
            config,
            vec!["node-a".to_string()],
        );

        // Test record_prepare_success
        coordinator.record_prepare_success("node-a").unwrap();
        assert_eq!(
            coordinator.get_participant("node-a").unwrap().state,
            TwoPhaseState::Prepared
        );

        // Test record_commit_success
        coordinator.record_commit_success("node-a").unwrap();
        assert_eq!(
            coordinator.get_participant("node-a").unwrap().state,
            TwoPhaseState::Committed
        );
    }

    #[test]
    fn test_record_failure_methods() {
        let config = create_test_config();
        let mut coordinator = TwoPhaseCommit::new(
            "test-chain".to_string(),
            config,
            vec!["node-a".to_string(), "node-b".to_string()],
        );

        // Test record_prepare_failure
        coordinator
            .record_prepare_failure("node-a", "error1".to_string())
            .unwrap();
        let participant = coordinator.get_participant("node-a").unwrap();
        assert!(matches!(participant.state, TwoPhaseState::Failed(_)));
        assert_eq!(participant.error, Some("error1".to_string()));

        // Test record_commit_failure
        coordinator.record_prepare_success("node-b").unwrap();
        coordinator
            .record_commit_failure("node-b", "error2".to_string())
            .unwrap();
        let participant = coordinator.get_participant("node-b").unwrap();
        assert!(matches!(participant.state, TwoPhaseState::Failed(_)));
        assert_eq!(participant.error, Some("error2".to_string()));
    }

    #[test]
    fn test_record_abort() {
        let config = create_test_config();
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

    // =========================================================================
    // Already finalized tests
    // =========================================================================

    #[tokio::test]
    async fn test_prepare_after_committed() {
        let config = create_test_config();
        let mut coordinator = TwoPhaseCommit::new(
            "test-chain".to_string(),
            config,
            vec!["node-a".to_string()],
        );

        coordinator.transaction_state = TwoPhaseState::Committed;

        let result = coordinator.prepare("node-a").await;
        assert!(matches!(result, Err(TwoPhaseError::AlreadyFinalized { .. })));
    }

    #[tokio::test]
    async fn test_prepare_all_after_aborted() {
        let config = create_test_config();
        let mut coordinator = TwoPhaseCommit::new(
            "test-chain".to_string(),
            config,
            vec!["node-a".to_string()],
        );

        coordinator.transaction_state = TwoPhaseState::Aborted;

        let errors = coordinator.prepare_all().await;
        assert_eq!(errors.len(), 1);
        assert!(matches!(errors[0], TwoPhaseError::AlreadyFinalized { .. }));
    }

    // =========================================================================
    // Mock network client tests
    // =========================================================================

    #[test]
    fn test_mock_network_client_setup() {
        let mock = MockNetworkClient::new();

        mock.fail_prepare("node-a", "error1");
        mock.fail_commit("node-b", "error2");
        mock.fail_abort("node-c", "error3");
        mock.set_delay(100);

        assert!(mock.prepare_failures.lock().unwrap().contains_key("node-a"));
        assert!(mock.commit_failures.lock().unwrap().contains_key("node-b"));
        assert!(mock.abort_failures.lock().unwrap().contains_key("node-c"));
        assert_eq!(mock.delay_ms.load(std::sync::atomic::Ordering::SeqCst), 100);
    }

    // =========================================================================
    // Edge case tests
    // =========================================================================

    #[test]
    fn test_empty_participants() {
        let config = create_test_config();
        let coordinator = TwoPhaseCommit::new(
            "test-chain".to_string(),
            config,
            vec![],
        );

        assert_eq!(coordinator.participant_count(), 0);
        assert!(coordinator.all_prepared()); // vacuously true
        assert!(coordinator.all_committed()); // vacuously true
        assert!(!coordinator.any_failed());
    }

    #[tokio::test]
    async fn test_prepare_all_empty() {
        let config = create_test_config();
        let mut coordinator = TwoPhaseCommit::new(
            "test-chain".to_string(),
            config,
            vec![],
        );

        let errors = coordinator.prepare_all().await;
        assert!(errors.is_empty());
        assert_eq!(*coordinator.transaction_state(), TwoPhaseState::Prepared);
    }

    #[tokio::test]
    async fn test_commit_all_empty() {
        let config = create_test_config();
        let mut coordinator = TwoPhaseCommit::new(
            "test-chain".to_string(),
            config,
            vec![],
        );

        let errors = coordinator.commit_all().await;
        assert!(errors.is_empty());
        assert_eq!(*coordinator.transaction_state(), TwoPhaseState::Committed);
    }
}
