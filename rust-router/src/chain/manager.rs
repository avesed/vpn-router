//! ChainManager - Multi-hop chain routing management for Phase 6
//!
//! This module implements chain lifecycle management with Two-Phase
//! Commit (2PC) protocol for distributed activation across nodes.
//!
//! # Phase 6 Implementation Status
//!
//! - [ ] 6.6.1 ChainManager structure
//! - [ ] 6.6.1 Chain validation
//! - [ ] 6.6.1 Remote egress validation
//! - [ ] 6.6.1 2PC integration
//!
//! # Architecture
//!
//! The ChainManager coordinates:
//! - Local chain state management
//! - Validation of chain configurations
//! - 2PC protocol execution for distributed activation
//! - Integration with PeerManager for tunnel access
//! - Integration with RuleEngine for dynamic rule updates
//!
//! # Example
//!
//! ```ignore
//! use rust_router::chain::manager::ChainManager;
//!
//! let manager = ChainManager::new(
//!     "local-node".to_string(),
//!     rule_engine,
//!     peer_manager,
//! );
//!
//! // Create a chain
//! manager.create_chain(ChainConfig {
//!     tag: "my-chain".to_string(),
//!     dscp_value: 10,
//!     hops: vec![...],
//!     exit_egress: "pia-us-east".to_string(),
//!     ..Default::default()
//! }).await?;
//!
//! // Activate using 2PC
//! manager.activate_chain("my-chain").await?;
//! ```
//!
//! # References
//!
//! - Implementation Plan: `docs/PHASE6_IMPLEMENTATION_PLAN_v3.2.md` Section 6.6.1

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::ipc::{ChainConfig, ChainRole, ChainState, ChainStatus};

/// Error types for chain operations
#[derive(Debug, thiserror::Error)]
pub enum ChainError {
    /// Chain not found
    #[error("Chain not found: {0}")]
    NotFound(String),

    /// Chain already exists
    #[error("Chain already exists: {0}")]
    AlreadyExists(String),

    /// Chain is already activating
    #[error("Chain is already activating: {0}")]
    AlreadyActivating(String),

    /// Chain is already active
    #[error("Chain is already active: {0}")]
    AlreadyActive(String),

    /// Invalid DSCP value
    #[error("Invalid DSCP value: {0} (must be 1-63)")]
    InvalidDscp(u8),

    /// DSCP conflict
    #[error("DSCP value {0} is already in use")]
    DscpConflict(u8),

    /// DSCP values exhausted
    #[error("No available DSCP values")]
    DscpExhausted,

    /// Chain has no hops
    #[error("Chain must have at least one hop")]
    NoHops,

    /// Chain has no terminal node
    #[error("Chain must have a terminal node")]
    NoTerminal,

    /// Chain has too many hops
    #[error("Chain has too many hops: {0} (max 10)")]
    TooManyHops(usize),

    /// "direct" egress not allowed
    #[error("Cannot use 'direct' as exit egress in a chain")]
    DirectNotAllowed,

    /// SOCKS-based egress not allowed (V2Ray, WARP MASQUE)
    #[error("SOCKS-based egress cannot be used as terminal egress: {0}")]
    SocksEgressNotAllowed(String),

    /// Egress not found on terminal node
    #[error("Egress not found on terminal node: {0}")]
    EgressNotFound(String),

    /// Peer not found
    #[error("Peer not found: {0}")]
    PeerNotFound(String),

    /// Peer not connected
    #[error("Peer not connected: {0}")]
    PeerNotConnected(String),

    /// Not in chain
    #[error("Local node is not in this chain")]
    NotInChain,

    /// Prepare failed
    #[error("PREPARE failed on node {0}: {1}")]
    PrepareFailed(String, String),

    /// Commit failed
    #[error("COMMIT failed on node {0}: {1}")]
    CommitFailed(String, String),

    /// Remote validation failed
    #[error("Remote validation failed: {0}")]
    RemoteValidationFailed(String),

    /// Rule engine error
    #[error("Rule engine error: {0}")]
    RuleEngine(String),

    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),
}

/// Internal chain state tracking
#[allow(dead_code)]
struct ChainStateInternal {
    /// Chain configuration
    config: ChainConfig,
    /// Current chain state
    state: ChainState,
    /// Local node's role in the chain
    my_role: Option<ChainRole>,
    /// Last error message
    last_error: Option<String>,
}

/// ChainManager handles multi-hop chain routing
///
/// TODO(Phase 6.6): Implement full chain management with 2PC
#[allow(dead_code)]
pub struct ChainManager {
    /// Map of chain tag to chain state
    chains: RwLock<HashMap<String, ChainStateInternal>>,
    /// Local node tag for identification
    local_node_tag: String,
    /// DSCP allocator
    dscp_allocator: Arc<crate::chain::allocator::DscpAllocator>,
}

impl ChainManager {
    /// Create a new ChainManager
    ///
    /// # Arguments
    ///
    /// * `local_node_tag` - Tag identifying the local node
    ///
    /// # Example
    ///
    /// ```ignore
    /// let manager = ChainManager::new("my-node".to_string());
    /// ```
    pub fn new(local_node_tag: String) -> Self {
        Self {
            chains: RwLock::new(HashMap::new()),
            local_node_tag,
            dscp_allocator: Arc::new(crate::chain::allocator::DscpAllocator::new()),
        }
    }

    /// Get the local node tag
    pub fn local_node_tag(&self) -> &str {
        &self.local_node_tag
    }

    /// Create a new chain
    ///
    /// # Arguments
    ///
    /// * `config` - Chain configuration
    ///
    /// TODO(Phase 6.6): Implement chain creation with validation
    pub async fn create_chain(&self, _config: ChainConfig) -> Result<(), ChainError> {
        unimplemented!("Phase 6.6: create_chain not yet implemented")
    }

    /// Remove a chain
    ///
    /// # Arguments
    ///
    /// * `tag` - Chain tag to remove
    ///
    /// TODO(Phase 6.6): Implement chain removal
    pub async fn remove_chain(&self, _tag: &str) -> Result<(), ChainError> {
        unimplemented!("Phase 6.6: remove_chain not yet implemented")
    }

    /// Activate a chain using Two-Phase Commit
    ///
    /// This method executes the full 2PC protocol:
    /// 1. PREPARE all nodes in the chain
    /// 2. If all PREPARE succeed: COMMIT all nodes
    /// 3. If any PREPARE fails: ABORT all nodes
    ///
    /// # Arguments
    ///
    /// * `tag` - Chain tag to activate
    ///
    /// TODO(Phase 6.6): Implement 2PC chain activation
    pub async fn activate_chain(&self, _tag: &str) -> Result<(), ChainError> {
        unimplemented!("Phase 6.6: activate_chain not yet implemented")
    }

    /// Deactivate a chain
    ///
    /// # Arguments
    ///
    /// * `tag` - Chain tag to deactivate
    ///
    /// TODO(Phase 6.6): Implement chain deactivation
    pub async fn deactivate_chain(&self, _tag: &str) -> Result<(), ChainError> {
        unimplemented!("Phase 6.6: deactivate_chain not yet implemented")
    }

    /// Get status of a specific chain
    ///
    /// # Arguments
    ///
    /// * `tag` - Chain tag
    ///
    /// # Returns
    ///
    /// Chain status information
    pub fn get_chain_status(&self, tag: &str) -> Option<ChainStatus> {
        let chains = self.chains.read().ok()?;
        let chain = chains.get(tag)?;

        Some(ChainStatus {
            tag: tag.to_string(),
            state: chain.state.clone(),
            dscp_value: chain.config.dscp_value,
            my_role: chain.my_role.clone(),
            hop_status: Vec::new(), // TODO: Populate from peer status
            active_connections: 0,
            last_error: chain.last_error.clone(),
        })
    }

    /// List all chains
    ///
    /// # Returns
    ///
    /// List of chain status information
    pub fn list_chains(&self) -> Vec<ChainStatus> {
        let chains = match self.chains.read() {
            Ok(guard) => guard,
            Err(_) => return Vec::new(),
        };

        chains
            .iter()
            .map(|(tag, chain)| ChainStatus {
                tag: tag.clone(),
                state: chain.state.clone(),
                dscp_value: chain.config.dscp_value,
                my_role: chain.my_role.clone(),
                hop_status: Vec::new(),
                active_connections: 0,
                last_error: chain.last_error.clone(),
            })
            .collect()
    }

    /// Get local node's role in a chain
    ///
    /// # Arguments
    ///
    /// * `tag` - Chain tag
    ///
    /// # Returns
    ///
    /// The local node's role (Entry, Relay, or Terminal)
    pub fn get_chain_role(&self, tag: &str) -> Option<ChainRole> {
        let chains = self.chains.read().ok()?;
        let chain = chains.get(tag)?;
        chain.my_role.clone()
    }

    /// Handle incoming PREPARE request from another node
    ///
    /// # Arguments
    ///
    /// * `chain_tag` - Chain tag
    /// * `config` - Chain configuration to validate
    /// * `source_node` - Node that initiated the request
    ///
    /// TODO(Phase 6.6): Implement PREPARE handler
    pub async fn handle_prepare_request(
        &self,
        _chain_tag: &str,
        _config: ChainConfig,
        _source_node: &str,
    ) -> Result<(), ChainError> {
        unimplemented!("Phase 6.6: handle_prepare_request not yet implemented")
    }

    /// Handle incoming COMMIT request from another node
    ///
    /// # Arguments
    ///
    /// * `chain_tag` - Chain tag
    /// * `source_node` - Node that initiated the request
    ///
    /// TODO(Phase 6.6): Implement COMMIT handler
    pub async fn handle_commit_request(
        &self,
        _chain_tag: &str,
        _source_node: &str,
    ) -> Result<(), ChainError> {
        unimplemented!("Phase 6.6: handle_commit_request not yet implemented")
    }

    /// Handle incoming ABORT request from another node
    ///
    /// # Arguments
    ///
    /// * `chain_tag` - Chain tag
    /// * `source_node` - Node that initiated the request
    ///
    /// TODO(Phase 6.6): Implement ABORT handler
    pub async fn handle_abort_request(
        &self,
        _chain_tag: &str,
        _source_node: &str,
    ) -> Result<(), ChainError> {
        unimplemented!("Phase 6.6: handle_abort_request not yet implemented")
    }

    /// Determine local node's role in a chain
    #[allow(dead_code)]
    fn determine_role(&self, config: &ChainConfig) -> Option<ChainRole> {
        for hop in &config.hops {
            if hop.node_tag == self.local_node_tag {
                return Some(hop.role.clone());
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chain_manager_creation() {
        let manager = ChainManager::new("test-node".to_string());
        assert_eq!(manager.local_node_tag(), "test-node");
    }

    #[test]
    fn test_list_chains_empty() {
        let manager = ChainManager::new("test-node".to_string());
        let chains = manager.list_chains();
        assert!(chains.is_empty());
    }

    #[test]
    fn test_get_chain_status_not_found() {
        let manager = ChainManager::new("test-node".to_string());
        let status = manager.get_chain_status("nonexistent");
        assert!(status.is_none());
    }

    #[test]
    fn test_get_chain_role_not_found() {
        let manager = ChainManager::new("test-node".to_string());
        let role = manager.get_chain_role("nonexistent");
        assert!(role.is_none());
    }
}
