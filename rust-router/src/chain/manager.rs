//! `ChainManager` - Multi-hop chain routing management for Phase 6
//!
//! This module implements chain lifecycle management with Two-Phase
//! Commit (2PC) protocol for distributed activation across nodes.
//!
//! # Phase 6 Implementation Status
//!
//! - [x] 6.6.1 `ChainManager` structure
//! - [x] 6.6.1 Chain validation
//! - [ ] 6.6.1 Remote egress validation
//! - [ ] 6.6.1 2PC integration
//!
//! # Architecture
//!
//! The `ChainManager` coordinates:
//! - Local chain state management
//! - Validation of chain configurations
//! - 2PC protocol execution for distributed activation
//! - Integration with `PeerManager` for tunnel access
//! - Integration with `RuleEngine` for dynamic rule updates
//!
//! # Chain Validation Rules
//!
//! 1. **Tag validation**: Must be 1-64 alphanumeric characters with hyphens/underscores
//! 2. **DSCP value**: Must be 0 (auto-allocate) or 1-63 (manual)
//! 3. **Hops count**: Must have 1-10 hops
//! 4. **Exit egress**: Cannot be "direct" (traffic would exit locally)
//! 5. **Xray relay**: Xray tunnels cannot be in relay position (DSCP lost in SOCKS5)
//! 6. **SOCKS-based egress**: `V2Ray` and WARP MASQUE cannot be terminal egress
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

use tracing::{debug, error, info, warn};

use crate::chain::allocator::{DscpAllocator, DscpAllocatorError};
use crate::chain::two_phase::{ChainNetworkClient, NoOpNetworkClient, TwoPhaseCommit, TwoPhaseError};
use crate::ipc::{ChainConfig, ChainRole, ChainState, ChainStatus, TunnelType};
use crate::peer::validation::{validate_chain_tag, validate_description};

/// Maximum number of hops allowed in a chain
pub const MAX_CHAIN_HOPS: usize = 10;

/// Minimum number of hops required in a chain (at least entry and terminal)
pub const MIN_CHAIN_HOPS: usize = 1;

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

    /// Invalid chain tag
    #[error("Invalid chain tag: {0}")]
    InvalidTag(String),

    /// Invalid description
    #[error("Invalid description: {0}")]
    InvalidDescription(String),

    /// Invalid DSCP value
    #[error("Invalid DSCP value: {0} (must be 0 for auto-allocate or 1-63 for manual)")]
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
    #[error("Chain has too many hops: {0} (max {MAX_CHAIN_HOPS})")]
    TooManyHops(usize),

    /// "direct" egress not allowed
    #[error("Cannot use 'direct' as exit egress in a chain (traffic would exit locally, not through the chain)")]
    DirectNotAllowed,

    /// SOCKS-based egress not allowed (`V2Ray`, WARP MASQUE)
    #[error("SOCKS-based egress cannot be used as terminal egress: {0}")]
    SocksEgressNotAllowed(String),

    /// Xray tunnel cannot be relay
    #[error("Xray tunnels cannot be used as relay nodes (DSCP headers are lost in SOCKS5 proxy)")]
    XrayRelayNotAllowed,

    /// Invalid hop role sequence
    #[error("Invalid hop role sequence: {0}")]
    InvalidHopSequence(String),

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

    /// Cannot remove active chain
    #[error("Cannot remove chain in state '{0}': must be inactive or error")]
    CannotRemoveActiveChain(String),

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

    /// Lock acquisition failed
    #[error("Failed to acquire lock: {0}")]
    LockError(String),

    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),
}

impl From<DscpAllocatorError> for ChainError {
    fn from(err: DscpAllocatorError) -> Self {
        match err {
            DscpAllocatorError::Exhausted => ChainError::DscpExhausted,
            DscpAllocatorError::AlreadyAllocated(v) => ChainError::DscpConflict(v),
            DscpAllocatorError::Reserved(v) => ChainError::DscpConflict(v),
            DscpAllocatorError::OutOfRange(v) => ChainError::InvalidDscp(v),
        }
    }
}

impl From<TwoPhaseError> for ChainError {
    fn from(err: TwoPhaseError) -> Self {
        match err {
            TwoPhaseError::PrepareFailed { node, reason } => ChainError::PrepareFailed(node, reason),
            TwoPhaseError::CommitFailed { node, reason } => ChainError::CommitFailed(node, reason),
            TwoPhaseError::Timeout { node, phase } => {
                ChainError::PrepareFailed(node, format!("Timeout during {phase}"))
            }
            TwoPhaseError::NotAllPrepared => {
                ChainError::Internal("Cannot commit: not all participants prepared".to_string())
            }
            TwoPhaseError::ParticipantNotFound(node) => ChainError::PeerNotFound(node),
            _ => ChainError::Internal(err.to_string()),
        }
    }
}

/// Callback trait for local DSCP routing operations
///
/// This trait is called during chain activation/deactivation to set up
/// or tear down local DSCP routing rules.
pub trait DscpRoutingCallback: Send + Sync {
    /// Set up DSCP routing for a chain
    ///
    /// Called during chain activation to set up local routing rules.
    /// For entry nodes, this marks outgoing packets with DSCP.
    /// For relay nodes, this forwards packets based on DSCP.
    /// For terminal nodes, this removes DSCP and applies exit egress.
    fn setup_routing(
        &self,
        chain_tag: &str,
        dscp_value: u8,
        role: ChainRole,
        exit_egress: Option<&str>,
    ) -> Result<(), String>;

    /// Tear down DSCP routing for a chain
    ///
    /// Called during chain deactivation to remove local routing rules.
    fn teardown_routing(&self, chain_tag: &str) -> Result<(), String>;
}

/// No-op routing callback for testing
pub struct NoOpRoutingCallback;

impl DscpRoutingCallback for NoOpRoutingCallback {
    fn setup_routing(
        &self,
        _chain_tag: &str,
        _dscp_value: u8,
        _role: ChainRole,
        _exit_egress: Option<&str>,
    ) -> Result<(), String> {
        Ok(())
    }

    fn teardown_routing(&self, _chain_tag: &str) -> Result<(), String> {
        Ok(())
    }
}

/// Callback trait for checking peer connectivity
///
/// Used during chain validation to verify all peer nodes are connected.
pub trait PeerConnectivityCallback: Send + Sync {
    /// Check if a peer node is connected
    fn is_peer_connected(&self, node_tag: &str) -> bool;
}

/// No-op peer connectivity callback (always returns true)
pub struct AlwaysConnectedCallback;

impl PeerConnectivityCallback for AlwaysConnectedCallback {
    fn is_peer_connected(&self, _node_tag: &str) -> bool {
        true
    }
}

/// Internal chain state tracking
#[derive(Debug, Clone)]
struct ChainStateInternal {
    /// Chain configuration
    config: ChainConfig,
    /// Current chain state
    state: ChainState,
    /// Local node's role in the chain
    my_role: Option<ChainRole>,
    /// Allocated DSCP value (may differ from config if auto-allocated)
    allocated_dscp: u8,
    /// Last error message
    last_error: Option<String>,
    /// Creation timestamp (Unix epoch seconds)
    created_at: u64,
}

/// `ChainManager` handles multi-hop chain routing
///
/// Manages the lifecycle of multi-hop routing chains, including:
/// - Chain creation with validation
/// - DSCP value allocation
/// - Role determination for local node
/// - Chain removal with resource cleanup
///
/// # Thread Safety
///
/// `ChainManager` uses `RwLock` for thread-safe access to chain state.
/// The DSCP allocator is shared via `Arc` for concurrent allocation.
///
/// # Lock Order (IMPORTANT: Follow this order to prevent deadlocks)
///
/// 1. `self.chains` - Main chain state map
/// 2. `self.peer_callback` - Peer connectivity callback
/// 3. `self.routing_callback` - DSCP routing callback
/// 4. `self.network_client` - 2PC network client
///
/// CRITICAL: Callback implementations (`DscpRoutingCallback`, `PeerConnectivityCallback`)
/// MUST NOT acquire any `ChainManager` locks. Deadlock WILL occur if they do.
///
/// When acquiring multiple locks:
/// - Always acquire locks in the order listed above
/// - Never hold a lock while calling into external code that might acquire locks
/// - Release `chains` lock before invoking callbacks
pub struct ChainManager {
    /// Map of chain tag to chain state
    chains: RwLock<HashMap<String, ChainStateInternal>>,
    /// Local node tag for identification
    local_node_tag: String,
    /// DSCP allocator (shared)
    dscp_allocator: Arc<DscpAllocator>,
    /// Network client for 2PC operations
    network_client: RwLock<Option<Arc<dyn ChainNetworkClient>>>,
    /// DSCP routing callback
    routing_callback: RwLock<Option<Arc<dyn DscpRoutingCallback>>>,
    /// Peer connectivity callback
    peer_callback: RwLock<Option<Arc<dyn PeerConnectivityCallback>>>,
}

impl ChainManager {
    /// Create a new `ChainManager`
    ///
    /// # Arguments
    ///
    /// * `local_node_tag` - Tag identifying the local node
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::chain::manager::ChainManager;
    ///
    /// let manager = ChainManager::new("my-node".to_string());
    /// assert_eq!(manager.local_node_tag(), "my-node");
    /// ```
    pub fn new(local_node_tag: String) -> Self {
        Self {
            chains: RwLock::new(HashMap::new()),
            local_node_tag,
            dscp_allocator: Arc::new(DscpAllocator::new()),
            network_client: RwLock::new(None),
            routing_callback: RwLock::new(None),
            peer_callback: RwLock::new(None),
        }
    }

    /// Create a `ChainManager` with a custom DSCP allocator
    ///
    /// This is primarily useful for testing or sharing allocators
    /// across multiple managers.
    ///
    /// # Arguments
    ///
    /// * `local_node_tag` - Tag identifying the local node
    /// * `dscp_allocator` - Shared DSCP allocator
    pub fn with_allocator(local_node_tag: String, dscp_allocator: Arc<DscpAllocator>) -> Self {
        Self {
            chains: RwLock::new(HashMap::new()),
            local_node_tag,
            dscp_allocator,
            network_client: RwLock::new(None),
            routing_callback: RwLock::new(None),
            peer_callback: RwLock::new(None),
        }
    }

    /// Set the network client for 2PC operations
    pub fn set_network_client(&self, client: Arc<dyn ChainNetworkClient>) {
        if let Ok(mut guard) = self.network_client.write() {
            *guard = Some(client);
        }
    }

    /// Set the DSCP routing callback
    pub fn set_routing_callback(&self, callback: Arc<dyn DscpRoutingCallback>) {
        if let Ok(mut guard) = self.routing_callback.write() {
            *guard = Some(callback);
        }
    }

    /// Set the peer connectivity callback
    pub fn set_peer_callback(&self, callback: Arc<dyn PeerConnectivityCallback>) {
        if let Ok(mut guard) = self.peer_callback.write() {
            *guard = Some(callback);
        }
    }

    /// Get the local node tag
    pub fn local_node_tag(&self) -> &str {
        &self.local_node_tag
    }

    /// Get a reference to the DSCP allocator
    pub fn dscp_allocator(&self) -> &Arc<DscpAllocator> {
        &self.dscp_allocator
    }

    /// Create a new chain
    ///
    /// Creates a chain with the given configuration after validation.
    /// If `dscp_value` is 0, a DSCP value will be auto-allocated.
    ///
    /// # Arguments
    ///
    /// * `config` - Chain configuration
    ///
    /// # Returns
    ///
    /// The allocated DSCP value on success.
    ///
    /// # Errors
    ///
    /// - `AlreadyExists` - Chain with this tag already exists
    /// - `InvalidTag` - Chain tag is invalid
    /// - `InvalidDscp` - DSCP value is out of range (must be 0 or 1-63)
    /// - `NoHops` - Chain has no hops
    /// - `TooManyHops` - Chain exceeds maximum hop count
    /// - `DirectNotAllowed` - Exit egress is "direct"
    /// - `XrayRelayNotAllowed` - Xray tunnel used as relay
    /// - `DscpExhausted` - No available DSCP values for auto-allocation
    /// - `DscpConflict` - Requested DSCP value already in use
    ///
    /// # Example
    ///
    /// ```ignore
    /// use rust_router::chain::manager::ChainManager;
    /// use rust_router::ipc::{ChainConfig, ChainHop, ChainRole, TunnelType};
    ///
    /// let manager = ChainManager::new("local-node".to_string());
    ///
    /// let config = ChainConfig {
    ///     tag: "my-chain".to_string(),
    ///     description: "Test chain".to_string(),
    ///     dscp_value: 0, // Auto-allocate
    ///     hops: vec![
    ///         ChainHop {
    ///             node_tag: "local-node".to_string(),
    ///             role: ChainRole::Entry,
    ///             tunnel_type: TunnelType::WireGuard,
    ///         },
    ///         ChainHop {
    ///             node_tag: "remote-node".to_string(),
    ///             role: ChainRole::Terminal,
    ///             tunnel_type: TunnelType::WireGuard,
    ///         },
    ///     ],
    ///     rules: vec![],
    ///     exit_egress: "pia-us-east".to_string(),
    ///     allow_transitive: false,
    /// };
    ///
    /// let dscp = manager.create_chain(config).await?;
    /// assert!(dscp >= 1 && dscp <= 63);
    /// ```
    #[must_use = "The allocated DSCP value should be used or the chain creation result should be checked"]
    pub async fn create_chain(&self, config: ChainConfig) -> Result<u8, ChainError> {
        // Step 1: Validate the chain configuration
        self.validate_chain(&config)?;

        // Step 2: Check if chain already exists
        {
            let chains = self
                .chains
                .read()
                .map_err(|e| ChainError::LockError(e.to_string()))?;
            if chains.contains_key(&config.tag) {
                return Err(ChainError::AlreadyExists(config.tag.clone()));
            }
        }

        // Step 3: Allocate DSCP value
        let allocated_dscp = if config.dscp_value == 0 {
            // Auto-allocate
            self.dscp_allocator.allocate()?
        } else {
            // Manual allocation - reserve the specific value
            self.dscp_allocator.reserve(config.dscp_value)?;
            config.dscp_value
        };

        // Step 4: Determine local node's role
        let my_role = self.determine_role(&config);

        // Step 5: Create internal state and store
        let internal_state = ChainStateInternal {
            config: config.clone(),
            state: ChainState::Inactive,
            my_role,
            allocated_dscp,
            last_error: None,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        };

        // Step 6: Insert into chains map
        // Note: We need to handle the case where another thread inserted the same tag
        // between our check and insert (TOCTOU). If that happens, release the DSCP.
        {
            let mut chains = self
                .chains
                .write()
                .map_err(|e| ChainError::LockError(e.to_string()))?;

            if chains.contains_key(&config.tag) {
                // Race condition: another thread inserted first
                // Release the DSCP we allocated
                self.dscp_allocator.release(allocated_dscp);
                return Err(ChainError::AlreadyExists(config.tag));
            }

            chains.insert(config.tag, internal_state);
        }

        Ok(allocated_dscp)
    }

    /// Remove a chain
    ///
    /// Removes a chain and releases its allocated DSCP value.
    /// The chain must be in `Inactive` or `Error` state.
    ///
    /// # Arguments
    ///
    /// * `tag` - Chain tag to remove
    ///
    /// # Errors
    ///
    /// - `NotFound` - Chain does not exist
    /// - `CannotRemoveActiveChain` - Chain is active or activating
    ///
    /// # Example
    ///
    /// ```ignore
    /// manager.remove_chain("my-chain").await?;
    /// ```
    pub async fn remove_chain(&self, tag: &str) -> Result<(), ChainError> {
        // Step 1: Check chain exists and get state info
        let (allocated_dscp, state) = {
            let chains = self
                .chains
                .read()
                .map_err(|e| ChainError::LockError(e.to_string()))?;

            let chain = chains
                .get(tag)
                .ok_or_else(|| ChainError::NotFound(tag.to_string()))?;

            (chain.allocated_dscp, chain.state)
        };

        // Step 2: Verify chain is not active or activating
        match state {
            ChainState::Inactive | ChainState::Error => {
                // OK to remove
            }
            ChainState::Active => {
                return Err(ChainError::CannotRemoveActiveChain("active".to_string()));
            }
            ChainState::Activating => {
                return Err(ChainError::CannotRemoveActiveChain("activating".to_string()));
            }
        }

        // Step 3: Remove from chains map
        {
            let mut chains = self
                .chains
                .write()
                .map_err(|e| ChainError::LockError(e.to_string()))?;

            // Re-check state in case it changed
            if let Some(chain) = chains.get(tag) {
                match chain.state {
                    ChainState::Inactive | ChainState::Error => {
                        // Still OK
                    }
                    ChainState::Active => {
                        return Err(ChainError::CannotRemoveActiveChain("active".to_string()));
                    }
                    ChainState::Activating => {
                        return Err(ChainError::CannotRemoveActiveChain(
                            "activating".to_string(),
                        ));
                    }
                }
            }

            chains.remove(tag);
        }

        // Step 4: Release the DSCP value
        self.dscp_allocator.release(allocated_dscp);

        Ok(())
    }

    /// Update an existing chain configuration
    ///
    /// Updates a chain configuration. The chain must be in Inactive state
    /// to be updated. DSCP value cannot be changed via update.
    ///
    /// # Arguments
    ///
    /// * `tag` - Chain tag to update
    /// * `config` - New chain configuration (tag and `dscp_value` are preserved from original)
    ///
    /// # Errors
    ///
    /// - `NotFound` - Chain does not exist
    /// - `AlreadyActive` - Chain is currently active
    /// - `AlreadyActivating` - Chain is currently activating
    /// - Validation errors if new configuration is invalid
    ///
    /// # Example
    ///
    /// ```ignore
    /// manager.update_chain("my-chain", updated_config).await?;
    /// ```
    pub async fn update_chain(&self, tag: &str, config: ChainConfig) -> Result<(), ChainError> {
        // Step 1: Validate the new configuration
        self.validate_chain(&config)?;

        // Step 2: Get current chain and check state
        let (allocated_dscp, my_role) = {
            let chains = self
                .chains
                .read()
                .map_err(|e| ChainError::LockError(e.to_string()))?;

            let chain = chains
                .get(tag)
                .ok_or_else(|| ChainError::NotFound(tag.to_string()))?;

            // Can only update inactive chains
            match chain.state {
                ChainState::Inactive | ChainState::Error => {
                    // OK to update
                }
                ChainState::Active => {
                    return Err(ChainError::AlreadyActive(tag.to_string()));
                }
                ChainState::Activating => {
                    return Err(ChainError::AlreadyActivating(tag.to_string()));
                }
            }

            (chain.allocated_dscp, chain.my_role)
        };

        // Step 3: Update the chain in-place
        {
            let mut chains = self
                .chains
                .write()
                .map_err(|e| ChainError::LockError(e.to_string()))?;

            let chain = chains
                .get_mut(tag)
                .ok_or_else(|| ChainError::NotFound(tag.to_string()))?;

            // Re-check state (TOCTOU prevention)
            match chain.state {
                ChainState::Inactive | ChainState::Error => {
                    // Still OK
                }
                ChainState::Active => {
                    return Err(ChainError::AlreadyActive(tag.to_string()));
                }
                ChainState::Activating => {
                    return Err(ChainError::AlreadyActivating(tag.to_string()));
                }
            }

            // Update the chain, preserving DSCP value and state
            chain.config = ChainConfig {
                tag: tag.to_string(),
                description: config.description,
                dscp_value: allocated_dscp, // Preserve original DSCP
                hops: config.hops,
                rules: config.rules,
                exit_egress: config.exit_egress,
                allow_transitive: config.allow_transitive,
            };
            chain.my_role = my_role;
            // Keep existing state and last_error
        }

        info!(tag = %tag, "Updated chain configuration");
        Ok(())
    }

    /// Validate a chain configuration
    ///
    /// Performs comprehensive validation of chain configuration including:
    /// - Tag format validation
    /// - Description length check
    /// - DSCP value range (0 for auto, 1-63 for manual)
    /// - Hop count (1-10)
    /// - Exit egress validation (cannot be "direct")
    /// - Xray relay validation (Xray cannot be relay)
    /// - Role sequence validation
    ///
    /// # Arguments
    ///
    /// * `config` - Chain configuration to validate
    ///
    /// # Errors
    ///
    /// Returns appropriate `ChainError` variant for validation failures.
    fn validate_chain(&self, config: &ChainConfig) -> Result<(), ChainError> {
        // Validate tag
        validate_chain_tag(&config.tag)
            .map_err(|e| ChainError::InvalidTag(e.to_string()))?;

        // Validate description
        validate_description(&config.description)
            .map_err(|e| ChainError::InvalidDescription(e.to_string()))?;

        // Validate DSCP value (0 = auto-allocate, 1-63 = manual)
        if config.dscp_value > 63 {
            return Err(ChainError::InvalidDscp(config.dscp_value));
        }

        // Validate hop count
        if config.hops.is_empty() {
            return Err(ChainError::NoHops);
        }
        if config.hops.len() > MAX_CHAIN_HOPS {
            return Err(ChainError::TooManyHops(config.hops.len()));
        }

        // Validate exit egress is not "direct"
        if config.exit_egress.eq_ignore_ascii_case("direct") {
            return Err(ChainError::DirectNotAllowed);
        }

        // Validate Xray tunnels are not in relay position
        // DSCP headers are lost when proxied through SOCKS5
        for hop in &config.hops {
            if hop.role == ChainRole::Relay && hop.tunnel_type == TunnelType::Xray {
                return Err(ChainError::XrayRelayNotAllowed);
            }
        }

        // Validate role sequence
        self.validate_hop_roles(config)?;

        Ok(())
    }

    /// Validate the role sequence in chain hops
    ///
    /// Ensures:
    /// - First hop has a valid entry role or is the local node
    /// - Last hop has Terminal role
    /// - Middle hops have Relay role
    fn validate_hop_roles(&self, config: &ChainConfig) -> Result<(), ChainError> {
        if config.hops.is_empty() {
            return Err(ChainError::NoHops);
        }

        // Check that there is exactly one terminal node (the last one)
        let terminal_count = config.hops.iter().filter(|h| h.role == ChainRole::Terminal).count();
        if terminal_count == 0 {
            return Err(ChainError::NoTerminal);
        }
        if terminal_count > 1 {
            return Err(ChainError::InvalidHopSequence(
                "Multiple terminal nodes found; only the last hop should be terminal".to_string(),
            ));
        }

        // The last hop must be terminal
        if let Some(last) = config.hops.last() {
            if last.role != ChainRole::Terminal {
                return Err(ChainError::InvalidHopSequence(
                    format!("Last hop '{}' must have Terminal role, got {:?}", last.node_tag, last.role),
                ));
            }
        }

        // For chains with more than one hop, first should be Entry
        if config.hops.len() > 1 {
            if let Some(first) = config.hops.first() {
                if first.role != ChainRole::Entry {
                    return Err(ChainError::InvalidHopSequence(
                        format!("First hop '{}' must have Entry role, got {:?}", first.node_tag, first.role),
                    ));
                }
            }

            // Middle hops (if any) should be Relay
            for hop in config.hops.iter().skip(1).take(config.hops.len() - 2) {
                if hop.role != ChainRole::Relay {
                    return Err(ChainError::InvalidHopSequence(
                        format!("Middle hop '{}' must have Relay role, got {:?}", hop.node_tag, hop.role),
                    ));
                }
            }
        }

        Ok(())
    }

    /// Activate a chain using Two-Phase Commit
    ///
    /// This method executes the full 2PC protocol:
    /// 1. Transition to Activating state
    /// 2. PREPARE all remote nodes in the chain
    /// 3. If all PREPARE succeed: COMMIT all nodes
    /// 4. If any PREPARE fails: ABORT all nodes
    /// 5. Set up local DSCP routing
    /// 6. Transition to Active or Error state
    ///
    /// # Arguments
    ///
    /// * `tag` - Chain tag to activate
    ///
    /// # Errors
    ///
    /// - `NotFound` - Chain does not exist
    /// - `AlreadyActive` - Chain is already active
    /// - `AlreadyActivating` - Chain is already activating
    /// - `PeerNotConnected` - A peer node is not connected
    /// - `PrepareFailed` - 2PC PREPARE phase failed
    /// - `CommitFailed` - 2PC COMMIT phase failed
    pub async fn activate_chain(&self, tag: &str) -> Result<(), ChainError> {
        // Step 1: Get chain info and validate state
        let (config, allocated_dscp, participant_tags, my_role) = {
            let chains = self
                .chains
                .read()
                .map_err(|e| ChainError::LockError(e.to_string()))?;

            let chain = chains
                .get(tag)
                .ok_or_else(|| ChainError::NotFound(tag.to_string()))?;

            // Validate current state
            match chain.state {
                ChainState::Inactive => {}
                ChainState::Active => return Err(ChainError::AlreadyActive(tag.to_string())),
                ChainState::Activating => return Err(ChainError::AlreadyActivating(tag.to_string())),
                ChainState::Error => {
                    // Can retry from error state
                }
            }

            // Check peer connectivity using callback
            if let Ok(peer_callback_guard) = self.peer_callback.read() {
                if let Some(callback) = peer_callback_guard.as_ref() {
                    for hop in &chain.config.hops {
                        if hop.node_tag != self.local_node_tag && !callback.is_peer_connected(&hop.node_tag) {
                            return Err(ChainError::PeerNotConnected(hop.node_tag.clone()));
                        }
                    }
                }
            }

            // Get participant tags (all remote nodes)
            let participant_tags: Vec<String> = chain
                .config
                .hops
                .iter()
                .filter(|hop| hop.node_tag != self.local_node_tag)
                .map(|hop| hop.node_tag.clone())
                .collect();

            (
                chain.config.clone(),
                chain.allocated_dscp,
                participant_tags,
                chain.my_role,
            )
        };

        // Step 2: Transition to Activating state
        self.update_chain_state(tag, ChainState::Activating, None)?;
        info!("Chain {} starting activation with DSCP {}", tag, allocated_dscp);

        // Step 3: Create 2PC coordinator
        let network_client = self
            .network_client
            .read()
            .ok()
            .and_then(|guard| guard.clone())
            .unwrap_or_else(|| Arc::new(NoOpNetworkClient));

        // Update config with allocated DSCP
        let mut final_config = config.clone();
        final_config.dscp_value = allocated_dscp;

        let mut coordinator =
            TwoPhaseCommit::new(tag.to_string(), final_config.clone(), participant_tags)
                .with_network_client(network_client);

        // Step 4: Execute 2PC
        let result = self.execute_2pc(&mut coordinator, tag).await;

        // Step 5: Handle result and set up routing
        match result {
            Ok(()) => {
                // Set up local DSCP routing
                if let Err(e) = self.setup_local_routing(tag, &final_config, my_role) {
                    error!("Failed to set up local routing for chain {}: {}", tag, e);
                    // Abort since routing failed
                    coordinator.abort_all().await;
                    self.update_chain_state(tag, ChainState::Error, Some(e.clone()))?;
                    return Err(ChainError::RuleEngine(e));
                }

                self.update_chain_state(tag, ChainState::Active, None)?;
                info!("Chain {} activated successfully", tag);
                Ok(())
            }
            Err(e) => {
                let error_msg = e.to_string();
                error!("Chain {} activation failed: {}", tag, error_msg);
                self.update_chain_state(tag, ChainState::Error, Some(error_msg))?;
                Err(e)
            }
        }
    }

    /// Execute the 2PC protocol for chain activation
    async fn execute_2pc(
        &self,
        coordinator: &mut TwoPhaseCommit,
        tag: &str,
    ) -> Result<(), ChainError> {
        // Phase 1: PREPARE all participants
        info!("Chain {} starting PREPARE phase", tag);
        let prepare_errors = coordinator.prepare_all().await;

        if !prepare_errors.is_empty() {
            // PREPARE failed - abort all
            warn!(
                "Chain {} PREPARE failed with {} errors, aborting",
                tag,
                prepare_errors.len()
            );
            for err in &prepare_errors {
                warn!("  PREPARE error: {}", err);
            }
            coordinator.abort_all().await;
            return Err(prepare_errors.into_iter().next().unwrap().into());
        }

        // Phase 2: COMMIT all participants
        info!("Chain {} starting COMMIT phase", tag);
        let commit_errors = coordinator.commit_all().await;

        if !commit_errors.is_empty() {
            // COMMIT partially failed - serious issue, some nodes may be committed
            error!(
                "Chain {} COMMIT partially failed with {} errors",
                tag,
                commit_errors.len()
            );
            for err in &commit_errors {
                error!("  COMMIT error: {}", err);
            }
            return Err(commit_errors.into_iter().next().unwrap().into());
        }

        info!("Chain {} 2PC completed successfully", tag);
        Ok(())
    }

    /// Set up local DSCP routing for a chain
    fn setup_local_routing(
        &self,
        tag: &str,
        config: &ChainConfig,
        my_role: Option<ChainRole>,
    ) -> Result<(), String> {
        if let Ok(routing_callback_guard) = self.routing_callback.read() {
            if let Some(callback) = routing_callback_guard.as_ref() {
                if let Some(role) = my_role {
                    let exit_egress = if role == ChainRole::Terminal {
                        Some(config.exit_egress.as_str())
                    } else {
                        None
                    };

                    debug!(
                        "Setting up DSCP routing for chain {} with role {:?}, DSCP {}",
                        tag, role, config.dscp_value
                    );
                    callback.setup_routing(tag, config.dscp_value, role, exit_egress)?;
                }
            }
        }
        Ok(())
    }

    /// Tear down local DSCP routing for a chain
    fn teardown_local_routing(&self, tag: &str) -> Result<(), String> {
        if let Ok(routing_callback_guard) = self.routing_callback.read() {
            if let Some(callback) = routing_callback_guard.as_ref() {
                debug!("Tearing down DSCP routing for chain {}", tag);
                callback.teardown_routing(tag)?;
            }
        }
        Ok(())
    }

    /// Deactivate a chain
    ///
    /// Transitions the chain from Active or Error state to Inactive.
    /// Cleans up local DSCP routing rules.
    ///
    /// # Arguments
    ///
    /// * `tag` - Chain tag to deactivate
    ///
    /// # Errors
    ///
    /// - `NotFound` - Chain does not exist
    /// - `CannotRemoveActiveChain` - Chain is in Activating state (cannot interrupt)
    pub async fn deactivate_chain(&self, tag: &str) -> Result<(), ChainError> {
        // Step 1: Get chain state and validate
        let current_state = {
            let chains = self
                .chains
                .read()
                .map_err(|e| ChainError::LockError(e.to_string()))?;

            let chain = chains
                .get(tag)
                .ok_or_else(|| ChainError::NotFound(tag.to_string()))?;

            chain.state
        };

        // Step 2: Validate state transition
        match current_state {
            ChainState::Active | ChainState::Error => {
                // OK to deactivate
            }
            ChainState::Activating => {
                // Cannot interrupt activation (would race with 2PC)
                return Err(ChainError::CannotRemoveActiveChain("activating".to_string()));
            }
            ChainState::Inactive => {
                // Already inactive - no-op
                debug!("Chain {} already inactive", tag);
                return Ok(());
            }
        }

        // Step 3: Tear down local routing (best-effort)
        if let Err(e) = self.teardown_local_routing(tag) {
            warn!("Failed to tear down local routing for chain {}: {}", tag, e);
            // Continue with deactivation even if routing teardown fails
        }

        // Step 4: Transition to Inactive state
        self.update_chain_state(tag, ChainState::Inactive, None)?;
        info!("Chain {} deactivated", tag);

        Ok(())
    }

    /// Get status of a specific chain
    ///
    /// # Arguments
    ///
    /// * `tag` - Chain tag
    ///
    /// # Returns
    ///
    /// Chain status information, or `None` if chain does not exist.
    pub fn get_chain_status(&self, tag: &str) -> Option<ChainStatus> {
        let chains = self.chains.read().ok()?;
        let chain = chains.get(tag)?;

        Some(ChainStatus {
            tag: tag.to_string(),
            state: chain.state,
            dscp_value: chain.allocated_dscp,
            my_role: chain.my_role,
            hop_status: Vec::new(), // TODO(Phase 6.6.2): Populate from peer status
            active_connections: 0,
            last_error: chain.last_error.clone(),
        })
    }

    /// Get chain configuration
    ///
    /// # Arguments
    ///
    /// * `tag` - Chain tag
    ///
    /// # Returns
    ///
    /// Chain configuration, or `None` if chain does not exist.
    pub fn get_chain_config(&self, tag: &str) -> Option<ChainConfig> {
        let chains = self.chains.read().ok()?;
        let chain = chains.get(tag)?;
        Some(chain.config.clone())
    }

    /// Check if a chain exists
    ///
    /// # Arguments
    ///
    /// * `tag` - Chain tag
    ///
    /// # Returns
    ///
    /// `true` if chain exists, `false` otherwise.
    pub fn chain_exists(&self, tag: &str) -> bool {
        self.chains
            .read()
            .map(|chains| chains.contains_key(tag))
            .unwrap_or(false)
    }

    /// Get number of chains
    pub fn chain_count(&self) -> usize {
        self.chains
            .read()
            .map(|chains| chains.len())
            .unwrap_or(0)
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
                state: chain.state,
                dscp_value: chain.allocated_dscp,
                my_role: chain.my_role,
                hop_status: Vec::new(),
                active_connections: 0,
                last_error: chain.last_error.clone(),
            })
            .collect()
    }

    /// Recover orphaned chains stuck in "Activating" state
    ///
    /// This method should be called during startup to recover chains that were
    /// interrupted during activation (e.g., due to a crash or restart).
    /// Such chains are transitioned to "Error" state with an appropriate message.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let manager = ChainManager::new("my-node".to_string());
    /// // Called during application startup
    /// let recovered = manager.recover_orphaned_chains();
    /// if recovered > 0 {
    ///     log::warn!("Recovered {} orphaned chains", recovered);
    /// }
    /// ```
    ///
    /// # Returns
    ///
    /// The number of chains that were recovered (transitioned from Activating to Error).
    pub fn recover_orphaned_chains(&self) -> usize {
        let mut recovered_count = 0;

        if let Ok(mut chains) = self.chains.write() {
            for (tag, chain) in chains.iter_mut() {
                if chain.state == ChainState::Activating {
                    warn!(
                        "Recovering orphaned chain '{}' from Activating state",
                        tag
                    );
                    chain.state = ChainState::Error;
                    chain.last_error = Some(
                        "Recovery: chain was interrupted during activation".to_string(),
                    );
                    recovered_count += 1;
                }
            }
        }

        if recovered_count > 0 {
            info!(
                "Recovered {} orphaned chain(s) stuck in Activating state",
                recovered_count
            );
        }

        recovered_count
    }

    /// Update chain state
    ///
    /// Internal method to update chain state with optional error message.
    /// Used by 2PC protocol handlers and activation/deactivation methods.
    ///
    /// # Arguments
    ///
    /// * `tag` - Chain tag
    /// * `new_state` - New state to set
    /// * `error` - Optional error message (only used for Error state)
    ///
    /// # Errors
    ///
    /// Returns `NotFound` if chain does not exist.
    #[allow(dead_code)] // Used in Phase 6.6.2: 2PC integration
    pub(crate) fn update_chain_state(
        &self,
        tag: &str,
        new_state: ChainState,
        error: Option<String>,
    ) -> Result<(), ChainError> {
        let mut chains = self
            .chains
            .write()
            .map_err(|e| ChainError::LockError(e.to_string()))?;

        let chain = chains
            .get_mut(tag)
            .ok_or_else(|| ChainError::NotFound(tag.to_string()))?;

        chain.state = new_state;
        chain.last_error = error;

        Ok(())
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
        chain.my_role
    }

    /// Handle incoming PREPARE request from another node
    ///
    /// This is called when another node (the coordinator) sends a PREPARE
    /// request as part of the 2PC protocol. This node validates the chain
    /// configuration and stores it in a pending state.
    ///
    /// # Arguments
    ///
    /// * `chain_tag` - Chain tag
    /// * `config` - Chain configuration to validate
    /// * `source_node` - Node that initiated the request
    ///
    /// # Returns
    ///
    /// Ok if this node is prepared to participate in the chain,
    /// Err if validation fails.
    pub async fn handle_prepare_request(
        &self,
        chain_tag: &str,
        config: ChainConfig,
        source_node: &str,
    ) -> Result<(), ChainError> {
        debug!(
            "Handling PREPARE request for chain {} from {}",
            chain_tag, source_node
        );

        // Step 1: Validate we are part of this chain
        let our_hop = config
            .hops
            .iter()
            .find(|hop| hop.node_tag == self.local_node_tag);

        if our_hop.is_none() {
            return Err(ChainError::NotInChain);
        }

        // Step 2: Validate the chain configuration
        self.validate_chain(&config)?;

        // Step 3: Validate tag and DSCP value
        if config.tag != chain_tag {
            return Err(ChainError::InvalidTag(chain_tag.to_string()));
        }

        if config.dscp_value == 0 {
            return Err(ChainError::InvalidDscp(config.dscp_value));
        }

        // Step 4: Pre-check existing state and DSCP usage
        let (existing_state, existing_dscp, dscp_conflict) = {
            let chains = self
                .chains
                .read()
                .map_err(|e| ChainError::LockError(e.to_string()))?;

            let existing = chains.get(chain_tag);
            let existing_state = existing.map(|chain| chain.state);
            let existing_dscp = existing.map(|chain| chain.allocated_dscp);
            let dscp_conflict = chains.iter().any(|(tag, chain)| {
                tag.as_str() != chain_tag && chain.allocated_dscp == config.dscp_value
            });

            (existing_state, existing_dscp, dscp_conflict)
        };

        if dscp_conflict {
            return Err(ChainError::DscpConflict(config.dscp_value));
        }

        if let Some(state) = existing_state {
            if state != ChainState::Inactive {
                return Err(ChainError::AlreadyActive(chain_tag.to_string()));
            }
        }

        if let Some(existing_dscp) = existing_dscp {
            if existing_dscp != config.dscp_value {
                return Err(ChainError::DscpConflict(config.dscp_value));
            }
        }

        // Step 5: Reserve DSCP if needed (align lock order with create_chain)
        let mut reserved = false;
        if !self.dscp_allocator.is_allocated(config.dscp_value) {
            self.dscp_allocator.reserve(config.dscp_value)?;
            reserved = true;
        }

        // Step 6: Determine our role
        let my_role = our_hop.map(|hop| hop.role);

        // Step 7: Store the chain config (still Inactive until COMMIT)
        let internal_state = ChainStateInternal {
            config: config.clone(),
            state: ChainState::Inactive,
            my_role,
            allocated_dscp: config.dscp_value,
            last_error: None,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        };

        let insert_result: Result<(), ChainError> = (|| {
            let mut chains = self
                .chains
                .write()
                .map_err(|e| ChainError::LockError(e.to_string()))?;

            if let Some(existing) = chains.get(chain_tag) {
                if existing.state != ChainState::Inactive {
                    return Err(ChainError::AlreadyActive(chain_tag.to_string()));
                }
                if existing.allocated_dscp != config.dscp_value {
                    return Err(ChainError::DscpConflict(config.dscp_value));
                }
            }

            if chains.iter().any(|(tag, chain)| {
                tag.as_str() != chain_tag && chain.allocated_dscp == config.dscp_value
            }) {
                return Err(ChainError::DscpConflict(config.dscp_value));
            }

            if chains.get(chain_tag).is_none() && !reserved {
                return Err(ChainError::DscpConflict(config.dscp_value));
            }

            chains.insert(chain_tag.to_string(), internal_state);
            Ok(())
        })();

        if let Err(err) = insert_result {
            if reserved {
                self.dscp_allocator.release(config.dscp_value);
            }
            return Err(err);
        }

        debug!("PREPARE succeeded for chain {}", chain_tag);
        Ok(())
    }

    /// Handle incoming COMMIT request from another node
    ///
    /// This is called when the coordinator sends a COMMIT request after
    /// all nodes have successfully prepared. This node applies the DSCP
    /// routing rules and transitions to Active state.
    ///
    /// # Arguments
    ///
    /// * `chain_tag` - Chain tag
    /// * `source_node` - Node that initiated the request
    pub async fn handle_commit_request(
        &self,
        chain_tag: &str,
        source_node: &str,
    ) -> Result<(), ChainError> {
        debug!(
            "Handling COMMIT request for chain {} from {}",
            chain_tag, source_node
        );

        // Step 1: Get chain config and role
        let (config, my_role) = {
            let chains = self
                .chains
                .read()
                .map_err(|e| ChainError::LockError(e.to_string()))?;

            let chain = chains
                .get(chain_tag)
                .ok_or_else(|| ChainError::NotFound(chain_tag.to_string()))?;

            // Chain must be in Inactive state (was prepared)
            if chain.state != ChainState::Inactive {
                return Err(ChainError::AlreadyActive(chain_tag.to_string()));
            }

            (chain.config.clone(), chain.my_role)
        };

        // Step 2: Set up local DSCP routing
        self.setup_local_routing(chain_tag, &config, my_role)
            .map_err(ChainError::RuleEngine)?;

        // Step 3: Transition to Active
        self.update_chain_state(chain_tag, ChainState::Active, None)?;

        debug!("COMMIT succeeded for chain {}", chain_tag);
        Ok(())
    }

    /// Handle incoming ABORT request from another node
    ///
    /// This is called when the coordinator sends an ABORT request because
    /// the 2PC failed on some node. This node cleans up any pending state.
    ///
    /// # Arguments
    ///
    /// * `chain_tag` - Chain tag
    /// * `source_node` - Node that initiated the request
    pub async fn handle_abort_request(
        &self,
        chain_tag: &str,
        source_node: &str,
    ) -> Result<(), ChainError> {
        debug!(
            "Handling ABORT request for chain {} from {}",
            chain_tag, source_node
        );

        // Step 1: Tear down any routing that may have been set up
        let _ = self.teardown_local_routing(chain_tag);

        // Step 2: Check if we need to clean up the chain
        let removed_dscp = {
            let mut chains = self
                .chains
                .write()
                .map_err(|e| ChainError::LockError(e.to_string()))?;

            if let Some(chain) = chains.get(chain_tag) {
                // Only remove if it was just prepared (still Inactive)
                // If it's somehow Active, don't remove it
                if chain.state == ChainState::Inactive {
                    let dscp = chain.allocated_dscp;
                    chains.remove(chain_tag);
                    debug!("Removed prepared chain {} on ABORT", chain_tag);
                    Some(dscp)
                } else {
                    None
                }
            } else {
                None
            }
        };

        if let Some(dscp) = removed_dscp {
            self.dscp_allocator.release(dscp);
        }

        debug!("ABORT handled for chain {}", chain_tag);
        Ok(())
    }

    /// Determine local node's role in a chain
    #[allow(dead_code)]
    fn determine_role(&self, config: &ChainConfig) -> Option<ChainRole> {
        for hop in &config.hops {
            if hop.node_tag == self.local_node_tag {
                return Some(hop.role);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::ChainHop;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::time::timeout;

    /// Helper to create a valid chain config for testing
    fn create_test_config(tag: &str, dscp: u8) -> ChainConfig {
        ChainConfig {
            tag: tag.to_string(),
            description: "Test chain".to_string(),
            dscp_value: dscp,
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

    /// Helper to create a single-hop (terminal-only) chain config
    fn create_single_hop_config(tag: &str) -> ChainConfig {
        ChainConfig {
            tag: tag.to_string(),
            description: "Single hop chain".to_string(),
            dscp_value: 0,
            hops: vec![ChainHop {
                node_tag: "node-a".to_string(),
                role: ChainRole::Terminal,
                tunnel_type: TunnelType::WireGuard,
            }],
            rules: vec![],
            exit_egress: "pia-us-east".to_string(),
            allow_transitive: false,
        }
    }

    /// Helper to create a three-hop chain config
    fn create_three_hop_config(tag: &str) -> ChainConfig {
        ChainConfig {
            tag: tag.to_string(),
            description: "Three hop chain".to_string(),
            dscp_value: 0,
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
            exit_egress: "pia-us-east".to_string(),
            allow_transitive: false,
        }
    }

    // =========================================================================
    // ChainManager creation tests
    // =========================================================================

    #[test]
    fn test_chain_manager_creation() {
        let manager = ChainManager::new("test-node".to_string());
        assert_eq!(manager.local_node_tag(), "test-node");
        assert_eq!(manager.chain_count(), 0);
    }

    #[test]
    fn test_chain_manager_with_allocator() {
        let allocator = Arc::new(DscpAllocator::new());
        let manager = ChainManager::with_allocator("test-node".to_string(), allocator.clone());
        assert_eq!(manager.local_node_tag(), "test-node");
        assert!(Arc::ptr_eq(&manager.dscp_allocator, &allocator));
    }

    // =========================================================================
    // Chain creation tests
    // =========================================================================

    #[tokio::test]
    async fn test_create_chain_basic() {
        let manager = ChainManager::new("node-a".to_string());
        let config = create_test_config("test-chain", 0);

        let result = manager.create_chain(config).await;
        assert!(result.is_ok());

        let dscp = result.unwrap();
        assert!(dscp >= 1 && dscp <= 63);
        assert_eq!(manager.chain_count(), 1);
        assert!(manager.chain_exists("test-chain"));
    }

    #[tokio::test]
    async fn test_create_chain_manual_dscp() {
        let manager = ChainManager::new("node-a".to_string());
        let config = create_test_config("test-chain", 42);

        let result = manager.create_chain(config).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 42);
    }

    #[tokio::test]
    async fn test_create_chain_auto_dscp() {
        let manager = ChainManager::new("node-a".to_string());
        let config = create_test_config("test-chain", 0);

        let dscp = manager.create_chain(config).await.unwrap();
        // Auto-allocated DSCP should be valid (1-63) and not reserved
        assert!(dscp >= 1 && dscp <= 63);
        assert!(manager.dscp_allocator().is_allocated(dscp));
    }

    #[tokio::test]
    async fn test_create_chain_already_exists() {
        let manager = ChainManager::new("node-a".to_string());
        let config1 = create_test_config("test-chain", 0);
        let config2 = create_test_config("test-chain", 0);

        manager.create_chain(config1).await.unwrap();
        let result = manager.create_chain(config2).await;

        assert!(matches!(result, Err(ChainError::AlreadyExists(_))));
    }

    #[tokio::test]
    async fn test_create_chain_dscp_conflict() {
        let manager = ChainManager::new("node-a".to_string());
        let config1 = create_test_config("chain-1", 42);
        let config2 = create_test_config("chain-2", 42);

        manager.create_chain(config1).await.unwrap();
        let result = manager.create_chain(config2).await;

        assert!(matches!(result, Err(ChainError::DscpConflict(42))));
    }

    #[tokio::test]
    async fn test_create_chain_single_hop() {
        let manager = ChainManager::new("node-a".to_string());
        let config = create_single_hop_config("single-hop");

        let result = manager.create_chain(config).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_create_chain_three_hops() {
        let manager = ChainManager::new("node-a".to_string());
        let config = create_three_hop_config("three-hop");

        let result = manager.create_chain(config).await;
        assert!(result.is_ok());
    }

    // =========================================================================
    // Chain validation tests
    // =========================================================================

    #[tokio::test]
    async fn test_validate_invalid_tag() {
        let manager = ChainManager::new("node-a".to_string());
        let mut config = create_test_config("valid-tag", 0);
        config.tag = "".to_string(); // Empty tag

        let result = manager.create_chain(config).await;
        assert!(matches!(result, Err(ChainError::InvalidTag(_))));
    }

    #[tokio::test]
    async fn test_validate_invalid_dscp() {
        let manager = ChainManager::new("node-a".to_string());
        let mut config = create_test_config("test-chain", 0);
        config.dscp_value = 64; // Too high

        let result = manager.create_chain(config).await;
        assert!(matches!(result, Err(ChainError::InvalidDscp(64))));
    }

    #[tokio::test]
    async fn test_validate_no_hops() {
        let manager = ChainManager::new("node-a".to_string());
        let mut config = create_test_config("test-chain", 0);
        config.hops = vec![];

        let result = manager.create_chain(config).await;
        assert!(matches!(result, Err(ChainError::NoHops)));
    }

    #[tokio::test]
    async fn test_validate_too_many_hops() {
        let manager = ChainManager::new("node-a".to_string());
        let mut config = create_test_config("test-chain", 0);

        // Create 11 hops (entry + 9 relay + terminal)
        config.hops = vec![ChainHop {
            node_tag: "entry".to_string(),
            role: ChainRole::Entry,
            tunnel_type: TunnelType::WireGuard,
        }];
        for i in 0..9 {
            config.hops.push(ChainHop {
                node_tag: format!("relay-{}", i),
                role: ChainRole::Relay,
                tunnel_type: TunnelType::WireGuard,
            });
        }
        config.hops.push(ChainHop {
            node_tag: "terminal".to_string(),
            role: ChainRole::Terminal,
            tunnel_type: TunnelType::WireGuard,
        });

        assert_eq!(config.hops.len(), 11);
        let result = manager.create_chain(config).await;
        assert!(matches!(result, Err(ChainError::TooManyHops(11))));
    }

    #[tokio::test]
    async fn test_validate_max_hops_allowed() {
        let manager = ChainManager::new("node-a".to_string());
        let mut config = create_test_config("test-chain", 0);

        // Create exactly 10 hops (max allowed)
        config.hops = vec![ChainHop {
            node_tag: "entry".to_string(),
            role: ChainRole::Entry,
            tunnel_type: TunnelType::WireGuard,
        }];
        for i in 0..8 {
            config.hops.push(ChainHop {
                node_tag: format!("relay-{}", i),
                role: ChainRole::Relay,
                tunnel_type: TunnelType::WireGuard,
            });
        }
        config.hops.push(ChainHop {
            node_tag: "terminal".to_string(),
            role: ChainRole::Terminal,
            tunnel_type: TunnelType::WireGuard,
        });

        assert_eq!(config.hops.len(), 10);
        let result = manager.create_chain(config).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_validate_direct_not_allowed() {
        let manager = ChainManager::new("node-a".to_string());
        let mut config = create_test_config("test-chain", 0);
        config.exit_egress = "direct".to_string();

        let result = manager.create_chain(config).await;
        assert!(matches!(result, Err(ChainError::DirectNotAllowed)));
    }

    #[tokio::test]
    async fn test_validate_direct_case_insensitive() {
        let manager = ChainManager::new("node-a".to_string());
        let mut config = create_test_config("test-chain", 0);
        config.exit_egress = "DIRECT".to_string();

        let result = manager.create_chain(config).await;
        assert!(matches!(result, Err(ChainError::DirectNotAllowed)));
    }

    #[tokio::test]
    async fn test_validate_xray_relay_not_allowed() {
        let manager = ChainManager::new("node-a".to_string());
        let config = ChainConfig {
            tag: "test-chain".to_string(),
            description: "Test".to_string(),
            dscp_value: 0,
            hops: vec![
                ChainHop {
                    node_tag: "entry".to_string(),
                    role: ChainRole::Entry,
                    tunnel_type: TunnelType::WireGuard,
                },
                ChainHop {
                    node_tag: "relay".to_string(),
                    role: ChainRole::Relay,
                    tunnel_type: TunnelType::Xray, // Xray as relay
                },
                ChainHop {
                    node_tag: "terminal".to_string(),
                    role: ChainRole::Terminal,
                    tunnel_type: TunnelType::WireGuard,
                },
            ],
            rules: vec![],
            exit_egress: "pia-us-east".to_string(),
            allow_transitive: false,
        };

        let result = manager.create_chain(config).await;
        assert!(matches!(result, Err(ChainError::XrayRelayNotAllowed)));
    }

    #[tokio::test]
    async fn test_validate_xray_entry_allowed() {
        let manager = ChainManager::new("node-a".to_string());
        let config = ChainConfig {
            tag: "test-chain".to_string(),
            description: "Test".to_string(),
            dscp_value: 0,
            hops: vec![
                ChainHop {
                    node_tag: "entry".to_string(),
                    role: ChainRole::Entry,
                    tunnel_type: TunnelType::Xray, // Xray as entry is OK
                },
                ChainHop {
                    node_tag: "terminal".to_string(),
                    role: ChainRole::Terminal,
                    tunnel_type: TunnelType::WireGuard,
                },
            ],
            rules: vec![],
            exit_egress: "pia-us-east".to_string(),
            allow_transitive: false,
        };

        let result = manager.create_chain(config).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_validate_xray_terminal_allowed() {
        let manager = ChainManager::new("node-a".to_string());
        let config = ChainConfig {
            tag: "test-chain".to_string(),
            description: "Test".to_string(),
            dscp_value: 0,
            hops: vec![
                ChainHop {
                    node_tag: "entry".to_string(),
                    role: ChainRole::Entry,
                    tunnel_type: TunnelType::WireGuard,
                },
                ChainHop {
                    node_tag: "terminal".to_string(),
                    role: ChainRole::Terminal,
                    tunnel_type: TunnelType::Xray, // Xray as terminal is OK
                },
            ],
            rules: vec![],
            exit_egress: "pia-us-east".to_string(),
            allow_transitive: false,
        };

        let result = manager.create_chain(config).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_validate_no_terminal() {
        let manager = ChainManager::new("node-a".to_string());
        let config = ChainConfig {
            tag: "test-chain".to_string(),
            description: "Test".to_string(),
            dscp_value: 0,
            hops: vec![
                ChainHop {
                    node_tag: "entry".to_string(),
                    role: ChainRole::Entry,
                    tunnel_type: TunnelType::WireGuard,
                },
                ChainHop {
                    node_tag: "relay".to_string(),
                    role: ChainRole::Relay,
                    tunnel_type: TunnelType::WireGuard,
                },
            ],
            rules: vec![],
            exit_egress: "pia-us-east".to_string(),
            allow_transitive: false,
        };

        let result = manager.create_chain(config).await;
        assert!(matches!(result, Err(ChainError::NoTerminal)));
    }

    #[tokio::test]
    async fn test_validate_multiple_terminals() {
        let manager = ChainManager::new("node-a".to_string());
        let config = ChainConfig {
            tag: "test-chain".to_string(),
            description: "Test".to_string(),
            dscp_value: 0,
            hops: vec![
                ChainHop {
                    node_tag: "terminal1".to_string(),
                    role: ChainRole::Terminal,
                    tunnel_type: TunnelType::WireGuard,
                },
                ChainHop {
                    node_tag: "terminal2".to_string(),
                    role: ChainRole::Terminal,
                    tunnel_type: TunnelType::WireGuard,
                },
            ],
            rules: vec![],
            exit_egress: "pia-us-east".to_string(),
            allow_transitive: false,
        };

        let result = manager.create_chain(config).await;
        assert!(matches!(result, Err(ChainError::InvalidHopSequence(_))));
    }

    #[tokio::test]
    async fn test_validate_wrong_role_sequence() {
        let manager = ChainManager::new("node-a".to_string());
        // First hop is Relay instead of Entry
        let config = ChainConfig {
            tag: "test-chain".to_string(),
            description: "Test".to_string(),
            dscp_value: 0,
            hops: vec![
                ChainHop {
                    node_tag: "relay".to_string(),
                    role: ChainRole::Relay,
                    tunnel_type: TunnelType::WireGuard,
                },
                ChainHop {
                    node_tag: "terminal".to_string(),
                    role: ChainRole::Terminal,
                    tunnel_type: TunnelType::WireGuard,
                },
            ],
            rules: vec![],
            exit_egress: "pia-us-east".to_string(),
            allow_transitive: false,
        };

        let result = manager.create_chain(config).await;
        assert!(matches!(result, Err(ChainError::InvalidHopSequence(_))));
    }

    // =========================================================================
    // Chain removal tests
    // =========================================================================

    #[tokio::test]
    async fn test_remove_chain_success() {
        let manager = ChainManager::new("node-a".to_string());
        let config = create_test_config("test-chain", 42);

        let dscp = manager.create_chain(config).await.unwrap();
        assert!(manager.dscp_allocator().is_allocated(dscp));

        let result = manager.remove_chain("test-chain").await;
        assert!(result.is_ok());
        assert!(!manager.chain_exists("test-chain"));
        assert!(!manager.dscp_allocator().is_allocated(dscp));
    }

    #[tokio::test]
    async fn test_remove_chain_not_found() {
        let manager = ChainManager::new("node-a".to_string());

        let result = manager.remove_chain("nonexistent").await;
        assert!(matches!(result, Err(ChainError::NotFound(_))));
    }

    #[tokio::test]
    async fn test_remove_chain_dscp_released() {
        let manager = ChainManager::new("node-a".to_string());
        let config = create_test_config("test-chain", 42);

        manager.create_chain(config).await.unwrap();
        manager.remove_chain("test-chain").await.unwrap();

        // Should be able to use the same DSCP again
        let config2 = create_test_config("test-chain-2", 42);
        let result = manager.create_chain(config2).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 42);
    }

    // =========================================================================
    // 2PC prepare/abort tests
    // =========================================================================

    #[tokio::test]
    async fn test_prepare_reserves_and_abort_releases_dscp() {
        let manager = ChainManager::new("node-a".to_string());
        let config = create_test_config("test-chain", 42);

        manager
            .handle_prepare_request("test-chain", config, "coordinator-node")
            .await
            .unwrap();
        assert!(manager.dscp_allocator().is_allocated(42));

        manager
            .handle_abort_request("test-chain", "coordinator-node")
            .await
            .unwrap();
        assert!(!manager.dscp_allocator().is_allocated(42));
    }

    #[tokio::test]
    async fn test_prepare_rejects_duplicate_dscp() {
        let manager = ChainManager::new("node-a".to_string());
        let config = create_test_config("chain-a", 42);

        manager
            .handle_prepare_request("chain-a", config, "coordinator-node")
            .await
            .unwrap();

        let config = create_test_config("chain-b", 42);
        let result = manager
            .handle_prepare_request("chain-b", config, "coordinator-node")
            .await;

        assert!(matches!(result, Err(ChainError::DscpConflict(42))));
    }

    #[tokio::test]
    async fn test_prepare_create_no_deadlock() {
        let manager = Arc::new(ChainManager::new("node-a".to_string()));
        let prepare_manager = Arc::clone(&manager);
        let create_manager = Arc::clone(&manager);

        let prepare = tokio::spawn(async move {
            let config = create_test_config("chain-prepare", 41);
            prepare_manager
                .handle_prepare_request("chain-prepare", config, "coordinator-node")
                .await
        });

        let create = tokio::spawn(async move {
            let config = create_test_config("chain-create", 42);
            create_manager.create_chain(config).await
        });

        let result = timeout(Duration::from_secs(2), async {
            let prepare_result = prepare.await.unwrap();
            let create_result = create.await.unwrap();
            (prepare_result, create_result)
        })
        .await;

        assert!(result.is_ok());
        let (prepare_result, create_result) = result.unwrap();
        assert!(prepare_result.is_ok());
        assert!(create_result.is_ok());
    }

    // =========================================================================
    // Chain status tests
    // =========================================================================

    #[tokio::test]
    async fn test_get_chain_status() {
        let manager = ChainManager::new("node-a".to_string());
        let config = create_test_config("test-chain", 42);

        manager.create_chain(config).await.unwrap();

        let status = manager.get_chain_status("test-chain");
        assert!(status.is_some());

        let status = status.unwrap();
        assert_eq!(status.tag, "test-chain");
        assert_eq!(status.dscp_value, 42);
        assert_eq!(status.state, ChainState::Inactive);
        assert_eq!(status.my_role, Some(ChainRole::Entry));
    }

    #[test]
    fn test_get_chain_status_not_found() {
        let manager = ChainManager::new("test-node".to_string());
        let status = manager.get_chain_status("nonexistent");
        assert!(status.is_none());
    }

    #[tokio::test]
    async fn test_get_chain_config() {
        let manager = ChainManager::new("node-a".to_string());
        let config = create_test_config("test-chain", 0);

        manager.create_chain(config.clone()).await.unwrap();

        let retrieved = manager.get_chain_config("test-chain");
        assert!(retrieved.is_some());

        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.tag, config.tag);
        assert_eq!(retrieved.description, config.description);
        assert_eq!(retrieved.exit_egress, config.exit_egress);
    }

    #[test]
    fn test_list_chains_empty() {
        let manager = ChainManager::new("test-node".to_string());
        let chains = manager.list_chains();
        assert!(chains.is_empty());
    }

    #[tokio::test]
    async fn test_list_chains() {
        let manager = ChainManager::new("node-a".to_string());
        let config1 = create_test_config("chain-1", 10);
        let config2 = create_test_config("chain-2", 20);

        manager.create_chain(config1).await.unwrap();
        manager.create_chain(config2).await.unwrap();

        let chains = manager.list_chains();
        assert_eq!(chains.len(), 2);

        let tags: Vec<_> = chains.iter().map(|c| c.tag.as_str()).collect();
        assert!(tags.contains(&"chain-1"));
        assert!(tags.contains(&"chain-2"));
    }

    // =========================================================================
    // Role determination tests
    // =========================================================================

    #[test]
    fn test_get_chain_role_not_found() {
        let manager = ChainManager::new("test-node".to_string());
        let role = manager.get_chain_role("nonexistent");
        assert!(role.is_none());
    }

    #[tokio::test]
    async fn test_determine_role_entry() {
        let manager = ChainManager::new("node-a".to_string());
        let config = create_test_config("test-chain", 0);

        manager.create_chain(config).await.unwrap();

        let role = manager.get_chain_role("test-chain");
        assert_eq!(role, Some(ChainRole::Entry));
    }

    #[tokio::test]
    async fn test_determine_role_terminal() {
        let manager = ChainManager::new("node-b".to_string());
        let config = create_test_config("test-chain", 0);

        manager.create_chain(config).await.unwrap();

        let role = manager.get_chain_role("test-chain");
        assert_eq!(role, Some(ChainRole::Terminal));
    }

    #[tokio::test]
    async fn test_determine_role_relay() {
        let manager = ChainManager::new("node-b".to_string());
        let config = create_three_hop_config("test-chain");

        manager.create_chain(config).await.unwrap();

        let role = manager.get_chain_role("test-chain");
        assert_eq!(role, Some(ChainRole::Relay));
    }

    #[tokio::test]
    async fn test_determine_role_not_in_chain() {
        let manager = ChainManager::new("node-x".to_string());
        let config = create_test_config("test-chain", 0);

        manager.create_chain(config).await.unwrap();

        let role = manager.get_chain_role("test-chain");
        assert_eq!(role, None);
    }

    // =========================================================================
    // Chain state update tests
    // =========================================================================

    #[tokio::test]
    async fn test_update_chain_state() {
        let manager = ChainManager::new("node-a".to_string());
        let config = create_test_config("test-chain", 0);

        manager.create_chain(config).await.unwrap();

        // Update to Active
        let result = manager.update_chain_state("test-chain", ChainState::Active, None);
        assert!(result.is_ok());

        let status = manager.get_chain_status("test-chain").unwrap();
        assert_eq!(status.state, ChainState::Active);
    }

    #[tokio::test]
    async fn test_update_chain_state_with_error() {
        let manager = ChainManager::new("node-a".to_string());
        let config = create_test_config("test-chain", 0);

        manager.create_chain(config).await.unwrap();

        // Update to Error with message
        let result = manager.update_chain_state(
            "test-chain",
            ChainState::Error,
            Some("Test error".to_string()),
        );
        assert!(result.is_ok());

        let status = manager.get_chain_status("test-chain").unwrap();
        assert_eq!(status.state, ChainState::Error);
        assert_eq!(status.last_error, Some("Test error".to_string()));
    }

    #[test]
    fn test_update_chain_state_not_found() {
        let manager = ChainManager::new("node-a".to_string());

        let result = manager.update_chain_state("nonexistent", ChainState::Active, None);
        assert!(matches!(result, Err(ChainError::NotFound(_))));
    }

    // =========================================================================
    // Error conversion tests
    // =========================================================================

    #[test]
    fn test_dscp_allocator_error_conversion() {
        let err: ChainError = DscpAllocatorError::Exhausted.into();
        assert!(matches!(err, ChainError::DscpExhausted));

        let err: ChainError = DscpAllocatorError::AlreadyAllocated(42).into();
        assert!(matches!(err, ChainError::DscpConflict(42)));

        let err: ChainError = DscpAllocatorError::Reserved(46).into();
        assert!(matches!(err, ChainError::DscpConflict(46)));

        let err: ChainError = DscpAllocatorError::OutOfRange(64).into();
        assert!(matches!(err, ChainError::InvalidDscp(64)));
    }

    // =========================================================================
    // Edge cases and error messages
    // =========================================================================

    #[test]
    fn test_chain_error_display() {
        assert!(ChainError::NotFound("test".to_string())
            .to_string()
            .contains("test"));
        assert!(ChainError::DirectNotAllowed
            .to_string()
            .contains("direct"));
        assert!(ChainError::XrayRelayNotAllowed
            .to_string()
            .contains("Xray"));
        assert!(ChainError::TooManyHops(11)
            .to_string()
            .contains("11"));
    }

    #[tokio::test]
    async fn test_multiple_chains_independent_dscp() {
        let manager = ChainManager::new("node-a".to_string());

        // Create multiple chains with auto DSCP
        for i in 0..5 {
            let config = create_test_config(&format!("chain-{}", i), 0);
            let result = manager.create_chain(config).await;
            assert!(result.is_ok());
        }

        assert_eq!(manager.chain_count(), 5);
        assert_eq!(manager.dscp_allocator().allocated_count(), 5);
    }

    // =========================================================================
    // Recovery tests
    // =========================================================================

    #[tokio::test]
    async fn test_recover_orphaned_chains_basic() {
        let manager = ChainManager::new("node-a".to_string());
        let config = create_test_config("orphan-chain", 0);

        manager.create_chain(config).await.unwrap();

        // Simulate stuck in Activating
        manager
            .update_chain_state("orphan-chain", ChainState::Activating, None)
            .unwrap();

        let recovered = manager.recover_orphaned_chains();
        assert_eq!(recovered, 1);

        let status = manager.get_chain_status("orphan-chain").unwrap();
        assert_eq!(status.state, ChainState::Error);
        assert!(status.last_error.unwrap().contains("Recovery"));
    }

    #[test]
    fn test_recover_orphaned_chains_empty() {
        let manager = ChainManager::new("node-a".to_string());
        let recovered = manager.recover_orphaned_chains();
        assert_eq!(recovered, 0);
    }

    #[tokio::test]
    async fn test_recover_orphaned_chains_skips_other_states() {
        let manager = ChainManager::new("node-a".to_string());

        // Create chains in different states
        let config1 = create_test_config("inactive-chain", 10);
        let config2 = create_test_config("error-chain", 20);

        manager.create_chain(config1).await.unwrap();
        manager.create_chain(config2).await.unwrap();

        manager
            .update_chain_state("error-chain", ChainState::Error, Some("Previous error".to_string()))
            .unwrap();

        // Recover should find no orphaned chains
        let recovered = manager.recover_orphaned_chains();
        assert_eq!(recovered, 0);

        // States should be unchanged
        let status1 = manager.get_chain_status("inactive-chain").unwrap();
        assert_eq!(status1.state, ChainState::Inactive);

        let status2 = manager.get_chain_status("error-chain").unwrap();
        assert_eq!(status2.state, ChainState::Error);
        assert_eq!(status2.last_error, Some("Previous error".to_string()));
    }

    // =========================================================================
    // Invalid description tests
    // =========================================================================

    #[tokio::test]
    async fn test_validate_description_too_long() {
        let manager = ChainManager::new("node-a".to_string());
        let mut config = create_test_config("desc-test", 0);
        config.description = "x".repeat(1025); // > 1024 chars (MAX_DESCRIPTION_LENGTH is 256 in validation.rs)

        let result = manager.create_chain(config).await;
        assert!(matches!(result, Err(ChainError::InvalidDescription(_))));
    }

    #[tokio::test]
    async fn test_validate_description_at_limit() {
        let manager = ChainManager::new("node-a".to_string());
        let mut config = create_test_config("desc-limit", 0);
        config.description = "x".repeat(256); // Exactly at limit

        let result = manager.create_chain(config).await;
        assert!(result.is_ok());
    }
}
