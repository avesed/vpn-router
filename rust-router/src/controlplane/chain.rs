//! DSCP Chain Routing Handler
//!
//! Handles multi-hop chain routing based on DSCP values in IP packets.
//! Extracted from `ingress/processor.rs` for reuse in the control plane.
//!
//! # Overview
//!
//! This module provides the `ChainHandler` which manages DSCP-based chain routing
//! decisions. It integrates with:
//!
//! - `ChainManager`: For chain configuration and role lookup
//! - `RuleEngine`: For DSCP-to-chain tag mapping via `FwmarkRouter`
//!
//! # Chain Routing Flow
//!
//! ```text
//! Packet arrives with DSCP > 0
//!         |
//!         v
//! +-------------------+
//! | FwmarkRouter      |  -> Look up chain_tag by DSCP value
//! +-------------------+
//!         |
//!         v
//! +-------------------+
//! | ChainManager      |  -> Get local node's role
//! +-------------------+
//!         |
//!         +-----> Terminal? -----> Route to exit_egress, clear DSCP
//!         |
//!         +-----> Entry/Relay? --> Forward to next hop, preserve DSCP
//!         |
//!         +-----> Unknown? ------> Block (prevent leak)
//! ```
//!
//! # Security Model
//!
//! DSCP-marked packets that cannot be routed are BLOCKED, not defaulted:
//!
//! - **Unregistered DSCP**: Blocked (chain activation issue)
//! - **No `ChainManager`**: Blocked (configuration error)
//! - **Missing config**: Blocked (inconsistent state)
//! - **No next hop**: Blocked (chain setup incomplete)
//! - **No role**: Blocked (node not in chain)
//!
//! This prevents traffic leaks to the default egress when chain routing fails.

use std::sync::Arc;

use tracing::{debug, trace, warn};

use crate::chain::ChainManager;
use crate::ipc::ChainRole;
use crate::rules::engine::RuleEngine;
use crate::rules::fwmark::ChainMark;

/// Result of chain routing decision
///
/// Represents the outcome of processing a DSCP-marked packet or a chain
/// entry rule match. Each variant indicates how the packet should be handled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainRoutingResult {
    /// Forward to next hop (Entry or Relay node)
    ///
    /// The packet should be forwarded to the specified peer tunnel,
    /// preserving the DSCP value for the next hop.
    Forward {
        /// Outbound tag (peer tunnel, e.g., "peer-node-b")
        outbound: String,
        /// DSCP value to preserve on the packet
        dscp: u8,
        /// Routing mark for policy routing
        routing_mark: u32,
    },

    /// Terminal node - route to exit egress and clear DSCP
    ///
    /// The packet has reached the terminal node and should be routed
    /// to the configured exit egress. DSCP should be cleared (set to 0).
    Terminal {
        /// Exit egress outbound tag (e.g., "pia-us-east")
        outbound: String,
    },

    /// Block the packet (chain error, leak prevention)
    ///
    /// The packet cannot be routed through the chain and must be blocked
    /// to prevent traffic leaking to the default egress.
    Block {
        /// Reason for blocking (for logging/debugging)
        reason: String,
    },

    /// Not a chain packet (DSCP=0 or no chain registered)
    ///
    /// The packet does not have a DSCP value that maps to a registered
    /// chain. Normal rule-based routing should be used.
    NotChain,
}

impl ChainRoutingResult {
    /// Returns true if the packet should be blocked
    #[must_use]
    pub fn is_block(&self) -> bool {
        matches!(self, Self::Block { .. })
    }

    /// Returns true if this is a chain packet (not `NotChain`)
    #[must_use]
    pub fn is_chain_packet(&self) -> bool {
        !matches!(self, Self::NotChain)
    }

    /// Returns the outbound tag, if any
    #[must_use]
    pub fn outbound(&self) -> Option<&str> {
        match self {
            Self::Forward { outbound, .. } | Self::Terminal { outbound } => Some(outbound),
            Self::Block { .. } | Self::NotChain => None,
        }
    }

    /// Returns the DSCP value to set, if any
    ///
    /// - `Forward`: Returns `Some(dscp)` to preserve DSCP
    /// - `Terminal`: Returns `Some(0)` to clear DSCP
    /// - `Block`: Returns `Some(0)` to clear DSCP before blocking
    /// - `NotChain`: Returns `None`
    #[must_use]
    pub fn dscp_to_set(&self) -> Option<u8> {
        match self {
            Self::Forward { dscp, .. } => Some(*dscp),
            Self::Terminal { .. } | Self::Block { .. } => Some(0),
            Self::NotChain => None,
        }
    }
}

impl std::fmt::Display for ChainRoutingResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Forward {
                outbound,
                dscp,
                routing_mark,
            } => {
                write!(f, "Forward(outbound={outbound}, dscp={dscp}, mark=0x{routing_mark:x})")
            }
            Self::Terminal { outbound } => write!(f, "Terminal(outbound={outbound})"),
            Self::Block { reason } => write!(f, "Block(reason={reason})"),
            Self::NotChain => write!(f, "NotChain"),
        }
    }
}

/// Handler for DSCP-based chain routing
///
/// This handler encapsulates the chain routing logic extracted from
/// `IngressProcessor`. It can be used with or without a `ChainManager`:
///
/// - **With `ChainManager`**: Full chain routing with role-based forwarding
/// - **Without `ChainManager`**: Returns `Block` for DSCP-marked packets
///
/// # Thread Safety
///
/// `ChainHandler` is `Send + Sync` and can be safely shared across tasks.
///
/// # Example
///
/// ```ignore
/// use rust_router::controlplane::ChainHandler;
/// use rust_router::chain::ChainManager;
/// use std::sync::Arc;
///
/// // Create handler with chain manager
/// let chain_manager = Arc::new(ChainManager::new("local-node".to_string()));
/// let handler = ChainHandler::with_chain_manager(chain_manager);
///
/// // Handle a DSCP-marked packet
/// let result = handler.handle_dscp_packet(10, &rule_engine);
/// match result {
///     ChainRoutingResult::Forward { outbound, dscp, .. } => {
///         println!("Forward to {} with DSCP {}", outbound, dscp);
///     }
///     ChainRoutingResult::Terminal { outbound } => {
///         println!("Terminal: route to {}", outbound);
///     }
///     ChainRoutingResult::Block { reason } => {
///         println!("Blocked: {}", reason);
///     }
///     ChainRoutingResult::NotChain => {
///         println!("Not a chain packet, use normal routing");
///     }
/// }
/// ```
pub struct ChainHandler {
    /// Optional chain manager for chain operations
    chain_manager: Option<Arc<ChainManager>>,
}

impl ChainHandler {
    /// Create a new `ChainHandler` without a chain manager
    ///
    /// This handler will return `Block` for any DSCP-marked packets
    /// since it cannot determine chain routing without a manager.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let handler = ChainHandler::new();
    /// // DSCP packets will be blocked
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            chain_manager: None,
        }
    }

    /// Create a `ChainHandler` with a `ChainManager`
    ///
    /// This enables full chain routing functionality.
    ///
    /// # Arguments
    ///
    /// * `chain_manager` - The chain manager for chain operations
    ///
    /// # Example
    ///
    /// ```ignore
    /// let chain_manager = Arc::new(ChainManager::new("local-node".to_string()));
    /// let handler = ChainHandler::with_chain_manager(chain_manager);
    /// ```
    #[must_use]
    pub fn with_chain_manager(chain_manager: Arc<ChainManager>) -> Self {
        Self {
            chain_manager: Some(chain_manager),
        }
    }

    /// Set the chain manager
    ///
    /// Allows setting or replacing the chain manager after construction.
    ///
    /// # Arguments
    ///
    /// * `chain_manager` - The chain manager for chain operations
    pub fn set_chain_manager(&mut self, chain_manager: Arc<ChainManager>) {
        self.chain_manager = Some(chain_manager);
    }

    /// Clear the chain manager
    ///
    /// After calling this, DSCP-marked packets will be blocked.
    pub fn clear_chain_manager(&mut self) {
        self.chain_manager = None;
    }

    /// Check if a chain manager is configured
    #[must_use]
    pub fn has_chain_manager(&self) -> bool {
        self.chain_manager.is_some()
    }

    /// Get a reference to the chain manager, if set
    #[must_use]
    pub fn chain_manager(&self) -> Option<&Arc<ChainManager>> {
        self.chain_manager.as_ref()
    }

    /// Handle a DSCP-marked packet
    ///
    /// If DSCP > 0, looks up the chain and determines routing based on
    /// the local node's role. Returns `NotChain` if DSCP = 0.
    ///
    /// # Arguments
    ///
    /// * `dscp` - DSCP value from the packet (0-63)
    /// * `rule_engine` - `RuleEngine` for `FwmarkRouter` lookup
    ///
    /// # Returns
    ///
    /// `ChainRoutingResult` indicating how to route the packet:
    /// - `NotChain`: DSCP = 0, use normal routing
    /// - `Forward`: Entry/Relay node, forward to next hop
    /// - `Terminal`: Terminal node, route to exit egress
    /// - `Block`: Error condition, block to prevent leak
    ///
    /// # Example
    ///
    /// ```ignore
    /// let dscp = get_dscp(&packet)?;
    /// let result = handler.handle_dscp_packet(dscp, &rule_engine);
    /// ```
    #[must_use]
    pub fn handle_dscp_packet(&self, dscp: u8, rule_engine: &RuleEngine) -> ChainRoutingResult {
        // DSCP 0 is not a chain packet
        if dscp == 0 {
            return ChainRoutingResult::NotChain;
        }

        // Look up chain by DSCP value in FwmarkRouter - O(1) lookup
        let snapshot = rule_engine.load();
        let chain_entry = snapshot.fwmark_router.get_chain_by_dscp(dscp);

        let Some((chain_tag, chain_mark)) = chain_entry else {
            // DSCP set but no chain registered - block to prevent leak
            warn!(
                dscp = dscp,
                "Received packet with DSCP={} but no chain registered. \
                 This indicates a chain activation issue. Blocking to prevent leak.",
                dscp
            );
            return ChainRoutingResult::Block {
                reason: format!("dscp:{dscp} unregistered"),
            };
        };

        // We have a chain registered for this DSCP - now route it
        self.route_chain_packet(chain_tag, *chain_mark)
    }

    /// Route a chain packet based on local node's role
    ///
    /// Internal method that handles the actual routing decision once
    /// we've identified the chain.
    fn route_chain_packet(&self, chain_tag: &str, chain_mark: ChainMark) -> ChainRoutingResult {
        // Check if we have a chain manager
        let Some(chain_manager) = &self.chain_manager else {
            warn!(
                dscp = chain_mark.dscp_value,
                chain_tag = chain_tag,
                routing_mark = chain_mark.routing_mark,
                "Chain packet detected but no chain manager available; blocking"
            );
            let dscp = chain_mark.dscp_value;
            return ChainRoutingResult::Block {
                reason: format!("dscp:{dscp} no-chain-manager"),
            };
        };

        // Get local node's role in this chain
        let my_role = chain_manager.get_chain_role(chain_tag);

        match my_role {
            Some(ChainRole::Terminal) => {
                // Terminal node: route to exit egress and clear DSCP
                self.handle_terminal_node(chain_tag, chain_mark, chain_manager)
            }

            Some(role @ (ChainRole::Entry | ChainRole::Relay)) => {
                // Entry/Relay node: forward to next hop
                self.handle_forwarding_node(chain_tag, chain_mark, chain_manager, role)
            }

            None => {
                // Local node has no role in this chain
                let dscp = chain_mark.dscp_value;
                warn!(
                    dscp = dscp,
                    chain_tag = chain_tag,
                    "Received chain packet but local node has no role; blocking"
                );
                ChainRoutingResult::Block {
                    reason: format!("dscp:{dscp} no-role"),
                }
            }
        }
    }

    /// Handle routing for terminal node
    fn handle_terminal_node(
        &self,
        chain_tag: &str,
        chain_mark: ChainMark,
        chain_manager: &ChainManager,
    ) -> ChainRoutingResult {
        // Get the chain config to find exit egress
        if let Some(config) = chain_manager.get_chain_config(chain_tag) {
            let exit_egress = config.exit_egress;
            trace!(
                dscp = chain_mark.dscp_value,
                chain_tag = chain_tag,
                exit_egress = %exit_egress,
                "Terminal chain packet detected"
            );
            ChainRoutingResult::Terminal {
                outbound: exit_egress,
            }
        } else {
            // Terminal node config missing - this is an error
            let dscp = chain_mark.dscp_value;
            warn!(
                dscp = dscp,
                chain_tag = chain_tag,
                "Terminal chain config missing; blocking to prevent leak"
            );
            ChainRoutingResult::Block {
                reason: format!("dscp:{dscp} terminal-config-missing"),
            }
        }
    }

    /// Handle routing for entry/relay node (forwarding)
    fn handle_forwarding_node(
        &self,
        chain_tag: &str,
        chain_mark: ChainMark,
        chain_manager: &ChainManager,
        role: ChainRole,
    ) -> ChainRoutingResult {
        // Get the next hop tunnel
        if let Some(next_hop_tunnel) = chain_manager.get_next_hop_tunnel(chain_tag) {
            trace!(
                dscp = chain_mark.dscp_value,
                chain_tag = chain_tag,
                next_hop = %next_hop_tunnel,
                role = ?role,
                "Forwarding chain packet to next hop"
            );
            ChainRoutingResult::Forward {
                outbound: next_hop_tunnel,
                dscp: chain_mark.dscp_value,
                routing_mark: chain_mark.routing_mark,
            }
        } else {
            // Next hop tunnel not found - block to prevent leak
            let dscp = chain_mark.dscp_value;
            warn!(
                dscp = dscp,
                chain_tag = chain_tag,
                role = ?role,
                "Next hop tunnel not found for chain; blocking to prevent leak"
            );
            ChainRoutingResult::Block {
                reason: format!("dscp:{dscp} next-hop-missing"),
            }
        }
    }

    /// Handle chain entry (when rule matches chain tag)
    ///
    /// Called when `RuleEngine` matches a connection to a chain tag.
    /// This is for packets with DSCP=0 that match a rule routing to a chain.
    /// The handler resolves the chain to the next hop peer tunnel.
    ///
    /// # Arguments
    ///
    /// * `chain_tag` - The chain tag from the rule match
    /// * `mark` - The chain mark (DSCP value and routing mark)
    ///
    /// # Returns
    ///
    /// `ChainRoutingResult` for chain entry:
    /// - `Forward`: Entry node, forward to next hop with DSCP set
    /// - `Block`: Error condition (no manager, no next hop)
    /// - `NotChain`: Should not occur, but returned if no manager
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Rule engine matched a chain rule
    /// if let Some(chain_mark) = result.routing_mark.and_then(ChainMark::from_routing_mark) {
    ///     let result = handler.handle_chain_entry(&result.outbound, chain_mark);
    ///     // result.dscp will be the DSCP value to set on the packet
    /// }
    /// ```
    #[must_use]
    pub fn handle_chain_entry(&self, chain_tag: &str, mark: ChainMark) -> ChainRoutingResult {
        let Some(chain_manager) = &self.chain_manager else {
            debug!(
                chain_tag = chain_tag,
                dscp = mark.dscp_value,
                "Chain rule matched but no ChainManager available"
            );
            return ChainRoutingResult::Block {
                reason: format!("chain:{chain_tag} no-chain-manager"),
            };
        };

        // For chain entry, we're always looking for the next hop
        if let Some(next_hop_tunnel) = chain_manager.get_next_hop_tunnel(chain_tag) {
            debug!(
                chain_tag = chain_tag,
                next_hop = %next_hop_tunnel,
                dscp = mark.dscp_value,
                "Entry node: routing to chain peer tunnel"
            );
            ChainRoutingResult::Forward {
                outbound: next_hop_tunnel,
                dscp: mark.dscp_value,
                routing_mark: mark.routing_mark,
            }
        } else {
            // Chain tag exists but no next hop (might be terminal or misconfigured)
            warn!(
                chain_tag = chain_tag,
                dscp = mark.dscp_value,
                "Chain route matched but no next hop tunnel found"
            );
            ChainRoutingResult::Block {
                reason: format!("chain:{chain_tag} no-next-hop"),
            }
        }
    }
}

impl Default for ChainHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for ChainHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChainHandler")
            .field("has_chain_manager", &self.chain_manager.is_some())
            .finish()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::{ChainConfig, ChainHop, TunnelType};
    use crate::rules::engine::RoutingSnapshotBuilder;
    use tokio::runtime::Runtime;

    // =========================================================================
    // ChainRoutingResult Tests
    // =========================================================================

    #[test]
    fn test_chain_routing_result_is_block() {
        assert!(ChainRoutingResult::Block {
            reason: "test".to_string()
        }
        .is_block());
        assert!(!ChainRoutingResult::NotChain.is_block());
        assert!(!ChainRoutingResult::Terminal {
            outbound: "test".to_string()
        }
        .is_block());
        assert!(!ChainRoutingResult::Forward {
            outbound: "test".to_string(),
            dscp: 10,
            routing_mark: 778,
        }
        .is_block());
    }

    #[test]
    fn test_chain_routing_result_is_chain_packet() {
        assert!(!ChainRoutingResult::NotChain.is_chain_packet());
        assert!(ChainRoutingResult::Block {
            reason: "test".to_string()
        }
        .is_chain_packet());
        assert!(ChainRoutingResult::Terminal {
            outbound: "test".to_string()
        }
        .is_chain_packet());
        assert!(ChainRoutingResult::Forward {
            outbound: "test".to_string(),
            dscp: 10,
            routing_mark: 778,
        }
        .is_chain_packet());
    }

    #[test]
    fn test_chain_routing_result_outbound() {
        assert_eq!(ChainRoutingResult::NotChain.outbound(), None);
        assert_eq!(
            ChainRoutingResult::Block {
                reason: "test".to_string()
            }
            .outbound(),
            None
        );
        assert_eq!(
            ChainRoutingResult::Terminal {
                outbound: "exit".to_string()
            }
            .outbound(),
            Some("exit")
        );
        assert_eq!(
            ChainRoutingResult::Forward {
                outbound: "peer-node".to_string(),
                dscp: 10,
                routing_mark: 778,
            }
            .outbound(),
            Some("peer-node")
        );
    }

    #[test]
    fn test_chain_routing_result_dscp_to_set() {
        assert_eq!(ChainRoutingResult::NotChain.dscp_to_set(), None);
        assert_eq!(
            ChainRoutingResult::Block {
                reason: "test".to_string()
            }
            .dscp_to_set(),
            Some(0)
        );
        assert_eq!(
            ChainRoutingResult::Terminal {
                outbound: "exit".to_string()
            }
            .dscp_to_set(),
            Some(0)
        );
        assert_eq!(
            ChainRoutingResult::Forward {
                outbound: "peer-node".to_string(),
                dscp: 10,
                routing_mark: 778,
            }
            .dscp_to_set(),
            Some(10)
        );
    }

    #[test]
    fn test_chain_routing_result_display() {
        let forward = ChainRoutingResult::Forward {
            outbound: "peer-node".to_string(),
            dscp: 10,
            routing_mark: 0x30a,
        };
        assert!(format!("{}", forward).contains("Forward"));
        assert!(format!("{}", forward).contains("peer-node"));

        let terminal = ChainRoutingResult::Terminal {
            outbound: "exit".to_string(),
        };
        assert!(format!("{}", terminal).contains("Terminal"));
        assert!(format!("{}", terminal).contains("exit"));

        let block = ChainRoutingResult::Block {
            reason: "no-manager".to_string(),
        };
        assert!(format!("{}", block).contains("Block"));
        assert!(format!("{}", block).contains("no-manager"));

        assert!(format!("{}", ChainRoutingResult::NotChain).contains("NotChain"));
    }

    #[test]
    fn test_chain_routing_result_equality() {
        let forward1 = ChainRoutingResult::Forward {
            outbound: "peer".to_string(),
            dscp: 10,
            routing_mark: 778,
        };
        let forward2 = ChainRoutingResult::Forward {
            outbound: "peer".to_string(),
            dscp: 10,
            routing_mark: 778,
        };
        let forward3 = ChainRoutingResult::Forward {
            outbound: "other".to_string(),
            dscp: 10,
            routing_mark: 778,
        };

        assert_eq!(forward1, forward2);
        assert_ne!(forward1, forward3);
        assert_ne!(forward1, ChainRoutingResult::NotChain);
    }

    // =========================================================================
    // ChainHandler Construction Tests
    // =========================================================================

    #[test]
    fn test_chain_handler_new() {
        let handler = ChainHandler::new();
        assert!(!handler.has_chain_manager());
        assert!(handler.chain_manager().is_none());
    }

    #[test]
    fn test_chain_handler_default() {
        let handler = ChainHandler::default();
        assert!(!handler.has_chain_manager());
    }

    #[test]
    fn test_chain_handler_with_chain_manager() {
        let chain_manager = Arc::new(ChainManager::new("test-node".to_string()));
        let handler = ChainHandler::with_chain_manager(chain_manager);
        assert!(handler.has_chain_manager());
        assert!(handler.chain_manager().is_some());
    }

    #[test]
    fn test_chain_handler_set_chain_manager() {
        let mut handler = ChainHandler::new();
        assert!(!handler.has_chain_manager());

        let chain_manager = Arc::new(ChainManager::new("test-node".to_string()));
        handler.set_chain_manager(chain_manager);
        assert!(handler.has_chain_manager());
    }

    #[test]
    fn test_chain_handler_clear_chain_manager() {
        let chain_manager = Arc::new(ChainManager::new("test-node".to_string()));
        let mut handler = ChainHandler::with_chain_manager(chain_manager);
        assert!(handler.has_chain_manager());

        handler.clear_chain_manager();
        assert!(!handler.has_chain_manager());
    }

    #[test]
    fn test_chain_handler_debug() {
        let handler = ChainHandler::new();
        let debug_str = format!("{:?}", handler);
        assert!(debug_str.contains("ChainHandler"));
        assert!(debug_str.contains("has_chain_manager"));
    }

    // =========================================================================
    // DSCP Packet Handling Tests
    // =========================================================================

    fn create_test_rule_engine() -> Arc<RuleEngine> {
        let snapshot = RoutingSnapshotBuilder::new()
            .default_outbound("direct")
            .version(1)
            .build()
            .unwrap();
        Arc::new(RuleEngine::new(snapshot))
    }

    fn create_rule_engine_with_chain(chain_tag: &str, dscp: u8) -> Arc<RuleEngine> {
        let mut builder = RoutingSnapshotBuilder::new();
        builder.add_chain_with_dscp(chain_tag, dscp).unwrap();
        let snapshot = builder.default_outbound("direct").build().unwrap();
        Arc::new(RuleEngine::new(snapshot))
    }

    #[test]
    fn test_not_chain_dscp_zero() {
        let handler = ChainHandler::new();
        let rule_engine = create_test_rule_engine();

        let result = handler.handle_dscp_packet(0, &rule_engine);
        assert_eq!(result, ChainRoutingResult::NotChain);
    }

    #[test]
    fn test_dscp_no_chain_registered_blocks() {
        let handler = ChainHandler::new();
        let rule_engine = create_test_rule_engine();

        // DSCP 10 but no chain registered for it
        let result = handler.handle_dscp_packet(10, &rule_engine);
        assert!(result.is_block());
        if let ChainRoutingResult::Block { reason } = result {
            assert!(reason.contains("unregistered"));
        }
    }

    #[test]
    fn test_dscp_no_chain_manager_blocks() {
        // Create rule engine with chain but handler without chain manager
        let handler = ChainHandler::new();
        let rule_engine = create_rule_engine_with_chain("test-chain", 10);

        let result = handler.handle_dscp_packet(10, &rule_engine);
        assert!(result.is_block());
        if let ChainRoutingResult::Block { reason } = result {
            assert!(reason.contains("no-chain-manager"));
        }
    }

    #[test]
    fn test_terminal_routes_to_exit() {
        let chain_manager = Arc::new(ChainManager::new("terminal-node".to_string()));

        // Create chain where local node is terminal
        let config = ChainConfig {
            tag: "test-chain".to_string(),
            description: "Test chain".to_string(),
            dscp_value: 10,
            hops: vec![
                ChainHop {
                    node_tag: "entry-node".to_string(),
                    role: ChainRole::Entry,
                    tunnel_type: TunnelType::WireGuard,
                },
                ChainHop {
                    node_tag: "terminal-node".to_string(),
                    role: ChainRole::Terminal,
                    tunnel_type: TunnelType::WireGuard,
                },
            ],
            rules: vec![],
            exit_egress: "pia-us-east".to_string(),
            allow_transitive: false,
        };

        let runtime = Runtime::new().unwrap();
        runtime.block_on(async {
            chain_manager.create_chain(config).await.unwrap();
        });

        let handler = ChainHandler::with_chain_manager(chain_manager);
        let rule_engine = create_rule_engine_with_chain("test-chain", 10);

        let result = handler.handle_dscp_packet(10, &rule_engine);
        match result {
            ChainRoutingResult::Terminal { outbound } => {
                assert_eq!(outbound, "pia-us-east");
            }
            _ => panic!("Expected Terminal, got {:?}", result),
        }
    }

    #[test]
    fn test_entry_forwards_to_next_hop() {
        let chain_manager = Arc::new(ChainManager::new("entry-node".to_string()));

        let config = ChainConfig {
            tag: "test-chain".to_string(),
            description: "Test chain".to_string(),
            dscp_value: 10,
            hops: vec![
                ChainHop {
                    node_tag: "entry-node".to_string(),
                    role: ChainRole::Entry,
                    tunnel_type: TunnelType::WireGuard,
                },
                ChainHop {
                    node_tag: "relay-node".to_string(),
                    role: ChainRole::Relay,
                    tunnel_type: TunnelType::WireGuard,
                },
                ChainHop {
                    node_tag: "terminal-node".to_string(),
                    role: ChainRole::Terminal,
                    tunnel_type: TunnelType::WireGuard,
                },
            ],
            rules: vec![],
            exit_egress: "pia-us-east".to_string(),
            allow_transitive: false,
        };

        let runtime = Runtime::new().unwrap();
        runtime.block_on(async {
            chain_manager.create_chain(config).await.unwrap();
        });

        let handler = ChainHandler::with_chain_manager(chain_manager);
        let rule_engine = create_rule_engine_with_chain("test-chain", 10);

        let result = handler.handle_dscp_packet(10, &rule_engine);
        match result {
            ChainRoutingResult::Forward {
                outbound,
                dscp,
                routing_mark,
            } => {
                assert_eq!(outbound, "peer-relay-node");
                assert_eq!(dscp, 10);
                assert!(routing_mark > 0);
            }
            _ => panic!("Expected Forward, got {:?}", result),
        }
    }

    #[test]
    fn test_relay_forwards_to_next_hop() {
        let chain_manager = Arc::new(ChainManager::new("relay-node".to_string()));

        let config = ChainConfig {
            tag: "test-chain".to_string(),
            description: "Test chain".to_string(),
            dscp_value: 10,
            hops: vec![
                ChainHop {
                    node_tag: "entry-node".to_string(),
                    role: ChainRole::Entry,
                    tunnel_type: TunnelType::WireGuard,
                },
                ChainHop {
                    node_tag: "relay-node".to_string(),
                    role: ChainRole::Relay,
                    tunnel_type: TunnelType::WireGuard,
                },
                ChainHop {
                    node_tag: "terminal-node".to_string(),
                    role: ChainRole::Terminal,
                    tunnel_type: TunnelType::WireGuard,
                },
            ],
            rules: vec![],
            exit_egress: "pia-us-east".to_string(),
            allow_transitive: false,
        };

        let runtime = Runtime::new().unwrap();
        runtime.block_on(async {
            chain_manager.create_chain(config).await.unwrap();
        });

        let handler = ChainHandler::with_chain_manager(chain_manager);
        let rule_engine = create_rule_engine_with_chain("test-chain", 10);

        let result = handler.handle_dscp_packet(10, &rule_engine);
        match result {
            ChainRoutingResult::Forward {
                outbound,
                dscp,
                routing_mark,
            } => {
                assert_eq!(outbound, "peer-terminal-node");
                assert_eq!(dscp, 10);
                assert!(routing_mark > 0);
            }
            _ => panic!("Expected Forward, got {:?}", result),
        }
    }

    #[test]
    fn test_no_role_blocks() {
        // Create chain manager for a node that's not in the chain
        let chain_manager = Arc::new(ChainManager::new("other-node".to_string()));

        let config = ChainConfig {
            tag: "test-chain".to_string(),
            description: "Test chain".to_string(),
            dscp_value: 10,
            hops: vec![
                ChainHop {
                    node_tag: "entry-node".to_string(),
                    role: ChainRole::Entry,
                    tunnel_type: TunnelType::WireGuard,
                },
                ChainHop {
                    node_tag: "terminal-node".to_string(),
                    role: ChainRole::Terminal,
                    tunnel_type: TunnelType::WireGuard,
                },
            ],
            rules: vec![],
            exit_egress: "pia-us-east".to_string(),
            allow_transitive: false,
        };

        let runtime = Runtime::new().unwrap();
        runtime.block_on(async {
            chain_manager.create_chain(config).await.unwrap();
        });

        let handler = ChainHandler::with_chain_manager(chain_manager);
        let rule_engine = create_rule_engine_with_chain("test-chain", 10);

        let result = handler.handle_dscp_packet(10, &rule_engine);
        assert!(result.is_block());
        if let ChainRoutingResult::Block { reason } = result {
            assert!(reason.contains("no-role"));
        }
    }

    // =========================================================================
    // Chain Entry Tests
    // =========================================================================

    #[test]
    fn test_chain_entry_no_manager() {
        let handler = ChainHandler::new();
        let mark = ChainMark::from_dscp(10).unwrap();

        let result = handler.handle_chain_entry("test-chain", mark);
        assert!(result.is_block());
        if let ChainRoutingResult::Block { reason } = result {
            assert!(reason.contains("no-chain-manager"));
        }
    }

    #[test]
    fn test_chain_entry_with_manager() {
        let chain_manager = Arc::new(ChainManager::new("entry-node".to_string()));

        let config = ChainConfig {
            tag: "test-chain".to_string(),
            description: "Test chain".to_string(),
            dscp_value: 10,
            hops: vec![
                ChainHop {
                    node_tag: "entry-node".to_string(),
                    role: ChainRole::Entry,
                    tunnel_type: TunnelType::WireGuard,
                },
                ChainHop {
                    node_tag: "terminal-node".to_string(),
                    role: ChainRole::Terminal,
                    tunnel_type: TunnelType::WireGuard,
                },
            ],
            rules: vec![],
            exit_egress: "pia-us-east".to_string(),
            allow_transitive: false,
        };

        let runtime = Runtime::new().unwrap();
        runtime.block_on(async {
            chain_manager.create_chain(config).await.unwrap();
        });

        let handler = ChainHandler::with_chain_manager(chain_manager);
        let mark = ChainMark::from_dscp(10).unwrap();

        let result = handler.handle_chain_entry("test-chain", mark);
        match result {
            ChainRoutingResult::Forward {
                outbound,
                dscp,
                routing_mark,
            } => {
                assert_eq!(outbound, "peer-terminal-node");
                assert_eq!(dscp, 10);
                assert_eq!(routing_mark, mark.routing_mark);
            }
            _ => panic!("Expected Forward, got {:?}", result),
        }
    }

    #[test]
    fn test_chain_entry_no_next_hop() {
        // Create chain manager for terminal node (no next hop)
        let chain_manager = Arc::new(ChainManager::new("terminal-node".to_string()));

        let config = ChainConfig {
            tag: "test-chain".to_string(),
            description: "Test chain".to_string(),
            dscp_value: 10,
            hops: vec![
                ChainHop {
                    node_tag: "entry-node".to_string(),
                    role: ChainRole::Entry,
                    tunnel_type: TunnelType::WireGuard,
                },
                ChainHop {
                    node_tag: "terminal-node".to_string(),
                    role: ChainRole::Terminal,
                    tunnel_type: TunnelType::WireGuard,
                },
            ],
            rules: vec![],
            exit_egress: "pia-us-east".to_string(),
            allow_transitive: false,
        };

        let runtime = Runtime::new().unwrap();
        runtime.block_on(async {
            chain_manager.create_chain(config).await.unwrap();
        });

        let handler = ChainHandler::with_chain_manager(chain_manager);
        let mark = ChainMark::from_dscp(10).unwrap();

        // Terminal nodes have no next hop
        let result = handler.handle_chain_entry("test-chain", mark);
        assert!(result.is_block());
        if let ChainRoutingResult::Block { reason } = result {
            assert!(reason.contains("no-next-hop"));
        }
    }

    // =========================================================================
    // Edge Case Tests
    // =========================================================================

    #[test]
    fn test_multiple_dscp_values() {
        let chain_manager = Arc::new(ChainManager::new("entry-node".to_string()));

        // Create two chains with different DSCP values
        let config1 = ChainConfig {
            tag: "chain-1".to_string(),
            description: "Chain 1".to_string(),
            dscp_value: 10,
            hops: vec![
                ChainHop {
                    node_tag: "entry-node".to_string(),
                    role: ChainRole::Entry,
                    tunnel_type: TunnelType::WireGuard,
                },
                ChainHop {
                    node_tag: "terminal-1".to_string(),
                    role: ChainRole::Terminal,
                    tunnel_type: TunnelType::WireGuard,
                },
            ],
            rules: vec![],
            exit_egress: "exit-1".to_string(),
            allow_transitive: false,
        };

        let config2 = ChainConfig {
            tag: "chain-2".to_string(),
            description: "Chain 2".to_string(),
            dscp_value: 20,
            hops: vec![
                ChainHop {
                    node_tag: "entry-node".to_string(),
                    role: ChainRole::Entry,
                    tunnel_type: TunnelType::WireGuard,
                },
                ChainHop {
                    node_tag: "terminal-2".to_string(),
                    role: ChainRole::Terminal,
                    tunnel_type: TunnelType::WireGuard,
                },
            ],
            rules: vec![],
            exit_egress: "exit-2".to_string(),
            allow_transitive: false,
        };

        let runtime = Runtime::new().unwrap();
        runtime.block_on(async {
            chain_manager.create_chain(config1).await.unwrap();
            chain_manager.create_chain(config2).await.unwrap();
        });

        let handler = ChainHandler::with_chain_manager(chain_manager);

        // Create rule engine with both chains
        let mut builder = RoutingSnapshotBuilder::new();
        builder.add_chain_with_dscp("chain-1", 10).unwrap();
        builder.add_chain_with_dscp("chain-2", 20).unwrap();
        let snapshot = builder.default_outbound("direct").build().unwrap();
        let rule_engine = Arc::new(RuleEngine::new(snapshot));

        // Check DSCP 10 routes to chain-1
        let result = handler.handle_dscp_packet(10, &rule_engine);
        if let ChainRoutingResult::Forward { outbound, dscp, .. } = result {
            assert_eq!(outbound, "peer-terminal-1");
            assert_eq!(dscp, 10);
        } else {
            panic!("Expected Forward for DSCP 10");
        }

        // Check DSCP 20 routes to chain-2
        let result = handler.handle_dscp_packet(20, &rule_engine);
        if let ChainRoutingResult::Forward { outbound, dscp, .. } = result {
            assert_eq!(outbound, "peer-terminal-2");
            assert_eq!(dscp, 20);
        } else {
            panic!("Expected Forward for DSCP 20");
        }
    }

    #[test]
    fn test_dscp_boundary_values() {
        let handler = ChainHandler::new();
        let rule_engine = create_test_rule_engine();

        // DSCP 0 is not a chain
        assert_eq!(
            handler.handle_dscp_packet(0, &rule_engine),
            ChainRoutingResult::NotChain
        );

        // DSCP 1-63 without registered chains should block
        for dscp in 1..=63 {
            let result = handler.handle_dscp_packet(dscp, &rule_engine);
            assert!(
                result.is_block(),
                "DSCP {} should be blocked without registered chain",
                dscp
            );
        }
    }
}
