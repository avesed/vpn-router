//! Firewall mark (fwmark) and DSCP routing utilities.
//!
//! This module provides constants and utilities for integrating with
//! the Linux kernel's routing mark system used for multi-hop chain routing.
//!
//! # Architecture
//!
//! The vpn-router project uses DSCP values and fwmark (firewall marks) for
//! multi-hop chain routing:
//!
//! ```text
//! Entry Node:    sing-box routing_mark -> iptables DSCP set -> WireGuard
//! Relay Node:    Transparent passthrough (Linux preserves DSCP)
//! Terminal Node: iptables DSCP read -> fwmark -> policy routing -> egress
//! ```
//!
//! # DSCP Values
//!
//! DSCP values 1-63 are available for chain routing (0 is reserved).
//! Each DSCP value maps to:
//! - A routing mark: `ENTRY_ROUTING_MARK_BASE + dscp_value`
//! - A routing table: `DSCP_TERMINAL_TABLE_MIN + dscp_value`
//!
//! # Example
//!
//! ```
//! use rust_router::rules::fwmark::{ChainMark, FwmarkRouter, DSCP_MIN, DSCP_MAX};
//!
//! // Create a chain mark from DSCP value
//! let mark = ChainMark::from_dscp(5).expect("valid DSCP");
//! assert_eq!(mark.dscp_value, 5);
//! assert_eq!(mark.routing_mark, 0x300 + 5); // 773
//! assert_eq!(mark.routing_table, 300 + 5);  // 305
//!
//! // Build a fwmark router with chains
//! let router = FwmarkRouter::builder()
//!     .add_chain("us-stream").unwrap()
//!     .add_chain("jp-gaming").unwrap()
//!     .build();
//!
//! assert_eq!(router.chain_count(), 2);
//! assert!(router.is_chain("us-stream"));
//! assert!(!router.is_chain("direct"));
//! ```

use std::collections::HashMap;

use crate::error::RuleError;

/// Base routing mark for DSCP-based chain routing.
///
/// Entry nodes use routing marks starting from this base:
/// `routing_mark = ENTRY_ROUTING_MARK_BASE + dscp_value`
///
/// This matches the Python implementation's `ENTRY_ROUTING_MARK_BASE = 0x300` (768).
///
/// Note: The Python implementation uses 0x100 (256) as default but can be configured.
/// For Rust, we use 0x300 (768) to avoid conflicts with ECMP marks (200-299).
pub const ENTRY_ROUTING_MARK_BASE: u32 = 0x300; // 768

/// Minimum valid DSCP value for chain routing.
///
/// DSCP 0 is reserved (Best Effort / default).
pub const DSCP_MIN: u8 = 1;

/// Maximum valid DSCP value for chain routing.
///
/// DSCP uses 6 bits, so valid range is 0-63.
pub const DSCP_MAX: u8 = 63;

/// Maximum number of chains (limited by DSCP range).
pub const MAX_CHAINS: usize = (DSCP_MAX - DSCP_MIN + 1) as usize; // 63

/// Routing table ranges used by vpn-router.
///
/// These constants define the non-overlapping table number ranges for
/// different routing purposes.
pub mod tables {
    /// TPROXY local delivery table.
    pub const TPROXY: u32 = 100;

    /// ECMP outbound groups minimum table number.
    pub const ECMP_MIN: u32 = 200;

    /// ECMP outbound groups maximum table number.
    pub const ECMP_MAX: u32 = 299;

    /// DSCP terminal routing minimum table number.
    ///
    /// Terminal nodes use tables 300-363 for DSCP-based routing.
    pub const DSCP_TERMINAL_MIN: u32 = 300;

    /// DSCP terminal routing maximum table number.
    pub const DSCP_TERMINAL_MAX: u32 = 363;

    /// Relay node forwarding minimum table number.
    pub const RELAY_MIN: u32 = 400;

    /// Relay node forwarding maximum table number.
    pub const RELAY_MAX: u32 = 463;

    /// Peer node tunnel minimum table number.
    pub const PEER_MIN: u32 = 500;

    /// Peer node tunnel maximum table number.
    pub const PEER_MAX: u32 = 599;
}

/// Reserved DSCP values (commonly used for `QoS`).
///
/// These values should be avoided for chain routing to prevent conflicts
/// with network `QoS` policies.
///
/// Includes:
/// - 0: BE (Best Effort, default)
/// - 10, 12, 14: AF11, AF12, AF13 (Assured Forwarding Class 1)
/// - 18, 20, 22: AF21, AF22, AF23 (Assured Forwarding Class 2)
/// - 26, 28, 30: AF31, AF32, AF33 (Assured Forwarding Class 3)
/// - 34, 36, 38: AF41, AF42, AF43 (Assured Forwarding Class 4)
/// - 46: EF (Expedited Forwarding)
pub const RESERVED_DSCP_VALUES: &[u8] = &[
    0, // Default (BE - Best Effort)
    10, 12, 14, // AF11, AF12, AF13 (Assured Forwarding Class 1)
    18, 20, 22, // AF21, AF22, AF23 (Assured Forwarding Class 2)
    26, 28, 30, // AF31, AF32, AF33 (Assured Forwarding Class 3)
    34, 36, 38, // AF41, AF42, AF43 (Assured Forwarding Class 4)
    46, // EF (Expedited Forwarding)
];

/// Chain routing mark information.
///
/// Encapsulates all the routing information needed for a chain:
/// - DSCP value (1-63)
/// - Routing mark for sing-box outbound
/// - Routing table for policy routing
///
/// # Example
///
/// ```
/// use rust_router::rules::fwmark::ChainMark;
///
/// let mark = ChainMark::from_dscp(10).expect("valid DSCP");
/// assert_eq!(mark.dscp_value, 10);
/// assert_eq!(mark.routing_mark, 0x300 + 10);
/// assert_eq!(mark.routing_table, 300 + 10);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChainMark {
    /// DSCP value (1-63).
    pub dscp_value: u8,

    /// Corresponding routing mark.
    ///
    /// Computed as `ENTRY_ROUTING_MARK_BASE + dscp_value`.
    pub routing_mark: u32,

    /// Routing table number.
    ///
    /// Computed as `tables::DSCP_TERMINAL_MIN + dscp_value`.
    pub routing_table: u32,
}

impl ChainMark {
    /// Create a new `ChainMark` from a DSCP value.
    ///
    /// # Arguments
    ///
    /// * `dscp_value` - DSCP value (must be 1-63)
    ///
    /// # Returns
    ///
    /// `Some(ChainMark)` if the DSCP value is valid, `None` otherwise.
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::rules::fwmark::ChainMark;
    ///
    /// // Valid DSCP
    /// let mark = ChainMark::from_dscp(5).unwrap();
    /// assert_eq!(mark.dscp_value, 5);
    ///
    /// // Invalid DSCP (0 is reserved)
    /// assert!(ChainMark::from_dscp(0).is_none());
    ///
    /// // Invalid DSCP (64 is out of range)
    /// assert!(ChainMark::from_dscp(64).is_none());
    /// ```
    #[must_use]
    pub fn from_dscp(dscp_value: u8) -> Option<Self> {
        if !(DSCP_MIN..=DSCP_MAX).contains(&dscp_value) {
            return None;
        }
        Some(Self {
            dscp_value,
            routing_mark: ENTRY_ROUTING_MARK_BASE + u32::from(dscp_value),
            routing_table: tables::DSCP_TERMINAL_MIN + u32::from(dscp_value),
        })
    }

    /// Create a `ChainMark` from a routing mark.
    ///
    /// Validates that the mark is within the valid range for chain routing.
    ///
    /// # Arguments
    ///
    /// * `mark` - Routing mark value
    ///
    /// # Returns
    ///
    /// `Some(ChainMark)` if the mark corresponds to a valid chain, `None` otherwise.
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::rules::fwmark::{ChainMark, ENTRY_ROUTING_MARK_BASE};
    ///
    /// // Valid routing mark (corresponds to DSCP 5)
    /// let mark = ChainMark::from_routing_mark(ENTRY_ROUTING_MARK_BASE + 5).unwrap();
    /// assert_eq!(mark.dscp_value, 5);
    ///
    /// // Invalid routing mark (below range)
    /// assert!(ChainMark::from_routing_mark(ENTRY_ROUTING_MARK_BASE).is_none());
    ///
    /// // Invalid routing mark (above range)
    /// assert!(ChainMark::from_routing_mark(ENTRY_ROUTING_MARK_BASE + 100).is_none());
    /// ```
    #[must_use]
    pub fn from_routing_mark(mark: u32) -> Option<Self> {
        if mark <= ENTRY_ROUTING_MARK_BASE
            || mark > ENTRY_ROUTING_MARK_BASE + u32::from(DSCP_MAX)
        {
            return None;
        }
        let dscp_value = (mark - ENTRY_ROUTING_MARK_BASE) as u8;
        Self::from_dscp(dscp_value)
    }

    /// Create a `ChainMark` from a routing table number.
    ///
    /// Validates that the table is within the DSCP terminal range.
    ///
    /// # Arguments
    ///
    /// * `table` - Routing table number
    ///
    /// # Returns
    ///
    /// `Some(ChainMark)` if the table corresponds to a valid chain, `None` otherwise.
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::rules::fwmark::{ChainMark, tables};
    ///
    /// // Valid routing table (corresponds to DSCP 5)
    /// let mark = ChainMark::from_routing_table(tables::DSCP_TERMINAL_MIN + 5).unwrap();
    /// assert_eq!(mark.dscp_value, 5);
    ///
    /// // Invalid routing table (outside DSCP range)
    /// assert!(ChainMark::from_routing_table(tables::ECMP_MIN).is_none());
    /// ```
    #[must_use]
    pub fn from_routing_table(table: u32) -> Option<Self> {
        if table <= tables::DSCP_TERMINAL_MIN || table > tables::DSCP_TERMINAL_MAX {
            return None;
        }
        let dscp_value = (table - tables::DSCP_TERMINAL_MIN) as u8;
        Self::from_dscp(dscp_value)
    }

    /// Check if this DSCP value is reserved (commonly used for `QoS`).
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::rules::fwmark::ChainMark;
    ///
    /// // DSCP 46 (EF) is reserved
    /// let mark = ChainMark::from_dscp(46).unwrap();
    /// assert!(mark.is_reserved());
    ///
    /// // DSCP 5 is not reserved
    /// let mark = ChainMark::from_dscp(5).unwrap();
    /// assert!(!mark.is_reserved());
    /// ```
    #[must_use]
    pub fn is_reserved(&self) -> bool {
        RESERVED_DSCP_VALUES.contains(&self.dscp_value)
    }
}

impl std::fmt::Display for ChainMark {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ChainMark(dscp={}, mark=0x{:x}, table={})",
            self.dscp_value, self.routing_mark, self.routing_table
        )
    }
}

/// Fwmark router for chain-based routing.
///
/// Maps chain tags to their corresponding `ChainMark` information,
/// enabling routing decisions based on chain membership.
///
/// # Example
///
/// ```
/// use rust_router::rules::fwmark::FwmarkRouter;
///
/// let router = FwmarkRouter::builder()
///     .add_chain("us-stream").unwrap()
///     .add_chain_with_dscp("jp-gaming", 20).unwrap()
///     .default_mark(0)
///     .build();
///
/// // Check chain membership
/// assert!(router.is_chain("us-stream"));
/// assert!(router.is_chain("jp-gaming"));
/// assert!(!router.is_chain("direct"));
///
/// // Get routing marks
/// let mark = router.get_routing_mark("us-stream");
/// assert!(mark.is_some());
/// ```
#[derive(Debug, Clone)]
pub struct FwmarkRouter {
    /// Chain tag -> `ChainMark` mapping.
    chains: HashMap<String, ChainMark>,

    /// Default mark for non-chain traffic (None = no mark).
    default_mark: Option<u32>,
}

impl FwmarkRouter {
    /// Create a new builder for `FwmarkRouter`.
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::rules::fwmark::FwmarkRouter;
    ///
    /// let router = FwmarkRouter::builder()
    ///     .add_chain("my-chain").unwrap()
    ///     .build();
    /// ```
    #[must_use]
    pub fn builder() -> FwmarkRouterBuilder {
        FwmarkRouterBuilder::new()
    }

    /// Create an empty router with no chains.
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::rules::fwmark::FwmarkRouter;
    ///
    /// let router = FwmarkRouter::empty();
    /// assert_eq!(router.chain_count(), 0);
    /// ```
    #[must_use]
    pub fn empty() -> Self {
        Self {
            chains: HashMap::new(),
            default_mark: None,
        }
    }

    /// Get the `ChainMark` for a chain tag.
    ///
    /// # Arguments
    ///
    /// * `chain_tag` - The chain tag to look up
    ///
    /// # Returns
    ///
    /// `Some(&ChainMark)` if the chain exists, `None` otherwise.
    #[must_use]
    pub fn get_chain_mark(&self, chain_tag: &str) -> Option<&ChainMark> {
        self.chains.get(chain_tag)
    }

    /// Get the routing mark for an outbound.
    ///
    /// Returns the chain's routing mark if it's a chain, or the default mark otherwise.
    ///
    /// # Arguments
    ///
    /// * `outbound` - The outbound tag to look up
    ///
    /// # Returns
    ///
    /// - `Some(routing_mark)` if this is a chain outbound
    /// - `self.default_mark` if not a chain (may be `None`)
    #[must_use]
    pub fn get_routing_mark(&self, outbound: &str) -> Option<u32> {
        self.chains
            .get(outbound)
            .map(|m| m.routing_mark)
            .or(self.default_mark)
    }

    /// Check if an outbound is a chain.
    ///
    /// # Arguments
    ///
    /// * `outbound` - The outbound tag to check
    ///
    /// # Returns
    ///
    /// `true` if the outbound is a registered chain, `false` otherwise.
    #[must_use]
    pub fn is_chain(&self, outbound: &str) -> bool {
        self.chains.contains_key(outbound)
    }

    /// Iterate over all registered chains.
    ///
    /// # Returns
    ///
    /// Iterator yielding `(chain_tag, chain_mark)` pairs.
    pub fn chains(&self) -> impl Iterator<Item = (&str, &ChainMark)> {
        self.chains.iter().map(|(k, v)| (k.as_str(), v))
    }

    /// Get the number of registered chains.
    #[must_use]
    pub fn chain_count(&self) -> usize {
        self.chains.len()
    }

    /// Get the default routing mark.
    #[must_use]
    pub fn default_mark(&self) -> Option<u32> {
        self.default_mark
    }

    /// Check if the router has any chains registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.chains.is_empty()
    }
}

impl Default for FwmarkRouter {
    fn default() -> Self {
        Self::empty()
    }
}

/// Builder for `FwmarkRouter`.
///
/// Provides a fluent API for constructing a `FwmarkRouter` with chains
/// and configuration options.
///
/// # Example
///
/// ```
/// use rust_router::rules::fwmark::FwmarkRouterBuilder;
///
/// let router = FwmarkRouterBuilder::new()
///     .add_chain("chain-a").unwrap()
///     .add_chain("chain-b").unwrap()
///     .add_chain_with_dscp("chain-c", 50).unwrap()
///     .default_mark(0)
///     .build();
///
/// assert_eq!(router.chain_count(), 3);
/// ```
#[derive(Debug, Clone)]
pub struct FwmarkRouterBuilder {
    /// Chain tag -> `ChainMark` mapping being built.
    chains: HashMap<String, ChainMark>,

    /// Default mark for non-chain traffic.
    default_mark: Option<u32>,

    /// Next auto-assigned DSCP value.
    next_dscp: u8,

    /// DSCP values already in use.
    used_dscp: std::collections::HashSet<u8>,
}

impl FwmarkRouterBuilder {
    /// Create a new builder.
    #[must_use]
    pub fn new() -> Self {
        Self {
            chains: HashMap::new(),
            default_mark: None,
            next_dscp: DSCP_MIN,
            used_dscp: std::collections::HashSet::new(),
        }
    }

    /// Register a chain with auto-assigned DSCP value.
    ///
    /// DSCP values are assigned sequentially starting from `DSCP_MIN` (1).
    /// Reserved DSCP values are skipped during auto-assignment.
    ///
    /// # Arguments
    ///
    /// * `tag` - The chain tag (must be unique)
    ///
    /// # Errors
    ///
    /// Returns `RuleError::DuplicateChain` if the tag already exists.
    /// Returns `RuleError::MaxChainsReached` if 63 chains are already registered.
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::rules::fwmark::FwmarkRouter;
    ///
    /// let router = FwmarkRouter::builder()
    ///     .add_chain("chain-1").unwrap()
    ///     .add_chain("chain-2").unwrap()
    ///     .build();
    ///
    /// // Chains get sequential DSCP values
    /// let mark1 = router.get_chain_mark("chain-1").unwrap();
    /// let mark2 = router.get_chain_mark("chain-2").unwrap();
    /// assert!(mark2.dscp_value > mark1.dscp_value);
    /// ```
    pub fn add_chain(mut self, tag: impl Into<String>) -> Result<Self, RuleError> {
        let tag = tag.into();

        // Check for duplicate
        if self.chains.contains_key(&tag) {
            return Err(RuleError::DuplicateChain(tag));
        }

        // Check max chains limit
        if self.chains.len() >= MAX_CHAINS {
            return Err(RuleError::MaxChainsReached);
        }

        // Find next available DSCP value (skip reserved and used values)
        while self.next_dscp <= DSCP_MAX {
            if !RESERVED_DSCP_VALUES.contains(&self.next_dscp)
                && !self.used_dscp.contains(&self.next_dscp)
            {
                break;
            }
            self.next_dscp += 1;
        }

        // Check if we ran out of DSCP values
        if self.next_dscp > DSCP_MAX {
            return Err(RuleError::MaxChainsReached);
        }

        let dscp = self.next_dscp;
        self.next_dscp += 1;

        self.add_chain_with_dscp_internal(tag, dscp)
    }

    /// Register a chain with a specific DSCP value.
    ///
    /// # Arguments
    ///
    /// * `tag` - The chain tag (must be unique)
    /// * `dscp` - The DSCP value (must be 1-63 and not already used)
    ///
    /// # Errors
    ///
    /// Returns `RuleError::DuplicateChain` if the tag already exists.
    /// Returns `RuleError::DscpOutOfRange` if the DSCP value is invalid.
    /// Returns `RuleError::DscpInUse` if the DSCP value is already used by another chain.
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::rules::fwmark::FwmarkRouter;
    ///
    /// let router = FwmarkRouter::builder()
    ///     .add_chain_with_dscp("high-priority", 50).unwrap()
    ///     .build();
    ///
    /// let mark = router.get_chain_mark("high-priority").unwrap();
    /// assert_eq!(mark.dscp_value, 50);
    /// ```
    pub fn add_chain_with_dscp(
        self,
        tag: impl Into<String>,
        dscp: u8,
    ) -> Result<Self, RuleError> {
        let tag = tag.into();

        // Check for duplicate tag
        if self.chains.contains_key(&tag) {
            return Err(RuleError::DuplicateChain(tag));
        }

        // Validate DSCP range
        if !(DSCP_MIN..=DSCP_MAX).contains(&dscp) {
            return Err(RuleError::DscpOutOfRange(dscp));
        }

        // Check if DSCP is already in use
        if self.used_dscp.contains(&dscp) {
            return Err(RuleError::DscpInUse(dscp));
        }

        self.add_chain_with_dscp_internal(tag, dscp)
    }

    /// Internal helper to add a chain with a validated DSCP value.
    fn add_chain_with_dscp_internal(
        mut self,
        tag: String,
        dscp: u8,
    ) -> Result<Self, RuleError> {
        let chain_mark =
            ChainMark::from_dscp(dscp).ok_or(RuleError::DscpOutOfRange(dscp))?;

        self.used_dscp.insert(dscp);
        self.chains.insert(tag, chain_mark);

        Ok(self)
    }

    /// Set the default routing mark for non-chain traffic.
    ///
    /// # Arguments
    ///
    /// * `mark` - The default routing mark
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::rules::fwmark::FwmarkRouter;
    ///
    /// let router = FwmarkRouter::builder()
    ///     .default_mark(0)
    ///     .build();
    ///
    /// assert_eq!(router.default_mark(), Some(0));
    /// ```
    #[must_use]
    pub fn default_mark(mut self, mark: u32) -> Self {
        self.default_mark = Some(mark);
        self
    }

    /// Build the `FwmarkRouter`.
    ///
    /// Consumes the builder and returns the configured router.
    #[must_use]
    pub fn build(self) -> FwmarkRouter {
        FwmarkRouter {
            chains: self.chains,
            default_mark: self.default_mark,
        }
    }
}

impl Default for FwmarkRouterBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Convert a DSCP value to a routing mark.
///
/// # Arguments
///
/// * `dscp` - DSCP value (1-63)
///
/// # Returns
///
/// `Some(routing_mark)` if the DSCP value is valid, `None` otherwise.
///
/// # Example
///
/// ```
/// use rust_router::rules::fwmark::dscp_to_routing_mark;
///
/// assert_eq!(dscp_to_routing_mark(5), Some(0x300 + 5));
/// assert_eq!(dscp_to_routing_mark(0), None);
/// assert_eq!(dscp_to_routing_mark(64), None);
/// ```
#[must_use]
pub fn dscp_to_routing_mark(dscp: u8) -> Option<u32> {
    ChainMark::from_dscp(dscp).map(|m| m.routing_mark)
}

/// Convert a routing mark to a DSCP value.
///
/// # Arguments
///
/// * `mark` - Routing mark value
///
/// # Returns
///
/// `Some(dscp_value)` if the mark corresponds to a valid chain, `None` otherwise.
///
/// # Example
///
/// ```
/// use rust_router::rules::fwmark::{routing_mark_to_dscp, ENTRY_ROUTING_MARK_BASE};
///
/// assert_eq!(routing_mark_to_dscp(ENTRY_ROUTING_MARK_BASE + 5), Some(5));
/// assert_eq!(routing_mark_to_dscp(ENTRY_ROUTING_MARK_BASE), None);
/// assert_eq!(routing_mark_to_dscp(100), None);
/// ```
#[must_use]
pub fn routing_mark_to_dscp(mark: u32) -> Option<u8> {
    ChainMark::from_routing_mark(mark).map(|m| m.dscp_value)
}

/// Convert a DSCP value to a routing table number.
///
/// # Arguments
///
/// * `dscp` - DSCP value (1-63)
///
/// # Returns
///
/// `Some(table_number)` if the DSCP value is valid, `None` otherwise.
///
/// # Example
///
/// ```
/// use rust_router::rules::fwmark::dscp_to_routing_table;
///
/// assert_eq!(dscp_to_routing_table(5), Some(305));
/// assert_eq!(dscp_to_routing_table(0), None);
/// ```
#[must_use]
pub fn dscp_to_routing_table(dscp: u8) -> Option<u32> {
    ChainMark::from_dscp(dscp).map(|m| m.routing_table)
}

/// Check if a routing table is in the DSCP terminal range.
///
/// # Arguments
///
/// * `table` - Routing table number
///
/// # Returns
///
/// `true` if the table is in the range 301-363.
///
/// # Example
///
/// ```
/// use rust_router::rules::fwmark::is_dscp_terminal_table;
///
/// assert!(is_dscp_terminal_table(305));
/// assert!(is_dscp_terminal_table(363));
/// assert!(!is_dscp_terminal_table(300)); // Boundary
/// assert!(!is_dscp_terminal_table(200)); // ECMP range
/// ```
#[must_use]
pub const fn is_dscp_terminal_table(table: u32) -> bool {
    table > tables::DSCP_TERMINAL_MIN && table <= tables::DSCP_TERMINAL_MAX
}

/// Check if a routing table is in the ECMP range.
///
/// # Arguments
///
/// * `table` - Routing table number
///
/// # Returns
///
/// `true` if the table is in the range 200-299.
///
/// # Example
///
/// ```
/// use rust_router::rules::fwmark::is_ecmp_table;
///
/// assert!(is_ecmp_table(200));
/// assert!(is_ecmp_table(250));
/// assert!(is_ecmp_table(299));
/// assert!(!is_ecmp_table(300)); // DSCP range
/// ```
#[must_use]
pub const fn is_ecmp_table(table: u32) -> bool {
    table >= tables::ECMP_MIN && table <= tables::ECMP_MAX
}

/// Check if a routing table is in the relay range.
///
/// # Arguments
///
/// * `table` - Routing table number
///
/// # Returns
///
/// `true` if the table is in the range 400-463.
///
/// # Example
///
/// ```
/// use rust_router::rules::fwmark::is_relay_table;
///
/// assert!(is_relay_table(400));
/// assert!(is_relay_table(450));
/// assert!(!is_relay_table(500)); // Peer range
/// ```
#[must_use]
pub const fn is_relay_table(table: u32) -> bool {
    table >= tables::RELAY_MIN && table <= tables::RELAY_MAX
}

/// Check if a routing table is in the peer range.
///
/// # Arguments
///
/// * `table` - Routing table number
///
/// # Returns
///
/// `true` if the table is in the range 500-599.
///
/// # Example
///
/// ```
/// use rust_router::rules::fwmark::is_peer_table;
///
/// assert!(is_peer_table(500));
/// assert!(is_peer_table(550));
/// assert!(is_peer_table(599));
/// assert!(!is_peer_table(600));
/// ```
#[must_use]
pub const fn is_peer_table(table: u32) -> bool {
    table >= tables::PEER_MIN && table <= tables::PEER_MAX
}

/// Check if a DSCP value is reserved (commonly used for `QoS`).
///
/// # Arguments
///
/// * `dscp` - DSCP value
///
/// # Returns
///
/// `true` if the DSCP value is in the reserved list.
///
/// # Example
///
/// ```
/// use rust_router::rules::fwmark::is_reserved_dscp;
///
/// assert!(is_reserved_dscp(0));  // Best Effort
/// assert!(is_reserved_dscp(46)); // Expedited Forwarding
/// assert!(!is_reserved_dscp(5)); // Not reserved
/// ```
#[must_use]
pub fn is_reserved_dscp(dscp: u8) -> bool {
    RESERVED_DSCP_VALUES.contains(&dscp)
}

/// Check if a DSCP value is valid for chain routing.
///
/// A DSCP value is valid if it's in the range 1-63.
/// Note: This does not check if the value is reserved.
///
/// # Arguments
///
/// * `dscp` - DSCP value
///
/// # Returns
///
/// `true` if the DSCP value is in the valid range.
///
/// # Example
///
/// ```
/// use rust_router::rules::fwmark::is_valid_dscp;
///
/// assert!(is_valid_dscp(1));
/// assert!(is_valid_dscp(63));
/// assert!(!is_valid_dscp(0));  // Reserved
/// assert!(!is_valid_dscp(64)); // Out of range
/// ```
#[must_use]
pub const fn is_valid_dscp(dscp: u8) -> bool {
    dscp >= DSCP_MIN && dscp <= DSCP_MAX
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // ChainMark Tests
    // ========================================================================

    #[test]
    fn test_chain_mark_from_dscp_valid() {
        let mark = ChainMark::from_dscp(5).unwrap();
        assert_eq!(mark.dscp_value, 5);
        assert_eq!(mark.routing_mark, ENTRY_ROUTING_MARK_BASE + 5);
        assert_eq!(mark.routing_table, tables::DSCP_TERMINAL_MIN + 5);
    }

    #[test]
    fn test_chain_mark_from_dscp_boundary() {
        // Minimum valid
        let mark = ChainMark::from_dscp(DSCP_MIN).unwrap();
        assert_eq!(mark.dscp_value, DSCP_MIN);

        // Maximum valid
        let mark = ChainMark::from_dscp(DSCP_MAX).unwrap();
        assert_eq!(mark.dscp_value, DSCP_MAX);
    }

    #[test]
    fn test_chain_mark_from_dscp_invalid() {
        // Zero is reserved
        assert!(ChainMark::from_dscp(0).is_none());

        // Above maximum
        assert!(ChainMark::from_dscp(64).is_none());
        assert!(ChainMark::from_dscp(255).is_none());
    }

    #[test]
    fn test_chain_mark_from_routing_mark_valid() {
        let mark = ChainMark::from_routing_mark(ENTRY_ROUTING_MARK_BASE + 10).unwrap();
        assert_eq!(mark.dscp_value, 10);
        assert_eq!(mark.routing_mark, ENTRY_ROUTING_MARK_BASE + 10);
    }

    #[test]
    fn test_chain_mark_from_routing_mark_invalid() {
        // At base (no DSCP offset)
        assert!(ChainMark::from_routing_mark(ENTRY_ROUTING_MARK_BASE).is_none());

        // Below base
        assert!(ChainMark::from_routing_mark(100).is_none());

        // Above maximum
        assert!(ChainMark::from_routing_mark(ENTRY_ROUTING_MARK_BASE + 100).is_none());
    }

    #[test]
    fn test_chain_mark_from_routing_table_valid() {
        let mark = ChainMark::from_routing_table(tables::DSCP_TERMINAL_MIN + 15).unwrap();
        assert_eq!(mark.dscp_value, 15);
        assert_eq!(mark.routing_table, tables::DSCP_TERMINAL_MIN + 15);
    }

    #[test]
    fn test_chain_mark_from_routing_table_invalid() {
        // At minimum (no DSCP offset)
        assert!(ChainMark::from_routing_table(tables::DSCP_TERMINAL_MIN).is_none());

        // In ECMP range
        assert!(ChainMark::from_routing_table(250).is_none());

        // Above maximum
        assert!(ChainMark::from_routing_table(400).is_none());
    }

    #[test]
    fn test_chain_mark_is_reserved() {
        // EF (46) is reserved
        let mark = ChainMark::from_dscp(46).unwrap();
        assert!(mark.is_reserved());

        // 5 is not reserved
        let mark = ChainMark::from_dscp(5).unwrap();
        assert!(!mark.is_reserved());

        // AF11 (10) is reserved
        let mark = ChainMark::from_dscp(10).unwrap();
        assert!(mark.is_reserved());
    }

    #[test]
    fn test_chain_mark_display() {
        let mark = ChainMark::from_dscp(5).unwrap();
        let display = format!("{}", mark);
        assert!(display.contains("dscp=5"));
        assert!(display.contains("mark=0x"));
        assert!(display.contains("table=305"));
    }

    #[test]
    fn test_chain_mark_equality() {
        let mark1 = ChainMark::from_dscp(5).unwrap();
        let mark2 = ChainMark::from_dscp(5).unwrap();
        let mark3 = ChainMark::from_dscp(10).unwrap();

        assert_eq!(mark1, mark2);
        assert_ne!(mark1, mark3);
    }

    // ========================================================================
    // FwmarkRouter Tests
    // ========================================================================

    #[test]
    fn test_fwmark_router_empty() {
        let router = FwmarkRouter::empty();
        assert!(router.is_empty());
        assert_eq!(router.chain_count(), 0);
        assert!(router.default_mark().is_none());
    }

    #[test]
    fn test_fwmark_router_builder_add_chain() {
        let router = FwmarkRouter::builder()
            .add_chain("chain-a")
            .unwrap()
            .add_chain("chain-b")
            .unwrap()
            .build();

        assert_eq!(router.chain_count(), 2);
        assert!(router.is_chain("chain-a"));
        assert!(router.is_chain("chain-b"));
        assert!(!router.is_chain("chain-c"));
    }

    #[test]
    fn test_fwmark_router_builder_duplicate_chain() {
        let result = FwmarkRouter::builder()
            .add_chain("chain-a")
            .unwrap()
            .add_chain("chain-a");

        assert!(matches!(result, Err(RuleError::DuplicateChain(_))));
    }

    #[test]
    fn test_fwmark_router_builder_with_dscp() {
        let router = FwmarkRouter::builder()
            .add_chain_with_dscp("high-priority", 50)
            .unwrap()
            .build();

        let mark = router.get_chain_mark("high-priority").unwrap();
        assert_eq!(mark.dscp_value, 50);
    }

    #[test]
    fn test_fwmark_router_builder_invalid_dscp() {
        // Zero is out of range
        let result = FwmarkRouter::builder().add_chain_with_dscp("chain", 0);
        assert!(matches!(result, Err(RuleError::DscpOutOfRange(0))));

        // 64 is out of range
        let result = FwmarkRouter::builder().add_chain_with_dscp("chain", 64);
        assert!(matches!(result, Err(RuleError::DscpOutOfRange(64))));
    }

    #[test]
    fn test_fwmark_router_builder_dscp_in_use() {
        let result = FwmarkRouter::builder()
            .add_chain_with_dscp("chain-a", 5)
            .unwrap()
            .add_chain_with_dscp("chain-b", 5);

        assert!(matches!(result, Err(RuleError::DscpInUse(5))));
    }

    #[test]
    fn test_fwmark_router_builder_default_mark() {
        let router = FwmarkRouter::builder().default_mark(0).build();

        assert_eq!(router.default_mark(), Some(0));
    }

    #[test]
    fn test_fwmark_router_get_routing_mark() {
        let router = FwmarkRouter::builder()
            .add_chain_with_dscp("my-chain", 5)
            .unwrap()
            .default_mark(0)
            .build();

        // Chain returns its routing mark
        assert_eq!(
            router.get_routing_mark("my-chain"),
            Some(ENTRY_ROUTING_MARK_BASE + 5)
        );

        // Non-chain returns default
        assert_eq!(router.get_routing_mark("direct"), Some(0));
    }

    #[test]
    fn test_fwmark_router_chains_iterator() {
        let router = FwmarkRouter::builder()
            .add_chain("chain-a")
            .unwrap()
            .add_chain("chain-b")
            .unwrap()
            .build();

        let chain_tags: Vec<&str> = router.chains().map(|(tag, _)| tag).collect();
        assert_eq!(chain_tags.len(), 2);
        assert!(chain_tags.contains(&"chain-a"));
        assert!(chain_tags.contains(&"chain-b"));
    }

    #[test]
    fn test_fwmark_router_auto_dscp_skips_reserved() {
        // Auto-assign DSCP values and verify reserved values are skipped
        // Build chains iteratively since builder takes ownership
        let mut builder = FwmarkRouter::builder();

        // Add chains until we would hit reserved value 10 (AF11)
        for i in 1..15 {
            builder = builder
                .add_chain(format!("chain-{}", i))
                .expect("should succeed");
        }

        let router = builder.build();

        // Verify no chain uses a reserved DSCP
        for (_, mark) in router.chains() {
            assert!(
                !mark.is_reserved(),
                "Chain should not use reserved DSCP {}",
                mark.dscp_value
            );
        }
    }

    // ========================================================================
    // Helper Function Tests
    // ========================================================================

    #[test]
    fn test_dscp_to_routing_mark() {
        assert_eq!(dscp_to_routing_mark(5), Some(ENTRY_ROUTING_MARK_BASE + 5));
        assert_eq!(dscp_to_routing_mark(0), None);
        assert_eq!(dscp_to_routing_mark(64), None);
    }

    #[test]
    fn test_routing_mark_to_dscp() {
        assert_eq!(routing_mark_to_dscp(ENTRY_ROUTING_MARK_BASE + 5), Some(5));
        assert_eq!(routing_mark_to_dscp(ENTRY_ROUTING_MARK_BASE), None);
        assert_eq!(routing_mark_to_dscp(100), None);
    }

    #[test]
    fn test_dscp_to_routing_table() {
        assert_eq!(dscp_to_routing_table(5), Some(305));
        assert_eq!(dscp_to_routing_table(0), None);
    }

    #[test]
    fn test_is_dscp_terminal_table() {
        assert!(!is_dscp_terminal_table(300)); // Boundary
        assert!(is_dscp_terminal_table(301)); // First valid
        assert!(is_dscp_terminal_table(363)); // Last valid
        assert!(!is_dscp_terminal_table(364)); // Above range
        assert!(!is_dscp_terminal_table(200)); // ECMP range
    }

    #[test]
    fn test_is_ecmp_table() {
        assert!(is_ecmp_table(200));
        assert!(is_ecmp_table(250));
        assert!(is_ecmp_table(299));
        assert!(!is_ecmp_table(199));
        assert!(!is_ecmp_table(300));
    }

    #[test]
    fn test_is_relay_table() {
        assert!(is_relay_table(400));
        assert!(is_relay_table(450));
        assert!(is_relay_table(463));
        assert!(!is_relay_table(399));
        assert!(!is_relay_table(464));
    }

    #[test]
    fn test_is_peer_table() {
        assert!(is_peer_table(500));
        assert!(is_peer_table(550));
        assert!(is_peer_table(599));
        assert!(!is_peer_table(499));
        assert!(!is_peer_table(600));
    }

    #[test]
    fn test_is_reserved_dscp() {
        assert!(is_reserved_dscp(0)); // Best Effort
        assert!(is_reserved_dscp(46)); // EF
        assert!(is_reserved_dscp(10)); // AF11
        assert!(!is_reserved_dscp(5)); // Not reserved
        assert!(!is_reserved_dscp(63)); // Not reserved
    }

    #[test]
    fn test_is_valid_dscp() {
        assert!(is_valid_dscp(1));
        assert!(is_valid_dscp(63));
        assert!(!is_valid_dscp(0));
        assert!(!is_valid_dscp(64));
    }

    // ========================================================================
    // Integration Tests
    // ========================================================================

    #[test]
    fn test_roundtrip_dscp_routing_mark() {
        for dscp in DSCP_MIN..=DSCP_MAX {
            let mark = dscp_to_routing_mark(dscp).expect("valid DSCP");
            let recovered = routing_mark_to_dscp(mark).expect("valid mark");
            assert_eq!(dscp, recovered, "Roundtrip failed for DSCP {}", dscp);
        }
    }

    #[test]
    fn test_chain_mark_consistency() {
        for dscp in DSCP_MIN..=DSCP_MAX {
            let mark = ChainMark::from_dscp(dscp).expect("valid DSCP");

            // From routing mark should give same result
            let from_mark = ChainMark::from_routing_mark(mark.routing_mark).expect("valid mark");
            assert_eq!(mark, from_mark);

            // From routing table should give same result
            let from_table =
                ChainMark::from_routing_table(mark.routing_table).expect("valid table");
            assert_eq!(mark, from_table);
        }
    }

    #[test]
    fn test_table_ranges_no_overlap() {
        // Verify that routing table ranges don't overlap

        // TPROXY is a single value
        assert!(!is_ecmp_table(tables::TPROXY));
        assert!(!is_dscp_terminal_table(tables::TPROXY));
        assert!(!is_relay_table(tables::TPROXY));
        assert!(!is_peer_table(tables::TPROXY));

        // ECMP range
        for table in tables::ECMP_MIN..=tables::ECMP_MAX {
            assert!(is_ecmp_table(table));
            assert!(!is_dscp_terminal_table(table));
            assert!(!is_relay_table(table));
            assert!(!is_peer_table(table));
        }

        // DSCP terminal range (301-363, not 300)
        for table in (tables::DSCP_TERMINAL_MIN + 1)..=tables::DSCP_TERMINAL_MAX {
            assert!(!is_ecmp_table(table));
            assert!(is_dscp_terminal_table(table));
            assert!(!is_relay_table(table));
            assert!(!is_peer_table(table));
        }

        // Relay range
        for table in tables::RELAY_MIN..=tables::RELAY_MAX {
            assert!(!is_ecmp_table(table));
            assert!(!is_dscp_terminal_table(table));
            assert!(is_relay_table(table));
            assert!(!is_peer_table(table));
        }

        // Peer range
        for table in tables::PEER_MIN..=tables::PEER_MAX {
            assert!(!is_ecmp_table(table));
            assert!(!is_dscp_terminal_table(table));
            assert!(!is_relay_table(table));
            assert!(is_peer_table(table));
        }
    }
}
