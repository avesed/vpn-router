//! Chain routing module
//!
//! This module implements multi-hop chain routing with DSCP marking
//! and Two-Phase Commit (2PC) protocol for distributed activation.
//!
//! # Overview
//!
//! The chain module handles:
//! - Chain lifecycle management (create, activate, deactivate, remove)
//! - DSCP packet modification with IPv4 checksum recalculation
//! - Two-Phase Commit protocol for distributed chain activation
//! - DSCP value allocation with conflict detection
//!
//! # Submodules
//!
//! - [`manager`]: `ChainManager` for lifecycle management
//! - [`dscp`]: DSCP packet modification and allocation
//! - [`two_phase`]: Two-Phase Commit protocol
//! - [`allocator`]: DSCP value allocator
//!
//! # Chain Routing Architecture
//!
//! ```text
//! Entry Node          Relay Node(s)         Terminal Node
//!     │                    │                     │
//!     │ Set DSCP header    │ Forward by DSCP     │ Remove DSCP, exit
//!     │ Mark routing_mark  │                     │ to egress
//!     ▼                    ▼                     ▼
//! [Rule Engine] ─────> [WG Tunnel] ─────> [WG Tunnel] ─────> [Egress]
//! ```
//!
//! # References
//!
//! - `WireGuard` Protocol: <https://www.wireguard.com/protocol/>

pub mod allocator;
pub mod dscp;
pub mod manager;
pub mod two_phase;

// Re-export commonly used types
pub use allocator::{DscpAllocator, DscpAllocatorError};
pub use dscp::{get_dscp, set_dscp, DscpError};
pub use manager::{
    AlwaysConnectedCallback, ChainError, ChainManager, DscpRoutingCallback, NoOpRoutingCallback,
    PeerConnectivityCallback,
};
pub use two_phase::{
    ChainNetworkClient, ForwardPeerNetworkClient, MockNetworkClient, NoOpNetworkClient,
    ParticipantState, TwoPhaseCommit, TwoPhaseError, TwoPhaseState,
};
