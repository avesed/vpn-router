//! Chain routing module for Phase 6
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
//! - [`manager`]: ChainManager for lifecycle management (Phase 6.6)
//! - [`dscp`]: DSCP packet modification and allocation (Phase 6.6)
//! - [`two_phase`]: Two-Phase Commit protocol (Phase 6.6)
//! - [`allocator`]: DSCP value allocator (Phase 6.6)
//!
//! # Phase 6 Implementation Status
//!
//! - [ ] 6.6.1 ChainManager structure
//! - [ ] 6.6.2 DSCP packet modification
//! - [ ] 6.6.3 Two-Phase Commit protocol
//! - [ ] 6.6.4 DSCP allocation
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
//! - Implementation Plan: `docs/PHASE6_IMPLEMENTATION_PLAN_v3.2.md` Section 6.6

pub mod allocator;
pub mod dscp;
pub mod manager;
pub mod two_phase;

// Re-export commonly used types
pub use allocator::{DscpAllocator, DscpAllocatorError};
pub use dscp::{get_dscp, set_dscp, DscpError};
pub use manager::{ChainError, ChainManager};
pub use two_phase::{TwoPhaseCommit, TwoPhaseError, TwoPhaseState};
