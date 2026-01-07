//! ECMP (Equal-Cost Multi-Path) load balancing module for Phase 6
//!
//! This module implements ECMP load balancing for distributing traffic
//! across multiple outbounds with health-aware failover.
//!
//! # Overview
//!
//! The ECMP module handles:
//! - ECMP group management (create, update, remove)
//! - Load balancing algorithms (round-robin, weighted, least-connections)
//! - Health-aware member selection
//! - Routing mark assignment for Linux policy routing
//!
//! # Submodules
//!
//! - [`group`]: ECMP group management (Phase 6.7)
//! - [`lb`]: Load balancing algorithms (Phase 6.7)
//!
//! # Phase 6 Implementation Status
//!
//! - [ ] 6.7 ECMP group structure
//! - [ ] 6.7 Load balancer algorithms
//! - [ ] 6.7 Health integration
//! - [ ] 6.7 Routing mark management
//!
//! # Architecture
//!
//! ```text
//! +-------------------+
//! |   ECMP Group      |
//! |  "us-exits"       |
//! +-------------------+
//!          |
//!    +-----+-----+
//!    |     |     |
//! +--v--+--v--+--v--+
//! |PIA  |PIA  |WARP |
//! |us-ny|us-ca|us   |
//! +-----+-----+-----+
//!    (routing_mark=200)
//! ```
//!
//! # References
//!
//! - Implementation Plan: `docs/PHASE6_IMPLEMENTATION_PLAN_v3.2.md` Section 6.7

pub mod group;
pub mod lb;

// Re-export commonly used types
pub use group::{EcmpGroup, EcmpGroupConfig, EcmpGroupError, EcmpMember};
pub use lb::{LbAlgorithm, LbError, LoadBalancer};
