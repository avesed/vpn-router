//! ECMP (Equal-Cost Multi-Path) load balancing module for Phase 6
//!
//! This module implements ECMP load balancing for distributing traffic
//! across multiple outbounds with health-aware failover.
//!
//! # Overview
//!
//! The ECMP module handles:
//! - ECMP group management (create, update, remove)
//! - Load balancing algorithms (five-tuple hash, round-robin, weighted, least-connections, random)
//! - Health-aware member selection
//! - Routing mark assignment for Linux policy routing
//! - Connection affinity via five-tuple hashing
//!
//! # Submodules
//!
//! - [`group`]: ECMP group management (Phase 6.7)
//! - [`lb`]: Load balancing algorithms (Phase 6.7)
//!
//! # Phase 6 Implementation Status
//!
//! - [x] 6.7 ECMP group structure
//! - [x] 6.7 Load balancer algorithms (`FiveTupleHash`, `RoundRobin`, Weighted, `LeastConnections`, Random)
//! - [x] 6.7 Health integration
//! - [x] 6.7 Routing mark management
//! - [x] 6.7 Connection affinity (five-tuple hash)
//! - [x] 6.7 `EcmpGroupManager`
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
//! # Load Balancing Algorithms
//!
//! | Algorithm | Description | Use Case |
//! |-----------|-------------|----------|
//! | `FiveTupleHash` | Hash 5-tuple for connection affinity (DEFAULT) | Stateful connections |
//! | `DestHash` | Hash destination (domain/IP) for session affinity | Video streaming, multi-conn apps |
//! | `RoundRobin` | Cycle through members sequentially | Equal distribution |
//! | `Weighted` | Distribute based on member weights | Capacity-based |
//! | `LeastConnections` | Select member with fewest connections | Load-based |
//! | `Random` | Random selection | Simple distribution |
//!
//! # Example
//!
//! ```
//! use rust_router::ecmp::{
//!     EcmpGroup, EcmpGroupConfig, EcmpGroupManager, EcmpMember,
//!     LbAlgorithm, FiveTuple, Protocol,
//! };
//!
//! // Create manager
//! let manager = EcmpGroupManager::new();
//!
//! // Add group with FiveTupleHash (default)
//! let config = EcmpGroupConfig {
//!     tag: "us-exits".to_string(),
//!     members: vec![
//!         EcmpMember::new("pia-us-ny".to_string()),
//!         EcmpMember::with_weight("pia-us-ca".to_string(), 2),
//!     ],
//!     routing_mark: Some(200),
//!     ..Default::default()
//! };
//! manager.add_group(config).unwrap();
//!
//! // Get group and select by connection
//! let group = manager.get_group("us-exits").unwrap();
//! let tuple = FiveTuple::new(
//!     "10.0.0.1".parse().unwrap(),
//!     "8.8.8.8".parse().unwrap(),
//!     12345,
//!     443,
//!     Protocol::Tcp,
//! );
//!
//! // Same connection always routes to same member
//! let member = group.select_by_connection(&tuple).unwrap();
//! ```
//!
//! # References
//!
//! - Implementation Plan: `docs/PHASE6_IMPLEMENTATION_PLAN_v3.2.md` Section 6.7

pub mod group;
pub mod lb;

// Re-export commonly used types from group module
pub use group::{
    EcmpGroup, EcmpGroupConfig, EcmpGroupError, EcmpGroupManager, EcmpGroupStats, EcmpMember,
    MemberStats, ECMP_ROUTING_MARK_MAX, ECMP_ROUTING_MARK_MIN, ECMP_ROUTING_TABLE_MAX,
    ECMP_ROUTING_TABLE_MIN,
};

// Re-export commonly used types from lb module
pub use lb::{DestKey, FiveTuple, LbAlgorithm, LbError, LbMember, LoadBalancer, Protocol};
