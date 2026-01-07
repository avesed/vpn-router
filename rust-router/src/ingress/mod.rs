//! WireGuard Ingress module for Phase 6.3
//!
//! This module provides WireGuard ingress functionality, allowing the rust-router
//! to accept incoming WireGuard connections from clients and route their traffic
//! based on DSCP values and rule matching.
//!
//! # Phase 6.3 Implementation Status
//!
//! - [x] WgIngressConfig configuration type
//! - [x] IngressError error types
//! - [x] IngressProcessor for packet processing
//! - [x] WgIngressManager for tunnel management
//! - [x] DSCP extraction and rule matching
//! - [x] Multi-peer support
//!
//! # Architecture
//!
//! ```text
//! +------------------------------------------------------------------+
//! |                        WgIngressManager                           |
//! |                                                                  |
//! |  +------------------------+    +---------------------------+     |
//! |  | UserspaceWgTunnel      |    | IngressProcessor          |     |
//! |  | (multi-peer mode)      |    | - DSCP extraction         |     |
//! |  | - Key management       |    | - Rule engine matching    |     |
//! |  | - Handshake handling   |    | - Routing decisions       |     |
//! |  +------------------------+    +---------------------------+     |
//! |            |                              |                       |
//! |            +------------------------------+                       |
//! |                          |                                       |
//! |  +--------------------+  |  +-----------------------------+      |
//! |  | Peer Registry      |  |  | Stats Collector             |      |
//! |  | - Add/Remove peers |  |  | - Per-peer statistics       |      |
//! |  | - Allowed IPs      |  |  | - Connection counts         |      |
//! |  +--------------------+  |  +-----------------------------+      |
//! +------------------------------------------------------------------+
//! ```
//!
//! # Example
//!
//! ```ignore
//! use rust_router::ingress::{WgIngressManager, WgIngressConfig};
//! use rust_router::rules::RuleEngine;
//! use std::sync::Arc;
//!
//! // Create configuration
//! let config = WgIngressConfig {
//!     private_key: "base64_private_key".to_string(),
//!     listen_addr: "0.0.0.0:36100".parse().unwrap(),
//!     local_ip: "10.25.0.1".parse().unwrap(),
//!     allowed_subnet: "10.25.0.0/24".parse().unwrap(),
//!     mtu: 1420,
//! };
//!
//! // Create manager with rule engine
//! let rule_engine = Arc::new(RuleEngine::new(snapshot));
//! let manager = WgIngressManager::new(config, rule_engine)?;
//!
//! // Start accepting connections
//! manager.start().await?;
//!
//! // Add a peer (client)
//! manager.add_peer(peer_config).await?;
//! ```
//!
//! # DSCP Handling
//!
//! The ingress manager extracts DSCP values from incoming IP packets and uses them
//! for chain routing decisions:
//!
//! 1. Decrypt incoming WireGuard packet
//! 2. Extract DSCP from IP header using `chain/dscp::get_dscp()`
//! 3. If DSCP > 0, map to routing mark using `rules/fwmark::ChainMark`
//! 4. Otherwise, use rule engine for routing decision
//!
//! # References
//!
//! - Implementation Plan: `docs/PHASE6_IMPLEMENTATION_PLAN_v3.2.md` Section 6.3
//! - WireGuard Protocol: <https://www.wireguard.com/protocol/>

pub mod config;
pub mod error;
pub mod manager;
pub mod processor;

// Re-export commonly used types
pub use config::WgIngressConfig;
pub use error::IngressError;
pub use manager::{WgIngressManager, WgIngressStats};
pub use processor::{IngressProcessor, RoutingDecision};
