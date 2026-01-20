//! `WireGuard` Ingress module for Phase 6.3
//!
//! This module provides `WireGuard` ingress functionality, allowing the rust-router
//! to accept incoming `WireGuard` connections from clients and route their traffic
//! based on DSCP values and rule matching.
//!
//! # Phase 6.3 Implementation Status
//!
//! - [x] `WgIngressConfig` configuration type
//! - [x] `IngressError` error types
//! - [x] `IngressProcessor` for packet processing
//! - [x] `WgIngressManager` for tunnel management
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
//! 1. Decrypt incoming `WireGuard` packet
//! 2. Extract DSCP from IP header using `chain/dscp::get_dscp()`
//! 3. If DSCP > 0 and matches a configured chain, route to that chain tag
//!    (terminal nodes route to the exit egress and clear DSCP)
//! 4. Otherwise, clear DSCP and use rule engine for routing decision
//!
//! # References
//!
//! - Implementation Plan: `docs/PHASE6_IMPLEMENTATION_PLAN_v3.2.md` Section 6.3
//! - `WireGuard` Protocol: <https://www.wireguard.com/protocol/>

pub mod config;
pub mod dns_cache;
pub mod error;
pub mod forwarder;
pub mod manager;
pub mod processor;
pub mod socks5_server;

// Re-export commonly used types
pub use config::WgIngressConfig;
pub use dns_cache::{IpDomainCache, IpDomainCacheStats, IpDomainCacheStatsSnapshot};
pub use error::IngressError;
pub use forwarder::{
    parse_ip_packet, parse_tcp_details, run_forwarding_loop, run_reply_router_loop,
    spawn_forwarding_task, spawn_reply_router, spawn_peer_tunnel_processor, tcp_flags,
    FiveTuple, ForwardingStats, ForwardingStatsSnapshot, IngressReplyStats, IngressReplyStatsSnapshot,
    IngressSessionTracker, ParsedPacket, PeerSession, PeerTunnelProcessorStats,
    PeerTunnelProcessorStatsSnapshot, ReplyPacket, TcpConnection, TcpConnectionManager,
    TcpConnectionState, TcpDetails,
};
pub use manager::{WgIngressManager, WgIngressStats};
pub use processor::{IngressProcessor, RoutingDecision};
pub use socks5_server::{Socks5Server, Socks5ServerConfig, Socks5ServerStats, Socks5ServerStatsSnapshot};
