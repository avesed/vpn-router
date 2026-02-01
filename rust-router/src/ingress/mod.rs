//! `WireGuard` Ingress module
//!
//! This module provides `WireGuard` ingress functionality, allowing the rust-router
//! to accept incoming `WireGuard` connections from clients and route their traffic
//! based on DSCP values and rule matching.
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
    get_proxy_udp_session_count,
    // SNI routing configuration
    get_sni_routing_config,
    // UDP stats helper functions
    get_udp_session_count,
    parse_ip_packet,
    parse_tcp_details,
    run_forwarding_loop,
    run_reply_router_loop,
    spawn_forwarding_task,
    spawn_peer_tunnel_processor,
    spawn_reply_router,
    tcp_flags,
    FiveTuple,
    ForwardingStats,
    ForwardingStatsSnapshot,
    IngressReplyStats,
    IngressReplyStatsSnapshot,
    IngressSessionTracker,
    ParsedPacket,
    PeerSession,
    PeerTunnelProcessorStats,
    PeerTunnelProcessorStatsSnapshot,
    ReplyPacket,
    TcpDetails,
    WgSniRoutingConfig,
};
pub use manager::{WgIngressManager, WgIngressStats};
pub use processor::{IngressProcessor, RoutingDecision};
pub use socks5_server::{
    Socks5Server, Socks5ServerConfig, Socks5ServerStats, Socks5ServerStatsSnapshot,
};

// TUN ingress bridge (feature-gated)
// Note: Uses TunIngressBridge internally which leverages the kernel's TCP/IP stack
// via TUN + TPROXY for better performance (200+ Mbps vs ipstack's 30-80 Mbps).
#[cfg(feature = "ipstack-tcp")]
pub use forwarder::{
    get_ipstack_diagnostics, get_ipstack_stats, init_ipstack_bridge, init_tun_ingress_bridge,
    is_ipstack_enabled, set_ipstack_enabled, spawn_ipstack_reply_router, try_route_wg_egress_reply,
};

// Re-export TUN bridge types for public API
#[cfg(feature = "ipstack-tcp")]
pub use crate::tun_bridge::{
    FiveTuple as TunFiveTuple, SessionInfo as TunSessionInfo, SessionTracker as TunSessionTracker,
    TunIngressBridge, TunIngressConfig, TunIngressStats, TunIngressStatsSnapshot,
};

// Note: ipstack_bridge module has been removed.
// TunIngressBridge (TUN + TPROXY) now provides the WG ingress → outbound path.
// The vless_wg_bridge module is still used for VLESS/SS → WG egress path.
