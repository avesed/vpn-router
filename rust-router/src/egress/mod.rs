//! WireGuard Egress module for Phase 6.4
//!
//! This module provides WireGuard egress functionality, allowing rust-router
//! to create and manage outbound WireGuard tunnels (PIA, custom WG, peer tunnels).
//!
//! # Phase 6.4 Implementation Status
//!
//! - [x] WgEgressConfig configuration type
//! - [x] EgressError error types
//! - [x] WgReplyHandler for reply traffic
//! - [x] WgEgressManager for tunnel management
//! - [x] Multi-tunnel support with concurrent operations
//!
//! # Architecture
//!
//! ```text
//! +------------------------------------------------------------------+
//! |                        WgEgressManager                            |
//! |                                                                  |
//! |  +------------------------+    +---------------------------+     |
//! |  | Tunnel Registry        |    | Reply Handler             |     |
//! |  | (tag -> tunnel)        |    | - Decrypted reply routing |     |
//! |  | - PIA tunnels          |    | - Back to ingress/local   |     |
//! |  | - Custom WG tunnels    |    +---------------------------+     |
//! |  | - Peer tunnels         |                |                     |
//! |  +------------------------+                |                     |
//! |            |                               |                     |
//! |            +-------------------------------+                     |
//! |                          |                                       |
//! |  +--------------------+  |  +-----------------------------+      |
//! |  | Per-Tunnel Stats   |  |  | Background Reply Tasks      |      |
//! |  | - TX/RX bytes      |  |  | - One per tunnel            |      |
//! |  | - Packets          |  |  | - Receive and decrypt       |      |
//! |  +--------------------+  |  +-----------------------------+      |
//! +------------------------------------------------------------------+
//! ```
//!
//! # Example
//!
//! ```ignore
//! use rust_router::egress::{WgEgressManager, WgEgressConfig, EgressTunnelType, WgReplyHandler};
//! use std::sync::Arc;
//!
//! // Create reply handler
//! let reply_handler = Arc::new(WgReplyHandler::new(|packet, tunnel_tag| {
//!     println!("Received reply from tunnel {}: {} bytes", tunnel_tag, packet.len());
//! }));
//!
//! // Create manager
//! let manager = WgEgressManager::new(reply_handler);
//!
//! // Create a PIA tunnel
//! let config = WgEgressConfig {
//!     tag: "pia-us-west".to_string(),
//!     tunnel_type: EgressTunnelType::Pia { region: "us-west".to_string() },
//!     private_key: "base64_private_key".to_string(),
//!     peer_public_key: "base64_peer_public_key".to_string(),
//!     peer_endpoint: "1.2.3.4:51820".to_string(),
//!     local_ip: Some("10.200.200.5".to_string()),
//!     allowed_ips: vec!["0.0.0.0/0".to_string()],
//!     persistent_keepalive: Some(25),
//!     mtu: Some(1420),
//! };
//!
//! manager.create_tunnel(config).await?;
//!
//! // Send a packet
//! manager.send("pia-us-west", packet.to_vec()).await?;
//!
//! // Later, remove the tunnel
//! manager.remove_tunnel("pia-us-west", Some(Duration::from_secs(5))).await?;
//! ```
//!
//! # Tunnel Types
//!
//! - **PIA**: Private Internet Access VPN tunnels
//! - **Custom**: User-configured WireGuard endpoints
//! - **Peer**: Inter-node peer tunnels for multi-hop routing
//!
//! # References
//!
//! - Implementation Plan: `docs/PHASE6_IMPLEMENTATION_PLAN_v3.2.md` Section 6.4
//! - WireGuard Protocol: <https://www.wireguard.com/protocol/>

pub mod config;
pub mod error;
pub mod manager;
pub mod reply;

// Re-export commonly used types
pub use config::{EgressState, EgressTunnelType, WgEgressConfig};
pub use error::{EgressError, EgressResult};
pub use manager::{EgressTunnelStatus, WgEgressManager, WgEgressStats};
pub use reply::WgReplyHandler;
