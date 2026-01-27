//! IpStack-based TCP/IP bridge for WireGuard ingress
//!
//! This module provides a userspace TCP/IP stack using the `ipstack` crate,
//! replacing the manual TCP state machine for Direct/SOCKS5/VLESS TCP outbound.
//!
//! # Architecture
//!
//! ```text
//! WireGuard Ingress (IP packets)
//!         |
//!         v
//! +---------------------+
//! |   IpStackBridge     |
//! |  - PacketChannel    | <-- IP packets in/out via async channels
//! |  - ipstack::IpStack |
//! |  - SessionTracker   | <-- 5-tuple -> peer mapping
//! +---------------------+
//!         |
//!         v
//!   IpStackTcpStream <-> OutboundStream (copy_bidirectional)
//! ```
//!
//! # Feature Flag
//!
//! This module is gated behind the `ipstack-tcp` feature flag. Enable it in
//! Cargo.toml:
//!
//! ```toml
//! [features]
//! ipstack-tcp = ["dep:ipstack"]
//! ```
//!
//! # Usage
//!
//! ```ignore
//! use rust_router::ingress::ipstack_bridge::{IpStackBridge, PacketChannel};
//!
//! // Create the bridge
//! let mut bridge = IpStackBridge::new();
//!
//! // Take the reply receiver for routing packets back to WireGuard
//! let reply_rx = bridge.take_reply_rx().unwrap();
//!
//! // Start the bridge
//! bridge.start().await?;
//!
//! // Inject IP packets from WireGuard
//! bridge.inject_packet(packet, peer_key).await?;
//! ```
//!
//! # Implementation
//!
//! This module provides complete ipstack integration:
//! - Configuration constants (MTU, timeouts, session limits)
//! - PacketChannel for AsyncRead/AsyncWrite bridging to ipstack
//! - Session tracking with 5-tuple to peer key mapping
//! - TCP connection handling via `copy_bidirectional`
//! - UDP stream handling with proper timeouts
//! - Reply packet routing back to correct WireGuard peer

#[cfg(feature = "ipstack-tcp")]
mod bridge;
#[cfg(feature = "ipstack-tcp")]
mod config;
#[cfg(feature = "ipstack-tcp")]
mod packet_channel;
#[cfg(feature = "ipstack-tcp")]
mod session_tracker;

#[cfg(feature = "ipstack-tcp")]
pub use bridge::{DiagnosticSnapshot, IpStackBridge, IpStackBridgeStats, IpStackBridgeStatsSnapshot};
#[cfg(feature = "ipstack-tcp")]
pub use config::*;
#[cfg(feature = "ipstack-tcp")]
pub use packet_channel::PacketChannel;
#[cfg(feature = "ipstack-tcp")]
pub use session_tracker::{FiveTuple, SessionInfo, SessionTracker};
