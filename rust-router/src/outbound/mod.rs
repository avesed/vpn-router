//! Outbound module
//!
//! This module provides outbound connection implementations for the proxy router.
//!
//! # Outbound Types
//!
//! - `DirectOutbound`: Connect directly to the destination, optionally through
//!   a specific interface or with a routing mark.
//! - `BlockOutbound`: Block/drop all connections (for ad-blocking, access control).
//!
//! # Example
//!
//! ```no_run
//! use rust_router::outbound::{DirectOutbound, BlockOutbound, OutboundManager, Outbound};
//! use rust_router::config::OutboundConfig;
//! use std::time::Duration;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create outbound manager
//! let manager = OutboundManager::new();
//!
//! // Add direct outbound
//! manager.add(Box::new(DirectOutbound::simple("direct")));
//!
//! // Add block outbound for ads
//! manager.add(Box::new(BlockOutbound::new("adblock")));
//!
//! // Get and use an outbound
//! if let Some(outbound) = manager.get("direct") {
//!     let addr = "1.2.3.4:80".parse()?;
//!     let conn = outbound.connect(addr, Duration::from_secs(10)).await?;
//!     println!("Connected to {}", conn.remote_addr());
//! }
//! # Ok(())
//! # }
//! ```

mod block;
mod direct;
mod manager;
pub mod socks5;
pub mod socks5_common;
pub mod socks5_udp;
mod traits;
pub mod vless;
pub mod wireguard;

pub use block::BlockOutbound;
pub use direct::DirectOutbound;
pub use manager::{OutboundManager, OutboundManagerBuilder};
pub use socks5::{PoolStats, Socks5Config, Socks5Error, Socks5Outbound};
pub use socks5_udp::{Socks5Auth, Socks5UdpAssociation, Socks5UdpError};
pub use vless::{
    TlsSettings, UuidInput, VlessConfig, VlessOutbound, VlessOutboundError, VlessTransportConfig,
};
pub use traits::{
    DirectUdpHandle, HealthStatus, Outbound, OutboundConnection, OutboundExt, OutboundStream,
    PoolStatsInfo, ProxyServerInfo, Socks5UdpHandle, UdpOutboundHandle,
};
pub use wireguard::{
    get_egress_interface_name, get_egress_type, get_interface_info, get_peer_routing_table,
    interface_exists, is_egress_interface, is_valid_routing_mark, list_egress_interfaces,
    parse_interface_name, validate_interface_exists, EgressType, InterfaceInfo, CUSTOM_PREFIX,
    INTERFACE_MAX_LEN, PEER_PORT_MAX, PEER_PORT_MIN, PEER_PREFIX, PEER_TABLE_BASE, PIA_PREFIX,
    WARP_PREFIX,
};
