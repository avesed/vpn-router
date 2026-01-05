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
mod traits;

pub use block::BlockOutbound;
pub use direct::DirectOutbound;
pub use manager::{OutboundManager, OutboundManagerBuilder};
pub use traits::{HealthStatus, Outbound, OutboundConnection, OutboundExt};
