//! Control Plane Module
//!
//! Unified routing logic that implements `netbridge::ConnectionHandler` to bridge
//! the data plane with control components (rules, chain, fakedns, sniff).
//!
//! # Architecture
//!
//! ```text
//! +---------------------------------------------------------------------+
//! |                      Control Plane                                   |
//! |  +--------------------------------------------------------------+  |
//! |  |                  ControlPlaneHandler                          |  |
//! |  |  - impl ConnectionHandler for netbridge                       |  |
//! |  |  - Bridges netbridge::ConnectionInfo <-> rules::ConnectionInfo  |  |
//! |  +--------------------------------------------------------------+  |
//! |         |                    |                    |                 |
//! |         v                    v                    v                 |
//! |  +----------+        +------------+        +----------------+     |
//! |  |RuleEngine|        |ChainHandler|        |OutboundManager |     |
//! |  |(ArcSwap) |        |(DSCP chain)|        |(connect)       |     |
//! |  +----------+        +------------+        +----------------+     |
//! +---------------------------------------------------------------------+
//! ```
//!
//! # Overview
//!
//! The control plane module provides the routing logic layer between the
//! network data plane (`netbridge`) and the control components:
//!
//! - **Rule Engine**: Matches connections against routing rules (domain, `GeoIP`, DSCP)
//! - **Chain Handler**: Manages DSCP-based chain routing for multi-hop paths
//! - **Outbound Manager**: Manages outbound connections (direct, SOCKS5, VLESS, etc.)
//! - **`FakeDNS`**: Maps IP addresses back to domains for domain-based routing
//! - **SNI Sniffing**: Extracts domains from TLS `ClientHello`
//!
//! # Design Principles
//!
//! 1. **Separation of Concerns**: Data plane handles packet forwarding; control
//!    plane handles routing decisions.
//!
//! 2. **Hot Reload Support**: Uses `ArcSwap` for the rule engine to allow
//!    runtime rule updates without restarting.
//!
//! 3. **Async-First**: Native async/await with Rust 1.75+ async traits.
//!
//! 4. **Type Safety**: Bridges between different `ConnectionInfo` types
//!    (netbridge vs rules) with explicit conversion.
//!
//! # Quick Start
//!
//! ```ignore
//! use rust_router::controlplane::{ControlPlaneHandler, ControlPlaneBuilder};
//! use rust_router::netbridge::{DataPlaneBuilder, ConnectionHandler};
//! use rust_router::rules::RuleEngine;
//! use rust_router::outbound::OutboundManager;
//!
//! // Create control plane with components
//! let handler = ControlPlaneBuilder::new()
//!     .with_rule_engine(rule_engine)
//!     .with_outbound_manager(outbound_manager)
//!     .with_chain_handler(chain_handler)  // Optional
//!     .with_fakedns(fakedns)              // Optional
//!     .build()?;
//!
//! // Use with data plane
//! let dp = DataPlaneBuilder::new()
//!     .with_tun("tun-netbridge")
//!     .with_handler(Arc::new(handler))
//!     .build()
//!     .await?;
//!
//! dp.run().await?;
//! ```
//!
//! # Submodules
//!
//! - [`error`]: Error types for the control plane
//!
//! # Future Phases
//!
//! - **Phase 2**: `chain.rs` - DSCP chain routing handler
//! - **Phase 3**: `handler.rs` - `ControlPlaneHandler` implementing `ConnectionHandler`
//! - **Phase 4**: `builder.rs` - Builder pattern for constructing the handler
//!
//! # Connection Info Bridging
//!
//! The control plane bridges two `ConnectionInfo` types:
//!
//! - `netbridge::dataplane::ConnectionInfo`: From the data plane (session, peer, etc.)
//! - `rules::ConnectionInfo`: For the rule engine (protocol, addresses, domain, etc.)
//!
//! The handler converts between these types, enriching the data plane info
//! with domain information from `FakeDNS`/SNI before passing to the rule engine.

mod builder;
mod chain;
mod error;
mod handler;

pub use builder::ControlPlaneBuilder;
pub use chain::{ChainHandler, ChainRoutingResult};
pub use error::{ControlPlaneError, Result};
pub use handler::{
    ControlPlaneConfig, ControlPlaneHandler, ControlPlaneStats, ControlPlaneStatsSnapshot,
    DomainSource,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_types_exported() {
        // Verify error types are accessible through the module
        let err = ControlPlaneError::OutboundNotFound("test".to_string());
        assert!(err.to_string().contains("outbound not found"));

        let err = ControlPlaneError::MissingComponent("rule_engine");
        assert!(err.should_reject());
    }

    #[test]
    fn test_result_type() {
        fn example_fn() -> Result<u32> {
            Ok(42)
        }

        fn example_err() -> Result<u32> {
            Err(ControlPlaneError::NoMatchingRule)
        }

        assert_eq!(example_fn().unwrap(), 42);
        assert!(example_err().is_err());
    }
}
