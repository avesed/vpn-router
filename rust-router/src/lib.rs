//! rust-router: High-performance transparent proxy router
//!
//! This crate provides a TPROXY-based transparent proxy router for Linux,
//! designed to work alongside the vpn-router project.
//!
//! # Features
//!
//! - **TPROXY Support**: Full support for Linux TPROXY transparent proxying
//! - **TLS SNI Sniffing**: Extract Server Name Indication from TLS ClientHello
//! - **Multiple Outbounds**: Support for direct and block outbound types
//! - **IPC Control**: Unix socket-based runtime control
//! - **Connection Management**: Backpressure, statistics, and graceful shutdown
//!
//! # Architecture
//!
//! ```text
//! Client → iptables TPROXY → rust-router → Outbound → Destination
//!                              ↓
//!                        TLS SNI Sniffing
//!                              ↓
//!                         Route Selection
//! ```
//!
//! # Quick Start
//!
//! ```no_run
//! use rust_router::config::load_config;
//! use rust_router::tproxy::TproxyListener;
//! use rust_router::outbound::OutboundManagerBuilder;
//! use rust_router::connection::ConnectionManager;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Load configuration
//! let config = load_config("/etc/rust-router/config.json")?;
//!
//! // Create outbound manager
//! let mut builder = OutboundManagerBuilder::new();
//! builder.add_all_from_config(&config.outbounds);
//! let outbound_manager = builder.build();
//!
//! // Create listener
//! let listener = TproxyListener::bind(&config.listen)?;
//!
//! // Accept and handle connections...
//! # Ok(())
//! # }
//! ```
//!
//! # Modules
//!
//! - [`config`]: Configuration types and loading
//! - [`connection`]: Connection management and statistics
//! - [`error`]: Error types
//! - [`io`]: I/O utilities for bidirectional copy
//! - [`ipc`]: IPC server and protocol
//! - [`outbound`]: Outbound implementations
//! - [`sniff`]: Protocol sniffing (TLS SNI)
//! - [`tproxy`]: TPROXY socket and listener

#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]

pub mod config;
pub mod connection;
pub mod error;
pub mod io;
pub mod ipc;
pub mod outbound;
pub mod sniff;
pub mod tproxy;

// Re-export commonly used types at the crate root
pub use config::{Config, ListenConfig, OutboundConfig};
pub use connection::{ConnectionManager, ConnectionStats};
pub use error::{ConfigError, ConnectionError, IpcError, OutboundError, RustRouterError, TproxyError};
pub use ipc::{IpcClient, IpcCommand, IpcResponse, IpcServer};
pub use outbound::{BlockOutbound, DirectOutbound, Outbound, OutboundManager};
pub use sniff::{sniff_tls_sni, Protocol, SniffResult};
pub use tproxy::{TproxyConnection, TproxyListener};

/// Crate version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Check if running with required capabilities for TPROXY
pub fn check_capabilities() -> Result<(), TproxyError> {
    if !tproxy::has_net_admin_capability() {
        return Err(TproxyError::PermissionDenied);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        assert!(!VERSION.is_empty());
    }

    #[test]
    fn test_check_capabilities() {
        // This test will pass or fail depending on privileges
        let result = check_capabilities();
        // Just verify it doesn't panic
        match result {
            Ok(()) => println!("Running with CAP_NET_ADMIN"),
            Err(TproxyError::PermissionDenied) => println!("Running without CAP_NET_ADMIN"),
            Err(e) => panic!("Unexpected error: {}", e),
        }
    }
}
