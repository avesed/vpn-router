//! WireGuard tunnel abstraction trait for Phase 6
//!
//! This module defines the trait interface for WireGuard tunnels,
//! allowing different implementations (userspace, kernel) to be
//! used interchangeably.
//!
//! # Phase 6 Implementation Status
//!
//! - [ ] 6.2 WgTunnel trait definition
//! - [ ] 6.2 Async read/write operations
//! - [ ] 6.2 Statistics collection
//!
//! # Trait Design
//!
//! The `WgTunnel` trait provides:
//! - Async send/receive for encrypted packets
//! - Configuration access
//! - Statistics collection
//! - Graceful shutdown
//!
//! # References
//!
//! - Implementation Plan: `docs/PHASE6_IMPLEMENTATION_PLAN_v3.2.md` Section 6.2

use std::net::SocketAddr;

use crate::tunnel::config::WgTunnelConfig;

/// Error types for WireGuard tunnel operations
#[derive(Debug, thiserror::Error)]
pub enum WgTunnelError {
    /// Tunnel is not connected
    #[error("Tunnel is not connected")]
    NotConnected,

    /// Tunnel is already connected
    #[error("Tunnel is already connected")]
    AlreadyConnected,

    /// Invalid configuration
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    /// Key error
    #[error("Key error: {0}")]
    KeyError(String),

    /// I/O error
    #[error("I/O error: {0}")]
    IoError(String),

    /// Handshake failed
    #[error("Handshake failed: {0}")]
    HandshakeFailed(String),

    /// Timeout
    #[error("Operation timed out")]
    Timeout,

    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),
}

impl From<std::io::Error> for WgTunnelError {
    fn from(err: std::io::Error) -> Self {
        Self::IoError(err.to_string())
    }
}

/// Statistics for a WireGuard tunnel
#[derive(Debug, Clone, Default)]
pub struct WgTunnelStats {
    /// Bytes transmitted
    pub tx_bytes: u64,
    /// Bytes received
    pub rx_bytes: u64,
    /// Packets transmitted
    pub tx_packets: u64,
    /// Packets received
    pub rx_packets: u64,
    /// Last handshake timestamp (Unix seconds)
    pub last_handshake: Option<u64>,
    /// Number of handshakes completed
    pub handshake_count: u64,
    /// Number of invalid packets received
    pub invalid_packets: u64,
}

/// Trait for WireGuard tunnel implementations
///
/// This trait abstracts over different WireGuard implementations
/// (userspace via boringtun, kernel via wg-quick, etc.).
///
/// # Lock Ordering
///
/// Implementations using interior mutability must follow this lock order:
/// 1. `tunn` (Mutex) - WireGuard crypto state
/// 2. `socket` (RwLock) - UDP socket
/// 3. `recv_tx` (RwLock) - Receive channel
/// 4. `local_ip` (RwLock) - Local IP address
/// 5. `allowed_ips` (RwLock) - Allowed IPs for validation
/// 6. `handshake_complete` (watch) - Handshake completion signal
///
/// Always acquire locks in this order to prevent deadlocks.
#[allow(dead_code)]
pub trait WgTunnel: Send + Sync {
    /// Get the tunnel configuration
    fn config(&self) -> &WgTunnelConfig;

    /// Check if the tunnel is connected
    fn is_connected(&self) -> bool;

    /// Get tunnel statistics
    fn stats(&self) -> WgTunnelStats;

    /// Get the local tunnel IP address
    ///
    /// Returns a cloned String because the underlying storage uses
    /// interior mutability (RwLock) which prevents returning references.
    fn local_ip(&self) -> Option<String>;

    /// Get the peer endpoint address
    fn peer_endpoint(&self) -> Option<SocketAddr>;

    /// Get the last handshake timestamp
    fn last_handshake(&self) -> Option<u64>;
}

/// Builder for creating WireGuard tunnels
///
/// Provides a fluent API for constructing WireGuard tunnel instances
/// with various configurations and implementations.
///
/// # Example
///
/// ```ignore
/// use rust_router::tunnel::{WgTunnelBuilder, WgTunnelConfig};
///
/// let config = WgTunnelConfig::new(private_key, peer_public_key, endpoint);
/// let tunnel = WgTunnelBuilder::new(config)
///     .build_userspace()?;
/// ```
pub struct WgTunnelBuilder {
    config: WgTunnelConfig,
}

impl WgTunnelBuilder {
    /// Create a new tunnel builder
    ///
    /// # Arguments
    ///
    /// * `config` - The WireGuard tunnel configuration
    pub fn new(config: WgTunnelConfig) -> Self {
        Self { config }
    }

    /// Build a userspace tunnel using boringtun
    ///
    /// Creates a new [`UserspaceWgTunnel`] instance using the provided
    /// configuration. The tunnel uses boringtun for WireGuard crypto
    /// operations in pure Rust.
    ///
    /// # Returns
    ///
    /// A boxed trait object implementing [`WgTunnel`]
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration is invalid:
    /// - Missing private key
    /// - Missing peer public key
    /// - Missing peer endpoint
    /// - Invalid key format (not valid Base64 or wrong length)
    /// - Invalid endpoint format
    ///
    /// # Example
    ///
    /// ```ignore
    /// let tunnel = WgTunnelBuilder::new(config).build_userspace()?;
    /// tunnel.connect().await?;
    /// ```
    pub fn build_userspace(self) -> Result<Box<dyn WgTunnel>, WgTunnelError> {
        use crate::tunnel::userspace::UserspaceWgTunnel;
        let tunnel = UserspaceWgTunnel::new(self.config)?;
        Ok(Box::new(tunnel))
    }

    /// Get a reference to the configuration
    pub fn config(&self) -> &WgTunnelConfig {
        &self.config
    }

    /// Consume the builder and return the configuration
    pub fn into_config(self) -> WgTunnelConfig {
        self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wg_tunnel_stats_default() {
        let stats = WgTunnelStats::default();
        assert_eq!(stats.tx_bytes, 0);
        assert_eq!(stats.rx_bytes, 0);
        assert!(stats.last_handshake.is_none());
    }

    #[test]
    fn test_wg_tunnel_error_from_io() {
        let io_error = std::io::Error::new(std::io::ErrorKind::Other, "test error");
        let tunnel_error: WgTunnelError = io_error.into();
        assert!(matches!(tunnel_error, WgTunnelError::IoError(_)));
    }
}
