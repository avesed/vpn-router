// Some fields are reserved for internal tracking.
#![allow(dead_code)]

//! TPROXY listener wrapper for the kernel backend
//!
//! This module provides wrappers around the existing TPROXY listener implementation,
//! integrating it with the netbridge types and error handling.
//!
//! # Architecture
//!
//! TPROXY (Transparent Proxy) allows intercepting TCP/UDP traffic without modifying
//! the client's packets, while preserving the original destination address.
//!
//! The wrapper provides:
//! - Integration with netbridge error types
//! - TCP and UDP listener management
//! - Connection metadata for session tracking
//!
//! # Requirements
//!
//! - Linux kernel with TPROXY support (xt_TPROXY module)
//! - CAP_NET_ADMIN capability for IP_TRANSPARENT socket option
//! - CAP_NET_RAW capability for transparent socket binding
//! - iptables rules configured by `IptablesManager`

use std::net::SocketAddr;
use std::time::Instant;

use tokio::net::TcpStream;
use tracing::{info, trace};

use crate::config::ListenConfig;
use crate::error::TproxyError;
use crate::netbridge::error::{NetBridgeError, Result};
use crate::netbridge::types::FiveTuple;
use crate::tproxy::{TproxyConnection, TproxyListener, TproxyListenerBuilder};

// =============================================================================
// TPROXY Listener Wrapper
// =============================================================================

/// Wrapper around TproxyListener for netbridge integration
///
/// This struct provides a higher-level interface to the TPROXY listener,
/// handling error translation and providing connection metadata.
#[derive(Debug)]
pub struct TproxyListenerWrapper {
    /// Underlying TPROXY listener
    listener: TproxyListener,
    /// Listen address
    listen_addr: SocketAddr,
    /// Optional fwmark for policy routing
    fwmark: Option<u32>,
    /// Statistics
    stats: TproxyListenerStats,
}

/// Statistics for the TPROXY listener
#[derive(Debug, Default)]
pub struct TproxyListenerStats {
    /// Total connections accepted
    pub connections_accepted: u64,
    /// Failed accepts
    pub accept_errors: u64,
    /// Original destination retrieval errors
    pub original_dst_errors: u64,
}

impl TproxyListenerWrapper {
    /// Create a new TPROXY TCP listener
    ///
    /// # Arguments
    ///
    /// * `listen_addr` - Address to listen on
    /// * `fwmark` - Optional fwmark for policy routing
    /// * `backlog` - TCP backlog size
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Socket creation fails
    /// - CAP_NET_ADMIN is missing
    /// - Binding fails
    pub fn bind(listen_addr: SocketAddr, fwmark: Option<u32>, backlog: u32) -> Result<Self> {
        info!(
            listen_addr = %listen_addr,
            fwmark = ?fwmark,
            backlog = backlog,
            "Creating TPROXY TCP listener"
        );

        let listener = TproxyListenerBuilder::new(listen_addr)
            .backlog(backlog)
            .fwmark(fwmark)
            .build()
            .map_err(Self::convert_tproxy_error)?;

        info!(
            listen_addr = %listen_addr,
            "TPROXY TCP listener created"
        );

        Ok(Self {
            listener,
            listen_addr,
            fwmark,
            stats: TproxyListenerStats::default(),
        })
    }

    /// Create from a ListenConfig
    ///
    /// # Arguments
    ///
    /// * `config` - Listen configuration
    /// * `fwmark` - Optional fwmark for policy routing
    pub fn from_config(config: &ListenConfig, fwmark: Option<u32>) -> Result<Self> {
        Self::bind(config.address, fwmark, config.tcp_backlog)
    }

    /// Accept a new TPROXY connection
    ///
    /// Returns a `TproxyConnectionWrapper` with client address, original
    /// destination, and the TCP stream.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Accept fails
    /// - Original destination retrieval fails
    /// - Listener is not active
    pub async fn accept(&mut self) -> Result<TproxyConnectionWrapper> {
        let connection = self
            .listener
            .accept()
            .await
            .map_err(|e| {
                self.stats.accept_errors += 1;
                match e {
                    TproxyError::OriginalDstError(msg) => {
                        self.stats.original_dst_errors += 1;
                        NetBridgeError::Tproxy(format!("Original destination error: {}", msg))
                    }
                    TproxyError::AcceptError(msg) => {
                        NetBridgeError::Tproxy(format!("Accept error: {}", msg))
                    }
                    other => Self::convert_tproxy_error(other),
                }
            })?;

        self.stats.connections_accepted += 1;

        trace!(
            client = %connection.client_addr(),
            dst = %connection.original_dst(),
            "Accepted TPROXY connection"
        );

        Ok(TproxyConnectionWrapper::new(connection))
    }

    /// Get the listen address
    #[inline]
    #[must_use]
    pub const fn listen_addr(&self) -> SocketAddr {
        self.listen_addr
    }

    /// Get the fwmark
    #[inline]
    #[must_use]
    pub const fn fwmark(&self) -> Option<u32> {
        self.fwmark
    }

    /// Check if the listener is active
    #[inline]
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.listener.is_active()
    }

    /// Deactivate the listener
    pub fn deactivate(&mut self) {
        self.listener.deactivate();
    }

    /// Reactivate the listener
    pub fn reactivate(&mut self) {
        self.listener.reactivate();
    }

    /// Get statistics
    #[inline]
    #[must_use]
    pub const fn stats(&self) -> &TproxyListenerStats {
        &self.stats
    }

    /// Convert TproxyError to NetBridgeError
    fn convert_tproxy_error(e: TproxyError) -> NetBridgeError {
        match e {
            TproxyError::PermissionDenied => NetBridgeError::PermissionDenied(
                "TPROXY requires CAP_NET_ADMIN capability".to_string(),
            ),
            TproxyError::SocketCreation(msg) => {
                NetBridgeError::Tproxy(format!("Socket creation failed: {}", msg))
            }
            TproxyError::SocketOption { option, reason } => {
                NetBridgeError::Tproxy(format!("Socket option {} failed: {}", option, reason))
            }
            TproxyError::BindError { addr, reason } => {
                NetBridgeError::Tproxy(format!("Bind to {} failed: {}", addr, reason))
            }
            TproxyError::OriginalDstError(msg) => {
                NetBridgeError::Tproxy(format!("Original destination error: {}", msg))
            }
            TproxyError::AcceptError(msg) => {
                NetBridgeError::Tproxy(format!("Accept error: {}", msg))
            }
            TproxyError::NotReady => NetBridgeError::NotInitialized,
            TproxyError::IoError(e) => NetBridgeError::Io(e),
        }
    }
}

// =============================================================================
// TPROXY Connection Wrapper
// =============================================================================

/// Wrapper around TproxyConnection for netbridge integration
///
/// This struct provides convenient access to connection metadata
/// and the underlying TCP stream.
#[derive(Debug)]
pub struct TproxyConnectionWrapper {
    /// Underlying connection
    connection: TproxyConnection,
    /// When the connection was wrapped
    wrapped_at: Instant,
}

impl TproxyConnectionWrapper {
    /// Create a new connection wrapper
    fn new(connection: TproxyConnection) -> Self {
        Self {
            connection,
            wrapped_at: Instant::now(),
        }
    }

    /// Get the client's source address
    #[inline]
    #[must_use]
    pub fn client_addr(&self) -> SocketAddr {
        self.connection.client_addr()
    }

    /// Get the original destination address
    #[inline]
    #[must_use]
    pub fn original_dst(&self) -> SocketAddr {
        self.connection.original_dst()
    }

    /// Get the 5-tuple for this connection
    #[inline]
    #[must_use]
    pub fn five_tuple(&self) -> FiveTuple {
        FiveTuple::tcp(self.client_addr(), self.original_dst())
    }

    /// Get when the connection was accepted
    #[inline]
    #[must_use]
    pub fn accepted_at(&self) -> Instant {
        self.connection.accepted_at()
    }

    /// Get the connection age since acceptance
    #[inline]
    #[must_use]
    pub fn age(&self) -> std::time::Duration {
        self.connection.age()
    }

    /// Check if the destination is likely TLS (port 443, 8443, 853)
    #[inline]
    #[must_use]
    pub fn is_likely_tls(&self) -> bool {
        self.connection.is_likely_tls()
    }

    /// Check if the destination is likely HTTP (port 80, 8080, 8000, 3000)
    #[inline]
    #[must_use]
    pub fn is_likely_http(&self) -> bool {
        self.connection.is_likely_http()
    }

    /// Get a reference to the underlying TCP stream
    #[inline]
    #[must_use]
    pub fn stream(&self) -> &TcpStream {
        self.connection.stream()
    }

    /// Get a mutable reference to the underlying TCP stream
    #[inline]
    pub fn stream_mut(&mut self) -> &mut TcpStream {
        self.connection.stream_mut()
    }

    /// Consume and return the underlying TCP stream
    #[inline]
    #[must_use]
    pub fn into_stream(self) -> TcpStream {
        self.connection.into_stream()
    }

    /// Consume and return the underlying connection
    #[inline]
    #[must_use]
    pub fn into_inner(self) -> TproxyConnection {
        self.connection
    }
}

// =============================================================================
// TPROXY Listener Builder
// =============================================================================

/// Builder for TPROXY listener configuration
#[derive(Debug, Clone)]
pub struct TproxyListenerConfig {
    /// Listen address
    pub listen_addr: SocketAddr,
    /// fwmark for policy routing
    pub fwmark: Option<u32>,
    /// TCP backlog
    pub backlog: u32,
}

impl TproxyListenerConfig {
    /// Create a new configuration with the given listen address
    #[must_use]
    pub fn new(listen_addr: SocketAddr) -> Self {
        Self {
            listen_addr,
            fwmark: None,
            backlog: 1024,
        }
    }

    /// Set the fwmark
    #[must_use]
    pub const fn fwmark(mut self, mark: u32) -> Self {
        self.fwmark = Some(mark);
        self
    }

    /// Set the TCP backlog
    #[must_use]
    pub const fn backlog(mut self, backlog: u32) -> Self {
        self.backlog = backlog;
        self
    }

    /// Build the TPROXY listener
    ///
    /// # Errors
    ///
    /// Returns an error if listener creation fails.
    pub fn build(self) -> Result<TproxyListenerWrapper> {
        TproxyListenerWrapper::bind(self.listen_addr, self.fwmark, self.backlog)
    }
}

impl Default for TproxyListenerConfig {
    fn default() -> Self {
        Self::new("127.0.0.1:7893".parse().unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn test_addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    }

    #[test]
    fn test_config_defaults() {
        let config = TproxyListenerConfig::default();
        assert_eq!(config.listen_addr.port(), 7893);
        assert_eq!(config.fwmark, None);
        assert_eq!(config.backlog, 1024);
    }

    #[test]
    fn test_config_builder() {
        let config = TproxyListenerConfig::new(test_addr(8080))
            .fwmark(0x1)
            .backlog(512);

        assert_eq!(config.listen_addr.port(), 8080);
        assert_eq!(config.fwmark, Some(0x1));
        assert_eq!(config.backlog, 512);
    }

    #[test]
    fn test_five_tuple_creation() {
        // Test that we can create a FiveTuple from addresses
        let client = test_addr(12345);
        let dst = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 443);

        let tuple = FiveTuple::tcp(client, dst);
        assert!(tuple.is_tcp());
        assert_eq!(tuple.src_port, 12345);
        assert_eq!(tuple.dst_port, 443);
    }

    #[test]
    fn test_stats_default() {
        let stats = TproxyListenerStats::default();
        assert_eq!(stats.connections_accepted, 0);
        assert_eq!(stats.accept_errors, 0);
        assert_eq!(stats.original_dst_errors, 0);
    }
}
