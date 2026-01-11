//! Error types for the `WireGuard` Ingress module
//!
//! This module defines error types specific to `WireGuard` ingress operations,
//! including tunnel management, packet processing, and peer management.
//!
//! # Error Categories
//!
//! - **Tunnel errors**: Issues with the underlying `WireGuard` tunnel
//! - **DSCP errors**: Packet processing and DSCP extraction failures
//! - **Configuration errors**: Invalid configuration parameters
//! - **State errors**: Invalid state transitions (already started, not started)
//! - **Processing errors**: Packet routing and processing failures
//! - **Peer errors**: Peer management failures

use std::net::IpAddr;

use thiserror::Error;

use crate::chain::dscp::DscpError;
use crate::tunnel::traits::WgTunnelError;

/// Error types for `WireGuard` ingress operations
#[derive(Debug, Error)]
pub enum IngressError {
    /// Tunnel error from the underlying `WireGuard` implementation
    #[error("Tunnel error: {0}")]
    TunnelError(#[from] WgTunnelError),

    /// DSCP extraction or modification error
    #[error("DSCP error: {0}")]
    DscpError(#[from] DscpError),

    /// Invalid configuration parameter
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    /// Ingress manager is already started
    #[error("Ingress manager already started")]
    AlreadyStarted,

    /// Ingress manager is not started
    #[error("Ingress manager not started")]
    NotStarted,

    /// Packet processing error
    #[error("Packet processing error: {0}")]
    ProcessingError(String),

    /// Peer not found
    #[error("Peer not found: {0}")]
    PeerNotFound(String),

    /// Peer already exists
    #[error("Peer already exists: {0}")]
    PeerAlreadyExists(String),

    /// Invalid packet (too short, malformed header)
    #[error("Invalid packet: {0}")]
    InvalidPacket(String),

    /// Source IP not in allowed subnet
    #[error("Source IP {ip} not in allowed subnet {subnet}")]
    SourceIpNotAllowed { ip: IpAddr, subnet: String },

    /// Socket bind error
    #[error("Failed to bind to {addr}: {reason}")]
    BindError { addr: String, reason: String },

    /// I/O error
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    /// Ingress manager is shutting down
    #[error("Ingress manager is shutting down")]
    ShuttingDown,

    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),
}

impl IngressError {
    /// Create an invalid configuration error
    pub fn invalid_config(msg: impl Into<String>) -> Self {
        Self::InvalidConfig(msg.into())
    }

    /// Create a processing error
    pub fn processing(msg: impl Into<String>) -> Self {
        Self::ProcessingError(msg.into())
    }

    /// Create a peer not found error
    pub fn peer_not_found(public_key: impl Into<String>) -> Self {
        Self::PeerNotFound(public_key.into())
    }

    /// Create a peer already exists error
    pub fn peer_already_exists(public_key: impl Into<String>) -> Self {
        Self::PeerAlreadyExists(public_key.into())
    }

    /// Create an invalid packet error
    pub fn invalid_packet(msg: impl Into<String>) -> Self {
        Self::InvalidPacket(msg.into())
    }

    /// Create a source IP not allowed error
    pub fn source_ip_not_allowed(ip: IpAddr, subnet: impl Into<String>) -> Self {
        Self::SourceIpNotAllowed {
            ip,
            subnet: subnet.into(),
        }
    }

    /// Create a bind error
    pub fn bind(addr: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::BindError {
            addr: addr.into(),
            reason: reason.into(),
        }
    }

    /// Create an internal error
    pub fn internal(msg: impl Into<String>) -> Self {
        Self::Internal(msg.into())
    }

    /// Check if this error is recoverable
    ///
    /// Recoverable errors can potentially be retried without intervention.
    #[must_use]
    pub fn is_recoverable(&self) -> bool {
        match self {
            Self::TunnelError(e) => matches!(
                e,
                WgTunnelError::IoError(_) | WgTunnelError::Timeout | WgTunnelError::NotConnected
            ),
            Self::DscpError(_) => true, // Packet-level errors are recoverable
            Self::InvalidConfig(_) => false,
            Self::AlreadyStarted => false,
            Self::NotStarted => false,
            Self::ProcessingError(_) => true,
            Self::PeerNotFound(_) => false,
            Self::PeerAlreadyExists(_) => false,
            Self::InvalidPacket(_) => true, // Skip the packet
            Self::SourceIpNotAllowed { .. } => true, // Skip the packet
            Self::BindError { .. } => false,
            Self::IoError(e) => matches!(
                e.kind(),
                std::io::ErrorKind::TimedOut
                    | std::io::ErrorKind::Interrupted
                    | std::io::ErrorKind::WouldBlock
            ),
            Self::ShuttingDown => false,
            Self::Internal(_) => false,
        }
    }
}

/// Type alias for Result with `IngressError`
pub type IngressResult<T> = std::result::Result<T, IngressError>;

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // Error Creation Tests
    // ========================================================================

    #[test]
    fn test_invalid_config_error() {
        let err = IngressError::invalid_config("missing private key");
        assert!(matches!(err, IngressError::InvalidConfig(_)));
        assert!(err.to_string().contains("missing private key"));
        assert!(!err.is_recoverable());
    }

    #[test]
    fn test_processing_error() {
        let err = IngressError::processing("failed to match rule");
        assert!(matches!(err, IngressError::ProcessingError(_)));
        assert!(err.to_string().contains("failed to match rule"));
        assert!(err.is_recoverable());
    }

    #[test]
    fn test_peer_not_found_error() {
        let err = IngressError::peer_not_found("abc123");
        assert!(matches!(err, IngressError::PeerNotFound(_)));
        assert!(err.to_string().contains("abc123"));
        assert!(!err.is_recoverable());
    }

    #[test]
    fn test_peer_already_exists_error() {
        let err = IngressError::peer_already_exists("xyz789");
        assert!(matches!(err, IngressError::PeerAlreadyExists(_)));
        assert!(err.to_string().contains("xyz789"));
        assert!(!err.is_recoverable());
    }

    #[test]
    fn test_invalid_packet_error() {
        let err = IngressError::invalid_packet("packet too short");
        assert!(matches!(err, IngressError::InvalidPacket(_)));
        assert!(err.to_string().contains("packet too short"));
        assert!(err.is_recoverable());
    }

    #[test]
    fn test_source_ip_not_allowed_error() {
        let ip: IpAddr = "192.168.1.100".parse().unwrap();
        let err = IngressError::source_ip_not_allowed(ip, "10.25.0.0/24");
        assert!(matches!(err, IngressError::SourceIpNotAllowed { .. }));
        assert!(err.to_string().contains("192.168.1.100"));
        assert!(err.to_string().contains("10.25.0.0/24"));
        assert!(err.is_recoverable());
    }

    #[test]
    fn test_bind_error() {
        let err = IngressError::bind("0.0.0.0:36100", "address already in use");
        assert!(matches!(err, IngressError::BindError { .. }));
        assert!(err.to_string().contains("0.0.0.0:36100"));
        assert!(err.to_string().contains("address already in use"));
        assert!(!err.is_recoverable());
    }

    #[test]
    fn test_internal_error() {
        let err = IngressError::internal("unexpected state");
        assert!(matches!(err, IngressError::Internal(_)));
        assert!(err.to_string().contains("unexpected state"));
        assert!(!err.is_recoverable());
    }

    // ========================================================================
    // State Error Tests
    // ========================================================================

    #[test]
    fn test_already_started_error() {
        let err = IngressError::AlreadyStarted;
        assert!(err.to_string().contains("already started"));
        assert!(!err.is_recoverable());
    }

    #[test]
    fn test_not_started_error() {
        let err = IngressError::NotStarted;
        assert!(err.to_string().contains("not started"));
        assert!(!err.is_recoverable());
    }

    #[test]
    fn test_shutting_down_error() {
        let err = IngressError::ShuttingDown;
        assert!(err.to_string().contains("shutting down"));
        assert!(!err.is_recoverable());
    }

    // ========================================================================
    // Error Conversion Tests
    // ========================================================================

    #[test]
    fn test_from_wg_tunnel_error() {
        let tunnel_err = WgTunnelError::NotConnected;
        let ingress_err: IngressError = tunnel_err.into();
        assert!(matches!(ingress_err, IngressError::TunnelError(_)));
        assert!(ingress_err.is_recoverable());
    }

    #[test]
    fn test_from_wg_tunnel_error_not_recoverable() {
        let tunnel_err = WgTunnelError::InvalidConfig("bad config".to_string());
        let ingress_err: IngressError = tunnel_err.into();
        assert!(matches!(ingress_err, IngressError::TunnelError(_)));
        assert!(!ingress_err.is_recoverable());
    }

    #[test]
    fn test_from_dscp_error() {
        let dscp_err = DscpError::EmptyPacket;
        let ingress_err: IngressError = dscp_err.into();
        assert!(matches!(ingress_err, IngressError::DscpError(_)));
        assert!(ingress_err.is_recoverable());
    }

    #[test]
    fn test_from_io_error_recoverable() {
        let io_err = std::io::Error::new(std::io::ErrorKind::TimedOut, "timeout");
        let ingress_err: IngressError = io_err.into();
        assert!(matches!(ingress_err, IngressError::IoError(_)));
        assert!(ingress_err.is_recoverable());
    }

    #[test]
    fn test_from_io_error_not_recoverable() {
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "permission denied");
        let ingress_err: IngressError = io_err.into();
        assert!(matches!(ingress_err, IngressError::IoError(_)));
        assert!(!ingress_err.is_recoverable());
    }

    // ========================================================================
    // Display Tests
    // ========================================================================

    #[test]
    fn test_error_display_tunnel() {
        let err = IngressError::TunnelError(WgTunnelError::Timeout);
        let display = err.to_string();
        assert!(display.contains("Tunnel error"));
    }

    #[test]
    fn test_error_display_dscp() {
        let err = IngressError::DscpError(DscpError::InvalidIpVersion(7));
        let display = err.to_string();
        assert!(display.contains("DSCP error"));
    }

    #[test]
    fn test_error_debug() {
        let err = IngressError::invalid_config("test");
        let debug = format!("{:?}", err);
        assert!(debug.contains("InvalidConfig"));
    }

    // ========================================================================
    // Recovery Classification Tests
    // ========================================================================

    #[test]
    fn test_recoverable_errors() {
        let recoverable = vec![
            IngressError::processing("test"),
            IngressError::invalid_packet("test"),
            IngressError::source_ip_not_allowed("10.0.0.1".parse().unwrap(), "192.168.0.0/24"),
            IngressError::DscpError(DscpError::PacketTooShort(10, 20)),
        ];

        for err in recoverable {
            assert!(
                err.is_recoverable(),
                "Expected {} to be recoverable",
                err
            );
        }
    }

    #[test]
    fn test_non_recoverable_errors() {
        let non_recoverable = vec![
            IngressError::invalid_config("test"),
            IngressError::AlreadyStarted,
            IngressError::NotStarted,
            IngressError::peer_not_found("key"),
            IngressError::peer_already_exists("key"),
            IngressError::bind("addr", "reason"),
            IngressError::ShuttingDown,
            IngressError::internal("test"),
        ];

        for err in non_recoverable {
            assert!(
                !err.is_recoverable(),
                "Expected {} to be non-recoverable",
                err
            );
        }
    }
}
