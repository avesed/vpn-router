//! Error types for the netbridge module
//!
//! This module defines error types used throughout the netbridge implementations.
//! All errors are designed to be informative for debugging while also being
//! suitable for logging and metrics.
//!
//! # Error Categories
//!
//! Errors are classified into categories that help determine appropriate handling:
//!
//! - **Transient**: May resolve on retry (port exhaustion, timeouts, temporary failures)
//! - **Permanent**: Will not resolve without intervention (invalid address, connection refused)
//! - **Resource Exhaustion**: System resource limits reached (ports, sockets, sessions)
//!
//! # Example
//!
//! ```ignore
//! use rust_router::netbridge::{NetBridgeError, Result};
//!
//! fn handle_connection() -> Result<()> {
//!     // ... operation that might fail ...
//!     Err(NetBridgeError::ConnectionTimeout)
//! }
//!
//! fn main() {
//!     match handle_connection() {
//!         Ok(()) => println!("Success"),
//!         Err(e) if e.is_transient() => println!("Retry later: {}", e),
//!         Err(e) if e.is_permanent() => println!("Cannot recover: {}", e),
//!         Err(e) => println!("Error: {}", e),
//!     }
//! }
//! ```

use std::io;
use thiserror::Error;

/// Errors that can occur during netbridge operations
#[derive(Error, Debug)]
pub enum NetBridgeError {
    // =========================================================================
    // Resource Exhaustion Errors
    // =========================================================================
    /// All ephemeral ports in the configured range are in use
    #[error("port exhausted: all ephemeral ports in use")]
    PortExhausted,

    /// The maximum number of sockets has been reached
    #[error("socket limit reached: max {0} sockets")]
    SocketLimitReached(usize),

    /// The maximum number of sessions has been reached
    #[error("session limit reached: max {0} sessions")]
    SessionLimitReached(usize),

    /// The maximum number of sessions per client has been reached
    #[error("per-client session limit reached: max {0} sessions per client")]
    PerClientSessionLimitReached(usize),

    /// The client is creating sessions too fast (rate limited)
    #[error("session creation rate limit exceeded: max {0} sessions per second")]
    SessionRateLimitExceeded(usize),

    /// Memory allocation failed
    #[error("memory allocation failed: {0}")]
    AllocationFailed(String),

    // =========================================================================
    // Connection Errors
    // =========================================================================
    /// The remote host refused the connection
    #[error("connection refused")]
    ConnectionRefused,

    /// The connection timed out
    #[error("connection timed out")]
    ConnectionTimeout,

    /// Connection was reset by peer
    #[error("connection reset")]
    ConnectionReset,

    /// Connection was aborted
    #[error("connection aborted")]
    ConnectionAborted,

    /// Network is unreachable
    #[error("network unreachable")]
    NetworkUnreachable,

    /// Host is unreachable
    #[error("host unreachable")]
    HostUnreachable,

    // =========================================================================
    // Session Errors
    // =========================================================================
    /// A session could not be found by its identifier
    #[error("session not found: {0}")]
    SessionNotFound(String),

    /// The session key already exists
    #[error("session already exists: {0}")]
    SessionAlreadyExists(String),

    /// Invalid session state for the requested operation
    #[error("invalid session state: expected {expected}, got {actual}")]
    InvalidSessionState {
        /// The expected state
        expected: String,
        /// The actual state
        actual: String,
    },

    // =========================================================================
    // Tunnel/Bridge Errors
    // =========================================================================
    /// The tunnel is not active or has failed
    #[error("tunnel down: {0}")]
    TunnelDown(String),

    /// Bridge not initialized
    #[error("bridge not initialized")]
    NotInitialized,

    /// Bridge is shutting down
    #[error("bridge shutting down")]
    ShuttingDown,

    /// TUN device error
    #[error("TUN device error: {0}")]
    TunDevice(String),

    /// TPROXY error
    #[error("TPROXY error: {0}")]
    Tproxy(String),

    /// iptables/nftables error
    #[error("firewall error: {0}")]
    Firewall(String),

    // =========================================================================
    // Protocol Errors
    // =========================================================================
    /// DNS resolution failed
    #[error("DNS resolution failed: {0}")]
    DnsResolutionFailed(String),

    /// Invalid address format
    #[error("invalid address: {0}")]
    InvalidAddress(String),

    /// Invalid packet format
    #[error("invalid packet: {0}")]
    InvalidPacket(String),

    /// Protocol error
    #[error("protocol error: {0}")]
    ProtocolError(String),

    // =========================================================================
    // Smoltcp-specific Errors
    // =========================================================================
    /// A smoltcp TCP socket error
    #[error("smoltcp TCP error: {0}")]
    SmoltcpTcp(String),

    /// A smoltcp UDP socket error
    #[error("smoltcp UDP error: {0}")]
    SmoltcpUdp(String),

    /// smoltcp interface error
    #[error("smoltcp interface error: {0}")]
    SmoltcpInterface(String),

    // =========================================================================
    // Channel Errors
    // =========================================================================
    /// Channel send failed
    #[error("channel send failed: {0}")]
    ChannelSendFailed(String),

    /// Channel receive failed
    #[error("channel receive failed: {0}")]
    ChannelReceiveFailed(String),

    /// Channel closed
    #[error("channel closed")]
    ChannelClosed,

    // =========================================================================
    // I/O Errors
    // =========================================================================
    /// An I/O error occurred
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    /// Permission denied
    #[error("permission denied: {0}")]
    PermissionDenied(String),

    // =========================================================================
    // Other Errors
    // =========================================================================
    /// Operation was cancelled
    #[error("operation cancelled")]
    Cancelled,

    /// Socket not found
    #[error("socket not found: {0}")]
    SocketNotFound(String),

    /// Configuration error
    #[error("configuration error: {0}")]
    Config(String),

    /// Internal error (should not happen)
    #[error("internal error: {0}")]
    Internal(String),

    /// Internal error with additional context
    #[error("internal error: {0}")]
    InternalError(String),

    /// Feature not supported
    #[error("not supported: {0}")]
    NotSupported(String),
}

impl NetBridgeError {
    /// Returns true if this error indicates a transient condition that may resolve
    ///
    /// Transient errors may succeed on retry after waiting or when resources
    /// become available.
    #[must_use]
    pub fn is_transient(&self) -> bool {
        matches!(
            self,
            Self::PortExhausted
                | Self::SocketLimitReached(_)
                | Self::SessionLimitReached(_)
                | Self::PerClientSessionLimitReached(_)
                | Self::SessionRateLimitExceeded(_)
                | Self::ConnectionTimeout
                | Self::ConnectionReset
                | Self::TunnelDown(_)
                | Self::Cancelled
                | Self::ChannelClosed
        )
    }

    /// Returns true if this error indicates a permanent failure
    ///
    /// Permanent errors will not resolve without external intervention
    /// (e.g., configuration change, network fix).
    #[must_use]
    pub fn is_permanent(&self) -> bool {
        matches!(
            self,
            Self::ConnectionRefused
                | Self::DnsResolutionFailed(_)
                | Self::InvalidAddress(_)
                | Self::InvalidPacket(_)
                | Self::InvalidSessionState { .. }
                | Self::NotInitialized
                | Self::Config(_)
                | Self::PermissionDenied(_)
                | Self::NotSupported(_)
        )
    }

    /// Returns true if this error indicates a resource exhaustion condition
    ///
    /// Resource exhaustion errors indicate system limits have been reached.
    /// The caller should wait for resources to be freed or reduce load.
    #[must_use]
    pub fn is_resource_exhaustion(&self) -> bool {
        matches!(
            self,
            Self::PortExhausted
                | Self::SocketLimitReached(_)
                | Self::SessionLimitReached(_)
                | Self::PerClientSessionLimitReached(_)
                | Self::SessionRateLimitExceeded(_)
                | Self::AllocationFailed(_)
        )
    }

    /// Returns true if this is a connection-related error
    #[must_use]
    pub fn is_connection_error(&self) -> bool {
        matches!(
            self,
            Self::ConnectionRefused
                | Self::ConnectionTimeout
                | Self::ConnectionReset
                | Self::ConnectionAborted
                | Self::NetworkUnreachable
                | Self::HostUnreachable
        )
    }

    /// Returns true if this is a session-related error
    #[must_use]
    pub fn is_session_error(&self) -> bool {
        matches!(
            self,
            Self::SessionNotFound(_)
                | Self::SessionAlreadyExists(_)
                | Self::InvalidSessionState { .. }
                | Self::SessionLimitReached(_)
                | Self::PerClientSessionLimitReached(_)
                | Self::SessionRateLimitExceeded(_)
        )
    }

    // =========================================================================
    // Smoltcp Error Helpers
    // =========================================================================

    /// Create a `SmoltcpTcp` error from a smoltcp connect error
    #[must_use]
    pub fn from_tcp_connect_error(err: smoltcp::socket::tcp::ConnectError) -> Self {
        Self::SmoltcpTcp(format!("connect error: {err:?}"))
    }

    /// Create a `SmoltcpTcp` error from a smoltcp send error
    #[must_use]
    pub fn from_tcp_send_error(err: smoltcp::socket::tcp::SendError) -> Self {
        Self::SmoltcpTcp(format!("send error: {err:?}"))
    }

    /// Create a `SmoltcpTcp` error from a smoltcp recv error
    #[must_use]
    pub fn from_tcp_recv_error(err: smoltcp::socket::tcp::RecvError) -> Self {
        Self::SmoltcpTcp(format!("recv error: {err:?}"))
    }

    /// Create a `SmoltcpTcp` error from a smoltcp listen error
    #[must_use]
    pub fn from_tcp_listen_error(err: smoltcp::socket::tcp::ListenError) -> Self {
        Self::SmoltcpTcp(format!("listen error: {err:?}"))
    }

    /// Create a `SmoltcpUdp` error from a smoltcp bind error
    #[must_use]
    pub fn from_udp_bind_error(err: smoltcp::socket::udp::BindError) -> Self {
        Self::SmoltcpUdp(format!("bind error: {err:?}"))
    }

    /// Create a `SmoltcpUdp` error from a smoltcp send error
    #[must_use]
    pub fn from_udp_send_error(err: smoltcp::socket::udp::SendError) -> Self {
        Self::SmoltcpUdp(format!("send error: {err:?}"))
    }

    /// Create a `SmoltcpUdp` error from a smoltcp recv error
    #[must_use]
    pub fn from_udp_recv_error(err: smoltcp::socket::udp::RecvError) -> Self {
        Self::SmoltcpUdp(format!("recv error: {err:?}"))
    }
}

/// A specialized Result type for netbridge operations
pub type Result<T> = std::result::Result<T, NetBridgeError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = NetBridgeError::PortExhausted;
        assert_eq!(
            err.to_string(),
            "port exhausted: all ephemeral ports in use"
        );

        let err = NetBridgeError::SocketLimitReached(2048);
        assert_eq!(err.to_string(), "socket limit reached: max 2048 sockets");

        let err = NetBridgeError::SessionNotFound("test-session".to_string());
        assert_eq!(err.to_string(), "session not found: test-session");

        let err = NetBridgeError::TunnelDown("wg-egress-1".to_string());
        assert_eq!(err.to_string(), "tunnel down: wg-egress-1");

        let err = NetBridgeError::ConnectionRefused;
        assert_eq!(err.to_string(), "connection refused");

        let err = NetBridgeError::ConnectionTimeout;
        assert_eq!(err.to_string(), "connection timed out");
    }

    #[test]
    fn test_io_error_conversion() {
        let io_err = io::Error::new(io::ErrorKind::ConnectionReset, "connection reset");
        let bridge_err: NetBridgeError = io_err.into();
        assert!(matches!(bridge_err, NetBridgeError::Io(_)));
        assert!(bridge_err.to_string().contains("connection reset"));
    }

    #[test]
    fn test_is_transient() {
        assert!(NetBridgeError::PortExhausted.is_transient());
        assert!(NetBridgeError::SocketLimitReached(2048).is_transient());
        assert!(NetBridgeError::ConnectionTimeout.is_transient());
        assert!(NetBridgeError::TunnelDown("test".to_string()).is_transient());
        assert!(NetBridgeError::SessionLimitReached(10000).is_transient());
        assert!(NetBridgeError::Cancelled.is_transient());

        assert!(!NetBridgeError::ConnectionRefused.is_transient());
        assert!(!NetBridgeError::DnsResolutionFailed("test".to_string()).is_transient());
    }

    #[test]
    fn test_is_permanent() {
        assert!(NetBridgeError::ConnectionRefused.is_permanent());
        assert!(NetBridgeError::DnsResolutionFailed("test".to_string()).is_permanent());
        assert!(NetBridgeError::InvalidAddress("test".to_string()).is_permanent());
        assert!(NetBridgeError::InvalidSessionState {
            expected: "active".to_string(),
            actual: "closed".to_string()
        }
        .is_permanent());
        assert!(NetBridgeError::NotInitialized.is_permanent());

        assert!(!NetBridgeError::PortExhausted.is_permanent());
        assert!(!NetBridgeError::ConnectionTimeout.is_permanent());
    }

    #[test]
    fn test_is_resource_exhaustion() {
        assert!(NetBridgeError::PortExhausted.is_resource_exhaustion());
        assert!(NetBridgeError::SocketLimitReached(2048).is_resource_exhaustion());
        assert!(NetBridgeError::SessionLimitReached(10000).is_resource_exhaustion());
        assert!(NetBridgeError::PerClientSessionLimitReached(100).is_resource_exhaustion());
        assert!(NetBridgeError::AllocationFailed("OOM".to_string()).is_resource_exhaustion());

        assert!(!NetBridgeError::ConnectionRefused.is_resource_exhaustion());
        assert!(!NetBridgeError::ConnectionTimeout.is_resource_exhaustion());
    }

    #[test]
    fn test_is_connection_error() {
        assert!(NetBridgeError::ConnectionRefused.is_connection_error());
        assert!(NetBridgeError::ConnectionTimeout.is_connection_error());
        assert!(NetBridgeError::ConnectionReset.is_connection_error());
        assert!(NetBridgeError::NetworkUnreachable.is_connection_error());

        assert!(!NetBridgeError::PortExhausted.is_connection_error());
        assert!(!NetBridgeError::SessionNotFound("x".to_string()).is_connection_error());
    }

    #[test]
    fn test_is_session_error() {
        assert!(NetBridgeError::SessionNotFound("x".to_string()).is_session_error());
        assert!(NetBridgeError::SessionAlreadyExists("x".to_string()).is_session_error());
        assert!(NetBridgeError::SessionLimitReached(100).is_session_error());

        assert!(!NetBridgeError::PortExhausted.is_session_error());
        assert!(!NetBridgeError::ConnectionTimeout.is_session_error());
    }

    #[test]
    fn test_channel_errors() {
        let err = NetBridgeError::ChannelSendFailed("buffer full".to_string());
        assert!(err.to_string().contains("channel send failed"));

        let err = NetBridgeError::ChannelReceiveFailed("channel closed".to_string());
        assert!(err.to_string().contains("channel receive failed"));

        let err = NetBridgeError::ChannelClosed;
        assert!(err.is_transient());
    }

    #[test]
    fn test_smoltcp_errors() {
        let err = NetBridgeError::SmoltcpTcp("test error".to_string());
        assert!(err.to_string().contains("smoltcp TCP error"));

        let err = NetBridgeError::SmoltcpUdp("test error".to_string());
        assert!(err.to_string().contains("smoltcp UDP error"));
    }

    #[test]
    fn test_new_error_variants() {
        let err = NetBridgeError::TunDevice("failed to create".to_string());
        assert!(err.to_string().contains("TUN device error"));

        let err = NetBridgeError::Tproxy("bind failed".to_string());
        assert!(err.to_string().contains("TPROXY error"));

        let err = NetBridgeError::Firewall("iptables failed".to_string());
        assert!(err.to_string().contains("firewall error"));

        let err = NetBridgeError::ShuttingDown;
        assert!(err.to_string().contains("shutting down"));
    }
}
