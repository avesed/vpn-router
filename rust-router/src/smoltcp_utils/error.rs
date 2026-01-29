//! Error types for smoltcp bridge utilities
//!
//! This module defines the error types used throughout the bridge implementations.
//! All errors are designed to be informative for debugging while also being
//! suitable for logging and metrics.
//!
//! # Error Categories
//!
//! Errors are classified into categories that help determine appropriate handling:
//!
//! - **Transient**: May resolve on retry (port exhaustion, timeouts)
//! - **Permanent**: Will not resolve without intervention (invalid address, connection refused)
//! - **Resource Exhaustion**: System resource limits reached
//!
//! # Example
//!
//! ```ignore
//! use rust_router::smoltcp_utils::{BridgeError, Result};
//!
//! fn handle_connection() -> Result<()> {
//!     // ... operation that might fail ...
//!     Err(BridgeError::ConnectionTimeout)
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

/// Errors that can occur during smoltcp bridge operations
#[derive(Error, Debug)]
pub enum BridgeError {
    /// All ephemeral ports in the configured range are in use
    #[error("port exhausted: all ephemeral ports in use")]
    PortExhausted,

    /// The maximum number of smoltcp sockets has been reached
    #[error("socket limit reached: max {0} sockets")]
    SocketLimitReached(usize),

    /// A session could not be found by its identifier
    #[error("session not found: {0}")]
    SessionNotFound(String),

    /// The WireGuard tunnel is not active or has failed
    #[error("tunnel down: {0}")]
    TunnelDown(String),

    /// DNS resolution failed for a domain
    #[error("DNS resolution failed: {0}")]
    DnsResolutionFailed(String),

    /// The remote host refused the connection
    #[error("connection refused")]
    ConnectionRefused,

    /// The connection timed out
    #[error("connection timed out")]
    ConnectionTimeout,

    /// An I/O error occurred
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    /// A smoltcp TCP socket error occurred
    #[error("smoltcp TCP error: {0}")]
    SmoltcpTcp(String),

    /// A smoltcp UDP socket error occurred
    #[error("smoltcp UDP error: {0}")]
    SmoltcpUdp(String),

    /// The maximum number of sessions has been reached
    #[error("session limit reached: max {0} sessions")]
    SessionLimitReached(usize),

    /// The maximum number of sessions per client has been reached
    #[error("per-client session limit reached: max {0} sessions per client")]
    PerClientSessionLimitReached(usize),

    /// The client is creating sessions too fast (rate limited)
    #[error("session creation rate limit exceeded: max {0} sessions per second")]
    SessionRateLimitExceeded(usize),

    /// Invalid session state for the requested operation
    #[error("invalid session state: expected {expected}, got {actual}")]
    InvalidSessionState {
        /// The expected state
        expected: String,
        /// The actual state
        actual: String,
    },

    /// The session key already exists
    #[error("session already exists: {0}")]
    SessionAlreadyExists(String),

    /// Invalid address format
    #[error("invalid address: {0}")]
    InvalidAddress(String),

    /// Channel send failed
    #[error("channel send failed: {0}")]
    ChannelSendFailed(String),

    /// Channel receive failed
    #[error("channel receive failed: {0}")]
    ChannelReceiveFailed(String),

    /// Socket not found
    #[error("socket not found: {0}")]
    SocketNotFound(String),

    /// Bridge not initialized
    #[error("bridge not initialized")]
    NotInitialized,

    /// Operation cancelled
    #[error("operation cancelled")]
    Cancelled,
}

impl BridgeError {
    /// Returns true if this error indicates a transient condition that may resolve
    ///
    /// Transient errors may succeed on retry after waiting or when resources
    /// become available.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let err = BridgeError::ConnectionTimeout;
    /// assert!(err.is_transient());
    ///
    /// let err = BridgeError::ConnectionRefused;
    /// assert!(!err.is_transient());
    /// ```
    #[must_use]
    pub fn is_transient(&self) -> bool {
        matches!(
            self,
            Self::PortExhausted
                | Self::SocketLimitReached(_)
                | Self::ConnectionTimeout
                | Self::TunnelDown(_)
                | Self::SessionLimitReached(_)
                | Self::PerClientSessionLimitReached(_)
                | Self::SessionRateLimitExceeded(_)
                | Self::Cancelled
        )
    }

    /// Returns true if this error indicates a permanent failure
    ///
    /// Permanent errors will not resolve without external intervention
    /// (e.g., configuration change, network fix).
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let err = BridgeError::ConnectionRefused;
    /// assert!(err.is_permanent());
    ///
    /// let err = BridgeError::ConnectionTimeout;
    /// assert!(!err.is_permanent());
    /// ```
    #[must_use]
    pub fn is_permanent(&self) -> bool {
        matches!(
            self,
            Self::ConnectionRefused
                | Self::DnsResolutionFailed(_)
                | Self::InvalidAddress(_)
                | Self::InvalidSessionState { .. }
                | Self::NotInitialized
        )
    }

    /// Returns true if this error indicates a resource exhaustion condition
    ///
    /// Resource exhaustion errors indicate system limits have been reached.
    /// The caller should wait for resources to be freed or reduce load.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let err = BridgeError::PortExhausted;
    /// assert!(err.is_resource_exhaustion());
    /// ```
    #[must_use]
    pub fn is_resource_exhaustion(&self) -> bool {
        matches!(
            self,
            Self::PortExhausted
                | Self::SocketLimitReached(_)
                | Self::SessionLimitReached(_)
                | Self::PerClientSessionLimitReached(_)
                | Self::SessionRateLimitExceeded(_)
        )
    }

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

/// A specialized Result type for bridge operations
pub type Result<T> = std::result::Result<T, BridgeError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = BridgeError::PortExhausted;
        assert_eq!(
            err.to_string(),
            "port exhausted: all ephemeral ports in use"
        );

        let err = BridgeError::SocketLimitReached(1024);
        assert_eq!(err.to_string(), "socket limit reached: max 1024 sockets");

        let err = BridgeError::SessionNotFound("test-session".to_string());
        assert_eq!(err.to_string(), "session not found: test-session");

        let err = BridgeError::TunnelDown("wg-egress-1".to_string());
        assert_eq!(err.to_string(), "tunnel down: wg-egress-1");

        let err = BridgeError::DnsResolutionFailed("example.com".to_string());
        assert_eq!(err.to_string(), "DNS resolution failed: example.com");

        let err = BridgeError::ConnectionRefused;
        assert_eq!(err.to_string(), "connection refused");

        let err = BridgeError::ConnectionTimeout;
        assert_eq!(err.to_string(), "connection timed out");
    }

    #[test]
    fn test_io_error_conversion() {
        let io_err = io::Error::new(io::ErrorKind::ConnectionReset, "connection reset");
        let bridge_err: BridgeError = io_err.into();
        assert!(matches!(bridge_err, BridgeError::Io(_)));
        assert!(bridge_err.to_string().contains("connection reset"));
    }

    #[test]
    fn test_is_transient() {
        assert!(BridgeError::PortExhausted.is_transient());
        assert!(BridgeError::SocketLimitReached(1024).is_transient());
        assert!(BridgeError::ConnectionTimeout.is_transient());
        assert!(BridgeError::TunnelDown("test".to_string()).is_transient());
        assert!(BridgeError::SessionLimitReached(10000).is_transient());
        assert!(BridgeError::PerClientSessionLimitReached(100).is_transient());
        assert!(BridgeError::Cancelled.is_transient());

        assert!(!BridgeError::ConnectionRefused.is_transient());
        assert!(!BridgeError::DnsResolutionFailed("test".to_string()).is_transient());
    }

    #[test]
    fn test_is_permanent() {
        assert!(BridgeError::ConnectionRefused.is_permanent());
        assert!(BridgeError::DnsResolutionFailed("test".to_string()).is_permanent());
        assert!(BridgeError::InvalidAddress("test".to_string()).is_permanent());
        assert!(BridgeError::InvalidSessionState {
            expected: "active".to_string(),
            actual: "closed".to_string()
        }
        .is_permanent());
        assert!(BridgeError::NotInitialized.is_permanent());

        assert!(!BridgeError::PortExhausted.is_permanent());
        assert!(!BridgeError::ConnectionTimeout.is_permanent());
    }

    #[test]
    fn test_is_resource_exhaustion() {
        assert!(BridgeError::PortExhausted.is_resource_exhaustion());
        assert!(BridgeError::SocketLimitReached(1024).is_resource_exhaustion());
        assert!(BridgeError::SessionLimitReached(10000).is_resource_exhaustion());
        assert!(BridgeError::PerClientSessionLimitReached(100).is_resource_exhaustion());

        assert!(!BridgeError::ConnectionRefused.is_resource_exhaustion());
        assert!(!BridgeError::ConnectionTimeout.is_resource_exhaustion());
    }

    #[test]
    fn test_smoltcp_error_helpers() {
        let err = BridgeError::SmoltcpTcp("test error".to_string());
        assert!(err.to_string().contains("smoltcp TCP error"));

        let err = BridgeError::SmoltcpUdp("test error".to_string());
        assert!(err.to_string().contains("smoltcp UDP error"));
    }

    #[test]
    fn test_session_already_exists() {
        let err = BridgeError::SessionAlreadyExists("10.0.0.1:1234->10.0.0.2:80".to_string());
        assert!(err.to_string().contains("session already exists"));
        assert!(!err.is_transient());
        assert!(!err.is_permanent());
    }

    #[test]
    fn test_channel_errors() {
        let err = BridgeError::ChannelSendFailed("buffer full".to_string());
        assert!(err.to_string().contains("channel send failed"));

        let err = BridgeError::ChannelReceiveFailed("channel closed".to_string());
        assert!(err.to_string().contains("channel receive failed"));
    }

    #[test]
    fn test_new_error_variants() {
        let err = BridgeError::SocketNotFound("handle-123".to_string());
        assert!(err.to_string().contains("socket not found"));

        let err = BridgeError::NotInitialized;
        assert!(err.to_string().contains("not initialized"));

        let err = BridgeError::Cancelled;
        assert!(err.to_string().contains("cancelled"));
    }
}
