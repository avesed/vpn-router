//! Error types for the `WireGuard` Egress module
//!
//! This module defines error types specific to `WireGuard` egress operations,
//! including tunnel management, packet sending, and configuration validation.
//!
//! # Error Categories
//!
//! - **Tunnel errors**: Issues with individual tunnels (not found, already exists)
//! - **Configuration errors**: Invalid configuration parameters
//! - **Send errors**: Packet sending failures
//! - **State errors**: Invalid state transitions (shutting down)

use thiserror::Error;

use crate::tunnel::traits::WgTunnelError;

/// Error types for `WireGuard` egress operations
#[derive(Debug, Error)]
pub enum EgressError {
    /// Tunnel not found
    #[error("Tunnel not found: {0}")]
    TunnelNotFound(String),

    /// Tunnel already exists
    #[error("Tunnel already exists: {0}")]
    TunnelAlreadyExists(String),

    /// Invalid configuration
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    /// Error from the underlying `WireGuard` tunnel
    #[error("Tunnel error: {0}")]
    TunnelError(#[from] WgTunnelError),

    /// Failed to send packet
    #[error("Send failed: {0}")]
    SendFailed(String),

    /// Manager is shutting down
    #[error("Egress manager is shutting down")]
    ShuttingDown,

    /// I/O error
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    /// Drain timeout expired
    #[error("Drain timeout expired for tunnel: {0}")]
    DrainTimeout(String),

    /// Connection error
    #[error("Connection error: {0}")]
    ConnectionError(String),

    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),
}

impl EgressError {
    /// Create an invalid configuration error
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::egress::EgressError;
    ///
    /// let err = EgressError::invalid_config("missing private key");
    /// assert!(err.to_string().contains("missing private key"));
    /// ```
    pub fn invalid_config(msg: impl Into<String>) -> Self {
        Self::InvalidConfig(msg.into())
    }

    /// Create a tunnel not found error
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::egress::EgressError;
    ///
    /// let err = EgressError::tunnel_not_found("my-tunnel");
    /// assert!(err.to_string().contains("my-tunnel"));
    /// ```
    pub fn tunnel_not_found(tag: impl Into<String>) -> Self {
        Self::TunnelNotFound(tag.into())
    }

    /// Create a tunnel already exists error
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::egress::EgressError;
    ///
    /// let err = EgressError::tunnel_already_exists("my-tunnel");
    /// assert!(err.to_string().contains("my-tunnel"));
    /// ```
    pub fn tunnel_already_exists(tag: impl Into<String>) -> Self {
        Self::TunnelAlreadyExists(tag.into())
    }

    /// Create a send failed error
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::egress::EgressError;
    ///
    /// let err = EgressError::send_failed("socket closed");
    /// assert!(err.to_string().contains("socket closed"));
    /// ```
    pub fn send_failed(msg: impl Into<String>) -> Self {
        Self::SendFailed(msg.into())
    }

    /// Create a connection error
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::egress::EgressError;
    ///
    /// let err = EgressError::connection("handshake failed");
    /// assert!(err.to_string().contains("handshake failed"));
    /// ```
    pub fn connection(msg: impl Into<String>) -> Self {
        Self::ConnectionError(msg.into())
    }

    /// Create a drain timeout error
    pub fn drain_timeout(tag: impl Into<String>) -> Self {
        Self::DrainTimeout(tag.into())
    }

    /// Create an internal error
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::egress::EgressError;
    ///
    /// let err = EgressError::internal("unexpected state");
    /// assert!(err.to_string().contains("unexpected state"));
    /// ```
    pub fn internal(msg: impl Into<String>) -> Self {
        Self::Internal(msg.into())
    }

    /// Check if this error is recoverable
    ///
    /// Recoverable errors can potentially be retried without intervention.
    ///
    /// # Recoverable errors:
    /// - `SendFailed` - Retry sending later
    /// - `TunnelError` (some variants) - Transient tunnel issues
    /// - `DrainTimeout` - Can retry with longer timeout
    ///
    /// # Non-recoverable errors:
    /// - `TunnelNotFound` - Tunnel needs to be created
    /// - `TunnelAlreadyExists` - Need to use different tag
    /// - `InvalidConfig` - Configuration needs to be fixed
    /// - `ShuttingDown` - Manager is shutting down
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::egress::EgressError;
    ///
    /// let recoverable = EgressError::send_failed("temporary failure");
    /// assert!(recoverable.is_recoverable());
    ///
    /// let non_recoverable = EgressError::tunnel_not_found("test");
    /// assert!(!non_recoverable.is_recoverable());
    /// ```
    #[must_use]
    pub fn is_recoverable(&self) -> bool {
        match self {
            Self::TunnelNotFound(_) => false,
            Self::TunnelAlreadyExists(_) => false,
            Self::InvalidConfig(_) => false,
            Self::TunnelError(e) => matches!(
                e,
                WgTunnelError::IoError(_) | WgTunnelError::Timeout | WgTunnelError::NotConnected
            ),
            Self::SendFailed(_) => true,
            Self::ShuttingDown => false,
            Self::IoError(e) => matches!(
                e.kind(),
                std::io::ErrorKind::TimedOut
                    | std::io::ErrorKind::Interrupted
                    | std::io::ErrorKind::WouldBlock
            ),
            Self::DrainTimeout(_) => true,
            Self::ConnectionError(_) => true,
            Self::Internal(_) => false,
        }
    }

    /// Check if this error indicates the tunnel doesn't exist
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::egress::EgressError;
    ///
    /// let err = EgressError::tunnel_not_found("my-tunnel");
    /// assert!(err.is_not_found());
    ///
    /// let err = EgressError::send_failed("test");
    /// assert!(!err.is_not_found());
    /// ```
    #[must_use]
    pub fn is_not_found(&self) -> bool {
        matches!(self, Self::TunnelNotFound(_))
    }

    /// Check if this error indicates a duplicate tunnel
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::egress::EgressError;
    ///
    /// let err = EgressError::tunnel_already_exists("my-tunnel");
    /// assert!(err.is_duplicate());
    ///
    /// let err = EgressError::send_failed("test");
    /// assert!(!err.is_duplicate());
    /// ```
    #[must_use]
    pub fn is_duplicate(&self) -> bool {
        matches!(self, Self::TunnelAlreadyExists(_))
    }
}

/// Type alias for Result with `EgressError`
pub type EgressResult<T> = std::result::Result<T, EgressError>;

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // Error Creation Tests
    // ========================================================================

    #[test]
    fn test_invalid_config_error() {
        let err = EgressError::invalid_config("missing key");
        assert!(matches!(err, EgressError::InvalidConfig(_)));
        assert!(err.to_string().contains("missing key"));
        assert!(!err.is_recoverable());
    }

    #[test]
    fn test_tunnel_not_found_error() {
        let err = EgressError::tunnel_not_found("my-tunnel");
        assert!(matches!(err, EgressError::TunnelNotFound(_)));
        assert!(err.to_string().contains("my-tunnel"));
        assert!(err.is_not_found());
        assert!(!err.is_recoverable());
    }

    #[test]
    fn test_tunnel_already_exists_error() {
        let err = EgressError::tunnel_already_exists("my-tunnel");
        assert!(matches!(err, EgressError::TunnelAlreadyExists(_)));
        assert!(err.to_string().contains("my-tunnel"));
        assert!(err.is_duplicate());
        assert!(!err.is_recoverable());
    }

    #[test]
    fn test_send_failed_error() {
        let err = EgressError::send_failed("socket error");
        assert!(matches!(err, EgressError::SendFailed(_)));
        assert!(err.to_string().contains("socket error"));
        assert!(err.is_recoverable());
    }

    #[test]
    fn test_connection_error() {
        let err = EgressError::connection("handshake failed");
        assert!(matches!(err, EgressError::ConnectionError(_)));
        assert!(err.to_string().contains("handshake failed"));
        assert!(err.is_recoverable());
    }

    #[test]
    fn test_drain_timeout_error() {
        let err = EgressError::drain_timeout("tunnel-1");
        assert!(matches!(err, EgressError::DrainTimeout(_)));
        assert!(err.to_string().contains("tunnel-1"));
        assert!(err.is_recoverable());
    }

    #[test]
    fn test_internal_error() {
        let err = EgressError::internal("unexpected state");
        assert!(matches!(err, EgressError::Internal(_)));
        assert!(err.to_string().contains("unexpected state"));
        assert!(!err.is_recoverable());
    }

    #[test]
    fn test_shutting_down_error() {
        let err = EgressError::ShuttingDown;
        assert!(err.to_string().contains("shutting down"));
        assert!(!err.is_recoverable());
    }

    // ========================================================================
    // Error Conversion Tests
    // ========================================================================

    #[test]
    fn test_from_wg_tunnel_error() {
        let tunnel_err = WgTunnelError::NotConnected;
        let egress_err: EgressError = tunnel_err.into();
        assert!(matches!(egress_err, EgressError::TunnelError(_)));
        assert!(egress_err.is_recoverable());
    }

    #[test]
    fn test_from_wg_tunnel_error_not_recoverable() {
        let tunnel_err = WgTunnelError::InvalidConfig("bad config".to_string());
        let egress_err: EgressError = tunnel_err.into();
        assert!(matches!(egress_err, EgressError::TunnelError(_)));
        assert!(!egress_err.is_recoverable());
    }

    #[test]
    fn test_from_io_error_recoverable() {
        let io_err = std::io::Error::new(std::io::ErrorKind::TimedOut, "timeout");
        let egress_err: EgressError = io_err.into();
        assert!(matches!(egress_err, EgressError::IoError(_)));
        assert!(egress_err.is_recoverable());
    }

    #[test]
    fn test_from_io_error_not_recoverable() {
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
        let egress_err: EgressError = io_err.into();
        assert!(matches!(egress_err, EgressError::IoError(_)));
        assert!(!egress_err.is_recoverable());
    }

    // ========================================================================
    // Error Classification Tests
    // ========================================================================

    #[test]
    fn test_is_not_found() {
        assert!(EgressError::tunnel_not_found("x").is_not_found());
        assert!(!EgressError::tunnel_already_exists("x").is_not_found());
        assert!(!EgressError::send_failed("x").is_not_found());
        assert!(!EgressError::ShuttingDown.is_not_found());
    }

    #[test]
    fn test_is_duplicate() {
        assert!(EgressError::tunnel_already_exists("x").is_duplicate());
        assert!(!EgressError::tunnel_not_found("x").is_duplicate());
        assert!(!EgressError::send_failed("x").is_duplicate());
        assert!(!EgressError::ShuttingDown.is_duplicate());
    }

    #[test]
    fn test_recoverable_errors() {
        let recoverable = vec![
            EgressError::send_failed("test"),
            EgressError::drain_timeout("test"),
            EgressError::connection("test"),
            EgressError::TunnelError(WgTunnelError::IoError("test".to_string())),
            EgressError::TunnelError(WgTunnelError::Timeout),
            EgressError::TunnelError(WgTunnelError::NotConnected),
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
            EgressError::tunnel_not_found("test"),
            EgressError::tunnel_already_exists("test"),
            EgressError::invalid_config("test"),
            EgressError::ShuttingDown,
            EgressError::internal("test"),
            EgressError::TunnelError(WgTunnelError::InvalidConfig("test".to_string())),
        ];

        for err in non_recoverable {
            assert!(
                !err.is_recoverable(),
                "Expected {} to be non-recoverable",
                err
            );
        }
    }

    // ========================================================================
    // Display Tests
    // ========================================================================

    #[test]
    fn test_error_display_tunnel_not_found() {
        let err = EgressError::tunnel_not_found("my-tunnel");
        let display = err.to_string();
        assert!(display.contains("Tunnel not found"));
        assert!(display.contains("my-tunnel"));
    }

    #[test]
    fn test_error_display_tunnel_already_exists() {
        let err = EgressError::tunnel_already_exists("my-tunnel");
        let display = err.to_string();
        assert!(display.contains("already exists"));
        assert!(display.contains("my-tunnel"));
    }

    #[test]
    fn test_error_display_invalid_config() {
        let err = EgressError::invalid_config("bad value");
        let display = err.to_string();
        assert!(display.contains("Invalid configuration"));
        assert!(display.contains("bad value"));
    }

    #[test]
    fn test_error_debug() {
        let err = EgressError::tunnel_not_found("test");
        let debug = format!("{:?}", err);
        assert!(debug.contains("TunnelNotFound"));
    }
}
