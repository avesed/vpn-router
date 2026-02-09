//! Error types for Shadowsocks inbound operations
//!
//! This module defines error types specific to Shadowsocks inbound operations,
//! including listener management, authentication, and connection handling.
//!
//! # Error Categories
//!
//! - **Bind errors**: Failed to bind to the listen address
//! - **Protocol errors**: Invalid Shadowsocks headers or encryption failures
//! - **Configuration errors**: Invalid configuration parameters
//! - **I/O errors**: Network-related failures

use std::io;
use std::net::SocketAddr;

use thiserror::Error;

use crate::shadowsocks::ShadowsocksError;

/// Error types for Shadowsocks inbound operations
#[derive(Debug, Error)]
pub enum ShadowsocksInboundError {
    /// Failed to bind to the listen address
    #[error("Failed to bind to {addr}: {reason}")]
    BindFailed {
        /// The address that failed to bind
        addr: SocketAddr,
        /// The reason for failure
        reason: String,
    },

    /// Invalid encryption method
    #[error("Invalid encryption method: {0}")]
    InvalidMethod(String),

    /// Invalid password configuration
    #[error("Invalid password: {0}")]
    InvalidPassword(String),

    /// Protocol error during handshake or data transfer
    #[error("Protocol error: {0}")]
    ProtocolError(String),

    /// Connection closed unexpectedly
    #[error("Connection closed")]
    ConnectionClosed,

    /// Connection accept error
    #[error("Failed to accept connection: {0}")]
    AcceptError(String),

    /// Listener is not active
    #[error("Listener is not active")]
    NotActive,

    /// Listener is already running
    #[error("Listener is already running")]
    AlreadyRunning,

    /// Listener is shutting down
    #[error("Listener is shutting down")]
    ShuttingDown,

    /// Invalid configuration
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    /// Shadowsocks crate error
    #[error("Shadowsocks error: {0}")]
    Shadowsocks(#[from] ShadowsocksError),

    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
}

impl ShadowsocksInboundError {
    /// Create a bind failed error
    pub fn bind_failed(addr: SocketAddr, reason: impl Into<String>) -> Self {
        Self::BindFailed {
            addr,
            reason: reason.into(),
        }
    }

    /// Create an invalid method error
    pub fn invalid_method(method: impl Into<String>) -> Self {
        Self::InvalidMethod(method.into())
    }

    /// Create an invalid password error
    pub fn invalid_password(reason: impl Into<String>) -> Self {
        Self::InvalidPassword(reason.into())
    }

    /// Create a protocol error
    pub fn protocol_error(msg: impl Into<String>) -> Self {
        Self::ProtocolError(msg.into())
    }

    /// Create an accept error
    pub fn accept(msg: impl Into<String>) -> Self {
        Self::AcceptError(msg.into())
    }

    /// Create an invalid configuration error
    pub fn invalid_config(msg: impl Into<String>) -> Self {
        Self::InvalidConfig(msg.into())
    }

    /// Check if this error is recoverable
    ///
    /// Recoverable errors are typically transient issues that may succeed
    /// on retry. Configuration and protocol errors are generally
    /// not recoverable.
    #[must_use]
    pub fn is_recoverable(&self) -> bool {
        match self {
            Self::BindFailed { .. } => false,
            Self::InvalidMethod(_) => false,
            Self::InvalidPassword(_) => false,
            Self::ProtocolError(_) => true, // May be a bad client, try next
            Self::ConnectionClosed => true,
            Self::AcceptError(_) => true,
            Self::NotActive => false,
            Self::AlreadyRunning => false,
            Self::ShuttingDown => false,
            Self::InvalidConfig(_) => false,
            Self::Shadowsocks(_) => false,
            Self::Io(e) => matches!(
                e.kind(),
                io::ErrorKind::TimedOut
                    | io::ErrorKind::Interrupted
                    | io::ErrorKind::WouldBlock
                    | io::ErrorKind::ConnectionReset
            ),
        }
    }
}

/// Convert `ShadowsocksInboundError` to `std::io::Error` for compatibility
impl From<ShadowsocksInboundError> for io::Error {
    fn from(e: ShadowsocksInboundError) -> Self {
        match e {
            ShadowsocksInboundError::Io(io_err) => io_err,
            ShadowsocksInboundError::BindFailed { .. } => {
                io::Error::new(io::ErrorKind::AddrInUse, e.to_string())
            }
            ShadowsocksInboundError::InvalidMethod(_)
            | ShadowsocksInboundError::InvalidPassword(_)
            | ShadowsocksInboundError::InvalidConfig(_) => {
                io::Error::new(io::ErrorKind::InvalidInput, e.to_string())
            }
            ShadowsocksInboundError::ProtocolError(_) => {
                io::Error::new(io::ErrorKind::InvalidData, e.to_string())
            }
            ShadowsocksInboundError::ConnectionClosed => {
                io::Error::new(io::ErrorKind::ConnectionReset, e.to_string())
            }
            ShadowsocksInboundError::AcceptError(_) => {
                io::Error::new(io::ErrorKind::ConnectionRefused, e.to_string())
            }
            ShadowsocksInboundError::NotActive
            | ShadowsocksInboundError::AlreadyRunning
            | ShadowsocksInboundError::ShuttingDown => {
                io::Error::new(io::ErrorKind::NotConnected, e.to_string())
            }
            ShadowsocksInboundError::Shadowsocks(_) => {
                io::Error::new(io::ErrorKind::Other, e.to_string())
            }
        }
    }
}

/// Type alias for Result with `ShadowsocksInboundError`
pub type ShadowsocksInboundResult<T> = std::result::Result<T, ShadowsocksInboundError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bind_failed_error() {
        let addr: SocketAddr = "127.0.0.1:8388".parse().unwrap();
        let err = ShadowsocksInboundError::bind_failed(addr, "address already in use");
        assert!(matches!(err, ShadowsocksInboundError::BindFailed { .. }));
        assert!(err.to_string().contains("127.0.0.1:8388"));
        assert!(err.to_string().contains("address already in use"));
        assert!(!err.is_recoverable());
    }

    #[test]
    fn test_invalid_method_error() {
        let err = ShadowsocksInboundError::invalid_method("bad-cipher");
        assert!(matches!(err, ShadowsocksInboundError::InvalidMethod(_)));
        assert!(err.to_string().contains("bad-cipher"));
        assert!(!err.is_recoverable());
    }

    #[test]
    fn test_invalid_password_error() {
        let err = ShadowsocksInboundError::invalid_password("too short");
        assert!(matches!(err, ShadowsocksInboundError::InvalidPassword(_)));
        assert!(err.to_string().contains("too short"));
        assert!(!err.is_recoverable());
    }

    #[test]
    fn test_protocol_error() {
        let err = ShadowsocksInboundError::protocol_error("invalid header");
        assert!(matches!(err, ShadowsocksInboundError::ProtocolError(_)));
        assert!(err.is_recoverable()); // Protocol errors may be bad clients
    }

    #[test]
    fn test_io_error() {
        use std::error::Error as StdError;
        let io_err = io::Error::new(io::ErrorKind::ConnectionReset, "connection reset");
        let err = ShadowsocksInboundError::from(io_err);
        assert!(err.to_string().contains("I/O error"));
        assert!(StdError::source(&err).is_some());
        assert!(err.is_recoverable()); // ConnectionReset is recoverable
    }

    #[test]
    fn test_error_to_io_error() {
        let addr: SocketAddr = "127.0.0.1:8388".parse().unwrap();
        let err = ShadowsocksInboundError::bind_failed(addr, "in use");
        let io_err: io::Error = err.into();
        assert_eq!(io_err.kind(), io::ErrorKind::AddrInUse);
    }

    #[test]
    fn test_recoverable_errors() {
        let recoverable = vec![
            ShadowsocksInboundError::protocol_error("reason"),
            ShadowsocksInboundError::ConnectionClosed,
            ShadowsocksInboundError::accept("reason"),
        ];

        for err in recoverable {
            assert!(err.is_recoverable(), "Expected {} to be recoverable", err);
        }
    }

    #[test]
    fn test_non_recoverable_errors() {
        let non_recoverable = vec![
            ShadowsocksInboundError::bind_failed("127.0.0.1:8388".parse().unwrap(), "reason"),
            ShadowsocksInboundError::invalid_method("bad"),
            ShadowsocksInboundError::invalid_password("bad"),
            ShadowsocksInboundError::invalid_config("bad"),
            ShadowsocksInboundError::NotActive,
            ShadowsocksInboundError::AlreadyRunning,
            ShadowsocksInboundError::ShuttingDown,
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
