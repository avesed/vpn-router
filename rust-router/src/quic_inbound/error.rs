//! Error types for QUIC inbound operations
//!
//! This module defines error types specific to QUIC inbound operations,
//! including listener management, connection handling, and TLS configuration.
//!
//! # Error Categories
//!
//! - **Bind errors**: Failed to bind to the listen address
//! - **TLS errors**: Certificate or key configuration issues
//! - **Connection errors**: Handshake failures, stream errors
//! - **Configuration errors**: Invalid configuration parameters

use std::io;
use std::net::SocketAddr;

use thiserror::Error;

use crate::transport::TransportError;

/// Error types for QUIC inbound operations
#[derive(Debug, Error)]
pub enum QuicInboundError {
    /// Failed to bind to the listen address
    #[error("Failed to bind to {addr}: {reason}")]
    BindFailed {
        /// The address that failed to bind
        addr: SocketAddr,
        /// The reason for failure
        reason: String,
    },

    /// TLS certificate error
    #[error("TLS certificate error: {0}")]
    CertificateError(String),

    /// TLS private key error
    #[error("TLS private key error: {0}")]
    PrivateKeyError(String),

    /// TLS configuration error
    #[error("TLS configuration error: {0}")]
    TlsConfigError(String),

    /// Connection handshake failed
    #[error("QUIC handshake failed: {0}")]
    HandshakeFailed(String),

    /// Stream error
    #[error("QUIC stream error: {0}")]
    StreamError(String),

    /// Connection closed
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

    /// Transport error
    #[error("Transport error: {0}")]
    Transport(#[from] TransportError),

    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
}

impl QuicInboundError {
    /// Create a bind failed error
    pub fn bind_failed(addr: SocketAddr, reason: impl Into<String>) -> Self {
        Self::BindFailed {
            addr,
            reason: reason.into(),
        }
    }

    /// Create a certificate error
    pub fn certificate(reason: impl Into<String>) -> Self {
        Self::CertificateError(reason.into())
    }

    /// Create a private key error
    pub fn private_key(reason: impl Into<String>) -> Self {
        Self::PrivateKeyError(reason.into())
    }

    /// Create a TLS configuration error
    pub fn tls_config(reason: impl Into<String>) -> Self {
        Self::TlsConfigError(reason.into())
    }

    /// Create a handshake failed error
    pub fn handshake(reason: impl Into<String>) -> Self {
        Self::HandshakeFailed(reason.into())
    }

    /// Create a stream error
    pub fn stream(reason: impl Into<String>) -> Self {
        Self::StreamError(reason.into())
    }

    /// Create an accept error
    pub fn accept(reason: impl Into<String>) -> Self {
        Self::AcceptError(reason.into())
    }

    /// Create an invalid configuration error
    pub fn invalid_config(reason: impl Into<String>) -> Self {
        Self::InvalidConfig(reason.into())
    }

    /// Check if this error is recoverable
    ///
    /// Recoverable errors are typically transient issues that may succeed
    /// on retry. Configuration and TLS errors are generally not recoverable.
    #[must_use]
    pub fn is_recoverable(&self) -> bool {
        match self {
            Self::BindFailed { .. } => false,
            Self::CertificateError(_) => false,
            Self::PrivateKeyError(_) => false,
            Self::TlsConfigError(_) => false,
            Self::HandshakeFailed(_) => true, // May be a bad client, try next
            Self::StreamError(_) => true,
            Self::ConnectionClosed => true,
            Self::AcceptError(_) => true,
            Self::NotActive => false,
            Self::AlreadyRunning => false,
            Self::ShuttingDown => false,
            Self::InvalidConfig(_) => false,
            Self::Transport(e) => e.is_recoverable(),
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

/// Convert `QuicInboundError` to `std::io::Error` for compatibility
impl From<QuicInboundError> for io::Error {
    fn from(e: QuicInboundError) -> Self {
        match e {
            QuicInboundError::Io(io_err) => io_err,
            QuicInboundError::BindFailed { .. } => {
                io::Error::new(io::ErrorKind::AddrInUse, e.to_string())
            }
            QuicInboundError::CertificateError(_)
            | QuicInboundError::PrivateKeyError(_)
            | QuicInboundError::TlsConfigError(_)
            | QuicInboundError::InvalidConfig(_) => {
                io::Error::new(io::ErrorKind::InvalidInput, e.to_string())
            }
            QuicInboundError::HandshakeFailed(_) | QuicInboundError::StreamError(_) => {
                io::Error::new(io::ErrorKind::ConnectionAborted, e.to_string())
            }
            QuicInboundError::ConnectionClosed => {
                io::Error::new(io::ErrorKind::ConnectionReset, e.to_string())
            }
            QuicInboundError::AcceptError(_) => {
                io::Error::new(io::ErrorKind::ConnectionRefused, e.to_string())
            }
            QuicInboundError::NotActive
            | QuicInboundError::AlreadyRunning
            | QuicInboundError::ShuttingDown => {
                io::Error::new(io::ErrorKind::NotConnected, e.to_string())
            }
            QuicInboundError::Transport(_) => {
                io::Error::new(io::ErrorKind::Other, e.to_string())
            }
        }
    }
}

/// Type alias for Result with `QuicInboundError`
pub type QuicInboundResult<T> = std::result::Result<T, QuicInboundError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bind_failed_error() {
        let addr: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let err = QuicInboundError::bind_failed(addr, "address already in use");
        assert!(matches!(err, QuicInboundError::BindFailed { .. }));
        assert!(err.to_string().contains("127.0.0.1:443"));
        assert!(err.to_string().contains("address already in use"));
        assert!(!err.is_recoverable());
    }

    #[test]
    fn test_certificate_error() {
        let err = QuicInboundError::certificate("invalid certificate");
        assert!(matches!(err, QuicInboundError::CertificateError(_)));
        assert!(err.to_string().contains("invalid certificate"));
        assert!(!err.is_recoverable());
    }

    #[test]
    fn test_private_key_error() {
        let err = QuicInboundError::private_key("invalid key format");
        assert!(matches!(err, QuicInboundError::PrivateKeyError(_)));
        assert!(!err.is_recoverable());
    }

    #[test]
    fn test_handshake_error() {
        let err = QuicInboundError::handshake("certificate verification failed");
        assert!(matches!(err, QuicInboundError::HandshakeFailed(_)));
        assert!(err.is_recoverable()); // May be a bad client
    }

    #[test]
    fn test_io_error() {
        let io_err = io::Error::new(io::ErrorKind::ConnectionReset, "connection reset");
        let err = QuicInboundError::from(io_err);
        assert!(err.to_string().contains("I/O error"));
        assert!(err.is_recoverable()); // ConnectionReset is recoverable
    }

    #[test]
    fn test_error_to_io_error() {
        let addr: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let err = QuicInboundError::bind_failed(addr, "in use");
        let io_err: io::Error = err.into();
        assert_eq!(io_err.kind(), io::ErrorKind::AddrInUse);
    }

    #[test]
    fn test_recoverable_errors() {
        let recoverable = vec![
            QuicInboundError::handshake("reason"),
            QuicInboundError::stream("reason"),
            QuicInboundError::ConnectionClosed,
            QuicInboundError::accept("reason"),
        ];

        for err in recoverable {
            assert!(err.is_recoverable(), "Expected {} to be recoverable", err);
        }
    }

    #[test]
    fn test_non_recoverable_errors() {
        let non_recoverable = vec![
            QuicInboundError::bind_failed("127.0.0.1:443".parse().unwrap(), "reason"),
            QuicInboundError::certificate("bad"),
            QuicInboundError::private_key("bad"),
            QuicInboundError::tls_config("bad"),
            QuicInboundError::invalid_config("bad"),
            QuicInboundError::NotActive,
            QuicInboundError::AlreadyRunning,
            QuicInboundError::ShuttingDown,
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
