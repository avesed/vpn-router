//! Error types for VLESS inbound operations
//!
//! This module defines error types specific to VLESS inbound operations,
//! including listener management, authentication, and connection handling.
//!
//! # Error Categories
//!
//! - **Bind errors**: Failed to bind to the listen address
//! - **TLS errors**: TLS configuration or handshake failures
//! - **Authentication errors**: UUID validation failures
//! - **Protocol errors**: Invalid VLESS headers
//! - **I/O errors**: Network-related failures

use std::io;
use std::net::SocketAddr;

use thiserror::Error;

use crate::vless::VlessError;

/// Error types for VLESS inbound operations
#[derive(Debug, Error)]
pub enum VlessInboundError {
    /// Failed to bind to the listen address
    #[error("Failed to bind to {addr}: {reason}")]
    BindFailed {
        /// The address that failed to bind
        addr: SocketAddr,
        /// The reason for failure
        reason: String,
    },

    /// TLS configuration error
    #[error("TLS configuration error: {0}")]
    TlsConfig(String),

    /// TLS handshake failed
    #[error("TLS handshake failed: {0}")]
    TlsHandshakeFailed(String),

    /// Failed to load certificate
    #[error("Failed to load certificate from {path}: {reason}")]
    CertificateLoad {
        /// Path to the certificate file
        path: String,
        /// The reason for failure
        reason: String,
    },

    /// Failed to load private key
    #[error("Failed to load private key from {path}: {reason}")]
    PrivateKeyLoad {
        /// Path to the key file
        path: String,
        /// The reason for failure
        reason: String,
    },

    /// Authentication failed (unknown UUID)
    #[error("Authentication failed: unknown UUID")]
    AuthenticationFailed,

    /// Invalid VLESS header
    #[error("Invalid VLESS header: {0}")]
    InvalidHeader(String),

    /// VLESS protocol error
    #[error("VLESS protocol error: {0}")]
    ProtocolError(#[from] VlessError),

    /// Connection closed unexpectedly
    #[error("Connection closed")]
    ConnectionClosed,

    /// Connection accept error
    #[error("Failed to accept connection: {0}")]
    AcceptError(String),

    /// Fallback connection error
    #[error("Fallback connection to {addr} failed: {reason}")]
    FallbackFailed {
        /// Fallback address
        addr: SocketAddr,
        /// Failure reason
        reason: String,
    },

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

    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
}

impl VlessInboundError {
    /// Create a bind failed error
    pub fn bind_failed(addr: SocketAddr, reason: impl Into<String>) -> Self {
        Self::BindFailed {
            addr,
            reason: reason.into(),
        }
    }

    /// Create a TLS configuration error
    pub fn tls_config(msg: impl Into<String>) -> Self {
        Self::TlsConfig(msg.into())
    }

    /// Create a TLS handshake failed error
    pub fn tls_handshake(msg: impl Into<String>) -> Self {
        Self::TlsHandshakeFailed(msg.into())
    }

    /// Create a certificate load error
    pub fn certificate_load(path: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::CertificateLoad {
            path: path.into(),
            reason: reason.into(),
        }
    }

    /// Create a private key load error
    pub fn private_key_load(path: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::PrivateKeyLoad {
            path: path.into(),
            reason: reason.into(),
        }
    }

    /// Create an invalid header error
    pub fn invalid_header(msg: impl Into<String>) -> Self {
        Self::InvalidHeader(msg.into())
    }

    /// Create an accept error
    pub fn accept(msg: impl Into<String>) -> Self {
        Self::AcceptError(msg.into())
    }

    /// Create a fallback failed error
    pub fn fallback_failed(addr: SocketAddr, reason: impl Into<String>) -> Self {
        Self::FallbackFailed {
            addr,
            reason: reason.into(),
        }
    }

    /// Create an invalid configuration error
    pub fn invalid_config(msg: impl Into<String>) -> Self {
        Self::InvalidConfig(msg.into())
    }

    /// Check if this error is recoverable
    ///
    /// Recoverable errors are typically transient issues that may succeed
    /// on retry. Configuration and authentication errors are generally
    /// not recoverable.
    #[must_use]
    pub fn is_recoverable(&self) -> bool {
        match self {
            Self::BindFailed { .. } => false,
            Self::TlsConfig(_) => false,
            Self::TlsHandshakeFailed(_) => true, // May succeed on retry
            Self::CertificateLoad { .. } => false,
            Self::PrivateKeyLoad { .. } => false,
            Self::AuthenticationFailed => false,
            Self::InvalidHeader(_) => false,
            Self::ProtocolError(e) => e.is_recoverable(),
            Self::ConnectionClosed => true,
            Self::AcceptError(_) => true,
            Self::FallbackFailed { .. } => true,
            Self::NotActive => false,
            Self::AlreadyRunning => false,
            Self::ShuttingDown => false,
            Self::InvalidConfig(_) => false,
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

/// Convert `VlessInboundError` to `std::io::Error` for compatibility
impl From<VlessInboundError> for io::Error {
    fn from(e: VlessInboundError) -> Self {
        match e {
            VlessInboundError::Io(io_err) => io_err,
            VlessInboundError::BindFailed { .. } => {
                io::Error::new(io::ErrorKind::AddrInUse, e.to_string())
            }
            VlessInboundError::TlsConfig(_)
            | VlessInboundError::CertificateLoad { .. }
            | VlessInboundError::PrivateKeyLoad { .. }
            | VlessInboundError::InvalidConfig(_) => {
                io::Error::new(io::ErrorKind::InvalidInput, e.to_string())
            }
            VlessInboundError::TlsHandshakeFailed(_) => {
                io::Error::new(io::ErrorKind::ConnectionAborted, e.to_string())
            }
            VlessInboundError::AuthenticationFailed => {
                io::Error::new(io::ErrorKind::PermissionDenied, e.to_string())
            }
            VlessInboundError::InvalidHeader(_) | VlessInboundError::ProtocolError(_) => {
                io::Error::new(io::ErrorKind::InvalidData, e.to_string())
            }
            VlessInboundError::ConnectionClosed => {
                io::Error::new(io::ErrorKind::ConnectionReset, e.to_string())
            }
            VlessInboundError::AcceptError(_) | VlessInboundError::FallbackFailed { .. } => {
                io::Error::new(io::ErrorKind::ConnectionRefused, e.to_string())
            }
            VlessInboundError::NotActive
            | VlessInboundError::AlreadyRunning
            | VlessInboundError::ShuttingDown => {
                io::Error::new(io::ErrorKind::NotConnected, e.to_string())
            }
        }
    }
}

/// Type alias for Result with `VlessInboundError`
pub type VlessInboundResult<T> = std::result::Result<T, VlessInboundError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bind_failed_error() {
        let addr: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let err = VlessInboundError::bind_failed(addr, "address already in use");
        assert!(matches!(err, VlessInboundError::BindFailed { .. }));
        assert!(err.to_string().contains("127.0.0.1:443"));
        assert!(err.to_string().contains("address already in use"));
        assert!(!err.is_recoverable());
    }

    #[test]
    fn test_tls_config_error() {
        let err = VlessInboundError::tls_config("missing certificate");
        assert!(matches!(err, VlessInboundError::TlsConfig(_)));
        assert!(err.to_string().contains("missing certificate"));
        assert!(!err.is_recoverable());
    }

    #[test]
    fn test_tls_handshake_error() {
        let err = VlessInboundError::tls_handshake("protocol error");
        assert!(matches!(err, VlessInboundError::TlsHandshakeFailed(_)));
        assert!(err.is_recoverable());
    }

    #[test]
    fn test_authentication_error() {
        let err = VlessInboundError::AuthenticationFailed;
        assert!(err.to_string().contains("unknown UUID"));
        assert!(!err.is_recoverable());
    }

    #[test]
    fn test_certificate_load_error() {
        let err = VlessInboundError::certificate_load("/path/to/cert.pem", "file not found");
        assert!(matches!(err, VlessInboundError::CertificateLoad { .. }));
        assert!(err.to_string().contains("/path/to/cert.pem"));
        assert!(!err.is_recoverable());
    }

    #[test]
    fn test_fallback_failed_error() {
        let addr: SocketAddr = "127.0.0.1:80".parse().unwrap();
        let err = VlessInboundError::fallback_failed(addr, "connection refused");
        assert!(matches!(err, VlessInboundError::FallbackFailed { .. }));
        assert!(err.is_recoverable());
    }

    #[test]
    fn test_error_to_io_error() {
        let err = VlessInboundError::AuthenticationFailed;
        let io_err: io::Error = err.into();
        assert_eq!(io_err.kind(), io::ErrorKind::PermissionDenied);

        let addr: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let err = VlessInboundError::bind_failed(addr, "in use");
        let io_err: io::Error = err.into();
        assert_eq!(io_err.kind(), io::ErrorKind::AddrInUse);
    }

    #[test]
    fn test_recoverable_errors() {
        let recoverable = vec![
            VlessInboundError::tls_handshake("reason"),
            VlessInboundError::ConnectionClosed,
            VlessInboundError::accept("reason"),
            VlessInboundError::fallback_failed("127.0.0.1:80".parse().unwrap(), "reason"),
        ];

        for err in recoverable {
            assert!(err.is_recoverable(), "Expected {} to be recoverable", err);
        }
    }

    #[test]
    fn test_non_recoverable_errors() {
        let non_recoverable = vec![
            VlessInboundError::bind_failed("127.0.0.1:443".parse().unwrap(), "reason"),
            VlessInboundError::tls_config("reason"),
            VlessInboundError::certificate_load("path", "reason"),
            VlessInboundError::private_key_load("path", "reason"),
            VlessInboundError::AuthenticationFailed,
            VlessInboundError::invalid_header("reason"),
            VlessInboundError::NotActive,
            VlessInboundError::AlreadyRunning,
            VlessInboundError::ShuttingDown,
            VlessInboundError::invalid_config("reason"),
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
