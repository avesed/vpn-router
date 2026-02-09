//! REALITY protocol error types
//!
//! This module defines error types for the REALITY protocol implementation.
//! These errors cover handshake failures, authentication issues, and
//! cryptographic validation problems.

use std::io;

use thiserror::Error;

/// REALITY protocol errors
///
/// This enum covers all error conditions that can occur during REALITY
/// protocol handshake, authentication, and data transfer.
#[derive(Debug, Error)]
pub enum RealityError {
    /// TLS 1.3 handshake failed
    #[error("Handshake failed: {0}")]
    HandshakeFailed(String),

    /// Invalid X25519 public key
    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),

    /// Invalid short ID format
    #[error("Invalid short ID: {0}")]
    InvalidShortId(String),

    /// Server authentication failed
    #[error("Authentication failed")]
    AuthenticationFailed,

    /// I/O error during read/write
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// Invalid server name (SNI)
    #[error("Invalid server name: {0}")]
    InvalidServerName(String),

    /// Invalid fingerprint specification
    #[error("Invalid fingerprint: {0}")]
    InvalidFingerprint(String),

    /// Key derivation error
    #[error("Key derivation failed: {0}")]
    KeyDerivation(String),

    /// Protocol error (general TLS issues)
    #[error("Protocol error: {0}")]
    ProtocolError(String),

    /// Configuration error
    #[error("Configuration error: {0}")]
    ConfigError(String),
}

impl RealityError {
    /// Check if this error is recoverable
    ///
    /// Recoverable errors are typically transient I/O issues that may
    /// succeed on retry. Protocol and authentication errors are generally
    /// not recoverable.
    #[must_use]
    pub fn is_recoverable(&self) -> bool {
        match self {
            Self::Io(e) => matches!(
                e.kind(),
                io::ErrorKind::TimedOut
                    | io::ErrorKind::Interrupted
                    | io::ErrorKind::WouldBlock
                    | io::ErrorKind::ConnectionReset
            ),
            _ => false,
        }
    }

    /// Create a handshake failed error
    pub fn handshake(msg: impl Into<String>) -> Self {
        Self::HandshakeFailed(msg.into())
    }

    /// Create an invalid public key error
    pub fn invalid_public_key(msg: impl Into<String>) -> Self {
        Self::InvalidPublicKey(msg.into())
    }

    /// Create an invalid short ID error
    pub fn invalid_short_id(msg: impl Into<String>) -> Self {
        Self::InvalidShortId(msg.into())
    }

    /// Create an invalid server name error
    pub fn invalid_server_name(msg: impl Into<String>) -> Self {
        Self::InvalidServerName(msg.into())
    }

    /// Create an invalid fingerprint error
    pub fn invalid_fingerprint(msg: impl Into<String>) -> Self {
        Self::InvalidFingerprint(msg.into())
    }

    /// Create a key derivation error
    pub fn key_derivation(msg: impl Into<String>) -> Self {
        Self::KeyDerivation(msg.into())
    }

    /// Create a protocol error
    pub fn protocol(msg: impl Into<String>) -> Self {
        Self::ProtocolError(msg.into())
    }

    /// Create a configuration error
    pub fn config(msg: impl Into<String>) -> Self {
        Self::ConfigError(msg.into())
    }
}

/// Convert `RealityError` to `std::io::Error` for compatibility with async I/O traits
impl From<RealityError> for io::Error {
    fn from(e: RealityError) -> Self {
        match e {
            RealityError::Io(io_err) => io_err,
            RealityError::HandshakeFailed(_)
            | RealityError::ProtocolError(_)
            | RealityError::KeyDerivation(_) => {
                io::Error::new(io::ErrorKind::InvalidData, e.to_string())
            }
            RealityError::AuthenticationFailed => {
                io::Error::new(io::ErrorKind::PermissionDenied, e.to_string())
            }
            RealityError::InvalidPublicKey(_)
            | RealityError::InvalidShortId(_)
            | RealityError::InvalidServerName(_)
            | RealityError::InvalidFingerprint(_)
            | RealityError::ConfigError(_) => {
                io::Error::new(io::ErrorKind::InvalidInput, e.to_string())
            }
        }
    }
}

/// Type alias for Result with `RealityError`
pub type RealityResult<T> = std::result::Result<T, RealityError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = RealityError::HandshakeFailed("connection reset".to_string());
        assert!(err.to_string().contains("Handshake failed"));
        assert!(err.to_string().contains("connection reset"));

        let err = RealityError::InvalidPublicKey("wrong length".to_string());
        assert!(err.to_string().contains("Invalid public key"));

        let err = RealityError::InvalidShortId("not hex".to_string());
        assert!(err.to_string().contains("Invalid short ID"));

        let err = RealityError::AuthenticationFailed;
        assert!(err.to_string().contains("Authentication failed"));
    }

    #[test]
    fn test_error_is_recoverable() {
        // Protocol errors are not recoverable
        assert!(!RealityError::HandshakeFailed("test".to_string()).is_recoverable());
        assert!(!RealityError::AuthenticationFailed.is_recoverable());
        assert!(!RealityError::InvalidPublicKey("test".to_string()).is_recoverable());

        // Timeout I/O error is recoverable
        let io_err = io::Error::new(io::ErrorKind::TimedOut, "timeout");
        assert!(RealityError::Io(io_err).is_recoverable());

        // Connection reset is recoverable
        let io_err = io::Error::new(io::ErrorKind::ConnectionReset, "reset");
        assert!(RealityError::Io(io_err).is_recoverable());

        // Connection refused is not recoverable
        let io_err = io::Error::new(io::ErrorKind::ConnectionRefused, "refused");
        assert!(!RealityError::Io(io_err).is_recoverable());
    }

    #[test]
    fn test_error_to_io_error() {
        let reality_err = RealityError::HandshakeFailed("test".to_string());
        let io_err: io::Error = reality_err.into();
        assert_eq!(io_err.kind(), io::ErrorKind::InvalidData);

        let reality_err = RealityError::AuthenticationFailed;
        let io_err: io::Error = reality_err.into();
        assert_eq!(io_err.kind(), io::ErrorKind::PermissionDenied);

        let reality_err = RealityError::InvalidPublicKey("test".to_string());
        let io_err: io::Error = reality_err.into();
        assert_eq!(io_err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn test_error_constructors() {
        let err = RealityError::handshake("connection failed");
        assert!(matches!(err, RealityError::HandshakeFailed(_)));

        let err = RealityError::invalid_public_key("bad key");
        assert!(matches!(err, RealityError::InvalidPublicKey(_)));

        let err = RealityError::invalid_short_id("not hex");
        assert!(matches!(err, RealityError::InvalidShortId(_)));

        let err = RealityError::protocol("TLS error");
        assert!(matches!(err, RealityError::ProtocolError(_)));

        let err = RealityError::config("missing field");
        assert!(matches!(err, RealityError::ConfigError(_)));
    }

    #[test]
    fn test_io_error_passthrough() {
        let original = io::Error::new(io::ErrorKind::NotFound, "file not found");
        let kind = original.kind();
        let reality_err = RealityError::Io(original);

        // Convert back to io::Error
        let io_err: io::Error = reality_err.into();
        assert_eq!(io_err.kind(), kind);
    }
}
