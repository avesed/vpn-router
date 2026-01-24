//! VLESS protocol error types
//!
//! This module defines error types for the VLESS protocol implementation.
//! All errors are designed to be informative and include relevant context
//! for debugging protocol issues.

use std::io;

use thiserror::Error;

/// VLESS protocol errors
///
/// This enum covers all error conditions that can occur during VLESS
/// protocol encoding, decoding, and authentication.
#[derive(Debug, Error)]
pub enum VlessError {
    /// Invalid protocol version (expected 0)
    #[error("Invalid VLESS version: expected 0, got {0}")]
    InvalidVersion(u8),

    /// Invalid or malformed UUID
    #[error("Invalid UUID: {0}")]
    InvalidUuid(String),

    /// UUID authentication failed (unknown user)
    #[error("Authentication failed: unknown UUID")]
    AuthenticationFailed,

    /// Invalid command byte
    #[error("Invalid command: {0:#04x} (expected 0x01=TCP, 0x02=UDP, 0x03=MUX)")]
    InvalidCommand(u8),

    /// Invalid address type
    #[error("Invalid address type: {0:#04x} (expected 0x01=IPv4, 0x02=Domain, 0x03=IPv6)")]
    InvalidAddressType(u8),

    /// Domain name too long (max 255 bytes)
    #[error("Domain name too long: {0} bytes (max 255)")]
    DomainTooLong(usize),

    /// Empty domain name
    #[error("Empty domain name")]
    EmptyDomain,

    /// Invalid domain name encoding
    #[error("Invalid domain name encoding: {0}")]
    InvalidDomainEncoding(String),

    /// Addons parsing error
    #[error("Failed to parse addons: {0}")]
    AddonsParseError(String),

    /// Addons encoding error
    #[error("Failed to encode addons: {0}")]
    AddonsEncodeError(String),

    /// Invalid flow value in addons
    #[error("Invalid flow value: {0}")]
    InvalidFlow(String),

    /// Unexpected end of data during parsing
    #[error("Unexpected end of data: expected {expected} bytes, got {actual}")]
    UnexpectedEof { expected: usize, actual: usize },

    /// Buffer too small for encoding
    #[error("Buffer too small: need {needed} bytes, have {available}")]
    BufferTooSmall { needed: usize, available: usize },

    /// I/O error during read/write
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// Protocol error (general malformed message)
    #[error("Protocol error: {0}")]
    ProtocolError(String),
}

impl VlessError {
    /// Check if this error is recoverable
    ///
    /// Recoverable errors are typically transient I/O issues that may
    /// succeed on retry. Protocol errors are generally not recoverable.
    #[must_use]
    pub fn is_recoverable(&self) -> bool {
        match self {
            Self::Io(e) => matches!(
                e.kind(),
                io::ErrorKind::TimedOut
                    | io::ErrorKind::Interrupted
                    | io::ErrorKind::WouldBlock
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::UnexpectedEof  // Client disconnected during handshake
                    | io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::BrokenPipe
            ),
            _ => false,
        }
    }

    /// Create an unexpected EOF error
    pub fn unexpected_eof(expected: usize, actual: usize) -> Self {
        Self::UnexpectedEof { expected, actual }
    }

    /// Create a buffer too small error
    pub fn buffer_too_small(needed: usize, available: usize) -> Self {
        Self::BufferTooSmall { needed, available }
    }

    /// Create a protocol error
    pub fn protocol(msg: impl Into<String>) -> Self {
        Self::ProtocolError(msg.into())
    }

    /// Create an addons parse error
    pub fn addons_parse(msg: impl Into<String>) -> Self {
        Self::AddonsParseError(msg.into())
    }

    /// Create an addons encode error
    pub fn addons_encode(msg: impl Into<String>) -> Self {
        Self::AddonsEncodeError(msg.into())
    }
}

/// Convert `VlessError` to `std::io::Error` for compatibility with async I/O traits
impl From<VlessError> for io::Error {
    fn from(e: VlessError) -> Self {
        match e {
            VlessError::Io(io_err) => io_err,
            VlessError::InvalidVersion(_)
            | VlessError::InvalidCommand(_)
            | VlessError::InvalidAddressType(_)
            | VlessError::AddonsParseError(_)
            | VlessError::ProtocolError(_) => {
                io::Error::new(io::ErrorKind::InvalidData, e.to_string())
            }
            VlessError::InvalidUuid(_) | VlessError::AuthenticationFailed => {
                io::Error::new(io::ErrorKind::PermissionDenied, e.to_string())
            }
            VlessError::DomainTooLong(_)
            | VlessError::EmptyDomain
            | VlessError::InvalidDomainEncoding(_)
            | VlessError::InvalidFlow(_)
            | VlessError::AddonsEncodeError(_) => {
                io::Error::new(io::ErrorKind::InvalidInput, e.to_string())
            }
            VlessError::UnexpectedEof { .. } => {
                io::Error::new(io::ErrorKind::UnexpectedEof, e.to_string())
            }
            VlessError::BufferTooSmall { .. } => {
                io::Error::new(io::ErrorKind::WriteZero, e.to_string())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = VlessError::InvalidVersion(1);
        assert!(err.to_string().contains("expected 0"));
        assert!(err.to_string().contains("got 1"));

        let err = VlessError::InvalidCommand(0x04);
        assert!(err.to_string().contains("0x04"));
        assert!(err.to_string().contains("TCP"));
        assert!(err.to_string().contains("UDP"));

        let err = VlessError::InvalidAddressType(0x05);
        assert!(err.to_string().contains("0x05"));

        let err = VlessError::DomainTooLong(300);
        assert!(err.to_string().contains("300"));
        assert!(err.to_string().contains("max 255"));
    }

    #[test]
    fn test_error_is_recoverable() {
        // Protocol errors are not recoverable
        assert!(!VlessError::InvalidVersion(1).is_recoverable());
        assert!(!VlessError::AuthenticationFailed.is_recoverable());
        assert!(!VlessError::InvalidCommand(0x04).is_recoverable());

        // Timeout I/O error is recoverable
        let io_err = io::Error::new(io::ErrorKind::TimedOut, "timeout");
        assert!(VlessError::Io(io_err).is_recoverable());

        // Connection reset is recoverable
        let io_err = io::Error::new(io::ErrorKind::ConnectionReset, "reset");
        assert!(VlessError::Io(io_err).is_recoverable());

        // Connection refused is not recoverable
        let io_err = io::Error::new(io::ErrorKind::ConnectionRefused, "refused");
        assert!(!VlessError::Io(io_err).is_recoverable());
    }

    #[test]
    fn test_error_to_io_error() {
        let vless_err = VlessError::InvalidVersion(1);
        let io_err: io::Error = vless_err.into();
        assert_eq!(io_err.kind(), io::ErrorKind::InvalidData);

        let vless_err = VlessError::AuthenticationFailed;
        let io_err: io::Error = vless_err.into();
        assert_eq!(io_err.kind(), io::ErrorKind::PermissionDenied);

        let vless_err = VlessError::unexpected_eof(10, 5);
        let io_err: io::Error = vless_err.into();
        assert_eq!(io_err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn test_error_constructors() {
        let err = VlessError::unexpected_eof(100, 50);
        match err {
            VlessError::UnexpectedEof { expected, actual } => {
                assert_eq!(expected, 100);
                assert_eq!(actual, 50);
            }
            _ => panic!("Wrong error type"),
        }

        let err = VlessError::buffer_too_small(200, 100);
        match err {
            VlessError::BufferTooSmall { needed, available } => {
                assert_eq!(needed, 200);
                assert_eq!(available, 100);
            }
            _ => panic!("Wrong error type"),
        }

        let err = VlessError::protocol("test error");
        match err {
            VlessError::ProtocolError(msg) => {
                assert_eq!(msg, "test error");
            }
            _ => panic!("Wrong error type"),
        }
    }

    #[test]
    fn test_io_error_passthrough() {
        let original = io::Error::new(io::ErrorKind::NotFound, "file not found");
        let kind = original.kind();
        let vless_err = VlessError::Io(original);

        // Convert back to io::Error
        let io_err: io::Error = vless_err.into();
        assert_eq!(io_err.kind(), kind);
    }
}
