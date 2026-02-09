//! XTLS-Vision error types
//!
//! This module defines error types for the XTLS-Vision protocol implementation.
//! These errors cover TLS detection failures, state transition issues, and
//! stream handling problems.

use std::io;

use thiserror::Error;

/// XTLS-Vision protocol errors
///
/// This enum covers all error conditions that can occur during XTLS-Vision
/// traffic detection, mode switching, and data transfer.
#[derive(Debug, Error)]
pub enum VisionError {
    /// TLS detection failed (data doesn't look like TLS)
    #[error("TLS detection failed: {0}")]
    DetectionFailed(String),

    /// Invalid TLS record structure
    #[error("Invalid TLS record: {0}")]
    InvalidTlsRecord(String),

    /// Invalid TLS version in record header
    #[error("Invalid TLS version: 0x{0:04x}")]
    InvalidTlsVersion(u16),

    /// Invalid TLS handshake type
    #[error("Invalid handshake type: 0x{0:02x}")]
    InvalidHandshakeType(u8),

    /// State transition error (invalid state change)
    #[error("Invalid state transition: cannot go from {from:?} to {to:?}")]
    InvalidStateTransition { from: String, to: String },

    /// Buffer too small for TLS record
    #[error("Buffer too small: need at least {needed} bytes, got {actual}")]
    BufferTooSmall { needed: usize, actual: usize },

    /// Unexpected end of data during parsing
    #[error("Unexpected end of data: expected {expected} bytes, got {actual}")]
    UnexpectedEof { expected: usize, actual: usize },

    /// I/O error during read/write
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// Stream handling error
    #[error("Stream error: {0}")]
    StreamError(String),

    /// Protocol error (general issues)
    #[error("Protocol error: {0}")]
    ProtocolError(String),
}

impl VisionError {
    /// Check if this error is recoverable
    ///
    /// Recoverable errors are typically transient I/O issues that may
    /// succeed on retry. Protocol and detection errors are generally
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

    /// Create a detection failed error
    pub fn detection_failed(msg: impl Into<String>) -> Self {
        Self::DetectionFailed(msg.into())
    }

    /// Create an invalid TLS record error
    pub fn invalid_tls_record(msg: impl Into<String>) -> Self {
        Self::InvalidTlsRecord(msg.into())
    }

    /// Create an invalid state transition error
    pub fn invalid_state_transition(from: impl Into<String>, to: impl Into<String>) -> Self {
        Self::InvalidStateTransition {
            from: from.into(),
            to: to.into(),
        }
    }

    /// Create a buffer too small error
    pub fn buffer_too_small(needed: usize, actual: usize) -> Self {
        Self::BufferTooSmall { needed, actual }
    }

    /// Create an unexpected EOF error
    pub fn unexpected_eof(expected: usize, actual: usize) -> Self {
        Self::UnexpectedEof { expected, actual }
    }

    /// Create a stream error
    pub fn stream(msg: impl Into<String>) -> Self {
        Self::StreamError(msg.into())
    }

    /// Create a protocol error
    pub fn protocol(msg: impl Into<String>) -> Self {
        Self::ProtocolError(msg.into())
    }
}

/// Convert `VisionError` to `std::io::Error` for compatibility with async I/O traits
impl From<VisionError> for io::Error {
    fn from(e: VisionError) -> Self {
        match e {
            VisionError::Io(io_err) => io_err,
            VisionError::DetectionFailed(_)
            | VisionError::InvalidTlsRecord(_)
            | VisionError::InvalidTlsVersion(_)
            | VisionError::InvalidHandshakeType(_)
            | VisionError::ProtocolError(_) => {
                io::Error::new(io::ErrorKind::InvalidData, e.to_string())
            }
            VisionError::InvalidStateTransition { .. } | VisionError::StreamError(_) => {
                io::Error::new(io::ErrorKind::Other, e.to_string())
            }
            VisionError::BufferTooSmall { .. } => {
                io::Error::new(io::ErrorKind::WriteZero, e.to_string())
            }
            VisionError::UnexpectedEof { .. } => {
                io::Error::new(io::ErrorKind::UnexpectedEof, e.to_string())
            }
        }
    }
}

/// Type alias for Result with `VisionError`
pub type VisionResult<T> = std::result::Result<T, VisionError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = VisionError::DetectionFailed("not TLS traffic".to_string());
        assert!(err.to_string().contains("TLS detection failed"));
        assert!(err.to_string().contains("not TLS traffic"));

        let err = VisionError::InvalidTlsVersion(0x0200);
        assert!(err.to_string().contains("0x0200"));

        let err = VisionError::InvalidHandshakeType(0xff);
        assert!(err.to_string().contains("0xff"));

        let err = VisionError::buffer_too_small(10, 5);
        assert!(err.to_string().contains("10"));
        assert!(err.to_string().contains("5"));
    }

    #[test]
    fn test_error_is_recoverable() {
        // Protocol errors are not recoverable
        assert!(!VisionError::DetectionFailed("test".to_string()).is_recoverable());
        assert!(!VisionError::InvalidTlsVersion(0x0200).is_recoverable());
        assert!(!VisionError::InvalidHandshakeType(0xff).is_recoverable());

        // Timeout I/O error is recoverable
        let io_err = io::Error::new(io::ErrorKind::TimedOut, "timeout");
        assert!(VisionError::Io(io_err).is_recoverable());

        // Connection reset is recoverable
        let io_err = io::Error::new(io::ErrorKind::ConnectionReset, "reset");
        assert!(VisionError::Io(io_err).is_recoverable());

        // Connection refused is not recoverable
        let io_err = io::Error::new(io::ErrorKind::ConnectionRefused, "refused");
        assert!(!VisionError::Io(io_err).is_recoverable());
    }

    #[test]
    fn test_error_to_io_error() {
        let vision_err = VisionError::InvalidTlsVersion(0x0200);
        let io_err: io::Error = vision_err.into();
        assert_eq!(io_err.kind(), io::ErrorKind::InvalidData);

        let vision_err = VisionError::unexpected_eof(10, 5);
        let io_err: io::Error = vision_err.into();
        assert_eq!(io_err.kind(), io::ErrorKind::UnexpectedEof);

        let vision_err = VisionError::buffer_too_small(20, 10);
        let io_err: io::Error = vision_err.into();
        assert_eq!(io_err.kind(), io::ErrorKind::WriteZero);
    }

    #[test]
    fn test_error_constructors() {
        let err = VisionError::detection_failed("no TLS header");
        assert!(matches!(err, VisionError::DetectionFailed(_)));

        let err = VisionError::invalid_tls_record("truncated");
        assert!(matches!(err, VisionError::InvalidTlsRecord(_)));

        let err = VisionError::invalid_state_transition("Inspecting", "Inspecting");
        assert!(matches!(err, VisionError::InvalidStateTransition { .. }));

        let err = VisionError::buffer_too_small(100, 50);
        match err {
            VisionError::BufferTooSmall { needed, actual } => {
                assert_eq!(needed, 100);
                assert_eq!(actual, 50);
            }
            _ => panic!("Wrong error type"),
        }

        let err = VisionError::unexpected_eof(200, 100);
        match err {
            VisionError::UnexpectedEof { expected, actual } => {
                assert_eq!(expected, 200);
                assert_eq!(actual, 100);
            }
            _ => panic!("Wrong error type"),
        }

        let err = VisionError::stream("connection closed");
        assert!(matches!(err, VisionError::StreamError(_)));

        let err = VisionError::protocol("general error");
        assert!(matches!(err, VisionError::ProtocolError(_)));
    }

    #[test]
    fn test_io_error_passthrough() {
        let original = io::Error::new(io::ErrorKind::NotFound, "file not found");
        let kind = original.kind();
        let vision_err = VisionError::Io(original);

        // Convert back to io::Error
        let io_err: io::Error = vision_err.into();
        assert_eq!(io_err.kind(), kind);
    }
}
