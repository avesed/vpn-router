//! Shadowsocks error types
//!
//! This module defines error types for Shadowsocks protocol operations.

use std::fmt;
use std::io;

/// Shadowsocks-specific errors
#[derive(Debug)]
pub enum ShadowsocksError {
    /// Invalid encryption method specified
    InvalidMethod(String),

    /// Invalid or missing password
    InvalidPassword(String),

    /// Connection to server failed
    ConnectionFailed {
        /// Server address that failed
        server: String,
        /// Reason for failure
        reason: String,
    },

    /// Protocol-level error
    ProtocolError(String),

    /// I/O error
    Io(io::Error),

    /// Configuration error
    ConfigError(String),
}

impl fmt::Display for ShadowsocksError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMethod(method) => {
                write!(f, "invalid Shadowsocks encryption method: {method}")
            }
            Self::InvalidPassword(reason) => {
                write!(f, "invalid Shadowsocks password: {reason}")
            }
            Self::ConnectionFailed { server, reason } => {
                write!(f, "Shadowsocks connection to {server} failed: {reason}")
            }
            Self::ProtocolError(msg) => {
                write!(f, "Shadowsocks protocol error: {msg}")
            }
            Self::Io(e) => {
                write!(f, "Shadowsocks I/O error: {e}")
            }
            Self::ConfigError(msg) => {
                write!(f, "Shadowsocks configuration error: {msg}")
            }
        }
    }
}

impl std::error::Error for ShadowsocksError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for ShadowsocksError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invalid_method_error() {
        let err = ShadowsocksError::InvalidMethod("bad-cipher".into());
        assert!(err.to_string().contains("invalid"));
        assert!(err.to_string().contains("bad-cipher"));
    }

    #[test]
    fn test_invalid_password_error() {
        let err = ShadowsocksError::InvalidPassword("too short".into());
        assert!(err.to_string().contains("password"));
        assert!(err.to_string().contains("too short"));
    }

    #[test]
    fn test_connection_failed_error() {
        let err = ShadowsocksError::ConnectionFailed {
            server: "192.168.1.1:8388".into(),
            reason: "connection refused".into(),
        };
        assert!(err.to_string().contains("192.168.1.1:8388"));
        assert!(err.to_string().contains("connection refused"));
    }

    #[test]
    fn test_protocol_error() {
        let err = ShadowsocksError::ProtocolError("invalid header".into());
        assert!(err.to_string().contains("protocol error"));
        assert!(err.to_string().contains("invalid header"));
    }

    #[test]
    fn test_io_error() {
        use std::error::Error as StdError;
        let io_err = io::Error::new(io::ErrorKind::ConnectionReset, "connection reset");
        let err = ShadowsocksError::from(io_err);
        assert!(err.to_string().contains("I/O error"));
        assert!(StdError::source(&err).is_some());
    }

    #[test]
    fn test_config_error() {
        let err = ShadowsocksError::ConfigError("missing server".into());
        assert!(err.to_string().contains("configuration error"));
        assert!(err.to_string().contains("missing server"));
    }
}
