//! Error types for rust-router
//!
//! This module defines a comprehensive error hierarchy for the transparent proxy router.
//! All errors are categorized by subsystem and include recovery hints.

use std::io;
use std::net::SocketAddr;

use thiserror::Error;

/// Top-level error type for rust-router
#[derive(Debug, Error)]
pub enum RustRouterError {
    /// Configuration errors (file parsing, validation)
    #[error("Configuration error: {0}")]
    Config(#[from] ConfigError),

    /// TPROXY socket and listener errors
    #[error("TPROXY error: {0}")]
    Tproxy(#[from] TproxyError),

    /// Outbound connection errors
    #[error("Outbound error: {0}")]
    Outbound(#[from] OutboundError),

    /// IPC communication errors
    #[error("IPC error: {0}")]
    Ipc(#[from] IpcError),

    /// Connection handling errors
    #[error("Connection error: {0}")]
    Connection(#[from] ConnectionError),

    /// I/O errors not covered by other categories
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
}

impl RustRouterError {
    /// Check if this error is recoverable (can retry operation)
    #[must_use]
    pub fn is_recoverable(&self) -> bool {
        match self {
            Self::Config(_) => false,
            Self::Tproxy(e) => e.is_recoverable(),
            Self::Outbound(e) => e.is_recoverable(),
            Self::Ipc(e) => e.is_recoverable(),
            Self::Connection(e) => e.is_recoverable(),
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

/// Configuration-related errors
#[derive(Debug, Error)]
pub enum ConfigError {
    /// File not found or inaccessible
    #[error("Configuration file not found: {path}")]
    FileNotFound { path: String },

    /// JSON/YAML parsing error
    #[error("Failed to parse configuration: {0}")]
    ParseError(String),

    /// Validation error (invalid values, missing required fields)
    #[error("Configuration validation failed: {0}")]
    ValidationError(String),

    /// Environment variable error
    #[error("Environment variable error: {name}: {reason}")]
    EnvError { name: String, reason: String },

    /// I/O error while reading config
    #[error("I/O error reading configuration: {0}")]
    IoError(#[from] io::Error),
}

impl ConfigError {
    /// Config errors are generally not recoverable without user intervention
    #[must_use]
    pub const fn is_recoverable(&self) -> bool {
        false
    }
}

/// TPROXY-related errors
#[derive(Debug, Error)]
pub enum TproxyError {
    /// Failed to create socket
    #[error("Failed to create TPROXY socket: {0}")]
    SocketCreation(String),

    /// Failed to set socket option (IP_TRANSPARENT, etc.)
    #[error("Failed to set socket option {option}: {reason}")]
    SocketOption { option: String, reason: String },

    /// Failed to bind to address
    #[error("Failed to bind to {addr}: {reason}")]
    BindError { addr: SocketAddr, reason: String },

    /// Failed to accept connection
    #[error("Accept error: {0}")]
    AcceptError(String),

    /// Failed to retrieve original destination
    #[error("Failed to get original destination: {0}")]
    OriginalDstError(String),

    /// Listener not ready
    #[error("Listener not ready")]
    NotReady,

    /// Permission denied (CAP_NET_ADMIN required)
    #[error("Permission denied: TPROXY requires CAP_NET_ADMIN capability")]
    PermissionDenied,

    /// I/O error
    #[error("TPROXY I/O error: {0}")]
    IoError(#[from] io::Error),
}

impl TproxyError {
    /// Check if this error is recoverable
    #[must_use]
    pub fn is_recoverable(&self) -> bool {
        match self {
            Self::SocketCreation(_) => false,
            Self::SocketOption { .. } => false,
            Self::BindError { .. } => false,
            Self::AcceptError(_) => true,
            Self::OriginalDstError(_) => true,
            Self::NotReady => true,
            Self::PermissionDenied => false,
            Self::IoError(e) => matches!(
                e.kind(),
                io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
            ),
        }
    }

    /// Create a socket option error
    pub fn socket_option(option: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::SocketOption {
            option: option.into(),
            reason: reason.into(),
        }
    }

    /// Create a bind error
    pub fn bind(addr: SocketAddr, reason: impl Into<String>) -> Self {
        Self::BindError {
            addr,
            reason: reason.into(),
        }
    }
}

/// Outbound connection errors
#[derive(Debug, Error)]
pub enum OutboundError {
    /// Connection failed
    #[error("Failed to connect to {addr}: {reason}")]
    ConnectionFailed { addr: SocketAddr, reason: String },

    /// Connection timeout
    #[error("Connection to {addr} timed out after {timeout_secs}s")]
    Timeout { addr: SocketAddr, timeout_secs: u64 },

    /// Outbound not found
    #[error("Outbound not found: {tag}")]
    NotFound { tag: String },

    /// Outbound is disabled or unhealthy
    #[error("Outbound {tag} is unavailable: {reason}")]
    Unavailable { tag: String, reason: String },

    /// Failed to set socket option (SO_BINDTODEVICE, SO_MARK)
    #[error("Failed to set outbound socket option {option}: {reason}")]
    SocketOption { option: String, reason: String },

    /// I/O error during connection
    #[error("Outbound I/O error: {0}")]
    IoError(#[from] io::Error),
}

impl OutboundError {
    /// Check if this error is recoverable
    #[must_use]
    pub fn is_recoverable(&self) -> bool {
        match self {
            Self::ConnectionFailed { .. } => true,
            Self::Timeout { .. } => true,
            Self::NotFound { .. } => false,
            Self::Unavailable { .. } => true,
            Self::SocketOption { .. } => false,
            Self::IoError(e) => matches!(
                e.kind(),
                io::ErrorKind::TimedOut
                    | io::ErrorKind::ConnectionRefused
                    | io::ErrorKind::ConnectionReset
            ),
        }
    }

    /// Create a connection failed error
    pub fn connection_failed(addr: SocketAddr, reason: impl Into<String>) -> Self {
        Self::ConnectionFailed {
            addr,
            reason: reason.into(),
        }
    }

    /// Create a not found error
    pub fn not_found(tag: impl Into<String>) -> Self {
        Self::NotFound { tag: tag.into() }
    }

    /// Create an unavailable error
    pub fn unavailable(tag: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::Unavailable {
            tag: tag.into(),
            reason: reason.into(),
        }
    }
}

/// IPC communication errors
#[derive(Debug, Error)]
pub enum IpcError {
    /// Failed to create Unix socket
    #[error("Failed to create IPC socket at {path}: {reason}")]
    SocketCreation { path: String, reason: String },

    /// Failed to bind Unix socket
    #[error("Failed to bind IPC socket to {path}: {reason}")]
    BindError { path: String, reason: String },

    /// Connection error
    #[error("IPC connection error: {0}")]
    ConnectionError(String),

    /// Protocol error (invalid message format)
    #[error("IPC protocol error: {0}")]
    ProtocolError(String),

    /// Command execution error
    #[error("IPC command failed: {command}: {reason}")]
    CommandError { command: String, reason: String },

    /// Serialization error
    #[error("IPC serialization error: {0}")]
    SerializationError(String),

    /// I/O error
    #[error("IPC I/O error: {0}")]
    IoError(#[from] io::Error),
}

impl IpcError {
    /// Check if this error is recoverable
    #[must_use]
    pub fn is_recoverable(&self) -> bool {
        match self {
            Self::SocketCreation { .. } => false,
            Self::BindError { .. } => false,
            Self::ConnectionError(_) => true,
            Self::ProtocolError(_) => true,
            Self::CommandError { .. } => true,
            Self::SerializationError(_) => false,
            Self::IoError(e) => matches!(
                e.kind(),
                io::ErrorKind::Interrupted
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::BrokenPipe
            ),
        }
    }

    /// Create a protocol error
    pub fn protocol(msg: impl Into<String>) -> Self {
        Self::ProtocolError(msg.into())
    }

    /// Create a command error
    pub fn command(cmd: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::CommandError {
            command: cmd.into(),
            reason: reason.into(),
        }
    }

    /// Create a serialization error
    pub fn serialization(msg: impl Into<String>) -> Self {
        Self::SerializationError(msg.into())
    }
}

/// Connection handling errors
#[derive(Debug, Error)]
pub enum ConnectionError {
    /// Connection pool exhausted
    #[error("Connection limit reached ({current}/{max})")]
    LimitReached { current: usize, max: usize },

    /// Connection was closed
    #[error("Connection closed: {reason}")]
    Closed { reason: String },

    /// Copy error during bidirectional transfer
    #[error("Data transfer error: {0}")]
    TransferError(String),

    /// Sniffing error
    #[error("Protocol sniffing failed: {0}")]
    SniffError(String),

    /// Shutdown in progress
    #[error("Server is shutting down")]
    ShuttingDown,

    /// I/O error
    #[error("Connection I/O error: {0}")]
    IoError(#[from] io::Error),
}

impl ConnectionError {
    /// Check if this error is recoverable
    #[must_use]
    pub fn is_recoverable(&self) -> bool {
        match self {
            Self::LimitReached { .. } => true,
            Self::Closed { .. } => false,
            Self::TransferError(_) => false,
            Self::SniffError(_) => true,
            Self::ShuttingDown => false,
            Self::IoError(e) => matches!(
                e.kind(),
                io::ErrorKind::TimedOut
                    | io::ErrorKind::Interrupted
                    | io::ErrorKind::ConnectionReset
            ),
        }
    }

    /// Create a limit reached error
    pub const fn limit_reached(current: usize, max: usize) -> Self {
        Self::LimitReached { current, max }
    }

    /// Create a closed error
    pub fn closed(reason: impl Into<String>) -> Self {
        Self::Closed {
            reason: reason.into(),
        }
    }

    /// Create a transfer error
    pub fn transfer(msg: impl Into<String>) -> Self {
        Self::TransferError(msg.into())
    }
}

/// Type alias for Result with RustRouterError
pub type Result<T> = std::result::Result<T, RustRouterError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_recovery_classification() {
        // Config errors are not recoverable
        let config_err = ConfigError::ValidationError("test".into());
        assert!(!config_err.is_recoverable());

        // Accept errors are recoverable
        let tproxy_err = TproxyError::AcceptError("test".into());
        assert!(tproxy_err.is_recoverable());

        // Permission denied is not recoverable
        let perm_err = TproxyError::PermissionDenied;
        assert!(!perm_err.is_recoverable());

        // Timeout is recoverable
        let timeout_err = OutboundError::Timeout {
            addr: "127.0.0.1:80".parse().unwrap(),
            timeout_secs: 10,
        };
        assert!(timeout_err.is_recoverable());

        // NotFound is not recoverable
        let not_found_err = OutboundError::not_found("test-outbound");
        assert!(!not_found_err.is_recoverable());
    }

    #[test]
    fn test_error_display() {
        let err = TproxyError::PermissionDenied;
        let msg = err.to_string();
        assert!(msg.contains("CAP_NET_ADMIN"));

        let err = OutboundError::connection_failed(
            "127.0.0.1:80".parse().unwrap(),
            "connection refused",
        );
        let msg = err.to_string();
        assert!(msg.contains("127.0.0.1:80"));
        assert!(msg.contains("connection refused"));
    }

    #[test]
    fn test_error_conversion() {
        let io_err = io::Error::new(io::ErrorKind::TimedOut, "timeout");
        let router_err: RustRouterError = io_err.into();
        assert!(router_err.is_recoverable());

        let config_err = ConfigError::ValidationError("invalid".into());
        let router_err: RustRouterError = config_err.into();
        assert!(!router_err.is_recoverable());
    }
}
