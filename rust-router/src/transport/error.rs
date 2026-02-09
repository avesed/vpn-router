//! Transport layer error types
//!
//! This module defines error types for transport layer operations including
//! connection establishment, TLS handshake, and WebSocket upgrade.

use std::io;

use thiserror::Error;

/// Transport layer errors
///
/// This enum covers all error conditions that can occur during transport
/// layer operations (TCP, TLS, WebSocket connections).
#[derive(Debug, Error)]
pub enum TransportError {
    /// TCP connection failed
    #[error("TCP connection to {address} failed: {reason}")]
    ConnectionFailed {
        /// Target address
        address: String,
        /// Failure reason
        reason: String,
    },

    /// Connection timeout
    #[error("Connection to {address} timed out after {timeout_ms}ms")]
    Timeout {
        /// Target address
        address: String,
        /// Timeout in milliseconds
        timeout_ms: u64,
    },

    /// DNS resolution failed
    #[error("Failed to resolve address {address}: {reason}")]
    DnsResolutionFailed {
        /// Hostname that failed to resolve
        address: String,
        /// Failure reason
        reason: String,
    },

    /// TLS configuration error
    #[error("TLS configuration error: {0}")]
    TlsConfigError(String),

    /// TLS handshake failed
    #[error("TLS handshake with {server_name} failed: {reason}")]
    TlsHandshakeFailed {
        /// Server name (SNI)
        server_name: String,
        /// Failure reason
        reason: String,
    },

    /// Invalid server name for TLS SNI
    #[error("Invalid server name for TLS SNI: {0}")]
    InvalidServerName(String),

    /// WebSocket handshake failed
    #[error("WebSocket handshake failed: {0}")]
    WebSocketHandshakeFailed(String),

    /// WebSocket protocol error
    #[error("WebSocket protocol error: {0}")]
    WebSocketProtocolError(String),

    /// Invalid WebSocket URL
    #[error("Invalid WebSocket URL: {0}")]
    InvalidWebSocketUrl(String),

    /// QUIC connection failed
    #[error("QUIC connection to {address} failed: {reason}")]
    QuicConnectionFailed {
        /// Target address
        address: String,
        /// Failure reason
        reason: String,
    },

    /// QUIC stream error
    #[error("QUIC stream error: {0}")]
    QuicStreamError(String),

    /// QUIC endpoint creation failed
    #[error("Failed to create QUIC endpoint: {0}")]
    QuicEndpointError(String),

    /// Address parse error
    #[error("Invalid address format: {0}")]
    InvalidAddress(String),

    /// Socket option error
    #[error("Failed to set socket option {option}: {reason}")]
    SocketOption {
        /// Option name
        option: String,
        /// Failure reason
        reason: String,
    },

    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
}

impl TransportError {
    /// Check if this error is recoverable (can retry)
    ///
    /// Recoverable errors are typically transient network issues that may
    /// succeed on retry. Configuration errors are generally not recoverable.
    #[must_use]
    pub fn is_recoverable(&self) -> bool {
        match self {
            Self::ConnectionFailed { .. } => true,
            Self::Timeout { .. } => true,
            Self::DnsResolutionFailed { .. } => true,
            Self::TlsConfigError(_) => false,
            Self::TlsHandshakeFailed { .. } => true,
            Self::InvalidServerName(_) => false,
            Self::WebSocketHandshakeFailed(_) => true,
            Self::WebSocketProtocolError(_) => false,
            Self::InvalidWebSocketUrl(_) => false,
            Self::QuicConnectionFailed { .. } => true,
            Self::QuicStreamError(_) => true,
            Self::QuicEndpointError(_) => false,
            Self::InvalidAddress(_) => false,
            Self::SocketOption { .. } => false,
            Self::Io(e) => matches!(
                e.kind(),
                io::ErrorKind::TimedOut
                    | io::ErrorKind::Interrupted
                    | io::ErrorKind::WouldBlock
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::ConnectionRefused
            ),
        }
    }

    /// Create a connection failed error
    pub fn connection_failed(address: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::ConnectionFailed {
            address: address.into(),
            reason: reason.into(),
        }
    }

    /// Create a timeout error
    pub fn timeout(address: impl Into<String>, timeout_ms: u64) -> Self {
        Self::Timeout {
            address: address.into(),
            timeout_ms,
        }
    }

    /// Create a DNS resolution failed error
    pub fn dns_failed(address: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::DnsResolutionFailed {
            address: address.into(),
            reason: reason.into(),
        }
    }

    /// Create a TLS configuration error
    pub fn tls_config(msg: impl Into<String>) -> Self {
        Self::TlsConfigError(msg.into())
    }

    /// Create a TLS handshake failed error
    pub fn tls_handshake(server_name: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::TlsHandshakeFailed {
            server_name: server_name.into(),
            reason: reason.into(),
        }
    }

    /// Create an invalid server name error
    pub fn invalid_server_name(name: impl Into<String>) -> Self {
        Self::InvalidServerName(name.into())
    }

    /// Create a WebSocket handshake failed error
    pub fn websocket_handshake(msg: impl Into<String>) -> Self {
        Self::WebSocketHandshakeFailed(msg.into())
    }

    /// Create a WebSocket protocol error
    pub fn websocket_protocol(msg: impl Into<String>) -> Self {
        Self::WebSocketProtocolError(msg.into())
    }

    /// Create an invalid WebSocket URL error
    pub fn invalid_websocket_url(msg: impl Into<String>) -> Self {
        Self::InvalidWebSocketUrl(msg.into())
    }

    /// Create a QUIC connection failed error
    pub fn quic_connection(address: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::QuicConnectionFailed {
            address: address.into(),
            reason: reason.into(),
        }
    }

    /// Create a QUIC stream error
    pub fn quic_stream(msg: impl Into<String>) -> Self {
        Self::QuicStreamError(msg.into())
    }

    /// Create a QUIC endpoint error
    pub fn quic_endpoint(msg: impl Into<String>) -> Self {
        Self::QuicEndpointError(msg.into())
    }

    /// Create an invalid address error
    pub fn invalid_address(msg: impl Into<String>) -> Self {
        Self::InvalidAddress(msg.into())
    }

    /// Create a socket option error
    pub fn socket_option(option: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::SocketOption {
            option: option.into(),
            reason: reason.into(),
        }
    }
}

/// Convert `TransportError` to `std::io::Error` for compatibility
impl From<TransportError> for io::Error {
    fn from(e: TransportError) -> Self {
        match e {
            TransportError::Io(io_err) => io_err,
            TransportError::ConnectionFailed { .. } => {
                io::Error::new(io::ErrorKind::ConnectionRefused, e.to_string())
            }
            TransportError::Timeout { .. } => {
                io::Error::new(io::ErrorKind::TimedOut, e.to_string())
            }
            TransportError::DnsResolutionFailed { .. } => {
                io::Error::new(io::ErrorKind::NotFound, e.to_string())
            }
            TransportError::TlsConfigError(_)
            | TransportError::InvalidServerName(_)
            | TransportError::InvalidWebSocketUrl(_)
            | TransportError::InvalidAddress(_)
            | TransportError::QuicEndpointError(_) => {
                io::Error::new(io::ErrorKind::InvalidInput, e.to_string())
            }
            TransportError::TlsHandshakeFailed { .. }
            | TransportError::WebSocketHandshakeFailed(_)
            | TransportError::WebSocketProtocolError(_)
            | TransportError::QuicConnectionFailed { .. }
            | TransportError::QuicStreamError(_) => {
                io::Error::new(io::ErrorKind::ConnectionAborted, e.to_string())
            }
            TransportError::SocketOption { .. } => {
                io::Error::new(io::ErrorKind::Other, e.to_string())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = TransportError::connection_failed("example.com:443", "connection refused");
        assert!(err.to_string().contains("example.com:443"));
        assert!(err.to_string().contains("connection refused"));

        let err = TransportError::timeout("example.com:443", 30000);
        assert!(err.to_string().contains("30000ms"));

        let err = TransportError::tls_handshake("example.com", "certificate expired");
        assert!(err.to_string().contains("example.com"));
        assert!(err.to_string().contains("certificate expired"));
    }

    #[test]
    fn test_error_is_recoverable() {
        // Connection errors are recoverable
        assert!(TransportError::connection_failed("addr", "refused").is_recoverable());
        assert!(TransportError::timeout("addr", 1000).is_recoverable());
        assert!(TransportError::dns_failed("addr", "nxdomain").is_recoverable());
        assert!(TransportError::tls_handshake("name", "reason").is_recoverable());
        assert!(TransportError::websocket_handshake("reason").is_recoverable());
        assert!(TransportError::quic_connection("addr", "reason").is_recoverable());
        assert!(TransportError::quic_stream("error").is_recoverable());

        // Configuration errors are not recoverable
        assert!(!TransportError::tls_config("bad config").is_recoverable());
        assert!(!TransportError::invalid_server_name("bad").is_recoverable());
        assert!(!TransportError::invalid_address("bad").is_recoverable());
        assert!(!TransportError::websocket_protocol("error").is_recoverable());
        assert!(!TransportError::quic_endpoint("error").is_recoverable());
    }

    #[test]
    fn test_error_to_io_error() {
        let transport_err = TransportError::connection_failed("addr", "refused");
        let io_err: io::Error = transport_err.into();
        assert_eq!(io_err.kind(), io::ErrorKind::ConnectionRefused);

        let transport_err = TransportError::timeout("addr", 1000);
        let io_err: io::Error = transport_err.into();
        assert_eq!(io_err.kind(), io::ErrorKind::TimedOut);

        let transport_err = TransportError::invalid_address("bad");
        let io_err: io::Error = transport_err.into();
        assert_eq!(io_err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn test_io_error_passthrough() {
        let original = io::Error::new(io::ErrorKind::NotFound, "not found");
        let kind = original.kind();
        let transport_err = TransportError::Io(original);

        let io_err: io::Error = transport_err.into();
        assert_eq!(io_err.kind(), kind);
    }

    #[test]
    fn test_error_constructors() {
        let err = TransportError::socket_option("TCP_NODELAY", "not supported");
        match err {
            TransportError::SocketOption { option, reason } => {
                assert_eq!(option, "TCP_NODELAY");
                assert_eq!(reason, "not supported");
            }
            _ => panic!("Wrong error type"),
        }
    }

    #[test]
    fn test_quic_error_constructors() {
        let err = TransportError::quic_connection("127.0.0.1:443", "handshake failed");
        match err {
            TransportError::QuicConnectionFailed { address, reason } => {
                assert_eq!(address, "127.0.0.1:443");
                assert_eq!(reason, "handshake failed");
            }
            _ => panic!("Wrong error type"),
        }

        let err = TransportError::quic_stream("stream reset");
        match err {
            TransportError::QuicStreamError(msg) => {
                assert_eq!(msg, "stream reset");
            }
            _ => panic!("Wrong error type"),
        }

        let err = TransportError::quic_endpoint("bind failed");
        match err {
            TransportError::QuicEndpointError(msg) => {
                assert_eq!(msg, "bind failed");
            }
            _ => panic!("Wrong error type"),
        }
    }

    #[test]
    fn test_quic_error_to_io_error() {
        let transport_err = TransportError::quic_connection("addr", "reason");
        let io_err: io::Error = transport_err.into();
        assert_eq!(io_err.kind(), io::ErrorKind::ConnectionAborted);

        let transport_err = TransportError::quic_stream("stream error");
        let io_err: io::Error = transport_err.into();
        assert_eq!(io_err.kind(), io::ErrorKind::ConnectionAborted);

        let transport_err = TransportError::quic_endpoint("endpoint error");
        let io_err: io::Error = transport_err.into();
        assert_eq!(io_err.kind(), io::ErrorKind::InvalidInput);
    }
}
