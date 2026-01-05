//! IPC Protocol definitions
//!
//! This module defines the command and response types used for
//! inter-process communication via Unix socket.

use serde::{Deserialize, Serialize};

use crate::config::OutboundConfig;
use crate::connection::StatsSnapshot;

/// IPC command types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum IpcCommand {
    /// Ping to check if the server is alive
    Ping,

    /// Get server status
    Status,

    /// Get server capabilities
    GetCapabilities,

    /// Get overall statistics
    GetStats,

    /// Get per-outbound statistics
    GetOutboundStats,

    /// Reload configuration
    Reload {
        /// Path to configuration file
        config_path: String,
    },

    /// Add a new outbound
    AddOutbound {
        /// Outbound configuration
        config: OutboundConfig,
    },

    /// Remove an outbound
    RemoveOutbound {
        /// Outbound tag to remove
        tag: String,
    },

    /// Enable an outbound
    EnableOutbound {
        /// Outbound tag
        tag: String,
    },

    /// Disable an outbound
    DisableOutbound {
        /// Outbound tag
        tag: String,
    },

    /// Get outbound info
    GetOutbound {
        /// Outbound tag
        tag: String,
    },

    /// List all outbounds
    ListOutbounds,

    /// Initiate graceful shutdown
    Shutdown {
        /// Optional drain timeout in seconds
        drain_timeout_secs: Option<u32>,
    },
}

/// IPC response types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum IpcResponse {
    /// Ping response
    Pong,

    /// Status response
    Status(ServerStatus),

    /// Capabilities response
    Capabilities(ServerCapabilities),

    /// Statistics response
    Stats(StatsSnapshot),

    /// Per-outbound statistics response
    OutboundStats(OutboundStatsResponse),

    /// Outbound info response
    OutboundInfo(OutboundInfo),

    /// List of outbounds
    OutboundList(Vec<OutboundInfo>),

    /// Success response (for commands that don't return data)
    Success {
        /// Optional message
        message: Option<String>,
    },

    /// Error response
    Error(IpcError),
}

impl IpcResponse {
    /// Create a success response with no message
    pub fn success() -> Self {
        Self::Success { message: None }
    }

    /// Create a success response with a message
    pub fn success_with_message(msg: impl Into<String>) -> Self {
        Self::Success {
            message: Some(msg.into()),
        }
    }

    /// Create an error response
    pub fn error(code: ErrorCode, message: impl Into<String>) -> Self {
        Self::Error(IpcError {
            code,
            message: message.into(),
        })
    }

    /// Check if this is an error response
    #[must_use]
    pub const fn is_error(&self) -> bool {
        matches!(self, Self::Error(_))
    }
}

/// Server status information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerStatus {
    /// Server version
    pub version: String,
    /// Uptime in seconds
    pub uptime_secs: u64,
    /// Active connections
    pub active_connections: u64,
    /// Total connections handled
    pub total_connections: u64,
    /// Number of configured outbounds
    pub outbound_count: usize,
    /// Whether the server is accepting new connections
    pub accepting: bool,
    /// Whether shutdown is in progress
    pub shutting_down: bool,
}

/// Server capabilities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerCapabilities {
    /// Supported outbound types
    pub outbound_types: Vec<String>,
    /// Whether hot reload is supported
    pub hot_reload: bool,
    /// Whether TLS sniffing is supported
    pub tls_sniffing: bool,
    /// Whether UDP is supported
    pub udp_support: bool,
    /// Maximum connections
    pub max_connections: usize,
    /// Protocol version
    pub protocol_version: u32,
}

impl Default for ServerCapabilities {
    fn default() -> Self {
        Self {
            outbound_types: vec!["direct".into(), "block".into()],
            hot_reload: true,
            tls_sniffing: true,
            udp_support: false, // Phase 1: TCP only
            max_connections: 65536,
            protocol_version: 1,
        }
    }
}

/// Per-outbound statistics response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundStatsResponse {
    /// Statistics per outbound tag
    pub outbounds: std::collections::HashMap<String, crate::connection::OutboundStatsSnapshot>,
}

/// Information about a single outbound
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundInfo {
    /// Outbound tag
    pub tag: String,
    /// Outbound type
    pub outbound_type: String,
    /// Whether enabled
    pub enabled: bool,
    /// Health status
    pub health: String,
    /// Active connections
    pub active_connections: u64,
    /// Total connections
    pub total_connections: u64,
    /// Bind interface (if any)
    pub bind_interface: Option<String>,
    /// Routing mark (if any)
    pub routing_mark: Option<u32>,
}

/// IPC error
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcError {
    /// Error code
    pub code: ErrorCode,
    /// Error message
    pub message: String,
}

impl std::fmt::Display for IpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {}", self.code, self.message)
    }
}

impl std::error::Error for IpcError {}

/// Error codes for IPC responses
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    /// Unknown error
    Unknown,
    /// Invalid command
    InvalidCommand,
    /// Invalid parameters
    InvalidParameters,
    /// Resource not found
    NotFound,
    /// Resource already exists
    AlreadyExists,
    /// Operation failed
    OperationFailed,
    /// Server is shutting down
    ShuttingDown,
    /// Permission denied
    PermissionDenied,
    /// Internal error
    InternalError,
}

/// Message framing for IPC
///
/// Messages are length-prefixed:
/// - 4 bytes: message length (big-endian u32)
/// - N bytes: JSON message
pub const MAX_MESSAGE_SIZE: usize = 1024 * 1024; // 1 MB
pub const LENGTH_PREFIX_SIZE: usize = 4;

/// Encode a message with length prefix
pub fn encode_message<T: Serialize>(msg: &T) -> Result<Vec<u8>, serde_json::Error> {
    let json = serde_json::to_vec(msg)?;
    let len = json.len() as u32;

    let mut buf = Vec::with_capacity(LENGTH_PREFIX_SIZE + json.len());
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(&json);

    Ok(buf)
}

/// Decode a length-prefixed message
pub fn decode_message<T: for<'de> Deserialize<'de>>(data: &[u8]) -> Result<T, serde_json::Error> {
    serde_json::from_slice(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_command_serialization() {
        let cmd = IpcCommand::Ping;
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("\"type\":\"ping\""));

        let cmd = IpcCommand::Reload {
            config_path: "/etc/router.json".into(),
        };
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("\"type\":\"reload\""));
        assert!(json.contains("config_path"));
    }

    #[test]
    fn test_response_serialization() {
        let resp = IpcResponse::Pong;
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"type\":\"pong\""));

        let resp = IpcResponse::error(ErrorCode::NotFound, "Outbound not found");
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"type\":\"error\""));
        assert!(json.contains("NOT_FOUND"));
    }

    #[test]
    fn test_encode_decode() {
        let cmd = IpcCommand::Status;
        let encoded = encode_message(&cmd).unwrap();

        // First 4 bytes are length
        let len = u32::from_be_bytes([encoded[0], encoded[1], encoded[2], encoded[3]]) as usize;
        assert_eq!(len, encoded.len() - 4);

        // Decode the JSON part
        let decoded: IpcCommand = decode_message(&encoded[4..]).unwrap();
        assert!(matches!(decoded, IpcCommand::Status));
    }

    #[test]
    fn test_capabilities_default() {
        let caps = ServerCapabilities::default();
        assert!(caps.outbound_types.contains(&"direct".to_string()));
        assert!(caps.hot_reload);
        assert!(!caps.udp_support); // Phase 1: TCP only
    }

    #[test]
    fn test_response_helpers() {
        let success = IpcResponse::success();
        assert!(!success.is_error());

        let error = IpcResponse::error(ErrorCode::NotFound, "test");
        assert!(error.is_error());
    }
}
