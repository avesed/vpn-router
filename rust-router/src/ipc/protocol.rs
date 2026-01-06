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

    /// Test rule matching (for debugging/parity testing)
    ///
    /// This command tests the rule engine against a specific connection.
    /// It is primarily used for debugging and parity testing with the
    /// Python reference implementation.
    TestMatch {
        /// Domain name (optional)
        domain: Option<String>,
        /// Destination IP address (optional)
        dest_ip: Option<String>,
        /// Destination port
        dest_port: u16,
        /// Transport protocol (tcp/udp)
        protocol: String,
        /// Sniffed protocol (optional: tls/http/quic)
        #[serde(default)]
        sniffed_protocol: Option<String>,
    },

    /// Get rule engine statistics
    ///
    /// Returns statistics about the current routing configuration,
    /// including rule counts and version information.
    GetRuleStats,

    /// Reload rules from configuration
    ///
    /// Reloads the rule engine configuration from the specified path.
    /// If no path is provided, uses the current configuration.
    ReloadRules {
        /// Optional path to configuration file (uses current config if None)
        #[serde(default)]
        config_path: Option<String>,
    },

    /// Add a SOCKS5 outbound with connection pool
    ///
    /// Creates a new SOCKS5 client outbound with deadpool connection pooling.
    /// Supports optional username/password authentication (RFC 1929).
    AddSocks5Outbound {
        /// Unique tag for this outbound
        tag: String,
        /// SOCKS5 server address (host:port)
        server_addr: String,
        /// Optional username for authentication
        #[serde(default)]
        username: Option<String>,
        /// Optional password for authentication
        #[serde(default)]
        password: Option<String>,
        /// Connection timeout in seconds (default: 10)
        #[serde(default = "default_connect_timeout")]
        connect_timeout_secs: u64,
        /// Idle timeout in seconds (default: 300)
        #[serde(default = "default_idle_timeout")]
        idle_timeout_secs: u64,
        /// Maximum pool size (default: 32)
        #[serde(default = "default_pool_size")]
        pool_max_size: usize,
    },

    /// Get connection pool statistics for a SOCKS5 outbound
    ///
    /// Returns pool statistics including current size, available connections,
    /// and number of waiters.
    GetPoolStats {
        /// Outbound tag (if None, returns stats for all SOCKS5 outbounds)
        #[serde(default)]
        tag: Option<String>,
    },

    // ========================================================================
    // Phase 3.3: IPC Protocol v2.1 Commands
    // ========================================================================

    /// Add a WireGuard outbound using DirectOutbound with bind_interface
    ///
    /// Creates a direct outbound bound to a WireGuard interface (e.g., wg-pia-us-east).
    /// The interface must already exist (created by Python setup_kernel_wg_egress.py).
    AddWireguardOutbound {
        /// Unique tag for this outbound
        tag: String,
        /// WireGuard interface name (e.g., "wg-pia-us-east")
        interface: String,
        /// Optional routing mark for policy routing
        #[serde(default)]
        routing_mark: Option<u32>,
        /// Optional routing table for policy routing
        #[serde(default)]
        routing_table: Option<u32>,
    },

    /// Drain an outbound gracefully before removal
    ///
    /// Waits for existing connections to complete (up to timeout),
    /// then removes the outbound. New connections are rejected during drain.
    DrainOutbound {
        /// Outbound tag to drain
        tag: String,
        /// Timeout in seconds (connections are forcefully closed after this)
        #[serde(default = "default_drain_timeout")]
        timeout_secs: u32,
    },

    /// Update routing rules atomically
    ///
    /// Replaces the current routing configuration with new rules.
    /// Uses ArcSwap for lock-free hot-reload.
    UpdateRouting {
        /// New routing rules
        rules: Vec<RuleConfig>,
        /// Default outbound for unmatched traffic
        default_outbound: String,
    },

    /// Set the default outbound for unmatched traffic
    ///
    /// Changes only the default outbound without modifying rules.
    SetDefaultOutbound {
        /// New default outbound tag
        tag: String,
    },

    /// Get health status for all outbounds
    ///
    /// Returns a map of outbound tags to their current health status.
    GetOutboundHealth,

    /// Notify about egress configuration change from Python
    ///
    /// Python sends this when egress is added/removed/updated so rust-router
    /// can update its state accordingly.
    NotifyEgressChange {
        /// Action type: added, removed, updated
        action: EgressAction,
        /// Outbound tag affected
        tag: String,
        /// Egress type (pia, custom, warp, v2ray, direct, openvpn)
        egress_type: String,
    },
}

/// Default connect timeout for SOCKS5 connections
fn default_connect_timeout() -> u64 {
    10
}

/// Default idle timeout for SOCKS5 connections
fn default_idle_timeout() -> u64 {
    300
}

/// Default pool size for SOCKS5 connections
fn default_pool_size() -> usize {
    32
}

/// Default drain timeout in seconds
fn default_drain_timeout() -> u32 {
    30
}

/// Egress action type for NotifyEgressChange
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EgressAction {
    /// Egress was added
    Added,
    /// Egress was removed
    Removed,
    /// Egress was updated (config changed)
    Updated,
}

/// Rule configuration for UpdateRouting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleConfig {
    /// Rule type (domain, domain_suffix, domain_keyword, geoip, port, protocol)
    pub rule_type: String,
    /// Target value (e.g., "google.com", "CN", "443", "tcp")
    pub target: String,
    /// Outbound tag to route to
    pub outbound: String,
    /// Rule priority (lower = higher priority)
    #[serde(default)]
    pub priority: i32,
    /// Whether the rule is enabled
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_enabled() -> bool {
    true
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
    OutboundList {
        /// List of outbound information
        outbounds: Vec<OutboundInfo>,
    },

    /// Test match result
    TestMatchResult(TestMatchResult),

    /// Rule engine statistics response
    RuleStats(RuleStatsResponse),

    /// Connection pool statistics response
    PoolStats(PoolStatsResponse),

    // ========================================================================
    // Phase 3.3: IPC Protocol v2.1 Response Types
    // ========================================================================

    /// Outbound health status response
    OutboundHealth(OutboundHealthResponse),

    /// Update routing result
    UpdateRoutingResult(UpdateRoutingResponse),

    /// Drain outbound result
    DrainResult(DrainResponse),

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
            outbound_types: vec![
                "direct".into(),
                "block".into(),
                "socks5".into(),
                "wireguard".into(), // Phase 3.3: WireGuard via DirectOutbound
            ],
            hot_reload: true,
            tls_sniffing: true,
            udp_support: false, // Phase 1: TCP only
            max_connections: 65536,
            protocol_version: 3, // Phase 3.3: IPC v2.1 with drain, health, routing updates
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

/// Result of a test match operation
///
/// Used for debugging and parity testing to verify the rule engine
/// produces the same results as the reference implementation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestMatchResult {
    /// The matched outbound tag
    pub outbound: String,
    /// The type of match that occurred (domain, geoip, port, protocol, or null for default)
    pub match_type: Option<String>,
    /// The routing mark to apply (if any)
    pub routing_mark: Option<u32>,
    /// Whether the outbound is a chain
    pub is_chain: bool,
    /// Time taken for matching in microseconds
    pub match_time_us: u64,
}

/// Rule engine statistics response
///
/// Contains statistics about the current routing configuration,
/// including counts of different rule types and configuration version.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleStatsResponse {
    /// Number of domain rules (exact, suffix, keyword, regex)
    pub domain_rules: u64,
    /// Number of GeoIP/CIDR rules
    pub geoip_rules: u64,
    /// Number of port rules
    pub port_rules: u64,
    /// Number of protocol rules
    pub protocol_rules: u64,
    /// Number of registered chains for multi-hop routing
    pub chain_count: u64,
    /// Configuration version (incremented on each reload)
    pub config_version: u64,
    /// ISO 8601 timestamp of last configuration reload (or None if never reloaded)
    pub last_reload: Option<String>,
    /// Default outbound tag
    pub default_outbound: String,
}

/// Connection pool statistics for a single SOCKS5 outbound
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Socks5PoolStats {
    /// Outbound tag
    pub tag: String,
    /// Current pool size (all connections)
    pub size: usize,
    /// Available connections in pool
    pub available: usize,
    /// Number of waiters for connections
    pub waiting: usize,
    /// Server address
    pub server_addr: String,
    /// Whether the outbound is enabled
    pub enabled: bool,
    /// Health status
    pub health: String,
}

/// Connection pool statistics response
///
/// Contains pool statistics for one or more SOCKS5 outbounds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolStatsResponse {
    /// Pool statistics per outbound
    pub pools: Vec<Socks5PoolStats>,
}

// ============================================================================
// Phase 3.3: IPC Protocol v2.1 Response Structs
// ============================================================================

/// Health status for a single outbound
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundHealthInfo {
    /// Outbound tag
    pub tag: String,
    /// Outbound type (direct, socks5, block)
    pub outbound_type: String,
    /// Health status (healthy, degraded, unhealthy, unknown)
    pub health: String,
    /// Whether the outbound is enabled
    pub enabled: bool,
    /// Active connection count
    pub active_connections: u64,
    /// Last health check time (ISO 8601)
    pub last_check: Option<String>,
    /// Error message if unhealthy
    pub error: Option<String>,
}

/// Response for GetOutboundHealth command
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundHealthResponse {
    /// Health status for each outbound
    pub outbounds: Vec<OutboundHealthInfo>,
    /// Overall system health (all healthy = healthy)
    pub overall_health: String,
}

/// Response for UpdateRouting command
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateRoutingResponse {
    /// Whether the update was successful
    pub success: bool,
    /// New configuration version
    pub version: u64,
    /// Number of rules applied
    pub rule_count: usize,
    /// New default outbound
    pub default_outbound: String,
}

/// Response for DrainOutbound command
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DrainResponse {
    /// Whether drain completed successfully
    pub success: bool,
    /// Number of connections that were drained
    pub drained_count: u64,
    /// Number of connections that were forcefully closed
    pub force_closed_count: u64,
    /// Time taken to drain in milliseconds
    pub drain_time_ms: u64,
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

    #[test]
    fn test_test_match_command_serialization() {
        let cmd = IpcCommand::TestMatch {
            domain: Some("google.com".into()),
            dest_ip: Some("8.8.8.8".into()),
            dest_port: 443,
            protocol: "tcp".into(),
            sniffed_protocol: Some("tls".into()),
        };
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("\"type\":\"test_match\""));
        assert!(json.contains("google.com"));
        assert!(json.contains("8.8.8.8"));
        assert!(json.contains("443"));
        assert!(json.contains("tcp"));
        assert!(json.contains("tls"));

        // Deserialize back
        let parsed: IpcCommand = serde_json::from_str(&json).unwrap();
        match parsed {
            IpcCommand::TestMatch { domain, dest_ip, dest_port, protocol, sniffed_protocol } => {
                assert_eq!(domain, Some("google.com".into()));
                assert_eq!(dest_ip, Some("8.8.8.8".into()));
                assert_eq!(dest_port, 443);
                assert_eq!(protocol, "tcp");
                assert_eq!(sniffed_protocol, Some("tls".into()));
            }
            _ => panic!("Expected TestMatch command"),
        }
    }

    #[test]
    fn test_test_match_result_serialization() {
        let result = TestMatchResult {
            outbound: "proxy".into(),
            match_type: Some("domain".into()),
            routing_mark: Some(773),
            is_chain: true,
            match_time_us: 42,
        };
        let resp = IpcResponse::TestMatchResult(result);
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"type\":\"test_match_result\""));
        assert!(json.contains("\"outbound\":\"proxy\""));
        assert!(json.contains("\"match_type\":\"domain\""));
        assert!(json.contains("\"routing_mark\":773"));
        assert!(json.contains("\"is_chain\":true"));
    }

    #[test]
    fn test_get_rule_stats_command_serialization() {
        let cmd = IpcCommand::GetRuleStats;
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("\"type\":\"get_rule_stats\""));

        // Deserialize back
        let parsed: IpcCommand = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, IpcCommand::GetRuleStats));
    }

    #[test]
    fn test_reload_rules_command_serialization() {
        // With config path
        let cmd = IpcCommand::ReloadRules {
            config_path: Some("/etc/rust-router/rules.json".into()),
        };
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("\"type\":\"reload_rules\""));
        assert!(json.contains("config_path"));

        // Without config path
        let cmd = IpcCommand::ReloadRules { config_path: None };
        let json = serde_json::to_string(&cmd).unwrap();
        let parsed: IpcCommand = serde_json::from_str(&json).unwrap();
        match parsed {
            IpcCommand::ReloadRules { config_path } => {
                assert!(config_path.is_none());
            }
            _ => panic!("Expected ReloadRules command"),
        }
    }

    #[test]
    fn test_rule_stats_response_serialization() {
        let stats = RuleStatsResponse {
            domain_rules: 1000,
            geoip_rules: 250,
            port_rules: 15,
            protocol_rules: 2,
            chain_count: 5,
            config_version: 42,
            last_reload: Some("2026-01-05T12:00:00Z".into()),
            default_outbound: "direct".into(),
        };
        let resp = IpcResponse::RuleStats(stats);
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"type\":\"rule_stats\""));
        assert!(json.contains("\"domain_rules\":1000"));
        assert!(json.contains("\"geoip_rules\":250"));
        assert!(json.contains("\"chain_count\":5"));
        assert!(json.contains("\"config_version\":42"));
        assert!(json.contains("\"default_outbound\":\"direct\""));

        // Deserialize back
        let parsed: IpcResponse = serde_json::from_str(&json).unwrap();
        if let IpcResponse::RuleStats(s) = parsed {
            assert_eq!(s.domain_rules, 1000);
            assert_eq!(s.config_version, 42);
        } else {
            panic!("Expected RuleStats response");
        }
    }

    // =========================================================================
    // P0 Serialization Tests - Phase 3.3 IPC Protocol v2.1
    // =========================================================================

    #[test]
    fn test_egress_action_serialization() {
        // Test Added variant
        let action = EgressAction::Added;
        let json = serde_json::to_string(&action).unwrap();
        assert_eq!(json, "\"added\"");
        let parsed: EgressAction = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, EgressAction::Added);

        // Test Removed variant
        let action = EgressAction::Removed;
        let json = serde_json::to_string(&action).unwrap();
        assert_eq!(json, "\"removed\"");
        let parsed: EgressAction = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, EgressAction::Removed);

        // Test Updated variant
        let action = EgressAction::Updated;
        let json = serde_json::to_string(&action).unwrap();
        assert_eq!(json, "\"updated\"");
        let parsed: EgressAction = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, EgressAction::Updated);
    }

    #[test]
    fn test_rule_config_serialization() {
        // Test with all fields
        let rule = RuleConfig {
            rule_type: "domain_suffix".into(),
            target: "google.com".into(),
            outbound: "proxy".into(),
            priority: 10,
            enabled: true,
        };
        let json = serde_json::to_string(&rule).unwrap();
        assert!(json.contains("\"rule_type\":\"domain_suffix\""));
        assert!(json.contains("\"target\":\"google.com\""));
        assert!(json.contains("\"outbound\":\"proxy\""));
        assert!(json.contains("\"priority\":10"));
        assert!(json.contains("\"enabled\":true"));

        // Deserialize back
        let parsed: RuleConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.rule_type, "domain_suffix");
        assert_eq!(parsed.target, "google.com");
        assert_eq!(parsed.outbound, "proxy");
        assert_eq!(parsed.priority, 10);
        assert!(parsed.enabled);

        // Test default values
        let json_minimal = r#"{"rule_type":"geoip","target":"CN","outbound":"cn-proxy"}"#;
        let parsed: RuleConfig = serde_json::from_str(json_minimal).unwrap();
        assert_eq!(parsed.priority, 0); // default
        assert!(parsed.enabled); // default_enabled()
    }

    #[test]
    fn test_drain_response_serialization() {
        let resp = DrainResponse {
            success: true,
            drained_count: 15,
            force_closed_count: 2,
            drain_time_ms: 1500,
        };
        let ipc_resp = IpcResponse::DrainResult(resp);
        let json = serde_json::to_string(&ipc_resp).unwrap();
        assert!(json.contains("\"type\":\"drain_result\""));
        assert!(json.contains("\"success\":true"));
        assert!(json.contains("\"drained_count\":15"));
        assert!(json.contains("\"force_closed_count\":2"));
        assert!(json.contains("\"drain_time_ms\":1500"));

        // Deserialize back
        let parsed: IpcResponse = serde_json::from_str(&json).unwrap();
        if let IpcResponse::DrainResult(dr) = parsed {
            assert!(dr.success);
            assert_eq!(dr.drained_count, 15);
            assert_eq!(dr.force_closed_count, 2);
            assert_eq!(dr.drain_time_ms, 1500);
        } else {
            panic!("Expected DrainResult response");
        }
    }

    #[test]
    fn test_update_routing_response_serialization() {
        let resp = UpdateRoutingResponse {
            success: true,
            version: 42,
            rule_count: 100,
            default_outbound: "direct".into(),
        };
        let ipc_resp = IpcResponse::UpdateRoutingResult(resp);
        let json = serde_json::to_string(&ipc_resp).unwrap();
        assert!(json.contains("\"type\":\"update_routing_result\""));
        assert!(json.contains("\"success\":true"));
        assert!(json.contains("\"version\":42"));
        assert!(json.contains("\"rule_count\":100"));
        assert!(json.contains("\"default_outbound\":\"direct\""));

        // Deserialize back
        let parsed: IpcResponse = serde_json::from_str(&json).unwrap();
        if let IpcResponse::UpdateRoutingResult(ur) = parsed {
            assert!(ur.success);
            assert_eq!(ur.version, 42);
            assert_eq!(ur.rule_count, 100);
            assert_eq!(ur.default_outbound, "direct");
        } else {
            panic!("Expected UpdateRoutingResult response");
        }
    }

    #[test]
    fn test_outbound_health_response_serialization() {
        let health = OutboundHealthResponse {
            outbounds: vec![
                OutboundHealthInfo {
                    tag: "direct".into(),
                    outbound_type: "direct".into(),
                    health: "healthy".into(),
                    enabled: true,
                    active_connections: 10,
                    last_check: Some("2026-01-06T12:00:00Z".into()),
                    error: None,
                },
                OutboundHealthInfo {
                    tag: "proxy".into(),
                    outbound_type: "socks5".into(),
                    health: "degraded".into(),
                    enabled: true,
                    active_connections: 5,
                    last_check: Some("2026-01-06T12:00:00Z".into()),
                    error: Some("Connection timeout".into()),
                },
            ],
            overall_health: "degraded".into(),
        };
        let ipc_resp = IpcResponse::OutboundHealth(health);
        let json = serde_json::to_string(&ipc_resp).unwrap();
        assert!(json.contains("\"type\":\"outbound_health\""));
        assert!(json.contains("\"overall_health\":\"degraded\""));
        assert!(json.contains("\"tag\":\"direct\""));
        assert!(json.contains("\"tag\":\"proxy\""));

        // Deserialize back
        let parsed: IpcResponse = serde_json::from_str(&json).unwrap();
        if let IpcResponse::OutboundHealth(oh) = parsed {
            assert_eq!(oh.outbounds.len(), 2);
            assert_eq!(oh.overall_health, "degraded");
            assert_eq!(oh.outbounds[0].tag, "direct");
            assert_eq!(oh.outbounds[1].error, Some("Connection timeout".into()));
        } else {
            panic!("Expected OutboundHealth response");
        }
    }
}
