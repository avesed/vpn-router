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

    /// Get Prometheus-formatted metrics
    ///
    /// Returns all metrics in Prometheus text exposition format for scraping.
    GetPrometheusMetrics,

    // ========================================================================
    // Phase 5.5: UDP IPC Commands
    // ========================================================================

    /// Get UDP statistics (sessions, packets, worker pool stats).
    ///
    /// Returns comprehensive UDP statistics including session manager stats,
    /// worker pool stats, and buffer pool stats.
    GetUdpStats,

    /// List active UDP sessions.
    ///
    /// Returns snapshots of active UDP sessions with optional limit.
    ListUdpSessions {
        /// Maximum number of sessions to return (default: 100)
        #[serde(default = "default_udp_session_limit")]
        limit: usize,
    },

    /// Get a specific UDP session by client and destination address.
    ///
    /// Returns detailed information about a single UDP session.
    GetUdpSession {
        /// Client address (e.g., "192.168.1.100:12345")
        client_addr: String,
        /// Destination address (e.g., "8.8.8.8:443")
        dest_addr: String,
    },

    /// Get UDP worker pool statistics.
    ///
    /// Returns statistics about the UDP worker pool including active workers,
    /// packets processed, and bytes received.
    GetUdpWorkerStats,

    /// Get UDP buffer pool statistics.
    ///
    /// Returns statistics about the lock-free UDP buffer pool including
    /// allocations, reuses, returns, and drops.
    GetBufferPoolStats,

    // ========================================================================
    // Phase 6.0: IPC Protocol v3.0 - WireGuard Tunnel Management
    // ========================================================================

    /// Create a userspace WireGuard tunnel
    ///
    /// Creates a new WireGuard tunnel using boringtun (Phase 6).
    CreateWgTunnel {
        /// Unique tag for this tunnel
        tag: String,
        /// WireGuard tunnel configuration
        config: WgTunnelConfig,
    },

    /// Remove a WireGuard tunnel
    ///
    /// Removes a userspace WireGuard tunnel with optional drain timeout.
    RemoveWgTunnel {
        /// Tunnel tag to remove
        tag: String,
        /// Optional drain timeout in seconds (default: 30)
        #[serde(default)]
        drain_timeout_secs: Option<u32>,
    },

    /// Get WireGuard tunnel status
    ///
    /// Returns status information for a specific WireGuard tunnel.
    GetWgTunnelStatus {
        /// Tunnel tag
        tag: String,
    },

    /// List all WireGuard tunnels
    ///
    /// Returns a list of all userspace WireGuard tunnels.
    ListWgTunnels,

    // ========================================================================
    // Phase 6.0: IPC Protocol v3.0 - ECMP Group Management
    // ========================================================================

    /// Create an ECMP (Equal-Cost Multi-Path) load balancing group
    ///
    /// Creates a new ECMP group for distributing traffic across multiple outbounds.
    CreateEcmpGroup {
        /// Unique tag for this group
        tag: String,
        /// ECMP group configuration
        config: EcmpGroupConfig,
    },

    /// Remove an ECMP group
    ///
    /// Removes an ECMP load balancing group.
    RemoveEcmpGroup {
        /// Group tag to remove
        tag: String,
    },

    /// Get ECMP group status
    ///
    /// Returns status information for a specific ECMP group.
    GetEcmpGroupStatus {
        /// Group tag
        tag: String,
    },

    /// List all ECMP groups
    ///
    /// Returns a list of all ECMP load balancing groups.
    ListEcmpGroups,

    /// Update ECMP group members
    ///
    /// Replaces the members of an existing ECMP group.
    UpdateEcmpGroupMembers {
        /// Group tag to update
        tag: String,
        /// New members list
        members: Vec<EcmpMemberConfig>,
    },

    // ========================================================================
    // Phase 6.0: IPC Protocol v3.2 - Peer Management
    // ========================================================================

    /// Generate offline pairing request code
    ///
    /// Generates a Base64-encoded pairing request for offline node pairing.
    /// Supports bidirectional pairing with pre-generated remote keys.
    GeneratePairRequest {
        /// Local node tag
        local_tag: String,
        /// Local node description
        local_description: String,
        /// Local endpoint (IP:port or hostname:port)
        local_endpoint: String,
        /// Local Web API port (default: 36000)
        local_api_port: u16,
        /// Whether to enable bidirectional auto-connect
        bidirectional: bool,
        /// Tunnel type (WireGuard or Xray)
        tunnel_type: TunnelType,
    },

    /// Import pairing request from another node
    ///
    /// Imports and processes a pairing request code from another node.
    /// Returns a response code to complete the handshake.
    ImportPairRequest {
        /// Base64-encoded pairing request code
        code: String,
        /// Local node tag
        local_tag: String,
        /// Local node description
        local_description: String,
        /// Local endpoint (IP:port or hostname:port)
        local_endpoint: String,
        /// Local Web API port (default: 36000)
        local_api_port: u16,
    },

    /// Complete the pairing handshake
    ///
    /// Completes the pairing process with the response code.
    CompleteHandshake {
        /// Base64-encoded pairing response code
        code: String,
    },

    /// Connect to a configured peer node
    ///
    /// Initiates connection to a previously configured peer.
    ConnectPeer {
        /// Peer node tag
        tag: String,
    },

    /// Disconnect from a peer node
    ///
    /// Disconnects from a connected peer.
    DisconnectPeer {
        /// Peer node tag
        tag: String,
    },

    /// Get peer node status
    ///
    /// Returns status information for a specific peer.
    GetPeerStatus {
        /// Peer node tag
        tag: String,
    },

    /// Get peer tunnel health status
    ///
    /// Returns health information based on WireGuard handshake for a peer.
    GetPeerTunnelHealth {
        /// Peer node tag
        tag: String,
    },

    /// List all peer nodes
    ///
    /// Returns a list of all configured peer nodes.
    ListPeers,

    /// Remove a peer node configuration
    ///
    /// Removes a peer node and its associated tunnel.
    RemovePeer {
        /// Peer node tag
        tag: String,
    },

    // ========================================================================
    // Phase 6.0: IPC Protocol v3.2 - Chain Management
    // ========================================================================

    /// Create a multi-node routing chain
    ///
    /// Creates a new chain for multi-hop traffic routing with DSCP marking.
    CreateChain {
        /// Unique tag for this chain
        tag: String,
        /// Chain configuration
        config: ChainConfig,
    },

    /// Remove a routing chain
    ///
    /// Removes a chain and cleans up associated routes.
    RemoveChain {
        /// Chain tag to remove
        tag: String,
    },

    /// Activate a routing chain
    ///
    /// Activates a chain using Two-Phase Commit protocol for distributed activation.
    ActivateChain {
        /// Chain tag to activate
        tag: String,
    },

    /// Deactivate a routing chain
    ///
    /// Deactivates a chain and removes its routing rules.
    DeactivateChain {
        /// Chain tag to deactivate
        tag: String,
    },

    /// Get chain status
    ///
    /// Returns status information for a specific chain.
    GetChainStatus {
        /// Chain tag
        tag: String,
    },

    /// List all routing chains
    ///
    /// Returns a list of all configured chains.
    ListChains,

    /// Get local node's role in a chain
    ///
    /// Returns the role (entry/relay/terminal) of the local node in a chain.
    GetChainRole {
        /// Chain tag
        chain_tag: String,
    },

    /// Update chain state in database
    ///
    /// Updates the chain state for persistence and recovery.
    UpdateChainState {
        /// Chain tag
        tag: String,
        /// New chain state
        state: ChainState,
        /// Optional error message
        #[serde(default)]
        last_error: Option<String>,
    },

    /// Update an existing chain configuration
    ///
    /// Updates a chain configuration. Chain must be inactive to update.
    /// Only specified fields are updated; others retain their current values.
    UpdateChain {
        /// Chain tag to update
        tag: String,
        /// New hops (if provided)
        #[serde(default, skip_serializing_if = "Option::is_none")]
        hops: Option<Vec<ChainHop>>,
        /// New exit egress (if provided)
        #[serde(default, skip_serializing_if = "Option::is_none")]
        exit_egress: Option<String>,
        /// New description (if provided)
        #[serde(default, skip_serializing_if = "Option::is_none")]
        description: Option<String>,
        /// New allow_transitive flag (if provided)
        #[serde(default, skip_serializing_if = "Option::is_none")]
        allow_transitive: Option<bool>,
    },

    // ========================================================================
    // Phase 6.0: IPC Protocol v3.2 - Two-Phase Commit Commands
    // ========================================================================

    /// Phase 1: Prepare chain route (validate only, no apply)
    ///
    /// Validates chain configuration on this node without applying rules.
    /// Part of the Two-Phase Commit protocol for distributed chain activation.
    PrepareChainRoute {
        /// Chain tag
        chain_tag: String,
        /// Chain configuration to validate
        config: ChainConfig,
        /// Node that initiated this request
        source_node: String,
    },

    /// Phase 2a: Commit chain route (apply rules)
    ///
    /// Applies chain routing rules after successful PREPARE on all nodes.
    CommitChainRoute {
        /// Chain tag
        chain_tag: String,
        /// Node that initiated this request
        source_node: String,
    },

    /// Phase 2b: Abort chain route (rollback any state)
    ///
    /// Rolls back any prepared state after a PREPARE failure.
    AbortChainRoute {
        /// Chain tag
        chain_tag: String,
        /// Node that initiated this request
        source_node: String,
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

/// Default limit for UDP session listing
fn default_udp_session_limit() -> usize {
    100
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

    /// Prometheus metrics response
    PrometheusMetrics(PrometheusMetricsResponse),

    // ========================================================================
    // Phase 5.5: UDP IPC Response Types
    // ========================================================================

    /// UDP statistics response
    UdpStats(UdpStatsResponse),

    /// UDP sessions list response
    UdpSessions(UdpSessionsResponse),

    /// Single UDP session response
    UdpSession(UdpSessionResponse),

    /// UDP worker pool statistics response
    UdpWorkerStats(UdpWorkerStatsResponse),

    /// UDP buffer pool statistics response
    BufferPoolStats(BufferPoolStatsResponse),

    // ========================================================================
    // Phase 6.0: IPC Protocol v3.2 Response Types
    // ========================================================================

    /// WireGuard tunnel status response
    WgTunnelStatus(WgTunnelStatus),

    /// WireGuard tunnel list response
    WgTunnelList(WgTunnelListResponse),

    /// ECMP group status response
    EcmpGroupStatus(EcmpGroupStatus),

    /// ECMP group list response
    EcmpGroupList(EcmpGroupListResponse),

    /// Peer status response
    PeerStatus(PeerStatus),

    /// Peer list response
    PeerList(PeerListResponse),

    /// Pairing operation response
    Pairing(PairingResponse),

    /// Chain status response
    ChainStatus(ChainStatus),

    /// Chain list response
    ChainList(ChainListResponse),

    /// Chain role response
    ChainRole(ChainRoleResponse),

    /// Two-Phase Commit prepare response
    PrepareResult(PrepareResponse),

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

/// Response for GetPrometheusMetrics command
///
/// Contains metrics in Prometheus text exposition format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrometheusMetricsResponse {
    /// Prometheus text format metrics
    pub metrics_text: String,
    /// Timestamp of metrics collection (Unix epoch milliseconds)
    pub timestamp_ms: u64,
}

// ============================================================================
// Phase 5.5: UDP IPC Response Structs
// ============================================================================

/// Comprehensive UDP statistics response
///
/// Combines session manager stats, worker pool stats, and buffer pool stats.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UdpStatsResponse {
    /// Whether UDP is enabled
    pub udp_enabled: bool,
    /// Session manager statistics
    pub session_stats: UdpSessionStatsInfo,
    /// Worker pool statistics (None if UDP not enabled)
    pub worker_stats: Option<UdpWorkerPoolInfo>,
    /// Buffer pool statistics (None if UDP not enabled)
    pub buffer_pool_stats: Option<BufferPoolInfo>,
    /// Processor statistics (None if UDP not enabled)
    pub processor_stats: Option<UdpProcessorInfo>,
}

/// UDP session manager statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UdpSessionStatsInfo {
    /// Current number of active sessions
    pub session_count: u64,
    /// Maximum allowed sessions
    pub max_sessions: u64,
    /// Total sessions created
    pub total_created: u64,
    /// Total sessions evicted
    pub total_evicted: u64,
    /// Cache utilization percentage
    pub utilization_percent: f64,
    /// Idle timeout in seconds
    pub idle_timeout_secs: u64,
    /// TTL in seconds
    pub ttl_secs: u64,
}

/// UDP worker pool statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UdpWorkerPoolInfo {
    /// Total packets processed
    pub packets_processed: u64,
    /// Total bytes received
    pub bytes_received: u64,
    /// Number of active workers
    pub workers_active: u32,
    /// Total workers spawned
    pub workers_total: u32,
    /// Number of worker errors
    pub worker_errors: u64,
}

/// UDP buffer pool statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BufferPoolInfo {
    /// Pool capacity
    pub capacity: usize,
    /// Buffer size in bytes
    pub buffer_size: usize,
    /// Currently available buffers
    pub available: usize,
    /// Number of new buffer allocations
    pub allocations: u64,
    /// Number of buffer reuses from pool
    pub reuses: u64,
    /// Number of buffers returned to pool
    pub returns: u64,
    /// Number of buffers dropped (pool was full)
    pub drops: u64,
    /// Pool efficiency (reuses / (reuses + allocations))
    pub efficiency: f64,
}

/// UDP packet processor statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UdpProcessorInfo {
    /// Packets processed
    pub packets_processed: u64,
    /// Packets forwarded successfully
    pub packets_forwarded: u64,
    /// Packets that failed processing
    pub packets_failed: u64,
    /// Sessions created
    pub sessions_created: u64,
    /// Sessions reused
    pub sessions_reused: u64,
    /// Total bytes sent
    pub bytes_sent: u64,
    /// QUIC packets detected
    pub quic_packets: u64,
    /// QUIC SNI successfully extracted
    pub quic_sni_extracted: u64,
    /// Rule matches
    pub rule_matches: u64,
    /// Currently active sessions in the processor cache
    pub active_sessions: u64,
}

/// UDP sessions list response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UdpSessionsResponse {
    /// List of session snapshots
    pub sessions: Vec<UdpSessionInfo>,
    /// Total session count (may differ from len if limit applied)
    pub total_count: u64,
    /// Whether the list was truncated due to limit
    pub truncated: bool,
}

/// Individual UDP session information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UdpSessionInfo {
    /// Client address
    pub client_addr: String,
    /// Destination address
    pub dest_addr: String,
    /// Outbound tag
    pub outbound: String,
    /// Routing mark (for chain routing / DSCP)
    pub routing_mark: Option<u32>,
    /// Sniffed domain (from QUIC SNI)
    pub sniffed_domain: Option<String>,
    /// Bytes sent (client -> upstream)
    pub bytes_sent: u64,
    /// Bytes received (upstream -> client)
    pub bytes_recv: u64,
    /// Packets sent
    pub packets_sent: u64,
    /// Packets received
    pub packets_recv: u64,
    /// Session age in seconds
    pub age_secs: u64,
}

/// Single UDP session response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UdpSessionResponse {
    /// Whether the session was found
    pub found: bool,
    /// Session information (None if not found)
    pub session: Option<UdpSessionInfo>,
}

/// UDP worker pool statistics response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UdpWorkerStatsResponse {
    /// Whether UDP workers are running
    pub running: bool,
    /// Number of workers
    pub num_workers: usize,
    /// Worker pool statistics
    pub stats: Option<UdpWorkerPoolInfo>,
}

/// UDP buffer pool statistics response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BufferPoolStatsResponse {
    /// Whether buffer pool is available
    pub available: bool,
    /// Buffer pool statistics
    pub stats: Option<BufferPoolInfo>,
}

// ============================================================================
// Phase 6.0: IPC Protocol v3.2 Types
// ============================================================================

/// Tunnel type for peer connections
///
/// Defines the type of tunnel used for peer-to-peer connections.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TunnelType {
    /// WireGuard tunnel (userspace via boringtun)
    WireGuard,
    /// Xray tunnel (via SOCKS5 bridge)
    Xray,
}

impl Default for TunnelType {
    fn default() -> Self {
        Self::WireGuard
    }
}

impl std::fmt::Display for TunnelType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WireGuard => write!(f, "wireguard"),
            Self::Xray => write!(f, "xray"),
        }
    }
}

/// WireGuard tunnel configuration
///
/// Configuration for creating a userspace WireGuard tunnel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WgTunnelConfig {
    /// WireGuard private key (Base64 encoded)
    pub private_key: String,
    /// Peer public key (Base64 encoded)
    pub peer_public_key: String,
    /// Peer endpoint (IP:port)
    pub peer_endpoint: String,
    /// Allowed IPs for this tunnel
    #[serde(default)]
    pub allowed_ips: Vec<String>,
    /// Local tunnel IP (e.g., "10.200.200.1/32")
    #[serde(default)]
    pub local_ip: Option<String>,
    /// Listen port for incoming connections
    #[serde(default)]
    pub listen_port: Option<u16>,
    /// Persistent keepalive interval in seconds
    #[serde(default)]
    pub persistent_keepalive: Option<u16>,
    /// MTU for the tunnel
    #[serde(default)]
    pub mtu: Option<u16>,
}

/// WireGuard tunnel status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WgTunnelStatus {
    /// Tunnel tag
    pub tag: String,
    /// Whether the tunnel is active
    pub active: bool,
    /// Local tunnel IP
    pub local_ip: Option<String>,
    /// Peer endpoint
    pub peer_endpoint: String,
    /// Last handshake timestamp (Unix epoch seconds)
    pub last_handshake: Option<u64>,
    /// Bytes transmitted
    pub tx_bytes: u64,
    /// Bytes received
    pub rx_bytes: u64,
    /// Active connections using this tunnel
    pub active_connections: u64,
    /// Error message if any
    pub error: Option<String>,
}

/// ECMP (Equal-Cost Multi-Path) load balancing algorithm
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EcmpAlgorithm {
    /// Round-robin distribution
    RoundRobin,
    /// Random selection
    Random,
    /// Hash-based (consistent hashing by source IP)
    SourceHash,
    /// Weighted random selection
    Weighted,
    /// Least connections
    LeastConnections,
}

impl Default for EcmpAlgorithm {
    fn default() -> Self {
        Self::RoundRobin
    }
}

/// ECMP group member configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EcmpMemberConfig {
    /// Outbound tag
    pub outbound: String,
    /// Weight for weighted algorithms (default: 1)
    #[serde(default = "default_ecmp_weight")]
    pub weight: u32,
    /// Whether this member is enabled
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_ecmp_weight() -> u32 {
    1
}

/// ECMP group configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EcmpGroupConfig {
    /// Group description (optional)
    #[serde(default)]
    pub description: String,
    /// Load balancing algorithm
    #[serde(default)]
    pub algorithm: EcmpAlgorithm,
    /// Group members (outbounds)
    pub members: Vec<EcmpMemberConfig>,
    /// Whether to skip unhealthy members
    #[serde(default = "default_enabled")]
    pub skip_unhealthy: bool,
    /// Health check interval in seconds
    #[serde(default = "default_health_interval")]
    pub health_check_interval_secs: u32,
    /// Routing mark for Linux policy routing (200-299)
    #[serde(default)]
    pub routing_mark: Option<u32>,
    /// Routing table for policy routing
    #[serde(default)]
    pub routing_table: Option<u32>,
}

fn default_health_interval() -> u32 {
    30
}

/// ECMP group status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EcmpGroupStatus {
    /// Group tag
    pub tag: String,
    /// Load balancing algorithm
    pub algorithm: EcmpAlgorithm,
    /// Member status
    pub members: Vec<EcmpMemberStatus>,
    /// Total active connections
    pub active_connections: u64,
    /// Total connections handled
    pub total_connections: u64,
}

/// ECMP member status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EcmpMemberStatus {
    /// Outbound tag
    pub outbound: String,
    /// Weight
    pub weight: u32,
    /// Whether enabled
    pub enabled: bool,
    /// Health status
    pub health: String,
    /// Active connections
    pub active_connections: u64,
    /// Total connections
    pub total_connections: u64,
}

// ============================================================================
// Phase 6.0: Peer Management Types
// ============================================================================

/// Peer node configuration
///
/// Configuration for a peer node in a multi-node setup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerConfig {
    /// Unique peer tag
    pub tag: String,
    /// Human-readable description
    pub description: String,
    /// Peer endpoint (IP:port or hostname:port)
    pub endpoint: String,
    /// Tunnel type (WireGuard or Xray)
    pub tunnel_type: TunnelType,
    /// Web API port on the peer (default: 36000)
    #[serde(default = "default_api_port")]
    pub api_port: u16,

    // WireGuard-specific fields
    /// Peer's WireGuard public key
    #[serde(default)]
    pub wg_public_key: Option<String>,
    /// Local WireGuard private key for this peer
    #[serde(default)]
    pub wg_local_private_key: Option<String>,
    /// Local tunnel IP
    #[serde(default)]
    pub tunnel_local_ip: Option<String>,
    /// Remote tunnel IP
    #[serde(default)]
    pub tunnel_remote_ip: Option<String>,
    /// Tunnel port
    #[serde(default)]
    pub tunnel_port: Option<u16>,
    /// Persistent keepalive interval
    #[serde(default)]
    pub persistent_keepalive: Option<u16>,

    // Xray-specific fields
    /// Xray user UUID
    #[serde(default)]
    pub xray_uuid: Option<String>,
    /// Xray server name for TLS
    #[serde(default)]
    pub xray_server_name: Option<String>,
    /// Xray public key for REALITY
    #[serde(default)]
    pub xray_public_key: Option<String>,
    /// Xray short ID
    #[serde(default)]
    pub xray_short_id: Option<String>,
    /// Local SOCKS5 port for Xray
    #[serde(default)]
    pub xray_local_socks_port: Option<u16>,
}

fn default_api_port() -> u16 {
    36000
}

/// Peer connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerState {
    /// Not connected
    Disconnected,
    /// Connection in progress
    Connecting,
    /// Successfully connected
    Connected,
    /// Connection failed
    Failed,
}

impl Default for PeerState {
    fn default() -> Self {
        Self::Disconnected
    }
}

impl std::fmt::Display for PeerState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Disconnected => write!(f, "disconnected"),
            Self::Connecting => write!(f, "connecting"),
            Self::Connected => write!(f, "connected"),
            Self::Failed => write!(f, "failed"),
        }
    }
}

/// Peer node status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerStatus {
    /// Peer tag
    pub tag: String,
    /// Current connection state
    pub state: PeerState,
    /// Tunnel type
    pub tunnel_type: TunnelType,
    /// Local tunnel IP
    pub tunnel_local_ip: Option<String>,
    /// Remote tunnel IP
    pub tunnel_remote_ip: Option<String>,
    /// Web API port
    pub api_port: u16,
    /// Last WireGuard handshake (Unix epoch seconds)
    pub last_handshake: Option<u64>,
    /// Bytes transmitted
    pub tx_bytes: u64,
    /// Bytes received
    pub rx_bytes: u64,
    /// Number of reconnection attempts
    pub reconnect_attempts: u32,
    /// Consecutive health check failures (for hysteresis)
    pub consecutive_failures: u32,
    /// Last error message
    pub last_error: Option<String>,
}

// ============================================================================
// Phase 6.0: Chain Management Types
// ============================================================================

/// Chain node role
///
/// Defines the role of a node in a multi-hop chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChainRole {
    /// Entry node: Receives traffic and marks with DSCP
    Entry,
    /// Relay node: Forwards traffic based on DSCP
    Relay,
    /// Terminal node: Final destination, removes DSCP and exits
    Terminal,
}

impl std::fmt::Display for ChainRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Entry => write!(f, "entry"),
            Self::Relay => write!(f, "relay"),
            Self::Terminal => write!(f, "terminal"),
        }
    }
}

/// Chain activation state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChainState {
    /// Chain is not active
    Inactive,
    /// Chain activation is in progress (2PC)
    Activating,
    /// Chain is active and routing traffic
    Active,
    /// Chain is in error state
    Error,
}

impl Default for ChainState {
    fn default() -> Self {
        Self::Inactive
    }
}

impl std::fmt::Display for ChainState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Inactive => write!(f, "inactive"),
            Self::Activating => write!(f, "activating"),
            Self::Active => write!(f, "active"),
            Self::Error => write!(f, "error"),
        }
    }
}

/// Chain hop configuration
///
/// Configuration for a single hop in a multi-hop chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainHop {
    /// Node tag (must be a configured peer or local node)
    pub node_tag: String,
    /// Role of this node in the chain
    pub role: ChainRole,
    /// Tunnel type to use for this hop
    pub tunnel_type: TunnelType,
}

/// Chain configuration
///
/// Configuration for a multi-node routing chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainConfig {
    /// Unique chain tag
    pub tag: String,
    /// Human-readable description
    pub description: String,
    /// DSCP value for marking (1-63)
    pub dscp_value: u8,
    /// Ordered list of hops in the chain
    pub hops: Vec<ChainHop>,
    /// Routing rules that use this chain
    #[serde(default)]
    pub rules: Vec<String>,
    /// Exit egress on the terminal node
    pub exit_egress: String,
    /// Allow transitive routing (skip remote egress validation)
    #[serde(default)]
    pub allow_transitive: bool,
}

/// Two-Phase Commit prepare status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrepareStatus {
    /// Not yet prepared
    Pending,
    /// Successfully prepared (validated)
    Prepared,
    /// Successfully committed (rules applied)
    Committed,
    /// Aborted (rolled back)
    Aborted,
}

impl Default for PrepareStatus {
    fn default() -> Self {
        Self::Pending
    }
}

/// Hop status in a chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HopStatus {
    /// Node tag
    pub node_tag: String,
    /// Node role
    pub role: ChainRole,
    /// Tunnel type
    pub tunnel_type: TunnelType,
    /// Whether the peer is connected
    pub peer_connected: bool,
    /// Two-Phase Commit status
    #[serde(default)]
    pub prepare_status: Option<PrepareStatus>,
}

/// Chain status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainStatus {
    /// Chain tag
    pub tag: String,
    /// Current chain state
    pub state: ChainState,
    /// DSCP value
    pub dscp_value: u8,
    /// Local node's role (None if not in chain)
    pub my_role: Option<ChainRole>,
    /// Status of each hop
    pub hop_status: Vec<HopStatus>,
    /// Active connections using this chain
    pub active_connections: u64,
    /// Last error message
    pub last_error: Option<String>,
}

// ============================================================================
// Phase 6.0: Pairing Types
// ============================================================================

/// Offline pairing request
///
/// Contains all information needed for offline node pairing.
/// Encoded as Base64 JSON for exchange via QR code or text.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairRequest {
    /// Protocol version (2 for v3.2)
    pub version: u8,
    /// Node tag
    pub node_tag: String,
    /// Node description
    pub node_description: String,
    /// Endpoint (IP:port with tunnel port)
    pub endpoint: String,
    /// Web API port
    pub api_port: u16,
    /// Tunnel type
    pub tunnel_type: TunnelType,
    /// Creation timestamp (Unix epoch seconds)
    pub timestamp: u64,
    /// Whether bidirectional auto-connect is requested
    pub bidirectional: bool,

    // WireGuard fields
    /// Local WireGuard public key
    #[serde(default)]
    pub wg_public_key: Option<String>,
    /// Tunnel IP assigned to this node
    #[serde(default)]
    pub tunnel_ip: Option<String>,

    // Bidirectional: Pre-generated keys for remote node
    /// Pre-generated remote WireGuard private key (for bidirectional)
    #[serde(default)]
    pub remote_wg_private_key: Option<String>,
    /// Pre-generated remote WireGuard public key (for bidirectional)
    #[serde(default)]
    pub remote_wg_public_key: Option<String>,

    // Xray fields
    /// Xray user UUID
    #[serde(default)]
    pub xray_uuid: Option<String>,
    /// Xray server name
    #[serde(default)]
    pub xray_server_name: Option<String>,
    /// Xray public key
    #[serde(default)]
    pub xray_public_key: Option<String>,
    /// Xray short ID
    #[serde(default)]
    pub xray_short_id: Option<String>,
}

/// Offline pairing response
///
/// Response to a pairing request, completing the handshake.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairResponse {
    /// Protocol version
    pub version: u8,
    /// Original request node tag
    pub request_node_tag: String,
    /// Responding node tag
    pub node_tag: String,
    /// Responding node description
    pub node_description: String,
    /// Responding node endpoint
    pub endpoint: String,
    /// Web API port
    pub api_port: u16,
    /// Tunnel type
    pub tunnel_type: TunnelType,
    /// Response timestamp
    pub timestamp: u64,

    // WireGuard fields
    /// Responding node's WireGuard public key
    #[serde(default)]
    pub wg_public_key: Option<String>,
    /// Local tunnel IP (assigned to responding node)
    #[serde(default)]
    pub tunnel_local_ip: Option<String>,
    /// Remote tunnel IP (assigned to requesting node)
    #[serde(default)]
    pub tunnel_remote_ip: Option<String>,

    // Tunnel API endpoint for post-tunnel communication
    /// API endpoint accessible via tunnel
    #[serde(default)]
    pub tunnel_api_endpoint: Option<String>,

    // Xray fields
    /// Xray user UUID for authentication
    #[serde(default)]
    pub xray_uuid: Option<String>,
}

// ============================================================================
// Phase 6.0: IPC Response Types
// ============================================================================

/// Response containing a WireGuard tunnel list
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WgTunnelListResponse {
    /// List of tunnel statuses
    pub tunnels: Vec<WgTunnelStatus>,
}

/// Response containing an ECMP group list
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EcmpGroupListResponse {
    /// List of group statuses
    pub groups: Vec<EcmpGroupStatus>,
}

/// Response containing a peer list
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerListResponse {
    /// List of peer statuses
    pub peers: Vec<PeerStatus>,
}

/// Response containing a chain list
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainListResponse {
    /// List of chain statuses
    pub chains: Vec<ChainStatus>,
}

/// Response for pairing operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairingResponse {
    /// Whether the operation succeeded
    pub success: bool,
    /// Base64-encoded code (for generate/import)
    #[serde(default)]
    pub code: Option<String>,
    /// Message
    #[serde(default)]
    pub message: Option<String>,
    /// Peer tag (for import/complete)
    #[serde(default)]
    pub peer_tag: Option<String>,
}

/// Response for chain role query
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainRoleResponse {
    /// Chain tag
    pub chain_tag: String,
    /// Local node's role (None if not in chain)
    pub role: Option<ChainRole>,
    /// Whether this node is in the chain
    pub in_chain: bool,
}

/// Response for Two-Phase Commit prepare
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrepareResponse {
    /// Whether prepare succeeded
    pub success: bool,
    /// Error message if failed
    #[serde(default)]
    pub message: Option<String>,
    /// Node that responded
    pub node: String,
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

    #[test]
    fn test_get_prometheus_metrics_command_serialization() {
        let cmd = IpcCommand::GetPrometheusMetrics;
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("\"type\":\"get_prometheus_metrics\""));

        // Deserialize back
        let parsed: IpcCommand = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, IpcCommand::GetPrometheusMetrics));
    }

    #[test]
    fn test_prometheus_metrics_response_serialization() {
        let metrics_text = r#"# HELP rust_router_connections_total Total connections
# TYPE rust_router_connections_total counter
rust_router_connections_total 12345
"#;
        let resp = PrometheusMetricsResponse {
            metrics_text: metrics_text.to_string(),
            timestamp_ms: 1704499200000,
        };
        let ipc_resp = IpcResponse::PrometheusMetrics(resp);
        let json = serde_json::to_string(&ipc_resp).unwrap();
        assert!(json.contains("\"type\":\"prometheus_metrics\""));
        assert!(json.contains("\"timestamp_ms\":1704499200000"));
        assert!(json.contains("rust_router_connections_total"));

        // Deserialize back
        let parsed: IpcResponse = serde_json::from_str(&json).unwrap();
        if let IpcResponse::PrometheusMetrics(pm) = parsed {
            assert_eq!(pm.timestamp_ms, 1704499200000);
            assert!(pm.metrics_text.contains("rust_router_connections_total"));
        } else {
            panic!("Expected PrometheusMetrics response");
        }
    }

    // =========================================================================
    // Phase 5.5: UDP IPC Protocol Tests
    // =========================================================================

    #[test]
    fn test_get_udp_stats_command_serialization() {
        let cmd = IpcCommand::GetUdpStats;
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("\"type\":\"get_udp_stats\""));

        let parsed: IpcCommand = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, IpcCommand::GetUdpStats));
    }

    #[test]
    fn test_list_udp_sessions_command_serialization() {
        // With explicit limit
        let cmd = IpcCommand::ListUdpSessions { limit: 50 };
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("\"type\":\"list_udp_sessions\""));
        assert!(json.contains("\"limit\":50"));

        let parsed: IpcCommand = serde_json::from_str(&json).unwrap();
        if let IpcCommand::ListUdpSessions { limit } = parsed {
            assert_eq!(limit, 50);
        } else {
            panic!("Expected ListUdpSessions command");
        }

        // With default limit
        let json_default = r#"{"type":"list_udp_sessions"}"#;
        let parsed: IpcCommand = serde_json::from_str(json_default).unwrap();
        if let IpcCommand::ListUdpSessions { limit } = parsed {
            assert_eq!(limit, 100); // default_udp_session_limit()
        } else {
            panic!("Expected ListUdpSessions command");
        }
    }

    #[test]
    fn test_get_udp_session_command_serialization() {
        let cmd = IpcCommand::GetUdpSession {
            client_addr: "192.168.1.100:12345".into(),
            dest_addr: "8.8.8.8:443".into(),
        };
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("\"type\":\"get_udp_session\""));
        assert!(json.contains("192.168.1.100:12345"));
        assert!(json.contains("8.8.8.8:443"));

        let parsed: IpcCommand = serde_json::from_str(&json).unwrap();
        if let IpcCommand::GetUdpSession { client_addr, dest_addr } = parsed {
            assert_eq!(client_addr, "192.168.1.100:12345");
            assert_eq!(dest_addr, "8.8.8.8:443");
        } else {
            panic!("Expected GetUdpSession command");
        }
    }

    #[test]
    fn test_get_udp_worker_stats_command_serialization() {
        let cmd = IpcCommand::GetUdpWorkerStats;
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("\"type\":\"get_udp_worker_stats\""));

        let parsed: IpcCommand = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, IpcCommand::GetUdpWorkerStats));
    }

    #[test]
    fn test_get_buffer_pool_stats_command_serialization() {
        let cmd = IpcCommand::GetBufferPoolStats;
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("\"type\":\"get_buffer_pool_stats\""));

        let parsed: IpcCommand = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, IpcCommand::GetBufferPoolStats));
    }

    #[test]
    fn test_udp_stats_response_serialization() {
        let resp = UdpStatsResponse {
            udp_enabled: true,
            session_stats: UdpSessionStatsInfo {
                session_count: 100,
                max_sessions: 65536,
                total_created: 500,
                total_evicted: 400,
                utilization_percent: 0.15,
                idle_timeout_secs: 300,
                ttl_secs: 600,
            },
            worker_stats: Some(UdpWorkerPoolInfo {
                packets_processed: 10000,
                bytes_received: 1_500_000,
                workers_active: 4,
                workers_total: 4,
                worker_errors: 5,
            }),
            buffer_pool_stats: Some(BufferPoolInfo {
                capacity: 1024,
                buffer_size: 65535,
                available: 800,
                allocations: 224,
                reuses: 9776,
                returns: 9800,
                drops: 0,
                efficiency: 0.9776,
            }),
            processor_stats: Some(UdpProcessorInfo {
                packets_processed: 10000,
                packets_forwarded: 9995,
                packets_failed: 5,
                sessions_created: 500,
                sessions_reused: 9500,
                bytes_sent: 1_200_000,
                quic_packets: 8000,
                quic_sni_extracted: 7500,
                rule_matches: 6000,
                active_sessions: 450,
            }),
        };
        let ipc_resp = IpcResponse::UdpStats(resp);
        let json = serde_json::to_string(&ipc_resp).unwrap();
        assert!(json.contains("\"type\":\"udp_stats\""));
        assert!(json.contains("\"udp_enabled\":true"));
        assert!(json.contains("\"session_count\":100"));
        assert!(json.contains("\"packets_processed\":10000"));

        // Deserialize back
        let parsed: IpcResponse = serde_json::from_str(&json).unwrap();
        if let IpcResponse::UdpStats(stats) = parsed {
            assert!(stats.udp_enabled);
            assert_eq!(stats.session_stats.session_count, 100);
            assert!(stats.worker_stats.is_some());
            assert_eq!(stats.worker_stats.as_ref().unwrap().packets_processed, 10000);
        } else {
            panic!("Expected UdpStats response");
        }
    }

    #[test]
    fn test_udp_sessions_response_serialization() {
        let resp = UdpSessionsResponse {
            sessions: vec![
                UdpSessionInfo {
                    client_addr: "192.168.1.100:12345".into(),
                    dest_addr: "8.8.8.8:443".into(),
                    outbound: "direct".into(),
                    routing_mark: None,
                    sniffed_domain: Some("example.com".into()),
                    bytes_sent: 1000,
                    bytes_recv: 5000,
                    packets_sent: 10,
                    packets_recv: 50,
                    age_secs: 30,
                },
            ],
            total_count: 100,
            truncated: true,
        };
        let ipc_resp = IpcResponse::UdpSessions(resp);
        let json = serde_json::to_string(&ipc_resp).unwrap();
        assert!(json.contains("\"type\":\"udp_sessions\""));
        assert!(json.contains("\"total_count\":100"));
        assert!(json.contains("\"truncated\":true"));
        assert!(json.contains("example.com"));

        // Deserialize back
        let parsed: IpcResponse = serde_json::from_str(&json).unwrap();
        if let IpcResponse::UdpSessions(sessions) = parsed {
            assert_eq!(sessions.sessions.len(), 1);
            assert_eq!(sessions.total_count, 100);
            assert!(sessions.truncated);
            assert_eq!(sessions.sessions[0].sniffed_domain, Some("example.com".into()));
        } else {
            panic!("Expected UdpSessions response");
        }
    }

    #[test]
    fn test_udp_session_response_serialization() {
        // Found case
        let resp = UdpSessionResponse {
            found: true,
            session: Some(UdpSessionInfo {
                client_addr: "192.168.1.100:12345".into(),
                dest_addr: "8.8.8.8:443".into(),
                outbound: "proxy".into(),
                routing_mark: Some(200),
                sniffed_domain: None,
                bytes_sent: 500,
                bytes_recv: 2000,
                packets_sent: 5,
                packets_recv: 20,
                age_secs: 15,
            }),
        };
        let ipc_resp = IpcResponse::UdpSession(resp);
        let json = serde_json::to_string(&ipc_resp).unwrap();
        assert!(json.contains("\"type\":\"udp_session\""));
        assert!(json.contains("\"found\":true"));
        assert!(json.contains("\"routing_mark\":200"));

        // Not found case
        let resp_not_found = UdpSessionResponse {
            found: false,
            session: None,
        };
        let ipc_resp_not_found = IpcResponse::UdpSession(resp_not_found);
        let json_not_found = serde_json::to_string(&ipc_resp_not_found).unwrap();
        assert!(json_not_found.contains("\"found\":false"));
        assert!(json_not_found.contains("\"session\":null"));
    }

    #[test]
    fn test_udp_worker_stats_response_serialization() {
        let resp = UdpWorkerStatsResponse {
            running: true,
            num_workers: 4,
            stats: Some(UdpWorkerPoolInfo {
                packets_processed: 50000,
                bytes_received: 10_000_000,
                workers_active: 4,
                workers_total: 4,
                worker_errors: 2,
            }),
        };
        let ipc_resp = IpcResponse::UdpWorkerStats(resp);
        let json = serde_json::to_string(&ipc_resp).unwrap();
        assert!(json.contains("\"type\":\"udp_worker_stats\""));
        assert!(json.contains("\"running\":true"));
        assert!(json.contains("\"num_workers\":4"));
        assert!(json.contains("\"packets_processed\":50000"));

        // Deserialize back
        let parsed: IpcResponse = serde_json::from_str(&json).unwrap();
        if let IpcResponse::UdpWorkerStats(stats) = parsed {
            assert!(stats.running);
            assert_eq!(stats.num_workers, 4);
            assert_eq!(stats.stats.as_ref().unwrap().packets_processed, 50000);
        } else {
            panic!("Expected UdpWorkerStats response");
        }
    }

    #[test]
    fn test_buffer_pool_stats_response_serialization() {
        let resp = BufferPoolStatsResponse {
            available: true,
            stats: Some(BufferPoolInfo {
                capacity: 2048,
                buffer_size: 65535,
                available: 1500,
                allocations: 548,
                reuses: 99452,
                returns: 100000,
                drops: 0,
                efficiency: 0.9945,
            }),
        };
        let ipc_resp = IpcResponse::BufferPoolStats(resp);
        let json = serde_json::to_string(&ipc_resp).unwrap();
        assert!(json.contains("\"type\":\"buffer_pool_stats\""));
        assert!(json.contains("\"available\":true"));
        assert!(json.contains("\"capacity\":2048"));
        assert!(json.contains("\"efficiency\":0.9945"));

        // Deserialize back
        let parsed: IpcResponse = serde_json::from_str(&json).unwrap();
        if let IpcResponse::BufferPoolStats(stats) = parsed {
            assert!(stats.available);
            assert_eq!(stats.stats.as_ref().unwrap().capacity, 2048);
            assert!((stats.stats.as_ref().unwrap().efficiency - 0.9945).abs() < 0.0001);
        } else {
            panic!("Expected BufferPoolStats response");
        }
    }

    #[test]
    fn test_udp_stats_disabled_serialization() {
        // Test UDP disabled case
        let resp = UdpStatsResponse {
            udp_enabled: false,
            session_stats: UdpSessionStatsInfo {
                session_count: 0,
                max_sessions: 65536,
                total_created: 0,
                total_evicted: 0,
                utilization_percent: 0.0,
                idle_timeout_secs: 300,
                ttl_secs: 600,
            },
            worker_stats: None,
            buffer_pool_stats: None,
            processor_stats: None,
        };
        let ipc_resp = IpcResponse::UdpStats(resp);
        let json = serde_json::to_string(&ipc_resp).unwrap();
        assert!(json.contains("\"udp_enabled\":false"));
        assert!(json.contains("\"worker_stats\":null"));
        assert!(json.contains("\"buffer_pool_stats\":null"));
        assert!(json.contains("\"processor_stats\":null"));
    }

    // =========================================================================
    // Phase 6.0 Serialization Tests - IPC Protocol v3.2
    // =========================================================================

    #[test]
    fn test_tunnel_type_serialization() {
        let wg = TunnelType::WireGuard;
        let json = serde_json::to_string(&wg).unwrap();
        assert_eq!(json, "\"wire_guard\"");

        let xray = TunnelType::Xray;
        let json = serde_json::to_string(&xray).unwrap();
        assert_eq!(json, "\"xray\"");

        // Deserialize back
        let parsed: TunnelType = serde_json::from_str("\"wire_guard\"").unwrap();
        assert_eq!(parsed, TunnelType::WireGuard);

        let parsed: TunnelType = serde_json::from_str("\"xray\"").unwrap();
        assert_eq!(parsed, TunnelType::Xray);

        // Test default
        assert_eq!(TunnelType::default(), TunnelType::WireGuard);
    }

    #[test]
    fn test_peer_state_serialization() {
        let state = PeerState::Connected;
        let json = serde_json::to_string(&state).unwrap();
        assert_eq!(json, "\"connected\"");

        let state = PeerState::Disconnected;
        let json = serde_json::to_string(&state).unwrap();
        assert_eq!(json, "\"disconnected\"");

        let state = PeerState::Connecting;
        let json = serde_json::to_string(&state).unwrap();
        assert_eq!(json, "\"connecting\"");

        let state = PeerState::Failed;
        let json = serde_json::to_string(&state).unwrap();
        assert_eq!(json, "\"failed\"");

        // Test default
        assert_eq!(PeerState::default(), PeerState::Disconnected);
    }

    #[test]
    fn test_chain_role_serialization() {
        let role = ChainRole::Entry;
        let json = serde_json::to_string(&role).unwrap();
        assert_eq!(json, "\"entry\"");

        let role = ChainRole::Relay;
        let json = serde_json::to_string(&role).unwrap();
        assert_eq!(json, "\"relay\"");

        let role = ChainRole::Terminal;
        let json = serde_json::to_string(&role).unwrap();
        assert_eq!(json, "\"terminal\"");
    }

    #[test]
    fn test_chain_state_serialization() {
        let state = ChainState::Inactive;
        let json = serde_json::to_string(&state).unwrap();
        assert_eq!(json, "\"inactive\"");

        let state = ChainState::Activating;
        let json = serde_json::to_string(&state).unwrap();
        assert_eq!(json, "\"activating\"");

        let state = ChainState::Active;
        let json = serde_json::to_string(&state).unwrap();
        assert_eq!(json, "\"active\"");

        let state = ChainState::Error;
        let json = serde_json::to_string(&state).unwrap();
        assert_eq!(json, "\"error\"");

        // Test default
        assert_eq!(ChainState::default(), ChainState::Inactive);
    }

    #[test]
    fn test_ecmp_algorithm_serialization() {
        let algo = EcmpAlgorithm::RoundRobin;
        let json = serde_json::to_string(&algo).unwrap();
        assert_eq!(json, "\"round_robin\"");

        let algo = EcmpAlgorithm::Weighted;
        let json = serde_json::to_string(&algo).unwrap();
        assert_eq!(json, "\"weighted\"");

        // Test default
        assert_eq!(EcmpAlgorithm::default(), EcmpAlgorithm::RoundRobin);
    }

    #[test]
    fn test_prepare_status_serialization() {
        let status = PrepareStatus::Pending;
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(json, "\"pending\"");

        let status = PrepareStatus::Prepared;
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(json, "\"prepared\"");

        let status = PrepareStatus::Committed;
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(json, "\"committed\"");

        let status = PrepareStatus::Aborted;
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(json, "\"aborted\"");

        // Test default
        assert_eq!(PrepareStatus::default(), PrepareStatus::Pending);
    }

    #[test]
    fn test_wg_tunnel_config_serialization() {
        let config = WgTunnelConfig {
            private_key: "cGFzc3dvcmQ=".into(),
            peer_public_key: "cGVlcmtleQ==".into(),
            peer_endpoint: "10.0.0.1:51820".into(),
            allowed_ips: vec!["10.200.200.0/24".into()],
            local_ip: Some("10.200.200.1/32".into()),
            listen_port: Some(36200),
            persistent_keepalive: Some(25),
            mtu: Some(1420),
        };
        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains("\"private_key\":\"cGFzc3dvcmQ=\""));
        assert!(json.contains("\"peer_endpoint\":\"10.0.0.1:51820\""));
        assert!(json.contains("\"listen_port\":36200"));
        assert!(json.contains("\"mtu\":1420"));

        let parsed: WgTunnelConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.peer_endpoint, "10.0.0.1:51820");
        assert_eq!(parsed.mtu, Some(1420));
    }

    #[test]
    fn test_chain_config_serialization() {
        let config = ChainConfig {
            tag: "test-chain".into(),
            description: "Test chain".into(),
            dscp_value: 10,
            hops: vec![
                ChainHop {
                    node_tag: "node-a".into(),
                    role: ChainRole::Entry,
                    tunnel_type: TunnelType::WireGuard,
                },
                ChainHop {
                    node_tag: "node-b".into(),
                    role: ChainRole::Terminal,
                    tunnel_type: TunnelType::WireGuard,
                },
            ],
            rules: vec!["rule1".into()],
            exit_egress: "direct".into(),
            allow_transitive: false,
        };
        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains("\"tag\":\"test-chain\""));
        assert!(json.contains("\"dscp_value\":10"));
        assert!(json.contains("\"exit_egress\":\"direct\""));
        assert!(json.contains("\"role\":\"entry\""));
        assert!(json.contains("\"role\":\"terminal\""));

        let parsed: ChainConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.tag, "test-chain");
        assert_eq!(parsed.dscp_value, 10);
        assert_eq!(parsed.hops.len(), 2);
        assert_eq!(parsed.hops[0].role, ChainRole::Entry);
    }

    #[test]
    fn test_pair_request_serialization() {
        let request = PairRequest {
            version: 2,
            node_tag: "node-a".into(),
            node_description: "Test node A".into(),
            endpoint: "192.168.1.100:36200".into(),
            api_port: 36000,
            tunnel_type: TunnelType::WireGuard,
            timestamp: 1704067200,
            bidirectional: true,
            wg_public_key: Some("cHVibGljX2tleQ==".into()),
            tunnel_ip: Some("10.200.200.1".into()),
            remote_wg_private_key: None,
            remote_wg_public_key: None,
            xray_uuid: None,
            xray_server_name: None,
            xray_public_key: None,
            xray_short_id: None,
        };
        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("\"version\":2"));
        assert!(json.contains("\"node_tag\":\"node-a\""));
        assert!(json.contains("\"bidirectional\":true"));
        assert!(json.contains("\"api_port\":36000"));

        let parsed: PairRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.version, 2);
        assert_eq!(parsed.api_port, 36000);
        assert!(parsed.bidirectional);
    }

    #[test]
    fn test_generate_pair_request_command_serialization() {
        let cmd = IpcCommand::GeneratePairRequest {
            local_tag: "local-node".into(),
            local_description: "My local node".into(),
            local_endpoint: "1.2.3.4:36200".into(),
            local_api_port: 36000,
            bidirectional: true,
            tunnel_type: TunnelType::WireGuard,
        };
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("\"type\":\"generate_pair_request\""));
        assert!(json.contains("\"local_tag\":\"local-node\""));
        assert!(json.contains("\"bidirectional\":true"));

        let parsed: IpcCommand = serde_json::from_str(&json).unwrap();
        if let IpcCommand::GeneratePairRequest { local_tag, bidirectional, .. } = parsed {
            assert_eq!(local_tag, "local-node");
            assert!(bidirectional);
        } else {
            panic!("Expected GeneratePairRequest command");
        }
    }

    #[test]
    fn test_create_chain_command_serialization() {
        let cmd = IpcCommand::CreateChain {
            tag: "my-chain".into(),
            config: ChainConfig {
                tag: "my-chain".into(),
                description: "My test chain".into(),
                dscp_value: 5,
                hops: vec![],
                rules: vec![],
                exit_egress: "proxy".into(),
                allow_transitive: false,
            },
        };
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("\"type\":\"create_chain\""));
        assert!(json.contains("\"tag\":\"my-chain\""));
        assert!(json.contains("\"dscp_value\":5"));

        let parsed: IpcCommand = serde_json::from_str(&json).unwrap();
        if let IpcCommand::CreateChain { tag, config } = parsed {
            assert_eq!(tag, "my-chain");
            assert_eq!(config.dscp_value, 5);
        } else {
            panic!("Expected CreateChain command");
        }
    }

    #[test]
    fn test_prepare_chain_route_command_serialization() {
        let cmd = IpcCommand::PrepareChainRoute {
            chain_tag: "chain-1".into(),
            config: ChainConfig {
                tag: "chain-1".into(),
                description: "Chain 1".into(),
                dscp_value: 10,
                hops: vec![],
                rules: vec![],
                exit_egress: "direct".into(),
                allow_transitive: false,
            },
            source_node: "entry-node".into(),
        };
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("\"type\":\"prepare_chain_route\""));
        assert!(json.contains("\"chain_tag\":\"chain-1\""));
        assert!(json.contains("\"source_node\":\"entry-node\""));

        let parsed: IpcCommand = serde_json::from_str(&json).unwrap();
        if let IpcCommand::PrepareChainRoute { chain_tag, source_node, .. } = parsed {
            assert_eq!(chain_tag, "chain-1");
            assert_eq!(source_node, "entry-node");
        } else {
            panic!("Expected PrepareChainRoute command");
        }
    }

    #[test]
    fn test_chain_status_response_serialization() {
        let status = ChainStatus {
            tag: "my-chain".into(),
            state: ChainState::Active,
            dscp_value: 10,
            my_role: Some(ChainRole::Entry),
            hop_status: vec![
                HopStatus {
                    node_tag: "node-a".into(),
                    role: ChainRole::Entry,
                    tunnel_type: TunnelType::WireGuard,
                    peer_connected: true,
                    prepare_status: Some(PrepareStatus::Committed),
                },
                HopStatus {
                    node_tag: "node-b".into(),
                    role: ChainRole::Terminal,
                    tunnel_type: TunnelType::WireGuard,
                    peer_connected: true,
                    prepare_status: Some(PrepareStatus::Committed),
                },
            ],
            active_connections: 5,
            last_error: None,
        };
        let ipc_resp = IpcResponse::ChainStatus(status);
        let json = serde_json::to_string(&ipc_resp).unwrap();
        assert!(json.contains("\"type\":\"chain_status\""));
        assert!(json.contains("\"state\":\"active\""));
        assert!(json.contains("\"my_role\":\"entry\""));
        assert!(json.contains("\"peer_connected\":true"));

        let parsed: IpcResponse = serde_json::from_str(&json).unwrap();
        if let IpcResponse::ChainStatus(s) = parsed {
            assert_eq!(s.tag, "my-chain");
            assert_eq!(s.state, ChainState::Active);
            assert_eq!(s.hop_status.len(), 2);
        } else {
            panic!("Expected ChainStatus response");
        }
    }

    #[test]
    fn test_peer_status_response_serialization() {
        let status = PeerStatus {
            tag: "peer-1".into(),
            state: PeerState::Connected,
            tunnel_type: TunnelType::WireGuard,
            tunnel_local_ip: Some("10.200.200.1".into()),
            tunnel_remote_ip: Some("10.200.200.2".into()),
            api_port: 36000,
            last_handshake: Some(1704067200),
            tx_bytes: 1000,
            rx_bytes: 2000,
            reconnect_attempts: 0,
            consecutive_failures: 0,
            last_error: None,
        };
        let ipc_resp = IpcResponse::PeerStatus(status);
        let json = serde_json::to_string(&ipc_resp).unwrap();
        assert!(json.contains("\"type\":\"peer_status\""));
        assert!(json.contains("\"state\":\"connected\""));
        assert!(json.contains("\"api_port\":36000"));
        assert!(json.contains("\"tx_bytes\":1000"));

        let parsed: IpcResponse = serde_json::from_str(&json).unwrap();
        if let IpcResponse::PeerStatus(s) = parsed {
            assert_eq!(s.tag, "peer-1");
            assert_eq!(s.state, PeerState::Connected);
            assert_eq!(s.api_port, 36000);
        } else {
            panic!("Expected PeerStatus response");
        }
    }

    #[test]
    fn test_ecmp_group_config_serialization() {
        let config = EcmpGroupConfig {
            description: "Test ECMP group".into(),
            algorithm: EcmpAlgorithm::Weighted,
            members: vec![
                EcmpMemberConfig {
                    outbound: "proxy-1".into(),
                    weight: 2,
                    enabled: true,
                },
                EcmpMemberConfig {
                    outbound: "proxy-2".into(),
                    weight: 1,
                    enabled: true,
                },
            ],
            skip_unhealthy: true,
            health_check_interval_secs: 30,
            routing_mark: Some(200),
            routing_table: Some(200),
        };
        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains("\"algorithm\":\"weighted\""));
        assert!(json.contains("\"weight\":2"));
        assert!(json.contains("\"skip_unhealthy\":true"));

        let parsed: EcmpGroupConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.algorithm, EcmpAlgorithm::Weighted);
        assert_eq!(parsed.members.len(), 2);
        assert_eq!(parsed.members[0].weight, 2);
    }

    #[test]
    fn test_wg_tunnel_commands_serialization() {
        // CreateWgTunnel
        let cmd = IpcCommand::CreateWgTunnel {
            tag: "wg-test".into(),
            config: WgTunnelConfig {
                private_key: "key".into(),
                peer_public_key: "peer".into(),
                peer_endpoint: "1.2.3.4:51820".into(),
                allowed_ips: vec![],
                local_ip: None,
                listen_port: None,
                persistent_keepalive: None,
                mtu: None,
            },
        };
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("\"type\":\"create_wg_tunnel\""));

        // RemoveWgTunnel
        let cmd = IpcCommand::RemoveWgTunnel {
            tag: "wg-test".into(),
            drain_timeout_secs: Some(30),
        };
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("\"type\":\"remove_wg_tunnel\""));
        assert!(json.contains("\"drain_timeout_secs\":30"));

        // GetWgTunnelStatus
        let cmd = IpcCommand::GetWgTunnelStatus { tag: "wg-test".into() };
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("\"type\":\"get_wg_tunnel_status\""));

        // ListWgTunnels
        let cmd = IpcCommand::ListWgTunnels;
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("\"type\":\"list_wg_tunnels\""));
    }

    #[test]
    fn test_peer_commands_serialization() {
        // ConnectPeer
        let cmd = IpcCommand::ConnectPeer { tag: "peer-1".into() };
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("\"type\":\"connect_peer\""));

        // DisconnectPeer
        let cmd = IpcCommand::DisconnectPeer { tag: "peer-1".into() };
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("\"type\":\"disconnect_peer\""));

        // GetPeerStatus
        let cmd = IpcCommand::GetPeerStatus { tag: "peer-1".into() };
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("\"type\":\"get_peer_status\""));

        // ListPeers
        let cmd = IpcCommand::ListPeers;
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("\"type\":\"list_peers\""));

        // RemovePeer
        let cmd = IpcCommand::RemovePeer { tag: "peer-1".into() };
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("\"type\":\"remove_peer\""));
    }

    #[test]
    fn test_chain_commands_serialization() {
        // ActivateChain
        let cmd = IpcCommand::ActivateChain { tag: "chain-1".into() };
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("\"type\":\"activate_chain\""));

        // DeactivateChain
        let cmd = IpcCommand::DeactivateChain { tag: "chain-1".into() };
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("\"type\":\"deactivate_chain\""));

        // GetChainStatus
        let cmd = IpcCommand::GetChainStatus { tag: "chain-1".into() };
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("\"type\":\"get_chain_status\""));

        // ListChains
        let cmd = IpcCommand::ListChains;
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("\"type\":\"list_chains\""));

        // GetChainRole
        let cmd = IpcCommand::GetChainRole { chain_tag: "chain-1".into() };
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("\"type\":\"get_chain_role\""));

        // UpdateChain
        let cmd = IpcCommand::UpdateChain {
            tag: "chain-1".into(),
            hops: None,
            exit_egress: Some("pia-uk".into()),
            description: Some("Updated".into()),
            allow_transitive: Some(true),
        };
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("\"type\":\"update_chain\""));
        assert!(json.contains("\"exit_egress\":\"pia-uk\""));
        assert!(json.contains("\"allow_transitive\":true"));
        // Skip serializing None fields
        assert!(!json.contains("\"hops\""));

        // UpdateChain with hops
        let cmd = IpcCommand::UpdateChain {
            tag: "chain-2".into(),
            hops: Some(vec![ChainHop {
                node_tag: "terminal".into(),
                tunnel_type: TunnelType::WireGuard,
                role: ChainRole::Terminal,
            }]),
            exit_egress: None,
            description: None,
            allow_transitive: None,
        };
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("\"type\":\"update_chain\""));
        assert!(json.contains("\"hops\":"));
        assert!(json.contains("\"node_tag\":\"terminal\""));
    }

    #[test]
    fn test_update_ecmp_group_members_serialization() {
        let cmd = IpcCommand::UpdateEcmpGroupMembers {
            tag: "group-1".into(),
            members: vec![
                EcmpMemberConfig {
                    outbound: "proxy-1".into(),
                    weight: 2,
                    enabled: true,
                },
                EcmpMemberConfig {
                    outbound: "proxy-2".into(),
                    weight: 3,
                    enabled: true,
                },
            ],
        };
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("\"type\":\"update_ecmp_group_members\""));
        assert!(json.contains("\"tag\":\"group-1\""));
        assert!(json.contains("\"outbound\":\"proxy-1\""));
        assert!(json.contains("\"weight\":2"));
    }

    #[test]
    fn test_two_phase_commit_commands_serialization() {
        // CommitChainRoute
        let cmd = IpcCommand::CommitChainRoute {
            chain_tag: "chain-1".into(),
            source_node: "entry".into(),
        };
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("\"type\":\"commit_chain_route\""));
        assert!(json.contains("\"source_node\":\"entry\""));

        // AbortChainRoute
        let cmd = IpcCommand::AbortChainRoute {
            chain_tag: "chain-1".into(),
            source_node: "entry".into(),
        };
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("\"type\":\"abort_chain_route\""));
    }

    #[test]
    fn test_pairing_response_serialization() {
        let resp = PairingResponse {
            success: true,
            code: Some("YmFzZTY0Y29kZQ==".into()),
            message: Some("Pairing code generated".into()),
            peer_tag: None,
        };
        let ipc_resp = IpcResponse::Pairing(resp);
        let json = serde_json::to_string(&ipc_resp).unwrap();
        assert!(json.contains("\"type\":\"pairing\""));
        assert!(json.contains("\"success\":true"));
        assert!(json.contains("\"code\":\"YmFzZTY0Y29kZQ==\""));

        let parsed: IpcResponse = serde_json::from_str(&json).unwrap();
        if let IpcResponse::Pairing(p) = parsed {
            assert!(p.success);
            assert_eq!(p.code, Some("YmFzZTY0Y29kZQ==".into()));
        } else {
            panic!("Expected Pairing response");
        }
    }

    #[test]
    fn test_chain_role_response_serialization() {
        let resp = ChainRoleResponse {
            chain_tag: "chain-1".into(),
            role: Some(ChainRole::Entry),
            in_chain: true,
        };
        let ipc_resp = IpcResponse::ChainRole(resp);
        let json = serde_json::to_string(&ipc_resp).unwrap();
        assert!(json.contains("\"type\":\"chain_role\""));
        assert!(json.contains("\"role\":\"entry\""));
        assert!(json.contains("\"in_chain\":true"));

        let parsed: IpcResponse = serde_json::from_str(&json).unwrap();
        if let IpcResponse::ChainRole(r) = parsed {
            assert_eq!(r.role, Some(ChainRole::Entry));
            assert!(r.in_chain);
        } else {
            panic!("Expected ChainRole response");
        }
    }

    #[test]
    fn test_prepare_response_serialization() {
        let resp = PrepareResponse {
            success: true,
            message: None,
            node: "relay-node".into(),
        };
        let ipc_resp = IpcResponse::PrepareResult(resp);
        let json = serde_json::to_string(&ipc_resp).unwrap();
        assert!(json.contains("\"type\":\"prepare_result\""));
        assert!(json.contains("\"node\":\"relay-node\""));

        let parsed: IpcResponse = serde_json::from_str(&json).unwrap();
        if let IpcResponse::PrepareResult(p) = parsed {
            assert!(p.success);
            assert_eq!(p.node, "relay-node");
        } else {
            panic!("Expected PrepareResult response");
        }
    }
}
