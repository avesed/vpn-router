//! rust-router: High-performance transparent proxy router
//!
//! This crate provides a TPROXY-based transparent proxy router for Linux,
//! designed to work alongside the vpn-router project.
//!
//! # Features
//!
//! - **TPROXY Support**: Full support for Linux TPROXY transparent proxying
//! - **TLS SNI Sniffing**: Extract Server Name Indication from TLS `ClientHello`
//! - **Multiple Outbounds**: Support for direct and block outbound types
//! - **IPC Control**: Unix socket-based runtime control
//! - **Connection Management**: Backpressure, statistics, and graceful shutdown
//!
//! # Architecture
//!
//! ```text
//! Client → iptables TPROXY → rust-router → Outbound → Destination
//!                              ↓
//!                        TLS SNI Sniffing
//!                              ↓
//!                         Route Selection
//! ```
//!
//! # Quick Start
//!
//! ```no_run
//! use rust_router::config::load_config;
//! use rust_router::tproxy::TproxyListener;
//! use rust_router::outbound::OutboundManagerBuilder;
//! use rust_router::connection::ConnectionManager;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Load configuration
//! let config = load_config("/etc/rust-router/config.json")?;
//!
//! // Create outbound manager
//! let mut builder = OutboundManagerBuilder::new();
//! builder.add_all_from_config(&config.outbounds);
//! let outbound_manager = builder.build();
//!
//! // Create listener
//! let listener = TproxyListener::bind(&config.listen)?;
//!
//! // Accept and handle connections...
//! # Ok(())
//! # }
//! ```
//!
//! # Module Migration Guide
//!
//! The `netbridge` module is the new unified implementation for IP <-> TCP/UDP bridging.
//! It is designed to eventually replace:
//!
//! - `tun_bridge/` -> `netbridge::kernel` (TUN + TPROXY, 200-400 Mbps)
//! - `vless_wg_bridge/` -> `netbridge::smoltcp` (userspace TCP/IP, 30-80 Mbps)
//! - `smoltcp_utils/` -> `netbridge` (shared utilities)
//!
//! During the migration period, both old and new modules coexist:
//!
//! - **Existing code**: Continue using `tun_bridge`, `vless_wg_bridge`, `smoltcp_utils`
//! - **New code**: Prefer `netbridge` types (prefixed with `Net` for disambiguation)
//!
//! ## Type Mapping (Old -> New)
//!
//! | Old Type | New Type | Notes |
//! |----------|----------|-------|
//! | `tun_bridge::FiveTuple` | `netbridge::FiveTuple` | Same semantics |
//! | `tun_bridge::SessionTracker` | `netbridge::SessionTracker` | New has rate limiting |
//! | `vless_wg_bridge::PortAllocator` | `netbridge::PortAllocator` | New has shard support |
//! | `smoltcp_utils::BridgeError` | `netbridge::NetBridgeError` | New has classification |
//!
//! ## Example Migration
//!
//! ```ignore
//! // Old code (still works)
//! use rust_router::{TunBridgeFiveTuple, PortAllocator, BridgeError};
//!
//! // New code (recommended for new implementations)
//! use rust_router::netbridge::{FiveTuple, PortAllocator, NetBridgeError};
//! // Or use re-exported aliases with Net prefix
//! use rust_router::{NetSessionTracker, NetPortAllocator, NetBridgeError};
//! ```
//!
//! # Modules
//!
//! - [`config`]: Configuration types and loading
//! - [`connection`]: Connection management and statistics
//! - [`error`]: Error types
//! - [`io`]: I/O utilities for bidirectional copy
//! - [`ipc`]: IPC server and protocol
//! - [`outbound`]: Outbound implementations
//! - [`sniff`]: Protocol sniffing (TLS SNI, QUIC SNI)
//! - [`tproxy`]: TPROXY socket and listener
//! - [`ingress`]: `WireGuard` ingress management
//! - [`egress`]: `WireGuard` egress management
//! - [`vless`]: VLESS protocol implementation
//! - [`vless_inbound`]: VLESS inbound listener (server mode)
//! - [`vision`]: XTLS-Vision TLS detection and zero-copy passthrough
//! - [`reality`]: REALITY protocol configuration (TLS 1.3 camouflage)
//! - [`transport`]: Transport layer abstraction (TCP, TLS, WebSocket)
//! - [`ss_inbound`]: Shadowsocks inbound listener (server mode)
//! - [`smoltcp_utils`]: Shared utilities for smoltcp-based bridges (legacy)
//! - [`tun_bridge`]: TUN + TPROXY ingress bridge (legacy)
//! - [`vless_wg_bridge`]: VLESS -> WireGuard bridge (legacy)
//! - [`netbridge`]: **NEW** Unified network bridge for IP <-> TCP/UDP conversion

#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]

pub mod chain;
pub mod config;
pub mod connection;
pub mod dns;
pub mod ecmp;
pub mod egress;
pub mod error;
#[cfg(feature = "fakedns")]
pub mod fakedns;
pub mod ingress;
pub mod io;
pub mod ipc;
pub mod netbridge;
pub mod outbound;
pub mod peer;
#[cfg(feature = "transport-quic")]
pub mod quic_inbound;
pub mod reality;
pub mod rules;
#[cfg(feature = "shadowsocks")]
pub mod shadowsocks;
pub mod smoltcp_utils;
pub mod sniff;
#[cfg(feature = "shadowsocks")]
pub mod ss_inbound;
pub mod tproxy;
pub mod transport;
pub mod tun;
pub mod tun_bridge;
pub mod tunnel;
pub mod vision;
pub mod vless;
pub mod vless_inbound;
pub mod vless_wg_bridge;
pub mod warp;

// Re-export commonly used types at the crate root
pub use chain::{
    ChainError, ChainManager, DscpAllocator, DscpRoutingCallback, NoOpRoutingCallback,
    PeerConnectivityCallback,
};
pub use config::{Config, ListenConfig, OutboundConfig, RuleConfig, RulesConfig};
pub use connection::{
    ConnectionManager, ConnectionStats, ProcessResult, ReplyHandlerConfig, ReplyHandlerStats,
    ReplyHandlerStatsSnapshot, UdpPacketProcessor, UdpProcessorConfig, UdpProcessorStats,
    UdpProcessorStatsSnapshot, UdpReplyHandler, UdpSession, UdpSessionConfig, UdpSessionKey,
    UdpSessionManager, UdpSessionSnapshot, UdpSessionStats, UdpSessionWrapper,
};
pub use dns::{
    analyze_negative_response, dns_classes, extract_soa_minimum, get_negative_cache_ttl,
    is_negative_response, record_types, BlockResponseType, BlockingConfig, CacheConfig, CacheEntry,
    CacheKey, CacheStats, CacheStatsSnapshot, DnsCache, DnsConfig, DnsError, DnsResult, LogFormat,
    LoggingConfig, NegativeAnalysis, NegativeCacheConfig, NegativeResponseType, RateLimitConfig,
    TcpServerConfig, UpstreamConfig, UpstreamProtocol,
};
pub use egress::{
    EgressError, EgressResult, EgressTunnelStatus, EgressTunnelType, WgEgressConfig,
    WgEgressManager, WgEgressStats, WgReplyHandler,
};
pub use error::{
    ConfigError, ConnectionError, IpcError, OutboundError, RuleError, RustRouterError, TproxyError,
    UdpError,
};
pub use ingress::{
    IngressError, IngressProcessor, RoutingDecision, WgIngressConfig, WgIngressManager,
    WgIngressStats,
};
pub use ipc::{IpcClient, IpcCommand, IpcResponse, IpcServer};
pub use outbound::{
    get_egress_interface_name, get_egress_type, get_interface_info, interface_exists,
    is_egress_interface, list_egress_interfaces, parse_interface_name, validate_interface_exists,
    BlockOutbound, DirectOutbound, DirectUdpHandle, EgressType, InterfaceInfo, Outbound,
    OutboundManager, Socks5UdpHandle, UdpOutboundHandle, CUSTOM_PREFIX, INTERFACE_MAX_LEN,
    PEER_PREFIX, PIA_PREFIX, WARP_PREFIX,
};
pub use peer::{
    validate_chain_tag, validate_dscp_value, validate_endpoint, validate_peer_tag,
    validate_tunnel_ip, validate_wg_key, ValidationError, WG_KEY_LENGTH,
};
pub use reality::{RealityConfig, RealityError, RealityResult};
pub use rules::{
    dscp_to_routing_mark, dscp_to_routing_table, is_dscp_terminal_table, is_ecmp_table,
    is_peer_table, is_relay_table, is_reserved_dscp, is_valid_dscp, routing_mark_to_dscp, tables,
    ChainMark, CompiledRuleSet, ConnectionInfo, CountryInfo, DomainMatcher, DomainMatcherBuilder,
    FwmarkRouter, FwmarkRouterBuilder, GeoIpMatcher, GeoIpMatcherBuilder, MatchResult, MatchedRule,
    PortRange, RoutingConfig, RoutingSnapshot, RoutingSnapshotBuilder, Rule, RuleEngine, RuleType,
    SnapshotStats, DSCP_MAX, DSCP_MIN, ENTRY_ROUTING_MARK_BASE, MAX_CHAINS, RESERVED_DSCP_VALUES,
};
pub use sniff::{
    looks_like_tls, sniff_tls, sniff_tls_sni, Protocol, QuicPacketType, QuicSniffResult,
    QuicSniffer, QuicVersion, SniffResult, TlsSniffResult,
};
pub use tproxy::{
    TproxyConnection, TproxyListener, TproxyUdpListener, TproxyUdpListenerBuilder, UdpPacketInfo,
};
pub use tun::{TunConfig, TunDevice, DEFAULT_MTU as TUN_DEFAULT_MTU};
pub use tun_bridge::{
    FiveTuple as TunBridgeFiveTuple, IptablesManager, SessionInfo as TunBridgeSessionInfo,
    SessionTracker as TunBridgeSessionTracker, TunIngressBridge, TunIngressConfig,
    TunIngressStats, TunIngressStatsSnapshot,
};
#[cfg(feature = "transport-tls")]
pub use transport::TlsTransport;
#[cfg(feature = "transport-ws")]
pub use transport::WebSocketTransport;
pub use transport::{
    connect, TcpTransport, TlsConfig, Transport, TransportConfig, TransportError, TransportStream,
    WebSocketConfig,
};
pub use vision::{
    is_application_data, is_client_hello, is_server_hello, is_tls_traffic, is_valid_tls_version,
    parse_tls_record_header, StreamState, VisionError, VisionResult, VisionState, VisionStream,
    HANDSHAKE_CLIENT_HELLO, HANDSHAKE_SERVER_HELLO, TLS_APPLICATION_DATA, TLS_HANDSHAKE,
    TLS_RECORD_HEADER_SIZE,
};
pub use vless::{
    VlessAccount, VlessAccountManager, VlessAddons, VlessAddress, VlessCommand, VlessError,
    VlessRequestHeader, VlessResponseHeader, VLESS_VERSION, XTLS_VISION_FLOW,
};
pub use vless_inbound::{
    AuthenticatedUser, InboundTlsConfig, VlessConnection, VlessConnectionHandler, VlessDestination,
    VlessInboundConfig, VlessInboundError, VlessInboundListener, VlessInboundResult,
    VlessInboundStats, VlessUser,
};
pub use vless_wg_bridge::{
    BridgeError, BridgeStats, BridgeStatsSnapshot, PortAllocator, PortAllocatorConfig, PortGuard,
    SessionKey, SessionStats, SessionTracker, TcpSession, TimeoutConfig,
    UdpSession as BridgeUdpSession, VlessConnectionId, VlessWgBridge, WgReplyPacket,
};

// =============================================================================
// netbridge module re-exports (NEW unified bridge implementation)
// =============================================================================
//
// The netbridge module provides a unified abstraction for IP <-> TCP/UDP bridging.
// It is designed to eventually replace tun_bridge, vless_wg_bridge, and smoltcp_utils.
//
// During migration, both old and new modules coexist:
// - Existing code: Continue using tun_bridge, vless_wg_bridge, smoltcp_utils
// - New code: Prefer netbridge types (prefixed with Net for disambiguation)
//
// Types are re-exported with "Net" prefix to avoid conflicts with legacy types.

// Core types (with Net prefix to avoid conflicts)
pub use netbridge::{
    // Core types
    FiveTuple as NetFiveTuple,
    IpPacket as NetIpPacket,
    IpProtocol as NetIpProtocol,
    ReplyPacket as NetReplyPacket,
    SessionId as NetSessionId,
    SessionIdGenerator as NetSessionIdGenerator,
    // Statistics
    EgressStats as NetEgressStats,
    IngressStats as NetIngressStats,
};

// Session tracking (with Net prefix)
pub use netbridge::{
    Session as NetSession,
    SessionError as NetSessionError,
    SessionTracker as NetSessionTracker,
    SessionTrackerConfig as NetSessionTrackerConfig,
    SessionTrackerStats as NetSessionTrackerStats,
};

// Port allocation (with Net prefix)
pub use netbridge::{
    PortAllocator as NetPortAllocator,
    PortAllocatorConfig as NetPortAllocatorConfig,
    PortAllocatorStats as NetPortAllocatorStats,
    PortGuard as NetPortGuard,
};

// Reply routing
pub use netbridge::{ReplyChannelBuilder, ReplyRouter, ReplyRouterStatsSnapshot};

// Error types
pub use netbridge::NetBridgeError;

// Traits (no prefix needed - unique names)
pub use netbridge::{
    CloseReason, NetBridgeEgress, NetBridgeIngress, NoOpSessionHandler, ReplyRouterExt,
    SessionCloseStats, SessionHandler, SessionInfo,
};

// Configuration constants (prefixed to avoid conflicts with smoltcp_utils)
pub use netbridge::{
    // Buffer sizes
    TCP_RX_BUFFER as NET_TCP_RX_BUFFER,
    TCP_TX_BUFFER as NET_TCP_TX_BUFFER,
    UDP_RX_BUFFER as NET_UDP_RX_BUFFER,
    UDP_TX_BUFFER as NET_UDP_TX_BUFFER,
    // Network parameters
    TCP_MSS as NET_TCP_MSS,
    TUN_MTU as NET_TUN_MTU,
    WG_MTU as NET_WG_MTU,
    MAX_IP_PACKET_SIZE as NET_MAX_IP_PACKET_SIZE,
    MAX_SOCKETS as NET_MAX_SOCKETS,
    // Timeouts
    TCP_IDLE_TIMEOUT_SECS as NET_TCP_IDLE_TIMEOUT_SECS,
    UDP_DEFAULT_TIMEOUT_SECS as NET_UDP_DEFAULT_TIMEOUT_SECS,
    UDP_DNS_TIMEOUT_SECS as NET_UDP_DNS_TIMEOUT_SECS,
    // Session limits
    MAX_SESSIONS_PER_PEER as NET_MAX_SESSIONS_PER_PEER,
    MAX_TOTAL_SESSIONS as NET_MAX_TOTAL_SESSIONS,
};

// Kernel backend (TUN + TPROXY)
pub use netbridge::kernel::{
    KernelIngress, KernelIngressConfig, KernelEgress, KernelEgressConfig,
    TunDeviceWrapper, TunDeviceBuilder,
    TproxyListenerWrapper, TproxyListenerConfig, TproxyListenerStats,
    IptablesManagerWrapper, IptablesConfig,
    DEFAULT_TPROXY_PORT, DEFAULT_FWMARK, DEFAULT_TABLE_ID,
};

// Smoltcp backend (userspace TCP/IP for VLESS/SS -> WG)
pub use netbridge::smoltcp::{
    SmoltcpEgress, SmoltcpEgressConfig, SmoltcpEgressStats,
    SmoltcpShard, SmoltcpShardConfig, SmoltcpShardStats,
    SmoltcpBridge, SmoltcpBridgeConfig,
    VirtualDevice, VirtualDeviceStats,
};

// Benchmarking utilities
pub use netbridge::bench::{
    BenchConfig, BenchResults, TrafficPattern, LoopbackTest,
    run_benchmark, run_quick_benchmark, run_full_suite,
};
#[cfg(feature = "fakedns")]
pub use fakedns::{
    FakeDns, FakeDnsBuilder, FakeDnsCache, FakeDnsCacheStats, FakeDnsCacheStatsSnapshot,
    FakeDnsConfig, FakeDnsError, FakeDnsManager, FakeDnsResult,
};
#[cfg(feature = "shadowsocks")]
pub use outbound::{ShadowsocksOutbound, ShadowsocksStream};
#[cfg(feature = "transport-quic")]
pub use quic_inbound::{
    ConnectionGuard as QuicConnectionGuardWrapper, QuicInboundConfig, QuicInboundConnection,
    QuicInboundError, QuicInboundListener, QuicInboundResult, QuicInboundStatus,
};
#[cfg(feature = "shadowsocks")]
pub use shadowsocks::{
    ShadowsocksError, ShadowsocksMethod, ShadowsocksOutboundConfig, ShadowsocksOutboundInfo,
};
#[cfg(feature = "shadowsocks")]
pub use ss_inbound::{
    ConnectionStats as SsConnectionStats, ShadowsocksConnection, ShadowsocksDestination,
    ShadowsocksInboundConfig, ShadowsocksInboundError, ShadowsocksInboundListener,
    ShadowsocksInboundResult, ShadowsocksInboundStats, ShadowsocksInboundStatsSnapshot,
    ShadowsocksInboundStatus,
};
#[cfg(feature = "transport-quic")]
pub use transport::{
    build_server_config, load_certs_from_pem, load_key_from_pem, QuicConnection,
    QuicConnectionGuard, QuicInboundStats, QuicInboundStatsSnapshot, QuicServerConfig,
};

/// Crate version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Check if running with required capabilities for TPROXY
pub fn check_capabilities() -> Result<(), TproxyError> {
    if !tproxy::has_net_admin_capability() {
        return Err(TproxyError::PermissionDenied);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        assert!(!VERSION.is_empty());
    }

    #[test]
    fn test_check_capabilities() {
        // This test will pass or fail depending on privileges
        let result = check_capabilities();
        // Just verify it doesn't panic
        match result {
            Ok(()) => println!("Running with CAP_NET_ADMIN"),
            Err(TproxyError::PermissionDenied) => println!("Running without CAP_NET_ADMIN"),
            Err(e) => panic!("Unexpected error: {}", e),
        }
    }
}
// Build trigger: Tue Jan 20 06:52:51 AM UTC 2026
