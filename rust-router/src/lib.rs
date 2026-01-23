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
pub mod ingress;
pub mod io;
pub mod ipc;
pub mod outbound;
pub mod peer;
pub mod reality;
pub mod rules;
pub mod sniff;
pub mod tproxy;
pub mod transport;
pub mod tunnel;
pub mod vision;
pub mod vless;
pub mod vless_inbound;
pub mod warp;

// Re-export commonly used types at the crate root
pub use config::{Config, ListenConfig, OutboundConfig, RuleConfig, RulesConfig};
pub use connection::{
    ConnectionManager, ConnectionStats, ProcessResult, ReplyHandlerConfig, ReplyHandlerStats,
    ReplyHandlerStatsSnapshot, UdpPacketProcessor, UdpProcessorConfig, UdpProcessorStats,
    UdpProcessorStatsSnapshot, UdpReplyHandler, UdpSession, UdpSessionConfig, UdpSessionKey,
    UdpSessionManager, UdpSessionSnapshot, UdpSessionStats, UdpSessionWrapper,
};
pub use error::{
    ConfigError, ConnectionError, IpcError, OutboundError, RuleError, RustRouterError, TproxyError,
    UdpError,
};
pub use ipc::{IpcClient, IpcCommand, IpcResponse, IpcServer};
pub use outbound::{
    get_egress_interface_name, get_egress_type, get_interface_info, interface_exists,
    is_egress_interface, list_egress_interfaces, parse_interface_name, validate_interface_exists,
    BlockOutbound, DirectOutbound, DirectUdpHandle, EgressType, InterfaceInfo, Outbound,
    OutboundManager, Socks5UdpHandle, UdpOutboundHandle, CUSTOM_PREFIX, INTERFACE_MAX_LEN,
    PEER_PREFIX, PIA_PREFIX, WARP_PREFIX,
};
pub use rules::{
    dscp_to_routing_mark, dscp_to_routing_table, is_dscp_terminal_table, is_ecmp_table,
    is_peer_table, is_relay_table, is_reserved_dscp, is_valid_dscp, routing_mark_to_dscp, tables,
    ChainMark, CompiledRuleSet, ConnectionInfo, CountryInfo, DomainMatcher, DomainMatcherBuilder,
    FwmarkRouter, FwmarkRouterBuilder, GeoIpMatcher, GeoIpMatcherBuilder, MatchResult, MatchedRule,
    PortRange, RoutingConfig, RoutingSnapshot, RoutingSnapshotBuilder, Rule, RuleEngine, RuleType,
    SnapshotStats, DSCP_MAX, DSCP_MIN, ENTRY_ROUTING_MARK_BASE, MAX_CHAINS, RESERVED_DSCP_VALUES,
};
pub use sniff::{
    sniff_tls_sni, Protocol, QuicPacketType, QuicSniffResult, QuicSniffer, QuicVersion, SniffResult,
};
pub use tproxy::{
    TproxyConnection, TproxyListener, TproxyUdpListener, TproxyUdpListenerBuilder, UdpPacketInfo,
};
pub use peer::{
    validate_chain_tag, validate_dscp_value, validate_endpoint, validate_peer_tag,
    validate_tunnel_ip, validate_wg_key, ValidationError, WG_KEY_LENGTH,
};
pub use ingress::{
    IngressError, IngressProcessor, RoutingDecision, WgIngressConfig, WgIngressManager,
    WgIngressStats,
};
pub use egress::{
    EgressError, EgressResult, EgressTunnelStatus, EgressTunnelType, WgEgressConfig,
    WgEgressManager, WgEgressStats, WgReplyHandler,
};
pub use chain::{
    ChainError, ChainManager, DscpAllocator, DscpRoutingCallback, NoOpRoutingCallback,
    PeerConnectivityCallback,
};
pub use dns::{
    analyze_negative_response, dns_classes, extract_soa_minimum, get_negative_cache_ttl,
    is_negative_response, record_types, BlockResponseType, BlockingConfig, CacheConfig, CacheEntry,
    CacheKey, CacheStats, CacheStatsSnapshot, DnsCache, DnsConfig, DnsError, DnsResult, LogFormat,
    LoggingConfig, NegativeAnalysis, NegativeCacheConfig, NegativeResponseType, RateLimitConfig,
    TcpServerConfig, UpstreamConfig, UpstreamProtocol,
};
pub use vless::{
    VlessAccount, VlessAccountManager, VlessAddons, VlessAddress, VlessCommand, VlessError,
    VlessRequestHeader, VlessResponseHeader, VLESS_VERSION, XTLS_VISION_FLOW,
};
pub use reality::{RealityConfig, RealityError, RealityResult};
pub use vision::{
    is_application_data, is_client_hello, is_server_hello, is_tls_traffic, is_valid_tls_version,
    parse_tls_record_header, VisionError, VisionResult, VisionState, HANDSHAKE_CLIENT_HELLO,
    HANDSHAKE_SERVER_HELLO, TLS_APPLICATION_DATA, TLS_HANDSHAKE, TLS_RECORD_HEADER_SIZE,
};
pub use transport::{
    connect, TcpTransport, TlsConfig, Transport, TransportConfig, TransportError, TransportStream,
    WebSocketConfig,
};
#[cfg(feature = "transport-tls")]
pub use transport::TlsTransport;
#[cfg(feature = "transport-ws")]
pub use transport::WebSocketTransport;
pub use vless_inbound::{
    AuthenticatedUser, InboundTlsConfig, VlessConnection, VlessConnectionHandler,
    VlessDestination, VlessInboundConfig, VlessInboundError, VlessInboundListener,
    VlessInboundResult, VlessInboundStats, VlessUser,
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
