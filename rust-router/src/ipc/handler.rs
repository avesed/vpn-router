//! IPC command handler
//!
//! This module processes IPC commands and generates responses.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use parking_lot::RwLock;

use tracing::{debug, info, trace, warn};

use super::protocol::{
    BufferPoolInfo, BufferPoolStatsResponse, ChainConfig, ChainDiagnosticsResponse,
    ChainListResponse, ChainRole, ChainRoleResponse, ChainState, DnsBlockStatsResponse,
    DnsCacheStatsResponse, DnsConfigResponse, DnsQueryLogResponse, DnsQueryResponse,
    DnsStatsResponse, DnsUpstreamInfo, DnsUpstreamStatusResponse, EcmpGroupListResponse,
    EcmpGroupStatus, EcmpMemberStatus, ErrorCode, IngressStatsResponse, IpcCommand, IpcResponse,
    OutboundInfo, OutboundStatsResponse, PairingResponse, PeerConfig, PeerListResponse, PeerState,
    PoolStatsResponse, PrepareResponse, PrometheusMetricsResponse, RuleStatsResponse,
    ServerCapabilities, ServerStatus, Socks5PoolStats, TunnelType, UdpProcessorInfo,
    UdpSessionInfo, UdpSessionResponse, UdpSessionStatsInfo, UdpSessionsResponse, UdpStatsResponse,
    UdpWorkerPoolInfo, UdpWorkerStatsResponse, WgTunnelListResponse, WgTunnelStatus,
};
use crate::chain::ChainManager;
use crate::dns::cache::DnsCache;
use crate::dns::client::UpstreamPool;
use crate::dns::filter::BlockFilter;
use crate::dns::log::QueryLogger;
use crate::dns::split::{DnsRouter, DomainMatchType};
use crate::dns::DnsConfig;
use crate::config::{load_config_with_env, OutboundConfig};
use crate::connection::{ConnectionManager, UdpSessionKey, UdpSessionManager};
use crate::ecmp::group::EcmpGroupManager;
use crate::egress::manager::WgEgressManager;
use crate::ingress::manager::WgIngressManager;
use crate::ingress::{ForwardingStats, IngressReplyStats, IngressSessionTracker};
use crate::io::UdpBufferPool;
use crate::outbound::{Outbound, OutboundManager};
use crate::peer::manager::PeerManager;
use crate::peer::pairing::PairRequestConfig;
use crate::rules::{ConnectionInfo, RuleEngine, RoutingSnapshotBuilder};
use crate::tproxy::UdpWorkerPool;

/// DNS engine component holder
///
/// This struct holds references to all DNS components needed for IPC command handling.
/// It provides a unified interface for DNS operations without exposing the internal
/// implementation details of each component.
pub struct DnsEngine {
    /// DNS cache for query result caching
    cache: Arc<DnsCache>,

    /// Upstream pool for DNS query forwarding
    upstream_pool: Arc<UpstreamPool>,

    /// Block filter for ad/tracker blocking
    block_filter: Arc<BlockFilter>,

    /// DNS router for split DNS routing
    router: Arc<DnsRouter>,

    /// Query logger for DNS query logging
    query_logger: Arc<QueryLogger>,

    /// DNS configuration
    config: DnsConfig,

    /// Engine start time for uptime calculation
    start_time: Instant,
}

impl DnsEngine {
    /// Create a new DNS engine with all components
    pub fn new(
        cache: Arc<DnsCache>,
        upstream_pool: Arc<UpstreamPool>,
        block_filter: Arc<BlockFilter>,
        router: Arc<DnsRouter>,
        query_logger: Arc<QueryLogger>,
        config: DnsConfig,
    ) -> Self {
        Self {
            cache,
            upstream_pool,
            block_filter,
            router,
            query_logger,
            config,
            start_time: Instant::now(),
        }
    }

    /// Get the uptime in seconds since the DNS engine started
    pub fn uptime_secs(&self) -> u64 {
        self.start_time.elapsed().as_secs()
    }

    /// Get a reference to the DNS cache
    pub fn cache(&self) -> &Arc<DnsCache> {
        &self.cache
    }

    /// Get a reference to the upstream pool
    pub fn upstream_pool(&self) -> &Arc<UpstreamPool> {
        &self.upstream_pool
    }

    /// Get a reference to the block filter
    pub fn block_filter(&self) -> &Arc<BlockFilter> {
        &self.block_filter
    }

    /// Get a reference to the DNS router
    pub fn router(&self) -> &Arc<DnsRouter> {
        &self.router
    }

    /// Get a reference to the query logger
    pub fn query_logger(&self) -> &Arc<QueryLogger> {
        &self.query_logger
    }

    /// Get the DNS configuration
    pub fn config(&self) -> &DnsConfig {
        &self.config
    }
}

/// IPC command handler
pub struct IpcHandler {
    /// Connection manager
    connection_manager: Arc<ConnectionManager>,

    /// Outbound manager
    outbound_manager: Arc<OutboundManager>,

    /// Rule engine for connection routing
    rule_engine: Arc<RuleEngine>,

    /// Server start time
    start_time: Instant,

    /// Server version
    version: String,

    /// Configuration version counter
    config_version: AtomicU64,

    /// Last reload timestamp (Unix epoch milliseconds)
    last_reload_timestamp: AtomicU64,

    // ========================================================================
    // UDP Components (Optional)
    // ========================================================================

    /// Whether UDP is enabled
    udp_enabled: bool,

    /// UDP session manager for tracking sessions
    udp_session_manager: Option<Arc<UdpSessionManager>>,

    /// UDP worker pool for multi-core packet processing
    udp_worker_pool: Option<Arc<UdpWorkerPool>>,

    /// UDP buffer pool for lock-free buffer management
    udp_buffer_pool: Option<Arc<UdpBufferPool>>,

    // ========================================================================
    // Chain Management Components
    // ========================================================================

    /// Chain manager for multi-hop routing
    chain_manager: Option<Arc<ChainManager>>,

    /// Local node tag for chain identification
    local_node_tag: String,

    // ========================================================================
    // Additional Manager Components
    // ========================================================================

    /// Peer manager for multi-node connections
    peer_manager: Option<Arc<PeerManager>>,

    /// ECMP group manager for load balancing
    ecmp_group_manager: Option<Arc<EcmpGroupManager>>,

    /// `WireGuard` ingress manager
    wg_ingress_manager: Option<Arc<WgIngressManager>>,

    /// `WireGuard` ingress forwarding stats
    ingress_forwarding_stats: Option<Arc<ForwardingStats>>,

    /// `WireGuard` ingress reply stats
    ingress_reply_stats: Option<Arc<IngressReplyStats>>,

    /// `WireGuard` ingress session tracker for active connection count
    /// Uses RwLock to allow setting after handler is created (Arc wrapped)
    ingress_session_tracker: RwLock<Option<Arc<IngressSessionTracker>>>,

    /// `WireGuard` egress manager
    wg_egress_manager: Option<Arc<WgEgressManager>>,

    // ========================================================================
    // DNS Engine Components
    // ========================================================================

    /// DNS engine for DNS query handling
    dns_engine: Option<Arc<DnsEngine>>,
}

impl IpcHandler {
    /// Create a new IPC handler
    pub fn new(
        connection_manager: Arc<ConnectionManager>,
        outbound_manager: Arc<OutboundManager>,
        rule_engine: Arc<RuleEngine>,
    ) -> Self {
        Self {
            connection_manager,
            outbound_manager,
            rule_engine,
            start_time: Instant::now(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            config_version: AtomicU64::new(1),
            last_reload_timestamp: AtomicU64::new(0),
            udp_enabled: false,
            udp_session_manager: None,
            udp_worker_pool: None,
            udp_buffer_pool: None,
            chain_manager: None,
            local_node_tag: String::from("local"),
            peer_manager: None,
            ecmp_group_manager: None,
            wg_ingress_manager: None,
            ingress_forwarding_stats: None,
            ingress_reply_stats: None,
            ingress_session_tracker: RwLock::new(None),
            wg_egress_manager: None,
            dns_engine: None,
        }
    }

    /// Create a new IPC handler with UDP components
    ///
    /// This enables UDP statistics and session management via IPC.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_udp(
        connection_manager: Arc<ConnectionManager>,
        outbound_manager: Arc<OutboundManager>,
        rule_engine: Arc<RuleEngine>,
        udp_session_manager: Arc<UdpSessionManager>,
        udp_worker_pool: Arc<UdpWorkerPool>,
        udp_buffer_pool: Arc<UdpBufferPool>,
    ) -> Self {
        Self {
            connection_manager,
            outbound_manager,
            rule_engine,
            start_time: Instant::now(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            config_version: AtomicU64::new(1),
            last_reload_timestamp: AtomicU64::new(0),
            udp_enabled: true,
            udp_session_manager: Some(udp_session_manager),
            udp_worker_pool: Some(udp_worker_pool),
            udp_buffer_pool: Some(udp_buffer_pool),
            chain_manager: None,
            local_node_tag: String::from("local"),
            peer_manager: None,
            ecmp_group_manager: None,
            wg_ingress_manager: None,
            ingress_forwarding_stats: None,
            ingress_reply_stats: None,
            ingress_session_tracker: RwLock::new(None),
            wg_egress_manager: None,
            dns_engine: None,
        }
    }

    /// Create a new IPC handler with chain manager
    ///
    /// This enables chain management commands.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_chain_manager(
        connection_manager: Arc<ConnectionManager>,
        outbound_manager: Arc<OutboundManager>,
        rule_engine: Arc<RuleEngine>,
        chain_manager: Arc<ChainManager>,
        local_node_tag: String,
    ) -> Self {
        Self {
            connection_manager,
            outbound_manager,
            rule_engine,
            start_time: Instant::now(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            config_version: AtomicU64::new(1),
            last_reload_timestamp: AtomicU64::new(0),
            udp_enabled: false,
            udp_session_manager: None,
            udp_worker_pool: None,
            udp_buffer_pool: None,
            chain_manager: Some(chain_manager),
            local_node_tag,
            peer_manager: None,
            ecmp_group_manager: None,
            wg_ingress_manager: None,
            ingress_forwarding_stats: None,
            ingress_reply_stats: None,
            ingress_session_tracker: RwLock::new(None),
            wg_egress_manager: None,
            dns_engine: None,
        }
    }

    /// Create a new IPC handler with all components
    ///
    /// This enables both UDP and chain management functionality.
    #[allow(clippy::too_many_arguments)]
    pub fn new_full(
        connection_manager: Arc<ConnectionManager>,
        outbound_manager: Arc<OutboundManager>,
        rule_engine: Arc<RuleEngine>,
        udp_session_manager: Arc<UdpSessionManager>,
        udp_worker_pool: Arc<UdpWorkerPool>,
        udp_buffer_pool: Arc<UdpBufferPool>,
        chain_manager: Arc<ChainManager>,
        local_node_tag: String,
    ) -> Self {
        Self {
            connection_manager,
            outbound_manager,
            rule_engine,
            start_time: Instant::now(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            config_version: AtomicU64::new(1),
            last_reload_timestamp: AtomicU64::new(0),
            udp_enabled: true,
            udp_session_manager: Some(udp_session_manager),
            udp_worker_pool: Some(udp_worker_pool),
            udp_buffer_pool: Some(udp_buffer_pool),
            chain_manager: Some(chain_manager),
            local_node_tag,
            peer_manager: None,
            ecmp_group_manager: None,
            wg_ingress_manager: None,
            ingress_forwarding_stats: None,
            ingress_reply_stats: None,
            ingress_session_tracker: RwLock::new(None),
            wg_egress_manager: None,
            dns_engine: None,
        }
    }

    /// Set the chain manager after construction
    ///
    /// This allows adding chain management capability to an existing handler.
    pub fn with_chain_manager(mut self, chain_manager: Arc<ChainManager>, local_node_tag: String) -> Self {
        self.chain_manager = Some(chain_manager);
        self.local_node_tag = local_node_tag;
        self
    }

    /// Set the peer manager after construction
    ///
    /// This allows adding peer management capability to an existing handler.
    pub fn with_peer_manager(mut self, peer_manager: Arc<PeerManager>) -> Self {
        self.peer_manager = Some(peer_manager);
        self
    }

    /// Set the ECMP group manager after construction
    ///
    /// This allows adding ECMP group management capability to an existing handler.
    pub fn with_ecmp_group_manager(mut self, ecmp_group_manager: Arc<EcmpGroupManager>) -> Self {
        self.ecmp_group_manager = Some(ecmp_group_manager);
        self
    }

    /// Set the `WireGuard` ingress manager after construction
    ///
    /// This allows adding `WireGuard` ingress capability to an existing handler.
    pub fn with_wg_ingress_manager(mut self, wg_ingress_manager: Arc<WgIngressManager>) -> Self {
        self.wg_ingress_manager = Some(wg_ingress_manager);
        self
    }

    /// Set ingress forwarding and reply statistics after construction
    pub fn with_ingress_stats(
        mut self,
        forwarding_stats: Arc<ForwardingStats>,
        reply_stats: Arc<IngressReplyStats>,
    ) -> Self {
        self.ingress_forwarding_stats = Some(forwarding_stats);
        self.ingress_reply_stats = Some(reply_stats);
        self
    }

    /// Set ingress session tracker after construction for active connection count
    pub fn with_ingress_session_tracker(
        self,
        session_tracker: Arc<IngressSessionTracker>,
    ) -> Self {
        *self.ingress_session_tracker.write() = Some(session_tracker);
        self
    }

    /// Set ingress session tracker on an already-created handler (via Arc)
    /// This is needed because session_tracker is created after the handler is wrapped in Arc
    pub fn set_ingress_session_tracker(&self, session_tracker: Arc<IngressSessionTracker>) {
        *self.ingress_session_tracker.write() = Some(session_tracker);
    }

    /// Set the `WireGuard` egress manager after construction
    ///
    /// This allows adding `WireGuard` egress capability to an existing handler.
    pub fn with_wg_egress_manager(mut self, wg_egress_manager: Arc<WgEgressManager>) -> Self {
        self.wg_egress_manager = Some(wg_egress_manager);
        self
    }

    /// Set the DNS engine after construction
    ///
    /// This allows adding DNS engine capability to an existing handler.
    pub fn with_dns_engine(mut self, dns_engine: Arc<DnsEngine>) -> Self {
        self.dns_engine = Some(dns_engine);
        self
    }

    /// Get a reference to the DNS engine (if available)
    pub fn dns_engine(&self) -> Option<&Arc<DnsEngine>> {
        self.dns_engine.as_ref()
    }

    /// Create a new IPC handler with a default (empty) rule engine
    ///
    /// This is useful for testing or when rules are not yet configured.
    pub fn new_with_default_rules(
        connection_manager: Arc<ConnectionManager>,
        outbound_manager: Arc<OutboundManager>,
    ) -> Self {
        let snapshot = RoutingSnapshotBuilder::new()
            .default_outbound("direct")
            .version(1)
            .build()
            .expect("Failed to create default routing snapshot");
        let rule_engine = Arc::new(RuleEngine::new(snapshot));

        Self::new(connection_manager, outbound_manager, rule_engine)
    }

    /// Get a reference to the chain manager (if available)
    pub fn chain_manager(&self) -> Option<&Arc<ChainManager>> {
        self.chain_manager.as_ref()
    }

    /// Get the local node tag
    pub fn local_node_tag(&self) -> &str {
        &self.local_node_tag
    }

    /// Check if an outbound tag is valid (exists in outbound_manager or wg_egress_manager,
    /// or is a WireGuard-prefixed tag that will be added via IPC).
    ///
    /// This fixes the routing validation bug where WireGuard outbounds
    /// in wg_egress_manager were not recognized, causing all traffic to fall back to "direct".
    fn is_valid_outbound_tag(&self, tag: &str) -> bool {
        // Check outbound_manager first (Direct/SOCKS5 outbounds)
        if self.outbound_manager.get(tag).is_some() {
            return true;
        }

        // Check wg_egress_manager for existing WireGuard tunnels
        if let Some(ref egress_mgr) = self.wg_egress_manager {
            if egress_mgr.has_tunnel(tag) {
                return true;
            }
        }

        // Check ecmp_group_manager for ECMP groups
        if let Some(ref ecmp_mgr) = self.ecmp_group_manager {
            if ecmp_mgr.has_group(tag) {
                return true;
            }
        }

        // Check chain_manager for multi-hop chains
        // Only ACTIVE chains can be used as outbounds (they're registered in FwmarkRouter)
        // Inactive chains exist but can't route traffic properly
        if let Some(ref chain_mgr) = self.chain_manager {
            if chain_mgr.is_chain_active(tag) {
                return true;
            }
        }

        // Allow WireGuard-prefixed tags that may be added later via IPC
        // These prefixes match the forwarder's is_wg_egress check
        if tag.starts_with("wg-")
            || tag.starts_with("pia-")
            || tag.starts_with("peer-")
        {
            return true;
        }

        // Also check "block" and "adblock" special tags
        if tag == "block" || tag == "adblock" {
            return true;
        }

        false
    }

    /// Handle an IPC command and return a response
    pub async fn handle(&self, command: IpcCommand) -> IpcResponse {
        debug!("Handling IPC command: {:?}", command);

        match command {
            IpcCommand::Ping => IpcResponse::Pong,

            IpcCommand::Status => self.handle_status(),

            IpcCommand::GetCapabilities => IpcResponse::Capabilities(ServerCapabilities::default()),

            IpcCommand::GetStats => self.handle_get_stats(),

            IpcCommand::GetOutboundStats => self.handle_get_outbound_stats(),

            IpcCommand::Reload { config_path } => self.handle_reload(&config_path).await,

            IpcCommand::AddOutbound { config } => self.handle_add_outbound(config),

            IpcCommand::RemoveOutbound { tag } => self.handle_remove_outbound(&tag),

            IpcCommand::EnableOutbound { tag } => self.handle_enable_outbound(&tag, true),

            IpcCommand::DisableOutbound { tag } => self.handle_enable_outbound(&tag, false),

            IpcCommand::GetOutbound { tag } => self.handle_get_outbound(&tag),

            IpcCommand::ListOutbounds => self.handle_list_outbounds(),

            IpcCommand::Shutdown { drain_timeout_secs } => {
                self.handle_shutdown(drain_timeout_secs).await
            }

            IpcCommand::TestMatch {
                domain,
                dest_ip,
                dest_port,
                protocol,
                sniffed_protocol,
            } => self.handle_test_match(domain, dest_ip, dest_port, protocol, sniffed_protocol),

            IpcCommand::GetRuleStats => self.handle_get_rule_stats(),

            IpcCommand::ReloadRules { config_path } => self.handle_reload_rules(config_path).await,

            IpcCommand::AddSocks5Outbound {
                tag,
                server_addr,
                username,
                password,
                connect_timeout_secs,
                idle_timeout_secs,
                pool_max_size,
            } => {
                self.handle_add_socks5_outbound(
                    tag,
                    server_addr,
                    username,
                    password,
                    connect_timeout_secs,
                    idle_timeout_secs,
                    pool_max_size,
                )
                .await
            }

            IpcCommand::GetPoolStats { tag } => self.handle_get_pool_stats(tag),

            // ================================================================
            // IPC Protocol v2.1 Command Handlers
            // ================================================================
            IpcCommand::AddWireguardOutbound {
                tag,
                interface,
                routing_mark,
                routing_table,
            } => self.handle_add_wireguard_outbound(tag, interface, routing_mark, routing_table),

            IpcCommand::DrainOutbound { tag, timeout_secs } => {
                self.handle_drain_outbound(tag, timeout_secs).await
            }

            IpcCommand::UpdateRouting {
                rules,
                default_outbound,
            } => self.handle_update_routing(rules, default_outbound),

            IpcCommand::SetDefaultOutbound { tag } => self.handle_set_default_outbound(tag),

            IpcCommand::GetOutboundHealth => self.handle_get_outbound_health(),

            IpcCommand::NotifyEgressChange {
                action,
                tag,
                egress_type,
            } => self.handle_notify_egress_change(action, tag, egress_type),

            IpcCommand::GetPrometheusMetrics => self.handle_get_prometheus_metrics(),

            // ================================================================
            // UDP IPC Command Handlers
            // ================================================================
            IpcCommand::GetUdpStats => self.handle_get_udp_stats(),

            IpcCommand::ListUdpSessions { limit } => self.handle_list_udp_sessions(limit),

            IpcCommand::GetUdpSession {
                client_addr,
                dest_addr,
            } => self.handle_get_udp_session(&client_addr, &dest_addr),

            IpcCommand::GetUdpWorkerStats => self.handle_get_udp_worker_stats(),

            IpcCommand::GetBufferPoolStats => self.handle_get_buffer_pool_stats(),

            // ================================================================
            // IPC Protocol v3.2 Command Handlers
            // ================================================================

            // WireGuard Tunnel Management (userspace WireGuard)
            IpcCommand::CreateWgTunnel { tag, config } => {
                self.handle_create_wg_tunnel(tag, config).await
            }
            IpcCommand::RemoveWgTunnel { tag, drain_timeout_secs } => {
                self.handle_remove_wg_tunnel(&tag, drain_timeout_secs).await
            }
            IpcCommand::GetWgTunnelStatus { tag } => {
                self.handle_get_wg_tunnel_status(&tag)
            }
            IpcCommand::ListWgTunnels => {
                self.handle_list_wg_tunnels()
            }

            // Ingress Peer Management
            IpcCommand::AddIngressPeer { public_key, allowed_ips, name, preshared_key } => {
                self.handle_add_ingress_peer(public_key, allowed_ips, name, preshared_key).await
            }
            IpcCommand::RemoveIngressPeer { public_key } => {
                self.handle_remove_ingress_peer(public_key).await
            }
            IpcCommand::ListIngressPeers => {
                self.handle_list_ingress_peers()
            }
            IpcCommand::GetIngressStats => {
                self.handle_get_ingress_stats()
            }

            // ECMP Group Management
            IpcCommand::CreateEcmpGroup { tag, config } => {
                self.handle_create_ecmp_group(tag, config)
            }
            IpcCommand::RemoveEcmpGroup { tag } => {
                self.handle_remove_ecmp_group(&tag)
            }
            IpcCommand::GetEcmpGroupStatus { tag } => {
                self.handle_get_ecmp_group_status(&tag)
            }
            IpcCommand::ListEcmpGroups => {
                self.handle_list_ecmp_groups()
            }
            IpcCommand::UpdateEcmpGroupMembers { tag, members } => {
                self.handle_update_ecmp_group_members(&tag, members)
            }

            // Peer Management
            IpcCommand::GeneratePairRequest {
                local_tag,
                local_description,
                local_endpoint,
                local_api_port,
                bidirectional,
                tunnel_type,
            } => {
                self.handle_generate_pair_request(
                    local_tag,
                    local_description,
                    local_endpoint,
                    local_api_port,
                    bidirectional,
                    tunnel_type,
                )
            }
            IpcCommand::ImportPairRequest {
                code,
                local_tag,
                local_description,
                local_endpoint,
                local_api_port,
            } => {
                self.handle_import_pair_request(
                    code,
                    local_tag,
                    local_description,
                    local_endpoint,
                    local_api_port,
                ).await
            }
            IpcCommand::CompleteHandshake { code } => {
                self.handle_complete_handshake(code).await
            }
            IpcCommand::AddPeer { config } => {
                self.handle_add_peer(config).await
            }
            IpcCommand::ConnectPeer { tag } => {
                self.handle_connect_peer(&tag).await
            }
            IpcCommand::DisconnectPeer { tag } => {
                self.handle_disconnect_peer(&tag).await
            }
            IpcCommand::GetPeerStatus { tag } => {
                self.handle_get_peer_status(&tag)
            }
            IpcCommand::GetPeerTunnelHealth { tag } => {
                self.handle_get_peer_tunnel_health(&tag)
            }
            IpcCommand::ListPeers => {
                self.handle_list_peers()
            }
            IpcCommand::RemovePeer { tag } => {
                self.handle_remove_peer(&tag).await
            }

            // ================================================================
            // Chain Management Command Handlers
            // ================================================================
            IpcCommand::CreateChain { tag, config } => {
                self.handle_create_chain(tag, config).await
            }
            IpcCommand::RemoveChain { tag } => {
                self.handle_remove_chain(&tag).await
            }
            IpcCommand::ActivateChain { tag } => {
                self.handle_activate_chain(&tag).await
            }
            IpcCommand::DeactivateChain { tag } => {
                self.handle_deactivate_chain(&tag).await
            }
            IpcCommand::GetChainStatus { tag } => {
                self.handle_get_chain_status(&tag)
            }
            IpcCommand::ListChains => {
                self.handle_list_chains()
            }
            IpcCommand::GetChainRole { chain_tag } => {
                self.handle_get_chain_role(&chain_tag)
            }
            IpcCommand::DiagnoseChain { tag } => {
                self.handle_diagnose_chain(&tag)
            }
            IpcCommand::UpdateChainState { tag, state, last_error } => {
                self.handle_update_chain_state(&tag, state, last_error)
            }
            IpcCommand::UpdateChain { tag, hops, exit_egress, description, allow_transitive } => {
                self.handle_update_chain(tag, hops, exit_egress, description, allow_transitive).await
            }

            // ================================================================
            // Two-Phase Commit Command Handlers
            // ================================================================
            IpcCommand::PrepareChainRoute { chain_tag, config, source_node } => {
                self.handle_prepare_chain_route(&chain_tag, config, &source_node).await
            }
            IpcCommand::CommitChainRoute { chain_tag, source_node } => {
                self.handle_commit_chain_route(&chain_tag, &source_node).await
            }
            IpcCommand::AbortChainRoute { chain_tag, source_node } => {
                self.handle_abort_chain_route(&chain_tag, &source_node).await
            }

            // ================================================================
            // DNS Command Handlers
            // ================================================================
            IpcCommand::GetDnsStats => {
                self.handle_get_dns_stats()
            }
            IpcCommand::GetDnsCacheStats => {
                self.handle_get_dns_cache_stats()
            }
            IpcCommand::FlushDnsCache { pattern } => {
                self.handle_flush_dns_cache(pattern)
            }
            IpcCommand::GetDnsBlockStats => {
                self.handle_get_dns_block_stats()
            }
            IpcCommand::ReloadDnsBlocklist => {
                self.handle_reload_dns_blocklist()
            }
            IpcCommand::AddDnsUpstream { tag, config } => {
                self.handle_add_dns_upstream(tag, config).await
            }
            IpcCommand::RemoveDnsUpstream { tag } => {
                self.handle_remove_dns_upstream(&tag).await
            }
            IpcCommand::GetDnsUpstreamStatus { tag } => {
                self.handle_get_dns_upstream_status(tag)
            }
            IpcCommand::AddDnsRoute { pattern, match_type, upstream_tag } => {
                self.handle_add_dns_route(pattern, match_type, upstream_tag)
            }
            IpcCommand::RemoveDnsRoute { pattern } => {
                self.handle_remove_dns_route(&pattern)
            }
            IpcCommand::GetDnsQueryLog { limit, offset } => {
                self.handle_get_dns_query_log(limit, offset)
            }
            IpcCommand::DnsQuery { domain, qtype, upstream } => {
                self.handle_dns_query(&domain, qtype, upstream).await
            }
            IpcCommand::GetDnsConfig => {
                self.handle_get_dns_config()
            }

            // ================================================================
            // WARP Registration Command Handler
            // ================================================================
            IpcCommand::RegisterWarp { tag, name, warp_plus_license } => {
                self.handle_register_warp(tag, name, warp_plus_license).await
            }

            // ================================================================
            // Speed Test Command Handler
            // ================================================================
            IpcCommand::SpeedTest { tag, size_bytes, timeout_secs } => {
                self.handle_speed_test(tag, size_bytes, timeout_secs).await
            }

            // ================================================================
            // Peer API Forwarding Command Handler
            // ================================================================
            IpcCommand::ForwardPeerRequest { peer_tag, method, path, body, timeout_secs, endpoint, tunnel_type, api_port, tunnel_ip, tunnel_local_ip, headers } => {
                self.handle_forward_peer_request(peer_tag, method, path, body, timeout_secs, endpoint, tunnel_type, api_port, tunnel_ip, tunnel_local_ip, headers).await
            }
        }
    }

    /// Handle status command
    fn handle_status(&self) -> IpcResponse {
        let stats = self.connection_manager.stats_snapshot();

        IpcResponse::Status(ServerStatus {
            version: self.version.clone(),
            uptime_secs: self.start_time.elapsed().as_secs(),
            active_connections: stats.active,
            total_connections: stats.total_accepted,
            outbound_count: self.outbound_manager.len(),
            accepting: !self.connection_manager.is_shutting_down(),
            shutting_down: self.connection_manager.is_shutting_down(),
        })
    }

    /// Handle get stats command
    fn handle_get_stats(&self) -> IpcResponse {
        IpcResponse::Stats(self.connection_manager.stats_snapshot())
    }

    /// Handle get outbound stats command
    fn handle_get_outbound_stats(&self) -> IpcResponse {
        IpcResponse::OutboundStats(OutboundStatsResponse {
            outbounds: self.outbound_manager.stats_summary(),
        })
    }

    /// Handle reload command
    async fn handle_reload(&self, config_path: &str) -> IpcResponse {
        info!("Reloading configuration from: {}", config_path);

        // Load new configuration
        let config = match load_config_with_env(config_path) {
            Ok(c) => c,
            Err(e) => {
                warn!("Failed to load config: {}", e);
                return IpcResponse::error(
                    ErrorCode::OperationFailed,
                    format!("Failed to load configuration: {e}"),
                );
            }
        };

        // Update outbounds
        // Note: This is a simplified implementation. A full implementation would
        // need to carefully handle in-flight connections.

        // Remove outbounds that no longer exist
        let new_tags: std::collections::HashSet<_> =
            config.outbounds.iter().map(|o| o.tag.as_str()).collect();
        let current_tags = self.outbound_manager.tags();

        for tag in current_tags {
            if !new_tags.contains(tag.as_str()) {
                self.outbound_manager.remove(&tag);
            }
        }

        // Add or update outbounds
        for outbound_config in &config.outbounds {
            if self.outbound_manager.contains(&outbound_config.tag) {
                // For simplicity, remove and re-add
                self.outbound_manager.remove(&outbound_config.tag);
            }

            // Add the outbound directly based on type
            use crate::config::OutboundType;
            let outbound: Box<dyn super::super::outbound::Outbound> = match outbound_config.outbound_type {
                OutboundType::Direct => {
                    Box::new(crate::outbound::DirectOutbound::new(outbound_config.clone()))
                }
                OutboundType::Block => {
                    Box::new(crate::outbound::BlockOutbound::from_config(outbound_config))
                }
            };
            self.outbound_manager.add(outbound);
        }

        IpcResponse::success_with_message("Configuration reloaded")
    }

    /// Handle add outbound command
    fn handle_add_outbound(&self, config: OutboundConfig) -> IpcResponse {
        if self.outbound_manager.contains(&config.tag) {
            return IpcResponse::error(
                ErrorCode::AlreadyExists,
                format!("Outbound '{}' already exists", config.tag),
            );
        }

        // Validate configuration
        if let Err(e) = config.validate() {
            return IpcResponse::error(ErrorCode::InvalidParameters, e.to_string());
        }

        // Create and add outbound based on type
        use crate::config::OutboundType;
        let outbound: Box<dyn super::super::outbound::Outbound> = match config.outbound_type {
            OutboundType::Direct => {
                Box::new(crate::outbound::DirectOutbound::new(config.clone()))
            }
            OutboundType::Block => {
                Box::new(crate::outbound::BlockOutbound::from_config(&config))
            }
        };
        self.outbound_manager.add(outbound);

        info!("Added outbound: {}", config.tag);
        IpcResponse::success_with_message(format!("Outbound '{}' added", config.tag))
    }

    /// Handle remove outbound command
    fn handle_remove_outbound(&self, tag: &str) -> IpcResponse {
        if !self.outbound_manager.contains(tag) {
            return IpcResponse::error(
                ErrorCode::NotFound,
                format!("Outbound '{tag}' not found"),
            );
        }

        // Check if outbound has active connections
        if let Some(outbound) = self.outbound_manager.get(tag) {
            let stats = outbound.stats();
            if stats.active() > 0 {
                warn!(
                    "Removing outbound '{}' with {} active connections",
                    tag,
                    stats.active()
                );
            }
        }

        self.outbound_manager.remove(tag);
        info!("Removed outbound: {}", tag);
        IpcResponse::success_with_message(format!("Outbound '{tag}' removed"))
    }

    /// Handle enable/disable outbound command
    fn handle_enable_outbound(&self, tag: &str, enable: bool) -> IpcResponse {
        // Note: Current implementation doesn't support runtime enable/disable
        // This would require modifying the Outbound trait
        if !self.outbound_manager.contains(tag) {
            return IpcResponse::error(
                ErrorCode::NotFound,
                format!("Outbound '{tag}' not found"),
            );
        }

        let action = if enable { "enabled" } else { "disabled" };
        info!("Outbound '{}' {}", tag, action);
        IpcResponse::success_with_message(format!("Outbound '{tag}' {action}"))
    }

    /// Handle get outbound command
    fn handle_get_outbound(&self, tag: &str) -> IpcResponse {
        match self.outbound_manager.get(tag) {
            Some(outbound) => {
                let stats = outbound.stats();
                IpcResponse::OutboundInfo(OutboundInfo {
                    tag: outbound.tag().to_string(),
                    outbound_type: outbound.outbound_type().to_string(),
                    enabled: outbound.is_enabled(),
                    health: outbound.health_status().to_string(),
                    active_connections: stats.active(),
                    total_connections: stats.connections(),
                    bind_interface: None, // Would need to expose this in Outbound trait
                    routing_mark: None,
                })
            }
            None => IpcResponse::error(ErrorCode::NotFound, format!("Outbound '{tag}' not found")),
        }
    }

    /// Handle list outbounds command
    ///
    /// Now includes `WgEgressManager` tunnels in addition to
    /// `OutboundManager` outbounds.
    fn handle_list_outbounds(&self) -> IpcResponse {
        let mut outbounds: Vec<OutboundInfo> = self
            .outbound_manager
            .all()
            .iter()
            .map(|o| {
                let stats = o.stats();
                OutboundInfo {
                    tag: o.tag().to_string(),
                    outbound_type: o.outbound_type().to_string(),
                    enabled: o.is_enabled(),
                    health: o.health_status().to_string(),
                    active_connections: stats.active(),
                    total_connections: stats.connections(),
                    bind_interface: None,
                    routing_mark: None,
                }
            })
            .collect();

        // Include userspace WireGuard egress tunnels
        if let Some(egress_manager) = &self.wg_egress_manager {
            let tunnel_tags = egress_manager.list_tunnels();
            for tag in tunnel_tags {
                if let Some(status) = egress_manager.get_tunnel_status(&tag) {
                    outbounds.push(OutboundInfo {
                        tag: status.tag.clone(),
                        outbound_type: "wireguard".to_string(),
                        enabled: status.connected,
                        health: if status.connected { "healthy".to_string() } else { "unhealthy".to_string() },
                        active_connections: 0,
                        total_connections: status.stats.tx_packets,
                        bind_interface: None,
                        routing_mark: None,
                    });
                }
            }
        }

        IpcResponse::OutboundList { outbounds }
    }

    /// Handle shutdown command
    async fn handle_shutdown(&self, drain_timeout_secs: Option<u32>) -> IpcResponse {
        info!(
            "Shutdown requested (drain timeout: {:?}s)",
            drain_timeout_secs
        );

        // Note: The actual shutdown is handled by the IPC server
        // This just returns a success response before shutdown begins
        IpcResponse::success_with_message("Shutdown initiated")
    }

    /// Handle test match command
    ///
    /// This is used for debugging and parity testing with the Python reference.
    fn handle_test_match(
        &self,
        domain: Option<String>,
        dest_ip: Option<String>,
        dest_port: u16,
        protocol: String,
        sniffed_protocol: Option<String>,
    ) -> IpcResponse {
        use super::protocol::TestMatchResult;

        let start = Instant::now();

        // Parse destination IP if provided
        let parsed_ip = dest_ip.as_ref().and_then(|s| s.parse().ok());

        // Convert protocol string to static str
        let protocol_static: &'static str = match protocol.to_lowercase().as_str() {
            "tcp" => "tcp",
            "udp" => "udp",
            _ => "tcp", // Default to TCP
        };

        // Convert sniffed protocol
        let sniffed_static: Option<&'static str> = sniffed_protocol.as_ref().map(|s| {
            match s.to_lowercase().as_str() {
                "tls" => "tls",
                "http" => "http",
                "quic" => "quic",
                _ => "unknown",
            }
        });

        // Build ConnectionInfo for rule matching
        let conn = ConnectionInfo {
            domain: domain.clone(),
            dest_ip: parsed_ip,
            dest_port,
            source_ip: None,
            protocol: protocol_static,
            sniffed_protocol: sniffed_static,
        };

        // Perform rule matching
        let result = self.rule_engine.match_connection(&conn);

        let match_time_us = start.elapsed().as_micros() as u64;

        // Determine match type string
        let match_type = result.matched_rule.as_ref().map(|m| match m {
            crate::rules::MatchedRule::Domain(_) => "domain".to_string(),
            crate::rules::MatchedRule::GeoIP(_) => "geoip".to_string(),
            crate::rules::MatchedRule::Rule(_) => "rule".to_string(),
        });

        // Check if the matched outbound is a chain
        let is_chain = result.routing_mark.is_some();

        debug!(
            "TestMatch: domain={:?}, ip={:?}, port={}, proto={}, sniffed={:?} -> {} ({}us, match_type={:?})",
            domain, dest_ip, dest_port, protocol, sniffed_protocol, result.outbound, match_time_us, match_type
        );

        IpcResponse::TestMatchResult(TestMatchResult {
            outbound: result.outbound,
            match_type,
            routing_mark: result.routing_mark,
            is_chain,
            match_time_us,
        })
    }

    /// Handle get rule stats command
    fn handle_get_rule_stats(&self) -> IpcResponse {
        let snapshot = self.rule_engine.load();
        let stats = snapshot.stats();

        // Count port and protocol rules separately from compiled rules
        let mut port_rules = 0u64;
        let mut protocol_rules = 0u64;
        for rule in snapshot.rules.iter() {
            match rule.rule_type {
                crate::rules::RuleType::Port => port_rules += 1,
                crate::rules::RuleType::Protocol => protocol_rules += 1,
                _ => {}
            }
        }

        // Get last reload timestamp
        let last_reload_ts = self.last_reload_timestamp.load(Ordering::Relaxed);
        let last_reload = if last_reload_ts > 0 {
            // Convert Unix timestamp (milliseconds) to seconds and format
            let secs = last_reload_ts / 1000;
            Some(chrono_lite_format(secs))
        } else {
            None
        };

        IpcResponse::RuleStats(RuleStatsResponse {
            domain_rules: stats.domain_rules as u64,
            geoip_rules: stats.geoip_rules as u64,
            port_rules,
            protocol_rules,
            chain_count: stats.chains as u64,
            config_version: self.config_version.load(Ordering::Relaxed),
            last_reload,
            default_outbound: snapshot.default_outbound.clone(),
        })
    }

    /// Handle reload rules command
    async fn handle_reload_rules(&self, config_path: Option<String>) -> IpcResponse {
        info!(
            "Reloading rules from: {:?}",
            config_path.as_deref().unwrap_or("<current config>")
        );

        // For now, we just increment the version and update the timestamp
        // Full rule loading from config will be implemented when rule config schema is defined
        let new_version = self.config_version.fetch_add(1, Ordering::Relaxed) + 1;

        // Update last reload timestamp
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        self.last_reload_timestamp.store(now, Ordering::Relaxed);

        // If config path provided, attempt to load rules
        if let Some(path) = config_path {
            // Note: Full implementation would parse rules from config file
            // For now, just log the attempt
            info!("Would load rules from: {} (not yet implemented)", path);
        }

        IpcResponse::success_with_message(format!(
            "Rules reloaded (version {new_version})"
        ))
    }

    /// Handle add SOCKS5 outbound command
    #[allow(clippy::too_many_arguments)]
    async fn handle_add_socks5_outbound(
        &self,
        tag: String,
        server_addr: String,
        username: Option<String>,
        password: Option<String>,
        connect_timeout_secs: u64,
        idle_timeout_secs: u64,
        pool_max_size: usize,
    ) -> IpcResponse {
        // Check if outbound already exists
        if self.outbound_manager.contains(&tag) {
            return IpcResponse::error(
                ErrorCode::AlreadyExists,
                format!("Outbound '{tag}' already exists"),
            );
        }

        // Parse server address
        let socks5_addr: std::net::SocketAddr = match server_addr.parse() {
            Ok(addr) => addr,
            Err(e) => {
                return IpcResponse::error(
                    ErrorCode::InvalidParameters,
                    format!("Invalid server address '{server_addr}': {e}"),
                );
            }
        };

        // Create SOCKS5 configuration
        let mut config = crate::outbound::Socks5Config::new(&tag, socks5_addr)
            .with_connect_timeout(connect_timeout_secs)
            .with_idle_timeout(idle_timeout_secs)
            .with_pool_size(pool_max_size);

        // Add authentication if provided
        if let (Some(user), Some(pass)) = (username, password) {
            config = config.with_auth(user, pass);
        }

        // Create SOCKS5 outbound
        let outbound = match crate::outbound::Socks5Outbound::new(config).await {
            Ok(o) => o,
            Err(e) => {
                return IpcResponse::error(
                    ErrorCode::OperationFailed,
                    format!("Failed to create SOCKS5 outbound: {e}"),
                );
            }
        };

        // Add to outbound manager
        self.outbound_manager.add(Box::new(outbound));

        info!("Added SOCKS5 outbound '{}' -> {}", tag, server_addr);
        IpcResponse::success_with_message(format!("SOCKS5 outbound '{tag}' added"))
    }

    /// Handle get pool stats command
    fn handle_get_pool_stats(&self, tag: Option<String>) -> IpcResponse {
        let mut pools = Vec::new();

        if let Some(specific_tag) = tag {
            // Get stats for specific outbound
            match self.outbound_manager.get(&specific_tag) {
                Some(outbound) => {
                    if outbound.outbound_type() == "socks5" {
                        // Use trait methods to get pool and server info
                        let pool_info = outbound.pool_stats_info().unwrap_or_default();
                        let server_info = outbound.proxy_server_info();

                        pools.push(Socks5PoolStats {
                            tag: outbound.tag().to_string(),
                            size: pool_info.size,
                            available: pool_info.available,
                            waiting: pool_info.waiting,
                            server_addr: server_info.map(|s| s.address).unwrap_or_default(),
                            enabled: outbound.is_enabled(),
                            health: outbound.health_status().to_string(),
                        });
                    } else {
                        return IpcResponse::error(
                            ErrorCode::InvalidParameters,
                            format!("Outbound '{specific_tag}' is not a SOCKS5 outbound"),
                        );
                    }
                }
                None => {
                    return IpcResponse::error(
                        ErrorCode::NotFound,
                        format!("Outbound '{specific_tag}' not found"),
                    );
                }
            }
        } else {
            // Get stats for all SOCKS5 outbounds
            for outbound in self.outbound_manager.all() {
                if outbound.outbound_type() == "socks5" {
                    let pool_info = outbound.pool_stats_info().unwrap_or_default();
                    let server_info = outbound.proxy_server_info();

                    pools.push(Socks5PoolStats {
                        tag: outbound.tag().to_string(),
                        size: pool_info.size,
                        available: pool_info.available,
                        waiting: pool_info.waiting,
                        server_addr: server_info.map(|s| s.address).unwrap_or_default(),
                        enabled: outbound.is_enabled(),
                        health: outbound.health_status().to_string(),
                    });
                }
            }
        }

        IpcResponse::PoolStats(PoolStatsResponse { pools })
    }

    // ========================================================================
    // IPC Protocol v2.1 Handler Implementations
    // ========================================================================

    /// Handle add `WireGuard` outbound command
    ///
    /// Creates a `DirectOutbound` bound to a `WireGuard` interface.
    fn handle_add_wireguard_outbound(
        &self,
        tag: String,
        interface: String,
        routing_mark: Option<u32>,
        routing_table: Option<u32>,
    ) -> IpcResponse {
        use crate::outbound::wireguard;

        // Check if outbound already exists
        if self.outbound_manager.get(&tag).is_some() {
            return IpcResponse::error(
                ErrorCode::AlreadyExists,
                format!("Outbound '{tag}' already exists"),
            );
        }

        // Validate interface exists
        if let Err(e) = wireguard::validate_interface_exists(&interface) {
            return IpcResponse::error(
                ErrorCode::InvalidParameters,
                format!("WireGuard interface validation failed: {e}"),
            );
        }

        // Create DirectOutbound with bind_interface
        let config = crate::config::OutboundConfig {
            tag: tag.clone(),
            outbound_type: crate::config::OutboundType::Direct,
            bind_interface: Some(interface.clone()),
            bind_address: None,
            routing_mark,
            connect_timeout_secs: 10,
            enabled: true,
        };

        // Store routing_table in the config for policy routing
        // Note: routing_table is used by iptables/ip rules, not directly by the outbound
        let _ = routing_table; // Suppress unused warning - stored for reference

        // DirectOutbound::new() returns DirectOutbound directly (not a Result)
        let outbound = crate::outbound::DirectOutbound::new(config);

        self.outbound_manager.add(Box::new(outbound));

        info!(
            "Added WireGuard outbound '{}' -> interface '{}' (mark={:?})",
            tag, interface, routing_mark
        );
        IpcResponse::success_with_message(format!("WireGuard outbound '{tag}' added"))
    }

    /// Handle drain outbound command
    ///
    /// Gracefully drains connections before removal.
    async fn handle_drain_outbound(&self, tag: String, timeout_secs: u32) -> IpcResponse {
        use super::protocol::DrainResponse;
        use std::time::{Duration, Instant};

        let start = Instant::now();

        // Check if outbound exists
        let outbound = match self.outbound_manager.get(&tag) {
            Some(o) => o,
            None => {
                return IpcResponse::error(
                    ErrorCode::NotFound,
                    format!("Outbound '{tag}' not found"),
                );
            }
        };

        // Disable the outbound to stop accepting new connections
        outbound.set_enabled(false);

        // Get initial active connection count
        let initial_count = outbound.active_connections();

        // Wait for connections to drain
        let timeout = Duration::from_secs(u64::from(timeout_secs));
        let poll_interval = Duration::from_millis(100);
        let deadline = start + timeout;

        let mut drained_count = 0u64;
        let mut force_closed_count = 0u64;

        while Instant::now() < deadline {
            let active = outbound.active_connections();
            if active == 0 {
                drained_count = initial_count;
                break;
            }
            drained_count = initial_count.saturating_sub(active);
            tokio::time::sleep(poll_interval).await;
        }

        // Force close any remaining connections
        let remaining = outbound.active_connections();
        if remaining > 0 {
            // In a real implementation, we would cancel active connections here
            force_closed_count = remaining;
            warn!(
                "Force closing {} remaining connections for outbound '{}'",
                remaining, tag
            );
        }

        // Remove the outbound
        if self.outbound_manager.remove(&tag).is_none() {
            return IpcResponse::error(
                ErrorCode::OperationFailed,
                format!("Failed to remove outbound '{tag}' after drain"),
            );
        }

        let drain_time_ms = start.elapsed().as_millis() as u64;

        info!(
            "Drained outbound '{}': {} drained, {} force-closed in {}ms",
            tag, drained_count, force_closed_count, drain_time_ms
        );

        IpcResponse::DrainResult(DrainResponse {
            success: true,
            drained_count,
            force_closed_count,
            drain_time_ms,
        })
    }

    /// Handle update routing command
    ///
    /// Atomically updates routing rules via `ArcSwap`.
    ///
    /// Properly rebuilds `domain_matcher` and `geoip_matcher`
    /// using `RoutingSnapshotBuilder` instead of just cloning existing matchers.
    /// This ensures domain/geoip rules are actually matched by the high-performance
    /// Aho-Corasick and CIDR matchers.
    fn handle_update_routing(
        &self,
        rules: Vec<super::protocol::RuleConfig>,
        default_outbound: String,
    ) -> IpcResponse {
        use super::protocol::UpdateRoutingResponse;
        use crate::rules::RuleType;

        // Validate default outbound exists (check both managers + WG prefixes)
        if !self.is_valid_outbound_tag(&default_outbound) {
            return IpcResponse::error(
                ErrorCode::NotFound,
                format!("Default outbound '{default_outbound}' not found"),
            );
        }

        // Atomically increment version BEFORE creating snapshot to prevent race condition
        let new_version = self.config_version.fetch_add(1, Ordering::SeqCst) + 1;

        // Load current snapshot to preserve fwmark router (chain configurations)
        let current = self.rule_engine.load();

        // Use RoutingSnapshotBuilder to properly build domain_matcher and geoip_matcher
        // This is the key fix - we must use the builder to add rules
        // to their respective matchers, not just compile them into CompiledRuleSet
        let mut builder = RoutingSnapshotBuilder::new()
            .default_outbound(&default_outbound)
            .version(new_version);

        // Track rule count for response
        let mut rule_count = 0usize;

        for rule_cfg in &rules {
            if !rule_cfg.enabled {
                continue;
            }

            // Validate outbound exists (check both managers + WG prefixes)
            if !self.is_valid_outbound_tag(&rule_cfg.outbound) {
                return IpcResponse::error(
                    ErrorCode::NotFound,
                    format!("Rule references unknown outbound '{}'", rule_cfg.outbound),
                );
            }

            let rule_type = match rule_cfg.rule_type.as_str() {
                "domain" => RuleType::Domain,
                "domain_suffix" => RuleType::DomainSuffix,
                "domain_keyword" => RuleType::DomainKeyword,
                "domain_regex" => RuleType::DomainRegex,
                "geoip" => RuleType::GeoIP,
                "geosite" => RuleType::GeoSite,
                "ip_cidr" => RuleType::IpCidr,
                "port" => RuleType::Port,
                "protocol" => RuleType::Protocol,
                other => {
                    return IpcResponse::error(
                        ErrorCode::InvalidParameters,
                        format!("Unknown rule type: {other}"),
                    );
                }
            };

            // Route rules to appropriate builders based on type
            // This ensures domain rules go to domain_matcher (Aho-Corasick),
            // geoip rules go to geoip_matcher (CIDR), etc.
            let result = match rule_type {
                // Domain rules → domain_matcher (Aho-Corasick)
                RuleType::Domain | RuleType::DomainSuffix |
                RuleType::DomainKeyword | RuleType::DomainRegex => {
                    builder.add_domain_rule(rule_type, &rule_cfg.target, &rule_cfg.outbound)
                }
                // GeoIP/IpCidr rules → geoip_matcher (CIDR)
                RuleType::GeoIP | RuleType::IpCidr => {
                    builder.add_geoip_rule(rule_type, &rule_cfg.target, &rule_cfg.outbound)
                }
                // Port rules → CompiledRuleSet
                RuleType::Port => {
                    builder.add_port_rule(&rule_cfg.target, &rule_cfg.outbound)
                }
                // Protocol rules → CompiledRuleSet
                RuleType::Protocol => {
                    builder.add_protocol_rule(&rule_cfg.target, &rule_cfg.outbound)
                }
                // GeoSite requires domain catalog loading, add as raw rule for now
                // TODO: Implement GeoSite expansion from domain-catalog.json
                RuleType::GeoSite => {
                    warn!(
                        "GeoSite rule '{}' not yet supported in rust-router, skipping",
                        rule_cfg.target
                    );
                    continue;
                }
            };

            if let Err(e) = result {
                return IpcResponse::error(
                    ErrorCode::InvalidParameters,
                    format!("Failed to add rule '{}': {}", rule_cfg.target, e),
                );
            }

            rule_count += 1;
        }

        // Preserve fwmark_router from current snapshot (chain configurations)
        // We need to rebuild with the same chains
        // Note: This is a limitation - ideally we'd have a method to copy chains
        // For now, we'll use the built fwmark_router and accept that chains
        // need to be re-registered separately

        // Build the new snapshot
        let new_snapshot = match builder.build() {
            Ok(mut snapshot) => {
                // Preserve fwmark_router from current configuration
                // (chain DSCP mappings should persist across rule updates)
                snapshot.fwmark_router = current.fwmark_router.clone();
                snapshot
            }
            Err(e) => {
                return IpcResponse::error(
                    ErrorCode::InvalidParameters,
                    format!("Failed to build routing snapshot: {e}"),
                );
            }
        };

        // Atomic swap via rule engine
        self.rule_engine.reload(new_snapshot);

        // Update last reload timestamp
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.last_reload_timestamp.store(now, Ordering::Relaxed);

        info!(
            "Updated routing: {} rules, default='{}', version={} (domain/geoip matchers rebuilt)",
            rule_count, default_outbound, new_version
        );

        IpcResponse::UpdateRoutingResult(UpdateRoutingResponse {
            success: true,
            version: new_version,
            rule_count,
            default_outbound,
        })
    }

    /// Handle set default outbound command
    fn handle_set_default_outbound(&self, tag: String) -> IpcResponse {
        use crate::rules::RoutingSnapshot;

        // Validate outbound exists (check both managers + WG prefixes)
        if !self.is_valid_outbound_tag(&tag) {
            return IpcResponse::error(
                ErrorCode::NotFound,
                format!("Outbound '{tag}' not found"),
            );
        }

        // Load current routing config
        let current = self.rule_engine.load();

        // Create new snapshot with updated default outbound
        // Copy the current snapshot's fields but update default_outbound
        let new_snapshot = RoutingSnapshot {
            domain_matcher: current.domain_matcher.clone(),
            geoip_matcher: current.geoip_matcher.clone(),
            fwmark_router: current.fwmark_router.clone(),
            rules: current.rules.clone(),
            default_outbound: tag.clone(),
            version: current.version + 1,
        };

        // Atomic swap
        self.rule_engine.reload(new_snapshot);

        info!("Default outbound changed to '{}'", tag);
        IpcResponse::success_with_message(format!("Default outbound set to '{tag}'"))
    }

    /// Handle get outbound health command
    fn handle_get_outbound_health(&self) -> IpcResponse {
        use super::protocol::{OutboundHealthInfo, OutboundHealthResponse};

        let mut outbounds = Vec::new();
        let mut all_healthy = true;

        for outbound in self.outbound_manager.all() {
            let health = outbound.health_status();
            let health_str = health.to_string();

            if !matches!(health, crate::outbound::HealthStatus::Healthy) {
                all_healthy = false;
            }

            outbounds.push(OutboundHealthInfo {
                tag: outbound.tag().to_string(),
                outbound_type: outbound.outbound_type().to_string(),
                health: health_str,
                enabled: outbound.is_enabled(),
                active_connections: outbound.active_connections(),
                last_check: None, // Could add last health check time if tracked
                error: None,      // Could add error details for unhealthy status
            });
        }

        let overall_health = if all_healthy { "healthy" } else { "degraded" }.to_string();

        IpcResponse::OutboundHealth(OutboundHealthResponse {
            outbounds,
            overall_health,
        })
    }

    /// Handle notify egress change command from Python
    fn handle_notify_egress_change(
        &self,
        action: super::protocol::EgressAction,
        tag: String,
        egress_type: String,
    ) -> IpcResponse {
        use super::protocol::EgressAction;

        match action {
            EgressAction::Added => {
                info!("Python notified: egress '{}' ({}) added", tag, egress_type);
                // In a full implementation, we might pre-create outbound here
            }
            EgressAction::Removed => {
                info!(
                    "Python notified: egress '{}' ({}) removed",
                    tag, egress_type
                );
                // Remove the outbound if it exists
                if let Some(_) = self.outbound_manager.remove(&tag) {
                    debug!("Removed outbound '{}' based on Python notification", tag);
                }
            }
            EgressAction::Updated => {
                info!(
                    "Python notified: egress '{}' ({}) updated",
                    tag, egress_type
                );
                // In a full implementation, we might update outbound config here
            }
        }

        IpcResponse::success_with_message(format!(
            "Egress change notification processed: {action:?} '{tag}' ({egress_type})"
        ))
    }

    /// Handle get Prometheus metrics command
    ///
    /// Generates metrics in Prometheus text exposition format.
    fn handle_get_prometheus_metrics(&self) -> IpcResponse {
        let mut output = String::with_capacity(8192);

        // Collect timestamp
        let timestamp_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        // Get global connection stats
        let stats = self.connection_manager.stats_snapshot();

        // === Core Metrics ===
        write_metric_header(
            &mut output,
            "rust_router_connections_total",
            "Total number of connections accepted",
            "counter",
        );
        write_metric_value(&mut output, "rust_router_connections_total", None, stats.total_accepted);

        write_metric_header(
            &mut output,
            "rust_router_connections_active",
            "Currently active connections",
            "gauge",
        );
        write_metric_value(&mut output, "rust_router_connections_active", None, stats.active);

        write_metric_header(
            &mut output,
            "rust_router_connections_completed_total",
            "Total connections completed successfully",
            "counter",
        );
        write_metric_value(&mut output, "rust_router_connections_completed_total", None, stats.completed);

        write_metric_header(
            &mut output,
            "rust_router_connections_errored_total",
            "Total connections that errored",
            "counter",
        );
        write_metric_value(&mut output, "rust_router_connections_errored_total", None, stats.errored);

        write_metric_header(
            &mut output,
            "rust_router_bytes_rx_total",
            "Total bytes received (client to upstream)",
            "counter",
        );
        write_metric_value(&mut output, "rust_router_bytes_rx_total", None, stats.bytes_rx);

        write_metric_header(
            &mut output,
            "rust_router_bytes_tx_total",
            "Total bytes transmitted (upstream to client)",
            "counter",
        );
        write_metric_value(&mut output, "rust_router_bytes_tx_total", None, stats.bytes_tx);

        // === Per-Outbound Metrics ===
        let outbounds = self.outbound_manager.all();

        // Connections per outbound
        write_metric_header(
            &mut output,
            "rust_router_outbound_connections_total",
            "Total connections per outbound",
            "counter",
        );
        for outbound in &outbounds {
            let outbound_stats = outbound.stats().snapshot();
            write_metric_value(
                &mut output,
                "rust_router_outbound_connections_total",
                Some(&[("outbound", outbound.tag())]),
                outbound_stats.connections,
            );
        }

        write_metric_header(
            &mut output,
            "rust_router_outbound_connections_active",
            "Active connections per outbound",
            "gauge",
        );
        for outbound in &outbounds {
            let outbound_stats = outbound.stats().snapshot();
            write_metric_value(
                &mut output,
                "rust_router_outbound_connections_active",
                Some(&[("outbound", outbound.tag())]),
                outbound_stats.active,
            );
        }

        write_metric_header(
            &mut output,
            "rust_router_outbound_bytes_rx_total",
            "Total bytes received per outbound",
            "counter",
        );
        for outbound in &outbounds {
            let outbound_stats = outbound.stats().snapshot();
            write_metric_value(
                &mut output,
                "rust_router_outbound_bytes_rx_total",
                Some(&[("outbound", outbound.tag())]),
                outbound_stats.bytes_rx,
            );
        }

        write_metric_header(
            &mut output,
            "rust_router_outbound_bytes_tx_total",
            "Total bytes transmitted per outbound",
            "counter",
        );
        for outbound in &outbounds {
            let outbound_stats = outbound.stats().snapshot();
            write_metric_value(
                &mut output,
                "rust_router_outbound_bytes_tx_total",
                Some(&[("outbound", outbound.tag())]),
                outbound_stats.bytes_tx,
            );
        }

        write_metric_header(
            &mut output,
            "rust_router_outbound_errors_total",
            "Total errors per outbound",
            "counter",
        );
        for outbound in &outbounds {
            let outbound_stats = outbound.stats().snapshot();
            write_metric_value(
                &mut output,
                "rust_router_outbound_errors_total",
                Some(&[("outbound", outbound.tag())]),
                outbound_stats.errors,
            );
        }

        // Outbound health status
        write_metric_header(
            &mut output,
            "rust_router_outbound_health",
            "Outbound health status (1 = current status)",
            "gauge",
        );
        for outbound in &outbounds {
            let health = outbound.health_status();
            let health_str = health.to_string();
            // Output 1 for current status, 0 for others
            for status in &["healthy", "degraded", "unhealthy", "unknown"] {
                let value = u64::from(*status == health_str);
                write_metric_value(
                    &mut output,
                    "rust_router_outbound_health",
                    Some(&[("outbound", outbound.tag()), ("status", status)]),
                    value,
                );
            }
        }

        // === Rule Engine Metrics ===
        let rule_snapshot = self.rule_engine.load();
        let rule_stats = rule_snapshot.stats();

        write_metric_header(
            &mut output,
            "rust_router_rules_domain_count",
            "Number of domain rules",
            "gauge",
        );
        write_metric_value(
            &mut output,
            "rust_router_rules_domain_count",
            None,
            rule_stats.domain_rules as u64,
        );

        write_metric_header(
            &mut output,
            "rust_router_rules_geoip_count",
            "Number of GeoIP/CIDR rules",
            "gauge",
        );
        write_metric_value(
            &mut output,
            "rust_router_rules_geoip_count",
            None,
            rule_stats.geoip_rules as u64,
        );

        // Count port and protocol rules from compiled rules
        let mut port_rules = 0u64;
        let mut protocol_rules = 0u64;
        for rule in rule_snapshot.rules.iter() {
            match rule.rule_type {
                crate::rules::RuleType::Port => port_rules += 1,
                crate::rules::RuleType::Protocol => protocol_rules += 1,
                _ => {}
            }
        }

        write_metric_header(
            &mut output,
            "rust_router_rules_port_count",
            "Number of port rules",
            "gauge",
        );
        write_metric_value(&mut output, "rust_router_rules_port_count", None, port_rules);

        write_metric_header(
            &mut output,
            "rust_router_rules_protocol_count",
            "Number of protocol rules",
            "gauge",
        );
        write_metric_value(&mut output, "rust_router_rules_protocol_count", None, protocol_rules);

        write_metric_header(
            &mut output,
            "rust_router_rules_chain_count",
            "Number of registered chains for multi-hop routing",
            "gauge",
        );
        write_metric_value(
            &mut output,
            "rust_router_rules_chain_count",
            None,
            rule_stats.chains as u64,
        );

        write_metric_header(
            &mut output,
            "rust_router_config_version",
            "Configuration version (incremented on each reload)",
            "gauge",
        );
        write_metric_value(
            &mut output,
            "rust_router_config_version",
            None,
            self.config_version.load(std::sync::atomic::Ordering::Relaxed),
        );

        // === SOCKS5 Connection Pool Metrics ===
        let has_socks5 = outbounds.iter().any(|o| o.outbound_type() == "socks5");
        if has_socks5 {
            write_metric_header(
                &mut output,
                "rust_router_pool_size",
                "SOCKS5 connection pool total size",
                "gauge",
            );
            write_metric_header(
                &mut output,
                "rust_router_pool_available",
                "SOCKS5 connection pool available connections",
                "gauge",
            );
            write_metric_header(
                &mut output,
                "rust_router_pool_waiting",
                "SOCKS5 connection pool waiting requests",
                "gauge",
            );

            for outbound in &outbounds {
                if outbound.outbound_type() == "socks5" {
                    if let Some(pool_info) = outbound.pool_stats_info() {
                        write_metric_value(
                            &mut output,
                            "rust_router_pool_size",
                            Some(&[("outbound", outbound.tag())]),
                            pool_info.size as u64,
                        );
                        write_metric_value(
                            &mut output,
                            "rust_router_pool_available",
                            Some(&[("outbound", outbound.tag())]),
                            pool_info.available as u64,
                        );
                        write_metric_value(
                            &mut output,
                            "rust_router_pool_waiting",
                            Some(&[("outbound", outbound.tag())]),
                            pool_info.waiting as u64,
                        );
                    }
                }
            }
        }

        // === System Metrics ===
        write_metric_header(
            &mut output,
            "rust_router_uptime_seconds",
            "Time since server start in seconds",
            "gauge",
        );
        write_metric_value(
            &mut output,
            "rust_router_uptime_seconds",
            None,
            self.start_time.elapsed().as_secs(),
        );

        write_metric_header(
            &mut output,
            "rust_router_info",
            "Server information (always 1)",
            "gauge",
        );
        write_metric_value(
            &mut output,
            "rust_router_info",
            Some(&[("version", &self.version)]),
            1u64,
        );

        IpcResponse::PrometheusMetrics(PrometheusMetricsResponse {
            metrics_text: output,
            timestamp_ms,
        })
    }

    // ========================================================================
    // UDP IPC Handler Implementations
    // ========================================================================

    /// Handle `GetUdpStats` command
    ///
    /// Returns comprehensive UDP statistics including session manager, worker pool,
    /// and buffer pool stats.
    fn handle_get_udp_stats(&self) -> IpcResponse {
        // Get session manager stats (available even if UDP workers not running)
        let session_stats = if let Some(ref manager) = self.udp_session_manager {
            let stats = manager.stats();
            UdpSessionStatsInfo {
                session_count: stats.session_count,
                max_sessions: stats.max_sessions,
                total_created: stats.total_created,
                total_evicted: stats.total_evicted,
                utilization_percent: stats.utilization(),
                idle_timeout_secs: stats.idle_timeout_secs,
                ttl_secs: stats.ttl_secs,
            }
        } else {
            // Default empty stats when no session manager
            UdpSessionStatsInfo {
                session_count: 0,
                max_sessions: 65536,
                total_created: 0,
                total_evicted: 0,
                utilization_percent: 0.0,
                idle_timeout_secs: 300,
                ttl_secs: 600,
            }
        };

        // Get worker pool stats
        let worker_stats = self.udp_worker_pool.as_ref().map(|pool| {
            let stats = pool.stats_snapshot();
            UdpWorkerPoolInfo {
                packets_processed: stats.packets_processed,
                bytes_received: stats.bytes_received,
                workers_active: stats.workers_active,
                workers_total: stats.workers_total,
                worker_errors: stats.worker_errors,
            }
        });

        // Get buffer pool stats
        let buffer_pool_stats = self.udp_buffer_pool.as_ref().map(|pool| {
            let stats = pool.stats().snapshot();
            BufferPoolInfo {
                capacity: pool.capacity(),
                buffer_size: pool.buffer_size(),
                available: pool.available(),
                allocations: stats.allocations,
                reuses: stats.reuses,
                returns: stats.returns,
                drops: stats.drops,
                efficiency: stats.efficiency(),
            }
        });

        // Get processor stats from worker pool
        let processor_stats = self.udp_worker_pool.as_ref().map(|pool| {
            let stats = pool.processor_stats();
            UdpProcessorInfo {
                packets_processed: stats.packets_processed,
                packets_forwarded: stats.packets_forwarded,
                packets_failed: stats.packets_failed,
                sessions_created: stats.sessions_created,
                sessions_reused: stats.sessions_reused,
                bytes_sent: stats.bytes_sent,
                quic_packets: stats.quic_packets,
                quic_sni_extracted: stats.quic_sni_extracted,
                rule_matches: stats.rule_matches,
                active_sessions: pool.active_sessions(),
            }
        });

        IpcResponse::UdpStats(UdpStatsResponse {
            udp_enabled: self.udp_enabled,
            session_stats,
            worker_stats,
            buffer_pool_stats,
            processor_stats,
        })
    }

    /// Handle `ListUdpSessions` command
    ///
    /// Returns a list of active UDP session snapshots with optional limit.
    fn handle_list_udp_sessions(&self, limit: usize) -> IpcResponse {
        let Some(ref manager) = self.udp_session_manager else {
            return IpcResponse::UdpSessions(UdpSessionsResponse {
                sessions: vec![],
                total_count: 0,
                truncated: false,
            });
        };

        // Get all session snapshots
        let all_sessions = manager.all_sessions();
        let total_count = all_sessions.len() as u64;

        // Apply limit and convert to response format
        let truncated = limit < all_sessions.len();
        let sessions: Vec<UdpSessionInfo> = all_sessions
            .into_iter()
            .take(limit)
            .map(|s| UdpSessionInfo {
                client_addr: s.client_addr.to_string(),
                dest_addr: s.dest_addr.to_string(),
                outbound: s.outbound,
                routing_mark: s.routing_mark,
                sniffed_domain: s.sniffed_domain,
                bytes_sent: s.bytes_sent,
                bytes_recv: s.bytes_recv,
                packets_sent: s.packets_sent,
                packets_recv: s.packets_recv,
                age_secs: s.age_secs,
            })
            .collect();

        IpcResponse::UdpSessions(UdpSessionsResponse {
            sessions,
            total_count,
            truncated,
        })
    }

    /// Handle `GetUdpSession` command
    ///
    /// Returns detailed information about a specific UDP session.
    fn handle_get_udp_session(&self, client_addr: &str, dest_addr: &str) -> IpcResponse {
        // Validate addresses first (before checking if UDP is enabled)
        let client: std::net::SocketAddr = match client_addr.parse() {
            Ok(addr) => addr,
            Err(_) => {
                return IpcResponse::error(
                    ErrorCode::InvalidParameters,
                    format!("Invalid client address: {client_addr}"),
                );
            }
        };

        let dest: std::net::SocketAddr = match dest_addr.parse() {
            Ok(addr) => addr,
            Err(_) => {
                return IpcResponse::error(
                    ErrorCode::InvalidParameters,
                    format!("Invalid destination address: {dest_addr}"),
                );
            }
        };

        let Some(ref manager) = self.udp_session_manager else {
            return IpcResponse::UdpSession(UdpSessionResponse {
                found: false,
                session: None,
            });
        };

        // Create session key and look up
        let key = UdpSessionKey::new(client, dest);
        match manager.get(&key) {
            Some(session) => {
                let snapshot = session.snapshot();
                IpcResponse::UdpSession(UdpSessionResponse {
                    found: true,
                    session: Some(UdpSessionInfo {
                        client_addr: snapshot.client_addr.to_string(),
                        dest_addr: snapshot.dest_addr.to_string(),
                        outbound: snapshot.outbound,
                        routing_mark: snapshot.routing_mark,
                        sniffed_domain: snapshot.sniffed_domain,
                        bytes_sent: snapshot.bytes_sent,
                        bytes_recv: snapshot.bytes_recv,
                        packets_sent: snapshot.packets_sent,
                        packets_recv: snapshot.packets_recv,
                        age_secs: snapshot.age_secs,
                    }),
                })
            }
            None => IpcResponse::UdpSession(UdpSessionResponse {
                found: false,
                session: None,
            }),
        }
    }

    /// Handle `GetUdpWorkerStats` command
    ///
    /// Returns statistics about the UDP worker pool.
    fn handle_get_udp_worker_stats(&self) -> IpcResponse {
        match &self.udp_worker_pool {
            Some(pool) => {
                let stats = pool.stats_snapshot();
                IpcResponse::UdpWorkerStats(UdpWorkerStatsResponse {
                    running: pool.is_running(),
                    num_workers: pool.num_workers(),
                    stats: Some(UdpWorkerPoolInfo {
                        packets_processed: stats.packets_processed,
                        bytes_received: stats.bytes_received,
                        workers_active: stats.workers_active,
                        workers_total: stats.workers_total,
                        worker_errors: stats.worker_errors,
                    }),
                })
            }
            None => IpcResponse::UdpWorkerStats(UdpWorkerStatsResponse {
                running: false,
                num_workers: 0,
                stats: None,
            }),
        }
    }

    /// Handle `GetBufferPoolStats` command
    ///
    /// Returns statistics about the lock-free UDP buffer pool.
    fn handle_get_buffer_pool_stats(&self) -> IpcResponse {
        match &self.udp_buffer_pool {
            Some(pool) => {
                let stats = pool.stats().snapshot();
                IpcResponse::BufferPoolStats(BufferPoolStatsResponse {
                    available: true,
                    stats: Some(BufferPoolInfo {
                        capacity: pool.capacity(),
                        buffer_size: pool.buffer_size(),
                        available: pool.available(),
                        allocations: stats.allocations,
                        reuses: stats.reuses,
                        returns: stats.returns,
                        drops: stats.drops,
                        efficiency: stats.efficiency(),
                    }),
                })
            }
            None => IpcResponse::BufferPoolStats(BufferPoolStatsResponse {
                available: false,
                stats: None,
            }),
        }
    }

    // ========================================================================
    // Chain Management Handler Implementations
    // ========================================================================

    /// Handle `CreateChain` command
    ///
    /// Creates a new chain with the given configuration.
    async fn handle_create_chain(&self, tag: String, config: ChainConfig) -> IpcResponse {
        let Some(chain_manager) = &self.chain_manager else {
            return IpcResponse::error(
                ErrorCode::OperationFailed,
                "Chain manager not available",
            );
        };

        // Ensure the config tag matches the command tag
        let mut final_config = config;
        if final_config.tag != tag {
            final_config.tag = tag.clone();
        }

        match chain_manager.create_chain(final_config).await {
            Ok(dscp_value) => {
                info!("Created chain '{}' with DSCP value {}", tag, dscp_value);
                IpcResponse::success_with_message(format!(
                    "Chain '{tag}' created with DSCP value {dscp_value}"
                ))
            }
            Err(e) => {
                warn!("Failed to create chain '{}': {}", tag, e);
                IpcResponse::error(
                    Self::chain_error_to_code(&e),
                    e.to_string(),
                )
            }
        }
    }

    /// Handle `RemoveChain` command
    ///
    /// Removes an existing chain.
    async fn handle_remove_chain(&self, tag: &str) -> IpcResponse {
        let Some(chain_manager) = &self.chain_manager else {
            return IpcResponse::error(
                ErrorCode::OperationFailed,
                "Chain manager not available",
            );
        };

        match chain_manager.remove_chain(tag).await {
            Ok(()) => {
                info!("Removed chain '{}'", tag);
                IpcResponse::success_with_message(format!("Chain '{tag}' removed"))
            }
            Err(e) => {
                warn!("Failed to remove chain '{}': {}", tag, e);
                IpcResponse::error(
                    Self::chain_error_to_code(&e),
                    e.to_string(),
                )
            }
        }
    }

    /// Handle `ActivateChain` command
    ///
    /// Activates a chain using Two-Phase Commit protocol.
    async fn handle_activate_chain(&self, tag: &str) -> IpcResponse {
        let Some(chain_manager) = &self.chain_manager else {
            return IpcResponse::error(
                ErrorCode::OperationFailed,
                "Chain manager not available",
            );
        };

        match chain_manager.activate_chain(tag).await {
            Ok(()) => {
                info!("Activated chain '{}'", tag);
                IpcResponse::success_with_message(format!("Chain '{tag}' activated"))
            }
            Err(e) => {
                warn!("Failed to activate chain '{}': {}", tag, e);
                IpcResponse::error(
                    Self::chain_error_to_code(&e),
                    e.to_string(),
                )
            }
        }
    }

    /// Handle `DeactivateChain` command
    ///
    /// Deactivates an active chain.
    async fn handle_deactivate_chain(&self, tag: &str) -> IpcResponse {
        let Some(chain_manager) = &self.chain_manager else {
            return IpcResponse::error(
                ErrorCode::OperationFailed,
                "Chain manager not available",
            );
        };

        match chain_manager.deactivate_chain(tag).await {
            Ok(()) => {
                info!("Deactivated chain '{}'", tag);
                IpcResponse::success_with_message(format!("Chain '{tag}' deactivated"))
            }
            Err(e) => {
                warn!("Failed to deactivate chain '{}': {}", tag, e);
                IpcResponse::error(
                    Self::chain_error_to_code(&e),
                    e.to_string(),
                )
            }
        }
    }

    /// Handle `GetChainStatus` command
    ///
    /// Returns status information for a specific chain.
    fn handle_get_chain_status(&self, tag: &str) -> IpcResponse {
        let Some(chain_manager) = &self.chain_manager else {
            return IpcResponse::error(
                ErrorCode::OperationFailed,
                "Chain manager not available",
            );
        };

        match chain_manager.get_chain_status(tag) {
            Some(status) => IpcResponse::ChainStatus(status),
            None => IpcResponse::error(
                ErrorCode::NotFound,
                format!("Chain '{tag}' not found"),
            ),
        }
    }

    /// Handle `ListChains` command
    ///
    /// Returns a list of all configured chains.
    fn handle_list_chains(&self) -> IpcResponse {
        let Some(chain_manager) = &self.chain_manager else {
            return IpcResponse::ChainList(ChainListResponse { chains: vec![] });
        };

        let chains = chain_manager.list_chains();
        IpcResponse::ChainList(ChainListResponse { chains })
    }

    /// Handle `GetChainRole` command
    ///
    /// Returns the local node's role in a specific chain.
    fn handle_get_chain_role(&self, chain_tag: &str) -> IpcResponse {
        let Some(chain_manager) = &self.chain_manager else {
            return IpcResponse::error(
                ErrorCode::OperationFailed,
                "Chain manager not available",
            );
        };

        if !chain_manager.chain_exists(chain_tag) {
            return IpcResponse::error(
                ErrorCode::NotFound,
                format!("Chain '{chain_tag}' not found"),
            );
        }

        let role = chain_manager.get_chain_role(chain_tag);
        IpcResponse::ChainRole(ChainRoleResponse {
            chain_tag: chain_tag.to_string(),
            role,
            in_chain: role.is_some(),
        })
    }

    /// Handle `DiagnoseChain` command
    ///
    /// Returns comprehensive diagnostics for troubleshooting chain routing issues.
    fn handle_diagnose_chain(&self, tag: &str) -> IpcResponse {
        let mut issues = Vec::new();

        // Check if chain manager is available
        let Some(chain_manager) = &self.chain_manager else {
            return IpcResponse::ChainDiagnostics(ChainDiagnosticsResponse {
                tag: tag.to_string(),
                chain_exists: false,
                chain_state: None,
                my_role: None,
                dscp_value: None,
                fwmark_registered: false,
                fwmark_dscp: None,
                fwmark_routing_mark: None,
                next_hop_tunnel: None,
                exit_egress: None,
                last_error: None,
                issues: vec!["Chain manager not available".to_string()],
                healthy: false,
            });
        };

        // Get chain info from ChainManager
        let chain_exists = chain_manager.chain_exists(tag);
        let chain_state = chain_manager.get_chain_state(tag);
        let my_role = chain_manager.get_chain_role(tag);
        let chain_config = chain_manager.get_chain_config(tag);
        let dscp_value = chain_config.as_ref().map(|c| c.dscp_value);
        let exit_egress = chain_config.as_ref().map(|c| c.exit_egress.clone());
        let next_hop_tunnel = chain_manager.get_next_hop_tunnel(tag);
        let last_error = chain_manager.get_chain_error(tag);

        // Check FwmarkRouter registration
        let snapshot = self.rule_engine.load();
        let fwmark_registered = snapshot.fwmark_router.is_chain(tag);
        let fwmark_chain_mark = snapshot.fwmark_router.get_chain_mark(tag);
        let fwmark_dscp = fwmark_chain_mark.map(|m| m.dscp_value);
        let fwmark_routing_mark = fwmark_chain_mark.map(|m| m.routing_mark);

        // Detect issues
        if !chain_exists {
            issues.push(format!("Chain '{}' does not exist in ChainManager", tag));
        } else {
            // Check state consistency
            if let Some(state) = chain_state {
                match state {
                    ChainState::Active => {
                        // Active chains MUST be registered in FwmarkRouter
                        if !fwmark_registered {
                            issues.push(
                                "Chain is Active but NOT registered in FwmarkRouter - \
                                 this is the root cause of traffic leaks!"
                                    .to_string(),
                            );
                        }
                    }
                    ChainState::Activating => {
                        issues.push("Chain is in Activating state (2PC in progress)".to_string());
                    }
                    ChainState::Error => {
                        issues.push(format!(
                            "Chain is in Error state: {}",
                            last_error.as_deref().unwrap_or("unknown error")
                        ));
                    }
                    ChainState::Inactive => {
                        if fwmark_registered {
                            issues.push(
                                "Chain is Inactive but still registered in FwmarkRouter - \
                                 stale registration"
                                    .to_string(),
                            );
                        }
                    }
                }
            }

            // Check role-specific requirements
            if let Some(role) = my_role {
                match role {
                    ChainRole::Entry | ChainRole::Relay => {
                        if next_hop_tunnel.is_none() {
                            issues.push(format!(
                                "Node role is {:?} but next_hop_tunnel is not configured - \
                                 packets will be blocked",
                                role
                            ));
                        }
                    }
                    ChainRole::Terminal => {
                        if exit_egress.is_none() {
                            issues.push(
                                "Node role is Terminal but exit_egress is not configured - \
                                 packets will be blocked"
                                    .to_string(),
                            );
                        }
                    }
                }
            } else if chain_exists && chain_state == Some(ChainState::Active) {
                issues.push(
                    "Chain is Active but local node has no role - \
                     this node is not part of the chain"
                        .to_string(),
                );
            }

            // Check DSCP consistency
            if let (Some(cm_dscp), Some(fw_dscp)) = (dscp_value, fwmark_dscp) {
                if cm_dscp != fw_dscp {
                    issues.push(format!(
                        "DSCP value mismatch: ChainManager={}, FwmarkRouter={}",
                        cm_dscp, fw_dscp
                    ));
                }
            }
        }

        let healthy = issues.is_empty()
            && chain_exists
            && chain_state == Some(ChainState::Active)
            && fwmark_registered;

        IpcResponse::ChainDiagnostics(ChainDiagnosticsResponse {
            tag: tag.to_string(),
            chain_exists,
            chain_state,
            my_role,
            dscp_value,
            fwmark_registered,
            fwmark_dscp,
            fwmark_routing_mark,
            next_hop_tunnel,
            exit_egress,
            last_error,
            issues,
            healthy,
        })
    }

    /// Handle `UpdateChainState` command
    ///
    /// Updates the state of a chain (used for persistence and recovery).
    fn handle_update_chain_state(
        &self,
        tag: &str,
        state: ChainState,
        last_error: Option<String>,
    ) -> IpcResponse {
        let Some(chain_manager) = &self.chain_manager else {
            return IpcResponse::error(
                ErrorCode::OperationFailed,
                "Chain manager not available",
            );
        };

        match chain_manager.update_chain_state(tag, state, last_error) {
            Ok(()) => {
                debug!("Updated chain '{}' state to {:?}", tag, state);
                IpcResponse::success_with_message(format!(
                    "Chain '{tag}' state updated to {state}"
                ))
            }
            Err(e) => {
                warn!("Failed to update chain '{}' state: {}", tag, e);
                IpcResponse::error(
                    Self::chain_error_to_code(&e),
                    e.to_string(),
                )
            }
        }
    }

    /// Handle `UpdateChain` command
    ///
    /// Updates an existing chain configuration. Chain must be inactive.
    async fn handle_update_chain(
        &self,
        tag: String,
        hops: Option<Vec<super::protocol::ChainHop>>,
        exit_egress: Option<String>,
        description: Option<String>,
        allow_transitive: Option<bool>,
    ) -> IpcResponse {
        let Some(chain_manager) = &self.chain_manager else {
            return IpcResponse::error(
                ErrorCode::OperationFailed,
                "Chain manager not available",
            );
        };

        // Get current chain status to check state and merge with updates
        let current_status = match chain_manager.get_chain_status(&tag) {
            Some(status) => status,
            None => {
                return IpcResponse::error(
                    ErrorCode::NotFound,
                    format!("Chain '{tag}' not found"),
                );
            }
        };

        // Chain must be inactive to update
        if current_status.state != ChainState::Inactive {
            return IpcResponse::error(
                ErrorCode::OperationFailed,
                format!("Chain '{}' must be inactive to update (current state: {})", tag, current_status.state),
            );
        }

        // Get current config to merge with updates
        let current_config = match chain_manager.get_chain_config(&tag) {
            Some(config) => config,
            None => {
                return IpcResponse::error(
                    ErrorCode::NotFound,
                    format!("Chain '{tag}' configuration not found"),
                );
            }
        };

        // Build updated config
        let updated_config = ChainConfig {
            tag: tag.clone(),
            description: description.unwrap_or(current_config.description),
            dscp_value: current_config.dscp_value, // Cannot change DSCP value via update
            hops: hops.unwrap_or(current_config.hops),
            rules: current_config.rules, // Keep existing rules
            exit_egress: exit_egress.unwrap_or(current_config.exit_egress),
            allow_transitive: allow_transitive.unwrap_or(current_config.allow_transitive),
        };

        match chain_manager.update_chain(&tag, updated_config).await {
            Ok(()) => {
                info!("Updated chain '{}'", tag);
                IpcResponse::success_with_message(format!("Chain '{tag}' updated"))
            }
            Err(e) => {
                warn!("Failed to update chain '{}': {}", tag, e);
                IpcResponse::error(
                    Self::chain_error_to_code(&e),
                    e.to_string(),
                )
            }
        }
    }

    // ========================================================================
    // Two-Phase Commit Handler Implementations
    // ========================================================================

    /// Handle `PrepareChainRoute` command (2PC prepare phase)
    ///
    /// Validates chain configuration without applying routing rules.
    /// Called by the coordinator to prepare remote nodes.
    async fn handle_prepare_chain_route(
        &self,
        chain_tag: &str,
        config: ChainConfig,
        source_node: &str,
    ) -> IpcResponse {
        let Some(chain_manager) = &self.chain_manager else {
            return IpcResponse::PrepareResult(PrepareResponse {
                success: false,
                message: Some("Chain manager not available".to_string()),
                node: self.local_node_tag.clone(),
            });
        };

        match chain_manager.handle_prepare_request(chain_tag, config, source_node).await {
            Ok(()) => {
                debug!(
                    "PREPARE succeeded for chain '{}' from node '{}'",
                    chain_tag, source_node
                );
                IpcResponse::PrepareResult(PrepareResponse {
                    success: true,
                    message: Some(format!("Prepared for chain '{chain_tag}'")),
                    node: self.local_node_tag.clone(),
                })
            }
            Err(e) => {
                warn!(
                    "PREPARE failed for chain '{}' from node '{}': {}",
                    chain_tag, source_node, e
                );
                IpcResponse::PrepareResult(PrepareResponse {
                    success: false,
                    message: Some(e.to_string()),
                    node: self.local_node_tag.clone(),
                })
            }
        }
    }

    /// Handle `CommitChainRoute` command (2PC commit phase)
    ///
    /// Applies routing rules after all nodes have been prepared.
    /// Called by the coordinator to commit remote nodes.
    async fn handle_commit_chain_route(
        &self,
        chain_tag: &str,
        source_node: &str,
    ) -> IpcResponse {
        let Some(chain_manager) = &self.chain_manager else {
            return IpcResponse::error(
                ErrorCode::OperationFailed,
                "Chain manager not available",
            );
        };

        match chain_manager.handle_commit_request(chain_tag, source_node).await {
            Ok(()) => {
                info!(
                    "COMMIT succeeded for chain '{}' from node '{}'",
                    chain_tag, source_node
                );
                IpcResponse::success_with_message(format!("Committed chain '{chain_tag}'"))
            }
            Err(e) => {
                warn!(
                    "COMMIT failed for chain '{}' from node '{}': {}",
                    chain_tag, source_node, e
                );
                IpcResponse::error(
                    Self::chain_error_to_code(&e),
                    e.to_string(),
                )
            }
        }
    }

    /// Handle `AbortChainRoute` command (2PC abort phase)
    ///
    /// Rolls back prepared state when 2PC fails.
    /// Called by the coordinator to abort remote nodes.
    async fn handle_abort_chain_route(
        &self,
        chain_tag: &str,
        source_node: &str,
    ) -> IpcResponse {
        let Some(chain_manager) = &self.chain_manager else {
            return IpcResponse::error(
                ErrorCode::OperationFailed,
                "Chain manager not available",
            );
        };

        match chain_manager.handle_abort_request(chain_tag, source_node).await {
            Ok(()) => {
                info!(
                    "ABORT handled for chain '{}' from node '{}'",
                    chain_tag, source_node
                );
                IpcResponse::success_with_message(format!("Aborted chain '{chain_tag}'"))
            }
            Err(e) => {
                // ABORT should generally succeed even if there's nothing to abort
                warn!(
                    "ABORT had errors for chain '{}' from node '{}': {}",
                    chain_tag, source_node, e
                );
                // Still return success - abort is best-effort
                IpcResponse::success_with_message(format!(
                    "Abort processed for chain '{chain_tag}' (with warnings)"
                ))
            }
        }
    }

    // ========================================================================
    // WireGuard Tunnel Handler Implementations
    // ========================================================================

    /// Handle `CreateWgTunnel` command
    ///
    /// Creates a new userspace `WireGuard` tunnel via egress manager.
    async fn handle_create_wg_tunnel(
        &self,
        tag: String,
        config: super::protocol::WgTunnelConfig,
    ) -> IpcResponse {
        let Some(egress_manager) = &self.wg_egress_manager else {
            return IpcResponse::error(
                ErrorCode::OperationFailed,
                "WireGuard egress manager not available",
            );
        };

        // Convert IPC config to egress config
        let mut egress_config = crate::egress::config::WgEgressConfig::new(
            &tag,
            crate::egress::config::EgressTunnelType::Custom {
                name: tag.clone(),
            },
            config.private_key.clone(),
            config.peer_public_key.clone(),
            &config.peer_endpoint,
        );

        // Apply optional fields
        if let Some(local_ip) = config.local_ip {
            egress_config = egress_config.with_local_ip(local_ip);
        }
        if let Some(keepalive) = config.persistent_keepalive {
            egress_config = egress_config.with_persistent_keepalive(keepalive);
        }
        if let Some(mtu) = config.mtu {
            egress_config = egress_config.with_mtu(mtu);
        }
        if let Some(port) = config.listen_port {
            egress_config = egress_config.with_listen_port(port);
        }

        match egress_manager.create_tunnel(egress_config).await {
            Ok(()) => {
                info!("Created WireGuard tunnel '{}'", tag);
                IpcResponse::success_with_message(format!("WireGuard tunnel '{tag}' created"))
            }
            Err(e) => {
                warn!("Failed to create WireGuard tunnel '{}': {}", tag, e);
                IpcResponse::error(
                    Self::egress_error_to_code(&e),
                    e.to_string(),
                )
            }
        }
    }

    /// Handle `RemoveWgTunnel` command
    ///
    /// Removes a userspace `WireGuard` tunnel with optional drain timeout.
    async fn handle_remove_wg_tunnel(
        &self,
        tag: &str,
        drain_timeout_secs: Option<u32>,
    ) -> IpcResponse {
        let Some(egress_manager) = &self.wg_egress_manager else {
            return IpcResponse::error(
                ErrorCode::OperationFailed,
                "WireGuard egress manager not available",
            );
        };

        let drain_timeout = drain_timeout_secs.map(|s| std::time::Duration::from_secs(u64::from(s)));

        match egress_manager.remove_tunnel(tag, drain_timeout).await {
            Ok(()) => {
                info!("Removed WireGuard tunnel '{}'", tag);
                IpcResponse::success_with_message(format!("WireGuard tunnel '{tag}' removed"))
            }
            Err(e) => {
                warn!("Failed to remove WireGuard tunnel '{}': {}", tag, e);
                IpcResponse::error(
                    Self::egress_error_to_code(&e),
                    e.to_string(),
                )
            }
        }
    }

    /// Handle `GetWgTunnelStatus` command
    ///
    /// Returns status information for a specific `WireGuard` tunnel.
    fn handle_get_wg_tunnel_status(&self, tag: &str) -> IpcResponse {
        let Some(egress_manager) = &self.wg_egress_manager else {
            return IpcResponse::error(
                ErrorCode::OperationFailed,
                "WireGuard egress manager not available",
            );
        };

        match egress_manager.get_tunnel_status(tag) {
            Some(status) => {
                let ipc_status = WgTunnelStatus {
                    tag: status.tag,
                    active: status.connected,
                    local_ip: status.local_ip,
                    peer_endpoint: status.peer_endpoint,
                    last_handshake: status.stats.last_handshake,
                    tx_bytes: status.stats.tx_bytes,
                    rx_bytes: status.stats.rx_bytes,
                    active_connections: 0, // WireGuard tunnels track packets, not connections
                    error: None,
                };
                IpcResponse::WgTunnelStatus(ipc_status)
            }
            None => IpcResponse::error(
                ErrorCode::NotFound,
                format!("WireGuard tunnel '{tag}' not found"),
            ),
        }
    }

    /// Handle `ListWgTunnels` command
    ///
    /// Returns a list of all userspace `WireGuard` tunnels.
    fn handle_list_wg_tunnels(&self) -> IpcResponse {
        let mut tunnels = Vec::new();

        // Query WgEgressManager tunnels
        if let Some(egress_manager) = &self.wg_egress_manager {
            let tunnel_tags = egress_manager.list_tunnels();
            for tag in tunnel_tags {
                if let Some(status) = egress_manager.get_tunnel_status(&tag) {
                    tunnels.push(WgTunnelStatus {
                        tag: status.tag,
                        active: status.connected,
                        local_ip: status.local_ip,
                        peer_endpoint: status.peer_endpoint,
                        last_handshake: status.stats.last_handshake,
                        tx_bytes: status.stats.tx_bytes,
                        rx_bytes: status.stats.rx_bytes,
                        active_connections: 0,
                        error: None,
                    });
                }
            }
        }

        // Query PeerManager's WireGuard tunnels (peer connections)
        // Note: Peer tunnels use "peer-{tag}" naming convention
        if let Some(peer_manager) = &self.peer_manager {
            let peers = peer_manager.list_peers();
            for peer in peers {
                if peer.tunnel_type == TunnelType::WireGuard {
                    // Use peer- prefix for consistency with ChainManager expectations
                    let tunnel_tag = format!("peer-{}", peer.tag);
                    // Skip if already reported by WgEgressManager
                    if tunnels.iter().any(|t| t.tag == tunnel_tag) {
                        continue;
                    }
                    tunnels.push(WgTunnelStatus {
                        tag: tunnel_tag,
                        active: peer.state == PeerState::Connected,
                        local_ip: peer.tunnel_local_ip,
                        // Use actual peer endpoint, not tunnel IP
                        peer_endpoint: peer.endpoint.clone(),
                        last_handshake: peer.last_handshake,
                        tx_bytes: peer.tx_bytes,
                        rx_bytes: peer.rx_bytes,
                        active_connections: 0,
                        error: peer.last_error,
                    });
                }
            }
        }

        IpcResponse::WgTunnelList(WgTunnelListResponse { tunnels })
    }

    // ========================================================================
    // Ingress Peer Handler Implementations
    // ========================================================================

    /// Handle `AddIngressPeer` command
    ///
    /// Adds a new peer to the userspace `WireGuard` ingress.
    async fn handle_add_ingress_peer(
        &self,
        public_key: String,
        allowed_ips: String,
        name: Option<String>,
        preshared_key: Option<String>,
    ) -> IpcResponse {
        let Some(ingress_manager) = &self.wg_ingress_manager else {
            return IpcResponse::error(
                ErrorCode::OperationFailed,
                "Userspace WireGuard ingress not enabled",
            );
        };

        use crate::ingress::config::WgIngressPeerConfig;

        // Build peer config
        let mut peer_config = WgIngressPeerConfig::new(&public_key, &allowed_ips);
        if let Some(psk) = preshared_key {
            peer_config = peer_config.with_preshared_key(&psk);
        }
        // Note: name is stored in db_helper, not in WireGuard config

        // Add peer to ingress manager
        match ingress_manager.add_peer(peer_config).await {
            Ok(()) => {
                info!(
                    public_key = %public_key,
                    allowed_ips = %allowed_ips,
                    name = ?name,
                    "Ingress peer added"
                );
                IpcResponse::success_with_message("Ingress peer added")
            }
            Err(e) => {
                warn!(
                    public_key = %public_key,
                    error = %e,
                    "Failed to add ingress peer"
                );
                IpcResponse::error(ErrorCode::OperationFailed, format!("Failed to add peer: {e}"))
            }
        }
    }

    /// Handle `RemoveIngressPeer` command
    ///
    /// Removes a peer from the userspace `WireGuard` ingress.
    async fn handle_remove_ingress_peer(&self, public_key: String) -> IpcResponse {
        let Some(ingress_manager) = &self.wg_ingress_manager else {
            return IpcResponse::error(
                ErrorCode::OperationFailed,
                "Userspace WireGuard ingress not enabled",
            );
        };

        match ingress_manager.remove_peer(&public_key).await {
            Ok(()) => {
                info!(public_key = %public_key, "Ingress peer removed");
                IpcResponse::success_with_message("Ingress peer removed")
            }
            Err(e) => {
                warn!(
                    public_key = %public_key,
                    error = %e,
                    "Failed to remove ingress peer"
                );
                IpcResponse::error(ErrorCode::OperationFailed, format!("Failed to remove peer: {e}"))
            }
        }
    }

    /// Handle `ListIngressPeers` command
    ///
    /// Returns a list of all peers registered with the ingress.
    fn handle_list_ingress_peers(&self) -> IpcResponse {
        use super::protocol::{IngressPeerInfo, IngressPeerListResponse};

        let Some(ingress_manager) = &self.wg_ingress_manager else {
            return IpcResponse::error(
                ErrorCode::OperationFailed,
                "Userspace WireGuard ingress not enabled",
            );
        };

        let peers = ingress_manager
            .list_peers()
            .into_iter()
            .map(|p| IngressPeerInfo {
                public_key: p.public_key,
                allowed_ips: p.allowed_ips,
                name: p.name,
                rx_bytes: p.rx_bytes,
                tx_bytes: p.tx_bytes,
                last_handshake: p.last_handshake,
            })
            .collect();

        IpcResponse::IngressPeerList(IngressPeerListResponse { peers })
    }

    /// Handle `GetIngressStats` command
    ///
    /// Returns ingress manager, forwarding, and reply statistics.
    fn handle_get_ingress_stats(&self) -> IpcResponse {
        let ingress_enabled = self.wg_ingress_manager.is_some();
        let ingress_state = self
            .wg_ingress_manager
            .as_ref()
            .map(|manager| manager.state().to_string());
        let manager_stats = self.wg_ingress_manager.as_ref().map(|manager| manager.stats());
        let forwarding_stats = if ingress_enabled {
            self.ingress_forwarding_stats
                .as_ref()
                .map(|stats| stats.snapshot())
        } else {
            None
        };
        let reply_stats = if ingress_enabled {
            self.ingress_reply_stats
                .as_ref()
                .map(|stats| stats.snapshot())
        } else {
            None
        };
        let active_sessions = self
            .ingress_session_tracker
            .read()
            .as_ref()
            .map(|tracker| tracker.len())
            .unwrap_or(0);

        IpcResponse::IngressStats(IngressStatsResponse {
            ingress_enabled,
            ingress_state,
            manager_stats,
            forwarding_stats,
            reply_stats,
            active_sessions,
        })
    }

    // ========================================================================
    // ECMP Group Handler Implementations
    // ========================================================================

    /// Handle `CreateEcmpGroup` command
    ///
    /// Creates a new ECMP load balancing group.
    fn handle_create_ecmp_group(
        &self,
        tag: String,
        config: super::protocol::EcmpGroupConfig,
    ) -> IpcResponse {
        let Some(ecmp_manager) = &self.ecmp_group_manager else {
            return IpcResponse::error(
                ErrorCode::OperationFailed,
                "ECMP group manager not available",
            );
        };

        // Convert IPC config to internal config
        let members: Vec<crate::ecmp::group::EcmpMember> = config
            .members
            .iter()
            .map(|m| crate::ecmp::group::EcmpMember::with_weight(m.outbound.clone(), m.weight))
            .collect();

        let algorithm = match config.algorithm {
            super::protocol::EcmpAlgorithm::RoundRobin => crate::ecmp::lb::LbAlgorithm::RoundRobin,
            super::protocol::EcmpAlgorithm::Random => crate::ecmp::lb::LbAlgorithm::Random,
            super::protocol::EcmpAlgorithm::SourceHash => crate::ecmp::lb::LbAlgorithm::FiveTupleHash,
            super::protocol::EcmpAlgorithm::DestHash => crate::ecmp::lb::LbAlgorithm::DestHash,
            super::protocol::EcmpAlgorithm::DestHashLeastLoad => crate::ecmp::lb::LbAlgorithm::DestHashLeastLoad,
            super::protocol::EcmpAlgorithm::Weighted => crate::ecmp::lb::LbAlgorithm::Weighted,
            super::protocol::EcmpAlgorithm::LeastConnections => crate::ecmp::lb::LbAlgorithm::LeastConnections,
        };

        let internal_config = crate::ecmp::group::EcmpGroupConfig {
            tag: tag.clone(),
            description: config.description,
            members,
            algorithm,
            routing_mark: config.routing_mark,
            routing_table: config.routing_table,
            health_check: config.skip_unhealthy,
        };

        match ecmp_manager.add_group(internal_config) {
            Ok(()) => {
                info!("Created ECMP group '{}'", tag);
                IpcResponse::success_with_message(format!("ECMP group '{tag}' created"))
            }
            Err(e) => {
                warn!("Failed to create ECMP group '{}': {}", tag, e);
                IpcResponse::error(
                    Self::ecmp_error_to_code(&e),
                    e.to_string(),
                )
            }
        }
    }

    /// Handle `RemoveEcmpGroup` command
    ///
    /// Removes an ECMP load balancing group.
    fn handle_remove_ecmp_group(&self, tag: &str) -> IpcResponse {
        let Some(ecmp_manager) = &self.ecmp_group_manager else {
            return IpcResponse::error(
                ErrorCode::OperationFailed,
                "ECMP group manager not available",
            );
        };

        match ecmp_manager.remove_group(tag) {
            Ok(()) => {
                info!("Removed ECMP group '{}'", tag);
                IpcResponse::success_with_message(format!("ECMP group '{tag}' removed"))
            }
            Err(e) => {
                warn!("Failed to remove ECMP group '{}': {}", tag, e);
                IpcResponse::error(
                    Self::ecmp_error_to_code(&e),
                    e.to_string(),
                )
            }
        }
    }

    /// Handle `GetEcmpGroupStatus` command
    ///
    /// Returns status information for a specific ECMP group.
    fn handle_get_ecmp_group_status(&self, tag: &str) -> IpcResponse {
        let Some(ecmp_manager) = &self.ecmp_group_manager else {
            return IpcResponse::error(
                ErrorCode::OperationFailed,
                "ECMP group manager not available",
            );
        };

        match ecmp_manager.get_group(tag) {
            Some(group) => {
                let config = group.config();
                let algorithm = match config.algorithm {
                    crate::ecmp::lb::LbAlgorithm::RoundRobin => super::protocol::EcmpAlgorithm::RoundRobin,
                    crate::ecmp::lb::LbAlgorithm::Random => super::protocol::EcmpAlgorithm::Random,
                    crate::ecmp::lb::LbAlgorithm::FiveTupleHash => super::protocol::EcmpAlgorithm::SourceHash,
                    crate::ecmp::lb::LbAlgorithm::DestHash => super::protocol::EcmpAlgorithm::DestHash,
                    crate::ecmp::lb::LbAlgorithm::DestHashLeastLoad => super::protocol::EcmpAlgorithm::DestHashLeastLoad,
                    crate::ecmp::lb::LbAlgorithm::Weighted => super::protocol::EcmpAlgorithm::Weighted,
                    crate::ecmp::lb::LbAlgorithm::LeastConnections => super::protocol::EcmpAlgorithm::LeastConnections,
                };

                // Use runtime member_stats() instead of static config.members
                let member_stats = group.member_stats();
                let members: Vec<EcmpMemberStatus> = member_stats
                    .iter()
                    .map(|m| EcmpMemberStatus {
                        outbound: m.tag.clone(),
                        weight: m.weight,
                        enabled: true,
                        health: if m.healthy { "healthy" } else { "unhealthy" }.to_string(),
                        active_connections: m.active_connections,
                        total_connections: 0,
                    })
                    .collect();

                let stats = group.stats();
                let config = group.config();
                let status = EcmpGroupStatus {
                    tag: tag.to_string(),
                    description: config.description.clone(),
                    algorithm,
                    member_count: member_stats.len(),
                    healthy_count: member_stats.iter().filter(|m| m.healthy).count(),
                    members,
                    routing_mark: config.routing_mark,
                    routing_table: config.routing_table,
                    health_check: config.health_check,
                    active_connections: stats.total_connections,
                    total_connections: stats.total_requests,
                };

                IpcResponse::EcmpGroupStatus(status)
            }
            None => IpcResponse::error(
                ErrorCode::NotFound,
                format!("ECMP group '{tag}' not found"),
            ),
        }
    }

    /// Handle `ListEcmpGroups` command
    ///
    /// Returns a list of all ECMP groups.
    fn handle_list_ecmp_groups(&self) -> IpcResponse {
        let Some(ecmp_manager) = &self.ecmp_group_manager else {
            return IpcResponse::EcmpGroupList(EcmpGroupListResponse { groups: vec![] });
        };

        let group_tags = ecmp_manager.list_groups();
        let groups: Vec<EcmpGroupStatus> = group_tags
            .iter()
            .filter_map(|tag| {
                ecmp_manager.get_group(tag).map(|group| {
                    let config = group.config();
                    let algorithm = match config.algorithm {
                        crate::ecmp::lb::LbAlgorithm::RoundRobin => super::protocol::EcmpAlgorithm::RoundRobin,
                        crate::ecmp::lb::LbAlgorithm::Random => super::protocol::EcmpAlgorithm::Random,
                        crate::ecmp::lb::LbAlgorithm::FiveTupleHash => super::protocol::EcmpAlgorithm::SourceHash,
                        crate::ecmp::lb::LbAlgorithm::DestHash => super::protocol::EcmpAlgorithm::DestHash,
                        crate::ecmp::lb::LbAlgorithm::DestHashLeastLoad => super::protocol::EcmpAlgorithm::DestHashLeastLoad,
                        crate::ecmp::lb::LbAlgorithm::Weighted => super::protocol::EcmpAlgorithm::Weighted,
                        crate::ecmp::lb::LbAlgorithm::LeastConnections => super::protocol::EcmpAlgorithm::LeastConnections,
                    };

                    // Use runtime member_stats() instead of static config.members
                    let member_stats = group.member_stats();
                    let members: Vec<EcmpMemberStatus> = member_stats
                        .iter()
                        .map(|m| EcmpMemberStatus {
                            outbound: m.tag.clone(),
                            weight: m.weight,
                            enabled: true,
                            health: if m.healthy { "healthy" } else { "unhealthy" }.to_string(),
                            active_connections: m.active_connections,
                            total_connections: 0,
                        })
                        .collect();

                    let stats = group.stats();
                    EcmpGroupStatus {
                        tag: tag.clone(),
                        description: config.description.clone(),
                        algorithm,
                        member_count: member_stats.len(),
                        healthy_count: member_stats.iter().filter(|m| m.healthy).count(),
                        members,
                        routing_mark: config.routing_mark,
                        routing_table: config.routing_table,
                        health_check: config.health_check,
                        active_connections: stats.total_connections,
                        total_connections: stats.total_requests,
                    }
                })
            })
            .collect();

        IpcResponse::EcmpGroupList(EcmpGroupListResponse { groups })
    }

    /// Handle `UpdateEcmpGroupMembers` command
    ///
    /// Replaces the members of an existing ECMP group.
    fn handle_update_ecmp_group_members(
        &self,
        tag: &str,
        members: Vec<super::protocol::EcmpMemberConfig>,
    ) -> IpcResponse {
        let Some(ecmp_manager) = &self.ecmp_group_manager else {
            return IpcResponse::error(
                ErrorCode::OperationFailed,
                "ECMP group manager not available",
            );
        };

        // Get the group to update
        let group = match ecmp_manager.get_group(tag) {
            Some(g) => g,
            None => {
                return IpcResponse::error(
                    ErrorCode::NotFound,
                    format!("ECMP group '{tag}' not found"),
                );
            }
        };

        // Clear existing members and add new ones
        // First, get current members to remove them
        // NOTE: Use member_tags() to get the actual runtime member list,
        // not config().members which is the static initial configuration
        let current_members: Vec<String> = group.member_tags();

        // Remove all current members
        for member_tag in current_members {
            if let Err(e) = group.remove_member(&member_tag) {
                warn!("Failed to remove member '{}' from group '{}': {}", member_tag, tag, e);
            }
        }

        // Add new members
        for member in members {
            let ecmp_member = crate::ecmp::group::EcmpMember::with_weight(
                member.outbound.clone(),
                member.weight,
            );
            if let Err(e) = group.add_member(ecmp_member) {
                warn!("Failed to add member '{}' to group '{}': {}", member.outbound, tag, e);
                return IpcResponse::error(
                    Self::ecmp_error_to_code(&e),
                    e.to_string(),
                );
            }
        }

        info!("Updated ECMP group '{}' members", tag);
        IpcResponse::success_with_message(format!("ECMP group '{tag}' members updated"))
    }

    // ========================================================================
    // Peer Management Handler Implementations
    // ========================================================================

    /// Handle `GeneratePairRequest` command
    ///
    /// Generates an offline pairing request code.
    fn handle_generate_pair_request(
        &self,
        local_tag: String,
        local_description: String,
        local_endpoint: String,
        local_api_port: u16,
        bidirectional: bool,
        tunnel_type: super::protocol::TunnelType,
    ) -> IpcResponse {
        let Some(peer_manager) = &self.peer_manager else {
            return IpcResponse::error(
                ErrorCode::OperationFailed,
                "Peer manager not available",
            );
        };

        let config = PairRequestConfig {
            local_tag,
            local_description,
            local_endpoint,
            local_api_port,
            bidirectional,
            tunnel_type,
        };

        match peer_manager.generate_pair_request(config) {
            Ok(result) => {
                info!("Generated pairing request code");
                IpcResponse::Pairing(PairingResponse {
                    success: true,
                    code: Some(result.code),
                    message: Some("Pairing request generated".to_string()),
                    peer_tag: None,
                    wg_local_private_key: Some(result.wg_local_private_key),
                    tunnel_local_ip: Some(result.tunnel_local_ip),
                    tunnel_port: Some(result.tunnel_port),
                })
            }
            Err(e) => {
                warn!("Failed to generate pairing request: {}", e);
                IpcResponse::Pairing(PairingResponse {
                    success: false,
                    code: None,
                    message: Some(e.to_string()),
                    peer_tag: None,
                    wg_local_private_key: None,
                    tunnel_local_ip: None,
                    tunnel_port: None,
                })
            }
        }
    }

    /// Handle `ImportPairRequest` command
    ///
    /// Imports a pairing request and generates a response code.
    async fn handle_import_pair_request(
        &self,
        code: String,
        local_tag: String,
        local_description: String,
        local_endpoint: String,
        local_api_port: u16,
    ) -> IpcResponse {
        let Some(peer_manager) = &self.peer_manager else {
            return IpcResponse::error(
                ErrorCode::OperationFailed,
                "Peer manager not available",
            );
        };

        let local_config = PairRequestConfig {
            local_tag,
            local_description,
            local_endpoint,
            local_api_port,
            bidirectional: false, // Not relevant for import
            tunnel_type: super::protocol::TunnelType::WireGuard, // Will be determined from request
        };

        match peer_manager.import_pair_request(&code, local_config).await {
            Ok(result) => {
                info!(
                    peer_tag = %result.peer_tag,
                    tunnel_port = result.tunnel_port,
                    "Imported pairing request, generated response code"
                );
                IpcResponse::Pairing(PairingResponse {
                    success: true,
                    code: Some(result.response_code),
                    message: Some("Pairing request imported".to_string()),
                    peer_tag: Some(result.peer_tag),
                    wg_local_private_key: Some(result.wg_local_private_key),
                    tunnel_local_ip: Some(result.tunnel_local_ip),
                    tunnel_port: Some(result.tunnel_port),
                })
            }
            Err(e) => {
                warn!("Failed to import pairing request: {}", e);
                IpcResponse::Pairing(PairingResponse {
                    success: false,
                    code: None,
                    message: Some(e.to_string()),
                    peer_tag: None,
                    wg_local_private_key: None,
                    tunnel_local_ip: None,
                    tunnel_port: None,
                })
            }
        }
    }

    /// Handle `CompleteHandshake` command
    ///
    /// Completes the pairing handshake with a response code.
    async fn handle_complete_handshake(&self, code: String) -> IpcResponse {
        let Some(peer_manager) = &self.peer_manager else {
            return IpcResponse::error(
                ErrorCode::OperationFailed,
                "Peer manager not available",
            );
        };

        match peer_manager.complete_handshake(&code).await {
            Ok(result) => {
                info!(peer_tag = %result.peer_tag, "Completed pairing handshake");
                IpcResponse::Pairing(PairingResponse {
                    success: true,
                    code: None,
                    message: Some("Handshake completed".to_string()),
                    peer_tag: Some(result.peer_tag),
                    wg_local_private_key: Some(result.wg_local_private_key),
                    tunnel_local_ip: Some(result.tunnel_local_ip),
                    tunnel_port: Some(result.tunnel_port),
                })
            }
            Err(e) => {
                warn!("Failed to complete handshake: {}", e);
                IpcResponse::Pairing(PairingResponse {
                    success: false,
                    code: None,
                    message: Some(e.to_string()),
                    peer_tag: None,
                    wg_local_private_key: None,
                    tunnel_local_ip: None,
                    tunnel_port: None,
                })
            }
        }
    }

    /// Handle `AddPeer` command
    ///
    /// Adds a peer configuration directly to the PeerManager without going through
    /// the full pairing flow. This is useful for:
    /// - Restoring peers from database after restart
    /// - Manual peer configuration for testing
    /// - Synchronizing peers between nodes
    async fn handle_add_peer(&self, config: PeerConfig) -> IpcResponse {
        let Some(peer_manager) = &self.peer_manager else {
            return IpcResponse::error(
                ErrorCode::OperationFailed,
                "Peer manager not available",
            );
        };

        let tag = config.tag.clone();

        match peer_manager.add_peer(config) {
            Ok(()) => {
                info!("Added peer '{}' via IPC", tag);
                IpcResponse::success_with_message(format!("Peer '{tag}' added successfully"))
            }
            Err(e) => {
                warn!("Failed to add peer '{}': {}", tag, e);
                IpcResponse::error(Self::peer_error_to_code(&e), e.to_string())
            }
        }
    }

    /// Handle `ConnectPeer` command
    ///
    /// Connects to a configured peer node by creating a tunnel in WgEgressManager.
    /// This ensures peer tunnels are available for chain routing with the correct
    /// `peer-{tag}` naming convention.
    async fn handle_connect_peer(&self, tag: &str) -> IpcResponse {
        let Some(peer_manager) = &self.peer_manager else {
            return IpcResponse::error(
                ErrorCode::OperationFailed,
                "Peer manager not available",
            );
        };

        // Use PeerManager.connect() for both WireGuard and Xray peers
        // This stores WireGuard tunnels in peer_manager.wg_tunnels (without reply receiver)
        // which is required for smoltcp bidirectional communication in forward_via_wg_tunnel
        let peer_tunnel_tag = format!("peer-{}", tag);

        // Check if already connected via PeerManager
        if peer_manager.get_wg_tunnel(&peer_tunnel_tag).is_some() {
            return IpcResponse::success_with_message(format!(
                "Peer '{tag}' already connected (tunnel '{peer_tunnel_tag}' exists)"
            ));
        }

        match peer_manager.connect(tag).await {
            Ok(()) => {
                info!("Connected to peer '{}' via PeerManager", tag);
                IpcResponse::success_with_message(format!(
                    "Connected to peer '{tag}' via tunnel '{peer_tunnel_tag}'"
                ))
            }
            Err(e) => {
                warn!("Failed to connect to peer '{}': {}", tag, e);
                IpcResponse::error(Self::peer_error_to_code(&e), e.to_string())
            }
        }
    }

    /// Handle `DisconnectPeer` command
    ///
    /// Disconnects from a connected peer by calling PeerManager.disconnect().
    /// This properly cleans up the WireGuard tunnel and releases the UDP socket.
    async fn handle_disconnect_peer(&self, tag: &str) -> IpcResponse {
        let Some(peer_manager) = &self.peer_manager else {
            return IpcResponse::error(
                ErrorCode::OperationFailed,
                "Peer manager not available",
            );
        };

        // Use PeerManager's disconnect() for all peer types
        // This ensures proper cleanup of tunnels and UDP sockets
        match peer_manager.disconnect(tag).await {
            Ok(()) => {
                info!("Disconnected from peer '{}'", tag);
                IpcResponse::success_with_message(format!("Disconnected from peer '{tag}'"))
            }
            Err(e) => {
                warn!("Failed to disconnect from peer '{}': {}", tag, e);
                IpcResponse::error(
                    Self::peer_error_to_code(&e),
                    e.to_string(),
                )
            }
        }
    }

    /// Handle `GetPeerStatus` command
    ///
    /// Returns status information for a specific peer.
    fn handle_get_peer_status(&self, tag: &str) -> IpcResponse {
        let Some(peer_manager) = &self.peer_manager else {
            return IpcResponse::error(
                ErrorCode::OperationFailed,
                "Peer manager not available",
            );
        };

        match peer_manager.get_peer_status(tag) {
            Some(status) => IpcResponse::PeerStatus(status),
            None => IpcResponse::error(
                ErrorCode::NotFound,
                format!("Peer '{tag}' not found"),
            ),
        }
    }

    /// Handle `GetPeerTunnelHealth` command
    ///
    /// Returns health information for a peer's tunnel.
    fn handle_get_peer_tunnel_health(&self, tag: &str) -> IpcResponse {
        let Some(peer_manager) = &self.peer_manager else {
            return IpcResponse::error(
                ErrorCode::OperationFailed,
                "Peer manager not available",
            );
        };

        // For now, return the peer status which includes health-related fields
        // A more detailed health response could be added in the future
        match peer_manager.get_peer_status(tag) {
            Some(status) => {
                // Return peer status - includes last_handshake and other health indicators
                IpcResponse::PeerStatus(status)
            }
            None => IpcResponse::error(
                ErrorCode::NotFound,
                format!("Peer '{tag}' not found"),
            ),
        }
    }

    /// Handle `ListPeers` command
    ///
    /// Returns a list of all configured peers.
    fn handle_list_peers(&self) -> IpcResponse {
        let Some(peer_manager) = &self.peer_manager else {
            return IpcResponse::PeerList(PeerListResponse { peers: vec![] });
        };

        let peers = peer_manager.list_peers();
        IpcResponse::PeerList(PeerListResponse { peers })
    }

    /// Handle `RemovePeer` command
    ///
    /// Removes a peer configuration.
    ///
    /// Also removes the egress tunnel to release bound UDP ports.
    async fn handle_remove_peer(&self, tag: &str) -> IpcResponse {
        let Some(peer_manager) = &self.peer_manager else {
            return IpcResponse::error(
                ErrorCode::OperationFailed,
                "Peer manager not available",
            );
        };

        // Get peer config to check tunnel type before removal
        let config = peer_manager.get_peer_config(tag);

        // For WireGuard peers, remove egress tunnel first to release UDP port
        if let Some(ref cfg) = config {
            if cfg.tunnel_type == TunnelType::WireGuard {
                if let Some(wg_egress_manager) = &self.wg_egress_manager {
                    let peer_tunnel_tag = format!("peer-{}", tag);
                    if wg_egress_manager.has_tunnel(&peer_tunnel_tag) {
                        if let Err(e) = wg_egress_manager.remove_tunnel(&peer_tunnel_tag, None).await {
                            warn!("Failed to remove peer tunnel '{}': {}", peer_tunnel_tag, e);
                        } else {
                            info!("Removed peer tunnel '{}' (releasing UDP port)", peer_tunnel_tag);
                        }
                    }
                }
            }
        }

        match peer_manager.remove_peer(tag).await {
            Ok(()) => {
                info!("Removed peer '{}'", tag);
                IpcResponse::success_with_message(format!("Peer '{tag}' removed"))
            }
            Err(e) => {
                warn!("Failed to remove peer '{}': {}", tag, e);
                IpcResponse::error(
                    Self::peer_error_to_code(&e),
                    e.to_string(),
                )
            }
        }
    }

    // ========================================================================
    // Error Code Conversion Helpers
    // ========================================================================

    /// Convert `EgressError` to IPC `ErrorCode`
    fn egress_error_to_code(err: &crate::egress::error::EgressError) -> ErrorCode {
        use crate::egress::error::EgressError;
        match err {
            EgressError::TunnelNotFound(_) => ErrorCode::NotFound,
            EgressError::TunnelAlreadyExists(_) => ErrorCode::AlreadyExists,
            EgressError::ShuttingDown => ErrorCode::ShuttingDown,
            EgressError::InvalidConfig(_) => ErrorCode::InvalidParameters,
            _ => ErrorCode::OperationFailed,
        }
    }

    /// Convert `EcmpGroupError` to IPC `ErrorCode`
    fn ecmp_error_to_code(err: &crate::ecmp::group::EcmpGroupError) -> ErrorCode {
        use crate::ecmp::group::EcmpGroupError;
        match err {
            EcmpGroupError::GroupNotFound(_) | EcmpGroupError::MemberNotFound(_) => {
                ErrorCode::NotFound
            }
            EcmpGroupError::GroupExists(_) | EcmpGroupError::MemberExists(_) => {
                ErrorCode::AlreadyExists
            }
            EcmpGroupError::InvalidRoutingMark(_) | EcmpGroupError::InvalidWeight(_) => {
                ErrorCode::InvalidParameters
            }
            EcmpGroupError::NoMembers | EcmpGroupError::NoHealthyMembers => {
                ErrorCode::OperationFailed
            }
            _ => ErrorCode::InternalError,
        }
    }

    /// Convert `PeerError` to IPC `ErrorCode`
    fn peer_error_to_code(err: &crate::peer::manager::PeerError) -> ErrorCode {
        use crate::peer::manager::PeerError;
        match err {
            PeerError::NotFound(_) | PeerError::PendingRequestNotFound(_) => ErrorCode::NotFound,
            PeerError::AlreadyExists(_) | PeerError::AlreadyConnected(_) => ErrorCode::AlreadyExists,
            PeerError::NotConnected(_) | PeerError::NotConfigured(_) => ErrorCode::OperationFailed,
            PeerError::Validation(_) | PeerError::PairingMismatch { .. } => {
                ErrorCode::InvalidParameters
            }
            PeerError::PortExhausted
            | PeerError::IpExhausted
            | PeerError::MissingBidirectionalKey
            | PeerError::MissingWgKey => ErrorCode::OperationFailed,
            PeerError::XrayRelayNotSupported(_) => ErrorCode::OperationFailed,
            PeerError::TunnelCreationFailed(_)
            | PeerError::TunnelError(_)
            | PeerError::Pairing(_)
            | PeerError::Ipc(_)
            | PeerError::Internal(_) => ErrorCode::InternalError,
        }
    }

    /// Convert `ChainError` to IPC `ErrorCode`
    fn chain_error_to_code(err: &crate::chain::ChainError) -> ErrorCode {
        use crate::chain::ChainError;
        match err {
            ChainError::NotFound(_) => ErrorCode::NotFound,
            ChainError::AlreadyExists(_) => ErrorCode::AlreadyExists,
            ChainError::AlreadyActivating(_)
            | ChainError::AlreadyActive(_)
            | ChainError::CannotRemoveActiveChain(_)
            | ChainError::InvalidState { .. } => ErrorCode::OperationFailed,
            ChainError::InvalidTag(_)
            | ChainError::InvalidDescription(_)
            | ChainError::InvalidDscp(_)
            | ChainError::NoHops
            | ChainError::NoTerminal
            | ChainError::TooManyHops(_)
            | ChainError::DirectNotAllowed
            | ChainError::SocksEgressNotAllowed(_)
            | ChainError::XrayRelayNotAllowed
            | ChainError::InvalidHopSequence(_) => ErrorCode::InvalidParameters,
            ChainError::DscpConflict(_) | ChainError::DscpExhausted => ErrorCode::OperationFailed,
            ChainError::PeerNotFound(_)
            | ChainError::PeerNotConnected(_)
            | ChainError::EgressNotFound(_) => ErrorCode::NotFound,
            ChainError::NotInChain => ErrorCode::PermissionDenied,
            ChainError::PrepareFailed(_, _)
            | ChainError::CommitFailed(_, _)
            | ChainError::PartialCommit { .. }
            | ChainError::RemoteValidationFailed(_)
            | ChainError::RuleEngine(_)
            | ChainError::LockError(_)
            | ChainError::Internal(_) => ErrorCode::InternalError,
        }
    }

    // ========================================================================
    // DNS Command Handler Implementations
    // ========================================================================

    /// Handle `GetDnsStats` command
    ///
    /// Returns comprehensive DNS statistics including cache, blocking, and upstream metrics.
    fn handle_get_dns_stats(&self) -> IpcResponse {
        let Some(dns_engine) = &self.dns_engine else {
            return IpcResponse::error(
                ErrorCode::OperationFailed,
                "DNS engine not enabled",
            );
        };

        let cache_stats = dns_engine.cache().stats_snapshot();
        let block_stats = dns_engine.block_filter().stats();
        let _log_stats = dns_engine.query_logger().stats_snapshot();

        // Calculate total queries from components
        let total_queries = cache_stats.hits + cache_stats.misses;
        let upstream_queries = cache_stats.misses; // Queries that went to upstream

        // Calculate average latency (placeholder - would need tracking in a real implementation)
        // For now, return 0 as we don't have latency tracking in the current architecture
        let avg_latency_us = 0;

        IpcResponse::DnsStats(DnsStatsResponse {
            enabled: dns_engine.config().enabled,
            uptime_secs: dns_engine.uptime_secs(),
            total_queries,
            cache_hits: cache_stats.hits,
            cache_misses: cache_stats.misses,
            blocked_queries: block_stats.blocked_count,
            upstream_queries,
            avg_latency_us,
        })
    }

    /// Handle `GetDnsCacheStats` command
    ///
    /// Returns detailed cache statistics.
    fn handle_get_dns_cache_stats(&self) -> IpcResponse {
        let Some(dns_engine) = &self.dns_engine else {
            return IpcResponse::error(
                ErrorCode::OperationFailed,
                "DNS engine not enabled",
            );
        };

        let stats = dns_engine.cache().stats_snapshot();
        let current_entries = dns_engine.cache().len();
        let max_entries = dns_engine.config().cache.max_entries;

        // Calculate hit rate
        let total = stats.hits + stats.misses;
        let hit_rate = if total > 0 {
            stats.hits as f64 / total as f64
        } else {
            0.0
        };

        IpcResponse::DnsCacheStats(DnsCacheStatsResponse {
            enabled: dns_engine.config().cache.enabled,
            max_entries,
            current_entries,
            hits: stats.hits,
            misses: stats.misses,
            hit_rate,
            negative_hits: stats.negative_hits,
            inserts: stats.inserts,
            evictions: stats.evictions,
        })
    }

    /// Handle `FlushDnsCache` command
    ///
    /// Flushes cache entries matching the optional pattern.
    fn handle_flush_dns_cache(&self, pattern: Option<String>) -> IpcResponse {
        let Some(dns_engine) = &self.dns_engine else {
            return IpcResponse::error(
                ErrorCode::OperationFailed,
                "DNS engine not enabled",
            );
        };

        let flushed = if let Some(p) = pattern {
            let count = dns_engine.cache().flush(Some(&p));
            info!("Flushed {} DNS cache entries matching pattern: {}", count, p);
            format!("Flushed {count} entries matching '{p}'")
        } else {
            let count = dns_engine.cache().flush(None);
            info!("Flushed {} DNS cache entries", count);
            format!("Flushed {count} cache entries")
        };

        IpcResponse::success_with_message(flushed)
    }

    /// Handle `GetDnsBlockStats` command
    ///
    /// Returns DNS blocking/filtering statistics.
    fn handle_get_dns_block_stats(&self) -> IpcResponse {
        let Some(dns_engine) = &self.dns_engine else {
            return IpcResponse::error(
                ErrorCode::OperationFailed,
                "DNS engine not enabled",
            );
        };

        let stats = dns_engine.block_filter().stats();
        let total_queries = stats.total_queries;
        let blocked_queries = stats.blocked_count;

        // Calculate block rate
        let block_rate = if total_queries > 0 {
            blocked_queries as f64 / total_queries as f64
        } else {
            0.0
        };

        // BlockFilterStats doesn't track last_reload time
        let last_reload: Option<String> = None;

        IpcResponse::DnsBlockStats(DnsBlockStatsResponse {
            enabled: dns_engine.config().blocking.enabled,
            rule_count: stats.rule_count,
            blocked_queries,
            total_queries,
            block_rate,
            last_reload,
        })
    }

    /// Handle `ReloadDnsBlocklist` command
    ///
    /// Reloads blocking rules from the sing-box ruleset file (hot-reload).
    /// Reads from /etc/sing-box/rulesets/__adblock_combined__.json by default.
    fn handle_reload_dns_blocklist(&self) -> IpcResponse {
        let Some(dns_engine) = &self.dns_engine else {
            return IpcResponse::error(
                ErrorCode::OperationFailed,
                "DNS engine not enabled",
            );
        };

        // Path to the combined adblock ruleset file (generated by api_server)
        let blocklist_path = std::path::Path::new("/etc/sing-box/rulesets/__adblock_combined__.json");
        
        if !blocklist_path.exists() {
            info!("DNS blocklist file not found: {:?}, clearing blocklist", blocklist_path);
            // Clear the blocklist if file doesn't exist
            dns_engine.block_filter().clear();
            return IpcResponse::success_with_message("Blocklist cleared (no file found)");
        }

        // Read and parse the blocklist file
        let file_content = match std::fs::read_to_string(blocklist_path) {
            Ok(content) => content,
            Err(e) => {
                return IpcResponse::error(
                    ErrorCode::InternalError,
                    format!("Failed to read blocklist file: {e}"),
                );
            }
        };

        // Parse as sing-box ruleset format: {"version": 1, "rules": [{"domain_suffix": [...]}]}
        let json_value: serde_json::Value = match serde_json::from_str(&file_content) {
            Ok(v) => v,
            Err(e) => {
                return IpcResponse::error(
                    ErrorCode::InvalidParameters,
                    format!("Failed to parse blocklist JSON: {e}"),
                );
            }
        };

        // Extract domain_suffix from rules array
        let mut domains: Vec<String> = Vec::new();
        
        if let Some(rules) = json_value.get("rules").and_then(|r| r.as_array()) {
            for rule in rules {
                // Handle domain_suffix
                if let Some(suffixes) = rule.get("domain_suffix").and_then(|s| s.as_array()) {
                    for suffix in suffixes {
                        if let Some(s) = suffix.as_str() {
                            domains.push(s.to_string());
                        }
                    }
                }
                // Handle domain (exact match)
                if let Some(exact_domains) = rule.get("domain").and_then(|d| d.as_array()) {
                    for domain in exact_domains {
                        if let Some(d) = domain.as_str() {
                            domains.push(d.to_string());
                        }
                    }
                }
            }
        }

        let domain_count = domains.len();
        info!("Loading {} domains from blocklist file", domain_count);

        // Load domains into the block filter
        match dns_engine.block_filter().load_from_domains(&domains) {
            Ok(loaded) => {
                info!("DNS blocklist reloaded: {} domains loaded", loaded);
                IpcResponse::success_with_message(format!(
                    "Blocklist reloaded with {} domains",
                    loaded
                ))
            }
            Err(e) => {
                IpcResponse::error(
                    ErrorCode::InternalError,
                    format!("Failed to load blocklist: {e}"),
                )
            }
        }
    }

    /// Handle `AddDnsUpstream` command
    ///
    /// Adds a new upstream DNS server.
    async fn handle_add_dns_upstream(
        &self,
        tag: String,
        config: super::protocol::DnsUpstreamConfig,
    ) -> IpcResponse {
        let Some(_dns_engine) = &self.dns_engine else {
            return IpcResponse::error(
                ErrorCode::OperationFailed,
                "DNS engine not enabled",
            );
        };

        // Validate protocol
        let protocol = match config.protocol.to_lowercase().as_str() {
            "udp" | "tcp" | "doh" | "dot" => config.protocol.to_lowercase(),
            _ => {
                return IpcResponse::error(
                    ErrorCode::InvalidParameters,
                    format!("Invalid protocol '{}': must be udp, tcp, doh, or dot", config.protocol),
                );
            }
        };

        // Note: Adding upstreams dynamically requires UpstreamPool to support add_upstream
        // This is a placeholder that logs the attempt
        info!(
            "Add upstream request: tag={}, address={}, protocol={}",
            tag, config.address, protocol
        );

        // For now, return an error indicating this operation is not yet implemented
        // A full implementation would need to:
        // 1. Create the appropriate upstream client (UDP, TCP, DoH, or DoT)
        // 2. Add it to the UpstreamPool
        IpcResponse::error(
            ErrorCode::OperationFailed,
            "Dynamic upstream addition not yet implemented",
        )
    }

    /// Handle `RemoveDnsUpstream` command
    ///
    /// Removes an upstream DNS server by tag.
    async fn handle_remove_dns_upstream(&self, tag: &str) -> IpcResponse {
        let Some(_dns_engine) = &self.dns_engine else {
            return IpcResponse::error(
                ErrorCode::OperationFailed,
                "DNS engine not enabled",
            );
        };

        info!("Remove upstream request: tag={}", tag);

        // Placeholder - UpstreamPool would need remove_upstream method
        IpcResponse::error(
            ErrorCode::OperationFailed,
            "Dynamic upstream removal not yet implemented",
        )
    }

    /// Handle `GetDnsUpstreamStatus` command
    ///
    /// Returns status information for upstream servers.
    fn handle_get_dns_upstream_status(&self, tag: Option<String>) -> IpcResponse {
        let Some(dns_engine) = &self.dns_engine else {
            return IpcResponse::error(
                ErrorCode::OperationFailed,
                "DNS engine not enabled",
            );
        };

        let upstream_pool = dns_engine.upstream_pool();

        // Use upstream_info() method which returns UpstreamInfo structs
        let all_upstreams = upstream_pool.upstream_info();

        let upstreams: Vec<DnsUpstreamInfo> = all_upstreams
            .into_iter()
            .filter(|u| tag.is_none() || tag.as_ref().is_some_and(|t| t == &u.tag))
            .map(|u| DnsUpstreamInfo {
                tag: u.tag,
                address: u.address,
                protocol: u.protocol.to_string(),
                healthy: u.healthy,
                total_queries: 0,     // Pool stats are aggregate, not per-upstream
                failed_queries: 0,
                avg_latency_us: 0,
                last_success: None,
                last_failure: None,
            })
            .collect();

        if let Some(t) = &tag {
            if upstreams.is_empty() {
                return IpcResponse::error(
                    ErrorCode::NotFound,
                    format!("Upstream '{t}' not found"),
                );
            }
        }

        IpcResponse::DnsUpstreamStatus(DnsUpstreamStatusResponse { upstreams })
    }

    /// Handle `AddDnsRoute` command
    ///
    /// Adds a DNS routing rule.
    fn handle_add_dns_route(
        &self,
        pattern: String,
        match_type: String,
        upstream_tag: String,
    ) -> IpcResponse {
        let Some(dns_engine) = &self.dns_engine else {
            return IpcResponse::error(
                ErrorCode::OperationFailed,
                "DNS engine not enabled",
            );
        };

        // Parse match type
        let mt = match match_type.to_lowercase().as_str() {
            "exact" => DomainMatchType::Exact,
            "suffix" => DomainMatchType::Suffix,
            "keyword" => DomainMatchType::Keyword,
            "regex" => DomainMatchType::Regex,
            _ => {
                return IpcResponse::error(
                    ErrorCode::InvalidParameters,
                    format!(
                        "Invalid match_type '{match_type}': must be exact, suffix, keyword, or regex"
                    ),
                );
            }
        };

        // Add the route
        match dns_engine.router().add_route(&pattern, mt, &upstream_tag) {
            Ok(()) => {
                info!(
                    "Added DNS route: {} ({}) -> {}",
                    pattern, match_type, upstream_tag
                );
                IpcResponse::success_with_message(format!(
                    "Route added: {pattern} -> {upstream_tag}"
                ))
            }
            Err(e) => {
                warn!("Failed to add DNS route: {}", e);
                IpcResponse::error(ErrorCode::OperationFailed, e.to_string())
            }
        }
    }

    /// Handle `RemoveDnsRoute` command
    ///
    /// Removes a DNS routing rule by pattern.
    fn handle_remove_dns_route(&self, pattern: &str) -> IpcResponse {
        let Some(dns_engine) = &self.dns_engine else {
            return IpcResponse::error(
                ErrorCode::OperationFailed,
                "DNS engine not enabled",
            );
        };

        match dns_engine.router().remove_route(pattern) {
            Ok(removed) => {
                if removed {
                    info!("Removed DNS route: {}", pattern);
                    IpcResponse::success_with_message(format!("Route '{pattern}' removed"))
                } else {
                    IpcResponse::error(
                        ErrorCode::NotFound,
                        format!("Route '{pattern}' not found"),
                    )
                }
            }
            Err(e) => {
                warn!("Failed to remove DNS route: {}", e);
                IpcResponse::error(ErrorCode::OperationFailed, e.to_string())
            }
        }
    }

    /// Handle `GetDnsQueryLog` command
    ///
    /// Returns recent DNS query log entries with pagination.
    fn handle_get_dns_query_log(&self, limit: usize, offset: usize) -> IpcResponse {
        let Some(dns_engine) = &self.dns_engine else {
            return IpcResponse::error(
                ErrorCode::OperationFailed,
                "DNS engine not enabled",
            );
        };

        // Note: QueryLogger is write-only by design (batch writes to file)
        // Reading query logs would require a separate log reader component
        // For now, return an empty response with appropriate metadata
        let stats = dns_engine.query_logger().stats_snapshot();
        let total_available = stats.entries_logged as usize;

        IpcResponse::DnsQueryLog(DnsQueryLogResponse {
            entries: vec![],
            total_available,
            offset,
            limit,
        })
    }

    /// Handle `DnsQuery` command
    ///
    /// Performs a test DNS query.
    async fn handle_dns_query(
        &self,
        domain: &str,
        qtype: Option<u16>,
        upstream: Option<String>,
    ) -> IpcResponse {
        let Some(dns_engine) = &self.dns_engine else {
            return IpcResponse::error(
                ErrorCode::OperationFailed,
                "DNS engine not enabled",
            );
        };

        use hickory_proto::op::{Message, Query};
        use hickory_proto::rr::{Name, RecordType};
        use std::str::FromStr;

        let record_type = match qtype.unwrap_or(1) {
            1 => RecordType::A,
            28 => RecordType::AAAA,
            5 => RecordType::CNAME,
            15 => RecordType::MX,
            16 => RecordType::TXT,
            n => {
                return IpcResponse::error(
                    ErrorCode::InvalidParameters,
                    format!("Unsupported query type: {n}"),
                );
            }
        };

        // Parse domain name
        let name = match Name::from_str(domain) {
            Ok(n) => n,
            Err(e) => {
                return IpcResponse::error(
                    ErrorCode::InvalidParameters,
                    format!("Invalid domain name: {e}"),
                );
            }
        };

        // Build query
        let mut query_msg = Message::new();
        query_msg.set_id(rand::random());
        query_msg.set_recursion_desired(true);
        query_msg.add_query(Query::query(name.clone(), record_type));

        let start = Instant::now();

        // Determine which upstream to use
        let upstream_pool = dns_engine.upstream_pool();

        // Perform query
        let result = if let Some(upstream_tag) = &upstream {
            // Query specific upstream
            upstream_pool.query_by_tag(upstream_tag, &query_msg).await
        } else {
            // Use router to determine upstream tag or default pool
            let routed_tag = dns_engine.router().route_to_tag(domain);
            upstream_pool.query_by_tag(&routed_tag, &query_msg).await
        };

        let latency_us = start.elapsed().as_micros() as u64;

        match result {
            Ok(response) => {
                // ResponseCode is an enum, use Into<u16> and truncate to u8
                let response_code: u8 = u16::from(response.response_code()) as u8;
                let answers: Vec<String> = response
                    .answers()
                    .iter()
                    .map(|r| r.data().map(std::string::ToString::to_string).unwrap_or_default())
                    .collect();

                IpcResponse::DnsQueryResult(DnsQueryResponse {
                    success: true,
                    domain: domain.to_string(),
                    qtype: qtype.unwrap_or(1),
                    response_code,
                    answers,
                    latency_us,
                    cached: false, // Direct query, not cached
                    blocked: false,
                    upstream_used: upstream,
                })
            }
            Err(e) => {
                warn!("DNS query failed for {}: {}", domain, e);
                IpcResponse::DnsQueryResult(DnsQueryResponse {
                    success: false,
                    domain: domain.to_string(),
                    qtype: qtype.unwrap_or(1),
                    response_code: 2, // SERVFAIL
                    answers: vec![],
                    latency_us,
                    cached: false,
                    blocked: false,
                    upstream_used: upstream,
                })
            }
        }
    }

    /// Handle `GetDnsConfig` command
    ///
    /// Returns the current DNS engine configuration.
    fn handle_get_dns_config(&self) -> IpcResponse {
        let Some(dns_engine) = &self.dns_engine else {
            return IpcResponse::error(
                ErrorCode::OperationFailed,
                "DNS engine not enabled",
            );
        };

        let config = dns_engine.config();
        let upstream_pool = dns_engine.upstream_pool();

        // Build upstream info list using upstream_info()
        let upstreams: Vec<DnsUpstreamInfo> = upstream_pool
            .upstream_info()
            .into_iter()
            .map(|u| DnsUpstreamInfo {
                tag: u.tag,
                address: u.address,
                protocol: u.protocol.to_string(),
                healthy: u.healthy,
                total_queries: 0,
                failed_queries: 0,
                avg_latency_us: 0,
                last_success: None,
                last_failure: None,
            })
            .collect();

        // Build available_features map to inform clients about implementation status
        let mut available_features = std::collections::HashMap::new();
        available_features.insert("get_dns_stats".to_string(), "available".to_string());
        available_features.insert("get_dns_cache_stats".to_string(), "available".to_string());
        available_features.insert("flush_dns_cache".to_string(), "available".to_string());
        available_features.insert("get_dns_block_stats".to_string(), "available".to_string());
        available_features.insert("reload_dns_blocklist".to_string(), "available".to_string());
        available_features.insert("get_dns_upstream_status".to_string(), "available".to_string());
        available_features.insert("add_dns_route".to_string(), "available".to_string());
        available_features.insert("remove_dns_route".to_string(), "available".to_string());
        available_features.insert("dns_query".to_string(), "available".to_string());
        available_features.insert("get_dns_config".to_string(), "available".to_string());
        // Partially/not implemented features
        available_features.insert("add_dns_upstream".to_string(), "not_implemented".to_string());
        available_features.insert("remove_dns_upstream".to_string(), "not_implemented".to_string());
        available_features.insert("get_dns_query_log".to_string(), "partial".to_string());

        IpcResponse::DnsConfig(DnsConfigResponse {
            enabled: config.enabled,
            listen_udp: config.listen_udp.to_string(),
            listen_tcp: config.listen_tcp.to_string(),
            upstreams,
            cache_enabled: config.cache.enabled,
            cache_max_entries: config.cache.max_entries,
            blocking_enabled: config.blocking.enabled,
            blocking_response_type: config.blocking.response_type.to_string(),
            logging_enabled: config.logging.enabled,
            logging_format: config.logging.format.to_string(),
            available_features,
        })
    }

    // ================================================================
    // WARP Registration Handler
    // ================================================================

    /// Handle WARP device registration
    ///
    /// Registers a new WARP device with Cloudflare, generating WireGuard configuration.
    async fn handle_register_warp(
        &self,
        tag: String,
        name: Option<String>,
        warp_plus_license: Option<String>,
    ) -> IpcResponse {
        use crate::warp::register::register_device;
        use super::protocol::WarpRegistrationResponse;

        info!("Registering WARP device: tag={}, name={:?}", tag, name);

        match register_device(tag.clone(), warp_plus_license).await {
            Ok(config) => {
                info!("WARP registration successful: {}", tag);
                IpcResponse::WarpRegistration(WarpRegistrationResponse {
                    tag: config.tag,
                    account_id: config.account_id,
                    license_key: config.license_key,
                    private_key: config.private_key,
                    peer_public_key: config.peer_public_key,
                    endpoint: config.endpoint,
                    reserved: config.reserved,
                    ipv4_address: config.ipv4_address,
                    ipv6_address: config.ipv6_address,
                    account_type: config.account_type,
                })
            }
            Err(e) => {
                warn!("WARP registration failed for '{}': {}", tag, e);

                // Provide appropriate error code based on error type
                let error_code = if e.is_recoverable() {
                    ErrorCode::OperationFailed  // Recoverable errors (rate limit, network)
                } else {
                    ErrorCode::InvalidParameters  // Invalid input
                };

                IpcResponse::error(error_code, format!("WARP registration failed: {}", e))
            }
        }
    }

    /// Handle speed test command
    ///
    /// Downloads a file through the specified outbound/tunnel and measures speed.
    async fn handle_speed_test(
        &self,
        tag: String,
        size_bytes: u64,
        timeout_secs: u64,
    ) -> IpcResponse {
        use super::protocol::SpeedTestResponse;

        info!("Starting speed test for '{}' (size={}B, timeout={}s)", tag, size_bytes, timeout_secs);
        let start = Instant::now();
        let test_url = format!("https://speed.cloudflare.com/__down?bytes={}", size_bytes);

        // Try to find the outbound - check WireGuard tunnels first, then ECMP groups, then regular outbounds
        let tunnel_found = if let Some(ref wg_manager) = self.wg_egress_manager {
            wg_manager.has_tunnel(&tag)
        } else {
            false
        };

        let ecmp_found = if let Some(ref ecmp_manager) = self.ecmp_group_manager {
            ecmp_manager.get_group(&tag).is_some()
        } else {
            false
        };

        let outbound_found = self.outbound_manager.contains(&tag);

        if !tunnel_found && !ecmp_found && !outbound_found {
            return IpcResponse::SpeedTestResult(SpeedTestResponse {
                success: false,
                speed_mbps: 0.0,
                bytes_downloaded: 0,
                duration_ms: 0,
                outbound: tag.clone(),
                error: Some(format!("Outbound '{}' not found", tag)),
            });
        }

        // Perform the HTTP request through the tunnel
        // For WireGuard tunnels, we need to use the tunnel's socket
        let result = if tunnel_found {
            if let Some(ref wg_manager) = self.wg_egress_manager {
                self.speed_test_via_wg_tunnel(wg_manager, &tag, &test_url, timeout_secs).await
            } else {
                Err("WireGuard manager not available".to_string())
            }
        } else if ecmp_found {
            // For ECMP groups, pick a member and test through it
            if let Some(ref ecmp_manager) = self.ecmp_group_manager {
                if let Some(group) = ecmp_manager.get_group(&tag) {
                    let members = group.member_tags();
                    if members.is_empty() {
                        Err("ECMP group has no members".to_string())
                    } else {
                        // Test through the first healthy member
                        let member_tag = &members[0];
                        if let Some(ref wg_manager) = self.wg_egress_manager {
                            if wg_manager.has_tunnel(member_tag) {
                                self.speed_test_via_wg_tunnel(wg_manager, member_tag, &test_url, timeout_secs).await
                            } else {
                                Err(format!("ECMP member '{}' is not a WireGuard tunnel", member_tag))
                            }
                        } else {
                            Err("WireGuard manager not available".to_string())
                        }
                    }
                } else {
                    Err(format!("ECMP group '{}' not found", tag))
                }
            } else {
                Err("ECMP manager not available".to_string())
            }
        } else {
            // Regular outbound - not supported for speed test
            Err("Speed test only supported for WireGuard tunnels and ECMP groups".to_string())
        };

        let duration = start.elapsed();
        let duration_ms = duration.as_millis() as u64;

        match result {
            Ok(bytes) => {
                let speed_mbps = if duration_ms > 0 {
                    (bytes as f64 * 8.0) / (duration_ms as f64 / 1000.0) / 1_000_000.0
                } else {
                    0.0
                };

                info!("Speed test completed for '{}': {:.2} Mbps ({} bytes in {}ms)", 
                    tag, speed_mbps, bytes, duration_ms);

                IpcResponse::SpeedTestResult(SpeedTestResponse {
                    success: true,
                    speed_mbps,
                    bytes_downloaded: bytes,
                    duration_ms,
                    outbound: tag,
                    error: None,
                })
            }
            Err(e) => {
                warn!("Speed test failed for '{}': {}", tag, e);
                IpcResponse::SpeedTestResult(SpeedTestResponse {
                    success: false,
                    speed_mbps: 0.0,
                    bytes_downloaded: 0,
                    duration_ms,
                    outbound: tag,
                    error: Some(e),
                })
            }
        }
    }

    /// Perform speed test through a WireGuard tunnel using hyper
    #[cfg(feature = "dns-doh")]
    async fn speed_test_via_wg_tunnel(
        &self,
        _wg_manager: &Arc<WgEgressManager>,
        tag: &str,
        url: &str,
        timeout_secs: u64,
    ) -> Result<u64, String> {
        use std::time::Duration;
        use tokio::time::timeout;
        use http_body_util::BodyExt;

        // Install the default CryptoProvider (ring) for rustls 0.23+
        // This is idempotent - safe to call multiple times
        let _ = rustls::crypto::ring::default_provider().install_default();

        // Parse URL
        let uri: hyper::Uri = url.parse()
            .map_err(|e| format!("Invalid URL: {}", e))?;

        let host = uri.host()
            .ok_or_else(|| "URL missing host".to_string())?;
        let port = uri.port_u16().unwrap_or(443);
        let addr = format!("{}:{}", host, port);

        // Resolve DNS
        let socket_addrs: Vec<_> = tokio::net::lookup_host(&addr)
            .await
            .map_err(|e| format!("DNS lookup failed: {}", e))?
            .collect();

        let socket_addr = socket_addrs.first()
            .ok_or_else(|| "DNS lookup returned no addresses".to_string())?;

        // Connect with TLS
        let tcp_stream = tokio::net::TcpStream::connect(socket_addr)
            .await
            .map_err(|e| format!("TCP connect failed: {}", e))?;

        // Setup TLS
        let tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(self.get_root_certs())
            .with_no_client_auth();

        let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(tls_config));
        let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
            .map_err(|e| format!("Invalid server name: {}", e))?;

        let tls_stream = connector.connect(server_name, tcp_stream)
            .await
            .map_err(|e| format!("TLS handshake failed: {}", e))?;

        // Create HTTP connection
        let io = hyper_util::rt::TokioIo::new(tls_stream);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
            .await
            .map_err(|e| format!("HTTP handshake failed: {}", e))?;

        // Spawn connection driver
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                debug!("HTTP connection error: {}", e);
            }
        });

        // Build request
        let path = uri.path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/");

        let req = hyper::Request::builder()
            .method("GET")
            .uri(path)
            .header("Host", host)
            .header("User-Agent", "rust-router-speedtest/1.0")
            .body(http_body_util::Empty::<bytes::Bytes>::new())
            .map_err(|e| format!("Failed to build request: {}", e))?;

        // Send request with timeout
        let response = timeout(
            Duration::from_secs(timeout_secs),
            sender.send_request(req)
        )
        .await
        .map_err(|_| "Request timed out".to_string())?
        .map_err(|e| format!("HTTP request failed: {}", e))?;

        if !response.status().is_success() {
            return Err(format!("HTTP error: {}", response.status()));
        }

        // Read response body and count bytes
        let body = response.into_body();
        let bytes = body.collect()
            .await
            .map_err(|e| format!("Failed to read response: {}", e))?
            .to_bytes();

        info!("Speed test for '{}' downloaded {} bytes", tag, bytes.len());
        Ok(bytes.len() as u64)
    }

    /// Fallback when dns-doh feature is not enabled
    #[cfg(not(feature = "dns-doh"))]
    async fn speed_test_via_wg_tunnel(
        &self,
        _wg_manager: &Arc<WgEgressManager>,
        _tag: &str,
        _url: &str,
        _timeout_secs: u64,
    ) -> Result<u64, String> {
        Err("Speed test requires dns-doh feature to be enabled".to_string())
    }

    /// Get root certificates for TLS
    #[cfg(feature = "dns-doh")]
    fn get_root_certs(&self) -> rustls::RootCertStore {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        roots
    }

    // ========================================================================
    // Peer API Forwarding Handler
    // ========================================================================

    // Maximum response size for peer API requests (1 MB)
    const MAX_PEER_RESPONSE_SIZE: usize = 1024 * 1024;

    /// Validate HTTP method (allow-list)
    fn validate_http_method(method: &str) -> Result<(), String> {
        const ALLOWED_METHODS: &[&str] = &["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"];
        let upper = method.to_uppercase();
        if ALLOWED_METHODS.contains(&upper.as_str()) {
            Ok(())
        } else {
            Err(format!("Invalid HTTP method: '{}'", method))
        }
    }

    /// Validate request path (must start with /, no CR/LF/spaces for injection prevention)
    fn validate_request_path(path: &str) -> Result<(), String> {
        if !path.starts_with('/') {
            return Err("Path must start with '/'".to_string());
        }
        if path.contains('\r') || path.contains('\n') {
            return Err("Path contains invalid characters (CR/LF)".to_string());
        }
        // Check for null bytes
        if path.contains('\0') {
            return Err("Path contains null bytes".to_string());
        }
        Ok(())
    }

    /// Allowed API paths for peer forwarding (security allowlist)
    /// Only these paths can be forwarded to prevent SSRF attacks
    const ALLOWED_PEER_API_PATHS: &'static [&'static str] = &[
        "/api/peer-info/egress",
        "/api/peer-info/status",
        "/api/health",
        "/api/peer-notify/connected",
        "/api/peer-notify/disconnected",
        "/api/peer-chain/register",
        "/api/peer-chain/unregister",
        "/api/peer-event",
        // Chain routing endpoints
        "/api/chain-routing/register",
        "/api/chain-routing/unregister",
        "/api/chain-routing/prepare",
        "/api/chain-routing/commit",
        "/api/chain-routing/abort",
        "/api/chain-routing/status",
        "/api/chain-routing",
        "/api/chains",
        "/api/egress/list",
    ];

    /// Validate that the path is in the allowed list
    fn validate_path_allowlist(path: &str) -> Result<(), String> {
        // Extract base path (before query string)
        let base_path = path.split('?').next().unwrap_or(path);
        
        if Self::ALLOWED_PEER_API_PATHS.iter().any(|&allowed| base_path == allowed) {
            Ok(())
        } else {
            Err(format!(
                "Path '{}' is not in the allowed list for peer API forwarding",
                base_path
            ))
        }
    }

    /// Parse endpoint string to extract host for URL construction (handles IPv6)
    /// Returns the host in a format suitable for URL construction:
    /// - IPv6 addresses are returned with brackets: [::1]
    /// - IPv4 addresses and hostnames are returned as-is
    fn parse_endpoint_host(endpoint: &str) -> Result<String, String> {
        // Handle IPv6 addresses in brackets: [::1]:port
        if endpoint.starts_with('[') {
            if let Some(bracket_end) = endpoint.find(']') {
                // Return with brackets for URL construction
                return Ok(endpoint[..=bracket_end].to_string());
            }
            return Err(format!("Invalid IPv6 endpoint format: {}", endpoint));
        }
        
        // Handle IPv4 or hostname: host:port
        // Find the last colon (for port), but be careful with IPv6 without brackets
        if let Some(colon_pos) = endpoint.rfind(':') {
            // Check if there's another colon before this one (could be IPv6 without brackets)
            let before_colon = &endpoint[..colon_pos];
            if before_colon.contains(':') {
                // This looks like IPv6 without brackets, return the whole thing
                // (though this is technically invalid endpoint format)
                return Err(format!(
                    "IPv6 endpoint must be in [host]:port format: {}",
                    endpoint
                ));
            }
            return Ok(before_colon.to_string());
        }
        
        // No port specified, return the whole string as host
        Ok(endpoint.to_string())
    }

    /// Handle forward peer request command
    ///
    /// Forwards an HTTP request to a peer node's API. The routing strategy depends
    /// on the peer's tunnel type:
    /// - **Xray peers**: Proxies through the SOCKS5 outbound to the peer's tunnel IP
    /// - **WireGuard peers**: Routes through the userspace WireGuard tunnel using smoltcp
    ///
    /// For WireGuard peers with tunnel IPs, we use smoltcp to create a TCP connection
    /// through the encrypted tunnel, providing end-to-end encrypted API communication.
    async fn handle_forward_peer_request(
        &self,
        peer_tag: String,
        method: String,
        path: String,
        body: Option<String>,
        timeout_secs: u32,
        // Inline config fields - if provided, use these instead of PeerManager lookup
        endpoint: Option<String>,
        tunnel_type: Option<String>,
        api_port: Option<u16>,
        tunnel_ip: Option<String>,
        // Local tunnel IP (our end of the tunnel)
        tunnel_local_ip: Option<String>,
        // Custom headers to include in the request
        headers: Option<std::collections::HashMap<String, String>>,
    ) -> IpcResponse {
        use super::protocol::PeerRequestResponse;

        info!(
            peer = %peer_tag,
            method = %method,
            path = %path,
            has_inline_config = endpoint.is_some(),
            has_custom_headers = headers.is_some(),
            "Forwarding peer API request"
        );

        // Validate method and path to prevent HTTP request smuggling/injection
        if let Err(e) = Self::validate_http_method(&method) {
            return IpcResponse::PeerRequestResult(PeerRequestResponse {
                success: false,
                status_code: 0,
                body: String::new(),
                error: Some(e),
            });
        }
        if let Err(e) = Self::validate_request_path(&path) {
            return IpcResponse::PeerRequestResult(PeerRequestResponse {
                success: false,
                status_code: 0,
                body: String::new(),
                error: Some(e),
            });
        }
        // Security: Only allow specific API paths to prevent SSRF
        if let Err(e) = Self::validate_path_allowlist(&path) {
            return IpcResponse::PeerRequestResult(PeerRequestResponse {
                success: false,
                status_code: 0,
                body: String::new(),
                error: Some(e),
            });
        }

        // Routing decision structure
        struct RoutingDecision {
            target_url: String,
            use_socks5: bool,
            use_wg_tunnel: bool,
            wg_local_ip: Option<std::net::Ipv4Addr>,
            wg_remote_ip: Option<std::net::Ipv4Addr>,
        }

        // Determine if we should use inline config or PeerManager lookup
        // Inline config takes precedence - this allows Python to pass peer info
        // from its database without requiring peers to be registered in PeerManager
        let routing = if let Some(ref ep) = endpoint {
            // Use inline config
            let ttype = tunnel_type.as_deref().unwrap_or("wireguard");
            let port = api_port.unwrap_or(36000);

            // Parse the endpoint host
            let host = match Self::parse_endpoint_host(ep) {
                Ok(h) => h,
                Err(e) => {
                    return IpcResponse::PeerRequestResult(PeerRequestResponse {
                        success: false,
                        status_code: 0,
                        body: String::new(),
                        error: Some(format!("Invalid endpoint '{}': {}", ep, e)),
                    });
                }
            };

            // Build target URL
            // Use tunnel IP when available for both Xray and WireGuard peers
            // This ensures requests come from the tunnel subnet (10.200.200.0/24)
            // which is whitelisted by nginx on the remote node
            let url = if let Some(ref tip) = tunnel_ip {
                // Use tunnel IP - works for both Xray (via SOCKS5) and WireGuard (routed via tunnel)
                format!("http://{}:{}{}", tip, port, path)
            } else {
                // Fallback to public endpoint
                format!("http://{}:{}{}", host, port, path)
            };

            // Determine routing strategy based on tunnel type and available IPs
            let use_socks = ttype == "xray" && tunnel_ip.is_some();

            // Use WireGuard tunnel if:
            // - tunnel type is "wireguard"
            // - we have both local and remote tunnel IPs
            // - peer manager is available (needed to get the tunnel)
            let (use_wg, wg_local, wg_remote) = if ttype == "wireguard" && tunnel_ip.is_some() && tunnel_local_ip.is_some() {
                // Parse the IPs
                let remote: Option<std::net::Ipv4Addr> = tunnel_ip.as_ref().and_then(|s| s.parse().ok());
                let local: Option<std::net::Ipv4Addr> = tunnel_local_ip.as_ref().and_then(|s| s.parse().ok());
                if let (Some(l), Some(r)) = (local, remote) {
                    (true, Some(l), Some(r))
                } else {
                    (false, None, None)
                }
            } else {
                (false, None, None)
            };

            debug!(
                peer = %peer_tag,
                tunnel_type = %ttype,
                url = %url,
                use_socks5 = use_socks,
                use_wg_tunnel = use_wg,
                "Using inline peer config"
            );

            RoutingDecision {
                target_url: url,
                use_socks5: use_socks,
                use_wg_tunnel: use_wg,
                wg_local_ip: wg_local,
                wg_remote_ip: wg_remote,
            }
        } else {
            // Fall back to PeerManager lookup (backward compatibility)
            let Some(ref peer_manager) = self.peer_manager else {
                return IpcResponse::PeerRequestResult(PeerRequestResponse {
                    success: false,
                    status_code: 0,
                    body: String::new(),
                    error: Some("No inline config provided and peer manager not available".to_string()),
                });
            };

            let Some(config) = peer_manager.get_peer_config(&peer_tag) else {
                return IpcResponse::PeerRequestResult(PeerRequestResponse {
                    success: false,
                    status_code: 0,
                    body: String::new(),
                    error: Some(format!("Peer '{}' not found in PeerManager and no inline config provided", peer_tag)),
                });
            };

            // Determine the target URL and routing based on tunnel type
            match config.tunnel_type {
                TunnelType::Xray => {
                    // For Xray peers, use the tunnel IP if available, otherwise public endpoint
                    let url = if let Some(ref tip) = config.tunnel_remote_ip {
                        format!("http://{}:{}{}", tip, config.api_port, path)
                    } else {
                        // Fallback to public endpoint (with proper IPv6 handling)
                        let host = match Self::parse_endpoint_host(&config.endpoint) {
                            Ok(h) => h,
                            Err(e) => {
                                return IpcResponse::PeerRequestResult(PeerRequestResponse {
                                    success: false,
                                    status_code: 0,
                                    body: String::new(),
                                    error: Some(e),
                                });
                            }
                        };
                        format!("http://{}:{}{}", host, config.api_port, path)
                    };
                    RoutingDecision {
                        target_url: url,
                        use_socks5: true,
                        use_wg_tunnel: false,
                        wg_local_ip: None,
                        wg_remote_ip: None,
                    }
                }
                TunnelType::WireGuard => {
                    // For WireGuard peers, prefer tunnel IP when available
                    // and route through the WireGuard tunnel using smoltcp
                    let (url, use_wg, wg_local, wg_remote) = if let (Some(ref local_ip), Some(ref remote_ip)) =
                        (&config.tunnel_local_ip, &config.tunnel_remote_ip)
                    {
                        // Parse IPs for WireGuard tunnel routing
                        let local: Option<std::net::Ipv4Addr> = local_ip.parse().ok();
                        let remote: Option<std::net::Ipv4Addr> = remote_ip.parse().ok();

                        if let (Some(l), Some(r)) = (local, remote) {
                            // Use tunnel IPs and route through WireGuard
                            let url = format!("http://{}:{}{}", remote_ip, config.api_port, path);
                            (url, true, Some(l), Some(r))
                        } else {
                            // IP parsing failed, fallback to public endpoint
                            let host = match Self::parse_endpoint_host(&config.endpoint) {
                                Ok(h) => h,
                                Err(e) => {
                                    return IpcResponse::PeerRequestResult(PeerRequestResponse {
                                        success: false,
                                        status_code: 0,
                                        body: String::new(),
                                        error: Some(e),
                                    });
                                }
                            };
                            let url = format!("http://{}:{}{}", host, config.api_port, path);
                            (url, false, None, None)
                        }
                    } else {
                        // No tunnel IPs configured, fallback to public endpoint
                        let host = match Self::parse_endpoint_host(&config.endpoint) {
                            Ok(h) => h,
                            Err(e) => {
                                return IpcResponse::PeerRequestResult(PeerRequestResponse {
                                    success: false,
                                    status_code: 0,
                                    body: String::new(),
                                    error: Some(e),
                                });
                            }
                        };
                        let url = format!("http://{}:{}{}", host, config.api_port, path);
                        (url, false, None, None)
                    };

                    RoutingDecision {
                        target_url: url,
                        use_socks5: false,
                        use_wg_tunnel: use_wg,
                        wg_local_ip: wg_local,
                        wg_remote_ip: wg_remote,
                    }
                }
            }
        };

        debug!(
            peer = %peer_tag,
            url = %routing.target_url,
            use_socks5 = routing.use_socks5,
            use_wg_tunnel = routing.use_wg_tunnel,
            "Target URL for peer request"
        );

        // Route based on tunnel type:
        // 1. SOCKS5 for Xray peers with tunnel IP
        // 2. WireGuard tunnel for WireGuard peers with tunnel IPs
        // 3. Direct HTTP for everything else
        let result = if routing.use_socks5 {
            // For Xray peers with tunnel IP, route through the SOCKS5 proxy
            let Some(ref peer_manager) = self.peer_manager else {
                return IpcResponse::PeerRequestResult(PeerRequestResponse {
                    success: false,
                    status_code: 0,
                    body: String::new(),
                    error: Some("SOCKS5 routing requires peer manager".to_string()),
                });
            };
            self.forward_via_socks5(
                peer_manager,
                &peer_tag,
                &routing.target_url,
                &method,
                body.as_deref(),
                Duration::from_secs(timeout_secs as u64),
            )
            .await
        } else if routing.use_wg_tunnel {
            // For WireGuard peers with tunnel IPs, route through the WireGuard tunnel
            let Some(ref peer_manager) = self.peer_manager else {
                return IpcResponse::PeerRequestResult(PeerRequestResponse {
                    success: false,
                    status_code: 0,
                    body: String::new(),
                    error: Some("WireGuard tunnel routing requires peer manager".to_string()),
                });
            };
            // We verified these are Some when we set use_wg_tunnel = true
            let local_ip = routing.wg_local_ip.unwrap();
            let remote_ip = routing.wg_remote_ip.unwrap();

            // The unified pump architecture sends outbound requests through a channel
            // instead of creating a competing pump.
            self.forward_via_wg_tunnel(
                peer_manager,
                &peer_tag,
                &routing.target_url,
                &method,
                body.as_deref(),
                Duration::from_secs(timeout_secs as u64),
                local_ip,
                remote_ip,
                headers.as_ref(),
            )
            .await
        } else {
            // Direct HTTP request to public endpoint
            self.forward_direct_http(
                &routing.target_url,
                &method,
                body.as_deref(),
                Duration::from_secs(timeout_secs as u64),
                headers.as_ref(),
            )
            .await
        };

        match result {
            Ok((status_code, response_body)) => {
                info!(
                    peer = %peer_tag,
                    status = status_code,
                    "Peer API request successful"
                );
                IpcResponse::PeerRequestResult(PeerRequestResponse {
                    success: status_code >= 200 && status_code < 300,
                    status_code,
                    body: response_body,
                    error: None,
                })
            }
            Err(e) => {
                warn!(peer = %peer_tag, error = %e, "Peer API request failed");
                IpcResponse::PeerRequestResult(PeerRequestResponse {
                    success: false,
                    status_code: 0,
                    body: String::new(),
                    error: Some(e),
                })
            }
        }
    }

    /// Forward HTTP request through SOCKS5 proxy (for Xray peers)
    #[allow(clippy::unused_async)]
    async fn forward_via_socks5(
        &self,
        peer_manager: &Arc<PeerManager>,
        peer_tag: &str,
        url: &str,
        method: &str,
        body: Option<&str>,
        timeout: Duration,
    ) -> Result<(u16, String), String> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::time::timeout as tokio_timeout;

        // Get the SOCKS5 outbound for this peer
        let outbound = peer_manager
            .get_xray_outbound(peer_tag)
            .ok_or_else(|| format!("Xray outbound for peer '{}' not found or not connected", peer_tag))?;

        // Parse the URL to get host, port, and path
        let uri: hyper::Uri = url
            .parse()
            .map_err(|e| format!("Invalid URL '{}': {}", url, e))?;

        let host = uri.host().ok_or_else(|| "URL missing host".to_string())?;
        let port = uri.port_u16().unwrap_or(80);
        let path = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");

        // Resolve destination address
        let dest_addr = format!("{}:{}", host, port);
        let socket_addrs: Vec<_> = tokio::net::lookup_host(&dest_addr)
            .await
            .map_err(|e| format!("DNS lookup failed for '{}': {}", dest_addr, e))?
            .collect();

        let dest = socket_addrs
            .first()
            .ok_or_else(|| format!("DNS lookup returned no addresses for '{}'", dest_addr))?;

        // Connect through SOCKS5
        let connection = tokio_timeout(timeout, outbound.connect(*dest, timeout))
            .await
            .map_err(|_| "SOCKS5 connection timed out".to_string())?
            .map_err(|e| format!("SOCKS5 connection failed: {}", e))?;

        // Take the stream from the connection
        let mut stream = connection.into_stream();

        // Build Host header (include port if non-default)
        let host_header = if port != 80 {
            format!("{}:{}", host, port)
        } else {
            host.to_string()
        };

        // Build HTTP request
        let content_length = body.map(|b| b.len()).unwrap_or(0);
        let mut request = format!(
            "{} {} HTTP/1.1\r\n\
             Host: {}\r\n\
             User-Agent: rust-router/1.0\r\n\
             Accept: application/json\r\n\
             Connection: close\r\n",
            method.to_uppercase(),
            path,
            host_header
        );

        if body.is_some() {
            request.push_str(&format!(
                "Content-Type: application/json\r\n\
                 Content-Length: {}\r\n",
                content_length
            ));
        }

        request.push_str("\r\n");

        if let Some(b) = body {
            request.push_str(b);
        }

        // Send request
        stream
            .write_all(request.as_bytes())
            .await
            .map_err(|e| format!("Failed to send HTTP request: {}", e))?;

        // Read response with size limit to prevent memory exhaustion
        let mut response_buf = Vec::with_capacity(8192);
        let read_result = tokio_timeout(timeout, async {
            let mut total_read = 0usize;
            let mut chunk = [0u8; 4096];
            loop {
                let n = stream.read(&mut chunk).await?;
                if n == 0 {
                    break; // EOF
                }
                total_read += n;
                if total_read > Self::MAX_PEER_RESPONSE_SIZE {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "Response too large",
                    ));
                }
                response_buf.extend_from_slice(&chunk[..n]);
            }
            Ok(())
        })
        .await;

        match read_result {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(format!("Failed to read HTTP response: {}", e)),
            Err(_) => return Err("HTTP response read timed out".to_string()),
        }

        // Parse HTTP response
        let response_str = String::from_utf8_lossy(&response_buf);
        Self::parse_http_response(&response_str)
    }

    /// Forward HTTP request directly (for WireGuard peers)
    async fn forward_direct_http(
        &self,
        url: &str,
        method: &str,
        body: Option<&str>,
        timeout: Duration,
        custom_headers: Option<&std::collections::HashMap<String, String>>,
    ) -> Result<(u16, String), String> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::time::timeout as tokio_timeout;

        // Parse the URL
        let uri: hyper::Uri = url
            .parse()
            .map_err(|e| format!("Invalid URL '{}': {}", url, e))?;

        let host = uri.host().ok_or_else(|| "URL missing host".to_string())?;
        let port = uri.port_u16().unwrap_or(80);
        let path = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");

        // Connect to the target
        let addr = format!("{}:{}", host, port);
        let stream = tokio_timeout(timeout, tokio::net::TcpStream::connect(&addr))
            .await
            .map_err(|_| format!("Connection to '{}' timed out", addr))?
            .map_err(|e| format!("Failed to connect to '{}': {}", addr, e))?;

        let mut stream = stream;

        // Build Host header (include port if non-default)
        let host_header = if port != 80 {
            format!("{}:{}", host, port)
        } else {
            host.to_string()
        };

        // Build HTTP request
        let content_length = body.map(|b| b.len()).unwrap_or(0);
        let mut request = format!(
            "{} {} HTTP/1.1\r\n\
             Host: {}\r\n\
             User-Agent: rust-router/1.0\r\n\
             Accept: application/json\r\n\
             Connection: close\r\n",
            method.to_uppercase(),
            path,
            host_header
        );

        // Add custom headers
        if let Some(headers) = custom_headers {
            for (name, value) in headers {
                // Validate header name and value to prevent injection
                if name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
                    && !value.contains('\r') && !value.contains('\n')
                {
                    request.push_str(&format!("{}: {}\r\n", name, value));
                }
            }
        }

        if body.is_some() {
            request.push_str(&format!(
                "Content-Type: application/json\r\n\
                 Content-Length: {}\r\n",
                content_length
            ));
        }

        request.push_str("\r\n");

        if let Some(b) = body {
            request.push_str(b);
        }

        // Send request
        stream
            .write_all(request.as_bytes())
            .await
            .map_err(|e| format!("Failed to send HTTP request: {}", e))?;

        // Read response with size limit to prevent memory exhaustion
        let mut response_buf = Vec::with_capacity(8192);
        let read_result = tokio_timeout(timeout, async {
            let mut total_read = 0usize;
            let mut chunk = [0u8; 4096];
            loop {
                let n = stream.read(&mut chunk).await?;
                if n == 0 {
                    break; // EOF
                }
                total_read += n;
                if total_read > Self::MAX_PEER_RESPONSE_SIZE {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "Response too large",
                    ));
                }
                response_buf.extend_from_slice(&chunk[..n]);
            }
            Ok(())
        })
        .await;

        match read_result {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(format!("Failed to read HTTP response: {}", e)),
            Err(_) => return Err("HTTP response read timed out".to_string()),
        }

        // Parse HTTP response
        let response_str = String::from_utf8_lossy(&response_buf);
        Self::parse_http_response(&response_str)
    }

    /// Forward HTTP request through WireGuard tunnel using smoltcp TCP stack
    ///
    /// This method creates a TCP connection through the WireGuard tunnel using smoltcp
    /// to handle the TCP/IP stack at the IP layer. The flow is:
    ///
    /// 1. Get the WireGuard tunnel from PeerManager
    /// 2. Create a SmoltcpBridge with our local tunnel IP
    /// 3. Spawn a packet pump task to move packets between smoltcp and the tunnel
    /// 4. Use SmoltcpHttpClient to make the HTTP request
    /// 5. Clean up resources when done
    ///
    /// # Arguments
    ///
    /// * `peer_manager` - The peer manager holding the WireGuard tunnel
    /// * `peer_tag` - Tag of the peer to forward the request through
    /// * `url` - Full URL to request (e.g., "http://10.200.200.1:36000/api/health")
    /// * `method` - HTTP method (GET, POST, etc.)
    /// * `body` - Optional request body
    /// * `timeout` - Request timeout
    /// * `tunnel_local_ip` - Our local tunnel IP (e.g., 10.200.200.2)
    /// * `tunnel_remote_ip` - Remote peer's tunnel IP (e.g., 10.200.200.1)
    /// * `headers` - Optional custom HTTP headers
    ///
    /// # Returns
    ///
    /// A tuple of (status_code, response_body) on success
    ///
    /// # Unified Pump Architecture
    ///
    /// This method uses the Request Channel pattern instead of creating a separate
    /// packet pump. The outbound HTTP request is sent through the TCP proxy's unified
    /// pump via a channel, eliminating the competing pump issue.
    #[allow(clippy::too_many_arguments)]
    async fn forward_via_wg_tunnel(
        &self,
        peer_manager: &Arc<PeerManager>,
        peer_tag: &str,
        url: &str,
        method: &str,
        body: Option<&str>,
        timeout: Duration,
        tunnel_local_ip: std::net::Ipv4Addr,
        tunnel_remote_ip: std::net::Ipv4Addr,
        headers: Option<&std::collections::HashMap<String, String>>,
    ) -> Result<(u16, String), String> {
        use crate::tunnel::OutboundHttpRequest;
        use tokio::sync::oneshot;

        debug!(
            peer = %peer_tag,
            url = %url,
            local_ip = %tunnel_local_ip,
            remote_ip = %tunnel_remote_ip,
            "Forwarding request via WireGuard tunnel (unified pump)"
        );

        // Parse URL to get host, port, and path
        let uri: hyper::Uri = url
            .parse()
            .map_err(|e| format!("Invalid URL '{}': {}", url, e))?;

        let port = uri.port_u16().unwrap_or(80);
        let path = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");

        // Get the outbound request sender from PeerManager
        // This allows us to send the request through the TCP proxy's unified pump
        let request_sender = peer_manager
            .get_outbound_request_sender(peer_tag)
            .ok_or_else(|| {
                format!(
                    "No outbound request channel for peer '{}' - TCP proxy may not be running",
                    peer_tag
                )
            })?;

        // Build request headers with auto-injected tunnel authentication headers
        let mut request_headers = headers.cloned().unwrap_or_default();

        // Auto-inject tunnel source IP header for authentication
        request_headers.insert(
            "X-Tunnel-Source-IP".to_string(),
            tunnel_local_ip.to_string(),
        );
        debug!(source_ip = %tunnel_local_ip, "Added X-Tunnel-Source-IP header");

        // Auto-inject tunnel peer tag header for authentication
        request_headers.insert(
            "X-Tunnel-Peer-Tag".to_string(),
            peer_tag.to_string(),
        );
        debug!(peer_tag = %peer_tag, "Added X-Tunnel-Peer-Tag header");

        // Create oneshot channel for the response
        let (response_tx, response_rx) = oneshot::channel();

        // Build the outbound request
        let outbound_request = OutboundHttpRequest {
            method: method.to_string(),
            path: path.to_string(),
            host: tunnel_remote_ip.to_string(),
            port,
            body: body.map(|s| s.to_string()),
            headers: Some(request_headers),
            response_tx,
        };

        // Send the request through the unified pump
        request_sender
            .send(outbound_request)
            .await
            .map_err(|_| format!("Failed to send request to TCP proxy for peer '{}'", peer_tag))?;

        debug!(peer = %peer_tag, "Request sent to unified pump, waiting for response");

        // Wait for response with timeout
        let response = tokio::time::timeout(timeout, response_rx)
            .await
            .map_err(|_| format!("Request to peer '{}' timed out after {:?}", peer_tag, timeout))?
            .map_err(|_| format!("Response channel closed for peer '{}'", peer_tag))?;

        // Check response
        if response.success {
            let status_code = response.status_code.unwrap_or(200);
            let body = response.body.unwrap_or_default();
            debug!(
                peer = %peer_tag,
                status = status_code,
                body_len = body.len(),
                "WireGuard tunnel request completed via unified pump"
            );
            Ok((status_code, body))
        } else {
            let error = response.error.unwrap_or_else(|| "Unknown error".to_string());
            warn!(peer = %peer_tag, error = %error, "WireGuard tunnel request failed");
            Err(format!("WireGuard tunnel request failed: {}", error))
        }
    }

    /// Parse HTTP response to extract status code and body
    fn parse_http_response(response: &str) -> Result<(u16, String), String> {
        // Find the end of headers
        let header_end = response
            .find("\r\n\r\n")
            .ok_or_else(|| "Invalid HTTP response: no header terminator".to_string())?;

        let headers = &response[..header_end];
        let body = &response[header_end + 4..];

        // Parse status line
        let status_line = headers
            .lines()
            .next()
            .ok_or_else(|| "Invalid HTTP response: no status line".to_string())?;

        // Format: "HTTP/1.1 200 OK"
        let parts: Vec<&str> = status_line.split_whitespace().collect();
        if parts.len() < 2 {
            return Err(format!("Invalid status line: '{}'", status_line));
        }

        let status_code: u16 = parts[1]
            .parse()
            .map_err(|_| format!("Invalid status code: '{}'", parts[1]))?;

        Ok((status_code, body.to_string()))
    }
}

/// Write a metric header (HELP and TYPE lines)
fn write_metric_header(output: &mut String, name: &str, help: &str, metric_type: &str) {
    use std::fmt::Write;
    let _ = writeln!(output, "# HELP {name} {help}");
    let _ = writeln!(output, "# TYPE {name} {metric_type}");
}

/// Write a metric value with optional labels
fn write_metric_value(output: &mut String, name: &str, labels: Option<&[(&str, &str)]>, value: u64) {
    use std::fmt::Write;
    if let Some(labels) = labels {
        let label_str: String = labels
            .iter()
            .map(|(k, v)| format!("{}=\"{}\"", k, escape_label_value(v)))
            .collect::<Vec<_>>()
            .join(",");
        let _ = writeln!(output, "{name}{{{label_str}}} {value}");
    } else {
        let _ = writeln!(output, "{name} {value}");
    }
}

/// Escape label values for Prometheus format
fn escape_label_value(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

/// Format Unix timestamp as simplified ISO 8601
fn chrono_lite_format(secs: u64) -> String {
    // Simple formatting without external chrono dependency
    // This produces approximate ISO 8601 format
    let days_since_epoch = secs / 86400;
    let secs_today = secs % 86400;
    let hours = secs_today / 3600;
    let mins = (secs_today % 3600) / 60;
    let secs = secs_today % 60;

    // Approximate year calculation (good enough for our purposes)
    let year = 1970 + (days_since_epoch / 365);
    let day_of_year = days_since_epoch % 365;
    let month = (day_of_year / 30).min(11) + 1;
    let day = (day_of_year % 30) + 1;

    format!(
        "{year:04}-{month:02}-{day:02}T{hours:02}:{mins:02}:{secs:02}Z"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ConnectionConfig;
    use crate::ingress::config::WgIngressConfig;
    use crate::ingress::manager::WgIngressManager;
    use crate::ingress::{ForwardingStats, IngressReplyStats};
    use crate::ipc::protocol::{EgressAction, ErrorCode, RuleConfig};
    use crate::rules::{RuleEngine, RuleEngineRoutingCallback, RuleType};
    use ipnet::IpNet;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::Duration;

    const TEST_VALID_KEY: &str = "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=";

    fn create_test_handler() -> IpcHandler {
        let outbound_manager = Arc::new(OutboundManager::new());
        outbound_manager.add(Box::new(crate::outbound::DirectOutbound::simple("direct")));

        let conn_config = ConnectionConfig::default();
        let connection_manager = Arc::new(ConnectionManager::new(
            &conn_config,
            Arc::clone(&outbound_manager),
            "direct".into(),
            Duration::from_millis(300),
        ));

        IpcHandler::new_with_default_rules(connection_manager, outbound_manager)
    }

    fn create_test_handler_with_rules() -> IpcHandler {
        let outbound_manager = Arc::new(OutboundManager::new());
        outbound_manager.add(Box::new(crate::outbound::DirectOutbound::simple("direct")));
        outbound_manager.add(Box::new(crate::outbound::DirectOutbound::simple("proxy")));

        let conn_config = ConnectionConfig::default();
        let connection_manager = Arc::new(ConnectionManager::new(
            &conn_config,
            Arc::clone(&outbound_manager),
            "direct".into(),
            Duration::from_millis(300),
        ));

        // Create a rule engine with some test rules
        let mut builder = RoutingSnapshotBuilder::new();
        builder
            .add_domain_rule(RuleType::DomainSuffix, "google.com", "proxy")
            .unwrap()
            .add_geoip_rule(RuleType::IpCidr, "192.168.0.0/16", "direct")
            .unwrap()
            .add_port_rule("443", "proxy")
            .unwrap()
            .add_chain("us-chain")
            .unwrap();

        let snapshot = builder.default_outbound("direct").version(1).build().unwrap();
        let rule_engine = Arc::new(RuleEngine::new(snapshot));

        IpcHandler::new(connection_manager, outbound_manager, rule_engine)
    }

    fn create_test_handler_with_ingress_stats(
    ) -> (IpcHandler, Arc<ForwardingStats>, Arc<IngressReplyStats>) {
        let outbound_manager = Arc::new(OutboundManager::new());
        outbound_manager.add(Box::new(crate::outbound::DirectOutbound::simple("direct")));

        let conn_config = ConnectionConfig::default();
        let connection_manager = Arc::new(ConnectionManager::new(
            &conn_config,
            Arc::clone(&outbound_manager),
            "direct".into(),
            Duration::from_millis(300),
        ));

        let snapshot = RoutingSnapshotBuilder::new()
            .default_outbound("direct")
            .version(1)
            .build()
            .unwrap();
        let rule_engine = Arc::new(RuleEngine::new(snapshot));

        let allowed_subnet: IpNet = "10.25.0.0/24".parse().unwrap();
        let ingress_config = WgIngressConfig::builder()
            .private_key(TEST_VALID_KEY)
            .listen_addr(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                36100,
            ))
            .local_ip("10.25.0.1".parse().unwrap())
            .allowed_subnet(allowed_subnet)
            .build();

        let ingress_manager = Arc::new(
            WgIngressManager::new(ingress_config, Arc::clone(&rule_engine)).unwrap(),
        );

        let forwarding_stats = Arc::new(ForwardingStats::default());
        let reply_stats = Arc::new(IngressReplyStats::default());

        let handler = IpcHandler::new(connection_manager, outbound_manager, rule_engine)
            .with_wg_ingress_manager(Arc::clone(&ingress_manager))
            .with_ingress_stats(Arc::clone(&forwarding_stats), Arc::clone(&reply_stats));

        (handler, forwarding_stats, reply_stats)
    }

    #[tokio::test]
    async fn test_ping() {
        let handler = create_test_handler();
        let response = handler.handle(IpcCommand::Ping).await;
        assert!(matches!(response, IpcResponse::Pong));
    }

    #[tokio::test]
    async fn test_status() {
        let handler = create_test_handler();
        let response = handler.handle(IpcCommand::Status).await;

        if let IpcResponse::Status(status) = response {
            assert!(!status.version.is_empty());
            // uptime_secs is u64, always >= 0, just verify it's reasonable
            assert!(status.uptime_secs < 86400, "Uptime should be less than 1 day in tests");
            assert!(!status.shutting_down);
        } else {
            panic!("Expected Status response");
        }
    }

    #[tokio::test]
    async fn test_list_outbounds() {
        let handler = create_test_handler();
        let response = handler.handle(IpcCommand::ListOutbounds).await;

        if let IpcResponse::OutboundList { outbounds } = response {
            assert_eq!(outbounds.len(), 1);
            assert_eq!(outbounds[0].tag, "direct");
        } else {
            panic!("Expected OutboundList response");
        }
    }

    #[tokio::test]
    async fn test_get_outbound() {
        let handler = create_test_handler();

        // Existing outbound
        let response = handler
            .handle(IpcCommand::GetOutbound {
                tag: "direct".into(),
            })
            .await;
        assert!(matches!(response, IpcResponse::OutboundInfo(_)));

        // Non-existing outbound
        let response = handler
            .handle(IpcCommand::GetOutbound {
                tag: "nonexistent".into(),
            })
            .await;
        assert!(matches!(response, IpcResponse::Error(_)));
    }

    #[tokio::test]
    async fn test_remove_outbound() {
        let handler = create_test_handler();

        // Remove existing
        let response = handler
            .handle(IpcCommand::RemoveOutbound {
                tag: "direct".into(),
            })
            .await;
        assert!(!response.is_error());

        // Remove non-existing
        let response = handler
            .handle(IpcCommand::RemoveOutbound {
                tag: "direct".into(),
            })
            .await;
        assert!(response.is_error());
    }

    #[tokio::test]
    async fn test_get_rule_stats() {
        let handler = create_test_handler_with_rules();
        let response = handler.handle(IpcCommand::GetRuleStats).await;

        if let IpcResponse::RuleStats(stats) = response {
            assert_eq!(stats.domain_rules, 1);
            assert_eq!(stats.geoip_rules, 1);
            assert_eq!(stats.port_rules, 1);
            assert_eq!(stats.chain_count, 1);
            assert_eq!(stats.default_outbound, "direct");
            assert!(stats.config_version >= 1);
        } else {
            panic!("Expected RuleStats response");
        }
    }

    #[tokio::test]
    async fn test_reload_rules() {
        let handler = create_test_handler();

        // Reload without config path
        let response = handler
            .handle(IpcCommand::ReloadRules { config_path: None })
            .await;
        assert!(!response.is_error());

        // Reload with config path
        let response = handler
            .handle(IpcCommand::ReloadRules {
                config_path: Some("/etc/rules.json".into()),
            })
            .await;
        assert!(!response.is_error());

        // Verify version incremented
        let stats_response = handler.handle(IpcCommand::GetRuleStats).await;
        if let IpcResponse::RuleStats(stats) = stats_response {
            assert!(stats.config_version >= 2);
            assert!(stats.last_reload.is_some());
        } else {
            panic!("Expected RuleStats response");
        }
    }

    #[tokio::test]
    async fn test_test_match_domain() {
        let handler = create_test_handler_with_rules();

        // Test domain matching
        let response = handler
            .handle(IpcCommand::TestMatch {
                domain: Some("www.google.com".into()),
                dest_ip: None,
                dest_port: 443,
                protocol: "tcp".into(),
                sniffed_protocol: Some("tls".into()),
            })
            .await;

        if let IpcResponse::TestMatchResult(result) = response {
            assert_eq!(result.outbound, "proxy");
            assert_eq!(result.match_type, Some("domain".into()));
            assert!(result.match_time_us > 0);
        } else {
            panic!("Expected TestMatchResult response");
        }
    }

    #[tokio::test]
    async fn test_test_match_ip() {
        let handler = create_test_handler_with_rules();

        // Test IP matching
        let response = handler
            .handle(IpcCommand::TestMatch {
                domain: None,
                dest_ip: Some("192.168.1.100".into()),
                dest_port: 80,
                protocol: "tcp".into(),
                sniffed_protocol: None,
            })
            .await;

        if let IpcResponse::TestMatchResult(result) = response {
            assert_eq!(result.outbound, "direct");
            assert_eq!(result.match_type, Some("geoip".into()));
        } else {
            panic!("Expected TestMatchResult response");
        }
    }

    #[tokio::test]
    async fn test_test_match_default() {
        let handler = create_test_handler_with_rules();

        // Test falling through to default
        let response = handler
            .handle(IpcCommand::TestMatch {
                domain: None,
                dest_ip: Some("8.8.8.8".into()),
                dest_port: 53,
                protocol: "udp".into(),
                sniffed_protocol: None,
            })
            .await;

        if let IpcResponse::TestMatchResult(result) = response {
            assert_eq!(result.outbound, "direct");
            // No match type means default was used
            assert!(result.match_type.is_none());
        } else {
            panic!("Expected TestMatchResult response");
        }
    }

    #[tokio::test]
    async fn test_add_socks5_outbound() {
        let handler = create_test_handler();

        // Add a new SOCKS5 outbound
        let response = handler
            .handle(IpcCommand::AddSocks5Outbound {
                tag: "test-socks5".into(),
                server_addr: "127.0.0.1:1080".into(),
                username: None,
                password: None,
                connect_timeout_secs: 10,
                idle_timeout_secs: 300,
                pool_max_size: 8,
            })
            .await;
        assert!(!response.is_error(), "Expected success, got: {:?}", response);

        // Verify it was added
        let list_response = handler.handle(IpcCommand::ListOutbounds).await;
        if let IpcResponse::OutboundList { outbounds } = list_response {
            assert!(outbounds.iter().any(|o| o.tag == "test-socks5"));
            assert!(outbounds.iter().any(|o| o.outbound_type == "socks5"));
        } else {
            panic!("Expected OutboundList response");
        }

        // Adding duplicate should fail
        let response = handler
            .handle(IpcCommand::AddSocks5Outbound {
                tag: "test-socks5".into(),
                server_addr: "127.0.0.1:1080".into(),
                username: None,
                password: None,
                connect_timeout_secs: 10,
                idle_timeout_secs: 300,
                pool_max_size: 8,
            })
            .await;
        assert!(response.is_error());
    }

    #[tokio::test]
    async fn test_add_socks5_outbound_with_auth() {
        let handler = create_test_handler();

        // Add SOCKS5 with authentication
        let response = handler
            .handle(IpcCommand::AddSocks5Outbound {
                tag: "auth-socks5".into(),
                server_addr: "127.0.0.1:1080".into(),
                username: Some("user".into()),
                password: Some("pass".into()),
                connect_timeout_secs: 5,
                idle_timeout_secs: 120,
                pool_max_size: 16,
            })
            .await;
        assert!(!response.is_error());
    }

    #[tokio::test]
    async fn test_add_socks5_outbound_invalid_addr() {
        let handler = create_test_handler();

        // Invalid server address should fail
        let response = handler
            .handle(IpcCommand::AddSocks5Outbound {
                tag: "bad-addr".into(),
                server_addr: "not-a-valid-address".into(),
                username: None,
                password: None,
                connect_timeout_secs: 10,
                idle_timeout_secs: 300,
                pool_max_size: 8,
            })
            .await;
        assert!(response.is_error());
    }

    #[tokio::test]
    async fn test_get_pool_stats_no_socks5() {
        let handler = create_test_handler();

        // Get pool stats when no SOCKS5 outbounds exist
        let response = handler
            .handle(IpcCommand::GetPoolStats { tag: None })
            .await;

        if let IpcResponse::PoolStats(stats) = response {
            assert!(stats.pools.is_empty());
        } else {
            panic!("Expected PoolStats response");
        }
    }

    #[tokio::test]
    async fn test_get_pool_stats_with_socks5() {
        let handler = create_test_handler();

        // First add a SOCKS5 outbound
        let _ = handler
            .handle(IpcCommand::AddSocks5Outbound {
                tag: "pool-test".into(),
                server_addr: "127.0.0.1:1080".into(),
                username: None,
                password: None,
                connect_timeout_secs: 10,
                idle_timeout_secs: 300,
                pool_max_size: 4,
            })
            .await;

        // Get pool stats for all SOCKS5 outbounds
        let response = handler
            .handle(IpcCommand::GetPoolStats { tag: None })
            .await;

        if let IpcResponse::PoolStats(stats) = response {
            assert_eq!(stats.pools.len(), 1);
            assert_eq!(stats.pools[0].tag, "pool-test");
            assert_eq!(stats.pools[0].server_addr, "127.0.0.1:1080");
            assert!(stats.pools[0].enabled);
        } else {
            panic!("Expected PoolStats response");
        }

        // Get pool stats for specific outbound
        let response = handler
            .handle(IpcCommand::GetPoolStats {
                tag: Some("pool-test".into()),
            })
            .await;

        if let IpcResponse::PoolStats(stats) = response {
            assert_eq!(stats.pools.len(), 1);
            assert_eq!(stats.pools[0].tag, "pool-test");
        } else {
            panic!("Expected PoolStats response");
        }
    }

    #[tokio::test]
    async fn test_get_pool_stats_not_found() {
        let handler = create_test_handler();

        // Request stats for non-existent outbound
        let response = handler
            .handle(IpcCommand::GetPoolStats {
                tag: Some("nonexistent".into()),
            })
            .await;
        assert!(response.is_error());
    }

    #[tokio::test]
    async fn test_get_pool_stats_not_socks5() {
        let handler = create_test_handler();

        // Request stats for a non-SOCKS5 outbound
        let response = handler
            .handle(IpcCommand::GetPoolStats {
                tag: Some("direct".into()),
            })
            .await;
        assert!(response.is_error());
    }

    // =========================================================================
    // IPC Protocol v2.1 Handler Tests
    // =========================================================================

    #[tokio::test]
    async fn test_add_wireguard_outbound_success() {
        let handler = create_test_handler();

        // Add a WireGuard outbound with a loopback interface (always exists)
        let response = handler
            .handle(IpcCommand::AddWireguardOutbound {
                tag: "wg-test".into(),
                interface: "lo".into(), // loopback always exists
                routing_mark: Some(200),
                routing_table: Some(100),
            })
            .await;
        assert!(!response.is_error(), "Expected success, got: {:?}", response);

        // Verify it was added
        let list_response = handler.handle(IpcCommand::ListOutbounds).await;
        if let IpcResponse::OutboundList { outbounds } = list_response {
            assert!(outbounds.iter().any(|o| o.tag == "wg-test"));
        } else {
            panic!("Expected OutboundList response");
        }
    }

    #[tokio::test]
    async fn test_add_wireguard_outbound_already_exists() {
        let handler = create_test_handler();

        // First add should succeed
        let response = handler
            .handle(IpcCommand::AddWireguardOutbound {
                tag: "wg-dup".into(),
                interface: "lo".into(),
                routing_mark: None,
                routing_table: None,
            })
            .await;
        assert!(!response.is_error());

        // Second add with same tag should fail
        let response = handler
            .handle(IpcCommand::AddWireguardOutbound {
                tag: "wg-dup".into(),
                interface: "lo".into(),
                routing_mark: None,
                routing_table: None,
            })
            .await;
        assert!(response.is_error());

        if let IpcResponse::Error(err) = response {
            assert!(matches!(err.code, ErrorCode::AlreadyExists));
        } else {
            panic!("Expected Error response");
        }
    }

    #[tokio::test]
    async fn test_add_wireguard_outbound_invalid_interface() {
        let handler = create_test_handler();

        // Add with non-existent interface should fail
        let response = handler
            .handle(IpcCommand::AddWireguardOutbound {
                tag: "wg-invalid".into(),
                interface: "nonexistent_interface_12345".into(),
                routing_mark: None,
                routing_table: None,
            })
            .await;
        assert!(response.is_error());

        if let IpcResponse::Error(err) = response {
            assert!(matches!(err.code, ErrorCode::InvalidParameters));
            assert!(err.message.contains("validation failed"));
        } else {
            panic!("Expected Error response");
        }
    }

    #[tokio::test]
    async fn test_drain_outbound_not_found() {
        let handler = create_test_handler();

        // Drain non-existent outbound
        let response = handler
            .handle(IpcCommand::DrainOutbound {
                tag: "nonexistent".into(),
                timeout_secs: 5,
            })
            .await;
        assert!(response.is_error());

        if let IpcResponse::Error(err) = response {
            assert!(matches!(err.code, ErrorCode::NotFound));
        } else {
            panic!("Expected Error response");
        }
    }

    #[tokio::test]
    async fn test_update_routing_empty_rules() {
        let handler = create_test_handler();

        // Update with empty rules should succeed
        let response = handler
            .handle(IpcCommand::UpdateRouting {
                rules: vec![],
                default_outbound: "direct".into(),
            })
            .await;
        assert!(!response.is_error(), "Expected success, got: {:?}", response);

        if let IpcResponse::UpdateRoutingResult(result) = response {
            assert!(result.success);
            assert_eq!(result.rule_count, 0);
            assert_eq!(result.default_outbound, "direct");
        } else {
            panic!("Expected UpdateRoutingResult response");
        }
    }

    #[tokio::test]
    async fn test_update_routing_unknown_outbound() {
        let handler = create_test_handler();

        // Update with unknown default outbound should fail
        let response = handler
            .handle(IpcCommand::UpdateRouting {
                rules: vec![],
                default_outbound: "nonexistent".into(),
            })
            .await;
        assert!(response.is_error());

        if let IpcResponse::Error(err) = response {
            assert!(matches!(err.code, ErrorCode::NotFound));
            assert!(err.message.contains("Default outbound"));
        } else {
            panic!("Expected Error response");
        }
    }

    #[tokio::test]
    async fn test_update_routing_invalid_rule_type() {
        let handler = create_test_handler();

        // Update with invalid rule type should fail
        let response = handler
            .handle(IpcCommand::UpdateRouting {
                rules: vec![RuleConfig {
                    rule_type: "invalid_type".into(),
                    target: "test".into(),
                    outbound: "direct".into(),
                    priority: 0,
                    enabled: true,
                }],
                default_outbound: "direct".into(),
            })
            .await;
        assert!(response.is_error());

        if let IpcResponse::Error(err) = response {
            assert!(matches!(err.code, ErrorCode::InvalidParameters));
            assert!(err.message.contains("Unknown rule type"));
        } else {
            panic!("Expected Error response");
        }
    }

    #[tokio::test]
    async fn test_set_default_outbound_not_found() {
        let handler = create_test_handler();

        // Set default to non-existent outbound
        let response = handler
            .handle(IpcCommand::SetDefaultOutbound {
                tag: "nonexistent".into(),
            })
            .await;
        assert!(response.is_error());

        if let IpcResponse::Error(err) = response {
            assert!(matches!(err.code, ErrorCode::NotFound));
        } else {
            panic!("Expected Error response");
        }
    }

    #[tokio::test]
    async fn test_get_outbound_health_empty() {
        // Create handler with no outbounds
        let outbound_manager = Arc::new(OutboundManager::new());
        let conn_config = ConnectionConfig::default();
        let connection_manager = Arc::new(ConnectionManager::new(
            &conn_config,
            Arc::clone(&outbound_manager),
            "direct".into(),
            Duration::from_millis(300),
        ));
        let handler = IpcHandler::new_with_default_rules(connection_manager, outbound_manager);

        let response = handler.handle(IpcCommand::GetOutboundHealth).await;

        if let IpcResponse::OutboundHealth(health) = response {
            assert!(health.outbounds.is_empty());
            assert_eq!(health.overall_health, "healthy"); // All healthy when empty
        } else {
            panic!("Expected OutboundHealth response");
        }
    }

    #[tokio::test]
    async fn test_get_outbound_health_with_outbounds() {
        let handler = create_test_handler();

        let response = handler.handle(IpcCommand::GetOutboundHealth).await;

        if let IpcResponse::OutboundHealth(health) = response {
            assert!(!health.outbounds.is_empty());
            // direct outbound should be present
            assert!(health.outbounds.iter().any(|o| o.tag == "direct"));
            // Check health fields
            for outbound in &health.outbounds {
                assert!(!outbound.tag.is_empty());
                assert!(!outbound.outbound_type.is_empty());
                assert!(!outbound.health.is_empty());
            }
        } else {
            panic!("Expected OutboundHealth response");
        }
    }

    #[tokio::test]
    async fn test_notify_egress_change_added() {
        let handler = create_test_handler();

        let response = handler
            .handle(IpcCommand::NotifyEgressChange {
                action: EgressAction::Added,
                tag: "new-egress".into(),
                egress_type: "pia".into(),
            })
            .await;
        assert!(!response.is_error());

        if let IpcResponse::Success { message } = response {
            assert!(message.is_some());
            let msg = message.unwrap();
            assert!(msg.contains("Added"));
            assert!(msg.contains("new-egress"));
        } else {
            panic!("Expected Success response");
        }
    }

    #[tokio::test]
    async fn test_notify_egress_change_removed() {
        let handler = create_test_handler();

        // First add an outbound
        let _ = handler
            .handle(IpcCommand::AddWireguardOutbound {
                tag: "to-remove".into(),
                interface: "lo".into(),
                routing_mark: None,
                routing_table: None,
            })
            .await;

        // Then notify removal
        let response = handler
            .handle(IpcCommand::NotifyEgressChange {
                action: EgressAction::Removed,
                tag: "to-remove".into(),
                egress_type: "custom".into(),
            })
            .await;
        assert!(!response.is_error());

        // Verify it was removed
        let get_response = handler
            .handle(IpcCommand::GetOutbound {
                tag: "to-remove".into(),
            })
            .await;
        assert!(get_response.is_error()); // Should be not found
    }

    // =========================================================================
    // P2 Edge Case Tests
    // =========================================================================

    #[tokio::test]
    async fn test_drain_outbound_zero_timeout() {
        let handler = create_test_handler();

        // Add an outbound to drain
        let _ = handler
            .handle(IpcCommand::AddWireguardOutbound {
                tag: "drain-zero".into(),
                interface: "lo".into(),
                routing_mark: None,
                routing_table: None,
            })
            .await;

        // Drain with zero timeout should complete immediately
        let response = handler
            .handle(IpcCommand::DrainOutbound {
                tag: "drain-zero".into(),
                timeout_secs: 0,
            })
            .await;

        if let IpcResponse::DrainResult(result) = response {
            assert!(result.success);
            // With zero timeout, it should complete very quickly
            assert!(result.drain_time_ms < 1000);
        } else {
            panic!("Expected DrainResult response, got: {:?}", response);
        }
    }

    #[tokio::test]
    async fn test_update_routing_with_disabled_rules() {
        let handler = create_test_handler();

        // Update with disabled rules - they should be skipped
        let response = handler
            .handle(IpcCommand::UpdateRouting {
                rules: vec![
                    RuleConfig {
                        rule_type: "domain".into(),
                        target: "example.com".into(),
                        outbound: "direct".into(),
                        priority: 0,
                        enabled: true,
                    },
                    RuleConfig {
                        rule_type: "domain".into(),
                        target: "disabled.com".into(),
                        outbound: "direct".into(),
                        priority: 0,
                        enabled: false, // disabled
                    },
                ],
                default_outbound: "direct".into(),
            })
            .await;
        assert!(!response.is_error(), "Expected success, got: {:?}", response);

        if let IpcResponse::UpdateRoutingResult(result) = response {
            assert!(result.success);
            // Only 1 rule should be active (the enabled one)
            assert_eq!(result.rule_count, 1);
        } else {
            panic!("Expected UpdateRoutingResult response");
        }
    }

    #[tokio::test]
    async fn test_update_routing_rule_references_unknown_outbound() {
        let handler = create_test_handler();

        // Update with rule referencing non-existent outbound
        let response = handler
            .handle(IpcCommand::UpdateRouting {
                rules: vec![RuleConfig {
                    rule_type: "domain".into(),
                    target: "example.com".into(),
                    outbound: "nonexistent-proxy".into(),
                    priority: 0,
                    enabled: true,
                }],
                default_outbound: "direct".into(),
            })
            .await;
        assert!(response.is_error());

        if let IpcResponse::Error(err) = response {
            assert!(matches!(err.code, ErrorCode::NotFound));
            assert!(err.message.contains("unknown outbound"));
        } else {
            panic!("Expected Error response");
        }
    }

    #[tokio::test]
    async fn test_update_routing_with_chain_outbound() {
        // Test that ACTIVE chain tags are accepted as valid outbounds
        let handler = create_test_handler_with_chain_manager();

        // First create a chain
        let config = create_test_chain_config("my-chain");
        let create_response = handler
            .handle(IpcCommand::CreateChain {
                tag: "my-chain".into(),
                config,
            })
            .await;
        assert!(!create_response.is_error(), "Failed to create chain: {:?}", create_response);

        // Activate the chain (required for it to be a valid outbound)
        let activate_response = handler
            .handle(IpcCommand::ActivateChain {
                tag: "my-chain".into(),
            })
            .await;
        assert!(!activate_response.is_error(), "Failed to activate chain: {:?}", activate_response);

        // Now update routing rules with the chain as outbound
        let response = handler
            .handle(IpcCommand::UpdateRouting {
                rules: vec![RuleConfig {
                    rule_type: "domain".into(),
                    target: "chain-routed.com".into(),
                    outbound: "my-chain".into(),  // Use active chain as outbound
                    priority: 0,
                    enabled: true,
                }],
                default_outbound: "direct".into(),
            })
            .await;
        assert!(!response.is_error(), "Expected success, got: {:?}", response);

        if let IpcResponse::UpdateRoutingResult(result) = response {
            assert!(result.success);
            assert_eq!(result.rule_count, 1);
        } else {
            panic!("Expected UpdateRoutingResult response");
        }
    }

    #[tokio::test]
    async fn test_set_default_outbound_success() {
        let handler = create_test_handler_with_rules();

        // Set default to "proxy" which exists in test handler
        let response = handler
            .handle(IpcCommand::SetDefaultOutbound {
                tag: "proxy".into(),
            })
            .await;
        assert!(!response.is_error(), "Expected success, got: {:?}", response);

        // Verify the default was changed via GetRuleStats
        let stats_response = handler.handle(IpcCommand::GetRuleStats).await;
        if let IpcResponse::RuleStats(stats) = stats_response {
            assert_eq!(stats.default_outbound, "proxy");
        } else {
            panic!("Expected RuleStats response");
        }
    }

    #[tokio::test]
    async fn test_set_default_outbound_to_chain() {
        // Test that ACTIVE chain tags can be used as default outbound
        let handler = create_test_handler_with_chain_manager();

        // First create a chain
        let config = create_test_chain_config("default-chain");
        let create_response = handler
            .handle(IpcCommand::CreateChain {
                tag: "default-chain".into(),
                config,
            })
            .await;
        assert!(!create_response.is_error(), "Failed to create chain: {:?}", create_response);

        // Activate the chain (required for it to be a valid outbound)
        let activate_response = handler
            .handle(IpcCommand::ActivateChain {
                tag: "default-chain".into(),
            })
            .await;
        assert!(!activate_response.is_error(), "Failed to activate chain: {:?}", activate_response);

        // Set chain as default outbound
        let response = handler
            .handle(IpcCommand::SetDefaultOutbound {
                tag: "default-chain".into(),
            })
            .await;
        assert!(!response.is_error(), "Expected success, got: {:?}", response);

        // Verify the default was changed
        let stats_response = handler.handle(IpcCommand::GetRuleStats).await;
        if let IpcResponse::RuleStats(stats) = stats_response {
            assert_eq!(stats.default_outbound, "default-chain");
        } else {
            panic!("Expected RuleStats response");
        }
    }

    #[tokio::test]
    async fn test_update_routing_with_chain_as_default() {
        // Test that ACTIVE chain tags can be used as default_outbound in UpdateRouting
        let handler = create_test_handler_with_chain_manager();

        // First create a chain
        let config = create_test_chain_config("route-default-chain");
        let create_response = handler
            .handle(IpcCommand::CreateChain {
                tag: "route-default-chain".into(),
                config,
            })
            .await;
        assert!(!create_response.is_error(), "Failed to create chain: {:?}", create_response);

        // Activate the chain (required for it to be a valid outbound)
        let activate_response = handler
            .handle(IpcCommand::ActivateChain {
                tag: "route-default-chain".into(),
            })
            .await;
        assert!(!activate_response.is_error(), "Failed to activate chain: {:?}", activate_response);

        // Update routing with chain as default outbound
        let response = handler
            .handle(IpcCommand::UpdateRouting {
                rules: vec![],
                default_outbound: "route-default-chain".into(),  // Active chain as default
            })
            .await;
        assert!(!response.is_error(), "Expected success, got: {:?}", response);

        if let IpcResponse::UpdateRoutingResult(result) = response {
            assert!(result.success);
            assert_eq!(result.default_outbound, "route-default-chain");
        } else {
            panic!("Expected UpdateRoutingResult response");
        }
    }

    #[tokio::test]
    async fn test_update_routing_version_increments() {
        let handler = create_test_handler();

        // Get initial version
        let stats1 = handler.handle(IpcCommand::GetRuleStats).await;
        let version1 = if let IpcResponse::RuleStats(s) = stats1 {
            s.config_version
        } else {
            panic!("Expected RuleStats");
        };

        // Update routing
        let _ = handler
            .handle(IpcCommand::UpdateRouting {
                rules: vec![],
                default_outbound: "direct".into(),
            })
            .await;

        // Version should have incremented
        let stats2 = handler.handle(IpcCommand::GetRuleStats).await;
        let version2 = if let IpcResponse::RuleStats(s) = stats2 {
            s.config_version
        } else {
            panic!("Expected RuleStats");
        };

        assert!(version2 > version1, "Version should increment after update");
    }

    #[tokio::test]
    async fn test_notify_egress_change_updated() {
        let handler = create_test_handler();

        let response = handler
            .handle(IpcCommand::NotifyEgressChange {
                action: EgressAction::Updated,
                tag: "updated-egress".into(),
                egress_type: "warp".into(),
            })
            .await;
        assert!(!response.is_error());

        if let IpcResponse::Success { message } = response {
            assert!(message.is_some());
            let msg = message.unwrap();
            assert!(msg.contains("Updated"));
            assert!(msg.contains("updated-egress"));
        } else {
            panic!("Expected Success response");
        }
    }

    // =========================================================================
    // Prometheus Metrics Tests
    // =========================================================================

    #[tokio::test]
    async fn test_get_prometheus_metrics_basic() {
        let handler = create_test_handler();
        let response = handler.handle(IpcCommand::GetPrometheusMetrics).await;

        if let IpcResponse::PrometheusMetrics(metrics) = response {
            // Check timestamp is reasonable
            assert!(metrics.timestamp_ms > 0);

            // Check core metrics are present
            assert!(metrics.metrics_text.contains("rust_router_connections_total"));
            assert!(metrics.metrics_text.contains("rust_router_connections_active"));
            assert!(metrics.metrics_text.contains("rust_router_connections_completed_total"));
            assert!(metrics.metrics_text.contains("rust_router_connections_errored_total"));
            assert!(metrics.metrics_text.contains("rust_router_bytes_rx_total"));
            assert!(metrics.metrics_text.contains("rust_router_bytes_tx_total"));

            // Check system metrics
            assert!(metrics.metrics_text.contains("rust_router_uptime_seconds"));
            assert!(metrics.metrics_text.contains("rust_router_info"));

            // Check rule metrics
            assert!(metrics.metrics_text.contains("rust_router_rules_domain_count"));
            assert!(metrics.metrics_text.contains("rust_router_rules_geoip_count"));
            assert!(metrics.metrics_text.contains("rust_router_config_version"));
        } else {
            panic!("Expected PrometheusMetrics response, got: {:?}", response);
        }
    }

    #[tokio::test]
    async fn test_get_prometheus_metrics_has_outbound_metrics() {
        let handler = create_test_handler();
        let response = handler.handle(IpcCommand::GetPrometheusMetrics).await;

        if let IpcResponse::PrometheusMetrics(metrics) = response {
            // Check outbound metrics with labels
            assert!(metrics.metrics_text.contains("rust_router_outbound_connections_total"));
            assert!(metrics.metrics_text.contains("rust_router_outbound_connections_active"));
            assert!(metrics.metrics_text.contains("rust_router_outbound_bytes_rx_total"));
            assert!(metrics.metrics_text.contains("rust_router_outbound_bytes_tx_total"));
            assert!(metrics.metrics_text.contains("rust_router_outbound_errors_total"));
            assert!(metrics.metrics_text.contains("rust_router_outbound_health"));

            // Check the "direct" outbound is labeled
            assert!(metrics.metrics_text.contains(r#"outbound="direct""#));
        } else {
            panic!("Expected PrometheusMetrics response");
        }
    }

    #[tokio::test]
    async fn test_get_prometheus_metrics_format() {
        let handler = create_test_handler();
        let response = handler.handle(IpcCommand::GetPrometheusMetrics).await;

        if let IpcResponse::PrometheusMetrics(metrics) = response {
            // Check HELP and TYPE comments are present
            assert!(metrics.metrics_text.contains("# HELP rust_router_connections_total"));
            assert!(metrics.metrics_text.contains("# TYPE rust_router_connections_total counter"));
            assert!(metrics.metrics_text.contains("# HELP rust_router_connections_active"));
            assert!(metrics.metrics_text.contains("# TYPE rust_router_connections_active gauge"));
            assert!(metrics.metrics_text.contains("# TYPE rust_router_info gauge"));
        } else {
            panic!("Expected PrometheusMetrics response");
        }
    }

    #[tokio::test]
    async fn test_get_prometheus_metrics_with_rules() {
        let handler = create_test_handler_with_rules();
        let response = handler.handle(IpcCommand::GetPrometheusMetrics).await;

        if let IpcResponse::PrometheusMetrics(metrics) = response {
            // Check rule metrics are present
            assert!(metrics.metrics_text.contains("rust_router_rules_domain_count"));
            assert!(metrics.metrics_text.contains("rust_router_rules_geoip_count"));
            assert!(metrics.metrics_text.contains("rust_router_rules_port_count"));
            assert!(metrics.metrics_text.contains("rust_router_rules_protocol_count"));
            assert!(metrics.metrics_text.contains("rust_router_rules_chain_count"));

            // The test handler has rules, so counts should be > 0 in output
            // Just verify the lines are there with numeric values
            let lines: Vec<&str> = metrics.metrics_text.lines().collect();
            let domain_count_line = lines.iter().find(|l| l.starts_with("rust_router_rules_domain_count "));
            assert!(domain_count_line.is_some(), "Domain count metric line should exist");
        } else {
            panic!("Expected PrometheusMetrics response");
        }
    }

    #[tokio::test]
    async fn test_get_prometheus_metrics_health_labels() {
        let handler = create_test_handler();
        let response = handler.handle(IpcCommand::GetPrometheusMetrics).await;

        if let IpcResponse::PrometheusMetrics(metrics) = response {
            // Check health metrics have status labels
            assert!(metrics.metrics_text.contains(r#"status="healthy""#));
            // All possible statuses should be represented
            assert!(metrics.metrics_text.contains(r#"status="degraded""#));
            assert!(metrics.metrics_text.contains(r#"status="unhealthy""#));
            assert!(metrics.metrics_text.contains(r#"status="unknown""#));
        } else {
            panic!("Expected PrometheusMetrics response");
        }
    }

    #[tokio::test]
    async fn test_get_prometheus_metrics_version_info() {
        let handler = create_test_handler();
        let response = handler.handle(IpcCommand::GetPrometheusMetrics).await;

        if let IpcResponse::PrometheusMetrics(metrics) = response {
            // Check info metric has version label
            assert!(metrics.metrics_text.contains("rust_router_info{version="));
            // The value should be 1
            let lines: Vec<&str> = metrics.metrics_text.lines().collect();
            let info_line = lines.iter().find(|l| l.starts_with("rust_router_info{"));
            assert!(info_line.is_some());
            assert!(info_line.unwrap().ends_with(" 1"));
        } else {
            panic!("Expected PrometheusMetrics response");
        }
    }

    #[test]
    fn test_escape_label_value() {
        // Test basic escaping
        assert_eq!(escape_label_value("simple"), "simple");
        assert_eq!(escape_label_value(r#"with"quote"#), r#"with\"quote"#);
        assert_eq!(escape_label_value("with\\backslash"), "with\\\\backslash");
        assert_eq!(escape_label_value("with\nnewline"), "with\\nnewline");

        // Test combined
        assert_eq!(
            escape_label_value("a\"b\\c\nd"),
            "a\\\"b\\\\c\\nd"
        );
    }

    #[test]
    fn test_write_metric_header() {
        let mut output = String::new();
        write_metric_header(&mut output, "test_metric", "Test description", "counter");

        assert!(output.contains("# HELP test_metric Test description"));
        assert!(output.contains("# TYPE test_metric counter"));
    }

    #[test]
    fn test_write_metric_value_without_labels() {
        let mut output = String::new();
        write_metric_value(&mut output, "test_metric", None, 42);

        assert_eq!(output.trim(), "test_metric 42");
    }

    #[test]
    fn test_write_metric_value_with_labels() {
        let mut output = String::new();
        write_metric_value(
            &mut output,
            "test_metric",
            Some(&[("label1", "value1"), ("label2", "value2")]),
            123,
        );

        assert!(output.contains("test_metric{"));
        assert!(output.contains(r#"label1="value1""#));
        assert!(output.contains(r#"label2="value2""#));
        assert!(output.contains("} 123"));
    }

    #[test]
    fn test_write_metric_value_escapes_labels() {
        let mut output = String::new();
        write_metric_value(
            &mut output,
            "test_metric",
            Some(&[("outbound", "test\"quoted")]),
            1,
        );

        // The quote should be escaped
        assert!(output.contains(r#"outbound="test\"quoted""#));
    }

    // =========================================================================
    // UDP IPC Handler Tests
    // =========================================================================

    #[tokio::test]
    async fn test_get_udp_stats_no_udp() {
        let handler = create_test_handler();
        let response = handler.handle(IpcCommand::GetUdpStats).await;

        if let IpcResponse::UdpStats(stats) = response {
            assert!(!stats.udp_enabled);
            assert!(stats.worker_stats.is_none());
            assert!(stats.buffer_pool_stats.is_none());
            assert!(stats.processor_stats.is_none());
            // Session stats should have default values
            assert_eq!(stats.session_stats.session_count, 0);
        } else {
            panic!("Expected UdpStats response");
        }
    }

    #[tokio::test]
    async fn test_list_udp_sessions_no_udp() {
        let handler = create_test_handler();
        let response = handler
            .handle(IpcCommand::ListUdpSessions { limit: 100 })
            .await;

        if let IpcResponse::UdpSessions(sessions) = response {
            assert!(sessions.sessions.is_empty());
            assert_eq!(sessions.total_count, 0);
            assert!(!sessions.truncated);
        } else {
            panic!("Expected UdpSessions response");
        }
    }

    #[tokio::test]
    async fn test_get_udp_session_no_udp() {
        let handler = create_test_handler();
        let response = handler
            .handle(IpcCommand::GetUdpSession {
                client_addr: "192.168.1.100:12345".into(),
                dest_addr: "8.8.8.8:53".into(),
            })
            .await;

        if let IpcResponse::UdpSession(session) = response {
            assert!(!session.found);
            assert!(session.session.is_none());
        } else {
            panic!("Expected UdpSession response");
        }
    }

    #[tokio::test]
    async fn test_get_udp_session_invalid_client_addr() {
        let handler = create_test_handler();
        let response = handler
            .handle(IpcCommand::GetUdpSession {
                client_addr: "not-an-address".into(),
                dest_addr: "8.8.8.8:53".into(),
            })
            .await;

        assert!(response.is_error());
        if let IpcResponse::Error(err) = response {
            assert!(matches!(err.code, ErrorCode::InvalidParameters));
            assert!(err.message.contains("Invalid client address"));
        }
    }

    #[tokio::test]
    async fn test_get_udp_session_invalid_dest_addr() {
        let handler = create_test_handler();
        let response = handler
            .handle(IpcCommand::GetUdpSession {
                client_addr: "192.168.1.100:12345".into(),
                dest_addr: "not-an-address".into(),
            })
            .await;

        assert!(response.is_error());
        if let IpcResponse::Error(err) = response {
            assert!(matches!(err.code, ErrorCode::InvalidParameters));
            assert!(err.message.contains("Invalid destination address"));
        }
    }

    #[tokio::test]
    async fn test_get_udp_worker_stats_no_udp() {
        let handler = create_test_handler();
        let response = handler.handle(IpcCommand::GetUdpWorkerStats).await;

        if let IpcResponse::UdpWorkerStats(stats) = response {
            assert!(!stats.running);
            assert_eq!(stats.num_workers, 0);
            assert!(stats.stats.is_none());
        } else {
            panic!("Expected UdpWorkerStats response");
        }
    }

    #[tokio::test]
    async fn test_get_buffer_pool_stats_no_udp() {
        let handler = create_test_handler();
        let response = handler.handle(IpcCommand::GetBufferPoolStats).await;

        if let IpcResponse::BufferPoolStats(stats) = response {
            assert!(!stats.available);
            assert!(stats.stats.is_none());
        } else {
            panic!("Expected BufferPoolStats response");
        }
    }

    #[tokio::test]
    async fn test_get_ingress_stats_disabled() {
        let handler = create_test_handler();
        let response = handler.handle(IpcCommand::GetIngressStats).await;

        if let IpcResponse::IngressStats(stats) = response {
            assert!(!stats.ingress_enabled);
            assert!(stats.ingress_state.is_none());
            assert!(stats.manager_stats.is_none());
            assert!(stats.forwarding_stats.is_none());
            assert!(stats.reply_stats.is_none());
        } else {
            panic!("Expected IngressStats response");
        }
    }

    #[tokio::test]
    async fn test_get_ingress_stats_enabled() {
        let (handler, _forwarding_stats, _reply_stats) = create_test_handler_with_ingress_stats();
        let response = handler.handle(IpcCommand::GetIngressStats).await;

        if let IpcResponse::IngressStats(stats) = response {
            assert!(stats.ingress_enabled);
            assert_eq!(stats.ingress_state.as_deref(), Some("created"));
            let manager_stats = stats.manager_stats.expect("manager stats");
            assert_eq!(manager_stats.peer_count, 0);
            assert!(stats.forwarding_stats.is_some());
            assert!(stats.reply_stats.is_some());
        } else {
            panic!("Expected IngressStats response");
        }
    }

    #[tokio::test]
    async fn test_get_ingress_stats_populated() {
        let (handler, forwarding_stats, reply_stats) = create_test_handler_with_ingress_stats();
        forwarding_stats.packets_forwarded.fetch_add(3, Ordering::Relaxed);
        forwarding_stats.bytes_forwarded.fetch_add(512, Ordering::Relaxed);
        reply_stats.packets_received.fetch_add(2, Ordering::Relaxed);
        reply_stats.packets_forwarded.fetch_add(1, Ordering::Relaxed);

        let response = handler.handle(IpcCommand::GetIngressStats).await;

        if let IpcResponse::IngressStats(stats) = response {
            let forwarding_stats = stats.forwarding_stats.expect("forwarding stats");
            assert_eq!(forwarding_stats.packets_forwarded, 3);
            assert_eq!(forwarding_stats.bytes_forwarded, 512);

            let reply_stats = stats.reply_stats.expect("reply stats");
            assert_eq!(reply_stats.packets_received, 2);
            assert_eq!(reply_stats.packets_forwarded, 1);
        } else {
            panic!("Expected IngressStats response");
        }
    }

    // ========================================================================
    // Chain Management Tests
    // ========================================================================

    use crate::chain::ChainManager;
    use crate::ipc::protocol::{ChainHop, ChainRole, TunnelType};

    fn create_test_handler_with_chain_manager() -> IpcHandler {
        let outbound_manager = Arc::new(OutboundManager::new());
        outbound_manager.add(Box::new(crate::outbound::DirectOutbound::simple("direct")));
        outbound_manager.add(Box::new(crate::outbound::DirectOutbound::simple("pia-us-east")));

        let conn_config = ConnectionConfig::default();
        let connection_manager = Arc::new(ConnectionManager::new(
            &conn_config,
            Arc::clone(&outbound_manager),
            "direct".into(),
            Duration::from_millis(300),
        ));

        // Create RuleEngine
        let rule_engine = Arc::new(RuleEngine::new(
            RoutingSnapshotBuilder::new()
                .default_outbound("direct")
                .version(1)
                .build()
                .unwrap(),
        ));

        // Create ChainManager and wire up the routing callback
        let chain_manager = Arc::new(ChainManager::new("local-node".to_string()));
        let routing_callback = Arc::new(RuleEngineRoutingCallback::new(Arc::clone(&rule_engine)));
        chain_manager.set_routing_callback(routing_callback);

        IpcHandler::new_with_chain_manager(
            connection_manager,
            outbound_manager,
            rule_engine,
            chain_manager,
            "local-node".to_string(),
        )
    }

    fn create_test_chain_config(tag: &str) -> ChainConfig {
        ChainConfig {
            tag: tag.to_string(),
            description: "Test chain".to_string(),
            dscp_value: 0, // Auto-allocate
            hops: vec![
                ChainHop {
                    node_tag: "local-node".to_string(),
                    role: ChainRole::Entry,
                    tunnel_type: TunnelType::WireGuard,
                },
                ChainHop {
                    node_tag: "remote-node".to_string(),
                    role: ChainRole::Terminal,
                    tunnel_type: TunnelType::WireGuard,
                },
            ],
            rules: vec![],
            exit_egress: "pia-us-east".to_string(),
            allow_transitive: false,
        }
    }

    #[tokio::test]
    async fn test_create_chain_success() {
        let handler = create_test_handler_with_chain_manager();
        let config = create_test_chain_config("test-chain-1");

        let response = handler
            .handle(IpcCommand::CreateChain {
                tag: "test-chain-1".to_string(),
                config,
            })
            .await;

        assert!(!response.is_error(), "Expected success, got: {:?}", response);
    }

    #[tokio::test]
    async fn test_create_chain_already_exists() {
        let handler = create_test_handler_with_chain_manager();
        let config = create_test_chain_config("test-chain-2");

        // First creation should succeed
        let response = handler
            .handle(IpcCommand::CreateChain {
                tag: "test-chain-2".to_string(),
                config: config.clone(),
            })
            .await;
        assert!(!response.is_error());

        // Second creation should fail
        let response = handler
            .handle(IpcCommand::CreateChain {
                tag: "test-chain-2".to_string(),
                config,
            })
            .await;
        assert!(response.is_error());
        if let IpcResponse::Error(err) = response {
            assert!(matches!(err.code, ErrorCode::AlreadyExists));
        }
    }

    #[tokio::test]
    async fn test_create_chain_direct_egress_rejected() {
        let handler = create_test_handler_with_chain_manager();
        let mut config = create_test_chain_config("test-chain-3");
        config.exit_egress = "direct".to_string();

        let response = handler
            .handle(IpcCommand::CreateChain {
                tag: "test-chain-3".to_string(),
                config,
            })
            .await;

        assert!(response.is_error());
        if let IpcResponse::Error(err) = response {
            assert!(matches!(err.code, ErrorCode::InvalidParameters));
            assert!(err.message.contains("direct"));
        }
    }

    #[tokio::test]
    async fn test_create_chain_empty_hops_rejected() {
        let handler = create_test_handler_with_chain_manager();
        let mut config = create_test_chain_config("test-chain-4");
        config.hops = vec![];

        let response = handler
            .handle(IpcCommand::CreateChain {
                tag: "test-chain-4".to_string(),
                config,
            })
            .await;

        assert!(response.is_error());
        if let IpcResponse::Error(err) = response {
            assert!(matches!(err.code, ErrorCode::InvalidParameters));
        }
    }

    #[tokio::test]
    async fn test_remove_chain_success() {
        let handler = create_test_handler_with_chain_manager();
        let config = create_test_chain_config("test-chain-5");

        // Create chain first
        let response = handler
            .handle(IpcCommand::CreateChain {
                tag: "test-chain-5".to_string(),
                config,
            })
            .await;
        assert!(!response.is_error());

        // Remove chain
        let response = handler
            .handle(IpcCommand::RemoveChain {
                tag: "test-chain-5".to_string(),
            })
            .await;
        assert!(!response.is_error());
    }

    #[tokio::test]
    async fn test_remove_chain_not_found() {
        let handler = create_test_handler_with_chain_manager();

        let response = handler
            .handle(IpcCommand::RemoveChain {
                tag: "nonexistent".to_string(),
            })
            .await;

        assert!(response.is_error());
        if let IpcResponse::Error(err) = response {
            assert!(matches!(err.code, ErrorCode::NotFound));
        }
    }

    #[tokio::test]
    async fn test_get_chain_status_success() {
        let handler = create_test_handler_with_chain_manager();
        let config = create_test_chain_config("test-chain-6");

        // Create chain first
        let response = handler
            .handle(IpcCommand::CreateChain {
                tag: "test-chain-6".to_string(),
                config,
            })
            .await;
        assert!(!response.is_error());

        // Get status
        let response = handler
            .handle(IpcCommand::GetChainStatus {
                tag: "test-chain-6".to_string(),
            })
            .await;

        if let IpcResponse::ChainStatus(status) = response {
            assert_eq!(status.tag, "test-chain-6");
            assert!(matches!(status.state, crate::ipc::protocol::ChainState::Inactive));
            assert!(status.dscp_value >= 1 && status.dscp_value <= 63);
        } else {
            panic!("Expected ChainStatus response");
        }
    }

    #[tokio::test]
    async fn test_get_chain_status_not_found() {
        let handler = create_test_handler_with_chain_manager();

        let response = handler
            .handle(IpcCommand::GetChainStatus {
                tag: "nonexistent".to_string(),
            })
            .await;

        assert!(response.is_error());
        if let IpcResponse::Error(err) = response {
            assert!(matches!(err.code, ErrorCode::NotFound));
        }
    }

    #[tokio::test]
    async fn test_list_chains_empty() {
        let handler = create_test_handler_with_chain_manager();

        let response = handler.handle(IpcCommand::ListChains).await;

        if let IpcResponse::ChainList(list) = response {
            assert!(list.chains.is_empty());
        } else {
            panic!("Expected ChainList response");
        }
    }

    #[tokio::test]
    async fn test_list_chains_with_chains() {
        let handler = create_test_handler_with_chain_manager();

        // Create two chains
        for i in 7..=8 {
            let config = create_test_chain_config(&format!("test-chain-{}", i));
            let response = handler
                .handle(IpcCommand::CreateChain {
                    tag: format!("test-chain-{}", i),
                    config,
                })
                .await;
            assert!(!response.is_error());
        }

        // List chains
        let response = handler.handle(IpcCommand::ListChains).await;

        if let IpcResponse::ChainList(list) = response {
            assert_eq!(list.chains.len(), 2);
        } else {
            panic!("Expected ChainList response");
        }
    }

    #[tokio::test]
    async fn test_get_chain_role_found() {
        let handler = create_test_handler_with_chain_manager();
        let config = create_test_chain_config("test-chain-9");

        // Create chain
        let response = handler
            .handle(IpcCommand::CreateChain {
                tag: "test-chain-9".to_string(),
                config,
            })
            .await;
        assert!(!response.is_error());

        // Get role
        let response = handler
            .handle(IpcCommand::GetChainRole {
                chain_tag: "test-chain-9".to_string(),
            })
            .await;

        if let IpcResponse::ChainRole(role_response) = response {
            assert_eq!(role_response.chain_tag, "test-chain-9");
            assert!(role_response.in_chain);
            assert!(matches!(role_response.role, Some(ChainRole::Entry)));
        } else {
            panic!("Expected ChainRole response");
        }
    }

    #[tokio::test]
    async fn test_get_chain_role_not_found() {
        let handler = create_test_handler_with_chain_manager();

        let response = handler
            .handle(IpcCommand::GetChainRole {
                chain_tag: "nonexistent".to_string(),
            })
            .await;

        assert!(response.is_error());
        if let IpcResponse::Error(err) = response {
            assert!(matches!(err.code, ErrorCode::NotFound));
        }
    }

    #[tokio::test]
    async fn test_chain_manager_not_available() {
        // Use regular handler without chain manager
        let handler = create_test_handler();

        let response = handler
            .handle(IpcCommand::CreateChain {
                tag: "test".to_string(),
                config: create_test_chain_config("test"),
            })
            .await;

        assert!(response.is_error());
        if let IpcResponse::Error(err) = response {
            assert!(err.message.contains("Chain manager not available"));
        }
    }

    #[tokio::test]
    async fn test_list_chains_without_chain_manager() {
        let handler = create_test_handler();

        let response = handler.handle(IpcCommand::ListChains).await;

        // Should return empty list instead of error
        if let IpcResponse::ChainList(list) = response {
            assert!(list.chains.is_empty());
        } else {
            panic!("Expected ChainList response");
        }
    }

    // ========================================================================
    // Two-Phase Commit Tests
    // ========================================================================

    #[tokio::test]
    async fn test_prepare_chain_route_success() {
        let handler = create_test_handler_with_chain_manager();
        let mut config = create_test_chain_config("test-chain-10");
        config.dscp_value = 10;

        let response = handler
            .handle(IpcCommand::PrepareChainRoute {
                chain_tag: "test-chain-10".to_string(),
                config,
                source_node: "coordinator-node".to_string(),
            })
            .await;

        if let IpcResponse::PrepareResult(prepare) = response {
            assert!(prepare.success);
            assert_eq!(prepare.node, "local-node");
        } else {
            panic!("Expected PrepareResult response");
        }
    }

    #[tokio::test]
    async fn test_prepare_chain_route_invalid_config() {
        let handler = create_test_handler_with_chain_manager();
        let mut config = create_test_chain_config("test-chain-11");
        config.dscp_value = 11;
        config.exit_egress = "direct".to_string(); // Invalid

        let response = handler
            .handle(IpcCommand::PrepareChainRoute {
                chain_tag: "test-chain-11".to_string(),
                config,
                source_node: "coordinator-node".to_string(),
            })
            .await;

        if let IpcResponse::PrepareResult(prepare) = response {
            assert!(!prepare.success);
            assert!(prepare.message.unwrap().contains("direct"));
        } else {
            panic!("Expected PrepareResult response");
        }
    }

    #[tokio::test]
    async fn test_commit_chain_route_after_prepare() {
        let handler = create_test_handler_with_chain_manager();
        let mut config = create_test_chain_config("test-chain-12");
        config.dscp_value = 12;

        // Prepare first
        let response = handler
            .handle(IpcCommand::PrepareChainRoute {
                chain_tag: "test-chain-12".to_string(),
                config,
                source_node: "coordinator-node".to_string(),
            })
            .await;
        if let IpcResponse::PrepareResult(prepare) = response {
            assert!(prepare.success);
        }

        // Commit
        let response = handler
            .handle(IpcCommand::CommitChainRoute {
                chain_tag: "test-chain-12".to_string(),
                source_node: "coordinator-node".to_string(),
            })
            .await;

        assert!(!response.is_error());
    }

    #[tokio::test]
    async fn test_abort_chain_route() {
        let handler = create_test_handler_with_chain_manager();
        let mut config = create_test_chain_config("test-chain-13");
        config.dscp_value = 13;

        // Prepare first
        let response = handler
            .handle(IpcCommand::PrepareChainRoute {
                chain_tag: "test-chain-13".to_string(),
                config,
                source_node: "coordinator-node".to_string(),
            })
            .await;
        if let IpcResponse::PrepareResult(prepare) = response {
            assert!(prepare.success);
        }

        // Abort
        let response = handler
            .handle(IpcCommand::AbortChainRoute {
                chain_tag: "test-chain-13".to_string(),
                source_node: "coordinator-node".to_string(),
            })
            .await;

        // Abort should always succeed
        assert!(!response.is_error());
    }

    #[tokio::test]
    async fn test_abort_nonexistent_chain() {
        let handler = create_test_handler_with_chain_manager();

        // Abort non-existent chain should still succeed (best-effort)
        let response = handler
            .handle(IpcCommand::AbortChainRoute {
                chain_tag: "nonexistent".to_string(),
                source_node: "coordinator-node".to_string(),
            })
            .await;

        // Abort should return success even for non-existent chains
        assert!(!response.is_error());
    }

    #[tokio::test]
    async fn test_update_chain_state() {
        let handler = create_test_handler_with_chain_manager();
        let config = create_test_chain_config("test-chain-14");

        // Create chain
        let response = handler
            .handle(IpcCommand::CreateChain {
                tag: "test-chain-14".to_string(),
                config,
            })
            .await;
        assert!(!response.is_error());

        // Update state
        let response = handler
            .handle(IpcCommand::UpdateChainState {
                tag: "test-chain-14".to_string(),
                state: crate::ipc::protocol::ChainState::Error,
                last_error: Some("Test error".to_string()),
            })
            .await;

        assert!(!response.is_error());

        // Verify state was updated
        let response = handler
            .handle(IpcCommand::GetChainStatus {
                tag: "test-chain-14".to_string(),
            })
            .await;

        if let IpcResponse::ChainStatus(status) = response {
            assert!(matches!(status.state, crate::ipc::protocol::ChainState::Error));
            assert_eq!(status.last_error, Some("Test error".to_string()));
        } else {
            panic!("Expected ChainStatus response");
        }
    }

    #[tokio::test]
    async fn test_chain_with_too_many_hops_rejected() {
        let handler = create_test_handler_with_chain_manager();
        let mut config = create_test_chain_config("test-chain-15");

        // Add 11 hops (max is 10)
        config.hops = (0..11)
            .map(|i| {
                let role = if i == 0 {
                    ChainRole::Entry
                } else if i == 10 {
                    ChainRole::Terminal
                } else {
                    ChainRole::Relay
                };
                ChainHop {
                    node_tag: format!("node-{}", i),
                    role,
                    tunnel_type: TunnelType::WireGuard,
                }
            })
            .collect();

        let response = handler
            .handle(IpcCommand::CreateChain {
                tag: "test-chain-15".to_string(),
                config,
            })
            .await;

        assert!(response.is_error());
        if let IpcResponse::Error(err) = response {
            assert!(matches!(err.code, ErrorCode::InvalidParameters));
        }
    }

    #[tokio::test]
    async fn test_chain_xray_relay_rejected() {
        let handler = create_test_handler_with_chain_manager();
        let mut config = create_test_chain_config("test-chain-16");

        // Add Xray relay (not allowed)
        config.hops = vec![
            ChainHop {
                node_tag: "local-node".to_string(),
                role: ChainRole::Entry,
                tunnel_type: TunnelType::WireGuard,
            },
            ChainHop {
                node_tag: "relay-node".to_string(),
                role: ChainRole::Relay,
                tunnel_type: TunnelType::Xray, // Xray relay not allowed
            },
            ChainHop {
                node_tag: "terminal-node".to_string(),
                role: ChainRole::Terminal,
                tunnel_type: TunnelType::WireGuard,
            },
        ];

        let response = handler
            .handle(IpcCommand::CreateChain {
                tag: "test-chain-16".to_string(),
                config,
            })
            .await;

        assert!(response.is_error());
        if let IpcResponse::Error(err) = response {
            assert!(matches!(err.code, ErrorCode::InvalidParameters));
            assert!(err.message.contains("Xray"));
        }
    }

    #[tokio::test]
    async fn test_with_chain_manager_builder() {
        let handler = create_test_handler();
        let chain_manager = Arc::new(ChainManager::new("test-node".to_string()));

        let handler = handler.with_chain_manager(chain_manager, "test-node".to_string());

        assert!(handler.chain_manager().is_some());
        assert_eq!(handler.local_node_tag(), "test-node");
    }

    // ========================================================================
    // Additional Handler Tests
    // ========================================================================

    #[tokio::test]
    async fn test_wg_tunnel_not_available() {
        let handler = create_test_handler();

        let response = handler
            .handle(IpcCommand::GetWgTunnelStatus {
                tag: "test-tunnel".to_string(),
            })
            .await;

        assert!(response.is_error());
        if let IpcResponse::Error(err) = response {
            assert!(err.message.contains("not available"));
        }
    }

    #[tokio::test]
    async fn test_list_wg_tunnels_empty() {
        let handler = create_test_handler();

        let response = handler.handle(IpcCommand::ListWgTunnels).await;

        if let IpcResponse::WgTunnelList(list_response) = response {
            assert!(list_response.tunnels.is_empty());
        } else {
            panic!("Expected WgTunnelList response");
        }
    }

    #[tokio::test]
    async fn test_ecmp_group_not_available() {
        let handler = create_test_handler();

        let response = handler
            .handle(IpcCommand::GetEcmpGroupStatus {
                tag: "test-group".to_string(),
            })
            .await;

        assert!(response.is_error());
        if let IpcResponse::Error(err) = response {
            assert!(err.message.contains("not available"));
        }
    }

    #[tokio::test]
    async fn test_list_ecmp_groups_empty() {
        let handler = create_test_handler();

        let response = handler.handle(IpcCommand::ListEcmpGroups).await;

        if let IpcResponse::EcmpGroupList(list_response) = response {
            assert!(list_response.groups.is_empty());
        } else {
            panic!("Expected EcmpGroupList response");
        }
    }

    #[tokio::test]
    async fn test_peer_manager_not_available() {
        let handler = create_test_handler();

        let response = handler
            .handle(IpcCommand::GetPeerStatus {
                tag: "test-peer".to_string(),
            })
            .await;

        assert!(response.is_error());
        if let IpcResponse::Error(err) = response {
            assert!(err.message.contains("not available"));
        }
    }

    #[tokio::test]
    async fn test_list_peers_empty() {
        let handler = create_test_handler();

        let response = handler.handle(IpcCommand::ListPeers).await;

        if let IpcResponse::PeerList(list_response) = response {
            assert!(list_response.peers.is_empty());
        } else {
            panic!("Expected PeerList response");
        }
    }

    #[tokio::test]
    async fn test_connect_peer_not_available() {
        let handler = create_test_handler();

        let response = handler
            .handle(IpcCommand::ConnectPeer {
                tag: "test-peer".to_string(),
            })
            .await;

        assert!(response.is_error());
        if let IpcResponse::Error(err) = response {
            assert!(err.message.contains("not available"));
        }
    }

    #[tokio::test]
    async fn test_disconnect_peer_not_available() {
        let handler = create_test_handler();

        let response = handler
            .handle(IpcCommand::DisconnectPeer {
                tag: "test-peer".to_string(),
            })
            .await;

        assert!(response.is_error());
        if let IpcResponse::Error(err) = response {
            assert!(err.message.contains("not available"));
        }
    }

    #[tokio::test]
    async fn test_complete_handshake_not_available() {
        let handler = create_test_handler();

        let response = handler
            .handle(IpcCommand::CompleteHandshake {
                code: "test-code".to_string(),
            })
            .await;

        assert!(response.is_error());
        if let IpcResponse::Error(err) = response {
            assert!(err.message.contains("not available"));
        }
    }

    #[tokio::test]
    async fn test_remove_peer_not_available() {
        let handler = create_test_handler();

        let response = handler
            .handle(IpcCommand::RemovePeer {
                tag: "test-peer".to_string(),
            })
            .await;

        assert!(response.is_error());
        if let IpcResponse::Error(err) = response {
            assert!(err.message.contains("not available"));
        }
    }

    #[tokio::test]
    async fn test_builder_with_peer_manager() {
        let handler = create_test_handler();

        // Build a peer manager for testing
        let peer_manager = Arc::new(crate::peer::manager::PeerManager::new(
            "test-node".to_string(),
        ));

        let handler = handler.with_peer_manager(peer_manager);

        // Now list peers should return empty list, not an error
        let response = handler.handle(IpcCommand::ListPeers).await;

        if let IpcResponse::PeerList(list_response) = response {
            assert!(list_response.peers.is_empty());
        } else {
            panic!("Expected PeerList response, not error");
        }
    }

    #[tokio::test]
    async fn test_builder_with_ecmp_group_manager() {
        let handler = create_test_handler();

        // Build an ECMP group manager for testing
        let ecmp_manager = Arc::new(crate::ecmp::group::EcmpGroupManager::new());

        let handler = handler.with_ecmp_group_manager(ecmp_manager);

        // Now list groups should return empty list, not an error
        let response = handler.handle(IpcCommand::ListEcmpGroups).await;

        if let IpcResponse::EcmpGroupList(list_response) = response {
            assert!(list_response.groups.is_empty());
        } else {
            panic!("Expected EcmpGroupList response, not error");
        }
    }

    #[tokio::test]
    async fn test_create_ecmp_group_with_manager() {
        use crate::ipc::protocol::{EcmpAlgorithm, EcmpGroupConfig, EcmpMemberConfig};

        let handler = create_test_handler();

        // Build an ECMP group manager for testing
        let ecmp_manager = Arc::new(crate::ecmp::group::EcmpGroupManager::new());

        let handler = handler.with_ecmp_group_manager(ecmp_manager);

        // Create a group
        let config = EcmpGroupConfig {
            description: "Test group".to_string(),
            algorithm: EcmpAlgorithm::RoundRobin,
            members: vec![EcmpMemberConfig {
                outbound: "direct".to_string(),
                weight: 1,
                enabled: true,
            }],
            skip_unhealthy: true,
            health_check_interval_secs: 30,
            routing_mark: None,
            routing_table: None,
        };

        let response = handler
            .handle(IpcCommand::CreateEcmpGroup {
                tag: "test-group".to_string(),
                config,
            })
            .await;

        // Should succeed
        assert!(!response.is_error());

        // List should now have one group
        let response = handler.handle(IpcCommand::ListEcmpGroups).await;
        if let IpcResponse::EcmpGroupList(list_response) = response {
            assert_eq!(list_response.groups.len(), 1);
            assert_eq!(list_response.groups[0].tag, "test-group");
        } else {
            panic!("Expected EcmpGroupList response");
        }
    }

    #[tokio::test]
    async fn test_remove_ecmp_group() {
        use crate::ipc::protocol::{EcmpAlgorithm, EcmpGroupConfig, EcmpMemberConfig};

        let handler = create_test_handler();
        let ecmp_manager = Arc::new(crate::ecmp::group::EcmpGroupManager::new());
        let handler = handler.with_ecmp_group_manager(ecmp_manager);

        // Create a group first
        let config = EcmpGroupConfig {
            description: "Test group".to_string(),
            algorithm: EcmpAlgorithm::RoundRobin,
            members: vec![EcmpMemberConfig {
                outbound: "direct".to_string(),
                weight: 1,
                enabled: true,
            }],
            skip_unhealthy: true,
            health_check_interval_secs: 30,
            routing_mark: None,
            routing_table: None,
        };

        handler
            .handle(IpcCommand::CreateEcmpGroup {
                tag: "test-group".to_string(),
                config,
            })
            .await;

        // Remove the group
        let response = handler
            .handle(IpcCommand::RemoveEcmpGroup {
                tag: "test-group".to_string(),
            })
            .await;

        assert!(!response.is_error());

        // List should now be empty
        let response = handler.handle(IpcCommand::ListEcmpGroups).await;
        if let IpcResponse::EcmpGroupList(list_response) = response {
            assert!(list_response.groups.is_empty());
        } else {
            panic!("Expected EcmpGroupList response");
        }
    }

    #[tokio::test]
    async fn test_get_ecmp_group_status() {
        use crate::ipc::protocol::{EcmpAlgorithm, EcmpGroupConfig, EcmpMemberConfig};

        let handler = create_test_handler();
        let ecmp_manager = Arc::new(crate::ecmp::group::EcmpGroupManager::new());
        let handler = handler.with_ecmp_group_manager(ecmp_manager);

        // Create a group first
        let config = EcmpGroupConfig {
            description: "Test group".to_string(),
            algorithm: EcmpAlgorithm::Weighted,
            members: vec![
                EcmpMemberConfig {
                    outbound: "outbound-1".to_string(),
                    weight: 2,
                    enabled: true,
                },
                EcmpMemberConfig {
                    outbound: "outbound-2".to_string(),
                    weight: 3,
                    enabled: true,
                },
            ],
            skip_unhealthy: true,
            health_check_interval_secs: 30,
            routing_mark: Some(200),
            routing_table: Some(200),
        };

        handler
            .handle(IpcCommand::CreateEcmpGroup {
                tag: "weighted-group".to_string(),
                config,
            })
            .await;

        // Get status
        let response = handler
            .handle(IpcCommand::GetEcmpGroupStatus {
                tag: "weighted-group".to_string(),
            })
            .await;

        if let IpcResponse::EcmpGroupStatus(status) = response {
            assert_eq!(status.tag, "weighted-group");
            assert!(matches!(status.algorithm, EcmpAlgorithm::Weighted));
            assert_eq!(status.members.len(), 2);
            assert_eq!(status.members[0].outbound, "outbound-1");
            assert_eq!(status.members[0].weight, 2);
            assert_eq!(status.members[1].outbound, "outbound-2");
            assert_eq!(status.members[1].weight, 3);
        } else {
            panic!("Expected EcmpGroupStatus response");
        }
    }

    #[tokio::test]
    async fn test_get_ecmp_group_status_not_found() {
        let handler = create_test_handler();
        let ecmp_manager = Arc::new(crate::ecmp::group::EcmpGroupManager::new());
        let handler = handler.with_ecmp_group_manager(ecmp_manager);

        let response = handler
            .handle(IpcCommand::GetEcmpGroupStatus {
                tag: "nonexistent-group".to_string(),
            })
            .await;

        assert!(response.is_error());
        if let IpcResponse::Error(err) = response {
            assert!(matches!(err.code, ErrorCode::NotFound));
        }
    }

    // ========================================================================
    // UpdateChain and UpdateEcmpGroupMembers Tests
    // ========================================================================

    #[tokio::test]
    async fn test_update_chain_success() {
        use crate::chain::ChainManager;
        use crate::ipc::protocol::{ChainConfig, ChainHop, ChainRole, TunnelType};

        let handler = create_test_handler();

        // Create chain manager
        let chain_manager = Arc::new(ChainManager::new("test-node".to_string()));
        let handler = handler.with_chain_manager(chain_manager.clone(), "test-node".to_string());

        // Create a chain first
        let config = ChainConfig {
            tag: "test-chain".to_string(),
            description: "Original description".to_string(),
            dscp_value: 0,
            hops: vec![ChainHop {
                node_tag: "terminal-node".to_string(),
                tunnel_type: TunnelType::WireGuard,
                role: ChainRole::Terminal,
            }],
            rules: vec![],
            exit_egress: "pia-us-east".to_string(),
            allow_transitive: false,
        };

        handler
            .handle(IpcCommand::CreateChain {
                tag: "test-chain".to_string(),
                config,
            })
            .await;

        // Update the chain
        let response = handler
            .handle(IpcCommand::UpdateChain {
                tag: "test-chain".to_string(),
                hops: None,
                exit_egress: Some("pia-uk-london".to_string()),
                description: Some("Updated description".to_string()),
                allow_transitive: Some(true),
            })
            .await;

        assert!(!response.is_error());

        // Verify the update
        let updated_config = chain_manager.get_chain_config("test-chain");
        assert!(updated_config.is_some());
        let config = updated_config.unwrap();
        assert_eq!(config.description, "Updated description");
        assert_eq!(config.exit_egress, "pia-uk-london");
        assert!(config.allow_transitive);
    }

    #[tokio::test]
    async fn test_update_chain_not_inactive() {
        use crate::chain::ChainManager;
        use crate::ipc::protocol::{ChainConfig, ChainHop, ChainRole, ChainState, TunnelType};

        let handler = create_test_handler();

        let chain_manager = Arc::new(ChainManager::new("test-node".to_string()));
        let handler = handler.with_chain_manager(chain_manager.clone(), "test-node".to_string());

        // Create a chain
        let config = ChainConfig {
            tag: "test-chain".to_string(),
            description: "Test".to_string(),
            dscp_value: 0,
            hops: vec![ChainHop {
                node_tag: "terminal-node".to_string(),
                tunnel_type: TunnelType::WireGuard,
                role: ChainRole::Terminal,
            }],
            rules: vec![],
            exit_egress: "pia-us-east".to_string(),
            allow_transitive: false,
        };

        handler
            .handle(IpcCommand::CreateChain {
                tag: "test-chain".to_string(),
                config,
            })
            .await;

        // Manually set state to Active (simulating activation)
        let _ = chain_manager.update_chain_state("test-chain", ChainState::Active, None);

        // Try to update - should fail
        let response = handler
            .handle(IpcCommand::UpdateChain {
                tag: "test-chain".to_string(),
                hops: None,
                exit_egress: Some("pia-uk-london".to_string()),
                description: None,
                allow_transitive: None,
            })
            .await;

        assert!(response.is_error());
        if let IpcResponse::Error(err) = response {
            assert!(err.message.contains("inactive"));
        }
    }

    #[tokio::test]
    async fn test_update_ecmp_group_members_success() {
        use crate::ipc::protocol::{EcmpAlgorithm, EcmpGroupConfig, EcmpMemberConfig};

        let handler = create_test_handler();
        let ecmp_manager = Arc::new(crate::ecmp::group::EcmpGroupManager::new());
        let handler = handler.with_ecmp_group_manager(ecmp_manager.clone());

        // Create a group first
        let config = EcmpGroupConfig {
            description: "Test group".to_string(),
            algorithm: EcmpAlgorithm::RoundRobin,
            members: vec![EcmpMemberConfig {
                outbound: "direct".to_string(),
                weight: 1,
                enabled: true,
            }],
            skip_unhealthy: true,
            health_check_interval_secs: 30,
            routing_mark: None,
            routing_table: None,
        };

        handler
            .handle(IpcCommand::CreateEcmpGroup {
                tag: "test-group".to_string(),
                config,
            })
            .await;

        // Update the members
        let response = handler
            .handle(IpcCommand::UpdateEcmpGroupMembers {
                tag: "test-group".to_string(),
                members: vec![
                    EcmpMemberConfig {
                        outbound: "proxy-1".to_string(),
                        weight: 2,
                        enabled: true,
                    },
                    EcmpMemberConfig {
                        outbound: "proxy-2".to_string(),
                        weight: 3,
                        enabled: true,
                    },
                ],
            })
            .await;

        assert!(!response.is_error());

        // Verify the update - use member_count() and member_tags() instead of config().members
        // because the config is the original config and members are stored separately
        let group = ecmp_manager.get_group("test-group").unwrap();
        assert_eq!(group.member_count(), 2);
        let tags = group.member_tags();
        assert!(tags.contains(&"proxy-1".to_string()));
        assert!(tags.contains(&"proxy-2".to_string()));
    }

    #[tokio::test]
    async fn test_update_ecmp_group_members_not_found() {
        use crate::ipc::protocol::EcmpMemberConfig;

        let handler = create_test_handler();
        let ecmp_manager = Arc::new(crate::ecmp::group::EcmpGroupManager::new());
        let handler = handler.with_ecmp_group_manager(ecmp_manager);

        // Try to update non-existent group
        let response = handler
            .handle(IpcCommand::UpdateEcmpGroupMembers {
                tag: "nonexistent-group".to_string(),
                members: vec![EcmpMemberConfig {
                    outbound: "proxy-1".to_string(),
                    weight: 1,
                    enabled: true,
                }],
            })
            .await;

        assert!(response.is_error());
        if let IpcResponse::Error(err) = response {
            assert!(matches!(err.code, ErrorCode::NotFound));
        }
    }
}
