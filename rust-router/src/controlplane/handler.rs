//! Control Plane Handler
//!
//! Implements `netbridge::ConnectionHandler` to make routing decisions
//! for incoming connections. This is the core component that bridges the
//! data plane (netbridge) with control components (rules, chain, fakedns, sniff).
//!
//! # Architecture
//!
//! ```text
//! netbridge::ConnectionInfo
//!         |
//!         v
//! ControlPlaneHandler
//!   |-- Domain resolution (SNI -> FakeDNS -> DNS cache)
//!   |-- Type bridging (netbridge::ConnectionInfo -> rules::ConnectionInfo)
//!   |-- Rule matching (RuleEngine)
//!   |-- Chain handling (ChainHandler)
//!   |-- Outbound connection (OutboundManager)
//!         |
//!         v
//! netbridge::RoutingDecision
//! ```
//!
//! # Domain Resolution Priority
//!
//! 1. **SNI**: Domain extracted by netbridge from TLS `ClientHello`
//! 2. **`FakeDNS`**: Reverse lookup of fake IP to domain
//! 3. **DNS Cache**: IP-to-domain cache from DNS responses
//!
//! # Example
//!
//! ```ignore
//! use rust_router::controlplane::{ControlPlaneHandler, ControlPlaneBuilder};
//! use rust_router::netbridge::{DataPlaneBuilder, ConnectionHandler};
//!
//! // Create handler
//! let handler = ControlPlaneBuilder::new()
//!     .with_rule_engine(rule_engine)
//!     .with_outbound_manager(outbound_manager)
//!     .build()?;
//!
//! // Use with data plane
//! let dp = DataPlaneBuilder::new()
//!     .with_handler(Arc::new(handler))
//!     .build()
//!     .await?;
//! ```

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tracing::{debug, error, trace, warn};

use crate::chain::ChainManager;
use crate::error::UdpError;
use crate::netbridge::dataplane::{
    ConnectionHandler, ConnectionInfo as NetbridgeConnectionInfo,
    RoutingDecision as NetbridgeRoutingDecision, UdpHandle, UdpHandleRemote,
};
use crate::netbridge::types::IpProtocol;
use crate::outbound::{OutboundConnection, OutboundManager, UdpOutboundHandle};
use crate::rules::engine::{ConnectionInfo as RulesConnectionInfo, RuleEngine};
use crate::rules::fwmark::ChainMark;

#[cfg(feature = "fakedns")]
use crate::fakedns::FakeDnsManager;
use crate::ingress::dns_cache::IpDomainCache;

use super::chain::{ChainHandler, ChainRoutingResult};
use super::error::ControlPlaneError;

// =============================================================================
// Domain Source
// =============================================================================

/// Source of domain information for routing decisions
///
/// Tracks where the domain name was resolved from, useful for debugging
/// and statistics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainSource {
    /// Domain extracted from TLS SNI by netbridge
    Sni,
    /// Domain resolved from `FakeDNS` reverse lookup
    FakeDns,
    /// Domain found in DNS response cache
    DnsCache,
    /// No domain information available
    None,
}

impl std::fmt::Display for DomainSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sni => write!(f, "sni"),
            Self::FakeDns => write!(f, "fakedns"),
            Self::DnsCache => write!(f, "dns-cache"),
            Self::None => write!(f, "none"),
        }
    }
}

// =============================================================================
// Routing Context
// =============================================================================

/// Internal routing context bridging netbridge and rules types
///
/// This struct holds both the original netbridge connection info and the
/// converted rules connection info, along with metadata about domain resolution.
struct RoutingContext {
    /// Original netbridge connection info (contains peer info, session ID, etc.)
    netbridge_info: NetbridgeConnectionInfo,
    /// Converted rules connection info (for rule matching)
    rules_info: RulesConnectionInfo,
    /// How the domain was resolved
    domain_source: DomainSource,
}

// =============================================================================
// Statistics
// =============================================================================

/// Statistics for the control plane handler
///
/// All counters are atomic and can be read without locking.
#[derive(Debug, Default)]
pub struct ControlPlaneStats {
    /// Total TCP connections handled
    pub tcp_connections: AtomicU64,
    /// Total UDP sessions handled
    pub udp_sessions: AtomicU64,
    /// Packets routed through chains
    pub chain_packets: AtomicU64,
    /// Connections blocked by rules
    pub blocked_connections: AtomicU64,
    /// Domains resolved via SNI
    pub domain_resolved_sni: AtomicU64,
    /// Domains resolved via `FakeDNS`
    pub domain_resolved_fakedns: AtomicU64,
    /// Domains resolved via DNS cache
    pub domain_resolved_cache: AtomicU64,
    /// Outbound connection failures
    pub outbound_failures: AtomicU64,
    /// Rule matching errors
    pub rule_errors: AtomicU64,
}

impl ControlPlaneStats {
    /// Create a new stats instance
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Get a snapshot of all statistics
    #[must_use]
    pub fn snapshot(&self) -> ControlPlaneStatsSnapshot {
        ControlPlaneStatsSnapshot {
            tcp_connections: self.tcp_connections.load(Ordering::Relaxed),
            udp_sessions: self.udp_sessions.load(Ordering::Relaxed),
            chain_packets: self.chain_packets.load(Ordering::Relaxed),
            blocked_connections: self.blocked_connections.load(Ordering::Relaxed),
            domain_resolved_sni: self.domain_resolved_sni.load(Ordering::Relaxed),
            domain_resolved_fakedns: self.domain_resolved_fakedns.load(Ordering::Relaxed),
            domain_resolved_cache: self.domain_resolved_cache.load(Ordering::Relaxed),
            outbound_failures: self.outbound_failures.load(Ordering::Relaxed),
            rule_errors: self.rule_errors.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of control plane statistics
#[derive(Debug, Clone, Default)]
pub struct ControlPlaneStatsSnapshot {
    pub tcp_connections: u64,
    pub udp_sessions: u64,
    pub chain_packets: u64,
    pub blocked_connections: u64,
    pub domain_resolved_sni: u64,
    pub domain_resolved_fakedns: u64,
    pub domain_resolved_cache: u64,
    pub outbound_failures: u64,
    pub rule_errors: u64,
}

// =============================================================================
// Configuration
// =============================================================================

/// Configuration for the control plane handler
#[derive(Debug, Clone)]
pub struct ControlPlaneConfig {
    /// Default outbound tag when no rules match
    pub default_outbound: String,
    /// Timeout for outbound connections
    pub connect_timeout: Duration,
    /// Maximum domain length (RFC 1035 allows 253)
    pub max_domain_length: usize,
}

impl Default for ControlPlaneConfig {
    fn default() -> Self {
        Self {
            default_outbound: "direct".to_string(),
            connect_timeout: Duration::from_secs(10),
            max_domain_length: 253,
        }
    }
}

// =============================================================================
// Control Plane Handler
// =============================================================================

/// Control Plane Handler implementing `netbridge::ConnectionHandler`
///
/// This handler bridges the data plane with control components to make
/// routing decisions for incoming connections.
///
/// # Thread Safety
///
/// `ControlPlaneHandler` is `Send + Sync` and can be safely shared across tasks.
/// All internal state uses atomic operations or lock-free data structures.
///
/// # Example
///
/// ```ignore
/// use rust_router::controlplane::ControlPlaneHandler;
/// use rust_router::netbridge::ConnectionHandler;
///
/// let handler = ControlPlaneHandler::new(
///     rule_engine,
///     outbound_manager,
///     "direct".to_string(),
/// );
///
/// // Use with netbridge DataPlane
/// let dp = DataPlaneBuilder::new()
///     .with_handler(Arc::new(handler))
///     .build()
///     .await?;
/// ```
pub struct ControlPlaneHandler {
    // Core components
    rule_engine: Arc<RuleEngine>,
    chain_handler: ChainHandler,
    outbound_manager: Arc<OutboundManager>,

    // Optional components
    #[cfg(feature = "fakedns")]
    fakedns: Option<Arc<FakeDnsManager>>,
    dns_cache: Option<Arc<IpDomainCache>>,

    // Configuration
    config: ControlPlaneConfig,

    // Statistics
    stats: ControlPlaneStats,
}

impl ControlPlaneHandler {
    /// Create a new control plane handler with minimal configuration
    ///
    /// # Arguments
    ///
    /// * `rule_engine` - Rule engine for connection matching
    /// * `outbound_manager` - Manager for outbound connections
    /// * `default_outbound` - Default outbound tag when no rules match
    #[must_use]
    pub fn new(
        rule_engine: Arc<RuleEngine>,
        outbound_manager: Arc<OutboundManager>,
        default_outbound: String,
    ) -> Self {
        Self {
            rule_engine,
            chain_handler: ChainHandler::new(),
            outbound_manager,
            #[cfg(feature = "fakedns")]
            fakedns: None,
            dns_cache: None,
            config: ControlPlaneConfig {
                default_outbound,
                ..Default::default()
            },
            stats: ControlPlaneStats::new(),
        }
    }

    /// Create with full configuration
    #[must_use]
    pub fn with_config(
        rule_engine: Arc<RuleEngine>,
        outbound_manager: Arc<OutboundManager>,
        config: ControlPlaneConfig,
    ) -> Self {
        Self {
            rule_engine,
            chain_handler: ChainHandler::new(),
            outbound_manager,
            #[cfg(feature = "fakedns")]
            fakedns: None,
            dns_cache: None,
            config,
            stats: ControlPlaneStats::new(),
        }
    }

    /// Set the chain manager for DSCP-based chain routing
    pub fn set_chain_manager(&mut self, chain_manager: Arc<ChainManager>) {
        self.chain_handler.set_chain_manager(chain_manager);
    }

    /// Set the FakeDNS manager for reverse IP lookups
    #[cfg(feature = "fakedns")]
    pub fn set_fakedns(&mut self, fakedns: Arc<FakeDnsManager>) {
        self.fakedns = Some(fakedns);
    }

    /// Set the DNS cache for IP-to-domain lookups
    pub fn set_dns_cache(&mut self, dns_cache: Arc<IpDomainCache>) {
        self.dns_cache = Some(dns_cache);
    }

    /// Get the rule engine
    #[must_use]
    pub fn rule_engine(&self) -> &Arc<RuleEngine> {
        &self.rule_engine
    }

    /// Get the outbound manager
    #[must_use]
    pub fn outbound_manager(&self) -> &Arc<OutboundManager> {
        &self.outbound_manager
    }

    /// Get the chain handler
    #[must_use]
    pub fn chain_handler(&self) -> &ChainHandler {
        &self.chain_handler
    }

    /// Get the configuration
    #[must_use]
    pub fn config(&self) -> &ControlPlaneConfig {
        &self.config
    }

    /// Get the statistics
    #[must_use]
    pub fn stats(&self) -> &ControlPlaneStats {
        &self.stats
    }

    // =========================================================================
    // Domain Validation
    // =========================================================================

    /// Validate a domain name
    ///
    /// Checks that the domain:
    /// - Is not longer than the configured maximum (default 253)
    /// - Does not contain null bytes
    ///
    /// # Errors
    ///
    /// Returns `ControlPlaneError::InvalidDomain` if validation fails.
    fn validate_domain(&self, domain: &str) -> Result<(), ControlPlaneError> {
        if domain.len() > self.config.max_domain_length {
            return Err(ControlPlaneError::InvalidDomain(format!(
                "domain too long: {} > {}",
                domain.len(),
                self.config.max_domain_length
            )));
        }
        if domain.contains('\0') {
            return Err(ControlPlaneError::InvalidDomain(
                "domain contains null byte".to_string(),
            ));
        }
        Ok(())
    }

    // =========================================================================
    // Domain Resolution
    // =========================================================================

    /// Resolve domain from multiple sources
    ///
    /// Tries sources in priority order:
    /// 1. SNI from netbridge (already extracted)
    /// 2. `FakeDNS` reverse lookup
    /// 3. DNS cache lookup
    ///
    /// Returns the domain and its source for logging/stats.
    fn resolve_domain(&self, info: &NetbridgeConnectionInfo) -> (Option<String>, DomainSource) {
        // 1. SNI from netbridge (highest priority)
        if let Some(ref domain) = info.domain {
            return (Some(domain.clone()), DomainSource::Sni);
        }

        // 2. FakeDNS reverse lookup
        #[cfg(feature = "fakedns")]
        if let Some(ref fakedns) = self.fakedns {
            if fakedns.is_fake_ip(info.dst.ip()) {
                if let Some(domain) = fakedns.map_ip_domain(info.dst.ip()) {
                    return (Some(domain), DomainSource::FakeDns);
                }
            }
        }

        // 3. DNS cache lookup
        if let Some(ref cache) = self.dns_cache {
            if let Some(domain) = cache.get(&info.dst.ip()) {
                return (Some(domain), DomainSource::DnsCache);
            }
        }

        (None, DomainSource::None)
    }

    // =========================================================================
    // Context Building
    // =========================================================================

    /// Build routing context from netbridge connection info
    ///
    /// Resolves domain and converts to `rules::ConnectionInfo` for matching.
    fn build_context(
        &self,
        info: NetbridgeConnectionInfo,
    ) -> Result<RoutingContext, ControlPlaneError> {
        let (domain, domain_source) = self.resolve_domain(&info);

        // Validate domain if present
        if let Some(ref d) = domain {
            self.validate_domain(d)?;
        }

        // Update stats based on domain source
        match domain_source {
            DomainSource::Sni => {
                self.stats.domain_resolved_sni.fetch_add(1, Ordering::Relaxed);
            }
            DomainSource::FakeDns => {
                self.stats
                    .domain_resolved_fakedns
                    .fetch_add(1, Ordering::Relaxed);
            }
            DomainSource::DnsCache => {
                self.stats
                    .domain_resolved_cache
                    .fetch_add(1, Ordering::Relaxed);
            }
            DomainSource::None => {}
        }

        // Convert IpProtocol to protocol string
        let protocol = match info.protocol {
            IpProtocol::Tcp => "tcp",
            IpProtocol::Udp => "udp",
            _ => "other",
        };

        // Build rules::ConnectionInfo
        let rules_info = RulesConnectionInfo {
            domain,
            dest_ip: Some(info.dst.ip()),
            dest_port: info.dst.port(),
            source_ip: Some(info.src.ip()),
            protocol,
            sniffed_protocol: None,
        };

        Ok(RoutingContext {
            netbridge_info: info,
            rules_info,
            domain_source,
        })
    }

    // =========================================================================
    // Outbound Connection
    // =========================================================================

    /// Connect to an outbound by tag
    ///
    /// Looks up the outbound in the manager and establishes a connection.
    /// Falls back to the default outbound if the specified tag is not found.
    async fn connect_outbound(
        &self,
        tag: &str,
        dest: std::net::SocketAddr,
        _domain: Option<&str>,
    ) -> Result<OutboundConnection, ControlPlaneError> {
        // Get outbound from manager
        let outbound = self
            .outbound_manager
            .get(tag)
            .or_else(|| self.outbound_manager.get(&self.config.default_outbound))
            .ok_or_else(|| ControlPlaneError::OutboundNotFound(tag.to_string()))?;

        // Connect with timeout
        let connect_fut = outbound.connect(dest, self.config.connect_timeout);
        match tokio::time::timeout(self.config.connect_timeout, connect_fut).await {
            Ok(Ok(conn)) => Ok(conn),
            Ok(Err(e)) => {
                self.stats.outbound_failures.fetch_add(1, Ordering::Relaxed);
                Err(ControlPlaneError::outbound_connect(e))
            }
            Err(_) => {
                self.stats.outbound_failures.fetch_add(1, Ordering::Relaxed);
                Err(ControlPlaneError::Timeout)
            }
        }
    }

    /// Connect to a UDP outbound by tag
    ///
    /// Looks up the outbound in the manager and establishes a UDP connection.
    /// Falls back to the default outbound if the specified tag is not found.
    /// Returns an error if the outbound does not support UDP.
    async fn connect_udp_outbound(
        &self,
        tag: &str,
        dest: std::net::SocketAddr,
    ) -> Result<UdpOutboundHandle, UdpError> {
        // Get outbound from manager
        let outbound = self
            .outbound_manager
            .get(tag)
            .or_else(|| self.outbound_manager.get(&self.config.default_outbound))
            .ok_or_else(|| UdpError::OutboundNotFound {
                tag: tag.to_string(),
            })?;

        // Check if outbound supports UDP
        if !outbound.supports_udp() {
            return Err(UdpError::UdpNotSupported {
                tag: outbound.tag().to_string(),
            });
        }

        // Connect with timeout
        let connect_fut = outbound.connect_udp(dest, self.config.connect_timeout);
        match tokio::time::timeout(self.config.connect_timeout, connect_fut).await {
            Ok(result) => result,
            Err(_) => {
                self.stats.outbound_failures.fetch_add(1, Ordering::Relaxed);
                Err(UdpError::IoError(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "UDP connect timeout",
                )))
            }
        }
    }

    // =========================================================================
    // TCP Routing
    // =========================================================================

    /// Route a TCP connection
    ///
    /// Matches rules, handles chain routing, and establishes outbound connection.
    async fn route_tcp(&self, ctx: RoutingContext) -> NetbridgeRoutingDecision {
        self.stats.tcp_connections.fetch_add(1, Ordering::Relaxed);

        // 1. Match rules
        let match_result = self.rule_engine.match_connection(&ctx.rules_info);

        debug!(
            session_id = %ctx.netbridge_info.session_id,
            dst = %ctx.netbridge_info.dst,
            domain = ?ctx.rules_info.domain,
            domain_source = %ctx.domain_source,
            outbound = %match_result.outbound,
            matched = ?match_result.matched_rule,
            "TCP routing decision"
        );

        // 2. Check if this is a chain entry
        if let Some(routing_mark) = match_result.routing_mark {
            if let Some(chain_mark) = ChainMark::from_routing_mark(routing_mark) {
                let chain_result = self
                    .chain_handler
                    .handle_chain_entry(&match_result.outbound, chain_mark);

                match chain_result {
                    ChainRoutingResult::Forward { outbound, .. } => {
                        self.stats.chain_packets.fetch_add(1, Ordering::Relaxed);
                        // Connect to chain peer tunnel
                        match self
                            .connect_outbound(
                                &outbound,
                                ctx.netbridge_info.dst,
                                ctx.rules_info.domain.as_deref(),
                            )
                            .await
                        {
                            Ok(conn) => {
                                return NetbridgeRoutingDecision::Accept(Box::new(
                                    conn.into_outbound_stream(),
                                ));
                            }
                            Err(e) => {
                                warn!(error = %e, outbound = %outbound, "Chain outbound connect failed");
                                return NetbridgeRoutingDecision::RejectWithError(e.to_string());
                            }
                        }
                    }
                    ChainRoutingResult::Block { reason } => {
                        self.stats
                            .blocked_connections
                            .fetch_add(1, Ordering::Relaxed);
                        warn!(reason = %reason, "Chain entry blocked");
                        return NetbridgeRoutingDecision::RejectWithError(reason);
                    }
                    ChainRoutingResult::Terminal { outbound } => {
                        // Terminal node: route to exit egress
                        debug!(outbound = %outbound, "Terminal chain node, routing to exit egress");
                        // Fall through to normal outbound handling with the exit egress
                        return self
                            .connect_and_return(
                                &outbound,
                                ctx.netbridge_info.dst,
                                ctx.rules_info.domain.as_deref(),
                            )
                            .await;
                    }
                    ChainRoutingResult::NotChain => {
                        // Not a chain packet, continue with normal routing
                    }
                }
            }
        }

        // 3. Handle block outbound
        if match_result.outbound == "block" || match_result.outbound == "adblock" {
            self.stats
                .blocked_connections
                .fetch_add(1, Ordering::Relaxed);
            return NetbridgeRoutingDecision::Reject;
        }

        // 4. Connect to outbound
        self.connect_and_return(
            &match_result.outbound,
            ctx.netbridge_info.dst,
            ctx.rules_info.domain.as_deref(),
        )
        .await
    }

    /// Helper to connect to outbound and return routing decision
    async fn connect_and_return(
        &self,
        outbound: &str,
        dest: std::net::SocketAddr,
        domain: Option<&str>,
    ) -> NetbridgeRoutingDecision {
        match self.connect_outbound(outbound, dest, domain).await {
            Ok(conn) => NetbridgeRoutingDecision::Accept(Box::new(conn.into_outbound_stream())),
            Err(e) => {
                warn!(error = %e, outbound = %outbound, "Outbound connect failed");
                NetbridgeRoutingDecision::RejectWithError(e.to_string())
            }
        }
    }

    // =========================================================================
    // UDP Routing
    // =========================================================================

    /// Route a UDP session
    ///
    /// Matches rules, handles block/chain decisions, and establishes
    /// UDP outbound connection via `UdpOutboundHandle`.
    async fn route_udp(&self, ctx: RoutingContext) -> NetbridgeRoutingDecision {
        self.stats.udp_sessions.fetch_add(1, Ordering::Relaxed);

        // Match rules (same as TCP)
        let match_result = self.rule_engine.match_connection(&ctx.rules_info);

        debug!(
            session_id = %ctx.netbridge_info.session_id,
            dst = %ctx.netbridge_info.dst,
            domain = ?ctx.rules_info.domain,
            domain_source = %ctx.domain_source,
            outbound = %match_result.outbound,
            matched = ?match_result.matched_rule,
            "UDP routing decision"
        );

        // Handle block outbound
        if match_result.outbound == "block" || match_result.outbound == "adblock" {
            self.stats
                .blocked_connections
                .fetch_add(1, Ordering::Relaxed);
            return NetbridgeRoutingDecision::Reject;
        }

        // Check if this is a chain entry - UDP does not support chain routing
        if let Some(routing_mark) = match_result.routing_mark {
            if ChainMark::from_routing_mark(routing_mark).is_some() {
                warn!(
                    session_id = %ctx.netbridge_info.session_id,
                    dst = %ctx.netbridge_info.dst,
                    "UDP chain routing not supported"
                );
                return NetbridgeRoutingDecision::RejectWithError(
                    "UDP chain routing not supported".to_string(),
                );
            }
        }

        // Connect to UDP outbound
        match self
            .connect_udp_outbound(&match_result.outbound, ctx.netbridge_info.dst)
            .await
        {
            Ok(outbound_handle) => {
                // Spawn forwarder and return handle for netbridge
                let session_id = ctx.netbridge_info.session_id;
                let handle = spawn_udp_forwarder(outbound_handle, session_id);
                NetbridgeRoutingDecision::AcceptUdp(handle)
            }
            Err(e) => {
                self.stats.outbound_failures.fetch_add(1, Ordering::Relaxed);
                warn!(
                    error = %e,
                    outbound = %match_result.outbound,
                    "UDP outbound connect failed"
                );
                NetbridgeRoutingDecision::RejectWithError(e.to_string())
            }
        }
    }
}

// =============================================================================
// UDP Forwarder
// =============================================================================

/// Default UDP channel capacity
const UDP_CHANNEL_CAPACITY: usize = 64;

/// Spawn a UDP forwarder task that bridges `UdpOutboundHandle` to netbridge `UdpHandle`
///
/// Creates a channel pair for bidirectional UDP forwarding:
/// - Packets from netbridge (client) are sent to the outbound
/// - Replies from the outbound are forwarded back to netbridge
///
/// The spawned task runs until either channel is closed or an error occurs.
fn spawn_udp_forwarder(
    outbound_handle: UdpOutboundHandle,
    session_id: crate::netbridge::types::SessionId,
) -> UdpHandle {
    let (handle, remote) = UdpHandle::new(UDP_CHANNEL_CAPACITY);

    tokio::spawn(udp_forwarder_task(outbound_handle, remote, session_id));

    handle
}

/// UDP forwarder task that performs bidirectional forwarding
async fn udp_forwarder_task(
    outbound_handle: UdpOutboundHandle,
    mut remote: UdpHandleRemote,
    session_id: crate::netbridge::types::SessionId,
) {
    // Buffer for receiving replies from outbound
    let mut recv_buf = vec![0u8; 65536];

    debug!(
        session_id = %session_id,
        dest = %outbound_handle.dest_addr(),
        "UDP forwarder started"
    );

    loop {
        tokio::select! {
            // Prioritize sending (client -> outbound) using biased
            biased;

            // Forward packets from netbridge to outbound
            Some(data) = remote.rx.recv() => {
                match outbound_handle.send(&data).await {
                    Ok(n) => {
                        trace!(
                            session_id = %session_id,
                            bytes = n,
                            "UDP packet sent to outbound"
                        );
                    }
                    Err(e) => {
                        error!(
                            session_id = %session_id,
                            error = %e,
                            "UDP send to outbound failed"
                        );
                        // Exit on send error
                        break;
                    }
                }
            }

            // Receive replies from outbound and forward to netbridge
            result = outbound_handle.recv(&mut recv_buf) => {
                match result {
                    Ok(n) if n > 0 => {
                        let packet = Bytes::copy_from_slice(&recv_buf[..n]);
                        if remote.tx.send(packet).await.is_err() {
                            // Netbridge side closed, exit gracefully
                            debug!(
                                session_id = %session_id,
                                "UDP forwarder: netbridge channel closed"
                            );
                            break;
                        }
                        trace!(
                            session_id = %session_id,
                            bytes = n,
                            "UDP reply received from outbound"
                        );
                    }
                    Ok(_) => {
                        // Zero-length receive, continue
                    }
                    Err(e) => {
                        // Check if it's a non-fatal error
                        if e.is_recoverable() {
                            trace!(
                                session_id = %session_id,
                                error = %e,
                                "UDP recv recoverable error, continuing"
                            );
                            continue;
                        }
                        error!(
                            session_id = %session_id,
                            error = %e,
                            "UDP recv from outbound failed"
                        );
                        break;
                    }
                }
            }

            // Handle channel closure
            else => {
                debug!(
                    session_id = %session_id,
                    "UDP forwarder: channels closed"
                );
                break;
            }
        }
    }

    debug!(
        session_id = %session_id,
        "UDP forwarder exited"
    );
}

// =============================================================================
// ConnectionHandler Implementation
// =============================================================================

impl ConnectionHandler for ControlPlaneHandler {
    fn on_tcp_connect(
        &self,
        info: NetbridgeConnectionInfo,
    ) -> Pin<Box<dyn Future<Output = NetbridgeRoutingDecision> + Send + '_>> {
        Box::pin(async move {
            match self.build_context(info) {
                Ok(ctx) => self.route_tcp(ctx).await,
                Err(e) => {
                    warn!(error = %e, "Failed to build routing context");
                    self.stats.rule_errors.fetch_add(1, Ordering::Relaxed);
                    NetbridgeRoutingDecision::RejectWithError(e.to_string())
                }
            }
        })
    }

    fn on_udp_session(
        &self,
        info: NetbridgeConnectionInfo,
    ) -> Pin<Box<dyn Future<Output = NetbridgeRoutingDecision> + Send + '_>> {
        Box::pin(async move {
            match self.build_context(info) {
                Ok(ctx) => self.route_udp(ctx).await,
                Err(e) => {
                    warn!(error = %e, "Failed to build routing context for UDP");
                    self.stats.rule_errors.fetch_add(1, Ordering::Relaxed);
                    NetbridgeRoutingDecision::RejectWithError(e.to_string())
                }
            }
        })
    }

    fn on_session_closed(
        &self,
        session_id: crate::netbridge::types::SessionId,
        bytes_sent: u64,
        bytes_received: u64,
        duration: Duration,
    ) {
        trace!(
            session_id = %session_id,
            bytes_sent = bytes_sent,
            bytes_received = bytes_received,
            duration_ms = duration.as_millis(),
            "Session closed"
        );
    }

    fn on_domain_resolved(&self, session_id: crate::netbridge::types::SessionId, domain: &str) {
        debug!(
            session_id = %session_id,
            domain = %domain,
            "Domain resolved post-connect"
        );
    }
}

// =============================================================================
// Debug Implementation
// =============================================================================

impl std::fmt::Debug for ControlPlaneHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControlPlaneHandler")
            .field("default_outbound", &self.config.default_outbound)
            .field("connect_timeout", &self.config.connect_timeout)
            .field("has_chain_manager", &self.chain_handler.has_chain_manager())
            .field("has_dns_cache", &self.dns_cache.is_some())
            .finish()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netbridge::types::{FiveTuple, SessionId};
    use crate::outbound::DirectOutbound;
    use crate::rules::engine::RoutingSnapshotBuilder;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn create_test_rule_engine() -> Arc<RuleEngine> {
        let snapshot = RoutingSnapshotBuilder::new()
            .default_outbound("direct")
            .version(1)
            .build()
            .unwrap();
        Arc::new(RuleEngine::new(snapshot))
    }

    fn create_test_outbound_manager() -> Arc<OutboundManager> {
        let manager = OutboundManager::new();
        manager.add(Box::new(DirectOutbound::simple("direct")));
        Arc::new(manager)
    }

    fn create_test_connection_info() -> NetbridgeConnectionInfo {
        let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 25, 0, 2)), 12345);
        let dst = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 443);

        NetbridgeConnectionInfo {
            session_id: SessionId::new(1),
            src,
            dst,
            protocol: IpProtocol::Tcp,
            peer_key: [0u8; 32],
            peer_endpoint: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 51820),
            domain: None,
            five_tuple: FiveTuple::tcp(src, dst),
        }
    }

    // =========================================================================
    // Domain Validation Tests
    // =========================================================================

    #[test]
    fn test_validate_domain_valid() {
        let handler = ControlPlaneHandler::new(
            create_test_rule_engine(),
            create_test_outbound_manager(),
            "direct".to_string(),
        );

        assert!(handler.validate_domain("example.com").is_ok());
        assert!(handler.validate_domain("www.example.com").is_ok());
        assert!(handler
            .validate_domain("sub.domain.example.com")
            .is_ok());
    }

    #[test]
    fn test_validate_domain_too_long() {
        let handler = ControlPlaneHandler::new(
            create_test_rule_engine(),
            create_test_outbound_manager(),
            "direct".to_string(),
        );

        // Create a domain longer than 253 characters
        let long_domain = "a".repeat(300);
        let result = handler.validate_domain(&long_domain);
        assert!(result.is_err());
        if let Err(ControlPlaneError::InvalidDomain(msg)) = result {
            assert!(msg.contains("too long"));
        } else {
            panic!("Expected InvalidDomain error");
        }
    }

    #[test]
    fn test_validate_domain_null_byte() {
        let handler = ControlPlaneHandler::new(
            create_test_rule_engine(),
            create_test_outbound_manager(),
            "direct".to_string(),
        );

        let result = handler.validate_domain("example\0.com");
        assert!(result.is_err());
        if let Err(ControlPlaneError::InvalidDomain(msg)) = result {
            assert!(msg.contains("null byte"));
        } else {
            panic!("Expected InvalidDomain error");
        }
    }

    // =========================================================================
    // Domain Resolution Tests
    // =========================================================================

    #[test]
    fn test_resolve_domain_sni_priority() {
        let handler = ControlPlaneHandler::new(
            create_test_rule_engine(),
            create_test_outbound_manager(),
            "direct".to_string(),
        );

        let mut info = create_test_connection_info();
        info.domain = Some("sni-domain.com".to_string());

        let (domain, source) = handler.resolve_domain(&info);
        assert_eq!(domain, Some("sni-domain.com".to_string()));
        assert_eq!(source, DomainSource::Sni);
    }

    #[test]
    fn test_resolve_domain_no_domain() {
        let handler = ControlPlaneHandler::new(
            create_test_rule_engine(),
            create_test_outbound_manager(),
            "direct".to_string(),
        );

        let info = create_test_connection_info();
        let (domain, source) = handler.resolve_domain(&info);
        assert!(domain.is_none());
        assert_eq!(source, DomainSource::None);
    }

    // =========================================================================
    // Context Building Tests
    // =========================================================================

    #[test]
    fn test_build_context_success() {
        let handler = ControlPlaneHandler::new(
            create_test_rule_engine(),
            create_test_outbound_manager(),
            "direct".to_string(),
        );

        let mut info = create_test_connection_info();
        info.domain = Some("example.com".to_string());

        let ctx = handler.build_context(info).unwrap();
        assert_eq!(ctx.rules_info.domain, Some("example.com".to_string()));
        assert_eq!(ctx.rules_info.protocol, "tcp");
        assert_eq!(ctx.rules_info.dest_port, 443);
        assert_eq!(ctx.domain_source, DomainSource::Sni);
    }

    #[test]
    fn test_build_context_invalid_domain() {
        let handler = ControlPlaneHandler::new(
            create_test_rule_engine(),
            create_test_outbound_manager(),
            "direct".to_string(),
        );

        let mut info = create_test_connection_info();
        info.domain = Some("example\0.com".to_string());

        let result = handler.build_context(info);
        assert!(result.is_err());
    }

    // =========================================================================
    // Statistics Tests
    // =========================================================================

    #[test]
    fn test_stats_atomic_updates() {
        let stats = ControlPlaneStats::new();

        stats.tcp_connections.fetch_add(5, Ordering::Relaxed);
        stats.udp_sessions.fetch_add(3, Ordering::Relaxed);
        stats.blocked_connections.fetch_add(1, Ordering::Relaxed);

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.tcp_connections, 5);
        assert_eq!(snapshot.udp_sessions, 3);
        assert_eq!(snapshot.blocked_connections, 1);
    }

    #[test]
    fn test_stats_snapshot() {
        let handler = ControlPlaneHandler::new(
            create_test_rule_engine(),
            create_test_outbound_manager(),
            "direct".to_string(),
        );

        // Initial stats should be zero
        let snapshot = handler.stats().snapshot();
        assert_eq!(snapshot.tcp_connections, 0);
        assert_eq!(snapshot.udp_sessions, 0);
    }

    // =========================================================================
    // Configuration Tests
    // =========================================================================

    #[test]
    fn test_config_default() {
        let config = ControlPlaneConfig::default();
        assert_eq!(config.default_outbound, "direct");
        assert_eq!(config.connect_timeout, Duration::from_secs(10));
        assert_eq!(config.max_domain_length, 253);
    }

    #[test]
    fn test_handler_with_config() {
        let config = ControlPlaneConfig {
            default_outbound: "proxy".to_string(),
            connect_timeout: Duration::from_secs(30),
            max_domain_length: 200,
        };

        let handler = ControlPlaneHandler::with_config(
            create_test_rule_engine(),
            create_test_outbound_manager(),
            config.clone(),
        );

        assert_eq!(handler.config().default_outbound, "proxy");
        assert_eq!(handler.config().connect_timeout, Duration::from_secs(30));
    }

    // =========================================================================
    // Domain Source Display Tests
    // =========================================================================

    #[test]
    fn test_domain_source_display() {
        assert_eq!(DomainSource::Sni.to_string(), "sni");
        assert_eq!(DomainSource::FakeDns.to_string(), "fakedns");
        assert_eq!(DomainSource::DnsCache.to_string(), "dns-cache");
        assert_eq!(DomainSource::None.to_string(), "none");
    }

    // =========================================================================
    // Handler Debug Tests
    // =========================================================================

    #[test]
    fn test_handler_debug() {
        let handler = ControlPlaneHandler::new(
            create_test_rule_engine(),
            create_test_outbound_manager(),
            "direct".to_string(),
        );

        let debug_str = format!("{:?}", handler);
        assert!(debug_str.contains("ControlPlaneHandler"));
        assert!(debug_str.contains("default_outbound"));
    }

    // =========================================================================
    // Handler Accessor Tests
    // =========================================================================

    #[test]
    fn test_handler_accessors() {
        let handler = ControlPlaneHandler::new(
            create_test_rule_engine(),
            create_test_outbound_manager(),
            "direct".to_string(),
        );

        assert!(handler.rule_engine().version() >= 0);
        assert!(!handler.outbound_manager().is_empty());
        assert!(!handler.chain_handler().has_chain_manager());
    }

    // =========================================================================
    // UDP Routing Tests
    // =========================================================================

    fn create_test_udp_connection_info() -> NetbridgeConnectionInfo {
        let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 25, 0, 2)), 12345);
        let dst = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53);

        NetbridgeConnectionInfo {
            session_id: SessionId::new(2),
            src,
            dst,
            protocol: IpProtocol::Udp,
            peer_key: [0u8; 32],
            peer_endpoint: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 51820),
            domain: None,
            five_tuple: FiveTuple::udp(src, dst),
        }
    }

    fn create_block_rule_engine() -> Arc<RuleEngine> {
        // Create a port rule that routes port 53 (DNS) to "block"
        let mut builder = RoutingSnapshotBuilder::new();
        builder.add_port_rule("53", "block").unwrap();

        let snapshot = builder
            .default_outbound("direct")
            .version(1)
            .build()
            .unwrap();
        Arc::new(RuleEngine::new(snapshot))
    }

    fn create_block_outbound_manager() -> Arc<OutboundManager> {
        use crate::outbound::BlockOutbound;

        let manager = OutboundManager::new();
        manager.add(Box::new(DirectOutbound::simple("direct")));
        manager.add(Box::new(BlockOutbound::new("block")));
        Arc::new(manager)
    }

    #[tokio::test]
    async fn test_route_udp_block_outbound() {
        // Create a rule engine that routes port 53 to "block"
        let rule_engine = create_block_rule_engine();
        let outbound_manager = create_block_outbound_manager();

        let handler = ControlPlaneHandler::new(
            rule_engine,
            outbound_manager,
            "direct".to_string(),
        );

        // Create a UDP connection info for port 53 (DNS)
        let info = create_test_udp_connection_info();
        let decision = handler.on_udp_session(info).await;

        // Should be rejected due to block outbound
        assert!(
            matches!(decision, NetbridgeRoutingDecision::Reject),
            "Expected Reject, got {:?}",
            decision
        );
    }

    #[tokio::test]
    async fn test_route_udp_stats_updated() {
        let handler = ControlPlaneHandler::new(
            create_test_rule_engine(),
            create_test_outbound_manager(),
            "direct".to_string(),
        );

        // Initial stats should be zero
        let initial_snapshot = handler.stats().snapshot();
        assert_eq!(initial_snapshot.udp_sessions, 0);

        // Create a UDP connection info
        let info = create_test_udp_connection_info();
        let _ = handler.on_udp_session(info).await;

        // UDP sessions counter should be incremented
        let snapshot = handler.stats().snapshot();
        assert_eq!(
            snapshot.udp_sessions, 1,
            "Expected udp_sessions to be 1, got {}",
            snapshot.udp_sessions
        );
    }

    #[test]
    fn test_udp_channel_capacity_constant() {
        // Verify the UDP channel capacity constant is reasonable
        assert!(
            UDP_CHANNEL_CAPACITY >= 32,
            "UDP_CHANNEL_CAPACITY should be at least 32"
        );
        assert!(
            UDP_CHANNEL_CAPACITY <= 256,
            "UDP_CHANNEL_CAPACITY should be at most 256"
        );
    }
}
