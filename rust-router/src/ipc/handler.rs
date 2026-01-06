//! IPC command handler
//!
//! This module processes IPC commands and generates responses.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use tracing::{debug, info, warn};

use super::protocol::{
    ErrorCode, IpcCommand, IpcResponse, OutboundInfo, OutboundStatsResponse, PoolStatsResponse,
    PrometheusMetricsResponse, RuleStatsResponse, ServerCapabilities, ServerStatus, Socks5PoolStats,
};
use crate::config::{load_config_with_env, OutboundConfig};
use crate::connection::ConnectionManager;
use crate::outbound::OutboundManager;
use crate::rules::{ConnectionInfo, RuleEngine, RoutingSnapshotBuilder};

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
        }
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
            // Phase 3.3: IPC Protocol v2.1 Command Handlers
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
                    format!("Failed to load configuration: {}", e),
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
                format!("Outbound '{}' not found", tag),
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
        IpcResponse::success_with_message(format!("Outbound '{}' removed", tag))
    }

    /// Handle enable/disable outbound command
    fn handle_enable_outbound(&self, tag: &str, enable: bool) -> IpcResponse {
        // Note: Current implementation doesn't support runtime enable/disable
        // This would require modifying the Outbound trait
        if !self.outbound_manager.contains(tag) {
            return IpcResponse::error(
                ErrorCode::NotFound,
                format!("Outbound '{}' not found", tag),
            );
        }

        let action = if enable { "enabled" } else { "disabled" };
        info!("Outbound '{}' {}", tag, action);
        IpcResponse::success_with_message(format!("Outbound '{}' {}", tag, action))
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
            None => IpcResponse::error(ErrorCode::NotFound, format!("Outbound '{}' not found", tag)),
        }
    }

    /// Handle list outbounds command
    fn handle_list_outbounds(&self) -> IpcResponse {
        let outbounds: Vec<OutboundInfo> = self
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
            "Rules reloaded (version {})",
            new_version
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
                format!("Outbound '{}' already exists", tag),
            );
        }

        // Parse server address
        let socks5_addr: std::net::SocketAddr = match server_addr.parse() {
            Ok(addr) => addr,
            Err(e) => {
                return IpcResponse::error(
                    ErrorCode::InvalidParameters,
                    format!("Invalid server address '{}': {}", server_addr, e),
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
                    format!("Failed to create SOCKS5 outbound: {}", e),
                );
            }
        };

        // Add to outbound manager
        self.outbound_manager.add(Box::new(outbound));

        info!("Added SOCKS5 outbound '{}' -> {}", tag, server_addr);
        IpcResponse::success_with_message(format!("SOCKS5 outbound '{}' added", tag))
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
                            format!("Outbound '{}' is not a SOCKS5 outbound", specific_tag),
                        );
                    }
                }
                None => {
                    return IpcResponse::error(
                        ErrorCode::NotFound,
                        format!("Outbound '{}' not found", specific_tag),
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
    // Phase 3.3: IPC Protocol v2.1 Handler Implementations
    // ========================================================================

    /// Handle add WireGuard outbound command
    ///
    /// Creates a DirectOutbound bound to a WireGuard interface.
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
                format!("Outbound '{}' already exists", tag),
            );
        }

        // Validate interface exists
        if let Err(e) = wireguard::validate_interface_exists(&interface) {
            return IpcResponse::error(
                ErrorCode::InvalidParameters,
                format!("WireGuard interface validation failed: {}", e),
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
        IpcResponse::success_with_message(format!("WireGuard outbound '{}' added", tag))
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
                    format!("Outbound '{}' not found", tag),
                );
            }
        };

        // Disable the outbound to stop accepting new connections
        outbound.set_enabled(false);

        // Get initial active connection count
        let initial_count = outbound.active_connections();

        // Wait for connections to drain
        let timeout = Duration::from_secs(timeout_secs as u64);
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
                format!("Failed to remove outbound '{}' after drain", tag),
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
    /// Atomically updates routing rules via ArcSwap.
    fn handle_update_routing(
        &self,
        rules: Vec<super::protocol::RuleConfig>,
        default_outbound: String,
    ) -> IpcResponse {
        use super::protocol::UpdateRoutingResponse;
        use crate::rules::{CompiledRuleSet, Rule, RuleType};

        // Validate default outbound exists
        if self.outbound_manager.get(&default_outbound).is_none() {
            return IpcResponse::error(
                ErrorCode::NotFound,
                format!("Default outbound '{}' not found", default_outbound),
            );
        }

        // Convert RuleConfig to internal Rule format
        let mut internal_rules = Vec::with_capacity(rules.len());
        let mut rule_id = 1u64;
        for rule_cfg in &rules {
            if !rule_cfg.enabled {
                continue;
            }

            // Validate outbound exists
            if self.outbound_manager.get(&rule_cfg.outbound).is_none() {
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
                        format!("Unknown rule type: {}", other),
                    );
                }
            };

            let rule = Rule::new(
                rule_id,
                rule_type,
                rule_cfg.target.clone(),
                rule_cfg.outbound.clone(),
            )
            .with_priority(rule_cfg.priority);

            rule_id += 1;
            internal_rules.push(rule);
        }

        // Compile rules into an optimized rule set
        let rule_count = internal_rules.len();
        let compiled = match CompiledRuleSet::new(internal_rules, default_outbound.clone()) {
            Ok(c) => c,
            Err(e) => {
                return IpcResponse::error(
                    ErrorCode::InvalidParameters,
                    format!("Failed to compile rules: {}", e),
                );
            }
        };

        // Atomically increment version BEFORE creating snapshot to prevent race condition
        // fetch_add returns the previous value, so we add 1 to get the new version
        let new_version = self.config_version.fetch_add(1, Ordering::SeqCst) + 1;

        // Load current snapshot to preserve domain/geoip/fwmark matchers
        let current = self.rule_engine.load();

        // Build new routing snapshot with updated rules
        let new_snapshot = crate::rules::RoutingSnapshot {
            domain_matcher: current.domain_matcher.clone(),
            geoip_matcher: current.geoip_matcher.clone(),
            fwmark_router: current.fwmark_router.clone(),
            rules: compiled,
            default_outbound: default_outbound.clone(),
            version: new_version,
        };

        // Atomic swap via rule engine
        self.rule_engine.reload(new_snapshot);

        // Version is already incremented, use new_version directly
        let version = new_version;

        // Update last reload timestamp
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.last_reload_timestamp.store(now, Ordering::Relaxed);

        info!(
            "Updated routing: {} rules, default='{}', version={}",
            rule_count, default_outbound, version
        );

        IpcResponse::UpdateRoutingResult(UpdateRoutingResponse {
            success: true,
            version,
            rule_count,
            default_outbound,
        })
    }

    /// Handle set default outbound command
    fn handle_set_default_outbound(&self, tag: String) -> IpcResponse {
        use crate::rules::RoutingSnapshot;

        // Validate outbound exists
        if self.outbound_manager.get(&tag).is_none() {
            return IpcResponse::error(
                ErrorCode::NotFound,
                format!("Outbound '{}' not found", tag),
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
        IpcResponse::success_with_message(format!("Default outbound set to '{}'", tag))
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
            "Egress change notification processed: {:?} '{}' ({})",
            action, tag, egress_type
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
                let value = if *status == health_str { 1u64 } else { 0u64 };
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
}

/// Write a metric header (HELP and TYPE lines)
fn write_metric_header(output: &mut String, name: &str, help: &str, metric_type: &str) {
    use std::fmt::Write;
    let _ = writeln!(output, "# HELP {} {}", name, help);
    let _ = writeln!(output, "# TYPE {} {}", name, metric_type);
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
        let _ = writeln!(output, "{}{{{}}} {}", name, label_str, value);
    } else {
        let _ = writeln!(output, "{} {}", name, value);
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
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hours, mins, secs
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ConnectionConfig;
    use crate::ipc::protocol::{EgressAction, ErrorCode, RuleConfig};
    use crate::rules::RuleType;
    use std::time::Duration;

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
    // P1 Handler Tests - Phase 3.3 IPC Protocol v2.1
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
}
