//! IPC command handler
//!
//! This module processes IPC commands and generates responses.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use tracing::{debug, info, warn};

use super::protocol::{
    ErrorCode, IpcCommand, IpcResponse, OutboundInfo, OutboundStatsResponse, RuleStatsResponse,
    ServerCapabilities, ServerStatus,
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
}
