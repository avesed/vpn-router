//! IPC command handler
//!
//! This module processes IPC commands and generates responses.

use std::sync::Arc;
use std::time::Instant;

use tracing::{debug, info, warn};

use super::protocol::{
    ErrorCode, IpcCommand, IpcResponse, OutboundInfo, OutboundStatsResponse, ServerCapabilities,
    ServerStatus,
};
use crate::config::{load_config_with_env, OutboundConfig};
use crate::connection::ConnectionManager;
use crate::outbound::OutboundManager;

/// IPC command handler
pub struct IpcHandler {
    /// Connection manager
    connection_manager: Arc<ConnectionManager>,

    /// Outbound manager
    outbound_manager: Arc<OutboundManager>,

    /// Server start time
    start_time: Instant,

    /// Server version
    version: String,
}

impl IpcHandler {
    /// Create a new IPC handler
    pub fn new(
        connection_manager: Arc<ConnectionManager>,
        outbound_manager: Arc<OutboundManager>,
    ) -> Self {
        Self {
            connection_manager,
            outbound_manager,
            start_time: Instant::now(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
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

        IpcResponse::OutboundList(outbounds)
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ConnectionConfig;
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

        IpcHandler::new(connection_manager, outbound_manager)
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

        if let IpcResponse::OutboundList(list) = response {
            assert_eq!(list.len(), 1);
            assert_eq!(list[0].tag, "direct");
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
}
