//! Block outbound implementation
//!
//! This module provides the `BlockOutbound` type which blocks/drops
//! all connections. Used for ad-blocking and access control.
//!
//! Supports both TCP and UDP protocols (both are blocked).

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tracing::debug;

use super::traits::{HealthStatus, Outbound, OutboundConnection, UdpOutboundHandle};
use crate::config::OutboundConfig;
use crate::connection::OutboundStats;
use crate::error::{OutboundError, UdpError};

/// Block outbound - drops all connections
///
/// This outbound type is used for:
/// - Ad-blocking (blocking connections to ad servers)
/// - Access control (blocking connections to specific destinations)
/// - Testing (simulating network failures)
pub struct BlockOutbound {
    /// Tag for this outbound
    tag: String,
    /// Connection statistics (for counting blocked connections)
    stats: Arc<OutboundStats>,
    /// Whether the outbound is enabled
    enabled: AtomicBool,
}

impl BlockOutbound {
    /// Create a new block outbound
    pub fn new(tag: impl Into<String>) -> Self {
        Self {
            tag: tag.into(),
            stats: Arc::new(OutboundStats::new()),
            enabled: AtomicBool::new(true),
        }
    }

    /// Create a block outbound from configuration
    pub fn from_config(config: &OutboundConfig) -> Self {
        let outbound = Self::new(&config.tag);
        outbound.enabled.store(config.enabled, Ordering::Relaxed);
        outbound
    }

    /// Enable or disable this outbound
    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Relaxed);
    }
}

#[async_trait]
impl Outbound for BlockOutbound {
    async fn connect(
        &self,
        addr: SocketAddr,
        _timeout: Duration,
    ) -> Result<OutboundConnection, OutboundError> {
        // Record the blocked connection
        self.stats.record_connection();

        debug!("Blocking connection to {} via {}", addr, self.tag);

        // Return an error indicating the connection was blocked
        Err(OutboundError::unavailable(
            &self.tag,
            format!("connection to {addr} blocked"),
        ))
    }

    fn tag(&self) -> &str {
        &self.tag
    }

    fn health_status(&self) -> HealthStatus {
        // Block outbound is always "healthy" - it's doing its job
        HealthStatus::Healthy
    }

    fn stats(&self) -> Arc<OutboundStats> {
        Arc::clone(&self.stats)
    }

    fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Relaxed);
    }

    fn active_connections(&self) -> u64 {
        0 // Block outbound doesn't maintain connections
    }

    fn outbound_type(&self) -> &'static str {
        "block"
    }

    // === UDP Methods (Phase 5.1) ===

    async fn connect_udp(
        &self,
        addr: SocketAddr,
        _timeout: Duration,
    ) -> Result<UdpOutboundHandle, UdpError> {
        // Record the blocked UDP connection
        self.stats.record_connection();

        debug!("Blocking UDP connection to {} via {}", addr, self.tag);

        // Return an error indicating the connection was blocked
        Err(UdpError::blocked(&self.tag, addr))
    }

    fn supports_udp(&self) -> bool {
        // Block outbound "supports" UDP in that it handles UDP requests
        // (by blocking them), so routing can direct UDP to it
        true
    }
}

impl std::fmt::Debug for BlockOutbound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlockOutbound")
            .field("tag", &self.tag)
            .field("enabled", &self.is_enabled())
            .field("blocked_count", &self.stats.connections())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_outbound_creation() {
        let outbound = BlockOutbound::new("block");
        assert_eq!(outbound.tag(), "block");
        assert!(outbound.is_enabled());
        assert_eq!(outbound.outbound_type(), "block");
    }

    #[test]
    fn test_from_config() {
        let mut config = OutboundConfig::block("adblock");
        config.enabled = false;

        let outbound = BlockOutbound::from_config(&config);
        assert_eq!(outbound.tag(), "adblock");
        assert!(!outbound.is_enabled());
    }

    #[tokio::test]
    async fn test_connect_blocks() {
        let outbound = BlockOutbound::new("test-block");
        let addr: SocketAddr = "1.2.3.4:80".parse().unwrap();

        let result = outbound.connect(addr, Duration::from_secs(1)).await;

        assert!(result.is_err());
        if let Err(OutboundError::Unavailable { tag, reason }) = result {
            assert_eq!(tag, "test-block");
            assert!(reason.contains("blocked"));
        } else {
            panic!("Expected Unavailable error");
        }

        // Stats should show the blocked connection
        assert_eq!(outbound.stats.connections(), 1);
    }

    #[test]
    fn test_health_status() {
        let outbound = BlockOutbound::new("block");
        // Block outbound is always healthy
        assert_eq!(outbound.health_status(), HealthStatus::Healthy);
    }

    #[test]
    fn test_enable_disable() {
        let outbound = BlockOutbound::new("block");
        assert!(outbound.is_enabled());

        outbound.set_enabled(false);
        assert!(!outbound.is_enabled());

        outbound.set_enabled(true);
        assert!(outbound.is_enabled());
    }

    // === UDP Tests ===

    #[test]
    fn test_block_supports_udp() {
        let outbound = BlockOutbound::new("block");
        // Block supports UDP (by blocking it)
        assert!(outbound.supports_udp());
    }

    #[tokio::test]
    async fn test_connect_udp_blocks() {
        let outbound = BlockOutbound::new("test-block-udp");
        let addr: SocketAddr = "8.8.8.8:53".parse().unwrap();

        let result = outbound.connect_udp(addr, Duration::from_secs(1)).await;

        assert!(result.is_err());
        if let Err(UdpError::Blocked { tag, addr: blocked_addr }) = result {
            assert_eq!(tag, "test-block-udp");
            assert_eq!(blocked_addr, addr);
        } else {
            panic!("Expected Blocked error, got {:?}", result);
        }

        // Stats should show the blocked connection
        assert_eq!(outbound.stats.connections(), 1);
    }
}
