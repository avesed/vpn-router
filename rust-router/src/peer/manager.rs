//! PeerManager - Multi-node peer management for Phase 6
//!
//! This module implements peer discovery, pairing, and tunnel management
//! for multi-node VPN routing.
//!
//! # Phase 6 Implementation Status
//!
//! - [x] 6.5.1 Input Validation (see validation.rs)
//! - [ ] 6.5.2 PeerManager Structure
//! - [ ] 6.5.3 Port Allocator
//! - [ ] 6.5.4 Health Checker
//!
//! # Architecture
//!
//! The PeerManager handles:
//! - Peer lifecycle management (add, remove, connect, disconnect)
//! - WireGuard tunnel creation via boringtun
//! - Xray tunnel creation via SOCKS5 bridge
//! - Bidirectional pairing with pre-generated keys
//! - Health monitoring with hysteresis
//!
//! # Example
//!
//! ```ignore
//! use rust_router::peer::manager::PeerManager;
//!
//! let manager = PeerManager::new("local-node".to_string());
//!
//! // Generate offline pairing request
//! let code = manager.generate_pair_request(PairRequestConfig {
//!     local_tag: "local-node".to_string(),
//!     local_endpoint: "192.168.1.1:36200".to_string(),
//!     local_api_port: 36000,
//!     bidirectional: true,
//!     tunnel_type: TunnelType::WireGuard,
//!     ..Default::default()
//! })?;
//! ```
//!
//! # References
//!
//! - Implementation Plan: `docs/PHASE6_IMPLEMENTATION_PLAN_v3.2.md` Section 6.5.2

use std::collections::HashMap;
use std::sync::RwLock;

use crate::ipc::{PeerConfig, PeerState, PeerStatus, TunnelType, ChainRole};
use crate::peer::health::HealthChecker;
use crate::peer::ip_allocator::TunnelIpAllocator;
use crate::peer::pairing::PairRequestConfig;
use crate::peer::port_allocator::TunnelPortAllocator;
use crate::peer::validation::ValidationError;

/// Error types for peer operations
#[derive(Debug, thiserror::Error)]
pub enum PeerError {
    /// Peer not found
    #[error("Peer not found: {0}")]
    NotFound(String),

    /// Peer already exists
    #[error("Peer already exists: {0}")]
    AlreadyExists(String),

    /// Peer is not connected
    #[error("Peer is not connected: {0}")]
    NotConnected(String),

    /// Peer is already connected
    #[error("Peer is already connected: {0}")]
    AlreadyConnected(String),

    /// Validation error
    #[error("Validation error: {0}")]
    Validation(#[from] ValidationError),

    /// Port allocation exhausted
    #[error("No available tunnel ports")]
    PortExhausted,

    /// IP allocation exhausted
    #[error("No available tunnel IPs")]
    IpExhausted,

    /// Missing bidirectional key
    #[error("Missing pre-generated key for bidirectional pairing")]
    MissingBidirectionalKey,

    /// Missing WireGuard key
    #[error("Missing WireGuard public key")]
    MissingWgKey,

    /// Xray relay not supported
    #[error("Xray tunnel cannot be used for relay in DSCP chains: {0}")]
    XrayRelayNotSupported(String),

    /// Tunnel creation failed
    #[error("Tunnel creation failed: {0}")]
    TunnelCreationFailed(String),

    /// IPC error
    #[error("IPC error: {0}")]
    Ipc(String),

    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),
}

/// Internal peer state tracking
#[allow(dead_code)]
struct PeerStateInternal {
    /// Peer configuration
    config: PeerConfig,
    /// Current connection state
    state: PeerState,
    /// Reconnection attempt counter
    reconnect_attempts: u32,
    /// Last error message
    last_error: Option<String>,
}

/// PeerManager handles multi-node peer connections
///
/// TODO(Phase 6.5): Implement full peer management
#[allow(dead_code)]
pub struct PeerManager {
    /// Map of peer tag to peer state
    peers: RwLock<HashMap<String, PeerStateInternal>>,
    /// Local node tag for identification
    local_node_tag: String,
    /// Tunnel IP allocator
    tunnel_ip_allocator: TunnelIpAllocator,
    /// Tunnel port allocator
    tunnel_port_allocator: TunnelPortAllocator,
    /// Health checker with hysteresis
    health_checker: HealthChecker,
}

impl PeerManager {
    /// Create a new PeerManager
    ///
    /// # Arguments
    ///
    /// * `local_node_tag` - Tag identifying the local node
    ///
    /// # Example
    ///
    /// ```ignore
    /// let manager = PeerManager::new("my-node".to_string());
    /// ```
    pub fn new(local_node_tag: String) -> Self {
        Self {
            peers: RwLock::new(HashMap::new()),
            local_node_tag,
            tunnel_ip_allocator: TunnelIpAllocator::new("10.200.200.0/24"),
            tunnel_port_allocator: TunnelPortAllocator::new(36200, 36299),
            health_checker: HealthChecker::new(3), // 3 consecutive failures threshold
        }
    }

    /// Get the local node tag
    pub fn local_node_tag(&self) -> &str {
        &self.local_node_tag
    }

    /// Generate an offline pairing request code
    ///
    /// # Arguments
    ///
    /// * `config` - Configuration for the pairing request
    ///
    /// # Returns
    ///
    /// Base64-encoded pairing request code
    ///
    /// TODO(Phase 6.5): Implement full pairing generation
    pub fn generate_pair_request(&self, _config: PairRequestConfig) -> Result<String, PeerError> {
        unimplemented!("Phase 6.5: generate_pair_request not yet implemented")
    }

    /// Import a pairing request from another node
    ///
    /// # Arguments
    ///
    /// * `code` - Base64-encoded pairing request code
    /// * `local_config` - Local node configuration for the response
    ///
    /// # Returns
    ///
    /// Base64-encoded pairing response code
    ///
    /// TODO(Phase 6.5): Implement full pairing import
    pub async fn import_pair_request(
        &self,
        _code: &str,
        _local_config: PairRequestConfig,
    ) -> Result<String, PeerError> {
        unimplemented!("Phase 6.5: import_pair_request not yet implemented")
    }

    /// Complete the pairing handshake
    ///
    /// # Arguments
    ///
    /// * `code` - Base64-encoded pairing response code
    ///
    /// TODO(Phase 6.5): Implement handshake completion
    pub async fn complete_handshake(&self, _code: &str) -> Result<(), PeerError> {
        unimplemented!("Phase 6.5: complete_handshake not yet implemented")
    }

    /// Connect to a configured peer
    ///
    /// # Arguments
    ///
    /// * `tag` - Peer node tag
    ///
    /// TODO(Phase 6.5): Implement peer connection
    pub async fn connect(&self, _tag: &str) -> Result<(), PeerError> {
        unimplemented!("Phase 6.5: connect not yet implemented")
    }

    /// Disconnect from a peer
    ///
    /// # Arguments
    ///
    /// * `tag` - Peer node tag
    ///
    /// TODO(Phase 6.5): Implement peer disconnection
    pub async fn disconnect(&self, _tag: &str) -> Result<(), PeerError> {
        unimplemented!("Phase 6.5: disconnect not yet implemented")
    }

    /// Get status of a specific peer
    ///
    /// # Arguments
    ///
    /// * `tag` - Peer node tag
    ///
    /// # Returns
    ///
    /// Peer status information
    pub fn get_peer_status(&self, tag: &str) -> Option<PeerStatus> {
        let peers = self.peers.read().ok()?;
        let peer = peers.get(tag)?;

        Some(PeerStatus {
            tag: tag.to_string(),
            state: peer.state.clone(),
            tunnel_type: peer.config.tunnel_type,
            tunnel_local_ip: peer.config.tunnel_local_ip.clone(),
            tunnel_remote_ip: peer.config.tunnel_remote_ip.clone(),
            api_port: peer.config.api_port,
            last_handshake: None,
            tx_bytes: 0,
            rx_bytes: 0,
            reconnect_attempts: peer.reconnect_attempts,
            consecutive_failures: self.health_checker.get_failure_count(tag),
            last_error: peer.last_error.clone(),
        })
    }

    /// List all peers
    ///
    /// # Returns
    ///
    /// List of peer status information
    pub fn list_peers(&self) -> Vec<PeerStatus> {
        let peers = match self.peers.read() {
            Ok(guard) => guard,
            Err(_) => return Vec::new(),
        };

        peers
            .iter()
            .map(|(tag, peer)| PeerStatus {
                tag: tag.clone(),
                state: peer.state.clone(),
                tunnel_type: peer.config.tunnel_type,
                tunnel_local_ip: peer.config.tunnel_local_ip.clone(),
                tunnel_remote_ip: peer.config.tunnel_remote_ip.clone(),
                api_port: peer.config.api_port,
                last_handshake: None,
                tx_bytes: 0,
                rx_bytes: 0,
                reconnect_attempts: peer.reconnect_attempts,
                consecutive_failures: self.health_checker.get_failure_count(tag),
                last_error: peer.last_error.clone(),
            })
            .collect()
    }

    /// Remove a peer
    ///
    /// # Arguments
    ///
    /// * `tag` - Peer node tag
    ///
    /// TODO(Phase 6.5): Implement peer removal with cleanup
    pub async fn remove_peer(&self, _tag: &str) -> Result<(), PeerError> {
        unimplemented!("Phase 6.5: remove_peer not yet implemented")
    }

    /// Validate tunnel type for DSCP chain participation
    ///
    /// Xray tunnels cannot participate in relay chains because DSCP
    /// headers are lost in the SOCKS5 protocol.
    ///
    /// # Arguments
    ///
    /// * `tag` - Peer node tag
    /// * `role` - Role in the chain (entry/relay/terminal)
    ///
    /// # Returns
    ///
    /// Ok if valid, Err if Xray used in relay position
    pub fn validate_tunnel_type_for_dscp(
        &self,
        tag: &str,
        role: ChainRole,
    ) -> Result<(), PeerError> {
        let peers = self.peers.read().map_err(|e| PeerError::Internal(e.to_string()))?;
        let peer = peers.get(tag).ok_or_else(|| PeerError::NotFound(tag.to_string()))?;

        // Xray tunnels cannot participate in relay chains (DSCP lost in SOCKS5)
        if peer.config.tunnel_type == TunnelType::Xray && role == ChainRole::Relay {
            return Err(PeerError::XrayRelayNotSupported(tag.to_string()));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_manager_creation() {
        let manager = PeerManager::new("test-node".to_string());
        assert_eq!(manager.local_node_tag(), "test-node");
    }

    #[test]
    fn test_list_peers_empty() {
        let manager = PeerManager::new("test-node".to_string());
        let peers = manager.list_peers();
        assert!(peers.is_empty());
    }

    #[test]
    fn test_get_peer_status_not_found() {
        let manager = PeerManager::new("test-node".to_string());
        let status = manager.get_peer_status("nonexistent");
        assert!(status.is_none());
    }
}
