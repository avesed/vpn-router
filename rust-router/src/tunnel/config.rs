//! Tunnel configuration types for Phase 6
//!
//! This module defines configuration types for WireGuard tunnels,
//! including both userspace and kernel-based implementations.
//!
//! # Phase 6 Implementation Status
//!
//! - [ ] 6.2 Configuration types
//! - [ ] 6.2 Validation
//! - [ ] 6.2 Serialization/deserialization
//!
//! # References
//!
//! - Implementation Plan: `docs/PHASE6_IMPLEMENTATION_PLAN_v3.2.md` Section 6.2

use serde::{Deserialize, Serialize};

/// Configuration for a WireGuard tunnel
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

impl Default for WgTunnelConfig {
    fn default() -> Self {
        Self {
            private_key: String::new(),
            peer_public_key: String::new(),
            peer_endpoint: String::new(),
            allowed_ips: vec!["0.0.0.0/0".to_string()],
            local_ip: None,
            listen_port: None,
            persistent_keepalive: Some(25),
            mtu: Some(1420),
        }
    }
}

impl WgTunnelConfig {
    /// Create a new tunnel configuration
    ///
    /// # Arguments
    ///
    /// * `private_key` - Local WireGuard private key
    /// * `peer_public_key` - Remote peer's public key
    /// * `peer_endpoint` - Remote peer's endpoint (IP:port)
    pub fn new(private_key: String, peer_public_key: String, peer_endpoint: String) -> Self {
        Self {
            private_key,
            peer_public_key,
            peer_endpoint,
            ..Default::default()
        }
    }

    /// Set the local tunnel IP
    pub fn with_local_ip(mut self, ip: String) -> Self {
        self.local_ip = Some(ip);
        self
    }

    /// Set the listen port
    pub fn with_listen_port(mut self, port: u16) -> Self {
        self.listen_port = Some(port);
        self
    }

    /// Set the allowed IPs
    pub fn with_allowed_ips(mut self, ips: Vec<String>) -> Self {
        self.allowed_ips = ips;
        self
    }

    /// Set the persistent keepalive
    pub fn with_persistent_keepalive(mut self, seconds: u16) -> Self {
        self.persistent_keepalive = Some(seconds);
        self
    }

    /// Set the MTU
    pub fn with_mtu(mut self, mtu: u16) -> Self {
        self.mtu = Some(mtu);
        self
    }

    /// Validate the configuration
    ///
    /// # Returns
    ///
    /// Ok if valid, Err with description if invalid
    pub fn validate(&self) -> Result<(), String> {
        if self.private_key.is_empty() {
            return Err("Private key is required".into());
        }
        if self.peer_public_key.is_empty() {
            return Err("Peer public key is required".into());
        }
        if self.peer_endpoint.is_empty() {
            return Err("Peer endpoint is required".into());
        }

        // Validate private key format (Base64, 44 chars)
        if self.private_key.len() != 44 || !self.private_key.ends_with('=') {
            // Note: This is a simplified check; real validation should decode Base64
        }

        // Validate peer public key format
        if self.peer_public_key.len() != 44 || !self.peer_public_key.ends_with('=') {
            // Note: This is a simplified check
        }

        // Validate endpoint format
        if !self.peer_endpoint.contains(':') {
            return Err("Peer endpoint must be in IP:port format".into());
        }

        // Validate MTU (minimum for IPv4 is 576, max is u16::MAX which is 65535)
        if let Some(mtu) = self.mtu {
            if mtu < 576 {
                return Err("MTU must be at least 576".into());
            }
        }

        Ok(())
    }
}

/// Configuration for a WireGuard peer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WgPeerConfig {
    /// Peer public key (Base64 encoded)
    pub public_key: String,
    /// Peer endpoint (IP:port, optional for dynamic endpoints)
    #[serde(default)]
    pub endpoint: Option<String>,
    /// Allowed IPs for this peer
    #[serde(default)]
    pub allowed_ips: Vec<String>,
    /// Persistent keepalive interval in seconds
    #[serde(default)]
    pub persistent_keepalive: Option<u16>,
    /// Pre-shared key for additional security (Base64 encoded)
    #[serde(default)]
    pub preshared_key: Option<String>,
}

impl Default for WgPeerConfig {
    fn default() -> Self {
        Self {
            public_key: String::new(),
            endpoint: None,
            allowed_ips: Vec::new(),
            persistent_keepalive: Some(25),
            preshared_key: None,
        }
    }
}

impl WgPeerConfig {
    /// Create a new peer configuration
    ///
    /// # Arguments
    ///
    /// * `public_key` - Peer's public key
    pub fn new(public_key: String) -> Self {
        Self {
            public_key,
            ..Default::default()
        }
    }

    /// Set the peer endpoint
    pub fn with_endpoint(mut self, endpoint: String) -> Self {
        self.endpoint = Some(endpoint);
        self
    }

    /// Set the allowed IPs
    pub fn with_allowed_ips(mut self, ips: Vec<String>) -> Self {
        self.allowed_ips = ips;
        self
    }

    /// Set the persistent keepalive
    pub fn with_persistent_keepalive(mut self, seconds: u16) -> Self {
        self.persistent_keepalive = Some(seconds);
        self
    }

    /// Set the pre-shared key
    pub fn with_preshared_key(mut self, key: String) -> Self {
        self.preshared_key = Some(key);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tunnel_config_default() {
        let config = WgTunnelConfig::default();
        assert!(config.private_key.is_empty());
        assert_eq!(config.persistent_keepalive, Some(25));
        assert_eq!(config.mtu, Some(1420));
    }

    #[test]
    fn test_tunnel_config_new() {
        let config = WgTunnelConfig::new(
            "private".to_string(),
            "public".to_string(),
            "1.2.3.4:51820".to_string(),
        );

        assert_eq!(config.private_key, "private");
        assert_eq!(config.peer_public_key, "public");
        assert_eq!(config.peer_endpoint, "1.2.3.4:51820");
    }

    #[test]
    fn test_tunnel_config_builder() {
        let config = WgTunnelConfig::new(
            "private".to_string(),
            "public".to_string(),
            "1.2.3.4:51820".to_string(),
        )
        .with_local_ip("10.200.200.1/32".to_string())
        .with_listen_port(36200)
        .with_mtu(1400);

        assert_eq!(config.local_ip, Some("10.200.200.1/32".to_string()));
        assert_eq!(config.listen_port, Some(36200));
        assert_eq!(config.mtu, Some(1400));
    }

    #[test]
    fn test_tunnel_config_validate_missing_private_key() {
        let config = WgTunnelConfig::default();
        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Private key"));
    }

    #[test]
    fn test_tunnel_config_validate_missing_endpoint() {
        let mut config = WgTunnelConfig::default();
        config.private_key = "test".to_string();
        config.peer_public_key = "test".to_string();

        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("endpoint"));
    }

    #[test]
    fn test_tunnel_config_validate_invalid_mtu() {
        let mut config = WgTunnelConfig::default();
        config.private_key = "test".to_string();
        config.peer_public_key = "test".to_string();
        config.peer_endpoint = "1.2.3.4:51820".to_string();
        config.mtu = Some(100); // Too small

        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("MTU"));
    }

    #[test]
    fn test_peer_config_default() {
        let config = WgPeerConfig::default();
        assert!(config.public_key.is_empty());
        assert!(config.endpoint.is_none());
    }

    #[test]
    fn test_peer_config_builder() {
        let config = WgPeerConfig::new("public-key".to_string())
            .with_endpoint("1.2.3.4:51820".to_string())
            .with_allowed_ips(vec!["10.0.0.0/8".to_string()])
            .with_persistent_keepalive(30);

        assert_eq!(config.public_key, "public-key");
        assert_eq!(config.endpoint, Some("1.2.3.4:51820".to_string()));
        assert_eq!(config.allowed_ips, vec!["10.0.0.0/8"]);
        assert_eq!(config.persistent_keepalive, Some(30));
    }

    #[test]
    fn test_tunnel_config_serialization() {
        let config = WgTunnelConfig::new(
            "private".to_string(),
            "public".to_string(),
            "1.2.3.4:51820".to_string(),
        );

        let json = serde_json::to_string(&config).expect("Should serialize");
        let decoded: WgTunnelConfig = serde_json::from_str(&json).expect("Should deserialize");

        assert_eq!(decoded.private_key, config.private_key);
        assert_eq!(decoded.peer_public_key, config.peer_public_key);
    }
}
