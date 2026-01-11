//! Tunnel configuration types for Phase 6
//!
//! This module defines configuration types for `WireGuard` tunnels,
//! including both userspace and kernel-based implementations.
//!
//! # Phase 6 Implementation Status
//!
//! - [x] 6.2 Configuration types
//! - [x] 6.2 Validation
//! - [x] 6.2 Serialization/deserialization
//!
//! # References
//!
//! - Implementation Plan: `docs/PHASE6_IMPLEMENTATION_PLAN_v3.2.md` Section 6.2

use std::net::SocketAddr;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use serde::{Deserialize, Serialize};

/// `WireGuard` rekey interval in seconds (3 minutes)
///
/// `WireGuard` initiates a new handshake when the current session key
/// has been in use for this duration. A peer is considered "connected"
/// if a successful handshake occurred within this interval.
///
/// Reference: <https://www.wireguard.com/protocol/>
pub const WG_REKEY_INTERVAL_SECS: u64 = 180;

/// Configuration for a `WireGuard` tunnel
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WgTunnelConfig {
    /// `WireGuard` private key (Base64 encoded)
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
    /// * `private_key` - Local `WireGuard` private key
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
    ///
    /// # Validation Steps
    ///
    /// 1. Required fields: `private_key`, `peer_public_key`, `peer_endpoint`
    /// 2. Private key: Must be valid Base64 decoding to exactly 32 bytes
    /// 3. Peer public key: Must be valid Base64 decoding to exactly 32 bytes
    /// 4. Peer endpoint: Must be in IP:port format
    /// 5. MTU: If specified, must be at least 576 (IPv4 minimum)
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

        // Validate private key format (Base64, 32 bytes decoded)
        let private_bytes = BASE64
            .decode(&self.private_key)
            .map_err(|e| format!("Invalid private key Base64: {e}"))?;
        if private_bytes.len() != 32 {
            return Err(format!(
                "Private key must be 32 bytes, got {}",
                private_bytes.len()
            ));
        }

        // Validate peer public key format (Base64, 32 bytes decoded)
        let public_bytes = BASE64
            .decode(&self.peer_public_key)
            .map_err(|e| format!("Invalid peer public key Base64: {e}"))?;
        if public_bytes.len() != 32 {
            return Err(format!(
                "Peer public key must be 32 bytes, got {}",
                public_bytes.len()
            ));
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

/// Configuration for a `WireGuard` peer
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

/// Information about a `WireGuard` peer
///
/// This struct contains runtime information about a connected peer,
/// including statistics and connection state.
///
/// # Example
///
/// ```
/// use rust_router::tunnel::config::WgPeerInfo;
///
/// let info = WgPeerInfo::new("base64_public_key".to_string());
/// assert!(!info.is_connected);
/// assert_eq!(info.tx_bytes, 0);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WgPeerInfo {
    /// Peer's public key (Base64 encoded)
    pub public_key: String,

    /// Current endpoint (if known)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<SocketAddr>,

    /// Allowed IPs for this peer
    #[serde(default)]
    pub allowed_ips: Vec<String>,

    /// Last handshake timestamp (Unix seconds)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_handshake: Option<u64>,

    /// Bytes transmitted to this peer
    #[serde(default)]
    pub tx_bytes: u64,

    /// Bytes received from this peer
    #[serde(default)]
    pub rx_bytes: u64,

    /// Persistent keepalive interval (seconds)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub persistent_keepalive: Option<u16>,

    /// Whether the peer is currently connected (had recent handshake)
    #[serde(default)]
    pub is_connected: bool,

    /// Pre-shared key (Base64 encoded, if set)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preshared_key: Option<String>,
}

impl WgPeerInfo {
    /// Create a new peer info with default values
    ///
    /// # Arguments
    ///
    /// * `public_key` - Peer's public key (Base64 encoded)
    pub fn new(public_key: String) -> Self {
        Self {
            public_key,
            endpoint: None,
            allowed_ips: Vec::new(),
            last_handshake: None,
            tx_bytes: 0,
            rx_bytes: 0,
            persistent_keepalive: None,
            is_connected: false,
            preshared_key: None,
        }
    }

    /// Create peer info from a peer configuration
    ///
    /// # Arguments
    ///
    /// * `config` - Peer configuration
    pub fn from_config(config: &WgPeerConfig) -> Self {
        Self {
            public_key: config.public_key.clone(),
            endpoint: config.endpoint.as_ref().and_then(|e| e.parse().ok()),
            allowed_ips: config.allowed_ips.clone(),
            last_handshake: None,
            tx_bytes: 0,
            rx_bytes: 0,
            persistent_keepalive: config.persistent_keepalive,
            is_connected: false,
            preshared_key: config.preshared_key.clone(),
        }
    }

    /// Check if the peer has had a recent handshake
    ///
    /// A handshake is considered recent if it occurred within the specified
    /// number of seconds.
    ///
    /// # Arguments
    ///
    /// * `threshold_secs` - Number of seconds to consider a handshake "recent"
    pub fn had_recent_handshake(&self, threshold_secs: u64) -> bool {
        if let Some(last) = self.last_handshake {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            now.saturating_sub(last) < threshold_secs
        } else {
            false
        }
    }

    /// Update connection status based on handshake timestamp
    ///
    /// Sets `is_connected` to true if the last handshake was within
    /// [`WG_REKEY_INTERVAL_SECS`] (3 minutes), which is the `WireGuard` rekey interval.
    pub fn update_connection_status(&mut self) {
        self.is_connected = self.had_recent_handshake(WG_REKEY_INTERVAL_SECS);
    }
}

impl Default for WgPeerInfo {
    fn default() -> Self {
        Self::new(String::new())
    }
}

/// Update parameters for a `WireGuard` peer
///
/// This struct contains optional fields for updating a peer's configuration.
/// Only the fields that are `Some` will be updated.
///
/// # Example
///
/// ```
/// use rust_router::tunnel::config::WgPeerUpdate;
///
/// let update = WgPeerUpdate::default()
///     .with_endpoint("192.168.1.1:51820".to_string())
///     .with_persistent_keepalive(25);
///
/// assert!(update.endpoint.is_some());
/// assert!(update.persistent_keepalive.is_some());
/// assert!(update.allowed_ips.is_none());
/// ```
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WgPeerUpdate {
    /// New endpoint (if changing)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,

    /// New allowed IPs (if changing)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_ips: Option<Vec<String>>,

    /// New persistent keepalive interval in seconds (if changing)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub persistent_keepalive: Option<u16>,

    /// New pre-shared key (if changing)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preshared_key: Option<String>,
}

impl WgPeerUpdate {
    /// Create a new empty peer update
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the new endpoint
    pub fn with_endpoint(mut self, endpoint: String) -> Self {
        self.endpoint = Some(endpoint);
        self
    }

    /// Set the new allowed IPs
    pub fn with_allowed_ips(mut self, ips: Vec<String>) -> Self {
        self.allowed_ips = Some(ips);
        self
    }

    /// Set the new persistent keepalive
    pub fn with_persistent_keepalive(mut self, seconds: u16) -> Self {
        self.persistent_keepalive = Some(seconds);
        self
    }

    /// Set the new pre-shared key
    pub fn with_preshared_key(mut self, key: String) -> Self {
        self.preshared_key = Some(key);
        self
    }

    /// Check if the update is empty (no fields set)
    pub fn is_empty(&self) -> bool {
        self.endpoint.is_none()
            && self.allowed_ips.is_none()
            && self.persistent_keepalive.is_none()
            && self.preshared_key.is_none()
    }

    /// Apply this update to a peer configuration
    ///
    /// # Arguments
    ///
    /// * `config` - The peer configuration to update
    pub fn apply_to(&self, config: &mut WgPeerConfig) {
        if let Some(ref endpoint) = self.endpoint {
            config.endpoint = Some(endpoint.clone());
        }
        if let Some(ref ips) = self.allowed_ips {
            config.allowed_ips = ips.clone();
        }
        if let Some(keepalive) = self.persistent_keepalive {
            config.persistent_keepalive = Some(keepalive);
        }
        if let Some(ref psk) = self.preshared_key {
            config.preshared_key = Some(psk.clone());
        }
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

    // Valid Base64-encoded 32-byte key for testing
    // This is a test key, NOT for production use
    const TEST_VALID_KEY: &str = "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=";

    #[test]
    fn test_tunnel_config_validate_missing_endpoint() {
        let mut config = WgTunnelConfig::default();
        config.private_key = TEST_VALID_KEY.to_string();
        config.peer_public_key = TEST_VALID_KEY.to_string();

        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("endpoint"));
    }

    #[test]
    fn test_tunnel_config_validate_invalid_mtu() {
        let mut config = WgTunnelConfig::default();
        config.private_key = TEST_VALID_KEY.to_string();
        config.peer_public_key = TEST_VALID_KEY.to_string();
        config.peer_endpoint = "1.2.3.4:51820".to_string();
        config.mtu = Some(100); // Too small

        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("MTU"));
    }

    #[test]
    fn test_tunnel_config_validate_invalid_private_key_base64() {
        let mut config = WgTunnelConfig::default();
        config.private_key = "not-valid-base64!!!".to_string();
        config.peer_public_key = TEST_VALID_KEY.to_string();
        config.peer_endpoint = "1.2.3.4:51820".to_string();

        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid private key Base64"));
    }

    #[test]
    fn test_tunnel_config_validate_private_key_wrong_length() {
        let mut config = WgTunnelConfig::default();
        // Valid Base64 but only 16 bytes when decoded
        config.private_key = "YWJjZGVmZ2hpamtsbW5v".to_string();
        config.peer_public_key = TEST_VALID_KEY.to_string();
        config.peer_endpoint = "1.2.3.4:51820".to_string();

        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("must be 32 bytes"));
    }

    #[test]
    fn test_tunnel_config_validate_invalid_peer_public_key_base64() {
        let mut config = WgTunnelConfig::default();
        config.private_key = TEST_VALID_KEY.to_string();
        config.peer_public_key = "not-valid-base64!!!".to_string();
        config.peer_endpoint = "1.2.3.4:51820".to_string();

        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid peer public key Base64"));
    }

    #[test]
    fn test_tunnel_config_validate_peer_public_key_wrong_length() {
        let mut config = WgTunnelConfig::default();
        config.private_key = TEST_VALID_KEY.to_string();
        // Valid Base64 but only 16 bytes when decoded
        config.peer_public_key = "YWJjZGVmZ2hpamtsbW5v".to_string();
        config.peer_endpoint = "1.2.3.4:51820".to_string();

        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Peer public key must be 32 bytes"));
    }

    #[test]
    fn test_tunnel_config_validate_success() {
        let mut config = WgTunnelConfig::default();
        config.private_key = TEST_VALID_KEY.to_string();
        config.peer_public_key = TEST_VALID_KEY.to_string();
        config.peer_endpoint = "1.2.3.4:51820".to_string();

        let result = config.validate();
        assert!(result.is_ok());
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

    // ========================================================================
    // WgPeerInfo Tests
    // ========================================================================

    #[test]
    fn test_peer_info_new() {
        let info = WgPeerInfo::new("test-key".to_string());
        assert_eq!(info.public_key, "test-key");
        assert!(info.endpoint.is_none());
        assert!(info.allowed_ips.is_empty());
        assert!(info.last_handshake.is_none());
        assert_eq!(info.tx_bytes, 0);
        assert_eq!(info.rx_bytes, 0);
        assert!(!info.is_connected);
    }

    #[test]
    fn test_peer_info_default() {
        let info = WgPeerInfo::default();
        assert!(info.public_key.is_empty());
        assert!(!info.is_connected);
    }

    #[test]
    fn test_peer_info_from_config() {
        let config = WgPeerConfig::new("public-key".to_string())
            .with_endpoint("192.168.1.1:51820".to_string())
            .with_allowed_ips(vec!["10.0.0.0/8".to_string()])
            .with_persistent_keepalive(25);

        let info = WgPeerInfo::from_config(&config);
        assert_eq!(info.public_key, "public-key");
        assert!(info.endpoint.is_some());
        assert_eq!(info.endpoint.unwrap().to_string(), "192.168.1.1:51820");
        assert_eq!(info.allowed_ips, vec!["10.0.0.0/8"]);
        assert_eq!(info.persistent_keepalive, Some(25));
        assert!(!info.is_connected);
    }

    #[test]
    fn test_peer_info_from_config_invalid_endpoint() {
        let config = WgPeerConfig::new("public-key".to_string())
            .with_endpoint("not-a-valid-endpoint".to_string());

        let info = WgPeerInfo::from_config(&config);
        assert!(info.endpoint.is_none());
    }

    #[test]
    fn test_peer_info_had_recent_handshake() {
        let mut info = WgPeerInfo::new("test-key".to_string());

        // No handshake timestamp
        assert!(!info.had_recent_handshake(180));

        // Recent handshake (now - 60 seconds)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        info.last_handshake = Some(now - 60);
        assert!(info.had_recent_handshake(180));

        // Old handshake (now - 300 seconds)
        info.last_handshake = Some(now - 300);
        assert!(!info.had_recent_handshake(180));
    }

    #[test]
    fn test_peer_info_update_connection_status() {
        let mut info = WgPeerInfo::new("test-key".to_string());

        // No handshake - not connected
        info.update_connection_status();
        assert!(!info.is_connected);

        // Recent handshake - connected
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        info.last_handshake = Some(now - 60);
        info.update_connection_status();
        assert!(info.is_connected);

        // Old handshake - not connected
        info.last_handshake = Some(now - 300);
        info.update_connection_status();
        assert!(!info.is_connected);
    }

    #[test]
    fn test_peer_info_serialization() {
        let mut info = WgPeerInfo::new("test-key".to_string());
        info.endpoint = Some("192.168.1.1:51820".parse().unwrap());
        info.allowed_ips = vec!["10.0.0.0/8".to_string()];
        info.tx_bytes = 1000;
        info.rx_bytes = 2000;
        info.is_connected = true;

        let json = serde_json::to_string(&info).expect("Should serialize");
        let decoded: WgPeerInfo = serde_json::from_str(&json).expect("Should deserialize");

        assert_eq!(decoded.public_key, info.public_key);
        assert_eq!(decoded.endpoint, info.endpoint);
        assert_eq!(decoded.allowed_ips, info.allowed_ips);
        assert_eq!(decoded.tx_bytes, info.tx_bytes);
        assert_eq!(decoded.rx_bytes, info.rx_bytes);
        assert_eq!(decoded.is_connected, info.is_connected);
    }

    #[test]
    fn test_peer_info_serialization_skip_none() {
        let info = WgPeerInfo::new("test-key".to_string());
        let json = serde_json::to_string(&info).expect("Should serialize");

        // Should not contain "endpoint" or "last_handshake" when None
        assert!(!json.contains("endpoint"));
        assert!(!json.contains("last_handshake"));
    }

    // ========================================================================
    // WgPeerUpdate Tests
    // ========================================================================

    #[test]
    fn test_peer_update_new() {
        let update = WgPeerUpdate::new();
        assert!(update.endpoint.is_none());
        assert!(update.allowed_ips.is_none());
        assert!(update.persistent_keepalive.is_none());
        assert!(update.preshared_key.is_none());
    }

    #[test]
    fn test_peer_update_default() {
        let update = WgPeerUpdate::default();
        assert!(update.is_empty());
    }

    #[test]
    fn test_peer_update_builder() {
        let update = WgPeerUpdate::new()
            .with_endpoint("192.168.1.1:51820".to_string())
            .with_allowed_ips(vec!["10.0.0.0/8".to_string()])
            .with_persistent_keepalive(30)
            .with_preshared_key("psk".to_string());

        assert_eq!(update.endpoint, Some("192.168.1.1:51820".to_string()));
        assert_eq!(update.allowed_ips, Some(vec!["10.0.0.0/8".to_string()]));
        assert_eq!(update.persistent_keepalive, Some(30));
        assert_eq!(update.preshared_key, Some("psk".to_string()));
    }

    #[test]
    fn test_peer_update_is_empty() {
        let empty = WgPeerUpdate::new();
        assert!(empty.is_empty());

        let with_endpoint = WgPeerUpdate::new().with_endpoint("1.2.3.4:51820".to_string());
        assert!(!with_endpoint.is_empty());

        let with_ips = WgPeerUpdate::new().with_allowed_ips(vec!["10.0.0.0/8".to_string()]);
        assert!(!with_ips.is_empty());

        let with_keepalive = WgPeerUpdate::new().with_persistent_keepalive(25);
        assert!(!with_keepalive.is_empty());

        let with_psk = WgPeerUpdate::new().with_preshared_key("psk".to_string());
        assert!(!with_psk.is_empty());
    }

    #[test]
    fn test_peer_update_apply_to() {
        let mut config = WgPeerConfig::new("public-key".to_string())
            .with_endpoint("1.1.1.1:51820".to_string())
            .with_allowed_ips(vec!["10.0.0.0/8".to_string()])
            .with_persistent_keepalive(25);

        let update = WgPeerUpdate::new()
            .with_endpoint("2.2.2.2:51820".to_string())
            .with_persistent_keepalive(30);

        update.apply_to(&mut config);

        // Updated fields
        assert_eq!(config.endpoint, Some("2.2.2.2:51820".to_string()));
        assert_eq!(config.persistent_keepalive, Some(30));

        // Unchanged fields
        assert_eq!(config.allowed_ips, vec!["10.0.0.0/8"]);
        assert_eq!(config.public_key, "public-key");
    }

    #[test]
    fn test_peer_update_apply_to_all_fields() {
        let mut config = WgPeerConfig::new("public-key".to_string());

        let update = WgPeerUpdate::new()
            .with_endpoint("1.2.3.4:51820".to_string())
            .with_allowed_ips(vec!["10.0.0.0/8".to_string(), "192.168.0.0/16".to_string()])
            .with_persistent_keepalive(60)
            .with_preshared_key("psk-base64".to_string());

        update.apply_to(&mut config);

        assert_eq!(config.endpoint, Some("1.2.3.4:51820".to_string()));
        assert_eq!(
            config.allowed_ips,
            vec!["10.0.0.0/8", "192.168.0.0/16"]
        );
        assert_eq!(config.persistent_keepalive, Some(60));
        assert_eq!(config.preshared_key, Some("psk-base64".to_string()));
    }

    #[test]
    fn test_peer_update_apply_empty() {
        let mut config = WgPeerConfig::new("public-key".to_string())
            .with_endpoint("1.1.1.1:51820".to_string())
            .with_allowed_ips(vec!["10.0.0.0/8".to_string()])
            .with_persistent_keepalive(25);

        let original_config = config.clone();
        let update = WgPeerUpdate::new();

        update.apply_to(&mut config);

        // Nothing should change
        assert_eq!(config.endpoint, original_config.endpoint);
        assert_eq!(config.allowed_ips, original_config.allowed_ips);
        assert_eq!(config.persistent_keepalive, original_config.persistent_keepalive);
    }

    #[test]
    fn test_peer_update_serialization() {
        let update = WgPeerUpdate::new()
            .with_endpoint("192.168.1.1:51820".to_string())
            .with_persistent_keepalive(30);

        let json = serde_json::to_string(&update).expect("Should serialize");
        let decoded: WgPeerUpdate = serde_json::from_str(&json).expect("Should deserialize");

        assert_eq!(decoded.endpoint, update.endpoint);
        assert_eq!(decoded.persistent_keepalive, update.persistent_keepalive);
        assert!(decoded.allowed_ips.is_none());
    }

    #[test]
    fn test_peer_update_serialization_skip_none() {
        let update = WgPeerUpdate::new().with_endpoint("1.2.3.4:51820".to_string());
        let json = serde_json::to_string(&update).expect("Should serialize");

        // Should contain endpoint but not the None fields
        assert!(json.contains("endpoint"));
        assert!(!json.contains("allowed_ips"));
        assert!(!json.contains("persistent_keepalive"));
        assert!(!json.contains("preshared_key"));
    }
}
