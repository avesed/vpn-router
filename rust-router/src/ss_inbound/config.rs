//! Configuration types for Shadowsocks inbound listener
//!
//! This module provides configuration structures for the Shadowsocks inbound listener,
//! including encryption method and password settings.
//!
//! # Example
//!
//! ```
//! use rust_router::ss_inbound::{ShadowsocksInboundConfig};
//! use rust_router::shadowsocks::ShadowsocksMethod;
//! use std::net::SocketAddr;
//!
//! let config = ShadowsocksInboundConfig {
//!     enabled: true,
//!     listen: "0.0.0.0:8388".parse().unwrap(),
//!     method: ShadowsocksMethod::Aead2022Blake3Aes256Gcm,
//!     password: "my-secret-password".to_string(),
//!     udp_enabled: false,
//! };
//! ```

use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

use super::error::{ShadowsocksInboundError, ShadowsocksInboundResult};
use crate::shadowsocks::ShadowsocksMethod;

#[cfg(feature = "shadowsocks")]
use shadowsocks::{
    config::{ServerConfig, ServerType},
    context::{Context as SsContext, SharedContext},
    ServerAddr,
};

/// Configuration for Shadowsocks inbound listener
///
/// This structure contains all settings needed to run a Shadowsocks inbound listener,
/// including the listen address, encryption method, and password.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowsocksInboundConfig {
    /// Whether the inbound is enabled
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// Listen address (e.g., "0.0.0.0:8388")
    pub listen: SocketAddr,

    /// Encryption method
    #[serde(default)]
    pub method: ShadowsocksMethod,

    /// Password for authentication
    ///
    /// For AEAD 2022 ciphers, this should be a Base64-encoded key of appropriate length.
    /// For legacy AEAD ciphers, this is a plaintext password that will be derived.
    pub password: String,

    /// Enable UDP support (default: false)
    ///
    /// Note: UDP relay is not yet implemented.
    #[serde(default)]
    pub udp_enabled: bool,
}

fn default_enabled() -> bool {
    true
}

impl ShadowsocksInboundConfig {
    /// Create a new Shadowsocks inbound configuration
    ///
    /// # Arguments
    ///
    /// * `listen` - Address to listen on
    /// * `password` - Password for authentication
    #[must_use]
    pub fn new(listen: SocketAddr, password: impl Into<String>) -> Self {
        Self {
            enabled: true,
            listen,
            method: ShadowsocksMethod::default(),
            password: password.into(),
            udp_enabled: false,
        }
    }

    /// Set the encryption method
    #[must_use]
    pub fn with_method(mut self, method: ShadowsocksMethod) -> Self {
        self.method = method;
        self
    }

    /// Enable or disable the inbound
    #[must_use]
    pub fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    /// Enable or disable UDP support
    #[must_use]
    pub fn with_udp(mut self, udp: bool) -> Self {
        self.udp_enabled = udp;
        self
    }

    /// Validate the configuration
    ///
    /// # Errors
    ///
    /// Returns `ShadowsocksInboundError::InvalidConfig` if:
    /// - Password is empty
    /// - Method is not supported
    pub fn validate(&self) -> ShadowsocksInboundResult<()> {
        if self.password.is_empty() {
            return Err(ShadowsocksInboundError::invalid_config(
                "password cannot be empty",
            ));
        }

        // Validate password length for AEAD 2022 ciphers
        if self.method.is_aead_2022() {
            // AEAD 2022 requires Base64-encoded keys
            let decoded = base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                &self.password,
            );

            match decoded {
                Ok(key) => {
                    let required_len = match self.method {
                        ShadowsocksMethod::Aead2022Blake3Aes256Gcm
                        | ShadowsocksMethod::Aead2022Blake3Chacha20Poly1305 => 32,
                        ShadowsocksMethod::Aead2022Blake3Aes128Gcm => 16,
                        _ => 0,
                    };

                    if required_len > 0 && key.len() != required_len {
                        return Err(ShadowsocksInboundError::invalid_config(format!(
                            "AEAD 2022 {} requires a {}-byte key (got {} bytes)",
                            self.method,
                            required_len,
                            key.len()
                        )));
                    }
                }
                Err(e) => {
                    return Err(ShadowsocksInboundError::invalid_config(format!(
                        "AEAD 2022 requires a Base64-encoded key: {}",
                        e
                    )));
                }
            }
        }

        Ok(())
    }

    /// Build a Shadowsocks `ServerConfig` from this configuration
    ///
    /// # Errors
    ///
    /// Returns error if the configuration is invalid or cipher is not supported.
    #[cfg(feature = "shadowsocks")]
    pub fn build_server_config(&self) -> ShadowsocksInboundResult<ServerConfig> {
        use crate::shadowsocks::ShadowsocksError;

        self.validate()?;

        let cipher_kind = self.method.to_cipher_kind().map_err(|e| {
            ShadowsocksInboundError::Shadowsocks(e)
        })?;

        let server_addr = ServerAddr::SocketAddr(self.listen);

        ServerConfig::new(server_addr, self.password.clone(), cipher_kind).map_err(|e| {
            ShadowsocksInboundError::invalid_config(format!("failed to create server config: {}", e))
        })
    }

    /// Build a Shadowsocks context for server mode
    #[cfg(feature = "shadowsocks")]
    pub fn build_context() -> SharedContext {
        SsContext::new_shared(ServerType::Server)
    }

    /// Check if UDP is enabled
    #[must_use]
    pub fn is_udp_enabled(&self) -> bool {
        self.udp_enabled
    }
}

impl Default for ShadowsocksInboundConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen: "0.0.0.0:8388".parse().unwrap(),
            method: ShadowsocksMethod::default(),
            password: String::new(),
            udp_enabled: false,
        }
    }
}

/// Status information for Shadowsocks inbound
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowsocksInboundStatus {
    /// Whether the listener is active
    pub active: bool,

    /// Listen address
    pub listen: SocketAddr,

    /// Encryption method
    pub method: String,

    /// Whether UDP is enabled
    pub udp_enabled: bool,

    /// Total connections accepted
    pub connections_accepted: u64,

    /// Active connections
    pub active_connections: u64,

    /// Total bytes received
    pub bytes_received: u64,

    /// Total bytes sent
    pub bytes_sent: u64,
}

impl Default for ShadowsocksInboundStatus {
    fn default() -> Self {
        Self {
            active: false,
            listen: "0.0.0.0:8388".parse().unwrap(),
            method: ShadowsocksMethod::default().to_string(),
            udp_enabled: false,
            connections_accepted: 0,
            active_connections: 0,
            bytes_received: 0,
            bytes_sent: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_new() {
        let config = ShadowsocksInboundConfig::new(
            "0.0.0.0:8388".parse().unwrap(),
            "test-password",
        );

        assert!(config.enabled);
        assert_eq!(config.listen.port(), 8388);
        assert_eq!(config.password, "test-password");
        assert_eq!(config.method, ShadowsocksMethod::default());
        assert!(!config.udp_enabled);
    }

    #[test]
    fn test_config_builder() {
        let config = ShadowsocksInboundConfig::new(
            "0.0.0.0:8388".parse().unwrap(),
            "test-password",
        )
        .with_method(ShadowsocksMethod::Aes256Gcm)
        .with_udp(true)
        .with_enabled(false);

        assert!(!config.enabled);
        assert_eq!(config.method, ShadowsocksMethod::Aes256Gcm);
        assert!(config.udp_enabled);
    }

    #[test]
    fn test_config_validate_empty_password() {
        let config = ShadowsocksInboundConfig {
            password: String::new(),
            ..Default::default()
        };

        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_validate_legacy_aead() {
        // Legacy AEAD accepts plaintext passwords
        let config = ShadowsocksInboundConfig::new(
            "0.0.0.0:8388".parse().unwrap(),
            "my-plain-password",
        )
        .with_method(ShadowsocksMethod::Aes256Gcm);

        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_validate_aead_2022_valid() {
        // AEAD 2022 requires Base64-encoded 32-byte key
        let key = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &[0u8; 32],
        );

        let config = ShadowsocksInboundConfig::new(
            "0.0.0.0:8388".parse().unwrap(),
            key,
        )
        .with_method(ShadowsocksMethod::Aead2022Blake3Aes256Gcm);

        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_validate_aead_2022_invalid_base64() {
        let config = ShadowsocksInboundConfig::new(
            "0.0.0.0:8388".parse().unwrap(),
            "not-base64!!!",
        )
        .with_method(ShadowsocksMethod::Aead2022Blake3Aes256Gcm);

        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_validate_aead_2022_wrong_key_length() {
        // Only 16 bytes, but AES-256 needs 32
        let key = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &[0u8; 16],
        );

        let config = ShadowsocksInboundConfig::new(
            "0.0.0.0:8388".parse().unwrap(),
            key,
        )
        .with_method(ShadowsocksMethod::Aead2022Blake3Aes256Gcm);

        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_default() {
        let config = ShadowsocksInboundConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.listen.port(), 8388);
        assert!(config.password.is_empty());
    }

    #[test]
    fn test_config_serialization() {
        let config = ShadowsocksInboundConfig::new(
            "0.0.0.0:8388".parse().unwrap(),
            "secret-password",
        )
        .with_method(ShadowsocksMethod::Aes256Gcm)
        .with_udp(true);

        let json = serde_json::to_string_pretty(&config).unwrap();
        assert!(json.contains("secret-password"));
        assert!(json.contains("aes-256-gcm"));

        let deserialized: ShadowsocksInboundConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.password, config.password);
        assert_eq!(deserialized.method, config.method);
        assert_eq!(deserialized.udp_enabled, config.udp_enabled);
    }

    #[test]
    fn test_status_default() {
        let status = ShadowsocksInboundStatus::default();
        assert!(!status.active);
        assert_eq!(status.connections_accepted, 0);
        assert_eq!(status.active_connections, 0);
    }
}
