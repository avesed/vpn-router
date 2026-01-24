//! Shadowsocks configuration types
//!
//! This module provides configuration types for Shadowsocks protocol,
//! including encryption methods and outbound configuration.

use serde::{Deserialize, Serialize};

#[cfg(feature = "shadowsocks")]
use shadowsocks::crypto::CipherKind;

use super::error::ShadowsocksError;

/// Shadowsocks encryption method
///
/// Supports AEAD 2022 (recommended) and legacy AEAD v1 ciphers.
/// The default is `Aead2022Blake3Aes256Gcm`, which provides the best
/// security and performance for most use cases.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ShadowsocksMethod {
    // AEAD 2022 (recommended)
    /// 2022-blake3-aes-256-gcm - Most secure, recommended default
    #[serde(rename = "2022-blake3-aes-256-gcm")]
    Aead2022Blake3Aes256Gcm,

    /// 2022-blake3-aes-128-gcm - Good security with slightly less overhead
    #[serde(rename = "2022-blake3-aes-128-gcm")]
    Aead2022Blake3Aes128Gcm,

    /// 2022-blake3-chacha20-poly1305 - Better for devices without AES-NI
    #[serde(rename = "2022-blake3-chacha20-poly1305")]
    Aead2022Blake3Chacha20Poly1305,

    // AEAD v1 (legacy but still secure)
    /// aes-256-gcm - Legacy AEAD, widely supported
    #[serde(rename = "aes-256-gcm")]
    Aes256Gcm,

    /// aes-128-gcm - Legacy AEAD, slightly faster
    #[serde(rename = "aes-128-gcm")]
    Aes128Gcm,

    /// chacha20-ietf-poly1305 - Legacy AEAD, good for ARM devices
    #[serde(rename = "chacha20-ietf-poly1305")]
    Chacha20IetfPoly1305,

    /// No encryption (for testing only, NOT SECURE)
    #[serde(rename = "none")]
    None,
}

impl Default for ShadowsocksMethod {
    fn default() -> Self {
        Self::Aead2022Blake3Aes256Gcm
    }
}

impl ShadowsocksMethod {
    /// Convert to shadowsocks CipherKind
    ///
    /// # Errors
    ///
    /// Returns an error if the cipher is not supported by the shadowsocks crate.
    #[cfg(feature = "shadowsocks")]
    pub fn to_cipher_kind(self) -> Result<CipherKind, ShadowsocksError> {
        match self {
            Self::Aead2022Blake3Aes256Gcm => Ok(CipherKind::AEAD2022_BLAKE3_AES_256_GCM),
            Self::Aead2022Blake3Aes128Gcm => Ok(CipherKind::AEAD2022_BLAKE3_AES_128_GCM),
            Self::Aead2022Blake3Chacha20Poly1305 => {
                Ok(CipherKind::AEAD2022_BLAKE3_CHACHA20_POLY1305)
            }
            Self::Aes256Gcm => Ok(CipherKind::AES_256_GCM),
            Self::Aes128Gcm => Ok(CipherKind::AES_128_GCM),
            Self::Chacha20IetfPoly1305 => Ok(CipherKind::CHACHA20_POLY1305),
            Self::None => Ok(CipherKind::NONE),
        }
    }

    /// Get the method name as a string
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Aead2022Blake3Aes256Gcm => "2022-blake3-aes-256-gcm",
            Self::Aead2022Blake3Aes128Gcm => "2022-blake3-aes-128-gcm",
            Self::Aead2022Blake3Chacha20Poly1305 => "2022-blake3-chacha20-poly1305",
            Self::Aes256Gcm => "aes-256-gcm",
            Self::Aes128Gcm => "aes-128-gcm",
            Self::Chacha20IetfPoly1305 => "chacha20-ietf-poly1305",
            Self::None => "none",
        }
    }

    /// Check if this is an AEAD 2022 cipher (recommended)
    #[must_use]
    pub const fn is_aead_2022(&self) -> bool {
        matches!(
            self,
            Self::Aead2022Blake3Aes256Gcm
                | Self::Aead2022Blake3Aes128Gcm
                | Self::Aead2022Blake3Chacha20Poly1305
        )
    }

    /// Check if this cipher provides encryption (not "none")
    #[must_use]
    pub const fn is_encrypted(&self) -> bool {
        !matches!(self, Self::None)
    }

    /// Parse method from string
    ///
    /// # Errors
    ///
    /// Returns an error if the method string is not recognized.
    pub fn parse_method(s: &str) -> Result<Self, ShadowsocksError> {
        match s.to_lowercase().as_str() {
            "2022-blake3-aes-256-gcm" => Ok(Self::Aead2022Blake3Aes256Gcm),
            "2022-blake3-aes-128-gcm" => Ok(Self::Aead2022Blake3Aes128Gcm),
            "2022-blake3-chacha20-poly1305" => Ok(Self::Aead2022Blake3Chacha20Poly1305),
            "aes-256-gcm" => Ok(Self::Aes256Gcm),
            "aes-128-gcm" => Ok(Self::Aes128Gcm),
            "chacha20-ietf-poly1305" => Ok(Self::Chacha20IetfPoly1305),
            "none" => Ok(Self::None),
            _ => Err(ShadowsocksError::InvalidMethod(s.to_string())),
        }
    }
}

impl std::fmt::Display for ShadowsocksMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for ShadowsocksMethod {
    type Err = ShadowsocksError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse_method(s)
    }
}

/// Shadowsocks outbound configuration
///
/// This struct contains all configuration needed to connect to a Shadowsocks server.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ShadowsocksOutboundConfig {
    /// Server hostname or IP address
    pub server: String,

    /// Server port
    pub server_port: u16,

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
    pub udp: bool,
}

impl ShadowsocksOutboundConfig {
    /// Create a new Shadowsocks configuration
    #[must_use]
    pub fn new(server: impl Into<String>, server_port: u16, password: impl Into<String>) -> Self {
        Self {
            server: server.into(),
            server_port,
            method: ShadowsocksMethod::default(),
            password: password.into(),
            udp: false,
        }
    }

    /// Set the encryption method
    #[must_use]
    pub fn with_method(mut self, method: ShadowsocksMethod) -> Self {
        self.method = method;
        self
    }

    /// Enable UDP support
    #[must_use]
    pub fn with_udp(mut self, udp: bool) -> Self {
        self.udp = udp;
        self
    }

    /// Get the server address string (host:port)
    #[must_use]
    pub fn server_string(&self) -> String {
        format!("{}:{}", self.server, self.server_port)
    }

    /// Validate the configuration
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration is invalid.
    pub fn validate(&self) -> Result<(), ShadowsocksError> {
        if self.server.is_empty() {
            return Err(ShadowsocksError::ConfigError(
                "server address cannot be empty".into(),
            ));
        }

        if self.server_port == 0 {
            return Err(ShadowsocksError::ConfigError(
                "server port cannot be 0".into(),
            ));
        }

        if self.password.is_empty() {
            return Err(ShadowsocksError::InvalidPassword(
                "password cannot be empty".into(),
            ));
        }

        Ok(())
    }
}

/// Information about a Shadowsocks outbound (for IPC responses)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowsocksOutboundInfo {
    /// Outbound tag
    pub tag: String,
    /// Server address
    pub server: String,
    /// Server port
    pub server_port: u16,
    /// Encryption method
    pub method: String,
    /// Whether UDP is enabled
    pub udp: bool,
    /// Current health status
    pub health: String,
    /// Whether the outbound is enabled
    pub enabled: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_method_default() {
        let method = ShadowsocksMethod::default();
        assert_eq!(method, ShadowsocksMethod::Aead2022Blake3Aes256Gcm);
    }

    #[test]
    fn test_method_as_str() {
        assert_eq!(
            ShadowsocksMethod::Aead2022Blake3Aes256Gcm.as_str(),
            "2022-blake3-aes-256-gcm"
        );
        assert_eq!(
            ShadowsocksMethod::Aead2022Blake3Aes128Gcm.as_str(),
            "2022-blake3-aes-128-gcm"
        );
        assert_eq!(
            ShadowsocksMethod::Aead2022Blake3Chacha20Poly1305.as_str(),
            "2022-blake3-chacha20-poly1305"
        );
        assert_eq!(ShadowsocksMethod::Aes256Gcm.as_str(), "aes-256-gcm");
        assert_eq!(ShadowsocksMethod::Aes128Gcm.as_str(), "aes-128-gcm");
        assert_eq!(
            ShadowsocksMethod::Chacha20IetfPoly1305.as_str(),
            "chacha20-ietf-poly1305"
        );
        assert_eq!(ShadowsocksMethod::None.as_str(), "none");
    }

    #[test]
    fn test_method_from_str() {
        use std::str::FromStr;

        assert_eq!(
            ShadowsocksMethod::parse_method("2022-blake3-aes-256-gcm").unwrap(),
            ShadowsocksMethod::Aead2022Blake3Aes256Gcm
        );
        assert_eq!(
            ShadowsocksMethod::parse_method("aes-256-gcm").unwrap(),
            ShadowsocksMethod::Aes256Gcm
        );
        assert_eq!(
            ShadowsocksMethod::parse_method("none").unwrap(),
            ShadowsocksMethod::None
        );

        // Case insensitive
        assert_eq!(
            ShadowsocksMethod::parse_method("AES-256-GCM").unwrap(),
            ShadowsocksMethod::Aes256Gcm
        );

        // Invalid method
        assert!(ShadowsocksMethod::parse_method("invalid-cipher").is_err());

        // Test FromStr trait
        assert_eq!(
            "aes-256-gcm".parse::<ShadowsocksMethod>().unwrap(),
            ShadowsocksMethod::Aes256Gcm
        );
    }

    #[test]
    fn test_method_is_aead_2022() {
        assert!(ShadowsocksMethod::Aead2022Blake3Aes256Gcm.is_aead_2022());
        assert!(ShadowsocksMethod::Aead2022Blake3Aes128Gcm.is_aead_2022());
        assert!(ShadowsocksMethod::Aead2022Blake3Chacha20Poly1305.is_aead_2022());
        assert!(!ShadowsocksMethod::Aes256Gcm.is_aead_2022());
        assert!(!ShadowsocksMethod::Aes128Gcm.is_aead_2022());
        assert!(!ShadowsocksMethod::Chacha20IetfPoly1305.is_aead_2022());
        assert!(!ShadowsocksMethod::None.is_aead_2022());
    }

    #[test]
    fn test_method_is_encrypted() {
        assert!(ShadowsocksMethod::Aead2022Blake3Aes256Gcm.is_encrypted());
        assert!(ShadowsocksMethod::Aes256Gcm.is_encrypted());
        assert!(!ShadowsocksMethod::None.is_encrypted());
    }

    #[test]
    fn test_method_display() {
        assert_eq!(
            format!("{}", ShadowsocksMethod::Aead2022Blake3Aes256Gcm),
            "2022-blake3-aes-256-gcm"
        );
    }

    #[test]
    fn test_config_new() {
        let config = ShadowsocksOutboundConfig::new("192.168.1.1", 8388, "my-password");
        assert_eq!(config.server, "192.168.1.1");
        assert_eq!(config.server_port, 8388);
        assert_eq!(config.password, "my-password");
        assert_eq!(config.method, ShadowsocksMethod::default());
        assert!(!config.udp);
    }

    #[test]
    fn test_config_with_method() {
        let config = ShadowsocksOutboundConfig::new("server.com", 443, "pass")
            .with_method(ShadowsocksMethod::Aes256Gcm);
        assert_eq!(config.method, ShadowsocksMethod::Aes256Gcm);
    }

    #[test]
    fn test_config_with_udp() {
        let config =
            ShadowsocksOutboundConfig::new("server.com", 443, "pass").with_udp(true);
        assert!(config.udp);
    }

    #[test]
    fn test_config_server_string() {
        let config = ShadowsocksOutboundConfig::new("example.com", 8388, "pass");
        assert_eq!(config.server_string(), "example.com:8388");
    }

    #[test]
    fn test_config_validate_valid() {
        let config = ShadowsocksOutboundConfig::new("example.com", 8388, "password");
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_validate_empty_server() {
        let config = ShadowsocksOutboundConfig::new("", 8388, "password");
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_validate_zero_port() {
        let config = ShadowsocksOutboundConfig::new("example.com", 0, "password");
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_validate_empty_password() {
        let config = ShadowsocksOutboundConfig::new("example.com", 8388, "");
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_serialization() {
        let config = ShadowsocksOutboundConfig::new("ss.example.com", 8388, "secret-password")
            .with_method(ShadowsocksMethod::Aes256Gcm)
            .with_udp(true);

        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains("ss.example.com"));
        assert!(json.contains("8388"));
        assert!(json.contains("aes-256-gcm"));

        let deserialized: ShadowsocksOutboundConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.server, config.server);
        assert_eq!(deserialized.server_port, config.server_port);
        assert_eq!(deserialized.method, config.method);
        assert_eq!(deserialized.password, config.password);
        assert_eq!(deserialized.udp, config.udp);
    }

    #[test]
    fn test_config_deserialization_defaults() {
        let json = r#"{"server":"ss.example.com","server-port":8388,"password":"secret"}"#;
        let config: ShadowsocksOutboundConfig = serde_json::from_str(json).unwrap();

        assert_eq!(config.server, "ss.example.com");
        assert_eq!(config.server_port, 8388);
        assert_eq!(config.password, "secret");
        assert_eq!(config.method, ShadowsocksMethod::default()); // Uses default
        assert!(!config.udp); // Uses default false
    }

    #[cfg(feature = "shadowsocks")]
    #[test]
    fn test_method_to_cipher_kind() {
        use shadowsocks::crypto::CipherKind;

        assert_eq!(
            ShadowsocksMethod::Aead2022Blake3Aes256Gcm
                .to_cipher_kind()
                .unwrap(),
            CipherKind::AEAD2022_BLAKE3_AES_256_GCM
        );
        assert_eq!(
            ShadowsocksMethod::Aes256Gcm.to_cipher_kind().unwrap(),
            CipherKind::AES_256_GCM
        );
        assert_eq!(
            ShadowsocksMethod::None.to_cipher_kind().unwrap(),
            CipherKind::NONE
        );
    }
}
