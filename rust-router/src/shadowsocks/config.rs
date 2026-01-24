//! Shadowsocks configuration types
//!
//! This module provides configuration types for Shadowsocks protocol,
//! including encryption methods, transport types, and outbound configuration.
//!
//! # Transport Types
//!
//! Shadowsocks can run over different transports:
//!
//! - **TCP** (default): Standard TCP connection to the Shadowsocks server
//! - **QUIC** (optional): QUIC transport for better performance over lossy networks
//!
//! # Example
//!
//! ```ignore
//! use rust_router::shadowsocks::{ShadowsocksOutboundConfig, ShadowsocksMethod, ShadowsocksTransport};
//!
//! // TCP transport (default)
//! let tcp_config = ShadowsocksOutboundConfig::new("ss.example.com", 8388, "password");
//!
//! // QUIC transport
//! let quic_config = ShadowsocksOutboundConfig::new("ss.example.com", 8388, "password")
//!     .with_quic();
//! ```

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

// ============================================================================
// Transport Configuration
// ============================================================================

/// Transport type for Shadowsocks connections
///
/// Shadowsocks can run over different transports. The default is TCP,
/// but QUIC transport is available for better performance over lossy
/// or high-latency networks.
///
/// # Feature Flags
///
/// - `transport-quic`: Required for QUIC transport support
///
/// # Example
///
/// ```
/// use rust_router::shadowsocks::ShadowsocksTransport;
///
/// // TCP transport (default)
/// let tcp = ShadowsocksTransport::default();
/// assert!(tcp.is_tcp());
///
/// // QUIC transport (when feature enabled)
/// #[cfg(feature = "transport-quic")]
/// {
///     let quic = ShadowsocksTransport::quic("ss.example.com");
///     assert!(quic.is_quic());
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ShadowsocksTransport {
    /// Standard TCP transport (default)
    Tcp,

    /// QUIC transport for improved performance
    ///
    /// QUIC provides:
    /// - 0-RTT connection resumption
    /// - Better handling of packet loss
    /// - Multiplexed streams
    /// - Built-in TLS 1.3 encryption
    #[cfg(feature = "transport-quic")]
    #[serde(rename = "quic")]
    Quic {
        /// Server Name Indication for QUIC/TLS
        /// Defaults to the server address if not specified
        #[serde(default, skip_serializing_if = "Option::is_none")]
        sni: Option<String>,

        /// ALPN protocols for QUIC negotiation
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        alpn: Vec<String>,

        /// Skip certificate verification (INSECURE - for testing only)
        #[serde(default)]
        skip_verify: bool,

        /// Idle timeout in seconds (default: 30)
        #[serde(default = "default_quic_idle_timeout")]
        idle_timeout_secs: u64,

        /// Keep-alive interval in seconds (default: 15)
        #[serde(default = "default_quic_keepalive")]
        keep_alive_secs: u64,
    },
}

#[cfg(feature = "transport-quic")]
fn default_quic_idle_timeout() -> u64 {
    30
}

#[cfg(feature = "transport-quic")]
fn default_quic_keepalive() -> u64 {
    15
}

impl Default for ShadowsocksTransport {
    fn default() -> Self {
        Self::Tcp
    }
}

impl ShadowsocksTransport {
    /// Create a new TCP transport (default)
    #[must_use]
    pub const fn tcp() -> Self {
        Self::Tcp
    }

    /// Create a new QUIC transport with default settings
    ///
    /// # Arguments
    ///
    /// * `sni` - Server Name Indication for TLS
    #[cfg(feature = "transport-quic")]
    #[must_use]
    pub fn quic(sni: impl Into<String>) -> Self {
        Self::Quic {
            sni: Some(sni.into()),
            alpn: Vec::new(),
            skip_verify: false,
            idle_timeout_secs: default_quic_idle_timeout(),
            keep_alive_secs: default_quic_keepalive(),
        }
    }

    /// Create a QUIC transport without explicit SNI (uses server address)
    #[cfg(feature = "transport-quic")]
    #[must_use]
    pub fn quic_default() -> Self {
        Self::Quic {
            sni: None,
            alpn: Vec::new(),
            skip_verify: false,
            idle_timeout_secs: default_quic_idle_timeout(),
            keep_alive_secs: default_quic_keepalive(),
        }
    }

    /// Check if this is TCP transport
    #[must_use]
    pub const fn is_tcp(&self) -> bool {
        matches!(self, Self::Tcp)
    }

    /// Check if this is QUIC transport
    #[must_use]
    pub fn is_quic(&self) -> bool {
        #[cfg(feature = "transport-quic")]
        {
            matches!(self, Self::Quic { .. })
        }
        #[cfg(not(feature = "transport-quic"))]
        {
            false
        }
    }

    /// Set ALPN protocols for QUIC transport
    ///
    /// Has no effect on TCP transport.
    #[cfg(feature = "transport-quic")]
    #[must_use]
    pub fn with_alpn<I, S>(mut self, protocols: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        if let Self::Quic { ref mut alpn, .. } = self {
            *alpn = protocols.into_iter().map(Into::into).collect();
        }
        self
    }

    /// Set SNI for QUIC transport
    ///
    /// Has no effect on TCP transport.
    #[cfg(feature = "transport-quic")]
    #[must_use]
    pub fn with_sni(mut self, server_name: impl Into<String>) -> Self {
        if let Self::Quic { ref mut sni, .. } = self {
            *sni = Some(server_name.into());
        }
        self
    }

    /// Skip certificate verification for QUIC transport (INSECURE)
    ///
    /// Has no effect on TCP transport.
    #[cfg(feature = "transport-quic")]
    #[must_use]
    pub fn insecure_skip_verify(mut self) -> Self {
        if let Self::Quic {
            ref mut skip_verify,
            ..
        } = self
        {
            *skip_verify = true;
        }
        self
    }

    /// Set idle timeout for QUIC transport
    ///
    /// Has no effect on TCP transport.
    #[cfg(feature = "transport-quic")]
    #[must_use]
    pub fn with_idle_timeout(mut self, secs: u64) -> Self {
        if let Self::Quic {
            ref mut idle_timeout_secs,
            ..
        } = self
        {
            *idle_timeout_secs = secs;
        }
        self
    }

    /// Set keep-alive interval for QUIC transport
    ///
    /// Has no effect on TCP transport.
    #[cfg(feature = "transport-quic")]
    #[must_use]
    pub fn with_keep_alive(mut self, secs: u64) -> Self {
        if let Self::Quic {
            ref mut keep_alive_secs,
            ..
        } = self
        {
            *keep_alive_secs = secs;
        }
        self
    }
}

impl std::fmt::Display for ShadowsocksTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tcp => write!(f, "tcp"),
            #[cfg(feature = "transport-quic")]
            Self::Quic { sni, .. } => {
                if let Some(sni) = sni {
                    write!(f, "quic (sni: {})", sni)
                } else {
                    write!(f, "quic")
                }
            }
        }
    }
}

/// Shadowsocks outbound configuration
///
/// This struct contains all configuration needed to connect to a Shadowsocks server.
///
/// # Example
///
/// ```ignore
/// use rust_router::shadowsocks::{ShadowsocksOutboundConfig, ShadowsocksMethod};
///
/// // TCP transport (default)
/// let tcp_config = ShadowsocksOutboundConfig::new("ss.example.com", 8388, "password")
///     .with_method(ShadowsocksMethod::Aead2022Blake3Aes256Gcm);
///
/// // QUIC transport
/// let quic_config = ShadowsocksOutboundConfig::new("ss.example.com", 8388, "password")
///     .with_quic()
///     .with_quic_sni("example.com");
/// ```
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

    /// Transport type (TCP or QUIC)
    ///
    /// Default is TCP. QUIC requires the `transport-quic` feature.
    #[serde(default)]
    pub transport: ShadowsocksTransport,
}

impl ShadowsocksOutboundConfig {
    /// Create a new Shadowsocks configuration with TCP transport
    #[must_use]
    pub fn new(server: impl Into<String>, server_port: u16, password: impl Into<String>) -> Self {
        Self {
            server: server.into(),
            server_port,
            method: ShadowsocksMethod::default(),
            password: password.into(),
            udp: false,
            transport: ShadowsocksTransport::default(),
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

    /// Set the transport type
    #[must_use]
    pub fn with_transport(mut self, transport: ShadowsocksTransport) -> Self {
        self.transport = transport;
        self
    }

    /// Use QUIC transport with default settings
    ///
    /// SNI will be set to the server address by default.
    #[cfg(feature = "transport-quic")]
    #[must_use]
    pub fn with_quic(mut self) -> Self {
        self.transport = ShadowsocksTransport::quic_default();
        self
    }

    /// Set SNI for QUIC transport
    ///
    /// Only has effect when using QUIC transport.
    #[cfg(feature = "transport-quic")]
    #[must_use]
    pub fn with_quic_sni(mut self, sni: impl Into<String>) -> Self {
        self.transport = self.transport.with_sni(sni);
        self
    }

    /// Set ALPN protocols for QUIC transport
    ///
    /// Only has effect when using QUIC transport.
    #[cfg(feature = "transport-quic")]
    #[must_use]
    pub fn with_quic_alpn<I, S>(mut self, protocols: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.transport = self.transport.with_alpn(protocols);
        self
    }

    /// Skip certificate verification for QUIC transport (INSECURE)
    ///
    /// Only has effect when using QUIC transport.
    #[cfg(feature = "transport-quic")]
    #[must_use]
    pub fn with_quic_insecure_skip_verify(mut self) -> Self {
        self.transport = self.transport.insecure_skip_verify();
        self
    }

    /// Check if this configuration uses QUIC transport
    #[must_use]
    pub fn is_quic(&self) -> bool {
        self.transport.is_quic()
    }

    /// Check if this configuration uses TCP transport
    #[must_use]
    pub fn is_tcp(&self) -> bool {
        self.transport.is_tcp()
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
    /// Transport type ("tcp" or "quic")
    pub transport: String,
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

    // ========================================================================
    // Transport Configuration Tests
    // ========================================================================

    #[test]
    fn test_transport_default() {
        let transport = ShadowsocksTransport::default();
        assert!(transport.is_tcp());
        assert!(!transport.is_quic());
    }

    #[test]
    fn test_transport_tcp() {
        let transport = ShadowsocksTransport::tcp();
        assert!(transport.is_tcp());
        assert!(!transport.is_quic());
        assert_eq!(transport.to_string(), "tcp");
    }

    #[cfg(feature = "transport-quic")]
    #[test]
    fn test_transport_quic() {
        let transport = ShadowsocksTransport::quic("example.com");
        assert!(!transport.is_tcp());
        assert!(transport.is_quic());
        assert!(transport.to_string().contains("quic"));
        assert!(transport.to_string().contains("example.com"));
    }

    #[cfg(feature = "transport-quic")]
    #[test]
    fn test_transport_quic_default() {
        let transport = ShadowsocksTransport::quic_default();
        assert!(transport.is_quic());
        assert_eq!(transport.to_string(), "quic");
    }

    #[cfg(feature = "transport-quic")]
    #[test]
    fn test_transport_quic_with_alpn() {
        let transport =
            ShadowsocksTransport::quic("ss.example.com").with_alpn(vec!["h3", "ss-quic"]);

        if let ShadowsocksTransport::Quic { alpn, .. } = transport {
            assert_eq!(alpn, vec!["h3", "ss-quic"]);
        } else {
            panic!("Expected QUIC transport");
        }
    }

    #[cfg(feature = "transport-quic")]
    #[test]
    fn test_transport_quic_with_sni() {
        let transport =
            ShadowsocksTransport::quic_default().with_sni("custom-sni.example.com");

        if let ShadowsocksTransport::Quic { sni, .. } = transport {
            assert_eq!(sni, Some("custom-sni.example.com".to_string()));
        } else {
            panic!("Expected QUIC transport");
        }
    }

    #[cfg(feature = "transport-quic")]
    #[test]
    fn test_transport_quic_insecure() {
        let transport = ShadowsocksTransport::quic("example.com").insecure_skip_verify();

        if let ShadowsocksTransport::Quic { skip_verify, .. } = transport {
            assert!(skip_verify);
        } else {
            panic!("Expected QUIC transport");
        }
    }

    #[cfg(feature = "transport-quic")]
    #[test]
    fn test_transport_quic_timeouts() {
        let transport = ShadowsocksTransport::quic("example.com")
            .with_idle_timeout(60)
            .with_keep_alive(30);

        if let ShadowsocksTransport::Quic {
            idle_timeout_secs,
            keep_alive_secs,
            ..
        } = transport
        {
            assert_eq!(idle_timeout_secs, 60);
            assert_eq!(keep_alive_secs, 30);
        } else {
            panic!("Expected QUIC transport");
        }
    }

    #[test]
    fn test_transport_serialization_tcp() {
        let transport = ShadowsocksTransport::Tcp;
        let json = serde_json::to_string(&transport).unwrap();
        assert!(json.contains("tcp"));

        let deserialized: ShadowsocksTransport = serde_json::from_str(&json).unwrap();
        assert!(deserialized.is_tcp());
    }

    #[cfg(feature = "transport-quic")]
    #[test]
    fn test_transport_serialization_quic() {
        let transport = ShadowsocksTransport::quic("ss.example.com")
            .with_alpn(vec!["h3"])
            .insecure_skip_verify();

        let json = serde_json::to_string(&transport).unwrap();
        assert!(json.contains("quic"));
        assert!(json.contains("ss.example.com"));
        assert!(json.contains("h3"));

        let deserialized: ShadowsocksTransport = serde_json::from_str(&json).unwrap();
        assert!(deserialized.is_quic());

        if let ShadowsocksTransport::Quic {
            sni,
            alpn,
            skip_verify,
            ..
        } = deserialized
        {
            assert_eq!(sni, Some("ss.example.com".to_string()));
            assert_eq!(alpn, vec!["h3"]);
            assert!(skip_verify);
        } else {
            panic!("Expected QUIC transport");
        }
    }

    #[test]
    fn test_config_default_transport() {
        let config = ShadowsocksOutboundConfig::new("ss.example.com", 8388, "password");
        assert!(config.is_tcp());
        assert!(!config.is_quic());
    }

    #[test]
    fn test_config_with_transport() {
        let config = ShadowsocksOutboundConfig::new("ss.example.com", 8388, "password")
            .with_transport(ShadowsocksTransport::Tcp);
        assert!(config.is_tcp());
    }

    #[cfg(feature = "transport-quic")]
    #[test]
    fn test_config_with_quic() {
        let config = ShadowsocksOutboundConfig::new("ss.example.com", 8388, "password")
            .with_quic();
        assert!(config.is_quic());
        assert!(!config.is_tcp());
    }

    #[cfg(feature = "transport-quic")]
    #[test]
    fn test_config_with_quic_sni() {
        let config = ShadowsocksOutboundConfig::new("ss.example.com", 8388, "password")
            .with_quic()
            .with_quic_sni("custom.example.com");

        if let ShadowsocksTransport::Quic { sni, .. } = &config.transport {
            assert_eq!(*sni, Some("custom.example.com".to_string()));
        } else {
            panic!("Expected QUIC transport");
        }
    }

    #[cfg(feature = "transport-quic")]
    #[test]
    fn test_config_with_quic_alpn() {
        let config = ShadowsocksOutboundConfig::new("ss.example.com", 8388, "password")
            .with_quic()
            .with_quic_alpn(vec!["ss-quic"]);

        if let ShadowsocksTransport::Quic { alpn, .. } = &config.transport {
            assert_eq!(*alpn, vec!["ss-quic"]);
        } else {
            panic!("Expected QUIC transport");
        }
    }

    #[cfg(feature = "transport-quic")]
    #[test]
    fn test_config_with_quic_insecure() {
        let config = ShadowsocksOutboundConfig::new("ss.example.com", 8388, "password")
            .with_quic()
            .with_quic_insecure_skip_verify();

        if let ShadowsocksTransport::Quic { skip_verify, .. } = &config.transport {
            assert!(*skip_verify);
        } else {
            panic!("Expected QUIC transport");
        }
    }

    #[cfg(feature = "transport-quic")]
    #[test]
    fn test_config_quic_full_chain() {
        let config = ShadowsocksOutboundConfig::new("ss.example.com", 8388, "password")
            .with_method(ShadowsocksMethod::Aead2022Blake3Aes256Gcm)
            .with_quic()
            .with_quic_sni("ss.example.com")
            .with_quic_alpn(vec!["ss-quic", "h3"])
            .with_quic_insecure_skip_verify()
            .with_udp(false);

        assert!(config.is_quic());
        assert_eq!(config.method, ShadowsocksMethod::Aead2022Blake3Aes256Gcm);
        assert!(!config.udp);

        if let ShadowsocksTransport::Quic {
            sni,
            alpn,
            skip_verify,
            ..
        } = &config.transport
        {
            assert_eq!(*sni, Some("ss.example.com".to_string()));
            assert_eq!(*alpn, vec!["ss-quic", "h3"]);
            assert!(*skip_verify);
        } else {
            panic!("Expected QUIC transport");
        }
    }

    #[test]
    fn test_config_serialization_with_transport() {
        let config = ShadowsocksOutboundConfig::new("ss.example.com", 8388, "password");
        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains("transport"));
        assert!(json.contains("tcp"));

        let deserialized: ShadowsocksOutboundConfig = serde_json::from_str(&json).unwrap();
        assert!(deserialized.is_tcp());
    }

    #[cfg(feature = "transport-quic")]
    #[test]
    fn test_config_serialization_quic_transport() {
        let config = ShadowsocksOutboundConfig::new("ss.example.com", 8388, "password")
            .with_quic()
            .with_quic_sni("example.com");

        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains("quic"));
        assert!(json.contains("example.com"));

        let deserialized: ShadowsocksOutboundConfig = serde_json::from_str(&json).unwrap();
        assert!(deserialized.is_quic());
    }
}
