//! Configuration types for VLESS inbound listener
//!
//! This module provides configuration structures for the VLESS inbound listener,
//! including user management, TLS settings, REALITY settings, and fallback configuration.
//!
//! # Example
//!
//! ```
//! use rust_router::vless_inbound::{VlessInboundConfig, VlessUser, InboundTlsConfig};
//! use std::net::SocketAddr;
//!
//! // Create a simple configuration
//! let config = VlessInboundConfig {
//!     listen: "0.0.0.0:443".parse().unwrap(),
//!     users: vec![
//!         VlessUser::new("550e8400-e29b-41d4-a716-446655440000", Some("admin@example.com")),
//!     ],
//!     tls: Some(InboundTlsConfig::new("/path/to/cert.pem", "/path/to/key.pem")),
//!     fallback: Some("127.0.0.1:80".parse().unwrap()),
//!     reality: None,
//!     udp_enabled: true,
//! };
//! ```

use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

use super::error::{VlessInboundError, VlessInboundResult};
use crate::reality::server::RealityServerConfig;
use crate::vless::{VlessAccount, VlessAccountManager};

/// Configuration for VLESS inbound listener
///
/// This structure contains all settings needed to run a VLESS inbound listener,
/// including the listen address, user accounts, TLS configuration, REALITY
/// configuration, and fallback.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VlessInboundConfig {
    /// Listen address (e.g., "0.0.0.0:443")
    pub listen: SocketAddr,

    /// Allowed user accounts
    pub users: Vec<VlessUser>,

    /// TLS configuration (optional, for plain VLESS without TLS)
    ///
    /// Note: When REALITY is enabled, this is ignored as REALITY handles TLS.
    #[serde(default)]
    pub tls: Option<InboundTlsConfig>,

    /// REALITY configuration (optional, for VLESS with REALITY camouflage)
    ///
    /// When enabled, incoming connections are validated using the REALITY
    /// protocol. Valid connections proceed with VLESS, while invalid
    /// connections are transparently proxied to the fallback destination
    /// specified in the REALITY config.
    #[serde(default)]
    pub reality: Option<InboundRealityConfig>,

    /// Fallback address for invalid requests (optional)
    ///
    /// When set, invalid requests (wrong version, unknown UUID) are forwarded
    /// to this address instead of being dropped. This helps disguise the
    /// VLESS server as a normal web server.
    ///
    /// Note: When REALITY is enabled, the REALITY config's `dest` field is
    /// used for fallback instead.
    #[serde(default)]
    pub fallback: Option<SocketAddr>,

    /// Enable UDP support (default: true)
    ///
    /// When enabled, VLESS command 0x02 (UDP) is accepted and forwarded
    /// through the VLESS-WG bridge. Supports both Basic and XUDP modes.
    /// Disable to only allow TCP connections.
    #[serde(default = "default_udp_enabled")]
    pub udp_enabled: bool,
}

fn default_udp_enabled() -> bool {
    true
}

/// Default maximum timestamp difference for REALITY (2 minutes)
fn default_max_time_diff_ms() -> u64 {
    120_000
}

/// REALITY configuration for inbound connections
///
/// This structure contains the REALITY protocol settings needed to validate
/// incoming TLS connections and provide camouflage through fallback proxying.
///
/// # Example
///
/// ```
/// use rust_router::vless_inbound::InboundRealityConfig;
///
/// let config = InboundRealityConfig {
///     private_key: "base64_encoded_private_key".to_string(),
///     short_ids: vec!["12345678".to_string(), "abcdef01".to_string()],
///     dest: "www.google.com:443".to_string(),
///     server_names: vec!["www.google.com".to_string()],
///     max_time_diff_ms: 120_000,
/// };
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboundRealityConfig {
    /// Server private key (Base64-encoded X25519, 32 bytes)
    pub private_key: String,

    /// Allowed short IDs (hex strings, up to 16 characters each)
    ///
    /// Each short ID is used for client authentication. Clients must use
    /// one of these IDs in their encrypted session_id.
    pub short_ids: Vec<String>,

    /// Fallback destination (e.g., "www.google.com:443")
    ///
    /// Unauthenticated connections are transparently proxied to this address,
    /// making the server indistinguishable from a real TLS server.
    pub dest: String,

    /// Allowed SNI server names
    ///
    /// Connections with SNI not in this list are rejected and proxied to fallback.
    pub server_names: Vec<String>,

    /// Maximum timestamp difference in milliseconds (default: 120000 = 2 minutes)
    ///
    /// REALITY validates that the timestamp in the encrypted session_id is
    /// within this range of the server's current time.
    #[serde(default = "default_max_time_diff_ms")]
    pub max_time_diff_ms: u64,
}

impl InboundRealityConfig {
    /// Create a new REALITY inbound configuration
    ///
    /// # Arguments
    /// * `private_key` - Base64-encoded X25519 private key
    /// * `dest` - Fallback destination address
    #[must_use]
    pub fn new(private_key: impl Into<String>, dest: impl Into<String>) -> Self {
        Self {
            private_key: private_key.into(),
            short_ids: Vec::new(),
            dest: dest.into(),
            server_names: Vec::new(),
            max_time_diff_ms: default_max_time_diff_ms(),
        }
    }

    /// Add an allowed short ID
    #[must_use]
    pub fn with_short_id(mut self, short_id: impl Into<String>) -> Self {
        self.short_ids.push(short_id.into());
        self
    }

    /// Add an allowed server name
    #[must_use]
    pub fn with_server_name(mut self, name: impl Into<String>) -> Self {
        self.server_names.push(name.into());
        self
    }

    /// Set maximum timestamp difference
    #[must_use]
    pub fn with_max_time_diff_ms(mut self, ms: u64) -> Self {
        self.max_time_diff_ms = ms;
        self
    }

    /// Validate the configuration
    ///
    /// # Errors
    ///
    /// Returns error if configuration is invalid.
    pub fn validate(&self) -> VlessInboundResult<()> {
        // Validate private key is valid Base64
        if self.private_key.is_empty() {
            return Err(VlessInboundError::invalid_config("REALITY private_key is empty"));
        }

        let key_bytes = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &self.private_key,
        )
        .map_err(|e| {
            VlessInboundError::invalid_config(format!("Invalid REALITY private_key Base64: {}", e))
        })?;

        if key_bytes.len() != 32 {
            return Err(VlessInboundError::invalid_config(format!(
                "REALITY private_key has invalid length: {} (expected 32 bytes)",
                key_bytes.len()
            )));
        }

        // Validate short IDs
        if self.short_ids.is_empty() {
            return Err(VlessInboundError::invalid_config(
                "REALITY short_ids is empty",
            ));
        }

        for (i, short_id) in self.short_ids.iter().enumerate() {
            if short_id.is_empty() || short_id.len() > 16 {
                return Err(VlessInboundError::invalid_config(format!(
                    "REALITY short_id[{}] has invalid length: {} (expected 1-16 hex chars)",
                    i,
                    short_id.len()
                )));
            }

            // Validate hex
            if hex::decode(short_id).is_err() {
                return Err(VlessInboundError::invalid_config(format!(
                    "REALITY short_id[{}] is not valid hex: {}",
                    i, short_id
                )));
            }
        }

        // Validate dest
        if self.dest.is_empty() {
            return Err(VlessInboundError::invalid_config("REALITY dest is empty"));
        }

        // Validate server names
        if self.server_names.is_empty() {
            return Err(VlessInboundError::invalid_config(
                "REALITY server_names is empty",
            ));
        }

        if self.max_time_diff_ms == 0 {
            return Err(VlessInboundError::invalid_config(
                "REALITY max_time_diff_ms cannot be zero",
            ));
        }

        Ok(())
    }

    /// Build a `RealityServerConfig` from this configuration
    ///
    /// # Errors
    ///
    /// Returns error if configuration is invalid.
    pub fn build_server_config(&self) -> VlessInboundResult<RealityServerConfig> {
        self.validate()?;

        // Decode private key
        let key_bytes = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &self.private_key,
        )
        .map_err(|e| {
            VlessInboundError::invalid_config(format!("Invalid REALITY private_key: {}", e))
        })?;

        let mut private_key = [0u8; 32];
        private_key.copy_from_slice(&key_bytes);

        // Decode short IDs
        let short_ids: Vec<Vec<u8>> = self
            .short_ids
            .iter()
            .map(|s| {
                let mut id = hex::decode(s).unwrap_or_default();
                // Pad to 8 bytes
                while id.len() < 8 {
                    id.push(0);
                }
                id.truncate(8);
                id
            })
            .collect();

        Ok(RealityServerConfig {
            private_key,
            short_ids,
            dest: self.dest.clone(),
            server_names: self.server_names.clone(),
            max_time_diff_ms: self.max_time_diff_ms,
        })
    }

    /// Get the server's public key derived from private key
    ///
    /// # Errors
    ///
    /// Returns error if private key is invalid.
    pub fn public_key(&self) -> VlessInboundResult<String> {
        let key_bytes = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &self.private_key,
        )
        .map_err(|e| {
            VlessInboundError::invalid_config(format!("Invalid REALITY private_key: {}", e))
        })?;

        if key_bytes.len() != 32 {
            return Err(VlessInboundError::invalid_config(
                "REALITY private_key has invalid length",
            ));
        }

        let mut private_key = [0u8; 32];
        private_key.copy_from_slice(&key_bytes);

        use x25519_dalek::{PublicKey, StaticSecret};
        let secret = StaticSecret::from(private_key);
        let public = PublicKey::from(&secret);

        Ok(base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            public.as_bytes(),
        ))
    }
}

impl VlessInboundConfig {
    /// Create a new VLESS inbound configuration
    ///
    /// # Arguments
    ///
    /// * `listen` - Address to listen on
    #[must_use]
    pub fn new(listen: SocketAddr) -> Self {
        Self {
            listen,
            users: Vec::new(),
            tls: None,
            reality: None,
            fallback: None,
            udp_enabled: true,
        }
    }

    /// Add a user to the configuration
    #[must_use]
    pub fn with_user(mut self, user: VlessUser) -> Self {
        self.users.push(user);
        self
    }

    /// Add multiple users to the configuration
    #[must_use]
    pub fn with_users(mut self, users: impl IntoIterator<Item = VlessUser>) -> Self {
        self.users.extend(users);
        self
    }

    /// Set TLS configuration
    #[must_use]
    pub fn with_tls(mut self, tls: InboundTlsConfig) -> Self {
        self.tls = Some(tls);
        self
    }

    /// Set REALITY configuration
    ///
    /// When REALITY is enabled, the server validates incoming TLS connections
    /// using the REALITY protocol. Valid connections proceed with VLESS,
    /// while invalid connections are transparently proxied to fallback.
    ///
    /// Note: When REALITY is enabled, the `tls` configuration is ignored.
    #[must_use]
    pub fn with_reality(mut self, reality: InboundRealityConfig) -> Self {
        self.reality = Some(reality);
        self
    }

    /// Set fallback address
    #[must_use]
    pub fn with_fallback(mut self, fallback: SocketAddr) -> Self {
        self.fallback = Some(fallback);
        self
    }

    /// Enable or disable UDP support
    ///
    /// When disabled, only TCP connections (VLESS command 0x01) are accepted.
    /// UDP connections (command 0x02) will be rejected.
    #[must_use]
    pub fn with_udp_enabled(mut self, enabled: bool) -> Self {
        self.udp_enabled = enabled;
        self
    }

    /// Check if UDP is enabled
    #[must_use]
    pub fn is_udp_enabled(&self) -> bool {
        self.udp_enabled
    }

    /// Validate the configuration
    ///
    /// # Errors
    ///
    /// Returns `VlessInboundError::InvalidConfig` if:
    /// - No users are configured
    /// - Any user has an invalid UUID
    /// - TLS configuration is invalid (when enabled)
    /// - REALITY configuration is invalid (when enabled)
    pub fn validate(&self) -> VlessInboundResult<()> {
        if self.users.is_empty() {
            return Err(VlessInboundError::invalid_config("no users configured"));
        }

        for user in &self.users {
            user.validate()?;
        }

        // Validate TLS config (only if REALITY is not enabled)
        if let Some(ref tls) = self.tls {
            if self.reality.is_none() {
                tls.validate()?;
            }
        }

        // Validate REALITY config
        if let Some(ref reality) = self.reality {
            reality.validate()?;
        }

        Ok(())
    }

    /// Build an account manager from the configuration
    ///
    /// # Errors
    ///
    /// Returns error if any user UUID is invalid.
    pub fn build_account_manager(&self) -> VlessInboundResult<VlessAccountManager> {
        let mut manager = VlessAccountManager::with_capacity(self.users.len());

        for user in &self.users {
            let account = user.to_account()?;
            manager.add_account(account);
        }

        Ok(manager)
    }

    /// Check if TLS is enabled
    ///
    /// Note: Returns false when REALITY is enabled, as REALITY handles TLS.
    #[must_use]
    pub fn has_tls(&self) -> bool {
        self.tls.is_some() && self.reality.is_none()
    }

    /// Check if REALITY is enabled
    #[must_use]
    pub fn has_reality(&self) -> bool {
        self.reality.is_some()
    }

    /// Check if fallback is configured
    #[must_use]
    pub fn has_fallback(&self) -> bool {
        self.fallback.is_some()
    }

    /// Build the REALITY server from configuration
    ///
    /// # Errors
    ///
    /// Returns error if REALITY is not configured or configuration is invalid.
    pub fn build_reality_server(&self) -> VlessInboundResult<crate::reality::RealityServer> {
        let reality = self.reality.as_ref().ok_or_else(|| {
            VlessInboundError::invalid_config("REALITY is not configured")
        })?;

        let server_config = reality.build_server_config()?;
        Ok(crate::reality::RealityServer::new(server_config))
    }
}

impl Default for VlessInboundConfig {
    fn default() -> Self {
        Self {
            listen: "0.0.0.0:443".parse().unwrap(),
            users: Vec::new(),
            tls: None,
            reality: None,
            fallback: None,
            udp_enabled: true,
        }
    }
}

/// VLESS user configuration
///
/// Each user is identified by a UUID which serves as the authentication credential.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VlessUser {
    /// UUID in standard format (e.g., "550e8400-e29b-41d4-a716-446655440000")
    pub uuid: String,

    /// Optional email for identification/logging
    #[serde(default)]
    pub email: Option<String>,

    /// Optional flow type (e.g., "xtls-rprx-vision")
    ///
    /// If set, only connections with this flow type are accepted.
    /// If not set, any flow type is accepted.
    #[serde(default)]
    pub flow: Option<String>,
}

impl VlessUser {
    /// Create a new VLESS user
    ///
    /// # Arguments
    ///
    /// * `uuid` - UUID string in standard format
    /// * `email` - Optional email address
    #[must_use]
    pub fn new(uuid: impl Into<String>, email: Option<impl Into<String>>) -> Self {
        Self {
            uuid: uuid.into(),
            email: email.map(Into::into),
            flow: None,
        }
    }

    /// Set the flow type for this user
    #[must_use]
    pub fn with_flow(mut self, flow: impl Into<String>) -> Self {
        self.flow = Some(flow.into());
        self
    }

    /// Validate the user configuration
    ///
    /// # Errors
    ///
    /// Returns error if the UUID is invalid.
    pub fn validate(&self) -> VlessInboundResult<()> {
        // Try to parse UUID to validate format
        uuid::Uuid::parse_str(&self.uuid).map_err(|e| {
            VlessInboundError::invalid_config(format!("invalid UUID '{}': {}", self.uuid, e))
        })?;

        Ok(())
    }

    /// Convert to `VlessAccount`
    ///
    /// # Errors
    ///
    /// Returns error if the UUID is invalid.
    pub fn to_account(&self) -> VlessInboundResult<VlessAccount> {
        VlessAccount::from_uuid_str(&self.uuid, self.email.clone())
            .map_err(|e| VlessInboundError::invalid_config(format!("invalid UUID: {}", e)))
    }
}

/// TLS configuration for inbound connections
///
/// This structure contains the paths to certificate and private key files,
/// as well as optional ALPN protocols.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboundTlsConfig {
    /// Path to the certificate file (PEM format)
    pub cert_path: String,

    /// Path to the private key file (PEM format)
    pub key_path: String,

    /// ALPN protocols (e.g., ["h2", "http/1.1"])
    #[serde(default)]
    pub alpn: Vec<String>,
}

impl InboundTlsConfig {
    /// Create a new TLS configuration
    ///
    /// # Arguments
    ///
    /// * `cert_path` - Path to certificate file
    /// * `key_path` - Path to private key file
    #[must_use]
    pub fn new(cert_path: impl Into<String>, key_path: impl Into<String>) -> Self {
        Self {
            cert_path: cert_path.into(),
            key_path: key_path.into(),
            alpn: Vec::new(),
        }
    }

    /// Set ALPN protocols
    #[must_use]
    pub fn with_alpn<I, S>(mut self, protocols: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.alpn = protocols.into_iter().map(Into::into).collect();
        self
    }

    /// Validate the TLS configuration
    ///
    /// # Errors
    ///
    /// Returns error if paths are empty.
    pub fn validate(&self) -> VlessInboundResult<()> {
        if self.cert_path.is_empty() {
            return Err(VlessInboundError::invalid_config(
                "certificate path is empty",
            ));
        }

        if self.key_path.is_empty() {
            return Err(VlessInboundError::invalid_config(
                "private key path is empty",
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vless_user_new() {
        let user = VlessUser::new("550e8400-e29b-41d4-a716-446655440000", Some("test@example.com"));
        assert_eq!(user.uuid, "550e8400-e29b-41d4-a716-446655440000");
        assert_eq!(user.email, Some("test@example.com".to_string()));
        assert!(user.flow.is_none());
    }

    #[test]
    fn test_vless_user_with_flow() {
        let user = VlessUser::new("550e8400-e29b-41d4-a716-446655440000", None::<String>)
            .with_flow("xtls-rprx-vision");
        assert_eq!(user.flow, Some("xtls-rprx-vision".to_string()));
    }

    #[test]
    fn test_vless_user_validate_valid() {
        let user =
            VlessUser::new("550e8400-e29b-41d4-a716-446655440000", Some("test@example.com"));
        assert!(user.validate().is_ok());
    }

    #[test]
    fn test_vless_user_validate_invalid() {
        let user = VlessUser::new("not-a-valid-uuid", None::<String>);
        assert!(user.validate().is_err());
    }

    #[test]
    fn test_vless_user_to_account() {
        let user =
            VlessUser::new("550e8400-e29b-41d4-a716-446655440000", Some("test@example.com"));
        let account = user.to_account().unwrap();
        assert_eq!(account.email(), Some("test@example.com"));
    }

    #[test]
    fn test_inbound_tls_config_new() {
        let tls = InboundTlsConfig::new("/path/to/cert.pem", "/path/to/key.pem");
        assert_eq!(tls.cert_path, "/path/to/cert.pem");
        assert_eq!(tls.key_path, "/path/to/key.pem");
        assert!(tls.alpn.is_empty());
    }

    #[test]
    fn test_inbound_tls_config_with_alpn() {
        let tls = InboundTlsConfig::new("/path/to/cert.pem", "/path/to/key.pem")
            .with_alpn(vec!["h2", "http/1.1"]);
        assert_eq!(tls.alpn, vec!["h2", "http/1.1"]);
    }

    #[test]
    fn test_inbound_tls_config_validate() {
        let tls = InboundTlsConfig::new("/path/to/cert.pem", "/path/to/key.pem");
        assert!(tls.validate().is_ok());

        let tls = InboundTlsConfig::new("", "/path/to/key.pem");
        assert!(tls.validate().is_err());

        let tls = InboundTlsConfig::new("/path/to/cert.pem", "");
        assert!(tls.validate().is_err());
    }

    #[test]
    fn test_vless_inbound_config_new() {
        let config = VlessInboundConfig::new("0.0.0.0:443".parse().unwrap());
        assert_eq!(config.listen.port(), 443);
        assert!(config.users.is_empty());
        assert!(config.tls.is_none());
        assert!(config.fallback.is_none());
    }

    #[test]
    fn test_vless_inbound_config_builder() {
        let config = VlessInboundConfig::new("0.0.0.0:443".parse().unwrap())
            .with_user(VlessUser::new(
                "550e8400-e29b-41d4-a716-446655440000",
                Some("admin"),
            ))
            .with_tls(InboundTlsConfig::new("/cert.pem", "/key.pem"))
            .with_fallback("127.0.0.1:80".parse().unwrap());

        assert_eq!(config.users.len(), 1);
        assert!(config.has_tls());
        assert!(config.has_fallback());
    }

    #[test]
    fn test_vless_inbound_config_validate_no_users() {
        let config = VlessInboundConfig::new("0.0.0.0:443".parse().unwrap());
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_vless_inbound_config_validate_valid() {
        let config = VlessInboundConfig::new("0.0.0.0:443".parse().unwrap()).with_user(
            VlessUser::new("550e8400-e29b-41d4-a716-446655440000", Some("admin")),
        );
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_vless_inbound_config_build_account_manager() {
        let config = VlessInboundConfig::new("0.0.0.0:443".parse().unwrap())
            .with_user(VlessUser::new(
                "550e8400-e29b-41d4-a716-446655440000",
                Some("user1"),
            ))
            .with_user(VlessUser::new(
                "660e8400-e29b-41d4-a716-446655440000",
                Some("user2"),
            ));

        let manager = config.build_account_manager().unwrap();
        assert_eq!(manager.len(), 2);
    }

    #[test]
    fn test_vless_inbound_config_default() {
        let config = VlessInboundConfig::default();
        assert_eq!(config.listen.port(), 443);
        assert!(config.users.is_empty());
    }

    #[test]
    fn test_vless_inbound_config_with_users() {
        let users = vec![
            VlessUser::new("550e8400-e29b-41d4-a716-446655440000", Some("user1")),
            VlessUser::new("660e8400-e29b-41d4-a716-446655440000", Some("user2")),
        ];

        let config = VlessInboundConfig::new("0.0.0.0:443".parse().unwrap()).with_users(users);
        assert_eq!(config.users.len(), 2);
    }

    #[test]
    fn test_config_serialization() {
        let config = VlessInboundConfig::new("0.0.0.0:443".parse().unwrap())
            .with_user(VlessUser::new(
                "550e8400-e29b-41d4-a716-446655440000",
                Some("admin"),
            ))
            .with_tls(
                InboundTlsConfig::new("/cert.pem", "/key.pem").with_alpn(vec!["h2", "http/1.1"]),
            )
            .with_fallback("127.0.0.1:80".parse().unwrap());

        let json = serde_json::to_string_pretty(&config).unwrap();
        assert!(json.contains("550e8400-e29b-41d4-a716-446655440000"));
        assert!(json.contains("cert.pem"));
        assert!(json.contains("h2"));

        // Deserialize and verify
        let deserialized: VlessInboundConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.users.len(), 1);
        assert!(deserialized.tls.is_some());
        assert!(deserialized.fallback.is_some());
    }
}
