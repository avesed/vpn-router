//! Configuration types for VLESS inbound listener
//!
//! This module provides configuration structures for the VLESS inbound listener,
//! including user management, TLS settings, and fallback configuration.
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
//! };
//! ```

use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

use super::error::{VlessInboundError, VlessInboundResult};
use crate::vless::{VlessAccount, VlessAccountManager};

/// Configuration for VLESS inbound listener
///
/// This structure contains all settings needed to run a VLESS inbound listener,
/// including the listen address, user accounts, TLS configuration, and fallback.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VlessInboundConfig {
    /// Listen address (e.g., "0.0.0.0:443")
    pub listen: SocketAddr,

    /// Allowed user accounts
    pub users: Vec<VlessUser>,

    /// TLS configuration (optional, for plain VLESS without TLS)
    #[serde(default)]
    pub tls: Option<InboundTlsConfig>,

    /// Fallback address for invalid requests (optional)
    ///
    /// When set, invalid requests (wrong version, unknown UUID) are forwarded
    /// to this address instead of being dropped. This helps disguise the
    /// VLESS server as a normal web server.
    #[serde(default)]
    pub fallback: Option<SocketAddr>,
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
            fallback: None,
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

    /// Set fallback address
    #[must_use]
    pub fn with_fallback(mut self, fallback: SocketAddr) -> Self {
        self.fallback = Some(fallback);
        self
    }

    /// Validate the configuration
    ///
    /// # Errors
    ///
    /// Returns `VlessInboundError::InvalidConfig` if:
    /// - No users are configured
    /// - Any user has an invalid UUID
    pub fn validate(&self) -> VlessInboundResult<()> {
        if self.users.is_empty() {
            return Err(VlessInboundError::invalid_config("no users configured"));
        }

        for user in &self.users {
            user.validate()?;
        }

        if let Some(ref tls) = self.tls {
            tls.validate()?;
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
    #[must_use]
    pub fn has_tls(&self) -> bool {
        self.tls.is_some()
    }

    /// Check if fallback is configured
    #[must_use]
    pub fn has_fallback(&self) -> bool {
        self.fallback.is_some()
    }
}

impl Default for VlessInboundConfig {
    fn default() -> Self {
        Self {
            listen: "0.0.0.0:443".parse().unwrap(),
            users: Vec::new(),
            tls: None,
            fallback: None,
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
