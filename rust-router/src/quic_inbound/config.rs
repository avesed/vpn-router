//! Configuration types for QUIC inbound listener
//!
//! This module provides configuration structures for the QUIC inbound listener,
//! including TLS certificate/key configuration and connection settings.
//!
//! # Example
//!
//! ```
//! use rust_router::quic_inbound::QuicInboundConfig;
//! use std::net::SocketAddr;
//!
//! let config = QuicInboundConfig {
//!     enabled: true,
//!     listen: "0.0.0.0:443".parse().unwrap(),
//!     cert_path: Some("/path/to/cert.pem".into()),
//!     key_path: Some("/path/to/key.pem".into()),
//!     cert_pem: None,
//!     key_pem: None,
//!     alpn: vec!["h3".to_string()],
//!     idle_timeout_secs: 60,
//!     max_concurrent_streams: 100,
//! };
//! ```

use std::net::SocketAddr;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use super::error::{QuicInboundError, QuicInboundResult};
use crate::transport::quic::QuicServerConfig;

/// Configuration for QUIC inbound listener
///
/// This structure contains all settings needed to run a QUIC inbound listener,
/// including the listen address, TLS certificates, and connection parameters.
///
/// # Certificate Configuration
///
/// Certificates can be provided in two ways:
/// - File paths: `cert_path` and `key_path`
/// - PEM strings: `cert_pem` and `key_pem`
///
/// If both are provided, the PEM strings take precedence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuicInboundConfig {
    /// Whether the inbound is enabled
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// Listen address (e.g., "0.0.0.0:443")
    pub listen: SocketAddr,

    /// Path to TLS certificate file (PEM format)
    #[serde(default)]
    pub cert_path: Option<PathBuf>,

    /// Path to TLS private key file (PEM format)
    #[serde(default)]
    pub key_path: Option<PathBuf>,

    /// TLS certificate PEM data (takes precedence over cert_path)
    #[serde(default)]
    pub cert_pem: Option<String>,

    /// TLS private key PEM data (takes precedence over key_path)
    #[serde(default)]
    pub key_pem: Option<String>,

    /// ALPN protocols (e.g., ["h3"])
    #[serde(default)]
    pub alpn: Vec<String>,

    /// Idle timeout in seconds
    #[serde(default = "default_idle_timeout")]
    pub idle_timeout_secs: u64,

    /// Maximum concurrent bidirectional streams per connection
    #[serde(default = "default_max_concurrent_streams")]
    pub max_concurrent_streams: u32,
}

fn default_enabled() -> bool {
    false
}

fn default_idle_timeout() -> u64 {
    60
}

fn default_max_concurrent_streams() -> u32 {
    100
}

impl QuicInboundConfig {
    /// Create a new QUIC inbound configuration
    ///
    /// # Arguments
    ///
    /// * `listen` - Address to listen on
    #[must_use]
    pub fn new(listen: SocketAddr) -> Self {
        Self {
            enabled: true,
            listen,
            cert_path: None,
            key_path: None,
            cert_pem: None,
            key_pem: None,
            alpn: Vec::new(),
            idle_timeout_secs: default_idle_timeout(),
            max_concurrent_streams: default_max_concurrent_streams(),
        }
    }

    /// Set the certificate file path
    #[must_use]
    pub fn with_cert_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.cert_path = Some(path.into());
        self
    }

    /// Set the private key file path
    #[must_use]
    pub fn with_key_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.key_path = Some(path.into());
        self
    }

    /// Set the certificate PEM data
    #[must_use]
    pub fn with_cert_pem(mut self, pem: impl Into<String>) -> Self {
        self.cert_pem = Some(pem.into());
        self
    }

    /// Set the private key PEM data
    #[must_use]
    pub fn with_key_pem(mut self, pem: impl Into<String>) -> Self {
        self.key_pem = Some(pem.into());
        self
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

    /// Set idle timeout in seconds
    #[must_use]
    pub fn with_idle_timeout(mut self, secs: u64) -> Self {
        self.idle_timeout_secs = secs;
        self
    }

    /// Set maximum concurrent streams per connection
    #[must_use]
    pub fn with_max_concurrent_streams(mut self, max: u32) -> Self {
        self.max_concurrent_streams = max;
        self
    }

    /// Enable or disable the inbound
    #[must_use]
    pub fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    /// Validate the configuration
    ///
    /// # Errors
    ///
    /// Returns `QuicInboundError` if:
    /// - No certificate is provided (neither path nor PEM)
    /// - No private key is provided (neither path nor PEM)
    pub fn validate(&self) -> QuicInboundResult<()> {
        if self.cert_path.is_none() && self.cert_pem.is_none() {
            return Err(QuicInboundError::invalid_config(
                "no TLS certificate provided (set cert_path or cert_pem)",
            ));
        }
        if self.key_path.is_none() && self.key_pem.is_none() {
            return Err(QuicInboundError::invalid_config(
                "no TLS private key provided (set key_path or key_pem)",
            ));
        }
        Ok(())
    }

    /// Convert to `QuicServerConfig`
    ///
    /// This loads certificates from files if necessary and creates
    /// the underlying transport layer configuration.
    ///
    /// # Errors
    ///
    /// Returns `QuicInboundError` if:
    /// - Configuration validation fails
    /// - Certificate/key files cannot be read
    pub fn to_server_config(&self) -> QuicInboundResult<QuicServerConfig> {
        self.validate()?;

        let mut config = QuicServerConfig::new(self.listen)
            .with_alpn(self.alpn.clone())
            .with_idle_timeout(self.idle_timeout_secs)
            .with_max_concurrent_streams(self.max_concurrent_streams);

        // Load certificate
        if let Some(ref pem) = self.cert_pem {
            config = config.with_cert_pem(pem.as_bytes().to_vec());
        } else if let Some(ref path) = self.cert_path {
            config = config
                .with_cert_file(path)
                .map_err(|e| QuicInboundError::certificate(e.to_string()))?;
        }

        // Load private key
        if let Some(ref pem) = self.key_pem {
            config = config.with_key_pem(pem.as_bytes().to_vec());
        } else if let Some(ref path) = self.key_path {
            config = config
                .with_key_file(path)
                .map_err(|e| QuicInboundError::private_key(e.to_string()))?;
        }

        Ok(config)
    }

    /// Check if the inbound is enabled
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
}

impl Default for QuicInboundConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen: "0.0.0.0:443".parse().unwrap(),
            cert_path: None,
            key_path: None,
            cert_pem: None,
            key_pem: None,
            alpn: Vec::new(),
            idle_timeout_secs: default_idle_timeout(),
            max_concurrent_streams: default_max_concurrent_streams(),
        }
    }
}

/// Status information for QUIC inbound
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuicInboundStatus {
    /// Whether the listener is active
    pub active: bool,

    /// Listen address
    pub listen: SocketAddr,

    /// ALPN protocols
    pub alpn: Vec<String>,

    /// Total connections accepted
    pub connections_accepted: u64,

    /// Active connections
    pub active_connections: u64,

    /// Total streams accepted
    pub streams_accepted: u64,

    /// Handshake errors
    pub handshake_errors: u64,

    /// Stream errors
    pub stream_errors: u64,
}

impl Default for QuicInboundStatus {
    fn default() -> Self {
        Self {
            active: false,
            listen: "0.0.0.0:443".parse().unwrap(),
            alpn: Vec::new(),
            connections_accepted: 0,
            active_connections: 0,
            streams_accepted: 0,
            handshake_errors: 0,
            stream_errors: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_new() {
        let config = QuicInboundConfig::new("0.0.0.0:443".parse().unwrap());

        assert!(config.enabled);
        assert_eq!(config.listen.port(), 443);
        assert!(config.cert_path.is_none());
        assert!(config.key_path.is_none());
        assert!(config.cert_pem.is_none());
        assert!(config.key_pem.is_none());
        assert!(config.alpn.is_empty());
    }

    #[test]
    fn test_config_builder() {
        let config = QuicInboundConfig::new("0.0.0.0:8443".parse().unwrap())
            .with_cert_path("/path/to/cert.pem")
            .with_key_path("/path/to/key.pem")
            .with_alpn(vec!["h3", "h3-29"])
            .with_idle_timeout(120)
            .with_max_concurrent_streams(50)
            .with_enabled(false);

        assert!(!config.enabled);
        assert_eq!(config.listen.port(), 8443);
        assert_eq!(config.cert_path, Some("/path/to/cert.pem".into()));
        assert_eq!(config.key_path, Some("/path/to/key.pem".into()));
        assert_eq!(config.alpn, vec!["h3", "h3-29"]);
        assert_eq!(config.idle_timeout_secs, 120);
        assert_eq!(config.max_concurrent_streams, 50);
    }

    #[test]
    fn test_config_with_pem() {
        let config = QuicInboundConfig::new("0.0.0.0:443".parse().unwrap())
            .with_cert_pem("-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----")
            .with_key_pem("-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----");

        assert!(config.cert_pem.is_some());
        assert!(config.key_pem.is_some());
    }

    #[test]
    fn test_config_validate_no_cert() {
        let config = QuicInboundConfig::new("0.0.0.0:443".parse().unwrap())
            .with_key_path("/path/to/key.pem");

        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("certificate"));
    }

    #[test]
    fn test_config_validate_no_key() {
        let config = QuicInboundConfig::new("0.0.0.0:443".parse().unwrap())
            .with_cert_path("/path/to/cert.pem");

        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("key"));
    }

    #[test]
    fn test_config_validate_valid_paths() {
        let config = QuicInboundConfig::new("0.0.0.0:443".parse().unwrap())
            .with_cert_path("/path/to/cert.pem")
            .with_key_path("/path/to/key.pem");

        let result = config.validate();
        assert!(result.is_ok());
    }

    #[test]
    fn test_config_validate_valid_pem() {
        let config = QuicInboundConfig::new("0.0.0.0:443".parse().unwrap())
            .with_cert_pem("cert")
            .with_key_pem("key");

        let result = config.validate();
        assert!(result.is_ok());
    }

    #[test]
    fn test_config_default() {
        let config = QuicInboundConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.listen.port(), 443);
        assert!(config.cert_path.is_none());
    }

    #[test]
    fn test_config_serialization() {
        let config = QuicInboundConfig::new("0.0.0.0:8443".parse().unwrap())
            .with_cert_path("/path/to/cert.pem")
            .with_key_path("/path/to/key.pem")
            .with_alpn(vec!["h3"]);

        let json = serde_json::to_string_pretty(&config).unwrap();
        assert!(json.contains("8443"));
        assert!(json.contains("cert.pem"));
        assert!(json.contains("h3"));

        let deserialized: QuicInboundConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.listen.port(), 8443);
        assert_eq!(deserialized.alpn, vec!["h3"]);
    }

    #[test]
    fn test_status_default() {
        let status = QuicInboundStatus::default();
        assert!(!status.active);
        assert_eq!(status.connections_accepted, 0);
        assert_eq!(status.active_connections, 0);
    }

    #[test]
    fn test_status_serialization() {
        let status = QuicInboundStatus {
            active: true,
            listen: "127.0.0.1:443".parse().unwrap(),
            alpn: vec!["h3".to_string()],
            connections_accepted: 100,
            active_connections: 5,
            streams_accepted: 200,
            handshake_errors: 2,
            stream_errors: 3,
        };

        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains("100"));
        assert!(json.contains("true"));

        let deserialized: QuicInboundStatus = serde_json::from_str(&json).unwrap();
        assert!(deserialized.active);
        assert_eq!(deserialized.connections_accepted, 100);
    }
}
