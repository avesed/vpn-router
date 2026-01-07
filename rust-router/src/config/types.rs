//! Configuration types for rust-router
//!
//! This module defines all configuration structures used by the router.
//! Configuration is loaded from JSON files and can be validated at startup.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::ConfigError;

/// Root configuration structure
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    /// Listen configuration for TPROXY
    pub listen: ListenConfig,

    /// Outbound configurations
    pub outbounds: Vec<OutboundConfig>,

    /// Default outbound tag (must exist in outbounds)
    pub default_outbound: String,

    /// IPC configuration
    pub ipc: IpcConfig,

    /// Logging configuration
    #[serde(default)]
    pub log: LogConfig,

    /// Connection limits
    #[serde(default)]
    pub connection: ConnectionConfig,

    /// Routing rules configuration
    #[serde(default)]
    pub rules: RulesConfig,
}

impl Config {
    /// Validate the configuration
    ///
    /// # Errors
    ///
    /// Returns `ConfigError::ValidationError` if validation fails.
    pub fn validate(&self) -> Result<(), ConfigError> {
        // Validate listen config
        self.listen.validate()?;

        // Validate outbounds
        if self.outbounds.is_empty() {
            return Err(ConfigError::ValidationError(
                "At least one outbound must be configured".into(),
            ));
        }

        let mut tags: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for outbound in &self.outbounds {
            outbound.validate()?;
            if !tags.insert(&outbound.tag) {
                return Err(ConfigError::ValidationError(format!(
                    "Duplicate outbound tag: {}",
                    outbound.tag
                )));
            }
        }

        // Validate default_outbound exists
        if !tags.contains(self.default_outbound.as_str()) {
            return Err(ConfigError::ValidationError(format!(
                "Default outbound '{}' not found in outbounds list",
                self.default_outbound
            )));
        }

        // Validate IPC config
        self.ipc.validate()?;

        // Validate rules config
        self.rules.validate(&tags)?;

        Ok(())
    }

    /// Create a minimal default configuration
    #[must_use]
    pub fn default_config() -> Self {
        Self {
            listen: ListenConfig::default(),
            outbounds: vec![OutboundConfig::direct("direct")],
            default_outbound: "direct".into(),
            ipc: IpcConfig::default(),
            log: LogConfig::default(),
            connection: ConnectionConfig::default(),
            rules: RulesConfig::default(),
        }
    }
}

/// Listen configuration for TPROXY inbound
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ListenConfig {
    /// Listen address (e.g., "127.0.0.1:7893")
    pub address: SocketAddr,

    /// Enable TCP TPROXY
    #[serde(default = "default_true")]
    pub tcp_enabled: bool,

    /// Enable UDP TPROXY
    #[serde(default = "default_true")]
    pub udp_enabled: bool,

    /// TCP accept backlog
    #[serde(default = "default_backlog")]
    pub tcp_backlog: u32,

    /// UDP session timeout in seconds
    #[serde(default = "default_udp_timeout_secs")]
    pub udp_timeout_secs: u64,

    /// Enable SO_REUSEPORT for multi-core scaling
    #[serde(default = "default_true")]
    pub reuse_port: bool,

    /// Sniff timeout in milliseconds (for TLS SNI detection)
    #[serde(default = "default_sniff_timeout_ms")]
    pub sniff_timeout_ms: u64,

    /// Number of UDP workers (default: num_cpus)
    ///
    /// Each worker binds to the same address with SO_REUSEPORT.
    /// The kernel distributes packets across workers based on 4-tuple hash.
    #[serde(default)]
    pub udp_workers: Option<usize>,

    /// UDP buffer pool size (total buffers across all workers)
    ///
    /// Buffers are reused to reduce allocation overhead.
    #[serde(default = "default_udp_buffer_pool_size")]
    pub udp_buffer_pool_size: usize,
}

impl ListenConfig {
    /// Validate listen configuration
    pub fn validate(&self) -> Result<(), ConfigError> {
        if !self.tcp_enabled && !self.udp_enabled {
            return Err(ConfigError::ValidationError(
                "At least one of tcp_enabled or udp_enabled must be true".into(),
            ));
        }

        if self.tcp_backlog == 0 {
            return Err(ConfigError::ValidationError(
                "tcp_backlog must be greater than 0".into(),
            ));
        }

        if self.udp_timeout_secs == 0 {
            return Err(ConfigError::ValidationError(
                "udp_timeout_secs must be greater than 0".into(),
            ));
        }

        Ok(())
    }

    /// Get UDP session timeout as Duration
    #[must_use]
    pub const fn udp_timeout(&self) -> Duration {
        Duration::from_secs(self.udp_timeout_secs)
    }

    /// Get sniff timeout as Duration
    #[must_use]
    pub const fn sniff_timeout(&self) -> Duration {
        Duration::from_millis(self.sniff_timeout_ms)
    }
}

impl Default for ListenConfig {
    fn default() -> Self {
        Self {
            address: "127.0.0.1:7893".parse().unwrap(),
            tcp_enabled: true,
            udp_enabled: true,
            tcp_backlog: 1024,
            udp_timeout_secs: 300,
            reuse_port: true,
            sniff_timeout_ms: 300,
            udp_workers: None,
            udp_buffer_pool_size: default_udp_buffer_pool_size(),
        }
    }
}

/// Outbound configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OutboundConfig {
    /// Unique tag for this outbound
    pub tag: String,

    /// Outbound type
    #[serde(rename = "type")]
    pub outbound_type: OutboundType,

    /// Bind to specific interface (SO_BINDTODEVICE)
    #[serde(default)]
    pub bind_interface: Option<String>,

    /// Bind to specific address
    #[serde(default)]
    pub bind_address: Option<SocketAddr>,

    /// Set routing mark (SO_MARK)
    #[serde(default)]
    pub routing_mark: Option<u32>,

    /// Connection timeout in seconds
    #[serde(default = "default_connect_timeout_secs")]
    pub connect_timeout_secs: u64,

    /// Enable this outbound
    #[serde(default = "default_true")]
    pub enabled: bool,
}

impl OutboundConfig {
    /// Create a direct outbound configuration
    pub fn direct(tag: impl Into<String>) -> Self {
        Self {
            tag: tag.into(),
            outbound_type: OutboundType::Direct,
            bind_interface: None,
            bind_address: None,
            routing_mark: None,
            connect_timeout_secs: default_connect_timeout_secs(),
            enabled: true,
        }
    }

    /// Create a block outbound configuration
    pub fn block(tag: impl Into<String>) -> Self {
        Self {
            tag: tag.into(),
            outbound_type: OutboundType::Block,
            bind_interface: None,
            bind_address: None,
            routing_mark: None,
            connect_timeout_secs: 0,
            enabled: true,
        }
    }

    /// Validate outbound configuration
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.tag.is_empty() {
            return Err(ConfigError::ValidationError(
                "Outbound tag cannot be empty".into(),
            ));
        }

        // Tag must be alphanumeric with hyphens/underscores
        if !self
            .tag
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
        {
            return Err(ConfigError::ValidationError(format!(
                "Outbound tag '{}' contains invalid characters (only alphanumeric, -, _ allowed)",
                self.tag
            )));
        }

        // Interface name length limit (IFNAMSIZ = 16 on Linux)
        if let Some(ref iface) = self.bind_interface {
            if iface.len() > 15 {
                return Err(ConfigError::ValidationError(format!(
                    "Interface name '{}' too long (max 15 chars)",
                    iface
                )));
            }
        }

        Ok(())
    }

    /// Get connect timeout as Duration
    #[must_use]
    pub const fn connect_timeout(&self) -> Duration {
        Duration::from_secs(self.connect_timeout_secs)
    }
}

/// Outbound types supported by rust-router
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum OutboundType {
    /// Direct connection to destination
    Direct,

    /// Block/drop connection
    Block,

    // Future: Socks5, Shadowsocks, etc.
}

impl std::fmt::Display for OutboundType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Direct => write!(f, "direct"),
            Self::Block => write!(f, "block"),
        }
    }
}

/// IPC configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct IpcConfig {
    /// Path to Unix socket
    pub socket_path: PathBuf,

    /// Socket file mode (octal, e.g., 0o660)
    #[serde(default = "default_socket_mode")]
    pub socket_mode: u32,

    /// Enable IPC server
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Maximum message size in bytes
    #[serde(default = "default_max_message_size")]
    pub max_message_size: usize,
}

impl IpcConfig {
    /// Validate IPC configuration
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.enabled && self.socket_path.as_os_str().is_empty() {
            return Err(ConfigError::ValidationError(
                "IPC socket path cannot be empty when IPC is enabled".into(),
            ));
        }

        if self.max_message_size == 0 {
            return Err(ConfigError::ValidationError(
                "max_message_size must be greater than 0".into(),
            ));
        }

        Ok(())
    }
}

impl Default for IpcConfig {
    fn default() -> Self {
        Self {
            socket_path: PathBuf::from("/var/run/rust-router.sock"),
            socket_mode: 0o660,
            enabled: true,
            max_message_size: 1024 * 1024, // 1MB
        }
    }
}

/// Logging configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LogConfig {
    /// Log level (trace, debug, info, warn, error)
    #[serde(default = "default_log_level")]
    pub level: String,

    /// Output format: "json" or "text"
    #[serde(default = "default_log_format")]
    pub format: String,

    /// Include timestamps
    #[serde(default = "default_true")]
    pub timestamps: bool,

    /// Include target (module path)
    #[serde(default = "default_true")]
    pub target: bool,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: "info".into(),
            format: "json".into(),
            timestamps: true,
            target: true,
        }
    }
}

/// Connection pool and limits configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ConnectionConfig {
    /// Maximum concurrent connections
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,

    /// Connection idle timeout in seconds
    #[serde(default = "default_idle_timeout_secs")]
    pub idle_timeout_secs: u64,

    /// Outbound connect timeout in seconds
    #[serde(default = "default_connect_timeout_secs")]
    pub connect_timeout_secs: u64,

    /// Buffer size for bidirectional copy
    #[serde(default = "default_buffer_size")]
    pub buffer_size: usize,

    /// Graceful shutdown drain timeout in seconds
    #[serde(default = "default_drain_timeout_secs")]
    pub drain_timeout_secs: u64,
}

impl ConnectionConfig {
    /// Get idle timeout as Duration
    #[must_use]
    pub const fn idle_timeout(&self) -> Duration {
        Duration::from_secs(self.idle_timeout_secs)
    }

    /// Get connect timeout as Duration
    #[must_use]
    pub const fn connect_timeout(&self) -> Duration {
        Duration::from_secs(self.connect_timeout_secs)
    }

    /// Get drain timeout as Duration
    #[must_use]
    pub const fn drain_timeout(&self) -> Duration {
        Duration::from_secs(self.drain_timeout_secs)
    }
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self {
            max_connections: 65536,
            idle_timeout_secs: 300,
            connect_timeout_secs: 10,
            buffer_size: 64 * 1024, // 64KB
            drain_timeout_secs: 30,
        }
    }
}

/// Routing rules configuration
///
/// Defines routing rules and paths to geodata files for rule matching.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct RulesConfig {
    /// List of routing rules
    #[serde(default)]
    pub rules: Vec<RuleConfig>,

    /// Path to domain catalog JSON file (for GeoSite matching)
    #[serde(default)]
    pub domain_catalog_path: Option<PathBuf>,

    /// Path to GeoIP catalog directory (for GeoIP matching)
    #[serde(default)]
    pub geoip_catalog_path: Option<PathBuf>,
}

impl RulesConfig {
    /// Validate rules configuration
    ///
    /// # Errors
    ///
    /// Returns `ConfigError::ValidationError` if:
    /// - A rule references an outbound that doesn't exist
    /// - A rule has an invalid type
    pub fn validate(
        &self,
        valid_outbounds: &std::collections::HashSet<&str>,
    ) -> Result<(), ConfigError> {
        for (index, rule) in self.rules.iter().enumerate() {
            // Validate rule type
            if !is_valid_rule_type(&rule.rule_type) {
                return Err(ConfigError::ValidationError(format!(
                    "Rule {} has invalid type: {}",
                    index, rule.rule_type
                )));
            }

            // Validate outbound exists
            if !valid_outbounds.contains(rule.outbound.as_str()) {
                return Err(ConfigError::ValidationError(format!(
                    "Rule {} references unknown outbound: {}",
                    index, rule.outbound
                )));
            }

            // Validate target is not empty
            if rule.target.trim().is_empty() {
                return Err(ConfigError::ValidationError(format!(
                    "Rule {} has empty target",
                    index
                )));
            }
        }

        Ok(())
    }
}

/// Single rule configuration (loaded from JSON)
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RuleConfig {
    /// Unique identifier for this rule
    #[serde(default)]
    pub id: u64,

    /// Rule type: "domain", "domain_suffix", "domain_keyword", "domain_regex",
    /// "geoip", "geosite", "ip_cidr", "port", "protocol"
    #[serde(rename = "type")]
    pub rule_type: String,

    /// Target value (domain, country code, CIDR, etc.)
    pub target: String,

    /// Outbound tag to route matching traffic to
    pub outbound: String,

    /// Priority (lower values matched first)
    #[serde(default)]
    pub priority: i32,

    /// Whether this rule is enabled
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Optional tag for grouping (e.g., "__adblock__")
    #[serde(default)]
    pub tag: Option<String>,
}

/// Check if a rule type string is valid
fn is_valid_rule_type(rule_type: &str) -> bool {
    matches!(
        rule_type.to_lowercase().as_str(),
        "domain"
            | "domain_suffix"
            | "domain_keyword"
            | "domain_regex"
            | "geoip"
            | "country"
            | "geosite"
            | "domain_list"
            | "ip_cidr"
            | "ip"
            | "port"
            | "port_range"
            | "protocol"
            | "network"
    )
}

// Default value functions for serde
const fn default_true() -> bool {
    true
}

const fn default_backlog() -> u32 {
    1024
}

const fn default_udp_timeout_secs() -> u64 {
    300
}

const fn default_sniff_timeout_ms() -> u64 {
    300
}

const fn default_udp_buffer_pool_size() -> usize {
    1024 // Default 1024 buffers in pool
}

const fn default_connect_timeout_secs() -> u64 {
    10
}

const fn default_socket_mode() -> u32 {
    0o660
}

const fn default_max_message_size() -> usize {
    1024 * 1024
}

fn default_log_level() -> String {
    "info".into()
}

fn default_log_format() -> String {
    "json".into()
}

const fn default_max_connections() -> usize {
    65536
}

const fn default_idle_timeout_secs() -> u64 {
    300
}

const fn default_buffer_size() -> usize {
    64 * 1024
}

const fn default_drain_timeout_secs() -> u64 {
    30
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_validates() {
        let config = Config::default_config();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_listen_config_validation() {
        let mut config = ListenConfig::default();
        assert!(config.validate().is_ok());

        config.tcp_enabled = false;
        config.udp_enabled = false;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_outbound_config_validation() {
        let config = OutboundConfig::direct("valid-tag_123");
        assert!(config.validate().is_ok());

        let config = OutboundConfig::direct("");
        assert!(config.validate().is_err());

        let config = OutboundConfig::direct("invalid tag!");
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_duplicate_outbound_tags() {
        let config = Config {
            listen: ListenConfig::default(),
            outbounds: vec![
                OutboundConfig::direct("direct"),
                OutboundConfig::direct("direct"), // duplicate
            ],
            default_outbound: "direct".into(),
            ipc: IpcConfig::default(),
            log: LogConfig::default(),
            connection: ConnectionConfig::default(),
            rules: RulesConfig::default(),
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_missing_default_outbound() {
        let config = Config {
            listen: ListenConfig::default(),
            outbounds: vec![OutboundConfig::direct("direct")],
            default_outbound: "nonexistent".into(),
            ipc: IpcConfig::default(),
            log: LogConfig::default(),
            connection: ConnectionConfig::default(),
            rules: RulesConfig::default(),
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_rules_config_validation() {
        // Valid rule referencing existing outbound
        let rules = RulesConfig {
            rules: vec![RuleConfig {
                id: 1,
                rule_type: "domain".into(),
                target: "example.com".into(),
                outbound: "direct".into(),
                priority: 0,
                enabled: true,
                tag: None,
            }],
            domain_catalog_path: None,
            geoip_catalog_path: None,
        };

        let config = Config {
            listen: ListenConfig::default(),
            outbounds: vec![OutboundConfig::direct("direct")],
            default_outbound: "direct".into(),
            ipc: IpcConfig::default(),
            log: LogConfig::default(),
            connection: ConnectionConfig::default(),
            rules,
        };
        assert!(config.validate().is_ok());

        // Invalid: rule references non-existent outbound
        let rules = RulesConfig {
            rules: vec![RuleConfig {
                id: 1,
                rule_type: "domain".into(),
                target: "example.com".into(),
                outbound: "nonexistent".into(),
                priority: 0,
                enabled: true,
                tag: None,
            }],
            domain_catalog_path: None,
            geoip_catalog_path: None,
        };

        let config = Config {
            listen: ListenConfig::default(),
            outbounds: vec![OutboundConfig::direct("direct")],
            default_outbound: "direct".into(),
            ipc: IpcConfig::default(),
            log: LogConfig::default(),
            connection: ConnectionConfig::default(),
            rules,
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_rules_config_serialization() {
        let rules = RulesConfig {
            rules: vec![RuleConfig {
                id: 1,
                rule_type: "domain_suffix".into(),
                target: ".google.com".into(),
                outbound: "proxy".into(),
                priority: 10,
                enabled: true,
                tag: Some("search".into()),
            }],
            domain_catalog_path: Some("/etc/rust-router/domain-catalog.json".into()),
            geoip_catalog_path: None,
        };

        let json = serde_json::to_string_pretty(&rules).unwrap();
        assert!(json.contains("\"type\": \"domain_suffix\""));
        assert!(json.contains("\".google.com\""));

        let parsed: RulesConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.rules.len(), 1);
        assert_eq!(parsed.rules[0].rule_type, "domain_suffix");
        assert_eq!(parsed.rules[0].target, ".google.com");
    }

    #[test]
    fn test_config_serialization() {
        let config = Config::default_config();
        let json = serde_json::to_string_pretty(&config).unwrap();
        let parsed: Config = serde_json::from_str(&json).unwrap();
        assert_eq!(config.default_outbound, parsed.default_outbound);
    }
}
