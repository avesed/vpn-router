//! DNS engine configuration types
//!
//! This module defines all configuration structures for the DNS engine,
//! including upstream servers, caching, blocking, logging, and rate limiting.
//!
//! # Configuration Structure
//!
//! ```text
//! DnsConfig
//! ├── enabled: bool
//! ├── listen_udp: SocketAddr
//! ├── listen_tcp: SocketAddr
//! ├── upstreams: Vec<UpstreamConfig>
//! ├── cache: CacheConfig
//! │   └── negative: NegativeCacheConfig
//! ├── blocking: BlockingConfig
//! ├── logging: LoggingConfig
//! ├── tcp: TcpServerConfig
//! └── rate_limit: RateLimitConfig
//! ```
//!
//! # Example
//!
//! ```
//! use rust_router::dns::{DnsConfig, UpstreamConfig, UpstreamProtocol};
//!
//! let config = DnsConfig::default();
//! assert!(config.enabled);
//! assert_eq!(config.listen_udp.port(), 7853);
//!
//! let upstream = UpstreamConfig::new("cloudflare", "1.1.1.1:53", UpstreamProtocol::Udp);
//! assert_eq!(upstream.timeout_secs, 5);
//! ```

use std::net::SocketAddr;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use super::error::{DnsError, DnsResult};

// ============================================================================
// Main DNS Configuration
// ============================================================================

/// Main DNS engine configuration
///
/// This is the top-level configuration for the DNS engine, containing
/// all sub-configurations for upstreams, caching, blocking, and more.
///
/// # Example
///
/// ```
/// use rust_router::dns::DnsConfig;
///
/// let config = DnsConfig::default();
/// assert!(config.enabled);
/// assert_eq!(config.upstreams.len(), 0);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsConfig {
    /// Whether the DNS engine is enabled
    ///
    /// When disabled, the DNS engine will not start and all DNS
    /// queries will be handled by the system resolver.
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// UDP listen address for DNS queries
    ///
    /// Default: `127.0.0.1:7853`
    #[serde(default = "default_listen_udp")]
    pub listen_udp: SocketAddr,

    /// TCP listen address for DNS queries
    ///
    /// Default: `127.0.0.1:7853`
    #[serde(default = "default_listen_tcp")]
    pub listen_tcp: SocketAddr,

    /// Upstream DNS server configurations
    ///
    /// Queries are forwarded to these upstreams. At least one upstream
    /// must be configured for the DNS engine to function.
    #[serde(default)]
    pub upstreams: Vec<UpstreamConfig>,

    /// Cache configuration
    #[serde(default)]
    pub cache: CacheConfig,

    /// Blocking/filtering configuration
    #[serde(default)]
    pub blocking: BlockingConfig,

    /// Query logging configuration
    #[serde(default)]
    pub logging: LoggingConfig,

    /// TCP server configuration (security settings)
    #[serde(default)]
    pub tcp: TcpServerConfig,

    /// Rate limiting configuration
    #[serde(default)]
    pub rate_limit: RateLimitConfig,
}

fn default_enabled() -> bool {
    true
}

fn default_listen_udp() -> SocketAddr {
    "127.0.0.1:7853".parse().expect("valid default address")
}

fn default_listen_tcp() -> SocketAddr {
    "127.0.0.1:7853".parse().expect("valid default address")
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            listen_udp: default_listen_udp(),
            listen_tcp: default_listen_tcp(),
            upstreams: Vec::new(),
            cache: CacheConfig::default(),
            blocking: BlockingConfig::default(),
            logging: LoggingConfig::default(),
            tcp: TcpServerConfig::default(),
            rate_limit: RateLimitConfig::default(),
        }
    }
}

impl DnsConfig {
    /// Create a new DNS configuration with default values
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::dns::DnsConfig;
    ///
    /// let config = DnsConfig::new();
    /// assert!(config.enabled);
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a disabled DNS configuration
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::dns::DnsConfig;
    ///
    /// let config = DnsConfig::disabled();
    /// assert!(!config.enabled);
    /// ```
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            ..Self::default()
        }
    }

    /// Add an upstream server configuration
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::dns::{DnsConfig, UpstreamConfig, UpstreamProtocol};
    ///
    /// let config = DnsConfig::new()
    ///     .with_upstream(UpstreamConfig::new("google", "8.8.8.8:53", UpstreamProtocol::Udp))
    ///     .with_upstream(UpstreamConfig::new("cloudflare", "1.1.1.1:53", UpstreamProtocol::Udp));
    ///
    /// assert_eq!(config.upstreams.len(), 2);
    /// ```
    #[must_use]
    pub fn with_upstream(mut self, upstream: UpstreamConfig) -> Self {
        self.upstreams.push(upstream);
        self
    }

    /// Set the cache configuration
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::dns::{DnsConfig, CacheConfig};
    ///
    /// let config = DnsConfig::new()
    ///     .with_cache(CacheConfig::default().with_max_entries(5000));
    ///
    /// assert_eq!(config.cache.max_entries, 5000);
    /// ```
    #[must_use]
    pub fn with_cache(mut self, cache: CacheConfig) -> Self {
        self.cache = cache;
        self
    }

    /// Set the blocking configuration
    #[must_use]
    pub fn with_blocking(mut self, blocking: BlockingConfig) -> Self {
        self.blocking = blocking;
        self
    }

    /// Set the rate limit configuration
    #[must_use]
    pub fn with_rate_limit(mut self, rate_limit: RateLimitConfig) -> Self {
        self.rate_limit = rate_limit;
        self
    }

    /// Validate the configuration
    ///
    /// Returns an error if the configuration is invalid.
    ///
    /// # Validation Rules
    ///
    /// - At least one upstream must be configured when enabled
    /// - Upstream tags must be unique
    /// - Cache settings must be valid (min <= max TTL)
    /// - Rate limit settings must be positive
    ///
    /// # Errors
    ///
    /// Returns `DnsError::ConfigError` if validation fails.
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::dns::{DnsConfig, UpstreamConfig, UpstreamProtocol};
    ///
    /// // Valid config
    /// let config = DnsConfig::new()
    ///     .with_upstream(UpstreamConfig::new("test", "8.8.8.8:53", UpstreamProtocol::Udp));
    /// assert!(config.validate().is_ok());
    ///
    /// // Invalid config (no upstreams)
    /// let empty = DnsConfig::new();
    /// assert!(empty.validate().is_err());
    /// ```
    pub fn validate(&self) -> DnsResult<()> {
        if self.enabled && self.upstreams.is_empty() {
            return Err(DnsError::config_field(
                "at least one upstream must be configured",
                "upstreams",
            ));
        }

        // Check for duplicate upstream tags
        let mut tags = std::collections::HashSet::new();
        for upstream in &self.upstreams {
            if !tags.insert(&upstream.tag) {
                return Err(DnsError::config_field(
                    format!("duplicate upstream tag: {}", upstream.tag),
                    "upstreams",
                ));
            }
            upstream.validate()?;
        }

        self.cache.validate()?;
        self.tcp.validate()?;
        self.rate_limit.validate()?;

        Ok(())
    }
}

// ============================================================================
// Upstream Configuration
// ============================================================================

/// Upstream DNS protocol
///
/// Specifies the protocol to use when communicating with an upstream
/// DNS server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum UpstreamProtocol {
    /// Plain UDP (RFC 1035)
    ///
    /// Fast but unencrypted. Best for local or trusted networks.
    #[default]
    Udp,

    /// Plain TCP (RFC 1035)
    ///
    /// Reliable but unencrypted. Used for large responses.
    Tcp,

    /// DNS-over-HTTPS (RFC 8484)
    ///
    /// Encrypted using HTTPS. Privacy-preserving but higher latency.
    #[serde(rename = "doh")]
    Doh,

    /// DNS-over-TLS (RFC 7858)
    ///
    /// Encrypted using TLS. Good balance of privacy and performance.
    #[serde(rename = "dot")]
    Dot,

    /// DNS-over-QUIC (RFC 9250)
    ///
    /// Encrypted using QUIC. Low latency and privacy-preserving.
    /// Note: Support may be limited.
    #[serde(rename = "doq")]
    Doq,
}

impl std::fmt::Display for UpstreamProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Udp => write!(f, "udp"),
            Self::Tcp => write!(f, "tcp"),
            Self::Doh => write!(f, "doh"),
            Self::Dot => write!(f, "dot"),
            Self::Doq => write!(f, "doq"),
        }
    }
}

/// Upstream DNS server configuration
///
/// Configures a single upstream DNS server including its address,
/// protocol, timeout, and optional bootstrap servers.
///
/// # Example
///
/// ```
/// use rust_router::dns::{UpstreamConfig, UpstreamProtocol};
///
/// // Simple UDP upstream
/// let udp = UpstreamConfig::new("google", "8.8.8.8:53", UpstreamProtocol::Udp);
///
/// // DoH upstream with bootstrap
/// let doh = UpstreamConfig::new("cloudflare-doh", "https://1.1.1.1/dns-query", UpstreamProtocol::Doh)
///     .with_bootstrap(vec!["1.1.1.1".to_string()]);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamConfig {
    /// Unique identifier for this upstream
    ///
    /// Used in logging and for upstream selection rules.
    pub tag: String,

    /// Server address
    ///
    /// Format depends on protocol:
    /// - UDP/TCP: `ip:port` (e.g., `8.8.8.8:53`)
    /// - `DoH`: `https://hostname/path` (e.g., `https://dns.google/dns-query`)
    /// - `DoT`: `hostname:port` (e.g., `dns.google:853`)
    /// - `DoQ`: `hostname:port` (e.g., `dns.adguard.com:784`)
    pub address: String,

    /// Protocol to use for this upstream
    #[serde(default)]
    pub protocol: UpstreamProtocol,

    /// Query timeout in seconds
    ///
    /// Default: 5 seconds
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,

    /// Bootstrap DNS servers for hostname resolution
    ///
    /// Required for DoH/DoT/DoQ when the address contains a hostname.
    /// These IPs are used to resolve the upstream hostname.
    #[serde(default)]
    pub bootstrap: Option<Vec<String>>,
}

fn default_timeout_secs() -> u64 {
    5
}

impl UpstreamConfig {
    /// Create a new upstream configuration
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::dns::{UpstreamConfig, UpstreamProtocol};
    ///
    /// let upstream = UpstreamConfig::new("test", "8.8.8.8:53", UpstreamProtocol::Udp);
    /// assert_eq!(upstream.tag, "test");
    /// assert_eq!(upstream.timeout_secs, 5);
    /// ```
    #[must_use]
    pub fn new(tag: impl Into<String>, address: impl Into<String>, protocol: UpstreamProtocol) -> Self {
        Self {
            tag: tag.into(),
            address: address.into(),
            protocol,
            timeout_secs: default_timeout_secs(),
            bootstrap: None,
        }
    }

    /// Set the query timeout
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::dns::{UpstreamConfig, UpstreamProtocol};
    ///
    /// let upstream = UpstreamConfig::new("test", "8.8.8.8:53", UpstreamProtocol::Udp)
    ///     .with_timeout(10);
    /// assert_eq!(upstream.timeout_secs, 10);
    /// ```
    #[must_use]
    pub fn with_timeout(mut self, timeout_secs: u64) -> Self {
        self.timeout_secs = timeout_secs;
        self
    }

    /// Set bootstrap DNS servers
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::dns::{UpstreamConfig, UpstreamProtocol};
    ///
    /// let upstream = UpstreamConfig::new("doh", "https://dns.google/dns-query", UpstreamProtocol::Doh)
    ///     .with_bootstrap(vec!["8.8.8.8".to_string(), "8.8.4.4".to_string()]);
    /// assert!(upstream.bootstrap.is_some());
    /// ```
    #[must_use]
    pub fn with_bootstrap(mut self, bootstrap: Vec<String>) -> Self {
        self.bootstrap = Some(bootstrap);
        self
    }

    /// Validate the upstream configuration
    ///
    /// # Errors
    ///
    /// Returns `DnsError::ConfigError` if:
    /// - `tag` is empty
    /// - `address` is empty
    /// - `timeout_secs` is zero
    pub fn validate(&self) -> DnsResult<()> {
        if self.tag.is_empty() {
            return Err(DnsError::config_field("tag cannot be empty", "upstream.tag"));
        }

        if self.address.is_empty() {
            return Err(DnsError::config_field(
                "address cannot be empty",
                "upstream.address",
            ));
        }

        if self.timeout_secs == 0 {
            return Err(DnsError::config_field(
                "timeout must be positive",
                "upstream.timeout_secs",
            ));
        }

        // Note: DoH/DoT/DoQ with hostname may need bootstrap servers for hostname resolution.
        // This is not validated here because bootstrap might be provided through other means
        // (e.g., system resolver, pre-resolved IP in address field).

        Ok(())
    }

    /// Check if this upstream uses an encrypted protocol
    #[must_use]
    pub fn is_encrypted(&self) -> bool {
        matches!(
            self.protocol,
            UpstreamProtocol::Doh | UpstreamProtocol::Dot | UpstreamProtocol::Doq
        )
    }
}

// ============================================================================
// Cache Configuration
// ============================================================================

/// DNS cache configuration
///
/// Controls caching behavior for DNS responses, including TTL limits
/// and negative caching settings.
///
/// # Example
///
/// ```
/// use rust_router::dns::CacheConfig;
///
/// let cache = CacheConfig::default()
///     .with_max_entries(5000)
///     .with_min_ttl(120);
///
/// assert_eq!(cache.max_entries, 5000);
/// assert_eq!(cache.min_ttl_secs, 120);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    /// Whether caching is enabled
    #[serde(default = "default_cache_enabled")]
    pub enabled: bool,

    /// Maximum number of cached entries
    ///
    /// Default: 10000
    #[serde(default = "default_max_entries")]
    pub max_entries: usize,

    /// Minimum TTL in seconds
    ///
    /// Responses with TTL below this value will have their TTL
    /// increased to this minimum. Default: 60 seconds
    #[serde(default = "default_min_ttl")]
    pub min_ttl_secs: u32,

    /// Maximum TTL in seconds
    ///
    /// Responses with TTL above this value will have their TTL
    /// capped to this maximum. Default: 86400 seconds (1 day)
    #[serde(default = "default_max_ttl")]
    pub max_ttl_secs: u32,

    /// Negative cache configuration
    #[serde(default)]
    pub negative: NegativeCacheConfig,
}

fn default_cache_enabled() -> bool {
    true
}

fn default_max_entries() -> usize {
    10000
}

fn default_min_ttl() -> u32 {
    60
}

fn default_max_ttl() -> u32 {
    86400
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: default_cache_enabled(),
            max_entries: default_max_entries(),
            min_ttl_secs: default_min_ttl(),
            max_ttl_secs: default_max_ttl(),
            negative: NegativeCacheConfig::default(),
        }
    }
}

impl CacheConfig {
    /// Set the maximum number of cache entries
    #[must_use]
    pub fn with_max_entries(mut self, max_entries: usize) -> Self {
        self.max_entries = max_entries;
        self
    }

    /// Set the minimum TTL
    #[must_use]
    pub fn with_min_ttl(mut self, min_ttl_secs: u32) -> Self {
        self.min_ttl_secs = min_ttl_secs;
        self
    }

    /// Set the maximum TTL
    #[must_use]
    pub fn with_max_ttl(mut self, max_ttl_secs: u32) -> Self {
        self.max_ttl_secs = max_ttl_secs;
        self
    }

    /// Set the negative cache configuration
    #[must_use]
    pub fn with_negative(mut self, negative: NegativeCacheConfig) -> Self {
        self.negative = negative;
        self
    }

    /// Disable caching
    #[must_use]
    pub fn disabled(mut self) -> Self {
        self.enabled = false;
        self
    }

    /// Validate the cache configuration
    ///
    /// # Errors
    ///
    /// Returns `DnsError::ConfigError` if:
    /// - `min_ttl_secs` is greater than `max_ttl_secs`
    /// - `max_entries` is zero when cache is enabled
    /// - Negative cache validation fails
    /// - Negative cache `max_ttl_secs` exceeds main cache `max_ttl_secs`
    pub fn validate(&self) -> DnsResult<()> {
        if self.min_ttl_secs > self.max_ttl_secs {
            return Err(DnsError::config_field(
                format!(
                    "min_ttl ({}) cannot be greater than max_ttl ({})",
                    self.min_ttl_secs, self.max_ttl_secs
                ),
                "cache",
            ));
        }

        if self.max_entries == 0 && self.enabled {
            return Err(DnsError::config_field(
                "max_entries must be positive when cache is enabled",
                "cache.max_entries",
            ));
        }

        self.negative.validate()?;

        // Cross-validation: negative cache TTL should not exceed main cache TTL
        if self.negative.max_ttl_secs > self.max_ttl_secs {
            return Err(DnsError::config_field(
                format!(
                    "negative cache max_ttl ({}) cannot exceed cache max_ttl ({})",
                    self.negative.max_ttl_secs, self.max_ttl_secs
                ),
                "cache.negative.max_ttl_secs",
            ));
        }

        Ok(())
    }

    /// Clamp a TTL value to the configured min/max range
    #[must_use]
    pub fn clamp_ttl(&self, ttl: u32) -> u32 {
        ttl.clamp(self.min_ttl_secs, self.max_ttl_secs)
    }
}

/// Negative cache configuration
///
/// Controls caching of negative responses (NXDOMAIN, NODATA).
///
/// # Example
///
/// ```
/// use rust_router::dns::NegativeCacheConfig;
///
/// let negative = NegativeCacheConfig::default();
/// assert!(negative.enabled);
/// assert_eq!(negative.default_ttl_secs, 300);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NegativeCacheConfig {
    /// Whether negative caching is enabled
    #[serde(default = "default_negative_enabled")]
    pub enabled: bool,

    /// Default TTL for negative responses without SOA MINIMUM
    ///
    /// Default: 300 seconds (5 minutes)
    #[serde(default = "default_negative_ttl")]
    pub default_ttl_secs: u32,

    /// Respect SOA MINIMUM field for negative TTL
    ///
    /// If true, use the SOA MINIMUM field from the authority section
    /// as the negative cache TTL. Default: true
    #[serde(default = "default_respect_soa")]
    pub respect_soa_minimum: bool,

    /// Maximum TTL for negative responses
    ///
    /// Default: 3600 seconds (1 hour)
    #[serde(default = "default_negative_max_ttl")]
    pub max_ttl_secs: u32,
}

fn default_negative_enabled() -> bool {
    true
}

fn default_negative_ttl() -> u32 {
    300
}

fn default_respect_soa() -> bool {
    true
}

fn default_negative_max_ttl() -> u32 {
    3600
}

impl Default for NegativeCacheConfig {
    fn default() -> Self {
        Self {
            enabled: default_negative_enabled(),
            default_ttl_secs: default_negative_ttl(),
            respect_soa_minimum: default_respect_soa(),
            max_ttl_secs: default_negative_max_ttl(),
        }
    }
}

impl NegativeCacheConfig {
    /// Validate the negative cache configuration
    ///
    /// # Errors
    ///
    /// Returns `DnsError::ConfigError` if `default_ttl_secs` is greater than `max_ttl_secs`.
    pub fn validate(&self) -> DnsResult<()> {
        if self.default_ttl_secs > self.max_ttl_secs {
            return Err(DnsError::config_field(
                format!(
                    "default_ttl ({}) cannot be greater than max_ttl ({})",
                    self.default_ttl_secs, self.max_ttl_secs
                ),
                "cache.negative",
            ));
        }

        Ok(())
    }
}

// ============================================================================
// Blocking Configuration
// ============================================================================

/// Blocking response type
///
/// Determines how blocked domains are handled in responses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum BlockResponseType {
    /// Return 0.0.0.0 for A queries and :: for AAAA queries
    ///
    /// This is the default and most compatible option. Blocked domains
    /// resolve to null addresses, causing connection attempts to fail quickly.
    #[default]
    #[serde(rename = "zero_ip")]
    ZeroIp,

    /// Return NXDOMAIN (domain does not exist)
    ///
    /// Makes the domain appear non-existent. Some applications may
    /// retry or show error messages differently than with `ZeroIp`.
    Nxdomain,

    /// Return REFUSED (server refuses to answer)
    ///
    /// Indicates the server refuses to answer. Applications may try
    /// alternative DNS servers.
    Refused,
}

impl std::fmt::Display for BlockResponseType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ZeroIp => write!(f, "zero_ip"),
            Self::Nxdomain => write!(f, "nxdomain"),
            Self::Refused => write!(f, "refused"),
        }
    }
}

/// Blocking/filtering configuration
///
/// Controls domain blocking behavior including CNAME detection.
///
/// # Example
///
/// ```
/// use rust_router::dns::{BlockingConfig, BlockResponseType};
///
/// let blocking = BlockingConfig::default();
/// assert!(blocking.enabled);
/// assert_eq!(blocking.response_type, BlockResponseType::ZeroIp);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockingConfig {
    /// Whether blocking is enabled
    #[serde(default = "default_blocking_enabled")]
    pub enabled: bool,

    /// How to respond to blocked queries
    #[serde(default)]
    pub response_type: BlockResponseType,

    /// Enable CNAME detection
    ///
    /// When enabled, CNAME chains are followed and each target is
    /// checked against blocking rules. Default: true
    #[serde(default = "default_cname_detection")]
    pub cname_detection: bool,

    /// Maximum CNAME chain depth to follow
    ///
    /// Limits how many CNAMEs to resolve when checking for blocked
    /// domains. Default: 5
    #[serde(default = "default_cname_max_depth")]
    pub cname_max_depth: u8,
}

fn default_blocking_enabled() -> bool {
    true
}

fn default_cname_detection() -> bool {
    true
}

fn default_cname_max_depth() -> u8 {
    5
}

impl Default for BlockingConfig {
    fn default() -> Self {
        Self {
            enabled: default_blocking_enabled(),
            response_type: BlockResponseType::default(),
            cname_detection: default_cname_detection(),
            cname_max_depth: default_cname_max_depth(),
        }
    }
}

impl BlockingConfig {
    /// Disable blocking
    #[must_use]
    pub fn disabled(mut self) -> Self {
        self.enabled = false;
        self
    }

    /// Set the response type for blocked queries
    #[must_use]
    pub fn with_response_type(mut self, response_type: BlockResponseType) -> Self {
        self.response_type = response_type;
        self
    }

    /// Enable or disable CNAME detection
    #[must_use]
    pub fn with_cname_detection(mut self, enabled: bool) -> Self {
        self.cname_detection = enabled;
        self
    }
}

// ============================================================================
// Logging Configuration
// ============================================================================

/// Query log format
///
/// Determines the format used for DNS query logging.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    /// JSON format (one JSON object per line)
    ///
    /// Easiest to parse programmatically. Includes all fields.
    #[default]
    Json,

    /// Tab-separated values
    ///
    /// More compact than JSON. Good for log aggregation.
    Tsv,

    /// Binary format (compact bincode encoding)
    ///
    /// Most space-efficient but requires special tooling to read.
    Binary,
}

impl std::fmt::Display for LogFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Json => write!(f, "json"),
            Self::Tsv => write!(f, "tsv"),
            Self::Binary => write!(f, "binary"),
        }
    }
}

/// Query logging configuration
///
/// Controls DNS query logging including format and rotation.
///
/// # Example
///
/// ```
/// use rust_router::dns::{LoggingConfig, LogFormat};
///
/// let logging = LoggingConfig::default();
/// assert!(!logging.enabled); // Disabled by default for privacy
/// assert_eq!(logging.format, LogFormat::Json);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Whether query logging is enabled
    ///
    /// Disabled by default for privacy reasons.
    #[serde(default)]
    pub enabled: bool,

    /// Log format
    #[serde(default)]
    pub format: LogFormat,

    /// Path to log file
    ///
    /// Default: `./dns-queries.log`
    #[serde(default = "default_log_path")]
    pub path: PathBuf,

    /// Log rotation interval in days
    ///
    /// Default: 7 days
    #[serde(default = "default_rotation_days")]
    pub rotation_days: u32,

    /// Maximum number of rotated log files to keep
    ///
    /// Default: 7
    #[serde(default = "default_max_files")]
    pub max_files: u32,

    /// In-memory buffer size (number of entries)
    ///
    /// Queries are buffered before writing to reduce I/O.
    /// Default: 10000
    #[serde(default = "default_buffer_size")]
    pub buffer_size: usize,
}

fn default_log_path() -> PathBuf {
    PathBuf::from("./dns-queries.log")
}

fn default_rotation_days() -> u32 {
    7
}

fn default_max_files() -> u32 {
    7
}

fn default_buffer_size() -> usize {
    10000
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            format: LogFormat::default(),
            path: default_log_path(),
            rotation_days: default_rotation_days(),
            max_files: default_max_files(),
            buffer_size: default_buffer_size(),
        }
    }
}

impl LoggingConfig {
    /// Enable logging with default settings
    #[must_use]
    pub fn enabled(mut self) -> Self {
        self.enabled = true;
        self
    }

    /// Set the log format
    #[must_use]
    pub fn with_format(mut self, format: LogFormat) -> Self {
        self.format = format;
        self
    }

    /// Set the log path
    #[must_use]
    pub fn with_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.path = path.into();
        self
    }
}

// ============================================================================
// TCP Server Configuration
// ============================================================================

/// TCP server security configuration
///
/// Controls connection limits and timeouts for the TCP DNS server
/// to prevent resource exhaustion attacks.
///
/// # Example
///
/// ```
/// use rust_router::dns::TcpServerConfig;
///
/// let tcp = TcpServerConfig::default();
/// assert_eq!(tcp.max_connections, 1000);
/// assert_eq!(tcp.per_ip_max_connections, 10);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpServerConfig {
    /// Maximum total concurrent TCP connections
    ///
    /// Default: 1000
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,

    /// Maximum concurrent connections per client IP
    ///
    /// Default: 10
    #[serde(default = "default_per_ip_max")]
    pub per_ip_max_connections: usize,

    /// Connection timeout in seconds
    ///
    /// Maximum time to wait for a complete query after connection.
    /// Default: 30 seconds
    #[serde(default = "default_connection_timeout")]
    pub connection_timeout_secs: u64,

    /// Idle timeout in seconds
    ///
    /// Close connection after this idle period.
    /// Default: 10 seconds
    #[serde(default = "default_idle_timeout")]
    pub idle_timeout_secs: u64,

    /// Maximum DNS message size
    ///
    /// Default: 65535 (maximum for DNS over TCP)
    #[serde(default = "default_max_message_size")]
    pub max_message_size: usize,
}

fn default_max_connections() -> usize {
    1000
}

fn default_per_ip_max() -> usize {
    10
}

fn default_connection_timeout() -> u64 {
    30
}

fn default_idle_timeout() -> u64 {
    10
}

fn default_max_message_size() -> usize {
    65535
}

impl Default for TcpServerConfig {
    fn default() -> Self {
        Self {
            max_connections: default_max_connections(),
            per_ip_max_connections: default_per_ip_max(),
            connection_timeout_secs: default_connection_timeout(),
            idle_timeout_secs: default_idle_timeout(),
            max_message_size: default_max_message_size(),
        }
    }
}

impl TcpServerConfig {
    /// Validate the TCP server configuration
    ///
    /// # Errors
    ///
    /// Returns `DnsError::ConfigError` if:
    /// - `max_connections` is zero
    /// - `per_ip_max_connections` is zero
    /// - `per_ip_max_connections` exceeds `max_connections`
    /// - `connection_timeout_secs` is zero
    /// - `max_message_size` is less than 512 bytes
    pub fn validate(&self) -> DnsResult<()> {
        if self.max_connections == 0 {
            return Err(DnsError::config_field(
                "max_connections must be positive",
                "tcp.max_connections",
            ));
        }

        if self.per_ip_max_connections == 0 {
            return Err(DnsError::config_field(
                "per_ip_max_connections must be positive",
                "tcp.per_ip_max_connections",
            ));
        }

        if self.per_ip_max_connections > self.max_connections {
            return Err(DnsError::config_field(
                format!(
                    "per_ip_max_connections ({}) cannot exceed max_connections ({})",
                    self.per_ip_max_connections, self.max_connections
                ),
                "tcp",
            ));
        }

        if self.connection_timeout_secs == 0 {
            return Err(DnsError::config_field(
                "connection_timeout must be positive",
                "tcp.connection_timeout_secs",
            ));
        }

        if self.max_message_size < 512 {
            return Err(DnsError::config_field(
                "max_message_size must be at least 512 bytes",
                "tcp.max_message_size",
            ));
        }

        Ok(())
    }
}

// ============================================================================
// Rate Limit Configuration
// ============================================================================

/// Rate limiting configuration
///
/// Controls per-client query rate limiting to prevent abuse.
///
/// # Example
///
/// ```
/// use rust_router::dns::RateLimitConfig;
///
/// let rate_limit = RateLimitConfig::default();
/// assert!(rate_limit.enabled);
/// assert_eq!(rate_limit.qps_per_client, 100);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Whether rate limiting is enabled
    #[serde(default = "default_rate_limit_enabled")]
    pub enabled: bool,

    /// Maximum queries per second per client
    ///
    /// Default: 100
    #[serde(default = "default_qps")]
    pub qps_per_client: u32,

    /// Burst size (token bucket capacity)
    ///
    /// Allows temporary bursts above the QPS limit.
    /// Default: 200
    #[serde(default = "default_burst")]
    pub burst_size: u32,
}

fn default_rate_limit_enabled() -> bool {
    true
}

fn default_qps() -> u32 {
    100
}

fn default_burst() -> u32 {
    200
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: default_rate_limit_enabled(),
            qps_per_client: default_qps(),
            burst_size: default_burst(),
        }
    }
}

impl RateLimitConfig {
    /// Disable rate limiting
    #[must_use]
    pub fn disabled(mut self) -> Self {
        self.enabled = false;
        self
    }

    /// Set the queries per second limit
    #[must_use]
    pub fn with_qps(mut self, qps: u32) -> Self {
        self.qps_per_client = qps;
        self
    }

    /// Set the burst size
    #[must_use]
    pub fn with_burst(mut self, burst: u32) -> Self {
        self.burst_size = burst;
        self
    }

    /// Validate the rate limit configuration
    ///
    /// # Errors
    ///
    /// Returns `DnsError::ConfigError` if:
    /// - `qps_per_client` is zero when rate limiting is enabled
    /// - `burst_size` is zero when rate limiting is enabled
    /// - `burst_size` is less than `qps_per_client`
    pub fn validate(&self) -> DnsResult<()> {
        if self.enabled && self.qps_per_client == 0 {
            return Err(DnsError::config_field(
                "qps_per_client must be positive when rate limiting is enabled",
                "rate_limit.qps_per_client",
            ));
        }

        if self.enabled && self.burst_size == 0 {
            return Err(DnsError::config_field(
                "burst_size must be positive when rate limiting is enabled",
                "rate_limit.burst_size",
            ));
        }

        if self.burst_size < self.qps_per_client {
            return Err(DnsError::config_field(
                format!(
                    "burst_size ({}) should be at least qps_per_client ({})",
                    self.burst_size, self.qps_per_client
                ),
                "rate_limit",
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // DnsConfig Tests
    // ========================================================================

    #[test]
    fn test_dns_config_default() {
        let config = DnsConfig::default();
        assert!(config.enabled);
        assert_eq!(config.listen_udp, "127.0.0.1:7853".parse().unwrap());
        assert_eq!(config.listen_tcp, "127.0.0.1:7853".parse().unwrap());
        assert!(config.upstreams.is_empty());
    }

    #[test]
    fn test_dns_config_disabled() {
        let config = DnsConfig::disabled();
        assert!(!config.enabled);
    }

    #[test]
    fn test_dns_config_with_upstream() {
        let config = DnsConfig::new()
            .with_upstream(UpstreamConfig::new("test", "8.8.8.8:53", UpstreamProtocol::Udp));
        assert_eq!(config.upstreams.len(), 1);
        assert_eq!(config.upstreams[0].tag, "test");
    }

    #[test]
    fn test_dns_config_validation_no_upstreams() {
        let config = DnsConfig::new();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_dns_config_validation_valid() {
        let config = DnsConfig::new()
            .with_upstream(UpstreamConfig::new("test", "8.8.8.8:53", UpstreamProtocol::Udp));
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_dns_config_validation_duplicate_tags() {
        let config = DnsConfig::new()
            .with_upstream(UpstreamConfig::new("test", "8.8.8.8:53", UpstreamProtocol::Udp))
            .with_upstream(UpstreamConfig::new("test", "1.1.1.1:53", UpstreamProtocol::Udp));
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_dns_config_serialization() {
        let config = DnsConfig::new()
            .with_upstream(UpstreamConfig::new("google", "8.8.8.8:53", UpstreamProtocol::Udp));

        let json = serde_json::to_string(&config).unwrap();
        let parsed: DnsConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.enabled, config.enabled);
        assert_eq!(parsed.upstreams.len(), 1);
    }

    // ========================================================================
    // UpstreamConfig Tests
    // ========================================================================

    #[test]
    fn test_upstream_config_new() {
        let upstream = UpstreamConfig::new("test", "8.8.8.8:53", UpstreamProtocol::Udp);
        assert_eq!(upstream.tag, "test");
        assert_eq!(upstream.address, "8.8.8.8:53");
        assert_eq!(upstream.protocol, UpstreamProtocol::Udp);
        assert_eq!(upstream.timeout_secs, 5);
        assert!(upstream.bootstrap.is_none());
    }

    #[test]
    fn test_upstream_config_with_timeout() {
        let upstream = UpstreamConfig::new("test", "8.8.8.8:53", UpstreamProtocol::Udp)
            .with_timeout(10);
        assert_eq!(upstream.timeout_secs, 10);
    }

    #[test]
    fn test_upstream_config_with_bootstrap() {
        let upstream = UpstreamConfig::new("doh", "https://dns.google/dns-query", UpstreamProtocol::Doh)
            .with_bootstrap(vec!["8.8.8.8".to_string()]);
        assert!(upstream.bootstrap.is_some());
        assert_eq!(upstream.bootstrap.as_ref().unwrap().len(), 1);
    }

    #[test]
    fn test_upstream_config_is_encrypted() {
        assert!(!UpstreamConfig::new("t", "1.1.1.1:53", UpstreamProtocol::Udp).is_encrypted());
        assert!(!UpstreamConfig::new("t", "1.1.1.1:53", UpstreamProtocol::Tcp).is_encrypted());
        assert!(UpstreamConfig::new("t", "https://dns.google", UpstreamProtocol::Doh).is_encrypted());
        assert!(UpstreamConfig::new("t", "dns.google:853", UpstreamProtocol::Dot).is_encrypted());
        assert!(UpstreamConfig::new("t", "dns.adguard.com:784", UpstreamProtocol::Doq).is_encrypted());
    }

    #[test]
    fn test_upstream_config_validation_empty_tag() {
        let upstream = UpstreamConfig::new("", "8.8.8.8:53", UpstreamProtocol::Udp);
        assert!(upstream.validate().is_err());
    }

    #[test]
    fn test_upstream_config_validation_empty_address() {
        let upstream = UpstreamConfig::new("test", "", UpstreamProtocol::Udp);
        assert!(upstream.validate().is_err());
    }

    #[test]
    fn test_upstream_config_validation_zero_timeout() {
        let mut upstream = UpstreamConfig::new("test", "8.8.8.8:53", UpstreamProtocol::Udp);
        upstream.timeout_secs = 0;
        assert!(upstream.validate().is_err());
    }

    // ========================================================================
    // UpstreamProtocol Tests
    // ========================================================================

    #[test]
    fn test_upstream_protocol_display() {
        assert_eq!(format!("{}", UpstreamProtocol::Udp), "udp");
        assert_eq!(format!("{}", UpstreamProtocol::Tcp), "tcp");
        assert_eq!(format!("{}", UpstreamProtocol::Doh), "doh");
        assert_eq!(format!("{}", UpstreamProtocol::Dot), "dot");
        assert_eq!(format!("{}", UpstreamProtocol::Doq), "doq");
    }

    #[test]
    fn test_upstream_protocol_serialization() {
        let json = serde_json::to_string(&UpstreamProtocol::Doh).unwrap();
        assert_eq!(json, "\"doh\"");

        let parsed: UpstreamProtocol = serde_json::from_str("\"dot\"").unwrap();
        assert_eq!(parsed, UpstreamProtocol::Dot);
    }

    // ========================================================================
    // CacheConfig Tests
    // ========================================================================

    #[test]
    fn test_cache_config_default() {
        let cache = CacheConfig::default();
        assert!(cache.enabled);
        assert_eq!(cache.max_entries, 10000);
        assert_eq!(cache.min_ttl_secs, 60);
        assert_eq!(cache.max_ttl_secs, 86400);
    }

    #[test]
    fn test_cache_config_builder() {
        let cache = CacheConfig::default()
            .with_max_entries(5000)
            .with_min_ttl(120)
            .with_max_ttl(43200);

        assert_eq!(cache.max_entries, 5000);
        assert_eq!(cache.min_ttl_secs, 120);
        assert_eq!(cache.max_ttl_secs, 43200);
    }

    #[test]
    fn test_cache_config_clamp_ttl() {
        let cache = CacheConfig::default()
            .with_min_ttl(60)
            .with_max_ttl(3600);

        assert_eq!(cache.clamp_ttl(30), 60);    // Below min
        assert_eq!(cache.clamp_ttl(300), 300);  // Within range
        assert_eq!(cache.clamp_ttl(7200), 3600); // Above max
    }

    #[test]
    fn test_cache_config_validation_invalid_ttl() {
        let cache = CacheConfig::default()
            .with_min_ttl(1000)
            .with_max_ttl(500);
        assert!(cache.validate().is_err());
    }

    #[test]
    fn test_cache_config_validation_zero_entries() {
        let mut cache = CacheConfig::default();
        cache.max_entries = 0;
        assert!(cache.validate().is_err());
    }

    // ========================================================================
    // NegativeCacheConfig Tests
    // ========================================================================

    #[test]
    fn test_negative_cache_config_default() {
        let negative = NegativeCacheConfig::default();
        assert!(negative.enabled);
        assert_eq!(negative.default_ttl_secs, 300);
        assert!(negative.respect_soa_minimum);
        assert_eq!(negative.max_ttl_secs, 3600);
    }

    #[test]
    fn test_negative_cache_config_validation_invalid_ttl() {
        let mut negative = NegativeCacheConfig::default();
        negative.default_ttl_secs = 7200;
        negative.max_ttl_secs = 3600;
        assert!(negative.validate().is_err());
    }

    #[test]
    fn test_cache_config_validation_negative_exceeds_main() {
        // Negative cache max_ttl (3600) exceeds main cache max_ttl (1800)
        let mut cache = CacheConfig::default();
        cache.max_ttl_secs = 1800; // Set main cache max TTL lower
        cache.negative.max_ttl_secs = 3600; // Negative cache max TTL higher
        let result = cache.validate();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("negative cache max_ttl"));
    }

    #[test]
    fn test_cache_config_validation_negative_within_main() {
        // Negative cache max_ttl (1800) within main cache max_ttl (86400)
        let mut cache = CacheConfig::default();
        cache.negative.max_ttl_secs = 1800;
        assert!(cache.validate().is_ok());
    }

    // ========================================================================
    // BlockingConfig Tests
    // ========================================================================

    #[test]
    fn test_blocking_config_default() {
        let blocking = BlockingConfig::default();
        assert!(blocking.enabled);
        assert_eq!(blocking.response_type, BlockResponseType::ZeroIp);
        assert!(blocking.cname_detection);
        assert_eq!(blocking.cname_max_depth, 5);
    }

    #[test]
    fn test_blocking_config_builder() {
        let blocking = BlockingConfig::default()
            .with_response_type(BlockResponseType::Nxdomain)
            .with_cname_detection(false);

        assert_eq!(blocking.response_type, BlockResponseType::Nxdomain);
        assert!(!blocking.cname_detection);
    }

    #[test]
    fn test_block_response_type_display() {
        assert_eq!(format!("{}", BlockResponseType::ZeroIp), "zero_ip");
        assert_eq!(format!("{}", BlockResponseType::Nxdomain), "nxdomain");
        assert_eq!(format!("{}", BlockResponseType::Refused), "refused");
    }

    // ========================================================================
    // LoggingConfig Tests
    // ========================================================================

    #[test]
    fn test_logging_config_default() {
        let logging = LoggingConfig::default();
        assert!(!logging.enabled);
        assert_eq!(logging.format, LogFormat::Json);
        assert_eq!(logging.rotation_days, 7);
        assert_eq!(logging.max_files, 7);
        assert_eq!(logging.buffer_size, 10000);
    }

    #[test]
    fn test_logging_config_builder() {
        let logging = LoggingConfig::default()
            .enabled()
            .with_format(LogFormat::Tsv)
            .with_path("/var/log/dns.log");

        assert!(logging.enabled);
        assert_eq!(logging.format, LogFormat::Tsv);
        assert_eq!(logging.path, PathBuf::from("/var/log/dns.log"));
    }

    #[test]
    fn test_log_format_display() {
        assert_eq!(format!("{}", LogFormat::Json), "json");
        assert_eq!(format!("{}", LogFormat::Tsv), "tsv");
        assert_eq!(format!("{}", LogFormat::Binary), "binary");
    }

    // ========================================================================
    // TcpServerConfig Tests
    // ========================================================================

    #[test]
    fn test_tcp_server_config_default() {
        let tcp = TcpServerConfig::default();
        assert_eq!(tcp.max_connections, 1000);
        assert_eq!(tcp.per_ip_max_connections, 10);
        assert_eq!(tcp.connection_timeout_secs, 30);
        assert_eq!(tcp.idle_timeout_secs, 10);
        assert_eq!(tcp.max_message_size, 65535);
    }

    #[test]
    fn test_tcp_server_config_validation_zero_max() {
        let mut tcp = TcpServerConfig::default();
        tcp.max_connections = 0;
        assert!(tcp.validate().is_err());
    }

    #[test]
    fn test_tcp_server_config_validation_per_ip_exceeds_max() {
        let mut tcp = TcpServerConfig::default();
        tcp.per_ip_max_connections = 2000;
        tcp.max_connections = 1000;
        assert!(tcp.validate().is_err());
    }

    #[test]
    fn test_tcp_server_config_validation_small_message_size() {
        let mut tcp = TcpServerConfig::default();
        tcp.max_message_size = 256;
        assert!(tcp.validate().is_err());
    }

    // ========================================================================
    // RateLimitConfig Tests
    // ========================================================================

    #[test]
    fn test_rate_limit_config_default() {
        let rate_limit = RateLimitConfig::default();
        assert!(rate_limit.enabled);
        assert_eq!(rate_limit.qps_per_client, 100);
        assert_eq!(rate_limit.burst_size, 200);
    }

    #[test]
    fn test_rate_limit_config_builder() {
        let rate_limit = RateLimitConfig::default()
            .with_qps(50)
            .with_burst(100);

        assert_eq!(rate_limit.qps_per_client, 50);
        assert_eq!(rate_limit.burst_size, 100);
    }

    #[test]
    fn test_rate_limit_config_validation_zero_qps() {
        let mut rate_limit = RateLimitConfig::default();
        rate_limit.qps_per_client = 0;
        assert!(rate_limit.validate().is_err());
    }

    #[test]
    fn test_rate_limit_config_validation_burst_less_than_qps() {
        let rate_limit = RateLimitConfig::default()
            .with_qps(100)
            .with_burst(50);
        assert!(rate_limit.validate().is_err());
    }

    #[test]
    fn test_rate_limit_config_disabled_validation() {
        let rate_limit = RateLimitConfig::default()
            .disabled()
            .with_qps(0);
        assert!(rate_limit.validate().is_ok());
    }
}
