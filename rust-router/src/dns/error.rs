//! Error types for the DNS engine module
//!
//! This module defines a comprehensive error hierarchy for DNS operations,
//! including message parsing, network I/O, upstream communication, caching,
//! and rate limiting.
//!
//! # Error Categories
//!
//! - **Parse/Serialize errors**: DNS message encoding/decoding failures
//! - **Network errors**: Socket I/O and connection issues
//! - **Upstream errors**: Upstream server communication failures
//! - **Cache errors**: Cache operation failures
//! - **Config errors**: Invalid configuration parameters
//! - **Rate limit errors**: Client rate limit exceeded
//! - **Blocking errors**: Domain blocked by policy
//!
//! # Example
//!
//! ```
//! use rust_router::dns::DnsError;
//!
//! let err = DnsError::timeout("query to 8.8.8.8:53", std::time::Duration::from_secs(5));
//! assert!(err.is_recoverable());
//! assert!(err.to_string().contains("timed out"));
//! ```

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use thiserror::Error;

/// Error types for DNS operations
///
/// `DnsError` categorizes all possible failures in the DNS engine,
/// from message parsing to network I/O to upstream server issues.
///
/// # Recoverability
///
/// Errors are classified as either recoverable or non-recoverable:
/// - **Recoverable**: Transient issues that may succeed on retry (timeouts, network errors)
/// - **Non-recoverable**: Permanent failures requiring configuration changes or intervention
#[derive(Debug, Error)]
pub enum DnsError {
    /// DNS message parsing failed
    ///
    /// This error occurs when a received DNS message cannot be decoded.
    /// Common causes include malformed packets, truncated messages,
    /// or unsupported record types.
    #[error("Failed to parse DNS message: {reason}")]
    ParseError {
        /// Description of what went wrong during parsing
        reason: String,
        /// Optional domain name involved in the parse error
        domain: Option<String>,
    },

    /// DNS message serialization failed
    ///
    /// This error occurs when a DNS message cannot be encoded for transmission.
    /// This typically indicates an internal error or invalid message construction.
    #[error("Failed to serialize DNS message: {reason}")]
    SerializeError {
        /// Description of what went wrong during serialization
        reason: String,
    },

    /// Network I/O error
    ///
    /// This error wraps low-level network errors such as socket failures,
    /// connection resets, or address binding issues.
    #[error("Network error: {reason}")]
    NetworkError {
        /// Description of the network failure
        reason: String,
        /// The underlying I/O error, if available
        #[source]
        source: Option<io::Error>,
    },

    /// Query timeout
    ///
    /// This error occurs when a DNS query does not receive a response
    /// within the configured timeout period.
    #[error("DNS query timed out after {timeout:?}: {context}")]
    TimeoutError {
        /// Description of what timed out
        context: String,
        /// The timeout duration that was exceeded
        timeout: Duration,
    },

    /// Upstream server error
    ///
    /// This error indicates a failure communicating with an upstream DNS server.
    /// This includes connection failures, protocol errors, and invalid responses.
    #[error("Upstream server error ({upstream}): {reason}")]
    UpstreamError {
        /// The upstream server address
        upstream: String,
        /// Description of the upstream failure
        reason: String,
        /// The DNS response code, if available (e.g., SERVFAIL, REFUSED)
        rcode: Option<u8>,
    },

    /// Cache operation failed
    ///
    /// This error occurs when a cache read or write operation fails.
    /// This is typically an internal error that should be rare.
    #[error("Cache error: {reason}")]
    CacheError {
        /// Description of the cache failure
        reason: String,
    },

    /// Invalid configuration
    ///
    /// This error indicates that the DNS engine configuration is invalid
    /// or contains unsupported parameters.
    #[error("Invalid DNS configuration: {reason}")]
    ConfigError {
        /// Description of the configuration error
        reason: String,
        /// The configuration field that is invalid, if applicable
        field: Option<String>,
    },

    /// Rate limit exceeded
    ///
    /// This error is returned when a client exceeds their configured
    /// query rate limit.
    #[error("Rate limit exceeded for client {client}: {qps} qps (limit: {limit} qps)")]
    RateLimitExceeded {
        /// The client address that exceeded the limit
        client: SocketAddr,
        /// The client's current query rate
        qps: u32,
        /// The configured limit
        limit: u32,
    },

    /// Domain is blocked
    ///
    /// This error indicates that a query was blocked by policy
    /// (e.g., ad blocking, parental controls).
    #[error("Domain blocked: {domain} (rule: {rule})")]
    Blocked {
        /// The blocked domain name
        domain: String,
        /// The rule or policy that caused the block
        rule: String,
    },

    /// No upstream available
    ///
    /// This error occurs when no upstream DNS servers are configured
    /// or all configured upstreams are unhealthy.
    #[error("No upstream DNS server available: {reason}")]
    NoUpstream {
        /// Reason why no upstream is available
        reason: String,
    },

    /// Invalid query
    ///
    /// This error indicates that the received query is malformed
    /// or contains invalid data (e.g., empty question section).
    #[error("Invalid DNS query: {reason}")]
    InvalidQuery {
        /// Description of why the query is invalid
        reason: String,
        /// The query ID, if available
        query_id: Option<u16>,
    },

    /// Internal processing error
    ///
    /// This error indicates an unexpected internal error during
    /// DNS processing. This should be rare and may indicate a bug.
    #[error("Internal DNS error: {reason}")]
    InternalError {
        /// Description of the internal error
        reason: String,
    },
}

impl DnsError {
    // ========================================================================
    // Constructor methods
    // ========================================================================

    /// Create a parse error
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::dns::DnsError;
    ///
    /// let err = DnsError::parse("invalid record type");
    /// assert!(err.to_string().contains("invalid record type"));
    /// ```
    pub fn parse(reason: impl Into<String>) -> Self {
        Self::ParseError {
            reason: reason.into(),
            domain: None,
        }
    }

    /// Create a parse error with domain context
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::dns::DnsError;
    ///
    /// let err = DnsError::parse_domain("label too long", "example.com");
    /// assert!(err.to_string().contains("label too long"));
    /// ```
    pub fn parse_domain(reason: impl Into<String>, domain: impl Into<String>) -> Self {
        Self::ParseError {
            reason: reason.into(),
            domain: Some(domain.into()),
        }
    }

    /// Create a serialization error
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::dns::DnsError;
    ///
    /// let err = DnsError::serialize("buffer too small");
    /// assert!(err.to_string().contains("buffer too small"));
    /// ```
    pub fn serialize(reason: impl Into<String>) -> Self {
        Self::SerializeError {
            reason: reason.into(),
        }
    }

    /// Create a network error
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::dns::DnsError;
    ///
    /// let err = DnsError::network("connection refused");
    /// assert!(err.to_string().contains("connection refused"));
    /// ```
    pub fn network(reason: impl Into<String>) -> Self {
        Self::NetworkError {
            reason: reason.into(),
            source: None,
        }
    }

    /// Create a network error from an I/O error
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::dns::DnsError;
    /// use std::io;
    ///
    /// let io_err = io::Error::new(io::ErrorKind::ConnectionRefused, "refused");
    /// let err = DnsError::network_io("connect failed", io_err);
    /// assert!(err.to_string().contains("connect failed"));
    /// ```
    pub fn network_io(reason: impl Into<String>, source: io::Error) -> Self {
        Self::NetworkError {
            reason: reason.into(),
            source: Some(source),
        }
    }

    /// Create a timeout error
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::dns::DnsError;
    /// use std::time::Duration;
    ///
    /// let err = DnsError::timeout("query to 8.8.8.8", Duration::from_secs(5));
    /// assert!(err.to_string().contains("timed out"));
    /// ```
    pub fn timeout(context: impl Into<String>, timeout: Duration) -> Self {
        Self::TimeoutError {
            context: context.into(),
            timeout,
        }
    }

    /// Create an upstream error
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::dns::DnsError;
    ///
    /// let err = DnsError::upstream("8.8.8.8:53", "connection reset");
    /// assert!(err.to_string().contains("8.8.8.8:53"));
    /// ```
    pub fn upstream(upstream: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::UpstreamError {
            upstream: upstream.into(),
            reason: reason.into(),
            rcode: None,
        }
    }

    /// Create an upstream error with response code
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::dns::DnsError;
    ///
    /// let err = DnsError::upstream_rcode("8.8.8.8:53", "server failure", 2);
    /// assert!(err.to_string().contains("server failure"));
    /// ```
    pub fn upstream_rcode(upstream: impl Into<String>, reason: impl Into<String>, rcode: u8) -> Self {
        Self::UpstreamError {
            upstream: upstream.into(),
            reason: reason.into(),
            rcode: Some(rcode),
        }
    }

    /// Create a cache error
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::dns::DnsError;
    ///
    /// let err = DnsError::cache("eviction failed");
    /// assert!(err.to_string().contains("eviction failed"));
    /// ```
    pub fn cache(reason: impl Into<String>) -> Self {
        Self::CacheError {
            reason: reason.into(),
        }
    }

    /// Create a configuration error
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::dns::DnsError;
    ///
    /// let err = DnsError::config("invalid listen address");
    /// assert!(err.to_string().contains("invalid listen address"));
    /// ```
    pub fn config(reason: impl Into<String>) -> Self {
        Self::ConfigError {
            reason: reason.into(),
            field: None,
        }
    }

    /// Create a configuration error with field context
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::dns::DnsError;
    ///
    /// let err = DnsError::config_field("must be positive", "cache.max_entries");
    /// assert!(err.to_string().contains("must be positive"));
    /// ```
    pub fn config_field(reason: impl Into<String>, field: impl Into<String>) -> Self {
        Self::ConfigError {
            reason: reason.into(),
            field: Some(field.into()),
        }
    }

    /// Create a rate limit exceeded error
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::dns::DnsError;
    /// use std::net::SocketAddr;
    ///
    /// let client: SocketAddr = "192.168.1.100:12345".parse().unwrap();
    /// let err = DnsError::rate_limit(client, 150, 100);
    /// assert!(err.to_string().contains("150 qps"));
    /// ```
    pub fn rate_limit(client: SocketAddr, qps: u32, limit: u32) -> Self {
        Self::RateLimitExceeded { client, qps, limit }
    }

    /// Create a blocked error
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::dns::DnsError;
    ///
    /// let err = DnsError::blocked("ads.example.com", "adblock-list");
    /// assert!(err.to_string().contains("ads.example.com"));
    /// ```
    pub fn blocked(domain: impl Into<String>, rule: impl Into<String>) -> Self {
        Self::Blocked {
            domain: domain.into(),
            rule: rule.into(),
        }
    }

    /// Create a no upstream available error
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::dns::DnsError;
    ///
    /// let err = DnsError::no_upstream("all upstreams unhealthy");
    /// assert!(err.to_string().contains("all upstreams unhealthy"));
    /// ```
    pub fn no_upstream(reason: impl Into<String>) -> Self {
        Self::NoUpstream {
            reason: reason.into(),
        }
    }

    /// Create an invalid query error
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::dns::DnsError;
    ///
    /// let err = DnsError::invalid_query("empty question section");
    /// assert!(err.to_string().contains("empty question section"));
    /// ```
    pub fn invalid_query(reason: impl Into<String>) -> Self {
        Self::InvalidQuery {
            reason: reason.into(),
            query_id: None,
        }
    }

    /// Create an invalid query error with query ID
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::dns::DnsError;
    ///
    /// let err = DnsError::invalid_query_id("invalid opcode", 0x1234);
    /// assert!(err.to_string().contains("invalid opcode"));
    /// ```
    pub fn invalid_query_id(reason: impl Into<String>, query_id: u16) -> Self {
        Self::InvalidQuery {
            reason: reason.into(),
            query_id: Some(query_id),
        }
    }

    /// Create an internal error
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::dns::DnsError;
    ///
    /// let err = DnsError::internal("unexpected state");
    /// assert!(err.to_string().contains("unexpected state"));
    /// ```
    pub fn internal(reason: impl Into<String>) -> Self {
        Self::InternalError {
            reason: reason.into(),
        }
    }

    // ========================================================================
    // Classification methods
    // ========================================================================

    /// Check if this error is recoverable
    ///
    /// Recoverable errors are transient and may succeed on retry.
    /// Non-recoverable errors require configuration changes or intervention.
    ///
    /// # Recoverable errors:
    /// - `NetworkError` - Transient network issues
    /// - `TimeoutError` - Query timed out, can retry
    /// - `UpstreamError` - Upstream server issue, can try another
    /// - `RateLimitExceeded` - Can retry after backoff
    ///
    /// # Non-recoverable errors:
    /// - `ParseError` - Message is malformed
    /// - `SerializeError` - Internal error
    /// - `CacheError` - Internal error
    /// - `ConfigError` - Configuration needs to be fixed
    /// - `Blocked` - Policy decision, won't change
    /// - `NoUpstream` - Configuration needs upstreams
    /// - `InvalidQuery` - Query is malformed
    /// - `InternalError` - Bug or unexpected state
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::dns::DnsError;
    /// use std::time::Duration;
    ///
    /// // Recoverable
    /// let timeout = DnsError::timeout("query", Duration::from_secs(5));
    /// assert!(timeout.is_recoverable());
    ///
    /// // Non-recoverable
    /// let config = DnsError::config("invalid address");
    /// assert!(!config.is_recoverable());
    /// ```
    #[must_use]
    pub fn is_recoverable(&self) -> bool {
        match self {
            Self::NetworkError { source, .. } => {
                // Some network errors are recoverable
                source.as_ref().is_none_or(|e| {
                    matches!(
                        e.kind(),
                        io::ErrorKind::TimedOut
                            | io::ErrorKind::Interrupted
                            | io::ErrorKind::WouldBlock
                            | io::ErrorKind::ConnectionReset
                            | io::ErrorKind::ConnectionRefused
                    )
                })
            }
            Self::TimeoutError { .. }
            | Self::UpstreamError { .. }
            | Self::RateLimitExceeded { .. } => true,
            Self::ParseError { .. }
            | Self::SerializeError { .. }
            | Self::CacheError { .. }
            | Self::ConfigError { .. }
            | Self::Blocked { .. }
            | Self::NoUpstream { .. }
            | Self::InvalidQuery { .. }
            | Self::InternalError { .. } => false,
        }
    }

    /// Check if this error indicates a blocked domain
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::dns::DnsError;
    ///
    /// let blocked = DnsError::blocked("ads.example.com", "rule1");
    /// assert!(blocked.is_blocked());
    ///
    /// let timeout = DnsError::timeout("query", std::time::Duration::from_secs(1));
    /// assert!(!timeout.is_blocked());
    /// ```
    #[must_use]
    pub fn is_blocked(&self) -> bool {
        matches!(self, Self::Blocked { .. })
    }

    /// Check if this error indicates a rate limit issue
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::dns::DnsError;
    /// use std::net::SocketAddr;
    ///
    /// let rate_limit = DnsError::rate_limit(
    ///     "192.168.1.100:12345".parse().unwrap(),
    ///     150,
    ///     100
    /// );
    /// assert!(rate_limit.is_rate_limited());
    /// ```
    #[must_use]
    pub fn is_rate_limited(&self) -> bool {
        matches!(self, Self::RateLimitExceeded { .. })
    }

    /// Check if this error indicates a timeout
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::dns::DnsError;
    /// use std::time::Duration;
    ///
    /// let timeout = DnsError::timeout("query", Duration::from_secs(5));
    /// assert!(timeout.is_timeout());
    /// ```
    #[must_use]
    pub fn is_timeout(&self) -> bool {
        matches!(self, Self::TimeoutError { .. })
    }

    /// Check if this error indicates an upstream failure
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::dns::DnsError;
    ///
    /// let upstream = DnsError::upstream("8.8.8.8:53", "connection reset");
    /// assert!(upstream.is_upstream_error());
    /// ```
    #[must_use]
    pub fn is_upstream_error(&self) -> bool {
        matches!(self, Self::UpstreamError { .. })
    }

    /// Get the domain associated with this error, if any
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::dns::DnsError;
    ///
    /// let blocked = DnsError::blocked("example.com", "rule1");
    /// assert_eq!(blocked.domain(), Some("example.com"));
    ///
    /// let timeout = DnsError::timeout("query", std::time::Duration::from_secs(1));
    /// assert_eq!(timeout.domain(), None);
    /// ```
    #[must_use]
    pub fn domain(&self) -> Option<&str> {
        match self {
            Self::ParseError { domain, .. } => domain.as_deref(),
            Self::Blocked { domain, .. } => Some(domain),
            _ => None,
        }
    }

    /// Get the upstream address associated with this error, if any
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::dns::DnsError;
    ///
    /// let upstream = DnsError::upstream("8.8.8.8:53", "error");
    /// assert_eq!(upstream.upstream_addr(), Some("8.8.8.8:53"));
    /// ```
    #[must_use]
    pub fn upstream_addr(&self) -> Option<&str> {
        match self {
            Self::UpstreamError { upstream, .. } => Some(upstream),
            _ => None,
        }
    }
}

impl From<io::Error> for DnsError {
    fn from(err: io::Error) -> Self {
        Self::NetworkError {
            reason: err.to_string(),
            source: Some(err),
        }
    }
}

/// Type alias for Result with [`DnsError`]
pub type DnsResult<T> = std::result::Result<T, DnsError>;

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // Error Creation Tests
    // ========================================================================

    #[test]
    fn test_parse_error() {
        let err = DnsError::parse("invalid header");
        assert!(matches!(err, DnsError::ParseError { .. }));
        assert!(err.to_string().contains("invalid header"));
        assert!(!err.is_recoverable());
        assert_eq!(err.domain(), None);
    }

    #[test]
    fn test_parse_error_with_domain() {
        let err = DnsError::parse_domain("label too long", "example.com");
        assert!(matches!(err, DnsError::ParseError { .. }));
        assert!(err.to_string().contains("label too long"));
        assert_eq!(err.domain(), Some("example.com"));
    }

    #[test]
    fn test_serialize_error() {
        let err = DnsError::serialize("buffer overflow");
        assert!(matches!(err, DnsError::SerializeError { .. }));
        assert!(err.to_string().contains("buffer overflow"));
        assert!(!err.is_recoverable());
    }

    #[test]
    fn test_network_error() {
        let err = DnsError::network("connection refused");
        assert!(matches!(err, DnsError::NetworkError { .. }));
        assert!(err.to_string().contains("connection refused"));
        assert!(err.is_recoverable());
    }

    #[test]
    fn test_network_error_with_io() {
        let io_err = io::Error::new(io::ErrorKind::ConnectionRefused, "refused");
        let err = DnsError::network_io("connect failed", io_err);
        assert!(matches!(err, DnsError::NetworkError { .. }));
        assert!(err.is_recoverable());
    }

    #[test]
    fn test_timeout_error() {
        let err = DnsError::timeout("query to 8.8.8.8", Duration::from_secs(5));
        assert!(matches!(err, DnsError::TimeoutError { .. }));
        assert!(err.to_string().contains("5s"));
        assert!(err.is_timeout());
        assert!(err.is_recoverable());
    }

    #[test]
    fn test_upstream_error() {
        let err = DnsError::upstream("8.8.8.8:53", "SERVFAIL");
        assert!(matches!(err, DnsError::UpstreamError { .. }));
        assert!(err.to_string().contains("8.8.8.8:53"));
        assert!(err.is_upstream_error());
        assert!(err.is_recoverable());
        assert_eq!(err.upstream_addr(), Some("8.8.8.8:53"));
    }

    #[test]
    fn test_upstream_error_with_rcode() {
        let err = DnsError::upstream_rcode("1.1.1.1:53", "server failure", 2);
        assert!(matches!(err, DnsError::UpstreamError { rcode: Some(2), .. }));
    }

    #[test]
    fn test_cache_error() {
        let err = DnsError::cache("eviction failed");
        assert!(matches!(err, DnsError::CacheError { .. }));
        assert!(err.to_string().contains("eviction failed"));
        assert!(!err.is_recoverable());
    }

    #[test]
    fn test_config_error() {
        let err = DnsError::config("invalid address");
        assert!(matches!(err, DnsError::ConfigError { .. }));
        assert!(err.to_string().contains("invalid address"));
        assert!(!err.is_recoverable());
    }

    #[test]
    fn test_config_error_with_field() {
        let err = DnsError::config_field("must be positive", "cache.max_entries");
        assert!(matches!(err, DnsError::ConfigError { field: Some(_), .. }));
    }

    #[test]
    fn test_rate_limit_error() {
        let client: SocketAddr = "192.168.1.100:12345".parse().unwrap();
        let err = DnsError::rate_limit(client, 150, 100);
        assert!(matches!(err, DnsError::RateLimitExceeded { .. }));
        assert!(err.to_string().contains("150 qps"));
        assert!(err.to_string().contains("limit: 100 qps"));
        assert!(err.is_rate_limited());
        assert!(err.is_recoverable());
    }

    #[test]
    fn test_blocked_error() {
        let err = DnsError::blocked("ads.example.com", "adblock-list");
        assert!(matches!(err, DnsError::Blocked { .. }));
        assert!(err.to_string().contains("ads.example.com"));
        assert!(err.to_string().contains("adblock-list"));
        assert!(err.is_blocked());
        assert!(!err.is_recoverable());
        assert_eq!(err.domain(), Some("ads.example.com"));
    }

    #[test]
    fn test_no_upstream_error() {
        let err = DnsError::no_upstream("all upstreams unhealthy");
        assert!(matches!(err, DnsError::NoUpstream { .. }));
        assert!(err.to_string().contains("all upstreams unhealthy"));
        assert!(!err.is_recoverable());
    }

    #[test]
    fn test_invalid_query_error() {
        let err = DnsError::invalid_query("empty question");
        assert!(matches!(err, DnsError::InvalidQuery { .. }));
        assert!(err.to_string().contains("empty question"));
        assert!(!err.is_recoverable());
    }

    #[test]
    fn test_invalid_query_error_with_id() {
        let err = DnsError::invalid_query_id("bad opcode", 0x1234);
        assert!(matches!(err, DnsError::InvalidQuery { query_id: Some(0x1234), .. }));
    }

    #[test]
    fn test_internal_error() {
        let err = DnsError::internal("unexpected state");
        assert!(matches!(err, DnsError::InternalError { .. }));
        assert!(err.to_string().contains("unexpected state"));
        assert!(!err.is_recoverable());
    }

    // ========================================================================
    // Error Conversion Tests
    // ========================================================================

    #[test]
    fn test_from_io_error() {
        let io_err = io::Error::new(io::ErrorKind::TimedOut, "timeout");
        let dns_err: DnsError = io_err.into();
        assert!(matches!(dns_err, DnsError::NetworkError { .. }));
        assert!(dns_err.is_recoverable());
    }

    #[test]
    fn test_from_io_error_permission_denied() {
        let io_err = io::Error::new(io::ErrorKind::PermissionDenied, "denied");
        let dns_err: DnsError = io_err.into();
        assert!(matches!(dns_err, DnsError::NetworkError { .. }));
        assert!(!dns_err.is_recoverable());
    }

    // ========================================================================
    // Recoverability Tests
    // ========================================================================

    #[test]
    fn test_recoverable_errors() {
        let recoverable = vec![
            DnsError::network("temporary failure"),
            DnsError::timeout("query", Duration::from_secs(1)),
            DnsError::upstream("8.8.8.8:53", "servfail"),
            DnsError::rate_limit("127.0.0.1:1234".parse().unwrap(), 200, 100),
        ];

        for err in recoverable {
            assert!(
                err.is_recoverable(),
                "Expected {} to be recoverable",
                err
            );
        }
    }

    #[test]
    fn test_non_recoverable_errors() {
        let non_recoverable = vec![
            DnsError::parse("malformed"),
            DnsError::serialize("buffer too small"),
            DnsError::cache("internal error"),
            DnsError::config("invalid address"),
            DnsError::blocked("example.com", "rule1"),
            DnsError::no_upstream("none configured"),
            DnsError::invalid_query("empty question"),
            DnsError::internal("bug"),
        ];

        for err in non_recoverable {
            assert!(
                !err.is_recoverable(),
                "Expected {} to be non-recoverable",
                err
            );
        }
    }

    // ========================================================================
    // Classification Tests
    // ========================================================================

    #[test]
    fn test_is_blocked() {
        assert!(DnsError::blocked("x.com", "r").is_blocked());
        assert!(!DnsError::timeout("q", Duration::from_secs(1)).is_blocked());
        assert!(!DnsError::upstream("8.8.8.8", "err").is_blocked());
    }

    #[test]
    fn test_is_rate_limited() {
        assert!(DnsError::rate_limit("127.0.0.1:1".parse().unwrap(), 100, 50).is_rate_limited());
        assert!(!DnsError::timeout("q", Duration::from_secs(1)).is_rate_limited());
    }

    #[test]
    fn test_is_timeout() {
        assert!(DnsError::timeout("q", Duration::from_secs(1)).is_timeout());
        assert!(!DnsError::blocked("x.com", "r").is_timeout());
    }

    #[test]
    fn test_is_upstream_error() {
        assert!(DnsError::upstream("8.8.8.8", "err").is_upstream_error());
        assert!(!DnsError::blocked("x.com", "r").is_upstream_error());
    }

    // ========================================================================
    // Display Tests
    // ========================================================================

    #[test]
    fn test_display_parse_error() {
        let err = DnsError::parse("invalid header");
        let display = err.to_string();
        assert!(display.contains("Failed to parse"));
        assert!(display.contains("invalid header"));
    }

    #[test]
    fn test_display_timeout_error() {
        let err = DnsError::timeout("query to 8.8.8.8", Duration::from_millis(500));
        let display = err.to_string();
        assert!(display.contains("timed out"));
        assert!(display.contains("500ms"));
    }

    #[test]
    fn test_display_rate_limit_error() {
        let client: SocketAddr = "10.0.0.1:5000".parse().unwrap();
        let err = DnsError::rate_limit(client, 150, 100);
        let display = err.to_string();
        assert!(display.contains("10.0.0.1:5000"));
        assert!(display.contains("150 qps"));
        assert!(display.contains("limit: 100 qps"));
    }

    #[test]
    fn test_error_debug() {
        let err = DnsError::blocked("example.com", "rule1");
        let debug = format!("{:?}", err);
        assert!(debug.contains("Blocked"));
        assert!(debug.contains("example.com"));
    }

    // ========================================================================
    // Domain/Upstream Extraction Tests
    // ========================================================================

    #[test]
    fn test_domain_extraction() {
        assert_eq!(
            DnsError::blocked("example.com", "r").domain(),
            Some("example.com")
        );
        assert_eq!(
            DnsError::parse_domain("err", "test.com").domain(),
            Some("test.com")
        );
        assert_eq!(DnsError::parse("err").domain(), None);
        assert_eq!(DnsError::timeout("q", Duration::from_secs(1)).domain(), None);
    }

    #[test]
    fn test_upstream_addr_extraction() {
        assert_eq!(
            DnsError::upstream("8.8.8.8:53", "err").upstream_addr(),
            Some("8.8.8.8:53")
        );
        assert_eq!(
            DnsError::upstream_rcode("1.1.1.1:53", "err", 2).upstream_addr(),
            Some("1.1.1.1:53")
        );
        assert_eq!(DnsError::timeout("q", Duration::from_secs(1)).upstream_addr(), None);
    }
}
