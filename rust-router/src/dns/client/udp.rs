//! UDP DNS Client
//!
//! This module provides a simple UDP DNS client for querying upstream
//! DNS servers using plain UDP (RFC 1035).
//!
//! # Features
//!
//! - Simple stateless UDP queries
//! - Configurable timeout and retry logic
//! - Query ID and QNAME validation
//! - Health tracking integration
//!
//! # Example
//!
//! ```no_run
//! use rust_router::dns::client::UdpClient;
//! use rust_router::dns::UpstreamConfig;
//! use rust_router::dns::UpstreamProtocol;
//! use hickory_proto::op::Message;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = UpstreamConfig::new("google-udp", "8.8.8.8:53", UpstreamProtocol::Udp);
//! let client = UdpClient::new(config)?;
//!
//! let mut query = Message::new();
//! query.set_id(0x1234);
//! // ... set up query ...
//!
//! let response = client.query(&query).await?;
//! # Ok(())
//! # }
//! ```

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use hickory_proto::op::Message;
use tokio::net::UdpSocket;
use tokio::time::timeout;

use super::health::{HealthCheckConfig, HealthChecker};
use super::traits::{validate_response, DnsUpstream, DEFAULT_UDP_RETRIES, MAX_UDP_MESSAGE_SIZE};
use crate::dns::config::{UpstreamConfig, UpstreamProtocol};
use crate::dns::error::{DnsError, DnsResult};

/// Maximum UDP response buffer size
///
/// UDP DNS messages can be up to 512 bytes without EDNS0,
/// or up to 4096 bytes with EDNS0. We use a larger buffer
/// to accommodate EDNS0 responses.
const UDP_RECV_BUFFER_SIZE: usize = 4096;

/// UDP DNS client
///
/// A stateless UDP client for querying DNS servers. Each query
/// creates a new UDP socket, sends the query, and waits for a
/// response with retry logic.
///
/// # Thread Safety
///
/// This client is thread-safe and can be shared across tasks.
///
/// # Example
///
/// ```no_run
/// use rust_router::dns::client::UdpClient;
/// use rust_router::dns::{UpstreamConfig, UpstreamProtocol};
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let config = UpstreamConfig::new("cloudflare", "1.1.1.1:53", UpstreamProtocol::Udp);
/// let client = UdpClient::new(config)?;
///
/// assert!(client.is_healthy());
/// assert_eq!(client.protocol(), UpstreamProtocol::Udp);
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct UdpClient {
    /// Upstream configuration
    config: UpstreamConfig,

    /// Parsed server address
    server_addr: SocketAddr,

    /// Query timeout
    timeout: Duration,

    /// Number of retries on failure
    retries: u32,

    /// Health checker
    health: Arc<HealthChecker>,
}

impl UdpClient {
    /// Create a new UDP client
    ///
    /// # Arguments
    ///
    /// * `config` - Upstream configuration
    ///
    /// # Errors
    ///
    /// Returns `DnsError::ConfigError` if the address cannot be parsed.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rust_router::dns::client::UdpClient;
    /// use rust_router::dns::{UpstreamConfig, UpstreamProtocol};
    ///
    /// let config = UpstreamConfig::new("google", "8.8.8.8:53", UpstreamProtocol::Udp);
    /// let client = UdpClient::new(config).expect("valid config");
    /// ```
    pub fn new(config: UpstreamConfig) -> DnsResult<Self> {
        Self::with_health_config(config, HealthCheckConfig::default())
    }

    /// Create a new UDP client with custom health check configuration
    ///
    /// # Arguments
    ///
    /// * `config` - Upstream configuration
    /// * `health_config` - Health check configuration
    ///
    /// # Errors
    ///
    /// Returns `DnsError::ConfigError` if the address cannot be parsed.
    pub fn with_health_config(
        config: UpstreamConfig,
        health_config: HealthCheckConfig,
    ) -> DnsResult<Self> {
        let server_addr: SocketAddr = config.address.parse().map_err(|e| {
            DnsError::config_field(
                format!("invalid UDP server address '{}': {}", config.address, e),
                "upstream.address",
            )
        })?;

        let timeout = Duration::from_secs(config.timeout_secs.max(1));
        let health = Arc::new(HealthChecker::new(&health_config));

        Ok(Self {
            config,
            server_addr,
            timeout,
            retries: DEFAULT_UDP_RETRIES,
            health,
        })
    }

    /// Create a UDP client with custom retry count
    ///
    /// # Arguments
    ///
    /// * `config` - Upstream configuration
    /// * `retries` - Number of retries on failure
    ///
    /// # Errors
    ///
    /// Returns `DnsError::ConfigError` if the address cannot be parsed.
    pub fn with_retries(config: UpstreamConfig, retries: u32) -> DnsResult<Self> {
        let mut client = Self::new(config)?;
        client.retries = retries;
        Ok(client)
    }

    /// Get the server socket address
    pub fn server_addr(&self) -> SocketAddr {
        self.server_addr
    }

    /// Get the number of configured retries
    pub fn retries(&self) -> u32 {
        self.retries
    }

    /// Get the health checker
    pub fn health(&self) -> &HealthChecker {
        &self.health
    }

    /// Perform a single UDP query attempt
    ///
    /// This method sends a query and waits for a response without retries.
    async fn query_once(&self, query: &Message) -> DnsResult<Message> {
        // Serialize the query
        let query_bytes = query.to_vec().map_err(|e| {
            DnsError::serialize(format!("failed to serialize DNS query: {e}"))
        })?;

        // Check message size
        if query_bytes.len() > MAX_UDP_MESSAGE_SIZE {
            return Err(DnsError::serialize(format!(
                "UDP query too large: {} bytes (max {})",
                query_bytes.len(),
                MAX_UDP_MESSAGE_SIZE
            )));
        }

        // Create a new UDP socket bound to any available port
        let socket = UdpSocket::bind("0.0.0.0:0").await.map_err(|e| {
            DnsError::network_io("failed to bind UDP socket", e)
        })?;

        // Send the query
        socket.send_to(&query_bytes, self.server_addr).await.map_err(|e| {
            DnsError::network_io(
                format!("failed to send UDP query to {}", self.server_addr),
                e,
            )
        })?;

        // Wait for response with timeout
        let mut recv_buf = vec![0u8; UDP_RECV_BUFFER_SIZE];
        let recv_result = timeout(self.timeout, socket.recv_from(&mut recv_buf)).await;

        match recv_result {
            Ok(Ok((len, src))) => {
                // Verify source address matches server
                if src != self.server_addr {
                    return Err(DnsError::upstream(
                        &self.config.address,
                        format!("response from unexpected source: {} (expected {})", src, self.server_addr),
                    ));
                }

                // Parse the response
                let response = Message::from_vec(&recv_buf[..len]).map_err(|e| {
                    DnsError::parse(format!("failed to parse DNS response: {e}"))
                })?;

                // Validate response matches query
                if !validate_response(query, &response) {
                    return Err(DnsError::upstream(
                        &self.config.address,
                        "response validation failed (ID or QNAME mismatch)",
                    ));
                }

                Ok(response)
            }
            Ok(Err(e)) => {
                Err(DnsError::network_io(
                    format!("failed to receive UDP response from {}", self.server_addr),
                    e,
                ))
            }
            Err(_) => {
                Err(DnsError::timeout(
                    format!("UDP query to {}", self.server_addr),
                    self.timeout,
                ))
            }
        }
    }
}

#[async_trait]
impl DnsUpstream for UdpClient {
    async fn query(&self, query: &Message) -> DnsResult<Message> {
        let mut last_error = None;

        // Try query with retries
        for attempt in 0..=self.retries {
            if attempt > 0 {
                tracing::debug!(
                    upstream = %self.config.tag,
                    attempt = attempt + 1,
                    max_attempts = self.retries + 1,
                    "retrying UDP query"
                );
            }

            match self.query_once(query).await {
                Ok(response) => {
                    self.health.record_success();
                    return Ok(response);
                }
                Err(e) => {
                    tracing::debug!(
                        upstream = %self.config.tag,
                        attempt = attempt + 1,
                        error = %e,
                        "UDP query attempt failed"
                    );
                    last_error = Some(e);
                }
            }
        }

        // All attempts failed
        self.health.record_failure();
        Err(last_error.unwrap_or_else(|| {
            DnsError::upstream(&self.config.address, "all UDP query attempts failed")
        }))
    }

    fn is_healthy(&self) -> bool {
        self.health.is_healthy()
    }

    fn protocol(&self) -> UpstreamProtocol {
        UpstreamProtocol::Udp
    }

    fn address(&self) -> &str {
        &self.config.address
    }

    fn tag(&self) -> &str {
        &self.config.tag
    }

    fn timeout(&self) -> Duration {
        self.timeout
    }

    fn mark_unhealthy(&self) {
        self.health.force_unhealthy();
    }

    fn mark_healthy(&self) {
        self.health.force_healthy();
    }
}

impl Clone for UdpClient {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            server_addr: self.server_addr,
            timeout: self.timeout,
            retries: self.retries,
            health: Arc::clone(&self.health),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{Query, ResponseCode};
    use hickory_proto::rr::{Name, RecordType};
    use std::str::FromStr;

    // ========================================================================
    // Helper Functions
    // ========================================================================

    fn create_config(tag: &str, address: &str) -> UpstreamConfig {
        UpstreamConfig::new(tag, address, UpstreamProtocol::Udp)
    }

    fn create_query(domain: &str, id: u16) -> Message {
        let mut message = Message::new();
        message.set_id(id);
        message.set_recursion_desired(true);

        let name = Name::from_str(domain).unwrap();
        let query = Query::query(name, RecordType::A);
        message.add_query(query);

        message
    }

    // ========================================================================
    // Creation Tests
    // ========================================================================

    #[test]
    fn test_udp_client_new() {
        let config = create_config("test", "8.8.8.8:53");
        let client = UdpClient::new(config).unwrap();

        assert_eq!(client.server_addr(), "8.8.8.8:53".parse().unwrap());
        assert_eq!(client.retries(), DEFAULT_UDP_RETRIES);
        assert!(client.is_healthy());
    }

    #[test]
    fn test_udp_client_with_retries() {
        let config = create_config("test", "1.1.1.1:53");
        let client = UdpClient::with_retries(config, 5).unwrap();

        assert_eq!(client.retries(), 5);
    }

    #[test]
    fn test_udp_client_invalid_address() {
        let config = create_config("test", "invalid:address");
        let result = UdpClient::new(config);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("invalid UDP server address"));
    }

    #[test]
    fn test_udp_client_missing_port() {
        let config = create_config("test", "8.8.8.8");
        let result = UdpClient::new(config);

        assert!(result.is_err());
    }

    #[test]
    fn test_udp_client_ipv6_address() {
        let config = create_config("test", "[2001:4860:4860::8888]:53");
        let client = UdpClient::new(config).unwrap();

        assert_eq!(
            client.server_addr(),
            "[2001:4860:4860::8888]:53".parse().unwrap()
        );
    }

    // ========================================================================
    // Trait Implementation Tests
    // ========================================================================

    #[test]
    fn test_udp_client_protocol() {
        let config = create_config("test", "8.8.8.8:53");
        let client = UdpClient::new(config).unwrap();

        assert_eq!(client.protocol(), UpstreamProtocol::Udp);
    }

    #[test]
    fn test_udp_client_address() {
        let config = create_config("test", "8.8.8.8:53");
        let client = UdpClient::new(config).unwrap();

        assert_eq!(client.address(), "8.8.8.8:53");
    }

    #[test]
    fn test_udp_client_tag() {
        let config = create_config("my-upstream", "8.8.8.8:53");
        let client = UdpClient::new(config).unwrap();

        assert_eq!(client.tag(), "my-upstream");
    }

    #[test]
    fn test_udp_client_timeout() {
        let mut config = create_config("test", "8.8.8.8:53");
        config.timeout_secs = 10;
        let client = UdpClient::new(config).unwrap();

        assert_eq!(client.timeout(), Duration::from_secs(10));
    }

    #[test]
    fn test_udp_client_timeout_minimum() {
        let mut config = create_config("test", "8.8.8.8:53");
        config.timeout_secs = 0;
        let client = UdpClient::new(config).unwrap();

        // Minimum timeout is 1 second
        assert_eq!(client.timeout(), Duration::from_secs(1));
    }

    #[test]
    fn test_udp_client_is_encrypted() {
        let config = create_config("test", "8.8.8.8:53");
        let client = UdpClient::new(config).unwrap();

        assert!(!client.is_encrypted());
    }

    // ========================================================================
    // Health Tests
    // ========================================================================

    #[test]
    fn test_udp_client_health_initial() {
        let config = create_config("test", "8.8.8.8:53");
        let client = UdpClient::new(config).unwrap();

        assert!(client.is_healthy());
    }

    #[test]
    fn test_udp_client_mark_unhealthy() {
        let config = create_config("test", "8.8.8.8:53");
        let client = UdpClient::new(config).unwrap();

        client.mark_unhealthy();
        assert!(!client.is_healthy());
    }

    #[test]
    fn test_udp_client_mark_healthy() {
        let config = create_config("test", "8.8.8.8:53");
        let client = UdpClient::new(config).unwrap();

        client.mark_unhealthy();
        assert!(!client.is_healthy());

        client.mark_healthy();
        assert!(client.is_healthy());
    }

    #[test]
    fn test_udp_client_health_checker_access() {
        let config = create_config("test", "8.8.8.8:53");
        let client = UdpClient::new(config).unwrap();

        let health = client.health();
        assert!(health.is_healthy());

        health.record_failure();
        assert_eq!(health.consecutive_failures(), 1);
    }

    // ========================================================================
    // Clone Tests
    // ========================================================================

    #[test]
    fn test_udp_client_clone() {
        let config = create_config("test", "8.8.8.8:53");
        let client = UdpClient::new(config).unwrap();

        let cloned = client.clone();

        assert_eq!(client.server_addr(), cloned.server_addr());
        assert_eq!(client.tag(), cloned.tag());
        assert_eq!(client.retries(), cloned.retries());
    }

    #[test]
    fn test_udp_client_clone_shares_health() {
        let config = create_config("test", "8.8.8.8:53");
        let client = UdpClient::new(config).unwrap();
        let cloned = client.clone();

        // Marking original unhealthy should affect clone
        client.mark_unhealthy();
        assert!(!cloned.is_healthy());
    }

    // ========================================================================
    // Custom Health Config Tests
    // ========================================================================

    #[test]
    fn test_udp_client_custom_health_config() {
        let config = create_config("test", "8.8.8.8:53");
        let health_config = HealthCheckConfig::default()
            .with_failure_threshold(5)
            .with_success_threshold(2);

        let client = UdpClient::with_health_config(config, health_config).unwrap();

        // Custom thresholds should be applied
        let health = client.health();
        assert_eq!(health.failure_threshold(), 5);
        assert_eq!(health.success_threshold(), 2);
    }

    // ========================================================================
    // Query Tests (require network - marked as ignored)
    // ========================================================================

    #[tokio::test]
    #[ignore = "requires network access"]
    async fn test_udp_client_query_real() {
        let config = create_config("google", "8.8.8.8:53");
        let client = UdpClient::new(config).unwrap();

        let query = create_query("google.com.", 0x1234);
        let response = client.query(&query).await;

        assert!(response.is_ok());
        let response = response.unwrap();
        assert_eq!(response.id(), 0x1234);
        assert!(!response.answers().is_empty());
    }

    #[tokio::test]
    #[ignore = "requires network access"]
    async fn test_udp_client_query_cloudflare() {
        let config = create_config("cloudflare", "1.1.1.1:53");
        let client = UdpClient::new(config).unwrap();

        let query = create_query("example.com.", 0x5678);
        let response = client.query(&query).await.unwrap();

        assert_eq!(response.id(), 0x5678);
        assert_eq!(response.response_code(), ResponseCode::NoError);
    }

    #[tokio::test]
    async fn test_udp_client_query_timeout() {
        // Use a non-routable IP to trigger timeout
        let mut config = create_config("timeout-test", "10.255.255.1:53");
        config.timeout_secs = 1;

        let client = UdpClient::with_retries(config, 0).unwrap();
        let query = create_query("example.com.", 0x1234);

        let result = client.query(&query).await;
        assert!(result.is_err());

        let err = result.unwrap_err();
        assert!(err.is_timeout());
    }

    #[tokio::test]
    async fn test_udp_client_query_connection_refused() {
        // Use localhost with likely closed port
        let config = create_config("refused-test", "127.0.0.1:59999");
        let client = UdpClient::with_retries(config, 0).unwrap();

        let query = create_query("example.com.", 0x1234);

        // Note: UDP is connectionless, so we may get timeout instead of refused
        let result = client.query(&query).await;
        assert!(result.is_err());
    }

    // ========================================================================
    // Message Size Tests
    // ========================================================================

    #[test]
    fn test_udp_recv_buffer_size() {
        // Buffer should accommodate EDNS0 responses
        assert!(UDP_RECV_BUFFER_SIZE >= 4096);
    }

    // ========================================================================
    // Debug Tests
    // ========================================================================

    #[test]
    fn test_udp_client_debug() {
        let config = create_config("debug-test", "8.8.8.8:53");
        let client = UdpClient::new(config).unwrap();

        let debug = format!("{:?}", client);
        assert!(debug.contains("UdpClient"));
        assert!(debug.contains("8.8.8.8:53"));
    }
}
