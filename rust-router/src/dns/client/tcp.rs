//! TCP DNS Client
//!
//! This module provides a TCP DNS client for querying upstream
//! DNS servers using plain TCP (RFC 1035).
//!
//! # Features
//!
//! - Connection pooling via deadpool
//! - 2-byte length prefix per RFC 1035
//! - Connection timeout and idle timeout
//! - Query ID and QNAME validation
//! - Health tracking integration
//!
//! # Example
//!
//! ```no_run
//! use rust_router::dns::client::TcpClient;
//! use rust_router::dns::{UpstreamConfig, UpstreamProtocol};
//! use hickory_proto::op::Message;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = UpstreamConfig::new("google-tcp", "8.8.8.8:53", UpstreamProtocol::Tcp);
//! let client = TcpClient::new(config)?;
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
use deadpool::managed::{self, Manager, Object, Pool, RecycleError, RecycleResult};
use hickory_proto::op::Message;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use super::health::{HealthCheckConfig, HealthChecker};
use super::traits::{validate_response, DnsUpstream, MAX_TCP_MESSAGE_SIZE};
use crate::dns::config::{UpstreamConfig, UpstreamProtocol};
use crate::dns::error::{DnsError, DnsResult};

/// Default connection pool size
const DEFAULT_POOL_SIZE: usize = 4;

/// Default connection timeout in seconds
const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 5;

/// Default idle timeout in seconds for pooled connections
const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 30;

/// TCP connection manager for deadpool
struct TcpConnectionManager {
    server_addr: SocketAddr,
    connect_timeout: Duration,
}

impl TcpConnectionManager {
    fn new(server_addr: SocketAddr, connect_timeout: Duration) -> Self {
        Self {
            server_addr,
            connect_timeout,
        }
    }
}

#[async_trait]
impl Manager for TcpConnectionManager {
    type Type = TcpStream;
    type Error = DnsError;

    async fn create(&self) -> Result<TcpStream, DnsError> {
        let connect_future = TcpStream::connect(self.server_addr);

        match timeout(self.connect_timeout, connect_future).await {
            Ok(Ok(stream)) => {
                // Disable Nagle's algorithm for lower latency
                stream.set_nodelay(true).ok();
                Ok(stream)
            }
            Ok(Err(e)) => Err(DnsError::network_io(
                format!("failed to connect to TCP DNS server {}", self.server_addr),
                e,
            )),
            Err(_) => Err(DnsError::timeout(
                format!("TCP connection to {}", self.server_addr),
                self.connect_timeout,
            )),
        }
    }

    async fn recycle(
        &self,
        conn: &mut TcpStream,
        _metrics: &managed::Metrics,
    ) -> RecycleResult<DnsError> {
        // Check if connection is still valid by peeking
        let mut buf = [0u8; 1];
        match conn.try_read(&mut buf) {
            // Would block means connection is idle but valid
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(()),
            // No data available is good
            Ok(0) => Err(RecycleError::Message(
                "TCP connection closed by server".to_string(),
            )),
            // Unexpected data on idle connection
            Ok(_) => Err(RecycleError::Message(
                "unexpected data on idle TCP connection".to_string(),
            )),
            // Other errors
            Err(e) => Err(RecycleError::Message(format!(
                "TCP connection check failed: {}",
                e
            ))),
        }
    }
}

/// TCP DNS client
///
/// A TCP client with connection pooling for querying DNS servers.
/// Uses deadpool for efficient connection management.
///
/// # Thread Safety
///
/// This client is thread-safe and can be shared across tasks.
///
/// # Example
///
/// ```no_run
/// use rust_router::dns::client::TcpClient;
/// use rust_router::dns::{UpstreamConfig, UpstreamProtocol};
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let config = UpstreamConfig::new("cloudflare", "1.1.1.1:53", UpstreamProtocol::Tcp);
/// let client = TcpClient::new(config)?;
///
/// assert!(client.is_healthy());
/// assert_eq!(client.protocol(), UpstreamProtocol::Tcp);
/// # Ok(())
/// # }
/// ```
pub struct TcpClient {
    /// Upstream configuration
    config: UpstreamConfig,

    /// Parsed server address
    server_addr: SocketAddr,

    /// Query timeout
    query_timeout: Duration,

    /// Connection pool
    pool: Pool<TcpConnectionManager>,

    /// Health checker
    health: Arc<HealthChecker>,
}

impl std::fmt::Debug for TcpClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TcpClient")
            .field("tag", &self.config.tag)
            .field("server_addr", &self.server_addr)
            .field("query_timeout", &self.query_timeout)
            .field("pool_size", &self.pool.status().size)
            .field("is_healthy", &self.health.is_healthy())
            .finish()
    }
}

impl TcpClient {
    /// Create a new TCP client
    ///
    /// # Arguments
    ///
    /// * `config` - Upstream configuration
    ///
    /// # Errors
    ///
    /// Returns `DnsError::ConfigError` if the address cannot be parsed
    /// or pool creation fails.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rust_router::dns::client::TcpClient;
    /// use rust_router::dns::{UpstreamConfig, UpstreamProtocol};
    ///
    /// let config = UpstreamConfig::new("google", "8.8.8.8:53", UpstreamProtocol::Tcp);
    /// let client = TcpClient::new(config).expect("valid config");
    /// ```
    pub fn new(config: UpstreamConfig) -> DnsResult<Self> {
        Self::with_pool_size(config, DEFAULT_POOL_SIZE)
    }

    /// Create a new TCP client with custom pool size
    ///
    /// # Arguments
    ///
    /// * `config` - Upstream configuration
    /// * `pool_size` - Maximum number of pooled connections
    ///
    /// # Errors
    ///
    /// Returns `DnsError::ConfigError` if the address cannot be parsed.
    pub fn with_pool_size(config: UpstreamConfig, pool_size: usize) -> DnsResult<Self> {
        Self::with_full_config(
            config,
            pool_size,
            Duration::from_secs(DEFAULT_CONNECT_TIMEOUT_SECS),
            HealthCheckConfig::default(),
        )
    }

    /// Create a new TCP client with full configuration
    ///
    /// # Arguments
    ///
    /// * `config` - Upstream configuration
    /// * `pool_size` - Maximum number of pooled connections
    /// * `connect_timeout` - Timeout for establishing connections
    /// * `health_config` - Health check configuration
    ///
    /// # Errors
    ///
    /// Returns `DnsError::ConfigError` if the address cannot be parsed.
    pub fn with_full_config(
        config: UpstreamConfig,
        pool_size: usize,
        connect_timeout: Duration,
        health_config: HealthCheckConfig,
    ) -> DnsResult<Self> {
        let server_addr: SocketAddr = config.address.parse().map_err(|e| {
            DnsError::config_field(
                format!("invalid TCP server address '{}': {}", config.address, e),
                "upstream.address",
            )
        })?;

        let manager = TcpConnectionManager::new(server_addr, connect_timeout);
        let pool = Pool::builder(manager)
            .max_size(pool_size)
            .build()
            .map_err(|e| DnsError::config(format!("failed to create TCP connection pool: {}", e)))?;

        let query_timeout = Duration::from_secs(config.timeout_secs.max(1));
        let health = Arc::new(HealthChecker::new(&health_config));

        Ok(Self {
            config,
            server_addr,
            query_timeout,
            pool,
            health,
        })
    }

    /// Get the server socket address
    pub fn server_addr(&self) -> SocketAddr {
        self.server_addr
    }

    /// Get the current pool status
    pub fn pool_status(&self) -> deadpool::Status {
        self.pool.status()
    }

    /// Get the health checker
    pub fn health(&self) -> &HealthChecker {
        &self.health
    }

    /// Perform a TCP DNS query
    ///
    /// This method gets a connection from the pool, sends the query
    /// with the 2-byte length prefix, and reads the response.
    async fn query_with_connection(
        &self,
        conn: &mut Object<TcpConnectionManager>,
        query: &Message,
    ) -> DnsResult<Message> {
        // Serialize the query
        let query_bytes = query.to_vec().map_err(|e| {
            DnsError::serialize(format!("failed to serialize DNS query: {}", e))
        })?;

        // Check message size
        if query_bytes.len() > MAX_TCP_MESSAGE_SIZE {
            return Err(DnsError::serialize(format!(
                "TCP query too large: {} bytes (max {})",
                query_bytes.len(),
                MAX_TCP_MESSAGE_SIZE
            )));
        }

        // Create message with 2-byte length prefix
        let len_prefix = (query_bytes.len() as u16).to_be_bytes();
        let mut send_buf = Vec::with_capacity(2 + query_bytes.len());
        send_buf.extend_from_slice(&len_prefix);
        send_buf.extend_from_slice(&query_bytes);

        // Send the query
        timeout(self.query_timeout, conn.write_all(&send_buf))
            .await
            .map_err(|_| {
                DnsError::timeout(
                    format!("TCP write to {}", self.server_addr),
                    self.query_timeout,
                )
            })?
            .map_err(|e| {
                DnsError::network_io(
                    format!("failed to send TCP query to {}", self.server_addr),
                    e,
                )
            })?;

        // Read response length (2 bytes)
        let mut len_buf = [0u8; 2];
        timeout(self.query_timeout, conn.read_exact(&mut len_buf))
            .await
            .map_err(|_| {
                DnsError::timeout(
                    format!("TCP read length from {}", self.server_addr),
                    self.query_timeout,
                )
            })?
            .map_err(|e| {
                DnsError::network_io(
                    format!("failed to read TCP response length from {}", self.server_addr),
                    e,
                )
            })?;

        let response_len = u16::from_be_bytes(len_buf) as usize;

        // Validate response length
        if response_len == 0 {
            return Err(DnsError::parse("received empty TCP DNS response"));
        }
        if response_len > MAX_TCP_MESSAGE_SIZE {
            return Err(DnsError::parse(format!(
                "TCP response too large: {} bytes (max {})",
                response_len, MAX_TCP_MESSAGE_SIZE
            )));
        }

        // Read response body
        let mut response_buf = vec![0u8; response_len];
        timeout(self.query_timeout, conn.read_exact(&mut response_buf))
            .await
            .map_err(|_| {
                DnsError::timeout(
                    format!("TCP read body from {}", self.server_addr),
                    self.query_timeout,
                )
            })?
            .map_err(|e| {
                DnsError::network_io(
                    format!("failed to read TCP response body from {}", self.server_addr),
                    e,
                )
            })?;

        // Parse the response
        let response = Message::from_vec(&response_buf).map_err(|e| {
            DnsError::parse(format!("failed to parse TCP DNS response: {}", e))
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
}

#[async_trait]
impl DnsUpstream for TcpClient {
    async fn query(&self, query: &Message) -> DnsResult<Message> {
        // Get a connection from the pool
        let mut conn = self.pool.get().await.map_err(|e| {
            DnsError::upstream(
                &self.config.address,
                format!("failed to get TCP connection from pool: {}", e),
            )
        })?;

        match self.query_with_connection(&mut conn, query).await {
            Ok(response) => {
                self.health.record_success();
                Ok(response)
            }
            Err(e) => {
                self.health.record_failure();

                // If there was a connection error, try once more with a fresh connection
                if e.is_recoverable() {
                    tracing::debug!(
                        upstream = %self.config.tag,
                        error = %e,
                        "retrying TCP query with fresh connection"
                    );

                    drop(conn); // Drop the potentially broken connection

                    let mut new_conn = self.pool.get().await.map_err(|e| {
                        DnsError::upstream(
                            &self.config.address,
                            format!("failed to get fresh TCP connection: {}", e),
                        )
                    })?;

                    match self.query_with_connection(&mut new_conn, query).await {
                        Ok(response) => {
                            self.health.record_success();
                            Ok(response)
                        }
                        Err(e) => {
                            self.health.record_failure();
                            Err(e)
                        }
                    }
                } else {
                    Err(e)
                }
            }
        }
    }

    fn is_healthy(&self) -> bool {
        self.health.is_healthy()
    }

    fn protocol(&self) -> UpstreamProtocol {
        UpstreamProtocol::Tcp
    }

    fn address(&self) -> &str {
        &self.config.address
    }

    fn tag(&self) -> &str {
        &self.config.tag
    }

    fn timeout(&self) -> Duration {
        self.query_timeout
    }

    fn mark_unhealthy(&self) {
        self.health.force_unhealthy();
    }

    fn mark_healthy(&self) {
        self.health.force_healthy();
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
        UpstreamConfig::new(tag, address, UpstreamProtocol::Tcp)
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
    fn test_tcp_client_new() {
        let config = create_config("test", "8.8.8.8:53");
        let client = TcpClient::new(config).unwrap();

        assert_eq!(client.server_addr(), "8.8.8.8:53".parse().unwrap());
        assert!(client.is_healthy());
    }

    #[test]
    fn test_tcp_client_with_pool_size() {
        let config = create_config("test", "1.1.1.1:53");
        let client = TcpClient::with_pool_size(config, 8).unwrap();

        assert_eq!(client.pool_status().max_size, 8);
    }

    #[test]
    fn test_tcp_client_invalid_address() {
        let config = create_config("test", "invalid:address");
        let result = TcpClient::new(config);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("invalid TCP server address"));
    }

    #[test]
    fn test_tcp_client_missing_port() {
        let config = create_config("test", "8.8.8.8");
        let result = TcpClient::new(config);

        assert!(result.is_err());
    }

    #[test]
    fn test_tcp_client_ipv6_address() {
        let config = create_config("test", "[2001:4860:4860::8888]:53");
        let client = TcpClient::new(config).unwrap();

        assert_eq!(
            client.server_addr(),
            "[2001:4860:4860::8888]:53".parse().unwrap()
        );
    }

    // ========================================================================
    // Trait Implementation Tests
    // ========================================================================

    #[test]
    fn test_tcp_client_protocol() {
        let config = create_config("test", "8.8.8.8:53");
        let client = TcpClient::new(config).unwrap();

        assert_eq!(client.protocol(), UpstreamProtocol::Tcp);
    }

    #[test]
    fn test_tcp_client_address() {
        let config = create_config("test", "8.8.8.8:53");
        let client = TcpClient::new(config).unwrap();

        assert_eq!(client.address(), "8.8.8.8:53");
    }

    #[test]
    fn test_tcp_client_tag() {
        let config = create_config("my-upstream", "8.8.8.8:53");
        let client = TcpClient::new(config).unwrap();

        assert_eq!(client.tag(), "my-upstream");
    }

    #[test]
    fn test_tcp_client_timeout() {
        let mut config = create_config("test", "8.8.8.8:53");
        config.timeout_secs = 10;
        let client = TcpClient::new(config).unwrap();

        assert_eq!(client.timeout(), Duration::from_secs(10));
    }

    #[test]
    fn test_tcp_client_timeout_minimum() {
        let mut config = create_config("test", "8.8.8.8:53");
        config.timeout_secs = 0;
        let client = TcpClient::new(config).unwrap();

        // Minimum timeout is 1 second
        assert_eq!(client.timeout(), Duration::from_secs(1));
    }

    #[test]
    fn test_tcp_client_is_encrypted() {
        let config = create_config("test", "8.8.8.8:53");
        let client = TcpClient::new(config).unwrap();

        assert!(!client.is_encrypted());
    }

    // ========================================================================
    // Health Tests
    // ========================================================================

    #[test]
    fn test_tcp_client_health_initial() {
        let config = create_config("test", "8.8.8.8:53");
        let client = TcpClient::new(config).unwrap();

        assert!(client.is_healthy());
    }

    #[test]
    fn test_tcp_client_mark_unhealthy() {
        let config = create_config("test", "8.8.8.8:53");
        let client = TcpClient::new(config).unwrap();

        client.mark_unhealthy();
        assert!(!client.is_healthy());
    }

    #[test]
    fn test_tcp_client_mark_healthy() {
        let config = create_config("test", "8.8.8.8:53");
        let client = TcpClient::new(config).unwrap();

        client.mark_unhealthy();
        assert!(!client.is_healthy());

        client.mark_healthy();
        assert!(client.is_healthy());
    }

    #[test]
    fn test_tcp_client_health_checker_access() {
        let config = create_config("test", "8.8.8.8:53");
        let client = TcpClient::new(config).unwrap();

        let health = client.health();
        assert!(health.is_healthy());

        health.record_failure();
        assert_eq!(health.consecutive_failures(), 1);
    }

    // ========================================================================
    // Pool Tests
    // ========================================================================

    #[test]
    fn test_tcp_client_pool_status() {
        let config = create_config("test", "8.8.8.8:53");
        let client = TcpClient::with_pool_size(config, 4).unwrap();

        let status = client.pool_status();
        assert_eq!(status.max_size, 4);
        assert_eq!(status.size, 0); // No connections created yet
    }

    // ========================================================================
    // Debug Tests
    // ========================================================================

    #[test]
    fn test_tcp_client_debug() {
        let config = create_config("debug-test", "8.8.8.8:53");
        let client = TcpClient::new(config).unwrap();

        let debug = format!("{:?}", client);
        assert!(debug.contains("TcpClient"));
        assert!(debug.contains("8.8.8.8:53"));
        assert!(debug.contains("debug-test"));
    }

    // ========================================================================
    // Custom Config Tests
    // ========================================================================

    #[test]
    fn test_tcp_client_custom_health_config() {
        let config = create_config("test", "8.8.8.8:53");
        let health_config = HealthCheckConfig::default()
            .with_failure_threshold(5)
            .with_success_threshold(2);

        let client = TcpClient::with_full_config(
            config,
            4,
            Duration::from_secs(10),
            health_config,
        )
        .unwrap();

        let health = client.health();
        assert_eq!(health.failure_threshold(), 5);
        assert_eq!(health.success_threshold(), 2);
    }

    // ========================================================================
    // Query Tests (require network - marked as ignored)
    // ========================================================================

    #[tokio::test]
    #[ignore = "requires network access"]
    async fn test_tcp_client_query_real() {
        let config = create_config("google", "8.8.8.8:53");
        let client = TcpClient::new(config).unwrap();

        let query = create_query("google.com.", 0x1234);
        let response = client.query(&query).await;

        assert!(response.is_ok());
        let response = response.unwrap();
        assert_eq!(response.id(), 0x1234);
        assert!(!response.answers().is_empty());
    }

    #[tokio::test]
    #[ignore = "requires network access"]
    async fn test_tcp_client_query_cloudflare() {
        let config = create_config("cloudflare", "1.1.1.1:53");
        let client = TcpClient::new(config).unwrap();

        let query = create_query("example.com.", 0x5678);
        let response = client.query(&query).await.unwrap();

        assert_eq!(response.id(), 0x5678);
        assert_eq!(response.response_code(), ResponseCode::NoError);
    }

    #[tokio::test]
    async fn test_tcp_client_query_connection_refused() {
        // Use localhost with likely closed port
        let config = create_config("refused-test", "127.0.0.1:59999");
        let client = TcpClient::new(config).unwrap();

        let query = create_query("example.com.", 0x1234);

        let result = client.query(&query).await;
        assert!(result.is_err());

        let err = result.unwrap_err();
        assert!(err.is_recoverable() || err.is_upstream_error());
    }

    #[tokio::test]
    #[ignore = "requires network access"]
    async fn test_tcp_client_connection_reuse() {
        let config = create_config("cloudflare", "1.1.1.1:53");
        let client = TcpClient::with_pool_size(config, 2).unwrap();

        // Multiple queries should reuse connections
        for i in 0..5 {
            let query = create_query("example.com.", i);
            let result = client.query(&query).await;
            assert!(result.is_ok());
        }

        // Pool should have connections
        let status = client.pool_status();
        assert!(status.size > 0);
    }
}
