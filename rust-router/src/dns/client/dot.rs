//! DNS-over-TLS (`DoT`) Client
//!
//! This module provides a `DoT` client implementing RFC 7858 for querying
//! upstream DNS servers over TLS.
//!
//! # Features
//!
//! - TLS 1.2/1.3 via tokio-rustls
//! - Connection pooling via deadpool
//! - Server name verification
//! - 2-byte length prefix over TLS (same as TCP)
//! - Health tracking integration
//!
//! # Example
//!
//! ```no_run
//! use rust_router::dns::client::DotClient;
//! use rust_router::dns::{UpstreamConfig, UpstreamProtocol};
//! use hickory_proto::op::Message;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = UpstreamConfig::new(
//!     "cloudflare-dot",
//!     "cloudflare-dns.com:853",
//!     UpstreamProtocol::Dot,
//! );
//! let client = DotClient::new(config)?;
//!
//! let mut query = Message::new();
//! query.set_id(0x1234);
//! // ... set up query ...
//!
//! let response = client.query(&query).await?;
//! # Ok(())
//! # }
//! ```

#[cfg(feature = "dns-dot")]
mod inner {
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;

    use async_trait::async_trait;
    use deadpool::managed::{self, Manager, Pool, RecycleError, RecycleResult};
    use hickory_proto::op::Message;
    use rustls::pki_types::ServerName;
    use rustls::ClientConfig;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio::time::timeout;
    use tokio_rustls::client::TlsStream;
    use tokio_rustls::TlsConnector;

    use crate::dns::client::health::{HealthCheckConfig, HealthChecker};
    use crate::dns::client::traits::{validate_response, DnsUpstream, MAX_TCP_MESSAGE_SIZE};
    use crate::dns::config::{UpstreamConfig, UpstreamProtocol};
    use crate::dns::error::{DnsError, DnsResult};

    /// Default `DoT` port (RFC 7858)
    const DEFAULT_DOT_PORT: u16 = 853;

    /// Default connection pool size
    const DEFAULT_POOL_SIZE: usize = 4;

    /// Default connection timeout in seconds
    const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 10;

    /// TLS connection wrapper for the pool
    type TlsConnection = TlsStream<TcpStream>;

    /// `DoT` connection manager for deadpool
    struct DotConnectionManager {
        server_addr: SocketAddr,
        server_name: ServerName<'static>,
        tls_connector: TlsConnector,
        connect_timeout: Duration,
    }

    impl DotConnectionManager {
        fn new(
            server_addr: SocketAddr,
            server_name: ServerName<'static>,
            tls_connector: TlsConnector,
            connect_timeout: Duration,
        ) -> Self {
            Self {
                server_addr,
                server_name,
                tls_connector,
                connect_timeout,
            }
        }
    }

    #[async_trait]
    impl Manager for DotConnectionManager {
        type Type = TlsConnection;
        type Error = DnsError;

        async fn create(&self) -> Result<TlsConnection, DnsError> {
            // Connect TCP
            let tcp_connect = TcpStream::connect(self.server_addr);
            let tcp_stream = timeout(self.connect_timeout, tcp_connect)
                .await
                .map_err(|_| {
                    DnsError::timeout(
                        format!("TCP connection to {}", self.server_addr),
                        self.connect_timeout,
                    )
                })?
                .map_err(|e| {
                    DnsError::network_io(
                        format!("failed to connect to DoT server {}", self.server_addr),
                        e,
                    )
                })?;

            // Disable Nagle's algorithm for lower latency
            tcp_stream.set_nodelay(true).ok();

            // Perform TLS handshake
            let tls_connect = self.tls_connector.connect(self.server_name.clone(), tcp_stream);
            let tls_stream = timeout(self.connect_timeout, tls_connect)
                .await
                .map_err(|_| {
                    DnsError::timeout(
                        "TLS handshake",
                        self.connect_timeout,
                    )
                })?
                .map_err(|e| {
                    DnsError::network(format!(
                        "TLS handshake failed: {e}"
                    ))
                })?;

            Ok(tls_stream)
        }

        async fn recycle(
            &self,
            conn: &mut TlsConnection,
            _metrics: &managed::Metrics,
        ) -> RecycleResult<DnsError> {
            // Split the connection to check readability
            // TLS connections don't support try_read, so we check if the connection is still open
            // by attempting a zero-byte read with a very short timeout
            let mut buf = [0u8; 1];

            // Use a very short timeout to check connection state
            match timeout(Duration::from_millis(1), conn.read(&mut buf)).await {
                // Timeout means connection is idle (good)
                Err(_) => Ok(()),
                // EOF means connection closed by server
                Ok(Ok(0)) => Err(RecycleError::Message(
                    "DoT connection closed by server".to_string(),
                )),
                // Unexpected data on idle connection
                Ok(Ok(_)) => Err(RecycleError::Message(
                    "unexpected data on idle DoT connection".to_string(),
                )),
                // Read error
                Ok(Err(e)) => Err(RecycleError::Message(format!(
                    "DoT connection check failed: {e}"
                ))),
            }
        }
    }

    /// DNS-over-TLS client
    ///
    /// A `DoT` client using tokio-rustls for TLS transport. Implements RFC 7858
    /// with connection pooling for efficient resource usage.
    ///
    /// # Thread Safety
    ///
    /// This client is thread-safe and can be shared across tasks.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rust_router::dns::client::DotClient;
    /// use rust_router::dns::{UpstreamConfig, UpstreamProtocol};
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let config = UpstreamConfig::new(
    ///     "cloudflare",
    ///     "cloudflare-dns.com:853",
    ///     UpstreamProtocol::Dot,
    /// );
    /// let client = DotClient::new(config)?;
    ///
    /// assert!(client.is_healthy());
    /// assert_eq!(client.protocol(), UpstreamProtocol::Dot);
    /// # Ok(())
    /// # }
    /// ```
    pub struct DotClient {
        /// Upstream configuration
        config: UpstreamConfig,

        /// Parsed server address
        server_addr: SocketAddr,

        /// Server hostname for SNI
        server_name: String,

        /// Query timeout
        query_timeout: Duration,

        /// Connection pool
        pool: Pool<DotConnectionManager>,

        /// Health checker
        health: Arc<HealthChecker>,
    }

    impl std::fmt::Debug for DotClient {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("DotClient")
                .field("tag", &self.config.tag)
                .field("server_addr", &self.server_addr)
                .field("server_name", &self.server_name)
                .field("query_timeout", &self.query_timeout)
                .field("pool_size", &self.pool.status().size)
                .field("is_healthy", &self.health.is_healthy())
                .finish()
        }
    }

    impl DotClient {
        /// Create a new `DoT` client
        ///
        /// # Arguments
        ///
        /// * `config` - Upstream configuration with `DoT` address
        ///
        /// The address can be in one of these formats:
        /// - `hostname:port` (e.g., `cloudflare-dns.com:853`)
        /// - `hostname` (port defaults to 853)
        /// - `ip:port` with separate `sni` field for server name
        ///
        /// # Errors
        ///
        /// Returns `DnsError::ConfigError` if the address is invalid or
        /// pool creation fails.
        ///
        /// # Example
        ///
        /// ```no_run
        /// use rust_router::dns::client::DotClient;
        /// use rust_router::dns::{UpstreamConfig, UpstreamProtocol};
        ///
        /// let config = UpstreamConfig::new(
        ///     "google",
        ///     "dns.google:853",
        ///     UpstreamProtocol::Dot,
        /// );
        /// let client = DotClient::new(config).expect("valid config");
        /// ```
        pub fn new(config: UpstreamConfig) -> DnsResult<Self> {
            Self::with_pool_size(config, DEFAULT_POOL_SIZE)
        }

        /// Create a new `DoT` client with custom pool size
        ///
        /// # Arguments
        ///
        /// * `config` - Upstream configuration with `DoT` address
        /// * `pool_size` - Maximum number of pooled connections
        ///
        /// # Errors
        ///
        /// Returns `DnsError::ConfigError` if the address is invalid.
        pub fn with_pool_size(config: UpstreamConfig, pool_size: usize) -> DnsResult<Self> {
            Self::with_full_config(
                config,
                pool_size,
                Duration::from_secs(DEFAULT_CONNECT_TIMEOUT_SECS),
                HealthCheckConfig::default(),
            )
        }

        /// Create a new `DoT` client with full configuration
        ///
        /// # Arguments
        ///
        /// * `config` - Upstream configuration with `DoT` address
        /// * `pool_size` - Maximum number of pooled connections
        /// * `connect_timeout` - Timeout for establishing connections
        /// * `health_config` - Health check configuration
        ///
        /// # Errors
        ///
        /// Returns `DnsError::ConfigError` if the address is invalid.
        pub fn with_full_config(
            config: UpstreamConfig,
            pool_size: usize,
            connect_timeout: Duration,
            health_config: HealthCheckConfig,
        ) -> DnsResult<Self> {
            // Parse address and extract hostname/port
            let (server_addr, server_name) = Self::parse_address(&config)?;

            // Create TLS config with webpki roots
            let tls_config = Self::create_tls_config()?;
            let tls_connector = TlsConnector::from(Arc::new(tls_config));

            // Create server name for TLS SNI
            let server_name_tls: ServerName<'static> = server_name
                .clone()
                .try_into()
                .map_err(|_| {
                    DnsError::config_field(
                        format!("invalid server name for SNI: {server_name}"),
                        "upstream.address",
                    )
                })?;

            // Create connection manager and pool
            let manager = DotConnectionManager::new(
                server_addr,
                server_name_tls,
                tls_connector,
                connect_timeout,
            );
            let pool = Pool::builder(manager).max_size(pool_size).build().map_err(|e| {
                DnsError::config(format!("failed to create DoT connection pool: {e}"))
            })?;

            let query_timeout = Duration::from_secs(config.timeout_secs.max(1));
            let health = Arc::new(HealthChecker::new(&health_config));

            Ok(Self {
                config,
                server_addr,
                server_name,
                query_timeout,
                pool,
                health,
            })
        }

        /// Parse the `DoT` address to extract socket address and hostname
        fn parse_address(config: &UpstreamConfig) -> DnsResult<(SocketAddr, String)> {
            let address = &config.address;

            // Check if SNI is explicitly provided
            let sni = config.sni.as_deref();

            // Try to parse as socket address first (ip:port)
            if let Ok(addr) = address.parse::<SocketAddr>() {
                // Need SNI for IP addresses
                let hostname = sni.ok_or_else(|| {
                    DnsError::config_field(
                        "SNI hostname required when using IP address for DoT".to_string(),
                        "upstream.sni",
                    )
                })?;
                return Ok((addr, hostname.to_string()));
            }

            // Parse as hostname:port or hostname
            let (hostname, port) = if let Some(colon_pos) = address.rfind(':') {
                let host_part = &address[..colon_pos];
                let port_part = &address[colon_pos + 1..];

                // Check if this looks like a port (all digits)
                if port_part.chars().all(|c| c.is_ascii_digit()) {
                    let port: u16 = port_part.parse().map_err(|_| {
                        DnsError::config_field(
                            format!("invalid DoT port: {port_part}"),
                            "upstream.address",
                        )
                    })?;
                    (host_part.to_string(), port)
                } else {
                    // No port, the whole thing is a hostname (might contain IPv6)
                    (address.clone(), DEFAULT_DOT_PORT)
                }
            } else {
                // No colon, default port
                (address.clone(), DEFAULT_DOT_PORT)
            };

            // Resolve hostname to socket address
            // For production, we'd want async DNS resolution, but for config parsing
            // we use blocking resolution (happens once at startup)
            let addr_str = format!("{hostname}:{port}");
            let socket_addr: SocketAddr = addr_str.parse().or_else(|_| {
                // If direct parse fails, try DNS resolution
                use std::net::ToSocketAddrs;
                addr_str
                    .to_socket_addrs()
                    .map_err(|e| {
                        DnsError::config_field(
                            format!("failed to resolve DoT hostname '{hostname}': {e}"),
                            "upstream.address",
                        )
                    })?
                    .next()
                    .ok_or_else(|| {
                        DnsError::config_field(
                            format!("no addresses found for DoT hostname '{hostname}'"),
                            "upstream.address",
                        )
                    })
            })?;

            // Use provided SNI or the parsed hostname
            let final_hostname = sni.map(|s: &str| s.to_string()).unwrap_or(hostname);

            Ok((socket_addr, final_hostname))
        }

        /// Create TLS configuration with secure defaults
        fn create_tls_config() -> DnsResult<ClientConfig> {
            let root_store = rustls::RootCertStore::from_iter(
                webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
            );

            let config = ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth();

            Ok(config)
        }

        /// Get the server socket address
        pub fn server_addr(&self) -> SocketAddr {
            self.server_addr
        }

        /// Get the server hostname (used for SNI)
        pub fn server_name(&self) -> &str {
            &self.server_name
        }

        /// Get the current pool status
        pub fn pool_status(&self) -> deadpool::Status {
            self.pool.status()
        }

        /// Get the health checker
        pub fn health(&self) -> &HealthChecker {
            &self.health
        }

        /// Perform a `DoT` DNS query
        ///
        /// Uses the same 2-byte length prefix format as plain TCP DNS (RFC 1035),
        /// but over TLS (RFC 7858).
        async fn query_with_connection(
            &self,
            conn: &mut TlsConnection,
            query: &Message,
        ) -> DnsResult<Message> {
            // Serialize the query
            let query_bytes = query.to_vec().map_err(|e| {
                DnsError::serialize(format!("failed to serialize DNS query: {e}"))
            })?;

            // Check message size
            if query_bytes.len() > MAX_TCP_MESSAGE_SIZE {
                return Err(DnsError::serialize(format!(
                    "DoT query too large: {} bytes (max {})",
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
                        format!("DoT write to {}", self.server_name),
                        self.query_timeout,
                    )
                })?
                .map_err(|e| {
                    DnsError::network_io(
                        format!("failed to send DoT query to {}", self.server_name),
                        e,
                    )
                })?;

            // Flush to ensure data is sent
            timeout(self.query_timeout, conn.flush())
                .await
                .map_err(|_| {
                    DnsError::timeout(
                        format!("DoT flush to {}", self.server_name),
                        self.query_timeout,
                    )
                })?
                .map_err(|e| {
                    DnsError::network_io(
                        format!("failed to flush DoT connection to {}", self.server_name),
                        e,
                    )
                })?;

            // Read response length (2 bytes)
            let mut len_buf = [0u8; 2];
            timeout(self.query_timeout, conn.read_exact(&mut len_buf))
                .await
                .map_err(|_| {
                    DnsError::timeout(
                        format!("DoT read length from {}", self.server_name),
                        self.query_timeout,
                    )
                })?
                .map_err(|e| {
                    DnsError::network_io(
                        format!("failed to read DoT response length from {}", self.server_name),
                        e,
                    )
                })?;

            let response_len = u16::from_be_bytes(len_buf) as usize;

            // Validate response length
            if response_len == 0 {
                return Err(DnsError::parse("received empty DoT DNS response"));
            }
            if response_len > MAX_TCP_MESSAGE_SIZE {
                return Err(DnsError::parse(format!(
                    "DoT response too large: {response_len} bytes (max {MAX_TCP_MESSAGE_SIZE})"
                )));
            }

            // Read response body
            let mut response_buf = vec![0u8; response_len];
            timeout(self.query_timeout, conn.read_exact(&mut response_buf))
                .await
                .map_err(|_| {
                    DnsError::timeout(
                        format!("DoT read body from {}", self.server_name),
                        self.query_timeout,
                    )
                })?
                .map_err(|e| {
                    DnsError::network_io(
                        format!("failed to read DoT response body from {}", self.server_name),
                        e,
                    )
                })?;

            // Parse the response
            let response = Message::from_vec(&response_buf).map_err(|e| {
                DnsError::parse(format!("failed to parse DoT DNS response: {e}"))
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
    impl DnsUpstream for DotClient {
        async fn query(&self, query: &Message) -> DnsResult<Message> {
            // Get a connection from the pool
            let mut conn = self.pool.get().await.map_err(|e| {
                DnsError::upstream(
                    &self.config.address,
                    format!("failed to get DoT connection from pool: {e}"),
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
                            "retrying DoT query with fresh connection"
                        );

                        drop(conn); // Drop the potentially broken connection

                        let mut new_conn = self.pool.get().await.map_err(|e| {
                            DnsError::upstream(
                                &self.config.address,
                                format!("failed to get fresh DoT connection: {e}"),
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
            UpstreamProtocol::Dot
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
}

#[cfg(feature = "dns-dot")]
pub use inner::DotClient;

#[cfg(test)]
#[cfg(feature = "dns-dot")]
mod tests {
    use super::*;
    use crate::dns::client::health::HealthCheckConfig;
    use crate::dns::client::traits::DnsUpstream;
    use crate::dns::config::{UpstreamConfig, UpstreamProtocol};
    use hickory_proto::op::{Message, Query, ResponseCode};
    use hickory_proto::rr::{Name, RecordType};
    use std::str::FromStr;
    use std::sync::Once;
    use std::time::Duration;

    static INIT_CRYPTO: Once = Once::new();

    fn init_crypto_provider() {
        INIT_CRYPTO.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
    }

    // ========================================================================
    // Helper Functions
    // ========================================================================

    fn create_config(tag: &str, address: &str) -> UpstreamConfig {
        init_crypto_provider();
        UpstreamConfig::new(tag, address, UpstreamProtocol::Dot)
    }

    fn create_config_with_sni(tag: &str, address: &str, sni: &str) -> UpstreamConfig {
        init_crypto_provider();
        UpstreamConfig::new(tag, address, UpstreamProtocol::Dot).with_sni(sni)
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
    fn test_dot_client_new_hostname_port() {
        let config = create_config("cloudflare", "cloudflare-dns.com:853");
        let client = DotClient::new(config).unwrap();

        assert!(client.is_healthy());
        assert_eq!(client.server_name(), "cloudflare-dns.com");
    }

    #[test]
    fn test_dot_client_new_hostname_only() {
        let config = create_config("cloudflare", "cloudflare-dns.com");
        let client = DotClient::new(config).unwrap();

        // Default port should be 853
        assert_eq!(client.server_addr().port(), 853);
        assert_eq!(client.server_name(), "cloudflare-dns.com");
    }

    #[test]
    fn test_dot_client_ip_with_sni() {
        let config = create_config_with_sni("cloudflare", "1.1.1.1:853", "cloudflare-dns.com");
        let client = DotClient::new(config).unwrap();

        assert_eq!(client.server_addr(), "1.1.1.1:853".parse().unwrap());
        assert_eq!(client.server_name(), "cloudflare-dns.com");
    }

    #[test]
    fn test_dot_client_ip_without_sni_fails() {
        let config = create_config("test", "1.1.1.1:853");
        let result = DotClient::new(config);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("SNI hostname required"));
    }

    #[test]
    fn test_dot_client_with_pool_size() {
        let config = create_config("test", "dns.google:853");
        let client = DotClient::with_pool_size(config, 8).unwrap();

        assert_eq!(client.pool_status().max_size, 8);
    }

    #[test]
    fn test_dot_client_invalid_server_name() {
        // Invalid characters in hostname
        let config = create_config("test", "invalid\x00name:853");
        let result = DotClient::new(config);

        assert!(result.is_err());
    }

    // ========================================================================
    // Trait Implementation Tests
    // ========================================================================

    #[test]
    fn test_dot_client_protocol() {
        let config = create_config("test", "cloudflare-dns.com:853");
        let client = DotClient::new(config).unwrap();

        assert_eq!(client.protocol(), UpstreamProtocol::Dot);
    }

    #[test]
    fn test_dot_client_address() {
        let config = create_config("test", "dns.google:853");
        let client = DotClient::new(config).unwrap();

        assert_eq!(client.address(), "dns.google:853");
    }

    #[test]
    fn test_dot_client_tag() {
        let config = create_config("my-dot-upstream", "cloudflare-dns.com:853");
        let client = DotClient::new(config).unwrap();

        assert_eq!(client.tag(), "my-dot-upstream");
    }

    #[test]
    fn test_dot_client_is_encrypted() {
        let config = create_config("test", "cloudflare-dns.com:853");
        let client = DotClient::new(config).unwrap();

        assert!(client.is_encrypted());
    }

    #[test]
    fn test_dot_client_timeout() {
        let mut config = create_config("test", "cloudflare-dns.com:853");
        config.timeout_secs = 15;
        let client = DotClient::new(config).unwrap();

        assert_eq!(client.timeout(), Duration::from_secs(15));
    }

    #[test]
    fn test_dot_client_timeout_minimum() {
        let mut config = create_config("test", "cloudflare-dns.com:853");
        config.timeout_secs = 0;
        let client = DotClient::new(config).unwrap();

        // Minimum timeout is 1 second
        assert_eq!(client.timeout(), Duration::from_secs(1));
    }

    // ========================================================================
    // Health Tests
    // ========================================================================

    #[test]
    fn test_dot_client_health_initial() {
        let config = create_config("test", "cloudflare-dns.com:853");
        let client = DotClient::new(config).unwrap();

        assert!(client.is_healthy());
    }

    #[test]
    fn test_dot_client_mark_unhealthy() {
        let config = create_config("test", "cloudflare-dns.com:853");
        let client = DotClient::new(config).unwrap();

        client.mark_unhealthy();
        assert!(!client.is_healthy());
    }

    #[test]
    fn test_dot_client_mark_healthy() {
        let config = create_config("test", "cloudflare-dns.com:853");
        let client = DotClient::new(config).unwrap();

        client.mark_unhealthy();
        assert!(!client.is_healthy());

        client.mark_healthy();
        assert!(client.is_healthy());
    }

    #[test]
    fn test_dot_client_health_checker_access() {
        let config = create_config("test", "cloudflare-dns.com:853");
        let client = DotClient::new(config).unwrap();

        let health = client.health();
        assert!(health.is_healthy());

        health.record_failure();
        assert_eq!(health.consecutive_failures(), 1);
    }

    // ========================================================================
    // Pool Tests
    // ========================================================================

    #[test]
    fn test_dot_client_pool_status() {
        let config = create_config("test", "dns.google:853");
        let client = DotClient::with_pool_size(config, 4).unwrap();

        let status = client.pool_status();
        assert_eq!(status.max_size, 4);
        assert_eq!(status.size, 0); // No connections created yet
    }

    // ========================================================================
    // Debug Tests
    // ========================================================================

    #[test]
    fn test_dot_client_debug() {
        let config = create_config("debug-test", "cloudflare-dns.com:853");
        let client = DotClient::new(config).unwrap();

        let debug = format!("{:?}", client);
        assert!(debug.contains("DotClient"));
        assert!(debug.contains("cloudflare-dns.com"));
        assert!(debug.contains("debug-test"));
    }

    // ========================================================================
    // Custom Config Tests
    // ========================================================================

    #[test]
    fn test_dot_client_custom_health_config() {
        let config = create_config("test", "dns.google:853");
        let health_config = HealthCheckConfig::default()
            .with_failure_threshold(5)
            .with_success_threshold(2);

        let client = DotClient::with_full_config(
            config,
            4,
            Duration::from_secs(15),
            health_config,
        )
        .unwrap();

        let health = client.health();
        assert_eq!(health.failure_threshold(), 5);
        assert_eq!(health.success_threshold(), 2);
    }

    // ========================================================================
    // Address Parsing Tests
    // ========================================================================

    #[test]
    fn test_dot_client_parse_google_dns() {
        let config = create_config("google", "dns.google:853");
        let client = DotClient::new(config).unwrap();

        assert_eq!(client.server_name(), "dns.google");
    }

    #[test]
    fn test_dot_client_parse_quad9() {
        let config = create_config("quad9", "dns.quad9.net:853");
        let client = DotClient::new(config).unwrap();

        assert_eq!(client.server_name(), "dns.quad9.net");
    }

    #[test]
    fn test_dot_client_parse_ipv6_with_sni() {
        let config = create_config_with_sni(
            "cloudflare-ipv6",
            "[2606:4700:4700::1111]:853",
            "cloudflare-dns.com",
        );
        let client = DotClient::new(config).unwrap();

        assert_eq!(client.server_name(), "cloudflare-dns.com");
        assert_eq!(client.server_addr().port(), 853);
    }

    // ========================================================================
    // Query Tests (require network - marked as ignored)
    // ========================================================================

    #[tokio::test]
    #[ignore = "requires network access"]
    async fn test_dot_client_query_cloudflare() {
        let config = create_config("cloudflare", "cloudflare-dns.com:853");
        let client = DotClient::new(config).unwrap();

        let query = create_query("example.com.", 0x1234);
        let response = client.query(&query).await;

        assert!(response.is_ok());
        let response = response.unwrap();
        assert_eq!(response.id(), 0x1234);
        assert!(!response.answers().is_empty());
    }

    #[tokio::test]
    #[ignore = "requires network access"]
    async fn test_dot_client_query_google() {
        let config = create_config("google", "dns.google:853");
        let client = DotClient::new(config).unwrap();

        let query = create_query("google.com.", 0x5678);
        let response = client.query(&query).await.unwrap();

        assert_eq!(response.id(), 0x5678);
        assert_eq!(response.response_code(), ResponseCode::NoError);
    }

    #[tokio::test]
    #[ignore = "requires network access"]
    async fn test_dot_client_query_quad9() {
        let config = create_config("quad9", "dns.quad9.net:853");
        let client = DotClient::new(config).unwrap();

        let query = create_query("example.org.", 0x9ABC);
        let response = client.query(&query).await.unwrap();

        assert_eq!(response.id(), 0x9ABC);
    }

    #[tokio::test]
    #[ignore = "requires network access"]
    async fn test_dot_client_ip_address_with_sni() {
        let config = create_config_with_sni("cloudflare-ip", "1.1.1.1:853", "cloudflare-dns.com");
        let client = DotClient::new(config).unwrap();

        let query = create_query("example.com.", 0xDEF0);
        let response = client.query(&query).await;

        assert!(response.is_ok());
    }

    #[tokio::test]
    #[ignore = "requires network access"]
    async fn test_dot_client_connection_reuse() {
        let config = create_config("cloudflare", "cloudflare-dns.com:853");
        let client = DotClient::with_pool_size(config, 2).unwrap();

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

    #[tokio::test]
    async fn test_dot_client_query_connection_refused() {
        // Use localhost with likely closed port
        let config = create_config_with_sni("refused-test", "127.0.0.1:59999", "localhost");
        let client = DotClient::new(config).unwrap();

        let query = create_query("example.com.", 0x1234);

        let result = client.query(&query).await;
        assert!(result.is_err());

        let err = result.unwrap_err();
        // Should be a connection or TLS error
        assert!(err.is_recoverable() || err.is_upstream_error());
    }
}
