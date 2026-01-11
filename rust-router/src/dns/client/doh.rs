//! DNS-over-HTTPS (`DoH`) Client
//!
//! This module provides a `DoH` client implementing RFC 8484 for querying
//! upstream DNS servers over HTTPS.
//!
//! # Features
//!
//! - HTTP/2 with hyper for connection multiplexing
//! - POST with `application/dns-message` content type
//! - TLS via hyper-rustls
//! - Connection pooling via hyper's built-in pooling
//! - Health tracking integration
//!
//! # Example
//!
//! ```no_run
//! use rust_router::dns::client::DohClient;
//! use rust_router::dns::{UpstreamConfig, UpstreamProtocol};
//! use hickory_proto::op::Message;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = UpstreamConfig::new(
//!     "cloudflare-doh",
//!     "https://cloudflare-dns.com/dns-query",
//!     UpstreamProtocol::Doh,
//! );
//! let client = DohClient::new(config)?;
//!
//! let mut query = Message::new();
//! query.set_id(0x1234);
//! // ... set up query ...
//!
//! let response = client.query(&query).await?;
//! # Ok(())
//! # }
//! ```

#[cfg(feature = "dns-doh")]
mod inner {
    use std::sync::Arc;
    use std::time::Duration;

    use async_trait::async_trait;
    use bytes::Bytes;
    use hickory_proto::op::Message;
    use http::{header, Method, Request, Uri};
    use http_body_util::{BodyExt, Full};
    use hyper::body::Incoming;
    use hyper_rustls::HttpsConnectorBuilder;
    use hyper_util::client::legacy::Client;
    use hyper_util::rt::TokioExecutor;
    use tokio::time::timeout;

    use crate::dns::client::health::{HealthCheckConfig, HealthChecker};
    use crate::dns::client::traits::{validate_response, DnsUpstream, MAX_TCP_MESSAGE_SIZE};
    use crate::dns::config::{UpstreamConfig, UpstreamProtocol};
    use crate::dns::error::{DnsError, DnsResult};

    /// `DoH` Content-Type for DNS wire format
    const DOH_CONTENT_TYPE: &str = "application/dns-message";

    /// `DoH` Accept header for DNS wire format
    const DOH_ACCEPT: &str = "application/dns-message";

    /// DNS-over-HTTPS client
    ///
    /// A `DoH` client using hyper for HTTP/2 transport. Implements RFC 8484
    /// using POST requests with `application/dns-message` content type.
    ///
    /// # Thread Safety
    ///
    /// This client is thread-safe and can be shared across tasks.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rust_router::dns::client::DohClient;
    /// use rust_router::dns::{UpstreamConfig, UpstreamProtocol};
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let config = UpstreamConfig::new(
    ///     "cloudflare",
    ///     "https://cloudflare-dns.com/dns-query",
    ///     UpstreamProtocol::Doh,
    /// );
    /// let client = DohClient::new(config)?;
    ///
    /// assert!(client.is_healthy());
    /// assert_eq!(client.protocol(), UpstreamProtocol::Doh);
    /// # Ok(())
    /// # }
    /// ```
    pub struct DohClient {
        /// Upstream configuration
        config: UpstreamConfig,

        /// Parsed `DoH` endpoint URI
        uri: Uri,

        /// HTTP client with HTTPS connector
        client: Client<hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>, Full<Bytes>>,

        /// Query timeout
        query_timeout: Duration,

        /// Health checker
        health: Arc<HealthChecker>,
    }

    impl std::fmt::Debug for DohClient {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("DohClient")
                .field("tag", &self.config.tag)
                .field("uri", &self.uri.to_string())
                .field("query_timeout", &self.query_timeout)
                .field("is_healthy", &self.health.is_healthy())
                .finish()
        }
    }

    impl DohClient {
        /// Create a new `DoH` client
        ///
        /// # Arguments
        ///
        /// * `config` - Upstream configuration with `DoH` URL
        ///
        /// # Errors
        ///
        /// Returns `DnsError::ConfigError` if the URL is invalid.
        ///
        /// # Example
        ///
        /// ```no_run
        /// use rust_router::dns::client::DohClient;
        /// use rust_router::dns::{UpstreamConfig, UpstreamProtocol};
        ///
        /// let config = UpstreamConfig::new(
        ///     "google",
        ///     "https://dns.google/dns-query",
        ///     UpstreamProtocol::Doh,
        /// );
        /// let client = DohClient::new(config).expect("valid config");
        /// ```
        pub fn new(config: UpstreamConfig) -> DnsResult<Self> {
            Self::with_health_config(config, HealthCheckConfig::default())
        }

        /// Create a new `DoH` client with custom health check configuration
        ///
        /// # Arguments
        ///
        /// * `config` - Upstream configuration with `DoH` URL
        /// * `health_config` - Health check configuration
        ///
        /// # Errors
        ///
        /// Returns `DnsError::ConfigError` if the URL is invalid.
        pub fn with_health_config(
            config: UpstreamConfig,
            health_config: HealthCheckConfig,
        ) -> DnsResult<Self> {
            // Parse the DoH URL
            let uri: Uri = config.address.parse().map_err(|e| {
                DnsError::config_field(
                    format!("invalid DoH URL '{}': {}", config.address, e),
                    "upstream.address",
                )
            })?;

            // Validate URL scheme
            let scheme = uri.scheme_str().unwrap_or("");
            if scheme != "https" {
                return Err(DnsError::config_field(
                    format!("DoH URL must use HTTPS scheme, got: {scheme}"),
                    "upstream.address",
                ));
            }

            // Create TLS config with webpki roots
            let root_store = rustls::RootCertStore::from_iter(
                webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
            );
            let tls_config = rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth();

            // Create HTTPS connector
            let https = HttpsConnectorBuilder::new()
                .with_tls_config(tls_config)
                .https_only()
                .enable_http2()
                .build();

            // Create HTTP client
            let client = Client::builder(TokioExecutor::new())
                .http2_only(true)
                .build(https);

            let query_timeout = Duration::from_secs(config.timeout_secs.max(1));
            let health = Arc::new(HealthChecker::new(&health_config));

            Ok(Self {
                config,
                uri,
                client,
                query_timeout,
                health,
            })
        }

        /// Get the `DoH` endpoint URI
        pub fn uri(&self) -> &Uri {
            &self.uri
        }

        /// Get the health checker
        pub fn health(&self) -> &HealthChecker {
            &self.health
        }

        /// Perform a `DoH` query using POST
        async fn query_post(&self, query: &Message) -> DnsResult<Message> {
            // Serialize the query
            let query_bytes = query.to_vec().map_err(|e| {
                DnsError::serialize(format!("failed to serialize DNS query: {e}"))
            })?;

            // Build HTTP request
            let request = Request::builder()
                .method(Method::POST)
                .uri(self.uri.clone())
                .header(header::CONTENT_TYPE, DOH_CONTENT_TYPE)
                .header(header::ACCEPT, DOH_ACCEPT)
                .header(header::CONTENT_LENGTH, query_bytes.len())
                .body(Full::new(Bytes::from(query_bytes)))
                .map_err(|e| {
                    DnsError::internal(format!("failed to build DoH request: {e}"))
                })?;

            // Send request with timeout
            let response = timeout(self.query_timeout, self.client.request(request))
                .await
                .map_err(|_| {
                    DnsError::timeout(
                        format!("DoH request to {}", self.uri),
                        self.query_timeout,
                    )
                })?
                .map_err(|e| {
                    DnsError::upstream(&self.config.address, format!("DoH request failed: {e}"))
                })?;

            // Check HTTP status
            let status = response.status();
            if !status.is_success() {
                return Err(DnsError::upstream(
                    &self.config.address,
                    format!("DoH request returned HTTP {status}"),
                ));
            }

            // Verify Content-Type
            if let Some(content_type) = response.headers().get(header::CONTENT_TYPE) {
                let ct = content_type.to_str().unwrap_or("");
                if !ct.starts_with(DOH_CONTENT_TYPE) {
                    return Err(DnsError::upstream(
                        &self.config.address,
                        format!("unexpected Content-Type: {ct}"),
                    ));
                }
            }

            // Read response body
            let body_bytes = self.collect_body(response.into_body()).await?;

            // Validate response size
            if body_bytes.len() > MAX_TCP_MESSAGE_SIZE {
                return Err(DnsError::parse(format!(
                    "DoH response too large: {} bytes (max {})",
                    body_bytes.len(),
                    MAX_TCP_MESSAGE_SIZE
                )));
            }

            // Parse DNS response
            let dns_response = Message::from_vec(&body_bytes).map_err(|e| {
                DnsError::parse(format!("failed to parse DoH DNS response: {e}"))
            })?;

            // Validate response matches query
            if !validate_response(query, &dns_response) {
                return Err(DnsError::upstream(
                    &self.config.address,
                    "response validation failed (ID or QNAME mismatch)",
                ));
            }

            Ok(dns_response)
        }

        /// Collect HTTP response body with timeout
        async fn collect_body(&self, body: Incoming) -> DnsResult<Vec<u8>> {
            let collected = timeout(self.query_timeout, body.collect())
                .await
                .map_err(|_| {
                    DnsError::timeout(
                        format!("DoH response body from {}", self.uri),
                        self.query_timeout,
                    )
                })?
                .map_err(|e| {
                    DnsError::upstream(
                        &self.config.address,
                        format!("failed to read DoH response body: {e}"),
                    )
                })?;

            Ok(collected.to_bytes().to_vec())
        }
    }

    #[async_trait]
    impl DnsUpstream for DohClient {
        async fn query(&self, query: &Message) -> DnsResult<Message> {
            match self.query_post(query).await {
                Ok(response) => {
                    self.health.record_success();
                    Ok(response)
                }
                Err(e) => {
                    self.health.record_failure();
                    Err(e)
                }
            }
        }

        fn is_healthy(&self) -> bool {
            self.health.is_healthy()
        }

        fn protocol(&self) -> UpstreamProtocol {
            UpstreamProtocol::Doh
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

#[cfg(feature = "dns-doh")]
pub use inner::DohClient;

#[cfg(test)]
#[cfg(feature = "dns-doh")]
mod tests {
    use super::*;
    use crate::dns::client::traits::DnsUpstream;
    use crate::dns::config::{UpstreamConfig, UpstreamProtocol};
    use hickory_proto::op::{Message, Query};
    use hickory_proto::rr::{Name, RecordType};
    use std::str::FromStr;
    use std::sync::Once;

    static INIT_CRYPTO: Once = Once::new();

    fn init_crypto_provider() {
        INIT_CRYPTO.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
    }

    // ========================================================================
    // Helper Functions
    // ========================================================================

    fn create_config(tag: &str, url: &str) -> UpstreamConfig {
        init_crypto_provider();
        UpstreamConfig::new(tag, url, UpstreamProtocol::Doh)
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
    fn test_doh_client_new() {
        let config = create_config("cloudflare", "https://cloudflare-dns.com/dns-query");
        let client = DohClient::new(config).unwrap();

        assert!(client.is_healthy());
        assert_eq!(client.protocol(), UpstreamProtocol::Doh);
    }

    #[test]
    fn test_doh_client_invalid_url_no_scheme() {
        // A URL without a scheme is parsed as a relative URI, but fails
        // the HTTPS scheme check
        let config = create_config("test", "not-a-valid-url");
        let result = DohClient::new(config);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("HTTPS scheme"));
    }

    #[test]
    fn test_doh_client_invalid_url_parse_error() {
        // A URL with spaces fails URI parsing
        let config = create_config("test", "https://dns server.example.com/dns-query");
        let result = DohClient::new(config);

        assert!(result.is_err());
        let err = result.unwrap_err();
        // URI parsing fails, so we get the "invalid DoH URL" error
        assert!(err.to_string().contains("invalid DoH URL"));
    }

    #[test]
    fn test_doh_client_http_scheme_rejected() {
        let config = create_config("test", "http://insecure-dns.example.com/dns-query");
        let result = DohClient::new(config);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("HTTPS scheme"));
    }

    #[test]
    fn test_doh_client_uri() {
        let config = create_config("google", "https://dns.google/dns-query");
        let client = DohClient::new(config).unwrap();

        assert_eq!(client.uri().to_string(), "https://dns.google/dns-query");
    }

    // ========================================================================
    // Trait Implementation Tests
    // ========================================================================

    #[test]
    fn test_doh_client_protocol() {
        let config = create_config("test", "https://dns.google/dns-query");
        let client = DohClient::new(config).unwrap();

        assert_eq!(client.protocol(), UpstreamProtocol::Doh);
    }

    #[test]
    fn test_doh_client_address() {
        let config = create_config("test", "https://cloudflare-dns.com/dns-query");
        let client = DohClient::new(config).unwrap();

        assert_eq!(client.address(), "https://cloudflare-dns.com/dns-query");
    }

    #[test]
    fn test_doh_client_tag() {
        let config = create_config("my-doh-upstream", "https://dns.google/dns-query");
        let client = DohClient::new(config).unwrap();

        assert_eq!(client.tag(), "my-doh-upstream");
    }

    #[test]
    fn test_doh_client_is_encrypted() {
        let config = create_config("test", "https://dns.google/dns-query");
        let client = DohClient::new(config).unwrap();

        assert!(client.is_encrypted());
    }

    #[test]
    fn test_doh_client_timeout() {
        let mut config = create_config("test", "https://dns.google/dns-query");
        config.timeout_secs = 15;
        let client = DohClient::new(config).unwrap();

        assert_eq!(client.timeout(), std::time::Duration::from_secs(15));
    }

    // ========================================================================
    // Health Tests
    // ========================================================================

    #[test]
    fn test_doh_client_health_initial() {
        let config = create_config("test", "https://dns.google/dns-query");
        let client = DohClient::new(config).unwrap();

        assert!(client.is_healthy());
    }

    #[test]
    fn test_doh_client_mark_unhealthy() {
        let config = create_config("test", "https://dns.google/dns-query");
        let client = DohClient::new(config).unwrap();

        client.mark_unhealthy();
        assert!(!client.is_healthy());
    }

    #[test]
    fn test_doh_client_mark_healthy() {
        let config = create_config("test", "https://dns.google/dns-query");
        let client = DohClient::new(config).unwrap();

        client.mark_unhealthy();
        assert!(!client.is_healthy());

        client.mark_healthy();
        assert!(client.is_healthy());
    }

    #[test]
    fn test_doh_client_health_checker_access() {
        let config = create_config("test", "https://dns.google/dns-query");
        let client = DohClient::new(config).unwrap();

        let health = client.health();
        assert!(health.is_healthy());

        health.record_failure();
        assert_eq!(health.consecutive_failures(), 1);
    }

    // ========================================================================
    // Debug Tests
    // ========================================================================

    #[test]
    fn test_doh_client_debug() {
        let config = create_config("debug-test", "https://dns.google/dns-query");
        let client = DohClient::new(config).unwrap();

        let debug = format!("{:?}", client);
        assert!(debug.contains("DohClient"));
        assert!(debug.contains("dns.google"));
        assert!(debug.contains("debug-test"));
    }

    // ========================================================================
    // Query Tests (require network - marked as ignored)
    // ========================================================================

    #[tokio::test]
    #[ignore = "requires network access"]
    async fn test_doh_client_query_cloudflare() {
        let config = create_config("cloudflare", "https://cloudflare-dns.com/dns-query");
        let client = DohClient::new(config).unwrap();

        let query = create_query("example.com.", 0x1234);
        let response = client.query(&query).await;

        assert!(response.is_ok());
        let response = response.unwrap();
        assert_eq!(response.id(), 0x1234);
        assert!(!response.answers().is_empty());
    }

    #[tokio::test]
    #[ignore = "requires network access"]
    async fn test_doh_client_query_google() {
        let config = create_config("google", "https://dns.google/dns-query");
        let client = DohClient::new(config).unwrap();

        let query = create_query("google.com.", 0x5678);
        let response = client.query(&query).await.unwrap();

        assert_eq!(response.id(), 0x5678);
        assert!(!response.answers().is_empty());
    }

    #[tokio::test]
    #[ignore = "requires network access"]
    async fn test_doh_client_query_quad9() {
        let config = create_config("quad9", "https://dns.quad9.net/dns-query");
        let client = DohClient::new(config).unwrap();

        let query = create_query("example.org.", 0x9ABC);
        let response = client.query(&query).await.unwrap();

        assert_eq!(response.id(), 0x9ABC);
    }
}
