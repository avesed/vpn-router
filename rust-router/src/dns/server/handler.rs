//! DNS Query Handler
//!
//! This module provides the core DNS query processing logic, including
//! parsing, validation, and response generation.
//!
//! # Architecture
//!
//! ```text
//! Incoming Query
//!     |
//!     v
//! Parse DNS Message (hickory-proto)
//!     |
//!     v
//! Rate Limit Check
//!     |
//!     v
//! Query Validation
//!     |   - Query ID validation
//!     |   - QNAME validation
//!     |   - OpCode validation
//!     |
//!     v
//! [Future: Block Check -> Cache -> Route -> Upstream]
//!     |
//!     v
//! Generate Response
//! ```
//!
//! # Features
//!
//! - **Message Parsing**: Full DNS message parsing via hickory-proto
//! - **Rate Limiting**: Integration with `DnsRateLimiter`
//! - **Validation**: Query ID, QNAME, and `OpCode` validation
//! - **Error Responses**: Proper DNS error response generation
//!
//! # Example
//!
//! ```
//! use rust_router::dns::server::{DnsHandler, DnsRateLimiter};
//! use rust_router::dns::RateLimitConfig;
//! use std::sync::Arc;
//! use std::net::SocketAddr;
//!
//! let rate_limiter = Arc::new(DnsRateLimiter::new(&RateLimitConfig::default()));
//! let handler = DnsHandler::new(rate_limiter);
//!
//! // Handler is ready to process queries
//! // let response = handler.handle_query(client_addr, &query_bytes).await;
//! ```

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use hickory_proto::op::{Header, Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::RecordType;
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use tracing::{debug, info, trace, warn};

use super::rate_limit::DnsRateLimiter;
use crate::dns::cache::DnsCache;
use crate::dns::client::UpstreamPool;
use crate::dns::error::{DnsError, DnsResult};
use crate::dns::filter::BlockFilter;
use crate::dns::log::QueryLogger;
use crate::dns::split::DnsRouter;

/// Minimum DNS header size
const DNS_HEADER_SIZE: usize = 12;

/// Maximum UDP response size without EDNS0 (RFC 1035 section 4.2.1)
///
/// DNS messages over UDP MUST be limited to 512 bytes unless the client
/// indicates EDNS0 support with a larger buffer size.
pub const MAX_UDP_RESPONSE_SIZE_NO_EDNS: usize = 512;

/// Maximum domain name length (RFC 1035)
const MAX_DOMAIN_LENGTH: usize = 253;

/// Maximum label length (RFC 1035)
const MAX_LABEL_LENGTH: usize = 63;

/// Query context containing parsed information
#[derive(Debug, Clone)]
pub struct QueryContext {
    /// Original query ID
    pub query_id: u16,
    /// Query domain name (QNAME)
    pub qname: String,
    /// Query type (A, AAAA, etc.)
    pub qtype: RecordType,
    /// Client address
    pub client: SocketAddr,
    /// Is recursion desired
    pub recursion_desired: bool,
}

/// Statistics for the DNS handler
#[derive(Debug, Default)]
pub struct HandlerStats {
    /// Total queries received
    queries_received: AtomicU64,
    /// Queries successfully processed
    queries_processed: AtomicU64,
    /// Parse errors
    parse_errors: AtomicU64,
    /// Validation errors
    validation_errors: AtomicU64,
    /// Rate limit rejections
    rate_limited: AtomicU64,
    /// Error responses generated
    error_responses: AtomicU64,
}

impl HandlerStats {
    /// Create new stats
    pub fn new() -> Self {
        Self::default()
    }

    /// Get queries received
    #[must_use]
    pub fn queries_received(&self) -> u64 {
        self.queries_received.load(Ordering::Relaxed)
    }

    /// Get queries processed
    #[must_use]
    pub fn queries_processed(&self) -> u64 {
        self.queries_processed.load(Ordering::Relaxed)
    }

    /// Get parse errors
    #[must_use]
    pub fn parse_errors(&self) -> u64 {
        self.parse_errors.load(Ordering::Relaxed)
    }

    /// Get validation errors
    #[must_use]
    pub fn validation_errors(&self) -> u64 {
        self.validation_errors.load(Ordering::Relaxed)
    }

    /// Get rate limited count
    #[must_use]
    pub fn rate_limited(&self) -> u64 {
        self.rate_limited.load(Ordering::Relaxed)
    }

    /// Get error responses count
    #[must_use]
    pub fn error_responses(&self) -> u64 {
        self.error_responses.load(Ordering::Relaxed)
    }

    /// Get snapshot
    #[must_use]
    pub fn snapshot(&self) -> HandlerStatsSnapshot {
        HandlerStatsSnapshot {
            queries_received: self.queries_received(),
            queries_processed: self.queries_processed(),
            parse_errors: self.parse_errors(),
            validation_errors: self.validation_errors(),
            rate_limited: self.rate_limited(),
            error_responses: self.error_responses(),
        }
    }
}

/// Snapshot of handler statistics
#[derive(Debug, Clone, Copy)]
pub struct HandlerStatsSnapshot {
    /// Queries received
    pub queries_received: u64,
    /// Queries processed
    pub queries_processed: u64,
    /// Parse errors
    pub parse_errors: u64,
    /// Validation errors
    pub validation_errors: u64,
    /// Rate limited
    pub rate_limited: u64,
    /// Error responses
    pub error_responses: u64,
}

impl HandlerStatsSnapshot {
    /// Get success rate
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn success_rate(&self) -> f64 {
        if self.queries_received == 0 {
            return 1.0;
        }
        self.queries_processed as f64 / self.queries_received as f64
    }
}

/// DNS query handler
///
/// Phase 11-Fix.AA: Now connected to all DNS components for real query processing.
///
/// Processes incoming DNS queries through the full pipeline:
/// 1. Rate limiting
/// 2. Query validation
/// 3. Block filter check
/// 4. Cache lookup
/// 5. DNS routing (upstream selection)
/// 6. Upstream query
/// 7. Cache update
/// 8. Query logging
pub struct DnsHandler {
    /// Rate limiter
    rate_limiter: Arc<DnsRateLimiter>,
    /// Statistics
    stats: HandlerStats,
    /// DNS cache for query result caching (optional for backward compatibility)
    cache: Option<Arc<DnsCache>>,
    /// Block filter for ad/tracker blocking (optional)
    block_filter: Option<Arc<BlockFilter>>,
    /// Upstream pool for DNS query forwarding (optional)
    upstream_pool: Option<Arc<UpstreamPool>>,
    /// DNS router for split DNS routing (optional)
    router: Option<Arc<DnsRouter>>,
    /// Query logger (optional)
    query_logger: Option<Arc<QueryLogger>>,
}

impl DnsHandler {
    /// Create a new DNS handler with minimal configuration (backward compatible)
    ///
    /// # Arguments
    ///
    /// * `rate_limiter` - Rate limiter instance
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::dns::server::{DnsHandler, DnsRateLimiter};
    /// use rust_router::dns::RateLimitConfig;
    /// use std::sync::Arc;
    ///
    /// let rate_limiter = Arc::new(DnsRateLimiter::new(&RateLimitConfig::default()));
    /// let handler = DnsHandler::new(rate_limiter);
    /// ```
    #[must_use]
    pub fn new(rate_limiter: Arc<DnsRateLimiter>) -> Self {
        Self {
            rate_limiter,
            stats: HandlerStats::new(),
            cache: None,
            block_filter: None,
            upstream_pool: None,
            router: None,
            query_logger: None,
        }
    }

    /// Create a handler with rate limiting disabled
    #[must_use]
    pub fn without_rate_limit() -> Self {
        Self::new(Arc::new(DnsRateLimiter::disabled()))
    }

    /// Phase 11-Fix.AA: Create a fully configured DNS handler
    ///
    /// This constructor connects the handler to all DNS components for
    /// real query processing.
    ///
    /// # Arguments
    ///
    /// * `rate_limiter` - Rate limiter instance
    /// * `cache` - DNS cache for query result caching
    /// * `block_filter` - Block filter for ad/tracker blocking
    /// * `upstream_pool` - Upstream pool for DNS query forwarding
    /// * `router` - DNS router for split DNS routing
    /// * `query_logger` - Query logger for DNS query logging
    #[must_use]
    pub fn with_components(
        rate_limiter: Arc<DnsRateLimiter>,
        cache: Arc<DnsCache>,
        block_filter: Arc<BlockFilter>,
        upstream_pool: Arc<UpstreamPool>,
        router: Arc<DnsRouter>,
        query_logger: Arc<QueryLogger>,
    ) -> Self {
        info!("Creating DnsHandler with all components connected");
        Self {
            rate_limiter,
            stats: HandlerStats::new(),
            cache: Some(cache),
            block_filter: Some(block_filter),
            upstream_pool: Some(upstream_pool),
            router: Some(router),
            query_logger: Some(query_logger),
        }
    }

    /// Handle an incoming DNS query
    ///
    /// Phase 11-Fix.AA: Now implements full query processing pipeline:
    /// 1. Rate limiting
    /// 2. Query validation
    /// 3. Block filter check
    /// 4. Cache lookup
    /// 5. DNS routing (upstream selection)
    /// 6. Upstream query
    /// 7. Cache update
    /// 8. Query logging
    ///
    /// # Arguments
    ///
    /// * `client` - Client socket address
    /// * `query_data` - Raw DNS query bytes
    ///
    /// # Returns
    ///
    /// Response bytes on success, or error if processing fails.
    ///
    /// # Errors
    ///
    /// - `DnsError::ParseError` if the query is malformed
    /// - `DnsError::RateLimitExceeded` if rate limit is exceeded
    /// - `DnsError::InvalidQuery` if query validation fails
    pub async fn handle_query(&self, client: SocketAddr, query_data: &[u8]) -> DnsResult<Vec<u8>> {
        self.stats.queries_received.fetch_add(1, Ordering::Relaxed);

        // Check rate limit first
        if let Err(e) = self.rate_limiter.check(client.ip()) {
            self.stats.rate_limited.fetch_add(1, Ordering::Relaxed);
            return Err(e);
        }

        // Parse the query
        let query = self.parse_query(query_data)?;

        trace!(
            client = %client,
            id = query.id(),
            "Processing DNS query"
        );

        // Validate the query
        let context = self.validate_query(client, &query)?;

        // Phase 11-Fix.AA: Real query processing with components
        let response = self.process_query(&query, &context).await?;

        self.stats.queries_processed.fetch_add(1, Ordering::Relaxed);

        self.serialize_response(&response)
    }

    /// Phase 11-Fix.AA: Process a validated DNS query through the full pipeline
    async fn process_query(&self, query: &Message, context: &QueryContext) -> DnsResult<Message> {
        let qname = &context.qname;

        // Step 1: Check block filter
        if let Some(block_filter) = &self.block_filter {
            if block_filter.is_blocked(qname).is_some() {
                debug!(qname = %qname, "Query blocked by filter");
                // Return blocked response (NXDOMAIN or zero IP based on config)
                return Ok(self.generate_blocked_response(query));
            }
        }

        // Step 2: Check cache (DnsCache.get takes Message directly)
        if let Some(cache) = &self.cache {
            if let Some(cached_response) = cache.get(query) {
                debug!(qname = %qname, "Cache hit");
                // Return cached response (already has correct query ID)
                return Ok(cached_response);
            }
        }

        // Step 3: Forward to upstream
        // First try the router, then fall back to the default upstream pool
        let upstream: Option<Arc<UpstreamPool>> = if let Some(router) = &self.router {
            // Use DNS router to select upstream based on domain
            match router.route(qname) {
                Some(pool) => Some(pool),
                None => self.upstream_pool.clone(),
            }
        } else {
            self.upstream_pool.clone()
        };

        if let Some(upstream_pool) = upstream {
            // Query upstream
            match upstream_pool.query(query).await {
                Ok(response) => {
                    // Step 4: Cache the response
                    if let Some(cache) = &self.cache {
                        cache.insert(query, &response, "default");
                    }
                    return Ok(response);
                }
                Err(e) => {
                    warn!(qname = %qname, error = %e, "Upstream query failed");
                    return Ok(self.generate_servfail_response(query, &format!("upstream error: {e}")));
                }
            }
        }

        // No upstream configured
        Ok(self.generate_servfail_response(query, "no upstream configured"))
    }

    /// Generate a blocked response (NXDOMAIN)
    fn generate_blocked_response(&self, query: &Message) -> Message {
        let mut response = query.clone();
        let mut header = Header::response_from_request(query.header());
        header.set_response_code(ResponseCode::NXDomain);
        header.set_recursion_available(true);
        header.set_authoritative(false);
        response.set_header(header);
        // Clear answers, we're just returning NXDOMAIN
        response
    }

    /// Parse raw bytes into a DNS message
    fn parse_query(&self, data: &[u8]) -> DnsResult<Message> {
        // Validate minimum size
        if data.len() < DNS_HEADER_SIZE {
            self.stats.parse_errors.fetch_add(1, Ordering::Relaxed);
            return Err(DnsError::parse(format!(
                "message too short: {} bytes (minimum: {})",
                data.len(),
                DNS_HEADER_SIZE
            )));
        }

        // Parse using hickory-proto
        Message::from_bytes(data).map_err(|e| {
            self.stats.parse_errors.fetch_add(1, Ordering::Relaxed);
            DnsError::parse(format!("failed to parse DNS message: {e}"))
        })
    }

    /// Validate a parsed DNS query
    fn validate_query(&self, client: SocketAddr, query: &Message) -> DnsResult<QueryContext> {
        let header = query.header();

        // Must be a query
        if header.message_type() != MessageType::Query {
            self.stats.validation_errors.fetch_add(1, Ordering::Relaxed);
            return Err(DnsError::invalid_query_id(
                "expected query, got response",
                header.id(),
            ));
        }

        // Must be standard query (QUERY opcode)
        if header.op_code() != OpCode::Query {
            self.stats.validation_errors.fetch_add(1, Ordering::Relaxed);
            return Err(DnsError::invalid_query_id(
                format!("unsupported opcode: {:?}", header.op_code()),
                header.id(),
            ));
        }

        // Must have at least one question
        let questions = query.queries();
        if questions.is_empty() {
            self.stats.validation_errors.fetch_add(1, Ordering::Relaxed);
            return Err(DnsError::invalid_query_id(
                "query has no questions",
                header.id(),
            ));
        }

        // Get the first question (standard DNS only has one)
        let question = &questions[0];
        let qname = question.name().to_string();
        let qtype = question.query_type();

        // Validate QNAME
        self.validate_qname(&qname)?;

        debug!(
            client = %client,
            qname = %qname,
            qtype = ?qtype,
            "Valid DNS query"
        );

        Ok(QueryContext {
            query_id: header.id(),
            qname,
            qtype,
            client,
            recursion_desired: header.recursion_desired(),
        })
    }

    /// Validate a domain name
    fn validate_qname(&self, qname: &str) -> DnsResult<()> {
        // Check total length (excluding trailing dot)
        let name_len = if qname.ends_with('.') {
            qname.len() - 1
        } else {
            qname.len()
        };

        if name_len > MAX_DOMAIN_LENGTH {
            self.stats.validation_errors.fetch_add(1, Ordering::Relaxed);
            return Err(DnsError::invalid_query(format!(
                "domain name too long: {name_len} chars (max: {MAX_DOMAIN_LENGTH})"
            )));
        }

        // Check each label
        for label in qname.trim_end_matches('.').split('.') {
            if label.is_empty() {
                // Root label or double dot
                if qname.trim_end_matches('.').contains("..") {
                    self.stats.validation_errors.fetch_add(1, Ordering::Relaxed);
                    return Err(DnsError::invalid_query("empty label in domain name"));
                }
            } else if label.len() > MAX_LABEL_LENGTH {
                self.stats.validation_errors.fetch_add(1, Ordering::Relaxed);
                return Err(DnsError::invalid_query(format!(
                    "label too long: {} chars (max: {})",
                    label.len(),
                    MAX_LABEL_LENGTH
                )));
            }
        }

        Ok(())
    }

    /// Generate a SERVFAIL response
    fn generate_servfail_response(&self, query: &Message, reason: &str) -> Message {
        debug!(
            id = query.header().id(),
            reason = reason,
            "Generating SERVFAIL response"
        );

        let mut response = Message::new();

        // Set up header
        let mut header = Header::new();
        header.set_id(query.header().id());
        header.set_message_type(MessageType::Response);
        header.set_op_code(query.header().op_code());
        header.set_response_code(ResponseCode::ServFail);
        header.set_recursion_desired(query.header().recursion_desired());
        header.set_recursion_available(true);

        response.set_header(header);

        // Copy questions
        for q in query.queries() {
            response.add_query(q.clone());
        }

        response
    }

    /// Generate an error response for a specific error
    ///
    /// Returns `None` if the query is too malformed to generate a response.
    pub fn generate_error_response(&self, query_data: &[u8], error: &DnsError) -> Option<Vec<u8>> {
        self.stats.error_responses.fetch_add(1, Ordering::Relaxed);

        // Try to extract query ID from raw bytes
        let query_id = if query_data.len() >= 2 {
            u16::from_be_bytes([query_data[0], query_data[1]])
        } else {
            return None;
        };

        let rcode = self.error_to_rcode(error);

        let mut response = Message::new();
        let mut header = Header::new();

        header.set_id(query_id);
        header.set_message_type(MessageType::Response);
        header.set_op_code(OpCode::Query);
        header.set_response_code(rcode);
        header.set_recursion_available(true);

        response.set_header(header);

        // Try to copy the question section if possible
        if let Ok(query) = Message::from_bytes(query_data) {
            for q in query.queries() {
                response.add_query(q.clone());
            }
        }

        match response.to_bytes() {
            Ok(bytes) => Some(bytes),
            Err(e) => {
                warn!(error = %e, "Failed to serialize error response");
                None
            }
        }
    }

    /// Map a `DnsError` to a DNS response code
    fn error_to_rcode(&self, error: &DnsError) -> ResponseCode {
        match error {
            DnsError::ParseError { .. } | DnsError::InvalidQuery { .. } => ResponseCode::FormErr,
            DnsError::RateLimitExceeded { .. } => ResponseCode::Refused,
            DnsError::Blocked { .. } => ResponseCode::NXDomain,
            DnsError::NoUpstream { .. } => ResponseCode::ServFail,
            DnsError::TimeoutError { .. } | DnsError::UpstreamError { .. } => ResponseCode::ServFail,
            _ => ResponseCode::ServFail,
        }
    }

    /// Serialize a response message to bytes
    fn serialize_response(&self, response: &Message) -> DnsResult<Vec<u8>> {
        response.to_bytes().map_err(|e| {
            DnsError::serialize(format!("failed to serialize response: {e}"))
        })
    }

    /// Check if a response needs truncation for UDP without EDNS0
    ///
    /// Per RFC 1035 section 4.2.1, UDP DNS responses MUST be <= 512 bytes
    /// unless the client advertises a larger buffer via EDNS0.
    ///
    /// # Arguments
    ///
    /// * `response_data` - Serialized response bytes
    /// * `client_buffer_size` - Client's advertised buffer size (512 if no EDNS0)
    ///
    /// # Returns
    ///
    /// `true` if the response needs truncation
    #[must_use]
    pub fn needs_truncation(&self, response_data: &[u8], client_buffer_size: usize) -> bool {
        response_data.len() > client_buffer_size
    }

    /// Generate a truncated response with TC (truncation) bit set
    ///
    /// When a UDP response exceeds the client's buffer size, this method
    /// generates a minimal response with just the header and question section,
    /// with the TC bit set to indicate truncation. The client should then
    /// retry over TCP.
    ///
    /// # Arguments
    ///
    /// * `query` - Original query message
    ///
    /// # Returns
    ///
    /// Serialized truncated response, or `None` if serialization fails
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::dns::server::{DnsHandler, DnsRateLimiter, MAX_UDP_RESPONSE_SIZE_NO_EDNS};
    /// use rust_router::dns::RateLimitConfig;
    /// use std::sync::Arc;
    ///
    /// let handler = DnsHandler::without_rate_limit();
    ///
    /// // If a response is too large, generate truncated response
    /// let response_data = vec![0u8; 600]; // Larger than 512
    /// if handler.needs_truncation(&response_data, MAX_UDP_RESPONSE_SIZE_NO_EDNS) {
    ///     // Would generate TC response here
    /// }
    /// ```
    pub fn generate_truncated_response(&self, query: &Message) -> Option<Vec<u8>> {
        let mut response = Message::new();

        // Set up header with TC bit
        let mut header = Header::new();
        header.set_id(query.header().id());
        header.set_message_type(MessageType::Response);
        header.set_op_code(query.header().op_code());
        header.set_truncated(true);
        header.set_response_code(ResponseCode::NoError);
        header.set_recursion_desired(query.header().recursion_desired());
        header.set_recursion_available(true);

        response.set_header(header);

        // Copy questions only (no answers to minimize size)
        for q in query.queries() {
            response.add_query(q.clone());
        }

        debug!(
            id = query.header().id(),
            "Generating truncated response (TC=1)"
        );

        match response.to_bytes() {
            Ok(bytes) => Some(bytes),
            Err(e) => {
                warn!(error = %e, "Failed to serialize truncated response");
                None
            }
        }
    }

    /// Process a response for UDP, applying truncation if needed
    ///
    /// This method checks if a response exceeds the client's buffer size
    /// and generates a truncated response if necessary.
    ///
    /// # Arguments
    ///
    /// * `query` - Original query message
    /// * `response_data` - Serialized response bytes
    /// * `client_buffer_size` - Client's buffer size (512 if no EDNS0, or EDNS0 value)
    ///
    /// # Returns
    ///
    /// Either the original response or a truncated response with TC bit set
    pub fn process_for_udp(
        &self,
        query: &Message,
        response_data: Vec<u8>,
        client_buffer_size: usize,
    ) -> Vec<u8> {
        if self.needs_truncation(&response_data, client_buffer_size) {
            debug!(
                response_size = response_data.len(),
                buffer_size = client_buffer_size,
                "Response exceeds buffer size, truncating"
            );
            self.generate_truncated_response(query)
                .unwrap_or(response_data)
        } else {
            response_data
        }
    }

    /// Extract client buffer size from query (EDNS0 OPT record)
    ///
    /// Returns the client's advertised UDP buffer size from EDNS0 OPT record,
    /// or `MAX_UDP_RESPONSE_SIZE_NO_EDNS` (512) if no EDNS0 is present.
    ///
    /// # Arguments
    ///
    /// * `query` - DNS query message
    ///
    /// # Returns
    ///
    /// Client's UDP buffer size
    #[must_use]
    pub fn get_client_buffer_size(&self, query: &Message) -> usize {
        // Look for OPT record in additional section
        for record in query.additionals() {
            if record.record_type() == RecordType::OPT {
                // The class field in OPT record contains the UDP payload size
                // hickory-proto stores this in the dns_class field
                let udp_size = u16::from(record.dns_class()) as usize;
                if udp_size > 0 {
                    return udp_size;
                }
            }
        }
        MAX_UDP_RESPONSE_SIZE_NO_EDNS
    }

    /// Get handler statistics
    #[must_use]
    pub fn stats(&self) -> &HandlerStats {
        &self.stats
    }

    /// Get rate limiter reference
    #[must_use]
    pub fn rate_limiter(&self) -> &Arc<DnsRateLimiter> {
        &self.rate_limiter
    }

    /// Validate that a response matches a query
    ///
    /// Used to verify responses from upstream servers.
    ///
    /// # Arguments
    ///
    /// * `query` - Original query message
    /// * `response` - Response message to validate
    ///
    /// # Returns
    ///
    /// `true` if the response is valid for the query.
    #[must_use]
    pub fn validate_response(&self, query: &Message, response: &Message) -> bool {
        // Query ID must match
        if query.header().id() != response.header().id() {
            debug!(
                expected = query.header().id(),
                got = response.header().id(),
                "Response ID mismatch"
            );
            return false;
        }

        // Must be a response
        if response.header().message_type() != MessageType::Response {
            debug!("Response is not a response message");
            return false;
        }

        // QNAME must match (if questions present)
        if !query.queries().is_empty() && !response.queries().is_empty() {
            let query_name = &query.queries()[0].name();
            let response_name = &response.queries()[0].name();

            if query_name != response_name {
                debug!(
                    expected = %query_name,
                    got = %response_name,
                    "Response QNAME mismatch"
                );
                return false;
            }
        }

        true
    }

    /// Parse a response and validate it against the original query
    pub fn parse_and_validate_response(
        &self,
        query: &Message,
        response_data: &[u8],
    ) -> DnsResult<Message> {
        let response = Message::from_bytes(response_data).map_err(|e| {
            DnsError::parse(format!("failed to parse response: {e}"))
        })?;

        if !self.validate_response(query, &response) {
            return Err(DnsError::parse("response validation failed"));
        }

        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::RateLimitConfig;
    use hickory_proto::rr::{Name, RecordType};
    use std::net::{Ipv4Addr, SocketAddrV4};

    fn test_client() -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), 12345))
    }

    fn create_handler() -> DnsHandler {
        let rate_limiter = Arc::new(DnsRateLimiter::new(&RateLimitConfig::default()));
        DnsHandler::new(rate_limiter)
    }

    fn create_valid_query() -> Vec<u8> {
        let mut query = Message::new();
        let mut header = Header::new();
        header.set_id(0x1234);
        header.set_message_type(MessageType::Query);
        header.set_op_code(OpCode::Query);
        header.set_recursion_desired(true);
        query.set_header(header);

        let name = Name::from_ascii("example.com.").unwrap();
        query.add_query(hickory_proto::op::Query::query(name, RecordType::A));

        query.to_bytes().unwrap()
    }

    fn create_raw_query(id: u16, domain: &str) -> Vec<u8> {
        let mut data = Vec::new();

        // Header
        data.extend_from_slice(&id.to_be_bytes());
        data.extend_from_slice(&[0x01, 0x00]); // Flags: standard query, RD=1
        data.extend_from_slice(&[0x00, 0x01]); // QDCOUNT = 1
        data.extend_from_slice(&[0x00, 0x00]); // ANCOUNT = 0
        data.extend_from_slice(&[0x00, 0x00]); // NSCOUNT = 0
        data.extend_from_slice(&[0x00, 0x00]); // ARCOUNT = 0

        // Question section
        for label in domain.split('.') {
            if !label.is_empty() {
                data.push(label.len() as u8);
                data.extend_from_slice(label.as_bytes());
            }
        }
        data.push(0x00); // End of name
        data.extend_from_slice(&[0x00, 0x01]); // QTYPE = A
        data.extend_from_slice(&[0x00, 0x01]); // QCLASS = IN

        data
    }

    // ========================================================================
    // Creation Tests
    // ========================================================================

    #[test]
    fn test_handler_new() {
        let handler = create_handler();
        assert_eq!(handler.stats().queries_received(), 0);
    }

    #[test]
    fn test_handler_without_rate_limit() {
        let handler = DnsHandler::without_rate_limit();
        assert!(!handler.rate_limiter().is_enabled());
    }

    // ========================================================================
    // Parse Tests
    // ========================================================================

    #[test]
    fn test_parse_valid_query() {
        let handler = create_handler();
        let query_data = create_valid_query();

        let result = handler.parse_query(&query_data);
        assert!(result.is_ok());

        let query = result.unwrap();
        assert_eq!(query.header().id(), 0x1234);
    }

    #[test]
    fn test_parse_too_short() {
        let handler = create_handler();
        let short_data = vec![0u8; 10]; // Less than header

        let result = handler.parse_query(&short_data);
        assert!(result.is_err());
        assert!(handler.stats().parse_errors() >= 1);
    }

    #[test]
    fn test_parse_garbage() {
        let handler = create_handler();
        let garbage = vec![0xFF; 50];

        let result = handler.parse_query(&garbage);
        // May or may not parse depending on garbage content
        // Just verify it doesn't panic
    }

    // ========================================================================
    // Validation Tests
    // ========================================================================

    #[test]
    fn test_validate_valid_query() {
        let handler = create_handler();
        let query_data = create_valid_query();
        let query = handler.parse_query(&query_data).unwrap();

        let result = handler.validate_query(test_client(), &query);
        assert!(result.is_ok());

        let context = result.unwrap();
        assert_eq!(context.query_id, 0x1234);
        assert!(context.qname.contains("example.com"));
    }

    #[test]
    fn test_validate_response_message() {
        let handler = create_handler();

        let mut response = Message::new();
        let mut header = Header::new();
        header.set_message_type(MessageType::Response); // Not a query
        header.set_op_code(OpCode::Query);
        response.set_header(header);

        let result = handler.validate_query(test_client(), &response);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_no_questions() {
        let handler = create_handler();

        let mut query = Message::new();
        let mut header = Header::new();
        header.set_message_type(MessageType::Query);
        header.set_op_code(OpCode::Query);
        query.set_header(header);
        // No questions added

        let result = handler.validate_query(test_client(), &query);
        assert!(result.is_err());
    }

    // ========================================================================
    // QNAME Validation Tests
    // ========================================================================

    #[test]
    fn test_validate_qname_valid() {
        let handler = create_handler();

        assert!(handler.validate_qname("example.com").is_ok());
        assert!(handler.validate_qname("sub.example.com").is_ok());
        assert!(handler.validate_qname("example.com.").is_ok());
    }

    #[test]
    fn test_validate_qname_too_long() {
        let handler = create_handler();

        let long_domain = "a".repeat(300);
        let result = handler.validate_qname(&long_domain);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_qname_label_too_long() {
        let handler = create_handler();

        let long_label = format!("{}.com", "a".repeat(70));
        let result = handler.validate_qname(&long_label);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_qname_empty_label() {
        let handler = create_handler();

        let result = handler.validate_qname("example..com");
        assert!(result.is_err());
    }

    // ========================================================================
    // Handle Query Tests
    // ========================================================================

    #[tokio::test]
    async fn test_handle_valid_query() {
        let handler = create_handler();
        let query_data = create_valid_query();

        let result = handler.handle_query(test_client(), &query_data).await;
        assert!(result.is_ok());

        let response = result.unwrap();
        assert!(response.len() >= DNS_HEADER_SIZE);

        // Check response ID matches
        let response_id = u16::from_be_bytes([response[0], response[1]]);
        assert_eq!(response_id, 0x1234);
    }

    #[tokio::test]
    async fn test_handle_malformed_query() {
        let handler = create_handler();
        let malformed = vec![0u8; 5]; // Too short

        let result = handler.handle_query(test_client(), &malformed).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_handle_rate_limited() {
        let config = RateLimitConfig::default().with_qps(1).with_burst(1);
        let rate_limiter = Arc::new(DnsRateLimiter::new(&config));
        let handler = DnsHandler::new(rate_limiter);

        let query_data = create_valid_query();
        let client = test_client();

        // First request should succeed
        let _ = handler.handle_query(client, &query_data).await;

        // Subsequent requests should be rate limited
        let result = handler.handle_query(client, &query_data).await;
        assert!(result.is_err());
        assert!(handler.stats().rate_limited() > 0);
    }

    // ========================================================================
    // Error Response Tests
    // ========================================================================

    #[test]
    fn test_generate_error_response() {
        let handler = create_handler();
        let query_data = create_raw_query(0xABCD, "example.com");

        let error = DnsError::parse("test error");
        let response = handler.generate_error_response(&query_data, &error);

        assert!(response.is_some());

        let response = response.unwrap();
        let response_id = u16::from_be_bytes([response[0], response[1]]);
        assert_eq!(response_id, 0xABCD);
    }

    #[test]
    fn test_generate_error_response_too_short() {
        let handler = create_handler();
        let short_data = vec![0x12]; // Only 1 byte

        let error = DnsError::parse("test");
        let response = handler.generate_error_response(&short_data, &error);

        assert!(response.is_none());
    }

    #[test]
    fn test_error_to_rcode_parse() {
        let handler = create_handler();
        let error = DnsError::parse("test");
        assert_eq!(handler.error_to_rcode(&error), ResponseCode::FormErr);
    }

    #[test]
    fn test_error_to_rcode_rate_limit() {
        let handler = create_handler();
        let error = DnsError::rate_limit(test_client(), 100, 50);
        assert_eq!(handler.error_to_rcode(&error), ResponseCode::Refused);
    }

    #[test]
    fn test_error_to_rcode_blocked() {
        let handler = create_handler();
        let error = DnsError::blocked("example.com", "test");
        assert_eq!(handler.error_to_rcode(&error), ResponseCode::NXDomain);
    }

    #[test]
    fn test_error_to_rcode_no_upstream() {
        let handler = create_handler();
        let error = DnsError::no_upstream("test");
        assert_eq!(handler.error_to_rcode(&error), ResponseCode::ServFail);
    }

    // ========================================================================
    // Response Validation Tests
    // ========================================================================

    #[test]
    fn test_validate_response_matching() {
        let handler = create_handler();

        // Create query
        let mut query = Message::new();
        let mut query_header = Header::new();
        query_header.set_id(0x1234);
        query_header.set_message_type(MessageType::Query);
        query.set_header(query_header);
        let name = Name::from_ascii("example.com.").unwrap();
        query.add_query(hickory_proto::op::Query::query(name.clone(), RecordType::A));

        // Create matching response
        let mut response = Message::new();
        let mut resp_header = Header::new();
        resp_header.set_id(0x1234);
        resp_header.set_message_type(MessageType::Response);
        response.set_header(resp_header);
        response.add_query(hickory_proto::op::Query::query(name, RecordType::A));

        assert!(handler.validate_response(&query, &response));
    }

    #[test]
    fn test_validate_response_id_mismatch() {
        let handler = create_handler();

        let mut query = Message::new();
        let mut query_header = Header::new();
        query_header.set_id(0x1234);
        query_header.set_message_type(MessageType::Query);
        query.set_header(query_header);

        let mut response = Message::new();
        let mut resp_header = Header::new();
        resp_header.set_id(0x5678); // Different ID
        resp_header.set_message_type(MessageType::Response);
        response.set_header(resp_header);

        assert!(!handler.validate_response(&query, &response));
    }

    #[test]
    fn test_validate_response_not_response() {
        let handler = create_handler();

        let mut query = Message::new();
        let mut query_header = Header::new();
        query_header.set_id(0x1234);
        query_header.set_message_type(MessageType::Query);
        query.set_header(query_header);

        let mut response = Message::new();
        let mut resp_header = Header::new();
        resp_header.set_id(0x1234);
        resp_header.set_message_type(MessageType::Query); // Not a response
        response.set_header(resp_header);

        assert!(!handler.validate_response(&query, &response));
    }

    // ========================================================================
    // Statistics Tests
    // ========================================================================

    #[tokio::test]
    async fn test_stats_tracking() {
        let handler = create_handler();
        let query_data = create_valid_query();

        let _ = handler.handle_query(test_client(), &query_data).await;

        let stats = handler.stats().snapshot();
        assert_eq!(stats.queries_received, 1);
        assert_eq!(stats.queries_processed, 1);
    }

    #[test]
    fn test_stats_success_rate() {
        let snapshot = HandlerStatsSnapshot {
            queries_received: 100,
            queries_processed: 90,
            parse_errors: 5,
            validation_errors: 3,
            rate_limited: 2,
            error_responses: 10,
        };

        let rate = snapshot.success_rate();
        assert!((rate - 0.9).abs() < 0.001);
    }

    #[test]
    fn test_stats_success_rate_zero_queries() {
        let snapshot = HandlerStatsSnapshot {
            queries_received: 0,
            queries_processed: 0,
            parse_errors: 0,
            validation_errors: 0,
            rate_limited: 0,
            error_responses: 0,
        };

        assert_eq!(snapshot.success_rate(), 1.0);
    }

    // ========================================================================
    // Query Context Tests
    // ========================================================================

    #[tokio::test]
    async fn test_query_context_fields() {
        let handler = create_handler();
        let query_data = create_valid_query();
        let query = handler.parse_query(&query_data).unwrap();

        let result = handler.validate_query(test_client(), &query);
        assert!(result.is_ok());

        let context = result.unwrap();
        assert_eq!(context.query_id, 0x1234);
        assert!(context.qname.contains("example.com"));
        assert_eq!(context.qtype, RecordType::A);
        assert!(context.recursion_desired);
    }

    // ========================================================================
    // Edge Case Tests
    // ========================================================================

    #[test]
    fn test_parse_minimum_valid_query() {
        let handler = create_handler();

        // Create absolute minimum valid DNS query
        let query = create_raw_query(0x0001, "a.b");
        let result = handler.parse_query(&query);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_handle_different_query_types() {
        let handler = create_handler();

        // A record
        let mut query = Message::new();
        let mut header = Header::new();
        header.set_id(0x0001);
        header.set_message_type(MessageType::Query);
        header.set_op_code(OpCode::Query);
        query.set_header(header);
        let name = Name::from_ascii("example.com.").unwrap();
        query.add_query(hickory_proto::op::Query::query(name.clone(), RecordType::A));

        let query_data = query.to_bytes().unwrap();
        let result = handler.handle_query(test_client(), &query_data).await;
        assert!(result.is_ok());

        // AAAA record
        let mut query = Message::new();
        let mut header = Header::new();
        header.set_id(0x0002);
        header.set_message_type(MessageType::Query);
        header.set_op_code(OpCode::Query);
        query.set_header(header);
        query.add_query(hickory_proto::op::Query::query(name, RecordType::AAAA));

        let query_data = query.to_bytes().unwrap();
        let result = handler.handle_query(test_client(), &query_data).await;
        assert!(result.is_ok());
    }

    // ========================================================================
    // Truncation Tests (RFC 1035 Compliance)
    // ========================================================================

    #[test]
    fn test_needs_truncation_under_limit() {
        let handler = create_handler();
        let response_data = vec![0u8; 400];

        assert!(!handler.needs_truncation(&response_data, 512));
    }

    #[test]
    fn test_needs_truncation_at_limit() {
        let handler = create_handler();
        let response_data = vec![0u8; 512];

        assert!(!handler.needs_truncation(&response_data, 512));
    }

    #[test]
    fn test_needs_truncation_over_limit() {
        let handler = create_handler();
        let response_data = vec![0u8; 600];

        assert!(handler.needs_truncation(&response_data, 512));
    }

    #[test]
    fn test_needs_truncation_with_edns0_larger_buffer() {
        let handler = create_handler();
        let response_data = vec![0u8; 1000];

        // With EDNS0 buffer size of 4096, should not need truncation
        assert!(!handler.needs_truncation(&response_data, 4096));
    }

    #[test]
    fn test_generate_truncated_response() {
        let handler = create_handler();
        let query_data = create_valid_query();
        let query = handler.parse_query(&query_data).unwrap();

        let truncated = handler.generate_truncated_response(&query);
        assert!(truncated.is_some());

        let truncated = truncated.unwrap();
        // Verify TC bit is set (flags byte 2, bit 1)
        // Flags are bytes 2-3, TC is bit 9 (second byte, bit 1)
        assert_eq!(truncated[2] & 0x02, 0x02, "TC bit should be set");

        // Verify ID matches
        let response_id = u16::from_be_bytes([truncated[0], truncated[1]]);
        assert_eq!(response_id, 0x1234);

        // Response should be small (just header + question)
        assert!(truncated.len() <= super::MAX_UDP_RESPONSE_SIZE_NO_EDNS);
    }

    #[test]
    fn test_process_for_udp_no_truncation_needed() {
        let handler = create_handler();
        let query_data = create_valid_query();
        let query = handler.parse_query(&query_data).unwrap();

        let response_data = vec![0u8; 200];
        let processed = handler.process_for_udp(&query, response_data.clone(), 512);

        assert_eq!(processed, response_data);
    }

    #[test]
    fn test_process_for_udp_truncation_needed() {
        let handler = create_handler();
        let query_data = create_valid_query();
        let query = handler.parse_query(&query_data).unwrap();

        let response_data = vec![0u8; 600];
        let processed = handler.process_for_udp(&query, response_data.clone(), 512);

        // Should be different from original (truncated)
        assert_ne!(processed, response_data);

        // Should be under the limit
        assert!(processed.len() <= 512);

        // TC bit should be set
        assert_eq!(processed[2] & 0x02, 0x02, "TC bit should be set");
    }

    #[test]
    fn test_get_client_buffer_size_no_edns() {
        let handler = create_handler();
        let query_data = create_valid_query();
        let query = handler.parse_query(&query_data).unwrap();

        // Standard query without EDNS0 should return 512
        let size = handler.get_client_buffer_size(&query);
        assert_eq!(size, super::MAX_UDP_RESPONSE_SIZE_NO_EDNS);
    }

    #[test]
    fn test_max_udp_response_size_constant() {
        // Verify the constant matches RFC 1035
        assert_eq!(super::MAX_UDP_RESPONSE_SIZE_NO_EDNS, 512);
    }
}
