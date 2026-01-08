//! DNS Upstream Client Traits
//!
//! This module defines the core traits for DNS upstream clients, providing
//! a unified interface for querying upstream DNS servers across different
//! protocols (UDP, TCP, DoH, DoT).
//!
//! # Example
//!
//! ```no_run
//! use rust_router::dns::client::{DnsUpstream, UpstreamProtocol};
//! use hickory_proto::op::Message;
//!
//! async fn query_upstream(upstream: &dyn DnsUpstream, query: &Message) {
//!     if upstream.is_healthy() {
//!         match upstream.query(query).await {
//!             Ok(response) => println!("Got response"),
//!             Err(e) => println!("Query failed: {}", e),
//!         }
//!     }
//! }
//! ```

use std::fmt::Debug;
use std::time::Duration;

use async_trait::async_trait;
use hickory_proto::op::Message;

use crate::dns::config::UpstreamProtocol;
use crate::dns::error::DnsResult;

/// Default query timeout in seconds
pub const DEFAULT_QUERY_TIMEOUT_SECS: u64 = 5;

/// Default number of retries for UDP queries
pub const DEFAULT_UDP_RETRIES: u32 = 2;

/// Maximum DNS message size for UDP (without EDNS)
pub const MAX_UDP_MESSAGE_SIZE: usize = 512;

/// Maximum DNS message size for TCP/DoH/DoT
pub const MAX_TCP_MESSAGE_SIZE: usize = 65535;

/// Trait for DNS upstream clients
///
/// This trait provides a unified interface for querying DNS servers
/// across different protocols. All implementations must be thread-safe
/// and async-compatible.
///
/// # Thread Safety
///
/// All implementations must be `Send + Sync` to allow sharing across
/// async tasks and threads.
///
/// # Example
///
/// ```no_run
/// use rust_router::dns::client::DnsUpstream;
/// use hickory_proto::op::Message;
///
/// async fn example(upstream: &dyn DnsUpstream) {
///     let mut query = Message::new();
///     query.set_id(0x1234);
///     // ... set up query ...
///
///     match upstream.query(&query).await {
///         Ok(response) => println!("Response: {:?}", response),
///         Err(e) => println!("Error: {}", e),
///     }
/// }
/// ```
#[async_trait]
pub trait DnsUpstream: Send + Sync + Debug {
    /// Send a DNS query and await the response
    ///
    /// # Arguments
    ///
    /// * `query` - The DNS query message to send
    ///
    /// # Returns
    ///
    /// The DNS response message, or an error if the query failed.
    ///
    /// # Errors
    ///
    /// Returns `DnsError` if:
    /// - Network connection fails
    /// - Query times out
    /// - Response validation fails (wrong ID, truncated, etc.)
    /// - Upstream server returns an error response
    async fn query(&self, query: &Message) -> DnsResult<Message>;

    /// Check if this upstream is currently healthy
    ///
    /// Health is determined by the health checker based on recent
    /// query success/failure patterns.
    ///
    /// # Returns
    ///
    /// `true` if the upstream is healthy and should be used for queries,
    /// `false` if the upstream is unhealthy and should be avoided.
    fn is_healthy(&self) -> bool;

    /// Get the protocol used by this upstream
    ///
    /// # Returns
    ///
    /// The protocol type (UDP, TCP, DoH, DoT, DoQ)
    fn protocol(&self) -> UpstreamProtocol;

    /// Get the upstream server address
    ///
    /// The format depends on the protocol:
    /// - UDP/TCP: `ip:port` (e.g., `8.8.8.8:53`)
    /// - DoH: Full URL (e.g., `https://dns.google/dns-query`)
    /// - DoT: `hostname:port` (e.g., `dns.google:853`)
    ///
    /// # Returns
    ///
    /// The server address as a string
    fn address(&self) -> &str;

    /// Get the unique tag/name for this upstream
    ///
    /// Used for logging and upstream selection rules.
    fn tag(&self) -> &str;

    /// Get the configured query timeout
    ///
    /// # Returns
    ///
    /// The timeout duration for queries
    fn timeout(&self) -> Duration {
        Duration::from_secs(DEFAULT_QUERY_TIMEOUT_SECS)
    }

    /// Check if this upstream uses an encrypted protocol
    ///
    /// # Returns
    ///
    /// `true` for DoH, DoT, DoQ; `false` for plain UDP/TCP
    fn is_encrypted(&self) -> bool {
        matches!(
            self.protocol(),
            UpstreamProtocol::Doh | UpstreamProtocol::Dot | UpstreamProtocol::Doq
        )
    }

    /// Mark this upstream as unhealthy
    ///
    /// Called by the health checker when failures exceed the threshold.
    /// This should update the internal health state.
    fn mark_unhealthy(&self);

    /// Mark this upstream as healthy
    ///
    /// Called by the health checker when the upstream recovers.
    /// This should update the internal health state.
    fn mark_healthy(&self);
}

/// Query context for tracking query metadata
///
/// Used to pass additional information about a query through the
/// upstream processing pipeline.
#[derive(Debug, Clone)]
pub struct QueryMetadata {
    /// The query ID from the original request
    pub query_id: u16,
    /// The query name (domain being queried)
    pub qname: String,
    /// The query type (A=1, AAAA=28, etc.)
    pub qtype: u16,
    /// The query class (usually IN=1)
    pub qclass: u16,
    /// Whether the query is recursive
    pub recursive: bool,
}

impl QueryMetadata {
    /// Create metadata from a DNS message
    ///
    /// # Arguments
    ///
    /// * `message` - The DNS query message
    ///
    /// # Returns
    ///
    /// `Some(QueryMetadata)` if the message has at least one question,
    /// `None` otherwise.
    pub fn from_message(message: &Message) -> Option<Self> {
        let query = message.queries().first()?;
        Some(Self {
            query_id: message.id(),
            qname: query.name().to_string(),
            qtype: query.query_type().into(),
            qclass: query.query_class().into(),
            recursive: message.recursion_desired(),
        })
    }
}

/// Validate that a DNS response matches the original query
///
/// Checks that the response has the same query ID and question section
/// as the original query. This prevents cache poisoning attacks.
///
/// # Arguments
///
/// * `query` - The original DNS query
/// * `response` - The DNS response to validate
///
/// # Returns
///
/// `true` if the response is valid, `false` otherwise.
pub fn validate_response(query: &Message, response: &Message) -> bool {
    // Check query ID matches
    if query.id() != response.id() {
        return false;
    }

    // Check that response has at least one question
    if response.queries().is_empty() {
        return false;
    }

    // Check that question section matches
    if let (Some(q_query), Some(r_query)) = (query.queries().first(), response.queries().first()) {
        if q_query.name() != r_query.name() {
            return false;
        }
        if q_query.query_type() != r_query.query_type() {
            return false;
        }
        if q_query.query_class() != r_query.query_class() {
            return false;
        }
    } else {
        return false;
    }

    true
}

/// Set the query ID on a message
///
/// Creates a new message with the specified ID, preserving all other fields.
///
/// # Arguments
///
/// * `message` - The message to modify
/// * `id` - The new query ID
///
/// # Returns
///
/// A new message with the updated ID
pub fn set_query_id(mut message: Message, id: u16) -> Message {
    message.set_id(id);
    message
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{MessageType, Query, ResponseCode};
    use hickory_proto::rr::{DNSClass, Name, RecordType};
    use std::str::FromStr;

    // ========================================================================
    // Helper Functions
    // ========================================================================

    fn create_query(domain: &str, id: u16) -> Message {
        let mut message = Message::new();
        message.set_id(id);
        message.set_recursion_desired(true);

        let name = Name::from_str(domain).unwrap();
        let query = Query::query(name, RecordType::A);
        message.add_query(query);

        message
    }

    fn create_response(domain: &str, id: u16) -> Message {
        let mut message = Message::new();
        message.set_id(id);
        message.set_message_type(MessageType::Response);
        message.set_response_code(ResponseCode::NoError);
        message.set_recursion_desired(true);
        message.set_recursion_available(true);

        let name = Name::from_str(domain).unwrap();
        let query = Query::query(name, RecordType::A);
        message.add_query(query);

        message
    }

    // ========================================================================
    // Constants Tests
    // ========================================================================

    #[test]
    fn test_default_constants() {
        assert_eq!(DEFAULT_QUERY_TIMEOUT_SECS, 5);
        assert_eq!(DEFAULT_UDP_RETRIES, 2);
        assert_eq!(MAX_UDP_MESSAGE_SIZE, 512);
        assert_eq!(MAX_TCP_MESSAGE_SIZE, 65535);
    }

    // ========================================================================
    // QueryMetadata Tests
    // ========================================================================

    #[test]
    fn test_query_metadata_from_message() {
        let query = create_query("example.com.", 0x1234);
        let metadata = QueryMetadata::from_message(&query).unwrap();

        assert_eq!(metadata.query_id, 0x1234);
        assert!(metadata.qname.contains("example.com"));
        assert_eq!(metadata.qtype, 1); // A record
        assert_eq!(metadata.qclass, 1); // IN class
        assert!(metadata.recursive);
    }

    #[test]
    fn test_query_metadata_empty_message() {
        let message = Message::new();
        let metadata = QueryMetadata::from_message(&message);
        assert!(metadata.is_none());
    }

    #[test]
    fn test_query_metadata_non_recursive() {
        let mut query = create_query("example.com.", 0x5678);
        query.set_recursion_desired(false);

        let metadata = QueryMetadata::from_message(&query).unwrap();
        assert!(!metadata.recursive);
    }

    #[test]
    fn test_query_metadata_aaaa_query() {
        let mut message = Message::new();
        message.set_id(0x9ABC);

        let name = Name::from_str("example.com.").unwrap();
        let query = Query::query(name, RecordType::AAAA);
        message.add_query(query);

        let metadata = QueryMetadata::from_message(&message).unwrap();
        assert_eq!(metadata.qtype, 28); // AAAA record
    }

    // ========================================================================
    // Response Validation Tests
    // ========================================================================

    #[test]
    fn test_validate_response_matching() {
        let query = create_query("example.com.", 0x1234);
        let response = create_response("example.com.", 0x1234);

        assert!(validate_response(&query, &response));
    }

    #[test]
    fn test_validate_response_id_mismatch() {
        let query = create_query("example.com.", 0x1234);
        let response = create_response("example.com.", 0x5678);

        assert!(!validate_response(&query, &response));
    }

    #[test]
    fn test_validate_response_domain_mismatch() {
        let query = create_query("example.com.", 0x1234);
        let response = create_response("other.com.", 0x1234);

        assert!(!validate_response(&query, &response));
    }

    #[test]
    fn test_validate_response_type_mismatch() {
        let query = create_query("example.com.", 0x1234);

        // Create response with different query type
        let mut response = Message::new();
        response.set_id(0x1234);
        response.set_message_type(MessageType::Response);

        let name = Name::from_str("example.com.").unwrap();
        let q = Query::query(name, RecordType::AAAA); // Different type
        response.add_query(q);

        assert!(!validate_response(&query, &response));
    }

    #[test]
    fn test_validate_response_empty_questions() {
        let query = create_query("example.com.", 0x1234);

        let mut response = Message::new();
        response.set_id(0x1234);
        response.set_message_type(MessageType::Response);
        // No questions added

        assert!(!validate_response(&query, &response));
    }

    #[test]
    fn test_validate_response_class_mismatch() {
        let query = create_query("example.com.", 0x1234);

        let mut response = Message::new();
        response.set_id(0x1234);
        response.set_message_type(MessageType::Response);

        let name = Name::from_str("example.com.").unwrap();
        let mut q = Query::query(name, RecordType::A);
        q.set_query_class(DNSClass::CH); // Different class
        response.add_query(q);

        assert!(!validate_response(&query, &response));
    }

    // ========================================================================
    // set_query_id Tests
    // ========================================================================

    #[test]
    fn test_set_query_id() {
        let message = create_query("example.com.", 0x1234);
        assert_eq!(message.id(), 0x1234);

        let updated = set_query_id(message, 0x5678);
        assert_eq!(updated.id(), 0x5678);

        // Questions should be preserved
        assert_eq!(updated.queries().len(), 1);
    }

    #[test]
    fn test_set_query_id_preserves_flags() {
        let mut message = Message::new();
        message.set_id(0x1111);
        message.set_recursion_desired(true);
        message.set_checking_disabled(true);

        let updated = set_query_id(message, 0x2222);
        assert_eq!(updated.id(), 0x2222);
        assert!(updated.recursion_desired());
        assert!(updated.checking_disabled());
    }

    // ========================================================================
    // Encryption Detection Tests
    // ========================================================================

    #[test]
    fn test_protocol_is_encrypted() {
        assert!(!matches!(UpstreamProtocol::Udp, p if matches!(p, UpstreamProtocol::Doh | UpstreamProtocol::Dot | UpstreamProtocol::Doq)));
        assert!(!matches!(UpstreamProtocol::Tcp, p if matches!(p, UpstreamProtocol::Doh | UpstreamProtocol::Dot | UpstreamProtocol::Doq)));
        assert!(matches!(UpstreamProtocol::Doh, p if matches!(p, UpstreamProtocol::Doh | UpstreamProtocol::Dot | UpstreamProtocol::Doq)));
        assert!(matches!(UpstreamProtocol::Dot, p if matches!(p, UpstreamProtocol::Doh | UpstreamProtocol::Dot | UpstreamProtocol::Doq)));
        assert!(matches!(UpstreamProtocol::Doq, p if matches!(p, UpstreamProtocol::Doh | UpstreamProtocol::Dot | UpstreamProtocol::Doq)));
    }
}
