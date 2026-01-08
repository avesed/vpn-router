//! Blocked response builder for DNS ad blocking
//!
//! This module generates appropriate DNS responses for blocked domains,
//! supporting different response types:
//!
//! - **ZeroIp**: Return 0.0.0.0 for A queries and :: for AAAA queries
//! - **Nxdomain**: Return NXDOMAIN (domain does not exist)
//! - **Refused**: Return REFUSED (server refuses to answer)
//!
//! # Example
//!
//! ```
//! use rust_router::dns::filter::BlockedResponseBuilder;
//! use rust_router::dns::BlockResponseType;
//! use hickory_proto::op::{Message, Query};
//! use hickory_proto::rr::{Name, RecordType};
//! use std::str::FromStr;
//!
//! // Create a builder for zero-IP responses
//! let builder = BlockedResponseBuilder::new(BlockResponseType::ZeroIp);
//!
//! // Build response for a query
//! let mut query = Message::new();
//! query.set_id(0x1234);
//! let name = Name::from_str("blocked.example.com.").unwrap();
//! query.add_query(Query::query(name, RecordType::A));
//!
//! let response = builder.build_response(&query);
//! assert!(!response.answers().is_empty()); // Contains 0.0.0.0 answer
//! ```

use std::net::{Ipv4Addr, Ipv6Addr};

use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::{DNSClass, RData, Record, RecordType};

use crate::dns::BlockResponseType;

/// Default TTL for blocked responses (in seconds)
const BLOCKED_RESPONSE_TTL: u32 = 60;

/// Builder for creating DNS responses to blocked queries
///
/// Generates appropriate DNS responses based on the configured
/// response type. The response preserves the original query's
/// ID, question section, and flags while setting the appropriate
/// response code and answer section.
///
/// # Response Types
///
/// | Type | A Query Response | AAAA Query Response | Other Query Response |
/// |------|-----------------|--------------------|--------------------|
/// | ZeroIp | 0.0.0.0 | :: | NoError (empty) |
/// | Nxdomain | NXDOMAIN | NXDOMAIN | NXDOMAIN |
/// | Refused | REFUSED | REFUSED | REFUSED |
///
/// # Example
///
/// ```
/// use rust_router::dns::filter::BlockedResponseBuilder;
/// use rust_router::dns::BlockResponseType;
///
/// // Different response types
/// let zero_builder = BlockedResponseBuilder::new(BlockResponseType::ZeroIp);
/// let nx_builder = BlockedResponseBuilder::new(BlockResponseType::Nxdomain);
/// let refused_builder = BlockedResponseBuilder::new(BlockResponseType::Refused);
/// ```
#[derive(Debug, Clone)]
pub struct BlockedResponseBuilder {
    /// The type of response to generate
    response_type: BlockResponseType,

    /// TTL for answer records (only used for ZeroIp type)
    ttl: u32,
}

impl BlockedResponseBuilder {
    /// Create a new blocked response builder
    ///
    /// # Arguments
    ///
    /// * `response_type` - The type of response to generate for blocked domains
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::dns::filter::BlockedResponseBuilder;
    /// use rust_router::dns::BlockResponseType;
    ///
    /// let builder = BlockedResponseBuilder::new(BlockResponseType::ZeroIp);
    /// ```
    #[must_use]
    pub fn new(response_type: BlockResponseType) -> Self {
        Self {
            response_type,
            ttl: BLOCKED_RESPONSE_TTL,
        }
    }

    /// Set the TTL for answer records
    ///
    /// Only affects `ZeroIp` response type which includes answer records.
    ///
    /// # Arguments
    ///
    /// * `ttl` - Time-to-live in seconds
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::dns::filter::BlockedResponseBuilder;
    /// use rust_router::dns::BlockResponseType;
    ///
    /// let builder = BlockedResponseBuilder::new(BlockResponseType::ZeroIp)
    ///     .with_ttl(300);
    /// ```
    #[must_use]
    pub fn with_ttl(mut self, ttl: u32) -> Self {
        self.ttl = ttl;
        self
    }

    /// Get the configured response type
    #[must_use]
    pub fn response_type(&self) -> BlockResponseType {
        self.response_type
    }

    /// Get the configured TTL
    #[must_use]
    pub fn ttl(&self) -> u32 {
        self.ttl
    }

    /// Build a blocked response for the given query
    ///
    /// Creates a DNS response message appropriate for the configured
    /// response type. The response preserves the query's ID and
    /// question section.
    ///
    /// # Arguments
    ///
    /// * `query` - The original DNS query message
    ///
    /// # Returns
    ///
    /// A DNS response message indicating the domain is blocked.
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::dns::filter::BlockedResponseBuilder;
    /// use rust_router::dns::BlockResponseType;
    /// use hickory_proto::op::{Message, Query, ResponseCode};
    /// use hickory_proto::rr::{Name, RecordType};
    /// use std::str::FromStr;
    ///
    /// let builder = BlockedResponseBuilder::new(BlockResponseType::Nxdomain);
    ///
    /// let mut query = Message::new();
    /// query.set_id(0x1234);
    /// let name = Name::from_str("blocked.example.com.").unwrap();
    /// query.add_query(Query::query(name, RecordType::A));
    ///
    /// let response = builder.build_response(&query);
    /// assert_eq!(response.id(), 0x1234);
    /// assert_eq!(response.response_code(), ResponseCode::NXDomain);
    /// ```
    #[must_use]
    pub fn build_response(&self, query: &Message) -> Message {
        let mut response = Message::new();

        // Copy query ID
        response.set_id(query.id());

        // Set as response
        response.set_message_type(MessageType::Response);

        // Copy query flags
        response.set_recursion_desired(query.recursion_desired());
        response.set_recursion_available(true);
        response.set_authoritative(false);

        // Copy all queries to the response
        for q in query.queries() {
            response.add_query(q.clone());
        }

        // Build response based on type
        match self.response_type {
            BlockResponseType::ZeroIp => {
                response.set_response_code(ResponseCode::NoError);
                self.add_zero_ip_answers(&mut response, query);
            }
            BlockResponseType::Nxdomain => {
                response.set_response_code(ResponseCode::NXDomain);
            }
            BlockResponseType::Refused => {
                response.set_response_code(ResponseCode::Refused);
            }
        }

        response
    }

    /// Add zero-IP answer records to the response
    ///
    /// Adds 0.0.0.0 for A queries and :: for AAAA queries.
    /// Other query types get no answer records (NoError with empty answer).
    fn add_zero_ip_answers(&self, response: &mut Message, query: &Message) {
        for q in query.queries() {
            let name = q.name().clone();
            let qtype = q.query_type();

            match qtype {
                RecordType::A => {
                    let mut record = Record::new();
                    record.set_name(name);
                    record.set_record_type(RecordType::A);
                    record.set_dns_class(DNSClass::IN);
                    record.set_ttl(self.ttl);
                    record.set_data(Some(RData::A(hickory_proto::rr::rdata::A(
                        Ipv4Addr::new(0, 0, 0, 0),
                    ))));
                    response.add_answer(record);
                }
                RecordType::AAAA => {
                    let mut record = Record::new();
                    record.set_name(name);
                    record.set_record_type(RecordType::AAAA);
                    record.set_dns_class(DNSClass::IN);
                    record.set_ttl(self.ttl);
                    record.set_data(Some(RData::AAAA(hickory_proto::rr::rdata::AAAA(
                        Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0),
                    ))));
                    response.add_answer(record);
                }
                _ => {
                    // For other query types, just return NoError with no answer
                    // This is the safest approach for unsupported types
                }
            }
        }
    }

    /// Build a blocked response from raw query bytes
    ///
    /// Parses the query bytes, builds a response, and serializes it back.
    /// Returns `None` if the query cannot be parsed.
    ///
    /// # Arguments
    ///
    /// * `query_bytes` - Raw DNS query message bytes
    ///
    /// # Returns
    ///
    /// Serialized response bytes, or `None` if parsing fails.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rust_router::dns::filter::BlockedResponseBuilder;
    /// use rust_router::dns::BlockResponseType;
    ///
    /// let builder = BlockedResponseBuilder::new(BlockResponseType::ZeroIp);
    ///
    /// // Parse and respond to raw query bytes
    /// let query_bytes: Vec<u8> = vec![/* DNS query bytes */];
    /// if let Some(response_bytes) = builder.build_response_bytes(&query_bytes) {
    ///     // Send response_bytes back to client
    /// }
    /// ```
    #[must_use]
    pub fn build_response_bytes(&self, query_bytes: &[u8]) -> Option<Vec<u8>> {
        use hickory_proto::serialize::binary::BinDecodable;

        // Parse the query
        let query = Message::from_bytes(query_bytes).ok()?;

        // Build the response
        let response = self.build_response(&query);

        // Serialize the response
        response.to_vec().ok()
    }
}

impl Default for BlockedResponseBuilder {
    fn default() -> Self {
        Self::new(BlockResponseType::ZeroIp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::Query;
    use hickory_proto::rr::Name;
    use std::str::FromStr;

    // ========================================================================
    // Builder Creation Tests
    // ========================================================================

    #[test]
    fn test_builder_new_zero_ip() {
        let builder = BlockedResponseBuilder::new(BlockResponseType::ZeroIp);
        assert_eq!(builder.response_type(), BlockResponseType::ZeroIp);
        assert_eq!(builder.ttl(), BLOCKED_RESPONSE_TTL);
    }

    #[test]
    fn test_builder_new_nxdomain() {
        let builder = BlockedResponseBuilder::new(BlockResponseType::Nxdomain);
        assert_eq!(builder.response_type(), BlockResponseType::Nxdomain);
    }

    #[test]
    fn test_builder_new_refused() {
        let builder = BlockedResponseBuilder::new(BlockResponseType::Refused);
        assert_eq!(builder.response_type(), BlockResponseType::Refused);
    }

    #[test]
    fn test_builder_default() {
        let builder = BlockedResponseBuilder::default();
        assert_eq!(builder.response_type(), BlockResponseType::ZeroIp);
    }

    #[test]
    fn test_builder_with_ttl() {
        let builder = BlockedResponseBuilder::new(BlockResponseType::ZeroIp).with_ttl(300);
        assert_eq!(builder.ttl(), 300);
    }

    #[test]
    fn test_builder_debug() {
        let builder = BlockedResponseBuilder::new(BlockResponseType::ZeroIp);
        let debug = format!("{:?}", builder);
        assert!(debug.contains("BlockedResponseBuilder"));
        assert!(debug.contains("ZeroIp"));
    }

    #[test]
    fn test_builder_clone() {
        let builder = BlockedResponseBuilder::new(BlockResponseType::Nxdomain).with_ttl(120);
        let cloned = builder.clone();
        assert_eq!(cloned.response_type(), BlockResponseType::Nxdomain);
        assert_eq!(cloned.ttl(), 120);
    }

    // ========================================================================
    // ZeroIp Response Tests
    // ========================================================================

    fn create_query(name: &str, qtype: RecordType) -> Message {
        let mut query = Message::new();
        query.set_id(0x1234);
        query.set_recursion_desired(true);
        let name = Name::from_str(&format!("{}.", name)).unwrap();
        query.add_query(Query::query(name, qtype));
        query
    }

    #[test]
    fn test_zero_ip_a_query() {
        let builder = BlockedResponseBuilder::new(BlockResponseType::ZeroIp);
        let query = create_query("blocked.example.com", RecordType::A);

        let response = builder.build_response(&query);

        assert_eq!(response.id(), 0x1234);
        assert_eq!(response.message_type(), MessageType::Response);
        assert_eq!(response.response_code(), ResponseCode::NoError);
        assert!(response.recursion_available());

        // Check answer section
        assert_eq!(response.answers().len(), 1);
        let answer = &response.answers()[0];
        assert_eq!(answer.record_type(), RecordType::A);
        assert_eq!(answer.ttl(), BLOCKED_RESPONSE_TTL);

        if let Some(RData::A(a)) = answer.data() {
            assert_eq!(a.0, Ipv4Addr::new(0, 0, 0, 0));
        } else {
            panic!("Expected A record data");
        }
    }

    #[test]
    fn test_zero_ip_aaaa_query() {
        let builder = BlockedResponseBuilder::new(BlockResponseType::ZeroIp);
        let query = create_query("blocked.example.com", RecordType::AAAA);

        let response = builder.build_response(&query);

        assert_eq!(response.response_code(), ResponseCode::NoError);
        assert_eq!(response.answers().len(), 1);

        let answer = &response.answers()[0];
        assert_eq!(answer.record_type(), RecordType::AAAA);

        if let Some(RData::AAAA(aaaa)) = answer.data() {
            assert_eq!(aaaa.0, Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0));
        } else {
            panic!("Expected AAAA record data");
        }
    }

    #[test]
    fn test_zero_ip_other_query_type() {
        let builder = BlockedResponseBuilder::new(BlockResponseType::ZeroIp);
        let query = create_query("blocked.example.com", RecordType::MX);

        let response = builder.build_response(&query);

        assert_eq!(response.response_code(), ResponseCode::NoError);
        assert!(response.answers().is_empty()); // No answer for non-A/AAAA
    }

    #[test]
    fn test_zero_ip_custom_ttl() {
        let builder = BlockedResponseBuilder::new(BlockResponseType::ZeroIp).with_ttl(300);
        let query = create_query("blocked.example.com", RecordType::A);

        let response = builder.build_response(&query);

        assert_eq!(response.answers()[0].ttl(), 300);
    }

    // ========================================================================
    // Nxdomain Response Tests
    // ========================================================================

    #[test]
    fn test_nxdomain_a_query() {
        let builder = BlockedResponseBuilder::new(BlockResponseType::Nxdomain);
        let query = create_query("blocked.example.com", RecordType::A);

        let response = builder.build_response(&query);

        assert_eq!(response.id(), 0x1234);
        assert_eq!(response.message_type(), MessageType::Response);
        assert_eq!(response.response_code(), ResponseCode::NXDomain);
        assert!(response.answers().is_empty());
    }

    #[test]
    fn test_nxdomain_aaaa_query() {
        let builder = BlockedResponseBuilder::new(BlockResponseType::Nxdomain);
        let query = create_query("blocked.example.com", RecordType::AAAA);

        let response = builder.build_response(&query);

        assert_eq!(response.response_code(), ResponseCode::NXDomain);
        assert!(response.answers().is_empty());
    }

    #[test]
    fn test_nxdomain_any_query_type() {
        let builder = BlockedResponseBuilder::new(BlockResponseType::Nxdomain);

        for qtype in [RecordType::A, RecordType::AAAA, RecordType::MX, RecordType::TXT] {
            let query = create_query("blocked.example.com", qtype);
            let response = builder.build_response(&query);

            assert_eq!(response.response_code(), ResponseCode::NXDomain);
            assert!(response.answers().is_empty());
        }
    }

    // ========================================================================
    // Refused Response Tests
    // ========================================================================

    #[test]
    fn test_refused_a_query() {
        let builder = BlockedResponseBuilder::new(BlockResponseType::Refused);
        let query = create_query("blocked.example.com", RecordType::A);

        let response = builder.build_response(&query);

        assert_eq!(response.id(), 0x1234);
        assert_eq!(response.message_type(), MessageType::Response);
        assert_eq!(response.response_code(), ResponseCode::Refused);
        assert!(response.answers().is_empty());
    }

    #[test]
    fn test_refused_any_query_type() {
        let builder = BlockedResponseBuilder::new(BlockResponseType::Refused);

        for qtype in [RecordType::A, RecordType::AAAA, RecordType::MX, RecordType::TXT] {
            let query = create_query("blocked.example.com", qtype);
            let response = builder.build_response(&query);

            assert_eq!(response.response_code(), ResponseCode::Refused);
            assert!(response.answers().is_empty());
        }
    }

    // ========================================================================
    // Query Preservation Tests
    // ========================================================================

    #[test]
    fn test_preserves_query_id() {
        let builder = BlockedResponseBuilder::new(BlockResponseType::ZeroIp);

        let mut query = Message::new();
        query.set_id(0xABCD);
        query.add_query(Query::query(
            Name::from_str("test.com.").unwrap(),
            RecordType::A,
        ));

        let response = builder.build_response(&query);
        assert_eq!(response.id(), 0xABCD);
    }

    #[test]
    fn test_preserves_questions() {
        let builder = BlockedResponseBuilder::new(BlockResponseType::ZeroIp);

        let mut query = Message::new();
        query.set_id(0x1234);
        let name = Name::from_str("blocked.example.com.").unwrap();
        query.add_query(Query::query(name.clone(), RecordType::A));

        let response = builder.build_response(&query);

        assert_eq!(response.queries().len(), 1);
        assert_eq!(response.queries()[0].name(), &name);
        assert_eq!(response.queries()[0].query_type(), RecordType::A);
    }

    #[test]
    fn test_preserves_recursion_desired() {
        let builder = BlockedResponseBuilder::new(BlockResponseType::ZeroIp);

        // With RD set
        let mut query1 = Message::new();
        query1.set_id(0x1234);
        query1.set_recursion_desired(true);
        query1.add_query(Query::query(
            Name::from_str("test.com.").unwrap(),
            RecordType::A,
        ));

        let response1 = builder.build_response(&query1);
        assert!(response1.recursion_desired());

        // Without RD set
        let mut query2 = Message::new();
        query2.set_id(0x1234);
        query2.set_recursion_desired(false);
        query2.add_query(Query::query(
            Name::from_str("test.com.").unwrap(),
            RecordType::A,
        ));

        let response2 = builder.build_response(&query2);
        assert!(!response2.recursion_desired());
    }

    #[test]
    fn test_sets_recursion_available() {
        let builder = BlockedResponseBuilder::new(BlockResponseType::ZeroIp);
        let query = create_query("test.com", RecordType::A);

        let response = builder.build_response(&query);
        assert!(response.recursion_available());
    }

    #[test]
    fn test_not_authoritative() {
        let builder = BlockedResponseBuilder::new(BlockResponseType::ZeroIp);
        let query = create_query("test.com", RecordType::A);

        let response = builder.build_response(&query);
        assert!(!response.authoritative());
    }

    // ========================================================================
    // Bytes Conversion Tests
    // ========================================================================

    #[test]
    fn test_build_response_bytes_valid() {
        use hickory_proto::serialize::binary::BinDecodable;

        let builder = BlockedResponseBuilder::new(BlockResponseType::ZeroIp);
        let query = create_query("blocked.example.com", RecordType::A);

        // Serialize query
        let query_bytes = query.to_vec().unwrap();

        // Build response from bytes
        let response_bytes = builder.build_response_bytes(&query_bytes);
        assert!(response_bytes.is_some());

        // Parse response
        let response_bytes = response_bytes.unwrap();
        let response = Message::from_bytes(&response_bytes).unwrap();

        assert_eq!(response.id(), 0x1234);
        assert_eq!(response.response_code(), ResponseCode::NoError);
        assert_eq!(response.answers().len(), 1);
    }

    #[test]
    fn test_build_response_bytes_invalid() {
        let builder = BlockedResponseBuilder::new(BlockResponseType::ZeroIp);

        // Invalid DNS message bytes
        let invalid_bytes = vec![0u8, 1, 2, 3];
        let result = builder.build_response_bytes(&invalid_bytes);

        assert!(result.is_none());
    }

    #[test]
    fn test_build_response_bytes_empty() {
        let builder = BlockedResponseBuilder::new(BlockResponseType::ZeroIp);

        // Empty bytes
        let empty_bytes: Vec<u8> = Vec::new();
        let result = builder.build_response_bytes(&empty_bytes);

        assert!(result.is_none());
    }

    // ========================================================================
    // Multiple Query Tests
    // ========================================================================

    #[test]
    fn test_multiple_queries_in_message() {
        let builder = BlockedResponseBuilder::new(BlockResponseType::ZeroIp);

        let mut query = Message::new();
        query.set_id(0x1234);
        query.add_query(Query::query(
            Name::from_str("blocked1.com.").unwrap(),
            RecordType::A,
        ));
        query.add_query(Query::query(
            Name::from_str("blocked2.com.").unwrap(),
            RecordType::AAAA,
        ));

        let response = builder.build_response(&query);

        // Should have 2 answers (one A, one AAAA)
        assert_eq!(response.answers().len(), 2);

        // Check answer types
        let answer_types: Vec<_> = response.answers().iter().map(|a| a.record_type()).collect();
        assert!(answer_types.contains(&RecordType::A));
        assert!(answer_types.contains(&RecordType::AAAA));
    }
}
