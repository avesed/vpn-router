//! DNS Cache Entry Implementation
//!
//! This module provides the `CacheEntry` type that stores cached DNS responses
//! along with their metadata for TTL management and cache statistics.
//!
//! # TTL Management
//!
//! DNS responses have a Time-To-Live (TTL) that determines how long they
//! remain valid. This module handles:
//!
//! - Expiration checking based on insertion time
//! - TTL adjustment for responses returned from cache
//! - TTL clamping within configured min/max bounds
//!
//! # Example
//!
//! ```
//! use rust_router::dns::cache::{CacheEntry, CacheKey};
//! use std::time::Instant;
//!
//! // Entry is considered expired when remaining TTL is 0
//! let entry = CacheEntry::new_with_ttl(vec![], 60, "upstream-1", false);
//! assert!(!entry.is_expired());
//! assert!(entry.remaining_ttl() <= 60);
//! ```

use std::time::Instant;

use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::{Record, RecordType};
use hickory_proto::serialize::binary::BinDecodable;

use super::super::config::CacheConfig;

/// A cached DNS response entry
///
/// This structure holds a DNS response along with metadata needed for
/// cache management, including the original TTL, insertion time, and
/// the upstream server that provided the response.
///
/// # Example
///
/// ```
/// use rust_router::dns::cache::CacheEntry;
///
/// let entry = CacheEntry::new_with_ttl(vec![], 300, "8.8.8.8:53", false);
/// assert_eq!(entry.original_ttl(), 300);
/// assert_eq!(entry.upstream(), "8.8.8.8:53");
/// assert!(!entry.is_negative());
/// ```
#[derive(Debug, Clone)]
pub struct CacheEntry {
    /// Serialized DNS response bytes
    response: Vec<u8>,
    /// Original TTL from the response (in seconds)
    ttl: u32,
    /// When this entry was inserted into the cache
    inserted_at: Instant,
    /// The upstream server that provided this response
    upstream: String,
    /// Whether this is a negative cache entry (NXDOMAIN/NODATA)
    is_negative: bool,
}

impl CacheEntry {
    /// Create a new cache entry
    ///
    /// # Arguments
    ///
    /// * `response` - Serialized DNS response bytes
    /// * `ttl` - The TTL for this entry (in seconds)
    /// * `upstream` - The upstream server tag that provided this response
    /// * `is_negative` - Whether this is a negative cache entry
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::dns::cache::CacheEntry;
    ///
    /// let entry = CacheEntry::new_with_ttl(vec![0u8; 12], 300, "cloudflare", false);
    /// assert_eq!(entry.original_ttl(), 300);
    /// ```
    #[must_use]
    pub fn new_with_ttl(
        response: Vec<u8>,
        ttl: u32,
        upstream: impl Into<String>,
        is_negative: bool,
    ) -> Self {
        Self {
            response,
            ttl,
            inserted_at: Instant::now(),
            upstream: upstream.into(),
            is_negative,
        }
    }

    /// Create a cache entry from a DNS message
    ///
    /// This extracts the minimum TTL from all answer records and uses
    /// it as the cache TTL. The TTL is clamped to the configured min/max.
    ///
    /// # Arguments
    ///
    /// * `message` - The DNS response message
    /// * `upstream` - The upstream server tag
    /// * `config` - Cache configuration for TTL clamping
    ///
    /// # Returns
    ///
    /// `None` if the message cannot be serialized.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rust_router::dns::cache::CacheEntry;
    /// use rust_router::dns::CacheConfig;
    /// use hickory_proto::op::Message;
    ///
    /// let response: Message = todo!("parse response");
    /// let config = CacheConfig::default();
    /// let entry = CacheEntry::from_message(&response, "upstream-1", &config);
    /// ```
    pub fn from_message(message: &Message, upstream: &str, config: &CacheConfig) -> Option<Self> {
        // Serialize the message
        let response = message.to_vec().ok()?;

        // Determine if this is a negative response
        let is_negative = Self::is_negative_response(message);

        // Calculate TTL from response
        let ttl = if is_negative {
            Self::extract_negative_ttl(message, config)
        } else {
            Self::extract_min_ttl(message, config)
        };

        Some(Self::new_with_ttl(response, ttl, upstream, is_negative))
    }

    /// Check if a DNS response is a negative response
    ///
    /// Negative responses include:
    /// - NXDOMAIN (Non-Existent Domain)
    /// - NODATA (empty answer section with SOA in authority)
    #[must_use]
    pub fn is_negative_response(message: &Message) -> bool {
        // NXDOMAIN
        if message.response_code() == ResponseCode::NXDomain {
            return true;
        }

        // NODATA: No answers but has SOA in authority
        if message.answers().is_empty() && message.message_type() == MessageType::Response {
            let has_soa = message
                .name_servers()
                .iter()
                .any(|r| r.record_type() == RecordType::SOA);
            if has_soa {
                return true;
            }
        }

        false
    }

    /// Extract the minimum TTL from answer records
    fn extract_min_ttl(message: &Message, config: &CacheConfig) -> u32 {
        let min_answer_ttl = message
            .answers()
            .iter()
            .map(Record::ttl)
            .min()
            .unwrap_or(config.min_ttl_secs);

        config.clamp_ttl(min_answer_ttl)
    }

    /// Extract TTL for negative responses (from SOA MINIMUM)
    fn extract_negative_ttl(message: &Message, config: &CacheConfig) -> u32 {
        let negative_config = &config.negative;

        if !negative_config.enabled {
            return negative_config.default_ttl_secs;
        }

        let ttl = if negative_config.respect_soa_minimum {
            // Try to extract SOA MINIMUM
            Self::extract_soa_minimum(message).unwrap_or(negative_config.default_ttl_secs)
        } else {
            negative_config.default_ttl_secs
        };

        // Clamp to negative cache limits
        ttl.clamp(config.min_ttl_secs, negative_config.max_ttl_secs)
    }

    /// Extract SOA MINIMUM field from authority section
    ///
    /// The SOA MINIMUM field indicates the negative cache TTL as per RFC 2308.
    fn extract_soa_minimum(message: &Message) -> Option<u32> {
        for record in message.name_servers() {
            if record.record_type() == RecordType::SOA {
                if let Some(rdata) = record.data() {
                    if let Some(soa) = rdata.as_soa() {
                        return Some(soa.minimum());
                    }
                }
            }
        }
        None
    }

    /// Check if this entry has expired
    ///
    /// An entry is expired when the time since insertion exceeds the TTL.
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::dns::cache::CacheEntry;
    ///
    /// let entry = CacheEntry::new_with_ttl(vec![], 0, "test", false);
    /// assert!(entry.is_expired());
    /// ```
    #[must_use]
    pub fn is_expired(&self) -> bool {
        self.remaining_ttl() == 0
    }

    /// Get the remaining TTL in seconds
    ///
    /// This is the original TTL minus the time elapsed since insertion.
    /// Returns 0 if the entry has expired.
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::dns::cache::CacheEntry;
    ///
    /// let entry = CacheEntry::new_with_ttl(vec![], 300, "test", false);
    /// assert!(entry.remaining_ttl() <= 300);
    /// ```
    #[must_use]
    pub fn remaining_ttl(&self) -> u32 {
        let elapsed = self.inserted_at.elapsed().as_secs();
        if elapsed >= u64::from(self.ttl) {
            0
        } else {
            self.ttl - elapsed as u32
        }
    }

    /// Get the original TTL value
    #[must_use]
    pub fn original_ttl(&self) -> u32 {
        self.ttl
    }

    /// Get the insertion time
    #[must_use]
    pub fn inserted_at(&self) -> Instant {
        self.inserted_at
    }

    /// Get the upstream server that provided this response
    #[must_use]
    pub fn upstream(&self) -> &str {
        &self.upstream
    }

    /// Check if this is a negative cache entry
    #[must_use]
    pub fn is_negative(&self) -> bool {
        self.is_negative
    }

    /// Get the raw response bytes
    #[must_use]
    pub fn response_bytes(&self) -> &[u8] {
        &self.response
    }

    /// Get the response size in bytes
    #[must_use]
    pub fn size(&self) -> usize {
        // Response bytes + metadata overhead
        self.response.len() + self.upstream.len() + 32
    }

    /// Parse the cached response into a Message
    ///
    /// # Returns
    ///
    /// `None` if parsing fails (should not happen for valid cached data).
    #[must_use]
    pub fn to_message(&self) -> Option<Message> {
        Message::from_bytes(&self.response).ok()
    }

    /// Create an adjusted response with updated TTLs
    ///
    /// This creates a new Message with all TTLs adjusted to reflect
    /// the time remaining in the cache.
    ///
    /// # Arguments
    ///
    /// * `query_id` - The query ID to use in the response
    ///
    /// # Returns
    ///
    /// The adjusted message, or `None` if parsing fails.
    #[must_use]
    pub fn to_adjusted_message(&self, query_id: u16) -> Option<Message> {
        let mut message = self.to_message()?;

        // Set the query ID to match the request
        message.set_id(query_id);

        // Adjust TTLs based on remaining time
        let remaining = self.remaining_ttl();

        // Adjust answer TTLs
        let adjusted_answers: Vec<Record> = message
            .answers()
            .iter()
            .map(|r| {
                let mut record = r.clone();
                let new_ttl = std::cmp::min(r.ttl(), remaining);
                record.set_ttl(new_ttl);
                record
            })
            .collect();

        // Adjust authority TTLs
        let adjusted_nameservers: Vec<Record> = message
            .name_servers()
            .iter()
            .map(|r| {
                let mut record = r.clone();
                let new_ttl = std::cmp::min(r.ttl(), remaining);
                record.set_ttl(new_ttl);
                record
            })
            .collect();

        // Adjust additional TTLs
        let adjusted_additionals: Vec<Record> = message
            .additionals()
            .iter()
            .map(|r| {
                let mut record = r.clone();
                let new_ttl = std::cmp::min(r.ttl(), remaining);
                record.set_ttl(new_ttl);
                record
            })
            .collect();

        // Create new message with adjusted records
        let mut adjusted = Message::new();
        adjusted.set_id(query_id);
        adjusted.set_message_type(MessageType::Response);
        adjusted.set_response_code(message.response_code());
        adjusted.set_recursion_desired(message.recursion_desired());
        adjusted.set_recursion_available(message.recursion_available());
        adjusted.set_authentic_data(message.authentic_data());
        adjusted.set_checking_disabled(message.checking_disabled());

        // Copy queries
        for query in message.queries() {
            adjusted.add_query(query.clone());
        }

        // Add adjusted records
        for record in adjusted_answers {
            adjusted.add_answer(record);
        }
        for record in adjusted_nameservers {
            adjusted.add_name_server(record);
        }
        for record in adjusted_additionals {
            adjusted.add_additional(record);
        }

        Some(adjusted)
    }

    /// Get the age of this entry in seconds
    #[must_use]
    pub fn age(&self) -> u64 {
        self.inserted_at.elapsed().as_secs()
    }

    /// Estimate memory usage of this entry
    #[must_use]
    pub fn estimated_memory(&self) -> usize {
        // Vec overhead (24 bytes) + capacity
        // String overhead (24 bytes) + length
        // Other fields (16 bytes for Instant, 4 for u32, 1 for bool)
        std::mem::size_of::<Self>() + self.response.capacity() + self.upstream.capacity()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::Query;
    use hickory_proto::rr::{DNSClass, Name, RData, RecordType};
    use std::net::Ipv4Addr;
    use std::str::FromStr;
    use std::thread::sleep;
    use std::time::Duration;

    // ========================================================================
    // Helper Functions
    // ========================================================================

    fn create_test_response(ttl: u32) -> Message {
        let mut message = Message::new();
        message.set_id(0x1234);
        message.set_message_type(MessageType::Response);
        message.set_response_code(ResponseCode::NoError);

        // Add a query
        let name = Name::from_str("example.com.").unwrap();
        let query = Query::query(name.clone(), RecordType::A);
        message.add_query(query);

        // Add an answer
        let mut record = Record::new();
        record.set_name(name);
        record.set_record_type(RecordType::A);
        record.set_dns_class(DNSClass::IN);
        record.set_ttl(ttl);
        record.set_data(Some(RData::A(hickory_proto::rr::rdata::A(Ipv4Addr::new(
            93, 184, 216, 34,
        )))));
        message.add_answer(record);

        message
    }

    fn create_nxdomain_response() -> Message {
        let mut message = Message::new();
        message.set_id(0x1234);
        message.set_message_type(MessageType::Response);
        message.set_response_code(ResponseCode::NXDomain);

        // Add a query
        let name = Name::from_str("nonexistent.example.com.").unwrap();
        let query = Query::query(name, RecordType::A);
        message.add_query(query);

        message
    }

    fn create_nodata_response_with_soa(soa_minimum: u32) -> Message {
        let mut message = Message::new();
        message.set_id(0x1234);
        message.set_message_type(MessageType::Response);
        message.set_response_code(ResponseCode::NoError);

        // Add a query
        let name = Name::from_str("example.com.").unwrap();
        let query = Query::query(name.clone(), RecordType::AAAA);
        message.add_query(query);

        // Add SOA in authority section
        let mname = Name::from_str("ns1.example.com.").unwrap();
        let rname = Name::from_str("admin.example.com.").unwrap();
        let soa = hickory_proto::rr::rdata::SOA::new(
            mname,
            rname,
            2023010101, // serial
            3600,       // refresh
            600,        // retry
            604800,     // expire
            soa_minimum,
        );

        let mut record = Record::new();
        record.set_name(name);
        record.set_record_type(RecordType::SOA);
        record.set_dns_class(DNSClass::IN);
        record.set_ttl(300);
        record.set_data(Some(RData::SOA(soa)));
        message.add_name_server(record);

        message
    }

    // ========================================================================
    // Basic Creation Tests
    // ========================================================================

    #[test]
    fn test_cache_entry_new() {
        let entry = CacheEntry::new_with_ttl(vec![1, 2, 3], 300, "test-upstream", false);
        assert_eq!(entry.original_ttl(), 300);
        assert_eq!(entry.upstream(), "test-upstream");
        assert!(!entry.is_negative());
        assert_eq!(entry.response_bytes(), &[1, 2, 3]);
    }

    #[test]
    fn test_cache_entry_negative() {
        let entry = CacheEntry::new_with_ttl(vec![], 60, "upstream", true);
        assert!(entry.is_negative());
    }

    #[test]
    fn test_cache_entry_from_message() {
        let response = create_test_response(300);
        let config = CacheConfig::default();
        let entry = CacheEntry::from_message(&response, "test", &config);

        assert!(entry.is_some());
        let entry = entry.unwrap();
        assert!(!entry.is_negative());
        assert!(entry.original_ttl() >= 60); // min_ttl clamped
        assert!(entry.original_ttl() <= 300);
    }

    #[test]
    fn test_cache_entry_from_nxdomain() {
        let response = create_nxdomain_response();
        let config = CacheConfig::default();
        let entry = CacheEntry::from_message(&response, "test", &config);

        assert!(entry.is_some());
        let entry = entry.unwrap();
        assert!(entry.is_negative());
    }

    #[test]
    fn test_cache_entry_from_nodata_with_soa() {
        let response = create_nodata_response_with_soa(120);
        let config = CacheConfig::default();
        let entry = CacheEntry::from_message(&response, "test", &config);

        assert!(entry.is_some());
        let entry = entry.unwrap();
        assert!(entry.is_negative());
        // TTL should be derived from SOA MINIMUM
        assert!(entry.original_ttl() <= 120);
    }

    // ========================================================================
    // TTL Management Tests
    // ========================================================================

    #[test]
    fn test_remaining_ttl_immediately() {
        let entry = CacheEntry::new_with_ttl(vec![], 300, "test", false);
        // Should be close to 300 immediately after creation
        assert!(entry.remaining_ttl() >= 299);
        assert!(entry.remaining_ttl() <= 300);
    }

    #[test]
    fn test_remaining_ttl_after_time() {
        let entry = CacheEntry::new_with_ttl(vec![], 300, "test", false);
        sleep(Duration::from_millis(100));
        // Should still be > 299 after 100ms
        assert!(entry.remaining_ttl() >= 299);
    }

    #[test]
    fn test_is_expired_false() {
        let entry = CacheEntry::new_with_ttl(vec![], 300, "test", false);
        assert!(!entry.is_expired());
    }

    #[test]
    fn test_is_expired_true_zero_ttl() {
        let entry = CacheEntry::new_with_ttl(vec![], 0, "test", false);
        assert!(entry.is_expired());
    }

    #[test]
    fn test_age() {
        let entry = CacheEntry::new_with_ttl(vec![], 300, "test", false);
        assert!(entry.age() < 1);
        sleep(Duration::from_millis(50));
        // Still 0 seconds as we're measuring in whole seconds
        assert!(entry.age() < 1);
    }

    // ========================================================================
    // TTL Clamping Tests
    // ========================================================================

    #[test]
    fn test_ttl_clamping_min() {
        let response = create_test_response(30); // Below default min of 60
        let config = CacheConfig::default();
        let entry = CacheEntry::from_message(&response, "test", &config);

        assert!(entry.is_some());
        let entry = entry.unwrap();
        // Should be clamped to min_ttl
        assert_eq!(entry.original_ttl(), 60);
    }

    #[test]
    fn test_ttl_clamping_max() {
        let response = create_test_response(100000); // Above default max of 86400
        let config = CacheConfig::default();
        let entry = CacheEntry::from_message(&response, "test", &config);

        assert!(entry.is_some());
        let entry = entry.unwrap();
        // Should be clamped to max_ttl
        assert_eq!(entry.original_ttl(), 86400);
    }

    #[test]
    fn test_ttl_within_range() {
        let response = create_test_response(500);
        let config = CacheConfig::default();
        let entry = CacheEntry::from_message(&response, "test", &config);

        assert!(entry.is_some());
        let entry = entry.unwrap();
        // Should be unchanged
        assert_eq!(entry.original_ttl(), 500);
    }

    // ========================================================================
    // Negative Response Detection Tests
    // ========================================================================

    #[test]
    fn test_is_negative_response_nxdomain() {
        let response = create_nxdomain_response();
        assert!(CacheEntry::is_negative_response(&response));
    }

    #[test]
    fn test_is_negative_response_nodata() {
        let response = create_nodata_response_with_soa(300);
        assert!(CacheEntry::is_negative_response(&response));
    }

    #[test]
    fn test_is_negative_response_positive() {
        let response = create_test_response(300);
        assert!(!CacheEntry::is_negative_response(&response));
    }

    // ========================================================================
    // Message Conversion Tests
    // ========================================================================

    #[test]
    fn test_to_message() {
        let response = create_test_response(300);
        let config = CacheConfig::default();
        let entry = CacheEntry::from_message(&response, "test", &config).unwrap();

        let parsed = entry.to_message();
        assert!(parsed.is_some());
        let parsed = parsed.unwrap();
        assert_eq!(parsed.response_code(), ResponseCode::NoError);
        assert!(!parsed.answers().is_empty());
    }

    #[test]
    fn test_to_adjusted_message() {
        let response = create_test_response(300);
        let config = CacheConfig::default();
        let entry = CacheEntry::from_message(&response, "test", &config).unwrap();

        let adjusted = entry.to_adjusted_message(0x5678);
        assert!(adjusted.is_some());
        let adjusted = adjusted.unwrap();
        assert_eq!(adjusted.id(), 0x5678);
        assert!(!adjusted.answers().is_empty());
        // TTL should be <= remaining TTL
        let answer_ttl = adjusted.answers()[0].ttl();
        assert!(answer_ttl <= entry.remaining_ttl());
    }

    #[test]
    fn test_to_adjusted_message_preserves_flags() {
        let mut response = create_test_response(300);
        response.set_recursion_desired(true);
        response.set_recursion_available(true);

        let config = CacheConfig::default();
        let entry = CacheEntry::from_message(&response, "test", &config).unwrap();

        let adjusted = entry.to_adjusted_message(0x5678).unwrap();
        assert!(adjusted.recursion_desired());
        assert!(adjusted.recursion_available());
    }

    // ========================================================================
    // Size and Memory Tests
    // ========================================================================

    #[test]
    fn test_size() {
        let entry = CacheEntry::new_with_ttl(vec![0u8; 100], 300, "upstream-1", false);
        let size = entry.size();
        // Should be at least 100 (response) + upstream length + overhead
        assert!(size >= 100 + 10 + 32);
    }

    #[test]
    fn test_estimated_memory() {
        let entry = CacheEntry::new_with_ttl(vec![0u8; 100], 300, "upstream-1", false);
        let mem = entry.estimated_memory();
        // Should include struct size + capacity of Vec and String
        assert!(mem >= 100);
    }

    // ========================================================================
    // SOA MINIMUM Extraction Tests
    // ========================================================================

    #[test]
    fn test_extract_soa_minimum() {
        let response = create_nodata_response_with_soa(180);
        let minimum = CacheEntry::extract_soa_minimum(&response);
        assert_eq!(minimum, Some(180));
    }

    #[test]
    fn test_extract_soa_minimum_none() {
        let response = create_test_response(300);
        let minimum = CacheEntry::extract_soa_minimum(&response);
        assert_eq!(minimum, None);
    }

    // ========================================================================
    // Clone and Debug Tests
    // ========================================================================

    #[test]
    fn test_cache_entry_clone() {
        let entry = CacheEntry::new_with_ttl(vec![1, 2, 3], 300, "test", false);
        let cloned = entry.clone();
        assert_eq!(entry.original_ttl(), cloned.original_ttl());
        assert_eq!(entry.upstream(), cloned.upstream());
        assert_eq!(entry.is_negative(), cloned.is_negative());
    }

    #[test]
    fn test_cache_entry_debug() {
        let entry = CacheEntry::new_with_ttl(vec![1, 2, 3], 300, "test", false);
        let debug = format!("{:?}", entry);
        assert!(debug.contains("ttl: 300"));
        assert!(debug.contains("test"));
    }

    // ========================================================================
    // Edge Case Tests
    // ========================================================================

    #[test]
    fn test_empty_response() {
        let entry = CacheEntry::new_with_ttl(vec![], 300, "test", false);
        assert_eq!(entry.response_bytes().len(), 0);
    }

    #[test]
    fn test_max_ttl() {
        let entry = CacheEntry::new_with_ttl(vec![], u32::MAX, "test", false);
        assert_eq!(entry.original_ttl(), u32::MAX);
        // remaining_ttl should still work
        assert!(entry.remaining_ttl() <= u32::MAX);
    }

    #[test]
    fn test_negative_config_disabled() {
        let response = create_nxdomain_response();
        let mut config = CacheConfig::default();
        config.negative.enabled = false;
        config.negative.default_ttl_secs = 120;

        let entry = CacheEntry::from_message(&response, "test", &config).unwrap();
        assert!(entry.is_negative());
        // Should use default TTL when negative caching is disabled
        assert_eq!(entry.original_ttl(), 120);
    }

    #[test]
    fn test_negative_config_no_respect_soa() {
        let response = create_nodata_response_with_soa(180);
        let mut config = CacheConfig::default();
        config.negative.respect_soa_minimum = false;
        config.negative.default_ttl_secs = 300;

        let entry = CacheEntry::from_message(&response, "test", &config).unwrap();
        assert!(entry.is_negative());
        // Should use default TTL instead of SOA MINIMUM
        assert_eq!(entry.original_ttl(), 300);
    }
}
