//! Negative Cache Implementation
//!
//! This module provides utilities for handling negative DNS responses
//! (NXDOMAIN and NODATA) according to RFC 2308.
//!
//! # Negative Response Types
//!
//! - **NXDOMAIN**: The domain name does not exist
//! - **NODATA**: The domain exists but has no records of the requested type
//!
//! # TTL Determination
//!
//! For negative responses, the TTL is determined by (in order of preference):
//! 1. SOA MINIMUM field (if `respect_soa_minimum` is enabled)
//! 2. SOA record TTL
//! 3. Default negative TTL from configuration
//!
//! # RFC 2308 Compliance
//!
//! This implementation follows RFC 2308 guidelines for negative caching:
//! - Caches NXDOMAIN and NODATA responses
//! - Uses SOA MINIMUM field for TTL when available
//! - Applies configurable TTL limits

use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::RecordType;

use super::super::config::NegativeCacheConfig;

/// Type of negative DNS response
///
/// # Example
///
/// ```
/// use rust_router::dns::cache::NegativeResponseType;
///
/// let response_type = NegativeResponseType::NxDomain;
/// assert!(response_type.is_nxdomain());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NegativeResponseType {
    /// NXDOMAIN (Non-Existent Domain)
    ///
    /// The domain name does not exist in the DNS.
    /// Response code 3 (NXDOMAIN).
    NxDomain,

    /// NODATA (No records of requested type)
    ///
    /// The domain exists but has no records of the queried type.
    /// Response code 0 (NOERROR) with empty answer section and SOA in authority.
    NoData,
}

impl NegativeResponseType {
    /// Check if this is an NXDOMAIN response
    #[must_use]
    pub fn is_nxdomain(&self) -> bool {
        matches!(self, Self::NxDomain)
    }

    /// Check if this is a NODATA response
    #[must_use]
    pub fn is_nodata(&self) -> bool {
        matches!(self, Self::NoData)
    }
}

impl std::fmt::Display for NegativeResponseType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NxDomain => write!(f, "NXDOMAIN"),
            Self::NoData => write!(f, "NODATA"),
        }
    }
}

/// Result of analyzing a DNS response for negative caching
///
/// Contains the type of negative response and the determined TTL.
#[derive(Debug, Clone, Copy)]
pub struct NegativeAnalysis {
    /// Type of negative response
    pub response_type: NegativeResponseType,
    /// TTL determined for caching (in seconds)
    pub ttl: u32,
    /// Whether TTL was derived from SOA MINIMUM
    pub from_soa: bool,
}

impl NegativeAnalysis {
    /// Create a new negative analysis result
    #[must_use]
    pub fn new(response_type: NegativeResponseType, ttl: u32, from_soa: bool) -> Self {
        Self {
            response_type,
            ttl,
            from_soa,
        }
    }
}

/// Analyze a DNS message for negative caching
///
/// This function determines:
/// 1. Whether the response is a negative response (NXDOMAIN or NODATA)
/// 2. The appropriate TTL for caching
///
/// # Arguments
///
/// * `message` - The DNS response message to analyze
/// * `config` - Negative cache configuration
///
/// # Returns
///
/// `Some(NegativeAnalysis)` if this is a negative response, `None` otherwise.
///
/// # Example
///
/// ```no_run
/// use rust_router::dns::cache::analyze_negative_response;
/// use rust_router::dns::NegativeCacheConfig;
/// use hickory_proto::op::Message;
///
/// let response: Message = todo!("parse response");
/// let config = NegativeCacheConfig::default();
///
/// if let Some(analysis) = analyze_negative_response(&response, &config) {
///     println!("Negative response: {} TTL: {}s", analysis.response_type, analysis.ttl);
/// }
/// ```
#[must_use]
pub fn analyze_negative_response(
    message: &Message,
    config: &NegativeCacheConfig,
) -> Option<NegativeAnalysis> {
    // Check for NXDOMAIN
    if message.response_code() == ResponseCode::NXDomain {
        let (ttl, from_soa) = determine_negative_ttl(message, config);
        return Some(NegativeAnalysis::new(
            NegativeResponseType::NxDomain,
            ttl,
            from_soa,
        ));
    }

    // Check for NODATA (NOERROR with empty answer and SOA in authority)
    if message.response_code() == ResponseCode::NoError
        && message.message_type() == MessageType::Response
        && message.answers().is_empty()
    {
        // Must have SOA in authority section for NODATA
        let has_soa = message
            .name_servers()
            .iter()
            .any(|r| r.record_type() == RecordType::SOA);

        if has_soa {
            let (ttl, from_soa) = determine_negative_ttl(message, config);
            return Some(NegativeAnalysis::new(
                NegativeResponseType::NoData,
                ttl,
                from_soa,
            ));
        }
    }

    None
}

/// Determine the TTL for a negative response
///
/// Order of preference:
/// 1. SOA MINIMUM field (if `respect_soa_minimum` is enabled)
/// 2. SOA record TTL
/// 3. Default negative TTL
///
/// The result is clamped to the configured `max_ttl`.
fn determine_negative_ttl(message: &Message, config: &NegativeCacheConfig) -> (u32, bool) {
    if !config.enabled {
        return (config.default_ttl_secs, false);
    }

    if config.respect_soa_minimum {
        // Try to extract SOA MINIMUM
        if let Some((soa_ttl, soa_minimum)) = extract_soa_fields(message) {
            // Use the minimum of SOA TTL and SOA MINIMUM per RFC 2308
            let ttl = std::cmp::min(soa_ttl, soa_minimum);
            let clamped = ttl.clamp(1, config.max_ttl_secs);
            return (clamped, true);
        }
    }

    // Fall back to default
    (config.default_ttl_secs.min(config.max_ttl_secs), false)
}

/// Extract SOA record fields from the authority section
///
/// Returns `(ttl, minimum)` if a SOA record is found.
fn extract_soa_fields(message: &Message) -> Option<(u32, u32)> {
    for record in message.name_servers() {
        if record.record_type() == RecordType::SOA {
            if let Some(rdata) = record.data() {
                if let Some(soa) = rdata.as_soa() {
                    return Some((record.ttl(), soa.minimum()));
                }
            }
        }
    }
    None
}

/// Check if a DNS response is a negative response
///
/// This is a convenience function that returns true for both
/// NXDOMAIN and NODATA responses.
///
/// # Example
///
/// ```no_run
/// use rust_router::dns::cache::is_negative_response;
/// use hickory_proto::op::Message;
///
/// let response: Message = todo!("parse response");
/// if is_negative_response(&response) {
///     println!("This is a negative response");
/// }
/// ```
#[must_use]
pub fn is_negative_response(message: &Message) -> bool {
    // NXDOMAIN
    if message.response_code() == ResponseCode::NXDomain {
        return true;
    }

    // NODATA
    if message.response_code() == ResponseCode::NoError
        && message.message_type() == MessageType::Response
        && message.answers().is_empty()
    {
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

/// Extract the SOA MINIMUM value from a message's authority section
///
/// This is useful for determining the negative cache TTL according to RFC 2308.
///
/// # Returns
///
/// The SOA MINIMUM value, or `None` if no SOA record is present.
#[must_use]
pub fn extract_soa_minimum(message: &Message) -> Option<u32> {
    extract_soa_fields(message).map(|(_, minimum)| minimum)
}

/// Get the recommended cache TTL for a negative response
///
/// This applies all the configuration rules:
/// - SOA MINIMUM if `respect_soa_minimum` is enabled
/// - Default TTL as fallback
/// - TTL clamping to `max_ttl`
///
/// # Arguments
///
/// * `message` - The negative DNS response
/// * `config` - Negative cache configuration
///
/// # Returns
///
/// The TTL to use for caching this negative response.
#[must_use]
pub fn get_negative_cache_ttl(message: &Message, config: &NegativeCacheConfig) -> u32 {
    let (ttl, _) = determine_negative_ttl(message, config);
    ttl
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::Query;
    use hickory_proto::rr::{DNSClass, Name, RData, Record};
    use std::str::FromStr;

    // ========================================================================
    // Helper Functions
    // ========================================================================

    fn create_nxdomain_response() -> Message {
        let mut message = Message::new();
        message.set_id(0x1234);
        message.set_message_type(MessageType::Response);
        message.set_response_code(ResponseCode::NXDomain);

        let name = Name::from_str("nonexistent.example.com.").unwrap();
        let query = Query::query(name, RecordType::A);
        message.add_query(query);

        message
    }

    fn create_nxdomain_with_soa(soa_ttl: u32, soa_minimum: u32) -> Message {
        let mut message = create_nxdomain_response();

        let name = Name::from_str("example.com.").unwrap();
        let mname = Name::from_str("ns1.example.com.").unwrap();
        let rname = Name::from_str("admin.example.com.").unwrap();
        let soa = hickory_proto::rr::rdata::SOA::new(
            mname,
            rname,
            2023010101,
            3600,
            600,
            604800,
            soa_minimum,
        );

        let mut record = Record::new();
        record.set_name(name);
        record.set_record_type(RecordType::SOA);
        record.set_dns_class(DNSClass::IN);
        record.set_ttl(soa_ttl);
        record.set_data(Some(RData::SOA(soa)));
        message.add_name_server(record);

        message
    }

    fn create_nodata_response(soa_ttl: u32, soa_minimum: u32) -> Message {
        let mut message = Message::new();
        message.set_id(0x1234);
        message.set_message_type(MessageType::Response);
        message.set_response_code(ResponseCode::NoError);

        // Add a query for AAAA (which will have no answer)
        let name = Name::from_str("example.com.").unwrap();
        let query = Query::query(name.clone(), RecordType::AAAA);
        message.add_query(query);

        // Add SOA in authority section
        let mname = Name::from_str("ns1.example.com.").unwrap();
        let rname = Name::from_str("admin.example.com.").unwrap();
        let soa = hickory_proto::rr::rdata::SOA::new(
            mname,
            rname,
            2023010101,
            3600,
            600,
            604800,
            soa_minimum,
        );

        let mut record = Record::new();
        record.set_name(name);
        record.set_record_type(RecordType::SOA);
        record.set_dns_class(DNSClass::IN);
        record.set_ttl(soa_ttl);
        record.set_data(Some(RData::SOA(soa)));
        message.add_name_server(record);

        message
    }

    fn create_positive_response() -> Message {
        use std::net::Ipv4Addr;

        let mut message = Message::new();
        message.set_id(0x1234);
        message.set_message_type(MessageType::Response);
        message.set_response_code(ResponseCode::NoError);

        let name = Name::from_str("example.com.").unwrap();
        let query = Query::query(name.clone(), RecordType::A);
        message.add_query(query);

        let mut record = Record::new();
        record.set_name(name);
        record.set_record_type(RecordType::A);
        record.set_dns_class(DNSClass::IN);
        record.set_ttl(300);
        record.set_data(Some(RData::A(hickory_proto::rr::rdata::A(Ipv4Addr::new(
            93, 184, 216, 34,
        )))));
        message.add_answer(record);

        message
    }

    // ========================================================================
    // NegativeResponseType Tests
    // ========================================================================

    #[test]
    fn test_negative_response_type_nxdomain() {
        let t = NegativeResponseType::NxDomain;
        assert!(t.is_nxdomain());
        assert!(!t.is_nodata());
        assert_eq!(format!("{}", t), "NXDOMAIN");
    }

    #[test]
    fn test_negative_response_type_nodata() {
        let t = NegativeResponseType::NoData;
        assert!(t.is_nodata());
        assert!(!t.is_nxdomain());
        assert_eq!(format!("{}", t), "NODATA");
    }

    // ========================================================================
    // analyze_negative_response Tests
    // ========================================================================

    #[test]
    fn test_analyze_nxdomain() {
        let response = create_nxdomain_response();
        let config = NegativeCacheConfig::default();

        let analysis = analyze_negative_response(&response, &config);
        assert!(analysis.is_some());
        let analysis = analysis.unwrap();
        assert!(analysis.response_type.is_nxdomain());
    }

    #[test]
    fn test_analyze_nxdomain_with_soa() {
        let response = create_nxdomain_with_soa(300, 120);
        let config = NegativeCacheConfig::default();

        let analysis = analyze_negative_response(&response, &config);
        assert!(analysis.is_some());
        let analysis = analysis.unwrap();
        assert!(analysis.response_type.is_nxdomain());
        assert!(analysis.from_soa);
        // TTL should be min(soa_ttl, soa_minimum) = min(300, 120) = 120
        assert_eq!(analysis.ttl, 120);
    }

    #[test]
    fn test_analyze_nodata() {
        let response = create_nodata_response(300, 180);
        let config = NegativeCacheConfig::default();

        let analysis = analyze_negative_response(&response, &config);
        assert!(analysis.is_some());
        let analysis = analysis.unwrap();
        assert!(analysis.response_type.is_nodata());
        assert!(analysis.from_soa);
    }

    #[test]
    fn test_analyze_positive_response() {
        let response = create_positive_response();
        let config = NegativeCacheConfig::default();

        let analysis = analyze_negative_response(&response, &config);
        assert!(analysis.is_none());
    }

    #[test]
    fn test_analyze_with_disabled_config() {
        let response = create_nxdomain_with_soa(300, 120);
        let mut config = NegativeCacheConfig::default();
        config.enabled = false;
        config.default_ttl_secs = 600;

        let analysis = analyze_negative_response(&response, &config);
        assert!(analysis.is_some());
        let analysis = analysis.unwrap();
        // Should use default TTL when disabled
        assert_eq!(analysis.ttl, 600);
        assert!(!analysis.from_soa);
    }

    #[test]
    fn test_analyze_without_respect_soa() {
        let response = create_nxdomain_with_soa(300, 120);
        let mut config = NegativeCacheConfig::default();
        config.respect_soa_minimum = false;
        config.default_ttl_secs = 500;

        let analysis = analyze_negative_response(&response, &config);
        assert!(analysis.is_some());
        let analysis = analysis.unwrap();
        // Should use default TTL
        assert_eq!(analysis.ttl, 500);
        assert!(!analysis.from_soa);
    }

    // ========================================================================
    // TTL Clamping Tests
    // ========================================================================

    #[test]
    fn test_ttl_clamping_max() {
        let response = create_nxdomain_with_soa(300, 10000);
        let mut config = NegativeCacheConfig::default();
        config.max_ttl_secs = 600;

        let analysis = analyze_negative_response(&response, &config);
        assert!(analysis.is_some());
        let analysis = analysis.unwrap();
        // Should be clamped to max_ttl (but we use min of soa_ttl and soa_minimum first)
        // min(300, 10000) = 300, then clamped to max 600, so 300
        assert_eq!(analysis.ttl, 300);
    }

    #[test]
    fn test_ttl_clamping_to_max() {
        let response = create_nxdomain_with_soa(1000, 2000);
        let mut config = NegativeCacheConfig::default();
        config.max_ttl_secs = 600;

        let analysis = analyze_negative_response(&response, &config);
        assert!(analysis.is_some());
        let analysis = analysis.unwrap();
        // min(1000, 2000) = 1000, then clamped to 600
        assert_eq!(analysis.ttl, 600);
    }

    #[test]
    fn test_ttl_minimum_bound() {
        let response = create_nxdomain_with_soa(0, 0);
        let config = NegativeCacheConfig::default();

        let analysis = analyze_negative_response(&response, &config);
        assert!(analysis.is_some());
        let analysis = analysis.unwrap();
        // min(0, 0) = 0, clamped to minimum of 1
        assert_eq!(analysis.ttl, 1);
    }

    // ========================================================================
    // is_negative_response Tests
    // ========================================================================

    #[test]
    fn test_is_negative_response_nxdomain() {
        let response = create_nxdomain_response();
        assert!(is_negative_response(&response));
    }

    #[test]
    fn test_is_negative_response_nodata() {
        let response = create_nodata_response(300, 180);
        assert!(is_negative_response(&response));
    }

    #[test]
    fn test_is_negative_response_positive() {
        let response = create_positive_response();
        assert!(!is_negative_response(&response));
    }

    #[test]
    fn test_is_negative_response_empty_no_soa() {
        let mut message = Message::new();
        message.set_id(0x1234);
        message.set_message_type(MessageType::Response);
        message.set_response_code(ResponseCode::NoError);
        // No answers, no SOA - not a proper NODATA response
        assert!(!is_negative_response(&message));
    }

    // ========================================================================
    // extract_soa_minimum Tests
    // ========================================================================

    #[test]
    fn test_extract_soa_minimum_present() {
        let response = create_nxdomain_with_soa(300, 180);
        assert_eq!(extract_soa_minimum(&response), Some(180));
    }

    #[test]
    fn test_extract_soa_minimum_absent() {
        let response = create_nxdomain_response();
        assert_eq!(extract_soa_minimum(&response), None);
    }

    #[test]
    fn test_extract_soa_minimum_from_nodata() {
        let response = create_nodata_response(300, 120);
        assert_eq!(extract_soa_minimum(&response), Some(120));
    }

    // ========================================================================
    // get_negative_cache_ttl Tests
    // ========================================================================

    #[test]
    fn test_get_negative_cache_ttl_with_soa() {
        let response = create_nxdomain_with_soa(300, 180);
        let config = NegativeCacheConfig::default();

        let ttl = get_negative_cache_ttl(&response, &config);
        // min(300, 180) = 180
        assert_eq!(ttl, 180);
    }

    #[test]
    fn test_get_negative_cache_ttl_fallback() {
        let response = create_nxdomain_response();
        let mut config = NegativeCacheConfig::default();
        config.default_ttl_secs = 600;

        let ttl = get_negative_cache_ttl(&response, &config);
        assert_eq!(ttl, 600);
    }

    #[test]
    fn test_get_negative_cache_ttl_disabled() {
        let response = create_nxdomain_with_soa(300, 180);
        let mut config = NegativeCacheConfig::default();
        config.enabled = false;
        config.default_ttl_secs = 500;

        let ttl = get_negative_cache_ttl(&response, &config);
        assert_eq!(ttl, 500);
    }

    // ========================================================================
    // Edge Cases
    // ========================================================================

    #[test]
    fn test_soa_minimum_zero() {
        let response = create_nxdomain_with_soa(300, 0);
        let config = NegativeCacheConfig::default();

        let analysis = analyze_negative_response(&response, &config);
        assert!(analysis.is_some());
        let analysis = analysis.unwrap();
        // min(300, 0) = 0, clamped to 1
        assert_eq!(analysis.ttl, 1);
    }

    #[test]
    fn test_soa_ttl_smaller_than_minimum() {
        let response = create_nxdomain_with_soa(60, 300);
        let config = NegativeCacheConfig::default();

        let analysis = analyze_negative_response(&response, &config);
        assert!(analysis.is_some());
        let analysis = analysis.unwrap();
        // min(60, 300) = 60
        assert_eq!(analysis.ttl, 60);
    }

    #[test]
    fn test_nodata_without_soa_not_detected() {
        let mut message = Message::new();
        message.set_id(0x1234);
        message.set_message_type(MessageType::Response);
        message.set_response_code(ResponseCode::NoError);

        // Add query but no answers and no SOA
        let name = Name::from_str("example.com.").unwrap();
        let query = Query::query(name, RecordType::AAAA);
        message.add_query(query);

        let config = NegativeCacheConfig::default();
        let analysis = analyze_negative_response(&message, &config);

        // Should not be detected as NODATA without SOA
        assert!(analysis.is_none());
    }
}
