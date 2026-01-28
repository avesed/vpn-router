//! DNS hijacking for FakeDNS integration
//!
//! This module handles DNS queries received through the ipstack bridge,
//! intercepting them and responding with fake IP addresses allocated by
//! the FakeDNS manager.
//!
//! # Protocol Support
//!
//! - UDP DNS (standard port 53)
//! - TCP DNS (port 53 with 2-byte length prefix per RFC 1035)
//!
//! # Error Handling
//!
//! - Returns SERVFAIL on FakeDNS pool exhaustion
//! - Returns NOTIMP for unsupported query types
//! - Returns empty AAAA response to force IPv4 usage

use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::{DNSClass, RData, Record, RecordType};
use std::io;
use std::net::Ipv4Addr;
use std::time::Duration;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, trace, warn};

#[cfg(feature = "fakedns")]
use crate::fakedns::{FakeDnsError, FakeDnsManager};

/// Maximum DNS message size for UDP (RFC 1035)
const MAX_DNS_UDP_SIZE: usize = 512;

/// Maximum DNS message size for TCP
const MAX_DNS_TCP_SIZE: usize = 65535;

/// Error type for DNS hijacking operations
#[derive(Error, Debug)]
pub enum DnsHijackError {
    /// Failed to read DNS query
    #[error("Failed to read DNS query: {0}")]
    ReadError(#[from] io::Error),

    /// Failed to parse DNS query
    #[error("Failed to parse DNS query: {0}")]
    ParseError(String),

    /// FakeDNS pool exhausted
    #[error("FakeDNS pool exhausted")]
    PoolExhausted,

    /// Query type not supported
    #[error("Query type not supported: {0:?}")]
    UnsupportedType(RecordType),

    /// Response encoding failed
    #[error("Failed to encode DNS response: {0}")]
    EncodeError(String),
}

/// Result type for DNS hijacking operations
pub type DnsHijackResult<T> = Result<T, DnsHijackError>;

/// Handle a UDP DNS query using FakeDNS
///
/// Reads the DNS query from the UDP stream, allocates a fake IP if needed,
/// and sends back a response.
///
/// # Arguments
///
/// * `udp_stream` - The ipstack UDP stream
/// * `fakedns` - The FakeDNS manager for IP allocation
///
/// # Returns
///
/// Returns `Ok(())` on successful response, or an error if the query
/// could not be processed.
#[cfg(feature = "fakedns")]
pub async fn handle_udp_dns_query(
    udp_stream: &mut ipstack::IpStackUdpStream,
    fakedns: &FakeDnsManager,
) -> DnsHijackResult<()> {
    // Read DNS query
    let mut buf = [0u8; MAX_DNS_UDP_SIZE];
    let n = udp_stream.read(&mut buf).await?;

    if n == 0 {
        return Ok(());
    }

    trace!(len = n, "Received UDP DNS query");

    // Process the query and build response
    let response_bytes = process_dns_query(&buf[..n], fakedns)?;

    // Send response
    udp_stream.write_all(&response_bytes).await?;

    trace!(len = response_bytes.len(), "Sent UDP DNS response");
    Ok(())
}

/// Handle a TCP DNS query using FakeDNS
///
/// TCP DNS uses a 2-byte length prefix before each message (RFC 1035 section 4.2.2).
///
/// # Arguments
///
/// * `tcp_stream` - Any async read/write stream (IpStackTcpStream, BufReader, etc.)
/// * `fakedns` - The FakeDNS manager for IP allocation
///
/// # Returns
///
/// Returns `Ok(())` on successful response, or an error if the query
/// could not be processed.
///
/// # Type Parameters
///
/// This function accepts any type that implements `AsyncRead + AsyncWrite + Unpin`,
/// allowing it to work with both raw IpStackTcpStream and BufReader-wrapped streams.
#[cfg(feature = "fakedns")]
pub async fn handle_tcp_dns_query<S>(
    tcp_stream: &mut S,
    fakedns: &FakeDnsManager,
) -> DnsHijackResult<()>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    // Read 2-byte length prefix
    let mut len_buf = [0u8; 2];
    tcp_stream.read_exact(&mut len_buf).await?;
    let query_len = u16::from_be_bytes(len_buf) as usize;

    if query_len == 0 || query_len > MAX_DNS_TCP_SIZE {
        return Err(DnsHijackError::ParseError(format!(
            "Invalid DNS query length: {}",
            query_len
        )));
    }

    // Read query
    let mut buf = vec![0u8; query_len];
    tcp_stream.read_exact(&mut buf).await?;

    trace!(len = query_len, "Received TCP DNS query");

    // Process the query and build response
    let response_bytes = process_dns_query(&buf, fakedns)?;

    // Send response with length prefix
    let response_len = (response_bytes.len() as u16).to_be_bytes();
    tcp_stream.write_all(&response_len).await?;
    tcp_stream.write_all(&response_bytes).await?;

    trace!(len = response_bytes.len(), "Sent TCP DNS response");
    Ok(())
}

/// Process a DNS query and return the response bytes
///
/// # Arguments
///
/// * `query_bytes` - Raw DNS query bytes
/// * `fakedns` - The FakeDNS manager for IP allocation
///
/// # Returns
///
/// The serialized DNS response bytes.
#[cfg(feature = "fakedns")]
fn process_dns_query(query_bytes: &[u8], fakedns: &FakeDnsManager) -> DnsHijackResult<Vec<u8>> {
    // Parse DNS query using hickory-proto
    let query = Message::from_vec(query_bytes)
        .map_err(|e| DnsHijackError::ParseError(e.to_string()))?;

    // Get the query question
    let question = query
        .queries()
        .first()
        .ok_or_else(|| DnsHijackError::ParseError("No question in query".into()))?;

    let domain = question.name().to_ascii();
    let qtype = question.query_type();
    let qclass = question.query_class();

    debug!(
        domain = %domain,
        qtype = ?qtype,
        qclass = ?qclass,
        "Processing DNS query"
    );

    // Only handle IN class queries
    if qclass != DNSClass::IN {
        let response = build_notimp_response(&query);
        return response
            .to_vec()
            .map_err(|e| DnsHijackError::EncodeError(e.to_string()));
    }

    // Build response based on query type
    let response = match qtype {
        RecordType::A => {
            match fakedns.map_domain_ipv4(&domain) {
                Ok((fake_ip, ttl)) => {
                    trace!(domain = %domain, ip = %fake_ip, ttl = ?ttl, "Allocated fake IP");
                    build_a_response(&query, fake_ip, ttl)
                }
                Err(FakeDnsError::PoolExhausted) => {
                    warn!(domain = %domain, "FakeDNS pool exhausted, returning SERVFAIL");
                    build_servfail_response(&query)
                }
                Err(e) => {
                    warn!(domain = %domain, error = %e, "FakeDNS error, returning SERVFAIL");
                    build_servfail_response(&query)
                }
            }
        }
        RecordType::AAAA => {
            // Return empty response for AAAA to force IPv4
            // This ensures clients fall back to A records
            trace!(domain = %domain, "Returning empty AAAA response to force IPv4");
            build_empty_response(&query)
        }
        _ => {
            // Return NOTIMP for unsupported query types (MX, TXT, SRV, etc.)
            trace!(domain = %domain, qtype = ?qtype, "Unsupported query type");
            build_notimp_response(&query)
        }
    };

    response
        .to_vec()
        .map_err(|e| DnsHijackError::EncodeError(e.to_string()))
}

/// Build a DNS A record response
fn build_a_response(query: &Message, ipv4: Ipv4Addr, ttl: Duration) -> Message {
    let mut response = Message::new();
    response.set_id(query.id());
    response.set_message_type(MessageType::Response);
    response.set_op_code(OpCode::Query);
    response.set_response_code(ResponseCode::NoError);
    response.set_recursion_desired(query.recursion_desired());
    response.set_recursion_available(true);
    response.set_authoritative(false);

    // Copy question section
    for q in query.queries() {
        response.add_query(q.clone());
    }

    // Add A record answer
    if let Some(question) = query.queries().first() {
        let record = Record::from_rdata(
            question.name().clone(),
            ttl.as_secs() as u32,
            RData::A(ipv4.into()),
        );
        response.add_answer(record);
    }

    response
}

/// Build an empty DNS response (no answers)
///
/// Used for AAAA queries to force IPv4 fallback.
fn build_empty_response(query: &Message) -> Message {
    let mut response = Message::new();
    response.set_id(query.id());
    response.set_message_type(MessageType::Response);
    response.set_op_code(OpCode::Query);
    response.set_response_code(ResponseCode::NoError);
    response.set_recursion_desired(query.recursion_desired());
    response.set_recursion_available(true);
    response.set_authoritative(false);

    // Copy question section
    for q in query.queries() {
        response.add_query(q.clone());
    }

    // No answer records
    response
}

/// Build a SERVFAIL response
///
/// Used when FakeDNS pool is exhausted or other internal errors occur.
fn build_servfail_response(query: &Message) -> Message {
    let mut response = Message::new();
    response.set_id(query.id());
    response.set_message_type(MessageType::Response);
    response.set_op_code(OpCode::Query);
    response.set_response_code(ResponseCode::ServFail);
    response.set_recursion_desired(query.recursion_desired());
    response.set_recursion_available(true);

    // Copy question section
    for q in query.queries() {
        response.add_query(q.clone());
    }

    response
}

/// Build a NOTIMP (Not Implemented) response
///
/// Used for unsupported query types.
fn build_notimp_response(query: &Message) -> Message {
    let mut response = Message::new();
    response.set_id(query.id());
    response.set_message_type(MessageType::Response);
    response.set_op_code(OpCode::Query);
    response.set_response_code(ResponseCode::NotImp);
    response.set_recursion_desired(query.recursion_desired());
    response.set_recursion_available(false);

    // Copy question section
    for q in query.queries() {
        response.add_query(q.clone());
    }

    response
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a simple DNS A query for testing
    fn create_test_a_query(domain: &str) -> Vec<u8> {
        use hickory_proto::rr::Name;

        let mut query = Message::new();
        query.set_id(0x1234);
        query.set_message_type(MessageType::Query);
        query.set_op_code(OpCode::Query);
        query.set_recursion_desired(true);

        let name = Name::from_ascii(domain).unwrap();
        let question = hickory_proto::op::Query::query(name, RecordType::A);
        query.add_query(question);

        query.to_vec().unwrap()
    }

    /// Create a DNS AAAA query for testing
    fn create_test_aaaa_query(domain: &str) -> Vec<u8> {
        use hickory_proto::rr::Name;

        let mut query = Message::new();
        query.set_id(0x5678);
        query.set_message_type(MessageType::Query);
        query.set_op_code(OpCode::Query);
        query.set_recursion_desired(true);

        let name = Name::from_ascii(domain).unwrap();
        let question = hickory_proto::op::Query::query(name, RecordType::AAAA);
        query.add_query(question);

        query.to_vec().unwrap()
    }

    #[test]
    fn test_build_empty_response() {
        let query_bytes = create_test_aaaa_query("example.com");
        let query = Message::from_vec(&query_bytes).unwrap();

        let response = build_empty_response(&query);

        assert_eq!(response.id(), query.id());
        assert_eq!(response.message_type(), MessageType::Response);
        assert_eq!(response.response_code(), ResponseCode::NoError);
        assert_eq!(response.queries().len(), 1);
        assert_eq!(response.answers().len(), 0);
    }

    #[test]
    fn test_build_servfail_response() {
        let query_bytes = create_test_a_query("example.com");
        let query = Message::from_vec(&query_bytes).unwrap();

        let response = build_servfail_response(&query);

        assert_eq!(response.id(), query.id());
        assert_eq!(response.message_type(), MessageType::Response);
        assert_eq!(response.response_code(), ResponseCode::ServFail);
    }

    #[test]
    fn test_build_notimp_response() {
        let query_bytes = create_test_a_query("example.com");
        let query = Message::from_vec(&query_bytes).unwrap();

        let response = build_notimp_response(&query);

        assert_eq!(response.id(), query.id());
        assert_eq!(response.message_type(), MessageType::Response);
        assert_eq!(response.response_code(), ResponseCode::NotImp);
    }

    #[test]
    fn test_build_a_response() {
        let query_bytes = create_test_a_query("example.com");
        let query = Message::from_vec(&query_bytes).unwrap();
        let ip: Ipv4Addr = "198.18.0.1".parse().unwrap();
        let ttl = Duration::from_secs(300);

        let response = build_a_response(&query, ip, ttl);

        assert_eq!(response.id(), query.id());
        assert_eq!(response.message_type(), MessageType::Response);
        assert_eq!(response.response_code(), ResponseCode::NoError);
        assert_eq!(response.answers().len(), 1);

        let answer = &response.answers()[0];
        assert_eq!(answer.ttl(), 300);
        match answer.data() {
            Some(RData::A(a)) => assert_eq!(a.0, ip),
            _ => panic!("Expected A record"),
        }
    }

    #[cfg(feature = "fakedns")]
    #[test]
    fn test_process_dns_a_query() {
        use crate::fakedns::FakeDnsConfig;

        let config = FakeDnsConfig::new()
            .with_ipv4_pool("198.18.0.0/24".parse().unwrap())
            .with_max_entries(1000)
            .with_ttl(Duration::from_secs(300));
        let fakedns = FakeDnsManager::new(&config);

        let query_bytes = create_test_a_query("example.com");
        let response_bytes = process_dns_query(&query_bytes, &fakedns).unwrap();

        let response = Message::from_vec(&response_bytes).unwrap();
        assert_eq!(response.response_code(), ResponseCode::NoError);
        assert_eq!(response.answers().len(), 1);

        // Verify the IP is from the FakeDNS pool
        if let Some(RData::A(a)) = response.answers()[0].data() {
            assert!(fakedns.is_fake_ip(std::net::IpAddr::V4(a.0)));
        } else {
            panic!("Expected A record");
        }
    }

    #[cfg(feature = "fakedns")]
    #[test]
    fn test_process_dns_aaaa_query_returns_empty() {
        use crate::fakedns::FakeDnsConfig;

        let config = FakeDnsConfig::new()
            .with_ipv4_pool("198.18.0.0/24".parse().unwrap())
            .with_max_entries(1000);
        let fakedns = FakeDnsManager::new(&config);

        let query_bytes = create_test_aaaa_query("example.com");
        let response_bytes = process_dns_query(&query_bytes, &fakedns).unwrap();

        let response = Message::from_vec(&response_bytes).unwrap();
        assert_eq!(response.response_code(), ResponseCode::NoError);
        assert_eq!(response.answers().len(), 0); // Empty response for AAAA
    }
}
