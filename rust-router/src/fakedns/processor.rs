//! DNS request processor
//!
//! This module handles DNS requests and returns fake IP addresses for domain names.

use std::io;

use hickory_proto::op::{Header, Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{DNSClass, RData, Record, RecordType};
use tracing::{debug, trace, warn};

use super::manager::FakeDnsManager;

/// Handle a DNS request and return a response with fake IP addresses
///
/// This function processes DNS queries for A and AAAA records, returning
/// fake IP addresses allocated by the FakeDNS manager.
///
/// # Arguments
/// * `req` - The incoming DNS request message
/// * `manager` - The FakeDNS manager for IP allocation
///
/// # Returns
/// A DNS response message with fake IP addresses for supported query types.
pub fn handle_dns_request(req: &Message, manager: &FakeDnsManager) -> io::Result<Message> {
    let mut rsp = Message::new();
    let header = Header::response_from_request(req.header());
    rsp.set_header(header);

    // Only handle standard queries
    if req.op_code() != OpCode::Query || req.message_type() != MessageType::Query {
        rsp.set_response_code(ResponseCode::NotImp);
        return Ok(rsp);
    }

    for query in req.queries() {
        // Copy query to response
        rsp.add_query(query.clone());

        // Only handle IN class
        if query.query_class() != DNSClass::IN {
            warn!(
                "FakeDNS unsupported DNS class: {:?} for query: {:?}",
                query.query_class(),
                query
            );
            continue;
        }

        // Get domain name and strip trailing dot
        let domain = query.name().to_string();
        let domain = domain.trim_end_matches('.');

        match query.query_type() {
            RecordType::A => {
                match manager.map_domain_ipv4(domain) {
                    Ok((ip, ttl)) => {
                        let mut record = Record::from_rdata(
                            query.name().clone(),
                            ttl.as_secs() as u32,
                            RData::A(A(ip)),
                        );
                        record.set_dns_class(query.query_class());
                        rsp.add_answer(record);
                    }
                    Err(err) => {
                        warn!("FakeDNS A record error for {}: {}", domain, err);
                        rsp.set_response_code(ResponseCode::ServFail);
                    }
                }
            }
            RecordType::AAAA => {
                match manager.map_domain_ipv6(domain) {
                    Ok((ip, ttl)) => {
                        let mut record = Record::from_rdata(
                            query.name().clone(),
                            ttl.as_secs() as u32,
                            RData::AAAA(AAAA(ip)),
                        );
                        record.set_dns_class(query.query_class());
                        rsp.add_answer(record);
                    }
                    Err(err) => {
                        // IPv6 not enabled is not an error - just return empty answer
                        debug!("FakeDNS AAAA record not available for {}: {}", domain, err);
                    }
                }
            }
            _ => {
                debug!(
                    "FakeDNS unsupported query type: {} for {}",
                    query.query_type(),
                    domain
                );
            }
        }
    }

    trace!("FakeDNS request: {:?} -> response: {:?}", req, rsp);
    Ok(rsp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fakedns::config::FakeDnsConfig;
    use hickory_proto::op::Query;
    use hickory_proto::rr::Name;
    use std::str::FromStr;
    use std::sync::Arc;
    use std::time::Duration;

    fn test_manager() -> Arc<FakeDnsManager> {
        let config = FakeDnsConfig::new()
            .with_ipv4_pool("10.0.0.0/24".parse().unwrap())
            .with_max_entries(1000)
            .with_ttl(Duration::from_secs(60));
        Arc::new(FakeDnsManager::new(&config))
    }

    fn test_manager_with_ipv6() -> Arc<FakeDnsManager> {
        let config = FakeDnsConfig::new()
            .with_ipv4_pool("10.0.0.0/24".parse().unwrap())
            .with_ipv6_pool("fc00::/120".parse().unwrap())
            .with_max_entries(1000)
            .with_ttl(Duration::from_secs(60));
        Arc::new(FakeDnsManager::new(&config))
    }

    #[test]
    fn test_a_record_query() {
        let manager = test_manager();

        let mut req = Message::new();
        req.set_id(1);
        req.set_message_type(MessageType::Query);
        req.set_op_code(OpCode::Query);
        req.add_query(Query::query(
            Name::from_str("example.com.").unwrap(),
            RecordType::A,
        ));

        let rsp = handle_dns_request(&req, &manager).unwrap();

        assert_eq!(rsp.id(), 1);
        assert_eq!(rsp.answers().len(), 1);

        let answer = &rsp.answers()[0];
        if let Some(RData::A(a)) = answer.data() {
            assert!(manager.is_fake_ip(std::net::IpAddr::V4(a.0)));
        } else {
            panic!("Expected A record");
        }
    }

    #[test]
    fn test_aaaa_record_query_no_ipv6() {
        let manager = test_manager();

        let mut req = Message::new();
        req.set_id(2);
        req.set_message_type(MessageType::Query);
        req.set_op_code(OpCode::Query);
        req.add_query(Query::query(
            Name::from_str("example.com.").unwrap(),
            RecordType::AAAA,
        ));

        let rsp = handle_dns_request(&req, &manager).unwrap();

        assert_eq!(rsp.id(), 2);
        // No AAAA record when IPv6 is not enabled
        assert!(rsp.answers().is_empty());
    }

    #[test]
    fn test_aaaa_record_query_with_ipv6() {
        let manager = test_manager_with_ipv6();

        let mut req = Message::new();
        req.set_id(3);
        req.set_message_type(MessageType::Query);
        req.set_op_code(OpCode::Query);
        req.add_query(Query::query(
            Name::from_str("example.com.").unwrap(),
            RecordType::AAAA,
        ));

        let rsp = handle_dns_request(&req, &manager).unwrap();

        assert_eq!(rsp.id(), 3);
        assert_eq!(rsp.answers().len(), 1);

        let answer = &rsp.answers()[0];
        if let Some(RData::AAAA(aaaa)) = answer.data() {
            assert!(manager.is_fake_ip(std::net::IpAddr::V6(aaaa.0)));
        } else {
            panic!("Expected AAAA record");
        }
    }

    #[test]
    fn test_unsupported_query_type() {
        let manager = test_manager();

        let mut req = Message::new();
        req.set_id(4);
        req.set_message_type(MessageType::Query);
        req.set_op_code(OpCode::Query);
        req.add_query(Query::query(
            Name::from_str("example.com.").unwrap(),
            RecordType::MX,
        ));

        let rsp = handle_dns_request(&req, &manager).unwrap();

        assert_eq!(rsp.id(), 4);
        // MX is not supported, should return empty
        assert!(rsp.answers().is_empty());
    }

    #[test]
    fn test_non_query_opcode() {
        let manager = test_manager();

        let mut req = Message::new();
        req.set_id(5);
        req.set_message_type(MessageType::Query);
        req.set_op_code(OpCode::Status);

        let rsp = handle_dns_request(&req, &manager).unwrap();

        assert_eq!(rsp.id(), 5);
        assert_eq!(rsp.response_code(), ResponseCode::NotImp);
    }

    #[test]
    fn test_consistent_mapping() {
        let manager = test_manager();

        // Query same domain twice
        let mut req1 = Message::new();
        req1.set_id(6);
        req1.set_message_type(MessageType::Query);
        req1.set_op_code(OpCode::Query);
        req1.add_query(Query::query(
            Name::from_str("example.com.").unwrap(),
            RecordType::A,
        ));

        let rsp1 = handle_dns_request(&req1, &manager).unwrap();
        let rsp2 = handle_dns_request(&req1, &manager).unwrap();

        // Should get same IP for same domain
        let ip1 = if let Some(RData::A(a)) = rsp1.answers()[0].data() {
            a.0
        } else {
            panic!("Expected A record");
        };

        let ip2 = if let Some(RData::A(a)) = rsp2.answers()[0].data() {
            a.0
        } else {
            panic!("Expected A record");
        };

        assert_eq!(ip1, ip2);
    }

    #[test]
    fn test_multiple_queries_in_request() {
        let manager = test_manager();

        let mut req = Message::new();
        req.set_id(7);
        req.set_message_type(MessageType::Query);
        req.set_op_code(OpCode::Query);
        req.add_query(Query::query(
            Name::from_str("example1.com.").unwrap(),
            RecordType::A,
        ));
        req.add_query(Query::query(
            Name::from_str("example2.com.").unwrap(),
            RecordType::A,
        ));

        let rsp = handle_dns_request(&req, &manager).unwrap();

        assert_eq!(rsp.id(), 7);
        assert_eq!(rsp.answers().len(), 2);

        // Should have different IPs for different domains
        let ip1 = if let Some(RData::A(a)) = rsp.answers()[0].data() {
            a.0
        } else {
            panic!("Expected A record");
        };

        let ip2 = if let Some(RData::A(a)) = rsp.answers()[1].data() {
            a.0
        } else {
            panic!("Expected A record");
        };

        assert_ne!(ip1, ip2);
    }
}
