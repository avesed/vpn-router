//! Ingress packet processor for Phase 6.3
//!
//! This module handles packet processing for `WireGuard` ingress traffic,
//! including DSCP extraction, rule matching, and routing decisions.
//!
//! # Processing Pipeline
//!
//! ```text
//! Decrypted Packet
//!       |
//!       v
//! +---------------------+
//! | Extract IP Headers  |
//! | (Source, Dest, Port)|
//! +---------------------+
//!       |
//!       v
//! +---------------------+
//! | Extract DSCP Value  |
//! | (chain/dscp.rs)     |
//! +---------------------+
//!       |
//!       +-----> DSCP > 0 ? -----+
//!       |                       |
//!       v (no)                  v (yes)
//! +---------------------+  +---------------------+
//! | Rule Engine Match   |  | FwmarkRouter Lookup |
//! | (domain/geoip/port) |  | (DSCP -> routing)   |
//! +---------------------+  +---------------------+
//!       |                       |
//!       +<----------------------+
//!       |
//!       v
//! +---------------------+
//! | RoutingDecision     |
//! | (outbound, dscp,    |
//! |  routing_mark)      |
//! +---------------------+
//! ```
//!
//! # DSCP Chain Routing
//!
//! When a packet arrives with a non-zero DSCP value, it indicates
//! the packet is part of a multi-hop chain. The processor:
//!
//! 1. Extracts the DSCP value from the IP header
//! 2. Looks up the corresponding chain tag via `FwmarkRouter`
//! 3. If the local node is terminal, routes to the exit egress and clears DSCP
//! 4. Otherwise returns a routing decision with the chain mark set
//!
//! # Example
//!
//! ```ignore
//! use rust_router::ingress::processor::{IngressProcessor, RoutingDecision};
//! use rust_router::rules::RuleEngine;
//! use std::sync::Arc;
//!
//! // Create processor with rule engine
//! let rule_engine = Arc::new(RuleEngine::new(snapshot));
//! let processor = IngressProcessor::new(rule_engine);
//!
//! // Process a decrypted packet
//! let decision = processor.process(&packet, "peer-public-key")?;
//! println!("Route to: {} (DSCP: {:?})", decision.outbound, decision.dscp_mark);
//! ```

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use parking_lot::RwLock;
use tracing::{debug, trace};

use super::error::IngressError;
use crate::chain::dscp::{get_dscp, DscpError, IPV4_MIN_HEADER_LEN, IPV6_MIN_HEADER_LEN};
use crate::chain::ChainManager;
use crate::ipc::ChainRole;
use crate::rules::engine::{ConnectionInfo, MatchResult, RuleEngine};
use crate::rules::fwmark::ChainMark;

/// IP protocol numbers
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_ICMP: u8 = 1;
const IPPROTO_ICMPV6: u8 = 58;

/// Routing decision from packet processing
///
/// Contains all information needed to route a packet to the appropriate
/// outbound, including optional DSCP marking for chain routing.
#[derive(Debug, Clone)]
pub struct RoutingDecision {
    /// Target outbound tag
    ///
    /// This is the tag of the outbound to use for this packet.
    pub outbound: String,

    /// Optional DSCP value to set on the packet
    ///
    /// If Some, the packet's DSCP field should be modified before sending.
    /// This is used for marking packets entering a chain or clearing DSCP
    /// when the packet should leave chain routing (value 0).
    pub dscp_mark: Option<u8>,

    /// Optional routing mark for kernel policy routing
    ///
    /// If Some, this mark should be set via `SO_MARK` on the outbound socket.
    /// This enables Linux policy routing for ECMP or chain routing.
    pub routing_mark: Option<u32>,

    /// Whether this packet matched a DSCP chain rule
    ///
    /// True if the packet's existing DSCP value was used for routing.
    pub is_chain_packet: bool,

    /// Information about the match (for logging/debugging)
    pub match_info: Option<String>,
}

impl RoutingDecision {
    /// Create a new routing decision for the default outbound
    #[must_use]
    pub fn default_route(outbound: impl Into<String>) -> Self {
        Self {
            outbound: outbound.into(),
            dscp_mark: None,
            routing_mark: None,
            is_chain_packet: false,
            match_info: Some("default".to_string()),
        }
    }

    /// Create a routing decision from a rule engine match result
    #[must_use]
    pub fn from_match_result(result: MatchResult) -> Self {
        let dscp_mark = result
            .routing_mark
            .and_then(ChainMark::from_routing_mark)
            .map(|mark| mark.dscp_value);

        Self {
            outbound: result.outbound,
            dscp_mark,
            routing_mark: result.routing_mark,
            is_chain_packet: false,
            match_info: result.matched_rule.map(|r| r.to_string()),
        }
    }

    /// Create a routing decision for a DSCP chain packet
    #[must_use]
    pub fn chain_packet(outbound: impl Into<String>, mark: ChainMark) -> Self {
        Self {
            outbound: outbound.into(),
            dscp_mark: Some(mark.dscp_value),
            routing_mark: Some(mark.routing_mark),
            is_chain_packet: true,
            match_info: Some(format!("dscp:{}", mark.dscp_value)),
        }
    }

    /// Check if this is a chain packet
    #[must_use]
    pub fn is_chain(&self) -> bool {
        self.is_chain_packet
    }

    /// Check if a routing mark is set
    #[must_use]
    pub fn has_routing_mark(&self) -> bool {
        self.routing_mark.is_some()
    }
}

impl Default for RoutingDecision {
    fn default() -> Self {
        Self::default_route("direct")
    }
}

/// Ingress packet processor
///
/// Processes decrypted packets from `WireGuard` ingress, extracting
/// connection information and making routing decisions.
///
/// # Thread Safety
///
/// The processor is thread-safe and can be shared across multiple tasks.
/// It uses `Arc<RuleEngine>` for lock-free rule matching.
pub struct IngressProcessor {
    /// Rule engine for routing decisions
    rule_engine: Arc<RuleEngine>,
    /// Optional chain manager for terminal routing decisions
    chain_manager: Arc<RwLock<Option<Arc<ChainManager>>>>,
}

impl IngressProcessor {
    /// Create a new ingress processor
    ///
    /// # Arguments
    ///
    /// * `rule_engine` - Rule engine for routing decisions
    ///
    /// # Example
    ///
    /// ```ignore
    /// let rule_engine = Arc::new(RuleEngine::new(snapshot));
    /// let processor = IngressProcessor::new(rule_engine);
    /// ```
    #[must_use]
    pub fn new(rule_engine: Arc<RuleEngine>) -> Self {
        Self {
            rule_engine,
            chain_manager: Arc::new(RwLock::new(None)),
        }
    }

    /// Process a decrypted packet and return a routing decision
    ///
    /// # Arguments
    ///
    /// * `packet` - Decrypted IP packet bytes
    /// * `src_peer` - Source peer's public key (for logging)
    ///
    /// # Returns
    ///
    /// A `RoutingDecision` indicating how to route this packet.
    ///
    /// # Processing Steps
    ///
    /// 1. Extract IP version from packet
    /// 2. Extract DSCP value
    /// 3. If DSCP > 0 and chain exists, use chain routing
    /// 4. Otherwise, extract connection info and use rule engine (clear DSCP)
    ///
    /// # Errors
    ///
    /// Returns an error if the packet is malformed or too short.
    pub fn process(&self, packet: &[u8], src_peer: &str) -> Result<RoutingDecision, IngressError> {
        // Extract DSCP first - this handles packet validation
        let dscp = match get_dscp(packet) {
            Ok(d) => d,
            Err(DscpError::EmptyPacket) => {
                return Err(IngressError::invalid_packet("empty packet"));
            }
            Err(DscpError::PacketTooShort(got, need)) => {
                return Err(IngressError::invalid_packet(format!(
                    "packet too short: {got} < {need}"
                )));
            }
            Err(DscpError::InvalidIpVersion(v)) => {
                return Err(IngressError::invalid_packet(format!(
                    "invalid IP version: {v}"
                )));
            }
            Err(e) => {
                return Err(IngressError::processing(format!("DSCP extraction failed: {e}")));
            }
        };

        // Check for chain routing (DSCP > 0)
        if dscp > 0 {
            let snapshot = self.rule_engine.load();

            if let Some((chain_tag, chain_mark)) = snapshot
                .fwmark_router
                .chains()
                .find(|(_, chain_mark)| chain_mark.dscp_value == dscp)
            {
                if let Some(chain_manager) = self.chain_manager.read().clone() {
                    if chain_manager.get_chain_role(chain_tag) == Some(ChainRole::Terminal) {
                        if let Some(config) = chain_manager.get_chain_config(chain_tag) {
                            let exit_egress = config.exit_egress;
                            trace!(
                                peer = src_peer,
                                dscp = dscp,
                                chain_tag = chain_tag,
                                exit_egress = %exit_egress,
                                "Terminal chain packet detected"
                            );
                            return Ok(RoutingDecision {
                                outbound: exit_egress,
                                dscp_mark: Some(0),
                                routing_mark: None,
                                is_chain_packet: true,
                                match_info: Some(format!("dscp:{} terminal", chain_mark.dscp_value)),
                            });
                        }

                        debug!(
                            peer = src_peer,
                            chain_tag = chain_tag,
                            "Terminal chain config missing; routing via chain tag"
                        );
                    }
                }

                trace!(
                    peer = src_peer,
                    dscp = dscp,
                    routing_mark = chain_mark.routing_mark,
                    chain_tag = chain_tag,
                    "Chain packet detected"
                );
                // For chain packets, route using the matching chain tag
                return Ok(RoutingDecision::chain_packet(chain_tag, *chain_mark));
            }

            // DSCP set but no chain registered - log and process normally
            debug!(
                peer = src_peer,
                dscp = dscp,
                "DSCP set but no chain registered, using rule matching"
            );
        }

        // Extract connection info for rule matching
        let conn_info = self.extract_connection_info(packet)?;

        trace!(
            peer = src_peer,
            dest_ip = ?conn_info.dest_ip,
            dest_port = conn_info.dest_port,
            protocol = conn_info.protocol,
            "Processing packet"
        );

        // Match against rule engine
        let result = self.rule_engine.match_connection(&conn_info);

        debug!(
            peer = src_peer,
            outbound = result.outbound,
            matched = ?result.matched_rule,
            "Routing decision"
        );

        let mut decision = RoutingDecision::from_match_result(result);
        if dscp > 0 && decision.dscp_mark.is_none() {
            decision.dscp_mark = Some(0);
        }

        Ok(decision)
    }

    /// Extract connection information from a packet
    ///
    /// # Arguments
    ///
    /// * `packet` - IP packet bytes
    ///
    /// # Returns
    ///
    /// `ConnectionInfo` populated with packet metadata.
    ///
    /// # Errors
    ///
    /// Returns an error if the packet is malformed.
    pub fn extract_connection_info(&self, packet: &[u8]) -> Result<ConnectionInfo, IngressError> {
        if packet.is_empty() {
            return Err(IngressError::invalid_packet("empty packet"));
        }

        let version = packet[0] >> 4;

        match version {
            4 => self.extract_ipv4_info(packet),
            6 => self.extract_ipv6_info(packet),
            _ => Err(IngressError::invalid_packet(format!(
                "invalid IP version: {version}"
            ))),
        }
    }

    /// Extract connection info from IPv4 packet
    fn extract_ipv4_info(&self, packet: &[u8]) -> Result<ConnectionInfo, IngressError> {
        if packet.len() < IPV4_MIN_HEADER_LEN {
            return Err(IngressError::invalid_packet(format!(
                "IPv4 packet too short: {} < {}",
                packet.len(),
                IPV4_MIN_HEADER_LEN
            )));
        }

        // Get IHL (header length in 32-bit words)
        let ihl = (packet[0] & 0x0F) as usize;
        let header_len = ihl * 4;

        if packet.len() < header_len {
            return Err(IngressError::invalid_packet(format!(
                "IPv4 packet too short for header: {} < {}",
                packet.len(),
                header_len
            )));
        }

        // Extract protocol
        let protocol = packet[9];

        // Extract source and destination IPs
        let src_ip = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
        let dest_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);

        // Extract ports for TCP/UDP
        let (dest_port, protocol_str) = if packet.len() >= header_len + 4 {
            match protocol {
                IPPROTO_TCP => {
                    let port =
                        u16::from_be_bytes([packet[header_len + 2], packet[header_len + 3]]);
                    (port, "tcp")
                }
                IPPROTO_UDP => {
                    let port =
                        u16::from_be_bytes([packet[header_len + 2], packet[header_len + 3]]);
                    (port, "udp")
                }
                IPPROTO_ICMP => (0, "icmp"),
                _ => (0, "unknown"),
            }
        } else {
            // No transport header available
            match protocol {
                IPPROTO_TCP => (0, "tcp"),
                IPPROTO_UDP => (0, "udp"),
                IPPROTO_ICMP => (0, "icmp"),
                _ => (0, "unknown"),
            }
        };

        Ok(ConnectionInfo {
            domain: None,
            dest_ip: Some(IpAddr::V4(dest_ip)),
            dest_port,
            source_ip: Some(IpAddr::V4(src_ip)),
            protocol: protocol_str,
            sniffed_protocol: None,
        })
    }

    /// Extract connection info from IPv6 packet
    fn extract_ipv6_info(&self, packet: &[u8]) -> Result<ConnectionInfo, IngressError> {
        if packet.len() < IPV6_MIN_HEADER_LEN {
            return Err(IngressError::invalid_packet(format!(
                "IPv6 packet too short: {} < {}",
                packet.len(),
                IPV6_MIN_HEADER_LEN
            )));
        }

        let (protocol, header_len, total_len) =
            super::forwarder::parse_ipv6_transport_header(packet)
                .ok_or_else(|| IngressError::invalid_packet("IPv6 extension header parsing failed"))?;

        // Extract source IP (bytes 8-23)
        let src_ip = Ipv6Addr::from([
            packet[8],
            packet[9],
            packet[10],
            packet[11],
            packet[12],
            packet[13],
            packet[14],
            packet[15],
            packet[16],
            packet[17],
            packet[18],
            packet[19],
            packet[20],
            packet[21],
            packet[22],
            packet[23],
        ]);

        // Extract destination IP (bytes 24-39)
        let dest_ip = Ipv6Addr::from([
            packet[24],
            packet[25],
            packet[26],
            packet[27],
            packet[28],
            packet[29],
            packet[30],
            packet[31],
            packet[32],
            packet[33],
            packet[34],
            packet[35],
            packet[36],
            packet[37],
            packet[38],
            packet[39],
        ]);

        // Extract ports for TCP/UDP (after IPv6 header)
        let (dest_port, protocol_str) = if total_len >= header_len + 4 {
            match protocol {
                IPPROTO_TCP => {
                    let port = u16::from_be_bytes([
                        packet[header_len + 2],
                        packet[header_len + 3],
                    ]);
                    (port, "tcp")
                }
                IPPROTO_UDP => {
                    let port = u16::from_be_bytes([
                        packet[header_len + 2],
                        packet[header_len + 3],
                    ]);
                    (port, "udp")
                }
                IPPROTO_ICMPV6 => (0, "icmpv6"),
                _ => (0, "unknown"),
            }
        } else {
            if matches!(protocol, IPPROTO_TCP | IPPROTO_UDP) {
                return Err(IngressError::invalid_packet(format!(
                    "IPv6 transport header truncated: {} < {}",
                    total_len,
                    header_len + 4
                )));
            }

            match protocol {
                IPPROTO_TCP => (0, "tcp"),
                IPPROTO_UDP => (0, "udp"),
                IPPROTO_ICMPV6 => (0, "icmpv6"),
                _ => (0, "unknown"),
            }
        };

        Ok(ConnectionInfo {
            domain: None,
            dest_ip: Some(IpAddr::V6(dest_ip)),
            dest_port,
            source_ip: Some(IpAddr::V6(src_ip)),
            protocol: protocol_str,
            sniffed_protocol: None,
        })
    }

    /// Get a reference to the rule engine
    #[must_use]
    pub fn rule_engine(&self) -> &Arc<RuleEngine> {
        &self.rule_engine
    }

    /// Attach a chain manager for terminal routing decisions
    pub fn set_chain_manager(&self, chain_manager: Arc<ChainManager>) {
        *self.chain_manager.write() = Some(chain_manager);
    }

    /// Update the rule engine (for hot-reload)
    pub fn set_rule_engine(&mut self, rule_engine: Arc<RuleEngine>) {
        self.rule_engine = rule_engine;
    }
}

impl std::fmt::Debug for IngressProcessor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IngressProcessor")
            .field("rule_engine_version", &self.rule_engine.version())
            .field("chain_manager_set", &self.chain_manager.read().is_some())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::dscp::set_dscp;
    use crate::chain::ChainManager;
    use crate::ipc::{ChainConfig, ChainHop, ChainRole, TunnelType};
    use crate::rules::engine::RoutingSnapshotBuilder;
    use crate::rules::RuleType;
    use tokio::runtime::Runtime;

    // Helper to create a simple rule engine
    fn create_test_engine() -> Arc<RuleEngine> {
        let snapshot = RoutingSnapshotBuilder::new()
            .default_outbound("direct")
            .version(1)
            .build()
            .unwrap();
        Arc::new(RuleEngine::new(snapshot))
    }

    // Helper to create IPv4 TCP packet
    fn create_ipv4_tcp_packet(src: &str, dst: &str, dst_port: u16) -> Vec<u8> {
        let src_ip: Ipv4Addr = src.parse().unwrap();
        let dst_ip: Ipv4Addr = dst.parse().unwrap();

        let packet = vec![
            0x45, 0x00, // Version=4, IHL=5, TOS=0
            0x00, 0x28, // Total Length = 40 (20 IP + 20 TCP)
            0x00, 0x00, 0x40, 0x00, // ID, Flags, Fragment
            0x40, 0x06, // TTL=64, Protocol=TCP
            0x00, 0x00, // Checksum (placeholder)
            src_ip.octets()[0],
            src_ip.octets()[1],
            src_ip.octets()[2],
            src_ip.octets()[3],
            dst_ip.octets()[0],
            dst_ip.octets()[1],
            dst_ip.octets()[2],
            dst_ip.octets()[3],
            // TCP header (20 bytes)
            0x12, 0x34, // Source port (4660)
            (dst_port >> 8) as u8,
            (dst_port & 0xFF) as u8,
            0x00, 0x00, 0x00, 0x01, // Seq number
            0x00, 0x00, 0x00, 0x00, // Ack number
            0x50, 0x02, // Data offset, flags (SYN)
            0xFF, 0xFF, // Window
            0x00, 0x00, // Checksum
            0x00, 0x00, // Urgent pointer
        ];

        packet
    }

    // Helper to create IPv4 UDP packet
    fn create_ipv4_udp_packet(src: &str, dst: &str, dst_port: u16) -> Vec<u8> {
        let src_ip: Ipv4Addr = src.parse().unwrap();
        let dst_ip: Ipv4Addr = dst.parse().unwrap();

        vec![
            0x45, 0x00, // Version=4, IHL=5, TOS=0
            0x00, 0x1C, // Total Length = 28 (20 IP + 8 UDP)
            0x00, 0x00, 0x40, 0x00, // ID, Flags, Fragment
            0x40, 0x11, // TTL=64, Protocol=UDP
            0x00, 0x00, // Checksum (placeholder)
            src_ip.octets()[0],
            src_ip.octets()[1],
            src_ip.octets()[2],
            src_ip.octets()[3],
            dst_ip.octets()[0],
            dst_ip.octets()[1],
            dst_ip.octets()[2],
            dst_ip.octets()[3],
            // UDP header (8 bytes)
            0x12, 0x34, // Source port (4660)
            (dst_port >> 8) as u8,
            (dst_port & 0xFF) as u8,
            0x00, 0x08, // Length
            0x00, 0x00, // Checksum
        ]
    }

    // Helper to create IPv6 TCP packet
    fn create_ipv6_tcp_packet(src: &str, dst: &str, dst_port: u16) -> Vec<u8> {
        let src_ip: Ipv6Addr = src.parse().unwrap();
        let dst_ip: Ipv6Addr = dst.parse().unwrap();

        let mut packet = vec![
            0x60, 0x00, // Version=6, Traffic Class=0, Flow Label
            0x00, 0x00, // Flow Label continued
            0x00, 0x14, // Payload Length = 20 (TCP header)
            0x06, 0x40, // Next Header=TCP, Hop Limit=64
        ];
        packet.extend_from_slice(&src_ip.octets());
        packet.extend_from_slice(&dst_ip.octets());

        // TCP header (20 bytes)
        packet.extend_from_slice(&[
            0x12, 0x34, // Source port (4660)
            (dst_port >> 8) as u8,
            (dst_port & 0xFF) as u8,
            0x00, 0x00, 0x00, 0x01, // Seq number
            0x00, 0x00, 0x00, 0x00, // Ack number
            0x50, 0x02, // Data offset, flags (SYN)
            0xFF, 0xFF, // Window
            0x00, 0x00, // Checksum
            0x00, 0x00, // Urgent pointer
        ]);

        packet
    }

    // ========================================================================
    // RoutingDecision Tests
    // ========================================================================

    #[test]
    fn test_routing_decision_default_route() {
        let decision = RoutingDecision::default_route("proxy");
        assert_eq!(decision.outbound, "proxy");
        assert!(decision.dscp_mark.is_none());
        assert!(decision.routing_mark.is_none());
        assert!(!decision.is_chain_packet);
    }

    #[test]
    fn test_routing_decision_chain_packet() {
        let mark = ChainMark::from_dscp(10).unwrap();
        let decision = RoutingDecision::chain_packet("chain", mark);
        assert_eq!(decision.outbound, "chain");
        assert_eq!(decision.dscp_mark, Some(10));
        assert!(decision.routing_mark.is_some());
        assert!(decision.is_chain_packet);
        assert!(decision.is_chain());
    }

    #[test]
    fn test_routing_decision_default() {
        let decision = RoutingDecision::default();
        assert_eq!(decision.outbound, "direct");
        assert!(!decision.is_chain());
    }

    #[test]
    fn test_routing_decision_has_routing_mark() {
        let decision = RoutingDecision::default_route("test");
        assert!(!decision.has_routing_mark());

        let mark = ChainMark::from_dscp(5).unwrap();
        let chain_decision = RoutingDecision::chain_packet("chain", mark);
        assert!(chain_decision.has_routing_mark());
    }

    // ========================================================================
    // IngressProcessor Creation Tests
    // ========================================================================

    #[test]
    fn test_processor_new() {
        let engine = create_test_engine();
        let processor = IngressProcessor::new(engine);
        assert!(format!("{:?}", processor).contains("IngressProcessor"));
    }

    #[test]
    fn test_processor_rule_engine_ref() {
        let engine = create_test_engine();
        let processor = IngressProcessor::new(Arc::clone(&engine));
        assert_eq!(processor.rule_engine().version(), 1);
    }

    #[test]
    fn test_processor_set_rule_engine() {
        let engine1 = create_test_engine();
        let mut processor = IngressProcessor::new(engine1);
        assert_eq!(processor.rule_engine().version(), 1);

        let engine2 = Arc::new(RuleEngine::new(
            RoutingSnapshotBuilder::new()
                .default_outbound("proxy")
                .version(2)
                .build()
                .unwrap(),
        ));
        processor.set_rule_engine(engine2);
        assert_eq!(processor.rule_engine().version(), 2);
    }

    // ========================================================================
    // IPv4 Processing Tests
    // ========================================================================

    #[test]
    fn test_process_ipv4_tcp_packet() {
        let engine = create_test_engine();
        let processor = IngressProcessor::new(engine);

        let packet = create_ipv4_tcp_packet("10.25.0.2", "8.8.8.8", 443);
        let decision = processor.process(&packet, "test-peer").unwrap();

        assert_eq!(decision.outbound, "direct");
        assert!(!decision.is_chain());
    }

    #[test]
    fn test_process_ipv4_udp_packet() {
        let engine = create_test_engine();
        let processor = IngressProcessor::new(engine);

        let packet = create_ipv4_udp_packet("10.25.0.2", "8.8.8.8", 53);
        let decision = processor.process(&packet, "test-peer").unwrap();

        assert_eq!(decision.outbound, "direct");
    }

    #[test]
    fn test_extract_ipv4_info() {
        let engine = create_test_engine();
        let processor = IngressProcessor::new(engine);

        let packet = create_ipv4_tcp_packet("10.25.0.2", "192.168.1.100", 8080);
        let info = processor.extract_connection_info(&packet).unwrap();

        assert_eq!(info.dest_ip, Some("192.168.1.100".parse().unwrap()));
        assert_eq!(info.source_ip, Some("10.25.0.2".parse().unwrap()));
        assert_eq!(info.dest_port, 8080);
        assert_eq!(info.protocol, "tcp");
    }

    #[test]
    fn test_extract_ipv4_udp_info() {
        let engine = create_test_engine();
        let processor = IngressProcessor::new(engine);

        let packet = create_ipv4_udp_packet("10.25.0.2", "1.1.1.1", 53);
        let info = processor.extract_connection_info(&packet).unwrap();

        assert_eq!(info.dest_ip, Some("1.1.1.1".parse().unwrap()));
        assert_eq!(info.dest_port, 53);
        assert_eq!(info.protocol, "udp");
    }

    // ========================================================================
    // IPv6 Processing Tests
    // ========================================================================

    #[test]
    fn test_process_ipv6_tcp_packet() {
        let engine = create_test_engine();
        let processor = IngressProcessor::new(engine);

        let packet = create_ipv6_tcp_packet("fd00::2", "2001:4860:4860::8888", 443);
        let decision = processor.process(&packet, "test-peer").unwrap();

        assert_eq!(decision.outbound, "direct");
    }

    #[test]
    fn test_extract_ipv6_info() {
        let engine = create_test_engine();
        let processor = IngressProcessor::new(engine);

        let packet = create_ipv6_tcp_packet("fd00::2", "2001:db8::1", 8080);
        let info = processor.extract_connection_info(&packet).unwrap();

        assert_eq!(info.dest_ip, Some("2001:db8::1".parse().unwrap()));
        assert_eq!(info.source_ip, Some("fd00::2".parse().unwrap()));
        assert_eq!(info.dest_port, 8080);
        assert_eq!(info.protocol, "tcp");
    }

    // ========================================================================
    // DSCP Processing Tests
    // ========================================================================

    #[test]
    fn test_process_dscp_packet_no_chain() {
        let engine = create_test_engine();
        let processor = IngressProcessor::new(engine);

        let mut packet = create_ipv4_tcp_packet("10.25.0.2", "8.8.8.8", 443);
        set_dscp(&mut packet, 10).unwrap();

        // No chain registered for DSCP 10, should use normal routing
        let decision = processor.process(&packet, "test-peer").unwrap();
        assert_eq!(decision.outbound, "direct");
        assert!(!decision.is_chain());
        assert_eq!(decision.dscp_mark, Some(0));
    }

    #[test]
    fn test_process_dscp_packet_with_chain() {
        // Create engine with chain registered
        let mut builder = RoutingSnapshotBuilder::new();
        builder.add_chain_with_dscp("test-chain", 10).unwrap();
        let snapshot = builder.default_outbound("direct").build().unwrap();
        let engine = Arc::new(RuleEngine::new(snapshot));
        let processor = IngressProcessor::new(engine);

        let mut packet = create_ipv4_tcp_packet("10.25.0.2", "8.8.8.8", 443);
        set_dscp(&mut packet, 10).unwrap();

        let decision = processor.process(&packet, "test-peer").unwrap();
        assert_eq!(decision.outbound, "test-chain");
        assert!(decision.is_chain());
        assert_eq!(decision.dscp_mark, Some(10));
    }

    #[test]
    fn test_process_dscp_packet_terminal_clears_dscp() {
        let mut builder = RoutingSnapshotBuilder::new();
        builder.add_chain_with_dscp("test-chain", 10).unwrap();
        let snapshot = builder.default_outbound("direct").build().unwrap();
        let engine = Arc::new(RuleEngine::new(snapshot));

        let chain_manager = Arc::new(ChainManager::new("terminal-node".to_string()));
        let config = ChainConfig {
            tag: "test-chain".to_string(),
            description: "Terminal chain".to_string(),
            dscp_value: 10,
            hops: vec![
                ChainHop {
                    node_tag: "entry-node".to_string(),
                    role: ChainRole::Entry,
                    tunnel_type: TunnelType::WireGuard,
                },
                ChainHop {
                    node_tag: "terminal-node".to_string(),
                    role: ChainRole::Terminal,
                    tunnel_type: TunnelType::WireGuard,
                },
            ],
            rules: vec![],
            exit_egress: "pia-us-east".to_string(),
            allow_transitive: false,
        };

        let runtime = Runtime::new().unwrap();
        runtime.block_on(async {
            chain_manager.create_chain(config).await.unwrap();
        });

        let processor = IngressProcessor::new(engine);
        processor.set_chain_manager(Arc::clone(&chain_manager));

        let mut packet = create_ipv4_tcp_packet("10.25.0.2", "8.8.8.8", 443);
        set_dscp(&mut packet, 10).unwrap();

        let decision = processor.process(&packet, "test-peer").unwrap();
        assert_eq!(decision.outbound, "pia-us-east");
        assert!(decision.is_chain());
        assert_eq!(decision.dscp_mark, Some(0));
        assert!(decision.routing_mark.is_none());
    }

    #[test]
    fn test_process_zero_dscp() {
        let engine = create_test_engine();
        let processor = IngressProcessor::new(engine);

        let packet = create_ipv4_tcp_packet("10.25.0.2", "8.8.8.8", 443);
        // DSCP is 0 by default

        let decision = processor.process(&packet, "test-peer").unwrap();
        assert!(!decision.is_chain());
    }

    // ========================================================================
    // Rule Matching Tests
    // ========================================================================

    #[test]
    fn test_process_matches_cidr_rule() {
        let mut builder = RoutingSnapshotBuilder::new();
        builder
            .add_geoip_rule(RuleType::IpCidr, "8.8.8.0/24", "google")
            .unwrap();
        let snapshot = builder.default_outbound("direct").build().unwrap();
        let engine = Arc::new(RuleEngine::new(snapshot));
        let processor = IngressProcessor::new(engine);

        let packet = create_ipv4_tcp_packet("10.25.0.2", "8.8.8.8", 443);
        let decision = processor.process(&packet, "test-peer").unwrap();

        assert_eq!(decision.outbound, "google");
    }

    #[test]
    fn test_process_matches_port_rule() {
        let mut builder = RoutingSnapshotBuilder::new();
        builder.add_port_rule("443", "https-proxy").unwrap();
        let snapshot = builder.default_outbound("direct").build().unwrap();
        let engine = Arc::new(RuleEngine::new(snapshot));
        let processor = IngressProcessor::new(engine);

        let packet = create_ipv4_tcp_packet("10.25.0.2", "1.2.3.4", 443);
        let decision = processor.process(&packet, "test-peer").unwrap();

        assert_eq!(decision.outbound, "https-proxy");
    }

    // ========================================================================
    // Error Handling Tests
    // ========================================================================

    #[test]
    fn test_process_empty_packet() {
        let engine = create_test_engine();
        let processor = IngressProcessor::new(engine);

        let result = processor.process(&[], "test-peer");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("empty packet"));
    }

    #[test]
    fn test_process_packet_too_short() {
        let engine = create_test_engine();
        let processor = IngressProcessor::new(engine);

        let packet = vec![0x45, 0x00]; // Only 2 bytes
        let result = processor.process(&packet, "test-peer");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too short"));
    }

    #[test]
    fn test_process_invalid_ip_version() {
        let engine = create_test_engine();
        let processor = IngressProcessor::new(engine);

        let mut packet = create_ipv4_tcp_packet("10.25.0.2", "8.8.8.8", 443);
        packet[0] = 0x75; // Version = 7

        let result = processor.process(&packet, "test-peer");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("version"));
    }

    #[test]
    fn test_extract_info_empty_packet() {
        let engine = create_test_engine();
        let processor = IngressProcessor::new(engine);

        let result = processor.extract_connection_info(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_ipv4_header_length_exceeded() {
        let engine = create_test_engine();
        let processor = IngressProcessor::new(engine);

        // IPv4 packet with IHL=15 (60 bytes) but only 20 bytes provided
        let mut packet = create_ipv4_tcp_packet("10.25.0.2", "8.8.8.8", 443);
        packet[0] = 0x4F; // IHL = 15

        let result = processor.extract_connection_info(&packet);
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_ipv6_packet_too_short() {
        let engine = create_test_engine();
        let processor = IngressProcessor::new(engine);

        let packet = vec![0x60, 0x00]; // Only 2 bytes
        let result = processor.extract_connection_info(&packet);
        assert!(result.is_err());
    }

    // ========================================================================
    // Edge Cases
    // ========================================================================

    #[test]
    fn test_process_icmp_packet() {
        let engine = create_test_engine();
        let processor = IngressProcessor::new(engine);

        let src_ip: Ipv4Addr = "10.25.0.2".parse().unwrap();
        let dst_ip: Ipv4Addr = "8.8.8.8".parse().unwrap();

        let packet = vec![
            0x45, 0x00, // Version=4, IHL=5, TOS=0
            0x00, 0x1C, // Total Length = 28
            0x00, 0x00, 0x40, 0x00,
            0x40, 0x01, // TTL=64, Protocol=ICMP
            0x00, 0x00,
            src_ip.octets()[0],
            src_ip.octets()[1],
            src_ip.octets()[2],
            src_ip.octets()[3],
            dst_ip.octets()[0],
            dst_ip.octets()[1],
            dst_ip.octets()[2],
            dst_ip.octets()[3],
            // ICMP data
            0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01,
        ];

        let info = processor.extract_connection_info(&packet).unwrap();
        assert_eq!(info.protocol, "icmp");
        assert_eq!(info.dest_port, 0);
    }

    #[test]
    fn test_process_packet_no_transport_header() {
        let engine = create_test_engine();
        let processor = IngressProcessor::new(engine);

        // IPv4 packet with no transport header (just IP header)
        let src_ip: Ipv4Addr = "10.25.0.2".parse().unwrap();
        let dst_ip: Ipv4Addr = "8.8.8.8".parse().unwrap();

        let packet = vec![
            0x45, 0x00,
            0x00, 0x14, // Total Length = 20 (header only)
            0x00, 0x00, 0x40, 0x00,
            0x40, 0x06, // TCP protocol
            0x00, 0x00,
            src_ip.octets()[0],
            src_ip.octets()[1],
            src_ip.octets()[2],
            src_ip.octets()[3],
            dst_ip.octets()[0],
            dst_ip.octets()[1],
            dst_ip.octets()[2],
            dst_ip.octets()[3],
        ];

        let info = processor.extract_connection_info(&packet).unwrap();
        assert_eq!(info.protocol, "tcp");
        assert_eq!(info.dest_port, 0); // No port available
    }

    #[test]
    fn test_routing_decision_debug() {
        let decision = RoutingDecision::default_route("test");
        let debug = format!("{:?}", decision);
        assert!(debug.contains("outbound"));
        assert!(debug.contains("test"));
    }

    #[test]
    fn test_routing_decision_clone() {
        let mark = ChainMark::from_dscp(5).unwrap();
        let decision = RoutingDecision::chain_packet("chain", mark);
        let cloned = decision.clone();

        assert_eq!(decision.outbound, cloned.outbound);
        assert_eq!(decision.dscp_mark, cloned.dscp_mark);
        assert_eq!(decision.routing_mark, cloned.routing_mark);
    }
}
