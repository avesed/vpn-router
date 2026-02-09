//! Shared test fixtures and helpers for controlplane equivalence tests
//!
//! This module provides common test infrastructure for comparing routing
//! decisions between `ControlPlaneHandler` and `IngressProcessor`.

#![allow(dead_code)] // Test fixtures may not all be used immediately

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use rust_router::controlplane::{ChainHandler, ChainRoutingResult, ControlPlaneHandler};
use rust_router::ingress::processor::{IngressProcessor, RoutingDecision};
use rust_router::netbridge::dataplane::ConnectionInfo as NetbridgeConnectionInfo;
use rust_router::netbridge::types::{FiveTuple, IpProtocol, SessionId};
use rust_router::outbound::{BlockOutbound, DirectOutbound, OutboundManager};
use rust_router::rules::engine::{
    ConnectionInfo as RulesConnectionInfo, RuleEngine, RoutingSnapshotBuilder,
};
use rust_router::rules::fwmark::ChainMark;

// =============================================================================
// Rule Engine Helpers
// =============================================================================

/// Create a minimal test rule engine with "direct" as default outbound
pub fn create_test_rule_engine() -> Arc<RuleEngine> {
    let snapshot = RoutingSnapshotBuilder::new()
        .default_outbound("direct")
        .version(1)
        .build()
        .expect("Failed to build routing snapshot");
    Arc::new(RuleEngine::new(snapshot))
}

/// Create a rule engine with a chain registered for the given DSCP value
pub fn create_rule_engine_with_chain(chain_tag: &str, dscp: u8) -> Arc<RuleEngine> {
    let mut builder = RoutingSnapshotBuilder::new();
    builder
        .add_chain_with_dscp(chain_tag, dscp)
        .expect("Failed to add chain with DSCP");
    let snapshot = builder
        .default_outbound("direct")
        .version(1)
        .build()
        .expect("Failed to build routing snapshot");
    Arc::new(RuleEngine::new(snapshot))
}

/// Create a rule engine that routes a specific port to "block" outbound
pub fn create_block_rule_engine(port: u16) -> Arc<RuleEngine> {
    let mut builder = RoutingSnapshotBuilder::new();
    builder
        .add_port_rule(&port.to_string(), "block")
        .expect("Failed to add port rule");
    let snapshot = builder
        .default_outbound("direct")
        .version(1)
        .build()
        .expect("Failed to build routing snapshot");
    Arc::new(RuleEngine::new(snapshot))
}

// =============================================================================
// Outbound Manager Helpers
// =============================================================================

/// Create a test outbound manager with Direct and Block outbounds
pub fn create_test_outbound_manager() -> Arc<OutboundManager> {
    let manager = OutboundManager::new();
    manager.add(Box::new(DirectOutbound::simple("direct")));
    manager.add(Box::new(BlockOutbound::new("block")));
    Arc::new(manager)
}

// =============================================================================
// Connection Info Helpers
// =============================================================================

/// Create a `rules::ConnectionInfo` for TCP connection testing
pub fn create_rules_connection_info(
    dest_ip: IpAddr,
    dest_port: u16,
    domain: Option<String>,
) -> RulesConnectionInfo {
    RulesConnectionInfo {
        domain,
        dest_ip: Some(dest_ip),
        dest_port,
        source_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 25, 0, 2))),
        protocol: "tcp",
        sniffed_protocol: None,
    }
}

/// Create a `netbridge::ConnectionInfo` for TCP connection testing
pub fn create_netbridge_connection_info(
    dest_ip: IpAddr,
    dest_port: u16,
    domain: Option<String>,
) -> NetbridgeConnectionInfo {
    let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 25, 0, 2)), 12345);
    let dst = SocketAddr::new(dest_ip, dest_port);

    NetbridgeConnectionInfo {
        session_id: SessionId::new(1),
        src,
        dst,
        protocol: IpProtocol::Tcp,
        peer_key: [0u8; 32],
        peer_endpoint: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 51820),
        domain,
        five_tuple: FiveTuple::tcp(src, dst),
    }
}

// =============================================================================
// Packet Builders
// =============================================================================

/// Create an IPv4 TCP packet with specified addresses and port
pub fn create_ipv4_tcp_packet(src: &str, dst: &str, dst_port: u16) -> Vec<u8> {
    let src_ip: Ipv4Addr = src.parse().expect("Invalid source IP");
    let dst_ip: Ipv4Addr = dst.parse().expect("Invalid destination IP");

    vec![
        0x45,
        0x00, // Version=4, IHL=5, TOS=0
        0x00,
        0x28, // Total Length = 40 (20 IP + 20 TCP)
        0x00,
        0x00,
        0x40,
        0x00, // ID, Flags, Fragment
        0x40,
        0x06, // TTL=64, Protocol=TCP
        0x00,
        0x00, // Checksum (placeholder)
        src_ip.octets()[0],
        src_ip.octets()[1],
        src_ip.octets()[2],
        src_ip.octets()[3],
        dst_ip.octets()[0],
        dst_ip.octets()[1],
        dst_ip.octets()[2],
        dst_ip.octets()[3],
        // TCP header (20 bytes)
        0x12,
        0x34, // Source port (4660)
        (dst_port >> 8) as u8,
        (dst_port & 0xFF) as u8,
        0x00,
        0x00,
        0x00,
        0x01, // Seq number
        0x00,
        0x00,
        0x00,
        0x00, // Ack number
        0x50,
        0x02, // Data offset, flags (SYN)
        0xFF,
        0xFF, // Window
        0x00,
        0x00, // Checksum
        0x00,
        0x00, // Urgent pointer
    ]
}

// =============================================================================
// Handler Factories
// =============================================================================

/// Create a `ControlPlaneHandler` for testing
pub fn create_control_plane_handler(
    rule_engine: Arc<RuleEngine>,
    outbound_manager: Arc<OutboundManager>,
) -> ControlPlaneHandler {
    ControlPlaneHandler::new(rule_engine, outbound_manager, "direct".to_string())
}

/// Create an `IngressProcessor` for testing
pub fn create_ingress_processor(rule_engine: Arc<RuleEngine>) -> IngressProcessor {
    IngressProcessor::new(rule_engine)
}

// =============================================================================
// Decision Comparison Helpers
// =============================================================================

/// Describes a routing outcome in a comparable way
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoutingOutcome {
    /// Route to the specified outbound
    Route { outbound: String },
    /// Block the connection
    Block,
    /// Not a chain packet (DSCP=0)
    NotChain,
}

impl From<&RoutingDecision> for RoutingOutcome {
    fn from(decision: &RoutingDecision) -> Self {
        if decision.outbound == "block" || decision.outbound == "adblock" {
            RoutingOutcome::Block
        } else {
            RoutingOutcome::Route {
                outbound: decision.outbound.clone(),
            }
        }
    }
}

impl From<&ChainRoutingResult> for RoutingOutcome {
    fn from(result: &ChainRoutingResult) -> Self {
        match result {
            ChainRoutingResult::Forward { outbound, .. } => RoutingOutcome::Route {
                outbound: outbound.clone(),
            },
            ChainRoutingResult::Terminal { outbound } => RoutingOutcome::Route {
                outbound: outbound.clone(),
            },
            ChainRoutingResult::Block { .. } => RoutingOutcome::Block,
            ChainRoutingResult::NotChain => RoutingOutcome::NotChain,
        }
    }
}

/// Compare routing decisions for equivalence
/// Returns true if both produce the same outcome (outbound or block)
pub fn decisions_are_equivalent(
    ingress_decision: &RoutingDecision,
    chain_result: &ChainRoutingResult,
) -> bool {
    let ingress_outcome = RoutingOutcome::from(ingress_decision);
    let chain_outcome = RoutingOutcome::from(chain_result);
    ingress_outcome == chain_outcome
}

// =============================================================================
// ChainMark Helper
// =============================================================================

/// Create a ChainMark for testing (convenience wrapper)
pub fn create_chain_mark(dscp: u8) -> Option<ChainMark> {
    ChainMark::from_dscp(dscp)
}
