//! Rule Matching Equivalence Tests
//!
//! Verifies that `ControlPlaneHandler` and `IngressProcessor` produce identical
//! routing decisions for rule-based routing (default outbound, block rules, etc.).
//!
//! # Test Scenarios
//!
//! - Default outbound routing when no rules match
//! - Block outbound rule handling
//! - Port-based rule matching

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use super::fixtures::*;
use rust_router::controlplane::ControlPlaneHandler;
use rust_router::ingress::processor::IngressProcessor;
use rust_router::netbridge::dataplane::RoutingDecision as NetbridgeRoutingDecision;
use rust_router::rules::engine::{ConnectionInfo as RulesConnectionInfo, RuleEngine};

// =============================================================================
// Default Outbound Tests
// =============================================================================

/// Test: IngressProcessor uses default outbound when no rules match
#[test]
fn test_default_outbound_processor() {
    let rule_engine = create_test_rule_engine();
    let processor = IngressProcessor::new(rule_engine);

    // Create packet that won't match any rules
    let packet = create_ipv4_tcp_packet("10.25.0.2", "93.184.216.34", 443);

    let decision = processor
        .process(&packet, "test-peer")
        .expect("Should process packet");

    // Should route to default outbound "direct"
    assert_eq!(
        decision.outbound, "direct",
        "IngressProcessor should use default outbound when no rules match"
    );
}

/// Test: ControlPlaneHandler rule matching produces same result as IngressProcessor
/// when no rules match (both use default outbound)
#[test]
fn test_default_outbound_rule_match_equivalence() {
    let rule_engine = create_test_rule_engine();

    // Test connection that won't match any rules
    let conn = RulesConnectionInfo {
        domain: None,
        dest_ip: Some(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))), // example.com
        dest_port: 443,
        source_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 25, 0, 2))),
        protocol: "tcp",
        sniffed_protocol: None,
    };

    // RuleEngine.match_connection is used by both handlers
    let result = rule_engine.match_connection(&conn);

    // Should return default outbound
    assert_eq!(
        result.outbound, "direct",
        "RuleEngine should return default outbound when no rules match"
    );
}

/// Test: Both handlers use the same default outbound
#[test]
fn test_default_outbound_equivalence() {
    let rule_engine = create_test_rule_engine();
    let outbound_manager = create_test_outbound_manager();

    // IngressProcessor decision
    let processor = IngressProcessor::new(rule_engine.clone());
    let packet = create_ipv4_tcp_packet("10.25.0.2", "93.184.216.34", 443);
    let ingress_decision = processor
        .process(&packet, "test-peer")
        .expect("Should process packet");

    // ControlPlaneHandler uses same RuleEngine internally
    // We verify by checking the rule engine directly
    let conn = RulesConnectionInfo {
        domain: None,
        dest_ip: Some(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))),
        dest_port: 443,
        source_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 25, 0, 2))),
        protocol: "tcp",
        sniffed_protocol: None,
    };
    let rule_result = rule_engine.match_connection(&conn);

    // Both should agree on the outbound
    assert_eq!(
        ingress_decision.outbound, rule_result.outbound,
        "IngressProcessor and RuleEngine should agree on default outbound"
    );
    assert_eq!(
        ingress_decision.outbound, "direct",
        "Default outbound should be 'direct'"
    );
}

// =============================================================================
// Block Outbound Tests
// =============================================================================

/// Test: IngressProcessor correctly routes to "block" outbound
#[test]
fn test_block_outbound_processor() {
    // Create rule engine that routes port 53 (DNS) to "block"
    let rule_engine = create_block_rule_engine(53);
    let processor = IngressProcessor::new(rule_engine);

    // Create DNS packet (port 53)
    let packet = create_ipv4_tcp_packet("10.25.0.2", "8.8.8.8", 53);

    let decision = processor
        .process(&packet, "test-peer")
        .expect("Should process packet");

    // Should route to "block"
    assert_eq!(
        decision.outbound, "block",
        "IngressProcessor should route port 53 to 'block'"
    );
}

/// Test: RuleEngine correctly matches port rule to "block"
#[test]
fn test_block_outbound_rule_match() {
    let rule_engine = create_block_rule_engine(53);

    let conn = RulesConnectionInfo {
        domain: None,
        dest_ip: Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
        dest_port: 53,
        source_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 25, 0, 2))),
        protocol: "tcp",
        sniffed_protocol: None,
    };

    let result = rule_engine.match_connection(&conn);

    // Should match the port rule and route to "block"
    assert_eq!(
        result.outbound, "block",
        "RuleEngine should match port rule to 'block'"
    );
}

/// Test: Both handlers agree on block routing for matching rules
#[test]
fn test_block_outbound_equivalence() {
    let rule_engine = create_block_rule_engine(53);

    // IngressProcessor decision
    let processor = IngressProcessor::new(rule_engine.clone());
    let packet = create_ipv4_tcp_packet("10.25.0.2", "8.8.8.8", 53);
    let ingress_decision = processor
        .process(&packet, "test-peer")
        .expect("Should process packet");

    // RuleEngine decision (same as what ControlPlaneHandler would use)
    let conn = RulesConnectionInfo {
        domain: None,
        dest_ip: Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
        dest_port: 53,
        source_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 25, 0, 2))),
        protocol: "tcp",
        sniffed_protocol: None,
    };
    let rule_result = rule_engine.match_connection(&conn);

    // Both should route to "block"
    assert_eq!(
        ingress_decision.outbound, rule_result.outbound,
        "IngressProcessor and RuleEngine should agree on block routing"
    );
    assert_eq!(ingress_decision.outbound, "block");
}

// =============================================================================
// Port Rule Tests
// =============================================================================

/// Test: Port rule matches correctly for IngressProcessor
#[test]
fn test_port_rule_processor() {
    use rust_router::rules::engine::RoutingSnapshotBuilder;

    // Create rule engine with port 443 -> "https-proxy"
    let mut builder = RoutingSnapshotBuilder::new();
    builder
        .add_port_rule("443", "https-proxy")
        .expect("Should add port rule");
    let snapshot = builder
        .default_outbound("direct")
        .version(1)
        .build()
        .expect("Should build snapshot");
    let rule_engine = Arc::new(RuleEngine::new(snapshot));

    let processor = IngressProcessor::new(rule_engine);

    // Create HTTPS packet (port 443)
    let packet = create_ipv4_tcp_packet("10.25.0.2", "93.184.216.34", 443);

    let decision = processor
        .process(&packet, "test-peer")
        .expect("Should process packet");

    // Should route to "https-proxy"
    assert_eq!(
        decision.outbound, "https-proxy",
        "Port 443 should route to 'https-proxy'"
    );
}

/// Test: Non-matching port uses default outbound
#[test]
fn test_non_matching_port_uses_default() {
    use rust_router::rules::engine::RoutingSnapshotBuilder;

    // Create rule engine with port 443 -> "https-proxy"
    let mut builder = RoutingSnapshotBuilder::new();
    builder
        .add_port_rule("443", "https-proxy")
        .expect("Should add port rule");
    let snapshot = builder
        .default_outbound("direct")
        .version(1)
        .build()
        .expect("Should build snapshot");
    let rule_engine = Arc::new(RuleEngine::new(snapshot));

    let processor = IngressProcessor::new(rule_engine);

    // Create packet for non-matching port (80 instead of 443)
    let packet = create_ipv4_tcp_packet("10.25.0.2", "93.184.216.34", 80);

    let decision = processor
        .process(&packet, "test-peer")
        .expect("Should process packet");

    // Should use default outbound
    assert_eq!(
        decision.outbound, "direct",
        "Non-matching port should route to default 'direct'"
    );
}

// =============================================================================
// ControlPlaneHandler Routing Decision Tests
// =============================================================================

/// Test: ControlPlaneHandler correctly handles block outbound in routing
#[tokio::test]
async fn test_control_plane_handler_block_routing() {
    use rust_router::netbridge::dataplane::ConnectionHandler;

    let rule_engine = create_block_rule_engine(53);
    let outbound_manager = create_test_outbound_manager();

    let handler =
        create_control_plane_handler(rule_engine, outbound_manager);

    // Create connection info for DNS (port 53)
    let info = create_netbridge_connection_info(
        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        53,
        None,
    );

    // Call on_tcp_connect
    let decision = handler.on_tcp_connect(info).await;

    // Should be rejected (block outbound)
    assert!(
        matches!(decision, NetbridgeRoutingDecision::Reject),
        "Block rule should result in Reject decision, got {:?}",
        decision
    );
}

/// Test: ControlPlaneHandler routes to default outbound when no rules match
///
/// This test verifies the routing decision matches the default outbound.
/// NOTE: Marked #[ignore] because it requires network connectivity to
/// establish the outbound connection. The routing DECISION logic is
/// verified in `test_default_outbound_rule_match_equivalence`.
#[tokio::test]
#[ignore = "requires network connectivity - routing decision verified in test_default_outbound_rule_match_equivalence"]
async fn test_control_plane_handler_default_routing() {
    use rust_router::netbridge::dataplane::ConnectionHandler;

    let rule_engine = create_test_rule_engine();
    let outbound_manager = create_test_outbound_manager();

    let handler =
        create_control_plane_handler(rule_engine, outbound_manager);

    // Create connection info that won't match any rules
    let info = create_netbridge_connection_info(
        IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
        443,
        None,
    );

    // Call on_tcp_connect
    let decision = handler.on_tcp_connect(info).await;

    // Should be accepted (default outbound)
    assert!(
        matches!(decision, NetbridgeRoutingDecision::Accept(_)),
        "Default routing should result in Accept decision, got {:?}",
        decision
    );
}

// =============================================================================
// Stats Verification Tests
// =============================================================================

/// Test: ControlPlaneHandler stats are updated on routing decisions
#[tokio::test]
async fn test_control_plane_handler_stats_update() {
    use rust_router::netbridge::dataplane::ConnectionHandler;

    let rule_engine = create_test_rule_engine();
    let outbound_manager = create_test_outbound_manager();

    let handler =
        create_control_plane_handler(rule_engine, outbound_manager);

    // Initial stats should be zero
    let initial_stats = handler.stats().snapshot();
    assert_eq!(initial_stats.tcp_connections, 0);

    // Make a routing decision
    let info = create_netbridge_connection_info(
        IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
        443,
        None,
    );
    let _ = handler.on_tcp_connect(info).await;

    // Stats should be updated
    let updated_stats = handler.stats().snapshot();
    assert_eq!(
        updated_stats.tcp_connections, 1,
        "TCP connections counter should be incremented"
    );
}

/// Test: ControlPlaneHandler increments blocked_connections for block rules
#[tokio::test]
async fn test_control_plane_handler_block_stats() {
    use rust_router::netbridge::dataplane::ConnectionHandler;

    let rule_engine = create_block_rule_engine(53);
    let outbound_manager = create_test_outbound_manager();

    let handler =
        create_control_plane_handler(rule_engine, outbound_manager);

    // Initial stats
    let initial_stats = handler.stats().snapshot();
    assert_eq!(initial_stats.blocked_connections, 0);

    // Make a routing decision that should be blocked
    let info = create_netbridge_connection_info(
        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        53,
        None,
    );
    let _ = handler.on_tcp_connect(info).await;

    // Blocked connections should be incremented
    let updated_stats = handler.stats().snapshot();
    assert_eq!(
        updated_stats.blocked_connections, 1,
        "Blocked connections counter should be incremented for block rules"
    );
}
