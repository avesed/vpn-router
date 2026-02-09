//! DSCP Chain Routing Equivalence Tests
//!
//! Verifies that `ChainHandler` and `IngressProcessor` produce identical
//! routing decisions for DSCP-marked packets and chain entry scenarios.
//!
//! # Test Scenarios
//!
//! - DSCP=0 is not treated as a chain packet
//! - Unregistered DSCP values are blocked
//! - Both handlers block when no ChainManager is configured

use super::fixtures::*;
use rust_router::chain::dscp::set_dscp;
use rust_router::controlplane::ChainHandler;
use rust_router::ingress::processor::IngressProcessor;
use rust_router::rules::fwmark::ChainMark;

// =============================================================================
// DSCP Zero Tests
// =============================================================================

/// Test: DSCP=0 is not treated as a chain packet by ChainHandler
#[test]
fn test_dscp_zero_not_chain_handler() {
    let handler = ChainHandler::new();
    let rule_engine = create_test_rule_engine();

    // DSCP=0 should return NotChain
    let result = handler.handle_dscp_packet(0, &rule_engine);
    assert_eq!(
        RoutingOutcome::from(&result),
        RoutingOutcome::NotChain,
        "ChainHandler: DSCP=0 should return NotChain"
    );
}

/// Test: DSCP=0 packets are routed normally by IngressProcessor
#[test]
fn test_dscp_zero_not_chain_processor() {
    let rule_engine = create_test_rule_engine();
    let processor = IngressProcessor::new(rule_engine);

    // Create packet with DSCP=0 (default)
    let packet = create_ipv4_tcp_packet("10.25.0.2", "8.8.8.8", 443);

    let decision = processor
        .process(&packet, "test-peer")
        .expect("Should process packet");

    // Should not be a chain packet
    assert!(
        !decision.is_chain(),
        "IngressProcessor: DSCP=0 packet should not be marked as chain"
    );

    // Should route to default outbound
    assert_eq!(
        decision.outbound, "direct",
        "IngressProcessor: DSCP=0 should route to default outbound"
    );
}

/// Test: Both handlers agree that DSCP=0 is not a chain packet
#[test]
fn test_dscp_zero_equivalence() {
    let rule_engine = create_test_rule_engine();

    // ChainHandler perspective
    let handler = ChainHandler::new();
    let chain_result = handler.handle_dscp_packet(0, &rule_engine);
    let chain_is_not_chain = matches!(chain_result, rust_router::controlplane::ChainRoutingResult::NotChain);

    // IngressProcessor perspective
    let processor = IngressProcessor::new(rule_engine);
    let packet = create_ipv4_tcp_packet("10.25.0.2", "8.8.8.8", 443);
    let ingress_decision = processor
        .process(&packet, "test-peer")
        .expect("Should process packet");
    let ingress_is_not_chain = !ingress_decision.is_chain();

    // Both should agree it's not a chain packet
    assert!(
        chain_is_not_chain && ingress_is_not_chain,
        "Both handlers should agree DSCP=0 is not a chain packet: chain={}, ingress={}",
        chain_is_not_chain,
        ingress_is_not_chain
    );
}

// =============================================================================
// Unregistered DSCP Tests
// =============================================================================

/// Test: Unregistered DSCP value is blocked by ChainHandler
#[test]
fn test_unregistered_dscp_blocks_handler() {
    let handler = ChainHandler::new();
    let rule_engine = create_test_rule_engine(); // No chains registered

    // DSCP=10 with no chain registered should block
    let result = handler.handle_dscp_packet(10, &rule_engine);
    assert_eq!(
        RoutingOutcome::from(&result),
        RoutingOutcome::Block,
        "ChainHandler: Unregistered DSCP should be blocked"
    );

    // Verify the block reason mentions "unregistered"
    if let rust_router::controlplane::ChainRoutingResult::Block { reason } = result {
        assert!(
            reason.contains("unregistered"),
            "Block reason should mention 'unregistered': {}",
            reason
        );
    }
}

/// Test: Unregistered DSCP value is blocked by IngressProcessor
#[test]
fn test_unregistered_dscp_blocks_processor() {
    let rule_engine = create_test_rule_engine(); // No chains registered
    let processor = IngressProcessor::new(rule_engine);

    // Create packet with DSCP=10
    let mut packet = create_ipv4_tcp_packet("10.25.0.2", "8.8.8.8", 443);
    set_dscp(&mut packet, 10).expect("Should set DSCP");

    let decision = processor
        .process(&packet, "test-peer")
        .expect("Should process packet");

    // Should be blocked (routed to "block")
    assert_eq!(
        decision.outbound, "block",
        "IngressProcessor: Unregistered DSCP should route to 'block'"
    );

    // Should be marked as a chain packet (even though blocked)
    assert!(
        decision.is_chain(),
        "IngressProcessor: Unregistered DSCP should still be marked as chain"
    );

    // Match info should mention "unregistered"
    assert!(
        decision
            .match_info
            .as_ref()
            .map_or(false, |info| info.contains("unregistered")),
        "IngressProcessor: match_info should mention 'unregistered': {:?}",
        decision.match_info
    );
}

/// Test: Both handlers agree on blocking unregistered DSCP
#[test]
fn test_unregistered_dscp_equivalence() {
    let rule_engine = create_test_rule_engine();

    // ChainHandler result
    let handler = ChainHandler::new();
    let chain_result = handler.handle_dscp_packet(10, &rule_engine);

    // IngressProcessor result
    let processor = IngressProcessor::new(rule_engine.clone());
    let mut packet = create_ipv4_tcp_packet("10.25.0.2", "8.8.8.8", 443);
    set_dscp(&mut packet, 10).expect("Should set DSCP");
    let ingress_decision = processor
        .process(&packet, "test-peer")
        .expect("Should process packet");

    // Both should block
    assert_eq!(
        RoutingOutcome::from(&chain_result),
        RoutingOutcome::Block,
        "ChainHandler should block unregistered DSCP"
    );
    assert_eq!(
        RoutingOutcome::from(&ingress_decision),
        RoutingOutcome::Block,
        "IngressProcessor should block unregistered DSCP"
    );
}

// =============================================================================
// No ChainManager Tests
// =============================================================================

/// Test: ChainHandler blocks when DSCP is registered but no ChainManager
#[test]
fn test_no_chain_manager_blocks_handler() {
    // Create rule engine with chain registered
    let rule_engine = create_rule_engine_with_chain("test-chain", 10);

    // Create handler WITHOUT chain manager
    let handler = ChainHandler::new();
    assert!(
        !handler.has_chain_manager(),
        "Handler should not have chain manager"
    );

    // DSCP=10 should be blocked (chain registered but no manager to route)
    let result = handler.handle_dscp_packet(10, &rule_engine);
    assert_eq!(
        RoutingOutcome::from(&result),
        RoutingOutcome::Block,
        "ChainHandler: Should block when no ChainManager available"
    );

    // Verify block reason mentions "no-chain-manager"
    if let rust_router::controlplane::ChainRoutingResult::Block { reason } = result {
        assert!(
            reason.contains("no-chain-manager"),
            "Block reason should mention 'no-chain-manager': {}",
            reason
        );
    }
}

/// Test: IngressProcessor blocks when DSCP is registered but no ChainManager
#[test]
fn test_no_chain_manager_blocks_processor() {
    // Create rule engine with chain registered
    let rule_engine = create_rule_engine_with_chain("test-chain", 10);

    // Create processor WITHOUT chain manager
    let processor = IngressProcessor::new(rule_engine);
    // Note: processor.set_chain_manager() is NOT called

    // Create packet with DSCP=10
    let mut packet = create_ipv4_tcp_packet("10.25.0.2", "8.8.8.8", 443);
    set_dscp(&mut packet, 10).expect("Should set DSCP");

    let decision = processor
        .process(&packet, "test-peer")
        .expect("Should process packet");

    // Should be blocked
    assert_eq!(
        decision.outbound, "block",
        "IngressProcessor: Should block when no ChainManager available"
    );

    // Match info should mention "no-chain-manager"
    assert!(
        decision
            .match_info
            .as_ref()
            .map_or(false, |info| info.contains("no-chain-manager")),
        "IngressProcessor: match_info should mention 'no-chain-manager': {:?}",
        decision.match_info
    );
}

/// Test: Both handlers agree on blocking when no ChainManager
#[test]
fn test_no_chain_manager_equivalence() {
    // Create rule engine with chain registered
    let rule_engine = create_rule_engine_with_chain("test-chain", 10);

    // ChainHandler result (no manager)
    let handler = ChainHandler::new();
    let chain_result = handler.handle_dscp_packet(10, &rule_engine);

    // IngressProcessor result (no manager)
    let processor = IngressProcessor::new(rule_engine.clone());
    let mut packet = create_ipv4_tcp_packet("10.25.0.2", "8.8.8.8", 443);
    set_dscp(&mut packet, 10).expect("Should set DSCP");
    let ingress_decision = processor
        .process(&packet, "test-peer")
        .expect("Should process packet");

    // Both should block
    assert_eq!(
        RoutingOutcome::from(&chain_result),
        RoutingOutcome::Block,
        "ChainHandler should block without ChainManager"
    );
    assert_eq!(
        RoutingOutcome::from(&ingress_decision),
        RoutingOutcome::Block,
        "IngressProcessor should block without ChainManager"
    );
}

// =============================================================================
// Chain Entry Without Manager Tests
// =============================================================================

/// Test: ChainHandler blocks chain entry when no manager
#[test]
fn test_chain_entry_no_manager_blocks() {
    let handler = ChainHandler::new();
    let mark = create_chain_mark(10).expect("Should create chain mark");

    // Handle chain entry without manager
    let result = handler.handle_chain_entry("test-chain", mark);

    assert_eq!(
        RoutingOutcome::from(&result),
        RoutingOutcome::Block,
        "Chain entry should be blocked without ChainManager"
    );
}

// =============================================================================
// DSCP Boundary Value Tests
// =============================================================================

/// Test: All valid DSCP values (1-63) without registered chains are blocked
#[test]
fn test_all_dscp_values_without_chain_blocked() {
    let handler = ChainHandler::new();
    let rule_engine = create_test_rule_engine();

    // Test all valid DSCP values (1-63)
    for dscp in 1..=63u8 {
        let result = handler.handle_dscp_packet(dscp, &rule_engine);
        assert_eq!(
            RoutingOutcome::from(&result),
            RoutingOutcome::Block,
            "DSCP {} should be blocked without registered chain",
            dscp
        );
    }
}

/// Test: DSCP=0 returns NotChain for all handlers
#[test]
fn test_dscp_zero_always_not_chain() {
    let handler = ChainHandler::new();

    // Test with minimal rule engine
    let rule_engine = create_test_rule_engine();
    let result = handler.handle_dscp_packet(0, &rule_engine);
    assert!(
        matches!(result, rust_router::controlplane::ChainRoutingResult::NotChain),
        "DSCP=0 should always return NotChain"
    );

    // Test with chain-registered rule engine
    let rule_engine_with_chain = create_rule_engine_with_chain("test-chain", 10);
    let result = handler.handle_dscp_packet(0, &rule_engine_with_chain);
    assert!(
        matches!(result, rust_router::controlplane::ChainRoutingResult::NotChain),
        "DSCP=0 should return NotChain even with chains registered"
    );
}
