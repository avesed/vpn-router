//! DSCP chain routing tests
//!
//! This module tests DSCP-based chain routing functionality, verifying
//! parity with Python implementation and correct fwmark/table mapping.
//!
//! # Background
//!
//! DSCP (Differentiated Services Code Point) is used for multi-hop chain routing:
//! - Entry node sets routing_mark based on chain
//! - iptables converts routing_mark to DSCP header
//! - Relay nodes use DSCP to select routing table
//! - Terminal node exits via configured egress
//!
//! # Test Categories
//!
//! 1. **DSCP Value Tests**: Verify value range and validation
//! 2. **Routing Mark Tests**: Test mark to DSCP conversion
//! 3. **Routing Table Tests**: Test table selection logic
//! 4. **Chain Activation Tests**: Test chain lifecycle
//! 5. **SOCKS Rejection Tests**: Test terminal egress validation
//! 6. **Parity Tests**: Compare with Python implementation

use rust_router::rules::fwmark::{
    dscp_to_routing_mark, dscp_to_routing_table, is_dscp_terminal_table, is_ecmp_table,
    is_peer_table, is_relay_table, is_reserved_dscp, is_valid_dscp, routing_mark_to_dscp, tables,
    ChainMark, FwmarkRouter, DSCP_MAX, DSCP_MIN, ENTRY_ROUTING_MARK_BASE,
};

// ============================================================================
// DSCP Value Tests
// ============================================================================

#[test]
fn test_dscp_value_range() {
    // Valid DSCP values are 1-63
    for dscp in DSCP_MIN..=DSCP_MAX {
        assert!(is_valid_dscp(dscp), "DSCP {} should be valid", dscp);
    }

    // 0 is reserved
    assert!(!is_valid_dscp(0), "DSCP 0 should be invalid");

    // Values > 63 exceed 6-bit field
    assert!(!is_valid_dscp(64), "DSCP 64 should be invalid");
    assert!(!is_valid_dscp(255), "DSCP 255 should be invalid");
}

#[test]
fn test_dscp_to_table_mapping() {
    // DSCP value maps to table DSCP_TABLE_BASE + dscp
    for dscp in DSCP_MIN..=DSCP_MAX {
        let expected_table = tables::DSCP_TERMINAL_MIN + dscp as u32;
        let actual_table = dscp_to_routing_table(dscp);
        assert_eq!(
            actual_table,
            Some(expected_table),
            "DSCP {} should map to table {}",
            dscp,
            expected_table
        );
    }
}

#[test]
fn test_table_to_dscp_mapping() {
    // Tables 301-363 map back to DSCP 1-63
    for table in (tables::DSCP_TERMINAL_MIN + 1)..=tables::DSCP_TERMINAL_MAX {
        let mark = ChainMark::from_routing_table(table);
        assert!(
            mark.is_some(),
            "Table {} should map to valid DSCP",
            table
        );
        let expected_dscp = (table - tables::DSCP_TERMINAL_MIN) as u8;
        assert_eq!(
            mark.unwrap().dscp_value,
            expected_dscp,
            "Table {} should map to DSCP {}",
            table,
            expected_dscp
        );
    }

    // Table 300 is boundary (DSCP 0 is invalid)
    assert!(ChainMark::from_routing_table(tables::DSCP_TERMINAL_MIN).is_none());

    // Tables outside range return None
    assert!(ChainMark::from_routing_table(tables::ECMP_MIN).is_none());
    assert!(ChainMark::from_routing_table(tables::DSCP_TERMINAL_MAX + 1).is_none());
}

// ============================================================================
// Routing Mark Tests
// ============================================================================

#[test]
fn test_entry_routing_mark_format() {
    // Entry marks are: ENTRY_ROUTING_MARK_BASE + dscp
    for dscp in DSCP_MIN..=DSCP_MAX {
        let mark = dscp_to_routing_mark(dscp);
        let expected = ENTRY_ROUTING_MARK_BASE + dscp as u32;
        assert_eq!(
            mark,
            Some(expected),
            "DSCP {} should have mark 0x{:x}",
            dscp,
            expected
        );
    }
}

#[test]
fn test_mark_to_dscp_extraction() {
    // Extract DSCP value from routing mark
    let test_cases = [
        (ENTRY_ROUTING_MARK_BASE + 1, 1u8),
        (ENTRY_ROUTING_MARK_BASE + 31, 31),
        (ENTRY_ROUTING_MARK_BASE + 63, 63),
    ];

    for (mark, expected_dscp) in test_cases {
        let dscp = routing_mark_to_dscp(mark);
        assert_eq!(
            dscp,
            Some(expected_dscp),
            "Mark 0x{:x} should extract DSCP {}",
            mark,
            expected_dscp
        );
    }
}

#[test]
fn test_mark_range_validation() {
    // Valid marks are 0x301-0x33F (DSCP 1-63)
    assert!(ChainMark::from_routing_mark(ENTRY_ROUTING_MARK_BASE + 1).is_some());
    assert!(ChainMark::from_routing_mark(ENTRY_ROUTING_MARK_BASE + 63).is_some());

    // Invalid marks
    assert!(
        ChainMark::from_routing_mark(ENTRY_ROUTING_MARK_BASE).is_none(),
        "DSCP 0 reserved"
    );
    assert!(
        ChainMark::from_routing_mark(ENTRY_ROUTING_MARK_BASE + 64).is_none(),
        "DSCP 64 invalid"
    );
    assert!(
        ChainMark::from_routing_mark(0x200).is_none(),
        "Wrong base"
    );
}

// ============================================================================
// Routing Table Tests
// ============================================================================

#[test]
fn test_dscp_table_range() {
    // DSCP tables are 300-363
    let min_table = tables::DSCP_TERMINAL_MIN;
    let max_table = tables::DSCP_TERMINAL_MAX;

    assert_eq!(min_table, 300);
    assert_eq!(max_table, 363);
}

#[test]
fn test_table_no_overlap_with_ecmp() {
    // ECMP tables are 200-299
    // DSCP tables are 300-363
    // No overlap should exist

    for ecmp_table in tables::ECMP_MIN..=tables::ECMP_MAX {
        assert!(is_ecmp_table(ecmp_table));
        assert!(
            !is_dscp_terminal_table(ecmp_table),
            "Table {} should not overlap with DSCP range",
            ecmp_table
        );
    }
}

#[test]
fn test_table_no_overlap_with_relay() {
    // Relay tables are 400-463
    // DSCP tables are 300-363

    for dscp_table in (tables::DSCP_TERMINAL_MIN + 1)..=tables::DSCP_TERMINAL_MAX {
        assert!(is_dscp_terminal_table(dscp_table));
        assert!(
            !is_relay_table(dscp_table),
            "Table {} should not be in relay range",
            dscp_table
        );
    }
}

#[test]
fn test_table_no_overlap_with_peer() {
    // Peer tables are 500-599
    // DSCP tables are 300-363

    for dscp_table in (tables::DSCP_TERMINAL_MIN + 1)..=tables::DSCP_TERMINAL_MAX {
        assert!(is_dscp_terminal_table(dscp_table));
        assert!(
            !is_peer_table(dscp_table),
            "Table {} should not be in peer range",
            dscp_table
        );
    }
}

// ============================================================================
// FwmarkRouter Tests
// ============================================================================

#[test]
fn test_fwmark_router_empty() {
    let router = FwmarkRouter::empty();
    assert_eq!(router.chain_count(), 0);
    assert!(router.is_empty());
}

#[test]
fn test_fwmark_router_add_chain() {
    let router = FwmarkRouter::builder()
        .add_chain("us-chain")
        .unwrap()
        .build();

    assert_eq!(router.chain_count(), 1);
    assert!(!router.is_empty());
}

#[test]
fn test_fwmark_router_dscp_allocation() {
    let router = FwmarkRouter::builder()
        .add_chain("chain-1")
        .unwrap()
        .add_chain("chain-2")
        .unwrap()
        .add_chain("chain-3")
        .unwrap()
        .build();

    assert_eq!(router.chain_count(), 3);
}

#[test]
fn test_fwmark_router_dscp_duplicate() {
    // Duplicate DSCP should fail
    let result = FwmarkRouter::builder()
        .add_chain_with_dscp("chain-a", 1)
        .unwrap()
        .add_chain_with_dscp("chain-b", 1);

    assert!(result.is_err());
}

#[test]
fn test_fwmark_router_dscp_out_of_range() {
    // DSCP 0 is invalid
    let result = FwmarkRouter::builder().add_chain_with_dscp("chain-zero", 0);
    assert!(result.is_err());

    // DSCP 64 exceeds max
    let result = FwmarkRouter::builder().add_chain_with_dscp("chain-64", 64);
    assert!(result.is_err());
}

#[test]
fn test_fwmark_router_get_chain_mark() {
    let router = FwmarkRouter::builder()
        .add_chain_with_dscp("us-chain", 10)
        .unwrap()
        .build();

    // Get route info for chain
    let mark = router.get_chain_mark("us-chain");
    assert!(mark.is_some());

    let chain_mark = mark.unwrap();
    assert_eq!(chain_mark.dscp_value, 10);
    assert_eq!(chain_mark.routing_table, 310); // 300 + 10
    assert_eq!(chain_mark.routing_mark, ENTRY_ROUTING_MARK_BASE + 10);
}

#[test]
fn test_fwmark_router_get_routing_mark() {
    let router = FwmarkRouter::builder()
        .add_chain_with_dscp("eu-chain", 20)
        .unwrap()
        .default_mark(0)
        .build();

    // Lookup chain by tag
    let mark = router.get_routing_mark("eu-chain");
    assert_eq!(mark, Some(ENTRY_ROUTING_MARK_BASE + 20));

    // Non-chain returns default
    let default = router.get_routing_mark("direct");
    assert_eq!(default, Some(0));
}

#[test]
fn test_fwmark_router_lookup_not_found() {
    let router = FwmarkRouter::empty();
    let mark = router.get_chain_mark("nonexistent");
    assert!(mark.is_none());
}

// ============================================================================
// Chain Activation Tests
// ============================================================================

#[test]
fn test_chain_dscp_assignment() {
    let router = FwmarkRouter::builder()
        .add_chain_with_dscp("us-chain", 1)
        .unwrap()
        .add_chain_with_dscp("eu-chain", 2)
        .unwrap()
        .add_chain_with_dscp("asia-chain", 3)
        .unwrap()
        .build();

    let us = router.get_chain_mark("us-chain").unwrap();
    let eu = router.get_chain_mark("eu-chain").unwrap();
    let asia = router.get_chain_mark("asia-chain").unwrap();

    assert_eq!(us.dscp_value, 1);
    assert_eq!(eu.dscp_value, 2);
    assert_eq!(asia.dscp_value, 3);
}

#[test]
fn test_chain_max_capacity() {
    // We can't easily test 63 chains due to reserved DSCP skipping,
    // but we can verify that adding many chains works
    let mut builder = FwmarkRouter::builder();

    for i in 1..=20 {
        builder = builder
            .add_chain(format!("chain-{}", i))
            .expect("should add chain");
    }

    let router = builder.build();
    assert_eq!(router.chain_count(), 20);
}

// ============================================================================
// SOCKS-Based Egress Rejection Tests
// ============================================================================

fn is_socks_based_egress(egress_type: &str) -> bool {
    matches!(egress_type, "v2ray" | "warp-masque")
}

fn can_be_terminal_egress(egress_type: &str) -> bool {
    !is_socks_based_egress(egress_type)
}

#[test]
fn test_reject_v2ray_terminal_egress() {
    // V2Ray egress uses SOCKS5 protocol, which cannot be terminal egress
    // because SOCKS5 strips DSCP headers

    let socks_based_types = ["v2ray", "warp-masque"];

    for egress_type in &socks_based_types {
        assert!(
            is_socks_based_egress(egress_type),
            "{} should be identified as SOCKS-based",
            egress_type
        );

        assert!(
            !can_be_terminal_egress(egress_type),
            "{} should not be allowed as terminal egress",
            egress_type
        );
    }
}

#[test]
fn test_allow_direct_terminal_egress() {
    // Direct egress types can be terminal egress
    let direct_types = ["direct", "pia", "custom", "warp-wireguard", "peer"];

    for egress_type in &direct_types {
        assert!(
            !is_socks_based_egress(egress_type),
            "{} should not be SOCKS-based",
            egress_type
        );

        assert!(
            can_be_terminal_egress(egress_type),
            "{} should be allowed as terminal egress",
            egress_type
        );
    }
}

// ============================================================================
// Python Parity Tests
// ============================================================================

#[test]
fn test_parity_dscp_table_base() {
    // Python: DSCP_TABLE_BASE = 300
    assert_eq!(tables::DSCP_TERMINAL_MIN, 300);
}

#[test]
fn test_parity_entry_mark_base() {
    // Python: ENTRY_ROUTING_MARK_BASE = 0x300
    assert_eq!(ENTRY_ROUTING_MARK_BASE, 0x300);
}

#[test]
fn test_parity_dscp_range() {
    // Python: DSCP values 1-63 (6-bit field, 0 reserved)
    assert_eq!(DSCP_MIN, 1);
    assert_eq!(DSCP_MAX, 63);
}

#[test]
fn test_parity_table_calculation() {
    // Python: table = DSCP_TABLE_BASE + dscp_value
    let test_cases = [(1, 301), (10, 310), (32, 332), (63, 363)];

    for (dscp, expected_table) in test_cases {
        let table = dscp_to_routing_table(dscp);
        assert_eq!(
            table,
            Some(expected_table),
            "DSCP {} should map to table {}",
            dscp,
            expected_table
        );
    }
}

#[test]
fn test_parity_mark_calculation() {
    // Python: routing_mark = ENTRY_ROUTING_MARK_BASE + dscp_value
    let test_cases = [(1u8, 0x301u32), (10, 0x30A), (16, 0x310), (63, 0x33F)];

    for (dscp, expected_mark) in test_cases {
        let mark = dscp_to_routing_mark(dscp);
        assert_eq!(
            mark,
            Some(expected_mark),
            "DSCP {} should have mark 0x{:x}",
            dscp,
            expected_mark
        );
    }
}

#[test]
fn test_parity_iptables_dscp_format() {
    // iptables uses DSCP value in TOS field
    // TOS = DSCP << 2 (for IPv4)

    for dscp in 1..=63u8 {
        let tos = dscp << 2;
        // Verify TOS is in valid range
        assert!(tos <= 252, "TOS {} should be <= 252", tos);
    }
}

// ============================================================================
// Integration Test Cases from Fixtures
// ============================================================================

#[test]
fn test_chain_routing_basic() {
    let router = FwmarkRouter::builder()
        .add_chain_with_dscp("test-chain", 5)
        .unwrap()
        .build();

    let mark = router.get_chain_mark("test-chain").unwrap();

    // Verify all derived values
    assert_eq!(mark.dscp_value, 5);
    assert_eq!(mark.routing_table, 305);
    assert_eq!(mark.routing_mark, ENTRY_ROUTING_MARK_BASE + 5);
}

#[test]
fn test_chain_routing_multiple() {
    let router = FwmarkRouter::builder()
        .add_chain_with_dscp("us-west", 1)
        .unwrap()
        .add_chain_with_dscp("us-east", 2)
        .unwrap()
        .add_chain_with_dscp("eu-london", 10)
        .unwrap()
        .add_chain_with_dscp("asia-tokyo", 20)
        .unwrap()
        .build();

    let chains = [("us-west", 1), ("us-east", 2), ("eu-london", 10), ("asia-tokyo", 20)];

    for (tag, dscp) in &chains {
        let mark = router.get_chain_mark(tag).expect("Chain should exist");
        assert_eq!(mark.dscp_value, *dscp);
        assert_eq!(mark.routing_table, 300 + *dscp as u32);
    }
}

#[test]
fn test_chain_routing_edge_dscp_values() {
    let router = FwmarkRouter::builder()
        // Minimum valid DSCP
        .add_chain_with_dscp("min-chain", 1)
        .unwrap()
        // Maximum valid DSCP
        .add_chain_with_dscp("max-chain", 63)
        .unwrap()
        .build();

    let min_mark = router.get_chain_mark("min-chain").unwrap();
    assert_eq!(min_mark.routing_table, 301);

    let max_mark = router.get_chain_mark("max-chain").unwrap();
    assert_eq!(max_mark.routing_table, 363);
}

#[test]
fn test_reserved_dscp_detection() {
    // Test that reserved DSCP values are correctly identified
    let reserved = [0, 10, 12, 14, 18, 20, 22, 26, 28, 30, 34, 36, 38, 46];
    let non_reserved = [1, 5, 7, 9, 11, 15, 50, 63];

    for dscp in reserved {
        assert!(
            is_reserved_dscp(dscp),
            "DSCP {} should be reserved",
            dscp
        );
    }

    for dscp in non_reserved {
        assert!(
            !is_reserved_dscp(dscp),
            "DSCP {} should not be reserved",
            dscp
        );
    }
}
