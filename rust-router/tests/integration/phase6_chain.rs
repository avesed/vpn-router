//! Phase 6 Chain Routing Integration Tests
//!
//! Integration tests for multi-hop chain routing with DSCP marking.
//!
//! # Test Categories
//!
//! - Chain creation and validation
//! - DSCP packet modification
//! - Chain activation/deactivation
//! - Error handling
//!
//! # Phase 6 Implementation Status
//!
//! These tests are placeholders that will be implemented as Phase 6
//! features are completed.

use rust_router::chain::{
    ChainManager, DscpAllocator, DscpAllocatorError,
    get_dscp, set_dscp, DscpError,
};
use rust_router::ipc::{ChainConfig, ChainHop, ChainRole, TunnelType};

// ============================================================================
// DSCP Packet Modification Tests
// ============================================================================

#[test]
fn test_dscp_get_ipv4() {
    // IPv4 packet with DSCP=10 (TOS=0x28)
    let packet = create_ipv4_packet(10);
    let dscp = get_dscp(&packet).expect("Should extract DSCP");
    assert_eq!(dscp, 10);
}

#[test]
fn test_dscp_set_ipv4() {
    let mut packet = create_ipv4_packet(0);

    set_dscp(&mut packet, 42).expect("Should set DSCP");

    let dscp = get_dscp(&packet).expect("Should extract DSCP");
    assert_eq!(dscp, 42);
}

#[test]
fn test_dscp_preserves_ecn() {
    let mut packet = create_ipv4_packet(0);

    // Set ECN bits (lower 2 bits of TOS byte)
    packet[1] |= 0x03; // ECN=11
    recalc_ipv4_checksum(&mut packet);

    // Set DSCP
    set_dscp(&mut packet, 42).expect("Should set DSCP");

    // Verify ECN is preserved
    assert_eq!(packet[1] & 0x03, 0x03);
}

#[test]
fn test_dscp_all_values() {
    // Test all valid DSCP values (0-63)
    for dscp in 0..=63 {
        let mut packet = create_ipv4_packet(0);
        set_dscp(&mut packet, dscp).expect(&format!("Should set DSCP to {}", dscp));
        assert_eq!(get_dscp(&packet).unwrap(), dscp);
    }
}

#[test]
fn test_dscp_invalid_value() {
    let mut packet = create_ipv4_packet(0);
    let result = set_dscp(&mut packet, 64);
    assert!(matches!(result, Err(DscpError::InvalidDscpValue(64))));
}

#[test]
fn test_dscp_empty_packet() {
    let packet: Vec<u8> = vec![];
    let result = get_dscp(&packet);
    assert!(matches!(result, Err(DscpError::EmptyPacket)));
}

#[test]
fn test_dscp_packet_too_short() {
    let packet = vec![0x45, 0x00]; // Only 2 bytes
    let result = get_dscp(&packet);
    assert!(matches!(result, Err(DscpError::PacketTooShort(2, 20))));
}

// ============================================================================
// DSCP Allocator Tests
// ============================================================================

#[test]
fn test_dscp_allocator_sequential() {
    let allocator = DscpAllocator::new();

    let dscp1 = allocator.allocate().expect("First allocation");
    let dscp2 = allocator.allocate().expect("Second allocation");

    assert_ne!(dscp1, dscp2);
    assert!(dscp1 >= 1 && dscp1 <= 63);
    assert!(dscp2 >= 1 && dscp2 <= 63);
}

#[test]
fn test_dscp_allocator_skips_reserved() {
    let allocator = DscpAllocator::new();

    // Allocate many values and verify none are reserved QoS values
    for _ in 0..30 {
        let dscp = allocator.allocate().expect("Should allocate");
        assert!(!allocator.is_reserved(dscp), "Should not allocate reserved value {}", dscp);
    }
}

#[test]
fn test_dscp_allocator_manual_reserve() {
    let allocator = DscpAllocator::new();

    // Reserve a specific value
    allocator.reserve(42).expect("Should reserve 42");
    assert!(allocator.is_allocated(42));

    // Try to reserve again
    let result = allocator.reserve(42);
    assert!(matches!(result, Err(DscpAllocatorError::AlreadyAllocated(42))));
}

#[test]
fn test_dscp_allocator_release() {
    let allocator = DscpAllocator::new();

    let dscp = allocator.allocate().expect("First allocation");
    allocator.release(dscp);

    // Should be able to allocate the same value again
    let dscp2 = allocator.allocate().expect("Second allocation");
    assert_eq!(dscp, dscp2);
}

// ============================================================================
// Chain Manager Tests
// ============================================================================

#[test]
fn test_chain_manager_creation() {
    let manager = ChainManager::new("test-node".to_string());
    assert_eq!(manager.local_node_tag(), "test-node");
}

#[test]
fn test_chain_manager_list_empty() {
    let manager = ChainManager::new("test-node".to_string());
    let chains = manager.list_chains();
    assert!(chains.is_empty());
}

#[test]
fn test_chain_manager_get_nonexistent() {
    let manager = ChainManager::new("test-node".to_string());
    let status = manager.get_chain_status("nonexistent");
    assert!(status.is_none());
}

// ============================================================================
// Chain Configuration Tests
// ============================================================================

#[test]
fn test_chain_config_serialization() {
    let config = ChainConfig {
        tag: "test-chain".to_string(),
        description: "Test chain".to_string(),
        dscp_value: 10,
        hops: vec![
            ChainHop {
                node_tag: "node-a".to_string(),
                role: ChainRole::Entry,
                tunnel_type: TunnelType::WireGuard,
            },
            ChainHop {
                node_tag: "node-b".to_string(),
                role: ChainRole::Terminal,
                tunnel_type: TunnelType::WireGuard,
            },
        ],
        rules: vec![],
        exit_egress: "pia-us-east".to_string(),
        allow_transitive: false,
    };

    let json = serde_json::to_string(&config).expect("Should serialize");
    let decoded: ChainConfig = serde_json::from_str(&json).expect("Should deserialize");

    assert_eq!(decoded.tag, "test-chain");
    assert_eq!(decoded.dscp_value, 10);
    assert_eq!(decoded.hops.len(), 2);
}

#[test]
fn test_chain_role_serialization() {
    let entry = ChainRole::Entry;
    let relay = ChainRole::Relay;
    let terminal = ChainRole::Terminal;

    assert_eq!(serde_json::to_string(&entry).unwrap(), "\"entry\"");
    assert_eq!(serde_json::to_string(&relay).unwrap(), "\"relay\"");
    assert_eq!(serde_json::to_string(&terminal).unwrap(), "\"terminal\"");
}

// ============================================================================
// Chain Validation Tests (Placeholders)
// ============================================================================

#[test]
#[ignore = "Phase 6.6: Chain creation not yet implemented"]
fn test_chain_creation() {
    let manager = ChainManager::new("node-a".to_string());

    let config = ChainConfig {
        tag: "test-chain".to_string(),
        description: "Test chain".to_string(),
        dscp_value: 10,
        hops: vec![
            ChainHop {
                node_tag: "node-a".to_string(),
                role: ChainRole::Entry,
                tunnel_type: TunnelType::WireGuard,
            },
            ChainHop {
                node_tag: "node-b".to_string(),
                role: ChainRole::Terminal,
                tunnel_type: TunnelType::WireGuard,
            },
        ],
        rules: vec![],
        exit_egress: "pia-us-east".to_string(),
        allow_transitive: false,
    };

    // TODO: Test chain creation
    // tokio_test::block_on(manager.create_chain(config)).expect("Should create chain");
}

#[test]
#[ignore = "Phase 6.6: Chain activation not yet implemented"]
fn test_chain_activation() {
    // TODO: Test chain activation with 2PC
}

// ============================================================================
// Helper Functions
// ============================================================================

fn create_ipv4_packet(dscp: u8) -> Vec<u8> {
    let tos = dscp << 2;
    let mut packet = vec![
        0x45, tos,  // Version=4, IHL=5, TOS
        0x00, 0x14, // Total Length = 20
        0x00, 0x00, 0x00, 0x00, // ID, Flags, Fragment
        0x40, 0x01, // TTL=64, Protocol=ICMP
        0x00, 0x00, // Checksum (will be calculated)
        0x0a, 0x00, 0x00, 0x01, // Source IP 10.0.0.1
        0x0a, 0x00, 0x00, 0x02, // Dest IP 10.0.0.2
    ];

    recalc_ipv4_checksum(&mut packet);
    packet
}

fn recalc_ipv4_checksum(packet: &mut [u8]) {
    // Zero existing checksum
    packet[10] = 0;
    packet[11] = 0;

    // Calculate sum of 16-bit words
    let mut sum: u32 = 0;
    for i in (0..20).step_by(2) {
        let word = (u32::from(packet[i]) << 8) | u32::from(packet[i + 1]);
        sum += word;
    }

    // Fold to 16 bits
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // One's complement
    let checksum = !sum as u16;

    packet[10] = (checksum >> 8) as u8;
    packet[11] = (checksum & 0xFF) as u8;
}
