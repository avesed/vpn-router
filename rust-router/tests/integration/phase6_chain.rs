//! Phase 6 Chain Routing Integration Tests
//!
//! Comprehensive integration tests for multi-hop chain routing with DSCP marking.
//!
//! # Test Categories
//!
//! 1. Chain Lifecycle (30 tests)
//!    - Chain creation with auto/manual DSCP allocation
//!    - Chain removal and DSCP reuse
//!    - State transitions and validation
//!
//! 2. DSCP Packet Modification (25 tests)
//!    - IPv4/IPv6 DSCP get/set operations
//!    - Checksum validation
//!    - ECN preservation
//!
//! 3. Role-Based Routing (20 tests)
//!    - Entry, Relay, Terminal node behaviors
//!    - Role determination from chain config
//!
//! 4. Multi-Hop Chain Scenarios (25 tests)
//!    - Various hop configurations
//!    - Mixed tunnel types
//!    - Transitive mode
//!
//! 5. Error Handling and Edge Cases (20 tests)
//!    - Invalid configurations
//!    - Resource exhaustion
//!    - Concurrent operations
//!
//! # Running Tests
//!
//! ```bash
//! cargo test --test integration phase6_chain -- --nocapture
//! ```

use std::sync::Arc;

use rust_router::chain::{
    ChainError, ChainManager, DscpAllocator, DscpAllocatorError,
    DscpRoutingCallback, NoOpRoutingCallback, PeerConnectivityCallback,
    get_dscp, set_dscp, DscpError,
};
use rust_router::ipc::{ChainConfig, ChainHop, ChainRole, ChainState, TunnelType};

// ============================================================================
// Test Helpers
// ============================================================================

/// Create a basic two-hop chain config (Entry -> Terminal)
fn create_two_hop_config(tag: &str, dscp: u8) -> ChainConfig {
    ChainConfig {
        tag: tag.to_string(),
        description: format!("Test chain: {}", tag),
        dscp_value: dscp,
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
    }
}

/// Create a three-hop chain config (Entry -> Relay -> Terminal)
fn create_three_hop_config(tag: &str, dscp: u8) -> ChainConfig {
    ChainConfig {
        tag: tag.to_string(),
        description: format!("Three hop chain: {}", tag),
        dscp_value: dscp,
        hops: vec![
            ChainHop {
                node_tag: "node-a".to_string(),
                role: ChainRole::Entry,
                tunnel_type: TunnelType::WireGuard,
            },
            ChainHop {
                node_tag: "node-b".to_string(),
                role: ChainRole::Relay,
                tunnel_type: TunnelType::WireGuard,
            },
            ChainHop {
                node_tag: "node-c".to_string(),
                role: ChainRole::Terminal,
                tunnel_type: TunnelType::WireGuard,
            },
        ],
        rules: vec![],
        exit_egress: "pia-us-west".to_string(),
        allow_transitive: false,
    }
}

/// Create a single-hop chain config (Terminal only)
fn create_single_hop_config(tag: &str, dscp: u8) -> ChainConfig {
    ChainConfig {
        tag: tag.to_string(),
        description: format!("Single hop chain: {}", tag),
        dscp_value: dscp,
        hops: vec![ChainHop {
            node_tag: "node-a".to_string(),
            role: ChainRole::Terminal,
            tunnel_type: TunnelType::WireGuard,
        }],
        rules: vec![],
        exit_egress: "pia-us-east".to_string(),
        allow_transitive: false,
    }
}

/// Create an IPv4 packet with specified DSCP
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

/// Create an IPv6 packet with specified DSCP
fn create_ipv6_packet(dscp: u8) -> Vec<u8> {
    let tc = dscp << 2;
    let byte0 = 0x60 | (tc >> 4);
    let byte1 = (tc << 4) & 0xF0;

    vec![
        byte0, byte1, // Version, Traffic Class, Flow Label
        0x00, 0x00, // Flow Label continued
        0x00, 0x00, // Payload Length
        0x3a, 0x40, // Next Header=ICMPv6, Hop Limit
        // Source IPv6 (16 bytes)
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        // Dest IPv6 (16 bytes)
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
    ]
}

fn recalc_ipv4_checksum(packet: &mut [u8]) {
    packet[10] = 0;
    packet[11] = 0;

    let mut sum: u32 = 0;
    for i in (0..20).step_by(2) {
        let word = (u32::from(packet[i]) << 8) | u32::from(packet[i + 1]);
        sum += word;
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    let checksum = !sum as u16;
    packet[10] = (checksum >> 8) as u8;
    packet[11] = (checksum & 0xFF) as u8;
}

fn verify_ipv4_checksum(packet: &[u8]) -> bool {
    if packet.len() < 20 {
        return false;
    }

    let mut sum: u32 = 0;
    for i in (0..20).step_by(2) {
        let word = (u32::from(packet[i]) << 8) | u32::from(packet[i + 1]);
        sum += word;
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    sum == 0xFFFF
}

/// Mock routing callback that tracks calls
struct TrackingRoutingCallback {
    setup_calls: std::sync::Mutex<Vec<(String, u8, ChainRole)>>,
    teardown_calls: std::sync::Mutex<Vec<String>>,
    fail_setup: std::sync::atomic::AtomicBool,
}

impl TrackingRoutingCallback {
    fn new() -> Self {
        Self {
            setup_calls: std::sync::Mutex::new(Vec::new()),
            teardown_calls: std::sync::Mutex::new(Vec::new()),
            fail_setup: std::sync::atomic::AtomicBool::new(false),
        }
    }

    fn set_fail_setup(&self, fail: bool) {
        self.fail_setup.store(fail, std::sync::atomic::Ordering::SeqCst);
    }

    fn setup_count(&self) -> usize {
        self.setup_calls.lock().unwrap().len()
    }

    fn teardown_count(&self) -> usize {
        self.teardown_calls.lock().unwrap().len()
    }
}

impl DscpRoutingCallback for TrackingRoutingCallback {
    fn setup_routing(
        &self,
        chain_tag: &str,
        dscp_value: u8,
        role: ChainRole,
        _exit_egress: Option<&str>,
    ) -> Result<(), String> {
        if self.fail_setup.load(std::sync::atomic::Ordering::SeqCst) {
            return Err("Simulated setup failure".to_string());
        }
        self.setup_calls
            .lock()
            .unwrap()
            .push((chain_tag.to_string(), dscp_value, role));
        Ok(())
    }

    fn teardown_routing(&self, chain_tag: &str) -> Result<(), String> {
        self.teardown_calls
            .lock()
            .unwrap()
            .push(chain_tag.to_string());
        Ok(())
    }
}

/// Mock peer connectivity callback
struct MockPeerConnectivity {
    connected_peers: std::sync::Mutex<std::collections::HashSet<String>>,
}

impl MockPeerConnectivity {
    fn new() -> Self {
        Self {
            connected_peers: std::sync::Mutex::new(std::collections::HashSet::new()),
        }
    }

    fn set_connected(&self, peer: &str) {
        self.connected_peers.lock().unwrap().insert(peer.to_string());
    }

    #[allow(dead_code)]
    fn set_disconnected(&self, peer: &str) {
        self.connected_peers.lock().unwrap().remove(peer);
    }
}

impl PeerConnectivityCallback for MockPeerConnectivity {
    fn is_peer_connected(&self, node_tag: &str) -> bool {
        self.connected_peers.lock().unwrap().contains(node_tag)
    }
}

// ============================================================================
// SECTION 1: Chain Lifecycle Tests (30 tests)
// ============================================================================

#[tokio::test]
async fn test_chain_create_with_auto_dscp() {
    let manager = ChainManager::new("node-a".to_string());
    let config = create_two_hop_config("auto-dscp-chain", 0);

    let dscp = manager.create_chain(config).await.unwrap();

    assert!(dscp >= 1 && dscp <= 63);
    assert!(manager.chain_exists("auto-dscp-chain"));
    assert_eq!(manager.chain_count(), 1);
}

#[tokio::test]
async fn test_chain_create_with_manual_dscp() {
    let manager = ChainManager::new("node-a".to_string());
    let config = create_two_hop_config("manual-dscp-chain", 42);

    let dscp = manager.create_chain(config).await.unwrap();

    assert_eq!(dscp, 42);
    assert!(manager.dscp_allocator().is_allocated(42));
}

#[tokio::test]
async fn test_chain_create_multiple_auto_dscp() {
    let manager = ChainManager::new("node-a".to_string());

    let mut allocated = Vec::new();
    for i in 0..10 {
        let config = create_two_hop_config(&format!("chain-{}", i), 0);
        let dscp = manager.create_chain(config).await.unwrap();
        assert!(!allocated.contains(&dscp), "DSCP {} allocated twice", dscp);
        allocated.push(dscp);
    }

    assert_eq!(manager.chain_count(), 10);
}

#[tokio::test]
async fn test_chain_create_duplicate_tag_rejected() {
    let manager = ChainManager::new("node-a".to_string());

    let config1 = create_two_hop_config("duplicate-tag", 10);
    manager.create_chain(config1).await.unwrap();

    let config2 = create_two_hop_config("duplicate-tag", 20);
    let result = manager.create_chain(config2).await;

    assert!(matches!(result, Err(ChainError::AlreadyExists(_))));
}

#[tokio::test]
async fn test_chain_create_duplicate_dscp_rejected() {
    let manager = ChainManager::new("node-a".to_string());

    let config1 = create_two_hop_config("chain-1", 42);
    manager.create_chain(config1).await.unwrap();

    let config2 = create_two_hop_config("chain-2", 42);
    let result = manager.create_chain(config2).await;

    assert!(matches!(result, Err(ChainError::DscpConflict(42))));
}

#[tokio::test]
async fn test_chain_remove_inactive_success() {
    let manager = ChainManager::new("node-a".to_string());

    let config = create_two_hop_config("removable-chain", 30);
    manager.create_chain(config).await.unwrap();

    let result = manager.remove_chain("removable-chain").await;
    assert!(result.is_ok());
    assert!(!manager.chain_exists("removable-chain"));
}

#[tokio::test]
async fn test_chain_remove_releases_dscp() {
    let manager = ChainManager::new("node-a".to_string());

    let config = create_two_hop_config("releasable-chain", 33);
    manager.create_chain(config).await.unwrap();
    assert!(manager.dscp_allocator().is_allocated(33));

    manager.remove_chain("releasable-chain").await.unwrap();
    assert!(!manager.dscp_allocator().is_allocated(33));
}

#[tokio::test]
async fn test_chain_dscp_reuse_after_removal() {
    let manager = ChainManager::new("node-a".to_string());

    let config1 = create_two_hop_config("first-chain", 25);
    manager.create_chain(config1).await.unwrap();
    manager.remove_chain("first-chain").await.unwrap();

    let config2 = create_two_hop_config("second-chain", 25);
    let result = manager.create_chain(config2).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 25);
}

#[tokio::test]
async fn test_chain_remove_nonexistent_fails() {
    let manager = ChainManager::new("node-a".to_string());

    let result = manager.remove_chain("nonexistent").await;
    assert!(matches!(result, Err(ChainError::NotFound(_))));
}

#[tokio::test]
async fn test_chain_state_initial_inactive() {
    let manager = ChainManager::new("node-a".to_string());

    let config = create_two_hop_config("state-test-chain", 0);
    manager.create_chain(config).await.unwrap();

    let status = manager.get_chain_status("state-test-chain").unwrap();
    assert_eq!(status.state, ChainState::Inactive);
}

#[tokio::test]
async fn test_chain_state_update_to_active() {
    let manager = ChainManager::new("node-a".to_string());
    manager.set_routing_callback(Arc::new(NoOpRoutingCallback));

    let config = create_two_hop_config("active-chain", 0);
    manager.create_chain(config).await.unwrap();

    // Use the public activate_chain API to transition to Active state
    manager.activate_chain("active-chain").await.unwrap();

    let status = manager.get_chain_status("active-chain").unwrap();
    assert_eq!(status.state, ChainState::Active);
}

#[tokio::test]
async fn test_chain_state_update_with_error() {
    let manager = ChainManager::new("node-a".to_string());

    // Use a failing callback to trigger error state
    let callback = Arc::new(TrackingRoutingCallback::new());
    callback.set_fail_setup(true);
    manager.set_routing_callback(callback);

    let config = create_two_hop_config("error-chain", 0);
    manager.create_chain(config).await.unwrap();

    // Activation should fail and put chain in Error state
    let result = manager.activate_chain("error-chain").await;
    assert!(result.is_err());

    let status = manager.get_chain_status("error-chain").unwrap();
    assert_eq!(status.state, ChainState::Error);
    assert!(status.last_error.is_some());
}

#[tokio::test]
async fn test_chain_config_retrieval() {
    let manager = ChainManager::new("node-a".to_string());

    let config = create_two_hop_config("config-chain", 15);
    manager.create_chain(config.clone()).await.unwrap();

    let retrieved = manager.get_chain_config("config-chain").unwrap();
    assert_eq!(retrieved.tag, config.tag);
    assert_eq!(retrieved.exit_egress, config.exit_egress);
    assert_eq!(retrieved.hops.len(), config.hops.len());
}

#[tokio::test]
async fn test_chain_list_multiple() {
    let manager = ChainManager::new("node-a".to_string());

    for i in 0..5 {
        let config = create_two_hop_config(&format!("list-chain-{}", i), 0);
        manager.create_chain(config).await.unwrap();
    }

    let chains = manager.list_chains();
    assert_eq!(chains.len(), 5);
}

#[tokio::test]
async fn test_chain_single_hop_terminal_only() {
    let manager = ChainManager::new("node-a".to_string());

    let config = create_single_hop_config("terminal-only", 0);
    let result = manager.create_chain(config).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_chain_three_hops() {
    let manager = ChainManager::new("node-a".to_string());

    let config = create_three_hop_config("three-hop", 0);
    let result = manager.create_chain(config).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_chain_max_hops_allowed() {
    let manager = ChainManager::new("node-a".to_string());

    let mut config = create_two_hop_config("max-hops", 0);
    config.hops = vec![ChainHop {
        node_tag: "entry".to_string(),
        role: ChainRole::Entry,
        tunnel_type: TunnelType::WireGuard,
    }];
    for i in 0..8 {
        config.hops.push(ChainHop {
            node_tag: format!("relay-{}", i),
            role: ChainRole::Relay,
            tunnel_type: TunnelType::WireGuard,
        });
    }
    config.hops.push(ChainHop {
        node_tag: "terminal".to_string(),
        role: ChainRole::Terminal,
        tunnel_type: TunnelType::WireGuard,
    });

    assert_eq!(config.hops.len(), 10);
    let result = manager.create_chain(config).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_chain_too_many_hops_rejected() {
    let manager = ChainManager::new("node-a".to_string());

    let mut config = create_two_hop_config("too-many-hops", 0);
    config.hops = vec![ChainHop {
        node_tag: "entry".to_string(),
        role: ChainRole::Entry,
        tunnel_type: TunnelType::WireGuard,
    }];
    for i in 0..9 {
        config.hops.push(ChainHop {
            node_tag: format!("relay-{}", i),
            role: ChainRole::Relay,
            tunnel_type: TunnelType::WireGuard,
        });
    }
    config.hops.push(ChainHop {
        node_tag: "terminal".to_string(),
        role: ChainRole::Terminal,
        tunnel_type: TunnelType::WireGuard,
    });

    assert_eq!(config.hops.len(), 11);
    let result = manager.create_chain(config).await;
    assert!(matches!(result, Err(ChainError::TooManyHops(11))));
}

#[tokio::test]
async fn test_chain_no_hops_rejected() {
    let manager = ChainManager::new("node-a".to_string());

    let mut config = create_two_hop_config("no-hops", 0);
    config.hops = vec![];

    let result = manager.create_chain(config).await;
    assert!(matches!(result, Err(ChainError::NoHops)));
}

#[tokio::test]
async fn test_chain_direct_egress_rejected() {
    let manager = ChainManager::new("node-a".to_string());

    let mut config = create_two_hop_config("direct-egress", 0);
    config.exit_egress = "direct".to_string();

    let result = manager.create_chain(config).await;
    assert!(matches!(result, Err(ChainError::DirectNotAllowed)));
}

#[tokio::test]
async fn test_chain_direct_egress_case_insensitive() {
    let manager = ChainManager::new("node-a".to_string());

    let mut config = create_two_hop_config("direct-upper", 0);
    config.exit_egress = "DIRECT".to_string();

    let result = manager.create_chain(config).await;
    assert!(matches!(result, Err(ChainError::DirectNotAllowed)));
}

#[tokio::test]
async fn test_chain_invalid_tag_rejected() {
    let manager = ChainManager::new("node-a".to_string());

    let mut config = create_two_hop_config("", 0);
    config.tag = "".to_string();

    let result = manager.create_chain(config).await;
    assert!(matches!(result, Err(ChainError::InvalidTag(_))));
}

#[tokio::test]
async fn test_chain_invalid_dscp_rejected() {
    let manager = ChainManager::new("node-a".to_string());

    let mut config = create_two_hop_config("invalid-dscp", 64);
    config.dscp_value = 64;

    let result = manager.create_chain(config).await;
    assert!(matches!(result, Err(ChainError::InvalidDscp(64))));
}

#[tokio::test]
async fn test_chain_xray_relay_rejected() {
    let manager = ChainManager::new("node-a".to_string());

    let config = ChainConfig {
        tag: "xray-relay-chain".to_string(),
        description: "Chain with Xray relay".to_string(),
        dscp_value: 0,
        hops: vec![
            ChainHop {
                node_tag: "entry".to_string(),
                role: ChainRole::Entry,
                tunnel_type: TunnelType::WireGuard,
            },
            ChainHop {
                node_tag: "relay".to_string(),
                role: ChainRole::Relay,
                tunnel_type: TunnelType::Xray, // Invalid: Xray as relay
            },
            ChainHop {
                node_tag: "terminal".to_string(),
                role: ChainRole::Terminal,
                tunnel_type: TunnelType::WireGuard,
            },
        ],
        rules: vec![],
        exit_egress: "pia-us-east".to_string(),
        allow_transitive: false,
    };

    let result = manager.create_chain(config).await;
    assert!(matches!(result, Err(ChainError::XrayRelayNotAllowed)));
}

#[tokio::test]
async fn test_chain_xray_entry_allowed() {
    let manager = ChainManager::new("node-a".to_string());

    let config = ChainConfig {
        tag: "xray-entry-chain".to_string(),
        description: "Chain with Xray entry".to_string(),
        dscp_value: 0,
        hops: vec![
            ChainHop {
                node_tag: "entry".to_string(),
                role: ChainRole::Entry,
                tunnel_type: TunnelType::Xray, // OK: Xray as entry
            },
            ChainHop {
                node_tag: "terminal".to_string(),
                role: ChainRole::Terminal,
                tunnel_type: TunnelType::WireGuard,
            },
        ],
        rules: vec![],
        exit_egress: "pia-us-east".to_string(),
        allow_transitive: false,
    };

    let result = manager.create_chain(config).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_chain_xray_terminal_allowed() {
    let manager = ChainManager::new("node-a".to_string());

    let config = ChainConfig {
        tag: "xray-terminal-chain".to_string(),
        description: "Chain with Xray terminal".to_string(),
        dscp_value: 0,
        hops: vec![
            ChainHop {
                node_tag: "entry".to_string(),
                role: ChainRole::Entry,
                tunnel_type: TunnelType::WireGuard,
            },
            ChainHop {
                node_tag: "terminal".to_string(),
                role: ChainRole::Terminal,
                tunnel_type: TunnelType::Xray, // OK: Xray as terminal
            },
        ],
        rules: vec![],
        exit_egress: "pia-us-east".to_string(),
        allow_transitive: false,
    };

    let result = manager.create_chain(config).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_chain_no_terminal_rejected() {
    let manager = ChainManager::new("node-a".to_string());

    let config = ChainConfig {
        tag: "no-terminal-chain".to_string(),
        description: "Chain without terminal".to_string(),
        dscp_value: 0,
        hops: vec![
            ChainHop {
                node_tag: "entry".to_string(),
                role: ChainRole::Entry,
                tunnel_type: TunnelType::WireGuard,
            },
            ChainHop {
                node_tag: "relay".to_string(),
                role: ChainRole::Relay,
                tunnel_type: TunnelType::WireGuard,
            },
        ],
        rules: vec![],
        exit_egress: "pia-us-east".to_string(),
        allow_transitive: false,
    };

    let result = manager.create_chain(config).await;
    assert!(matches!(result, Err(ChainError::NoTerminal)));
}

#[tokio::test]
async fn test_chain_with_shared_dscp_allocator() {
    let allocator = Arc::new(DscpAllocator::new());
    let manager1 = ChainManager::with_allocator("node-a".to_string(), allocator.clone());
    let manager2 = ChainManager::with_allocator("node-b".to_string(), allocator.clone());

    let config1 = create_two_hop_config("chain-1", 50);
    manager1.create_chain(config1).await.unwrap();

    // Manager 2 should see the allocation
    assert!(allocator.is_allocated(50));

    // Manager 2 should fail to use the same DSCP
    let config2 = create_two_hop_config("chain-2", 50);
    let result = manager2.create_chain(config2).await;
    assert!(matches!(result, Err(ChainError::DscpConflict(50))));
}

// ============================================================================
// SECTION 2: DSCP Packet Modification Tests (25 tests)
// ============================================================================

#[test]
fn test_dscp_get_ipv4_zero() {
    let packet = create_ipv4_packet(0);
    let dscp = get_dscp(&packet).unwrap();
    assert_eq!(dscp, 0);
}

#[test]
fn test_dscp_get_ipv4_min() {
    let packet = create_ipv4_packet(1);
    let dscp = get_dscp(&packet).unwrap();
    assert_eq!(dscp, 1);
}

#[test]
fn test_dscp_get_ipv4_max() {
    let packet = create_ipv4_packet(63);
    let dscp = get_dscp(&packet).unwrap();
    assert_eq!(dscp, 63);
}

#[test]
fn test_dscp_get_ipv4_middle() {
    let packet = create_ipv4_packet(32);
    let dscp = get_dscp(&packet).unwrap();
    assert_eq!(dscp, 32);
}

#[test]
fn test_dscp_set_ipv4_basic() {
    let mut packet = create_ipv4_packet(0);
    set_dscp(&mut packet, 42).unwrap();
    assert_eq!(get_dscp(&packet).unwrap(), 42);
}

#[test]
fn test_dscp_set_ipv4_checksum_valid() {
    let mut packet = create_ipv4_packet(0);
    set_dscp(&mut packet, 42).unwrap();
    assert!(verify_ipv4_checksum(&packet));
}

#[test]
fn test_dscp_set_ipv4_preserves_ecn() {
    let mut packet = create_ipv4_packet(0);
    // Set ECN bits (lower 2 bits of TOS)
    packet[1] |= 0x03;
    recalc_ipv4_checksum(&mut packet);

    set_dscp(&mut packet, 42).unwrap();

    // Verify ECN is preserved
    assert_eq!(packet[1] & 0x03, 0x03);
    // Verify DSCP is set
    assert_eq!((packet[1] >> 2) & 0x3F, 42);
}

#[test]
fn test_dscp_set_ipv4_all_values() {
    for dscp in 0..=63 {
        let mut packet = create_ipv4_packet(0);
        set_dscp(&mut packet, dscp).unwrap();
        assert_eq!(get_dscp(&packet).unwrap(), dscp);
        assert!(verify_ipv4_checksum(&packet));
    }
}

#[test]
fn test_dscp_get_ipv6_zero() {
    let packet = create_ipv6_packet(0);
    let dscp = get_dscp(&packet).unwrap();
    assert_eq!(dscp, 0);
}

#[test]
fn test_dscp_get_ipv6_max() {
    let packet = create_ipv6_packet(63);
    let dscp = get_dscp(&packet).unwrap();
    assert_eq!(dscp, 63);
}

#[test]
fn test_dscp_set_ipv6_basic() {
    let mut packet = create_ipv6_packet(0);
    set_dscp(&mut packet, 42).unwrap();
    assert_eq!(get_dscp(&packet).unwrap(), 42);
}

#[test]
fn test_dscp_set_ipv6_all_values() {
    for dscp in 0..=63 {
        let mut packet = create_ipv6_packet(0);
        set_dscp(&mut packet, dscp).unwrap();
        assert_eq!(get_dscp(&packet).unwrap(), dscp);
    }
}

#[test]
fn test_dscp_invalid_value_rejected() {
    let mut packet = create_ipv4_packet(0);
    let result = set_dscp(&mut packet, 64);
    assert!(matches!(result, Err(DscpError::InvalidDscpValue(64))));
}

#[test]
fn test_dscp_empty_packet_error() {
    let packet: Vec<u8> = vec![];
    let result = get_dscp(&packet);
    assert!(matches!(result, Err(DscpError::EmptyPacket)));
}

#[test]
fn test_dscp_packet_too_short_ipv4() {
    let packet = vec![0x45, 0x00]; // Only 2 bytes
    let result = get_dscp(&packet);
    assert!(matches!(result, Err(DscpError::PacketTooShort(2, 20))));
}

#[test]
fn test_dscp_packet_too_short_ipv6() {
    let packet = vec![0x60, 0x00, 0x00, 0x00]; // Only 4 bytes
    let result = get_dscp(&packet);
    assert!(matches!(result, Err(DscpError::PacketTooShort(4, 40))));
}

#[test]
fn test_dscp_invalid_version() {
    let mut packet = create_ipv4_packet(0);
    packet[0] = 0x75; // Version = 7
    let result = get_dscp(&packet);
    assert!(matches!(result, Err(DscpError::InvalidIpVersion(7))));
}

#[test]
fn test_dscp_roundtrip_ipv4() {
    let original_dscp = 35;
    let mut packet = create_ipv4_packet(0);

    set_dscp(&mut packet, original_dscp).unwrap();
    let retrieved = get_dscp(&packet).unwrap();

    assert_eq!(original_dscp, retrieved);
}

#[test]
fn test_dscp_roundtrip_ipv6() {
    let original_dscp = 55;
    let mut packet = create_ipv6_packet(0);

    set_dscp(&mut packet, original_dscp).unwrap();
    let retrieved = get_dscp(&packet).unwrap();

    assert_eq!(original_dscp, retrieved);
}

#[test]
fn test_dscp_modify_existing_value_ipv4() {
    let mut packet = create_ipv4_packet(10);
    assert_eq!(get_dscp(&packet).unwrap(), 10);

    set_dscp(&mut packet, 50).unwrap();
    assert_eq!(get_dscp(&packet).unwrap(), 50);
    assert!(verify_ipv4_checksum(&packet));
}

#[test]
fn test_dscp_modify_existing_value_ipv6() {
    let mut packet = create_ipv6_packet(10);
    assert_eq!(get_dscp(&packet).unwrap(), 10);

    set_dscp(&mut packet, 50).unwrap();
    assert_eq!(get_dscp(&packet).unwrap(), 50);
}

#[test]
fn test_dscp_multiple_modifications_ipv4() {
    let mut packet = create_ipv4_packet(0);

    for dscp in [10, 20, 30, 40, 50, 60, 1, 63] {
        set_dscp(&mut packet, dscp).unwrap();
        assert_eq!(get_dscp(&packet).unwrap(), dscp);
        assert!(verify_ipv4_checksum(&packet));
    }
}

#[test]
fn test_dscp_set_empty_packet_error() {
    let mut packet: Vec<u8> = vec![];
    let result = set_dscp(&mut packet, 10);
    assert!(matches!(result, Err(DscpError::EmptyPacket)));
}

#[test]
fn test_dscp_boundary_values() {
    // Test boundary DSCP values
    for dscp in [0, 1, 31, 32, 62, 63] {
        let mut packet_v4 = create_ipv4_packet(0);
        let mut packet_v6 = create_ipv6_packet(0);

        set_dscp(&mut packet_v4, dscp).unwrap();
        set_dscp(&mut packet_v6, dscp).unwrap();

        assert_eq!(get_dscp(&packet_v4).unwrap(), dscp);
        assert_eq!(get_dscp(&packet_v6).unwrap(), dscp);
    }
}

// ============================================================================
// SECTION 3: DSCP Allocator Tests (15 tests)
// ============================================================================

#[test]
fn test_allocator_sequential_allocation() {
    let allocator = DscpAllocator::new();

    let dscp1 = allocator.allocate().unwrap();
    let dscp2 = allocator.allocate().unwrap();

    assert_ne!(dscp1, dscp2);
    assert!(dscp1 >= 1 && dscp1 <= 63);
    assert!(dscp2 >= 1 && dscp2 <= 63);
}

#[test]
fn test_allocator_skips_reserved_values() {
    let allocator = DscpAllocator::new();

    // Allocate many values and verify none are reserved
    for _ in 0..30 {
        let dscp = allocator.allocate().unwrap();
        assert!(
            !allocator.is_reserved(dscp),
            "Auto-allocated DSCP {} should not be reserved",
            dscp
        );
    }
}

#[test]
fn test_allocator_manual_reserve() {
    let allocator = DscpAllocator::new();

    allocator.reserve(42).unwrap();
    assert!(allocator.is_allocated(42));

    let result = allocator.reserve(42);
    assert!(matches!(result, Err(DscpAllocatorError::AlreadyAllocated(42))));
}

#[test]
fn test_allocator_release_and_reuse() {
    let allocator = DscpAllocator::new();

    let dscp = allocator.allocate().unwrap();
    allocator.release(dscp);

    // Should be able to allocate the same value again
    let dscp2 = allocator.allocate().unwrap();
    assert_eq!(dscp, dscp2);
}

#[test]
fn test_allocator_reserve_out_of_range() {
    let allocator = DscpAllocator::new();

    assert!(matches!(
        allocator.reserve(0),
        Err(DscpAllocatorError::OutOfRange(0))
    ));
    assert!(matches!(
        allocator.reserve(64),
        Err(DscpAllocatorError::OutOfRange(64))
    ));
}

#[test]
fn test_allocator_reserved_qos_values() {
    let allocator = DscpAllocator::new();

    // Standard QoS values should be reserved
    assert!(allocator.is_reserved(0));  // BE
    assert!(allocator.is_reserved(8));  // CS1
    assert!(allocator.is_reserved(46)); // EF

    // Non-standard values should not be reserved
    assert!(!allocator.is_reserved(1));
    assert!(!allocator.is_reserved(42));
}

#[test]
fn test_allocator_manual_reserve_qos_value() {
    let allocator = DscpAllocator::new();

    // Manual reservation of QoS values should work
    allocator.reserve(46).unwrap(); // EF
    assert!(allocator.is_allocated(46));
}

#[test]
fn test_allocator_count() {
    let allocator = DscpAllocator::new();

    assert_eq!(allocator.allocated_count(), 0);

    allocator.allocate().unwrap();
    assert_eq!(allocator.allocated_count(), 1);

    allocator.allocate().unwrap();
    assert_eq!(allocator.allocated_count(), 2);
}

#[test]
fn test_allocator_allocated_values() {
    let allocator = DscpAllocator::new();

    allocator.reserve(10).unwrap();
    allocator.reserve(20).unwrap();
    allocator.reserve(30).unwrap();

    let values = allocator.allocated_values();
    assert_eq!(values.len(), 3);
    assert!(values.contains(&10));
    assert!(values.contains(&20));
    assert!(values.contains(&30));
}

#[test]
fn test_allocator_thread_safety() {
    use std::thread;

    let allocator = Arc::new(DscpAllocator::new());
    let mut handles = vec![];

    // Spawn multiple threads allocating concurrently
    for _ in 0..10 {
        let alloc = allocator.clone();
        handles.push(thread::spawn(move || {
            let dscp = alloc.allocate().unwrap();
            assert!(dscp >= 1 && dscp <= 63);
            dscp
        }));
    }

    let results: Vec<u8> = handles.into_iter().map(|h| h.join().unwrap()).collect();

    // All values should be unique
    let unique: std::collections::HashSet<u8> = results.iter().cloned().collect();
    assert_eq!(unique.len(), results.len());
}

// ============================================================================
// SECTION 4: Role Determination Tests (20 tests)
// ============================================================================

#[tokio::test]
async fn test_role_entry_node() {
    let manager = ChainManager::new("node-a".to_string());
    let config = create_two_hop_config("role-test", 0);

    manager.create_chain(config).await.unwrap();

    let role = manager.get_chain_role("role-test");
    assert_eq!(role, Some(ChainRole::Entry));
}

#[tokio::test]
async fn test_role_terminal_node() {
    let manager = ChainManager::new("node-b".to_string());
    let config = create_two_hop_config("role-test", 0);

    manager.create_chain(config).await.unwrap();

    let role = manager.get_chain_role("role-test");
    assert_eq!(role, Some(ChainRole::Terminal));
}

#[tokio::test]
async fn test_role_relay_node() {
    let manager = ChainManager::new("node-b".to_string());
    let config = create_three_hop_config("role-test", 0);

    manager.create_chain(config).await.unwrap();

    let role = manager.get_chain_role("role-test");
    assert_eq!(role, Some(ChainRole::Relay));
}

#[tokio::test]
async fn test_role_not_in_chain() {
    let manager = ChainManager::new("node-x".to_string());
    let config = create_two_hop_config("role-test", 0);

    manager.create_chain(config).await.unwrap();

    let role = manager.get_chain_role("role-test");
    assert_eq!(role, None);
}

#[tokio::test]
async fn test_role_nonexistent_chain() {
    let manager = ChainManager::new("node-a".to_string());

    let role = manager.get_chain_role("nonexistent");
    assert_eq!(role, None);
}

#[tokio::test]
async fn test_role_in_status() {
    let manager = ChainManager::new("node-a".to_string());
    let config = create_two_hop_config("status-role-test", 0);

    manager.create_chain(config).await.unwrap();

    let status = manager.get_chain_status("status-role-test").unwrap();
    assert_eq!(status.my_role, Some(ChainRole::Entry));
}

#[tokio::test]
async fn test_role_terminal_in_single_hop() {
    let manager = ChainManager::new("node-a".to_string());
    let config = create_single_hop_config("single-hop-role", 0);

    manager.create_chain(config).await.unwrap();

    let role = manager.get_chain_role("single-hop-role");
    assert_eq!(role, Some(ChainRole::Terminal));
}

#[tokio::test]
async fn test_role_multiple_chains_different_roles() {
    let manager = ChainManager::new("node-b".to_string());

    // In this chain, node-b is terminal
    let config1 = create_two_hop_config("chain-1", 10);
    manager.create_chain(config1).await.unwrap();

    // In this chain, node-b is relay
    let config2 = create_three_hop_config("chain-2", 20);
    manager.create_chain(config2).await.unwrap();

    assert_eq!(manager.get_chain_role("chain-1"), Some(ChainRole::Terminal));
    assert_eq!(manager.get_chain_role("chain-2"), Some(ChainRole::Relay));
}

#[test]
fn test_chain_role_display() {
    assert_eq!(ChainRole::Entry.to_string(), "entry");
    assert_eq!(ChainRole::Relay.to_string(), "relay");
    assert_eq!(ChainRole::Terminal.to_string(), "terminal");
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

#[test]
fn test_chain_role_deserialization() {
    let entry: ChainRole = serde_json::from_str("\"entry\"").unwrap();
    let relay: ChainRole = serde_json::from_str("\"relay\"").unwrap();
    let terminal: ChainRole = serde_json::from_str("\"terminal\"").unwrap();

    assert_eq!(entry, ChainRole::Entry);
    assert_eq!(relay, ChainRole::Relay);
    assert_eq!(terminal, ChainRole::Terminal);
}

// ============================================================================
// SECTION 5: Chain Activation/Deactivation Tests (20 tests)
// ============================================================================

#[tokio::test]
async fn test_activation_basic_success() {
    let manager = ChainManager::new("node-a".to_string());
    manager.set_routing_callback(Arc::new(NoOpRoutingCallback));

    let config = create_two_hop_config("activate-test", 0);
    manager.create_chain(config).await.unwrap();

    let result = manager.activate_chain("activate-test").await;
    assert!(result.is_ok());

    let status = manager.get_chain_status("activate-test").unwrap();
    assert_eq!(status.state, ChainState::Active);
}

#[tokio::test]
async fn test_activation_nonexistent_chain_fails() {
    let manager = ChainManager::new("node-a".to_string());

    let result = manager.activate_chain("nonexistent").await;
    assert!(matches!(result, Err(ChainError::NotFound(_))));
}

#[tokio::test]
async fn test_activation_already_active_fails() {
    let manager = ChainManager::new("node-a".to_string());
    manager.set_routing_callback(Arc::new(NoOpRoutingCallback));

    let config = create_two_hop_config("already-active", 0);
    manager.create_chain(config).await.unwrap();
    manager.activate_chain("already-active").await.unwrap();

    let result = manager.activate_chain("already-active").await;
    assert!(matches!(result, Err(ChainError::AlreadyActive(_))));
}

#[tokio::test]
async fn test_activation_calls_routing_callback() {
    let manager = ChainManager::new("node-a".to_string());
    let callback = Arc::new(TrackingRoutingCallback::new());
    manager.set_routing_callback(callback.clone());

    let config = create_two_hop_config("callback-test", 15);
    manager.create_chain(config).await.unwrap();
    manager.activate_chain("callback-test").await.unwrap();

    assert_eq!(callback.setup_count(), 1);
}

#[tokio::test]
async fn test_activation_routing_failure_transitions_to_error() {
    let manager = ChainManager::new("node-a".to_string());
    let callback = Arc::new(TrackingRoutingCallback::new());
    callback.set_fail_setup(true);
    manager.set_routing_callback(callback);

    let config = create_two_hop_config("routing-fail", 0);
    manager.create_chain(config).await.unwrap();

    let result = manager.activate_chain("routing-fail").await;
    assert!(result.is_err());

    let status = manager.get_chain_status("routing-fail").unwrap();
    assert_eq!(status.state, ChainState::Error);
}

#[tokio::test]
async fn test_activation_from_error_state() {
    let manager = ChainManager::new("node-a".to_string());

    // Start with a failing callback to put chain in error state
    let callback = Arc::new(TrackingRoutingCallback::new());
    callback.set_fail_setup(true);
    manager.set_routing_callback(callback.clone());

    let config = create_two_hop_config("retry-chain", 0);
    manager.create_chain(config).await.unwrap();

    // First activation fails, puts chain in error state
    let _ = manager.activate_chain("retry-chain").await;
    let status = manager.get_chain_status("retry-chain").unwrap();
    assert_eq!(status.state, ChainState::Error);

    // Now allow activation to succeed
    callback.set_fail_setup(false);

    // Should be able to activate from error state
    let result = manager.activate_chain("retry-chain").await;
    assert!(result.is_ok());

    let status = manager.get_chain_status("retry-chain").unwrap();
    assert_eq!(status.state, ChainState::Active);
}

#[tokio::test]
async fn test_activation_checks_peer_connectivity() {
    let manager = ChainManager::new("node-a".to_string());
    let peer_callback = Arc::new(MockPeerConnectivity::new());
    manager.set_peer_callback(peer_callback.clone());
    manager.set_routing_callback(Arc::new(NoOpRoutingCallback));

    let config = create_two_hop_config("peer-check", 0);
    manager.create_chain(config).await.unwrap();

    // node-b is not connected
    let result = manager.activate_chain("peer-check").await;
    assert!(matches!(result, Err(ChainError::PeerNotConnected(_))));
}

#[tokio::test]
async fn test_activation_with_connected_peers() {
    let manager = ChainManager::new("node-a".to_string());
    let peer_callback = Arc::new(MockPeerConnectivity::new());
    peer_callback.set_connected("node-b");
    manager.set_peer_callback(peer_callback);
    manager.set_routing_callback(Arc::new(NoOpRoutingCallback));

    let config = create_two_hop_config("connected-peers", 0);
    manager.create_chain(config).await.unwrap();

    let result = manager.activate_chain("connected-peers").await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_deactivation_basic_success() {
    let manager = ChainManager::new("node-a".to_string());
    manager.set_routing_callback(Arc::new(NoOpRoutingCallback));

    let config = create_two_hop_config("deactivate-test", 0);
    manager.create_chain(config).await.unwrap();
    manager.activate_chain("deactivate-test").await.unwrap();

    let result = manager.deactivate_chain("deactivate-test").await;
    assert!(result.is_ok());

    let status = manager.get_chain_status("deactivate-test").unwrap();
    assert_eq!(status.state, ChainState::Inactive);
}

#[tokio::test]
async fn test_deactivation_calls_teardown_callback() {
    let manager = ChainManager::new("node-a".to_string());
    let callback = Arc::new(TrackingRoutingCallback::new());
    manager.set_routing_callback(callback.clone());

    let config = create_two_hop_config("teardown-test", 0);
    manager.create_chain(config).await.unwrap();
    manager.activate_chain("teardown-test").await.unwrap();
    manager.deactivate_chain("teardown-test").await.unwrap();

    assert_eq!(callback.teardown_count(), 1);
}

#[tokio::test]
async fn test_deactivation_already_inactive_is_noop() {
    let manager = ChainManager::new("node-a".to_string());

    let config = create_two_hop_config("already-inactive", 0);
    manager.create_chain(config).await.unwrap();

    // Should succeed silently
    let result = manager.deactivate_chain("already-inactive").await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_deactivation_from_error_state() {
    let manager = ChainManager::new("node-a".to_string());

    // Use failing callback to put chain in error state
    let callback = Arc::new(TrackingRoutingCallback::new());
    callback.set_fail_setup(true);
    manager.set_routing_callback(callback.clone());

    let config = create_two_hop_config("error-deactivate", 0);
    manager.create_chain(config).await.unwrap();

    // Activation fails, puts chain in error state
    let _ = manager.activate_chain("error-deactivate").await;
    let status = manager.get_chain_status("error-deactivate").unwrap();
    assert_eq!(status.state, ChainState::Error);

    // Now allow teardown to succeed
    callback.set_fail_setup(false);

    let result = manager.deactivate_chain("error-deactivate").await;
    assert!(result.is_ok());

    let status = manager.get_chain_status("error-deactivate").unwrap();
    assert_eq!(status.state, ChainState::Inactive);
}

#[tokio::test]
async fn test_deactivation_nonexistent_chain_fails() {
    let manager = ChainManager::new("node-a".to_string());

    let result = manager.deactivate_chain("nonexistent").await;
    assert!(matches!(result, Err(ChainError::NotFound(_))));
}

#[tokio::test]
async fn test_remove_active_chain_fails() {
    let manager = ChainManager::new("node-a".to_string());
    manager.set_routing_callback(Arc::new(NoOpRoutingCallback));

    let config = create_two_hop_config("active-remove", 0);
    manager.create_chain(config).await.unwrap();
    manager.activate_chain("active-remove").await.unwrap();

    let result = manager.remove_chain("active-remove").await;
    assert!(matches!(result, Err(ChainError::CannotRemoveActiveChain(_))));
}

#[tokio::test]
async fn test_remove_error_state_chain_succeeds() {
    let manager = ChainManager::new("node-a".to_string());

    // Use failing callback to put chain in error state
    let callback = Arc::new(TrackingRoutingCallback::new());
    callback.set_fail_setup(true);
    manager.set_routing_callback(callback);

    let config = create_two_hop_config("error-remove", 0);
    let dscp = manager.create_chain(config).await.unwrap();

    // Activation fails, puts chain in error state
    let _ = manager.activate_chain("error-remove").await;
    let status = manager.get_chain_status("error-remove").unwrap();
    assert_eq!(status.state, ChainState::Error);

    let result = manager.remove_chain("error-remove").await;
    assert!(result.is_ok());
    assert!(!manager.dscp_allocator().is_allocated(dscp));
}

// ============================================================================
// SECTION 6: 2PC Request Handler Tests (15 tests)
// ============================================================================

#[tokio::test]
async fn test_handle_prepare_request_success() {
    let manager = ChainManager::new("node-b".to_string());

    let config = create_two_hop_config("prepare-test", 10);

    let result = manager
        .handle_prepare_request("prepare-test", config, "node-a")
        .await;
    assert!(result.is_ok());
    assert!(manager.chain_exists("prepare-test"));
}

#[tokio::test]
async fn test_handle_prepare_request_not_in_chain() {
    let manager = ChainManager::new("node-x".to_string()); // Not in the chain

    let config = create_two_hop_config("not-in-chain", 10);

    let result = manager
        .handle_prepare_request("not-in-chain", config, "node-a")
        .await;
    assert!(matches!(result, Err(ChainError::NotInChain)));
}

#[tokio::test]
async fn test_handle_prepare_request_invalid_config() {
    let manager = ChainManager::new("node-b".to_string());

    let mut config = create_two_hop_config("invalid-prepare", 0);
    config.exit_egress = "direct".to_string(); // Invalid

    let result = manager
        .handle_prepare_request("invalid-prepare", config, "node-a")
        .await;
    assert!(matches!(result, Err(ChainError::DirectNotAllowed)));
}

#[tokio::test]
async fn test_handle_commit_request_success() {
    let manager = ChainManager::new("node-b".to_string());
    manager.set_routing_callback(Arc::new(NoOpRoutingCallback));

    let config = create_two_hop_config("commit-test", 10);

    // First prepare
    manager
        .handle_prepare_request("commit-test", config, "node-a")
        .await
        .unwrap();

    // Then commit
    let result = manager
        .handle_commit_request("commit-test", "node-a")
        .await;
    assert!(result.is_ok());

    let status = manager.get_chain_status("commit-test").unwrap();
    assert_eq!(status.state, ChainState::Active);
}

#[tokio::test]
async fn test_handle_commit_request_not_prepared() {
    let manager = ChainManager::new("node-b".to_string());

    let result = manager
        .handle_commit_request("not-prepared", "node-a")
        .await;
    assert!(matches!(result, Err(ChainError::NotFound(_))));
}

#[tokio::test]
async fn test_handle_abort_request_after_prepare() {
    let manager = ChainManager::new("node-b".to_string());

    let config = create_two_hop_config("abort-test", 10);

    manager
        .handle_prepare_request("abort-test", config, "node-a")
        .await
        .unwrap();

    let result = manager
        .handle_abort_request("abort-test", "node-a")
        .await;
    assert!(result.is_ok());

    // Chain should be removed
    assert!(!manager.chain_exists("abort-test"));
}

#[tokio::test]
async fn test_handle_abort_request_nonexistent() {
    let manager = ChainManager::new("node-b".to_string());

    // Should succeed silently for nonexistent chain
    let result = manager
        .handle_abort_request("nonexistent", "node-a")
        .await;
    assert!(result.is_ok());
}

// ============================================================================
// SECTION 7: Multi-Hop Scenario Tests (15 tests)
// ============================================================================

#[tokio::test]
async fn test_multi_hop_two_nodes() {
    let entry_manager = ChainManager::new("node-a".to_string());
    let terminal_manager = ChainManager::new("node-b".to_string());

    entry_manager.set_routing_callback(Arc::new(NoOpRoutingCallback));
    terminal_manager.set_routing_callback(Arc::new(NoOpRoutingCallback));

    let config = create_two_hop_config("two-node-chain", 15);

    // Entry node creates chain
    let dscp = entry_manager.create_chain(config.clone()).await.unwrap();
    assert_eq!(dscp, 15);

    // Terminal node receives PREPARE
    terminal_manager
        .handle_prepare_request("two-node-chain", config, "node-a")
        .await
        .unwrap();

    // Both should have the chain
    assert!(entry_manager.chain_exists("two-node-chain"));
    assert!(terminal_manager.chain_exists("two-node-chain"));

    // Roles should be correct
    assert_eq!(
        entry_manager.get_chain_role("two-node-chain"),
        Some(ChainRole::Entry)
    );
    assert_eq!(
        terminal_manager.get_chain_role("two-node-chain"),
        Some(ChainRole::Terminal)
    );
}

#[tokio::test]
async fn test_multi_hop_three_nodes() {
    let entry_manager = ChainManager::new("node-a".to_string());
    let relay_manager = ChainManager::new("node-b".to_string());
    let terminal_manager = ChainManager::new("node-c".to_string());

    let config = create_three_hop_config("three-node-chain", 20);

    // All nodes receive the config via PREPARE
    entry_manager.create_chain(config.clone()).await.unwrap();
    relay_manager
        .handle_prepare_request("three-node-chain", config.clone(), "node-a")
        .await
        .unwrap();
    terminal_manager
        .handle_prepare_request("three-node-chain", config, "node-a")
        .await
        .unwrap();

    // Verify roles
    assert_eq!(
        entry_manager.get_chain_role("three-node-chain"),
        Some(ChainRole::Entry)
    );
    assert_eq!(
        relay_manager.get_chain_role("three-node-chain"),
        Some(ChainRole::Relay)
    );
    assert_eq!(
        terminal_manager.get_chain_role("three-node-chain"),
        Some(ChainRole::Terminal)
    );
}

#[tokio::test]
async fn test_multi_hop_mixed_tunnel_types() {
    let manager = ChainManager::new("node-a".to_string());

    let config = ChainConfig {
        tag: "mixed-tunnel".to_string(),
        description: "Mixed tunnel types".to_string(),
        dscp_value: 0,
        hops: vec![
            ChainHop {
                node_tag: "node-a".to_string(),
                role: ChainRole::Entry,
                tunnel_type: TunnelType::WireGuard,
            },
            ChainHop {
                node_tag: "node-b".to_string(),
                role: ChainRole::Relay,
                tunnel_type: TunnelType::WireGuard, // Must be WireGuard for relay
            },
            ChainHop {
                node_tag: "node-c".to_string(),
                role: ChainRole::Terminal,
                tunnel_type: TunnelType::Xray, // Can be Xray for terminal
            },
        ],
        rules: vec![],
        exit_egress: "pia-us-east".to_string(),
        allow_transitive: false,
    };

    let result = manager.create_chain(config).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_multi_hop_transitive_mode() {
    let manager = ChainManager::new("node-a".to_string());

    let config = ChainConfig {
        tag: "transitive-chain".to_string(),
        description: "Transitive chain".to_string(),
        dscp_value: 0,
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
        exit_egress: "remote-egress".to_string(),
        allow_transitive: true, // Skip remote egress validation
    };

    let result = manager.create_chain(config).await;
    assert!(result.is_ok());

    let retrieved = manager.get_chain_config("transitive-chain").unwrap();
    assert!(retrieved.allow_transitive);
}

#[tokio::test]
async fn test_multi_hop_chain_isolation() {
    let manager = ChainManager::new("node-a".to_string());

    // Create multiple chains
    for i in 0..5 {
        let config = create_two_hop_config(&format!("chain-{}", i), 0);
        manager.create_chain(config).await.unwrap();
    }

    // Each chain should have independent DSCP
    let chains = manager.list_chains();
    let dscp_values: std::collections::HashSet<u8> =
        chains.iter().map(|c| c.dscp_value).collect();
    assert_eq!(dscp_values.len(), 5);
}

// ============================================================================
// SECTION 8: Error Handling and Edge Cases (15 tests)
// ============================================================================

#[test]
fn test_chain_error_display() {
    assert!(ChainError::NotFound("test".to_string())
        .to_string()
        .contains("test"));
    assert!(ChainError::DirectNotAllowed
        .to_string()
        .contains("direct"));
    assert!(ChainError::XrayRelayNotAllowed
        .to_string()
        .contains("Xray"));
    assert!(ChainError::TooManyHops(11).to_string().contains("11"));
    assert!(ChainError::DscpExhausted
        .to_string()
        .contains("available"));
}

#[test]
fn test_dscp_error_display() {
    assert!(DscpError::EmptyPacket.to_string().contains("Empty"));
    assert!(DscpError::PacketTooShort(5, 20)
        .to_string()
        .contains("5"));
    assert!(DscpError::InvalidIpVersion(7).to_string().contains("7"));
    assert!(DscpError::InvalidDscpValue(64)
        .to_string()
        .contains("64"));
}

#[test]
fn test_allocator_error_display() {
    assert!(DscpAllocatorError::Exhausted
        .to_string()
        .contains("available"));
    assert!(DscpAllocatorError::AlreadyAllocated(42)
        .to_string()
        .contains("42"));
    assert!(DscpAllocatorError::Reserved(46)
        .to_string()
        .contains("46"));
    assert!(DscpAllocatorError::OutOfRange(64)
        .to_string()
        .contains("64"));
}

#[tokio::test]
async fn test_chain_with_special_characters_in_description() {
    let manager = ChainManager::new("node-a".to_string());

    let mut config = create_two_hop_config("special-desc", 0);
    config.description = "Chain with <special> & \"characters\"".to_string();

    let result = manager.create_chain(config).await;
    assert!(result.is_ok());

    let retrieved = manager.get_chain_config("special-desc").unwrap();
    assert_eq!(
        retrieved.description,
        "Chain with <special> & \"characters\""
    );
}

#[tokio::test]
async fn test_chain_with_long_tag() {
    let manager = ChainManager::new("node-a".to_string());

    let long_tag = "a".repeat(64); // Max allowed length
    let mut config = create_two_hop_config(&long_tag, 0);
    config.tag = long_tag.clone();

    let result = manager.create_chain(config).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_chain_concurrent_creation() {
    use std::sync::Arc;
    use tokio::task::JoinSet;

    let manager = Arc::new(ChainManager::new("node-a".to_string()));
    let mut set = JoinSet::new();

    for i in 0..10 {
        let mgr = manager.clone();
        set.spawn(async move {
            let config = create_two_hop_config(&format!("concurrent-{}", i), 0);
            mgr.create_chain(config).await
        });
    }

    let mut successes = 0;
    while let Some(result) = set.join_next().await {
        if result.unwrap().is_ok() {
            successes += 1;
        }
    }

    // All should succeed with unique DSCP values
    assert_eq!(successes, 10);
    assert_eq!(manager.chain_count(), 10);
}

#[test]
fn test_chain_state_serialization() {
    let states = vec![
        ChainState::Inactive,
        ChainState::Activating,
        ChainState::Active,
        ChainState::Error,
    ];

    for state in states {
        let json = serde_json::to_string(&state).unwrap();
        let decoded: ChainState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, decoded);
    }
}

#[test]
fn test_chain_config_serialization_roundtrip() {
    let config = create_three_hop_config("serialize-test", 42);

    let json = serde_json::to_string(&config).unwrap();
    let decoded: ChainConfig = serde_json::from_str(&json).unwrap();

    assert_eq!(decoded.tag, config.tag);
    assert_eq!(decoded.dscp_value, config.dscp_value);
    assert_eq!(decoded.hops.len(), config.hops.len());
    assert_eq!(decoded.exit_egress, config.exit_egress);
}

#[tokio::test]
async fn test_chain_with_empty_rules() {
    let manager = ChainManager::new("node-a".to_string());

    let config = ChainConfig {
        tag: "empty-rules".to_string(),
        description: "Chain with empty rules".to_string(),
        dscp_value: 0,
        hops: vec![ChainHop {
            node_tag: "node-a".to_string(),
            role: ChainRole::Terminal,
            tunnel_type: TunnelType::WireGuard,
        }],
        rules: vec![], // Explicitly empty
        exit_egress: "pia-us-east".to_string(),
        allow_transitive: false,
    };

    let result = manager.create_chain(config).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_chain_with_rules() {
    let manager = ChainManager::new("node-a".to_string());

    let config = ChainConfig {
        tag: "with-rules".to_string(),
        description: "Chain with rules".to_string(),
        dscp_value: 0,
        hops: vec![ChainHop {
            node_tag: "node-a".to_string(),
            role: ChainRole::Terminal,
            tunnel_type: TunnelType::WireGuard,
        }],
        rules: vec!["rule-1".to_string(), "rule-2".to_string()],
        exit_egress: "pia-us-east".to_string(),
        allow_transitive: false,
    };

    let result = manager.create_chain(config).await;
    assert!(result.is_ok());

    let retrieved = manager.get_chain_config("with-rules").unwrap();
    assert_eq!(retrieved.rules.len(), 2);
}

// ============================================================================
// SECTION 9: Additional Tests (Review Findings)
// ============================================================================

#[tokio::test]
async fn test_chain_invalid_description_too_long() {
    let manager = ChainManager::new("node-a".to_string());

    let mut config = create_two_hop_config("long-desc-chain", 0);
    // Description > 256 characters should be rejected
    config.description = "a".repeat(1025);

    let result = manager.create_chain(config).await;
    assert!(matches!(result, Err(ChainError::InvalidDescription(_))));
}

#[tokio::test]
async fn test_dscp_exhaustion() {
    let allocator = Arc::new(DscpAllocator::new());
    let manager = ChainManager::with_allocator("node-a".to_string(), allocator.clone());

    // DSCP values 1-63 are available for allocation (63 values total)
    // Some are reserved for QoS but we'll allocate until exhaustion
    // Allocate chains until we hit exhaustion
    let mut i = 0;
    loop {
        let config = create_two_hop_config(&format!("exhaust-chain-{}", i), 0);
        let result = manager.create_chain(config).await;
        match result {
            Ok(_) => {
                i += 1;
                // Safety limit to prevent infinite loop
                assert!(i <= 63, "Allocated more than 63 DSCP values!");
            }
            Err(ChainError::DscpExhausted) => {
                // Expected - we exhausted the allocator
                break;
            }
            Err(e) => {
                panic!("Unexpected error during chain creation: {:?}", e);
            }
        }
    }

    // Verify we allocated a reasonable number (at least 40, max 63)
    // The exact number depends on RESERVED_DSCP count
    assert!(
        i >= 40,
        "Expected to allocate at least 40 chains, got {}",
        i
    );

    // Verify we can't allocate any more
    let config = create_two_hop_config("one-more-chain", 0);
    let result = manager.create_chain(config).await;
    assert!(
        matches!(result, Err(ChainError::DscpExhausted)),
        "Expected DscpExhausted error on second attempt, got {:?}", result
    );
}

#[tokio::test]
async fn test_concurrent_chain_activation() {
    use std::sync::Arc;
    use tokio::task::JoinSet;

    let manager = Arc::new(ChainManager::new("node-a".to_string()));
    manager.set_routing_callback(Arc::new(NoOpRoutingCallback));

    // Create a chain first
    let config = create_two_hop_config("concurrent-activate", 0);
    manager.create_chain(config).await.unwrap();

    // Try to activate from multiple tasks concurrently
    let mut set = JoinSet::new();

    for _ in 0..5 {
        let mgr = manager.clone();
        set.spawn(async move {
            mgr.activate_chain("concurrent-activate").await
        });
    }

    let mut success_count = 0;
    let mut already_active_count = 0;
    let mut already_activating_count = 0;

    while let Some(result) = set.join_next().await {
        match result.unwrap() {
            Ok(()) => success_count += 1,
            Err(ChainError::AlreadyActive(_)) => already_active_count += 1,
            Err(ChainError::AlreadyActivating(_)) => already_activating_count += 1,
            Err(e) => panic!("Unexpected error: {:?}", e),
        }
    }

    // Exactly one should succeed, others should get AlreadyActive or AlreadyActivating
    assert_eq!(success_count, 1, "Exactly one activation should succeed");
    assert_eq!(
        already_active_count + already_activating_count + success_count,
        5,
        "All activations should complete"
    );
}

// Note: Tests for recover_orphaned_chains() are in the unit test module
// (src/chain/manager.rs) because they require access to the private
// update_chain_state() method to simulate orphaned chains.
// The integration tests below verify recovery behavior from the public API.

#[tokio::test]
async fn test_recover_orphaned_chains_empty_manager() {
    // Recovery on an empty manager should succeed and return 0
    let manager = ChainManager::new("node-a".to_string());
    let recovered = manager.recover_orphaned_chains();
    assert_eq!(recovered, 0);
}

#[tokio::test]
async fn test_recover_chains_in_normal_states() {
    let manager = ChainManager::new("node-a".to_string());

    // Create chains in normal states (Inactive, Active, Error)
    let config1 = create_two_hop_config("inactive-chain", 10);
    manager.create_chain(config1).await.unwrap();

    let config2 = create_two_hop_config("active-chain", 20);
    manager.create_chain(config2).await.unwrap();
    manager.set_routing_callback(Arc::new(NoOpRoutingCallback));
    manager.activate_chain("active-chain").await.unwrap();

    // Use failing callback to create an error state chain
    let failing_callback = Arc::new(TrackingRoutingCallback::new());
    failing_callback.set_fail_setup(true);
    manager.set_routing_callback(failing_callback);

    let config3 = create_two_hop_config("error-chain", 30);
    manager.create_chain(config3).await.unwrap();
    let _ = manager.activate_chain("error-chain").await; // This will fail

    // Recover should not affect chains in normal states
    let recovered = manager.recover_orphaned_chains();
    assert_eq!(recovered, 0);

    // Verify states are unchanged
    let status1 = manager.get_chain_status("inactive-chain").unwrap();
    assert_eq!(status1.state, ChainState::Inactive);

    let status2 = manager.get_chain_status("active-chain").unwrap();
    assert_eq!(status2.state, ChainState::Active);

    let status3 = manager.get_chain_status("error-chain").unwrap();
    assert_eq!(status3.state, ChainState::Error);
}
