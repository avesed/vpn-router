//! Phase 6 Pairing Integration Tests
//!
//! Integration tests for the offline pairing protocol and peer management.
//!
//! # Test Categories
//!
//! - Pairing code generation
//! - Pairing code import
//! - Bidirectional pairing
//! - Handshake completion
//! - Error handling
//!
//! # Phase 6 Implementation Status
//!
//! These tests are placeholders that will be implemented as Phase 6
//! features are completed.

use rust_router::peer::{
    PairRequest, PairRequestConfig, PairResponse, PeerManager,
    TunnelPortAllocator, TunnelIpAllocator, HealthChecker,
};
use rust_router::ipc::TunnelType;

// ============================================================================
// Port Allocator Tests
// ============================================================================

#[test]
fn test_port_allocator_basic() {
    let allocator = TunnelPortAllocator::new(36200, 36204);

    let port1 = allocator.allocate().expect("Should allocate first port");
    let port2 = allocator.allocate().expect("Should allocate second port");

    assert_ne!(port1, port2);
    assert!(port1 >= 36200 && port1 <= 36204);
    assert!(port2 >= 36200 && port2 <= 36204);
}

#[test]
fn test_port_allocator_exhaustion() {
    let allocator = TunnelPortAllocator::new(36200, 36201);

    allocator.allocate().expect("First allocation");
    allocator.allocate().expect("Second allocation");

    // Third allocation should fail
    let result = allocator.allocate();
    assert!(result.is_err());
}

#[test]
fn test_port_allocator_release() {
    let allocator = TunnelPortAllocator::new(36200, 36200);

    let port = allocator.allocate().expect("First allocation");
    allocator.release(port);

    // Should be able to allocate again
    let port2 = allocator.allocate().expect("Second allocation");
    assert_eq!(port, port2);
}

// ============================================================================
// IP Allocator Tests
// ============================================================================

#[test]
fn test_ip_allocator_basic() {
    let allocator = TunnelIpAllocator::new("10.200.200.0/24");

    let ip1 = allocator.allocate().expect("Should allocate first IP");
    let ip2 = allocator.allocate().expect("Should allocate second IP");

    assert_ne!(ip1, ip2);
}

#[test]
fn test_ip_allocator_pair() {
    let allocator = TunnelIpAllocator::new("10.200.200.0/24");

    let (local_ip, remote_ip) = allocator.allocate_pair().expect("Should allocate pair");

    assert_ne!(local_ip, remote_ip);
    assert!(allocator.is_allocated(local_ip));
    assert!(allocator.is_allocated(remote_ip));
}

// ============================================================================
// Health Checker Tests
// ============================================================================

#[test]
fn test_health_checker_threshold() {
    let checker = HealthChecker::new(3);

    // First two failures don't exceed threshold
    assert!(!checker.record_failure("peer-1"));
    assert!(!checker.record_failure("peer-1"));

    // Third failure exceeds threshold
    assert!(checker.record_failure("peer-1"));
    assert!(checker.is_unhealthy("peer-1"));
}

#[test]
fn test_health_checker_success_resets() {
    let checker = HealthChecker::new(3);

    checker.record_failure("peer-1");
    checker.record_failure("peer-1");

    // Success resets counter
    checker.record_success("peer-1");
    assert_eq!(checker.get_failure_count("peer-1"), 0);
    assert!(!checker.is_unhealthy("peer-1"));
}

// ============================================================================
// Peer Manager Tests
// ============================================================================

#[test]
fn test_peer_manager_creation() {
    let manager = PeerManager::new("test-node".to_string());
    assert_eq!(manager.local_node_tag(), "test-node");
}

#[test]
fn test_peer_manager_list_empty() {
    let manager = PeerManager::new("test-node".to_string());
    let peers = manager.list_peers();
    assert!(peers.is_empty());
}

// ============================================================================
// Pairing Protocol Tests (Placeholders)
// ============================================================================

#[test]
#[ignore = "Phase 6.5: Pairing not yet implemented"]
fn test_pairing_request_generation() {
    let manager = PeerManager::new("local-node".to_string());

    let _code = manager.generate_pair_request(PairRequestConfig {
        local_tag: "local-node".to_string(),
        local_description: "Local Node".to_string(),
        local_endpoint: "192.168.1.1:36200".to_string(),
        local_api_port: 36000,
        bidirectional: false,
        tunnel_type: TunnelType::WireGuard,
    }).expect("Should generate pairing code");
}

#[test]
#[ignore = "Phase 6.5: Pairing not yet implemented"]
fn test_pairing_bidirectional() {
    let _manager_a = PeerManager::new("node-a".to_string());
    let _manager_b = PeerManager::new("node-b".to_string());

    // TODO: Test bidirectional pairing flow
    // 1. Node A generates request with bidirectional=true
    // 2. Node B imports request and generates response
    // 3. Node A completes handshake
    // 4. Both nodes should have tunnel configured
}

#[test]
#[ignore = "Phase 6.5: Pairing not yet implemented"]
fn test_pairing_invalid_code() {
    let _manager = PeerManager::new("test-node".to_string());

    // Invalid Base64 should fail
    // let result = manager.import_pair_request("invalid-code", config);
    // assert!(result.is_err());
}

// ============================================================================
// Tunnel Type Validation Tests
// ============================================================================

#[test]
fn test_tunnel_type_serialization() {
    let wireguard = TunnelType::WireGuard;
    let xray = TunnelType::Xray;

    let json_wg = serde_json::to_string(&wireguard).expect("Serialize WireGuard");
    let json_xray = serde_json::to_string(&xray).expect("Serialize Xray");

    assert_eq!(json_wg, "\"wire_guard\"");
    assert_eq!(json_xray, "\"xray\"");
}

// ============================================================================
// Pairing Struct Tests
// ============================================================================

#[test]
fn test_pair_request_serialization() {
    let request = PairRequest {
        version: 2,
        node_tag: "test-node".to_string(),
        node_description: "Test Node".to_string(),
        endpoint: "192.168.1.1:36200".to_string(),
        api_port: 36000,
        tunnel_type: TunnelType::WireGuard,
        timestamp: 1704672000,
        bidirectional: false,
        wg_public_key: Some("test-key".to_string()),
        tunnel_ip: Some("10.200.200.1".to_string()),
        remote_wg_private_key: None,
        remote_wg_public_key: None,
        xray_uuid: None,
        xray_server_name: None,
        xray_public_key: None,
        xray_short_id: None,
    };

    let json = serde_json::to_string(&request).expect("Should serialize");
    let decoded: PairRequest = serde_json::from_str(&json).expect("Should deserialize");

    assert_eq!(decoded.node_tag, "test-node");
    assert_eq!(decoded.version, 2);
}

#[test]
fn test_pair_response_serialization() {
    let response = PairResponse {
        version: 2,
        request_node_tag: "request-node".to_string(),
        node_tag: "response-node".to_string(),
        node_description: "Response Node".to_string(),
        endpoint: "192.168.1.2:36201".to_string(),
        api_port: 36000,
        tunnel_type: TunnelType::WireGuard,
        timestamp: 1704672000,
        wg_public_key: Some("response-key".to_string()),
        tunnel_local_ip: Some("10.200.200.2".to_string()),
        tunnel_remote_ip: Some("10.200.200.1".to_string()),
        tunnel_api_endpoint: Some("10.200.200.2:36000".to_string()),
        xray_uuid: None,
    };

    let json = serde_json::to_string(&response).expect("Should serialize");
    let decoded: PairResponse = serde_json::from_str(&json).expect("Should deserialize");

    assert_eq!(decoded.node_tag, "response-node");
    assert_eq!(decoded.request_node_tag, "request-node");
}
