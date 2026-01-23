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
    decode_pair_request, PairRequest, PairRequestConfig, PairResponse, PeerManager,
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
// Pairing Protocol Tests
// ============================================================================

#[test]
fn test_pairing_request_generation() {
    let manager = PeerManager::new("local-node".to_string());

    let code = manager.generate_pair_request(PairRequestConfig {
        local_tag: "local-node".to_string(),
        local_description: "Local Node".to_string(),
        local_endpoint: "192.168.1.1:36200".to_string(),
        local_api_port: 36000,
        bidirectional: false,
        tunnel_type: TunnelType::WireGuard,
    }).expect("Should generate pairing code");

    // Verify code is valid Base64
    assert!(!code.code.is_empty());
    assert!(code.code.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '='));

    // Decode and verify content
    use rust_router::peer::decode_pair_request;
    let request = decode_pair_request(&code.code).expect("Should decode pairing code");
    assert_eq!(request.node_tag, "local-node");
    assert_eq!(request.api_port, 36000);
    assert!(!request.bidirectional);
}

#[tokio::test]
async fn test_pairing_bidirectional() {
    let manager_a = PeerManager::new("node-a".to_string());
    let manager_b = PeerManager::new("node-b".to_string());

    // Step 1: Node A generates request with bidirectional=true
    let request_code = manager_a.generate_pair_request(PairRequestConfig {
        local_tag: "node-a".to_string(),
        local_description: "Node A".to_string(),
        local_endpoint: "192.168.1.1:36200".to_string(),
        local_api_port: 36000,
        bidirectional: true,
        tunnel_type: TunnelType::WireGuard,
    }).expect("Should generate pairing request");

    // Step 2: Node B imports request and generates response
    let response_result = manager_b.import_pair_request(
        &request_code.code,
        PairRequestConfig {
            local_tag: "node-b".to_string(),
            local_description: "Node B".to_string(),
            local_endpoint: "192.168.1.2:36201".to_string(),
            local_api_port: 36000,
            bidirectional: true,
            tunnel_type: TunnelType::WireGuard,
        },
    ).await.expect("Should import pairing request");

    // Node B should now have node-a as a peer
    assert!(manager_b.peer_exists("node-a"));

    // Step 3: Node A completes handshake
    manager_a.complete_handshake(&response_result.response_code)
        .await
        .expect("Should complete handshake");

    // Node A should now have node-b as a peer
    assert!(manager_a.peer_exists("node-b"));

    // Verify both peers are configured
    let peer_a_on_b = manager_b.get_peer_config("node-a").expect("Node A should exist on B");
    let peer_b_on_a = manager_a.get_peer_config("node-b").expect("Node B should exist on A");

    assert_eq!(peer_a_on_b.tunnel_type, TunnelType::WireGuard);
    assert_eq!(peer_b_on_a.tunnel_type, TunnelType::WireGuard);
}

#[tokio::test]
async fn test_pairing_invalid_code() {
    let manager = PeerManager::new("test-node".to_string());

    // Invalid Base64 should fail
    let result = manager.import_pair_request(
        "not-valid-base64!!!",
        PairRequestConfig {
            local_tag: "test-node".to_string(),
            local_description: "Test Node".to_string(),
            local_endpoint: "192.168.1.1:36200".to_string(),
            local_api_port: 36000,
            bidirectional: false,
            tunnel_type: TunnelType::WireGuard,
        },
    ).await;

    assert!(result.is_err());
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

    // Phase 11-Fix.AC: TunnelType uses "wireguard" for REST API compatibility
    assert_eq!(json_wg, "\"wireguard\"");
    assert_eq!(json_xray, "\"xray\"");
}

// ============================================================================
// Pairing Struct Tests
// ============================================================================

#[test]
fn test_pair_request_serialization() {
    let request = PairRequest {
        message_type: "pair_request".to_string(),
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
        remote_tunnel_ip: None,
        remote_wg_private_key: None,
        remote_wg_public_key: None,
        xray_uuid: None,
        xray_server_name: None,
        xray_public_key: None,
        xray_short_id: None,
    };

    let json = serde_json::to_string(&request).expect("Should serialize");
    // Verify type field is serialized as "type" (not "message_type")
    assert!(json.contains("\"type\":\"pair_request\""));

    let decoded: PairRequest = serde_json::from_str(&json).expect("Should deserialize");

    assert_eq!(decoded.node_tag, "test-node");
    assert_eq!(decoded.version, 2);
    assert_eq!(decoded.message_type, "pair_request");
}

#[test]
fn test_pair_response_serialization() {
    let response = PairResponse {
        message_type: "pair_response".to_string(),
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
    // Verify type field is serialized as "type" (not "message_type")
    assert!(json.contains("\"type\":\"pair_response\""));

    let decoded: PairResponse = serde_json::from_str(&json).expect("Should deserialize");

    assert_eq!(decoded.node_tag, "response-node");
    assert_eq!(decoded.request_node_tag, "request-node");
    assert_eq!(decoded.message_type, "pair_response");
}

// ============================================================================
// Phase 6.11 - Xray Pairing Tests
// ============================================================================

/// Test Xray tunnel pairing request generation
///
/// Xray tunnels use SOCKS5 bridge for connectivity, requiring different
/// configuration fields than WireGuard tunnels.
#[test]
fn test_xray_pairing_request_generation() {
    let manager = PeerManager::new("xray-node".to_string());

    let code = manager.generate_pair_request(PairRequestConfig {
        local_tag: "xray-node".to_string(),
        local_description: "Xray Test Node".to_string(),
        local_endpoint: "192.168.1.1:443".to_string(),
        local_api_port: 36000,
        bidirectional: false,
        tunnel_type: TunnelType::Xray,
    }).expect("Should generate Xray pairing code");

    // Verify code is valid Base64
    assert!(!code.code.is_empty());

    // Decode and verify content
    let request = decode_pair_request(&code.code).expect("Should decode pairing code");
    assert_eq!(request.node_tag, "xray-node");
    assert_eq!(request.tunnel_type, TunnelType::Xray);
    // Xray requests still include WG public key for hybrid scenarios
    assert!(request.wg_public_key.is_some());
}

/// Test Xray tunnel type serialization/deserialization
#[test]
fn test_xray_tunnel_type_serde() {
    let xray = TunnelType::Xray;
    let wireguard = TunnelType::WireGuard;

    // Serialize
    let xray_json = serde_json::to_string(&xray).expect("Serialize Xray");
    let wg_json = serde_json::to_string(&wireguard).expect("Serialize WireGuard");

    assert_eq!(xray_json, "\"xray\"");
    // Phase 11-Fix.AC: TunnelType uses "wireguard" for REST API compatibility
    assert_eq!(wg_json, "\"wireguard\"");

    // Deserialize
    let decoded_xray: TunnelType = serde_json::from_str(&xray_json).expect("Deserialize Xray");
    let decoded_wg: TunnelType = serde_json::from_str(&wg_json).expect("Deserialize WireGuard");

    assert_eq!(decoded_xray, TunnelType::Xray);
    assert_eq!(decoded_wg, TunnelType::WireGuard);
}

/// Test PairRequest with Xray-specific fields
#[test]
fn test_xray_pair_request_fields() {
    let request = PairRequest {
        message_type: "pair_request".to_string(),
        version: 2,
        node_tag: "xray-peer".to_string(),
        node_description: "Xray Peer Node".to_string(),
        endpoint: "example.com:443".to_string(),
        api_port: 36000,
        tunnel_type: TunnelType::Xray,
        timestamp: 1704672000,
        bidirectional: false,
        wg_public_key: None,
        tunnel_ip: None,
        remote_tunnel_ip: None,
        remote_wg_private_key: None,
        remote_wg_public_key: None,
        xray_uuid: Some("550e8400-e29b-41d4-a716-446655440000".to_string()),
        xray_server_name: Some("example.com".to_string()),
        xray_public_key: Some("some-reality-public-key".to_string()),
        xray_short_id: Some("abc123".to_string()),
    };

    let json = serde_json::to_string(&request).expect("Should serialize");
    let decoded: PairRequest = serde_json::from_str(&json).expect("Should deserialize");

    assert_eq!(decoded.tunnel_type, TunnelType::Xray);
    assert_eq!(decoded.xray_uuid, Some("550e8400-e29b-41d4-a716-446655440000".to_string()));
    assert_eq!(decoded.xray_server_name, Some("example.com".to_string()));
    assert_eq!(decoded.xray_public_key, Some("some-reality-public-key".to_string()));
    assert_eq!(decoded.xray_short_id, Some("abc123".to_string()));
}

// ============================================================================
// Phase 6.11 - Enhanced Validation Tests
// ============================================================================

/// Test that pairing request validation rejects empty tags
#[test]
fn test_pairing_validation_empty_tag() {
    let manager = PeerManager::new("test-node".to_string());

    let result = manager.generate_pair_request(PairRequestConfig {
        local_tag: "".to_string(), // Empty tag
        local_description: "Test Node".to_string(),
        local_endpoint: "192.168.1.1:36200".to_string(),
        local_api_port: 36000,
        bidirectional: false,
        tunnel_type: TunnelType::WireGuard,
    });

    assert!(result.is_err());
}

/// Test that pairing request validation rejects tags with invalid characters
#[test]
fn test_pairing_validation_invalid_tag_chars() {
    let manager = PeerManager::new("test-node".to_string());

    let result = manager.generate_pair_request(PairRequestConfig {
        local_tag: "node with spaces".to_string(), // Invalid characters
        local_description: "Test Node".to_string(),
        local_endpoint: "192.168.1.1:36200".to_string(),
        local_api_port: 36000,
        bidirectional: false,
        tunnel_type: TunnelType::WireGuard,
    });

    assert!(result.is_err());
}

/// Test that pairing request validation rejects invalid endpoints
#[test]
fn test_pairing_validation_invalid_endpoint() {
    let manager = PeerManager::new("test-node".to_string());

    // Test with invalid endpoint format
    let result = manager.generate_pair_request(PairRequestConfig {
        local_tag: "valid-tag".to_string(),
        local_description: "Test Node".to_string(),
        local_endpoint: "not-an-endpoint".to_string(), // Invalid format
        local_api_port: 36000,
        bidirectional: false,
        tunnel_type: TunnelType::WireGuard,
    });

    assert!(result.is_err());
}

/// Test that pairing request validation rejects overly long descriptions
#[test]
fn test_pairing_validation_long_description() {
    let manager = PeerManager::new("test-node".to_string());

    let result = manager.generate_pair_request(PairRequestConfig {
        local_tag: "valid-tag".to_string(),
        local_description: "a".repeat(1025), // Too long
        local_endpoint: "192.168.1.1:36200".to_string(),
        local_api_port: 36000,
        bidirectional: false,
        tunnel_type: TunnelType::WireGuard,
    });

    assert!(result.is_err());
}

/// Test import rejects truncated/corrupted pairing codes
#[tokio::test]
async fn test_pairing_import_truncated_code() {
    let manager = PeerManager::new("test-node".to_string());

    // Generate a valid code first
    let valid_code = manager.generate_pair_request(PairRequestConfig {
        local_tag: "source-node".to_string(),
        local_description: "Source Node".to_string(),
        local_endpoint: "192.168.1.1:36200".to_string(),
        local_api_port: 36000,
        bidirectional: false,
        tunnel_type: TunnelType::WireGuard,
    }).expect("Should generate code");

    // Truncate the code
    let truncated = &valid_code.code[..valid_code.code.len() / 2];

    let result = manager.import_pair_request(
        truncated,
        PairRequestConfig {
            local_tag: "dest-node".to_string(),
            local_description: "Dest Node".to_string(),
            local_endpoint: "192.168.1.2:36201".to_string(),
            local_api_port: 36000,
            bidirectional: false,
            tunnel_type: TunnelType::WireGuard,
        },
    ).await;

    assert!(result.is_err());
}

/// Test import rejects random garbage data
#[tokio::test]
async fn test_pairing_import_garbage_data() {
    let manager = PeerManager::new("test-node".to_string());

    let garbage_codes = vec![
        "!!garbage!!",
        "AAAA",
        "{}",
        "{\"invalid\":\"json\"}",
        "aGVsbG8gd29ybGQ=", // "hello world" in base64 - valid base64, invalid format
    ];

    for garbage in garbage_codes {
        let result = manager.import_pair_request(
            garbage,
            PairRequestConfig {
                local_tag: "test-node".to_string(),
                local_description: "Test Node".to_string(),
                local_endpoint: "192.168.1.1:36200".to_string(),
                local_api_port: 36000,
                bidirectional: false,
                tunnel_type: TunnelType::WireGuard,
            },
        ).await;

        assert!(result.is_err(), "Should reject garbage input: {}", garbage);
    }
}

// ============================================================================
// Phase 6.11 - Health Check Hysteresis Tests
// ============================================================================

/// Test that health checker requires consecutive failures before marking unhealthy
#[test]
fn test_health_check_hysteresis_consecutive_failures() {
    let checker = HealthChecker::new(3); // 3 consecutive failures threshold

    // Single failure should not mark unhealthy
    assert!(!checker.record_failure("peer-1"));
    assert!(!checker.is_unhealthy("peer-1"));

    // Second failure still not unhealthy
    assert!(!checker.record_failure("peer-1"));
    assert!(!checker.is_unhealthy("peer-1"));

    // Third failure crosses threshold
    assert!(checker.record_failure("peer-1"));
    assert!(checker.is_unhealthy("peer-1"));
}

/// Test that a success in the middle resets the failure count
#[test]
fn test_health_check_hysteresis_success_interruption() {
    let checker = HealthChecker::new(3);

    // Two failures
    checker.record_failure("peer-1");
    checker.record_failure("peer-1");
    assert_eq!(checker.get_failure_count("peer-1"), 2);

    // Success resets counter
    checker.record_success("peer-1");
    assert_eq!(checker.get_failure_count("peer-1"), 0);
    assert!(!checker.is_unhealthy("peer-1"));

    // Need 3 more consecutive failures
    checker.record_failure("peer-1");
    checker.record_failure("peer-1");
    assert!(!checker.is_unhealthy("peer-1")); // Only 2 consecutive

    checker.record_failure("peer-1");
    assert!(checker.is_unhealthy("peer-1")); // Now 3 consecutive
}

/// Test recovery from unhealthy state after success
#[test]
fn test_health_check_recovery_from_unhealthy() {
    let checker = HealthChecker::new(3);

    // Get to unhealthy state
    checker.record_failure("peer-1");
    checker.record_failure("peer-1");
    checker.record_failure("peer-1");
    assert!(checker.is_unhealthy("peer-1"));

    // Single success should clear unhealthy state
    checker.record_success("peer-1");
    assert!(!checker.is_unhealthy("peer-1"));
    assert_eq!(checker.get_failure_count("peer-1"), 0);
}

/// Test health checker with multiple peers
#[test]
fn test_health_check_multiple_peers_isolation() {
    let checker = HealthChecker::new(2);

    // Peer 1 hits threshold
    checker.record_failure("peer-1");
    checker.record_failure("peer-1");
    assert!(checker.is_unhealthy("peer-1"));

    // Peer 2 should be unaffected
    checker.record_failure("peer-2");
    assert!(!checker.is_unhealthy("peer-2"));

    // Peer 1 success should not affect peer 2's count
    checker.record_success("peer-1");
    assert!(!checker.is_unhealthy("peer-1"));
    assert_eq!(checker.get_failure_count("peer-2"), 1);
}

/// Test health checker with threshold of 1 (no hysteresis)
#[test]
fn test_health_check_threshold_one() {
    let checker = HealthChecker::new(1);

    // Single failure immediately marks unhealthy
    assert!(checker.record_failure("peer-1"));
    assert!(checker.is_unhealthy("peer-1"));

    // Recovery still works
    checker.record_success("peer-1");
    assert!(!checker.is_unhealthy("peer-1"));
}

/// Test health checker failure count persists across checks
#[test]
fn test_health_check_failure_count_persistence() {
    let checker = HealthChecker::new(5);

    for i in 1..=4 {
        checker.record_failure("peer-1");
        assert_eq!(checker.get_failure_count("peer-1"), i);
        assert!(!checker.is_unhealthy("peer-1"));
    }

    // 5th failure crosses threshold
    checker.record_failure("peer-1");
    assert_eq!(checker.get_failure_count("peer-1"), 5);
    assert!(checker.is_unhealthy("peer-1"));
}
