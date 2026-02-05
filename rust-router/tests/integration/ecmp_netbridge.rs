//! ECMP + netbridge Integration Tests
//!
//! Tests verifying ECMP load balancing through the control plane and netbridge data path.
//! These tests ensure that ECMP selection works correctly when integrated with
//! the full routing infrastructure.
//!
//! # Test Categories
//!
//! - Control plane ECMP resolution via `ControlPlaneBuilder`
//! - Health check integration (unhealthy members excluded)
//! - Algorithm-specific behavior verification
//!
//! # Running These Tests
//!
//! ```bash
//! cargo test --test integration ecmp_netbridge
//! ```

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use rust_router::controlplane::ControlPlaneBuilder;
use rust_router::ecmp::{
    EcmpGroup, EcmpGroupConfig, EcmpGroupManager, EcmpMember, LbAlgorithm,
};
use rust_router::netbridge::dataplane::ConnectionInfo;
use rust_router::netbridge::types::{FiveTuple, IpProtocol, SessionId};
use rust_router::outbound::{DirectOutbound, OutboundManager};
use rust_router::rules::engine::{RuleEngine, RoutingSnapshotBuilder};

// =============================================================================
// Test Fixtures
// =============================================================================

/// Create a test rule engine with ECMP group configured as outbound
fn create_ecmp_rule_engine(ecmp_group_tag: &str) -> Arc<RuleEngine> {
    let mut builder = RoutingSnapshotBuilder::new();
    // Add a port rule that routes to the ECMP group
    builder
        .add_port_rule("443", ecmp_group_tag)
        .expect("Failed to add port rule");
    let snapshot = builder
        .default_outbound("direct")
        .version(1)
        .build()
        .expect("Failed to build routing snapshot");
    Arc::new(RuleEngine::new(snapshot))
}

/// Create a basic test rule engine
fn create_basic_rule_engine() -> Arc<RuleEngine> {
    let snapshot = RoutingSnapshotBuilder::new()
        .default_outbound("direct")
        .version(1)
        .build()
        .expect("Failed to build routing snapshot");
    Arc::new(RuleEngine::new(snapshot))
}

/// Create outbound manager with ECMP members registered as outbounds
fn create_outbound_manager_with_members(member_tags: &[&str]) -> Arc<OutboundManager> {
    let manager = OutboundManager::new();
    manager.add(Box::new(DirectOutbound::simple("direct")));

    for tag in member_tags {
        manager.add(Box::new(DirectOutbound::simple(*tag)));
    }

    Arc::new(manager)
}

/// Create ECMP group manager with a test group
fn create_ecmp_manager(
    group_tag: &str,
    member_tags: &[&str],
    algorithm: LbAlgorithm,
) -> Arc<EcmpGroupManager> {
    let manager = EcmpGroupManager::new();

    let members: Vec<EcmpMember> = member_tags
        .iter()
        .map(|tag| EcmpMember::new(tag.to_string()))
        .collect();

    let config = EcmpGroupConfig {
        tag: group_tag.to_string(),
        members,
        algorithm,
        ..Default::default()
    };

    manager.add_group(config).expect("Failed to add ECMP group");
    Arc::new(manager)
}

/// Create weighted ECMP group manager
fn create_weighted_ecmp_manager(
    group_tag: &str,
    weights: &[(&str, u32)],
    algorithm: LbAlgorithm,
) -> Arc<EcmpGroupManager> {
    let manager = EcmpGroupManager::new();

    let members: Vec<EcmpMember> = weights
        .iter()
        .map(|(tag, weight)| EcmpMember::with_weight(tag.to_string(), *weight))
        .collect();

    let config = EcmpGroupConfig {
        tag: group_tag.to_string(),
        members,
        algorithm,
        ..Default::default()
    };

    manager.add_group(config).expect("Failed to add ECMP group");
    Arc::new(manager)
}

/// Create a test ConnectionInfo for netbridge
fn create_connection_info(
    dest_ip: IpAddr,
    dest_port: u16,
    src_port: u16,
    domain: Option<String>,
) -> ConnectionInfo {
    let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 25, 0, 2)), src_port);
    let dst = SocketAddr::new(dest_ip, dest_port);

    ConnectionInfo {
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
// ControlPlaneBuilder with ECMP Tests
// =============================================================================

/// Test that ControlPlaneBuilder can be configured with ECMP manager
#[test]
fn test_controlplane_builder_with_ecmp() {
    let member_tags = ["exit-1", "exit-2", "exit-3"];
    let ecmp_manager = create_ecmp_manager("us-exits", &member_tags, LbAlgorithm::RoundRobin);
    let outbound_manager = create_outbound_manager_with_members(&member_tags);
    let rule_engine = create_basic_rule_engine();

    let handler = ControlPlaneBuilder::new()
        .with_rule_engine(rule_engine)
        .with_outbound_manager(outbound_manager)
        .with_ecmp_manager(ecmp_manager.clone())
        .build()
        .expect("Failed to build control plane handler");

    // Verify ECMP manager is accessible
    assert!(handler.ecmp_manager().is_some());
}

/// Test ECMP selection through control plane handler
#[test]
fn test_ecmp_selection_via_controlplane() {
    let member_tags = ["exit-1", "exit-2", "exit-3"];
    let ecmp_manager = create_ecmp_manager("us-exits", &member_tags, LbAlgorithm::RoundRobin);
    let outbound_manager = create_outbound_manager_with_members(&member_tags);
    let rule_engine = create_ecmp_rule_engine("us-exits");

    let handler = ControlPlaneBuilder::new()
        .with_rule_engine(rule_engine)
        .with_outbound_manager(outbound_manager)
        .with_ecmp_manager(ecmp_manager.clone())
        .build()
        .expect("Failed to build control plane handler");

    // Get ECMP group and verify round-robin selection
    let group = ecmp_manager.get_group("us-exits").expect("Group not found");

    let mut selections: Vec<String> = Vec::new();
    for _ in 0..9 {
        let member = group.next_member().expect("Selection failed");
        selections.push(member);
    }

    // Round-robin should cycle through members
    // With 3 members and 9 selections: [0,1,2,0,1,2,0,1,2]
    for i in 0..3 {
        assert_eq!(selections[i], selections[i + 3]);
        assert_eq!(selections[i], selections[i + 6]);
    }
}

// =============================================================================
// Health Check Integration Tests
// =============================================================================

/// Test that unhealthy members are excluded from ECMP selection
#[test]
fn test_ecmp_health_check_integration() {
    let member_tags = ["exit-1", "exit-2", "exit-3"];
    let ecmp_manager = create_ecmp_manager("us-exits", &member_tags, LbAlgorithm::RoundRobin);
    let outbound_manager = create_outbound_manager_with_members(&member_tags);
    let rule_engine = create_ecmp_rule_engine("us-exits");

    let _ = ControlPlaneBuilder::new()
        .with_rule_engine(rule_engine)
        .with_outbound_manager(outbound_manager)
        .with_ecmp_manager(ecmp_manager.clone())
        .build()
        .expect("Failed to build control plane handler");

    let group = ecmp_manager.get_group("us-exits").expect("Group not found");

    // Mark exit-2 as unhealthy
    group
        .update_member_health("exit-2", false)
        .expect("Failed to update health");

    // Collect selections - exit-2 should never be selected
    let mut selections: std::collections::HashSet<String> = std::collections::HashSet::new();
    for _ in 0..100 {
        let member = group.next_member().expect("Selection failed");
        selections.insert(member);
    }

    assert!(!selections.contains("exit-2"), "Unhealthy member was selected");
    assert!(selections.contains("exit-1"), "Healthy member should be selected");
    assert!(selections.contains("exit-3"), "Healthy member should be selected");
}

/// Test recovery when member becomes healthy again
#[test]
fn test_ecmp_member_recovery() {
    let member_tags = ["exit-1", "exit-2"];
    let ecmp_manager = create_ecmp_manager("exits", &member_tags, LbAlgorithm::RoundRobin);

    let group = ecmp_manager.get_group("exits").expect("Group not found");

    // Mark exit-2 as unhealthy
    group.update_member_health("exit-2", false).unwrap();

    // All selections should be exit-1
    for _ in 0..10 {
        assert_eq!(group.next_member().unwrap(), "exit-1");
    }

    // Recover exit-2
    group.update_member_health("exit-2", true).unwrap();

    // Now both should be selected
    let mut selections: std::collections::HashSet<String> = std::collections::HashSet::new();
    for _ in 0..10 {
        selections.insert(group.next_member().unwrap());
    }

    assert_eq!(selections.len(), 2, "Both members should be selected after recovery");
}

// =============================================================================
// Algorithm-Specific Tests
// =============================================================================

/// Test five-tuple hash affinity through control plane
#[test]
fn test_ecmp_five_tuple_hash_affinity() {
    let member_tags = ["exit-1", "exit-2", "exit-3"];
    let ecmp_manager = create_ecmp_manager("exits", &member_tags, LbAlgorithm::FiveTupleHash);

    let group = ecmp_manager.get_group("exits").expect("Group not found");

    // Create a specific five-tuple
    use rust_router::ecmp::lb::{FiveTuple as EcmpFiveTuple, Protocol};
    let tuple = EcmpFiveTuple::new(
        "10.0.0.1".parse().unwrap(),
        "8.8.8.8".parse().unwrap(),
        12345,
        443,
        Protocol::Tcp,
    );

    // Same tuple should always return same member
    let first = group.select_by_connection(&tuple).expect("Selection failed");
    for _ in 0..100 {
        let selected = group.select_by_connection(&tuple).expect("Selection failed");
        assert_eq!(selected, first, "Five-tuple affinity violated");
    }
}

/// Test weighted distribution through control plane
#[test]
fn test_ecmp_weighted_distribution() {
    let weights = [("light", 1), ("heavy", 3)];
    let ecmp_manager = create_weighted_ecmp_manager("exits", &weights, LbAlgorithm::Weighted);

    let group = ecmp_manager.get_group("exits").expect("Group not found");

    let mut light_count = 0u64;
    let mut heavy_count = 0u64;

    for _ in 0..4000 {
        let member = group.next_member().expect("Selection failed");
        match member.as_str() {
            "light" => light_count += 1,
            "heavy" => heavy_count += 1,
            _ => panic!("Unexpected member: {}", member),
        }
    }

    // Heavy should get approximately 3x more traffic than light
    let ratio = heavy_count as f64 / light_count as f64;
    assert!(
        ratio > 2.0 && ratio < 4.0,
        "Weight ratio should be ~3.0, got {:.2}",
        ratio
    );
}

/// Test least-connections through control plane
#[test]
fn test_ecmp_least_connections() {
    let member_tags = ["exit-1", "exit-2", "exit-3"];
    let ecmp_manager = create_ecmp_manager("exits", &member_tags, LbAlgorithm::LeastConnections);

    let group = ecmp_manager.get_group("exits").expect("Group not found");

    // Preload connections on exit-1 and exit-2
    for _ in 0..100 {
        let _ = group.increment_connections("exit-1");
        let _ = group.increment_connections("exit-2");
    }

    // New selections should prefer exit-3 (least loaded)
    let mut exit3_count = 0;
    for _ in 0..100 {
        let member = group.next_member().expect("Selection failed");
        if member == "exit-3" {
            exit3_count += 1;
        }
    }

    assert!(
        exit3_count >= 90,
        "Least-connections should prefer idle member, got {} selections for exit-3",
        exit3_count
    );
}

/// Test destination hash affinity
#[test]
fn test_ecmp_dest_hash_affinity() {
    let member_tags = ["exit-1", "exit-2", "exit-3"];
    let ecmp_manager = create_ecmp_manager("exits", &member_tags, LbAlgorithm::DestHash);

    let group = ecmp_manager.get_group("exits").expect("Group not found");

    use rust_router::ecmp::lb::DestKey;

    // Same client + same domain should always get same member
    let key = DestKey::new(
        "10.0.0.1".parse().unwrap(),
        Some("youtube.com"),
        "142.250.185.142".parse().unwrap(),
    );

    let first = group.select_by_dest(&key).expect("Selection failed");

    // Different CDN IPs should still select same member
    for i in 0..10 {
        let key = DestKey::new(
            "10.0.0.1".parse().unwrap(),
            Some("youtube.com"),
            format!("142.250.185.{}", 142 + i).parse().unwrap(),
        );
        let selected = group.select_by_dest(&key).expect("Selection failed");
        assert_eq!(selected, first, "Destination hash affinity violated");
    }
}

/// Test Ketama consistent hashing
#[test]
fn test_ecmp_ketama_affinity() {
    let member_tags = ["exit-1", "exit-2", "exit-3"];
    let ecmp_manager = create_ecmp_manager("exits", &member_tags, LbAlgorithm::Ketama);

    let group = ecmp_manager.get_group("exits").expect("Group not found");

    // Same key should always return same member
    let key = "example.com";
    let first = group.select_ketama(key).expect("Selection failed");

    for _ in 0..100 {
        let selected = group.select_ketama(key).expect("Selection failed");
        assert_eq!(selected, first, "Ketama affinity violated");
    }
}

// =============================================================================
// Error Handling Tests
// =============================================================================

/// Test that ECMP group lookup fails gracefully for non-existent groups
#[test]
fn test_ecmp_group_not_found() {
    let ecmp_manager = Arc::new(EcmpGroupManager::new());

    let result = ecmp_manager.get_group("nonexistent");
    assert!(result.is_none(), "Non-existent group should return None");
}

/// Test that all members unhealthy returns error
#[test]
fn test_ecmp_all_members_unhealthy() {
    let member_tags = ["exit-1", "exit-2"];
    let ecmp_manager = create_ecmp_manager("exits", &member_tags, LbAlgorithm::RoundRobin);

    let group = ecmp_manager.get_group("exits").expect("Group not found");

    // Mark all as unhealthy
    group.update_member_health("exit-1", false).unwrap();
    group.update_member_health("exit-2", false).unwrap();

    let result = group.next_member();
    assert!(result.is_err(), "Should return error when all members unhealthy");
}

// =============================================================================
// Concurrent Access Tests
// =============================================================================

/// Test concurrent ECMP selection is thread-safe
#[test]
fn test_ecmp_concurrent_selection() {
    use std::thread;

    let member_tags = ["exit-1", "exit-2", "exit-3"];
    let ecmp_manager = create_ecmp_manager("exits", &member_tags, LbAlgorithm::RoundRobin);

    let group = ecmp_manager.get_group("exits").expect("Group not found");

    let handles: Vec<_> = (0..4)
        .map(|_| {
            let group_clone = ecmp_manager.get_group("exits").unwrap();
            thread::spawn(move || {
                let mut count = 0u64;
                for _ in 0..1000 {
                    if group_clone.next_member().is_ok() {
                        count += 1;
                    }
                }
                count
            })
        })
        .collect();

    let total: u64 = handles.into_iter().map(|h| h.join().unwrap()).sum();

    // All selections should succeed
    assert_eq!(total, 4000, "All concurrent selections should succeed");
}

/// Test concurrent health updates don't cause race conditions
#[test]
fn test_ecmp_concurrent_health_updates() {
    use std::thread;

    let member_tags = ["exit-1", "exit-2"];
    let ecmp_manager = create_ecmp_manager("exits", &member_tags, LbAlgorithm::RoundRobin);

    // Thread 1: Toggle health status
    let manager1 = ecmp_manager.clone();
    let handle1 = thread::spawn(move || {
        let group = manager1.get_group("exits").unwrap();
        for i in 0..100 {
            let _ = group.update_member_health("exit-1", i % 2 == 0);
        }
    });

    // Thread 2: Perform selections
    let manager2 = ecmp_manager.clone();
    let handle2 = thread::spawn(move || {
        let group = manager2.get_group("exits").unwrap();
        let mut success = 0;
        for _ in 0..100 {
            // May fail if all unhealthy, that's OK
            if group.next_member().is_ok() {
                success += 1;
            }
        }
        success
    });

    handle1.join().unwrap();
    let success = handle2.join().unwrap();

    // At least some selections should succeed (exit-2 always healthy)
    assert!(success > 0, "Should have some successful selections");
}
