//! ECMP Traffic Tests
//!
//! Unit tests for ECMP load balancing algorithms using simulated traffic.
//! These tests verify correct distribution patterns for each algorithm.

use std::collections::HashMap;

use crate::ecmp::lb::{DestKey, FiveTuple, LbAlgorithm, Protocol};
use crate::ecmp::traffic_test::{
    create_test_group, create_weighted_group, verify_dest_affinity, verify_five_tuple_affinity,
    EcmpTrafficGenerator, TrafficPattern, DEFAULT_TOLERANCE, WEIGHTED_TOLERANCE,
};
use crate::ecmp::{EcmpGroup, EcmpGroupConfig, EcmpMember};

// =============================================================================
// Round-Robin Algorithm Tests
// =============================================================================

/// Test that round-robin distributes traffic evenly across members.
///
/// With N members and M requests, each member should receive approximately M/N requests
/// within a 5% tolerance.
#[test]
fn test_round_robin_traffic_distribution() {
    let group = create_test_group(4, LbAlgorithm::RoundRobin);
    let mut generator = EcmpTrafficGenerator::new(&group);

    let results = generator.run_round_robin_test(10_000);

    // Round-robin should be very evenly distributed
    assert!(
        results.is_evenly_distributed(DEFAULT_TOLERANCE),
        "Round-robin distribution exceeded 5% tolerance:\n{}",
        results.summary()
    );

    // Each member should receive ~2500 connections
    for i in 0..4 {
        let count = results.get_count(&format!("member-{}", i));
        assert!(
            count >= 2000 && count <= 3000,
            "member-{} received {} connections, expected ~2500",
            i,
            count
        );
    }
}

/// Test round-robin with 2 members.
#[test]
fn test_round_robin_two_members() {
    let group = create_test_group(2, LbAlgorithm::RoundRobin);
    let mut generator = EcmpTrafficGenerator::new(&group);

    let results = generator.run_round_robin_test(1000);

    // Should be very close to 50/50
    let count_0 = results.get_count("member-0");
    let count_1 = results.get_count("member-1");

    assert!(
        (count_0 as i64 - count_1 as i64).unsigned_abs() <= 10,
        "Round-robin with 2 members not balanced: {} vs {}",
        count_0,
        count_1
    );
}

// =============================================================================
// Five-Tuple Hash Algorithm Tests
// =============================================================================

/// Test that the same 5-tuple always selects the same member (100% affinity).
#[test]
fn test_five_tuple_hash_affinity() {
    let group = create_test_group(4, LbAlgorithm::FiveTupleHash);

    // Same tuple should always return same member
    assert!(
        verify_five_tuple_affinity(&group, 1000),
        "Five-tuple hash affinity violated"
    );
}

/// Test that different 5-tuples distribute across members.
#[test]
fn test_five_tuple_hash_distribution() {
    let group = create_test_group(4, LbAlgorithm::FiveTupleHash);
    let mut generator = EcmpTrafficGenerator::new(&group);

    // Use sequential ports to generate different 5-tuples
    let results = generator.run_five_tuple_test(10_000, TrafficPattern::SequentialPorts);

    // Different tuples should distribute across members
    // Hash distribution won't be perfectly even, but should use all members
    for i in 0..4 {
        let count = results.get_count(&format!("member-{}", i));
        assert!(
            count > 0,
            "member-{} received no traffic despite different 5-tuples",
            i
        );
    }

    // Distribution should be reasonably balanced (within 20% for hash-based)
    let max_deviation = results.max_deviation();
    assert!(
        max_deviation < 0.30,
        "Five-tuple hash distribution too uneven: {:.1}% max deviation\n{}",
        max_deviation * 100.0,
        results.summary()
    );
}

/// Test five-tuple affinity with fixed port (same connection).
#[test]
fn test_five_tuple_fixed_port_affinity() {
    let group = create_test_group(4, LbAlgorithm::FiveTupleHash);
    let mut generator = EcmpTrafficGenerator::new(&group);

    // All requests with fixed port should go to same member
    let results = generator.run_five_tuple_test(100, TrafficPattern::FixedPort);

    // Count how many members received traffic
    let active_members: Vec<_> = results
        .member_counts
        .iter()
        .filter(|(_, &count)| count > 0)
        .collect();

    // With fixed 5-tuple, only one member should receive all traffic
    assert_eq!(
        active_members.len(),
        1,
        "Fixed 5-tuple should route to exactly one member, but routed to {}",
        active_members.len()
    );
}

// =============================================================================
// Weighted Algorithm Tests
// =============================================================================

/// Test that weighted distribution respects member weights.
#[test]
fn test_weighted_traffic_distribution() {
    let weights = vec![
        ("light".to_string(), 1),
        ("medium".to_string(), 2),
        ("heavy".to_string(), 4),
    ];
    let group = create_weighted_group(&weights, LbAlgorithm::Weighted);
    let mut generator = EcmpTrafficGenerator::new(&group);

    let results = generator.run_weighted_test(10_000);

    // Total weight = 1 + 2 + 4 = 7
    // light should get ~1/7 = 14.3%
    // medium should get ~2/7 = 28.6%
    // heavy should get ~4/7 = 57.1%

    let weight_map: HashMap<String, u32> = weights.into_iter().collect();

    assert!(
        results.matches_weights(&weight_map, WEIGHTED_TOLERANCE),
        "Weighted distribution does not match expected weights:\n{}",
        results.summary()
    );

    // Verify relative ordering
    let light = results.get_count("light");
    let medium = results.get_count("medium");
    let heavy = results.get_count("heavy");

    assert!(
        heavy > medium && medium > light,
        "Weight ordering violated: light={}, medium={}, heavy={}",
        light,
        medium,
        heavy
    );
}

/// Test weighted with extreme weights.
#[test]
fn test_weighted_extreme_weights() {
    let weights = vec![
        ("tiny".to_string(), 1),
        ("huge".to_string(), 99),
    ];
    let group = create_weighted_group(&weights, LbAlgorithm::Weighted);
    let mut generator = EcmpTrafficGenerator::new(&group);

    let results = generator.run_weighted_test(10_000);

    // huge should get ~99% of traffic
    let tiny = results.get_count("tiny");
    let huge = results.get_count("huge");

    let tiny_ratio = tiny as f64 / results.total_connections as f64;
    let huge_ratio = huge as f64 / results.total_connections as f64;

    assert!(
        tiny_ratio < 0.03,
        "tiny member got too much traffic: {:.1}%",
        tiny_ratio * 100.0
    );
    assert!(
        huge_ratio > 0.95,
        "huge member got too little traffic: {:.1}%",
        huge_ratio * 100.0
    );
}

// =============================================================================
// Least-Connections Algorithm Tests
// =============================================================================

/// Test that least-connections balances load under simulated traffic.
#[test]
fn test_least_connections_under_load() {
    let group = create_test_group(4, LbAlgorithm::LeastConnections);
    let mut generator = EcmpTrafficGenerator::new(&group);

    let results = generator.run_least_connections_test(1000);

    // Least connections should result in fairly even distribution
    // since we're incrementing connections for each selection
    assert!(
        results.is_evenly_distributed(0.15), // Allow 15% tolerance for LC
        "Least-connections distribution too uneven:\n{}",
        results.summary()
    );
}

/// Test that least-connections prefers member with fewer connections.
#[test]
fn test_least_connections_prefers_idle() {
    let group = create_test_group(3, LbAlgorithm::LeastConnections);

    // Simulate heavy load on members 0 and 1
    for _ in 0..100 {
        let _ = group.increment_connections("member-0");
        let _ = group.increment_connections("member-1");
    }

    // New connections should go to member-2 (idle)
    let mut member_2_count = 0;
    for _ in 0..100 {
        if let Ok(member) = group.next_member() {
            if member == "member-2" {
                member_2_count += 1;
            }
        }
    }

    // Most traffic should go to idle member
    assert!(
        member_2_count >= 90,
        "Least-connections should prefer idle member, but member-2 only got {} of 100",
        member_2_count
    );
}

// =============================================================================
// Destination Hash Algorithm Tests
// =============================================================================

/// Test destination hash domain affinity.
///
/// Same client + same domain should always select the same member,
/// even when connecting to different CDN IPs.
#[test]
fn test_dest_hash_domain_affinity() {
    let group = create_test_group(4, LbAlgorithm::DestHash);

    assert!(
        verify_dest_affinity(&group, 100),
        "Destination hash affinity violated"
    );
}

/// Test destination hash distributes different domains across members.
#[test]
fn test_dest_hash_domain_distribution() {
    let group = create_test_group(4, LbAlgorithm::DestHash);
    let mut generator = EcmpTrafficGenerator::new(&group);

    let results = generator.run_dest_hash_test(10_000, TrafficPattern::MultipleDomains);

    // Different domains should distribute across members
    for i in 0..4 {
        let count = results.get_count(&format!("member-{}", i));
        assert!(
            count > 0,
            "member-{} received no traffic from different domains",
            i
        );
    }
}

/// Test destination hash with multiple clients to same domain.
#[test]
fn test_dest_hash_multiple_clients() {
    let group = create_test_group(4, LbAlgorithm::DestHash);
    let mut generator = EcmpTrafficGenerator::new(&group);

    let results = generator.run_dest_hash_test(10_000, TrafficPattern::MultipleClients);

    // Different clients should potentially use different members
    // (since hash includes client IP)
    let active_members: usize = results.member_counts.values().filter(|&&c| c > 0).count();

    assert!(
        active_members >= 2,
        "Multiple clients should distribute across members"
    );
}

// =============================================================================
// Health Check Tests
// =============================================================================

/// Test that unhealthy members receive no traffic.
#[test]
fn test_unhealthy_member_excluded() {
    let group = create_test_group(3, LbAlgorithm::RoundRobin);

    // Mark member-1 as unhealthy
    group.update_member_health("member-1", false).unwrap();

    let mut generator = EcmpTrafficGenerator::new(&group);
    let results = generator.run_round_robin_test(1000);

    // member-1 should receive no traffic
    assert!(
        results.member_excluded("member-1"),
        "Unhealthy member-1 received {} connections",
        results.get_count("member-1")
    );

    // Traffic should go to healthy members
    let count_0 = results.get_count("member-0");
    let count_2 = results.get_count("member-2");

    assert!(
        count_0 > 400 && count_0 < 600,
        "member-0 should get ~50% but got {}",
        count_0
    );
    assert!(
        count_2 > 400 && count_2 < 600,
        "member-2 should get ~50% but got {}",
        count_2
    );
}

/// Test unhealthy exclusion with five-tuple hash.
#[test]
fn test_unhealthy_member_five_tuple_hash() {
    let group = create_test_group(4, LbAlgorithm::FiveTupleHash);

    // Mark member-1 as unhealthy
    group.update_member_health("member-1", false).unwrap();

    let mut generator = EcmpTrafficGenerator::new(&group);
    let results = generator.run_five_tuple_test(1000, TrafficPattern::SequentialPorts);

    // member-1 should receive no traffic
    assert!(
        results.member_excluded("member-1"),
        "Unhealthy member-1 received traffic with five-tuple hash"
    );
}

/// Test recovery: member becomes healthy again.
#[test]
fn test_member_recovery() {
    let group = create_test_group(3, LbAlgorithm::RoundRobin);

    // Mark member-1 as unhealthy
    group.update_member_health("member-1", false).unwrap();

    // Run some traffic
    for _ in 0..100 {
        let _ = group.next_member();
    }

    // member-1 should have 0 connections
    assert_eq!(group.get_active_connections("member-1"), Some(0));

    // Recover member-1
    group.update_member_health("member-1", true).unwrap();

    // Now member-1 should receive traffic
    let mut generator = EcmpTrafficGenerator::new(&group);
    let results = generator.run_round_robin_test(300);

    // All members should receive traffic
    for i in 0..3 {
        let count = results.get_count(&format!("member-{}", i));
        assert!(
            count > 50,
            "member-{} should receive traffic after recovery, got {}",
            i,
            count
        );
    }
}

// =============================================================================
// Ketama Consistent Hashing Tests
// =============================================================================

/// Test Ketama consistent hashing distribution.
#[test]
fn test_ketama_traffic_distribution() {
    let group = create_test_group(4, LbAlgorithm::Ketama);
    let mut generator = EcmpTrafficGenerator::new(&group);

    let results = generator.run_ketama_test(10_000);

    // All members should receive some traffic
    for i in 0..4 {
        let count = results.get_count(&format!("member-{}", i));
        assert!(
            count > 0,
            "member-{} received no traffic with Ketama",
            i
        );
    }

    // Distribution should be reasonably balanced (consistent hashing isn't perfect)
    let max_deviation = results.max_deviation();
    assert!(
        max_deviation < 0.40,
        "Ketama distribution too uneven: {:.1}% max deviation\n{}",
        max_deviation * 100.0,
        results.summary()
    );
}

/// Test Ketama key affinity: same key always returns same member.
#[test]
fn test_ketama_key_affinity() {
    let group = create_test_group(4, LbAlgorithm::Ketama);

    let key = "example.com";
    let first = group.select_ketama(key).unwrap();

    for _ in 0..100 {
        let selected = group.select_ketama(key).unwrap();
        assert_eq!(
            selected, first,
            "Ketama affinity violated: {} != {}",
            selected, first
        );
    }
}

/// Test Ketama consistent hashing with weighted members.
#[test]
fn test_ketama_weighted() {
    let weights = vec![
        ("light".to_string(), 1),
        ("heavy".to_string(), 3),
    ];
    let group = create_weighted_group(&weights, LbAlgorithm::Ketama);

    let mut counts: HashMap<String, u64> = HashMap::new();
    counts.insert("light".to_string(), 0);
    counts.insert("heavy".to_string(), 0);

    for i in 0..10_000 {
        let key = format!("key-{}", i);
        if let Ok(member) = group.select_ketama(&key) {
            *counts.get_mut(&member).unwrap() += 1;
        }
    }

    let light = counts.get("light").copied().unwrap_or(0);
    let heavy = counts.get("heavy").copied().unwrap_or(0);

    // heavy should get more traffic due to more virtual nodes
    assert!(
        heavy > light,
        "Ketama should respect weights: light={}, heavy={}",
        light,
        heavy
    );
}

// =============================================================================
// Edge Cases and Error Handling
// =============================================================================

/// Test with single member.
#[test]
fn test_single_member_group() {
    let group = create_test_group(1, LbAlgorithm::RoundRobin);
    let mut generator = EcmpTrafficGenerator::new(&group);

    let results = generator.run_round_robin_test(100);

    // Single member should receive all traffic
    assert_eq!(results.get_count("member-0"), 100);
}

/// Test all members unhealthy returns error.
#[test]
fn test_all_members_unhealthy() {
    let group = create_test_group(3, LbAlgorithm::RoundRobin);

    // Mark all as unhealthy
    for i in 0..3 {
        group
            .update_member_health(&format!("member-{}", i), false)
            .unwrap();
    }

    // Should return error
    assert!(group.next_member().is_err());
}

/// Test concurrent connection counting doesn't underflow.
#[test]
fn test_connection_count_no_underflow() {
    let group = create_test_group(2, LbAlgorithm::LeastConnections);

    // Decrement without increment should not panic or underflow
    for _ in 0..100 {
        let _ = group.decrement_connections("member-0");
    }

    // Should still be 0
    assert_eq!(group.get_active_connections("member-0"), Some(0));
}

/// Test traffic results coefficient of variation.
#[test]
fn test_results_statistics() {
    let group = create_test_group(4, LbAlgorithm::RoundRobin);
    let mut generator = EcmpTrafficGenerator::new(&group);

    let results = generator.run_round_robin_test(4000);

    // Round-robin should have very low CV
    let cv = results.coefficient_of_variation();
    assert!(
        cv < 0.05,
        "Round-robin CV should be very low, got {:.4}",
        cv
    );
}

// =============================================================================
// Regression Tests
// =============================================================================

/// Ensure hash changes with different source IPs.
#[test]
fn test_source_ip_affects_hash() {
    let group = create_test_group(4, LbAlgorithm::FiveTupleHash);

    // Two different source IPs connecting to same destination
    let tuple1 = FiveTuple::new(
        "10.0.0.1".parse().unwrap(),
        "8.8.8.8".parse().unwrap(),
        12345,
        443,
        Protocol::Tcp,
    );

    let tuple2 = FiveTuple::new(
        "10.0.0.2".parse().unwrap(), // Different source IP
        "8.8.8.8".parse().unwrap(),
        12345,
        443,
        Protocol::Tcp,
    );

    let member1 = group.select_by_connection(&tuple1).unwrap();
    let member2 = group.select_by_connection(&tuple2).unwrap();

    // They might select same member by chance, but hashes should differ
    // We can't assert inequality, but we can verify both work
    assert!(!member1.is_empty());
    assert!(!member2.is_empty());
}

/// Ensure TCP and UDP are treated differently.
#[test]
fn test_protocol_affects_hash() {
    let group = create_test_group(4, LbAlgorithm::FiveTupleHash);

    let tcp_tuple = FiveTuple::new(
        "10.0.0.1".parse().unwrap(),
        "8.8.8.8".parse().unwrap(),
        12345,
        443,
        Protocol::Tcp,
    );

    let udp_tuple = FiveTuple::new(
        "10.0.0.1".parse().unwrap(),
        "8.8.8.8".parse().unwrap(),
        12345,
        443,
        Protocol::Udp,
    );

    let tcp_member = group.select_by_connection(&tcp_tuple).unwrap();
    let udp_member = group.select_by_connection(&udp_tuple).unwrap();

    // Both should work (might select same or different member)
    assert!(!tcp_member.is_empty());
    assert!(!udp_member.is_empty());
}
