//! ECMP group management for Phase 6
//!
//! This module implements ECMP group management with health-aware
//! member selection and routing mark assignment.
//!
//! # Phase 6 Implementation Status
//!
//! - [ ] 6.7 ECMP group structure
//! - [ ] 6.7 Member management
//! - [ ] 6.7 Health integration
//! - [ ] 6.7 Routing mark allocation
//!
//! # Example
//!
//! ```ignore
//! use rust_router::ecmp::group::{EcmpGroup, EcmpGroupConfig, EcmpMember};
//!
//! let mut group = EcmpGroup::new(EcmpGroupConfig {
//!     tag: "us-exits".to_string(),
//!     members: vec![
//!         EcmpMember { tag: "pia-us-ny".to_string(), weight: 1 },
//!         EcmpMember { tag: "pia-us-ca".to_string(), weight: 1 },
//!     ],
//!     routing_mark: Some(200),
//!     ..Default::default()
//! })?;
//!
//! // Get next member using configured algorithm
//! let member = group.next_member()?;
//! ```
//!
//! # References
//!
//! - Implementation Plan: `docs/PHASE6_IMPLEMENTATION_PLAN_v3.2.md` Section 6.7

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;

use serde::{Deserialize, Serialize};

use crate::ecmp::lb::{LbAlgorithm, LoadBalancer};

/// Minimum routing mark for ECMP groups
pub const ECMP_ROUTING_MARK_MIN: u32 = 200;

/// Maximum routing mark for ECMP groups
pub const ECMP_ROUTING_MARK_MAX: u32 = 299;

/// Error types for ECMP operations
#[derive(Debug, Clone, thiserror::Error)]
pub enum EcmpGroupError {
    /// No members in group
    #[error("ECMP group has no members")]
    NoMembers,

    /// No healthy members available
    #[error("No healthy members available")]
    NoHealthyMembers,

    /// Member not found
    #[error("Member not found: {0}")]
    MemberNotFound(String),

    /// Member already exists
    #[error("Member already exists: {0}")]
    MemberExists(String),

    /// Invalid routing mark
    #[error("Routing mark {0} is out of ECMP range ({ECMP_ROUTING_MARK_MIN}-{ECMP_ROUTING_MARK_MAX})")]
    InvalidRoutingMark(u32),

    /// Invalid weight
    #[error("Weight must be positive: {0}")]
    InvalidWeight(u32),

    /// Load balancer error
    #[error("Load balancer error: {0}")]
    LoadBalancer(String),

    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),
}

/// ECMP group member
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EcmpMember {
    /// Outbound tag
    pub tag: String,
    /// Weight for weighted load balancing (default: 1)
    #[serde(default = "default_weight")]
    pub weight: u32,
}

fn default_weight() -> u32 {
    1
}

impl EcmpMember {
    /// Create a new member with default weight
    pub fn new(tag: String) -> Self {
        Self { tag, weight: 1 }
    }

    /// Create a new member with specified weight
    pub fn with_weight(tag: String, weight: u32) -> Self {
        Self { tag, weight }
    }
}

/// ECMP group member state
#[allow(dead_code)]
struct MemberState {
    /// Member configuration
    config: EcmpMember,
    /// Whether the member is healthy
    healthy: bool,
    /// Active connection count (for least-connections)
    active_connections: AtomicU64,
}

/// ECMP group configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EcmpGroupConfig {
    /// Group tag
    pub tag: String,
    /// Group description
    #[serde(default)]
    pub description: String,
    /// Group members
    pub members: Vec<EcmpMember>,
    /// Load balancing algorithm
    #[serde(default)]
    pub algorithm: LbAlgorithm,
    /// Routing mark for Linux policy routing (200-299)
    #[serde(default)]
    pub routing_mark: Option<u32>,
    /// Routing table for policy routing
    #[serde(default)]
    pub routing_table: Option<u32>,
    /// Whether to enable health checking
    #[serde(default = "default_health_check")]
    pub health_check: bool,
}

fn default_health_check() -> bool {
    true
}

impl Default for EcmpGroupConfig {
    fn default() -> Self {
        Self {
            tag: String::new(),
            description: String::new(),
            members: Vec::new(),
            algorithm: LbAlgorithm::RoundRobin,
            routing_mark: None,
            routing_table: None,
            health_check: true,
        }
    }
}

/// ECMP load balancing group
///
/// TODO(Phase 6.7): Implement full ECMP group management
#[allow(dead_code)]
pub struct EcmpGroup {
    /// Group configuration
    config: EcmpGroupConfig,
    /// Member states
    members: RwLock<Vec<MemberState>>,
    /// Load balancer instance
    load_balancer: LoadBalancer,
    /// Total requests processed
    total_requests: AtomicU64,
}

impl EcmpGroup {
    /// Create a new ECMP group
    ///
    /// # Arguments
    ///
    /// * `config` - Group configuration
    ///
    /// # Example
    ///
    /// ```ignore
    /// let group = EcmpGroup::new(config)?;
    /// ```
    pub fn new(config: EcmpGroupConfig) -> Result<Self, EcmpGroupError> {
        // Validate configuration
        if config.members.is_empty() {
            return Err(EcmpGroupError::NoMembers);
        }

        // Validate routing mark if specified
        if let Some(mark) = config.routing_mark {
            if mark < ECMP_ROUTING_MARK_MIN || mark > ECMP_ROUTING_MARK_MAX {
                return Err(EcmpGroupError::InvalidRoutingMark(mark));
            }
        }

        // Validate weights
        for member in &config.members {
            if member.weight == 0 {
                return Err(EcmpGroupError::InvalidWeight(0));
            }
        }

        // Create member states
        let member_states: Vec<MemberState> = config
            .members
            .iter()
            .map(|m| MemberState {
                config: m.clone(),
                healthy: true, // Assume healthy initially
                active_connections: AtomicU64::new(0),
            })
            .collect();

        // Create load balancer
        let load_balancer = LoadBalancer::new(config.algorithm.clone());

        Ok(Self {
            config,
            members: RwLock::new(member_states),
            load_balancer,
            total_requests: AtomicU64::new(0),
        })
    }

    /// Get the group tag
    pub fn tag(&self) -> &str {
        &self.config.tag
    }

    /// Get the group configuration
    pub fn config(&self) -> &EcmpGroupConfig {
        &self.config
    }

    /// Get the routing mark for this group
    pub fn routing_mark(&self) -> Option<u32> {
        self.config.routing_mark
    }

    /// Get the total number of members
    pub fn member_count(&self) -> usize {
        self.members
            .read()
            .map(|m| m.len())
            .unwrap_or(0)
    }

    /// Get the number of healthy members
    pub fn healthy_count(&self) -> usize {
        self.members
            .read()
            .map(|m| m.iter().filter(|s| s.healthy).count())
            .unwrap_or(0)
    }

    /// Get the next member for load balancing
    ///
    /// TODO(Phase 6.7): Implement load balancer selection
    pub fn next_member(&self) -> Result<String, EcmpGroupError> {
        unimplemented!("Phase 6.7: next_member not yet implemented")
    }

    /// Update member health status
    ///
    /// # Arguments
    ///
    /// * `tag` - Member outbound tag
    /// * `healthy` - New health status
    pub fn update_member_health(&self, tag: &str, healthy: bool) -> Result<(), EcmpGroupError> {
        let mut members = self
            .members
            .write()
            .map_err(|e| EcmpGroupError::Internal(e.to_string()))?;

        let member = members
            .iter_mut()
            .find(|m| m.config.tag == tag)
            .ok_or_else(|| EcmpGroupError::MemberNotFound(tag.to_string()))?;

        member.healthy = healthy;
        Ok(())
    }

    /// Add a new member to the group
    ///
    /// # Arguments
    ///
    /// * `member` - Member to add
    pub fn add_member(&self, member: EcmpMember) -> Result<(), EcmpGroupError> {
        if member.weight == 0 {
            return Err(EcmpGroupError::InvalidWeight(0));
        }

        let mut members = self
            .members
            .write()
            .map_err(|e| EcmpGroupError::Internal(e.to_string()))?;

        if members.iter().any(|m| m.config.tag == member.tag) {
            return Err(EcmpGroupError::MemberExists(member.tag));
        }

        members.push(MemberState {
            config: member,
            healthy: true,
            active_connections: AtomicU64::new(0),
        });

        Ok(())
    }

    /// Remove a member from the group
    ///
    /// # Arguments
    ///
    /// * `tag` - Member outbound tag to remove
    pub fn remove_member(&self, tag: &str) -> Result<(), EcmpGroupError> {
        let mut members = self
            .members
            .write()
            .map_err(|e| EcmpGroupError::Internal(e.to_string()))?;

        let pos = members
            .iter()
            .position(|m| m.config.tag == tag)
            .ok_or_else(|| EcmpGroupError::MemberNotFound(tag.to_string()))?;

        members.remove(pos);
        Ok(())
    }

    /// Get statistics for the group
    pub fn stats(&self) -> EcmpGroupStats {
        let (member_count, healthy_count) = self
            .members
            .read()
            .map(|m| (m.len(), m.iter().filter(|s| s.healthy).count()))
            .unwrap_or((0, 0));

        EcmpGroupStats {
            tag: self.config.tag.clone(),
            member_count,
            healthy_count,
            total_requests: self.total_requests.load(Ordering::Relaxed),
            algorithm: self.config.algorithm.clone(),
        }
    }
}

/// Statistics for an ECMP group
#[derive(Debug, Clone)]
pub struct EcmpGroupStats {
    /// Group tag
    pub tag: String,
    /// Total member count
    pub member_count: usize,
    /// Healthy member count
    pub healthy_count: usize,
    /// Total requests processed
    pub total_requests: u64,
    /// Load balancing algorithm
    pub algorithm: LbAlgorithm,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_config() -> EcmpGroupConfig {
        EcmpGroupConfig {
            tag: "test-group".to_string(),
            description: "Test ECMP group".to_string(),
            members: vec![
                EcmpMember::new("member-1".to_string()),
                EcmpMember::new("member-2".to_string()),
            ],
            algorithm: LbAlgorithm::RoundRobin,
            routing_mark: Some(200),
            routing_table: Some(200),
            health_check: true,
        }
    }

    #[test]
    fn test_new_group() {
        let config = create_test_config();
        let group = EcmpGroup::new(config).unwrap();

        assert_eq!(group.tag(), "test-group");
        assert_eq!(group.member_count(), 2);
        assert_eq!(group.healthy_count(), 2);
    }

    #[test]
    fn test_no_members() {
        let mut config = create_test_config();
        config.members = vec![];

        let result = EcmpGroup::new(config);
        assert!(matches!(result, Err(EcmpGroupError::NoMembers)));
    }

    #[test]
    fn test_invalid_routing_mark() {
        let mut config = create_test_config();
        config.routing_mark = Some(100); // Out of range

        let result = EcmpGroup::new(config);
        assert!(matches!(result, Err(EcmpGroupError::InvalidRoutingMark(_))));
    }

    #[test]
    fn test_invalid_weight() {
        let mut config = create_test_config();
        config.members[0].weight = 0;

        let result = EcmpGroup::new(config);
        assert!(matches!(result, Err(EcmpGroupError::InvalidWeight(0))));
    }

    #[test]
    fn test_update_member_health() {
        let config = create_test_config();
        let group = EcmpGroup::new(config).unwrap();

        assert_eq!(group.healthy_count(), 2);

        group.update_member_health("member-1", false).unwrap();
        assert_eq!(group.healthy_count(), 1);

        group.update_member_health("member-1", true).unwrap();
        assert_eq!(group.healthy_count(), 2);
    }

    #[test]
    fn test_add_remove_member() {
        let config = create_test_config();
        let group = EcmpGroup::new(config).unwrap();

        assert_eq!(group.member_count(), 2);

        group.add_member(EcmpMember::new("member-3".to_string())).unwrap();
        assert_eq!(group.member_count(), 3);

        group.remove_member("member-3").unwrap();
        assert_eq!(group.member_count(), 2);
    }

    #[test]
    fn test_add_duplicate_member() {
        let config = create_test_config();
        let group = EcmpGroup::new(config).unwrap();

        let result = group.add_member(EcmpMember::new("member-1".to_string()));
        assert!(matches!(result, Err(EcmpGroupError::MemberExists(_))));
    }

    #[test]
    fn test_stats() {
        let config = create_test_config();
        let group = EcmpGroup::new(config).unwrap();

        let stats = group.stats();
        assert_eq!(stats.tag, "test-group");
        assert_eq!(stats.member_count, 2);
        assert_eq!(stats.healthy_count, 2);
        assert_eq!(stats.total_requests, 0);
    }
}
