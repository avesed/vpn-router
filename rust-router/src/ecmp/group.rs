//! ECMP group management for Phase 6
//!
//! This module implements ECMP group management with health-aware
//! member selection and routing mark assignment.
//!
//! # Phase 6 Implementation Status
//!
//! - [x] 6.7 ECMP group structure
//! - [x] 6.7 Member management
//! - [x] 6.7 Health integration
//! - [x] 6.7 Routing mark allocation
//! - [x] 6.7 EcmpGroupManager
//! - [x] 6.7 Connection-based selection
//!
//! # Example
//!
//! ```
//! use rust_router::ecmp::group::{EcmpGroup, EcmpGroupConfig, EcmpMember};
//! use rust_router::ecmp::lb::LbAlgorithm;
//!
//! let group = EcmpGroup::new(EcmpGroupConfig {
//!     tag: "us-exits".to_string(),
//!     members: vec![
//!         EcmpMember::new("pia-us-ny".to_string()),
//!         EcmpMember::new("pia-us-ca".to_string()),
//!     ],
//!     routing_mark: Some(200),
//!     ..Default::default()
//! }).unwrap();
//!
//! // Get next member using configured algorithm
//! let member = group.next_member().unwrap();
//! ```
//!
//! # References
//!
//! - Implementation Plan: `docs/PHASE6_IMPLEMENTATION_PLAN_v3.2.md` Section 6.7

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::ecmp::lb::{FiveTuple, LbAlgorithm, LbError, LbMember, LoadBalancer};

/// Minimum routing mark for ECMP groups
pub const ECMP_ROUTING_MARK_MIN: u32 = 200;

/// Maximum routing mark for ECMP groups
pub const ECMP_ROUTING_MARK_MAX: u32 = 299;

/// Minimum routing table for ECMP groups
pub const ECMP_ROUTING_TABLE_MIN: u32 = 200;

/// Maximum routing table for ECMP groups
pub const ECMP_ROUTING_TABLE_MAX: u32 = 299;

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

    /// Group not found
    #[error("Group not found: {0}")]
    GroupNotFound(String),

    /// Group already exists
    #[error("Group already exists: {0}")]
    GroupExists(String),

    /// Invalid routing mark
    #[error("Routing mark {0} is out of ECMP range ({ECMP_ROUTING_MARK_MIN}-{ECMP_ROUTING_MARK_MAX})")]
    InvalidRoutingMark(u32),

    /// Invalid weight
    #[error("Weight must be positive: {0}")]
    InvalidWeight(u32),

    /// No routing tables available
    #[error("No routing tables available in range {ECMP_ROUTING_TABLE_MIN}-{ECMP_ROUTING_TABLE_MAX}")]
    NoRoutingTablesAvailable,

    /// Routing table already allocated
    #[error("Routing table {0} is already allocated")]
    RoutingTableAlreadyAllocated(u32),

    /// Load balancer error
    #[error("Load balancer error: {0}")]
    LoadBalancer(String),

    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),
}

impl From<LbError> for EcmpGroupError {
    fn from(err: LbError) -> Self {
        match err {
            LbError::NoMembers => Self::NoHealthyMembers,
            LbError::ZeroWeight => Self::InvalidWeight(0),
            LbError::MissingFiveTuple => Self::LoadBalancer("Five-tuple required".into()),
            LbError::Internal(msg) => Self::Internal(msg),
        }
    }
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
    #[must_use]
    pub fn new(tag: String) -> Self {
        Self { tag, weight: 1 }
    }

    /// Create a new member with specified weight
    #[must_use]
    pub fn with_weight(tag: String, weight: u32) -> Self {
        Self { tag, weight }
    }
}

/// ECMP group member state
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
            algorithm: LbAlgorithm::default(),
            routing_mark: None,
            routing_table: None,
            health_check: true,
        }
    }
}

/// ECMP load balancing group
///
/// Manages a group of outbound members with health-aware load balancing.
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
    /// # Errors
    ///
    /// Returns `EcmpGroupError` if:
    /// - Group has no members
    /// - Routing mark is out of range
    /// - Any member has zero weight
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::ecmp::group::{EcmpGroup, EcmpGroupConfig, EcmpMember};
    ///
    /// let config = EcmpGroupConfig {
    ///     tag: "test".to_string(),
    ///     members: vec![EcmpMember::new("member-1".to_string())],
    ///     ..Default::default()
    /// };
    /// let group = EcmpGroup::new(config).unwrap();
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
    #[must_use]
    pub fn tag(&self) -> &str {
        &self.config.tag
    }

    /// Get the group configuration
    #[must_use]
    pub fn config(&self) -> &EcmpGroupConfig {
        &self.config
    }

    /// Get the routing mark for this group
    #[must_use]
    pub fn routing_mark(&self) -> Option<u32> {
        self.config.routing_mark
    }

    /// Get the routing table for this group
    #[must_use]
    pub fn routing_table(&self) -> Option<u32> {
        self.config.routing_table
    }

    /// Get the total number of members
    #[must_use]
    pub fn member_count(&self) -> usize {
        self.members.read().len()
    }

    /// Get the number of healthy members
    #[must_use]
    pub fn healthy_count(&self) -> usize {
        self.members.read().iter().filter(|s| s.healthy).count()
    }

    /// Get all member tags
    #[must_use]
    pub fn member_tags(&self) -> Vec<String> {
        self.members
            .read()
            .iter()
            .map(|m| m.config.tag.clone())
            .collect()
    }

    /// Get the next member for load balancing
    ///
    /// Uses the configured load balancing algorithm to select a healthy member.
    /// For `FiveTupleHash` algorithm, this falls back to round-robin since
    /// no connection info is provided.
    ///
    /// # Returns
    ///
    /// The tag of the selected member.
    ///
    /// # Errors
    ///
    /// Returns `EcmpGroupError::NoHealthyMembers` if no healthy members are available.
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::ecmp::group::{EcmpGroup, EcmpGroupConfig, EcmpMember};
    /// use rust_router::ecmp::lb::LbAlgorithm;
    ///
    /// let config = EcmpGroupConfig {
    ///     tag: "test".to_string(),
    ///     members: vec![
    ///         EcmpMember::new("m1".to_string()),
    ///         EcmpMember::new("m2".to_string()),
    ///     ],
    ///     algorithm: LbAlgorithm::RoundRobin,
    ///     ..Default::default()
    /// };
    /// let group = EcmpGroup::new(config).unwrap();
    ///
    /// let member = group.next_member().unwrap();
    /// assert!(member == "m1" || member == "m2");
    /// ```
    pub fn next_member(&self) -> Result<String, EcmpGroupError> {
        let members = self.members.read();

        // Build LbMember list
        let lb_members: Vec<LbMember> = members
            .iter()
            .enumerate()
            .map(|(i, m)| {
                LbMember::new(i)
                    .with_weight(m.config.weight)
                    .with_active_connections(m.active_connections.load(Ordering::Relaxed))
                    .with_healthy(m.healthy)
            })
            .collect();

        // For FiveTupleHash, fall back to RoundRobin when no tuple is provided
        let index = if matches!(self.config.algorithm, LbAlgorithm::FiveTupleHash) {
            // Use a fallback round-robin for API calls without connection info
            let healthy: Vec<&LbMember> = lb_members.iter().filter(|m| m.healthy).collect();
            if healthy.is_empty() {
                return Err(EcmpGroupError::NoHealthyMembers);
            }
            let counter = self.total_requests.fetch_add(1, Ordering::Relaxed);
            healthy[(counter as usize) % healthy.len()].index
        } else {
            // Increment total requests for non-FiveTupleHash algorithms
            self.total_requests.fetch_add(1, Ordering::Relaxed);
            self.load_balancer.select(&lb_members)?
        };

        Ok(members[index].config.tag.clone())
    }

    /// Select a member using five-tuple hash for connection affinity.
    ///
    /// The same five-tuple will always select the same healthy member.
    ///
    /// # Arguments
    ///
    /// * `five_tuple` - The connection's five-tuple
    ///
    /// # Returns
    ///
    /// The tag of the selected member.
    ///
    /// # Errors
    ///
    /// Returns `EcmpGroupError::NoHealthyMembers` if no healthy members are available.
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::ecmp::group::{EcmpGroup, EcmpGroupConfig, EcmpMember};
    /// use rust_router::ecmp::lb::{LbAlgorithm, FiveTuple, Protocol};
    ///
    /// let config = EcmpGroupConfig {
    ///     tag: "test".to_string(),
    ///     members: vec![
    ///         EcmpMember::new("m1".to_string()),
    ///         EcmpMember::new("m2".to_string()),
    ///     ],
    ///     algorithm: LbAlgorithm::FiveTupleHash,
    ///     ..Default::default()
    /// };
    /// let group = EcmpGroup::new(config).unwrap();
    ///
    /// let tuple = FiveTuple::new(
    ///     "10.0.0.1".parse().unwrap(),
    ///     "8.8.8.8".parse().unwrap(),
    ///     12345,
    ///     443,
    ///     Protocol::Tcp,
    /// );
    ///
    /// // Same tuple always returns same member
    /// let m1 = group.select_by_connection(&tuple).unwrap();
    /// let m2 = group.select_by_connection(&tuple).unwrap();
    /// assert_eq!(m1, m2);
    /// ```
    pub fn select_by_connection(&self, five_tuple: &FiveTuple) -> Result<String, EcmpGroupError> {
        let members = self.members.read();

        // Build LbMember list
        let lb_members: Vec<LbMember> = members
            .iter()
            .enumerate()
            .map(|(i, m)| {
                LbMember::new(i)
                    .with_weight(m.config.weight)
                    .with_active_connections(m.active_connections.load(Ordering::Relaxed))
                    .with_healthy(m.healthy)
            })
            .collect();

        // Use five-tuple hash selection (weighted or unweighted based on algorithm)
        let index = if matches!(self.config.algorithm, LbAlgorithm::Weighted) {
            self.load_balancer
                .select_by_five_tuple_weighted(&lb_members, five_tuple)?
        } else {
            self.load_balancer
                .select_by_five_tuple(&lb_members, five_tuple)?
        };

        // Increment total requests
        self.total_requests.fetch_add(1, Ordering::Relaxed);

        Ok(members[index].config.tag.clone())
    }

    /// Increment active connections for a member.
    ///
    /// Used for least-connections load balancing.
    ///
    /// # Arguments
    ///
    /// * `tag` - Member outbound tag
    ///
    /// # Errors
    ///
    /// Returns `EcmpGroupError::MemberNotFound` if the member doesn't exist.
    pub fn increment_connections(&self, tag: &str) -> Result<(), EcmpGroupError> {
        let members = self.members.read();
        let member = members
            .iter()
            .find(|m| m.config.tag == tag)
            .ok_or_else(|| EcmpGroupError::MemberNotFound(tag.to_string()))?;

        member.active_connections.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Decrement active connections for a member.
    ///
    /// Used for least-connections load balancing.
    ///
    /// # Arguments
    ///
    /// * `tag` - Member outbound tag
    ///
    /// # Errors
    ///
    /// Returns `EcmpGroupError::MemberNotFound` if the member doesn't exist.
    pub fn decrement_connections(&self, tag: &str) -> Result<(), EcmpGroupError> {
        let members = self.members.read();
        let member = members
            .iter()
            .find(|m| m.config.tag == tag)
            .ok_or_else(|| EcmpGroupError::MemberNotFound(tag.to_string()))?;

        // Use atomic fetch_update to avoid race condition (check-then-act)
        // This atomically decrements only if current > 0, preventing underflow
        let _ = member.active_connections.fetch_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |current| current.checked_sub(1),
        );
        Ok(())
    }

    /// Get active connections for a member.
    ///
    /// # Arguments
    ///
    /// * `tag` - Member outbound tag
    ///
    /// # Returns
    ///
    /// The number of active connections, or `None` if member not found.
    #[must_use]
    pub fn get_active_connections(&self, tag: &str) -> Option<u64> {
        let members = self.members.read();
        members
            .iter()
            .find(|m| m.config.tag == tag)
            .map(|m| m.active_connections.load(Ordering::Relaxed))
    }

    /// Update member health status
    ///
    /// # Arguments
    ///
    /// * `tag` - Member outbound tag
    /// * `healthy` - New health status
    ///
    /// # Errors
    ///
    /// Returns `EcmpGroupError::MemberNotFound` if the member doesn't exist.
    pub fn update_member_health(&self, tag: &str, healthy: bool) -> Result<(), EcmpGroupError> {
        let mut members = self.members.write();

        let member = members
            .iter_mut()
            .find(|m| m.config.tag == tag)
            .ok_or_else(|| EcmpGroupError::MemberNotFound(tag.to_string()))?;

        member.healthy = healthy;
        Ok(())
    }

    /// Check if a member is healthy.
    ///
    /// # Arguments
    ///
    /// * `tag` - Member outbound tag
    ///
    /// # Returns
    ///
    /// `Some(bool)` with health status, or `None` if member not found.
    #[must_use]
    pub fn is_member_healthy(&self, tag: &str) -> Option<bool> {
        let members = self.members.read();
        members.iter().find(|m| m.config.tag == tag).map(|m| m.healthy)
    }

    /// Add a new member to the group
    ///
    /// # Arguments
    ///
    /// * `member` - Member to add
    ///
    /// # Errors
    ///
    /// Returns `EcmpGroupError::InvalidWeight` if weight is zero.
    /// Returns `EcmpGroupError::MemberExists` if member already exists.
    pub fn add_member(&self, member: EcmpMember) -> Result<(), EcmpGroupError> {
        if member.weight == 0 {
            return Err(EcmpGroupError::InvalidWeight(0));
        }

        let mut members = self.members.write();

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
    ///
    /// # Errors
    ///
    /// Returns `EcmpGroupError::MemberNotFound` if member doesn't exist.
    pub fn remove_member(&self, tag: &str) -> Result<(), EcmpGroupError> {
        let mut members = self.members.write();

        let pos = members
            .iter()
            .position(|m| m.config.tag == tag)
            .ok_or_else(|| EcmpGroupError::MemberNotFound(tag.to_string()))?;

        members.remove(pos);
        Ok(())
    }

    /// Update member weight.
    ///
    /// # Arguments
    ///
    /// * `tag` - Member outbound tag
    /// * `weight` - New weight (must be > 0)
    ///
    /// # Errors
    ///
    /// Returns `EcmpGroupError::InvalidWeight` if weight is zero.
    /// Returns `EcmpGroupError::MemberNotFound` if member doesn't exist.
    pub fn update_member_weight(&self, tag: &str, weight: u32) -> Result<(), EcmpGroupError> {
        if weight == 0 {
            return Err(EcmpGroupError::InvalidWeight(0));
        }

        let mut members = self.members.write();

        let member = members
            .iter_mut()
            .find(|m| m.config.tag == tag)
            .ok_or_else(|| EcmpGroupError::MemberNotFound(tag.to_string()))?;

        member.config.weight = weight;
        Ok(())
    }

    /// Get statistics for the group
    #[must_use]
    pub fn stats(&self) -> EcmpGroupStats {
        let members = self.members.read();
        let member_count = members.len();
        let healthy_count = members.iter().filter(|s| s.healthy).count();
        let total_connections: u64 = members
            .iter()
            .map(|m| m.active_connections.load(Ordering::Relaxed))
            .sum();

        EcmpGroupStats {
            tag: self.config.tag.clone(),
            member_count,
            healthy_count,
            total_requests: self.total_requests.load(Ordering::Relaxed),
            total_connections,
            algorithm: self.config.algorithm.clone(),
        }
    }

    /// Get per-member statistics.
    #[must_use]
    pub fn member_stats(&self) -> Vec<MemberStats> {
        let members = self.members.read();
        members
            .iter()
            .map(|m| MemberStats {
                tag: m.config.tag.clone(),
                weight: m.config.weight,
                healthy: m.healthy,
                active_connections: m.active_connections.load(Ordering::Relaxed),
            })
            .collect()
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
    /// Total active connections across all members
    pub total_connections: u64,
    /// Load balancing algorithm
    pub algorithm: LbAlgorithm,
}

/// Statistics for a single member
#[derive(Debug, Clone)]
pub struct MemberStats {
    /// Member tag
    pub tag: String,
    /// Member weight
    pub weight: u32,
    /// Whether the member is healthy
    pub healthy: bool,
    /// Active connection count
    pub active_connections: u64,
}

/// Manager for multiple ECMP groups.
///
/// Handles group lifecycle and routing table allocation.
///
/// # Example
///
/// ```
/// use rust_router::ecmp::group::{EcmpGroupManager, EcmpGroupConfig, EcmpMember};
///
/// let manager = EcmpGroupManager::new();
///
/// let config = EcmpGroupConfig {
///     tag: "us-exits".to_string(),
///     members: vec![EcmpMember::new("member-1".to_string())],
///     ..Default::default()
/// };
///
/// manager.add_group(config).unwrap();
/// assert!(manager.get_group("us-exits").is_some());
/// ```
pub struct EcmpGroupManager {
    /// Registered groups
    groups: RwLock<HashMap<String, Arc<EcmpGroup>>>,
    /// Allocated routing tables (200-299)
    routing_table_allocator: RwLock<HashSet<u32>>,
}

impl EcmpGroupManager {
    /// Create a new ECMP group manager.
    #[must_use]
    pub fn new() -> Self {
        Self {
            groups: RwLock::new(HashMap::new()),
            routing_table_allocator: RwLock::new(HashSet::new()),
        }
    }

    /// Add a new ECMP group.
    ///
    /// # Arguments
    ///
    /// * `config` - Group configuration
    ///
    /// # Errors
    ///
    /// Returns `EcmpGroupError::GroupExists` if a group with the same tag exists.
    /// Returns other errors from `EcmpGroup::new()`.
    pub fn add_group(&self, mut config: EcmpGroupConfig) -> Result<(), EcmpGroupError> {
        let mut groups = self.groups.write();

        if groups.contains_key(&config.tag) {
            return Err(EcmpGroupError::GroupExists(config.tag));
        }

        // Auto-allocate routing table if not specified
        if config.routing_table.is_none() {
            config.routing_table = self.allocate_routing_table();
        } else if let Some(table) = config.routing_table {
            // Track explicitly specified routing table
            if table >= ECMP_ROUTING_TABLE_MIN && table <= ECMP_ROUTING_TABLE_MAX {
                self.routing_table_allocator.write().insert(table);
            }
        }

        // Auto-allocate routing mark if not specified (use same as table)
        if config.routing_mark.is_none() {
            config.routing_mark = config.routing_table;
        }

        let group = EcmpGroup::new(config.clone())?;
        groups.insert(config.tag, Arc::new(group));

        Ok(())
    }

    /// Remove an ECMP group.
    ///
    /// # Arguments
    ///
    /// * `tag` - Group tag to remove
    ///
    /// # Errors
    ///
    /// Returns `EcmpGroupError::GroupNotFound` if the group doesn't exist.
    pub fn remove_group(&self, tag: &str) -> Result<(), EcmpGroupError> {
        let mut groups = self.groups.write();

        let group = groups
            .remove(tag)
            .ok_or_else(|| EcmpGroupError::GroupNotFound(tag.to_string()))?;

        // Release routing table if allocated
        if let Some(table) = group.routing_table() {
            self.release_routing_table(table);
        }

        Ok(())
    }

    /// Get an ECMP group by tag.
    ///
    /// # Arguments
    ///
    /// * `tag` - Group tag
    ///
    /// # Returns
    ///
    /// `Some(Arc<EcmpGroup>)` if found, `None` otherwise.
    #[must_use]
    pub fn get_group(&self, tag: &str) -> Option<Arc<EcmpGroup>> {
        self.groups.read().get(tag).cloned()
    }

    /// List all group tags.
    #[must_use]
    pub fn list_groups(&self) -> Vec<String> {
        self.groups.read().keys().cloned().collect()
    }

    /// Get the number of registered groups.
    #[must_use]
    pub fn group_count(&self) -> usize {
        self.groups.read().len()
    }

    /// Check if a group exists.
    #[must_use]
    pub fn has_group(&self, tag: &str) -> bool {
        self.groups.read().contains_key(tag)
    }

    /// Allocate a routing table from the 200-299 range.
    ///
    /// # Returns
    ///
    /// `Some(table)` if available, `None` if all tables are allocated.
    #[must_use]
    pub fn allocate_routing_table(&self) -> Option<u32> {
        let mut allocated = self.routing_table_allocator.write();

        for table in ECMP_ROUTING_TABLE_MIN..=ECMP_ROUTING_TABLE_MAX {
            if !allocated.contains(&table) {
                allocated.insert(table);
                return Some(table);
            }
        }

        None
    }

    /// Release a routing table back to the pool.
    ///
    /// # Arguments
    ///
    /// * `table` - Table number to release
    pub fn release_routing_table(&self, table: u32) {
        if table >= ECMP_ROUTING_TABLE_MIN && table <= ECMP_ROUTING_TABLE_MAX {
            self.routing_table_allocator.write().remove(&table);
        }
    }

    /// Check if a routing table is allocated.
    #[must_use]
    pub fn is_routing_table_allocated(&self, table: u32) -> bool {
        self.routing_table_allocator.read().contains(&table)
    }

    /// Get the number of allocated routing tables.
    #[must_use]
    pub fn allocated_table_count(&self) -> usize {
        self.routing_table_allocator.read().len()
    }

    /// Get all group statistics.
    #[must_use]
    pub fn all_stats(&self) -> Vec<EcmpGroupStats> {
        self.groups
            .read()
            .values()
            .map(|g| g.stats())
            .collect()
    }

    /// Update member health across all groups.
    ///
    /// # Arguments
    ///
    /// * `tag` - Member outbound tag
    /// * `healthy` - New health status
    ///
    /// # Returns
    ///
    /// Number of groups updated.
    pub fn update_member_health_all(&self, tag: &str, healthy: bool) -> usize {
        let groups = self.groups.read();
        let mut updated = 0;

        for group in groups.values() {
            if group.update_member_health(tag, healthy).is_ok() {
                updated += 1;
            }
        }

        updated
    }
}

impl Default for EcmpGroupManager {
    fn default() -> Self {
        Self::new()
    }
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

    // ========================================================================
    // EcmpMember Tests
    // ========================================================================

    #[test]
    fn test_ecmp_member_new() {
        let member = EcmpMember::new("test".to_string());
        assert_eq!(member.tag, "test");
        assert_eq!(member.weight, 1);
    }

    #[test]
    fn test_ecmp_member_with_weight() {
        let member = EcmpMember::with_weight("test".to_string(), 5);
        assert_eq!(member.tag, "test");
        assert_eq!(member.weight, 5);
    }

    // ========================================================================
    // EcmpGroup Creation Tests
    // ========================================================================

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
    fn test_invalid_routing_mark_low() {
        let mut config = create_test_config();
        config.routing_mark = Some(100); // Out of range

        let result = EcmpGroup::new(config);
        assert!(matches!(result, Err(EcmpGroupError::InvalidRoutingMark(_))));
    }

    #[test]
    fn test_invalid_routing_mark_high() {
        let mut config = create_test_config();
        config.routing_mark = Some(300); // Out of range

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
    fn test_valid_routing_mark_boundaries() {
        let mut config = create_test_config();

        // Test minimum
        config.routing_mark = Some(200);
        assert!(EcmpGroup::new(config.clone()).is_ok());

        // Test maximum
        config.routing_mark = Some(299);
        assert!(EcmpGroup::new(config).is_ok());
    }

    // ========================================================================
    // EcmpGroup next_member Tests
    // ========================================================================

    #[test]
    fn test_next_member_round_robin() {
        let mut config = create_test_config();
        config.algorithm = LbAlgorithm::RoundRobin;
        let group = EcmpGroup::new(config).unwrap();

        let m1 = group.next_member().unwrap();
        let m2 = group.next_member().unwrap();
        let m3 = group.next_member().unwrap();

        // Round-robin should alternate
        assert!(m1 == "member-1" || m1 == "member-2");
        assert_ne!(m1, m2);
        assert_eq!(m1, m3);
    }

    #[test]
    fn test_next_member_weighted() {
        let config = EcmpGroupConfig {
            tag: "weighted-test".to_string(),
            members: vec![
                EcmpMember::with_weight("light".to_string(), 1),
                EcmpMember::with_weight("heavy".to_string(), 9),
            ],
            algorithm: LbAlgorithm::Weighted,
            ..Default::default()
        };
        let group = EcmpGroup::new(config).unwrap();

        let mut heavy_count = 0;
        for _ in 0..100 {
            if group.next_member().unwrap() == "heavy" {
                heavy_count += 1;
            }
        }

        // Heavy should be selected significantly more often
        assert!(heavy_count > 70, "Heavy member should be selected more often");
    }

    #[test]
    fn test_next_member_least_connections() {
        let config = EcmpGroupConfig {
            tag: "lc-test".to_string(),
            members: vec![
                EcmpMember::new("busy".to_string()),
                EcmpMember::new("idle".to_string()),
            ],
            algorithm: LbAlgorithm::LeastConnections,
            ..Default::default()
        };
        let group = EcmpGroup::new(config).unwrap();

        // Add connections to "busy"
        for _ in 0..10 {
            group.increment_connections("busy").unwrap();
        }

        // Should select "idle" (fewer connections)
        assert_eq!(group.next_member().unwrap(), "idle");
    }

    #[test]
    fn test_next_member_no_healthy() {
        let config = create_test_config();
        let group = EcmpGroup::new(config).unwrap();

        group.update_member_health("member-1", false).unwrap();
        group.update_member_health("member-2", false).unwrap();

        let result = group.next_member();
        assert!(matches!(result, Err(EcmpGroupError::NoHealthyMembers)));
    }

    #[test]
    fn test_next_member_skips_unhealthy() {
        let config = create_test_config();
        let group = EcmpGroup::new(config).unwrap();

        group.update_member_health("member-1", false).unwrap();

        // Should always return member-2
        for _ in 0..10 {
            assert_eq!(group.next_member().unwrap(), "member-2");
        }
    }

    #[test]
    fn test_next_member_five_tuple_hash_fallback() {
        let config = EcmpGroupConfig {
            tag: "hash-test".to_string(),
            members: vec![
                EcmpMember::new("m1".to_string()),
                EcmpMember::new("m2".to_string()),
            ],
            algorithm: LbAlgorithm::FiveTupleHash,
            ..Default::default()
        };
        let group = EcmpGroup::new(config).unwrap();

        // Should fall back to round-robin
        let m1 = group.next_member().unwrap();
        let m2 = group.next_member().unwrap();
        assert!(m1 == "m1" || m1 == "m2");
        assert_ne!(m1, m2);
    }

    // ========================================================================
    // EcmpGroup select_by_connection Tests
    // ========================================================================

    #[test]
    fn test_select_by_connection_affinity() {
        let config = EcmpGroupConfig {
            tag: "hash-test".to_string(),
            members: vec![
                EcmpMember::new("m1".to_string()),
                EcmpMember::new("m2".to_string()),
                EcmpMember::new("m3".to_string()),
            ],
            algorithm: LbAlgorithm::FiveTupleHash,
            ..Default::default()
        };
        let group = EcmpGroup::new(config).unwrap();

        let tuple = FiveTuple::new(
            "10.0.0.1".parse().unwrap(),
            "8.8.8.8".parse().unwrap(),
            12345,
            443,
            crate::ecmp::lb::Protocol::Tcp,
        );

        // Same tuple should always return same member
        let first = group.select_by_connection(&tuple).unwrap();
        for _ in 0..100 {
            assert_eq!(group.select_by_connection(&tuple).unwrap(), first);
        }
    }

    #[test]
    fn test_select_by_connection_different_tuples() {
        let config = EcmpGroupConfig {
            tag: "hash-test".to_string(),
            members: vec![
                EcmpMember::new("m1".to_string()),
                EcmpMember::new("m2".to_string()),
                EcmpMember::new("m3".to_string()),
            ],
            algorithm: LbAlgorithm::FiveTupleHash,
            ..Default::default()
        };
        let group = EcmpGroup::new(config).unwrap();

        let mut selections: HashMap<String, usize> = HashMap::new();

        for i in 0..300 {
            let tuple = FiveTuple::new(
                "10.0.0.1".parse().unwrap(),
                "8.8.8.8".parse().unwrap(),
                (10000 + i) as u16,
                443,
                crate::ecmp::lb::Protocol::Tcp,
            );
            let member = group.select_by_connection(&tuple).unwrap();
            *selections.entry(member).or_insert(0) += 1;
        }

        // Should distribute across all members
        assert!(selections.len() > 1, "Should select multiple members");
    }

    #[test]
    fn test_select_by_connection_weighted() {
        let config = EcmpGroupConfig {
            tag: "weighted-hash-test".to_string(),
            members: vec![
                EcmpMember::with_weight("light".to_string(), 1),
                EcmpMember::with_weight("heavy".to_string(), 3),
            ],
            algorithm: LbAlgorithm::Weighted,
            ..Default::default()
        };
        let group = EcmpGroup::new(config).unwrap();

        let tuple = FiveTuple::new(
            "10.0.0.1".parse().unwrap(),
            "8.8.8.8".parse().unwrap(),
            12345,
            443,
            crate::ecmp::lb::Protocol::Tcp,
        );

        // Should be deterministic
        let first = group.select_by_connection(&tuple).unwrap();
        for _ in 0..10 {
            assert_eq!(group.select_by_connection(&tuple).unwrap(), first);
        }
    }

    #[test]
    fn test_select_by_connection_skips_unhealthy() {
        let config = EcmpGroupConfig {
            tag: "hash-test".to_string(),
            members: vec![
                EcmpMember::new("m1".to_string()),
                EcmpMember::new("m2".to_string()),
            ],
            algorithm: LbAlgorithm::FiveTupleHash,
            ..Default::default()
        };
        let group = EcmpGroup::new(config).unwrap();

        group.update_member_health("m1", false).unwrap();

        let tuple = FiveTuple::new(
            "10.0.0.1".parse().unwrap(),
            "8.8.8.8".parse().unwrap(),
            12345,
            443,
            crate::ecmp::lb::Protocol::Tcp,
        );

        // Should always return m2
        for _ in 0..10 {
            assert_eq!(group.select_by_connection(&tuple).unwrap(), "m2");
        }
    }

    // ========================================================================
    // EcmpGroup Connection Tracking Tests
    // ========================================================================

    #[test]
    fn test_increment_connections() {
        let config = create_test_config();
        let group = EcmpGroup::new(config).unwrap();

        assert_eq!(group.get_active_connections("member-1"), Some(0));

        group.increment_connections("member-1").unwrap();
        group.increment_connections("member-1").unwrap();

        assert_eq!(group.get_active_connections("member-1"), Some(2));
    }

    #[test]
    fn test_decrement_connections() {
        let config = create_test_config();
        let group = EcmpGroup::new(config).unwrap();

        group.increment_connections("member-1").unwrap();
        group.increment_connections("member-1").unwrap();
        group.decrement_connections("member-1").unwrap();

        assert_eq!(group.get_active_connections("member-1"), Some(1));
    }

    #[test]
    fn test_decrement_connections_no_underflow() {
        let config = create_test_config();
        let group = EcmpGroup::new(config).unwrap();

        // Should not underflow
        group.decrement_connections("member-1").unwrap();
        assert_eq!(group.get_active_connections("member-1"), Some(0));
    }

    #[test]
    fn test_increment_connections_not_found() {
        let config = create_test_config();
        let group = EcmpGroup::new(config).unwrap();

        let result = group.increment_connections("nonexistent");
        assert!(matches!(result, Err(EcmpGroupError::MemberNotFound(_))));
    }

    #[test]
    fn test_decrement_connections_not_found() {
        let config = create_test_config();
        let group = EcmpGroup::new(config).unwrap();

        let result = group.decrement_connections("nonexistent");
        assert!(matches!(result, Err(EcmpGroupError::MemberNotFound(_))));
    }

    // ========================================================================
    // EcmpGroup Health Tests
    // ========================================================================

    #[test]
    fn test_update_member_health() {
        let config = create_test_config();
        let group = EcmpGroup::new(config).unwrap();

        assert_eq!(group.healthy_count(), 2);

        group.update_member_health("member-1", false).unwrap();
        assert_eq!(group.healthy_count(), 1);
        assert_eq!(group.is_member_healthy("member-1"), Some(false));
        assert_eq!(group.is_member_healthy("member-2"), Some(true));

        group.update_member_health("member-1", true).unwrap();
        assert_eq!(group.healthy_count(), 2);
    }

    #[test]
    fn test_update_member_health_not_found() {
        let config = create_test_config();
        let group = EcmpGroup::new(config).unwrap();

        let result = group.update_member_health("nonexistent", false);
        assert!(matches!(result, Err(EcmpGroupError::MemberNotFound(_))));
    }

    #[test]
    fn test_is_member_healthy_not_found() {
        let config = create_test_config();
        let group = EcmpGroup::new(config).unwrap();

        assert!(group.is_member_healthy("nonexistent").is_none());
    }

    // ========================================================================
    // EcmpGroup Member Management Tests
    // ========================================================================

    #[test]
    fn test_add_remove_member() {
        let config = create_test_config();
        let group = EcmpGroup::new(config).unwrap();

        assert_eq!(group.member_count(), 2);

        group
            .add_member(EcmpMember::new("member-3".to_string()))
            .unwrap();
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
    fn test_add_member_zero_weight() {
        let config = create_test_config();
        let group = EcmpGroup::new(config).unwrap();

        let result = group.add_member(EcmpMember::with_weight("new".to_string(), 0));
        assert!(matches!(result, Err(EcmpGroupError::InvalidWeight(0))));
    }

    #[test]
    fn test_remove_member_not_found() {
        let config = create_test_config();
        let group = EcmpGroup::new(config).unwrap();

        let result = group.remove_member("nonexistent");
        assert!(matches!(result, Err(EcmpGroupError::MemberNotFound(_))));
    }

    #[test]
    fn test_update_member_weight() {
        let config = create_test_config();
        let group = EcmpGroup::new(config).unwrap();

        group.update_member_weight("member-1", 5).unwrap();

        let stats = group.member_stats();
        let m1 = stats.iter().find(|m| m.tag == "member-1").unwrap();
        assert_eq!(m1.weight, 5);
    }

    #[test]
    fn test_update_member_weight_zero() {
        let config = create_test_config();
        let group = EcmpGroup::new(config).unwrap();

        let result = group.update_member_weight("member-1", 0);
        assert!(matches!(result, Err(EcmpGroupError::InvalidWeight(0))));
    }

    #[test]
    fn test_update_member_weight_not_found() {
        let config = create_test_config();
        let group = EcmpGroup::new(config).unwrap();

        let result = group.update_member_weight("nonexistent", 5);
        assert!(matches!(result, Err(EcmpGroupError::MemberNotFound(_))));
    }

    #[test]
    fn test_member_tags() {
        let config = create_test_config();
        let group = EcmpGroup::new(config).unwrap();

        let tags = group.member_tags();
        assert_eq!(tags.len(), 2);
        assert!(tags.contains(&"member-1".to_string()));
        assert!(tags.contains(&"member-2".to_string()));
    }

    // ========================================================================
    // EcmpGroup Stats Tests
    // ========================================================================

    #[test]
    fn test_stats() {
        let config = create_test_config();
        let group = EcmpGroup::new(config).unwrap();

        let stats = group.stats();
        assert_eq!(stats.tag, "test-group");
        assert_eq!(stats.member_count, 2);
        assert_eq!(stats.healthy_count, 2);
        assert_eq!(stats.total_requests, 0);
        assert_eq!(stats.total_connections, 0);
    }

    #[test]
    fn test_stats_after_operations() {
        let config = create_test_config();
        let group = EcmpGroup::new(config).unwrap();

        group.next_member().unwrap();
        group.next_member().unwrap();
        group.increment_connections("member-1").unwrap();
        group.update_member_health("member-2", false).unwrap();

        let stats = group.stats();
        assert_eq!(stats.healthy_count, 1);
        assert!(stats.total_requests > 0);
        assert_eq!(stats.total_connections, 1);
    }

    #[test]
    fn test_member_stats() {
        let config = create_test_config();
        let group = EcmpGroup::new(config).unwrap();

        group.increment_connections("member-1").unwrap();
        group.update_member_health("member-2", false).unwrap();

        let stats = group.member_stats();
        assert_eq!(stats.len(), 2);

        let m1 = stats.iter().find(|m| m.tag == "member-1").unwrap();
        assert_eq!(m1.active_connections, 1);
        assert!(m1.healthy);

        let m2 = stats.iter().find(|m| m.tag == "member-2").unwrap();
        assert_eq!(m2.active_connections, 0);
        assert!(!m2.healthy);
    }

    // ========================================================================
    // EcmpGroupManager Tests
    // ========================================================================

    #[test]
    fn test_manager_new() {
        let manager = EcmpGroupManager::new();
        assert_eq!(manager.group_count(), 0);
        assert!(manager.list_groups().is_empty());
    }

    #[test]
    fn test_manager_default() {
        let manager = EcmpGroupManager::default();
        assert_eq!(manager.group_count(), 0);
    }

    #[test]
    fn test_manager_add_group() {
        let manager = EcmpGroupManager::new();
        let config = create_test_config();

        manager.add_group(config).unwrap();

        assert_eq!(manager.group_count(), 1);
        assert!(manager.has_group("test-group"));
        assert!(manager.get_group("test-group").is_some());
    }

    #[test]
    fn test_manager_add_duplicate_group() {
        let manager = EcmpGroupManager::new();
        let config = create_test_config();

        manager.add_group(config.clone()).unwrap();
        let result = manager.add_group(config);

        assert!(matches!(result, Err(EcmpGroupError::GroupExists(_))));
    }

    #[test]
    fn test_manager_remove_group() {
        let manager = EcmpGroupManager::new();
        let config = create_test_config();

        manager.add_group(config).unwrap();
        manager.remove_group("test-group").unwrap();

        assert_eq!(manager.group_count(), 0);
        assert!(!manager.has_group("test-group"));
    }

    #[test]
    fn test_manager_remove_group_not_found() {
        let manager = EcmpGroupManager::new();

        let result = manager.remove_group("nonexistent");
        assert!(matches!(result, Err(EcmpGroupError::GroupNotFound(_))));
    }

    #[test]
    fn test_manager_get_group_not_found() {
        let manager = EcmpGroupManager::new();
        assert!(manager.get_group("nonexistent").is_none());
    }

    #[test]
    fn test_manager_list_groups() {
        let manager = EcmpGroupManager::new();

        let mut config1 = create_test_config();
        config1.tag = "group-1".to_string();
        config1.routing_table = Some(201);

        let mut config2 = create_test_config();
        config2.tag = "group-2".to_string();
        config2.routing_table = Some(202);

        manager.add_group(config1).unwrap();
        manager.add_group(config2).unwrap();

        let groups = manager.list_groups();
        assert_eq!(groups.len(), 2);
        assert!(groups.contains(&"group-1".to_string()));
        assert!(groups.contains(&"group-2".to_string()));
    }

    // ========================================================================
    // EcmpGroupManager Routing Table Allocation Tests
    // ========================================================================

    #[test]
    fn test_manager_allocate_routing_table() {
        let manager = EcmpGroupManager::new();

        let table1 = manager.allocate_routing_table();
        assert_eq!(table1, Some(200));
        assert!(manager.is_routing_table_allocated(200));

        let table2 = manager.allocate_routing_table();
        assert_eq!(table2, Some(201));
    }

    #[test]
    fn test_manager_release_routing_table() {
        let manager = EcmpGroupManager::new();

        manager.allocate_routing_table();
        manager.allocate_routing_table();

        assert_eq!(manager.allocated_table_count(), 2);

        manager.release_routing_table(200);
        assert_eq!(manager.allocated_table_count(), 1);
        assert!(!manager.is_routing_table_allocated(200));
    }

    #[test]
    fn test_manager_release_routing_table_out_of_range() {
        let manager = EcmpGroupManager::new();

        // Should not affect anything
        manager.release_routing_table(100);
        manager.release_routing_table(300);

        assert_eq!(manager.allocated_table_count(), 0);
    }

    #[test]
    fn test_manager_auto_allocate_routing_table() {
        let manager = EcmpGroupManager::new();

        let mut config = create_test_config();
        config.routing_table = None;
        config.routing_mark = None;

        manager.add_group(config).unwrap();

        let group = manager.get_group("test-group").unwrap();
        assert!(group.routing_table().is_some());
        assert!(group.routing_mark().is_some());
    }

    #[test]
    fn test_manager_routing_table_released_on_remove() {
        let manager = EcmpGroupManager::new();

        let config = create_test_config();
        manager.add_group(config).unwrap();

        assert!(manager.is_routing_table_allocated(200));

        manager.remove_group("test-group").unwrap();
        assert!(!manager.is_routing_table_allocated(200));
    }

    #[test]
    fn test_manager_routing_table_exhaustion() {
        let manager = EcmpGroupManager::new();

        // Allocate all tables
        for _ in 0..100 {
            manager.allocate_routing_table();
        }

        assert_eq!(manager.allocated_table_count(), 100);

        // Next allocation should fail
        assert!(manager.allocate_routing_table().is_none());
    }

    // ========================================================================
    // EcmpGroupManager Health Update Tests
    // ========================================================================

    #[test]
    fn test_manager_update_member_health_all() {
        let manager = EcmpGroupManager::new();

        // Create two groups with overlapping members
        let mut config1 = create_test_config();
        config1.tag = "group-1".to_string();
        config1.routing_table = Some(201);

        let mut config2 = create_test_config();
        config2.tag = "group-2".to_string();
        config2.routing_table = Some(202);

        manager.add_group(config1).unwrap();
        manager.add_group(config2).unwrap();

        // Update health for member-1 in all groups
        let updated = manager.update_member_health_all("member-1", false);
        assert_eq!(updated, 2);

        // Verify both groups updated
        let g1 = manager.get_group("group-1").unwrap();
        let g2 = manager.get_group("group-2").unwrap();
        assert_eq!(g1.healthy_count(), 1);
        assert_eq!(g2.healthy_count(), 1);
    }

    #[test]
    fn test_manager_update_member_health_all_not_found() {
        let manager = EcmpGroupManager::new();

        let config = create_test_config();
        manager.add_group(config).unwrap();

        let updated = manager.update_member_health_all("nonexistent", false);
        assert_eq!(updated, 0);
    }

    // ========================================================================
    // EcmpGroupManager Stats Tests
    // ========================================================================

    #[test]
    fn test_manager_all_stats() {
        let manager = EcmpGroupManager::new();

        let mut config1 = create_test_config();
        config1.tag = "group-1".to_string();
        config1.routing_table = Some(201);

        let mut config2 = create_test_config();
        config2.tag = "group-2".to_string();
        config2.routing_table = Some(202);

        manager.add_group(config1).unwrap();
        manager.add_group(config2).unwrap();

        let stats = manager.all_stats();
        assert_eq!(stats.len(), 2);
    }

    // ========================================================================
    // Error Tests
    // ========================================================================

    #[test]
    fn test_error_from_lb_error() {
        let err: EcmpGroupError = LbError::NoMembers.into();
        assert!(matches!(err, EcmpGroupError::NoHealthyMembers));

        let err: EcmpGroupError = LbError::ZeroWeight.into();
        assert!(matches!(err, EcmpGroupError::InvalidWeight(0)));

        let err: EcmpGroupError = LbError::MissingFiveTuple.into();
        assert!(matches!(err, EcmpGroupError::LoadBalancer(_)));

        let err: EcmpGroupError = LbError::Internal("test".into()).into();
        assert!(matches!(err, EcmpGroupError::Internal(_)));
    }

    #[test]
    fn test_error_display() {
        let err = EcmpGroupError::NoMembers;
        assert_eq!(err.to_string(), "ECMP group has no members");

        let err = EcmpGroupError::NoHealthyMembers;
        assert_eq!(err.to_string(), "No healthy members available");

        let err = EcmpGroupError::MemberNotFound("test".into());
        assert_eq!(err.to_string(), "Member not found: test");

        let err = EcmpGroupError::GroupNotFound("test".into());
        assert_eq!(err.to_string(), "Group not found: test");

        let err = EcmpGroupError::InvalidRoutingMark(100);
        assert!(err.to_string().contains("100"));
    }

    // ========================================================================
    // Concurrent Access Tests
    // ========================================================================

    #[test]
    fn test_concurrent_next_member() {
        use std::sync::Arc;
        use std::thread;

        let config = create_test_config();
        let group = Arc::new(EcmpGroup::new(config).unwrap());

        let mut handles = vec![];

        for _ in 0..4 {
            let g = Arc::clone(&group);
            handles.push(thread::spawn(move || {
                for _ in 0..1000 {
                    let _ = g.next_member();
                }
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        // Should have processed many requests without panic
        assert!(group.stats().total_requests > 0);
    }

    #[test]
    fn test_concurrent_health_updates() {
        use std::sync::Arc;
        use std::thread;

        let config = create_test_config();
        let group = Arc::new(EcmpGroup::new(config).unwrap());

        let mut handles = vec![];

        // Health update threads
        for i in 0..2 {
            let g = Arc::clone(&group);
            let member = if i == 0 { "member-1" } else { "member-2" };
            handles.push(thread::spawn(move || {
                for j in 0..100 {
                    let _ = g.update_member_health(member, j % 2 == 0);
                }
            }));
        }

        // Reader threads
        for _ in 0..2 {
            let g = Arc::clone(&group);
            handles.push(thread::spawn(move || {
                for _ in 0..100 {
                    let _ = g.next_member();
                }
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }
    }

    #[test]
    fn test_concurrent_connection_tracking() {
        use std::sync::Arc;
        use std::thread;

        let config = create_test_config();
        let group = Arc::new(EcmpGroup::new(config).unwrap());

        let mut handles = vec![];

        // Increment threads
        for _ in 0..2 {
            let g = Arc::clone(&group);
            handles.push(thread::spawn(move || {
                for _ in 0..500 {
                    let _ = g.increment_connections("member-1");
                }
            }));
        }

        // Decrement threads
        for _ in 0..2 {
            let g = Arc::clone(&group);
            handles.push(thread::spawn(move || {
                for _ in 0..500 {
                    let _ = g.decrement_connections("member-1");
                }
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        // Should be close to 0 (might not be exactly 0 due to race conditions)
        let conns = group.get_active_connections("member-1").unwrap();
        assert!(conns <= 1000); // Upper bound check
    }
}
