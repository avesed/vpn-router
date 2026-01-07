//! Load balancing algorithms for Phase 6
//!
//! This module implements various load balancing algorithms for ECMP
//! groups, including round-robin, weighted, and least-connections.
//!
//! # Phase 6 Implementation Status
//!
//! - [ ] 6.7 Round-robin algorithm
//! - [ ] 6.7 Weighted round-robin
//! - [ ] 6.7 Least connections
//! - [ ] 6.7 Random selection
//!
//! # Algorithms
//!
//! | Algorithm | Description |
//! |-----------|-------------|
//! | RoundRobin | Cycle through members sequentially |
//! | Weighted | Distribute based on member weights |
//! | LeastConnections | Select member with fewest active connections |
//! | Random | Random selection (no state) |
//!
//! # Example
//!
//! ```ignore
//! use rust_router::ecmp::lb::{LoadBalancer, LbAlgorithm};
//!
//! let lb = LoadBalancer::new(LbAlgorithm::RoundRobin);
//! let index = lb.select(members.len())?;
//! ```
//!
//! # References
//!
//! - Implementation Plan: `docs/PHASE6_IMPLEMENTATION_PLAN_v3.2.md` Section 6.7

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// Load balancing algorithm
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LbAlgorithm {
    /// Round-robin: Cycle through members sequentially
    RoundRobin,
    /// Weighted: Distribute based on member weights
    Weighted,
    /// Least connections: Select member with fewest active connections
    LeastConnections,
    /// Random: Random selection
    Random,
}

impl Default for LbAlgorithm {
    fn default() -> Self {
        Self::RoundRobin
    }
}

impl std::fmt::Display for LbAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RoundRobin => write!(f, "round_robin"),
            Self::Weighted => write!(f, "weighted"),
            Self::LeastConnections => write!(f, "least_connections"),
            Self::Random => write!(f, "random"),
        }
    }
}

/// Error types for load balancer operations
#[derive(Debug, Clone, thiserror::Error)]
pub enum LbError {
    /// No members to select from
    #[error("No members available")]
    NoMembers,

    /// Invalid weights
    #[error("Invalid weights: total weight is zero")]
    ZeroWeight,

    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),
}

/// Member information for load balancing
#[derive(Debug, Clone)]
pub struct LbMember {
    /// Member index
    pub index: usize,
    /// Member weight (for weighted algorithms)
    pub weight: u32,
    /// Active connection count (for least-connections)
    pub active_connections: u64,
    /// Whether the member is healthy
    pub healthy: bool,
}

impl LbMember {
    /// Create a new member with default values
    pub fn new(index: usize) -> Self {
        Self {
            index,
            weight: 1,
            active_connections: 0,
            healthy: true,
        }
    }

    /// Set the weight
    pub fn with_weight(mut self, weight: u32) -> Self {
        self.weight = weight;
        self
    }

    /// Set the active connections
    pub fn with_active_connections(mut self, count: u64) -> Self {
        self.active_connections = count;
        self
    }

    /// Set the health status
    pub fn with_healthy(mut self, healthy: bool) -> Self {
        self.healthy = healthy;
        self
    }
}

/// Load balancer implementation
///
/// TODO(Phase 6.7): Implement full load balancer
pub struct LoadBalancer {
    /// Selected algorithm
    algorithm: LbAlgorithm,
    /// Round-robin counter
    rr_counter: AtomicUsize,
}

impl LoadBalancer {
    /// Create a new load balancer
    ///
    /// # Arguments
    ///
    /// * `algorithm` - Load balancing algorithm to use
    pub fn new(algorithm: LbAlgorithm) -> Self {
        Self {
            algorithm,
            rr_counter: AtomicUsize::new(0),
        }
    }

    /// Get the algorithm
    pub fn algorithm(&self) -> &LbAlgorithm {
        &self.algorithm
    }

    /// Select the next member index using simple selection
    ///
    /// This method only uses the member count and is suitable for
    /// round-robin and random algorithms.
    ///
    /// # Arguments
    ///
    /// * `member_count` - Total number of members
    ///
    /// # Returns
    ///
    /// Selected member index
    pub fn select_simple(&self, member_count: usize) -> Result<usize, LbError> {
        if member_count == 0 {
            return Err(LbError::NoMembers);
        }

        match self.algorithm {
            LbAlgorithm::RoundRobin => {
                let index = self.rr_counter.fetch_add(1, Ordering::Relaxed) % member_count;
                Ok(index)
            }
            LbAlgorithm::Random => {
                // Use system time as entropy source combined with counter for randomness
                // This avoids needing external rand crate while providing decent distribution
                let counter = self.rr_counter.fetch_add(1, Ordering::Relaxed);
                let time_ns = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_nanos() as usize)
                    .unwrap_or(0);
                // XorShift-like mixing for better distribution
                let mut seed = counter.wrapping_add(time_ns);
                seed ^= seed >> 13;
                seed ^= seed << 7;
                seed ^= seed >> 17;
                let index = seed % member_count;
                Ok(index)
            }
            _ => Err(LbError::Internal(
                "Algorithm requires detailed member information".into(),
            )),
        }
    }

    /// Select the next member using full member information
    ///
    /// This method uses detailed member information for weighted
    /// and least-connections algorithms.
    ///
    /// # Arguments
    ///
    /// * `members` - List of member information
    ///
    /// # Returns
    ///
    /// Selected member index
    ///
    /// TODO(Phase 6.7): Implement weighted and least-connections
    pub fn select(&self, members: &[LbMember]) -> Result<usize, LbError> {
        // Filter healthy members
        let healthy: Vec<&LbMember> = members.iter().filter(|m| m.healthy).collect();

        if healthy.is_empty() {
            return Err(LbError::NoMembers);
        }

        match self.algorithm {
            LbAlgorithm::RoundRobin => {
                let index = self.rr_counter.fetch_add(1, Ordering::Relaxed) % healthy.len();
                Ok(healthy[index].index)
            }
            LbAlgorithm::Random => {
                // Use system time as entropy source combined with counter for randomness
                let counter = self.rr_counter.fetch_add(1, Ordering::Relaxed);
                let time_ns = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_nanos() as usize)
                    .unwrap_or(0);
                // XorShift-like mixing for better distribution
                let mut seed = counter.wrapping_add(time_ns);
                seed ^= seed >> 13;
                seed ^= seed << 7;
                seed ^= seed >> 17;
                let index = seed % healthy.len();
                Ok(healthy[index].index)
            }
            LbAlgorithm::Weighted => self.select_weighted(&healthy),
            LbAlgorithm::LeastConnections => self.select_least_connections(&healthy),
        }
    }

    /// Weighted selection
    fn select_weighted(&self, members: &[&LbMember]) -> Result<usize, LbError> {
        let total_weight: u64 = members.iter().map(|m| u64::from(m.weight)).sum();

        if total_weight == 0 {
            return Err(LbError::ZeroWeight);
        }

        // Use counter as pseudo-random source
        let counter = self.rr_counter.fetch_add(1, Ordering::Relaxed) as u64;
        let target = counter % total_weight;

        let mut cumulative: u64 = 0;
        for member in members {
            cumulative += u64::from(member.weight);
            if target < cumulative {
                return Ok(member.index);
            }
        }

        // Fallback to first member (should not happen)
        Ok(members[0].index)
    }

    /// Least connections selection
    fn select_least_connections(&self, members: &[&LbMember]) -> Result<usize, LbError> {
        let selected = members
            .iter()
            .min_by_key(|m| m.active_connections)
            .ok_or(LbError::NoMembers)?;

        Ok(selected.index)
    }

    /// Reset the round-robin counter
    pub fn reset(&self) {
        self.rr_counter.store(0, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_round_robin() {
        let lb = LoadBalancer::new(LbAlgorithm::RoundRobin);

        assert_eq!(lb.select_simple(3).unwrap(), 0);
        assert_eq!(lb.select_simple(3).unwrap(), 1);
        assert_eq!(lb.select_simple(3).unwrap(), 2);
        assert_eq!(lb.select_simple(3).unwrap(), 0);
    }

    #[test]
    fn test_round_robin_with_members() {
        let lb = LoadBalancer::new(LbAlgorithm::RoundRobin);
        let members = vec![
            LbMember::new(0),
            LbMember::new(1),
            LbMember::new(2),
        ];

        assert_eq!(lb.select(&members).unwrap(), 0);
        assert_eq!(lb.select(&members).unwrap(), 1);
        assert_eq!(lb.select(&members).unwrap(), 2);
        assert_eq!(lb.select(&members).unwrap(), 0);
    }

    #[test]
    fn test_round_robin_skips_unhealthy() {
        let lb = LoadBalancer::new(LbAlgorithm::RoundRobin);
        let members = vec![
            LbMember::new(0).with_healthy(false),
            LbMember::new(1),
            LbMember::new(2),
        ];

        // Should only select from healthy members (1 and 2)
        let selected1 = lb.select(&members).unwrap();
        let selected2 = lb.select(&members).unwrap();
        let selected3 = lb.select(&members).unwrap();

        assert!(selected1 == 1 || selected1 == 2);
        assert!(selected2 == 1 || selected2 == 2);
        assert_ne!(selected1, 0);
        assert_ne!(selected2, 0);
        assert_ne!(selected3, 0);
    }

    #[test]
    fn test_weighted() {
        let lb = LoadBalancer::new(LbAlgorithm::Weighted);
        let members = vec![
            LbMember::new(0).with_weight(1),
            LbMember::new(1).with_weight(2),
            LbMember::new(2).with_weight(1),
        ];

        // Just verify it doesn't panic and returns valid indices
        for _ in 0..10 {
            let index = lb.select(&members).unwrap();
            assert!(index < 3);
        }
    }

    #[test]
    fn test_least_connections() {
        let lb = LoadBalancer::new(LbAlgorithm::LeastConnections);
        let members = vec![
            LbMember::new(0).with_active_connections(10),
            LbMember::new(1).with_active_connections(5),
            LbMember::new(2).with_active_connections(8),
        ];

        // Should always select member 1 (5 connections)
        assert_eq!(lb.select(&members).unwrap(), 1);
    }

    #[test]
    fn test_no_members() {
        let lb = LoadBalancer::new(LbAlgorithm::RoundRobin);
        let result = lb.select_simple(0);
        assert!(matches!(result, Err(LbError::NoMembers)));
    }

    #[test]
    fn test_no_healthy_members() {
        let lb = LoadBalancer::new(LbAlgorithm::RoundRobin);
        let members = vec![
            LbMember::new(0).with_healthy(false),
            LbMember::new(1).with_healthy(false),
        ];

        let result = lb.select(&members);
        assert!(matches!(result, Err(LbError::NoMembers)));
    }

    #[test]
    fn test_zero_weight() {
        let lb = LoadBalancer::new(LbAlgorithm::Weighted);
        let members = vec![
            LbMember::new(0).with_weight(0),
            LbMember::new(1).with_weight(0),
        ];

        let result = lb.select(&members);
        assert!(matches!(result, Err(LbError::ZeroWeight)));
    }

    #[test]
    fn test_reset() {
        let lb = LoadBalancer::new(LbAlgorithm::RoundRobin);

        assert_eq!(lb.select_simple(3).unwrap(), 0);
        assert_eq!(lb.select_simple(3).unwrap(), 1);

        lb.reset();

        assert_eq!(lb.select_simple(3).unwrap(), 0);
    }

    #[test]
    fn test_algorithm_display() {
        assert_eq!(LbAlgorithm::RoundRobin.to_string(), "round_robin");
        assert_eq!(LbAlgorithm::Weighted.to_string(), "weighted");
        assert_eq!(LbAlgorithm::LeastConnections.to_string(), "least_connections");
        assert_eq!(LbAlgorithm::Random.to_string(), "random");
    }
}
