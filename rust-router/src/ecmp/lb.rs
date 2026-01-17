//! Load balancing algorithms for Phase 6
//!
//! This module implements various load balancing algorithms for ECMP
//! groups, including round-robin, weighted, least-connections, random,
//! five-tuple hash for connection affinity, and destination hash for
//! session affinity (video streaming).
//!
//! # Phase 6 Implementation Status
//!
//! - [x] 6.7 Round-robin algorithm
//! - [x] 6.7 Weighted round-robin
//! - [x] 6.7 Least connections
//! - [x] 6.7 Random selection
//! - [x] 6.7 Five-tuple hash (connection affinity)
//! - [x] 6.7 Destination hash (session affinity for video streaming)
//! - [x] 6.7 Destination hash with least-load (session affinity + smart LB)
//!
//! # Algorithms
//!
//! | Algorithm | Description |
//! |-----------|-------------|
//! | `FiveTupleHash` | Hash 5-tuple for connection affinity (DEFAULT) |
//! | `DestHash` | Hash destination (domain/IP) for session affinity |
//! | `DestHashLeastLoad` | Session affinity + intelligent load balancing |
//! | `RoundRobin` | Cycle through members sequentially |
//! | `Weighted` | Distribute based on member weights |
//! | `LeastConnections` | Select member with fewest active connections |
//! | `Random` | Random selection (no state) |
//!
//! # Example
//!
//! ```
//! use rust_router::ecmp::lb::{LoadBalancer, LbAlgorithm, FiveTuple, Protocol};
//! use std::net::IpAddr;
//!
//! let lb = LoadBalancer::new(LbAlgorithm::FiveTupleHash);
//! let five_tuple = FiveTuple {
//!     src_ip: "10.0.0.1".parse().unwrap(),
//!     dst_ip: "8.8.8.8".parse().unwrap(),
//!     src_port: 12345,
//!     dst_port: 443,
//!     protocol: Protocol::Tcp,
//! };
//! // Same 5-tuple always selects the same member (connection affinity)
//! ```
//!
//! # References
//!
//! - Implementation Plan: `docs/PHASE6_IMPLEMENTATION_PLAN_v3.2.md` Section 6.7

use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// Network protocol for five-tuple identification.
///
/// Used in `FiveTuple` to distinguish between TCP and UDP connections.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum Protocol {
    /// Transmission Control Protocol
    #[default]
    Tcp,
    /// User Datagram Protocol
    Udp,
}

impl Protocol {
    /// Create a Protocol from a string.
    ///
    /// # Arguments
    ///
    /// * `s` - Protocol string ("tcp" or "udp")
    ///
    /// # Returns
    ///
    /// `Some(Protocol)` if valid, `None` otherwise.
    #[must_use]
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "tcp" => Some(Self::Tcp),
            "udp" => Some(Self::Udp),
            _ => None,
        }
    }

    /// Get the protocol as a static string.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}


impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Five-tuple connection identifier for connection affinity.
///
/// The five-tuple uniquely identifies a connection and is used by
/// the `FiveTupleHash` algorithm to ensure the same connection
/// always routes to the same backend.
///
/// # Example
///
/// ```
/// use rust_router::ecmp::lb::{FiveTuple, Protocol};
/// use std::net::IpAddr;
///
/// let tuple = FiveTuple {
///     src_ip: "192.168.1.100".parse().unwrap(),
///     dst_ip: "8.8.8.8".parse().unwrap(),
///     src_port: 54321,
///     dst_port: 443,
///     protocol: Protocol::Tcp,
/// };
///
/// assert_eq!(tuple.protocol, Protocol::Tcp);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FiveTuple {
    /// Source IP address
    pub src_ip: IpAddr,
    /// Destination IP address
    pub dst_ip: IpAddr,
    /// Source port
    pub src_port: u16,
    /// Destination port
    pub dst_port: u16,
    /// Transport protocol (TCP or UDP)
    pub protocol: Protocol,
}

impl FiveTuple {
    /// Create a new `FiveTuple`.
    ///
    /// # Arguments
    ///
    /// * `src_ip` - Source IP address
    /// * `dst_ip` - Destination IP address
    /// * `src_port` - Source port
    /// * `dst_port` - Destination port
    /// * `protocol` - Transport protocol
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::ecmp::lb::{FiveTuple, Protocol};
    ///
    /// let tuple = FiveTuple::new(
    ///     "10.0.0.1".parse().unwrap(),
    ///     "8.8.8.8".parse().unwrap(),
    ///     12345,
    ///     443,
    ///     Protocol::Tcp,
    /// );
    /// ```
    #[must_use]
    pub const fn new(
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: u16,
        dst_port: u16,
        protocol: Protocol,
    ) -> Self {
        Self {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
        }
    }

    /// Create a `FiveTuple` from a `ConnectionInfo` and source port.
    ///
    /// This is a convenience method for creating a `FiveTuple` from
    /// the rule engine's `ConnectionInfo` type.
    ///
    /// # Arguments
    ///
    /// * `source_ip` - Source IP address
    /// * `dest_ip` - Destination IP address
    /// * `source_port` - Source port
    /// * `dest_port` - Destination port
    /// * `protocol` - Protocol string ("tcp" or "udp")
    ///
    /// # Returns
    ///
    /// `Some(FiveTuple)` if all addresses are available and protocol is valid,
    /// `None` otherwise.
    #[must_use]
    #[allow(clippy::similar_names)]
    pub fn from_connection(
        source_ip: Option<IpAddr>,
        dest_ip: Option<IpAddr>,
        source_port: u16,
        dest_port: u16,
        protocol: &str,
    ) -> Option<Self> {
        let src = source_ip?;
        let dst = dest_ip?;
        let proto = Protocol::from_str(protocol)?;

        Some(Self {
            src_ip: src,
            dst_ip: dst,
            src_port: source_port,
            dst_port: dest_port,
            protocol: proto,
        })
    }

    /// Compute a hash of this five-tuple.
    ///
    /// Uses `std::hash::DefaultHasher` for deterministic hashing
    /// within the same process.
    #[must_use]
    pub fn compute_hash(&self) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        let mut hasher = DefaultHasher::new();
        self.hash(&mut hasher);
        hasher.finish()
    }
}

impl std::fmt::Display for FiveTuple {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{}->{}:{}/{}",
            self.src_ip, self.src_port, self.dst_ip, self.dst_port, self.protocol
        )
    }
}

/// Destination key for session affinity.
///
/// Used by `DestHash` algorithm to ensure all connections from the same
/// client to the same destination (domain or IP) use the same exit.
/// This is useful for video streaming where a player opens multiple connections.
///
/// Hash is computed from: `source_ip + (domain OR dest_ip)`
///
/// This ensures:
/// - Same client to same domain → same exit (session affinity)
/// - Different clients to same domain → can use different exits (load balancing)
///
/// # Example
///
/// ```
/// use rust_router::ecmp::lb::DestKey;
/// use std::net::IpAddr;
///
/// // Same client, same domain, different CDN IPs → same hash
/// let key1 = DestKey::new("10.0.0.1".parse().unwrap(), Some("youtube.com"), "142.250.185.142".parse().unwrap());
/// let key2 = DestKey::new("10.0.0.1".parse().unwrap(), Some("youtube.com"), "142.250.185.143".parse().unwrap());
/// assert_eq!(key1.compute_hash(), key2.compute_hash());
///
/// // Different clients, same domain → different hash (load balanced)
/// let key3 = DestKey::new("10.0.0.2".parse().unwrap(), Some("youtube.com"), "142.250.185.142".parse().unwrap());
/// assert_ne!(key1.compute_hash(), key3.compute_hash());
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DestKey {
    /// Source IP address (client)
    pub source_ip: IpAddr,
    /// Domain name (from TLS SNI or QUIC SNI), if available
    pub domain: Option<String>,
    /// Destination IP address (used as fallback when domain not available)
    pub dest_ip: IpAddr,
}

impl DestKey {
    /// Create a new `DestKey`.
    ///
    /// # Arguments
    ///
    /// * `source_ip` - Source/client IP address
    /// * `domain` - Optional domain name (from SNI sniffing)
    /// * `dest_ip` - Destination IP address
    #[must_use]
    pub fn new(source_ip: IpAddr, domain: Option<&str>, dest_ip: IpAddr) -> Self {
        Self {
            source_ip,
            // Normalize domain: lowercase and remove trailing dot
            // This ensures case-insensitive matching (DNS is case-insensitive)
            domain: domain.map(|d| Self::normalize_domain(d)),
            dest_ip,
        }
    }

    /// Normalize a domain name for consistent hashing.
    ///
    /// - Converts to lowercase (DNS is case-insensitive)
    /// - Removes trailing dot (FQDN vs non-FQDN)
    fn normalize_domain(domain: &str) -> String {
        let lower = domain.to_lowercase();
        lower.trim_end_matches('.').to_string()
    }

    /// Compute a hash of this destination key.
    ///
    /// Hash includes source_ip + (domain OR dest_ip).
    /// This ensures same client to same destination always gets same exit,
    /// while different clients can be load balanced across exits.
    #[must_use]
    pub fn compute_hash(&self) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        let mut hasher = DefaultHasher::new();

        // Always include source IP for per-client affinity
        self.source_ip.hash(&mut hasher);

        if let Some(ref domain) = self.domain {
            // Hash source_ip + domain
            domain.hash(&mut hasher);
        } else {
            // Fallback: hash source_ip + dest_ip
            self.dest_ip.hash(&mut hasher);
        }

        hasher.finish()
    }

    /// Returns the key used for hashing (source:domain or source:ip).
    #[must_use]
    pub fn key_str(&self) -> String {
        if let Some(ref domain) = self.domain {
            format!("{}:{}", self.source_ip, domain)
        } else {
            format!("{}:{}", self.source_ip, self.dest_ip)
        }
    }
}

impl std::fmt::Display for DestKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(ref domain) = self.domain {
            write!(f, "{}->domain:{}", self.source_ip, domain)
        } else {
            write!(f, "{}->ip:{}", self.source_ip, self.dest_ip)
        }
    }
}

/// Load balancing algorithm
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum LbAlgorithm {
    /// Five-tuple hash: Connection affinity based on 5-tuple hash (DEFAULT)
    #[serde(rename = "five_tuple_hash")]
    #[default]
    FiveTupleHash,
    /// Destination hash: Hash destination (domain or IP) for session affinity.
    /// Useful for video streaming where multiple connections to the same domain
    /// should use the same exit.
    #[serde(rename = "dest_hash")]
    DestHash,
    /// Destination hash with least-load selection: For NEW sessions, select the
    /// exit with the lowest load. For EXISTING sessions, maintain affinity.
    /// This combines session affinity with intelligent load balancing.
    #[serde(rename = "dest_hash_least_load")]
    DestHashLeastLoad,
    /// Round-robin: Cycle through members sequentially
    RoundRobin,
    /// Weighted: Distribute based on member weights
    Weighted,
    /// Least connections: Select member with fewest active connections
    LeastConnections,
    /// Random: Random selection
    Random,
}


impl std::fmt::Display for LbAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FiveTupleHash => write!(f, "five_tuple_hash"),
            Self::DestHash => write!(f, "dest_hash"),
            Self::DestHashLeastLoad => write!(f, "dest_hash_least_load"),
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

    /// Missing five-tuple for hash algorithm
    #[error("FiveTupleHash algorithm requires a five-tuple")]
    MissingFiveTuple,

    /// Missing destination key for DestHash algorithm
    #[error("DestHash algorithm requires a destination key")]
    MissingDestKey,

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
    #[must_use]
    pub const fn new(index: usize) -> Self {
        Self {
            index,
            weight: 1,
            active_connections: 0,
            healthy: true,
        }
    }

    /// Set the weight
    #[must_use]
    pub const fn with_weight(mut self, weight: u32) -> Self {
        self.weight = weight;
        self
    }

    /// Set the active connections
    #[must_use]
    pub const fn with_active_connections(mut self, count: u64) -> Self {
        self.active_connections = count;
        self
    }

    /// Set the health status
    #[must_use]
    pub const fn with_healthy(mut self, healthy: bool) -> Self {
        self.healthy = healthy;
        self
    }
}

/// Load balancer implementation
///
/// Provides various load balancing algorithms for distributing
/// traffic across multiple backend members.
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
    #[must_use]
    pub fn new(algorithm: LbAlgorithm) -> Self {
        Self {
            algorithm,
            rr_counter: AtomicUsize::new(0),
        }
    }

    /// Get the algorithm
    #[must_use]
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
            LbAlgorithm::FiveTupleHash => Err(LbError::MissingFiveTuple),
            LbAlgorithm::DestHash | LbAlgorithm::DestHashLeastLoad => Err(LbError::MissingDestKey),
            LbAlgorithm::Weighted | LbAlgorithm::LeastConnections => Err(LbError::Internal(
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
            LbAlgorithm::FiveTupleHash => Err(LbError::MissingFiveTuple),
            LbAlgorithm::DestHash | LbAlgorithm::DestHashLeastLoad => Err(LbError::MissingDestKey),
        }
    }

    /// Select a member using five-tuple hash for connection affinity.
    ///
    /// The same five-tuple will always select the same member (as long as
    /// the member list and health status remain unchanged).
    ///
    /// # Arguments
    ///
    /// * `members` - List of member information
    /// * `five_tuple` - The connection's five-tuple
    ///
    /// # Returns
    ///
    /// Selected member index
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::ecmp::lb::{LoadBalancer, LbAlgorithm, LbMember, FiveTuple, Protocol};
    ///
    /// let lb = LoadBalancer::new(LbAlgorithm::FiveTupleHash);
    /// let members = vec![
    ///     LbMember::new(0),
    ///     LbMember::new(1),
    ///     LbMember::new(2),
    /// ];
    /// let tuple = FiveTuple::new(
    ///     "10.0.0.1".parse().unwrap(),
    ///     "8.8.8.8".parse().unwrap(),
    ///     12345,
    ///     443,
    ///     Protocol::Tcp,
    /// );
    ///
    /// // Same tuple always returns same member
    /// let idx1 = lb.select_by_five_tuple(&members, &tuple).unwrap();
    /// let idx2 = lb.select_by_five_tuple(&members, &tuple).unwrap();
    /// assert_eq!(idx1, idx2);
    /// ```
    pub fn select_by_five_tuple(
        &self,
        members: &[LbMember],
        five_tuple: &FiveTuple,
    ) -> Result<usize, LbError> {
        // Filter healthy members
        let healthy: Vec<&LbMember> = members.iter().filter(|m| m.healthy).collect();

        if healthy.is_empty() {
            return Err(LbError::NoMembers);
        }

        // Compute hash and select member
        let hash = five_tuple.compute_hash();
        let index = (hash as usize) % healthy.len();

        Ok(healthy[index].index)
    }

    /// Select a member using five-tuple hash with weighted distribution.
    ///
    /// Combines five-tuple hashing with member weights for deterministic
    /// weighted selection.
    ///
    /// # Arguments
    ///
    /// * `members` - List of member information
    /// * `five_tuple` - The connection's five-tuple
    ///
    /// # Returns
    ///
    /// Selected member index
    pub fn select_by_five_tuple_weighted(
        &self,
        members: &[LbMember],
        five_tuple: &FiveTuple,
    ) -> Result<usize, LbError> {
        // Filter healthy members
        let healthy: Vec<&LbMember> = members.iter().filter(|m| m.healthy).collect();

        if healthy.is_empty() {
            return Err(LbError::NoMembers);
        }

        let total_weight: u64 = healthy.iter().map(|m| u64::from(m.weight)).sum();

        if total_weight == 0 {
            return Err(LbError::ZeroWeight);
        }

        // Compute hash and map to weight range
        let hash = five_tuple.compute_hash();
        let target = hash % total_weight;

        let mut cumulative: u64 = 0;
        for member in &healthy {
            cumulative += u64::from(member.weight);
            if target < cumulative {
                return Ok(member.index);
            }
        }

        // Fallback to first member (should not happen)
        Ok(healthy[0].index)
    }

    /// Select a member using destination hash for session affinity.
    ///
    /// All connections to the same destination (domain or IP) will select
    /// the same healthy member. This is useful for video streaming where
    /// a player opens multiple connections to the same service.
    ///
    /// # Arguments
    ///
    /// * `members` - List of member information
    /// * `dest_key` - The destination key (domain or IP)
    ///
    /// # Returns
    ///
    /// Selected member index
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::ecmp::lb::{LoadBalancer, LbAlgorithm, LbMember, DestKey};
    ///
    /// let lb = LoadBalancer::new(LbAlgorithm::DestHash);
    /// let members = vec![
    ///     LbMember::new(0),
    ///     LbMember::new(1),
    ///     LbMember::new(2),
    /// ];
    ///
    /// // Same client + same domain → same member (even with different CDN IPs)
    /// let key1 = DestKey::new("10.0.0.1".parse().unwrap(), Some("youtube.com"), "142.250.185.142".parse().unwrap());
    /// let key2 = DestKey::new("10.0.0.1".parse().unwrap(), Some("youtube.com"), "142.250.185.143".parse().unwrap());
    /// let idx1 = lb.select_by_dest(&members, &key1).unwrap();
    /// let idx2 = lb.select_by_dest(&members, &key2).unwrap();
    /// assert_eq!(idx1, idx2);
    /// ```
    pub fn select_by_dest(
        &self,
        members: &[LbMember],
        dest_key: &DestKey,
    ) -> Result<usize, LbError> {
        // Filter healthy members
        let healthy: Vec<&LbMember> = members.iter().filter(|m| m.healthy).collect();

        if healthy.is_empty() {
            return Err(LbError::NoMembers);
        }

        // Compute hash and select member
        let hash = dest_key.compute_hash();
        let index = (hash as usize) % healthy.len();

        Ok(healthy[index].index)
    }

    /// Select a member using destination hash with weighted distribution.
    ///
    /// Combines destination hashing with member weights for deterministic
    /// weighted selection.
    ///
    /// # Arguments
    ///
    /// * `members` - List of member information
    /// * `dest_key` - The destination key (domain or IP)
    ///
    /// # Returns
    ///
    /// Selected member index
    pub fn select_by_dest_weighted(
        &self,
        members: &[LbMember],
        dest_key: &DestKey,
    ) -> Result<usize, LbError> {
        // Filter healthy members
        let healthy: Vec<&LbMember> = members.iter().filter(|m| m.healthy).collect();

        if healthy.is_empty() {
            return Err(LbError::NoMembers);
        }

        let total_weight: u64 = healthy.iter().map(|m| u64::from(m.weight)).sum();

        if total_weight == 0 {
            return Err(LbError::ZeroWeight);
        }

        // Compute hash and map to weight range
        let hash = dest_key.compute_hash();
        let target = hash % total_weight;

        let mut cumulative: u64 = 0;
        for member in &healthy {
            cumulative += u64::from(member.weight);
            if target < cumulative {
                return Ok(member.index);
            }
        }

        // Fallback to first member (should not happen)
        Ok(healthy[0].index)
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

    // ========================================================================
    // Protocol Tests
    // ========================================================================

    #[test]
    fn test_protocol_from_str() {
        assert_eq!(Protocol::from_str("tcp"), Some(Protocol::Tcp));
        assert_eq!(Protocol::from_str("TCP"), Some(Protocol::Tcp));
        assert_eq!(Protocol::from_str("udp"), Some(Protocol::Udp));
        assert_eq!(Protocol::from_str("UDP"), Some(Protocol::Udp));
        assert_eq!(Protocol::from_str("icmp"), None);
        assert_eq!(Protocol::from_str(""), None);
    }

    #[test]
    fn test_protocol_as_str() {
        assert_eq!(Protocol::Tcp.as_str(), "tcp");
        assert_eq!(Protocol::Udp.as_str(), "udp");
    }

    #[test]
    fn test_protocol_default() {
        assert_eq!(Protocol::default(), Protocol::Tcp);
    }

    #[test]
    fn test_protocol_display() {
        assert_eq!(format!("{}", Protocol::Tcp), "tcp");
        assert_eq!(format!("{}", Protocol::Udp), "udp");
    }

    #[test]
    fn test_protocol_serialize() {
        let tcp = Protocol::Tcp;
        let json = serde_json::to_string(&tcp).unwrap();
        assert_eq!(json, "\"tcp\"");

        let udp = Protocol::Udp;
        let json = serde_json::to_string(&udp).unwrap();
        assert_eq!(json, "\"udp\"");
    }

    #[test]
    fn test_protocol_deserialize() {
        let tcp: Protocol = serde_json::from_str("\"tcp\"").unwrap();
        assert_eq!(tcp, Protocol::Tcp);

        let udp: Protocol = serde_json::from_str("\"udp\"").unwrap();
        assert_eq!(udp, Protocol::Udp);
    }

    // ========================================================================
    // FiveTuple Tests
    // ========================================================================

    #[test]
    fn test_five_tuple_new() {
        let tuple = FiveTuple::new(
            "10.0.0.1".parse().unwrap(),
            "8.8.8.8".parse().unwrap(),
            12345,
            443,
            Protocol::Tcp,
        );

        assert_eq!(tuple.src_ip, "10.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(tuple.dst_ip, "8.8.8.8".parse::<IpAddr>().unwrap());
        assert_eq!(tuple.src_port, 12345);
        assert_eq!(tuple.dst_port, 443);
        assert_eq!(tuple.protocol, Protocol::Tcp);
    }

    #[test]
    fn test_five_tuple_from_connection() {
        let tuple = FiveTuple::from_connection(
            Some("10.0.0.1".parse().unwrap()),
            Some("8.8.8.8".parse().unwrap()),
            12345,
            443,
            "tcp",
        );

        assert!(tuple.is_some());
        let tuple = tuple.unwrap();
        assert_eq!(tuple.src_port, 12345);
        assert_eq!(tuple.dst_port, 443);
    }

    #[test]
    fn test_five_tuple_from_connection_missing_src_ip() {
        let tuple = FiveTuple::from_connection(None, Some("8.8.8.8".parse().unwrap()), 12345, 443, "tcp");
        assert!(tuple.is_none());
    }

    #[test]
    fn test_five_tuple_from_connection_missing_dst_ip() {
        let tuple = FiveTuple::from_connection(Some("10.0.0.1".parse().unwrap()), None, 12345, 443, "tcp");
        assert!(tuple.is_none());
    }

    #[test]
    fn test_five_tuple_from_connection_invalid_protocol() {
        let tuple = FiveTuple::from_connection(
            Some("10.0.0.1".parse().unwrap()),
            Some("8.8.8.8".parse().unwrap()),
            12345,
            443,
            "icmp",
        );
        assert!(tuple.is_none());
    }

    #[test]
    fn test_five_tuple_hash_deterministic() {
        let tuple1 = FiveTuple::new(
            "10.0.0.1".parse().unwrap(),
            "8.8.8.8".parse().unwrap(),
            12345,
            443,
            Protocol::Tcp,
        );

        let tuple2 = FiveTuple::new(
            "10.0.0.1".parse().unwrap(),
            "8.8.8.8".parse().unwrap(),
            12345,
            443,
            Protocol::Tcp,
        );

        assert_eq!(tuple1.compute_hash(), tuple2.compute_hash());
    }

    #[test]
    fn test_five_tuple_hash_different_src_port() {
        let tuple1 = FiveTuple::new(
            "10.0.0.1".parse().unwrap(),
            "8.8.8.8".parse().unwrap(),
            12345,
            443,
            Protocol::Tcp,
        );

        let tuple2 = FiveTuple::new(
            "10.0.0.1".parse().unwrap(),
            "8.8.8.8".parse().unwrap(),
            12346, // Different src port
            443,
            Protocol::Tcp,
        );

        assert_ne!(tuple1.compute_hash(), tuple2.compute_hash());
    }

    #[test]
    fn test_five_tuple_hash_different_dst_ip() {
        let tuple1 = FiveTuple::new(
            "10.0.0.1".parse().unwrap(),
            "8.8.8.8".parse().unwrap(),
            12345,
            443,
            Protocol::Tcp,
        );

        let tuple2 = FiveTuple::new(
            "10.0.0.1".parse().unwrap(),
            "8.8.4.4".parse().unwrap(), // Different dst IP
            12345,
            443,
            Protocol::Tcp,
        );

        assert_ne!(tuple1.compute_hash(), tuple2.compute_hash());
    }

    #[test]
    fn test_five_tuple_hash_different_protocol() {
        let tuple1 = FiveTuple::new(
            "10.0.0.1".parse().unwrap(),
            "8.8.8.8".parse().unwrap(),
            12345,
            443,
            Protocol::Tcp,
        );

        let tuple2 = FiveTuple::new(
            "10.0.0.1".parse().unwrap(),
            "8.8.8.8".parse().unwrap(),
            12345,
            443,
            Protocol::Udp, // Different protocol
        );

        assert_ne!(tuple1.compute_hash(), tuple2.compute_hash());
    }

    #[test]
    fn test_five_tuple_display() {
        let tuple = FiveTuple::new(
            "10.0.0.1".parse().unwrap(),
            "8.8.8.8".parse().unwrap(),
            12345,
            443,
            Protocol::Tcp,
        );

        assert_eq!(format!("{}", tuple), "10.0.0.1:12345->8.8.8.8:443/tcp");
    }

    #[test]
    fn test_five_tuple_ipv6() {
        let tuple = FiveTuple::new(
            "::1".parse().unwrap(),
            "2001:4860:4860::8888".parse().unwrap(),
            12345,
            443,
            Protocol::Tcp,
        );

        assert_eq!(tuple.src_ip, "::1".parse::<IpAddr>().unwrap());
        assert!(tuple.compute_hash() != 0);
    }

    #[test]
    fn test_five_tuple_equality() {
        let tuple1 = FiveTuple::new(
            "10.0.0.1".parse().unwrap(),
            "8.8.8.8".parse().unwrap(),
            12345,
            443,
            Protocol::Tcp,
        );

        let tuple2 = FiveTuple::new(
            "10.0.0.1".parse().unwrap(),
            "8.8.8.8".parse().unwrap(),
            12345,
            443,
            Protocol::Tcp,
        );

        let tuple3 = FiveTuple::new(
            "10.0.0.2".parse().unwrap(), // Different
            "8.8.8.8".parse().unwrap(),
            12345,
            443,
            Protocol::Tcp,
        );

        assert_eq!(tuple1, tuple2);
        assert_ne!(tuple1, tuple3);
    }

    // ========================================================================
    // LbAlgorithm Tests
    // ========================================================================

    #[test]
    fn test_lb_algorithm_default() {
        assert_eq!(LbAlgorithm::default(), LbAlgorithm::FiveTupleHash);
    }

    #[test]
    fn test_algorithm_display() {
        assert_eq!(LbAlgorithm::FiveTupleHash.to_string(), "five_tuple_hash");
        assert_eq!(LbAlgorithm::RoundRobin.to_string(), "round_robin");
        assert_eq!(LbAlgorithm::Weighted.to_string(), "weighted");
        assert_eq!(LbAlgorithm::LeastConnections.to_string(), "least_connections");
        assert_eq!(LbAlgorithm::Random.to_string(), "random");
    }

    #[test]
    fn test_lb_algorithm_serialize() {
        let algo = LbAlgorithm::FiveTupleHash;
        let json = serde_json::to_string(&algo).unwrap();
        assert_eq!(json, "\"five_tuple_hash\"");

        let algo = LbAlgorithm::RoundRobin;
        let json = serde_json::to_string(&algo).unwrap();
        assert_eq!(json, "\"round_robin\"");
    }

    #[test]
    fn test_lb_algorithm_deserialize() {
        let algo: LbAlgorithm = serde_json::from_str("\"five_tuple_hash\"").unwrap();
        assert_eq!(algo, LbAlgorithm::FiveTupleHash);

        let algo: LbAlgorithm = serde_json::from_str("\"round_robin\"").unwrap();
        assert_eq!(algo, LbAlgorithm::RoundRobin);
    }

    // ========================================================================
    // LbMember Tests
    // ========================================================================

    #[test]
    fn test_lb_member_new() {
        let member = LbMember::new(5);
        assert_eq!(member.index, 5);
        assert_eq!(member.weight, 1);
        assert_eq!(member.active_connections, 0);
        assert!(member.healthy);
    }

    #[test]
    fn test_lb_member_builders() {
        let member = LbMember::new(0)
            .with_weight(10)
            .with_active_connections(5)
            .with_healthy(false);

        assert_eq!(member.weight, 10);
        assert_eq!(member.active_connections, 5);
        assert!(!member.healthy);
    }

    // ========================================================================
    // LoadBalancer - Round Robin Tests
    // ========================================================================

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
        let members = vec![LbMember::new(0), LbMember::new(1), LbMember::new(2)];

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
    fn test_round_robin_single_healthy() {
        let lb = LoadBalancer::new(LbAlgorithm::RoundRobin);
        let members = vec![
            LbMember::new(0).with_healthy(false),
            LbMember::new(1),
            LbMember::new(2).with_healthy(false),
        ];

        // Should always select member 1
        for _ in 0..10 {
            assert_eq!(lb.select(&members).unwrap(), 1);
        }
    }

    // ========================================================================
    // LoadBalancer - Weighted Tests
    // ========================================================================

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
    fn test_weighted_distribution() {
        let lb = LoadBalancer::new(LbAlgorithm::Weighted);
        let members = vec![
            LbMember::new(0).with_weight(1),
            LbMember::new(1).with_weight(3), // Should be selected more often
        ];

        let mut counts = [0usize; 2];
        for _ in 0..100 {
            let index = lb.select(&members).unwrap();
            counts[index] += 1;
        }

        // Member 1 should be selected approximately 3x more than member 0
        // Allow for some variance
        assert!(counts[1] > counts[0]);
    }

    #[test]
    fn test_weighted_single_member() {
        let lb = LoadBalancer::new(LbAlgorithm::Weighted);
        let members = vec![LbMember::new(5).with_weight(10)];

        for _ in 0..10 {
            assert_eq!(lb.select(&members).unwrap(), 5);
        }
    }

    // ========================================================================
    // LoadBalancer - Least Connections Tests
    // ========================================================================

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
    fn test_least_connections_tie() {
        let lb = LoadBalancer::new(LbAlgorithm::LeastConnections);
        let members = vec![
            LbMember::new(0).with_active_connections(5),
            LbMember::new(1).with_active_connections(5),
            LbMember::new(2).with_active_connections(5),
        ];

        // Should select first one with minimum (implementation detail)
        let selected = lb.select(&members).unwrap();
        assert!(selected < 3);
    }

    #[test]
    fn test_least_connections_skips_unhealthy() {
        let lb = LoadBalancer::new(LbAlgorithm::LeastConnections);
        let members = vec![
            LbMember::new(0).with_active_connections(1).with_healthy(false),
            LbMember::new(1).with_active_connections(5),
            LbMember::new(2).with_active_connections(3),
        ];

        // Should select member 2 (least connections among healthy)
        assert_eq!(lb.select(&members).unwrap(), 2);
    }

    // ========================================================================
    // LoadBalancer - Random Tests
    // ========================================================================

    #[test]
    fn test_random() {
        let lb = LoadBalancer::new(LbAlgorithm::Random);
        let members = vec![LbMember::new(0), LbMember::new(1), LbMember::new(2)];

        // Just verify it returns valid indices
        for _ in 0..10 {
            let index = lb.select(&members).unwrap();
            assert!(index < 3);
        }
    }

    #[test]
    fn test_random_simple() {
        let lb = LoadBalancer::new(LbAlgorithm::Random);

        for _ in 0..10 {
            let index = lb.select_simple(5).unwrap();
            assert!(index < 5);
        }
    }

    #[test]
    fn test_random_distribution() {
        let lb = LoadBalancer::new(LbAlgorithm::Random);
        let members = vec![LbMember::new(0), LbMember::new(1), LbMember::new(2)];

        let mut counts = [0usize; 3];
        for _ in 0..300 {
            let index = lb.select(&members).unwrap();
            counts[index] += 1;
        }

        // Each should be selected at least once
        assert!(counts[0] > 0);
        assert!(counts[1] > 0);
        assert!(counts[2] > 0);
    }

    // ========================================================================
    // LoadBalancer - FiveTupleHash Tests
    // ========================================================================

    #[test]
    fn test_five_tuple_hash_connection_affinity() {
        let lb = LoadBalancer::new(LbAlgorithm::FiveTupleHash);
        let members = vec![LbMember::new(0), LbMember::new(1), LbMember::new(2)];

        let tuple = FiveTuple::new(
            "10.0.0.1".parse().unwrap(),
            "8.8.8.8".parse().unwrap(),
            12345,
            443,
            Protocol::Tcp,
        );

        // Same tuple should always select the same member
        let first = lb.select_by_five_tuple(&members, &tuple).unwrap();
        for _ in 0..100 {
            let idx = lb.select_by_five_tuple(&members, &tuple).unwrap();
            assert_eq!(idx, first);
        }
    }

    #[test]
    fn test_five_tuple_hash_different_tuples_distribute() {
        let lb = LoadBalancer::new(LbAlgorithm::FiveTupleHash);
        let members = vec![LbMember::new(0), LbMember::new(1), LbMember::new(2)];

        let mut counts = [0usize; 3];

        // Generate many different tuples
        for i in 0..300 {
            let tuple = FiveTuple::new(
                "10.0.0.1".parse().unwrap(),
                "8.8.8.8".parse().unwrap(),
                (10000 + i) as u16,
                443,
                Protocol::Tcp,
            );
            let idx = lb.select_by_five_tuple(&members, &tuple).unwrap();
            counts[idx] += 1;
        }

        // Should distribute across all members
        assert!(counts[0] > 0, "Member 0 should be selected at least once");
        assert!(counts[1] > 0, "Member 1 should be selected at least once");
        assert!(counts[2] > 0, "Member 2 should be selected at least once");
    }

    #[test]
    fn test_five_tuple_hash_skips_unhealthy() {
        let lb = LoadBalancer::new(LbAlgorithm::FiveTupleHash);
        let members = vec![
            LbMember::new(0).with_healthy(false),
            LbMember::new(1),
            LbMember::new(2).with_healthy(false),
        ];

        let tuple = FiveTuple::new(
            "10.0.0.1".parse().unwrap(),
            "8.8.8.8".parse().unwrap(),
            12345,
            443,
            Protocol::Tcp,
        );

        // Should always select member 1 (only healthy)
        for _ in 0..10 {
            let idx = lb.select_by_five_tuple(&members, &tuple).unwrap();
            assert_eq!(idx, 1);
        }
    }

    #[test]
    fn test_five_tuple_hash_no_healthy_members() {
        let lb = LoadBalancer::new(LbAlgorithm::FiveTupleHash);
        let members = vec![
            LbMember::new(0).with_healthy(false),
            LbMember::new(1).with_healthy(false),
        ];

        let tuple = FiveTuple::new(
            "10.0.0.1".parse().unwrap(),
            "8.8.8.8".parse().unwrap(),
            12345,
            443,
            Protocol::Tcp,
        );

        let result = lb.select_by_five_tuple(&members, &tuple);
        assert!(matches!(result, Err(LbError::NoMembers)));
    }

    #[test]
    fn test_five_tuple_hash_weighted() {
        let lb = LoadBalancer::new(LbAlgorithm::FiveTupleHash);
        let members = vec![
            LbMember::new(0).with_weight(1),
            LbMember::new(1).with_weight(3),
        ];

        let tuple = FiveTuple::new(
            "10.0.0.1".parse().unwrap(),
            "8.8.8.8".parse().unwrap(),
            12345,
            443,
            Protocol::Tcp,
        );

        // Deterministic selection based on hash + weight
        let first = lb.select_by_five_tuple_weighted(&members, &tuple).unwrap();
        for _ in 0..10 {
            let idx = lb.select_by_five_tuple_weighted(&members, &tuple).unwrap();
            assert_eq!(idx, first);
        }
    }

    #[test]
    fn test_five_tuple_hash_weighted_distribution() {
        let lb = LoadBalancer::new(LbAlgorithm::FiveTupleHash);
        let members = vec![
            LbMember::new(0).with_weight(1),
            LbMember::new(1).with_weight(3), // Should be selected more often
        ];

        let mut counts = [0usize; 2];

        for i in 0..400 {
            let tuple = FiveTuple::new(
                "10.0.0.1".parse().unwrap(),
                "8.8.8.8".parse().unwrap(),
                (10000 + i) as u16,
                443,
                Protocol::Tcp,
            );
            let idx = lb.select_by_five_tuple_weighted(&members, &tuple).unwrap();
            counts[idx] += 1;
        }

        // Member 1 should be selected approximately 3x more than member 0
        assert!(counts[1] > counts[0], "Weighted member should be selected more often");
    }

    #[test]
    fn test_five_tuple_hash_weighted_zero_weight() {
        let lb = LoadBalancer::new(LbAlgorithm::FiveTupleHash);
        let members = vec![
            LbMember::new(0).with_weight(0),
            LbMember::new(1).with_weight(0),
        ];

        let tuple = FiveTuple::new(
            "10.0.0.1".parse().unwrap(),
            "8.8.8.8".parse().unwrap(),
            12345,
            443,
            Protocol::Tcp,
        );

        let result = lb.select_by_five_tuple_weighted(&members, &tuple);
        assert!(matches!(result, Err(LbError::ZeroWeight)));
    }

    #[test]
    fn test_five_tuple_hash_select_simple_error() {
        let lb = LoadBalancer::new(LbAlgorithm::FiveTupleHash);
        let result = lb.select_simple(3);
        assert!(matches!(result, Err(LbError::MissingFiveTuple)));
    }

    #[test]
    fn test_five_tuple_hash_select_error() {
        let lb = LoadBalancer::new(LbAlgorithm::FiveTupleHash);
        let members = vec![LbMember::new(0), LbMember::new(1)];
        let result = lb.select(&members);
        assert!(matches!(result, Err(LbError::MissingFiveTuple)));
    }

    // ========================================================================
    // LoadBalancer - DestHash Tests (video streaming session affinity)
    // ========================================================================

    #[test]
    fn test_dest_hash_domain_affinity() {
        let lb = LoadBalancer::new(LbAlgorithm::DestHash);
        let members = vec![LbMember::new(0), LbMember::new(1), LbMember::new(2)];
        let client_ip: IpAddr = "10.0.0.1".parse().unwrap();

        // Same client + same domain with different CDN IPs should select the same member
        let key1 = DestKey::new(client_ip, Some("youtube.com"), "142.250.185.142".parse().unwrap());
        let key2 = DestKey::new(client_ip, Some("youtube.com"), "142.250.185.143".parse().unwrap());
        let key3 = DestKey::new(client_ip, Some("youtube.com"), "142.250.185.144".parse().unwrap());

        let idx1 = lb.select_by_dest(&members, &key1).unwrap();
        let idx2 = lb.select_by_dest(&members, &key2).unwrap();
        let idx3 = lb.select_by_dest(&members, &key3).unwrap();

        // All should be the same since client + domain is the same
        assert_eq!(idx1, idx2, "Same client+domain should select same member");
        assert_eq!(idx2, idx3, "Same client+domain should select same member");
    }

    #[test]
    fn test_dest_hash_different_clients_distribute() {
        let lb = LoadBalancer::new(LbAlgorithm::DestHash);
        let members = vec![LbMember::new(0), LbMember::new(1), LbMember::new(2)];

        // Different clients accessing same domain should distribute across members
        let mut selected = std::collections::HashSet::new();
        for i in 1..=20 {
            let client_ip: IpAddr = format!("10.0.0.{}", i).parse().unwrap();
            let key = DestKey::new(client_ip, Some("youtube.com"), "142.250.185.142".parse().unwrap());
            let idx = lb.select_by_dest(&members, &key).unwrap();
            selected.insert(idx);
        }

        // Should distribute across multiple members (load balancing)
        assert!(selected.len() > 1, "Different clients should distribute across members");
    }

    #[test]
    fn test_dest_hash_ip_fallback() {
        let lb = LoadBalancer::new(LbAlgorithm::DestHash);
        let members = vec![LbMember::new(0), LbMember::new(1), LbMember::new(2)];
        let client_ip: IpAddr = "10.0.0.1".parse().unwrap();

        // Without domain, should hash by client_ip + dest_ip
        let key1 = DestKey::new(client_ip, None, "8.8.8.8".parse().unwrap());
        let key2 = DestKey::new(client_ip, None, "8.8.8.8".parse().unwrap());

        let idx1 = lb.select_by_dest(&members, &key1).unwrap();
        let idx2 = lb.select_by_dest(&members, &key2).unwrap();

        // Same client + same dest IP should select same member
        assert_eq!(idx1, idx2);
    }

    #[test]
    fn test_dest_hash_different_domains_distribute() {
        let lb = LoadBalancer::new(LbAlgorithm::DestHash);
        let members = vec![LbMember::new(0), LbMember::new(1), LbMember::new(2)];
        let client_ip: IpAddr = "10.0.0.1".parse().unwrap();

        let domains = [
            "youtube.com",
            "netflix.com",
            "twitch.tv",
            "amazon.com",
            "google.com",
            "facebook.com",
            "twitter.com",
            "github.com",
            "reddit.com",
        ];

        let mut selected = std::collections::HashSet::new();
        for domain in &domains {
            let key = DestKey::new(client_ip, Some(domain), "1.1.1.1".parse().unwrap());
            let idx = lb.select_by_dest(&members, &key).unwrap();
            selected.insert(idx);
        }

        // Should distribute across multiple members
        assert!(selected.len() > 1, "Different domains should distribute across members");
    }

    #[test]
    fn test_dest_hash_skips_unhealthy() {
        let lb = LoadBalancer::new(LbAlgorithm::DestHash);
        let members = vec![
            LbMember::new(0).with_healthy(false),
            LbMember::new(1),
            LbMember::new(2).with_healthy(false),
        ];
        let client_ip: IpAddr = "10.0.0.1".parse().unwrap();

        let key = DestKey::new(client_ip, Some("youtube.com"), "142.250.185.142".parse().unwrap());

        // Should always select member 1 (only healthy)
        for _ in 0..10 {
            let idx = lb.select_by_dest(&members, &key).unwrap();
            assert_eq!(idx, 1);
        }
    }

    #[test]
    fn test_dest_hash_no_healthy_members() {
        let lb = LoadBalancer::new(LbAlgorithm::DestHash);
        let members = vec![
            LbMember::new(0).with_healthy(false),
            LbMember::new(1).with_healthy(false),
        ];
        let client_ip: IpAddr = "10.0.0.1".parse().unwrap();

        let key = DestKey::new(client_ip, Some("youtube.com"), "142.250.185.142".parse().unwrap());
        let result = lb.select_by_dest(&members, &key);
        assert!(matches!(result, Err(LbError::NoMembers)));
    }

    #[test]
    fn test_dest_hash_select_error() {
        let lb = LoadBalancer::new(LbAlgorithm::DestHash);
        let members = vec![LbMember::new(0), LbMember::new(1)];
        let result = lb.select(&members);
        assert!(matches!(result, Err(LbError::MissingDestKey)));
    }

    #[test]
    fn test_dest_key_compute_hash() {
        let client_ip: IpAddr = "10.0.0.1".parse().unwrap();

        // Same client + same domain with different dest IPs → same hash
        let key1 = DestKey::new(client_ip, Some("example.com"), "1.1.1.1".parse().unwrap());
        let key2 = DestKey::new(client_ip, Some("example.com"), "2.2.2.2".parse().unwrap());
        assert_eq!(key1.compute_hash(), key2.compute_hash());

        // Same client + different domains → different hash
        let key3 = DestKey::new(client_ip, Some("other.com"), "1.1.1.1".parse().unwrap());
        assert_ne!(key1.compute_hash(), key3.compute_hash());

        // Different clients + same domain → different hash (load balanced)
        let client_ip2: IpAddr = "10.0.0.2".parse().unwrap();
        let key4 = DestKey::new(client_ip2, Some("example.com"), "1.1.1.1".parse().unwrap());
        assert_ne!(key1.compute_hash(), key4.compute_hash());

        // Without domain, hash includes client + dest IP
        let key5 = DestKey::new(client_ip, None, "8.8.8.8".parse().unwrap());
        let key6 = DestKey::new(client_ip, None, "8.8.8.8".parse().unwrap());
        let key7 = DestKey::new(client_ip, None, "8.8.4.4".parse().unwrap());
        assert_eq!(key5.compute_hash(), key6.compute_hash());
        assert_ne!(key5.compute_hash(), key7.compute_hash());
    }

    #[test]
    fn test_dest_key_domain_normalization() {
        let client_ip: IpAddr = "10.0.0.1".parse().unwrap();

        // Case-insensitive: YouTube.COM == youtube.com
        let key1 = DestKey::new(client_ip, Some("YouTube.COM"), "1.1.1.1".parse().unwrap());
        let key2 = DestKey::new(client_ip, Some("youtube.com"), "1.1.1.1".parse().unwrap());
        assert_eq!(key1.compute_hash(), key2.compute_hash());
        assert_eq!(key1.domain, key2.domain); // Both normalized to lowercase

        // Trailing dot removal: example.com. == example.com
        let key3 = DestKey::new(client_ip, Some("example.com."), "1.1.1.1".parse().unwrap());
        let key4 = DestKey::new(client_ip, Some("example.com"), "1.1.1.1".parse().unwrap());
        assert_eq!(key3.compute_hash(), key4.compute_hash());
        assert_eq!(key3.domain, key4.domain);

        // Combined: EXAMPLE.COM. == example.com
        let key5 = DestKey::new(client_ip, Some("EXAMPLE.COM."), "1.1.1.1".parse().unwrap());
        assert_eq!(key5.compute_hash(), key4.compute_hash());
    }

    #[test]
    fn test_dest_key_display() {
        let client_ip: IpAddr = "10.0.0.1".parse().unwrap();

        let key1 = DestKey::new(client_ip, Some("youtube.com"), "1.1.1.1".parse().unwrap());
        assert_eq!(key1.to_string(), "10.0.0.1->domain:youtube.com");

        let key2 = DestKey::new(client_ip, None, "8.8.8.8".parse().unwrap());
        assert_eq!(key2.to_string(), "10.0.0.1->ip:8.8.8.8");
    }

    #[test]
    fn test_dest_key_key_str() {
        let client_ip: IpAddr = "10.0.0.1".parse().unwrap();

        let key1 = DestKey::new(client_ip, Some("example.com"), "1.1.1.1".parse().unwrap());
        assert_eq!(key1.key_str(), "10.0.0.1:example.com");

        let key2 = DestKey::new(client_ip, None, "8.8.8.8".parse().unwrap());
        assert_eq!(key2.key_str(), "10.0.0.1:8.8.8.8");
    }

    // ========================================================================
    // Error Cases
    // ========================================================================

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
    fn test_empty_members_slice() {
        let lb = LoadBalancer::new(LbAlgorithm::RoundRobin);
        let members: Vec<LbMember> = vec![];

        let result = lb.select(&members);
        assert!(matches!(result, Err(LbError::NoMembers)));
    }

    // ========================================================================
    // Reset and State Tests
    // ========================================================================

    #[test]
    fn test_reset() {
        let lb = LoadBalancer::new(LbAlgorithm::RoundRobin);

        assert_eq!(lb.select_simple(3).unwrap(), 0);
        assert_eq!(lb.select_simple(3).unwrap(), 1);

        lb.reset();

        assert_eq!(lb.select_simple(3).unwrap(), 0);
    }

    #[test]
    fn test_algorithm_getter() {
        let lb = LoadBalancer::new(LbAlgorithm::Weighted);
        assert_eq!(*lb.algorithm(), LbAlgorithm::Weighted);
    }

    // ========================================================================
    // LbError Tests
    // ========================================================================

    #[test]
    fn test_lb_error_display() {
        let err = LbError::NoMembers;
        assert_eq!(err.to_string(), "No members available");

        let err = LbError::ZeroWeight;
        assert_eq!(err.to_string(), "Invalid weights: total weight is zero");

        let err = LbError::MissingFiveTuple;
        assert_eq!(err.to_string(), "FiveTupleHash algorithm requires a five-tuple");

        let err = LbError::Internal("test error".into());
        assert_eq!(err.to_string(), "Internal error: test error");
    }

    // ========================================================================
    // Edge Cases
    // ========================================================================

    #[test]
    fn test_large_member_count() {
        let lb = LoadBalancer::new(LbAlgorithm::RoundRobin);
        let members: Vec<LbMember> = (0..1000).map(|i| LbMember::new(i)).collect();

        for i in 0..1000 {
            assert_eq!(lb.select(&members).unwrap(), i);
        }
    }

    #[test]
    fn test_counter_wraparound() {
        let lb = LoadBalancer::new(LbAlgorithm::RoundRobin);

        // Manually set counter near max
        lb.rr_counter.store(usize::MAX - 2, Ordering::Relaxed);

        // Should not panic on wraparound
        let _ = lb.select_simple(3);
        let _ = lb.select_simple(3);
        let _ = lb.select_simple(3);
        let _ = lb.select_simple(3);
    }

    #[test]
    fn test_five_tuple_hash_consistency_across_calls() {
        // Test that the hash is consistent across multiple LoadBalancer instances
        let lb1 = LoadBalancer::new(LbAlgorithm::FiveTupleHash);
        let lb2 = LoadBalancer::new(LbAlgorithm::FiveTupleHash);
        let members = vec![LbMember::new(0), LbMember::new(1), LbMember::new(2)];

        let tuple = FiveTuple::new(
            "192.168.1.100".parse().unwrap(),
            "172.16.0.1".parse().unwrap(),
            54321,
            8080,
            Protocol::Udp,
        );

        let idx1 = lb1.select_by_five_tuple(&members, &tuple).unwrap();
        let idx2 = lb2.select_by_five_tuple(&members, &tuple).unwrap();
        assert_eq!(idx1, idx2);
    }
}
