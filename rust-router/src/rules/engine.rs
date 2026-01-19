//! Integrated rule engine with hot-reload support.
//!
//! This module provides a hot-reloadable rule engine using `ArcSwap` for
//! lock-free reads during connection routing.
//!
//! # Architecture
//!
//! The engine maintains an immutable `RoutingSnapshot` that can be atomically
//! swapped for hot-reload without blocking any ongoing connection routing.
//!
//! ```text
//! Connection -> RuleEngine::match_connection() -> ArcSwap::load() -> RoutingSnapshot
//!                                                      |
//!                                               (lock-free read)
//!
//! Hot Reload -> RuleEngine::reload() -> ArcSwap::store() -> Old config dropped
//!                                             |               when readers finish
//!                                       (atomic swap)
//! ```
//!
//! # Example
//!
//! ```
//! use rust_router::rules::engine::{RuleEngine, RoutingSnapshot, RoutingSnapshotBuilder, ConnectionInfo};
//!
//! // Build initial snapshot
//! let mut builder = RoutingSnapshotBuilder::new();
//! builder
//!     .add_domain_rule(rust_router::RuleType::DomainSuffix, "google.com", "proxy")
//!     .unwrap();
//! let snapshot = builder.default_outbound("direct").version(1).build().unwrap();
//!
//! // Create engine
//! let engine = RuleEngine::new(snapshot);
//!
//! // Match connections (lock-free)
//! let conn = ConnectionInfo {
//!     domain: Some("www.google.com".to_string()),
//!     dest_ip: None,
//!     dest_port: 443,
//!     source_ip: None,
//!     protocol: "tcp",
//!     sniffed_protocol: Some("tls"),
//! };
//! let result = engine.match_connection(&conn);
//! assert_eq!(result.outbound, "proxy");
//! ```

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;

use arc_swap::{ArcSwap, Guard};

use super::{
    CompiledRuleSet, DomainMatcher, DomainMatcherBuilder, FwmarkRouter, FwmarkRouterBuilder,
    GeoIpMatcher, GeoIpMatcherBuilder, PortRange, Rule, RuleType,
};
use crate::chain::manager::DscpRoutingCallback;
use crate::error::RuleError;
use crate::ipc::ChainRole;

/// Connection metadata for rule matching.
///
/// Contains all relevant information about a connection that can be used
/// for routing decisions.
///
/// # Example
///
/// ```
/// use rust_router::rules::engine::ConnectionInfo;
/// use std::net::IpAddr;
///
/// let conn = ConnectionInfo {
///     domain: Some("example.com".to_string()),
///     dest_ip: Some("93.184.216.34".parse().unwrap()),
///     dest_port: 443,
///     source_ip: Some("10.0.0.100".parse().unwrap()),
///     protocol: "tcp",
///     sniffed_protocol: Some("tls"),
/// };
///
/// assert!(conn.domain.is_some());
/// assert_eq!(conn.dest_port, 443);
/// ```
#[derive(Debug, Clone, Default)]
pub struct ConnectionInfo {
    /// Destination domain (from TLS SNI or HTTP Host header).
    pub domain: Option<String>,

    /// Destination IP address.
    pub dest_ip: Option<IpAddr>,

    /// Destination port.
    pub dest_port: u16,

    /// Source IP address.
    pub source_ip: Option<IpAddr>,

    /// Transport protocol ("tcp" or "udp").
    pub protocol: &'static str,

    /// Sniffed application protocol ("tls", "http", "quic", "unknown").
    pub sniffed_protocol: Option<&'static str>,
}

impl ConnectionInfo {
    /// Create a new `ConnectionInfo` with minimal required fields.
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::rules::engine::ConnectionInfo;
    ///
    /// let conn = ConnectionInfo::new("tcp", 443);
    /// assert_eq!(conn.protocol, "tcp");
    /// assert_eq!(conn.dest_port, 443);
    /// ```
    #[must_use]
    pub const fn new(protocol: &'static str, dest_port: u16) -> Self {
        Self {
            domain: None,
            dest_ip: None,
            dest_port,
            source_ip: None,
            protocol,
            sniffed_protocol: None,
        }
    }

    /// Set the domain.
    #[must_use]
    pub fn with_domain(mut self, domain: impl Into<String>) -> Self {
        self.domain = Some(domain.into());
        self
    }

    /// Set the destination IP.
    #[must_use]
    pub const fn with_dest_ip(mut self, ip: IpAddr) -> Self {
        self.dest_ip = Some(ip);
        self
    }

    /// Set the source IP.
    #[must_use]
    pub const fn with_source_ip(mut self, ip: IpAddr) -> Self {
        self.source_ip = Some(ip);
        self
    }

    /// Set the sniffed protocol.
    #[must_use]
    pub const fn with_sniffed_protocol(mut self, protocol: &'static str) -> Self {
        self.sniffed_protocol = Some(protocol);
        self
    }
}

/// Hot-reloadable rule engine.
///
/// Uses `ArcSwap` to provide lock-free reads for connection matching while
/// allowing atomic configuration updates.
///
/// # Thread Safety
///
/// The engine is safe to share across threads. Reads are lock-free and
/// do not block writes. Configuration swaps are atomic and wait-free.
///
/// # Example
///
/// ```
/// use rust_router::rules::engine::{RuleEngine, RoutingSnapshot, RoutingSnapshotBuilder};
///
/// // Create initial configuration
/// let snapshot = RoutingSnapshotBuilder::new()
///     .default_outbound("direct")
///     .version(1)
///     .build()
///     .unwrap();
///
/// let engine = RuleEngine::new(snapshot);
///
/// // Hot reload with new configuration
/// let new_snapshot = RoutingSnapshotBuilder::new()
///     .default_outbound("proxy")
///     .version(2)
///     .build()
///     .unwrap();
///
/// engine.reload(new_snapshot);
/// assert_eq!(engine.version(), 2);
/// ```
pub struct RuleEngine {
    /// Current routing configuration (lock-free reads via `ArcSwap`).
    config: ArcSwap<RoutingSnapshot>,
}

impl RuleEngine {
    /// Create a new rule engine with initial configuration.
    ///
    /// # Arguments
    ///
    /// * `snapshot` - Initial routing configuration.
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::rules::engine::{RuleEngine, RoutingSnapshotBuilder};
    ///
    /// let snapshot = RoutingSnapshotBuilder::new()
    ///     .default_outbound("direct")
    ///     .build()
    ///     .unwrap();
    ///
    /// let engine = RuleEngine::new(snapshot);
    /// ```
    #[must_use]
    pub fn new(snapshot: RoutingSnapshot) -> Self {
        Self {
            config: ArcSwap::from_pointee(snapshot),
        }
    }

    /// Get current configuration snapshot (lock-free read).
    ///
    /// The returned `Guard` keeps the snapshot alive for the duration
    /// of its lifetime. This is useful for batch processing where you
    /// want to ensure consistent configuration across multiple matches.
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::rules::engine::{RuleEngine, RoutingSnapshotBuilder};
    ///
    /// let engine = RuleEngine::new(
    ///     RoutingSnapshotBuilder::new()
    ///         .default_outbound("direct")
    ///         .build()
    ///         .unwrap()
    /// );
    ///
    /// let snapshot = engine.load();
    /// // Use snapshot for multiple operations...
    /// println!("Default: {}", snapshot.default_outbound);
    /// ```
    pub fn load(&self) -> Guard<Arc<RoutingSnapshot>> {
        self.config.load()
    }

    /// Hot-reload configuration (atomic swap).
    ///
    /// The old configuration is dropped when all readers finish using it.
    /// This operation is wait-free for writers.
    ///
    /// # Arguments
    ///
    /// * `new_snapshot` - New routing configuration to swap in.
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::rules::engine::{RuleEngine, RoutingSnapshotBuilder};
    ///
    /// let engine = RuleEngine::new(
    ///     RoutingSnapshotBuilder::new()
    ///         .default_outbound("direct")
    ///         .version(1)
    ///         .build()
    ///         .unwrap()
    /// );
    ///
    /// // Reload with new config
    /// let new_snapshot = RoutingSnapshotBuilder::new()
    ///     .default_outbound("proxy")
    ///     .version(2)
    ///     .build()
    ///     .unwrap();
    ///
    /// engine.reload(new_snapshot);
    /// assert_eq!(engine.version(), 2);
    /// ```
    pub fn reload(&self, new_snapshot: RoutingSnapshot) {
        self.config.store(Arc::new(new_snapshot));
    }

    /// Match a connection and return the routing result.
    ///
    /// This method is lock-free and safe to call from multiple threads.
    ///
    /// # Priority Order
    ///
    /// 1. Domain rules (if domain available)
    /// 2. `GeoIP` rules (if `dest_ip` available)
    /// 3. Compiled rules (port, protocol)
    /// 4. Default outbound
    ///
    /// # Arguments
    ///
    /// * `conn` - Connection metadata for matching.
    ///
    /// # Returns
    ///
    /// A `MatchResult` containing the selected outbound and match details.
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::rules::engine::{RuleEngine, RoutingSnapshotBuilder, ConnectionInfo};
    ///
    /// let engine = RuleEngine::new(
    ///     RoutingSnapshotBuilder::new()
    ///         .default_outbound("direct")
    ///         .build()
    ///         .unwrap()
    /// );
    ///
    /// let conn = ConnectionInfo::new("tcp", 443);
    /// let result = engine.match_connection(&conn);
    /// assert_eq!(result.outbound, "direct");
    /// ```
    #[must_use]
    pub fn match_connection(&self, conn: &ConnectionInfo) -> MatchResult {
        let config = self.config.load();
        Self::match_with_snapshot(&config, conn)
    }

    /// Match using a specific snapshot (for batch processing).
    ///
    /// This is useful when you want to ensure consistent configuration
    /// across multiple connection matches.
    ///
    /// # Arguments
    ///
    /// * `snapshot` - The routing snapshot to use.
    /// * `conn` - Connection metadata for matching.
    #[must_use]
    pub fn match_with_snapshot(snapshot: &RoutingSnapshot, conn: &ConnectionInfo) -> MatchResult {
        // Priority 1: Domain rules (if domain available)
        if let Some(ref domain) = conn.domain {
            if let Some(outbound) = snapshot.domain_matcher.match_domain(domain) {
                return MatchResult {
                    outbound: outbound.to_string(),
                    matched_rule: Some(MatchedRule::Domain(domain.clone())),
                    routing_mark: snapshot.fwmark_router.get_routing_mark(outbound),
                };
            }
        }

        // Priority 2: GeoIP rules (if dest_ip available)
        if let Some(ip) = conn.dest_ip {
            if let Some(outbound) = snapshot.geoip_matcher.match_ip(ip) {
                return MatchResult {
                    outbound: outbound.to_string(),
                    matched_rule: Some(MatchedRule::GeoIP(ip)),
                    routing_mark: snapshot.fwmark_router.get_routing_mark(outbound),
                };
            }
        }

        // Priority 3: Compiled rules (port, protocol)
        if let Some((rule_id, outbound)) = snapshot.rules.match_connection(conn) {
            return MatchResult {
                outbound: outbound.to_string(),
                matched_rule: Some(MatchedRule::Rule(rule_id)),
                routing_mark: snapshot.fwmark_router.get_routing_mark(outbound),
            };
        }

        // Priority 4: Default outbound
        MatchResult {
            outbound: snapshot.default_outbound.clone(),
            matched_rule: None,
            routing_mark: snapshot
                .fwmark_router
                .get_routing_mark(&snapshot.default_outbound),
        }
    }

    /// Get current configuration version.
    ///
    /// Useful for debugging and logging to track which configuration
    /// is currently active.
    #[must_use]
    pub fn version(&self) -> u64 {
        self.config.load().version
    }

    /// Get the default outbound from current configuration.
    #[must_use]
    pub fn default_outbound(&self) -> String {
        self.config.load().default_outbound.clone()
    }

    /// Add a chain with the specified DSCP value.
    ///
    /// This atomically updates the routing configuration to include the new chain.
    ///
    /// # Arguments
    ///
    /// * `tag` - Unique chain identifier
    /// * `dscp` - DSCP value for this chain (1-63)
    ///
    /// # Errors
    ///
    /// Returns `RuleError` if:
    /// - The DSCP value is out of range
    /// - The chain tag already exists
    pub fn add_chain(&self, tag: &str, dscp: u8) -> Result<(), RuleError> {
        let current = self.config.load();
        
        // Clone the existing fwmark_router and add the new chain
        let mut fwmark_builder = FwmarkRouterBuilder::new();
        
        // Copy existing chains
        for (existing_tag, chain_mark) in current.fwmark_router.chains() {
            fwmark_builder = fwmark_builder
                .add_chain_with_dscp(existing_tag, chain_mark.dscp_value)?;
        }
        
        // Add the new chain
        fwmark_builder = fwmark_builder.add_chain_with_dscp(tag, dscp)?;
        
        // Build new snapshot with updated fwmark_router
        let new_snapshot = RoutingSnapshot {
            domain_matcher: current.domain_matcher.clone(),
            geoip_matcher: current.geoip_matcher.clone(),
            fwmark_router: fwmark_builder.build(),
            rules: current.rules.clone(),
            default_outbound: current.default_outbound.clone(),
            version: current.version + 1,
        };
        
        self.config.store(Arc::new(new_snapshot));
        Ok(())
    }

    /// Remove a chain from the routing configuration.
    ///
    /// # Arguments
    ///
    /// * `tag` - Chain identifier to remove
    ///
    /// # Returns
    ///
    /// Returns `true` if the chain was found and removed, `false` otherwise.
    pub fn remove_chain(&self, tag: &str) -> bool {
        let current = self.config.load();
        
        // Check if chain exists
        if current.fwmark_router.get_chain_mark(tag).is_none() {
            return false;
        }
        
        // Rebuild fwmark_router without the removed chain using fold
        // Note: add_chain_with_dscp should never fail here since we're copying
        // existing valid chains (excluding the one being removed)
        let fwmark_router = current
            .fwmark_router
            .chains()
            .filter(|(existing_tag, _)| *existing_tag != tag)
            .fold(FwmarkRouterBuilder::new(), |builder, (chain_tag, chain_mark)| {
                builder
                    .add_chain_with_dscp(chain_tag, chain_mark.dscp_value)
                    .expect("existing chain should have valid DSCP")
            })
            .build();
        
        // Build new snapshot with updated fwmark_router
        let new_snapshot = RoutingSnapshot {
            domain_matcher: current.domain_matcher.clone(),
            geoip_matcher: current.geoip_matcher.clone(),
            fwmark_router,
            rules: current.rules.clone(),
            default_outbound: current.default_outbound.clone(),
            version: current.version + 1,
        };
        
        self.config.store(Arc::new(new_snapshot));
        true
    }

    /// Check if a chain exists in the current configuration.
    #[must_use]
    pub fn has_chain(&self, tag: &str) -> bool {
        self.config.load().fwmark_router.get_chain_mark(tag).is_some()
    }
}

impl std::fmt::Debug for RuleEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let snapshot = self.config.load();
        f.debug_struct("RuleEngine")
            .field("version", &snapshot.version)
            .field("default_outbound", &snapshot.default_outbound)
            .field("domain_rules", &snapshot.domain_matcher.rule_count())
            .field("geoip_rules", &snapshot.geoip_matcher.rule_count())
            .field("compiled_rules", &snapshot.rules.len())
            .field("chains", &snapshot.fwmark_router.chain_count())
            .finish()
    }
}

/// Result of rule matching.
///
/// Contains the selected outbound and information about which rule matched.
#[derive(Debug, Clone)]
pub struct MatchResult {
    /// The outbound tag to use for this connection.
    pub outbound: String,

    /// Which rule matched (if any).
    ///
    /// `None` means the default outbound was used.
    pub matched_rule: Option<MatchedRule>,

    /// Routing mark for chain routing (if applicable).
    ///
    /// This is used for DSCP-based multi-hop chain routing.
    pub routing_mark: Option<u32>,
}

impl MatchResult {
    /// Check if this result used the default outbound.
    #[must_use]
    pub fn is_default(&self) -> bool {
        self.matched_rule.is_none()
    }

    /// Check if this result has a routing mark.
    #[must_use]
    pub fn has_routing_mark(&self) -> bool {
        self.routing_mark.is_some()
    }
}

/// Information about which rule matched.
#[derive(Debug, Clone)]
pub enum MatchedRule {
    /// Matched by domain rule.
    Domain(String),

    /// Matched by `GeoIP` rule.
    GeoIP(IpAddr),

    /// Matched by a compiled rule (rule ID).
    Rule(u64),
}

impl std::fmt::Display for MatchedRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Domain(d) => write!(f, "domain:{d}"),
            Self::GeoIP(ip) => write!(f, "geoip:{ip}"),
            Self::Rule(id) => write!(f, "rule:{id}"),
        }
    }
}

/// Immutable snapshot of routing configuration.
///
/// Contains all matchers and rules needed for routing decisions.
/// This struct is designed to be wrapped in `Arc` and swapped atomically.
#[derive(Debug)]
pub struct RoutingSnapshot {
    /// Domain matcher for domain-based rules.
    pub domain_matcher: DomainMatcher,

    /// `GeoIP` matcher for IP-based rules.
    pub geoip_matcher: GeoIpMatcher,

    /// Fwmark router for chain routing.
    pub fwmark_router: FwmarkRouter,

    /// Compiled rule set for priority-based matching.
    pub rules: CompiledRuleSet,

    /// Default outbound when no rules match.
    pub default_outbound: String,

    /// Configuration version (for debugging/logging).
    pub version: u64,
}

impl RoutingSnapshot {
    /// Create an empty snapshot with only a default outbound.
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::rules::engine::RoutingSnapshot;
    ///
    /// let snapshot = RoutingSnapshot::empty("direct");
    /// assert_eq!(snapshot.default_outbound, "direct");
    /// assert_eq!(snapshot.version, 0);
    /// ```
    #[must_use]
    pub fn empty(default_outbound: impl Into<String>) -> Self {
        Self {
            domain_matcher: DomainMatcher::empty(),
            geoip_matcher: GeoIpMatcher::empty(),
            fwmark_router: FwmarkRouter::empty(),
            rules: CompiledRuleSet::empty("direct".to_string()),
            default_outbound: default_outbound.into(),
            version: 0,
        }
    }

    /// Get summary statistics about this snapshot.
    #[must_use]
    pub fn stats(&self) -> SnapshotStats {
        SnapshotStats {
            domain_rules: self.domain_matcher.rule_count(),
            geoip_rules: self.geoip_matcher.rule_count(),
            compiled_rules: self.rules.len(),
            chains: self.fwmark_router.chain_count(),
            version: self.version,
        }
    }
}

/// Statistics about a routing snapshot.
#[derive(Debug, Clone, Copy)]
pub struct SnapshotStats {
    /// Number of domain rules.
    pub domain_rules: usize,

    /// Number of `GeoIP` rules.
    pub geoip_rules: usize,

    /// Number of compiled rules.
    pub compiled_rules: usize,

    /// Number of registered chains.
    pub chains: usize,

    /// Configuration version.
    pub version: u64,
}

/// Builder for `RoutingSnapshot`.
///
/// Provides a fluent API for constructing a routing configuration.
///
/// # Example
///
/// ```
/// use rust_router::rules::engine::RoutingSnapshotBuilder;
/// use rust_router::rules::RuleType;
///
/// let mut builder = RoutingSnapshotBuilder::new();
/// builder
///     .add_domain_rule(RuleType::DomainSuffix, "google.com", "proxy")
///     .unwrap()
///     .add_domain_rule(RuleType::DomainKeyword, "facebook", "proxy")
///     .unwrap();
///
/// let snapshot = builder
///     .default_outbound("direct")
///     .version(1)
///     .build()
///     .unwrap();
///
/// assert_eq!(snapshot.version, 1);
/// ```
pub struct RoutingSnapshotBuilder {
    domain_builder: DomainMatcherBuilder,
    geoip_builder: GeoIpMatcherBuilder,
    fwmark_builder: FwmarkRouterBuilder,
    rules: Vec<Rule>,
    default_outbound: String,
    version: u64,
    next_rule_id: u64,
}

impl RoutingSnapshotBuilder {
    /// Create a new builder with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self {
            domain_builder: DomainMatcherBuilder::new(),
            geoip_builder: GeoIpMatcherBuilder::new(),
            fwmark_builder: FwmarkRouterBuilder::new(),
            rules: Vec::new(),
            default_outbound: "direct".to_string(),
            version: 0,
            next_rule_id: 1,
        }
    }

    /// Set the default outbound.
    ///
    /// This is used when no rules match a connection.
    #[must_use]
    pub fn default_outbound(mut self, outbound: impl Into<String>) -> Self {
        self.default_outbound = outbound.into();
        self
    }

    /// Set the configuration version.
    ///
    /// Useful for tracking configuration changes.
    #[must_use]
    pub const fn version(mut self, version: u64) -> Self {
        self.version = version;
        self
    }

    /// Add a domain rule.
    ///
    /// # Arguments
    ///
    /// * `rule_type` - Type of domain matching (`Domain`, `DomainSuffix`, `DomainKeyword`, `DomainRegex`)
    /// * `target` - Domain pattern to match
    /// * `outbound` - Outbound tag for matching connections
    ///
    /// # Errors
    ///
    /// Returns `RuleError::InvalidRegex` if `rule_type` is `DomainRegex` and the pattern is invalid.
    /// Returns `RuleError::InvalidTarget` if the rule type is not a domain type.
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::rules::engine::RoutingSnapshotBuilder;
    /// use rust_router::rules::RuleType;
    ///
    /// let mut builder = RoutingSnapshotBuilder::new();
    /// builder
    ///     .add_domain_rule(RuleType::DomainSuffix, "google.com", "proxy")
    ///     .unwrap();
    /// ```
    pub fn add_domain_rule(
        &mut self,
        rule_type: RuleType,
        target: &str,
        outbound: &str,
    ) -> Result<&mut Self, RuleError> {
        match rule_type {
            RuleType::Domain => {
                self.domain_builder = std::mem::take(&mut self.domain_builder)
                    .add_exact(target, outbound);
            }
            RuleType::DomainSuffix => {
                self.domain_builder = std::mem::take(&mut self.domain_builder)
                    .add_suffix(target, outbound);
            }
            RuleType::DomainKeyword => {
                self.domain_builder = std::mem::take(&mut self.domain_builder)
                    .add_keyword(target, outbound);
            }
            RuleType::DomainRegex => {
                self.domain_builder =
                    std::mem::take(&mut self.domain_builder).add_regex(target, outbound)?;
            }
            _ => {
                return Err(RuleError::InvalidTarget(format!(
                    "rule type {rule_type} is not a domain type"
                )));
            }
        }
        Ok(self)
    }

    /// Add a `GeoIP` rule.
    ///
    /// # Arguments
    ///
    /// * `rule_type` - Type of IP matching (`GeoIP` or `IpCidr`)
    /// * `target` - Country code (for `GeoIP`) or CIDR notation (for `IpCidr`)
    /// * `outbound` - Outbound tag for matching connections
    ///
    /// # Errors
    ///
    /// Returns `RuleError::InvalidCidr` if `rule_type` is `IpCidr` and the CIDR is invalid.
    /// Returns `RuleError::UnknownCountry` if the country code is not in the catalog.
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::rules::engine::RoutingSnapshotBuilder;
    /// use rust_router::rules::RuleType;
    ///
    /// let mut builder = RoutingSnapshotBuilder::new();
    /// builder
    ///     .add_geoip_rule(RuleType::IpCidr, "192.168.0.0/16", "direct")
    ///     .unwrap();
    /// ```
    pub fn add_geoip_rule(
        &mut self,
        rule_type: RuleType,
        target: &str,
        outbound: &str,
    ) -> Result<&mut Self, RuleError> {
        match rule_type {
            RuleType::IpCidr => {
                self.geoip_builder =
                    std::mem::take(&mut self.geoip_builder).add_cidr(target, outbound)?;
            }
            RuleType::GeoIP => {
                self.geoip_builder =
                    std::mem::take(&mut self.geoip_builder).add_country(target, outbound)?;
            }
            _ => {
                return Err(RuleError::InvalidTarget(format!(
                    "rule type {rule_type} is not a GeoIP type"
                )));
            }
        }
        Ok(self)
    }

    /// Add a port rule.
    ///
    /// # Arguments
    ///
    /// * `port_spec` - Port specification (e.g., "443" or "80-443")
    /// * `outbound` - Outbound tag for matching connections
    ///
    /// # Errors
    ///
    /// Returns `RuleError` if the port specification is invalid.
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::rules::engine::RoutingSnapshotBuilder;
    ///
    /// let mut builder = RoutingSnapshotBuilder::new();
    /// builder.add_port_rule("443", "https-proxy").unwrap();
    /// builder.add_port_rule("80-8080", "http-proxy").unwrap();
    /// ```
    pub fn add_port_rule(
        &mut self,
        port_spec: &str,
        outbound: &str,
    ) -> Result<&mut Self, RuleError> {
        // Validate port specification
        let _ = PortRange::parse(port_spec)?;

        let rule = Rule::new(
            self.next_rule_id,
            RuleType::Port,
            port_spec.to_string(),
            outbound.to_string(),
        );
        self.next_rule_id += 1;
        self.rules.push(rule);
        Ok(self)
    }

    /// Add a protocol rule.
    ///
    /// # Arguments
    ///
    /// * `protocol` - Protocol to match ("tcp" or "udp")
    /// * `outbound` - Outbound tag for matching connections
    ///
    /// # Errors
    ///
    /// Returns `RuleError::InvalidTarget` if the protocol is not "tcp" or "udp".
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::rules::engine::RoutingSnapshotBuilder;
    ///
    /// let mut builder = RoutingSnapshotBuilder::new();
    /// builder.add_protocol_rule("tcp", "tcp-handler").unwrap();
    /// ```
    pub fn add_protocol_rule(
        &mut self,
        protocol: &str,
        outbound: &str,
    ) -> Result<&mut Self, RuleError> {
        let proto_lower = protocol.to_lowercase();
        if proto_lower != "tcp" && proto_lower != "udp" {
            return Err(RuleError::InvalidTarget(format!(
                "protocol must be 'tcp' or 'udp': {protocol}"
            )));
        }

        let rule = Rule::new(
            self.next_rule_id,
            RuleType::Protocol,
            proto_lower,
            outbound.to_string(),
        );
        self.next_rule_id += 1;
        self.rules.push(rule);
        Ok(self)
    }

    /// Add a raw rule with full control.
    ///
    /// # Arguments
    ///
    /// * `rule` - The rule to add
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::rules::{Rule, RuleType};
    /// use rust_router::rules::engine::RoutingSnapshotBuilder;
    ///
    /// let mut builder = RoutingSnapshotBuilder::new();
    /// let rule = Rule::new(100, RuleType::Port, "443".into(), "proxy".into())
    ///     .with_priority(-10);
    /// builder.add_rule(rule);
    /// ```
    pub fn add_rule(&mut self, rule: Rule) -> &mut Self {
        self.rules.push(rule);
        self
    }

    /// Add a chain for multi-hop routing.
    ///
    /// # Arguments
    ///
    /// * `tag` - Chain tag (must be unique)
    ///
    /// # Errors
    ///
    /// Returns `RuleError::DuplicateChain` if the tag already exists.
    /// Returns `RuleError::MaxChainsReached` if 63 chains are already registered.
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::rules::engine::RoutingSnapshotBuilder;
    ///
    /// let mut builder = RoutingSnapshotBuilder::new();
    /// builder.add_chain("us-stream").unwrap();
    /// builder.add_chain("jp-gaming").unwrap();
    /// ```
    pub fn add_chain(&mut self, tag: &str) -> Result<&mut Self, RuleError> {
        self.fwmark_builder = std::mem::take(&mut self.fwmark_builder).add_chain(tag)?;
        Ok(self)
    }

    /// Add a chain with a specific DSCP value.
    ///
    /// # Arguments
    ///
    /// * `tag` - Chain tag (must be unique)
    /// * `dscp` - DSCP value (1-63)
    ///
    /// # Errors
    ///
    /// Returns `RuleError::DuplicateChain` if the tag already exists.
    /// Returns `RuleError::DscpOutOfRange` if DSCP is not in 1-63.
    /// Returns `RuleError::DscpInUse` if the DSCP value is already used.
    pub fn add_chain_with_dscp(&mut self, tag: &str, dscp: u8) -> Result<&mut Self, RuleError> {
        self.fwmark_builder =
            std::mem::take(&mut self.fwmark_builder).add_chain_with_dscp(tag, dscp)?;
        Ok(self)
    }

    /// Set the `GeoIP` directory for lazy loading.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the directory containing country JSON files
    #[must_use]
    pub fn geoip_dir(mut self, path: impl Into<PathBuf>) -> Self {
        self.geoip_builder = self.geoip_builder.geoip_dir(path);
        self
    }

    /// Load the `GeoIP` catalog.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the geoip-catalog.json file
    ///
    /// # Errors
    ///
    /// Returns `RuleError::GeoIpLoadError` if the file cannot be read.
    pub fn load_geoip_catalog(
        mut self,
        path: impl AsRef<std::path::Path>,
    ) -> Result<Self, RuleError> {
        self.geoip_builder = self.geoip_builder.load_catalog(path)?;
        Ok(self)
    }

    /// Build the routing snapshot.
    ///
    /// # Errors
    ///
    /// Returns `RuleError` if:
    /// - Domain matcher fails to build
    /// - `GeoIP` matcher fails to build
    /// - Compiled rules have validation errors
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::rules::engine::RoutingSnapshotBuilder;
    ///
    /// let snapshot = RoutingSnapshotBuilder::new()
    ///     .default_outbound("direct")
    ///     .version(1)
    ///     .build()
    ///     .unwrap();
    ///
    /// assert_eq!(snapshot.version, 1);
    /// ```
    pub fn build(self) -> Result<RoutingSnapshot, RuleError> {
        let domain_matcher = self.domain_builder.build()?;
        let geoip_matcher = self.geoip_builder.build()?;
        let fwmark_router = self.fwmark_builder.build();
        let rules = CompiledRuleSet::new(self.rules, self.default_outbound.clone())?;

        Ok(RoutingSnapshot {
            domain_matcher,
            geoip_matcher,
            fwmark_router,
            rules,
            default_outbound: self.default_outbound,
            version: self.version,
        })
    }
}

impl Default for RoutingSnapshotBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for RoutingSnapshotBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RoutingSnapshotBuilder")
            .field("default_outbound", &self.default_outbound)
            .field("version", &self.version)
            .field("rules_count", &self.rules.len())
            .field("next_rule_id", &self.next_rule_id)
            .finish_non_exhaustive()
    }
}

// ============================================================================
// RuleEngineRoutingCallback
// ============================================================================

/// Routing callback that registers chains with the RuleEngine's FwmarkRouter.
///
/// This callback is set on `ChainManager` to ensure that when chains are
/// activated or deactivated, the `RuleEngine`'s `FwmarkRouter` is updated
/// to enable DSCP-based routing.
///
/// # Example
///
/// ```ignore
/// use std::sync::Arc;
/// use rust_router::rules::engine::{RuleEngine, RuleEngineRoutingCallback};
/// use rust_router::chain::manager::ChainManager;
///
/// let rule_engine = Arc::new(RuleEngine::new(snapshot));
/// let chain_manager = Arc::new(ChainManager::new("local-node".to_string()));
///
/// // Wire up the callback
/// let callback = Arc::new(RuleEngineRoutingCallback::new(Arc::clone(&rule_engine)));
/// chain_manager.set_routing_callback(callback);
/// ```
pub struct RuleEngineRoutingCallback {
    rule_engine: Arc<RuleEngine>,
}

impl RuleEngineRoutingCallback {
    /// Create a new routing callback for the given rule engine.
    #[must_use]
    pub fn new(rule_engine: Arc<RuleEngine>) -> Self {
        Self { rule_engine }
    }
}

impl DscpRoutingCallback for RuleEngineRoutingCallback {
    fn setup_routing(
        &self,
        chain_tag: &str,
        dscp_value: u8,
        role: ChainRole,
        _exit_egress: Option<&str>,
    ) -> Result<(), String> {
        tracing::info!(
            chain = %chain_tag,
            dscp = dscp_value,
            role = ?role,
            "RuleEngineRoutingCallback: Adding chain to FwmarkRouter"
        );

        self.rule_engine
            .add_chain(chain_tag, dscp_value)
            .map_err(|e| format!("Failed to add chain to FwmarkRouter: {e}"))
    }

    fn teardown_routing(&self, chain_tag: &str) -> Result<(), String> {
        tracing::info!(
            chain = %chain_tag,
            "RuleEngineRoutingCallback: Removing chain from FwmarkRouter"
        );

        let removed = self.rule_engine.remove_chain(chain_tag);
        if !removed {
            tracing::warn!(
                chain = %chain_tag,
                "Chain was not found in FwmarkRouter during teardown"
            );
        }
        Ok(())
    }

    fn is_chain_registered(&self, chain_tag: &str) -> bool {
        let is_registered = self.rule_engine.has_chain(chain_tag);
        tracing::trace!(
            chain = %chain_tag,
            registered = is_registered,
            "RuleEngineRoutingCallback: Checking chain registration"
        );
        is_registered
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // ConnectionInfo Tests
    // ========================================================================

    #[test]
    fn test_connection_info_default() {
        let conn = ConnectionInfo::default();
        assert!(conn.domain.is_none());
        assert!(conn.dest_ip.is_none());
        assert_eq!(conn.dest_port, 0);
        assert!(conn.source_ip.is_none());
        assert_eq!(conn.protocol, "");
        assert!(conn.sniffed_protocol.is_none());
    }

    #[test]
    fn test_connection_info_new() {
        let conn = ConnectionInfo::new("tcp", 443);
        assert_eq!(conn.protocol, "tcp");
        assert_eq!(conn.dest_port, 443);
    }

    #[test]
    fn test_connection_info_builder() {
        let conn = ConnectionInfo::new("tcp", 443)
            .with_domain("example.com")
            .with_dest_ip("8.8.8.8".parse().unwrap())
            .with_source_ip("10.0.0.1".parse().unwrap())
            .with_sniffed_protocol("tls");

        assert_eq!(conn.domain, Some("example.com".to_string()));
        assert_eq!(conn.dest_ip, Some("8.8.8.8".parse().unwrap()));
        assert_eq!(conn.source_ip, Some("10.0.0.1".parse().unwrap()));
        assert_eq!(conn.sniffed_protocol, Some("tls"));
    }

    // ========================================================================
    // RuleEngine Tests
    // ========================================================================

    #[test]
    fn test_rule_engine_creation() {
        let snapshot = RoutingSnapshotBuilder::new()
            .default_outbound("direct")
            .version(1)
            .build()
            .unwrap();

        let engine = RuleEngine::new(snapshot);
        assert_eq!(engine.version(), 1);
        assert_eq!(engine.default_outbound(), "direct");
    }

    #[test]
    fn test_rule_engine_hot_reload() {
        let snapshot1 = RoutingSnapshotBuilder::new()
            .default_outbound("direct")
            .version(1)
            .build()
            .unwrap();

        let engine = RuleEngine::new(snapshot1);
        assert_eq!(engine.version(), 1);

        // Hot reload
        let snapshot2 = RoutingSnapshotBuilder::new()
            .default_outbound("proxy")
            .version(2)
            .build()
            .unwrap();

        engine.reload(snapshot2);
        assert_eq!(engine.version(), 2);
        assert_eq!(engine.default_outbound(), "proxy");
    }

    #[test]
    fn test_rule_engine_load_snapshot() {
        let engine = RuleEngine::new(
            RoutingSnapshotBuilder::new()
                .default_outbound("direct")
                .version(42)
                .build()
                .unwrap(),
        );

        let snapshot = engine.load();
        assert_eq!(snapshot.version, 42);
        assert_eq!(snapshot.default_outbound, "direct");
    }

    #[test]
    fn test_rule_engine_match_default() {
        let engine = RuleEngine::new(
            RoutingSnapshotBuilder::new()
                .default_outbound("direct")
                .build()
                .unwrap(),
        );

        let conn = ConnectionInfo::new("tcp", 443);
        let result = engine.match_connection(&conn);

        assert_eq!(result.outbound, "direct");
        assert!(result.is_default());
        assert!(result.matched_rule.is_none());
    }

    #[test]
    fn test_rule_engine_match_domain() {
        let mut builder = RoutingSnapshotBuilder::new();
        builder
            .add_domain_rule(RuleType::DomainSuffix, "google.com", "proxy")
            .unwrap();

        let engine = RuleEngine::new(builder.default_outbound("direct").build().unwrap());

        // Match google.com
        let conn = ConnectionInfo::new("tcp", 443).with_domain("www.google.com");
        let result = engine.match_connection(&conn);
        assert_eq!(result.outbound, "proxy");
        assert!(!result.is_default());
        assert!(matches!(result.matched_rule, Some(MatchedRule::Domain(_))));

        // No match
        let conn = ConnectionInfo::new("tcp", 443).with_domain("example.com");
        let result = engine.match_connection(&conn);
        assert_eq!(result.outbound, "direct");
        assert!(result.is_default());
    }

    #[test]
    fn test_rule_engine_match_geoip() {
        let mut builder = RoutingSnapshotBuilder::new();
        builder
            .add_geoip_rule(RuleType::IpCidr, "192.168.0.0/16", "local")
            .unwrap();

        let engine = RuleEngine::new(builder.default_outbound("direct").build().unwrap());

        // Match local IP
        let conn = ConnectionInfo::new("tcp", 80).with_dest_ip("192.168.1.100".parse().unwrap());
        let result = engine.match_connection(&conn);
        assert_eq!(result.outbound, "local");
        assert!(matches!(result.matched_rule, Some(MatchedRule::GeoIP(_))));

        // No match
        let conn = ConnectionInfo::new("tcp", 80).with_dest_ip("8.8.8.8".parse().unwrap());
        let result = engine.match_connection(&conn);
        assert_eq!(result.outbound, "direct");
    }

    #[test]
    fn test_rule_engine_match_port() {
        let mut builder = RoutingSnapshotBuilder::new();
        builder.add_port_rule("443", "https-proxy").unwrap();

        let engine = RuleEngine::new(builder.default_outbound("direct").build().unwrap());

        // Match port 443
        let conn = ConnectionInfo::new("tcp", 443);
        let result = engine.match_connection(&conn);
        assert_eq!(result.outbound, "https-proxy");
        assert!(matches!(result.matched_rule, Some(MatchedRule::Rule(_))));

        // No match
        let conn = ConnectionInfo::new("tcp", 80);
        let result = engine.match_connection(&conn);
        assert_eq!(result.outbound, "direct");
    }

    #[test]
    fn test_rule_engine_priority_domain_over_geoip() {
        let mut builder = RoutingSnapshotBuilder::new();
        builder
            .add_domain_rule(RuleType::DomainSuffix, "example.com", "domain-proxy")
            .unwrap()
            .add_geoip_rule(RuleType::IpCidr, "0.0.0.0/0", "catch-all")
            .unwrap();

        let engine = RuleEngine::new(builder.default_outbound("direct").build().unwrap());

        // Domain should match first
        let conn = ConnectionInfo::new("tcp", 443)
            .with_domain("www.example.com")
            .with_dest_ip("1.2.3.4".parse().unwrap());
        let result = engine.match_connection(&conn);
        assert_eq!(result.outbound, "domain-proxy");
    }

    #[test]
    fn test_rule_engine_debug() {
        let engine = RuleEngine::new(
            RoutingSnapshotBuilder::new()
                .default_outbound("direct")
                .version(1)
                .build()
                .unwrap(),
        );

        let debug_str = format!("{:?}", engine);
        assert!(debug_str.contains("RuleEngine"));
        assert!(debug_str.contains("version"));
    }

    // ========================================================================
    // MatchResult Tests
    // ========================================================================

    #[test]
    fn test_match_result_is_default() {
        let result = MatchResult {
            outbound: "direct".to_string(),
            matched_rule: None,
            routing_mark: None,
        };
        assert!(result.is_default());

        let result = MatchResult {
            outbound: "proxy".to_string(),
            matched_rule: Some(MatchedRule::Domain("example.com".to_string())),
            routing_mark: None,
        };
        assert!(!result.is_default());
    }

    #[test]
    fn test_match_result_has_routing_mark() {
        let result = MatchResult {
            outbound: "chain".to_string(),
            matched_rule: None,
            routing_mark: Some(773),
        };
        assert!(result.has_routing_mark());

        let result = MatchResult {
            outbound: "direct".to_string(),
            matched_rule: None,
            routing_mark: None,
        };
        assert!(!result.has_routing_mark());
    }

    // ========================================================================
    // MatchedRule Tests
    // ========================================================================

    #[test]
    fn test_matched_rule_display() {
        let rule = MatchedRule::Domain("example.com".to_string());
        assert_eq!(format!("{rule}"), "domain:example.com");

        let rule = MatchedRule::GeoIP("8.8.8.8".parse().unwrap());
        assert_eq!(format!("{rule}"), "geoip:8.8.8.8");

        let rule = MatchedRule::Rule(42);
        assert_eq!(format!("{rule}"), "rule:42");
    }

    // ========================================================================
    // RoutingSnapshot Tests
    // ========================================================================

    #[test]
    fn test_routing_snapshot_empty() {
        let snapshot = RoutingSnapshot::empty("direct");
        assert_eq!(snapshot.default_outbound, "direct");
        assert_eq!(snapshot.version, 0);
        assert!(snapshot.domain_matcher.is_empty());
        assert!(snapshot.geoip_matcher.is_empty());
    }

    #[test]
    fn test_routing_snapshot_stats() {
        let mut builder = RoutingSnapshotBuilder::new();
        builder
            .add_domain_rule(RuleType::DomainSuffix, "google.com", "proxy")
            .unwrap()
            .add_geoip_rule(RuleType::IpCidr, "10.0.0.0/8", "local")
            .unwrap()
            .add_port_rule("443", "https")
            .unwrap()
            .add_chain("my-chain")
            .unwrap();

        let snapshot = builder.default_outbound("direct").version(5).build().unwrap();

        let stats = snapshot.stats();
        assert_eq!(stats.domain_rules, 1);
        assert_eq!(stats.geoip_rules, 1);
        assert_eq!(stats.compiled_rules, 1);
        assert_eq!(stats.chains, 1);
        assert_eq!(stats.version, 5);
    }

    // ========================================================================
    // RoutingSnapshotBuilder Tests
    // ========================================================================

    #[test]
    fn test_builder_default() {
        let builder = RoutingSnapshotBuilder::new();
        let snapshot = builder.build().unwrap();

        assert_eq!(snapshot.default_outbound, "direct");
        assert_eq!(snapshot.version, 0);
    }

    #[test]
    fn test_builder_add_domain_rules() {
        let mut builder = RoutingSnapshotBuilder::new();
        builder
            .add_domain_rule(RuleType::Domain, "exact.com", "proxy")
            .unwrap()
            .add_domain_rule(RuleType::DomainSuffix, "suffix.com", "proxy")
            .unwrap()
            .add_domain_rule(RuleType::DomainKeyword, "keyword", "proxy")
            .unwrap()
            .add_domain_rule(RuleType::DomainRegex, r".*\.regex\.com$", "proxy")
            .unwrap();

        let snapshot = builder.build().unwrap();
        assert_eq!(snapshot.domain_matcher.rule_count(), 4);
    }

    #[test]
    fn test_builder_add_domain_rule_invalid_type() {
        let mut builder = RoutingSnapshotBuilder::new();
        let result = builder.add_domain_rule(RuleType::Port, "443", "proxy");
        assert!(result.is_err());
    }

    #[test]
    fn test_builder_add_geoip_rules() {
        let mut builder = RoutingSnapshotBuilder::new();
        builder
            .add_geoip_rule(RuleType::IpCidr, "192.168.0.0/16", "local")
            .unwrap()
            .add_geoip_rule(RuleType::IpCidr, "10.0.0.0/8", "private")
            .unwrap();

        let snapshot = builder.build().unwrap();
        assert_eq!(snapshot.geoip_matcher.rule_count(), 2);
    }

    #[test]
    fn test_builder_add_geoip_rule_invalid_cidr() {
        let mut builder = RoutingSnapshotBuilder::new();
        let result = builder.add_geoip_rule(RuleType::IpCidr, "not-a-cidr", "proxy");
        assert!(result.is_err());
    }

    #[test]
    fn test_builder_add_port_rules() {
        let mut builder = RoutingSnapshotBuilder::new();
        builder
            .add_port_rule("443", "https")
            .unwrap()
            .add_port_rule("80-8080", "http")
            .unwrap();

        let snapshot = builder.build().unwrap();
        assert_eq!(snapshot.rules.len(), 2);
    }

    #[test]
    fn test_builder_add_port_rule_invalid() {
        let mut builder = RoutingSnapshotBuilder::new();
        let result = builder.add_port_rule("not-a-port", "proxy");
        assert!(result.is_err());
    }

    #[test]
    fn test_builder_add_protocol_rule() {
        let mut builder = RoutingSnapshotBuilder::new();
        builder.add_protocol_rule("tcp", "tcp-handler").unwrap();

        let snapshot = builder.build().unwrap();
        assert_eq!(snapshot.rules.len(), 1);
    }

    #[test]
    fn test_builder_add_protocol_rule_invalid() {
        let mut builder = RoutingSnapshotBuilder::new();
        let result = builder.add_protocol_rule("icmp", "proxy");
        assert!(result.is_err());
    }

    #[test]
    fn test_builder_add_raw_rule() {
        let mut builder = RoutingSnapshotBuilder::new();
        let rule = Rule::new(100, RuleType::Port, "443".into(), "proxy".into()).with_priority(-10);
        builder.add_rule(rule);

        let snapshot = builder.build().unwrap();
        assert_eq!(snapshot.rules.len(), 1);
    }

    #[test]
    fn test_builder_add_chain() {
        let mut builder = RoutingSnapshotBuilder::new();
        builder
            .add_chain("chain-a")
            .unwrap()
            .add_chain("chain-b")
            .unwrap();

        let snapshot = builder.build().unwrap();
        assert_eq!(snapshot.fwmark_router.chain_count(), 2);
    }

    #[test]
    fn test_builder_add_chain_duplicate() {
        let mut builder = RoutingSnapshotBuilder::new();
        builder.add_chain("chain-a").unwrap();
        let result = builder.add_chain("chain-a");
        assert!(result.is_err());
    }

    #[test]
    fn test_builder_add_chain_with_dscp() {
        let mut builder = RoutingSnapshotBuilder::new();
        builder.add_chain_with_dscp("high-priority", 50).unwrap();

        let snapshot = builder.build().unwrap();
        let mark = snapshot.fwmark_router.get_chain_mark("high-priority").unwrap();
        assert_eq!(mark.dscp_value, 50);
    }

    #[test]
    fn test_builder_debug() {
        let builder = RoutingSnapshotBuilder::new();
        let debug_str = format!("{:?}", builder);
        assert!(debug_str.contains("RoutingSnapshotBuilder"));
    }

    // ========================================================================
    // Concurrent Access Test
    // ========================================================================

    #[test]
    fn test_concurrent_access() {
        use std::sync::Arc;
        use std::thread;

        let engine = Arc::new(RuleEngine::new(
            RoutingSnapshotBuilder::new()
                .default_outbound("direct")
                .version(1)
                .build()
                .unwrap(),
        ));

        let mut handles = vec![];

        // Spawn reader threads
        for _ in 0..4 {
            let engine = Arc::clone(&engine);
            handles.push(thread::spawn(move || {
                for _ in 0..1000 {
                    let conn = ConnectionInfo::new("tcp", 443);
                    let _ = engine.match_connection(&conn);
                }
            }));
        }

        // Spawn writer thread
        {
            let engine = Arc::clone(&engine);
            handles.push(thread::spawn(move || {
                for i in 2..10 {
                    let snapshot = RoutingSnapshotBuilder::new()
                        .default_outbound(if i % 2 == 0 { "direct" } else { "proxy" })
                        .version(i)
                        .build()
                        .unwrap();
                    engine.reload(snapshot);
                    thread::sleep(std::time::Duration::from_millis(1));
                }
            }));
        }

        // Wait for all threads
        for handle in handles {
            handle.join().unwrap();
        }

        // Engine should still be functional
        assert!(engine.version() >= 1);
    }

    // ========================================================================
    // Chain Routing Mark Test
    // ========================================================================

    #[test]
    fn test_chain_routing_mark() {
        let mut builder = RoutingSnapshotBuilder::new();
        builder
            .add_domain_rule(RuleType::DomainSuffix, "chain-test.com", "my-chain")
            .unwrap()
            .add_chain_with_dscp("my-chain", 5)
            .unwrap();

        let engine = RuleEngine::new(builder.default_outbound("direct").build().unwrap());

        let conn = ConnectionInfo::new("tcp", 443).with_domain("www.chain-test.com");
        let result = engine.match_connection(&conn);

        assert_eq!(result.outbound, "my-chain");
        assert!(result.routing_mark.is_some());
        // ENTRY_ROUTING_MARK_BASE (0x300 = 768) + 5 = 773
        assert_eq!(result.routing_mark.unwrap(), 768 + 5);
    }

    // ========================================================================
    // Empty Configuration Test
    // ========================================================================

    #[test]
    fn test_empty_configuration() {
        let snapshot = RoutingSnapshot::empty("fallback");
        let engine = RuleEngine::new(snapshot);

        let conn = ConnectionInfo::new("tcp", 443)
            .with_domain("any.domain.com")
            .with_dest_ip("1.2.3.4".parse().unwrap());

        let result = engine.match_connection(&conn);
        assert_eq!(result.outbound, "fallback");
        assert!(result.is_default());
    }
}
