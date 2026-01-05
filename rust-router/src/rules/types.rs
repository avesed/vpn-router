//! Core rule types for the routing engine
//!
//! This module defines the fundamental types for routing rules:
//! - [`RuleType`]: The type of matching to perform
//! - [`Rule`]: A single routing rule
//! - [`PortRange`]: A range of ports for port-based matching
//! - [`CompiledRuleSet`]: An optimized collection of rules for fast matching
//! - [`RoutingConfig`]: Hot-reloadable routing configuration

use std::collections::HashSet;
use std::fmt;
use std::net::IpAddr;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::error::RuleError;

/// Rule matching type
///
/// Defines how a rule's target should be matched against connection metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RuleType {
    /// Exact domain name match (e.g., "www.google.com")
    #[serde(rename = "domain")]
    Domain,

    /// Domain suffix match (e.g., ".google.com" matches "www.google.com")
    #[serde(rename = "domain_suffix")]
    DomainSuffix,

    /// Domain keyword match (e.g., "youtube" matches "www.youtube.com")
    #[serde(rename = "domain_keyword")]
    DomainKeyword,

    /// Regular expression match against domain
    #[serde(rename = "domain_regex")]
    DomainRegex,

    /// `GeoIP` country code match (e.g., "CN", "US")
    #[serde(rename = "geoip")]
    GeoIP,

    /// `GeoSite` list match (e.g., "netflix", "google", "cn")
    #[serde(rename = "geosite")]
    GeoSite,

    /// IP CIDR match (e.g., "192.168.0.0/16")
    #[serde(rename = "ip_cidr")]
    IpCidr,

    /// Destination port match (single port or range)
    #[serde(rename = "port")]
    Port,

    /// Protocol match (tcp/udp)
    #[serde(rename = "protocol")]
    Protocol,
}

impl RuleType {
    /// Parse rule type from string
    ///
    /// # Errors
    ///
    /// Returns `RuleError::InvalidRuleType` if the string is not a valid rule type.
    pub fn parse(s: &str) -> Result<Self, RuleError> {
        match s.to_lowercase().as_str() {
            "domain" => Ok(Self::Domain),
            "domain_suffix" => Ok(Self::DomainSuffix),
            "domain_keyword" => Ok(Self::DomainKeyword),
            "domain_regex" => Ok(Self::DomainRegex),
            "geoip" | "country" => Ok(Self::GeoIP),
            "geosite" | "domain_list" => Ok(Self::GeoSite),
            "ip_cidr" | "ip" => Ok(Self::IpCidr),
            "port" | "port_range" => Ok(Self::Port),
            "protocol" | "network" => Ok(Self::Protocol),
            _ => Err(RuleError::InvalidRuleType(s.to_string())),
        }
    }

    /// Check if this rule type requires domain information
    #[must_use]
    pub const fn requires_domain(&self) -> bool {
        matches!(
            self,
            Self::Domain | Self::DomainSuffix | Self::DomainKeyword | Self::DomainRegex
        )
    }

    /// Check if this rule type uses GeoIP/GeoSite databases
    #[must_use]
    pub const fn requires_geodata(&self) -> bool {
        matches!(self, Self::GeoIP | Self::GeoSite)
    }

    /// Check if this rule type matches IP addresses
    #[must_use]
    pub const fn matches_ip(&self) -> bool {
        matches!(self, Self::GeoIP | Self::IpCidr)
    }
}

impl fmt::Display for RuleType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Domain => write!(f, "domain"),
            Self::DomainSuffix => write!(f, "domain_suffix"),
            Self::DomainKeyword => write!(f, "domain_keyword"),
            Self::DomainRegex => write!(f, "domain_regex"),
            Self::GeoIP => write!(f, "geoip"),
            Self::GeoSite => write!(f, "geosite"),
            Self::IpCidr => write!(f, "ip_cidr"),
            Self::Port => write!(f, "port"),
            Self::Protocol => write!(f, "protocol"),
        }
    }
}

/// A single routing rule
///
/// Rules are matched against connection metadata (domain, IP, port)
/// to determine which outbound to use.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    /// Unique identifier for this rule
    pub id: u64,

    /// Type of matching to perform
    pub rule_type: RuleType,

    /// Target value to match against (domain, country code, CIDR, etc.)
    pub target: String,

    /// Outbound tag to route matching traffic to
    pub outbound: String,

    /// Priority (lower values = higher priority, matched first)
    #[serde(default)]
    pub priority: i32,

    /// Whether this rule is enabled
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Optional tag for grouping rules (e.g., "__adblock__")
    #[serde(default)]
    pub tag: Option<String>,
}

impl Rule {
    /// Create a new rule with default priority and enabled state
    ///
    /// # Examples
    ///
    /// ```
    /// use rust_router::rules::{Rule, RuleType};
    ///
    /// let rule = Rule::new(1, RuleType::DomainSuffix, ".google.com".into(), "proxy".into());
    /// assert_eq!(rule.priority, 0);
    /// assert!(rule.enabled);
    /// ```
    #[must_use]
    pub fn new(id: u64, rule_type: RuleType, target: String, outbound: String) -> Self {
        Self {
            id,
            rule_type,
            target,
            outbound,
            priority: 0,
            enabled: true,
            tag: None,
        }
    }

    /// Set the priority for this rule
    ///
    /// Lower values are matched first.
    ///
    /// # Examples
    ///
    /// ```
    /// use rust_router::rules::{Rule, RuleType};
    ///
    /// let rule = Rule::new(1, RuleType::Domain, "example.com".into(), "direct".into())
    ///     .with_priority(10);
    /// assert_eq!(rule.priority, 10);
    /// ```
    #[must_use]
    pub const fn with_priority(mut self, priority: i32) -> Self {
        self.priority = priority;
        self
    }

    /// Set the enabled state for this rule
    #[must_use]
    pub const fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    /// Set the tag for this rule
    #[must_use]
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tag = Some(tag.into());
        self
    }

    /// Validate this rule
    ///
    /// # Errors
    ///
    /// Returns `RuleError` if the rule is invalid:
    /// - Empty target
    /// - Empty outbound
    /// - Invalid regex pattern (for `DomainRegex` type)
    /// - Invalid CIDR notation (for `IpCidr` type)
    /// - Invalid port specification (for `Port` type)
    pub fn validate(&self) -> Result<(), RuleError> {
        // Target cannot be empty
        if self.target.trim().is_empty() {
            return Err(RuleError::InvalidTarget(
                "target cannot be empty".to_string(),
            ));
        }

        // Outbound cannot be empty
        if self.outbound.trim().is_empty() {
            return Err(RuleError::InvalidTarget(
                "outbound cannot be empty".to_string(),
            ));
        }

        // Type-specific validation
        match self.rule_type {
            RuleType::DomainRegex => {
                // Validate regex pattern
                if regex::Regex::new(&self.target).is_err() {
                    return Err(RuleError::InvalidRegex(self.target.clone()));
                }
            }
            RuleType::IpCidr => {
                // Validate CIDR notation
                if self.target.parse::<ipnet::IpNet>().is_err() {
                    return Err(RuleError::InvalidTarget(format!(
                        "invalid CIDR notation: {}",
                        self.target
                    )));
                }
            }
            RuleType::Port => {
                // Validate port or port range
                PortRange::parse(&self.target)?;
            }
            RuleType::GeoIP => {
                // Country codes should be 2 characters
                if self.target.len() != 2 {
                    return Err(RuleError::InvalidTarget(format!(
                        "GeoIP country code must be 2 characters: {}",
                        self.target
                    )));
                }
            }
            RuleType::Protocol => {
                // Protocol must be tcp or udp
                let proto = self.target.to_lowercase();
                if proto != "tcp" && proto != "udp" {
                    return Err(RuleError::InvalidTarget(format!(
                        "protocol must be 'tcp' or 'udp': {}",
                        self.target
                    )));
                }
            }
            _ => {}
        }

        Ok(())
    }
}

/// A range of ports for port-based matching
///
/// Supports both single ports and ranges (e.g., "80" or "80-443").
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PortRange {
    /// Start of the range (inclusive)
    pub start: u16,
    /// End of the range (inclusive)
    pub end: u16,
}

impl PortRange {
    /// Create a new port range
    ///
    /// # Errors
    ///
    /// Returns `RuleError::InvalidPortRange` if start > end.
    ///
    /// # Examples
    ///
    /// ```
    /// use rust_router::rules::PortRange;
    ///
    /// let range = PortRange::new(80, 443).unwrap();
    /// assert!(range.contains(80));
    /// assert!(range.contains(443));
    /// assert!(!range.contains(8080));
    /// ```
    pub fn new(start: u16, end: u16) -> Result<Self, RuleError> {
        if start > end {
            return Err(RuleError::InvalidPortRange { start, end });
        }
        Ok(Self { start, end })
    }

    /// Create a range for a single port
    ///
    /// # Examples
    ///
    /// ```
    /// use rust_router::rules::PortRange;
    ///
    /// let range = PortRange::single(443);
    /// assert!(range.contains(443));
    /// assert!(!range.contains(80));
    /// ```
    #[must_use]
    pub const fn single(port: u16) -> Self {
        Self {
            start: port,
            end: port,
        }
    }

    /// Check if a port is within this range
    ///
    /// # Examples
    ///
    /// ```
    /// use rust_router::rules::PortRange;
    ///
    /// let range = PortRange::new(80, 443).unwrap();
    /// assert!(range.contains(80));
    /// assert!(range.contains(200));
    /// assert!(range.contains(443));
    /// assert!(!range.contains(79));
    /// assert!(!range.contains(444));
    /// ```
    #[must_use]
    pub const fn contains(&self, port: u16) -> bool {
        port >= self.start && port <= self.end
    }

    /// Parse a port range from a string
    ///
    /// Accepts formats:
    /// - Single port: "80"
    /// - Port range: "80-443"
    ///
    /// # Errors
    ///
    /// Returns `RuleError::InvalidTarget` if parsing fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use rust_router::rules::PortRange;
    ///
    /// let single = PortRange::parse("443").unwrap();
    /// assert_eq!(single.start, 443);
    /// assert_eq!(single.end, 443);
    ///
    /// let range = PortRange::parse("80-443").unwrap();
    /// assert_eq!(range.start, 80);
    /// assert_eq!(range.end, 443);
    ///
    /// // Invalid range (start > end)
    /// assert!(PortRange::parse("443-80").is_err());
    /// ```
    pub fn parse(s: &str) -> Result<Self, RuleError> {
        let s = s.trim();

        if let Some((start_str, end_str)) = s.split_once('-') {
            // Range format: "80-443"
            let start = start_str.trim().parse::<u16>().map_err(|_| {
                RuleError::InvalidTarget(format!("invalid port number: {start_str}"))
            })?;
            let end = end_str
                .trim()
                .parse::<u16>()
                .map_err(|_| RuleError::InvalidTarget(format!("invalid port number: {end_str}")))?;

            Self::new(start, end)
        } else {
            // Single port format: "80"
            let port = s
                .parse::<u16>()
                .map_err(|_| RuleError::InvalidTarget(format!("invalid port number: {s}")))?;
            Ok(Self::single(port))
        }
    }

    /// Check if this range represents a single port
    #[must_use]
    pub const fn is_single(&self) -> bool {
        self.start == self.end
    }
}

impl fmt::Display for PortRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_single() {
            write!(f, "{}", self.start)
        } else {
            write!(f, "{}-{}", self.start, self.end)
        }
    }
}

impl Serialize for PortRange {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for PortRange {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

/// Compiled rule set for fast matching
///
/// Rules are sorted by priority during compilation for efficient matching.
/// The `CompiledRuleSet` is immutable after creation.
///
/// Note: Full matching logic (domain, IP) will be implemented in Phase 2.2/2.3.
/// Currently only provides priority-based iteration.
pub struct CompiledRuleSet {
    /// Rules sorted by priority (ascending = higher priority first)
    rules: Vec<Rule>,
    /// Default outbound tag when no rules match
    default_outbound: String,
}

impl CompiledRuleSet {
    /// Create a new compiled rule set
    ///
    /// Rules are validated and sorted by priority during construction.
    ///
    /// # Errors
    ///
    /// Returns `RuleError` if:
    /// - Any rule fails validation
    /// - Duplicate rule IDs exist
    ///
    /// # Examples
    ///
    /// ```
    /// use rust_router::rules::{Rule, RuleType, CompiledRuleSet};
    ///
    /// let rules = vec![
    ///     Rule::new(1, RuleType::DomainSuffix, ".google.com".into(), "proxy".into())
    ///         .with_priority(20),
    ///     Rule::new(2, RuleType::Domain, "example.com".into(), "direct".into())
    ///         .with_priority(10),
    /// ];
    ///
    /// let ruleset = CompiledRuleSet::new(rules, "direct".into()).unwrap();
    /// // Rules are sorted by priority
    /// let targets: Vec<_> = ruleset.all_outbound_targets().collect();
    /// assert!(targets.contains(&"proxy"));
    /// assert!(targets.contains(&"direct"));
    /// ```
    pub fn new(mut rules: Vec<Rule>, default_outbound: String) -> Result<Self, RuleError> {
        // Filter to enabled rules only
        rules.retain(|r| r.enabled);

        // Validate all rules
        for rule in &rules {
            rule.validate()?;
        }

        // Check for duplicate IDs
        let mut seen_ids: HashSet<u64> = HashSet::with_capacity(rules.len());
        for rule in &rules {
            if !seen_ids.insert(rule.id) {
                return Err(RuleError::DuplicateRuleId(rule.id));
            }
        }

        // Sort by priority (ascending = higher priority first)
        rules.sort_by_key(|r| r.priority);

        Ok(Self {
            rules,
            default_outbound,
        })
    }

    /// Create an empty rule set with just a default outbound
    #[must_use]
    pub fn empty(default_outbound: String) -> Self {
        Self {
            rules: Vec::new(),
            default_outbound,
        }
    }

    /// Get the default outbound tag
    #[must_use]
    pub fn default_outbound(&self) -> &str {
        &self.default_outbound
    }

    /// Get the number of rules in this set
    #[must_use]
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Check if this rule set is empty
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Iterate over all rules in priority order
    pub fn iter(&self) -> impl Iterator<Item = &Rule> {
        self.rules.iter()
    }

    /// Get all unique outbound targets referenced by rules
    ///
    /// Useful for validation to ensure all referenced outbounds exist.
    ///
    /// # Examples
    ///
    /// ```
    /// use rust_router::rules::{Rule, RuleType, CompiledRuleSet};
    /// use std::collections::HashSet;
    ///
    /// let rules = vec![
    ///     Rule::new(1, RuleType::Domain, "a.com".into(), "proxy".into()),
    ///     Rule::new(2, RuleType::Domain, "b.com".into(), "direct".into()),
    ///     Rule::new(3, RuleType::Domain, "c.com".into(), "proxy".into()), // duplicate outbound
    /// ];
    ///
    /// let ruleset = CompiledRuleSet::new(rules, "direct".into()).unwrap();
    /// let targets: HashSet<_> = ruleset.all_outbound_targets().collect();
    /// assert_eq!(targets.len(), 2); // "proxy" and "direct"
    /// ```
    pub fn all_outbound_targets(&self) -> impl Iterator<Item = &str> {
        let mut seen = HashSet::new();
        self.rules
            .iter()
            .filter_map(move |r| {
                if seen.insert(r.outbound.as_str()) {
                    Some(r.outbound.as_str())
                } else {
                    None
                }
            })
            .chain(std::iter::once(self.default_outbound.as_str()))
    }

    /// Simple priority-based matching (Phase 2.1 implementation)
    ///
    /// Returns the outbound tag for the first matching rule, or the default
    /// outbound if no rules match.
    ///
    /// Note: This is a basic implementation that only checks rule types.
    /// Full matching (domain suffix, regex, `GeoIP` lookup) will be implemented
    /// in Phase 2.2/2.3.
    ///
    /// # Arguments
    ///
    /// * `domain` - Optional domain name (from TLS SNI or HTTP Host)
    /// * `dest_ip` - Destination IP address
    /// * `dest_port` - Destination port
    ///
    /// # Examples
    ///
    /// ```
    /// use rust_router::rules::{Rule, RuleType, CompiledRuleSet};
    /// use std::net::IpAddr;
    ///
    /// let rules = vec![
    ///     Rule::new(1, RuleType::Port, "443".into(), "https-proxy".into())
    ///         .with_priority(10),
    /// ];
    ///
    /// let ruleset = CompiledRuleSet::new(rules, "direct".into()).unwrap();
    /// let ip: IpAddr = "1.2.3.4".parse().unwrap();
    ///
    /// // Port 443 matches
    /// assert_eq!(ruleset.match_by_priority(None, ip, 443), "https-proxy");
    ///
    /// // Port 80 doesn't match, falls through to default
    /// assert_eq!(ruleset.match_by_priority(None, ip, 80), "direct");
    /// ```
    #[must_use]
    pub fn match_by_priority(&self, domain: Option<&str>, dest_ip: IpAddr, dest_port: u16) -> &str {
        for rule in &self.rules {
            if Self::matches_rule(rule, domain, dest_ip, dest_port) {
                return &rule.outbound;
            }
        }
        &self.default_outbound
    }

    /// Match a connection using `ConnectionInfo` (Phase 2.5).
    ///
    /// This method is designed for use with the rule engine and returns
    /// both the rule ID and outbound for tracking which rule matched.
    ///
    /// Only matches Port and Protocol rules. Domain and `GeoIP` rules are
    /// handled by dedicated matchers in the rule engine.
    ///
    /// # Arguments
    ///
    /// * `conn` - Connection metadata for matching
    ///
    /// # Returns
    ///
    /// `Some((rule_id, outbound))` if a rule matches, `None` otherwise.
    ///
    /// # Examples
    ///
    /// ```
    /// use rust_router::rules::{Rule, RuleType, CompiledRuleSet};
    /// use rust_router::rules::engine::ConnectionInfo;
    ///
    /// let rules = vec![
    ///     Rule::new(1, RuleType::Port, "443".into(), "https-proxy".into()),
    ///     Rule::new(2, RuleType::Protocol, "tcp".into(), "tcp-handler".into()),
    /// ];
    ///
    /// let ruleset = CompiledRuleSet::new(rules, "direct".into()).unwrap();
    /// let conn = ConnectionInfo::new("tcp", 443);
    ///
    /// let result = ruleset.match_connection(&conn);
    /// assert!(result.is_some());
    /// let (rule_id, outbound) = result.unwrap();
    /// assert_eq!(rule_id, 1);
    /// assert_eq!(outbound, "https-proxy");
    /// ```
    #[must_use]
    pub fn match_connection(&self, conn: &crate::rules::engine::ConnectionInfo) -> Option<(u64, &str)> {
        for rule in &self.rules {
            if Self::connection_matches_rule(rule, conn) {
                return Some((rule.id, &rule.outbound));
            }
        }
        None
    }

    /// Check if a connection matches a rule.
    ///
    /// Only handles Port and Protocol rules. Domain and `GeoIP` rules
    /// are handled by dedicated matchers.
    fn connection_matches_rule(rule: &Rule, conn: &crate::rules::engine::ConnectionInfo) -> bool {
        match rule.rule_type {
            RuleType::Port => {
                // Parse and check port range
                if let Ok(range) = PortRange::parse(&rule.target) {
                    range.contains(conn.dest_port)
                } else {
                    false
                }
            }
            RuleType::Protocol => {
                let target_lower = rule.target.to_lowercase();
                // Match transport protocol
                if conn.protocol.eq_ignore_ascii_case(&target_lower) {
                    return true;
                }
                // Also check sniffed protocol
                if let Some(sniffed) = conn.sniffed_protocol {
                    if sniffed.eq_ignore_ascii_case(&target_lower) {
                        return true;
                    }
                }
                false
            }
            // Domain and GeoIP handled by dedicated matchers in RuleEngine
            _ => false,
        }
    }

    /// Check if a single rule matches the connection
    ///
    /// Phase 2.1 implements basic matching for:
    /// - Port/PortRange matching
    /// - Protocol matching (always true in Phase 2.1, TCP-only)
    /// - Exact domain matching
    ///
    /// Domain suffix, keyword, regex, `GeoIP`, `GeoSite`, and IP CIDR matching
    /// will be implemented in Phase 2.2/2.3.
    fn matches_rule(
        rule: &Rule,
        domain: Option<&str>,
        _dest_ip: IpAddr,
        dest_port: u16,
    ) -> bool {
        match rule.rule_type {
            RuleType::Port => {
                // Parse and check port range
                if let Ok(range) = PortRange::parse(&rule.target) {
                    range.contains(dest_port)
                } else {
                    false
                }
            }
            RuleType::Protocol => {
                // Phase 2.1: TCP-only, so "tcp" always matches
                rule.target.to_lowercase() == "tcp"
            }
            RuleType::Domain => {
                // Exact domain match
                if let Some(dom) = domain {
                    dom.eq_ignore_ascii_case(&rule.target)
                } else {
                    false
                }
            }
            // These will be implemented in Phase 2.2/2.3
            RuleType::DomainSuffix
            | RuleType::DomainKeyword
            | RuleType::DomainRegex
            | RuleType::GeoIP
            | RuleType::GeoSite
            | RuleType::IpCidr => false,
        }
    }
}

impl fmt::Debug for CompiledRuleSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CompiledRuleSet")
            .field("rules_count", &self.rules.len())
            .field("default_outbound", &self.default_outbound)
            .finish()
    }
}

/// Hot-reloadable routing configuration
///
/// Designed to be wrapped in `ArcSwap` for lock-free atomic updates.
///
/// # Example
///
/// ```
/// use rust_router::rules::{RoutingConfig, CompiledRuleSet};
/// use std::sync::Arc;
///
/// let ruleset = CompiledRuleSet::empty("direct".into());
/// let config = RoutingConfig::new(ruleset, "direct".into());
///
/// // Wrap in ArcSwap for hot reload
/// // let routing = ArcSwap::from_pointee(config);
/// ```
#[derive(Debug, Clone)]
pub struct RoutingConfig {
    /// Compiled rules for fast matching
    pub rules: Arc<CompiledRuleSet>,
    /// Default outbound for connections that don't match any rules
    pub default_outbound: String,
}

impl RoutingConfig {
    /// Create a new routing configuration
    #[must_use]
    pub fn new(rules: CompiledRuleSet, default_outbound: String) -> Self {
        Self {
            rules: Arc::new(rules),
            default_outbound,
        }
    }
}

// Default value helper for serde
const fn default_true() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_rule_type_serialization() {
        // Serialize
        let domain_type = RuleType::Domain;
        let json = serde_json::to_string(&domain_type).unwrap();
        assert_eq!(json, "\"domain\"");

        let suffix_type = RuleType::DomainSuffix;
        let json = serde_json::to_string(&suffix_type).unwrap();
        assert_eq!(json, "\"domain_suffix\"");

        // Deserialize
        let parsed: RuleType = serde_json::from_str("\"geoip\"").unwrap();
        assert_eq!(parsed, RuleType::GeoIP);

        let parsed: RuleType = serde_json::from_str("\"domain_keyword\"").unwrap();
        assert_eq!(parsed, RuleType::DomainKeyword);
    }

    #[test]
    fn test_rule_type_parse() {
        assert_eq!(RuleType::parse("domain").unwrap(), RuleType::Domain);
        assert_eq!(
            RuleType::parse("DOMAIN_SUFFIX").unwrap(),
            RuleType::DomainSuffix
        );
        assert_eq!(RuleType::parse("geoip").unwrap(), RuleType::GeoIP);
        assert_eq!(RuleType::parse("country").unwrap(), RuleType::GeoIP);
        assert_eq!(RuleType::parse("ip").unwrap(), RuleType::IpCidr);
        assert_eq!(RuleType::parse("ip_cidr").unwrap(), RuleType::IpCidr);
        assert_eq!(RuleType::parse("port").unwrap(), RuleType::Port);
        assert_eq!(RuleType::parse("port_range").unwrap(), RuleType::Port);
        assert_eq!(RuleType::parse("protocol").unwrap(), RuleType::Protocol);
        assert_eq!(RuleType::parse("network").unwrap(), RuleType::Protocol);

        assert!(RuleType::parse("invalid").is_err());
    }

    #[test]
    fn test_rule_type_display() {
        assert_eq!(RuleType::Domain.to_string(), "domain");
        assert_eq!(RuleType::DomainSuffix.to_string(), "domain_suffix");
        assert_eq!(RuleType::GeoIP.to_string(), "geoip");
        assert_eq!(RuleType::IpCidr.to_string(), "ip_cidr");
    }

    #[test]
    fn test_rule_type_properties() {
        assert!(RuleType::Domain.requires_domain());
        assert!(RuleType::DomainSuffix.requires_domain());
        assert!(RuleType::DomainKeyword.requires_domain());
        assert!(RuleType::DomainRegex.requires_domain());
        assert!(!RuleType::GeoIP.requires_domain());
        assert!(!RuleType::Port.requires_domain());

        assert!(RuleType::GeoIP.requires_geodata());
        assert!(RuleType::GeoSite.requires_geodata());
        assert!(!RuleType::Domain.requires_geodata());

        assert!(RuleType::GeoIP.matches_ip());
        assert!(RuleType::IpCidr.matches_ip());
        assert!(!RuleType::Domain.matches_ip());
    }

    #[test]
    fn test_rule_creation() {
        let rule = Rule::new(
            1,
            RuleType::DomainSuffix,
            ".google.com".into(),
            "proxy".into(),
        );

        assert_eq!(rule.id, 1);
        assert_eq!(rule.rule_type, RuleType::DomainSuffix);
        assert_eq!(rule.target, ".google.com");
        assert_eq!(rule.outbound, "proxy");
        assert_eq!(rule.priority, 0);
        assert!(rule.enabled);
        assert!(rule.tag.is_none());

        // With builder methods
        let rule = rule.with_priority(10).with_enabled(false).with_tag("test");
        assert_eq!(rule.priority, 10);
        assert!(!rule.enabled);
        assert_eq!(rule.tag, Some("test".into()));
    }

    #[test]
    fn test_rule_validation() {
        // Valid rule
        let rule = Rule::new(1, RuleType::Domain, "example.com".into(), "direct".into());
        assert!(rule.validate().is_ok());

        // Empty target
        let rule = Rule::new(1, RuleType::Domain, "".into(), "direct".into());
        assert!(rule.validate().is_err());

        // Empty outbound
        let rule = Rule::new(1, RuleType::Domain, "example.com".into(), "".into());
        assert!(rule.validate().is_err());

        // Valid regex
        let rule = Rule::new(1, RuleType::DomainRegex, r".*\.google\.com$".into(), "proxy".into());
        assert!(rule.validate().is_ok());

        // Invalid regex
        let rule = Rule::new(1, RuleType::DomainRegex, r"[invalid".into(), "proxy".into());
        assert!(matches!(rule.validate(), Err(RuleError::InvalidRegex(_))));

        // Valid CIDR
        let rule = Rule::new(1, RuleType::IpCidr, "192.168.0.0/16".into(), "direct".into());
        assert!(rule.validate().is_ok());

        // Invalid CIDR
        let rule = Rule::new(1, RuleType::IpCidr, "not-a-cidr".into(), "direct".into());
        assert!(rule.validate().is_err());

        // Valid GeoIP (2-char country code)
        let rule = Rule::new(1, RuleType::GeoIP, "CN".into(), "direct".into());
        assert!(rule.validate().is_ok());

        // Invalid GeoIP (not 2 chars)
        let rule = Rule::new(1, RuleType::GeoIP, "USA".into(), "direct".into());
        assert!(rule.validate().is_err());

        // Valid protocol
        let rule = Rule::new(1, RuleType::Protocol, "tcp".into(), "direct".into());
        assert!(rule.validate().is_ok());

        // Invalid protocol
        let rule = Rule::new(1, RuleType::Protocol, "icmp".into(), "direct".into());
        assert!(rule.validate().is_err());
    }

    #[test]
    fn test_port_range_parsing() {
        // Single port
        let range = PortRange::parse("80").unwrap();
        assert_eq!(range.start, 80);
        assert_eq!(range.end, 80);
        assert!(range.is_single());

        // Port range
        let range = PortRange::parse("80-443").unwrap();
        assert_eq!(range.start, 80);
        assert_eq!(range.end, 443);
        assert!(!range.is_single());

        // With whitespace
        let range = PortRange::parse(" 80 - 443 ").unwrap();
        assert_eq!(range.start, 80);
        assert_eq!(range.end, 443);

        // Invalid: start > end
        assert!(PortRange::parse("443-80").is_err());

        // Invalid: not a number
        assert!(PortRange::parse("abc").is_err());
        assert!(PortRange::parse("80-abc").is_err());
    }

    #[test]
    fn test_port_range_contains() {
        let range = PortRange::new(80, 443).unwrap();

        assert!(range.contains(80));
        assert!(range.contains(200));
        assert!(range.contains(443));
        assert!(!range.contains(79));
        assert!(!range.contains(444));

        let single = PortRange::single(443);
        assert!(single.contains(443));
        assert!(!single.contains(80));
    }

    #[test]
    fn test_port_range_display() {
        let single = PortRange::single(443);
        assert_eq!(single.to_string(), "443");

        let range = PortRange::new(80, 443).unwrap();
        assert_eq!(range.to_string(), "80-443");
    }

    #[test]
    fn test_port_range_serde() {
        let range = PortRange::new(80, 443).unwrap();
        let json = serde_json::to_string(&range).unwrap();
        assert_eq!(json, "\"80-443\"");

        let parsed: PortRange = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.start, 80);
        assert_eq!(parsed.end, 443);

        let single = PortRange::single(443);
        let json = serde_json::to_string(&single).unwrap();
        assert_eq!(json, "\"443\"");
    }

    #[test]
    fn test_compiled_ruleset_creation() {
        let rules = vec![
            Rule::new(1, RuleType::Domain, "a.com".into(), "proxy".into()).with_priority(20),
            Rule::new(2, RuleType::Domain, "b.com".into(), "direct".into()).with_priority(10),
            Rule::new(3, RuleType::Domain, "c.com".into(), "block".into()).with_priority(30),
        ];

        let ruleset = CompiledRuleSet::new(rules, "direct".into()).unwrap();
        assert_eq!(ruleset.len(), 3);
        assert!(!ruleset.is_empty());
        assert_eq!(ruleset.default_outbound(), "direct");

        // Verify rules are sorted by priority
        let priorities: Vec<i32> = ruleset.iter().map(|r| r.priority).collect();
        assert_eq!(priorities, vec![10, 20, 30]);
    }

    #[test]
    fn test_compiled_ruleset_empty() {
        let ruleset = CompiledRuleSet::empty("direct".into());
        assert!(ruleset.is_empty());
        assert_eq!(ruleset.len(), 0);
        assert_eq!(ruleset.default_outbound(), "direct");
    }

    #[test]
    fn test_compiled_ruleset_filters_disabled() {
        let rules = vec![
            Rule::new(1, RuleType::Domain, "a.com".into(), "proxy".into()).with_enabled(true),
            Rule::new(2, RuleType::Domain, "b.com".into(), "direct".into()).with_enabled(false),
            Rule::new(3, RuleType::Domain, "c.com".into(), "block".into()).with_enabled(true),
        ];

        let ruleset = CompiledRuleSet::new(rules, "direct".into()).unwrap();
        assert_eq!(ruleset.len(), 2); // Only enabled rules
    }

    #[test]
    fn test_compiled_ruleset_duplicate_id() {
        let rules = vec![
            Rule::new(1, RuleType::Domain, "a.com".into(), "proxy".into()),
            Rule::new(1, RuleType::Domain, "b.com".into(), "direct".into()), // Duplicate ID
        ];

        let result = CompiledRuleSet::new(rules, "direct".into());
        assert!(matches!(result, Err(RuleError::DuplicateRuleId(1))));
    }

    #[test]
    fn test_compiled_ruleset_outbound_targets() {
        let rules = vec![
            Rule::new(1, RuleType::Domain, "a.com".into(), "proxy".into()),
            Rule::new(2, RuleType::Domain, "b.com".into(), "direct".into()),
            Rule::new(3, RuleType::Domain, "c.com".into(), "proxy".into()), // Duplicate outbound
            Rule::new(4, RuleType::Domain, "d.com".into(), "block".into()),
        ];

        let ruleset = CompiledRuleSet::new(rules, "fallback".into()).unwrap();
        let targets: HashSet<&str> = ruleset.all_outbound_targets().collect();

        // Should include: proxy, direct, block, fallback (default)
        assert_eq!(targets.len(), 4);
        assert!(targets.contains("proxy"));
        assert!(targets.contains("direct"));
        assert!(targets.contains("block"));
        assert!(targets.contains("fallback"));
    }

    #[test]
    fn test_rule_serialization() {
        let rule = Rule::new(1, RuleType::DomainSuffix, ".google.com".into(), "proxy".into())
            .with_priority(10)
            .with_tag("test-tag");

        let json = serde_json::to_string_pretty(&rule).unwrap();
        assert!(json.contains("\"rule_type\": \"domain_suffix\""));
        assert!(json.contains("\"target\": \".google.com\""));
        assert!(json.contains("\"priority\": 10"));
        assert!(json.contains("\"tag\": \"test-tag\""));

        // Deserialize
        let parsed: Rule = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.id, 1);
        assert_eq!(parsed.rule_type, RuleType::DomainSuffix);
        assert_eq!(parsed.target, ".google.com");
        assert_eq!(parsed.outbound, "proxy");
        assert_eq!(parsed.priority, 10);
        assert_eq!(parsed.tag, Some("test-tag".into()));
    }

    #[test]
    fn test_rule_priority_sorting() {
        let rules = vec![
            Rule::new(1, RuleType::Domain, "low.com".into(), "low".into()).with_priority(100),
            Rule::new(2, RuleType::Domain, "high.com".into(), "high".into()).with_priority(-10),
            Rule::new(3, RuleType::Domain, "med.com".into(), "med".into()).with_priority(50),
            Rule::new(4, RuleType::Domain, "zero.com".into(), "zero".into()).with_priority(0),
        ];

        let ruleset = CompiledRuleSet::new(rules, "default".into()).unwrap();
        let targets: Vec<&str> = ruleset.iter().map(|r| r.target.as_str()).collect();

        // Should be sorted by priority: -10, 0, 50, 100
        assert_eq!(targets, vec!["high.com", "zero.com", "med.com", "low.com"]);
    }

    #[test]
    fn test_match_by_priority_port() {
        let rules = vec![
            Rule::new(1, RuleType::Port, "443".into(), "https".into()).with_priority(10),
            Rule::new(2, RuleType::Port, "80-8080".into(), "http".into()).with_priority(20),
        ];

        let ruleset = CompiledRuleSet::new(rules, "direct".into()).unwrap();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();

        assert_eq!(ruleset.match_by_priority(None, ip, 443), "https");
        assert_eq!(ruleset.match_by_priority(None, ip, 80), "http");
        assert_eq!(ruleset.match_by_priority(None, ip, 8080), "http");
        assert_eq!(ruleset.match_by_priority(None, ip, 22), "direct");
    }

    #[test]
    fn test_match_by_priority_protocol() {
        let rules = vec![
            Rule::new(1, RuleType::Protocol, "tcp".into(), "tcp-handler".into()),
        ];

        let ruleset = CompiledRuleSet::new(rules, "direct".into()).unwrap();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();

        // TCP matches in Phase 2.1
        assert_eq!(ruleset.match_by_priority(None, ip, 80), "tcp-handler");
    }

    #[test]
    fn test_match_by_priority_exact_domain() {
        let rules = vec![
            Rule::new(1, RuleType::Domain, "example.com".into(), "proxy".into()),
        ];

        let ruleset = CompiledRuleSet::new(rules, "direct".into()).unwrap();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();

        assert_eq!(
            ruleset.match_by_priority(Some("example.com"), ip, 80),
            "proxy"
        );
        assert_eq!(
            ruleset.match_by_priority(Some("EXAMPLE.COM"), ip, 80),
            "proxy"
        ); // Case insensitive
        assert_eq!(
            ruleset.match_by_priority(Some("other.com"), ip, 80),
            "direct"
        );
        assert_eq!(ruleset.match_by_priority(None, ip, 80), "direct");
    }

    #[test]
    fn test_routing_config() {
        let ruleset = CompiledRuleSet::empty("direct".into());
        let config = RoutingConfig::new(ruleset, "direct".into());

        assert_eq!(config.default_outbound, "direct");
        assert!(config.rules.is_empty());
    }
}
