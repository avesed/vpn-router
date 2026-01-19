//! Rule engine module for routing decisions
//!
//! This module provides:
//! - Rule type definitions
//! - Domain matching (Phase 2.2)
//! - `GeoIP` matching (Phase 2.3)
//! - fwmark/DSCP routing (Phase 2.4)
//! - Hot-reloadable rule engine (Phase 2.5)
//!
//! # Architecture
//!
//! Rules are processed in priority order (lower values = higher priority).
//! The first matching rule determines the outbound for a connection.
//!
//! # Example
//!
//! ```
//! use rust_router::rules::{Rule, RuleType, CompiledRuleSet};
//!
//! // Create rules
//! let rules = vec![
//!     Rule::new(1, RuleType::DomainSuffix, ".google.com".into(), "proxy".into())
//!         .with_priority(10),
//!     Rule::new(2, RuleType::GeoIP, "CN".into(), "direct".into())
//!         .with_priority(20),
//! ];
//!
//! // Compile for fast matching
//! let ruleset = CompiledRuleSet::new(rules, "direct".into()).unwrap();
//! assert_eq!(ruleset.default_outbound(), "direct");
//! ```
//!
//! # Domain Matching (Phase 2.2)
//!
//! High-performance domain matching using Aho-Corasick algorithm:
//!
//! ```
//! use rust_router::rules::domain::DomainMatcher;
//!
//! let matcher = DomainMatcher::builder()
//!     .add_exact("example.com", "direct")
//!     .add_suffix("google.com", "proxy")
//!     .add_keyword("ads", "block")
//!     .build()
//!     .unwrap();
//!
//! assert_eq!(matcher.match_domain("example.com"), Some("direct"));
//! assert_eq!(matcher.match_domain("www.google.com"), Some("proxy"));
//! assert_eq!(matcher.match_domain("ads.example.org"), Some("block"));
//! ```
//!
//! # `GeoIP` Matching (Phase 2.3)
//!
//! IP-based routing with CIDR and country code matching:
//!
//! ```
//! use rust_router::rules::geoip::GeoIpMatcher;
//! use std::net::IpAddr;
//!
//! let matcher = GeoIpMatcher::builder()
//!     .add_cidr("192.168.0.0/16", "local")
//!     .unwrap()
//!     .add_cidr("10.0.0.0/8", "private")
//!     .unwrap()
//!     .build()
//!     .unwrap();
//!
//! let ip: IpAddr = "192.168.1.100".parse().unwrap();
//! assert_eq!(matcher.match_ip(ip), Some("local"));
//!
//! let ip: IpAddr = "8.8.8.8".parse().unwrap();
//! assert_eq!(matcher.match_ip(ip), None);
//! ```
//!
//! # fwmark/DSCP Chain Routing (Phase 2.4)
//!
//! DSCP-based multi-hop chain routing:
//!
//! ```
//! use rust_router::rules::fwmark::{ChainMark, FwmarkRouter, DSCP_MIN, DSCP_MAX};
//!
//! // Create a chain mark from DSCP value
//! let mark = ChainMark::from_dscp(5).expect("valid DSCP");
//! assert_eq!(mark.dscp_value, 5);
//!
//! // Build a fwmark router with chains
//! let router = FwmarkRouter::builder()
//!     .add_chain("us-stream").unwrap()
//!     .add_chain("jp-gaming").unwrap()
//!     .build();
//!
//! assert!(router.is_chain("us-stream"));
//! assert!(!router.is_chain("direct"));
//! ```
//!
//! # Hot-Reloadable Rule Engine (Phase 2.5)
//!
//! Lock-free routing configuration with atomic hot-reload:
//!
//! ```
//! use rust_router::rules::engine::{RuleEngine, RoutingSnapshotBuilder, ConnectionInfo};
//! use rust_router::rules::RuleType;
//!
//! // Build initial configuration
//! let mut builder = RoutingSnapshotBuilder::new();
//! builder
//!     .add_domain_rule(RuleType::DomainSuffix, "google.com", "proxy")
//!     .unwrap();
//! let snapshot = builder.default_outbound("direct").version(1).build().unwrap();
//!
//! // Create engine (lock-free reads)
//! let engine = RuleEngine::new(snapshot);
//!
//! // Match connections
//! let conn = ConnectionInfo::new("tcp", 443).with_domain("www.google.com");
//! let result = engine.match_connection(&conn);
//! assert_eq!(result.outbound, "proxy");
//!
//! // Hot reload (atomic swap)
//! let new_snapshot = RoutingSnapshotBuilder::new()
//!     .default_outbound("block")
//!     .version(2)
//!     .build()
//!     .unwrap();
//! engine.reload(new_snapshot);
//! assert_eq!(engine.version(), 2);
//! ```

pub mod domain;
pub mod engine;
pub mod fwmark;
pub mod geoip;
pub mod types;

// Re-exports
pub use domain::{DomainMatcher, DomainMatcherBuilder};
pub use engine::{
    ConnectionInfo, MatchResult, MatchedRule, RoutingSnapshot, RoutingSnapshotBuilder, RuleEngine,
    RuleEngineRoutingCallback, SnapshotStats,
};
pub use fwmark::{
    dscp_to_routing_mark, dscp_to_routing_table, is_dscp_terminal_table, is_ecmp_table,
    is_peer_table, is_relay_table, is_reserved_dscp, is_valid_dscp, routing_mark_to_dscp, tables,
    ChainMark, FwmarkRouter, FwmarkRouterBuilder, DSCP_MAX, DSCP_MIN, ENTRY_ROUTING_MARK_BASE,
    MAX_CHAINS, RESERVED_DSCP_VALUES,
};
pub use geoip::{CountryInfo, GeoIpMatcher, GeoIpMatcherBuilder};
pub use types::*;
