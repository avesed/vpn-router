//! Builder for ControlPlaneHandler
//!
//! Provides a fluent API for constructing a fully configured ControlPlaneHandler.
//!
//! # Example
//!
//! ```ignore
//! use rust_router::controlplane::ControlPlaneBuilder;
//! use std::sync::Arc;
//! use std::time::Duration;
//!
//! let handler = ControlPlaneBuilder::new()
//!     .with_rule_engine(rule_engine)
//!     .with_outbound_manager(outbound_manager)
//!     .with_chain_manager(chain_manager)      // Optional
//!     .with_fakedns(fakedns)                  // Optional, feature-gated
//!     .with_dns_cache(dns_cache)              // Optional
//!     .with_default_outbound("direct")        // Default: "direct"
//!     .with_connect_timeout(Duration::from_secs(30))  // Default: 10s
//!     .build()?;
//! ```
//!
//! # Required Components
//!
//! The builder requires at minimum:
//! - `rule_engine`: For routing rule matching
//! - `outbound_manager`: For outbound connection management
//!
//! # Validation
//!
//! The `build()` method performs validation:
//! - Ensures required components are set
//! - Warns (does not fail) if chain_manager is set without matching fwmark configuration

use std::sync::Arc;
use std::time::Duration;

use tracing::warn;

use crate::chain::ChainManager;
use crate::ecmp::group::EcmpGroupManager;
use crate::ingress::dns_cache::IpDomainCache;
use crate::outbound::OutboundManager;
use crate::rules::engine::RuleEngine;

#[cfg(feature = "fakedns")]
use crate::fakedns::FakeDnsManager;

use super::error::ControlPlaneError;
use super::handler::{ControlPlaneConfig, ControlPlaneHandler};

/// Default outbound tag when no rules match
const DEFAULT_OUTBOUND: &str = "direct";

/// Default connection timeout
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Default maximum domain length (RFC 1035)
const DEFAULT_MAX_DOMAIN_LENGTH: usize = 253;

/// Builder for constructing a `ControlPlaneHandler`
///
/// Provides a fluent API for configuring all components of the control plane.
/// Required components are `rule_engine` and `outbound_manager`.
///
/// # Example
///
/// ```ignore
/// let handler = ControlPlaneBuilder::new()
///     .with_rule_engine(rule_engine)
///     .with_outbound_manager(outbound_manager)
///     .build()?;
/// ```
pub struct ControlPlaneBuilder {
    rule_engine: Option<Arc<RuleEngine>>,
    chain_manager: Option<Arc<ChainManager>>,
    outbound_manager: Option<Arc<OutboundManager>>,
    ecmp_manager: Option<Arc<EcmpGroupManager>>,
    #[cfg(feature = "fakedns")]
    fakedns: Option<Arc<FakeDnsManager>>,
    dns_cache: Option<Arc<IpDomainCache>>,
    default_outbound: String,
    connect_timeout: Duration,
    max_domain_length: usize,
}

impl ControlPlaneBuilder {
    /// Create a new builder with default values
    ///
    /// Default configuration:
    /// - `default_outbound`: "direct"
    /// - `connect_timeout`: 10 seconds
    /// - `max_domain_length`: 253 (RFC 1035)
    ///
    /// # Example
    ///
    /// ```ignore
    /// let builder = ControlPlaneBuilder::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            rule_engine: None,
            chain_manager: None,
            outbound_manager: None,
            ecmp_manager: None,
            #[cfg(feature = "fakedns")]
            fakedns: None,
            dns_cache: None,
            default_outbound: DEFAULT_OUTBOUND.to_string(),
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            max_domain_length: DEFAULT_MAX_DOMAIN_LENGTH,
        }
    }

    /// Set the rule engine (required)
    ///
    /// The rule engine is used for matching connections against routing rules.
    ///
    /// # Arguments
    ///
    /// * `rule_engine` - The rule engine instance
    ///
    /// # Example
    ///
    /// ```ignore
    /// builder.with_rule_engine(Arc::new(rule_engine))
    /// ```
    #[must_use]
    pub fn with_rule_engine(mut self, rule_engine: Arc<RuleEngine>) -> Self {
        self.rule_engine = Some(rule_engine);
        self
    }

    /// Set the outbound manager (required)
    ///
    /// The outbound manager provides access to outbound connections.
    ///
    /// # Arguments
    ///
    /// * `outbound_manager` - The outbound manager instance
    ///
    /// # Example
    ///
    /// ```ignore
    /// builder.with_outbound_manager(Arc::new(outbound_manager))
    /// ```
    #[must_use]
    pub fn with_outbound_manager(mut self, outbound_manager: Arc<OutboundManager>) -> Self {
        self.outbound_manager = Some(outbound_manager);
        self
    }

    /// Set the chain manager (optional)
    ///
    /// The chain manager enables DSCP-based multi-hop chain routing.
    /// If not set, chain routing will be disabled (DSCP packets blocked).
    ///
    /// # Arguments
    ///
    /// * `chain_manager` - The chain manager instance
    ///
    /// # Example
    ///
    /// ```ignore
    /// builder.with_chain_manager(Arc::new(chain_manager))
    /// ```
    #[must_use]
    pub fn with_chain_manager(mut self, chain_manager: Arc<ChainManager>) -> Self {
        self.chain_manager = Some(chain_manager);
        self
    }

    /// Set the FakeDNS manager (optional, feature-gated)
    ///
    /// FakeDNS enables domain-based routing by mapping IPs back to domains.
    /// This is only available when the `fakedns` feature is enabled.
    ///
    /// # Arguments
    ///
    /// * `fakedns` - The FakeDNS manager instance
    ///
    /// # Example
    ///
    /// ```ignore
    /// #[cfg(feature = "fakedns")]
    /// builder.with_fakedns(Arc::new(fakedns_manager))
    /// ```
    #[cfg(feature = "fakedns")]
    #[must_use]
    pub fn with_fakedns(mut self, fakedns: Arc<FakeDnsManager>) -> Self {
        self.fakedns = Some(fakedns);
        self
    }

    /// Set the DNS cache (optional)
    ///
    /// The DNS cache provides IP-to-domain lookups from DNS responses.
    /// This is used as a fallback when SNI and FakeDNS are unavailable.
    ///
    /// # Arguments
    ///
    /// * `dns_cache` - The DNS cache instance
    ///
    /// # Example
    ///
    /// ```ignore
    /// builder.with_dns_cache(Arc::new(dns_cache))
    /// ```
    #[must_use]
    pub fn with_dns_cache(mut self, dns_cache: Arc<IpDomainCache>) -> Self {
        self.dns_cache = Some(dns_cache);
        self
    }

    /// Set the ECMP group manager (optional)
    ///
    /// The ECMP manager enables load balancing across multiple outbound
    /// connections. When an outbound tag matches an ECMP group, the handler
    /// will select a member using the group's configured algorithm.
    ///
    /// # Arguments
    ///
    /// * `ecmp_manager` - The ECMP group manager instance
    ///
    /// # Example
    ///
    /// ```ignore
    /// builder.with_ecmp_manager(Arc::new(ecmp_manager))
    /// ```
    #[must_use]
    pub fn with_ecmp_manager(mut self, ecmp_manager: Arc<EcmpGroupManager>) -> Self {
        self.ecmp_manager = Some(ecmp_manager);
        self
    }

    /// Set the default outbound tag
    ///
    /// The default outbound is used when no rules match a connection.
    /// Default: "direct"
    ///
    /// # Arguments
    ///
    /// * `outbound` - The default outbound tag
    ///
    /// # Example
    ///
    /// ```ignore
    /// builder.with_default_outbound("my-proxy")
    /// ```
    #[must_use]
    pub fn with_default_outbound(mut self, outbound: impl Into<String>) -> Self {
        self.default_outbound = outbound.into();
        self
    }

    /// Set the connection timeout
    ///
    /// The timeout used when connecting to outbound destinations.
    /// Default: 10 seconds
    ///
    /// # Arguments
    ///
    /// * `timeout` - The connection timeout
    ///
    /// # Example
    ///
    /// ```ignore
    /// builder.with_connect_timeout(Duration::from_secs(30))
    /// ```
    #[must_use]
    pub fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Set the maximum domain length
    ///
    /// Domains longer than this limit will be rejected.
    /// Default: 253 (RFC 1035 maximum)
    ///
    /// # Arguments
    ///
    /// * `length` - The maximum domain length
    ///
    /// # Example
    ///
    /// ```ignore
    /// builder.with_max_domain_length(200)
    /// ```
    #[must_use]
    pub fn with_max_domain_length(mut self, length: usize) -> Self {
        self.max_domain_length = length;
        self
    }

    /// Set all components at once
    ///
    /// Convenience method for setting all required and common optional components
    /// in a single call. This is useful when you have all components ready.
    ///
    /// # Arguments
    ///
    /// * `rule_engine` - The rule engine instance (required)
    /// * `outbound_manager` - The outbound manager instance (required)
    /// * `chain_manager` - The chain manager instance (optional)
    /// * `dns_cache` - The DNS cache instance (optional)
    ///
    /// # Example
    ///
    /// ```ignore
    /// builder.with_all_components(
    ///     rule_engine,
    ///     outbound_manager,
    ///     Some(chain_manager),
    ///     Some(dns_cache),
    /// )
    /// ```
    #[must_use]
    pub fn with_all_components(
        mut self,
        rule_engine: Arc<RuleEngine>,
        outbound_manager: Arc<OutboundManager>,
        chain_manager: Option<Arc<ChainManager>>,
        dns_cache: Option<Arc<IpDomainCache>>,
    ) -> Self {
        self.rule_engine = Some(rule_engine);
        self.outbound_manager = Some(outbound_manager);
        self.chain_manager = chain_manager;
        self.dns_cache = dns_cache;
        self
    }

    /// Build the `ControlPlaneHandler`
    ///
    /// Validates that required components are set and constructs the handler.
    ///
    /// # Errors
    ///
    /// Returns `ControlPlaneError::MissingComponent` if:
    /// - `rule_engine` is not set
    /// - `outbound_manager` is not set
    ///
    /// # Validation
    ///
    /// Logs a warning (does not fail) if:
    /// - `chain_manager` is set but `fwmark_router` has no chains registered
    ///
    /// # Example
    ///
    /// ```ignore
    /// let handler = builder.build()?;
    /// ```
    pub fn build(self) -> Result<ControlPlaneHandler, ControlPlaneError> {
        // Validate required components
        let rule_engine = self
            .rule_engine
            .ok_or(ControlPlaneError::MissingComponent("rule_engine"))?;

        let outbound_manager = self
            .outbound_manager
            .ok_or(ControlPlaneError::MissingComponent("outbound_manager"))?;

        // Validate chain/fwmark sync (warning only)
        if let Some(ref chain_manager) = self.chain_manager {
            let snapshot = rule_engine.load();
            let fwmark_chain_count = snapshot.fwmark_router.chains().count();
            let chain_count = chain_manager.list_chains().len();

            if chain_count > 0 && fwmark_chain_count == 0 {
                warn!(
                    chain_count = chain_count,
                    "ChainManager has {} chains but FwmarkRouter has no chains registered. \
                     Chain routing may not work correctly. \
                     Ensure chains are added to the rule engine via add_chain_with_dscp().",
                    chain_count
                );
            }
        }

        // Build configuration
        let config = ControlPlaneConfig {
            default_outbound: self.default_outbound,
            connect_timeout: self.connect_timeout,
            max_domain_length: self.max_domain_length,
        };

        // Create handler with config
        let mut handler = ControlPlaneHandler::with_config(rule_engine, outbound_manager, config);

        // Set optional components
        if let Some(chain_manager) = self.chain_manager {
            handler.set_chain_manager(chain_manager);
        }

        #[cfg(feature = "fakedns")]
        if let Some(fakedns) = self.fakedns {
            handler.set_fakedns(fakedns);
        }

        if let Some(dns_cache) = self.dns_cache {
            handler.set_dns_cache(dns_cache);
        }

        if let Some(ecmp_manager) = self.ecmp_manager {
            handler.set_ecmp_manager(ecmp_manager);
        }

        Ok(handler)
    }
}

impl Default for ControlPlaneBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for ControlPlaneBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut debug = f.debug_struct("ControlPlaneBuilder");
        debug
            .field("has_rule_engine", &self.rule_engine.is_some())
            .field("has_chain_manager", &self.chain_manager.is_some())
            .field("has_outbound_manager", &self.outbound_manager.is_some())
            .field("has_ecmp_manager", &self.ecmp_manager.is_some())
            .field("has_dns_cache", &self.dns_cache.is_some())
            .field("default_outbound", &self.default_outbound)
            .field("connect_timeout", &self.connect_timeout)
            .field("max_domain_length", &self.max_domain_length);

        #[cfg(feature = "fakedns")]
        debug.field("has_fakedns", &self.fakedns.is_some());

        debug.finish()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::outbound::DirectOutbound;
    use crate::rules::engine::RoutingSnapshotBuilder;

    fn create_test_rule_engine() -> Arc<RuleEngine> {
        let snapshot = RoutingSnapshotBuilder::new()
            .default_outbound("direct")
            .version(1)
            .build()
            .unwrap();
        Arc::new(RuleEngine::new(snapshot))
    }

    fn create_test_outbound_manager() -> Arc<OutboundManager> {
        let manager = OutboundManager::new();
        manager.add(Box::new(DirectOutbound::simple("direct")));
        Arc::new(manager)
    }

    // =========================================================================
    // Missing Component Tests
    // =========================================================================

    #[test]
    fn test_builder_missing_rule_engine() {
        let result = ControlPlaneBuilder::new()
            .with_outbound_manager(create_test_outbound_manager())
            .build();

        assert!(result.is_err());
        match result {
            Err(ControlPlaneError::MissingComponent(component)) => {
                assert_eq!(component, "rule_engine");
            }
            _ => panic!("Expected MissingComponent error for rule_engine"),
        }
    }

    #[test]
    fn test_builder_missing_outbound_manager() {
        let result = ControlPlaneBuilder::new()
            .with_rule_engine(create_test_rule_engine())
            .build();

        assert!(result.is_err());
        match result {
            Err(ControlPlaneError::MissingComponent(component)) => {
                assert_eq!(component, "outbound_manager");
            }
            _ => panic!("Expected MissingComponent error for outbound_manager"),
        }
    }

    // =========================================================================
    // Successful Build Tests
    // =========================================================================

    #[test]
    fn test_builder_with_required_only() {
        let result = ControlPlaneBuilder::new()
            .with_rule_engine(create_test_rule_engine())
            .with_outbound_manager(create_test_outbound_manager())
            .build();

        assert!(result.is_ok());
        let handler = result.unwrap();

        // Verify defaults
        assert_eq!(handler.config().default_outbound, "direct");
        assert_eq!(handler.config().connect_timeout, Duration::from_secs(10));
        assert_eq!(handler.config().max_domain_length, 253);
        assert!(!handler.chain_handler().has_chain_manager());
    }

    #[test]
    fn test_builder_with_all_components() {
        let rule_engine = create_test_rule_engine();
        let outbound_manager = create_test_outbound_manager();
        let chain_manager = Arc::new(ChainManager::new("test-node".to_string()));
        let dns_cache = Arc::new(IpDomainCache::default());

        let result = ControlPlaneBuilder::new()
            .with_all_components(
                rule_engine,
                outbound_manager,
                Some(chain_manager),
                Some(dns_cache),
            )
            .build();

        assert!(result.is_ok());
        let handler = result.unwrap();
        assert!(handler.chain_handler().has_chain_manager());
    }

    // =========================================================================
    // Default Value Tests
    // =========================================================================

    #[test]
    fn test_builder_default_values() {
        let builder = ControlPlaneBuilder::new();

        // Check defaults through debug output
        let debug_str = format!("{:?}", builder);
        assert!(debug_str.contains("default_outbound"));
        assert!(debug_str.contains("direct"));
        assert!(debug_str.contains("has_rule_engine"));
        assert!(debug_str.contains("false"));
    }

    #[test]
    fn test_builder_default_trait() {
        let builder = ControlPlaneBuilder::default();
        let result = builder
            .with_rule_engine(create_test_rule_engine())
            .with_outbound_manager(create_test_outbound_manager())
            .build();

        assert!(result.is_ok());
    }

    // =========================================================================
    // Custom Configuration Tests
    // =========================================================================

    #[test]
    fn test_builder_custom_config() {
        let result = ControlPlaneBuilder::new()
            .with_rule_engine(create_test_rule_engine())
            .with_outbound_manager(create_test_outbound_manager())
            .with_default_outbound("my-proxy")
            .with_connect_timeout(Duration::from_secs(30))
            .with_max_domain_length(200)
            .build();

        assert!(result.is_ok());
        let handler = result.unwrap();

        assert_eq!(handler.config().default_outbound, "my-proxy");
        assert_eq!(handler.config().connect_timeout, Duration::from_secs(30));
        assert_eq!(handler.config().max_domain_length, 200);
    }

    #[test]
    fn test_builder_with_chain_manager() {
        let chain_manager = Arc::new(ChainManager::new("test-node".to_string()));

        let result = ControlPlaneBuilder::new()
            .with_rule_engine(create_test_rule_engine())
            .with_outbound_manager(create_test_outbound_manager())
            .with_chain_manager(chain_manager)
            .build();

        assert!(result.is_ok());
        let handler = result.unwrap();
        assert!(handler.chain_handler().has_chain_manager());
    }

    #[test]
    fn test_builder_with_dns_cache() {
        let dns_cache = Arc::new(IpDomainCache::default());

        let result = ControlPlaneBuilder::new()
            .with_rule_engine(create_test_rule_engine())
            .with_outbound_manager(create_test_outbound_manager())
            .with_dns_cache(dns_cache)
            .build();

        assert!(result.is_ok());
    }

    // =========================================================================
    // Fluent API Tests
    // =========================================================================

    #[test]
    fn test_builder_fluent_chaining() {
        // Verify all methods return Self for chaining
        let handler = ControlPlaneBuilder::new()
            .with_rule_engine(create_test_rule_engine())
            .with_outbound_manager(create_test_outbound_manager())
            .with_default_outbound("direct")
            .with_connect_timeout(Duration::from_secs(10))
            .with_max_domain_length(253)
            .build()
            .unwrap();

        // If we got here, chaining worked
        assert_eq!(handler.config().default_outbound, "direct");
    }

    // =========================================================================
    // Debug Implementation Tests
    // =========================================================================

    #[test]
    fn test_builder_debug() {
        let builder = ControlPlaneBuilder::new()
            .with_rule_engine(create_test_rule_engine())
            .with_default_outbound("proxy");

        let debug_str = format!("{:?}", builder);
        assert!(debug_str.contains("ControlPlaneBuilder"));
        assert!(debug_str.contains("has_rule_engine"));
        assert!(debug_str.contains("true"));
        assert!(debug_str.contains("proxy"));
    }
}
