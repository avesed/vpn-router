//! Control plane error types
//!
//! This module defines error types for the control plane, which bridges the
//! data plane (netbridge) with control components (rules, chain, fakedns, sniff).
//!
//! # Error Categories
//!
//! Errors are classified into categories that help determine appropriate handling:
//!
//! - **Should Reject**: Connection should be rejected (blocked, invalid, etc.)
//! - **Transient**: May resolve on retry (temporary failures, timeouts)
//! - **Permanent**: Will not resolve without intervention (misconfiguration)
//!
//! # Example
//!
//! ```ignore
//! use rust_router::controlplane::{ControlPlaneError, Result};
//!
//! fn route_connection() -> Result<String> {
//!     // ... routing logic ...
//!     Err(ControlPlaneError::OutboundNotFound("direct".to_string()))
//! }
//!
//! fn main() {
//!     match route_connection() {
//!         Ok(outbound) => println!("Routed to: {}", outbound),
//!         Err(e) if e.should_reject() => println!("Reject connection: {}", e),
//!         Err(e) if e.is_transient() => println!("Retry later: {}", e),
//!         Err(e) => println!("Error: {}", e),
//!     }
//! }
//! ```

use std::io;

use thiserror::Error;

/// Control plane errors
///
/// These errors represent failures in the control plane layer that bridges
/// the data plane with routing components.
#[derive(Debug, Error)]
pub enum ControlPlaneError {
    // =========================================================================
    // Outbound Errors
    // =========================================================================
    /// Outbound not found in `OutboundManager`
    ///
    /// The specified outbound tag does not exist in the outbound registry.
    #[error("outbound not found: {0}")]
    OutboundNotFound(String),

    /// Failed to connect to outbound
    ///
    /// The outbound exists but connection establishment failed.
    #[error("outbound connect failed: {0}")]
    OutboundConnect(#[source] Box<dyn std::error::Error + Send + Sync>),

    /// Outbound is temporarily unavailable
    ///
    /// The outbound exists but is currently unavailable (e.g., tunnel down).
    #[error("outbound unavailable: {0}")]
    OutboundUnavailable(String),

    // =========================================================================
    // Component Configuration Errors
    // =========================================================================
    /// Required component not configured
    ///
    /// A required component (e.g., `rule_engine`, `outbound_manager`) was not
    /// provided to the control plane handler.
    #[error("missing component: {0}")]
    MissingComponent(&'static str),

    /// Component initialization failed
    ///
    /// A component failed to initialize properly.
    #[error("component initialization failed: {component}: {reason}")]
    ComponentInitFailed {
        /// Component name
        component: &'static str,
        /// Failure reason
        reason: String,
    },

    // =========================================================================
    // Chain Routing Errors
    // =========================================================================
    /// Chain routing error
    ///
    /// An error occurred during DSCP chain routing (invalid state, missing hop).
    #[error("chain routing error: {0}")]
    ChainRouting(String),

    /// Invalid chain state
    ///
    /// The chain is in an invalid state for the requested operation.
    #[error("invalid chain state: expected {expected}, got {actual}")]
    InvalidChainState {
        /// Expected state
        expected: String,
        /// Actual state
        actual: String,
    },

    /// Chain not found
    ///
    /// The specified chain does not exist.
    #[error("chain not found: {0}")]
    ChainNotFound(String),

    // =========================================================================
    // Domain and DNS Errors
    // =========================================================================
    /// Invalid domain
    ///
    /// The domain name is invalid (too long, contains null bytes, etc.).
    #[error("invalid domain: {0}")]
    InvalidDomain(String),

    /// `FakeDNS` lookup error
    ///
    /// Failed to look up domain from `FakeDNS` IP mapping.
    #[error("fakedns error: {0}")]
    FakeDnsError(String),

    /// Domain resolution failed
    ///
    /// Failed to resolve a domain name.
    #[error("domain resolution failed: {0}")]
    DomainResolutionFailed(String),

    // =========================================================================
    // Rule Matching Errors
    // =========================================================================
    /// Rule matching error
    ///
    /// An error occurred while matching rules against the connection.
    #[error("rule matching error: {0}")]
    RuleMatching(String),

    /// No matching rule found
    ///
    /// No rule matched the connection (should use default outbound).
    #[error("no matching rule for connection")]
    NoMatchingRule,

    /// Rule blocked the connection
    ///
    /// A blocking rule matched the connection.
    #[error("connection blocked by rule: {0}")]
    BlockedByRule(String),

    // =========================================================================
    // SNI/Protocol Errors
    // =========================================================================
    /// SNI extraction failed
    ///
    /// Failed to extract SNI from TLS `ClientHello`.
    #[error("SNI extraction failed: {0}")]
    SniExtractionFailed(String),

    /// Protocol detection failed
    ///
    /// Failed to detect the protocol of the connection.
    #[error("protocol detection failed: {0}")]
    ProtocolDetectionFailed(String),

    // =========================================================================
    // Connection Errors
    // =========================================================================
    /// Invalid connection info
    ///
    /// The connection information is invalid or incomplete.
    #[error("invalid connection info: {0}")]
    InvalidConnectionInfo(String),

    /// Connection timeout
    ///
    /// The operation timed out.
    #[error("connection timeout")]
    Timeout,

    /// Connection cancelled
    ///
    /// The operation was cancelled (e.g., shutdown in progress).
    #[error("operation cancelled")]
    Cancelled,

    // =========================================================================
    // Underlying Errors
    // =========================================================================
    /// I/O error
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    /// `NetBridge` error
    #[error("netbridge error: {0}")]
    NetBridge(#[from] crate::netbridge::NetBridgeError),

    /// Internal error
    ///
    /// An unexpected internal error occurred.
    #[error("internal error: {0}")]
    Internal(String),
}

impl ControlPlaneError {
    /// Returns true if the connection should be rejected
    ///
    /// When this returns true, the connection should be closed without
    /// forwarding any data.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let err = ControlPlaneError::BlockedByRule("adblock".to_string());
    /// assert!(err.should_reject());
    ///
    /// let err = ControlPlaneError::OutboundUnavailable("tunnel".to_string());
    /// assert!(!err.should_reject());
    /// ```
    #[must_use]
    pub fn should_reject(&self) -> bool {
        matches!(
            self,
            Self::BlockedByRule(_)
                | Self::InvalidDomain(_)
                | Self::InvalidConnectionInfo(_)
                | Self::MissingComponent(_)
        )
    }

    /// Returns true if the error is transient and may resolve on retry
    ///
    /// Transient errors may succeed if retried after a delay.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let err = ControlPlaneError::OutboundUnavailable("tunnel".to_string());
    /// assert!(err.is_transient());
    ///
    /// let err = ControlPlaneError::OutboundNotFound("direct".to_string());
    /// assert!(!err.is_transient());
    /// ```
    #[must_use]
    pub fn is_transient(&self) -> bool {
        matches!(
            self,
            Self::OutboundUnavailable(_)
                | Self::Timeout
                | Self::Cancelled
                | Self::DomainResolutionFailed(_)
                | Self::FakeDnsError(_)
        )
    }

    /// Returns true if the error is permanent and will not resolve
    ///
    /// Permanent errors indicate misconfiguration or logic errors that
    /// require external intervention.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let err = ControlPlaneError::OutboundNotFound("nonexistent".to_string());
    /// assert!(err.is_permanent());
    /// ```
    #[must_use]
    pub fn is_permanent(&self) -> bool {
        matches!(
            self,
            Self::OutboundNotFound(_)
                | Self::MissingComponent(_)
                | Self::ComponentInitFailed { .. }
                | Self::ChainNotFound(_)
                | Self::InvalidDomain(_)
                | Self::InvalidConnectionInfo(_)
        )
    }

    /// Returns true if this is a chain-related error
    #[must_use]
    pub fn is_chain_error(&self) -> bool {
        matches!(
            self,
            Self::ChainRouting(_) | Self::InvalidChainState { .. } | Self::ChainNotFound(_)
        )
    }

    /// Returns true if this is a rule-related error
    #[must_use]
    pub fn is_rule_error(&self) -> bool {
        matches!(
            self,
            Self::RuleMatching(_) | Self::NoMatchingRule | Self::BlockedByRule(_)
        )
    }

    /// Returns true if this is an outbound-related error
    #[must_use]
    pub fn is_outbound_error(&self) -> bool {
        matches!(
            self,
            Self::OutboundNotFound(_) | Self::OutboundConnect(_) | Self::OutboundUnavailable(_)
        )
    }

    // =========================================================================
    // Constructor Helpers
    // =========================================================================

    /// Create an outbound connect error from any error type
    pub fn outbound_connect<E>(err: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::OutboundConnect(Box::new(err))
    }

    /// Create a component initialization error
    pub fn component_init_failed(component: &'static str, reason: impl Into<String>) -> Self {
        Self::ComponentInitFailed {
            component,
            reason: reason.into(),
        }
    }

    /// Create an invalid chain state error
    pub fn invalid_chain_state(expected: impl Into<String>, actual: impl Into<String>) -> Self {
        Self::InvalidChainState {
            expected: expected.into(),
            actual: actual.into(),
        }
    }

    /// Create a chain routing error
    pub fn chain_routing(msg: impl Into<String>) -> Self {
        Self::ChainRouting(msg.into())
    }

    /// Create a rule matching error
    pub fn rule_matching(msg: impl Into<String>) -> Self {
        Self::RuleMatching(msg.into())
    }

    /// Create a blocked by rule error
    pub fn blocked(rule_name: impl Into<String>) -> Self {
        Self::BlockedByRule(rule_name.into())
    }

    /// Create an invalid domain error
    pub fn invalid_domain(reason: impl Into<String>) -> Self {
        Self::InvalidDomain(reason.into())
    }

    /// Create a `FakeDNS` error
    pub fn fakedns(msg: impl Into<String>) -> Self {
        Self::FakeDnsError(msg.into())
    }

    /// Create an internal error
    pub fn internal(msg: impl Into<String>) -> Self {
        Self::Internal(msg.into())
    }
}

/// A specialized Result type for control plane operations
pub type Result<T> = std::result::Result<T, ControlPlaneError>;

// =============================================================================
// Conversions from other error types
// =============================================================================

impl From<crate::error::RuleError> for ControlPlaneError {
    fn from(err: crate::error::RuleError) -> Self {
        Self::RuleMatching(err.to_string())
    }
}

impl From<crate::chain::ChainError> for ControlPlaneError {
    fn from(err: crate::chain::ChainError) -> Self {
        Self::ChainRouting(err.to_string())
    }
}

impl From<crate::transport::TransportError> for ControlPlaneError {
    fn from(err: crate::transport::TransportError) -> Self {
        Self::OutboundConnect(Box::new(err))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = ControlPlaneError::OutboundNotFound("direct".to_string());
        assert_eq!(err.to_string(), "outbound not found: direct");

        let err = ControlPlaneError::MissingComponent("rule_engine");
        assert_eq!(err.to_string(), "missing component: rule_engine");

        let err = ControlPlaneError::blocked("adblock");
        assert_eq!(err.to_string(), "connection blocked by rule: adblock");

        let err = ControlPlaneError::invalid_chain_state("active", "inactive");
        assert!(err.to_string().contains("expected active"));
        assert!(err.to_string().contains("got inactive"));
    }

    #[test]
    fn test_should_reject() {
        assert!(ControlPlaneError::blocked("rule").should_reject());
        assert!(ControlPlaneError::invalid_domain("bad").should_reject());
        assert!(ControlPlaneError::InvalidConnectionInfo("bad".to_string()).should_reject());
        assert!(ControlPlaneError::MissingComponent("x").should_reject());

        assert!(!ControlPlaneError::OutboundUnavailable("tunnel".to_string()).should_reject());
        assert!(!ControlPlaneError::Timeout.should_reject());
        assert!(!ControlPlaneError::OutboundNotFound("x".to_string()).should_reject());
    }

    #[test]
    fn test_is_transient() {
        assert!(ControlPlaneError::OutboundUnavailable("tunnel".to_string()).is_transient());
        assert!(ControlPlaneError::Timeout.is_transient());
        assert!(ControlPlaneError::Cancelled.is_transient());
        assert!(ControlPlaneError::DomainResolutionFailed("err".to_string()).is_transient());
        assert!(ControlPlaneError::fakedns("lookup failed").is_transient());

        assert!(!ControlPlaneError::OutboundNotFound("x".to_string()).is_transient());
        assert!(!ControlPlaneError::blocked("rule").is_transient());
    }

    #[test]
    fn test_is_permanent() {
        assert!(ControlPlaneError::OutboundNotFound("x".to_string()).is_permanent());
        assert!(ControlPlaneError::MissingComponent("x").is_permanent());
        assert!(ControlPlaneError::component_init_failed("x", "y").is_permanent());
        assert!(ControlPlaneError::ChainNotFound("chain1".to_string()).is_permanent());
        assert!(ControlPlaneError::invalid_domain("bad").is_permanent());

        assert!(!ControlPlaneError::Timeout.is_permanent());
        assert!(!ControlPlaneError::blocked("rule").is_permanent());
    }

    #[test]
    fn test_is_chain_error() {
        assert!(ControlPlaneError::chain_routing("err").is_chain_error());
        assert!(ControlPlaneError::invalid_chain_state("a", "b").is_chain_error());
        assert!(ControlPlaneError::ChainNotFound("c".to_string()).is_chain_error());

        assert!(!ControlPlaneError::OutboundNotFound("x".to_string()).is_chain_error());
    }

    #[test]
    fn test_is_rule_error() {
        assert!(ControlPlaneError::rule_matching("err").is_rule_error());
        assert!(ControlPlaneError::NoMatchingRule.is_rule_error());
        assert!(ControlPlaneError::blocked("rule").is_rule_error());

        assert!(!ControlPlaneError::ChainRouting("x".to_string()).is_rule_error());
    }

    #[test]
    fn test_is_outbound_error() {
        assert!(ControlPlaneError::OutboundNotFound("x".to_string()).is_outbound_error());
        assert!(ControlPlaneError::OutboundUnavailable("x".to_string()).is_outbound_error());
        assert!(ControlPlaneError::outbound_connect(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            "refused"
        ))
        .is_outbound_error());

        assert!(!ControlPlaneError::Timeout.is_outbound_error());
    }

    #[test]
    fn test_io_error_conversion() {
        let io_err = io::Error::new(io::ErrorKind::ConnectionReset, "reset");
        let ctrl_err: ControlPlaneError = io_err.into();
        assert!(matches!(ctrl_err, ControlPlaneError::Io(_)));
        assert!(ctrl_err.to_string().contains("reset"));
    }

    #[test]
    fn test_netbridge_error_conversion() {
        let nb_err = crate::netbridge::NetBridgeError::ConnectionTimeout;
        let ctrl_err: ControlPlaneError = nb_err.into();
        assert!(matches!(ctrl_err, ControlPlaneError::NetBridge(_)));
    }

    #[test]
    fn test_constructor_helpers() {
        let err = ControlPlaneError::outbound_connect(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            "refused",
        ));
        assert!(matches!(err, ControlPlaneError::OutboundConnect(_)));

        let err = ControlPlaneError::component_init_failed("rule_engine", "load failed");
        assert!(matches!(err, ControlPlaneError::ComponentInitFailed { .. }));

        let err = ControlPlaneError::internal("unexpected state");
        assert!(matches!(err, ControlPlaneError::Internal(_)));
    }

    #[test]
    fn test_error_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<ControlPlaneError>();
    }
}
