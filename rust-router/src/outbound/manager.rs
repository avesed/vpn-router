//! Outbound Manager
//!
//! This module provides centralized management of outbound connections,
//! including registration, lookup, and health monitoring.

use std::collections::HashMap;
use std::sync::Arc;

use dashmap::DashMap;
use tracing::{debug, info};

use super::traits::{HealthStatus, Outbound};
use crate::config::OutboundConfig;
use crate::connection::OutboundStatsSnapshot;

/// Manages all configured outbounds
pub struct OutboundManager {
    /// Map of outbound tag to outbound implementation
    outbounds: DashMap<String, Arc<dyn Outbound>>,
}

impl OutboundManager {
    /// Create a new outbound manager
    #[must_use]
    pub fn new() -> Self {
        Self {
            outbounds: DashMap::new(),
        }
    }

    /// Add an outbound to the manager
    pub fn add(&self, outbound: Box<dyn Outbound>) {
        let tag = outbound.tag().to_string();
        info!(
            "Adding outbound: {} (type: {})",
            tag,
            outbound.outbound_type()
        );
        self.outbounds.insert(tag, Arc::from(outbound));
    }

    /// Get an outbound by tag
    #[must_use]
    pub fn get(&self, tag: &str) -> Option<Arc<dyn Outbound>> {
        self.outbounds.get(tag).map(|r| Arc::clone(r.value()))
    }

    /// Remove an outbound by tag
    pub fn remove(&self, tag: &str) -> Option<Arc<dyn Outbound>> {
        info!("Removing outbound: {}", tag);
        self.outbounds.remove(tag).map(|(_, v)| v)
    }

    /// Check if an outbound exists
    #[must_use]
    pub fn contains(&self, tag: &str) -> bool {
        self.outbounds.contains_key(tag)
    }

    /// Get all outbound tags
    #[must_use]
    pub fn tags(&self) -> Vec<String> {
        self.outbounds.iter().map(|r| r.key().clone()).collect()
    }

    /// Get the number of registered outbounds
    #[must_use]
    pub fn len(&self) -> usize {
        self.outbounds.len()
    }

    /// Check if no outbounds are registered
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.outbounds.is_empty()
    }

    /// Get all outbounds
    pub fn all(&self) -> Vec<Arc<dyn Outbound>> {
        self.outbounds.iter().map(|r| Arc::clone(r.value())).collect()
    }

    /// Get all enabled outbounds
    pub fn enabled(&self) -> Vec<Arc<dyn Outbound>> {
        self.outbounds
            .iter()
            .filter(|r| r.value().is_enabled())
            .map(|r| Arc::clone(r.value()))
            .collect()
    }

    /// Get all healthy outbounds
    pub fn healthy(&self) -> Vec<Arc<dyn Outbound>> {
        self.outbounds
            .iter()
            .filter(|r| {
                let o = r.value();
                o.is_enabled() && o.health_status().is_available()
            })
            .map(|r| Arc::clone(r.value()))
            .collect()
    }

    /// Get health status of all outbounds
    #[must_use]
    pub fn health_summary(&self) -> HashMap<String, HealthStatus> {
        self.outbounds
            .iter()
            .map(|r| (r.key().clone(), r.value().health_status()))
            .collect()
    }

    /// Get statistics for all outbounds
    #[must_use]
    pub fn stats_summary(&self) -> HashMap<String, OutboundStatsSnapshot> {
        self.outbounds
            .iter()
            .map(|r| (r.key().clone(), r.value().stats().snapshot()))
            .collect()
    }

    /// Get an available outbound, preferring healthy ones
    ///
    /// Returns the first healthy outbound, or any available outbound
    /// if no healthy ones exist.
    #[must_use]
    pub fn get_available(&self, preferred_tag: &str) -> Option<Arc<dyn Outbound>> {
        // Try preferred first
        if let Some(outbound) = self.get(preferred_tag) {
            if outbound.is_enabled() && outbound.health_status().is_available() {
                return Some(outbound);
            }
        }

        // Try any healthy outbound
        self.healthy().into_iter().next()
    }

    /// Log current status of all outbounds
    pub fn log_status(&self) {
        for entry in &self.outbounds {
            let outbound = entry.value();
            let stats = outbound.stats();
            debug!(
                "Outbound {}: type={} enabled={} health={} connections={}",
                outbound.tag(),
                outbound.outbound_type(),
                outbound.is_enabled(),
                outbound.health_status(),
                stats.connections()
            );
        }
    }
}

impl Default for OutboundManager {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for OutboundManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutboundManager")
            .field("count", &self.len())
            .field("tags", &self.tags())
            .finish()
    }
}

/// Builder for creating an `OutboundManager` from configuration
pub struct OutboundManagerBuilder {
    manager: OutboundManager,
}

impl OutboundManagerBuilder {
    /// Create a new builder
    #[must_use]
    pub fn new() -> Self {
        Self {
            manager: OutboundManager::new(),
        }
    }

    /// Add an outbound from configuration
    pub fn add_from_config(&mut self, config: &OutboundConfig) -> &mut Self {
        use super::{BlockOutbound, DirectOutbound};
        use crate::config::OutboundType;

        let outbound: Box<dyn Outbound> = match config.outbound_type {
            OutboundType::Direct => Box::new(DirectOutbound::new(config.clone())),
            OutboundType::Block => Box::new(BlockOutbound::from_config(config)),
        };

        self.manager.add(outbound);
        self
    }

    /// Add multiple outbounds from configuration
    pub fn add_all_from_config(&mut self, configs: &[OutboundConfig]) -> &mut Self {
        for config in configs {
            self.add_from_config(config);
        }
        self
    }

    /// Build the manager
    #[must_use]
    pub fn build(self) -> OutboundManager {
        self.manager
    }
}

impl Default for OutboundManagerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::outbound::{BlockOutbound, DirectOutbound};

    #[test]
    fn test_manager_creation() {
        let manager = OutboundManager::new();
        assert!(manager.is_empty());
        assert_eq!(manager.len(), 0);
    }

    #[test]
    fn test_add_and_get() {
        let manager = OutboundManager::new();

        manager.add(Box::new(DirectOutbound::simple("direct")));
        manager.add(Box::new(BlockOutbound::new("block")));

        assert_eq!(manager.len(), 2);
        assert!(manager.contains("direct"));
        assert!(manager.contains("block"));
        assert!(!manager.contains("nonexistent"));

        let direct = manager.get("direct").unwrap();
        assert_eq!(direct.tag(), "direct");
        assert_eq!(direct.outbound_type(), "direct");
    }

    #[test]
    fn test_remove() {
        let manager = OutboundManager::new();
        manager.add(Box::new(DirectOutbound::simple("test")));

        assert!(manager.contains("test"));

        let removed = manager.remove("test");
        assert!(removed.is_some());
        assert!(!manager.contains("test"));

        let removed_again = manager.remove("test");
        assert!(removed_again.is_none());
    }

    #[test]
    fn test_tags() {
        let manager = OutboundManager::new();
        manager.add(Box::new(DirectOutbound::simple("a")));
        manager.add(Box::new(DirectOutbound::simple("b")));
        manager.add(Box::new(BlockOutbound::new("c")));

        let mut tags = manager.tags();
        tags.sort();
        assert_eq!(tags, vec!["a", "b", "c"]);
    }

    #[test]
    fn test_health_summary() {
        let manager = OutboundManager::new();
        manager.add(Box::new(DirectOutbound::simple("direct")));
        manager.add(Box::new(BlockOutbound::new("block")));

        let summary = manager.health_summary();
        assert_eq!(summary.len(), 2);
        // Block is always healthy
        assert_eq!(summary.get("block"), Some(&HealthStatus::Healthy));
    }

    #[test]
    fn test_builder() {
        let config = OutboundConfig::direct("built");
        let mut builder = OutboundManagerBuilder::new();
        builder.add_from_config(&config);

        let manager = builder.build();
        assert!(manager.contains("built"));
    }

    #[test]
    fn test_builder_multiple() {
        let configs = vec![
            OutboundConfig::direct("direct"),
            OutboundConfig::block("block"),
        ];

        let mut builder = OutboundManagerBuilder::new();
        builder.add_all_from_config(&configs);
        let manager = builder.build();

        assert_eq!(manager.len(), 2);
        assert!(manager.contains("direct"));
        assert!(manager.contains("block"));
    }
}
