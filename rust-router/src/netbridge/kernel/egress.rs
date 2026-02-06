//! KernelEgress placeholder for the kernel backend
//!
//! This module provides a placeholder for the kernel egress bridge. The kernel
//! backend uses the kernel TCP/IP stack for egress, so this is primarily a
//! statistics collector rather than an active component.
//!
//! # Architecture
//!
//! In the kernel backend, egress is handled by:
//!
//! 1. TPROXY listener accepts TCP/UDP connections
//! 2. Outbound module connects to the destination
//! 3. Kernel manages the TCP/UDP session
//! 4. Reply packets flow back through the TUN device
//!
//! The actual "egress" work is done by the outbound module, not a separate
//! egress bridge. This type exists for statistics collection and future expansion.
//!
//! # Note
//!
//! This type does NOT implement `NetBridgeEgress` because that trait is designed
//! for smoltcp-based egress with methods like `handle_tcp`, `feed_reply`, etc.
//! The kernel backend doesn't use smoltcp for egress.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use tracing::info;

use crate::netbridge::types::EgressStats;

// =============================================================================
// KernelEgress Configuration
// =============================================================================

/// Configuration for the kernel egress bridge
#[derive(Debug, Clone)]
pub struct KernelEgressConfig {
    /// Enable statistics collection
    pub enable_stats: bool,
}

impl Default for KernelEgressConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl KernelEgressConfig {
    /// Create a new configuration
    #[must_use]
    pub const fn new() -> Self {
        Self { enable_stats: true }
    }

    /// Enable or disable statistics
    #[must_use]
    pub const fn enable_stats(mut self, enable: bool) -> Self {
        self.enable_stats = enable;
        self
    }
}

// =============================================================================
// KernelEgress Implementation
// =============================================================================

/// Kernel-based egress bridge (placeholder)
///
/// In the kernel backend, egress traffic is handled by the kernel TCP/IP
/// stack via TPROXY connections. This type exists as a placeholder for
/// the trait system and for collecting statistics.
///
/// # Usage
///
/// The kernel egress does not need to be explicitly started. It is
/// implicitly active when:
///
/// 1. The TPROXY listener is accepting connections
/// 2. The outbound module is processing those connections
/// 3. Reply packets flow back through the TUN device
///
/// # Statistics
///
/// The egress bridge can track:
/// - TCP session count
/// - UDP session count
/// - Bytes sent/received
/// - Reply packets generated
/// - Errors encountered
pub struct KernelEgress {
    /// Configuration
    config: KernelEgressConfig,
    /// Whether statistics are being collected
    stats_enabled: AtomicBool,
    /// Statistics
    stats: KernelEgressStats,
}

impl KernelEgress {
    /// Create a new kernel egress bridge
    #[must_use]
    pub fn new(config: KernelEgressConfig) -> Self {
        info!("Creating kernel egress bridge (placeholder)");

        Self {
            stats_enabled: AtomicBool::new(config.enable_stats),
            config,
            stats: KernelEgressStats::default(),
        }
    }

    /// Create with default configuration
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(KernelEgressConfig::default())
    }

    /// Record a TCP session
    #[inline]
    pub fn record_tcp_session(&self) {
        if self.stats_enabled.load(Ordering::Relaxed) {
            self.stats.tcp_sessions.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Record a UDP session
    #[inline]
    pub fn record_udp_session(&self) {
        if self.stats_enabled.load(Ordering::Relaxed) {
            self.stats.udp_sessions.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Record bytes sent to outbound
    #[inline]
    pub fn record_bytes_sent(&self, bytes: u64) {
        if self.stats_enabled.load(Ordering::Relaxed) {
            self.stats.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
        }
    }

    /// Record bytes received from outbound
    #[inline]
    pub fn record_bytes_received(&self, bytes: u64) {
        if self.stats_enabled.load(Ordering::Relaxed) {
            self.stats.bytes_received.fetch_add(bytes, Ordering::Relaxed);
        }
    }

    /// Record a reply packet generated
    #[inline]
    pub fn record_reply_packet(&self) {
        if self.stats_enabled.load(Ordering::Relaxed) {
            self.stats.reply_packets.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Record an error
    #[inline]
    pub fn record_error(&self) {
        if self.stats_enabled.load(Ordering::Relaxed) {
            self.stats.errors.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Check if statistics are enabled
    #[inline]
    #[must_use]
    pub fn stats_enabled(&self) -> bool {
        self.stats_enabled.load(Ordering::Relaxed)
    }

    /// Enable statistics collection
    pub fn enable_stats(&self) {
        self.stats_enabled.store(true, Ordering::Relaxed);
    }

    /// Disable statistics collection
    pub fn disable_stats(&self) {
        self.stats_enabled.store(false, Ordering::Relaxed);
    }
}

impl KernelEgress {
    /// Get egress statistics
    #[must_use]
    pub fn stats(&self) -> EgressStats {
        EgressStats {
            tcp_sessions: self.stats.tcp_sessions.load(Ordering::Relaxed),
            udp_sessions: self.stats.udp_sessions.load(Ordering::Relaxed),
            bytes_sent: self.stats.bytes_sent.load(Ordering::Relaxed),
            bytes_received: self.stats.bytes_received.load(Ordering::Relaxed),
            reply_packets: self.stats.reply_packets.load(Ordering::Relaxed),
            errors: self.stats.errors.load(Ordering::Relaxed),
        }
    }

    /// Check if the egress bridge is running
    ///
    /// For the kernel backend, always returns true since egress is
    /// implicitly running via the kernel TCP/IP stack.
    #[must_use]
    pub fn is_running(&self) -> bool {
        true
    }
}

impl std::fmt::Debug for KernelEgress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KernelEgress")
            .field("config", &self.config)
            .field("stats_enabled", &self.stats_enabled.load(Ordering::Relaxed))
            .finish()
    }
}

// =============================================================================
// Statistics
// =============================================================================

/// Internal statistics counters
#[derive(Debug, Default)]
struct KernelEgressStats {
    /// Total TCP sessions handled
    tcp_sessions: AtomicU64,
    /// Total UDP sessions handled
    udp_sessions: AtomicU64,
    /// Total bytes sent to outbound
    bytes_sent: AtomicU64,
    /// Total bytes received from outbound
    bytes_received: AtomicU64,
    /// Reply packets generated
    reply_packets: AtomicU64,
    /// Errors encountered
    errors: AtomicU64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = KernelEgressConfig::default();
        assert!(config.enable_stats);
    }

    #[test]
    fn test_config_builder() {
        let config = KernelEgressConfig::new().enable_stats(false);
        assert!(!config.enable_stats);
    }

    #[test]
    fn test_egress_creation() {
        let egress = KernelEgress::with_defaults();
        assert!(egress.stats_enabled());
        assert!(egress.is_running());
    }

    #[test]
    fn test_stats_recording() {
        let egress = KernelEgress::with_defaults();

        egress.record_tcp_session();
        egress.record_tcp_session();
        egress.record_udp_session();
        egress.record_bytes_sent(1000);
        egress.record_bytes_received(2000);
        egress.record_reply_packet();
        egress.record_error();

        let stats = egress.stats();
        assert_eq!(stats.tcp_sessions, 2);
        assert_eq!(stats.udp_sessions, 1);
        assert_eq!(stats.bytes_sent, 1000);
        assert_eq!(stats.bytes_received, 2000);
        assert_eq!(stats.reply_packets, 1);
        assert_eq!(stats.errors, 1);
    }

    #[test]
    fn test_stats_disabled() {
        let config = KernelEgressConfig::new().enable_stats(false);
        let egress = KernelEgress::new(config);

        egress.record_tcp_session();
        egress.record_bytes_sent(1000);

        let stats = egress.stats();
        assert_eq!(stats.tcp_sessions, 0);
        assert_eq!(stats.bytes_sent, 0);
    }

    #[test]
    fn test_stats_toggle() {
        let egress = KernelEgress::with_defaults();

        egress.record_tcp_session();
        assert_eq!(egress.stats().tcp_sessions, 1);

        egress.disable_stats();
        egress.record_tcp_session();
        assert_eq!(egress.stats().tcp_sessions, 1); // No change

        egress.enable_stats();
        egress.record_tcp_session();
        assert_eq!(egress.stats().tcp_sessions, 2);
    }

}
