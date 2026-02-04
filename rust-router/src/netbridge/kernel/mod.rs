//! Kernel backend for the netbridge module
//!
//! This module provides the kernel-based (TUN + TPROXY) implementation of the
//! netbridge traits. It achieves 200-400 Mbps throughput by leveraging the
//! Linux kernel's optimized TCP/IP stack.
//!
//! # Architecture
//!
//! The kernel backend uses a combination of:
//!
//! - **TUN device**: Receives decrypted IP packets from WireGuard
//! - **TPROXY**: Transparently intercepts TCP/UDP connections
//! - **iptables**: Configures packet routing and TPROXY redirection
//! - **Kernel TCP/IP**: Handles congestion control (BBR/CUBIC), retransmission, etc.
//!
//! # Data Flow
//!
//! ```text
//! Ingress (WireGuard -> Outbound):
//!   WireGuard UDP -> boringtun decrypt -> TUN write -> Kernel TCP/IP -> TPROXY accept
//!
//! Egress (Outbound -> WireGuard):
//!   Outbound reply -> Kernel TCP/IP -> TUN read -> Session lookup -> WireGuard encrypt
//! ```
//!
//! # Performance
//!
//! | Metric | Value |
//! |--------|-------|
//! | Single connection | 200-400 Mbps |
//! | Multiple connections | 400-800 Mbps |
//! | Congestion control | BBR, CUBIC (kernel-managed) |
//! | Memory | Kernel-managed (no tuning needed) |
//!
//! # Requirements
//!
//! - Linux kernel with TUN and TPROXY support
//! - CAP_NET_ADMIN capability
//! - CAP_NET_RAW capability
//! - Privileged container mode (for Docker)
//!
//! # Example
//!
//! ```ignore
//! use rust_router::netbridge::kernel::{KernelIngress, KernelIngressConfig};
//! use rust_router::netbridge::traits::NetBridgeIngress;
//!
//! // Create the ingress bridge
//! let config = KernelIngressConfig::new("tun-in", "10.25.0.1/24", "10.25.0.0/24");
//! let mut ingress = KernelIngress::new(config)?;
//!
//! // Take the reply receiver (for WireGuard)
//! let reply_rx = ingress.take_reply_rx().unwrap();
//!
//! // Run the bridge
//! ingress.run().await?;
//! ```

// =============================================================================
// Sub-modules
// =============================================================================

mod egress;
mod ingress;
pub mod iptables_core;
mod iptables;
mod tproxy;
mod tun;

// =============================================================================
// Public Exports
// =============================================================================

// TUN device wrapper
pub use tun::{TunDeviceBuilder, TunDeviceWrapper};

// TPROXY listener wrapper
pub use tproxy::{TproxyConnectionWrapper, TproxyListenerConfig, TproxyListenerStats, TproxyListenerWrapper};

// Core iptables manager (canonical location)
pub use iptables_core::IptablesManager;

// iptables manager wrapper (with crash recovery)
pub use iptables::{IptablesConfig, IptablesManagerWrapper, IptablesState};

// KernelIngress implementation
pub use ingress::{KernelIngress, KernelIngressConfig, KernelIngressStats, KernelIngressStatsSnapshot};

// KernelEgress placeholder
pub use egress::{KernelEgress, KernelEgressConfig};

// =============================================================================
// Convenience Re-exports
// =============================================================================

/// Default TPROXY port
pub const DEFAULT_TPROXY_PORT: u16 = 7893;

/// Default fwmark for policy routing
pub const DEFAULT_FWMARK: u32 = 0x1;

/// Default routing table ID
pub const DEFAULT_TABLE_ID: u32 = 100;

/// Create a kernel ingress bridge with default settings
///
/// Uses:
/// - TUN device: tun-in with 10.25.0.1/24
/// - TPROXY: 127.0.0.1:7893
/// - fwmark: 0x1
/// - table: 100
///
/// # Errors
///
/// Returns an error if bridge creation fails (permissions, etc.).
pub fn create_default_ingress() -> crate::netbridge::error::Result<KernelIngress> {
    KernelIngress::with_defaults()
}

/// Create a kernel egress bridge with default settings
///
/// The kernel egress is a placeholder since egress is handled by
/// the kernel TCP/IP stack via TPROXY connections.
#[must_use]
pub fn create_default_egress() -> KernelEgress {
    KernelEgress::with_defaults()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(DEFAULT_TPROXY_PORT, 7893);
        assert_eq!(DEFAULT_FWMARK, 0x1);
        assert_eq!(DEFAULT_TABLE_ID, 100);
    }

    #[test]
    fn test_default_egress() {
        let egress = create_default_egress();
        assert!(egress.is_running());
    }
}
