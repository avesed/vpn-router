//! TUN + TPROXY Bridge Module (Legacy Compatibility)
//!
//! This module provides backward-compatible re-exports from `netbridge` for code
//! that still uses `tun_bridge` types. The actual implementation has been moved
//! to `netbridge::kernel`.
//!
//! # Migration
//!
//! New code should use `netbridge` directly:
//! - `netbridge::KernelIngress` instead of `TunIngressBridge`
//! - `netbridge::FiveTuple` instead of local `FiveTuple`
//! - `netbridge::SessionTracker` instead of local `SessionTracker`
//!
//! # Note
//!
//! The original TunIngressBridge implementation has been removed in favor of
//! netbridge::KernelIngress. This module now only provides:
//! - Constants for backward compatibility
//! - Re-exports from netbridge for gradual migration
//! - IptablesManager re-export (for backward compatibility)

mod iptables;

// Re-export iptables manager for backward compatibility
pub use iptables::IptablesManager;

/// Default TPROXY listener port
pub const DEFAULT_TPROXY_PORT: u16 = 7893;

/// Default fwmark for TPROXY routing
pub const DEFAULT_FWMARK: u32 = 0x1;

/// Default routing table ID for TPROXY
pub const DEFAULT_ROUTE_TABLE_ID: u32 = 100;

/// Default TUN device name
pub const DEFAULT_TUN_NAME: &str = "tun-in";

/// Default TUN device CIDR (same as WireGuard ingress subnet)
pub const DEFAULT_TUN_CIDR: &str = "10.25.0.1/24";

/// Default TUN MTU (WireGuard standard)
pub const DEFAULT_TUN_MTU: u16 = 1420;

/// TCP session timeout in seconds
pub const TCP_SESSION_TIMEOUT_SECS: u64 = 300; // 5 minutes

/// UDP session timeout in seconds
pub const UDP_SESSION_TIMEOUT_SECS: u64 = 30;

/// DNS query session timeout in seconds
pub const DNS_SESSION_TIMEOUT_SECS: u64 = 10;

/// Session cleanup interval in seconds
pub const SESSION_CLEANUP_INTERVAL_SECS: u64 = 30;

/// Maximum sessions per peer (rate limiting)
pub const MAX_SESSIONS_PER_PEER: usize = 1000;

/// Maximum total sessions (resource limit)
pub const MAX_TOTAL_SESSIONS: usize = 10000;

/// Reply channel capacity
pub const REPLY_CHANNEL_SIZE: usize = 4096;

/// SNI peek buffer size
pub const SNI_PEEK_BUFFER_SIZE: usize = 4096;

/// SNI peek timeout in milliseconds
pub const SNI_PEEK_TIMEOUT_MS: u64 = 50;

/// TCP connect timeout in seconds
pub const TCP_CONNECT_TIMEOUT_SECS: u64 = 10;

// =============================================================================
// Migration Compatibility Re-exports from netbridge
// =============================================================================
//
// These re-exports allow code to migrate from tun_bridge to netbridge gradually.
// During migration, both modules coexist and code can use either path.
//
// Legacy path: use crate::tun_bridge::{FiveTuple, SessionTracker, ...}
// New path:    use crate::netbridge::{FiveTuple, SessionTracker, ...}
//
// Eventually, these re-exports will be deprecated in favor of direct netbridge imports.

/// Re-export netbridge FiveTuple as NetFiveTuple for disambiguation
pub use crate::netbridge::FiveTuple as NetFiveTuple;

/// Re-export netbridge SessionTracker as NetSessionTracker for disambiguation
pub use crate::netbridge::SessionTracker as NetSessionTracker;

/// Re-export netbridge IpProtocol
pub use crate::netbridge::IpProtocol;

/// Re-export netbridge KernelIngress and related types
pub use crate::netbridge::{
    KernelIngress, KernelIngressConfig, KernelIngressStats, KernelIngressStatsSnapshot,
};

/// Re-export netbridge types for reply routing
pub use crate::netbridge::{ReplyPacket, ReplyRouter};

/// Re-export netbridge session types
pub use crate::netbridge::Session as NetSession;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ingress_constants() {
        assert_eq!(DEFAULT_TPROXY_PORT, 7893);
        assert_eq!(DEFAULT_FWMARK, 0x1);
        assert_eq!(DEFAULT_ROUTE_TABLE_ID, 100);
        assert_eq!(DEFAULT_TUN_NAME, "tun-in");
        assert_eq!(DEFAULT_TUN_CIDR, "10.25.0.1/24");
        assert_eq!(DEFAULT_TUN_MTU, 1420);
        assert_eq!(TCP_SESSION_TIMEOUT_SECS, 300);
        assert_eq!(UDP_SESSION_TIMEOUT_SECS, 30);
        assert_eq!(DNS_SESSION_TIMEOUT_SECS, 10);
        assert_eq!(SESSION_CLEANUP_INTERVAL_SECS, 30);
        assert_eq!(MAX_SESSIONS_PER_PEER, 1000);
        assert_eq!(MAX_TOTAL_SESSIONS, 10000);
        assert_eq!(REPLY_CHANNEL_SIZE, 4096);
        assert_eq!(SNI_PEEK_BUFFER_SIZE, 4096);
        assert_eq!(SNI_PEEK_TIMEOUT_MS, 50);
        assert_eq!(TCP_CONNECT_TIMEOUT_SECS, 10);
    }

}
