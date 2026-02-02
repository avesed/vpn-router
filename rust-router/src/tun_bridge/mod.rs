//! TUN + TPROXY Bridge Module
//!
//! This module provides high-performance bridges for routing traffic between
//! WireGuard, VLESS/Shadowsocks, and outbound connections using TUN devices.
//!
//! # Module Overview
//!
//! ## Ingress Bridge (`ingress.rs`)
//!
//! Routes WireGuard ingress traffic through the kernel's TCP/IP stack using
//! TUN device + TPROXY. Used for: WG -> Direct/SOCKS5/VLESS outbound.
//!
//! ## Egress Bridge (`egress.rs`)
//!
//! Routes VLESS/Shadowsocks inbound TCP/UDP streams through WireGuard tunnels
//! using kernel sockets bound to a TUN device. Used for: VLESS/SS -> WG outbound.
//!
//! # Ingress Architecture
//!
//! ```text
//! WireGuard (boringtun)          Linux Kernel                    Outbound
//!       │                            │                              │
//!       ▼                            ▼                              ▼
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                         TunIngressBridge                                │
//! │                                                                         │
//! │  ┌─────────────────────────┐   ┌──────────────────────────────────┐   │
//! │  │   inject_packet()       │   │        TproxyListener             │   │
//! │  │   ────────────────►     │   │   ◄───────────────────────        │   │
//! │  │   WG decrypted packet   │   │   Intercepted TCP/UDP             │   │
//! │  │                         │   │   with original destination       │   │
//! │  └───────────┬─────────────┘   └──────────────┬───────────────────┘   │
//! │              │                                │                        │
//! │              ▼                                ▼                        │
//! │  ┌─────────────────────────┐   ┌──────────────────────────────────┐   │
//! │  │     TUN Device          │   │     run_accept_loop()             │   │
//! │  │   (write IP packets)    │   │   - DNS hijack (FakeDNS)         │   │
//! │  │         │               │   │   - Domain resolution            │   │
//! │  │         ▼               │   │   - Rule matching                │   │
//! │  │   Kernel routes to      │   │   - Outbound connect             │   │
//! │  │   TPROXY listener       │   │   - Bidirectional copy           │   │
//! │  └─────────────────────────┘   └──────────────────────────────────┘   │
//! │                                                                        │
//! │  ┌─────────────────────────┐   ┌──────────────────────────────────┐   │
//! │  │   run_tun_read_loop()   │   │        SessionTracker             │   │
//! │  │   ────────────────►     │   │   - 5-tuple → peer_key mapping   │   │
//! │  │   Reply packets from    │   │   - Thread-safe (DashMap)        │   │
//! │  │   kernel → WG peer      │   │   - Session timeout cleanup      │   │
//! │  └─────────────────────────┘   └──────────────────────────────────┘   │
//! │                                                                        │
//! │  ┌─────────────────────────────────────────────────────────────────┐  │
//! │  │                     IptablesManager                              │  │
//! │  │   - TPROXY mangle rules (TCP/UDP)                               │  │
//! │  │   - Policy routing (fwmark → table)                             │  │
//! │  │   - Local route for TPROXY                                      │  │
//! │  │   - sysctl settings (ip_forward, route_localnet, rp_filter)     │  │
//! │  └─────────────────────────────────────────────────────────────────┘  │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Egress Architecture
//!
//! ```text
//! VLESS/SS Inbound                  Kernel Space                    WireGuard Egress
//! ┌─────────────────┐              ┌─────────────────┐              ┌─────────────────┐
//! │ TCP/UDP Stream  │───────────▶  │ Socket (bound   │──────────▶  │ TUN Device      │
//! │ from VLESS/SS   │              │ to tun-out)     │              │ (tun-out)       │
//! └─────────────────┘              └─────────────────┘              └────────┬────────┘
//!                                                                            │
//!                                                                            │ IP packets
//!                                                                            ▼
//!                                                                   ┌─────────────────┐
//!                                                                   │ WgEgressManager │
//!                                                                   │ (send to tunnel)│
//!                                                                   └─────────────────┘
//! ```
//!
//! # Advantages over ipstack
//!
//! | Aspect | ipstack (userspace) | TUN + TPROXY (kernel) |
//! |--------|---------------------|------------------------|
//! | TCP implementation | Userspace (limited) | Kernel (full-featured) |
//! | Congestion control | Basic | CUBIC, BBR, etc. |
//! | Performance | 30-80 Mbps | 200+ Mbps |
//! | Memory usage | Higher (buffers) | Lower (kernel manages) |
//! | Connection tracking | Manual | Kernel conntrack |
//! | Path MTU discovery | Manual | Kernel handles |
//!
//! # Data Flow
//!
//! ## Ingress (client → outbound):
//! 1. WireGuard decrypts packet → `inject_packet()`
//! 2. Packet written to TUN device
//! 3. Kernel routes packet, TPROXY intercepts
//! 4. `run_accept_loop()` accepts connection
//! 5. FakeDNS/SNI resolution for domain routing
//! 6. `OutboundManager::connect()` to destination
//! 7. Bidirectional copy until connection closes
//!
//! ## Egress (outbound → client):
//! 1. Outbound sends data through kernel socket
//! 2. Kernel generates reply packets
//! 3. Packets routed to TUN device
//! 4. `run_tun_read_loop()` reads reply packets
//! 5. `SessionTracker` looks up peer_key by 5-tuple
//! 6. Reply sent to `reply_tx` for WireGuard encryption
//!
//! # Usage
//!
//! ```ignore
//! use rust_router::tun_bridge::{TunIngressBridge, TunIngressConfig};
//!
//! // Create configuration
//! let config = TunIngressConfig {
//!     tun_name: "tun-in".to_string(),
//!     tun_cidr: "10.25.0.1/24".to_string(),
//!     tun_mtu: 1420,
//!     tproxy_port: 7893,
//!     fwmark: 0x1,
//!     route_table_id: 100,
//!     fakedns: Arc::clone(&fakedns_manager),
//!     rule_engine: Arc::clone(&rule_engine),
//!     outbound_manager: Arc::clone(&outbound_manager),
//! };
//!
//! // Create bridge
//! let mut bridge = TunIngressBridge::new(config).await?;
//!
//! // Get reply receiver for WireGuard encryption
//! let reply_rx = bridge.take_reply_rx().unwrap();
//!
//! // Spawn the accept loop and TUN read loop
//! let bridge = Arc::new(bridge);
//! tokio::spawn({
//!     let bridge = Arc::clone(&bridge);
//!     async move { bridge.run_accept_loop().await }
//! });
//! tokio::spawn({
//!     let bridge = Arc::clone(&bridge);
//!     async move { bridge.run_tun_read_loop().await }
//! });
//!
//! // Inject packets from WireGuard
//! bridge.inject_packet(packet, peer_key, peer_endpoint, "direct").await?;
//! ```
//!
//! # Requirements
//!
//! - Linux kernel with TUN and TPROXY support
//! - `CAP_NET_ADMIN` capability (for TUN, iptables, routing)
//! - `CAP_NET_RAW` capability (for TPROXY)
//! - iptables installed
//!
//! # Feature Flags
//!
//! This module is always compiled. Feature-specific functionality:
//! - `fakedns`: Enables FakeDNS integration for domain-based routing
//! - `sni-sniffing`: Enables TLS SNI extraction for domain resolution

mod egress;
mod ingress;
mod iptables;
mod session;

// Re-export public types - Ingress
pub use ingress::{TunIngressBridge, TunIngressConfig, TunIngressStats, TunIngressStatsSnapshot};
pub use iptables::IptablesManager;
pub use session::{FiveTuple, SessionInfo, SessionTracker};

// Re-export public types - Egress
pub use egress::{
    EgressRoutingManager, SessionId, TcpConnectionStats, TunEgressBridge, TunEgressConfig,
    TunEgressStats, TunnelRouter, UdpConnectionStats,
};

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
// Egress Bridge Constants
// =============================================================================

/// Default egress TUN device name
pub const DEFAULT_EGRESS_TUN_NAME: &str = "tun-out";

/// Default egress TUN CIDR
pub const DEFAULT_EGRESS_TUN_CIDR: &str = "10.200.200.1/24";

/// Default routing table ID for egress TUN
pub const DEFAULT_EGRESS_ROUTE_TABLE: u32 = 201;

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

    #[test]
    fn test_egress_constants() {
        assert_eq!(DEFAULT_EGRESS_TUN_NAME, "tun-out");
        assert_eq!(DEFAULT_EGRESS_TUN_CIDR, "10.200.200.1/24");
        assert_eq!(DEFAULT_EGRESS_ROUTE_TABLE, 201);
        // Note: fwmark removed - egress uses SO_BINDTODEVICE instead
    }
}
