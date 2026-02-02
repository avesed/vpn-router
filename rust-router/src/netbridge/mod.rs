//! Unified network bridge module for IP <-> TCP/UDP conversion
//!
//! This module provides a unified abstraction for bridging between IP packets
//! (WireGuard) and TCP/UDP streams (VLESS, Shadowsocks), with two backend
//! implementations:
//!
//! - **Kernel backend** (`kernel/`): TUN + TPROXY for 200-400 Mbps performance
//! - **Smoltcp backend** (`smoltcp/`): Userspace TCP/IP for VLESS/SS -> WG bridging
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │                        INGRESS                                       │
//! ├─────────────────────────────────────────────────────────────────────┤
//! │  WireGuard (UDP)                    VLESS/SS (TCP)                  │
//! │       │                                  │                          │
//! │       ▼                                  ▼                          │
//! │  NetBridgeIngress                   NetBridgeEgress                 │
//! │  ├─ KernelIngress (TUN+TPROXY)      └─ SmoltcpEgress (userspace)    │
//! │  └─ (future: SmoltcpIngress)                                        │
//! │       │                                  │                          │
//! │       ▼                                  ▼                          │
//! │  SessionTracker ←───────────────────────────────────────────────────┤
//! │       │                                  │                          │
//! │       ▼                                  ▼                          │
//! │  ReplyRouter ────────────────────────────────────────────────────→  │
//! │                                                                     │
//! └─────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Features
//!
//! - **Zero-copy**: Uses `bytes::Bytes` for efficient packet handling
//! - **High-performance buffers**: 1 MB TCP buffers for 500+ Mbps
//! - **Session tracking**: Thread-safe with per-peer rate limiting
//! - **Port allocation**: TIME_WAIT tracking, shard support
//! - **Native async traits**: Rust 1.75+ async trait syntax
//! - **Standalone Data Plane**: Use as independent crate with callback-based routing
//!
//! # Quick Start
//!
//! ```ignore
//! use rust_router::netbridge::{
//!     SessionTracker, PortAllocator, ReplyRouter, ReplyChannelBuilder,
//!     FiveTuple, IpProtocol, config,
//! };
//!
//! // Create session tracker
//! let sessions = Arc::new(SessionTracker::new());
//!
//! // Create reply channel
//! let (reply_tx, reply_rx) = ReplyChannelBuilder::new().build();
//!
//! // Create reply router
//! let router = ReplyRouter::new(Arc::clone(&sessions), reply_tx);
//!
//! // Register a session
//! let session = sessions.register(
//!     peer_key,
//!     peer_endpoint,
//!     FiveTuple::tcp(src, dst),
//!     "direct".to_string(),
//! )?;
//! ```
//!
//! # Migration from Legacy Modules
//!
//! This module is designed to eventually replace:
//!
//! - `tun_bridge/` -> `netbridge::kernel`
//! - `vless_wg_bridge/` -> `netbridge::smoltcp`
//! - `smoltcp_utils/` -> `netbridge` (shared utilities)
//!
//! During migration, both old and new modules coexist.
//!
//! # Submodules
//!
//! - [`config`]: Configuration constants (buffer sizes, timeouts, limits)
//! - [`types`]: Core types (`IpPacket`, `FiveTuple`, `ReplyPacket`, etc.)
//! - [`error`]: Error types with transient/permanent classification
//! - [`traits`]: Core traits (`NetBridgeIngress`, `NetBridgeEgress`)
//! - [`session`]: Thread-safe session tracking
//! - [`port`]: Ephemeral port allocation with TIME_WAIT
//! - [`reply`]: Reply packet routing
//! - [`kernel`]: Kernel backend (TUN + TPROXY)
//! - [`smoltcp`]: Smoltcp backend (userspace TCP/IP)
//! - [`mod@bench`]: Benchmarking utilities
//! - [`dataplane`]: Standalone data plane API with callback-based routing
//!
//! # Standalone Data Plane
//!
//! For using netbridge as an independent data plane with control plane separation:
//!
//! ```ignore
//! use netbridge::{DataPlaneBuilder, ConnectionHandler, ConnectionInfo, RoutingDecision};
//!
//! // Implement your routing logic
//! struct MyRouter;
//!
//! impl ConnectionHandler for MyRouter {
//!     fn on_tcp_connect(&self, info: ConnectionInfo)
//!         -> Pin<Box<dyn Future<Output = RoutingDecision> + Send + '_>> {
//!         Box::pin(async move {
//!             // Your routing decision logic here
//!             let stream = TcpStream::connect(info.dst).await.unwrap();
//!             RoutingDecision::Accept(Box::new(stream))
//!         })
//!     }
//!     // ... implement other methods
//! }
//!
//! // Create and run the data plane
//! let dp = DataPlaneBuilder::new()
//!     .with_tun("my-tun")
//!     .with_handler(Arc::new(MyRouter))
//!     .build()
//!     .await?;
//!
//! dp.run().await?;
//! ```

// Submodules
pub mod bench;
pub mod config;
pub mod dataplane;
pub mod error;
pub mod kernel;
pub mod port;
pub mod reply;
pub mod session;
pub mod smoltcp;
pub mod socket_guard;
pub mod traits;
pub mod types;
pub mod vless_adapter;

// Re-export commonly used types at the module level
pub use config::{
    // Buffer sizes
    TCP_RX_BUFFER,
    TCP_TX_BUFFER,
    UDP_RX_BUFFER,
    UDP_TX_BUFFER,
    // Network parameters
    TCP_MSS,
    TUN_MTU,
    WG_MTU,
    MAX_IP_PACKET_SIZE,
    MAX_SOCKETS,
    // Port allocation
    PORT_RANGE_END,
    PORT_RANGE_START,
    // Timeouts
    CONNECT_TIMEOUT_SECS,
    PORT_TIME_WAIT_SECS,
    SNI_PEEK_TIMEOUT_MS,
    TCP_IDLE_TIMEOUT_SECS,
    UDP_DEFAULT_TIMEOUT_SECS,
    UDP_DNS_TIMEOUT_SECS,
    // Session limits
    MAX_SESSIONS_PER_PEER,
    MAX_SESSIONS_PER_PEER_PER_SECOND,
    MAX_TOTAL_SESSIONS,
    // Channel sizes
    INGRESS_CHANNEL_SIZE,
    REPLY_CHANNEL_SIZE,
    // Helper functions
    cleanup_interval,
    connect_timeout,
    ephemeral_port_count,
    ephemeral_port_range,
    estimate_memory_usage,
    port_time_wait_duration,
    sni_peek_timeout,
    tcp_idle_timeout,
    udp_default_timeout,
    udp_dns_timeout,
};

pub use error::{NetBridgeError, Result};

pub use port::{PortAllocator, PortAllocatorConfig, PortAllocatorStats, PortGuard};

pub use reply::{ReplyChannelBuilder, ReplyRouter, ReplyRouterStatsSnapshot};

pub use session::{Session, SessionError, SessionTracker, SessionTrackerConfig, SessionTrackerStats};

pub use traits::{
    CloseReason, NetBridgeEgress, NetBridgeIngress, NoOpSessionHandler, ReplyRouterExt,
    SessionCloseStats, SessionHandler, SessionInfo,
};

pub use types::{
    ConnId, ConnIdAllocator, EgressStats, FiveTuple, IngressStats, IpPacket, IpProtocol,
    ReplyPacket, SessionId, SessionIdGenerator,
};

// Socket guard types (migrated from smoltcp_utils)
pub use socket_guard::{
    init_cleanup_channel, run_cleanup_task, SocketCleanupReceiver, TcpSocketGuard, UdpSocketGuard,
};

// Kernel backend (TUN + TPROXY)
pub use kernel::{
    KernelIngress, KernelIngressConfig, KernelIngressStats, KernelIngressStatsSnapshot,
};

// Smoltcp backend (userspace TCP/IP)
pub use smoltcp::{SmoltcpEgress, SmoltcpShard};

// Benchmark utilities
pub use bench::{BenchConfig, BenchResults, TrafficPattern};

// Standalone data plane API
pub use dataplane::{
    ConnectionHandler, ConnectionInfo, DataPlane, DataPlaneBuilder, DataPlaneConfig,
    DirectHandler, OutboundStream, RejectHandler, RoutingDecision, UdpHandle, UdpHandleRemote,
};

// VLESS adapter for ShardedVlessWgBridge API compatibility
pub use vless_adapter::{
    NetbridgeVlessAdapter, TcpConnectionStats, UdpConnectionStats,
    AggregatedStats as VlessAdapterStats,
};

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;

    #[test]
    fn test_module_exports() {
        // Verify key types are accessible
        let _: FiveTuple = FiveTuple::tcp(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 80),
        );

        let _: IpProtocol = IpProtocol::Tcp;
        let _: SessionId = SessionId::new(1);

        // Verify config constants
        assert!(TCP_RX_BUFFER >= 1_000_000); // 1 MB
        assert!(UDP_RX_BUFFER >= 200_000);    // 256 KB
        assert_eq!(TCP_MSS, 1380);
        assert_eq!(WG_MTU, 1420);
    }

    #[test]
    fn test_session_tracker_integration() {
        let tracker = SessionTracker::new();
        let peer_key = [42u8; 32];
        let peer_endpoint = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 51820);

        let five_tuple = FiveTuple::tcp(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 25, 0, 2)), 12345),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 443),
        );

        let session = tracker
            .register(peer_key, peer_endpoint, five_tuple, "direct".to_string())
            .expect("should register");

        assert_eq!(session.id.as_u64(), 1);
        assert!(session.is_tcp());

        // Lookup should work
        let found = tracker.lookup(&five_tuple).expect("should find");
        assert_eq!(found.id, session.id);

        // Reverse lookup should work
        let reply_tuple = five_tuple.reverse();
        let found = tracker.lookup_by_reply(&reply_tuple).expect("should find by reply");
        assert_eq!(found.id, session.id);
    }

    #[test]
    fn test_port_allocator_integration() {
        let allocator = PortAllocator::new();

        let guard = allocator.allocate().expect("should allocate");
        let port = guard.port();

        assert!(port >= PORT_RANGE_START);
        assert!(port <= PORT_RANGE_END);
        assert!(allocator.is_allocated(port));

        drop(guard);

        assert!(!allocator.is_allocated(port));
        assert!(allocator.is_in_time_wait(port));
    }

    #[tokio::test]
    async fn test_reply_router_integration() {
        let sessions = Arc::new(SessionTracker::new());
        let (tx, mut rx) = ReplyChannelBuilder::new().capacity(100).build();
        let router = ReplyRouter::new(Arc::clone(&sessions), tx);

        // Register a session
        let peer_key = [1u8; 32];
        let peer_endpoint = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 51820);
        let five_tuple = FiveTuple::tcp(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 25, 0, 2)), 12345),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 80),
        );

        sessions
            .register(peer_key, peer_endpoint, five_tuple, "direct".to_string())
            .unwrap();

        // Create a reply packet (reversed direction)
        // IPv4 TCP packet from 93.184.216.34:80 -> 10.25.0.2:12345
        let reply_packet = vec![
            0x45, 0x00, 0x00, 0x28, // Version=4, IHL=5
            0x00, 0x00, 0x00, 0x00,
            0x40, 0x06, 0x00, 0x00, // Protocol=TCP
            0x5d, 0xb8, 0xd8, 0x22, // Src: 93.184.216.34
            0x0a, 0x19, 0x00, 0x02, // Dst: 10.25.0.2
            0x00, 0x50, 0x30, 0x39, // Port 80 -> 12345
        ];

        router.route(&reply_packet).await.unwrap();

        // Verify we received it
        let received = rx.recv().await.expect("should receive");
        assert_eq!(received.peer_key, peer_key);
        assert_eq!(received.peer_endpoint, peer_endpoint);
    }

    #[test]
    fn test_error_classification() {
        assert!(NetBridgeError::PortExhausted.is_transient());
        assert!(NetBridgeError::PortExhausted.is_resource_exhaustion());

        assert!(NetBridgeError::ConnectionRefused.is_permanent());
        assert!(NetBridgeError::ConnectionRefused.is_connection_error());

        assert!(NetBridgeError::SessionNotFound("x".to_string()).is_session_error());
    }
}
