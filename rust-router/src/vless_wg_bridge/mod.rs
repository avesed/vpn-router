//! VLESS to WireGuard Bridge Module
//!
//! This module provides the infrastructure for bridging VLESS inbound TCP/UDP
//! connections to WireGuard outbound tunnels using smoltcp as the userspace
//! TCP/IP stack.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────────┐
//! │                           VlessWgBridge                                      │
//! ├─────────────────────────────────────────────────────────────────────────────┤
//! │                                                                              │
//! │  ┌─────────────┐    ┌──────────────────┐    ┌─────────────────────────┐    │
//! │  │ VLESS       │    │ SessionTracker   │    │ SmoltcpBridge           │    │
//! │  │ Connection  │◄──►│                  │◄──►│ (TCP + UDP sockets)     │    │
//! │  │             │    │ - TCP sessions   │    │                         │    │
//! │  │ - conn_id   │    │ - UDP sessions   │    │ - MAX_SOCKETS = 1024    │    │
//! │  │ - stream    │    │ - port allocator │    │ - MSS = 1380            │    │
//! │  │ - command   │    │ - RAII guards    │    │ - feed_rx_packet()      │    │
//! │  └─────────────┘    └──────────────────┘    │ - drain_tx_packets()    │    │
//! │         │                    │              └─────────────────────────┘    │
//! │         │                    │                           │                  │
//! │         │                    ▼                           │                  │
//! │         │           ┌──────────────────┐                 │                  │
//! │         │           │ PacketRouter     │◄────────────────┘                  │
//! │         │           │                  │                                    │
//! │         └──────────►│ - Forward: VLESS→WG │                                │
//! │                     │ - Reverse: WG→VLESS │                                │
//! │                     └──────────────────┘                                    │
//! └─────────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Core Challenge
//!
//! The bridge solves the protocol layer mismatch between VLESS (Layer 4 TCP streams)
//! and WireGuard (Layer 3 IP packets). When a VLESS client sends TCP data, we must:
//!
//! 1. Create a corresponding TCP socket in the smoltcp userspace stack
//! 2. Forward the TCP data through smoltcp to generate IP packets
//! 3. Send those IP packets through the WireGuard tunnel
//! 4. Route reply packets back through smoltcp to the original VLESS connection
//!
//! # Key Components
//!
//! - [`crate::netbridge::config`]: Configuration constants (socket limits, timeouts, buffer sizes)
//! - [`crate::netbridge::error`]: Error types for bridge operations (`NetBridgeError`)
//! - [`crate::netbridge::port`]: Ephemeral port allocation with TIME_WAIT tracking
//! - [`session`]: VLESS-specific session tracking with forward and reverse indices
//!
//! # Usage
//!
//! ```ignore
//! use rust_router::vless_wg_bridge::{
//!     PortAllocator, SessionTracker, VlessConnectionId,
//!     BridgeError,
//! };
//!
//! // Create port allocator
//! let allocator = PortAllocator::new();
//!
//! // Allocate a port with RAII guard
//! let port_guard = allocator.allocate().ok_or(BridgeError::PortExhausted)?;
//! let port = port_guard.port();
//!
//! // Create session tracker
//! let tracker = SessionTracker::new(allocator);
//!
//! // Create connection ID
//! let conn_id = VlessConnectionId::new(client_addr);
//! ```
//!
//! # Implementation Notes
//!
//! This module shares common infrastructure with other smoltcp bridges via
//! `crate::netbridge`. VLESS-specific components (session tracking, UDP framing,
//! reply registry) are defined here.

pub mod cleanup;
pub mod event_channel;
pub mod events;
pub mod reply_registry;
pub mod session;
pub mod shard;
pub mod sharded_bridge;
pub mod sharded_reply_registry;
pub mod tcp_session;
pub mod udp_frame;
pub mod udp_session;

// Re-export from netbridge for API compatibility
pub use crate::netbridge::{
    // Error types
    NetBridgeError as BridgeError,
    Result,
    // Port allocator
    PortAllocator,
    PortAllocatorConfig,
    PortGuard,
    // Socket guards
    TcpSocketGuard,
    UdpSocketGuard,
    // Connection ID types
    ConnId,
    ConnIdAllocator,
    // Config constants
    MAX_SESSIONS_PER_PEER as MAX_SESSIONS_PER_CLIENT,
    MAX_SOCKETS,
    MAX_TOTAL_SESSIONS,
    PORT_RANGE_END,
    PORT_RANGE_START,
    PORT_TIME_WAIT_SECS,
    TCP_IDLE_TIMEOUT_SECS,
    TCP_MSS,
    TCP_RX_BUFFER,
    TCP_TX_BUFFER,
    UDP_DEFAULT_TIMEOUT_SECS,
    UDP_DNS_TIMEOUT_SECS,
    UDP_RX_BUFFER,
    UDP_TX_BUFFER,
    WG_MTU,
    REPLY_CHANNEL_SIZE as WG_REPLY_CHANNEL_SIZE,
};

// VLESS-specific session types
pub use session::{
    SessionKey, SessionStats, SessionTracker, TcpSession, TimeoutConfig, UdpSession,
    VlessConnectionId,
};

pub use udp_frame::{UdpFrameAddress, VlessUdpCodec, VlessUdpFrame};

// Compatibility re-exports for code that uses these types from vless_wg_bridge
// RawUdpReply is provided by sharded_bridge (the modern implementation)
#[cfg(any(feature = "use-netbridge-egress", feature = "sharded-vless-wg-bridge"))]
pub use sharded_bridge::RawUdpReply;

// WgReplyPacket is now defined in reply_registry (always available)
pub use reply_registry::{RegistryStatsSnapshot, VlessReplyKey, VlessReplyRegistry, WgReplyPacket};

// Event Bus types for the new architecture
pub use events::{BridgeEvent, EventPriority, TcpReply, UdpReply, UdpSessionKey};

// Event Channel for shard communication
pub use event_channel::{
    create_event_channel, EventChannelConfig, EventChannelStats, EventReceiver, EventSender,
    TrySendError, HIGH_PRIORITY_CHANNEL_SIZE, NORMAL_PRIORITY_CHANNEL_SIZE,
};

// TCP Session State Machine for Event Bus architecture
pub use tcp_session::{TcpSession as ShardTcpSession, TcpSessionState};

// UDP Session for Event Bus architecture
pub use udp_session::{
    ShardUdpSession, UdpSessionStats, ACTIVITY_UPDATE_INTERVAL, ACTIVITY_UPDATE_TIME_SECS,
    UDP_DEFAULT_TIMEOUT, UDP_DNS_TIMEOUT,
};

// SmoltcpShard for Event Bus architecture (Task 2.1)
pub use shard::{
    ShardConfig, ShardStats, SmoltcpShard, DEFAULT_POLL_INTERVAL, MAX_POLL_INTERVAL,
    MIN_POLL_INTERVAL, SHARD_MAX_SOCKETS, WG_BATCH_SIZE, WG_BATCH_TIMEOUT_US,
};

// Cleanup configuration and statistics (Task 2.5)
pub use cleanup::{
    CleanupConfig, CleanupStats, CLEANUP_INTERVAL_SECS, TCP_IDLE_TIMEOUT_SECS as CLEANUP_TCP_TIMEOUT_SECS,
    UDP_DEFAULT_TIMEOUT_SECS as CLEANUP_UDP_DEFAULT_TIMEOUT_SECS,
    UDP_DNS_TIMEOUT_SECS as CLEANUP_UDP_DNS_TIMEOUT_SECS,
};

// ShardedVlessWgBridge routing layer (Task 3.1) + Public API (Task 3.2)
pub use sharded_bridge::{
    AggregatedStats, AggregatedStatsSnapshot, ShardConfigTemplate, ShardKey, ShardStatsCollector,
    ShardStatsSnapshot, ShardedBridgeConfig, ShardedVlessWgBridge, TcpConnectionStats,
    TcpSessionKey, UdpConnectionStats, DEFAULT_SHARD_COUNT, MAX_SHARD_COUNT, MIN_SHARD_COUNT,
};
// Re-export RawUdpReply from sharded_bridge with an alias to avoid conflict
pub use sharded_bridge::RawUdpReply as ShardedRawUdpReply;

// Sharded bridge reply registry for WgReplyHandler integration
pub use sharded_reply_registry::{ShardedBridgeReplyRegistry, ShardedRegistryStatsSnapshot};
