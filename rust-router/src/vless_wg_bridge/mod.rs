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
//! - [`crate::smoltcp_utils::config`]: Configuration constants (socket limits, timeouts, buffer sizes)
//! - [`crate::smoltcp_utils::error`]: Error types for bridge operations
//! - [`crate::smoltcp_utils::port_allocator`]: Ephemeral port allocation with TIME_WAIT tracking
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
//! `crate::smoltcp_utils`. VLESS-specific components (session tracking, UDP framing,
//! reply registry) are defined here.

pub mod bridge;
pub mod reply_registry;
pub mod session;
pub mod udp_frame;

// Re-export from smoltcp_utils for API compatibility
pub use crate::smoltcp_utils::{
    // Config constants
    MAX_SESSIONS_PER_CLIENT, MAX_SOCKETS, MAX_TOTAL_SESSIONS, PORT_RANGE_END, PORT_RANGE_START,
    PORT_TIME_WAIT_SECS, TCP_IDLE_TIMEOUT_SECS, TCP_MSS, TCP_RX_BUFFER, TCP_TX_BUFFER,
    UDP_DEFAULT_TIMEOUT_SECS, UDP_DNS_TIMEOUT_SECS, UDP_PACKET_META, UDP_RX_BUFFER, UDP_TX_BUFFER,
    WG_MTU, WG_REPLY_CHANNEL_SIZE,
    // Error types
    BridgeError, Result,
    // Port allocator
    PortAllocator, PortAllocatorConfig, PortGuard,
    // Socket guards
    TcpSocketGuard, UdpSocketGuard,
};

// VLESS-specific session types
pub use session::{
    SessionKey, SessionStats, SessionTracker, TcpSession, TimeoutConfig, UdpSession,
    VlessConnectionId,
};

pub use udp_frame::{UdpFrameAddress, VlessUdpCodec, VlessUdpFrame};

pub use bridge::{
    BridgeStats, BridgeStatsSnapshot, RawUdpReply, RawUdpSessionKey, VlessUdpMode, VlessWgBridge,
    WgReplyPacket,
};

pub use reply_registry::{RegistryStatsSnapshot, VlessReplyKey, VlessReplyRegistry};
