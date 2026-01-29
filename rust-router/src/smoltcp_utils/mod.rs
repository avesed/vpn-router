//! Shared smoltcp utilities for bridge modules
//!
//! This module provides reusable components for building bridges between
//! TCP/UDP streams and IP packet-based tunnels (like WireGuard) using
//! smoltcp as the userspace TCP/IP stack.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────────┐
//! │                         smoltcp_utils Components                            │
//! ├─────────────────────────────────────────────────────────────────────────────┤
//! │                                                                              │
//! │  ┌─────────────────┐    ┌──────────────────┐    ┌─────────────────────┐    │
//! │  │   config        │    │  port_allocator  │    │   socket_guard      │    │
//! │  │                 │    │                  │    │                     │    │
//! │  │ - Buffer sizes  │    │ - PortAllocator  │    │ - TcpSocketGuard    │    │
//! │  │ - Timeouts      │    │ - PortGuard      │    │ - UdpSocketGuard    │    │
//! │  │ - Limits        │    │ - TIME_WAIT      │    │ - RAII cleanup      │    │
//! │  └─────────────────┘    └──────────────────┘    └─────────────────────┘    │
//! │                                                                              │
//! │  ┌─────────────────┐    ┌──────────────────┐                                │
//! │  │     error       │    │     session      │                                │
//! │  │                 │    │                  │                                │
//! │  │ - BridgeError   │    │ - SessionKey     │                                │
//! │  │ - Result type   │    │ - SessionStats   │                                │
//! │  │ - Error helpers │    │ - SessionTracker │                                │
//! │  └─────────────────┘    └──────────────────┘                                │
//! │                                                                              │
//! └─────────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Usage
//!
//! These utilities are designed to be used by bridge implementations that
//! need to convert between Layer 4 streams (TCP/UDP) and Layer 3 IP packets.
//!
//! ## Example: Creating a Port Allocator
//!
//! ```ignore
//! use rust_router::smoltcp_utils::{PortAllocator, PortAllocatorConfig};
//!
//! // Create allocator with default IANA ephemeral port range
//! let allocator = PortAllocator::new();
//!
//! // Allocate a port - returns a RAII guard
//! if let Some(guard) = allocator.allocate() {
//!     let port = guard.port();
//!     println!("Allocated port: {}", port);
//!     // Port is automatically released when guard drops
//! }
//! ```
//!
//! ## Example: Using Socket Guards
//!
//! ```ignore
//! use std::sync::Arc;
//! use tokio::sync::Mutex;
//! use rust_router::smoltcp_utils::TcpSocketGuard;
//! use rust_router::tunnel::smoltcp_bridge::SmoltcpBridge;
//!
//! async fn handle_connection(bridge: Arc<Mutex<SmoltcpBridge>>) {
//!     let handle = {
//!         let mut b = bridge.lock().await;
//!         b.create_tcp_socket_default().unwrap()
//!     };
//!
//!     // Socket is automatically cleaned up when guard drops
//!     let guard = TcpSocketGuard::new(bridge.clone(), handle);
//!
//!     // Even on early return, socket is cleaned up
//!     if some_error_condition {
//!         return; // guard drops, socket cleaned up
//!     }
//!
//!     // For graceful close, use the async method
//!     guard.close_gracefully().await;
//! }
//! ```
//!
//! # Thread Safety
//!
//! - `PortAllocator` is thread-safe and can be shared across tasks
//! - `SessionTracker` uses `DashMap` for lock-free concurrent access
//! - Socket guards hold `Arc<Mutex<SmoltcpBridge>>` and are `Send + Sync`
//!
//! # Components
//!
//! - [`config`]: Configuration constants (buffer sizes, timeouts, limits)
//! - [`error`]: Error types with transient/permanent classification
//! - [`port_allocator`]: Ephemeral port allocation with TIME_WAIT tracking
//! - [`socket_guard`]: RAII guards for TCP/UDP socket cleanup
//! - [`session`]: Session tracking with bidirectional indices

pub mod config;
pub mod error;
pub mod port_allocator;
pub mod session;
pub mod socket_guard;

// Re-export commonly used types
pub use config::{
    ephemeral_port_count, ephemeral_port_range, port_time_wait_duration, tcp_idle_timeout,
    udp_default_timeout, udp_dns_timeout, MAX_SESSIONS_PER_CLIENT, MAX_SESSIONS_PER_CLIENT_PER_SECOND,
    MAX_SOCKETS, MAX_TOTAL_SESSIONS, PORT_RANGE_END, PORT_RANGE_START, PORT_TIME_WAIT_SECS,
    RATE_LIMIT_WINDOW_SECS, TCP_IDLE_TIMEOUT_SECS, TCP_MSS, TCP_RX_BUFFER, TCP_TX_BUFFER,
    UDP_DEFAULT_TIMEOUT_SECS, UDP_DNS_TIMEOUT_SECS, UDP_PACKET_META, UDP_RX_BUFFER, UDP_TX_BUFFER,
    WG_MTU, WG_REPLY_CHANNEL_SIZE,
};

pub use error::{BridgeError, Result};

pub use port_allocator::{PortAllocator, PortAllocatorConfig, PortGuard};

pub use session::{
    ConnectionId, SessionKey, SessionStats, SessionTracker, TcpSession, TimeoutConfig, UdpSession,
};

pub use socket_guard::{
    init_cleanup_channel, run_cleanup_task, SocketCleanupReceiver, TcpSocketGuard, UdpSocketGuard,
};
