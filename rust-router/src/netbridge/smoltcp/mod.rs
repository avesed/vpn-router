//! Smoltcp backend for netbridge (userspace TCP/IP)
//!
//! This module provides a userspace implementation of the netbridge
//! using the smoltcp TCP/IP stack for converting TCP/UDP streams to IP packets.
//!
//! # Architecture
//!
//! ```text
//! VLESS/SS TCP stream
//!         |
//!         v
//! SmoltcpEgress.handle_tcp()
//!         |
//!         v (channel)
//! SmoltcpShard (owns smoltcp)
//!         |
//!         v (IP packets)
//! WireGuard encryption
//!         |
//!         v
//! UDP to peer
//! ```
//!
//! # Key Design Decisions
//!
//! ## Single-Task Ownership
//!
//! The smoltcp `Interface` and `SocketSet` are NOT thread-safe. Instead of
//! using `Arc<Mutex<...>>`, we use a single-task ownership model where the
//! `SmoltcpShard` owns all smoltcp resources and communicates via channels.
//!
//! ## Event-Driven Polling
//!
//! Uses `smoltcp::iface::Interface::poll_delay()` for event-driven polling
//! instead of fixed-interval polling. This reduces CPU usage when idle.
//!
//! ## 1 MB TCP Buffers
//!
//! Large TCP buffers (1 MB each) are critical for high throughput over
//! high-latency WireGuard tunnels. With 70ms effective RTT, 1MB allows
//! ~114 Mbps throughput per connection.
//!
//! # Use Cases
//!
//! The smoltcp backend is used for:
//! - VLESS -> WireGuard bridging
//! - Shadowsocks -> WireGuard bridging
//! - Any TCP/UDP stream -> IP packet conversion
//!
//! # Performance
//!
//! The smoltcp backend achieves ~30-80 Mbps throughput per connection,
//! limited by userspace TCP/IP processing. For higher performance, use
//! the kernel backend (TUN + TPROXY) when possible.
//!
//! # Example
//!
//! ```ignore
//! use rust_router::netbridge::smoltcp::{SmoltcpEgress, SmoltcpEgressConfig};
//!
//! // Create egress bridge
//! let config = SmoltcpEgressConfig::new(
//!     smoltcp::wire::IpAddress::v4(10, 200, 200, 2),
//! );
//! let (egress, wg_rx) = SmoltcpEgress::new(config);
//!
//! // Handle a TCP connection
//! let stream = tokio::net::TcpStream::connect("127.0.0.1:8080").await?;
//! let dest = "93.184.216.34:443".parse()?;
//! let session_id = egress.handle_tcp(stream, dest).await?;
//!
//! // Drain IP packets to send to WireGuard
//! for packet in egress.drain_tx() {
//!     wg_tunnel.send(&packet).await?;
//! }
//! ```

mod bridge;
mod device;
mod egress;
mod shard;

// Re-export public types
pub use bridge::{SmoltcpBridge, SmoltcpBridgeConfig};
pub use device::{VirtualDevice, VirtualDeviceStats};
pub use egress::{SmoltcpEgress, SmoltcpEgressConfig, SmoltcpEgressStats};
pub use shard::{SmoltcpShard, SmoltcpShardConfig, SmoltcpShardStats};

// =============================================================================
// Constants
// =============================================================================

/// Default WireGuard MTU
pub const WG_MTU: usize = crate::netbridge::config::WG_MTU;

/// TCP Maximum Segment Size (MTU - IP header - TCP header)
pub const TCP_MSS: u16 = crate::netbridge::config::TCP_MSS;

/// TCP receive buffer size (1 MB for high-latency tunnels)
pub const TCP_RX_BUFFER: usize = crate::netbridge::config::TCP_RX_BUFFER;

/// TCP transmit buffer size (1 MB for high-latency tunnels)
pub const TCP_TX_BUFFER: usize = crate::netbridge::config::TCP_TX_BUFFER;

/// UDP receive buffer size
pub const UDP_RX_BUFFER: usize = crate::netbridge::config::UDP_RX_BUFFER;

/// UDP transmit buffer size
pub const UDP_TX_BUFFER: usize = crate::netbridge::config::UDP_TX_BUFFER;

/// UDP packet metadata count
pub const UDP_PACKET_META: usize = crate::netbridge::config::UDP_PACKET_META;

/// Maximum number of smoltcp sockets per shard
pub const MAX_SOCKETS: usize = crate::netbridge::config::MAX_SOCKETS;

/// Maximum TX buffer capacity for virtual device
pub const DEVICE_TX_BUFFER_CAPACITY: usize = 256;

/// Maximum RX buffer capacity for virtual device
pub const DEVICE_RX_BUFFER_CAPACITY: usize = 256;

/// Minimum poll interval (1ms) - prevents busy-looping
pub const MIN_POLL_INTERVAL_MS: u64 = 1;

/// Maximum poll interval (50ms) - ensures timely retransmissions
pub const MAX_POLL_INTERVAL_MS: u64 = 50;

/// Default poll interval when smoltcp has no specific timing requirements
pub const DEFAULT_POLL_INTERVAL_MS: u64 = 5;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        // Verify buffer sizes are large enough for high performance
        assert!(TCP_RX_BUFFER >= 1_000_000, "TCP RX buffer should be 1 MB");
        assert!(TCP_TX_BUFFER >= 1_000_000, "TCP TX buffer should be 1 MB");
        assert!(UDP_RX_BUFFER >= 200_000, "UDP RX buffer should be 256 KB");

        // Verify MSS is correctly calculated
        assert_eq!(TCP_MSS, 1380); // 1420 - 20 - 20

        // Verify poll intervals
        assert!(MIN_POLL_INTERVAL_MS < MAX_POLL_INTERVAL_MS);
        assert!(DEFAULT_POLL_INTERVAL_MS >= MIN_POLL_INTERVAL_MS);
        assert!(DEFAULT_POLL_INTERVAL_MS <= MAX_POLL_INTERVAL_MS);
    }
}
