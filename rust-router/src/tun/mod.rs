//! TUN device module for Linux userspace networking
//!
//! This module provides a safe, async Rust interface for creating and interacting
//! with Linux TUN (network TUNnel) devices.
//!
//! # Overview
//!
//! A TUN device is a virtual network interface that operates at layer 3 (IP).
//! Unlike physical interfaces that send/receive Ethernet frames, a TUN device
//! sends/receives raw IP packets through a userspace file descriptor.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │                        Linux Kernel                                  │
//! │                                                                      │
//! │  ┌──────────┐    ┌──────────┐    ┌──────────────────────────────┐  │
//! │  │ eth0     │    │ wg0      │    │ tun-in (TUN device)          │  │
//! │  │ (physical│    │(wireguard│    │                              │  │
//! │  │ NIC)     │    │ kernel)  │    │  /dev/net/tun fd ────────────┼──┼──→ userspace
//! │  └──────────┘    └──────────┘    └──────────────────────────────┘  │
//! │       ↑              ↑                         ↑                    │
//! │       │              │                         │                    │
//! │       └──────────────┴─────────────────────────┘                    │
//! │                      Network Stack                                  │
//! │                      (routing, iptables, etc.)                      │
//! └─────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Use Cases
//!
//! 1. **VPN/Tunnel Ingress**: Receive decrypted packets from WireGuard and route them
//! 2. **Transparent Proxy**: Intercept and process IP packets before forwarding
//! 3. **Network Simulation**: Create virtual networks for testing
//! 4. **Traffic Shaping**: Implement custom QoS policies
//!
//! # Comparison: TUN vs TPROXY
//!
//! | Feature | TUN | TPROXY |
//! |---------|-----|--------|
//! | Layer | L3 (IP) | L4 (TCP/UDP) |
//! | Packet type | Raw IP packets | TCP streams, UDP datagrams |
//! | Routing | Via kernel routing table | Via iptables mangle |
//! | Performance | Higher (less copying) | Lower (kernel TCP/UDP) |
//! | Complexity | Must handle IP/TCP/UDP | Kernel handles L3/L4 |
//! | Use case | VPN ingress, WireGuard | Per-connection proxying |
//!
//! # Requirements
//!
//! - Linux kernel with TUN support (virtually all modern kernels)
//! - `CAP_NET_ADMIN` capability or root privileges
//! - `/dev/net/tun` device node (usually exists by default)
//!
//! # Example
//!
//! ```no_run
//! use rust_router::tun::{TunConfig, TunDevice};
//!
//! # async fn example() -> std::io::Result<()> {
//! // Create a TUN device
//! let config = TunConfig::new("tun-in")
//!     .with_mtu(1420);  // WireGuard MTU
//!
//! let device = TunDevice::create(&config)?;
//! println!("Created TUN device: {}", device.name());
//!
//! // Read packets in a loop
//! let mut buf = [0u8; 1500];
//! loop {
//!     let n = device.read_packet(&mut buf).await?;
//!     let ip_version = buf[0] >> 4;
//!     println!("Received {} byte IPv{} packet", n, ip_version);
//!
//!     // Process and potentially write back
//!     // device.write_packet(&response).await?;
//! }
//! # }
//! ```
//!
//! # Multi-Queue Support
//!
//! For high-throughput scenarios, TUN devices support multi-queue mode where
//! multiple file descriptors can read/write to the same interface in parallel:
//!
//! ```no_run
//! use rust_router::tun::{TunConfig, TunDevice};
//!
//! # fn example() -> std::io::Result<()> {
//! // Create a multi-queue TUN device
//! let config = TunConfig::new("tun-mq")
//!     .with_mtu(1420)
//!     .with_multi_queue(true);
//!
//! // Create multiple queues (each gets its own fd)
//! let queue1 = TunDevice::create(&config)?;
//! let queue2 = TunDevice::create(&config)?;  // Same name = same interface
//!
//! // Now queue1 and queue2 can be used on different threads
//! # Ok(())
//! # }
//! ```
//!
//! # Module Structure
//!
//! - [`config`]: TUN device configuration ([`TunConfig`])
//! - [`device`]: TUN device implementation ([`TunDevice`])
//! - [`ioctl`]: Low-level ioctl constants and helpers

// Allow doc_markdown for TUN/WireGuard/TPROXY terminology
#![allow(clippy::doc_markdown)]

mod config;
mod device;
mod ioctl;

// Re-export public types
pub use config::{TunConfig, DEFAULT_MTU};
pub use device::TunDevice;

// Re-export commonly used ioctl constants and types
pub use ioctl::{
    // Types
    IfReq, IfReqData, SockAddrIn,
    // TUN/TAP flags
    IFF_MULTI_QUEUE, IFF_NO_PI, IFF_TAP, IFF_TUN, IFF_VNET_HDR,
    // Interface flags for bring_up/configure
    IFF_RUNNING, IFF_UP,
    // Socket ioctls
    SIOCGIFFLAGS, SIOCSIFADDR, SIOCSIFFLAGS, SIOCSIFMTU, SIOCSIFNETMASK,
    // TUN ioctls
    TUNSETIFF, TUNSETOWNER, TUNSETPERSIST,
    // Constants
    IFNAMSIZ, MAX_INTERFACE_NAME_LEN, TUN_DEV_PATH,
};

// ============================================================================
// Module-level tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_exports() {
        // Verify all expected types are exported
        let _ = TunConfig::new("test");
        assert_eq!(DEFAULT_MTU, 1500);
        assert_eq!(IFF_TUN, 0x0001);
        assert_eq!(IFF_NO_PI, 0x1000);
        assert_eq!(TUN_DEV_PATH.to_str().unwrap(), "/dev/net/tun");
        assert_eq!(MAX_INTERFACE_NAME_LEN, 15);
        // Verify new exports
        assert_eq!(IFF_UP, 0x1);
        assert_eq!(IFF_RUNNING, 0x40);
        assert_eq!(SIOCSIFADDR, 0x8916);
    }

    #[test]
    fn test_ifreq_construction() {
        let ifr = IfReq::new("tun0", IFF_TUN | IFF_NO_PI);
        assert_eq!(ifr.name(), "tun0");
    }
}
