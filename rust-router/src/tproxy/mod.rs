//! TPROXY module for transparent proxying
//!
//! This module provides all functionality needed for TPROXY-based transparent
//! proxying, including socket creation, connection handling, and listeners.
//!
//! # Overview
//!
//! TPROXY (transparent proxy) is a Linux kernel feature that allows a proxy
//! to intercept connections destined for any address without requiring any
//! client-side configuration.
//!
//! # IPv4 Only
//!
//! **Important**: This implementation currently supports IPv4 only. IPv6 support
//! is planned for a future release. The `get_original_dst_v6` function exists but
//! is not integrated into the listener infrastructure.
//!
//! # Requirements
//!
//! ## System Capabilities
//!
//! - Linux kernel with TPROXY support (3.x+)
//! - `CAP_NET_ADMIN` capability (or root)
//! - iptables with TPROXY target (`xt_TPROXY` module)
//!
//! ## Required sysctl Settings
//!
//! The following sysctl settings are **required** for TPROXY to function:
//!
//! ```bash
//! # Allow routing to 127.0.0.0/8 (required for TPROXY --on-ip 127.0.0.1)
//! sysctl -w net.ipv4.conf.all.route_localnet=1
//! sysctl -w net.ipv4.conf.lo.route_localnet=1
//!
//! # Allow binding to non-local addresses (required for reply sockets)
//! sysctl -w net.ipv4.ip_nonlocal_bind=1
//!
//! # Disable reverse path filtering (required for TPROXY packets)
//! sysctl -w net.ipv4.conf.all.rp_filter=0
//! sysctl -w net.ipv4.conf.default.rp_filter=0
//!
//! # For specific interfaces (e.g., wg-ingress):
//! sysctl -w net.ipv4.conf.wg-ingress.rp_filter=0
//! sysctl -w net.ipv4.conf.wg-ingress.route_localnet=1
//! ```
//!
//! ### Why These Settings Are Required
//!
//! | Setting | Purpose |
//! |---------|---------|
//! | `route_localnet=1` | TPROXY uses `--on-ip 127.0.0.1` to redirect traffic to loopback. Without this, the kernel treats 127.0.0.0/8 as "martian" and silently drops packets. |
//! | `ip_nonlocal_bind=1` | UDP reply sockets must bind to the original destination (a non-local address) to spoof the source. Without this, `bind()` fails with EADDRNOTAVAIL. |
//! | `rp_filter=0` | Reverse path filtering drops packets whose source address doesn't match the expected ingress interface. TPROXY packets may fail this check. |
//!
//! ## Example iptables Setup
//!
//! ```bash
//! # Create TPROXY routing table
//! ip rule add fwmark 0x1 lookup 100
//! ip route add local 0.0.0.0/0 dev lo table 100
//!
//! # DIVERT chain for established connections (optional but recommended)
//! iptables -t mangle -N DIVERT
//! iptables -t mangle -A DIVERT -j MARK --set-mark 0x1
//! iptables -t mangle -A DIVERT -j ACCEPT
//!
//! # Handle established connections first (avoids re-processing)
//! iptables -t mangle -A PREROUTING -i wg-ingress -p tcp -m socket --transparent -j DIVERT
//! iptables -t mangle -A PREROUTING -i wg-ingress -p udp -m socket --transparent -j DIVERT
//!
//! # TPROXY new connections (TCP and UDP)
//! iptables -t mangle -A PREROUTING -i wg-ingress -p tcp -j TPROXY \
//!     --on-ip 127.0.0.1 --on-port 7893 --tproxy-mark 0x1
//! iptables -t mangle -A PREROUTING -i wg-ingress -p udp -j TPROXY \
//!     --on-ip 127.0.0.1 --on-port 7893 --tproxy-mark 0x1
//! ```
//!
//! # Usage
//!
//! ## TCP
//!
//! ```no_run
//! use rust_router::tproxy::TproxyListener;
//! use rust_router::config::ListenConfig;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = ListenConfig::default();
//! let listener = TproxyListener::bind(&config)?;
//!
//! loop {
//!     let conn = listener.accept().await?;
//!     println!("TCP: {} -> {}", conn.client_addr(), conn.original_dst());
//! }
//! # }
//! ```
//!
//! ## UDP
//!
//! ```no_run
//! use rust_router::tproxy::TproxyUdpListener;
//! use rust_router::config::ListenConfig;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = ListenConfig::default();
//! let listener = TproxyUdpListener::bind(&config)?;
//!
//! loop {
//!     let packet = listener.recv_packet().await?;
//!     println!("UDP: {} -> {} ({} bytes)",
//!         packet.client_addr, packet.original_dst, packet.len());
//! }
//! # }
//! ```
//!
//! # Troubleshooting
//!
//! ## Traffic Received but Not Processed ("Black Hole")
//!
//! If iptables counters increase but sing-box/rust-router never sees the traffic:
//!
//! 1. Check `route_localnet`:
//!    ```bash
//!    sysctl net.ipv4.conf.all.route_localnet  # Must be 1
//!    ```
//!
//! 2. Check for martian packet drops:
//!    ```bash
//!    dmesg | grep -i martian
//!    ```
//!
//! 3. Verify routing table 100:
//!    ```bash
//!    ip route show table 100
//!    # Expected: local 0.0.0.0/0 dev lo scope host
//!    ```
//!
//! ## Permission Denied Errors
//!
//! TPROXY requires `CAP_NET_ADMIN`. Run as root or with:
//! ```bash
//! setcap cap_net_admin+ep ./rust-router
//! ```

mod connection;
mod listener;
mod socket;
mod udp_listener;
mod udp_worker;

pub use connection::{ConnectionInfo, TproxyConnection};
pub use listener::{TproxyListener, TproxyListenerBuilder};
pub use socket::{
    create_tproxy_tcp_socket, create_tproxy_udp_socket, default_socket_provider, get_original_dst,
    get_original_dst_v6, has_net_admin_capability, is_root, RealSocketProvider, SocketProvider,
    IP_RECVORIGDSTADDR, IP_TRANSPARENT, SO_ORIGINAL_DST,
};
pub use udp_listener::{TproxyUdpListener, TproxyUdpListenerBuilder, UdpPacketInfo};
pub use udp_worker::{
    UdpWorkerPool, UdpWorkerPoolConfig, UdpWorkerPoolStats, UdpWorkerPoolStatsSnapshot,
};

#[cfg(test)]
pub use socket::MockSocketProvider;
