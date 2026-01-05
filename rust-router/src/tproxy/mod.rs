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
//! ## Requirements
//!
//! - Linux kernel with TPROXY support
//! - CAP_NET_ADMIN capability (or root)
//! - iptables TPROXY rules configured
//! - ip rules and routes for TPROXY mark
//!
//! ## Example iptables Setup
//!
//! ```bash
//! # Mark packets for TPROXY
//! iptables -t mangle -A PREROUTING -i wg-ingress -p tcp -j TPROXY \
//!     --on-ip 127.0.0.1 --on-port 7893 --tproxy-mark 0x1
//!
//! # Route marked packets locally
//! ip rule add fwmark 0x1 lookup 100
//! ip route add local 0.0.0.0/0 dev lo table 100
//! ```
//!
//! # Usage
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
//!     println!("Connection from {} to {}", conn.client_addr(), conn.original_dst());
//! }
//! # }
//! ```

mod connection;
mod listener;
mod socket;

pub use connection::{ConnectionInfo, TproxyConnection};
pub use listener::{TproxyListener, TproxyListenerBuilder};
pub use socket::{
    create_tproxy_tcp_socket, create_tproxy_udp_socket, get_original_dst, get_original_dst_v6,
    has_net_admin_capability, is_root, IP_RECVORIGDSTADDR, IP_TRANSPARENT, SO_ORIGINAL_DST,
};
