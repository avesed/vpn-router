//! FakeDNS - Virtual DNS server for domain-based routing
//!
//! This module provides a FakeDNS server that maps domain names to fake IP addresses,
//! enabling transparent domain-based routing. When a client queries a domain name,
//! the server allocates a fake IP from a configured pool and maintains a bidirectional
//! mapping. When traffic is later received for that fake IP, the original domain name
//! can be retrieved for routing decisions.
//!
//! ## Features
//!
//! - **Bidirectional mapping**: Domain -> IP and IP -> Domain lookups
//! - **Thread-safe**: Uses DashMap for lock-free concurrent access
//! - **TTL-based expiration**: Automatic cleanup of stale entries
//! - **IPv4 and IPv6 support**: Optional IPv6 pool configuration
//! - **TCP and UDP DNS**: Standard DNS protocol over both transports
//!
//! ## Example
//!
//! ```rust,ignore
//! use rust_router::fakedns::{FakeDns, FakeDnsConfig};
//! use std::net::SocketAddr;
//!
//! #[tokio::main]
//! async fn main() -> std::io::Result<()> {
//!     let addr: SocketAddr = "127.0.0.1:5353".parse().unwrap();
//!     let config = FakeDnsConfig::new()
//!         .with_ipv4_pool("198.18.0.0/15".parse().unwrap())
//!         .with_max_entries(65536);
//!
//!     let fakedns = FakeDns::builder(addr)
//!         .config(config)
//!         .build()
//!         .await?;
//!
//!     // Access the manager for IP-to-domain lookups
//!     let manager = fakedns.manager().clone();
//!
//!     // Run the server
//!     fakedns.run().await
//! }
//! ```

pub mod cache;
pub mod config;
pub mod manager;
pub mod pool;
mod processor;
pub mod server;
mod tcp_server;
mod udp_server;

// Re-export main types for convenience
pub use cache::{FakeDnsCache, FakeDnsCacheStats, FakeDnsCacheStatsSnapshot};
pub use config::FakeDnsConfig;
pub use manager::{FakeDnsError, FakeDnsManager, FakeDnsResult};
pub use server::{FakeDns, FakeDnsBuilder};
