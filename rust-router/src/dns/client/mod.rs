//! DNS Upstream Client Module
//!
//! This module provides DNS client implementations for querying upstream
//! DNS servers across different protocols.
//!
//! # Supported Protocols
//!
//! - **UDP** - Plain DNS over UDP (RFC 1035)
//! - **TCP** - Plain DNS over TCP (RFC 1035)
//! - **DoH** - DNS over HTTPS (RFC 8484) - requires `dns-doh` feature
//! - **DoT** - DNS over TLS (RFC 7858) - requires `dns-dot` feature
//!
//! # Architecture
//!
//! All clients implement the [`DnsUpstream`] trait, providing a unified
//! interface for DNS queries:
//!
//! ```text
//!                    ┌───────────────┐
//!                    │  DnsUpstream  │ (trait)
//!                    └───────┬───────┘
//!           ┌────────────────┼────────────────┐
//!           │                │                │
//!     ┌─────┴─────┐   ┌─────┴─────┐   ┌─────┴─────┐
//!     │ UdpClient │   │ TcpClient │   │ DohClient │
//!     └───────────┘   └───────────┘   └───────────┘
//!                            │                │
//!                     ┌──────┴──────┐         │
//!                     │  deadpool   │   ┌─────┴─────┐
//!                     │ (connection │   │ DotClient │
//!                     │   pooling)  │   └───────────┘
//!                     └─────────────┘         │
//!                                       ┌─────┴─────┐
//!                                       │  rustls   │
//!                                       │ (TLS)     │
//!                                       └───────────┘
//! ```
//!
//! # Health Checking
//!
//! Each client tracks its health state using the [`HealthChecker`], which
//! implements a state machine:
//!
//! - **Healthy** -> **Unhealthy**: After 3 consecutive failures (configurable)
//! - **Unhealthy** -> **Healthy**: After 1 success (configurable)
//!
//! # Upstream Pool
//!
//! The [`UpstreamPool`] manages multiple upstreams with:
//!
//! - Health-aware selection (skips unhealthy upstreams)
//! - Multiple selection strategies (round-robin, random, weighted)
//! - Automatic failover on query failure
//!
//! # Example
//!
//! ```no_run
//! use rust_router::dns::client::{UdpClient, TcpClient, UpstreamPool, SelectionStrategy};
//! use rust_router::dns::{UpstreamConfig, UpstreamProtocol};
//! use hickory_proto::op::Message;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create UDP client
//! let udp_config = UpstreamConfig::new("google-udp", "8.8.8.8:53", UpstreamProtocol::Udp);
//! let udp_client = UdpClient::new(udp_config)?;
//!
//! // Create TCP client with connection pooling
//! let tcp_config = UpstreamConfig::new("cloudflare-tcp", "1.1.1.1:53", UpstreamProtocol::Tcp);
//! let tcp_client = TcpClient::new(tcp_config)?;
//!
//! // Create upstream pool
//! let pool = UpstreamPool::builder()
//!     .add_upstream(Box::new(udp_client))
//!     .add_upstream(Box::new(tcp_client))
//!     .strategy(SelectionStrategy::RoundRobin)
//!     .build();
//!
//! // Query using the pool (automatic health-aware selection)
//! let mut query = Message::new();
//! query.set_id(0x1234);
//! // ... set up query ...
//!
//! let response = pool.query(&query).await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Feature Flags
//!
//! - `dns-doh` - Enable DNS-over-HTTPS support (hyper + rustls)
//! - `dns-dot` - Enable DNS-over-TLS support (tokio-rustls)
//!
//! Both features are enabled by default.

mod health;
mod pool;
mod tcp;
mod traits;
mod udp;

#[cfg(feature = "dns-doh")]
mod doh;

#[cfg(feature = "dns-dot")]
mod dot;

// Re-export public types
pub use health::{HealthCheckConfig, HealthChecker, HealthStats};
pub use pool::{PoolStats, SelectionStrategy, UpstreamInfo, UpstreamPool, UpstreamPoolBuilder};
pub use tcp::TcpClient;
pub use traits::{
    validate_response, DnsUpstream, QueryMetadata, DEFAULT_QUERY_TIMEOUT_SECS, DEFAULT_UDP_RETRIES,
    MAX_TCP_MESSAGE_SIZE, MAX_UDP_MESSAGE_SIZE,
};
pub use udp::UdpClient;

#[cfg(feature = "dns-doh")]
pub use doh::DohClient;

#[cfg(feature = "dns-dot")]
pub use dot::DotClient;

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // Module Re-export Tests
    // ========================================================================

    #[test]
    fn test_reexports_exist() {
        // Verify key types are exported
        fn _check_health_exports() {
            let _ = HealthCheckConfig::default();
        }

        fn _check_pool_exports() {
            let _: SelectionStrategy = SelectionStrategy::RoundRobin;
        }

        fn _check_trait_constants() {
            let _: u64 = DEFAULT_QUERY_TIMEOUT_SECS;
            let _: u32 = DEFAULT_UDP_RETRIES;
            let _: usize = MAX_UDP_MESSAGE_SIZE;
            let _: usize = MAX_TCP_MESSAGE_SIZE;
        }
    }

    #[test]
    fn test_constants_values() {
        assert_eq!(DEFAULT_QUERY_TIMEOUT_SECS, 5);
        assert_eq!(DEFAULT_UDP_RETRIES, 2);
        assert_eq!(MAX_UDP_MESSAGE_SIZE, 512);
        assert_eq!(MAX_TCP_MESSAGE_SIZE, 65535);
    }

    #[test]
    fn test_selection_strategy_variants() {
        let rr = SelectionStrategy::RoundRobin;
        let random = SelectionStrategy::Random;
        let first = SelectionStrategy::FirstAvailable;
        let weighted = SelectionStrategy::Weighted;

        assert!(matches!(rr, SelectionStrategy::RoundRobin));
        assert!(matches!(random, SelectionStrategy::Random));
        assert!(matches!(first, SelectionStrategy::FirstAvailable));
        assert!(matches!(weighted, SelectionStrategy::Weighted));
    }

    #[test]
    fn test_selection_strategy_default() {
        let default = SelectionStrategy::default();
        assert!(matches!(default, SelectionStrategy::RoundRobin));
    }
}
