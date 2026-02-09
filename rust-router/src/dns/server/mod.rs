//! DNS Server Module for rust-router
//!
//! This module provides UDP and TCP DNS listeners with rate limiting,
//! connection management, and query handling.
//!
//! # Architecture
//!
//! ```text
//! Client Query (UDP/TCP)
//!     |
//!     v
//! +-------------------+
//! |  Rate Limiter     | -- Exceeded --> RateLimitExceeded error
//! +-------------------+
//!     |
//!     v
//! +-------------------+
//! |  DnsHandler       | -- Parse & Validate --> InvalidQuery error
//! +-------------------+
//!     |
//!     v
//! [Future: Cache/Filter/Route/Upstream]
//! ```
//!
//! # Components
//!
//! - [`rate_limit`]: Per-client rate limiting using token bucket algorithm
//! - [`udp`]: UDP DNS listener with batch I/O support
//! - [`tcp`]: TCP DNS listener with connection limits and security
//! - [`handler`]: Core DNS query processing
//!
//! # Example
//!
//! ```no_run
//! use rust_router::dns::server::{DnsRateLimiter, DnsHandler, UdpDnsServer};
//! use rust_router::dns::{RateLimitConfig, DnsConfig, TcpServerConfig};
//! use std::sync::Arc;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create rate limiter
//! let rate_limiter = Arc::new(DnsRateLimiter::new(&RateLimitConfig::default()));
//!
//! // Create handler
//! let handler = Arc::new(DnsHandler::new(Arc::clone(&rate_limiter)));
//!
//! // Create and run UDP server
//! let config = DnsConfig::default();
//! let server = UdpDnsServer::bind(config.listen_udp, Arc::clone(&handler)).await?;
//! // server.run().await?;
//! # Ok(())
//! # }
//! ```

pub mod handler;
pub mod rate_limit;
pub mod tcp;
pub mod udp;

// Re-exports
pub use handler::{DnsHandler, QueryContext, MAX_UDP_RESPONSE_SIZE_NO_EDNS};
pub use rate_limit::{DnsRateLimiter, RateLimiterStats};
pub use tcp::{TcpConnectionTracker, TcpDnsServer};
pub use udp::UdpDnsServer;
