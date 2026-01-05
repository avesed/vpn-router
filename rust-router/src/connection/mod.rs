//! Connection handling module
//!
//! This module provides connection management, including:
//! - Connection limiting with backpressure
//! - TCP connection handling
//! - Statistics collection
//! - Graceful shutdown

mod manager;
mod stats;
mod tcp;

pub use manager::{run_accept_loop, ConnectionManager};
pub use stats::{ConnectionStats, OutboundStats, OutboundStatsSnapshot, StatsSnapshot};
pub use tcp::{handle_tcp_connection, TcpConnectionContext, TcpConnectionResult};
