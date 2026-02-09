//! Connection handling module
//!
//! This module provides connection management, including:
//! - Connection limiting with backpressure
//! - TCP connection handling
//! - UDP session management with LRU eviction
//! - UDP packet processing and reply handling
//! - Statistics collection
//! - Graceful shutdown

mod manager;
mod stats;
mod tcp;
pub mod udp;
mod udp_processor;
mod udp_reply;

pub use manager::{run_accept_loop, ConnectionManager};
pub use stats::{ConnectionStats, OutboundStats, OutboundStatsSnapshot, StatsSnapshot};
pub use tcp::{handle_tcp_connection, TcpConnectionContext, TcpConnectionResult};
pub use udp::{
    UdpSession, UdpSessionConfig, UdpSessionKey, UdpSessionManager, UdpSessionSnapshot,
    UdpSessionStats,
};
pub use udp_processor::{
    ProcessResult, UdpPacketProcessor, UdpProcessorConfig, UdpProcessorStats,
    UdpProcessorStatsSnapshot, UdpRoutingInfo, UdpSessionWrapper,
};
pub use udp_reply::{
    ReplyHandlerConfig, ReplyHandlerStats, ReplyHandlerStatsSnapshot, UdpReplyHandler,
};
