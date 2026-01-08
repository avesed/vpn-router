//! IPC (Inter-Process Communication) module
//!
//! This module provides a Unix socket-based IPC server for controlling
//! the router at runtime.
//!
//! # Protocol
//!
//! Messages are length-prefixed JSON:
//! - 4 bytes: message length (big-endian u32)
//! - N bytes: JSON-encoded command or response
//!
//! # Example
//!
//! ```no_run
//! use rust_router::ipc::{IpcClient, IpcCommand, IpcResponse};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let client = IpcClient::new("/var/run/rust-router.sock");
//!
//! // Check if server is alive
//! if client.ping().await? {
//!     println!("Server is alive!");
//! }
//!
//! // Get server status
//! let response = client.send(IpcCommand::Status).await?;
//! if let IpcResponse::Status(status) = response {
//!     println!("Active connections: {}", status.active_connections);
//! }
//! # Ok(())
//! # }
//! ```

mod handler;
mod protocol;
mod server;

pub use handler::{DnsEngine, IpcHandler};
pub use protocol::{
    decode_message, encode_message, ErrorCode, IpcCommand, IpcError, IpcResponse, OutboundInfo,
    OutboundStatsResponse, ServerCapabilities, ServerStatus, LENGTH_PREFIX_SIZE, MAX_MESSAGE_SIZE,
    // Phase 6.0: IPC Protocol v3.2 types
    TunnelType, WgTunnelConfig, WgTunnelStatus, WgTunnelListResponse,
    EcmpAlgorithm, EcmpMemberConfig, EcmpGroupConfig, EcmpGroupStatus, EcmpMemberStatus, EcmpGroupListResponse,
    PeerConfig, PeerState, PeerStatus, PeerListResponse,
    ChainRole, ChainState, ChainHop, ChainConfig, HopStatus, ChainStatus, ChainListResponse,
    PrepareStatus, ChainRoleResponse, PrepareResponse, PairingResponse,
    PairRequest, PairResponse,
    // Phase 7.7: DNS IPC types
    DnsUpstreamConfig, DnsStatsResponse, DnsCacheStatsResponse, DnsBlockStatsResponse,
    DnsUpstreamStatusResponse, DnsUpstreamInfo, DnsQueryLogResponse, DnsQueryLogEntry,
    DnsQueryResponse, DnsConfigResponse,
};
pub use server::{IpcClient, IpcServer};
