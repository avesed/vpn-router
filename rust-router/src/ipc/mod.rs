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
    decode_message,
    encode_message,
    ChainConfig,
    ChainHop,
    ChainListResponse,
    ChainRole,
    ChainRoleResponse,
    ChainState,
    ChainStatus,
    DnsBlockStatsResponse,
    DnsCacheStatsResponse,
    DnsConfigResponse,
    DnsQueryLogEntry,
    DnsQueryLogResponse,
    DnsQueryResponse,
    DnsStatsResponse,
    // DNS IPC types
    DnsUpstreamConfig,
    DnsUpstreamInfo,
    DnsUpstreamStatusResponse,
    EcmpAlgorithm,
    EcmpGroupConfig,
    EcmpGroupListResponse,
    EcmpGroupStatus,
    EcmpMemberConfig,
    EcmpMemberStatus,
    ErrorCode,
    HopStatus,
    IngressStatsResponse,
    IpcCommand,
    IpcError,
    IpcResponse,
    OutboundInfo,
    OutboundStatsResponse,
    PairRequest,
    PairResponse,
    PairingResponse,
    PeerConfig,
    PeerListResponse,
    PeerState,
    PeerStatus,
    PrepareResponse,
    PrepareStatus,
    ServerCapabilities,
    ServerStatus,
    // IPC Protocol v3.2 types
    TunnelType,
    VlessInboundStatusResponse,
    VlessOutboundInfoResponse,
    // VLESS IPC types (v3.3)
    VlessUserConfig,
    VlessUserInfo,
    VlessWgBridgeStats,
    WgTunnelConfig,
    WgTunnelListResponse,
    WgTunnelStatus,
    LENGTH_PREFIX_SIZE,
    MAX_MESSAGE_SIZE,
};

// Sharded VLESS-WG bridge types (feature: sharded-vless-wg-bridge)
#[cfg(feature = "sharded-vless-wg-bridge")]
pub use protocol::{
    ShardedBridgeStatsResponse, ShardHealthResponse, ShardStatsSnapshot, SupervisorStatsResponse,
};
pub use server::{IpcClient, IpcServer};
