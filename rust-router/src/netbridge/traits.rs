//! Core traits for the netbridge module
//!
//! This module defines the core traits that abstract over different backend
//! implementations (kernel TUN+TPROXY vs userspace smoltcp).
//!
//! # Architecture
//!
//! The netbridge module uses two main traits:
//!
//! - [`NetBridgeIngress`]: Handles incoming IP packets from WireGuard/TUN
//! - [`NetBridgeEgress`]: Handles outgoing TCP/UDP connections
//!
//! These traits use Rust 1.75+ native async trait syntax (no `async_trait` macro).
//!
//! # Backend Implementations
//!
//! ## Kernel Backend (TUN + TPROXY)
//!
//! - Uses TUN device for IP packet injection
//! - TPROXY for transparent TCP/UDP handling
//! - Kernel TCP/IP stack for 200-400 Mbps performance
//!
//! ## Smoltcp Backend (Userspace)
//!
//! - Pure userspace TCP/IP stack
//! - No kernel dependencies
//! - Works in non-privileged containers
//!
//! # Example
//!
//! ```ignore
//! use rust_router::netbridge::{NetBridgeIngress, NetBridgeEgress, ReplyPacket};
//!
//! async fn handle_traffic<I, E>(ingress: &I, egress: &E)
//! where
//!     I: NetBridgeIngress,
//!     E: NetBridgeEgress,
//! {
//!     // Inject packet from WireGuard
//!     ingress.inject_packet(&packet, peer_key, peer_endpoint).await?;
//!
//!     // Handle reply packets
//!     let mut rx = ingress.take_reply_rx().unwrap();
//!     while let Some(reply) = rx.recv().await {
//!         send_to_wireguard(reply).await;
//!     }
//! }
//! ```

use std::future::Future;
use std::net::SocketAddr;

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;

use super::error::{NetBridgeError, Result};
use super::types::{EgressStats, IngressStats, ReplyPacket, SessionId};

// =============================================================================
// Ingress Trait
// =============================================================================

/// Trait for handling ingress IP packets
///
/// An ingress bridge receives raw IP packets from WireGuard, processes them,
/// and routes them to the appropriate outbound. Reply packets are collected
/// and sent back to the peer.
///
/// # Implementations
///
/// - `KernelIngress`: TUN device + TPROXY (kernel TCP/IP)
/// - `SmoltcpIngress`: Userspace smoltcp stack
///
/// # Lifecycle
///
/// 1. Create the bridge with configuration
/// 2. Call `take_reply_rx()` to get the reply channel
/// 3. Call `run()` to start the bridge
/// 4. Use `inject_packet()` to send packets from WireGuard
/// 5. Receive replies from the channel and send to WireGuard
pub trait NetBridgeIngress: Send + Sync {
    /// Inject an IP packet from WireGuard into the bridge
    ///
    /// The packet is processed and routed according to the configured rules.
    /// Any reply packets will be sent through the reply channel.
    ///
    /// # Arguments
    ///
    /// * `packet` - Raw IP packet data
    /// * `peer_key` - WireGuard peer public key (32 bytes)
    /// * `peer_endpoint` - Peer's WireGuard endpoint for reply routing
    ///
    /// # Returns
    ///
    /// `Ok(())` if the packet was successfully injected, or an error if
    /// the bridge is not ready or the packet is invalid.
    fn inject_packet(
        &self,
        packet: &[u8],
        peer_key: [u8; 32],
        peer_endpoint: SocketAddr,
    ) -> impl Future<Output = Result<()>> + Send;

    /// Take the reply packet receiver
    ///
    /// This should be called once before starting the bridge. The receiver
    /// produces `ReplyPacket` values that should be encrypted and sent to
    /// the appropriate WireGuard peer.
    ///
    /// # Returns
    ///
    /// The reply receiver, or `None` if already taken.
    fn take_reply_rx(&mut self) -> Option<mpsc::Receiver<ReplyPacket>>;

    /// Run the ingress bridge
    ///
    /// This starts the main processing loops (TUN reader, TPROXY acceptor, etc.)
    /// and runs until the bridge is shut down.
    ///
    /// # Returns
    ///
    /// `Ok(())` on clean shutdown, or an error if the bridge fails.
    fn run(&self) -> impl Future<Output = Result<()>> + Send;

    /// Shutdown the ingress bridge
    ///
    /// Initiates a graceful shutdown. In-flight connections will be allowed
    /// to complete before the bridge stops.
    fn shutdown(&self) -> impl Future<Output = ()> + Send;

    /// Get current statistics
    fn stats(&self) -> IngressStats;

    /// Check if the bridge is running
    fn is_running(&self) -> bool;
}

// =============================================================================
// Egress Trait
// =============================================================================

/// Trait for handling egress TCP/UDP connections
///
/// An egress bridge handles connections from VLESS/Shadowsocks inbound to
/// WireGuard outbound, using smoltcp for TCP/IP ↔ IP packet conversion.
///
/// # Implementations
///
/// - `SmoltcpEgress`: Userspace smoltcp stack for VLESS → WG bridging
///
/// # Data Flow
///
/// ```text
/// VLESS TCP stream → handle_tcp() → smoltcp → IP packets → WireGuard
/// VLESS UDP stream → handle_udp() → smoltcp → IP packets → WireGuard
/// WireGuard reply → feed_reply() → smoltcp → TCP/UDP data → VLESS
/// ```
pub trait NetBridgeEgress: Send + Sync {
    /// Handle a TCP connection
    ///
    /// Takes ownership of a TCP stream and bridges it to the WireGuard tunnel
    /// via the smoltcp stack.
    ///
    /// # Arguments
    ///
    /// * `stream` - The TCP stream from the inbound (VLESS, etc.)
    /// * `dest` - The destination address to connect to
    ///
    /// # Returns
    ///
    /// The session ID on success, or an error if the connection fails.
    fn handle_tcp<S>(
        &self,
        stream: S,
        dest: SocketAddr,
    ) -> impl Future<Output = Result<SessionId>> + Send
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static;

    /// Handle a UDP connection/session
    ///
    /// Bridges UDP traffic between the inbound and the WireGuard tunnel.
    ///
    /// # Arguments
    ///
    /// * `src` - The source address (client)
    /// * `dest` - The destination address
    /// * `data` - The UDP payload
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, or an error if the operation fails.
    fn handle_udp(
        &self,
        src: SocketAddr,
        dest: SocketAddr,
        data: &[u8],
    ) -> impl Future<Output = Result<()>> + Send;

    /// Feed a reply IP packet into the egress bridge
    ///
    /// This is called when an IP packet is received from the WireGuard tunnel
    /// that needs to be processed by smoltcp and forwarded to the TCP/UDP
    /// streams.
    ///
    /// # Arguments
    ///
    /// * `packet` - Raw IP packet from WireGuard
    ///
    /// # Returns
    ///
    /// `Ok(())` if the packet was accepted, or an error if invalid.
    fn feed_reply(&self, packet: &[u8]) -> Result<()>;

    /// Drain pending TX packets
    ///
    /// Returns all IP packets waiting to be sent to WireGuard.
    /// This should be called after processing to collect outgoing packets.
    ///
    /// # Returns
    ///
    /// A vector of IP packets to send to WireGuard.
    fn drain_tx(&self) -> Vec<Bytes>;

    /// Poll the smoltcp stack
    ///
    /// This should be called periodically to process timeouts, retransmissions,
    /// and other timed operations.
    ///
    /// # Returns
    ///
    /// The duration until the next required poll, or `None` if immediate.
    fn poll(&self) -> impl Future<Output = Option<std::time::Duration>> + Send;

    /// Close a specific session
    ///
    /// # Arguments
    ///
    /// * `session_id` - The session to close
    fn close_session(
        &self,
        session_id: SessionId,
    ) -> impl Future<Output = Result<()>> + Send;

    /// Get current statistics
    fn stats(&self) -> EgressStats;

    /// Get the number of active sessions
    fn active_sessions(&self) -> usize;
}

// =============================================================================
// Reply Router Trait
// =============================================================================

/// Trait for routing reply packets to WireGuard peers
///
/// This abstracts the mechanism for sending encrypted reply packets back
/// to WireGuard clients.
pub trait ReplyRouterExt: Send + Sync {
    /// Send a reply packet to a WireGuard peer
    ///
    /// The packet should be encrypted with the peer's session key and
    /// sent to the peer's endpoint.
    ///
    /// # Arguments
    ///
    /// * `reply` - The reply packet with peer routing information
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, or an error if the send fails.
    fn send_reply(&self, reply: ReplyPacket) -> impl Future<Output = Result<()>> + Send;

    /// Send multiple reply packets efficiently
    ///
    /// This can batch packets for better performance.
    ///
    /// # Arguments
    ///
    /// * `replies` - Iterator of reply packets
    ///
    /// # Returns
    ///
    /// The number of packets successfully sent.
    fn send_replies<I>(&self, replies: I) -> impl Future<Output = usize> + Send
    where
        I: IntoIterator<Item = ReplyPacket> + Send;
}

// =============================================================================
// Session Handler Trait
// =============================================================================

/// Trait for handling session lifecycle events
///
/// Implementations receive callbacks when sessions are created, updated,
/// or closed.
pub trait SessionHandler: Send + Sync {
    /// Called when a new session is created
    fn on_session_created(&self, session_id: SessionId, info: &SessionInfo);

    /// Called when a session is closed
    fn on_session_closed(&self, session_id: SessionId, stats: SessionCloseStats);

    /// Called when a session encounters an error
    fn on_session_error(&self, session_id: SessionId, error: &NetBridgeError);
}

/// Information about a session at creation time
#[derive(Debug, Clone)]
pub struct SessionInfo {
    /// Unique session identifier
    pub session_id: SessionId,
    /// Session protocol (TCP/UDP)
    pub protocol: super::types::IpProtocol,
    /// Source address
    pub src_addr: SocketAddr,
    /// Destination address
    pub dst_addr: SocketAddr,
    /// Outbound tag for routing
    pub outbound_tag: String,
    /// Peer public key
    pub peer_key: [u8; 32],
}

/// Statistics when a session closes
#[derive(Debug, Clone, Default)]
pub struct SessionCloseStats {
    /// Session duration in milliseconds
    pub duration_ms: u64,
    /// Bytes sent to outbound
    pub bytes_sent: u64,
    /// Bytes received from outbound
    pub bytes_received: u64,
    /// Close reason
    pub close_reason: CloseReason,
}

/// Reason for session closure
#[derive(Debug, Clone, Default)]
pub enum CloseReason {
    /// Normal closure
    #[default]
    Normal,
    /// Connection timeout
    Timeout,
    /// Connection reset
    Reset,
    /// Error occurred
    Error(String),
    /// Bridge shutdown
    Shutdown,
}

// =============================================================================
// No-op Implementations
// =============================================================================

/// No-op session handler for when callbacks are not needed
#[derive(Debug, Default, Clone, Copy)]
pub struct NoOpSessionHandler;

impl SessionHandler for NoOpSessionHandler {
    fn on_session_created(&self, _session_id: SessionId, _info: &SessionInfo) {}
    fn on_session_closed(&self, _session_id: SessionId, _stats: SessionCloseStats) {}
    fn on_session_error(&self, _session_id: SessionId, _error: &NetBridgeError) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_close_reason_default() {
        let reason: CloseReason = Default::default();
        assert!(matches!(reason, CloseReason::Normal));
    }

    #[test]
    fn test_session_close_stats_default() {
        let stats: SessionCloseStats = Default::default();
        assert_eq!(stats.duration_ms, 0);
        assert_eq!(stats.bytes_sent, 0);
        assert_eq!(stats.bytes_received, 0);
        assert!(matches!(stats.close_reason, CloseReason::Normal));
    }

    #[test]
    fn test_noop_session_handler() {
        use super::super::types::IpProtocol;
        use std::net::{IpAddr, Ipv4Addr};

        let handler = NoOpSessionHandler;
        let info = SessionInfo {
            session_id: SessionId::new(1),
            protocol: IpProtocol::Tcp,
            src_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345),
            dst_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 80),
            outbound_tag: "direct".to_string(),
            peer_key: [0u8; 32],
        };

        // These should all complete without error
        handler.on_session_created(SessionId::new(1), &info);
        handler.on_session_closed(SessionId::new(1), SessionCloseStats::default());
        handler.on_session_error(SessionId::new(1), &NetBridgeError::ConnectionTimeout);
    }
}
