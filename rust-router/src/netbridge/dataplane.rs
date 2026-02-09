// Some fields are reserved for future features.
#![allow(dead_code)]

//! Standalone Data Plane API for netbridge
//!
//! This module provides a clean, independent API for using netbridge as a
//! standalone data plane. The control plane makes routing decisions via
//! callbacks, while the data plane handles only packet forwarding.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │                      Control Plane (User Code)                       │
//! │                                                                     │
//! │  impl ConnectionHandler for MyRouter {                              │
//! │      fn on_tcp_connect(&self, info) -> Option<OutboundStream> {    │
//! │          // Decide routing based on info.dst, info.domain, etc.    │
//! │          Some(connect_to_outbound(info.dst))                       │
//! │      }                                                              │
//! │  }                                                                  │
//! └───────────────────────────────────┬─────────────────────────────────┘
//!                                     │ ConnectionHandler trait
//!                                     ▼
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │                      Data Plane (netbridge)                         │
//! │                                                                     │
//! │  ┌─────────────────┐              ┌─────────────────────────────┐  │
//! │  │  Ingress        │              │  Egress                     │  │
//! │  │  (IP → TCP/UDP) │              │  (TCP/UDP → IP)             │  │
//! │  │                 │              │                             │  │
//! │  │  - TUN device   │              │  - smoltcp stack            │  │
//! │  │  - TPROXY       │              │  - TCP/UDP sessions         │  │
//! │  │  - Session mgmt │              │  - IP packet generation     │  │
//! │  └─────────────────┘              └─────────────────────────────┘  │
//! │                                                                     │
//! └─────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Quick Start
//!
//! ```ignore
//! use netbridge::dataplane::{DataPlane, DataPlaneBuilder, ConnectionHandler, ConnectionInfo};
//! use tokio::net::TcpStream;
//!
//! // 1. Implement ConnectionHandler (control plane)
//! struct MyRouter;
//!
//! impl ConnectionHandler for MyRouter {
//!     async fn on_tcp_connect(&self, info: ConnectionInfo) -> Option<Box<dyn OutboundStream>> {
//!         // Simple direct connection
//!         let stream = TcpStream::connect(info.dst).await.ok()?;
//!         Some(Box::new(stream))
//!     }
//!
//!     async fn on_udp_session(&self, info: ConnectionInfo) -> Option<UdpHandle> {
//!         // Create UDP socket for this session
//!         let socket = UdpSocket::bind("0.0.0.0:0").await.ok()?;
//!         socket.connect(info.dst).await.ok()?;
//!         Some(UdpHandle::new(socket))
//!     }
//! }
//!
//! // 2. Create data plane with handler
//! let dp = DataPlaneBuilder::new()
//!     .with_tun("tun-netbridge")
//!     .with_tproxy_port(7893)
//!     .with_handler(Arc::new(MyRouter))
//!     .build()
//!     .await?;
//!
//! // 3. Inject packets from WireGuard
//! dp.inject_packet(&ip_packet, peer_key, peer_endpoint).await?;
//!
//! // 4. Get reply packets to send back to WireGuard
//! while let Some(reply) = dp.recv_reply().await {
//!     send_to_wireguard(&reply.data, &reply.peer_endpoint).await;
//! }
//! ```
//!
//! # Design Principles
//!
//! 1. **Separation of Concerns**: Data plane handles forwarding only;
//!    routing decisions are delegated to the control plane via callbacks.
//!
//! 2. **Zero Runtime Dependencies**: No built-in rule engine, FakeDNS,
//!    or outbound implementations. All provided by the control plane.
//!
//! 3. **Async-First**: Native async/await with Rust 1.75+ async traits.
//!
//! 4. **High Performance**: Zero-copy where possible, 1 MB buffers for
//!    500+ Mbps throughput.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;

use super::config;
use super::error::{NetBridgeError, Result};
use super::types::{FiveTuple, IpProtocol, ReplyPacket, SessionId};

// =============================================================================
// Connection Handler (Control Plane Interface)
// =============================================================================

/// Information about an incoming connection
///
/// This is passed to the control plane when a new connection is detected.
/// The control plane uses this information to make routing decisions.
#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    /// Unique session identifier
    pub session_id: SessionId,
    /// Source address (client)
    pub src: SocketAddr,
    /// Destination address (target)
    pub dst: SocketAddr,
    /// Protocol (TCP or UDP)
    pub protocol: IpProtocol,
    /// WireGuard peer public key
    pub peer_key: [u8; 32],
    /// WireGuard peer endpoint
    pub peer_endpoint: SocketAddr,
    /// Domain name (if extracted from SNI/DNS)
    pub domain: Option<String>,
    /// Original 5-tuple
    pub five_tuple: FiveTuple,
}

/// Trait for outbound streams (TCP connections)
///
/// This abstracts the outbound connection, allowing the control plane
/// to provide any async stream (TcpStream, TLS stream, proxy stream, etc.).
pub trait OutboundStream: AsyncRead + AsyncWrite + Unpin + Send + 'static {}

// Blanket implementation for all qualifying types
impl<T> OutboundStream for T where T: AsyncRead + AsyncWrite + Unpin + Send + 'static {}

/// Handle for UDP session forwarding
///
/// The control plane provides this to handle UDP packet forwarding.
/// The data plane calls `send()` to forward packets and `recv()` to
/// get replies.
#[derive(Debug)]
pub struct UdpHandle {
    /// Sender for outgoing packets
    pub tx: mpsc::Sender<Bytes>,
    /// Receiver for incoming replies
    pub rx: mpsc::Receiver<Bytes>,
}

impl UdpHandle {
    /// Create a new UDP handle with the given channel capacity
    pub fn new(capacity: usize) -> (Self, UdpHandleRemote) {
        let (tx_out, rx_out) = mpsc::channel(capacity);
        let (tx_in, rx_in) = mpsc::channel(capacity);

        let handle = Self { tx: tx_out, rx: rx_in };
        let remote = UdpHandleRemote { tx: tx_in, rx: rx_out };

        (handle, remote)
    }
}

/// Remote end of a UDP handle (held by the outbound implementation)
#[derive(Debug)]
pub struct UdpHandleRemote {
    /// Sender for reply packets
    pub tx: mpsc::Sender<Bytes>,
    /// Receiver for outgoing packets
    pub rx: mpsc::Receiver<Bytes>,
}

/// Routing decision from the control plane
pub enum RoutingDecision {
    /// Accept the connection with the given outbound stream
    Accept(Box<dyn OutboundStream>),
    /// Accept UDP session with the given handle
    AcceptUdp(UdpHandle),
    /// Reject the connection
    Reject,
    /// Reject with a specific error message
    RejectWithError(String),
}

impl std::fmt::Debug for RoutingDecision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Accept(_) => f.debug_tuple("Accept").field(&"<stream>").finish(),
            Self::AcceptUdp(handle) => f.debug_tuple("AcceptUdp").field(handle).finish(),
            Self::Reject => write!(f, "Reject"),
            Self::RejectWithError(msg) => f.debug_tuple("RejectWithError").field(msg).finish(),
        }
    }
}

/// Control plane callback trait
///
/// Implement this trait to handle routing decisions. The data plane
/// calls these methods when new connections are detected.
///
/// # Thread Safety
///
/// Implementations must be `Send + Sync` as callbacks may be called
/// from multiple tasks concurrently.
///
/// # Example
///
/// ```ignore
/// struct DirectRouter;
///
/// impl ConnectionHandler for DirectRouter {
///     async fn on_tcp_connect(&self, info: ConnectionInfo) -> RoutingDecision {
///         match TcpStream::connect(info.dst).await {
///             Ok(stream) => RoutingDecision::Accept(Box::new(stream)),
///             Err(e) => RoutingDecision::RejectWithError(e.to_string()),
///         }
///     }
///
///     async fn on_udp_session(&self, info: ConnectionInfo) -> RoutingDecision {
///         // ... handle UDP
///     }
/// }
/// ```
pub trait ConnectionHandler: Send + Sync {
    /// Called when a new TCP connection is detected
    ///
    /// The control plane should:
    /// 1. Decide whether to accept or reject the connection
    /// 2. If accepting, establish the outbound connection
    /// 3. Return the outbound stream wrapped in `RoutingDecision::Accept`
    ///
    /// # Arguments
    ///
    /// * `info` - Information about the incoming connection
    ///
    /// # Returns
    ///
    /// A routing decision indicating how to handle the connection.
    fn on_tcp_connect(
        &self,
        info: ConnectionInfo,
    ) -> Pin<Box<dyn Future<Output = RoutingDecision> + Send + '_>>;

    /// Called when a new UDP session is detected
    ///
    /// Similar to `on_tcp_connect`, but for UDP traffic.
    ///
    /// # Arguments
    ///
    /// * `info` - Information about the UDP session
    ///
    /// # Returns
    ///
    /// A routing decision with a `UdpHandle` if accepting.
    fn on_udp_session(
        &self,
        info: ConnectionInfo,
    ) -> Pin<Box<dyn Future<Output = RoutingDecision> + Send + '_>>;

    /// Called when a session is closed
    ///
    /// This is informational only; no action is required.
    ///
    /// # Arguments
    ///
    /// * `session_id` - The closed session
    /// * `bytes_sent` - Total bytes sent
    /// * `bytes_received` - Total bytes received
    /// * `duration` - Session duration
    fn on_session_closed(
        &self,
        _session_id: SessionId,
        _bytes_sent: u64,
        _bytes_received: u64,
        _duration: Duration,
    ) {
        // Default: no-op
    }

    /// Called when domain information becomes available
    ///
    /// This happens after SNI extraction or DNS lookup completes.
    /// The control plane can use this to update routing if needed.
    fn on_domain_resolved(&self, _session_id: SessionId, _domain: &str) {
        // Default: no-op
    }
}

// =============================================================================
// Data Plane Configuration
// =============================================================================

/// Data plane configuration
#[derive(Debug, Clone)]
pub struct DataPlaneConfig {
    /// TUN device name
    pub tun_name: String,
    /// TUN device MTU
    pub tun_mtu: usize,
    /// TUN device IP address (CIDR)
    pub tun_cidr: String,
    /// TPROXY listener port
    pub tproxy_port: u16,
    /// Firewall mark for routing
    pub fwmark: u32,
    /// TCP receive buffer size
    pub tcp_rx_buffer: usize,
    /// TCP transmit buffer size
    pub tcp_tx_buffer: usize,
    /// UDP receive buffer size
    pub udp_rx_buffer: usize,
    /// UDP transmit buffer size
    pub udp_tx_buffer: usize,
    /// Maximum sessions per peer
    pub max_sessions_per_peer: usize,
    /// Maximum total sessions
    pub max_total_sessions: usize,
    /// Reply channel capacity
    pub reply_channel_size: usize,
    /// Enable SNI extraction
    pub enable_sni_extraction: bool,
    /// SNI peek timeout
    pub sni_peek_timeout: Duration,
}

impl Default for DataPlaneConfig {
    fn default() -> Self {
        Self {
            tun_name: "tun-netbridge".to_string(),
            tun_mtu: config::TUN_MTU,
            tun_cidr: "10.25.0.1/24".to_string(),
            tproxy_port: 7893,
            fwmark: 0x1,
            tcp_rx_buffer: config::TCP_RX_BUFFER,
            tcp_tx_buffer: config::TCP_TX_BUFFER,
            udp_rx_buffer: config::UDP_RX_BUFFER,
            udp_tx_buffer: config::UDP_TX_BUFFER,
            max_sessions_per_peer: config::MAX_SESSIONS_PER_PEER,
            max_total_sessions: config::MAX_TOTAL_SESSIONS,
            reply_channel_size: config::REPLY_CHANNEL_SIZE,
            enable_sni_extraction: true,
            sni_peek_timeout: config::sni_peek_timeout(),
        }
    }
}

// =============================================================================
// Data Plane Builder
// =============================================================================

/// Builder for creating a data plane instance
///
/// # Example
///
/// ```ignore
/// let dp = DataPlaneBuilder::new()
///     .with_tun("my-tun")
///     .with_tproxy_port(7893)
///     .with_handler(Arc::new(MyHandler))
///     .build()
///     .await?;
/// ```
pub struct DataPlaneBuilder<H = ()> {
    config: DataPlaneConfig,
    handler: Option<Arc<H>>,
}

impl DataPlaneBuilder<()> {
    /// Create a new builder with default configuration
    pub fn new() -> DataPlaneBuilder<()> {
        DataPlaneBuilder {
            config: DataPlaneConfig::default(),
            handler: None,
        }
    }
}

impl Default for DataPlaneBuilder<()> {
    fn default() -> Self {
        Self::new()
    }
}

impl<H> DataPlaneBuilder<H> {
    /// Set the TUN device name
    pub fn with_tun(mut self, name: impl Into<String>) -> Self {
        self.config.tun_name = name.into();
        self
    }

    /// Set the TUN device CIDR
    pub fn with_tun_cidr(mut self, cidr: impl Into<String>) -> Self {
        self.config.tun_cidr = cidr.into();
        self
    }

    /// Set the TPROXY listener port
    pub fn with_tproxy_port(mut self, port: u16) -> Self {
        self.config.tproxy_port = port;
        self
    }

    /// Set the firewall mark
    pub fn with_fwmark(mut self, mark: u32) -> Self {
        self.config.fwmark = mark;
        self
    }

    /// Set TCP buffer sizes
    pub fn with_tcp_buffers(mut self, rx: usize, tx: usize) -> Self {
        self.config.tcp_rx_buffer = rx;
        self.config.tcp_tx_buffer = tx;
        self
    }

    /// Set UDP buffer sizes
    pub fn with_udp_buffers(mut self, rx: usize, tx: usize) -> Self {
        self.config.udp_rx_buffer = rx;
        self.config.udp_tx_buffer = tx;
        self
    }

    /// Set session limits
    pub fn with_session_limits(mut self, per_peer: usize, total: usize) -> Self {
        self.config.max_sessions_per_peer = per_peer;
        self.config.max_total_sessions = total;
        self
    }

    /// Enable or disable SNI extraction
    pub fn with_sni_extraction(mut self, enabled: bool) -> Self {
        self.config.enable_sni_extraction = enabled;
        self
    }

    /// Set the full configuration
    pub fn with_config(mut self, config: DataPlaneConfig) -> Self {
        self.config = config;
        self
    }

    /// Set the connection handler
    pub fn with_handler<H2: ConnectionHandler>(
        self,
        handler: Arc<H2>,
    ) -> DataPlaneBuilder<H2> {
        DataPlaneBuilder {
            config: self.config,
            handler: Some(handler),
        }
    }
}

impl<H: ConnectionHandler + 'static> DataPlaneBuilder<H> {
    /// Build the data plane instance
    ///
    /// This creates the TUN device, sets up iptables rules, and
    /// initializes the TPROXY listener.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - TUN device creation fails
    /// - iptables rule setup fails
    /// - TPROXY listener binding fails
    /// - No handler is set
    pub async fn build(self) -> Result<DataPlane<H>> {
        let handler = self.handler.ok_or(NetBridgeError::NotInitialized)?;

        DataPlane::new(self.config, handler).await
    }
}

// =============================================================================
// Data Plane
// =============================================================================

/// Standalone data plane instance
///
/// This is the main entry point for using netbridge as an independent
/// data plane. It handles:
///
/// - TUN device management
/// - TPROXY listener for transparent proxying
/// - Session tracking
/// - Packet forwarding
///
/// Routing decisions are delegated to the `ConnectionHandler`.
pub struct DataPlane<H: ConnectionHandler> {
    /// Configuration
    config: DataPlaneConfig,
    /// Connection handler (control plane)
    handler: Arc<H>,
    /// Reply packet receiver
    reply_rx: Option<mpsc::Receiver<ReplyPacket>>,
    /// Reply packet sender (internal)
    reply_tx: mpsc::Sender<ReplyPacket>,
    /// Shutdown signal
    shutdown_tx: Option<mpsc::Sender<()>>,
    /// Running flag
    running: std::sync::atomic::AtomicBool,
}

impl<H: ConnectionHandler + 'static> DataPlane<H> {
    /// Create a new data plane instance
    async fn new(config: DataPlaneConfig, handler: Arc<H>) -> Result<Self> {
        let (reply_tx, reply_rx) = mpsc::channel(config.reply_channel_size);
        let (shutdown_tx, _shutdown_rx) = mpsc::channel(1);

        Ok(Self {
            config,
            handler,
            reply_rx: Some(reply_rx),
            reply_tx,
            shutdown_tx: Some(shutdown_tx),
            running: std::sync::atomic::AtomicBool::new(false),
        })
    }

    /// Get the configuration
    pub fn config(&self) -> &DataPlaneConfig {
        &self.config
    }

    /// Get the connection handler
    pub fn handler(&self) -> &Arc<H> {
        &self.handler
    }

    /// Take the reply receiver
    ///
    /// This should be called once before running the data plane.
    /// The receiver produces `ReplyPacket` values to send to WireGuard.
    pub fn take_reply_rx(&mut self) -> Option<mpsc::Receiver<ReplyPacket>> {
        self.reply_rx.take()
    }

    /// Inject an IP packet from WireGuard
    ///
    /// The packet is processed and forwarded according to the
    /// connection handler's routing decision.
    ///
    /// # Arguments
    ///
    /// * `packet` - Raw IP packet data
    /// * `peer_key` - WireGuard peer public key
    /// * `peer_endpoint` - Peer's endpoint for reply routing
    pub async fn inject_packet(
        &self,
        _packet: &[u8],
        _peer_key: [u8; 32],
        _peer_endpoint: SocketAddr,
    ) -> Result<()> {
        // TODO: Implement packet injection
        // 1. Parse IP packet to get 5-tuple
        // 2. Look up or create session
        // 3. Write packet to TUN device
        Ok(())
    }

    /// Run the data plane
    ///
    /// This starts all processing loops:
    /// - TUN read loop
    /// - TPROXY accept loop
    /// - Reply routing
    ///
    /// The function returns when `shutdown()` is called or an error occurs.
    pub async fn run(&self) -> Result<()> {
        use std::sync::atomic::Ordering;
        self.running.store(true, Ordering::SeqCst);

        // TODO: Implement full run loop
        // 1. Initialize TUN device
        // 2. Set up iptables rules
        // 3. Start TPROXY listener
        // 4. Run accept loop with ConnectionHandler callbacks

        Ok(())
    }

    /// Shutdown the data plane
    pub async fn shutdown(&self) {
        use std::sync::atomic::Ordering;
        self.running.store(false, Ordering::SeqCst);
        // Signal shutdown to all tasks
        if let Some(ref tx) = self.shutdown_tx {
            let _ = tx.send(()).await;
        }
    }

    /// Check if the data plane is running
    pub fn is_running(&self) -> bool {
        use std::sync::atomic::Ordering;
        self.running.load(Ordering::SeqCst)
    }
}

// =============================================================================
// Simple Handlers (for testing and simple use cases)
// =============================================================================

/// A simple direct connection handler
///
/// This handler connects directly to the destination without any
/// routing logic. Useful for testing or simple setups.
///
/// # Example
///
/// ```ignore
/// let dp = DataPlaneBuilder::new()
///     .with_handler(Arc::new(DirectHandler::new()))
///     .build()
///     .await?;
/// ```
pub struct DirectHandler {
    /// Connection timeout
    pub connect_timeout: Duration,
}

impl DirectHandler {
    /// Create a new direct handler with default settings
    pub fn new() -> Self {
        Self {
            connect_timeout: Duration::from_secs(10),
        }
    }

    /// Create with a custom timeout
    pub fn with_timeout(timeout: Duration) -> Self {
        Self {
            connect_timeout: timeout,
        }
    }
}

impl Default for DirectHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectionHandler for DirectHandler {
    fn on_tcp_connect(
        &self,
        info: ConnectionInfo,
    ) -> Pin<Box<dyn Future<Output = RoutingDecision> + Send + '_>> {
        let timeout = self.connect_timeout;
        Box::pin(async move {
            use tokio::net::TcpStream;
            use tokio::time::timeout as tokio_timeout;

            match tokio_timeout(timeout, TcpStream::connect(info.dst)).await {
                Ok(Ok(stream)) => RoutingDecision::Accept(Box::new(stream)),
                Ok(Err(e)) => RoutingDecision::RejectWithError(format!("connect failed: {e}")),
                Err(_) => RoutingDecision::RejectWithError("connect timeout".to_string()),
            }
        })
    }

    fn on_udp_session(
        &self,
        info: ConnectionInfo,
    ) -> Pin<Box<dyn Future<Output = RoutingDecision> + Send + '_>> {
        Box::pin(async move {
            use tokio::net::UdpSocket;

            // Create a UDP socket and connect to destination
            let socket = match UdpSocket::bind("0.0.0.0:0").await {
                Ok(s) => s,
                Err(e) => return RoutingDecision::RejectWithError(format!("bind failed: {e}")),
            };

            if let Err(e) = socket.connect(info.dst).await {
                return RoutingDecision::RejectWithError(format!("connect failed: {e}"));
            }

            // Create handle pair
            let (handle, remote) = UdpHandle::new(64);

            // Spawn forwarding task
            tokio::spawn(async move {
                let mut remote = remote;
                let mut buf = vec![0u8; 65536];

                loop {
                    tokio::select! {
                        // Forward outgoing packets
                        Some(data) = remote.rx.recv() => {
                            let _ = socket.send(&data).await;
                        }
                        // Receive replies
                        result = socket.recv(&mut buf) => {
                            match result {
                                Ok(n) => {
                                    let _ = remote.tx.send(Bytes::copy_from_slice(&buf[..n])).await;
                                }
                                Err(_) => break,
                            }
                        }
                    }
                }
            });

            RoutingDecision::AcceptUdp(handle)
        })
    }
}

/// A rejecting handler that refuses all connections
///
/// Useful for testing or when you want to selectively handle
/// connections in a wrapper handler.
#[derive(Debug, Default, Clone, Copy)]
pub struct RejectHandler;

impl ConnectionHandler for RejectHandler {
    fn on_tcp_connect(
        &self,
        _info: ConnectionInfo,
    ) -> Pin<Box<dyn Future<Output = RoutingDecision> + Send + '_>> {
        Box::pin(async { RoutingDecision::Reject })
    }

    fn on_udp_session(
        &self,
        _info: ConnectionInfo,
    ) -> Pin<Box<dyn Future<Output = RoutingDecision> + Send + '_>> {
        Box::pin(async { RoutingDecision::Reject })
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_config_default() {
        let config = DataPlaneConfig::default();
        assert_eq!(config.tun_name, "tun-netbridge");
        assert_eq!(config.tproxy_port, 7893);
        assert_eq!(config.tcp_rx_buffer, config::TCP_RX_BUFFER);
    }

    #[test]
    fn test_builder() {
        let builder = DataPlaneBuilder::new()
            .with_tun("test-tun")
            .with_tproxy_port(8000)
            .with_fwmark(0x2);

        assert_eq!(builder.config.tun_name, "test-tun");
        assert_eq!(builder.config.tproxy_port, 8000);
        assert_eq!(builder.config.fwmark, 0x2);
    }

    #[test]
    fn test_connection_info() {
        let info = ConnectionInfo {
            session_id: SessionId::new(1),
            src: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 12345),
            dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 443),
            protocol: IpProtocol::Tcp,
            peer_key: [0u8; 32],
            peer_endpoint: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 51820),
            domain: Some("example.com".to_string()),
            five_tuple: FiveTuple::tcp(
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 12345),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 443),
            ),
        };

        assert_eq!(info.protocol, IpProtocol::Tcp);
        assert_eq!(info.domain, Some("example.com".to_string()));
    }

    #[test]
    fn test_udp_handle() {
        let (handle, remote) = UdpHandle::new(16);
        assert!(handle.tx.capacity() >= 16);
        assert!(remote.rx.capacity() >= 16);
    }

    #[tokio::test]
    async fn test_reject_handler() {
        let handler = RejectHandler;
        let info = ConnectionInfo {
            session_id: SessionId::new(1),
            src: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345),
            dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 80),
            protocol: IpProtocol::Tcp,
            peer_key: [0u8; 32],
            peer_endpoint: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 51820),
            domain: None,
            five_tuple: FiveTuple::tcp(
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 80),
            ),
        };

        let decision = handler.on_tcp_connect(info).await;
        assert!(matches!(decision, RoutingDecision::Reject));
    }

    #[test]
    fn test_direct_handler_default() {
        let handler = DirectHandler::default();
        assert_eq!(handler.connect_timeout, Duration::from_secs(10));
    }
}
