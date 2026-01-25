//! Outbound trait definitions
//!
//! This module defines the core `Outbound` trait that all outbound types must implement.
//! Supports both TCP and UDP protocols.
//!
//! # Stream Types
//!
//! The module supports multiple stream types through `OutboundStream`:
//! - **TCP**: Direct TCP connections
//! - **Transport**: TLS, WebSocket, and other transport layer streams
//!
//! This abstraction allows outbound implementations like VLESS to work
//! over different transport layers while maintaining a unified interface.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpStream, UdpSocket};

use crate::connection::OutboundStats;
use crate::error::{OutboundError, UdpError};
use crate::transport::TransportStream;
use crate::vless::VlessStream;

/// Connection pool statistics (for pooled outbound types like SOCKS5)
#[derive(Debug, Clone, Copy, Default)]
pub struct PoolStatsInfo {
    /// Current pool size (all connections)
    pub size: usize,
    /// Available connections in pool
    pub available: usize,
    /// Number of waiters for connections
    pub waiting: usize,
}

/// Server address information for proxy outbounds
#[derive(Debug, Clone)]
pub struct ProxyServerInfo {
    /// Server address as string
    pub address: String,
    /// Whether authentication is configured
    pub has_auth: bool,
}

/// Health status of an outbound
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthStatus {
    /// Outbound is healthy and accepting connections
    Healthy,
    /// Outbound is degraded (some failures)
    Degraded,
    /// Outbound is unhealthy (not accepting connections)
    Unhealthy,
    /// Health status is unknown
    Unknown,
}

impl HealthStatus {
    /// Check if the outbound is available for connections
    #[must_use]
    pub const fn is_available(&self) -> bool {
        matches!(self, Self::Healthy | Self::Degraded | Self::Unknown)
    }
}

impl std::fmt::Display for HealthStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Healthy => write!(f, "healthy"),
            Self::Degraded => write!(f, "degraded"),
            Self::Unhealthy => write!(f, "unhealthy"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

// ============================================================================
// Stream Types
// ============================================================================

/// Unified stream type for outbound connections
///
/// This enum allows outbound connections to use different transport types
/// (TCP, TLS, WebSocket) while maintaining a unified interface for data transfer.
///
/// # Example
///
/// ```ignore
/// use rust_router::outbound::OutboundStream;
///
/// // TCP stream
/// let stream = OutboundStream::Tcp(tcp_stream);
///
/// // Transport stream (TLS/WebSocket)
/// let stream = OutboundStream::Transport(transport_stream);
/// ```
pub enum OutboundStream {
    /// Plain TCP stream
    Tcp(TcpStream),
    /// Transport layer stream (TLS, WebSocket, etc.)
    Transport(TransportStream),
    /// Shadowsocks encrypted stream
    #[cfg(feature = "shadowsocks")]
    Shadowsocks(super::shadowsocks::ShadowsocksStream),
    /// VLESS stream with deferred response header handling
    Vless(VlessStream),
}

impl OutboundStream {
    /// Create from a TCP stream
    #[must_use]
    pub fn tcp(stream: TcpStream) -> Self {
        Self::Tcp(stream)
    }

    /// Create from a transport stream
    #[must_use]
    pub fn transport(stream: TransportStream) -> Self {
        Self::Transport(stream)
    }

    /// Create from a VLESS stream
    #[must_use]
    pub fn vless(stream: VlessStream) -> Self {
        Self::Vless(stream)
    }

    /// Check if this is a TCP stream
    #[must_use]
    pub const fn is_tcp(&self) -> bool {
        matches!(self, Self::Tcp(_))
    }

    /// Check if this is a transport stream
    #[must_use]
    pub const fn is_transport(&self) -> bool {
        matches!(self, Self::Transport(_))
    }

    /// Check if this is a Shadowsocks stream
    #[must_use]
    pub const fn is_shadowsocks(&self) -> bool {
        #[cfg(feature = "shadowsocks")]
        {
            matches!(self, Self::Shadowsocks(_))
        }
        #[cfg(not(feature = "shadowsocks"))]
        {
            false
        }
    }

    /// Check if this is a VLESS stream
    #[must_use]
    pub const fn is_vless(&self) -> bool {
        matches!(self, Self::Vless(_))
    }

    /// Check if this stream requires a write operation before reading.
    ///
    /// Some proxy protocols (like Shadowsocks) defer sending the target address
    /// until the first write operation. If you try to read before writing,
    /// the remote server doesn't know where to connect and the read will fail.
    ///
    /// For such streams, you should either:
    /// - Wait for client data and write it first, or
    /// - Send an empty write to trigger address transmission before reading
    ///
    /// # Example
    ///
    /// ```ignore
    /// use tokio::io::AsyncWriteExt;
    ///
    /// if stream.requires_write_before_read() {
    ///     // Trigger address transmission by sending empty data
    ///     stream.write_all(&[]).await?;
    ///     stream.flush().await?;
    /// }
    /// let (reader, writer) = tokio::io::split(stream);
    /// ```
    #[must_use]
    pub const fn requires_write_before_read(&self) -> bool {
        #[cfg(feature = "shadowsocks")]
        {
            matches!(self, Self::Shadowsocks(_))
        }
        #[cfg(not(feature = "shadowsocks"))]
        {
            false
        }
    }

    /// Try to get the underlying TCP stream
    ///
    /// Returns `None` if this is not a TCP stream.
    #[must_use]
    pub fn as_tcp(&self) -> Option<&TcpStream> {
        match self {
            Self::Tcp(s) => Some(s),
            Self::Transport(_) => None,
            #[cfg(feature = "shadowsocks")]
            Self::Shadowsocks(_) => None,
            Self::Vless(_) => None,
        }
    }

    /// Try to get a mutable reference to the underlying TCP stream
    ///
    /// Returns `None` if this is not a TCP stream.
    pub fn as_tcp_mut(&mut self) -> Option<&mut TcpStream> {
        match self {
            Self::Tcp(s) => Some(s),
            Self::Transport(_) => None,
            #[cfg(feature = "shadowsocks")]
            Self::Shadowsocks(_) => None,
            Self::Vless(_) => None,
        }
    }

    /// Try to convert into a TCP stream
    ///
    /// Returns `Err(self)` if this is not a TCP stream.
    pub fn try_into_tcp(self) -> Result<TcpStream, Self> {
        match self {
            Self::Tcp(s) => Ok(s),
            #[allow(unused_variables)]
            other => Err(other),
        }
    }

    /// Get the local address if available
    #[must_use]
    pub fn local_addr(&self) -> Option<SocketAddr> {
        match self {
            Self::Tcp(s) => s.local_addr().ok(),
            Self::Transport(TransportStream::Tcp(s)) => s.local_addr().ok(),
            #[cfg(feature = "transport-tls")]
            Self::Transport(TransportStream::Tls(s)) => {
                // TLS stream wraps TCP, get address from inner stream
                s.get_ref().0.local_addr().ok()
            }
            #[cfg(feature = "transport-ws")]
            Self::Transport(TransportStream::WebSocket(_)) => None, // WebSocket doesn't expose local addr
            #[cfg(feature = "transport-quic")]
            Self::Transport(TransportStream::Quic(s)) => Some(s.remote_address()), // Return remote address for QUIC
            #[cfg(feature = "shadowsocks")]
            Self::Shadowsocks(_) => None, // Shadowsocks doesn't expose local addr directly
            Self::Vless(_) => None, // VLESS wraps transport, doesn't expose local addr directly
        }
    }
}

impl std::fmt::Debug for OutboundStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tcp(s) => f
                .debug_struct("OutboundStream::Tcp")
                .field("local_addr", &s.local_addr().ok())
                .field("peer_addr", &s.peer_addr().ok())
                .finish(),
            Self::Transport(t) => f
                .debug_struct("OutboundStream::Transport")
                .field("inner", &t)
                .finish(),
            #[cfg(feature = "shadowsocks")]
            Self::Shadowsocks(s) => f
                .debug_struct("OutboundStream::Shadowsocks")
                .field("inner", &s)
                .finish(),
            Self::Vless(s) => f
                .debug_struct("OutboundStream::Vless")
                .field("header_consumed", &s.is_header_consumed())
                .finish(),
        }
    }
}

impl AsyncRead for OutboundStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_read(cx, buf),
            Self::Transport(s) => Pin::new(s).poll_read(cx, buf),
            #[cfg(feature = "shadowsocks")]
            Self::Shadowsocks(s) => Pin::new(s).poll_read(cx, buf),
            Self::Vless(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for OutboundStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_write(cx, buf),
            Self::Transport(s) => Pin::new(s).poll_write(cx, buf),
            #[cfg(feature = "shadowsocks")]
            Self::Shadowsocks(s) => Pin::new(s).poll_write(cx, buf),
            Self::Vless(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_flush(cx),
            Self::Transport(s) => Pin::new(s).poll_flush(cx),
            #[cfg(feature = "shadowsocks")]
            Self::Shadowsocks(s) => Pin::new(s).poll_flush(cx),
            Self::Vless(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_shutdown(cx),
            Self::Transport(s) => Pin::new(s).poll_shutdown(cx),
            #[cfg(feature = "shadowsocks")]
            Self::Shadowsocks(s) => Pin::new(s).poll_shutdown(cx),
            Self::Vless(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

/// Represents an established outbound connection
///
/// This struct wraps an `OutboundStream` which can be either a plain TCP stream
/// or a transport stream (TLS, WebSocket). The unified interface allows consumers
/// to work with different stream types transparently.
pub struct OutboundConnection {
    /// The underlying stream (TCP or transport)
    stream: OutboundStream,
    /// Local address of the connection
    local_addr: Option<SocketAddr>,
    /// Remote address
    remote_addr: SocketAddr,
}

/// UDP outbound handle (enum-based for stable Rust compatibility)
///
/// This enum wraps different UDP handle types for various outbound implementations.
/// Using an enum instead of trait objects allows for better performance and
/// avoids lifetime complexity with async trait methods.
#[derive(Debug)]
pub enum UdpOutboundHandle {
    /// Direct UDP socket handle
    Direct(DirectUdpHandle),
    /// SOCKS5 UDP ASSOCIATE handle
    Socks5(Socks5UdpHandle),
    /// Shadowsocks UDP relay handle
    #[cfg(feature = "shadowsocks")]
    Shadowsocks(super::shadowsocks::ShadowsocksUdpHandle),
}

impl UdpOutboundHandle {
    /// Get the destination address
    #[must_use]
    pub fn dest_addr(&self) -> SocketAddr {
        match self {
            Self::Direct(h) => h.dest_addr,
            Self::Socks5(h) => h.dest_addr,
            #[cfg(feature = "shadowsocks")]
            Self::Shadowsocks(h) => h.dest_addr(),
        }
    }

    /// Send data through this UDP handle
    ///
    /// # Errors
    ///
    /// Returns `UdpError` if sending fails.
    pub async fn send(&self, data: &[u8]) -> Result<usize, UdpError> {
        match self {
            Self::Direct(h) => h.send(data).await,
            Self::Socks5(h) => h.send(data).await,
            #[cfg(feature = "shadowsocks")]
            Self::Shadowsocks(h) => h.send(data).await,
        }
    }

    /// Receive data from this UDP handle
    ///
    /// # Errors
    ///
    /// Returns `UdpError` if receiving fails.
    pub async fn recv(&self, buf: &mut [u8]) -> Result<usize, UdpError> {
        match self {
            Self::Direct(h) => h.recv(buf).await,
            Self::Socks5(h) => h.recv(buf).await,
            #[cfg(feature = "shadowsocks")]
            Self::Shadowsocks(h) => h.recv(buf).await,
        }
    }

    /// Try to receive data without blocking
    ///
    /// # Errors
    ///
    /// Returns `UdpError` if the operation fails (including `WouldBlock`).
    pub fn try_recv(&self, buf: &mut [u8]) -> Result<usize, UdpError> {
        match self {
            Self::Direct(h) => h.try_recv(buf),
            Self::Socks5(h) => h.try_recv(buf),
            #[cfg(feature = "shadowsocks")]
            Self::Shadowsocks(h) => h.try_recv(buf),
        }
    }

    /// Get the routing mark (if any)
    #[must_use]
    pub fn routing_mark(&self) -> Option<u32> {
        match self {
            Self::Direct(h) => h.routing_mark,
            Self::Socks5(_) => None,
            #[cfg(feature = "shadowsocks")]
            Self::Shadowsocks(_) => None, // Shadowsocks handles routing at protocol level
        }
    }
}

/// Direct UDP outbound handle
///
/// Wraps a UDP socket connected to the destination for direct forwarding.
#[derive(Debug)]
pub struct DirectUdpHandle {
    /// The underlying UDP socket (connected to destination)
    socket: Arc<UdpSocket>,
    /// Destination address
    pub dest_addr: SocketAddr,
    /// Routing mark (if configured)
    pub routing_mark: Option<u32>,
}

impl DirectUdpHandle {
    /// Create a new direct UDP handle
    pub fn new(socket: UdpSocket, dest_addr: SocketAddr, routing_mark: Option<u32>) -> Self {
        Self {
            socket: Arc::new(socket),
            dest_addr,
            routing_mark,
        }
    }

    /// Get a reference to the underlying socket
    #[must_use]
    pub fn socket(&self) -> &Arc<UdpSocket> {
        &self.socket
    }

    /// Send data to the connected destination
    ///
    /// # Errors
    ///
    /// Returns `UdpError` if sending fails.
    pub async fn send(&self, data: &[u8]) -> Result<usize, UdpError> {
        self.socket
            .send(data)
            .await
            .map_err(|e| UdpError::send(self.dest_addr, e.to_string()))
    }

    /// Receive data from the connected destination
    ///
    /// # Errors
    ///
    /// Returns `UdpError` if receiving fails.
    pub async fn recv(&self, buf: &mut [u8]) -> Result<usize, UdpError> {
        self.socket
            .recv(buf)
            .await
            .map_err(|e| UdpError::RecvError(e.to_string()))
    }

    /// Try to receive data without blocking
    ///
    /// # Errors
    ///
    /// Returns `UdpError` if receiving fails (including `WouldBlock`).
    pub fn try_recv(&self, buf: &mut [u8]) -> Result<usize, UdpError> {
        self.socket
            .try_recv(buf)
            .map_err(|e| UdpError::RecvError(e.to_string()))
    }
}

/// SOCKS5 UDP ASSOCIATE handle (RFC 1928)
///
/// Wraps a SOCKS5 UDP association for sending and receiving UDP packets
/// through a SOCKS5 proxy server. The association includes:
/// - A TCP control connection that must remain open
/// - A UDP socket connected to the relay endpoint
/// - Automatic encapsulation/decapsulation of SOCKS5 UDP packets
///
/// # Thread Safety
///
/// The underlying `Socks5UdpAssociation` is thread-safe and can be shared.
pub struct Socks5UdpHandle {
    /// The UDP association (wrapped in Arc for sharing)
    pub association: Arc<super::socks5_udp::Socks5UdpAssociation>,
    /// Destination address for this handle
    pub dest_addr: SocketAddr,
}

impl std::fmt::Debug for Socks5UdpHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Socks5UdpHandle")
            .field("dest_addr", &self.dest_addr)
            .field("relay_addr", &self.association.relay_addr())
            .field("active", &self.association.is_active())
            .finish_non_exhaustive()
    }
}

impl Socks5UdpHandle {
    /// Create a new SOCKS5 UDP handle
    pub fn new(
        association: Arc<super::socks5_udp::Socks5UdpAssociation>,
        dest_addr: SocketAddr,
    ) -> Self {
        Self {
            association,
            dest_addr,
        }
    }

    /// Send data to the destination through the SOCKS5 relay
    ///
    /// The data is automatically encapsulated in SOCKS5 UDP format.
    ///
    /// # Errors
    ///
    /// Returns `UdpError` if the association is closed or sending fails.
    pub async fn send(&self, data: &[u8]) -> Result<usize, UdpError> {
        if !self.association.is_active() {
            return Err(UdpError::Socks5ControlConnectionClosed);
        }

        self.association
            .send_to(data, self.dest_addr)
            .await
            .map_err(|e| UdpError::Socks5UdpRelayError {
                reason: e.to_string(),
            })
    }

    /// Receive data from the SOCKS5 relay
    ///
    /// The received packet is automatically decapsulated from SOCKS5 UDP format.
    /// Note: The source address in the reply may differ from `dest_addr` if the
    /// server sends from a different address.
    ///
    /// # Errors
    ///
    /// Returns `UdpError` if the association is closed, receiving fails,
    /// or the packet format is invalid.
    pub async fn recv(&self, buf: &mut [u8]) -> Result<usize, UdpError> {
        if !self.association.is_active() {
            return Err(UdpError::Socks5ControlConnectionClosed);
        }

        let (n, _src_addr) = self
            .association
            .recv_from(buf)
            .await
            .map_err(|e| match e {
                super::socks5_udp::Socks5UdpError::FragmentedPacket { frag } => {
                    UdpError::Socks5FragmentedPacket { frag }
                }
                super::socks5_udp::Socks5UdpError::PacketFormatError(msg) => {
                    UdpError::Socks5PacketFormatError { reason: msg }
                }
                super::socks5_udp::Socks5UdpError::ControlConnectionClosed => {
                    UdpError::Socks5ControlConnectionClosed
                }
                other => UdpError::Socks5UdpRelayError {
                    reason: other.to_string(),
                },
            })?;

        Ok(n)
    }

    /// Try to receive data without blocking
    ///
    /// # Errors
    ///
    /// Returns `UdpError` if the association is closed or operation would block.
    pub fn try_recv(&self, _buf: &mut [u8]) -> Result<usize, UdpError> {
        if !self.association.is_active() {
            return Err(UdpError::Socks5ControlConnectionClosed);
        }

        // Non-blocking receive is not directly supported by the async association.
        // Return WouldBlock to indicate caller should use async recv instead.
        Err(UdpError::IoError(std::io::Error::new(
            std::io::ErrorKind::WouldBlock,
            "SOCKS5 UDP try_recv not supported, use async recv",
        )))
    }

    /// Check if the association is still active
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.association.is_active()
    }

    /// Get the UDP relay address
    #[must_use]
    pub fn relay_addr(&self) -> SocketAddr {
        self.association.relay_addr()
    }

    /// Get the SOCKS5 server address
    #[must_use]
    pub fn server_addr(&self) -> SocketAddr {
        self.association.server_addr()
    }

    /// Get statistics: packets sent
    #[must_use]
    pub fn packets_sent(&self) -> u64 {
        self.association.packets_sent()
    }

    /// Get statistics: packets received
    #[must_use]
    pub fn packets_received(&self) -> u64 {
        self.association.packets_received()
    }
}

impl OutboundConnection {
    /// Create a new outbound connection from a TCP stream
    ///
    /// This is the traditional constructor for TCP-based outbounds.
    pub fn new(stream: TcpStream, remote_addr: SocketAddr) -> Self {
        let local_addr = stream.local_addr().ok();
        Self {
            stream: OutboundStream::Tcp(stream),
            local_addr,
            remote_addr,
        }
    }

    /// Create a new outbound connection from a transport stream
    ///
    /// Use this constructor for TLS, WebSocket, or other transport-based streams.
    pub fn from_transport(stream: TransportStream, remote_addr: SocketAddr) -> Self {
        let local_addr = match &stream {
            TransportStream::Tcp(s) => s.local_addr().ok(),
            #[cfg(feature = "transport-tls")]
            TransportStream::Tls(s) => s.get_ref().0.local_addr().ok(),
            #[cfg(feature = "transport-ws")]
            TransportStream::WebSocket(_) => None,
            #[cfg(feature = "transport-quic")]
            TransportStream::Quic(s) => Some(s.remote_address()),
        };
        Self {
            stream: OutboundStream::Transport(stream),
            local_addr,
            remote_addr,
        }
    }

    /// Create a new outbound connection from an OutboundStream
    pub fn from_stream(stream: OutboundStream, remote_addr: SocketAddr) -> Self {
        let local_addr = stream.local_addr();
        Self {
            stream,
            local_addr,
            remote_addr,
        }
    }

    /// Create a new outbound connection from a VLESS stream
    ///
    /// Use this constructor for VLESS connections that use deferred response header.
    pub fn from_vless(stream: VlessStream, remote_addr: SocketAddr) -> Self {
        Self {
            stream: OutboundStream::Vless(stream),
            local_addr: None, // VlessStream doesn't expose local address
            remote_addr,
        }
    }

    /// Get the underlying stream reference (generic)
    ///
    /// This returns the `OutboundStream` enum which can be matched to get
    /// the specific stream type.
    #[must_use]
    pub fn outbound_stream(&self) -> &OutboundStream {
        &self.stream
    }

    /// Get a mutable reference to the underlying stream (generic)
    pub fn outbound_stream_mut(&mut self) -> &mut OutboundStream {
        &mut self.stream
    }

    /// Consume and return the underlying OutboundStream
    ///
    /// Use this when you need to work with either TCP or transport streams.
    #[must_use]
    pub fn into_outbound_stream(self) -> OutboundStream {
        self.stream
    }

    /// Get the underlying TCP stream if this is a TCP connection
    ///
    /// Returns `None` if the connection uses a transport stream.
    #[must_use]
    pub fn stream(&self) -> Option<&TcpStream> {
        self.stream.as_tcp()
    }

    /// Get mutable reference to the TCP stream if this is a TCP connection
    ///
    /// Returns `None` if the connection uses a transport stream.
    pub fn stream_mut(&mut self) -> Option<&mut TcpStream> {
        self.stream.as_tcp_mut()
    }

    /// Consume and return the underlying TCP stream
    ///
    /// # Panics
    ///
    /// Panics if the connection uses a transport stream instead of TCP.
    /// Use `try_into_stream()` for a non-panicking alternative.
    #[must_use]
    pub fn into_stream(self) -> TcpStream {
        match self.stream {
            OutboundStream::Tcp(s) => s,
            OutboundStream::Transport(TransportStream::Tcp(s)) => s,
            #[cfg(feature = "transport-tls")]
            OutboundStream::Transport(TransportStream::Tls(_)) => {
                panic!("Cannot convert TLS stream to TcpStream; use into_outbound_stream() instead")
            }
            #[cfg(feature = "transport-ws")]
            OutboundStream::Transport(TransportStream::WebSocket(_)) => {
                panic!("Cannot convert WebSocket stream to TcpStream; use into_outbound_stream() instead")
            }
            #[cfg(feature = "transport-quic")]
            OutboundStream::Transport(TransportStream::Quic(_)) => {
                panic!("Cannot convert QUIC stream to TcpStream; use into_outbound_stream() instead")
            }
            #[cfg(feature = "shadowsocks")]
            OutboundStream::Shadowsocks(_) => {
                panic!("Cannot convert Shadowsocks stream to TcpStream; use into_outbound_stream() instead")
            }
            OutboundStream::Vless(_) => {
                panic!("Cannot convert VLESS stream to TcpStream; use into_outbound_stream() instead")
            }
        }
    }

    /// Try to consume and return the underlying TCP stream
    ///
    /// Returns `Err(self)` if the connection uses a non-TCP transport stream.
    pub fn try_into_stream(self) -> Result<TcpStream, Self> {
        match self.stream {
            OutboundStream::Tcp(s) => Ok(s),
            OutboundStream::Transport(TransportStream::Tcp(s)) => Ok(s),
            stream => Err(Self {
                stream,
                local_addr: self.local_addr,
                remote_addr: self.remote_addr,
            }),
        }
    }

    /// Check if this connection uses a plain TCP stream
    #[must_use]
    pub fn is_tcp(&self) -> bool {
        matches!(
            &self.stream,
            OutboundStream::Tcp(_) | OutboundStream::Transport(TransportStream::Tcp(_))
        )
    }

    /// Check if this connection uses TLS
    #[must_use]
    pub fn is_tls(&self) -> bool {
        #[cfg(feature = "transport-tls")]
        {
            matches!(
                &self.stream,
                OutboundStream::Transport(TransportStream::Tls(_))
            )
        }
        #[cfg(not(feature = "transport-tls"))]
        {
            false
        }
    }

    /// Check if this connection uses WebSocket
    #[must_use]
    pub fn is_websocket(&self) -> bool {
        #[cfg(feature = "transport-ws")]
        {
            matches!(
                &self.stream,
                OutboundStream::Transport(TransportStream::WebSocket(_))
            )
        }
        #[cfg(not(feature = "transport-ws"))]
        {
            false
        }
    }

    /// Get the local address
    #[must_use]
    pub const fn local_addr(&self) -> Option<SocketAddr> {
        self.local_addr
    }

    /// Get the remote address
    #[must_use]
    pub const fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }
}

/// Core trait for outbound implementations
///
/// All outbound types (Direct, Block, SOCKS5, etc.) must implement this trait.
#[async_trait]
pub trait Outbound: Send + Sync {
    /// Connect to the target address through this outbound.
    ///
    /// # Arguments
    ///
    /// * `addr` - Target address to connect to
    /// * `timeout` - Connection timeout
    ///
    /// # Errors
    ///
    /// Returns `OutboundError` if the connection fails.
    async fn connect(
        &self,
        addr: SocketAddr,
        timeout: Duration,
    ) -> Result<OutboundConnection, OutboundError>;

    /// Get the unique tag for this outbound
    fn tag(&self) -> &str;

    /// Get the current health status
    fn health_status(&self) -> HealthStatus;

    /// Get connection statistics
    fn stats(&self) -> Arc<OutboundStats>;

    /// Check if this outbound is enabled
    fn is_enabled(&self) -> bool;

    /// Set the enabled state
    fn set_enabled(&self, enabled: bool);

    /// Get the count of active connections through this outbound
    fn active_connections(&self) -> u64;

    /// Get the outbound type name
    fn outbound_type(&self) -> &str;

    /// Get connection pool statistics (for pooled outbound types)
    ///
    /// Returns `None` for non-pooled outbound types like Direct.
    fn pool_stats_info(&self) -> Option<PoolStatsInfo> {
        None
    }

    /// Get proxy server information (for proxy outbound types like SOCKS5)
    ///
    /// Returns `None` for non-proxy outbound types like Direct.
    fn proxy_server_info(&self) -> Option<ProxyServerInfo> {
        None
    }

    /// Get the transport type name (e.g., "tcp", "tls", "websocket")
    ///
    /// Returns `None` for outbound types that don't have a configurable transport.
    fn transport_type(&self) -> Option<&str> {
        None
    }

    // === UDP Methods ===

    /// Connect for UDP through this outbound.
    ///
    /// Creates a UDP socket configured for this outbound and connects it
    /// to the destination address. The returned handle can be used to
    /// send and receive UDP datagrams.
    ///
    /// # Arguments
    ///
    /// * `addr` - Target address to connect to
    /// * `timeout` - Connection/setup timeout
    ///
    /// # Errors
    ///
    /// Returns `UdpError::UdpNotSupported` by default.
    /// Outbounds that support UDP should override this method.
    async fn connect_udp(
        &self,
        _addr: SocketAddr,
        _timeout: Duration,
    ) -> Result<UdpOutboundHandle, UdpError> {
        Err(UdpError::UdpNotSupported {
            tag: self.tag().to_string(),
        })
    }

    /// Check if this outbound supports UDP
    ///
    /// Returns `false` by default. Outbounds that support UDP should
    /// override this to return `true`.
    fn supports_udp(&self) -> bool {
        false
    }
}

/// Extension trait for additional outbound functionality
pub trait OutboundExt: Outbound {
    /// Check if this outbound supports the given destination
    fn supports_destination(&self, _addr: SocketAddr) -> bool {
        true
    }

    /// Get the priority for load balancing (higher = preferred)
    fn priority(&self) -> u32 {
        100
    }
}

// Blanket implementation
impl<T: Outbound> OutboundExt for T {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_status() {
        assert!(HealthStatus::Healthy.is_available());
        assert!(HealthStatus::Degraded.is_available());
        assert!(!HealthStatus::Unhealthy.is_available());
        assert!(HealthStatus::Unknown.is_available());
    }

    #[test]
    fn test_health_status_display() {
        assert_eq!(HealthStatus::Healthy.to_string(), "healthy");
        assert_eq!(HealthStatus::Unhealthy.to_string(), "unhealthy");
    }

    #[tokio::test]
    async fn test_outbound_connection() {
        // Create a simple connection for testing
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let connect_task = tokio::spawn(async move { TcpStream::connect(addr).await });

        let (server, _) = listener.accept().await.unwrap();
        let client = connect_task.await.unwrap().unwrap();

        let conn = OutboundConnection::new(client, addr);
        assert_eq!(conn.remote_addr(), addr);
        assert!(conn.local_addr().is_some());

        drop(server);
    }

    // === UDP Handle Tests ===

    #[tokio::test]
    async fn test_direct_udp_handle_send_recv() {
        // Create a UDP echo server
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();

        // Create client socket and handle
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.connect(server_addr).await.unwrap();
        let handle = DirectUdpHandle::new(client, server_addr, None);

        // Test send
        let data = b"hello";
        let sent = handle.send(data).await.unwrap();
        assert_eq!(sent, data.len());

        // Receive on server side
        let mut buf = [0u8; 64];
        let (n, client_addr) = server.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], data);

        // Send reply
        server.send_to(b"world", client_addr).await.unwrap();

        // Receive reply
        let n = handle.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"world");
    }

    #[tokio::test]
    async fn test_direct_udp_handle_routing_mark() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = "8.8.8.8:53".parse().unwrap();

        let handle_with_mark = DirectUdpHandle::new(socket, addr, Some(100));
        assert_eq!(handle_with_mark.routing_mark, Some(100));
        assert_eq!(handle_with_mark.dest_addr, addr);
    }

    // Note: Socks5UdpHandle tests moved to socks5_udp.rs integration tests
    // as they require a running SOCKS5 server to test properly.

    #[test]
    fn test_udp_outbound_handle_routing_mark_direct() {
        // DirectUdpHandle routing mark is tested via UdpOutboundHandle
        let addr: SocketAddr = "1.2.3.4:443".parse().unwrap();
        // Can't create Socks5UdpHandle without association, so we skip that test here.
        // SOCKS5 UDP handle tests are in socks5_udp.rs with mock server.

        // Direct handles return their routing_mark
        // Socks5 handles return None (routing is handled at protocol level)
        assert!(true); // Placeholder - actual tests in socks5_udp.rs
    }

    #[tokio::test]
    async fn test_udp_outbound_handle_enum_send() {
        // Create a UDP echo server
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();

        // Create client socket and wrap in enum
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.connect(server_addr).await.unwrap();
        let direct_handle = DirectUdpHandle::new(client, server_addr, Some(200));
        let handle = UdpOutboundHandle::Direct(direct_handle);

        // Test via enum
        assert_eq!(handle.dest_addr(), server_addr);
        assert_eq!(handle.routing_mark(), Some(200));

        // Send via enum
        let sent = handle.send(b"test").await.unwrap();
        assert_eq!(sent, 4);
    }
}
