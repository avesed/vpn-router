//! Shadowsocks client outbound implementation
//!
//! This module provides a Shadowsocks client outbound that implements the `Outbound` trait.
//! Shadowsocks is a secure proxy protocol with AEAD encryption, commonly used for
//! bypassing network restrictions.
//!
//! # Transport Types
//!
//! Shadowsocks supports multiple transport types:
//!
//! - **TCP** (default): Standard TCP connection
//! - **QUIC** (optional, `transport-quic` feature): QUIC transport for better performance
//!
//! # Protocol Overview
//!
//! ## TCP Connection Flow
//! 1. Establish TCP connection to the Shadowsocks server
//! 2. Send encrypted target address header
//! 3. Bidirectional encrypted data relay
//!
//! ## QUIC Connection Flow
//! 1. Establish QUIC connection to the Shadowsocks server
//! 2. Open bidirectional stream
//! 3. Send encrypted target address header
//! 4. Bidirectional encrypted data relay
//!
//! ## UDP Relay Flow
//! 1. Create UDP socket connected to the Shadowsocks server
//! 2. Send encrypted UDP packets with target address header
//! 3. Receive encrypted UDP reply packets
//! 4. Each packet is individually encrypted (no session state)
//!
//! # Example
//!
//! ```ignore
//! use rust_router::outbound::shadowsocks::{ShadowsocksOutbound, ShadowsocksOutboundConfig};
//! use rust_router::shadowsocks::ShadowsocksMethod;
//! use rust_router::outbound::Outbound;
//! use std::time::Duration;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // TCP transport (default)
//! let tcp_config = ShadowsocksOutboundConfig::new("ss.example.com", 8388, "password")
//!     .with_method(ShadowsocksMethod::Aead2022Blake3Aes256Gcm);
//!
//! let tcp_outbound = ShadowsocksOutbound::new("my-ss-tcp", tcp_config)?;
//!
//! // QUIC transport
//! let quic_config = ShadowsocksOutboundConfig::new("ss.example.com", 8388, "password")
//!     .with_quic()
//!     .with_quic_sni("ss.example.com");
//!
//! let quic_outbound = ShadowsocksOutbound::new("my-ss-quic", quic_config)?;
//!
//! // Connect
//! let conn = tcp_outbound.connect("8.8.8.8:443".parse()?, Duration::from_secs(10)).await?;
//! # Ok(())
//! # }
//! ```

use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::timeout;
use tracing::{debug, trace, warn};

use super::traits::{
    HealthStatus, Outbound, OutboundConnection, OutboundStream, ProxyServerInfo, UdpOutboundHandle,
};
use crate::connection::OutboundStats;
use crate::error::{OutboundError, UdpError};
use crate::shadowsocks::{
    ShadowsocksError, ShadowsocksMethod, ShadowsocksOutboundConfig, ShadowsocksTransport,
};

#[cfg(feature = "shadowsocks")]
use shadowsocks::{
    config::{ServerConfig, ServerType},
    context::{Context as SsContext, SharedContext},
    net::TcpStream as SsTcpStream,
    relay::{
        socks5::Address as SsAddress,
        tcprelay::ProxyClientStream,
        udprelay::proxy_socket::ProxySocket,
    },
    ServerAddr,
};

#[cfg(all(feature = "shadowsocks", feature = "transport-quic"))]
use crate::transport::{QuicClientConfig, QuicEndpointPool, QuicStream};

// ============================================================================
// Shadowsocks Stream Wrapper
// ============================================================================

/// Inner stream type for Shadowsocks connections
///
/// This enum allows Shadowsocks to work over different transports while
/// maintaining a unified interface.
#[cfg(feature = "shadowsocks")]
enum ShadowsocksStreamInner {
    /// TCP-based Shadowsocks stream
    Tcp(ProxyClientStream<SsTcpStream>),

    /// QUIC-based Shadowsocks stream
    #[cfg(feature = "transport-quic")]
    Quic(ProxyClientStream<QuicStream>),
}

/// Wrapper around `ProxyClientStream` that implements `AsyncRead` and `AsyncWrite`
///
/// This wrapper is needed because `ProxyClientStream` has a generic parameter
/// and we need a concrete type for `OutboundStream`. It supports both TCP and
/// QUIC transport types.
///
/// # Transport Types
///
/// - **TCP**: Standard TCP connection (default)
/// - **QUIC**: QUIC transport for better performance over lossy networks
#[cfg(feature = "shadowsocks")]
pub struct ShadowsocksStream {
    inner: ShadowsocksStreamInner,
}

#[cfg(feature = "shadowsocks")]
impl ShadowsocksStream {
    /// Create a new Shadowsocks stream from a TCP-based ProxyClientStream
    fn from_tcp(inner: ProxyClientStream<SsTcpStream>) -> Self {
        Self {
            inner: ShadowsocksStreamInner::Tcp(inner),
        }
    }

    /// Create a new Shadowsocks stream from a QUIC-based ProxyClientStream
    #[cfg(feature = "transport-quic")]
    fn from_quic(inner: ProxyClientStream<QuicStream>) -> Self {
        Self {
            inner: ShadowsocksStreamInner::Quic(inner),
        }
    }

    /// Check if this stream uses QUIC transport
    #[allow(dead_code)]
    pub fn is_quic(&self) -> bool {
        #[cfg(feature = "transport-quic")]
        {
            matches!(self.inner, ShadowsocksStreamInner::Quic(_))
        }
        #[cfg(not(feature = "transport-quic"))]
        {
            false
        }
    }

    /// Check if this stream uses TCP transport
    #[allow(dead_code)]
    pub fn is_tcp(&self) -> bool {
        matches!(self.inner, ShadowsocksStreamInner::Tcp(_))
    }
}

#[cfg(feature = "shadowsocks")]
impl AsyncRead for ShadowsocksStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match &mut self.inner {
            ShadowsocksStreamInner::Tcp(s) => Pin::new(s).poll_read(cx, buf),
            #[cfg(feature = "transport-quic")]
            ShadowsocksStreamInner::Quic(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

#[cfg(feature = "shadowsocks")]
impl AsyncWrite for ShadowsocksStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match &mut self.inner {
            ShadowsocksStreamInner::Tcp(s) => Pin::new(s).poll_write(cx, buf),
            #[cfg(feature = "transport-quic")]
            ShadowsocksStreamInner::Quic(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.inner {
            ShadowsocksStreamInner::Tcp(s) => Pin::new(s).poll_flush(cx),
            #[cfg(feature = "transport-quic")]
            ShadowsocksStreamInner::Quic(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.inner {
            ShadowsocksStreamInner::Tcp(s) => Pin::new(s).poll_shutdown(cx),
            #[cfg(feature = "transport-quic")]
            ShadowsocksStreamInner::Quic(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

#[cfg(feature = "shadowsocks")]
impl fmt::Debug for ShadowsocksStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.inner {
            ShadowsocksStreamInner::Tcp(_) => f
                .debug_struct("ShadowsocksStream")
                .field("transport", &"tcp")
                .finish_non_exhaustive(),
            #[cfg(feature = "transport-quic")]
            ShadowsocksStreamInner::Quic(_) => f
                .debug_struct("ShadowsocksStream")
                .field("transport", &"quic")
                .finish_non_exhaustive(),
        }
    }
}

// ============================================================================
// Shadowsocks UDP Handle
// ============================================================================

/// Shadowsocks UDP relay handle
///
/// Wraps a Shadowsocks `ProxySocket` for UDP relay operations.
/// Each UDP packet is individually encrypted with the target address.
#[cfg(feature = "shadowsocks")]
pub struct ShadowsocksUdpHandle {
    /// The underlying proxy socket for UDP relay
    socket: Arc<ProxySocket<shadowsocks::net::UdpSocket>>,
    /// Destination address for this handle
    dest_addr: SocketAddr,
    /// Target address in Shadowsocks format
    ss_addr: SsAddress,
    /// Statistics: packets sent
    packets_sent: AtomicU64,
    /// Statistics: packets received
    packets_received: AtomicU64,
}

#[cfg(feature = "shadowsocks")]
impl ShadowsocksUdpHandle {
    /// Create a new Shadowsocks UDP handle
    fn new(
        socket: Arc<ProxySocket<shadowsocks::net::UdpSocket>>,
        dest_addr: SocketAddr,
    ) -> Self {
        Self {
            socket,
            dest_addr,
            ss_addr: SsAddress::SocketAddress(dest_addr),
            packets_sent: AtomicU64::new(0),
            packets_received: AtomicU64::new(0),
        }
    }

    /// Get the destination address
    #[must_use]
    pub fn dest_addr(&self) -> SocketAddr {
        self.dest_addr
    }

    /// Send data through the Shadowsocks UDP relay
    ///
    /// The data is encrypted and encapsulated with the target address.
    ///
    /// # Errors
    ///
    /// Returns `UdpError` if sending fails.
    pub async fn send(&self, data: &[u8]) -> Result<usize, UdpError> {
        let result = self
            .socket
            .send(&self.ss_addr, data)
            .await
            .map_err(|e| UdpError::send(self.dest_addr, e.to_string()))?;

        self.packets_sent.fetch_add(1, Ordering::Relaxed);
        trace!(
            dest = %self.dest_addr,
            bytes = result,
            "Shadowsocks UDP send"
        );
        Ok(result)
    }

    /// Receive data from the Shadowsocks UDP relay
    ///
    /// The received data is decrypted and the source address is extracted.
    /// Note: The buffer should be at least 65536 bytes for maximum compatibility.
    ///
    /// # Errors
    ///
    /// Returns `UdpError` if receiving fails.
    pub async fn recv(&self, buf: &mut [u8]) -> Result<usize, UdpError> {
        // The recv_from returns (payload_len, server_addr, target_addr, raw_len)
        let (n, _server_addr, _target_addr, _raw_len) = self
            .socket
            .recv_from(buf)
            .await
            .map_err(|e| UdpError::RecvError(e.to_string()))?;

        self.packets_received.fetch_add(1, Ordering::Relaxed);
        trace!(
            bytes = n,
            "Shadowsocks UDP recv"
        );
        Ok(n)
    }

    /// Try to receive data without blocking
    ///
    /// Note: Shadowsocks ProxySocket doesn't provide a try_recv method,
    /// so this returns WouldBlock to indicate caller should use async recv.
    ///
    /// # Errors
    ///
    /// Always returns `WouldBlock` - use async `recv` instead.
    pub fn try_recv(&self, _buf: &mut [u8]) -> Result<usize, UdpError> {
        Err(UdpError::IoError(io::Error::new(
            io::ErrorKind::WouldBlock,
            "Shadowsocks UDP try_recv not supported, use async recv",
        )))
    }

    /// Get the number of packets sent
    #[must_use]
    pub fn packets_sent(&self) -> u64 {
        self.packets_sent.load(Ordering::Relaxed)
    }

    /// Get the number of packets received
    #[must_use]
    pub fn packets_received(&self) -> u64 {
        self.packets_received.load(Ordering::Relaxed)
    }
}

#[cfg(feature = "shadowsocks")]
impl fmt::Debug for ShadowsocksUdpHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ShadowsocksUdpHandle")
            .field("dest_addr", &self.dest_addr)
            .field("packets_sent", &self.packets_sent())
            .field("packets_received", &self.packets_received())
            .finish_non_exhaustive()
    }
}

// ============================================================================
// Shadowsocks Outbound
// ============================================================================

/// Shadowsocks outbound implementation
///
/// Provides Shadowsocks protocol support with AEAD encryption.
#[cfg(feature = "shadowsocks")]
pub struct ShadowsocksOutbound {
    /// Unique tag for this outbound
    tag: String,
    /// Configuration
    config: ShadowsocksOutboundConfig,
    /// Shadowsocks context (shared)
    ss_context: SharedContext,
    /// Shadowsocks server configuration
    ss_config: ServerConfig,
    /// Connection statistics
    stats: Arc<OutboundStats>,
    /// Whether the outbound is enabled
    enabled: AtomicBool,
    /// Current health status
    health: std::sync::RwLock<HealthStatus>,
    /// Consecutive failure count for health tracking
    consecutive_failures: AtomicU64,
}

#[cfg(feature = "shadowsocks")]
impl ShadowsocksOutbound {
    /// Create a new Shadowsocks outbound from configuration
    ///
    /// # Errors
    ///
    /// Returns `ShadowsocksError` if the configuration is invalid.
    pub fn new(
        tag: impl Into<String>,
        config: ShadowsocksOutboundConfig,
    ) -> Result<Self, ShadowsocksError> {
        let tag = tag.into();

        // Validate configuration
        config.validate()?;

        if tag.is_empty() {
            return Err(ShadowsocksError::ConfigError(
                "outbound tag cannot be empty".into(),
            ));
        }

        // Create shadowsocks context for client mode (Local)
        let ss_context = SsContext::new_shared(ServerType::Local);

        // Convert method to CipherKind
        let cipher_kind = config.method.to_cipher_kind()?;

        // Create server configuration
        let server_addr = if config.server.parse::<std::net::IpAddr>().is_ok() {
            // It's an IP address
            let addr: SocketAddr = format!("{}:{}", config.server, config.server_port)
                .parse()
                .map_err(|e| {
                    ShadowsocksError::ConfigError(format!("invalid server address: {e}"))
                })?;
            ServerAddr::SocketAddr(addr)
        } else {
            // It's a hostname
            ServerAddr::DomainName(config.server.clone(), config.server_port)
        };

        let ss_config = ServerConfig::new(server_addr, config.password.clone(), cipher_kind)
            .map_err(|e| ShadowsocksError::InvalidPassword(format!("{e}")))?;

        debug!(
            "Created Shadowsocks outbound '{}' to {} with method {}",
            tag,
            config.server_string(),
            config.method
        );

        Ok(Self {
            tag,
            config,
            ss_context,
            ss_config,
            stats: Arc::new(OutboundStats::new()),
            enabled: AtomicBool::new(true),
            health: std::sync::RwLock::new(HealthStatus::Unknown),
            consecutive_failures: AtomicU64::new(0),
        })
    }

    /// Get the server address
    #[must_use]
    pub fn server_address(&self) -> &str {
        &self.config.server
    }

    /// Get the server port
    #[must_use]
    pub fn server_port(&self) -> u16 {
        self.config.server_port
    }

    /// Get the encryption method
    #[must_use]
    pub fn method(&self) -> ShadowsocksMethod {
        self.config.method
    }

    /// Update health status based on connection result
    fn update_health(&self, success: bool) {
        if success {
            self.consecutive_failures.store(0, Ordering::Relaxed);
            let mut health = self.health.write().unwrap();
            *health = HealthStatus::Healthy;
        } else {
            let failures = self.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;
            let mut health = self.health.write().unwrap();
            *health = if failures >= 5 {
                HealthStatus::Unhealthy
            } else if failures >= 2 {
                HealthStatus::Degraded
            } else {
                HealthStatus::Unknown
            };
        }
    }

    /// Convert destination SocketAddr to Shadowsocks Address
    fn socket_addr_to_ss_address(addr: SocketAddr) -> SsAddress {
        SsAddress::SocketAddress(addr)
    }

    /// Get the transport type string for logging
    fn transport_type(&self) -> &'static str {
        match &self.config.transport {
            ShadowsocksTransport::Tcp => "tcp",
            #[cfg(feature = "transport-quic")]
            ShadowsocksTransport::Quic { .. } => "quic",
        }
    }

    /// Connect to a destination via TCP transport
    async fn connect_tcp(
        &self,
        addr: SocketAddr,
        connect_timeout: Duration,
    ) -> Result<OutboundConnection, OutboundError> {
        debug!(
            "Shadowsocks (TCP) connecting to {} via {} (server: {})",
            addr,
            self.tag,
            self.config.server_string()
        );

        // Convert destination to Shadowsocks Address
        let ss_addr = Self::socket_addr_to_ss_address(addr);

        // Connect via Shadowsocks proxy with timeout
        let connect_result = timeout(
            connect_timeout,
            ProxyClientStream::connect(self.ss_context.clone(), &self.ss_config, ss_addr),
        )
        .await;

        match connect_result {
            Ok(Ok(proxy_stream)) => {
                self.update_health(true);
                debug!(
                    "Shadowsocks (TCP) connection to {} via {} successful",
                    addr, self.tag
                );

                // Wrap the ProxyClientStream in our wrapper
                let ss_stream = ShadowsocksStream::from_tcp(proxy_stream);
                Ok(OutboundConnection::from_shadowsocks(ss_stream, addr))
            }
            Ok(Err(e)) => {
                self.update_health(false);
                self.stats.record_error();
                warn!(
                    "Shadowsocks (TCP) connection to {} via {} failed: {}",
                    addr, self.tag, e
                );
                Err(OutboundError::connection_failed(
                    addr,
                    format!("Shadowsocks TCP connection failed: {e}"),
                ))
            }
            Err(_) => {
                self.update_health(false);
                self.stats.record_error();
                warn!(
                    "Shadowsocks (TCP) connection to {} via {} timed out",
                    addr, self.tag
                );
                Err(OutboundError::Timeout {
                    addr,
                    timeout_secs: connect_timeout.as_secs(),
                })
            }
        }
    }

    /// Connect to a destination via QUIC transport
    #[cfg(feature = "transport-quic")]
    async fn connect_quic(
        &self,
        addr: SocketAddr,
        connect_timeout: Duration,
    ) -> Result<OutboundConnection, OutboundError> {
        use std::net::ToSocketAddrs;

        debug!(
            "Shadowsocks (QUIC) connecting to {} via {} (server: {})",
            addr,
            self.tag,
            self.config.server_string()
        );

        // Extract QUIC configuration
        let (sni, alpn, skip_verify, idle_timeout_secs, keep_alive_secs) =
            match &self.config.transport {
                ShadowsocksTransport::Quic {
                    sni,
                    alpn,
                    skip_verify,
                    idle_timeout_secs,
                    keep_alive_secs,
                } => (
                    sni.clone(),
                    alpn.clone(),
                    *skip_verify,
                    *idle_timeout_secs,
                    *keep_alive_secs,
                ),
                _ => unreachable!("connect_quic called with non-QUIC transport"),
            };

        // Use SNI or fall back to server address
        let server_name = sni.unwrap_or_else(|| self.config.server.clone());

        // Resolve server address
        let server_addr_str = self.config.server_string();
        let server_socket_addr = server_addr_str
            .to_socket_addrs()
            .map_err(|e| {
                OutboundError::connection_failed(
                    addr,
                    format!("Failed to resolve server address {}: {}", server_addr_str, e),
                )
            })?
            .next()
            .ok_or_else(|| {
                OutboundError::connection_failed(
                    addr,
                    format!("No addresses found for {}", server_addr_str),
                )
            })?;

        // Create QUIC client configuration
        let mut quic_config = QuicClientConfig::new(&server_name)
            .with_idle_timeout(idle_timeout_secs)
            .with_keep_alive_interval(keep_alive_secs)
            .with_num_endpoints(1); // Use single endpoint per connection

        if !alpn.is_empty() {
            quic_config = quic_config.with_alpn(alpn);
        }

        if skip_verify {
            quic_config = quic_config.insecure_skip_verify();
        }

        // Connect via QUIC with timeout
        let connect_result = timeout(connect_timeout, async {
            // Create endpoint pool (single endpoint)
            let pool = QuicEndpointPool::new(&quic_config).await?;

            // Connect to the Shadowsocks server via QUIC
            let quic_stream = pool.connect(server_socket_addr, &server_name).await?;

            // Convert destination to Shadowsocks Address
            let ss_addr = Self::socket_addr_to_ss_address(addr);

            // Create ProxyClientStream over the QUIC stream
            let proxy_stream =
                ProxyClientStream::from_stream(self.ss_context.clone(), quic_stream, &self.ss_config, ss_addr);

            Ok::<_, crate::transport::TransportError>(proxy_stream)
        })
        .await;

        match connect_result {
            Ok(Ok(proxy_stream)) => {
                self.update_health(true);
                debug!(
                    "Shadowsocks (QUIC) connection to {} via {} successful",
                    addr, self.tag
                );

                // Wrap the ProxyClientStream in our wrapper
                let ss_stream = ShadowsocksStream::from_quic(proxy_stream);
                Ok(OutboundConnection::from_shadowsocks(ss_stream, addr))
            }
            Ok(Err(e)) => {
                self.update_health(false);
                self.stats.record_error();
                warn!(
                    "Shadowsocks (QUIC) connection to {} via {} failed: {}",
                    addr, self.tag, e
                );
                Err(OutboundError::connection_failed(
                    addr,
                    format!("Shadowsocks QUIC connection failed: {e}"),
                ))
            }
            Err(_) => {
                self.update_health(false);
                self.stats.record_error();
                warn!(
                    "Shadowsocks (QUIC) connection to {} via {} timed out",
                    addr, self.tag
                );
                Err(OutboundError::Timeout {
                    addr,
                    timeout_secs: connect_timeout.as_secs(),
                })
            }
        }
    }
}

#[cfg(feature = "shadowsocks")]
#[async_trait]
impl Outbound for ShadowsocksOutbound {
    async fn connect(
        &self,
        addr: SocketAddr,
        connect_timeout: Duration,
    ) -> Result<OutboundConnection, OutboundError> {
        if !self.is_enabled() {
            return Err(OutboundError::unavailable(
                &self.tag,
                "outbound is disabled",
            ));
        }

        self.stats.record_connection();

        // Dispatch based on transport type
        match &self.config.transport {
            ShadowsocksTransport::Tcp => self.connect_tcp(addr, connect_timeout).await,
            #[cfg(feature = "transport-quic")]
            ShadowsocksTransport::Quic { .. } => self.connect_quic(addr, connect_timeout).await,
        }
    }

    fn tag(&self) -> &str {
        &self.tag
    }

    fn health_status(&self) -> HealthStatus {
        *self.health.read().unwrap()
    }

    fn stats(&self) -> Arc<OutboundStats> {
        Arc::clone(&self.stats)
    }

    fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Relaxed);
    }

    fn active_connections(&self) -> u64 {
        self.stats.active()
    }

    fn outbound_type(&self) -> &str {
        "shadowsocks"
    }

    fn proxy_server_info(&self) -> Option<ProxyServerInfo> {
        Some(ProxyServerInfo {
            address: self.config.server_string(),
            has_auth: true, // Shadowsocks always uses password auth
        })
    }

    /// Connect for UDP relay through Shadowsocks
    ///
    /// Creates a ProxySocket connected to the Shadowsocks server for UDP relay.
    /// Each UDP packet is individually encrypted with the target address.
    async fn connect_udp(
        &self,
        addr: SocketAddr,
        connect_timeout: Duration,
    ) -> Result<UdpOutboundHandle, UdpError> {
        // Check if UDP is enabled in config
        if !self.config.udp {
            return Err(UdpError::UdpNotSupported {
                tag: self.tag.clone(),
            });
        }

        if !self.is_enabled() {
            return Err(UdpError::OutboundDisabled {
                tag: self.tag.clone(),
            });
        }

        debug!(
            "Shadowsocks UDP connecting to {} via {} (server: {})",
            addr,
            self.tag,
            self.config.server_string()
        );

        // Create UDP proxy socket with timeout
        let connect_result = timeout(
            connect_timeout,
            ProxySocket::connect(self.ss_context.clone(), &self.ss_config),
        )
        .await;

        match connect_result {
            Ok(Ok(proxy_socket)) => {
                self.update_health(true);
                debug!(
                    "Shadowsocks UDP socket to {} via {} ready",
                    addr, self.tag
                );

                // Create the handle
                let handle = ShadowsocksUdpHandle::new(Arc::new(proxy_socket), addr);
                Ok(UdpOutboundHandle::Shadowsocks(handle))
            }
            Ok(Err(e)) => {
                self.update_health(false);
                self.stats.record_error();
                warn!(
                    "Shadowsocks UDP connection to {} via {} failed: {}",
                    addr, self.tag, e
                );
                Err(UdpError::Socks5UdpAssociationFailed {
                    reason: format!("Shadowsocks UDP connection failed: {e}"),
                })
            }
            Err(_) => {
                self.update_health(false);
                self.stats.record_error();
                warn!(
                    "Shadowsocks UDP connection to {} via {} timed out",
                    addr, self.tag
                );
                Err(UdpError::IoError(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("Shadowsocks UDP connection timed out after {}s", connect_timeout.as_secs()),
                )))
            }
        }
    }

    fn supports_udp(&self) -> bool {
        // UDP is supported when enabled in config
        self.config.udp
    }
}

#[cfg(feature = "shadowsocks")]
impl fmt::Debug for ShadowsocksOutbound {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ShadowsocksOutbound")
            .field("tag", &self.tag)
            .field("server", &self.config.server_string())
            .field("method", &self.config.method)
            .field("transport", &self.transport_type())
            .field("enabled", &self.is_enabled())
            .field("health", &self.health_status())
            .finish_non_exhaustive()
    }
}

// ============================================================================
// OutboundConnection extension for Shadowsocks
// ============================================================================

// We need to extend OutboundConnection to support ShadowsocksStream
// This will be done by adding a method and potentially a new OutboundStream variant

#[cfg(feature = "shadowsocks")]
impl OutboundConnection {
    /// Create a new outbound connection from a Shadowsocks stream
    pub fn from_shadowsocks(stream: ShadowsocksStream, remote_addr: SocketAddr) -> Self {
        // We'll use the Transport variant with a custom wrapper
        // This requires adding Shadowsocks to TransportStream or OutboundStream
        // For now, we'll use a Box wrapper approach

        // Actually, the cleanest solution is to add OutboundStream::Shadowsocks
        // But that requires modifying traits.rs

        // Workaround: Create a wrapper type that can be used
        Self::from_stream(OutboundStream::Shadowsocks(stream), remote_addr)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(all(test, feature = "shadowsocks"))]
mod tests {
    use super::*;

    /// Helper to create a config with legacy AEAD cipher for testing
    /// (Legacy ciphers accept regular password strings)
    fn test_config(server: &str, port: u16) -> ShadowsocksOutboundConfig {
        ShadowsocksOutboundConfig::new(server, port, "test-password")
            .with_method(ShadowsocksMethod::Aes256Gcm)
    }

    /// Helper to create a config with UDP enabled
    fn test_config_with_udp(server: &str, port: u16) -> ShadowsocksOutboundConfig {
        ShadowsocksOutboundConfig::new(server, port, "test-password")
            .with_method(ShadowsocksMethod::Aes256Gcm)
            .with_udp(true)
    }

    #[test]
    fn test_shadowsocks_outbound_new() {
        let config = test_config("192.168.1.1", 8388);
        let outbound = ShadowsocksOutbound::new("test-ss", config).unwrap();

        assert_eq!(outbound.tag(), "test-ss");
        assert_eq!(outbound.server_address(), "192.168.1.1");
        assert_eq!(outbound.server_port(), 8388);
        assert_eq!(outbound.method(), ShadowsocksMethod::Aes256Gcm);
        assert!(outbound.is_enabled());
        assert_eq!(outbound.outbound_type(), "shadowsocks");
        assert!(!outbound.supports_udp()); // UDP disabled by default
    }

    #[test]
    fn test_shadowsocks_outbound_with_udp() {
        let config = test_config_with_udp("192.168.1.1", 8388);
        let outbound = ShadowsocksOutbound::new("test-ss-udp", config).unwrap();

        assert_eq!(outbound.tag(), "test-ss-udp");
        assert!(outbound.supports_udp()); // UDP should be enabled
    }

    #[test]
    fn test_shadowsocks_outbound_empty_tag() {
        let config = test_config("192.168.1.1", 8388);
        let result = ShadowsocksOutbound::new("", config);
        assert!(result.is_err());
    }

    #[test]
    fn test_shadowsocks_outbound_invalid_config() {
        // Empty server
        let config = ShadowsocksOutboundConfig::new("", 8388, "password");
        let result = ShadowsocksOutbound::new("test", config);
        assert!(result.is_err());

        // Empty password
        let config = ShadowsocksOutboundConfig::new("server.com", 8388, "");
        let result = ShadowsocksOutbound::new("test", config);
        assert!(result.is_err());
    }

    #[test]
    fn test_shadowsocks_outbound_with_hostname() {
        let config = ShadowsocksOutboundConfig::new("ss.example.com", 443, "secret-password")
            .with_method(ShadowsocksMethod::Aes256Gcm);
        let outbound = ShadowsocksOutbound::new("hostname-test", config).unwrap();

        assert_eq!(outbound.server_address(), "ss.example.com");
        assert_eq!(outbound.method(), ShadowsocksMethod::Aes256Gcm);
    }

    #[test]
    fn test_shadowsocks_outbound_proxy_server_info() {
        let config = test_config("192.168.1.1", 8388);
        let outbound = ShadowsocksOutbound::new("test", config).unwrap();

        let info = outbound.proxy_server_info().unwrap();
        assert_eq!(info.address, "192.168.1.1:8388");
        assert!(info.has_auth);
    }

    #[test]
    fn test_shadowsocks_outbound_stats() {
        let config = test_config("192.168.1.1", 8388);
        let outbound = ShadowsocksOutbound::new("test", config).unwrap();

        let stats = outbound.stats();
        assert_eq!(stats.connections(), 0);
        assert_eq!(stats.active(), 0);
        assert_eq!(stats.errors(), 0);
    }

    #[test]
    fn test_shadowsocks_outbound_enable_disable() {
        let config = test_config("192.168.1.1", 8388);
        let outbound = ShadowsocksOutbound::new("test", config).unwrap();

        assert!(outbound.is_enabled());
        outbound.set_enabled(false);
        assert!(!outbound.is_enabled());
        outbound.set_enabled(true);
        assert!(outbound.is_enabled());
    }

    #[test]
    fn test_shadowsocks_outbound_debug() {
        let config = test_config("192.168.1.1", 8388);
        let outbound = ShadowsocksOutbound::new("debug-test", config).unwrap();

        let debug_str = format!("{:?}", outbound);
        assert!(debug_str.contains("ShadowsocksOutbound"));
        assert!(debug_str.contains("debug-test"));
        assert!(debug_str.contains("192.168.1.1:8388"));
    }

    #[tokio::test]
    async fn test_shadowsocks_outbound_udp_not_supported_when_disabled() {
        // Config without UDP enabled
        let config = test_config("192.168.1.1", 8388);
        let outbound = ShadowsocksOutbound::new("udp-test", config).unwrap();

        assert!(!outbound.supports_udp());

        let dest: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let result = outbound.connect_udp(dest, Duration::from_secs(1)).await;

        assert!(result.is_err());
        if let Err(UdpError::UdpNotSupported { tag }) = result {
            assert_eq!(tag, "udp-test");
        } else {
            panic!("Expected UdpNotSupported error");
        }
    }

    #[tokio::test]
    async fn test_shadowsocks_outbound_udp_disabled_outbound() {
        // Config with UDP enabled, but outbound disabled
        let config = test_config_with_udp("192.168.1.1", 8388);
        let outbound = ShadowsocksOutbound::new("udp-disabled-test", config).unwrap();

        assert!(outbound.supports_udp());
        outbound.set_enabled(false);

        let dest: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let result = outbound.connect_udp(dest, Duration::from_secs(1)).await;

        assert!(result.is_err());
        if let Err(UdpError::OutboundDisabled { tag }) = result {
            assert_eq!(tag, "udp-disabled-test");
        } else {
            panic!("Expected OutboundDisabled error, got {:?}", result);
        }
    }

    #[tokio::test]
    async fn test_shadowsocks_outbound_disabled() {
        let config = test_config("192.168.1.1", 8388);
        let outbound = ShadowsocksOutbound::new("disabled-test", config).unwrap();

        outbound.set_enabled(false);

        let dest: SocketAddr = "8.8.8.8:443".parse().unwrap();
        let result = outbound.connect(dest, Duration::from_secs(1)).await;

        assert!(result.is_err());
        if let Err(OutboundError::Unavailable { tag, reason }) = result {
            assert_eq!(tag, "disabled-test");
            assert!(reason.contains("disabled"));
        } else {
            panic!("Expected Unavailable error");
        }
    }

    #[test]
    fn test_health_status_transitions() {
        let config = test_config("192.168.1.1", 8388);
        let outbound = ShadowsocksOutbound::new("health-test", config).unwrap();

        // Initial status is Unknown
        assert_eq!(outbound.health_status(), HealthStatus::Unknown);

        // Success -> Healthy
        outbound.update_health(true);
        assert_eq!(outbound.health_status(), HealthStatus::Healthy);

        // One failure -> Unknown
        outbound.update_health(false);
        assert_eq!(outbound.health_status(), HealthStatus::Unknown);

        // Two failures -> Degraded
        outbound.update_health(false);
        assert_eq!(outbound.health_status(), HealthStatus::Degraded);

        // Success resets
        outbound.update_health(true);
        assert_eq!(outbound.health_status(), HealthStatus::Healthy);

        // Five failures -> Unhealthy
        for _ in 0..5 {
            outbound.update_health(false);
        }
        assert_eq!(outbound.health_status(), HealthStatus::Unhealthy);
    }
}
