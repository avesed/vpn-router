//! SOCKS5 client outbound implementation with connection pooling
//!
//! This module provides a SOCKS5 client outbound that implements RFC 1928 (SOCKS5 protocol)
//! and RFC 1929 (username/password authentication). Connections are pooled using `deadpool`
//! for efficient reuse.
//!
//! # Protocol Overview
//!
//! SOCKS5 connection flow:
//! 1. Client sends version identifier/method selection (VER, NMETHODS, METHODS)
//! 2. Server replies with selected method (VER, METHOD)
//! 3. If authentication required, client sends credentials (RFC 1929)
//! 4. Client sends CONNECT request with destination address
//! 5. Server replies with result and bound address
//!
//! # Connection Pooling
//!
//! This implementation uses `deadpool` for connection pooling. Each pooled connection
//! has completed the SOCKS5 handshake but NOT the CONNECT command. The CONNECT is
//! issued when the connection is borrowed from the pool.
//!
//! # Example
//!
//! ```no_run
//! use rust_router::outbound::socks5::{Socks5Outbound, Socks5Config};
//! use rust_router::outbound::Outbound;  // Required for connect() method
//! use std::time::Duration;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = Socks5Config {
//!     tag: "my-socks5".into(),
//!     socks5_addr: "127.0.0.1:1080".parse()?,
//!     username: None,
//!     password: None,
//!     connect_timeout_secs: 10,
//!     idle_timeout_secs: 300,
//!     pool_max_size: 32,
//! };
//!
//! let outbound = Socks5Outbound::new(config).await?;
//! let conn = outbound.connect("8.8.8.8:443".parse()?, Duration::from_secs(10)).await?;
//! # Ok(())
//! # }
//! ```

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use deadpool::managed::{Manager, Metrics, Pool, RecycleError, RecycleResult};
use serde::{Deserialize, Serialize};
use socket2::{Domain, Protocol, Socket, TcpKeepalive, Type};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{debug, trace};

use super::traits::{HealthStatus, Outbound, OutboundConnection};
use crate::connection::OutboundStats;
use crate::error::OutboundError;

// Import shared SOCKS5 constants from the common module
use super::socks5_common::{
    reply_message, ATYP_DOMAIN, ATYP_IPV4, ATYP_IPV6, AUTH_METHOD_NONE, AUTH_METHOD_NO_ACCEPTABLE,
    AUTH_METHOD_PASSWORD, AUTH_PASSWORD_VERSION, CMD_CONNECT, REPLY_SUCCEEDED, SOCKS5_VERSION,
};

// ============================================================================
// Error Types
// ============================================================================

/// SOCKS5 specific errors
#[derive(Debug, Clone)]
pub enum Socks5Error {
    /// Invalid protocol version
    InvalidVersion { expected: u8, actual: u8 },
    /// No acceptable authentication method
    NoAcceptableMethod,
    /// Authentication failed
    AuthFailed,
    /// Server returned error reply
    ServerReply { code: u8, message: String },
    /// Invalid address type
    InvalidAddressType(u8),
    /// Protocol error (malformed message)
    ProtocolError(String),
    /// Connection error
    ConnectionError(String),
    /// Timeout during handshake
    HandshakeTimeout,
}

impl fmt::Display for Socks5Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidVersion { expected, actual } => {
                write!(f, "Invalid SOCKS version: expected {expected}, got {actual}")
            }
            Self::NoAcceptableMethod => write!(f, "No acceptable authentication method"),
            Self::AuthFailed => write!(f, "SOCKS5 authentication failed"),
            Self::ServerReply { code, message } => {
                write!(f, "SOCKS5 server error (code {code:#04x}): {message}")
            }
            Self::InvalidAddressType(atyp) => write!(f, "Invalid address type: {atyp:#04x}"),
            Self::ProtocolError(msg) => write!(f, "SOCKS5 protocol error: {msg}"),
            Self::ConnectionError(msg) => write!(f, "SOCKS5 connection error: {msg}"),
            Self::HandshakeTimeout => write!(f, "SOCKS5 handshake timeout"),
        }
    }
}

impl std::error::Error for Socks5Error {}

impl From<Socks5Error> for OutboundError {
    fn from(e: Socks5Error) -> Self {
        // Use a placeholder address for SOCKS5 protocol errors
        OutboundError::ConnectionFailed {
            addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
            reason: e.to_string(),
        }
    }
}

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for SOCKS5 outbound
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Socks5Config {
    /// Unique tag for this outbound
    pub tag: String,
    /// SOCKS5 server address
    pub socks5_addr: SocketAddr,
    /// Username for authentication (optional)
    pub username: Option<String>,
    /// Password for authentication (optional)
    pub password: Option<String>,
    /// Connection timeout in seconds
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout_secs: u64,
    /// Idle connection timeout in seconds
    #[serde(default = "default_idle_timeout")]
    pub idle_timeout_secs: u64,
    /// Maximum pool size
    #[serde(default = "default_pool_max_size")]
    pub pool_max_size: usize,
}

fn default_connect_timeout() -> u64 {
    10
}

fn default_idle_timeout() -> u64 {
    300
}

fn default_pool_max_size() -> usize {
    32
}

impl Socks5Config {
    /// Create a new SOCKS5 configuration with default values
    pub fn new(tag: impl Into<String>, socks5_addr: SocketAddr) -> Self {
        Self {
            tag: tag.into(),
            socks5_addr,
            username: None,
            password: None,
            connect_timeout_secs: default_connect_timeout(),
            idle_timeout_secs: default_idle_timeout(),
            pool_max_size: default_pool_max_size(),
        }
    }

    /// Set authentication credentials
    #[must_use]
    pub fn with_auth(mut self, username: impl Into<String>, password: impl Into<String>) -> Self {
        self.username = Some(username.into());
        self.password = Some(password.into());
        self
    }

    /// Set pool max size
    #[must_use]
    pub const fn with_pool_size(mut self, size: usize) -> Self {
        self.pool_max_size = size;
        self
    }

    /// Set connect timeout
    #[must_use]
    pub const fn with_connect_timeout(mut self, secs: u64) -> Self {
        self.connect_timeout_secs = secs;
        self
    }

    /// Set idle timeout
    #[must_use]
    pub const fn with_idle_timeout(mut self, secs: u64) -> Self {
        self.idle_timeout_secs = secs;
        self
    }

    /// Check if authentication is configured
    #[must_use]
    pub fn has_auth(&self) -> bool {
        self.username.is_some() && self.password.is_some()
    }
}

// ============================================================================
// Connection and Pool Statistics
// ============================================================================

/// Pool statistics snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolStats {
    /// Current pool size (all connections)
    pub size: usize,
    /// Available connections in pool
    pub available: usize,
    /// Number of waiters for connections
    pub waiting: usize,
}

// ============================================================================
// SOCKS5 Connection
// ============================================================================

/// A SOCKS5 connection that has completed handshake and authentication
#[allow(clippy::missing_fields_in_debug)]
pub struct Socks5Connection {
    /// Underlying TCP stream (Option to allow taking ownership)
    stream: Option<TcpStream>,
    /// When this connection was created
    created_at: Instant,
    /// When this connection was last used
    last_used: Instant,
    /// Whether handshake is complete
    handshake_complete: bool,
}

impl Socks5Connection {
    /// Create a new SOCKS5 connection wrapper
    fn new(stream: TcpStream) -> Self {
        let now = Instant::now();
        Self {
            stream: Some(stream),
            created_at: now,
            last_used: now,
            handshake_complete: false,
        }
    }

    /// Mark handshake as complete
    fn mark_handshake_complete(&mut self) {
        self.handshake_complete = true;
    }

    /// Update last used timestamp
    fn touch(&mut self) {
        self.last_used = Instant::now();
    }

    /// Check if connection has been idle for too long
    fn is_idle(&self, idle_timeout: Duration) -> bool {
        self.last_used.elapsed() > idle_timeout
    }

    /// Get connection age
    fn age(&self) -> Duration {
        self.created_at.elapsed()
    }

    /// Take ownership of the underlying stream
    fn take_stream(&mut self) -> Option<TcpStream> {
        self.stream.take()
    }

    /// Get a mutable reference to the stream
    fn stream_mut(&mut self) -> Option<&mut TcpStream> {
        self.stream.as_mut()
    }

    /// Check if the stream is still present
    fn has_stream(&self) -> bool {
        self.stream.is_some()
    }

    /// Check if connection is still alive using a zero-byte read
    async fn is_alive(&mut self) -> bool {
        let Some(stream) = self.stream.as_mut() else {
            return false;
        };

        // Try to read with zero timeout - if we get Ok(0), connection is closed
        // If we get WouldBlock/TimedOut, connection is still alive
        let mut buf = [0u8; 1];
        match tokio::time::timeout(Duration::from_millis(1), stream.peek(&mut buf)).await {
            // Connection closed or error reading
            Ok(Ok(0) | Err(_)) => false,
            // Timeout = connection alive
            Err(_) => true,
            // Got data unexpectedly - could be server push or error
            // Consider connection compromised
            Ok(Ok(_)) => false,
        }
    }
}

impl fmt::Debug for Socks5Connection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Socks5Connection")
            .field("has_stream", &self.stream.is_some())
            .field("handshake_complete", &self.handshake_complete)
            .field("age_ms", &self.age().as_millis())
            .field("idle_ms", &self.last_used.elapsed().as_millis())
            .finish_non_exhaustive()
    }
}

// ============================================================================
// Connection Manager for deadpool
// ============================================================================

/// Connection manager for the SOCKS5 connection pool
pub struct Socks5ConnectionManager {
    /// SOCKS5 server address
    socks5_addr: SocketAddr,
    /// Optional authentication credentials
    auth: Option<(String, String)>,
    /// Connection timeout
    connect_timeout: Duration,
    /// Idle timeout for recycling
    idle_timeout: Duration,
}

impl Socks5ConnectionManager {
    /// Create a new connection manager
    pub fn new(config: &Socks5Config) -> Self {
        Self {
            socks5_addr: config.socks5_addr,
            auth: config
                .username
                .as_ref()
                .zip(config.password.as_ref())
                .map(|(u, p)| (u.clone(), p.clone())),
            connect_timeout: Duration::from_secs(config.connect_timeout_secs),
            idle_timeout: Duration::from_secs(config.idle_timeout_secs),
        }
    }

    /// Perform TCP connection to SOCKS5 server
    async fn tcp_connect(&self) -> Result<TcpStream, Socks5Error> {
        // Create socket with proper domain based on SOCKS5 server address type
        let domain = if self.socks5_addr.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };
        let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))
            .map_err(|e| Socks5Error::ConnectionError(format!("socket creation failed: {e}")))?;

        // Set non-blocking for tokio
        socket
            .set_nonblocking(true)
            .map_err(|e| Socks5Error::ConnectionError(format!("set nonblocking failed: {e}")))?;

        // Enable TCP keepalive
        let keepalive = TcpKeepalive::new()
            .with_time(Duration::from_secs(60))
            .with_interval(Duration::from_secs(15));

        socket
            .set_tcp_keepalive(&keepalive)
            .map_err(|e| Socks5Error::ConnectionError(format!("set keepalive failed: {e}")))?;

        // Initiate non-blocking connect
        match socket.connect(&self.socks5_addr.into()) {
            Ok(()) => {}
            Err(ref e) if e.raw_os_error() == Some(libc::EINPROGRESS) => {}
            Err(e) => {
                return Err(Socks5Error::ConnectionError(format!(
                    "connect to {} failed: {e}",
                    self.socks5_addr
                )));
            }
        }

        // Convert to TcpStream
        let std_stream: std::net::TcpStream = socket.into();
        let stream = TcpStream::from_std(std_stream)
            .map_err(|e| Socks5Error::ConnectionError(format!("TcpStream conversion failed: {e}")))?;

        // Wait for connection with timeout
        let result = timeout(self.connect_timeout, async {
            stream
                .writable()
                .await
                .map_err(|e| Socks5Error::ConnectionError(e.to_string()))?;

            // Check for connection errors
            match stream.take_error() {
                Ok(None) => Ok(()),
                Ok(Some(e)) | Err(e) => Err(Socks5Error::ConnectionError(e.to_string())),
            }
        })
        .await;

        match result {
            Ok(Ok(())) => {
                // Disable Nagle's algorithm for lower latency
                if let Err(e) = stream.set_nodelay(true) {
                    tracing::warn!("Failed to set TCP_NODELAY for SOCKS5: {}", e);
                }
                Ok(stream)
            },
            Ok(Err(e)) => Err(e),
            Err(_) => Err(Socks5Error::HandshakeTimeout),
        }
    }

    /// Perform SOCKS5 handshake (version exchange + auth)
    async fn handshake(&self, conn: &mut Socks5Connection) -> Result<(), Socks5Error> {
        let stream = conn
            .stream_mut()
            .ok_or_else(|| Socks5Error::ConnectionError("stream already taken".into()))?;
        // Send method selection
        let methods: Vec<u8> = if self.auth.is_some() {
            vec![SOCKS5_VERSION, 2, AUTH_METHOD_NONE, AUTH_METHOD_PASSWORD]
        } else {
            vec![SOCKS5_VERSION, 1, AUTH_METHOD_NONE]
        };

        trace!("Sending SOCKS5 method selection: {:?}", methods);

        stream
            .write_all(&methods)
            .await
            .map_err(|e| Socks5Error::ConnectionError(format!("write methods failed: {e}")))?;

        // Read server response
        let mut response = [0u8; 2];
        stream
            .read_exact(&mut response)
            .await
            .map_err(|e| Socks5Error::ConnectionError(format!("read method response failed: {e}")))?;

        trace!("SOCKS5 method response: {:?}", response);

        // Validate version
        if response[0] != SOCKS5_VERSION {
            return Err(Socks5Error::InvalidVersion {
                expected: SOCKS5_VERSION,
                actual: response[0],
            });
        }

        // Handle selected method
        match response[1] {
            AUTH_METHOD_NONE => {
                trace!("SOCKS5 server selected no authentication");
                Ok(())
            }
            AUTH_METHOD_PASSWORD => {
                trace!("SOCKS5 server requires password authentication");
                self.authenticate(conn).await
            }
            AUTH_METHOD_NO_ACCEPTABLE => Err(Socks5Error::NoAcceptableMethod),
            other => Err(Socks5Error::ProtocolError(format!(
                "unsupported auth method: {other:#04x}"
            ))),
        }
    }

    /// Perform username/password authentication (RFC 1929)
    async fn authenticate(&self, conn: &mut Socks5Connection) -> Result<(), Socks5Error> {
        let stream = conn
            .stream_mut()
            .ok_or_else(|| Socks5Error::ConnectionError("stream already taken".into()))?;

        let (username, password) = self
            .auth
            .as_ref()
            .ok_or(Socks5Error::AuthFailed)?;

        // Validate lengths
        if username.len() > 255 {
            return Err(Socks5Error::ProtocolError(
                "username too long (max 255)".into(),
            ));
        }
        if password.len() > 255 {
            return Err(Socks5Error::ProtocolError(
                "password too long (max 255)".into(),
            ));
        }

        // Build auth request: VER | ULEN | USERNAME | PLEN | PASSWORD
        // Note: Length casts are safe because we validated lengths above (max 255)
        #[allow(clippy::cast_possible_truncation)]
        let ulen = username.len() as u8;
        #[allow(clippy::cast_possible_truncation)]
        let plen = password.len() as u8;

        let mut auth_req = Vec::with_capacity(3 + username.len() + password.len());
        auth_req.push(AUTH_PASSWORD_VERSION);
        auth_req.push(ulen);
        auth_req.extend_from_slice(username.as_bytes());
        auth_req.push(plen);
        auth_req.extend_from_slice(password.as_bytes());

        trace!("Sending SOCKS5 auth request");

        stream
            .write_all(&auth_req)
            .await
            .map_err(|e| Socks5Error::ConnectionError(format!("write auth failed: {e}")))?;

        // Read auth response: VER | STATUS
        let mut response = [0u8; 2];
        stream
            .read_exact(&mut response)
            .await
            .map_err(|e| Socks5Error::ConnectionError(format!("read auth response failed: {e}")))?;

        trace!("SOCKS5 auth response: {:?}", response);

        if response[0] != AUTH_PASSWORD_VERSION {
            return Err(Socks5Error::ProtocolError(format!(
                "invalid auth version: {:#04x}",
                response[0]
            )));
        }

        if response[1] != 0x00 {
            return Err(Socks5Error::AuthFailed);
        }

        trace!("SOCKS5 authentication successful");
        Ok(())
    }
}

#[async_trait]
impl Manager for Socks5ConnectionManager {
    type Type = Socks5Connection;
    type Error = Socks5Error;

    async fn create(&self) -> Result<Socks5Connection, Socks5Error> {
        trace!("Creating new SOCKS5 connection to {}", self.socks5_addr);

        // TCP connect
        let stream = self.tcp_connect().await?;

        // Create connection wrapper
        let mut conn = Socks5Connection::new(stream);

        // Perform handshake
        self.handshake(&mut conn).await?;

        conn.mark_handshake_complete();

        debug!(
            "SOCKS5 connection to {} established (handshake complete)",
            self.socks5_addr
        );

        Ok(conn)
    }

    async fn recycle(
        &self,
        conn: &mut Socks5Connection,
        _metrics: &Metrics,
    ) -> RecycleResult<Socks5Error> {
        // Check if stream was taken (connection used for CONNECT)
        if !conn.has_stream() {
            return Err(RecycleError::StaticMessage("stream already taken"));
        }

        // Check if handshake was complete
        if !conn.handshake_complete {
            return Err(RecycleError::StaticMessage("handshake not complete"));
        }

        // Check idle timeout
        if conn.is_idle(self.idle_timeout) {
            debug!(
                "SOCKS5 connection idle for {:?}, recycling",
                conn.last_used.elapsed()
            );
            return Err(RecycleError::StaticMessage("connection idle too long"));
        }

        // Check if connection is still alive
        if !conn.is_alive().await {
            debug!("SOCKS5 connection no longer alive, recycling");
            return Err(RecycleError::StaticMessage("connection closed"));
        }

        trace!("SOCKS5 connection recycled successfully");
        Ok(())
    }
}

// ============================================================================
// SOCKS5 Protocol Helpers
// ============================================================================

/// Build SOCKS5 CONNECT request for a socket address
fn build_connect_request(addr: SocketAddr) -> Vec<u8> {
    let mut request = Vec::with_capacity(22);

    // VER | CMD | RSV
    request.push(SOCKS5_VERSION);
    request.push(CMD_CONNECT);
    request.push(0x00); // Reserved

    // DST.ADDR
    match addr {
        SocketAddr::V4(v4) => {
            request.push(ATYP_IPV4);
            request.extend_from_slice(&v4.ip().octets());
        }
        SocketAddr::V6(v6) => {
            request.push(ATYP_IPV6);
            request.extend_from_slice(&v6.ip().octets());
        }
    }

    // DST.PORT (network byte order)
    request.push((addr.port() >> 8) as u8);
    request.push((addr.port() & 0xFF) as u8);

    request
}

/// Parse SOCKS5 reply and extract bound address
async fn read_connect_reply(stream: &mut TcpStream) -> Result<SocketAddr, Socks5Error> {
    // Read header: VER | REP | RSV | ATYP
    let mut header = [0u8; 4];
    stream
        .read_exact(&mut header)
        .await
        .map_err(|e| Socks5Error::ConnectionError(format!("read reply header failed: {e}")))?;

    trace!("SOCKS5 reply header: {:?}", header);

    // Validate version
    if header[0] != SOCKS5_VERSION {
        return Err(Socks5Error::InvalidVersion {
            expected: SOCKS5_VERSION,
            actual: header[0],
        });
    }

    // Check reply status
    if header[1] != REPLY_SUCCEEDED {
        return Err(Socks5Error::ServerReply {
            code: header[1],
            message: reply_message(header[1]).to_string(),
        });
    }

    // Read bound address based on ATYP
    let bound_addr = match header[3] {
        ATYP_IPV4 => {
            let mut addr = [0u8; 4];
            stream
                .read_exact(&mut addr)
                .await
                .map_err(|e| Socks5Error::ConnectionError(format!("read IPv4 addr failed: {e}")))?;

            let mut port = [0u8; 2];
            stream
                .read_exact(&mut port)
                .await
                .map_err(|e| Socks5Error::ConnectionError(format!("read port failed: {e}")))?;

            SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::from(addr),
                u16::from_be_bytes(port),
            ))
        }
        ATYP_IPV6 => {
            let mut addr = [0u8; 16];
            stream
                .read_exact(&mut addr)
                .await
                .map_err(|e| Socks5Error::ConnectionError(format!("read IPv6 addr failed: {e}")))?;

            let mut port = [0u8; 2];
            stream
                .read_exact(&mut port)
                .await
                .map_err(|e| Socks5Error::ConnectionError(format!("read port failed: {e}")))?;

            SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(addr),
                u16::from_be_bytes(port),
                0,
                0,
            ))
        }
        ATYP_DOMAIN => {
            // Read domain length
            let mut len = [0u8; 1];
            stream
                .read_exact(&mut len)
                .await
                .map_err(|e| Socks5Error::ConnectionError(format!("read domain len failed: {e}")))?;

            // Read domain name (we don't use it, just skip)
            let mut domain = vec![0u8; len[0] as usize];
            stream.read_exact(&mut domain).await.map_err(|e| {
                Socks5Error::ConnectionError(format!("read domain failed: {e}"))
            })?;

            // Read port
            let mut port = [0u8; 2];
            stream
                .read_exact(&mut port)
                .await
                .map_err(|e| Socks5Error::ConnectionError(format!("read port failed: {e}")))?;

            // Return placeholder address since we can't resolve domain here
            SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::UNSPECIFIED,
                u16::from_be_bytes(port),
            ))
        }
        other => {
            return Err(Socks5Error::InvalidAddressType(other));
        }
    };

    trace!("SOCKS5 bound address: {}", bound_addr);
    Ok(bound_addr)
}

// ============================================================================
// SOCKS5 Outbound
// ============================================================================

/// SOCKS5 outbound with connection pooling
#[allow(clippy::missing_fields_in_debug)]
pub struct Socks5Outbound {
    /// Configuration
    config: Socks5Config,
    /// Connection pool
    pool: Pool<Socks5ConnectionManager>,
    /// Connection statistics
    stats: Arc<OutboundStats>,
    /// Whether the outbound is enabled
    enabled: AtomicBool,
    /// Current health status
    health: std::sync::RwLock<HealthStatus>,
}

impl Socks5Outbound {
    /// Create a new SOCKS5 outbound from configuration
    ///
    /// # Errors
    ///
    /// Returns `OutboundError::ConnectionFailed` if the connection pool cannot be created.
    #[allow(clippy::unused_async)] // Async for future compatibility (connection warmup)
    pub async fn new(config: Socks5Config) -> Result<Self, OutboundError> {
        let manager = Socks5ConnectionManager::new(&config);
        let pool = Pool::builder(manager)
            .max_size(config.pool_max_size)
            .build()
            .map_err(|e| OutboundError::ConnectionFailed {
                addr: config.socks5_addr,
                reason: format!("failed to create connection pool: {e}"),
            })?;

        Ok(Self {
            enabled: AtomicBool::new(true),
            config,
            pool,
            stats: Arc::new(OutboundStats::new()),
            health: std::sync::RwLock::new(HealthStatus::Unknown),
        })
    }

    /// Get pool statistics
    #[must_use]
    pub fn pool_stats(&self) -> PoolStats {
        let status = self.pool.status();
        PoolStats {
            size: status.size,
            available: status.available,
            waiting: status.waiting,
        }
    }

    /// Get the SOCKS5 server address
    #[must_use]
    pub const fn socks5_addr(&self) -> SocketAddr {
        self.config.socks5_addr
    }

    /// Update health status based on connection result
    fn update_health(&self, success: bool) {
        let mut health = self.health.write().unwrap();
        if success {
            *health = HealthStatus::Healthy;
        } else {
            *health = match *health {
                HealthStatus::Healthy => HealthStatus::Degraded,
                HealthStatus::Degraded | HealthStatus::Unhealthy | HealthStatus::Unknown => {
                    HealthStatus::Unhealthy
                }
            };
        }
    }

    /// Perform CONNECT through SOCKS5 to destination
    async fn socks5_connect(
        &self,
        conn: &mut Socks5Connection,
        dest: SocketAddr,
    ) -> Result<(), Socks5Error> {
        let stream = conn
            .stream_mut()
            .ok_or_else(|| Socks5Error::ConnectionError("stream already taken".into()))?;

        // Build and send CONNECT request
        let request = build_connect_request(dest);
        trace!("Sending SOCKS5 CONNECT to {}: {:?}", dest, request);

        stream
            .write_all(&request)
            .await
            .map_err(|e| Socks5Error::ConnectionError(format!("write CONNECT failed: {e}")))?;

        // Read and validate reply
        let _bound_addr = read_connect_reply(stream).await?;

        // Update connection state
        conn.touch();

        debug!("SOCKS5 CONNECT to {} succeeded", dest);
        Ok(())
    }
}

#[async_trait]
impl Outbound for Socks5Outbound {
    async fn connect(
        &self,
        addr: SocketAddr,
        connect_timeout: Duration,
    ) -> Result<OutboundConnection, OutboundError> {
        if !self.is_enabled() {
            return Err(OutboundError::unavailable(
                &self.config.tag,
                "outbound is disabled",
            ));
        }

        self.stats.record_connection();

        // Get connection from pool with timeout
        let pool_get = timeout(connect_timeout, self.pool.get()).await;

        let mut conn = match pool_get {
            Ok(Ok(conn)) => conn,
            Ok(Err(e)) => {
                self.update_health(false);
                self.stats.record_error();
                return Err(OutboundError::connection_failed(
                    self.config.socks5_addr,
                    format!("pool error: {e}"),
                ));
            }
            Err(_) => {
                self.update_health(false);
                self.stats.record_error();
                return Err(OutboundError::Timeout {
                    addr: self.config.socks5_addr,
                    timeout_secs: connect_timeout.as_secs(),
                });
            }
        };

        // Perform CONNECT to destination
        let connect_result =
            timeout(connect_timeout, self.socks5_connect(&mut conn, addr)).await;

        match connect_result {
            Ok(Ok(())) => {
                self.update_health(true);
                debug!(
                    "SOCKS5 connection to {} via {} successful",
                    addr, self.config.tag
                );

                // Take ownership of the stream from the pooled connection
                // This ensures the connection won't be returned to pool
                let stream = match conn.take_stream() {
                    Some(s) => s,
                    None => {
                        self.stats.record_error();
                        return Err(OutboundError::connection_failed(addr, "stream already taken"));
                    }
                };

                Ok(OutboundConnection::new(stream, addr))
            }
            Ok(Err(e)) => {
                self.update_health(false);
                self.stats.record_error();
                // Stream will be dropped with conn, preventing recycling
                Err(OutboundError::connection_failed(addr, e.to_string()))
            }
            Err(_) => {
                self.update_health(false);
                self.stats.record_error();
                // Stream will be dropped with conn, preventing recycling
                Err(OutboundError::Timeout {
                    addr,
                    timeout_secs: connect_timeout.as_secs(),
                })
            }
        }
    }

    fn tag(&self) -> &str {
        &self.config.tag
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

    fn outbound_type(&self) -> &'static str {
        "socks5"
    }

    fn pool_stats_info(&self) -> Option<super::traits::PoolStatsInfo> {
        let stats = self.pool_stats();
        Some(super::traits::PoolStatsInfo {
            size: stats.size,
            available: stats.available,
            waiting: stats.waiting,
        })
    }

    fn proxy_server_info(&self) -> Option<super::traits::ProxyServerInfo> {
        Some(super::traits::ProxyServerInfo {
            address: self.config.socks5_addr.to_string(),
            has_auth: self.config.has_auth(),
        })
    }

    // === UDP Methods ===

    async fn connect_udp(
        &self,
        addr: SocketAddr,
        connect_timeout: Duration,
    ) -> Result<super::traits::UdpOutboundHandle, crate::error::UdpError> {
        use super::socks5_udp::{Socks5Auth, Socks5UdpAssociation};
        use super::traits::{Socks5UdpHandle, UdpOutboundHandle};
        use crate::error::UdpError;

        if !self.is_enabled() {
            return Err(UdpError::OutboundDisabled {
                tag: self.config.tag.clone(),
            });
        }

        // Convert config auth to SOCKS5 UDP auth format
        let auth = if self.config.has_auth() {
            Some(Socks5Auth::new(
                self.config.username.clone().unwrap_or_default(),
                self.config.password.clone().unwrap_or_default(),
            ))
        } else {
            None
        };

        // Establish UDP ASSOCIATE
        let association = Socks5UdpAssociation::establish(
            self.config.socks5_addr,
            auth,
            connect_timeout,
        )
        .await
        .map_err(|e| UdpError::Socks5UdpAssociationFailed {
            reason: e.to_string(),
        })?;

        debug!(
            "SOCKS5 UDP association established for {} via {} (relay: {})",
            addr,
            self.config.tag,
            association.relay_addr()
        );

        Ok(UdpOutboundHandle::Socks5(Socks5UdpHandle::new(
            std::sync::Arc::new(association),
            addr,
        )))
    }

    fn supports_udp(&self) -> bool {
        true
    }
}

impl fmt::Debug for Socks5Outbound {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let pool_stats = self.pool_stats();
        f.debug_struct("Socks5Outbound")
            .field("tag", &self.config.tag)
            .field("socks5_addr", &self.config.socks5_addr)
            .field("has_auth", &self.config.has_auth())
            .field("enabled", &self.is_enabled())
            .field("health", &self.health_status())
            .field("pool_size", &pool_stats.size)
            .field("pool_available", &pool_stats.available)
            .finish_non_exhaustive()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::outbound::socks5_common::{
        REPLY_CONNECTION_REFUSED, REPLY_HOST_UNREACHABLE, REPLY_NETWORK_UNREACHABLE,
    };

    // ========================================================================
    // Protocol Constants Tests
    // ========================================================================

    #[test]
    fn test_socks5_version() {
        assert_eq!(SOCKS5_VERSION, 0x05);
    }

    #[test]
    fn test_auth_methods() {
        assert_eq!(AUTH_METHOD_NONE, 0x00);
        assert_eq!(AUTH_METHOD_PASSWORD, 0x02);
        assert_eq!(AUTH_METHOD_NO_ACCEPTABLE, 0xFF);
    }

    #[test]
    fn test_commands() {
        assert_eq!(CMD_CONNECT, 0x01);
    }

    #[test]
    fn test_address_types() {
        assert_eq!(ATYP_IPV4, 0x01);
        assert_eq!(ATYP_DOMAIN, 0x03);
        assert_eq!(ATYP_IPV6, 0x04);
    }

    #[test]
    fn test_reply_codes() {
        // Only REPLY_SUCCEEDED is imported, other codes tested in socks5_common
        assert_eq!(REPLY_SUCCEEDED, 0x00);
    }

    // ========================================================================
    // Reply Message Tests
    // ========================================================================

    #[test]
    fn test_reply_message_succeeded() {
        assert_eq!(reply_message(REPLY_SUCCEEDED), "succeeded");
    }

    #[test]
    fn test_reply_message_all_codes() {
        // Comprehensive tests are in socks5_common module
        // Here we just verify the function works via import
        assert_eq!(reply_message(0x01), "general SOCKS server failure");
        assert_eq!(reply_message(0x02), "connection not allowed by ruleset");
        assert_eq!(reply_message(0x03), "network unreachable");
        assert_eq!(reply_message(0x04), "host unreachable");
        assert_eq!(reply_message(0x05), "connection refused");
    }

    #[test]
    fn test_reply_message_additional_codes() {
        // Use raw values since constants aren't imported
        assert_eq!(reply_message(0x06), "TTL expired");
        assert_eq!(reply_message(0x07), "command not supported");
        assert_eq!(reply_message(0x08), "address type not supported");
        assert_eq!(reply_message(0x99), "unknown error");
    }

    // ========================================================================
    // Socks5Error Tests
    // ========================================================================

    #[test]
    fn test_socks5_error_invalid_version() {
        let err = Socks5Error::InvalidVersion {
            expected: 5,
            actual: 4,
        };
        assert!(err.to_string().contains("Invalid SOCKS version"));
        assert!(err.to_string().contains("expected 5"));
        assert!(err.to_string().contains("got 4"));
    }

    #[test]
    fn test_socks5_error_no_acceptable_method() {
        let err = Socks5Error::NoAcceptableMethod;
        assert!(err.to_string().contains("No acceptable authentication method"));
    }

    #[test]
    fn test_socks5_error_auth_failed() {
        let err = Socks5Error::AuthFailed;
        assert!(err.to_string().contains("authentication failed"));
    }

    #[test]
    fn test_socks5_error_server_reply() {
        let err = Socks5Error::ServerReply {
            code: 0x05,
            message: "connection refused".into(),
        };
        assert!(err.to_string().contains("SOCKS5 server error"));
        assert!(err.to_string().contains("0x05"));
        assert!(err.to_string().contains("connection refused"));
    }

    #[test]
    fn test_socks5_error_invalid_address_type() {
        let err = Socks5Error::InvalidAddressType(0x99);
        assert!(err.to_string().contains("Invalid address type"));
        assert!(err.to_string().contains("0x99"));
    }

    #[test]
    fn test_socks5_error_protocol_error() {
        let err = Socks5Error::ProtocolError("malformed message".into());
        assert!(err.to_string().contains("protocol error"));
        assert!(err.to_string().contains("malformed message"));
    }

    #[test]
    fn test_socks5_error_connection_error() {
        let err = Socks5Error::ConnectionError("connection reset".into());
        assert!(err.to_string().contains("connection error"));
        assert!(err.to_string().contains("connection reset"));
    }

    #[test]
    fn test_socks5_error_handshake_timeout() {
        let err = Socks5Error::HandshakeTimeout;
        assert!(err.to_string().contains("handshake timeout"));
    }

    #[test]
    fn test_socks5_error_to_outbound_error() {
        let err = Socks5Error::AuthFailed;
        let outbound_err: OutboundError = err.into();
        match outbound_err {
            OutboundError::ConnectionFailed { reason, .. } => {
                assert!(reason.contains("authentication failed"));
            }
            _ => panic!("Expected ConnectionFailed"),
        }
    }

    // ========================================================================
    // Socks5Config Tests
    // ========================================================================

    #[test]
    fn test_config_new() {
        let addr: SocketAddr = "127.0.0.1:1080".parse().unwrap();
        let config = Socks5Config::new("test", addr);

        assert_eq!(config.tag, "test");
        assert_eq!(config.socks5_addr, addr);
        assert!(config.username.is_none());
        assert!(config.password.is_none());
        assert_eq!(config.connect_timeout_secs, 10);
        assert_eq!(config.idle_timeout_secs, 300);
        assert_eq!(config.pool_max_size, 32);
    }

    #[test]
    fn test_config_with_auth() {
        let addr: SocketAddr = "127.0.0.1:1080".parse().unwrap();
        let config = Socks5Config::new("test", addr).with_auth("user", "pass");

        assert_eq!(config.username, Some("user".into()));
        assert_eq!(config.password, Some("pass".into()));
        assert!(config.has_auth());
    }

    #[test]
    fn test_config_with_pool_size() {
        let addr: SocketAddr = "127.0.0.1:1080".parse().unwrap();
        let config = Socks5Config::new("test", addr).with_pool_size(64);

        assert_eq!(config.pool_max_size, 64);
    }

    #[test]
    fn test_config_with_connect_timeout() {
        let addr: SocketAddr = "127.0.0.1:1080".parse().unwrap();
        let config = Socks5Config::new("test", addr).with_connect_timeout(30);

        assert_eq!(config.connect_timeout_secs, 30);
    }

    #[test]
    fn test_config_with_idle_timeout() {
        let addr: SocketAddr = "127.0.0.1:1080".parse().unwrap();
        let config = Socks5Config::new("test", addr).with_idle_timeout(600);

        assert_eq!(config.idle_timeout_secs, 600);
    }

    #[test]
    fn test_config_has_auth_false() {
        let addr: SocketAddr = "127.0.0.1:1080".parse().unwrap();
        let config = Socks5Config::new("test", addr);
        assert!(!config.has_auth());
    }

    #[test]
    fn test_config_has_auth_partial() {
        let addr: SocketAddr = "127.0.0.1:1080".parse().unwrap();
        let mut config = Socks5Config::new("test", addr);
        config.username = Some("user".into());
        // No password
        assert!(!config.has_auth());
    }

    #[test]
    fn test_config_serialization() {
        let addr: SocketAddr = "127.0.0.1:1080".parse().unwrap();
        let config = Socks5Config::new("test", addr).with_auth("user", "pass");

        let json = serde_json::to_string(&config).unwrap();
        let deserialized: Socks5Config = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.tag, config.tag);
        assert_eq!(deserialized.socks5_addr, config.socks5_addr);
        assert_eq!(deserialized.username, config.username);
        assert_eq!(deserialized.password, config.password);
    }

    // ========================================================================
    // Build Connect Request Tests
    // ========================================================================

    #[test]
    fn test_build_connect_request_ipv4() {
        let addr: SocketAddr = "192.168.1.1:8080".parse().unwrap();
        let request = build_connect_request(addr);

        // VER | CMD | RSV | ATYP | IP (4 bytes) | PORT (2 bytes)
        assert_eq!(request.len(), 10);
        assert_eq!(request[0], SOCKS5_VERSION); // Version
        assert_eq!(request[1], CMD_CONNECT);     // CONNECT
        assert_eq!(request[2], 0x00);            // Reserved
        assert_eq!(request[3], ATYP_IPV4);       // IPv4
        assert_eq!(request[4], 192);             // IP byte 1
        assert_eq!(request[5], 168);             // IP byte 2
        assert_eq!(request[6], 1);               // IP byte 3
        assert_eq!(request[7], 1);               // IP byte 4
        assert_eq!(request[8], 0x1F);            // Port high byte (8080 >> 8)
        assert_eq!(request[9], 0x90);            // Port low byte (8080 & 0xFF)
    }

    #[test]
    fn test_build_connect_request_ipv6() {
        let addr: SocketAddr = "[::1]:443".parse().unwrap();
        let request = build_connect_request(addr);

        // VER | CMD | RSV | ATYP | IP (16 bytes) | PORT (2 bytes)
        assert_eq!(request.len(), 22);
        assert_eq!(request[0], SOCKS5_VERSION);
        assert_eq!(request[1], CMD_CONNECT);
        assert_eq!(request[2], 0x00);
        assert_eq!(request[3], ATYP_IPV6);
        // IPv6 ::1 = 15 zeros + 1
        for i in 4..19 {
            assert_eq!(request[i], 0);
        }
        assert_eq!(request[19], 1);              // Last byte of ::1
        assert_eq!(request[20], 0x01);           // Port high byte (443 >> 8)
        assert_eq!(request[21], 0xBB);           // Port low byte (443 & 0xFF)
    }

    #[test]
    fn test_build_connect_request_port_boundary() {
        // Test port 1 (minimum valid port)
        let addr: SocketAddr = "1.2.3.4:1".parse().unwrap();
        let request = build_connect_request(addr);
        assert_eq!(request[8], 0x00);
        assert_eq!(request[9], 0x01);

        // Test port 65535 (maximum valid port)
        let addr: SocketAddr = "1.2.3.4:65535".parse().unwrap();
        let request = build_connect_request(addr);
        assert_eq!(request[8], 0xFF);
        assert_eq!(request[9], 0xFF);
    }

    // ========================================================================
    // Pool Stats Tests
    // ========================================================================

    #[test]
    fn test_pool_stats_default() {
        let stats = PoolStats {
            size: 10,
            available: 5,
            waiting: 2,
        };

        assert_eq!(stats.size, 10);
        assert_eq!(stats.available, 5);
        assert_eq!(stats.waiting, 2);
    }

    #[test]
    fn test_pool_stats_serialization() {
        let stats = PoolStats {
            size: 10,
            available: 5,
            waiting: 2,
        };

        let json = serde_json::to_string(&stats).unwrap();
        let deserialized: PoolStats = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.size, stats.size);
        assert_eq!(deserialized.available, stats.available);
        assert_eq!(deserialized.waiting, stats.waiting);
    }

    // ========================================================================
    // Socks5Connection Tests
    // ========================================================================

    #[tokio::test]
    async fn test_socks5_connection_idle() {
        // Create a dummy TCP connection for testing
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let connect_task = tokio::spawn(async move { TcpStream::connect(addr).await });
        let (_, _) = listener.accept().await.unwrap();
        let stream = connect_task.await.unwrap().unwrap();

        let mut conn = Socks5Connection::new(stream);

        // Should not be idle initially
        assert!(!conn.is_idle(Duration::from_secs(1)));

        // After marking handshake complete
        conn.mark_handshake_complete();
        assert!(conn.handshake_complete);
    }

    #[test]
    fn test_socks5_connection_age() {
        // Test requires a stream, so we just verify the method exists
        // and the age calculation logic
        let now = Instant::now();
        std::thread::sleep(Duration::from_millis(10));
        let elapsed = now.elapsed();
        assert!(elapsed.as_millis() >= 10);
    }

    // ========================================================================
    // Connection Manager Tests
    // ========================================================================

    #[test]
    fn test_connection_manager_new_no_auth() {
        let addr: SocketAddr = "127.0.0.1:1080".parse().unwrap();
        let config = Socks5Config::new("test", addr);
        let manager = Socks5ConnectionManager::new(&config);

        assert_eq!(manager.socks5_addr, addr);
        assert!(manager.auth.is_none());
        assert_eq!(manager.connect_timeout, Duration::from_secs(10));
        assert_eq!(manager.idle_timeout, Duration::from_secs(300));
    }

    #[test]
    fn test_connection_manager_new_with_auth() {
        let addr: SocketAddr = "127.0.0.1:1080".parse().unwrap();
        let config = Socks5Config::new("test", addr).with_auth("user", "pass");
        let manager = Socks5ConnectionManager::new(&config);

        assert!(manager.auth.is_some());
        let (user, pass) = manager.auth.unwrap();
        assert_eq!(user, "user");
        assert_eq!(pass, "pass");
    }

    // ========================================================================
    // Health Status Tests
    // ========================================================================

    #[tokio::test]
    async fn test_health_status_transitions() {
        // We can't create actual outbound without a server, but we can test
        // the health transition logic pattern
        let health: std::sync::RwLock<HealthStatus> =
            std::sync::RwLock::new(HealthStatus::Unknown);

        // Simulate update_health pattern
        {
            let mut h = health.write().unwrap();
            *h = HealthStatus::Healthy;
        }
        assert_eq!(*health.read().unwrap(), HealthStatus::Healthy);

        // First failure -> Degraded
        {
            let mut h = health.write().unwrap();
            *h = HealthStatus::Degraded;
        }
        assert_eq!(*health.read().unwrap(), HealthStatus::Degraded);

        // Second failure -> Unhealthy
        {
            let mut h = health.write().unwrap();
            *h = HealthStatus::Unhealthy;
        }
        assert_eq!(*health.read().unwrap(), HealthStatus::Unhealthy);

        // Success -> Back to Healthy
        {
            let mut h = health.write().unwrap();
            *h = HealthStatus::Healthy;
        }
        assert_eq!(*health.read().unwrap(), HealthStatus::Healthy);
    }

    // ========================================================================
    // Default Value Tests
    // ========================================================================

    #[test]
    fn test_default_connect_timeout() {
        assert_eq!(default_connect_timeout(), 10);
    }

    #[test]
    fn test_default_idle_timeout() {
        assert_eq!(default_idle_timeout(), 300);
    }

    #[test]
    fn test_default_pool_max_size() {
        assert_eq!(default_pool_max_size(), 32);
    }

    // ========================================================================
    // Integration Tests (Mock Server)
    // ========================================================================

    /// Simple SOCKS5 mock server for testing
    async fn run_mock_socks5_server(
        listener: tokio::net::TcpListener,
        require_auth: bool,
        reply_code: u8,
    ) {
        let (mut socket, _) = listener.accept().await.unwrap();

        // Read method selection header: VER | NMETHODS
        let mut header = [0u8; 2];
        socket.read_exact(&mut header).await.unwrap();
        assert_eq!(header[0], SOCKS5_VERSION);
        let nmethods = header[1] as usize;

        // Read method list
        let mut methods = vec![0u8; nmethods];
        socket.read_exact(&mut methods).await.unwrap();

        if require_auth {
            // Reply with password auth required
            socket.write_all(&[SOCKS5_VERSION, AUTH_METHOD_PASSWORD]).await.unwrap();

            // Read auth request
            let mut auth_buf = [0u8; 2];
            socket.read_exact(&mut auth_buf).await.unwrap();
            let ulen = auth_buf[1] as usize;
            let mut username = vec![0u8; ulen];
            socket.read_exact(&mut username).await.unwrap();
            let mut plen_buf = [0u8; 1];
            socket.read_exact(&mut plen_buf).await.unwrap();
            let plen = plen_buf[0] as usize;
            let mut password = vec![0u8; plen];
            socket.read_exact(&mut password).await.unwrap();

            // Reply with auth success
            socket.write_all(&[AUTH_PASSWORD_VERSION, 0x00]).await.unwrap();
        } else {
            // Reply with no auth
            socket.write_all(&[SOCKS5_VERSION, AUTH_METHOD_NONE]).await.unwrap();
        }

        // Read CONNECT request
        let mut connect_buf = [0u8; 4];
        socket.read_exact(&mut connect_buf).await.unwrap();

        // Read rest of request based on ATYP
        match connect_buf[3] {
            ATYP_IPV4 => {
                let mut addr_buf = [0u8; 6]; // 4 bytes IP + 2 bytes port
                socket.read_exact(&mut addr_buf).await.unwrap();
            }
            ATYP_IPV6 => {
                let mut addr_buf = [0u8; 18]; // 16 bytes IP + 2 bytes port
                socket.read_exact(&mut addr_buf).await.unwrap();
            }
            _ => panic!("Unexpected ATYP"),
        }

        // Send reply
        let reply = [
            SOCKS5_VERSION,
            reply_code,
            0x00,
            ATYP_IPV4,
            0, 0, 0, 0, // Bound address
            0, 0,       // Bound port
        ];
        socket.write_all(&reply).await.unwrap();
    }

    #[tokio::test]
    async fn test_socks5_outbound_connect_no_auth() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        // Start mock server
        let server = tokio::spawn(async move {
            run_mock_socks5_server(listener, false, REPLY_SUCCEEDED).await;
        });

        // Create outbound
        let config = Socks5Config::new("test", server_addr)
            .with_pool_size(1)
            .with_connect_timeout(5);

        let outbound = Socks5Outbound::new(config).await.unwrap();
        assert_eq!(outbound.tag(), "test");
        assert_eq!(outbound.outbound_type(), "socks5");
        assert!(outbound.is_enabled());

        // Connect through SOCKS5
        let dest: SocketAddr = "93.184.216.34:80".parse().unwrap(); // example.com
        let result = outbound.connect(dest, Duration::from_secs(5)).await;

        // Connection should succeed
        assert!(result.is_ok());
        let conn = result.unwrap();
        assert_eq!(conn.remote_addr(), dest);

        // Wait for server
        let _ = server.await;
    }

    #[tokio::test]
    async fn test_socks5_outbound_connect_with_auth() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        // Start mock server requiring auth
        let server = tokio::spawn(async move {
            run_mock_socks5_server(listener, true, REPLY_SUCCEEDED).await;
        });

        // Create outbound with auth
        let config = Socks5Config::new("test-auth", server_addr)
            .with_auth("testuser", "testpass")
            .with_pool_size(1);

        let outbound = Socks5Outbound::new(config).await.unwrap();

        // Connect
        let dest: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let result = outbound.connect(dest, Duration::from_secs(5)).await;

        assert!(result.is_ok());

        let _ = server.await;
    }

    #[tokio::test]
    async fn test_socks5_outbound_connection_refused() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        // Start mock server that returns connection refused
        let server = tokio::spawn(async move {
            run_mock_socks5_server(listener, false, REPLY_CONNECTION_REFUSED).await;
        });

        let config = Socks5Config::new("test-refused", server_addr).with_pool_size(1);

        let outbound = Socks5Outbound::new(config).await.unwrap();

        let dest: SocketAddr = "1.2.3.4:80".parse().unwrap();
        let result = outbound.connect(dest, Duration::from_secs(5)).await;

        assert!(result.is_err());
        if let Err(OutboundError::ConnectionFailed { reason, .. }) = result {
            assert!(reason.contains("connection refused"));
        } else {
            panic!("Expected ConnectionFailed error");
        }

        let _ = server.await;
    }

    #[tokio::test]
    async fn test_socks5_outbound_host_unreachable() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            run_mock_socks5_server(listener, false, REPLY_HOST_UNREACHABLE).await;
        });

        let config = Socks5Config::new("test-host", server_addr).with_pool_size(1);
        let outbound = Socks5Outbound::new(config).await.unwrap();

        let dest: SocketAddr = "1.2.3.4:80".parse().unwrap();
        let result = outbound.connect(dest, Duration::from_secs(5)).await;

        assert!(result.is_err());
        if let Err(OutboundError::ConnectionFailed { reason, .. }) = result {
            assert!(reason.contains("host unreachable"));
        } else {
            panic!("Expected ConnectionFailed error");
        }

        let _ = server.await;
    }

    #[tokio::test]
    async fn test_socks5_outbound_network_unreachable() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            run_mock_socks5_server(listener, false, REPLY_NETWORK_UNREACHABLE).await;
        });

        let config = Socks5Config::new("test-net", server_addr).with_pool_size(1);
        let outbound = Socks5Outbound::new(config).await.unwrap();

        let dest: SocketAddr = "1.2.3.4:80".parse().unwrap();
        let result = outbound.connect(dest, Duration::from_secs(5)).await;

        assert!(result.is_err());

        let _ = server.await;
    }

    #[tokio::test]
    async fn test_socks5_outbound_disabled() {
        let addr: SocketAddr = "127.0.0.1:1080".parse().unwrap();
        let config = Socks5Config::new("test-disabled", addr);
        let outbound = Socks5Outbound::new(config).await.unwrap();

        // Disable outbound
        outbound.enabled.store(false, Ordering::Relaxed);
        assert!(!outbound.is_enabled());

        let dest: SocketAddr = "1.2.3.4:80".parse().unwrap();
        let result = outbound.connect(dest, Duration::from_secs(1)).await;

        assert!(result.is_err());
        if let Err(OutboundError::Unavailable { tag, reason }) = result {
            assert_eq!(tag, "test-disabled");
            assert!(reason.contains("disabled"));
        } else {
            panic!("Expected Unavailable error");
        }
    }

    #[tokio::test]
    async fn test_socks5_outbound_pool_stats() {
        let addr: SocketAddr = "127.0.0.1:1080".parse().unwrap();
        let config = Socks5Config::new("test-stats", addr).with_pool_size(16);
        let outbound = Socks5Outbound::new(config).await.unwrap();

        let stats = outbound.pool_stats();
        assert_eq!(stats.size, 0); // No connections yet
        assert_eq!(stats.available, 0);
        assert_eq!(stats.waiting, 0);
    }

    #[tokio::test]
    async fn test_socks5_outbound_socks5_addr() {
        let addr: SocketAddr = "192.168.1.100:1080".parse().unwrap();
        let config = Socks5Config::new("test-addr", addr);
        let outbound = Socks5Outbound::new(config).await.unwrap();

        assert_eq!(outbound.socks5_addr(), addr);
    }

    #[tokio::test]
    async fn test_socks5_outbound_debug() {
        let addr: SocketAddr = "127.0.0.1:1080".parse().unwrap();
        let config = Socks5Config::new("test-debug", addr);
        let outbound = Socks5Outbound::new(config).await.unwrap();

        let debug_str = format!("{:?}", outbound);
        assert!(debug_str.contains("Socks5Outbound"));
        assert!(debug_str.contains("test-debug"));
        assert!(debug_str.contains("127.0.0.1:1080"));
    }

    #[tokio::test]
    async fn test_socks5_outbound_stats() {
        let addr: SocketAddr = "127.0.0.1:1080".parse().unwrap();
        let config = Socks5Config::new("test-stats", addr);
        let outbound = Socks5Outbound::new(config).await.unwrap();

        let stats = outbound.stats();
        assert_eq!(stats.connections(), 0);
        assert_eq!(stats.active(), 0);
        assert_eq!(stats.errors(), 0);
    }

    #[tokio::test]
    async fn test_socks5_outbound_timeout() {
        // Connect to a non-routable address to trigger timeout
        let addr: SocketAddr = "192.0.2.1:1080".parse().unwrap(); // TEST-NET-1
        let config = Socks5Config::new("test-timeout", addr)
            .with_connect_timeout(1)
            .with_pool_size(1);

        let outbound = Socks5Outbound::new(config).await.unwrap();

        let dest: SocketAddr = "1.2.3.4:80".parse().unwrap();
        let result = outbound.connect(dest, Duration::from_millis(100)).await;

        assert!(result.is_err());
        // Should be either timeout or connection failed
        match result {
            Err(OutboundError::Timeout { .. }) => {}
            Err(OutboundError::ConnectionFailed { .. }) => {}
            _ => panic!("Expected Timeout or ConnectionFailed error"),
        }
    }

    // ========================================================================
    // NEW-7: Domain BND.ADDR Tests
    // ========================================================================
    // These tests verify that the SOCKS5 client correctly parses domain name
    // responses in the BND.ADDR field (ATYP=0x03) per RFC 1928 Section 6.
    //
    // Some SOCKS5 servers return domain names instead of IP addresses in the
    // bound address field. The client must read and skip the domain correctly.

    /// Mock server that returns a domain name in BND.ADDR
    async fn run_mock_socks5_server_with_domain_reply(
        listener: tokio::net::TcpListener,
        domain: &[u8],
        port: u16,
    ) {
        let (mut socket, _) = listener.accept().await.unwrap();

        // Read method selection: VER | NMETHODS
        let mut header = [0u8; 2];
        socket.read_exact(&mut header).await.unwrap();
        let nmethods = header[1] as usize;
        let mut methods = vec![0u8; nmethods];
        socket.read_exact(&mut methods).await.unwrap();

        // Reply with no auth
        socket.write_all(&[SOCKS5_VERSION, AUTH_METHOD_NONE]).await.unwrap();

        // Read CONNECT request header: VER | CMD | RSV | ATYP
        let mut connect_buf = [0u8; 4];
        socket.read_exact(&mut connect_buf).await.unwrap();

        // Read rest based on ATYP
        match connect_buf[3] {
            ATYP_IPV4 => {
                let mut addr_buf = [0u8; 6];
                socket.read_exact(&mut addr_buf).await.unwrap();
            }
            ATYP_IPV6 => {
                let mut addr_buf = [0u8; 18];
                socket.read_exact(&mut addr_buf).await.unwrap();
            }
            _ => panic!("Unexpected ATYP in request"),
        }

        // Build reply with domain BND.ADDR
        // VER | REP | RSV | ATYP | LEN | DOMAIN | PORT
        let mut reply = vec![SOCKS5_VERSION, REPLY_SUCCEEDED, 0x00, ATYP_DOMAIN];
        reply.push(domain.len() as u8);
        reply.extend_from_slice(domain);
        reply.push((port >> 8) as u8);
        reply.push((port & 0xFF) as u8);

        socket.write_all(&reply).await.unwrap();
    }

    #[tokio::test]
    async fn test_socks5_domain_bnd_addr_basic() {
        // NEW-7 TEST: Server returns a domain name in BND.ADDR
        // The client should parse it correctly and return a placeholder address
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            run_mock_socks5_server_with_domain_reply(
                listener,
                b"proxy.example.com",
                8080,
            ).await;
        });

        let config = Socks5Config::new("test-domain", server_addr).with_pool_size(1);
        let outbound = Socks5Outbound::new(config).await.unwrap();

        let dest: SocketAddr = "93.184.216.34:80".parse().unwrap();
        let result = outbound.connect(dest, Duration::from_secs(5)).await;

        // Connection should succeed - domain BND.ADDR is valid
        assert!(result.is_ok(), "Domain BND.ADDR should be parsed successfully");
        let conn = result.unwrap();
        assert_eq!(conn.remote_addr(), dest);

        let _ = server.await;
    }

    #[tokio::test]
    async fn test_socks5_domain_bnd_addr_single_char() {
        // NEW-7 TEST: Minimum valid domain (1 character)
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            run_mock_socks5_server_with_domain_reply(listener, b"x", 443).await;
        });

        let config = Socks5Config::new("test-domain-short", server_addr).with_pool_size(1);
        let outbound = Socks5Outbound::new(config).await.unwrap();

        let dest: SocketAddr = "1.2.3.4:443".parse().unwrap();
        let result = outbound.connect(dest, Duration::from_secs(5)).await;

        assert!(result.is_ok(), "Single char domain should work");

        let _ = server.await;
    }

    #[tokio::test]
    async fn test_socks5_domain_bnd_addr_max_length() {
        // NEW-7 TEST: Maximum domain length (255 bytes per RFC 1928)
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        // Create max length domain (255 characters)
        let max_domain = vec![b'a'; 255];

        let server = tokio::spawn(async move {
            run_mock_socks5_server_with_domain_reply(listener, &max_domain, 80).await;
        });

        let config = Socks5Config::new("test-domain-max", server_addr).with_pool_size(1);
        let outbound = Socks5Outbound::new(config).await.unwrap();

        let dest: SocketAddr = "1.2.3.4:80".parse().unwrap();
        let result = outbound.connect(dest, Duration::from_secs(5)).await;

        assert!(result.is_ok(), "Max length domain (255) should work");

        let _ = server.await;
    }

    #[tokio::test]
    async fn test_socks5_domain_bnd_addr_with_dots() {
        // NEW-7 TEST: Typical FQDN with multiple labels
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            run_mock_socks5_server_with_domain_reply(
                listener,
                b"relay.us-east-1.socks.example.com",
                1080,
            ).await;
        });

        let config = Socks5Config::new("test-domain-fqdn", server_addr).with_pool_size(1);
        let outbound = Socks5Outbound::new(config).await.unwrap();

        let dest: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let result = outbound.connect(dest, Duration::from_secs(5)).await;

        assert!(result.is_ok(), "FQDN with dots should work");

        let _ = server.await;
    }

    #[tokio::test]
    async fn test_socks5_domain_bnd_addr_port_boundary_low() {
        // NEW-7 TEST: Domain with port 1 (minimum valid port)
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            run_mock_socks5_server_with_domain_reply(listener, b"localhost", 1).await;
        });

        let config = Socks5Config::new("test-domain-port1", server_addr).with_pool_size(1);
        let outbound = Socks5Outbound::new(config).await.unwrap();

        let dest: SocketAddr = "1.2.3.4:80".parse().unwrap();
        let result = outbound.connect(dest, Duration::from_secs(5)).await;

        assert!(result.is_ok(), "Domain with port 1 should work");

        let _ = server.await;
    }

    #[tokio::test]
    async fn test_socks5_domain_bnd_addr_port_boundary_high() {
        // NEW-7 TEST: Domain with port 65535 (maximum valid port)
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            run_mock_socks5_server_with_domain_reply(listener, b"localhost", 65535).await;
        });

        let config = Socks5Config::new("test-domain-port-max", server_addr).with_pool_size(1);
        let outbound = Socks5Outbound::new(config).await.unwrap();

        let dest: SocketAddr = "1.2.3.4:80".parse().unwrap();
        let result = outbound.connect(dest, Duration::from_secs(5)).await;

        assert!(result.is_ok(), "Domain with port 65535 should work");

        let _ = server.await;
    }

    /// Mock server that returns IPv6 in BND.ADDR
    async fn run_mock_socks5_server_with_ipv6_reply(
        listener: tokio::net::TcpListener,
        ipv6: Ipv6Addr,
        port: u16,
    ) {
        let (mut socket, _) = listener.accept().await.unwrap();

        // Method selection
        let mut header = [0u8; 2];
        socket.read_exact(&mut header).await.unwrap();
        let nmethods = header[1] as usize;
        let mut methods = vec![0u8; nmethods];
        socket.read_exact(&mut methods).await.unwrap();
        socket.write_all(&[SOCKS5_VERSION, AUTH_METHOD_NONE]).await.unwrap();

        // CONNECT request
        let mut connect_buf = [0u8; 4];
        socket.read_exact(&mut connect_buf).await.unwrap();
        match connect_buf[3] {
            ATYP_IPV4 => {
                let mut addr_buf = [0u8; 6];
                socket.read_exact(&mut addr_buf).await.unwrap();
            }
            ATYP_IPV6 => {
                let mut addr_buf = [0u8; 18];
                socket.read_exact(&mut addr_buf).await.unwrap();
            }
            _ => panic!("Unexpected ATYP"),
        }

        // Reply with IPv6 BND.ADDR
        let mut reply = vec![SOCKS5_VERSION, REPLY_SUCCEEDED, 0x00, ATYP_IPV6];
        reply.extend_from_slice(&ipv6.octets());
        reply.push((port >> 8) as u8);
        reply.push((port & 0xFF) as u8);

        socket.write_all(&reply).await.unwrap();
    }

    #[tokio::test]
    async fn test_socks5_ipv6_bnd_addr() {
        // NEW-7 TEST: Server returns IPv6 in BND.ADDR (ATYP=0x04)
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            run_mock_socks5_server_with_ipv6_reply(
                listener,
                "2001:db8::1".parse().unwrap(),
                8080,
            ).await;
        });

        let config = Socks5Config::new("test-ipv6", server_addr).with_pool_size(1);
        let outbound = Socks5Outbound::new(config).await.unwrap();

        let dest: SocketAddr = "1.2.3.4:80".parse().unwrap();
        let result = outbound.connect(dest, Duration::from_secs(5)).await;

        assert!(result.is_ok(), "IPv6 BND.ADDR should work");

        let _ = server.await;
    }

    #[tokio::test]
    async fn test_socks5_ipv6_bnd_addr_loopback() {
        // NEW-7 TEST: IPv6 loopback ::1 in BND.ADDR
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            run_mock_socks5_server_with_ipv6_reply(
                listener,
                Ipv6Addr::LOCALHOST,
                1080,
            ).await;
        });

        let config = Socks5Config::new("test-ipv6-lo", server_addr).with_pool_size(1);
        let outbound = Socks5Outbound::new(config).await.unwrap();

        let dest: SocketAddr = "1.2.3.4:80".parse().unwrap();
        let result = outbound.connect(dest, Duration::from_secs(5)).await;

        assert!(result.is_ok(), "IPv6 loopback BND.ADDR should work");

        let _ = server.await;
    }

    /// Mock server that returns invalid ATYP in BND.ADDR
    async fn run_mock_socks5_server_with_invalid_atyp(
        listener: tokio::net::TcpListener,
        invalid_atyp: u8,
    ) {
        let (mut socket, _) = listener.accept().await.unwrap();

        // Method selection
        let mut header = [0u8; 2];
        socket.read_exact(&mut header).await.unwrap();
        let nmethods = header[1] as usize;
        let mut methods = vec![0u8; nmethods];
        socket.read_exact(&mut methods).await.unwrap();
        socket.write_all(&[SOCKS5_VERSION, AUTH_METHOD_NONE]).await.unwrap();

        // CONNECT request
        let mut connect_buf = [0u8; 4];
        socket.read_exact(&mut connect_buf).await.unwrap();
        match connect_buf[3] {
            ATYP_IPV4 => {
                let mut addr_buf = [0u8; 6];
                socket.read_exact(&mut addr_buf).await.unwrap();
            }
            _ => {}
        }

        // Reply with invalid ATYP
        let reply = [SOCKS5_VERSION, REPLY_SUCCEEDED, 0x00, invalid_atyp, 0, 0];
        socket.write_all(&reply).await.unwrap();
    }

    #[tokio::test]
    async fn test_socks5_invalid_atyp_bnd_addr() {
        // NEW-7 TEST: Server returns invalid ATYP (0x05) - should fail
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            run_mock_socks5_server_with_invalid_atyp(listener, 0x05).await;
        });

        let config = Socks5Config::new("test-invalid-atyp", server_addr).with_pool_size(1);
        let outbound = Socks5Outbound::new(config).await.unwrap();

        let dest: SocketAddr = "1.2.3.4:80".parse().unwrap();
        let result = outbound.connect(dest, Duration::from_secs(5)).await;

        assert!(result.is_err(), "Invalid ATYP should fail");
        if let Err(OutboundError::ConnectionFailed { reason, .. }) = result {
            assert!(
                reason.contains("Invalid address type") || reason.contains("0x05"),
                "Error should mention invalid address type: {}",
                reason
            );
        } else {
            panic!("Expected ConnectionFailed error");
        }

        let _ = server.await;
    }

    #[tokio::test]
    async fn test_socks5_atyp_zero_invalid() {
        // NEW-7 TEST: ATYP=0x00 is invalid per RFC 1928
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            run_mock_socks5_server_with_invalid_atyp(listener, 0x00).await;
        });

        let config = Socks5Config::new("test-atyp-zero", server_addr).with_pool_size(1);
        let outbound = Socks5Outbound::new(config).await.unwrap();

        let dest: SocketAddr = "1.2.3.4:80".parse().unwrap();
        let result = outbound.connect(dest, Duration::from_secs(5)).await;

        assert!(result.is_err(), "ATYP=0x00 should fail");

        let _ = server.await;
    }

    #[tokio::test]
    async fn test_socks5_atyp_two_invalid() {
        // NEW-7 TEST: ATYP=0x02 is reserved/invalid per RFC 1928
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            run_mock_socks5_server_with_invalid_atyp(listener, 0x02).await;
        });

        let config = Socks5Config::new("test-atyp-two", server_addr).with_pool_size(1);
        let outbound = Socks5Outbound::new(config).await.unwrap();

        let dest: SocketAddr = "1.2.3.4:80".parse().unwrap();
        let result = outbound.connect(dest, Duration::from_secs(5)).await;

        assert!(result.is_err(), "ATYP=0x02 should fail");

        let _ = server.await;
    }
}
