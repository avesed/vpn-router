//! SOCKS5 UDP ASSOCIATE implementation (RFC 1928)
//!
//! This module implements the UDP ASSOCIATE command of the SOCKS5 protocol,
//! allowing UDP traffic to be relayed through a SOCKS5 proxy server.
//!
//! # Protocol Overview
//!
//! UDP ASSOCIATE (CMD=0x03) flow:
//! 1. Client establishes TCP control connection to SOCKS5 server
//! 2. Client performs authentication handshake (if required)
//! 3. Client sends UDP ASSOCIATE request with expected client address
//! 4. Server replies with BND.ADDR (UDP relay endpoint address)
//! 5. Client sends/receives UDP packets via the relay endpoint
//! 6. TCP control connection must remain open during the association
//!
//! # UDP Packet Format (RFC 1928 Section 7)
//!
//! ```text
//! +------+------+------+----------+----------+----------+
//! | RSV  | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
//! +------+------+------+----------+----------+----------+
//! |  2   |  1   |  1   | Variable |    2     | Variable |
//! +------+------+------+----------+----------+----------+
//! ```
//!
//! - RSV: Reserved, must be 0x0000
//! - FRAG: Fragment number (0 = standalone, >0 = fragment)
//! - ATYP: Address type (0x01=IPv4, 0x03=Domain, 0x04=IPv6)
//! - DST.ADDR: Destination address
//! - DST.PORT: Destination port
//! - DATA: User data
//!
//! # Example
//!
//! ```no_run
//! use rust_router::outbound::socks5_udp::Socks5UdpAssociation;
//! use std::net::SocketAddr;
//! use std::time::Duration;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let server: SocketAddr = "127.0.0.1:1080".parse()?;
//! let assoc = Socks5UdpAssociation::establish(server, None, Duration::from_secs(10)).await?;
//!
//! // Send UDP packet to destination
//! let dest: SocketAddr = "8.8.8.8:53".parse()?;
//! assoc.send_to(b"\x00\x01...", dest).await?;
//!
//! // Receive reply
//! let mut buf = [0u8; 65535];
//! let (n, from) = assoc.recv_from(&mut buf).await?;
//! # Ok(())
//! # }
//! ```

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use bytes::{BufMut, BytesMut};
use socket2::{Domain, Protocol, Socket, TcpKeepalive, Type};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Mutex;
use tokio::time::timeout;
use tracing::{debug, trace, warn};

// Import shared SOCKS5 constants from the common module
use super::socks5_common::{
    ATYP_DOMAIN, ATYP_IPV4, ATYP_IPV6, AUTH_METHOD_NONE, AUTH_METHOD_NO_ACCEPTABLE,
    AUTH_METHOD_PASSWORD, AUTH_PASSWORD_VERSION, CMD_UDP_ASSOCIATE, REPLY_SUCCEEDED,
    SOCKS5_VERSION, UDP_HEADER_IPV6_SIZE, UDP_HEADER_MIN_SIZE,
};

// ============================================================================
// Error Types
// ============================================================================

/// SOCKS5 UDP-specific errors
#[derive(Debug, Clone)]
pub enum Socks5UdpError {
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
    /// Connection error (TCP control connection)
    ConnectionError(String),
    /// Timeout during handshake
    HandshakeTimeout,
    /// UDP relay error
    RelayError(String),
    /// Packet format error
    PacketFormatError(String),
    /// Invalid packet (e.g., non-zero RSV field)
    InvalidPacket(String),
    /// Fragmented packet (not supported)
    FragmentedPacket { frag: u8 },
    /// Control connection closed
    ControlConnectionClosed,
    /// I/O error
    IoError(String),
}

impl fmt::Display for Socks5UdpError {
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
            Self::RelayError(msg) => write!(f, "SOCKS5 UDP relay error: {msg}"),
            Self::PacketFormatError(msg) => write!(f, "SOCKS5 UDP packet format error: {msg}"),
            Self::InvalidPacket(msg) => write!(f, "SOCKS5 UDP invalid packet: {msg}"),
            Self::FragmentedPacket { frag } => {
                write!(f, "Fragmented UDP packet not supported (FRAG={frag})")
            }
            Self::ControlConnectionClosed => write!(f, "SOCKS5 control connection closed"),
            Self::IoError(msg) => write!(f, "I/O error: {msg}"),
        }
    }
}

impl std::error::Error for Socks5UdpError {}

impl From<std::io::Error> for Socks5UdpError {
    fn from(e: std::io::Error) -> Self {
        Self::IoError(e.to_string())
    }
}

// Use reply_message from socks5_common module
use super::socks5_common::reply_message;

// ============================================================================
// Authentication
// ============================================================================

/// SOCKS5 authentication credentials
#[derive(Debug, Clone)]
pub struct Socks5Auth {
    /// Username
    pub username: String,
    /// Password
    pub password: String,
}

impl Socks5Auth {
    /// Create new authentication credentials
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            password: password.into(),
        }
    }
}

// ============================================================================
// UDP Association
// ============================================================================

/// SOCKS5 UDP Association (RFC 1928)
///
/// Manages a UDP relay connection through a SOCKS5 proxy. The association
/// includes:
/// - A TCP control connection that must stay open
/// - The UDP relay address provided by the server
/// - A local UDP socket for communicating with the relay
///
/// # Thread Safety
///
/// This struct is thread-safe and can be shared between tasks.
pub struct Socks5UdpAssociation {
    /// TCP control connection (must stay open)
    control_conn: Mutex<TcpStream>,
    /// UDP relay address from server (BND.ADDR)
    relay_addr: SocketAddr,
    /// Local UDP socket for relay communication
    udp_socket: UdpSocket,
    /// SOCKS5 server address (for reconnection)
    server_addr: SocketAddr,
    /// Authentication credentials (for reconnection)
    #[allow(dead_code)] // Kept for potential reconnection support
    auth: Option<Socks5Auth>,
    /// Whether the association is active
    active: AtomicBool,
    /// Statistics: packets sent
    packets_sent: AtomicU64,
    /// Statistics: packets received
    packets_received: AtomicU64,
    /// Statistics: bytes sent (payload only)
    bytes_sent: AtomicU64,
    /// Statistics: bytes received (payload only)
    bytes_received: AtomicU64,
}

impl fmt::Debug for Socks5UdpAssociation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Socks5UdpAssociation")
            .field("server_addr", &self.server_addr)
            .field("relay_addr", &self.relay_addr)
            .field("active", &self.active.load(Ordering::Relaxed))
            .field("packets_sent", &self.packets_sent.load(Ordering::Relaxed))
            .field("packets_received", &self.packets_received.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl Socks5UdpAssociation {
    /// Establish a UDP ASSOCIATE with the SOCKS5 server
    ///
    /// This performs the full SOCKS5 handshake for UDP ASSOCIATE:
    /// 1. TCP connection to server
    /// 2. Authentication (if credentials provided)
    /// 3. UDP ASSOCIATE command
    /// 4. Create local UDP socket bound to relay
    ///
    /// # Arguments
    ///
    /// * `server_addr` - SOCKS5 server address
    /// * `auth` - Optional authentication credentials
    /// * `timeout_duration` - Timeout for the entire handshake
    ///
    /// # Errors
    ///
    /// Returns `Socks5UdpError` if any step of the handshake fails.
    pub async fn establish(
        server_addr: SocketAddr,
        auth: Option<Socks5Auth>,
        timeout_duration: Duration,
    ) -> Result<Self, Socks5UdpError> {
        let result = timeout(
            timeout_duration,
            Self::establish_inner(server_addr, auth.clone()),
        )
        .await;

        match result {
            Ok(Ok(assoc)) => Ok(assoc),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(Socks5UdpError::HandshakeTimeout),
        }
    }

    async fn establish_inner(
        server_addr: SocketAddr,
        auth: Option<Socks5Auth>,
    ) -> Result<Self, Socks5UdpError> {
        debug!("Establishing SOCKS5 UDP ASSOCIATE to {}", server_addr);

        // Step 1: TCP connect
        let stream = Self::tcp_connect(server_addr).await?;

        // Step 2: Method selection and authentication
        let stream = Self::handshake(stream, &auth).await?;

        // Step 3: UDP ASSOCIATE request
        let (stream, relay_addr) = Self::udp_associate(stream).await?;

        // Step 4: Create local UDP socket
        let domain = if relay_addr.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };

        let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))
            .map_err(|e| Socks5UdpError::IoError(format!("UDP socket creation failed: {e}")))?;

        socket
            .set_nonblocking(true)
            .map_err(|e| Socks5UdpError::IoError(format!("set nonblocking failed: {e}")))?;

        // Bind to any local address
        let bind_addr: SocketAddr = if relay_addr.is_ipv4() {
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))
        } else {
            SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0))
        };

        socket
            .bind(&bind_addr.into())
            .map_err(|e| Socks5UdpError::IoError(format!("UDP bind failed: {e}")))?;

        // Convert to tokio socket
        let std_socket: std::net::UdpSocket = socket.into();
        let udp_socket = UdpSocket::from_std(std_socket)
            .map_err(|e| Socks5UdpError::IoError(format!("UDP conversion failed: {e}")))?;

        // Connect to relay address for send/recv
        udp_socket
            .connect(relay_addr)
            .await
            .map_err(|e| Socks5UdpError::IoError(format!("UDP connect to relay failed: {e}")))?;

        debug!(
            "SOCKS5 UDP ASSOCIATE established, relay at {}",
            relay_addr
        );

        Ok(Self {
            control_conn: Mutex::new(stream),
            relay_addr,
            udp_socket,
            server_addr,
            auth,
            active: AtomicBool::new(true),
            packets_sent: AtomicU64::new(0),
            packets_received: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
        })
    }

    /// TCP connect to SOCKS5 server with keepalive
    async fn tcp_connect(server_addr: SocketAddr) -> Result<TcpStream, Socks5UdpError> {
        let domain = if server_addr.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };

        let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))
            .map_err(|e| Socks5UdpError::ConnectionError(format!("socket creation failed: {e}")))?;

        socket
            .set_nonblocking(true)
            .map_err(|e| Socks5UdpError::ConnectionError(format!("set nonblocking failed: {e}")))?;

        // Enable TCP keepalive to detect control connection failure
        let keepalive = TcpKeepalive::new()
            .with_time(Duration::from_secs(30))
            .with_interval(Duration::from_secs(10));

        socket
            .set_tcp_keepalive(&keepalive)
            .map_err(|e| Socks5UdpError::ConnectionError(format!("set keepalive failed: {e}")))?;

        // Non-blocking connect
        match socket.connect(&server_addr.into()) {
            Ok(()) => {}
            Err(ref e) if e.raw_os_error() == Some(libc::EINPROGRESS) => {}
            Err(e) => {
                return Err(Socks5UdpError::ConnectionError(format!(
                    "connect to {server_addr} failed: {e}"
                )));
            }
        }

        // Convert to TcpStream
        let std_stream: std::net::TcpStream = socket.into();
        let stream = TcpStream::from_std(std_stream)
            .map_err(|e| Socks5UdpError::ConnectionError(format!("TcpStream conversion: {e}")))?;

        // Wait for connection
        stream
            .writable()
            .await
            .map_err(|e| Socks5UdpError::ConnectionError(e.to_string()))?;

        // Check for connection errors
        match stream.take_error() {
            Ok(None) => Ok(stream),
            Ok(Some(e)) | Err(e) => Err(Socks5UdpError::ConnectionError(e.to_string())),
        }
    }

    /// Perform SOCKS5 handshake (method selection + optional auth)
    async fn handshake(
        mut stream: TcpStream,
        auth: &Option<Socks5Auth>,
    ) -> Result<TcpStream, Socks5UdpError> {
        // Send method selection
        let methods: Vec<u8> = if auth.is_some() {
            vec![SOCKS5_VERSION, 2, AUTH_METHOD_NONE, AUTH_METHOD_PASSWORD]
        } else {
            vec![SOCKS5_VERSION, 1, AUTH_METHOD_NONE]
        };

        trace!("Sending SOCKS5 method selection: {:?}", methods);
        stream
            .write_all(&methods)
            .await
            .map_err(|e| Socks5UdpError::ConnectionError(format!("write methods: {e}")))?;

        // Read response
        let mut response = [0u8; 2];
        stream
            .read_exact(&mut response)
            .await
            .map_err(|e| Socks5UdpError::ConnectionError(format!("read method response: {e}")))?;

        trace!("SOCKS5 method response: {:?}", response);

        // Validate version
        if response[0] != SOCKS5_VERSION {
            return Err(Socks5UdpError::InvalidVersion {
                expected: SOCKS5_VERSION,
                actual: response[0],
            });
        }

        // Handle selected method
        match response[1] {
            AUTH_METHOD_NONE => {
                trace!("SOCKS5 server selected no authentication");
                Ok(stream)
            }
            AUTH_METHOD_PASSWORD => {
                trace!("SOCKS5 server requires password authentication");
                Self::authenticate(stream, auth.as_ref().ok_or(Socks5UdpError::AuthFailed)?).await
            }
            AUTH_METHOD_NO_ACCEPTABLE => Err(Socks5UdpError::NoAcceptableMethod),
            other => Err(Socks5UdpError::ProtocolError(format!(
                "unsupported auth method: {other:#04x}"
            ))),
        }
    }

    /// Perform username/password authentication (RFC 1929)
    async fn authenticate(
        mut stream: TcpStream,
        auth: &Socks5Auth,
    ) -> Result<TcpStream, Socks5UdpError> {
        // Validate lengths
        if auth.username.len() > 255 {
            return Err(Socks5UdpError::ProtocolError(
                "username too long (max 255)".into(),
            ));
        }
        if auth.password.len() > 255 {
            return Err(Socks5UdpError::ProtocolError(
                "password too long (max 255)".into(),
            ));
        }

        // Build auth request
        #[allow(clippy::cast_possible_truncation)]
        let ulen = auth.username.len() as u8;
        #[allow(clippy::cast_possible_truncation)]
        let plen = auth.password.len() as u8;

        let mut auth_req = Vec::with_capacity(3 + auth.username.len() + auth.password.len());
        auth_req.push(AUTH_PASSWORD_VERSION);
        auth_req.push(ulen);
        auth_req.extend_from_slice(auth.username.as_bytes());
        auth_req.push(plen);
        auth_req.extend_from_slice(auth.password.as_bytes());

        trace!("Sending SOCKS5 auth request");
        stream
            .write_all(&auth_req)
            .await
            .map_err(|e| Socks5UdpError::ConnectionError(format!("write auth: {e}")))?;

        // Read auth response
        let mut response = [0u8; 2];
        stream
            .read_exact(&mut response)
            .await
            .map_err(|e| Socks5UdpError::ConnectionError(format!("read auth response: {e}")))?;

        trace!("SOCKS5 auth response: {:?}", response);

        if response[0] != AUTH_PASSWORD_VERSION {
            return Err(Socks5UdpError::ProtocolError(format!(
                "invalid auth version: {:#04x}",
                response[0]
            )));
        }

        if response[1] != 0x00 {
            return Err(Socks5UdpError::AuthFailed);
        }

        trace!("SOCKS5 authentication successful");
        Ok(stream)
    }

    /// Send UDP ASSOCIATE request and get relay address
    async fn udp_associate(mut stream: TcpStream) -> Result<(TcpStream, SocketAddr), Socks5UdpError> {
        // Build UDP ASSOCIATE request
        // We use 0.0.0.0:0 as the expected client address (server chooses)
        let request = [
            SOCKS5_VERSION,
            CMD_UDP_ASSOCIATE,
            0x00, // Reserved
            ATYP_IPV4,
            0, 0, 0, 0, // 0.0.0.0
            0, 0, // Port 0
        ];

        trace!("Sending SOCKS5 UDP ASSOCIATE request");
        stream
            .write_all(&request)
            .await
            .map_err(|e| Socks5UdpError::ConnectionError(format!("write UDP ASSOCIATE: {e}")))?;

        // Read reply header
        let mut header = [0u8; 4];
        stream
            .read_exact(&mut header)
            .await
            .map_err(|e| Socks5UdpError::ConnectionError(format!("read reply header: {e}")))?;

        trace!("SOCKS5 UDP ASSOCIATE reply header: {:?}", header);

        // Validate version
        if header[0] != SOCKS5_VERSION {
            return Err(Socks5UdpError::InvalidVersion {
                expected: SOCKS5_VERSION,
                actual: header[0],
            });
        }

        // Check reply status
        if header[1] != REPLY_SUCCEEDED {
            return Err(Socks5UdpError::ServerReply {
                code: header[1],
                message: reply_message(header[1]).to_string(),
            });
        }

        // Read bound address based on ATYP
        let relay_addr = match header[3] {
            ATYP_IPV4 => {
                let mut addr = [0u8; 4];
                stream.read_exact(&mut addr).await.map_err(|e| {
                    Socks5UdpError::ConnectionError(format!("read IPv4 addr: {e}"))
                })?;

                let mut port = [0u8; 2];
                stream
                    .read_exact(&mut port)
                    .await
                    .map_err(|e| Socks5UdpError::ConnectionError(format!("read port: {e}")))?;

                SocketAddr::V4(SocketAddrV4::new(
                    Ipv4Addr::from(addr),
                    u16::from_be_bytes(port),
                ))
            }
            ATYP_IPV6 => {
                let mut addr = [0u8; 16];
                stream.read_exact(&mut addr).await.map_err(|e| {
                    Socks5UdpError::ConnectionError(format!("read IPv6 addr: {e}"))
                })?;

                let mut port = [0u8; 2];
                stream
                    .read_exact(&mut port)
                    .await
                    .map_err(|e| Socks5UdpError::ConnectionError(format!("read port: {e}")))?;

                SocketAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::from(addr),
                    u16::from_be_bytes(port),
                    0,
                    0,
                ))
            }
            ATYP_DOMAIN => {
                // Domain name - we need to resolve or fail
                let mut len = [0u8; 1];
                stream.read_exact(&mut len).await.map_err(|e| {
                    Socks5UdpError::ConnectionError(format!("read domain len: {e}"))
                })?;

                let mut domain = vec![0u8; len[0] as usize];
                stream
                    .read_exact(&mut domain)
                    .await
                    .map_err(|e| Socks5UdpError::ConnectionError(format!("read domain: {e}")))?;

                let mut port = [0u8; 2];
                stream
                    .read_exact(&mut port)
                    .await
                    .map_err(|e| Socks5UdpError::ConnectionError(format!("read port: {e}")))?;

                // NET-2 FIX: Resolve domain BND.ADDR via DNS
                // Some SOCKS5 servers return a domain name instead of an IP address.
                // This is rare but valid per RFC 1928.
                let domain_str = String::from_utf8(domain).map_err(|_| {
                    Socks5UdpError::ProtocolError("invalid domain encoding in BND.ADDR".into())
                })?;
                let port_num = u16::from_be_bytes(port);

                debug!(
                    "SOCKS5 server returned domain BND.ADDR: {}:{}, resolving DNS",
                    domain_str, port_num
                );

                // Use tokio's async DNS resolver
                let addr_with_port = format!("{}:{}", domain_str, port_num);
                let resolved = tokio::net::lookup_host(&addr_with_port)
                    .await
                    .map_err(|e| {
                        Socks5UdpError::ConnectionError(format!(
                            "DNS resolution failed for {}: {}",
                            domain_str, e
                        ))
                    })?
                    .next()
                    .ok_or_else(|| {
                        Socks5UdpError::ConnectionError(format!(
                            "DNS resolution returned no addresses for {}",
                            domain_str
                        ))
                    })?;

                debug!(
                    "Resolved SOCKS5 domain BND.ADDR {} -> {}",
                    domain_str, resolved
                );
                resolved
            }
            other => {
                return Err(Socks5UdpError::InvalidAddressType(other));
            }
        };

        trace!("SOCKS5 UDP relay address: {}", relay_addr);

        // Handle 0.0.0.0:PORT case - use server address with relay port
        let relay_addr = if relay_addr.ip().is_unspecified() {
            warn!(
                "SOCKS5 server returned unspecified relay address, using server IP: {}",
                relay_addr
            );
            let port = relay_addr.port();
            match stream.peer_addr() {
                Ok(peer) => SocketAddr::new(peer.ip(), port),
                Err(_) => relay_addr, // Fall back to original
            }
        } else {
            relay_addr
        };

        Ok((stream, relay_addr))
    }

    /// Encapsulate data into SOCKS5 UDP packet format
    ///
    /// Creates a properly formatted SOCKS5 UDP packet containing:
    /// - 2 bytes RSV (0x0000)
    /// - 1 byte FRAG (0x00)
    /// - Address header (ATYP + DST.ADDR + DST.PORT)
    /// - User data
    ///
    /// # Arguments
    ///
    /// * `dest` - Destination address for the UDP packet
    /// * `data` - Payload data to encapsulate
    ///
    /// # Returns
    ///
    /// A `BytesMut` containing the encapsulated packet ready for sending.
    #[must_use]
    pub fn encapsulate(dest: SocketAddr, data: &[u8]) -> BytesMut {
        let header_size = match dest {
            SocketAddr::V4(_) => UDP_HEADER_MIN_SIZE,
            SocketAddr::V6(_) => UDP_HEADER_IPV6_SIZE,
        };

        let mut packet = BytesMut::with_capacity(header_size + data.len());

        // RSV (2 bytes, must be 0)
        packet.put_u16(0);

        // FRAG (1 byte, 0 = standalone packet)
        packet.put_u8(0);

        // Address header
        match dest {
            SocketAddr::V4(v4) => {
                packet.put_u8(ATYP_IPV4);
                packet.put_slice(&v4.ip().octets());
                packet.put_u16(v4.port());
            }
            SocketAddr::V6(v6) => {
                packet.put_u8(ATYP_IPV6);
                packet.put_slice(&v6.ip().octets());
                packet.put_u16(v6.port());
            }
        }

        // Data
        packet.put_slice(data);

        packet
    }

    /// Encapsulate data with domain name destination
    ///
    /// Similar to `encapsulate` but uses a domain name instead of IP address.
    ///
    /// # Arguments
    ///
    /// * `domain` - Destination domain name
    /// * `port` - Destination port
    /// * `data` - Payload data to encapsulate
    ///
    /// # Returns
    ///
    /// A `BytesMut` containing the encapsulated packet, or `None` if domain is too long.
    #[must_use]
    pub fn encapsulate_domain(domain: &str, port: u16, data: &[u8]) -> Option<BytesMut> {
        if domain.len() > 255 {
            return None;
        }

        let header_size = 2 + 1 + 1 + 1 + domain.len() + 2; // RSV + FRAG + ATYP + LEN + DOMAIN + PORT
        let mut packet = BytesMut::with_capacity(header_size + data.len());

        // RSV (2 bytes)
        packet.put_u16(0);

        // FRAG (1 byte)
        packet.put_u8(0);

        // Address header (domain)
        packet.put_u8(ATYP_DOMAIN);
        #[allow(clippy::cast_possible_truncation)]
        packet.put_u8(domain.len() as u8);
        packet.put_slice(domain.as_bytes());
        packet.put_u16(port);

        // Data
        packet.put_slice(data);

        Some(packet)
    }

    /// Decapsulate a SOCKS5 UDP packet
    ///
    /// Parses the SOCKS5 UDP header and extracts:
    /// - Source address (from DST.ADDR/DST.PORT in reply)
    /// - Payload data
    ///
    /// # Arguments
    ///
    /// * `packet` - Raw UDP packet received from relay
    ///
    /// # Returns
    ///
    /// A tuple of (source address, payload slice), or an error if parsing fails.
    ///
    /// # Errors
    ///
    /// Returns `Socks5UdpError::PacketFormatError` if the packet is malformed,
    /// `Socks5UdpError::InvalidPacket` if RSV field is non-zero,
    /// or `Socks5UdpError::FragmentedPacket` if FRAG != 0.
    pub fn decapsulate(packet: &[u8]) -> Result<(SocketAddr, &[u8]), Socks5UdpError> {
        if packet.len() < UDP_HEADER_MIN_SIZE {
            return Err(Socks5UdpError::PacketFormatError(format!(
                "packet too short: {} bytes (min {})",
                packet.len(),
                UDP_HEADER_MIN_SIZE
            )));
        }

        // Check RSV field - RFC 1928 requires it to be 0x0000
        let rsv = u16::from_be_bytes([packet[0], packet[1]]);
        if rsv != 0 {
            return Err(Socks5UdpError::InvalidPacket(format!(
                "RSV field must be zero, got {rsv:#06x}"
            )));
        }

        // Check FRAG
        let frag = packet[2];
        if frag != 0 {
            // We don't support fragmented packets
            // According to RFC 1928, if a FRAG value other than 0 is received,
            // the implementation should drop the packet
            return Err(Socks5UdpError::FragmentedPacket { frag });
        }

        // Parse address
        let atyp = packet[3];
        let (addr, data_offset) = match atyp {
            ATYP_IPV4 => {
                if packet.len() < UDP_HEADER_MIN_SIZE {
                    return Err(Socks5UdpError::PacketFormatError(
                        "packet too short for IPv4 address".into(),
                    ));
                }
                let ip = Ipv4Addr::new(packet[4], packet[5], packet[6], packet[7]);
                let port = u16::from_be_bytes([packet[8], packet[9]]);
                (SocketAddr::V4(SocketAddrV4::new(ip, port)), 10)
            }
            ATYP_IPV6 => {
                if packet.len() < UDP_HEADER_IPV6_SIZE {
                    return Err(Socks5UdpError::PacketFormatError(
                        "packet too short for IPv6 address".into(),
                    ));
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&packet[4..20]);
                let ip = Ipv6Addr::from(octets);
                let port = u16::from_be_bytes([packet[20], packet[21]]);
                (SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0)), 22)
            }
            ATYP_DOMAIN => {
                if packet.len() < 5 {
                    return Err(Socks5UdpError::PacketFormatError(
                        "packet too short for domain".into(),
                    ));
                }
                let domain_len = packet[4] as usize;
                let min_len = 5 + domain_len + 2;
                if packet.len() < min_len {
                    return Err(Socks5UdpError::PacketFormatError(
                        "packet too short for domain address".into(),
                    ));
                }
                let _domain = &packet[5..5 + domain_len];
                let port_offset = 5 + domain_len;
                let port = u16::from_be_bytes([packet[port_offset], packet[port_offset + 1]]);

                // We can't return a domain as SocketAddr, return placeholder
                // In practice, UDP replies usually use IP addresses
                let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port));
                (addr, port_offset + 2)
            }
            other => {
                return Err(Socks5UdpError::InvalidAddressType(other));
            }
        };

        // Return data slice
        Ok((addr, &packet[data_offset..]))
    }

    /// Send a UDP packet to the specified destination through the relay
    ///
    /// Encapsulates the data and sends it to the SOCKS5 UDP relay.
    ///
    /// # Arguments
    ///
    /// * `data` - Payload data to send
    /// * `dest` - Destination address
    ///
    /// # Returns
    ///
    /// Number of payload bytes sent (not including SOCKS5 header).
    ///
    /// # Errors
    ///
    /// Returns `Socks5UdpError` if the association is closed or sending fails.
    pub async fn send_to(&self, data: &[u8], dest: SocketAddr) -> Result<usize, Socks5UdpError> {
        if !self.is_active() {
            return Err(Socks5UdpError::ControlConnectionClosed);
        }

        let packet = Self::encapsulate(dest, data);
        let sent = self
            .udp_socket
            .send(&packet)
            .await
            .map_err(|e| Socks5UdpError::RelayError(format!("send failed: {e}")))?;

        // Update statistics
        self.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.bytes_sent
            .fetch_add(data.len() as u64, Ordering::Relaxed);

        trace!("SOCKS5 UDP: sent {} bytes to {} via relay", data.len(), dest);

        // Return payload size (not total packet size)
        Ok(sent.saturating_sub(packet.len() - data.len()))
    }

    /// Receive a UDP packet from the relay
    ///
    /// Receives and decapsulates a UDP packet from the SOCKS5 relay.
    ///
    /// # Arguments
    ///
    /// * `buf` - Buffer to receive payload data
    ///
    /// # Returns
    ///
    /// A tuple of (bytes received, source address).
    ///
    /// # Errors
    ///
    /// Returns `Socks5UdpError` if the association is closed, receiving fails,
    /// or the packet format is invalid.
    pub async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), Socks5UdpError> {
        if !self.is_active() {
            return Err(Socks5UdpError::ControlConnectionClosed);
        }

        // Receive raw packet (need extra space for SOCKS5 header)
        let mut raw_buf = vec![0u8; buf.len() + UDP_HEADER_IPV6_SIZE];
        let n = self
            .udp_socket
            .recv(&mut raw_buf)
            .await
            .map_err(|e| Socks5UdpError::RelayError(format!("recv failed: {e}")))?;

        if n == 0 {
            return Err(Socks5UdpError::RelayError("received zero bytes".into()));
        }

        // Decapsulate
        let (src_addr, data) = Self::decapsulate(&raw_buf[..n])?;

        // Copy payload to user buffer
        let copy_len = data.len().min(buf.len());
        buf[..copy_len].copy_from_slice(&data[..copy_len]);

        // Update statistics
        self.packets_received.fetch_add(1, Ordering::Relaxed);
        self.bytes_received
            .fetch_add(copy_len as u64, Ordering::Relaxed);

        trace!(
            "SOCKS5 UDP: received {} bytes from {} via relay",
            copy_len,
            src_addr
        );

        Ok((copy_len, src_addr))
    }

    /// Check if the control connection is still alive
    ///
    /// Uses a zero-byte peek on the TCP control connection to detect closure.
    ///
    /// # Returns
    ///
    /// `true` if the connection appears alive, `false` otherwise.
    pub async fn check_control_connection(&self) -> bool {
        if !self.active.load(Ordering::Relaxed) {
            return false;
        }

        let stream = self.control_conn.lock().await;
        let mut buf = [0u8; 1];

        match tokio::time::timeout(Duration::from_millis(1), stream.peek(&mut buf)).await {
            Ok(Ok(0) | Err(_)) => {
                // Connection closed or error
                self.active.store(false, Ordering::Relaxed);
                false
            }
            Err(_) => {
                // Timeout = still alive
                true
            }
            Ok(Ok(_)) => {
                // Unexpected data received - protocol error
                warn!("Unexpected data on SOCKS5 control connection");
                self.active.store(false, Ordering::Relaxed);
                false
            }
        }
    }

    /// Check if the association is active
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::Relaxed)
    }

    /// Get the UDP relay address
    #[must_use]
    pub const fn relay_addr(&self) -> SocketAddr {
        self.relay_addr
    }

    /// Get the SOCKS5 server address
    #[must_use]
    pub const fn server_addr(&self) -> SocketAddr {
        self.server_addr
    }

    /// Get statistics: packets sent
    #[must_use]
    pub fn packets_sent(&self) -> u64 {
        self.packets_sent.load(Ordering::Relaxed)
    }

    /// Get statistics: packets received
    #[must_use]
    pub fn packets_received(&self) -> u64 {
        self.packets_received.load(Ordering::Relaxed)
    }

    /// Get statistics: bytes sent (payload only)
    #[must_use]
    pub fn bytes_sent(&self) -> u64 {
        self.bytes_sent.load(Ordering::Relaxed)
    }

    /// Get statistics: bytes received (payload only)
    #[must_use]
    pub fn bytes_received(&self) -> u64 {
        self.bytes_received.load(Ordering::Relaxed)
    }

    /// Close the association
    ///
    /// Marks the association as inactive and closes the control connection.
    pub async fn close(&self) {
        self.active.store(false, Ordering::Relaxed);
        // The TCP stream will be dropped when the lock is released
        let mut stream = self.control_conn.lock().await;
        let _ = stream.shutdown().await;
        debug!("SOCKS5 UDP association closed");
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    // ========================================================================
    // Protocol Constants Tests
    // ========================================================================

    #[test]
    fn test_socks5_version() {
        assert_eq!(SOCKS5_VERSION, 0x05);
    }

    #[test]
    fn test_udp_associate_command() {
        assert_eq!(CMD_UDP_ASSOCIATE, 0x03);
    }

    #[test]
    fn test_address_types() {
        assert_eq!(ATYP_IPV4, 0x01);
        assert_eq!(ATYP_DOMAIN, 0x03);
        assert_eq!(ATYP_IPV6, 0x04);
    }

    // ========================================================================
    // Error Tests
    // ========================================================================

    #[test]
    fn test_error_display_invalid_version() {
        let err = Socks5UdpError::InvalidVersion {
            expected: 5,
            actual: 4,
        };
        let msg = err.to_string();
        assert!(msg.contains("Invalid SOCKS version"));
        assert!(msg.contains("expected 5"));
        assert!(msg.contains("got 4"));
    }

    #[test]
    fn test_error_display_fragmented_packet() {
        let err = Socks5UdpError::FragmentedPacket { frag: 1 };
        let msg = err.to_string();
        assert!(msg.contains("Fragmented"));
        assert!(msg.contains("FRAG=1"));
    }

    #[test]
    fn test_error_display_control_connection_closed() {
        let err = Socks5UdpError::ControlConnectionClosed;
        assert!(err.to_string().contains("control connection closed"));
    }

    #[test]
    fn test_error_display_invalid_packet() {
        let err = Socks5UdpError::InvalidPacket("RSV field must be zero".into());
        let msg = err.to_string();
        assert!(msg.contains("invalid packet"));
        assert!(msg.contains("RSV field must be zero"));
    }

    #[test]
    fn test_error_display_no_acceptable_method() {
        let err = Socks5UdpError::NoAcceptableMethod;
        assert!(err.to_string().contains("No acceptable authentication method"));
    }

    #[test]
    fn test_reply_message() {
        assert_eq!(reply_message(0x00), "succeeded");
        assert_eq!(reply_message(0x01), "general SOCKS server failure");
        assert_eq!(reply_message(0x05), "connection refused");
        assert_eq!(reply_message(0x99), "unknown error");
    }

    // ========================================================================
    // Socks5Auth Tests
    // ========================================================================

    #[test]
    fn test_auth_new() {
        let auth = Socks5Auth::new("user", "pass");
        assert_eq!(auth.username, "user");
        assert_eq!(auth.password, "pass");
    }

    // ========================================================================
    // Encapsulation Tests
    // ========================================================================

    #[test]
    fn test_encapsulate_ipv4() {
        let dest: SocketAddr = "192.168.1.1:8080".parse().unwrap();
        let data = b"hello";
        let packet = Socks5UdpAssociation::encapsulate(dest, data);

        // Verify header
        assert_eq!(packet[0], 0x00); // RSV
        assert_eq!(packet[1], 0x00); // RSV
        assert_eq!(packet[2], 0x00); // FRAG
        assert_eq!(packet[3], ATYP_IPV4);
        assert_eq!(packet[4], 192); // IP
        assert_eq!(packet[5], 168);
        assert_eq!(packet[6], 1);
        assert_eq!(packet[7], 1);
        assert_eq!(packet[8], 0x1F); // Port high byte (8080 >> 8)
        assert_eq!(packet[9], 0x90); // Port low byte

        // Verify data
        assert_eq!(&packet[10..], data);
    }

    #[test]
    fn test_encapsulate_ipv6() {
        let dest: SocketAddr = "[::1]:443".parse().unwrap();
        let data = b"test";
        let packet = Socks5UdpAssociation::encapsulate(dest, data);

        // Verify header
        assert_eq!(packet[0], 0x00);
        assert_eq!(packet[1], 0x00);
        assert_eq!(packet[2], 0x00);
        assert_eq!(packet[3], ATYP_IPV6);

        // IPv6 address (::1 = 15 zeros + 1)
        for i in 4..19 {
            assert_eq!(packet[i], 0);
        }
        assert_eq!(packet[19], 1);

        // Port 443
        assert_eq!(packet[20], 0x01);
        assert_eq!(packet[21], 0xBB);

        // Data
        assert_eq!(&packet[22..], data);
    }

    #[test]
    fn test_encapsulate_domain() {
        let packet = Socks5UdpAssociation::encapsulate_domain("example.com", 80, b"data").unwrap();

        assert_eq!(packet[0], 0x00); // RSV
        assert_eq!(packet[1], 0x00);
        assert_eq!(packet[2], 0x00); // FRAG
        assert_eq!(packet[3], ATYP_DOMAIN);
        assert_eq!(packet[4], 11); // "example.com" length
        assert_eq!(&packet[5..16], b"example.com");
        assert_eq!(packet[16], 0x00); // Port high
        assert_eq!(packet[17], 0x50); // Port low (80)
        assert_eq!(&packet[18..], b"data");
    }

    #[test]
    fn test_encapsulate_domain_too_long() {
        let long_domain = "a".repeat(256);
        let result = Socks5UdpAssociation::encapsulate_domain(&long_domain, 80, b"data");
        assert!(result.is_none());
    }

    // ========================================================================
    // Decapsulation Tests
    // ========================================================================

    #[test]
    fn test_decapsulate_ipv4() {
        let mut packet = vec![0x00, 0x00, 0x00, ATYP_IPV4, 8, 8, 8, 8, 0x00, 0x35];
        packet.extend_from_slice(b"response");

        let (addr, data) = Socks5UdpAssociation::decapsulate(&packet).unwrap();

        assert_eq!(addr, "8.8.8.8:53".parse::<SocketAddr>().unwrap());
        assert_eq!(data, b"response");
    }

    #[test]
    fn test_decapsulate_ipv6() {
        let mut packet = vec![0x00, 0x00, 0x00, ATYP_IPV6];
        // ::1
        packet.extend_from_slice(&[0; 15]);
        packet.push(1);
        // Port 443
        packet.extend_from_slice(&[0x01, 0xBB]);
        // Data
        packet.extend_from_slice(b"data");

        let (addr, data) = Socks5UdpAssociation::decapsulate(&packet).unwrap();

        assert_eq!(addr, "[::1]:443".parse::<SocketAddr>().unwrap());
        assert_eq!(data, b"data");
    }

    #[test]
    fn test_decapsulate_domain() {
        let mut packet = vec![0x00, 0x00, 0x00, ATYP_DOMAIN, 4];
        packet.extend_from_slice(b"test");
        packet.extend_from_slice(&[0x00, 0x50]); // Port 80
        packet.extend_from_slice(b"payload");

        let (addr, data) = Socks5UdpAssociation::decapsulate(&packet).unwrap();

        // Domain returns placeholder address
        assert_eq!(addr.port(), 80);
        assert_eq!(data, b"payload");
    }

    #[test]
    fn test_decapsulate_too_short() {
        let packet = vec![0x00, 0x00, 0x00];
        let result = Socks5UdpAssociation::decapsulate(&packet);

        assert!(matches!(result, Err(Socks5UdpError::PacketFormatError(_))));
    }

    #[test]
    fn test_decapsulate_fragmented() {
        let packet = vec![0x00, 0x00, 0x01, ATYP_IPV4, 1, 2, 3, 4, 0x00, 0x50];
        let result = Socks5UdpAssociation::decapsulate(&packet);

        assert!(matches!(
            result,
            Err(Socks5UdpError::FragmentedPacket { frag: 1 })
        ));
    }

    #[test]
    fn test_decapsulate_invalid_atyp() {
        let packet = vec![0x00, 0x00, 0x00, 0x99, 0, 0, 0, 0, 0, 0];
        let result = Socks5UdpAssociation::decapsulate(&packet);

        assert!(matches!(result, Err(Socks5UdpError::InvalidAddressType(0x99))));
    }

    #[test]
    fn test_decapsulate_nonzero_rsv_rejected() {
        // RFC 1928 requires RSV field to be 0x0000
        // Test with non-zero RSV high byte
        let packet = vec![0x01, 0x00, 0x00, ATYP_IPV4, 8, 8, 8, 8, 0x00, 0x35];
        let result = Socks5UdpAssociation::decapsulate(&packet);

        assert!(matches!(result, Err(Socks5UdpError::InvalidPacket(_))));
        if let Err(Socks5UdpError::InvalidPacket(msg)) = result {
            assert!(msg.contains("RSV field must be zero"));
        }

        // Test with non-zero RSV low byte
        let packet = vec![0x00, 0x01, 0x00, ATYP_IPV4, 8, 8, 8, 8, 0x00, 0x35];
        let result = Socks5UdpAssociation::decapsulate(&packet);
        assert!(matches!(result, Err(Socks5UdpError::InvalidPacket(_))));

        // Test with both RSV bytes non-zero
        let packet = vec![0xAB, 0xCD, 0x00, ATYP_IPV4, 8, 8, 8, 8, 0x00, 0x35];
        let result = Socks5UdpAssociation::decapsulate(&packet);
        assert!(matches!(result, Err(Socks5UdpError::InvalidPacket(_))));
    }

    // ========================================================================
    // Roundtrip Tests
    // ========================================================================

    #[test]
    fn test_encapsulate_decapsulate_roundtrip_ipv4() {
        let dest: SocketAddr = "1.2.3.4:5678".parse().unwrap();
        let data = b"test data here";

        let packet = Socks5UdpAssociation::encapsulate(dest, data);
        let (addr, decoded) = Socks5UdpAssociation::decapsulate(&packet).unwrap();

        assert_eq!(addr, dest);
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_encapsulate_decapsulate_roundtrip_ipv6() {
        let dest: SocketAddr = "[2001:db8::1]:8080".parse().unwrap();
        let data = b"ipv6 test";

        let packet = Socks5UdpAssociation::encapsulate(dest, data);
        let (addr, decoded) = Socks5UdpAssociation::decapsulate(&packet).unwrap();

        assert_eq!(addr, dest);
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_encapsulate_empty_data() {
        let dest: SocketAddr = "1.1.1.1:53".parse().unwrap();
        let data = b"";

        let packet = Socks5UdpAssociation::encapsulate(dest, data);
        let (addr, decoded) = Socks5UdpAssociation::decapsulate(&packet).unwrap();

        assert_eq!(addr, dest);
        assert!(decoded.is_empty());
    }

    #[test]
    fn test_encapsulate_large_data() {
        let dest: SocketAddr = "1.1.1.1:53".parse().unwrap();
        let data = vec![0xABu8; 65000]; // Large payload

        let packet = Socks5UdpAssociation::encapsulate(dest, &data);
        let (addr, decoded) = Socks5UdpAssociation::decapsulate(&packet).unwrap();

        assert_eq!(addr, dest);
        assert_eq!(decoded, data.as_slice());
    }

    // ========================================================================
    // Integration Tests (Mock Server)
    // ========================================================================

    /// Mock SOCKS5 UDP ASSOCIATE server for testing
    async fn run_mock_udp_associate_server(
        listener: tokio::net::TcpListener,
        require_auth: bool,
        reply_code: u8,
        relay_port: u16,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let (mut socket, _) = listener.accept().await?;

        // Read method selection
        let mut header = [0u8; 2];
        socket.read_exact(&mut header).await?;
        assert_eq!(header[0], SOCKS5_VERSION);
        let nmethods = header[1] as usize;

        let mut methods = vec![0u8; nmethods];
        socket.read_exact(&mut methods).await?;

        if require_auth {
            // Request password auth
            socket
                .write_all(&[SOCKS5_VERSION, AUTH_METHOD_PASSWORD])
                .await?;

            // Read auth
            let mut auth_ver = [0u8; 1];
            socket.read_exact(&mut auth_ver).await?;
            let mut ulen = [0u8; 1];
            socket.read_exact(&mut ulen).await?;
            let mut username = vec![0u8; ulen[0] as usize];
            socket.read_exact(&mut username).await?;
            let mut plen = [0u8; 1];
            socket.read_exact(&mut plen).await?;
            let mut password = vec![0u8; plen[0] as usize];
            socket.read_exact(&mut password).await?;

            // Auth success
            socket.write_all(&[AUTH_PASSWORD_VERSION, 0x00]).await?;
        } else {
            socket.write_all(&[SOCKS5_VERSION, AUTH_METHOD_NONE]).await?;
        }

        // Read UDP ASSOCIATE request
        let mut request = [0u8; 10]; // VER + CMD + RSV + ATYP + IPv4 + PORT
        socket.read_exact(&mut request).await?;
        assert_eq!(request[1], CMD_UDP_ASSOCIATE);

        // Send reply
        let mut reply = vec![
            SOCKS5_VERSION,
            reply_code,
            0x00, // RSV
            ATYP_IPV4,
            127,
            0,
            0,
            1, // 127.0.0.1
        ];
        reply.extend_from_slice(&relay_port.to_be_bytes());
        socket.write_all(&reply).await?;

        // Keep connection open until client closes
        let mut buf = [0u8; 1];
        let _ = socket.read(&mut buf).await;

        Ok(())
    }

    #[tokio::test]
    async fn test_establish_no_auth() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        // Create a mock UDP relay endpoint
        let relay_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_port = relay_socket.local_addr().unwrap().port();

        // Start mock server
        let server = tokio::spawn(async move {
            run_mock_udp_associate_server(listener, false, REPLY_SUCCEEDED, relay_port).await
        });

        // Establish association
        let result = Socks5UdpAssociation::establish(server_addr, None, Duration::from_secs(5)).await;

        assert!(result.is_ok());
        let assoc = result.unwrap();
        assert!(assoc.is_active());
        assert_eq!(assoc.relay_addr().port(), relay_port);
        assert_eq!(assoc.server_addr(), server_addr);
        assert_eq!(assoc.packets_sent(), 0);
        assert_eq!(assoc.packets_received(), 0);

        // Cleanup
        assoc.close().await;
        let _ = server.await;
    }

    #[tokio::test]
    async fn test_establish_with_auth() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let relay_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_port = relay_socket.local_addr().unwrap().port();

        let server = tokio::spawn(async move {
            run_mock_udp_associate_server(listener, true, REPLY_SUCCEEDED, relay_port).await
        });

        let auth = Some(Socks5Auth::new("testuser", "testpass"));
        let result =
            Socks5UdpAssociation::establish(server_addr, auth, Duration::from_secs(5)).await;

        assert!(result.is_ok());
        let assoc = result.unwrap();
        assert!(assoc.is_active());

        assoc.close().await;
        let _ = server.await;
    }

    #[tokio::test]
    async fn test_establish_server_error() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            // Return "command not supported" error
            run_mock_udp_associate_server(listener, false, 0x07, 0).await
        });

        let result = Socks5UdpAssociation::establish(server_addr, None, Duration::from_secs(5)).await;

        assert!(result.is_err());
        if let Err(Socks5UdpError::ServerReply { code, message }) = result {
            assert_eq!(code, 0x07);
            assert!(message.contains("command not supported"));
        } else {
            panic!("Expected ServerReply error");
        }

        let _ = server.await;
    }

    #[tokio::test]
    async fn test_establish_timeout() {
        // Connect to a non-routable address to trigger timeout
        let addr: SocketAddr = "192.0.2.1:1080".parse().unwrap(); // TEST-NET-1

        let result = Socks5UdpAssociation::establish(addr, None, Duration::from_millis(100)).await;

        assert!(matches!(result, Err(Socks5UdpError::HandshakeTimeout)));
    }

    #[tokio::test]
    async fn test_send_receive_echo() {
        // Setup mock server and relay
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        // Create UDP relay (echo server)
        let relay_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let relay_port = relay_socket.local_addr().unwrap().port();

        // Start SOCKS5 control server
        let server = tokio::spawn(async move {
            run_mock_udp_associate_server(listener, false, REPLY_SUCCEEDED, relay_port).await
        });

        // Start UDP echo task
        let echo_socket = Arc::clone(&relay_socket);
        let echo_task = tokio::spawn(async move {
            let mut buf = [0u8; 65535];
            if let Ok((n, addr)) = echo_socket.recv_from(&mut buf).await {
                let _ = echo_socket.send_to(&buf[..n], addr).await;
            }
        });

        // Establish association
        let assoc = Socks5UdpAssociation::establish(server_addr, None, Duration::from_secs(5))
            .await
            .unwrap();

        // Send a packet (the relay will echo it back)
        // Note: We're sending to the relay itself (loopback test)
        let dest: SocketAddr = format!("127.0.0.1:{relay_port}").parse().unwrap();
        let send_data = b"echo test";

        // Encapsulate manually to send to relay as destination
        let packet = Socks5UdpAssociation::encapsulate(dest, send_data);

        // Send raw packet
        assoc.udp_socket.send(&packet).await.unwrap();

        // Receive response with timeout
        let mut recv_buf = vec![0u8; 65535];
        let recv_result = tokio::time::timeout(
            Duration::from_secs(1),
            assoc.udp_socket.recv(&mut recv_buf),
        )
        .await;

        // The echo will return the same SOCKS5 encapsulated packet
        if let Ok(Ok(n)) = recv_result {
            let (_, data) = Socks5UdpAssociation::decapsulate(&recv_buf[..n]).unwrap();
            assert_eq!(data, send_data);
        }

        assoc.close().await;
        let _ = server.await;
        let _ = echo_task.await;
    }

    #[tokio::test]
    async fn test_check_control_connection() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let relay_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_port = relay_socket.local_addr().unwrap().port();

        let server = tokio::spawn(async move {
            run_mock_udp_associate_server(listener, false, REPLY_SUCCEEDED, relay_port).await
        });

        let assoc = Socks5UdpAssociation::establish(server_addr, None, Duration::from_secs(5))
            .await
            .unwrap();

        // Connection should be alive
        assert!(assoc.check_control_connection().await);
        assert!(assoc.is_active());

        assoc.close().await;
        let _ = server.await;
    }

    #[tokio::test]
    async fn test_association_debug() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let relay_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_port = relay_socket.local_addr().unwrap().port();

        let server = tokio::spawn(async move {
            run_mock_udp_associate_server(listener, false, REPLY_SUCCEEDED, relay_port).await
        });

        let assoc = Socks5UdpAssociation::establish(server_addr, None, Duration::from_secs(5))
            .await
            .unwrap();

        let debug_str = format!("{:?}", assoc);
        assert!(debug_str.contains("Socks5UdpAssociation"));
        assert!(debug_str.contains("server_addr"));
        assert!(debug_str.contains("relay_addr"));
        assert!(debug_str.contains("active"));

        assoc.close().await;
        let _ = server.await;
    }

    // ========================================================================
    // Statistics Tests (MT-1)
    // ========================================================================

    #[tokio::test]
    async fn test_bytes_sent_received_statistics() {
        // Setup mock server and relay
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        // Create UDP relay (echo server)
        let relay_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let relay_port = relay_socket.local_addr().unwrap().port();

        // Start SOCKS5 control server
        let server = tokio::spawn(async move {
            run_mock_udp_associate_server(listener, false, REPLY_SUCCEEDED, relay_port).await
        });

        // Start UDP echo task
        let echo_socket = Arc::clone(&relay_socket);
        let echo_task = tokio::spawn(async move {
            let mut buf = [0u8; 65535];
            if let Ok((n, addr)) = echo_socket.recv_from(&mut buf).await {
                let _ = echo_socket.send_to(&buf[..n], addr).await;
            }
        });

        // Establish association
        let assoc = Socks5UdpAssociation::establish(server_addr, None, Duration::from_secs(5))
            .await
            .unwrap();

        // Initial stats should be zero
        assert_eq!(assoc.bytes_sent(), 0);
        assert_eq!(assoc.bytes_received(), 0);
        assert_eq!(assoc.packets_sent(), 0);
        assert_eq!(assoc.packets_received(), 0);

        // Send a packet through the high-level API
        let dest: SocketAddr = format!("127.0.0.1:{relay_port}").parse().unwrap();
        let send_data = b"test payload for stats";
        let payload_len = send_data.len() as u64;

        let sent = assoc.send_to(send_data, dest).await.unwrap();

        // Verify bytes_sent was incremented by payload size
        assert_eq!(assoc.bytes_sent(), payload_len);
        assert_eq!(assoc.packets_sent(), 1);
        assert!(sent <= send_data.len()); // May be less due to header subtraction

        // Receive response
        let mut recv_buf = [0u8; 65535];
        let recv_result = tokio::time::timeout(
            Duration::from_secs(2),
            assoc.recv_from(&mut recv_buf),
        )
        .await;

        // If we received a response, verify bytes_received was incremented
        if let Ok(Ok((n, _))) = recv_result {
            assert!(n > 0);
            assert!(assoc.bytes_received() > 0);
            assert_eq!(assoc.packets_received(), 1);
        }

        assoc.close().await;
        let _ = server.await;
        let _ = echo_task.await;
    }

    // ========================================================================
    // IPv6 BND.ADDR Tests (MT-2)
    // ========================================================================

    /// Mock SOCKS5 server that returns IPv6 BND.ADDR in UDP ASSOCIATE reply
    async fn run_mock_udp_associate_server_ipv6_bnd(
        listener: tokio::net::TcpListener,
        relay_addr_v6: std::net::Ipv6Addr,
        relay_port: u16,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let (mut socket, _) = listener.accept().await?;

        // Read method selection
        let mut header = [0u8; 2];
        socket.read_exact(&mut header).await?;
        let nmethods = header[1] as usize;
        let mut methods = vec![0u8; nmethods];
        socket.read_exact(&mut methods).await?;

        // No auth required
        socket.write_all(&[SOCKS5_VERSION, AUTH_METHOD_NONE]).await?;

        // Read UDP ASSOCIATE request
        let mut request = [0u8; 10];
        socket.read_exact(&mut request).await?;

        // Send reply with IPv6 BND.ADDR
        let mut reply = vec![
            SOCKS5_VERSION,
            REPLY_SUCCEEDED,
            0x00, // RSV
            ATYP_IPV6,
        ];
        reply.extend_from_slice(&relay_addr_v6.octets());
        reply.extend_from_slice(&relay_port.to_be_bytes());
        socket.write_all(&reply).await?;

        // Keep connection open
        let mut buf = [0u8; 1];
        let _ = socket.read(&mut buf).await;

        Ok(())
    }

    #[tokio::test]
    async fn test_establish_with_ipv6_bnd_addr() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        // Use localhost IPv6 (::1) as the BND.ADDR
        let relay_ipv6 = std::net::Ipv6Addr::LOCALHOST;
        let relay_port = 12345u16;

        let server = tokio::spawn(async move {
            run_mock_udp_associate_server_ipv6_bnd(listener, relay_ipv6, relay_port).await
        });

        let result = Socks5UdpAssociation::establish(server_addr, None, Duration::from_secs(5)).await;

        // IPv6 tests may fail on systems without IPv6 loopback support
        // (e.g., some CI environments or containers)
        match &result {
            Ok(assoc) => {
                // Verify the relay address is IPv6
                let relay_addr = assoc.relay_addr();
                assert!(relay_addr.is_ipv6());
                assert_eq!(relay_addr.port(), relay_port);

                if let SocketAddr::V6(v6) = relay_addr {
                    assert_eq!(*v6.ip(), relay_ipv6);
                } else {
                    panic!("Expected IPv6 relay address");
                }

                assoc.close().await;
            }
            Err(Socks5UdpError::IoError(msg))
                if msg.contains("connect") || msg.contains("bind") =>
            {
                // IPv6 not available on this system, skip the test
                eprintln!("Skipping IPv6 BND.ADDR test: IPv6 not available ({msg})");
            }
            Err(e) => {
                panic!("Unexpected error: {e}");
            }
        }

        let _ = server.await;
    }

    // ========================================================================
    // NoAcceptableMethod Tests (MT-3)
    // ========================================================================

    /// Mock SOCKS5 server that rejects all authentication methods
    async fn run_mock_udp_associate_server_no_acceptable_method(
        listener: tokio::net::TcpListener,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let (mut socket, _) = listener.accept().await?;

        // Read method selection
        let mut header = [0u8; 2];
        socket.read_exact(&mut header).await?;
        let nmethods = header[1] as usize;
        let mut methods = vec![0u8; nmethods];
        socket.read_exact(&mut methods).await?;

        // Reply with "no acceptable method" (0xFF)
        socket.write_all(&[SOCKS5_VERSION, AUTH_METHOD_NO_ACCEPTABLE]).await?;

        Ok(())
    }

    #[tokio::test]
    async fn test_establish_no_acceptable_method() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            run_mock_udp_associate_server_no_acceptable_method(listener).await
        });

        let result = Socks5UdpAssociation::establish(server_addr, None, Duration::from_secs(5)).await;

        assert!(result.is_err());
        assert!(matches!(result, Err(Socks5UdpError::NoAcceptableMethod)));

        let _ = server.await;
    }
}
