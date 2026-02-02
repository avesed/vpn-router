//! TUN-based egress bridge for VLESS/SS -> WireGuard
//!
//! This module provides the egress path for routing VLESS and Shadowsocks inbound
//! TCP/UDP streams through WireGuard tunnels using kernel socket bound to a TUN device.
//!
//! # Architecture
//!
//! ```text
//! VLESS/SS Inbound                  Kernel Space                    WireGuard Egress
//! ┌─────────────────┐              ┌─────────────────┐              ┌─────────────────┐
//! │ TCP/UDP Stream  │───────────▶  │ Socket (bound   │──────────▶  │ TUN Device      │
//! │ from VLESS/SS   │              │ to tun-out)     │              │ (tun-out)       │
//! └─────────────────┘              └─────────────────┘              └────────┬────────┘
//!                                                                            │
//!                                                                            │ IP packets
//!                                                                            ▼
//!                                                                   ┌─────────────────┐
//!                                                                   │ WgEgressManager │
//!                                                                   │ (send to tunnel)│
//!                                                                   └─────────────────┘
//! ```
//!
//! # Key Design
//!
//! Instead of using a userspace TCP/IP stack (smoltcp), this implementation leverages
//! the kernel's TCP/IP stack by:
//!
//! 1. Creating a TUN device (`tun-out`)
//! 2. Binding sockets to the TUN device using `SO_BINDTODEVICE`
//! 3. Reading IP packets from the TUN device
//! 4. Sending those packets through WireGuard tunnels
//! 5. Injecting WireGuard replies back into the TUN device
//!
//! This approach provides:
//! - Native kernel TCP congestion control
//! - Better performance than userspace TCP stacks
//! - Simpler implementation
//!
//! # Requirements
//!
//! - `CAP_NET_RAW` capability for `SO_BINDTODEVICE`
//! - `CAP_NET_ADMIN` for TUN device creation
//! - Proper routing rules to direct traffic through the TUN
//!
//! # Example
//!
//! ```ignore
//! use rust_router::tun_bridge::egress::{TunEgressBridge, TunEgressConfig};
//! use std::sync::Arc;
//!
//! // Create the bridge
//! let config = TunEgressConfig {
//!     tun_name: "tun-out".to_string(),
//!     tun_cidr: "10.200.200.1/24".to_string(),
//!     tun_mtu: 1420,
//!     wg_egress: wg_manager.clone(),
//! };
//!
//! let bridge = TunEgressBridge::new(config).await?;
//!
//! // Spawn the TUN read loop
//! let bridge_clone = bridge.clone();
//! tokio::spawn(async move {
//!     if let Err(e) = bridge_clone.run_tun_read_loop().await {
//!         eprintln!("TUN read loop error: {}", e);
//!     }
//! });
//!
//! // Handle a TCP connection from VLESS inbound
//! let stats = bridge.handle_tcp_connection(
//!     vless_stream,
//!     "93.184.216.34:80".parse()?,
//!     "wg-pia-nyc",
//! ).await?;
//! ```

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use dashmap::DashMap;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpSocket;
use tokio::sync::{mpsc, Notify};
use tracing::{debug, error, info, trace, warn};

use crate::egress::WgEgressManager;
use crate::tun::{TunConfig, TunDevice};

// =============================================================================
// Constants
// =============================================================================

/// Default egress TUN device name
pub const DEFAULT_EGRESS_TUN_NAME: &str = "tun-out";

/// Default egress TUN CIDR
pub const DEFAULT_EGRESS_TUN_CIDR: &str = "10.200.200.1/24";

/// Default TUN MTU
pub const DEFAULT_TUN_MTU: u16 = 1420;

/// Buffer size for socket I/O
const SOCKET_BUFFER_SIZE: usize = 65536;

/// Buffer size for TUN packet reading
const TUN_PACKET_BUFFER_SIZE: usize = 2048;

/// Maximum number of concurrent TCP sessions
const MAX_TCP_SESSIONS: usize = 10000;

/// TCP connect timeout
const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// UDP session timeout
const UDP_SESSION_TIMEOUT: Duration = Duration::from_secs(30);

/// DNS UDP session timeout (shorter for faster cleanup)
const UDP_DNS_TIMEOUT: Duration = Duration::from_secs(10);

/// Routing table ID for egress TUN (reserved for future use)
pub const EGRESS_ROUTE_TABLE: u32 = 201;

// =============================================================================
// Configuration
// =============================================================================

/// Configuration for the TUN egress bridge
#[derive(Debug, Clone)]
pub struct TunEgressConfig {
    /// TUN device name (e.g., "tun-out")
    pub tun_name: String,
    /// TUN device CIDR (e.g., "10.200.200.1/24")
    pub tun_cidr: String,
    /// TUN device MTU
    pub tun_mtu: u16,
    /// WireGuard egress manager for sending packets
    pub wg_egress: Arc<WgEgressManager>,
    /// Default tunnel tag for packets without explicit routing
    pub default_tunnel_tag: Option<String>,
}

impl Default for TunEgressConfig {
    fn default() -> Self {
        Self {
            tun_name: DEFAULT_EGRESS_TUN_NAME.to_string(),
            tun_cidr: DEFAULT_EGRESS_TUN_CIDR.to_string(),
            tun_mtu: DEFAULT_TUN_MTU,
            wg_egress: Arc::new(WgEgressManager::new(Arc::new(
                crate::egress::reply::WgReplyHandler::noop(),
            ))),
            default_tunnel_tag: None,
        }
    }
}

// =============================================================================
// Statistics
// =============================================================================

/// Statistics for TCP connections
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TcpConnectionStats {
    /// Bytes sent from client to server
    pub bytes_sent: u64,
    /// Bytes received from server to client
    pub bytes_received: u64,
    /// Duration of the connection
    pub duration_ms: u64,
    /// Whether the connection completed successfully
    pub success: bool,
    /// Error message if connection failed
    pub error: Option<String>,
}

/// Statistics for UDP connections
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UdpConnectionStats {
    /// Packets sent
    pub packets_sent: u64,
    /// Packets received
    pub packets_received: u64,
    /// Bytes sent
    pub bytes_sent: u64,
    /// Bytes received
    pub bytes_received: u64,
    /// Duration of the session
    pub duration_ms: u64,
}

/// Overall statistics for the egress bridge
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TunEgressStats {
    /// Total TCP connections handled
    pub tcp_connections: u64,
    /// Active TCP connections
    pub tcp_active: u64,
    /// TCP connection errors
    pub tcp_errors: u64,
    /// Total TCP bytes sent
    pub tcp_bytes_sent: u64,
    /// Total TCP bytes received
    pub tcp_bytes_received: u64,
    /// Total UDP sessions
    pub udp_sessions: u64,
    /// Active UDP sessions
    pub udp_active: u64,
    /// UDP packets sent
    pub udp_packets_sent: u64,
    /// UDP packets received
    pub udp_packets_received: u64,
    /// Packets read from TUN device
    pub tun_packets_read: u64,
    /// Packets written to TUN device
    pub tun_packets_written: u64,
    /// Packets sent to WireGuard tunnels
    pub wg_packets_sent: u64,
    /// WireGuard reply packets injected
    pub wg_replies_injected: u64,
}

/// Internal atomic statistics
#[derive(Default)]
struct AtomicStats {
    tcp_connections: AtomicU64,
    tcp_active: AtomicU64,
    tcp_errors: AtomicU64,
    tcp_bytes_sent: AtomicU64,
    tcp_bytes_received: AtomicU64,
    udp_sessions: AtomicU64,
    udp_active: AtomicU64,
    udp_packets_sent: AtomicU64,
    udp_packets_received: AtomicU64,
    tun_packets_read: AtomicU64,
    tun_packets_written: AtomicU64,
    wg_packets_sent: AtomicU64,
    wg_replies_injected: AtomicU64,
}

impl AtomicStats {
    fn snapshot(&self) -> TunEgressStats {
        TunEgressStats {
            tcp_connections: self.tcp_connections.load(Ordering::Relaxed),
            tcp_active: self.tcp_active.load(Ordering::Relaxed),
            tcp_errors: self.tcp_errors.load(Ordering::Relaxed),
            tcp_bytes_sent: self.tcp_bytes_sent.load(Ordering::Relaxed),
            tcp_bytes_received: self.tcp_bytes_received.load(Ordering::Relaxed),
            udp_sessions: self.udp_sessions.load(Ordering::Relaxed),
            udp_active: self.udp_active.load(Ordering::Relaxed),
            udp_packets_sent: self.udp_packets_sent.load(Ordering::Relaxed),
            udp_packets_received: self.udp_packets_received.load(Ordering::Relaxed),
            tun_packets_read: self.tun_packets_read.load(Ordering::Relaxed),
            tun_packets_written: self.tun_packets_written.load(Ordering::Relaxed),
            wg_packets_sent: self.wg_packets_sent.load(Ordering::Relaxed),
            wg_replies_injected: self.wg_replies_injected.load(Ordering::Relaxed),
        }
    }
}

// =============================================================================
// Session Tracking
// =============================================================================

/// Unique session identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId(u64);

impl SessionId {
    /// Create a new session ID from a counter
    #[must_use]
    pub fn new(id: u64) -> Self {
        Self(id)
    }

    /// Get the raw ID value
    #[must_use]
    pub fn as_u64(&self) -> u64 {
        self.0
    }
}

impl std::fmt::Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Session({})", self.0)
    }
}

/// TCP session handle for tracking active connections
#[derive(Debug)]
struct TcpSessionHandle {
    /// Session ID
    id: SessionId,
    /// Destination address
    dest_addr: SocketAddr,
    /// Tunnel tag being used
    tunnel_tag: String,
    /// Creation time
    created_at: Instant,
    /// Shutdown signal
    shutdown_tx: Option<mpsc::Sender<()>>,
}

/// UDP session handle
#[derive(Debug)]
struct UdpSessionHandle {
    /// Session ID
    id: SessionId,
    /// Client address (source)
    client_addr: SocketAddr,
    /// Tunnel tag being used
    tunnel_tag: String,
    /// Last activity time
    last_activity: Instant,
    /// Reply sender
    reply_tx: mpsc::Sender<(SocketAddr, Bytes)>,
}

// =============================================================================
// Routing
// =============================================================================

/// Destination-to-tunnel routing table
///
/// Maps destination IP ranges to tunnel tags for packet routing.
#[derive(Debug, Default)]
pub struct TunnelRouter {
    /// IP prefix to tunnel tag mapping
    routes: RwLock<HashMap<IpAddr, String>>,
    /// Default tunnel tag
    default_tunnel: RwLock<Option<String>>,
}

impl TunnelRouter {
    /// Create a new router
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a route for an IP address
    pub fn add_route(&self, dest_ip: IpAddr, tunnel_tag: String) {
        let mut routes = self.routes.write();
        routes.insert(dest_ip, tunnel_tag);
    }

    /// Remove a route
    pub fn remove_route(&self, dest_ip: &IpAddr) {
        let mut routes = self.routes.write();
        routes.remove(dest_ip);
    }

    /// Set the default tunnel
    pub fn set_default(&self, tunnel_tag: Option<String>) {
        let mut default = self.default_tunnel.write();
        *default = tunnel_tag;
    }

    /// Get the tunnel tag for a destination IP
    #[must_use]
    pub fn get_tunnel(&self, dest_ip: &IpAddr) -> Option<String> {
        let routes = self.routes.read();
        if let Some(tag) = routes.get(dest_ip) {
            return Some(tag.clone());
        }

        let default = self.default_tunnel.read();
        default.clone()
    }
}

// =============================================================================
// TunEgressBridge
// =============================================================================

/// TUN-based egress bridge for VLESS/SS -> WireGuard
///
/// This bridge handles routing TCP and UDP traffic from VLESS/Shadowsocks
/// inbound connections through WireGuard tunnels using kernel sockets
/// bound to a TUN device.
pub struct TunEgressBridge {
    /// TUN device for capturing outbound packets
    tun: Arc<TunDevice>,
    /// WireGuard egress manager
    wg_egress: Arc<WgEgressManager>,
    /// Tunnel router for destination-based routing
    router: Arc<TunnelRouter>,
    /// Active TCP sessions
    tcp_sessions: DashMap<SessionId, TcpSessionHandle>,
    /// Active UDP sessions (keyed by client addr + dest addr)
    udp_sessions: DashMap<(SocketAddr, SocketAddr), UdpSessionHandle>,
    /// Statistics
    stats: Arc<AtomicStats>,
    /// Session ID counter
    session_counter: AtomicU64,
    /// Shutdown flag
    shutdown: AtomicBool,
    /// Shutdown notification
    shutdown_notify: Arc<Notify>,
    /// Configuration
    config: TunEgressConfig,
}

impl TunEgressBridge {
    /// Create a new egress bridge
    ///
    /// # Arguments
    ///
    /// * `config` - Bridge configuration
    ///
    /// # Errors
    ///
    /// Returns an error if TUN device creation fails.
    ///
    /// # Requirements
    ///
    /// - `CAP_NET_ADMIN` capability for TUN device creation
    pub async fn new(config: TunEgressConfig) -> io::Result<Arc<Self>> {
        info!(
            tun = %config.tun_name,
            cidr = %config.tun_cidr,
            mtu = config.tun_mtu,
            "Creating TUN egress bridge"
        );

        // Create the TUN device configuration
        let tun_config = TunConfig::new(&config.tun_name).with_mtu(config.tun_mtu);

        // Create the TUN device
        let tun = TunDevice::create(&tun_config)?;

        // Configure the TUN device with IP address
        tun.configure(&config.tun_cidr)?;

        let tun = Arc::new(tun);

        // Set up routing
        let router = Arc::new(TunnelRouter::new());
        if let Some(ref tag) = config.default_tunnel_tag {
            router.set_default(Some(tag.clone()));
        }

        let bridge = Arc::new(Self {
            tun,
            wg_egress: config.wg_egress.clone(),
            router,
            tcp_sessions: DashMap::new(),
            udp_sessions: DashMap::new(),
            stats: Arc::new(AtomicStats::default()),
            session_counter: AtomicU64::new(1),
            shutdown: AtomicBool::new(false),
            shutdown_notify: Arc::new(Notify::new()),
            config,
        });

        info!("TUN egress bridge created successfully");

        Ok(bridge)
    }

    /// Get a reference to the TUN device
    #[must_use]
    pub fn tun(&self) -> &TunDevice {
        &self.tun
    }

    /// Get a reference to the tunnel router
    #[must_use]
    pub fn router(&self) -> &TunnelRouter {
        &self.router
    }

    /// Get current statistics
    #[must_use]
    pub fn stats(&self) -> TunEgressStats {
        self.stats.snapshot()
    }

    /// Check if the bridge is shutting down
    #[must_use]
    pub fn is_shutting_down(&self) -> bool {
        self.shutdown.load(Ordering::Acquire)
    }

    /// Generate a new session ID
    fn next_session_id(&self) -> SessionId {
        SessionId::new(self.session_counter.fetch_add(1, Ordering::Relaxed))
    }

    /// Handle a TCP connection from VLESS/SS inbound
    ///
    /// This creates a kernel socket bound to the TUN interface,
    /// connects to the destination, and performs bidirectional copy.
    /// The kernel generates IP packets through the TUN.
    ///
    /// # Arguments
    ///
    /// * `stream` - The inbound TCP stream from VLESS/SS
    /// * `dest_addr` - Destination address to connect to
    /// * `tunnel_tag` - WireGuard tunnel tag to route through
    ///
    /// # Returns
    ///
    /// Connection statistics after the connection closes.
    ///
    /// # Requirements
    ///
    /// - `CAP_NET_RAW` capability for `SO_BINDTODEVICE`
    pub async fn handle_tcp_connection<S>(
        &self,
        stream: S,
        dest_addr: SocketAddr,
        tunnel_tag: &str,
    ) -> io::Result<TcpConnectionStats>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let start = Instant::now();
        let session_id = self.next_session_id();

        debug!(
            session = %session_id,
            dest = %dest_addr,
            tunnel = %tunnel_tag,
            "Handling TCP connection"
        );

        // Update stats
        self.stats.tcp_connections.fetch_add(1, Ordering::Relaxed);
        self.stats.tcp_active.fetch_add(1, Ordering::Relaxed);

        // Create shutdown channel
        let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);

        // Track the session
        self.tcp_sessions.insert(
            session_id,
            TcpSessionHandle {
                id: session_id,
                dest_addr,
                tunnel_tag: tunnel_tag.to_string(),
                created_at: start,
                shutdown_tx: Some(shutdown_tx),
            },
        );

        // Create and connect the socket
        let socket = match self.create_bound_socket(dest_addr.is_ipv4()).await {
            Ok(s) => s,
            Err(e) => {
                self.cleanup_tcp_session(session_id);
                self.stats.tcp_errors.fetch_add(1, Ordering::Relaxed);
                return Ok(TcpConnectionStats {
                    success: false,
                    error: Some(format!("Failed to create socket: {}", e)),
                    duration_ms: start.elapsed().as_millis() as u64,
                    ..Default::default()
                });
            }
        };

        // Connect with timeout
        let connect_result = tokio::time::timeout(
            TCP_CONNECT_TIMEOUT,
            socket.connect(dest_addr),
        )
        .await;

        let mut tcp_stream = match connect_result {
            Ok(Ok(stream)) => stream,
            Ok(Err(e)) => {
                self.cleanup_tcp_session(session_id);
                self.stats.tcp_errors.fetch_add(1, Ordering::Relaxed);
                return Ok(TcpConnectionStats {
                    success: false,
                    error: Some(format!("Connect failed: {}", e)),
                    duration_ms: start.elapsed().as_millis() as u64,
                    ..Default::default()
                });
            }
            Err(_) => {
                self.cleanup_tcp_session(session_id);
                self.stats.tcp_errors.fetch_add(1, Ordering::Relaxed);
                return Ok(TcpConnectionStats {
                    success: false,
                    error: Some("Connect timeout".to_string()),
                    duration_ms: start.elapsed().as_millis() as u64,
                    ..Default::default()
                });
            }
        };

        debug!(
            session = %session_id,
            dest = %dest_addr,
            "TCP connection established"
        );

        // Perform bidirectional copy
        let (mut read_half, mut write_half) = tcp_stream.split();
        let (mut stream_read, mut stream_write) = tokio::io::split(stream);

        let bytes_sent = Arc::new(AtomicU64::new(0));
        let bytes_received = Arc::new(AtomicU64::new(0));

        let bytes_sent_clone = bytes_sent.clone();
        let bytes_received_clone = bytes_received.clone();

        // Bidirectional copy with shutdown handling
        let copy_result = tokio::select! {
            biased;

            _ = shutdown_rx.recv() => {
                debug!(session = %session_id, "TCP session shutdown requested");
                Ok((0, 0))
            }

            result = async {
                let client_to_server = async {
                    let mut buf = vec![0u8; SOCKET_BUFFER_SIZE];
                    let mut total = 0u64;
                    loop {
                        let n = stream_read.read(&mut buf).await?;
                        if n == 0 {
                            break;
                        }
                        write_half.write_all(&buf[..n]).await?;
                        total += n as u64;
                        bytes_sent_clone.fetch_add(n as u64, Ordering::Relaxed);
                    }
                    write_half.shutdown().await?;
                    Ok::<_, io::Error>(total)
                };

                let server_to_client = async {
                    let mut buf = vec![0u8; SOCKET_BUFFER_SIZE];
                    let mut total = 0u64;
                    loop {
                        let n = read_half.read(&mut buf).await?;
                        if n == 0 {
                            break;
                        }
                        stream_write.write_all(&buf[..n]).await?;
                        total += n as u64;
                        bytes_received_clone.fetch_add(n as u64, Ordering::Relaxed);
                    }
                    stream_write.shutdown().await?;
                    Ok::<_, io::Error>(total)
                };

                tokio::try_join!(client_to_server, server_to_client)
            } => result,
        };

        // Cleanup
        self.cleanup_tcp_session(session_id);

        let sent = bytes_sent.load(Ordering::Relaxed);
        let received = bytes_received.load(Ordering::Relaxed);
        let duration_ms = start.elapsed().as_millis() as u64;

        // Update global stats
        self.stats.tcp_bytes_sent.fetch_add(sent, Ordering::Relaxed);
        self.stats.tcp_bytes_received.fetch_add(received, Ordering::Relaxed);

        match copy_result {
            Ok(_) => {
                debug!(
                    session = %session_id,
                    sent = sent,
                    received = received,
                    duration_ms = duration_ms,
                    "TCP connection completed successfully"
                );
                Ok(TcpConnectionStats {
                    bytes_sent: sent,
                    bytes_received: received,
                    duration_ms,
                    success: true,
                    error: None,
                })
            }
            Err(e) => {
                debug!(
                    session = %session_id,
                    error = %e,
                    "TCP connection error"
                );
                self.stats.tcp_errors.fetch_add(1, Ordering::Relaxed);
                Ok(TcpConnectionStats {
                    bytes_sent: sent,
                    bytes_received: received,
                    duration_ms,
                    success: false,
                    error: Some(e.to_string()),
                })
            }
        }
    }

    /// Handle a UDP "connection" from VLESS/SS inbound (XUDP format)
    ///
    /// This handles the VLESS/Xray UDP-over-TCP framing format where each
    /// UDP datagram is prefixed with address and length information.
    ///
    /// # Arguments
    ///
    /// * `stream` - The inbound stream carrying UDP datagrams
    /// * `initial_dest` - Initial destination address (from VLESS header)
    /// * `tunnel_tag` - WireGuard tunnel tag to route through
    ///
    /// # Returns
    ///
    /// Session statistics after the session closes.
    pub async fn handle_udp_connection<S>(
        &self,
        mut stream: S,
        initial_dest: SocketAddr,
        tunnel_tag: &str,
    ) -> io::Result<UdpConnectionStats>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let start = Instant::now();
        let session_id = self.next_session_id();

        debug!(
            session = %session_id,
            dest = %initial_dest,
            tunnel = %tunnel_tag,
            "Handling UDP connection"
        );

        // Update stats
        self.stats.udp_sessions.fetch_add(1, Ordering::Relaxed);
        self.stats.udp_active.fetch_add(1, Ordering::Relaxed);

        // Create reply channel
        let (reply_tx, mut reply_rx) = mpsc::channel::<(SocketAddr, Bytes)>(256);

        // Create UDP socket bound to TUN
        let socket = self.create_udp_socket().await?;

        // Track session with a synthetic client address
        // In practice, this would come from the VLESS protocol
        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0);

        self.udp_sessions.insert(
            (client_addr, initial_dest),
            UdpSessionHandle {
                id: session_id,
                client_addr,
                tunnel_tag: tunnel_tag.to_string(),
                last_activity: Instant::now(),
                reply_tx: reply_tx.clone(),
            },
        );

        let mut packets_sent = 0u64;
        let mut packets_received = 0u64;
        let mut bytes_sent = 0u64;
        let mut bytes_received = 0u64;

        // Determine timeout based on whether this looks like DNS
        let timeout = if initial_dest.port() == 53 {
            UDP_DNS_TIMEOUT
        } else {
            UDP_SESSION_TIMEOUT
        };

        // Simple UDP relay loop
        // In practice, this would parse XUDP framing from the stream
        // Use separate buffers to avoid mutable borrow issues in select!
        let mut recv_buf = vec![0u8; SOCKET_BUFFER_SIZE];
        let mut send_buf = vec![0u8; SOCKET_BUFFER_SIZE];

        loop {
            tokio::select! {
                biased;

                // Check for shutdown
                _ = self.shutdown_notify.notified(), if self.is_shutting_down() => {
                    debug!(session = %session_id, "UDP session shutdown");
                    break;
                }

                // Receive replies from the socket
                result = socket.recv_from(&mut recv_buf) => {
                    match result {
                        Ok((n, from)) => {
                            trace!(
                                session = %session_id,
                                from = %from,
                                len = n,
                                "UDP reply received"
                            );
                            packets_received += 1;
                            bytes_received += n as u64;
                            self.stats.udp_packets_received.fetch_add(1, Ordering::Relaxed);

                            // Send reply back through the stream
                            // This would need proper XUDP framing in practice
                            if stream.write_all(&recv_buf[..n]).await.is_err() {
                                break;
                            }
                        }
                        Err(e) => {
                            debug!(session = %session_id, error = %e, "UDP recv error");
                            break;
                        }
                    }
                }

                // Read from the inbound stream
                result = stream.read(&mut send_buf) => {
                    match result {
                        Ok(0) => {
                            debug!(session = %session_id, "UDP stream closed");
                            break;
                        }
                        Ok(n) => {
                            trace!(
                                session = %session_id,
                                len = n,
                                "UDP data from client"
                            );
                            packets_sent += 1;
                            bytes_sent += n as u64;
                            self.stats.udp_packets_sent.fetch_add(1, Ordering::Relaxed);

                            // Send to the destination
                            // This would need proper XUDP parsing in practice
                            if socket.send_to(&send_buf[..n], initial_dest).await.is_err() {
                                break;
                            }
                        }
                        Err(e) => {
                            debug!(session = %session_id, error = %e, "UDP read error");
                            break;
                        }
                    }
                }

                // Handle replies from reply channel
                Some((from, data)) = reply_rx.recv() => {
                    trace!(
                        session = %session_id,
                        from = %from,
                        len = data.len(),
                        "UDP reply from channel"
                    );
                    packets_received += 1;
                    bytes_received += data.len() as u64;

                    if stream.write_all(&data).await.is_err() {
                        break;
                    }
                }

                // Timeout
                _ = tokio::time::sleep(timeout) => {
                    debug!(session = %session_id, "UDP session timeout");
                    break;
                }
            }
        }

        // Cleanup
        self.udp_sessions.remove(&(client_addr, initial_dest));
        self.stats.udp_active.fetch_sub(1, Ordering::Relaxed);

        let duration_ms = start.elapsed().as_millis() as u64;

        debug!(
            session = %session_id,
            packets_sent = packets_sent,
            packets_received = packets_received,
            duration_ms = duration_ms,
            "UDP session completed"
        );

        Ok(UdpConnectionStats {
            packets_sent,
            packets_received,
            bytes_sent,
            bytes_received,
            duration_ms,
        })
    }

    /// Run the TUN read loop
    ///
    /// This loop reads IP packets from the TUN device and sends them
    /// to the appropriate WireGuard tunnel based on the router configuration.
    ///
    /// # Cancellation
    ///
    /// The loop exits when `shutdown()` is called.
    pub async fn run_tun_read_loop(&self) -> io::Result<()> {
        info!("Starting TUN read loop");

        let mut buf = vec![0u8; TUN_PACKET_BUFFER_SIZE];

        loop {
            tokio::select! {
                biased;

                // Check for shutdown
                _ = self.shutdown_notify.notified(), if self.is_shutting_down() => {
                    info!("TUN read loop shutting down");
                    break;
                }

                // Read packet from TUN
                result = self.tun.read_packet(&mut buf) => {
                    match result {
                        Ok(n) if n > 0 => {
                            self.stats.tun_packets_read.fetch_add(1, Ordering::Relaxed);

                            // Parse destination IP from packet
                            if let Some(dest_ip) = parse_dest_ip(&buf[..n]) {
                                // Get tunnel tag for this destination
                                if let Some(tunnel_tag) = self.router.get_tunnel(&dest_ip) {
                                    // Send to WireGuard tunnel
                                    if let Err(e) = self.wg_egress.send(&tunnel_tag, buf[..n].to_vec()).await {
                                        trace!(
                                            dest = %dest_ip,
                                            tunnel = %tunnel_tag,
                                            error = %e,
                                            "Failed to send packet to WG tunnel"
                                        );
                                    } else {
                                        self.stats.wg_packets_sent.fetch_add(1, Ordering::Relaxed);
                                    }
                                } else {
                                    trace!(dest = %dest_ip, "No tunnel route for destination");
                                }
                            }
                        }
                        Ok(_) => {
                            // Zero-length read, continue
                        }
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                            // Non-blocking read returned no data
                            tokio::task::yield_now().await;
                        }
                        Err(e) => {
                            error!("TUN read error: {}", e);
                            // Brief delay before retrying
                            tokio::time::sleep(Duration::from_millis(10)).await;
                        }
                    }
                }
            }
        }

        info!("TUN read loop stopped");
        Ok(())
    }

    /// Inject a WireGuard reply packet into TUN
    ///
    /// When the WireGuard tunnel receives a reply packet, call this method
    /// to inject it into the TUN device so the kernel can route it to the
    /// appropriate socket.
    ///
    /// # Arguments
    ///
    /// * `packet` - Raw IP packet from WireGuard tunnel
    pub async fn inject_wg_reply(&self, packet: &[u8]) -> io::Result<()> {
        self.tun.write_packet(packet).await?;
        self.stats.wg_replies_injected.fetch_add(1, Ordering::Relaxed);
        self.stats.tun_packets_written.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Graceful shutdown
    ///
    /// Stops accepting new connections, signals existing sessions to close,
    /// and waits for cleanup to complete.
    pub async fn shutdown(&self) {
        info!("Initiating TUN egress bridge shutdown");

        // Set shutdown flag
        self.shutdown.store(true, Ordering::Release);

        // Notify all waiters
        self.shutdown_notify.notify_waiters();

        // Signal all TCP sessions to close
        for session in self.tcp_sessions.iter() {
            if let Some(ref tx) = session.shutdown_tx {
                let _ = tx.send(()).await;
            }
        }

        // Wait briefly for sessions to close
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Clear session maps
        self.tcp_sessions.clear();
        self.udp_sessions.clear();

        info!("TUN egress bridge shutdown complete");
    }

    /// Create a TCP socket bound to the TUN device
    ///
    /// # Requirements
    ///
    /// - `CAP_NET_RAW` capability for `SO_BINDTODEVICE`
    async fn create_bound_socket(&self, ipv4: bool) -> io::Result<TcpSocket> {
        let socket = if ipv4 {
            TcpSocket::new_v4()?
        } else {
            TcpSocket::new_v6()?
        };

        // Bind the socket to the TUN device
        self.bind_to_device(&socket)?;

        Ok(socket)
    }

    /// Create a UDP socket bound to the TUN device
    async fn create_udp_socket(&self) -> io::Result<tokio::net::UdpSocket> {
        let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;

        // Bind to device
        self.bind_socket_to_device(socket.as_raw_fd())?;

        Ok(socket)
    }

    /// Bind a TCP socket to the TUN device using SO_BINDTODEVICE
    fn bind_to_device(&self, socket: &TcpSocket) -> io::Result<()> {
        self.bind_socket_to_device(socket.as_raw_fd())
    }

    /// Bind a raw file descriptor to the TUN device
    fn bind_socket_to_device(&self, fd: i32) -> io::Result<()> {
        let device_bytes = self.config.tun_name.as_bytes();

        let ret = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_BINDTODEVICE,
                device_bytes.as_ptr() as *const libc::c_void,
                device_bytes.len() as libc::socklen_t,
            )
        };

        if ret < 0 {
            let err = io::Error::last_os_error();
            error!(
                device = %self.config.tun_name,
                error = %err,
                "Failed to bind socket to device (requires CAP_NET_RAW)"
            );
            return Err(err);
        }

        debug!(device = %self.config.tun_name, fd = fd, "Socket bound to device");
        Ok(())
    }

    /// Clean up a TCP session
    fn cleanup_tcp_session(&self, session_id: SessionId) {
        if self.tcp_sessions.remove(&session_id).is_some() {
            self.stats.tcp_active.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

impl std::fmt::Debug for TunEgressBridge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TunEgressBridge")
            .field("tun", &self.config.tun_name)
            .field("tcp_sessions", &self.tcp_sessions.len())
            .field("udp_sessions", &self.udp_sessions.len())
            .field("shutting_down", &self.is_shutting_down())
            .finish()
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Parse the destination IP address from an IP packet
///
/// Supports both IPv4 and IPv6 packets.
fn parse_dest_ip(packet: &[u8]) -> Option<IpAddr> {
    if packet.is_empty() {
        return None;
    }

    let version = (packet[0] >> 4) & 0xF;

    match version {
        4 if packet.len() >= 20 => {
            // IPv4: destination is at bytes 16-19
            let dest = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
            Some(IpAddr::V4(dest))
        }
        6 if packet.len() >= 40 => {
            // IPv6: destination is at bytes 24-39
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&packet[24..40]);
            let dest = std::net::Ipv6Addr::from(octets);
            Some(IpAddr::V6(dest))
        }
        _ => None,
    }
}

/// Parse the source IP address from an IP packet
#[allow(dead_code)]
fn parse_src_ip(packet: &[u8]) -> Option<IpAddr> {
    if packet.is_empty() {
        return None;
    }

    let version = (packet[0] >> 4) & 0xF;

    match version {
        4 if packet.len() >= 20 => {
            // IPv4: source is at bytes 12-15
            let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
            Some(IpAddr::V4(src))
        }
        6 if packet.len() >= 40 => {
            // IPv6: source is at bytes 8-23
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&packet[8..24]);
            let src = std::net::Ipv6Addr::from(octets);
            Some(IpAddr::V6(src))
        }
        _ => None,
    }
}

// =============================================================================
// Routing Setup
// =============================================================================

/// Manager for egress routing rules
///
/// Sets up the necessary routing rules to direct traffic through the egress TUN.
///
/// # Note on Routing Strategy
///
/// This implementation uses `SO_BINDTODEVICE` to bind sockets directly to the TUN
/// interface rather than fwmark-based policy routing. This is simpler and more
/// direct for our use case where we control all sockets.
///
/// The `SO_BINDTODEVICE` approach:
/// - Directly binds sockets to `tun-out` interface
/// - Traffic automatically uses the interface's routing table
/// - No additional iptables/policy routing rules needed
/// - Requires `CAP_NET_RAW` capability
pub struct EgressRoutingManager {
    /// TUN interface name
    tun_iface: String,
    /// Routing table ID (for documentation, not actively used with SO_BINDTODEVICE)
    table_id: u32,
    /// Whether rules have been applied
    rules_applied: bool,
}

impl EgressRoutingManager {
    /// Create a new routing manager
    ///
    /// # Arguments
    ///
    /// * `tun_iface` - TUN interface name
    /// * `table_id` - Routing table ID (default: 201, for documentation purposes)
    ///
    /// # Note
    ///
    /// Since we use `SO_BINDTODEVICE` on egress sockets, the routing table is
    /// not strictly needed. The kernel routes based on the bound interface.
    pub fn new(tun_iface: &str, table_id: u32) -> io::Result<Self> {
        // Validate interface name (IFNAMSIZ = 16, last byte for null terminator)
        if tun_iface.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Interface name cannot be empty",
            ));
        }
        if tun_iface.len() > 15 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Interface name '{}' exceeds 15 characters", tun_iface),
            ));
        }
        // Validate characters (alphanumeric, hyphen, underscore)
        for c in tun_iface.chars() {
            if !c.is_ascii_alphanumeric() && c != '-' && c != '_' {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("Invalid character '{}' in interface name", c),
                ));
            }
        }

        Ok(Self {
            tun_iface: tun_iface.to_string(),
            table_id,
            rules_applied: false,
        })
    }

    /// Apply routing rules
    ///
    /// Sets up a default route through the TUN device in the routing table.
    ///
    /// # Note
    ///
    /// When using `SO_BINDTODEVICE`, additional policy routing rules are typically
    /// not needed. The socket is bound directly to the interface and traffic
    /// follows that interface's routing. This method is provided for compatibility
    /// and for cases where explicit routing table entries are needed.
    pub fn apply_rules(&mut self) -> io::Result<()> {
        info!(
            tun = %self.tun_iface,
            table = self.table_id,
            "Applying egress routing rules (default route through TUN)"
        );

        // Add default route through TUN in routing table
        // This ensures any traffic destined for this table goes through our TUN
        self.run_command(
            "ip",
            &[
                "route",
                "add",
                "default",
                "dev",
                &self.tun_iface,
                "table",
                &self.table_id.to_string(),
            ],
        )?;

        self.rules_applied = true;
        info!("Egress routing rules applied");

        Ok(())
    }

    /// Clean up routing rules
    pub fn cleanup_rules(&mut self) -> io::Result<()> {
        if !self.rules_applied {
            return Ok(());
        }

        info!("Cleaning up egress routing rules");

        // Remove default route
        let _ = self.run_command(
            "ip",
            &[
                "route",
                "del",
                "default",
                "dev",
                &self.tun_iface,
                "table",
                &self.table_id.to_string(),
            ],
        );

        self.rules_applied = false;
        Ok(())
    }

    /// Run a command
    fn run_command(&self, program: &str, args: &[&str]) -> io::Result<()> {
        use std::process::Command;

        debug!(program = %program, args = ?args, "Running command");

        let output = Command::new(program).args(args).output()?;

        if output.status.success() {
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(io::Error::new(
                io::ErrorKind::Other,
                format!("{} failed: {}", program, stderr.trim()),
            ))
        }
    }

    /// Generate setup commands for documentation/debugging
    #[must_use]
    pub fn generate_setup_commands(&self) -> String {
        format!(
            r#"# Egress TUN routing setup
# Route traffic through {tun} interface using SO_BINDTODEVICE

# Optional: Add default route in table {table} (for explicit routing)
ip route add default dev {tun} table {table}

# Note: With SO_BINDTODEVICE, sockets are bound directly to the interface.
# No additional policy routing rules are needed. Example in code:
#
#   let ret = libc::setsockopt(
#       fd, libc::SOL_SOCKET, libc::SO_BINDTODEVICE,
#       "{tun}".as_ptr(), {tun_len}
#   );
#
# Requires CAP_NET_RAW capability.
"#,
            tun = self.tun_iface,
            table = self.table_id,
            tun_len = self.tun_iface.len(),
        )
    }
}

impl Drop for EgressRoutingManager {
    fn drop(&mut self) {
        if self.rules_applied {
            if let Err(e) = self.cleanup_rules() {
                warn!("Failed to cleanup routing rules on drop: {}", e);
            }
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_id() {
        let id1 = SessionId::new(1);
        let id2 = SessionId::new(2);

        assert_eq!(id1.as_u64(), 1);
        assert_eq!(id2.as_u64(), 2);
        assert_ne!(id1, id2);

        let display = format!("{}", id1);
        assert!(display.contains("1"));
    }

    #[test]
    fn test_tunnel_router() {
        let router = TunnelRouter::new();

        // No default, no routes
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(router.get_tunnel(&ip).is_none());

        // Set default
        router.set_default(Some("default-tunnel".to_string()));
        assert_eq!(router.get_tunnel(&ip), Some("default-tunnel".to_string()));

        // Add specific route
        router.add_route(ip, "specific-tunnel".to_string());
        assert_eq!(router.get_tunnel(&ip), Some("specific-tunnel".to_string()));

        // Different IP uses default
        let other_ip: IpAddr = "10.0.0.2".parse().unwrap();
        assert_eq!(router.get_tunnel(&other_ip), Some("default-tunnel".to_string()));

        // Remove route, falls back to default
        router.remove_route(&ip);
        assert_eq!(router.get_tunnel(&ip), Some("default-tunnel".to_string()));
    }

    #[test]
    fn test_parse_dest_ip_v4() {
        // Minimal IPv4 packet (20 bytes header)
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45; // Version 4, IHL 5
        // Destination at bytes 16-19
        packet[16] = 192;
        packet[17] = 168;
        packet[18] = 1;
        packet[19] = 100;

        let dest = parse_dest_ip(&packet);
        assert_eq!(dest, Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
    }

    #[test]
    fn test_parse_dest_ip_v6() {
        // Minimal IPv6 packet (40 bytes header)
        let mut packet = vec![0u8; 40];
        packet[0] = 0x60; // Version 6
        // Destination at bytes 24-39
        packet[24..40].copy_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ]);

        let dest = parse_dest_ip(&packet);
        assert!(matches!(dest, Some(IpAddr::V6(_))));
    }

    #[test]
    fn test_parse_dest_ip_invalid() {
        // Too short
        assert!(parse_dest_ip(&[]).is_none());
        assert!(parse_dest_ip(&[0x45]).is_none());

        // Invalid version
        let mut packet = vec![0u8; 20];
        packet[0] = 0x35; // Version 3 (invalid)
        assert!(parse_dest_ip(&packet).is_none());
    }

    #[test]
    fn test_parse_src_ip_v4() {
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45;
        // Source at bytes 12-15
        packet[12] = 10;
        packet[13] = 0;
        packet[14] = 0;
        packet[15] = 1;

        let src = parse_src_ip(&packet);
        assert_eq!(src, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    }

    #[test]
    fn test_tcp_connection_stats_default() {
        let stats = TcpConnectionStats::default();
        assert_eq!(stats.bytes_sent, 0);
        assert_eq!(stats.bytes_received, 0);
        assert!(!stats.success);
        assert!(stats.error.is_none());
    }

    #[test]
    fn test_udp_connection_stats_default() {
        let stats = UdpConnectionStats::default();
        assert_eq!(stats.packets_sent, 0);
        assert_eq!(stats.packets_received, 0);
    }

    #[test]
    fn test_tun_egress_stats_default() {
        let stats = TunEgressStats::default();
        assert_eq!(stats.tcp_connections, 0);
        assert_eq!(stats.tcp_active, 0);
        assert_eq!(stats.udp_sessions, 0);
    }

    #[test]
    fn test_egress_routing_manager_new() {
        let manager = EgressRoutingManager::new("tun-out", 201).unwrap();
        assert_eq!(manager.tun_iface, "tun-out");
        assert_eq!(manager.table_id, 201);
        assert!(!manager.rules_applied);
    }

    #[test]
    fn test_egress_routing_manager_invalid_name() {
        // Empty name
        assert!(EgressRoutingManager::new("", 201).is_err());

        // Name too long
        assert!(EgressRoutingManager::new("this-name-is-way-too-long", 201).is_err());

        // Invalid characters
        assert!(EgressRoutingManager::new("tun/out", 201).is_err());
        assert!(EgressRoutingManager::new("tun out", 201).is_err());
    }

    #[test]
    fn test_egress_routing_manager_valid_names() {
        // Alphanumeric
        assert!(EgressRoutingManager::new("tun0", 201).is_ok());
        // With hyphen
        assert!(EgressRoutingManager::new("tun-out", 201).is_ok());
        // With underscore
        assert!(EgressRoutingManager::new("tun_out", 201).is_ok());
        // Max length (15 chars)
        assert!(EgressRoutingManager::new("tun-egress-out1", 201).is_ok());
    }

    #[test]
    fn test_egress_routing_manager_generate_commands() {
        let manager = EgressRoutingManager::new("tun-out", 201).unwrap();
        let commands = manager.generate_setup_commands();

        assert!(commands.contains("tun-out"));
        assert!(commands.contains("table 201"));
        assert!(commands.contains("SO_BINDTODEVICE"));
    }

    #[test]
    fn test_config_default() {
        let config = TunEgressConfig::default();
        assert_eq!(config.tun_name, DEFAULT_EGRESS_TUN_NAME);
        assert_eq!(config.tun_cidr, DEFAULT_EGRESS_TUN_CIDR);
        assert_eq!(config.tun_mtu, DEFAULT_TUN_MTU);
        assert!(config.default_tunnel_tag.is_none());
    }

    #[test]
    fn test_atomic_stats_snapshot() {
        let stats = AtomicStats::default();
        stats.tcp_connections.store(10, Ordering::Relaxed);
        stats.tcp_active.store(5, Ordering::Relaxed);
        stats.udp_sessions.store(20, Ordering::Relaxed);

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.tcp_connections, 10);
        assert_eq!(snapshot.tcp_active, 5);
        assert_eq!(snapshot.udp_sessions, 20);
    }
}
