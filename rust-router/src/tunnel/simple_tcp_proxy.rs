//! Simple TCP proxy for forwarding connections through smoltcp to localhost
//!
//! This module provides `SimpleTcpProxy`, which handles incoming TCP connections
//! received via the smoltcp stack (through peer tunnels) and proxies them to
//! the local API server at `localhost:36000`.
//!
//! # Architecture
//!
//! ```text
//! Peer Tunnel (receives packets)
//!       |
//!       v
//! SmoltcpBridge (handles TCP state)
//!       |
//!       v
//! SimpleTcpProxy (proxies to localhost:36000, injects X-Tunnel-Source-IP)
//!       |
//!       v
//! API Server (localhost:36000)
//! ```
//!
//! # Features
//!
//! - TCP connection proxying from smoltcp to localhost
//! - HTTP header injection (`X-Tunnel-Source-IP`) for source identification
//! - Bidirectional data forwarding
//! - Connection timeout handling
//! - Graceful shutdown support
//!
//! # Usage
//!
//! ```ignore
//! use std::net::Ipv4Addr;
//! use rust_router::tunnel::simple_tcp_proxy::SimpleTcpProxy;
//! use rust_router::tunnel::SmoltcpBridge;
//! use tokio::sync::mpsc;
//!
//! // Create bridge with local tunnel IP
//! let bridge = SmoltcpBridge::new(Ipv4Addr::new(10, 200, 200, 1), 1420);
//!
//! // Create channels for packet exchange with WireGuard tunnel
//! let (tx_sender, tx_receiver) = mpsc::channel(256);
//! let (rx_sender, rx_receiver) = mpsc::channel(256);
//!
//! // Create and run the proxy
//! let proxy = SimpleTcpProxy::new(36000);
//! proxy.run(bridge, tx_sender, rx_receiver, shutdown_rx).await?;
//! ```

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use smoltcp::iface::SocketHandle;
use smoltcp::socket::tcp::State as TcpState;
use smoltcp::wire::{IpAddress, Ipv4Packet};
use thiserror::Error;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::{sleep, timeout, Instant};
use tracing::{debug, info, trace, warn};

use crate::tunnel::smoltcp_bridge::SmoltcpBridge;

/// Default port for the API server
pub const DEFAULT_API_PORT: u16 = 36000;

/// Connection timeout for localhost (5 seconds - localhost should respond quickly)
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(5);

/// Idle timeout for connections (2 minutes)
const IDLE_TIMEOUT: Duration = Duration::from_secs(120);

/// Minimum poll interval to avoid busy-waiting (1ms)
const MIN_POLL_INTERVAL_MS: u64 = 1;

/// Maximum poll interval (50ms)
const MAX_POLL_INTERVAL_MS: u64 = 50;

/// Buffer size for reading from smoltcp sockets (increased to reduce buffer asymmetry with 64KB socket buffers)
const SMOLTCP_BUFFER_SIZE: usize = 16384;

/// Buffer size for reading from local TCP connections
const LOCAL_BUFFER_SIZE: usize = 8192;

/// Maximum HTTP request header size for injection detection
const MAX_HEADER_DETECT_SIZE: usize = 8192;

/// Maximum concurrent connections to prevent DoS resource exhaustion
const MAX_CONCURRENT_CONNECTIONS: usize = 64;

/// Error types for TCP proxy operations
#[derive(Debug, Error)]
pub enum TcpProxyError {
    /// Failed to accept connection
    #[error("Accept failed: {0}")]
    AcceptFailed(String),

    /// Failed to connect to local server
    #[error("Local connection failed: {0}")]
    LocalConnectionFailed(String),

    /// Connection timed out
    #[error("Connection timed out")]
    Timeout,

    /// Socket error from smoltcp
    #[error("Socket error: {0}")]
    SocketError(String),

    /// I/O error
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    /// Tunnel communication error
    #[error("Tunnel error: {0}")]
    TunnelError(String),

    /// Proxy was shut down
    #[error("Proxy shutdown")]
    Shutdown,
}

/// Statistics for the TCP proxy
#[derive(Debug, Default)]
pub struct TcpProxyStats {
    /// Total connections accepted
    pub connections_accepted: std::sync::atomic::AtomicU64,
    /// Total connections completed successfully
    pub connections_completed: std::sync::atomic::AtomicU64,
    /// Total connections that failed
    pub connections_failed: std::sync::atomic::AtomicU64,
    /// Total bytes forwarded from tunnel to local
    pub bytes_tunnel_to_local: std::sync::atomic::AtomicU64,
    /// Total bytes forwarded from local to tunnel
    pub bytes_local_to_tunnel: std::sync::atomic::AtomicU64,
    /// Current active connections
    pub active_connections: std::sync::atomic::AtomicU64,
}

impl TcpProxyStats {
    /// Create new empty stats
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }
}

/// Represents an active proxied connection
struct ProxiedConnection {
    /// Socket handle in smoltcp
    handle: SocketHandle,
    /// Local TCP stream to the API server
    local_stream: TcpStream,
    /// Source IP from the tunnel (for header injection)
    source_ip: Ipv4Addr,
    /// Peer tag for logging and future authentication headers (Phase 5)
    /// Currently unused but will be used for X-Tunnel-Peer-Tag and HMAC auth headers
    #[allow(dead_code)]
    peer_tag: Option<String>,
    /// Buffer for data received from smoltcp
    smoltcp_buffer: Vec<u8>,
    /// Buffer for data from local that couldn't be sent to tunnel (prevents data loss on partial send)
    pending_to_tunnel: Vec<u8>,
    /// Whether we've injected the header (only once per connection)
    header_injected: bool,
    /// Last activity time
    last_activity: Instant,
    /// Connection state
    state: ConnectionState,
    /// Whether the local side has closed (half-close support)
    local_read_closed: bool,
    /// Whether the tunnel side has closed (half-close support)
    tunnel_read_closed: bool,
}

/// Connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectionState {
    /// Actively proxying data
    Active,
    /// Closing gracefully
    Closing,
}

impl ProxiedConnection {
    /// Create a new proxied connection
    fn new(handle: SocketHandle, local_stream: TcpStream, source_ip: Ipv4Addr) -> Self {
        Self {
            handle,
            local_stream,
            source_ip,
            peer_tag: None,
            smoltcp_buffer: Vec::with_capacity(SMOLTCP_BUFFER_SIZE),
            pending_to_tunnel: Vec::new(),
            header_injected: false,
            last_activity: Instant::now(),
            state: ConnectionState::Active,
            local_read_closed: false,
            tunnel_read_closed: false,
        }
    }

    /// Create a new proxied connection with peer tag
    /// Reserved for Phase 5 authentication header injection
    #[allow(dead_code)]
    fn with_peer_tag(
        handle: SocketHandle,
        local_stream: TcpStream,
        source_ip: Ipv4Addr,
        peer_tag: String,
    ) -> Self {
        Self {
            handle,
            local_stream,
            source_ip,
            peer_tag: Some(peer_tag),
            smoltcp_buffer: Vec::with_capacity(SMOLTCP_BUFFER_SIZE),
            pending_to_tunnel: Vec::new(),
            header_injected: false,
            last_activity: Instant::now(),
            state: ConnectionState::Active,
            local_read_closed: false,
            tunnel_read_closed: false,
        }
    }

    /// Update last activity time
    fn touch(&mut self) {
        self.last_activity = Instant::now();
    }

    /// Check if connection is idle (exceeded timeout)
    fn is_idle(&self) -> bool {
        self.last_activity.elapsed() > IDLE_TIMEOUT
    }
}

/// Simple TCP proxy that forwards connections from smoltcp to localhost
///
/// This proxy:
/// 1. Accepts TCP connections on the configured port via smoltcp
/// 2. Connects to `localhost:target_port`
/// 3. For HTTP traffic, injects `X-Tunnel-Source-IP` header
/// 4. Performs bidirectional data forwarding
pub struct SimpleTcpProxy {
    /// Port to listen on (in smoltcp)
    listen_port: u16,
    /// Target port on localhost
    target_port: u16,
    /// Statistics
    stats: Arc<TcpProxyStats>,
}

impl SimpleTcpProxy {
    /// Create a new TCP proxy
    ///
    /// # Arguments
    ///
    /// * `target_port` - The port on localhost to forward connections to
    #[must_use]
    pub fn new(target_port: u16) -> Self {
        Self {
            listen_port: target_port, // Listen on same port by default
            target_port,
            stats: TcpProxyStats::new(),
        }
    }

    /// Create a new TCP proxy with custom listen port
    ///
    /// # Arguments
    ///
    /// * `listen_port` - The port to listen on (in the tunnel)
    /// * `target_port` - The port on localhost to forward connections to
    #[must_use]
    pub fn with_ports(listen_port: u16, target_port: u16) -> Self {
        Self {
            listen_port,
            target_port,
            stats: TcpProxyStats::new(),
        }
    }

    /// Get the statistics
    #[must_use]
    pub fn stats(&self) -> &Arc<TcpProxyStats> {
        &self.stats
    }

    /// Run the TCP proxy
    ///
    /// This method runs the main proxy loop, accepting connections on the
    /// listen port via smoltcp and forwarding them to localhost.
    ///
    /// # Arguments
    ///
    /// * `bridge` - The smoltcp bridge for TCP/IP handling
    /// * `tx_sender` - Channel to send packets to the WireGuard tunnel
    /// * `rx_receiver` - Channel to receive packets from the WireGuard tunnel
    /// * `shutdown_rx` - Broadcast receiver for shutdown signal
    ///
    /// # Errors
    ///
    /// Returns error if the proxy encounters a fatal error
    pub async fn run(
        &self,
        mut bridge: SmoltcpBridge,
        tx_sender: mpsc::Sender<Vec<u8>>,
        mut rx_receiver: mpsc::Receiver<Vec<u8>>,
        mut shutdown_rx: tokio::sync::broadcast::Receiver<()>,
    ) -> Result<(), TcpProxyError> {
        info!(
            "SimpleTcpProxy starting: listening on tunnel port {}, forwarding to localhost:{}",
            self.listen_port, self.target_port
        );

        // Create the listening socket
        let mut listen_handle = bridge
            .create_tcp_socket_default()
            .ok_or_else(|| TcpProxyError::SocketError("Failed to create listen socket".into()))?;

        // Start listening
        {
            let socket = bridge.get_tcp_socket_mut(listen_handle);
            socket
                .listen(self.listen_port)
                .map_err(|e| TcpProxyError::SocketError(format!("Failed to listen: {:?}", e)))?;
        }

        info!("TCP proxy listening on port {}", self.listen_port);

        // Active connections
        let mut connections: HashMap<SocketHandle, ProxiedConnection> = HashMap::new();

        // Main event loop
        loop {
            // Check for shutdown
            if shutdown_rx.try_recv().is_ok() {
                info!("TCP proxy shutting down");
                break;
            }

            // Process incoming packets from the tunnel
            while let Ok(packet) = rx_receiver.try_recv() {
                bridge.feed_rx_packet(packet);
            }

            // Poll smoltcp
            bridge.poll();

            // Check listening socket for new connections
            {
                let socket = bridge.get_tcp_socket(listen_handle);
                if socket.is_active() && socket.state() == TcpState::Established {
                    // A connection was accepted - get the remote endpoint
                    if let Some(remote) = socket.remote_endpoint() {
                        let source_ip = match remote.addr {
                            IpAddress::Ipv4(addr) => Ipv4Addr::from(addr.0),
                        };

                        // Check connection limit before accepting
                        if connections.len() >= MAX_CONCURRENT_CONNECTIONS {
                            warn!(
                                "Maximum connections ({}) reached, rejecting connection from {}",
                                MAX_CONCURRENT_CONNECTIONS, source_ip
                            );
                            // Abort the connection that took over the listen socket
                            let socket = bridge.get_tcp_socket_mut(listen_handle);
                            socket.abort();
                            self.stats.connections_failed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        } else {
                            debug!(
                                "New connection from {} on port {}",
                                source_ip, self.listen_port
                            );

                            // The listening socket becomes the connection socket
                            // We need to create a new listening socket
                            match self.accept_connection(&mut bridge, listen_handle, source_ip).await {
                                Ok(conn) => {
                                    self.stats.connections_accepted.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                    self.stats.active_connections.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                    connections.insert(conn.handle, conn);
                                }
                                Err(e) => {
                                    warn!("Failed to accept connection: {}", e);
                                    self.stats.connections_failed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                }
                            }
                        }

                        // Create a new listening socket to replace the one that became a connection
                        // This must happen regardless of whether accept succeeded, since the old socket
                        // is now either a connection or was aborted
                        listen_handle = bridge
                            .create_tcp_socket_default()
                            .ok_or_else(|| TcpProxyError::SocketError("Failed to create new listen socket".into()))?;

                        {
                            let socket = bridge.get_tcp_socket_mut(listen_handle);
                            socket
                                .listen(self.listen_port)
                                .map_err(|e| TcpProxyError::SocketError(format!("Failed to listen: {:?}", e)))?;
                        }
                    }
                }
            }

            // Process active connections
            let mut to_remove = Vec::new();
            for (handle, conn) in &mut connections {
                match self.process_connection(&mut bridge, conn, &tx_sender).await {
                    Ok(true) => {
                        // Connection still active
                    }
                    Ok(false) => {
                        // Connection finished
                        to_remove.push(*handle);
                        self.stats.connections_completed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    Err(e) => {
                        warn!("Connection error: {}", e);
                        to_remove.push(*handle);
                        self.stats.connections_failed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                }
            }

            // Remove finished connections
            for handle in to_remove {
                if let Some(_conn) = connections.remove(&handle) {
                    bridge.remove_socket(handle);
                    self.stats.active_connections.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                }
            }

            // Remove idle connections
            let mut idle_handles = Vec::new();
            for (handle, conn) in &connections {
                if conn.is_idle() {
                    info!("Removing idle connection from {} (idle timeout exceeded)", conn.source_ip);
                    idle_handles.push(*handle);
                }
            }
            for handle in idle_handles {
                if let Some(_conn) = connections.remove(&handle) {
                    bridge.remove_socket(handle);
                    self.stats.active_connections.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                    self.stats.connections_failed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
            }

            // Send any outgoing packets
            for packet in bridge.drain_tx_packets() {
                if tx_sender.send(packet).await.is_err() {
                    return Err(TcpProxyError::TunnelError("Failed to send packet to tunnel".into()));
                }
            }

            // Calculate sleep duration based on smoltcp poll delay
            let delay = bridge
                .poll_delay()
                .map(|d| {
                    d.clamp(
                        Duration::from_millis(MIN_POLL_INTERVAL_MS),
                        Duration::from_millis(MAX_POLL_INTERVAL_MS),
                    )
                })
                .unwrap_or(Duration::from_millis(MIN_POLL_INTERVAL_MS));

            sleep(delay).await;
        }

        // Cleanup
        for (handle, _conn) in connections {
            bridge.remove_socket(handle);
        }
        bridge.remove_socket(listen_handle);

        Ok(())
    }

    /// Accept a new connection and set up local forwarding
    async fn accept_connection(
        &self,
        _bridge: &mut SmoltcpBridge,
        handle: SocketHandle,
        source_ip: Ipv4Addr,
    ) -> Result<ProxiedConnection, TcpProxyError> {
        // Connect to the local API server
        let local_addr = format!("127.0.0.1:{}", self.target_port);

        let local_stream = timeout(CONNECTION_TIMEOUT, TcpStream::connect(&local_addr))
            .await
            .map_err(|_| TcpProxyError::Timeout)?
            .map_err(|e| TcpProxyError::LocalConnectionFailed(e.to_string()))?;

        // Set non-blocking mode
        local_stream.set_nodelay(true)?;

        debug!(
            "Connected to local API server at {} for source {}",
            local_addr, source_ip
        );

        Ok(ProxiedConnection::new(handle, local_stream, source_ip))
    }

    /// Process a single connection - forward data bidirectionally
    async fn process_connection(
        &self,
        bridge: &mut SmoltcpBridge,
        conn: &mut ProxiedConnection,
        _tx_sender: &mpsc::Sender<Vec<u8>>,
    ) -> Result<bool, TcpProxyError> {
        let socket_state = bridge.tcp_socket_state(conn.handle);

        // Check if connection is fully closed
        if matches!(socket_state, TcpState::Closed | TcpState::TimeWait) {
            return Ok(false);
        }

        // Check if tunnel side has closed its read (we can't receive more data)
        if !conn.tunnel_read_closed {
            // Check if smoltcp socket has no more data to receive and is in a closing state
            let socket = bridge.get_tcp_socket(conn.handle);
            if matches!(
                socket.state(),
                TcpState::CloseWait | TcpState::LastAck | TcpState::Closing
            ) && !bridge.tcp_can_recv(conn.handle)
            {
                conn.tunnel_read_closed = true;
                debug!("Tunnel side closed for connection from {}", conn.source_ip);
            }
        }

        // Forward data from smoltcp to local
        if bridge.tcp_can_recv(conn.handle) && !conn.tunnel_read_closed {
            let socket = bridge.get_tcp_socket_mut(conn.handle);
            let mut buf = [0u8; SMOLTCP_BUFFER_SIZE];
            match socket.recv_slice(&mut buf) {
                Ok(n) if n > 0 => {
                    conn.touch();
                    trace!("Received {} bytes from tunnel", n);

                    let mut data = &buf[..n];

                    // Check if we need to inject the header
                    if !conn.header_injected {
                        // Accumulate data for header detection
                        conn.smoltcp_buffer.extend_from_slice(data);

                        // Try to detect and inject header
                        if let Some(modified) = inject_tunnel_source_header(
                            &conn.smoltcp_buffer,
                            conn.source_ip,
                        ) {
                            conn.header_injected = true;
                            conn.smoltcp_buffer = modified;
                            data = &conn.smoltcp_buffer;
                        } else if conn.smoltcp_buffer.len() >= MAX_HEADER_DETECT_SIZE {
                            // Gave up on header detection, send as-is
                            conn.header_injected = true;
                            data = &conn.smoltcp_buffer;
                        } else {
                            // Wait for more data
                            return Ok(true);
                        }
                    }

                    // Write to local
                    match conn.local_stream.write_all(data).await {
                        Ok(()) => {
                            self.stats.bytes_tunnel_to_local.fetch_add(
                                data.len() as u64,
                                std::sync::atomic::Ordering::Relaxed,
                            );
                            // Clear buffer after successful write
                            if !conn.smoltcp_buffer.is_empty() {
                                conn.smoltcp_buffer.clear();
                            }
                        }
                        Err(e) => {
                            return Err(TcpProxyError::IoError(e));
                        }
                    }
                }
                Ok(_) => {
                    // No data available
                }
                Err(e) => {
                    return Err(TcpProxyError::SocketError(format!("{:?}", e)));
                }
            }
        }

        // First, try to send any pending data that couldn't be sent previously
        if !conn.pending_to_tunnel.is_empty() && bridge.tcp_can_send(conn.handle) {
            let socket = bridge.get_tcp_socket_mut(conn.handle);
            match socket.send_slice(&conn.pending_to_tunnel) {
                Ok(sent) => {
                    self.stats.bytes_local_to_tunnel.fetch_add(
                        sent as u64,
                        std::sync::atomic::Ordering::Relaxed,
                    );
                    if sent > 0 {
                        conn.touch();
                        // Remove sent bytes from pending buffer
                        conn.pending_to_tunnel.drain(..sent);
                        trace!("Sent {} pending bytes to tunnel, {} remaining", sent, conn.pending_to_tunnel.len());
                    }
                }
                Err(e) => {
                    return Err(TcpProxyError::SocketError(format!("{:?}", e)));
                }
            }
        }

        // Forward data from local to smoltcp (only if no pending data or pending is small enough)
        // Use try_read to avoid blocking
        // Skip reading new data if we have too much pending data (backpressure)
        if !conn.local_read_closed && conn.pending_to_tunnel.len() < LOCAL_BUFFER_SIZE {
            let mut local_buf = [0u8; LOCAL_BUFFER_SIZE];
            match conn.local_stream.try_read(&mut local_buf) {
                Ok(0) => {
                    // EOF from local - send FIN to tunnel (graceful half-close)
                    debug!("Local connection closed (EOF) for {}", conn.source_ip);
                    conn.local_read_closed = true;

                    // Only close the tunnel side if we've sent all pending data
                    if conn.pending_to_tunnel.is_empty() {
                        let socket = bridge.get_tcp_socket_mut(conn.handle);
                        socket.close(); // Graceful FIN, not abort
                        conn.state = ConnectionState::Closing;
                    }
                }
                Ok(n) => {
                    conn.touch();
                    trace!("Received {} bytes from local", n);

                    // Write to smoltcp socket
                    if bridge.tcp_can_send(conn.handle) {
                        let socket = bridge.get_tcp_socket_mut(conn.handle);
                        match socket.send_slice(&local_buf[..n]) {
                            Ok(sent) => {
                                self.stats.bytes_local_to_tunnel.fetch_add(
                                    sent as u64,
                                    std::sync::atomic::Ordering::Relaxed,
                                );
                                if sent < n {
                                    // Buffer the unsent data instead of dropping it
                                    conn.pending_to_tunnel.extend_from_slice(&local_buf[sent..n]);
                                    trace!(
                                        "Buffered {} bytes for later send ({} total pending)",
                                        n - sent,
                                        conn.pending_to_tunnel.len()
                                    );
                                }
                            }
                            Err(e) => {
                                return Err(TcpProxyError::SocketError(format!("{:?}", e)));
                            }
                        }
                    } else {
                        // Can't send now, buffer all data
                        conn.pending_to_tunnel.extend_from_slice(&local_buf[..n]);
                        trace!(
                            "Buffered all {} bytes (socket can't send), {} total pending",
                            n,
                            conn.pending_to_tunnel.len()
                        );
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // No data available - this is normal
                }
                Err(e) => {
                    return Err(TcpProxyError::IoError(e));
                }
            }
        }

        // If local is closed and all pending data sent, close the tunnel side
        if conn.local_read_closed
            && conn.pending_to_tunnel.is_empty()
            && conn.state != ConnectionState::Closing
        {
            let socket = bridge.get_tcp_socket_mut(conn.handle);
            socket.close(); // Graceful FIN
            conn.state = ConnectionState::Closing;
        }

        // Connection is done when both sides are closed and no pending data
        if conn.local_read_closed && conn.tunnel_read_closed && conn.pending_to_tunnel.is_empty() {
            return Ok(false);
        }

        Ok(true)
    }
}

impl std::fmt::Debug for SimpleTcpProxy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SimpleTcpProxy")
            .field("listen_port", &self.listen_port)
            .field("target_port", &self.target_port)
            .finish()
    }
}

/// HTTP methods that indicate the start of an HTTP request
const HTTP_METHODS: &[&[u8]] = &[
    b"GET ",
    b"POST ",
    b"PUT ",
    b"DELETE ",
    b"PATCH ",
    b"HEAD ",
    b"OPTIONS ",
    b"CONNECT ",
    b"TRACE ",
];

/// Check if data starts with an HTTP method
fn is_http_request(data: &[u8]) -> bool {
    HTTP_METHODS.iter().any(|method| data.starts_with(method))
}

/// Find the position of the first CRLF (end of request line)
fn find_request_line_end(data: &[u8]) -> Option<usize> {
    data.windows(2)
        .position(|w| w == b"\r\n")
        .map(|pos| pos + 2)
}

/// Sanitize a header value by removing CR and LF characters
///
/// This prevents HTTP header injection attacks where malicious values
/// could inject additional headers.
pub fn sanitize_header_value(value: &str) -> String {
    value
        .chars()
        .filter(|c| *c != '\r' && *c != '\n')
        .collect()
}

/// Inject the X-Tunnel-Source-IP header into an HTTP request
///
/// This function:
/// 1. Detects if the data is an HTTP request
/// 2. Finds the end of the request line
/// 3. Inserts the header after the request line
///
/// # Arguments
///
/// * `data` - The raw HTTP request data
/// * `source_ip` - The source IP to inject
///
/// # Returns
///
/// - `Some(modified_data)` if injection was successful
/// - `None` if the data is not an HTTP request or incomplete
pub fn inject_tunnel_source_header(data: &[u8], source_ip: Ipv4Addr) -> Option<Vec<u8>> {
    // Check if this looks like an HTTP request
    if !is_http_request(data) {
        // Not HTTP, return data as-is (but mark as "processed")
        return Some(data.to_vec());
    }

    // Find the end of the request line
    let request_line_end = find_request_line_end(data)?;

    // Build the injected header
    // Defense-in-depth: sanitize even though Ipv4Addr::to_string() only produces safe output
    let header = format!(
        "X-Tunnel-Source-IP: {}\r\n",
        sanitize_header_value(&source_ip.to_string())
    );

    // Build the modified request
    let mut modified = Vec::with_capacity(data.len() + header.len());
    modified.extend_from_slice(&data[..request_line_end]);
    modified.extend_from_slice(header.as_bytes());
    modified.extend_from_slice(&data[request_line_end..]);

    Some(modified)
}

/// Extract source IP from an IP packet
///
/// # Arguments
///
/// * `packet` - The raw IPv4 packet
///
/// # Returns
///
/// The source IP address if the packet is valid
pub fn extract_source_ip(packet: &[u8]) -> Option<Ipv4Addr> {
    // Parse as IPv4 packet
    match Ipv4Packet::new_checked(packet) {
        Ok(ipv4) => {
            let src = ipv4.src_addr();
            Some(Ipv4Addr::new(src.0[0], src.0[1], src.0[2], src.0[3]))
        }
        Err(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_http_request() {
        assert!(is_http_request(b"GET / HTTP/1.1\r\n"));
        assert!(is_http_request(b"POST /api/test HTTP/1.1\r\n"));
        assert!(is_http_request(b"PUT /resource HTTP/1.0\r\n"));
        assert!(is_http_request(b"DELETE /item/1 HTTP/1.1\r\n"));
        assert!(is_http_request(b"PATCH /update HTTP/1.1\r\n"));
        assert!(is_http_request(b"HEAD / HTTP/1.1\r\n"));
        assert!(is_http_request(b"OPTIONS * HTTP/1.1\r\n"));
        assert!(is_http_request(b"CONNECT example.com:443 HTTP/1.1\r\n"));
        assert!(is_http_request(b"TRACE / HTTP/1.1\r\n"));

        // Not HTTP
        assert!(!is_http_request(b"\x16\x03\x01")); // TLS
        assert!(!is_http_request(b"SSH-2.0"));
        assert!(!is_http_request(b"binary\x00data"));
        assert!(!is_http_request(b""));
        assert!(!is_http_request(b"G")); // Too short
    }

    #[test]
    fn test_find_request_line_end() {
        assert_eq!(
            find_request_line_end(b"GET / HTTP/1.1\r\nHost: example.com\r\n"),
            Some(16)
        );
        assert_eq!(
            find_request_line_end(b"POST /api HTTP/1.1\r\n"),
            Some(20)
        );

        // No CRLF yet
        assert_eq!(find_request_line_end(b"GET / HTTP/1.1"), None);

        // Empty
        assert_eq!(find_request_line_end(b""), None);
    }

    #[test]
    fn test_sanitize_header_value() {
        // Normal values pass through
        assert_eq!(sanitize_header_value("10.200.200.1"), "10.200.200.1");
        assert_eq!(sanitize_header_value("normal value"), "normal value");

        // CR/LF are removed
        assert_eq!(
            sanitize_header_value("value\r\nX-Injected: malicious"),
            "valueX-Injected: malicious"
        );
        assert_eq!(sanitize_header_value("value\rinjected"), "valueinjected");
        assert_eq!(sanitize_header_value("value\ninjected"), "valueinjected");

        // Empty string stays empty
        assert_eq!(sanitize_header_value(""), "");
    }

    #[test]
    fn test_inject_tunnel_source_header_get() {
        let data = b"GET /api/health HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let source_ip = Ipv4Addr::new(10, 200, 200, 2);

        let result = inject_tunnel_source_header(data, source_ip);
        assert!(result.is_some());

        let modified = result.unwrap();
        let modified_str = String::from_utf8_lossy(&modified);

        // Should contain the injected header
        assert!(modified_str.contains("X-Tunnel-Source-IP: 10.200.200.2\r\n"));

        // Header should be after request line
        assert!(modified_str.starts_with("GET /api/health HTTP/1.1\r\nX-Tunnel-Source-IP: 10.200.200.2\r\n"));

        // Original headers should still be there
        assert!(modified_str.contains("Host: localhost\r\n"));
    }

    #[test]
    fn test_inject_tunnel_source_header_post() {
        let data = b"POST /api/chains HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 14\r\n\r\n{\"tag\":\"test\"}";
        let source_ip = Ipv4Addr::new(10, 200, 200, 5);

        let result = inject_tunnel_source_header(data, source_ip);
        assert!(result.is_some());

        let modified = result.unwrap();
        let modified_str = String::from_utf8_lossy(&modified);

        // Should contain the injected header
        assert!(modified_str.contains("X-Tunnel-Source-IP: 10.200.200.5\r\n"));

        // Body should be preserved
        assert!(modified_str.ends_with("{\"tag\":\"test\"}"));
    }

    #[test]
    fn test_inject_tunnel_source_header_non_http() {
        // TLS handshake
        let data = b"\x16\x03\x01\x00\xf1\x01\x00\x00\xed";
        let source_ip = Ipv4Addr::new(10, 200, 200, 2);

        let result = inject_tunnel_source_header(data, source_ip);
        assert!(result.is_some());

        // Should return data unchanged
        let modified = result.unwrap();
        assert_eq!(modified, data);
    }

    #[test]
    fn test_inject_tunnel_source_header_incomplete() {
        // HTTP request without complete request line
        let data = b"GET /api/health";
        let source_ip = Ipv4Addr::new(10, 200, 200, 2);

        let result = inject_tunnel_source_header(data, source_ip);
        // Should return None because we haven't seen the end of request line
        assert!(result.is_none());
    }

    #[test]
    fn test_inject_header_with_malicious_ip() {
        // Attempt header injection via source IP (shouldn't happen in practice,
        // but we sanitize anyway for defense in depth)
        // Note: This test is about sanitize_header_value, not about the data payload.
        #[allow(unused)]
        let _data = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";

        // Simulate what would happen if somehow the IP contained special chars
        // In reality, Ipv4Addr::to_string() is safe, but we test sanitization anyway
        let safe_ip = sanitize_header_value("10.200.200.2\r\nX-Injected: bad");
        assert_eq!(safe_ip, "10.200.200.2X-Injected: bad");
    }

    #[test]
    fn test_tcp_proxy_stats() {
        let stats = TcpProxyStats::new();

        assert_eq!(stats.connections_accepted.load(std::sync::atomic::Ordering::Relaxed), 0);
        assert_eq!(stats.connections_completed.load(std::sync::atomic::Ordering::Relaxed), 0);

        stats.connections_accepted.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(stats.connections_accepted.load(std::sync::atomic::Ordering::Relaxed), 1);
    }

    #[test]
    fn test_simple_tcp_proxy_new() {
        let proxy = SimpleTcpProxy::new(36000);
        assert_eq!(proxy.listen_port, 36000);
        assert_eq!(proxy.target_port, 36000);
    }

    #[test]
    fn test_simple_tcp_proxy_with_ports() {
        let proxy = SimpleTcpProxy::with_ports(8080, 36000);
        assert_eq!(proxy.listen_port, 8080);
        assert_eq!(proxy.target_port, 36000);
    }

    #[test]
    fn test_connection_state() {
        assert_eq!(ConnectionState::Active, ConnectionState::Active);
        assert_ne!(ConnectionState::Active, ConnectionState::Closing);
    }

    #[test]
    fn test_extract_source_ip_valid() {
        // Minimal valid IPv4 packet (20 bytes header, no options)
        // Version=4, IHL=5, Total Length=20, TTL=64, Protocol=TCP(6)
        // Source: 10.200.200.2, Dest: 10.200.200.1
        let packet = [
            0x45, 0x00, 0x00, 0x14, // Version, IHL, TOS, Total Length
            0x00, 0x00, 0x00, 0x00, // ID, Flags, Fragment Offset
            0x40, 0x06, 0x00, 0x00, // TTL, Protocol (TCP), Checksum
            0x0a, 0xc8, 0xc8, 0x02, // Source IP: 10.200.200.2
            0x0a, 0xc8, 0xc8, 0x01, // Dest IP: 10.200.200.1
        ];

        let result = extract_source_ip(&packet);
        assert_eq!(result, Some(Ipv4Addr::new(10, 200, 200, 2)));
    }

    #[test]
    fn test_extract_source_ip_invalid() {
        // Too short
        let result = extract_source_ip(&[0x45, 0x00]);
        assert!(result.is_none());

        // Empty
        let result = extract_source_ip(&[]);
        assert!(result.is_none());
    }

    #[test]
    fn test_inject_all_http_methods() {
        let methods = [
            "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "CONNECT", "TRACE",
        ];
        let source_ip = Ipv4Addr::new(192, 168, 1, 100);

        for method in methods {
            let request = format!("{} /test HTTP/1.1\r\nHost: localhost\r\n\r\n", method);
            let result = inject_tunnel_source_header(request.as_bytes(), source_ip);
            assert!(result.is_some(), "Failed for method: {}", method);

            let result_data = result.unwrap();
            let modified = String::from_utf8_lossy(&result_data);
            assert!(
                modified.contains("X-Tunnel-Source-IP: 192.168.1.100\r\n"),
                "Header not found for method: {}",
                method
            );
        }
    }
}
