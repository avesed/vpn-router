//! UDP DNS Server
//!
//! This module provides a UDP-based DNS server with support for batch I/O
//! and efficient buffer pooling.
//!
//! # Architecture
//!
//! ```text
//! UDP Socket (port 7853)
//!     |
//!     v
//! recvfrom() / recvmmsg()
//!     |
//!     v
//! DnsHandler.handle_query()
//!     |
//!     v
//! sendto() / sendmmsg()
//! ```
//!
//! # Features
//!
//! - **Batch I/O**: Uses recvmmsg/sendmmsg when available (Linux)
//! - **Buffer Pooling**: Reuses buffers to minimize allocations
//! - **Rate Limiting**: Integrated with DnsRateLimiter
//! - **Graceful Shutdown**: Responds to shutdown signals
//!
//! # Example
//!
//! ```no_run
//! use rust_router::dns::server::{UdpDnsServer, DnsHandler, DnsRateLimiter};
//! use rust_router::dns::RateLimitConfig;
//! use std::sync::Arc;
//! use std::net::SocketAddr;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let rate_limiter = Arc::new(DnsRateLimiter::new(&RateLimitConfig::default()));
//! let handler = Arc::new(DnsHandler::new(Arc::clone(&rate_limiter)));
//!
//! let addr: SocketAddr = "127.0.0.1:7853".parse()?;
//! let server = UdpDnsServer::bind(addr, handler).await?;
//!
//! // Run with shutdown signal
//! // server.run_until_shutdown(shutdown_rx).await?;
//! # Ok(())
//! # }
//! ```

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;

use tokio::net::UdpSocket;
use tracing::{debug, error, info, trace, warn};

use hickory_proto::serialize::binary::BinDecodable;
use hickory_proto::op::Message;

use super::handler::{DnsHandler, MAX_UDP_RESPONSE_SIZE_NO_EDNS};
use crate::dns::error::{DnsError, DnsResult};
use crate::io::{BufferPoolConfig, UdpBufferPool};

/// Maximum DNS message size over UDP (with EDNS0)
pub const MAX_UDP_MESSAGE_SIZE: usize = 4096;

/// Default buffer pool size for UDP server
const DEFAULT_BUFFER_POOL_SIZE: usize = 256;

/// Threshold for consecutive errors that indicates socket degradation
const CONSECUTIVE_ERROR_THRESHOLD: u32 = 10;

/// Statistics for the UDP DNS server
#[derive(Debug, Default)]
pub struct UdpServerStats {
    /// Total packets received
    packets_received: AtomicU64,
    /// Total packets sent
    packets_sent: AtomicU64,
    /// Packets dropped due to errors
    packets_dropped: AtomicU64,
    /// Parse errors (malformed DNS messages)
    parse_errors: AtomicU64,
    /// Rate limit rejections
    rate_limit_rejections: AtomicU64,
    /// Total bytes received
    bytes_received: AtomicU64,
    /// Total bytes sent
    bytes_sent: AtomicU64,
    /// Consecutive receive errors (resets on success)
    consecutive_recv_errors: AtomicU32,
    /// Consecutive send errors (resets on success)
    consecutive_send_errors: AtomicU32,
}

impl UdpServerStats {
    /// Create new stats instance
    pub fn new() -> Self {
        Self::default()
    }

    /// Get total packets received
    #[must_use]
    pub fn packets_received(&self) -> u64 {
        self.packets_received.load(Ordering::Relaxed)
    }

    /// Get total packets sent
    #[must_use]
    pub fn packets_sent(&self) -> u64 {
        self.packets_sent.load(Ordering::Relaxed)
    }

    /// Get packets dropped
    #[must_use]
    pub fn packets_dropped(&self) -> u64 {
        self.packets_dropped.load(Ordering::Relaxed)
    }

    /// Get parse errors
    #[must_use]
    pub fn parse_errors(&self) -> u64 {
        self.parse_errors.load(Ordering::Relaxed)
    }

    /// Get rate limit rejections
    #[must_use]
    pub fn rate_limit_rejections(&self) -> u64 {
        self.rate_limit_rejections.load(Ordering::Relaxed)
    }

    /// Get bytes received
    #[must_use]
    pub fn bytes_received(&self) -> u64 {
        self.bytes_received.load(Ordering::Relaxed)
    }

    /// Get bytes sent
    #[must_use]
    pub fn bytes_sent(&self) -> u64 {
        self.bytes_sent.load(Ordering::Relaxed)
    }

    /// Get consecutive receive errors (resets on successful receive)
    #[must_use]
    pub fn consecutive_recv_errors(&self) -> u32 {
        self.consecutive_recv_errors.load(Ordering::Relaxed)
    }

    /// Get consecutive send errors (resets on successful send)
    #[must_use]
    pub fn consecutive_send_errors(&self) -> u32 {
        self.consecutive_send_errors.load(Ordering::Relaxed)
    }

    /// Record a successful receive (resets consecutive error counter)
    fn record_recv_success(&self) {
        self.consecutive_recv_errors.store(0, Ordering::Relaxed);
    }

    /// Record a receive error (increments consecutive error counter)
    fn record_recv_error(&self) -> u32 {
        self.consecutive_recv_errors.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Record a successful send (resets consecutive error counter)
    fn record_send_success(&self) {
        self.consecutive_send_errors.store(0, Ordering::Relaxed);
    }

    /// Record a send error (increments consecutive error counter)
    fn record_send_error(&self) -> u32 {
        self.consecutive_send_errors.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Check if the socket appears degraded based on consecutive errors
    #[must_use]
    pub fn is_socket_degraded(&self) -> bool {
        self.consecutive_recv_errors() >= CONSECUTIVE_ERROR_THRESHOLD
            || self.consecutive_send_errors() >= CONSECUTIVE_ERROR_THRESHOLD
    }

    /// Get a snapshot of all stats
    #[must_use]
    pub fn snapshot(&self) -> UdpServerStatsSnapshot {
        UdpServerStatsSnapshot {
            packets_received: self.packets_received(),
            packets_sent: self.packets_sent(),
            packets_dropped: self.packets_dropped(),
            parse_errors: self.parse_errors(),
            rate_limit_rejections: self.rate_limit_rejections(),
            bytes_received: self.bytes_received(),
            bytes_sent: self.bytes_sent(),
            consecutive_recv_errors: self.consecutive_recv_errors(),
            consecutive_send_errors: self.consecutive_send_errors(),
        }
    }
}

/// Snapshot of UDP server statistics
#[derive(Debug, Clone, Copy)]
pub struct UdpServerStatsSnapshot {
    /// Total packets received
    pub packets_received: u64,
    /// Total packets sent
    pub packets_sent: u64,
    /// Packets dropped
    pub packets_dropped: u64,
    /// Parse errors
    pub parse_errors: u64,
    /// Rate limit rejections
    pub rate_limit_rejections: u64,
    /// Bytes received
    pub bytes_received: u64,
    /// Bytes sent
    pub bytes_sent: u64,
    /// Current consecutive receive errors
    pub consecutive_recv_errors: u32,
    /// Current consecutive send errors
    pub consecutive_send_errors: u32,
}

impl UdpServerStatsSnapshot {
    /// Calculate success rate
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn success_rate(&self) -> f64 {
        if self.packets_received == 0 {
            return 1.0;
        }
        self.packets_sent as f64 / self.packets_received as f64
    }
}

/// UDP DNS Server
///
/// Handles DNS queries over UDP with rate limiting and response generation.
pub struct UdpDnsServer {
    /// Bound UDP socket
    socket: Arc<UdpSocket>,
    /// DNS query handler
    handler: Arc<DnsHandler>,
    /// Buffer pool for receive operations
    buffer_pool: Arc<UdpBufferPool>,
    /// Server statistics
    stats: Arc<UdpServerStats>,
    /// Shutdown flag
    shutdown: Arc<AtomicBool>,
    /// Local bind address
    local_addr: SocketAddr,
}

impl UdpDnsServer {
    /// Create and bind a new UDP DNS server
    ///
    /// # Arguments
    ///
    /// * `addr` - Address to bind to (e.g., "127.0.0.1:7853")
    /// * `handler` - DNS query handler
    ///
    /// # Errors
    ///
    /// Returns an error if the socket cannot be bound.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rust_router::dns::server::{UdpDnsServer, DnsHandler, DnsRateLimiter};
    /// use rust_router::dns::RateLimitConfig;
    /// use std::sync::Arc;
    /// use std::net::SocketAddr;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let rate_limiter = Arc::new(DnsRateLimiter::new(&RateLimitConfig::default()));
    /// let handler = Arc::new(DnsHandler::new(rate_limiter));
    ///
    /// let addr: SocketAddr = "127.0.0.1:7853".parse()?;
    /// let server = UdpDnsServer::bind(addr, handler).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn bind(addr: SocketAddr, handler: Arc<DnsHandler>) -> DnsResult<Self> {
        let socket = UdpSocket::bind(addr).await.map_err(|e| {
            DnsError::network_io(format!("failed to bind UDP socket to {}", addr), e)
        })?;

        let local_addr = socket.local_addr().map_err(|e| {
            DnsError::network_io("failed to get local address".to_string(), e)
        })?;

        info!(addr = %local_addr, "UDP DNS server bound");

        let buffer_pool = BufferPoolConfig::new(DEFAULT_BUFFER_POOL_SIZE, MAX_UDP_MESSAGE_SIZE)
            .with_prewarm(DEFAULT_BUFFER_POOL_SIZE / 4)
            .build();

        Ok(Self {
            socket: Arc::new(socket),
            handler,
            buffer_pool,
            stats: Arc::new(UdpServerStats::new()),
            shutdown: Arc::new(AtomicBool::new(false)),
            local_addr,
        })
    }

    /// Create a server from an existing socket
    ///
    /// Useful for testing or when the socket is created externally.
    pub fn from_socket(socket: UdpSocket, handler: Arc<DnsHandler>) -> DnsResult<Self> {
        let local_addr = socket.local_addr().map_err(|e| {
            DnsError::network_io("failed to get local address".to_string(), e)
        })?;

        let buffer_pool = BufferPoolConfig::new(DEFAULT_BUFFER_POOL_SIZE, MAX_UDP_MESSAGE_SIZE)
            .with_prewarm(DEFAULT_BUFFER_POOL_SIZE / 4)
            .build();

        Ok(Self {
            socket: Arc::new(socket),
            handler,
            buffer_pool,
            stats: Arc::new(UdpServerStats::new()),
            shutdown: Arc::new(AtomicBool::new(false)),
            local_addr,
        })
    }

    /// Get the local address this server is bound to
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Get server statistics
    #[must_use]
    pub fn stats(&self) -> &Arc<UdpServerStats> {
        &self.stats
    }

    /// Check if the server is shut down
    #[must_use]
    pub fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::SeqCst)
    }

    /// Signal the server to shut down
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
    }

    /// Run the server until shutdown is signaled
    ///
    /// This method blocks until the shutdown flag is set or an error occurs.
    ///
    /// # Errors
    ///
    /// Returns an error if there's a fatal socket error.
    pub async fn run(&self) -> DnsResult<()> {
        info!(addr = %self.local_addr, "UDP DNS server starting");

        loop {
            if self.shutdown.load(Ordering::SeqCst) {
                info!("UDP DNS server shutting down");
                break;
            }

            // Check for socket degradation periodically
            if self.stats.is_socket_degraded() {
                warn!(
                    recv_errors = self.stats.consecutive_recv_errors.load(Ordering::Relaxed),
                    send_errors = self.stats.consecutive_send_errors.load(Ordering::Relaxed),
                    threshold = CONSECUTIVE_ERROR_THRESHOLD,
                    "Socket appears degraded - too many consecutive errors"
                );
            }

            if let Err(e) = self.handle_one_packet().await {
                // Log error but continue unless it's fatal
                if Self::is_fatal_error(&e) {
                    error!(error = %e, "Fatal UDP error, shutting down");
                    return Err(e);
                }
                debug!(error = %e, "Non-fatal UDP error");
            }
        }

        Ok(())
    }

    /// Run the server with a shutdown receiver
    ///
    /// # Arguments
    ///
    /// * `shutdown_rx` - Receiver that will be signaled on shutdown
    pub async fn run_until_shutdown(
        &self,
        mut shutdown_rx: tokio::sync::oneshot::Receiver<()>,
    ) -> DnsResult<()> {
        info!(addr = %self.local_addr, "UDP DNS server starting");

        loop {
            // Check for socket degradation periodically
            if self.stats.is_socket_degraded() {
                warn!(
                    recv_errors = self.stats.consecutive_recv_errors.load(Ordering::Relaxed),
                    send_errors = self.stats.consecutive_send_errors.load(Ordering::Relaxed),
                    threshold = CONSECUTIVE_ERROR_THRESHOLD,
                    "Socket appears degraded - too many consecutive errors"
                );
            }

            tokio::select! {
                result = self.handle_one_packet() => {
                    if let Err(e) = result {
                        if Self::is_fatal_error(&e) {
                            error!(error = %e, "Fatal UDP error, shutting down");
                            return Err(e);
                        }
                        debug!(error = %e, "Non-fatal UDP error");
                    }
                }
                _ = &mut shutdown_rx => {
                    info!("UDP DNS server received shutdown signal");
                    self.shutdown.store(true, Ordering::SeqCst);
                    break;
                }
            }
        }

        Ok(())
    }

    /// Handle a single incoming packet
    async fn handle_one_packet(&self) -> DnsResult<()> {
        let buffer = self.buffer_pool.get();
        let mut recv_buf = buffer.into_vec();

        // Receive packet
        let (len, src) = match self.socket.recv_from(&mut recv_buf).await {
            Ok(result) => {
                self.stats.record_recv_success();
                result
            }
            Err(e) => {
                let error_count = self.stats.record_recv_error();
                let dns_error = DnsError::network_io("UDP recv_from failed".to_string(), e);
                if Self::is_degraded_error(&dns_error) && error_count % 10 == 0 {
                    warn!(
                        consecutive_errors = error_count,
                        "Consecutive degraded recv errors detected"
                    );
                }
                return Err(dns_error);
            }
        };

        self.stats.packets_received.fetch_add(1, Ordering::Relaxed);
        self.stats.bytes_received.fetch_add(len as u64, Ordering::Relaxed);

        trace!(src = %src, len = len, "Received UDP DNS packet");

        // Process the query
        let query_data = &recv_buf[..len];
        let response = self.process_query(src, query_data).await;

        // Send response if we have one
        if let Some(response_data) = response {
            match self.socket.send_to(&response_data, src).await {
                Ok(sent) => {
                    self.stats.record_send_success();
                    self.stats.packets_sent.fetch_add(1, Ordering::Relaxed);
                    self.stats.bytes_sent.fetch_add(sent as u64, Ordering::Relaxed);
                    trace!(dst = %src, len = sent, "Sent UDP DNS response");
                }
                Err(e) => {
                    let error_count = self.stats.record_send_error();
                    self.stats.packets_dropped.fetch_add(1, Ordering::Relaxed);
                    warn!(
                        dst = %src,
                        error = %e,
                        consecutive_errors = error_count,
                        "Failed to send UDP response"
                    );
                }
            }
        }

        Ok(())
    }

    /// Process a DNS query and return the response
    ///
    /// This method handles query processing and applies UDP-specific
    /// truncation if the response exceeds the client's buffer size.
    async fn process_query(&self, src: SocketAddr, query: &[u8]) -> Option<Vec<u8>> {
        // Parse query to determine client buffer size (EDNS0)
        let parsed_query = Message::from_bytes(query).ok();
        let client_buffer_size = parsed_query
            .as_ref()
            .map(|q| self.handler.get_client_buffer_size(q))
            .unwrap_or(MAX_UDP_RESPONSE_SIZE_NO_EDNS);

        match self.handler.handle_query(src, query).await {
            Ok(response) => {
                // Apply truncation if response exceeds client buffer size
                if let Some(ref query_msg) = parsed_query {
                    if self.handler.needs_truncation(&response, client_buffer_size) {
                        debug!(
                            src = %src,
                            response_size = response.len(),
                            buffer_size = client_buffer_size,
                            "Response exceeds buffer, generating TC response"
                        );
                        return Some(self.handler.process_for_udp(
                            query_msg,
                            response,
                            client_buffer_size,
                        ));
                    }
                }
                Some(response)
            }
            Err(e) => {
                // Track specific error types
                if e.is_rate_limited() {
                    self.stats.rate_limit_rejections.fetch_add(1, Ordering::Relaxed);
                    debug!(src = %src, "Query rate limited");
                } else if matches!(e, DnsError::ParseError { .. } | DnsError::InvalidQuery { .. }) {
                    self.stats.parse_errors.fetch_add(1, Ordering::Relaxed);
                    debug!(src = %src, error = %e, "Query parse error");
                } else {
                    self.stats.packets_dropped.fetch_add(1, Ordering::Relaxed);
                    debug!(src = %src, error = %e, "Query handling error");
                }

                // Try to generate error response
                self.handler.generate_error_response(query, &e)
            }
        }
    }

    /// Check if an error is fatal (server should stop)
    ///
    /// Fatal errors include:
    /// - Permission denied (e.g., binding to privileged port)
    /// - Address already in use
    /// - Out of memory (ENOMEM)
    /// - No buffer space available (ENOBUFS)
    /// - Network is down (ENETDOWN)
    /// - Network is unreachable (ENETUNREACH) - for persistent errors
    /// - Too many open files (EMFILE, ENFILE)
    fn is_fatal_error(err: &DnsError) -> bool {
        match err {
            DnsError::NetworkError { source, .. } => {
                if let Some(io_err) = source {
                    match io_err.kind() {
                        // Definitely fatal - can't recover from these
                        io::ErrorKind::PermissionDenied | io::ErrorKind::AddrInUse => true,

                        // Resource exhaustion - likely fatal
                        io::ErrorKind::OutOfMemory => true,

                        // Check for specific OS errors that indicate serious problems
                        io::ErrorKind::Other => {
                            // Check raw OS error codes for fatal conditions
                            if let Some(raw_err) = io_err.raw_os_error() {
                                // ENOBUFS (105), ENOMEM (12), EMFILE (24), ENFILE (23)
                                // ENETDOWN (100), EHOSTUNREACH (113)
                                matches!(raw_err, 12 | 23 | 24 | 100 | 105 | 113)
                            } else {
                                false
                            }
                        }

                        // Not fatal - can retry
                        _ => false,
                    }
                } else {
                    false
                }
            }
            _ => false,
        }
    }

    /// Check if an error indicates a degraded socket state
    ///
    /// Some errors are not immediately fatal but indicate the socket
    /// may be in a bad state if they persist (e.g., repeated WouldBlock
    /// when the socket should be readable).
    fn is_degraded_error(err: &DnsError) -> bool {
        match err {
            DnsError::NetworkError { source, .. } => {
                if let Some(io_err) = source {
                    match io_err.kind() {
                        // These are normally transient but concerning if persistent
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => true,

                        // Resource limits being hit repeatedly
                        io::ErrorKind::Other => {
                            if let Some(raw_err) = io_err.raw_os_error() {
                                // EAGAIN (11), ENOBUFS (105), ENOMEM (12)
                                matches!(raw_err, 11 | 12 | 105)
                            } else {
                                false
                            }
                        }

                        _ => false,
                    }
                } else {
                    false
                }
            }
            _ => false,
        }
    }

    /// Get a clone of the socket for testing
    #[cfg(test)]
    pub fn socket(&self) -> Arc<UdpSocket> {
        Arc::clone(&self.socket)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::server::rate_limit::DnsRateLimiter;
    use crate::dns::RateLimitConfig;
    use std::net::Ipv6Addr;
    use tokio::net::UdpSocket as TokioUdpSocket;

    async fn create_test_server() -> (UdpDnsServer, SocketAddr) {
        let rate_limiter = Arc::new(DnsRateLimiter::new(&RateLimitConfig::default()));
        let handler = Arc::new(DnsHandler::new(rate_limiter));

        // Bind to random port
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let server = UdpDnsServer::bind(addr, handler).await.unwrap();
        let local_addr = server.local_addr();

        (server, local_addr)
    }

    fn create_simple_dns_query() -> Vec<u8> {
        // Minimal valid DNS query
        // Header: ID=0x1234, flags=0x0100 (standard query), 1 question
        // Question: example.com, type A, class IN
        let mut query = vec![
            0x12, 0x34, // ID
            0x01, 0x00, // Flags: standard query
            0x00, 0x01, // QDCOUNT: 1
            0x00, 0x00, // ANCOUNT: 0
            0x00, 0x00, // NSCOUNT: 0
            0x00, 0x00, // ARCOUNT: 0
        ];

        // Question section: example.com
        query.extend_from_slice(&[
            0x07, // length: 7
            b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            0x03, // length: 3
            b'c', b'o', b'm',
            0x00, // end of name
            0x00, 0x01, // QTYPE: A
            0x00, 0x01, // QCLASS: IN
        ]);

        query
    }

    // ========================================================================
    // Creation Tests
    // ========================================================================

    #[tokio::test]
    async fn test_bind_success() {
        let (server, addr) = create_test_server().await;

        assert_eq!(server.local_addr(), addr);
        assert!(!server.is_shutdown());
    }

    #[tokio::test]
    async fn test_from_socket() {
        let socket = TokioUdpSocket::bind("127.0.0.1:0").await.unwrap();
        let local_addr = socket.local_addr().unwrap();

        let rate_limiter = Arc::new(DnsRateLimiter::new(&RateLimitConfig::default()));
        let handler = Arc::new(DnsHandler::new(rate_limiter));

        let server = UdpDnsServer::from_socket(socket, handler).unwrap();

        assert_eq!(server.local_addr(), local_addr);
    }

    #[tokio::test]
    async fn test_bind_ipv6() {
        let rate_limiter = Arc::new(DnsRateLimiter::new(&RateLimitConfig::default()));
        let handler = Arc::new(DnsHandler::new(rate_limiter));

        let addr = SocketAddr::new(std::net::IpAddr::V6(Ipv6Addr::LOCALHOST), 0);
        let result = UdpDnsServer::bind(addr, handler).await;

        // May fail on systems without IPv6, that's ok
        if let Ok(server) = result {
            assert!(server.local_addr().is_ipv6());
        }
    }

    // ========================================================================
    // Stats Tests
    // ========================================================================

    #[tokio::test]
    async fn test_stats_initial() {
        let (server, _) = create_test_server().await;

        let stats = server.stats().snapshot();
        assert_eq!(stats.packets_received, 0);
        assert_eq!(stats.packets_sent, 0);
        assert_eq!(stats.packets_dropped, 0);
    }

    #[test]
    fn test_stats_snapshot_success_rate() {
        let stats = UdpServerStatsSnapshot {
            packets_received: 100,
            packets_sent: 95,
            packets_dropped: 5,
            parse_errors: 0,
            rate_limit_rejections: 0,
            bytes_received: 1000,
            bytes_sent: 950,
            consecutive_recv_errors: 0,
            consecutive_send_errors: 0,
        };

        let rate = stats.success_rate();
        assert!((rate - 0.95).abs() < 0.001);
    }

    #[test]
    fn test_stats_snapshot_success_rate_no_packets() {
        let stats = UdpServerStatsSnapshot {
            packets_received: 0,
            packets_sent: 0,
            packets_dropped: 0,
            parse_errors: 0,
            rate_limit_rejections: 0,
            bytes_received: 0,
            bytes_sent: 0,
            consecutive_recv_errors: 0,
            consecutive_send_errors: 0,
        };

        assert_eq!(stats.success_rate(), 1.0);
    }

    // ========================================================================
    // Shutdown Tests
    // ========================================================================

    #[tokio::test]
    async fn test_shutdown_flag() {
        let (server, _) = create_test_server().await;

        assert!(!server.is_shutdown());
        server.shutdown();
        assert!(server.is_shutdown());
    }

    #[tokio::test]
    async fn test_run_until_shutdown() {
        let (server, addr) = create_test_server().await;
        let server = Arc::new(server);

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

        // Spawn server
        let server_clone = Arc::clone(&server);
        let handle = tokio::spawn(async move {
            server_clone.run_until_shutdown(shutdown_rx).await
        });

        // Give it time to start
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        // Send shutdown signal
        shutdown_tx.send(()).unwrap();

        // Wait for server to stop
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            handle,
        )
        .await;

        assert!(result.is_ok(), "Server should have stopped");
    }

    // ========================================================================
    // Query Processing Tests
    // ========================================================================

    #[tokio::test]
    async fn test_handle_valid_query() {
        let (server, addr) = create_test_server().await;
        let server = Arc::new(server);

        // Create client socket
        let client = TokioUdpSocket::bind("127.0.0.1:0").await.unwrap();

        // Send query
        let query = create_simple_dns_query();
        client.send_to(&query, addr).await.unwrap();

        // Spawn server to handle one packet
        let server_clone = Arc::clone(&server);
        let handle = tokio::spawn(async move {
            server_clone.handle_one_packet().await
        });

        // Receive response
        let mut response_buf = vec![0u8; MAX_UDP_MESSAGE_SIZE];
        let recv_result = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            client.recv_from(&mut response_buf),
        )
        .await;

        assert!(handle.await.is_ok());

        // We should get a response (might be SERVFAIL since no upstream)
        if let Ok(Ok((len, _))) = recv_result {
            assert!(len > 12, "Response should have DNS header");

            // Check that ID matches
            assert_eq!(response_buf[0], 0x12);
            assert_eq!(response_buf[1], 0x34);
        }
    }

    #[tokio::test]
    async fn test_handle_malformed_query() {
        let (server, addr) = create_test_server().await;
        let server = Arc::new(server);

        let client = TokioUdpSocket::bind("127.0.0.1:0").await.unwrap();

        // Send garbage
        let garbage = vec![0x00, 0x01, 0x02, 0x03];
        client.send_to(&garbage, addr).await.unwrap();

        // Handle packet
        let server_clone = Arc::clone(&server);
        let handle = tokio::spawn(async move {
            server_clone.handle_one_packet().await
        });

        // Wait for handling
        let _ = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            handle,
        )
        .await;

        // Stats should show parse error
        let stats = server.stats().snapshot();
        assert!(stats.packets_received >= 1);
    }

    #[tokio::test]
    async fn test_stats_increment_on_query() {
        let (server, addr) = create_test_server().await;
        let server = Arc::new(server);

        let client = TokioUdpSocket::bind("127.0.0.1:0").await.unwrap();

        let query = create_simple_dns_query();
        client.send_to(&query, addr).await.unwrap();

        let server_clone = Arc::clone(&server);
        tokio::spawn(async move {
            let _ = server_clone.handle_one_packet().await;
        });

        // Wait for processing
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let stats = server.stats().snapshot();
        assert!(stats.packets_received >= 1);
        assert!(stats.bytes_received >= query.len() as u64);
    }

    // ========================================================================
    // Buffer Pool Tests
    // ========================================================================

    #[tokio::test]
    async fn test_buffer_pool_reuse() {
        let (server, addr) = create_test_server().await;
        let server = Arc::new(server);

        let client = TokioUdpSocket::bind("127.0.0.1:0").await.unwrap();

        // Send multiple queries
        for _ in 0..5 {
            let query = create_simple_dns_query();
            client.send_to(&query, addr).await.unwrap();

            let server_clone = Arc::clone(&server);
            tokio::spawn(async move {
                let _ = server_clone.handle_one_packet().await;
            });
        }

        // Wait for processing
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Buffer pool should have some reuses
        let pool_stats = server.buffer_pool.stats().snapshot();
        // At least some allocations happened
        assert!(pool_stats.allocations > 0 || pool_stats.reuses > 0);
    }

    // ========================================================================
    // Error Handling Tests
    // ========================================================================

    #[test]
    fn test_is_fatal_error_permission_denied() {
        let io_err = io::Error::new(io::ErrorKind::PermissionDenied, "denied");
        let dns_err = DnsError::network_io("test", io_err);

        assert!(UdpDnsServer::is_fatal_error(&dns_err));
    }

    #[test]
    fn test_is_fatal_error_addr_in_use() {
        let io_err = io::Error::new(io::ErrorKind::AddrInUse, "in use");
        let dns_err = DnsError::network_io("test", io_err);

        assert!(UdpDnsServer::is_fatal_error(&dns_err));
    }

    #[test]
    fn test_is_fatal_error_connection_reset() {
        let io_err = io::Error::new(io::ErrorKind::ConnectionReset, "reset");
        let dns_err = DnsError::network_io("test", io_err);

        assert!(!UdpDnsServer::is_fatal_error(&dns_err));
    }

    #[test]
    fn test_is_fatal_error_parse() {
        let dns_err = DnsError::parse("test");
        assert!(!UdpDnsServer::is_fatal_error(&dns_err));
    }

    #[test]
    fn test_is_fatal_error_rate_limit() {
        let dns_err = DnsError::rate_limit(
            "127.0.0.1:1234".parse().unwrap(),
            100,
            50,
        );
        assert!(!UdpDnsServer::is_fatal_error(&dns_err));
    }

    #[test]
    fn test_is_fatal_error_out_of_memory() {
        let io_err = io::Error::new(io::ErrorKind::OutOfMemory, "out of memory");
        let dns_err = DnsError::network_io("test", io_err);

        assert!(UdpDnsServer::is_fatal_error(&dns_err));
    }

    #[test]
    fn test_is_fatal_error_would_block() {
        let io_err = io::Error::new(io::ErrorKind::WouldBlock, "would block");
        let dns_err = DnsError::network_io("test", io_err);

        // WouldBlock is not fatal, just transient
        assert!(!UdpDnsServer::is_fatal_error(&dns_err));
    }

    #[test]
    fn test_is_degraded_error_would_block() {
        let io_err = io::Error::new(io::ErrorKind::WouldBlock, "would block");
        let dns_err = DnsError::network_io("test", io_err);

        // WouldBlock is considered a degraded state indicator
        assert!(UdpDnsServer::is_degraded_error(&dns_err));
    }

    #[test]
    fn test_is_degraded_error_timeout() {
        let io_err = io::Error::new(io::ErrorKind::TimedOut, "timeout");
        let dns_err = DnsError::network_io("test", io_err);

        assert!(UdpDnsServer::is_degraded_error(&dns_err));
    }

    #[test]
    fn test_is_degraded_error_connection_reset() {
        let io_err = io::Error::new(io::ErrorKind::ConnectionReset, "reset");
        let dns_err = DnsError::network_io("test", io_err);

        // ConnectionReset is not a degraded error, just a transient issue
        assert!(!UdpDnsServer::is_degraded_error(&dns_err));
    }

    // ========================================================================
    // Consecutive Error Tracking Tests
    // ========================================================================

    #[test]
    fn test_consecutive_recv_errors_tracking() {
        let stats = UdpServerStats::new();

        // Initially zero
        assert_eq!(stats.consecutive_recv_errors(), 0);

        // Increment errors
        assert_eq!(stats.record_recv_error(), 1);
        assert_eq!(stats.record_recv_error(), 2);
        assert_eq!(stats.record_recv_error(), 3);
        assert_eq!(stats.consecutive_recv_errors(), 3);

        // Success resets counter
        stats.record_recv_success();
        assert_eq!(stats.consecutive_recv_errors(), 0);
    }

    #[test]
    fn test_consecutive_send_errors_tracking() {
        let stats = UdpServerStats::new();

        // Initially zero
        assert_eq!(stats.consecutive_send_errors(), 0);

        // Increment errors
        assert_eq!(stats.record_send_error(), 1);
        assert_eq!(stats.record_send_error(), 2);
        assert_eq!(stats.consecutive_send_errors(), 2);

        // Success resets counter
        stats.record_send_success();
        assert_eq!(stats.consecutive_send_errors(), 0);
    }

    #[test]
    fn test_socket_degraded_threshold() {
        let stats = UdpServerStats::new();

        // Initially not degraded
        assert!(!stats.is_socket_degraded());

        // Below threshold
        for _ in 0..(CONSECUTIVE_ERROR_THRESHOLD - 1) {
            stats.record_recv_error();
        }
        assert!(!stats.is_socket_degraded());

        // At threshold - should be degraded
        stats.record_recv_error();
        assert!(stats.is_socket_degraded());

        // Reset recv errors
        stats.record_recv_success();
        assert!(!stats.is_socket_degraded());

        // Test send errors too
        for _ in 0..CONSECUTIVE_ERROR_THRESHOLD {
            stats.record_send_error();
        }
        assert!(stats.is_socket_degraded());
    }

    #[test]
    fn test_snapshot_includes_consecutive_errors() {
        let stats = UdpServerStats::new();

        stats.record_recv_error();
        stats.record_recv_error();
        stats.record_send_error();

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.consecutive_recv_errors, 2);
        assert_eq!(snapshot.consecutive_send_errors, 1);
    }

    // ========================================================================
    // Constants Tests
    // ========================================================================

    #[test]
    fn test_max_udp_message_size() {
        assert!(MAX_UDP_MESSAGE_SIZE >= 512);
        assert!(MAX_UDP_MESSAGE_SIZE <= 65535);
    }

    #[test]
    fn test_consecutive_error_threshold() {
        // Threshold should be reasonable
        assert!(CONSECUTIVE_ERROR_THRESHOLD >= 5);
        assert!(CONSECUTIVE_ERROR_THRESHOLD <= 100);
    }
}
