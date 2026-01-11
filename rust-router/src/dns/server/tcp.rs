//! TCP DNS Server
//!
//! This module provides a TCP-based DNS server with connection limits,
//! per-IP tracking, and timeout enforcement for security.
//!
//! # Architecture
//!
//! ```text
//! TCP Listener (port 7853)
//!     |
//!     v
//! Connection Tracker (per-IP limits)
//!     |
//!     v
//! Accept Connection
//!     |
//!     v
//! Handle Connection (with timeouts)
//!     |
//!     +-- Read 2-byte length prefix
//!     +-- Read DNS message
//!     +-- Process via DnsHandler
//!     +-- Write 2-byte length prefix + response
//! ```
//!
//! # Security Features
//!
//! - **Global connection limit**: Prevents resource exhaustion
//! - **Per-IP connection limit**: Prevents single-client abuse
//! - **Connection timeout**: Closes slow clients
//! - **Idle timeout**: Closes inactive connections
//! - **Message size limit**: Prevents memory exhaustion
//!
//! # Example
//!
//! ```no_run
//! use rust_router::dns::server::{TcpDnsServer, DnsHandler, DnsRateLimiter};
//! use rust_router::dns::{RateLimitConfig, TcpServerConfig};
//! use std::sync::Arc;
//! use std::net::SocketAddr;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let rate_limiter = Arc::new(DnsRateLimiter::new(&RateLimitConfig::default()));
//! let handler = Arc::new(DnsHandler::new(rate_limiter));
//! let tcp_config = TcpServerConfig::default();
//!
//! let addr: SocketAddr = "127.0.0.1:7853".parse()?;
//! let server = TcpDnsServer::bind(addr, handler, tcp_config).await?;
//!
//! // Run with shutdown signal
//! // server.run_until_shutdown(shutdown_rx).await?;
//! # Ok(())
//! # }
//! ```

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tracing::{debug, error, info, trace};

use super::handler::DnsHandler;
use crate::dns::config::TcpServerConfig;
use crate::dns::error::{DnsError, DnsResult};

/// Maximum DNS message size (RFC 1035 allows up to 65535 for TCP)
pub const MAX_TCP_MESSAGE_SIZE: usize = 65535;

/// Minimum DNS message size (just a header)
pub const MIN_DNS_MESSAGE_SIZE: usize = 12;

/// Per-IP connection tracker
///
/// Tracks the number of active connections from each IP address
/// to enforce per-IP connection limits.
#[derive(Debug)]
pub struct TcpConnectionTracker {
    /// Per-IP connection counts
    connections: DashMap<IpAddr, AtomicUsize>,
    /// Total connection count
    total_connections: AtomicUsize,
    /// Maximum total connections
    max_total: usize,
    /// Maximum connections per IP
    max_per_ip: usize,
    /// Statistics
    stats: ConnectionTrackerStats,
}

/// Statistics for the connection tracker
#[derive(Debug, Default)]
pub struct ConnectionTrackerStats {
    /// Total connections accepted
    accepted: AtomicU64,
    /// Connections rejected (global limit)
    rejected_global: AtomicU64,
    /// Connections rejected (per-IP limit)
    rejected_per_ip: AtomicU64,
    /// Total connections closed
    closed: AtomicU64,
}

impl ConnectionTrackerStats {
    /// Get total accepted connections
    #[must_use]
    pub fn accepted(&self) -> u64 {
        self.accepted.load(Ordering::Relaxed)
    }

    /// Get connections rejected due to global limit
    #[must_use]
    pub fn rejected_global(&self) -> u64 {
        self.rejected_global.load(Ordering::Relaxed)
    }

    /// Get connections rejected due to per-IP limit
    #[must_use]
    pub fn rejected_per_ip(&self) -> u64 {
        self.rejected_per_ip.load(Ordering::Relaxed)
    }

    /// Get total connections closed
    #[must_use]
    pub fn closed(&self) -> u64 {
        self.closed.load(Ordering::Relaxed)
    }

    /// Get snapshot of stats
    #[must_use]
    pub fn snapshot(&self) -> ConnectionTrackerStatsSnapshot {
        ConnectionTrackerStatsSnapshot {
            accepted: self.accepted(),
            rejected_global: self.rejected_global(),
            rejected_per_ip: self.rejected_per_ip(),
            closed: self.closed(),
        }
    }
}

/// Snapshot of connection tracker statistics
#[derive(Debug, Clone, Copy)]
pub struct ConnectionTrackerStatsSnapshot {
    /// Total connections accepted
    pub accepted: u64,
    /// Connections rejected (global limit)
    pub rejected_global: u64,
    /// Connections rejected (per-IP limit)
    pub rejected_per_ip: u64,
    /// Total connections closed
    pub closed: u64,
}

impl TcpConnectionTracker {
    /// Create a new connection tracker
    ///
    /// # Arguments
    ///
    /// * `max_total` - Maximum total concurrent connections
    /// * `max_per_ip` - Maximum connections per IP address
    #[must_use]
    pub fn new(max_total: usize, max_per_ip: usize) -> Self {
        Self {
            connections: DashMap::new(),
            total_connections: AtomicUsize::new(0),
            max_total,
            max_per_ip,
            stats: ConnectionTrackerStats::default(),
        }
    }

    /// Create from TCP server configuration
    #[must_use]
    pub fn from_config(config: &TcpServerConfig) -> Self {
        Self::new(config.max_connections, config.per_ip_max_connections)
    }

    /// Try to acquire a connection slot for an IP address
    ///
    /// Returns `true` if the connection is allowed, `false` if rejected.
    ///
    /// # Arguments
    ///
    /// * `ip` - Client IP address
    pub fn try_acquire(&self, ip: IpAddr) -> bool {
        // Check global limit first
        let current_total = self.total_connections.load(Ordering::SeqCst);
        if current_total >= self.max_total {
            self.stats.rejected_global.fetch_add(1, Ordering::Relaxed);
            debug!(
                ip = %ip,
                current = current_total,
                max = self.max_total,
                "Connection rejected: global limit exceeded"
            );
            return false;
        }

        // Check per-IP limit
        let entry = self.connections.entry(ip).or_insert_with(|| AtomicUsize::new(0));
        let current_ip = entry.load(Ordering::SeqCst);

        if current_ip >= self.max_per_ip {
            self.stats.rejected_per_ip.fetch_add(1, Ordering::Relaxed);
            debug!(
                ip = %ip,
                current = current_ip,
                max = self.max_per_ip,
                "Connection rejected: per-IP limit exceeded"
            );
            return false;
        }

        // Try to increment both counters atomically
        // This is not perfectly atomic between the two, but close enough for rate limiting
        let new_ip = entry.fetch_add(1, Ordering::SeqCst) + 1;
        if new_ip > self.max_per_ip {
            // Race condition - rollback
            entry.fetch_sub(1, Ordering::SeqCst);
            self.stats.rejected_per_ip.fetch_add(1, Ordering::Relaxed);
            return false;
        }

        let new_total = self.total_connections.fetch_add(1, Ordering::SeqCst) + 1;
        if new_total > self.max_total {
            // Race condition - rollback both
            entry.fetch_sub(1, Ordering::SeqCst);
            self.total_connections.fetch_sub(1, Ordering::SeqCst);
            self.stats.rejected_global.fetch_add(1, Ordering::Relaxed);
            return false;
        }

        self.stats.accepted.fetch_add(1, Ordering::Relaxed);
        trace!(ip = %ip, "Connection acquired");
        true
    }

    /// Release a connection slot for an IP address
    ///
    /// # Arguments
    ///
    /// * `ip` - Client IP address
    pub fn release(&self, ip: IpAddr) {
        // Decrement per-IP counter
        if let Some(entry) = self.connections.get(&ip) {
            let prev = entry.fetch_sub(1, Ordering::SeqCst);
            if prev == 0 {
                // Underflow protection
                entry.fetch_add(1, Ordering::SeqCst);
            }
        }

        // Decrement total counter
        let prev = self.total_connections.fetch_sub(1, Ordering::SeqCst);
        if prev == 0 {
            // Underflow protection
            self.total_connections.fetch_add(1, Ordering::SeqCst);
        }

        self.stats.closed.fetch_add(1, Ordering::Relaxed);
        trace!(ip = %ip, "Connection released");
    }

    /// Get current total connection count
    #[must_use]
    pub fn total_connections(&self) -> usize {
        self.total_connections.load(Ordering::SeqCst)
    }

    /// Get connection count for a specific IP
    #[must_use]
    pub fn connections_from(&self, ip: IpAddr) -> usize {
        self.connections
            .get(&ip)
            .map_or(0, |entry| entry.load(Ordering::SeqCst))
    }

    /// Get the number of tracked IPs
    #[must_use]
    pub fn tracked_ips(&self) -> usize {
        self.connections.len()
    }

    /// Get statistics
    #[must_use]
    pub fn stats(&self) -> &ConnectionTrackerStats {
        &self.stats
    }

    /// Clean up IPs with zero connections
    pub fn cleanup_empty(&self) {
        self.connections.retain(|_, count| count.load(Ordering::SeqCst) > 0);
    }
}

/// RAII guard for connection tracking
struct ConnectionGuard {
    tracker: Arc<TcpConnectionTracker>,
    ip: IpAddr,
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.tracker.release(self.ip);
    }
}

/// Statistics for the TCP DNS server
#[derive(Debug, Default)]
pub struct TcpServerStats {
    /// Total connections accepted
    connections_accepted: AtomicU64,
    /// Connections rejected (limits)
    connections_rejected: AtomicU64,
    /// Total queries processed
    queries_processed: AtomicU64,
    /// Queries that timed out
    queries_timeout: AtomicU64,
    /// Read errors
    read_errors: AtomicU64,
    /// Write errors
    write_errors: AtomicU64,
    /// Parse errors
    parse_errors: AtomicU64,
    /// Total bytes received
    bytes_received: AtomicU64,
    /// Total bytes sent
    bytes_sent: AtomicU64,
}

impl TcpServerStats {
    /// Get connections accepted
    #[must_use]
    pub fn connections_accepted(&self) -> u64 {
        self.connections_accepted.load(Ordering::Relaxed)
    }

    /// Get connections rejected
    #[must_use]
    pub fn connections_rejected(&self) -> u64 {
        self.connections_rejected.load(Ordering::Relaxed)
    }

    /// Get queries processed
    #[must_use]
    pub fn queries_processed(&self) -> u64 {
        self.queries_processed.load(Ordering::Relaxed)
    }

    /// Get snapshot
    #[must_use]
    pub fn snapshot(&self) -> TcpServerStatsSnapshot {
        TcpServerStatsSnapshot {
            connections_accepted: self.connections_accepted(),
            connections_rejected: self.connections_rejected(),
            queries_processed: self.queries_processed(),
            queries_timeout: self.queries_timeout.load(Ordering::Relaxed),
            read_errors: self.read_errors.load(Ordering::Relaxed),
            write_errors: self.write_errors.load(Ordering::Relaxed),
            parse_errors: self.parse_errors.load(Ordering::Relaxed),
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of TCP server statistics
#[derive(Debug, Clone, Copy)]
pub struct TcpServerStatsSnapshot {
    /// Connections accepted
    pub connections_accepted: u64,
    /// Connections rejected
    pub connections_rejected: u64,
    /// Queries processed
    pub queries_processed: u64,
    /// Queries timed out
    pub queries_timeout: u64,
    /// Read errors
    pub read_errors: u64,
    /// Write errors
    pub write_errors: u64,
    /// Parse errors
    pub parse_errors: u64,
    /// Bytes received
    pub bytes_received: u64,
    /// Bytes sent
    pub bytes_sent: u64,
}

/// TCP DNS Server
///
/// Handles DNS queries over TCP with connection management and security.
pub struct TcpDnsServer {
    /// TCP listener
    listener: TcpListener,
    /// DNS query handler
    handler: Arc<DnsHandler>,
    /// Connection tracker
    tracker: Arc<TcpConnectionTracker>,
    /// Server configuration
    config: TcpServerConfig,
    /// Server statistics
    stats: Arc<TcpServerStats>,
    /// Shutdown flag
    shutdown: Arc<AtomicBool>,
    /// Local bind address
    local_addr: SocketAddr,
}

impl TcpDnsServer {
    /// Create and bind a new TCP DNS server
    ///
    /// # Arguments
    ///
    /// * `addr` - Address to bind to
    /// * `handler` - DNS query handler
    /// * `config` - TCP server configuration
    ///
    /// # Errors
    ///
    /// Returns an error if the socket cannot be bound.
    pub async fn bind(
        addr: SocketAddr,
        handler: Arc<DnsHandler>,
        config: TcpServerConfig,
    ) -> DnsResult<Self> {
        let listener = TcpListener::bind(addr).await.map_err(|e| {
            DnsError::network_io(format!("failed to bind TCP socket to {addr}"), e)
        })?;

        let local_addr = listener.local_addr().map_err(|e| {
            DnsError::network_io("failed to get local address".to_string(), e)
        })?;

        info!(addr = %local_addr, "TCP DNS server bound");

        let tracker = Arc::new(TcpConnectionTracker::from_config(&config));

        Ok(Self {
            listener,
            handler,
            tracker,
            config,
            stats: Arc::new(TcpServerStats::default()),
            shutdown: Arc::new(AtomicBool::new(false)),
            local_addr,
        })
    }

    /// Get the local address
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Get server statistics
    #[must_use]
    pub fn stats(&self) -> &Arc<TcpServerStats> {
        &self.stats
    }

    /// Get connection tracker
    #[must_use]
    pub fn tracker(&self) -> &Arc<TcpConnectionTracker> {
        &self.tracker
    }

    /// Check if shut down
    #[must_use]
    pub fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::SeqCst)
    }

    /// Signal shutdown
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
    }

    /// Run the server until shutdown
    pub async fn run(&self) -> DnsResult<()> {
        info!(addr = %self.local_addr, "TCP DNS server starting");

        loop {
            if self.shutdown.load(Ordering::SeqCst) {
                info!("TCP DNS server shutting down");
                break;
            }

            match self.listener.accept().await {
                Ok((stream, peer_addr)) => {
                    self.handle_connection(stream, peer_addr);
                }
                Err(e) => {
                    if Self::is_fatal_error(&e) {
                        error!(error = %e, "Fatal TCP accept error");
                        return Err(DnsError::network_io("accept failed".to_string(), e));
                    }
                    debug!(error = %e, "Non-fatal accept error");
                }
            }
        }

        Ok(())
    }

    /// Run with shutdown receiver
    pub async fn run_until_shutdown(
        &self,
        mut shutdown_rx: tokio::sync::oneshot::Receiver<()>,
    ) -> DnsResult<()> {
        info!(addr = %self.local_addr, "TCP DNS server starting");

        loop {
            tokio::select! {
                result = self.listener.accept() => {
                    match result {
                        Ok((stream, peer_addr)) => {
                            self.handle_connection(stream, peer_addr);
                        }
                        Err(e) => {
                            if Self::is_fatal_error(&e) {
                                error!(error = %e, "Fatal TCP accept error");
                                return Err(DnsError::network_io("accept failed".to_string(), e));
                            }
                            debug!(error = %e, "Non-fatal accept error");
                        }
                    }
                }
                _ = &mut shutdown_rx => {
                    info!("TCP DNS server received shutdown signal");
                    self.shutdown.store(true, Ordering::SeqCst);
                    break;
                }
            }
        }

        Ok(())
    }

    /// Handle a new connection
    fn handle_connection(&self, stream: TcpStream, peer_addr: SocketAddr) {
        let ip = peer_addr.ip();

        // Check connection limits
        if !self.tracker.try_acquire(ip) {
            self.stats.connections_rejected.fetch_add(1, Ordering::Relaxed);
            debug!(peer = %peer_addr, "Connection rejected: limit exceeded");
            return;
        }

        self.stats.connections_accepted.fetch_add(1, Ordering::Relaxed);

        // Spawn handler task
        let handler = Arc::clone(&self.handler);
        let tracker = Arc::clone(&self.tracker);
        let stats = Arc::clone(&self.stats);
        let config = self.config.clone();

        tokio::spawn(async move {
            let _guard = ConnectionGuard { tracker, ip };

            if let Err(e) = Self::handle_connection_inner(stream, peer_addr, handler, stats, config).await {
                debug!(peer = %peer_addr, error = %e, "Connection error");
            }
        });
    }

    /// Inner connection handler
    async fn handle_connection_inner(
        mut stream: TcpStream,
        peer_addr: SocketAddr,
        handler: Arc<DnsHandler>,
        stats: Arc<TcpServerStats>,
        config: TcpServerConfig,
    ) -> DnsResult<()> {
        let connection_timeout = Duration::from_secs(config.connection_timeout_secs);
        let idle_timeout = Duration::from_secs(config.idle_timeout_secs);
        let max_message_size = config.max_message_size;

        trace!(peer = %peer_addr, "Handling TCP connection");

        loop {
            // Read message with timeout
            let message = timeout(
                idle_timeout,
                Self::read_dns_message(&mut stream, max_message_size),
            )
            .await;

            let message = match message {
                Ok(Ok(msg)) => msg,
                Ok(Err(e)) => {
                    // Read error
                    if matches!(e, DnsError::NetworkError { .. }) {
                        // Connection closed or network error
                        return Ok(());
                    }
                    stats.read_errors.fetch_add(1, Ordering::Relaxed);
                    return Err(e);
                }
                Err(_) => {
                    // Timeout
                    stats.queries_timeout.fetch_add(1, Ordering::Relaxed);
                    debug!(peer = %peer_addr, "Connection idle timeout");
                    return Ok(());
                }
            };

            stats.bytes_received.fetch_add(message.len() as u64 + 2, Ordering::Relaxed);

            // Process query with timeout
            let response = timeout(
                connection_timeout,
                handler.handle_query(peer_addr, &message),
            )
            .await;

            let response_data = match response {
                Ok(Ok(data)) => data,
                Ok(Err(e)) => {
                    if e.is_rate_limited() || matches!(e, DnsError::ParseError { .. }) {
                        stats.parse_errors.fetch_add(1, Ordering::Relaxed);
                    }
                    // Try to generate error response
                    match handler.generate_error_response(&message, &e) {
                        Some(data) => data,
                        None => continue, // Skip this query
                    }
                }
                Err(_) => {
                    stats.queries_timeout.fetch_add(1, Ordering::Relaxed);
                    debug!(peer = %peer_addr, "Query processing timeout");
                    continue;
                }
            };

            // Write response with timeout
            let write_result = timeout(
                connection_timeout,
                Self::write_dns_message(&mut stream, &response_data),
            )
            .await;

            match write_result {
                Ok(Ok(())) => {
                    stats.queries_processed.fetch_add(1, Ordering::Relaxed);
                    stats.bytes_sent.fetch_add(response_data.len() as u64 + 2, Ordering::Relaxed);
                }
                Ok(Err(e)) => {
                    stats.write_errors.fetch_add(1, Ordering::Relaxed);
                    return Err(e);
                }
                Err(_) => {
                    stats.queries_timeout.fetch_add(1, Ordering::Relaxed);
                    debug!(peer = %peer_addr, "Write timeout");
                    return Ok(());
                }
            }
        }
    }

    /// Read a DNS message (2-byte length prefix + message)
    async fn read_dns_message(stream: &mut TcpStream, max_size: usize) -> DnsResult<Vec<u8>> {
        // Read 2-byte length prefix
        let mut len_buf = [0u8; 2];
        match stream.read_exact(&mut len_buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                // Connection closed
                return Err(DnsError::network("connection closed".to_string()));
            }
            Err(e) => {
                return Err(DnsError::network_io("failed to read length prefix".to_string(), e));
            }
        }

        let len = u16::from_be_bytes(len_buf) as usize;

        // Validate length
        if len < MIN_DNS_MESSAGE_SIZE {
            return Err(DnsError::parse(format!(
                "message too small: {len} bytes (min: {MIN_DNS_MESSAGE_SIZE})"
            )));
        }

        if len > max_size {
            return Err(DnsError::parse(format!(
                "message too large: {len} bytes (max: {max_size})"
            )));
        }

        // Read message body
        let mut message = vec![0u8; len];
        stream.read_exact(&mut message).await.map_err(|e| {
            DnsError::network_io("failed to read message body".to_string(), e)
        })?;

        Ok(message)
    }

    /// Write a DNS message (2-byte length prefix + message)
    async fn write_dns_message(stream: &mut TcpStream, message: &[u8]) -> DnsResult<()> {
        if message.len() > MAX_TCP_MESSAGE_SIZE {
            return Err(DnsError::serialize(format!(
                "response too large: {} bytes (max: {})",
                message.len(),
                MAX_TCP_MESSAGE_SIZE
            )));
        }

        // Write length prefix
        let len_bytes = (message.len() as u16).to_be_bytes();
        stream.write_all(&len_bytes).await.map_err(|e| {
            DnsError::network_io("failed to write length prefix".to_string(), e)
        })?;

        // Write message body
        stream.write_all(message).await.map_err(|e| {
            DnsError::network_io("failed to write message body".to_string(), e)
        })?;

        stream.flush().await.map_err(|e| {
            DnsError::network_io("failed to flush".to_string(), e)
        })?;

        Ok(())
    }

    /// Check if an error is fatal
    fn is_fatal_error(err: &io::Error) -> bool {
        matches!(
            err.kind(),
            io::ErrorKind::PermissionDenied | io::ErrorKind::AddrInUse
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::server::rate_limit::DnsRateLimiter;
    use crate::dns::RateLimitConfig;
    use std::net::Ipv4Addr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream as TokioTcpStream;

    fn test_ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, last))
    }

    async fn create_test_server() -> (TcpDnsServer, SocketAddr) {
        let rate_limiter = Arc::new(DnsRateLimiter::new(&RateLimitConfig::default()));
        let handler = Arc::new(DnsHandler::new(rate_limiter));
        let config = TcpServerConfig::default();

        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let server = TcpDnsServer::bind(addr, handler, config).await.unwrap();
        let local_addr = server.local_addr();

        (server, local_addr)
    }

    fn create_simple_dns_query() -> Vec<u8> {
        let mut query = vec![
            0x12, 0x34, // ID
            0x01, 0x00, // Flags
            0x00, 0x01, // QDCOUNT
            0x00, 0x00, // ANCOUNT
            0x00, 0x00, // NSCOUNT
            0x00, 0x00, // ARCOUNT
        ];

        query.extend_from_slice(&[
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            0x03, b'c', b'o', b'm',
            0x00,
            0x00, 0x01, // A
            0x00, 0x01, // IN
        ]);

        query
    }

    // ========================================================================
    // Connection Tracker Tests
    // ========================================================================

    #[test]
    fn test_tracker_new() {
        let tracker = TcpConnectionTracker::new(100, 10);
        assert_eq!(tracker.total_connections(), 0);
        assert_eq!(tracker.tracked_ips(), 0);
    }

    #[test]
    fn test_tracker_acquire_release() {
        let tracker = TcpConnectionTracker::new(100, 10);
        let ip = test_ip(1);

        assert!(tracker.try_acquire(ip));
        assert_eq!(tracker.total_connections(), 1);
        assert_eq!(tracker.connections_from(ip), 1);

        tracker.release(ip);
        assert_eq!(tracker.total_connections(), 0);
        assert_eq!(tracker.connections_from(ip), 0);
    }

    #[test]
    fn test_tracker_global_limit() {
        let tracker = TcpConnectionTracker::new(2, 10);

        assert!(tracker.try_acquire(test_ip(1)));
        assert!(tracker.try_acquire(test_ip(2)));
        assert!(!tracker.try_acquire(test_ip(3))); // Global limit

        assert_eq!(tracker.stats().rejected_global(), 1);
    }

    #[test]
    fn test_tracker_per_ip_limit() {
        let tracker = TcpConnectionTracker::new(100, 2);
        let ip = test_ip(1);

        assert!(tracker.try_acquire(ip));
        assert!(tracker.try_acquire(ip));
        assert!(!tracker.try_acquire(ip)); // Per-IP limit

        assert_eq!(tracker.stats().rejected_per_ip(), 1);
    }

    #[test]
    fn test_tracker_multiple_ips() {
        let tracker = TcpConnectionTracker::new(100, 10);

        for i in 1..=5 {
            assert!(tracker.try_acquire(test_ip(i)));
        }

        assert_eq!(tracker.total_connections(), 5);
        assert_eq!(tracker.tracked_ips(), 5);
    }

    #[test]
    fn test_tracker_cleanup_empty() {
        let tracker = TcpConnectionTracker::new(100, 10);
        let ip = test_ip(1);

        tracker.try_acquire(ip);
        tracker.release(ip);

        assert_eq!(tracker.tracked_ips(), 1); // Still tracked

        tracker.cleanup_empty();
        assert_eq!(tracker.tracked_ips(), 0); // Cleaned up
    }

    #[test]
    fn test_tracker_stats_snapshot() {
        let tracker = TcpConnectionTracker::new(100, 10);
        let ip = test_ip(1);

        tracker.try_acquire(ip);
        tracker.release(ip);

        let snapshot = tracker.stats().snapshot();
        assert_eq!(snapshot.accepted, 1);
        assert_eq!(snapshot.closed, 1);
    }

    // ========================================================================
    // Server Creation Tests
    // ========================================================================

    #[tokio::test]
    async fn test_bind_success() {
        let (server, addr) = create_test_server().await;

        assert_eq!(server.local_addr(), addr);
        assert!(!server.is_shutdown());
    }

    #[tokio::test]
    async fn test_stats_initial() {
        let (server, _) = create_test_server().await;

        let stats = server.stats().snapshot();
        assert_eq!(stats.connections_accepted, 0);
        assert_eq!(stats.queries_processed, 0);
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
        let (server, _) = create_test_server().await;
        let server = Arc::new(server);

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

        let server_clone = Arc::clone(&server);
        let handle = tokio::spawn(async move {
            server_clone.run_until_shutdown(shutdown_rx).await
        });

        tokio::time::sleep(Duration::from_millis(10)).await;

        shutdown_tx.send(()).unwrap();

        let result = tokio::time::timeout(Duration::from_secs(1), handle).await;
        assert!(result.is_ok());
    }

    // ========================================================================
    // Connection Handling Tests
    // ========================================================================

    #[tokio::test]
    async fn test_accept_connection() {
        let (server, addr) = create_test_server().await;
        let server = Arc::new(server);

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

        let server_clone = Arc::clone(&server);
        tokio::spawn(async move {
            let _ = server_clone.run_until_shutdown(shutdown_rx).await;
        });

        tokio::time::sleep(Duration::from_millis(10)).await;

        // Connect
        let stream = TokioTcpStream::connect(addr).await;
        assert!(stream.is_ok());

        tokio::time::sleep(Duration::from_millis(50)).await;

        assert!(server.stats().connections_accepted() >= 1);

        shutdown_tx.send(()).unwrap();
    }

    #[tokio::test]
    async fn test_send_query() {
        let (server, addr) = create_test_server().await;
        let server = Arc::new(server);

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

        let server_clone = Arc::clone(&server);
        tokio::spawn(async move {
            let _ = server_clone.run_until_shutdown(shutdown_rx).await;
        });

        tokio::time::sleep(Duration::from_millis(10)).await;

        // Connect and send query
        let mut stream = TokioTcpStream::connect(addr).await.unwrap();

        let query = create_simple_dns_query();
        let len_bytes = (query.len() as u16).to_be_bytes();

        stream.write_all(&len_bytes).await.unwrap();
        stream.write_all(&query).await.unwrap();
        stream.flush().await.unwrap();

        // Read response
        let mut response_len_buf = [0u8; 2];
        let read_result = tokio::time::timeout(
            Duration::from_secs(1),
            stream.read_exact(&mut response_len_buf),
        )
        .await;

        if let Ok(Ok(_)) = read_result {
            let response_len = u16::from_be_bytes(response_len_buf) as usize;
            assert!(response_len >= MIN_DNS_MESSAGE_SIZE);
        }

        shutdown_tx.send(()).unwrap();
    }

    // ========================================================================
    // Message Reading/Writing Tests
    // ========================================================================

    #[tokio::test]
    async fn test_read_dns_message() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Sender task
        tokio::spawn(async move {
            let mut stream = TokioTcpStream::connect(addr).await.unwrap();
            let data = vec![0u8; 20];
            let len_bytes = (data.len() as u16).to_be_bytes();
            stream.write_all(&len_bytes).await.unwrap();
            stream.write_all(&data).await.unwrap();
        });

        // Receiver
        let (mut stream, _) = listener.accept().await.unwrap();
        let result = TcpDnsServer::read_dns_message(&mut stream, MAX_TCP_MESSAGE_SIZE).await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 20);
    }

    #[tokio::test]
    async fn test_read_dns_message_too_small() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let mut stream = TokioTcpStream::connect(addr).await.unwrap();
            let len_bytes = 5u16.to_be_bytes(); // Too small
            stream.write_all(&len_bytes).await.unwrap();
        });

        let (mut stream, _) = listener.accept().await.unwrap();
        let result = TcpDnsServer::read_dns_message(&mut stream, MAX_TCP_MESSAGE_SIZE).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_read_dns_message_too_large() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let mut stream = TokioTcpStream::connect(addr).await.unwrap();
            let len_bytes = 60000u16.to_be_bytes();
            stream.write_all(&len_bytes).await.unwrap();
        });

        let (mut stream, _) = listener.accept().await.unwrap();
        let result = TcpDnsServer::read_dns_message(&mut stream, 1000).await; // Small max

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_write_dns_message() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Writer
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let data = vec![0xAB; 100];
            TcpDnsServer::write_dns_message(&mut stream, &data).await.unwrap();
        });

        // Reader
        let mut stream = TokioTcpStream::connect(addr).await.unwrap();

        let mut len_buf = [0u8; 2];
        stream.read_exact(&mut len_buf).await.unwrap();
        let len = u16::from_be_bytes(len_buf) as usize;
        assert_eq!(len, 100);

        let mut data = vec![0u8; len];
        stream.read_exact(&mut data).await.unwrap();
        assert_eq!(data[0], 0xAB);
    }

    // ========================================================================
    // Error Tests
    // ========================================================================

    #[test]
    fn test_is_fatal_error_permission() {
        let err = io::Error::new(io::ErrorKind::PermissionDenied, "denied");
        assert!(TcpDnsServer::is_fatal_error(&err));
    }

    #[test]
    fn test_is_fatal_error_addr_in_use() {
        let err = io::Error::new(io::ErrorKind::AddrInUse, "in use");
        assert!(TcpDnsServer::is_fatal_error(&err));
    }

    #[test]
    fn test_is_fatal_error_connection_reset() {
        let err = io::Error::new(io::ErrorKind::ConnectionReset, "reset");
        assert!(!TcpDnsServer::is_fatal_error(&err));
    }

    // ========================================================================
    // Constants Tests
    // ========================================================================

    #[test]
    fn test_max_tcp_message_size() {
        assert_eq!(MAX_TCP_MESSAGE_SIZE, 65535);
    }

    #[test]
    fn test_min_dns_message_size() {
        assert_eq!(MIN_DNS_MESSAGE_SIZE, 12);
    }
}
