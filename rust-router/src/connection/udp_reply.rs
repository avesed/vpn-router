//! UDP Reply Socket Handler
//!
//! This module provides the mechanism for sending UDP replies back to clients
//! through TPROXY with spoofed source addresses. This is critical because
//! TPROXY-intercepted UDP needs replies to appear to come from the original
//! destination address, not the proxy's address.
//!
//! # IPv4 Only
//!
//! **Important**: This implementation supports IPv4 only. The `IP_TRANSPARENT`
//! socket option and bind semantics are IPv4-specific. IPv6 support would
//! require `IPV6_TRANSPARENT` and different socket handling.
//!
//! # Architecture
//!
//! ```text
//! Destination → Outbound Handle → Reply Handler → Client
//!                                      ↓
//!                              IP_TRANSPARENT socket
//!                              bound to original_dst
//!                                      ↓
//!                              sendto(client_addr)
//! ```
//!
//! # Requirements
//!
//! - `CAP_NET_ADMIN` capability for `IP_TRANSPARENT`
//! - `net.ipv4.ip_nonlocal_bind = 1` sysctl
//!
//! # Why We Need This
//!
//! When a UDP packet arrives via TPROXY destined for `8.8.8.8:53`, we forward
//! it to DNS and get a reply. To send the reply back to the client, we must:
//!
//! 1. Create a socket with `IP_TRANSPARENT`
//! 2. Bind to `8.8.8.8:53` (the original destination - a non-local address)
//! 3. Send the reply to the client
//!
//! Without `IP_TRANSPARENT` and `ip_nonlocal_bind`, we cannot bind to non-local
//! addresses, and the reply would come from our proxy IP instead of the
//! expected destination IP.

use std::io;
use std::mem;
use std::net::SocketAddr;
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use moka::sync::Cache;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tracing::{debug, trace, warn};

use crate::error::UdpError;

/// Linux kernel constant: `IP_TRANSPARENT`
const IP_TRANSPARENT: libc::c_int = 19;

/// Default TTL for reply sockets in cache (5 minutes)
const DEFAULT_REPLY_SOCKET_TTL: Duration = Duration::from_secs(300);

/// Default idle timeout for reply sockets (60 seconds)
const DEFAULT_REPLY_SOCKET_IDLE: Duration = Duration::from_secs(60);

/// Maximum number of cached reply sockets
const DEFAULT_MAX_REPLY_SOCKETS: u64 = 10_000;

/// Configuration for the reply handler
#[derive(Debug, Clone)]
pub struct ReplyHandlerConfig {
    /// Maximum number of cached reply sockets
    pub max_sockets: u64,
    /// TTL for cached sockets
    pub socket_ttl: Duration,
    /// Idle timeout for cached sockets
    pub socket_idle_timeout: Duration,
}

impl Default for ReplyHandlerConfig {
    fn default() -> Self {
        Self {
            max_sockets: DEFAULT_MAX_REPLY_SOCKETS,
            socket_ttl: DEFAULT_REPLY_SOCKET_TTL,
            socket_idle_timeout: DEFAULT_REPLY_SOCKET_IDLE,
        }
    }
}

/// Statistics for the reply handler
#[derive(Debug, Default)]
pub struct ReplyHandlerStats {
    /// Total replies sent
    pub replies_sent: AtomicU64,
    /// Total bytes sent
    pub bytes_sent: AtomicU64,
    /// Sockets created
    pub sockets_created: AtomicU64,
    /// Socket cache hits
    pub cache_hits: AtomicU64,
    /// Socket cache misses (required new socket creation)
    pub cache_misses: AtomicU64,
    /// Sockets evicted from cache (by TTL, idle timeout, or LRU)
    pub evictions: AtomicU64,
    /// Send failures
    pub send_failures: AtomicU64,
}

impl ReplyHandlerStats {
    /// Get a snapshot of the stats
    #[must_use]
    pub fn snapshot(&self) -> ReplyHandlerStatsSnapshot {
        ReplyHandlerStatsSnapshot {
            replies_sent: self.replies_sent.load(Ordering::Relaxed),
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            sockets_created: self.sockets_created.load(Ordering::Relaxed),
            cache_hits: self.cache_hits.load(Ordering::Relaxed),
            cache_misses: self.cache_misses.load(Ordering::Relaxed),
            evictions: self.evictions.load(Ordering::Relaxed),
            send_failures: self.send_failures.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of reply handler stats
#[derive(Debug, Clone)]
pub struct ReplyHandlerStatsSnapshot {
    pub replies_sent: u64,
    pub bytes_sent: u64,
    pub sockets_created: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub evictions: u64,
    pub send_failures: u64,
}

impl ReplyHandlerStatsSnapshot {
    /// Calculate cache hit rate as a percentage (0.0 - 100.0).
    ///
    /// Returns 0.0 if no lookups have been performed.
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn cache_hit_rate(&self) -> f64 {
        let total = self.cache_hits + self.cache_misses;
        if total == 0 {
            0.0
        } else {
            (self.cache_hits as f64 / total as f64) * 100.0
        }
    }
}

/// A cached reply socket bound to a specific "original destination"
#[derive(Debug)]
struct ReplySocket {
    /// The underlying tokio UDP socket
    socket: UdpSocket,
    /// The address this socket is bound to (original destination)
    bound_addr: SocketAddr,
}

impl ReplySocket {
    /// Send a reply to the client
    async fn send_to(&self, data: &[u8], client_addr: SocketAddr) -> io::Result<usize> {
        self.socket.send_to(data, client_addr).await
    }
}

/// UDP Reply Handler
///
/// Manages a cache of `IP_TRANSPARENT` sockets for sending replies with
/// spoofed source addresses. Each unique "original destination" gets its
/// own socket bound to that address.
pub struct UdpReplyHandler {
    /// Cache of reply sockets, keyed by original destination
    socket_cache: Cache<SocketAddr, Arc<ReplySocket>>,
    /// Statistics
    stats: Arc<ReplyHandlerStats>,
    /// Configuration
    config: ReplyHandlerConfig,
}

impl UdpReplyHandler {
    /// Create a new reply handler with the given configuration
    pub fn new(config: ReplyHandlerConfig) -> Self {
        let stats = Arc::new(ReplyHandlerStats::default());
        let stats_for_eviction = Arc::clone(&stats);

        let socket_cache = Cache::builder()
            .max_capacity(config.max_sockets)
            .time_to_live(config.socket_ttl)
            .time_to_idle(config.socket_idle_timeout)
            .eviction_listener(move |_key, _value, _cause| {
                stats_for_eviction.evictions.fetch_add(1, Ordering::Relaxed);
            })
            .build();

        Self {
            socket_cache,
            stats,
            config,
        }
    }

    /// Create with default configuration
    #[must_use]
    pub fn new_default() -> Self {
        Self::new(ReplyHandlerConfig::default())
    }

    /// Send a reply to a client.
    ///
    /// The reply will appear to come from `original_dst` (the address the
    /// client originally tried to reach) even though we're sending it from
    /// our proxy.
    ///
    /// # Arguments
    ///
    /// * `data` - The reply data to send
    /// * `client_addr` - The client's address to send to
    /// * `original_dst` - The original destination (appears as source of reply)
    ///
    /// # Errors
    ///
    /// Returns `UdpError` if:
    /// - Reply socket creation fails (likely missing `CAP_NET_ADMIN`)
    /// - Sending fails
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Client sent UDP to 8.8.8.8:53, we forward and get a response
    /// // Now send the response back with 8.8.8.8:53 as the source
    /// handler.send_reply(
    ///     &dns_response,
    ///     "192.168.1.100:12345".parse().unwrap(),  // client
    ///     "8.8.8.8:53".parse().unwrap(),            // original destination
    /// ).await?;
    /// ```
    pub async fn send_reply(
        &self,
        data: &[u8],
        client_addr: SocketAddr,
        original_dst: SocketAddr,
    ) -> Result<usize, UdpError> {
        // Try to get existing socket from cache
        if let Some(socket) = self.socket_cache.get(&original_dst) {
            self.stats.cache_hits.fetch_add(1, Ordering::Relaxed);
            trace!(
                "Using cached reply socket for {} -> {}",
                original_dst,
                client_addr
            );
            return self.do_send(&socket, data, client_addr).await;
        }

        // Cache miss - need to create a new reply socket
        self.stats.cache_misses.fetch_add(1, Ordering::Relaxed);
        debug!(
            "Creating reply socket bound to {} for client {}",
            original_dst, client_addr
        );

        let socket = Self::create_reply_socket(original_dst)?;
        let socket = Arc::new(socket);

        // Insert into cache
        self.socket_cache.insert(original_dst, Arc::clone(&socket));
        self.stats.sockets_created.fetch_add(1, Ordering::Relaxed);

        self.do_send(&socket, data, client_addr).await
    }

    /// Perform the actual send operation
    async fn do_send(
        &self,
        socket: &ReplySocket,
        data: &[u8],
        client_addr: SocketAddr,
    ) -> Result<usize, UdpError> {
        match socket.send_to(data, client_addr).await {
            Ok(n) => {
                self.stats.replies_sent.fetch_add(1, Ordering::Relaxed);
                self.stats.bytes_sent.fetch_add(n as u64, Ordering::Relaxed);
                trace!("Sent {} bytes reply to {}", n, client_addr);
                Ok(n)
            }
            Err(e) => {
                self.stats.send_failures.fetch_add(1, Ordering::Relaxed);
                warn!(
                    "Failed to send reply to {} from {}: {}",
                    client_addr, socket.bound_addr, e
                );
                Err(UdpError::send(client_addr, e.to_string()))
            }
        }
    }

    /// Create a reply socket bound to the original destination.
    ///
    /// This requires `CAP_NET_ADMIN` for `IP_TRANSPARENT` and
    /// `ip_nonlocal_bind=1` sysctl for binding to non-local addresses.
    fn create_reply_socket(bind_addr: SocketAddr) -> Result<ReplySocket, UdpError> {
        // Create UDP socket
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).map_err(|e| {
            UdpError::reply_socket(bind_addr, format!("Failed to create socket: {e}"))
        })?;

        // Set IP_TRANSPARENT to allow binding to non-local addresses
        set_ip_transparent(&socket).map_err(|e| {
            UdpError::reply_socket(bind_addr, format!("Failed to set IP_TRANSPARENT: {e}"))
        })?;

        // Set SO_REUSEADDR
        socket.set_reuse_address(true).map_err(|e| {
            UdpError::reply_socket(bind_addr, format!("Failed to set SO_REUSEADDR: {e}"))
        })?;

        // Bind to the "original destination" (a non-local address)
        socket.bind(&bind_addr.into()).map_err(|e| {
            UdpError::reply_socket(
                bind_addr,
                format!(
                    "Failed to bind to {bind_addr} (need ip_nonlocal_bind=1 and CAP_NET_ADMIN): {e}"
                ),
            )
        })?;

        // Set non-blocking for tokio
        socket.set_nonblocking(true).map_err(|e| {
            UdpError::reply_socket(bind_addr, format!("Failed to set non-blocking: {e}"))
        })?;

        // Convert to tokio socket
        let std_socket = unsafe { std::net::UdpSocket::from_raw_fd(socket.into_raw_fd()) };
        let tokio_socket = UdpSocket::from_std(std_socket).map_err(|e| {
            UdpError::reply_socket(bind_addr, format!("Failed to convert to tokio socket: {e}"))
        })?;

        debug!("Created reply socket bound to {}", bind_addr);

        Ok(ReplySocket {
            socket: tokio_socket,
            bound_addr: bind_addr,
        })
    }

    /// Get statistics
    pub fn stats(&self) -> &Arc<ReplyHandlerStats> {
        &self.stats
    }

    /// Get a stats snapshot
    pub fn stats_snapshot(&self) -> ReplyHandlerStatsSnapshot {
        self.stats.snapshot()
    }

    /// Get the number of cached sockets
    pub fn cached_sockets(&self) -> u64 {
        self.socket_cache.entry_count()
    }

    /// Invalidate (remove) a specific socket from cache
    pub fn invalidate(&self, original_dst: &SocketAddr) {
        self.socket_cache.invalidate(original_dst);
    }

    /// Clear all cached sockets
    pub fn clear_cache(&self) {
        self.socket_cache.invalidate_all();
    }
}

/// Set `IP_TRANSPARENT` socket option
#[allow(clippy::cast_possible_truncation)] // socklen_t is always u32
fn set_ip_transparent(socket: &Socket) -> Result<(), io::Error> {
    let fd = socket.as_raw_fd();
    let one: libc::c_int = 1;

    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_IP,
            IP_TRANSPARENT,
            std::ptr::addr_of!(one).cast::<libc::c_void>(),
            mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };

    if ret != 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

impl std::fmt::Debug for UdpReplyHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpReplyHandler")
            .field("cached_sockets", &self.cached_sockets())
            .field("config", &self.config)
            .field("stats", &self.stats_snapshot())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = ReplyHandlerConfig::default();
        assert_eq!(config.max_sockets, DEFAULT_MAX_REPLY_SOCKETS);
        assert_eq!(config.socket_ttl, DEFAULT_REPLY_SOCKET_TTL);
        assert_eq!(config.socket_idle_timeout, DEFAULT_REPLY_SOCKET_IDLE);
    }

    #[test]
    fn test_stats_snapshot() {
        let stats = ReplyHandlerStats::default();
        stats.replies_sent.fetch_add(10, Ordering::Relaxed);
        stats.bytes_sent.fetch_add(1000, Ordering::Relaxed);
        stats.sockets_created.fetch_add(5, Ordering::Relaxed);
        stats.cache_hits.fetch_add(8, Ordering::Relaxed);
        stats.cache_misses.fetch_add(2, Ordering::Relaxed);
        stats.evictions.fetch_add(1, Ordering::Relaxed);

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.replies_sent, 10);
        assert_eq!(snapshot.bytes_sent, 1000);
        assert_eq!(snapshot.sockets_created, 5);
        assert_eq!(snapshot.cache_hits, 8);
        assert_eq!(snapshot.cache_misses, 2);
        assert_eq!(snapshot.evictions, 1);

        // Test cache hit rate calculation: 8 / (8 + 2) = 80%
        assert!((snapshot.cache_hit_rate() - 80.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_cache_hit_rate_zero_lookups() {
        let snapshot = ReplyHandlerStatsSnapshot {
            replies_sent: 0,
            bytes_sent: 0,
            sockets_created: 0,
            cache_hits: 0,
            cache_misses: 0,
            evictions: 0,
            send_failures: 0,
        };
        assert!((snapshot.cache_hit_rate() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_handler_creation() {
        let handler = UdpReplyHandler::new_default();
        assert_eq!(handler.cached_sockets(), 0);
    }

    #[tokio::test]
    async fn test_send_reply_no_cap() {
        // This test verifies the handler handles permission errors gracefully
        let handler = UdpReplyHandler::new_default();

        let data = b"test reply";
        let client: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let original_dst: SocketAddr = "8.8.8.8:53".parse().unwrap();

        let result = handler.send_reply(data, client, original_dst).await;

        // Will fail without CAP_NET_ADMIN - this is expected
        match result {
            Ok(_) => {
                // Running with privileges
                assert_eq!(handler.stats_snapshot().replies_sent, 1);
            }
            Err(UdpError::ReplySocketError { addr, .. }) => {
                // Expected without CAP_NET_ADMIN
                assert_eq!(addr, original_dst);
            }
            Err(e) => {
                panic!("Unexpected error type: {e}");
            }
        }
    }

    #[tokio::test]
    async fn test_send_reply_local_address() {
        // Test with a local address (should work without CAP_NET_ADMIN)
        let _handler = UdpReplyHandler::new_default();

        // Create a UDP listener to verify we can send
        let listener = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let listener_addr = listener.local_addr().unwrap();

        // Bind handler socket to a local address
        let local_bind: SocketAddr = "127.0.0.1:0".parse().unwrap();

        // Create reply socket manually for local address (should succeed)
        let result = UdpReplyHandler::create_reply_socket(local_bind);

        match result {
            Ok(socket) => {
                // Send and verify
                let data = b"hello from reply";
                let n = socket.send_to(data, listener_addr).await.unwrap();
                assert_eq!(n, data.len());

                // Receive and verify
                let mut buf = [0u8; 64];
                let (n, from) = listener.recv_from(&mut buf).await.unwrap();
                assert_eq!(&buf[..n], data);
                assert_eq!(from.port(), socket.bound_addr.port());
            }
            Err(UdpError::ReplySocketError { reason, .. }) => {
                // IP_TRANSPARENT might still require privileges even for local
                // addresses on some systems
                assert!(reason.contains("IP_TRANSPARENT") || reason.contains("CAP_NET_ADMIN"));
            }
            Err(e) => {
                panic!("Unexpected error: {e}");
            }
        }
    }

    #[test]
    fn test_cache_operations() {
        let handler = UdpReplyHandler::new_default();
        assert_eq!(handler.cached_sockets(), 0);

        // Invalidate non-existent - should not panic
        let addr: SocketAddr = "1.2.3.4:53".parse().unwrap();
        handler.invalidate(&addr);

        // Clear empty cache - should not panic
        handler.clear_cache();
    }
}
