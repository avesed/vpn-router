//! UDP Session State Machine for the VLESS-WG Bridge Event Bus Architecture
//!
//! This module provides the UDP session tracking infrastructure for the shard-based
//! Event Bus architecture. Each UDP session maintains:
//!
//! - Session key (5-tuple) for identification
//! - smoltcp socket handle for packet routing
//! - Reply channel for sending responses back to the VLESS handler
//! - Throttled activity tracking for performance
//! - Statistics for monitoring
//!
//! # Throttled Activity Tracking
//!
//! To avoid the CPU overhead of updating timestamps on every packet, activity
//! tracking is throttled:
//!
//! - Timestamps are updated every 100 packets OR
//! - When at least 1 second has passed since the last update
//!
//! This optimization reduces atomic operations in the hot path while still
//! providing accurate enough timeout detection for UDP sessions.
//!
//! # DNS Fast Timeout
//!
//! DNS queries (destination port 53) use a shorter 10-second timeout instead
//! of the default 30-second timeout. This allows faster resource reclamation
//! for the typically short-lived DNS sessions.
//!
//! # Example
//!
//! ```ignore
//! use rust_router::vless_wg_bridge::{UdpSessionKey, UdpReply};
//! use rust_router::vless_wg_bridge::udp_session::ShardUdpSession;
//! use tokio::sync::mpsc;
//!
//! // Create reply channel
//! let (reply_tx, mut reply_rx) = mpsc::channel(32);
//!
//! // Create session key
//! let session_key = UdpSessionKey::from_parts(
//!     "10.200.200.2".parse().unwrap(),
//!     50000,
//!     "8.8.8.8".parse().unwrap(),
//!     53,
//! );
//!
//! // Create session (socket_handle would come from smoltcp)
//! let session = ShardUdpSession::new(session_key, socket_handle, reply_tx);
//!
//! // Check if DNS session
//! assert!(session.is_dns());
//! assert_eq!(session.timeout().as_secs(), 10);
//!
//! // Record activity (throttled)
//! session.touch();
//! session.record_sent(100);
//! session.record_received(200);
//!
//! // Check timeout
//! if session.is_expired() {
//!     // Clean up session
//! }
//! ```

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use smoltcp::iface::SocketHandle;
use tokio::sync::mpsc;

use super::events::{UdpReply, UdpSessionKey};

// =============================================================================
// Constants
// =============================================================================

/// Default UDP session timeout (30 seconds)
///
/// UDP sessions with no activity for this duration are considered expired.
/// This matches the value in `netbridge/config.rs`.
pub const UDP_DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// DNS UDP session timeout (10 seconds)
///
/// DNS queries should complete quickly, so we use a shorter timeout
/// to free up resources faster. This matches the value in `netbridge/config.rs`.
pub const UDP_DNS_TIMEOUT: Duration = Duration::from_secs(10);

/// Activity update interval (packet count)
///
/// Timestamps are updated every N packets to avoid CPU overhead from
/// frequent atomic operations.
pub const ACTIVITY_UPDATE_INTERVAL: u64 = 100;

/// Activity update interval (time)
///
/// If more than this duration has passed since the last update,
/// the timestamp will be updated regardless of packet count.
pub const ACTIVITY_UPDATE_TIME_SECS: u64 = 1;

// =============================================================================
// UDP Session Statistics
// =============================================================================

/// Statistics snapshot for a UDP session
///
/// This is a point-in-time snapshot of session statistics, suitable for
/// logging, monitoring, or returning via IPC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpSessionStats {
    /// Bytes sent through this session
    pub bytes_sent: u64,
    /// Bytes received through this session
    pub bytes_received: u64,
    /// Number of packets processed (for throttle tracking)
    pub packet_count: u64,
    /// Session age in seconds
    pub age_secs: u64,
    /// Idle duration in seconds
    pub idle_secs: u64,
    /// Whether this is a DNS session
    pub is_dns: bool,
}

impl UdpSessionStats {
    /// Get total bytes (sent + received)
    #[must_use]
    #[inline]
    pub fn total_bytes(&self) -> u64 {
        self.bytes_sent.saturating_add(self.bytes_received)
    }
}

impl std::fmt::Display for UdpSessionStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "sent={} recv={} packets={} age={}s idle={}s dns={}",
            self.bytes_sent,
            self.bytes_received,
            self.packet_count,
            self.age_secs,
            self.idle_secs,
            self.is_dns
        )
    }
}

// =============================================================================
// UDP Session
// =============================================================================

/// UDP session for the shard-based Event Bus architecture
///
/// This struct tracks a single UDP session within a smoltcp shard. Unlike TCP,
/// UDP is stateless, so the "state machine" is simply timeout-based cleanup.
///
/// # Thread Safety
///
/// All mutable fields use atomic types, making this struct safe to share
/// across tasks (though in the Event Bus architecture, sessions are typically
/// owned by a single shard task).
///
/// # Performance
///
/// Activity tracking is throttled to reduce CPU overhead:
/// - `touch()` only updates the timestamp every 100 packets or 1 second
/// - Statistics use `Relaxed` ordering for minimal overhead
pub struct ShardUdpSession {
    /// Session key (5-tuple)
    session_key: UdpSessionKey,

    /// smoltcp socket handle
    socket_handle: SocketHandle,

    /// Reply channel for sending responses back to VLESS handler
    reply_tx: mpsc::Sender<UdpReply>,

    /// Last activity timestamp (Unix timestamp in seconds)
    ///
    /// Using seconds since epoch allows atomic updates without locks.
    /// The precision loss (1 second) is acceptable for timeout detection.
    last_activity_secs: AtomicU64,

    /// Packet count (used for throttling activity updates)
    packet_count: AtomicU64,

    /// Creation time (for session age calculation)
    created_at: Instant,

    /// Bytes sent through this session
    bytes_sent: AtomicU64,

    /// Bytes received through this session
    bytes_received: AtomicU64,
}

impl ShardUdpSession {
    /// Create a new UDP session
    ///
    /// # Arguments
    ///
    /// * `session_key` - The 5-tuple identifying this session
    /// * `socket_handle` - The smoltcp socket handle for this session
    /// * `reply_tx` - Channel for sending replies back to the VLESS handler
    #[must_use]
    pub fn new(
        session_key: UdpSessionKey,
        socket_handle: SocketHandle,
        reply_tx: mpsc::Sender<UdpReply>,
    ) -> Self {
        let now_secs = current_time_secs();

        Self {
            session_key,
            socket_handle,
            reply_tx,
            last_activity_secs: AtomicU64::new(now_secs),
            packet_count: AtomicU64::new(0),
            created_at: Instant::now(),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
        }
    }

    // -------------------------------------------------------------------------
    // Accessors
    // -------------------------------------------------------------------------

    /// Get the session key (5-tuple)
    #[must_use]
    #[inline]
    pub fn session_key(&self) -> &UdpSessionKey {
        &self.session_key
    }

    /// Get the smoltcp socket handle
    #[must_use]
    #[inline]
    pub fn socket_handle(&self) -> SocketHandle {
        self.socket_handle
    }

    /// Get a reference to the reply channel sender
    #[must_use]
    #[inline]
    pub fn reply_tx(&self) -> &mpsc::Sender<UdpReply> {
        &self.reply_tx
    }

    /// Get the session creation time
    #[must_use]
    #[inline]
    pub fn created_at(&self) -> Instant {
        self.created_at
    }

    // -------------------------------------------------------------------------
    // Activity Tracking (Throttled)
    // -------------------------------------------------------------------------

    /// Record activity on this session (throttled)
    ///
    /// This method implements throttled timestamp updates to reduce CPU overhead.
    /// The timestamp is only updated when:
    /// - The packet count is a multiple of `ACTIVITY_UPDATE_INTERVAL` (100)
    /// - OR more than `ACTIVITY_UPDATE_TIME_SECS` (1 second) has passed
    ///
    /// This optimization reduces atomic operations in the hot path while still
    /// providing accurate enough timeout detection.
    #[inline]
    pub fn touch(&self) {
        let count = self.packet_count.fetch_add(1, Ordering::Relaxed);

        // Update every 100 packets
        if count % ACTIVITY_UPDATE_INTERVAL == 0 {
            self.update_activity_time();
            return;
        }

        // Or if more than 1 second has passed (checked less frequently)
        // Only check every 10 packets to avoid overhead
        if count % 10 == 0 {
            let now_secs = current_time_secs();
            let last = self.last_activity_secs.load(Ordering::Relaxed);
            if now_secs.saturating_sub(last) >= ACTIVITY_UPDATE_TIME_SECS {
                self.update_activity_time();
            }
        }
    }

    /// Force update the activity timestamp
    ///
    /// Unlike `touch()`, this always updates the timestamp without throttling.
    /// Use this when you need to ensure the timestamp is current (e.g., after
    /// receiving a reply).
    #[inline]
    pub fn update_activity_time(&self) {
        let now_secs = current_time_secs();
        self.last_activity_secs.store(now_secs, Ordering::Relaxed);
    }

    /// Record bytes sent and update activity
    #[inline]
    pub fn record_sent(&self, bytes: u64) {
        self.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
        self.touch();
    }

    /// Record bytes received and update activity
    #[inline]
    pub fn record_received(&self, bytes: u64) {
        self.bytes_received.fetch_add(bytes, Ordering::Relaxed);
        // Force update on receive since replies are less frequent
        self.update_activity_time();
    }

    // -------------------------------------------------------------------------
    // Timeout Checking
    // -------------------------------------------------------------------------

    /// Check if this is a DNS session (destination port 53)
    #[must_use]
    #[inline]
    pub fn is_dns(&self) -> bool {
        self.session_key.is_dns()
    }

    /// Get the timeout duration for this session
    ///
    /// Returns `UDP_DNS_TIMEOUT` (10s) for DNS sessions,
    /// `UDP_DEFAULT_TIMEOUT` (30s) for all others.
    #[must_use]
    #[inline]
    pub fn timeout(&self) -> Duration {
        if self.is_dns() {
            UDP_DNS_TIMEOUT
        } else {
            UDP_DEFAULT_TIMEOUT
        }
    }

    /// Get the idle duration (time since last activity)
    #[must_use]
    pub fn idle_duration(&self) -> Duration {
        let last = self.last_activity_secs.load(Ordering::Relaxed);
        let now = current_time_secs();
        Duration::from_secs(now.saturating_sub(last))
    }

    /// Check if this session has expired
    ///
    /// Uses the appropriate timeout based on whether this is a DNS session.
    #[must_use]
    #[inline]
    pub fn is_expired(&self) -> bool {
        self.is_expired_with_timeout(self.timeout())
    }

    /// Check if this session has expired with a custom timeout
    #[must_use]
    pub fn is_expired_with_timeout(&self, timeout: Duration) -> bool {
        self.idle_duration() >= timeout
    }

    /// Get the remaining time before this session expires
    ///
    /// Returns `Duration::ZERO` if already expired.
    #[must_use]
    pub fn time_until_expiry(&self) -> Duration {
        let timeout = self.timeout();
        let idle = self.idle_duration();
        timeout.saturating_sub(idle)
    }

    // -------------------------------------------------------------------------
    // Reply Handling
    // -------------------------------------------------------------------------

    /// Send a reply back to the VLESS handler
    ///
    /// This is a convenience method that sends a `UdpReply` through the
    /// session's reply channel.
    ///
    /// # Errors
    ///
    /// Returns `SendError` if the receiver has been dropped (VLESS connection closed).
    pub async fn send_reply(&self, reply: UdpReply) -> Result<(), mpsc::error::SendError<UdpReply>> {
        self.reply_tx.send(reply).await
    }

    /// Try to send a reply without blocking
    ///
    /// This is useful in synchronous contexts where blocking is not allowed.
    ///
    /// # Errors
    ///
    /// Returns `TrySendError` if the channel is full or the receiver has been dropped.
    pub fn try_send_reply(
        &self,
        reply: UdpReply,
    ) -> Result<(), mpsc::error::TrySendError<UdpReply>> {
        self.reply_tx.try_send(reply)
    }

    /// Check if the reply channel is closed
    ///
    /// Returns `true` if the VLESS handler has dropped the receiver.
    #[must_use]
    pub fn is_reply_channel_closed(&self) -> bool {
        self.reply_tx.is_closed()
    }

    // -------------------------------------------------------------------------
    // Statistics
    // -------------------------------------------------------------------------

    /// Get a snapshot of session statistics
    #[must_use]
    pub fn stats(&self) -> UdpSessionStats {
        UdpSessionStats {
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
            packet_count: self.packet_count.load(Ordering::Relaxed),
            age_secs: self.created_at.elapsed().as_secs(),
            idle_secs: self.idle_duration().as_secs(),
            is_dns: self.is_dns(),
        }
    }

    /// Get the total bytes sent
    #[must_use]
    #[inline]
    pub fn total_bytes_sent(&self) -> u64 {
        self.bytes_sent.load(Ordering::Relaxed)
    }

    /// Get the total bytes received
    #[must_use]
    #[inline]
    pub fn total_bytes_received(&self) -> u64 {
        self.bytes_received.load(Ordering::Relaxed)
    }

    /// Get the packet count
    #[must_use]
    #[inline]
    pub fn total_packets(&self) -> u64 {
        self.packet_count.load(Ordering::Relaxed)
    }

    /// Get the session age
    #[must_use]
    #[inline]
    pub fn age(&self) -> Duration {
        self.created_at.elapsed()
    }
}

impl std::fmt::Debug for ShardUdpSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShardUdpSession")
            .field("session_key", &self.session_key)
            .field("socket_handle", &self.socket_handle)
            .field("bytes_sent", &self.bytes_sent.load(Ordering::Relaxed))
            .field("bytes_received", &self.bytes_received.load(Ordering::Relaxed))
            .field("packet_count", &self.packet_count.load(Ordering::Relaxed))
            .field("idle_secs", &self.idle_duration().as_secs())
            .field("is_dns", &self.is_dns())
            .field("reply_channel_closed", &self.is_reply_channel_closed())
            .finish()
    }
}

impl std::fmt::Display for ShardUdpSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "UdpSession({}, idle={}s, {})",
            self.session_key,
            self.idle_duration().as_secs(),
            if self.is_dns() { "DNS" } else { "UDP" }
        )
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Get the current time as seconds since Unix epoch
///
/// This is used for atomic timestamp storage. Falls back to 0 on error
/// (which would cause immediate expiry, a safe failure mode).
#[inline]
fn current_time_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vless_wg_bridge::events::DNS_PORT;
    use bytes::Bytes;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    // Helper to create a mock socket handle
    fn mock_socket_handle(id: usize) -> SocketHandle {
        unsafe { std::mem::transmute(id) }
    }

    // Helper to create a DNS session key
    fn dns_session_key() -> UdpSessionKey {
        UdpSessionKey::from_parts(
            IpAddr::V4(Ipv4Addr::new(10, 200, 200, 2)),
            50000,
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            DNS_PORT,
        )
    }

    // Helper to create a non-DNS session key
    fn regular_session_key() -> UdpSessionKey {
        UdpSessionKey::from_parts(
            IpAddr::V4(Ipv4Addr::new(10, 200, 200, 2)),
            50000,
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            443,
        )
    }

    // -------------------------------------------------------------------------
    // Basic Session Tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_session_creation() {
        let (tx, _rx) = mpsc::channel(32);
        let key = dns_session_key();
        let handle = mock_socket_handle(1);

        let session = ShardUdpSession::new(key.clone(), handle, tx);

        assert_eq!(session.session_key(), &key);
        assert_eq!(session.socket_handle(), handle);
        assert!(session.is_dns());
    }

    #[test]
    fn test_dns_vs_regular_timeout() {
        let (tx1, _rx1) = mpsc::channel(32);
        let (tx2, _rx2) = mpsc::channel(32);

        let dns_session = ShardUdpSession::new(dns_session_key(), mock_socket_handle(1), tx1);

        let regular_session =
            ShardUdpSession::new(regular_session_key(), mock_socket_handle(2), tx2);

        assert!(dns_session.is_dns());
        assert!(!regular_session.is_dns());

        assert_eq!(dns_session.timeout(), UDP_DNS_TIMEOUT);
        assert_eq!(regular_session.timeout(), UDP_DEFAULT_TIMEOUT);

        assert_eq!(dns_session.timeout().as_secs(), 10);
        assert_eq!(regular_session.timeout().as_secs(), 30);
    }

    // -------------------------------------------------------------------------
    // Activity Tracking Tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_touch_increments_packet_count() {
        let (tx, _rx) = mpsc::channel(32);
        let session = ShardUdpSession::new(dns_session_key(), mock_socket_handle(1), tx);

        assert_eq!(session.total_packets(), 0);

        session.touch();
        assert_eq!(session.total_packets(), 1);

        session.touch();
        session.touch();
        assert_eq!(session.total_packets(), 3);
    }

    #[test]
    fn test_touch_throttling() {
        let (tx, _rx) = mpsc::channel(32);
        let session = ShardUdpSession::new(dns_session_key(), mock_socket_handle(1), tx);

        let initial_time = session.last_activity_secs.load(Ordering::Relaxed);

        // Touch many times - timestamp should only update on 100th packet
        for i in 0..99 {
            session.touch();
            // Before 100th packet (and assuming less than 1 second elapsed),
            // timestamp might not change (depending on timing)
            let _ = i;
        }

        // 100th touch should definitely update
        session.touch();

        // Packet count should be 100
        assert_eq!(session.total_packets(), 100);

        // Timestamp should be >= initial (it was updated at least once)
        let current_time = session.last_activity_secs.load(Ordering::Relaxed);
        assert!(current_time >= initial_time);
    }

    #[test]
    fn test_record_sent() {
        let (tx, _rx) = mpsc::channel(32);
        let session = ShardUdpSession::new(dns_session_key(), mock_socket_handle(1), tx);

        assert_eq!(session.total_bytes_sent(), 0);

        session.record_sent(100);
        assert_eq!(session.total_bytes_sent(), 100);

        session.record_sent(50);
        assert_eq!(session.total_bytes_sent(), 150);

        // Should also increment packet count
        assert_eq!(session.total_packets(), 2);
    }

    #[test]
    fn test_record_received() {
        let (tx, _rx) = mpsc::channel(32);
        let session = ShardUdpSession::new(dns_session_key(), mock_socket_handle(1), tx);

        assert_eq!(session.total_bytes_received(), 0);

        session.record_received(200);
        assert_eq!(session.total_bytes_received(), 200);

        session.record_received(100);
        assert_eq!(session.total_bytes_received(), 300);

        // Note: record_received doesn't increment packet_count via touch(),
        // it uses update_activity_time() directly
    }

    // -------------------------------------------------------------------------
    // Timeout Tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_idle_duration_initially_zero() {
        let (tx, _rx) = mpsc::channel(32);
        let session = ShardUdpSession::new(dns_session_key(), mock_socket_handle(1), tx);

        // Should be 0 or very small (depending on timing)
        assert!(session.idle_duration().as_secs() <= 1);
    }

    #[test]
    fn test_not_expired_initially() {
        let (tx, _rx) = mpsc::channel(32);
        let session = ShardUdpSession::new(dns_session_key(), mock_socket_handle(1), tx);

        assert!(!session.is_expired());
    }

    #[test]
    fn test_time_until_expiry() {
        let (tx, _rx) = mpsc::channel(32);
        let session = ShardUdpSession::new(dns_session_key(), mock_socket_handle(1), tx);

        let time_left = session.time_until_expiry();

        // Should be close to full timeout (10s for DNS)
        assert!(time_left.as_secs() >= 9);
        assert!(time_left.as_secs() <= 10);
    }

    #[test]
    fn test_is_expired_with_custom_timeout() {
        let (tx, _rx) = mpsc::channel(32);
        let session = ShardUdpSession::new(dns_session_key(), mock_socket_handle(1), tx);

        // Not expired with normal timeout
        assert!(!session.is_expired_with_timeout(Duration::from_secs(30)));

        // Would be expired with zero timeout
        assert!(session.is_expired_with_timeout(Duration::ZERO));
    }

    // -------------------------------------------------------------------------
    // Statistics Tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_stats_snapshot() {
        let (tx, _rx) = mpsc::channel(32);
        let session = ShardUdpSession::new(dns_session_key(), mock_socket_handle(1), tx);

        session.record_sent(100);
        session.record_received(200);
        session.touch();

        let stats = session.stats();

        assert_eq!(stats.bytes_sent, 100);
        assert_eq!(stats.bytes_received, 200);
        assert_eq!(stats.total_bytes(), 300);
        assert!(stats.is_dns);
        assert!(stats.idle_secs <= 1);
        assert!(stats.age_secs <= 1);
    }

    #[test]
    fn test_stats_display() {
        let stats = UdpSessionStats {
            bytes_sent: 100,
            bytes_received: 200,
            packet_count: 5,
            age_secs: 10,
            idle_secs: 2,
            is_dns: true,
        };

        let display = format!("{}", stats);
        assert!(display.contains("sent=100"));
        assert!(display.contains("recv=200"));
        assert!(display.contains("packets=5"));
        assert!(display.contains("dns=true"));
    }

    #[test]
    fn test_session_age() {
        let (tx, _rx) = mpsc::channel(32);
        let session = ShardUdpSession::new(dns_session_key(), mock_socket_handle(1), tx);

        // Age should be very small initially
        assert!(session.age().as_millis() < 100);
    }

    // -------------------------------------------------------------------------
    // Reply Channel Tests
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn test_send_reply() {
        let (tx, mut rx) = mpsc::channel(32);
        let session = ShardUdpSession::new(dns_session_key(), mock_socket_handle(1), tx);

        let source: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let reply = UdpReply::new(source, Bytes::from_static(b"DNS response"));

        session.send_reply(reply).await.expect("should send");

        let received = rx.recv().await.expect("should receive");
        assert_eq!(received.source, source);
        assert_eq!(received.data.as_ref(), b"DNS response");
    }

    #[test]
    fn test_try_send_reply() {
        let (tx, mut rx) = mpsc::channel(1); // Small buffer
        let session = ShardUdpSession::new(dns_session_key(), mock_socket_handle(1), tx);

        let source: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let reply = UdpReply::new(source, Bytes::from_static(b"DNS response"));

        // First send should succeed
        session.try_send_reply(reply).expect("should send");

        // Verify it was received
        let received = rx.try_recv().expect("should receive");
        assert_eq!(received.source, source);
    }

    #[test]
    fn test_reply_channel_closed() {
        let (tx, rx) = mpsc::channel(32);
        let session = ShardUdpSession::new(dns_session_key(), mock_socket_handle(1), tx);

        assert!(!session.is_reply_channel_closed());

        // Drop the receiver
        drop(rx);

        assert!(session.is_reply_channel_closed());
    }

    // -------------------------------------------------------------------------
    // Debug/Display Tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_debug_impl() {
        let (tx, _rx) = mpsc::channel(32);
        let session = ShardUdpSession::new(dns_session_key(), mock_socket_handle(1), tx);

        let debug = format!("{:?}", session);
        assert!(debug.contains("ShardUdpSession"));
        assert!(debug.contains("session_key"));
        assert!(debug.contains("is_dns"));
    }

    #[test]
    fn test_display_impl() {
        let (tx, _rx) = mpsc::channel(32);
        let dns_session = ShardUdpSession::new(dns_session_key(), mock_socket_handle(1), tx);

        let display = format!("{}", dns_session);
        assert!(display.contains("UdpSession"));
        assert!(display.contains("DNS"));

        let (tx2, _rx2) = mpsc::channel(32);
        let regular_session =
            ShardUdpSession::new(regular_session_key(), mock_socket_handle(2), tx2);

        let display = format!("{}", regular_session);
        assert!(display.contains("UDP"));
        assert!(!display.contains("DNS"));
    }

    // -------------------------------------------------------------------------
    // Edge Cases
    // -------------------------------------------------------------------------

    #[test]
    fn test_concurrent_updates() {
        use std::sync::Arc;
        use std::thread;

        let (tx, _rx) = mpsc::channel(1024);
        let session = Arc::new(ShardUdpSession::new(
            dns_session_key(),
            mock_socket_handle(1),
            tx,
        ));

        let handles: Vec<_> = (0..4)
            .map(|_| {
                let session = Arc::clone(&session);
                thread::spawn(move || {
                    for _ in 0..1000 {
                        session.touch();
                        session.record_sent(10);
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }

        // 4 threads * 1000 iterations * (1 touch + 1 record_sent which also calls touch)
        assert_eq!(session.total_packets(), 4 * 1000 * 2);
        assert_eq!(session.total_bytes_sent(), 4 * 1000 * 10);
    }

    #[test]
    fn test_stats_total_bytes_overflow_safety() {
        let stats = UdpSessionStats {
            bytes_sent: u64::MAX,
            bytes_received: 1,
            packet_count: 0,
            age_secs: 0,
            idle_secs: 0,
            is_dns: false,
        };

        // Should use saturating_add to prevent overflow
        assert_eq!(stats.total_bytes(), u64::MAX);
    }
}
