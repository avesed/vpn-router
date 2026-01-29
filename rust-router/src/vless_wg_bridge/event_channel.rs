//! Priority-aware event channel for the VLESS-WG Bridge
//!
//! This module implements a dual-channel architecture that provides priority-based
//! event processing for the smoltcp shard. High-priority events (WireGuard packets,
//! DNS) are processed before lower-priority events (TCP, cleanup).
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────────┐
//! │  Public API (multiple senders)                                              │
//! │                                                                             │
//! │  ┌─────────────┐   ┌─────────────┐   ┌─────────────┐                       │
//! │  │ TCP Handler │   │ UDP Handler │   │ WG Egress   │                       │
//! │  └──────┬──────┘   └──────┬──────┘   └──────┬──────┘                       │
//! │         │                 │                 │                               │
//! │         └────────────────┬┴─────────────────┘                               │
//! │                          │                                                  │
//! │                          ▼                                                  │
//! │                   ┌─────────────┐                                           │
//! │                   │ EventSender │ (Clone-able, routes by priority)          │
//! │                   └──────┬──────┘                                           │
//! │                          │                                                  │
//! │         ┌────────────────┴────────────────┐                                 │
//! │         ▼                                 ▼                                 │
//! │  ┌─────────────────┐            ┌─────────────────┐                        │
//! │  │ High Priority   │            │ Normal Priority │                        │
//! │  │ Channel (256)   │            │ Channel (1024)  │                        │
//! │  │ - WgPacket      │            │ - TcpConnect    │                        │
//! │  │ - UdpDns        │            │ - TcpData       │                        │
//! │  └────────┬────────┘            │ - UdpSend       │                        │
//! │           │                     │ - Cleanup       │                        │
//! │           │                     │ - Shutdown      │                        │
//! │           │                     └────────┬────────┘                        │
//! │           │                              │                                 │
//! │           └──────────────┬───────────────┘                                 │
//! │                          ▼                                                  │
//! │                   ┌──────────────┐                                          │
//! │                   │EventReceiver │ (biased select!, high priority first)    │
//! │                   └──────┬───────┘                                          │
//! │                          │                                                  │
//! │                          ▼                                                  │
//! │                   ┌─────────────┐                                           │
//! │                   │SmoltcpShard │                                           │
//! │                   └─────────────┘                                           │
//! └─────────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Backpressure Strategy
//!
//! - **High priority channel full**: Return `SendError::HighPriorityFull` (should not happen)
//! - **Normal priority channel full**: `try_send` returns `TrySendError::Full`, `send` blocks
//! - **Both channels full**: Events are dropped with statistics tracking
//!
//! # Example
//!
//! ```ignore
//! use rust_router::vless_wg_bridge::event_channel::{create_event_channel, EventChannelConfig};
//! use rust_router::vless_wg_bridge::events::BridgeEvent;
//! use bytes::Bytes;
//!
//! // Create channel with default config
//! let (sender, mut receiver) = create_event_channel(EventChannelConfig::default());
//!
//! // Clone sender for multiple producers
//! let sender2 = sender.clone();
//!
//! // Send high-priority WG packet
//! sender.try_send(BridgeEvent::wg_packet(Bytes::from_static(b"packet"))).unwrap();
//!
//! // Receive with priority ordering
//! let event = receiver.recv().await;
//! ```

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;

use super::events::{BridgeEvent, EventPriority};

// =============================================================================
// Configuration Constants
// =============================================================================

/// High priority channel capacity
///
/// Increased from 256 to 512 for better WG packet burst handling.
/// If this fills up consistently, consider adding more shards.
pub const HIGH_PRIORITY_CHANNEL_SIZE: usize = 512;

/// Normal priority channel capacity
///
/// Increased from 1024 to 2048 for better throughput under load.
/// TCP and UDP events can tolerate some queuing.
pub const NORMAL_PRIORITY_CHANNEL_SIZE: usize = 2048;

/// Default send timeout for blocking sends
pub const DEFAULT_SEND_TIMEOUT_MS: u64 = 5000;

// =============================================================================
// Error Types
// =============================================================================

/// Error returned when sending an event fails
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendError {
    /// High priority channel is full (should not happen in normal operation)
    HighPriorityFull,
    /// Normal priority channel is full
    NormalPriorityFull,
    /// Channel is closed (receiver dropped)
    Closed,
    /// Send timed out
    Timeout,
}

impl std::fmt::Display for SendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HighPriorityFull => write!(f, "high priority channel full"),
            Self::NormalPriorityFull => write!(f, "normal priority channel full"),
            Self::Closed => write!(f, "channel closed"),
            Self::Timeout => write!(f, "send timed out"),
        }
    }
}

impl std::error::Error for SendError {}

/// Error returned when try_send fails
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrySendError {
    /// Channel is full (would block)
    Full(EventPriority),
    /// Channel is closed (receiver dropped)
    Closed,
}

impl std::fmt::Display for TrySendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Full(priority) => write!(f, "channel full for priority {:?}", priority),
            Self::Closed => write!(f, "channel closed"),
        }
    }
}

impl std::error::Error for TrySendError {}

// =============================================================================
// Configuration
// =============================================================================

/// Configuration for the event channel
#[derive(Debug, Clone)]
pub struct EventChannelConfig {
    /// Capacity of the high priority channel
    pub high_priority_capacity: usize,
    /// Capacity of the normal priority channel
    pub normal_priority_capacity: usize,
    /// Timeout for blocking sends (None = wait forever)
    pub send_timeout: Option<Duration>,
}

impl Default for EventChannelConfig {
    fn default() -> Self {
        Self {
            high_priority_capacity: HIGH_PRIORITY_CHANNEL_SIZE,
            normal_priority_capacity: NORMAL_PRIORITY_CHANNEL_SIZE,
            send_timeout: Some(Duration::from_millis(DEFAULT_SEND_TIMEOUT_MS)),
        }
    }
}

impl EventChannelConfig {
    /// Create a new configuration with custom capacities
    #[must_use]
    pub fn new(high_priority_capacity: usize, normal_priority_capacity: usize) -> Self {
        Self {
            high_priority_capacity,
            normal_priority_capacity,
            send_timeout: Some(Duration::from_millis(DEFAULT_SEND_TIMEOUT_MS)),
        }
    }

    /// Set the send timeout
    #[must_use]
    pub fn with_send_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.send_timeout = timeout;
        self
    }

    /// Create a configuration for testing with smaller buffers
    #[cfg(test)]
    #[must_use]
    pub fn for_test() -> Self {
        Self {
            high_priority_capacity: 8,
            normal_priority_capacity: 16,
            send_timeout: Some(Duration::from_millis(100)),
        }
    }
}

// =============================================================================
// Statistics
// =============================================================================

/// Statistics for the event channel
#[derive(Debug, Default)]
pub struct EventChannelStatsInner {
    /// Total events sent successfully
    pub sent_total: AtomicU64,
    /// High priority events sent
    pub sent_high_priority: AtomicU64,
    /// Normal priority events sent
    pub sent_normal_priority: AtomicU64,
    /// Events dropped due to full channel
    pub dropped_full: AtomicU64,
    /// Events dropped due to closed channel
    pub dropped_closed: AtomicU64,
    /// Events dropped due to timeout
    pub dropped_timeout: AtomicU64,
    /// Events received
    pub received_total: AtomicU64,
    /// High priority events received
    pub received_high_priority: AtomicU64,
    /// Normal priority events received
    pub received_normal_priority: AtomicU64,
}

/// Snapshot of event channel statistics
#[derive(Debug, Clone, Default)]
pub struct EventChannelStats {
    /// Total events sent successfully
    pub sent_total: u64,
    /// High priority events sent
    pub sent_high_priority: u64,
    /// Normal priority events sent
    pub sent_normal_priority: u64,
    /// Events dropped due to full channel
    pub dropped_full: u64,
    /// Events dropped due to closed channel
    pub dropped_closed: u64,
    /// Events dropped due to timeout
    pub dropped_timeout: u64,
    /// Events received
    pub received_total: u64,
    /// High priority events received
    pub received_high_priority: u64,
    /// Normal priority events received
    pub received_normal_priority: u64,
}

impl EventChannelStatsInner {
    /// Take a snapshot of the current statistics
    #[must_use]
    pub fn snapshot(&self) -> EventChannelStats {
        EventChannelStats {
            sent_total: self.sent_total.load(Ordering::Relaxed),
            sent_high_priority: self.sent_high_priority.load(Ordering::Relaxed),
            sent_normal_priority: self.sent_normal_priority.load(Ordering::Relaxed),
            dropped_full: self.dropped_full.load(Ordering::Relaxed),
            dropped_closed: self.dropped_closed.load(Ordering::Relaxed),
            dropped_timeout: self.dropped_timeout.load(Ordering::Relaxed),
            received_total: self.received_total.load(Ordering::Relaxed),
            received_high_priority: self.received_high_priority.load(Ordering::Relaxed),
            received_normal_priority: self.received_normal_priority.load(Ordering::Relaxed),
        }
    }

    /// Record a successful send
    fn record_send(&self, is_high_priority: bool) {
        self.sent_total.fetch_add(1, Ordering::Relaxed);
        if is_high_priority {
            self.sent_high_priority.fetch_add(1, Ordering::Relaxed);
        } else {
            self.sent_normal_priority.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Record a dropped event
    fn record_drop(&self, reason: DropReason) {
        match reason {
            DropReason::Full => self.dropped_full.fetch_add(1, Ordering::Relaxed),
            DropReason::Closed => self.dropped_closed.fetch_add(1, Ordering::Relaxed),
            DropReason::Timeout => self.dropped_timeout.fetch_add(1, Ordering::Relaxed),
        };
    }

    /// Record a successful receive
    fn record_recv(&self, is_high_priority: bool) {
        self.received_total.fetch_add(1, Ordering::Relaxed);
        if is_high_priority {
            self.received_high_priority.fetch_add(1, Ordering::Relaxed);
        } else {
            self.received_normal_priority
                .fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Reason for dropping an event
#[derive(Debug, Clone, Copy)]
enum DropReason {
    Full,
    Closed,
    Timeout,
}

// =============================================================================
// Event Sender
// =============================================================================

/// Sender end of the event channel
///
/// This type is `Clone` and can be shared among multiple producers.
/// Events are automatically routed to the appropriate priority channel
/// based on their `EventPriority`.
#[derive(Clone)]
pub struct EventSender {
    /// High priority channel sender
    high_priority_tx: mpsc::Sender<BridgeEvent>,
    /// Normal priority channel sender
    normal_priority_tx: mpsc::Sender<BridgeEvent>,
    /// Shared statistics
    stats: Arc<EventChannelStatsInner>,
    /// Send timeout
    send_timeout: Option<Duration>,
}

impl EventSender {
    /// Send an event, blocking if the channel is full
    ///
    /// The event is automatically routed to the high or normal priority
    /// channel based on its priority level.
    ///
    /// # Errors
    ///
    /// Returns `SendError::Closed` if the receiver has been dropped.
    /// Returns `SendError::Timeout` if the send times out (when configured).
    pub async fn send(&self, event: BridgeEvent) -> Result<(), SendError> {
        let is_high = event.is_high_priority();

        let result = if is_high {
            self.send_high_priority(event).await
        } else {
            self.send_normal_priority(event).await
        };

        match &result {
            Ok(()) => self.stats.record_send(is_high),
            Err(SendError::Closed) => self.stats.record_drop(DropReason::Closed),
            Err(SendError::Timeout) => self.stats.record_drop(DropReason::Timeout),
            Err(SendError::HighPriorityFull | SendError::NormalPriorityFull) => {
                self.stats.record_drop(DropReason::Full);
            }
        }

        result
    }

    /// Try to send an event without blocking
    ///
    /// # Errors
    ///
    /// Returns `TrySendError::Full` if the appropriate channel is full.
    /// Returns `TrySendError::Closed` if the receiver has been dropped.
    pub fn try_send(&self, event: BridgeEvent) -> Result<(), TrySendError> {
        let is_high = event.is_high_priority();
        let priority = event.priority();

        let result = if is_high {
            self.high_priority_tx.try_send(event).map_err(|e| match e {
                mpsc::error::TrySendError::Full(_) => TrySendError::Full(priority),
                mpsc::error::TrySendError::Closed(_) => TrySendError::Closed,
            })
        } else {
            self.normal_priority_tx
                .try_send(event)
                .map_err(|e| match e {
                    mpsc::error::TrySendError::Full(_) => TrySendError::Full(priority),
                    mpsc::error::TrySendError::Closed(_) => TrySendError::Closed,
                })
        };

        match &result {
            Ok(()) => self.stats.record_send(is_high),
            Err(TrySendError::Full(_)) => self.stats.record_drop(DropReason::Full),
            Err(TrySendError::Closed) => self.stats.record_drop(DropReason::Closed),
        }

        result
    }

    /// Send to high priority channel with timeout
    async fn send_high_priority(&self, event: BridgeEvent) -> Result<(), SendError> {
        match self.send_timeout {
            Some(timeout) => {
                match tokio::time::timeout(timeout, self.high_priority_tx.send(event)).await {
                    Ok(Ok(())) => Ok(()),
                    Ok(Err(_)) => Err(SendError::Closed),
                    Err(_) => Err(SendError::Timeout),
                }
            }
            None => self
                .high_priority_tx
                .send(event)
                .await
                .map_err(|_| SendError::Closed),
        }
    }

    /// Send to normal priority channel with timeout
    async fn send_normal_priority(&self, event: BridgeEvent) -> Result<(), SendError> {
        match self.send_timeout {
            Some(timeout) => {
                match tokio::time::timeout(timeout, self.normal_priority_tx.send(event)).await {
                    Ok(Ok(())) => Ok(()),
                    Ok(Err(_)) => Err(SendError::Closed),
                    Err(_) => Err(SendError::Timeout),
                }
            }
            None => self
                .normal_priority_tx
                .send(event)
                .await
                .map_err(|_| SendError::Closed),
        }
    }

    /// Get a snapshot of the current statistics
    #[must_use]
    pub fn stats(&self) -> EventChannelStats {
        self.stats.snapshot()
    }

    /// Check if the channel is closed
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.high_priority_tx.is_closed() || self.normal_priority_tx.is_closed()
    }

    /// Get the capacity of the high priority channel
    #[must_use]
    pub fn high_priority_capacity(&self) -> usize {
        self.high_priority_tx.capacity()
    }

    /// Get the capacity of the normal priority channel
    #[must_use]
    pub fn normal_priority_capacity(&self) -> usize {
        self.normal_priority_tx.capacity()
    }
}

impl std::fmt::Debug for EventSender {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventSender")
            .field("high_priority_capacity", &self.high_priority_capacity())
            .field("normal_priority_capacity", &self.normal_priority_capacity())
            .field("is_closed", &self.is_closed())
            .finish()
    }
}

// =============================================================================
// Event Receiver
// =============================================================================

/// Receiver end of the event channel
///
/// This type is NOT `Clone` and should be owned by a single shard task.
/// Events are received in priority order: high priority events are always
/// processed before normal priority events.
pub struct EventReceiver {
    /// High priority channel receiver
    high_priority_rx: mpsc::Receiver<BridgeEvent>,
    /// Normal priority channel receiver
    normal_priority_rx: mpsc::Receiver<BridgeEvent>,
    /// Shared statistics
    stats: Arc<EventChannelStatsInner>,
}

impl EventReceiver {
    /// Receive the next event in priority order
    ///
    /// High priority events are always returned before normal priority events
    /// when both are available. This uses a biased `select!` to ensure
    /// priority ordering.
    ///
    /// Returns `None` when all senders have been dropped.
    pub async fn recv(&mut self) -> Option<BridgeEvent> {
        // Use biased select! to prioritize high priority channel
        tokio::select! {
            biased;

            // Check high priority first
            Some(event) = self.high_priority_rx.recv() => {
                self.stats.record_recv(true);
                Some(event)
            }

            // Then normal priority
            Some(event) = self.normal_priority_rx.recv() => {
                self.stats.record_recv(false);
                Some(event)
            }

            // Both channels closed
            else => None
        }
    }

    /// Try to receive an event without blocking
    ///
    /// Checks high priority channel first, then normal priority.
    /// Returns `None` if no events are available.
    pub fn try_recv(&mut self) -> Option<BridgeEvent> {
        // Check high priority first
        if let Ok(event) = self.high_priority_rx.try_recv() {
            self.stats.record_recv(true);
            return Some(event);
        }

        // Then normal priority
        if let Ok(event) = self.normal_priority_rx.try_recv() {
            self.stats.record_recv(false);
            return Some(event);
        }

        None
    }

    /// Receive with timeout
    ///
    /// Returns `None` if no event is received within the timeout.
    pub async fn recv_timeout(&mut self, timeout: Duration) -> Option<BridgeEvent> {
        tokio::time::timeout(timeout, self.recv()).await.ok()?
    }

    /// Get a snapshot of the current statistics
    #[must_use]
    pub fn stats(&self) -> EventChannelStats {
        self.stats.snapshot()
    }

    /// Check if there are pending high priority events
    ///
    /// Note: This is a hint and may not be accurate due to concurrent access.
    #[must_use]
    pub fn has_high_priority_pending(&self) -> bool {
        // Check if the channel is not empty by attempting a non-blocking peek
        // Unfortunately, tokio mpsc doesn't have a peek or len method,
        // so we use try_recv on a clone... but we can't clone the receiver.
        // Instead, we'll just return false as a conservative estimate.
        // The biased select! in recv() handles priority correctly anyway.
        false
    }
}

impl std::fmt::Debug for EventReceiver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventReceiver")
            .field("stats", &self.stats.snapshot())
            .finish()
    }
}

// =============================================================================
// Factory Function
// =============================================================================

/// Create a new event channel with the given configuration
///
/// Returns a sender/receiver pair. The sender can be cloned for multiple
/// producers, while the receiver should be owned by a single shard task.
///
/// # Example
///
/// ```ignore
/// let config = EventChannelConfig::default();
/// let (sender, receiver) = create_event_channel(config);
///
/// // Clone sender for multiple producers
/// let sender2 = sender.clone();
/// let sender3 = sender.clone();
///
/// // Receiver is owned by shard
/// tokio::spawn(async move {
///     while let Some(event) = receiver.recv().await {
///         // Process event
///     }
/// });
/// ```
#[must_use]
pub fn create_event_channel(config: EventChannelConfig) -> (EventSender, EventReceiver) {
    let (high_priority_tx, high_priority_rx) = mpsc::channel(config.high_priority_capacity);
    let (normal_priority_tx, normal_priority_rx) = mpsc::channel(config.normal_priority_capacity);

    let stats = Arc::new(EventChannelStatsInner::default());

    let sender = EventSender {
        high_priority_tx,
        normal_priority_tx,
        stats: Arc::clone(&stats),
        send_timeout: config.send_timeout,
    };

    let receiver = EventReceiver {
        high_priority_rx,
        normal_priority_rx,
        stats,
    };

    (sender, receiver)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use tokio::sync::mpsc as tokio_mpsc;

    use crate::vless_wg_bridge::events::{TcpReply, UdpSessionKey};

    // Helper to create a test config
    fn test_config() -> EventChannelConfig {
        EventChannelConfig::for_test()
    }

    // Helper to create a WG packet event (high priority)
    fn wg_packet_event() -> BridgeEvent {
        BridgeEvent::wg_packet(Bytes::from_static(b"test packet"))
    }

    // Helper to create a DNS UDP event (high priority)
    fn dns_udp_event() -> BridgeEvent {
        let session_key = UdpSessionKey::from_parts(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            5000,
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            53, // DNS port
        );
        BridgeEvent::udp_send(
            session_key,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
            Bytes::from_static(b"dns query"),
            None,
        )
    }

    // Helper to create a TCP event (normal priority)
    fn tcp_connect_event(conn_id: u64) -> BridgeEvent {
        let (tx, _rx) = tokio_mpsc::channel::<TcpReply>(1);
        BridgeEvent::tcp_connect(
            conn_id,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 80),
            tx,
        )
    }

    // Helper to create a UDP event (normal priority)
    fn udp_send_event() -> BridgeEvent {
        let session_key = UdpSessionKey::from_parts(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            5000,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            8080, // Non-DNS port
        );
        BridgeEvent::udp_send(
            session_key,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 8080),
            Bytes::from_static(b"udp data"),
            None,
        )
    }

    // -------------------------------------------------------------------------
    // Basic functionality tests
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn test_create_channel() {
        let (sender, _receiver) = create_event_channel(test_config());
        assert!(!sender.is_closed());
        assert_eq!(sender.high_priority_capacity(), 8);
        assert_eq!(sender.normal_priority_capacity(), 16);
    }

    #[tokio::test]
    async fn test_send_recv_wg_packet() {
        let (sender, mut receiver) = create_event_channel(test_config());

        sender.try_send(wg_packet_event()).unwrap();

        let event = receiver.try_recv().unwrap();
        assert!(matches!(event, BridgeEvent::WgPacket { .. }));
    }

    #[tokio::test]
    async fn test_send_recv_tcp_connect() {
        let (sender, mut receiver) = create_event_channel(test_config());

        sender.try_send(tcp_connect_event(1)).unwrap();

        let event = receiver.try_recv().unwrap();
        assert!(matches!(event, BridgeEvent::TcpConnect { conn_id: 1, .. }));
    }

    #[tokio::test]
    async fn test_async_send_recv() {
        let (sender, mut receiver) = create_event_channel(test_config());

        sender.send(wg_packet_event()).await.unwrap();

        let event = receiver.recv().await.unwrap();
        assert!(matches!(event, BridgeEvent::WgPacket { .. }));
    }

    // -------------------------------------------------------------------------
    // Priority ordering tests
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn test_priority_ordering_wg_before_tcp() {
        let (sender, mut receiver) = create_event_channel(test_config());

        // Send normal priority first, then high priority
        sender.try_send(tcp_connect_event(1)).unwrap();
        sender.try_send(wg_packet_event()).unwrap();

        // Should receive high priority (WG) first
        let event = receiver.try_recv().unwrap();
        assert!(
            matches!(event, BridgeEvent::WgPacket { .. }),
            "Expected WgPacket first, got {:?}",
            event
        );

        // Then normal priority (TCP)
        let event = receiver.try_recv().unwrap();
        assert!(
            matches!(event, BridgeEvent::TcpConnect { .. }),
            "Expected TcpConnect second, got {:?}",
            event
        );
    }

    #[tokio::test]
    async fn test_priority_ordering_dns_before_regular_udp() {
        let (sender, mut receiver) = create_event_channel(test_config());

        // Send regular UDP first, then DNS UDP
        sender.try_send(udp_send_event()).unwrap();
        sender.try_send(dns_udp_event()).unwrap();

        // Should receive DNS (high priority) first
        let event = receiver.try_recv().unwrap();
        match &event {
            BridgeEvent::UdpSend { session_key, .. } => {
                assert!(
                    session_key.is_dns(),
                    "Expected DNS packet first, got non-DNS"
                );
            }
            _ => panic!("Expected UdpSend, got {:?}", event),
        }

        // Then regular UDP
        let event = receiver.try_recv().unwrap();
        match &event {
            BridgeEvent::UdpSend { session_key, .. } => {
                assert!(
                    !session_key.is_dns(),
                    "Expected non-DNS packet second, got DNS"
                );
            }
            _ => panic!("Expected UdpSend, got {:?}", event),
        }
    }

    #[tokio::test]
    async fn test_priority_ordering_multiple_events() {
        let (sender, mut receiver) = create_event_channel(test_config());

        // Send events in reverse priority order
        sender.try_send(BridgeEvent::Shutdown).unwrap(); // Lowest priority
        sender.try_send(tcp_connect_event(1)).unwrap(); // Normal priority
        sender.try_send(dns_udp_event()).unwrap(); // High priority
        sender.try_send(wg_packet_event()).unwrap(); // Highest priority

        // Receive in priority order
        let event = receiver.try_recv().unwrap();
        assert!(
            matches!(event, BridgeEvent::WgPacket { .. }),
            "Expected WgPacket first"
        );

        let event = receiver.try_recv().unwrap();
        match &event {
            BridgeEvent::UdpSend { session_key, .. } => assert!(session_key.is_dns()),
            _ => panic!("Expected DNS UdpSend second"),
        }

        // Note: TCP and Shutdown are in the same channel, so they come in FIFO order
        let event = receiver.try_recv().unwrap();
        assert!(
            matches!(event, BridgeEvent::Shutdown),
            "Expected Shutdown third"
        );

        let event = receiver.try_recv().unwrap();
        assert!(
            matches!(event, BridgeEvent::TcpConnect { .. }),
            "Expected TcpConnect fourth"
        );
    }

    #[tokio::test]
    async fn test_async_recv_priority() {
        let (sender, mut receiver) = create_event_channel(test_config());

        // Send normal priority first
        sender.send(tcp_connect_event(1)).await.unwrap();
        sender.send(tcp_connect_event(2)).await.unwrap();

        // Then high priority
        sender.send(wg_packet_event()).await.unwrap();

        // Async recv should also respect priority
        let event = receiver.recv().await.unwrap();
        assert!(
            matches!(event, BridgeEvent::WgPacket { .. }),
            "Expected WgPacket first"
        );

        let event = receiver.recv().await.unwrap();
        assert!(
            matches!(event, BridgeEvent::TcpConnect { conn_id: 1, .. }),
            "Expected TcpConnect(1) second"
        );

        let event = receiver.recv().await.unwrap();
        assert!(
            matches!(event, BridgeEvent::TcpConnect { conn_id: 2, .. }),
            "Expected TcpConnect(2) third"
        );
    }

    // -------------------------------------------------------------------------
    // Backpressure tests
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn test_try_send_full_high_priority() {
        let config = EventChannelConfig::new(2, 16); // Very small high priority
        let (sender, _receiver) = create_event_channel(config);

        // Fill the high priority channel
        sender.try_send(wg_packet_event()).unwrap();
        sender.try_send(wg_packet_event()).unwrap();

        // Third send should fail
        let result = sender.try_send(wg_packet_event());
        assert!(matches!(
            result,
            Err(TrySendError::Full(EventPriority::WgPacket))
        ));
    }

    #[tokio::test]
    async fn test_try_send_full_normal_priority() {
        let config = EventChannelConfig::new(16, 2); // Very small normal priority
        let (sender, _receiver) = create_event_channel(config);

        // Fill the normal priority channel
        sender.try_send(tcp_connect_event(1)).unwrap();
        sender.try_send(tcp_connect_event(2)).unwrap();

        // Third send should fail
        let result = sender.try_send(tcp_connect_event(3));
        assert!(matches!(
            result,
            Err(TrySendError::Full(EventPriority::Tcp))
        ));
    }

    #[tokio::test]
    async fn test_send_timeout() {
        let config =
            EventChannelConfig::new(1, 1).with_send_timeout(Some(Duration::from_millis(10)));
        let (sender, _receiver) = create_event_channel(config);

        // Fill channels
        sender.try_send(wg_packet_event()).unwrap();
        sender.try_send(tcp_connect_event(1)).unwrap();

        // Async send should timeout
        let result = sender.send(wg_packet_event()).await;
        assert!(matches!(result, Err(SendError::Timeout)));
    }

    // -------------------------------------------------------------------------
    // Statistics tests
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn test_stats_send_count() {
        let (sender, mut receiver) = create_event_channel(test_config());

        sender.try_send(wg_packet_event()).unwrap();
        sender.try_send(tcp_connect_event(1)).unwrap();
        sender.try_send(dns_udp_event()).unwrap();

        let stats = sender.stats();
        assert_eq!(stats.sent_total, 3);
        assert_eq!(stats.sent_high_priority, 2); // WG + DNS
        assert_eq!(stats.sent_normal_priority, 1); // TCP

        // Receive all events
        receiver.try_recv().unwrap();
        receiver.try_recv().unwrap();
        receiver.try_recv().unwrap();

        let stats = receiver.stats();
        assert_eq!(stats.received_total, 3);
    }

    #[tokio::test]
    async fn test_stats_dropped_full() {
        let config = EventChannelConfig::new(1, 1);
        let (sender, _receiver) = create_event_channel(config);

        // Fill channels
        sender.try_send(wg_packet_event()).unwrap();
        sender.try_send(tcp_connect_event(1)).unwrap();

        // Try to send more (should be dropped)
        let _ = sender.try_send(wg_packet_event());
        let _ = sender.try_send(tcp_connect_event(2));

        let stats = sender.stats();
        assert_eq!(stats.sent_total, 2);
        assert_eq!(stats.dropped_full, 2);
    }

    #[tokio::test]
    async fn test_stats_dropped_closed() {
        let (sender, receiver) = create_event_channel(test_config());

        // Drop receiver
        drop(receiver);

        // Send should fail with closed
        let _ = sender.try_send(wg_packet_event());

        let stats = sender.stats();
        assert_eq!(stats.dropped_closed, 1);
    }

    // -------------------------------------------------------------------------
    // Channel closure tests
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn test_sender_is_closed() {
        let (sender, receiver) = create_event_channel(test_config());

        assert!(!sender.is_closed());

        drop(receiver);

        assert!(sender.is_closed());
    }

    #[tokio::test]
    async fn test_recv_returns_none_when_closed() {
        let (sender, mut receiver) = create_event_channel(test_config());

        // Drop all senders
        drop(sender);

        // Recv should return None
        let result = receiver.recv().await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_recv_timeout() {
        let (sender, mut receiver) = create_event_channel(test_config());

        // Don't send anything, just let it timeout
        let result = receiver.recv_timeout(Duration::from_millis(10)).await;
        assert!(result.is_none());

        // Now send something
        sender.try_send(wg_packet_event()).unwrap();

        let result = receiver.recv_timeout(Duration::from_millis(100)).await;
        assert!(result.is_some());
    }

    // -------------------------------------------------------------------------
    // Clone and concurrent tests
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn test_sender_clone() {
        let (sender, mut receiver) = create_event_channel(test_config());
        let sender2 = sender.clone();

        sender.try_send(wg_packet_event()).unwrap();
        sender2.try_send(tcp_connect_event(1)).unwrap();

        // Both should have sent to the same channel
        let event = receiver.try_recv().unwrap();
        assert!(matches!(event, BridgeEvent::WgPacket { .. }));

        let event = receiver.try_recv().unwrap();
        assert!(matches!(event, BridgeEvent::TcpConnect { .. }));

        // Stats are shared
        let stats1 = sender.stats();
        let stats2 = sender2.stats();
        assert_eq!(stats1.sent_total, stats2.sent_total);
        assert_eq!(stats1.sent_total, 2);
    }

    #[tokio::test]
    async fn test_concurrent_sends() {
        let (sender, mut receiver) = create_event_channel(test_config());

        // Spawn multiple senders
        let sender1 = sender.clone();
        let sender2 = sender.clone();
        let sender3 = sender.clone();

        let h1 = tokio::spawn(async move {
            for _ in 0..3 {
                sender1.send(wg_packet_event()).await.unwrap();
            }
        });

        let h2 = tokio::spawn(async move {
            for i in 0..3 {
                sender2.send(tcp_connect_event(i)).await.unwrap();
            }
        });

        let h3 = tokio::spawn(async move {
            for _ in 0..3 {
                sender3.send(dns_udp_event()).await.unwrap();
            }
        });

        // Wait for all senders
        h1.await.unwrap();
        h2.await.unwrap();
        h3.await.unwrap();

        // Receive all events
        let mut count = 0;
        while receiver.try_recv().is_some() {
            count += 1;
        }
        assert_eq!(count, 9);

        let stats = sender.stats();
        assert_eq!(stats.sent_total, 9);
    }

    // -------------------------------------------------------------------------
    // Debug formatting tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_sender_debug() {
        let (sender, _receiver) = create_event_channel(test_config());
        let debug = format!("{:?}", sender);
        assert!(debug.contains("EventSender"));
        assert!(debug.contains("high_priority_capacity"));
    }

    #[test]
    fn test_receiver_debug() {
        let (_sender, receiver) = create_event_channel(test_config());
        let debug = format!("{:?}", receiver);
        assert!(debug.contains("EventReceiver"));
    }

    #[test]
    fn test_send_error_display() {
        assert_eq!(
            format!("{}", SendError::HighPriorityFull),
            "high priority channel full"
        );
        assert_eq!(
            format!("{}", SendError::NormalPriorityFull),
            "normal priority channel full"
        );
        assert_eq!(format!("{}", SendError::Closed), "channel closed");
        assert_eq!(format!("{}", SendError::Timeout), "send timed out");
    }

    #[test]
    fn test_try_send_error_display() {
        assert!(format!("{}", TrySendError::Full(EventPriority::Tcp)).contains("Tcp"));
        assert_eq!(format!("{}", TrySendError::Closed), "channel closed");
    }

    // -------------------------------------------------------------------------
    // Configuration tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_config_default() {
        let config = EventChannelConfig::default();
        assert_eq!(config.high_priority_capacity, HIGH_PRIORITY_CHANNEL_SIZE);
        assert_eq!(
            config.normal_priority_capacity,
            NORMAL_PRIORITY_CHANNEL_SIZE
        );
        assert!(config.send_timeout.is_some());
    }

    #[test]
    fn test_config_new() {
        let config = EventChannelConfig::new(100, 200);
        assert_eq!(config.high_priority_capacity, 100);
        assert_eq!(config.normal_priority_capacity, 200);
    }

    #[test]
    fn test_config_with_send_timeout() {
        let config = EventChannelConfig::default().with_send_timeout(None);
        assert!(config.send_timeout.is_none());

        let config = config.with_send_timeout(Some(Duration::from_secs(10)));
        assert_eq!(config.send_timeout, Some(Duration::from_secs(10)));
    }
}
