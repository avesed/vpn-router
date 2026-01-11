//! Reply handler for `WireGuard` egress traffic
//!
//! This module provides the `WgReplyHandler` that handles decrypted reply
//! packets from egress tunnels and routes them back to the appropriate
//! destination (ingress or local).
//!
//! # Architecture
//!
//! ```text
//! Egress Tunnel → Decrypt → WgReplyHandler → Ingress/Local
//!                             ↓
//!                    reply_callback(packet, tunnel_tag)
//! ```
//!
//! # Example
//!
//! ```
//! use rust_router::egress::WgReplyHandler;
//! use std::sync::Arc;
//! use std::sync::atomic::{AtomicUsize, Ordering};
//!
//! let packet_count = Arc::new(AtomicUsize::new(0));
//! let count_clone = packet_count.clone();
//!
//! let handler = WgReplyHandler::new(move |packet, tunnel_tag| {
//!     count_clone.fetch_add(1, Ordering::Relaxed);
//!     println!("Received {} bytes from {}", packet.len(), tunnel_tag);
//! });
//!
//! // Handle a reply packet
//! handler.handle_reply(vec![1, 2, 3, 4], "my-tunnel");
//!
//! assert_eq!(packet_count.load(Ordering::Relaxed), 1);
//! ```

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tracing::{debug, trace};

/// Callback type for handling reply packets
///
/// The callback receives:
/// - `Vec<u8>`: The decrypted IP packet
/// - `String`: The tag of the tunnel that received the reply
pub type ReplyCallback = Arc<dyn Fn(Vec<u8>, String) + Send + Sync>;

/// Handler for decrypted reply packets from egress tunnels
///
/// This struct wraps a callback function that is invoked for each
/// decrypted reply packet received from an egress tunnel.
///
/// # Thread Safety
///
/// `WgReplyHandler` is `Send + Sync` and can be shared across tasks.
/// The callback is stored in an `Arc` and can be called concurrently.
///
/// # Example
///
/// ```
/// use rust_router::egress::WgReplyHandler;
/// use std::sync::Arc;
///
/// // Create with a closure
/// let handler = WgReplyHandler::new(|packet, tag| {
///     println!("Got {} bytes from {}", packet.len(), tag);
/// });
///
/// // Create with a no-op (for testing)
/// let noop_handler = WgReplyHandler::noop();
///
/// // Check statistics
/// let stats = handler.stats();
/// assert_eq!(stats.packets_handled, 0);
/// ```
pub struct WgReplyHandler {
    /// Callback for handling decrypted reply packets
    reply_callback: ReplyCallback,

    /// Statistics
    stats: ReplyHandlerStats,
}

impl WgReplyHandler {
    /// Create a new reply handler with the given callback
    ///
    /// # Arguments
    ///
    /// * `callback` - Function to call for each decrypted reply packet
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::egress::WgReplyHandler;
    ///
    /// let handler = WgReplyHandler::new(|packet, tunnel_tag| {
    ///     println!("Reply from {}: {} bytes", tunnel_tag, packet.len());
    /// });
    /// ```
    pub fn new<F>(callback: F) -> Self
    where
        F: Fn(Vec<u8>, String) + Send + Sync + 'static,
    {
        Self {
            reply_callback: Arc::new(callback),
            stats: ReplyHandlerStats::default(),
        }
    }

    /// Create a new reply handler with an Arc callback
    ///
    /// This variant allows sharing the callback across multiple handlers.
    ///
    /// # Arguments
    ///
    /// * `callback` - Arc-wrapped callback function
    pub fn with_arc_callback(callback: ReplyCallback) -> Self {
        Self {
            reply_callback: callback,
            stats: ReplyHandlerStats::default(),
        }
    }

    /// Create a no-op reply handler (for testing)
    ///
    /// This handler silently discards all packets.
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::egress::WgReplyHandler;
    ///
    /// let handler = WgReplyHandler::noop();
    /// handler.handle_reply(vec![1, 2, 3], "test");
    /// // Packet is discarded
    /// ```
    #[must_use]
    pub fn noop() -> Self {
        Self::new(|_packet, _tag| {
            // Do nothing
        })
    }

    /// Handle a decrypted reply packet
    ///
    /// This method invokes the callback with the packet data and tunnel tag.
    ///
    /// # Arguments
    ///
    /// * `packet` - The decrypted IP packet
    /// * `tunnel_tag` - The tag of the tunnel that received this reply
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::egress::WgReplyHandler;
    /// use std::sync::atomic::{AtomicBool, Ordering};
    /// use std::sync::Arc;
    ///
    /// let received = Arc::new(AtomicBool::new(false));
    /// let received_clone = received.clone();
    ///
    /// let handler = WgReplyHandler::new(move |packet, _tag| {
    ///     received_clone.store(true, Ordering::Relaxed);
    ///     assert_eq!(packet, vec![1, 2, 3, 4]);
    /// });
    ///
    /// handler.handle_reply(vec![1, 2, 3, 4], "my-tunnel");
    /// assert!(received.load(Ordering::Relaxed));
    /// ```
    pub fn handle_reply(&self, packet: Vec<u8>, tunnel_tag: impl Into<String>) {
        let tag = tunnel_tag.into();
        let len = packet.len();

        trace!("Handling reply packet from {} ({} bytes)", tag, len);

        // Update statistics
        self.stats.packets_handled.fetch_add(1, Ordering::Relaxed);
        self.stats.bytes_handled.fetch_add(len as u64, Ordering::Relaxed);

        // Invoke the callback
        (self.reply_callback)(packet, tag);

        debug!("Dispatched reply packet ({} bytes)", len);
    }

    /// Handle multiple reply packets at once
    ///
    /// This is a convenience method for handling batches of packets.
    ///
    /// # Arguments
    ///
    /// * `packets` - Iterator of (packet, `tunnel_tag`) pairs
    ///
    /// # Returns
    ///
    /// The number of packets handled
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::egress::WgReplyHandler;
    ///
    /// let handler = WgReplyHandler::noop();
    ///
    /// let packets = vec![
    ///     (vec![1, 2], "tunnel-1"),
    ///     (vec![3, 4], "tunnel-2"),
    /// ];
    ///
    /// let count = handler.handle_batch(packets);
    /// assert_eq!(count, 2);
    /// ```
    pub fn handle_batch<I, S>(&self, packets: I) -> usize
    where
        I: IntoIterator<Item = (Vec<u8>, S)>,
        S: Into<String>,
    {
        let mut count = 0;
        for (packet, tag) in packets {
            self.handle_reply(packet, tag);
            count += 1;
        }
        count
    }

    /// Get the handler statistics
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::egress::WgReplyHandler;
    ///
    /// let handler = WgReplyHandler::noop();
    /// handler.handle_reply(vec![1, 2, 3, 4], "test");
    ///
    /// let stats = handler.stats();
    /// assert_eq!(stats.packets_handled, 1);
    /// assert_eq!(stats.bytes_handled, 4);
    /// ```
    #[must_use]
    pub fn stats(&self) -> ReplyHandlerStatsSnapshot {
        ReplyHandlerStatsSnapshot {
            packets_handled: self.stats.packets_handled.load(Ordering::Relaxed),
            bytes_handled: self.stats.bytes_handled.load(Ordering::Relaxed),
        }
    }

    /// Reset the statistics
    pub fn reset_stats(&self) {
        self.stats.packets_handled.store(0, Ordering::Relaxed);
        self.stats.bytes_handled.store(0, Ordering::Relaxed);
    }

    /// Get the callback (for testing or cloning)
    #[must_use]
    pub fn callback(&self) -> ReplyCallback {
        self.reply_callback.clone()
    }
}

impl std::fmt::Debug for WgReplyHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WgReplyHandler")
            .field("stats", &self.stats())
            .finish()
    }
}

// Implement Clone by creating a new handler with the same callback
impl Clone for WgReplyHandler {
    fn clone(&self) -> Self {
        Self {
            reply_callback: self.reply_callback.clone(),
            stats: ReplyHandlerStats::default(), // New stats for clone
        }
    }
}

/// Internal statistics tracking
#[derive(Default)]
struct ReplyHandlerStats {
    packets_handled: AtomicU64,
    bytes_handled: AtomicU64,
}

/// Snapshot of reply handler statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReplyHandlerStatsSnapshot {
    /// Total packets handled
    pub packets_handled: u64,
    /// Total bytes handled
    pub bytes_handled: u64,
}

impl ReplyHandlerStatsSnapshot {
    /// Create a new snapshot with zero values
    #[must_use]
    pub fn zero() -> Self {
        Self::default()
    }

    /// Add another snapshot to this one
    pub fn add(&mut self, other: &Self) {
        self.packets_handled += other.packets_handled;
        self.bytes_handled += other.bytes_handled;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;

    // ========================================================================
    // WgReplyHandler Creation Tests
    // ========================================================================

    #[test]
    fn test_handler_new() {
        let called = Arc::new(AtomicBool::new(false));
        let called_clone = called.clone();

        let handler = WgReplyHandler::new(move |_packet, _tag| {
            called_clone.store(true, Ordering::Relaxed);
        });

        handler.handle_reply(vec![1, 2, 3], "test");
        assert!(called.load(Ordering::Relaxed));
    }

    #[test]
    fn test_handler_with_arc_callback() {
        let called = Arc::new(AtomicBool::new(false));
        let called_clone = called.clone();

        let callback: ReplyCallback = Arc::new(move |_packet, _tag| {
            called_clone.store(true, Ordering::Relaxed);
        });

        let handler = WgReplyHandler::with_arc_callback(callback);
        handler.handle_reply(vec![1, 2, 3], "test");
        assert!(called.load(Ordering::Relaxed));
    }

    #[test]
    fn test_handler_noop() {
        let handler = WgReplyHandler::noop();
        // Should not panic
        handler.handle_reply(vec![1, 2, 3, 4], "test");

        let stats = handler.stats();
        assert_eq!(stats.packets_handled, 1);
        assert_eq!(stats.bytes_handled, 4);
    }

    // ========================================================================
    // Handle Reply Tests
    // ========================================================================

    #[test]
    fn test_handle_reply_packet_and_tag() {
        let received_packet = Arc::new(std::sync::Mutex::new(Vec::new()));
        let received_tag = Arc::new(std::sync::Mutex::new(String::new()));

        let packet_clone = received_packet.clone();
        let tag_clone = received_tag.clone();

        let handler = WgReplyHandler::new(move |packet, tag| {
            *packet_clone.lock().unwrap() = packet;
            *tag_clone.lock().unwrap() = tag;
        });

        handler.handle_reply(vec![1, 2, 3, 4, 5], "my-tunnel");

        assert_eq!(*received_packet.lock().unwrap(), vec![1, 2, 3, 4, 5]);
        assert_eq!(*received_tag.lock().unwrap(), "my-tunnel");
    }

    #[test]
    fn test_handle_reply_with_string_tag() {
        let handler = WgReplyHandler::noop();

        // Test with String
        handler.handle_reply(vec![1], String::from("test"));

        // Test with &str
        handler.handle_reply(vec![1], "test");

        let stats = handler.stats();
        assert_eq!(stats.packets_handled, 2);
    }

    #[test]
    fn test_handle_reply_empty_packet() {
        let handler = WgReplyHandler::noop();
        handler.handle_reply(Vec::new(), "test");

        let stats = handler.stats();
        assert_eq!(stats.packets_handled, 1);
        assert_eq!(stats.bytes_handled, 0);
    }

    #[test]
    fn test_handle_reply_large_packet() {
        let handler = WgReplyHandler::noop();
        let large_packet = vec![0u8; 65535];
        handler.handle_reply(large_packet, "test");

        let stats = handler.stats();
        assert_eq!(stats.packets_handled, 1);
        assert_eq!(stats.bytes_handled, 65535);
    }

    // ========================================================================
    // Handle Batch Tests
    // ========================================================================

    #[test]
    fn test_handle_batch() {
        let handler = WgReplyHandler::noop();

        let packets = vec![
            (vec![1, 2], "tunnel-1"),
            (vec![3, 4, 5], "tunnel-2"),
            (vec![6], "tunnel-3"),
        ];

        let count = handler.handle_batch(packets);

        assert_eq!(count, 3);
        let stats = handler.stats();
        assert_eq!(stats.packets_handled, 3);
        assert_eq!(stats.bytes_handled, 6); // 2 + 3 + 1
    }

    #[test]
    fn test_handle_batch_empty() {
        let handler = WgReplyHandler::noop();
        let packets: Vec<(Vec<u8>, &str)> = Vec::new();
        let count = handler.handle_batch(packets);

        assert_eq!(count, 0);
        let stats = handler.stats();
        assert_eq!(stats.packets_handled, 0);
    }

    #[test]
    fn test_handle_batch_with_string_tags() {
        let handler = WgReplyHandler::noop();

        let packets = vec![
            (vec![1], String::from("tunnel-1")),
            (vec![2], String::from("tunnel-2")),
        ];

        let count = handler.handle_batch(packets);
        assert_eq!(count, 2);
    }

    // ========================================================================
    // Statistics Tests
    // ========================================================================

    #[test]
    fn test_stats_initial() {
        let handler = WgReplyHandler::noop();
        let stats = handler.stats();

        assert_eq!(stats.packets_handled, 0);
        assert_eq!(stats.bytes_handled, 0);
    }

    #[test]
    fn test_stats_after_packets() {
        let handler = WgReplyHandler::noop();

        handler.handle_reply(vec![1, 2, 3], "t1");
        handler.handle_reply(vec![4, 5, 6, 7], "t2");

        let stats = handler.stats();
        assert_eq!(stats.packets_handled, 2);
        assert_eq!(stats.bytes_handled, 7); // 3 + 4
    }

    #[test]
    fn test_reset_stats() {
        let handler = WgReplyHandler::noop();

        handler.handle_reply(vec![1, 2, 3], "test");
        assert_eq!(handler.stats().packets_handled, 1);

        handler.reset_stats();

        let stats = handler.stats();
        assert_eq!(stats.packets_handled, 0);
        assert_eq!(stats.bytes_handled, 0);
    }

    // ========================================================================
    // Clone and Debug Tests
    // ========================================================================

    #[test]
    fn test_handler_clone() {
        let counter = Arc::new(AtomicU64::new(0));
        let counter_clone = counter.clone();

        let handler = WgReplyHandler::new(move |_packet, _tag| {
            counter_clone.fetch_add(1, Ordering::Relaxed);
        });

        // Handle on original
        handler.handle_reply(vec![1], "test");
        assert_eq!(counter.load(Ordering::Relaxed), 1);

        // Clone shares the callback
        let cloned = handler.clone();
        cloned.handle_reply(vec![2], "test");
        assert_eq!(counter.load(Ordering::Relaxed), 2);

        // But stats are separate
        assert_eq!(handler.stats().packets_handled, 1);
        assert_eq!(cloned.stats().packets_handled, 1);
    }

    #[test]
    fn test_handler_debug() {
        let handler = WgReplyHandler::noop();
        handler.handle_reply(vec![1, 2, 3], "test");

        let debug_str = format!("{:?}", handler);
        assert!(debug_str.contains("WgReplyHandler"));
        assert!(debug_str.contains("packets_handled"));
    }

    #[test]
    fn test_callback_getter() {
        let handler = WgReplyHandler::noop();
        let callback = handler.callback();

        // Callback should be callable
        callback(vec![1, 2, 3], "test".to_string());
    }

    // ========================================================================
    // ReplyHandlerStatsSnapshot Tests
    // ========================================================================

    #[test]
    fn test_stats_snapshot_zero() {
        let snapshot = ReplyHandlerStatsSnapshot::zero();
        assert_eq!(snapshot.packets_handled, 0);
        assert_eq!(snapshot.bytes_handled, 0);
    }

    #[test]
    fn test_stats_snapshot_default() {
        let snapshot = ReplyHandlerStatsSnapshot::default();
        assert_eq!(snapshot.packets_handled, 0);
        assert_eq!(snapshot.bytes_handled, 0);
    }

    #[test]
    fn test_stats_snapshot_add() {
        let mut snapshot1 = ReplyHandlerStatsSnapshot {
            packets_handled: 10,
            bytes_handled: 1000,
        };

        let snapshot2 = ReplyHandlerStatsSnapshot {
            packets_handled: 5,
            bytes_handled: 500,
        };

        snapshot1.add(&snapshot2);

        assert_eq!(snapshot1.packets_handled, 15);
        assert_eq!(snapshot1.bytes_handled, 1500);
    }

    #[test]
    fn test_stats_snapshot_serialization() {
        let snapshot = ReplyHandlerStatsSnapshot {
            packets_handled: 100,
            bytes_handled: 50000,
        };

        let json = serde_json::to_string(&snapshot).expect("Should serialize");
        assert!(json.contains("100"));
        assert!(json.contains("50000"));

        let deserialized: ReplyHandlerStatsSnapshot =
            serde_json::from_str(&json).expect("Should deserialize");
        assert_eq!(deserialized.packets_handled, snapshot.packets_handled);
        assert_eq!(deserialized.bytes_handled, snapshot.bytes_handled);
    }

    // ========================================================================
    // Concurrency Tests
    // ========================================================================

    #[test]
    fn test_handler_thread_safety() {
        use std::thread;

        let handler = Arc::new(WgReplyHandler::noop());
        let mut handles = vec![];

        for i in 0..10 {
            let h = handler.clone();
            handles.push(thread::spawn(move || {
                for j in 0..100 {
                    h.handle_reply(vec![i as u8, j as u8], format!("thread-{i}"));
                }
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        let stats = handler.stats();
        assert_eq!(stats.packets_handled, 1000); // 10 threads * 100 packets
    }
}
