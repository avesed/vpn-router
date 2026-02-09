//! Sharded bridge reply registry for routing WireGuard replies to sharded bridges
//!
//! This module provides a registry that maps WireGuard tunnel tags to their
//! `ShardedVlessWgBridge` reply channels. When the `WgReplyHandler` receives a
//! decrypted packet, it checks this registry to route it to the correct sharded
//! bridge's reply channel.
//!
//! # Architecture
//!
//! ```text
//! WgReplyHandler (callback)
//!         │
//!         ▼ try_route(tunnel_tag, packet)
//! ShardedBridgeReplyRegistry
//!         │
//!         ├── tunnel-1 -> mpsc::Sender<Vec<u8>>
//!         ├── tunnel-2 -> mpsc::Sender<Vec<u8>>
//!         └── tunnel-N -> mpsc::Sender<Vec<u8>>
//!                 │
//!                 ▼
//!         ShardedVlessWgBridge.wg_reply_rx
//! ```

use std::sync::atomic::{AtomicU64, Ordering};

use dashmap::DashMap;
use tokio::sync::mpsc;
use tracing::{debug, trace, warn};

/// Sharded bridge reply registry
///
/// A concurrent registry that maps WireGuard tunnel tags to their sharded
/// bridge reply channels. This enables the `WgReplyHandler` to route packets
/// to the correct `ShardedVlessWgBridge`.
///
/// # Thread Safety
///
/// Uses `DashMap` for lock-free concurrent access from multiple tasks.
pub struct ShardedBridgeReplyRegistry {
    /// Tunnel tag -> reply sender
    senders: DashMap<String, mpsc::Sender<Vec<u8>>>,
    /// Statistics
    stats: RegistryStats,
}

/// Registry statistics
#[derive(Debug, Default)]
struct RegistryStats {
    /// Total tunnels registered
    registered: AtomicU64,
    /// Total tunnels unregistered
    unregistered: AtomicU64,
    /// Packets routed successfully
    packets_routed: AtomicU64,
    /// Packets dropped (no tunnel found)
    packets_dropped: AtomicU64,
    /// Packets dropped (channel full)
    channel_full: AtomicU64,
}

/// Snapshot of registry statistics
#[derive(Debug, Clone, Default)]
pub struct ShardedRegistryStatsSnapshot {
    /// Total tunnels registered
    pub registered: u64,
    /// Total tunnels unregistered
    pub unregistered: u64,
    /// Packets routed successfully
    pub packets_routed: u64,
    /// Packets dropped (no tunnel found)
    pub packets_dropped: u64,
    /// Packets dropped (channel full)
    pub channel_full: u64,
    /// Current number of active tunnels
    pub active_tunnels: usize,
}

impl ShardedBridgeReplyRegistry {
    /// Create a new empty registry
    pub fn new() -> Self {
        Self {
            senders: DashMap::new(),
            stats: RegistryStats::default(),
        }
    }

    /// Register a sharded bridge's reply channel
    ///
    /// # Arguments
    ///
    /// * `tunnel_tag` - The WireGuard tunnel tag
    /// * `sender` - The mpsc sender for routing replies to the sharded bridge
    ///
    /// # Returns
    ///
    /// The previous sender if one existed (for replacement scenarios)
    pub fn register(
        &self,
        tunnel_tag: String,
        sender: mpsc::Sender<Vec<u8>>,
    ) -> Option<mpsc::Sender<Vec<u8>>> {
        self.stats.registered.fetch_add(1, Ordering::Relaxed);
        debug!(tunnel_tag = %tunnel_tag, "Registered sharded bridge reply channel");
        self.senders.insert(tunnel_tag, sender)
    }

    /// Unregister a sharded bridge's reply channel
    ///
    /// # Arguments
    ///
    /// * `tunnel_tag` - The WireGuard tunnel tag to unregister
    ///
    /// # Returns
    ///
    /// The removed sender if it existed
    pub fn unregister(&self, tunnel_tag: &str) -> Option<mpsc::Sender<Vec<u8>>> {
        let removed = self.senders.remove(tunnel_tag).map(|(_, sender)| sender);
        if removed.is_some() {
            self.stats.unregistered.fetch_add(1, Ordering::Relaxed);
            debug!(tunnel_tag = %tunnel_tag, "Unregistered sharded bridge reply channel");
        }
        removed
    }

    /// Try to route a packet to a sharded bridge
    ///
    /// This should be called by the `WgReplyHandler` callback to attempt
    /// routing packets to sharded bridges before falling back to other handlers.
    ///
    /// # Arguments
    ///
    /// * `tunnel_tag` - The WireGuard tunnel tag the packet came from
    /// * `packet` - The decrypted IP packet data
    ///
    /// # Returns
    ///
    /// `true` if the packet was successfully sent to a sharded bridge,
    /// `false` if no bridge is registered for this tunnel (packet should be
    /// handled by other mechanisms)
    pub fn try_route(&self, tunnel_tag: &str, packet: &[u8]) -> bool {
        if let Some(sender) = self.senders.get(tunnel_tag) {
            let packet_vec = packet.to_vec();
            match sender.try_send(packet_vec) {
                Ok(()) => {
                    self.stats.packets_routed.fetch_add(1, Ordering::Relaxed);
                    trace!(
                        tunnel_tag = %tunnel_tag,
                        len = packet.len(),
                        "Routed packet to sharded bridge"
                    );
                    true
                }
                Err(mpsc::error::TrySendError::Full(_)) => {
                    self.stats.channel_full.fetch_add(1, Ordering::Relaxed);
                    warn!(
                        tunnel_tag = %tunnel_tag,
                        len = packet.len(),
                        "Sharded bridge reply channel full, dropping packet"
                    );
                    // Return true because we found the bridge, just couldn't send
                    // This prevents fallback to other handlers for a known tunnel
                    true
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    self.stats.packets_dropped.fetch_add(1, Ordering::Relaxed);
                    warn!(
                        tunnel_tag = %tunnel_tag,
                        "Sharded bridge reply channel closed, dropping packet"
                    );
                    // Remove the closed channel
                    self.senders.remove(tunnel_tag);
                    false
                }
            }
        } else {
            // No sharded bridge for this tunnel - let caller try other handlers
            false
        }
    }

    /// Check if a tunnel has a registered sharded bridge
    pub fn has_tunnel(&self, tunnel_tag: &str) -> bool {
        self.senders.contains_key(tunnel_tag)
    }

    /// Get the number of registered tunnels
    pub fn len(&self) -> usize {
        self.senders.len()
    }

    /// Check if the registry is empty
    pub fn is_empty(&self) -> bool {
        self.senders.is_empty()
    }

    /// List all registered tunnel tags
    pub fn list_tunnels(&self) -> Vec<String> {
        self.senders.iter().map(|e| e.key().clone()).collect()
    }

    /// Get statistics snapshot
    pub fn stats(&self) -> ShardedRegistryStatsSnapshot {
        ShardedRegistryStatsSnapshot {
            registered: self.stats.registered.load(Ordering::Relaxed),
            unregistered: self.stats.unregistered.load(Ordering::Relaxed),
            packets_routed: self.stats.packets_routed.load(Ordering::Relaxed),
            packets_dropped: self.stats.packets_dropped.load(Ordering::Relaxed),
            channel_full: self.stats.channel_full.load(Ordering::Relaxed),
            active_tunnels: self.senders.len(),
        }
    }
}

impl Default for ShardedBridgeReplyRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for ShardedBridgeReplyRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShardedBridgeReplyRegistry")
            .field("tunnels", &self.senders.len())
            .field("stats", &self.stats())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_new() {
        let registry = ShardedBridgeReplyRegistry::new();
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);
    }

    #[test]
    fn test_register_and_unregister() {
        let registry = ShardedBridgeReplyRegistry::new();
        let (tx, _rx) = mpsc::channel(10);

        // Register
        assert!(registry.register("test-tunnel".to_string(), tx).is_none());
        assert!(registry.has_tunnel("test-tunnel"));
        assert_eq!(registry.len(), 1);

        // Unregister
        assert!(registry.unregister("test-tunnel").is_some());
        assert!(!registry.has_tunnel("test-tunnel"));
        assert!(registry.is_empty());

        // Unregister non-existent
        assert!(registry.unregister("test-tunnel").is_none());
    }

    #[tokio::test]
    async fn test_try_route_success() {
        let registry = ShardedBridgeReplyRegistry::new();
        let (tx, mut rx) = mpsc::channel(10);

        registry.register("test-tunnel".to_string(), tx);

        let packet = vec![1, 2, 3, 4];
        assert!(registry.try_route("test-tunnel", &packet));

        let received = rx.recv().await.unwrap();
        assert_eq!(&received[..], &packet[..]);

        let stats = registry.stats();
        assert_eq!(stats.packets_routed, 1);
    }

    #[test]
    fn test_try_route_no_tunnel() {
        let registry = ShardedBridgeReplyRegistry::new();
        let packet = vec![1, 2, 3, 4];
        assert!(!registry.try_route("non-existent", &packet));
    }

    #[test]
    fn test_list_tunnels() {
        let registry = ShardedBridgeReplyRegistry::new();
        let (tx1, _rx1) = mpsc::channel(10);
        let (tx2, _rx2) = mpsc::channel(10);

        registry.register("tunnel-a".to_string(), tx1);
        registry.register("tunnel-b".to_string(), tx2);

        let tunnels = registry.list_tunnels();
        assert_eq!(tunnels.len(), 2);
        assert!(tunnels.contains(&"tunnel-a".to_string()));
        assert!(tunnels.contains(&"tunnel-b".to_string()));
    }

    #[test]
    fn test_stats() {
        let registry = ShardedBridgeReplyRegistry::new();
        let (tx, _rx) = mpsc::channel(10);

        registry.register("test".to_string(), tx);
        let _ = registry.try_route("non-existent", &[1, 2, 3]);
        registry.unregister("test");

        let stats = registry.stats();
        assert_eq!(stats.registered, 1);
        assert_eq!(stats.unregistered, 1);
        assert_eq!(stats.active_tunnels, 0);
    }
}
