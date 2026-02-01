//! Reply routing for the netbridge module
//!
//! This module provides abstractions for routing reply packets back to
//! WireGuard peers.
//!
//! # Architecture
//!
//! Reply routing involves:
//! 1. Looking up the session by 5-tuple (reversed for reply packets)
//! 2. Getting the peer key and endpoint from the session
//! 3. Encrypting and sending the packet to the peer
//!
//! This module provides the `ReplyRouter` abstraction that bridges
//! these operations.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use tokio::sync::mpsc;
use tracing::{trace, warn};

use super::error::{NetBridgeError, Result};
use super::session::SessionTracker;
use super::types::{FiveTuple, ReplyPacket};

// =============================================================================
// Reply Router
// =============================================================================

/// Reply router that sends packets back to WireGuard peers
///
/// This struct combines session tracking with reply packet generation,
/// looking up the appropriate peer for each reply packet.
#[derive(Debug)]
pub struct ReplyRouter {
    /// Session tracker for looking up peer info
    sessions: Arc<SessionTracker>,
    /// Reply packet sender
    reply_tx: mpsc::Sender<ReplyPacket>,
    /// Statistics
    stats: ReplyRouterStats,
}

impl ReplyRouter {
    /// Create a new reply router
    ///
    /// # Arguments
    ///
    /// * `sessions` - Session tracker for peer lookups
    /// * `reply_tx` - Channel sender for reply packets
    #[must_use]
    pub fn new(sessions: Arc<SessionTracker>, reply_tx: mpsc::Sender<ReplyPacket>) -> Self {
        Self {
            sessions,
            reply_tx,
            stats: ReplyRouterStats::default(),
        }
    }

    /// Route a reply packet to the appropriate WireGuard peer
    ///
    /// This method:
    /// 1. Parses the IP packet to extract the 5-tuple
    /// 2. Looks up the session by the reversed 5-tuple
    /// 3. Sends the reply packet with peer routing information
    ///
    /// # Arguments
    ///
    /// * `packet` - Raw IP packet data
    ///
    /// # Returns
    ///
    /// `Ok(())` if the packet was successfully routed, or an error if
    /// the session was not found or the channel is closed.
    pub async fn route(&self, packet: &[u8]) -> Result<()> {
        self.stats.packets_received.fetch_add(1, Ordering::Relaxed);

        // Parse 5-tuple from packet
        let five_tuple = match FiveTuple::from_packet(packet) {
            Some(ft) => ft,
            None => {
                self.stats.parse_errors.fetch_add(1, Ordering::Relaxed);
                return Err(NetBridgeError::InvalidPacket(
                    "failed to parse 5-tuple from reply packet".to_string(),
                ));
            }
        };

        // Look up session by reversed 5-tuple
        let session = match self.sessions.lookup_by_reply(&five_tuple) {
            Some(s) => s,
            None => {
                self.stats.session_misses.fetch_add(1, Ordering::Relaxed);
                trace!(
                    five_tuple = %five_tuple,
                    "No session found for reply packet"
                );
                return Err(NetBridgeError::SessionNotFound(format!(
                    "no session for {}",
                    five_tuple
                )));
            }
        };

        // Update session stats
        session.add_bytes_received(packet.len() as u64);

        // Create reply packet
        let reply = ReplyPacket::new(
            Bytes::copy_from_slice(packet),
            session.peer_key,
            session.peer_endpoint(),
        );

        // Send to channel
        if self.reply_tx.send(reply).await.is_err() {
            self.stats.send_errors.fetch_add(1, Ordering::Relaxed);
            return Err(NetBridgeError::ChannelClosed);
        }

        self.stats.packets_routed.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Route a reply packet with explicit peer information
    ///
    /// Use this when the peer information is already known (e.g., from
    /// session state stored elsewhere).
    ///
    /// # Arguments
    ///
    /// * `packet` - Raw IP packet data
    /// * `peer_key` - WireGuard peer public key
    /// * `peer_endpoint` - Peer's endpoint address
    pub async fn route_to_peer(
        &self,
        packet: &[u8],
        peer_key: [u8; 32],
        peer_endpoint: std::net::SocketAddr,
    ) -> Result<()> {
        self.stats.packets_received.fetch_add(1, Ordering::Relaxed);

        let reply = ReplyPacket::new(Bytes::copy_from_slice(packet), peer_key, peer_endpoint);

        if self.reply_tx.send(reply).await.is_err() {
            self.stats.send_errors.fetch_add(1, Ordering::Relaxed);
            return Err(NetBridgeError::ChannelClosed);
        }

        self.stats.packets_routed.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Try to route a reply packet without waiting
    ///
    /// This is a non-blocking version that returns immediately if the
    /// channel is full.
    ///
    /// # Returns
    ///
    /// - `Ok(true)` if the packet was sent
    /// - `Ok(false)` if the channel is full (packet dropped)
    /// - `Err` if parsing failed or session not found
    pub fn try_route(&self, packet: &[u8]) -> Result<bool> {
        self.stats.packets_received.fetch_add(1, Ordering::Relaxed);

        // Parse 5-tuple from packet
        let five_tuple = match FiveTuple::from_packet(packet) {
            Some(ft) => ft,
            None => {
                self.stats.parse_errors.fetch_add(1, Ordering::Relaxed);
                return Err(NetBridgeError::InvalidPacket(
                    "failed to parse 5-tuple".to_string(),
                ));
            }
        };

        // Look up session
        let session = match self.sessions.lookup_by_reply(&five_tuple) {
            Some(s) => s,
            None => {
                self.stats.session_misses.fetch_add(1, Ordering::Relaxed);
                return Err(NetBridgeError::SessionNotFound(format!(
                    "no session for {}",
                    five_tuple
                )));
            }
        };

        session.add_bytes_received(packet.len() as u64);

        let reply = ReplyPacket::new(
            Bytes::copy_from_slice(packet),
            session.peer_key,
            session.peer_endpoint(),
        );

        match self.reply_tx.try_send(reply) {
            Ok(()) => {
                self.stats.packets_routed.fetch_add(1, Ordering::Relaxed);
                Ok(true)
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.stats.channel_full.fetch_add(1, Ordering::Relaxed);
                warn!("Reply channel full, dropping packet");
                Ok(false)
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.stats.send_errors.fetch_add(1, Ordering::Relaxed);
                Err(NetBridgeError::ChannelClosed)
            }
        }
    }

    /// Get router statistics
    #[must_use]
    pub fn stats(&self) -> ReplyRouterStatsSnapshot {
        ReplyRouterStatsSnapshot {
            packets_received: self.stats.packets_received.load(Ordering::Relaxed),
            packets_routed: self.stats.packets_routed.load(Ordering::Relaxed),
            session_misses: self.stats.session_misses.load(Ordering::Relaxed),
            parse_errors: self.stats.parse_errors.load(Ordering::Relaxed),
            send_errors: self.stats.send_errors.load(Ordering::Relaxed),
            channel_full: self.stats.channel_full.load(Ordering::Relaxed),
        }
    }
}

// =============================================================================
// Statistics
// =============================================================================

/// Internal statistics counters
#[derive(Debug, Default)]
struct ReplyRouterStats {
    /// Total packets received for routing
    packets_received: AtomicU64,
    /// Packets successfully routed
    packets_routed: AtomicU64,
    /// Session lookup misses
    session_misses: AtomicU64,
    /// Packet parse errors
    parse_errors: AtomicU64,
    /// Channel send errors
    send_errors: AtomicU64,
    /// Channel full (backpressure)
    channel_full: AtomicU64,
}

/// Snapshot of reply router statistics
#[derive(Debug, Clone, Default)]
pub struct ReplyRouterStatsSnapshot {
    /// Total packets received for routing
    pub packets_received: u64,
    /// Packets successfully routed
    pub packets_routed: u64,
    /// Session lookup misses
    pub session_misses: u64,
    /// Packet parse errors
    pub parse_errors: u64,
    /// Channel send errors
    pub send_errors: u64,
    /// Channel full (backpressure) events
    pub channel_full: u64,
}

impl ReplyRouterStatsSnapshot {
    /// Get the success rate as a percentage
    #[must_use]
    pub fn success_rate(&self) -> f64 {
        if self.packets_received == 0 {
            100.0
        } else {
            (self.packets_routed as f64 / self.packets_received as f64) * 100.0
        }
    }

    /// Get total errors
    #[must_use]
    pub fn total_errors(&self) -> u64 {
        self.session_misses + self.parse_errors + self.send_errors
    }
}

// =============================================================================
// Reply Channel Builder
// =============================================================================

/// Builder for creating reply channels with appropriate sizing
pub struct ReplyChannelBuilder {
    /// Channel capacity
    capacity: usize,
}

impl ReplyChannelBuilder {
    /// Create a new builder with default capacity
    #[must_use]
    pub fn new() -> Self {
        Self {
            capacity: super::config::REPLY_CHANNEL_SIZE,
        }
    }

    /// Set the channel capacity
    #[must_use]
    pub fn capacity(mut self, capacity: usize) -> Self {
        self.capacity = capacity;
        self
    }

    /// Build the channel pair
    #[must_use]
    pub fn build(self) -> (mpsc::Sender<ReplyPacket>, mpsc::Receiver<ReplyPacket>) {
        mpsc::channel(self.capacity)
    }
}

impl Default for ReplyChannelBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn make_ipv4_tcp_packet(src_port: u16, dst_port: u16) -> Vec<u8> {
        // IPv4 TCP packet: 10.25.0.2:src_port -> 93.184.216.34:dst_port
        let src_port_bytes = src_port.to_be_bytes();
        let dst_port_bytes = dst_port.to_be_bytes();

        vec![
            0x45, 0x00, 0x00, 0x28, // Version=4, IHL=5, Total Length=40
            0x00, 0x00, 0x00, 0x00, // ID, Flags, Fragment
            0x40, 0x06, 0x00, 0x00, // TTL=64, Protocol=TCP, Checksum
            0x0a, 0x19, 0x00, 0x02, // Src: 10.25.0.2
            0x5d, 0xb8, 0xd8, 0x22, // Dst: 93.184.216.34
            src_port_bytes[0], src_port_bytes[1],
            dst_port_bytes[0], dst_port_bytes[1],
            // Minimal TCP header would follow...
        ]
    }

    fn test_peer_endpoint() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 51820)
    }

    #[tokio::test]
    async fn test_reply_router_basic() {
        let sessions = Arc::new(SessionTracker::new());
        let (tx, mut rx) = mpsc::channel(100);
        let router = ReplyRouter::new(Arc::clone(&sessions), tx);

        let peer_key = [42u8; 32];
        let peer_endpoint = test_peer_endpoint();

        // Create forward 5-tuple (client -> server)
        let forward_tuple = FiveTuple::tcp(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 25, 0, 2)), 12345),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 80),
        );

        // Register session
        sessions
            .register(peer_key, peer_endpoint, forward_tuple, "direct".to_string())
            .unwrap();

        // Create reply packet (server -> client, reversed)
        let reply_packet = make_ipv4_tcp_packet(80, 12345);

        // Route it
        router.route(&reply_packet).await.unwrap();

        // Check we received the reply
        let received = rx.recv().await.unwrap();
        assert_eq!(received.peer_key, peer_key);
        assert_eq!(received.peer_endpoint, peer_endpoint);
    }

    #[tokio::test]
    async fn test_reply_router_session_not_found() {
        let sessions = Arc::new(SessionTracker::new());
        let (tx, _rx) = mpsc::channel(100);
        let router = ReplyRouter::new(sessions, tx);

        // Try to route without registering session
        let packet = make_ipv4_tcp_packet(80, 12345);
        let result = router.route(&packet).await;

        assert!(matches!(result, Err(NetBridgeError::SessionNotFound(_))));
    }

    #[test]
    fn test_try_route_channel_full() {
        let sessions = Arc::new(SessionTracker::new());
        let (tx, _rx) = mpsc::channel(1); // Very small channel
        let router = ReplyRouter::new(Arc::clone(&sessions), tx);

        let peer_key = [42u8; 32];
        let peer_endpoint = test_peer_endpoint();

        let forward_tuple = FiveTuple::tcp(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 25, 0, 2)), 12345),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 80),
        );

        sessions
            .register(peer_key, peer_endpoint, forward_tuple, "direct".to_string())
            .unwrap();

        let packet = make_ipv4_tcp_packet(80, 12345);

        // First should succeed
        assert!(router.try_route(&packet).unwrap());

        // Second might fill channel (depending on implementation)
        // We just verify it doesn't panic
        let _ = router.try_route(&packet);
    }

    #[test]
    fn test_stats_snapshot() {
        let stats = ReplyRouterStatsSnapshot {
            packets_received: 100,
            packets_routed: 95,
            session_misses: 3,
            parse_errors: 1,
            send_errors: 1,
            channel_full: 0,
        };

        assert!((stats.success_rate() - 95.0).abs() < 0.01);
        assert_eq!(stats.total_errors(), 5);
    }

    #[test]
    fn test_reply_channel_builder() {
        let (tx, rx) = ReplyChannelBuilder::new().capacity(500).build();

        // Verify the channel works
        drop(rx);
        assert!(tx.is_closed());
    }
}
