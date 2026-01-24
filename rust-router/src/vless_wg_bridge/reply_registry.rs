//! VLESS reply registry for routing WireGuard replies to VLESS sessions
//!
//! This module provides a shared registry that maps VLESS sessions to their
//! reply senders. When the WgReplyHandler receives a decrypted packet, it
//! checks this registry to see if it should be routed to a VLESS session
//! instead of the IngressForwarder.

use std::net::IpAddr;
use std::sync::Arc;

use dashmap::DashMap;
use parking_lot::RwLock;
use tokio::sync::mpsc;
use tracing::{debug, trace, warn};

use super::bridge::WgReplyPacket;

/// Key for session lookup in the registry
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VlessReplyKey {
    /// WireGuard tunnel tag
    pub tunnel_tag: String,
    /// Local IP (bridge's IP in the WG tunnel)
    pub local_ip: IpAddr,
    /// Local port (ephemeral port allocated by smoltcp)
    pub local_port: u16,
    /// Remote IP (destination server)
    pub remote_ip: IpAddr,
    /// Remote port (destination port)
    pub remote_port: u16,
}

impl VlessReplyKey {
    /// Create a new reply key
    pub fn new(
        tunnel_tag: String,
        local_ip: IpAddr,
        local_port: u16,
        remote_ip: IpAddr,
        remote_port: u16,
    ) -> Self {
        Self {
            tunnel_tag,
            local_ip,
            local_port,
            remote_ip,
            remote_port,
        }
    }
}

/// Entry in the reply registry
struct RegistryEntry {
    /// Reply sender for this session
    sender: mpsc::Sender<WgReplyPacket>,
    /// Client address (for logging/debugging)
    client_addr: std::net::SocketAddr,
}

/// VLESS reply registry
///
/// A concurrent registry that maps VLESS sessions to their reply senders.
/// This is used by the global WgReplyHandler to route decrypted packets
/// back to the correct VlessWgBridge.
///
/// # Thread Safety
///
/// Uses `DashMap` for lock-free concurrent access from multiple tasks.
pub struct VlessReplyRegistry {
    /// Sessions indexed by (tunnel_tag, local_ip, local_port, remote_ip, remote_port)
    sessions: DashMap<VlessReplyKey, RegistryEntry>,
    /// Statistics
    stats: RegistryStats,
}

/// Registry statistics
#[derive(Debug, Default)]
struct RegistryStats {
    /// Total sessions registered
    registered: std::sync::atomic::AtomicU64,
    /// Total sessions unregistered
    unregistered: std::sync::atomic::AtomicU64,
    /// Packets routed successfully
    packets_routed: std::sync::atomic::AtomicU64,
    /// Packets dropped (no session found)
    packets_dropped: std::sync::atomic::AtomicU64,
    /// Packets dropped (channel full)
    channel_full: std::sync::atomic::AtomicU64,
}

impl VlessReplyRegistry {
    /// Create a new empty registry
    pub fn new() -> Self {
        Self {
            sessions: DashMap::new(),
            stats: RegistryStats::default(),
        }
    }

    /// Register a VLESS session
    ///
    /// # Arguments
    ///
    /// * `key` - Session key (tunnel_tag, local_ip, local_port, remote_ip, remote_port)
    /// * `sender` - Reply sender for this session
    /// * `client_addr` - Client's source address (for logging)
    pub fn register(
        &self,
        key: VlessReplyKey,
        sender: mpsc::Sender<WgReplyPacket>,
        client_addr: std::net::SocketAddr,
    ) {
        debug!(
            "Registering VLESS session: tunnel={} {}:{} -> {}:{} (client={})",
            key.tunnel_tag, key.local_ip, key.local_port, key.remote_ip, key.remote_port, client_addr
        );

        self.sessions.insert(key, RegistryEntry { sender, client_addr });
        self.stats.registered.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Unregister a VLESS session
    ///
    /// # Returns
    ///
    /// `true` if the session was found and removed, `false` otherwise.
    pub fn unregister(&self, key: &VlessReplyKey) -> bool {
        let removed = self.sessions.remove(key).is_some();
        if removed {
            debug!(
                "Unregistered VLESS session: tunnel={} {}:{} -> {}:{}",
                key.tunnel_tag, key.local_ip, key.local_port, key.remote_ip, key.remote_port
            );
            self.stats.unregistered.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        removed
    }

    /// Try to route a reply packet to a VLESS session
    ///
    /// This method is called by the WgReplyHandler callback to check if
    /// a packet should be routed to a VLESS session.
    ///
    /// # Arguments
    ///
    /// * `tunnel_tag` - WireGuard tunnel tag
    /// * `packet` - Decrypted IP packet
    ///
    /// # Returns
    ///
    /// `true` if the packet was routed to a VLESS session, `false` otherwise
    /// (meaning the caller should use the default routing).
    pub fn try_route(&self, tunnel_tag: &str, packet: &[u8]) -> bool {
        // Parse the IP packet to extract source/destination
        let (src_ip, src_port, dst_ip, dst_port, protocol) = match parse_ip_packet(packet) {
            Some(tuple) => tuple,
            None => {
                trace!("Failed to parse IP packet for VLESS routing");
                return false;
            }
        };

        // Only handle TCP and UDP
        if protocol != 6 && protocol != 17 {
            return false;
        }

        // Build the key for lookup
        // Note: In a reply packet, src is the remote server, dst is our local IP
        let key = VlessReplyKey {
            tunnel_tag: tunnel_tag.to_string(),
            local_ip: dst_ip,
            local_port: dst_port,
            remote_ip: src_ip,
            remote_port: src_port,
        };

        // Look up the session
        if let Some(entry) = self.sessions.get(&key) {
            // Found a VLESS session - try to send the packet
            let reply = WgReplyPacket {
                tag: tunnel_tag.to_string(),
                packet: packet.to_vec(),
            };

            match entry.sender.try_send(reply) {
                Ok(()) => {
                    trace!(
                        "Routed reply to VLESS session: {}:{} <- {}:{} (tunnel={})",
                        dst_ip, dst_port, src_ip, src_port, tunnel_tag
                    );
                    self.stats.packets_routed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    true
                }
                Err(mpsc::error::TrySendError::Full(_)) => {
                    warn!(
                        "VLESS reply channel full: {}:{} <- {}:{} (tunnel={})",
                        dst_ip, dst_port, src_ip, src_port, tunnel_tag
                    );
                    self.stats.channel_full.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    // Return true to indicate we "handled" it (even though we dropped)
                    // This prevents the packet from being double-processed
                    true
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    warn!(
                        "VLESS reply channel closed: {}:{} <- {}:{} (tunnel={})",
                        dst_ip, dst_port, src_ip, src_port, tunnel_tag
                    );
                    // Session is gone, remove it
                    drop(entry); // Release the borrow before removing
                    self.sessions.remove(&key);
                    false
                }
            }
        } else {
            trace!(
                "No VLESS session for reply: {}:{} <- {}:{} (tunnel={})",
                dst_ip, dst_port, src_ip, src_port, tunnel_tag
            );
            false
        }
    }

    /// Get the number of active sessions
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Get statistics snapshot
    pub fn stats(&self) -> RegistryStatsSnapshot {
        RegistryStatsSnapshot {
            registered: self.stats.registered.load(std::sync::atomic::Ordering::Relaxed),
            unregistered: self.stats.unregistered.load(std::sync::atomic::Ordering::Relaxed),
            packets_routed: self.stats.packets_routed.load(std::sync::atomic::Ordering::Relaxed),
            packets_dropped: self.stats.packets_dropped.load(std::sync::atomic::Ordering::Relaxed),
            channel_full: self.stats.channel_full.load(std::sync::atomic::Ordering::Relaxed),
            active_sessions: self.sessions.len(),
        }
    }
}

impl Default for VlessReplyRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics snapshot
#[derive(Debug, Clone, serde::Serialize)]
pub struct RegistryStatsSnapshot {
    pub registered: u64,
    pub unregistered: u64,
    pub packets_routed: u64,
    pub packets_dropped: u64,
    pub channel_full: u64,
    pub active_sessions: usize,
}

/// Parse an IP packet to extract the 5-tuple
///
/// Returns (src_ip, src_port, dst_ip, dst_port, protocol) if successful.
fn parse_ip_packet(packet: &[u8]) -> Option<(IpAddr, u16, IpAddr, u16, u8)> {
    if packet.is_empty() {
        return None;
    }

    let version = packet[0] >> 4;

    match version {
        4 => parse_ipv4_packet(packet),
        6 => parse_ipv6_packet(packet),
        _ => None,
    }
}

fn parse_ipv4_packet(packet: &[u8]) -> Option<(IpAddr, u16, IpAddr, u16, u8)> {
    if packet.len() < 20 {
        return None;
    }

    let ihl = (packet[0] & 0x0f) as usize * 4;
    if packet.len() < ihl {
        return None;
    }

    let protocol = packet[9];
    let src_ip = IpAddr::V4(std::net::Ipv4Addr::new(
        packet[12], packet[13], packet[14], packet[15],
    ));
    let dst_ip = IpAddr::V4(std::net::Ipv4Addr::new(
        packet[16], packet[17], packet[18], packet[19],
    ));

    // Parse transport header for ports
    let transport = &packet[ihl..];
    if transport.len() < 4 {
        return None;
    }

    let src_port = u16::from_be_bytes([transport[0], transport[1]]);
    let dst_port = u16::from_be_bytes([transport[2], transport[3]]);

    Some((src_ip, src_port, dst_ip, dst_port, protocol))
}

fn parse_ipv6_packet(packet: &[u8]) -> Option<(IpAddr, u16, IpAddr, u16, u8)> {
    if packet.len() < 40 {
        return None;
    }

    let next_header = packet[6];

    let src_octets: [u8; 16] = packet[8..24].try_into().ok()?;
    let dst_octets: [u8; 16] = packet[24..40].try_into().ok()?;

    let src_ip = IpAddr::V6(std::net::Ipv6Addr::from(src_octets));
    let dst_ip = IpAddr::V6(std::net::Ipv6Addr::from(dst_octets));

    // Parse transport header for ports (assuming no extension headers)
    let transport = &packet[40..];
    if transport.len() < 4 {
        return None;
    }

    let src_port = u16::from_be_bytes([transport[0], transport[1]]);
    let dst_port = u16::from_be_bytes([transport[2], transport[3]]);

    Some((src_ip, src_port, dst_ip, dst_port, next_header))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr};

    #[test]
    fn test_registry_register_unregister() {
        let registry = VlessReplyRegistry::new();
        let (tx, _rx) = mpsc::channel(10);

        let key = VlessReplyKey::new(
            "warp-1".to_string(),
            IpAddr::V4(Ipv4Addr::new(172, 16, 0, 2)),
            12345,
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            443,
        );

        let client_addr: SocketAddr = "192.168.1.100:54321".parse().unwrap();

        registry.register(key.clone(), tx, client_addr);
        assert_eq!(registry.session_count(), 1);

        assert!(registry.unregister(&key));
        assert_eq!(registry.session_count(), 0);

        // Unregister again should return false
        assert!(!registry.unregister(&key));
    }

    #[test]
    fn test_parse_ipv4_tcp_packet() {
        // Minimal IPv4 TCP packet header
        let mut packet = vec![
            0x45, 0x00, 0x00, 0x28, // Version, IHL, TOS, Length
            0x00, 0x00, 0x00, 0x00, // ID, Flags, Fragment
            0x40, 0x06, 0x00, 0x00, // TTL, Protocol (TCP=6), Checksum
            0x01, 0x01, 0x01, 0x01, // Src IP: 1.1.1.1
            0xac, 0x10, 0x00, 0x02, // Dst IP: 172.16.0.2
            // TCP header
            0x01, 0xbb, 0x30, 0x39, // Src port: 443, Dst port: 12345
        ];

        let result = parse_ip_packet(&packet);
        assert!(result.is_some());

        let (src_ip, src_port, dst_ip, dst_port, protocol) = result.unwrap();
        assert_eq!(src_ip, IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
        assert_eq!(src_port, 443);
        assert_eq!(dst_ip, IpAddr::V4(Ipv4Addr::new(172, 16, 0, 2)));
        assert_eq!(dst_port, 12345);
        assert_eq!(protocol, 6); // TCP
    }
}
