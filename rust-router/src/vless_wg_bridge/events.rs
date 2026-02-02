//! Event types for the VLESS-WG Bridge Event Bus architecture
//!
//! This module defines the core event types used for communication between
//! the public interface and the smoltcp shard tasks. The Event Bus pattern
//! eliminates `Arc<Mutex<SmoltcpBridge>>` lock contention by having a single
//! task own the smoltcp instance and process events from a channel.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────────┐
//! │  Public API Layer                                                            │
//! │  ┌─────────────────────────────────────────────────────────────────────────┐ │
//! │  │  handle_tcp_connection()  handle_udp_connection()  send_raw_udp_packet()│ │
//! │  └────────────────────────────────┬────────────────────────────────────────┘ │
//! │                                   │                                          │
//! │                                   │ BridgeEvent (via mpsc::channel)          │
//! │                                   ▼                                          │
//! │  ┌─────────────────────────────────────────────────────────────────────────┐ │
//! │  │  SmoltcpShard (owns smoltcp, single task)                               │ │
//! │  │  - Receives BridgeEvent                                                  │ │
//! │  │  - Sends TcpReply/UdpReply back via reply channels                       │ │
//! │  └─────────────────────────────────────────────────────────────────────────┘ │
//! └─────────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Event Priority
//!
//! Events have priority levels to ensure critical operations (like WG packet
//! processing) are handled before less time-sensitive operations:
//!
//! | Priority | Event Types | Reason |
//! |----------|-------------|--------|
//! | 0 (highest) | `WgPacket` | TCP retransmit timing sensitive |
//! | 1 | `UdpSend` (DNS) | DNS latency affects user experience |
//! | 2 | `UdpSend`, `UdpClose` | UDP is typically latency-sensitive |
//! | 3 | `TcpConnect`, `TcpData` | TCP has built-in retransmission |
//! | 4 | `TcpCloseWrite`, `TcpAbort` | Cleanup can be deferred |
//! | 5 (lowest) | `Shutdown` | Graceful shutdown |
//!
//! # Example
//!
//! ```ignore
//! use rust_router::vless_wg_bridge::events::{BridgeEvent, TcpReply, UdpSessionKey};
//! use tokio::sync::mpsc;
//!
//! // Create a reply channel for TCP connection
//! let (reply_tx, mut reply_rx) = mpsc::channel(32);
//!
//! // Send a TCP connect event to the shard
//! let event = BridgeEvent::TcpConnect {
//!     conn_id: 42,
//!     dest_addr: "93.184.216.34:80".parse().unwrap(),
//!     reply_tx,
//! };
//!
//! // Wait for connection result
//! match reply_rx.recv().await {
//!     Some(TcpReply::Connected) => println!("Connected!"),
//!     Some(TcpReply::ConnectFailed { error }) => println!("Failed: {}", error),
//!     _ => {}
//! }
//! ```

use std::hash::{Hash, Hasher};
use std::net::{IpAddr, SocketAddr};

use bytes::Bytes;
use tokio::sync::mpsc;

use crate::netbridge::NetBridgeError as BridgeError;

// =============================================================================
// Constants
// =============================================================================

/// Standard DNS port (UDP and TCP)
pub const DNS_PORT: u16 = 53;

// =============================================================================
// Event Priority
// =============================================================================

/// Event priority levels (lower = higher priority)
///
/// These priorities are used by the shard's event loop to process critical
/// events first. The `biased` select! macro in the shard loop uses these
/// priorities to determine processing order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum EventPriority {
    /// Highest priority - `WireGuard` packets for TCP retransmit timing
    WgPacket = 0,
    /// High priority - DNS UDP for low latency
    UdpDns = 1,
    /// Medium-high priority - General UDP traffic
    Udp = 2,
    /// Medium priority - TCP data transfer
    Tcp = 3,
    /// Low priority - Connection cleanup
    Cleanup = 4,
    /// Lowest priority - Shutdown signal
    Shutdown = 5,
}

impl EventPriority {
    /// Returns true if this priority is higher than another
    #[must_use]
    #[inline]
    pub fn is_higher_than(self, other: Self) -> bool {
        (self as u8) < (other as u8)
    }

    /// Returns true if this is the highest priority (`WgPacket`)
    #[must_use]
    #[inline]
    pub fn is_highest(self) -> bool {
        self == Self::WgPacket
    }
}

// =============================================================================
// UDP Session Key
// =============================================================================

/// Five-tuple key identifying a UDP session
///
/// This is used for routing UDP packets to the correct session and for
/// shard selection via consistent hashing. The five-tuple ensures that
/// all packets for a given flow are processed by the same shard.
///
/// # Hash Stability
///
/// The `Hash` implementation uses a deterministic order of fields to ensure
/// consistent hashing across different runs. This is critical for shard
/// assignment stability.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct UdpSessionKey {
    /// Source IP address (VLESS client's tunnel IP)
    pub src_ip: IpAddr,
    /// Source port (VLESS client's ephemeral port)
    pub src_port: u16,
    /// Destination IP address (remote server)
    pub dest_ip: IpAddr,
    /// Destination port (remote server port)
    pub dest_port: u16,
    /// Protocol identifier (always UDP, included for potential future extension)
    pub protocol: u8,
}

impl UdpSessionKey {
    /// UDP protocol number
    pub const PROTOCOL_UDP: u8 = 17;

    /// Create a new UDP session key from addresses
    #[must_use]
    pub fn new(src_addr: SocketAddr, dest_addr: SocketAddr) -> Self {
        Self {
            src_ip: src_addr.ip(),
            src_port: src_addr.port(),
            dest_ip: dest_addr.ip(),
            dest_port: dest_addr.port(),
            protocol: Self::PROTOCOL_UDP,
        }
    }

    /// Create a new UDP session key from individual components
    #[must_use]
    pub fn from_parts(src_ip: IpAddr, src_port: u16, dest_ip: IpAddr, dest_port: u16) -> Self {
        Self {
            src_ip,
            src_port,
            dest_ip,
            dest_port,
            protocol: Self::PROTOCOL_UDP,
        }
    }

    /// Get the source address as a `SocketAddr`
    #[must_use]
    pub fn src_addr(&self) -> SocketAddr {
        SocketAddr::new(self.src_ip, self.src_port)
    }

    /// Get the destination address as a `SocketAddr`
    #[must_use]
    pub fn dest_addr(&self) -> SocketAddr {
        SocketAddr::new(self.dest_ip, self.dest_port)
    }

    /// Check if this is a DNS query (destination port 53)
    #[must_use]
    #[inline]
    pub fn is_dns(&self) -> bool {
        self.dest_port == DNS_PORT
    }

    /// Generate a hash value for shard selection
    ///
    /// This uses the same hashing as the `Hash` trait but returns a `u64`
    /// directly for convenience in shard selection.
    ///
    /// # Stability Note
    ///
    /// This uses `std::collections::hash_map::DefaultHasher` which is **not**
    /// guaranteed to be stable across Rust versions. However, for shard selection
    /// this is acceptable because:
    /// 1. Shard assignment only needs to be consistent within a single process
    /// 2. Session affinity is maintained by the session maps, not the hash
    /// 3. A different hash after restart just means different shard assignment
    ///
    /// If cross-process or persistent hash stability is ever needed, consider
    /// using `ahash` or `xxhash` instead.
    #[must_use]
    pub fn shard_hash(&self) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        let mut hasher = DefaultHasher::new();
        self.hash(&mut hasher);
        hasher.finish()
    }
}

impl Hash for UdpSessionKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // Hash in a deterministic order for consistent shard assignment
        self.protocol.hash(state);
        // Hash IP addresses as bytes for consistency
        match self.src_ip {
            IpAddr::V4(addr) => {
                0u8.hash(state); // IPv4 marker
                addr.octets().hash(state);
            }
            IpAddr::V6(addr) => {
                1u8.hash(state); // IPv6 marker
                addr.octets().hash(state);
            }
        }
        self.src_port.hash(state);
        match self.dest_ip {
            IpAddr::V4(addr) => {
                0u8.hash(state);
                addr.octets().hash(state);
            }
            IpAddr::V6(addr) => {
                1u8.hash(state);
                addr.octets().hash(state);
            }
        }
        self.dest_port.hash(state);
    }
}

impl std::fmt::Display for UdpSessionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "UDP {}:{} -> {}:{}",
            self.src_ip, self.src_port, self.dest_ip, self.dest_port
        )
    }
}

// =============================================================================
// TCP Reply
// =============================================================================

/// Reply events sent from the smoltcp shard back to the TCP handler task
///
/// These events represent the lifecycle of a TCP connection as seen from
/// the smoltcp side. The handler task translates these into appropriate
/// actions on the VLESS stream.
#[derive(Debug)]
pub enum TcpReply {
    /// TCP connection established successfully
    ///
    /// The three-way handshake completed and the connection is ready for data.
    Connected,

    /// TCP connection failed to establish
    ///
    /// This can happen due to timeout, connection refused, or network errors.
    ConnectFailed {
        /// The error that caused the connection to fail
        error: BridgeError,
    },

    /// Data received from the remote server
    ///
    /// This data should be forwarded to the VLESS client.
    Data {
        /// The received data
        data: Bytes,
    },

    /// Remote server closed the connection (FIN received)
    ///
    /// This indicates a half-close - the server won't send more data but
    /// may still accept data from the client.
    RemoteClosed,

    /// Connection fully closed (both directions)
    ///
    /// All resources for this connection can be released.
    Closed,

    /// An error occurred on the connection
    ///
    /// The connection should be considered dead after this.
    Error {
        /// The error that occurred
        error: BridgeError,
    },
}

impl TcpReply {
    /// Check if this reply indicates the connection is still usable
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::ConnectFailed { .. } | Self::Closed | Self::Error { .. }
        )
    }

    /// Get the error if this is an error reply
    #[must_use]
    pub fn error(&self) -> Option<&BridgeError> {
        match self {
            Self::ConnectFailed { error } | Self::Error { error } => Some(error),
            _ => None,
        }
    }
}

// =============================================================================
// UDP Reply
// =============================================================================

/// Reply events sent from the smoltcp shard back to the UDP handler
///
/// Unlike TCP, UDP is connectionless, so each reply is a self-contained
/// datagram with its source address.
#[derive(Debug, Clone)]
pub struct UdpReply {
    /// Source address of the reply (remote server that sent this packet)
    pub source: SocketAddr,
    /// The reply data
    pub data: Bytes,
}

impl UdpReply {
    /// Create a new UDP reply
    #[must_use]
    pub fn new(source: SocketAddr, data: Bytes) -> Self {
        Self { source, data }
    }

    /// Get the size of the data
    #[must_use]
    #[inline]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if the data is empty
    #[must_use]
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

// =============================================================================
// Bridge Event
// =============================================================================

/// Events sent to smoltcp shard tasks
///
/// These events are processed by the shard's main loop. Each event type
/// has an associated priority that determines processing order when multiple
/// events are queued.
///
/// # Thread Safety
///
/// `BridgeEvent` is `Send` but not `Clone` because it contains channels.
/// Once sent to a shard, ownership is transferred.
#[derive(Debug)]
pub enum BridgeEvent {
    // =========================================================================
    // TCP Events (Priority 3-4)
    // =========================================================================
    /// Request to establish a TCP connection
    ///
    /// The shard will create a smoltcp TCP socket and attempt to connect
    /// to the destination. Results are sent via `reply_tx`.
    TcpConnect {
        /// Unique connection identifier (monotonic counter from `VlessConnectionId`)
        conn_id: u64,
        /// Destination address to connect to
        dest_addr: SocketAddr,
        /// Channel for sending connection status and data back
        reply_tx: mpsc::Sender<TcpReply>,
    },

    /// Send data on an established TCP connection
    ///
    /// The data will be queued in the smoltcp socket's send buffer.
    /// If the buffer is full, the shard will apply backpressure.
    TcpData {
        /// Connection identifier
        conn_id: u64,
        /// Data to send
        data: Bytes,
    },

    /// Close the write side of a TCP connection (send FIN)
    ///
    /// This initiates a half-close, allowing the remote to send remaining
    /// data while indicating no more data will be sent from this side.
    TcpCloseWrite {
        /// Connection identifier
        conn_id: u64,
    },

    /// Abort a TCP connection immediately (send RST)
    ///
    /// This forcefully closes the connection without graceful shutdown.
    /// Use this for error conditions or cleanup.
    TcpAbort {
        /// Connection identifier
        conn_id: u64,
    },

    // =========================================================================
    // UDP Events (Priority 1-2)
    // =========================================================================
    /// Send a UDP datagram
    ///
    /// For the first packet of a new session, `reply_tx` should be `Some`
    /// to establish the reply channel. Subsequent packets can use `None`
    /// since the session is already registered.
    UdpSend {
        /// Session key (5-tuple)
        session_key: UdpSessionKey,
        /// Destination address
        dest: SocketAddr,
        /// Data to send
        data: Bytes,
        /// Reply channel (only needed for first packet of a session)
        reply_tx: Option<mpsc::Sender<UdpReply>>,
    },

    /// Close a UDP session
    ///
    /// This releases resources associated with the session. The session
    /// may also be closed automatically via timeout.
    UdpClose {
        /// Session key
        session_key: UdpSessionKey,
    },

    // =========================================================================
    // WireGuard Events (Priority 0 - Highest)
    // =========================================================================
    /// `WireGuard` packet received from the egress tunnel
    ///
    /// This is the highest priority event because TCP retransmission timing
    /// is sensitive to packet processing delays. The packet should be fed
    /// to smoltcp immediately via `feed_rx_packet()`.
    WgPacket {
        /// Raw IP packet data (decrypted from `WireGuard`)
        data: Bytes,
    },

    // =========================================================================
    // Control Events (Priority 5 - Lowest)
    // =========================================================================
    /// Graceful shutdown request
    ///
    /// The shard should stop accepting new connections, drain existing
    /// connections, and exit its event loop.
    Shutdown,
}

impl BridgeEvent {
    /// Get the priority of this event
    ///
    /// Lower values indicate higher priority. This is used by the shard's
    /// event loop to process critical events first.
    #[must_use]
    pub fn priority(&self) -> EventPriority {
        match self {
            Self::WgPacket { .. } => EventPriority::WgPacket,
            Self::UdpSend { session_key, .. } if session_key.is_dns() => EventPriority::UdpDns,
            Self::UdpSend { .. } | Self::UdpClose { .. } => EventPriority::Udp,
            Self::TcpConnect { .. } | Self::TcpData { .. } => EventPriority::Tcp,
            Self::TcpCloseWrite { .. } | Self::TcpAbort { .. } => EventPriority::Cleanup,
            Self::Shutdown => EventPriority::Shutdown,
        }
    }

    /// Check if this is a high-priority event (`WgPacket` or DNS)
    #[must_use]
    #[inline]
    pub fn is_high_priority(&self) -> bool {
        matches!(
            self.priority(),
            EventPriority::WgPacket | EventPriority::UdpDns
        )
    }

    /// Get the connection ID if this is a TCP event
    #[must_use]
    pub fn tcp_conn_id(&self) -> Option<u64> {
        match self {
            Self::TcpConnect { conn_id, .. }
            | Self::TcpData { conn_id, .. }
            | Self::TcpCloseWrite { conn_id, .. }
            | Self::TcpAbort { conn_id, .. } => Some(*conn_id),
            _ => None,
        }
    }

    /// Get the session key if this is a UDP event
    #[must_use]
    pub fn udp_session_key(&self) -> Option<&UdpSessionKey> {
        match self {
            Self::UdpSend { session_key, .. } | Self::UdpClose { session_key, .. } => {
                Some(session_key)
            }
            _ => None,
        }
    }

    /// Create a new TCP connect event
    #[must_use]
    pub fn tcp_connect(
        conn_id: u64,
        dest_addr: SocketAddr,
        reply_tx: mpsc::Sender<TcpReply>,
    ) -> Self {
        Self::TcpConnect {
            conn_id,
            dest_addr,
            reply_tx,
        }
    }

    /// Create a new TCP data event
    #[must_use]
    pub fn tcp_data(conn_id: u64, data: Bytes) -> Self {
        Self::TcpData { conn_id, data }
    }

    /// Create a new TCP close write event
    #[must_use]
    pub fn tcp_close_write(conn_id: u64) -> Self {
        Self::TcpCloseWrite { conn_id }
    }

    /// Create a new TCP abort event
    #[must_use]
    pub fn tcp_abort(conn_id: u64) -> Self {
        Self::TcpAbort { conn_id }
    }

    /// Create a new UDP send event
    #[must_use]
    pub fn udp_send(
        session_key: UdpSessionKey,
        dest: SocketAddr,
        data: Bytes,
        reply_tx: Option<mpsc::Sender<UdpReply>>,
    ) -> Self {
        Self::UdpSend {
            session_key,
            dest,
            data,
            reply_tx,
        }
    }

    /// Create a new UDP close event
    #[must_use]
    pub fn udp_close(session_key: UdpSessionKey) -> Self {
        Self::UdpClose { session_key }
    }

    /// Create a new WG packet event
    #[must_use]
    pub fn wg_packet(data: Bytes) -> Self {
        Self::WgPacket { data }
    }
}

impl std::fmt::Display for BridgeEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TcpConnect {
                conn_id, dest_addr, ..
            } => {
                write!(f, "TcpConnect(conn={conn_id}, dest={dest_addr})")
            }
            Self::TcpData { conn_id, data } => {
                let len = data.len();
                write!(f, "TcpData(conn={conn_id}, len={len})")
            }
            Self::TcpCloseWrite { conn_id } => {
                write!(f, "TcpCloseWrite(conn={conn_id})")
            }
            Self::TcpAbort { conn_id } => {
                write!(f, "TcpAbort(conn={conn_id})")
            }
            Self::UdpSend {
                session_key, data, ..
            } => {
                let len = data.len();
                write!(f, "UdpSend({session_key}, len={len})")
            }
            Self::UdpClose { session_key } => {
                write!(f, "UdpClose({session_key})")
            }
            Self::WgPacket { data } => {
                let len = data.len();
                write!(f, "WgPacket(len={len})")
            }
            Self::Shutdown => write!(f, "Shutdown"),
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::hash_map::DefaultHasher;
    use std::net::{Ipv4Addr, Ipv6Addr};

    // -------------------------------------------------------------------------
    // EventPriority tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_event_priority_ordering() {
        assert!(EventPriority::WgPacket.is_higher_than(EventPriority::UdpDns));
        assert!(EventPriority::UdpDns.is_higher_than(EventPriority::Udp));
        assert!(EventPriority::Udp.is_higher_than(EventPriority::Tcp));
        assert!(EventPriority::Tcp.is_higher_than(EventPriority::Cleanup));
        assert!(EventPriority::Cleanup.is_higher_than(EventPriority::Shutdown));

        assert!(!EventPriority::Shutdown.is_higher_than(EventPriority::WgPacket));
    }

    #[test]
    fn test_event_priority_is_highest() {
        assert!(EventPriority::WgPacket.is_highest());
        assert!(!EventPriority::UdpDns.is_highest());
        assert!(!EventPriority::Shutdown.is_highest());
    }

    // -------------------------------------------------------------------------
    // UdpSessionKey tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_udp_session_key_new() {
        let src: SocketAddr = "192.168.1.100:12345".parse().unwrap();
        let dest: SocketAddr = "8.8.8.8:53".parse().unwrap();

        let key = UdpSessionKey::new(src, dest);

        assert_eq!(key.src_ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)));
        assert_eq!(key.src_port, 12345);
        assert_eq!(key.dest_ip, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        assert_eq!(key.dest_port, 53);
        assert_eq!(key.protocol, UdpSessionKey::PROTOCOL_UDP);
    }

    #[test]
    fn test_udp_session_key_from_parts() {
        let key = UdpSessionKey::from_parts(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            5000,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            8080,
        );

        assert_eq!(key.src_addr(), "10.0.0.1:5000".parse().unwrap());
        assert_eq!(key.dest_addr(), "10.0.0.2:8080".parse().unwrap());
    }

    #[test]
    fn test_udp_session_key_ipv6() {
        let src: SocketAddr = "[2001:db8::1]:12345".parse().unwrap();
        let dest: SocketAddr = "[2606:4700:4700::1111]:53".parse().unwrap();

        let key = UdpSessionKey::new(src, dest);

        assert!(matches!(key.src_ip, IpAddr::V6(_)));
        assert!(matches!(key.dest_ip, IpAddr::V6(_)));
        assert_eq!(key.src_addr(), src);
        assert_eq!(key.dest_addr(), dest);
    }

    #[test]
    fn test_udp_session_key_is_dns() {
        let dns_key = UdpSessionKey::from_parts(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            5000,
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            53,
        );
        assert!(dns_key.is_dns());

        let non_dns_key = UdpSessionKey::from_parts(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            5000,
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            443,
        );
        assert!(!non_dns_key.is_dns());
    }

    #[test]
    fn test_udp_session_key_hash_consistency() {
        let key1 = UdpSessionKey::from_parts(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            12345,
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            53,
        );
        let key2 = UdpSessionKey::from_parts(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            12345,
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            53,
        );

        // Same keys should have same hash
        assert_eq!(key1.shard_hash(), key2.shard_hash());

        // Hash via trait should match
        fn compute_hash<T: Hash>(t: &T) -> u64 {
            let mut hasher = DefaultHasher::new();
            t.hash(&mut hasher);
            hasher.finish()
        }

        assert_eq!(compute_hash(&key1), compute_hash(&key2));
    }

    #[test]
    fn test_udp_session_key_hash_different_keys() {
        let key1 = UdpSessionKey::from_parts(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            12345,
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            53,
        );
        let key2 = UdpSessionKey::from_parts(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 101)), // Different source IP
            12345,
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            53,
        );

        // Different keys should (very likely) have different hashes
        assert_ne!(key1.shard_hash(), key2.shard_hash());
    }

    #[test]
    fn test_udp_session_key_hash_ipv4_vs_ipv6() {
        let key_v4 = UdpSessionKey::from_parts(
            IpAddr::V4(Ipv4Addr::new(0, 0, 0, 1)),
            1000,
            IpAddr::V4(Ipv4Addr::new(0, 0, 0, 2)),
            2000,
        );
        let key_v6 = UdpSessionKey::from_parts(
            IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
            1000,
            IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 2)),
            2000,
        );

        // IPv4 and IPv6 keys should have different hashes due to marker byte
        assert_ne!(key_v4.shard_hash(), key_v6.shard_hash());
    }

    #[test]
    fn test_udp_session_key_display() {
        let key = UdpSessionKey::from_parts(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            12345,
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            53,
        );

        let display = format!("{}", key);
        assert!(display.contains("UDP"));
        assert!(display.contains("192.168.1.100:12345"));
        assert!(display.contains("8.8.8.8:53"));
    }

    // -------------------------------------------------------------------------
    // TcpReply tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_tcp_reply_is_terminal() {
        assert!(!TcpReply::Connected.is_terminal());
        assert!(!TcpReply::Data { data: Bytes::new() }.is_terminal());
        assert!(!TcpReply::RemoteClosed.is_terminal());

        assert!(TcpReply::Closed.is_terminal());
        assert!(TcpReply::ConnectFailed {
            error: BridgeError::ConnectionTimeout
        }
        .is_terminal());
        assert!(TcpReply::Error {
            error: BridgeError::ConnectionRefused
        }
        .is_terminal());
    }

    #[test]
    fn test_tcp_reply_error() {
        let connected = TcpReply::Connected;
        assert!(connected.error().is_none());

        let failed = TcpReply::ConnectFailed {
            error: BridgeError::ConnectionTimeout,
        };
        assert!(failed.error().is_some());

        let error = TcpReply::Error {
            error: BridgeError::ConnectionRefused,
        };
        assert!(error.error().is_some());
    }

    // -------------------------------------------------------------------------
    // UdpReply tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_udp_reply_new() {
        let source: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let data = Bytes::from_static(b"DNS response");

        let reply = UdpReply::new(source, data.clone());

        assert_eq!(reply.source, source);
        assert_eq!(reply.data, data);
        assert_eq!(reply.len(), 12);
        assert!(!reply.is_empty());
    }

    #[test]
    fn test_udp_reply_empty() {
        let reply = UdpReply::new("0.0.0.0:0".parse().unwrap(), Bytes::new());
        assert!(reply.is_empty());
        assert_eq!(reply.len(), 0);
    }

    // -------------------------------------------------------------------------
    // BridgeEvent tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_bridge_event_priority() {
        let wg = BridgeEvent::wg_packet(Bytes::new());
        assert_eq!(wg.priority(), EventPriority::WgPacket);
        assert!(wg.is_high_priority());

        // DNS UDP should be high priority
        let dns_key = UdpSessionKey::from_parts(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            5000,
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            53,
        );
        let dns_udp =
            BridgeEvent::udp_send(dns_key, "8.8.8.8:53".parse().unwrap(), Bytes::new(), None);
        assert_eq!(dns_udp.priority(), EventPriority::UdpDns);
        assert!(dns_udp.is_high_priority());

        // Non-DNS UDP
        let regular_key = UdpSessionKey::from_parts(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            5000,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            8080,
        );
        let regular_udp = BridgeEvent::udp_send(
            regular_key.clone(),
            "10.0.0.2:8080".parse().unwrap(),
            Bytes::new(),
            None,
        );
        assert_eq!(regular_udp.priority(), EventPriority::Udp);
        assert!(!regular_udp.is_high_priority());

        // UDP close
        let udp_close = BridgeEvent::udp_close(regular_key);
        assert_eq!(udp_close.priority(), EventPriority::Udp);

        // TCP events
        let (tx, _rx) = mpsc::channel(1);
        let tcp_connect = BridgeEvent::tcp_connect(1, "10.0.0.1:80".parse().unwrap(), tx);
        assert_eq!(tcp_connect.priority(), EventPriority::Tcp);

        let tcp_data = BridgeEvent::tcp_data(1, Bytes::new());
        assert_eq!(tcp_data.priority(), EventPriority::Tcp);

        let tcp_close = BridgeEvent::tcp_close_write(1);
        assert_eq!(tcp_close.priority(), EventPriority::Cleanup);

        let tcp_abort = BridgeEvent::tcp_abort(1);
        assert_eq!(tcp_abort.priority(), EventPriority::Cleanup);

        // Shutdown
        assert_eq!(BridgeEvent::Shutdown.priority(), EventPriority::Shutdown);
    }

    #[test]
    fn test_bridge_event_tcp_conn_id() {
        let (tx, _rx) = mpsc::channel(1);
        let connect = BridgeEvent::tcp_connect(42, "10.0.0.1:80".parse().unwrap(), tx);
        assert_eq!(connect.tcp_conn_id(), Some(42));

        let data = BridgeEvent::tcp_data(123, Bytes::new());
        assert_eq!(data.tcp_conn_id(), Some(123));

        let close = BridgeEvent::tcp_close_write(456);
        assert_eq!(close.tcp_conn_id(), Some(456));

        let abort = BridgeEvent::tcp_abort(789);
        assert_eq!(abort.tcp_conn_id(), Some(789));

        // Non-TCP events should return None
        let wg = BridgeEvent::wg_packet(Bytes::new());
        assert!(wg.tcp_conn_id().is_none());

        assert!(BridgeEvent::Shutdown.tcp_conn_id().is_none());
    }

    #[test]
    fn test_bridge_event_udp_session_key() {
        let key = UdpSessionKey::from_parts(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            5000,
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            53,
        );

        let send = BridgeEvent::udp_send(
            key.clone(),
            "8.8.8.8:53".parse().unwrap(),
            Bytes::new(),
            None,
        );
        assert_eq!(send.udp_session_key(), Some(&key));

        let close = BridgeEvent::udp_close(key.clone());
        assert_eq!(close.udp_session_key(), Some(&key));

        // Non-UDP events should return None
        let wg = BridgeEvent::wg_packet(Bytes::new());
        assert!(wg.udp_session_key().is_none());

        let (tx, _rx) = mpsc::channel(1);
        let tcp = BridgeEvent::tcp_connect(1, "10.0.0.1:80".parse().unwrap(), tx);
        assert!(tcp.udp_session_key().is_none());
    }

    #[test]
    fn test_bridge_event_display() {
        let (tx, _rx) = mpsc::channel(1);

        let connect = BridgeEvent::tcp_connect(42, "10.0.0.1:80".parse().unwrap(), tx);
        let display = format!("{}", connect);
        assert!(display.contains("TcpConnect"));
        assert!(display.contains("42"));
        assert!(display.contains("10.0.0.1:80"));

        let data = BridgeEvent::tcp_data(123, Bytes::from_static(b"hello"));
        let display = format!("{}", data);
        assert!(display.contains("TcpData"));
        assert!(display.contains("123"));
        assert!(display.contains("5")); // length

        let close = BridgeEvent::tcp_close_write(456);
        assert!(format!("{}", close).contains("TcpCloseWrite"));

        let abort = BridgeEvent::tcp_abort(789);
        assert!(format!("{}", abort).contains("TcpAbort"));

        let key = UdpSessionKey::from_parts(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            5000,
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            53,
        );
        let udp_send = BridgeEvent::udp_send(
            key.clone(),
            "8.8.8.8:53".parse().unwrap(),
            Bytes::new(),
            None,
        );
        let display = format!("{}", udp_send);
        assert!(display.contains("UdpSend"));

        let udp_close = BridgeEvent::udp_close(key);
        assert!(format!("{}", udp_close).contains("UdpClose"));

        let wg = BridgeEvent::wg_packet(Bytes::from_static(b"packet data"));
        let display = format!("{}", wg);
        assert!(display.contains("WgPacket"));
        assert!(display.contains("11")); // length

        assert!(format!("{}", BridgeEvent::Shutdown).contains("Shutdown"));
    }

    #[test]
    fn test_bridge_event_constructors() {
        // Test all constructor methods produce expected variants
        let (tx, _rx) = mpsc::channel::<TcpReply>(1);
        let (udp_tx, _udp_rx) = mpsc::channel::<UdpReply>(1);

        let _ = BridgeEvent::tcp_connect(1, "10.0.0.1:80".parse().unwrap(), tx);
        let _ = BridgeEvent::tcp_data(1, Bytes::from_static(b"data"));
        let _ = BridgeEvent::tcp_close_write(1);
        let _ = BridgeEvent::tcp_abort(1);

        let key = UdpSessionKey::from_parts(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            5000,
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            53,
        );
        let _ = BridgeEvent::udp_send(
            key.clone(),
            "8.8.8.8:53".parse().unwrap(),
            Bytes::new(),
            Some(udp_tx),
        );
        let _ = BridgeEvent::udp_close(key);
        let _ = BridgeEvent::wg_packet(Bytes::from_static(b"ip packet"));
    }
}
