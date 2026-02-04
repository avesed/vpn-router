//! Core types for the netbridge module
//!
//! This module defines the fundamental types used throughout the netbridge
//! implementations, including IP packet wrappers, session identifiers, and
//! reply packet structures.
//!
//! # Design Principles
//!
//! - **Zero-copy**: Uses `bytes::Bytes` for efficient packet handling
//! - **Parse-on-demand**: Caches parsed fields lazily to minimize overhead
//! - **Type safety**: Strong types prevent mixing up different identifiers
//!
//! # Key Types
//!
//! - [`IpPacket`]: Wrapper around raw IP packet data with parsing utilities
//! - [`FiveTuple`]: 5-tuple session identifier (src/dst addr, src/dst port, protocol)
//! - [`IpProtocol`]: Type-safe IP protocol enum
//! - [`ReplyPacket`]: Reply packet with peer routing information
//! - [`SessionId`]: Unique session identifier

use bytes::Bytes;
use std::fmt;
use std::hash::Hash;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};

// =============================================================================
// Session Identifier
// =============================================================================

/// Unique identifier for a session
///
/// Session IDs are monotonically increasing and unique within a bridge instance.
/// They provide a stable reference to sessions independent of their 5-tuple.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SessionId(pub u64);

impl SessionId {
    /// Create a new session ID from a raw value
    #[inline]
    #[must_use]
    pub const fn new(id: u64) -> Self {
        Self(id)
    }

    /// Get the raw ID value
    #[inline]
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "session-{}", self.0)
    }
}

impl From<u64> for SessionId {
    fn from(id: u64) -> Self {
        Self(id)
    }
}

/// Thread-safe session ID generator
#[derive(Debug, Default)]
pub struct SessionIdGenerator {
    next: AtomicU64,
}

impl SessionIdGenerator {
    /// Create a new generator starting from 1
    #[must_use]
    pub const fn new() -> Self {
        Self {
            next: AtomicU64::new(1),
        }
    }

    /// Generate the next session ID
    #[inline]
    pub fn next(&self) -> SessionId {
        SessionId(self.next.fetch_add(1, Ordering::Relaxed))
    }
}

// =============================================================================
// IP Protocol
// =============================================================================

/// IP protocol numbers
///
/// Type-safe representation of common IP protocol numbers.
/// Provides convenient constructors and checks for TCP, UDP, and ICMP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IpProtocol {
    /// ICMP (Internet Control Message Protocol)
    Icmp,
    /// TCP (Transmission Control Protocol)
    Tcp,
    /// UDP (User Datagram Protocol)
    Udp,
    /// ICMPv6 (Internet Control Message Protocol for IPv6)
    Icmpv6,
    /// Other protocol with raw number
    Other(u8),
}

impl IpProtocol {
    /// ICMP protocol number (1)
    pub const ICMP: u8 = 1;
    /// TCP protocol number (6)
    pub const TCP: u8 = 6;
    /// UDP protocol number (17)
    pub const UDP: u8 = 17;
    /// ICMPv6 protocol number (58)
    pub const ICMPV6: u8 = 58;

    /// Create from raw protocol number
    #[inline]
    #[must_use]
    pub const fn from_u8(proto: u8) -> Self {
        match proto {
            Self::ICMP => Self::Icmp,
            Self::TCP => Self::Tcp,
            Self::UDP => Self::Udp,
            Self::ICMPV6 => Self::Icmpv6,
            other => Self::Other(other),
        }
    }

    /// Convert to raw protocol number
    #[inline]
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Icmp => Self::ICMP,
            Self::Tcp => Self::TCP,
            Self::Udp => Self::UDP,
            Self::Icmpv6 => Self::ICMPV6,
            Self::Other(n) => n,
        }
    }

    /// Check if this is TCP
    #[inline]
    #[must_use]
    pub const fn is_tcp(self) -> bool {
        matches!(self, Self::Tcp)
    }

    /// Check if this is UDP
    #[inline]
    #[must_use]
    pub const fn is_udp(self) -> bool {
        matches!(self, Self::Udp)
    }

    /// Check if this is ICMP (v4 or v6)
    #[inline]
    #[must_use]
    pub const fn is_icmp(self) -> bool {
        matches!(self, Self::Icmp | Self::Icmpv6)
    }

    /// Check if this protocol uses ports (TCP or UDP)
    #[inline]
    #[must_use]
    pub const fn has_ports(self) -> bool {
        matches!(self, Self::Tcp | Self::Udp)
    }
}

impl fmt::Display for IpProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Icmp => write!(f, "ICMP"),
            Self::Tcp => write!(f, "TCP"),
            Self::Udp => write!(f, "UDP"),
            Self::Icmpv6 => write!(f, "ICMPv6"),
            Self::Other(n) => write!(f, "proto-{n}"),
        }
    }
}

impl From<u8> for IpProtocol {
    fn from(proto: u8) -> Self {
        Self::from_u8(proto)
    }
}

impl From<IpProtocol> for u8 {
    fn from(proto: IpProtocol) -> Self {
        proto.as_u8()
    }
}

// =============================================================================
// Five Tuple
// =============================================================================

/// 5-tuple identifying a TCP/UDP session
///
/// A 5-tuple uniquely identifies a network session based on:
/// - Source address (IP + port) - the client
/// - Destination address (IP + port) - the server
/// - Protocol (TCP or UDP)
///
/// # Example
///
/// ```
/// use rust_router::netbridge::{FiveTuple, IpProtocol};
/// use std::net::{IpAddr, Ipv4Addr, SocketAddr};
///
/// let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 25, 0, 2)), 12345);
/// let dst = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 443);
/// let tuple = FiveTuple::tcp(src, dst);
///
/// assert!(tuple.is_tcp());
/// assert_eq!(tuple.src_port(), 12345);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FiveTuple {
    /// IP protocol (TCP, UDP, etc.)
    pub protocol: IpProtocol,
    /// Source IP address
    pub src_addr: IpAddr,
    /// Source port
    pub src_port: u16,
    /// Destination IP address
    pub dst_addr: IpAddr,
    /// Destination port
    pub dst_port: u16,
}

impl FiveTuple {
    /// Create a new TCP 5-tuple
    ///
    /// # Arguments
    ///
    /// * `src` - Source socket address (client)
    /// * `dst` - Destination socket address (server)
    #[inline]
    #[must_use]
    pub fn tcp(src: SocketAddr, dst: SocketAddr) -> Self {
        Self {
            protocol: IpProtocol::Tcp,
            src_addr: src.ip(),
            src_port: src.port(),
            dst_addr: dst.ip(),
            dst_port: dst.port(),
        }
    }

    /// Create a new UDP 5-tuple
    ///
    /// # Arguments
    ///
    /// * `src` - Source socket address (client)
    /// * `dst` - Destination socket address (server)
    #[inline]
    #[must_use]
    pub fn udp(src: SocketAddr, dst: SocketAddr) -> Self {
        Self {
            protocol: IpProtocol::Udp,
            src_addr: src.ip(),
            src_port: src.port(),
            dst_addr: dst.ip(),
            dst_port: dst.port(),
        }
    }

    /// Create a new 5-tuple with explicit protocol
    #[inline]
    #[must_use]
    pub fn new(
        protocol: IpProtocol,
        src_addr: IpAddr,
        src_port: u16,
        dst_addr: IpAddr,
        dst_port: u16,
    ) -> Self {
        Self {
            protocol,
            src_addr,
            src_port,
            dst_addr,
            dst_port,
        }
    }

    /// Create from source and destination socket addresses
    #[inline]
    #[must_use]
    pub fn from_addrs(protocol: IpProtocol, src: SocketAddr, dst: SocketAddr) -> Self {
        Self {
            protocol,
            src_addr: src.ip(),
            src_port: src.port(),
            dst_addr: dst.ip(),
            dst_port: dst.port(),
        }
    }

    /// Get the source socket address
    #[inline]
    #[must_use]
    pub fn src_socket_addr(&self) -> SocketAddr {
        SocketAddr::new(self.src_addr, self.src_port)
    }

    /// Get the destination socket address
    #[inline]
    #[must_use]
    pub fn dst_socket_addr(&self) -> SocketAddr {
        SocketAddr::new(self.dst_addr, self.dst_port)
    }

    /// Create the reverse tuple (for reply packets)
    ///
    /// Returns a new 5-tuple with source and destination swapped.
    /// This is used to match reply packets back to the original session.
    #[inline]
    #[must_use]
    pub fn reverse(&self) -> Self {
        Self {
            protocol: self.protocol,
            src_addr: self.dst_addr,
            src_port: self.dst_port,
            dst_addr: self.src_addr,
            dst_port: self.src_port,
        }
    }

    /// Check if this is a TCP session
    #[inline]
    #[must_use]
    pub fn is_tcp(&self) -> bool {
        self.protocol.is_tcp()
    }

    /// Check if this is a UDP session
    #[inline]
    #[must_use]
    pub fn is_udp(&self) -> bool {
        self.protocol.is_udp()
    }

    /// Check if this uses IPv4
    #[inline]
    #[must_use]
    pub fn is_ipv4(&self) -> bool {
        self.src_addr.is_ipv4()
    }

    /// Check if this uses IPv6
    #[inline]
    #[must_use]
    pub fn is_ipv6(&self) -> bool {
        self.src_addr.is_ipv6()
    }

    /// Parse a 5-tuple from an IP packet
    ///
    /// Returns `None` if the packet is malformed or not TCP/UDP.
    #[must_use]
    pub fn from_packet(packet: &[u8]) -> Option<Self> {
        if packet.is_empty() {
            return None;
        }

        let version = packet[0] >> 4;
        match version {
            4 => Self::parse_ipv4(packet),
            6 => Self::parse_ipv6(packet),
            _ => None,
        }
    }

    /// Parse an IPv4 packet to extract the 5-tuple
    fn parse_ipv4(packet: &[u8]) -> Option<Self> {
        // Minimum IPv4 header is 20 bytes
        if packet.len() < 20 {
            return None;
        }

        let ihl = (packet[0] & 0x0f) as usize * 4;
        if packet.len() < ihl {
            return None;
        }

        let protocol = IpProtocol::from_u8(packet[9]);
        if !protocol.has_ports() {
            return None;
        }

        let src_ip = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
        let dst_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);

        // Need at least 4 more bytes for ports
        if packet.len() < ihl + 4 {
            return None;
        }

        let src_port = u16::from_be_bytes([packet[ihl], packet[ihl + 1]]);
        let dst_port = u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]]);

        Some(Self {
            protocol,
            src_addr: IpAddr::V4(src_ip),
            src_port,
            dst_addr: IpAddr::V4(dst_ip),
            dst_port,
        })
    }

    /// Parse an IPv6 packet to extract the 5-tuple
    ///
    /// Handles IPv6 extension headers by skipping through them.
    fn parse_ipv6(packet: &[u8]) -> Option<Self> {
        // Minimum IPv6 header is 40 bytes
        if packet.len() < 40 {
            return None;
        }

        // Extract addresses
        let mut src_octets = [0u8; 16];
        let mut dst_octets = [0u8; 16];
        src_octets.copy_from_slice(&packet[8..24]);
        dst_octets.copy_from_slice(&packet[24..40]);

        let src_ip = Ipv6Addr::from(src_octets);
        let dst_ip = Ipv6Addr::from(dst_octets);

        // Skip extension headers
        let mut next_header = packet[6];
        let mut offset = 40;

        loop {
            match next_header {
                6 | 17 => break, // TCP or UDP
                0 | 43 | 60 | 135 => {
                    // Hop-by-Hop, Routing, Dest Options, Mobility
                    if packet.len() < offset + 2 {
                        return None;
                    }
                    next_header = packet[offset];
                    let ext_len = (packet[offset + 1] as usize + 1) * 8;
                    offset += ext_len;
                }
                44 => {
                    // Fragment header
                    if packet.len() < offset + 8 {
                        return None;
                    }
                    next_header = packet[offset];
                    offset += 8;
                }
                _ => return None,
            }

            if offset > packet.len() {
                return None;
            }
        }

        let protocol = IpProtocol::from_u8(next_header);
        if !protocol.has_ports() {
            return None;
        }

        if packet.len() < offset + 4 {
            return None;
        }

        let src_port = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
        let dst_port = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]);

        Some(Self {
            protocol,
            src_addr: IpAddr::V6(src_ip),
            src_port,
            dst_addr: IpAddr::V6(dst_ip),
            dst_port,
        })
    }
}

impl fmt::Display for FiveTuple {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}:{} -> {}:{}",
            self.protocol, self.src_addr, self.src_port, self.dst_addr, self.dst_port
        )
    }
}

// =============================================================================
// IP Packet
// =============================================================================

/// Wrapper around raw IP packet data
///
/// Provides efficient access to packet headers and payload with zero-copy
/// semantics using `bytes::Bytes`.
///
/// # Parsing
///
/// The packet is parsed lazily on first access to minimize overhead for
/// packets that don't need full parsing (e.g., direct forwarding).
///
/// # Example
///
/// ```ignore
/// use rust_router::netbridge::IpPacket;
///
/// let data = Bytes::from(raw_packet);
/// let packet = IpPacket::new(data);
///
/// if let Some(tuple) = packet.five_tuple() {
///     println!("Session: {}", tuple);
/// }
/// ```
#[derive(Clone)]
pub struct IpPacket {
    /// Raw packet data
    data: Bytes,
}

impl IpPacket {
    /// Create a new IP packet from raw bytes
    #[inline]
    #[must_use]
    pub fn new(data: Bytes) -> Self {
        Self { data }
    }

    /// Create from a byte slice (copies data)
    #[inline]
    #[must_use]
    pub fn from_slice(slice: &[u8]) -> Self {
        Self {
            data: Bytes::copy_from_slice(slice),
        }
    }

    /// Get the raw packet data
    #[inline]
    #[must_use]
    pub fn data(&self) -> &Bytes {
        &self.data
    }

    /// Get the packet as a byte slice
    #[inline]
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Consume and return the underlying Bytes
    #[inline]
    #[must_use]
    pub fn into_bytes(self) -> Bytes {
        self.data
    }

    /// Get the packet length
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if the packet is empty
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Get the IP version (4 or 6)
    ///
    /// Returns `None` if the packet is empty.
    #[inline]
    #[must_use]
    pub fn version(&self) -> Option<u8> {
        self.data.first().map(|b| b >> 4)
    }

    /// Check if this is an IPv4 packet
    #[inline]
    #[must_use]
    pub fn is_ipv4(&self) -> bool {
        self.version() == Some(4)
    }

    /// Check if this is an IPv6 packet
    #[inline]
    #[must_use]
    pub fn is_ipv6(&self) -> bool {
        self.version() == Some(6)
    }

    /// Extract the 5-tuple from the packet
    ///
    /// Returns `None` if the packet is malformed or not TCP/UDP.
    #[must_use]
    pub fn five_tuple(&self) -> Option<FiveTuple> {
        FiveTuple::from_packet(&self.data)
    }

    /// Get the source IP address
    #[must_use]
    pub fn src_addr(&self) -> Option<IpAddr> {
        match self.version()? {
            4 if self.data.len() >= 16 => Some(IpAddr::V4(Ipv4Addr::new(
                self.data[12],
                self.data[13],
                self.data[14],
                self.data[15],
            ))),
            6 if self.data.len() >= 24 => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&self.data[8..24]);
                Some(IpAddr::V6(Ipv6Addr::from(octets)))
            }
            _ => None,
        }
    }

    /// Get the destination IP address
    #[must_use]
    pub fn dst_addr(&self) -> Option<IpAddr> {
        match self.version()? {
            4 if self.data.len() >= 20 => Some(IpAddr::V4(Ipv4Addr::new(
                self.data[16],
                self.data[17],
                self.data[18],
                self.data[19],
            ))),
            6 if self.data.len() >= 40 => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&self.data[24..40]);
                Some(IpAddr::V6(Ipv6Addr::from(octets)))
            }
            _ => None,
        }
    }

    /// Get the IP protocol
    #[must_use]
    pub fn protocol(&self) -> Option<IpProtocol> {
        match self.version()? {
            4 if self.data.len() >= 10 => Some(IpProtocol::from_u8(self.data[9])),
            6 if self.data.len() >= 7 => Some(IpProtocol::from_u8(self.data[6])),
            _ => None,
        }
    }

    /// Get the DSCP (Differentiated Services Code Point) value
    ///
    /// Returns the 6-bit DSCP value from the IP header.
    #[must_use]
    pub fn dscp(&self) -> Option<u8> {
        match self.version()? {
            4 if self.data.len() >= 2 => Some(self.data[1] >> 2),
            6 if self.data.len() >= 2 => {
                // IPv6: Traffic Class is in bits 4-11 (DSCP in bits 4-9)
                Some(((self.data[0] & 0x0f) << 2) | (self.data[1] >> 6))
            }
            _ => None,
        }
    }
}

impl fmt::Debug for IpPacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IpPacket")
            .field("len", &self.len())
            .field("version", &self.version())
            .field("protocol", &self.protocol())
            .field("src_addr", &self.src_addr())
            .field("dst_addr", &self.dst_addr())
            .finish()
    }
}

impl AsRef<[u8]> for IpPacket {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

// =============================================================================
// Reply Packet
// =============================================================================

/// Reply packet with WireGuard peer routing information
///
/// When a reply packet is received from an outbound connection, it needs
/// to be routed back to the correct WireGuard peer. This struct bundles
/// the packet data with the necessary routing information.
#[derive(Debug, Clone)]
pub struct ReplyPacket {
    /// Raw packet data
    pub data: Bytes,
    /// WireGuard peer public key (32 bytes)
    pub peer_key: [u8; 32],
    /// Peer's WireGuard endpoint (IP:port) for sending replies
    pub peer_endpoint: SocketAddr,
}

impl ReplyPacket {
    /// Create a new reply packet
    #[inline]
    #[must_use]
    pub fn new(data: Bytes, peer_key: [u8; 32], peer_endpoint: SocketAddr) -> Self {
        Self {
            data,
            peer_key,
            peer_endpoint,
        }
    }

    /// Create from a byte slice (copies data)
    #[inline]
    #[must_use]
    pub fn from_slice(slice: &[u8], peer_key: [u8; 32], peer_endpoint: SocketAddr) -> Self {
        Self {
            data: Bytes::copy_from_slice(slice),
            peer_key,
            peer_endpoint,
        }
    }

    /// Get the packet length
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if the packet is empty
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Get the packet as a byte slice
    #[inline]
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Consume and return the underlying Bytes
    #[inline]
    #[must_use]
    pub fn into_bytes(self) -> Bytes {
        self.data
    }

    /// Get a short representation of the peer key (first 8 bytes as hex)
    #[must_use]
    pub fn peer_key_short(&self) -> String {
        hex::encode(&self.peer_key[..8])
    }
}

impl AsRef<[u8]> for ReplyPacket {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

// =============================================================================
// Statistics Types
// =============================================================================

/// Ingress bridge statistics
#[derive(Debug, Clone, Default)]
pub struct IngressStats {
    /// Total packets received from WireGuard
    pub packets_received: u64,
    /// Total packets injected to outbound
    pub packets_injected: u64,
    /// Total bytes received
    pub bytes_received: u64,
    /// Packets dropped (parse errors, etc.)
    pub packets_dropped: u64,
    /// Active sessions
    pub active_sessions: usize,
    /// DNS queries intercepted (FakeDNS)
    pub dns_queries_intercepted: u64,
    /// SNI extractions performed
    pub sni_extractions: u64,
}

/// Egress bridge statistics
#[derive(Debug, Clone, Default)]
pub struct EgressStats {
    /// Total TCP sessions handled
    pub tcp_sessions: u64,
    /// Total UDP sessions handled
    pub udp_sessions: u64,
    /// Total bytes sent to outbound
    pub bytes_sent: u64,
    /// Total bytes received from outbound
    pub bytes_received: u64,
    /// Reply packets generated
    pub reply_packets: u64,
    /// Errors encountered
    pub errors: u64,
}

// =============================================================================
// Connection ID
// =============================================================================

/// Number of bits reserved for the shard index
const SHARD_BITS: u32 = 16;

/// Number of bits for the sequence number
const SEQUENCE_BITS: u32 = 64 - SHARD_BITS;

/// Mask for extracting the sequence number (48 bits)
const SEQUENCE_MASK: u64 = (1 << SEQUENCE_BITS) - 1;

/// Mask for extracting the shard index (high 16 bits)
const SHARD_MASK: u64 = !SEQUENCE_MASK;

/// Maximum sequence value before wrapping (2^48 - 1)
const MAX_SEQUENCE: u64 = SEQUENCE_MASK;

/// Unique identifier for a connection/session
///
/// A 64-bit value that can optionally encode a shard index in the high 16 bits.
/// When created without a shard, the entire 64 bits are used for the sequence.
///
/// # ID Layout
///
/// ```text
/// Without shard (global allocator):
/// +----------------------------------------------------------------+
/// |                         64-bit sequence                         |
/// +----------------------------------------------------------------+
///
/// With shard (per-shard allocator):
/// +----------------+------------------------------------------------+
/// | 16-bit shard   |              48-bit sequence                    |
/// +----------------+------------------------------------------------+
/// ```
///
/// # Properties
///
/// - `Copy` and `Clone`: IDs are cheap to copy
/// - `Eq` and `Hash`: Can be used as map keys
/// - `Ord`: Sortable by raw value (shard-aware ordering)
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ConnId(u64);

impl ConnId {
    /// Create a connection ID from a raw 64-bit value
    #[must_use]
    pub const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    /// Get the raw 64-bit value
    #[must_use]
    pub const fn raw(&self) -> u64 {
        self.0
    }

    /// Create a connection ID with a specific shard index and sequence
    ///
    /// # Panics
    ///
    /// Panics in debug builds if sequence exceeds 48 bits.
    #[must_use]
    pub const fn with_shard_and_sequence(shard_index: u16, sequence: u64) -> Self {
        debug_assert!(
            sequence <= MAX_SEQUENCE,
            "sequence exceeds 48-bit limit"
        );
        let raw = ((shard_index as u64) << SEQUENCE_BITS) | (sequence & SEQUENCE_MASK);
        Self(raw)
    }

    /// Get the shard index if this ID was created with one
    ///
    /// Returns `Some(shard_index)` if the high 16 bits are non-zero,
    /// `None` otherwise. Note that shard index 0 is indistinguishable
    /// from a global ID.
    #[must_use]
    pub const fn shard_index(&self) -> Option<u16> {
        let shard = ((self.0 & SHARD_MASK) >> SEQUENCE_BITS) as u16;
        if shard == 0 {
            None
        } else {
            Some(shard)
        }
    }

    /// Get the shard index, returning 0 if not set
    #[must_use]
    pub const fn shard_index_or_zero(&self) -> u16 {
        ((self.0 & SHARD_MASK) >> SEQUENCE_BITS) as u16
    }

    /// Get the sequence number portion (low 48 bits for sharded IDs)
    ///
    /// For global IDs (no shard), this returns the full 64-bit value.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.0 & SEQUENCE_MASK
    }

    /// Check if this ID has a shard index encoded
    #[must_use]
    pub const fn has_shard(&self) -> bool {
        (self.0 & SHARD_MASK) != 0
    }
}

impl fmt::Debug for ConnId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(shard) = self.shard_index() {
            write!(f, "ConnId(shard={}, seq={})", shard, self.sequence())
        } else {
            write!(f, "ConnId({})", self.0)
        }
    }
}

impl fmt::Display for ConnId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(shard) = self.shard_index() {
            write!(f, "s{}-{}", shard, self.sequence())
        } else {
            write!(f, "c{}", self.0)
        }
    }
}

/// Thread-safe allocator for connection IDs
///
/// Can operate in two modes:
/// 1. **Global mode**: Creates IDs using the full 64-bit space
/// 2. **Shard mode**: Encodes a shard index in the high 16 bits
///
/// # Example
///
/// ```ignore
/// // Create allocators for different shards
/// let alloc_shard_1 = ConnIdAllocator::with_shard(1);
/// let alloc_shard_2 = ConnIdAllocator::with_shard(2);
///
/// // IDs from different shards are always unique
/// let id1 = alloc_shard_1.next();
/// let id2 = alloc_shard_2.next();
/// assert_ne!(id1, id2);
///
/// // Can identify which shard generated the ID
/// assert_eq!(id1.shard_index(), Some(1));
/// assert_eq!(id2.shard_index(), Some(2));
/// ```
pub struct ConnIdAllocator {
    /// Next sequence number (low 48 bits when sharded)
    next_seq: AtomicU64,
    /// Optional shard index (None for global allocator)
    shard_index: Option<u16>,
}

impl ConnIdAllocator {
    /// Create a global allocator (no shard encoding)
    ///
    /// IDs will use the full 64-bit space for the sequence number.
    #[must_use]
    pub fn new() -> Self {
        Self {
            next_seq: AtomicU64::new(1), // Start at 1, reserve 0 for "no ID"
            shard_index: None,
        }
    }

    /// Create a shard-specific allocator
    ///
    /// IDs will have the shard index encoded in the high 16 bits.
    ///
    /// # Note
    ///
    /// Using `shard_index = 0` is valid but the resulting IDs will be
    /// indistinguishable from global IDs when calling `shard_index()`.
    #[must_use]
    pub fn with_shard(shard_index: u16) -> Self {
        Self {
            next_seq: AtomicU64::new(1), // Start at 1
            shard_index: Some(shard_index),
        }
    }

    /// Allocate the next connection ID
    ///
    /// This operation is lock-free and thread-safe. The sequence number
    /// will wrap around after reaching the maximum value (2^48 - 1 for
    /// sharded allocators, 2^64 - 1 for global allocators).
    #[must_use]
    pub fn next(&self) -> ConnId {
        let seq = self.next_seq.fetch_add(1, Ordering::Relaxed);

        match self.shard_index {
            Some(shard) => {
                // Wrap sequence at 48 bits
                let seq = seq & SEQUENCE_MASK;
                ConnId::with_shard_and_sequence(shard, seq)
            }
            None => {
                // Use full 64-bit space
                ConnId::from_raw(seq)
            }
        }
    }

    /// Get the current allocation count (for debugging)
    ///
    /// Returns the number of IDs that have been allocated.
    /// Note: Due to concurrent access, this may be slightly stale.
    #[must_use]
    pub fn current_count(&self) -> u64 {
        self.next_seq.load(Ordering::Relaxed).saturating_sub(1)
    }

    /// Check if this allocator encodes shard indices
    #[must_use]
    pub fn is_sharded(&self) -> bool {
        self.shard_index.is_some()
    }

    /// Get the shard index for this allocator
    #[must_use]
    pub fn shard(&self) -> Option<u16> {
        self.shard_index
    }
}

impl Default for ConnIdAllocator {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for ConnIdAllocator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnIdAllocator")
            .field("shard_index", &self.shard_index)
            .field("allocated", &self.current_count())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_id() {
        let id = SessionId::new(42);
        assert_eq!(id.as_u64(), 42);
        assert_eq!(format!("{id}"), "session-42");

        let id2: SessionId = 100.into();
        assert_eq!(id2.as_u64(), 100);
    }

    #[test]
    fn test_session_id_generator() {
        let gen = SessionIdGenerator::new();
        let id1 = gen.next();
        let id2 = gen.next();
        let id3 = gen.next();

        assert_eq!(id1.as_u64(), 1);
        assert_eq!(id2.as_u64(), 2);
        assert_eq!(id3.as_u64(), 3);
    }

    #[test]
    fn test_ip_protocol() {
        assert!(IpProtocol::Tcp.is_tcp());
        assert!(!IpProtocol::Tcp.is_udp());
        assert!(IpProtocol::Tcp.has_ports());

        assert!(IpProtocol::Udp.is_udp());
        assert!(!IpProtocol::Udp.is_tcp());
        assert!(IpProtocol::Udp.has_ports());

        assert!(IpProtocol::Icmp.is_icmp());
        assert!(!IpProtocol::Icmp.has_ports());

        assert_eq!(IpProtocol::from_u8(6), IpProtocol::Tcp);
        assert_eq!(IpProtocol::from_u8(17), IpProtocol::Udp);
        assert_eq!(IpProtocol::Tcp.as_u8(), 6);
    }

    #[test]
    fn test_five_tuple_tcp() {
        let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 25, 0, 2)), 12345);
        let dst = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 443);
        let tuple = FiveTuple::tcp(src, dst);

        assert!(tuple.is_tcp());
        assert!(!tuple.is_udp());
        assert!(tuple.is_ipv4());
        assert_eq!(tuple.src_port, 12345);
        assert_eq!(tuple.dst_port, 443);
    }

    #[test]
    fn test_five_tuple_udp() {
        let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 25, 0, 2)), 54321);
        let dst = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53);
        let tuple = FiveTuple::udp(src, dst);

        assert!(tuple.is_udp());
        assert!(!tuple.is_tcp());
    }

    #[test]
    fn test_five_tuple_reverse() {
        let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 25, 0, 2)), 12345);
        let dst = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 80);
        let tuple = FiveTuple::tcp(src, dst);
        let reversed = tuple.reverse();

        assert_eq!(reversed.src_port, 80);
        assert_eq!(reversed.dst_port, 12345);
        assert_eq!(reversed.src_addr, dst.ip());
        assert_eq!(reversed.dst_addr, src.ip());
    }

    #[test]
    fn test_five_tuple_from_ipv4_tcp_packet() {
        // IPv4 TCP packet: 10.25.0.2:12345 -> 93.184.216.34:80
        let packet = vec![
            0x45, 0x00, 0x00, 0x28, // Version, IHL, DSCP, Total Length
            0x00, 0x00, 0x00, 0x00, // ID, Flags, Fragment Offset
            0x40, 0x06, 0x00, 0x00, // TTL, Protocol (TCP=6), Checksum
            0x0a, 0x19, 0x00, 0x02, // Source IP: 10.25.0.2
            0x5d, 0xb8, 0xd8, 0x22, // Dest IP: 93.184.216.34
            0x30, 0x39, 0x00, 0x50, // Source Port: 12345, Dest Port: 80
        ];

        let tuple = FiveTuple::from_packet(&packet);
        assert!(tuple.is_some());

        let ft = tuple.unwrap();
        assert!(ft.is_tcp());
        assert_eq!(ft.src_port, 12345);
        assert_eq!(ft.dst_port, 80);
    }

    #[test]
    fn test_ip_packet_basics() {
        let data = Bytes::from(vec![
            0x45, 0x00, 0x00, 0x28, // Version=4, IHL=5
            0x00, 0x00, 0x00, 0x00,
            0x40, 0x06, 0x00, 0x00, // Protocol=TCP
            0x0a, 0x19, 0x00, 0x02, // Src: 10.25.0.2
            0x5d, 0xb8, 0xd8, 0x22, // Dst: 93.184.216.34
            0x30, 0x39, 0x00, 0x50, // Ports
        ]);

        let packet = IpPacket::new(data);
        assert!(packet.is_ipv4());
        assert!(!packet.is_ipv6());
        assert_eq!(packet.version(), Some(4));
        assert_eq!(packet.protocol(), Some(IpProtocol::Tcp));
        assert!(packet.src_addr().is_some());
        assert!(packet.dst_addr().is_some());
    }

    #[test]
    fn test_reply_packet() {
        let data = Bytes::from(vec![1, 2, 3, 4]);
        let peer_key = [0u8; 32];
        let peer_endpoint = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 51820);

        let reply = ReplyPacket::new(data.clone(), peer_key, peer_endpoint);
        assert_eq!(reply.len(), 4);
        assert!(!reply.is_empty());
        assert_eq!(reply.peer_endpoint, peer_endpoint);
        assert_eq!(reply.peer_key_short(), "0000000000000000");
    }

    #[test]
    fn test_five_tuple_display() {
        let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 25, 0, 2)), 12345);
        let dst = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 80);
        let tuple = FiveTuple::tcp(src, dst);

        let display = format!("{tuple}");
        assert!(display.contains("TCP"));
        assert!(display.contains("10.25.0.2"));
        assert!(display.contains("12345"));
    }

    // =========================================================================
    // ConnId Tests
    // =========================================================================

    #[test]
    fn test_conn_id_from_raw() {
        let id = ConnId::from_raw(12345);
        assert_eq!(id.raw(), 12345);
    }

    #[test]
    fn test_conn_id_with_shard() {
        let id = ConnId::with_shard_and_sequence(5, 1000);
        assert_eq!(id.shard_index(), Some(5));
        assert_eq!(id.sequence(), 1000);
        assert!(id.has_shard());
    }

    #[test]
    fn test_conn_id_without_shard() {
        let id = ConnId::from_raw(12345);
        assert_eq!(id.shard_index(), None);
        assert_eq!(id.sequence(), 12345);
        assert!(!id.has_shard());
    }

    #[test]
    fn test_conn_id_shard_zero() {
        // Shard 0 is indistinguishable from global
        let id = ConnId::with_shard_and_sequence(0, 1000);
        assert_eq!(id.shard_index(), None);
        assert_eq!(id.shard_index_or_zero(), 0);
        assert_eq!(id.sequence(), 1000);
    }

    #[test]
    fn test_conn_id_display_with_shard() {
        let id = ConnId::with_shard_and_sequence(3, 42);
        let s = id.to_string();
        assert_eq!(s, "s3-42");
    }

    #[test]
    fn test_conn_id_display_without_shard() {
        let id = ConnId::from_raw(999);
        let s = id.to_string();
        assert_eq!(s, "c999");
    }

    #[test]
    fn test_conn_id_debug() {
        let id_with_shard = ConnId::with_shard_and_sequence(7, 123);
        let s = format!("{:?}", id_with_shard);
        assert!(s.contains("shard=7"));
        assert!(s.contains("seq=123"));

        let id_without_shard = ConnId::from_raw(456);
        let s = format!("{:?}", id_without_shard);
        assert!(s.contains("456"));
    }

    #[test]
    fn test_conn_id_eq_hash() {
        use std::collections::HashSet;

        let id1 = ConnId::from_raw(100);
        let id2 = ConnId::from_raw(100);
        let id3 = ConnId::from_raw(200);

        assert_eq!(id1, id2);
        assert_ne!(id1, id3);

        let mut set = HashSet::new();
        set.insert(id1);
        assert!(set.contains(&id2));
        assert!(!set.contains(&id3));
    }

    #[test]
    fn test_conn_id_ordering() {
        let id1 = ConnId::with_shard_and_sequence(1, 100);
        let id2 = ConnId::with_shard_and_sequence(1, 200);
        let id3 = ConnId::with_shard_and_sequence(2, 50);

        // Same shard, different sequence
        assert!(id1 < id2);

        // Different shard (higher shard = higher ID)
        assert!(id2 < id3);
    }

    // =========================================================================
    // ConnIdAllocator Tests
    // =========================================================================

    #[test]
    fn test_conn_id_allocator_global_monotonic() {
        let alloc = ConnIdAllocator::new();

        let id1 = alloc.next();
        let id2 = alloc.next();
        let id3 = alloc.next();

        assert!(id1.raw() < id2.raw());
        assert!(id2.raw() < id3.raw());
        assert_eq!(alloc.current_count(), 3);
    }

    #[test]
    fn test_conn_id_allocator_starts_at_one() {
        let alloc = ConnIdAllocator::new();
        let id = alloc.next();
        assert_eq!(id.raw(), 1); // 0 is reserved
    }

    #[test]
    fn test_conn_id_allocator_sharded_monotonic() {
        let alloc = ConnIdAllocator::with_shard(5);

        let id1 = alloc.next();
        let id2 = alloc.next();

        assert_eq!(id1.shard_index(), Some(5));
        assert_eq!(id2.shard_index(), Some(5));
        assert!(id1.sequence() < id2.sequence());
    }

    #[test]
    fn test_conn_id_allocator_different_shards_unique() {
        let alloc1 = ConnIdAllocator::with_shard(1);
        let alloc2 = ConnIdAllocator::with_shard(2);

        let id1 = alloc1.next();
        let id2 = alloc2.next();

        // Same sequence number but different shards
        assert_eq!(id1.sequence(), 1);
        assert_eq!(id2.sequence(), 1);

        // But IDs are different
        assert_ne!(id1, id2);
        assert_ne!(id1.raw(), id2.raw());
    }

    #[test]
    fn test_conn_id_allocator_is_sharded() {
        let global = ConnIdAllocator::new();
        let sharded = ConnIdAllocator::with_shard(1);

        assert!(!global.is_sharded());
        assert!(sharded.is_sharded());
    }

    #[test]
    fn test_conn_id_allocator_shard_getter() {
        let global = ConnIdAllocator::new();
        let sharded = ConnIdAllocator::with_shard(42);

        assert_eq!(global.shard(), None);
        assert_eq!(sharded.shard(), Some(42));
    }

    #[test]
    fn test_conn_id_allocator_debug() {
        let alloc = ConnIdAllocator::with_shard(3);
        let _ = alloc.next();
        let _ = alloc.next();

        let s = format!("{:?}", alloc);
        assert!(s.contains("shard_index: Some(3)"));
        assert!(s.contains("allocated: 2"));
    }

    #[test]
    fn test_conn_id_allocator_default() {
        let alloc = ConnIdAllocator::default();
        assert!(!alloc.is_sharded());
    }
}
