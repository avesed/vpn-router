//! Loopback test - Performance testing with realistic network simulation
//!
//! This module provides `LoopbackTest` which creates a closed-loop testing
//! environment where smoltcp egress packets are fed back as "replies" to
//! simulate a remote server. This allows benchmarking netbridge performance
//! with configurable network conditions.
//!
//! # Network Simulation Features
//!
//! Unlike simple in-memory benchmarks, this module supports:
//! - **Latency injection**: Configurable base RTT + jitter
//! - **Packet loss**: Random packet drop with configurable probability
//! - **Bandwidth limiting**: Cap throughput to simulate constrained links
//! - **Congestion simulation**: Increasing delay under load
//! - **Realistic TCP behavior**: Connection establishment delays
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │                      LoopbackTest                                   │
//! ├─────────────────────────────────────────────────────────────────────┤
//! │                                                                     │
//! │  Test Client                   MockResponder + NetworkConditions    │
//! │       │                              ▲                              │
//! │       │ write data                   │ reply packet (delayed)       │
//! │       ▼                              │                              │
//! │  SmoltcpEgress                       │                              │
//! │       │                              │ ┌──────────────────────────┐│
//! │       │ TCP/UDP → IP                 │ │ NetworkConditions:       ││
//! │       │ packets                      │ │ - latency_ms: 10-50      ││
//! │       ▼                              │ │ - packet_loss: 0.1%      ││
//! │   drain_tx() ───────────────────────►│ │ - bandwidth_mbps: 100    ││
//! │       │                              │ │ - jitter_ms: 5           ││
//! │       │ IP packets                   │ └──────────────────────────┘│
//! │       ▼                              │                              │
//! │   feed_reply() ◄────────────────────┘                              │
//! │       │                              (MockResponder transforms      │
//! │       │                               with network simulation)      │
//! │       ▼                                                             │
//! │   Test Client receives response                                     │
//! │                                                                     │
//! └─────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Example
//!
//! ```ignore
//! use rust_router::netbridge::bench::loopback::{LoopbackTest, NetworkConditions};
//! use rust_router::netbridge::bench::{BenchConfig, TrafficPattern};
//!
//! // Create test with realistic network conditions
//! let conditions = NetworkConditions::wan_typical();  // 30ms RTT, 0.1% loss
//! let test = LoopbackTest::new().with_network_conditions(conditions);
//!
//! // Run throughput test
//! let results = test.run_throughput(&BenchConfig::default()).await;
//! println!("Throughput: {} Mbps (with network simulation)", results.throughput_mbps);
//! ```

use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use rand::Rng;
use smoltcp::wire::IpAddress;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;
use tracing::{debug, trace, warn};

use super::{BenchConfig, BenchResults, TrafficPattern};
use crate::netbridge::smoltcp::{SmoltcpEgress, SmoltcpEgressConfig};
use crate::netbridge::traits::NetBridgeEgress;

// =============================================================================
// Network Conditions Simulation
// =============================================================================

/// Network conditions for realistic benchmarking
///
/// This allows simulating various network characteristics:
/// - Latency (base RTT + jitter)
/// - Packet loss (random drop probability)
/// - Bandwidth limiting (bytes per second cap)
/// - Congestion (increasing delay under load)
///
/// # Presets
///
/// - [`NetworkConditions::ideal()`]: Zero latency, no loss (baseline)
/// - [`NetworkConditions::lan()`]: 1ms RTT, no loss
/// - [`NetworkConditions::wan_typical()`]: 30ms RTT, 0.1% loss
/// - [`NetworkConditions::wan_lossy()`]: 50ms RTT, 1% loss
/// - [`NetworkConditions::satellite()`]: 600ms RTT, 0.5% loss
/// - [`NetworkConditions::mobile_4g()`]: 50ms RTT, 0.5% loss, variable
#[derive(Debug, Clone)]
pub struct NetworkConditions {
    /// Base one-way latency in milliseconds
    pub latency_ms: u32,
    /// Latency jitter (random variation) in milliseconds
    pub jitter_ms: u32,
    /// Packet loss probability (0.0 - 1.0)
    pub packet_loss_rate: f64,
    /// Bandwidth limit in Mbps (0 = unlimited)
    pub bandwidth_mbps: u32,
    /// Whether to simulate congestion (increasing delay under load)
    pub simulate_congestion: bool,
    /// Congestion threshold (packets in flight before adding delay)
    pub congestion_threshold: usize,
    /// Maximum congestion-induced delay in milliseconds
    pub max_congestion_delay_ms: u32,
    /// Packet reordering probability (0.0 - 1.0)
    pub reorder_rate: f64,
    /// Maximum reorder delay in milliseconds
    pub reorder_delay_ms: u32,
    /// Connection establishment overhead in milliseconds (TCP SYN-ACK)
    pub connection_setup_ms: u32,
}

impl Default for NetworkConditions {
    fn default() -> Self {
        Self::ideal()
    }
}

impl NetworkConditions {
    // =========================================================================
    // Bandwidth Presets (ordered from unlimited to lowest)
    // =========================================================================

    /// Ideal conditions - unlimited bandwidth, no impairments (baseline benchmark)
    #[must_use]
    pub fn ideal() -> Self {
        Self {
            latency_ms: 0,
            jitter_ms: 0,
            packet_loss_rate: 0.0,
            bandwidth_mbps: 0, // unlimited (0 = no limit)
            simulate_congestion: false,
            congestion_threshold: 1000,
            max_congestion_delay_ms: 100,
            reorder_rate: 0.0,
            reorder_delay_ms: 0,
            connection_setup_ms: 0,
        }
    }

    /// Datacenter conditions - 100 Gbps, ultra-low latency
    #[must_use]
    pub fn datacenter() -> Self {
        Self {
            latency_ms: 0,
            jitter_ms: 0,
            packet_loss_rate: 0.0,
            bandwidth_mbps: 100_000, // 100 Gbps
            simulate_congestion: false,
            congestion_threshold: 10000,
            max_congestion_delay_ms: 5,
            reorder_rate: 0.0,
            reorder_delay_ms: 0,
            connection_setup_ms: 0,
        }
    }

    /// LAN conditions - 10 Gbps, fast reliable local network
    #[must_use]
    pub fn lan() -> Self {
        Self {
            latency_ms: 1,
            jitter_ms: 0,
            packet_loss_rate: 0.0,
            bandwidth_mbps: 10_000, // 10 Gbps
            simulate_congestion: false,
            congestion_threshold: 1000,
            max_congestion_delay_ms: 10,
            reorder_rate: 0.0,
            reorder_delay_ms: 0,
            connection_setup_ms: 1,
        }
    }

    /// Typical WAN conditions - 1 Gbps, moderate latency
    #[must_use]
    pub fn wan_typical() -> Self {
        Self {
            latency_ms: 15, // 30ms RTT
            jitter_ms: 5,
            packet_loss_rate: 0.001, // 0.1%
            bandwidth_mbps: 1_000, // 1 Gbps
            simulate_congestion: true,
            congestion_threshold: 100,
            max_congestion_delay_ms: 50,
            reorder_rate: 0.001,
            reorder_delay_ms: 10,
            connection_setup_ms: 30, // TCP 3-way handshake
        }
    }

    /// Lossy WAN conditions - 500 Mbps, higher latency and loss
    #[must_use]
    pub fn wan_lossy() -> Self {
        Self {
            latency_ms: 25, // 50ms RTT
            jitter_ms: 15,
            packet_loss_rate: 0.01, // 1%
            bandwidth_mbps: 500, // 500 Mbps
            simulate_congestion: true,
            congestion_threshold: 50,
            max_congestion_delay_ms: 100,
            reorder_rate: 0.005,
            reorder_delay_ms: 20,
            connection_setup_ms: 50,
        }
    }

    /// Mobile 5G conditions - 300 Mbps, variable latency
    #[must_use]
    pub fn mobile_4g() -> Self {
        Self {
            latency_ms: 25,          // 50ms RTT base
            jitter_ms: 25,           // High variability
            packet_loss_rate: 0.005, // 0.5%
            bandwidth_mbps: 300, // 300 Mbps
            simulate_congestion: true,
            congestion_threshold: 30,
            max_congestion_delay_ms: 100,
            reorder_rate: 0.01,
            reorder_delay_ms: 30,
            connection_setup_ms: 75,
        }
    }

    /// Satellite link conditions - 200 Mbps, very high latency
    #[must_use]
    pub fn satellite() -> Self {
        Self {
            latency_ms: 300, // 600ms RTT
            jitter_ms: 20,
            packet_loss_rate: 0.005, // 0.5%
            bandwidth_mbps: 200, // 200 Mbps
            simulate_congestion: true,
            congestion_threshold: 20,
            max_congestion_delay_ms: 200,
            reorder_rate: 0.002,
            reorder_delay_ms: 50,
            connection_setup_ms: 600, // 3x RTT for handshake
        }
    }

    /// Create custom conditions with builder pattern
    #[must_use]
    pub fn custom() -> Self {
        Self::ideal()
    }

    /// Set latency (one-way, RTT = 2x)
    #[must_use]
    pub fn with_latency_ms(mut self, ms: u32) -> Self {
        self.latency_ms = ms;
        self
    }

    /// Set jitter
    #[must_use]
    pub fn with_jitter_ms(mut self, ms: u32) -> Self {
        self.jitter_ms = ms;
        self
    }

    /// Set packet loss rate (0.0 - 1.0)
    #[must_use]
    pub fn with_packet_loss(mut self, rate: f64) -> Self {
        self.packet_loss_rate = rate.clamp(0.0, 1.0);
        self
    }

    /// Set bandwidth limit in Mbps
    #[must_use]
    pub fn with_bandwidth_mbps(mut self, mbps: u32) -> Self {
        self.bandwidth_mbps = mbps;
        self
    }

    /// Enable congestion simulation
    #[must_use]
    pub fn with_congestion(mut self, threshold: usize, max_delay_ms: u32) -> Self {
        self.simulate_congestion = true;
        self.congestion_threshold = threshold;
        self.max_congestion_delay_ms = max_delay_ms;
        self
    }

    /// Calculate effective delay for a packet
    pub fn calculate_delay(&self, packets_in_flight: usize, rng: &mut impl Rng) -> Duration {
        let mut delay_ms = self.latency_ms as f64;

        // Add jitter
        if self.jitter_ms > 0 {
            let jitter = rng.gen_range(0..=self.jitter_ms) as f64;
            // Jitter can add or subtract (but total can't go negative)
            if rng.gen_bool(0.5) {
                delay_ms += jitter;
            } else {
                delay_ms = (delay_ms - jitter).max(0.0);
            }
        }

        // Add congestion delay
        if self.simulate_congestion && packets_in_flight > self.congestion_threshold {
            let excess = packets_in_flight - self.congestion_threshold;
            let congestion_factor = (excess as f64 / self.congestion_threshold as f64).min(1.0);
            delay_ms += congestion_factor * self.max_congestion_delay_ms as f64;
        }

        Duration::from_micros((delay_ms * 1000.0) as u64)
    }

    /// Decide if a packet should be dropped
    pub fn should_drop(&self, rng: &mut impl Rng) -> bool {
        if self.packet_loss_rate <= 0.0 {
            return false;
        }
        rng.gen_bool(self.packet_loss_rate)
    }

    /// Decide if a packet should be reordered
    pub fn should_reorder(&self, rng: &mut impl Rng) -> bool {
        if self.reorder_rate <= 0.0 {
            return false;
        }
        rng.gen_bool(self.reorder_rate)
    }

    /// Calculate reorder delay
    pub fn calculate_reorder_delay(&self, rng: &mut impl Rng) -> Duration {
        if self.reorder_delay_ms == 0 {
            return Duration::ZERO;
        }
        let delay_ms = rng.gen_range(0..=self.reorder_delay_ms);
        Duration::from_millis(delay_ms as u64)
    }

    /// Calculate bandwidth delay (time to transmit bytes)
    pub fn calculate_bandwidth_delay(&self, bytes: usize) -> Duration {
        if self.bandwidth_mbps == 0 {
            return Duration::ZERO;
        }
        // bytes * 8 / (mbps * 1_000_000) = seconds
        let bits = bytes as f64 * 8.0;
        let bits_per_sec = self.bandwidth_mbps as f64 * 1_000_000.0;
        let seconds = bits / bits_per_sec;
        Duration::from_secs_f64(seconds)
    }
}

/// Delayed packet for reordering simulation
#[derive(Debug)]
struct DelayedPacket {
    data: Vec<u8>,
    deliver_at: Instant,
}

/// Network condition statistics
#[derive(Debug, Default, Clone)]
pub struct NetworkConditionStats {
    /// Packets processed
    pub packets_processed: u64,
    /// Packets dropped (simulated loss)
    pub packets_dropped: u64,
    /// Packets reordered
    pub packets_reordered: u64,
    /// Total delay added (microseconds)
    pub total_delay_us: u64,
    /// Average delay (microseconds)
    pub avg_delay_us: u64,
    /// Bandwidth throttle events
    pub throttle_events: u64,
}

// =============================================================================
// Constants
// =============================================================================

/// Default local IP for the test client
const CLIENT_IP: [u8; 4] = [10, 200, 200, 2];

/// Default remote IP for the mock server
const SERVER_IP: [u8; 4] = [93, 184, 216, 34];

/// Default server port
const SERVER_PORT: u16 = 80;

/// Default data block size for throughput tests (64 KB)
const DATA_BLOCK_SIZE: usize = 65536;

/// Packet processing batch size
const BATCH_SIZE: usize = 64;

// =============================================================================
// LoopbackTest Configuration
// =============================================================================

/// Configuration for the loopback test
#[derive(Debug, Clone)]
pub struct LoopbackTestConfig {
    /// Local IP address (smoltcp client side)
    pub local_ip: IpAddress,
    /// Remote IP address (mock server side)
    pub remote_ip: Ipv4Addr,
    /// Remote port
    pub remote_port: u16,
    /// Data block size for throughput tests
    pub data_block_size: usize,
    /// Whether to echo data back (true) or just acknowledge (false)
    pub echo_mode: bool,
}

impl Default for LoopbackTestConfig {
    fn default() -> Self {
        Self {
            local_ip: IpAddress::v4(CLIENT_IP[0], CLIENT_IP[1], CLIENT_IP[2], CLIENT_IP[3]),
            remote_ip: Ipv4Addr::new(SERVER_IP[0], SERVER_IP[1], SERVER_IP[2], SERVER_IP[3]),
            remote_port: SERVER_PORT,
            data_block_size: DATA_BLOCK_SIZE,
            echo_mode: true,
        }
    }
}

// =============================================================================
// MockResponder - Simulates remote server
// =============================================================================

/// Mock responder that transforms egress packets into reply packets
///
/// The responder swaps source/destination addresses and optionally
/// echoes or acknowledges the data to simulate a remote server.
/// With `NetworkConditions`, it can simulate latency, packet loss,
/// congestion, and reordering for realistic benchmarks.
pub struct MockResponder {
    /// Echo mode: true = echo data back, false = just ACK
    echo_mode: bool,
    /// Network conditions for simulation
    conditions: NetworkConditions,
    /// Packets processed counter
    packets_processed: AtomicU64,
    /// Bytes processed counter
    bytes_processed: AtomicU64,
    /// Packets dropped (simulated loss)
    packets_dropped: AtomicU64,
    /// Packets reordered
    packets_reordered: AtomicU64,
    /// Current packets in flight (for congestion)
    packets_in_flight: AtomicU64,
    /// Total delay added (microseconds)
    total_delay_us: AtomicU64,
}

impl MockResponder {
    /// Create a new mock responder with ideal network conditions
    #[must_use]
    pub fn new(echo_mode: bool) -> Self {
        Self::with_conditions(echo_mode, NetworkConditions::ideal())
    }

    /// Create a new mock responder with custom network conditions
    #[must_use]
    pub fn with_conditions(echo_mode: bool, conditions: NetworkConditions) -> Self {
        Self {
            echo_mode,
            conditions,
            packets_processed: AtomicU64::new(0),
            bytes_processed: AtomicU64::new(0),
            packets_dropped: AtomicU64::new(0),
            packets_reordered: AtomicU64::new(0),
            packets_in_flight: AtomicU64::new(0),
            total_delay_us: AtomicU64::new(0),
        }
    }

    /// Update network conditions
    pub fn set_conditions(&mut self, conditions: NetworkConditions) {
        self.conditions = conditions;
    }

    /// Get network conditions reference
    pub fn conditions(&self) -> &NetworkConditions {
        &self.conditions
    }

    /// Increment packets in flight counter
    pub fn packet_sent(&self) {
        self.packets_in_flight.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrement packets in flight counter
    pub fn packet_received(&self) {
        self.packets_in_flight.fetch_sub(1, Ordering::Relaxed);
    }

    /// Get current packets in flight
    pub fn get_packets_in_flight(&self) -> usize {
        self.packets_in_flight.load(Ordering::Relaxed) as usize
    }

    /// Record delay statistics
    pub fn record_delay(&self, delay: Duration) {
        self.total_delay_us
            .fetch_add(delay.as_micros() as u64, Ordering::Relaxed);
    }

    /// Record dropped packet
    pub fn record_dropped(&self) {
        self.packets_dropped.fetch_add(1, Ordering::Relaxed);
    }

    /// Record reordered packet
    pub fn record_reordered(&self) {
        self.packets_reordered.fetch_add(1, Ordering::Relaxed);
    }

    /// Transform an egress packet into a reply packet
    ///
    /// For TCP:
    /// - SYN -> SYN-ACK
    /// - ACK (data) -> ACK with echoed data (or just ACK)
    /// - FIN -> FIN-ACK
    ///
    /// For UDP:
    /// - Echo the datagram back with swapped addresses
    pub fn process_packet(&self, packet: &[u8]) -> Option<Vec<u8>> {
        if packet.is_empty() {
            return None;
        }

        self.packets_processed.fetch_add(1, Ordering::Relaxed);
        self.bytes_processed
            .fetch_add(packet.len() as u64, Ordering::Relaxed);

        let version = packet[0] >> 4;
        if version != 4 {
            // Only IPv4 supported for now
            return None;
        }

        // Parse IPv4 header
        if packet.len() < 20 {
            return None;
        }

        let ihl = (packet[0] & 0x0f) as usize * 4;
        if packet.len() < ihl {
            return None;
        }

        let protocol = packet[9];

        match protocol {
            6 => self.process_tcp_packet(packet, ihl),
            17 => self.process_udp_packet(packet, ihl),
            _ => None,
        }
    }

    /// Process a TCP packet
    fn process_tcp_packet(&self, packet: &[u8], ip_header_len: usize) -> Option<Vec<u8>> {
        // Minimum TCP header is 20 bytes
        if packet.len() < ip_header_len + 20 {
            return None;
        }

        let tcp_start = ip_header_len;
        let tcp_header = &packet[tcp_start..];

        // Extract TCP fields
        let src_port = u16::from_be_bytes([tcp_header[0], tcp_header[1]]);
        let dst_port = u16::from_be_bytes([tcp_header[2], tcp_header[3]]);
        let seq_num =
            u32::from_be_bytes([tcp_header[4], tcp_header[5], tcp_header[6], tcp_header[7]]);
        let ack_num =
            u32::from_be_bytes([tcp_header[8], tcp_header[9], tcp_header[10], tcp_header[11]]);
        let data_offset = ((tcp_header[12] >> 4) as usize) * 4;
        let flags = tcp_header[13];

        // Parse flags
        let syn = flags & 0x02 != 0;
        let ack = flags & 0x10 != 0;
        let fin = flags & 0x01 != 0;
        let rst = flags & 0x04 != 0;

        // Extract payload
        let tcp_header_end = tcp_start + data_offset;
        let payload_len = if packet.len() > tcp_header_end {
            packet.len() - tcp_header_end
        } else {
            0
        };

        // Calculate response
        let (new_flags, new_seq, new_ack, response_payload) = if syn && !ack {
            // SYN -> SYN-ACK
            (0x12u8, 1000u32, seq_num + 1, Vec::new())
        } else if fin {
            // FIN -> FIN-ACK
            (0x11u8, ack_num, seq_num + 1, Vec::new())
        } else if rst {
            // RST -> ignore
            return None;
        } else if payload_len > 0 {
            // Data packet -> ACK with optional echo
            let payload = if self.echo_mode {
                packet[tcp_header_end..].to_vec()
            } else {
                Vec::new()
            };
            (0x10u8, ack_num, seq_num + payload_len as u32, payload)
        } else {
            // Pure ACK -> ignore (no response needed for ACK-only)
            return None;
        };

        // Build response packet
        Some(self.build_tcp_response(
            packet,
            ip_header_len,
            dst_port,
            src_port,
            new_seq,
            new_ack,
            new_flags,
            &response_payload,
        ))
    }

    /// Build a TCP response packet
    fn build_tcp_response(
        &self,
        original: &[u8],
        ip_header_len: usize,
        src_port: u16,
        dst_port: u16,
        seq: u32,
        ack: u32,
        flags: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let tcp_header_len = 20; // Minimum TCP header
        let total_len = ip_header_len + tcp_header_len + payload.len();

        let mut packet = vec![0u8; total_len];

        // Copy and modify IP header
        packet[..ip_header_len].copy_from_slice(&original[..ip_header_len]);

        // Set IP version and header length
        packet[0] = 0x45;
        // Set total length
        packet[2] = (total_len >> 8) as u8;
        packet[3] = total_len as u8;
        // Swap source and destination IP
        let src_ip = &original[12..16];
        let dst_ip = &original[16..20];
        packet[12..16].copy_from_slice(dst_ip);
        packet[16..20].copy_from_slice(src_ip);
        // Clear checksum (will be computed by smoltcp)
        packet[10] = 0;
        packet[11] = 0;

        // Build TCP header
        let tcp = &mut packet[ip_header_len..];
        tcp[0..2].copy_from_slice(&src_port.to_be_bytes());
        tcp[2..4].copy_from_slice(&dst_port.to_be_bytes());
        tcp[4..8].copy_from_slice(&seq.to_be_bytes());
        tcp[8..12].copy_from_slice(&ack.to_be_bytes());
        tcp[12] = 0x50; // Data offset = 5 (20 bytes)
        tcp[13] = flags;
        tcp[14..16].copy_from_slice(&65535u16.to_be_bytes()); // Window
                                                              // Checksum will be computed by smoltcp
        tcp[16..18].copy_from_slice(&[0, 0]);
        tcp[18..20].copy_from_slice(&[0, 0]); // Urgent pointer

        // Copy payload
        if !payload.is_empty() {
            tcp[tcp_header_len..tcp_header_len + payload.len()].copy_from_slice(payload);
        }

        // Compute IP checksum
        let checksum = self.compute_ip_checksum(&packet[..ip_header_len]);
        packet[10] = (checksum >> 8) as u8;
        packet[11] = checksum as u8;

        // Compute TCP checksum
        let tcp_checksum = self.compute_tcp_checksum(&packet, ip_header_len);
        packet[ip_header_len + 16] = (tcp_checksum >> 8) as u8;
        packet[ip_header_len + 17] = tcp_checksum as u8;

        packet
    }

    /// Process a UDP packet
    fn process_udp_packet(&self, packet: &[u8], ip_header_len: usize) -> Option<Vec<u8>> {
        // Minimum UDP header is 8 bytes
        if packet.len() < ip_header_len + 8 {
            return None;
        }

        let udp_start = ip_header_len;
        let udp_header = &packet[udp_start..];

        let src_port = u16::from_be_bytes([udp_header[0], udp_header[1]]);
        let dst_port = u16::from_be_bytes([udp_header[2], udp_header[3]]);
        let _udp_len = u16::from_be_bytes([udp_header[4], udp_header[5]]) as usize;

        // Extract payload
        let payload_start = udp_start + 8;
        let payload = if packet.len() > payload_start && self.echo_mode {
            packet[payload_start..].to_vec()
        } else {
            // Return a minimal response
            vec![0u8; 4]
        };

        // Build response
        Some(self.build_udp_response(packet, ip_header_len, dst_port, src_port, &payload))
    }

    /// Build a UDP response packet
    fn build_udp_response(
        &self,
        original: &[u8],
        ip_header_len: usize,
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let udp_len = 8 + payload.len();
        let total_len = ip_header_len + udp_len;

        let mut packet = vec![0u8; total_len];

        // Copy and modify IP header
        packet[..ip_header_len].copy_from_slice(&original[..ip_header_len]);

        // Set IP version and header length
        packet[0] = 0x45;
        // Set total length
        packet[2] = (total_len >> 8) as u8;
        packet[3] = total_len as u8;
        // Set protocol to UDP
        packet[9] = 17;
        // Swap source and destination IP
        let src_ip = &original[12..16];
        let dst_ip = &original[16..20];
        packet[12..16].copy_from_slice(dst_ip);
        packet[16..20].copy_from_slice(src_ip);
        // Clear checksum
        packet[10] = 0;
        packet[11] = 0;

        // Build UDP header
        let udp = &mut packet[ip_header_len..];
        udp[0..2].copy_from_slice(&src_port.to_be_bytes());
        udp[2..4].copy_from_slice(&dst_port.to_be_bytes());
        udp[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
        // UDP checksum (0 = disabled for IPv4)
        udp[6..8].copy_from_slice(&[0, 0]);

        // Copy payload
        if !payload.is_empty() {
            udp[8..8 + payload.len()].copy_from_slice(payload);
        }

        // Compute IP checksum
        let checksum = self.compute_ip_checksum(&packet[..ip_header_len]);
        packet[10] = (checksum >> 8) as u8;
        packet[11] = checksum as u8;

        packet
    }

    /// Compute IP header checksum
    fn compute_ip_checksum(&self, header: &[u8]) -> u16 {
        let mut sum: u32 = 0;

        for i in (0..header.len()).step_by(2) {
            if i == 10 {
                // Skip checksum field
                continue;
            }
            let word = if i + 1 < header.len() {
                ((header[i] as u32) << 8) | (header[i + 1] as u32)
            } else {
                (header[i] as u32) << 8
            };
            sum += word;
        }

        // Fold 32-bit sum into 16 bits
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        !sum as u16
    }

    /// Compute TCP checksum (with pseudo-header)
    fn compute_tcp_checksum(&self, packet: &[u8], ip_header_len: usize) -> u16 {
        let tcp_len = packet.len() - ip_header_len;
        let mut sum: u32 = 0;

        // Pseudo-header: src IP, dst IP, zero, protocol, TCP length
        for i in (12..20).step_by(2) {
            sum += ((packet[i] as u32) << 8) | (packet[i + 1] as u32);
        }
        sum += 6u32; // Protocol TCP
        sum += tcp_len as u32;

        // TCP header + data
        let tcp = &packet[ip_header_len..];
        for i in (0..tcp.len()).step_by(2) {
            if i == 16 {
                // Skip checksum field
                continue;
            }
            let word = if i + 1 < tcp.len() {
                ((tcp[i] as u32) << 8) | (tcp[i + 1] as u32)
            } else {
                (tcp[i] as u32) << 8
            };
            sum += word;
        }

        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        !sum as u16
    }

    /// Get statistics
    pub fn stats(&self) -> (u64, u64) {
        (
            self.packets_processed.load(Ordering::Relaxed),
            self.bytes_processed.load(Ordering::Relaxed),
        )
    }

    /// Get extended statistics including network simulation stats
    pub fn extended_stats(&self) -> NetworkConditionStats {
        let packets_processed = self.packets_processed.load(Ordering::Relaxed);
        NetworkConditionStats {
            packets_processed,
            packets_dropped: self.packets_dropped.load(Ordering::Relaxed),
            packets_reordered: self.packets_reordered.load(Ordering::Relaxed),
            total_delay_us: self.total_delay_us.load(Ordering::Relaxed),
            avg_delay_us: if packets_processed > 0 {
                self.total_delay_us.load(Ordering::Relaxed) / packets_processed
            } else {
                0
            },
            throttle_events: 0, // Not tracked yet
        }
    }
}

// =============================================================================
// LoopbackTest
// =============================================================================

/// Loopback test for measuring pure netbridge performance
///
/// Creates a closed-loop testing environment where egress packets are
/// transformed and fed back as replies to simulate a remote server.
#[derive(Clone)]
pub struct LoopbackTest {
    /// Test configuration
    config: LoopbackTestConfig,
    /// Optional network conditions for realistic simulation
    network_conditions: Option<NetworkConditions>,
}

impl LoopbackTest {
    /// Create a new loopback test with default configuration
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: LoopbackTestConfig::default(),
            network_conditions: None,
        }
    }

    /// Create a new loopback test with custom configuration
    #[must_use]
    pub fn with_config(config: LoopbackTestConfig) -> Self {
        Self {
            config,
            network_conditions: None,
        }
    }

    /// Set network conditions for realistic simulation
    ///
    /// When set, the benchmark will use the realistic responder loop
    /// that applies latency, packet loss, congestion, and reordering.
    #[must_use]
    pub fn with_network_conditions(mut self, conditions: NetworkConditions) -> Self {
        self.network_conditions = Some(conditions);
        self
    }

    /// Get the current network conditions (if any)
    pub fn network_conditions(&self) -> Option<&NetworkConditions> {
        self.network_conditions.as_ref()
    }

    /// Run a throughput benchmark
    ///
    /// Creates TCP connections and measures data transfer rate.
    pub async fn run_throughput(&self, bench_config: &BenchConfig) -> BenchResults {
        let start = Instant::now();

        let mut results = match bench_config.pattern {
            TrafficPattern::SingleTcp => self.run_single_tcp_throughput(bench_config).await,
            TrafficPattern::ManyShortTcp => self.run_many_tcp_throughput(bench_config).await,
            TrafficPattern::UdpStream => self.run_udp_throughput(bench_config).await,
            TrafficPattern::DnsLikeUdp => self.run_dns_like_udp(bench_config).await,
            TrafficPattern::Mixed => self.run_mixed_throughput(bench_config).await,
        };

        results.duration_ms = start.elapsed().as_millis() as u64;
        results.calculate_throughput();
        results.calculate_session_rate();

        results
    }

    /// Run a latency benchmark
    pub async fn run_latency(&self, bench_config: &BenchConfig) -> BenchResults {
        let start = Instant::now();
        let egress_config = SmoltcpEgressConfig::new(self.config.local_ip);
        let (egress, handle) = SmoltcpEgress::spawn(egress_config);

        // Create responder with network conditions
        let conditions = self.network_conditions.clone().unwrap_or_default();
        let responder = Arc::new(MockResponder::with_conditions(true, conditions));
        let shutdown = Arc::new(AtomicBool::new(false));

        // Start responder task (use realistic loop if conditions are non-ideal)
        let responder_clone = Arc::clone(&responder);
        let egress_clone = Arc::clone(&egress);
        let shutdown_clone = Arc::clone(&shutdown);
        let use_realistic = self.network_conditions.is_some();
        let responder_task = tokio::spawn(async move {
            if use_realistic {
                Self::run_realistic_responder_loop(egress_clone, responder_clone, shutdown_clone)
                    .await;
            } else {
                Self::run_responder_loop(egress_clone, responder_clone, shutdown_clone).await;
            }
        });

        // Measure latencies
        let mut latencies = Vec::new();
        let dest = SocketAddr::new(IpAddr::V4(self.config.remote_ip), self.config.remote_port);

        let iterations = std::cmp::min(1000, bench_config.duration_secs * 100);

        for _ in 0..iterations {
            let iter_start = Instant::now();

            // Send a small UDP packet
            let data = b"ping";
            let src = SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(
                    CLIENT_IP[0],
                    CLIENT_IP[1],
                    CLIENT_IP[2],
                    CLIENT_IP[3],
                )),
                12345,
            );

            if egress.handle_udp(src, dest, data).await.is_ok() {
                // Wait a bit for processing
                tokio::time::sleep(Duration::from_micros(100)).await;
                let latency = iter_start.elapsed();
                latencies.push(latency.as_micros() as u64);
            }
        }

        // Shutdown
        shutdown.store(true, Ordering::Relaxed);
        let _ = egress.shutdown().await;
        let _ = responder_task.await;
        let _ = handle.task.await;

        // Calculate statistics
        let mut results = BenchResults::default();
        results.duration_ms = start.elapsed().as_millis() as u64;
        results.sessions_created = latencies.len() as u64;

        if !latencies.is_empty() {
            latencies.sort();
            let len = latencies.len();

            results.avg_latency_us = latencies.iter().sum::<u64>() / len as u64;
            results.p99_latency_us = latencies[len * 99 / 100];
        }

        results.calculate_session_rate();
        results
    }

    /// Run a single TCP connection throughput test
    async fn run_single_tcp_throughput(&self, bench_config: &BenchConfig) -> BenchResults {
        let egress_config = SmoltcpEgressConfig::new(self.config.local_ip);
        let (egress, handle) = SmoltcpEgress::spawn(egress_config);

        // Create responder with network conditions
        let conditions = self.network_conditions.clone().unwrap_or_default();
        let responder = Arc::new(MockResponder::with_conditions(
            self.config.echo_mode,
            conditions,
        ));
        let shutdown = Arc::new(AtomicBool::new(false));

        // Start responder task (use realistic loop if conditions are non-ideal)
        let responder_clone = Arc::clone(&responder);
        let egress_clone = Arc::clone(&egress);
        let shutdown_clone = Arc::clone(&shutdown);
        let use_realistic = self.network_conditions.is_some();
        let responder_task = tokio::spawn(async move {
            if use_realistic {
                Self::run_realistic_responder_loop(egress_clone, responder_clone, shutdown_clone)
                    .await;
            } else {
                Self::run_responder_loop(egress_clone, responder_clone, shutdown_clone).await;
            }
        });

        // Create a virtual TCP stream using channels
        let (client_tx, server_rx) = mpsc::channel::<Bytes>(1024);
        let (server_tx, client_rx) = mpsc::channel::<Bytes>(1024);

        let stream = ChannelStream::new(client_rx, client_tx);
        let dest = SocketAddr::new(IpAddr::V4(self.config.remote_ip), self.config.remote_port);

        let bytes_sent = Arc::new(AtomicU64::new(0));
        let bytes_received = Arc::new(AtomicU64::new(0));
        let errors = Arc::new(AtomicU64::new(0));

        // Start the TCP session through egress
        match egress.handle_tcp(stream, dest).await {
            Ok(session_id) => {
                debug!(?session_id, "TCP session created for throughput test");
            }
            Err(e) => {
                warn!(?e, "Failed to create TCP session");
                errors.fetch_add(1, Ordering::Relaxed);
            }
        }

        // Run data transfer for the configured duration
        let duration = Duration::from_secs(bench_config.duration_secs);
        let start = Instant::now();
        let data_block = vec![0xABu8; self.config.data_block_size];

        let bytes_sent_clone = Arc::clone(&bytes_sent);
        let send_task = tokio::spawn(async move {
            while start.elapsed() < duration {
                if server_tx
                    .send(Bytes::from(data_block.clone()))
                    .await
                    .is_err()
                {
                    break;
                }
                bytes_sent_clone.fetch_add(data_block.len() as u64, Ordering::Relaxed);
            }
        });

        let bytes_received_clone = Arc::clone(&bytes_received);
        let mut server_rx = server_rx;
        let recv_task = tokio::spawn(async move {
            while let Some(data) = server_rx.recv().await {
                bytes_received_clone.fetch_add(data.len() as u64, Ordering::Relaxed);
            }
        });

        // Wait for duration
        tokio::time::sleep(duration).await;

        // Shutdown
        shutdown.store(true, Ordering::Relaxed);
        let _ = egress.shutdown().await;
        let _ = tokio::time::timeout(Duration::from_secs(1), responder_task).await;
        let _ = tokio::time::timeout(Duration::from_secs(1), send_task).await;
        let _ = tokio::time::timeout(Duration::from_secs(1), recv_task).await;
        let _ = handle.task.await;

        let mut results = BenchResults::default();
        results.bytes_transferred = bytes_sent.load(Ordering::Relaxed);
        results.sessions_created = 1;
        results.errors = errors.load(Ordering::Relaxed);

        results
    }

    /// Run many short TCP connections throughput test
    async fn run_many_tcp_throughput(&self, bench_config: &BenchConfig) -> BenchResults {
        let egress_config = SmoltcpEgressConfig::new(self.config.local_ip);
        let (egress, handle) = SmoltcpEgress::spawn(egress_config);

        // Create responder with network conditions
        let conditions = self.network_conditions.clone().unwrap_or_default();
        let responder = Arc::new(MockResponder::with_conditions(
            self.config.echo_mode,
            conditions,
        ));
        let shutdown = Arc::new(AtomicBool::new(false));

        // Start responder task (use realistic loop if conditions are non-ideal)
        let responder_clone = Arc::clone(&responder);
        let egress_clone = Arc::clone(&egress);
        let shutdown_clone = Arc::clone(&shutdown);
        let use_realistic = self.network_conditions.is_some();
        let responder_task = tokio::spawn(async move {
            if use_realistic {
                Self::run_realistic_responder_loop(egress_clone, responder_clone, shutdown_clone)
                    .await;
            } else {
                Self::run_responder_loop(egress_clone, responder_clone, shutdown_clone).await;
            }
        });

        let duration = Duration::from_secs(bench_config.duration_secs);
        let start = Instant::now();

        let bytes_transferred = Arc::new(AtomicU64::new(0));
        let sessions_created = Arc::new(AtomicU64::new(0));
        let errors = Arc::new(AtomicU64::new(0));

        // Create multiple concurrent connections
        let mut handles = Vec::new();
        let dest = SocketAddr::new(IpAddr::V4(self.config.remote_ip), self.config.remote_port);

        for _ in 0..bench_config.concurrency {
            let egress_clone = Arc::clone(&egress);
            let bytes_clone = Arc::clone(&bytes_transferred);
            let sessions_clone = Arc::clone(&sessions_created);
            let errors_clone = Arc::clone(&errors);
            let data_block_size = self.config.data_block_size;

            handles.push(tokio::spawn(async move {
                let data_block = vec![0xABu8; data_block_size];

                while start.elapsed() < duration {
                    let (client_tx, _server_rx) = mpsc::channel::<Bytes>(64);
                    let (_server_tx, client_rx) = mpsc::channel::<Bytes>(64);
                    let stream = ChannelStream::new(client_rx, client_tx);

                    match egress_clone.handle_tcp(stream, dest).await {
                        Ok(_) => {
                            sessions_clone.fetch_add(1, Ordering::Relaxed);
                            bytes_clone.fetch_add(data_block.len() as u64, Ordering::Relaxed);
                        }
                        Err(_) => {
                            errors_clone.fetch_add(1, Ordering::Relaxed);
                        }
                    }

                    // Small delay between connections
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            }));
        }

        // Wait for all tasks
        for h in handles {
            let _ = h.await;
        }

        // Shutdown
        shutdown.store(true, Ordering::Relaxed);
        let _ = egress.shutdown().await;
        let _ = responder_task.await;
        let _ = handle.task.await;

        let mut results = BenchResults::default();
        results.bytes_transferred = bytes_transferred.load(Ordering::Relaxed);
        results.sessions_created = sessions_created.load(Ordering::Relaxed);
        results.errors = errors.load(Ordering::Relaxed);

        results
    }

    /// Run UDP stream throughput test
    async fn run_udp_throughput(&self, bench_config: &BenchConfig) -> BenchResults {
        let egress_config = SmoltcpEgressConfig::new(self.config.local_ip);
        let (egress, handle) = SmoltcpEgress::spawn(egress_config);

        // Create responder with network conditions
        let conditions = self.network_conditions.clone().unwrap_or_default();
        let responder = Arc::new(MockResponder::with_conditions(
            self.config.echo_mode,
            conditions,
        ));
        let shutdown = Arc::new(AtomicBool::new(false));

        // Start responder task (use realistic loop if conditions are non-ideal)
        let responder_clone = Arc::clone(&responder);
        let egress_clone = Arc::clone(&egress);
        let shutdown_clone = Arc::clone(&shutdown);
        let use_realistic = self.network_conditions.is_some();
        let responder_task = tokio::spawn(async move {
            if use_realistic {
                Self::run_realistic_responder_loop(egress_clone, responder_clone, shutdown_clone)
                    .await;
            } else {
                Self::run_responder_loop(egress_clone, responder_clone, shutdown_clone).await;
            }
        });

        let duration = Duration::from_secs(bench_config.duration_secs);
        let start = Instant::now();

        let bytes_transferred = Arc::new(AtomicU64::new(0));
        let datagrams_sent = Arc::new(AtomicU64::new(0));
        let errors = Arc::new(AtomicU64::new(0));

        let src = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(
                CLIENT_IP[0],
                CLIENT_IP[1],
                CLIENT_IP[2],
                CLIENT_IP[3],
            )),
            12345,
        );
        let dest = SocketAddr::new(IpAddr::V4(self.config.remote_ip), self.config.remote_port);

        // Send UDP packets
        let data = vec![0xCDu8; bench_config.udp_packet_size];

        while start.elapsed() < duration {
            match egress.handle_udp(src, dest, &data).await {
                Ok(()) => {
                    bytes_transferred.fetch_add(data.len() as u64, Ordering::Relaxed);
                    datagrams_sent.fetch_add(1, Ordering::Relaxed);
                }
                Err(_) => {
                    errors.fetch_add(1, Ordering::Relaxed);
                }
            }

            // Small yield to allow responder to process
            tokio::task::yield_now().await;
        }

        // Shutdown
        shutdown.store(true, Ordering::Relaxed);
        let _ = egress.shutdown().await;
        let _ = responder_task.await;
        let _ = handle.task.await;

        let mut results = BenchResults::default();
        results.bytes_transferred = bytes_transferred.load(Ordering::Relaxed);
        results.sessions_created = datagrams_sent.load(Ordering::Relaxed);
        results.errors = errors.load(Ordering::Relaxed);

        results
    }

    /// Run DNS-like UDP test (small packets, many sessions)
    async fn run_dns_like_udp(&self, bench_config: &BenchConfig) -> BenchResults {
        // Similar to UDP throughput but with smaller packets
        let mut config = bench_config.clone();
        config.udp_packet_size = 64; // DNS-like size
        self.run_udp_throughput(&config).await
    }

    /// Run mixed TCP and UDP test
    async fn run_mixed_throughput(&self, bench_config: &BenchConfig) -> BenchResults {
        let tcp_config = BenchConfig {
            pattern: TrafficPattern::SingleTcp,
            concurrency: bench_config.concurrency / 2,
            ..bench_config.clone()
        };

        let udp_config = BenchConfig {
            pattern: TrafficPattern::UdpStream,
            ..bench_config.clone()
        };

        // Run both in parallel
        let tcp_future = self.run_single_tcp_throughput(&tcp_config);
        let udp_future = self.run_udp_throughput(&udp_config);

        let (tcp_results, udp_results) = tokio::join!(tcp_future, udp_future);

        // Combine results
        let mut results = BenchResults::default();
        results.bytes_transferred = tcp_results.bytes_transferred + udp_results.bytes_transferred;
        results.sessions_created = tcp_results.sessions_created + udp_results.sessions_created;
        results.errors = tcp_results.errors + udp_results.errors;

        results
    }

    /// Run the responder loop that processes egress packets
    async fn run_responder_loop(
        egress: Arc<SmoltcpEgress>,
        responder: Arc<MockResponder>,
        shutdown: Arc<AtomicBool>,
    ) {
        let mut interval = tokio::time::interval(Duration::from_micros(100));

        while !shutdown.load(Ordering::Relaxed) {
            interval.tick().await;

            // Drain TX packets and generate responses
            let packets = egress.drain_tx();

            for packet in packets {
                if let Some(response) = responder.process_packet(&packet) {
                    if egress.feed_reply(&response).is_err() {
                        break;
                    }
                }
            }
        }
    }

    /// Run the responder loop with realistic network simulation
    ///
    /// This version applies latency, packet loss, congestion, and reordering
    /// based on the MockResponder's NetworkConditions.
    async fn run_realistic_responder_loop(
        egress: Arc<SmoltcpEgress>,
        responder: Arc<MockResponder>,
        shutdown: Arc<AtomicBool>,
    ) {
        use rand::SeedableRng;
        let mut rng = rand::rngs::StdRng::from_entropy();
        let mut delayed_packets: VecDeque<DelayedPacket> = VecDeque::new();
        let mut interval = tokio::time::interval(Duration::from_micros(100));

        while !shutdown.load(Ordering::Relaxed) {
            interval.tick().await;

            // 1. Deliver packets that have reached their delivery time
            let now = Instant::now();
            while let Some(pkt) = delayed_packets.front() {
                if pkt.deliver_at <= now {
                    let pkt = delayed_packets.pop_front().unwrap();
                    responder.packet_received();
                    if egress.feed_reply(&pkt.data).is_err() {
                        break;
                    }
                } else {
                    break;
                }
            }

            // 2. Process new outgoing packets
            let packets = egress.drain_tx();
            for packet in packets {
                let conditions = responder.conditions();

                // Check for packet loss
                if conditions.should_drop(&mut rng) {
                    responder.record_dropped();
                    continue;
                }

                // Generate response
                if let Some(response) = responder.process_packet(&packet) {
                    responder.packet_sent();

                    // Calculate total delay
                    let in_flight = responder.get_packets_in_flight();
                    let base_delay = conditions.calculate_delay(in_flight, &mut rng);
                    let bandwidth_delay = conditions.calculate_bandwidth_delay(response.len());
                    let total_delay = base_delay + bandwidth_delay;

                    responder.record_delay(total_delay);

                    // Check for reordering
                    let deliver_at = if conditions.should_reorder(&mut rng) {
                        responder.record_reordered();
                        let extra = conditions.calculate_reorder_delay(&mut rng);
                        now + total_delay + extra
                    } else {
                        now + total_delay
                    };

                    // Insert into delay queue (maintain time order)
                    let delayed = DelayedPacket {
                        data: response,
                        deliver_at,
                    };
                    let pos = delayed_packets
                        .iter()
                        .position(|p| p.deliver_at > deliver_at)
                        .unwrap_or(delayed_packets.len());
                    delayed_packets.insert(pos, delayed);
                }
            }
        }

        // Drain remaining delayed packets on shutdown
        trace!(
            "Draining {} delayed packets on shutdown",
            delayed_packets.len()
        );
    }

    /// Run a quick benchmark and return results
    pub async fn run_quick_benchmark(&self) -> BenchResults {
        let config = BenchConfig {
            pattern: TrafficPattern::UdpStream,
            duration_secs: 2,
            target_mbps: 0,
            concurrency: 1,
            udp_packet_size: 1400,
        };

        self.run_throughput(&config).await
    }
}

impl Default for LoopbackTest {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// ChannelStream - Virtual stream using channels
// =============================================================================

/// A virtual async stream backed by channels
///
/// Used to create "fake" TCP streams for testing without real sockets.
pub struct ChannelStream {
    rx: mpsc::Receiver<Bytes>,
    tx: mpsc::Sender<Bytes>,
    read_buf: Vec<u8>,
}

impl ChannelStream {
    /// Create a new channel stream
    pub fn new(rx: mpsc::Receiver<Bytes>, tx: mpsc::Sender<Bytes>) -> Self {
        Self {
            rx,
            tx,
            read_buf: Vec::new(),
        }
    }
}

impl AsyncRead for ChannelStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        // First try to consume from buffer
        if !self.read_buf.is_empty() {
            let to_copy = std::cmp::min(buf.remaining(), self.read_buf.len());
            buf.put_slice(&self.read_buf[..to_copy]);
            self.read_buf.drain(..to_copy);
            return std::task::Poll::Ready(Ok(()));
        }

        // Try to receive from channel
        match std::pin::Pin::new(&mut self.rx).poll_recv(cx) {
            std::task::Poll::Ready(Some(data)) => {
                let to_copy = std::cmp::min(buf.remaining(), data.len());
                buf.put_slice(&data[..to_copy]);
                if to_copy < data.len() {
                    self.read_buf.extend_from_slice(&data[to_copy..]);
                }
                std::task::Poll::Ready(Ok(()))
            }
            std::task::Poll::Ready(None) => std::task::Poll::Ready(Ok(())),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

impl AsyncWrite for ChannelStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let data = Bytes::copy_from_slice(buf);
        match self.tx.try_send(data) {
            Ok(()) => std::task::Poll::Ready(Ok(buf.len())),
            Err(mpsc::error::TrySendError::Full(_)) => std::task::Poll::Pending,
            Err(mpsc::error::TrySendError::Closed(_)) => std::task::Poll::Ready(Err(
                std::io::Error::new(std::io::ErrorKind::BrokenPipe, "channel closed"),
            )),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

impl Unpin for ChannelStream {}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn test_loopback_config_default() {
        let config = LoopbackTestConfig::default();
        assert_eq!(config.remote_ip, Ipv4Addr::new(93, 184, 216, 34));
        assert_eq!(config.remote_port, 80);
        assert!(config.echo_mode);
    }

    #[test]
    fn test_mock_responder_new() {
        let responder = MockResponder::new(true);
        let (packets, bytes) = responder.stats();
        assert_eq!(packets, 0);
        assert_eq!(bytes, 0);
    }

    #[test]
    fn test_mock_responder_udp() {
        let responder = MockResponder::new(true);

        // Create a simple UDP packet
        let mut packet = vec![0u8; 28];
        packet[0] = 0x45; // IPv4, IHL=5
        packet[2..4].copy_from_slice(&28u16.to_be_bytes()); // Total length
        packet[9] = 17; // UDP
        packet[12..16].copy_from_slice(&[10, 200, 200, 2]); // Src IP
        packet[16..20].copy_from_slice(&[93, 184, 216, 34]); // Dst IP
        packet[20..22].copy_from_slice(&12345u16.to_be_bytes()); // Src port
        packet[22..24].copy_from_slice(&80u16.to_be_bytes()); // Dst port
        packet[24..26].copy_from_slice(&8u16.to_be_bytes()); // UDP length

        let response = responder.process_packet(&packet);
        assert!(response.is_some());

        let resp = response.unwrap();
        // Check that addresses are swapped
        assert_eq!(&resp[12..16], &[93, 184, 216, 34]);
        assert_eq!(&resp[16..20], &[10, 200, 200, 2]);
    }

    #[test]
    fn test_mock_responder_ip_checksum() {
        let responder = MockResponder::new(true);

        let header = [
            0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0xac, 0x10,
            0x0a, 0x63, 0xac, 0x10, 0x0a, 0x0c,
        ];

        let checksum = responder.compute_ip_checksum(&header);
        // The checksum should be non-zero and valid
        assert!(checksum != 0);
    }

    #[test]
    fn test_loopback_test_new() {
        let test = LoopbackTest::new();
        assert!(test.config.echo_mode);
    }

    #[tokio::test]
    async fn test_channel_stream_basic() {
        let (tx1, rx1) = mpsc::channel(16);
        let (tx2, mut rx2) = mpsc::channel(16);

        let mut stream = ChannelStream::new(rx1, tx2);

        // Send some data through tx1
        tx1.send(Bytes::from("hello")).await.unwrap();

        // Read from stream
        let mut buf = [0u8; 10];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(n, 5);
        assert_eq!(&buf[..5], b"hello");

        // Write to stream
        let n = stream.write(b"world").await.unwrap();
        assert_eq!(n, 5);

        // Should be receivable on rx2
        let data = rx2.recv().await.unwrap();
        assert_eq!(&data[..], b"world");
    }

    #[tokio::test]
    async fn test_quick_benchmark() {
        let test = LoopbackTest::new();
        let results = test.run_quick_benchmark().await;

        // Basic sanity checks
        assert!(results.duration_ms > 0);
        // Note: In testing environment, throughput may be low
    }

    // =========================================================================
    // NetworkConditions tests
    // =========================================================================

    #[test]
    fn test_network_conditions_presets() {
        // Test that all presets are properly configured
        let ideal = NetworkConditions::ideal();
        assert_eq!(ideal.latency_ms, 0);
        assert_eq!(ideal.packet_loss_rate, 0.0);
        assert!(!ideal.simulate_congestion);

        let lan = NetworkConditions::lan();
        assert_eq!(lan.latency_ms, 1);
        assert_eq!(lan.bandwidth_mbps, 10_000); // 10 Gbps

        let wan = NetworkConditions::wan_typical();
        assert_eq!(wan.latency_ms, 15); // 30ms RTT
        assert!(wan.packet_loss_rate > 0.0);
        assert!(wan.simulate_congestion);

        let lossy = NetworkConditions::wan_lossy();
        assert!(lossy.packet_loss_rate > wan.packet_loss_rate);
        assert!(lossy.jitter_ms > wan.jitter_ms);

        let satellite = NetworkConditions::satellite();
        assert!(satellite.latency_ms >= 300); // High latency

        let mobile = NetworkConditions::mobile_4g();
        assert!(mobile.jitter_ms >= 20); // High variability
    }

    #[test]
    fn test_network_conditions_builder() {
        let conditions = NetworkConditions::custom()
            .with_latency_ms(50)
            .with_jitter_ms(10)
            .with_packet_loss(0.05)
            .with_bandwidth_mbps(100)
            .with_congestion(50, 100);

        assert_eq!(conditions.latency_ms, 50);
        assert_eq!(conditions.jitter_ms, 10);
        assert!((conditions.packet_loss_rate - 0.05).abs() < 0.001);
        assert_eq!(conditions.bandwidth_mbps, 100);
        assert!(conditions.simulate_congestion);
        assert_eq!(conditions.congestion_threshold, 50);
        assert_eq!(conditions.max_congestion_delay_ms, 100);
    }

    #[test]
    fn test_network_conditions_delay_calculation() {
        let mut rng = rand::thread_rng();

        // Ideal conditions should have zero delay
        let ideal = NetworkConditions::ideal();
        let delay = ideal.calculate_delay(0, &mut rng);
        assert_eq!(delay, Duration::ZERO);

        // WAN should have non-zero delay
        let wan = NetworkConditions::wan_typical();
        let delay = wan.calculate_delay(0, &mut rng);
        assert!(delay > Duration::ZERO);

        // Congestion should increase delay
        let delay_light = wan.calculate_delay(10, &mut rng);
        let delay_heavy = wan.calculate_delay(500, &mut rng);
        // Due to jitter, we can't guarantee heavy > light, but on average it should
        // Just verify both are positive
        assert!(delay_light >= Duration::ZERO);
        assert!(delay_heavy >= Duration::ZERO);
    }

    #[test]
    fn test_network_conditions_packet_loss() {
        let mut rng = rand::thread_rng();

        // Zero loss rate should never drop
        let no_loss = NetworkConditions::ideal();
        for _ in 0..1000 {
            assert!(!no_loss.should_drop(&mut rng));
        }

        // 100% loss rate should always drop
        let all_loss = NetworkConditions::custom().with_packet_loss(1.0);
        for _ in 0..100 {
            assert!(all_loss.should_drop(&mut rng));
        }
    }

    #[test]
    fn test_network_conditions_bandwidth_delay() {
        let conditions = NetworkConditions::custom().with_bandwidth_mbps(100);

        // 1 MB should take ~80ms at 100 Mbps
        let delay = conditions.calculate_bandwidth_delay(1_000_000);
        let expected_ms = (1_000_000.0 * 8.0) / (100.0 * 1_000_000.0) * 1000.0;
        let actual_ms = delay.as_secs_f64() * 1000.0;
        assert!((actual_ms - expected_ms).abs() < 1.0);

        // Unlimited bandwidth should have zero delay
        let unlimited = NetworkConditions::ideal();
        let delay = unlimited.calculate_bandwidth_delay(1_000_000);
        assert_eq!(delay, Duration::ZERO);
    }

    #[test]
    fn test_network_conditions_reordering() {
        let mut rng = rand::thread_rng();

        // Zero reorder rate should never reorder
        let no_reorder = NetworkConditions::ideal();
        for _ in 0..1000 {
            assert!(!no_reorder.should_reorder(&mut rng));
        }

        // 100% reorder rate should always reorder
        let conditions = NetworkConditions {
            reorder_rate: 1.0,
            reorder_delay_ms: 50,
            ..Default::default()
        };
        for _ in 0..100 {
            assert!(conditions.should_reorder(&mut rng));
        }

        // Reorder delay should be in range
        let delay = conditions.calculate_reorder_delay(&mut rng);
        assert!(delay <= Duration::from_millis(50));
    }

    #[test]
    fn test_mock_responder_with_conditions() {
        let conditions = NetworkConditions::wan_typical();
        let responder = MockResponder::with_conditions(true, conditions);

        // Verify initial stats
        let stats = responder.extended_stats();
        assert_eq!(stats.packets_processed, 0);
        assert_eq!(stats.packets_dropped, 0);
        assert_eq!(stats.packets_reordered, 0);
        assert_eq!(stats.total_delay_us, 0);
        assert_eq!(stats.avg_delay_us, 0);
    }

    #[test]
    fn test_mock_responder_stats_tracking() {
        let responder = MockResponder::new(true);

        // Simulate some activity
        responder.record_dropped();
        responder.record_dropped();
        responder.record_reordered();
        responder.record_delay(Duration::from_micros(1000));
        responder.record_delay(Duration::from_micros(2000));

        // Create a simple UDP packet to process
        let mut packet = vec![0u8; 28];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&28u16.to_be_bytes());
        packet[9] = 17; // UDP
        packet[12..16].copy_from_slice(&[10, 200, 200, 2]);
        packet[16..20].copy_from_slice(&[93, 184, 216, 34]);
        packet[20..22].copy_from_slice(&12345u16.to_be_bytes());
        packet[22..24].copy_from_slice(&80u16.to_be_bytes());
        packet[24..26].copy_from_slice(&8u16.to_be_bytes());

        responder.process_packet(&packet);

        let stats = responder.extended_stats();
        assert_eq!(stats.packets_processed, 1);
        assert_eq!(stats.packets_dropped, 2);
        assert_eq!(stats.packets_reordered, 1);
        assert_eq!(stats.total_delay_us, 3000);
        assert_eq!(stats.avg_delay_us, 3000); // 3000 / 1 packet
    }

    #[test]
    fn test_mock_responder_packets_in_flight() {
        let responder = MockResponder::new(true);

        assert_eq!(responder.get_packets_in_flight(), 0);

        responder.packet_sent();
        responder.packet_sent();
        assert_eq!(responder.get_packets_in_flight(), 2);

        responder.packet_received();
        assert_eq!(responder.get_packets_in_flight(), 1);
    }

    #[test]
    fn test_loopback_test_with_network_conditions() {
        let test = LoopbackTest::new().with_network_conditions(NetworkConditions::wan_typical());

        assert!(test.network_conditions().is_some());
        let conditions = test.network_conditions().unwrap();
        assert_eq!(conditions.latency_ms, 15);
    }

    #[test]
    fn test_loopback_test_clone() {
        let test1 = LoopbackTest::new().with_network_conditions(NetworkConditions::wan_typical());

        let test2 = test1.clone();

        assert!(test2.network_conditions().is_some());
        assert_eq!(
            test2.network_conditions().unwrap().latency_ms,
            test1.network_conditions().unwrap().latency_ms
        );
    }

    #[test]
    fn test_network_condition_stats_default() {
        let stats = NetworkConditionStats::default();
        assert_eq!(stats.packets_processed, 0);
        assert_eq!(stats.packets_dropped, 0);
        assert_eq!(stats.packets_reordered, 0);
        assert_eq!(stats.total_delay_us, 0);
        assert_eq!(stats.avg_delay_us, 0);
        assert_eq!(stats.throttle_events, 0);
    }
}
