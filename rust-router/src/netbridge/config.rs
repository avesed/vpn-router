//! Configuration constants for the netbridge module
//!
//! This module defines all configuration constants used throughout the netbridge
//! implementations. These values are tuned for high-performance (500+ Mbps) operation
//! with WireGuard tunnels.
//!
//! # Performance Tuning
//!
//! The buffer sizes in this module are significantly larger than typical defaults
//! to achieve 500+ Mbps throughput:
//!
//! - TCP buffers: 1 MB each (vs 64 KB typical) for large bandwidth-delay products
//! - UDP buffers: 256 KB each for handling bursts
//!
//! # Network Parameters
//!
//! Socket and buffer sizes are optimized for the WireGuard MTU of 1420 bytes:
//!
//! - TCP MSS is set to 1380 bytes (MTU 1420 - IP header 20 - TCP header 20)
//! - This ensures TCP segments fit within a single WireGuard packet
//!
//! # Timeout Values
//!
//! Timeouts follow RFC recommendations and common practice:
//!
//! - TCP idle timeout: 300 seconds (5 minutes)
//! - UDP default timeout: 30 seconds
//! - UDP DNS timeout: 10 seconds
//! - Port TIME_WAIT: 60 seconds (RFC 793 recommends 2*MSL)
//!
//! # Memory Usage Estimation
//!
//! Memory usage can be estimated as:
//! ```text
//! max_sessions * (tcp_rx + tcp_tx + udp_rx + udp_tx) + base_overhead
//! ```
//!
//! Example configurations:
//! - High-performance (1 MB buffers, 10K sessions): ~20 GB peak
//! - Balanced (256 KB buffers, 10K sessions): ~5 GB peak
//! - Conservative (64 KB buffers, 2K sessions): ~256 MB peak

use std::time::Duration;

// =============================================================================
// Network Parameters
// =============================================================================

/// Maximum number of smoltcp sockets per bridge instance
///
/// Increased from typical defaults to support high-concurrency scenarios.
/// Each TCP/UDP session requires one or more smoltcp sockets.
pub const MAX_SOCKETS: usize = 2048;

/// TCP Maximum Segment Size
///
/// Calculated as: WireGuard MTU (1420) - IP header (20) - TCP header (20) = 1380
/// This ensures TCP segments fit within a single WireGuard packet without fragmentation.
pub const TCP_MSS: u16 = 1380;

/// WireGuard Maximum Transmission Unit
///
/// Standard WireGuard MTU, accounting for the WireGuard overhead (40 bytes)
/// on top of the underlying transport.
pub const WG_MTU: usize = 1420;

/// Default TUN device MTU
///
/// Same as WireGuard MTU for seamless packet forwarding.
pub const TUN_MTU: usize = 1420;

/// Maximum IP packet size for buffer allocation
///
/// Set to the maximum IPv4 packet size (65535 bytes) to handle jumbo frames
/// if needed, though most traffic will be at or below WG_MTU.
pub const MAX_IP_PACKET_SIZE: usize = 65535;

// =============================================================================
// Buffer Sizes - High Performance Configuration
// =============================================================================

/// TCP receive buffer size (1 MB for 500+ Mbps)
///
/// Large buffers are critical for high throughput over links with significant
/// bandwidth-delay product. 1 MB allows for ~8 Mbps with 1 second RTT, or
/// ~800 Mbps with 10 ms RTT.
///
/// This is 16x larger than the typical 64 KB default.
pub const TCP_RX_BUFFER: usize = 1_048_576; // 1 MB

/// TCP transmit buffer size (1 MB for 500+ Mbps)
///
/// Matched to the receive buffer size for symmetric performance.
pub const TCP_TX_BUFFER: usize = 1_048_576; // 1 MB

/// UDP receive buffer size (256 KB)
///
/// Large enough to handle UDP bursts without dropping packets.
/// UDP traffic is typically more bursty than TCP.
pub const UDP_RX_BUFFER: usize = 262_144; // 256 KB

/// UDP transmit buffer size (256 KB)
///
/// Matched to the receive buffer size for symmetric performance.
pub const UDP_TX_BUFFER: usize = 262_144; // 256 KB

/// UDP packet metadata count
///
/// Number of packet metadata slots in the UDP socket buffer.
/// Each slot tracks one queued UDP packet. Increased for burst handling.
pub const UDP_PACKET_META: usize = 256;

/// Reply channel buffer size
///
/// Size of the async channel used to receive reply packets from the
/// outbound layer. Should be large enough to handle bursts.
pub const REPLY_CHANNEL_SIZE: usize = 4096;

/// Ingress packet channel size
///
/// Size of the channel for incoming IP packets from WireGuard/TUN.
pub const INGRESS_CHANNEL_SIZE: usize = 4096;

// =============================================================================
// Port Allocation
// =============================================================================

/// Ephemeral port range start
///
/// IANA recommends 49152-65535 for dynamic/private ports.
/// Using this standard range ensures compatibility with most networks.
pub const PORT_RANGE_START: u16 = 49152;

/// Ephemeral port range end
///
/// IANA recommends 49152-65535 for dynamic/private ports.
pub const PORT_RANGE_END: u16 = 65535;

// =============================================================================
// Timeout Parameters
// =============================================================================

/// TCP idle timeout in seconds
///
/// Connections with no activity for this duration are considered dead
/// and will be cleaned up. Set to 5 minutes, matching common TCP
/// keepalive intervals.
pub const TCP_IDLE_TIMEOUT_SECS: u64 = 300;

/// UDP default timeout in seconds
///
/// UDP "sessions" (request-response pairs) timeout after this duration.
/// Set to 30 seconds, suitable for most UDP applications.
pub const UDP_DEFAULT_TIMEOUT_SECS: u64 = 30;

/// UDP DNS timeout in seconds
///
/// DNS queries should complete quickly, so we use a shorter timeout
/// to free up resources faster.
pub const UDP_DNS_TIMEOUT_SECS: u64 = 10;

/// Port TIME_WAIT duration in seconds
///
/// After a TCP connection closes, the port enters TIME_WAIT to handle
/// delayed packets. RFC 793 recommends 2*MSL (Maximum Segment Lifetime),
/// which is typically 60 seconds.
pub const PORT_TIME_WAIT_SECS: u64 = 60;

/// Connection establishment timeout in seconds
///
/// Maximum time to wait for a TCP handshake to complete.
pub const CONNECT_TIMEOUT_SECS: u64 = 30;

/// SNI sniffing peek timeout in milliseconds
///
/// Maximum time to wait for initial data when sniffing for TLS SNI.
/// Kept short to minimize latency impact.
pub const SNI_PEEK_TIMEOUT_MS: u64 = 50;

// =============================================================================
// Session Limits
// =============================================================================

/// Maximum sessions per peer
///
/// Limits the number of concurrent sessions a single WireGuard peer can create.
/// This prevents a single client from exhausting resources.
pub const MAX_SESSIONS_PER_PEER: usize = 1000;

/// Maximum total sessions
///
/// Hard limit on the total number of concurrent sessions across all clients.
/// This protects against resource exhaustion under heavy load.
pub const MAX_TOTAL_SESSIONS: usize = 50_000;

/// Maximum session creation rate per client per second
///
/// Limits how fast a single client can create new sessions.
/// This prevents CPU exhaustion from rapid session creation/destruction.
pub const MAX_SESSIONS_PER_PEER_PER_SECOND: usize = 100;

/// Rate limit window duration in seconds
///
/// The time window for rate limiting session creation.
pub const RATE_LIMIT_WINDOW_SECS: u64 = 1;

// =============================================================================
// Cleanup Parameters
// =============================================================================

/// Cleanup interval in seconds
///
/// How often to run the idle session cleanup task.
pub const CLEANUP_INTERVAL_SECS: u64 = 30;

/// Batch size for cleanup operations
///
/// Maximum number of sessions to clean up in a single batch.
/// Prevents long blocking during cleanup.
pub const CLEANUP_BATCH_SIZE: usize = 100;

// =============================================================================
// Helper Functions
// =============================================================================

/// Get the TCP idle timeout as a Duration
#[inline]
#[must_use]
pub const fn tcp_idle_timeout() -> Duration {
    Duration::from_secs(TCP_IDLE_TIMEOUT_SECS)
}

/// Get the UDP default timeout as a Duration
#[inline]
#[must_use]
pub const fn udp_default_timeout() -> Duration {
    Duration::from_secs(UDP_DEFAULT_TIMEOUT_SECS)
}

/// Get the UDP DNS timeout as a Duration
#[inline]
#[must_use]
pub const fn udp_dns_timeout() -> Duration {
    Duration::from_secs(UDP_DNS_TIMEOUT_SECS)
}

/// Get the port TIME_WAIT duration as a Duration
#[inline]
#[must_use]
pub const fn port_time_wait_duration() -> Duration {
    Duration::from_secs(PORT_TIME_WAIT_SECS)
}

/// Get the connection establishment timeout as a Duration
#[inline]
#[must_use]
pub const fn connect_timeout() -> Duration {
    Duration::from_secs(CONNECT_TIMEOUT_SECS)
}

/// Get the SNI peek timeout as a Duration
#[inline]
#[must_use]
pub const fn sni_peek_timeout() -> Duration {
    Duration::from_millis(SNI_PEEK_TIMEOUT_MS)
}

/// Get the cleanup interval as a Duration
#[inline]
#[must_use]
pub const fn cleanup_interval() -> Duration {
    Duration::from_secs(CLEANUP_INTERVAL_SECS)
}

/// Get the ephemeral port range
#[inline]
#[must_use]
pub const fn ephemeral_port_range() -> std::ops::RangeInclusive<u16> {
    PORT_RANGE_START..=PORT_RANGE_END
}

/// Calculate the number of ephemeral ports available
#[inline]
#[must_use]
pub const fn ephemeral_port_count() -> usize {
    (PORT_RANGE_END - PORT_RANGE_START + 1) as usize
}

/// Calculate memory usage estimate for a given session count
///
/// Returns the estimated peak memory usage in bytes.
#[inline]
#[must_use]
pub const fn estimate_memory_usage(session_count: usize) -> usize {
    // Each session uses: TCP_RX + TCP_TX + UDP_RX + UDP_TX + overhead (~1 KB)
    let per_session = TCP_RX_BUFFER + TCP_TX_BUFFER + UDP_RX_BUFFER + UDP_TX_BUFFER + 1024;
    let base_overhead = 50 * 1024 * 1024; // 50 MB base
    session_count * per_session + base_overhead
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_mss_calculation() {
        // Verify MSS = MTU - IP header - TCP header
        assert_eq!(TCP_MSS, (WG_MTU - 20 - 20) as u16);
    }

    #[test]
    fn test_port_range() {
        // Verify IANA ephemeral port range
        assert_eq!(PORT_RANGE_START, 49152);
        assert_eq!(PORT_RANGE_END, 65535);

        let range = ephemeral_port_range();
        assert_eq!(*range.start(), PORT_RANGE_START);
        assert_eq!(*range.end(), PORT_RANGE_END);
    }

    #[test]
    fn test_ephemeral_port_count() {
        // 65535 - 49152 + 1 = 16384 ports
        assert_eq!(ephemeral_port_count(), 16384);
    }

    #[test]
    fn test_timeout_durations() {
        assert_eq!(tcp_idle_timeout(), Duration::from_secs(300));
        assert_eq!(udp_default_timeout(), Duration::from_secs(30));
        assert_eq!(udp_dns_timeout(), Duration::from_secs(10));
        assert_eq!(port_time_wait_duration(), Duration::from_secs(60));
        assert_eq!(connect_timeout(), Duration::from_secs(30));
        assert_eq!(sni_peek_timeout(), Duration::from_millis(50));
        assert_eq!(cleanup_interval(), Duration::from_secs(30));
    }

    #[test]
    fn test_buffer_sizes_for_high_performance() {
        // TCP buffers should be 1 MB for 500+ Mbps
        assert_eq!(TCP_RX_BUFFER, 1_048_576);
        assert_eq!(TCP_TX_BUFFER, 1_048_576);

        // UDP buffers should be 256 KB
        assert_eq!(UDP_RX_BUFFER, 262_144);
        assert_eq!(UDP_TX_BUFFER, 262_144);
    }

    #[test]
    fn test_buffer_sizes_symmetric() {
        // TCP buffers should be equal
        assert_eq!(TCP_RX_BUFFER, TCP_TX_BUFFER);

        // UDP buffers should be equal
        assert_eq!(UDP_RX_BUFFER, UDP_TX_BUFFER);
    }

    #[test]
    fn test_max_sockets() {
        // MAX_SOCKETS should be at least 1024 for high concurrency
        assert!(MAX_SOCKETS >= 1024);
        assert!(MAX_SOCKETS <= 65536);
    }

    #[test]
    fn test_session_limits() {
        // Per-peer limit should be less than total limit
        assert!(MAX_SESSIONS_PER_PEER < MAX_TOTAL_SESSIONS);

        // Total limit should be reasonable for memory
        assert!(MAX_TOTAL_SESSIONS <= 100_000);
    }

    #[test]
    fn test_channel_sizes() {
        // Channels should be large enough for bursts
        assert!(REPLY_CHANNEL_SIZE >= 1024);
        assert!(INGRESS_CHANNEL_SIZE >= 1024);
    }

    #[test]
    fn test_memory_estimation() {
        // 1000 sessions should be under 3 GB
        let mem_1000 = estimate_memory_usage(1000);
        assert!(mem_1000 < 3 * 1024 * 1024 * 1024);

        // 10000 sessions should be under 25 GB
        let mem_10000 = estimate_memory_usage(10000);
        assert!(mem_10000 < 25 * 1024 * 1024 * 1024);
    }
}
