//! Configuration constants for smoltcp bridge utilities
//!
//! This module defines all the configuration constants used throughout the bridge
//! implementations. These values are tuned for optimal performance with WireGuard
//! tunnels and can be adjusted based on deployment requirements.
//!
//! # Network Parameters
//!
//! The socket and buffer sizes are optimized for the WireGuard MTU of 1420 bytes:
//!
//! - TCP MSS is set to 1380 bytes (MTU 1420 - IP header 20 - TCP header 20)
//! - Buffer sizes are set to balance memory usage and throughput
//!
//! # Timeout Values
//!
//! Timeouts follow RFC recommendations and common practice:
//!
//! - TCP idle timeout: 300 seconds (5 minutes)
//! - UDP default timeout: 30 seconds
//! - UDP DNS timeout: 10 seconds (DNS queries should be fast)
//! - Port TIME_WAIT: 60 seconds (RFC 793 recommends 2*MSL)
//!
//! # Memory Usage Estimation
//!
//! Memory usage can be estimated as:
//! ```text
//! max_sessions * (buffer_size * 3 + max_unack * 2) + 50MB base
//! ```
//!
//! Example configurations:
//! - Default (64KB buffer, 256KB unack, 10K sessions): ~7GB peak
//! - Conservative (16KB buffer, 64KB unack, 2K sessions): ~300MB peak

use std::time::Duration;

// =============================================================================
// Network Parameters
// =============================================================================

/// Maximum number of smoltcp sockets
///
/// Increased from the default 16 to support high-concurrency scenarios.
/// Each connection creates one or more smoltcp sockets.
pub const MAX_SOCKETS: usize = 1024;

/// TCP Maximum Segment Size
///
/// Calculated as: WireGuard MTU (1420) - IP header (20) - TCP header (20) = 1380
/// This ensures TCP segments fit within a single WireGuard packet without fragmentation.
pub const TCP_MSS: u16 = 1380;

/// WireGuard Maximum Transmission Unit
///
/// Standard WireGuard MTU, accounting for the WireGuard overhead on top of
/// the underlying transport.
pub const WG_MTU: usize = 1420;

// =============================================================================
// Buffer Sizes
// =============================================================================

/// TCP receive buffer size
///
/// Set to 64 KB for better throughput over high-latency links.
/// Larger buffers allow bigger TCP windows which improves performance
/// when RTT is significant.
pub const TCP_RX_BUFFER: usize = 65536;

/// TCP transmit buffer size
///
/// Matched to the receive buffer size for symmetric performance.
pub const TCP_TX_BUFFER: usize = 65536;

/// UDP receive buffer size
///
/// Set to 64 KB to handle large UDP datagrams and bursts.
pub const UDP_RX_BUFFER: usize = 65536;

/// UDP transmit buffer size
///
/// Matched to the receive buffer size for symmetric performance.
pub const UDP_TX_BUFFER: usize = 65536;

/// UDP packet metadata count
///
/// Number of packet metadata slots in the UDP socket buffer.
/// Each slot tracks one queued UDP packet.
pub const UDP_PACKET_META: usize = 64;

// =============================================================================
// Port Allocation
// =============================================================================

/// Ephemeral port range start
///
/// IANA recommends 49152-65535 for dynamic/private ports.
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
/// Connections with no activity for this duration are considered dead.
/// Set to 5 minutes, matching common TCP keepalive intervals.
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

// =============================================================================
// Rate Limiting
// =============================================================================

/// Maximum sessions per client
///
/// Limits the number of concurrent sessions a single client can create.
/// This prevents a single client from exhausting resources.
pub const MAX_SESSIONS_PER_CLIENT: usize = 100;

/// Maximum total sessions
///
/// Hard limit on the total number of concurrent sessions across all clients.
/// This protects against resource exhaustion under heavy load.
pub const MAX_TOTAL_SESSIONS: usize = 10000;

/// Maximum session creation rate per client per second
///
/// Limits how fast a single client can create new sessions.
/// This prevents CPU exhaustion from rapid session creation/destruction.
pub const MAX_SESSIONS_PER_CLIENT_PER_SECOND: usize = 10;

/// Rate limit window duration in seconds
///
/// The time window for rate limiting session creation.
pub const RATE_LIMIT_WINDOW_SECS: u64 = 1;

/// WireGuard reply channel size
///
/// Size of the async channel used to receive reply packets from the
/// WireGuard egress manager. Should be large enough to handle bursts.
pub const WG_REPLY_CHANNEL_SIZE: usize = 1024;

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
    }

    #[test]
    fn test_buffer_sizes() {
        // TCP buffers should be equal
        assert_eq!(TCP_RX_BUFFER, TCP_TX_BUFFER);

        // UDP buffers should be equal
        assert_eq!(UDP_RX_BUFFER, UDP_TX_BUFFER);

        // Both TCP and UDP should have at least 64KB buffers for throughput
        assert!(TCP_RX_BUFFER >= 65536);
        assert!(UDP_RX_BUFFER >= 65536);
    }

    #[test]
    fn test_max_sockets() {
        // MAX_SOCKETS should be reasonable
        assert!(MAX_SOCKETS >= 256);
        assert!(MAX_SOCKETS <= 65536);
    }

    #[test]
    fn test_session_limits() {
        // Per-client limit should be less than total limit
        assert!(MAX_SESSIONS_PER_CLIENT < MAX_TOTAL_SESSIONS);

        // Total limit should be reasonable
        assert!(MAX_TOTAL_SESSIONS <= 100_000);
    }

    #[test]
    fn test_channel_size() {
        // Channel should be large enough for bursts
        assert!(WG_REPLY_CHANNEL_SIZE >= 256);
    }
}
