//! Configuration constants for IpStack bridge
//!
//! This module defines all configuration constants used throughout the IpStack
//! bridge implementation. These values are tuned for optimal performance with
//! WireGuard tunnels.
//!
//! # Network Parameters
//!
//! The socket and buffer sizes are optimized for the WireGuard MTU of 1420 bytes:
//!
//! - TCP MSS is set to 1380 bytes (MTU 1420 - IP header 20 - TCP header 20)
//! - Buffer sizes balance memory usage and throughput
//!
//! # Timeout Values
//!
//! Timeouts follow RFC recommendations and common practice:
//!
//! - TCP idle timeout: 300 seconds (5 minutes)
//! - UDP default timeout: 30 seconds
//! - UDP DNS timeout: 10 seconds (DNS queries should be fast)

use std::time::Duration;

// =============================================================================
// Network Parameters
// =============================================================================

/// MTU for WireGuard tunnel (standard WG MTU)
///
/// This is the Maximum Transmission Unit for packets sent through the
/// WireGuard tunnel. It accounts for WireGuard overhead on top of the
/// underlying transport.
pub const WG_MTU: usize = 1420;

/// Maximum Segment Size for TCP (MTU - IP header - TCP header)
///
/// Calculated as: WireGuard MTU (1420) - IP header (20) - TCP header (20) = 1380
/// This ensures TCP segments fit within a single WireGuard packet without
/// fragmentation.
pub const TCP_MSS: u16 = 1380;

/// Buffer size for TCP copy operations (64KB)
///
/// This is the buffer size used by `copy_bidirectional_with_sizes` for
/// bridging IpStackTcpStream to outbound TcpStream. Larger buffers improve
/// throughput by reducing context switches and allowing more data to be
/// copied per syscall.
///
/// 64KB is chosen as it:
/// - Matches typical socket buffer sizes
/// - Provides good throughput for bulk transfers
/// - Is large enough to hold multiple WireGuard packets (1420 * ~45)
pub const TCP_COPY_BUFFER_SIZE: usize = 64 * 1024;

// =============================================================================
// Timeout Parameters
// =============================================================================

/// TCP idle timeout in seconds
///
/// Connections with no activity for this duration are considered dead.
/// Set to 5 minutes, matching common TCP keepalive intervals.
pub const TCP_IDLE_TIMEOUT_SECS: u64 = 300;

/// UDP session timeout in seconds
///
/// UDP "sessions" (request-response pairs) timeout after this duration.
/// Set to 30 seconds, suitable for most UDP applications.
pub const UDP_SESSION_TIMEOUT_SECS: u64 = 30;

/// DNS-specific UDP timeout (shorter for responsiveness)
///
/// DNS queries should complete quickly, so we use a shorter timeout
/// to free up resources faster.
pub const UDP_DNS_TIMEOUT_SECS: u64 = 10;

/// Session cleanup interval in seconds
///
/// How often the cleanup task runs to remove idle sessions.
/// Set to 60 seconds (1 minute) for a balance between responsiveness
/// and CPU usage.
pub const SESSION_CLEANUP_INTERVAL_SECS: u64 = 60;

// =============================================================================
// Session Limits
// =============================================================================

/// Maximum concurrent sessions per peer
///
/// Limits the number of concurrent sessions a single WireGuard peer can create.
/// This prevents a single peer from exhausting resources.
pub const MAX_SESSIONS_PER_PEER: usize = 100;

/// Maximum total sessions across all peers
///
/// Hard limit on the total number of concurrent sessions across all peers.
/// This protects against resource exhaustion under heavy load.
pub const MAX_TOTAL_SESSIONS: usize = 10000;

// =============================================================================
// Channel Sizes
// =============================================================================

/// Channel size for packet queues
///
/// Size of the async channel used for IP packet queues between the
/// forwarder and the IpStack bridge. Should be large enough to handle bursts.
pub const PACKET_CHANNEL_SIZE: usize = 1024;

/// Channel size for reply packets back to WireGuard
///
/// Size of the async channel used to send reply packets from the
/// IpStack bridge back to WireGuard for transmission to peers.
pub const REPLY_CHANNEL_SIZE: usize = 1024;

// =============================================================================
// Helper Functions
// =============================================================================

/// Get the TCP idle timeout as a Duration
#[inline]
#[must_use]
pub const fn tcp_idle_timeout() -> Duration {
    Duration::from_secs(TCP_IDLE_TIMEOUT_SECS)
}

/// Get the UDP session timeout as a Duration
#[inline]
#[must_use]
pub const fn udp_session_timeout() -> Duration {
    Duration::from_secs(UDP_SESSION_TIMEOUT_SECS)
}

/// Get the UDP DNS timeout as a Duration
#[inline]
#[must_use]
pub const fn udp_dns_timeout() -> Duration {
    Duration::from_secs(UDP_DNS_TIMEOUT_SECS)
}

/// Get the session cleanup interval as a Duration
#[inline]
#[must_use]
pub const fn session_cleanup_interval() -> Duration {
    Duration::from_secs(SESSION_CLEANUP_INTERVAL_SECS)
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
    fn test_timeout_durations() {
        assert_eq!(tcp_idle_timeout(), Duration::from_secs(300));
        assert_eq!(udp_session_timeout(), Duration::from_secs(30));
        assert_eq!(udp_dns_timeout(), Duration::from_secs(10));
    }

    #[test]
    fn test_session_limits() {
        // Per-peer limit should be less than total limit
        assert!(MAX_SESSIONS_PER_PEER < MAX_TOTAL_SESSIONS);

        // Total limit should be reasonable
        assert!(MAX_TOTAL_SESSIONS <= 100_000);
    }

    #[test]
    fn test_channel_sizes() {
        // Channels should be large enough for bursts
        assert!(PACKET_CHANNEL_SIZE >= 256);
        assert!(REPLY_CHANNEL_SIZE >= 256);
    }

    #[test]
    fn test_wg_mtu() {
        // Standard WireGuard MTU
        assert_eq!(WG_MTU, 1420);
    }
}
