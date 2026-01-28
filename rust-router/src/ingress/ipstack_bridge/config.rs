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

/// Default buffer size for TCP copy operations (64KB)
///
/// Used by `tokio::io::copy_bidirectional_with_sizes` for high-throughput connections.
/// The default tokio `copy_bidirectional` uses only 8KB buffers, which causes excessive
/// syscalls at high throughput (each 8KB copy at 1.5 Gbps = ~23K syscalls/sec).
///
/// 64KB chosen as it:
/// - Reduces syscall overhead by 8x compared to default 8KB
/// - Still fits comfortably in L3 cache
/// - Holds ~45 WireGuard packets (1420 bytes each)
/// - Provides good balance between memory and performance
///
/// Memory impact: 128KB per active TCP connection (64KB each direction)
///
/// # Override
///
/// Use `IPSTACK_TCP_BUFFER_KB` environment variable to override (8-256 KB allowed).
/// For low-memory systems (1GB RAM), consider setting to 16 or 32.
pub const TCP_COPY_BUFFER_SIZE_DEFAULT: usize = 64 * 1024;

/// Socket buffer size for TCP connections (256KB)
///
/// Larger socket buffers allow the OS to buffer more data, improving throughput
/// especially for high-bandwidth connections. This sets both SO_RCVBUF and SO_SNDBUF.
///
/// 256KB is chosen as it:
/// - Allows for larger TCP windows (better for high-latency links)
/// - Reduces the chance of buffer underrun during high-throughput transfers
/// - Is within typical OS limits (Linux default max is often 4MB+)
pub const TCP_SOCKET_BUFFER_SIZE: usize = 256 * 1024;

// =============================================================================
// SNI Sniffing Parameters
// =============================================================================

/// Default buffer size for SNI peek operations (64KB)
///
/// This buffer is used by BufReader wrapping TCP streams. It serves dual purposes:
/// 1. SNI/HTTP sniffing - captures initial data for domain resolution
/// 2. Buffered I/O - improves copy_bidirectional performance
///
/// 64KB chosen to:
/// - Match TCP_COPY_BUFFER_SIZE for consistent performance
/// - Handle large TLS ClientHello (up to 16KB with extensions)
/// - Reduce syscall overhead during bidirectional copy
/// - Allow BufReader to batch reads efficiently
///
/// Memory impact: 64KB per active TCP connection (one direction only since
/// BufReader only wraps the ipstack->outbound direction)
///
/// # Override
///
/// Controlled by `IPSTACK_TCP_BUFFER_KB` (same as TCP copy buffer for consistency).
/// Minimum 4KB to ensure TLS ClientHello fits.
pub const SNI_PEEK_BUFFER_SIZE_DEFAULT: usize = 64 * 1024;

/// Timeout for SNI peek operations in milliseconds
///
/// Maximum time to wait for initial packet data. Set to 50ms to:
/// - Be fast enough not to noticeably delay connections
/// - Allow enough time for the first packet to arrive on typical networks
/// - Be less than TCP's typical initial RTO (200ms+)
///
/// Reduced from 100ms for lower latency impact.
pub const SNI_PEEK_TIMEOUT_MS: u64 = 50;

/// Get the SNI peek timeout as a Duration
#[inline]
#[must_use]
pub const fn sni_peek_timeout() -> Duration {
    Duration::from_millis(SNI_PEEK_TIMEOUT_MS)
}

// =============================================================================
// Timeout Parameters
// =============================================================================

/// TCP connection timeout in seconds
///
/// Maximum time to wait for a TCP connection to be established.
/// Set to 10 seconds, which is reasonable for most outbound connections.
pub const TCP_CONNECT_TIMEOUT_SECS: u64 = 10;

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
///
/// At 1.5 Gbps with 1420-byte packets (~132K pps), channel fills in:
/// - 4096 packets: ~31ms
/// - 16384 packets: ~124ms (provides better burst tolerance)
///
/// Memory impact: 16384 * ~1500 bytes ≈ 24MB total (acceptable)
pub const PACKET_CHANNEL_SIZE: usize = 16384;

/// Channel size for reply packets back to WireGuard
///
/// Size of the async channel used to send reply packets from the
/// IpStack bridge back to WireGuard for transmission to peers.
///
/// This is a critical bottleneck: all N shards funnel through this single
/// channel. At 1.5 Gbps, 4096 packets fill in ~31ms, causing backpressure
/// and TCP stack stalls. Increased to 16384 for ~124ms buffer.
///
/// Memory impact: 16384 * ~1500 bytes ≈ 24MB total (acceptable)
pub const REPLY_CHANNEL_SIZE: usize = 16384;

// =============================================================================
// Helper Functions
// =============================================================================

/// Get the TCP connection timeout as a Duration
#[inline]
#[must_use]
pub const fn tcp_connect_timeout() -> Duration {
    Duration::from_secs(TCP_CONNECT_TIMEOUT_SECS)
}

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

// =============================================================================
// Configurable Buffer Sizes (via environment variables)
// =============================================================================

/// Get configured TCP copy buffer size from environment or defaults
///
/// Checks the `IPSTACK_TCP_BUFFER_KB` environment variable first, then falls back
/// to `TCP_COPY_BUFFER_SIZE_DEFAULT` (64KB).
///
/// # Environment Variable
///
/// Set `IPSTACK_TCP_BUFFER_KB=16` for low-memory systems (1GB RAM).
/// Set `IPSTACK_TCP_BUFFER_KB=128` for high-memory systems (4GB+ RAM).
///
/// # Memory Impact
///
/// Per active TCP connection: buffer_size * 3 (two copy directions + BufReader)
/// - 16KB: ~48KB/connection → ~470MB for 10K connections
/// - 64KB: ~192KB/connection → ~1.9GB for 10K connections
/// - 128KB: ~384KB/connection → ~3.8GB for 10K connections
///
/// # Examples
///
/// ```bash
/// # Low memory (1GB VPS)
/// IPSTACK_TCP_BUFFER_KB=16 cargo run
///
/// # High throughput server (4GB+ RAM)
/// IPSTACK_TCP_BUFFER_KB=128 cargo run
/// ```
#[inline]
#[must_use]
pub fn configured_tcp_buffer_size() -> usize {
    std::env::var("IPSTACK_TCP_BUFFER_KB")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|&kb| kb >= 8 && kb <= 256) // 8KB min, 256KB max
        .map(|kb| kb * 1024)
        .unwrap_or(TCP_COPY_BUFFER_SIZE_DEFAULT)
}

/// Get configured SNI peek buffer size
///
/// Uses the same value as `configured_tcp_buffer_size()` for consistency,
/// but enforces a minimum of 4KB to ensure TLS ClientHello fits.
#[inline]
#[must_use]
pub fn configured_sni_buffer_size() -> usize {
    configured_tcp_buffer_size().max(4 * 1024)
}

/// Get configured max total sessions from environment or defaults
///
/// Checks the `IPSTACK_MAX_SESSIONS` environment variable first, then falls back
/// to `MAX_TOTAL_SESSIONS` (10000).
///
/// # Environment Variable
///
/// Set `IPSTACK_MAX_SESSIONS=2000` for low-memory systems (1GB RAM).
///
/// # Memory Impact
///
/// Total memory ≈ max_sessions × per_connection_memory
/// With default 64KB buffers: 10000 × 192KB ≈ 1.9GB
/// With 16KB buffers: 10000 × 48KB ≈ 470MB
///
/// For 1GB VPS: recommend IPSTACK_MAX_SESSIONS=2000 + IPSTACK_TCP_BUFFER_KB=16
#[inline]
#[must_use]
pub fn configured_max_sessions() -> usize {
    std::env::var("IPSTACK_MAX_SESSIONS")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|&n| n >= 100 && n <= 100_000) // 100 min, 100K max
        .unwrap_or(MAX_TOTAL_SESSIONS)
}

// =============================================================================
// TCP Window Configuration (Critical for Throughput)
// =============================================================================

/// Default max unacknowledged bytes (256KB)
///
/// This value is used for **both** `max_unacked_bytes` (send) and `read_buffer_size` (receive)
/// in ipstack's TcpConfig. This is **critical** for bidirectional TCP throughput.
///
/// # Bandwidth-Delay Product (BDP)
///
/// To fully utilize a link, these buffers must be >= BDP = Bandwidth × RTT
///
/// | RTT    | For 100 Mbps | For 1 Gbps   | For 10 Gbps  |
/// |--------|--------------|--------------|--------------|
/// | 10ms   | 125 KB       | 1.25 MB      | 12.5 MB      |
/// | 50ms   | 625 KB       | 6.25 MB      | 62.5 MB      |
/// | 100ms  | 1.25 MB      | 12.5 MB      | 125 MB       |
///
/// # How ipstack TCP Buffers Work
///
/// - **`max_unacked_bytes`** (SEND direction): Limits data sent but not yet ACKed.
///   This controls **download** speed to the WireGuard client.
/// - **`read_buffer_size`** (RECEIVE direction): Determines the TCP receive window
///   advertised to the peer. This controls **upload** speed from the client.
///
/// Both must be large enough to fill the BDP for full bidirectional throughput!
///
/// # Default Value: 256KB
///
/// 256KB is chosen as a reasonable default that:
/// - Supports 1 Gbps at ~20ms RTT (typical domestic connections)
/// - Supports 100 Mbps at ~200ms RTT (international connections)
/// - Uses ~512KB memory per connection (256KB send + 256KB receive)
///
/// # ipstack Default
///
/// The ipstack crate defaults to only 16KB for both buffers, which severely limits throughput:
/// - 16KB @ 100ms RTT = only 1.28 Mbps maximum!
/// - This was the root cause of the "200 Mbps down / 60 Mbps up speedtest" issue
///
/// # Memory Impact
///
/// Per connection: max_unack × 2 (send + receive buffers in ipstack)
/// - 16KB: 32KB/connection (ipstack default, very low throughput)
/// - 256KB: 512KB/connection (our default, balanced)
/// - 1MB: 2MB/connection (high throughput, high memory)
/// - 4MB: 8MB/connection (extreme throughput, very high memory)
pub const MAX_UNACK_DEFAULT_KB: u32 = 256;

/// Get configured max unacknowledged bytes from environment or defaults
///
/// Checks the `IPSTACK_MAX_UNACK_KB` environment variable first, then falls back
/// to `MAX_UNACK_DEFAULT_KB` (256KB).
///
/// # Environment Variable
///
/// Set `IPSTACK_MAX_UNACK_KB=64` for low-memory systems (1GB RAM).
/// Set `IPSTACK_MAX_UNACK_KB=1024` for high-throughput servers (10 Gbps).
///
/// # Recommended Values
///
/// | Scenario                    | Recommended Value |
/// |-----------------------------|-------------------|
/// | Low memory VPS (1GB)        | 64 KB             |
/// | Standard server (4GB)       | 256 KB (default)  |
/// | High bandwidth (1+ Gbps)    | 512 KB - 1 MB     |
/// | Ultra high bandwidth (10G)  | 2 - 4 MB          |
///
/// # Examples
///
/// ```bash
/// # Low memory (1GB VPS)
/// IPSTACK_MAX_UNACK_KB=64 cargo run
///
/// # High throughput server
/// IPSTACK_MAX_UNACK_KB=1024 cargo run
/// ```
#[inline]
#[must_use]
pub fn configured_max_unack() -> u32 {
    std::env::var("IPSTACK_MAX_UNACK_KB")
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
        .filter(|&kb| kb >= 16 && kb <= 16384) // 16KB min (ipstack default), 16MB max
        .map(|kb| kb * 1024)
        .unwrap_or(MAX_UNACK_DEFAULT_KB * 1024)
}

// =============================================================================
// Sharding Configuration
// =============================================================================

/// Default shard count based on CPU cores
///
/// Uses cores/2, clamped to [2, 16] for optimal performance.
/// This provides a good balance between parallelism and overhead.
///
/// # Rationale
///
/// - Minimum 2 shards: Even single-core systems benefit from some parallelism
///   due to async I/O patterns
/// - Maximum 16 shards: For high-core systems (32+ cores), 16 shards provides
///   good parallelism. Previous limit of 8 underutilized multi-core systems.
/// - cores/2: Leaves headroom for other system tasks and avoids
///   over-subscription
///
/// # Override
///
/// Use `IPSTACK_SHARDS` environment variable to override (1-64 allowed).
#[inline]
#[must_use]
pub fn default_shard_count() -> usize {
    let cores = num_cpus::get();
    (cores / 2).clamp(2, 16)
}

/// Get configured shard count from environment or defaults
///
/// Checks the `IPSTACK_SHARDS` environment variable first, then falls back
/// to `default_shard_count()`.
///
/// # Environment Variable
///
/// Set `IPSTACK_SHARDS=4` to force 4 shards regardless of CPU count.
///
/// # Examples
///
/// ```bash
/// # Force 4 shards
/// IPSTACK_SHARDS=4 cargo run
///
/// # Use default (cores/2, clamped to [2, 8])
/// cargo run
/// ```
#[inline]
#[must_use]
pub fn configured_shard_count() -> usize {
    std::env::var("IPSTACK_SHARDS")
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|&n| n > 0 && n <= 64) // Sanity check: max 64 shards
        .unwrap_or_else(default_shard_count)
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
        // Channels should be large enough for bursts (4096 to reduce backpressure)
        assert!(PACKET_CHANNEL_SIZE >= 4096);
        assert!(REPLY_CHANNEL_SIZE >= 4096);
    }

    #[test]
    fn test_wg_mtu() {
        // Standard WireGuard MTU
        assert_eq!(WG_MTU, 1420);
    }

    #[test]
    fn test_default_shard_count() {
        let count = default_shard_count();
        // Should be between 2 and 16
        assert!(count >= 2);
        assert!(count <= 16);
    }

    #[test]
    fn test_configured_shard_count_default() {
        // When IPSTACK_SHARDS is not set, should return default
        // (This test may be affected by env vars set in other tests)
        let count = configured_shard_count();
        assert!(count >= 2);
        assert!(count <= 64);
    }

    #[test]
    fn test_sni_peek_config() {
        // SNI peek buffer is now 64KB (used for both SNI sniffing and buffered I/O)
        assert!(SNI_PEEK_BUFFER_SIZE_DEFAULT >= 1024);
        assert!(SNI_PEEK_BUFFER_SIZE_DEFAULT <= 128 * 1024); // Allow up to 128KB

        // SNI peek timeout should be reasonable
        assert!(SNI_PEEK_TIMEOUT_MS >= 10);
        assert!(SNI_PEEK_TIMEOUT_MS <= 200);
        assert_eq!(sni_peek_timeout(), Duration::from_millis(SNI_PEEK_TIMEOUT_MS));
    }

    #[test]
    fn test_tcp_copy_buffer_size() {
        // TCP copy buffer should be large enough for efficient high-throughput
        assert!(TCP_COPY_BUFFER_SIZE_DEFAULT >= 32 * 1024); // At least 32KB
        assert!(TCP_COPY_BUFFER_SIZE_DEFAULT <= 256 * 1024); // Not more than 256KB
    }

    #[test]
    fn test_configured_tcp_buffer_size() {
        // Default should be 64KB when env var not set
        let size = configured_tcp_buffer_size();
        assert!(size >= 8 * 1024); // Minimum 8KB
        assert!(size <= 256 * 1024); // Maximum 256KB
    }

    #[test]
    fn test_configured_sni_buffer_size() {
        // Should be at least 4KB for TLS ClientHello
        let size = configured_sni_buffer_size();
        assert!(size >= 4 * 1024);
    }

    #[test]
    fn test_configured_max_sessions() {
        // Default should be MAX_TOTAL_SESSIONS
        let max = configured_max_sessions();
        assert!(max >= 100);
        assert!(max <= 100_000);
    }

    #[test]
    fn test_max_unack_default() {
        // Default should be 256KB
        assert_eq!(MAX_UNACK_DEFAULT_KB, 256);
    }

    #[test]
    fn test_configured_max_unack() {
        // Default should be 256KB = 262144 bytes when env var not set
        let max = configured_max_unack();
        assert!(max >= 16 * 1024); // Minimum 16KB (ipstack default)
        assert!(max <= 16384 * 1024); // Maximum 16MB
        // Default is 256KB
        assert_eq!(max, MAX_UNACK_DEFAULT_KB * 1024);
    }
}
