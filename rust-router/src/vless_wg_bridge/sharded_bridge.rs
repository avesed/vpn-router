//! ShardedVlessWgBridge - Routing layer for multiple SmoltcpShard instances
//!
//! This module provides `ShardedVlessWgBridge`, which manages multiple `SmoltcpShard`
//! instances and routes events to the appropriate shard using 5-tuple hashing.
//!
//! # Architecture
//!
//! ```text
//! ┌───────────────────────────────────────────────────────────────────────┐
//! │  ShardedVlessWgBridge                                                  │
//! │  - handle_tcp_connection(stream, dest) -> Result                       │
//! │  - handle_udp_connection(stream, dest) -> Result                       │
//! │  - send_raw_udp_packet(client, dest, payload) -> Result                │
//! │  - stats() -> AggregatedStatsSnapshot                                  │
//! └───────────────────────────────┬───────────────────────────────────────┘
//!                                 │ 5-tuple hash routing
//!                                 ▼
//! ┌────────────────┐   ┌────────────────┐   ┌────────────────┐
//! │    Shard 0     │   │    Shard 1     │   │    Shard N     │
//! │  SmoltcpShard  │   │  SmoltcpShard  │   │  SmoltcpShard  │
//! └────────────────┘   └────────────────┘   └────────────────┘
//!
//!                      ▲
//!                      │ WG Reply Dispatcher
//!                      │ (routes based on dest IP:port)
//!                      │
//! ┌────────────────────┴────────────────────┐
//! │          WgEgressManager                 │
//! │          (wg_reply_rx)                   │
//! └─────────────────────────────────────────┘
//! ```
//!
//! # 5-Tuple Hash Routing
//!
//! All packets from the same connection are routed to the same shard using
//! consistent hashing of the 5-tuple (src_ip, src_port, dst_ip, dst_port, protocol).
//! This ensures:
//!
//! - TCP connections maintain correct sequencing
//! - UDP sessions have all their packets processed by one shard
//! - No cross-shard coordination needed for connection state
//!
//! # WG Reply Distribution
//!
//! A dedicated dispatcher task receives WireGuard reply packets and routes them
//! to the correct shard based on the destination IP:port extracted from the packet.
//!
//! # Example
//!
//! ```ignore
//! use rust_router::vless_wg_bridge::sharded_bridge::{
//!     ShardedVlessWgBridge, ShardedBridgeConfig
//! };
//! use tokio::sync::mpsc;
//!
//! // Create WG channels
//! let (wg_tx, wg_rx) = mpsc::channel(1024);
//! let (wg_reply_tx, wg_reply_rx) = mpsc::channel(1024);
//!
//! // Create sharded bridge
//! let config = ShardedBridgeConfig::default();
//! let bridge = ShardedVlessWgBridge::new(config, wg_reply_rx, wg_tx).await;
//!
//! // Handle connections
//! let (event_tx, _stats) = bridge.get_shard_sender(&session_key);
//! event_tx.try_send(BridgeEvent::UdpSend { ... }).unwrap();
//!
//! // Get aggregated stats
//! let stats = bridge.stats();
//! println!("Total events: {}", stats.total_events_processed);
//! ```

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use smoltcp::wire::{IpAddress, IpCidr};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, error, info, trace, warn};

use crate::smoltcp_utils::{BridgeError, PortAllocator};

use super::cleanup::{CleanupConfig, CleanupStats};
use super::event_channel::{create_event_channel, EventChannelConfig, EventSender};
use super::events::{BridgeEvent, TcpReply, UdpReply, UdpSessionKey};
use super::shard::{ShardConfig, ShardStats, SmoltcpShard};
use super::udp_frame::VlessUdpFrame;

// =============================================================================
// Constants
// =============================================================================

/// Fallback number of shards when CPU count cannot be determined
pub const DEFAULT_SHARD_COUNT: usize = 4;

/// Minimum number of shards
pub const MIN_SHARD_COUNT: usize = 1;

/// Maximum number of shards
pub const MAX_SHARD_COUNT: usize = 64;

/// WG reply dispatcher channel size (per shard)
///
/// Increased from 256 to 512 for better burst handling during high traffic.
const WG_REPLY_DISPATCHER_CHANNEL_SIZE: usize = 512;

/// Base IP for shard local addresses (10.200.x.y where x = shard_index)
const SHARD_BASE_IP_OCTET_1: u8 = 10;
const SHARD_BASE_IP_OCTET_2: u8 = 200;

/// Default TCP read/write buffer size
const TCP_BUFFER_SIZE: usize = 32768;

/// Default reply channel size per connection
///
/// Increased from 64 to 128 for better throughput under load.
const REPLY_CHANNEL_SIZE: usize = 128;

// =============================================================================
// Connection Statistics Types
// =============================================================================

/// Statistics for a completed TCP connection
///
/// Returned by `handle_tcp_connection` after the connection closes.
#[derive(Debug, Clone, Default)]
pub struct TcpConnectionStats {
    /// Total bytes sent to the remote peer
    pub bytes_sent: u64,
    /// Total bytes received from the remote peer
    pub bytes_received: u64,
    /// Total duration of the connection
    pub duration: Duration,
}

impl TcpConnectionStats {
    /// Create new empty stats
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

/// Statistics for a completed UDP connection/session
///
/// Returned by `handle_udp_connection` after the stream closes.
#[derive(Debug, Clone, Default)]
pub struct UdpConnectionStats {
    /// Total datagrams sent
    pub datagrams_sent: u64,
    /// Total datagrams received
    pub datagrams_received: u64,
    /// Total bytes sent
    pub bytes_sent: u64,
    /// Total bytes received
    pub bytes_received: u64,
    /// Total duration of the session
    pub duration: Duration,
}

impl UdpConnectionStats {
    /// Create new empty stats
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

/// Raw UDP reply for external callers (e.g., Shadowsocks UDP relay)
///
/// This is used by `send_raw_udp_packet` and `try_recv_raw_udp_reply` for
/// protocols that send individual UDP packets rather than using VLESS
/// UDP-over-TCP framing.
#[derive(Debug, Clone)]
pub struct RawUdpReply {
    /// Original client address (for reply routing)
    pub client_addr: SocketAddr,
    /// Source address of the reply (remote server that sent this)
    pub source_addr: SocketAddr,
    /// Reply data
    pub data: Bytes,
}

impl RawUdpReply {
    /// Create a new raw UDP reply
    #[must_use]
    pub fn new(client_addr: SocketAddr, source_addr: SocketAddr, data: Bytes) -> Self {
        Self {
            client_addr,
            source_addr,
            data,
        }
    }
}

// =============================================================================
// Configuration
// =============================================================================

/// Configuration for creating a ShardedVlessWgBridge
#[derive(Debug, Clone)]
pub struct ShardedBridgeConfig {
    /// Number of shards to create
    pub num_shards: usize,
    /// Configuration for each shard
    pub shard_config: ShardConfigTemplate,
    /// Cleanup configuration for sessions
    pub cleanup_config: CleanupConfig,
    /// Event channel configuration
    pub event_channel_config: EventChannelConfig,
    /// Tunnel's actual local IP address
    ///
    /// This is the IP address assigned to the WireGuard tunnel (e.g., 10.200.200.2).
    /// All shards will use this IP as the source address for smoltcp-generated packets.
    /// If not set, falls back to synthetic shard IPs (10.200.{shard_index}.1).
    pub tunnel_local_ip: Option<IpAddress>,
}

impl ShardedBridgeConfig {
    /// Create a new configuration with specified shard count
    #[must_use]
    pub fn new(num_shards: usize) -> Self {
        let num_shards = num_shards.clamp(MIN_SHARD_COUNT, MAX_SHARD_COUNT);
        Self {
            num_shards,
            shard_config: ShardConfigTemplate::default(),
            cleanup_config: CleanupConfig::default(),
            event_channel_config: EventChannelConfig::default(),
            tunnel_local_ip: None,
        }
    }

    /// Set the tunnel's actual local IP address
    ///
    /// All shards will use this IP as the source address for generated packets.
    #[must_use]
    pub fn with_tunnel_local_ip(mut self, ip: IpAddress) -> Self {
        self.tunnel_local_ip = Some(ip);
        self
    }

    /// Set the cleanup configuration
    #[must_use]
    pub fn with_cleanup_config(mut self, config: CleanupConfig) -> Self {
        self.cleanup_config = config;
        self
    }

    /// Set the event channel configuration
    #[must_use]
    pub fn with_event_channel_config(mut self, config: EventChannelConfig) -> Self {
        self.event_channel_config = config;
        self
    }

    /// Set the shard configuration template
    #[must_use]
    pub fn with_shard_config(mut self, config: ShardConfigTemplate) -> Self {
        self.shard_config = config;
        self
    }

    /// Create configuration from environment variables
    ///
    /// Reads `VLESS_WG_BRIDGE_SHARDS` environment variable for shard count.
    #[must_use]
    pub fn from_env() -> Self {
        let num_shards = std::env::var("VLESS_WG_BRIDGE_SHARDS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(DEFAULT_SHARD_COUNT);

        Self::new(num_shards)
    }
}

impl Default for ShardedBridgeConfig {
    /// Create default configuration with CPU-aware shard count.
    ///
    /// Uses half the CPU cores (clamped to 2-16 range) for optimal
    /// balance between parallelism and memory usage.
    fn default() -> Self {
        let cpu_count = num_cpus::get();
        // Use half the cores, clamped to reasonable range
        let num_shards = (cpu_count / 2).clamp(2, 16);
        Self::new(num_shards)
    }
}

/// Template for creating ShardConfig for each shard
#[derive(Debug, Clone)]
pub struct ShardConfigTemplate {
    /// Base CIDR for shard local addresses
    pub base_cidr_prefix: u8,
    /// MTU for the smoltcp interface
    pub mtu: usize,
}

impl ShardConfigTemplate {
    /// Create a ShardConfig for a specific shard index
    ///
    /// If `tunnel_local_ip` is provided, all shards will use that IP as their source address.
    /// This is the correct behavior for WG tunnels where all packets must have the tunnel's
    /// assigned IP as the source.
    ///
    /// If `tunnel_local_ip` is None, falls back to synthetic shard IPs (10.200.{shard_index}.1).
    ///
    /// # Arguments
    ///
    /// * `shard_index` - Index of this shard (0-based)
    /// * `total_shards` - Total number of shards (needed for port range partitioning)
    /// * `tunnel_local_ip` - Optional tunnel IP to use for all shards
    #[must_use]
    pub fn for_shard(
        &self,
        shard_index: u16,
        total_shards: u16,
        tunnel_local_ip: Option<IpAddress>,
    ) -> ShardConfig {
        // Use tunnel's actual IP if provided, otherwise fall back to synthetic shard IP
        let local_ip = tunnel_local_ip.unwrap_or_else(|| {
            // Legacy behavior: each shard gets its own synthetic IP
            IpAddress::v4(
                SHARD_BASE_IP_OCTET_1,
                SHARD_BASE_IP_OCTET_2,
                shard_index as u8,
                1,
            )
        });

        // CIDR is always based on the actual local_ip with /32 prefix for point-to-point tunnel
        // We don't use the synthetic subnet anymore since all shards share the same tunnel IP
        let cidr = IpCidr::new(local_ip, 32);

        ShardConfig {
            shard_index,
            total_shards,
            local_ip,
            local_cidr: cidr,
            mtu: self.mtu,
        }
    }
}

impl Default for ShardConfigTemplate {
    fn default() -> Self {
        Self {
            base_cidr_prefix: 24,
            mtu: 1420, // Standard WireGuard MTU
        }
    }
}

// =============================================================================
// Shard Key Trait
// =============================================================================

/// Trait for types that can be hashed for shard routing
///
/// Types implementing this trait can be used to determine which shard
/// should handle a particular connection or packet.
pub trait ShardKey {
    /// Generate a hash value for shard selection
    fn shard_hash(&self) -> u64;
}

impl ShardKey for UdpSessionKey {
    fn shard_hash(&self) -> u64 {
        UdpSessionKey::shard_hash(self)
    }
}

/// TCP 5-tuple for shard routing
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TcpSessionKey {
    /// Source IP address
    pub src_ip: IpAddr,
    /// Source port
    pub src_port: u16,
    /// Destination IP address
    pub dest_ip: IpAddr,
    /// Destination port
    pub dest_port: u16,
}

impl TcpSessionKey {
    /// Create a new TCP session key from socket addresses
    #[must_use]
    pub fn new(src_addr: SocketAddr, dest_addr: SocketAddr) -> Self {
        Self {
            src_ip: src_addr.ip(),
            src_port: src_addr.port(),
            dest_ip: dest_addr.ip(),
            dest_port: dest_addr.port(),
        }
    }

    /// Create from individual components
    #[must_use]
    pub fn from_parts(src_ip: IpAddr, src_port: u16, dest_ip: IpAddr, dest_port: u16) -> Self {
        Self {
            src_ip,
            src_port,
            dest_ip,
            dest_port,
        }
    }
}

impl ShardKey for TcpSessionKey {
    fn shard_hash(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        self.hash(&mut hasher);
        hasher.finish()
    }
}

/// Generic 5-tuple for shard routing (TCP or UDP)
impl ShardKey for (IpAddr, u16, IpAddr, u16) {
    fn shard_hash(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        self.hash(&mut hasher);
        hasher.finish()
    }
}

// =============================================================================
// Aggregated Statistics
// =============================================================================

/// Aggregated statistics across all shards
#[derive(Debug)]
pub struct AggregatedStats {
    /// Individual shard statistics
    shard_stats: Vec<Arc<ShardStatsCollector>>,
    /// Number of shards
    num_shards: usize,
}

impl AggregatedStats {
    /// Create new aggregated stats for the given shard count
    fn new(num_shards: usize) -> Self {
        let shard_stats = (0..num_shards)
            .map(|_| Arc::new(ShardStatsCollector::new()))
            .collect();
        Self {
            shard_stats,
            num_shards,
        }
    }

    /// Get the stats collector for a specific shard
    fn get_collector(&self, shard_idx: usize) -> Option<Arc<ShardStatsCollector>> {
        self.shard_stats.get(shard_idx).cloned()
    }

    /// Take a snapshot of aggregated statistics
    #[must_use]
    pub fn snapshot(&self) -> AggregatedStatsSnapshot {
        let per_shard = self.shard_stats.iter().map(|s| s.snapshot()).collect();

        let mut total = AggregatedStatsSnapshot::new(self.num_shards);
        total.per_shard_stats = per_shard;
        total.aggregate();
        total
    }
}

/// Thread-safe statistics collector for a single shard
#[derive(Debug, Default)]
pub struct ShardStatsCollector {
    /// Total events processed
    pub events_processed: AtomicU64,
    /// WireGuard packets received
    pub wg_packets_received: AtomicU64,
    /// WireGuard packets sent
    pub wg_packets_sent: AtomicU64,
    /// WireGuard bytes received
    pub wg_bytes_received: AtomicU64,
    /// WireGuard bytes sent
    pub wg_bytes_sent: AtomicU64,
    /// WireGuard packets dropped
    pub wg_packets_dropped: AtomicU64,
    /// TCP sessions created
    pub tcp_sessions_created: AtomicU64,
    /// TCP sessions closed
    pub tcp_sessions_closed: AtomicU64,
    /// UDP sessions created
    pub udp_sessions_created: AtomicU64,
    /// UDP sessions closed
    pub udp_sessions_closed: AtomicU64,
    /// UDP datagrams sent
    pub udp_datagrams_sent: AtomicU64,
    /// UDP datagrams received
    pub udp_datagrams_received: AtomicU64,
    /// smoltcp poll count
    pub poll_count: AtomicU64,
}

impl ShardStatsCollector {
    /// Create a new stats collector
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Update from ShardStats
    pub fn update_from(&self, stats: &ShardStats) {
        self.events_processed
            .store(stats.events_processed, Ordering::Relaxed);
        self.wg_packets_received
            .store(stats.wg_packets_received, Ordering::Relaxed);
        self.wg_packets_sent
            .store(stats.wg_packets_sent, Ordering::Relaxed);
        self.wg_bytes_received
            .store(stats.wg_bytes_received, Ordering::Relaxed);
        self.wg_bytes_sent
            .store(stats.wg_bytes_sent, Ordering::Relaxed);
        self.wg_packets_dropped
            .store(stats.wg_packets_dropped, Ordering::Relaxed);
        self.tcp_sessions_created
            .store(stats.tcp_sessions_created, Ordering::Relaxed);
        self.tcp_sessions_closed
            .store(stats.tcp_sessions_closed, Ordering::Relaxed);
        self.udp_sessions_created
            .store(stats.udp_sessions_created, Ordering::Relaxed);
        self.udp_sessions_closed
            .store(stats.udp_sessions_closed, Ordering::Relaxed);
        self.udp_datagrams_sent
            .store(stats.udp_datagrams_sent, Ordering::Relaxed);
        self.udp_datagrams_received
            .store(stats.udp_datagrams_received, Ordering::Relaxed);
        self.poll_count.store(stats.poll_count, Ordering::Relaxed);
    }

    /// Take a snapshot of current statistics
    #[must_use]
    pub fn snapshot(&self) -> ShardStatsSnapshot {
        ShardStatsSnapshot {
            events_processed: self.events_processed.load(Ordering::Relaxed),
            wg_packets_received: self.wg_packets_received.load(Ordering::Relaxed),
            wg_packets_sent: self.wg_packets_sent.load(Ordering::Relaxed),
            wg_bytes_received: self.wg_bytes_received.load(Ordering::Relaxed),
            wg_bytes_sent: self.wg_bytes_sent.load(Ordering::Relaxed),
            wg_packets_dropped: self.wg_packets_dropped.load(Ordering::Relaxed),
            tcp_sessions_created: self.tcp_sessions_created.load(Ordering::Relaxed),
            tcp_sessions_closed: self.tcp_sessions_closed.load(Ordering::Relaxed),
            udp_sessions_created: self.udp_sessions_created.load(Ordering::Relaxed),
            udp_sessions_closed: self.udp_sessions_closed.load(Ordering::Relaxed),
            udp_datagrams_sent: self.udp_datagrams_sent.load(Ordering::Relaxed),
            udp_datagrams_received: self.udp_datagrams_received.load(Ordering::Relaxed),
            poll_count: self.poll_count.load(Ordering::Relaxed),
            cleanup_stats: CleanupStats::default(),
        }
    }
}

/// Snapshot of shard statistics
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct ShardStatsSnapshot {
    /// Total events processed
    pub events_processed: u64,
    /// WireGuard packets received
    pub wg_packets_received: u64,
    /// WireGuard packets sent
    pub wg_packets_sent: u64,
    /// WireGuard bytes received
    pub wg_bytes_received: u64,
    /// WireGuard bytes sent
    pub wg_bytes_sent: u64,
    /// WireGuard packets dropped
    pub wg_packets_dropped: u64,
    /// TCP sessions created
    pub tcp_sessions_created: u64,
    /// TCP sessions closed
    pub tcp_sessions_closed: u64,
    /// UDP sessions created
    pub udp_sessions_created: u64,
    /// UDP sessions closed
    pub udp_sessions_closed: u64,
    /// UDP datagrams sent
    pub udp_datagrams_sent: u64,
    /// UDP datagrams received
    pub udp_datagrams_received: u64,
    /// smoltcp poll count
    pub poll_count: u64,
    /// Cleanup statistics (skipped in serialization as CleanupStats doesn't impl Serialize)
    #[serde(skip)]
    pub cleanup_stats: CleanupStats,
}

/// Snapshot of aggregated statistics across all shards
#[derive(Debug, Clone, serde::Serialize)]
pub struct AggregatedStatsSnapshot {
    /// Number of shards
    pub num_shards: usize,
    /// Per-shard statistics
    pub per_shard_stats: Vec<ShardStatsSnapshot>,

    // Aggregated totals
    /// Total events processed across all shards
    pub total_events_processed: u64,
    /// Total WG packets received
    pub total_wg_packets_received: u64,
    /// Total WG packets sent
    pub total_wg_packets_sent: u64,
    /// Total WG bytes received
    pub total_wg_bytes_received: u64,
    /// Total WG bytes sent
    pub total_wg_bytes_sent: u64,
    /// Total WG packets dropped
    pub total_wg_packets_dropped: u64,
    /// Total TCP sessions created
    pub total_tcp_sessions_created: u64,
    /// Total TCP sessions closed
    pub total_tcp_sessions_closed: u64,
    /// Total UDP sessions created
    pub total_udp_sessions_created: u64,
    /// Total UDP sessions closed
    pub total_udp_sessions_closed: u64,
    /// Total UDP datagrams sent
    pub total_udp_datagrams_sent: u64,
    /// Total UDP datagrams received
    pub total_udp_datagrams_received: u64,
    /// Total smoltcp polls
    pub total_poll_count: u64,
    /// Aggregated cleanup statistics (skipped in serialization)
    #[serde(skip)]
    pub cleanup_stats: CleanupStats,
}

impl AggregatedStatsSnapshot {
    /// Create a new empty snapshot
    fn new(num_shards: usize) -> Self {
        Self {
            num_shards,
            per_shard_stats: Vec::with_capacity(num_shards),
            total_events_processed: 0,
            total_wg_packets_received: 0,
            total_wg_packets_sent: 0,
            total_wg_bytes_received: 0,
            total_wg_bytes_sent: 0,
            total_wg_packets_dropped: 0,
            total_tcp_sessions_created: 0,
            total_tcp_sessions_closed: 0,
            total_udp_sessions_created: 0,
            total_udp_sessions_closed: 0,
            total_udp_datagrams_sent: 0,
            total_udp_datagrams_received: 0,
            total_poll_count: 0,
            cleanup_stats: CleanupStats::default(),
        }
    }

    /// Aggregate per-shard stats into totals
    fn aggregate(&mut self) {
        for shard in &self.per_shard_stats {
            self.total_events_processed += shard.events_processed;
            self.total_wg_packets_received += shard.wg_packets_received;
            self.total_wg_packets_sent += shard.wg_packets_sent;
            self.total_wg_bytes_received += shard.wg_bytes_received;
            self.total_wg_bytes_sent += shard.wg_bytes_sent;
            self.total_wg_packets_dropped += shard.wg_packets_dropped;
            self.total_tcp_sessions_created += shard.tcp_sessions_created;
            self.total_tcp_sessions_closed += shard.tcp_sessions_closed;
            self.total_udp_sessions_created += shard.udp_sessions_created;
            self.total_udp_sessions_closed += shard.udp_sessions_closed;
            self.total_udp_datagrams_sent += shard.udp_datagrams_sent;
            self.total_udp_datagrams_received += shard.udp_datagrams_received;
            self.total_poll_count += shard.poll_count;
            self.cleanup_stats.merge(&shard.cleanup_stats);
        }
    }

    /// Calculate the distribution skew (standard deviation of events per shard)
    ///
    /// Lower values indicate more even distribution.
    #[must_use]
    pub fn distribution_skew(&self) -> f64 {
        if self.per_shard_stats.is_empty() || self.total_events_processed == 0 {
            return 0.0;
        }
        let mean = self.total_events_processed as f64 / self.num_shards as f64;
        let variance: f64 = self
            .per_shard_stats
            .iter()
            .map(|s| {
                let diff = s.events_processed as f64 - mean;
                diff * diff
            })
            .sum::<f64>()
            / self.num_shards as f64;
        variance.sqrt()
    }

    /// Get the active TCP sessions count (created - closed)
    #[must_use]
    pub fn active_tcp_sessions(&self) -> u64 {
        self.total_tcp_sessions_created
            .saturating_sub(self.total_tcp_sessions_closed)
    }

    /// Get the active UDP sessions count (created - closed)
    #[must_use]
    pub fn active_udp_sessions(&self) -> u64 {
        self.total_udp_sessions_created
            .saturating_sub(self.total_udp_sessions_closed)
    }
}

// =============================================================================
// Sharded Bridge
// =============================================================================

/// Sharded VLESS-WG Bridge managing multiple SmoltcpShard instances
///
/// This struct provides the routing layer that distributes events across
/// multiple shards for parallel processing.
pub struct ShardedVlessWgBridge {
    /// Event senders for each shard
    shard_senders: Vec<EventSender>,

    /// WG TX channel senders (one per shard, for sending to WgEgressManager)
    wg_tx_senders: Vec<mpsc::Sender<Bytes>>,

    /// Shard task handles
    shard_handles: Vec<JoinHandle<()>>,

    /// WG reply dispatcher task handle
    dispatcher_handle: Option<JoinHandle<()>>,

    /// Aggregated statistics
    stats: Arc<AggregatedStats>,

    /// Shutdown flag
    shutdown: Arc<AtomicBool>,

    /// Number of shards
    num_shards: usize,
}

impl ShardedVlessWgBridge {
    /// Create and start a new sharded bridge
    ///
    /// # Arguments
    ///
    /// * `config` - Bridge configuration
    /// * `wg_reply_rx` - Channel receiving WG reply packets from WgEgressManager
    /// * `wg_tx` - Channel for sending WG packets to WgEgressManager
    ///
    /// # Returns
    ///
    /// A new ShardedVlessWgBridge with all shards running
    pub async fn new(
        config: ShardedBridgeConfig,
        wg_reply_rx: mpsc::Receiver<Bytes>,
        wg_tx: mpsc::Sender<Bytes>,
    ) -> Self {
        let num_shards = config.num_shards;
        let stats = Arc::new(AggregatedStats::new(num_shards));
        let shutdown = Arc::new(AtomicBool::new(false));

        let mut shard_senders = Vec::with_capacity(num_shards);
        let mut shard_handles = Vec::with_capacity(num_shards);
        let mut wg_tx_senders = Vec::with_capacity(num_shards);
        let mut wg_reply_senders = Vec::with_capacity(num_shards);

        // Create shards
        for shard_idx in 0..num_shards {
            // Create event channel for this shard
            let (event_tx, event_rx) = create_event_channel(config.event_channel_config.clone());
            shard_senders.push(event_tx);

            // Create WG reply channel for this shard
            let (wg_reply_tx, shard_wg_reply_rx) =
                mpsc::channel::<Bytes>(WG_REPLY_DISPATCHER_CHANNEL_SIZE);
            wg_reply_senders.push(wg_reply_tx);

            // Clone the shared WG TX for this shard
            wg_tx_senders.push(wg_tx.clone());

            // Create shard configuration, passing the tunnel's local IP if available
            // Also pass total_shards for port range partitioning
            let shard_config = config.shard_config.for_shard(
                shard_idx as u16,
                num_shards as u16,
                config.tunnel_local_ip,
            );
            let shard_local_ip = shard_config.local_ip;

            // Create shard with cleanup configuration
            let shard = SmoltcpShard::with_cleanup_config(
                shard_config,
                event_rx,
                shard_wg_reply_rx,
                wg_tx.clone(),
                config.cleanup_config,
            );

            info!(
                "Created SmoltcpShard {} with local_ip={:?}",
                shard_idx, shard_local_ip
            );

            // Spawn shard task
            let handle = tokio::spawn(shard.run());
            shard_handles.push(handle);
        }

        // Start WG reply dispatcher
        let dispatcher_handle = Some(Self::spawn_wg_reply_dispatcher(
            wg_reply_rx,
            wg_reply_senders,
            num_shards,
            Arc::clone(&shutdown),
        ));

        info!(
            "ShardedVlessWgBridge started with {} shards",
            num_shards
        );

        Self {
            shard_senders,
            wg_tx_senders,
            shard_handles,
            dispatcher_handle,
            stats,
            shutdown,
            num_shards,
        }
    }

    /// Spawn the WG reply dispatcher task
    fn spawn_wg_reply_dispatcher(
        mut wg_reply_rx: mpsc::Receiver<Bytes>,
        shard_wg_rx_senders: Vec<mpsc::Sender<Bytes>>,
        num_shards: usize,
        shutdown: Arc<AtomicBool>,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            info!("WG reply dispatcher started");

            while let Some(packet) = wg_reply_rx.recv().await {
                if shutdown.load(Ordering::Relaxed) {
                    break;
                }

                // Parse IP header to get destination for routing
                if let Some((dest_ip, dest_port)) = Self::parse_ip_packet_dest(&packet) {
                    let shard_idx = Self::compute_shard_index(dest_ip, dest_port, num_shards);
                    trace!(
                        "Routing WG reply to shard {}: dest={}:{}",
                        shard_idx,
                        dest_ip,
                        dest_port
                    );

                    if let Err(e) = shard_wg_rx_senders[shard_idx].try_send(packet) {
                        warn!(
                            "Failed to send WG reply to shard {}: {:?}",
                            shard_idx, e
                        );
                    }
                } else {
                    // Unable to parse packet, use round-robin fallback
                    static FALLBACK_COUNTER: AtomicU64 = AtomicU64::new(0);
                    let shard_idx = (FALLBACK_COUNTER.fetch_add(1, Ordering::Relaxed) as usize)
                        % num_shards;
                    trace!("WG reply fallback to shard {} (unparseable packet)", shard_idx);
                    let _ = shard_wg_rx_senders[shard_idx].try_send(packet);
                }
            }

            info!("WG reply dispatcher stopped");
        })
    }

    /// Parse an IP packet to extract destination IP and port
    fn parse_ip_packet_dest(packet: &[u8]) -> Option<(IpAddr, u16)> {
        if packet.is_empty() {
            return None;
        }

        let version = packet[0] >> 4;
        match version {
            4 => Self::parse_ipv4_dest(packet),
            6 => Self::parse_ipv6_dest(packet),
            _ => None,
        }
    }

    /// Parse IPv4 packet destination
    fn parse_ipv4_dest(packet: &[u8]) -> Option<(IpAddr, u16)> {
        // Minimum IPv4 header is 20 bytes
        if packet.len() < 20 {
            return None;
        }

        let ihl = (packet[0] & 0x0f) as usize * 4;
        if packet.len() < ihl + 4 {
            return None;
        }

        let dst_ip = std::net::Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
        let dst_port = u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]]);

        Some((IpAddr::V4(dst_ip), dst_port))
    }

    /// Parse IPv6 packet destination
    fn parse_ipv6_dest(packet: &[u8]) -> Option<(IpAddr, u16)> {
        // Minimum IPv6 header is 40 bytes
        if packet.len() < 40 + 4 {
            return None;
        }

        let mut dst_octets = [0u8; 16];
        dst_octets.copy_from_slice(&packet[24..40]);
        let dst_ip = std::net::Ipv6Addr::from(dst_octets);

        // Get port from transport header (simplified: assume no extension headers)
        let dst_port = u16::from_be_bytes([packet[42], packet[43]]);

        Some((IpAddr::V6(dst_ip), dst_port))
    }

    /// Compute shard index from IP and port
    ///
    /// Uses port-based routing to determine the correct shard. Each shard has a
    /// partitioned range of ephemeral ports, so we can determine which shard owns
    /// a connection by looking at which port range the destination port falls into.
    ///
    /// Falls back to hash-based routing for ports outside the ephemeral range.
    fn compute_shard_index(_ip: IpAddr, port: u16, num_shards: usize) -> usize {
        // Use port-based routing for ephemeral ports (where our connections originate)
        // This avoids routing errors when all shards share the same tunnel IP
        if let Some(shard_idx) = PortAllocator::shard_for_port(port, num_shards as u16) {
            shard_idx
        } else {
            // For non-ephemeral ports (e.g., well-known ports), fall back to hash routing
            // This shouldn't normally happen for reply packets since we always use
            // ephemeral ports as source ports
            let mut hasher = DefaultHasher::new();
            port.hash(&mut hasher);
            (hasher.finish() as usize) % num_shards
        }
    }

    /// Route to the appropriate shard based on a ShardKey
    #[inline]
    pub fn route_to_shard(&self, key: &impl ShardKey) -> usize {
        (key.shard_hash() as usize) % self.num_shards
    }

    /// Get the event sender for a specific shard index
    #[must_use]
    pub fn get_shard_sender_by_index(&self, shard_idx: usize) -> Option<&EventSender> {
        self.shard_senders.get(shard_idx)
    }

    /// Get the event sender for a session key
    #[must_use]
    pub fn get_shard_sender(&self, key: &impl ShardKey) -> &EventSender {
        let shard_idx = self.route_to_shard(key);
        &self.shard_senders[shard_idx]
    }

    /// Get the number of shards
    #[inline]
    #[must_use]
    pub fn num_shards(&self) -> usize {
        self.num_shards
    }

    /// Check if the bridge is shut down
    #[must_use]
    pub fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::Relaxed)
    }

    /// Get aggregated statistics
    #[must_use]
    pub fn stats(&self) -> AggregatedStatsSnapshot {
        self.stats.snapshot()
    }

    /// Send a shutdown event to all shards
    pub async fn shutdown(&self) {
        if self.shutdown.swap(true, Ordering::Relaxed) {
            // Already shutting down
            return;
        }

        info!("ShardedVlessWgBridge initiating shutdown");

        // Send shutdown event to all shards
        for (idx, sender) in self.shard_senders.iter().enumerate() {
            if let Err(e) = sender.try_send(BridgeEvent::Shutdown) {
                warn!("Failed to send shutdown to shard {}: {:?}", idx, e);
            }
        }
    }

    /// Wait for all shards to complete
    ///
    /// This should be called after `shutdown()` to wait for graceful termination.
    pub async fn wait_for_shutdown(mut self) {
        // Wait for dispatcher to finish
        if let Some(handle) = self.dispatcher_handle.take() {
            if let Err(e) = handle.await {
                error!("WG reply dispatcher task panicked: {:?}", e);
            }
        }

        // Wait for all shard tasks
        for (idx, handle) in self.shard_handles.drain(..).enumerate() {
            if let Err(e) = handle.await {
                error!("Shard {} task panicked: {:?}", idx, e);
            }
        }

        info!("ShardedVlessWgBridge shutdown complete");
    }

    // =========================================================================
    // Public API - TCP Connection Handling
    // =========================================================================

    /// Handle a TCP connection from VLESS/SS inbound
    ///
    /// This method bridges a TCP stream to the WireGuard tunnel. It:
    /// 1. Allocates a connection ID and routes to the appropriate shard
    /// 2. Sends a TcpConnect event to establish the connection
    /// 3. Forwards data bidirectionally between the stream and the shard
    /// 4. Returns statistics when the connection closes
    ///
    /// # Arguments
    ///
    /// * `stream` - The incoming TCP stream (from VLESS/SS inbound)
    /// * `dest_addr` - The destination address to connect to
    ///
    /// # Returns
    ///
    /// Connection statistics on success, or `BridgeError` on failure.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let stats = bridge.handle_tcp_connection(stream, dest_addr).await?;
    /// println!("Transferred {} bytes in {:?}", stats.bytes_sent + stats.bytes_received, stats.duration);
    /// ```
    pub async fn handle_tcp_connection<S>(
        &self,
        mut stream: S,
        dest_addr: SocketAddr,
    ) -> Result<TcpConnectionStats, BridgeError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let start = Instant::now();

        if self.is_shutdown() {
            return Err(BridgeError::TunnelDown("bridge is shutting down".into()));
        }

        // Generate connection ID using atomic counter
        let conn_id = self.allocate_conn_id();

        info!(
            "[VLESS-WG] handle_tcp_connection called: conn_id={}, dest={}",
            conn_id, dest_addr
        );

        // Create the TCP session key for shard routing
        // Use a pseudo source address based on conn_id for consistent routing
        let pseudo_src_port = (conn_id & 0xFFFF) as u16;
        let pseudo_src_ip = IpAddr::V4(std::net::Ipv4Addr::new(
            10,
            200,
            ((conn_id >> 16) & 0xFF) as u8,
            ((conn_id >> 8) & 0xFF) as u8,
        ));
        let tcp_key = TcpSessionKey::new(
            SocketAddr::new(pseudo_src_ip, pseudo_src_port),
            dest_addr,
        );
        let shard_idx = self.route_to_shard(&tcp_key);

        info!(
            "[VLESS-WG] TCP conn_id={} -> {} routed to shard {} (pseudo_src={}:{})",
            conn_id, dest_addr, shard_idx, pseudo_src_ip, pseudo_src_port
        );

        // Create reply channel for this connection
        let (reply_tx, mut reply_rx) = mpsc::channel::<TcpReply>(REPLY_CHANNEL_SIZE);

        // Send TcpConnect event to the shard
        let event = BridgeEvent::tcp_connect(conn_id, dest_addr, reply_tx);
        info!(
            "[VLESS-WG] Sending TcpConnect event to shard {}: conn_id={}",
            shard_idx, conn_id
        );
        if let Err(e) = self.shard_senders[shard_idx].try_send(event) {
            error!(
                "[VLESS-WG] Failed to send TcpConnect to shard {}: conn_id={}, err={:?}",
                shard_idx, conn_id, e
            );
            return Err(BridgeError::ChannelSendFailed(format!(
                "failed to send TcpConnect to shard {}: {:?}",
                shard_idx, e
            )));
        }

        // Wait for connection to establish
        let connected = tokio::time::timeout(Duration::from_secs(30), reply_rx.recv()).await;
        match connected {
            Ok(Some(TcpReply::Connected)) => {
                debug!("TCP connection {} established", conn_id);
            }
            Ok(Some(TcpReply::ConnectFailed { error })) => {
                return Err(error);
            }
            Ok(Some(other)) => {
                return Err(BridgeError::InvalidSessionState {
                    expected: "Connected".to_string(),
                    actual: format!("{:?}", other),
                });
            }
            Ok(None) => {
                return Err(BridgeError::ChannelReceiveFailed(
                    "reply channel closed unexpectedly".into(),
                ));
            }
            Err(_) => {
                // Timeout - send abort and return error
                let _ = self.shard_senders[shard_idx].try_send(BridgeEvent::tcp_abort(conn_id));
                return Err(BridgeError::ConnectionTimeout);
            }
        }

        // Bidirectional data forwarding
        let mut bytes_sent = 0u64;
        let mut bytes_received = 0u64;
        let mut buf = vec![0u8; TCP_BUFFER_SIZE];
        let mut remote_closed = false;
        let mut local_eof = false; // Track local EOF to avoid repeated CloseWrite

        loop {
            if self.is_shutdown() {
                let _ = self.shard_senders[shard_idx].try_send(BridgeEvent::tcp_abort(conn_id));
                return Err(BridgeError::TunnelDown("bridge shutdown".into()));
            }

            tokio::select! {
                biased;

                // Read from stream -> send to shard (only if not already EOF)
                result = stream.read(&mut buf), if !local_eof => {
                    match result {
                        Ok(0) => {
                            // EOF - send CloseWrite to initiate graceful close
                            local_eof = true; // Prevent further reads
                            debug!("TCP {} stream EOF, sending CloseWrite", conn_id);
                            let _ = self.shard_senders[shard_idx]
                                .try_send(BridgeEvent::tcp_close_write(conn_id));
                            if remote_closed {
                                break;
                            }
                        }
                        Ok(n) => {
                            bytes_sent += n as u64;
                            let event = BridgeEvent::tcp_data(conn_id, Bytes::copy_from_slice(&buf[..n]));
                            if let Err(e) = self.shard_senders[shard_idx].try_send(event) {
                                warn!("Failed to send TcpData: {:?}", e);
                                break;
                            }
                        }
                        Err(e) => {
                            warn!("TCP {} stream read error: {}", conn_id, e);
                            let _ = self.shard_senders[shard_idx].try_send(BridgeEvent::tcp_abort(conn_id));
                            return Err(e.into());
                        }
                    }
                }

                // Receive from shard -> write to stream
                Some(reply) = reply_rx.recv() => {
                    match reply {
                        TcpReply::Data { data } => {
                            bytes_received += data.len() as u64;
                            if let Err(e) = stream.write_all(&data).await {
                                warn!("TCP {} stream write error: {}", conn_id, e);
                                let _ = self.shard_senders[shard_idx].try_send(BridgeEvent::tcp_abort(conn_id));
                                return Err(e.into());
                            }
                        }
                        TcpReply::RemoteClosed => {
                            debug!("TCP {} remote closed", conn_id);
                            remote_closed = true;
                            // Continue receiving until local also closes
                        }
                        TcpReply::Closed | TcpReply::Error { .. } => {
                            debug!("TCP {} connection closed", conn_id);
                            break;
                        }
                        TcpReply::Connected | TcpReply::ConnectFailed { .. } => {
                            // Unexpected during data transfer
                            trace!("TCP {} unexpected reply during transfer: {:?}", conn_id, reply);
                        }
                    }
                }
            }
        }

        // Flush any remaining data
        let _ = stream.flush().await;

        Ok(TcpConnectionStats {
            bytes_sent,
            bytes_received,
            duration: start.elapsed(),
        })
    }

    // =========================================================================
    // Public API - UDP Connection Handling
    // =========================================================================

    /// Handle a UDP connection from VLESS UDP-over-TCP
    ///
    /// This method bridges a VLESS UDP-over-TCP stream to the WireGuard tunnel.
    /// Uses Xray-compatible framing: `[Length(2)][AddrType(1)][Address][Port(2)][Payload]`.
    ///
    /// # Arguments
    ///
    /// * `stream` - The incoming TCP stream carrying UDP frames
    /// * `initial_dest` - Initial destination from VLESS header (used for routing)
    ///
    /// # Returns
    ///
    /// Connection statistics on success, or `BridgeError` on failure.
    ///
    /// # XUDP Mode
    ///
    /// In XUDP mode, each UDP frame contains its own destination address,
    /// allowing multiplexed UDP traffic over a single TCP connection.
    /// The `initial_dest` is used for shard routing consistency.
    pub async fn handle_udp_connection<S>(
        &self,
        mut stream: S,
        initial_dest: SocketAddr,
    ) -> Result<UdpConnectionStats, BridgeError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let start = Instant::now();

        if self.is_shutdown() {
            return Err(BridgeError::TunnelDown("bridge is shutting down".into()));
        }

        let mut datagrams_sent = 0u64;
        let mut datagrams_received = 0u64;
        let mut bytes_sent = 0u64;
        let mut bytes_received = 0u64;

        // Create reply channel for UDP replies
        let (reply_tx, mut reply_rx) = mpsc::channel::<UdpReply>(REPLY_CHANNEL_SIZE);

        // Track the session key for this connection
        // Use initial_dest for routing; actual per-packet dest may vary in XUDP mode
        let conn_id = self.allocate_conn_id();
        let pseudo_src = SocketAddr::new(
            IpAddr::V4(std::net::Ipv4Addr::new(
                10,
                200,
                ((conn_id >> 16) & 0xFF) as u8,
                ((conn_id >> 8) & 0xFF) as u8,
            )),
            (conn_id & 0xFFFF) as u16,
        );
        let session_key = UdpSessionKey::new(pseudo_src, initial_dest);
        let shard_idx = self.route_to_shard(&session_key);

        debug!(
            "UDP connection for {} routed to shard {}",
            initial_dest, shard_idx
        );

        // Track last activity time for timeout
        let mut last_activity = Instant::now();

        loop {
            if self.is_shutdown() {
                break;
            }

            tokio::select! {
                biased;

                // Read VLESS UDP frame from stream (Xray-compatible format)
                frame_result = VlessUdpFrame::read_from(&mut stream) => {
                    match frame_result {
                        Ok(Some(frame)) => {
                            last_activity = Instant::now();
                            bytes_sent += frame.payload.len() as u64;
                            datagrams_sent += 1;

                            // Extract destination from frame (XUDP mode support)
                            // Fall back to initial_dest if frame has domain (requires DNS resolution)
                            let dest_addr = frame.socket_addr().unwrap_or(initial_dest);

                            trace!(
                                "UDP frame {} -> {}: {} bytes",
                                pseudo_src, dest_addr, frame.payload.len()
                            );

                            // Send UDP datagram through shard
                            let event = BridgeEvent::udp_send(
                                session_key.clone(),
                                dest_addr,
                                frame.payload,
                                if datagrams_sent == 1 {
                                    Some(reply_tx.clone())
                                } else {
                                    None
                                },
                            );

                            if let Err(e) = self.shard_senders[shard_idx].try_send(event) {
                                warn!("Failed to send UdpSend: {:?}", e);
                            }
                        }
                        Ok(None) => {
                            // Clean EOF
                            debug!("UDP stream closed (EOF)");
                            break;
                        }
                        Err(e) => {
                            // Check if it's a connection reset or other expected close
                            if let BridgeError::Io(ref io_err) = e {
                                if io_err.kind() == std::io::ErrorKind::UnexpectedEof
                                    || io_err.kind() == std::io::ErrorKind::ConnectionReset
                                {
                                    debug!("UDP stream closed: {}", io_err.kind());
                                    break;
                                }
                            }
                            warn!("UDP frame read error: {}", e);
                            return Err(e);
                        }
                    }
                }

                // Receive UDP reply from shard
                Some(reply) = reply_rx.recv() => {
                    last_activity = Instant::now();
                    bytes_received += reply.data.len() as u64;
                    datagrams_received += 1;

                    // Write reply as VLESS UDP frame (Xray-compatible format)
                    let reply_frame = VlessUdpFrame::from_socket_addr(reply.source, reply.data);
                    if let Err(e) = reply_frame.write_to(&mut stream).await {
                        warn!("UDP stream write error: {}", e);
                        break;
                    }
                }

                // Timeout for cleanup (30 seconds of inactivity)
                _ = tokio::time::sleep(Duration::from_secs(30)) => {
                    if last_activity.elapsed() > Duration::from_secs(30) {
                        debug!("UDP session timeout after 30s of inactivity");
                        break;
                    }
                }
            }
        }

        // Flush stream before closing
        let _ = stream.flush().await;

        // Send close event
        let _ = self.shard_senders[shard_idx].try_send(BridgeEvent::udp_close(session_key));

        Ok(UdpConnectionStats {
            datagrams_sent,
            datagrams_received,
            bytes_sent,
            bytes_received,
            duration: start.elapsed(),
        })
    }

    // =========================================================================
    // Public API - Raw UDP Packet Handling (for Shadowsocks)
    // =========================================================================

    /// Send a raw UDP packet through the WireGuard tunnel
    ///
    /// This is designed for protocols like Shadowsocks that send individual
    /// UDP packets rather than using VLESS UDP-over-TCP framing.
    ///
    /// # Arguments
    ///
    /// * `client_addr` - Original client address (for reply routing)
    /// * `dest_addr` - Destination address
    /// * `payload` - UDP payload to send
    /// * `reply_tx` - Channel for receiving replies
    ///
    /// # Returns
    ///
    /// `Ok(())` if the packet was queued for sending.
    pub async fn send_raw_udp_packet(
        &self,
        client_addr: SocketAddr,
        dest_addr: SocketAddr,
        payload: Bytes,
        reply_tx: mpsc::Sender<RawUdpReply>,
    ) -> Result<(), BridgeError> {
        if self.is_shutdown() {
            return Err(BridgeError::TunnelDown("bridge is shutting down".into()));
        }

        // Create session key and route to shard
        let session_key = UdpSessionKey::new(client_addr, dest_addr);
        let shard_idx = self.route_to_shard(&session_key);

        // Wrap the reply_tx to convert UdpReply -> RawUdpReply
        let client_addr_copy = client_addr;
        let (inner_tx, mut inner_rx) = mpsc::channel::<UdpReply>(16);

        // Spawn a task to convert replies
        let reply_tx_clone = reply_tx.clone();
        tokio::spawn(async move {
            while let Some(udp_reply) = inner_rx.recv().await {
                let raw_reply = RawUdpReply::new(
                    client_addr_copy,
                    udp_reply.source,
                    udp_reply.data,
                );
                if reply_tx_clone.send(raw_reply).await.is_err() {
                    break;
                }
            }
        });

        // Send UDP packet
        let event = BridgeEvent::udp_send(
            session_key,
            dest_addr,
            payload,
            Some(inner_tx),
        );

        self.shard_senders[shard_idx]
            .try_send(event)
            .map_err(|e| BridgeError::ChannelSendFailed(format!("{:?}", e)))
    }

    /// Try to receive a raw UDP reply (non-blocking)
    ///
    /// This is a legacy API for compatibility. New code should use the
    /// `reply_tx` channel passed to `send_raw_udp_packet`.
    ///
    /// # Returns
    ///
    /// `None` since replies are now delivered via the per-packet reply channel.
    #[must_use]
    pub fn try_recv_raw_udp_reply(&self) -> Option<RawUdpReply> {
        // In the new architecture, replies are delivered via the reply_tx
        // channel passed to send_raw_udp_packet. This method exists for
        // API compatibility but always returns None.
        None
    }

    // =========================================================================
    // Internal Helpers
    // =========================================================================

    /// Allocate a unique connection ID
    fn allocate_conn_id(&self) -> u64 {
        static CONN_ID_COUNTER: AtomicU64 = AtomicU64::new(1);
        CONN_ID_COUNTER.fetch_add(1, Ordering::Relaxed)
    }
}

impl std::fmt::Debug for ShardedVlessWgBridge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShardedVlessWgBridge")
            .field("num_shards", &self.num_shards)
            .field("is_shutdown", &self.is_shutdown())
            .finish()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    // -------------------------------------------------------------------------
    // Configuration Tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_sharded_bridge_config_default() {
        let config = ShardedBridgeConfig::default();
        // Default uses half CPU cores, clamped to 2-16
        let expected = (num_cpus::get() / 2).clamp(2, 16);
        assert_eq!(config.num_shards, expected);
    }

    #[test]
    fn test_sharded_bridge_config_new() {
        let config = ShardedBridgeConfig::new(8);
        assert_eq!(config.num_shards, 8);
    }

    #[test]
    fn test_sharded_bridge_config_clamp() {
        let config_min = ShardedBridgeConfig::new(0);
        assert_eq!(config_min.num_shards, MIN_SHARD_COUNT);

        let config_max = ShardedBridgeConfig::new(1000);
        assert_eq!(config_max.num_shards, MAX_SHARD_COUNT);
    }

    #[test]
    fn test_shard_config_template_synthetic_ip() {
        let template = ShardConfigTemplate::default();
        // Without tunnel_local_ip, should use synthetic shard IP
        // Pass total_shards=8 for port partitioning
        let config = template.for_shard(5, 8, None);

        assert_eq!(config.shard_index, 5);
        assert_eq!(config.total_shards, 8);
        assert_eq!(config.mtu, 1420);
        // IP should be 10.200.5.1 (synthetic shard IP)
        assert_eq!(config.local_ip, IpAddress::v4(10, 200, 5, 1));
        // CIDR should be /32 for point-to-point
        assert_eq!(
            config.local_cidr,
            IpCidr::new(IpAddress::v4(10, 200, 5, 1), 32)
        );
    }

    #[test]
    fn test_shard_config_template_with_tunnel_ip() {
        let template = ShardConfigTemplate::default();
        let tunnel_ip = IpAddress::v4(10, 200, 200, 5);
        // With tunnel_local_ip, all shards should use the tunnel's IP
        // Pass total_shards=8 for port partitioning
        let config = template.for_shard(5, 8, Some(tunnel_ip));

        assert_eq!(config.shard_index, 5);
        assert_eq!(config.total_shards, 8);
        assert_eq!(config.mtu, 1420);
        // IP should be the tunnel's actual IP
        assert_eq!(config.local_ip, IpAddress::v4(10, 200, 200, 5));
        // CIDR should be /32 for point-to-point
        assert_eq!(
            config.local_cidr,
            IpCidr::new(IpAddress::v4(10, 200, 200, 5), 32)
        );
    }

    #[test]
    fn test_port_based_shard_routing() {
        // Test that port-based routing works correctly with partitioned ports
        // With 4 shards and 16384 ports (49152-65535):
        // Shard 0: 49152-53247 (4096 ports)
        // Shard 1: 53248-57343 (4096 ports)
        // Shard 2: 57344-61439 (4096 ports)
        // Shard 3: 61440-65535 (4096 ports)

        assert_eq!(PortAllocator::shard_for_port(49152, 4), Some(0));
        assert_eq!(PortAllocator::shard_for_port(53247, 4), Some(0));
        assert_eq!(PortAllocator::shard_for_port(53248, 4), Some(1));
        assert_eq!(PortAllocator::shard_for_port(57343, 4), Some(1));
        assert_eq!(PortAllocator::shard_for_port(57344, 4), Some(2));
        assert_eq!(PortAllocator::shard_for_port(61439, 4), Some(2));
        assert_eq!(PortAllocator::shard_for_port(61440, 4), Some(3));
        assert_eq!(PortAllocator::shard_for_port(65535, 4), Some(3));

        // Ports outside ephemeral range return None
        assert_eq!(PortAllocator::shard_for_port(80, 4), None);
        assert_eq!(PortAllocator::shard_for_port(443, 4), None);
        assert_eq!(PortAllocator::shard_for_port(49151, 4), None);
    }

    // -------------------------------------------------------------------------
    // ShardKey Tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_tcp_session_key_hash() {
        let key1 = TcpSessionKey::from_parts(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            12345,
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            443,
        );
        let key2 = TcpSessionKey::from_parts(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            12345,
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            443,
        );

        assert_eq!(key1.shard_hash(), key2.shard_hash());
    }

    #[test]
    fn test_tcp_session_key_different_hash() {
        let key1 = TcpSessionKey::from_parts(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            12345,
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            443,
        );
        let key2 = TcpSessionKey::from_parts(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)), // Different IP
            12345,
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            443,
        );

        assert_ne!(key1.shard_hash(), key2.shard_hash());
    }

    #[test]
    fn test_tuple_shard_key() {
        let tuple = (
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            5000u16,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            8080u16,
        );

        let hash = tuple.shard_hash();
        assert!(hash > 0); // Non-zero hash
    }

    // -------------------------------------------------------------------------
    // Statistics Tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_aggregated_stats_new() {
        let stats = AggregatedStats::new(4);
        assert_eq!(stats.num_shards, 4);
        assert_eq!(stats.shard_stats.len(), 4);
    }

    #[test]
    fn test_shard_stats_collector() {
        let collector = ShardStatsCollector::new();
        collector.events_processed.store(100, Ordering::Relaxed);
        collector.wg_packets_received.store(50, Ordering::Relaxed);

        let snapshot = collector.snapshot();
        assert_eq!(snapshot.events_processed, 100);
        assert_eq!(snapshot.wg_packets_received, 50);
    }

    #[test]
    fn test_aggregated_stats_snapshot() {
        let stats = AggregatedStats::new(2);

        // Update first shard
        stats.shard_stats[0]
            .events_processed
            .store(100, Ordering::Relaxed);
        stats.shard_stats[0]
            .tcp_sessions_created
            .store(10, Ordering::Relaxed);

        // Update second shard
        stats.shard_stats[1]
            .events_processed
            .store(150, Ordering::Relaxed);
        stats.shard_stats[1]
            .tcp_sessions_created
            .store(15, Ordering::Relaxed);

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.total_events_processed, 250);
        assert_eq!(snapshot.total_tcp_sessions_created, 25);
    }

    #[test]
    fn test_distribution_skew() {
        let stats = AggregatedStats::new(2);

        // Even distribution
        stats.shard_stats[0]
            .events_processed
            .store(100, Ordering::Relaxed);
        stats.shard_stats[1]
            .events_processed
            .store(100, Ordering::Relaxed);

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.distribution_skew(), 0.0);

        // Uneven distribution
        stats.shard_stats[0]
            .events_processed
            .store(100, Ordering::Relaxed);
        stats.shard_stats[1]
            .events_processed
            .store(200, Ordering::Relaxed);

        let snapshot = stats.snapshot();
        assert!(snapshot.distribution_skew() > 0.0);
    }

    #[test]
    fn test_active_sessions() {
        let stats = AggregatedStats::new(1);
        stats.shard_stats[0]
            .tcp_sessions_created
            .store(100, Ordering::Relaxed);
        stats.shard_stats[0]
            .tcp_sessions_closed
            .store(30, Ordering::Relaxed);
        stats.shard_stats[0]
            .udp_sessions_created
            .store(50, Ordering::Relaxed);
        stats.shard_stats[0]
            .udp_sessions_closed
            .store(10, Ordering::Relaxed);

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.active_tcp_sessions(), 70);
        assert_eq!(snapshot.active_udp_sessions(), 40);
    }

    // -------------------------------------------------------------------------
    // IP Packet Parsing Tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_parse_ipv4_dest() {
        // Minimal IPv4 TCP packet
        let mut packet = vec![0u8; 40];
        packet[0] = 0x45; // Version 4, IHL 5 (20 bytes)
        packet[9] = 6; // TCP protocol
        packet[16..20].copy_from_slice(&[93, 184, 216, 34]); // Dest IP: 93.184.216.34
        packet[22..24].copy_from_slice(&80u16.to_be_bytes()); // Dest port: 80

        let result = ShardedVlessWgBridge::parse_ipv4_dest(&packet);
        assert!(result.is_some());
        let (ip, port) = result.unwrap();
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));
        assert_eq!(port, 80);
    }

    #[test]
    fn test_parse_ipv4_dest_too_short() {
        let packet = vec![0u8; 10]; // Too short
        assert!(ShardedVlessWgBridge::parse_ipv4_dest(&packet).is_none());
    }

    #[test]
    fn test_compute_shard_index_consistency() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let port = 12345u16;

        let idx1 = ShardedVlessWgBridge::compute_shard_index(ip, port, 8);
        let idx2 = ShardedVlessWgBridge::compute_shard_index(ip, port, 8);

        assert_eq!(idx1, idx2);
        assert!(idx1 < 8);
    }

    #[test]
    fn test_compute_shard_index_distribution() {
        // Test that different IPs get distributed across shards
        let mut shard_counts = [0usize; 8];

        for i in 0..256 {
            let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, i as u8));
            let idx = ShardedVlessWgBridge::compute_shard_index(ip, 80, 8);
            shard_counts[idx] += 1;
        }

        // All shards should have some traffic
        for count in shard_counts {
            assert!(count > 0, "Expected all shards to receive some traffic");
        }
    }
}
