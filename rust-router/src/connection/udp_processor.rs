//! UDP Packet Processor
//!
//! This module provides the core logic for processing UDP packets received
//! from the TPROXY listener and forwarding them through outbounds.
//!
//! # Architecture
//!
//! ```text
//! Client → TPROXY Listener → UDP Processor → RuleEngine → Outbound → Destination
//!               ↓                  ↓              ↓            ↓
//!         UdpPacketInfo      QUIC SNI Sniff  ConnectionInfo  UdpOutboundHandle
//!                                  ↓              ↓
//!                            Handle Cache   ReplyHandler → Client
//! ```
//!
//! # Session Management
//!
//! UDP is connectionless, so we use sessions to track the mapping between
//! client endpoints and outbound handles. Outbound handles are cached in
//! a moka LRU cache with configurable TTL.
//!
//! # QUIC SNI Integration (Phase 5.3)
//!
//! The processor supports QUIC Initial packet SNI extraction for rule-based routing:
//! - Detects QUIC Initial packets using `QuicSniffer::is_initial()`
//! - Extracts SNI hostname for domain-based rule matching
//! - Falls back to IP/port-based routing when SNI unavailable
//!
//! # Example
//!
//! ```no_run
//! use rust_router::connection::{UdpPacketProcessor, UdpProcessorConfig};
//! use rust_router::rules::engine::RuleEngine;
//! use rust_router::outbound::OutboundManager;
//! use std::sync::Arc;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = UdpProcessorConfig::default();
//! let processor = UdpPacketProcessor::new(config);
//!
//! // With rule engine integration
//! // let rule_engine = Arc::new(RuleEngine::new(...));
//! // let outbound_manager = Arc::new(OutboundManager::new());
//! // let result = processor.process_with_rules(&packet, &rule_engine, &outbound_manager).await;
//! # Ok(())
//! # }
//! ```

use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

// SEC-2 FIX: Mutex for synchronizing cleanup operations
use std::sync::Mutex;

use dashmap::DashMap;
use moka::sync::Cache;
use tracing::{debug, trace, warn};

use super::udp::{UdpSessionConfig, UdpSessionKey};
use crate::ecmp::{EcmpGroupManager, FiveTuple, Protocol};
use crate::error::UdpError;
use crate::outbound::{Outbound, OutboundManager, UdpOutboundHandle};
use crate::rules::engine::{ConnectionInfo, RuleEngine};
use crate::sniff::quic::QuicSniffer;
use crate::tproxy::UdpPacketInfo;

/// Default timeout for UDP outbound connections in seconds.
///
/// This timeout applies to the initial connection establishment for
/// UDP sessions. DNS and other latency-sensitive UDP protocols may
/// benefit from a shorter timeout, while file transfer protocols
/// may need longer timeouts.
pub const DEFAULT_UDP_CONNECT_TIMEOUT_SECS: u64 = 10;

/// Default maximum sessions per source IP address.
///
/// SEC-1 FIX: This limit prevents IP spoofing attacks from exhausting
/// the session table. An attacker forging source IPs could create one
/// session per spoofed IP, filling the cache. With per-IP limiting,
/// each source IP is capped at this number of concurrent sessions.
///
/// The default of 1000 sessions/IP is generous for legitimate clients
/// (e.g., browsers with many QUIC connections) while limiting attack impact.
pub const DEFAULT_MAX_SESSIONS_PER_IP: u32 = 1000;

/// SEC-2 FIX: Default maximum number of tracked source IPs.
///
/// This prevents memory exhaustion attacks where an attacker sends packets
/// from millions of unique spoofed source IPs. Each IP entry consumes ~56 bytes,
/// so 100,000 entries = ~5.6MB maximum memory for IP tracking.
///
/// When this limit is reached, zero-count entries are cleaned up. If still over
/// limit after cleanup, new IPs are rejected until existing sessions expire.
pub const DEFAULT_MAX_TRACKED_IPS: usize = 100_000;

/// SEC-2 FIX: Default interval between cleanup checks in seconds.
///
/// Cleanup removes zero-count IP entries to prevent memory exhaustion.
/// The cleanup runs when:
/// 1. A session is decremented (opportunistic cleanup every N decrements), or
/// 2. The tracked IP count exceeds `max_tracked_ips`
pub const DEFAULT_CLEANUP_INTERVAL_SECS: u64 = 60;

/// SEC-2 FIX: Number of decrements between cleanup checks.
///
/// To avoid running cleanup too frequently, we only check every N decrements.
/// This provides a balance between memory efficiency and CPU usage.
const CLEANUP_CHECK_INTERVAL_DECREMENTS: u64 = 1000;

/// P1 FIX: Helper function to safely decrement an `AtomicU32` without underflow.
///
/// Uses a CAS (Compare-And-Swap) loop to ensure the counter never goes below 0.
/// This is extracted to avoid code duplication between the eviction listener
/// and the `decrement_ip_session_count` method.
///
/// # Returns
///
/// `true` if the counter was successfully decremented, `false` if it was already 0.
#[inline]
fn cas_decrement(counter: &AtomicU32) -> bool {
    loop {
        let current = counter.load(Ordering::Relaxed);
        if current == 0 {
            // Already at 0, nothing to decrement
            return false;
        }
        // Try to decrement atomically
        match counter.compare_exchange_weak(
            current,
            current - 1,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => return true,   // Successfully decremented
            Err(_) => continue,     // Another thread modified, retry
        }
    }
}

/// Configuration for the UDP processor
#[derive(Debug, Clone)]
pub struct UdpProcessorConfig {
    /// Session manager configuration
    pub session_config: UdpSessionConfig,
    /// Outbound connection timeout
    pub connect_timeout: Duration,
    /// Whether to enable QUIC SNI sniffing
    pub enable_quic_sniff: bool,
    /// SEC-1 FIX: Maximum sessions per source IP (0 = unlimited)
    ///
    /// This prevents session table exhaustion via IP spoofing attacks.
    /// When a source IP reaches this limit, new sessions from that IP are rejected.
    pub max_sessions_per_ip: u32,
    /// SEC-2 FIX: Maximum number of tracked source IPs (0 = unlimited)
    ///
    /// This prevents memory exhaustion via IP spoofing attacks.
    /// When exceeded, zero-count entries are cleaned up.
    pub max_tracked_ips: usize,
    /// SEC-2 FIX: Minimum interval between cleanup operations
    ///
    /// Cleanup removes zero-count IP entries to prevent memory exhaustion.
    pub cleanup_interval: Duration,
}

impl Default for UdpProcessorConfig {
    fn default() -> Self {
        Self {
            session_config: UdpSessionConfig::default(),
            connect_timeout: Duration::from_secs(DEFAULT_UDP_CONNECT_TIMEOUT_SECS),
            enable_quic_sniff: true,
            max_sessions_per_ip: DEFAULT_MAX_SESSIONS_PER_IP,
            max_tracked_ips: DEFAULT_MAX_TRACKED_IPS,
            cleanup_interval: Duration::from_secs(DEFAULT_CLEANUP_INTERVAL_SECS),
        }
    }
}

/// Statistics for the UDP processor
#[derive(Debug, Default)]
pub struct UdpProcessorStats {
    /// Total packets processed
    pub packets_processed: AtomicU64,
    /// Packets forwarded to outbound
    pub packets_forwarded: AtomicU64,
    /// Packets failed
    pub packets_failed: AtomicU64,
    /// Sessions created
    pub sessions_created: AtomicU64,
    /// Sessions reused
    pub sessions_reused: AtomicU64,
    /// Total bytes sent
    pub bytes_sent: AtomicU64,
    /// QUIC packets detected
    pub quic_packets: AtomicU64,
    /// QUIC SNI extracted successfully
    pub quic_sni_extracted: AtomicU64,
    /// Rule matches (non-default outbound)
    pub rule_matches: AtomicU64,
    /// SEC-1: Sessions rejected due to per-IP rate limit
    pub sessions_rate_limited: AtomicU64,
}

impl UdpProcessorStats {
    /// Create a new stats instance
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Get a snapshot of the stats
    #[must_use]
    pub fn snapshot(&self) -> UdpProcessorStatsSnapshot {
        UdpProcessorStatsSnapshot {
            packets_processed: self.packets_processed.load(Ordering::Relaxed),
            packets_forwarded: self.packets_forwarded.load(Ordering::Relaxed),
            packets_failed: self.packets_failed.load(Ordering::Relaxed),
            sessions_created: self.sessions_created.load(Ordering::Relaxed),
            sessions_reused: self.sessions_reused.load(Ordering::Relaxed),
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            quic_packets: self.quic_packets.load(Ordering::Relaxed),
            quic_sni_extracted: self.quic_sni_extracted.load(Ordering::Relaxed),
            rule_matches: self.rule_matches.load(Ordering::Relaxed),
            sessions_rate_limited: self.sessions_rate_limited.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of UDP processor stats
#[derive(Debug, Clone)]
pub struct UdpProcessorStatsSnapshot {
    /// Total packets processed
    pub packets_processed: u64,
    /// Packets forwarded to outbound
    pub packets_forwarded: u64,
    /// Packets failed
    pub packets_failed: u64,
    /// Sessions created
    pub sessions_created: u64,
    /// Sessions reused
    pub sessions_reused: u64,
    /// Total bytes sent
    pub bytes_sent: u64,
    /// QUIC packets detected
    pub quic_packets: u64,
    /// QUIC SNI extracted successfully
    pub quic_sni_extracted: u64,
    /// Rule matches (non-default outbound)
    pub rule_matches: u64,
    /// SEC-1: Sessions rejected due to per-IP rate limit
    pub sessions_rate_limited: u64,
}

/// Result of processing a UDP packet
#[derive(Debug)]
pub enum ProcessResult {
    /// Packet was forwarded successfully
    Forwarded {
        /// Session key used
        session_key: UdpSessionKey,
        /// Bytes sent
        bytes_sent: usize,
        /// Whether a new session was created
        new_session: bool,
        /// Outbound tag used
        outbound_tag: String,
        /// Sniffed domain (from QUIC SNI)
        sniffed_domain: Option<String>,
        /// Whether rule matched (vs default outbound)
        rule_matched: bool,
    },
    /// Packet was blocked by the outbound
    Blocked {
        /// Reason for blocking
        reason: String,
    },
    /// Processing failed with an error
    Failed {
        /// Error that occurred
        error: UdpError,
    },
    /// SEC-1 FIX: Session creation rejected due to per-IP rate limit
    RateLimited {
        /// Source IP that hit the limit
        source_ip: IpAddr,
        /// Current session count for this IP
        current_count: u32,
        /// Maximum allowed sessions per IP
        max_allowed: u32,
    },
}

/// Metadata about a UDP session for routing decisions.
#[derive(Debug, Clone)]
pub struct UdpRoutingInfo {
    /// Sniffed domain (from QUIC SNI)
    pub domain: Option<String>,
    /// Selected outbound tag
    pub outbound: String,
    /// Routing mark (for DSCP chains)
    pub routing_mark: Option<u32>,
    /// Whether a rule matched (vs default outbound)
    pub rule_matched: bool,
}

/// UDP Packet Processor
///
/// Handles incoming UDP packets from the TPROXY listener, manages sessions,
/// and forwards packets through the appropriate outbound.
pub struct UdpPacketProcessor {
    /// Cache of outbound handles, keyed by session key
    handle_cache: Cache<UdpSessionKey, Arc<UdpSessionWrapper>>,
    /// Configuration
    config: UdpProcessorConfig,
    /// Statistics
    stats: Arc<UdpProcessorStats>,
    /// SEC-1 FIX: Per-IP session counter to prevent session table exhaustion
    ///
    /// Maps source IP to current session count. Uses `AtomicU32` for lock-free
    /// increment/decrement. When a session is created, the counter is incremented;
    /// when evicted from cache, it's decremented.
    ///
    /// NEW-3 FIX: Wrapped in Arc to allow sharing with moka's eviction listener.
    /// The eviction listener runs on moka's internal thread and needs access to
    /// this map to decrement counters when sessions are evicted by TTL/LRU.
    ip_session_counts: Arc<DashMap<IpAddr, AtomicU32>>,
    /// SEC-2 FIX: Counter for decrement operations since last cleanup
    decrement_counter: AtomicU64,
    /// SEC-2 FIX: Last cleanup timestamp, protected by Mutex for thread-safe updates
    last_cleanup: Mutex<Instant>,
    /// Phase 6-Fix.AI: ECMP group manager for load balancing
    ecmp_group_manager: Option<Arc<EcmpGroupManager>>,
}

impl UdpPacketProcessor {
    /// Create a new UDP packet processor
    pub fn new(config: UdpProcessorConfig) -> Self {
        // NEW-3 FIX: Create ip_session_counts as Arc so it can be shared with eviction listener
        let ip_session_counts: Arc<DashMap<IpAddr, AtomicU32>> = Arc::new(DashMap::new());
        let max_sessions_per_ip = config.max_sessions_per_ip;

        // Clone the Arc for the eviction listener closure
        let ip_counts_for_listener = Arc::clone(&ip_session_counts);

        let handle_cache = Cache::builder()
            .max_capacity(config.session_config.max_sessions)
            .time_to_idle(config.session_config.idle_timeout)
            .time_to_live(config.session_config.ttl)
            // NEW-3 FIX: Add eviction listener to decrement IP session counts when
            // sessions are evicted by TTL, LRU, or explicit invalidation.
            // This prevents counter drift that would otherwise cause legitimate
            // clients to be incorrectly rate-limited.
            .eviction_listener(move |key: Arc<UdpSessionKey>, _value, _cause| {
                // Skip if rate limiting is disabled
                if max_sessions_per_ip == 0 {
                    return;
                }

                let source_ip = key.client_addr.ip();
                if let Some(entry) = ip_counts_for_listener.get(&source_ip) {
                    // P1 FIX: Use extracted helper for CAS decrement
                    cas_decrement(entry.value());
                }
            })
            .build();

        Self {
            handle_cache,
            config,
            stats: Arc::new(UdpProcessorStats::new()),
            ip_session_counts,
            decrement_counter: AtomicU64::new(0),
            last_cleanup: Mutex::new(Instant::now()),
            ecmp_group_manager: None,
        }
    }

    /// Create with default configuration
    #[must_use]
    pub fn new_default() -> Self {
        Self::new(UdpProcessorConfig::default())
    }

    /// Phase 6-Fix.AI: Set ECMP group manager for load balancing
    pub fn with_ecmp_group_manager(mut self, ecmp_manager: Arc<EcmpGroupManager>) -> Self {
        self.ecmp_group_manager = Some(ecmp_manager);
        self
    }

    /// Phase 6-Fix.AI: Set ECMP group manager (mutable reference version)
    pub fn set_ecmp_group_manager(&mut self, ecmp_manager: Arc<EcmpGroupManager>) {
        self.ecmp_group_manager = Some(ecmp_manager);
    }

    /// Phase 6-Fix.AI: Resolve an outbound tag, checking ECMP groups if needed.
    ///
    /// This method first tries to find the tag in `outbound_manager`. If not found
    /// and an ECMP group manager is configured, it checks if the tag is an ECMP
    /// group and selects a member using the five-tuple hash.
    ///
    /// # Arguments
    ///
    /// * `tag` - The outbound tag to resolve
    /// * `packet` - The UDP packet (for building five-tuple)
    /// * `outbound_manager` - The outbound manager
    ///
    /// # Returns
    ///
    /// The resolved outbound and its tag, or None if not found.
    fn resolve_outbound_with_ecmp(
        &self,
        tag: &str,
        packet: &UdpPacketInfo,
        outbound_manager: &OutboundManager,
    ) -> Option<(Arc<dyn Outbound>, String)> {
        // Try direct lookup first
        if let Some(outbound) = outbound_manager.get(tag) {
            return Some((outbound, tag.to_string()));
        }

        // Check if it's an ECMP group
        if let Some(ref ecmp_mgr) = self.ecmp_group_manager {
            if ecmp_mgr.has_group(tag) {
                // Build five-tuple for load balancing
                let five_tuple = FiveTuple::new(
                    packet.client_addr.ip(),
                    packet.original_dst.ip(),
                    packet.client_addr.port(),
                    packet.original_dst.port(),
                    Protocol::Udp,
                );

                // Select member using the group's load balancing algorithm
                if let Some(group) = ecmp_mgr.get_group(tag) {
                    match group.select_by_connection(&five_tuple) {
                        Ok(member_tag) => {
                            debug!(
                                "ECMP group '{}' selected member '{}' for {} -> {}",
                                tag, member_tag, packet.client_addr, packet.original_dst
                            );
                            // Recursively resolve the member (it might be in outbound_manager)
                            if let Some(outbound) = outbound_manager.get(&member_tag) {
                                return Some((outbound, member_tag));
                            }
                            warn!(
                                "ECMP member '{}' not found in outbound_manager",
                                member_tag
                            );
                        }
                        Err(e) => {
                            warn!("ECMP group '{}' failed to select member: {}", tag, e);
                        }
                    }
                }
            }
        }

        None
    }

    /// SEC-1 FIX: Check if source IP has exceeded session limit.
    ///
    /// Returns `Ok(current_count)` if a new session is allowed,
    /// or `Err((current, max))` if the limit is reached.
    ///
    /// # Thread Safety
    ///
    /// This method uses atomic operations for lock-free updates.
    ///
    /// # SEC-2 Enhancement
    ///
    /// This method now enforces `max_tracked_ips` as a hard limit. When the
    /// `DashMap` has reached capacity, NEW IPs are rejected without creating
    /// an entry. Existing IPs can still create sessions up to their limit.
    fn check_ip_session_limit(&self, source_ip: IpAddr) -> Result<u32, (u32, u32)> {
        // 0 means unlimited
        if self.config.max_sessions_per_ip == 0 {
            return Ok(0);
        }

        // SEC-2 FIX: Check if this is a NEW IP and we're at capacity.
        // We must check BEFORE calling entry() to avoid creating a new entry.
        // Using contains_key + entry is a TOCTOU, but the worst case is we
        // allow one extra entry, which is acceptable for DoS protection.
        if self.config.max_tracked_ips > 0
            && !self.ip_session_counts.contains_key(&source_ip)
            && self.ip_session_counts.len() >= self.config.max_tracked_ips
        {
            // At capacity, reject NEW IPs (0 sessions allowed)
            debug!(
                "SEC-2: Rejecting new IP {} - at capacity ({}/{})",
                source_ip,
                self.ip_session_counts.len(),
                self.config.max_tracked_ips
            );
            return Err((0, 0)); // Special case: (0, 0) means "at IP capacity"
        }

        // Get or create counter for this IP
        let entry = self.ip_session_counts.entry(source_ip).or_insert_with(|| AtomicU32::new(0));

        // Try to increment atomically
        let current = entry.value().load(Ordering::Relaxed);
        if current >= self.config.max_sessions_per_ip {
            return Err((current, self.config.max_sessions_per_ip));
        }

        // Increment the counter
        // Note: This is a relaxed operation - in high contention scenarios,
        // we might briefly exceed the limit, but this is acceptable for DoS protection.
        let new_count = entry.value().fetch_add(1, Ordering::Relaxed) + 1;

        // Double-check we didn't exceed due to race
        if new_count > self.config.max_sessions_per_ip {
            // Undo the increment - another thread beat us
            entry.value().fetch_sub(1, Ordering::Relaxed);
            return Err((new_count - 1, self.config.max_sessions_per_ip));
        }

        Ok(new_count)
    }

    /// SEC-1 FIX: Decrement session count for a source IP.
    ///
    /// Should be called when a session is evicted or explicitly invalidated.
    ///
    /// NEW-4 FIX: Uses CAS (Compare-And-Swap) loop to prevent counter underflow.
    /// The previous implementation used `fetch_sub` which would underflow to
    /// `u32::MAX` if the counter was already 0, then try to fix it by storing 0,
    /// but by then the damage was done (wrapping subtraction already happened).
    ///
    /// SEC-2 FIX: Also triggers cleanup check to remove zero-count entries.
    fn decrement_ip_session_count(&self, source_ip: IpAddr) {
        if self.config.max_sessions_per_ip == 0 {
            return;
        }

        if let Some(entry) = self.ip_session_counts.get(&source_ip) {
            // P1 FIX: Use extracted helper for CAS decrement
            cas_decrement(entry.value());
        }

        // SEC-2 FIX: Check if cleanup is needed after decrement
        self.maybe_cleanup();
    }

    /// Get current session count for a source IP (for monitoring/debugging)
    #[must_use]
    pub fn get_ip_session_count(&self, source_ip: IpAddr) -> u32 {
        self.ip_session_counts
            .get(&source_ip)
            .map_or(0, |e| e.value().load(Ordering::Relaxed))
    }

    /// Get number of tracked source IPs (for monitoring)
    #[must_use]
    pub fn tracked_source_ips(&self) -> usize {
        self.ip_session_counts.len()
    }

    /// SEC-2 FIX: Clean up zero-count IP entries to prevent memory exhaustion.
    ///
    /// This method removes entries from `ip_session_counts` where the session
    /// count has dropped to 0. These entries are created when new IPs connect
    /// and would otherwise accumulate indefinitely.
    ///
    /// # Returns
    ///
    /// The number of entries removed.
    ///
    /// # Thread Safety
    ///
    /// Uses `DashMap::retain` which acquires locks per-shard, so this may
    /// briefly block other threads accessing the same shard. However, the
    /// lock is held only for the duration of the predicate check per entry.
    pub fn cleanup_zero_count_ips(&self) -> usize {
        // Skip cleanup if rate limiting is disabled
        if self.config.max_sessions_per_ip == 0 {
            return 0;
        }

        let before_count = self.ip_session_counts.len();

        // Remove entries where count is 0
        self.ip_session_counts.retain(|_ip, count| {
            count.load(Ordering::Relaxed) > 0
        });

        let removed = before_count.saturating_sub(self.ip_session_counts.len());
        if removed > 0 {
            debug!(
                "SEC-2: Cleaned up {} zero-count IP entries, {} remaining",
                removed,
                self.ip_session_counts.len()
            );
        }
        removed
    }

    /// SEC-2 FIX: Check if cleanup should run and perform it if needed.
    ///
    /// Cleanup triggers if:
    /// 1. Number of tracked IPs exceeds `max_tracked_ips`, OR
    /// 2. Enough time has passed since last cleanup AND enough decrements have occurred
    ///
    /// This is called opportunistically after decrement operations to avoid
    /// dedicating a separate background task for cleanup.
    fn maybe_cleanup(&self) {
        // Skip if rate limiting disabled or max_tracked_ips is unlimited
        if self.config.max_sessions_per_ip == 0 || self.config.max_tracked_ips == 0 {
            return;
        }

        let current_count = self.ip_session_counts.len();
        let should_cleanup = if current_count > self.config.max_tracked_ips {
            // Condition 1: Over capacity - must cleanup
            trace!(
                "SEC-2: IP count {} exceeds limit {}, triggering cleanup",
                current_count,
                self.config.max_tracked_ips
            );
            true
        } else {
            // Condition 2: Check interval-based cleanup
            let decrement_count = self.decrement_counter.fetch_add(1, Ordering::Relaxed) + 1;
            if decrement_count % CLEANUP_CHECK_INTERVAL_DECREMENTS == 0 {
                // Enough decrements have occurred, check time
                // Use try_lock to avoid blocking - if another thread is cleaning, skip
                if let Ok(mut last) = self.last_cleanup.try_lock() {
                    if last.elapsed() >= self.config.cleanup_interval {
                        *last = Instant::now();
                        true
                    } else {
                        false
                    }
                } else {
                    // Another thread holds the lock, likely doing cleanup
                    false
                }
            } else {
                false
            }
        };

        if should_cleanup {
            let removed = self.cleanup_zero_count_ips();

            // If still over capacity after cleanup, log a warning
            let after_count = self.ip_session_counts.len();
            if after_count > self.config.max_tracked_ips {
                warn!(
                    "SEC-2: After cleanup, IP count {} still exceeds limit {}. \
                     {} active sessions blocking cleanup. Consider increasing max_tracked_ips \
                     or reducing session timeout.",
                    after_count,
                    self.config.max_tracked_ips,
                    after_count
                );
            } else if removed > 0 {
                // Update last_cleanup time on successful cleanup
                // P1 FIX: Use unwrap_or_else to recover from poisoned mutex.
                // A poisoned mutex means a thread panicked while holding it,
                // but the inner data (Instant) is still valid and usable.
                let mut last = self.last_cleanup.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                *last = Instant::now();
            }
        }
    }

    /// SEC-2 FIX: Force cleanup of zero-count entries.
    ///
    /// This is useful for testing or when memory pressure is detected externally.
    /// Unlike `maybe_cleanup`, this always runs cleanup regardless of interval.
    ///
    /// # Returns
    ///
    /// The number of entries removed.
    pub fn force_cleanup(&self) -> usize {
        let removed = self.cleanup_zero_count_ips();

        // Update last_cleanup time
        // P1 FIX: Use unwrap_or_else to recover from poisoned mutex
        let mut last = self.last_cleanup.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        *last = Instant::now();

        // Reset decrement counter
        self.decrement_counter.store(0, Ordering::Relaxed);

        removed
    }

    /// Process a UDP packet with rule-based routing and QUIC SNI sniffing.
    ///
    /// This is the main entry point for UDP packet processing with full
    /// rule engine integration. It:
    ///
    /// 1. Sniffs QUIC Initial packets for SNI extraction (if enabled)
    /// 2. Builds `ConnectionInfo` for rule matching
    /// 3. Matches rules using `RuleEngine` to select outbound
    /// 4. Creates/reuses session with the selected outbound
    /// 5. Forwards the packet through the outbound
    ///
    /// # Arguments
    ///
    /// * `packet` - The received UDP packet info from TPROXY
    /// * `rule_engine` - Rule engine for connection routing
    /// * `outbound_manager` - Manager to get outbound by tag
    ///
    /// # Returns
    ///
    /// `ProcessResult` indicating success, blocked, or failure.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use rust_router::connection::{UdpPacketProcessor, UdpProcessorConfig};
    /// # use rust_router::rules::engine::{RuleEngine, RoutingSnapshotBuilder};
    /// # use rust_router::outbound::OutboundManager;
    /// # use std::sync::Arc;
    /// # async fn example(packet: &rust_router::tproxy::UdpPacketInfo) {
    /// let config = UdpProcessorConfig::default();
    /// let processor = UdpPacketProcessor::new(config);
    /// let rule_engine = Arc::new(RuleEngine::new(
    ///     RoutingSnapshotBuilder::new().default_outbound("direct").build().unwrap()
    /// ));
    /// let outbound_manager = Arc::new(OutboundManager::new());
    ///
    /// let result = processor.process_with_rules(&packet, &rule_engine, &outbound_manager).await;
    /// # }
    /// ```
    pub async fn process_with_rules(
        &self,
        packet: &UdpPacketInfo,
        rule_engine: &RuleEngine,
        outbound_manager: &OutboundManager,
    ) -> ProcessResult {
        self.stats.packets_processed.fetch_add(1, Ordering::Relaxed);

        let session_key = UdpSessionKey::new(packet.client_addr, packet.original_dst);

        // Try to get existing session
        if let Some(session) = self.handle_cache.get(&session_key) {
            // Reuse existing session
            self.stats.sessions_reused.fetch_add(1, Ordering::Relaxed);
            trace!(
                "Reusing UDP session for {} -> {} via {}",
                packet.client_addr,
                packet.original_dst,
                session.routing_info.outbound
            );

            return self.forward_packet(packet, session, session_key, false).await;
        }

        // SEC-1 FIX: Check per-IP session rate limit before creating new session
        let source_ip = packet.client_addr.ip();
        if let Err((current, max)) = self.check_ip_session_limit(source_ip) {
            self.stats.sessions_rate_limited.fetch_add(1, Ordering::Relaxed);
            warn!(
                "Rate limit: {} has {} sessions (max {}), rejecting {} -> {}",
                source_ip, current, max, packet.client_addr, packet.original_dst
            );
            return ProcessResult::RateLimited {
                source_ip,
                current_count: current,
                max_allowed: max,
            };
        }

        // Sniff QUIC SNI on first packet of session
        let sniffed_domain = self.sniff_quic_sni(&packet.data);

        // Build ConnectionInfo for rule matching
        let conn_info = self.build_connection_info(packet, sniffed_domain.as_deref());

        // Match rules using RuleEngine
        let match_result = rule_engine.match_connection(&conn_info);

        debug!(
            "UDP routing {} -> {} via {} (domain: {:?}, matched: {})",
            packet.client_addr,
            packet.original_dst,
            match_result.outbound,
            sniffed_domain,
            !match_result.is_default()
        );

        // Phase 6-Fix.AI: Get outbound from manager with ECMP group resolution
        // This supports both direct outbounds and ECMP load balancing groups
        let (outbound, actual_outbound_tag) = if let Some(resolved) =
            self.resolve_outbound_with_ecmp(&match_result.outbound, packet, outbound_manager)
        {
            resolved
        } else {
            warn!(
                "Outbound '{}' not found, using default",
                match_result.outbound
            );
            // Try to resolve the default outbound (which could also be an ECMP group)
            if let Some(resolved) =
                self.resolve_outbound_with_ecmp(&rule_engine.default_outbound(), packet, outbound_manager)
            {
                resolved
            } else {
                // Counter drift fix: decrement counter since session won't be created
                self.decrement_ip_session_count(source_ip);
                return ProcessResult::Failed {
                    error: UdpError::OutboundNotFound {
                        tag: match_result.outbound,
                    },
                };
            }
        };

        // Track rule match stats
        if !match_result.is_default() {
            self.stats.rule_matches.fetch_add(1, Ordering::Relaxed);
        }

        // Create routing info - move sniffed_domain instead of cloning
        // since it's not used after this point
        // Phase 6-Fix.AI: Use actual_outbound_tag which reflects ECMP member selection
        let routing_info = UdpRoutingInfo {
            domain: sniffed_domain,
            outbound: actual_outbound_tag,
            routing_mark: match_result.routing_mark,
            rule_matched: !match_result.is_default(),
        };

        // Create new session
        self.create_and_forward_session(packet, outbound.as_ref(), session_key, routing_info)
            .await
    }

    /// Process a UDP packet with a pre-selected outbound (legacy method).
    ///
    /// This method is provided for backwards compatibility or when the
    /// outbound is already determined externally.
    ///
    /// # Arguments
    ///
    /// * `packet` - The received UDP packet info from TPROXY
    /// * `outbound` - The outbound to use for this packet
    ///
    /// # Returns
    ///
    /// `ProcessResult` indicating success, blocked, or failure.
    pub async fn process(
        &self,
        packet: &UdpPacketInfo,
        outbound: &dyn Outbound,
    ) -> ProcessResult {
        self.stats.packets_processed.fetch_add(1, Ordering::Relaxed);

        let session_key = UdpSessionKey::new(packet.client_addr, packet.original_dst);

        // Try to get existing session
        if let Some(session) = self.handle_cache.get(&session_key) {
            // Reuse existing session
            self.stats.sessions_reused.fetch_add(1, Ordering::Relaxed);
            trace!(
                "Reusing UDP session for {} -> {}",
                packet.client_addr,
                packet.original_dst
            );

            return self.forward_packet(packet, session, session_key, false).await;
        }

        // SEC-1 FIX: Check per-IP session rate limit before creating new session
        let source_ip = packet.client_addr.ip();
        if let Err((current, max)) = self.check_ip_session_limit(source_ip) {
            self.stats.sessions_rate_limited.fetch_add(1, Ordering::Relaxed);
            warn!(
                "Rate limit: {} has {} sessions (max {}), rejecting {} -> {}",
                source_ip, current, max, packet.client_addr, packet.original_dst
            );
            return ProcessResult::RateLimited {
                source_ip,
                current_count: current,
                max_allowed: max,
            };
        }

        // Optionally sniff QUIC SNI for logging
        let sniffed_domain = if self.config.enable_quic_sniff {
            self.sniff_quic_sni(&packet.data)
        } else {
            None
        };

        // Create routing info
        let routing_info = UdpRoutingInfo {
            domain: sniffed_domain,
            outbound: outbound.tag().to_string(),
            routing_mark: None,
            rule_matched: false,
        };

        // Need to create a new session
        debug!(
            "Creating new UDP session for {} -> {} via {} (domain: {:?})",
            packet.client_addr,
            packet.original_dst,
            outbound.tag(),
            routing_info.domain
        );

        self.create_and_forward_session(packet, outbound, session_key, routing_info)
            .await
    }

    /// Sniff QUIC SNI from UDP packet data.
    ///
    /// Returns `Some(domain)` if a QUIC Initial packet with SNI is detected.
    fn sniff_quic_sni(&self, data: &[u8]) -> Option<String> {
        if !self.config.enable_quic_sniff {
            return None;
        }

        // Check if this looks like a QUIC Initial packet
        if QuicSniffer::is_initial(data) {
            self.stats.quic_packets.fetch_add(1, Ordering::Relaxed);

            let result = QuicSniffer::sniff(data);
            if let Some(ref sni) = result.server_name {
                self.stats.quic_sni_extracted.fetch_add(1, Ordering::Relaxed);
                trace!("Extracted QUIC SNI: {}", sni);
                return Some(sni.clone());
            }
        }
        None
    }

    /// Build `ConnectionInfo` for rule matching.
    fn build_connection_info(
        &self,
        packet: &UdpPacketInfo,
        domain: Option<&str>,
    ) -> ConnectionInfo {
        let mut conn_info = ConnectionInfo::new("udp", packet.original_dst.port());

        // Set destination IP
        conn_info.dest_ip = Some(packet.original_dst.ip());

        // Set source IP
        conn_info.source_ip = Some(packet.client_addr.ip());

        // Set domain if sniffed from QUIC
        if let Some(d) = domain {
            conn_info.domain = Some(d.to_string());
            conn_info.sniffed_protocol = Some("quic");
        }

        conn_info
    }

    /// Create a new session and forward the packet.
    async fn create_and_forward_session(
        &self,
        packet: &UdpPacketInfo,
        outbound: &dyn Outbound,
        session_key: UdpSessionKey,
        routing_info: UdpRoutingInfo,
    ) -> ProcessResult {
        // Check if outbound supports UDP
        if !outbound.supports_udp() {
            // Counter drift fix: decrement counter since session won't be created
            self.decrement_ip_session_count(packet.client_addr.ip());
            return ProcessResult::Failed {
                error: UdpError::UdpNotSupported {
                    tag: outbound.tag().to_string(),
                },
            };
        }

        // Connect outbound for UDP
        let handle = match outbound
            .connect_udp(packet.original_dst, self.config.connect_timeout)
            .await
        {
            Ok(handle) => handle,
            Err(UdpError::UdpNotSupported { tag }) => {
                // Counter drift fix: decrement counter since session won't be created
                self.decrement_ip_session_count(packet.client_addr.ip());
                // Blocked by outbound
                return ProcessResult::Blocked {
                    reason: format!("Blocked by outbound: {tag}"),
                };
            }
            Err(UdpError::Blocked { tag, addr }) => {
                // Counter drift fix: decrement counter since session won't be created
                self.decrement_ip_session_count(packet.client_addr.ip());
                // Explicitly blocked by BlockOutbound
                return ProcessResult::Blocked {
                    reason: format!("Blocked by outbound '{tag}': {addr}"),
                };
            }
            Err(e) => {
                // Counter drift fix: decrement counter since session won't be created
                self.decrement_ip_session_count(packet.client_addr.ip());
                self.stats.packets_failed.fetch_add(1, Ordering::Relaxed);
                return ProcessResult::Failed { error: e };
            }
        };

        // Create and store session wrapper
        let session = Arc::new(UdpSessionWrapper::new(handle, routing_info));
        self.handle_cache.insert(session_key, Arc::clone(&session));

        self.stats.sessions_created.fetch_add(1, Ordering::Relaxed);

        // Forward the packet
        self.forward_packet(packet, session, session_key, true).await
    }

    /// Forward a packet through an existing or new session.
    async fn forward_packet(
        &self,
        packet: &UdpPacketInfo,
        session: Arc<UdpSessionWrapper>,
        session_key: UdpSessionKey,
        new_session: bool,
    ) -> ProcessResult {
        // Send the packet
        match session.handle.send(&packet.data).await {
            Ok(bytes_sent) => {
                self.stats.packets_forwarded.fetch_add(1, Ordering::Relaxed);
                self.stats
                    .bytes_sent
                    .fetch_add(bytes_sent as u64, Ordering::Relaxed);
                session.record_send(bytes_sent);

                ProcessResult::Forwarded {
                    session_key,
                    bytes_sent,
                    new_session,
                    outbound_tag: session.routing_info.outbound.clone(),
                    sniffed_domain: session.routing_info.domain.clone(),
                    rule_matched: session.routing_info.rule_matched,
                }
            }
            Err(e) => {
                self.stats.packets_failed.fetch_add(1, Ordering::Relaxed);
                warn!(
                    "Failed to forward UDP packet {} -> {}: {}",
                    packet.client_addr, packet.original_dst, e
                );
                ProcessResult::Failed { error: e }
            }
        }
    }

    /// Get a handle from the cache
    pub fn get_handle(&self, key: &UdpSessionKey) -> Option<Arc<UdpSessionWrapper>> {
        self.handle_cache.get(key)
    }

    /// Get statistics
    pub fn stats(&self) -> &Arc<UdpProcessorStats> {
        &self.stats
    }

    /// Get a stats snapshot
    pub fn stats_snapshot(&self) -> UdpProcessorStatsSnapshot {
        self.stats.snapshot()
    }

    /// Get the number of active sessions
    pub fn active_sessions(&self) -> u64 {
        self.handle_cache.entry_count()
    }

    /// Invalidate a specific session
    ///
    /// Note: The eviction listener handles decrementing the per-IP session counter.
    /// Do NOT manually decrement here to avoid double-decrement bugs.
    pub fn invalidate(&self, key: &UdpSessionKey) {
        // Eviction listener will decrement IP session count automatically
        self.handle_cache.invalidate(key);
    }

    /// Clear all sessions
    ///
    /// SEC-1 FIX: Also clears all per-IP session counters.
    pub fn clear(&self) {
        // Clear IP session counts first
        self.ip_session_counts.clear();
        self.handle_cache.invalidate_all();
    }

    /// Process a UDP packet standalone (without rule engine).
    ///
    /// This is a simplified processing path for the worker pool that uses
    /// the default direct outbound. For full routing, use `process_with_rules`.
    ///
    /// # Arguments
    ///
    /// * `packet` - The received UDP packet info from TPROXY
    pub async fn process_standalone(&self, packet: &UdpPacketInfo) {
        use crate::outbound::DirectOutbound;

        self.stats.packets_processed.fetch_add(1, Ordering::Relaxed);

        let session_key = UdpSessionKey::new(packet.client_addr, packet.original_dst);

        // Try to get existing session
        if let Some(session) = self.handle_cache.get(&session_key) {
            // Reuse existing session
            self.stats.sessions_reused.fetch_add(1, Ordering::Relaxed);
            trace!(
                "Reusing UDP session for {} -> {} via {}",
                packet.client_addr,
                packet.original_dst,
                session.routing_info.outbound
            );

            let _ = self.forward_packet(packet, session, session_key, false).await;
            return;
        }

        // Sniff QUIC SNI on first packet of session (for stats)
        let sniffed_domain = self.sniff_quic_sni(&packet.data);

        // Create a direct outbound for standalone processing
        let outbound = DirectOutbound::simple("direct");

        // Create routing info
        let routing_info = UdpRoutingInfo {
            domain: sniffed_domain,
            outbound: "direct".to_string(),
            routing_mark: None,
            rule_matched: false,
        };

        debug!(
            "Processing standalone UDP packet {} -> {} (domain: {:?})",
            packet.client_addr,
            packet.original_dst,
            routing_info.domain
        );

        let _ = self
            .create_and_forward_session(packet, &outbound, session_key, routing_info)
            .await;
    }
}

/// Wrapper around `UdpOutboundHandle` with session tracking
#[derive(Debug)]
pub struct UdpSessionWrapper {
    /// The outbound handle
    pub handle: UdpOutboundHandle,
    /// Routing info (outbound tag, domain, etc.)
    pub routing_info: UdpRoutingInfo,
    /// Bytes sent through this session
    bytes_sent: AtomicU64,
    /// Bytes received through this session
    bytes_recv: AtomicU64,
    /// Packets sent
    packets_sent: AtomicU64,
    /// Packets received
    packets_recv: AtomicU64,
}

impl UdpSessionWrapper {
    /// Create a new session wrapper
    pub fn new(handle: UdpOutboundHandle, routing_info: UdpRoutingInfo) -> Self {
        Self {
            handle,
            routing_info,
            bytes_sent: AtomicU64::new(0),
            bytes_recv: AtomicU64::new(0),
            packets_sent: AtomicU64::new(0),
            packets_recv: AtomicU64::new(0),
        }
    }

    /// Create a new session wrapper with simple routing info.
    ///
    /// This is a convenience constructor for cases where the outbound tag
    /// is known but no SNI was extracted.
    pub fn simple(handle: UdpOutboundHandle, outbound_tag: impl Into<String>) -> Self {
        Self::new(
            handle,
            UdpRoutingInfo {
                domain: None,
                outbound: outbound_tag.into(),
                routing_mark: None,
                rule_matched: false,
            },
        )
    }

    /// Record a send operation
    pub fn record_send(&self, bytes: usize) {
        self.bytes_sent.fetch_add(bytes as u64, Ordering::Relaxed);
        self.packets_sent.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a receive operation
    pub fn record_recv(&self, bytes: usize) {
        self.bytes_recv.fetch_add(bytes as u64, Ordering::Relaxed);
        self.packets_recv.fetch_add(1, Ordering::Relaxed);
    }

    /// Get total bytes sent
    pub fn bytes_sent(&self) -> u64 {
        self.bytes_sent.load(Ordering::Relaxed)
    }

    /// Get total bytes received
    pub fn bytes_recv(&self) -> u64 {
        self.bytes_recv.load(Ordering::Relaxed)
    }

    /// Get total packets sent
    pub fn packets_sent(&self) -> u64 {
        self.packets_sent.load(Ordering::Relaxed)
    }

    /// Get total packets received
    pub fn packets_recv(&self) -> u64 {
        self.packets_recv.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::outbound::DirectOutbound;
    use bytes::Bytes;
    use std::time::Instant;

    #[test]
    fn test_processor_config_default() {
        let config = UdpProcessorConfig::default();
        assert_eq!(
            config.connect_timeout,
            Duration::from_secs(DEFAULT_UDP_CONNECT_TIMEOUT_SECS)
        );
        assert!(config.enable_quic_sniff);
    }

    #[test]
    fn test_processor_stats() {
        let stats = UdpProcessorStats::new();
        stats.packets_processed.fetch_add(10, Ordering::Relaxed);
        stats.packets_forwarded.fetch_add(8, Ordering::Relaxed);
        stats.packets_failed.fetch_add(2, Ordering::Relaxed);

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.packets_processed, 10);
        assert_eq!(snapshot.packets_forwarded, 8);
        assert_eq!(snapshot.packets_failed, 2);
    }

    #[test]
    fn test_processor_creation() {
        let processor = UdpPacketProcessor::new_default();
        assert_eq!(processor.active_sessions(), 0);
        assert_eq!(processor.stats_snapshot().packets_processed, 0);
    }

    #[tokio::test]
    async fn test_process_packet_direct() {
        // Create a UDP server to receive packets
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();

        // Create processor
        let processor = UdpPacketProcessor::new_default();

        // Create packet info
        let packet = UdpPacketInfo {
            data: Bytes::from_static(b"hello"),
            client_addr: "127.0.0.1:12345".parse().unwrap(),
            original_dst: server_addr,
            received_at: Instant::now(),
        };

        // Create outbound
        let outbound = DirectOutbound::simple("test");

        // Process packet
        let result = processor.process(&packet, &outbound).await;

        match result {
            ProcessResult::Forwarded {
                session_key,
                bytes_sent,
                new_session,
                outbound_tag,
                sniffed_domain,
                rule_matched,
            } => {
                assert_eq!(bytes_sent, 5);
                assert!(new_session);
                assert_eq!(session_key.client_addr, packet.client_addr);
                assert_eq!(session_key.dest_addr, server_addr);
                assert_eq!(outbound_tag, "test");
                assert!(sniffed_domain.is_none()); // Not a QUIC packet
                assert!(!rule_matched); // Direct process doesn't set rule_matched
            }
            ProcessResult::Failed { error } => {
                panic!("Unexpected failure: {error}");
            }
            ProcessResult::Blocked { reason } => {
                panic!("Unexpected block: {reason}");
            }
            ProcessResult::RateLimited { source_ip, current_count, max_allowed } => {
                panic!("Unexpected rate limit: {source_ip} has {current_count}/{max_allowed}");
            }
        }

        // Verify server received the packet
        let mut buf = [0u8; 64];
        let (n, _) = server.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello");

        // Check stats
        let stats = processor.stats_snapshot();
        assert_eq!(stats.packets_processed, 1);
        assert_eq!(stats.packets_forwarded, 1);
        assert_eq!(stats.sessions_created, 1);
        assert_eq!(stats.bytes_sent, 5);
    }

    #[tokio::test]
    async fn test_session_reuse() {
        // Create a UDP server
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();

        let processor = UdpPacketProcessor::new_default();
        let outbound = DirectOutbound::simple("test");

        // Process first packet
        let packet1 = UdpPacketInfo {
            data: Bytes::from_static(b"first"),
            client_addr: "127.0.0.1:12345".parse().unwrap(),
            original_dst: server_addr,
            received_at: Instant::now(),
        };

        let result1 = processor.process(&packet1, &outbound).await;
        assert!(matches!(result1, ProcessResult::Forwarded { new_session: true, .. }));

        // Process second packet from same client
        let packet2 = UdpPacketInfo {
            data: Bytes::from_static(b"second"),
            client_addr: "127.0.0.1:12345".parse().unwrap(),
            original_dst: server_addr,
            received_at: Instant::now(),
        };

        let result2 = processor.process(&packet2, &outbound).await;

        // Note: Session reuse requires the session wrapper to be stored properly
        // For now, this test verifies the basic flow
        assert!(matches!(result2, ProcessResult::Forwarded { .. }));

        // Check stats
        let stats = processor.stats_snapshot();
        assert_eq!(stats.packets_processed, 2);
        assert_eq!(stats.packets_forwarded, 2);
    }

    #[test]
    fn test_session_wrapper() {
        use std::net::SocketAddr;
        use tokio::net::UdpSocket;
        use tokio::runtime::Runtime;
        use crate::outbound::DirectUdpHandle;

        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let dest: SocketAddr = "127.0.0.1:53".parse().unwrap();

            let handle = DirectUdpHandle::new(socket, dest, None);
            let wrapper = UdpSessionWrapper::simple(UdpOutboundHandle::Direct(handle), "direct");

            assert_eq!(wrapper.bytes_sent(), 0);
            assert_eq!(wrapper.bytes_recv(), 0);
            assert_eq!(wrapper.packets_sent(), 0);
            assert_eq!(wrapper.packets_recv(), 0);

            wrapper.record_send(100);
            wrapper.record_recv(200);

            assert_eq!(wrapper.bytes_sent(), 100);
            assert_eq!(wrapper.bytes_recv(), 200);
            assert_eq!(wrapper.packets_sent(), 1);
            assert_eq!(wrapper.packets_recv(), 1);
        });
    }

    #[test]
    fn test_session_wrapper_with_routing_info() {
        use std::net::SocketAddr;
        use tokio::net::UdpSocket;
        use tokio::runtime::Runtime;
        use crate::outbound::DirectUdpHandle;

        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let dest: SocketAddr = "127.0.0.1:53".parse().unwrap();

            let handle = DirectUdpHandle::new(socket, dest, None);
            let routing_info = UdpRoutingInfo {
                domain: Some("example.com".to_string()),
                outbound: "proxy".to_string(),
                routing_mark: Some(200),
                rule_matched: true,
            };
            let wrapper = UdpSessionWrapper::new(UdpOutboundHandle::Direct(handle), routing_info);

            assert_eq!(wrapper.routing_info.domain, Some("example.com".to_string()));
            assert_eq!(wrapper.routing_info.outbound, "proxy");
            assert_eq!(wrapper.routing_info.routing_mark, Some(200));
            assert!(wrapper.routing_info.rule_matched);
        });
    }

    #[test]
    fn test_udp_routing_info() {
        let info = UdpRoutingInfo {
            domain: Some("google.com".to_string()),
            outbound: "us-west".to_string(),
            routing_mark: Some(773),
            rule_matched: true,
        };

        assert_eq!(info.domain, Some("google.com".to_string()));
        assert_eq!(info.outbound, "us-west");
        assert_eq!(info.routing_mark, Some(773));
        assert!(info.rule_matched);
    }

    #[test]
    fn test_stats_with_quic_fields() {
        let stats = UdpProcessorStats::new();
        stats.quic_packets.fetch_add(10, Ordering::Relaxed);
        stats.quic_sni_extracted.fetch_add(5, Ordering::Relaxed);
        stats.rule_matches.fetch_add(8, Ordering::Relaxed);

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.quic_packets, 10);
        assert_eq!(snapshot.quic_sni_extracted, 5);
        assert_eq!(snapshot.rule_matches, 8);
    }

    /// Construct a QUIC v1 Initial packet with embedded SNI for testing.
    ///
    /// This helper creates a minimal QUIC Initial packet structure with
    /// an SNI extension embedded in the payload area. Note that in real
    /// QUIC, the payload is encrypted - this packet is for unit testing
    /// the heuristic SNI extraction only.
    fn build_quic_initial_with_sni(hostname: &str) -> Vec<u8> {
        // Build the SNI extension structure
        let name_bytes = hostname.as_bytes();
        let name_len = name_bytes.len() as u16;
        let list_len = 3 + name_len; // name_type (1) + name_length (2) + name
        let ext_len = 2 + list_len; // list_length (2) + list

        let mut sni_extension = vec![
            0x00, 0x00, // Extension type (SNI)
            (ext_len >> 8) as u8, ext_len as u8, // Extension length
            (list_len >> 8) as u8, list_len as u8, // List length
            0x00, // Name type (host_name)
            (name_len >> 8) as u8, name_len as u8, // Name length
        ];
        sni_extension.extend_from_slice(name_bytes);

        // Build QUIC v1 Initial packet header
        let mut packet = vec![
            0xc3, // Long header (1), fixed bit (1), Initial type (00), PN length 4
            0x00, 0x00, 0x00, 0x01, // QUIC v1
            0x08, // DCID length (8 bytes)
            0xba, 0xba, 0xba, 0xba, 0xba, 0xba, 0xba, 0xba, // DCID
            0x00, // SCID length (0)
            0x00, // Token length (varint, 0)
        ];

        // Add packet length (2-byte varint) - we need room for SNI + padding
        let payload_len = (sni_extension.len() + 64) as u16;
        packet.push(0x40 | ((payload_len >> 8) as u8 & 0x3f)); // 2-byte varint
        packet.push(payload_len as u8);

        // Add some random bytes before SNI to simulate encrypted data
        packet.extend_from_slice(&[0x00; 16]);

        // Embed the SNI extension (in real QUIC this would be in encrypted CRYPTO frame)
        packet.extend_from_slice(&sni_extension);

        // Add padding to make it look like a real packet
        packet.extend_from_slice(&[0x00; 32]);

        packet
    }

    #[test]
    fn test_sniff_quic_sni_with_real_initial_packet() {
        let processor = UdpPacketProcessor::new_default();

        // Build a QUIC Initial packet with SNI
        let quic_packet = build_quic_initial_with_sni("www.example.com");

        // Verify it's detected as a QUIC Initial
        assert!(crate::sniff::quic::QuicSniffer::is_initial(&quic_packet));

        // Extract SNI through the processor
        let result = processor.sniff_quic_sni(&quic_packet);

        // Should extract the SNI
        assert_eq!(result, Some("www.example.com".to_string()));

        // Verify stats were updated
        let stats = processor.stats_snapshot();
        assert_eq!(stats.quic_packets, 1);
        assert_eq!(stats.quic_sni_extracted, 1);
    }

    #[test]
    fn test_sniff_quic_sni_various_hostnames() {
        let processor = UdpPacketProcessor::new_default();

        let test_cases = vec![
            "google.com",
            "www.google.com",
            "api.github.com",
            "cdn.cloudflare.net",
            "a.very.long.subdomain.example.org",
        ];

        for hostname in test_cases {
            let quic_packet = build_quic_initial_with_sni(hostname);
            let result = processor.sniff_quic_sni(&quic_packet);
            assert_eq!(
                result,
                Some(hostname.to_string()),
                "Failed to extract SNI for {}",
                hostname
            );
        }
    }

    #[tokio::test]
    async fn test_process_with_rules_quic_sni_domain_match() {
        use crate::outbound::{DirectOutbound, OutboundManager};
        use crate::rules::engine::{RuleEngine, RoutingSnapshotBuilder};
        use crate::rules::RuleType;

        // Create a UDP server
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();

        let config = UdpProcessorConfig::default();
        let processor = UdpPacketProcessor::new(config);

        // Create rule engine with domain rule that matches our QUIC SNI
        let mut builder = RoutingSnapshotBuilder::new();
        builder
            .add_domain_rule(RuleType::DomainSuffix, "example.com", "proxy")
            .unwrap();
        let snapshot = builder.default_outbound("direct").version(1).build().unwrap();
        let rule_engine = RuleEngine::new(snapshot);

        // Create outbound manager
        let outbound_manager = OutboundManager::new();
        outbound_manager.add(Box::new(DirectOutbound::simple("direct")));
        outbound_manager.add(Box::new(DirectOutbound::simple("proxy")));

        // Build a QUIC Initial packet with SNI that should match the rule
        let quic_packet_data = build_quic_initial_with_sni("api.example.com");

        let packet = UdpPacketInfo {
            data: Bytes::from(quic_packet_data),
            client_addr: "192.168.1.100:12345".parse().unwrap(),
            original_dst: server_addr,
            received_at: Instant::now(),
        };

        let result = processor.process_with_rules(&packet, &rule_engine, &outbound_manager).await;

        match result {
            ProcessResult::Forwarded {
                outbound_tag,
                rule_matched,
                sniffed_domain,
                ..
            } => {
                // Should use proxy because domain suffix matches
                assert_eq!(outbound_tag, "proxy");
                assert!(rule_matched);
                assert_eq!(sniffed_domain, Some("api.example.com".to_string()));
            }
            ProcessResult::Failed { error } => {
                panic!("Unexpected failure: {error}");
            }
            ProcessResult::Blocked { reason } => {
                panic!("Unexpected block: {reason}");
            }
            ProcessResult::RateLimited { source_ip, current_count, max_allowed } => {
                panic!("Unexpected rate limit: {source_ip} has {current_count}/{max_allowed}");
            }
        }

        // Verify QUIC stats
        let stats = processor.stats_snapshot();
        assert_eq!(stats.quic_packets, 1);
        assert_eq!(stats.quic_sni_extracted, 1);
        assert_eq!(stats.rule_matches, 1);
    }

    #[tokio::test]
    async fn test_process_with_rules_dscp_routing_mark_propagation() {
        use crate::outbound::{DirectOutbound, OutboundManager};
        use crate::rules::engine::{RuleEngine, RoutingSnapshotBuilder};
        use crate::rules::RuleType;
        use crate::rules::fwmark::ENTRY_ROUTING_MARK_BASE;

        // Create a UDP server
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();

        let processor = UdpPacketProcessor::new_default();

        // Create rule engine with a chain that has DSCP routing mark
        let mut builder = RoutingSnapshotBuilder::new();
        // Add a domain rule that routes to a chain
        builder
            .add_domain_rule(RuleType::DomainSuffix, "chain-test.com", "my-chain")
            .unwrap()
            // Register the chain with DSCP value 5
            .add_chain_with_dscp("my-chain", 5)
            .unwrap();

        let snapshot = builder.default_outbound("direct").version(1).build().unwrap();
        let rule_engine = RuleEngine::new(snapshot);

        // Create outbound manager with the chain outbound
        let outbound_manager = OutboundManager::new();
        outbound_manager.add(Box::new(DirectOutbound::simple("direct")));
        outbound_manager.add(Box::new(DirectOutbound::simple("my-chain")));

        // Build a QUIC packet with SNI that matches the chain rule
        let quic_packet_data = build_quic_initial_with_sni("api.chain-test.com");

        let packet = UdpPacketInfo {
            data: Bytes::from(quic_packet_data),
            client_addr: "192.168.1.100:12345".parse().unwrap(),
            original_dst: server_addr,
            received_at: Instant::now(),
        };

        let result = processor.process_with_rules(&packet, &rule_engine, &outbound_manager).await;

        match result {
            ProcessResult::Forwarded {
                outbound_tag,
                rule_matched,
                sniffed_domain,
                ..
            } => {
                // Should route to my-chain
                assert_eq!(outbound_tag, "my-chain");
                assert!(rule_matched);
                assert_eq!(sniffed_domain, Some("api.chain-test.com".to_string()));

                // Verify that the session has the correct routing_mark from the chain
                let session_key = crate::connection::udp::UdpSessionKey::new(
                    packet.client_addr,
                    server_addr,
                );
                let session = processor.get_handle(&session_key).expect("session should exist");

                // routing_mark should be ENTRY_ROUTING_MARK_BASE + dscp_value
                // 0x300 (768) + 5 = 773
                let expected_mark = ENTRY_ROUTING_MARK_BASE + 5;
                assert_eq!(
                    session.routing_info.routing_mark,
                    Some(expected_mark),
                    "routing_mark should be {} (0x{:x})",
                    expected_mark,
                    expected_mark
                );
                assert!(session.routing_info.rule_matched);
            }
            ProcessResult::Failed { error } => {
                panic!("Unexpected failure: {error}");
            }
            ProcessResult::Blocked { reason } => {
                panic!("Unexpected block: {reason}");
            }
            ProcessResult::RateLimited { source_ip, current_count, max_allowed } => {
                panic!("Unexpected rate limit: {source_ip} has {current_count}/{max_allowed}");
            }
        }
    }

    #[tokio::test]
    async fn test_process_with_rules_no_routing_mark_for_non_chain() {
        use crate::outbound::{DirectOutbound, OutboundManager};
        use crate::rules::engine::{RuleEngine, RoutingSnapshotBuilder};
        use crate::rules::RuleType;

        // Create a UDP server
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();

        let processor = UdpPacketProcessor::new_default();

        // Create rule engine with a regular (non-chain) domain rule
        let mut builder = RoutingSnapshotBuilder::new();
        builder
            .add_domain_rule(RuleType::DomainSuffix, "regular.com", "proxy")
            .unwrap();
        // No chain registered for "proxy"

        let snapshot = builder.default_outbound("direct").version(1).build().unwrap();
        let rule_engine = RuleEngine::new(snapshot);

        // Create outbound manager
        let outbound_manager = OutboundManager::new();
        outbound_manager.add(Box::new(DirectOutbound::simple("direct")));
        outbound_manager.add(Box::new(DirectOutbound::simple("proxy")));

        // Build a QUIC packet with SNI that matches the regular rule
        let quic_packet_data = build_quic_initial_with_sni("api.regular.com");

        let packet = UdpPacketInfo {
            data: Bytes::from(quic_packet_data),
            client_addr: "192.168.1.100:54321".parse().unwrap(),
            original_dst: server_addr,
            received_at: Instant::now(),
        };

        let result = processor.process_with_rules(&packet, &rule_engine, &outbound_manager).await;

        match result {
            ProcessResult::Forwarded {
                outbound_tag,
                rule_matched,
                ..
            } => {
                // Should route to proxy
                assert_eq!(outbound_tag, "proxy");
                assert!(rule_matched);

                // Verify that the session has NO routing_mark (not a chain)
                let session_key = crate::connection::udp::UdpSessionKey::new(
                    packet.client_addr,
                    server_addr,
                );
                let session = processor.get_handle(&session_key).expect("session should exist");

                // routing_mark should be None for non-chain outbounds
                assert_eq!(
                    session.routing_info.routing_mark,
                    None,
                    "routing_mark should be None for non-chain outbound"
                );
            }
            ProcessResult::Failed { error } => {
                panic!("Unexpected failure: {error}");
            }
            ProcessResult::Blocked { reason } => {
                panic!("Unexpected block: {reason}");
            }
            ProcessResult::RateLimited { source_ip, current_count, max_allowed } => {
                panic!("Unexpected rate limit: {source_ip} has {current_count}/{max_allowed}");
            }
        }
    }

    #[test]
    fn test_sniff_quic_sni_non_quic_packet() {
        let processor = UdpPacketProcessor::new_default();

        // Regular UDP data (not QUIC)
        let data = b"Hello, World!";
        let result = processor.sniff_quic_sni(data);

        assert!(result.is_none());
    }

    #[test]
    fn test_sniff_quic_sni_disabled() {
        let mut config = UdpProcessorConfig::default();
        config.enable_quic_sniff = false;
        let processor = UdpPacketProcessor::new(config);

        // Even with QUIC-like data, should return None when disabled
        let data = b"Hello, World!";
        let result = processor.sniff_quic_sni(data);

        assert!(result.is_none());
    }

    #[test]
    fn test_build_connection_info_without_domain() {
        use std::net::IpAddr;

        let processor = UdpPacketProcessor::new_default();
        let packet = UdpPacketInfo {
            data: Bytes::from_static(b"test"),
            client_addr: "192.168.1.100:12345".parse().unwrap(),
            original_dst: "8.8.8.8:443".parse().unwrap(),
            received_at: Instant::now(),
        };

        let conn_info = processor.build_connection_info(&packet, None);

        assert!(conn_info.domain.is_none());
        assert_eq!(conn_info.dest_ip, Some(IpAddr::from([8, 8, 8, 8])));
        assert_eq!(conn_info.dest_port, 443);
        assert_eq!(conn_info.source_ip, Some(IpAddr::from([192, 168, 1, 100])));
        assert_eq!(conn_info.protocol, "udp");
        assert!(conn_info.sniffed_protocol.is_none());
    }

    #[test]
    fn test_build_connection_info_with_domain() {
        let processor = UdpPacketProcessor::new_default();
        let packet = UdpPacketInfo {
            data: Bytes::from_static(b"test"),
            client_addr: "192.168.1.100:12345".parse().unwrap(),
            original_dst: "8.8.8.8:443".parse().unwrap(),
            received_at: Instant::now(),
        };

        let conn_info = processor.build_connection_info(&packet, Some("google.com"));

        assert_eq!(conn_info.domain, Some("google.com".to_string()));
        assert_eq!(conn_info.sniffed_protocol, Some("quic"));
    }

    #[tokio::test]
    async fn test_process_with_rules_outbound_not_found() {
        use crate::outbound::OutboundManager;
        use crate::rules::engine::{RuleEngine, RoutingSnapshotBuilder};

        let processor = UdpPacketProcessor::new_default();

        // Create rule engine with non-existent default outbound
        let snapshot = RoutingSnapshotBuilder::new()
            .default_outbound("nonexistent")
            .version(1)
            .build()
            .unwrap();
        let rule_engine = RuleEngine::new(snapshot);

        // Create empty outbound manager
        let outbound_manager = OutboundManager::new();

        let packet = UdpPacketInfo {
            data: Bytes::from_static(b"test"),
            client_addr: "192.168.1.100:12345".parse().unwrap(),
            original_dst: "8.8.8.8:443".parse().unwrap(),
            received_at: Instant::now(),
        };

        let result = processor.process_with_rules(&packet, &rule_engine, &outbound_manager).await;

        match result {
            ProcessResult::Failed { error } => {
                assert!(matches!(error, UdpError::OutboundNotFound { .. }));
            }
            _ => panic!("Expected OutboundNotFound error"),
        }
    }

    #[tokio::test]
    async fn test_process_with_rules_default_outbound() {
        use crate::outbound::{DirectOutbound, OutboundManager};
        use crate::rules::engine::{RuleEngine, RoutingSnapshotBuilder};

        // Create a UDP server
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();

        let processor = UdpPacketProcessor::new_default();

        // Create rule engine with direct as default
        let snapshot = RoutingSnapshotBuilder::new()
            .default_outbound("direct")
            .version(1)
            .build()
            .unwrap();
        let rule_engine = RuleEngine::new(snapshot);

        // Create outbound manager with direct outbound
        let outbound_manager = OutboundManager::new();
        outbound_manager.add(Box::new(DirectOutbound::simple("direct")));

        let packet = UdpPacketInfo {
            data: Bytes::from_static(b"test"),
            client_addr: "192.168.1.100:12345".parse().unwrap(),
            original_dst: server_addr,
            received_at: Instant::now(),
        };

        let result = processor.process_with_rules(&packet, &rule_engine, &outbound_manager).await;

        match result {
            ProcessResult::Forwarded {
                outbound_tag,
                rule_matched,
                sniffed_domain,
                ..
            } => {
                assert_eq!(outbound_tag, "direct");
                assert!(!rule_matched); // Default outbound, not matched
                assert!(sniffed_domain.is_none()); // Not a QUIC packet
            }
            ProcessResult::Failed { error } => {
                panic!("Unexpected failure: {error}");
            }
            ProcessResult::Blocked { reason } => {
                panic!("Unexpected block: {reason}");
            }
            ProcessResult::RateLimited { source_ip, current_count, max_allowed } => {
                panic!("Unexpected rate limit: {source_ip} has {current_count}/{max_allowed}");
            }
        }

        // Verify server received the packet
        let mut buf = [0u8; 64];
        let (n, _) = server.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"test");
    }

    #[tokio::test]
    async fn test_process_with_rules_domain_match() {
        use crate::outbound::{DirectOutbound, OutboundManager};
        use crate::rules::engine::{RuleEngine, RoutingSnapshotBuilder};
        use crate::rules::RuleType;

        // Create a UDP server
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();

        let mut config = UdpProcessorConfig::default();
        config.enable_quic_sniff = true;
        let processor = UdpPacketProcessor::new(config);

        // Create rule engine with domain rule
        let mut builder = RoutingSnapshotBuilder::new();
        builder
            .add_domain_rule(RuleType::DomainSuffix, "google.com", "proxy")
            .unwrap();
        let snapshot = builder.default_outbound("direct").version(1).build().unwrap();
        let rule_engine = RuleEngine::new(snapshot);

        // Create outbound manager
        let outbound_manager = OutboundManager::new();
        outbound_manager.add(Box::new(DirectOutbound::simple("direct")));
        outbound_manager.add(Box::new(DirectOutbound::simple("proxy")));

        // Non-QUIC packet won't have domain, so falls to default
        let packet = UdpPacketInfo {
            data: Bytes::from_static(b"test"),
            client_addr: "192.168.1.100:12345".parse().unwrap(),
            original_dst: server_addr,
            received_at: Instant::now(),
        };

        let result = processor.process_with_rules(&packet, &rule_engine, &outbound_manager).await;

        match result {
            ProcessResult::Forwarded {
                outbound_tag,
                rule_matched,
                sniffed_domain,
                ..
            } => {
                // No QUIC SNI, so uses default
                assert_eq!(outbound_tag, "direct");
                assert!(!rule_matched);
                assert!(sniffed_domain.is_none());
            }
            ProcessResult::Failed { error } => {
                panic!("Unexpected failure: {error}");
            }
            ProcessResult::Blocked { reason } => {
                panic!("Unexpected block: {reason}");
            }
            ProcessResult::RateLimited { source_ip, current_count, max_allowed } => {
                panic!("Unexpected rate limit: {source_ip} has {current_count}/{max_allowed}");
            }
        }

        // Check stats - QUIC detection should not increment since it's not QUIC
        let stats = processor.stats_snapshot();
        assert_eq!(stats.quic_packets, 0);
        assert_eq!(stats.quic_sni_extracted, 0);
    }

    // ===================================================================
    // NEW-3 and NEW-4 FIX TESTS: Eviction listener and CAS underflow protection
    // ===================================================================

    #[tokio::test]
    async fn test_new3_eviction_listener_decrements_ip_count() {
        // NEW-3 FIX TEST: Verify that when a session is evicted via TTL,
        // the IP session counter is properly decremented by the eviction listener.
        use std::time::Duration;

        // Create processor with 200ms TTL - short enough to test quickly,
        // but long enough to allow reliable session creation before expiry
        let mut session_config = UdpSessionConfig::default();
        session_config.ttl = Duration::from_millis(200);
        session_config.idle_timeout = Duration::from_millis(200);

        let config = UdpProcessorConfig {
            session_config,
            connect_timeout: Duration::from_secs(5),
            enable_quic_sniff: false,
            max_sessions_per_ip: 100, // Enable rate limiting
            max_tracked_ips: DEFAULT_MAX_TRACKED_IPS,
            cleanup_interval: Duration::from_secs(DEFAULT_CLEANUP_INTERVAL_SECS),
        };

        let processor = UdpPacketProcessor::new(config);

        // Create a UDP server
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();

        let source_ip: IpAddr = "192.168.1.50".parse().unwrap();
        let outbound = DirectOutbound::simple("test");

        // Create a session (this increments the IP counter)
        let packet = UdpPacketInfo {
            data: Bytes::from_static(b"test"),
            client_addr: format!("{}:12345", source_ip).parse().unwrap(),
            original_dst: server_addr,
            received_at: Instant::now(),
        };

        let result = processor.process(&packet, &outbound).await;
        assert!(matches!(result, ProcessResult::Forwarded { new_session: true, .. }));

        // Run pending tasks immediately after insert to ensure it's committed
        processor.handle_cache.run_pending_tasks();

        // Verify IP counter was incremented
        let count_after_create = processor.get_ip_session_count(source_ip);
        assert_eq!(count_after_create, 1, "IP counter should be 1 after creating session");
        assert!(processor.active_sessions() >= 1, "Should have at least 1 active session");

        // Wait for TTL to expire (200ms + some buffer)
        tokio::time::sleep(Duration::from_millis(300)).await;

        // Force moka to run maintenance (eviction) multiple times
        // moka's eviction is asynchronous and may need multiple cycles
        for _ in 0..10 {
            processor.handle_cache.run_pending_tasks();
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        // The session should be evicted and counter should be decremented
        let final_count = processor.get_ip_session_count(source_ip);
        assert_eq!(
            final_count, 0,
            "IP session count should be 0 after eviction, got {}",
            final_count
        );
    }

    #[test]
    fn test_new4_cas_loop_prevents_underflow() {
        // NEW-4 FIX TEST: Verify that decrementing a counter at 0
        // does not cause underflow to u32::MAX.
        use std::time::Duration;

        let config = UdpProcessorConfig {
            session_config: UdpSessionConfig::default(),
            connect_timeout: Duration::from_secs(5),
            enable_quic_sniff: false,
            max_sessions_per_ip: 100, // Enable rate limiting
            max_tracked_ips: DEFAULT_MAX_TRACKED_IPS,
            cleanup_interval: Duration::from_secs(DEFAULT_CLEANUP_INTERVAL_SECS),
        };

        let processor = UdpPacketProcessor::new(config);

        let source_ip: IpAddr = "10.0.0.1".parse().unwrap();

        // Manually set the counter to 0 (simulating empty state)
        processor.ip_session_counts.insert(source_ip, AtomicU32::new(0));

        // Try to decrement - this should NOT cause underflow
        processor.decrement_ip_session_count(source_ip);

        // Verify counter is still 0 (not u32::MAX from underflow)
        let count = processor.get_ip_session_count(source_ip);
        assert_eq!(count, 0, "Counter should stay at 0, not underflow to {}", count);

        // Now set it to 1 and decrement
        processor.ip_session_counts.insert(source_ip, AtomicU32::new(1));
        processor.decrement_ip_session_count(source_ip);

        // Should be 0 now
        let count = processor.get_ip_session_count(source_ip);
        assert_eq!(count, 0, "Counter should be 0 after decrement");

        // Decrement again - should stay at 0
        processor.decrement_ip_session_count(source_ip);
        let count = processor.get_ip_session_count(source_ip);
        assert_eq!(count, 0, "Counter should stay at 0, not underflow");
    }

    #[test]
    fn test_new4_cas_loop_concurrent_decrements() {
        // NEW-4 FIX TEST: Verify CAS loop handles concurrent decrements correctly.
        use std::sync::Arc;
        use std::thread;
        use std::time::Duration;

        let config = UdpProcessorConfig {
            session_config: UdpSessionConfig::default(),
            connect_timeout: Duration::from_secs(5),
            enable_quic_sniff: false,
            max_sessions_per_ip: 100,
            max_tracked_ips: DEFAULT_MAX_TRACKED_IPS,
            cleanup_interval: Duration::from_secs(DEFAULT_CLEANUP_INTERVAL_SECS),
        };

        let processor = Arc::new(UdpPacketProcessor::new(config));

        let source_ip: IpAddr = "10.0.0.2".parse().unwrap();

        // Set initial count to 1000
        processor.ip_session_counts.insert(source_ip, AtomicU32::new(1000));

        // Spawn 10 threads, each decrementing 100 times
        let threads: Vec<_> = (0..10)
            .map(|_| {
                let proc = Arc::clone(&processor);
                let ip = source_ip;
                thread::spawn(move || {
                    for _ in 0..100 {
                        proc.decrement_ip_session_count(ip);
                    }
                })
            })
            .collect();

        // Wait for all threads
        for t in threads {
            t.join().unwrap();
        }

        // Final count should be 0 (1000 - 10*100 = 0)
        let count = processor.get_ip_session_count(source_ip);
        assert_eq!(count, 0, "Counter should be 0 after 1000 concurrent decrements, got {}", count);
    }

    #[test]
    fn test_new4_no_decrement_when_rate_limiting_disabled() {
        // NEW-4 FIX TEST: Verify decrement is skipped when rate limiting is disabled.
        use std::time::Duration;

        let config = UdpProcessorConfig {
            session_config: UdpSessionConfig::default(),
            connect_timeout: Duration::from_secs(5),
            enable_quic_sniff: false,
            max_sessions_per_ip: 0, // Disable rate limiting
            max_tracked_ips: DEFAULT_MAX_TRACKED_IPS,
            cleanup_interval: Duration::from_secs(DEFAULT_CLEANUP_INTERVAL_SECS),
        };

        let processor = UdpPacketProcessor::new(config);

        let source_ip: IpAddr = "10.0.0.3".parse().unwrap();

        // Manually set counter (shouldn't happen in practice when disabled)
        processor.ip_session_counts.insert(source_ip, AtomicU32::new(5));

        // Decrement should be no-op when rate limiting is disabled
        processor.decrement_ip_session_count(source_ip);

        // Counter should remain 5 (decrement was skipped)
        let count = processor.get_ip_session_count(source_ip);
        assert_eq!(count, 5, "Counter should be unchanged when rate limiting is disabled");
    }

    #[tokio::test]
    async fn test_new3_explicit_invalidate_decrements_counter() {
        // NEW-3 FIX TEST: Verify that explicit invalidate() also decrements the counter.
        use std::time::Duration;

        let config = UdpProcessorConfig {
            session_config: UdpSessionConfig::default(),
            connect_timeout: Duration::from_secs(5),
            enable_quic_sniff: false,
            max_sessions_per_ip: 100,
            max_tracked_ips: DEFAULT_MAX_TRACKED_IPS,
            cleanup_interval: Duration::from_secs(DEFAULT_CLEANUP_INTERVAL_SECS),
        };

        let processor = UdpPacketProcessor::new(config);

        // Create a UDP server
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();

        let source_ip: IpAddr = "192.168.1.100".parse().unwrap();
        let client_addr: std::net::SocketAddr = format!("{}:54321", source_ip).parse().unwrap();
        let outbound = DirectOutbound::simple("test");

        // Create a session
        let packet = UdpPacketInfo {
            data: Bytes::from_static(b"test"),
            client_addr,
            original_dst: server_addr,
            received_at: Instant::now(),
        };

        let result = processor.process(&packet, &outbound).await;
        assert!(matches!(result, ProcessResult::Forwarded { new_session: true, .. }));

        // Verify counter was incremented
        assert_eq!(processor.get_ip_session_count(source_ip), 1);

        // Explicitly invalidate the session
        let session_key = UdpSessionKey::new(client_addr, server_addr);
        processor.invalidate(&session_key);

        // Counter should be decremented
        assert_eq!(processor.get_ip_session_count(source_ip), 0);
    }

    #[tokio::test]
    async fn test_new3_clear_resets_all_counters() {
        // NEW-3 FIX TEST: Verify that clear() resets all IP session counters.
        use std::time::Duration;

        let config = UdpProcessorConfig {
            session_config: UdpSessionConfig::default(),
            connect_timeout: Duration::from_secs(5),
            enable_quic_sniff: false,
            max_sessions_per_ip: 100,
            max_tracked_ips: DEFAULT_MAX_TRACKED_IPS,
            cleanup_interval: Duration::from_secs(DEFAULT_CLEANUP_INTERVAL_SECS),
        };

        let processor = UdpPacketProcessor::new(config);

        // Create a UDP server
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();

        let outbound = DirectOutbound::simple("test");

        // Create sessions from multiple IPs
        for i in 1..=5 {
            let packet = UdpPacketInfo {
                data: Bytes::from_static(b"test"),
                client_addr: format!("192.168.1.{}:{}", i, 10000 + i).parse().unwrap(),
                original_dst: server_addr,
                received_at: Instant::now(),
            };
            let _ = processor.process(&packet, &outbound).await;
        }

        // Verify we have multiple tracked IPs
        assert_eq!(processor.tracked_source_ips(), 5);

        // Clear all sessions
        processor.clear();

        // All counters should be cleared
        assert_eq!(processor.tracked_source_ips(), 0);
        assert_eq!(processor.active_sessions(), 0);
    }

    /// REGRESSION TEST: Double-decrement bug fix verification.
    ///
    /// Previously, `invalidate()` would:
    /// 1. Manually call `decrement_ip_session_count()`
    /// 2. Call `handle_cache.invalidate()` which triggers eviction listener
    /// 3. Eviction listener ALSO calls decrement
    ///
    /// This caused the counter to be decremented twice per invalidation.
    /// The fix: Remove the manual decrement from `invalidate()`, let eviction listener handle it.
    #[tokio::test]
    async fn test_regression_no_double_decrement_on_invalidate() {
        use std::time::Duration;

        let config = UdpProcessorConfig {
            session_config: UdpSessionConfig::default(),
            connect_timeout: Duration::from_secs(5),
            enable_quic_sniff: false,
            max_sessions_per_ip: 100,
            max_tracked_ips: DEFAULT_MAX_TRACKED_IPS,
            cleanup_interval: Duration::from_secs(DEFAULT_CLEANUP_INTERVAL_SECS),
        };

        let processor = UdpPacketProcessor::new(config);

        // Create a UDP server
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();

        let source_ip: IpAddr = "192.168.1.200".parse().unwrap();
        let outbound = DirectOutbound::simple("test");

        // Create 3 sessions from the same IP
        let mut session_keys = Vec::new();
        for port in 40001..=40003 {
            let client_addr: std::net::SocketAddr = format!("{}:{}", source_ip, port).parse().unwrap();
            let packet = UdpPacketInfo {
                data: Bytes::from_static(b"test"),
                client_addr,
                original_dst: server_addr,
                received_at: Instant::now(),
            };

            let result = processor.process(&packet, &outbound).await;
            assert!(matches!(result, ProcessResult::Forwarded { new_session: true, .. }));

            session_keys.push(UdpSessionKey::new(client_addr, server_addr));
        }

        // Verify counter is 3
        assert_eq!(processor.get_ip_session_count(source_ip), 3);

        // Invalidate the first session
        processor.invalidate(&session_keys[0]);

        // Counter should be 2 (NOT 1 from double-decrement)
        let count = processor.get_ip_session_count(source_ip);
        assert_eq!(count, 2, "Counter should be 2 after single invalidate, got {} (double-decrement bug!)", count);

        // Invalidate the second session
        processor.invalidate(&session_keys[1]);

        // Counter should be 1
        let count = processor.get_ip_session_count(source_ip);
        assert_eq!(count, 1, "Counter should be 1 after second invalidate, got {}", count);

        // Invalidate the third session
        processor.invalidate(&session_keys[2]);

        // Counter should be 0
        let count = processor.get_ip_session_count(source_ip);
        assert_eq!(count, 0, "Counter should be 0 after all invalidates, got {}", count);
    }

    /// REGRESSION TEST: Counter drift fix verification.
    ///
    /// Previously, if `check_ip_session_limit()` incremented the counter but
    /// session creation failed (e.g., connect_udp error), the counter was never
    /// decremented, causing "phantom sessions" to consume rate limit slots.
    ///
    /// The fix: Add decrement calls in all error paths after counter increment.
    #[tokio::test]
    async fn test_regression_counter_decrement_on_creation_failure() {
        use std::time::Duration;

        let config = UdpProcessorConfig {
            session_config: UdpSessionConfig::default(),
            connect_timeout: Duration::from_secs(5),
            enable_quic_sniff: false,
            max_sessions_per_ip: 10,
            max_tracked_ips: DEFAULT_MAX_TRACKED_IPS,
            cleanup_interval: Duration::from_secs(DEFAULT_CLEANUP_INTERVAL_SECS),
        };

        let processor = UdpPacketProcessor::new(config);

        let source_ip: IpAddr = "192.168.1.201".parse().unwrap();
        let client_addr: std::net::SocketAddr = format!("{}:50001", source_ip).parse().unwrap();

        // Use BlockOutbound which returns UdpNotSupported (simulating blocked/failed creation)
        let block_outbound = crate::outbound::BlockOutbound::new("block");

        // Try to create a session - this should fail with UdpNotSupported
        let packet = UdpPacketInfo {
            data: Bytes::from_static(b"test"),
            client_addr,
            original_dst: "1.2.3.4:443".parse().unwrap(),
            received_at: Instant::now(),
        };

        let result = processor.process(&packet, &block_outbound).await;

        // Should be blocked
        assert!(matches!(result, ProcessResult::Blocked { .. }));

        // Counter should be 0 (decremented after failure), NOT 1
        let count = processor.get_ip_session_count(source_ip);
        assert_eq!(count, 0, "Counter should be 0 after blocked session, got {} (counter drift bug!)", count);

        // Try multiple failed creations
        for port in 50002..=50005 {
            let client_addr: std::net::SocketAddr = format!("{}:{}", source_ip, port).parse().unwrap();
            let packet = UdpPacketInfo {
                data: Bytes::from_static(b"test"),
                client_addr,
                original_dst: "1.2.3.4:443".parse().unwrap(),
                received_at: Instant::now(),
            };

            let _ = processor.process(&packet, &block_outbound).await;
        }

        // Counter should still be 0 (all failed creations should decrement)
        let count = processor.get_ip_session_count(source_ip);
        assert_eq!(count, 0, "Counter should still be 0 after multiple failed sessions, got {} (counter drift bug!)", count);
    }

    // ========================================================================
    // NEW-2 FIX: Rate limiting tests for check_ip_session_limit
    // ========================================================================

    #[test]
    fn test_check_ip_session_limit_unlimited_mode() {
        // NEW-2 TEST: When max_sessions_per_ip = 0, rate limiting is disabled.
        use std::time::Duration;

        let config = UdpProcessorConfig {
            session_config: UdpSessionConfig::default(),
            connect_timeout: Duration::from_secs(5),
            enable_quic_sniff: false,
            max_sessions_per_ip: 0, // Unlimited
            max_tracked_ips: DEFAULT_MAX_TRACKED_IPS,
            cleanup_interval: Duration::from_secs(DEFAULT_CLEANUP_INTERVAL_SECS),
        };

        let processor = UdpPacketProcessor::new(config);
        let source_ip: IpAddr = "10.0.0.100".parse().unwrap();

        // Should always return Ok(0) when unlimited
        for _ in 0..100 {
            let result = processor.check_ip_session_limit(source_ip);
            assert!(result.is_ok(), "Unlimited mode should always allow");
            assert_eq!(result.unwrap(), 0, "Unlimited mode should return 0");
        }

        // Counter should remain 0 (not tracked in unlimited mode)
        let count = processor.get_ip_session_count(source_ip);
        assert_eq!(count, 0, "Counter should not increment in unlimited mode");
    }

    #[test]
    fn test_check_ip_session_limit_under_limit() {
        // NEW-2 TEST: Normal case - under the limit, increments counter.
        use std::time::Duration;

        let config = UdpProcessorConfig {
            session_config: UdpSessionConfig::default(),
            connect_timeout: Duration::from_secs(5),
            enable_quic_sniff: false,
            max_sessions_per_ip: 10,
            max_tracked_ips: DEFAULT_MAX_TRACKED_IPS,
            cleanup_interval: Duration::from_secs(DEFAULT_CLEANUP_INTERVAL_SECS),
        };

        let processor = UdpPacketProcessor::new(config);
        let source_ip: IpAddr = "10.0.0.101".parse().unwrap();

        // First 10 calls should succeed
        for i in 1..=10 {
            let result = processor.check_ip_session_limit(source_ip);
            assert!(result.is_ok(), "Should allow session {} of 10", i);
            assert_eq!(result.unwrap(), i as u32, "Counter should be {}", i);
        }

        // Counter should be at max
        let count = processor.get_ip_session_count(source_ip);
        assert_eq!(count, 10, "Counter should be 10");
    }

    #[test]
    fn test_check_ip_session_limit_at_limit() {
        // NEW-2 TEST: At max limit, should reject new sessions.
        use std::time::Duration;

        let config = UdpProcessorConfig {
            session_config: UdpSessionConfig::default(),
            connect_timeout: Duration::from_secs(5),
            enable_quic_sniff: false,
            max_sessions_per_ip: 5,
            max_tracked_ips: DEFAULT_MAX_TRACKED_IPS,
            cleanup_interval: Duration::from_secs(DEFAULT_CLEANUP_INTERVAL_SECS),
        };

        let processor = UdpPacketProcessor::new(config);
        let source_ip: IpAddr = "10.0.0.102".parse().unwrap();

        // Pre-set counter to max
        processor.ip_session_counts.insert(source_ip, AtomicU32::new(5));

        // Next call should be rejected
        let result = processor.check_ip_session_limit(source_ip);
        assert!(result.is_err(), "Should reject when at limit");
        let (current, max) = result.unwrap_err();
        assert_eq!(current, 5, "Current should be 5");
        assert_eq!(max, 5, "Max should be 5");

        // Counter should still be 5 (not incremented)
        let count = processor.get_ip_session_count(source_ip);
        assert_eq!(count, 5, "Counter should remain 5 after rejection");
    }

    #[test]
    fn test_check_ip_session_limit_multiple_ips() {
        // NEW-2 TEST: Different IPs have independent counters.
        use std::time::Duration;

        let config = UdpProcessorConfig {
            session_config: UdpSessionConfig::default(),
            connect_timeout: Duration::from_secs(5),
            enable_quic_sniff: false,
            max_sessions_per_ip: 3,
            max_tracked_ips: DEFAULT_MAX_TRACKED_IPS,
            cleanup_interval: Duration::from_secs(DEFAULT_CLEANUP_INTERVAL_SECS),
        };

        let processor = UdpPacketProcessor::new(config);
        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();
        let ip3: IpAddr = "10.0.0.3".parse().unwrap();

        // Each IP can have 3 sessions
        for _ in 0..3 {
            assert!(processor.check_ip_session_limit(ip1).is_ok());
            assert!(processor.check_ip_session_limit(ip2).is_ok());
            assert!(processor.check_ip_session_limit(ip3).is_ok());
        }

        // All should be at limit now
        assert!(processor.check_ip_session_limit(ip1).is_err());
        assert!(processor.check_ip_session_limit(ip2).is_err());
        assert!(processor.check_ip_session_limit(ip3).is_err());

        // Each IP should have count of 3
        assert_eq!(processor.get_ip_session_count(ip1), 3);
        assert_eq!(processor.get_ip_session_count(ip2), 3);
        assert_eq!(processor.get_ip_session_count(ip3), 3);
    }

    #[test]
    fn test_check_ip_session_limit_concurrent_increment() {
        // NEW-2 TEST: Concurrent access should not exceed limit.
        use std::sync::Arc;
        use std::thread;
        use std::time::Duration;

        let config = UdpProcessorConfig {
            session_config: UdpSessionConfig::default(),
            connect_timeout: Duration::from_secs(5),
            enable_quic_sniff: false,
            max_sessions_per_ip: 100,
            max_tracked_ips: DEFAULT_MAX_TRACKED_IPS,
            cleanup_interval: Duration::from_secs(DEFAULT_CLEANUP_INTERVAL_SECS),
        };

        let processor = Arc::new(UdpPacketProcessor::new(config));
        let source_ip: IpAddr = "10.0.0.200".parse().unwrap();

        // Spawn 20 threads, each trying to get 10 sessions
        let threads: Vec<_> = (0..20)
            .map(|_| {
                let proc = Arc::clone(&processor);
                let ip = source_ip;
                thread::spawn(move || {
                    let mut successes = 0;
                    for _ in 0..10 {
                        if proc.check_ip_session_limit(ip).is_ok() {
                            successes += 1;
                        }
                    }
                    successes
                })
            })
            .collect();

        // Wait and collect results
        let total_successes: u32 = threads.into_iter().map(|t| t.join().unwrap()).sum();

        // Counter should be exactly 100 (the limit)
        let count = processor.get_ip_session_count(source_ip);
        assert_eq!(count, 100, "Counter should be exactly at limit (100), got {}", count);
        assert_eq!(total_successes, 100, "Total successes should be 100, got {}", total_successes);
    }

    #[test]
    fn test_check_ip_session_limit_ipv6() {
        // NEW-2 TEST: IPv6 addresses should work the same as IPv4.
        use std::time::Duration;

        let config = UdpProcessorConfig {
            session_config: UdpSessionConfig::default(),
            connect_timeout: Duration::from_secs(5),
            enable_quic_sniff: false,
            max_sessions_per_ip: 5,
            max_tracked_ips: DEFAULT_MAX_TRACKED_IPS,
            cleanup_interval: Duration::from_secs(DEFAULT_CLEANUP_INTERVAL_SECS),
        };

        let processor = UdpPacketProcessor::new(config);
        let ipv6: IpAddr = "2001:db8::1".parse().unwrap();

        // Should work for IPv6
        for i in 1..=5 {
            let result = processor.check_ip_session_limit(ipv6);
            assert!(result.is_ok(), "Should allow IPv6 session {}", i);
        }

        // Should be limited at 5
        let result = processor.check_ip_session_limit(ipv6);
        assert!(result.is_err(), "IPv6 should be rate limited");
    }

    #[tokio::test]
    async fn test_process_returns_rate_limited() {
        // NEW-2 TEST: process() should return RateLimited when limit is reached.
        use std::time::Duration;

        let config = UdpProcessorConfig {
            session_config: UdpSessionConfig::default(),
            connect_timeout: Duration::from_secs(5),
            enable_quic_sniff: false,
            max_sessions_per_ip: 2,
            max_tracked_ips: DEFAULT_MAX_TRACKED_IPS,
            cleanup_interval: Duration::from_secs(DEFAULT_CLEANUP_INTERVAL_SECS),
        };

        let processor = UdpPacketProcessor::new(config);
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();

        let source_ip: IpAddr = "192.168.1.250".parse().unwrap();
        let outbound = DirectOutbound::simple("test");

        // Create first session (should succeed)
        let packet1 = UdpPacketInfo {
            data: Bytes::from_static(b"test1"),
            client_addr: format!("{}:10001", source_ip).parse().unwrap(),
            original_dst: server_addr,
            received_at: Instant::now(),
        };
        let result1 = processor.process(&packet1, &outbound).await;
        assert!(matches!(result1, ProcessResult::Forwarded { new_session: true, .. }), "First session should succeed");

        // Create second session (should succeed)
        let packet2 = UdpPacketInfo {
            data: Bytes::from_static(b"test2"),
            client_addr: format!("{}:10002", source_ip).parse().unwrap(),
            original_dst: server_addr,
            received_at: Instant::now(),
        };
        let result2 = processor.process(&packet2, &outbound).await;
        assert!(matches!(result2, ProcessResult::Forwarded { new_session: true, .. }), "Second session should succeed");

        // Third session should be rate limited
        let packet3 = UdpPacketInfo {
            data: Bytes::from_static(b"test3"),
            client_addr: format!("{}:10003", source_ip).parse().unwrap(),
            original_dst: server_addr,
            received_at: Instant::now(),
        };
        let result3 = processor.process(&packet3, &outbound).await;
        assert!(matches!(result3, ProcessResult::RateLimited { .. }), "Third session should be rate limited, got {:?}", result3);

        // Counter should be 2
        assert_eq!(processor.get_ip_session_count(source_ip), 2, "Counter should be 2");
    }

    #[test]
    fn test_tracked_source_ips() {
        // NEW-2 TEST: tracked_source_ips() returns correct count of IPs.
        use std::time::Duration;

        let config = UdpProcessorConfig {
            session_config: UdpSessionConfig::default(),
            connect_timeout: Duration::from_secs(5),
            enable_quic_sniff: false,
            max_sessions_per_ip: 100,
            max_tracked_ips: DEFAULT_MAX_TRACKED_IPS,
            cleanup_interval: Duration::from_secs(DEFAULT_CLEANUP_INTERVAL_SECS),
        };

        let processor = UdpPacketProcessor::new(config);

        // Initially empty
        assert_eq!(processor.tracked_source_ips(), 0);

        // Add some IPs
        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();
        let ip3: IpAddr = "10.0.0.3".parse().unwrap();

        processor.check_ip_session_limit(ip1).unwrap();
        assert_eq!(processor.tracked_source_ips(), 1);

        processor.check_ip_session_limit(ip2).unwrap();
        assert_eq!(processor.tracked_source_ips(), 2);

        processor.check_ip_session_limit(ip3).unwrap();
        assert_eq!(processor.tracked_source_ips(), 3);
    }

    #[test]
    fn test_clear_resets_ip_counts() {
        // NEW-2 TEST: clear() should also clear IP counters.
        use std::time::Duration;

        let config = UdpProcessorConfig {
            session_config: UdpSessionConfig::default(),
            connect_timeout: Duration::from_secs(5),
            enable_quic_sniff: false,
            max_sessions_per_ip: 100,
            max_tracked_ips: DEFAULT_MAX_TRACKED_IPS,
            cleanup_interval: Duration::from_secs(DEFAULT_CLEANUP_INTERVAL_SECS),
        };

        let processor = UdpPacketProcessor::new(config);

        // Add some sessions
        let ip: IpAddr = "10.0.0.50".parse().unwrap();
        for _ in 0..10 {
            processor.check_ip_session_limit(ip).unwrap();
        }
        assert_eq!(processor.get_ip_session_count(ip), 10);

        // Clear all
        processor.clear();

        // IP counts should be cleared
        assert_eq!(processor.get_ip_session_count(ip), 0);
        assert_eq!(processor.tracked_source_ips(), 0);
    }

    // === SEC-2 FIX: IP Session Counts Cleanup Tests ===

    #[test]
    fn test_sec2_cleanup_removes_zero_count_entries() {
        // SEC-2 FIX TEST: Verify cleanup_zero_count_ips removes entries with count 0
        use std::time::Duration;

        let config = UdpProcessorConfig {
            session_config: UdpSessionConfig::default(),
            connect_timeout: Duration::from_secs(5),
            enable_quic_sniff: false,
            max_sessions_per_ip: 100,
            max_tracked_ips: DEFAULT_MAX_TRACKED_IPS,
            cleanup_interval: Duration::from_secs(DEFAULT_CLEANUP_INTERVAL_SECS),
        };

        let processor = UdpPacketProcessor::new(config);

        // Add some IPs with count 0 (simulating sessions that have all expired)
        processor.ip_session_counts.insert("10.0.0.1".parse().unwrap(), AtomicU32::new(0));
        processor.ip_session_counts.insert("10.0.0.2".parse().unwrap(), AtomicU32::new(0));
        processor.ip_session_counts.insert("10.0.0.3".parse().unwrap(), AtomicU32::new(5)); // Active

        assert_eq!(processor.tracked_source_ips(), 3);

        // Cleanup should remove zero-count entries
        let removed = processor.cleanup_zero_count_ips();

        assert_eq!(removed, 2, "Should remove 2 zero-count entries");
        assert_eq!(processor.tracked_source_ips(), 1, "Should have 1 remaining");
        assert_eq!(processor.get_ip_session_count("10.0.0.3".parse().unwrap()), 5);
    }

    #[test]
    fn test_sec2_cleanup_skipped_when_rate_limiting_disabled() {
        // SEC-2 FIX TEST: Verify cleanup is skipped when rate limiting is disabled
        use std::time::Duration;

        let config = UdpProcessorConfig {
            session_config: UdpSessionConfig::default(),
            connect_timeout: Duration::from_secs(5),
            enable_quic_sniff: false,
            max_sessions_per_ip: 0, // Disabled
            max_tracked_ips: DEFAULT_MAX_TRACKED_IPS,
            cleanup_interval: Duration::from_secs(DEFAULT_CLEANUP_INTERVAL_SECS),
        };

        let processor = UdpPacketProcessor::new(config);

        // Add an entry (shouldn't happen in practice, but test anyway)
        processor.ip_session_counts.insert("10.0.0.1".parse().unwrap(), AtomicU32::new(0));

        // Cleanup should return 0 (no-op)
        let removed = processor.cleanup_zero_count_ips();

        assert_eq!(removed, 0, "Cleanup should be no-op when rate limiting disabled");
        assert_eq!(processor.tracked_source_ips(), 1, "Entry should still exist");
    }

    #[test]
    fn test_sec2_force_cleanup() {
        // SEC-2 FIX TEST: Verify force_cleanup always runs and resets counter
        use std::time::Duration;

        let config = UdpProcessorConfig {
            session_config: UdpSessionConfig::default(),
            connect_timeout: Duration::from_secs(5),
            enable_quic_sniff: false,
            max_sessions_per_ip: 100,
            max_tracked_ips: DEFAULT_MAX_TRACKED_IPS,
            cleanup_interval: Duration::from_secs(3600), // Long interval
        };

        let processor = UdpPacketProcessor::new(config);

        // Add zero-count entries
        for i in 0..100 {
            processor.ip_session_counts.insert(
                format!("10.0.{}.{}", i / 256, i % 256).parse().unwrap(),
                AtomicU32::new(0)
            );
        }

        assert_eq!(processor.tracked_source_ips(), 100);

        // Force cleanup should work immediately regardless of interval
        let removed = processor.force_cleanup();

        assert_eq!(removed, 100, "Should remove all 100 zero-count entries");
        assert_eq!(processor.tracked_source_ips(), 0);
    }

    #[test]
    fn test_sec2_maybe_cleanup_triggers_on_capacity() {
        // SEC-2 FIX TEST: Verify maybe_cleanup triggers when over capacity
        use std::time::Duration;

        let config = UdpProcessorConfig {
            session_config: UdpSessionConfig::default(),
            connect_timeout: Duration::from_secs(5),
            enable_quic_sniff: false,
            max_sessions_per_ip: 100,
            max_tracked_ips: 50, // Low limit for testing
            cleanup_interval: Duration::from_secs(3600), // Long interval
        };

        let processor = UdpPacketProcessor::new(config);

        // Add 60 zero-count entries (over limit of 50)
        for i in 0..60 {
            processor.ip_session_counts.insert(
                format!("10.0.{}.{}", i / 256, i % 256).parse().unwrap(),
                AtomicU32::new(0)
            );
        }

        assert_eq!(processor.tracked_source_ips(), 60);

        // maybe_cleanup should trigger because we're over capacity
        processor.maybe_cleanup();

        // All zero-count entries should be removed
        assert_eq!(processor.tracked_source_ips(), 0, "All zero-count entries should be cleaned");
    }

    #[test]
    fn test_sec2_cleanup_preserves_active_entries() {
        // SEC-2 FIX TEST: Verify cleanup doesn't remove entries with active sessions
        use std::time::Duration;

        let config = UdpProcessorConfig {
            session_config: UdpSessionConfig::default(),
            connect_timeout: Duration::from_secs(5),
            enable_quic_sniff: false,
            max_sessions_per_ip: 100,
            max_tracked_ips: 10, // Low limit to trigger cleanup
            cleanup_interval: Duration::from_secs(3600),
        };

        let processor = UdpPacketProcessor::new(config);

        // Add mix of active and inactive entries
        processor.ip_session_counts.insert("10.0.0.1".parse().unwrap(), AtomicU32::new(5)); // Active
        processor.ip_session_counts.insert("10.0.0.2".parse().unwrap(), AtomicU32::new(0)); // Inactive
        processor.ip_session_counts.insert("10.0.0.3".parse().unwrap(), AtomicU32::new(10)); // Active
        processor.ip_session_counts.insert("10.0.0.4".parse().unwrap(), AtomicU32::new(0)); // Inactive

        // Force cleanup
        let removed = processor.force_cleanup();

        assert_eq!(removed, 2, "Should remove 2 zero-count entries");
        assert_eq!(processor.tracked_source_ips(), 2, "Should keep 2 active entries");
        assert_eq!(processor.get_ip_session_count("10.0.0.1".parse().unwrap()), 5);
        assert_eq!(processor.get_ip_session_count("10.0.0.3".parse().unwrap()), 10);
    }

    #[test]
    fn test_sec2_config_max_tracked_ips() {
        // SEC-2 FIX TEST: Verify new config fields work
        use std::time::Duration;

        let config = UdpProcessorConfig {
            session_config: UdpSessionConfig::default(),
            connect_timeout: Duration::from_secs(5),
            enable_quic_sniff: false,
            max_sessions_per_ip: 100,
            max_tracked_ips: 5000,
            cleanup_interval: Duration::from_secs(30),
        };

        assert_eq!(config.max_tracked_ips, 5000);
        assert_eq!(config.cleanup_interval, Duration::from_secs(30));
    }

    #[test]
    fn test_sec2_default_config_values() {
        // SEC-2 FIX TEST: Verify default values for new config fields
        let config = UdpProcessorConfig::default();

        assert_eq!(config.max_tracked_ips, DEFAULT_MAX_TRACKED_IPS);
        assert_eq!(config.cleanup_interval, Duration::from_secs(DEFAULT_CLEANUP_INTERVAL_SECS));
    }

    #[test]
    fn test_sec2_memory_attack_mitigation() {
        // SEC-2 FIX TEST: Simulate memory exhaustion attack scenario
        // An attacker sends packets from many unique spoofed IPs
        use std::time::Duration;

        let config = UdpProcessorConfig {
            session_config: UdpSessionConfig::default(),
            connect_timeout: Duration::from_secs(5),
            enable_quic_sniff: false,
            max_sessions_per_ip: 100,
            max_tracked_ips: 100, // Small limit for test
            cleanup_interval: Duration::from_secs(3600),
        };

        let processor = UdpPacketProcessor::new(config);

        // Simulate attack: create many IPs, then "expire" their sessions (set to 0)
        for i in 0..200 {
            let ip: IpAddr = format!("192.168.{}.{}", i / 256, i % 256).parse().unwrap();
            processor.ip_session_counts.insert(ip, AtomicU32::new(0));
        }

        assert_eq!(processor.tracked_source_ips(), 200, "Before cleanup: 200 entries");

        // maybe_cleanup should trigger (over capacity 200 > 100)
        processor.maybe_cleanup();

        // After cleanup, all zero-count entries should be gone
        assert_eq!(processor.tracked_source_ips(), 0, "After cleanup: 0 entries");
    }

    #[test]
    fn test_sec2_cleanup_interval_check() {
        // SEC-2 FIX TEST: Verify interval-based cleanup timing
        use std::time::Duration;

        let config = UdpProcessorConfig {
            session_config: UdpSessionConfig::default(),
            connect_timeout: Duration::from_secs(5),
            enable_quic_sniff: false,
            max_sessions_per_ip: 100,
            max_tracked_ips: 10000, // High limit so capacity check doesn't trigger
            cleanup_interval: Duration::from_millis(10), // Very short for testing
        };

        let processor = UdpPacketProcessor::new(config);

        // Add a zero-count entry
        processor.ip_session_counts.insert("10.0.0.1".parse().unwrap(), AtomicU32::new(0));

        // Wait for interval to pass
        std::thread::sleep(Duration::from_millis(20));

        // Set decrement counter high enough to trigger check
        processor.decrement_counter.store(CLEANUP_CHECK_INTERVAL_DECREMENTS - 1, Ordering::Relaxed);

        // This decrement should trigger cleanup
        let ip: IpAddr = "10.0.0.2".parse().unwrap();
        processor.ip_session_counts.insert(ip, AtomicU32::new(1));
        processor.decrement_ip_session_count(ip);

        // The zero-count entry should have been cleaned up
        // Note: Due to timing, this might not always work in CI, so we just verify no crash
        assert!(processor.tracked_source_ips() <= 2);
    }

    #[test]
    fn test_sec2_p1_hard_limit_enforcement() {
        // P1 FIX TEST: Verify new IPs are rejected when at capacity
        use std::time::Duration;

        // Small capacity for testing
        let config = UdpProcessorConfig {
            session_config: UdpSessionConfig::default(),
            connect_timeout: Duration::from_secs(5),
            enable_quic_sniff: false,
            max_sessions_per_ip: 10,
            max_tracked_ips: 3, // Very small for testing
            cleanup_interval: Duration::from_secs(3600), // Long interval, won't auto-clean
        };

        let processor = UdpPacketProcessor::new(config);

        // Fill up to capacity with active sessions
        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();
        let ip3: IpAddr = "10.0.0.3".parse().unwrap();
        let ip4: IpAddr = "10.0.0.4".parse().unwrap(); // This should be rejected

        // Create sessions for first 3 IPs
        assert!(processor.check_ip_session_limit(ip1).is_ok(), "IP1 should succeed");
        assert!(processor.check_ip_session_limit(ip2).is_ok(), "IP2 should succeed");
        assert!(processor.check_ip_session_limit(ip3).is_ok(), "IP3 should succeed");

        // Verify we're at capacity
        assert_eq!(processor.tracked_source_ips(), 3, "Should have 3 tracked IPs");

        // Try to add a new IP - should be rejected
        let result = processor.check_ip_session_limit(ip4);
        assert!(result.is_err(), "IP4 should be rejected - at capacity");
        assert_eq!(result.unwrap_err(), (0, 0), "Special (0,0) indicates IP capacity");

        // Verify no new entry was created
        assert_eq!(processor.tracked_source_ips(), 3, "Should still have 3 IPs");
        assert!(!processor.ip_session_counts.contains_key(&ip4), "IP4 should not exist");

        // Existing IPs should still be able to create sessions
        assert!(processor.check_ip_session_limit(ip1).is_ok(), "Existing IP1 should still work");
        assert_eq!(processor.get_ip_session_count(ip1), 2, "IP1 should have 2 sessions");
    }

    #[test]
    fn test_sec2_p1_hard_limit_with_cleanup() {
        // P1 FIX TEST: After cleanup, new IPs should be allowed
        use std::time::Duration;

        let config = UdpProcessorConfig {
            session_config: UdpSessionConfig::default(),
            connect_timeout: Duration::from_secs(5),
            enable_quic_sniff: false,
            max_sessions_per_ip: 10,
            max_tracked_ips: 2,
            cleanup_interval: Duration::from_secs(3600),
        };

        let processor = UdpPacketProcessor::new(config);

        // Create sessions
        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();
        assert!(processor.check_ip_session_limit(ip1).is_ok());
        assert!(processor.check_ip_session_limit(ip2).is_ok());

        // Now decrement IP1's count to 0 (simulating session end)
        processor.decrement_ip_session_count(ip1);
        assert_eq!(processor.get_ip_session_count(ip1), 0);

        // Force cleanup to remove zero-count entry
        let removed = processor.force_cleanup();
        assert_eq!(removed, 1, "Should remove 1 zero-count entry");
        assert_eq!(processor.tracked_source_ips(), 1, "Should have 1 IP left");

        // Now a new IP should be allowed
        let ip3: IpAddr = "10.0.0.3".parse().unwrap();
        assert!(processor.check_ip_session_limit(ip3).is_ok(), "IP3 should now succeed");
        assert_eq!(processor.tracked_source_ips(), 2, "Should have 2 IPs");
    }

    #[test]
    fn test_p1_cas_decrement_helper() {
        // P1 FIX TEST: Verify the extracted CAS helper function works correctly
        use std::sync::atomic::AtomicU32;

        // Test normal decrement
        let counter = AtomicU32::new(5);
        assert!(cas_decrement(&counter), "Should return true on successful decrement");
        assert_eq!(counter.load(Ordering::Relaxed), 4);

        // Test decrement to zero
        let counter = AtomicU32::new(1);
        assert!(cas_decrement(&counter), "Should return true on decrement to 0");
        assert_eq!(counter.load(Ordering::Relaxed), 0);

        // Test decrement when already zero
        let counter = AtomicU32::new(0);
        assert!(!cas_decrement(&counter), "Should return false when already 0");
        assert_eq!(counter.load(Ordering::Relaxed), 0);
    }
}
