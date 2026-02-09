// Some fields/methods are reserved for future features or debugging.
#![allow(dead_code)]

//! SmoltcpShard - Single-task owner of smoltcp resources
//!
//! This module provides `SmoltcpShard`, which owns the smoltcp `Interface`
//! and `SocketSet` within a single async task. Communication with the shard
//! happens through channels, eliminating the need for mutexes.
//!
//! # Architecture
//!
//! ```text
//! ┌───────────────────────────────────────────────────────────────────────┐
//! │                     SmoltcpShard (single task)                        │
//! ├───────────────────────────────────────────────────────────────────────┤
//! │                                                                       │
//! │  ┌─────────────────────┐    ┌─────────────────────┐                  │
//! │  │ SmoltcpBridge       │    │ Session Maps        │                  │
//! │  │ (owns Interface,    │    │ - TCP sessions      │                  │
//! │  │  SocketSet, Device) │    │ - UDP sessions      │                  │
//! │  └─────────────────────┘    └─────────────────────┘                  │
//! │                                                                       │
//! │  ┌───────────────────────────────────────────────────────────────┐   │
//! │  │                     Event Loop                                 │   │
//! │  │                                                                │   │
//! │  │  tokio::select! {                                              │   │
//! │  │      biased;                                                   │   │
//! │  │                                                                │   │
//! │  │      // Highest priority: WG reply packets                     │   │
//! │  │      Some(packet) = wg_reply_rx.recv() => handle_wg_reply()   │   │
//! │  │                                                                │   │
//! │  │      // Medium: Commands (tcp connect, udp send, etc.)         │   │
//! │  │      Some(cmd) = command_rx.recv() => handle_command()        │   │
//! │  │                                                                │   │
//! │  │      // Low: Timer-based polling                               │   │
//! │  │      _ = sleep(poll_delay) => poll_smoltcp()                   │   │
//! │  │  }                                                             │   │
//! │  └───────────────────────────────────────────────────────────────┘   │
//! └───────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Thread Safety
//!
//! `SmoltcpShard` is `Send` but NOT `Sync`. It should be moved into a single
//! async task via `tokio::spawn(shard.run())`.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use smoltcp::iface::SocketHandle;
use smoltcp::socket::tcp::State as TcpState;
use smoltcp::wire::{IpAddress, IpEndpoint};
use tokio::sync::{mpsc, oneshot, Notify};
use tracing::{debug, info, trace, warn};

use super::bridge::{socket_addr_to_endpoint, SmoltcpBridge, SmoltcpBridgeConfig};
use super::{DEFAULT_POLL_INTERVAL_MS, MAX_POLL_INTERVAL_MS, MIN_POLL_INTERVAL_MS};
use crate::netbridge::error::{NetBridgeError, Result};
use crate::netbridge::port::PortAllocator;

// =============================================================================
// Configuration
// =============================================================================

/// Configuration for creating a SmoltcpShard
#[derive(Debug, Clone)]
pub struct SmoltcpShardConfig {
    /// Shard index (for logging and metrics)
    pub shard_index: usize,
    /// Total number of shards
    pub total_shards: usize,
    /// Local IP address for the smoltcp interface
    pub local_ip: IpAddress,
    /// Maximum transmission unit
    pub mtu: usize,
    /// TCP idle timeout
    pub tcp_idle_timeout: Duration,
    /// UDP idle timeout
    pub udp_idle_timeout: Duration,
    /// Cleanup interval for expired sessions
    pub cleanup_interval: Duration,
}

impl SmoltcpShardConfig {
    /// Create a new shard config
    #[must_use]
    pub fn new(shard_index: usize, total_shards: usize, local_ip: IpAddress) -> Self {
        Self {
            shard_index,
            total_shards,
            local_ip,
            mtu: super::WG_MTU,
            tcp_idle_timeout: Duration::from_secs(300),  // 5 minutes
            udp_idle_timeout: Duration::from_secs(30),   // 30 seconds
            cleanup_interval: Duration::from_secs(30),   // 30 seconds
        }
    }

    /// Create a config with IPv4 address
    #[must_use]
    pub fn with_ipv4(shard_index: usize, total_shards: usize, a: u8, b: u8, c: u8, d: u8) -> Self {
        Self::new(shard_index, total_shards, IpAddress::v4(a, b, c, d))
    }
}

impl Default for SmoltcpShardConfig {
    fn default() -> Self {
        Self::with_ipv4(0, 1, 10, 200, 200, 2)
    }
}

// =============================================================================
// Commands
// =============================================================================

/// Commands sent to the shard
pub enum ShardCommand {
    /// Handle a TCP connection
    TcpConnect {
        /// Destination address
        dest: SocketAddr,
        /// Reply channel for session ID or error
        reply: oneshot::Sender<Result<u64>>,
        /// Data sender channel
        data_tx: mpsc::Sender<Bytes>,
        /// Data receiver channel
        data_rx: mpsc::Receiver<Bytes>,
    },
    /// Send data on a TCP session
    TcpSend {
        /// Session ID
        session_id: u64,
        /// Data to send
        data: Bytes,
    },
    /// Close a TCP session
    TcpClose {
        /// Session ID
        session_id: u64,
    },
    /// Handle a UDP packet
    UdpSend {
        /// Source address (for reply routing)
        src: SocketAddr,
        /// Destination address
        dest: SocketAddr,
        /// Packet data
        data: Bytes,
        /// Reply channel (optional, for first packet in session)
        reply: Option<oneshot::Sender<Result<u64>>>,
    },
    /// Close a UDP session
    UdpClose {
        /// Session ID
        session_id: u64,
    },
    /// Shutdown the shard
    Shutdown,
    /// Get statistics
    GetStats {
        /// Reply channel
        reply: oneshot::Sender<SmoltcpShardStats>,
    },
}

// =============================================================================
// Statistics
// =============================================================================

/// Statistics for a SmoltcpShard
#[derive(Debug, Clone, Default)]
pub struct SmoltcpShardStats {
    /// Commands processed
    pub commands_processed: u64,
    /// WG packets received (reply direction)
    pub wg_packets_received: u64,
    /// WG packets sent (to tunnel)
    pub wg_packets_sent: u64,
    /// TCP sessions created
    pub tcp_sessions_created: u64,
    /// TCP sessions closed
    pub tcp_sessions_closed: u64,
    /// TCP bytes sent
    pub tcp_bytes_sent: u64,
    /// TCP bytes received
    pub tcp_bytes_received: u64,
    /// UDP sessions created
    pub udp_sessions_created: u64,
    /// UDP sessions closed
    pub udp_sessions_closed: u64,
    /// UDP datagrams sent
    pub udp_datagrams_sent: u64,
    /// UDP datagrams received
    pub udp_datagrams_received: u64,
    /// Poll count
    pub poll_count: u64,
    /// Session cleanup count
    pub cleanup_runs: u64,
    /// Sessions cleaned up
    pub sessions_cleaned: u64,
    /// Upload notify wakeups
    pub upload_notify_wakeups: u64,
    /// Times the per-session drain limit was hit (potential throughput bottleneck)
    pub drain_limit_hits: u64,
    /// Times the 2nd poll in poll_and_process produced new TX packets
    pub second_poll_productive: u64,
}

// =============================================================================
// TCP Session
// =============================================================================

/// State for a TCP session within the shard
struct TcpSession {
    /// Session ID
    id: u64,
    /// Socket handle
    handle: SocketHandle,
    /// Allocated local port
    local_port: u16,
    /// Remote endpoint
    remote: IpEndpoint,
    /// Data sender to the client task
    data_tx: mpsc::Sender<Bytes>,
    /// Last activity time
    last_active: Instant,
    /// Bytes sent
    bytes_sent: u64,
    /// Bytes received
    bytes_received: u64,
    /// Pending data to send (buffered when socket can't send)
    pending_send: Vec<u8>,
    /// Pending data to receive (buffered when data_tx channel is full)
    /// This prevents data loss: smoltcp has already ACK'd this data,
    /// so we MUST deliver it to the client eventually.
    pending_recv: Option<Bytes>,
    /// Per-session upload data receiver.
    /// Data arrives from the pump task's read_half via per-session channel,
    /// bypassing the shared command_tx to eliminate contention.
    data_rx: mpsc::Receiver<Bytes>,
}

// =============================================================================
// UDP Session
// =============================================================================

/// State for a UDP session within the shard
struct UdpSession {
    /// Session ID
    id: u64,
    /// Socket handle
    handle: SocketHandle,
    /// Allocated local port
    local_port: u16,
    /// Client source address (for reply routing)
    client_src: SocketAddr,
    /// Destination address
    dest: SocketAddr,
    /// Data sender to the client task
    data_tx: mpsc::Sender<Bytes>,
    /// Last activity time
    last_active: Instant,
    /// Datagrams sent
    datagrams_sent: u64,
    /// Datagrams received
    datagrams_received: u64,
}

/// Key for UDP session lookup
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct UdpSessionKey {
    src: SocketAddr,
    dst: SocketAddr,
}

// =============================================================================
// SmoltcpShard
// =============================================================================

/// Single-task owner of smoltcp resources
///
/// This struct owns all smoltcp resources and runs in a dedicated async task.
/// Communication happens through the `command_rx` and `wg_reply_rx` channels.
pub struct SmoltcpShard {
    /// Configuration
    config: SmoltcpShardConfig,
    /// The smoltcp bridge (owns Interface, SocketSet, Device)
    bridge: SmoltcpBridge,
    /// Port allocator
    port_allocator: PortAllocator,
    /// Session ID counter
    next_session_id: u64,
    /// TCP sessions by session ID
    tcp_sessions: HashMap<u64, TcpSession>,
    /// TCP session lookup by socket handle
    tcp_by_handle: HashMap<SocketHandle, u64>,
    /// UDP sessions by session ID
    udp_sessions: HashMap<u64, UdpSession>,
    /// UDP session lookup by key
    udp_by_key: HashMap<UdpSessionKey, u64>,
    /// Command receiver
    command_rx: mpsc::Receiver<ShardCommand>,
    /// WG reply packet receiver
    wg_reply_rx: mpsc::Receiver<Vec<u8>>,
    /// WG TX packet sender
    wg_tx: mpsc::Sender<Bytes>,
    /// Upload data notification -- signaled by pump tasks when new data arrives
    upload_notify: Arc<Notify>,
    /// Shutdown flag
    shutdown: bool,
    /// Statistics
    stats: SmoltcpShardStats,
    /// Pending WG TX packets that couldn't be sent (channel full)
    /// Used by non-blocking drain to buffer unsent packets.
    pending_wg_tx: VecDeque<Bytes>,
    /// Reusable buffer for TCP recv to avoid per-session allocation
    tcp_recv_buf: Vec<u8>,
}

impl SmoltcpShard {
    /// Create a new shard
    ///
    /// # Arguments
    ///
    /// * `config` - Shard configuration
    /// * `command_rx` - Channel for receiving commands
    /// * `wg_reply_rx` - Channel for receiving WG reply packets
    /// * `wg_tx` - Channel for sending WG packets
    /// * `upload_notify` - Notify handle signaled by pump tasks when upload data arrives
    #[must_use]
    pub fn new(
        config: SmoltcpShardConfig,
        command_rx: mpsc::Receiver<ShardCommand>,
        wg_reply_rx: mpsc::Receiver<Vec<u8>>,
        wg_tx: mpsc::Sender<Bytes>,
        upload_notify: Arc<Notify>,
    ) -> Self {
        // Create bridge with the local IP
        let bridge_config = SmoltcpBridgeConfig::new(config.local_ip).with_mtu(config.mtu);
        let bridge = SmoltcpBridge::new(bridge_config);

        // Create port allocator with shard partitioning
        let port_allocator = if config.total_shards > 1 {
            PortAllocator::for_shard(config.shard_index as u16, config.total_shards as u16)
        } else {
            PortAllocator::new()
        };

        info!(
            shard_index = config.shard_index,
            local_ip = %config.local_ip,
            mtu = config.mtu,
            "SmoltcpShard created"
        );

        Self {
            config,
            bridge,
            port_allocator,
            next_session_id: 1,
            tcp_sessions: HashMap::new(),
            tcp_by_handle: HashMap::new(),
            udp_sessions: HashMap::new(),
            udp_by_key: HashMap::new(),
            command_rx,
            wg_reply_rx,
            wg_tx,
            upload_notify,
            shutdown: false,
            stats: SmoltcpShardStats::default(),
            pending_wg_tx: VecDeque::new(),
            tcp_recv_buf: vec![0u8; 65536],
        }
    }

    /// Allocate a new session ID
    fn alloc_session_id(&mut self) -> u64 {
        let id = self.next_session_id;
        self.next_session_id += 1;
        id
    }

    /// Run the shard event loop (consumes self)
    ///
    /// This method runs until shutdown is requested or all senders are dropped.
    pub async fn run(mut self) {
        info!(
            shard_index = self.config.shard_index,
            "SmoltcpShard starting event loop"
        );

        // Create cleanup timer
        let mut cleanup_timer = tokio::time::interval(self.config.cleanup_interval);
        cleanup_timer.tick().await; // Skip first immediate tick

        loop {
            if self.shutdown {
                info!(
                    shard_index = self.config.shard_index,
                    "SmoltcpShard shutting down"
                );
                break;
            }

            let poll_delay = self.calculate_poll_delay();

            tokio::select! {
                biased;

                // WG reply packets trigger processing
                Some(packet) = self.wg_reply_rx.recv() => {
                    self.handle_wg_reply(packet);
                    // Batch drain all queued reply packets with interleaved polling
                    self.handle_wg_reply_batch();
                    // ALSO drain commands to prevent priority inversion
                    // (control commands like TcpConnect/TcpClose need timely processing)
                    while let Ok(cmd) = self.command_rx.try_recv() {
                        self.handle_command(cmd).await;
                    }
                    self.poll_and_process();
                    self.drain_wg_packets();
                }

                // Commands trigger processing (TcpConnect, TcpClose, UdpSend, etc.)
                Some(cmd) = self.command_rx.recv() => {
                    self.handle_command(cmd).await;
                    // Batch drain all queued commands
                    while let Ok(cmd) = self.command_rx.try_recv() {
                        self.handle_command(cmd).await;
                    }
                    // ALSO drain WG replies to prevent starvation in other direction
                    self.handle_wg_reply_batch();
                    self.poll_and_process();
                    self.drain_wg_packets();
                }

                // Upload data notification (from pump tasks)
                // Priority: lower than WG replies and commands, higher than timer
                _ = self.upload_notify.notified() => {
                    self.stats.upload_notify_wakeups += 1;
                    // CRITICAL: Must cross-drain all channels to prevent starvation
                    // Under heavy upload, this branch fires continuously. Without
                    // cross-drain, WG replies (ACKs) and commands (TcpClose) would
                    // be starved, causing download stalls and session leaks.
                    self.handle_wg_reply_batch();
                    while let Ok(cmd) = self.command_rx.try_recv() {
                        self.handle_command(cmd).await;
                    }
                    self.poll_and_process();
                    self.drain_wg_packets();
                }

                // Timer-based polling (process both channels)
                _ = tokio::time::sleep(poll_delay) => {
                    // Drain both channels even on timer tick
                    self.handle_wg_reply_batch();
                    while let Ok(cmd) = self.command_rx.try_recv() {
                        self.handle_command(cmd).await;
                    }
                    self.poll_and_process();
                    self.drain_wg_packets();
                }

                // Periodic cleanup
                _ = cleanup_timer.tick() => {
                    self.cleanup_expired_sessions();
                }
            }
        }

        info!(
            shard_index = self.config.shard_index,
            stats = ?self.stats,
            "SmoltcpShard event loop ended"
        );
    }

    /// Calculate the poll delay
    fn calculate_poll_delay(&mut self) -> Duration {
        self.bridge
            .poll_delay()
            .map(|d| d.clamp(
                Duration::from_millis(MIN_POLL_INTERVAL_MS),
                Duration::from_millis(MAX_POLL_INTERVAL_MS),
            ))
            .unwrap_or(Duration::from_millis(DEFAULT_POLL_INTERVAL_MS))
    }

    /// Poll smoltcp and process socket events
    fn poll_and_process(&mut self) {
        // 1st poll: process RX (incoming ACKs/data), generate TX (ACKs, retransmits)
        self.bridge.poll();
        self.stats.poll_count += 1;
        // Flush TX from 1st poll to free device buffer space
        // Critical: smoltcp's socket_ingress consumes TX slots for ACKs,
        // which can fill the entire TX buffer and starve data segments
        self.drain_wg_packets();
        // Drain per-session upload data into smoltcp socket TX buffers
        self.process_tcp_sockets();
        self.process_udp_sockets();
        // 2nd poll: convert newly injected upload data into IP packets
        // Without this, data waits until the next event loop iteration (5-50ms)
        let second_poll_did_work = self.bridge.poll();
        if second_poll_did_work {
            self.stats.second_poll_productive += 1;
        }
    }

    /// Handle a WG reply packet
    fn handle_wg_reply(&mut self, packet: Vec<u8>) {
        trace!(
            shard_index = self.config.shard_index,
            len = packet.len(),
            "Received WG reply packet"
        );

        self.stats.wg_packets_received += 1;

        // Feed packet to the bridge (zero-copy: Vec<u8> passed directly)
        if !self.bridge.feed_rx(packet) {
            warn!(
                shard_index = self.config.shard_index,
                "Bridge RX buffer full, dropping packet"
            );
        }
    }

    /// Batch drain WG reply packets with interleaved polling.
    ///
    /// Polls smoltcp every BATCH_POLL_THRESHOLD packets to prevent
    /// VirtualDevice RX buffer overflow. Without this, a burst of 2048
    /// packets from wg_reply_rx would overflow the 512/1024-entry RX buffer,
    /// silently dropping ACKs and causing retransmission storms.
    ///
    /// Tracks RX drops during the batch and logs a single summary at the end
    /// instead of per-packet warnings to avoid log storms under burst.
    fn handle_wg_reply_batch(&mut self) {
        const BATCH_POLL_THRESHOLD: usize = 64;
        let mut count = 0;
        let mut drops = 0;
        while let Ok(packet) = self.wg_reply_rx.try_recv() {
            self.stats.wg_packets_received += 1;
            if !self.bridge.feed_rx(packet) {
                drops += 1;
            }
            count += 1;
            if count % BATCH_POLL_THRESHOLD == 0 {
                // Intermediate poll: process accumulated RX packets (generates ACKs)
                self.bridge.poll();
                // Drain ACKs to free TX buffer space for next batch
                self.drain_wg_packets();
            }
        }
        if drops > 0 {
            warn!(
                shard_index = self.config.shard_index,
                batch_size = count,
                drops,
                "WG reply batch RX drops (buffer overflow)"
            );
        }
        if count > 0 {
            trace!(
                shard_index = self.config.shard_index,
                batch_size = count,
                "WG reply batch drained"
            );
        }
    }

    /// Handle a command
    async fn handle_command(&mut self, cmd: ShardCommand) {
        self.stats.commands_processed += 1;

        match cmd {
            ShardCommand::TcpConnect { dest, reply, data_tx, data_rx } => {
                let result = self.handle_tcp_connect(dest, data_tx, data_rx);
                let _ = reply.send(result);
            }
            ShardCommand::TcpSend { session_id, data } => {
                self.handle_tcp_send(session_id, data);
            }
            ShardCommand::TcpClose { session_id } => {
                self.handle_tcp_close(session_id);
            }
            ShardCommand::UdpSend { src, dest, data, reply } => {
                let result = self.handle_udp_send(src, dest, data);
                if let Some(reply_tx) = reply {
                    let _ = reply_tx.send(result);
                }
            }
            ShardCommand::UdpClose { session_id } => {
                self.handle_udp_close(session_id);
            }
            ShardCommand::Shutdown => {
                self.shutdown = true;
            }
            ShardCommand::GetStats { reply } => {
                let _ = reply.send(self.stats.clone());
            }
        }
    }

    /// Handle TCP connect command
    fn handle_tcp_connect(
        &mut self,
        dest: SocketAddr,
        data_tx: mpsc::Sender<Bytes>,
        data_rx: mpsc::Receiver<Bytes>,
    ) -> Result<u64> {
        // Convert destination
        let remote = socket_addr_to_endpoint(dest).ok_or_else(|| {
            NetBridgeError::InvalidAddress("IPv6 not supported".to_string())
        })?;

        // Allocate port
        let local_port = self.port_allocator.allocate()
            .ok_or_else(|| {
                warn!(
                    target: "netbridge::shard",
                    shard_index = self.config.shard_index,
                    ?remote,
                    "TCP port allocation failed: port range exhausted"
                );
                NetBridgeError::PortExhausted
            })?
            .take();

        // Create socket
        let handle = self.bridge.create_tcp_socket()?;

        // Initiate connection
        if let Err(e) = self.bridge.tcp_connect(handle, remote, local_port) {
            self.bridge.remove_socket(handle);
            self.port_allocator.release(local_port);
            return Err(e);
        }

        // Create session
        let session_id = self.alloc_session_id();
        let session = TcpSession {
            id: session_id,
            handle,
            local_port,
            remote,
            data_tx,
            last_active: Instant::now(),
            bytes_sent: 0,
            bytes_received: 0,
            pending_send: Vec::new(),
            pending_recv: None,
            data_rx,
        };

        self.tcp_sessions.insert(session_id, session);
        self.tcp_by_handle.insert(handle, session_id);
        self.stats.tcp_sessions_created += 1;

        debug!(
            shard_index = self.config.shard_index,
            session_id,
            ?remote,
            local_port,
            "TCP session created"
        );

        Ok(session_id)
    }

    /// Handle TCP send command
    fn handle_tcp_send(&mut self, session_id: u64, data: Bytes) {
        let Some(session) = self.tcp_sessions.get_mut(&session_id) else {
            warn!(session_id, "TCP session not found for send");
            return;
        };

        session.last_active = Instant::now();

        // Try to send immediately
        if self.bridge.tcp_can_send(session.handle) && session.pending_send.is_empty() {
            match self.bridge.tcp_send(session.handle, &data) {
                Ok(sent) => {
                    session.bytes_sent += sent as u64;
                    self.stats.tcp_bytes_sent += sent as u64;

                    // Buffer any unsent data
                    if sent < data.len() {
                        session.pending_send.extend_from_slice(&data[sent..]);
                    }
                }
                Err(e) => {
                    warn!(session_id, ?e, "TCP send error");
                }
            }
        } else {
            // Buffer the data
            session.pending_send.extend_from_slice(&data);
        }
    }

    /// Handle TCP close command
    fn handle_tcp_close(&mut self, session_id: u64) {
        if let Some(mut session) = self.tcp_sessions.remove(&session_id) {
            // Drain any remaining upload data before closing
            let mut close_drained: u64 = 0;
            while let Ok(data) = session.data_rx.try_recv() {
                if self.bridge.tcp_can_send(session.handle) && session.pending_send.is_empty() {
                    match self.bridge.tcp_send(session.handle, &data) {
                        Ok(sent) => {
                            close_drained += sent as u64;
                            session.bytes_sent += sent as u64;
                            self.stats.tcp_bytes_sent += sent as u64;
                            if sent < data.len() {
                                debug!(
                                    session_id,
                                    dropped = data.len() - sent,
                                    "TCP close: partial send, dropping remaining bytes"
                                );
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                } else {
                    break;
                }
            }

            if close_drained > 0 {
                debug!(
                    session_id,
                    close_drained,
                    "TCP close: flushed remaining upload data"
                );
            }

            self.tcp_by_handle.remove(&session.handle);
            self.bridge.tcp_close(session.handle);
            self.bridge.remove_socket(session.handle);
            self.port_allocator.release(session.local_port);
            self.stats.tcp_sessions_closed += 1;

            debug!(
                shard_index = self.config.shard_index,
                session_id,
                bytes_sent = session.bytes_sent,
                bytes_received = session.bytes_received,
                "TCP session closed"
            );
        }
    }

    /// Handle UDP send command
    fn handle_udp_send(
        &mut self,
        src: SocketAddr,
        dest: SocketAddr,
        data: Bytes,
    ) -> Result<u64> {
        let key = UdpSessionKey { src, dst: dest };

        // Find or create session
        let session_id = if let Some(&id) = self.udp_by_key.get(&key) {
            id
        } else {
            // Create new session
            let _remote = socket_addr_to_endpoint(dest).ok_or_else(|| {
                NetBridgeError::InvalidAddress("IPv6 not supported".to_string())
            })?;

            let local_port = self.port_allocator.allocate()
                .ok_or(NetBridgeError::PortExhausted)?
                .take();

            let handle = self.bridge.create_udp_socket()?;
            self.bridge.udp_bind(handle, local_port)?;

            let session_id = self.alloc_session_id();

            // Create a dummy channel for now (real implementation would use shared channel)
            let (data_tx, _data_rx) = mpsc::channel(128);

            let session = UdpSession {
                id: session_id,
                handle,
                local_port,
                client_src: src,
                dest,
                data_tx,
                last_active: Instant::now(),
                datagrams_sent: 0,
                datagrams_received: 0,
            };

            self.udp_sessions.insert(session_id, session);
            self.udp_by_key.insert(key, session_id);
            self.stats.udp_sessions_created += 1;

            debug!(
                shard_index = self.config.shard_index,
                session_id,
                %src,
                %dest,
                local_port,
                "UDP session created"
            );

            session_id
        };

        // Send the datagram
        let session = self.udp_sessions.get_mut(&session_id).unwrap();
        session.last_active = Instant::now();

        let remote = socket_addr_to_endpoint(dest).unwrap();
        if let Err(e) = self.bridge.udp_send(session.handle, &data, remote) {
            warn!(session_id, ?e, "UDP send error");
            return Err(e);
        }

        session.datagrams_sent += 1;
        self.stats.udp_datagrams_sent += 1;

        Ok(session_id)
    }

    /// Handle UDP close command
    fn handle_udp_close(&mut self, session_id: u64) {
        if let Some(session) = self.udp_sessions.remove(&session_id) {
            // Remove from key index
            let key = UdpSessionKey {
                src: session.client_src,
                dst: session.dest,
            };
            self.udp_by_key.remove(&key);

            self.bridge.udp_close(session.handle);
            self.bridge.remove_socket(session.handle);
            self.port_allocator.release(session.local_port);
            self.stats.udp_sessions_closed += 1;

            debug!(
                shard_index = self.config.shard_index,
                session_id,
                datagrams_sent = session.datagrams_sent,
                datagrams_received = session.datagrams_received,
                "UDP session closed"
            );
        }
    }

    /// Process TCP socket events
    fn process_tcp_sockets(&mut self) {
        // Collect session IDs to avoid borrow issues
        let session_ids: Vec<u64> = self.tcp_sessions.keys().copied().collect();

        // Take the reusable recv buffer out of self to avoid borrow conflicts.
        // mem::take replaces it with an empty Vec (zero-cost, no allocation).
        let mut recv_buf = std::mem::take(&mut self.tcp_recv_buf);

        for session_id in session_ids {
            let Some(session) = self.tcp_sessions.get_mut(&session_id) else {
                continue;
            };

            let handle = session.handle;

            // Try to send pending data
            if !session.pending_send.is_empty() && self.bridge.tcp_can_send(handle) {
                let pending = std::mem::take(&mut session.pending_send);
                match self.bridge.tcp_send(handle, &pending) {
                    Ok(sent) => {
                        session.bytes_sent += sent as u64;
                        self.stats.tcp_bytes_sent += sent as u64;
                        if sent < pending.len() {
                            session.pending_send = pending[sent..].to_vec();
                        }
                    }
                    Err(e) => {
                        warn!(session_id, ?e, "TCP send error");
                        session.pending_send = pending;
                    }
                }
            }

            // ── Per-session upload data drain ──
            // Drain upload data from per-session channel when buffer is available.
            // Only drain when pending_send is empty to maintain backpressure.
            if session.pending_send.is_empty() {
                const MAX_DRAIN_PER_SESSION: usize = 16;
                let mut drained = 0;
                while drained < MAX_DRAIN_PER_SESSION {
                    match session.data_rx.try_recv() {
                        Ok(data) => {
                            session.last_active = Instant::now();
                            if self.bridge.tcp_can_send(handle) {
                                match self.bridge.tcp_send(handle, &data) {
                                    Ok(sent) => {
                                        session.bytes_sent += sent as u64;
                                        self.stats.tcp_bytes_sent += sent as u64;
                                        if sent < data.len() {
                                            session.pending_send.extend_from_slice(&data[sent..]);
                                            break; // Buffer full, stop draining
                                        }
                                    }
                                    Err(e) => {
                                        warn!(session_id, ?e, "TCP send error from data_rx");
                                        break;
                                    }
                                }
                            } else {
                                // Socket can't send - buffer and stop draining
                                session.pending_send.extend_from_slice(&data);
                                break;
                            }
                            drained += 1;
                        }
                        Err(mpsc::error::TryRecvError::Empty) => break,
                        Err(mpsc::error::TryRecvError::Disconnected) => {
                            trace!(session_id, "Per-session data_rx disconnected (pump task exited)");
                            break;
                        }
                    }
                }
                if drained >= MAX_DRAIN_PER_SESSION {
                    self.stats.drain_limit_hits += 1;
                }
            }

            // First, try to flush any pending_recv from previous iteration
            if let Some(pending) = session.pending_recv.take() {
                match session.data_tx.try_send(pending) {
                    Ok(()) => {} // Successfully flushed
                    Err(mpsc::error::TrySendError::Full(data)) => {
                        // Still can't send - put it back and skip reading more
                        session.pending_recv = Some(data);
                        // Don't read from smoltcp - backpressure will stop remote sender
                        continue;
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        // Channel closed - session is dead
                        continue;
                    }
                }
            }

            // Check for received data (only if no pending_recv - backpressure)
            // PERF: Reuse recv_buf instead of allocating vec![0u8; 65536] per session per poll
            if self.bridge.tcp_can_recv(handle) {
                match self.bridge.tcp_recv(handle, &mut recv_buf) {
                    Ok(len) if len > 0 => {
                        session.bytes_received += len as u64;
                        self.stats.tcp_bytes_received += len as u64;
                        session.last_active = Instant::now();

                        // Send to client task (with backpressure)
                        // Allocates only `len` bytes (not 65536)
                        let data = Bytes::copy_from_slice(&recv_buf[..len]);
                        match session.data_tx.try_send(data) {
                            Ok(()) => {} // Sent successfully
                            Err(mpsc::error::TrySendError::Full(data)) => {
                                // Channel full - buffer for next iteration
                                // Data is safe: smoltcp already ACK'd it, we MUST deliver it
                                trace!(session_id, len = data.len(), "TCP download channel full, buffering in pending_recv");
                                session.pending_recv = Some(data);
                            }
                            Err(mpsc::error::TrySendError::Closed(_)) => {
                                // Client disconnected
                                trace!(session_id, "TCP data channel closed");
                            }
                        }
                    }
                    Ok(_) => {}
                    Err(e) => {
                        trace!(session_id, ?e, "TCP recv error");
                    }
                }
            }

            // Check socket state for cleanup
            let state = self.bridge.tcp_state(handle);
            if matches!(state, TcpState::Closed | TcpState::TimeWait) {
                // Session will be cleaned up by cleanup_expired_sessions
            }
        }

        // Put the buffer back for reuse on the next poll cycle
        self.tcp_recv_buf = recv_buf;
    }

    /// Process UDP socket events
    fn process_udp_sockets(&mut self) {
        let session_ids: Vec<u64> = self.udp_sessions.keys().copied().collect();

        for session_id in session_ids {
            let Some(session) = self.udp_sessions.get_mut(&session_id) else {
                continue;
            };

            let handle = session.handle;

            // Check for received datagrams
            while self.bridge.udp_can_recv(handle) {
                match self.bridge.udp_recv(handle) {
                    Ok((data, _remote)) => {
                        session.datagrams_received += 1;
                        self.stats.udp_datagrams_received += 1;
                        session.last_active = Instant::now();

                        // Send to client task
                        if session.data_tx.try_send(Bytes::from(data)).is_err() {
                            warn!(session_id, "UDP data channel full or closed");
                        }
                    }
                    Err(e) => {
                        trace!(session_id, ?e, "UDP recv error");
                        break;
                    }
                }
            }
        }
    }

    /// Maximum pending WG TX packets before dropping (prevents unbounded growth)
    const MAX_PENDING_WG_TX: usize = 4096;

    /// Drain TX packets and send through WG channel (NON-BLOCKING)
    ///
    /// CRITICAL: This method must NEVER block/await. If the wg_tx channel is full,
    /// unsent packets are buffered in `pending_wg_tx` and retried on the next
    /// event loop iteration.
    ///
    /// CRITICAL: VirtualDevice TX MUST always be drained. If the device TX buffer
    /// fills up, smoltcp cannot generate ANY packets — not data segments, not ACKs,
    /// not retransmissions. This would stall both upload and download directions.
    /// The `pending_wg_tx` buffer exists precisely to decouple smoltcp's output
    /// rate from the WG TX channel's drain rate.
    fn drain_wg_packets(&mut self) {
        // First, try to flush pending TX from previous iterations (FIFO order)
        while let Some(bytes) = self.pending_wg_tx.front().cloned() {
            match self.wg_tx.try_send(bytes) {
                Ok(()) => {
                    self.pending_wg_tx.pop_front();
                }
                Err(mpsc::error::TrySendError::Full(_)) => {
                    break; // Channel full, but MUST still drain device TX below
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    warn!(shard_index = self.config.shard_index, "WG TX channel closed, initiating shutdown");
                    self.shutdown = true;
                    return;
                }
            }
        }

        // ALWAYS drain smoltcp device TX — this is critical for preventing
        // VirtualDevice TX buffer overflow which would block smoltcp entirely.
        // When pending_wg_tx has items, append to it (maintain FIFO order).
        // When pending_wg_tx is empty, try wg_tx directly for zero-copy fast path.
        let has_pending = !self.pending_wg_tx.is_empty();
        for packet in self.bridge.drain_tx() {
            self.stats.wg_packets_sent += 1;
            let bytes = Bytes::from(packet);

            if has_pending {
                // Pending queue is non-empty: append to maintain FIFO ordering.
                // Sending directly to wg_tx would reorder packets (new before old).
                if self.pending_wg_tx.len() < Self::MAX_PENDING_WG_TX {
                    self.pending_wg_tx.push_back(bytes);
                } else {
                    warn!(
                        shard_index = self.config.shard_index,
                        pending = self.pending_wg_tx.len(),
                        "Pending WG TX overflow, dropping packet"
                    );
                }
            } else {
                // Fast path: no pending items, try direct send
                match self.wg_tx.try_send(bytes) {
                    Ok(()) => {}
                    Err(mpsc::error::TrySendError::Full(bytes)) => {
                        if self.pending_wg_tx.len() < Self::MAX_PENDING_WG_TX {
                            self.pending_wg_tx.push_back(bytes);
                        } else {
                            warn!(
                                shard_index = self.config.shard_index,
                                pending = self.pending_wg_tx.len(),
                                "Pending WG TX overflow, dropping packet"
                            );
                        }
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        warn!(shard_index = self.config.shard_index, "WG TX channel closed, initiating shutdown");
                        self.shutdown = true;
                        return;
                    }
                }
            }
        }
    }

    /// Cleanup expired sessions
    fn cleanup_expired_sessions(&mut self) {
        self.stats.cleanup_runs += 1;
        let now = Instant::now();
        let mut cleaned_this_run: u64 = 0;

        // Cleanup TCP sessions
        let tcp_to_remove: Vec<u64> = self.tcp_sessions.iter()
            .filter(|(_, s)| {
                let idle = now.duration_since(s.last_active);
                let state = self.bridge.tcp_state(s.handle);
                idle > self.config.tcp_idle_timeout ||
                matches!(state, TcpState::Closed | TcpState::TimeWait)
            })
            .map(|(&id, _)| id)
            .collect();

        for id in tcp_to_remove {
            self.handle_tcp_close(id);
            self.stats.sessions_cleaned += 1;
            cleaned_this_run += 1;
        }

        // Cleanup UDP sessions
        let udp_to_remove: Vec<u64> = self.udp_sessions.iter()
            .filter(|(_, s)| {
                now.duration_since(s.last_active) > self.config.udp_idle_timeout
            })
            .map(|(&id, _)| id)
            .collect();

        for id in udp_to_remove {
            self.handle_udp_close(id);
            self.stats.sessions_cleaned += 1;
            cleaned_this_run += 1;
        }

        if cleaned_this_run > 0 {
            trace!(
                shard_index = self.config.shard_index,
                cleaned = cleaned_this_run,
                tcp_sessions = self.tcp_sessions.len(),
                udp_sessions = self.udp_sessions.len(),
                "Cleanup completed"
            );
        }

        debug!(
            shard_index = self.config.shard_index,
            tcp_sessions = self.tcp_sessions.len(),
            udp_sessions = self.udp_sessions.len(),
            pending_wg_tx = self.pending_wg_tx.len(),
            poll_count = self.stats.poll_count,
            upload_notify_wakeups = self.stats.upload_notify_wakeups,
            drain_limit_hits = self.stats.drain_limit_hits,
            second_poll_productive = self.stats.second_poll_productive,
            "Shard health summary"
        );
    }

    /// Get current statistics
    #[must_use]
    pub fn stats(&self) -> &SmoltcpShardStats {
        &self.stats
    }
}

impl std::fmt::Debug for SmoltcpShard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SmoltcpShard")
            .field("shard_index", &self.config.shard_index)
            .field("tcp_sessions", &self.tcp_sessions.len())
            .field("udp_sessions", &self.udp_sessions.len())
            .field("shutdown", &self.shutdown)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shard_config_default() {
        let config = SmoltcpShardConfig::default();
        assert_eq!(config.shard_index, 0);
        assert_eq!(config.total_shards, 1);
        assert_eq!(config.local_ip, IpAddress::v4(10, 200, 200, 2));
    }

    #[test]
    fn test_shard_config_with_ipv4() {
        let config = SmoltcpShardConfig::with_ipv4(2, 4, 192, 168, 1, 1);
        assert_eq!(config.shard_index, 2);
        assert_eq!(config.total_shards, 4);
        assert_eq!(config.local_ip, IpAddress::v4(192, 168, 1, 1));
    }

    #[test]
    fn test_stats_default() {
        let stats = SmoltcpShardStats::default();
        assert_eq!(stats.commands_processed, 0);
        assert_eq!(stats.tcp_sessions_created, 0);
    }

    #[tokio::test]
    async fn test_shard_creation() {
        let config = SmoltcpShardConfig::default();
        let (_cmd_tx, cmd_rx) = mpsc::channel(128);
        let (_wg_reply_tx, wg_reply_rx) = mpsc::channel(128);
        let (wg_tx, _wg_rx) = mpsc::channel(128);

        let shard = SmoltcpShard::new(config, cmd_rx, wg_reply_rx, wg_tx, Arc::new(Notify::new()));

        assert_eq!(shard.config.shard_index, 0);
        assert!(shard.tcp_sessions.is_empty());
        assert!(shard.udp_sessions.is_empty());
        assert!(!shard.shutdown);
    }

    #[tokio::test]
    async fn test_shard_shutdown() {
        let config = SmoltcpShardConfig::default();
        let (cmd_tx, cmd_rx) = mpsc::channel(128);
        let (_wg_reply_tx, wg_reply_rx) = mpsc::channel(128);
        let (wg_tx, _wg_rx) = mpsc::channel(128);

        let shard = SmoltcpShard::new(config, cmd_rx, wg_reply_rx, wg_tx, Arc::new(Notify::new()));

        // Spawn the shard
        let handle = tokio::spawn(shard.run());

        // Send shutdown command
        cmd_tx.send(ShardCommand::Shutdown).await.unwrap();

        // Shard should exit cleanly
        tokio::time::timeout(Duration::from_secs(1), handle)
            .await
            .expect("Shard should shutdown within 1 second")
            .expect("Shard task should complete without panic");
    }

    #[tokio::test]
    async fn test_shard_get_stats() {
        let config = SmoltcpShardConfig::default();
        let (cmd_tx, cmd_rx) = mpsc::channel(128);
        let (_wg_reply_tx, wg_reply_rx) = mpsc::channel(128);
        let (wg_tx, _wg_rx) = mpsc::channel(128);

        let shard = SmoltcpShard::new(config, cmd_rx, wg_reply_rx, wg_tx, Arc::new(Notify::new()));

        let handle = tokio::spawn(shard.run());

        // Request stats
        let (reply_tx, reply_rx) = oneshot::channel();
        cmd_tx.send(ShardCommand::GetStats { reply: reply_tx }).await.unwrap();

        let stats = reply_rx.await.expect("Should receive stats");
        assert_eq!(stats.tcp_sessions_created, 0);

        // Shutdown
        cmd_tx.send(ShardCommand::Shutdown).await.unwrap();
        let _ = handle.await;
    }
}
