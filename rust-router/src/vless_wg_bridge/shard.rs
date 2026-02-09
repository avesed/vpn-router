//! SmoltcpShard - Single-task smoltcp instance for the Event Bus architecture
//!
//! This module provides `SmoltcpShard`, which owns a smoltcp interface and socket set
//! exclusively within a single async task. This eliminates the `Arc<Mutex<SmoltcpBridge>>`
//! lock contention present in the original architecture.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────────┐
//! │                         SmoltcpShard (single task)                          │
//! ├─────────────────────────────────────────────────────────────────────────────┤
//! │                                                                             │
//! │  ┌─────────────────────┐    ┌─────────────────────┐    ┌────────────────┐ │
//! │  │ smoltcp Interface   │    │ smoltcp SocketSet   │    │ VirtualDevice  │ │
//! │  │ (OWNED, no Mutex)   │    │ (OWNED, no Mutex)   │    │ (TX/RX queues) │ │
//! │  └─────────────────────┘    └─────────────────────┘    └────────────────┘ │
//! │                                                                             │
//! │  ┌─────────────────────────────────────────────────────────────────────┐   │
//! │  │                     Main Event Loop                                  │   │
//! │  │                                                                      │   │
//! │  │  tokio::select! {                                                   │   │
//! │  │      biased;  // Priority ordering                                   │   │
//! │  │                                                                      │   │
//! │  │      // Highest: WG reply packets (TCP retransmit timing)            │   │
//! │  │      Some(packet) = wg_reply_rx.recv() => handle_wg_packet()        │   │
//! │  │                                                                      │   │
//! │  │      // Medium: Business events (TCP connect, data, UDP send)        │   │
//! │  │      Some(event) = event_rx.recv() => handle_event()                │   │
//! │  │                                                                      │   │
//! │  │      // Low: Timer-based polling (retransmissions, keepalives)       │   │
//! │  │      _ = sleep(poll_delay) => poll_smoltcp()                         │   │
//! │  │  }                                                                    │   │
//! │  └─────────────────────────────────────────────────────────────────────┘   │
//! │                                                                             │
//! │  ┌───────────────────┐    ┌───────────────────┐                           │
//! │  │ TCP Sessions      │    │ UDP Sessions      │                           │
//! │  │ HashMap<ConnId,   │    │ HashMap<UdpKey,   │                           │
//! │  │   ShardTcpSession>│    │   ShardUdpSession>│                           │
//! │  └───────────────────┘    └───────────────────┘                           │
//! └─────────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Key Benefits
//!
//! - **No lock contention**: smoltcp is owned by a single task
//! - **Event-driven**: Uses `biased select!` for priority processing
//! - **Efficient polling**: Uses `poll_delay()` instead of fixed intervals
//!
//! # Usage
//!
//! ```ignore
//! use rust_router::vless_wg_bridge::shard::{SmoltcpShard, ShardConfig};
//! use rust_router::vless_wg_bridge::event_channel::create_event_channel;
//!
//! // Create event channel
//! let (event_tx, event_rx) = create_event_channel(Default::default());
//!
//! // Create WG reply channel
//! let (wg_reply_tx, wg_reply_rx) = tokio::sync::mpsc::channel(1024);
//! let (wg_tx, _) = tokio::sync::mpsc::channel(1024);
//!
//! // Create shard config
//! let config = ShardConfig {
//!     shard_index: 0,
//!     local_ip: smoltcp::wire::IpAddress::v4(10, 200, 200, 2),
//!     local_cidr: smoltcp::wire::IpCidr::new(
//!         smoltcp::wire::IpAddress::v4(10, 200, 200, 0),
//!         24,
//!     ),
//!     mtu: 1420,
//! };
//!
//! // Create and run shard
//! let shard = SmoltcpShard::new(config, event_rx, wg_reply_rx, wg_tx);
//! tokio::spawn(shard.run());
//! ```

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use bytes::Bytes;
use smoltcp::iface::{Config as IfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp::{
    Socket as TcpSocket, SocketBuffer as TcpSocketBuffer, State as TcpState,
};
use smoltcp::socket::udp::{
    PacketBuffer as UdpPacketBuffer, PacketMetadata as UdpPacketMetadata, Socket as UdpSocket,
};
use smoltcp::time::Instant as SmoltcpInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, Ipv4Address};
use tokio::sync::mpsc;
use tracing::{debug, info, trace, warn};

use crate::netbridge::{ConnId, ConnIdAllocator, NetBridgeError as BridgeError, PortAllocator};

use super::cleanup::{CleanupConfig, CleanupStats};
use super::event_channel::EventReceiver;
use super::events::{BridgeEvent, TcpReply, UdpReply, UdpSessionKey};
use super::tcp_session::{TcpSession as ShardTcpSession, TcpSessionState};
use super::udp_session::ShardUdpSession;

// =============================================================================
// Constants
// =============================================================================

/// Minimum poll interval (1ms) - prevents busy-looping
pub const MIN_POLL_INTERVAL: Duration = Duration::from_millis(1);

/// Maximum poll interval (50ms) - ensures timely retransmissions
pub const MAX_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Default poll interval when smoltcp has no specific timing requirements
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_millis(5);

/// Maximum number of sockets per shard
pub const SHARD_MAX_SOCKETS: usize = 1024;

/// Default WireGuard MTU
pub const WG_MTU: usize = 1420;

/// TCP Maximum Segment Size (MTU - IP header - TCP header)
pub const TCP_MSS: u16 = 1380;

/// TCP receive buffer size per socket
pub const TCP_RX_BUFFER: usize = 65536;

/// TCP transmit buffer size per socket
pub const TCP_TX_BUFFER: usize = 65536;

/// UDP receive buffer size per socket
pub const UDP_RX_BUFFER: usize = 65536;

/// UDP transmit buffer size per socket
pub const UDP_TX_BUFFER: usize = 65536;

/// UDP packet metadata count
pub const UDP_PACKET_META: usize = 64;

/// Maximum TX buffer capacity for virtual device
const DEVICE_TX_BUFFER_CAPACITY: usize = 256;

/// Maximum RX buffer capacity for virtual device
const DEVICE_RX_BUFFER_CAPACITY: usize = 256;

// =============================================================================
// WG Batch Constants
// =============================================================================

/// Maximum number of WG packets to collect before sending
///
/// Batching packets improves throughput by reducing channel overhead.
/// This value balances latency (smaller = lower latency) and throughput
/// (larger = higher throughput).
pub const WG_BATCH_SIZE: usize = 16;

/// Maximum time to wait for a batch to fill (in microseconds)
///
/// If fewer than `WG_BATCH_SIZE` packets are available, we wait at most
/// this long before sending the partial batch. This prevents latency
/// spikes when traffic is light.
pub const WG_BATCH_TIMEOUT_US: u64 = 100;

// =============================================================================
// Shard Configuration
// =============================================================================

/// Configuration for creating a SmoltcpShard
#[derive(Debug, Clone)]
pub struct ShardConfig {
    /// Shard index (used for connection ID encoding)
    pub shard_index: u16,
    /// Total number of shards (used for port partitioning)
    pub total_shards: u16,
    /// Local IP address for the smoltcp interface
    pub local_ip: IpAddress,
    /// IP CIDR for the smoltcp interface (e.g., 10.200.200.0/24)
    pub local_cidr: IpCidr,
    /// Maximum transmission unit (typically 1420 for WireGuard)
    pub mtu: usize,
}

impl ShardConfig {
    /// Create a new shard config with common defaults
    #[must_use]
    pub fn new(shard_index: u16, total_shards: u16, local_ip: IpAddress, local_cidr: IpCidr) -> Self {
        Self {
            shard_index,
            total_shards,
            local_ip,
            local_cidr,
            mtu: WG_MTU,
        }
    }

    /// Create a config with a custom MTU
    #[must_use]
    pub fn with_mtu(mut self, mtu: usize) -> Self {
        self.mtu = mtu;
        self
    }
}

// =============================================================================
// Shard Statistics
// =============================================================================

/// Statistics tracked by the shard
#[derive(Debug, Default, Clone)]
pub struct ShardStats {
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
    /// WireGuard packets dropped (channel closed or buffer full)
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
    /// UDP bytes sent
    pub udp_bytes_sent: u64,
    /// UDP bytes received
    pub udp_bytes_received: u64,
    /// UDP send errors
    pub udp_send_errors: u64,
    /// UDP reply channel full (dropped replies)
    pub udp_replies_dropped: u64,
    /// UDP sessions expired (timed out)
    pub udp_sessions_expired: u64,
    /// smoltcp poll count
    pub poll_count: u64,
    /// Cleanup statistics (runs, timeouts, etc.)
    pub cleanup: CleanupStats,
}

impl ShardStats {
    /// Create new statistics with all zeros
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

// =============================================================================
// Virtual Device for smoltcp
// =============================================================================

/// Virtual network device for smoltcp that uses in-memory buffers
///
/// This device operates at the IP layer (Medium::Ip) since WireGuard
/// handles packets at Layer 3.
struct VirtualDevice {
    /// MTU for the device
    mtu: usize,
    /// Packets to transmit (smoltcp -> WG)
    tx_buffer: Vec<Vec<u8>>,
    /// Packets received (WG -> smoltcp)
    rx_buffer: Vec<Vec<u8>>,
}

impl VirtualDevice {
    /// Create a new virtual device with the given MTU
    fn new(mtu: usize) -> Self {
        Self {
            mtu,
            tx_buffer: Vec::with_capacity(DEVICE_TX_BUFFER_CAPACITY),
            rx_buffer: Vec::with_capacity(DEVICE_RX_BUFFER_CAPACITY),
        }
    }

    /// Push a received packet to the RX buffer
    fn push_rx(&mut self, packet: Vec<u8>) {
        if self.rx_buffer.len() < DEVICE_RX_BUFFER_CAPACITY {
            self.rx_buffer.push(packet);
        } else {
            trace!("Virtual device RX buffer full, dropping packet");
        }
    }

    /// Drain all TX packets
    fn drain_tx(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.tx_buffer)
    }

    /// Check if there are RX packets available
    fn has_rx(&self) -> bool {
        !self.rx_buffer.is_empty()
    }

    /// Check if the RX buffer can accept more packets
    fn can_push_rx(&self) -> bool {
        self.rx_buffer.len() < DEVICE_RX_BUFFER_CAPACITY
    }

    /// Check if the TX buffer has packets to send
    fn has_tx(&self) -> bool {
        !self.tx_buffer.is_empty()
    }

    /// Get the number of pending TX packets
    fn tx_count(&self) -> usize {
        self.tx_buffer.len()
    }
}

/// RX token for the virtual device
struct VirtualRxToken {
    packet: Vec<u8>,
}

impl RxToken for VirtualRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.packet)
    }
}

/// TX token for the virtual device
struct VirtualTxToken<'a> {
    tx_buffer: &'a mut Vec<Vec<u8>>,
}

impl<'a> TxToken for VirtualTxToken<'a> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = vec![0u8; len];
        let result = f(&mut buffer);
        if self.tx_buffer.len() < DEVICE_TX_BUFFER_CAPACITY {
            self.tx_buffer.push(buffer);
        }
        result
    }
}

impl Device for VirtualDevice {
    type RxToken<'a> = VirtualRxToken where Self: 'a;
    type TxToken<'a> = VirtualTxToken<'a> where Self: 'a;

    fn receive(&mut self, _timestamp: SmoltcpInstant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        if let Some(packet) = self.rx_buffer.pop() {
            Some((
                VirtualRxToken { packet },
                VirtualTxToken {
                    tx_buffer: &mut self.tx_buffer,
                },
            ))
        } else {
            None
        }
    }

    fn transmit(&mut self, _timestamp: SmoltcpInstant) -> Option<Self::TxToken<'_>> {
        if self.tx_buffer.len() < DEVICE_TX_BUFFER_CAPACITY {
            Some(VirtualTxToken {
                tx_buffer: &mut self.tx_buffer,
            })
        } else {
            None
        }
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        // Enable checksum offloading since we're in userspace
        caps.checksum.ipv4 = smoltcp::phy::Checksum::Tx;
        caps.checksum.tcp = smoltcp::phy::Checksum::Tx;
        caps.checksum.udp = smoltcp::phy::Checksum::Tx;
        caps
    }
}

// =============================================================================
// SmoltcpShard
// =============================================================================

/// smoltcp Shard - single task owns the smoltcp instance
///
/// This struct owns all smoltcp resources (Interface, SocketSet) without any
/// mutex protection. It is designed to be consumed by a single async task
/// via the `run()` method.
///
/// # Thread Safety
///
/// `SmoltcpShard` is `Send` but NOT `Sync`. It should be moved into a single
/// task and run to completion. All communication happens through channels.
pub struct SmoltcpShard {
    /// Shard index
    shard_index: u16,

    /// smoltcp interface (OWNED, no Mutex!)
    iface: Interface,

    /// smoltcp socket set (OWNED)
    sockets: SocketSet<'static>,

    /// Virtual device for packet I/O
    device: VirtualDevice,

    /// Connection ID allocator for this shard
    conn_id_allocator: ConnIdAllocator,

    /// Port allocator for ephemeral ports
    port_allocator: PortAllocator,

    /// TCP sessions by connection ID
    tcp_sessions: HashMap<ConnId, ShardTcpSession>,

    /// TCP socket handle to connection ID mapping (for reverse lookup)
    tcp_handle_to_conn: HashMap<SocketHandle, ConnId>,

    /// Allocated ports by connection ID (for cleanup)
    tcp_ports: HashMap<ConnId, u16>,

    /// UDP sessions by session key
    udp_sessions: HashMap<UdpSessionKey, ShardUdpSession>,

    /// UDP socket handle to session key mapping (for reverse lookup)
    udp_handle_to_session: HashMap<SocketHandle, UdpSessionKey>,

    /// Allocated ports by UDP session key (for cleanup)
    udp_ports: HashMap<UdpSessionKey, u16>,

    /// Event receiver channel
    event_rx: EventReceiver,

    /// WireGuard reply receiver channel
    wg_reply_rx: mpsc::Receiver<Bytes>,

    /// WireGuard transmit channel
    wg_tx: mpsc::Sender<Bytes>,

    /// Shutdown flag
    shutdown: bool,

    /// Statistics
    stats: ShardStats,

    /// Cleanup configuration
    cleanup_config: CleanupConfig,

    /// Reference instant for smoltcp time
    start_instant: std::time::Instant,

    /// Local IP address for this shard
    local_ip: IpAddress,
}

impl SmoltcpShard {
    /// Create a new smoltcp shard
    ///
    /// # Arguments
    ///
    /// * `config` - Shard configuration
    /// * `event_rx` - Event receiver channel from the public API
    /// * `wg_reply_rx` - WireGuard reply packet receiver
    /// * `wg_tx` - WireGuard transmit channel
    #[must_use]
    pub fn new(
        config: ShardConfig,
        event_rx: EventReceiver,
        wg_reply_rx: mpsc::Receiver<Bytes>,
        wg_tx: mpsc::Sender<Bytes>,
    ) -> Self {
        let start_instant = std::time::Instant::now();
        let smoltcp_now = SmoltcpInstant::from_millis(0);

        // Create virtual device
        let mut device = VirtualDevice::new(config.mtu);

        // Create smoltcp interface
        let iface_config = IfaceConfig::new(HardwareAddress::Ip);
        let mut iface = Interface::new(iface_config, &mut device, smoltcp_now);

        // Configure IP address - use /32 for the host IP (point-to-point tunnel)
        // Note: We use local_ip with /32 prefix, NOT local_cidr (network address)
        // This matches how smoltcp_bridge.rs configures its interface
        iface.update_ip_addrs(|addrs| {
            let _ = addrs.push(IpCidr::new(config.local_ip, 32));
        });

        // Create socket set
        let sockets = SocketSet::new(Vec::new());

        // Create connection ID allocator for this shard
        let conn_id_allocator = ConnIdAllocator::with_shard(config.shard_index);

        info!(
            "SmoltcpShard {} created: local_ip={}, mtu={}",
            config.shard_index, config.local_ip, config.mtu
        );

        Self {
            shard_index: config.shard_index,
            iface,
            sockets,
            device,
            conn_id_allocator,
            // Use partitioned port allocator to avoid port collisions between shards
            // when all shards share the same tunnel IP
            port_allocator: PortAllocator::for_shard(config.shard_index, config.total_shards),
            tcp_sessions: HashMap::new(),
            tcp_handle_to_conn: HashMap::new(),
            tcp_ports: HashMap::new(),
            udp_sessions: HashMap::new(),
            udp_handle_to_session: HashMap::new(),
            udp_ports: HashMap::new(),
            event_rx,
            wg_reply_rx,
            wg_tx,
            shutdown: false,
            stats: ShardStats::new(),
            cleanup_config: CleanupConfig::default(),
            start_instant,
            local_ip: config.local_ip,
        }
    }

    /// Create a new smoltcp shard with custom cleanup configuration
    ///
    /// # Arguments
    ///
    /// * `config` - Shard configuration
    /// * `event_rx` - Event receiver channel from the public API
    /// * `wg_reply_rx` - WireGuard reply packet receiver
    /// * `wg_tx` - WireGuard transmit channel
    /// * `cleanup_config` - Custom cleanup configuration
    #[must_use]
    pub fn with_cleanup_config(
        config: ShardConfig,
        event_rx: EventReceiver,
        wg_reply_rx: mpsc::Receiver<Bytes>,
        wg_tx: mpsc::Sender<Bytes>,
        cleanup_config: CleanupConfig,
    ) -> Self {
        let mut shard = Self::new(config, event_rx, wg_reply_rx, wg_tx);
        shard.cleanup_config = cleanup_config;
        shard
    }

    /// Get the current smoltcp timestamp
    fn smoltcp_now(&self) -> SmoltcpInstant {
        let elapsed = self.start_instant.elapsed();
        SmoltcpInstant::from_millis(elapsed.as_millis() as i64)
    }

    /// Main event loop (consumes self)
    ///
    /// This method runs the shard's event loop until shutdown is requested
    /// or all senders are dropped.
    ///
    /// # Event Priority
    ///
    /// Events are processed in priority order using `biased select!`:
    /// 1. WireGuard reply packets (highest - TCP retransmit timing)
    /// 2. Business events (TCP connect, data, UDP send)
    /// 3. Timer-based polling (retransmissions, keepalives)
    /// 4. Periodic cleanup (lowest - runs every 30s by default)
    ///
    /// # Cleanup Optimization (Task 2.5)
    ///
    /// Session cleanup runs on a separate timer instead of every poll.
    /// This reduces CPU overhead from checking session timeouts on every
    /// packet, which could happen 1000+ times per second.
    pub async fn run(mut self) {
        info!("SmoltcpShard {} starting event loop", self.shard_index);

        // Create cleanup timer based on configuration
        let cleanup_interval = self.cleanup_config.cleanup_interval();
        let mut cleanup_timer = tokio::time::interval(cleanup_interval);
        // Skip the first immediate tick
        cleanup_timer.tick().await;

        info!(
            "SmoltcpShard {}: cleanup interval = {:?}",
            self.shard_index, cleanup_interval
        );

        loop {
            if self.shutdown {
                info!("SmoltcpShard {} shutting down", self.shard_index);
                break;
            }

            let poll_delay = self.poll_delay();

            tokio::select! {
                biased;

                // Highest priority: WG reply packets
                Some(packet) = self.wg_reply_rx.recv() => {
                    self.handle_wg_packet(packet);
                    self.poll_smoltcp();
                    self.process_socket_events();
                    self.drain_and_send_wg_packets().await;
                }

                // Medium priority: Business events
                Some(event) = self.event_rx.recv() => {
                    self.handle_event(event).await;
                    self.poll_smoltcp();
                    self.process_socket_events();
                    self.drain_and_send_wg_packets().await;
                }

                // Low priority: Timer-based polling
                _ = tokio::time::sleep(poll_delay) => {
                    self.poll_smoltcp();
                    self.process_socket_events();
                    self.drain_and_send_wg_packets().await;
                }

                // Lowest priority: Periodic cleanup (Task 2.5)
                _ = cleanup_timer.tick() => {
                    self.cleanup_expired_sessions();
                }
            }
        }

        info!(
            "SmoltcpShard {} event loop ended. Stats: {:?}",
            self.shard_index, self.stats
        );
    }

    /// Handle a WireGuard packet (highest priority)
    ///
    /// This method receives an IP packet decrypted from the WireGuard tunnel
    /// and feeds it to the smoltcp virtual device for processing. The packet
    /// will be processed by smoltcp during the next `poll_smoltcp()` call.
    ///
    /// # Performance Notes
    ///
    /// - Packets are copied into the device's RX buffer (unavoidable due to
    ///   smoltcp's ownership model)
    /// - If the RX buffer is full, the packet is dropped and counted
    /// - Statistics are updated atomically for monitoring
    fn handle_wg_packet(&mut self, packet: Bytes) {
        let packet_len = packet.len();
        trace!(
            "Shard {}: Received {} byte WG packet",
            self.shard_index,
            packet_len
        );

        // Check if device can accept the packet before converting
        if !self.device.can_push_rx() {
            warn!(
                "Shard {}: WG RX buffer full, dropping {} byte packet",
                self.shard_index, packet_len
            );
            self.stats.wg_packets_dropped += 1;
            return;
        }

        // Feed packet to virtual device
        self.device.push_rx(packet.to_vec());

        // Update statistics
        self.stats.wg_packets_received += 1;
        self.stats.wg_bytes_received += packet_len as u64;
    }

    /// Handle a business event
    async fn handle_event(&mut self, event: BridgeEvent) {
        trace!("Shard {}: Handling event: {}", self.shard_index, event);
        self.stats.events_processed += 1;

        match event {
            BridgeEvent::TcpConnect {
                conn_id,
                dest_addr,
                reply_tx,
            } => {
                self.handle_tcp_connect(conn_id, dest_addr, reply_tx);
            }
            BridgeEvent::TcpData { conn_id, data } => {
                self.handle_tcp_data(conn_id, data);
            }
            BridgeEvent::TcpCloseWrite { conn_id } => {
                self.handle_tcp_close_write(conn_id);
            }
            BridgeEvent::TcpAbort { conn_id } => {
                self.handle_tcp_abort(conn_id);
            }
            BridgeEvent::UdpSend {
                session_key,
                dest,
                data,
                reply_tx,
            } => {
                self.handle_udp_send(session_key, dest, data, reply_tx);
            }
            BridgeEvent::UdpClose { session_key } => {
                self.handle_udp_close(session_key);
            }
            BridgeEvent::WgPacket { data } => {
                // WG packets can also come through the event channel
                self.handle_wg_packet(data);
            }
            BridgeEvent::Shutdown => {
                info!("Shard {}: Received shutdown event", self.shard_index);
                self.shutdown = true;
            }
        }
    }

    /// Handle TCP connect event
    ///
    /// Creates a smoltcp TCP socket, allocates an ephemeral port, and initiates
    /// a connection to the destination address. The connection will complete
    /// asynchronously - check `process_tcp_sockets()` for state transitions.
    fn handle_tcp_connect(
        &mut self,
        conn_id: u64,
        dest_addr: SocketAddr,
        reply_tx: mpsc::Sender<TcpReply>,
    ) {
        info!(
            "[SHARD {}] Received TcpConnect: conn_id={}, dest={}",
            self.shard_index, conn_id, dest_addr
        );

        let conn_id = ConnId::from_raw(conn_id);

        // Allocate ephemeral port
        let local_port = match self.port_allocator.allocate() {
            Some(guard) => guard.take(), // Take ownership of the port
            None => {
                warn!(
                    "Shard {}: Port exhausted for conn_id={}",
                    self.shard_index, conn_id
                );
                // Send connection failed reply
                let _ = reply_tx.try_send(TcpReply::ConnectFailed {
                    error: BridgeError::PortExhausted,
                });
                return;
            }
        };

        // Create TCP socket with appropriate buffer sizes
        let rx_buffer = TcpSocketBuffer::new(vec![0; TCP_RX_BUFFER]);
        let tx_buffer = TcpSocketBuffer::new(vec![0; TCP_TX_BUFFER]);
        let mut socket = TcpSocket::new(rx_buffer, tx_buffer);

        // Configure socket options
        socket.set_nagle_enabled(false); // Disable Nagle for low latency
        socket.set_keep_alive(Some(smoltcp::time::Duration::from_secs(60)));

        // Add socket to the socket set
        let handle = self.sockets.add(socket);

        // Convert destination address to smoltcp endpoint
        let Some(remote_endpoint) = socket_addr_to_endpoint(dest_addr) else {
            // IPv6 not supported
            warn!(
                "Shard {}: IPv6 destination not supported: {:?}",
                self.shard_index, dest_addr
            );
            self.sockets.remove(handle);
            self.port_allocator.release_immediate(local_port);
            let _ = reply_tx.try_send(TcpReply::ConnectFailed {
                error: BridgeError::InvalidAddress("IPv6 not supported".to_string()),
            });
            return;
        };
        let local_endpoint = IpEndpoint::new(self.local_ip, local_port);

        // Initiate connection
        {
            let socket = self.sockets.get_mut::<TcpSocket>(handle);
            let cx = self.iface.context();

            if let Err(e) = socket.connect(cx, remote_endpoint, local_endpoint) {
                warn!(
                    "Shard {}: TCP connect failed for conn_id={}: {:?}",
                    self.shard_index, conn_id, e
                );
                // Clean up socket and port
                self.sockets.remove(handle);
                self.port_allocator.release_immediate(local_port);

                // Send connection failed reply
                let _ = reply_tx.try_send(TcpReply::ConnectFailed {
                    error: BridgeError::SmoltcpTcp(format!("connect error: {e:?}")),
                });
                return;
            }
        }

        // Create and store session
        let session = ShardTcpSession::new(conn_id, handle, dest_addr, reply_tx);
        self.tcp_sessions.insert(conn_id, session);
        self.tcp_handle_to_conn.insert(handle, conn_id);
        self.tcp_ports.insert(conn_id, local_port);
        self.stats.tcp_sessions_created += 1;

        info!(
            "[SHARD {}] Created TCP session: conn_id={}, handle={:?}, local_port={}, local_ip={}, total_sessions={}",
            self.shard_index, conn_id, handle, local_port, self.local_ip, self.tcp_sessions.len()
        );
    }

    /// Handle TCP data event
    ///
    /// Writes data to the smoltcp TCP socket's transmit buffer. If the buffer
    /// is full, the data will be partially written and the session will queue
    /// the remainder for later transmission.
    fn handle_tcp_data(&mut self, conn_id: u64, data: Bytes) {
        let conn_id = ConnId::from_raw(conn_id);
        trace!(
            "Shard {}: TCP data: conn_id={}, len={}",
            self.shard_index,
            conn_id,
            data.len()
        );

        let Some(session) = self.tcp_sessions.get_mut(&conn_id) else {
            warn!(
                "Shard {}: TCP data for unknown connection: {}",
                self.shard_index, conn_id
            );
            return;
        };

        let handle = session.socket_handle();
        let socket = self.sockets.get_mut::<TcpSocket>(handle);

        // Check if socket can send data
        if !socket.can_send() {
            trace!(
                "Shard {}: Socket cannot send for conn_id={}, state={:?} - queueing data",
                self.shard_index,
                conn_id,
                socket.state()
            );
            // Queue data for later when socket becomes available
            session.queue_pending_data(data);
            return;
        }

        // Try to send data to the socket
        match socket.send_slice(&data) {
            Ok(sent) => {
                session.record_sent(sent as u64);
                trace!(
                    "Shard {}: Sent {} of {} bytes for conn_id={}",
                    self.shard_index,
                    sent,
                    data.len(),
                    conn_id
                );

                // If not all data was sent, queue the remainder
                if sent < data.len() {
                    let remaining = data.slice(sent..);
                    session.queue_pending_data(remaining);
                    trace!(
                        "Shard {}: Queued {} remaining bytes for conn_id={}",
                        self.shard_index,
                        data.len() - sent,
                        conn_id
                    );
                }
            }
            Err(e) => {
                warn!(
                    "Shard {}: Failed to send data for conn_id={}: {:?}",
                    self.shard_index, conn_id, e
                );
                // Notify about error via reply channel
                let _ = session.reply_tx().try_send(TcpReply::Error {
                    error: BridgeError::SmoltcpTcp(format!("send error: {e:?}")),
                });
            }
        }
    }

    /// Handle TCP close write event
    ///
    /// Initiates graceful shutdown of the write side of the TCP connection
    /// by sending a FIN packet.
    fn handle_tcp_close_write(&mut self, conn_id: u64) {
        let conn_id = ConnId::from_raw(conn_id);
        debug!(
            "Shard {}: TCP close write: conn_id={}",
            self.shard_index, conn_id
        );

        let Some(session) = self.tcp_sessions.get_mut(&conn_id) else {
            // Log existing sessions for debugging
            let existing_ids: Vec<_> = self.tcp_sessions.keys().take(10).collect();
            warn!(
                "[SHARD {}] TCP close write for unknown connection: {} (existing sessions: {:?}, total={})",
                self.shard_index, conn_id, existing_ids, self.tcp_sessions.len()
            );
            return;
        };

        let handle = session.socket_handle();
        let socket = self.sockets.get_mut::<TcpSocket>(handle);

        // Mark session as closing
        session.set_closing();

        // Initiate graceful close (sends FIN)
        socket.close();

        debug!(
            "Shard {}: Initiated close for conn_id={}, state={:?}",
            self.shard_index, conn_id, socket.state()
        );
    }

    /// Handle TCP abort event
    ///
    /// Immediately terminates the TCP connection by sending a RST packet.
    /// This is used for error conditions or when immediate termination is required.
    fn handle_tcp_abort(&mut self, conn_id: u64) {
        let conn_id = ConnId::from_raw(conn_id);
        debug!(
            "Shard {}: TCP abort: conn_id={}",
            self.shard_index, conn_id
        );

        // Remove session and clean up resources
        if let Some(mut session) = self.tcp_sessions.remove(&conn_id) {
            let handle = session.socket_handle();

            // Remove reverse mapping
            self.tcp_handle_to_conn.remove(&handle);

            // Abort the socket (sends RST)
            {
                let socket = self.sockets.get_mut::<TcpSocket>(handle);
                socket.abort();
            }

            // Remove socket from socket set
            self.sockets.remove(handle);

            // Release port
            if let Some(port) = self.tcp_ports.remove(&conn_id) {
                // Use immediate release since connection was aborted
                self.port_allocator.release_immediate(port);
            }

            session.set_closed();
            self.stats.tcp_sessions_closed += 1;

            debug!(
                "Shard {}: Aborted TCP session: conn_id={}",
                self.shard_index, conn_id
            );
        } else {
            warn!(
                "Shard {}: TCP abort for unknown connection: {}",
                self.shard_index, conn_id
            );
        }
    }

    /// Handle UDP send event
    ///
    /// This method handles sending UDP datagrams through the smoltcp stack.
    /// For new sessions, it creates a UDP socket, allocates a local port, and
    /// binds the socket. For existing sessions, it sends data through the
    /// established socket.
    fn handle_udp_send(
        &mut self,
        session_key: UdpSessionKey,
        dest: SocketAddr,
        data: Bytes,
        reply_tx: Option<mpsc::Sender<UdpReply>>,
    ) {
        trace!(
            "Shard {}: UDP send: key={}, dest={}, len={}, is_dns={}",
            self.shard_index,
            session_key,
            dest,
            data.len(),
            session_key.is_dns()
        );

        // Get or create session
        let (handle, _is_new) = if let Some(session) = self.udp_sessions.get(&session_key) {
            (session.socket_handle(), false)
        } else {
            // Need to create a new session
            let Some(reply_tx) = reply_tx else {
                warn!(
                    "Shard {}: UDP send for unknown session without reply_tx: {}",
                    self.shard_index, session_key
                );
                return;
            };

            // Allocate a local port
            let local_port = match self.port_allocator.allocate() {
                Some(guard) => guard.take(), // Take ownership, we'll manage the port manually
                None => {
                    warn!(
                        "Shard {}: Port exhaustion for UDP session: {}",
                        self.shard_index, session_key
                    );
                    self.stats.udp_send_errors += 1;
                    return;
                }
            };

            // Create UDP socket with buffers
            let rx_buffer = UdpPacketBuffer::new(
                vec![UdpPacketMetadata::EMPTY; UDP_PACKET_META],
                vec![0; UDP_RX_BUFFER],
            );
            let tx_buffer = UdpPacketBuffer::new(
                vec![UdpPacketMetadata::EMPTY; UDP_PACKET_META],
                vec![0; UDP_TX_BUFFER],
            );
            let socket = UdpSocket::new(rx_buffer, tx_buffer);
            let handle = self.sockets.add(socket);

            // Bind the socket to the local port
            {
                let socket = self.sockets.get_mut::<UdpSocket>(handle);
                if let Err(e) = socket.bind(local_port) {
                    warn!(
                        "Shard {}: Failed to bind UDP socket to port {}: {:?}",
                        self.shard_index, local_port, e
                    );
                    self.sockets.remove(handle);
                    self.port_allocator.release(local_port);
                    self.stats.udp_send_errors += 1;
                    return;
                }
            }

            // Create and store the session
            let session = ShardUdpSession::new(session_key.clone(), handle, reply_tx);
            self.udp_sessions.insert(session_key.clone(), session);
            self.udp_handle_to_session.insert(handle, session_key.clone());
            self.udp_ports.insert(session_key.clone(), local_port);
            self.stats.udp_sessions_created += 1;

            debug!(
                "Shard {}: Created UDP session: key={}, handle={:?}, local_port={}, is_dns={}",
                self.shard_index, session_key, handle, local_port, session_key.is_dns()
            );

            (handle, true)
        };

        // Convert destination to smoltcp IpEndpoint
        let Some(smoltcp_dest) = socket_addr_to_endpoint(dest) else {
            // IPv6 not supported
            warn!(
                "Shard {}: IPv6 destination not supported for UDP: {:?}",
                self.shard_index, dest
            );
            return;
        };

        // Send the data
        {
            let socket = self.sockets.get_mut::<UdpSocket>(handle);
            if socket.can_send() {
                match socket.send_slice(&data, smoltcp_dest) {
                    Ok(()) => {
                        self.stats.udp_datagrams_sent += 1;
                        self.stats.udp_bytes_sent += data.len() as u64;
                        trace!(
                            "Shard {}: UDP datagram sent: {} bytes to {}",
                            self.shard_index,
                            data.len(),
                            dest
                        );

                        // Update session activity (throttled)
                        if let Some(session) = self.udp_sessions.get(&session_key) {
                            session.record_sent(data.len() as u64);
                        }
                    }
                    Err(e) => {
                        warn!(
                            "Shard {}: UDP send_slice failed for {}: {:?}",
                            self.shard_index, session_key, e
                        );
                        self.stats.udp_send_errors += 1;
                    }
                }
            } else {
                warn!(
                    "Shard {}: UDP socket cannot send for {}",
                    self.shard_index, session_key
                );
                self.stats.udp_send_errors += 1;
            }
        }
    }

    /// Handle UDP close event
    ///
    /// Closes a UDP session and releases all associated resources:
    /// - Removes the smoltcp socket
    /// - Releases the allocated port back to the port allocator
    /// - Cleans up all tracking maps
    fn handle_udp_close(&mut self, session_key: UdpSessionKey) {
        debug!(
            "Shard {}: UDP close: key={}",
            self.shard_index, session_key
        );

        if let Some(session) = self.udp_sessions.remove(&session_key) {
            let handle = session.socket_handle();

            // Log final session stats
            let stats = session.stats();
            debug!(
                "Shard {}: UDP session closed: key={}, stats={}",
                self.shard_index, session_key, stats
            );

            // Remove the smoltcp socket
            self.sockets.remove(handle);

            // Remove from handle-to-session map
            self.udp_handle_to_session.remove(&handle);

            // Release the allocated port
            if let Some(port) = self.udp_ports.remove(&session_key) {
                self.port_allocator.release(port);
                trace!(
                    "Shard {}: Released UDP port {} for session {}",
                    self.shard_index,
                    port,
                    session_key
                );
            }

            self.stats.udp_sessions_closed += 1;
        }
    }

    /// Close a UDP session by handle (internal helper)
    fn close_udp_session_by_handle(&mut self, handle: SocketHandle) {
        if let Some(session_key) = self.udp_handle_to_session.remove(&handle) {
            if let Some(session) = self.udp_sessions.remove(&session_key) {
                let stats = session.stats();
                debug!(
                    "Shard {}: UDP session closed (by handle): key={}, stats={}",
                    self.shard_index, session_key, stats
                );
            }

            // Remove the smoltcp socket
            self.sockets.remove(handle);

            // Release the allocated port
            if let Some(port) = self.udp_ports.remove(&session_key) {
                self.port_allocator.release(port);
            }

            self.stats.udp_sessions_closed += 1;
        }
    }

    /// Poll smoltcp state machine
    fn poll_smoltcp(&mut self) {
        let timestamp = self.smoltcp_now();
        self.iface.poll(timestamp, &mut self.device, &mut self.sockets);
        self.stats.poll_count += 1;
    }

    /// Process socket state changes and generate replies
    ///
    /// This method is called after polling smoltcp to process any socket
    /// state changes. It handles:
    /// - TCP connection establishment (Task 2.2)
    /// - TCP data available (Task 2.2)
    /// - TCP remote close (Task 2.2)
    /// - UDP data available
    ///
    /// Note: Session cleanup is handled by `cleanup_expired_sessions()` which
    /// runs on a separate timer (Task 2.5) instead of every poll.
    fn process_socket_events(&mut self) {
        // Process TCP sockets - state changes and data
        self.process_tcp_sockets();

        // Process UDP sockets - receive data and send replies
        self.process_udp_sockets();
    }

    /// Process TCP sockets - check state changes and data availability
    ///
    /// TODO: Task 2.2 will implement full TCP socket processing including:
    /// - Detects connection establishment (SynSent -> Established)
    /// - Reads available data and sends TcpReply::Data
    /// - Detects remote close (CloseWait state)
    /// - Detects full close (Closed/TimeWait state)
    /// - Sends any pending data that couldn't be sent earlier
    fn process_tcp_sockets(&mut self) {
        // Collect conn_ids to process (avoid borrowing issues)
        let conn_ids: Vec<ConnId> = self.tcp_sessions.keys().copied().collect();

        // Track sessions to remove
        let mut sessions_to_remove: Vec<ConnId> = Vec::new();

        for conn_id in conn_ids {
            let Some(session) = self.tcp_sessions.get_mut(&conn_id) else {
                continue;
            };

            let handle = session.socket_handle();
            let previous_state = session.state();
            let socket = self.sockets.get_mut::<TcpSocket>(handle);
            let current_state = socket.state();

            // Check for state transitions
            match (previous_state, current_state) {
                // Connection established
                (TcpSessionState::Connecting, TcpState::Established) => {
                    debug!(
                        "Shard {}: TCP connection established for conn_id={}",
                        self.shard_index, conn_id
                    );
                    session.set_established();

                    // Send Connected reply
                    let _ = session.reply_tx().try_send(TcpReply::Connected);
                }

                // Connection failed during SYN
                (TcpSessionState::Connecting, TcpState::Closed) => {
                    debug!(
                        "Shard {}: TCP connection failed for conn_id={}",
                        self.shard_index, conn_id
                    );

                    // Send ConnectFailed reply
                    let _ = session.reply_tx().try_send(TcpReply::ConnectFailed {
                        error: BridgeError::ConnectionRefused,
                    });

                    sessions_to_remove.push(conn_id);
                    continue;
                }

                // Remote initiated close (received FIN)
                (TcpSessionState::Established, TcpState::CloseWait) => {
                    debug!(
                        "Shard {}: TCP remote closed for conn_id={}",
                        self.shard_index, conn_id
                    );
                    session.set_close_wait();

                    // Send RemoteClosed reply
                    let _ = session.reply_tx().try_send(TcpReply::RemoteClosed);
                }

                // Connection fully closed
                (_, TcpState::Closed | TcpState::TimeWait)
                    if previous_state != TcpSessionState::Connecting =>
                {
                    debug!(
                        "Shard {}: TCP connection closed for conn_id={}, previous_state={:?}",
                        self.shard_index, conn_id, previous_state
                    );

                    // Send Closed reply
                    let _ = session.reply_tx().try_send(TcpReply::Closed);

                    sessions_to_remove.push(conn_id);
                    continue;
                }

                _ => {}
            }

            // Try to send any pending data first
            if socket.can_send() && session.has_pending_data() {
                if let Some(pending) = session.take_pending_data() {
                    match socket.send_slice(&pending) {
                        Ok(sent) => {
                            session.record_sent(sent as u64);
                            if sent < pending.len() {
                                // Re-queue the remainder
                                let remaining = pending.slice(sent..);
                                session.queue_pending_data(remaining);
                            }
                        }
                        Err(e) => {
                            warn!(
                                "Shard {}: Failed to send pending data for conn_id={}: {:?}",
                                self.shard_index, conn_id, e
                            );
                        }
                    }
                }
            }

            // Read available data from socket
            if socket.can_recv() {
                // Read in chunks to avoid holding too much data
                const READ_CHUNK_SIZE: usize = 16384;
                let mut total_received = 0usize;

                while socket.can_recv() && total_received < TCP_RX_BUFFER {
                    match socket.recv(|buffer| {
                        let len = buffer.len().min(READ_CHUNK_SIZE);
                        let data = buffer[..len].to_vec();
                        (len, data)
                    }) {
                        Ok(data) if !data.is_empty() => {
                            let data_len = data.len();
                            total_received += data_len;
                            session.record_received(data_len as u64);

                            trace!(
                                "Shard {}: Received {} bytes for conn_id={}",
                                self.shard_index,
                                data_len,
                                conn_id
                            );

                            // Send Data reply
                            let reply = TcpReply::Data {
                                data: Bytes::from(data),
                            };
                            if session.reply_tx().try_send(reply).is_err() {
                                warn!(
                                    "Shard {}: Reply channel full for conn_id={}, data may be lost",
                                    self.shard_index, conn_id
                                );
                                // Don't break - continue reading to prevent buffer backlog
                            }
                        }
                        Ok(_) => break, // Empty read
                        Err(e) => {
                            warn!(
                                "Shard {}: TCP recv error for conn_id={}: {:?}",
                                self.shard_index, conn_id, e
                            );
                            break;
                        }
                    }
                }
            }

            // Check if reply channel is closed (VLESS client disconnected)
            if session.is_reply_channel_closed() {
                debug!(
                    "Shard {}: Reply channel closed for conn_id={}, initiating close",
                    self.shard_index, conn_id
                );
                socket.close();
                session.set_closing();
            }
        }

        // Clean up removed sessions
        for conn_id in sessions_to_remove {
            self.cleanup_tcp_session(conn_id);
        }
    }

    /// Clean up a TCP session and release all associated resources
    fn cleanup_tcp_session(&mut self, conn_id: ConnId) {
        if let Some(mut session) = self.tcp_sessions.remove(&conn_id) {
            let handle = session.socket_handle();

            // Remove reverse mapping
            self.tcp_handle_to_conn.remove(&handle);

            // Remove socket
            self.sockets.remove(handle);

            // Release port (with TIME_WAIT)
            if let Some(port) = self.tcp_ports.remove(&conn_id) {
                self.port_allocator.release(port);
            }

            session.set_closed();
            self.stats.tcp_sessions_closed += 1;

            debug!(
                "Shard {}: Cleaned up TCP session: conn_id={}",
                self.shard_index, conn_id
            );
        }
    }

    /// Process UDP sockets - receive data and send replies
    ///
    /// This method iterates through all UDP sessions and checks if any
    /// sockets have received data. If so, it reads the data and sends
    /// a UdpReply to the session's reply channel.
    fn process_udp_sockets(&mut self) {
        // Collect session keys to process (avoid borrowing issues)
        let session_keys: Vec<UdpSessionKey> = self.udp_sessions.keys().cloned().collect();

        for session_key in session_keys {
            // Get the socket handle
            let Some(session) = self.udp_sessions.get(&session_key) else {
                continue;
            };
            let handle = session.socket_handle();
            let is_reply_closed = session.is_reply_channel_closed();

            // If reply channel is closed, close the session
            if is_reply_closed {
                debug!(
                    "Shard {}: UDP reply channel closed for {}, closing session",
                    self.shard_index, session_key
                );
                self.handle_udp_close(session_key);
                continue;
            }

            // Check if socket has data to receive
            let socket = self.sockets.get_mut::<UdpSocket>(handle);

            // Read all available datagrams
            while socket.can_recv() {
                match socket.recv() {
                    Ok((data, endpoint)) => {
                        let source = endpoint_to_socket_addr(endpoint.endpoint);
                        let data_len = data.len();

                        // Create the reply
                        let reply = UdpReply::new(source, Bytes::copy_from_slice(data));

                        // Update stats
                        self.stats.udp_datagrams_received += 1;
                        self.stats.udp_bytes_received += data_len as u64;

                        // Get session again and try to send the reply
                        if let Some(session) = self.udp_sessions.get(&session_key) {
                            session.record_received(data_len as u64);

                            // Try to send the reply (non-blocking)
                            if let Err(e) = session.try_send_reply(reply) {
                                match e {
                                    mpsc::error::TrySendError::Full(_) => {
                                        warn!(
                                            "Shard {}: UDP reply channel full for {}, dropping reply",
                                            self.shard_index, session_key
                                        );
                                        self.stats.udp_replies_dropped += 1;
                                    }
                                    mpsc::error::TrySendError::Closed(_) => {
                                        debug!(
                                            "Shard {}: UDP reply channel closed for {}, will close session",
                                            self.shard_index, session_key
                                        );
                                        // Will be cleaned up on next iteration
                                        break;
                                    }
                                }
                            } else {
                                trace!(
                                    "Shard {}: UDP reply sent: {} bytes from {} for {}",
                                    self.shard_index,
                                    data_len,
                                    source,
                                    session_key
                                );
                            }
                        }
                    }
                    Err(smoltcp::socket::udp::RecvError::Exhausted) => {
                        // No more data available
                        break;
                    }
                    Err(smoltcp::socket::udp::RecvError::Truncated) => {
                        warn!(
                            "Shard {}: UDP datagram truncated for {}",
                            self.shard_index, session_key
                        );
                        // Continue to try reading more
                    }
                }
            }
        }
    }

    /// Cleanup expired sessions (Task 2.5)
    ///
    /// This method is called by the cleanup timer to check for expired TCP
    /// and UDP sessions. Running cleanup on a timer instead of every poll
    /// significantly reduces CPU overhead.
    ///
    /// # Performance Optimization
    ///
    /// Before Task 2.5, cleanup ran on every poll (1000+ times/second).
    /// Now it runs every 30 seconds (configurable via `CleanupConfig`),
    /// reducing overhead while still ensuring timely resource reclamation.
    ///
    /// # Cleanup Strategy
    ///
    /// 1. **TCP sessions**: Check for idle timeout (default 300s)
    ///    - Sessions with closed reply channels are also cleaned up
    ///
    /// 2. **UDP sessions**: Check for inactivity timeout
    ///    - DNS sessions (port 53): 10 seconds
    ///    - Regular UDP sessions: 30 seconds
    ///    - Sessions with closed reply channels are also cleaned up
    fn cleanup_expired_sessions(&mut self) {
        let start = std::time::Instant::now();

        // Track cleanup counts for this run
        let mut tcp_timed_out = 0u64;
        let mut tcp_channel_closed = 0u64;
        let mut udp_expired = 0u64;
        let mut udp_channel_closed = 0u64;

        // --- TCP Cleanup ---
        // Check for TCP sessions with closed reply channels or idle timeouts
        let tcp_timeout = self.cleanup_config.tcp_idle_timeout();
        let tcp_to_cleanup: Vec<(ConnId, bool)> = self
            .tcp_sessions
            .iter()
            .filter_map(|(conn_id, session)| {
                if session.is_reply_channel_closed() {
                    Some((*conn_id, true)) // true = channel closed
                } else if session.idle_duration() > tcp_timeout {
                    Some((*conn_id, false)) // false = timed out
                } else {
                    None
                }
            })
            .collect();

        for (conn_id, channel_closed) in tcp_to_cleanup {
            if channel_closed {
                debug!(
                    "Shard {}: TCP session cleanup (channel closed): conn_id={}",
                    self.shard_index, conn_id
                );
                tcp_channel_closed += 1;
            } else {
                debug!(
                    "Shard {}: TCP session cleanup (timed out): conn_id={}",
                    self.shard_index, conn_id
                );
                tcp_timed_out += 1;
            }
            self.cleanup_tcp_session(conn_id);
        }

        // --- UDP Cleanup ---
        // Note: cleanup_expired_udp_sessions now also tracks channel-closed sessions
        let udp_expired_keys: Vec<(UdpSessionKey, bool)> = self
            .udp_sessions
            .iter()
            .filter_map(|(key, session)| {
                if session.is_reply_channel_closed() {
                    Some((key.clone(), true)) // true = channel closed
                } else if session.is_expired() {
                    Some((key.clone(), false)) // false = expired
                } else {
                    None
                }
            })
            .collect();

        for (session_key, channel_closed) in udp_expired_keys {
            if channel_closed {
                debug!(
                    "Shard {}: UDP session cleanup (channel closed): key={}",
                    self.shard_index, session_key
                );
                udp_channel_closed += 1;
            } else {
                debug!(
                    "Shard {}: UDP session cleanup (expired): key={}",
                    self.shard_index, session_key
                );
                udp_expired += 1;
            }
            self.handle_udp_close(session_key);
        }

        // Update statistics
        self.stats.cleanup.cleanup_runs += 1;
        self.stats.cleanup.tcp_sessions_timed_out += tcp_timed_out;
        self.stats.cleanup.tcp_sessions_channel_closed += tcp_channel_closed;
        self.stats.cleanup.udp_sessions_expired += udp_expired;
        self.stats.cleanup.udp_sessions_channel_closed += udp_channel_closed;

        // Also update the legacy stat for backward compatibility
        self.stats.udp_sessions_expired += udp_expired;

        let elapsed = start.elapsed();
        let total_cleaned = tcp_timed_out + tcp_channel_closed + udp_expired + udp_channel_closed;

        if total_cleaned > 0 {
            info!(
                "Shard {}: Cleanup run #{}: cleaned {} sessions (tcp_timeout={}, tcp_channel={}, udp_expired={}, udp_channel={}) in {:?}",
                self.shard_index,
                self.stats.cleanup.cleanup_runs,
                total_cleaned,
                tcp_timed_out,
                tcp_channel_closed,
                udp_expired,
                udp_channel_closed,
                elapsed
            );
        } else {
            trace!(
                "Shard {}: Cleanup run #{}: no sessions to clean (tcp={}, udp={}) in {:?}",
                self.shard_index,
                self.stats.cleanup.cleanup_runs,
                self.tcp_sessions.len(),
                self.udp_sessions.len(),
                elapsed
            );
        }
    }

    /// Cleanup expired UDP sessions (legacy method, now called by cleanup_expired_sessions)
    ///
    /// UDP sessions that have not had any activity for their timeout period
    /// are considered expired and are closed. DNS sessions (port 53) have a
    /// shorter timeout (10s) than regular UDP sessions (30s).
    ///
    /// Note: This method is kept for compatibility but is no longer called
    /// from process_socket_events(). Use cleanup_expired_sessions() instead.
    #[allow(dead_code)]
    fn cleanup_expired_udp_sessions(&mut self) {
        // Collect expired session keys
        let expired_keys: Vec<UdpSessionKey> = self
            .udp_sessions
            .iter()
            .filter(|(_, session)| session.is_expired())
            .map(|(key, _)| key.clone())
            .collect();

        // Close expired sessions
        for session_key in expired_keys {
            debug!(
                "Shard {}: UDP session expired: {}",
                self.shard_index, session_key
            );
            self.handle_udp_close(session_key);
            self.stats.udp_sessions_expired += 1;
        }
    }

    /// Drain TX packets from device and send to WG
    ///
    /// This method extracts all pending IP packets from the smoltcp virtual
    /// device and sends them to the WireGuard tunnel via the `wg_tx` channel.
    ///
    /// # Batch Optimization
    ///
    /// Packets are sent one at a time (channel operations are already efficient),
    /// but we track batch statistics for monitoring. The batch constants
    /// (`WG_BATCH_SIZE`, `WG_BATCH_TIMEOUT_US`) are available for future
    /// optimizations if channel overhead becomes a bottleneck.
    ///
    /// # Error Handling
    ///
    /// If the WG channel is closed (receiver dropped), this method sets the
    /// `shutdown` flag to signal the event loop to terminate gracefully.
    async fn drain_and_send_wg_packets(&mut self) {
        // Drain all pending packets from the device
        let packets = self.device.drain_tx();
        let packet_count = packets.len();

        if packet_count == 0 {
            return;
        }

        trace!(
            "Shard {}: Draining {} WG packets",
            self.shard_index,
            packet_count
        );

        // Send packets through the WG channel
        let mut bytes_sent: u64 = 0;
        let mut packets_sent: u64 = 0;
        let mut packets_dropped: u64 = 0;

        for packet in packets {
            let packet_len = packet.len() as u64;

            match self.wg_tx.send(Bytes::from(packet)).await {
                Ok(()) => {
                    packets_sent += 1;
                    bytes_sent += packet_len;
                }
                Err(e) => {
                    // Channel closed - receiver dropped
                    warn!(
                        "Shard {}: WG channel closed, setting shutdown flag. Error: {}",
                        self.shard_index, e
                    );
                    packets_dropped += 1;
                    self.shutdown = true;
                    // Don't try to send more packets
                    break;
                }
            }
        }

        // Update statistics
        self.stats.wg_packets_sent += packets_sent;
        self.stats.wg_bytes_sent += bytes_sent;
        self.stats.wg_packets_dropped += packets_dropped;

        if packets_sent > 0 {
            trace!(
                "Shard {}: Sent {} WG packets ({} bytes)",
                self.shard_index,
                packets_sent,
                bytes_sent
            );
        }

        if packets_dropped > 0 {
            warn!(
                "Shard {}: Dropped {} WG packets due to channel closure",
                self.shard_index, packets_dropped
            );
        }
    }

    /// Send a batch of WG packets (helper method)
    ///
    /// This method is provided for future batch optimization but is currently
    /// unused. It could be used to implement a batched sender that collects
    /// packets up to `WG_BATCH_SIZE` or `WG_BATCH_TIMEOUT_US` before sending.
    #[allow(dead_code)]
    async fn send_wg_batch(&mut self, batch: &mut Vec<Vec<u8>>) {
        for packet in batch.drain(..) {
            let packet_len = packet.len() as u64;

            if self.wg_tx.send(Bytes::from(packet)).await.is_err() {
                self.stats.wg_packets_dropped += 1;
                self.shutdown = true;
                return;
            }

            self.stats.wg_packets_sent += 1;
            self.stats.wg_bytes_sent += packet_len;
        }
    }

    /// Calculate the next poll delay based on smoltcp state
    fn poll_delay(&mut self) -> Duration {
        let timestamp = self.smoltcp_now();

        // Get smoltcp's recommended poll delay
        if let Some(delay) = self.iface.poll_delay(timestamp, &self.sockets) {
            // Clamp to reasonable bounds
            let delay_duration = Duration::from_micros(delay.total_micros());
            delay_duration.clamp(MIN_POLL_INTERVAL, MAX_POLL_INTERVAL)
        } else {
            // No specific timing requirement, use default
            DEFAULT_POLL_INTERVAL
        }
    }

    /// Check if the shard should shut down
    #[must_use]
    pub fn is_shutdown(&self) -> bool {
        self.shutdown
    }

    /// Get a snapshot of current statistics
    #[must_use]
    pub fn stats(&self) -> &ShardStats {
        &self.stats
    }

    /// Get the shard index
    #[must_use]
    pub fn shard_index(&self) -> u16 {
        self.shard_index
    }

    /// Get the number of active TCP sessions
    #[must_use]
    pub fn tcp_session_count(&self) -> usize {
        self.tcp_sessions.len()
    }

    /// Get the number of active UDP sessions
    #[must_use]
    pub fn udp_session_count(&self) -> usize {
        self.udp_sessions.len()
    }
}

impl std::fmt::Debug for SmoltcpShard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SmoltcpShard")
            .field("shard_index", &self.shard_index)
            .field("tcp_sessions", &self.tcp_sessions.len())
            .field("udp_sessions", &self.udp_sessions.len())
            .field("shutdown", &self.shutdown)
            .field("stats", &self.stats)
            .finish_non_exhaustive()
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Convert a `std::net::SocketAddr` to a smoltcp `IpEndpoint`
///
/// Note: IPv6 is not supported by smoltcp in this build. IPv6 addresses will
/// Returns `None` for IPv6 addresses as smoltcp is compiled without IPv6 support.
#[inline]
fn socket_addr_to_endpoint(addr: SocketAddr) -> Option<IpEndpoint> {
    match addr {
        SocketAddr::V4(v4) => Some(IpEndpoint {
            addr: IpAddress::Ipv4(Ipv4Address::from(v4.ip().octets())),
            port: v4.port(),
        }),
        SocketAddr::V6(_) => {
            // smoltcp is compiled without IPv6 support in this project
            None
        }
    }
}

/// Convert a smoltcp `IpEndpoint` to a `std::net::SocketAddr`
///
/// Note: Only IPv4 is supported in this build.
#[inline]
fn endpoint_to_socket_addr(endpoint: IpEndpoint) -> SocketAddr {
    match endpoint.addr {
        IpAddress::Ipv4(v4) => {
            SocketAddr::new(
                IpAddr::V4(v4),
                endpoint.port,
            )
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vless_wg_bridge::event_channel::{create_event_channel, EventChannelConfig};
    use std::net::{IpAddr, Ipv4Addr};

    fn test_config() -> ShardConfig {
        ShardConfig {
            shard_index: 0,
            total_shards: 4, // Use 4 shards for tests
            local_ip: IpAddress::v4(10, 200, 200, 2),
            local_cidr: IpCidr::new(IpAddress::v4(10, 200, 200, 0), 24),
            mtu: WG_MTU,
        }
    }

    #[test]
    fn test_shard_config_new() {
        let config = ShardConfig::new(
            1,
            4, // total_shards
            IpAddress::v4(10, 0, 0, 1),
            IpCidr::new(IpAddress::v4(10, 0, 0, 0), 24),
        );
        assert_eq!(config.shard_index, 1);
        assert_eq!(config.total_shards, 4);
        assert_eq!(config.mtu, WG_MTU);
    }

    #[test]
    fn test_shard_config_with_mtu() {
        let config = ShardConfig::new(
            0,
            4, // total_shards
            IpAddress::v4(10, 0, 0, 1),
            IpCidr::new(IpAddress::v4(10, 0, 0, 0), 24),
        )
        .with_mtu(1400);
        assert_eq!(config.mtu, 1400);
    }

    #[test]
    fn test_shard_stats_default() {
        let stats = ShardStats::new();
        assert_eq!(stats.events_processed, 0);
        assert_eq!(stats.wg_packets_received, 0);
        assert_eq!(stats.tcp_sessions_created, 0);
    }

    #[test]
    fn test_virtual_device_creation() {
        let device = VirtualDevice::new(1420);
        assert_eq!(device.mtu, 1420);
        assert!(device.tx_buffer.is_empty());
        assert!(device.rx_buffer.is_empty());
    }

    #[test]
    fn test_virtual_device_rx_buffer() {
        let mut device = VirtualDevice::new(1420);
        assert!(!device.has_rx());

        device.push_rx(vec![1, 2, 3, 4]);
        assert!(device.has_rx());

        // Drain via Device trait would consume the packet
    }

    #[test]
    fn test_virtual_device_capabilities() {
        let device = VirtualDevice::new(1420);
        let caps = device.capabilities();
        assert_eq!(caps.medium, Medium::Ip);
        assert_eq!(caps.max_transmission_unit, 1420);
    }

    #[tokio::test]
    async fn test_shard_creation() {
        let config = test_config();
        let (_, event_rx) = create_event_channel(EventChannelConfig::default());
        let (_, wg_reply_rx) = mpsc::channel(1024);
        let (wg_tx, _) = mpsc::channel(1024);

        let shard = SmoltcpShard::new(config, event_rx, wg_reply_rx, wg_tx);

        assert_eq!(shard.shard_index(), 0);
        assert!(!shard.is_shutdown());
        assert_eq!(shard.tcp_session_count(), 0);
        assert_eq!(shard.udp_session_count(), 0);
    }

    #[tokio::test]
    async fn test_shard_poll_delay() {
        let config = test_config();
        let (_, event_rx) = create_event_channel(EventChannelConfig::default());
        let (_, wg_reply_rx) = mpsc::channel(1024);
        let (wg_tx, _) = mpsc::channel(1024);

        let mut shard = SmoltcpShard::new(config, event_rx, wg_reply_rx, wg_tx);

        let delay = shard.poll_delay();
        assert!(delay >= MIN_POLL_INTERVAL);
        assert!(delay <= MAX_POLL_INTERVAL);
    }

    #[tokio::test]
    async fn test_shard_handle_wg_packet() {
        let config = test_config();
        let (_, event_rx) = create_event_channel(EventChannelConfig::default());
        let (_, wg_reply_rx) = mpsc::channel(1024);
        let (wg_tx, _) = mpsc::channel(1024);

        let mut shard = SmoltcpShard::new(config, event_rx, wg_reply_rx, wg_tx);

        let packet = Bytes::from_static(&[0x45, 0x00, 0x00, 0x14]); // Minimal IPv4 header
        shard.handle_wg_packet(packet);

        assert_eq!(shard.stats.wg_packets_received, 1);
    }

    #[tokio::test]
    async fn test_shard_shutdown_event() {
        let config = test_config();
        let (event_tx, event_rx) = create_event_channel(EventChannelConfig::default());
        let (_, wg_reply_rx) = mpsc::channel(1024);
        let (wg_tx, _) = mpsc::channel(1024);

        let mut shard = SmoltcpShard::new(config, event_rx, wg_reply_rx, wg_tx);

        assert!(!shard.is_shutdown());

        shard.handle_event(BridgeEvent::Shutdown).await;

        assert!(shard.is_shutdown());
    }

    #[tokio::test]
    async fn test_shard_tcp_connect() {
        let config = test_config();
        let (_, event_rx) = create_event_channel(EventChannelConfig::default());
        let (_, wg_reply_rx) = mpsc::channel(1024);
        let (wg_tx, _) = mpsc::channel(1024);

        let mut shard = SmoltcpShard::new(config, event_rx, wg_reply_rx, wg_tx);

        let (reply_tx, _reply_rx) = mpsc::channel(32);
        let dest_addr: SocketAddr = "93.184.216.34:80".parse().unwrap();

        shard.handle_tcp_connect(42, dest_addr, reply_tx);

        assert_eq!(shard.tcp_session_count(), 1);
        assert_eq!(shard.stats.tcp_sessions_created, 1);
    }

    #[tokio::test]
    async fn test_shard_udp_send() {
        let config = test_config();
        let (_, event_rx) = create_event_channel(EventChannelConfig::default());
        let (_, wg_reply_rx) = mpsc::channel(1024);
        let (wg_tx, _) = mpsc::channel(1024);

        let mut shard = SmoltcpShard::new(config, event_rx, wg_reply_rx, wg_tx);

        let (reply_tx, _reply_rx) = mpsc::channel(32);
        let session_key = UdpSessionKey::from_parts(
            IpAddr::V4(Ipv4Addr::new(10, 200, 200, 2)),
            50000,
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            53,
        );
        let dest: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let data = Bytes::from_static(b"DNS query");

        shard.handle_udp_send(session_key, dest, data, Some(reply_tx));

        assert_eq!(shard.udp_session_count(), 1);
        assert_eq!(shard.stats.udp_sessions_created, 1);
    }

    #[test]
    fn test_shard_debug_impl() {
        // Synchronous test for Debug impl
        let debug_output = "SmoltcpShard";
        assert!(!debug_output.is_empty());
    }

    #[test]
    fn test_poll_interval_constants() {
        assert!(MIN_POLL_INTERVAL < DEFAULT_POLL_INTERVAL);
        assert!(DEFAULT_POLL_INTERVAL < MAX_POLL_INTERVAL);
        assert_eq!(MIN_POLL_INTERVAL, Duration::from_millis(1));
        assert_eq!(MAX_POLL_INTERVAL, Duration::from_millis(50));
    }

    // =========================================================================
    // UDP Session Tests
    // =========================================================================

    #[tokio::test]
    async fn test_udp_send_creates_session_with_port() {
        let config = test_config();
        let (_, event_rx) = create_event_channel(EventChannelConfig::default());
        let (_, wg_reply_rx) = mpsc::channel(1024);
        let (wg_tx, _) = mpsc::channel(1024);

        let mut shard = SmoltcpShard::new(config, event_rx, wg_reply_rx, wg_tx);

        let (reply_tx, _reply_rx) = mpsc::channel(32);
        let session_key = UdpSessionKey::from_parts(
            IpAddr::V4(Ipv4Addr::new(10, 200, 200, 2)),
            50000,
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            53,
        );
        let dest: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let data = Bytes::from_static(b"DNS query");

        shard.handle_udp_send(session_key.clone(), dest, data, Some(reply_tx));

        // Verify session was created
        assert_eq!(shard.udp_session_count(), 1);
        assert_eq!(shard.stats.udp_sessions_created, 1);

        // Verify port was allocated
        assert!(shard.udp_ports.contains_key(&session_key));
        assert!(shard.udp_handle_to_session.len() == 1);

        // Verify stats
        assert_eq!(shard.stats.udp_datagrams_sent, 1);
        assert_eq!(shard.stats.udp_bytes_sent, 9); // "DNS query" is 9 bytes
    }

    #[tokio::test]
    async fn test_udp_send_without_reply_tx_fails_for_new_session() {
        let config = test_config();
        let (_, event_rx) = create_event_channel(EventChannelConfig::default());
        let (_, wg_reply_rx) = mpsc::channel(1024);
        let (wg_tx, _) = mpsc::channel(1024);

        let mut shard = SmoltcpShard::new(config, event_rx, wg_reply_rx, wg_tx);

        let session_key = UdpSessionKey::from_parts(
            IpAddr::V4(Ipv4Addr::new(10, 200, 200, 2)),
            50000,
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            53,
        );
        let dest: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let data = Bytes::from_static(b"DNS query");

        // Send without reply_tx - should not create session
        shard.handle_udp_send(session_key, dest, data, None);

        // No session should be created
        assert_eq!(shard.udp_session_count(), 0);
        assert_eq!(shard.stats.udp_sessions_created, 0);
    }

    #[tokio::test]
    async fn test_udp_send_subsequent_uses_existing_session() {
        let config = test_config();
        let (_, event_rx) = create_event_channel(EventChannelConfig::default());
        let (_, wg_reply_rx) = mpsc::channel(1024);
        let (wg_tx, _) = mpsc::channel(1024);

        let mut shard = SmoltcpShard::new(config, event_rx, wg_reply_rx, wg_tx);

        let (reply_tx, _reply_rx) = mpsc::channel(32);
        let session_key = UdpSessionKey::from_parts(
            IpAddr::V4(Ipv4Addr::new(10, 200, 200, 2)),
            50000,
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            53,
        );
        let dest: SocketAddr = "8.8.8.8:53".parse().unwrap();

        // First send creates session
        shard.handle_udp_send(
            session_key.clone(),
            dest,
            Bytes::from_static(b"query1"),
            Some(reply_tx),
        );

        assert_eq!(shard.stats.udp_sessions_created, 1);

        // Subsequent sends use existing session (no reply_tx needed)
        shard.handle_udp_send(
            session_key.clone(),
            dest,
            Bytes::from_static(b"query2"),
            None,
        );
        shard.handle_udp_send(
            session_key.clone(),
            dest,
            Bytes::from_static(b"query3"),
            None,
        );

        // Still only 1 session
        assert_eq!(shard.udp_session_count(), 1);
        assert_eq!(shard.stats.udp_sessions_created, 1);

        // But 3 datagrams sent
        assert_eq!(shard.stats.udp_datagrams_sent, 3);
    }

    #[tokio::test]
    async fn test_udp_close_releases_port() {
        let config = test_config();
        let (_, event_rx) = create_event_channel(EventChannelConfig::default());
        let (_, wg_reply_rx) = mpsc::channel(1024);
        let (wg_tx, _) = mpsc::channel(1024);

        let mut shard = SmoltcpShard::new(config, event_rx, wg_reply_rx, wg_tx);

        let (reply_tx, _reply_rx) = mpsc::channel(32);
        let session_key = UdpSessionKey::from_parts(
            IpAddr::V4(Ipv4Addr::new(10, 200, 200, 2)),
            50000,
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            53,
        );
        let dest: SocketAddr = "8.8.8.8:53".parse().unwrap();

        // Create session
        shard.handle_udp_send(session_key.clone(), dest, Bytes::from_static(b"test"), Some(reply_tx));
        assert_eq!(shard.udp_session_count(), 1);

        // Get the allocated port
        let allocated_port = *shard.udp_ports.get(&session_key).unwrap();

        // Close session
        shard.handle_udp_close(session_key.clone());

        // Verify cleanup
        assert_eq!(shard.udp_session_count(), 0);
        assert_eq!(shard.stats.udp_sessions_closed, 1);
        assert!(shard.udp_ports.is_empty());
        assert!(shard.udp_handle_to_session.is_empty());

        // Port should be in TIME_WAIT
        assert!(shard.port_allocator.is_in_time_wait(allocated_port));
    }

    #[tokio::test]
    async fn test_udp_dns_session_detection() {
        let config = test_config();
        let (_, event_rx) = create_event_channel(EventChannelConfig::default());
        let (_, wg_reply_rx) = mpsc::channel(1024);
        let (wg_tx, _) = mpsc::channel(1024);

        let mut shard = SmoltcpShard::new(config, event_rx, wg_reply_rx, wg_tx);

        // DNS session (port 53)
        let (reply_tx1, _) = mpsc::channel(32);
        let dns_key = UdpSessionKey::from_parts(
            IpAddr::V4(Ipv4Addr::new(10, 200, 200, 2)),
            50000,
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            53,
        );
        shard.handle_udp_send(dns_key.clone(), "8.8.8.8:53".parse().unwrap(), Bytes::from_static(b"dns"), Some(reply_tx1));

        // Regular UDP session (port 443)
        let (reply_tx2, _) = mpsc::channel(32);
        let regular_key = UdpSessionKey::from_parts(
            IpAddr::V4(Ipv4Addr::new(10, 200, 200, 2)),
            50001,
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            443,
        );
        shard.handle_udp_send(regular_key.clone(), "93.184.216.34:443".parse().unwrap(), Bytes::from_static(b"quic"), Some(reply_tx2));

        // Verify both sessions created
        assert_eq!(shard.udp_session_count(), 2);

        // Verify DNS detection
        assert!(dns_key.is_dns());
        assert!(!regular_key.is_dns());
    }

    // =========================================================================
    // Helper Function Tests
    // =========================================================================

    #[test]
    fn test_socket_addr_to_endpoint_ipv4() {
        let addr: SocketAddr = "192.168.1.100:8080".parse().unwrap();
        let endpoint = socket_addr_to_endpoint(addr).expect("IPv4 should succeed");

        assert_eq!(endpoint.port, 8080);
        match endpoint.addr {
            IpAddress::Ipv4(v4) => {
                assert_eq!(v4.octets(), [192, 168, 1, 100]);
            }
        }
    }

    #[test]
    fn test_socket_addr_to_endpoint_ipv6_returns_none() {
        // IPv6 is not supported in this build of smoltcp
        let addr: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        assert!(socket_addr_to_endpoint(addr).is_none(), "IPv6 should return None");
    }

    #[test]
    fn test_endpoint_to_socket_addr_ipv4() {
        let endpoint = IpEndpoint {
            addr: IpAddress::Ipv4(Ipv4Address::new(10, 0, 0, 1)),
            port: 53,
        };
        let addr = endpoint_to_socket_addr(endpoint);

        assert_eq!(addr, "10.0.0.1:53".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn test_endpoint_conversion_roundtrip() {
        let original: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let endpoint = socket_addr_to_endpoint(original).expect("IPv4 should succeed");
        let converted = endpoint_to_socket_addr(endpoint);

        assert_eq!(original, converted);
    }

    // =========================================================================
    // Statistics Tests
    // =========================================================================

    #[test]
    fn test_shard_stats_udp_fields() {
        let mut stats = ShardStats::new();

        // Verify UDP-specific fields exist and are zero
        assert_eq!(stats.udp_datagrams_sent, 0);
        assert_eq!(stats.udp_datagrams_received, 0);
        assert_eq!(stats.udp_bytes_sent, 0);
        assert_eq!(stats.udp_bytes_received, 0);
        assert_eq!(stats.udp_send_errors, 0);
        assert_eq!(stats.udp_replies_dropped, 0);
        assert_eq!(stats.udp_sessions_expired, 0);

        // Verify we can update them
        stats.udp_datagrams_sent = 10;
        stats.udp_bytes_sent = 1000;
        assert_eq!(stats.udp_datagrams_sent, 10);
        assert_eq!(stats.udp_bytes_sent, 1000);
    }

    // =========================================================================
    // Cleanup Tests (Task 2.5)
    // =========================================================================

    #[test]
    fn test_shard_stats_cleanup_fields() {
        let stats = ShardStats::new();

        // Verify cleanup stats are included and zero
        assert_eq!(stats.cleanup.cleanup_runs, 0);
        assert_eq!(stats.cleanup.tcp_sessions_timed_out, 0);
        assert_eq!(stats.cleanup.udp_sessions_expired, 0);
        assert_eq!(stats.cleanup.tcp_sessions_channel_closed, 0);
        assert_eq!(stats.cleanup.udp_sessions_channel_closed, 0);
    }

    #[test]
    fn test_cleanup_config_default() {
        use super::super::cleanup::CleanupConfig;

        let config = CleanupConfig::default();

        // Verify default values
        assert_eq!(config.cleanup_interval_secs, 30);
        assert_eq!(config.tcp_idle_timeout_secs, 300);
        assert_eq!(config.udp_default_timeout_secs, 30);
        assert_eq!(config.udp_dns_timeout_secs, 10);
    }

    #[tokio::test]
    async fn test_shard_with_cleanup_config() {
        use super::super::cleanup::CleanupConfig;

        let config = test_config();
        let (_, event_rx) = create_event_channel(EventChannelConfig::default());
        let (_, wg_reply_rx) = mpsc::channel(1024);
        let (wg_tx, _) = mpsc::channel(1024);

        // Use custom cleanup config
        let cleanup_config = CleanupConfig::high_traffic();

        let shard = SmoltcpShard::with_cleanup_config(
            config, event_rx, wg_reply_rx, wg_tx, cleanup_config
        );

        // Verify custom config was applied
        assert_eq!(shard.cleanup_config.cleanup_interval_secs, 15);
        assert_eq!(shard.cleanup_config.tcp_idle_timeout_secs, 120);
    }

    #[tokio::test]
    async fn test_cleanup_empty_sessions() {
        let config = test_config();
        let (_, event_rx) = create_event_channel(EventChannelConfig::default());
        let (_, wg_reply_rx) = mpsc::channel(1024);
        let (wg_tx, _) = mpsc::channel(1024);

        let mut shard = SmoltcpShard::new(config, event_rx, wg_reply_rx, wg_tx);

        // No sessions, cleanup should be a no-op
        assert_eq!(shard.tcp_session_count(), 0);
        assert_eq!(shard.udp_session_count(), 0);

        // Run cleanup
        shard.cleanup_expired_sessions();

        // Verify cleanup ran and reported no cleaned sessions
        assert_eq!(shard.stats.cleanup.cleanup_runs, 1);
        assert_eq!(shard.stats.cleanup.tcp_sessions_timed_out, 0);
        assert_eq!(shard.stats.cleanup.udp_sessions_expired, 0);
    }

    #[tokio::test]
    async fn test_cleanup_udp_channel_closed() {
        let config = test_config();
        let (_, event_rx) = create_event_channel(EventChannelConfig::default());
        let (_, wg_reply_rx) = mpsc::channel(1024);
        let (wg_tx, _) = mpsc::channel(1024);

        let mut shard = SmoltcpShard::new(config, event_rx, wg_reply_rx, wg_tx);

        // Create a UDP session
        let (reply_tx, reply_rx) = mpsc::channel(32);
        let session_key = UdpSessionKey::from_parts(
            IpAddr::V4(Ipv4Addr::new(10, 200, 200, 2)),
            50000,
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            53,
        );
        shard.handle_udp_send(
            session_key.clone(),
            "8.8.8.8:53".parse().unwrap(),
            Bytes::from_static(b"test"),
            Some(reply_tx),
        );

        assert_eq!(shard.udp_session_count(), 1);

        // Drop the reply receiver to close the channel
        drop(reply_rx);

        // Run cleanup - should detect channel closed
        shard.cleanup_expired_sessions();

        // Verify session was cleaned up due to closed channel
        assert_eq!(shard.udp_session_count(), 0);
        assert_eq!(shard.stats.cleanup.cleanup_runs, 1);
        assert_eq!(shard.stats.cleanup.udp_sessions_channel_closed, 1);
        assert_eq!(shard.stats.cleanup.udp_sessions_expired, 0); // Not expired, channel closed
    }

    #[tokio::test]
    async fn test_cleanup_tcp_channel_closed() {
        let config = test_config();
        let (_, event_rx) = create_event_channel(EventChannelConfig::default());
        let (_, wg_reply_rx) = mpsc::channel(1024);
        let (wg_tx, _) = mpsc::channel(1024);

        let mut shard = SmoltcpShard::new(config, event_rx, wg_reply_rx, wg_tx);

        // Create a TCP session
        let (reply_tx, reply_rx) = mpsc::channel(32);
        let dest_addr: SocketAddr = "93.184.216.34:80".parse().unwrap();
        shard.handle_tcp_connect(42, dest_addr, reply_tx);

        assert_eq!(shard.tcp_session_count(), 1);

        // Drop the reply receiver to close the channel
        drop(reply_rx);

        // Run cleanup - should detect channel closed
        shard.cleanup_expired_sessions();

        // Verify session was cleaned up due to closed channel
        assert_eq!(shard.tcp_session_count(), 0);
        assert_eq!(shard.stats.cleanup.cleanup_runs, 1);
        assert_eq!(shard.stats.cleanup.tcp_sessions_channel_closed, 1);
        assert_eq!(shard.stats.cleanup.tcp_sessions_timed_out, 0); // Not timed out, channel closed
    }

    #[tokio::test]
    async fn test_cleanup_mixed_sessions() {
        let config = test_config();
        let (_, event_rx) = create_event_channel(EventChannelConfig::default());
        let (_, wg_reply_rx) = mpsc::channel(1024);
        let (wg_tx, _) = mpsc::channel(1024);

        let mut shard = SmoltcpShard::new(config, event_rx, wg_reply_rx, wg_tx);

        // Create TCP session with closed channel
        let (reply_tx1, reply_rx1) = mpsc::channel(32);
        shard.handle_tcp_connect(1, "93.184.216.34:80".parse().unwrap(), reply_tx1);
        drop(reply_rx1); // Close channel

        // Create TCP session with open channel
        let (reply_tx2, _reply_rx2) = mpsc::channel(32);
        shard.handle_tcp_connect(2, "93.184.216.34:443".parse().unwrap(), reply_tx2);

        // Create UDP session with closed channel
        let (reply_tx3, reply_rx3) = mpsc::channel(32);
        let udp_key1 = UdpSessionKey::from_parts(
            IpAddr::V4(Ipv4Addr::new(10, 200, 200, 2)),
            50000,
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            53,
        );
        shard.handle_udp_send(udp_key1, "8.8.8.8:53".parse().unwrap(), Bytes::from_static(b"a"), Some(reply_tx3));
        drop(reply_rx3); // Close channel

        // Create UDP session with open channel
        let (reply_tx4, _reply_rx4) = mpsc::channel(32);
        let udp_key2 = UdpSessionKey::from_parts(
            IpAddr::V4(Ipv4Addr::new(10, 200, 200, 2)),
            50001,
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            53,
        );
        shard.handle_udp_send(udp_key2, "1.1.1.1:53".parse().unwrap(), Bytes::from_static(b"b"), Some(reply_tx4));

        // Verify initial state
        assert_eq!(shard.tcp_session_count(), 2);
        assert_eq!(shard.udp_session_count(), 2);

        // Run cleanup
        shard.cleanup_expired_sessions();

        // Verify only closed-channel sessions were cleaned up
        assert_eq!(shard.tcp_session_count(), 1);
        assert_eq!(shard.udp_session_count(), 1);
        assert_eq!(shard.stats.cleanup.tcp_sessions_channel_closed, 1);
        assert_eq!(shard.stats.cleanup.udp_sessions_channel_closed, 1);
    }

    #[tokio::test]
    async fn test_cleanup_stats_accumulate() {
        let config = test_config();
        let (_, event_rx) = create_event_channel(EventChannelConfig::default());
        let (_, wg_reply_rx) = mpsc::channel(1024);
        let (wg_tx, _) = mpsc::channel(1024);

        let mut shard = SmoltcpShard::new(config, event_rx, wg_reply_rx, wg_tx);

        // Run cleanup multiple times
        shard.cleanup_expired_sessions();
        shard.cleanup_expired_sessions();
        shard.cleanup_expired_sessions();

        // Verify runs accumulate
        assert_eq!(shard.stats.cleanup.cleanup_runs, 3);
    }

    #[test]
    fn test_cleanup_config_profiles() {
        use super::super::cleanup::CleanupConfig;

        let default = CleanupConfig::default();
        let high_traffic = CleanupConfig::high_traffic();
        let low_memory = CleanupConfig::low_memory();
        let long_lived = CleanupConfig::long_lived();

        // High traffic has shorter intervals
        assert!(high_traffic.cleanup_interval_secs < default.cleanup_interval_secs);
        assert!(high_traffic.tcp_idle_timeout_secs < default.tcp_idle_timeout_secs);

        // Low memory has aggressive cleanup
        assert!(low_memory.cleanup_interval_secs <= 10);
        assert!(low_memory.tcp_idle_timeout_secs <= 60);

        // Long lived has longer timeouts
        assert!(long_lived.tcp_idle_timeout_secs > default.tcp_idle_timeout_secs);
        assert!(long_lived.udp_default_timeout_secs > default.udp_default_timeout_secs);
    }

    // =========================================================================
    // WG Packet Handling Tests (Task 2.4)
    // =========================================================================

    #[test]
    fn test_wg_batch_constants() {
        // Verify batch constants are reasonable
        assert!(WG_BATCH_SIZE >= 1);
        assert!(WG_BATCH_SIZE <= 256);
        assert!(WG_BATCH_TIMEOUT_US <= 10_000); // Max 10ms
    }

    #[test]
    fn test_shard_stats_wg_fields() {
        let mut stats = ShardStats::new();

        // Verify WG-specific fields exist and are zero
        assert_eq!(stats.wg_packets_received, 0);
        assert_eq!(stats.wg_packets_sent, 0);
        assert_eq!(stats.wg_bytes_received, 0);
        assert_eq!(stats.wg_bytes_sent, 0);
        assert_eq!(stats.wg_packets_dropped, 0);

        // Verify we can update them
        stats.wg_packets_received = 100;
        stats.wg_bytes_received = 140000;
        stats.wg_packets_sent = 50;
        stats.wg_bytes_sent = 70000;
        stats.wg_packets_dropped = 2;

        assert_eq!(stats.wg_packets_received, 100);
        assert_eq!(stats.wg_bytes_received, 140000);
        assert_eq!(stats.wg_packets_sent, 50);
        assert_eq!(stats.wg_bytes_sent, 70000);
        assert_eq!(stats.wg_packets_dropped, 2);
    }

    #[test]
    fn test_virtual_device_can_push_rx() {
        let mut device = VirtualDevice::new(1420);

        // Should be able to push initially
        assert!(device.can_push_rx());

        // Push packets up to capacity - 1
        for _ in 0..(DEVICE_RX_BUFFER_CAPACITY - 1) {
            assert!(device.can_push_rx());
            device.push_rx(vec![0u8; 100]);
        }

        // Should still be able to push one more
        assert!(device.can_push_rx());
        device.push_rx(vec![0u8; 100]);

        // Now should be full
        assert!(!device.can_push_rx());
    }

    #[test]
    fn test_virtual_device_has_tx() {
        let device = VirtualDevice::new(1420);
        assert!(!device.has_tx());
        assert_eq!(device.tx_count(), 0);
    }

    #[tokio::test]
    async fn test_shard_handle_wg_packet_with_bytes() {
        let config = test_config();
        let (_, event_rx) = create_event_channel(EventChannelConfig::default());
        let (_, wg_reply_rx) = mpsc::channel(1024);
        let (wg_tx, _) = mpsc::channel(1024);

        let mut shard = SmoltcpShard::new(config, event_rx, wg_reply_rx, wg_tx);

        // Send a 100-byte packet
        let packet = Bytes::from(vec![0u8; 100]);
        shard.handle_wg_packet(packet);

        assert_eq!(shard.stats.wg_packets_received, 1);
        assert_eq!(shard.stats.wg_bytes_received, 100);
        assert_eq!(shard.stats.wg_packets_dropped, 0);
    }

    #[tokio::test]
    async fn test_shard_handle_multiple_wg_packets() {
        let config = test_config();
        let (_, event_rx) = create_event_channel(EventChannelConfig::default());
        let (_, wg_reply_rx) = mpsc::channel(1024);
        let (wg_tx, _) = mpsc::channel(1024);

        let mut shard = SmoltcpShard::new(config, event_rx, wg_reply_rx, wg_tx);

        // Send multiple packets
        for i in 1..=5 {
            let packet = Bytes::from(vec![0u8; i * 100]);
            shard.handle_wg_packet(packet);
        }

        assert_eq!(shard.stats.wg_packets_received, 5);
        // Total bytes: 100 + 200 + 300 + 400 + 500 = 1500
        assert_eq!(shard.stats.wg_bytes_received, 1500);
        assert_eq!(shard.stats.wg_packets_dropped, 0);
    }

    #[tokio::test]
    async fn test_shard_drain_and_send_wg_packets_empty() {
        let config = test_config();
        let (_, event_rx) = create_event_channel(EventChannelConfig::default());
        let (_, wg_reply_rx) = mpsc::channel(1024);
        let (wg_tx, _wg_rx) = mpsc::channel(1024);

        let mut shard = SmoltcpShard::new(config, event_rx, wg_reply_rx, wg_tx);

        // Drain with no packets should be a no-op
        shard.drain_and_send_wg_packets().await;

        assert_eq!(shard.stats.wg_packets_sent, 0);
        assert_eq!(shard.stats.wg_bytes_sent, 0);
        assert!(!shard.is_shutdown());
    }

    #[tokio::test]
    async fn test_shard_drain_and_send_wg_packets_channel_closed() {
        let config = test_config();
        let (_, event_rx) = create_event_channel(EventChannelConfig::default());
        let (_, wg_reply_rx) = mpsc::channel(1024);
        let (wg_tx, wg_rx) = mpsc::channel(1024);

        let mut shard = SmoltcpShard::new(config, event_rx, wg_reply_rx, wg_tx);

        // Drop the receiver to close the channel
        drop(wg_rx);

        // With no packets in the buffer, drain should be a no-op
        // even with the channel closed
        shard.drain_and_send_wg_packets().await;

        // With no packets, should not have set shutdown
        assert!(!shard.is_shutdown());
    }

    #[test]
    fn test_virtual_device_drain_tx() {
        let mut device = VirtualDevice::new(1420);

        // Initially empty
        let drained = device.drain_tx();
        assert!(drained.is_empty());

        // Verify the drain behavior
        assert!(!device.has_tx());
        assert_eq!(device.tx_count(), 0);
    }

    #[tokio::test]
    async fn test_wg_packet_via_event_channel() {
        let config = test_config();
        let (_, event_rx) = create_event_channel(EventChannelConfig::default());
        let (_, wg_reply_rx) = mpsc::channel(1024);
        let (wg_tx, _) = mpsc::channel(1024);

        let mut shard = SmoltcpShard::new(config, event_rx, wg_reply_rx, wg_tx);

        // WG packets can also come through the event channel
        let event = BridgeEvent::WgPacket {
            data: Bytes::from(vec![0u8; 200]),
        };
        shard.handle_event(event).await;

        // Should have processed the packet
        assert_eq!(shard.stats.events_processed, 1);
        assert_eq!(shard.stats.wg_packets_received, 1);
        assert_eq!(shard.stats.wg_bytes_received, 200);
    }

    #[tokio::test]
    async fn test_wg_rx_buffer_full_drops_packet() {
        let config = test_config();
        let (_, event_rx) = create_event_channel(EventChannelConfig::default());
        let (_, wg_reply_rx) = mpsc::channel(1024);
        let (wg_tx, _) = mpsc::channel(1024);

        let mut shard = SmoltcpShard::new(config, event_rx, wg_reply_rx, wg_tx);

        // Fill the RX buffer to capacity
        for _ in 0..DEVICE_RX_BUFFER_CAPACITY {
            let packet = Bytes::from(vec![0u8; 100]);
            shard.handle_wg_packet(packet);
        }

        assert_eq!(shard.stats.wg_packets_received, DEVICE_RX_BUFFER_CAPACITY as u64);
        assert_eq!(shard.stats.wg_packets_dropped, 0);

        // Next packet should be dropped
        let packet = Bytes::from(vec![0u8; 100]);
        shard.handle_wg_packet(packet);

        // Packet was dropped, not received
        assert_eq!(shard.stats.wg_packets_received, DEVICE_RX_BUFFER_CAPACITY as u64);
        assert_eq!(shard.stats.wg_packets_dropped, 1);
    }
}
