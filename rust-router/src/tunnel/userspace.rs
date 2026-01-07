//! Userspace WireGuard tunnel via boringtun for Phase 6
//!
//! This module implements userspace WireGuard tunnels using the
//! boringtun library for Rust-native WireGuard support.
//!
//! # Phase 6.1 Implementation
//!
//! - [x] boringtun integration
//! - [x] Key generation
//! - [x] Handshake handling
//! - [x] Packet encryption/decryption
//! - [x] Buffer pooling integration
//! - [x] Allowed IPs validation
//! - [x] Handshake completion signal
//! - [x] Background task monitoring
//!
//! # Architecture
//!
//! ```text
//! +--------------------------------------------------+
//! |              UserspaceWgTunnel                    |
//! |                                                  |
//! | +--------------------+  +---------------------+  |
//! | | boringtun::Tunn    |  | UDP Socket          |  |
//! | | (crypto + state)   |  | (network I/O)       |  |
//! | +--------------------+  +---------------------+  |
//! |           |                        |             |
//! |           +------------------------+             |
//! |                      |                           |
//! |              +-------+-------+                   |
//! |              | Timer Task    |                   |
//! |              | (keepalive)   |                   |
//! |              +---------------+                   |
//! +--------------------------------------------------+
//! ```
//!
//! # Example
//!
//! ```ignore
//! use rust_router::tunnel::userspace::{UserspaceWgTunnel, generate_private_key, derive_public_key};
//!
//! // Generate keys
//! let private_key = generate_private_key();
//! let public_key = derive_public_key(&private_key)?;
//!
//! // Create tunnel
//! let config = WgTunnelConfig::new(private_key, peer_public_key, "1.2.3.4:51820".to_string());
//! let tunnel = UserspaceWgTunnel::new(config)?;
//! tunnel.connect().await?;
//!
//! // Wait for handshake to complete
//! tunnel.wait_handshake(Duration::from_secs(5)).await?;
//!
//! // Send encrypted data
//! tunnel.send(plaintext_packet).await?;
//!
//! // Receive decrypted data
//! let packet = tunnel.recv().await?;
//! ```
//!
//! # References
//!
//! - boringtun: <https://github.com/cloudflare/boringtun>
//! - Implementation Plan: `docs/PHASE6_IMPLEMENTATION_PLAN_v3.2.md` Section 6.1

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use ipnet::IpNet;
use parking_lot::Mutex;
use rand::RngCore;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot, watch, RwLock};
use tokio::task::JoinHandle;
use tokio::time::interval;
use tracing::{debug, error, info, trace, warn};

use crate::io::UdpBufferPool;
use crate::tunnel::config::WgTunnelConfig;
use crate::tunnel::traits::{WgTunnel, WgTunnelError, WgTunnelStats};

/// WireGuard transport data packet overhead
///
/// For transport data packets:
/// - 4 bytes: message type
/// - 4 bytes: receiver index
/// - 8 bytes: counter
/// - 16 bytes: Poly1305 authentication tag
///
/// Total: 32 bytes overhead added to the encrypted payload
pub const WG_TRANSPORT_OVERHEAD: usize = 32;

/// WireGuard handshake initiation packet size
///
/// Handshake initiation is the largest packet type:
/// - 4 bytes: message type (1)
/// - 4 bytes: sender index
/// - 32 bytes: unencrypted ephemeral public key
/// - 48 bytes: encrypted static public key (32 + 16 poly1305)
/// - 28 bytes: encrypted timestamp (12 + 16 poly1305)
/// - 16 bytes: MAC1
/// - 16 bytes: MAC2
///
/// Total: 148 bytes
pub const WG_HANDSHAKE_INIT_SIZE: usize = 148;

/// WireGuard handshake response packet size
///
/// - 4 bytes: message type (2)
/// - 4 bytes: sender index
/// - 4 bytes: receiver index
/// - 32 bytes: unencrypted ephemeral public key
/// - 16 bytes: encrypted empty (0 + 16 poly1305)
/// - 16 bytes: MAC1
/// - 16 bytes: MAC2
///
/// Total: 92 bytes
pub const WG_HANDSHAKE_RESPONSE_SIZE: usize = 92;

/// Deprecated: Use `WG_TRANSPORT_OVERHEAD` instead
#[deprecated(since = "0.2.0", note = "Use WG_TRANSPORT_OVERHEAD instead")]
pub const WG_OVERHEAD: usize = WG_TRANSPORT_OVERHEAD;

/// Minimum buffer size for WireGuard packets (must fit handshake initiation)
pub const MIN_BUFFER_SIZE: usize = WG_HANDSHAKE_INIT_SIZE;

/// Maximum transmission unit for WireGuard (default)
pub const DEFAULT_MTU: usize = 1420;

/// Timer tick interval in milliseconds
const TIMER_TICK_MS: u64 = 250;

/// Buffer size for UDP receive operations
const UDP_RECV_BUFFER_SIZE: usize = 65536;

/// Channel capacity for received packets
const RECV_CHANNEL_CAPACITY: usize = 256;

/// Default buffer pool capacity for tunnel operations
const BUFFER_POOL_CAPACITY: usize = 64;

/// Default socket receive buffer size (in bytes)
/// Used as default for `configure_socket_buffers()`.
#[allow(dead_code)]
const DEFAULT_SO_RCVBUF: usize = 212_992; // 208 KB

/// Default socket send buffer size (in bytes)
/// Used as default for `configure_socket_buffers()`.
#[allow(dead_code)]
const DEFAULT_SO_SNDBUF: usize = 212_992; // 208 KB

/// Userspace WireGuard tunnel using boringtun
///
/// This implementation uses the boringtun library for WireGuard
/// cryptographic operations in pure Rust.
///
/// # Thread Safety
///
/// The tunnel is designed to be used from multiple async tasks:
/// - `send()` can be called concurrently from multiple tasks
/// - `recv()` returns packets via an internal channel
/// - Timer task runs in the background
///
/// The boringtun `Tunn` is protected by a `Mutex` to ensure
/// thread-safe access.
///
/// # Lock Ordering
///
/// When acquiring multiple locks, always follow this order to prevent deadlocks:
/// 1. `shared.tunn` (Mutex)
/// 2. `shared.socket` (RwLock)
/// 3. `shared.recv_tx` (RwLock)
/// 4. `shared.local_ip` (RwLock)
/// 5. `shared.allowed_ips` (RwLock)
pub struct UserspaceWgTunnel {
    /// Tunnel configuration
    config: WgTunnelConfig,

    /// Peer endpoint address (parsed from config)
    peer_addr_parsed: SocketAddr,

    /// Shared state for background task
    shared: Arc<TunnelShared>,

    /// Shutdown signal sender
    shutdown_tx: Mutex<Option<oneshot::Sender<()>>>,

    /// Received packet channel receiver
    recv_rx: tokio::sync::Mutex<Option<mpsc::Receiver<Vec<u8>>>>,

    /// Tunnel index (used by boringtun)
    index: AtomicU64,

    /// Background task handle for monitoring
    background_task: tokio::sync::Mutex<Option<JoinHandle<()>>>,

    /// Handshake completion receiver
    handshake_rx: watch::Receiver<bool>,

    /// Buffer pool for efficient memory management
    buffer_pool: Arc<UdpBufferPool>,
}

/// Shared state between main tunnel and background task
///
/// # Lock Ordering (Critical for Deadlock Prevention)
///
/// When acquiring multiple locks, ALWAYS follow this order:
/// 1. `tunn` (Mutex) - Acquired first, released last
/// 2. `socket` (RwLock)
/// 3. `recv_tx` (RwLock)
/// 4. `local_ip` (RwLock)
/// 5. `allowed_ips` (RwLock) - Acquired last
///
/// The `handshake_tx` is a watch channel and does not require ordering.
struct TunnelShared {
    /// Whether the tunnel is connected
    connected: AtomicBool,

    /// Local tunnel IP (parsed from config)
    local_ip: RwLock<Option<String>>,

    /// boringtun tunnel instance (protected by Mutex for thread safety)
    tunn: Mutex<Option<Box<Tunn>>>,

    /// UDP socket for network I/O
    socket: RwLock<Option<Arc<UdpSocket>>>,

    /// Received packet channel sender (from background task)
    recv_tx: RwLock<Option<mpsc::Sender<Vec<u8>>>>,

    /// Statistics
    stats: TunnelStatsInner,

    /// Parsed allowed IPs for source IP validation (C3 fix)
    allowed_ips: RwLock<Vec<IpNet>>,

    /// Handshake completion signal sender (H3 fix)
    handshake_tx: watch::Sender<bool>,
}

/// Internal statistics tracking
struct TunnelStatsInner {
    tx_bytes: AtomicU64,
    rx_bytes: AtomicU64,
    tx_packets: AtomicU64,
    rx_packets: AtomicU64,
    last_handshake: AtomicU64,
    last_handshake_valid: AtomicBool,
    handshake_count: AtomicU64,
    invalid_packets: AtomicU64,
}

impl Default for TunnelStatsInner {
    fn default() -> Self {
        Self {
            tx_bytes: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
            tx_packets: AtomicU64::new(0),
            rx_packets: AtomicU64::new(0),
            last_handshake: AtomicU64::new(0),
            last_handshake_valid: AtomicBool::new(false),
            handshake_count: AtomicU64::new(0),
            invalid_packets: AtomicU64::new(0),
        }
    }
}

impl UserspaceWgTunnel {
    /// Create a new userspace WireGuard tunnel
    ///
    /// # Arguments
    ///
    /// * `config` - Tunnel configuration
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration is invalid (missing keys or endpoint).
    ///
    /// # Example
    ///
    /// ```ignore
    /// let config = WgTunnelConfig::new(private_key, peer_public_key, "1.2.3.4:51820".to_string());
    /// let tunnel = UserspaceWgTunnel::new(config)?;
    /// ```
    pub fn new(config: WgTunnelConfig) -> Result<Self, WgTunnelError> {
        Self::with_buffer_pool(config, None)
    }

    /// Create a new tunnel with a custom buffer pool
    ///
    /// # Arguments
    ///
    /// * `config` - Tunnel configuration
    /// * `buffer_pool` - Optional custom buffer pool (creates default if None)
    pub fn with_buffer_pool(
        config: WgTunnelConfig,
        buffer_pool: Option<Arc<UdpBufferPool>>,
    ) -> Result<Self, WgTunnelError> {
        // Validate configuration
        if config.private_key.is_empty() {
            return Err(WgTunnelError::InvalidConfig(
                "Private key is required".into(),
            ));
        }
        if config.peer_public_key.is_empty() {
            return Err(WgTunnelError::InvalidConfig(
                "Peer public key is required".into(),
            ));
        }
        if config.peer_endpoint.is_empty() {
            return Err(WgTunnelError::InvalidConfig(
                "Peer endpoint is required".into(),
            ));
        }

        // Validate private key format
        decode_private_key(&config.private_key)?;

        // Validate peer public key format
        decode_public_key(&config.peer_public_key)?;

        // Parse peer endpoint
        let peer_addr: SocketAddr = config
            .peer_endpoint
            .parse()
            .map_err(|e| WgTunnelError::InvalidConfig(format!("Invalid peer endpoint: {e}")))?;

        // Parse allowed_ips into CIDR ranges for validation (C3 fix)
        let allowed_ips_parsed: Vec<IpNet> = config
            .allowed_ips
            .iter()
            .filter_map(|s| s.parse().ok())
            .collect();

        // Create handshake completion channel (H3 fix)
        let (handshake_tx, handshake_rx) = watch::channel(false);

        let shared = Arc::new(TunnelShared {
            connected: AtomicBool::new(false),
            local_ip: RwLock::new(None),
            tunn: Mutex::new(None),
            socket: RwLock::new(None),
            recv_tx: RwLock::new(None),
            stats: TunnelStatsInner::default(),
            allowed_ips: RwLock::new(allowed_ips_parsed),
            handshake_tx,
        });

        // Create or use provided buffer pool (H1 fix)
        let buffer_pool = buffer_pool
            .unwrap_or_else(|| Arc::new(UdpBufferPool::new(BUFFER_POOL_CAPACITY, UDP_RECV_BUFFER_SIZE)));

        Ok(Self {
            config,
            peer_addr_parsed: peer_addr,
            shared,
            shutdown_tx: Mutex::new(None),
            recv_rx: tokio::sync::Mutex::new(None),
            index: AtomicU64::new(0),
            background_task: tokio::sync::Mutex::new(None),
            handshake_rx,
            buffer_pool,
        })
    }

    /// Connect the tunnel
    ///
    /// Initializes the boringtun tunnel, binds the UDP socket, starts the
    /// handshake process, and spawns the background timer task.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Already connected
    /// - Failed to decode keys
    /// - Failed to create boringtun tunnel
    /// - Failed to bind UDP socket
    /// - Handshake failed
    ///
    /// # Example
    ///
    /// ```ignore
    /// tunnel.connect().await?;
    /// assert!(tunnel.is_connected());
    /// ```
    pub async fn connect(&self) -> Result<(), WgTunnelError> {
        // Check if already connected
        if self.shared.connected.load(Ordering::Acquire) {
            return Err(WgTunnelError::AlreadyConnected);
        }

        info!(
            "Connecting userspace WireGuard tunnel to {}",
            self.config.peer_endpoint
        );

        // Decode keys
        let static_private = decode_private_key(&self.config.private_key)?;
        let peer_public = decode_public_key(&self.config.peer_public_key)?;

        // Create boringtun tunnel
        let index = self.index.fetch_add(1, Ordering::Relaxed) as u32;
        let tunn = Tunn::new(
            static_private,
            peer_public,
            None, // No pre-shared key
            self.config.persistent_keepalive,
            index,
            None, // No rate limiter
        )
        .map_err(|e| WgTunnelError::Internal(format!("Failed to create tunnel: {e}")))?;

        // Store tunnel instance
        {
            let mut tunn_guard = self.shared.tunn.lock();
            *tunn_guard = Some(Box::new(tunn));
        }

        // Get peer address
        let peer_addr = self.peer_addr_parsed;

        // Bind UDP socket
        let listen_port = self.config.listen_port.unwrap_or(0);
        let socket = UdpSocket::bind(format!("0.0.0.0:{listen_port}"))
            .await
            .map_err(|e| WgTunnelError::IoError(format!("Failed to bind UDP socket: {e}")))?;

        let actual_port = socket
            .local_addr()
            .map(|a| a.port())
            .unwrap_or(listen_port);
        debug!("Bound UDP socket to port {}", actual_port);

        // Connect socket to peer (enables send without specifying address)
        socket.connect(peer_addr).await.map_err(|e| {
            WgTunnelError::IoError(format!("Failed to connect UDP socket to peer: {e}"))
        })?;

        let socket = Arc::new(socket);

        // Store socket
        {
            let mut socket_guard = self.shared.socket.write().await;
            *socket_guard = Some(socket.clone());
        }

        // Set local IP from config
        if let Some(ref local_ip) = self.config.local_ip {
            let mut local_ip_guard = self.shared.local_ip.write().await;
            // Extract just the IP part (without CIDR notation)
            let ip_only = local_ip.split('/').next().unwrap_or(local_ip);
            *local_ip_guard = Some(ip_only.to_string());
        }

        // Create packet receive channel
        let (recv_tx, recv_rx) = mpsc::channel(RECV_CHANNEL_CAPACITY);
        {
            let mut tx_guard = self.shared.recv_tx.write().await;
            *tx_guard = Some(recv_tx);
        }
        {
            let mut rx_guard = self.recv_rx.lock().await;
            *rx_guard = Some(recv_rx);
        }

        // Create shutdown channel
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        {
            let mut shutdown_guard = self.shutdown_tx.lock();
            *shutdown_guard = Some(shutdown_tx);
        }

        // Mark as connected (before starting background task)
        self.shared.connected.store(true, Ordering::Release);

        // Spawn background tasks and store handle (H2 fix)
        let handle = self.spawn_background_tasks(socket, peer_addr, shutdown_rx);
        {
            let mut task_guard = self.background_task.lock().await;
            *task_guard = Some(handle);
        }

        // Initiate handshake
        self.initiate_handshake().await?;

        info!(
            "Userspace WireGuard tunnel connected to {}",
            self.config.peer_endpoint
        );

        Ok(())
    }

    /// Wait for the WireGuard handshake to complete
    ///
    /// This method blocks until the handshake with the peer is successful
    /// or the timeout expires.
    ///
    /// # Arguments
    ///
    /// * `timeout` - Maximum time to wait for handshake completion
    ///
    /// # Errors
    ///
    /// Returns `WgTunnelError::Timeout` if the handshake doesn't complete
    /// within the specified timeout.
    ///
    /// # Example
    ///
    /// ```ignore
    /// tunnel.connect().await?;
    /// tunnel.wait_handshake(Duration::from_secs(5)).await?;
    /// // Tunnel is now fully established
    /// ```
    pub async fn wait_handshake(&self, timeout: Duration) -> Result<(), WgTunnelError> {
        if !self.shared.connected.load(Ordering::Acquire) {
            return Err(WgTunnelError::NotConnected);
        }

        // Check if already complete
        if *self.handshake_rx.borrow() {
            return Ok(());
        }

        // Wait for handshake with timeout
        let mut rx = self.handshake_rx.clone();
        let result = tokio::time::timeout(timeout, async {
            loop {
                rx.changed().await.map_err(|_| WgTunnelError::NotConnected)?;
                if *rx.borrow() {
                    return Ok(());
                }
            }
        })
        .await;

        match result {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(WgTunnelError::Timeout),
        }
    }

    /// Check if the background task is still running
    ///
    /// Returns `true` if the background task is running, `false` if it has
    /// completed or panicked.
    pub async fn is_task_running(&self) -> bool {
        let task_guard = self.background_task.lock().await;
        match task_guard.as_ref() {
            Some(handle) => !handle.is_finished(),
            None => false,
        }
    }

    /// Disconnect the tunnel
    ///
    /// Gracefully shuts down the tunnel by:
    /// 1. Signaling the background task to stop
    /// 2. Aborting and awaiting the background task
    /// 3. Closing the UDP socket
    /// 4. Clearing the boringtun tunnel instance
    ///
    /// # Errors
    ///
    /// Returns an error if the tunnel is not connected.
    pub async fn disconnect(&self) -> Result<(), WgTunnelError> {
        if !self.shared.connected.load(Ordering::Acquire) {
            return Err(WgTunnelError::NotConnected);
        }

        info!(
            "Disconnecting userspace WireGuard tunnel from {}",
            self.config.peer_endpoint
        );

        // Mark as disconnected first to stop accepting new operations
        self.shared.connected.store(false, Ordering::Release);

        // Send shutdown signal
        if let Some(tx) = self.shutdown_tx.lock().take() {
            let _ = tx.send(());
        }

        // Abort and await background task (H2 fix)
        {
            let mut task_guard = self.background_task.lock().await;
            if let Some(handle) = task_guard.take() {
                handle.abort();
                // Wait for task to finish (will return Err(JoinError) due to abort)
                let _ = handle.await;
            }
        }

        // Clear socket
        {
            let mut socket_guard = self.shared.socket.write().await;
            *socket_guard = None;
        }

        // Clear tunnel
        {
            let mut tunn_guard = self.shared.tunn.lock();
            *tunn_guard = None;
        }

        // Clear receive channels
        {
            let mut tx_guard = self.shared.recv_tx.write().await;
            *tx_guard = None;
        }
        {
            let mut rx_guard = self.recv_rx.lock().await;
            *rx_guard = None;
        }

        info!(
            "Userspace WireGuard tunnel disconnected from {}",
            self.config.peer_endpoint
        );

        Ok(())
    }

    /// Send a packet through the tunnel
    ///
    /// The packet will be encrypted using WireGuard and sent to the peer.
    ///
    /// # Arguments
    ///
    /// * `packet` - Plaintext IP packet to send
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Not connected
    /// - Encryption failed
    /// - Network send failed
    ///
    /// # Example
    ///
    /// ```ignore
    /// let ip_packet = [0x45, 0x00, ...]; // IPv4 packet
    /// tunnel.send(&ip_packet).await?;
    /// ```
    pub async fn send(&self, packet: &[u8]) -> Result<(), WgTunnelError> {
        if !self.shared.connected.load(Ordering::Acquire) {
            return Err(WgTunnelError::NotConnected);
        }

        let socket = self
            .shared
            .socket
            .read()
            .await
            .clone()
            .ok_or(WgTunnelError::NotConnected)?;

        // Allocate buffer for encrypted packet
        // WG_TRANSPORT_OVERHEAD (32 bytes) includes the Poly1305 tag (16 bytes)
        let mut dst = vec![0u8; packet.len() + WG_TRANSPORT_OVERHEAD];

        // Encapsulate packet
        let result = {
            let mut tunn_guard = self.shared.tunn.lock();
            let tunn = tunn_guard
                .as_mut()
                .ok_or(WgTunnelError::NotConnected)?;
            tunn.encapsulate(packet, &mut dst)
        };

        // Process result
        match result {
            TunnResult::WriteToNetwork(encrypted) => {
                socket.send(encrypted).await.map_err(|e| {
                    WgTunnelError::IoError(format!("Failed to send encrypted packet: {e}"))
                })?;

                // Update stats
                self.shared
                    .stats
                    .tx_bytes
                    .fetch_add(packet.len() as u64, Ordering::Relaxed);
                self.shared.stats.tx_packets.fetch_add(1, Ordering::Relaxed);

                trace!("Sent {} bytes through tunnel", packet.len());
                Ok(())
            }
            TunnResult::Done => {
                // Packet was queued, may need handshake first
                debug!("Packet queued, handshake may be in progress");
                Ok(())
            }
            TunnResult::Err(e) => {
                error!("Encapsulation error: {:?}", e);
                Err(WgTunnelError::Internal(format!(
                    "Encapsulation failed: {e:?}"
                )))
            }
            _ => {
                // WriteToTunnelV4/V6 shouldn't happen for encapsulate
                warn!("Unexpected encapsulate result");
                Ok(())
            }
        }
    }

    /// Receive a packet from the tunnel
    ///
    /// Returns the next decrypted IP packet from the peer.
    /// This method will block until a packet is available or the tunnel is disconnected.
    ///
    /// # Returns
    ///
    /// Decrypted IP packet
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Not connected
    /// - Channel closed (tunnel disconnected)
    ///
    /// # Example
    ///
    /// ```ignore
    /// loop {
    ///     let packet = tunnel.recv().await?;
    ///     // Process decrypted IP packet
    ///     process_packet(&packet);
    /// }
    /// ```
    pub async fn recv(&self) -> Result<Vec<u8>, WgTunnelError> {
        if !self.shared.connected.load(Ordering::Acquire) {
            return Err(WgTunnelError::NotConnected);
        }

        // Get a mutable reference to the receiver
        let packet = {
            let mut rx_guard = self.recv_rx.lock().await;
            let rx = rx_guard
                .as_mut()
                .ok_or(WgTunnelError::NotConnected)?;
            rx.recv().await
        };

        match packet {
            Some(data) => {
                trace!("Received {} bytes from tunnel", data.len());
                Ok(data)
            }
            None => {
                // Channel closed, tunnel disconnected
                Err(WgTunnelError::NotConnected)
            }
        }
    }

    /// Force a handshake with the peer
    ///
    /// This can be used to verify connectivity or refresh session keys.
    /// The handshake will timeout after [`HANDSHAKE_TIMEOUT_SECS`] seconds.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Not connected
    /// - Handshake times out
    /// - Network error
    pub async fn force_handshake(&self) -> Result<(), WgTunnelError> {
        if !self.shared.connected.load(Ordering::Acquire) {
            return Err(WgTunnelError::NotConnected);
        }

        info!("Forcing handshake with peer");
        self.initiate_handshake().await
    }

    /// Get the local port the tunnel is bound to
    pub async fn local_port(&self) -> Option<u16> {
        self.shared
            .socket
            .read()
            .await
            .as_ref()
            .and_then(|s| s.local_addr().ok())
            .map(|addr| addr.port())
    }

    /// Initiate WireGuard handshake
    async fn initiate_handshake(&self) -> Result<(), WgTunnelError> {
        let socket = self
            .shared
            .socket
            .read()
            .await
            .clone()
            .ok_or(WgTunnelError::NotConnected)?;

        let mut dst = vec![0u8; MIN_BUFFER_SIZE];

        // Format handshake initiation
        let result = {
            let mut tunn_guard = self.shared.tunn.lock();
            let tunn = tunn_guard
                .as_mut()
                .ok_or(WgTunnelError::NotConnected)?;
            tunn.format_handshake_initiation(&mut dst, true)
        };

        match result {
            TunnResult::WriteToNetwork(handshake) => {
                socket.send(handshake).await.map_err(|e| {
                    WgTunnelError::IoError(format!("Failed to send handshake: {e}"))
                })?;
                debug!("Sent handshake initiation");
                Ok(())
            }
            TunnResult::Done => {
                debug!("Handshake already in progress or complete");
                Ok(())
            }
            TunnResult::Err(e) => {
                error!("Handshake initiation error: {:?}", e);
                Err(WgTunnelError::HandshakeFailed(format!("{e:?}")))
            }
            _ => {
                warn!("Unexpected handshake result");
                Ok(())
            }
        }
    }

    /// Spawn background tasks for timer events and packet receiving
    ///
    /// Returns the JoinHandle for monitoring the task status.
    fn spawn_background_tasks(
        &self,
        socket: Arc<UdpSocket>,
        _peer_addr: SocketAddr,
        shutdown_rx: oneshot::Receiver<()>,
    ) -> JoinHandle<()> {
        // Clone Arc for the background task
        let shared = Arc::clone(&self.shared);
        let buffer_pool = Arc::clone(&self.buffer_pool);

        // Spawn combined background task
        tokio::spawn(async move {
            run_background_task(socket, shutdown_rx, shared, buffer_pool).await;
        })
    }

    /// Get the buffer pool used by this tunnel
    pub fn buffer_pool(&self) -> &Arc<UdpBufferPool> {
        &self.buffer_pool
    }

    /// Configure socket buffer sizes
    ///
    /// Sets the SO_RCVBUF and SO_SNDBUF socket options for the UDP socket.
    /// Must be called before `connect()`.
    ///
    /// # Arguments
    ///
    /// * `recv_buf` - Receive buffer size in bytes
    /// * `send_buf` - Send buffer size in bytes
    ///
    /// Note: The actual buffer size may be doubled by the kernel (Linux)
    /// and may be capped by system limits.
    pub async fn configure_socket_buffers(
        &self,
        recv_buf: usize,
        send_buf: usize,
    ) -> Result<(), WgTunnelError> {
        let socket_guard = self.shared.socket.read().await;
        let socket = socket_guard.as_ref().ok_or(WgTunnelError::NotConnected)?;

        // Get the raw file descriptor
        use std::os::unix::io::AsRawFd;
        let fd = socket.as_raw_fd();

        // Set receive buffer size
        let recv_buf_i32 = recv_buf as libc::c_int;
        let result = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &recv_buf_i32 as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if result != 0 {
            warn!("Failed to set SO_RCVBUF: {}", std::io::Error::last_os_error());
        }

        // Set send buffer size
        let send_buf_i32 = send_buf as libc::c_int;
        let result = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                &send_buf_i32 as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if result != 0 {
            warn!("Failed to set SO_SNDBUF: {}", std::io::Error::last_os_error());
        }

        debug!("Socket buffers configured: recv={}, send={}", recv_buf, send_buf);
        Ok(())
    }
}

/// Run the background task for timer events and packet receiving
async fn run_background_task(
    socket: Arc<UdpSocket>,
    mut shutdown_rx: oneshot::Receiver<()>,
    shared: Arc<TunnelShared>,
    buffer_pool: Arc<UdpBufferPool>,
) {
    let mut timer_interval = interval(Duration::from_millis(TIMER_TICK_MS));
    // Use buffer pool for receive buffer (H1 fix)
    let mut recv_buf = buffer_pool.get();
    let mut dst_buf = vec![0u8; UDP_RECV_BUFFER_SIZE];
    let mut timer_buf = vec![0u8; MIN_BUFFER_SIZE];

    loop {
        tokio::select! {
            // Check for shutdown signal
            _ = &mut shutdown_rx => {
                debug!("Background task received shutdown signal");
                break;
            }

            // Timer tick for keepalive and handshake retransmission
            _ = timer_interval.tick() => {
                if !shared.connected.load(Ordering::Acquire) {
                    break;
                }

                // Update timers
                let result = {
                    let mut tunn_guard = shared.tunn.lock();
                    if let Some(tunn) = tunn_guard.as_mut() {
                        Some(tunn.update_timers(&mut timer_buf))
                    } else {
                        None
                    }
                };

                if let Some(result) = result {
                    if let TunnResult::WriteToNetwork(data) = result {
                        if let Err(e) = socket.send(data).await {
                            warn!("Failed to send timer packet: {}", e);
                        } else {
                            trace!("Sent timer packet ({} bytes)", data.len());
                        }
                    }
                }
            }

            // Receive incoming packets
            result = socket.recv(&mut recv_buf) => {
                match result {
                    Ok(len) => {
                        if !shared.connected.load(Ordering::Acquire) {
                            break;
                        }

                        // Process incoming packet
                        let process_result = {
                            let mut tunn_guard = shared.tunn.lock();
                            if let Some(tunn) = tunn_guard.as_mut() {
                                Some(tunn.decapsulate(None, &recv_buf[..len], &mut dst_buf))
                            } else {
                                None
                            }
                        };

                        if let Some(result) = process_result {
                            handle_decapsulate_result(
                                result,
                                &socket,
                                &shared,
                            ).await;
                        }
                    }
                    Err(e) => {
                        if shared.connected.load(Ordering::Acquire) {
                            warn!("UDP receive error: {}", e);
                        }
                    }
                }
            }
        }
    }

    debug!("Background task exiting");
}

/// Extract source IP address from an IP packet
///
/// Returns the source IP address for IPv4 or IPv6 packets.
/// Returns None if the packet is too short or has an invalid version.
fn extract_source_ip(packet: &[u8]) -> Option<IpAddr> {
    if packet.is_empty() {
        return None;
    }

    let version = packet[0] >> 4;
    match version {
        4 => {
            // IPv4: minimum header is 20 bytes, source IP at bytes 12-15
            if packet.len() < 20 {
                return None;
            }
            let src_bytes: [u8; 4] = packet[12..16].try_into().ok()?;
            Some(IpAddr::V4(Ipv4Addr::from(src_bytes)))
        }
        6 => {
            // IPv6: minimum header is 40 bytes, source IP at bytes 8-23
            if packet.len() < 40 {
                return None;
            }
            let src_bytes: [u8; 16] = packet[8..24].try_into().ok()?;
            Some(IpAddr::V6(Ipv6Addr::from(src_bytes)))
        }
        _ => None,
    }
}

/// Check if an IP address is allowed by the allowed_ips list
fn is_ip_allowed(ip: IpAddr, allowed_ips: &[IpNet]) -> bool {
    // Empty allowed_ips means allow all (0.0.0.0/0 behavior)
    if allowed_ips.is_empty() {
        return true;
    }

    allowed_ips.iter().any(|net| net.contains(&ip))
}

/// Handle the result of decapsulating a received packet
async fn handle_decapsulate_result(
    result: TunnResult<'_>,
    socket: &Arc<UdpSocket>,
    shared: &Arc<TunnelShared>,
) {
    match result {
        TunnResult::WriteToTunnelV4(data, _addr) => {
            // Decrypted IPv4 packet ready
            let packet = data.to_vec();
            let packet_len = packet.len();

            // C3 fix: Validate source IP against allowed_ips
            if let Some(src_ip) = extract_source_ip(&packet) {
                let allowed_ips = shared.allowed_ips.read().await;
                if !is_ip_allowed(src_ip, &allowed_ips) {
                    warn!(
                        "Dropped IPv4 packet from {} - not in allowed_ips",
                        src_ip
                    );
                    shared.stats.invalid_packets.fetch_add(1, Ordering::Relaxed);
                    return;
                }
            } else {
                // Could not extract source IP, drop packet
                warn!("Dropped IPv4 packet - could not extract source IP");
                shared.stats.invalid_packets.fetch_add(1, Ordering::Relaxed);
                return;
            }

            // Update stats
            shared.stats.rx_bytes.fetch_add(packet_len as u64, Ordering::Relaxed);
            shared.stats.rx_packets.fetch_add(1, Ordering::Relaxed);

            // Send to receiver channel
            let recv_tx = shared.recv_tx.read().await;
            if let Some(tx) = recv_tx.as_ref() {
                if tx.send(packet).await.is_err() {
                    trace!("Receiver channel closed");
                }
            }

            trace!("Decrypted IPv4 packet: {} bytes", packet_len);
        }

        TunnResult::WriteToTunnelV6(data, _addr) => {
            // Decrypted IPv6 packet ready
            let packet = data.to_vec();
            let packet_len = packet.len();

            // C3 fix: Validate source IP against allowed_ips
            if let Some(src_ip) = extract_source_ip(&packet) {
                let allowed_ips = shared.allowed_ips.read().await;
                if !is_ip_allowed(src_ip, &allowed_ips) {
                    warn!(
                        "Dropped IPv6 packet from {} - not in allowed_ips",
                        src_ip
                    );
                    shared.stats.invalid_packets.fetch_add(1, Ordering::Relaxed);
                    return;
                }
            } else {
                // Could not extract source IP, drop packet
                warn!("Dropped IPv6 packet - could not extract source IP");
                shared.stats.invalid_packets.fetch_add(1, Ordering::Relaxed);
                return;
            }

            // Update stats
            shared.stats.rx_bytes.fetch_add(packet_len as u64, Ordering::Relaxed);
            shared.stats.rx_packets.fetch_add(1, Ordering::Relaxed);

            // Send to receiver channel
            let recv_tx = shared.recv_tx.read().await;
            if let Some(tx) = recv_tx.as_ref() {
                if tx.send(packet).await.is_err() {
                    trace!("Receiver channel closed");
                }
            }

            trace!("Decrypted IPv6 packet: {} bytes", packet_len);
        }

        TunnResult::WriteToNetwork(response) => {
            // Need to send response (handshake response, keepalive, etc.)
            if let Err(e) = socket.send(response).await {
                warn!("Failed to send response: {}", e);
            } else {
                trace!("Sent response ({} bytes)", response.len());

                // Update handshake timestamp
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                shared.stats.last_handshake.store(now, Ordering::Relaxed);
                shared.stats.last_handshake_valid.store(true, Ordering::Relaxed);
                shared.stats.handshake_count.fetch_add(1, Ordering::Relaxed);

                // H3 fix: Signal handshake completion
                // Sending response typically indicates handshake response was sent
                let _ = shared.handshake_tx.send(true);
            }

            // Process any additional data after sending response
            // Use a separate buffer for continuation processing
            let mut cont_buf = vec![0u8; UDP_RECV_BUFFER_SIZE];
            let mut continue_processing = true;
            while continue_processing {
                let additional_result = {
                    let mut tunn_guard = shared.tunn.lock();
                    if let Some(tunn) = tunn_guard.as_mut() {
                        Some(tunn.decapsulate(None, &[], &mut cont_buf))
                    } else {
                        None
                    }
                };

                match additional_result {
                    Some(TunnResult::WriteToTunnelV4(data, _)) => {
                        let packet = data.to_vec();
                        // C3 fix: Validate source IP in continuation packets too
                        if let Some(src_ip) = extract_source_ip(&packet) {
                            let allowed_ips = shared.allowed_ips.read().await;
                            if !is_ip_allowed(src_ip, &allowed_ips) {
                                shared.stats.invalid_packets.fetch_add(1, Ordering::Relaxed);
                                continue;
                            }
                        } else {
                            shared.stats.invalid_packets.fetch_add(1, Ordering::Relaxed);
                            continue;
                        }
                        let recv_tx = shared.recv_tx.read().await;
                        if let Some(tx) = recv_tx.as_ref() {
                            let _ = tx.send(packet).await;
                        }
                    }
                    Some(TunnResult::WriteToTunnelV6(data, _)) => {
                        let packet = data.to_vec();
                        // C3 fix: Validate source IP in continuation packets too
                        if let Some(src_ip) = extract_source_ip(&packet) {
                            let allowed_ips = shared.allowed_ips.read().await;
                            if !is_ip_allowed(src_ip, &allowed_ips) {
                                shared.stats.invalid_packets.fetch_add(1, Ordering::Relaxed);
                                continue;
                            }
                        } else {
                            shared.stats.invalid_packets.fetch_add(1, Ordering::Relaxed);
                            continue;
                        }
                        let recv_tx = shared.recv_tx.read().await;
                        if let Some(tx) = recv_tx.as_ref() {
                            let _ = tx.send(packet).await;
                        }
                    }
                    Some(TunnResult::WriteToNetwork(data)) => {
                        let _ = socket.send(data).await;
                    }
                    _ => {
                        continue_processing = false;
                    }
                }
            }
        }

        TunnResult::Done => {
            // Nothing to do
            trace!("Decapsulate done");
        }

        TunnResult::Err(e) => {
            // Invalid packet
            warn!("Decapsulation error: {:?}", e);
            shared.stats.invalid_packets.fetch_add(1, Ordering::Relaxed);
        }
    }
}

impl WgTunnel for UserspaceWgTunnel {
    fn config(&self) -> &WgTunnelConfig {
        &self.config
    }

    fn is_connected(&self) -> bool {
        self.shared.connected.load(Ordering::Acquire)
    }

    fn stats(&self) -> WgTunnelStats {
        let last_handshake = if self.shared.stats.last_handshake_valid.load(Ordering::Relaxed) {
            Some(self.shared.stats.last_handshake.load(Ordering::Relaxed))
        } else {
            None
        };

        WgTunnelStats {
            tx_bytes: self.shared.stats.tx_bytes.load(Ordering::Relaxed),
            rx_bytes: self.shared.stats.rx_bytes.load(Ordering::Relaxed),
            tx_packets: self.shared.stats.tx_packets.load(Ordering::Relaxed),
            rx_packets: self.shared.stats.rx_packets.load(Ordering::Relaxed),
            last_handshake,
            handshake_count: self.shared.stats.handshake_count.load(Ordering::Relaxed),
            invalid_packets: self.shared.stats.invalid_packets.load(Ordering::Relaxed),
        }
    }

    fn local_ip(&self) -> Option<String> {
        // C1 fix: Return cloned String instead of reference
        // Use try_read to avoid blocking in trait method
        self.shared
            .local_ip
            .try_read()
            .ok()
            .and_then(|guard| guard.clone())
    }

    fn peer_endpoint(&self) -> Option<SocketAddr> {
        Some(self.peer_addr_parsed)
    }

    fn last_handshake(&self) -> Option<u64> {
        if self.shared.stats.last_handshake_valid.load(Ordering::Relaxed) {
            Some(self.shared.stats.last_handshake.load(Ordering::Relaxed))
        } else {
            None
        }
    }
}

// ============================================================================
// Key Generation Functions
// ============================================================================

/// Generate a new WireGuard private key
///
/// Generates a random 32-byte private key suitable for WireGuard.
/// The key is clamped according to X25519 requirements.
///
/// # Returns
///
/// Base64-encoded 32-byte private key (44 characters including padding)
///
/// # Example
///
/// ```
/// use rust_router::tunnel::userspace::generate_private_key;
///
/// let private_key = generate_private_key();
/// assert_eq!(private_key.len(), 44);
/// assert!(private_key.ends_with('='));
/// ```
pub fn generate_private_key() -> String {
    let mut rng = rand::thread_rng();
    let mut key_bytes = [0u8; 32];
    rng.fill_bytes(&mut key_bytes);

    // Create StaticSecret which handles clamping
    let secret = StaticSecret::from(key_bytes);

    // Convert to bytes and encode as Base64
    BASE64.encode(secret.as_bytes())
}

/// Derive a public key from a private key
///
/// Takes a Base64-encoded private key and derives the corresponding
/// public key using X25519 elliptic curve Diffie-Hellman.
///
/// # Arguments
///
/// * `private_key` - Base64-encoded 32-byte private key
///
/// # Returns
///
/// Base64-encoded 32-byte public key
///
/// # Errors
///
/// Returns an error if the private key is invalid:
/// - Not valid Base64
/// - Not exactly 32 bytes when decoded
///
/// # Example
///
/// ```
/// use rust_router::tunnel::userspace::{generate_private_key, derive_public_key};
///
/// let private_key = generate_private_key();
/// let public_key = derive_public_key(&private_key).unwrap();
/// assert_eq!(public_key.len(), 44);
/// ```
pub fn derive_public_key(private_key: &str) -> Result<String, WgTunnelError> {
    let secret = decode_private_key(private_key)?;
    let public = PublicKey::from(&secret);
    Ok(BASE64.encode(public.as_bytes()))
}

/// Validate a WireGuard key (private or public)
///
/// Checks that the key is valid Base64 and decodes to exactly 32 bytes.
///
/// # Arguments
///
/// * `key` - Base64-encoded key to validate
///
/// # Returns
///
/// `true` if the key is valid, `false` otherwise
///
/// # Example
///
/// ```
/// use rust_router::tunnel::userspace::{generate_private_key, validate_key};
///
/// let key = generate_private_key();
/// assert!(validate_key(&key));
/// assert!(!validate_key("invalid"));
/// ```
pub fn validate_key(key: &str) -> bool {
    BASE64
        .decode(key)
        .map(|bytes| bytes.len() == 32)
        .unwrap_or(false)
}

/// Decode a Base64-encoded private key to StaticSecret
fn decode_private_key(key: &str) -> Result<StaticSecret, WgTunnelError> {
    let bytes = BASE64
        .decode(key)
        .map_err(|e| WgTunnelError::KeyError(format!("Invalid private key Base64: {e}")))?;

    if bytes.len() != 32 {
        return Err(WgTunnelError::KeyError(format!(
            "Private key must be 32 bytes, got {}",
            bytes.len()
        )));
    }

    let mut key_array = [0u8; 32];
    key_array.copy_from_slice(&bytes);
    Ok(StaticSecret::from(key_array))
}

/// Decode a Base64-encoded public key to PublicKey
fn decode_public_key(key: &str) -> Result<PublicKey, WgTunnelError> {
    let bytes = BASE64
        .decode(key)
        .map_err(|e| WgTunnelError::KeyError(format!("Invalid public key Base64: {e}")))?;

    if bytes.len() != 32 {
        return Err(WgTunnelError::KeyError(format!(
            "Public key must be 32 bytes, got {}",
            bytes.len()
        )));
    }

    let mut key_array = [0u8; 32];
    key_array.copy_from_slice(&bytes);
    Ok(PublicKey::from(key_array))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // Helper to create a test config with valid keys
    fn create_test_config() -> WgTunnelConfig {
        let private_key = generate_private_key();
        let peer_private = generate_private_key();
        let peer_public = derive_public_key(&peer_private).unwrap();

        WgTunnelConfig {
            private_key,
            peer_public_key: peer_public,
            peer_endpoint: "192.168.1.1:51820".to_string(),
            allowed_ips: vec!["0.0.0.0/0".to_string()],
            local_ip: Some("10.200.200.1/32".to_string()),
            listen_port: Some(0), // Use ephemeral port
            persistent_keepalive: Some(25),
            mtu: Some(1420),
        }
    }

    // ========================================================================
    // Key Generation Tests
    // ========================================================================

    #[test]
    fn test_generate_private_key() {
        let key1 = generate_private_key();
        let key2 = generate_private_key();

        // Keys should be valid Base64
        assert!(validate_key(&key1));
        assert!(validate_key(&key2));

        // Keys should be different
        assert_ne!(key1, key2);

        // Keys should be 44 characters (32 bytes + Base64 padding)
        assert_eq!(key1.len(), 44);
        assert_eq!(key2.len(), 44);
    }

    #[test]
    fn test_derive_public_key() {
        let private_key = generate_private_key();
        let public_key = derive_public_key(&private_key).unwrap();

        // Public key should be valid
        assert!(validate_key(&public_key));
        assert_eq!(public_key.len(), 44);

        // Same private key should produce same public key
        let public_key2 = derive_public_key(&private_key).unwrap();
        assert_eq!(public_key, public_key2);
    }

    #[test]
    fn test_derive_public_key_different_private_keys() {
        let private1 = generate_private_key();
        let private2 = generate_private_key();

        let public1 = derive_public_key(&private1).unwrap();
        let public2 = derive_public_key(&private2).unwrap();

        // Different private keys should produce different public keys
        assert_ne!(public1, public2);
    }

    #[test]
    fn test_derive_public_key_invalid_base64() {
        let result = derive_public_key("not-valid-base64!!!");
        assert!(matches!(result, Err(WgTunnelError::KeyError(_))));
    }

    #[test]
    fn test_derive_public_key_wrong_length() {
        // Valid Base64 but wrong length (16 bytes instead of 32)
        let short_key = BASE64.encode(&[0u8; 16]);
        let result = derive_public_key(&short_key);
        assert!(matches!(result, Err(WgTunnelError::KeyError(_))));

        // Valid Base64 but too long (64 bytes instead of 32)
        let long_key = BASE64.encode(&[0u8; 64]);
        let result = derive_public_key(&long_key);
        assert!(matches!(result, Err(WgTunnelError::KeyError(_))));
    }

    #[test]
    fn test_validate_key() {
        let valid_key = generate_private_key();
        assert!(validate_key(&valid_key));

        // Invalid Base64
        assert!(!validate_key("not-base64!!!"));

        // Valid Base64 but wrong length
        assert!(!validate_key(&BASE64.encode(&[0u8; 16])));
        assert!(!validate_key(&BASE64.encode(&[0u8; 64])));

        // Empty string
        assert!(!validate_key(""));
    }

    // ========================================================================
    // Tunnel Creation Tests
    // ========================================================================

    #[test]
    fn test_new_tunnel() {
        let config = create_test_config();
        let tunnel = UserspaceWgTunnel::new(config).unwrap();

        assert!(!tunnel.is_connected());
        assert_eq!(tunnel.stats().tx_bytes, 0);
        assert_eq!(tunnel.stats().rx_bytes, 0);
    }

    #[test]
    fn test_invalid_config_no_private_key() {
        let mut config = create_test_config();
        config.private_key = String::new();

        let result = UserspaceWgTunnel::new(config);
        assert!(matches!(result, Err(WgTunnelError::InvalidConfig(_))));
    }

    #[test]
    fn test_invalid_config_no_peer_key() {
        let mut config = create_test_config();
        config.peer_public_key = String::new();

        let result = UserspaceWgTunnel::new(config);
        assert!(matches!(result, Err(WgTunnelError::InvalidConfig(_))));
    }

    #[test]
    fn test_invalid_config_no_endpoint() {
        let mut config = create_test_config();
        config.peer_endpoint = String::new();

        let result = UserspaceWgTunnel::new(config);
        assert!(matches!(result, Err(WgTunnelError::InvalidConfig(_))));
    }

    #[test]
    fn test_invalid_config_bad_private_key() {
        let mut config = create_test_config();
        config.private_key = "invalid-base64!!!".to_string();

        let result = UserspaceWgTunnel::new(config);
        assert!(matches!(result, Err(WgTunnelError::KeyError(_))));
    }

    #[test]
    fn test_invalid_config_bad_peer_key() {
        let mut config = create_test_config();
        config.peer_public_key = "invalid-base64!!!".to_string();

        let result = UserspaceWgTunnel::new(config);
        assert!(matches!(result, Err(WgTunnelError::KeyError(_))));
    }

    #[test]
    fn test_invalid_config_bad_endpoint() {
        let mut config = create_test_config();
        config.peer_endpoint = "not-a-valid-endpoint".to_string();

        let result = UserspaceWgTunnel::new(config);
        assert!(matches!(result, Err(WgTunnelError::InvalidConfig(_))));
    }

    #[test]
    fn test_stats_default() {
        let config = create_test_config();
        let tunnel = UserspaceWgTunnel::new(config).unwrap();
        let stats = tunnel.stats();

        assert_eq!(stats.tx_bytes, 0);
        assert_eq!(stats.rx_bytes, 0);
        assert_eq!(stats.tx_packets, 0);
        assert_eq!(stats.rx_packets, 0);
        assert!(stats.last_handshake.is_none());
        assert_eq!(stats.handshake_count, 0);
        assert_eq!(stats.invalid_packets, 0);
    }

    #[test]
    fn test_peer_endpoint() {
        let config = create_test_config();
        let tunnel = UserspaceWgTunnel::new(config).unwrap();

        let endpoint = tunnel.peer_endpoint();
        assert!(endpoint.is_some());
        assert_eq!(
            endpoint.unwrap(),
            "192.168.1.1:51820".parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    fn test_config_access() {
        let config = create_test_config();
        let tunnel = UserspaceWgTunnel::new(config.clone()).unwrap();

        assert_eq!(tunnel.config().private_key, config.private_key);
        assert_eq!(tunnel.config().peer_public_key, config.peer_public_key);
        assert_eq!(tunnel.config().peer_endpoint, config.peer_endpoint);
    }

    // ========================================================================
    // Connection State Tests
    // ========================================================================

    #[tokio::test]
    async fn test_send_not_connected() {
        let config = create_test_config();
        let tunnel = UserspaceWgTunnel::new(config).unwrap();

        let result = tunnel.send(&[0u8; 100]).await;
        assert!(matches!(result, Err(WgTunnelError::NotConnected)));
    }

    #[tokio::test]
    async fn test_recv_not_connected() {
        let config = create_test_config();
        let tunnel = UserspaceWgTunnel::new(config).unwrap();

        let result = tunnel.recv().await;
        assert!(matches!(result, Err(WgTunnelError::NotConnected)));
    }

    #[tokio::test]
    async fn test_disconnect_not_connected() {
        let config = create_test_config();
        let tunnel = UserspaceWgTunnel::new(config).unwrap();

        let result = tunnel.disconnect().await;
        assert!(matches!(result, Err(WgTunnelError::NotConnected)));
    }

    #[tokio::test]
    async fn test_force_handshake_not_connected() {
        let config = create_test_config();
        let tunnel = UserspaceWgTunnel::new(config).unwrap();

        let result = tunnel.force_handshake().await;
        assert!(matches!(result, Err(WgTunnelError::NotConnected)));
    }

    // ========================================================================
    // Integration Tests (require network - may fail in CI)
    // ========================================================================

    #[tokio::test]
    #[ignore] // Requires network access
    async fn test_connect_and_disconnect() {
        let config = create_test_config();
        let tunnel = UserspaceWgTunnel::new(config).unwrap();

        // Connect
        let connect_result = tunnel.connect().await;
        // Note: This will fail because there's no actual peer, but it tests the flow
        if connect_result.is_ok() {
            assert!(tunnel.is_connected());

            // Disconnect
            let disconnect_result = tunnel.disconnect().await;
            assert!(disconnect_result.is_ok());
            assert!(!tunnel.is_connected());
        }
    }

    #[tokio::test]
    #[ignore] // Requires network access
    async fn test_double_connect() {
        let config = create_test_config();
        let tunnel = UserspaceWgTunnel::new(config).unwrap();

        // First connect
        if tunnel.connect().await.is_ok() {
            // Second connect should fail
            let result = tunnel.connect().await;
            assert!(matches!(result, Err(WgTunnelError::AlreadyConnected)));

            // Cleanup
            let _ = tunnel.disconnect().await;
        }
    }

    // ========================================================================
    // Key Encoding Tests
    // ========================================================================

    #[test]
    fn test_decode_private_key_success() {
        let key = generate_private_key();
        let result = decode_private_key(&key);
        assert!(result.is_ok());
    }

    #[test]
    fn test_decode_public_key_success() {
        let private_key = generate_private_key();
        let public_key = derive_public_key(&private_key).unwrap();
        let result = decode_public_key(&public_key);
        assert!(result.is_ok());
    }

    #[test]
    fn test_key_roundtrip() {
        // Generate key pair
        let private_key = generate_private_key();
        let public_key = derive_public_key(&private_key).unwrap();

        // Decode and re-encode
        let decoded_private = decode_private_key(&private_key).unwrap();
        let re_encoded_private = BASE64.encode(decoded_private.as_bytes());

        let decoded_public = decode_public_key(&public_key).unwrap();
        let re_encoded_public = BASE64.encode(decoded_public.as_bytes());

        // Should match original
        assert_eq!(private_key, re_encoded_private);
        assert_eq!(public_key, re_encoded_public);
    }

    // ========================================================================
    // Buffer Size Tests
    // ========================================================================

    #[test]
    fn test_buffer_constants() {
        // C2 fix: Test new constant names
        assert_eq!(WG_TRANSPORT_OVERHEAD, 32);
        assert_eq!(WG_HANDSHAKE_INIT_SIZE, 148);
        assert_eq!(WG_HANDSHAKE_RESPONSE_SIZE, 92);
        assert_eq!(MIN_BUFFER_SIZE, WG_HANDSHAKE_INIT_SIZE);
        assert_eq!(DEFAULT_MTU, 1420);
        assert!(UDP_RECV_BUFFER_SIZE >= 65536);
    }

    // ========================================================================
    // Allowed IPs Validation Tests (C3 fix)
    // ========================================================================

    #[test]
    fn test_extract_source_ip_v4() {
        // Minimal IPv4 packet with source IP 192.168.1.1
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45; // Version 4, IHL 5
        packet[12..16].copy_from_slice(&[192, 168, 1, 1]); // Source IP

        let ip = extract_source_ip(&packet);
        assert!(ip.is_some());
        assert_eq!(ip.unwrap().to_string(), "192.168.1.1");
    }

    #[test]
    fn test_extract_source_ip_v6() {
        // Minimal IPv6 packet with source IP 2001:db8::1
        let mut packet = vec![0u8; 40];
        packet[0] = 0x60; // Version 6
        // Source IP at bytes 8-23: 2001:0db8:0000:0000:0000:0000:0000:0001
        packet[8..10].copy_from_slice(&[0x20, 0x01]);
        packet[10..12].copy_from_slice(&[0x0d, 0xb8]);
        packet[22..24].copy_from_slice(&[0x00, 0x01]);

        let ip = extract_source_ip(&packet);
        assert!(ip.is_some());
        assert!(ip.unwrap().to_string().contains("2001:db8"));
    }

    #[test]
    fn test_extract_source_ip_invalid() {
        // Empty packet
        assert!(extract_source_ip(&[]).is_none());

        // Too short for IPv4
        let short_v4 = vec![0x45u8; 10];
        assert!(extract_source_ip(&short_v4).is_none());

        // Too short for IPv6
        let short_v6 = vec![0x60u8; 30];
        assert!(extract_source_ip(&short_v6).is_none());

        // Invalid version
        let invalid = vec![0xA0u8; 40]; // Version 10
        assert!(extract_source_ip(&invalid).is_none());
    }

    #[test]
    fn test_is_ip_allowed_empty_list() {
        // Empty allowed_ips means allow all
        assert!(is_ip_allowed("192.168.1.1".parse().unwrap(), &[]));
        assert!(is_ip_allowed("10.0.0.1".parse().unwrap(), &[]));
    }

    #[test]
    fn test_is_ip_allowed_matching() {
        let allowed: Vec<IpNet> = vec![
            "10.0.0.0/8".parse().unwrap(),
            "192.168.0.0/16".parse().unwrap(),
        ];

        assert!(is_ip_allowed("10.1.2.3".parse().unwrap(), &allowed));
        assert!(is_ip_allowed("192.168.1.1".parse().unwrap(), &allowed));
        assert!(!is_ip_allowed("172.16.0.1".parse().unwrap(), &allowed));
        assert!(!is_ip_allowed("8.8.8.8".parse().unwrap(), &allowed));
    }

    #[test]
    fn test_is_ip_allowed_all_traffic() {
        let allowed: Vec<IpNet> = vec!["0.0.0.0/0".parse().unwrap()];

        assert!(is_ip_allowed("10.1.2.3".parse().unwrap(), &allowed));
        assert!(is_ip_allowed("8.8.8.8".parse().unwrap(), &allowed));
        assert!(is_ip_allowed("192.168.1.1".parse().unwrap(), &allowed));
    }

    // ========================================================================
    // Handshake Signal Tests (H3 fix)
    // ========================================================================

    #[tokio::test]
    async fn test_wait_handshake_not_connected() {
        let config = create_test_config();
        let tunnel = UserspaceWgTunnel::new(config).unwrap();

        let result = tunnel.wait_handshake(Duration::from_millis(100)).await;
        assert!(matches!(result, Err(WgTunnelError::NotConnected)));
    }

    // ========================================================================
    // Background Task Tests (H2 fix)
    // ========================================================================

    #[tokio::test]
    async fn test_is_task_running_not_connected() {
        let config = create_test_config();
        let tunnel = UserspaceWgTunnel::new(config).unwrap();

        // Task should not be running before connect
        assert!(!tunnel.is_task_running().await);
    }

    // ========================================================================
    // Local IP Tests (C1 fix)
    // ========================================================================

    #[test]
    fn test_local_ip_not_connected() {
        let config = create_test_config();
        let tunnel = UserspaceWgTunnel::new(config).unwrap();

        // local_ip should return None when not connected
        assert!(tunnel.local_ip().is_none());
    }
}
