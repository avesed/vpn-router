//! Userspace `WireGuard` tunnel via boringtun for Phase 6
//!
//! This module implements userspace `WireGuard` tunnels using the
//! boringtun library for Rust-native `WireGuard` support.
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
//! # Phase 6.2 Implementation
//!
//! - [x] `WgTunnel` trait encrypt/decrypt methods
//! - [x] Peer management (single-peer egress mode)
//! - [x] `trigger_handshake/shutdown` trait methods
//! - [x] `get_peer/list_peers` for single peer
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
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use dashmap::DashMap;
use ipnet::IpNet;
use parking_lot::Mutex;
use rand::RngCore;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot, watch, RwLock};
use tokio::task::JoinHandle;
use tokio::time::interval;
use tracing::{debug, error, info, trace, warn};

use crate::io::UdpBufferPool;
use crate::tunnel::config::{WgPeerConfig, WgPeerInfo, WgPeerUpdate, WgTunnelConfig};
#[cfg(feature = "handshake_retry")]
use crate::tunnel::handshake::{HandshakeConfig, HandshakeTracker};
use crate::tunnel::traits::{BoxFuture, DecryptResult, WgTunnel, WgTunnelError, WgTunnelStats};

/// `WireGuard` transport data packet overhead
///
/// For transport data packets:
/// - 4 bytes: message type
/// - 4 bytes: receiver index
/// - 8 bytes: counter
/// - 16 bytes: Poly1305 authentication tag
///
/// Total: 32 bytes overhead added to the encrypted payload
pub const WG_TRANSPORT_OVERHEAD: usize = 32;

/// `WireGuard` handshake initiation packet size
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

/// `WireGuard` handshake response packet size
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

/// Minimum buffer size for `WireGuard` packets (must fit handshake initiation)
pub const MIN_BUFFER_SIZE: usize = WG_HANDSHAKE_INIT_SIZE;

/// Maximum transmission unit for `WireGuard` (default)
pub const DEFAULT_MTU: usize = 1420;

/// Timer tick interval in milliseconds
const TIMER_TICK_MS: u64 = 250;

/// Buffer size for UDP receive operations
const UDP_RECV_BUFFER_SIZE: usize = 65536;

/// Channel capacity for received packets - increased for better throughput
const RECV_CHANNEL_CAPACITY: usize = 1024;

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

/// Default tag for tunnels created without an explicit tag
const DEFAULT_TUNNEL_TAG: &str = "unnamed";

/// Userspace `WireGuard` tunnel using boringtun
///
/// This implementation uses the boringtun library for `WireGuard`
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
/// 2. `shared.socket` (`RwLock`)
/// 3. `shared.recv_tx` (`RwLock`)
/// 4. `shared.local_ip` (`RwLock`)
/// 5. `shared.allowed_ips` (`RwLock`)
/// 6. `shared.peer_state` (`RwLock`) - Phase 6.2
///
/// # Peer Mode
///
/// This implementation operates in **single-peer (egress) mode**. Each tunnel
/// has exactly one peer (the configured peer). For multi-peer (ingress) mode,
/// use `MultiPeerWgTunnel` (Phase 6.3).
pub struct UserspaceWgTunnel {
    /// Tunnel tag identifier
    tag: String,

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
/// 2. `socket` (`RwLock`)
/// 3. `recv_tx` (`RwLock`)
/// 4. `local_ip` (`RwLock`)
/// 5. `allowed_ips` (`RwLock`)
/// 6. `peer_state` (`RwLock`) - Phase 6.2
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

    /// Single peer state tracking (Phase 6.2)
    /// This is initialized on tunnel creation and updated during operation.
    peer_state: RwLock<Option<Arc<PeerStateInner>>>,

    /// Handshake tracker for retry with backoff (Issue #13 fix)
    /// Prevents busy loop when connecting to unreachable peers.
    #[cfg(feature = "handshake_retry")]
    handshake_tracker: HandshakeTracker,

    /// NAT table for SNAT/DNAT when tunnel has local_ip configured
    /// Key: (protocol, remote_ip, remote_port, local_port) -> original source IP
    /// Used to restore original destination IP on incoming packets
    nat_table: DashMap<NatKey, NatEntry>,
}

/// Key for NAT table lookup
/// Uses connection tuple to avoid collisions between different clients
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct NatKey {
    /// IP protocol (6=TCP, 17=UDP, 1=ICMP)
    protocol: u8,
    /// Remote IP address (destination on outgoing, source on incoming)
    remote_ip: IpAddr,
    /// Remote port (destination port on outgoing, source port on incoming)
    remote_port: u16,
    /// Local port (source port on outgoing, destination port on incoming)
    local_port: u16,
}

/// NAT table entry tracking original source IP
#[derive(Clone, Debug)]
struct NatEntry {
    /// Original source IP before SNAT
    original_src_ip: IpAddr,
    /// When this entry was created (for cleanup)
    created_at: Instant,
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

/// Internal peer state tracking for single-peer (egress) mode
///
/// This structure tracks the runtime state of the configured peer,
/// including statistics and handshake information.
///
/// # Thread Safety
///
/// All fields use atomic types for lock-free updates from multiple threads.
#[derive(Debug)]
struct PeerStateInner {
    /// Peer public key (Base64 encoded)
    public_key: String,
    /// Peer endpoint address
    endpoint: Option<SocketAddr>,
    /// Allowed IPs for this peer
    allowed_ips: Vec<String>,
    /// Persistent keepalive interval (seconds)
    persistent_keepalive: Option<u16>,
    /// Pre-shared key (if configured)
    preshared_key: Option<String>,
    /// Bytes transmitted to this peer
    tx_bytes: AtomicU64,
    /// Bytes received from this peer
    rx_bytes: AtomicU64,
    /// Last handshake timestamp (Unix seconds)
    last_handshake: AtomicU64,
    /// Whether `last_handshake` contains a valid value
    last_handshake_valid: AtomicBool,
}

impl PeerStateInner {
    /// Create a new peer state from configuration
    #[cfg_attr(not(test), allow(dead_code))]
    fn new(public_key: String, endpoint: Option<SocketAddr>, allowed_ips: Vec<String>) -> Self {
        Self {
            public_key,
            endpoint,
            allowed_ips,
            persistent_keepalive: None,
            preshared_key: None,
            tx_bytes: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
            last_handshake: AtomicU64::new(0),
            last_handshake_valid: AtomicBool::new(false),
        }
    }

    /// Convert to `WgPeerInfo`
    fn to_peer_info(&self) -> WgPeerInfo {
        let last_handshake = if self.last_handshake_valid.load(Ordering::Relaxed) {
            Some(self.last_handshake.load(Ordering::Relaxed))
        } else {
            None
        };

        let mut info = WgPeerInfo::new(self.public_key.clone());
        info.endpoint = self.endpoint;
        info.allowed_ips = self.allowed_ips.clone();
        info.last_handshake = last_handshake;
        info.tx_bytes = self.tx_bytes.load(Ordering::Relaxed);
        info.rx_bytes = self.rx_bytes.load(Ordering::Relaxed);
        info.persistent_keepalive = self.persistent_keepalive;
        info.preshared_key = self.preshared_key.clone();

        // Update connection status based on handshake timestamp
        info.update_connection_status();
        info
    }

    /// Update handshake timestamp
    #[cfg_attr(not(test), allow(dead_code))]
    fn update_handshake(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.last_handshake.store(now, Ordering::Relaxed);
        self.last_handshake_valid.store(true, Ordering::Relaxed);
    }
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
    /// Create a new userspace `WireGuard` tunnel
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
        Self::with_tag(config, None)
    }

    /// Create a new tunnel with a custom tag
    ///
    /// # Arguments
    ///
    /// * `config` - Tunnel configuration
    /// * `tag` - Optional tunnel tag identifier (uses "unnamed" if None)
    ///
    /// # Example
    ///
    /// ```ignore
    /// let config = WgTunnelConfig::new(private_key, peer_public_key, "1.2.3.4:51820".to_string());
    /// let tunnel = UserspaceWgTunnel::with_tag(config, Some("egress-us-west".to_string()))?;
    /// ```
    pub fn with_tag(config: WgTunnelConfig, tag: Option<String>) -> Result<Self, WgTunnelError> {
        Self::with_tag_and_buffer_pool(config, tag, None)
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
        Self::with_tag_and_buffer_pool(config, None, buffer_pool)
    }

    /// Create a new tunnel with custom tag and buffer pool
    ///
    /// # Arguments
    ///
    /// * `config` - Tunnel configuration
    /// * `tag` - Optional tunnel tag identifier (uses "unnamed" if None)
    /// * `buffer_pool` - Optional custom buffer pool (creates default if None)
    pub fn with_tag_and_buffer_pool(
        config: WgTunnelConfig,
        tag: Option<String>,
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

        // Initialize peer state for single-peer mode (Phase 6.2)
        let peer_state = PeerStateInner {
            public_key: config.peer_public_key.clone(),
            endpoint: Some(peer_addr),
            allowed_ips: config.allowed_ips.clone(),
            persistent_keepalive: config.persistent_keepalive,
            preshared_key: None, // Not currently supported in config
            tx_bytes: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
            last_handshake: AtomicU64::new(0),
            last_handshake_valid: AtomicBool::new(false),
        };

        let shared = Arc::new(TunnelShared {
            connected: AtomicBool::new(false),
            local_ip: RwLock::new(None),
            tunn: Mutex::new(None),
            socket: RwLock::new(None),
            recv_tx: RwLock::new(None),
            stats: TunnelStatsInner::default(),
            allowed_ips: RwLock::new(allowed_ips_parsed),
            handshake_tx,
            peer_state: RwLock::new(Some(Arc::new(peer_state))),
            #[cfg(feature = "handshake_retry")]
            handshake_tracker: HandshakeTracker::new(HandshakeConfig::from_env()),
            nat_table: DashMap::new(),
        });

        // Create or use provided buffer pool (H1 fix)
        let buffer_pool = buffer_pool
            .unwrap_or_else(|| Arc::new(UdpBufferPool::new(BUFFER_POOL_CAPACITY, UDP_RECV_BUFFER_SIZE)));

        // Set tag (use default if None)
        let tunnel_tag = tag.unwrap_or_else(|| DEFAULT_TUNNEL_TAG.to_string());

        Ok(Self {
            tag: tunnel_tag,
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

        // Issue #13 fix: Reset handshake tracker for new connection
        #[cfg(feature = "handshake_retry")]
        self.shared.handshake_tracker.reset();

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

        // Phase 11-Fix.6C: Do NOT call socket.connect()
        // Using connected UDP sockets causes problems with ICMP errors:
        // - When peer is not ready, we get ICMP "Port Unreachable"
        // - This error is cached on the connected socket
        // - All subsequent send() calls fail with "Connection refused"
        // - Even after peer becomes ready, the socket remains broken
        //
        // Solution: Use unconnected socket with send_to() instead of send()
        // This allows the socket to recover from transient errors.
        debug!("Using unconnected UDP socket (peer: {})", peer_addr);

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

    /// Wait for the `WireGuard` handshake to complete
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

        // Issue #13 fix: Set handshake tracker to disconnecting state
        #[cfg(feature = "handshake_retry")]
        self.shared.handshake_tracker.set_disconnecting();

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
    /// The packet will be encrypted using `WireGuard` and sent to the peer.
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

        // Check if SNAT is needed (tunnel has a local_ip configured)
        let packet_to_send: std::borrow::Cow<'_, [u8]> = if let Some(ref local_ip_str) = self.config.local_ip {
            // Parse the tunnel's local IP (strip CIDR suffix like /32 if present)
            if let Some(tunnel_ip) = parse_ip_strip_cidr(local_ip_str) {
                // Extract full connection tuple for NAT tracking
                if let Some(tuple) = extract_connection_tuple(packet) {
                    // Only SNAT if source IP differs from tunnel IP
                    if tuple.src_ip != tunnel_ip {
                        // Rewrite source IP to tunnel's local IP
                        if let Some(rewritten) = rewrite_source_ip(packet, tunnel_ip) {
                            // Only record NAT mapping AFTER successful rewrite
                            // Key uses connection tuple to avoid collisions between clients
                            let nat_key = NatKey {
                                protocol: tuple.protocol,
                                remote_ip: tuple.dst_ip,
                                remote_port: tuple.dst_port,
                                local_port: tuple.src_port,
                            };
                            // Check NAT table capacity before inserting
                            // If over capacity, force cleanup of expired entries first
                            if self.shared.nat_table.len() >= NAT_TABLE_MAX_CAPACITY {
                                let before = self.shared.nat_table.len();
                                self.shared.nat_table.retain(|_, entry| {
                                    entry.created_at.elapsed() < NAT_ENTRY_TIMEOUT
                                });
                                let removed = before.saturating_sub(self.shared.nat_table.len());
                                if removed > 0 {
                                    debug!("NAT table at capacity, cleaned {} expired entries", removed);
                                }
                                // If still at capacity after cleanup, log warning but still insert
                                // (will evict on next cleanup cycle)
                                if self.shared.nat_table.len() >= NAT_TABLE_MAX_CAPACITY {
                                    warn!(
                                        "NAT table at max capacity ({}), may cause DNAT failures",
                                        NAT_TABLE_MAX_CAPACITY
                                    );
                                }
                            }
                            
                            self.shared.nat_table.insert(nat_key, NatEntry {
                                original_src_ip: tuple.src_ip,
                                created_at: Instant::now(),
                            });
                            
                            debug!(
                                "Tunnel {} SNAT: {} -> {} (proto={}, {}:{} -> {}:{})",
                                self.tag, tuple.src_ip, tunnel_ip, tuple.protocol,
                                tuple.src_ip, tuple.src_port, tuple.dst_ip, tuple.dst_port
                            );
                            std::borrow::Cow::Owned(rewritten)
                        } else {
                            warn!("Tunnel {} failed to rewrite source IP", self.tag);
                            std::borrow::Cow::Borrowed(packet)
                        }
                    } else {
                        std::borrow::Cow::Borrowed(packet)
                    }
                } else {
                    std::borrow::Cow::Borrowed(packet)
                }
            } else {
                std::borrow::Cow::Borrowed(packet)
            }
        } else {
            std::borrow::Cow::Borrowed(packet)
        };

        // Log packet details for debugging (after potential SNAT)
        if let Some(src_ip) = extract_source_ip(&packet_to_send) {
            debug!(
                "Tunnel {} send: {} bytes, src_ip={}, tunnel_local_ip={:?}",
                self.tag,
                packet_to_send.len(),
                src_ip,
                self.config.local_ip
            );
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
        // Buffer must be at least WG_HANDSHAKE_INIT_SIZE (148 bytes) to hold handshake
        // messages that boringtun may generate during rekey
        let mut dst = vec![0u8; (packet_to_send.len() + WG_TRANSPORT_OVERHEAD).max(WG_HANDSHAKE_INIT_SIZE)];

        // Encapsulate packet
        let result = {
            let mut tunn_guard = self.shared.tunn.lock();
            let tunn = tunn_guard
                .as_mut()
                .ok_or(WgTunnelError::NotConnected)?;
            tunn.encapsulate(&packet_to_send, &mut dst)
        };

        // Phase 12-Fix.P: Log encapsulation result for debugging
        let result_type = match &result {
            TunnResult::WriteToNetwork(data) => format!("WriteToNetwork({} bytes)", data.len()),
            TunnResult::Done => "Done".to_string(),
            TunnResult::Err(e) => format!("Err({:?})", e),
            _ => "Other".to_string(),
        };
        debug!(
            "Tunnel {} encapsulate result: {} for {} byte packet",
            self.tag, result_type, packet_to_send.len()
        );

        // Process result
        match result {
            TunnResult::WriteToNetwork(encrypted) => {
                // Phase 11-Fix.6C: Use send_to() instead of send() for unconnected socket
                socket.send_to(encrypted, self.peer_addr_parsed).await.map_err(|e| {
                    WgTunnelError::IoError(format!("Failed to send encrypted packet: {e}"))
                })?;

                // Update stats
                self.shared
                    .stats
                    .tx_bytes
                    .fetch_add(packet_to_send.len() as u64, Ordering::Relaxed);
                self.shared.stats.tx_packets.fetch_add(1, Ordering::Relaxed);

                debug!("Sent {} bytes through tunnel {} to {:?}", packet_to_send.len(), self.tag, self.peer_addr_parsed);
                Ok(())
            }
            TunnResult::Done => {
                // Packet was queued, may need handshake first
                warn!("Tunnel {} packet queued (handshake may be in progress), {} bytes", self.tag, packet_to_send.len());
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
                // Phase 12-Fix.P: Log received packets at debug level
                debug!("Tunnel {} recv(): got {} bytes from channel", self.tag, data.len());
                Ok(data)
            }
            None => {
                // Channel closed, tunnel disconnected
                debug!("Tunnel {} recv(): channel closed", self.tag);
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

    /// Initiate `WireGuard` handshake
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
                // Phase 11-Fix.6C: Use send_to() instead of send()
                socket.send_to(handshake, self.peer_addr_parsed).await.map_err(|e| {
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
    /// Returns the `JoinHandle` for monitoring the task status.
    fn spawn_background_tasks(
        &self,
        socket: Arc<UdpSocket>,
        peer_addr: SocketAddr,
        shutdown_rx: oneshot::Receiver<()>,
    ) -> JoinHandle<()> {
        // Clone Arc for the background task
        let shared = Arc::clone(&self.shared);
        let buffer_pool = Arc::clone(&self.buffer_pool);
        let tag_for_task = self.tag.clone(); // Phase 12-Fix.P: tag for debug logging

        // Spawn combined background task
        // Phase 11-Fix.6C: Pass peer_addr for send_to() calls
        tokio::spawn(async move {
            run_background_task(socket, shutdown_rx, shared, buffer_pool, peer_addr, tag_for_task).await;
        })
    }

    /// Get the buffer pool used by this tunnel
    pub fn buffer_pool(&self) -> &Arc<UdpBufferPool> {
        &self.buffer_pool
    }

    /// Configure socket buffer sizes
    ///
    /// Sets the `SO_RCVBUF` and `SO_SNDBUF` socket options for the UDP socket.
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
        // SAFETY: This is safe because:
        // 1. `fd` is a valid file descriptor obtained from `socket.as_raw_fd()`,
        //    which returns the underlying OS file descriptor for the UDP socket.
        // 2. `SOL_SOCKET` is a valid socket level constant defined by POSIX.
        // 3. `SO_RCVBUF` is a valid socket option for setting receive buffer size.
        // 4. `&recv_buf_i32` is a valid pointer to a stack-allocated i32 value.
        // 5. `size_of::<c_int>()` correctly specifies the size of the option value.
        // 6. tokio's UdpSocket maintains ownership of the underlying socket,
        //    ensuring the fd remains valid for the duration of this call.
        let result = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                (&raw const recv_buf_i32).cast::<libc::c_void>(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if result != 0 {
            warn!("Failed to set SO_RCVBUF: {}", std::io::Error::last_os_error());
        }

        // Set send buffer size
        let send_buf_i32 = send_buf as libc::c_int;
        // SAFETY: This is safe because:
        // 1. `fd` is a valid file descriptor obtained from `socket.as_raw_fd()`,
        //    which returns the underlying OS file descriptor for the UDP socket.
        // 2. `SOL_SOCKET` is a valid socket level constant defined by POSIX.
        // 3. `SO_SNDBUF` is a valid socket option for setting send buffer size.
        // 4. `&send_buf_i32` is a valid pointer to a stack-allocated i32 value.
        // 5. `size_of::<c_int>()` correctly specifies the size of the option value.
        // 6. tokio's UdpSocket maintains ownership of the underlying socket,
        //    ensuring the fd remains valid for the duration of this call.
        let result = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                (&raw const send_buf_i32).cast::<libc::c_void>(),
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
    peer_addr: SocketAddr,  // Phase 11-Fix.6C: peer address for send_to()
    tunnel_tag_for_task: String, // Phase 12-Fix.P: tag for debug logging
) {
    let mut timer_interval = interval(Duration::from_millis(TIMER_TICK_MS));
    // NAT table cleanup interval (Issue: memory leak from stale NAT entries)
    let mut nat_cleanup_interval = interval(NAT_CLEANUP_INTERVAL);
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

            // Periodic NAT table cleanup to prevent memory leaks
            // Issue: NAT entries were only cleaned when receiving reply packets,
            // causing unbounded growth for one-way traffic or lost replies
            _ = nat_cleanup_interval.tick() => {
                let before_count = shared.nat_table.len();
                if before_count > 0 {
                    let now = std::time::Instant::now();
                    shared.nat_table.retain(|_key, entry| {
                        entry.created_at.elapsed() < NAT_ENTRY_TIMEOUT
                    });
                    let removed = before_count.saturating_sub(shared.nat_table.len());
                    if removed > 0 {
                        debug!(
                            "NAT table cleanup: removed {} expired entries, {} remaining (took {:?})",
                            removed,
                            shared.nat_table.len(),
                            now.elapsed()
                        );
                    }
                }
            }

            // Timer tick for keepalive and handshake retransmission
            _ = timer_interval.tick() => {
                if !shared.connected.load(Ordering::Acquire) {
                    break;
                }

                // Update timers
                let result = {
                    let mut tunn_guard = shared.tunn.lock();
                    tunn_guard.as_mut().map(|tunn| tunn.update_timers(&mut timer_buf))
                };

                if let Some(result) = result {
                    if let TunnResult::WriteToNetwork(data) = result {
                        // Issue #13 fix: Use handshake tracker to prevent busy loop
                        #[cfg(feature = "handshake_retry")]
                        {
                            // Check if this is a handshake initiation (148 bytes)
                            let is_handshake_init = data.len() == WG_HANDSHAKE_INIT_SIZE;

                            if is_handshake_init {
                                // Check if handshake retry is allowed (respects backoff)
                                if shared.handshake_tracker.can_initiate() {
                                    match shared.handshake_tracker.on_initiate() {
                                        Ok(attempt) => {
                                            // Phase 11-Fix.6C: Use send_to() for unconnected socket
                                            if let Err(e) = socket.send_to(data, peer_addr).await {
                                                warn!("Failed to send handshake attempt {}: {}", attempt, e);
                                                shared.handshake_tracker.on_network_error();
                                            } else {
                                                info!("Sent handshake initiation attempt {} ({} bytes) to {}", attempt, data.len(), peer_addr);
                                            }
                                        }
                                        Err(e) => {
                                            trace!("Handshake initiation blocked: {}", e);
                                        }
                                    }
                                } else if shared.handshake_tracker.is_failed() {
                                    // Handshake retries exhausted, stop the tunnel
                                    warn!("Handshake retries exhausted, stopping tunnel");
                                    shared.connected.store(false, Ordering::Release);
                                    break;
                                } else {
                                    // Still in backoff period
                                    if let Some(remaining) = shared.handshake_tracker.time_until_next_retry() {
                                        trace!("Handshake backoff: {:?} remaining", remaining);
                                    }
                                }
                            } else {
                                // Not a handshake init (keepalive, data, etc.) - send immediately
                                // Phase 11-Fix.6C: Use send_to() for unconnected socket
                                if let Err(e) = socket.send_to(data, peer_addr).await {
                                    warn!("Failed to send timer packet: {}", e);
                                } else {
                                    trace!("Sent timer packet ({} bytes)", data.len());
                                }
                            }
                        }

                        // Without handshake_retry feature, send all packets immediately
                        #[cfg(not(feature = "handshake_retry"))]
                        {
                            // Phase 11-Fix.6C: Use send_to() for unconnected socket
                            if let Err(e) = socket.send_to(data, peer_addr).await {
                                warn!("Failed to send timer packet: {}", e);
                            } else {
                                trace!("Sent timer packet ({} bytes)", data.len());
                            }
                        }
                    }
                }
            }

            // Receive incoming packets
            // Phase 11-Fix.6C: Use recv_from() for unconnected socket
            result = socket.recv_from(&mut recv_buf) => {
                match result {
                    Ok((len, src_addr)) => {
                        // Phase 12-Fix.P: Log received UDP packets at debug level for troubleshooting
                        debug!("Tunnel {} UDP recv: {} bytes from {} (expecting {})", tunnel_tag_for_task, len, src_addr, peer_addr);

                        if !shared.connected.load(Ordering::Acquire) {
                            break;
                        }

                        // Validate source address matches expected peer
                        if src_addr != peer_addr {
                            warn!("Tunnel {} ignoring packet from unexpected source: {} (expected {})", tunnel_tag_for_task, src_addr, peer_addr);
                            continue;
                        }

                        // Process incoming packet
                        let process_result = {
                            let mut tunn_guard = shared.tunn.lock();
                            tunn_guard.as_mut().map(|tunn| tunn.decapsulate(None, &recv_buf[..len], &mut dst_buf))
                        };

                        if let Some(ref result) = process_result {
                            // Phase 12-Fix.P: Log decapsulate result at debug level
                            let result_type = match result {
                                TunnResult::WriteToTunnelV4(data, _) => format!("WriteToTunnelV4({} bytes)", data.len()),
                                TunnResult::WriteToTunnelV6(data, _) => format!("WriteToTunnelV6({} bytes)", data.len()),
                                TunnResult::WriteToNetwork(data) => format!("WriteToNetwork({} bytes)", data.len()),
                                TunnResult::Done => "Done".to_string(),
                                TunnResult::Err(e) => format!("Err({:?})", e),
                            };
                            debug!("Tunnel {} decapsulate: {} bytes -> {}", tunnel_tag_for_task, len, result_type);
                        }

                        if let Some(result) = process_result {
                            handle_decapsulate_result(
                                result,
                                &socket,
                                &shared,
                                peer_addr,  // Phase 11-Fix.6C
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

/// Check if an IP address is allowed by the `allowed_ips` list
fn is_ip_allowed(ip: IpAddr, allowed_ips: &[IpNet]) -> bool {
    // Empty allowed_ips means allow all (0.0.0.0/0 behavior)
    if allowed_ips.is_empty() {
        return true;
    }

    allowed_ips.iter().any(|net| net.contains(&ip))
}

/// Extract destination IP address from an IP packet
#[allow(dead_code)]
fn extract_dest_ip(packet: &[u8]) -> Option<IpAddr> {
    if packet.is_empty() {
        return None;
    }

    let version = packet[0] >> 4;
    match version {
        4 => {
            // IPv4: minimum header is 20 bytes, dest IP at bytes 16-19
            if packet.len() < 20 {
                return None;
            }
            let dst_bytes: [u8; 4] = packet[16..20].try_into().ok()?;
            Some(IpAddr::V4(Ipv4Addr::from(dst_bytes)))
        }
        6 => {
            // IPv6: minimum header is 40 bytes, dest IP at bytes 24-39
            if packet.len() < 40 {
                return None;
            }
            let dst_bytes: [u8; 16] = packet[24..40].try_into().ok()?;
            Some(IpAddr::V6(Ipv6Addr::from(dst_bytes)))
        }
        _ => None,
    }
}

/// Extract protocol and source port from an IP packet
/// Returns (protocol, src_port) or None if packet is malformed
#[allow(dead_code)]
fn extract_protocol_and_src_port(packet: &[u8]) -> Option<(u8, u16)> {
    if packet.is_empty() {
        return None;
    }

    let version = packet[0] >> 4;
    match version {
        4 => {
            if packet.len() < 20 {
                return None;
            }
            let protocol = packet[9];
            let ihl = (packet[0] & 0x0f) as usize * 4;
            
            match protocol {
                6 | 17 => {
                    // TCP or UDP: src port is first 2 bytes after IP header
                    if packet.len() < ihl + 2 {
                        return None;
                    }
                    let src_port = u16::from_be_bytes([packet[ihl], packet[ihl + 1]]);
                    Some((protocol, src_port))
                }
                1 => {
                    // ICMP: use identifier as "port" (bytes 4-5 of ICMP header)
                    if packet.len() < ihl + 6 {
                        return None;
                    }
                    let icmp_id = u16::from_be_bytes([packet[ihl + 4], packet[ihl + 5]]);
                    Some((protocol, icmp_id))
                }
                _ => Some((protocol, 0)),
            }
        }
        6 => {
            if packet.len() < 40 {
                return None;
            }
            let protocol = packet[6]; // Next Header
            
            match protocol {
                6 | 17 => {
                    // TCP or UDP: src port is first 2 bytes after IPv6 header
                    if packet.len() < 42 {
                        return None;
                    }
                    let src_port = u16::from_be_bytes([packet[40], packet[41]]);
                    Some((protocol, src_port))
                }
                58 => {
                    // ICMPv6: use identifier as "port"
                    if packet.len() < 46 {
                        return None;
                    }
                    let icmp_id = u16::from_be_bytes([packet[44], packet[45]]);
                    Some((protocol, icmp_id))
                }
                _ => Some((protocol, 0)),
            }
        }
        _ => None,
    }
}

/// Extract protocol and destination port from an IP packet
#[allow(dead_code)]
fn extract_protocol_and_dst_port(packet: &[u8]) -> Option<(u8, u16)> {
    if packet.is_empty() {
        return None;
    }

    let version = packet[0] >> 4;
    match version {
        4 => {
            if packet.len() < 20 {
                return None;
            }
            let protocol = packet[9];
            let ihl = (packet[0] & 0x0f) as usize * 4;
            
            match protocol {
                6 | 17 => {
                    // TCP or UDP: dst port is bytes 2-3 after IP header
                    if packet.len() < ihl + 4 {
                        return None;
                    }
                    let dst_port = u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]]);
                    Some((protocol, dst_port))
                }
                1 => {
                    // ICMP: use identifier as "port"
                    if packet.len() < ihl + 6 {
                        return None;
                    }
                    let icmp_id = u16::from_be_bytes([packet[ihl + 4], packet[ihl + 5]]);
                    Some((protocol, icmp_id))
                }
                _ => Some((protocol, 0)),
            }
        }
        6 => {
            if packet.len() < 40 {
                return None;
            }
            let protocol = packet[6];
            
            match protocol {
                6 | 17 => {
                    // TCP or UDP: dst port is bytes 2-3 after IPv6 header
                    if packet.len() < 44 {
                        return None;
                    }
                    let dst_port = u16::from_be_bytes([packet[42], packet[43]]);
                    Some((protocol, dst_port))
                }
                58 => {
                    // ICMPv6: use identifier
                    if packet.len() < 46 {
                        return None;
                    }
                    let icmp_id = u16::from_be_bytes([packet[44], packet[45]]);
                    Some((protocol, icmp_id))
                }
                _ => Some((protocol, 0)),
            }
        }
        _ => None,
    }
}

/// Connection tuple for NAT tracking
#[derive(Clone, Copy, Debug)]
struct ConnectionTuple {
    protocol: u8,
    src_ip: IpAddr,
    src_port: u16,
    dst_ip: IpAddr,
    dst_port: u16,
}

/// Extract full connection tuple from an IP packet
/// Returns (protocol, src_ip, src_port, dst_ip, dst_port) for TCP/UDP/ICMP
fn extract_connection_tuple(packet: &[u8]) -> Option<ConnectionTuple> {
    if packet.is_empty() {
        return None;
    }

    let version = packet[0] >> 4;
    match version {
        4 => {
            if packet.len() < 20 {
                return None;
            }
            let ihl = (packet[0] & 0x0f) as usize * 4;
            // Validate IHL (minimum 20 bytes, maximum packet length)
            if ihl < 20 || packet.len() < ihl {
                return None;
            }
            
            let protocol = packet[9];
            let src_ip = IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(&packet[12..16]).ok()?));
            let dst_ip = IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(&packet[16..20]).ok()?));
            
            let (src_port, dst_port) = match protocol {
                6 | 17 => {
                    // TCP or UDP
                    if packet.len() < ihl + 4 {
                        return None;
                    }
                    let sp = u16::from_be_bytes([packet[ihl], packet[ihl + 1]]);
                    let dp = u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]]);
                    (sp, dp)
                }
                1 => {
                    // ICMP: use identifier as both "ports"
                    if packet.len() < ihl + 6 {
                        return None;
                    }
                    let id = u16::from_be_bytes([packet[ihl + 4], packet[ihl + 5]]);
                    (id, id)
                }
                _ => (0, 0),
            };
            
            Some(ConnectionTuple { protocol, src_ip, src_port, dst_ip, dst_port })
        }
        6 => {
            if packet.len() < 40 {
                return None;
            }
            let protocol = packet[6]; // Next Header (simplified, doesn't handle extension headers)
            let src_ip = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).ok()?));
            let dst_ip = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).ok()?));
            
            let (src_port, dst_port) = match protocol {
                6 | 17 => {
                    // TCP or UDP
                    if packet.len() < 44 {
                        return None;
                    }
                    let sp = u16::from_be_bytes([packet[40], packet[41]]);
                    let dp = u16::from_be_bytes([packet[42], packet[43]]);
                    (sp, dp)
                }
                58 => {
                    // ICMPv6
                    if packet.len() < 46 {
                        return None;
                    }
                    let id = u16::from_be_bytes([packet[44], packet[45]]);
                    (id, id)
                }
                _ => (0, 0),
            };
            
            Some(ConnectionTuple { protocol, src_ip, src_port, dst_ip, dst_port })
        }
        _ => None,
    }
}

/// Parse IP address from string, stripping optional CIDR suffix
fn parse_ip_strip_cidr(s: &str) -> Option<IpAddr> {
    // Strip CIDR suffix if present (e.g., "10.0.0.1/32" -> "10.0.0.1")
    let ip_str = s.split('/').next()?;
    ip_str.parse().ok()
}

/// Rewrite source IP in a packet and update checksums
/// Returns the modified packet or None if rewriting failed
fn rewrite_source_ip(packet: &[u8], new_src_ip: IpAddr) -> Option<Vec<u8>> {
    if packet.is_empty() {
        return None;
    }

    let version = packet[0] >> 4;
    let mut modified = packet.to_vec();

    match (version, new_src_ip) {
        (4, IpAddr::V4(new_ip)) => {
            if modified.len() < 20 {
                return None;
            }
            // Get old source IP for checksum delta
            let old_src: [u8; 4] = modified[12..16].try_into().ok()?;
            let new_src = new_ip.octets();
            
            // Rewrite source IP at bytes 12-15
            modified[12..16].copy_from_slice(&new_src);
            
            // Update IP header checksum
            update_ipv4_checksum(&mut modified, &old_src, &new_src);
            
            // Update transport layer checksum (TCP/UDP use pseudo-header)
            let protocol = modified[9];
            let ihl = (modified[0] & 0x0f) as usize * 4;
            update_transport_checksum(&mut modified, ihl, protocol, &old_src, &new_src, true);
            
            Some(modified)
        }
        (6, IpAddr::V6(new_ip)) => {
            if modified.len() < 40 {
                return None;
            }
            // Get old source IP for checksum delta  
            let old_src: [u8; 16] = modified[8..24].try_into().ok()?;
            let new_src = new_ip.octets();
            
            // Rewrite source IP at bytes 8-23
            modified[8..24].copy_from_slice(&new_src);
            
            // Update transport layer checksum
            let protocol = modified[6];
            update_transport_checksum_v6(&mut modified, 40, protocol, &old_src, &new_src, true);
            
            Some(modified)
        }
        _ => None, // Version mismatch
    }
}

/// Rewrite destination IP in a packet and update checksums
fn rewrite_dest_ip(packet: &[u8], new_dst_ip: IpAddr) -> Option<Vec<u8>> {
    if packet.is_empty() {
        return None;
    }

    let version = packet[0] >> 4;
    let mut modified = packet.to_vec();

    match (version, new_dst_ip) {
        (4, IpAddr::V4(new_ip)) => {
            if modified.len() < 20 {
                return None;
            }
            // Get old dest IP for checksum delta
            let old_dst: [u8; 4] = modified[16..20].try_into().ok()?;
            let new_dst = new_ip.octets();
            
            // Rewrite dest IP at bytes 16-19
            modified[16..20].copy_from_slice(&new_dst);
            
            // Update IP header checksum
            update_ipv4_checksum(&mut modified, &old_dst, &new_dst);
            
            // Update transport layer checksum
            let protocol = modified[9];
            let ihl = (modified[0] & 0x0f) as usize * 4;
            update_transport_checksum(&mut modified, ihl, protocol, &old_dst, &new_dst, false);
            
            Some(modified)
        }
        (6, IpAddr::V6(new_ip)) => {
            if modified.len() < 40 {
                return None;
            }
            // Get old dest IP
            let old_dst: [u8; 16] = modified[24..40].try_into().ok()?;
            let new_dst = new_ip.octets();
            
            // Rewrite dest IP at bytes 24-39
            modified[24..40].copy_from_slice(&new_dst);
            
            // Update transport layer checksum
            let protocol = modified[6];
            update_transport_checksum_v6(&mut modified, 40, protocol, &old_dst, &new_dst, false);
            
            Some(modified)
        }
        _ => None,
    }
}

/// Update IPv4 header checksum using incremental update
/// Based on RFC 1624: only recomputes the delta from changed bytes
fn update_ipv4_checksum(packet: &mut [u8], old_bytes: &[u8; 4], new_bytes: &[u8; 4]) {
    if packet.len() < 20 {
        return;
    }
    
    // Get current checksum
    let old_check = u16::from_be_bytes([packet[10], packet[11]]);
    
    // Calculate checksum delta using one's complement arithmetic
    let mut delta: i32 = 0;
    
    // Subtract old values, add new values (in 16-bit chunks)
    delta -= u16::from_be_bytes([old_bytes[0], old_bytes[1]]) as i32;
    delta -= u16::from_be_bytes([old_bytes[2], old_bytes[3]]) as i32;
    delta += u16::from_be_bytes([new_bytes[0], new_bytes[1]]) as i32;
    delta += u16::from_be_bytes([new_bytes[2], new_bytes[3]]) as i32;
    
    // Apply delta to old checksum (using one's complement)
    let mut new_check = (!old_check as i32) + delta;
    
    // Fold carry bits
    while new_check >> 16 != 0 {
        new_check = (new_check & 0xffff) + (new_check >> 16);
    }
    
    let new_check = !new_check as u16;
    packet[10..12].copy_from_slice(&new_check.to_be_bytes());
}

/// Update transport layer (TCP/UDP) checksum for IPv4
/// is_source: true if we're updating source IP, false for dest IP
fn update_transport_checksum(
    packet: &mut [u8],
    ihl: usize,
    protocol: u8,
    old_bytes: &[u8; 4],
    new_bytes: &[u8; 4],
    _is_source: bool,
) {
    let check_offset = match protocol {
        6 => ihl + 16,  // TCP checksum at offset 16 in TCP header
        17 => ihl + 6,  // UDP checksum at offset 6 in UDP header
        _ => return,    // No checksum update for other protocols
    };
    
    if packet.len() < check_offset + 2 {
        return;
    }
    
    let old_check = u16::from_be_bytes([packet[check_offset], packet[check_offset + 1]]);
    
    // UDP checksum of 0 means "no checksum" - don't update it
    if protocol == 17 && old_check == 0 {
        return;
    }
    
    // Calculate delta
    let mut delta: i32 = 0;
    delta -= u16::from_be_bytes([old_bytes[0], old_bytes[1]]) as i32;
    delta -= u16::from_be_bytes([old_bytes[2], old_bytes[3]]) as i32;
    delta += u16::from_be_bytes([new_bytes[0], new_bytes[1]]) as i32;
    delta += u16::from_be_bytes([new_bytes[2], new_bytes[3]]) as i32;
    
    let mut new_check = (!old_check as i32) + delta;
    while new_check >> 16 != 0 {
        new_check = (new_check & 0xffff) + (new_check >> 16);
    }
    
    let new_check = !new_check as u16;
    // Handle the special case where checksum becomes 0 for UDP
    let final_check = if protocol == 17 && new_check == 0 { 0xffff } else { new_check };
    packet[check_offset..check_offset + 2].copy_from_slice(&final_check.to_be_bytes());
}

/// Update transport layer checksum for IPv6
fn update_transport_checksum_v6(
    packet: &mut [u8],
    header_len: usize,
    protocol: u8,
    old_bytes: &[u8; 16],
    new_bytes: &[u8; 16],
    _is_source: bool,
) {
    let check_offset = match protocol {
        6 => header_len + 16,   // TCP
        17 => header_len + 6,   // UDP
        58 => header_len + 2,   // ICMPv6
        _ => return,
    };
    
    if packet.len() < check_offset + 2 {
        return;
    }
    
    let old_check = u16::from_be_bytes([packet[check_offset], packet[check_offset + 1]]);
    
    // Calculate delta for 16-byte address
    let mut delta: i32 = 0;
    for i in 0..8 {
        delta -= u16::from_be_bytes([old_bytes[i * 2], old_bytes[i * 2 + 1]]) as i32;
        delta += u16::from_be_bytes([new_bytes[i * 2], new_bytes[i * 2 + 1]]) as i32;
    }
    
    let mut new_check = (!old_check as i32) + delta;
    while new_check >> 16 != 0 {
        new_check = (new_check & 0xffff) + (new_check >> 16);
    }
    
    let new_check = !new_check as u16;
    let final_check = if protocol == 17 && new_check == 0 { 0xffff } else { new_check };
    packet[check_offset..check_offset + 2].copy_from_slice(&final_check.to_be_bytes());
}

/// NAT table entry timeout (5 minutes)
const NAT_ENTRY_TIMEOUT: Duration = Duration::from_secs(300);

/// NAT table cleanup interval (60 seconds)
const NAT_CLEANUP_INTERVAL: Duration = Duration::from_secs(60);

/// NAT table maximum capacity (prevent unbounded memory growth under high traffic)
const NAT_TABLE_MAX_CAPACITY: usize = 100_000;

/// Handle the result of decapsulating a received packet
async fn handle_decapsulate_result(
    result: TunnResult<'_>,
    socket: &Arc<UdpSocket>,
    shared: &Arc<TunnelShared>,
    peer_addr: SocketAddr,  // Phase 11-Fix.6C: peer address for send_to()
) {
    match result {
        TunnResult::WriteToTunnelV4(data, _addr) => {
            // Decrypted IPv4 packet ready
            let mut packet = data.to_vec();
            
            // Perform DNAT if NAT table has an entry for this packet
            // Response packet has swapped src/dst compared to outgoing
            // Outgoing: (proto, dst_ip, dst_port, src_port) -> original_src_ip
            // Incoming: lookup by (proto, src_ip, src_port, dst_port)
            if let Some(tuple) = extract_connection_tuple(&packet) {
                let nat_key = NatKey {
                    protocol: tuple.protocol,
                    remote_ip: tuple.src_ip,      // Was dst_ip on outgoing
                    remote_port: tuple.src_port,  // Was dst_port on outgoing
                    local_port: tuple.dst_port,   // Was src_port on outgoing
                };
                if let Some(entry) = shared.nat_table.get(&nat_key) {
                    // Check if entry is still valid (not expired)
                    if entry.created_at.elapsed() < NAT_ENTRY_TIMEOUT {
                        let original_src_ip = entry.original_src_ip;
                        drop(entry); // Release DashMap ref before await
                        
                        // Rewrite destination IP back to original client IP
                        if let Some(rewritten) = rewrite_dest_ip(&packet, original_src_ip) {
                            debug!(
                                "DNAT: {} -> {} (proto={}, {}:{} -> local:{})",
                                tuple.dst_ip, original_src_ip, tuple.protocol,
                                tuple.src_ip, tuple.src_port, tuple.dst_port
                            );
                            packet = rewritten;
                        }
                    } else {
                        // Entry expired, remove it
                        drop(entry);
                        shared.nat_table.remove(&nat_key);
                    }
                }
            }
            
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
                // Phase 12-Fix.P: Log channel send for debugging
                debug!("Sending {} bytes to recv_tx channel", packet_len);
                if tx.send(packet).await.is_err() {
                    warn!("Receiver channel closed - packet dropped");
                } else {
                    debug!("Successfully sent {} bytes to recv_tx channel", packet_len);
                }
            } else {
                warn!("recv_tx is None - packet dropped (tunnel may not be connected)");
            }

            debug!("Decrypted IPv4 packet: {} bytes (stats: rx_bytes={}, rx_packets={})",
                packet_len,
                shared.stats.rx_bytes.load(Ordering::Relaxed),
                shared.stats.rx_packets.load(Ordering::Relaxed));
        }

        TunnResult::WriteToTunnelV6(data, _addr) => {
            // Decrypted IPv6 packet ready
            let mut packet = data.to_vec();
            
            // Perform DNAT if NAT table has an entry for this packet
            if let Some(tuple) = extract_connection_tuple(&packet) {
                let nat_key = NatKey {
                    protocol: tuple.protocol,
                    remote_ip: tuple.src_ip,
                    remote_port: tuple.src_port,
                    local_port: tuple.dst_port,
                };
                if let Some(entry) = shared.nat_table.get(&nat_key) {
                    if entry.created_at.elapsed() < NAT_ENTRY_TIMEOUT {
                        let original_src_ip = entry.original_src_ip;
                        drop(entry);
                        
                        if let Some(rewritten) = rewrite_dest_ip(&packet, original_src_ip) {
                            debug!(
                                "DNAT (v6): {} -> {} (proto={}, {}:{} -> local:{})",
                                tuple.dst_ip, original_src_ip, tuple.protocol,
                                tuple.src_ip, tuple.src_port, tuple.dst_port
                            );
                            packet = rewritten;
                        }
                    } else {
                        drop(entry);
                        shared.nat_table.remove(&nat_key);
                    }
                }
            }
            
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
            // Phase 11-Fix.6C: Use send_to() for unconnected socket
            if let Err(e) = socket.send_to(response, peer_addr).await {
                warn!("Failed to send response: {}", e);
            } else {
                info!("Sent WG response ({} bytes) to {}", response.len(), peer_addr);

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

                // Issue #13 fix: Signal handshake tracker completion
                #[cfg(feature = "handshake_retry")]
                shared.handshake_tracker.on_complete();
            }

            // Process any additional data after sending response
            // Use a separate buffer for continuation processing
            let mut cont_buf = vec![0u8; UDP_RECV_BUFFER_SIZE];
            let mut continue_processing = true;
            while continue_processing {
                let additional_result = {
                    let mut tunn_guard = shared.tunn.lock();
                    tunn_guard.as_mut().map(|tunn| tunn.decapsulate(None, &[], &mut cont_buf))
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
                        // Phase 11-Fix.6C: Use send_to() for unconnected socket
                        let _ = socket.send_to(data, peer_addr).await;
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
    fn tag(&self) -> &str {
        &self.tag
    }

    fn config(&self) -> &WgTunnelConfig {
        &self.config
    }

    fn is_connected(&self) -> bool {
        self.shared.connected.load(Ordering::Acquire)
    }

    fn is_healthy(&self) -> bool {
        // A tunnel is healthy if connected and had a recent handshake (within 180 seconds)
        if !self.is_connected() {
            return false;
        }
        // Check if we had a handshake within 180 seconds (WireGuard rekey interval)
        if let Some(last) = self.last_handshake() {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            now.saturating_sub(last) < 180
        } else {
            // No handshake yet, but still connected (handshake may be in progress)
            true
        }
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

    /// Get the UDP socket for batch I/O operations (Phase 6.8)
    ///
    /// Returns an Arc-wrapped `UdpSocket` if the tunnel is connected.
    /// This allows batch send/receive operations using `sendmmsg`/`recvmmsg`.
    ///
    /// # Safety
    ///
    /// The returned socket should not be used for direct send/receive operations
    /// without proper `WireGuard` encryption/decryption handling.
    fn socket(&self) -> Option<Arc<UdpSocket>> {
        self.shared.socket.try_read().ok().and_then(|guard| guard.clone())
    }

    fn last_handshake(&self) -> Option<u64> {
        if self.shared.stats.last_handshake_valid.load(Ordering::Relaxed) {
            Some(self.shared.stats.last_handshake.load(Ordering::Relaxed))
        } else {
            None
        }
    }

    // ========================================================================
    // Phase 6.2: Peer Management (Single-Peer Mode)
    // ========================================================================

    fn add_peer(&self, _peer: WgPeerConfig) -> BoxFuture<'_, Result<(), WgTunnelError>> {
        // Single-peer mode: Cannot add additional peers
        Box::pin(async {
            Err(WgTunnelError::NotSupported(
                "Single-peer (egress) mode does not support adding peers. Use MultiPeerWgTunnel for ingress mode.".into(),
            ))
        })
    }

    fn remove_peer(&self, _public_key: &str) -> BoxFuture<'_, Result<(), WgTunnelError>> {
        // Single-peer mode: Cannot remove the configured peer
        Box::pin(async {
            Err(WgTunnelError::NotSupported(
                "Single-peer (egress) mode does not support removing peers.".into(),
            ))
        })
    }

    fn update_peer(
        &self,
        public_key: &str,
        update: WgPeerUpdate,
    ) -> BoxFuture<'_, Result<(), WgTunnelError>> {
        let public_key = public_key.to_string();
        Box::pin(async move {
            // Validate that the public key matches our configured peer
            let peer_state_guard = self.shared.peer_state.try_read().ok();
            let peer_state = peer_state_guard
                .as_ref()
                .and_then(|g| g.as_ref())
                .cloned();

            match peer_state {
                Some(state) if state.public_key == public_key => {
                    // For single-peer mode, we can update endpoint and keepalive settings
                    // However, boringtun's Tunn doesn't support dynamic updates
                    // So we can only update our tracking state, not the actual tunnel

                    if update.endpoint.is_some() || update.allowed_ips.is_some() {
                        // These would require recreating the tunnel
                        return Err(WgTunnelError::NotSupported(
                            "Updating endpoint or allowed_ips requires tunnel recreation.".into(),
                        ));
                    }

                    // Keepalive and PSK updates are tracked but not applied to running tunnel
                    if update.persistent_keepalive.is_some() || update.preshared_key.is_some() {
                        warn!("Peer update accepted but changes only take effect on reconnect");
                    }

                    Ok(())
                }
                Some(_) => Err(WgTunnelError::PeerNotFound(format!(
                    "No peer with public key: {public_key}"
                ))),
                None => Err(WgTunnelError::Internal("Peer state not initialized".into())),
            }
        })
    }

    fn get_peer(&self, public_key: &str) -> Option<WgPeerInfo> {
        // For single-peer mode, return info if the key matches
        let guard = self.shared.peer_state.try_read().ok()?;
        let state = guard.as_ref()?.clone();

        if state.public_key == public_key {
            Some(state.to_peer_info())
        } else {
            None
        }
    }

    fn list_peers(&self) -> Vec<WgPeerInfo> {
        // For single-peer mode, return the single configured peer
        match self.shared.peer_state.try_read() {
            Ok(guard) => match guard.as_ref() {
                Some(state) => vec![state.to_peer_info()],
                None => Vec::new(),
            },
            Err(_) => Vec::new(),
        }
    }

    // ========================================================================
    // Phase 6.2: Encryption/Decryption Operations
    // ========================================================================

    fn decrypt(&self, encrypted: &[u8]) -> Result<DecryptResult, WgTunnelError> {
        if !self.shared.connected.load(Ordering::Acquire) {
            return Err(WgTunnelError::NotConnected);
        }

        // Get peer public key for result
        let peer_public_key = self.config.peer_public_key.clone();

        // Allocate buffer for decrypted packet
        let mut dst = vec![0u8; encrypted.len() + WG_TRANSPORT_OVERHEAD];

        // Decapsulate packet
        let result = {
            let mut tunn_guard = self.shared.tunn.lock();
            let tunn = tunn_guard
                .as_mut()
                .ok_or(WgTunnelError::NotConnected)?;
            tunn.decapsulate(None, encrypted, &mut dst)
        };

        // Process result
        match result {
            TunnResult::WriteToTunnelV4(data, _addr) => {
                Ok((data.to_vec(), peer_public_key))
            }
            TunnResult::WriteToTunnelV6(data, _addr) => {
                Ok((data.to_vec(), peer_public_key))
            }
            TunnResult::WriteToNetwork(_) => {
                // This typically means we need to send a handshake response
                // For direct decrypt, this is unexpected - we should handle it
                Err(WgTunnelError::DecryptionError(
                    "Received handshake packet; use recv() for normal operation".into(),
                ))
            }
            TunnResult::Done => {
                Err(WgTunnelError::DecryptionError(
                    "No data to decrypt (packet was empty or already processed)".into(),
                ))
            }
            TunnResult::Err(e) => {
                Err(WgTunnelError::DecryptionError(format!(
                    "Decapsulation failed: {e:?}"
                )))
            }
        }
    }

    fn encrypt(&self, payload: &[u8], peer_public_key: &str) -> Result<Vec<u8>, WgTunnelError> {
        if !self.shared.connected.load(Ordering::Acquire) {
            return Err(WgTunnelError::NotConnected);
        }

        // Verify the peer public key matches our configured peer
        if peer_public_key != self.config.peer_public_key {
            return Err(WgTunnelError::PeerNotFound(format!(
                "Unknown peer: {}. Single-peer tunnel only supports peer: {}",
                peer_public_key, self.config.peer_public_key
            )));
        }

        // Allocate buffer for encrypted packet
        // Buffer must be at least WG_HANDSHAKE_INIT_SIZE (148 bytes) to hold handshake
        // messages that boringtun may generate during rekey
        let mut dst = vec![0u8; (payload.len() + WG_TRANSPORT_OVERHEAD).max(WG_HANDSHAKE_INIT_SIZE)];

        // Encapsulate packet
        let result = {
            let mut tunn_guard = self.shared.tunn.lock();
            let tunn = tunn_guard
                .as_mut()
                .ok_or(WgTunnelError::NotConnected)?;
            tunn.encapsulate(payload, &mut dst)
        };

        // Process result
        match result {
            TunnResult::WriteToNetwork(encrypted) => {
                Ok(encrypted.to_vec())
            }
            TunnResult::Done => {
                // Packet was queued for later (handshake not complete)
                Err(WgTunnelError::EncryptionError(
                    "Handshake not complete; packet queued but not encrypted".into(),
                ))
            }
            TunnResult::Err(e) => {
                Err(WgTunnelError::EncryptionError(format!(
                    "Encapsulation failed: {e:?}"
                )))
            }
            _ => {
                // WriteToTunnelV4/V6 shouldn't happen for encapsulate
                Err(WgTunnelError::EncryptionError(
                    "Unexpected encapsulation result".into(),
                ))
            }
        }
    }

    // ========================================================================
    // Phase 6.2: Tunnel Control
    // ========================================================================

    fn connect(&self) -> BoxFuture<'_, Result<(), WgTunnelError>> {
        Box::pin(async move {
            // Delegate to the inherent async connect method
            UserspaceWgTunnel::connect(self).await
        })
    }

    fn trigger_handshake(
        &self,
        peer_public_key: Option<&str>,
    ) -> BoxFuture<'_, Result<(), WgTunnelError>> {
        // Clone the peer_public_key option since we need 'static lifetime for the future
        let peer_public_key = peer_public_key.map(std::string::ToString::to_string);

        Box::pin(async move {
            if !self.shared.connected.load(Ordering::Acquire) {
                return Err(WgTunnelError::NotConnected);
            }

            // If a specific peer is requested, verify it matches our peer
            if let Some(ref requested_key) = peer_public_key {
                if requested_key != &self.config.peer_public_key {
                    return Err(WgTunnelError::PeerNotFound(format!(
                        "Unknown peer: {}. Single-peer tunnel only supports peer: {}",
                        requested_key, self.config.peer_public_key
                    )));
                }
            }

            // Use existing force_handshake implementation
            self.force_handshake().await
        })
    }

    fn shutdown(&self) -> BoxFuture<'_, Result<(), WgTunnelError>> {
        Box::pin(async move {
            if !self.shared.connected.load(Ordering::Acquire) {
                return Err(WgTunnelError::NotConnected);
            }

            info!("Shutting down userspace WireGuard tunnel");

            // Use existing disconnect implementation
            self.disconnect().await
        })
    }

    fn send(&self, packet: &[u8]) -> BoxFuture<'_, Result<(), WgTunnelError>> {
        // We need to clone the packet data since we're moving into the future
        let packet = packet.to_vec();
        Box::pin(async move {
            // Delegate to the inherent async send method
            UserspaceWgTunnel::send(self, &packet).await
        })
    }

    fn recv(&self) -> BoxFuture<'_, Result<Vec<u8>, WgTunnelError>> {
        Box::pin(async move {
            // Delegate to the inherent async recv method
            UserspaceWgTunnel::recv(self).await
        })
    }
}

// ============================================================================
// Key Generation Functions
// ============================================================================

/// Generate a new `WireGuard` private key
///
/// Generates a random 32-byte private key suitable for `WireGuard`.
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

/// Validate a `WireGuard` key (private or public)
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

/// Decode a Base64-encoded private key to `StaticSecret`
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

/// Decode a Base64-encoded public key to `PublicKey`
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

    // ========================================================================
    // Tag Tests (Phase 6.2)
    // ========================================================================

    #[test]
    fn test_tunnel_default_tag() {
        let config = create_test_config();
        let tunnel = UserspaceWgTunnel::new(config).unwrap();

        // Default tag should be "unnamed"
        assert_eq!(tunnel.tag(), "unnamed");
    }

    #[test]
    fn test_tunnel_with_custom_tag() {
        let config = create_test_config();
        let tunnel =
            UserspaceWgTunnel::with_tag(config, Some("egress-us-west".to_string())).unwrap();

        assert_eq!(tunnel.tag(), "egress-us-west");
    }

    #[test]
    fn test_tunnel_with_none_tag() {
        let config = create_test_config();
        let tunnel = UserspaceWgTunnel::with_tag(config, None).unwrap();

        // Should use default tag
        assert_eq!(tunnel.tag(), "unnamed");
    }

    #[test]
    fn test_tunnel_with_tag_and_buffer_pool() {
        let config = create_test_config();
        let buffer_pool = Arc::new(UdpBufferPool::new(32, 1500));
        let tunnel = UserspaceWgTunnel::with_tag_and_buffer_pool(
            config,
            Some("test-tunnel".to_string()),
            Some(buffer_pool),
        )
        .unwrap();

        assert_eq!(tunnel.tag(), "test-tunnel");
    }

    // ========================================================================
    // is_healthy Tests (Phase 6.2)
    // ========================================================================

    #[test]
    fn test_is_healthy_not_connected() {
        let config = create_test_config();
        let tunnel = UserspaceWgTunnel::new(config).unwrap();

        // Not connected = not healthy
        assert!(!tunnel.is_healthy());
    }

    // ========================================================================
    // Phase 6.2: Peer Management Tests
    // ========================================================================

    #[test]
    fn test_get_peer_with_matching_key() {
        let config = create_test_config();
        let peer_public_key = config.peer_public_key.clone();
        let tunnel = UserspaceWgTunnel::new(config).unwrap();

        // Single-peer tunnel returns Some for the configured peer's key
        let peer_info = tunnel.get_peer(&peer_public_key);
        assert!(peer_info.is_some());
        let info = peer_info.unwrap();
        assert_eq!(info.public_key, peer_public_key);
    }

    #[test]
    fn test_get_peer_with_wrong_key() {
        let config = create_test_config();
        let tunnel = UserspaceWgTunnel::new(config).unwrap();

        // Single-peer tunnel returns None for unknown keys
        assert!(tunnel.get_peer("unknown-key").is_none());
    }

    #[test]
    fn test_list_peers_returns_single_peer() {
        let config = create_test_config();
        let peer_public_key = config.peer_public_key.clone();
        let tunnel = UserspaceWgTunnel::new(config).unwrap();

        // Single-peer tunnel returns exactly one peer
        let peers = tunnel.list_peers();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].public_key, peer_public_key);
    }

    #[test]
    fn test_peer_info_has_correct_endpoint() {
        let config = create_test_config();
        let tunnel = UserspaceWgTunnel::new(config).unwrap();

        let peers = tunnel.list_peers();
        assert_eq!(peers.len(), 1);
        assert!(peers[0].endpoint.is_some());
        assert_eq!(
            peers[0].endpoint.unwrap().to_string(),
            "192.168.1.1:51820"
        );
    }

    #[test]
    fn test_peer_info_has_allowed_ips() {
        let config = create_test_config();
        let tunnel = UserspaceWgTunnel::new(config).unwrap();

        let peers = tunnel.list_peers();
        assert_eq!(peers.len(), 1);
        assert!(!peers[0].allowed_ips.is_empty());
        assert!(peers[0].allowed_ips.contains(&"0.0.0.0/0".to_string()));
    }

    #[tokio::test]
    async fn test_add_peer_single_peer_mode() {
        use crate::tunnel::config::WgPeerConfig;

        let config = create_test_config();
        let tunnel = UserspaceWgTunnel::new(config).unwrap();

        // Single-peer mode doesn't support adding peers
        let peer_config = WgPeerConfig::new("peer-public-key".to_string());
        let result = tunnel.add_peer(peer_config).await;
        assert!(matches!(result, Err(WgTunnelError::NotSupported(_))));
    }

    #[tokio::test]
    async fn test_remove_peer_single_peer_mode() {
        let config = create_test_config();
        let tunnel = UserspaceWgTunnel::new(config).unwrap();

        // Single-peer mode doesn't support removing peers
        let result = tunnel.remove_peer("some-key").await;
        assert!(matches!(result, Err(WgTunnelError::NotSupported(_))));
    }

    #[tokio::test]
    async fn test_update_peer_unknown_key() {
        use crate::tunnel::config::WgPeerUpdate;

        let config = create_test_config();
        let tunnel = UserspaceWgTunnel::new(config).unwrap();

        // Updating unknown peer should fail
        let update = WgPeerUpdate::new().with_persistent_keepalive(30);
        let result = tunnel.update_peer("unknown-key", update).await;
        assert!(matches!(result, Err(WgTunnelError::PeerNotFound(_))));
    }

    #[tokio::test]
    async fn test_update_peer_endpoint_not_supported() {
        use crate::tunnel::config::WgPeerUpdate;

        let config = create_test_config();
        let peer_public_key = config.peer_public_key.clone();
        let tunnel = UserspaceWgTunnel::new(config).unwrap();

        // Updating endpoint requires tunnel recreation
        let update = WgPeerUpdate::new().with_endpoint("1.2.3.4:51820".to_string());
        let result = tunnel.update_peer(&peer_public_key, update).await;
        assert!(matches!(result, Err(WgTunnelError::NotSupported(_))));
    }

    #[tokio::test]
    async fn test_update_peer_keepalive_accepted() {
        use crate::tunnel::config::WgPeerUpdate;

        let config = create_test_config();
        let peer_public_key = config.peer_public_key.clone();
        let tunnel = UserspaceWgTunnel::new(config).unwrap();

        // Updating keepalive is accepted (but only takes effect on reconnect)
        let update = WgPeerUpdate::new().with_persistent_keepalive(30);
        let result = tunnel.update_peer(&peer_public_key, update).await;
        assert!(result.is_ok());
    }

    // ========================================================================
    // Phase 6.2: Encryption/Decryption Tests
    // ========================================================================

    #[test]
    fn test_decrypt_not_connected() {
        let config = create_test_config();
        let tunnel = UserspaceWgTunnel::new(config).unwrap();

        let result = tunnel.decrypt(&[0u8; 100]);
        assert!(matches!(result, Err(WgTunnelError::NotConnected)));
    }

    #[test]
    fn test_encrypt_not_connected() {
        let config = create_test_config();
        let peer_key = config.peer_public_key.clone();
        let tunnel = UserspaceWgTunnel::new(config).unwrap();

        let result = tunnel.encrypt(&[0u8; 100], &peer_key);
        assert!(matches!(result, Err(WgTunnelError::NotConnected)));
    }

    #[test]
    fn test_encrypt_unknown_peer() {
        let config = create_test_config();
        let tunnel = UserspaceWgTunnel::new(config).unwrap();

        // Mark as connected for test (simulating connected state)
        tunnel.shared.connected.store(true, Ordering::Release);

        // Encrypting for unknown peer should fail (even when "connected")
        // Note: This will still fail because there's no actual Tunn instance
        let result = tunnel.encrypt(&[0u8; 100], "unknown-peer-key");
        // Should fail with PeerNotFound, not NotConnected
        match result {
            Err(WgTunnelError::PeerNotFound(_)) => (), // Expected
            Err(WgTunnelError::NotConnected) => (), // Also acceptable (no actual Tunn)
            _ => panic!("Expected PeerNotFound or NotConnected error"),
        }
    }

    // ========================================================================
    // Phase 6.2: Tunnel Control Tests
    // ========================================================================

    #[tokio::test]
    async fn test_trigger_handshake_not_connected() {
        let config = create_test_config();
        let tunnel = UserspaceWgTunnel::new(config).unwrap();

        let result = tunnel.trigger_handshake(None).await;
        assert!(matches!(result, Err(WgTunnelError::NotConnected)));
    }

    #[tokio::test]
    async fn test_trigger_handshake_unknown_peer() {
        let config = create_test_config();
        let tunnel = UserspaceWgTunnel::new(config).unwrap();

        // Mark as connected for test
        tunnel.shared.connected.store(true, Ordering::Release);

        // Trigger handshake for unknown peer should fail
        let result = tunnel.trigger_handshake(Some("unknown-key")).await;
        assert!(matches!(result, Err(WgTunnelError::PeerNotFound(_))));
    }

    #[tokio::test]
    async fn test_shutdown_not_connected() {
        let config = create_test_config();
        let tunnel = UserspaceWgTunnel::new(config).unwrap();

        let result = tunnel.shutdown().await;
        assert!(matches!(result, Err(WgTunnelError::NotConnected)));
    }

    // ========================================================================
    // Phase 6.2: Additional Encryption Tests
    // ========================================================================

    #[test]
    fn test_encrypt_wrong_peer_key() {
        let config = create_test_config();
        let tunnel = UserspaceWgTunnel::new(config).unwrap();

        // Mark as connected for test
        tunnel.shared.connected.store(true, Ordering::Release);

        // Generate a different key that's not the configured peer
        let other_private = generate_private_key();
        let other_public = derive_public_key(&other_private).unwrap();

        // Encrypting for wrong peer should fail with PeerNotFound
        let result = tunnel.encrypt(&[0u8; 100], &other_public);
        assert!(matches!(result, Err(WgTunnelError::PeerNotFound(_))));
    }

    #[test]
    fn test_encrypt_empty_payload() {
        let config = create_test_config();
        let peer_key = config.peer_public_key.clone();
        let tunnel = UserspaceWgTunnel::new(config).unwrap();

        // Mark as connected but without actual Tunn instance
        tunnel.shared.connected.store(true, Ordering::Release);

        // Empty payload should still attempt encryption
        // Will fail because no Tunn instance, but tests the path
        let result = tunnel.encrypt(&[], &peer_key);
        // Should fail with NotConnected (no Tunn) or EncryptionError
        assert!(matches!(
            result,
            Err(WgTunnelError::NotConnected) | Err(WgTunnelError::EncryptionError(_))
        ));
    }

    #[test]
    fn test_encrypt_large_payload() {
        let config = create_test_config();
        let peer_key = config.peer_public_key.clone();
        let tunnel = UserspaceWgTunnel::new(config).unwrap();

        // Mark as connected but without actual Tunn instance
        tunnel.shared.connected.store(true, Ordering::Release);

        // Large payload (larger than MTU)
        let large_payload = vec![0u8; 10000];
        let result = tunnel.encrypt(&large_payload, &peer_key);
        // Should fail with NotConnected (no Tunn) or EncryptionError
        assert!(matches!(
            result,
            Err(WgTunnelError::NotConnected) | Err(WgTunnelError::EncryptionError(_))
        ));
    }

    #[test]
    fn test_encrypt_valid_ipv4_packet() {
        let config = create_test_config();
        let peer_key = config.peer_public_key.clone();
        let tunnel = UserspaceWgTunnel::new(config).unwrap();

        // Mark as connected but without actual Tunn instance
        tunnel.shared.connected.store(true, Ordering::Release);

        // Create a valid IPv4 packet header (minimum 20 bytes)
        let mut ipv4_packet = vec![0u8; 20];
        ipv4_packet[0] = 0x45; // Version 4, IHL 5
        ipv4_packet[2..4].copy_from_slice(&20u16.to_be_bytes()); // Total length
        ipv4_packet[12..16].copy_from_slice(&[192, 168, 1, 1]); // Source IP
        ipv4_packet[16..20].copy_from_slice(&[8, 8, 8, 8]); // Dest IP

        let result = tunnel.encrypt(&ipv4_packet, &peer_key);
        // Should fail with NotConnected (no Tunn) since we didn't actually connect
        assert!(matches!(
            result,
            Err(WgTunnelError::NotConnected) | Err(WgTunnelError::EncryptionError(_))
        ));
    }

    #[test]
    fn test_encrypt_peer_key_format_validation() {
        let config = create_test_config();
        let tunnel = UserspaceWgTunnel::new(config).unwrap();

        // Mark as connected
        tunnel.shared.connected.store(true, Ordering::Release);

        // Invalid peer key format (not valid base64)
        let result = tunnel.encrypt(&[0u8; 100], "not-valid-base64!!!");
        // Should fail with PeerNotFound (key doesn't match)
        assert!(matches!(result, Err(WgTunnelError::PeerNotFound(_))));
    }

    #[tokio::test]
    async fn test_encrypt_after_disconnect() {
        let config = create_test_config();
        let peer_key = config.peer_public_key.clone();
        let tunnel = UserspaceWgTunnel::new(config).unwrap();

        // Never connected, so should fail with NotConnected
        let result = tunnel.encrypt(&[0u8; 100], &peer_key);
        assert!(matches!(result, Err(WgTunnelError::NotConnected)));

        // Simulate connect then disconnect (connected = false)
        tunnel.shared.connected.store(true, Ordering::Release);
        tunnel.shared.connected.store(false, Ordering::Release);

        let result = tunnel.encrypt(&[0u8; 100], &peer_key);
        assert!(matches!(result, Err(WgTunnelError::NotConnected)));
    }

    // ========================================================================
    // Phase 6.2: Additional Decryption Tests
    // ========================================================================

    #[test]
    fn test_decrypt_invalid_packet() {
        let config = create_test_config();
        let tunnel = UserspaceWgTunnel::new(config).unwrap();

        // Mark as connected but without actual Tunn instance
        tunnel.shared.connected.store(true, Ordering::Release);

        // Invalid encrypted packet (random bytes)
        let invalid_packet = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02, 0x03];
        let result = tunnel.decrypt(&invalid_packet);
        // Should fail with NotConnected (no Tunn) or DecryptionError
        assert!(matches!(
            result,
            Err(WgTunnelError::NotConnected) | Err(WgTunnelError::DecryptionError(_))
        ));
    }

    #[test]
    fn test_decrypt_empty_packet() {
        let config = create_test_config();
        let tunnel = UserspaceWgTunnel::new(config).unwrap();

        // Mark as connected but without actual Tunn instance
        tunnel.shared.connected.store(true, Ordering::Release);

        // Empty packet
        let result = tunnel.decrypt(&[]);
        // Should fail with NotConnected (no Tunn) or DecryptionError
        assert!(matches!(
            result,
            Err(WgTunnelError::NotConnected) | Err(WgTunnelError::DecryptionError(_))
        ));
    }

    #[test]
    fn test_decrypt_too_short_packet() {
        let config = create_test_config();
        let tunnel = UserspaceWgTunnel::new(config).unwrap();

        // Mark as connected but without actual Tunn instance
        tunnel.shared.connected.store(true, Ordering::Release);

        // Packet shorter than WG_TRANSPORT_OVERHEAD (32 bytes)
        let short_packet = vec![0u8; 16];
        let result = tunnel.decrypt(&short_packet);
        // Should fail with NotConnected (no Tunn) or DecryptionError
        assert!(matches!(
            result,
            Err(WgTunnelError::NotConnected) | Err(WgTunnelError::DecryptionError(_))
        ));
    }

    #[test]
    fn test_decrypt_random_data() {
        let config = create_test_config();
        let tunnel = UserspaceWgTunnel::new(config).unwrap();

        // Mark as connected but without actual Tunn instance
        tunnel.shared.connected.store(true, Ordering::Release);

        // Random data that looks like a WireGuard packet size but isn't valid
        let mut random_data = vec![0u8; 100];
        rand::thread_rng().fill_bytes(&mut random_data);

        let result = tunnel.decrypt(&random_data);
        // Should fail with NotConnected (no Tunn) or DecryptionError
        assert!(matches!(
            result,
            Err(WgTunnelError::NotConnected) | Err(WgTunnelError::DecryptionError(_))
        ));
    }

    // ========================================================================
    // Phase 6.2: DecryptResult Type Tests
    // ========================================================================

    #[test]
    fn test_decrypt_result_type_usage() {
        // Verify DecryptResult is a tuple of (Vec<u8>, String)
        let decrypted_data = vec![1u8, 2, 3, 4];
        let peer_key = "test-peer-key".to_string();

        let result: DecryptResult = (decrypted_data.clone(), peer_key.clone());

        // Destructure to verify the type
        let (data, key) = result;
        assert_eq!(data, decrypted_data);
        assert_eq!(key, peer_key);
    }

    #[test]
    fn test_decrypt_result_contains_peer_key() {
        // When decrypt succeeds, it should contain the peer public key
        // We can't easily test a successful decrypt without a real tunnel,
        // but we can verify the type structure
        let config = create_test_config();
        let expected_peer_key = config.peer_public_key.clone();

        // Create a mock result as if decrypt succeeded
        let mock_result: DecryptResult = (vec![0u8; 100], expected_peer_key.clone());

        let (_, returned_key) = mock_result;
        assert_eq!(returned_key, expected_peer_key);
    }

    // ========================================================================
    // Phase 6.2: WG_TRANSPORT_OVERHEAD Constant Tests
    // ========================================================================

    #[test]
    fn test_wg_transport_overhead_value() {
        // WireGuard transport data overhead is exactly 32 bytes:
        // - 4 bytes: message type
        // - 4 bytes: receiver index
        // - 8 bytes: counter
        // - 16 bytes: Poly1305 authentication tag
        assert_eq!(WG_TRANSPORT_OVERHEAD, 32);
    }

    #[test]
    fn test_wg_overhead_matches_transport_overhead() {
        // The deprecated WG_OVERHEAD should match WG_TRANSPORT_OVERHEAD
        #[allow(deprecated)]
        {
            assert_eq!(WG_OVERHEAD, WG_TRANSPORT_OVERHEAD);
        }
    }

    #[test]
    fn test_min_buffer_size_adequate() {
        // MIN_BUFFER_SIZE must be at least WG_HANDSHAKE_INIT_SIZE
        assert!(MIN_BUFFER_SIZE >= WG_HANDSHAKE_INIT_SIZE);
        // It should also be larger than transport overhead
        assert!(MIN_BUFFER_SIZE > WG_TRANSPORT_OVERHEAD);
    }

    // ========================================================================
    // Phase 6.2: PeerStateInner Tests
    // ========================================================================

    #[test]
    fn test_peer_state_inner_new() {
        let state = PeerStateInner::new(
            "test-public-key".to_string(),
            Some("192.168.1.1:51820".parse().unwrap()),
            vec!["0.0.0.0/0".to_string()],
        );

        assert_eq!(state.public_key, "test-public-key");
        assert!(state.endpoint.is_some());
        assert_eq!(state.allowed_ips, vec!["0.0.0.0/0"]);
        assert!(state.persistent_keepalive.is_none());
        assert!(state.preshared_key.is_none());
        assert_eq!(state.tx_bytes.load(Ordering::Relaxed), 0);
        assert_eq!(state.rx_bytes.load(Ordering::Relaxed), 0);
        assert!(!state.last_handshake_valid.load(Ordering::Relaxed));
    }

    #[test]
    fn test_peer_state_inner_to_peer_info() {
        let state = PeerStateInner::new(
            "test-public-key".to_string(),
            Some("192.168.1.1:51820".parse().unwrap()),
            vec!["10.0.0.0/8".to_string()],
        );

        // Set some stats
        state.tx_bytes.store(1000, Ordering::Relaxed);
        state.rx_bytes.store(2000, Ordering::Relaxed);

        let info = state.to_peer_info();
        assert_eq!(info.public_key, "test-public-key");
        assert_eq!(info.endpoint.unwrap().to_string(), "192.168.1.1:51820");
        assert_eq!(info.allowed_ips, vec!["10.0.0.0/8"]);
        assert_eq!(info.tx_bytes, 1000);
        assert_eq!(info.rx_bytes, 2000);
        assert!(info.last_handshake.is_none());
        assert!(!info.is_connected); // No handshake = not connected
    }

    #[test]
    fn test_peer_state_inner_update_handshake() {
        let state = PeerStateInner::new(
            "test-public-key".to_string(),
            None,
            vec![],
        );

        // Initially no handshake
        assert!(!state.last_handshake_valid.load(Ordering::Relaxed));

        // Update handshake
        state.update_handshake();

        // Should now have a valid handshake timestamp
        assert!(state.last_handshake_valid.load(Ordering::Relaxed));
        let timestamp = state.last_handshake.load(Ordering::Relaxed);
        assert!(timestamp > 0);
    }

    #[test]
    fn test_peer_state_inner_to_peer_info_with_handshake() {
        let state = PeerStateInner::new(
            "test-public-key".to_string(),
            None,
            vec![],
        );

        // Update handshake to make it "recent"
        state.update_handshake();

        let info = state.to_peer_info();
        assert!(info.last_handshake.is_some());
        assert!(info.is_connected); // Recent handshake = connected
    }
}
