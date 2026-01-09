//! WireGuard Ingress Manager for Phase 6.3
//!
//! This module provides the main `WgIngressManager` struct that manages
//! the WireGuard ingress tunnel, including peer management, packet
//! processing, and statistics collection.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                       WgIngressManager                           │
//! ├─────────────────────────────────────────────────────────────────┤
//! │  State Machine:                                                  │
//! │  [Created] → [Starting] → [Running] → [Stopping] → [Stopped]   │
//! │                                │                                │
//! │                                └── Error handling ──→ [Error]   │
//! ├─────────────────────────────────────────────────────────────────┤
//! │  Components:                                                     │
//! │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐ │
//! │  │ UDP Socket      │  │ Peer Registry   │  │ IngressProcessor│ │
//! │  │ (listen_addr)   │  │ (public_key →   │  │ (DSCP + Rules)  │ │
//! │  │                 │  │  peer config)   │  │                 │ │
//! │  └─────────────────┘  └─────────────────┘  └─────────────────┘ │
//! │           │                    │                    │          │
//! │           └────────────────────┼────────────────────┘          │
//! │                                │                               │
//! │                    ┌───────────▼───────────┐                   │
//! │                    │   Packet Processing   │                   │
//! │                    │   Loop (async task)   │                   │
//! │                    └───────────────────────┘                   │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Lock Ordering (Critical for Deadlock Prevention)
//!
//! When acquiring multiple locks in `WgIngressManager`, always follow this order:
//! 1. `state` (RwLock) - State machine
//! 2. `peers` (RwLock) - Peer registry
//! 3. `socket` (RwLock) - UDP socket
//! 4. `shutdown_tx` (RwLock) - Shutdown signal
//! 5. `task_handle` (RwLock) - Background task handle
//! 6. `packet_rx` (tokio::Mutex) - Packet receiver
//! 7. Per-peer tunnel locks (see `UserspaceWgTunnel` lock ordering)
//!
//! Never hold a higher-numbered lock while acquiring a lower-numbered lock.
//!
//! # Example
//!
//! ```ignore
//! use rust_router::ingress::{WgIngressManager, WgIngressConfig};
//! use rust_router::rules::RuleEngine;
//! use std::sync::Arc;
//!
//! // Create configuration
//! let config = WgIngressConfig::builder()
//!     .private_key("base64_private_key")
//!     .listen_addr("0.0.0.0:36100".parse().unwrap())
//!     .local_ip("10.25.0.1".parse().unwrap())
//!     .allowed_subnet("10.25.0.0/24".parse().unwrap())
//!     .build();
//!
//! // Create manager
//! let rule_engine = Arc::new(RuleEngine::new(snapshot));
//! let manager = WgIngressManager::new(config, rule_engine)?;
//!
//! // Start accepting connections
//! manager.start().await?;
//!
//! // Add a peer
//! let peer = WgIngressPeerConfig::new("peer_public_key", "10.25.0.2");
//! manager.add_peer(peer).await?;
//!
//! // Later, stop gracefully
//! manager.stop().await?;
//! ```

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use ipnet::IpNet;
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tracing::{debug, info, trace, warn};

// Phase 6.8: Batch I/O imports (Linux only)
#[cfg(target_os = "linux")]
use crate::io::{BatchConfig, BatchReceiver};

use super::config::{WgIngressConfig, WgIngressPeerConfig};
use super::error::{IngressError, IngressResult};
use super::processor::{IngressProcessor, RoutingDecision};
use crate::rules::RuleEngine;

/// Default buffer size for UDP receive
const UDP_RECV_BUFFER_SIZE: usize = 65536;

/// Channel capacity for processed packets
const PACKET_CHANNEL_CAPACITY: usize = 256;

/// WireGuard transport data packet overhead
const WG_TRANSPORT_OVERHEAD: usize = 32;

/// Minimum buffer size for WireGuard packets (must fit handshake initiation)
#[allow(dead_code)]
const MIN_BUFFER_SIZE: usize = 148;

/// Default socket receive buffer size (208 KB)
pub const DEFAULT_SO_RCVBUF: usize = 212_992;

/// Default socket send buffer size (208 KB)
pub const DEFAULT_SO_SNDBUF: usize = 212_992;

/// Ingress manager state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngressState {
    /// Manager created but not started
    Created,
    /// Manager is starting up
    Starting,
    /// Manager is running and accepting connections
    Running,
    /// Manager is stopping
    Stopping,
    /// Manager has stopped
    Stopped,
    /// Manager encountered an error
    Error,
}

impl std::fmt::Display for IngressState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Created => write!(f, "created"),
            Self::Starting => write!(f, "starting"),
            Self::Running => write!(f, "running"),
            Self::Stopping => write!(f, "stopping"),
            Self::Stopped => write!(f, "stopped"),
            Self::Error => write!(f, "error"),
        }
    }
}

/// Phase 11-Fix.AA: Information about an ingress peer for listing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngressPeerListItem {
    /// Peer public key (Base64)
    pub public_key: String,
    /// Allowed IPs (comma-separated)
    pub allowed_ips: String,
    /// Optional peer name (from database)
    pub name: Option<String>,
    /// Bytes received from this peer
    pub rx_bytes: u64,
    /// Bytes sent to this peer
    pub tx_bytes: u64,
    /// Last handshake timestamp (Unix epoch seconds)
    pub last_handshake: Option<u64>,
}

/// Statistics for the WireGuard ingress manager
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WgIngressStats {
    /// Total bytes received from all peers
    pub rx_bytes: u64,
    /// Total bytes transmitted to all peers
    pub tx_bytes: u64,
    /// Total packets received
    pub rx_packets: u64,
    /// Total packets transmitted
    pub tx_packets: u64,
    /// Total invalid packets received
    pub invalid_packets: u64,
    /// Total handshakes completed
    pub handshake_count: u64,
    /// Number of currently registered peers
    pub peer_count: usize,
    /// Number of active (connected) peers
    pub active_peer_count: usize,
    /// Packets dropped due to errors
    pub dropped_packets: u64,
}

/// Internal statistics tracking
#[derive(Default)]
struct StatsInner {
    rx_bytes: AtomicU64,
    tx_bytes: AtomicU64,
    rx_packets: AtomicU64,
    tx_packets: AtomicU64,
    invalid_packets: AtomicU64,
    handshake_count: AtomicU64,
    dropped_packets: AtomicU64,
}

impl StatsInner {
    fn snapshot(&self, peer_count: usize, active_peer_count: usize) -> WgIngressStats {
        WgIngressStats {
            rx_bytes: self.rx_bytes.load(Ordering::Relaxed),
            tx_bytes: self.tx_bytes.load(Ordering::Relaxed),
            rx_packets: self.rx_packets.load(Ordering::Relaxed),
            tx_packets: self.tx_packets.load(Ordering::Relaxed),
            invalid_packets: self.invalid_packets.load(Ordering::Relaxed),
            handshake_count: self.handshake_count.load(Ordering::Relaxed),
            peer_count,
            active_peer_count,
            dropped_packets: self.dropped_packets.load(Ordering::Relaxed),
        }
    }
}

/// Registered peer information with boringtun tunnel
///
/// # Lock Ordering
///
/// When acquiring locks on RegisteredPeer:
/// 1. `tunn` (Mutex) - WireGuard crypto state
/// 2. `allowed_ips_parsed` - Read-only after initialization (no lock needed)
///
/// These locks are level 7 in the global ordering (per-peer tunnel locks).
struct RegisteredPeer {
    /// Peer configuration (reserved for future per-peer routing)
    #[allow(dead_code)]
    config: WgIngressPeerConfig,
    /// boringtun tunnel for this peer (for decryption)
    tunn: Mutex<Option<Box<Tunn>>>,
    /// Whether the peer is currently connected
    is_connected: AtomicBool,
    /// Bytes received from this peer
    rx_bytes: AtomicU64,
    /// Bytes transmitted to this peer (reserved for future use)
    #[allow(dead_code)]
    tx_bytes: AtomicU64,
    /// Last activity timestamp (Unix seconds)
    last_activity: AtomicU64,
    /// Last handshake timestamp (Unix seconds)
    last_handshake: AtomicU64,
    /// Parsed allowed IPs for source IP validation
    allowed_ips_parsed: Vec<IpNet>,
    /// Tunnel index for boringtun (reserved for future session lookup optimization)
    #[allow(dead_code)]
    tunnel_index: u32,
}

impl RegisteredPeer {
    fn new(config: WgIngressPeerConfig, private_key: &StaticSecret, tunnel_index: u32) -> Result<Self, IngressError> {
        // Parse peer public key
        let peer_public = decode_public_key(&config.public_key)
            .map_err(|e| IngressError::invalid_config(format!("Invalid peer public key: {}", e)))?;

        // Parse preshared key if present
        let psk = config.preshared_key.as_ref().map(|psk| {
            decode_psk(psk)
        }).transpose().map_err(|e| IngressError::invalid_config(format!("Invalid preshared key: {}", e)))?;

        // Create boringtun tunnel for this peer
        let tunn = Tunn::new(
            private_key.clone(),
            peer_public,
            psk,
            config.persistent_keepalive,
            tunnel_index,
            None, // No rate limiter
        ).map_err(|e| IngressError::internal(format!("Failed to create tunnel for peer: {}", e)))?;

        // Parse allowed IPs
        let allowed_ips_parsed: Vec<IpNet> = config.allowed_ips
            .iter()
            .filter_map(|ip| ip.to_string().parse().ok())
            .collect();

        Ok(Self {
            config,
            tunn: Mutex::new(Some(Box::new(tunn))),
            is_connected: AtomicBool::new(false),
            rx_bytes: AtomicU64::new(0),
            tx_bytes: AtomicU64::new(0),
            last_activity: AtomicU64::new(0),
            last_handshake: AtomicU64::new(0),
            allowed_ips_parsed,
            tunnel_index,
        })
    }

    /// Decrypt an incoming packet using this peer's tunnel
    ///
    /// Returns the decrypted data if successful, or None if decryption failed
    /// (e.g., packet is not from this peer or invalid).
    fn decrypt(&self, encrypted: &[u8], dst: &mut [u8]) -> Option<DecryptedPacket> {
        let mut tunn_guard = self.tunn.lock();
        let tunn = tunn_guard.as_mut()?;

        match tunn.decapsulate(None, encrypted, dst) {
            TunnResult::WriteToTunnelV4(data, _) => {
                Some(DecryptedPacket {
                    data: data.to_vec(),
                    needs_response: false,
                    response: None,
                })
            }
            TunnResult::WriteToTunnelV6(data, _) => {
                Some(DecryptedPacket {
                    data: data.to_vec(),
                    needs_response: false,
                    response: None,
                })
            }
            TunnResult::WriteToNetwork(response) => {
                // Need to send a response (handshake response, etc.)
                Some(DecryptedPacket {
                    data: Vec::new(),
                    needs_response: true,
                    response: Some(response.to_vec()),
                })
            }
            TunnResult::Done => None,
            TunnResult::Err(_e) => None,
        }
    }

    /// Check if a source IP is allowed for this peer
    fn is_source_ip_allowed(&self, ip: IpAddr) -> bool {
        if self.allowed_ips_parsed.is_empty() {
            // If no allowed IPs configured, allow all (shouldn't happen normally)
            return true;
        }
        self.allowed_ips_parsed.iter().any(|net| net.contains(&ip))
    }

    /// Update handshake timestamp
    fn update_handshake(&self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.last_handshake.store(now, Ordering::Relaxed);
    }

    /// Update activity timestamp
    fn update_activity(&self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.last_activity.store(now, Ordering::Relaxed);
    }
}

/// Result of decrypting a WireGuard packet
struct DecryptedPacket {
    /// Decrypted plaintext data (empty if needs_response is true)
    data: Vec<u8>,
    /// Whether a response needs to be sent
    needs_response: bool,
    /// Response data to send (e.g., handshake response)
    response: Option<Vec<u8>>,
}

/// Decode a Base64-encoded private key to StaticSecret
fn decode_private_key(key: &str) -> Result<StaticSecret, String> {
    let bytes = BASE64
        .decode(key)
        .map_err(|e| format!("Invalid Base64: {}", e))?;

    if bytes.len() != 32 {
        return Err(format!("Key must be 32 bytes, got {}", bytes.len()));
    }

    let mut key_array = [0u8; 32];
    key_array.copy_from_slice(&bytes);
    Ok(StaticSecret::from(key_array))
}

/// Decode a Base64-encoded public key to PublicKey
fn decode_public_key(key: &str) -> Result<PublicKey, String> {
    let bytes = BASE64
        .decode(key)
        .map_err(|e| format!("Invalid Base64: {}", e))?;

    if bytes.len() != 32 {
        return Err(format!("Key must be 32 bytes, got {}", bytes.len()));
    }

    let mut key_array = [0u8; 32];
    key_array.copy_from_slice(&bytes);
    Ok(PublicKey::from(key_array))
}

/// Decode a Base64-encoded preshared key
fn decode_psk(key: &str) -> Result<[u8; 32], String> {
    let bytes = BASE64
        .decode(key)
        .map_err(|e| format!("Invalid Base64: {}", e))?;

    if bytes.len() != 32 {
        return Err(format!("PSK must be 32 bytes, got {}", bytes.len()));
    }

    let mut key_array = [0u8; 32];
    key_array.copy_from_slice(&bytes);
    Ok(key_array)
}

/// WireGuard Ingress Manager
///
/// Manages a WireGuard ingress tunnel, accepting connections from clients
/// and routing their traffic based on DSCP values and rule matching.
///
/// # Thread Safety
///
/// The manager is designed to be used from multiple async tasks:
/// - `start()`, `stop()` should be called from a single control task
/// - `add_peer()`, `remove_peer()` can be called concurrently
/// - `stats()` can be called from any task
///
/// # State Machine
///
/// ```text
/// Created → Starting → Running ↔ Stopping → Stopped
///                         ↓
///                       Error
/// ```
///
/// # Lock Ordering (Critical for Deadlock Prevention)
///
/// When acquiring multiple locks, always follow this order:
/// 1. `state` (RwLock)
/// 2. `peers` (RwLock)
/// 3. `socket` (RwLock)
/// 4. `shutdown_tx` (RwLock)
/// 5. `task_handle` (RwLock)
/// 6. `packet_rx` (tokio::Mutex)
/// 7. Per-peer `tunn` locks (Mutex) - see RegisteredPeer
///
/// Never hold a higher-numbered lock while acquiring a lower-numbered lock.
pub struct WgIngressManager {
    /// Configuration
    config: WgIngressConfig,

    /// Private key for WireGuard operations (decoded from config)
    private_key: StaticSecret,

    /// Packet processor
    processor: Arc<IngressProcessor>,

    /// Current state
    state: RwLock<IngressState>,

    /// Registered peers (public_key -> peer info)
    peers: RwLock<HashMap<String, Arc<RegisteredPeer>>>,

    /// Statistics
    stats: Arc<StatsInner>,

    /// UDP socket (set after start)
    socket: RwLock<Option<Arc<UdpSocket>>>,

    /// Shutdown signal sender
    shutdown_tx: RwLock<Option<oneshot::Sender<()>>>,

    /// Background task handle
    task_handle: RwLock<Option<JoinHandle<()>>>,

    /// Processed packet receiver (for testing/integration)
    packet_rx: tokio::sync::Mutex<Option<mpsc::Receiver<ProcessedPacket>>>,

    /// Next tunnel index for peer creation
    next_tunnel_index: AtomicU64,

    /// Socket buffer configuration
    socket_recv_buffer: usize,
    socket_send_buffer: usize,
}

/// A processed packet ready for routing
#[derive(Debug, Clone)]
pub struct ProcessedPacket {
    /// Original packet data
    pub data: Vec<u8>,
    /// Routing decision
    pub routing: RoutingDecision,
    /// Source peer's public key
    pub peer_public_key: String,
    /// Source address
    pub src_addr: SocketAddr,
}

impl WgIngressManager {
    /// Create a new WireGuard ingress manager
    ///
    /// # Arguments
    ///
    /// * `config` - Ingress configuration
    /// * `rule_engine` - Rule engine for routing decisions
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration is invalid.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let config = WgIngressConfig::builder()
    ///     .private_key("key")
    ///     .listen_addr("0.0.0.0:36100".parse().unwrap())
    ///     .local_ip("10.25.0.1".parse().unwrap())
    ///     .allowed_subnet("10.25.0.0/24".parse().unwrap())
    ///     .build();
    ///
    /// let manager = WgIngressManager::new(config, rule_engine)?;
    /// ```
    pub fn new(config: WgIngressConfig, rule_engine: Arc<RuleEngine>) -> IngressResult<Self> {
        // Validate configuration
        config.validate()?;

        // Decode private key
        let private_key = decode_private_key(&config.private_key)
            .map_err(|e| IngressError::invalid_config(format!("Invalid private key: {}", e)))?;

        let processor = Arc::new(IngressProcessor::new(rule_engine));

        info!(
            listen_addr = %config.listen_addr,
            local_ip = %config.local_ip,
            subnet = %config.allowed_subnet,
            "Creating WireGuard ingress manager"
        );

        Ok(Self {
            config,
            private_key,
            processor,
            state: RwLock::new(IngressState::Created),
            peers: RwLock::new(HashMap::new()),
            stats: Arc::new(StatsInner::default()),
            socket: RwLock::new(None),
            shutdown_tx: RwLock::new(None),
            task_handle: RwLock::new(None),
            packet_rx: tokio::sync::Mutex::new(None),
            next_tunnel_index: AtomicU64::new(1),
            socket_recv_buffer: DEFAULT_SO_RCVBUF,
            socket_send_buffer: DEFAULT_SO_SNDBUF,
        })
    }

    /// Create a new WireGuard ingress manager with custom socket buffers
    ///
    /// # Arguments
    ///
    /// * `config` - Ingress configuration
    /// * `rule_engine` - Rule engine for routing decisions
    /// * `recv_buffer` - Socket receive buffer size
    /// * `send_buffer` - Socket send buffer size
    pub fn with_socket_buffers(
        config: WgIngressConfig,
        rule_engine: Arc<RuleEngine>,
        recv_buffer: usize,
        send_buffer: usize,
    ) -> IngressResult<Self> {
        let mut manager = Self::new(config, rule_engine)?;
        manager.socket_recv_buffer = recv_buffer;
        manager.socket_send_buffer = send_buffer;
        Ok(manager)
    }

    /// Start the ingress manager
    ///
    /// Binds to the configured UDP address and starts the packet processing loop.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Manager is already started
    /// - UDP socket binding fails
    /// - Background task spawning fails
    ///
    /// # Example
    ///
    /// ```ignore
    /// manager.start().await?;
    /// ```
    pub async fn start(&self) -> IngressResult<()> {
        // Check and update state
        {
            let mut state = self.state.write();
            match *state {
                IngressState::Created | IngressState::Stopped => {
                    *state = IngressState::Starting;
                }
                IngressState::Running | IngressState::Starting => {
                    return Err(IngressError::AlreadyStarted);
                }
                IngressState::Stopping => {
                    return Err(IngressError::internal("Cannot start while stopping"));
                }
                IngressState::Error => {
                    // Allow restart from error state
                    *state = IngressState::Starting;
                }
            }
        }

        info!(listen_addr = %self.config.listen_addr, "Starting WireGuard ingress");

        // Bind UDP socket
        let socket = match UdpSocket::bind(self.config.listen_addr).await {
            Ok(s) => Arc::new(s),
            Err(e) => {
                *self.state.write() = IngressState::Error;
                return Err(IngressError::bind(
                    self.config.listen_addr.to_string(),
                    e.to_string(),
                ));
            }
        };

        // Configure socket buffers for better performance
        if let Err(e) = configure_socket_buffers(&socket, self.socket_recv_buffer, self.socket_send_buffer) {
            warn!("Failed to configure socket buffers: {}", e);
        }

        // Store socket
        *self.socket.write() = Some(Arc::clone(&socket));

        // Create shutdown channel
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        *self.shutdown_tx.write() = Some(shutdown_tx);

        // Create packet channel
        let (packet_tx, packet_rx) = mpsc::channel(PACKET_CHANNEL_CAPACITY);
        *self.packet_rx.lock().await = Some(packet_rx);

        // Clone peers map for the background task
        let task_peers = {
            let peers = self.peers.read();
            peers.clone()
        };

        // Spawn background task
        let task_socket = Arc::clone(&socket);
        let task_processor = Arc::clone(&self.processor);
        let task_stats = Arc::clone(&self.stats);
        let task_config = self.config.clone();

        let handle = tokio::spawn(async move {
            Self::packet_loop(
                task_socket,
                task_processor,
                task_stats,
                task_config,
                task_peers,
                packet_tx,
                shutdown_rx,
            )
            .await;
        });

        *self.task_handle.write() = Some(handle);
        *self.state.write() = IngressState::Running;

        info!("WireGuard ingress started successfully");
        Ok(())
    }

    /// Stop the ingress manager gracefully
    ///
    /// Signals the background task to stop and waits for it to complete.
    ///
    /// # Errors
    ///
    /// Returns an error if the manager is not running.
    ///
    /// # Example
    ///
    /// ```ignore
    /// manager.stop().await?;
    /// ```
    pub async fn stop(&self) -> IngressResult<()> {
        // Check and update state
        {
            let mut state = self.state.write();
            match *state {
                IngressState::Running => {
                    *state = IngressState::Stopping;
                }
                IngressState::Created | IngressState::Stopped => {
                    return Err(IngressError::NotStarted);
                }
                IngressState::Starting | IngressState::Stopping => {
                    return Err(IngressError::internal("Invalid state for stop"));
                }
                IngressState::Error => {
                    *state = IngressState::Stopping;
                }
            }
        }

        info!("Stopping WireGuard ingress");

        // Send shutdown signal
        if let Some(tx) = self.shutdown_tx.write().take() {
            let _ = tx.send(());
        }

        // Wait for background task
        if let Some(handle) = self.task_handle.write().take() {
            let _ = tokio::time::timeout(std::time::Duration::from_secs(5), handle).await;
        }

        // Clean up socket
        *self.socket.write() = None;

        *self.state.write() = IngressState::Stopped;

        info!("WireGuard ingress stopped");
        Ok(())
    }

    /// Add a peer (client) to the ingress
    ///
    /// The peer will be allowed to connect to the WireGuard ingress.
    ///
    /// # Arguments
    ///
    /// * `peer` - Peer configuration
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Peer configuration is invalid
    /// - Peer already exists (by public key)
    ///
    /// # Example
    ///
    /// ```ignore
    /// let peer = WgIngressPeerConfig::new("public_key", "10.25.0.2");
    /// manager.add_peer(peer).await?;
    /// ```
    pub async fn add_peer(&self, peer: WgIngressPeerConfig) -> IngressResult<()> {
        // Validate peer configuration
        peer.validate()?;

        let public_key = peer.public_key.clone();

        // Check for duplicate
        {
            let peers = self.peers.read();
            if peers.contains_key(&public_key) {
                return Err(IngressError::peer_already_exists(&public_key));
            }
        }

        // Get next tunnel index
        let tunnel_index = self.next_tunnel_index.fetch_add(1, Ordering::Relaxed) as u32;

        // Create registered peer with boringtun tunnel
        let registered_peer = RegisteredPeer::new(peer, &self.private_key, tunnel_index)?;

        // Add peer
        {
            let mut peers = self.peers.write();
            peers.insert(public_key.clone(), Arc::new(registered_peer));
        }

        info!(public_key = %public_key, tunnel_index = tunnel_index, "Added peer to ingress");
        Ok(())
    }

    /// Remove a peer from the ingress
    ///
    /// # Arguments
    ///
    /// * `public_key` - Peer's public key (Base64 encoded)
    ///
    /// # Errors
    ///
    /// Returns an error if the peer is not found.
    ///
    /// # Example
    ///
    /// ```ignore
    /// manager.remove_peer("public_key").await?;
    /// ```
    pub async fn remove_peer(&self, public_key: &str) -> IngressResult<()> {
        let mut peers = self.peers.write();
        if peers.remove(public_key).is_none() {
            return Err(IngressError::peer_not_found(public_key));
        }

        info!(public_key = %public_key, "Removed peer from ingress");
        Ok(())
    }

    /// Get current statistics
    ///
    /// # Returns
    ///
    /// A snapshot of the current ingress statistics.
    #[must_use]
    pub fn stats(&self) -> WgIngressStats {
        let peers = self.peers.read();
        let peer_count = peers.len();
        let active_peer_count = peers
            .values()
            .filter(|p| p.is_connected.load(Ordering::Relaxed))
            .count();
        self.stats.snapshot(peer_count, active_peer_count)
    }

    /// Get current state
    #[must_use]
    pub fn state(&self) -> IngressState {
        *self.state.read()
    }

    /// Check if manager is running
    #[must_use]
    pub fn is_running(&self) -> bool {
        *self.state.read() == IngressState::Running
    }

    /// Get the number of registered peers
    #[must_use]
    pub fn peer_count(&self) -> usize {
        self.peers.read().len()
    }

    /// Get the configuration
    #[must_use]
    pub fn config(&self) -> &WgIngressConfig {
        &self.config
    }

    /// Get a reference to the processor
    #[must_use]
    pub fn processor(&self) -> &Arc<IngressProcessor> {
        &self.processor
    }

    /// Get the listen address
    #[must_use]
    pub fn listen_addr(&self) -> SocketAddr {
        self.config.listen_addr
    }

    /// Check if a public key is registered as a peer
    #[must_use]
    pub fn has_peer(&self, public_key: &str) -> bool {
        self.peers.read().contains_key(public_key)
    }

    /// Phase 11-Fix.AA: List all registered peers
    ///
    /// Returns information about all peers registered with the ingress.
    #[must_use]
    pub fn list_peers(&self) -> Vec<IngressPeerListItem> {
        let peers = self.peers.read();
        peers
            .iter()
            .map(|(public_key, p)| IngressPeerListItem {
                public_key: public_key.clone(),
                allowed_ips: p.config.allowed_ips.iter().map(|ip| ip.to_string()).collect::<Vec<_>>().join(","),
                name: None, // Name is stored in database, not in WireGuard config
                rx_bytes: p.rx_bytes.load(Ordering::Relaxed),
                tx_bytes: p.tx_bytes.load(Ordering::Relaxed),
                last_handshake: {
                    let ts = p.last_handshake.load(Ordering::Relaxed);
                    if ts > 0 { Some(ts) } else { None }
                },
            })
            .collect()
    }

    /// Get list of registered peer public keys
    #[must_use]
    pub fn peer_keys(&self) -> Vec<String> {
        self.peers.read().keys().cloned().collect()
    }

    /// Take the packet receiver (for testing/integration)
    ///
    /// This can only be called once; subsequent calls return None.
    pub async fn take_packet_receiver(&self) -> Option<mpsc::Receiver<ProcessedPacket>> {
        self.packet_rx.lock().await.take()
    }

    /// Background packet processing loop
    ///
    /// This loop:
    /// 1. Receives encrypted WireGuard packets from the socket
    /// 2. Identifies the peer by trying decryption with each registered peer's tunnel
    /// 3. Validates the source IP against the peer's allowed_ips (AFTER decryption)
    /// 4. Processes the decrypted packet through the rule engine
    /// 5. Sends handshake responses back to the client if needed
    ///
    /// # Phase 6.8: Batch I/O
    ///
    /// On Linux, when `use_batch_io` is enabled, uses `recvmmsg` to receive
    /// multiple packets per syscall for improved throughput.
    async fn packet_loop(
        socket: Arc<UdpSocket>,
        processor: Arc<IngressProcessor>,
        stats: Arc<StatsInner>,
        config: WgIngressConfig,
        peers: HashMap<String, Arc<RegisteredPeer>>,
        packet_tx: mpsc::Sender<ProcessedPacket>,
        shutdown_rx: oneshot::Receiver<()>,
    ) {
        // Phase 6.8: Use batch I/O on Linux when enabled
        #[cfg(target_os = "linux")]
        {
            if config.use_batch_io {
                Self::packet_loop_batch(
                    socket,
                    processor,
                    stats,
                    config,
                    peers,
                    packet_tx,
                    shutdown_rx,
                )
                .await;
                return;
            }
        }

        // Fallback: single-packet I/O
        Self::packet_loop_single(
            socket,
            processor,
            stats,
            config,
            peers,
            packet_tx,
            shutdown_rx,
        )
        .await;
    }

    /// Single-packet I/O loop (fallback for non-Linux or when batch I/O is disabled)
    async fn packet_loop_single(
        socket: Arc<UdpSocket>,
        processor: Arc<IngressProcessor>,
        stats: Arc<StatsInner>,
        config: WgIngressConfig,
        peers: HashMap<String, Arc<RegisteredPeer>>,
        packet_tx: mpsc::Sender<ProcessedPacket>,
        mut shutdown_rx: oneshot::Receiver<()>,
    ) {
        let mut recv_buf = vec![0u8; UDP_RECV_BUFFER_SIZE];
        let mut decrypt_buf = vec![0u8; UDP_RECV_BUFFER_SIZE + WG_TRANSPORT_OVERHEAD];

        loop {
            tokio::select! {
                biased;

                _ = &mut shutdown_rx => {
                    debug!("Received shutdown signal");
                    break;
                }

                result = socket.recv_from(&mut recv_buf) => {
                    match result {
                        Ok((len, src_addr)) => {
                            Self::process_single_packet(
                                &recv_buf[..len],
                                src_addr,
                                &socket,
                                &processor,
                                &stats,
                                &config,
                                &peers,
                                &packet_tx,
                                &mut decrypt_buf,
                            ).await;
                        }
                        Err(e) => {
                            warn!(error = %e, "Failed to receive packet");
                        }
                    }
                }
            }
        }

        debug!("Packet loop (single) exited");
    }

    /// Batch I/O loop using recvmmsg (Linux only)
    #[cfg(target_os = "linux")]
    async fn packet_loop_batch(
        socket: Arc<UdpSocket>,
        processor: Arc<IngressProcessor>,
        stats: Arc<StatsInner>,
        config: WgIngressConfig,
        peers: HashMap<String, Arc<RegisteredPeer>>,
        packet_tx: mpsc::Sender<ProcessedPacket>,
        mut shutdown_rx: oneshot::Receiver<()>,
    ) {
        use std::os::unix::io::AsRawFd;

        let batch_size = config.batch_size.min(256);
        let batch_config = BatchConfig::new(batch_size)
            .with_buffer_size(UDP_RECV_BUFFER_SIZE)
            .non_blocking();

        let fd = socket.as_raw_fd();
        let mut batch_receiver = BatchReceiver::new(fd, batch_config);
        let mut decrypt_buf = vec![0u8; UDP_RECV_BUFFER_SIZE + WG_TRANSPORT_OVERHEAD];

        info!(
            batch_size = batch_size,
            "Using batch I/O for ingress receive loop"
        );

        loop {
            // Wait for socket to be readable
            tokio::select! {
                biased;

                _ = &mut shutdown_rx => {
                    debug!("Received shutdown signal");
                    break;
                }

                result = socket.readable() => {
                    if let Err(e) = result {
                        warn!(error = %e, "Socket readable check failed");
                        continue;
                    }

                    // Try to receive a batch of packets
                    match batch_receiver.recv_batch() {
                        Ok(packets) => {
                            for received in packets {
                                Self::process_single_packet(
                                    &received.data[..received.len],
                                    received.src_addr,
                                    &socket,
                                    &processor,
                                    &stats,
                                    &config,
                                    &peers,
                                    &packet_tx,
                                    &mut decrypt_buf,
                                ).await;
                            }
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            // No packets available, continue waiting
                            continue;
                        }
                        Err(e) => {
                            warn!(error = %e, "Batch receive failed");
                        }
                    }
                }
            }
        }

        debug!(
            "Packet loop (batch) exited, stats: batches={}, packets={}",
            batch_receiver.stats().batch_operations,
            batch_receiver.stats().packets_processed
        );
    }

    /// Process a single received packet
    ///
    /// This helper is used by both single-packet and batch I/O loops.
    #[allow(clippy::too_many_arguments)]
    async fn process_single_packet(
        encrypted_data: &[u8],
        src_addr: SocketAddr,
        socket: &Arc<UdpSocket>,
        processor: &Arc<IngressProcessor>,
        stats: &Arc<StatsInner>,
        config: &WgIngressConfig,
        peers: &HashMap<String, Arc<RegisteredPeer>>,
        packet_tx: &mpsc::Sender<ProcessedPacket>,
        decrypt_buf: &mut [u8],
    ) {
        // Update stats for received bytes (encrypted)
        stats.rx_bytes.fetch_add(encrypted_data.len() as u64, Ordering::Relaxed);
        stats.rx_packets.fetch_add(1, Ordering::Relaxed);

        // Try to identify peer and decrypt packet
        // WireGuard uses the receiver's public key index to identify
        // which peer sent the packet, but boringtun handles this internally
        let (decrypted_data, peer_public_key, peer_ref) =
            match Self::identify_and_decrypt(peers, encrypted_data, decrypt_buf, stats) {
                Some(result) => result,
                None => {
                    trace!(src_addr = %src_addr, "Failed to decrypt packet from any peer");
                    stats.invalid_packets.fetch_add(1, Ordering::Relaxed);
                    return;
                }
            };

        // Handle handshake responses
        if let Some(response) = decrypted_data.response {
            if let Err(e) = socket.send_to(&response, src_addr).await {
                warn!(error = %e, "Failed to send handshake response");
            } else {
                trace!(src_addr = %src_addr, "Sent handshake response");
                stats.handshake_count.fetch_add(1, Ordering::Relaxed);
                peer_ref.update_handshake();
                peer_ref.is_connected.store(true, Ordering::Relaxed);
            }
        }

        // If this was just a handshake packet, no data to process
        if decrypted_data.needs_response && decrypted_data.data.is_empty() {
            return;
        }

        // Validate source IP AFTER decryption against peer's allowed_ips
        // This is critical for security - we validate the inner packet's source
        if let Some(inner_src_ip) = Self::extract_source_ip(&decrypted_data.data) {
            // First check against peer's allowed_ips
            if !peer_ref.is_source_ip_allowed(inner_src_ip) {
                trace!(
                    src_ip = %inner_src_ip,
                    peer = %peer_public_key,
                    "Inner packet source IP not in peer's allowed_ips"
                );
                stats.invalid_packets.fetch_add(1, Ordering::Relaxed);
                return;
            }

            // Also check against global allowed subnet
            if !config.is_ip_allowed(inner_src_ip) {
                trace!(
                    src_ip = %inner_src_ip,
                    subnet = %config.allowed_subnet,
                    "Inner packet source IP not in allowed subnet"
                );
                stats.invalid_packets.fetch_add(1, Ordering::Relaxed);
                return;
            }
        } else if !decrypted_data.data.is_empty() {
            // Could not extract source IP from decrypted packet
            trace!("Could not extract source IP from decrypted packet");
            stats.invalid_packets.fetch_add(1, Ordering::Relaxed);
            return;
        }

        // Update peer activity
        peer_ref.update_activity();
        peer_ref.rx_bytes.fetch_add(decrypted_data.data.len() as u64, Ordering::Relaxed);

        // Process decrypted packet through rule engine
        match processor.process(&decrypted_data.data, &peer_public_key) {
            Ok(routing) => {
                let processed = ProcessedPacket {
                    data: decrypted_data.data,
                    routing,
                    peer_public_key,
                    src_addr,
                };

                if packet_tx.send(processed).await.is_err() {
                    debug!("Packet channel closed");
                    stats.dropped_packets.fetch_add(1, Ordering::Relaxed);
                }
            }
            Err(e) => {
                trace!(error = %e, "Failed to process packet");
                stats.invalid_packets.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Identify the peer that sent a packet and decrypt it
    ///
    /// WireGuard packets contain a receiver index that identifies the session,
    /// but we need to try decryption with each peer's tunnel since boringtun
    /// doesn't expose the receiver index directly.
    ///
    /// Returns None if no peer could decrypt the packet.
    fn identify_and_decrypt<'a>(
        peers: &'a HashMap<String, Arc<RegisteredPeer>>,
        encrypted: &[u8],
        dst: &mut [u8],
        stats: &StatsInner,
    ) -> Option<(DecryptedPacket, String, &'a Arc<RegisteredPeer>)> {
        // Try to decrypt with each peer's tunnel
        // In a real implementation with many peers, we'd use the receiver index
        // to look up the peer directly, but boringtun handles sessions internally
        for (public_key, peer) in peers.iter() {
            if let Some(decrypted) = peer.decrypt(encrypted, dst) {
                return Some((decrypted, public_key.clone(), peer));
            }
        }

        // If no registered peer could decrypt, increment stats
        stats.invalid_packets.fetch_add(1, Ordering::Relaxed);
        None
    }

    /// Extract source IP from packet (IPv4 or IPv6)
    fn extract_source_ip(packet: &[u8]) -> Option<IpAddr> {
        if packet.is_empty() {
            return None;
        }

        let version = packet[0] >> 4;

        match version {
            4 if packet.len() >= 20 => {
                let ip = std::net::Ipv4Addr::new(
                    packet[12],
                    packet[13],
                    packet[14],
                    packet[15],
                );
                Some(IpAddr::V4(ip))
            }
            6 if packet.len() >= 40 => {
                let ip = std::net::Ipv6Addr::from([
                    packet[8],
                    packet[9],
                    packet[10],
                    packet[11],
                    packet[12],
                    packet[13],
                    packet[14],
                    packet[15],
                    packet[16],
                    packet[17],
                    packet[18],
                    packet[19],
                    packet[20],
                    packet[21],
                    packet[22],
                    packet[23],
                ]);
                Some(IpAddr::V6(ip))
            }
            _ => None,
        }
    }
}

impl std::fmt::Debug for WgIngressManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WgIngressManager")
            .field("listen_addr", &self.config.listen_addr)
            .field("local_ip", &self.config.local_ip)
            .field("state", &*self.state.read())
            .field("peer_count", &self.peers.read().len())
            .finish()
    }
}

impl Drop for WgIngressManager {
    fn drop(&mut self) {
        // Send shutdown signal if still running
        if let Some(tx) = self.shutdown_tx.write().take() {
            let _ = tx.send(());
        }
    }
}

/// Configure socket buffer sizes
///
/// Sets the SO_RCVBUF and SO_SNDBUF socket options.
///
/// # Arguments
///
/// * `socket` - UDP socket to configure
/// * `recv_buf` - Receive buffer size in bytes
/// * `send_buf` - Send buffer size in bytes
///
/// Note: The actual buffer size may be doubled by the kernel (Linux)
/// and may be capped by system limits.
fn configure_socket_buffers(socket: &UdpSocket, recv_buf: usize, send_buf: usize) -> std::io::Result<()> {
    use std::os::unix::io::AsRawFd;

    let fd = socket.as_raw_fd();

    // Set receive buffer size
    let recv_buf_i32 = recv_buf as libc::c_int;
    // SAFETY: This is safe because:
    // 1. `fd` is a valid file descriptor from `socket.as_raw_fd()`
    // 2. `SOL_SOCKET` is a valid socket level constant
    // 3. `SO_RCVBUF` is a valid socket option
    // 4. `&recv_buf_i32` is a valid pointer to stack-allocated value
    // 5. `size_of::<c_int>()` is the correct size
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
    // SAFETY: Same as above for SO_RCVBUF
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::engine::RoutingSnapshotBuilder;

    // Valid 32-byte key (Base64 encoded)
    const TEST_VALID_KEY: &str = "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=";

    fn create_test_config() -> WgIngressConfig {
        WgIngressConfig::builder()
            .private_key(TEST_VALID_KEY)
            .listen_addr("127.0.0.1:0".parse().unwrap()) // Use port 0 for auto-assign
            .local_ip("10.25.0.1".parse().unwrap())
            .allowed_subnet("10.25.0.0/24".parse().unwrap())
            .build()
    }

    fn create_test_engine() -> Arc<RuleEngine> {
        let snapshot = RoutingSnapshotBuilder::new()
            .default_outbound("direct")
            .version(1)
            .build()
            .unwrap();
        Arc::new(RuleEngine::new(snapshot))
    }

    // ========================================================================
    // WgIngressStats Tests
    // ========================================================================

    #[test]
    fn test_stats_default() {
        let stats = WgIngressStats::default();
        assert_eq!(stats.rx_bytes, 0);
        assert_eq!(stats.tx_bytes, 0);
        assert_eq!(stats.peer_count, 0);
    }

    #[test]
    fn test_stats_serialization() {
        let stats = WgIngressStats {
            rx_bytes: 1000,
            tx_bytes: 500,
            rx_packets: 10,
            tx_packets: 5,
            invalid_packets: 1,
            handshake_count: 3,
            peer_count: 2,
            active_peer_count: 1,
            dropped_packets: 0,
        };

        let json = serde_json::to_string(&stats).expect("Should serialize");
        let deserialized: WgIngressStats = serde_json::from_str(&json).expect("Should deserialize");

        assert_eq!(deserialized.rx_bytes, stats.rx_bytes);
        assert_eq!(deserialized.peer_count, stats.peer_count);
    }

    // ========================================================================
    // IngressState Tests
    // ========================================================================

    #[test]
    fn test_state_display() {
        assert_eq!(IngressState::Created.to_string(), "created");
        assert_eq!(IngressState::Running.to_string(), "running");
        assert_eq!(IngressState::Stopped.to_string(), "stopped");
    }

    // ========================================================================
    // WgIngressManager Creation Tests
    // ========================================================================

    #[test]
    fn test_manager_new() {
        let config = create_test_config();
        let engine = create_test_engine();
        let manager = WgIngressManager::new(config, engine);

        assert!(manager.is_ok());
        let manager = manager.unwrap();
        assert_eq!(manager.state(), IngressState::Created);
        assert_eq!(manager.peer_count(), 0);
    }

    #[test]
    fn test_manager_new_invalid_config() {
        let config = WgIngressConfig::builder()
            .listen_addr("127.0.0.1:36100".parse().unwrap())
            .local_ip("10.25.0.1".parse().unwrap())
            .allowed_subnet("10.25.0.0/24".parse().unwrap())
            .build(); // Missing private key

        let engine = create_test_engine();
        let result = WgIngressManager::new(config, engine);
        assert!(result.is_err());
    }

    #[test]
    fn test_manager_debug() {
        let config = create_test_config();
        let engine = create_test_engine();
        let manager = WgIngressManager::new(config, engine).unwrap();

        let debug = format!("{:?}", manager);
        assert!(debug.contains("WgIngressManager"));
        assert!(debug.contains("listen_addr"));
    }

    // ========================================================================
    // Peer Management Tests
    // ========================================================================

    #[tokio::test]
    async fn test_add_peer() {
        let config = create_test_config();
        let engine = create_test_engine();
        let manager = WgIngressManager::new(config, engine).unwrap();

        let peer = WgIngressPeerConfig::new(TEST_VALID_KEY, "10.25.0.2");
        let result = manager.add_peer(peer).await;

        assert!(result.is_ok());
        assert_eq!(manager.peer_count(), 1);
        assert!(manager.has_peer(TEST_VALID_KEY));
    }

    #[tokio::test]
    async fn test_add_peer_duplicate() {
        let config = create_test_config();
        let engine = create_test_engine();
        let manager = WgIngressManager::new(config, engine).unwrap();

        let peer = WgIngressPeerConfig::new(TEST_VALID_KEY, "10.25.0.2");
        manager.add_peer(peer.clone()).await.unwrap();

        // Try to add again
        let result = manager.add_peer(peer).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("already exists"));
    }

    #[tokio::test]
    async fn test_add_peer_invalid() {
        let config = create_test_config();
        let engine = create_test_engine();
        let manager = WgIngressManager::new(config, engine).unwrap();

        let peer = WgIngressPeerConfig::new("", "10.25.0.2"); // Empty key
        let result = manager.add_peer(peer).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_remove_peer() {
        let config = create_test_config();
        let engine = create_test_engine();
        let manager = WgIngressManager::new(config, engine).unwrap();

        let peer = WgIngressPeerConfig::new(TEST_VALID_KEY, "10.25.0.2");
        manager.add_peer(peer).await.unwrap();
        assert_eq!(manager.peer_count(), 1);

        let result = manager.remove_peer(TEST_VALID_KEY).await;
        assert!(result.is_ok());
        assert_eq!(manager.peer_count(), 0);
        assert!(!manager.has_peer(TEST_VALID_KEY));
    }

    #[tokio::test]
    async fn test_remove_peer_not_found() {
        let config = create_test_config();
        let engine = create_test_engine();
        let manager = WgIngressManager::new(config, engine).unwrap();

        let result = manager.remove_peer("nonexistent").await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));
    }

    #[tokio::test]
    async fn test_peer_keys() {
        let config = create_test_config();
        let engine = create_test_engine();
        let manager = WgIngressManager::new(config, engine).unwrap();

        // Different 32-byte keys
        let key1 = "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=";
        let key2 = "MTIzNDU2YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo=";

        manager
            .add_peer(WgIngressPeerConfig::new(key1, "10.25.0.2"))
            .await
            .unwrap();
        manager
            .add_peer(WgIngressPeerConfig::new(key2, "10.25.0.3"))
            .await
            .unwrap();

        let keys = manager.peer_keys();
        assert_eq!(keys.len(), 2);
        assert!(keys.contains(&key1.to_string()));
        assert!(keys.contains(&key2.to_string()));
    }

    // ========================================================================
    // Start/Stop Tests
    // ========================================================================

    #[tokio::test]
    async fn test_start_stop() {
        let config = create_test_config();
        let engine = create_test_engine();
        let manager = WgIngressManager::new(config, engine).unwrap();

        assert_eq!(manager.state(), IngressState::Created);
        assert!(!manager.is_running());

        // Start
        manager.start().await.unwrap();
        assert_eq!(manager.state(), IngressState::Running);
        assert!(manager.is_running());

        // Stop
        manager.stop().await.unwrap();
        assert_eq!(manager.state(), IngressState::Stopped);
        assert!(!manager.is_running());
    }

    #[tokio::test]
    async fn test_start_already_started() {
        let config = create_test_config();
        let engine = create_test_engine();
        let manager = WgIngressManager::new(config, engine).unwrap();

        manager.start().await.unwrap();

        let result = manager.start().await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            IngressError::AlreadyStarted
        ));

        manager.stop().await.unwrap();
    }

    #[tokio::test]
    async fn test_stop_not_started() {
        let config = create_test_config();
        let engine = create_test_engine();
        let manager = WgIngressManager::new(config, engine).unwrap();

        let result = manager.stop().await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), IngressError::NotStarted));
    }

    #[tokio::test]
    async fn test_restart() {
        let config = create_test_config();
        let engine = create_test_engine();
        let manager = WgIngressManager::new(config, engine).unwrap();

        // Start
        manager.start().await.unwrap();
        assert!(manager.is_running());

        // Stop
        manager.stop().await.unwrap();
        assert!(!manager.is_running());

        // Restart
        manager.start().await.unwrap();
        assert!(manager.is_running());

        // Clean up
        manager.stop().await.unwrap();
    }

    // ========================================================================
    // Statistics Tests
    // ========================================================================

    #[tokio::test]
    async fn test_stats_initial() {
        let config = create_test_config();
        let engine = create_test_engine();
        let manager = WgIngressManager::new(config, engine).unwrap();

        let stats = manager.stats();
        assert_eq!(stats.rx_bytes, 0);
        assert_eq!(stats.peer_count, 0);
    }

    #[tokio::test]
    async fn test_stats_with_peers() {
        let config = create_test_config();
        let engine = create_test_engine();
        let manager = WgIngressManager::new(config, engine).unwrap();

        manager
            .add_peer(WgIngressPeerConfig::new(TEST_VALID_KEY, "10.25.0.2"))
            .await
            .unwrap();

        let stats = manager.stats();
        assert_eq!(stats.peer_count, 1);
    }

    // ========================================================================
    // Config and Processor Access Tests
    // ========================================================================

    #[test]
    fn test_config_access() {
        let config = create_test_config();
        let engine = create_test_engine();
        let manager = WgIngressManager::new(config.clone(), engine).unwrap();

        assert_eq!(manager.config().local_ip, config.local_ip);
        assert_eq!(manager.listen_addr(), config.listen_addr);
    }

    #[test]
    fn test_processor_access() {
        let config = create_test_config();
        let engine = create_test_engine();
        let manager = WgIngressManager::new(config, engine).unwrap();

        let processor = manager.processor();
        assert_eq!(processor.rule_engine().version(), 1);
    }

    // ========================================================================
    // Extract Source IP Tests
    // ========================================================================

    #[test]
    fn test_extract_source_ip_ipv4() {
        let packet = vec![
            0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00,
            0x40, 0x06, 0x00, 0x00, 0x0a, 0x19, 0x00, 0x02, // Source: 10.25.0.2
            0x08, 0x08, 0x08, 0x08, // Dest: 8.8.8.8
        ];

        let ip = WgIngressManager::extract_source_ip(&packet);
        assert_eq!(ip, Some("10.25.0.2".parse().unwrap()));
    }

    #[test]
    fn test_extract_source_ip_ipv6() {
        let mut packet = vec![
            0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3a, 0x40,
        ];
        // Source IPv6
        packet.extend_from_slice(&[
            0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        ]);
        // Dest IPv6
        packet.extend_from_slice(&[
            0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0x88,
        ]);

        let ip = WgIngressManager::extract_source_ip(&packet);
        assert_eq!(ip, Some("fd00::2".parse().unwrap()));
    }

    #[test]
    fn test_extract_source_ip_empty() {
        let ip = WgIngressManager::extract_source_ip(&[]);
        assert!(ip.is_none());
    }

    #[test]
    fn test_extract_source_ip_too_short() {
        let packet = vec![0x45, 0x00]; // Only 2 bytes
        let ip = WgIngressManager::extract_source_ip(&packet);
        assert!(ip.is_none());
    }

    #[test]
    fn test_extract_source_ip_invalid_version() {
        let mut packet = vec![0x75, 0x00]; // Version 7
        packet.extend_from_slice(&[0x00; 18]); // Pad to 20 bytes
        let ip = WgIngressManager::extract_source_ip(&packet);
        assert!(ip.is_none());
    }

    // ========================================================================
    // Processed Packet Tests
    // ========================================================================

    #[test]
    fn test_processed_packet_clone() {
        let processed = ProcessedPacket {
            data: vec![1, 2, 3],
            routing: RoutingDecision::default_route("test"),
            peer_public_key: "key".to_string(),
            src_addr: "127.0.0.1:1234".parse().unwrap(),
        };

        let cloned = processed.clone();
        assert_eq!(cloned.data, processed.data);
        assert_eq!(cloned.peer_public_key, processed.peer_public_key);
    }

    #[test]
    fn test_processed_packet_debug() {
        let processed = ProcessedPacket {
            data: vec![1, 2, 3],
            routing: RoutingDecision::default_route("test"),
            peer_public_key: "key".to_string(),
            src_addr: "127.0.0.1:1234".parse().unwrap(),
        };

        let debug = format!("{:?}", processed);
        assert!(debug.contains("ProcessedPacket"));
    }

    // ========================================================================
    // Packet Receiver Tests
    // ========================================================================

    #[tokio::test]
    async fn test_take_packet_receiver() {
        let config = create_test_config();
        let engine = create_test_engine();
        let manager = WgIngressManager::new(config, engine).unwrap();

        manager.start().await.unwrap();

        // First take succeeds
        let rx1 = manager.take_packet_receiver().await;
        assert!(rx1.is_some());

        // Second take returns None
        let rx2 = manager.take_packet_receiver().await;
        assert!(rx2.is_none());

        manager.stop().await.unwrap();
    }

    // ========================================================================
    // StatsInner Tests
    // ========================================================================

    #[test]
    fn test_stats_inner_snapshot() {
        let stats = StatsInner::default();
        stats.rx_bytes.store(100, Ordering::Relaxed);
        stats.rx_packets.store(5, Ordering::Relaxed);

        let snapshot = stats.snapshot(3, 2);
        assert_eq!(snapshot.rx_bytes, 100);
        assert_eq!(snapshot.rx_packets, 5);
        assert_eq!(snapshot.peer_count, 3);
        assert_eq!(snapshot.active_peer_count, 2);
    }

    // ========================================================================
    // Key Decoding Tests
    // ========================================================================

    #[test]
    fn test_decode_private_key_valid() {
        let result = decode_private_key(TEST_VALID_KEY);
        assert!(result.is_ok());
    }

    #[test]
    fn test_decode_private_key_invalid_base64() {
        let result = decode_private_key("not-valid-base64!!!");
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(err.contains("Invalid Base64"));
    }

    #[test]
    fn test_decode_private_key_wrong_length() {
        // Valid Base64 but wrong length (16 bytes instead of 32)
        let result = decode_private_key("YWJjZGVmZ2hpamtsbW5v");
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(err.contains("32 bytes"));
    }

    #[test]
    fn test_decode_public_key_valid() {
        let result = decode_public_key(TEST_VALID_KEY);
        assert!(result.is_ok());
    }

    #[test]
    fn test_decode_public_key_invalid_base64() {
        let result = decode_public_key(";;;invalid;;;");
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_psk_valid() {
        let result = decode_psk(TEST_VALID_KEY);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 32);
    }

    #[test]
    fn test_decode_psk_wrong_length() {
        // Too short
        let result = decode_psk("YWJj");
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(err.contains("32 bytes"));
    }

    // ========================================================================
    // Socket Buffer Tests
    // ========================================================================

    #[tokio::test]
    async fn test_manager_with_socket_buffers() {
        let config = create_test_config();
        let engine = create_test_engine();

        let manager = WgIngressManager::with_socket_buffers(
            config,
            engine,
            1024 * 1024, // 1MB
            512 * 1024,  // 512KB
        );

        assert!(manager.is_ok());
        let manager = manager.unwrap();
        assert_eq!(manager.socket_recv_buffer, 1024 * 1024);
        assert_eq!(manager.socket_send_buffer, 512 * 1024);
    }

    #[test]
    fn test_default_socket_buffer_constants() {
        assert!(DEFAULT_SO_RCVBUF >= 64 * 1024); // At least 64KB
        assert!(DEFAULT_SO_SNDBUF >= 64 * 1024);
    }

    // ========================================================================
    // DSCP Integration Tests (Phase 6.3)
    // ========================================================================

    #[test]
    fn test_dscp_chain_mark_range() {
        use crate::rules::fwmark::ChainMark;

        // Valid DSCP values (1-63)
        for dscp in 1..=63 {
            let mark = ChainMark::from_dscp(dscp);
            assert!(mark.is_some(), "DSCP {} should be valid", dscp);
            let mark = mark.unwrap();
            assert_eq!(mark.dscp_value, dscp);
        }

        // Invalid DSCP value 0
        let mark = ChainMark::from_dscp(0);
        assert!(mark.is_none());
    }

    #[test]
    fn test_dscp_extraction_ipv4() {
        use crate::chain::dscp::{get_dscp, set_dscp};

        // Create IPv4 packet with DSCP
        let mut packet = vec![
            0x45, 0x00, // Version=4, IHL=5, TOS=0
            0x00, 0x14, // Total Length
            0x00, 0x00, 0x00, 0x00, // ID, Flags, Fragment
            0x40, 0x06, // TTL=64, Protocol=TCP
            0x00, 0x00, // Checksum
            10, 25, 0, 2, // Source IP
            8, 8, 8, 8, // Dest IP
        ];

        // Initially DSCP should be 0
        assert_eq!(get_dscp(&packet).unwrap(), 0);

        // Set DSCP to 42
        set_dscp(&mut packet, 42).unwrap();
        assert_eq!(get_dscp(&packet).unwrap(), 42);

        // Set DSCP to max (63)
        set_dscp(&mut packet, 63).unwrap();
        assert_eq!(get_dscp(&packet).unwrap(), 63);
    }

    #[test]
    fn test_dscp_extraction_ipv6() {
        use crate::chain::dscp::{get_dscp, set_dscp};

        // Create IPv6 packet
        let mut packet = vec![
            0x60, 0x00, // Version=6, Traffic Class=0, Flow Label
            0x00, 0x00, // Flow Label continued
            0x00, 0x14, // Payload Length
            0x06, 0x40, // Next Header=TCP, Hop Limit=64
        ];
        // Source IPv6 (16 bytes)
        packet.extend_from_slice(&[0xfd, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        // Dest IPv6 (16 bytes)
        packet.extend_from_slice(&[0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0x88]);

        // Initially DSCP should be 0
        assert_eq!(get_dscp(&packet).unwrap(), 0);

        // Set DSCP to 15
        set_dscp(&mut packet, 15).unwrap();
        assert_eq!(get_dscp(&packet).unwrap(), 15);
    }

    #[test]
    fn test_dscp_checksum_recalculation_ipv4() {
        use crate::chain::dscp::set_dscp;

        // Create IPv4 packet with proper checksum
        let mut packet = vec![
            0x45, 0x00, // Version=4, IHL=5, TOS=0
            0x00, 0x14, // Total Length = 20
            0x00, 0x00, 0x40, 0x00, // ID, Flags, Fragment
            0x40, 0x06, // TTL=64, Protocol=TCP
            0xb4, 0x53, // Checksum (calculated)
            10, 25, 0, 2, // Source IP: 10.25.0.2
            8, 8, 8, 8, // Dest IP: 8.8.8.8
        ];

        let original_checksum = u16::from_be_bytes([packet[10], packet[11]]);

        // Modify DSCP - should recalculate checksum
        set_dscp(&mut packet, 42).unwrap();

        let new_checksum = u16::from_be_bytes([packet[10], packet[11]]);

        // Checksum should be different after DSCP change
        assert_ne!(original_checksum, new_checksum, "Checksum should be recalculated after DSCP change");
    }

    #[test]
    fn test_dscp_preserves_ecn() {
        use crate::chain::dscp::{get_dscp, set_dscp};

        // Create packet with ECN bits set (ECT(1) = 0b01)
        let mut packet = vec![
            0x45, 0x01, // Version=4, IHL=5, TOS=0x01 (ECN=01)
            0x00, 0x14, // Total Length
            0x00, 0x00, 0x00, 0x00,
            0x40, 0x06,
            0x00, 0x00,
            10, 25, 0, 2,
            8, 8, 8, 8,
        ];

        // Set DSCP to 20 - should preserve ECN bits
        set_dscp(&mut packet, 20).unwrap();

        // DSCP should be 20
        assert_eq!(get_dscp(&packet).unwrap(), 20);

        // ECN bits (bottom 2 bits of TOS) should still be 01
        assert_eq!(packet[1] & 0x03, 0x01);
    }

    #[test]
    fn test_dscp_invalid_value() {
        use crate::chain::dscp::set_dscp;

        let mut packet = vec![
            0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00,
            0x40, 0x06, 0x00, 0x00, 10, 25, 0, 2, 8, 8, 8, 8,
        ];

        // DSCP value 64 is out of range (max is 63)
        let result = set_dscp(&mut packet, 64);
        assert!(result.is_err());
    }

    #[test]
    fn test_dscp_empty_packet() {
        use crate::chain::dscp::get_dscp;

        let result = get_dscp(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_dscp_packet_too_short() {
        use crate::chain::dscp::get_dscp;

        // Only 10 bytes - not enough for IPv4 header
        let packet = vec![0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x40, 0x06];
        let result = get_dscp(&packet);
        assert!(result.is_err());
    }

    #[test]
    fn test_dscp_invalid_ip_version() {
        use crate::chain::dscp::get_dscp;

        // Version 7 (invalid)
        let mut packet = vec![0x75, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x40, 0x06];
        packet.extend_from_slice(&[0x00; 10]); // Pad to 20 bytes
        let result = get_dscp(&packet);
        assert!(result.is_err());
    }

    // ========================================================================
    // Rule Matching Tests (Phase 6.3)
    // ========================================================================

    #[test]
    fn test_rule_matching_ip_cidr() {
        use crate::rules::RuleType;

        let mut builder = RoutingSnapshotBuilder::new();
        builder.add_geoip_rule(RuleType::IpCidr, "192.168.0.0/16", "private").unwrap();
        builder.add_geoip_rule(RuleType::IpCidr, "10.0.0.0/8", "vpn").unwrap();
        let snapshot = builder.default_outbound("direct").build().unwrap();
        let engine = Arc::new(RuleEngine::new(snapshot));
        let processor = IngressProcessor::new(engine);

        // Create packets to different destinations
        let src_ip: std::net::Ipv4Addr = "10.25.0.2".parse().unwrap();
        let private_dst: std::net::Ipv4Addr = "192.168.1.100".parse().unwrap();
        let vpn_dst: std::net::Ipv4Addr = "10.1.2.3".parse().unwrap();
        let public_dst: std::net::Ipv4Addr = "8.8.8.8".parse().unwrap();

        // Test private network match
        let mut packet = vec![
            0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00,
        ];
        packet.extend_from_slice(&src_ip.octets());
        packet.extend_from_slice(&private_dst.octets());
        packet.extend_from_slice(&[0x12, 0x34, 0x01, 0xbb, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00]);

        let decision = processor.process(&packet, "test").unwrap();
        assert_eq!(decision.outbound, "private");

        // Test VPN network match
        packet[16..20].copy_from_slice(&vpn_dst.octets());
        let decision = processor.process(&packet, "test").unwrap();
        assert_eq!(decision.outbound, "vpn");

        // Test public (no match -> default)
        packet[16..20].copy_from_slice(&public_dst.octets());
        let decision = processor.process(&packet, "test").unwrap();
        assert_eq!(decision.outbound, "direct");
    }

    #[test]
    fn test_rule_matching_port_ranges() {
        let mut builder = RoutingSnapshotBuilder::new();
        builder.add_port_rule("80", "http").unwrap();
        builder.add_port_rule("443", "https").unwrap();
        builder.add_port_rule("22", "ssh").unwrap();
        let snapshot = builder.default_outbound("direct").build().unwrap();
        let engine = Arc::new(RuleEngine::new(snapshot));
        let processor = IngressProcessor::new(engine);

        let src_ip: std::net::Ipv4Addr = "10.25.0.2".parse().unwrap();
        let dst_ip: std::net::Ipv4Addr = "8.8.8.8".parse().unwrap();

        let mut base_packet = vec![
            0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00,
        ];
        base_packet.extend_from_slice(&src_ip.octets());
        base_packet.extend_from_slice(&dst_ip.octets());

        // Test port 80
        base_packet.extend_from_slice(&[0x12, 0x34, 0x00, 0x50]); // src=4660, dst=80
        base_packet.extend_from_slice(&[0x00; 16]); // TCP header padding
        let decision = processor.process(&base_packet, "test").unwrap();
        assert_eq!(decision.outbound, "http");

        // Test port 443
        base_packet[22] = 0x01; base_packet[23] = 0xbb; // port 443
        let decision = processor.process(&base_packet, "test").unwrap();
        assert_eq!(decision.outbound, "https");

        // Test port 22
        base_packet[22] = 0x00; base_packet[23] = 0x16; // port 22
        let decision = processor.process(&base_packet, "test").unwrap();
        assert_eq!(decision.outbound, "ssh");

        // Test unmatched port -> default
        base_packet[22] = 0x1f; base_packet[23] = 0x90; // port 8080
        let decision = processor.process(&base_packet, "test").unwrap();
        assert_eq!(decision.outbound, "direct");
    }

    #[test]
    fn test_rule_priority_cidr_over_default() {
        use crate::rules::RuleType;

        let mut builder = RoutingSnapshotBuilder::new();
        builder.add_geoip_rule(RuleType::IpCidr, "8.8.0.0/16", "google").unwrap();
        let snapshot = builder.default_outbound("fallback").build().unwrap();
        let engine = Arc::new(RuleEngine::new(snapshot));
        let processor = IngressProcessor::new(engine);

        let src_ip: std::net::Ipv4Addr = "10.25.0.2".parse().unwrap();
        let google_dst: std::net::Ipv4Addr = "8.8.8.8".parse().unwrap();
        let other_dst: std::net::Ipv4Addr = "1.1.1.1".parse().unwrap();

        let mut packet = vec![
            0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00,
        ];
        packet.extend_from_slice(&src_ip.octets());
        packet.extend_from_slice(&google_dst.octets());
        packet.extend_from_slice(&[0x12, 0x34, 0x01, 0xbb, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00]);

        // Should match CIDR rule
        let decision = processor.process(&packet, "test").unwrap();
        assert_eq!(decision.outbound, "google");

        // Should fall back to default
        packet[16..20].copy_from_slice(&other_dst.octets());
        let decision = processor.process(&packet, "test").unwrap();
        assert_eq!(decision.outbound, "fallback");
    }

    #[test]
    fn test_rule_matching_protocol_udp() {
        let mut builder = RoutingSnapshotBuilder::new();
        builder.add_port_rule("53", "dns").unwrap();
        let snapshot = builder.default_outbound("direct").build().unwrap();
        let engine = Arc::new(RuleEngine::new(snapshot));
        let processor = IngressProcessor::new(engine);

        let src_ip: std::net::Ipv4Addr = "10.25.0.2".parse().unwrap();
        let dst_ip: std::net::Ipv4Addr = "1.1.1.1".parse().unwrap();

        // UDP packet to port 53
        let mut packet = vec![
            0x45, 0x00, 0x00, 0x1C, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, // UDP protocol
        ];
        packet.extend_from_slice(&src_ip.octets());
        packet.extend_from_slice(&dst_ip.octets());
        packet.extend_from_slice(&[0x12, 0x34, 0x00, 0x35, 0x00, 0x08, 0x00, 0x00]); // src, dst=53, len, checksum

        let decision = processor.process(&packet, "test").unwrap();
        assert_eq!(decision.outbound, "dns");
    }

    #[test]
    fn test_multiple_rules_first_match_wins() {
        use crate::rules::RuleType;

        // Create rules where order matters
        let mut builder = RoutingSnapshotBuilder::new();
        builder.add_geoip_rule(RuleType::IpCidr, "8.8.8.8/32", "specific").unwrap();
        builder.add_geoip_rule(RuleType::IpCidr, "8.8.0.0/16", "general").unwrap();
        let snapshot = builder.default_outbound("direct").build().unwrap();
        let engine = Arc::new(RuleEngine::new(snapshot));
        let processor = IngressProcessor::new(engine);

        let src_ip: std::net::Ipv4Addr = "10.25.0.2".parse().unwrap();
        let specific_dst: std::net::Ipv4Addr = "8.8.8.8".parse().unwrap();
        let general_dst: std::net::Ipv4Addr = "8.8.4.4".parse().unwrap();

        let mut packet = vec![
            0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00,
        ];
        packet.extend_from_slice(&src_ip.octets());
        packet.extend_from_slice(&specific_dst.octets());
        packet.extend_from_slice(&[0x12, 0x34, 0x01, 0xbb, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00]);

        // Exact match wins
        let decision = processor.process(&packet, "test").unwrap();
        assert_eq!(decision.outbound, "specific");

        // General match
        packet[16..20].copy_from_slice(&general_dst.octets());
        let decision = processor.process(&packet, "test").unwrap();
        assert_eq!(decision.outbound, "general");
    }

    // ========================================================================
    // RegisteredPeer Source IP Validation Tests
    // ========================================================================

    #[test]
    fn test_source_ip_allowed_empty_list() {
        // Test that empty allowed_ips allows all traffic
        let config = WgIngressPeerConfig {
            public_key: TEST_VALID_KEY.to_string(),
            allowed_ips: vec![],
            persistent_keepalive: None,
            preshared_key: None,
        };

        let private_key = decode_private_key(TEST_VALID_KEY).unwrap();
        let peer = RegisteredPeer::new(config, &private_key, 1).unwrap();

        // Should allow any IP when list is empty
        assert!(peer.is_source_ip_allowed("10.25.0.2".parse().unwrap()));
        assert!(peer.is_source_ip_allowed("192.168.1.1".parse().unwrap()));
    }

    #[test]
    fn test_source_ip_allowed_single_ip() {
        let config = WgIngressPeerConfig {
            public_key: TEST_VALID_KEY.to_string(),
            allowed_ips: vec!["10.25.0.2/32".parse().unwrap()],
            persistent_keepalive: None,
            preshared_key: None,
        };

        let private_key = decode_private_key(TEST_VALID_KEY).unwrap();
        let peer = RegisteredPeer::new(config, &private_key, 1).unwrap();

        // Should allow exact IP
        assert!(peer.is_source_ip_allowed("10.25.0.2".parse().unwrap()));
        // Should reject other IPs
        assert!(!peer.is_source_ip_allowed("10.25.0.3".parse().unwrap()));
        assert!(!peer.is_source_ip_allowed("192.168.1.1".parse().unwrap()));
    }

    #[test]
    fn test_source_ip_allowed_subnet() {
        let config = WgIngressPeerConfig {
            public_key: TEST_VALID_KEY.to_string(),
            allowed_ips: vec!["10.25.0.0/24".parse().unwrap()],
            persistent_keepalive: None,
            preshared_key: None,
        };

        let private_key = decode_private_key(TEST_VALID_KEY).unwrap();
        let peer = RegisteredPeer::new(config, &private_key, 1).unwrap();

        // Should allow IPs in subnet
        assert!(peer.is_source_ip_allowed("10.25.0.1".parse().unwrap()));
        assert!(peer.is_source_ip_allowed("10.25.0.254".parse().unwrap()));
        // Should reject IPs outside subnet
        assert!(!peer.is_source_ip_allowed("10.25.1.1".parse().unwrap()));
        assert!(!peer.is_source_ip_allowed("192.168.1.1".parse().unwrap()));
    }
}
