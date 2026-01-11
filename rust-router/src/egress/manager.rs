//! `WireGuard` Egress Manager for Phase 6.4
//!
//! This module provides the main `WgEgressManager` struct that manages
//! multiple `WireGuard` egress tunnels, including creation, removal, and
//! packet sending.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                       WgEgressManager                            │
//! ├─────────────────────────────────────────────────────────────────┤
//! │  Tunnel Registry (RwLock<HashMap>):                              │
//! │  ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐    │
//! │  │ pia-us-west     │ │ custom-my-vpn   │ │ peer-node-1     │    │
//! │  │ (ManagedTunnel) │ │ (ManagedTunnel) │ │ (ManagedTunnel) │    │
//! │  └─────────────────┘ └─────────────────┘ └─────────────────┘    │
//! │           │                   │                   │              │
//! │           └───────────────────┴───────────────────┘              │
//! │                               │                                  │
//! │  ┌────────────────────────────▼─────────────────────────────┐   │
//! │  │                   WgReplyHandler                          │   │
//! │  │  (shared callback for all tunnels)                        │   │
//! │  └───────────────────────────────────────────────────────────┘   │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Lock Ordering
//!
//! When acquiring locks in `WgEgressManager`, follow this order:
//! 1. `shutdown` (`AtomicBool`) - Check first, no lock needed
//! 2. `tunnels` (`RwLock`) - Registry lock
//! 3. Per-tunnel locks (see `UserspaceWgTunnel` lock ordering)
//!
//! # Example
//!
//! ```ignore
//! use rust_router::egress::{WgEgressManager, WgEgressConfig, EgressTunnelType, WgReplyHandler};
//! use std::sync::Arc;
//!
//! // Create reply handler
//! let reply_handler = Arc::new(WgReplyHandler::new(|packet, tag| {
//!     println!("Reply from {}: {} bytes", tag, packet.len());
//! }));
//!
//! // Create manager
//! let manager = WgEgressManager::new(reply_handler);
//!
//! // Create tunnel
//! let config = WgEgressConfig::new(
//!     "pia-us-west",
//!     EgressTunnelType::Pia { region: "us-west".to_string() },
//!     private_key,
//!     peer_public_key,
//!     "1.2.3.4:51820",
//! );
//! manager.create_tunnel(config).await?;
//!
//! // Send packet
//! manager.send("pia-us-west", packet).await?;
//!
//! // Remove tunnel
//! manager.remove_tunnel("pia-us-west", None).await?;
//! ```

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tracing::{debug, error, info, trace, warn};

use super::config::{EgressState, EgressTunnelType, WgEgressConfig};
use super::error::{EgressError, EgressResult};
use super::reply::WgReplyHandler;
use crate::tunnel::config::WgTunnelConfig;
use crate::tunnel::traits::{WgTunnel, WgTunnelError, WgTunnelStats};
use crate::tunnel::userspace::UserspaceWgTunnel;

// Phase 6.8: Batch I/O imports (Linux only)
#[cfg(target_os = "linux")]
use crate::io::BatchSender;

/// Default drain timeout when removing tunnels
pub const DEFAULT_DRAIN_TIMEOUT_SECS: u64 = 5;

/// Status of an egress tunnel
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EgressTunnelStatus {
    /// Tunnel tag
    pub tag: String,
    /// Tunnel type
    pub tunnel_type: EgressTunnelType,
    /// Tunnel state
    pub state: EgressState,
    /// Whether the tunnel is connected
    pub connected: bool,
    /// Whether the tunnel is healthy
    pub healthy: bool,
    /// Tunnel statistics
    pub stats: WgTunnelStats,
    /// Local tunnel IP (if configured)
    pub local_ip: Option<String>,
    /// Peer endpoint
    pub peer_endpoint: String,
}

/// Statistics for the egress manager
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WgEgressStats {
    /// Number of tunnels currently registered
    pub tunnel_count: usize,
    /// Number of connected tunnels
    pub connected_count: usize,
    /// Total bytes transmitted across all tunnels
    pub total_tx_bytes: u64,
    /// Total bytes received across all tunnels
    pub total_rx_bytes: u64,
    /// Total packets transmitted
    pub total_tx_packets: u64,
    /// Total packets received
    pub total_rx_packets: u64,
    /// Number of send errors
    pub send_errors: u64,
    /// Number of tunnels created since startup
    pub tunnels_created: u64,
    /// Number of tunnels removed since startup
    pub tunnels_removed: u64,
}

/// Internal tunnel wrapper with metadata
struct ManagedTunnel {
    /// The underlying `WireGuard` tunnel
    tunnel: Arc<UserspaceWgTunnel>,
    /// Tunnel configuration
    config: WgEgressConfig,
    /// Tunnel state (atomic for lock-free access)
    state: parking_lot::Mutex<EgressState>,
    /// Shutdown signal sender for reply receiver task
    reply_shutdown_tx: Option<oneshot::Sender<()>>,
    /// Reply receiver task handle
    reply_task: Option<JoinHandle<()>>,
}

impl ManagedTunnel {
    fn new(tunnel: UserspaceWgTunnel, config: WgEgressConfig) -> Self {
        Self {
            tunnel: Arc::new(tunnel),
            config,
            state: parking_lot::Mutex::new(EgressState::Created),
            reply_shutdown_tx: None,
            reply_task: None,
        }
    }

    fn is_draining(&self) -> bool {
        let state = self.state.lock();
        state.is_draining()
    }

    fn set_draining(&self, draining: bool) {
        if draining {
            *self.state.lock() = EgressState::Draining;
        }
    }

    fn get_state(&self) -> EgressState {
        *self.state.lock()
    }

    fn set_state(&self, new_state: EgressState) {
        *self.state.lock() = new_state;
    }
}

/// Manager for `WireGuard` egress tunnels
///
/// Provides centralized management of multiple egress tunnels with
/// concurrent send operations and automatic reply handling.
///
/// # Thread Safety
///
/// `WgEgressManager` is `Send + Sync` and designed to be shared across
/// async tasks. The internal tunnel registry is protected by `RwLock`.
pub struct WgEgressManager {
    /// Tunnel registry (tag -> managed tunnel)
    tunnels: RwLock<HashMap<String, ManagedTunnel>>,
    /// Reply handler for decrypted packets
    reply_handler: Arc<WgReplyHandler>,
    /// Shutdown flag
    shutdown: AtomicBool,
    /// Statistics
    stats: EgressManagerStats,
}

/// Internal statistics tracking
#[derive(Default)]
struct EgressManagerStats {
    /// Total packets sent across all tunnels
    packets_sent: Arc<AtomicU64>,
    /// Total bytes sent across all tunnels
    bytes_sent: Arc<AtomicU64>,
    /// Number of send errors
    send_errors: Arc<AtomicU64>,
    /// Number of tunnels created since startup
    tunnels_created: AtomicU64,
    /// Number of tunnels removed since startup
    tunnels_removed: AtomicU64,
}

/// Helper struct for sending stats to spawned tasks in `send_nowait`
struct EgressSendStats {
    packets_sent: Arc<AtomicU64>,
    bytes_sent: Arc<AtomicU64>,
    send_errors: Arc<AtomicU64>,
}

impl WgEgressManager {
    /// Create a new egress manager
    ///
    /// # Arguments
    ///
    /// * `reply_handler` - Handler for decrypted reply packets
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::egress::{WgEgressManager, WgReplyHandler};
    /// use std::sync::Arc;
    ///
    /// let reply_handler = Arc::new(WgReplyHandler::noop());
    /// let manager = WgEgressManager::new(reply_handler);
    ///
    /// assert_eq!(manager.tunnel_count(), 0);
    /// ```
    #[must_use]
    pub fn new(reply_handler: Arc<WgReplyHandler>) -> Self {
        Self {
            tunnels: RwLock::new(HashMap::new()),
            reply_handler,
            shutdown: AtomicBool::new(false),
            stats: EgressManagerStats::default(),
        }
    }

    /// Create a new egress tunnel
    ///
    /// Creates and connects a `WireGuard` tunnel with the given configuration.
    /// Spawns a background task to receive and handle reply packets.
    ///
    /// # Arguments
    ///
    /// * `config` - Tunnel configuration
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The manager is shutting down
    /// - A tunnel with the same tag already exists
    /// - The configuration is invalid
    /// - Failed to connect the tunnel
    ///
    /// # Example
    ///
    /// ```ignore
    /// let config = WgEgressConfig::new(
    ///     "my-tunnel",
    ///     EgressTunnelType::Custom { name: "vpn".to_string() },
    ///     private_key,
    ///     peer_public_key,
    ///     "1.2.3.4:51820",
    /// );
    ///
    /// manager.create_tunnel(config).await?;
    /// ```
    pub async fn create_tunnel(&self, config: WgEgressConfig) -> EgressResult<()> {
        // Check shutdown state
        if self.shutdown.load(Ordering::Acquire) {
            return Err(EgressError::ShuttingDown);
        }

        // Validate configuration
        config.validate()?;

        let tag = config.tag.clone();

        // Check if tunnel already exists (read lock)
        {
            let tunnels = self.tunnels.read();
            if tunnels.contains_key(&tag) {
                return Err(EgressError::tunnel_already_exists(&tag));
            }
        }

        info!(
            "Creating egress tunnel '{}' ({})",
            tag,
            config.tunnel_type.display_name()
        );

        // Convert to WgTunnelConfig
        let tunnel_config = WgTunnelConfig {
            private_key: config.private_key.clone(),
            peer_public_key: config.peer_public_key.clone(),
            peer_endpoint: config.peer_endpoint.clone(),
            local_ip: config.local_ip.clone(),
            allowed_ips: config.allowed_ips.clone(),
            listen_port: None, // Let the system choose
            persistent_keepalive: config.persistent_keepalive,
            mtu: config.mtu,
        };

        // Create the tunnel
        let tunnel = UserspaceWgTunnel::with_tag(tunnel_config, Some(tag.clone()))
            .map_err(EgressError::TunnelError)?;

        // Connect the tunnel
        tunnel
            .connect()
            .await
            .map_err(EgressError::TunnelError)?;

        // Create managed tunnel
        let mut managed = ManagedTunnel::new(tunnel, config);
        managed.set_state(EgressState::Connecting);

        // Spawn the reply receiver task
        let (shutdown_tx, reply_task) = Self::spawn_reply_receiver(
            tag.clone(),
            managed.tunnel.clone(),
            self.reply_handler.clone(),
        );
        managed.reply_shutdown_tx = Some(shutdown_tx);
        managed.reply_task = Some(reply_task);

        // Update state to Running
        managed.set_state(EgressState::Running);

        // Insert into registry (write lock)
        // Use Option to track whether we inserted or hit a race condition
        let race_managed: Option<ManagedTunnel> = {
            let mut tunnels = self.tunnels.write();
            // Double-check (race condition)
            if tunnels.contains_key(&tag) {
                Some(managed) // Return managed for cleanup
            } else {
                tunnels.insert(tag.clone(), managed);
                None // Successfully inserted
            }
        };
        // Lock is released before any async operations

        // Handle race condition cleanup outside the lock
        if let Some(mut managed) = race_managed {
            warn!("Race condition: tunnel '{}' already exists", tag);
            // Send shutdown signal to reply task
            if let Some(tx) = managed.reply_shutdown_tx.take() {
                let _ = tx.send(());
            }
            if let Some(handle) = managed.reply_task.take() {
                handle.abort();
            }
            // Fire-and-forget disconnect (now outside the lock)
            let _ = managed.tunnel.disconnect().await;
            return Err(EgressError::tunnel_already_exists(&tag));
        }

        // Update stats
        self.stats.tunnels_created.fetch_add(1, Ordering::Relaxed);

        info!("Created egress tunnel '{}'", tag);

        Ok(())
    }

    /// Spawn a background task to receive reply packets from the tunnel
    ///
    /// This task continuously receives decrypted packets from the `WireGuard` tunnel
    /// and forwards them to the reply handler for processing.
    ///
    /// # Arguments
    ///
    /// * `tag` - Tunnel tag for logging and identification
    /// * `tunnel` - Arc-wrapped tunnel instance
    /// * `reply_handler` - Handler for decrypted reply packets
    ///
    /// # Returns
    ///
    /// A tuple of (`shutdown_sender`, `task_handle`) for controlling the task.
    fn spawn_reply_receiver(
        tag: String,
        tunnel: Arc<UserspaceWgTunnel>,
        reply_handler: Arc<WgReplyHandler>,
    ) -> (oneshot::Sender<()>, JoinHandle<()>) {
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();

        let tag_clone = tag.clone();
        let handle = tokio::spawn(async move {
            debug!("Reply receiver started for tunnel '{}'", tag_clone);

            loop {
                tokio::select! {
                    biased;

                    // Check for shutdown signal first (biased)
                    _ = &mut shutdown_rx => {
                        debug!("Reply receiver shutdown signal received for tunnel '{}'", tag_clone);
                        break;
                    }

                    // Receive packets from the tunnel
                    result = tunnel.recv() => {
                        match result {
                            Ok(packet) => {
                                trace!(
                                    "Reply receiver got {} bytes from tunnel '{}'",
                                    packet.len(),
                                    tag_clone
                                );
                                reply_handler.handle_reply(packet, tag_clone.clone());
                            }
                            Err(e) => {
                                // Check if this is a shutdown error (expected during disconnect)
                                if matches!(e, WgTunnelError::ShuttingDown | WgTunnelError::NotConnected) {
                                    debug!(
                                        "Reply receiver stopping for tunnel '{}': {}",
                                        tag_clone, e
                                    );
                                } else {
                                    error!(
                                        "Error receiving from tunnel '{}': {}",
                                        tag_clone, e
                                    );
                                }
                                break;
                            }
                        }
                    }
                }
            }

            debug!("Reply receiver stopped for tunnel '{}'", tag_clone);
        });

        (shutdown_tx, handle)
    }

    /// Remove an egress tunnel
    ///
    /// Gracefully shuts down the tunnel, optionally waiting for in-flight
    /// operations to complete (drain timeout).
    ///
    /// # Arguments
    ///
    /// * `tag` - Tag of the tunnel to remove
    /// * `drain_timeout` - Optional timeout to wait for in-flight operations
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The tunnel is not found
    /// - The drain timeout expires (returns `DrainTimeout`)
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Remove immediately
    /// manager.remove_tunnel("my-tunnel", None).await?;
    ///
    /// // Remove with drain timeout
    /// manager.remove_tunnel("my-tunnel", Some(Duration::from_secs(5))).await?;
    /// ```
    pub async fn remove_tunnel(
        &self,
        tag: &str,
        drain_timeout: Option<Duration>,
    ) -> EgressResult<()> {
        info!("Removing egress tunnel '{}'", tag);

        // Mark as draining
        {
            let tunnels = self.tunnels.read();
            if let Some(managed) = tunnels.get(tag) {
                managed.set_draining(true);
            } else {
                return Err(EgressError::tunnel_not_found(tag));
            }
        }

        // Wait for drain timeout if specified
        if let Some(timeout) = drain_timeout {
            debug!("Draining tunnel '{}' for {:?}", tag, timeout);
            tokio::time::sleep(timeout).await;
        }

        // Remove from registry (write lock)
        let managed = {
            let mut tunnels = self.tunnels.write();
            tunnels.remove(tag)
        };

        let Some(mut managed) = managed else {
            return Err(EgressError::tunnel_not_found(tag));
        };

        // Send shutdown signal to reply receiver
        if let Some(tx) = managed.reply_shutdown_tx.take() {
            let _ = tx.send(());
        }

        // Abort reply task
        if let Some(handle) = managed.reply_task.take() {
            handle.abort();
            let _ = handle.await;
        }

        // Disconnect the tunnel
        if let Err(e) = managed.tunnel.disconnect().await {
            warn!("Error disconnecting tunnel '{}': {}", tag, e);
            // Continue anyway
        }

        // Update stats
        self.stats.tunnels_removed.fetch_add(1, Ordering::Relaxed);

        info!("Removed egress tunnel '{}'", tag);

        Ok(())
    }

    /// Get the status of a tunnel
    ///
    /// # Arguments
    ///
    /// * `tag` - Tag of the tunnel
    ///
    /// # Returns
    ///
    /// `Some(EgressTunnelStatus)` if the tunnel exists, `None` otherwise.
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::egress::{WgEgressManager, WgReplyHandler};
    /// use std::sync::Arc;
    ///
    /// let manager = WgEgressManager::new(Arc::new(WgReplyHandler::noop()));
    /// assert!(manager.get_tunnel_status("nonexistent").is_none());
    /// ```
    #[must_use]
    pub fn get_tunnel_status(&self, tag: &str) -> Option<EgressTunnelStatus> {
        let tunnels = self.tunnels.read();
        tunnels.get(tag).map(|managed| EgressTunnelStatus {
            tag: tag.to_string(),
            tunnel_type: managed.config.tunnel_type.clone(),
            state: managed.get_state(),
            connected: managed.tunnel.is_connected(),
            healthy: managed.tunnel.is_healthy(),
            stats: managed.tunnel.stats(),
            local_ip: managed.tunnel.local_ip(),
            peer_endpoint: managed.config.peer_endpoint.clone(),
        })
    }

    /// List all tunnel tags
    ///
    /// # Returns
    ///
    /// A vector of all registered tunnel tags.
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::egress::{WgEgressManager, WgReplyHandler};
    /// use std::sync::Arc;
    ///
    /// let manager = WgEgressManager::new(Arc::new(WgReplyHandler::noop()));
    /// assert!(manager.list_tunnels().is_empty());
    /// ```
    #[must_use]
    pub fn list_tunnels(&self) -> Vec<String> {
        let tunnels = self.tunnels.read();
        tunnels.keys().cloned().collect()
    }

    /// Get the number of registered tunnels
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::egress::{WgEgressManager, WgReplyHandler};
    /// use std::sync::Arc;
    ///
    /// let manager = WgEgressManager::new(Arc::new(WgReplyHandler::noop()));
    /// assert_eq!(manager.tunnel_count(), 0);
    /// ```
    #[must_use]
    pub fn tunnel_count(&self) -> usize {
        let tunnels = self.tunnels.read();
        tunnels.len()
    }

    /// Check if a tunnel exists
    ///
    /// # Arguments
    ///
    /// * `tag` - Tag of the tunnel
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::egress::{WgEgressManager, WgReplyHandler};
    /// use std::sync::Arc;
    ///
    /// let manager = WgEgressManager::new(Arc::new(WgReplyHandler::noop()));
    /// assert!(!manager.has_tunnel("test"));
    /// ```
    #[must_use]
    pub fn has_tunnel(&self, tag: &str) -> bool {
        let tunnels = self.tunnels.read();
        tunnels.contains_key(tag)
    }

    /// Send a packet through an egress tunnel
    ///
    /// The packet will be encrypted using `WireGuard` and sent to the peer.
    ///
    /// # Arguments
    ///
    /// * `tag` - Tag of the tunnel to use
    /// * `packet` - Plaintext IP packet to send
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The manager is shutting down
    /// - The tunnel is not found
    /// - The tunnel is draining
    /// - The send operation fails
    ///
    /// # Example
    ///
    /// ```ignore
    /// manager.send("my-tunnel", packet).await?;
    /// ```
    pub async fn send(&self, tag: &str, packet: Vec<u8>) -> EgressResult<()> {
        // Check shutdown state
        if self.shutdown.load(Ordering::Acquire) {
            return Err(EgressError::ShuttingDown);
        }

        trace!("Sending {} bytes through tunnel '{}'", packet.len(), tag);

        // Get tunnel Arc (release lock quickly before async operation)
        let tunnel = {
            let tunnels = self.tunnels.read();
            match tunnels.get(tag) {
                Some(managed) => {
                    if managed.is_draining() {
                        return Err(EgressError::send_failed(format!(
                            "Tunnel '{tag}' is draining, no new traffic allowed"
                        )));
                    }
                    managed.tunnel.clone()
                }
                None => return Err(EgressError::tunnel_not_found(tag)),
            }
        };
        // Lock is now released

        // Send packet (without holding lock)
        match tunnel.send(&packet).await {
            Ok(()) => {
                self.stats.packets_sent.fetch_add(1, Ordering::Relaxed);
                self.stats
                    .bytes_sent
                    .fetch_add(packet.len() as u64, Ordering::Relaxed);
                Ok(())
            }
            Err(e) => {
                self.stats.send_errors.fetch_add(1, Ordering::Relaxed);
                Err(EgressError::send_failed(format!(
                    "Failed to send packet through tunnel '{tag}': {e}"
                )))
            }
        }
    }

    /// Send a packet through an egress tunnel without waiting
    ///
    /// This is a fire-and-forget version of `send` that spawns a task
    /// to handle the send operation.
    ///
    /// # Arguments
    ///
    /// * `tag` - Tag of the tunnel to use
    /// * `packet` - Plaintext IP packet to send
    ///
    /// # Note
    ///
    /// Errors are logged but not returned. Use `send` if you need error handling.
    pub fn send_nowait(&self, tag: &str, packet: Vec<u8>) {
        // Check shutdown state
        if self.shutdown.load(Ordering::Acquire) {
            debug!("Dropping packet: manager is shutting down");
            return;
        }

        // Get the tunnel Arc if it exists and is not draining
        let tunnel = {
            let tunnels = self.tunnels.read();
            match tunnels.get(tag) {
                Some(managed) if !managed.is_draining() => Some(managed.tunnel.clone()),
                Some(_) => {
                    debug!("Dropping packet: tunnel '{}' is draining", tag);
                    self.stats.send_errors.fetch_add(1, Ordering::Relaxed);
                    None
                }
                None => {
                    debug!("Dropping packet: tunnel '{}' not found", tag);
                    self.stats.send_errors.fetch_add(1, Ordering::Relaxed);
                    None
                }
            }
        };

        // Spawn a task to perform the actual send if we have a valid tunnel
        if let Some(tunnel) = tunnel {
            let tag_owned = tag.to_string();
            let packet_len = packet.len();
            let stats = EgressSendStats {
                packets_sent: self.stats.packets_sent.clone(),
                bytes_sent: self.stats.bytes_sent.clone(),
                send_errors: self.stats.send_errors.clone(),
            };

            tokio::spawn(async move {
                match tunnel.send(&packet).await {
                    Ok(()) => {
                        stats.packets_sent.fetch_add(1, Ordering::Relaxed);
                        stats.bytes_sent.fetch_add(packet_len as u64, Ordering::Relaxed);
                        trace!(
                            "send_nowait: sent {} bytes through tunnel '{}'",
                            packet_len,
                            tag_owned
                        );
                    }
                    Err(e) => {
                        stats.send_errors.fetch_add(1, Ordering::Relaxed);
                        warn!("send_nowait: failed to send through tunnel '{}': {}", tag_owned, e);
                    }
                }
            });
        }
    }

    /// Get manager statistics
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::egress::{WgEgressManager, WgReplyHandler};
    /// use std::sync::Arc;
    ///
    /// let manager = WgEgressManager::new(Arc::new(WgReplyHandler::noop()));
    /// let stats = manager.stats();
    ///
    /// assert_eq!(stats.tunnel_count, 0);
    /// assert_eq!(stats.tunnels_created, 0);
    /// ```
    #[must_use]
    pub fn stats(&self) -> WgEgressStats {
        let tunnels = self.tunnels.read();

        let mut tx_bytes_total = 0u64;
        let mut rx_bytes_total = 0u64;
        let mut tx_packets_total = 0u64;
        let mut rx_packets_total = 0u64;
        let mut connected_count = 0usize;

        for managed in tunnels.values() {
            let tunnel_stats = managed.tunnel.stats();
            tx_bytes_total += tunnel_stats.tx_bytes;
            rx_bytes_total += tunnel_stats.rx_bytes;
            tx_packets_total += tunnel_stats.tx_packets;
            rx_packets_total += tunnel_stats.rx_packets;
            if managed.tunnel.is_connected() {
                connected_count += 1;
            }
        }

        WgEgressStats {
            tunnel_count: tunnels.len(),
            connected_count,
            total_tx_bytes: tx_bytes_total,
            total_rx_bytes: rx_bytes_total,
            total_tx_packets: tx_packets_total,
            total_rx_packets: rx_packets_total,
            send_errors: self.stats.send_errors.load(Ordering::Relaxed),
            tunnels_created: self.stats.tunnels_created.load(Ordering::Relaxed),
            tunnels_removed: self.stats.tunnels_removed.load(Ordering::Relaxed),
        }
    }

    /// Get the reply handler
    ///
    /// # Returns
    ///
    /// A clone of the Arc-wrapped reply handler.
    #[must_use]
    pub fn reply_handler(&self) -> Arc<WgReplyHandler> {
        self.reply_handler.clone()
    }

    /// Check if the manager is shutting down
    #[must_use]
    pub fn is_shutting_down(&self) -> bool {
        self.shutdown.load(Ordering::Acquire)
    }

    /// Shutdown all tunnels gracefully
    ///
    /// This method:
    /// 1. Sets the shutdown flag to prevent new operations
    /// 2. Disconnects all tunnels
    /// 3. Cleans up all resources
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::egress::{WgEgressManager, WgReplyHandler};
    /// use std::sync::Arc;
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let manager = WgEgressManager::new(Arc::new(WgReplyHandler::noop()));
    ///     manager.shutdown().await;
    ///     assert!(manager.is_shutting_down());
    /// }
    /// ```
    pub async fn shutdown(&self) {
        info!("Shutting down egress manager");

        // Set shutdown flag
        self.shutdown.store(true, Ordering::Release);

        // Get all tunnel tags
        let tags: Vec<String> = {
            let tunnels = self.tunnels.read();
            tunnels.keys().cloned().collect()
        };

        // Remove all tunnels
        for tag in tags {
            if let Err(e) = self.remove_tunnel(&tag, None).await {
                warn!("Error removing tunnel '{}' during shutdown: {}", tag, e);
            }
        }

        info!("Egress manager shutdown complete");
    }

    /// Get all tunnel statuses
    ///
    /// # Returns
    ///
    /// A vector of status for all registered tunnels.
    #[must_use]
    pub fn all_tunnel_statuses(&self) -> Vec<EgressTunnelStatus> {
        let tunnels = self.tunnels.read();
        tunnels
            .iter()
            .map(|(tag, managed)| EgressTunnelStatus {
                tag: tag.clone(),
                tunnel_type: managed.config.tunnel_type.clone(),
                state: managed.get_state(),
                connected: managed.tunnel.is_connected(),
                healthy: managed.tunnel.is_healthy(),
                stats: managed.tunnel.stats(),
                local_ip: managed.tunnel.local_ip(),
                peer_endpoint: managed.config.peer_endpoint.clone(),
            })
            .collect()
    }

    /// Get tunnels by type
    ///
    /// # Arguments
    ///
    /// * `tunnel_type_filter` - The type to filter by
    ///
    /// # Returns
    ///
    /// A vector of tags for tunnels matching the specified type.
    #[must_use]
    pub fn get_tunnels_by_type(&self, tunnel_type_filter: &str) -> Vec<String> {
        let tunnels = self.tunnels.read();
        tunnels
            .iter()
            .filter(|(_, managed)| managed.config.tunnel_type.short_name() == tunnel_type_filter)
            .map(|(tag, _)| tag.clone())
            .collect()
    }

    /// Send multiple packets through an egress tunnel using batch I/O (Linux only)
    ///
    /// On Linux, this uses `sendmmsg` to send multiple packets in a single syscall,
    /// providing significant throughput improvement over individual sends.
    ///
    /// On non-Linux platforms, falls back to sequential sends.
    ///
    /// # Arguments
    ///
    /// * `tag` - Tag of the tunnel to use
    /// * `packets` - Vector of plaintext IP packets to send
    ///
    /// # Returns
    ///
    /// Number of packets successfully sent.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The manager is shutting down
    /// - The tunnel is not found
    /// - The tunnel is draining
    ///
    /// # Example
    ///
    /// ```ignore
    /// let packets = vec![
    ///     vec![/* packet 1 data */],
    ///     vec![/* packet 2 data */],
    /// ];
    /// let sent = manager.send_batch("my-tunnel", packets).await?;
    /// println!("Sent {} packets", sent);
    /// ```
    pub async fn send_batch(&self, tag: &str, packets: Vec<Vec<u8>>) -> EgressResult<usize> {
        // Check shutdown state
        if self.shutdown.load(Ordering::Acquire) {
            return Err(EgressError::ShuttingDown);
        }

        if packets.is_empty() {
            return Ok(0);
        }

        trace!(
            "Sending batch of {} packets through tunnel '{}'",
            packets.len(),
            tag
        );

        // Get tunnel Arc (release lock quickly before async operation)
        let (tunnel, use_batch_io, batch_size, peer_public_key) = {
            let tunnels = self.tunnels.read();
            match tunnels.get(tag) {
                Some(managed) => {
                    if managed.is_draining() {
                        return Err(EgressError::send_failed(format!(
                            "Tunnel '{tag}' is draining, no new traffic allowed"
                        )));
                    }
                    (
                        managed.tunnel.clone(),
                        managed.config.use_batch_io,
                        managed.config.batch_size,
                        managed.config.peer_public_key.clone(),
                    )
                }
                None => return Err(EgressError::tunnel_not_found(tag)),
            }
        };
        // Lock is now released

        // Phase 6.8: Use batch I/O on Linux when enabled
        #[cfg(target_os = "linux")]
        {
            if use_batch_io {
                return self
                    .send_batch_linux(tag, packets, tunnel, batch_size, &peer_public_key)
                    .await;
            }
        }

        // Fallback: sequential sends
        let _ = (use_batch_io, batch_size, peer_public_key); // Suppress unused warning on non-Linux
        self.send_batch_sequential(tag, packets, tunnel).await
    }

    /// Sequential batch send (fallback for non-Linux or when batch I/O is disabled)
    async fn send_batch_sequential(
        &self,
        tag: &str,
        packets: Vec<Vec<u8>>,
        tunnel: Arc<UserspaceWgTunnel>,
    ) -> EgressResult<usize> {
        let mut sent_count = 0;

        for packet in packets {
            match tunnel.send(&packet).await {
                Ok(()) => {
                    self.stats.packets_sent.fetch_add(1, Ordering::Relaxed);
                    self.stats
                        .bytes_sent
                        .fetch_add(packet.len() as u64, Ordering::Relaxed);
                    sent_count += 1;
                }
                Err(e) => {
                    self.stats.send_errors.fetch_add(1, Ordering::Relaxed);
                    warn!(
                        "send_batch: failed to send packet {} through tunnel '{}': {}",
                        sent_count, tag, e
                    );
                    // Continue trying to send remaining packets
                }
            }
        }

        Ok(sent_count)
    }

    /// Batch send using sendmmsg (Linux only)
    ///
    /// Encrypts packets via the `WireGuard` tunnel and sends them in batches
    /// using the sendmmsg syscall for improved throughput.
    #[cfg(target_os = "linux")]
    async fn send_batch_linux(
        &self,
        tag: &str,
        packets: Vec<Vec<u8>>,
        tunnel: Arc<UserspaceWgTunnel>,
        batch_size: usize,
        peer_public_key: &str,
    ) -> EgressResult<usize> {
        use crate::tunnel::traits::WgTunnel;
        use std::os::unix::io::AsRawFd;

        // Get the socket file descriptor from the tunnel
        let socket = tunnel
            .socket()
            .ok_or_else(|| EgressError::send_failed("Tunnel socket not available"))?;

        // Get the peer endpoint
        let peer_endpoint: SocketAddr = tunnel
            .peer_endpoint()
            .ok_or_else(|| EgressError::send_failed("Tunnel peer endpoint not available"))?;

        let fd = socket.as_raw_fd();
        let mut batch_sender = BatchSender::new(fd);

        let mut sent_count = 0;
        let mut total_bytes = 0u64;

        // Process packets in batches
        for chunk in packets.chunks(batch_size) {
            // Encrypt all packets in this batch
            let mut encrypted_batch: Vec<(Vec<u8>, SocketAddr)> = Vec::with_capacity(chunk.len());

            for packet in chunk {
                match tunnel.encrypt(packet, peer_public_key) {
                    Ok(encrypted) => {
                        total_bytes += encrypted.len() as u64;
                        encrypted_batch.push((encrypted, peer_endpoint));
                    }
                    Err(e) => {
                        self.stats.send_errors.fetch_add(1, Ordering::Relaxed);
                        warn!(
                            "send_batch_linux: failed to encrypt packet for tunnel '{}': {}",
                            tag, e
                        );
                        // Continue with other packets
                    }
                }
            }

            if encrypted_batch.is_empty() {
                continue;
            }

            // Convert to the format expected by BatchSender
            let send_data: Vec<(&[u8], SocketAddr)> = encrypted_batch
                .iter()
                .map(|(data, addr)| (data.as_slice(), *addr))
                .collect();

            // Send the batch
            match batch_sender.send_batch(&send_data) {
                Ok(count) => {
                    sent_count += count;
                    self.stats
                        .packets_sent
                        .fetch_add(count as u64, Ordering::Relaxed);
                    trace!(
                        "send_batch_linux: sent {}/{} packets through tunnel '{}'",
                        count,
                        send_data.len(),
                        tag
                    );
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // Socket buffer full, try again later
                    warn!(
                        "send_batch_linux: socket buffer full for tunnel '{}', {} packets dropped",
                        tag,
                        send_data.len()
                    );
                    self.stats
                        .send_errors
                        .fetch_add(send_data.len() as u64, Ordering::Relaxed);
                }
                Err(e) => {
                    self.stats
                        .send_errors
                        .fetch_add(send_data.len() as u64, Ordering::Relaxed);
                    warn!(
                        "send_batch_linux: sendmmsg failed for tunnel '{}': {}",
                        tag, e
                    );
                }
            }
        }

        self.stats.bytes_sent.fetch_add(total_bytes, Ordering::Relaxed);

        debug!(
            "send_batch_linux: sent {} packets ({} bytes) through tunnel '{}', batch stats: ops={}, avg_per_batch={:.1}",
            sent_count,
            total_bytes,
            tag,
            batch_sender.stats().batch_operations,
            batch_sender.stats().avg_packets_per_batch()
        );

        Ok(sent_count)
    }
}

impl std::fmt::Debug for WgEgressManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WgEgressManager")
            .field("tunnel_count", &self.tunnel_count())
            .field("shutting_down", &self.is_shutting_down())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Valid 32-byte key (Base64 encoded)
    const TEST_VALID_KEY: &str = "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=";

    fn create_test_config(tag: &str) -> WgEgressConfig {
        WgEgressConfig::new(
            tag,
            EgressTunnelType::Custom {
                name: "test".to_string(),
            },
            TEST_VALID_KEY,
            TEST_VALID_KEY,
            "1.2.3.4:51820",
        )
    }

    // ========================================================================
    // WgEgressManager Creation Tests
    // ========================================================================

    #[test]
    fn test_manager_new() {
        let handler = Arc::new(WgReplyHandler::noop());
        let manager = WgEgressManager::new(handler);

        assert_eq!(manager.tunnel_count(), 0);
        assert!(!manager.is_shutting_down());
    }

    #[test]
    fn test_manager_debug() {
        let handler = Arc::new(WgReplyHandler::noop());
        let manager = WgEgressManager::new(handler);

        let debug_str = format!("{:?}", manager);
        assert!(debug_str.contains("WgEgressManager"));
        assert!(debug_str.contains("tunnel_count"));
    }

    // ========================================================================
    // Tunnel Registry Tests
    // ========================================================================

    #[test]
    fn test_has_tunnel_empty() {
        let manager = WgEgressManager::new(Arc::new(WgReplyHandler::noop()));
        assert!(!manager.has_tunnel("nonexistent"));
    }

    #[test]
    fn test_list_tunnels_empty() {
        let manager = WgEgressManager::new(Arc::new(WgReplyHandler::noop()));
        assert!(manager.list_tunnels().is_empty());
    }

    #[test]
    fn test_tunnel_count_empty() {
        let manager = WgEgressManager::new(Arc::new(WgReplyHandler::noop()));
        assert_eq!(manager.tunnel_count(), 0);
    }

    #[test]
    fn test_get_tunnel_status_not_found() {
        let manager = WgEgressManager::new(Arc::new(WgReplyHandler::noop()));
        assert!(manager.get_tunnel_status("nonexistent").is_none());
    }

    // ========================================================================
    // Statistics Tests
    // ========================================================================

    #[test]
    fn test_stats_initial() {
        let manager = WgEgressManager::new(Arc::new(WgReplyHandler::noop()));
        let stats = manager.stats();

        assert_eq!(stats.tunnel_count, 0);
        assert_eq!(stats.connected_count, 0);
        assert_eq!(stats.total_tx_bytes, 0);
        assert_eq!(stats.total_rx_bytes, 0);
        assert_eq!(stats.send_errors, 0);
        assert_eq!(stats.tunnels_created, 0);
        assert_eq!(stats.tunnels_removed, 0);
    }

    #[test]
    fn test_reply_handler_getter() {
        let handler = Arc::new(WgReplyHandler::noop());
        let manager = WgEgressManager::new(handler.clone());

        let retrieved = manager.reply_handler();
        // They should point to the same handler
        assert!(Arc::ptr_eq(&handler, &retrieved));
    }

    // ========================================================================
    // Shutdown Tests
    // ========================================================================

    #[tokio::test]
    async fn test_shutdown_empty_manager() {
        let manager = WgEgressManager::new(Arc::new(WgReplyHandler::noop()));
        assert!(!manager.is_shutting_down());

        manager.shutdown().await;

        assert!(manager.is_shutting_down());
        assert_eq!(manager.tunnel_count(), 0);
    }

    // ========================================================================
    // Get Tunnels By Type Tests
    // ========================================================================

    #[test]
    fn test_get_tunnels_by_type_empty() {
        let manager = WgEgressManager::new(Arc::new(WgReplyHandler::noop()));

        let pia = manager.get_tunnels_by_type("pia");
        let custom = manager.get_tunnels_by_type("custom");
        let peer = manager.get_tunnels_by_type("peer");

        assert!(pia.is_empty());
        assert!(custom.is_empty());
        assert!(peer.is_empty());
    }

    // ========================================================================
    // All Tunnel Statuses Tests
    // ========================================================================

    #[test]
    fn test_all_tunnel_statuses_empty() {
        let manager = WgEgressManager::new(Arc::new(WgReplyHandler::noop()));
        let statuses = manager.all_tunnel_statuses();
        assert!(statuses.is_empty());
    }

    // ========================================================================
    // EgressTunnelStatus Tests
    // ========================================================================

    #[test]
    fn test_egress_tunnel_status_serialization() {
        let status = EgressTunnelStatus {
            tag: "test-tunnel".to_string(),
            tunnel_type: EgressTunnelType::Pia {
                region: "us-west".to_string(),
            },
            state: EgressState::Running,
            connected: true,
            healthy: true,
            stats: WgTunnelStats::default(),
            local_ip: Some("10.200.200.5".to_string()),
            peer_endpoint: "1.2.3.4:51820".to_string(),
        };

        let json = serde_json::to_string(&status).expect("Should serialize");
        assert!(json.contains("test-tunnel"));
        assert!(json.contains("us-west"));
        assert!(json.contains("10.200.200.5"));
        assert!(json.contains("running"));

        let deserialized: EgressTunnelStatus =
            serde_json::from_str(&json).expect("Should deserialize");
        assert_eq!(deserialized.tag, status.tag);
        assert!(deserialized.connected);
        assert_eq!(deserialized.state, EgressState::Running);
    }

    // ========================================================================
    // WgEgressStats Tests
    // ========================================================================

    #[test]
    fn test_egress_stats_default() {
        let stats = WgEgressStats::default();
        assert_eq!(stats.tunnel_count, 0);
        assert_eq!(stats.connected_count, 0);
        assert_eq!(stats.total_tx_bytes, 0);
    }

    #[test]
    fn test_egress_stats_serialization() {
        let stats = WgEgressStats {
            tunnel_count: 5,
            connected_count: 3,
            total_tx_bytes: 1000,
            total_rx_bytes: 2000,
            total_tx_packets: 10,
            total_rx_packets: 20,
            send_errors: 1,
            tunnels_created: 7,
            tunnels_removed: 2,
        };

        let json = serde_json::to_string(&stats).expect("Should serialize");
        assert!(json.contains("1000"));
        assert!(json.contains("2000"));

        let deserialized: WgEgressStats =
            serde_json::from_str(&json).expect("Should deserialize");
        assert_eq!(deserialized.tunnel_count, stats.tunnel_count);
        assert_eq!(deserialized.total_tx_bytes, stats.total_tx_bytes);
    }

    // ========================================================================
    // Create Tunnel Validation Tests (without network)
    // ========================================================================

    #[tokio::test]
    async fn test_create_tunnel_shutting_down() {
        let manager = WgEgressManager::new(Arc::new(WgReplyHandler::noop()));
        manager.shutdown().await;

        let config = create_test_config("test-tunnel");
        let result = manager.create_tunnel(config).await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), EgressError::ShuttingDown));
    }

    #[tokio::test]
    async fn test_create_tunnel_invalid_config() {
        let manager = WgEgressManager::new(Arc::new(WgReplyHandler::noop()));

        // Empty tag
        let mut config = create_test_config("");
        config.tag = String::new();

        let result = manager.create_tunnel(config).await;
        assert!(result.is_err());
    }

    // ========================================================================
    // Remove Tunnel Tests
    // ========================================================================

    #[tokio::test]
    async fn test_remove_tunnel_not_found() {
        let manager = WgEgressManager::new(Arc::new(WgReplyHandler::noop()));

        let result = manager.remove_tunnel("nonexistent", None).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), EgressError::TunnelNotFound(_)));
    }

    // ========================================================================
    // Send Tests
    // ========================================================================

    #[tokio::test]
    async fn test_send_shutting_down() {
        let manager = WgEgressManager::new(Arc::new(WgReplyHandler::noop()));
        manager.shutdown().await;

        let result = manager.send("test", vec![1, 2, 3]).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), EgressError::ShuttingDown));
    }

    #[tokio::test]
    async fn test_send_tunnel_not_found() {
        let manager = WgEgressManager::new(Arc::new(WgReplyHandler::noop()));

        let result = manager.send("nonexistent", vec![1, 2, 3]).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), EgressError::TunnelNotFound(_)));
    }

    #[test]
    fn test_send_nowait_shutting_down() {
        let manager = WgEgressManager::new(Arc::new(WgReplyHandler::noop()));
        manager.shutdown.store(true, Ordering::Release);

        // Should not panic, just drop the packet
        manager.send_nowait("test", vec![1, 2, 3]);
    }

    #[test]
    fn test_send_nowait_tunnel_not_found() {
        let manager = WgEgressManager::new(Arc::new(WgReplyHandler::noop()));

        // Should not panic, just drop the packet
        manager.send_nowait("nonexistent", vec![1, 2, 3]);

        // Check that send error was recorded
        let stats = manager.stats();
        assert_eq!(stats.send_errors, 1);
    }

    // ========================================================================
    // ManagedTunnel Tests (internal)
    // ========================================================================

    #[test]
    fn test_managed_tunnel_draining() {
        let config = create_test_config("test");
        // We can't create a real tunnel without network, but we can test the draining flag
        // This test is a placeholder for when we have mock tunnels
    }
}
