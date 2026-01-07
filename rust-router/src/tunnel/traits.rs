//! WireGuard tunnel abstraction trait for Phase 6
//!
//! This module defines the trait interface for WireGuard tunnels,
//! allowing different implementations (userspace, kernel) to be
//! used interchangeably.
//!
//! # Phase 6 Implementation Status
//!
//! - [x] 6.2 WgTunnel trait definition
//! - [x] 6.2 Async read/write operations
//! - [x] 6.2 Statistics collection
//! - [x] 6.2 Peer management (Ingress mode)
//! - [x] 6.2 Encryption/decryption operations
//!
//! # Trait Design
//!
//! The `WgTunnel` trait provides:
//! - Async send/receive for encrypted packets
//! - Configuration access
//! - Statistics collection
//! - Peer management (for Ingress mode with multiple clients)
//! - Direct encryption/decryption operations
//! - Graceful shutdown
//!
//! # Object Safety
//!
//! The trait is designed to be object-safe, allowing use of `dyn WgTunnel`.
//! Async methods return boxed futures to maintain object safety.
//!
//! # References
//!
//! - Implementation Plan: `docs/PHASE6_IMPLEMENTATION_PLAN_v3.2.md` Section 6.2

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;

use crate::tunnel::config::{WgPeerConfig, WgPeerInfo, WgPeerUpdate, WgTunnelConfig};

/// Error types for WireGuard tunnel operations
#[derive(Debug, thiserror::Error)]
pub enum WgTunnelError {
    /// Tunnel is not connected
    #[error("Tunnel is not connected")]
    NotConnected,

    /// Tunnel is already connected
    #[error("Tunnel is already connected")]
    AlreadyConnected,

    /// Invalid configuration
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    /// Key error
    #[error("Key error: {0}")]
    KeyError(String),

    /// I/O error
    #[error("I/O error: {0}")]
    IoError(String),

    /// Handshake failed
    #[error("Handshake failed: {0}")]
    HandshakeFailed(String),

    /// Timeout
    #[error("Operation timed out")]
    Timeout,

    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),

    /// Peer not found
    #[error("Peer not found: {0}")]
    PeerNotFound(String),

    /// Peer already exists
    #[error("Peer already exists: {0}")]
    PeerAlreadyExists(String),

    /// Encryption error
    #[error("Encryption error: {0}")]
    EncryptionError(String),

    /// Decryption error
    #[error("Decryption error: {0}")]
    DecryptionError(String),

    /// Operation not supported
    #[error("Operation not supported: {0}")]
    NotSupported(String),

    /// Tunnel is shutting down
    #[error("Tunnel is shutting down")]
    ShuttingDown,
}

impl From<std::io::Error> for WgTunnelError {
    fn from(err: std::io::Error) -> Self {
        Self::IoError(err.to_string())
    }
}

/// Statistics for a WireGuard tunnel
#[derive(Debug, Clone, Default)]
pub struct WgTunnelStats {
    /// Bytes transmitted
    pub tx_bytes: u64,
    /// Bytes received
    pub rx_bytes: u64,
    /// Packets transmitted
    pub tx_packets: u64,
    /// Packets received
    pub rx_packets: u64,
    /// Last handshake timestamp (Unix seconds)
    pub last_handshake: Option<u64>,
    /// Number of handshakes completed
    pub handshake_count: u64,
    /// Number of invalid packets received
    pub invalid_packets: u64,
}

/// Result type alias for decryption operations
///
/// Returns the decrypted packet and the public key of the source peer.
pub type DecryptResult = (Vec<u8>, String);

/// Boxed future type for async trait methods (object-safe)
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Trait for WireGuard tunnel implementations
///
/// This trait abstracts over different WireGuard implementations
/// (userspace via boringtun, kernel via wg-quick, etc.).
///
/// # Modes of Operation
///
/// WireGuard tunnels can operate in two modes:
///
/// 1. **Egress mode** (single peer): Traditional VPN client mode where the tunnel
///    connects to a single remote endpoint. Most methods work as expected.
///
/// 2. **Ingress mode** (multiple peers): Server mode where the tunnel accepts
///    connections from multiple clients. The peer management methods (`add_peer`,
///    `remove_peer`, `update_peer`, `get_peer`, `list_peers`) are designed for
///    this mode. Implementations may return `NotSupported` for single-peer tunnels.
///
/// # Object Safety
///
/// This trait is object-safe and can be used as `dyn WgTunnel`. Async methods
/// return boxed futures to maintain object safety.
///
/// # Lock Ordering
///
/// Implementations using interior mutability must follow this lock order:
/// 1. `tunn` (Mutex) - WireGuard crypto state
/// 2. `socket` (RwLock) - UDP socket
/// 3. `recv_tx` (RwLock) - Receive channel
/// 4. `local_ip` (RwLock) - Local IP address
/// 5. `allowed_ips` (RwLock) - Allowed IPs for validation
/// 6. `handshake_complete` (watch) - Handshake completion signal
///
/// Always acquire locks in this order to prevent deadlocks.
#[allow(dead_code)]
pub trait WgTunnel: Send + Sync {
    // ========================================================================
    // Identity and Configuration
    // ========================================================================

    /// Get the tunnel tag identifier
    ///
    /// The tag is a unique identifier for this tunnel instance, typically
    /// used for logging and management operations.
    ///
    /// # Returns
    ///
    /// The tunnel's unique tag identifier
    fn tag(&self) -> &str;

    /// Get the tunnel configuration
    fn config(&self) -> &WgTunnelConfig;

    // ========================================================================
    // Connection State
    // ========================================================================

    /// Check if the tunnel is connected
    fn is_connected(&self) -> bool;

    /// Check if the tunnel is healthy
    ///
    /// A tunnel is considered healthy if it is connected and has had a
    /// recent successful handshake. The default implementation returns
    /// the same value as `is_connected()`.
    ///
    /// Implementations may override this to include additional health
    /// checks such as packet loss, latency, or handshake age.
    fn is_healthy(&self) -> bool {
        self.is_connected()
    }

    /// Get tunnel statistics
    fn stats(&self) -> WgTunnelStats;

    /// Get the local tunnel IP address
    ///
    /// Returns a cloned String because the underlying storage uses
    /// interior mutability (RwLock) which prevents returning references.
    fn local_ip(&self) -> Option<String>;

    /// Get the peer endpoint address
    ///
    /// For single-peer (egress) mode, returns the configured peer endpoint.
    /// For multi-peer (ingress) mode, this may return None and callers
    /// should use `get_peer()` to get individual peer endpoints.
    fn peer_endpoint(&self) -> Option<SocketAddr>;

    /// Get the last handshake timestamp
    ///
    /// For single-peer mode, returns the last handshake with the peer.
    /// For multi-peer mode, returns the most recent handshake across all peers.
    fn last_handshake(&self) -> Option<u64>;

    // ========================================================================
    // Peer Management (Ingress Mode)
    // ========================================================================

    /// Add a new peer to the tunnel
    ///
    /// This method is primarily for Ingress mode where the tunnel can accept
    /// connections from multiple clients.
    ///
    /// # Arguments
    ///
    /// * `peer` - Configuration for the new peer
    ///
    /// # Errors
    ///
    /// - `PeerAlreadyExists` - A peer with the same public key already exists
    /// - `InvalidConfig` - The peer configuration is invalid
    /// - `NotSupported` - The tunnel implementation doesn't support multiple peers
    ///
    /// # Default Implementation
    ///
    /// Returns `NotSupported` error. Implementations supporting multiple peers
    /// should override this method.
    fn add_peer(&self, _peer: WgPeerConfig) -> BoxFuture<'_, Result<(), WgTunnelError>> {
        Box::pin(async {
            Err(WgTunnelError::NotSupported(
                "This tunnel implementation does not support multiple peers".into(),
            ))
        })
    }

    /// Remove a peer from the tunnel
    ///
    /// # Arguments
    ///
    /// * `public_key` - The public key of the peer to remove (Base64 encoded)
    ///
    /// # Errors
    ///
    /// - `PeerNotFound` - No peer with the given public key exists
    /// - `NotSupported` - The tunnel implementation doesn't support multiple peers
    ///
    /// # Default Implementation
    ///
    /// Returns `NotSupported` error.
    fn remove_peer(&self, _public_key: &str) -> BoxFuture<'_, Result<(), WgTunnelError>> {
        Box::pin(async {
            Err(WgTunnelError::NotSupported(
                "This tunnel implementation does not support multiple peers".into(),
            ))
        })
    }

    /// Update a peer's configuration
    ///
    /// # Arguments
    ///
    /// * `public_key` - The public key of the peer to update (Base64 encoded)
    /// * `update` - The updates to apply
    ///
    /// # Errors
    ///
    /// - `PeerNotFound` - No peer with the given public key exists
    /// - `InvalidConfig` - The update contains invalid configuration
    /// - `NotSupported` - The tunnel implementation doesn't support multiple peers
    ///
    /// # Default Implementation
    ///
    /// Returns `NotSupported` error.
    fn update_peer(
        &self,
        _public_key: &str,
        _update: WgPeerUpdate,
    ) -> BoxFuture<'_, Result<(), WgTunnelError>> {
        Box::pin(async {
            Err(WgTunnelError::NotSupported(
                "This tunnel implementation does not support multiple peers".into(),
            ))
        })
    }

    /// Get information about a specific peer
    ///
    /// # Arguments
    ///
    /// * `public_key` - The public key of the peer (Base64 encoded)
    ///
    /// # Returns
    ///
    /// `Some(WgPeerInfo)` if the peer exists, `None` otherwise.
    ///
    /// # Default Implementation
    ///
    /// Returns `None`. Single-peer implementations may override to return
    /// information about the configured peer.
    fn get_peer(&self, _public_key: &str) -> Option<WgPeerInfo> {
        None
    }

    /// List all peers
    ///
    /// # Returns
    ///
    /// A vector of all peer information. For single-peer tunnels, this may
    /// return a single-element vector or an empty vector.
    ///
    /// # Default Implementation
    ///
    /// Returns an empty vector.
    fn list_peers(&self) -> Vec<WgPeerInfo> {
        Vec::new()
    }

    // ========================================================================
    // Encryption/Decryption Operations
    // ========================================================================

    /// Decrypt an incoming WireGuard packet
    ///
    /// Takes a raw encrypted WireGuard packet and returns the decrypted
    /// inner IP packet along with the source peer's public key.
    ///
    /// This is useful for Ingress mode where you need to identify which
    /// peer sent the packet for routing decisions.
    ///
    /// # Arguments
    ///
    /// * `encrypted` - The encrypted WireGuard packet
    ///
    /// # Returns
    ///
    /// A tuple of (decrypted_packet, source_peer_public_key)
    ///
    /// # Errors
    ///
    /// - `NotConnected` - The tunnel is not connected
    /// - `DecryptionError` - The packet could not be decrypted
    ///
    /// # Default Implementation
    ///
    /// Returns `NotSupported` error. Implementations should override this
    /// to provide actual decryption functionality.
    fn decrypt(&self, _encrypted: &[u8]) -> Result<DecryptResult, WgTunnelError> {
        Err(WgTunnelError::NotSupported(
            "Direct decryption not supported by this implementation".into(),
        ))
    }

    /// Encrypt a payload for a specific peer
    ///
    /// Takes a plaintext IP packet and encrypts it for the specified peer.
    ///
    /// # Arguments
    ///
    /// * `payload` - The plaintext IP packet to encrypt
    /// * `peer_public_key` - The public key of the destination peer (Base64 encoded)
    ///
    /// # Returns
    ///
    /// The encrypted WireGuard packet ready to be sent over the network.
    ///
    /// # Errors
    ///
    /// - `NotConnected` - The tunnel is not connected
    /// - `PeerNotFound` - No peer with the given public key exists
    /// - `EncryptionError` - Encryption failed
    ///
    /// # Default Implementation
    ///
    /// Returns `NotSupported` error. Implementations should override this
    /// to provide actual encryption functionality.
    fn encrypt(&self, _payload: &[u8], _peer_public_key: &str) -> Result<Vec<u8>, WgTunnelError> {
        Err(WgTunnelError::NotSupported(
            "Direct encryption not supported by this implementation".into(),
        ))
    }

    // ========================================================================
    // Tunnel Control
    // ========================================================================

    /// Trigger a handshake with a specific peer
    ///
    /// This can be used to verify connectivity or refresh session keys.
    ///
    /// # Arguments
    ///
    /// * `peer_public_key` - Optional public key of the peer to handshake with.
    ///   If `None`, triggers handshake with all peers (or the single peer in
    ///   egress mode).
    ///
    /// # Errors
    ///
    /// - `NotConnected` - The tunnel is not connected
    /// - `PeerNotFound` - The specified peer was not found
    /// - `HandshakeFailed` - The handshake initiation failed
    ///
    /// # Default Implementation
    ///
    /// Returns `NotConnected` error if not connected, otherwise `NotSupported`.
    fn trigger_handshake(
        &self,
        _peer_public_key: Option<&str>,
    ) -> BoxFuture<'_, Result<(), WgTunnelError>> {
        Box::pin(async {
            if !self.is_connected() {
                return Err(WgTunnelError::NotConnected);
            }
            Err(WgTunnelError::NotSupported(
                "Handshake triggering not supported by this implementation".into(),
            ))
        })
    }

    /// Shutdown the tunnel gracefully
    ///
    /// This method initiates a graceful shutdown of the tunnel:
    /// 1. Stops accepting new connections/packets
    /// 2. Completes any in-flight operations
    /// 3. Closes the underlying socket
    /// 4. Cleans up resources
    ///
    /// After calling this method, the tunnel should not be used.
    ///
    /// # Errors
    ///
    /// - `NotConnected` - The tunnel is not connected
    /// - `Internal` - An error occurred during shutdown
    ///
    /// # Default Implementation
    ///
    /// Returns `NotConnected` error if not connected, otherwise `Ok(())`.
    /// Implementations should override this with actual cleanup logic.
    fn shutdown(&self) -> BoxFuture<'_, Result<(), WgTunnelError>> {
        Box::pin(async {
            if !self.is_connected() {
                return Err(WgTunnelError::NotConnected);
            }
            Ok(())
        })
    }
}

/// Builder for creating WireGuard tunnels
///
/// Provides a fluent API for constructing WireGuard tunnel instances
/// with various configurations and implementations.
///
/// # Example
///
/// ```ignore
/// use rust_router::tunnel::{WgTunnelBuilder, WgTunnelConfig};
///
/// let config = WgTunnelConfig::new(private_key, peer_public_key, endpoint);
/// let tunnel = WgTunnelBuilder::new(config)
///     .with_tag("egress-us-west")
///     .build_userspace()?;
/// ```
pub struct WgTunnelBuilder {
    config: WgTunnelConfig,
    tag: Option<String>,
}

impl WgTunnelBuilder {
    /// Create a new tunnel builder
    ///
    /// # Arguments
    ///
    /// * `config` - The WireGuard tunnel configuration
    pub fn new(config: WgTunnelConfig) -> Self {
        Self { config, tag: None }
    }

    /// Set the tunnel tag identifier
    ///
    /// # Arguments
    ///
    /// * `tag` - A unique identifier for the tunnel
    ///
    /// # Example
    ///
    /// ```ignore
    /// let builder = WgTunnelBuilder::new(config)
    ///     .with_tag("egress-us-west");
    /// ```
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tag = Some(tag.into());
        self
    }

    /// Build a userspace tunnel using boringtun
    ///
    /// Creates a new [`UserspaceWgTunnel`] instance using the provided
    /// configuration. The tunnel uses boringtun for WireGuard crypto
    /// operations in pure Rust.
    ///
    /// # Returns
    ///
    /// A boxed trait object implementing [`WgTunnel`]
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration is invalid:
    /// - Missing private key
    /// - Missing peer public key
    /// - Missing peer endpoint
    /// - Invalid key format (not valid Base64 or wrong length)
    /// - Invalid endpoint format
    ///
    /// # Example
    ///
    /// ```ignore
    /// let tunnel = WgTunnelBuilder::new(config).build_userspace()?;
    /// tunnel.connect().await?;
    /// ```
    pub fn build_userspace(self) -> Result<Box<dyn WgTunnel>, WgTunnelError> {
        use crate::tunnel::userspace::UserspaceWgTunnel;
        let tunnel = UserspaceWgTunnel::with_tag(self.config, self.tag)?;
        Ok(Box::new(tunnel))
    }

    /// Get a reference to the configuration
    pub fn config(&self) -> &WgTunnelConfig {
        &self.config
    }

    /// Get the configured tag
    pub fn get_tag(&self) -> Option<&str> {
        self.tag.as_deref()
    }

    /// Consume the builder and return the configuration
    pub fn into_config(self) -> WgTunnelConfig {
        self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // WgTunnelStats Tests
    // ========================================================================

    #[test]
    fn test_wg_tunnel_stats_default() {
        let stats = WgTunnelStats::default();
        assert_eq!(stats.tx_bytes, 0);
        assert_eq!(stats.rx_bytes, 0);
        assert_eq!(stats.tx_packets, 0);
        assert_eq!(stats.rx_packets, 0);
        assert!(stats.last_handshake.is_none());
        assert_eq!(stats.handshake_count, 0);
        assert_eq!(stats.invalid_packets, 0);
    }

    // ========================================================================
    // WgTunnelError Tests
    // ========================================================================

    #[test]
    fn test_wg_tunnel_error_from_io() {
        let io_error = std::io::Error::new(std::io::ErrorKind::Other, "test error");
        let tunnel_error: WgTunnelError = io_error.into();
        assert!(matches!(tunnel_error, WgTunnelError::IoError(_)));
    }

    #[test]
    fn test_wg_tunnel_error_not_connected() {
        let err = WgTunnelError::NotConnected;
        assert_eq!(err.to_string(), "Tunnel is not connected");
    }

    #[test]
    fn test_wg_tunnel_error_already_connected() {
        let err = WgTunnelError::AlreadyConnected;
        assert_eq!(err.to_string(), "Tunnel is already connected");
    }

    #[test]
    fn test_wg_tunnel_error_invalid_config() {
        let err = WgTunnelError::InvalidConfig("missing key".into());
        assert!(err.to_string().contains("missing key"));
    }

    #[test]
    fn test_wg_tunnel_error_key_error() {
        let err = WgTunnelError::KeyError("invalid base64".into());
        assert!(err.to_string().contains("invalid base64"));
    }

    #[test]
    fn test_wg_tunnel_error_io_error() {
        let err = WgTunnelError::IoError("socket error".into());
        assert!(err.to_string().contains("socket error"));
    }

    #[test]
    fn test_wg_tunnel_error_handshake_failed() {
        let err = WgTunnelError::HandshakeFailed("timeout".into());
        assert!(err.to_string().contains("timeout"));
    }

    #[test]
    fn test_wg_tunnel_error_timeout() {
        let err = WgTunnelError::Timeout;
        assert_eq!(err.to_string(), "Operation timed out");
    }

    #[test]
    fn test_wg_tunnel_error_internal() {
        let err = WgTunnelError::Internal("internal error".into());
        assert!(err.to_string().contains("internal error"));
    }

    #[test]
    fn test_wg_tunnel_error_peer_not_found() {
        let err = WgTunnelError::PeerNotFound("abc123".into());
        assert!(err.to_string().contains("abc123"));
        assert!(err.to_string().contains("not found"));
    }

    #[test]
    fn test_wg_tunnel_error_peer_already_exists() {
        let err = WgTunnelError::PeerAlreadyExists("abc123".into());
        assert!(err.to_string().contains("abc123"));
        assert!(err.to_string().contains("already exists"));
    }

    #[test]
    fn test_wg_tunnel_error_encryption_error() {
        let err = WgTunnelError::EncryptionError("crypto fail".into());
        assert!(err.to_string().contains("crypto fail"));
    }

    #[test]
    fn test_wg_tunnel_error_decryption_error() {
        let err = WgTunnelError::DecryptionError("invalid packet".into());
        assert!(err.to_string().contains("invalid packet"));
    }

    #[test]
    fn test_wg_tunnel_error_not_supported() {
        let err = WgTunnelError::NotSupported("multi-peer".into());
        assert!(err.to_string().contains("multi-peer"));
    }

    #[test]
    fn test_wg_tunnel_error_shutting_down() {
        let err = WgTunnelError::ShuttingDown;
        assert_eq!(err.to_string(), "Tunnel is shutting down");
    }

    #[test]
    fn test_wg_tunnel_error_debug() {
        let err = WgTunnelError::NotConnected;
        let debug_str = format!("{:?}", err);
        assert!(debug_str.contains("NotConnected"));
    }

    // ========================================================================
    // WgTunnelBuilder Tests
    // ========================================================================

    #[test]
    fn test_wg_tunnel_builder_new() {
        let config = WgTunnelConfig::default();
        let builder = WgTunnelBuilder::new(config);
        assert!(builder.get_tag().is_none());
    }

    #[test]
    fn test_wg_tunnel_builder_with_tag() {
        let config = WgTunnelConfig::default();
        let builder = WgTunnelBuilder::new(config).with_tag("test-tunnel");
        assert_eq!(builder.get_tag(), Some("test-tunnel"));
    }

    #[test]
    fn test_wg_tunnel_builder_with_tag_string() {
        let config = WgTunnelConfig::default();
        let builder = WgTunnelBuilder::new(config).with_tag(String::from("test-tunnel"));
        assert_eq!(builder.get_tag(), Some("test-tunnel"));
    }

    #[test]
    fn test_wg_tunnel_builder_config() {
        let config = WgTunnelConfig::new(
            "private".to_string(),
            "public".to_string(),
            "1.2.3.4:51820".to_string(),
        );
        let builder = WgTunnelBuilder::new(config.clone());
        assert_eq!(builder.config().private_key, config.private_key);
        assert_eq!(builder.config().peer_public_key, config.peer_public_key);
    }

    #[test]
    fn test_wg_tunnel_builder_into_config() {
        let config = WgTunnelConfig::new(
            "private".to_string(),
            "public".to_string(),
            "1.2.3.4:51820".to_string(),
        );
        let builder = WgTunnelBuilder::new(config.clone());
        let returned_config = builder.into_config();
        assert_eq!(returned_config.private_key, config.private_key);
    }

    // ========================================================================
    // Type Alias Tests
    // ========================================================================

    #[test]
    fn test_decrypt_result_type() {
        // Verify the type alias works as expected
        let result: DecryptResult = (vec![1, 2, 3], "public_key".to_string());
        assert_eq!(result.0, vec![1, 2, 3]);
        assert_eq!(result.1, "public_key");
    }
}
