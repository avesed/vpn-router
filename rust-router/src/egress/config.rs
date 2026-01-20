//! Configuration types for `WireGuard` Egress
//!
//! This module defines configuration types for `WireGuard` egress tunnels,
//! including different tunnel types (PIA, Custom, Peer) and validation.
//!
//! # Configuration Parameters
//!
//! | Parameter | Description | Default |
//! |-----------|-------------|---------|
//! | `tag` | Unique tunnel identifier | Required |
//! | `tunnel_type` | Tunnel type (PIA, Custom, Peer) | Required |
//! | `private_key` | `WireGuard` private key (Base64) | Required |
//! | `peer_public_key` | Peer's public key (Base64) | Required |
//! | `peer_endpoint` | Peer's endpoint (IP:port) | Required |
//! | `local_ip` | Local tunnel IP | Optional |
//! | `allowed_ips` | Allowed IPs for routing | `["0.0.0.0/0"]` |
//! | `persistent_keepalive` | Keepalive interval (seconds) | 25 |
//! | `mtu` | Maximum transmission unit | 1420 |
//!
//! # Example
//!
//! ```
//! use rust_router::egress::{WgEgressConfig, EgressTunnelType};
//!
//! let config = WgEgressConfig::new(
//!     "pia-us-west",
//!     EgressTunnelType::Pia { region: "us-west".to_string() },
//!     "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=",
//!     "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=",
//!     "1.2.3.4:51820",
//! );
//!
//! assert_eq!(config.tag, "pia-us-west");
//! ```

use std::net::SocketAddr;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use serde::{Deserialize, Serialize};

use super::error::EgressError;

/// State of an egress tunnel
///
/// Represents the lifecycle state of an egress tunnel, used for
/// consistent state management and transition validation.
///
/// # State Machine
///
/// ```text
///            create_tunnel()
/// Created ──────────────────────► Connecting
///                                     │
///                            connect() success
///                                     │
///                                     ▼
///                                 Running ◄────── reconnect()
///                                     │               ▲
///                        set_draining()│               │
///                                     ▼               │
///                                 Draining ───────────┘
///                                     │
///                        remove_tunnel()
///                                     │
///                                     ▼
///                                 Stopped
///
///            (any state)
///                │
///          error occurs
///                │
///                ▼
///              Error
/// ```
///
/// # Example
///
/// ```
/// use rust_router::egress::EgressState;
///
/// let state = EgressState::Created;
/// assert!(state.can_connect());
/// assert!(!state.is_active());
///
/// let running = EgressState::Running;
/// assert!(running.is_active());
/// assert!(running.can_send());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum EgressState {
    /// Tunnel created but not connected
    #[default]
    Created,
    /// Tunnel is connecting
    Connecting,
    /// Tunnel is connected and running
    Running,
    /// Tunnel is draining (no new traffic accepted)
    Draining,
    /// Tunnel is stopped/disconnected
    Stopped,
    /// Tunnel encountered an error
    Error,
}

impl EgressState {
    /// Check if the tunnel can accept new connections
    ///
    /// Returns `true` if the tunnel is in a state where `connect()` can be called.
    #[must_use]
    pub fn can_connect(&self) -> bool {
        matches!(self, Self::Created | Self::Stopped | Self::Error)
    }

    /// Check if the tunnel is active and can send traffic
    ///
    /// Returns `true` if the tunnel is connected and not draining.
    #[must_use]
    pub fn is_active(&self) -> bool {
        matches!(self, Self::Running)
    }

    /// Check if the tunnel can send packets
    ///
    /// Returns `true` if the tunnel is in Running state.
    /// Draining tunnels cannot send new traffic.
    #[must_use]
    pub fn can_send(&self) -> bool {
        matches!(self, Self::Running)
    }

    /// Check if the tunnel is in a draining state
    #[must_use]
    pub fn is_draining(&self) -> bool {
        matches!(self, Self::Draining)
    }

    /// Check if the tunnel is stopped or errored
    #[must_use]
    pub fn is_terminated(&self) -> bool {
        matches!(self, Self::Stopped | Self::Error)
    }

    /// Check if the tunnel is in an error state
    #[must_use]
    pub fn is_error(&self) -> bool {
        matches!(self, Self::Error)
    }

    /// Get a human-readable description of the state
    #[must_use]
    pub fn description(&self) -> &'static str {
        match self {
            Self::Created => "Created but not connected",
            Self::Connecting => "Connecting to peer",
            Self::Running => "Connected and running",
            Self::Draining => "Draining (no new traffic)",
            Self::Stopped => "Stopped",
            Self::Error => "Error state",
        }
    }
}

impl std::fmt::Display for EgressState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Created => write!(f, "created"),
            Self::Connecting => write!(f, "connecting"),
            Self::Running => write!(f, "running"),
            Self::Draining => write!(f, "draining"),
            Self::Stopped => write!(f, "stopped"),
            Self::Error => write!(f, "error"),
        }
    }
}

/// Default MTU for `WireGuard` tunnels
pub const DEFAULT_MTU: u16 = 1420;

/// Default persistent keepalive interval in seconds
pub const DEFAULT_PERSISTENT_KEEPALIVE: u16 = 25;

/// Egress tunnel type
///
/// Identifies the type of egress tunnel for logging and management purposes.
///
/// # Example
///
/// ```
/// use rust_router::egress::EgressTunnelType;
///
/// let pia = EgressTunnelType::Pia { region: "us-west".to_string() };
/// let custom = EgressTunnelType::Custom { name: "my-vpn".to_string() };
/// let peer = EgressTunnelType::Peer { node_tag: "node-1".to_string() };
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EgressTunnelType {
    /// Private Internet Access VPN tunnel
    Pia {
        /// PIA region identifier (e.g., "us-west", "eu-frankfurt")
        region: String,
    },
    /// Custom `WireGuard` endpoint
    Custom {
        /// User-defined name for the custom tunnel
        name: String,
    },
    /// Inter-node peer tunnel for multi-hop routing
    Peer {
        /// Node tag of the peer (e.g., "node-us-1")
        node_tag: String,
    },
}

impl EgressTunnelType {
    /// Get a display name for the tunnel type
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::egress::EgressTunnelType;
    ///
    /// let pia = EgressTunnelType::Pia { region: "us-west".to_string() };
    /// assert_eq!(pia.display_name(), "PIA (us-west)");
    ///
    /// let custom = EgressTunnelType::Custom { name: "my-vpn".to_string() };
    /// assert_eq!(custom.display_name(), "Custom (my-vpn)");
    ///
    /// let peer = EgressTunnelType::Peer { node_tag: "node-1".to_string() };
    /// assert_eq!(peer.display_name(), "Peer (node-1)");
    /// ```
    #[must_use]
    pub fn display_name(&self) -> String {
        match self {
            Self::Pia { region } => format!("PIA ({region})"),
            Self::Custom { name } => format!("Custom ({name})"),
            Self::Peer { node_tag } => format!("Peer ({node_tag})"),
        }
    }

    /// Get the short type name
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::egress::EgressTunnelType;
    ///
    /// let pia = EgressTunnelType::Pia { region: "us-west".to_string() };
    /// assert_eq!(pia.short_name(), "pia");
    /// ```
    #[must_use]
    pub fn short_name(&self) -> &'static str {
        match self {
            Self::Pia { .. } => "pia",
            Self::Custom { .. } => "custom",
            Self::Peer { .. } => "peer",
        }
    }

    /// Check if this is a PIA tunnel
    #[must_use]
    pub fn is_pia(&self) -> bool {
        matches!(self, Self::Pia { .. })
    }

    /// Check if this is a custom tunnel
    #[must_use]
    pub fn is_custom(&self) -> bool {
        matches!(self, Self::Custom { .. })
    }

    /// Check if this is a peer tunnel
    #[must_use]
    pub fn is_peer(&self) -> bool {
        matches!(self, Self::Peer { .. })
    }
}

impl std::fmt::Display for EgressTunnelType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

/// Configuration for a `WireGuard` egress tunnel
///
/// Contains all parameters needed to create and manage an egress tunnel.
///
/// # Example
///
/// ```
/// use rust_router::egress::{WgEgressConfig, EgressTunnelType};
///
/// // Create a PIA tunnel config
/// let config = WgEgressConfig::new(
///     "pia-us-west",
///     EgressTunnelType::Pia { region: "us-west".to_string() },
///     "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=",
///     "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=",
///     "1.2.3.4:51820",
/// )
/// .with_local_ip("10.200.200.5")
/// .with_mtu(1400);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WgEgressConfig {
    /// Unique identifier for this tunnel
    ///
    /// Must be unique across all egress tunnels in the manager.
    pub tag: String,

    /// Type of tunnel (PIA, Custom, or Peer)
    pub tunnel_type: EgressTunnelType,

    /// `WireGuard` private key (Base64 encoded)
    ///
    /// Must be a valid 32-byte X25519 private key.
    pub private_key: String,

    /// Peer's public key (Base64 encoded)
    ///
    /// Must be a valid 32-byte X25519 public key.
    pub peer_public_key: String,

    /// Peer endpoint (IP:port)
    ///
    /// The remote `WireGuard` endpoint to connect to.
    pub peer_endpoint: String,

    /// Local tunnel IP address (optional)
    ///
    /// The IP address assigned to this tunnel interface.
    /// May include CIDR notation (e.g., "10.200.200.5/32").
    #[serde(default)]
    pub local_ip: Option<String>,

    /// Allowed IPs for this tunnel
    ///
    /// Determines which destination IPs are routed through this tunnel.
    /// Defaults to `["0.0.0.0/0"]` (route all traffic).
    #[serde(default = "default_allowed_ips")]
    pub allowed_ips: Vec<String>,

    /// Persistent keepalive interval in seconds
    ///
    /// Sends keepalive packets at this interval to maintain NAT mappings.
    /// Defaults to 25 seconds.
    #[serde(default = "default_persistent_keepalive")]
    pub persistent_keepalive: Option<u16>,

    /// Maximum transmission unit
    ///
    /// Should be lower than the underlying network MTU to account for
    /// `WireGuard` overhead (typically 80 bytes).
    /// Defaults to 1420.
    #[serde(default = "default_mtu")]
    pub mtu: Option<u16>,

    /// Listen port for incoming connections
    ///
    /// For peer tunnels, this specifies the UDP port to listen on for
    /// incoming WireGuard traffic. If not specified, a random port is used.
    /// Peer tunnels typically need a fixed port (e.g., 36200) so peers can
    /// connect to each other.
    #[serde(default)]
    pub listen_port: Option<u16>,

    /// Pre-shared key for additional security (optional, Base64 encoded)
    #[serde(default)]
    pub preshared_key: Option<String>,

    /// Enable batch I/O using `sendmmsg` syscall (Linux only)
    ///
    /// When enabled, outgoing packets are buffered and sent in batches using
    /// a single syscall, providing 20%+ throughput improvement.
    ///
    /// Default: true on Linux, false on other platforms (where it's not available).
    ///
    /// # Note
    ///
    /// This feature is only available on Linux. On other platforms, this field
    /// is ignored and single-packet I/O is always used.
    #[serde(default = "default_use_batch_io")]
    pub use_batch_io: bool,

    /// Batch size for batch I/O operations (default: 64)
    ///
    /// Only used when `use_batch_io` is true. Maximum value is 256.
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,
}

fn default_allowed_ips() -> Vec<String> {
    vec!["0.0.0.0/0".to_string()]
}

fn default_persistent_keepalive() -> Option<u16> {
    Some(DEFAULT_PERSISTENT_KEEPALIVE)
}

fn default_mtu() -> Option<u16> {
    Some(DEFAULT_MTU)
}

/// Default for batch I/O: true on Linux, false elsewhere
fn default_use_batch_io() -> bool {
    cfg!(target_os = "linux")
}

/// Default batch size for batch I/O operations
fn default_batch_size() -> usize {
    64
}

impl WgEgressConfig {
    /// Create a new egress configuration
    ///
    /// # Arguments
    ///
    /// * `tag` - Unique tunnel identifier
    /// * `tunnel_type` - Type of tunnel (PIA, Custom, Peer)
    /// * `private_key` - `WireGuard` private key (Base64)
    /// * `peer_public_key` - Peer's public key (Base64)
    /// * `peer_endpoint` - Peer's endpoint (IP:port)
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::egress::{WgEgressConfig, EgressTunnelType};
    ///
    /// let config = WgEgressConfig::new(
    ///     "my-tunnel",
    ///     EgressTunnelType::Custom { name: "vpn".to_string() },
    ///     "private_key_base64",
    ///     "public_key_base64",
    ///     "1.2.3.4:51820",
    /// );
    /// ```
    #[must_use]
    pub fn new(
        tag: impl Into<String>,
        tunnel_type: EgressTunnelType,
        private_key: impl Into<String>,
        peer_public_key: impl Into<String>,
        peer_endpoint: impl Into<String>,
    ) -> Self {
        Self {
            tag: tag.into(),
            tunnel_type,
            private_key: private_key.into(),
            peer_public_key: peer_public_key.into(),
            peer_endpoint: peer_endpoint.into(),
            local_ip: None,
            allowed_ips: default_allowed_ips(),
            persistent_keepalive: default_persistent_keepalive(),
            mtu: default_mtu(),
            listen_port: None,
            preshared_key: None,
            use_batch_io: default_use_batch_io(),
            batch_size: default_batch_size(),
        }
    }

    /// Create a peer tunnel configuration
    ///
    /// This helper creates a configuration for inter-node peer tunnels with
    /// the correct naming convention (`peer-{node_tag}`).
    ///
    /// # Arguments
    ///
    /// * `node_tag` - The peer node's tag (e.g., "vpn-router")
    /// * `private_key` - Local WireGuard private key (Base64)
    /// * `peer_public_key` - Peer's public key (Base64)
    /// * `peer_endpoint` - Peer's endpoint (IP:port)
    /// * `local_ip` - Local tunnel IP address (e.g., "10.200.200.2/32")
    ///
    /// # Example
    ///
    /// ```ignore
    /// let config = WgEgressConfig::new_peer(
    ///     "vpn-router",
    ///     "local_private_key_base64",
    ///     "peer_public_key_base64",
    ///     "10.1.1.10:36200",
    ///     "10.200.200.2/32",
    /// );
    /// assert_eq!(config.tag, "peer-vpn-router");
    /// ```
    #[must_use]
    pub fn new_peer(
        node_tag: impl Into<String>,
        private_key: impl Into<String>,
        peer_public_key: impl Into<String>,
        peer_endpoint: impl Into<String>,
        local_ip: impl Into<String>,
    ) -> Self {
        let node_tag = node_tag.into();
        let tag = format!("peer-{}", node_tag);
        Self {
            tag,
            tunnel_type: EgressTunnelType::Peer { node_tag },
            private_key: private_key.into(),
            peer_public_key: peer_public_key.into(),
            peer_endpoint: peer_endpoint.into(),
            local_ip: Some(local_ip.into()),
            allowed_ips: default_allowed_ips(),
            persistent_keepalive: default_persistent_keepalive(),
            mtu: default_mtu(),
            listen_port: None,
            preshared_key: None,
            use_batch_io: default_use_batch_io(),
            batch_size: default_batch_size(),
        }
    }

    /// Set the local tunnel IP
    #[must_use]
    pub fn with_local_ip(mut self, ip: impl Into<String>) -> Self {
        self.local_ip = Some(ip.into());
        self
    }

    /// Set the allowed IPs
    #[must_use]
    pub fn with_allowed_ips(mut self, ips: Vec<String>) -> Self {
        self.allowed_ips = ips;
        self
    }

    /// Set the persistent keepalive interval
    #[must_use]
    pub fn with_persistent_keepalive(mut self, seconds: u16) -> Self {
        self.persistent_keepalive = Some(seconds);
        self
    }

    /// Set the MTU
    #[must_use]
    pub fn with_mtu(mut self, mtu: u16) -> Self {
        self.mtu = Some(mtu);
        self
    }

    /// Set the listen port for incoming connections
    ///
    /// For peer tunnels, this specifies the UDP port to bind for
    /// incoming WireGuard traffic. If not set, a random port is used.
    #[must_use]
    pub fn with_listen_port(mut self, port: u16) -> Self {
        self.listen_port = Some(port);
        self
    }

    /// Set the pre-shared key
    #[must_use]
    pub fn with_preshared_key(mut self, key: impl Into<String>) -> Self {
        self.preshared_key = Some(key.into());
        self
    }

    /// Enable or disable batch I/O (Linux only)
    ///
    /// When enabled, outgoing packets are buffered and sent in batches using
    /// `sendmmsg` for improved throughput.
    #[must_use]
    pub fn with_batch_io(mut self, enabled: bool) -> Self {
        self.use_batch_io = enabled;
        self
    }

    /// Set the batch size for batch I/O operations
    ///
    /// Only used when `use_batch_io` is true. Maximum value is 256.
    #[must_use]
    pub fn with_batch_size(mut self, size: usize) -> Self {
        self.batch_size = size.min(256);
        self
    }

    /// Validate the configuration
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `tag` is empty
    /// - `private_key` is empty or invalid Base64
    /// - `private_key` decoded is not exactly 32 bytes
    /// - `peer_public_key` is empty or invalid Base64
    /// - `peer_public_key` decoded is not exactly 32 bytes
    /// - `peer_endpoint` is empty or invalid format
    /// - `mtu` is less than 576 (IPv4 minimum)
    /// - `preshared_key` if present is invalid Base64 or not 32 bytes
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::egress::{WgEgressConfig, EgressTunnelType};
    ///
    /// let config = WgEgressConfig::new(
    ///     "my-tunnel",
    ///     EgressTunnelType::Custom { name: "vpn".to_string() },
    ///     "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=",
    ///     "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=",
    ///     "1.2.3.4:51820",
    /// );
    ///
    /// assert!(config.validate().is_ok());
    /// ```
    pub fn validate(&self) -> Result<(), EgressError> {
        // Validate tag
        if self.tag.is_empty() {
            return Err(EgressError::invalid_config("tag cannot be empty"));
        }

        // Validate private key
        if self.private_key.is_empty() {
            return Err(EgressError::invalid_config("private_key is required"));
        }

        let private_bytes = BASE64.decode(&self.private_key).map_err(|e| {
            EgressError::invalid_config(format!("Invalid private key Base64: {e}"))
        })?;

        if private_bytes.len() != 32 {
            return Err(EgressError::invalid_config(format!(
                "Private key must be 32 bytes, got {}",
                private_bytes.len()
            )));
        }

        // Validate peer public key
        if self.peer_public_key.is_empty() {
            return Err(EgressError::invalid_config("peer_public_key is required"));
        }

        let public_bytes = BASE64.decode(&self.peer_public_key).map_err(|e| {
            EgressError::invalid_config(format!("Invalid peer public key Base64: {e}"))
        })?;

        if public_bytes.len() != 32 {
            return Err(EgressError::invalid_config(format!(
                "Peer public key must be 32 bytes, got {}",
                public_bytes.len()
            )));
        }

        // Validate endpoint - must be a valid SocketAddr
        if self.peer_endpoint.is_empty() {
            return Err(EgressError::invalid_config("peer_endpoint is required"));
        }

        self.peer_endpoint.parse::<SocketAddr>().map_err(|e| {
            EgressError::invalid_config(format!(
                "Invalid peer_endpoint '{}': {}",
                self.peer_endpoint, e
            ))
        })?;

        // Validate MTU
        if let Some(mtu) = self.mtu {
            if mtu < 576 {
                return Err(EgressError::invalid_config(format!(
                    "MTU must be at least 576, got {mtu}"
                )));
            }
        }

        // Validate preshared key if present
        if let Some(ref psk) = self.preshared_key {
            let psk_bytes = BASE64
                .decode(psk)
                .map_err(|e| EgressError::invalid_config(format!("Invalid preshared key Base64: {e}")))?;

            if psk_bytes.len() != 32 {
                return Err(EgressError::invalid_config(format!(
                    "Preshared key must be 32 bytes, got {}",
                    psk_bytes.len()
                )));
            }
        }

        // Validate batch_size (must be 1-256)
        if self.batch_size == 0 {
            return Err(EgressError::invalid_config("batch_size must be at least 1"));
        }
        if self.batch_size > 256 {
            return Err(EgressError::invalid_config(format!(
                "batch_size must be <= 256, got {}",
                self.batch_size
            )));
        }

        Ok(())
    }

    /// Get the effective MTU
    #[must_use]
    pub fn effective_mtu(&self) -> u16 {
        self.mtu.unwrap_or(DEFAULT_MTU)
    }

    /// Get the effective keepalive interval
    #[must_use]
    pub fn effective_keepalive(&self) -> Option<u16> {
        self.persistent_keepalive.or(Some(DEFAULT_PERSISTENT_KEEPALIVE))
    }
}

impl Default for WgEgressConfig {
    fn default() -> Self {
        Self {
            tag: String::new(),
            tunnel_type: EgressTunnelType::Custom {
                name: "default".to_string(),
            },
            private_key: String::new(),
            peer_public_key: String::new(),
            peer_endpoint: String::new(),
            local_ip: None,
            allowed_ips: default_allowed_ips(),
            persistent_keepalive: default_persistent_keepalive(),
            mtu: default_mtu(),
            listen_port: None,
            preshared_key: None,
            use_batch_io: default_use_batch_io(),
            batch_size: default_batch_size(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Valid 32-byte key (Base64 encoded)
    const TEST_VALID_KEY: &str = "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=";

    // ========================================================================
    // EgressTunnelType Tests
    // ========================================================================

    #[test]
    fn test_tunnel_type_pia() {
        let t = EgressTunnelType::Pia {
            region: "us-west".to_string(),
        };
        assert!(t.is_pia());
        assert!(!t.is_custom());
        assert!(!t.is_peer());
        assert_eq!(t.short_name(), "pia");
        assert_eq!(t.display_name(), "PIA (us-west)");
    }

    #[test]
    fn test_tunnel_type_custom() {
        let t = EgressTunnelType::Custom {
            name: "my-vpn".to_string(),
        };
        assert!(!t.is_pia());
        assert!(t.is_custom());
        assert!(!t.is_peer());
        assert_eq!(t.short_name(), "custom");
        assert_eq!(t.display_name(), "Custom (my-vpn)");
    }

    #[test]
    fn test_tunnel_type_peer() {
        let t = EgressTunnelType::Peer {
            node_tag: "node-1".to_string(),
        };
        assert!(!t.is_pia());
        assert!(!t.is_custom());
        assert!(t.is_peer());
        assert_eq!(t.short_name(), "peer");
        assert_eq!(t.display_name(), "Peer (node-1)");
    }

    #[test]
    fn test_tunnel_type_display() {
        let t = EgressTunnelType::Pia {
            region: "eu-frankfurt".to_string(),
        };
        assert_eq!(format!("{t}"), "PIA (eu-frankfurt)");
    }

    #[test]
    fn test_tunnel_type_serialization() {
        let t = EgressTunnelType::Pia {
            region: "us-east".to_string(),
        };
        let json = serde_json::to_string(&t).expect("Should serialize");
        assert!(json.contains("pia"));
        assert!(json.contains("us-east"));

        let deserialized: EgressTunnelType = serde_json::from_str(&json).expect("Should deserialize");
        assert_eq!(deserialized, t);
    }

    #[test]
    fn test_tunnel_type_eq() {
        let t1 = EgressTunnelType::Pia {
            region: "us-west".to_string(),
        };
        let t2 = EgressTunnelType::Pia {
            region: "us-west".to_string(),
        };
        let t3 = EgressTunnelType::Pia {
            region: "us-east".to_string(),
        };

        assert_eq!(t1, t2);
        assert_ne!(t1, t3);
    }

    // ========================================================================
    // WgEgressConfig Creation Tests
    // ========================================================================

    #[test]
    fn test_config_new() {
        let config = WgEgressConfig::new(
            "my-tunnel",
            EgressTunnelType::Custom {
                name: "vpn".to_string(),
            },
            TEST_VALID_KEY,
            TEST_VALID_KEY,
            "1.2.3.4:51820",
        );

        assert_eq!(config.tag, "my-tunnel");
        assert!(config.tunnel_type.is_custom());
        assert_eq!(config.private_key, TEST_VALID_KEY);
        assert_eq!(config.peer_public_key, TEST_VALID_KEY);
        assert_eq!(config.peer_endpoint, "1.2.3.4:51820");
        assert!(config.local_ip.is_none());
        assert_eq!(config.allowed_ips, vec!["0.0.0.0/0"]);
        assert_eq!(config.persistent_keepalive, Some(DEFAULT_PERSISTENT_KEEPALIVE));
        assert_eq!(config.mtu, Some(DEFAULT_MTU));
    }

    #[test]
    fn test_config_default() {
        let config = WgEgressConfig::default();
        assert!(config.tag.is_empty());
        assert!(config.private_key.is_empty());
        assert_eq!(config.mtu, Some(DEFAULT_MTU));
    }

    #[test]
    fn test_config_builder_with_local_ip() {
        let config = WgEgressConfig::new(
            "test",
            EgressTunnelType::Pia {
                region: "test".to_string(),
            },
            TEST_VALID_KEY,
            TEST_VALID_KEY,
            "1.2.3.4:51820",
        )
        .with_local_ip("10.200.200.5");

        assert_eq!(config.local_ip, Some("10.200.200.5".to_string()));
    }

    #[test]
    fn test_config_builder_with_allowed_ips() {
        let config = WgEgressConfig::new(
            "test",
            EgressTunnelType::Pia {
                region: "test".to_string(),
            },
            TEST_VALID_KEY,
            TEST_VALID_KEY,
            "1.2.3.4:51820",
        )
        .with_allowed_ips(vec!["10.0.0.0/8".to_string(), "192.168.0.0/16".to_string()]);

        assert_eq!(config.allowed_ips.len(), 2);
        assert_eq!(config.allowed_ips[0], "10.0.0.0/8");
    }

    #[test]
    fn test_config_builder_with_mtu() {
        let config = WgEgressConfig::new(
            "test",
            EgressTunnelType::Pia {
                region: "test".to_string(),
            },
            TEST_VALID_KEY,
            TEST_VALID_KEY,
            "1.2.3.4:51820",
        )
        .with_mtu(1400);

        assert_eq!(config.mtu, Some(1400));
        assert_eq!(config.effective_mtu(), 1400);
    }

    #[test]
    fn test_config_builder_with_keepalive() {
        let config = WgEgressConfig::new(
            "test",
            EgressTunnelType::Pia {
                region: "test".to_string(),
            },
            TEST_VALID_KEY,
            TEST_VALID_KEY,
            "1.2.3.4:51820",
        )
        .with_persistent_keepalive(30);

        assert_eq!(config.persistent_keepalive, Some(30));
        assert_eq!(config.effective_keepalive(), Some(30));
    }

    #[test]
    fn test_config_builder_with_psk() {
        let config = WgEgressConfig::new(
            "test",
            EgressTunnelType::Pia {
                region: "test".to_string(),
            },
            TEST_VALID_KEY,
            TEST_VALID_KEY,
            "1.2.3.4:51820",
        )
        .with_preshared_key(TEST_VALID_KEY);

        assert_eq!(config.preshared_key, Some(TEST_VALID_KEY.to_string()));
    }

    // ========================================================================
    // WgEgressConfig Validation Tests
    // ========================================================================

    #[test]
    fn test_config_validate_success() {
        let config = WgEgressConfig::new(
            "test-tunnel",
            EgressTunnelType::Custom {
                name: "vpn".to_string(),
            },
            TEST_VALID_KEY,
            TEST_VALID_KEY,
            "1.2.3.4:51820",
        );

        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_validate_empty_tag() {
        let config = WgEgressConfig::new(
            "",
            EgressTunnelType::Custom {
                name: "vpn".to_string(),
            },
            TEST_VALID_KEY,
            TEST_VALID_KEY,
            "1.2.3.4:51820",
        );

        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("tag"));
    }

    #[test]
    fn test_config_validate_empty_private_key() {
        let config = WgEgressConfig::new(
            "test",
            EgressTunnelType::Custom {
                name: "vpn".to_string(),
            },
            "",
            TEST_VALID_KEY,
            "1.2.3.4:51820",
        );

        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("private_key"));
    }

    #[test]
    fn test_config_validate_invalid_private_key_base64() {
        let config = WgEgressConfig::new(
            "test",
            EgressTunnelType::Custom {
                name: "vpn".to_string(),
            },
            "not-valid-base64!!!",
            TEST_VALID_KEY,
            "1.2.3.4:51820",
        );

        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Base64"));
    }

    #[test]
    fn test_config_validate_private_key_wrong_length() {
        // Valid Base64 but only 16 bytes
        let config = WgEgressConfig::new(
            "test",
            EgressTunnelType::Custom {
                name: "vpn".to_string(),
            },
            "YWJjZGVmZ2hpamtsbW5v",
            TEST_VALID_KEY,
            "1.2.3.4:51820",
        );

        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("32 bytes"));
    }

    #[test]
    fn test_config_validate_empty_peer_public_key() {
        let config = WgEgressConfig::new(
            "test",
            EgressTunnelType::Custom {
                name: "vpn".to_string(),
            },
            TEST_VALID_KEY,
            "",
            "1.2.3.4:51820",
        );

        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("peer_public_key"));
    }

    #[test]
    fn test_config_validate_invalid_peer_public_key() {
        let config = WgEgressConfig::new(
            "test",
            EgressTunnelType::Custom {
                name: "vpn".to_string(),
            },
            TEST_VALID_KEY,
            "not-valid-base64!!!",
            "1.2.3.4:51820",
        );

        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Base64"));
    }

    #[test]
    fn test_config_validate_empty_endpoint() {
        let config = WgEgressConfig::new(
            "test",
            EgressTunnelType::Custom {
                name: "vpn".to_string(),
            },
            TEST_VALID_KEY,
            TEST_VALID_KEY,
            "",
        );

        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("peer_endpoint"));
    }

    #[test]
    fn test_config_validate_invalid_endpoint_format() {
        let config = WgEgressConfig::new(
            "test",
            EgressTunnelType::Custom {
                name: "vpn".to_string(),
            },
            TEST_VALID_KEY,
            TEST_VALID_KEY,
            "invalid-endpoint",
        );

        let result = config.validate();
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("invalid-endpoint") || err_msg.contains("Invalid peer_endpoint"));
    }

    #[test]
    fn test_config_validate_invalid_endpoint_port() {
        let config = WgEgressConfig::new(
            "test",
            EgressTunnelType::Custom {
                name: "vpn".to_string(),
            },
            TEST_VALID_KEY,
            TEST_VALID_KEY,
            "1.2.3.4:99999", // Invalid port number
        );

        let result = config.validate();
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("Invalid peer_endpoint"));
    }

    #[test]
    fn test_config_validate_invalid_endpoint_ip() {
        let config = WgEgressConfig::new(
            "test",
            EgressTunnelType::Custom {
                name: "vpn".to_string(),
            },
            TEST_VALID_KEY,
            TEST_VALID_KEY,
            "999.999.999.999:51820", // Invalid IP address
        );

        let result = config.validate();
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("Invalid peer_endpoint"));
    }

    #[test]
    fn test_config_validate_mtu_too_small() {
        let config = WgEgressConfig::new(
            "test",
            EgressTunnelType::Custom {
                name: "vpn".to_string(),
            },
            TEST_VALID_KEY,
            TEST_VALID_KEY,
            "1.2.3.4:51820",
        )
        .with_mtu(100);

        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("576"));
    }

    #[test]
    fn test_config_validate_with_valid_psk() {
        let config = WgEgressConfig::new(
            "test",
            EgressTunnelType::Custom {
                name: "vpn".to_string(),
            },
            TEST_VALID_KEY,
            TEST_VALID_KEY,
            "1.2.3.4:51820",
        )
        .with_preshared_key(TEST_VALID_KEY);

        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_validate_with_invalid_psk() {
        let config = WgEgressConfig::new(
            "test",
            EgressTunnelType::Custom {
                name: "vpn".to_string(),
            },
            TEST_VALID_KEY,
            TEST_VALID_KEY,
            "1.2.3.4:51820",
        )
        .with_preshared_key("invalid!!!");

        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("preshared key"));
    }

    #[test]
    fn test_config_validate_batch_size_zero() {
        let mut config = WgEgressConfig::new(
            "test",
            EgressTunnelType::Custom {
                name: "vpn".to_string(),
            },
            TEST_VALID_KEY,
            TEST_VALID_KEY,
            "1.2.3.4:51820",
        );
        config.batch_size = 0;

        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("batch_size"));
    }

    #[test]
    fn test_config_validate_batch_size_too_large() {
        let mut config = WgEgressConfig::new(
            "test",
            EgressTunnelType::Custom {
                name: "vpn".to_string(),
            },
            TEST_VALID_KEY,
            TEST_VALID_KEY,
            "1.2.3.4:51820",
        );
        config.batch_size = 300;

        let result = config.validate();
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("batch_size") && err_msg.contains("256"));
    }

    #[test]
    fn test_config_with_batch_size_caps_at_256() {
        let config = WgEgressConfig::new(
            "test",
            EgressTunnelType::Custom {
                name: "vpn".to_string(),
            },
            TEST_VALID_KEY,
            TEST_VALID_KEY,
            "1.2.3.4:51820",
        )
        .with_batch_size(500);

        assert_eq!(config.batch_size, 256);
    }

    // ========================================================================
    // WgEgressConfig Helper Method Tests
    // ========================================================================

    #[test]
    fn test_config_effective_mtu_with_value() {
        let config = WgEgressConfig::new(
            "test",
            EgressTunnelType::Pia {
                region: "test".to_string(),
            },
            TEST_VALID_KEY,
            TEST_VALID_KEY,
            "1.2.3.4:51820",
        )
        .with_mtu(1400);

        assert_eq!(config.effective_mtu(), 1400);
    }

    #[test]
    fn test_config_effective_mtu_default() {
        let mut config = WgEgressConfig::default();
        config.mtu = None;

        assert_eq!(config.effective_mtu(), DEFAULT_MTU);
    }

    #[test]
    fn test_config_effective_keepalive_with_value() {
        let config = WgEgressConfig::new(
            "test",
            EgressTunnelType::Pia {
                region: "test".to_string(),
            },
            TEST_VALID_KEY,
            TEST_VALID_KEY,
            "1.2.3.4:51820",
        )
        .with_persistent_keepalive(60);

        assert_eq!(config.effective_keepalive(), Some(60));
    }

    #[test]
    fn test_config_effective_keepalive_default() {
        let mut config = WgEgressConfig::default();
        config.persistent_keepalive = None;

        assert_eq!(config.effective_keepalive(), Some(DEFAULT_PERSISTENT_KEEPALIVE));
    }

    // ========================================================================
    // Serialization Tests
    // ========================================================================

    #[test]
    fn test_config_serialization() {
        let config = WgEgressConfig::new(
            "pia-us-west",
            EgressTunnelType::Pia {
                region: "us-west".to_string(),
            },
            TEST_VALID_KEY,
            TEST_VALID_KEY,
            "1.2.3.4:51820",
        )
        .with_local_ip("10.200.200.5")
        .with_mtu(1400);

        let json = serde_json::to_string(&config).expect("Should serialize");
        assert!(json.contains("pia-us-west"));
        assert!(json.contains("us-west"));
        assert!(json.contains("10.200.200.5"));

        let deserialized: WgEgressConfig = serde_json::from_str(&json).expect("Should deserialize");
        assert_eq!(deserialized.tag, config.tag);
        assert_eq!(deserialized.tunnel_type, config.tunnel_type);
        assert_eq!(deserialized.local_ip, config.local_ip);
        assert_eq!(deserialized.mtu, config.mtu);
    }

    #[test]
    fn test_config_deserialization_with_defaults() {
        let json = r#"{
            "tag": "test",
            "tunnel_type": {"type": "custom", "name": "vpn"},
            "private_key": "key",
            "peer_public_key": "peer",
            "peer_endpoint": "1.2.3.4:51820"
        }"#;

        let config: WgEgressConfig = serde_json::from_str(json).expect("Should deserialize");
        assert_eq!(config.tag, "test");
        assert!(config.local_ip.is_none());
        assert_eq!(config.allowed_ips, vec!["0.0.0.0/0"]);
        assert_eq!(config.mtu, Some(DEFAULT_MTU));
        assert_eq!(config.persistent_keepalive, Some(DEFAULT_PERSISTENT_KEEPALIVE));
    }

    // ========================================================================
    // EgressState Tests
    // ========================================================================

    #[test]
    fn test_egress_state_default() {
        let state = EgressState::default();
        assert_eq!(state, EgressState::Created);
    }

    #[test]
    fn test_egress_state_can_connect() {
        assert!(EgressState::Created.can_connect());
        assert!(!EgressState::Connecting.can_connect());
        assert!(!EgressState::Running.can_connect());
        assert!(!EgressState::Draining.can_connect());
        assert!(EgressState::Stopped.can_connect());
        assert!(EgressState::Error.can_connect());
    }

    #[test]
    fn test_egress_state_is_active() {
        assert!(!EgressState::Created.is_active());
        assert!(!EgressState::Connecting.is_active());
        assert!(EgressState::Running.is_active());
        assert!(!EgressState::Draining.is_active());
        assert!(!EgressState::Stopped.is_active());
        assert!(!EgressState::Error.is_active());
    }

    #[test]
    fn test_egress_state_can_send() {
        assert!(!EgressState::Created.can_send());
        assert!(!EgressState::Connecting.can_send());
        assert!(EgressState::Running.can_send());
        assert!(!EgressState::Draining.can_send());
        assert!(!EgressState::Stopped.can_send());
        assert!(!EgressState::Error.can_send());
    }

    #[test]
    fn test_egress_state_is_draining() {
        assert!(!EgressState::Created.is_draining());
        assert!(!EgressState::Connecting.is_draining());
        assert!(!EgressState::Running.is_draining());
        assert!(EgressState::Draining.is_draining());
        assert!(!EgressState::Stopped.is_draining());
        assert!(!EgressState::Error.is_draining());
    }

    #[test]
    fn test_egress_state_is_terminated() {
        assert!(!EgressState::Created.is_terminated());
        assert!(!EgressState::Connecting.is_terminated());
        assert!(!EgressState::Running.is_terminated());
        assert!(!EgressState::Draining.is_terminated());
        assert!(EgressState::Stopped.is_terminated());
        assert!(EgressState::Error.is_terminated());
    }

    #[test]
    fn test_egress_state_is_error() {
        assert!(!EgressState::Created.is_error());
        assert!(!EgressState::Connecting.is_error());
        assert!(!EgressState::Running.is_error());
        assert!(!EgressState::Draining.is_error());
        assert!(!EgressState::Stopped.is_error());
        assert!(EgressState::Error.is_error());
    }

    #[test]
    fn test_egress_state_display() {
        assert_eq!(EgressState::Created.to_string(), "created");
        assert_eq!(EgressState::Connecting.to_string(), "connecting");
        assert_eq!(EgressState::Running.to_string(), "running");
        assert_eq!(EgressState::Draining.to_string(), "draining");
        assert_eq!(EgressState::Stopped.to_string(), "stopped");
        assert_eq!(EgressState::Error.to_string(), "error");
    }

    #[test]
    fn test_egress_state_description() {
        assert!(EgressState::Created.description().contains("Created"));
        assert!(EgressState::Connecting.description().contains("Connecting"));
        assert!(EgressState::Running.description().contains("running"));
        assert!(EgressState::Draining.description().contains("Draining"));
        assert!(EgressState::Stopped.description().contains("Stopped"));
        assert!(EgressState::Error.description().contains("Error"));
    }

    #[test]
    fn test_egress_state_serialization() {
        let state = EgressState::Running;
        let json = serde_json::to_string(&state).expect("Should serialize");
        assert!(json.contains("running"));

        let deserialized: EgressState = serde_json::from_str(&json).expect("Should deserialize");
        assert_eq!(deserialized, state);
    }

    #[test]
    fn test_egress_state_debug() {
        let state = EgressState::Running;
        let debug_str = format!("{:?}", state);
        assert!(debug_str.contains("Running"));
    }

    #[test]
    fn test_egress_state_clone() {
        let state = EgressState::Running;
        let cloned = state;
        assert_eq!(state, cloned);
    }

    #[test]
    fn test_egress_state_eq() {
        assert_eq!(EgressState::Created, EgressState::Created);
        assert_ne!(EgressState::Created, EgressState::Running);
    }
}
