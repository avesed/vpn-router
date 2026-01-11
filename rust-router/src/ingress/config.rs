//! Configuration types for `WireGuard` Ingress
//!
//! This module defines configuration types for the `WireGuard` ingress manager,
//! including validation and builder patterns.
//!
//! # Configuration Parameters
//!
//! | Parameter | Description | Default |
//! |-----------|-------------|---------|
//! | `private_key` | `WireGuard` private key (Base64) | Required |
//! | `listen_addr` | UDP listen address | Required |
//! | `local_ip` | Local tunnel IP | Required |
//! | `allowed_subnet` | Allowed client subnet | Required |
//! | `mtu` | Maximum transmission unit | 1420 |
//!
//! # Example
//!
//! ```
//! use rust_router::ingress::WgIngressConfig;
//! use std::net::SocketAddr;
//!
//! let config = WgIngressConfig::builder()
//!     .private_key("base64_private_key")
//!     .listen_addr("0.0.0.0:36100".parse().unwrap())
//!     .local_ip("10.25.0.1".parse().unwrap())
//!     .allowed_subnet("10.25.0.0/24".parse().unwrap())
//!     .mtu(1420)
//!     .build();
//! ```

use std::net::{IpAddr, SocketAddr};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use super::error::IngressError;

/// Default MTU for `WireGuard` tunnels
pub const DEFAULT_MTU: u16 = 1420;

/// Default listen port for `WireGuard` ingress
pub const DEFAULT_LISTEN_PORT: u16 = 36100;

/// Configuration for `WireGuard` ingress manager
///
/// This struct contains all configuration needed to run a `WireGuard` ingress
/// that accepts client connections and routes their traffic.
///
/// # Example
///
/// ```
/// use rust_router::ingress::WgIngressConfig;
/// use std::net::{IpAddr, Ipv4Addr, SocketAddr};
/// use ipnet::IpNet;
///
/// let config = WgIngressConfig {
///     private_key: "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=".to_string(),
///     listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 36100),
///     local_ip: IpAddr::V4(Ipv4Addr::new(10, 25, 0, 1)),
///     allowed_subnet: "10.25.0.0/24".parse().unwrap(),
///     mtu: 1420,
///     use_batch_io: true, // Linux batch I/O
///     batch_size: 64,     // Packets per batch
/// };
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WgIngressConfig {
    /// `WireGuard` private key (Base64 encoded)
    ///
    /// This must be a valid 32-byte X25519 private key encoded in Base64.
    pub private_key: String,

    /// UDP listen address for incoming `WireGuard` connections
    ///
    /// Typically `0.0.0.0:36100` for accepting connections on all interfaces.
    pub listen_addr: SocketAddr,

    /// Local tunnel IP address
    ///
    /// This is the IP address assigned to the ingress interface.
    /// Clients use this as their gateway.
    pub local_ip: IpAddr,

    /// Allowed subnet for client IP addresses
    ///
    /// Only packets with source IPs in this subnet will be accepted.
    /// Typically the same subnet as `local_ip` (e.g., `10.25.0.0/24`).
    pub allowed_subnet: IpNet,

    /// Maximum transmission unit (default: 1420)
    ///
    /// The MTU should be lower than the underlying network MTU to account
    /// for `WireGuard` overhead (typically 80 bytes).
    #[serde(default = "default_mtu")]
    pub mtu: u16,

    /// Enable batch I/O using `recvmmsg` syscall (Linux only)
    ///
    /// When enabled, the receive loop uses `recvmmsg` to receive multiple
    /// packets in a single syscall, providing 20%+ throughput improvement.
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

fn default_mtu() -> u16 {
    DEFAULT_MTU
}

/// Default for batch I/O: true on Linux, false elsewhere
fn default_use_batch_io() -> bool {
    cfg!(target_os = "linux")
}

/// Default batch size for batch I/O operations
fn default_batch_size() -> usize {
    64
}

impl WgIngressConfig {
    /// Create a new builder for `WgIngressConfig`
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::ingress::WgIngressConfig;
    ///
    /// let config = WgIngressConfig::builder()
    ///     .private_key("base64_key")
    ///     .listen_addr("0.0.0.0:36100".parse().unwrap())
    ///     .local_ip("10.25.0.1".parse().unwrap())
    ///     .allowed_subnet("10.25.0.0/24".parse().unwrap())
    ///     .build();
    /// ```
    #[must_use]
    pub fn builder() -> WgIngressConfigBuilder {
        WgIngressConfigBuilder::new()
    }

    /// Validate the configuration
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `private_key` is empty or invalid Base64
    /// - `private_key` decoded is not exactly 32 bytes
    /// - `local_ip` is not in `allowed_subnet`
    /// - `mtu` is less than 576 (IPv4 minimum)
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::ingress::WgIngressConfig;
    ///
    /// let config = WgIngressConfig::builder()
    ///     .private_key("YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=")
    ///     .listen_addr("0.0.0.0:36100".parse().unwrap())
    ///     .local_ip("10.25.0.1".parse().unwrap())
    ///     .allowed_subnet("10.25.0.0/24".parse().unwrap())
    ///     .build();
    ///
    /// assert!(config.validate().is_ok());
    /// ```
    pub fn validate(&self) -> Result<(), IngressError> {
        // Validate private key
        if self.private_key.is_empty() {
            return Err(IngressError::invalid_config("private_key is required"));
        }

        let key_bytes = BASE64
            .decode(&self.private_key)
            .map_err(|e| IngressError::invalid_config(format!("Invalid private key Base64: {e}")))?;

        if key_bytes.len() != 32 {
            return Err(IngressError::invalid_config(format!(
                "Private key must be 32 bytes, got {}",
                key_bytes.len()
            )));
        }

        // Validate local_ip is in allowed_subnet
        if !self.allowed_subnet.contains(&self.local_ip) {
            return Err(IngressError::invalid_config(format!(
                "local_ip {} is not in allowed_subnet {}",
                self.local_ip, self.allowed_subnet
            )));
        }

        // Validate MTU
        if self.mtu < 576 {
            return Err(IngressError::invalid_config(format!(
                "MTU must be at least 576, got {}",
                self.mtu
            )));
        }

        // Validate batch_size (must be 1-256)
        if self.batch_size == 0 {
            return Err(IngressError::invalid_config("batch_size must be at least 1"));
        }
        if self.batch_size > 256 {
            return Err(IngressError::invalid_config(format!(
                "batch_size must be <= 256, got {}",
                self.batch_size
            )));
        }

        Ok(())
    }

    /// Check if an IP address is in the allowed subnet
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::ingress::WgIngressConfig;
    /// use std::net::IpAddr;
    ///
    /// let config = WgIngressConfig::builder()
    ///     .private_key("YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=")
    ///     .listen_addr("0.0.0.0:36100".parse().unwrap())
    ///     .local_ip("10.25.0.1".parse().unwrap())
    ///     .allowed_subnet("10.25.0.0/24".parse().unwrap())
    ///     .build();
    ///
    /// assert!(config.is_ip_allowed("10.25.0.100".parse().unwrap()));
    /// assert!(!config.is_ip_allowed("192.168.1.1".parse().unwrap()));
    /// ```
    #[must_use]
    pub fn is_ip_allowed(&self, ip: IpAddr) -> bool {
        self.allowed_subnet.contains(&ip)
    }

    /// Get the listen port
    #[must_use]
    pub fn listen_port(&self) -> u16 {
        self.listen_addr.port()
    }
}

impl Default for WgIngressConfig {
    fn default() -> Self {
        Self {
            private_key: String::new(),
            listen_addr: SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), DEFAULT_LISTEN_PORT),
            local_ip: IpAddr::V4(std::net::Ipv4Addr::new(10, 25, 0, 1)),
            allowed_subnet: "10.25.0.0/24".parse().unwrap(),
            mtu: DEFAULT_MTU,
            use_batch_io: default_use_batch_io(),
            batch_size: default_batch_size(),
        }
    }
}

/// Builder for `WgIngressConfig`
///
/// Provides a fluent API for constructing `WgIngressConfig` instances.
#[derive(Debug, Default)]
pub struct WgIngressConfigBuilder {
    private_key: Option<String>,
    listen_addr: Option<SocketAddr>,
    local_ip: Option<IpAddr>,
    allowed_subnet: Option<IpNet>,
    mtu: Option<u16>,
    use_batch_io: Option<bool>,
    batch_size: Option<usize>,
}

impl WgIngressConfigBuilder {
    /// Create a new builder
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the private key (Base64 encoded)
    #[must_use]
    pub fn private_key(mut self, key: impl Into<String>) -> Self {
        self.private_key = Some(key.into());
        self
    }

    /// Set the listen address
    #[must_use]
    pub fn listen_addr(mut self, addr: SocketAddr) -> Self {
        self.listen_addr = Some(addr);
        self
    }

    /// Set the local tunnel IP
    #[must_use]
    pub fn local_ip(mut self, ip: IpAddr) -> Self {
        self.local_ip = Some(ip);
        self
    }

    /// Set the allowed subnet
    #[must_use]
    pub fn allowed_subnet(mut self, subnet: IpNet) -> Self {
        self.allowed_subnet = Some(subnet);
        self
    }

    /// Set the MTU
    #[must_use]
    pub fn mtu(mut self, mtu: u16) -> Self {
        self.mtu = Some(mtu);
        self
    }

    /// Enable or disable batch I/O (Linux only)
    ///
    /// When enabled, the receive loop uses `recvmmsg` to receive multiple
    /// packets in a single syscall for improved throughput.
    #[must_use]
    pub fn use_batch_io(mut self, enabled: bool) -> Self {
        self.use_batch_io = Some(enabled);
        self
    }

    /// Set the batch size for batch I/O operations
    ///
    /// Only used when `use_batch_io` is true. Maximum value is 256.
    #[must_use]
    pub fn batch_size(mut self, size: usize) -> Self {
        self.batch_size = Some(size.min(256));
        self
    }

    /// Build the configuration
    ///
    /// Uses default values for any unset fields.
    #[must_use]
    pub fn build(self) -> WgIngressConfig {
        let default = WgIngressConfig::default();
        WgIngressConfig {
            private_key: self.private_key.unwrap_or(default.private_key),
            listen_addr: self.listen_addr.unwrap_or(default.listen_addr),
            local_ip: self.local_ip.unwrap_or(default.local_ip),
            allowed_subnet: self.allowed_subnet.unwrap_or(default.allowed_subnet),
            mtu: self.mtu.unwrap_or(default.mtu),
            use_batch_io: self.use_batch_io.unwrap_or(default.use_batch_io),
            batch_size: self.batch_size.unwrap_or(default.batch_size),
        }
    }

    /// Build and validate the configuration
    ///
    /// # Errors
    ///
    /// Returns an error if validation fails.
    pub fn build_validated(self) -> Result<WgIngressConfig, IngressError> {
        let config = self.build();
        config.validate()?;
        Ok(config)
    }
}

/// Peer configuration for `WireGuard` ingress
///
/// This represents a client that can connect to the ingress.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WgIngressPeerConfig {
    /// Peer's public key (Base64 encoded)
    pub public_key: String,

    /// Allowed IPs for this peer (typically a single /32 address)
    pub allowed_ips: Vec<IpNet>,

    /// Optional pre-shared key for additional security
    #[serde(default)]
    pub preshared_key: Option<String>,

    /// Optional persistent keepalive interval in seconds
    #[serde(default)]
    pub persistent_keepalive: Option<u16>,
}

impl WgIngressPeerConfig {
    /// Create a new peer configuration
    ///
    /// # Arguments
    ///
    /// * `public_key` - Peer's public key (Base64 encoded)
    /// * `allowed_ip` - The IP address assigned to this peer
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::ingress::config::WgIngressPeerConfig;
    ///
    /// let peer = WgIngressPeerConfig::new("base64_public_key", "10.25.0.2");
    /// ```
    #[must_use]
    pub fn new(public_key: impl Into<String>, allowed_ip: impl Into<String>) -> Self {
        let ip_str = allowed_ip.into();
        // If the IP doesn't have a prefix, add /32
        let ip_net = if ip_str.contains('/') {
            ip_str.parse().unwrap_or_else(|_| "0.0.0.0/0".parse().unwrap())
        } else {
            format!("{ip_str}/32").parse().unwrap_or_else(|_| "0.0.0.0/0".parse().unwrap())
        };

        Self {
            public_key: public_key.into(),
            allowed_ips: vec![ip_net],
            preshared_key: None,
            persistent_keepalive: Some(25),
        }
    }

    /// Set the pre-shared key
    #[must_use]
    pub fn with_preshared_key(mut self, key: impl Into<String>) -> Self {
        self.preshared_key = Some(key.into());
        self
    }

    /// Set the persistent keepalive interval
    #[must_use]
    pub fn with_persistent_keepalive(mut self, seconds: u16) -> Self {
        self.persistent_keepalive = Some(seconds);
        self
    }

    /// Add an allowed IP
    #[must_use]
    pub fn with_allowed_ip(mut self, ip: IpNet) -> Self {
        self.allowed_ips.push(ip);
        self
    }

    /// Validate the peer configuration
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `public_key` is empty or invalid Base64
    /// - `public_key` decoded is not exactly 32 bytes
    /// - `allowed_ips` is empty
    pub fn validate(&self) -> Result<(), IngressError> {
        if self.public_key.is_empty() {
            return Err(IngressError::invalid_config("public_key is required"));
        }

        let key_bytes = BASE64
            .decode(&self.public_key)
            .map_err(|e| IngressError::invalid_config(format!("Invalid public key Base64: {e}")))?;

        if key_bytes.len() != 32 {
            return Err(IngressError::invalid_config(format!(
                "Public key must be 32 bytes, got {}",
                key_bytes.len()
            )));
        }

        if self.allowed_ips.is_empty() {
            return Err(IngressError::invalid_config("allowed_ips cannot be empty"));
        }

        // Validate preshared key if present
        if let Some(ref psk) = self.preshared_key {
            let psk_bytes = BASE64
                .decode(psk)
                .map_err(|e| IngressError::invalid_config(format!("Invalid preshared key Base64: {e}")))?;

            if psk_bytes.len() != 32 {
                return Err(IngressError::invalid_config(format!(
                    "Preshared key must be 32 bytes, got {}",
                    psk_bytes.len()
                )));
            }
        }

        Ok(())
    }

    /// Get the primary IP address for this peer
    ///
    /// Returns the first allowed IP's address, typically a /32.
    #[must_use]
    pub fn primary_ip(&self) -> Option<IpAddr> {
        self.allowed_ips.first().map(ipnet::IpNet::addr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Valid 32-byte key (Base64 encoded)
    const TEST_VALID_KEY: &str = "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=";

    // ========================================================================
    // WgIngressConfig Tests
    // ========================================================================

    #[test]
    fn test_config_default() {
        let config = WgIngressConfig::default();
        assert!(config.private_key.is_empty());
        assert_eq!(config.listen_addr.port(), DEFAULT_LISTEN_PORT);
        assert_eq!(config.mtu, DEFAULT_MTU);
    }

    #[test]
    fn test_config_builder() {
        let config = WgIngressConfig::builder()
            .private_key(TEST_VALID_KEY)
            .listen_addr("0.0.0.0:51820".parse().unwrap())
            .local_ip("10.25.0.1".parse().unwrap())
            .allowed_subnet("10.25.0.0/24".parse().unwrap())
            .mtu(1400)
            .build();

        assert_eq!(config.private_key, TEST_VALID_KEY);
        assert_eq!(config.listen_addr.port(), 51820);
        assert_eq!(config.mtu, 1400);
    }

    #[test]
    fn test_config_validate_success() {
        let config = WgIngressConfig::builder()
            .private_key(TEST_VALID_KEY)
            .listen_addr("0.0.0.0:36100".parse().unwrap())
            .local_ip("10.25.0.1".parse().unwrap())
            .allowed_subnet("10.25.0.0/24".parse().unwrap())
            .build();

        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_validate_empty_key() {
        let config = WgIngressConfig::builder()
            .listen_addr("0.0.0.0:36100".parse().unwrap())
            .local_ip("10.25.0.1".parse().unwrap())
            .allowed_subnet("10.25.0.0/24".parse().unwrap())
            .build();

        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("private_key"));
    }

    #[test]
    fn test_config_validate_invalid_key() {
        let config = WgIngressConfig::builder()
            .private_key("not-valid-base64!!!")
            .listen_addr("0.0.0.0:36100".parse().unwrap())
            .local_ip("10.25.0.1".parse().unwrap())
            .allowed_subnet("10.25.0.0/24".parse().unwrap())
            .build();

        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Base64"));
    }

    #[test]
    fn test_config_validate_key_wrong_length() {
        // Valid Base64 but only 16 bytes
        let config = WgIngressConfig::builder()
            .private_key("YWJjZGVmZ2hpamtsbW5v")
            .listen_addr("0.0.0.0:36100".parse().unwrap())
            .local_ip("10.25.0.1".parse().unwrap())
            .allowed_subnet("10.25.0.0/24".parse().unwrap())
            .build();

        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("32 bytes"));
    }

    #[test]
    fn test_config_validate_local_ip_not_in_subnet() {
        let config = WgIngressConfig::builder()
            .private_key(TEST_VALID_KEY)
            .listen_addr("0.0.0.0:36100".parse().unwrap())
            .local_ip("192.168.1.1".parse().unwrap())
            .allowed_subnet("10.25.0.0/24".parse().unwrap())
            .build();

        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not in allowed_subnet"));
    }

    #[test]
    fn test_config_validate_mtu_too_small() {
        let config = WgIngressConfig::builder()
            .private_key(TEST_VALID_KEY)
            .listen_addr("0.0.0.0:36100".parse().unwrap())
            .local_ip("10.25.0.1".parse().unwrap())
            .allowed_subnet("10.25.0.0/24".parse().unwrap())
            .mtu(100)
            .build();

        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("576"));
    }

    #[test]
    fn test_config_validate_batch_size_zero() {
        let mut config = WgIngressConfig::builder()
            .private_key(TEST_VALID_KEY)
            .listen_addr("0.0.0.0:36100".parse().unwrap())
            .local_ip("10.25.0.1".parse().unwrap())
            .allowed_subnet("10.25.0.0/24".parse().unwrap())
            .build();
        config.batch_size = 0;

        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("batch_size"));
    }

    #[test]
    fn test_config_validate_batch_size_too_large() {
        let mut config = WgIngressConfig::builder()
            .private_key(TEST_VALID_KEY)
            .listen_addr("0.0.0.0:36100".parse().unwrap())
            .local_ip("10.25.0.1".parse().unwrap())
            .allowed_subnet("10.25.0.0/24".parse().unwrap())
            .build();
        config.batch_size = 300;

        let result = config.validate();
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("batch_size") && err_msg.contains("256"));
    }

    #[test]
    fn test_config_builder_batch_size_caps_at_256() {
        let config = WgIngressConfig::builder()
            .private_key(TEST_VALID_KEY)
            .listen_addr("0.0.0.0:36100".parse().unwrap())
            .local_ip("10.25.0.1".parse().unwrap())
            .allowed_subnet("10.25.0.0/24".parse().unwrap())
            .batch_size(500)
            .build();

        assert_eq!(config.batch_size, 256);
    }

    #[test]
    fn test_config_is_ip_allowed() {
        let config = WgIngressConfig::builder()
            .private_key(TEST_VALID_KEY)
            .listen_addr("0.0.0.0:36100".parse().unwrap())
            .local_ip("10.25.0.1".parse().unwrap())
            .allowed_subnet("10.25.0.0/24".parse().unwrap())
            .build();

        assert!(config.is_ip_allowed("10.25.0.1".parse().unwrap()));
        assert!(config.is_ip_allowed("10.25.0.100".parse().unwrap()));
        assert!(config.is_ip_allowed("10.25.0.254".parse().unwrap()));
        assert!(!config.is_ip_allowed("10.25.1.1".parse().unwrap()));
        assert!(!config.is_ip_allowed("192.168.1.1".parse().unwrap()));
    }

    #[test]
    fn test_config_listen_port() {
        let config = WgIngressConfig::builder()
            .listen_addr("0.0.0.0:51820".parse().unwrap())
            .build();

        assert_eq!(config.listen_port(), 51820);
    }

    #[test]
    fn test_config_build_validated() {
        let result = WgIngressConfig::builder()
            .private_key(TEST_VALID_KEY)
            .listen_addr("0.0.0.0:36100".parse().unwrap())
            .local_ip("10.25.0.1".parse().unwrap())
            .allowed_subnet("10.25.0.0/24".parse().unwrap())
            .build_validated();

        assert!(result.is_ok());
    }

    #[test]
    fn test_config_build_validated_fails() {
        let result = WgIngressConfig::builder()
            .listen_addr("0.0.0.0:36100".parse().unwrap())
            .local_ip("10.25.0.1".parse().unwrap())
            .allowed_subnet("10.25.0.0/24".parse().unwrap())
            .build_validated();

        assert!(result.is_err());
    }

    #[test]
    fn test_config_serialization() {
        let config = WgIngressConfig::builder()
            .private_key(TEST_VALID_KEY)
            .listen_addr("0.0.0.0:36100".parse().unwrap())
            .local_ip("10.25.0.1".parse().unwrap())
            .allowed_subnet("10.25.0.0/24".parse().unwrap())
            .mtu(1400)
            .build();

        let json = serde_json::to_string(&config).expect("Should serialize");
        let deserialized: WgIngressConfig = serde_json::from_str(&json).expect("Should deserialize");

        assert_eq!(deserialized.private_key, config.private_key);
        assert_eq!(deserialized.listen_addr, config.listen_addr);
        assert_eq!(deserialized.mtu, config.mtu);
    }

    // ========================================================================
    // WgIngressPeerConfig Tests
    // ========================================================================

    #[test]
    fn test_peer_config_new() {
        let peer = WgIngressPeerConfig::new(TEST_VALID_KEY, "10.25.0.2");
        assert_eq!(peer.public_key, TEST_VALID_KEY);
        assert_eq!(peer.allowed_ips.len(), 1);
        assert_eq!(peer.allowed_ips[0].to_string(), "10.25.0.2/32");
    }

    #[test]
    fn test_peer_config_new_with_prefix() {
        let peer = WgIngressPeerConfig::new(TEST_VALID_KEY, "10.25.0.0/24");
        assert_eq!(peer.allowed_ips[0].to_string(), "10.25.0.0/24");
    }

    #[test]
    fn test_peer_config_builder() {
        let peer = WgIngressPeerConfig::new(TEST_VALID_KEY, "10.25.0.2")
            .with_preshared_key(TEST_VALID_KEY)
            .with_persistent_keepalive(30)
            .with_allowed_ip("10.25.1.0/24".parse().unwrap());

        assert!(peer.preshared_key.is_some());
        assert_eq!(peer.persistent_keepalive, Some(30));
        assert_eq!(peer.allowed_ips.len(), 2);
    }

    #[test]
    fn test_peer_config_validate_success() {
        let peer = WgIngressPeerConfig::new(TEST_VALID_KEY, "10.25.0.2");
        assert!(peer.validate().is_ok());
    }

    #[test]
    fn test_peer_config_validate_empty_key() {
        let peer = WgIngressPeerConfig::new("", "10.25.0.2");
        let result = peer.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("public_key"));
    }

    #[test]
    fn test_peer_config_validate_invalid_key() {
        let peer = WgIngressPeerConfig::new("invalid-base64!!!", "10.25.0.2");
        let result = peer.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Base64"));
    }

    #[test]
    fn test_peer_config_validate_empty_allowed_ips() {
        let peer = WgIngressPeerConfig {
            public_key: TEST_VALID_KEY.to_string(),
            allowed_ips: Vec::new(),
            preshared_key: None,
            persistent_keepalive: None,
        };
        let result = peer.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("allowed_ips"));
    }

    #[test]
    fn test_peer_config_validate_with_psk() {
        let peer = WgIngressPeerConfig::new(TEST_VALID_KEY, "10.25.0.2")
            .with_preshared_key(TEST_VALID_KEY);
        assert!(peer.validate().is_ok());
    }

    #[test]
    fn test_peer_config_validate_invalid_psk() {
        let peer = WgIngressPeerConfig::new(TEST_VALID_KEY, "10.25.0.2")
            .with_preshared_key("invalid!!!");
        let result = peer.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("preshared key"));
    }

    #[test]
    fn test_peer_config_primary_ip() {
        let peer = WgIngressPeerConfig::new(TEST_VALID_KEY, "10.25.0.2");
        assert_eq!(peer.primary_ip(), Some("10.25.0.2".parse().unwrap()));
    }

    #[test]
    fn test_peer_config_primary_ip_empty() {
        let peer = WgIngressPeerConfig {
            public_key: TEST_VALID_KEY.to_string(),
            allowed_ips: Vec::new(),
            preshared_key: None,
            persistent_keepalive: None,
        };
        assert!(peer.primary_ip().is_none());
    }

    #[test]
    fn test_peer_config_serialization() {
        let peer = WgIngressPeerConfig::new(TEST_VALID_KEY, "10.25.0.2")
            .with_persistent_keepalive(30);

        let json = serde_json::to_string(&peer).expect("Should serialize");
        let deserialized: WgIngressPeerConfig = serde_json::from_str(&json).expect("Should deserialize");

        assert_eq!(deserialized.public_key, peer.public_key);
        assert_eq!(deserialized.allowed_ips.len(), peer.allowed_ips.len());
        assert_eq!(deserialized.persistent_keepalive, peer.persistent_keepalive);
    }

    // ========================================================================
    // IPv6 Tests
    // ========================================================================

    #[test]
    fn test_config_ipv6() {
        let config = WgIngressConfig::builder()
            .private_key(TEST_VALID_KEY)
            .listen_addr("[::]:36100".parse().unwrap())
            .local_ip("fd00::1".parse().unwrap())
            .allowed_subnet("fd00::/64".parse().unwrap())
            .build();

        assert!(config.validate().is_ok());
        assert!(config.is_ip_allowed("fd00::100".parse().unwrap()));
        assert!(!config.is_ip_allowed("fe80::1".parse().unwrap()));
    }

    #[test]
    fn test_peer_config_ipv6() {
        let peer = WgIngressPeerConfig::new(TEST_VALID_KEY, "fd00::2");
        assert!(peer.validate().is_ok());
        assert_eq!(peer.primary_ip(), Some("fd00::2".parse().unwrap()));
    }
}
