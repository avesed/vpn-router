//! VLESS client outbound implementation
//!
//! This module provides a VLESS client outbound that implements the `Outbound` trait.
//! VLESS is a lightweight proxy protocol with UUID-based authentication, commonly
//! used with TLS or XTLS-Vision for traffic obfuscation.
//!
//! # Protocol Overview
//!
//! VLESS connection flow:
//! 1. Establish transport connection (TCP, TLS, or WebSocket)
//! 2. Send VLESS request header (version, UUID, addons, command, destination)
//! 3. Read VLESS response header (version, addons)
//! 4. Bidirectional data relay
//!
//! # Example
//!
//! ```no_run
//! use rust_router::outbound::vless::{VlessOutbound, VlessConfig, VlessTransportConfig};
//! use rust_router::outbound::Outbound;
//! use std::time::Duration;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = VlessConfig {
//!     tag: "my-vless".into(),
//!     server_address: "proxy.example.com".into(),
//!     server_port: 443,
//!     uuid: uuid::Uuid::new_v4().to_string(),  // UUID as string
//!     flow: String::new(),  // or "xtls-rprx-vision"
//!     transport: VlessTransportConfig::Tls {
//!         server_name: "proxy.example.com".into(),
//!         alpn: vec!["h2".into(), "http/1.1".into()],
//!         skip_verify: false,
//!     },
//! };
//!
//! let outbound = VlessOutbound::new(config).await?;
//! let conn = outbound.connect("8.8.8.8:443".parse()?, Duration::from_secs(10)).await?;
//! # Ok(())
//! # }
//! ```

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;
use tracing::{debug, trace};
use uuid::Uuid;

use super::traits::{HealthStatus, Outbound, OutboundConnection, ProxyServerInfo};
use crate::connection::OutboundStats;
use crate::error::{OutboundError, UdpError};
use crate::transport::{connect as transport_connect, TlsConfig, TransportConfig, WebSocketConfig};
use crate::vless::{
    VlessAddons, VlessAddress, VlessCommand, VlessRequestHeader, VlessResponseHeader,
};

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for VLESS outbound
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VlessConfig {
    /// Unique tag for this outbound
    pub tag: String,

    /// Server address (IP or hostname)
    pub server_address: String,

    /// Server port
    pub server_port: u16,

    /// User UUID for authentication (stored as hyphenated string for JSON compatibility)
    ///
    /// The UUID is stored as a string (e.g., "550e8400-e29b-41d4-a716-446655440000")
    /// and parsed into bytes when needed for the VLESS protocol.
    pub uuid: String,

    /// Flow control (e.g., "xtls-rprx-vision", empty for none)
    #[serde(default)]
    pub flow: String,

    /// Transport configuration
    pub transport: VlessTransportConfig,
}

impl VlessConfig {
    /// Create a new VLESS configuration with plain TCP transport
    ///
    /// The UUID can be provided as either a `Uuid` type or a string.
    pub fn tcp(
        tag: impl Into<String>,
        server_address: impl Into<String>,
        server_port: u16,
        uuid: impl Into<UuidInput>,
    ) -> Self {
        Self {
            tag: tag.into(),
            server_address: server_address.into(),
            server_port,
            uuid: uuid.into().to_string(),
            flow: String::new(),
            transport: VlessTransportConfig::Tcp,
        }
    }

    /// Create a new VLESS configuration with TLS transport
    pub fn tls(
        tag: impl Into<String>,
        server_address: impl Into<String>,
        server_port: u16,
        uuid: impl Into<UuidInput>,
        server_name: impl Into<String>,
    ) -> Self {
        Self {
            tag: tag.into(),
            server_address: server_address.into(),
            server_port,
            uuid: uuid.into().to_string(),
            flow: String::new(),
            transport: VlessTransportConfig::Tls {
                server_name: server_name.into(),
                alpn: Vec::new(),
                skip_verify: false,
            },
        }
    }

    /// Set flow control (e.g., "xtls-rprx-vision")
    #[must_use]
    pub fn with_flow(mut self, flow: impl Into<String>) -> Self {
        self.flow = flow.into();
        self
    }

    /// Check if flow control is enabled
    #[must_use]
    pub fn has_flow(&self) -> bool {
        !self.flow.is_empty()
    }

    /// Get the server address string (host:port)
    #[must_use]
    pub fn server_string(&self) -> String {
        format!("{}:{}", self.server_address, self.server_port)
    }

    /// Parse the UUID string into a 16-byte array
    ///
    /// # Errors
    ///
    /// Returns an error if the UUID string is not a valid UUID format.
    pub fn parse_uuid(&self) -> Result<[u8; 16], OutboundError> {
        Uuid::parse_str(&self.uuid)
            .map(|u| *u.as_bytes())
            .map_err(|e| OutboundError::ConnectionFailed {
                addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
                reason: format!("invalid UUID '{}': {e}", self.uuid),
            })
    }

    /// Get the UUID as a `Uuid` type
    ///
    /// # Errors
    ///
    /// Returns an error if the UUID string is not a valid UUID format.
    pub fn uuid(&self) -> Result<Uuid, OutboundError> {
        Uuid::parse_str(&self.uuid).map_err(|e| OutboundError::ConnectionFailed {
            addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
            reason: format!("invalid UUID '{}': {e}", self.uuid),
        })
    }
}

/// Helper type for accepting UUID input in multiple formats
pub enum UuidInput {
    /// UUID type
    Uuid(Uuid),
    /// String representation
    String(String),
}

impl UuidInput {
    fn to_string(self) -> String {
        match self {
            Self::Uuid(u) => u.to_string(),
            Self::String(s) => s,
        }
    }
}

impl From<Uuid> for UuidInput {
    fn from(u: Uuid) -> Self {
        Self::Uuid(u)
    }
}

impl From<String> for UuidInput {
    fn from(s: String) -> Self {
        Self::String(s)
    }
}

impl From<&str> for UuidInput {
    fn from(s: &str) -> Self {
        Self::String(s.to_string())
    }
}

/// Transport configuration for VLESS connections
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum VlessTransportConfig {
    /// Plain TCP connection (NOT RECOMMENDED - VLESS UUID is sent in plaintext)
    Tcp,

    /// TLS over TCP
    Tls {
        /// Server name for SNI
        server_name: String,
        /// ALPN protocols
        #[serde(default)]
        alpn: Vec<String>,
        /// Skip certificate verification (INSECURE)
        #[serde(default)]
        skip_verify: bool,
    },

    /// WebSocket transport
    WebSocket {
        /// WebSocket path (e.g., "/ws")
        path: String,
        /// Host header override
        #[serde(default)]
        host: Option<String>,
        /// Additional headers
        #[serde(default)]
        headers: Vec<(String, String)>,
        /// TLS settings (None for plain WebSocket)
        #[serde(default)]
        tls: Option<TlsSettings>,
    },
}

/// TLS settings for WebSocket transport
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsSettings {
    /// Server name for SNI
    pub server_name: String,
    /// ALPN protocols
    #[serde(default)]
    pub alpn: Vec<String>,
    /// Skip certificate verification (INSECURE)
    #[serde(default)]
    pub skip_verify: bool,
}

impl TlsSettings {
    /// Create new TLS settings
    pub fn new(server_name: impl Into<String>) -> Self {
        Self {
            server_name: server_name.into(),
            alpn: Vec::new(),
            skip_verify: false,
        }
    }

    /// Set ALPN protocols
    #[must_use]
    pub fn with_alpn<I, S>(mut self, alpn: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.alpn = alpn.into_iter().map(Into::into).collect();
        self
    }

    /// Skip certificate verification (INSECURE)
    #[must_use]
    pub fn insecure_skip_verify(mut self) -> Self {
        self.skip_verify = true;
        self
    }
}

// ============================================================================
// Error Types
// ============================================================================

/// VLESS-specific errors
#[derive(Debug, Clone)]
pub enum VlessOutboundError {
    /// Transport connection failed
    TransportFailed(String),
    /// VLESS handshake failed
    HandshakeFailed(String),
    /// Protocol error
    ProtocolError(String),
    /// Connection timeout
    Timeout,
}

impl fmt::Display for VlessOutboundError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TransportFailed(msg) => write!(f, "VLESS transport failed: {msg}"),
            Self::HandshakeFailed(msg) => write!(f, "VLESS handshake failed: {msg}"),
            Self::ProtocolError(msg) => write!(f, "VLESS protocol error: {msg}"),
            Self::Timeout => write!(f, "VLESS connection timeout"),
        }
    }
}

impl std::error::Error for VlessOutboundError {}

impl From<VlessOutboundError> for OutboundError {
    fn from(e: VlessOutboundError) -> Self {
        OutboundError::ConnectionFailed {
            addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
            reason: e.to_string(),
        }
    }
}

// ============================================================================
// VLESS Outbound
// ============================================================================

/// VLESS outbound implementation
///
/// Provides VLESS protocol support with TCP, TLS, and WebSocket transports.
pub struct VlessOutbound {
    /// Configuration
    config: VlessConfig,
    /// Connection statistics
    stats: Arc<OutboundStats>,
    /// Whether the outbound is enabled
    enabled: AtomicBool,
    /// Current health status
    health: std::sync::RwLock<HealthStatus>,
    /// Consecutive failure count for health tracking
    consecutive_failures: AtomicU64,
}

impl VlessOutbound {
    /// Create a new VLESS outbound from configuration
    ///
    /// # Errors
    ///
    /// Returns `OutboundError` if the configuration is invalid.
    pub async fn new(config: VlessConfig) -> Result<Self, OutboundError> {
        // Validate configuration
        if config.tag.is_empty() {
            return Err(OutboundError::ConnectionFailed {
                addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
                reason: "VLESS outbound tag cannot be empty".into(),
            });
        }

        if config.server_address.is_empty() {
            return Err(OutboundError::ConnectionFailed {
                addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
                reason: "VLESS server address cannot be empty".into(),
            });
        }

        // Validate UUID format
        config.parse_uuid()?;

        Ok(Self {
            config,
            stats: Arc::new(OutboundStats::new()),
            enabled: AtomicBool::new(true),
            health: std::sync::RwLock::new(HealthStatus::Unknown),
            consecutive_failures: AtomicU64::new(0),
        })
    }

    /// Get the VLESS server address
    #[must_use]
    pub fn server_address(&self) -> &str {
        &self.config.server_address
    }

    /// Get the VLESS server port
    #[must_use]
    pub fn server_port(&self) -> u16 {
        self.config.server_port
    }

    /// Get the UUID as a string
    #[must_use]
    pub fn uuid_str(&self) -> &str {
        &self.config.uuid
    }

    /// Get the UUID bytes (cached at creation time, so this cannot fail)
    #[must_use]
    pub fn uuid_bytes(&self) -> [u8; 16] {
        // This unwrap is safe because we validated the UUID in new()
        self.config.parse_uuid().unwrap()
    }

    /// Update health status based on connection result
    fn update_health(&self, success: bool) {
        if success {
            self.consecutive_failures.store(0, Ordering::Relaxed);
            let mut health = self.health.write().unwrap();
            *health = HealthStatus::Healthy;
        } else {
            let failures = self.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;
            let mut health = self.health.write().unwrap();
            *health = if failures >= 5 {
                HealthStatus::Unhealthy
            } else if failures >= 2 {
                HealthStatus::Degraded
            } else {
                HealthStatus::Unknown
            };
        }
    }

    /// Build transport configuration from VLESS config
    fn build_transport_config(&self) -> TransportConfig {
        let mut transport = TransportConfig::tcp(&self.config.server_address, self.config.server_port);

        match &self.config.transport {
            VlessTransportConfig::Tcp => {
                // Plain TCP, no additional configuration
            }
            VlessTransportConfig::Tls {
                server_name,
                alpn,
                skip_verify,
            } => {
                let mut tls = TlsConfig::new(server_name);
                if !alpn.is_empty() {
                    tls = tls.with_alpn(alpn.iter().cloned());
                }
                if *skip_verify {
                    tls = tls.insecure_skip_verify();
                }
                transport = transport.with_tls(tls);
            }
            VlessTransportConfig::WebSocket { path, host, headers, tls } => {
                let mut ws = WebSocketConfig::new(path);
                if let Some(h) = host {
                    ws = ws.with_host(h);
                }
                for (name, value) in headers {
                    ws = ws.with_header(name, value);
                }
                transport = transport.with_websocket(ws);

                if let Some(tls_settings) = tls {
                    let mut tls_config = TlsConfig::new(&tls_settings.server_name);
                    if !tls_settings.alpn.is_empty() {
                        tls_config = tls_config.with_alpn(tls_settings.alpn.iter().cloned());
                    }
                    if tls_settings.skip_verify {
                        tls_config = tls_config.insecure_skip_verify();
                    }
                    transport = transport.with_tls(tls_config);
                }
            }
        }

        transport
    }

    /// Convert destination SocketAddr to VlessAddress
    fn socket_addr_to_vless_address(addr: SocketAddr) -> VlessAddress {
        match addr.ip() {
            IpAddr::V4(ipv4) => VlessAddress::ipv4(ipv4),
            IpAddr::V6(ipv6) => VlessAddress::ipv6(ipv6),
        }
    }

    /// Perform VLESS handshake on a connected stream
    async fn vless_handshake<S>(
        &self,
        stream: &mut S,
        dest_addr: SocketAddr,
    ) -> Result<(), VlessOutboundError>
    where
        S: AsyncReadExt + AsyncWriteExt + Unpin,
    {
        // Build addons
        let addons = if self.config.flow.is_empty() {
            VlessAddons::new()
        } else {
            VlessAddons::with_flow(&self.config.flow)
        };

        // Build VLESS request header
        let request = VlessRequestHeader::with_addons(
            self.uuid_bytes(),
            addons,
            VlessCommand::Tcp,
            Self::socket_addr_to_vless_address(dest_addr),
            dest_addr.port(),
        );

        // Encode and send request
        let encoded = request
            .encode()
            .map_err(|e| VlessOutboundError::ProtocolError(format!("failed to encode request: {e}")))?;

        trace!(
            "Sending VLESS request header ({} bytes) for {}",
            encoded.len(),
            dest_addr
        );

        stream
            .write_all(&encoded)
            .await
            .map_err(|e| VlessOutboundError::HandshakeFailed(format!("failed to send request: {e}")))?;

        // Read response header
        // Response format: version (1 byte) + addons length (1 byte) + addons (variable)
        let response = VlessResponseHeader::read_from(stream)
            .await
            .map_err(|e| VlessOutboundError::HandshakeFailed(format!("failed to read response: {e}")))?;

        trace!(
            "Received VLESS response header: version={}, addons_empty={}",
            response.version,
            response.addons.is_empty()
        );

        Ok(())
    }
}

#[async_trait]
impl Outbound for VlessOutbound {
    async fn connect(
        &self,
        addr: SocketAddr,
        connect_timeout: Duration,
    ) -> Result<OutboundConnection, OutboundError> {
        if !self.is_enabled() {
            return Err(OutboundError::unavailable(
                &self.config.tag,
                "outbound is disabled",
            ));
        }

        self.stats.record_connection();

        // Build transport configuration
        let transport_config = self.build_transport_config();

        debug!(
            "VLESS connecting to {} via {} (dest: {})",
            self.config.server_string(),
            self.config.tag,
            addr
        );

        // Connect transport with timeout
        let transport_result = timeout(connect_timeout, transport_connect(&transport_config)).await;

        let mut stream = match transport_result {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                self.update_health(false);
                self.stats.record_error();
                return Err(OutboundError::connection_failed(
                    addr,
                    format!("transport connection failed: {e}"),
                ));
            }
            Err(_) => {
                self.update_health(false);
                self.stats.record_error();
                return Err(OutboundError::Timeout {
                    addr,
                    timeout_secs: connect_timeout.as_secs(),
                });
            }
        };

        // Perform VLESS handshake with remaining timeout
        let handshake_result = timeout(connect_timeout, self.vless_handshake(&mut stream, addr)).await;

        match handshake_result {
            Ok(Ok(())) => {
                self.update_health(true);
                debug!(
                    "VLESS connection to {} via {} successful",
                    addr, self.config.tag
                );

                // Create OutboundConnection from the TransportStream
                // This supports all transport types (TCP, TLS, WebSocket)
                Ok(OutboundConnection::from_transport(stream, addr))
            }
            Ok(Err(e)) => {
                self.update_health(false);
                self.stats.record_error();
                Err(OutboundError::connection_failed(addr, e.to_string()))
            }
            Err(_) => {
                self.update_health(false);
                self.stats.record_error();
                Err(OutboundError::Timeout {
                    addr,
                    timeout_secs: connect_timeout.as_secs(),
                })
            }
        }
    }

    fn tag(&self) -> &str {
        &self.config.tag
    }

    fn health_status(&self) -> HealthStatus {
        *self.health.read().unwrap()
    }

    fn stats(&self) -> Arc<OutboundStats> {
        Arc::clone(&self.stats)
    }

    fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Relaxed);
    }

    fn active_connections(&self) -> u64 {
        self.stats.active()
    }

    fn outbound_type(&self) -> &'static str {
        "vless"
    }

    fn proxy_server_info(&self) -> Option<ProxyServerInfo> {
        Some(ProxyServerInfo {
            address: self.config.server_string(),
            has_auth: true, // VLESS always uses UUID auth
        })
    }

    // UDP is not supported yet
    async fn connect_udp(
        &self,
        _addr: SocketAddr,
        _timeout: Duration,
    ) -> Result<super::traits::UdpOutboundHandle, UdpError> {
        Err(UdpError::UdpNotSupported {
            tag: self.config.tag.clone(),
        })
    }

    fn supports_udp(&self) -> bool {
        false
    }
}

impl fmt::Debug for VlessOutbound {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VlessOutbound")
            .field("tag", &self.config.tag)
            .field("server", &self.config.server_string())
            .field("uuid", &self.config.uuid.to_string())
            .field("flow", &self.config.flow)
            .field("enabled", &self.is_enabled())
            .field("health", &self.health_status())
            .finish_non_exhaustive()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // Configuration Tests
    // ========================================================================

    #[test]
    fn test_vless_config_tcp() {
        let uuid = Uuid::new_v4();
        let config = VlessConfig::tcp("test", "proxy.example.com", 443, uuid);

        assert_eq!(config.tag, "test");
        assert_eq!(config.server_address, "proxy.example.com");
        assert_eq!(config.server_port, 443);
        assert_eq!(config.uuid, uuid.to_string());
        assert!(config.flow.is_empty());
        assert!(!config.has_flow());
        assert!(matches!(config.transport, VlessTransportConfig::Tcp));
        assert_eq!(config.server_string(), "proxy.example.com:443");
    }

    #[test]
    fn test_vless_config_tls() {
        let uuid = Uuid::new_v4();
        let config = VlessConfig::tls("test-tls", "secure.example.com", 443, uuid, "secure.example.com");

        assert_eq!(config.tag, "test-tls");
        assert!(matches!(config.transport, VlessTransportConfig::Tls { .. }));

        if let VlessTransportConfig::Tls { server_name, alpn, skip_verify } = &config.transport {
            assert_eq!(server_name, "secure.example.com");
            assert!(alpn.is_empty());
            assert!(!skip_verify);
        }
    }

    #[test]
    fn test_vless_config_with_flow() {
        let uuid = Uuid::new_v4();
        let config = VlessConfig::tcp("test", "proxy.example.com", 443, uuid)
            .with_flow("xtls-rprx-vision");

        assert_eq!(config.flow, "xtls-rprx-vision");
        assert!(config.has_flow());
    }

    #[test]
    fn test_vless_config_serialization() {
        let uuid = Uuid::new_v4();
        let config = VlessConfig::tls("test", "proxy.example.com", 443, uuid, "proxy.example.com")
            .with_flow("xtls-rprx-vision");

        let json = serde_json::to_string(&config).unwrap();
        let deserialized: VlessConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.tag, config.tag);
        assert_eq!(deserialized.server_address, config.server_address);
        assert_eq!(deserialized.server_port, config.server_port);
        assert_eq!(deserialized.uuid, config.uuid);
        assert_eq!(deserialized.flow, config.flow);
    }

    // ========================================================================
    // Transport Config Tests
    // ========================================================================

    #[test]
    fn test_transport_config_tcp() {
        let transport = VlessTransportConfig::Tcp;
        let json = serde_json::to_string(&transport).unwrap();
        assert!(json.contains("tcp"));
    }

    #[test]
    fn test_transport_config_tls() {
        let transport = VlessTransportConfig::Tls {
            server_name: "example.com".into(),
            alpn: vec!["h2".into(), "http/1.1".into()],
            skip_verify: false,
        };

        let json = serde_json::to_string(&transport).unwrap();
        let deserialized: VlessTransportConfig = serde_json::from_str(&json).unwrap();

        if let VlessTransportConfig::Tls { server_name, alpn, skip_verify } = deserialized {
            assert_eq!(server_name, "example.com");
            assert_eq!(alpn, vec!["h2", "http/1.1"]);
            assert!(!skip_verify);
        } else {
            panic!("Wrong transport type");
        }
    }

    #[test]
    fn test_transport_config_websocket() {
        let transport = VlessTransportConfig::WebSocket {
            path: "/ws".into(),
            host: Some("cdn.example.com".into()),
            headers: vec![("X-Custom".into(), "value".into())],
            tls: Some(TlsSettings::new("cdn.example.com")),
        };

        let json = serde_json::to_string(&transport).unwrap();
        let deserialized: VlessTransportConfig = serde_json::from_str(&json).unwrap();

        if let VlessTransportConfig::WebSocket { path, host, headers, tls } = deserialized {
            assert_eq!(path, "/ws");
            assert_eq!(host, Some("cdn.example.com".into()));
            assert_eq!(headers.len(), 1);
            assert!(tls.is_some());
        } else {
            panic!("Wrong transport type");
        }
    }

    // ========================================================================
    // TLS Settings Tests
    // ========================================================================

    #[test]
    fn test_tls_settings() {
        let tls = TlsSettings::new("example.com")
            .with_alpn(vec!["h2", "http/1.1"])
            .insecure_skip_verify();

        assert_eq!(tls.server_name, "example.com");
        assert_eq!(tls.alpn, vec!["h2", "http/1.1"]);
        assert!(tls.skip_verify);
    }

    // ========================================================================
    // VlessOutbound Tests
    // ========================================================================

    #[tokio::test]
    async fn test_vless_outbound_new() {
        let uuid = Uuid::new_v4();
        let config = VlessConfig::tcp("test-outbound", "proxy.example.com", 443, uuid);
        let outbound = VlessOutbound::new(config).await.unwrap();

        assert_eq!(outbound.tag(), "test-outbound");
        assert_eq!(outbound.server_address(), "proxy.example.com");
        assert_eq!(outbound.server_port(), 443);
        assert_eq!(outbound.uuid_str(), uuid.to_string());
        assert_eq!(outbound.uuid_bytes(), *uuid.as_bytes());
        assert!(outbound.is_enabled());
        assert_eq!(outbound.outbound_type(), "vless");
        assert!(!outbound.supports_udp());
    }

    #[tokio::test]
    async fn test_vless_outbound_empty_tag_error() {
        let uuid = Uuid::new_v4();
        let config = VlessConfig {
            tag: String::new(),
            server_address: "proxy.example.com".into(),
            server_port: 443,
            uuid: uuid.to_string(),
            flow: String::new(),
            transport: VlessTransportConfig::Tcp,
        };

        let result = VlessOutbound::new(config).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_vless_outbound_empty_address_error() {
        let uuid = Uuid::new_v4();
        let config = VlessConfig {
            tag: "test".into(),
            server_address: String::new(),
            server_port: 443,
            uuid: uuid.to_string(),
            flow: String::new(),
            transport: VlessTransportConfig::Tcp,
        };

        let result = VlessOutbound::new(config).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_vless_outbound_invalid_uuid_error() {
        let config = VlessConfig {
            tag: "test".into(),
            server_address: "proxy.example.com".into(),
            server_port: 443,
            uuid: "not-a-valid-uuid".into(),
            flow: String::new(),
            transport: VlessTransportConfig::Tcp,
        };

        let result = VlessOutbound::new(config).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_vless_outbound_disabled() {
        let uuid = Uuid::new_v4();
        let config = VlessConfig::tcp("test-disabled", "proxy.example.com", 443, uuid);
        let outbound = VlessOutbound::new(config).await.unwrap();

        outbound.set_enabled(false);
        assert!(!outbound.is_enabled());

        let dest: SocketAddr = "8.8.8.8:443".parse().unwrap();
        let result = outbound.connect(dest, Duration::from_secs(1)).await;

        assert!(result.is_err());
        if let Err(OutboundError::Unavailable { tag, reason }) = result {
            assert_eq!(tag, "test-disabled");
            assert!(reason.contains("disabled"));
        } else {
            panic!("Expected Unavailable error");
        }
    }

    #[tokio::test]
    async fn test_vless_outbound_proxy_server_info() {
        let uuid = Uuid::new_v4();
        let config = VlessConfig::tcp("test-info", "proxy.example.com", 443, uuid);
        let outbound = VlessOutbound::new(config).await.unwrap();

        let info = outbound.proxy_server_info().unwrap();
        assert_eq!(info.address, "proxy.example.com:443");
        assert!(info.has_auth);
    }

    #[tokio::test]
    async fn test_vless_outbound_stats() {
        let uuid = Uuid::new_v4();
        let config = VlessConfig::tcp("test-stats", "proxy.example.com", 443, uuid);
        let outbound = VlessOutbound::new(config).await.unwrap();

        let stats = outbound.stats();
        assert_eq!(stats.connections(), 0);
        assert_eq!(stats.active(), 0);
        assert_eq!(stats.errors(), 0);
    }

    #[tokio::test]
    async fn test_vless_outbound_udp_not_supported() {
        let uuid = Uuid::new_v4();
        let config = VlessConfig::tcp("test-udp", "proxy.example.com", 443, uuid);
        let outbound = VlessOutbound::new(config).await.unwrap();

        let dest: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let result = outbound.connect_udp(dest, Duration::from_secs(1)).await;

        assert!(result.is_err());
        if let Err(UdpError::UdpNotSupported { tag }) = result {
            assert_eq!(tag, "test-udp");
        } else {
            panic!("Expected UdpNotSupported error");
        }
    }

    #[tokio::test]
    async fn test_vless_outbound_debug() {
        let uuid = Uuid::new_v4();
        let config = VlessConfig::tcp("test-debug", "proxy.example.com", 443, uuid);
        let outbound = VlessOutbound::new(config).await.unwrap();

        let debug_str = format!("{:?}", outbound);
        assert!(debug_str.contains("VlessOutbound"));
        assert!(debug_str.contains("test-debug"));
        assert!(debug_str.contains("proxy.example.com:443"));
    }

    // ========================================================================
    // Transport Config Building Tests
    // ========================================================================

    #[tokio::test]
    async fn test_build_transport_config_tcp() {
        let uuid = Uuid::new_v4();
        let config = VlessConfig::tcp("test", "proxy.example.com", 443, uuid);
        let outbound = VlessOutbound::new(config).await.unwrap();

        let transport = outbound.build_transport_config();
        assert_eq!(transport.address, "proxy.example.com");
        assert_eq!(transport.port, 443);
        assert!(transport.tls.is_none());
        assert!(transport.websocket.is_none());
    }

    #[tokio::test]
    async fn test_build_transport_config_tls() {
        let uuid = Uuid::new_v4();
        let config = VlessConfig {
            tag: "test-tls".into(),
            server_address: "proxy.example.com".into(),
            server_port: 443,
            uuid: uuid.to_string(),
            flow: String::new(),
            transport: VlessTransportConfig::Tls {
                server_name: "proxy.example.com".into(),
                alpn: vec!["h2".into()],
                skip_verify: false,
            },
        };
        let outbound = VlessOutbound::new(config).await.unwrap();

        let transport = outbound.build_transport_config();
        assert!(transport.tls.is_some());
        let tls = transport.tls.unwrap();
        assert_eq!(tls.server_name, "proxy.example.com");
        assert_eq!(tls.alpn, vec!["h2"]);
        assert!(!tls.skip_verify);
    }

    #[tokio::test]
    async fn test_build_transport_config_websocket() {
        let uuid = Uuid::new_v4();
        let config = VlessConfig {
            tag: "test-ws".into(),
            server_address: "proxy.example.com".into(),
            server_port: 443,
            uuid: uuid.to_string(),
            flow: String::new(),
            transport: VlessTransportConfig::WebSocket {
                path: "/ws".into(),
                host: Some("cdn.example.com".into()),
                headers: vec![("X-Custom".into(), "value".into())],
                tls: Some(TlsSettings::new("cdn.example.com")),
            },
        };
        let outbound = VlessOutbound::new(config).await.unwrap();

        let transport = outbound.build_transport_config();
        assert!(transport.websocket.is_some());
        assert!(transport.tls.is_some());
        let ws = transport.websocket.unwrap();
        assert_eq!(ws.path, "/ws");
        assert_eq!(ws.host, Some("cdn.example.com".into()));
    }

    // ========================================================================
    // Address Conversion Tests
    // ========================================================================

    #[test]
    fn test_socket_addr_to_vless_address_ipv4() {
        let addr: SocketAddr = "192.168.1.1:443".parse().unwrap();
        let vless_addr = VlessOutbound::socket_addr_to_vless_address(addr);

        assert!(matches!(vless_addr, VlessAddress::Ipv4(_)));
        assert_eq!(vless_addr.as_ipv4(), Some("192.168.1.1".parse().unwrap()));
    }

    #[test]
    fn test_socket_addr_to_vless_address_ipv6() {
        let addr: SocketAddr = "[::1]:443".parse().unwrap();
        let vless_addr = VlessOutbound::socket_addr_to_vless_address(addr);

        assert!(matches!(vless_addr, VlessAddress::Ipv6(_)));
        assert_eq!(vless_addr.as_ipv6(), Some("::1".parse().unwrap()));
    }

    // ========================================================================
    // Health Status Tests
    // ========================================================================

    #[tokio::test]
    async fn test_health_status_transitions() {
        let uuid = Uuid::new_v4();
        let config = VlessConfig::tcp("test-health", "proxy.example.com", 443, uuid);
        let outbound = VlessOutbound::new(config).await.unwrap();

        // Initial status is Unknown
        assert_eq!(outbound.health_status(), HealthStatus::Unknown);

        // Success -> Healthy
        outbound.update_health(true);
        assert_eq!(outbound.health_status(), HealthStatus::Healthy);

        // One failure -> Unknown (resets from Healthy)
        outbound.update_health(false);
        assert_eq!(outbound.health_status(), HealthStatus::Unknown);

        // Two failures -> Degraded
        outbound.update_health(false);
        assert_eq!(outbound.health_status(), HealthStatus::Degraded);

        // Success resets
        outbound.update_health(true);
        assert_eq!(outbound.health_status(), HealthStatus::Healthy);

        // Five failures -> Unhealthy
        for _ in 0..5 {
            outbound.update_health(false);
        }
        assert_eq!(outbound.health_status(), HealthStatus::Unhealthy);
    }

    // ========================================================================
    // Error Tests
    // ========================================================================

    #[test]
    fn test_vless_outbound_error_display() {
        let err = VlessOutboundError::TransportFailed("connection refused".into());
        assert!(err.to_string().contains("transport failed"));
        assert!(err.to_string().contains("connection refused"));

        let err = VlessOutboundError::HandshakeFailed("invalid response".into());
        assert!(err.to_string().contains("handshake failed"));

        let err = VlessOutboundError::ProtocolError("bad header".into());
        assert!(err.to_string().contains("protocol error"));

        let err = VlessOutboundError::Timeout;
        assert!(err.to_string().contains("timeout"));
    }

    #[test]
    fn test_vless_outbound_error_to_outbound_error() {
        let err = VlessOutboundError::HandshakeFailed("test".into());
        let outbound_err: OutboundError = err.into();

        match outbound_err {
            OutboundError::ConnectionFailed { reason, .. } => {
                assert!(reason.contains("handshake failed"));
            }
            _ => panic!("Expected ConnectionFailed"),
        }
    }

    // ========================================================================
    // Mock Server Integration Tests
    // ========================================================================

    /// Simple mock VLESS server for testing
    async fn run_mock_vless_server(
        listener: tokio::net::TcpListener,
        expected_uuid: [u8; 16],
        response_version: u8,
    ) -> std::io::Result<()> {
        let (mut socket, _) = listener.accept().await?;

        // Read request header
        // Version (1 byte)
        let version = socket.read_u8().await?;
        assert_eq!(version, 0);

        // UUID (16 bytes)
        let mut uuid = [0u8; 16];
        socket.read_exact(&mut uuid).await?;
        assert_eq!(uuid, expected_uuid);

        // Addons length (1 byte)
        let addons_len = socket.read_u8().await?;
        if addons_len > 0 {
            let mut addons = vec![0u8; addons_len as usize];
            socket.read_exact(&mut addons).await?;
        }

        // Command (1 byte)
        let command = socket.read_u8().await?;
        assert_eq!(command, 0x01); // TCP

        // Port (2 bytes)
        let _port = socket.read_u16().await?;

        // Address type (1 byte)
        let atyp = socket.read_u8().await?;
        match atyp {
            0x01 => {
                // IPv4
                let mut addr = [0u8; 4];
                socket.read_exact(&mut addr).await?;
            }
            0x03 => {
                // IPv6
                let mut addr = [0u8; 16];
                socket.read_exact(&mut addr).await?;
            }
            _ => {}
        }

        // Send response: version (1 byte) + addons length (1 byte, 0 = no addons)
        socket.write_all(&[response_version, 0]).await?;

        Ok(())
    }

    #[tokio::test]
    async fn test_vless_handshake_with_mock_server() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let uuid = Uuid::new_v4();
        let uuid_bytes = *uuid.as_bytes();

        // Start mock server
        let server = tokio::spawn(async move {
            run_mock_vless_server(listener, uuid_bytes, 0).await.unwrap();
        });

        // Create outbound with TCP transport (no TLS for testing)
        let config = VlessConfig {
            tag: "test-mock".into(),
            server_address: server_addr.ip().to_string(),
            server_port: server_addr.port(),
            uuid: uuid.to_string(),
            flow: String::new(),
            transport: VlessTransportConfig::Tcp,
        };

        let outbound = VlessOutbound::new(config).await.unwrap();

        // Connect to mock server
        let dest: SocketAddr = "8.8.8.8:443".parse().unwrap();
        let result = outbound.connect(dest, Duration::from_secs(5)).await;

        // Should succeed
        assert!(result.is_ok());
        let conn = result.unwrap();
        assert_eq!(conn.remote_addr(), dest);

        // Wait for server
        let _ = server.await;
    }

    #[tokio::test]
    async fn test_vless_handshake_invalid_response_version() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let uuid = Uuid::new_v4();
        let uuid_bytes = *uuid.as_bytes();

        // Start mock server with invalid response version
        let server = tokio::spawn(async move {
            run_mock_vless_server(listener, uuid_bytes, 1).await.unwrap(); // Invalid version 1
        });

        let config = VlessConfig {
            tag: "test-invalid".into(),
            server_address: server_addr.ip().to_string(),
            server_port: server_addr.port(),
            uuid: uuid.to_string(),
            flow: String::new(),
            transport: VlessTransportConfig::Tcp,
        };

        let outbound = VlessOutbound::new(config).await.unwrap();

        let dest: SocketAddr = "8.8.8.8:443".parse().unwrap();
        let result = outbound.connect(dest, Duration::from_secs(5)).await;

        // Should fail due to invalid response version
        assert!(result.is_err());

        let _ = server.await;
    }

    #[tokio::test]
    async fn test_vless_handshake_with_flow() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let uuid = Uuid::new_v4();
        let uuid_bytes = *uuid.as_bytes();

        // Start mock server
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();

            // Read version
            let version = socket.read_u8().await.unwrap();
            assert_eq!(version, 0);

            // Read UUID
            let mut uuid = [0u8; 16];
            socket.read_exact(&mut uuid).await.unwrap();
            assert_eq!(uuid, uuid_bytes);

            // Read addons length - should be > 0 for flow
            let addons_len = socket.read_u8().await.unwrap();
            assert!(addons_len > 0, "Expected flow addons");

            // Skip rest of addons and request
            let mut remaining = vec![0u8; addons_len as usize + 1 + 2 + 1 + 4]; // addons + cmd + port + atyp + ipv4
            socket.read_exact(&mut remaining).await.unwrap();

            // Send response
            socket.write_all(&[0, 0]).await.unwrap();
        });

        let config = VlessConfig {
            tag: "test-flow".into(),
            server_address: server_addr.ip().to_string(),
            server_port: server_addr.port(),
            uuid: uuid.to_string(),
            flow: "xtls-rprx-vision".into(),
            transport: VlessTransportConfig::Tcp,
        };

        let outbound = VlessOutbound::new(config).await.unwrap();

        let dest: SocketAddr = "8.8.8.8:443".parse().unwrap();
        let result = outbound.connect(dest, Duration::from_secs(5)).await;

        assert!(result.is_ok());

        let _ = server.await;
    }

    #[tokio::test]
    async fn test_vless_connection_timeout() {
        // Use a non-routable address to trigger timeout
        let config = VlessConfig {
            tag: "test-timeout".into(),
            server_address: "192.0.2.1".into(), // TEST-NET-1, non-routable
            server_port: 443,
            uuid: Uuid::new_v4().to_string(),
            flow: String::new(),
            transport: VlessTransportConfig::Tcp,
        };

        let outbound = VlessOutbound::new(config).await.unwrap();

        let dest: SocketAddr = "8.8.8.8:443".parse().unwrap();
        let result = outbound.connect(dest, Duration::from_millis(100)).await;

        assert!(result.is_err());
        match result {
            Err(OutboundError::Timeout { .. }) => {}
            Err(OutboundError::ConnectionFailed { .. }) => {}
            _ => panic!("Expected Timeout or ConnectionFailed error"),
        }
    }
}
