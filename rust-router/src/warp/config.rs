// WARP configuration types

use serde::{Deserialize, Serialize};

/// WARP registration request
#[derive(Debug, Clone, Serialize)]
pub struct RegisterRequest {
    pub key: String,
    pub install_id: String,
    pub fcm_token: String,
    pub tos: String,
    #[serde(rename = "type")]
    pub device_type: String,
    pub model: String,
    pub locale: String,
}

impl Default for RegisterRequest {
    fn default() -> Self {
        Self {
            key: String::new(),
            install_id: String::new(),
            fcm_token: String::new(),
            tos: "2021-01-01T00:00:00.000Z".to_string(),
            device_type: "Android".to_string(),
            model: "PC".to_string(),
            locale: "en_US".to_string(),
        }
    }
}

/// WARP registration response
#[derive(Debug, Clone, Deserialize)]
pub struct RegisterResponse {
    pub id: String,
    pub account: Account,
    pub config: WarpConfig,
}

/// WARP account information
#[derive(Debug, Clone, Deserialize)]
pub struct Account {
    pub id: String,
    pub account_type: String,
    pub created: String,
    pub license: String,
    #[serde(default)]
    pub warp_plus: bool,
}

/// WARP WireGuard configuration
#[derive(Debug, Clone, Deserialize)]
pub struct WarpConfig {
    pub client_id: String,
    pub interface: Interface,
    pub peers: Vec<Peer>,
}

/// WireGuard interface configuration
#[derive(Debug, Clone, Deserialize)]
pub struct Interface {
    pub addresses: Addresses,
}

/// Interface addresses (IPv4 and IPv6)
#[derive(Debug, Clone, Deserialize)]
pub struct Addresses {
    pub v4: String,
    pub v6: String,
}

/// WireGuard peer configuration
#[derive(Debug, Clone, Deserialize)]
pub struct Peer {
    pub public_key: String,
    pub endpoint: Endpoint,
}

/// Peer endpoint
#[derive(Debug, Clone, Deserialize)]
pub struct Endpoint {
    pub host: String,
    #[serde(default)]
    pub v4: Option<String>,
    #[serde(default)]
    pub v6: Option<String>,
}

/// Complete WARP registration result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WarpRegistration {
    /// User-defined tag
    pub tag: String,
    /// Cloudflare account ID
    pub account_id: String,
    /// Account license key (for WARP+ upgrade)
    pub license_key: String,
    /// WireGuard private key (base64)
    pub private_key: String,
    /// Peer public key (Cloudflare server)
    pub peer_public_key: String,
    /// WireGuard endpoint (host:port)
    pub endpoint: String,
    /// Reserved bytes (3-byte client identifier)
    pub reserved: [u8; 3],
    /// Interface IPv4 address
    pub ipv4_address: String,
    /// Interface IPv6 address
    pub ipv6_address: String,
    /// Account type (free or plus)
    pub account_type: String,
}

/// WARP+ upgrade request
#[derive(Debug, Clone, Serialize)]
pub struct UpgradeRequest {
    pub license: String,
}

/// API configuration constants
pub mod constants {
    pub const API_BASE: &str = "https://api.cloudflareclient.com";
    pub const API_VERSION: &str = "v0a2158";
    pub const CF_CLIENT_VERSION: &str = "a-6.30";
    pub const USER_AGENT: &str = "rust-router/0.1.0";

    pub const FALLBACK_ENDPOINTS: &[&str] = &[
        "engage.cloudflareclient.com:2408",
        "162.159.192.1:2408",
        "[2606:4700:d0::a29f:c001]:2408",
    ];

    pub const DEFAULT_KEEPALIVE: u16 = 25;
}
