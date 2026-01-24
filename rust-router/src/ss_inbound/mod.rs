//! Shadowsocks inbound listener module
//!
//! This module provides a Shadowsocks inbound listener that accepts connections from
//! Shadowsocks clients. It allows rust-router to act as a Shadowsocks server.
//!
//! # Architecture
//!
//! ```text
//! +------------------------------------------------------------------+
//! |                  ShadowsocksInboundListener                       |
//! |                                                                  |
//! |  +------------------------+    +---------------------------+     |
//! |  | ProxyListener          |    | ShadowsocksConnection     |     |
//! |  | (shadowsocks crate)    |    | - Decrypted stream        |     |
//! |  | - Accept connections   |    | - Target address          |     |
//! |  | - Decrypt traffic      |    | - Client address          |     |
//! |  +------------------------+    +---------------------------+     |
//! |            |                              |                       |
//! |            v                              v                       |
//! |  +------------------------+    +---------------------------+     |
//! |  | Handshake              |    | Route to outbound         |     |
//! |  | - Read target address  |    | via RuleEngine            |     |
//! |  +------------------------+    +---------------------------+     |
//! +------------------------------------------------------------------+
//! ```
//!
//! # Features
//!
//! - **AEAD Encryption**: Supports both AEAD 2022 and legacy AEAD ciphers
//! - **Multiple Methods**: aes-256-gcm, aes-128-gcm, chacha20-ietf-poly1305, and 2022 variants
//! - **Graceful Shutdown**: Clean shutdown with connection draining
//! - **Statistics**: Connection and byte counters
//!
//! # Example
//!
//! ## Basic Usage
//!
//! ```no_run
//! use rust_router::ss_inbound::{ShadowsocksInboundListener, ShadowsocksInboundConfig};
//! use rust_router::shadowsocks::ShadowsocksMethod;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create configuration
//! let config = ShadowsocksInboundConfig::new(
//!     "0.0.0.0:8388".parse()?,
//!     "my-secret-password",
//! ).with_method(ShadowsocksMethod::Aes256Gcm);
//!
//! // Create listener
//! let listener = ShadowsocksInboundListener::new(config).await?;
//!
//! // Accept connections
//! loop {
//!     let conn = listener.accept().await?;
//!     println!("Connection from {} to {}",
//!         conn.client_addr(),
//!         conn.destination());
//!
//!     // Forward to destination...
//! }
//! # }
//! ```
//!
//! ## With AEAD 2022
//!
//! ```no_run
//! use rust_router::ss_inbound::{ShadowsocksInboundListener, ShadowsocksInboundConfig};
//! use rust_router::shadowsocks::ShadowsocksMethod;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Generate a 32-byte key and Base64 encode it
//! let key = base64::Engine::encode(
//!     &base64::engine::general_purpose::STANDARD,
//!     &[0u8; 32], // Use a secure random key in production!
//! );
//!
//! let config = ShadowsocksInboundConfig::new(
//!     "0.0.0.0:8388".parse()?,
//!     key,
//! ).with_method(ShadowsocksMethod::Aead2022Blake3Aes256Gcm);
//!
//! let listener = ShadowsocksInboundListener::new(config).await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Connection Flow
//!
//! 1. **TCP Accept**: Accept incoming TCP connection
//! 2. **Decrypt Stream**: Create encrypted stream using ProxyListener
//! 3. **Handshake**: Read target address from the Shadowsocks header
//! 4. **Forward Data**: Return connection for bidirectional forwarding
//!
//! # Security Considerations
//!
//! - **Use AEAD 2022**: Prefer 2022-blake3-aes-256-gcm for better security
//! - **Strong Passwords**: Use randomly generated passwords/keys
//! - **Key Length**: AEAD 2022 requires proper key lengths (32 bytes for AES-256)
//!
//! # Modules
//!
//! - [`config`]: Configuration types for the Shadowsocks inbound listener
//! - [`error`]: Error types for inbound operations
//! - [`handler`]: Connection types and destination handling
//! - [`listener`]: The main Shadowsocks inbound listener implementation

pub mod config;
pub mod error;
pub mod handler;
#[cfg(feature = "shadowsocks")]
pub mod listener;
#[cfg(feature = "shadowsocks")]
pub mod udp_relay;

// Re-export commonly used types
pub use config::{ShadowsocksInboundConfig, ShadowsocksInboundStatus};
pub use error::{ShadowsocksInboundError, ShadowsocksInboundResult};
pub use handler::{ConnectionStats, ShadowsocksConnection, ShadowsocksDestination};
#[cfg(feature = "shadowsocks")]
pub use listener::{
    ConnectionGuard, ShadowsocksInboundListener, ShadowsocksInboundStats,
    ShadowsocksInboundStatsSnapshot,
};
#[cfg(feature = "shadowsocks")]
pub use udp_relay::{
    SsUdpPacket, SsUdpRelayInbound, SsUdpRelayStats, SsUdpRelayStatsSnapshot, UdpRelaySession,
    DEFAULT_CLEANUP_INTERVAL_SECS, SESSION_CLEANUP_THRESHOLD,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shadowsocks::ShadowsocksMethod;

    #[test]
    fn test_module_exports() {
        // Verify all types are exported correctly
        let _ = ShadowsocksInboundError::NotActive;
        let _ = ShadowsocksInboundConfig::default();
        let _ = ShadowsocksInboundStatus::default();
        let _ = ShadowsocksDestination::from_domain("example.com", 443);
    }

    #[test]
    fn test_config_with_builder_pattern() {
        let config = ShadowsocksInboundConfig::new("0.0.0.0:8388".parse().unwrap(), "password")
            .with_method(ShadowsocksMethod::Aes256Gcm)
            .with_udp(true)
            .with_enabled(true);

        assert!(config.enabled);
        assert_eq!(config.method, ShadowsocksMethod::Aes256Gcm);
        assert!(config.udp_enabled);
    }

    #[test]
    fn test_destination_types() {
        let socket_dest =
            ShadowsocksDestination::from_socket_addr("192.168.1.1:443".parse().unwrap());
        assert_eq!(socket_dest.port(), 443);
        assert!(socket_dest.as_socket_addr().is_some());

        let domain_dest = ShadowsocksDestination::from_domain("example.com", 80);
        assert_eq!(domain_dest.port(), 80);
        assert!(domain_dest.as_socket_addr().is_none());
    }

    #[test]
    fn test_error_types() {
        let err = ShadowsocksInboundError::NotActive;
        assert!(!err.is_recoverable());

        let err = ShadowsocksInboundError::protocol_error("invalid header");
        assert!(err.is_recoverable());

        let addr: std::net::SocketAddr = "127.0.0.1:8388".parse().unwrap();
        let err = ShadowsocksInboundError::bind_failed(addr, "address in use");
        assert!(!err.is_recoverable());
        assert!(err.to_string().contains("127.0.0.1:8388"));
    }

    #[cfg(feature = "shadowsocks")]
    #[tokio::test]
    async fn test_full_flow() {
        // Create config with legacy AEAD (accepts plaintext password)
        let config =
            ShadowsocksInboundConfig::new("127.0.0.1:0".parse().unwrap(), "test-password")
                .with_method(ShadowsocksMethod::Aes256Gcm);

        // Validate config
        assert!(config.validate().is_ok());

        // Create listener
        let listener = ShadowsocksInboundListener::new(config).await.unwrap();
        assert!(listener.is_active());

        // Get local address
        let local_addr = listener.local_addr().unwrap();
        assert!(local_addr.port() > 0);

        // Check stats
        let stats = listener.stats_snapshot();
        assert_eq!(stats.connections_accepted, 0);

        // Shutdown
        listener.shutdown();
        assert!(!listener.is_active());
    }
}
