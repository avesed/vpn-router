//! QUIC inbound listener module
//!
//! This module provides a QUIC inbound listener that accepts connections from
//! QUIC clients. It allows rust-router to act as a QUIC server.
//!
//! # Architecture
//!
//! ```text
//! +------------------------------------------------------------------+
//! |                    QuicInboundListener                            |
//! |                                                                  |
//! |  +------------------------+    +---------------------------+     |
//! |  | quinn Endpoint         |    | QuicInboundConnection     |     |
//! |  | - UDP socket           |    | - QUIC stream             |     |
//! |  | - TLS config           |    | - Remote address          |     |
//! |  | - Accept connections   |    |                           |     |
//! |  +------------------------+    +---------------------------+     |
//! |            |                              |                       |
//! |            v                              v                       |
//! |  +------------------------+    +---------------------------+     |
//! |  | QUIC Handshake         |    | Route to outbound         |     |
//! |  | - TLS 1.3              |    | via RuleEngine            |     |
//! |  | - ALPN negotiation     |    |                           |     |
//! |  +------------------------+    +---------------------------+     |
//! +------------------------------------------------------------------+
//! ```
//!
//! # Features
//!
//! - **QUIC Transport**: High-performance multiplexed connections over UDP
//! - **TLS 1.3**: Mandatory encryption with modern TLS
//! - **ALPN**: Application-Layer Protocol Negotiation support
//! - **Multi-stream**: Support for multiple streams per connection
//! - **Graceful Shutdown**: Clean shutdown with connection draining
//! - **Statistics**: Connection and stream counters
//!
//! # Example
//!
//! ## Basic Usage
//!
//! ```no_run
//! use rust_router::quic_inbound::{QuicInboundListener, QuicInboundConfig};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create configuration
//! let config = QuicInboundConfig::new("0.0.0.0:443".parse()?)
//!     .with_cert_path("/path/to/cert.pem")
//!     .with_key_path("/path/to/key.pem")
//!     .with_alpn(vec!["h3"]);
//!
//! // Create listener
//! let listener = QuicInboundListener::new(config).await?;
//!
//! // Accept connections
//! loop {
//!     let (conn, _guard) = listener.accept_with_guard().await?;
//!     println!("Connection from {}", conn.remote_addr());
//!
//!     // Forward to destination...
//! }
//! # }
//! ```
//!
//! ## With PEM Data
//!
//! ```no_run
//! use rust_router::quic_inbound::{QuicInboundListener, QuicInboundConfig};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let cert_pem = std::fs::read_to_string("/path/to/cert.pem")?;
//! let key_pem = std::fs::read_to_string("/path/to/key.pem")?;
//!
//! let config = QuicInboundConfig::new("0.0.0.0:443".parse()?)
//!     .with_cert_pem(cert_pem)
//!     .with_key_pem(key_pem)
//!     .with_alpn(vec!["h3"]);
//!
//! let listener = QuicInboundListener::new(config).await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Connection Flow
//!
//! 1. **UDP Accept**: Accept incoming UDP datagrams
//! 2. **QUIC Handshake**: Complete the QUIC connection handshake (TLS 1.3)
//! 3. **Stream Accept**: Accept bidirectional streams from the connection
//! 4. **Forward Data**: Return connection for bidirectional forwarding
//!
//! # Security Considerations
//!
//! - **TLS 1.3**: QUIC requires TLS 1.3, providing strong encryption
//! - **Valid Certificates**: Use properly signed certificates in production
//! - **ALPN Verification**: Verify ALPN to ensure protocol compatibility
//!
//! # Modules
//!
//! - [`config`]: Configuration types for the QUIC inbound listener
//! - [`error`]: Error types for inbound operations
//! - [`listener`]: The main QUIC inbound listener implementation

#[cfg(feature = "transport-quic")]
pub mod config;
#[cfg(feature = "transport-quic")]
pub mod error;
#[cfg(feature = "transport-quic")]
pub mod listener;

// Re-export commonly used types
#[cfg(feature = "transport-quic")]
pub use config::{QuicInboundConfig, QuicInboundStatus};
#[cfg(feature = "transport-quic")]
pub use error::{QuicInboundError, QuicInboundResult};
#[cfg(feature = "transport-quic")]
pub use listener::{ConnectionGuard, QuicInboundConnection, QuicInboundListener};

// Re-export transport layer types for convenience
#[cfg(feature = "transport-quic")]
pub use crate::transport::quic::{
    QuicConnection, QuicConnectionGuard, QuicInboundStats, QuicInboundStatsSnapshot,
    QuicServerConfig, QuicStream,
};

#[cfg(all(test, feature = "transport-quic"))]
mod tests {
    use super::*;
    use std::sync::Once;

    static INIT_CRYPTO: Once = Once::new();

    fn init_crypto_provider() {
        INIT_CRYPTO.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
    }

    #[test]
    fn test_module_exports() {
        // Verify all types are exported correctly
        let _ = QuicInboundError::NotActive;
        let _ = QuicInboundConfig::default();
        let _ = QuicInboundStatus::default();
    }

    #[test]
    fn test_config_with_builder_pattern() {
        let config = QuicInboundConfig::new("0.0.0.0:443".parse().unwrap())
            .with_cert_path("/path/to/cert.pem")
            .with_key_path("/path/to/key.pem")
            .with_alpn(vec!["h3"])
            .with_enabled(true);

        assert!(config.enabled);
        assert_eq!(config.alpn, vec!["h3"]);
    }

    #[test]
    fn test_error_types() {
        let err = QuicInboundError::NotActive;
        assert!(!err.is_recoverable());

        let err = QuicInboundError::handshake("invalid certificate");
        assert!(err.is_recoverable());

        let addr: std::net::SocketAddr = "127.0.0.1:443".parse().unwrap();
        let err = QuicInboundError::bind_failed(addr, "address in use");
        assert!(!err.is_recoverable());
        assert!(err.to_string().contains("127.0.0.1:443"));
    }

    #[tokio::test]
    async fn test_full_flow() {
        init_crypto_provider();

        // Test certificate PEM (EC P-256)
        let cert_pem = "-----BEGIN CERTIFICATE-----
MIIBdDCCARmgAwIBAgIUD03a2Olf9h4dAKq4JZ0wvvdyVy8wCgYIKoZIzj0EAwIw
DzENMAsGA1UEAwwEdGVzdDAeFw0yNjAxMjQwMzU2MTJaFw0zNjAxMjIwMzU2MTJa
MA8xDTALBgNVBAMMBHRlc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARqAX7m
glRxBt1WVkeu6Xv1DZgQ6auVD6DXsPR4mV5qERVBux0V17EH8+u2f8G7/g5q+kjt
zegGuc0ES6Am/yh1o1MwUTAdBgNVHQ4EFgQUHSw86X0pO16Fimg2rwu9TbSKuE0w
HwYDVR0jBBgwFoAUHSw86X0pO16Fimg2rwu9TbSKuE0wDwYDVR0TAQH/BAUwAwEB
/zAKBggqhkjOPQQDAgNJADBGAiEAlBG5Mg/0+lwJG6NXRBaYyAwPrXmfsdn4Xu4M
DlV6WPACIQDfEQFhvHY+GwxJtD4VwLr9wLomdF8bx8nyE69ttA3QVg==
-----END CERTIFICATE-----
";
        let key_pem = "-----BEGIN EC PRIVATE KEY-----
MHcCAQEEINqlpC+I/zCwt3mMtoL76ZRT/gjmCAQ2K0RoeR0RpTJmoAoGCCqGSM49
AwEHoUQDQgAEagF+5oJUcQbdVlZHrul79Q2YEOmrlQ+g17D0eJleahEVQbsdFdex
B/Prtn/Bu/4OavpI7c3oBrnNBEugJv8odQ==
-----END EC PRIVATE KEY-----
";

        // Create config with PEM data
        let config = QuicInboundConfig::new("127.0.0.1:0".parse().unwrap())
            .with_cert_pem(cert_pem)
            .with_key_pem(key_pem)
            .with_alpn(vec!["h3"]);

        // Validate config
        assert!(config.validate().is_ok());

        // Create listener
        let listener = QuicInboundListener::new(config).await.unwrap();
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
