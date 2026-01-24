//! VLESS inbound listener module
//!
//! This module provides a VLESS inbound listener that accepts connections from
//! VLESS clients. It allows the rust-router to act as a VLESS server, similar
//! to how xray-lite works.
//!
//! # Architecture
//!
//! ```text
//! +------------------------------------------------------------------+
//! |                     VlessInboundListener                         |
//! |                                                                  |
//! |  +------------------------+    +---------------------------+     |
//! |  | TCP Listener           |    | VlessConnectionHandler    |     |
//! |  | - Accept connections   |    | - Read VLESS header       |     |
//! |  | - Optional TLS         |    | - Validate UUID           |     |
//! |  +------------------------+    | - Send response           |     |
//! |            |                   +---------------------------+     |
//! |            v                              |                       |
//! |  +------------------------+              v                       |
//! |  | TLS Acceptor           |    +---------------------------+     |
//! |  | (optional)             |    | VlessConnection           |     |
//! |  | - Certificate loading  |    | - Authenticated user      |     |
//! |  | - ALPN protocols       |    | - Destination info        |     |
//! |  +------------------------+    | - Stream for forwarding   |     |
//! |                                +---------------------------+     |
//! +------------------------------------------------------------------+
//! ```
//!
//! # Features
//!
//! - **UUID Authentication**: Validate client UUIDs against a configured user list
//! - **TLS Support**: Optional TLS encryption with certificate and key loading
//! - **XTLS-Vision**: Support for XTLS-Vision flow control
//! - **Fallback**: Forward non-VLESS connections to a fallback address
//! - **Graceful Shutdown**: Clean shutdown with connection draining
//!
//! # Example
//!
//! ## Basic Usage
//!
//! ```no_run
//! use rust_router::vless_inbound::{VlessInboundListener, VlessInboundConfig, VlessUser};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create configuration
//! let config = VlessInboundConfig::new("0.0.0.0:443".parse()?)
//!     .with_user(VlessUser::new(
//!         "550e8400-e29b-41d4-a716-446655440000",
//!         Some("admin@example.com"),
//!     ));
//!
//! // Create listener
//! let listener = VlessInboundListener::new(config).await?;
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
//! ## With TLS
//!
//! ```no_run
//! use rust_router::vless_inbound::{
//!     VlessInboundListener, VlessInboundConfig, VlessUser, InboundTlsConfig
//! };
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = VlessInboundConfig::new("0.0.0.0:443".parse()?)
//!     .with_user(VlessUser::new(
//!         "550e8400-e29b-41d4-a716-446655440000",
//!         Some("admin"),
//!     ))
//!     .with_tls(
//!         InboundTlsConfig::new("/path/to/cert.pem", "/path/to/key.pem")
//!             .with_alpn(vec!["h2", "http/1.1"])
//!     );
//!
//! let listener = VlessInboundListener::new(config).await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## With Fallback
//!
//! ```no_run
//! use rust_router::vless_inbound::{VlessInboundListener, VlessInboundConfig, VlessUser};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Non-VLESS connections will be forwarded to the fallback
//! let config = VlessInboundConfig::new("0.0.0.0:443".parse()?)
//!     .with_user(VlessUser::new(
//!         "550e8400-e29b-41d4-a716-446655440000",
//!         Some("admin"),
//!     ))
//!     .with_fallback("127.0.0.1:80".parse()?);
//!
//! let listener = VlessInboundListener::new(config).await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Connection Flow
//!
//! 1. **TCP Accept**: Accept incoming TCP connection
//! 2. **TLS Handshake** (optional): Perform TLS handshake if configured
//! 3. **Read VLESS Header**: Parse the VLESS request header
//!    - Version (must be 0)
//!    - UUID (validate against allowed users)
//!    - Addons (parse flow type)
//!    - Command (TCP/UDP)
//!    - Destination address
//! 4. **Send Response**: Send VLESS response header (version + empty addons)
//! 5. **Forward Data**: Return authenticated connection for bidirectional forwarding
//!
//! # Security Considerations
//!
//! - **Always use TLS**: VLESS transmits the UUID in plaintext, so transport
//!   encryption is essential for security
//! - **Treat UUIDs as secrets**: They are the sole authentication credential
//! - **Use XTLS-Vision**: For additional traffic obfuscation
//! - **Fallback disguise**: Configure fallback to disguise the server as
//!   a normal web server
//!
//! # Modules
//!
//! - [`config`]: Configuration types for the VLESS inbound listener
//! - [`error`]: Error types for inbound operations
//! - [`handler`]: Connection handler for processing VLESS requests
//! - [`listener`]: The main VLESS inbound listener implementation

pub mod config;
pub mod error;
pub mod handler;
pub mod listener;

// Re-export commonly used types
pub use config::{InboundRealityConfig, InboundTlsConfig, VlessInboundConfig, VlessUser};
pub use error::{VlessInboundError, VlessInboundResult};
pub use handler::{AuthenticatedUser, VlessConnection, VlessConnectionHandler, VlessDestination};
pub use listener::{VlessInboundListener, VlessInboundStats};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_exports() {
        // Verify all types are exported correctly
        let _ = VlessInboundError::AuthenticationFailed;
        let _ = VlessInboundConfig::default();
        let _ = VlessUser::new("550e8400-e29b-41d4-a716-446655440000", Some("test"));
        let _ = InboundTlsConfig::new("/cert.pem", "/key.pem");
        let _ = VlessInboundStats::new();
    }

    #[test]
    fn test_config_with_builder_pattern() {
        let config = VlessInboundConfig::new("0.0.0.0:443".parse().unwrap())
            .with_user(VlessUser::new(
                "550e8400-e29b-41d4-a716-446655440000",
                Some("user1"),
            ))
            .with_user(VlessUser::new(
                "660e8400-e29b-41d4-a716-446655440000",
                Some("user2"),
            ))
            .with_tls(
                InboundTlsConfig::new("/path/to/cert.pem", "/path/to/key.pem")
                    .with_alpn(vec!["h2", "http/1.1"]),
            )
            .with_fallback("127.0.0.1:80".parse().unwrap());

        assert_eq!(config.users.len(), 2);
        assert!(config.has_tls());
        assert!(config.has_fallback());
    }

    #[tokio::test]
    async fn test_full_flow() {
        // Create config with valid user
        let config = VlessInboundConfig::new("127.0.0.1:0".parse().unwrap()).with_user(
            VlessUser::new("550e8400-e29b-41d4-a716-446655440000", Some("test")),
        );

        // Validate config
        assert!(config.validate().is_ok());

        // Build account manager
        let account_manager = config.build_account_manager().unwrap();
        assert_eq!(account_manager.len(), 1);

        // Create listener
        let listener = VlessInboundListener::new(config).await.unwrap();
        assert!(listener.is_active());
        assert_eq!(listener.user_count(), 1);

        // Shutdown
        listener.shutdown();
    }

    #[test]
    fn test_vless_user_with_flow() {
        let user = VlessUser::new("550e8400-e29b-41d4-a716-446655440000", Some("test"))
            .with_flow("xtls-rprx-vision");

        assert_eq!(user.uuid, "550e8400-e29b-41d4-a716-446655440000");
        assert_eq!(user.email, Some("test".to_string()));
        assert_eq!(user.flow, Some("xtls-rprx-vision".to_string()));
    }

    #[test]
    fn test_error_types() {
        let err = VlessInboundError::AuthenticationFailed;
        assert!(!err.is_recoverable());

        let err = VlessInboundError::tls_handshake("protocol error");
        assert!(err.is_recoverable());

        let addr: std::net::SocketAddr = "127.0.0.1:443".parse().unwrap();
        let err = VlessInboundError::bind_failed(addr, "address in use");
        assert!(!err.is_recoverable());
        assert!(err.to_string().contains("127.0.0.1:443"));
    }
}
