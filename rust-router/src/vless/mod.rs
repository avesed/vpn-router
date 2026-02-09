//! VLESS protocol implementation for rust-router
//!
//! This module provides a complete implementation of the VLESS protocol,
//! a lightweight proxy protocol designed for high performance with minimal
//! overhead. VLESS is commonly used with XTLS-Vision for advanced traffic
//! obfuscation.
//!
//! # Protocol Overview
//!
//! VLESS uses UUID-based authentication and supports TCP, UDP, and multiplexed
//! connections. The protocol consists of:
//!
//! - **Request Header**: Version + UUID + Addons + Command + Destination
//! - **Response Header**: Version + Addons
//! - **Data Payload**: Raw traffic after headers
//!
//! # Wire Format
//!
//! ## Request Header
//!
//! ```text
//! +--------+-------+----------+---------+----------+
//! | Version|  UUID |  Addons  | Command | Port+Addr|
//! +--------+-------+----------+---------+----------+
//! |   1B   |  16B  | Variable |   1B    | Variable |
//! +--------+-------+----------+---------+----------+
//! ```
//!
//! ## Response Header
//!
//! ```text
//! +--------+----------+
//! | Version|  Addons  |
//! +--------+----------+
//! |   1B   | Variable |
//! +--------+----------+
//! ```
//!
//! # Features
//!
//! - **UUID Authentication**: 16-byte RFC 4122 UUID for user identification
//! - **XTLS-Vision Support**: Flow control addons for traffic obfuscation
//! - **Multiple Commands**: TCP (0x01), UDP (0x02), MUX (0x03)
//! - **Flexible Addressing**: IPv4, IPv6, and domain name support
//! - **Zero-Copy Parsing**: Efficient async I/O with minimal allocations
//!
//! # Example Usage
//!
//! ## Server-side: Reading Requests
//!
//! ```no_run
//! use rust_router::vless::{VlessRequestHeader, VlessResponseHeader, VlessAccountManager, VlessAccount};
//! use tokio::net::TcpListener;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Set up account manager
//! let mut accounts = VlessAccountManager::new();
//! accounts.add_account(VlessAccount::new("admin@example.com"));
//!
//! let listener = TcpListener::bind("127.0.0.1:443").await?;
//! let (mut stream, _) = listener.accept().await?;
//!
//! // Read and validate request
//! let request = VlessRequestHeader::read_from(&mut stream).await?;
//!
//! // Authenticate
//! if accounts.validate_uuid(&request.uuid).is_none() {
//!     // Close connection - unknown user
//!     return Ok(());
//! }
//!
//! // Process command
//! match request.command {
//!     rust_router::vless::VlessCommand::Tcp => {
//!         // Connect to destination and relay traffic
//!         let response = VlessResponseHeader::minimal();
//!         response.write_to(&mut stream).await?;
//!         // ... relay data ...
//!     }
//!     _ => { /* Handle UDP/MUX */ }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Client-side: Sending Requests
//!
//! ```no_run
//! use rust_router::vless::{VlessRequestHeader, VlessResponseHeader, VlessAddress, VlessCommand, VlessAddons};
//! use tokio::net::TcpStream;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let mut stream = TcpStream::connect("proxy.example.com:443").await?;
//!
//! // Create request header
//! let uuid = [0x55u8; 16]; // Your UUID
//! let request = VlessRequestHeader::with_addons(
//!     uuid,
//!     VlessAddons::with_xtls_vision(),
//!     VlessCommand::Tcp,
//!     VlessAddress::domain("google.com"),
//!     443,
//! );
//!
//! // Send request
//! request.write_to(&mut stream).await?;
//!
//! // Read response
//! let response = VlessResponseHeader::read_from(&mut stream).await?;
//!
//! // Now relay application data...
//! # Ok(())
//! # }
//! ```
//!
//! # Modules
//!
//! - [`error`]: Error types for VLESS protocol operations
//! - [`addons`]: Protobuf-like addon encoding (flow control)
//! - [`account`]: UUID-based user account management
//! - [`protocol`]: Wire protocol encoding and decoding
//!
//! # Security Considerations
//!
//! VLESS transmits the UUID in plaintext in the request header. For security:
//!
//! 1. **Always use TLS or REALITY** for transport encryption
//! 2. **Treat UUIDs as secrets** - they are the authentication credential
//! 3. **Use XTLS-Vision** for additional traffic obfuscation
//!
//! # Reference Implementations
//!
//! This implementation is based on:
//! - [Xray-core](https://github.com/XTLS/Xray-core) - Official Go implementation
//! - [shoes](https://github.com/cfal/shoes) - MIT-licensed Rust reference

pub mod account;
pub mod addons;
pub mod error;
pub mod protocol;
pub mod stream;

// Re-export commonly used types at module level
pub use account::{VlessAccount, VlessAccountManager};
pub use addons::{encode_flow_addon, parse_addons, VlessAddons, XTLS_VISION_FLOW};
pub use error::VlessError;
pub use protocol::{
    address_type, VlessAddress, VlessCommand, VlessRequestHeader, VlessResponseHeader,
    VLESS_VERSION,
};
pub use stream::VlessStream;

/// VLESS protocol constants
pub mod constants {
    /// VLESS protocol version (always 0)
    pub const VERSION: u8 = super::VLESS_VERSION;

    /// TCP command byte
    pub const COMMAND_TCP: u8 = 0x01;

    /// UDP command byte
    pub const COMMAND_UDP: u8 = 0x02;

    /// MUX command byte
    pub const COMMAND_MUX: u8 = 0x03;

    /// IPv4 address type
    pub const ATYP_IPV4: u8 = 0x01;

    /// Domain address type
    pub const ATYP_DOMAIN: u8 = 0x02;

    /// IPv6 address type
    pub const ATYP_IPV6: u8 = 0x03;

    /// XTLS-Vision flow identifier
    pub const FLOW_XTLS_VISION: &str = super::XTLS_VISION_FLOW;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::net::Ipv4Addr;

    #[test]
    fn test_module_exports() {
        // Verify all types are exported correctly
        let _ = VlessError::InvalidVersion(0);
        let _ = VlessAddons::new();
        let _ = VlessAccount::new("test");
        let _ = VlessAccountManager::new();
        let _ = VlessCommand::Tcp;
        let _ = VlessAddress::domain("test");
        let _ = VLESS_VERSION;
        let _ = XTLS_VISION_FLOW;
    }

    #[test]
    fn test_constants() {
        assert_eq!(constants::VERSION, 0);
        assert_eq!(constants::COMMAND_TCP, 0x01);
        assert_eq!(constants::COMMAND_UDP, 0x02);
        assert_eq!(constants::COMMAND_MUX, 0x03);
        assert_eq!(constants::ATYP_IPV4, 0x01);
        assert_eq!(constants::ATYP_DOMAIN, 0x02);
        assert_eq!(constants::ATYP_IPV6, 0x03);
        assert_eq!(constants::FLOW_XTLS_VISION, "xtls-rprx-vision");
    }

    #[tokio::test]
    async fn test_full_request_response_cycle() {
        // Create account manager and account
        let mut manager = VlessAccountManager::new();
        let account = VlessAccount::new("test@example.com");
        let uuid = account.id_bytes();
        manager.add_account(account);

        // Create request
        let request = VlessRequestHeader::with_addons(
            uuid,
            VlessAddons::with_xtls_vision(),
            VlessCommand::Tcp,
            VlessAddress::ipv4(Ipv4Addr::new(8, 8, 8, 8)),
            443,
        );

        // Encode request
        let encoded_request = request.encode().unwrap();

        // Decode request (simulating server)
        let mut cursor = Cursor::new(encoded_request);
        let decoded_request = VlessRequestHeader::read_from(&mut cursor).await.unwrap();

        // Validate UUID
        assert!(manager.validate_uuid(&decoded_request.uuid).is_some());

        // Check request details
        assert_eq!(decoded_request.command, VlessCommand::Tcp);
        assert!(decoded_request.addons.is_xtls_vision());
        assert_eq!(
            decoded_request.address.as_ipv4(),
            Some(Ipv4Addr::new(8, 8, 8, 8))
        );
        assert_eq!(decoded_request.port, 443);

        // Create response
        let response = VlessResponseHeader::minimal();
        let encoded_response = response.encode().unwrap();

        // Verify response can be decoded
        let mut cursor = Cursor::new(encoded_response);
        let decoded_response = VlessResponseHeader::read_from(&mut cursor).await.unwrap();
        assert_eq!(decoded_response.version, VLESS_VERSION);
    }

    #[test]
    fn test_encode_flow_addon_export() {
        let encoded = encode_flow_addon("test-flow").unwrap();
        assert!(!encoded.is_empty());

        let (parsed, _) = parse_addons(&encoded).unwrap();
        assert_eq!(parsed.flow, Some("test-flow".to_string()));
    }

    #[test]
    fn test_address_type_constants() {
        assert_eq!(address_type::IPV4, constants::ATYP_IPV4);
        assert_eq!(address_type::DOMAIN, constants::ATYP_DOMAIN);
        assert_eq!(address_type::IPV6, constants::ATYP_IPV6);
    }
}
