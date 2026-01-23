//! REALITY protocol implementation
//!
//! REALITY is a TLS 1.3 camouflage protocol that makes connections look like
//! legitimate HTTPS traffic to a target website (e.g., google.com). It provides
//! strong obfuscation against deep packet inspection (DPI) while maintaining
//! efficient performance.
//!
//! # Architecture
//!
//! This implementation is organized into the following modules:
//!
//! - [`common`]: TLS 1.3 constants and shared utilities
//! - [`crypto`]: Cryptographic primitives (AEAD, HKDF, X25519)
//! - [`tls`]: TLS 1.3 message construction and record layer
//! - [`auth`]: REALITY-specific authentication (SessionId, short_id)
//! - [`client`]: Client-side connection handling
//! - [`stream`]: Async I/O wrappers
//! - [`config`]: Configuration types
//! - [`error`]: Error types
//!
//! # How REALITY Works
//!
//! 1. **Client Hello**: Client generates an X25519 ephemeral key pair and sends
//!    a TLS 1.3 `ClientHello` that perfectly mimics a real browser (Chrome, Firefox, etc.)
//!
//! 2. **Server Authentication**: The server validates the client's `short_id` and
//!    derives a shared secret using X25519 key exchange with the client's ephemeral
//!    public key
//!
//! 3. **Key Derivation**: Both sides derive encryption keys from the shared secret
//!    using HKDF, following the TLS 1.3 key schedule
//!
//! 4. **Data Transfer**: Subsequent data is encrypted with the derived keys,
//!    making the connection indistinguishable from legitimate TLS traffic
//!
//! # Configuration Example
//!
//! ```no_run
//! use rust_router::reality::{RealityConfig, RealityConnector};
//!
//! // Using the high-level connector
//! let connector = RealityConnector::from_encoded(
//!     "UuMBgl7MXTPCQo57FPi4gkLxvkJedeWFWW2oU1hwGDA=",  // Server public key
//!     "12345678",                                        // Short ID
//!     "www.google.com",                                  // SNI
//! ).expect("Invalid configuration");
//!
//! // Or using the legacy config type
//! let config = RealityConfig::new(
//!     "www.google.com",
//!     "UuMBgl7MXTPCQo57FPi4gkLxvkJedeWFWW2oU1hwGDA=",
//!     "12345678",
//! );
//! config.validate().expect("Invalid configuration");
//! ```
//!
//! # Security Properties
//!
//! - **Indistinguishable from TLS**: Traffic analysis cannot distinguish REALITY
//!   connections from legitimate HTTPS connections to the camouflage target
//!
//! - **Forward Secrecy**: Each connection uses a fresh ephemeral key pair
//!
//! - **Replay Protection**: The handshake includes timestamps and random values
//!   to prevent replay attacks
//!
//! - **Active Probing Resistance**: Unauthenticated connections are proxied to
//!   the real camouflage target, making active probing ineffective
//!
//! # Implementation Notes
//!
//! This implementation is ported from the shoes project (MIT license):
//! <https://github.com/cfal/shoes>
//!
//! Key differences from the original:
//! - Uses pure Rust cryptographic crates (aes-gcm, chacha20poly1305, sha2, hkdf)
//!   instead of aws-lc-rs
//! - Simplified module structure
//! - Added async stream wrappers for tokio integration
//!
//! # References
//!
//! - shoes: <https://github.com/cfal/shoes> (MIT license, Rust implementation)
//! - xray-core: <https://github.com/XTLS/Xray-core> (MPL-2.0, Go reference implementation)
//! - REALITY protocol spec: <https://github.com/XTLS/REALITY>
//! - RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3

// Core modules
mod common;
mod config;
mod error;

// Submodule hierarchies
pub mod crypto;
pub mod tls;

// Protocol implementation
mod auth;
mod client;
mod stream;

// =============================================================================
// Public exports
// =============================================================================

// Configuration types
pub use config::RealityConfig;
pub use error::{RealityError, RealityResult};

// Constants
pub use common::{
    AEAD_TAG_SIZE, CONTENT_TYPE_APPLICATION_DATA, CONTENT_TYPE_HANDSHAKE,
    MAX_TLS_CIPHERTEXT_LEN, MAX_TLS_PLAINTEXT_LEN, NONCE_SIZE, REALITY_AUTH_INFO,
    REALITY_DEFAULT_MAX_TIME_DIFF_MS, REALITY_SHORT_ID_SIZE, TLS_MAX_RECORD_SIZE,
    TLS_RECORD_HEADER_SIZE,
};

// Crypto primitives
pub use crypto::{
    AeadKey, CipherSuite, DEFAULT_CIPHER_SUITES, Tls13HandshakeKeys,
    compute_finished_verify_data, derive_application_secrets, derive_handshake_keys,
    derive_traffic_keys, generate_keypair, perform_ecdh, X25519KeyPair, X25519PublicKey,
};

// TLS message handling
pub use tls::{
    construct_client_hello, construct_encrypted_extensions, construct_finished,
    construct_server_hello, extract_server_cipher_suite, extract_server_public_key,
    write_record_header, RecordDecryptor, RecordEncryptor, DEFAULT_ALPN_PROTOCOLS,
};

// Authentication
pub use auth::{
    current_timestamp, decode_short_id, decrypt_session_id, derive_auth_key,
    encrypt_session_id, validate_auth, SessionId,
};

// Client connection
pub use client::{FeedResult, RealityClientConfig, RealityClientConnection};

// Async stream wrappers
pub use stream::{RealityConnector, RealityStream};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_exports() {
        // Verify that the public types are exported correctly
        let config = RealityConfig::new(
            "www.google.com",
            "UuMBgl7MXTPCQo57FPi4gkLxvkJedeWFWW2oU1hwGDA=",
            "12345678",
        );

        assert_eq!(config.server_name(), "www.google.com");
        assert_eq!(config.fingerprint(), "chrome");

        // Verify error types are exported
        let error = RealityError::handshake("test");
        assert!(error.to_string().contains("Handshake"));
    }

    #[test]
    fn test_config_validation_integration() {
        // Valid config
        let config = RealityConfig::new(
            "www.google.com",
            "UuMBgl7MXTPCQo57FPi4gkLxvkJedeWFWW2oU1hwGDA=",
            "12345678",
        );
        assert!(config.validate().is_ok());

        // Invalid config - empty server name
        let config = RealityConfig::new(
            "",
            "UuMBgl7MXTPCQo57FPi4gkLxvkJedeWFWW2oU1hwGDA=",
            "12345678",
        );
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_error_result_type() {
        // Verify RealityResult type alias works
        fn example_function() -> RealityResult<()> {
            let config = RealityConfig::new(
                "www.google.com",
                "UuMBgl7MXTPCQo57FPi4gkLxvkJedeWFWW2oU1hwGDA=",
                "12345678",
            );
            config.validate()?;
            Ok(())
        }

        assert!(example_function().is_ok());
    }

    #[test]
    fn test_crypto_exports() {
        // Test that crypto exports work
        let keypair = generate_keypair();
        let public_key = keypair.public_key();
        assert_eq!(public_key.as_bytes().len(), 32);

        // Test cipher suite
        let cs = CipherSuite::AES_128_GCM_SHA256;
        assert_eq!(cs.key_len(), 16);
        assert_eq!(cs.nonce_len(), 12);
    }

    #[test]
    fn test_auth_exports() {
        // Test SessionId
        let session_id = SessionId::new([1, 8, 1], [0xAB; 8]);
        let plaintext = session_id.to_plaintext();
        assert_eq!(plaintext.len(), 16);

        // Test decode_short_id
        let short_id = decode_short_id("1234567890abcdef").unwrap();
        assert_eq!(short_id.len(), 8);
    }

    #[test]
    fn test_tls_exports() {
        // Test message construction
        let verify_data = vec![0x42u8; 32];
        let finished = construct_finished(&verify_data).unwrap();
        assert_eq!(finished[0], 20); // Finished message type

        // Test record header
        let header = write_record_header(0x17, 100);
        assert_eq!(header.len(), 5);
    }

    #[test]
    fn test_client_exports() {
        // Test client config
        let config = RealityClientConfig::new(
            [0x42u8; 32],
            [0xABu8; 8],
            "www.google.com".to_string(),
        );

        assert_eq!(config.server_name, "www.google.com");

        // Test client connection creation
        let conn = RealityClientConnection::new(config);
        assert!(!conn.is_established());
        assert!(conn.is_handshaking());
    }

    #[test]
    fn test_connector_export() {
        // Test RealityConnector
        let result = RealityConnector::from_encoded(
            "UuMBgl7MXTPCQo57FPi4gkLxvkJedeWFWW2oU1hwGDA=",
            "12345678",
            "www.google.com",
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_constants_exported() {
        // Test that constants are accessible
        assert_eq!(MAX_TLS_PLAINTEXT_LEN, 16384);
        assert_eq!(TLS_RECORD_HEADER_SIZE, 5);
        assert_eq!(AEAD_TAG_SIZE, 16);
        assert_eq!(NONCE_SIZE, 12);
        assert_eq!(REALITY_SHORT_ID_SIZE, 8);
    }
}
