//! Cryptographic primitives for REALITY protocol
//!
//! This module provides:
//! - AEAD encryption (AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305)
//! - TLS 1.3 key derivation (HKDF)
//! - X25519 key exchange
//! - Cipher suite definitions

mod aead;
mod keys;
pub mod x25519;
pub mod cipher_suite;

pub use aead::{AeadKey, decrypt_handshake_message};
pub use cipher_suite::{CipherSuite, HashAlgorithm, DEFAULT_CIPHER_SUITES};
pub use keys::{
    compute_finished_verify_data, derive_application_secrets, derive_handshake_keys,
    derive_traffic_keys, Tls13HandshakeKeys,
};
pub use x25519::{
    decode_public_key, encode_public_key, generate_keypair, perform_ecdh, random_bytes,
    X25519KeyPair, X25519PublicKey,
};
