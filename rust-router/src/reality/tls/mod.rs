//! TLS 1.3 protocol implementation for REALITY
//!
//! This module provides:
//! - TLS 1.3 message construction and parsing
//! - Record layer encryption/decryption

mod messages;
mod records;

pub use messages::{
    construct_client_hello, construct_encrypted_extensions, construct_finished,
    construct_server_hello, extract_client_public_key, extract_client_random,
    extract_server_cipher_suite, extract_server_public_key, extract_session_id,
    write_record_header, DEFAULT_ALPN_PROTOCOLS,
};
pub use records::{RecordDecryptor, RecordEncryptor};
