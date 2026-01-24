//! Shadowsocks protocol support
//!
//! This module provides Shadowsocks client (outbound) functionality for rust-router.
//! Shadowsocks is a secure proxy protocol designed for privacy and efficiency.
//!
//! # Supported Features
//!
//! - **AEAD 2022 Ciphers** (recommended):
//!   - `2022-blake3-aes-256-gcm` (default, most secure)
//!   - `2022-blake3-aes-128-gcm`
//!   - `2022-blake3-chacha20-poly1305`
//!
//! - **Legacy AEAD Ciphers**:
//!   - `aes-256-gcm`
//!   - `aes-128-gcm`
//!   - `chacha20-ietf-poly1305`
//!
//! # Not Yet Implemented
//!
//! - Shadowsocks inbound (server mode)
//! - UDP relay support
//! - QUIC transport for Shadowsocks
//! - SIP003 plugin support
//!
//! # Example
//!
//! ```ignore
//! use rust_router::shadowsocks::{ShadowsocksOutboundConfig, ShadowsocksMethod};
//!
//! let config = ShadowsocksOutboundConfig::new("ss.example.com", 8388, "password")
//!     .with_method(ShadowsocksMethod::Aead2022Blake3Aes256Gcm);
//! ```
//!
//! # Security Recommendations
//!
//! 1. Always use AEAD 2022 ciphers when possible - they provide better security
//!    and resistance against replay attacks.
//!
//! 2. Use strong, randomly generated passwords. For AEAD 2022, the password
//!    should be a Base64-encoded key of the appropriate length (32 bytes for
//!    AES-256, 16 bytes for AES-128).
//!
//! 3. Never use `method: none` in production - it provides no encryption.

mod config;
mod error;

pub use config::{ShadowsocksMethod, ShadowsocksOutboundConfig, ShadowsocksOutboundInfo};
pub use error::ShadowsocksError;
