//! Protocol sniffing module
//!
//! This module provides protocol detection and parsing capabilities,
//! primarily for extracting TLS SNI (Server Name Indication) from
//! ClientHello messages.
//!
//! # Supported Protocols
//!
//! - TLS: SNI extraction from ClientHello
//! - HTTP: Host header extraction (future)
//! - QUIC: SNI extraction (future)
//!
//! # Example
//!
//! ```
//! use rust_router::sniff::{sniff_tls_sni, looks_like_tls};
//!
//! let data = [/* TLS ClientHello bytes */];
//!
//! if looks_like_tls(&data) {
//!     if let Some(sni) = sniff_tls_sni(&data) {
//!         println!("TLS connection to: {}", sni);
//!     }
//! }
//! ```

mod result;
mod tls;

pub use result::{Protocol, SniffResult};
pub use tls::{looks_like_tls, sniff_tls_sni};
