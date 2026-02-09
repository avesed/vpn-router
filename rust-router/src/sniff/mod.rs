//! Protocol sniffing module
//!
//! This module provides protocol detection and parsing capabilities,
//! primarily for extracting SNI (Server Name Indication) from
//! TLS `ClientHello` and QUIC Initial packets, as well as HTTP Host headers.
//!
//! # Supported Protocols
//!
//! - TLS: SNI extraction from `ClientHello`
//! - QUIC: SNI extraction from Initial packets
//! - HTTP: Host header extraction
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
//!
//! # QUIC Example
//!
//! ```
//! use rust_router::sniff::quic::QuicSniffer;
//!
//! let data = [/* UDP packet bytes */];
//!
//! if QuicSniffer::is_quic(&data) {
//!     let result = QuicSniffer::sniff(&data);
//!     if let Some(sni) = result.server_name {
//!         println!("QUIC connection to: {}", sni);
//!     }
//! }
//! ```
//!
//! # HTTP Example
//!
//! ```
//! use rust_router::sniff::http::{sniff_http_host, looks_like_http};
//!
//! let data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
//!
//! if looks_like_http(data) {
//!     if let Some(host) = sniff_http_host(data) {
//!         println!("HTTP request to: {}", host);
//!     }
//! }
//! ```

pub mod http;
pub mod quic;
mod result;
mod tls;

#[cfg(feature = "quic-sni")]
pub mod quic_decrypt;

pub use http::{looks_like_http, sniff_http, sniff_http_host, HttpSniffResult};
pub use quic::{QuicPacketType, QuicSniffResult, QuicSniffer, QuicVersion};
pub use result::{Protocol, SniffResult};
pub use tls::{looks_like_tls, sniff_tls, sniff_tls_sni, TlsSniffResult};

#[cfg(feature = "quic-sni")]
pub use quic_decrypt::{decrypt_quic_initial, sniff_quic_with_decrypt, DecryptError};
