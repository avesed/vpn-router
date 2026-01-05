//! Protocol sniffing module
//!
//! This module provides protocol detection and parsing capabilities,
//! primarily for extracting SNI (Server Name Indication) from
//! TLS ClientHello and QUIC Initial packets.
//!
//! # Supported Protocols
//!
//! - TLS: SNI extraction from ClientHello
//! - QUIC: SNI extraction from Initial packets
//! - HTTP: Host header extraction (future)
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

pub mod quic;
mod result;
mod tls;

pub use quic::{QuicPacketType, QuicSniffResult, QuicSniffer, QuicVersion};
pub use result::{Protocol, SniffResult};
pub use tls::{looks_like_tls, sniff_tls_sni};
