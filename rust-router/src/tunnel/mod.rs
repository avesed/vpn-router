//! WireGuard tunnel module for Phase 6
//!
//! This module provides userspace WireGuard tunnel implementations
//! using boringtun for full Rust-native WireGuard support.
//!
//! # Overview
//!
//! The tunnel module handles:
//! - Userspace WireGuard tunnel creation and management
//! - Tunnel abstraction trait for different implementations
//! - Configuration types for tunnel setup
//! - Key generation and derivation utilities
//!
//! # Quick Start
//!
//! ```ignore
//! use rust_router::tunnel::{
//!     WgTunnelConfig, WgTunnelBuilder,
//!     generate_private_key, derive_public_key,
//! };
//!
//! // Generate keys
//! let private_key = generate_private_key();
//! let public_key = derive_public_key(&private_key)?;
//!
//! // Create tunnel configuration
//! let config = WgTunnelConfig::new(
//!     private_key,
//!     peer_public_key,
//!     "192.168.1.1:51820".to_string(),
//! );
//!
//! // Build and connect tunnel
//! let tunnel = WgTunnelBuilder::new(config).build_userspace()?;
//! tunnel.connect().await?;
//!
//! // Send and receive packets
//! tunnel.send(&ip_packet).await?;
//! let received = tunnel.recv().await?;
//! ```
//!
//! # Submodules
//!
//! - [`traits`]: Tunnel abstraction trait and builder
//! - [`userspace`]: Userspace WireGuard via boringtun
//! - [`config`]: Tunnel configuration types
//!
//! # Phase 6 Implementation Status
//!
//! - [x] 6.1 boringtun integration
//! - [x] 6.1 Key generation (generate_private_key, derive_public_key)
//! - [x] 6.1 Handshake handling
//! - [x] 6.1 Packet encryption/decryption
//! - [x] 6.1 Timer task (keepalive, rekey)
//! - [ ] 6.2 Tunnel abstraction trait (extended)
//! - [ ] 6.3 WireGuard ingress
//! - [ ] 6.4 WireGuard egress
//!
//! # Architecture
//!
//! ```text
//! +------------------+     +------------------+
//! | UserspaceWgTunnel|     | KernelWgTunnel   |
//! | (boringtun)      |     | (wg-quick style) |
//! +--------+---------+     +--------+---------+
//!          |                        |
//!          +------------------------+
//!                      |
//!               +------+------+
//!               | WgTunnel    |
//!               | (trait)     |
//!               +-------------+
//! ```
//!
//! # Key Generation
//!
//! WireGuard uses X25519 elliptic curve Diffie-Hellman for key exchange.
//! This module provides utilities for generating key pairs:
//!
//! ```
//! use rust_router::tunnel::{generate_private_key, derive_public_key, validate_key};
//!
//! // Generate a new private key
//! let private_key = generate_private_key();
//! assert!(validate_key(&private_key));
//!
//! // Derive the corresponding public key
//! let public_key = derive_public_key(&private_key).unwrap();
//! assert!(validate_key(&public_key));
//! ```
//!
//! # References
//!
//! - boringtun: <https://github.com/cloudflare/boringtun>
//! - WireGuard Protocol: <https://www.wireguard.com/protocol/>
//! - Implementation Plan: `docs/PHASE6_IMPLEMENTATION_PLAN_v3.2.md` Sections 6.1-6.4

pub mod config;
pub mod traits;
pub mod userspace;

// Re-export commonly used types
pub use config::{WgPeerConfig, WgTunnelConfig};
pub use traits::{WgTunnel, WgTunnelBuilder, WgTunnelError, WgTunnelStats};
pub use userspace::{
    derive_public_key, generate_private_key, validate_key, UserspaceWgTunnel, DEFAULT_MTU,
    MIN_BUFFER_SIZE, WG_HANDSHAKE_INIT_SIZE, WG_HANDSHAKE_RESPONSE_SIZE, WG_TRANSPORT_OVERHEAD,
};

// Deprecated re-export for backward compatibility
#[allow(deprecated)]
pub use userspace::WG_OVERHEAD;
