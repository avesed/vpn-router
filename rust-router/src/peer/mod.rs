//! Peer management module
//!
//! This module provides types and utilities for managing peer nodes
//! in a multi-node VPN routing setup.
//!
//! # Overview
//!
//! The peer module handles:
//! - Input validation for peer-related operations
//! - Peer node configuration and state management
//! - Pairing protocol support for offline node discovery
//! - Port and IP allocation for tunnels
//! - Health checking with hysteresis
//!
//! # Submodules
//!
//! - [`validation`]: Input validation utilities for peer operations
//! - [`manager`]: `PeerManager` for lifecycle management
//! - [`pairing`]: Offline pairing protocol
//! - [`port_allocator`]: Tunnel port allocation
//! - [`ip_allocator`]: Tunnel IP allocation
//! - [`health`]: Health checker with hysteresis

pub mod health;
pub mod ip_allocator;
pub mod manager;
pub mod pairing;
pub mod port_allocator;
pub mod validation;

// Re-export commonly used types from validation
pub use validation::{
    validate_chain_tag, validate_dscp_value, validate_endpoint, validate_peer_tag,
    validate_tunnel_ip, validate_wg_key, ValidationError, WG_KEY_LENGTH,
};

// Re-export PeerManager and related types
pub use manager::{PeerError, PeerManager};

// Re-export pairing types and functions
pub use pairing::{
    decode_pair_request, encode_pair_request, decode_pair_response, encode_pair_response,
    PairRequest, PairRequestConfig, PairResponse, PairingError,
};

// Re-export allocators
pub use ip_allocator::{IpAllocatorError, TunnelIpAllocator};
pub use port_allocator::{PortAllocatorError, TunnelPortAllocator};

// Re-export health checker
pub use health::HealthChecker;
