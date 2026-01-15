// WARP registration module
//
// This module provides native WARP registration without warp-cli dependency.
// It directly calls Cloudflare API to register devices and obtain WireGuard configs.

pub mod config;
pub mod error;
pub mod register;

// Re-exports for convenience
pub use config::{constants, WarpRegistration};
pub use error::{Result, WarpError};
pub use register::{generate_keypair, register_device};
