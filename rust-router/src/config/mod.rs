//! Configuration module for rust-router
//!
//! This module provides configuration types and loading utilities.
//!
//! # Example
//!
//! ```no_run
//! use rust_router::config::{load_config, Config};
//!
//! let config = load_config("/etc/rust-router/config.json").unwrap();
//! println!("Default outbound: {}", config.default_outbound);
//! ```

mod loader;
mod types;

pub use loader::{create_default_config, load_config, load_config_str, load_config_with_env};
pub use types::{
    Config, ConnectionConfig, IpcConfig, ListenConfig, LogConfig, OutboundConfig, OutboundType,
    RuleConfig, RulesConfig,
};
