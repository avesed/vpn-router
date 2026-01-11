//! Configuration loading and management
//!
//! This module handles loading configuration from files and environment variables.

use std::path::Path;

use tracing::{debug, info};

use super::types::Config;
use crate::error::ConfigError;

/// Load configuration from a JSON file
///
/// # Arguments
///
/// * `path` - Path to the configuration file
///
/// # Errors
///
/// Returns `ConfigError` if the file cannot be read or parsed.
pub fn load_config(path: impl AsRef<Path>) -> Result<Config, ConfigError> {
    let path = path.as_ref();

    debug!("Loading configuration from {:?}", path);

    // Check if file exists
    if !path.exists() {
        return Err(ConfigError::FileNotFound {
            path: path.display().to_string(),
        });
    }

    // Read file contents
    let contents = std::fs::read_to_string(path)?;

    // Parse JSON
    let config: Config = serde_json::from_str(&contents).map_err(|e| {
        ConfigError::ParseError(format!("Failed to parse JSON: {e} at {path:?}"))
    })?;

    // Validate configuration
    config.validate()?;

    info!(
        "Configuration loaded: {} outbounds, default={}",
        config.outbounds.len(),
        config.default_outbound
    );

    Ok(config)
}

/// Load configuration from a JSON string
///
/// # Errors
///
/// Returns `ConfigError` if parsing or validation fails.
pub fn load_config_str(json: &str) -> Result<Config, ConfigError> {
    let config: Config =
        serde_json::from_str(json).map_err(|e| ConfigError::ParseError(e.to_string()))?;

    config.validate()?;

    Ok(config)
}

/// Load configuration with environment variable overrides
///
/// Environment variables:
/// - `RUST_ROUTER_LISTEN_ADDR`: Override listen address
/// - `RUST_ROUTER_LOG_LEVEL`: Override log level
/// - `RUST_ROUTER_MAX_CONNECTIONS`: Override max connections
/// - `RUST_ROUTER_IPC_SOCKET`: Override IPC socket path
///
/// # Errors
///
/// Returns `ConfigError` if loading or parsing fails.
pub fn load_config_with_env(path: impl AsRef<Path>) -> Result<Config, ConfigError> {
    let mut config = load_config(path)?;

    // Override listen address
    if let Ok(addr) = std::env::var("RUST_ROUTER_LISTEN_ADDR") {
        config.listen.address = addr.parse().map_err(|_| {
            ConfigError::EnvError {
                name: "RUST_ROUTER_LISTEN_ADDR".into(),
                reason: format!("Invalid socket address: {addr}"),
            }
        })?;
        debug!("Listen address overridden to {}", config.listen.address);
    }

    // Override log level
    if let Ok(level) = std::env::var("RUST_ROUTER_LOG_LEVEL") {
        config.log.level = level;
        debug!("Log level overridden to {}", config.log.level);
    }

    // Override max connections
    if let Ok(max) = std::env::var("RUST_ROUTER_MAX_CONNECTIONS") {
        config.connection.max_connections = max.parse().map_err(|_| ConfigError::EnvError {
            name: "RUST_ROUTER_MAX_CONNECTIONS".into(),
            reason: format!("Invalid number: {max}"),
        })?;
        debug!(
            "Max connections overridden to {}",
            config.connection.max_connections
        );
    }

    // Override IPC socket path
    if let Ok(socket) = std::env::var("RUST_ROUTER_IPC_SOCKET") {
        config.ipc.socket_path = socket.into();
        debug!("IPC socket path overridden to {:?}", config.ipc.socket_path);
    }

    // Re-validate after overrides
    config.validate()?;

    Ok(config)
}

/// Create a default configuration file at the given path
///
/// # Errors
///
/// Returns `ConfigError` if the file cannot be written.
pub fn create_default_config(path: impl AsRef<Path>) -> Result<(), ConfigError> {
    let config = Config::default_config();
    let json = serde_json::to_string_pretty(&config)
        .map_err(|e| ConfigError::ParseError(format!("Failed to serialize config: {e}")))?;

    std::fs::write(path, json)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn create_temp_config() -> NamedTempFile {
        let mut file = NamedTempFile::new().unwrap();
        let config = Config::default_config();
        let json = serde_json::to_string_pretty(&config).unwrap();
        file.write_all(json.as_bytes()).unwrap();
        file
    }

    #[test]
    fn test_load_config() {
        let file = create_temp_config();
        let config = load_config(file.path()).unwrap();
        assert_eq!(config.default_outbound, "direct");
    }

    #[test]
    fn test_load_config_file_not_found() {
        let result = load_config("/nonexistent/path/config.json");
        assert!(matches!(result, Err(ConfigError::FileNotFound { .. })));
    }

    #[test]
    fn test_load_config_str() {
        let json = r#"{
            "listen": { "address": "127.0.0.1:7893" },
            "outbounds": [{ "tag": "direct", "type": "direct" }],
            "default_outbound": "direct",
            "ipc": { "socket_path": "/tmp/test.sock" }
        }"#;
        let config = load_config_str(json).unwrap();
        assert_eq!(config.default_outbound, "direct");
    }

    #[test]
    fn test_load_config_invalid_json() {
        let result = load_config_str("not valid json");
        assert!(matches!(result, Err(ConfigError::ParseError(_))));
    }
}
