//! TUN device configuration
//!
//! This module provides the configuration types for creating TUN devices.

// Allow doc_markdown for WireGuard/TUN terminology
#![allow(clippy::doc_markdown)]

use crate::tun::ioctl::MAX_INTERFACE_NAME_LEN;

/// Default MTU for TUN devices
///
/// 1500 bytes is the standard Ethernet MTU. For WireGuard tunnels,
/// you may want to use a lower value (e.g., 1420) to account for
/// encapsulation overhead.
pub const DEFAULT_MTU: u16 = 1500;

/// Configuration for creating a TUN device
#[derive(Debug, Clone)]
pub struct TunConfig {
    /// Device name (max 15 characters)
    ///
    /// Examples: "tun0", "tun-in", "wg-ingress"
    ///
    /// If empty, the kernel will assign a name (tun0, tun1, etc.).
    pub name: String,

    /// Maximum Transmission Unit in bytes
    ///
    /// Default: 1500 (standard Ethernet MTU)
    ///
    /// Common values:
    /// - 1500: Standard Ethernet
    /// - 1420: WireGuard default (1500 - 80 for WG overhead)
    /// - 1280: IPv6 minimum MTU
    pub mtu: u16,

    /// Enable multi-queue support
    ///
    /// When enabled, multiple file descriptors can be opened for the same
    /// TUN device, allowing parallel packet processing across multiple
    /// threads or async tasks.
    ///
    /// Default: false
    ///
    /// # Requirements
    ///
    /// - Linux kernel 3.8+
    /// - All queues must use the same interface name
    pub multi_queue: bool,
}

impl TunConfig {
    /// Create a new TUN configuration with the given name
    ///
    /// Uses default values for MTU (1500) and multi_queue (false).
    ///
    /// # Arguments
    ///
    /// * `name` - Device name (max 15 characters)
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::tun::TunConfig;
    ///
    /// let config = TunConfig::new("tun-in");
    /// assert_eq!(config.name, "tun-in");
    /// assert_eq!(config.mtu, 1500);
    /// assert!(!config.multi_queue);
    /// ```
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            mtu: DEFAULT_MTU,
            multi_queue: false,
        }
    }

    /// Set the MTU value
    ///
    /// # Arguments
    ///
    /// * `mtu` - Maximum Transmission Unit in bytes
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::tun::TunConfig;
    ///
    /// let config = TunConfig::new("tun0").with_mtu(1420);
    /// assert_eq!(config.mtu, 1420);
    /// ```
    #[must_use]
    pub const fn with_mtu(mut self, mtu: u16) -> Self {
        self.mtu = mtu;
        self
    }

    /// Enable or disable multi-queue support
    ///
    /// # Arguments
    ///
    /// * `enabled` - Whether to enable multi-queue
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::tun::TunConfig;
    ///
    /// let config = TunConfig::new("tun0").with_multi_queue(true);
    /// assert!(config.multi_queue);
    /// ```
    #[must_use]
    pub const fn with_multi_queue(mut self, enabled: bool) -> Self {
        self.multi_queue = enabled;
        self
    }

    /// Validate the configuration
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The device name is longer than 15 characters
    /// - The MTU is zero
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::tun::TunConfig;
    ///
    /// let config = TunConfig::new("tun0");
    /// assert!(config.validate().is_ok());
    ///
    /// let bad_config = TunConfig::new("this-name-is-way-too-long-for-linux");
    /// assert!(bad_config.validate().is_err());
    /// ```
    pub fn validate(&self) -> std::io::Result<()> {
        // Check name length
        if self.name.len() > MAX_INTERFACE_NAME_LEN {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "TUN device name too long: {} (max {} characters)",
                    self.name.len(),
                    MAX_INTERFACE_NAME_LEN
                ),
            ));
        }

        // Check for invalid characters in name
        // Linux interface names can contain alphanumeric characters, hyphens, and underscores
        if !self.name.is_empty() {
            for (i, c) in self.name.chars().enumerate() {
                if !c.is_ascii_alphanumeric() && c != '-' && c != '_' {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("Invalid character '{c}' at position {i} in TUN device name"),
                    ));
                }
            }

            // Name shouldn't start with a hyphen
            if self.name.starts_with('-') {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "TUN device name cannot start with a hyphen",
                ));
            }
        }

        // Check MTU
        if self.mtu == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "TUN device MTU cannot be zero",
            ));
        }

        // Warn about unusually small MTU (but don't error)
        // IPv6 minimum is 1280, but we allow smaller for testing
        if self.mtu < 68 {
            // IPv4 minimum MTU
            tracing::warn!(
                "TUN device MTU {} is below IPv4 minimum (68), this may cause issues",
                self.mtu
            );
        }

        Ok(())
    }
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            mtu: DEFAULT_MTU,
            multi_queue: false,
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_new() {
        let config = TunConfig::new("tun-test");
        assert_eq!(config.name, "tun-test");
        assert_eq!(config.mtu, DEFAULT_MTU);
        assert!(!config.multi_queue);
    }

    #[test]
    fn test_config_builder() {
        let config = TunConfig::new("tun0").with_mtu(1420).with_multi_queue(true);

        assert_eq!(config.name, "tun0");
        assert_eq!(config.mtu, 1420);
        assert!(config.multi_queue);
    }

    #[test]
    fn test_config_default() {
        let config = TunConfig::default();
        assert!(config.name.is_empty());
        assert_eq!(config.mtu, DEFAULT_MTU);
        assert!(!config.multi_queue);
    }

    #[test]
    fn test_validate_valid_config() {
        let config = TunConfig::new("tun0");
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_empty_name() {
        // Empty name is valid (kernel assigns name)
        let config = TunConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_max_name_length() {
        // 15 characters is OK
        let config = TunConfig::new("a".repeat(MAX_INTERFACE_NAME_LEN));
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_name_too_long() {
        // 16 characters is too long
        let config = TunConfig::new("a".repeat(MAX_INTERFACE_NAME_LEN + 1));
        let err = config.validate().unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("too long"));
    }

    #[test]
    fn test_validate_invalid_name_chars() {
        let config = TunConfig::new("tun/bad");
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("Invalid character"));
    }

    #[test]
    fn test_validate_name_with_hyphen() {
        let config = TunConfig::new("tun-ingress");
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_name_with_underscore() {
        let config = TunConfig::new("tun_ingress");
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_name_starts_with_hyphen() {
        let config = TunConfig::new("-tun");
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("cannot start with a hyphen"));
    }

    #[test]
    fn test_validate_zero_mtu() {
        let config = TunConfig::new("tun0").with_mtu(0);
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("MTU cannot be zero"));
    }

    #[test]
    fn test_config_clone() {
        let config = TunConfig::new("tun0").with_mtu(1420);
        let cloned = config.clone();
        assert_eq!(config.name, cloned.name);
        assert_eq!(config.mtu, cloned.mtu);
    }

    #[test]
    fn test_config_debug() {
        let config = TunConfig::new("tun0");
        let debug = format!("{:?}", config);
        assert!(debug.contains("tun0"));
    }
}
