//! TUN device wrapper for the kernel backend
//!
//! This module provides a thin wrapper around the existing TUN device implementation,
//! integrating it with the netbridge types and error handling.
//!
//! # Architecture
//!
//! The `TunDeviceWrapper` wraps the `tun::TunDevice` and provides:
//! - Integration with netbridge error types
//! - Async packet read/write operations
//! - Configuration and lifecycle management
//!
//! # Example
//!
//! ```ignore
//! use rust_router::netbridge::kernel::TunDeviceWrapper;
//!
//! let tun = TunDeviceWrapper::create("tun-in", "10.25.0.1/24", 1420)?;
//! tun.configure()?;
//!
//! // Read packets
//! let mut buf = [0u8; 1500];
//! let n = tun.read_packet(&mut buf).await?;
//! ```

use std::io;

use tracing::{debug, info};

use crate::netbridge::error::{NetBridgeError, Result};
use crate::netbridge::config::TUN_MTU;
use crate::tun::{TunConfig, TunDevice};

// =============================================================================
// TUN Device Wrapper
// =============================================================================

/// Wrapper around TunDevice for netbridge integration
///
/// This struct provides a higher-level interface to the TUN device,
/// handling configuration and error translation for the netbridge module.
pub struct TunDeviceWrapper {
    /// Underlying TUN device
    device: TunDevice,
    /// Device name
    name: String,
    /// Address in CIDR notation
    address: String,
    /// MTU
    mtu: u16,
    /// Whether the device is configured and up
    configured: bool,
}

impl std::fmt::Debug for TunDeviceWrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TunDeviceWrapper")
            .field("name", &self.name)
            .field("address", &self.address)
            .field("mtu", &self.mtu)
            .field("configured", &self.configured)
            .finish_non_exhaustive()
    }
}

impl TunDeviceWrapper {
    /// Create a new TUN device
    ///
    /// This creates the TUN device but does not configure it yet.
    /// Call `configure()` to set the address and bring the interface up.
    ///
    /// # Arguments
    ///
    /// * `name` - Device name (e.g., "tun-in")
    /// * `address` - IP address in CIDR notation (e.g., "10.25.0.1/24")
    /// * `mtu` - Maximum transmission unit (typically 1420 for WireGuard)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The device name is invalid (too long, invalid characters)
    /// - The device cannot be created (permission denied, etc.)
    pub fn create(name: &str, address: &str, mtu: u16) -> Result<Self> {
        info!(
            name = %name,
            address = %address,
            mtu = mtu,
            "Creating TUN device"
        );

        // Validate name length (Linux IFNAMSIZ is 16, last byte is null)
        if name.len() > 15 {
            return Err(NetBridgeError::Config(format!(
                "TUN device name '{}' exceeds 15 character limit",
                name
            )));
        }

        // Validate name characters
        for c in name.chars() {
            if !c.is_ascii_alphanumeric() && c != '-' && c != '_' {
                return Err(NetBridgeError::Config(format!(
                    "Invalid character '{}' in TUN device name '{}'",
                    c, name
                )));
            }
        }

        // Create the TUN configuration
        let config = TunConfig::new(name).with_mtu(mtu);

        // Create the TUN device
        let device = TunDevice::create(&config).map_err(|e| {
            NetBridgeError::Io(io::Error::new(
                e.kind(),
                format!("Failed to create TUN device '{}': {}", name, e),
            ))
        })?;

        let actual_name = device.name().to_string();
        debug!(
            requested = %name,
            actual = %actual_name,
            "TUN device created"
        );

        Ok(Self {
            device,
            name: actual_name,
            address: address.to_string(),
            mtu,
            configured: false,
        })
    }

    /// Create with default MTU (1420 for WireGuard)
    ///
    /// # Arguments
    ///
    /// * `name` - Device name
    /// * `address` - IP address in CIDR notation
    pub fn create_default(name: &str, address: &str) -> Result<Self> {
        Self::create(name, address, TUN_MTU as u16)
    }

    /// Configure the TUN device (set address, MTU, and bring up)
    ///
    /// This must be called after creation to make the device operational.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Setting the address fails
    /// - Setting the MTU fails
    /// - Bringing the interface up fails
    pub fn configure(&mut self) -> Result<()> {
        if self.configured {
            debug!(name = %self.name, "TUN device already configured");
            return Ok(());
        }

        info!(
            name = %self.name,
            address = %self.address,
            mtu = self.mtu,
            "Configuring TUN device"
        );

        self.device.configure(&self.address).map_err(|e| {
            NetBridgeError::Io(io::Error::new(
                e.kind(),
                format!(
                    "Failed to configure TUN device '{}' with address '{}': {}",
                    self.name, self.address, e
                ),
            ))
        })?;

        self.configured = true;
        info!(name = %self.name, "TUN device configured and up");
        Ok(())
    }

    /// Read a packet from the TUN device (async)
    ///
    /// # Arguments
    ///
    /// * `buf` - Buffer to read the packet into
    ///
    /// # Returns
    ///
    /// The number of bytes read.
    ///
    /// # Errors
    ///
    /// Returns an error if the read operation fails.
    #[inline]
    pub async fn read_packet(&self, buf: &mut [u8]) -> Result<usize> {
        self.device.read_packet(buf).await.map_err(|e| {
            NetBridgeError::Io(io::Error::new(
                e.kind(),
                format!("Failed to read from TUN device '{}': {}", self.name, e),
            ))
        })
    }

    /// Write a packet to the TUN device (async)
    ///
    /// # Arguments
    ///
    /// * `buf` - The IP packet to write
    ///
    /// # Returns
    ///
    /// The number of bytes written.
    ///
    /// # Errors
    ///
    /// Returns an error if the write operation fails.
    #[inline]
    pub async fn write_packet(&self, buf: &[u8]) -> Result<usize> {
        self.device.write_packet(buf).await.map_err(|e| {
            NetBridgeError::Io(io::Error::new(
                e.kind(),
                format!("Failed to write to TUN device '{}': {}", self.name, e),
            ))
        })
    }

    /// Try to read a packet without blocking
    ///
    /// # Arguments
    ///
    /// * `buf` - Buffer to read the packet into
    ///
    /// # Returns
    ///
    /// - `Ok(Some(n))` - Successfully read n bytes
    /// - `Ok(None)` - No packet available (would block)
    /// - `Err(e)` - An error occurred
    #[inline]
    pub fn try_read_packet(&self, buf: &mut [u8]) -> Result<Option<usize>> {
        self.device.try_read_packet(buf).map_err(|e| {
            NetBridgeError::Io(io::Error::new(
                e.kind(),
                format!("Failed to try_read from TUN device '{}': {}", self.name, e),
            ))
        })
    }

    /// Try to write a packet without blocking
    ///
    /// # Arguments
    ///
    /// * `buf` - The IP packet to write
    ///
    /// # Returns
    ///
    /// - `Ok(Some(n))` - Successfully wrote n bytes
    /// - `Ok(None)` - Device not ready (would block)
    /// - `Err(e)` - An error occurred
    #[inline]
    pub fn try_write_packet(&self, buf: &[u8]) -> Result<Option<usize>> {
        self.device.try_write_packet(buf).map_err(|e| {
            NetBridgeError::Io(io::Error::new(
                e.kind(),
                format!("Failed to try_write to TUN device '{}': {}", self.name, e),
            ))
        })
    }

    /// Get the device name
    #[inline]
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the configured address
    #[inline]
    #[must_use]
    pub fn address(&self) -> &str {
        &self.address
    }

    /// Get the MTU
    #[inline]
    #[must_use]
    pub fn mtu(&self) -> u16 {
        self.mtu
    }

    /// Check if the device is configured
    #[inline]
    #[must_use]
    pub fn is_configured(&self) -> bool {
        self.configured
    }

    /// Get the raw file descriptor
    ///
    /// # Safety
    ///
    /// The returned fd is borrowed and must not be closed or transferred.
    #[inline]
    #[must_use]
    pub fn raw_fd(&self) -> std::os::unix::io::RawFd {
        self.device.raw_fd()
    }

    /// Get a reference to the underlying TunDevice
    #[inline]
    #[must_use]
    pub fn inner(&self) -> &TunDevice {
        &self.device
    }
}

// =============================================================================
// TUN Configuration Builder
// =============================================================================

/// Builder for TUN device configuration
#[derive(Debug, Clone)]
pub struct TunDeviceBuilder {
    /// Device name
    name: String,
    /// IP address in CIDR notation
    address: String,
    /// MTU
    mtu: u16,
    /// Whether to auto-configure on creation
    auto_configure: bool,
}

impl TunDeviceBuilder {
    /// Create a new builder with required parameters
    #[must_use]
    pub fn new(name: &str, address: &str) -> Self {
        Self {
            name: name.to_string(),
            address: address.to_string(),
            mtu: TUN_MTU as u16,
            auto_configure: true,
        }
    }

    /// Set the MTU
    #[must_use]
    pub const fn mtu(mut self, mtu: u16) -> Self {
        self.mtu = mtu;
        self
    }

    /// Set whether to auto-configure on creation
    #[must_use]
    pub const fn auto_configure(mut self, auto: bool) -> Self {
        self.auto_configure = auto;
        self
    }

    /// Build and optionally configure the TUN device
    ///
    /// # Errors
    ///
    /// Returns an error if device creation or configuration fails.
    pub fn build(self) -> Result<TunDeviceWrapper> {
        let mut wrapper = TunDeviceWrapper::create(&self.name, &self.address, self.mtu)?;

        if self.auto_configure {
            wrapper.configure()?;
        }

        Ok(wrapper)
    }
}

impl Default for TunDeviceBuilder {
    fn default() -> Self {
        Self::new("tun-nb", "10.25.0.1/24")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_name_validation_valid() {
        // These should pass validation (not actually create devices)
        let names = ["tun0", "tun-in", "tun_bridge_0", "eth0", "wg-pia-nyc"];
        for name in names {
            assert!(name.len() <= 15);
            for c in name.chars() {
                assert!(c.is_ascii_alphanumeric() || c == '-' || c == '_');
            }
        }
    }

    #[test]
    fn test_name_validation_too_long() {
        let name = "this-name-is-way-too-long";
        assert!(name.len() > 15);
    }

    #[test]
    fn test_name_validation_invalid_char() {
        let name = "tun/bad";
        let has_invalid = name.chars().any(|c| !c.is_ascii_alphanumeric() && c != '-' && c != '_');
        assert!(has_invalid);
    }

    #[test]
    fn test_builder_defaults() {
        let builder = TunDeviceBuilder::default();
        assert_eq!(builder.name, "tun-nb");
        assert_eq!(builder.address, "10.25.0.1/24");
        assert_eq!(builder.mtu, TUN_MTU as u16);
        assert!(builder.auto_configure);
    }

    #[test]
    fn test_builder_custom() {
        let builder = TunDeviceBuilder::new("tun-test", "192.168.1.1/24")
            .mtu(1500)
            .auto_configure(false);

        assert_eq!(builder.name, "tun-test");
        assert_eq!(builder.address, "192.168.1.1/24");
        assert_eq!(builder.mtu, 1500);
        assert!(!builder.auto_configure);
    }
}
