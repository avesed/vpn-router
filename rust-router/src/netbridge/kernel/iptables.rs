//! iptables rule management for the kernel backend
//!
//! This module manages the iptables and routing rules required for TPROXY
//! transparent proxying, wrapping the existing `tun_bridge::IptablesManager`.
//!
//! # Architecture
//!
//! TPROXY requires a specific set of iptables and routing rules:
//!
//! 1. **Policy Routing**: Route packets with a specific fwmark to a dedicated table
//! 2. **Local Route**: In that table, route all traffic to localhost
//! 3. **TPROXY Rule**: Mark packets and redirect them to the TPROXY socket
//! 4. **DIVERT Chain**: Optimize established connection handling
//!
//! # RAII Cleanup
//!
//! The wrapper implements `Drop` to automatically clean up rules when dropped,
//! ensuring no stale rules are left behind.
//!
//! # Example
//!
//! ```ignore
//! use rust_router::netbridge::kernel::IptablesManagerWrapper;
//!
//! let mut manager = IptablesManagerWrapper::new(
//!     "tun-in",
//!     "10.25.0.0/24",
//!     7893,
//!     0x1,
//!     100,
//! )?;
//!
//! // Apply rules
//! manager.apply()?;
//!
//! // Rules are automatically cleaned up on drop
//! ```

use tracing::{debug, info};

use crate::netbridge::error::{NetBridgeError, Result};
use crate::tun_bridge::IptablesManager;

// =============================================================================
// iptables Manager Wrapper
// =============================================================================

/// Wrapper around IptablesManager for netbridge integration
///
/// This struct provides a higher-level interface with netbridge error types
/// and automatic cleanup on drop.
#[derive(Debug)]
pub struct IptablesManagerWrapper {
    /// Underlying iptables manager
    manager: IptablesManager,
    /// Whether rules are currently applied
    rules_applied: bool,
}

impl IptablesManagerWrapper {
    /// Create a new iptables manager
    ///
    /// # Arguments
    ///
    /// * `tun_iface` - TUN interface name (e.g., "tun-in")
    /// * `tun_subnet` - TUN subnet CIDR (e.g., "10.25.0.0/24") for reply routing
    /// * `tproxy_port` - TPROXY listener port (e.g., 7893)
    /// * `fwmark` - fwmark value for policy routing (e.g., 0x1)
    /// * `table_id` - Routing table ID (e.g., 100)
    ///
    /// # Errors
    ///
    /// Returns an error if the interface name is invalid.
    pub fn new(
        tun_iface: &str,
        tun_subnet: &str,
        tproxy_port: u16,
        fwmark: u32,
        table_id: u32,
    ) -> Result<Self> {
        info!(
            tun_iface = %tun_iface,
            tun_subnet = %tun_subnet,
            tproxy_port = tproxy_port,
            fwmark = fwmark,
            table_id = table_id,
            "Creating iptables manager"
        );

        let manager = IptablesManager::new(tun_iface, tun_subnet, tproxy_port, fwmark, table_id)
            .map_err(|e| NetBridgeError::Config(format!("Invalid iptables configuration: {}", e)))?;

        Ok(Self {
            manager,
            rules_applied: false,
        })
    }

    /// Apply all required iptables and routing rules
    ///
    /// This method:
    /// 1. Configures sysctl settings (ip_forward, route_localnet, rp_filter)
    /// 2. Adds policy routing rules (fwmark -> table)
    /// 3. Adds local route in routing table
    /// 4. Adds TUN subnet route for reply packets
    /// 5. Creates DIVERT chain for established connection optimization
    /// 6. Adds TPROXY iptables rules
    ///
    /// # Errors
    ///
    /// Returns an error if any rule fails to apply.
    pub fn apply(&mut self) -> Result<()> {
        if self.rules_applied {
            debug!("iptables rules already applied");
            return Ok(());
        }

        info!(
            tun = %self.manager.tun_iface(),
            port = self.manager.tproxy_port(),
            "Applying iptables rules"
        );

        self.manager.apply_rules().map_err(|e| {
            NetBridgeError::Io(std::io::Error::new(
                e.kind(),
                format!("Failed to apply iptables rules: {}", e),
            ))
        })?;

        self.rules_applied = true;
        info!("iptables rules applied successfully");
        Ok(())
    }

    /// Clean up all applied rules
    ///
    /// This removes all rules that were added by `apply()`.
    /// Safe to call even if rules weren't applied.
    ///
    /// # Errors
    ///
    /// Returns an error if cleanup fails. Individual failures are logged
    /// but don't stop the cleanup process.
    pub fn cleanup(&mut self) -> Result<()> {
        if !self.rules_applied {
            debug!("No iptables rules to clean up");
            return Ok(());
        }

        info!(
            tun = %self.manager.tun_iface(),
            "Cleaning up iptables rules"
        );

        self.manager.cleanup_rules().map_err(|e| {
            NetBridgeError::Io(std::io::Error::new(
                e.kind(),
                format!("Failed to cleanup iptables rules: {}", e),
            ))
        })?;

        self.rules_applied = false;
        info!("iptables rules cleaned up");
        Ok(())
    }

    /// Get the TUN interface name
    #[inline]
    #[must_use]
    pub fn tun_iface(&self) -> &str {
        self.manager.tun_iface()
    }

    /// Get the TUN subnet CIDR
    #[inline]
    #[must_use]
    pub fn tun_subnet(&self) -> &str {
        self.manager.tun_subnet()
    }

    /// Get the TPROXY port
    #[inline]
    #[must_use]
    pub fn tproxy_port(&self) -> u16 {
        self.manager.tproxy_port()
    }

    /// Get the fwmark value
    #[inline]
    #[must_use]
    pub fn fwmark(&self) -> u32 {
        self.manager.fwmark()
    }

    /// Get the routing table ID
    #[inline]
    #[must_use]
    pub fn table_id(&self) -> u32 {
        self.manager.table_id()
    }

    /// Check if rules have been applied
    #[inline]
    #[must_use]
    pub fn rules_applied(&self) -> bool {
        self.rules_applied
    }

    /// Generate shell commands for manual setup
    ///
    /// Useful for debugging or documentation.
    #[must_use]
    pub fn generate_setup_commands(&self) -> String {
        self.manager.generate_setup_commands()
    }

    /// Generate shell commands for manual cleanup
    #[must_use]
    pub fn generate_cleanup_commands(&self) -> String {
        self.manager.generate_cleanup_commands()
    }
}

impl Drop for IptablesManagerWrapper {
    fn drop(&mut self) {
        if self.rules_applied {
            debug!("IptablesManagerWrapper dropped with rules applied, cleaning up");
            if let Err(e) = self.cleanup() {
                tracing::error!("Failed to cleanup iptables rules on drop: {}", e);
            }
        }
    }
}

// =============================================================================
// iptables Configuration Builder
// =============================================================================

/// Builder for iptables configuration
#[derive(Debug, Clone)]
pub struct IptablesConfig {
    /// TUN interface name
    pub tun_iface: String,
    /// TUN subnet CIDR
    pub tun_subnet: String,
    /// TPROXY listener port
    pub tproxy_port: u16,
    /// fwmark value for policy routing
    pub fwmark: u32,
    /// Routing table ID
    pub table_id: u32,
    /// Whether to apply rules on build
    pub auto_apply: bool,
}

impl IptablesConfig {
    /// Create a new configuration
    #[must_use]
    pub fn new(tun_iface: &str, tun_subnet: &str) -> Self {
        Self {
            tun_iface: tun_iface.to_string(),
            tun_subnet: tun_subnet.to_string(),
            tproxy_port: 7893,
            fwmark: 0x1,
            table_id: 100,
            auto_apply: true,
        }
    }

    /// Set the TPROXY port
    #[must_use]
    pub const fn tproxy_port(mut self, port: u16) -> Self {
        self.tproxy_port = port;
        self
    }

    /// Set the fwmark
    #[must_use]
    pub const fn fwmark(mut self, mark: u32) -> Self {
        self.fwmark = mark;
        self
    }

    /// Set the routing table ID
    #[must_use]
    pub const fn table_id(mut self, id: u32) -> Self {
        self.table_id = id;
        self
    }

    /// Set whether to auto-apply rules on build
    #[must_use]
    pub const fn auto_apply(mut self, auto: bool) -> Self {
        self.auto_apply = auto;
        self
    }

    /// Build the iptables manager
    ///
    /// # Errors
    ///
    /// Returns an error if creation or application fails.
    pub fn build(self) -> Result<IptablesManagerWrapper> {
        let mut wrapper = IptablesManagerWrapper::new(
            &self.tun_iface,
            &self.tun_subnet,
            self.tproxy_port,
            self.fwmark,
            self.table_id,
        )?;

        if self.auto_apply {
            wrapper.apply()?;
        }

        Ok(wrapper)
    }
}

impl Default for IptablesConfig {
    fn default() -> Self {
        Self::new("tun-in", "10.25.0.0/24")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults() {
        let config = IptablesConfig::default();
        assert_eq!(config.tun_iface, "tun-in");
        assert_eq!(config.tun_subnet, "10.25.0.0/24");
        assert_eq!(config.tproxy_port, 7893);
        assert_eq!(config.fwmark, 0x1);
        assert_eq!(config.table_id, 100);
        assert!(config.auto_apply);
    }

    #[test]
    fn test_config_builder() {
        let config = IptablesConfig::new("tun-test", "192.168.0.0/24")
            .tproxy_port(8080)
            .fwmark(0x2)
            .table_id(200)
            .auto_apply(false);

        assert_eq!(config.tun_iface, "tun-test");
        assert_eq!(config.tun_subnet, "192.168.0.0/24");
        assert_eq!(config.tproxy_port, 8080);
        assert_eq!(config.fwmark, 0x2);
        assert_eq!(config.table_id, 200);
        assert!(!config.auto_apply);
    }

    #[test]
    fn test_wrapper_creation() {
        // This should succeed even without root (just validation)
        let result = IptablesManagerWrapper::new("tun-test", "10.25.0.0/24", 7893, 0x1, 100);
        assert!(result.is_ok());

        let wrapper = result.unwrap();
        assert_eq!(wrapper.tun_iface(), "tun-test");
        assert_eq!(wrapper.tun_subnet(), "10.25.0.0/24");
        assert_eq!(wrapper.tproxy_port(), 7893);
        assert_eq!(wrapper.fwmark(), 0x1);
        assert_eq!(wrapper.table_id(), 100);
        assert!(!wrapper.rules_applied());
    }

    #[test]
    fn test_wrapper_invalid_name() {
        // Name too long
        let result = IptablesManagerWrapper::new(
            "this-name-is-way-too-long",
            "10.25.0.0/24",
            7893,
            0x1,
            100,
        );
        assert!(result.is_err());

        // Invalid character
        let result = IptablesManagerWrapper::new("tun/bad", "10.25.0.0/24", 7893, 0x1, 100);
        assert!(result.is_err());

        // Empty name
        let result = IptablesManagerWrapper::new("", "10.25.0.0/24", 7893, 0x1, 100);
        assert!(result.is_err());
    }

    #[test]
    fn test_generate_commands() {
        let wrapper =
            IptablesManagerWrapper::new("tun-in", "10.25.0.0/24", 7893, 0x1, 100).unwrap();

        let setup = wrapper.generate_setup_commands();
        assert!(setup.contains("ip_forward=1"));
        assert!(setup.contains("TPROXY"));
        assert!(setup.contains("7893"));
        assert!(setup.contains("0x1"));
        assert!(setup.contains("table 100"));
        assert!(setup.contains("10.25.0.0/24"));

        let cleanup = wrapper.generate_cleanup_commands();
        assert!(cleanup.contains("-D PREROUTING"));
        assert!(cleanup.contains("ip rule del"));
    }
}
