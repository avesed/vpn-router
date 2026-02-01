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
//! # Crash Recovery
//!
//! If the process crashes (SIGKILL, OOM, power failure), the `Drop` implementation
//! doesn't run, leaving stale rules in the system. This module implements crash
//! recovery by:
//!
//! 1. Writing a state file to `/run/netbridge-iptables-{tun_iface}.state` when rules are applied
//! 2. On startup, checking for stale state files (where the PID no longer exists)
//! 3. Cleaning up stale rules before applying new ones
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
//! // Apply rules (automatically recovers stale rules first)
//! manager.apply()?;
//!
//! // Rules are automatically cleaned up on drop
//! ```

use std::fs;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, warn};

use crate::netbridge::error::{NetBridgeError, Result};
use crate::tun_bridge::IptablesManager;

// =============================================================================
// State File for Crash Recovery
// =============================================================================

/// Directory for state files (tmpfs, survives normal restarts but not reboot)
const STATE_DIR: &str = "/run";

/// State file prefix
const STATE_FILE_PREFIX: &str = "netbridge-iptables-";

/// State file suffix
const STATE_FILE_SUFFIX: &str = ".state";

/// Persistent state for crash recovery
///
/// This is written to disk when rules are applied and deleted on cleanup.
/// If the process crashes, the next startup can detect and clean up stale rules.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IptablesState {
    /// Process ID that applied the rules
    pub pid: u32,
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
    /// Timestamp when rules were applied
    pub applied_at: DateTime<Utc>,
}

impl IptablesState {
    /// Create a new state from the current configuration
    fn new(
        tun_iface: &str,
        tun_subnet: &str,
        tproxy_port: u16,
        fwmark: u32,
        table_id: u32,
    ) -> Self {
        Self {
            pid: std::process::id(),
            tun_iface: tun_iface.to_string(),
            tun_subnet: tun_subnet.to_string(),
            tproxy_port,
            fwmark,
            table_id,
            applied_at: Utc::now(),
        }
    }

    /// Get the state file path for a given TUN interface
    pub fn state_file_path(tun_iface: &str) -> PathBuf {
        Path::new(STATE_DIR).join(format!("{STATE_FILE_PREFIX}{tun_iface}{STATE_FILE_SUFFIX}"))
    }

    /// Get the state file path for a given TUN interface with custom directory
    /// (used for testing)
    #[cfg(test)]
    fn state_file_path_in_dir(tun_iface: &str, dir: &Path) -> PathBuf {
        dir.join(format!("{STATE_FILE_PREFIX}{tun_iface}{STATE_FILE_SUFFIX}"))
    }

    /// Write state to file
    fn write(&self) -> Result<()> {
        self.write_to_dir(Path::new(STATE_DIR))
    }

    /// Write state to a specific directory (used for testing)
    fn write_to_dir(&self, dir: &Path) -> Result<()> {
        let path = dir.join(format!(
            "{STATE_FILE_PREFIX}{}{STATE_FILE_SUFFIX}",
            self.tun_iface
        ));
        let json = serde_json::to_string_pretty(self).map_err(|e| {
            NetBridgeError::Firewall(format!("Failed to serialize iptables state: {e}"))
        })?;

        fs::write(&path, json).map_err(|e| {
            NetBridgeError::Firewall(format!(
                "Failed to write iptables state file {}: {e}",
                path.display()
            ))
        })?;

        debug!(
            path = %path.display(),
            pid = self.pid,
            "Wrote iptables state file"
        );
        Ok(())
    }

    /// Read state from file
    fn read(tun_iface: &str) -> Result<Option<Self>> {
        Self::read_from_dir(tun_iface, Path::new(STATE_DIR))
    }

    /// Read state from a specific directory (used for testing)
    fn read_from_dir(tun_iface: &str, dir: &Path) -> Result<Option<Self>> {
        let path = dir.join(format!(
            "{STATE_FILE_PREFIX}{tun_iface}{STATE_FILE_SUFFIX}"
        ));

        if !path.exists() {
            return Ok(None);
        }

        let json = fs::read_to_string(&path).map_err(|e| {
            NetBridgeError::Firewall(format!(
                "Failed to read iptables state file {}: {e}",
                path.display()
            ))
        })?;

        let state: Self = serde_json::from_str(&json).map_err(|e| {
            NetBridgeError::Firewall(format!(
                "Failed to parse iptables state file {}: {e}",
                path.display()
            ))
        })?;

        Ok(Some(state))
    }

    /// Delete state file
    fn delete(tun_iface: &str) -> Result<()> {
        Self::delete_from_dir(tun_iface, Path::new(STATE_DIR))
    }

    /// Delete state file from a specific directory (used for testing)
    fn delete_from_dir(tun_iface: &str, dir: &Path) -> Result<()> {
        let path = dir.join(format!(
            "{STATE_FILE_PREFIX}{tun_iface}{STATE_FILE_SUFFIX}"
        ));

        if path.exists() {
            fs::remove_file(&path).map_err(|e| {
                NetBridgeError::Firewall(format!(
                    "Failed to delete iptables state file {}: {e}",
                    path.display()
                ))
            })?;
            debug!(path = %path.display(), "Deleted iptables state file");
        }
        Ok(())
    }

    /// Check if a PID is still running
    fn is_pid_running(pid: u32) -> bool {
        // On Linux, we can check /proc/{pid} existence
        Path::new(&format!("/proc/{pid}")).exists()
    }

    /// Check if this state is stale (process no longer running or not current process)
    pub fn is_stale(&self) -> bool {
        let current_pid = std::process::id();
        // Stale if:
        // 1. The PID doesn't exist at all, OR
        // 2. The PID exists but is not the current process (could be reused)
        !Self::is_pid_running(self.pid) || self.pid != current_pid
    }
}

/// Find all state files in the state directory
fn find_all_state_files() -> Vec<PathBuf> {
    find_all_state_files_in_dir(Path::new(STATE_DIR))
}

/// Find all state files in a specific directory (used for testing)
fn find_all_state_files_in_dir(dir: &Path) -> Vec<PathBuf> {
    if !dir.exists() {
        return Vec::new();
    }

    fs::read_dir(dir)
        .map(|entries| {
            entries
                .filter_map(std::result::Result::ok)
                .map(|e| e.path())
                .filter(|path| {
                    path.file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(|name| {
                            name.starts_with(STATE_FILE_PREFIX) && name.ends_with(STATE_FILE_SUFFIX)
                        })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Extract TUN interface name from state file path
fn extract_tun_iface_from_path(path: &Path) -> Option<String> {
    path.file_name()
        .and_then(|n| n.to_str())
        .and_then(|name| {
            name.strip_prefix(STATE_FILE_PREFIX)
                .and_then(|s| s.strip_suffix(STATE_FILE_SUFFIX))
                .map(ToString::to_string)
        })
}

// =============================================================================
// iptables Manager Wrapper
// =============================================================================

/// Wrapper around `IptablesManager` for netbridge integration
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
            .map_err(|e| NetBridgeError::Config(format!("Invalid iptables configuration: {e}")))?;

        Ok(Self {
            manager,
            rules_applied: false,
        })
    }

    /// Apply all required iptables and routing rules
    ///
    /// This method:
    /// 1. Recovers any stale rules from a previous crash
    /// 2. Configures sysctl settings (`ip_forward`, `route_localnet`, `rp_filter`)
    /// 3. Adds policy routing rules (fwmark -> table)
    /// 4. Adds local route in routing table
    /// 5. Adds TUN subnet route for reply packets
    /// 6. Creates DIVERT chain for established connection optimization
    /// 7. Adds TPROXY iptables rules
    /// 8. Writes state file for crash recovery
    ///
    /// # Errors
    ///
    /// Returns an error if any rule fails to apply.
    pub fn apply(&mut self) -> Result<()> {
        if self.rules_applied {
            debug!("iptables rules already applied");
            return Ok(());
        }

        // Recover stale rules before applying new ones
        self.recover_stale_rules()?;

        info!(
            tun = %self.manager.tun_iface(),
            port = self.manager.tproxy_port(),
            "Applying iptables rules"
        );

        self.manager.apply_rules().map_err(|e| {
            NetBridgeError::Io(std::io::Error::new(
                e.kind(),
                format!("Failed to apply iptables rules: {e}"),
            ))
        })?;

        self.rules_applied = true;

        // Write state file for crash recovery
        if let Err(e) = self.write_state_file() {
            // Log but don't fail - rules are applied, just no crash recovery
            warn!("Failed to write iptables state file (crash recovery disabled): {e}");
        }

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
                format!("Failed to cleanup iptables rules: {e}"),
            ))
        })?;

        self.rules_applied = false;

        // Delete state file
        if let Err(e) = IptablesState::delete(self.manager.tun_iface()) {
            warn!("Failed to delete iptables state file: {e}");
        }

        info!("iptables rules cleaned up");
        Ok(())
    }

    /// Recover stale rules from a previous crash
    ///
    /// This method:
    /// 1. Checks for a state file for this TUN interface
    /// 2. If found and stale (PID doesn't exist or isn't current process), cleans up those rules
    /// 3. Also scans for any other stale state files and cleans them up
    ///
    /// This should be called before applying new rules to ensure a clean slate.
    ///
    /// # Errors
    ///
    /// Returns an error if reading state files or cleaning up stale rules fails.
    pub fn recover_stale_rules(&self) -> Result<()> {
        // First, check for a state file for this specific TUN interface
        if let Some(state) = IptablesState::read(self.manager.tun_iface())? {
            if state.is_stale() {
                info!(
                    tun_iface = %state.tun_iface,
                    stale_pid = state.pid,
                    applied_at = %state.applied_at,
                    "Found stale iptables rules from crashed process, cleaning up"
                );
                Self::cleanup_stale_rules(&state)?;
            } else {
                // State file exists and PID is current process - shouldn't happen
                // but if it does, just continue (rules already applied)
                debug!(
                    tun_iface = %state.tun_iface,
                    pid = state.pid,
                    "Found state file for current process, will overwrite"
                );
            }
        }

        // Also scan for any other stale state files (different interfaces)
        for path in find_all_state_files() {
            if let Some(tun_iface) = extract_tun_iface_from_path(&path) {
                // Skip our own interface (already handled above)
                if tun_iface == self.manager.tun_iface() {
                    continue;
                }

                if let Ok(Some(state)) = IptablesState::read(&tun_iface) {
                    if state.is_stale() {
                        warn!(
                            tun_iface = %state.tun_iface,
                            stale_pid = state.pid,
                            applied_at = %state.applied_at,
                            "Found stale iptables rules for different interface, cleaning up"
                        );
                        // Best effort cleanup for other interfaces
                        if let Err(e) = Self::cleanup_stale_rules(&state) {
                            warn!(
                                tun_iface = %state.tun_iface,
                                error = %e,
                                "Failed to clean up stale rules for other interface"
                            );
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Clean up stale rules from a previous crash using stored state
    fn cleanup_stale_rules(state: &IptablesState) -> Result<()> {
        info!(
            tun_iface = %state.tun_iface,
            tun_subnet = %state.tun_subnet,
            tproxy_port = state.tproxy_port,
            fwmark = state.fwmark,
            table_id = state.table_id,
            "Cleaning up stale iptables rules"
        );

        // Create a temporary manager with the stale configuration
        let mut stale_manager = IptablesManager::new(
            &state.tun_iface,
            &state.tun_subnet,
            state.tproxy_port,
            state.fwmark,
            state.table_id,
        )
        .map_err(|e| {
            NetBridgeError::Firewall(format!(
                "Failed to create manager for stale rule cleanup: {e}"
            ))
        })?;

        // Mark as applied so cleanup will run
        // Note: We're accessing internal state here, but IptablesManager::cleanup_rules
        // doesn't check rules_applied, it just removes the rules
        if let Err(e) = stale_manager.cleanup_rules() {
            error!(
                tun_iface = %state.tun_iface,
                error = %e,
                "Failed to cleanup stale iptables rules"
            );
            // Continue to delete state file even if cleanup failed
        } else {
            info!(
                tun_iface = %state.tun_iface,
                "Successfully cleaned up stale iptables rules"
            );
        }

        // Delete the stale state file
        IptablesState::delete(&state.tun_iface)?;

        Ok(())
    }

    /// Write state file for crash recovery
    fn write_state_file(&self) -> Result<()> {
        let state = IptablesState::new(
            self.manager.tun_iface(),
            self.manager.tun_subnet(),
            self.manager.tproxy_port(),
            self.manager.fwmark(),
            self.manager.table_id(),
        );
        state.write()
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
                error!("Failed to cleanup iptables rules on drop: {}", e);
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
    use tempfile::TempDir;

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

    // =========================================================================
    // State File Tests
    // =========================================================================

    #[test]
    fn test_state_serialization() {
        let state = IptablesState::new("tun-in", "10.25.0.0/24", 7893, 0x1, 100);

        let json = serde_json::to_string_pretty(&state).unwrap();
        assert!(json.contains("\"pid\""));
        assert!(json.contains("\"tun_iface\": \"tun-in\""));
        assert!(json.contains("\"tun_subnet\": \"10.25.0.0/24\""));
        assert!(json.contains("\"tproxy_port\": 7893"));
        assert!(json.contains("\"fwmark\": 1"));
        assert!(json.contains("\"table_id\": 100"));
        assert!(json.contains("\"applied_at\""));

        let parsed: IptablesState = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.tun_iface, "tun-in");
        assert_eq!(parsed.tun_subnet, "10.25.0.0/24");
        assert_eq!(parsed.tproxy_port, 7893);
        assert_eq!(parsed.fwmark, 0x1);
        assert_eq!(parsed.table_id, 100);
    }

    #[test]
    fn test_state_file_path() {
        let path = IptablesState::state_file_path("tun-in");
        assert_eq!(
            path.to_str().unwrap(),
            "/run/netbridge-iptables-tun-in.state"
        );

        let path = IptablesState::state_file_path("tun-proxy-0");
        assert_eq!(
            path.to_str().unwrap(),
            "/run/netbridge-iptables-tun-proxy-0.state"
        );
    }

    #[test]
    fn test_state_write_read_delete() {
        let temp_dir = TempDir::new().unwrap();
        let dir = temp_dir.path();

        let state = IptablesState::new("tun-test", "10.25.0.0/24", 7893, 0x1, 100);

        // Write
        state.write_to_dir(dir).unwrap();
        let path = IptablesState::state_file_path_in_dir("tun-test", dir);
        assert!(path.exists());

        // Read
        let read_state = IptablesState::read_from_dir("tun-test", dir)
            .unwrap()
            .unwrap();
        assert_eq!(read_state.tun_iface, "tun-test");
        assert_eq!(read_state.tun_subnet, "10.25.0.0/24");
        assert_eq!(read_state.tproxy_port, 7893);
        assert_eq!(read_state.fwmark, 0x1);
        assert_eq!(read_state.table_id, 100);
        assert_eq!(read_state.pid, std::process::id());

        // Delete
        IptablesState::delete_from_dir("tun-test", dir).unwrap();
        assert!(!path.exists());

        // Read after delete should return None
        let read_state = IptablesState::read_from_dir("tun-test", dir).unwrap();
        assert!(read_state.is_none());
    }

    #[test]
    fn test_state_read_nonexistent() {
        let temp_dir = TempDir::new().unwrap();
        let result = IptablesState::read_from_dir("nonexistent", temp_dir.path()).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_state_delete_nonexistent() {
        let temp_dir = TempDir::new().unwrap();
        // Should not error when deleting nonexistent file
        let result = IptablesState::delete_from_dir("nonexistent", temp_dir.path());
        assert!(result.is_ok());
    }

    #[test]
    fn test_state_is_stale_current_process() {
        let state = IptablesState::new("tun-in", "10.25.0.0/24", 7893, 0x1, 100);
        // Current process is not stale
        assert!(!state.is_stale());
    }

    #[test]
    fn test_state_is_stale_different_pid() {
        let mut state = IptablesState::new("tun-in", "10.25.0.0/24", 7893, 0x1, 100);
        // Use a PID that definitely doesn't exist (PID 1 is init, but not our process)
        // Use a very high PID that's unlikely to exist
        state.pid = 999999999;
        assert!(state.is_stale());
    }

    #[test]
    fn test_state_is_stale_pid_exists_but_not_current() {
        let mut state = IptablesState::new("tun-in", "10.25.0.0/24", 7893, 0x1, 100);
        // PID 1 (init) exists but is not current process
        state.pid = 1;
        assert!(state.is_stale());
    }

    #[test]
    fn test_is_pid_running() {
        // Current process should be running
        assert!(IptablesState::is_pid_running(std::process::id()));

        // PID 1 (init) should be running
        assert!(IptablesState::is_pid_running(1));

        // Very high PID should not exist
        assert!(!IptablesState::is_pid_running(999999999));
    }

    #[test]
    fn test_find_all_state_files() {
        let temp_dir = TempDir::new().unwrap();
        let dir = temp_dir.path();

        // Create some state files
        let state1 = IptablesState::new("tun-a", "10.25.0.0/24", 7893, 0x1, 100);
        let state2 = IptablesState::new("tun-b", "10.25.0.0/24", 7893, 0x1, 100);
        state1.write_to_dir(dir).unwrap();
        state2.write_to_dir(dir).unwrap();

        // Create a non-state file
        fs::write(dir.join("other-file.txt"), "not a state file").unwrap();

        let files = find_all_state_files_in_dir(dir);
        assert_eq!(files.len(), 2);

        // Check that we found the right files
        let filenames: Vec<_> = files
            .iter()
            .filter_map(|p| p.file_name())
            .filter_map(|n| n.to_str())
            .collect();
        assert!(filenames.contains(&"netbridge-iptables-tun-a.state"));
        assert!(filenames.contains(&"netbridge-iptables-tun-b.state"));
    }

    #[test]
    fn test_find_all_state_files_empty_dir() {
        let temp_dir = TempDir::new().unwrap();
        let files = find_all_state_files_in_dir(temp_dir.path());
        assert!(files.is_empty());
    }

    #[test]
    fn test_find_all_state_files_nonexistent_dir() {
        let files = find_all_state_files_in_dir(Path::new("/nonexistent/dir"));
        assert!(files.is_empty());
    }

    #[test]
    fn test_extract_tun_iface_from_path() {
        let path = Path::new("/run/netbridge-iptables-tun-in.state");
        assert_eq!(
            extract_tun_iface_from_path(path),
            Some("tun-in".to_string())
        );

        let path = Path::new("/run/netbridge-iptables-tun-proxy-0.state");
        assert_eq!(
            extract_tun_iface_from_path(path),
            Some("tun-proxy-0".to_string())
        );

        // Not a state file
        let path = Path::new("/run/other-file.txt");
        assert_eq!(extract_tun_iface_from_path(path), None);

        // Wrong prefix
        let path = Path::new("/run/wrong-prefix-tun-in.state");
        assert_eq!(extract_tun_iface_from_path(path), None);

        // Wrong suffix
        let path = Path::new("/run/netbridge-iptables-tun-in.json");
        assert_eq!(extract_tun_iface_from_path(path), None);
    }

    #[test]
    fn test_state_json_format() {
        // Test that the JSON format matches the expected format from the task
        let mut state = IptablesState::new("tun-in", "10.25.0.0/24", 7893, 1, 100);
        state.pid = 12345;

        let json = serde_json::to_string_pretty(&state).unwrap();

        // Verify all expected fields are present
        assert!(json.contains("\"pid\": 12345"));
        assert!(json.contains("\"tun_iface\": \"tun-in\""));
        assert!(json.contains("\"tun_subnet\": \"10.25.0.0/24\""));
        assert!(json.contains("\"tproxy_port\": 7893"));
        assert!(json.contains("\"fwmark\": 1"));
        assert!(json.contains("\"table_id\": 100"));
        assert!(json.contains("\"applied_at\":"));
    }

    #[test]
    fn test_state_roundtrip_with_example_json() {
        // Parse the example JSON from the task
        let example_json = r#"{
            "pid": 12345,
            "tun_iface": "tun-in",
            "tun_subnet": "10.25.0.0/24",
            "tproxy_port": 7893,
            "fwmark": 1,
            "table_id": 100,
            "applied_at": "2024-01-15T10:30:00Z"
        }"#;

        let state: IptablesState = serde_json::from_str(example_json).unwrap();
        assert_eq!(state.pid, 12345);
        assert_eq!(state.tun_iface, "tun-in");
        assert_eq!(state.tun_subnet, "10.25.0.0/24");
        assert_eq!(state.tproxy_port, 7893);
        assert_eq!(state.fwmark, 1);
        assert_eq!(state.table_id, 100);

        // Verify we can serialize it back
        let json = serde_json::to_string(&state).unwrap();
        let parsed: IptablesState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, parsed);
    }
}
