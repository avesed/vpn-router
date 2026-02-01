//! iptables management for TUN + TPROXY bridge
//!
//! This module manages the iptables rules required for TPROXY transparent proxying.
//!
//! # Overview
//!
//! TPROXY (Transparent Proxy) requires a specific set of iptables and routing rules
//! to intercept traffic and redirect it to a local socket while preserving the
//! original destination address.
//!
//! # Required Rules
//!
//! 1. **Policy Routing**: Route packets with a specific fwmark to a dedicated table
//! 2. **Local Route**: In that table, route all traffic to localhost
//! 3. **TPROXY Rule**: Mark packets and redirect them to the TPROXY socket
//!
//! # Example Configuration
//!
//! ```bash
//! # Policy routing: packets with mark 0x1 use table 100
//! ip rule add fwmark 0x1 lookup 100
//!
//! # Table 100: route everything to localhost
//! ip route add local 0.0.0.0/0 dev lo table 100
//!
//! # Mark and TPROXY packets from TUN interface
//! iptables -t mangle -A PREROUTING -i tun-in -p tcp -j TPROXY \
//!     --on-port 7893 --tproxy-mark 0x1/0x1
//! iptables -t mangle -A PREROUTING -i tun-in -p udp -j TPROXY \
//!     --on-port 7893 --tproxy-mark 0x1/0x1
//! ```
//!
//! # Sysctl Settings
//!
//! The following sysctl settings are required for TPROXY to work:
//!
//! - `net.ipv4.ip_forward=1`: Enable IP forwarding
//! - `net.ipv4.conf.all.route_localnet=1`: Allow routing to localhost
//! - `net.ipv4.conf.<iface>.rp_filter=0`: Disable reverse path filtering
//!
//! # Safety
//!
//! This module executes shell commands with elevated privileges. All commands
//! are carefully constructed to prevent injection attacks.

use std::io;
use std::process::Command;
use tracing::{debug, error, info, warn};

/// Manages iptables and routing rules for TPROXY
///
/// This struct provides methods to apply and clean up all required
/// rules for TPROXY transparent proxying.
///
/// # Example
///
/// ```ignore
/// use rust_router::tun_bridge::IptablesManager;
///
/// let manager = IptablesManager::new("tun-in", 7893, 0x1, 100);
///
/// // Apply rules
/// manager.apply_rules()?;
///
/// // ... run proxy ...
///
/// // Clean up when done
/// manager.cleanup_rules()?;
/// ```
#[derive(Debug, Clone)]
pub struct IptablesManager {
    /// TUN interface name
    tun_iface: String,
    /// TUN subnet CIDR (e.g., "10.25.0.0/24") - for routing reply packets
    tun_subnet: String,
    /// TPROXY listener port
    tproxy_port: u16,
    /// fwmark value for policy routing
    fwmark: u32,
    /// Routing table ID
    table_id: u32,
    /// Whether rules have been applied
    rules_applied: bool,
}

impl IptablesManager {
    /// Create a new iptables manager
    ///
    /// # Arguments
    ///
    /// * `tun_iface` - TUN interface name (e.g., "tun-in")
    /// * `tun_subnet` - TUN subnet CIDR (e.g., "10.25.0.0/24") for routing reply packets
    /// * `tproxy_port` - TPROXY listener port (e.g., 7893)
    /// * `fwmark` - fwmark value for policy routing (e.g., 0x1)
    /// * `table_id` - Routing table ID (e.g., 100)
    ///
    /// # Errors
    ///
    /// Returns an error if the interface name is invalid:
    /// - Too long (max 15 characters)
    /// - Contains invalid characters (only alphanumeric, '-', '_' allowed)
    pub fn new(
        tun_iface: &str,
        tun_subnet: &str,
        tproxy_port: u16,
        fwmark: u32,
        table_id: u32,
    ) -> io::Result<Self> {
        // Validate interface name (same rules as Linux IFNAMSIZ)
        if tun_iface.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Interface name cannot be empty",
            ));
        }
        if tun_iface.len() > 15 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "Interface name '{}' too long (max 15 characters, got {})",
                    tun_iface,
                    tun_iface.len()
                ),
            ));
        }
        for c in tun_iface.chars() {
            if !c.is_ascii_alphanumeric() && c != '-' && c != '_' {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("Invalid character '{}' in interface name '{}'", c, tun_iface),
                ));
            }
        }

        Ok(Self {
            tun_iface: tun_iface.to_string(),
            tun_subnet: tun_subnet.to_string(),
            tproxy_port,
            fwmark,
            table_id,
            rules_applied: false,
        })
    }

    /// Apply all required iptables and routing rules
    ///
    /// This method:
    /// 1. Configures sysctl settings
    /// 2. Adds policy routing rules
    /// 3. Adds TPROXY iptables rules
    ///
    /// # Errors
    ///
    /// Returns an error if any rule fails to apply.
    pub fn apply_rules(&mut self) -> io::Result<()> {
        info!(
            tun = %self.tun_iface,
            port = self.tproxy_port,
            fwmark = self.fwmark,
            table = self.table_id,
            "Applying iptables rules for TPROXY"
        );

        // Configure sysctl settings
        self.apply_sysctl_settings()?;

        // Add policy routing rule
        self.apply_policy_routing()?;

        // Add local route in routing table
        self.apply_local_route()?;

        // Add TPROXY iptables rules
        self.apply_tproxy_rules()?;

        self.rules_applied = true;
        info!("TPROXY rules applied successfully");

        Ok(())
    }

    /// Clean up all applied rules
    ///
    /// This method removes all rules that were added by `apply_rules()`.
    /// It's safe to call even if rules weren't applied.
    ///
    /// # Errors
    ///
    /// Returns an error if cleanup fails. Individual failures are logged
    /// but don't stop the cleanup process.
    pub fn cleanup_rules(&mut self) -> io::Result<()> {
        info!(
            tun = %self.tun_iface,
            table = self.table_id,
            "Cleaning up TPROXY rules"
        );

        // Remove TPROXY iptables rules
        if let Err(e) = self.remove_tproxy_rules() {
            warn!("Failed to remove TPROXY rules: {}", e);
        }

        // Remove local route
        if let Err(e) = self.remove_local_route() {
            warn!("Failed to remove local route: {}", e);
        }

        // Remove policy routing rule
        if let Err(e) = self.remove_policy_routing() {
            warn!("Failed to remove policy routing rule: {}", e);
        }

        // Note: We don't restore sysctl settings as they may be needed by other services

        self.rules_applied = false;
        info!("TPROXY rules cleaned up");

        Ok(())
    }

    /// Configure sysctl settings for TPROXY
    fn apply_sysctl_settings(&self) -> io::Result<()> {
        debug!("Configuring sysctl settings");

        // Enable IP forwarding
        self.sysctl_write("net.ipv4.ip_forward", "1")?;

        // Allow routing to localhost (required for TPROXY)
        self.sysctl_write("net.ipv4.conf.all.route_localnet", "1")?;
        self.sysctl_write(&format!("net.ipv4.conf.{}.route_localnet", self.tun_iface), "1")?;

        // Disable reverse path filtering for the TUN interface
        self.sysctl_write(&format!("net.ipv4.conf.{}.rp_filter", self.tun_iface), "0")?;
        self.sysctl_write("net.ipv4.conf.all.rp_filter", "0")?;

        // Allow binding to non-local addresses (required for TPROXY reply sockets)
        self.sysctl_write("net.ipv4.ip_nonlocal_bind", "1")?;

        Ok(())
    }

    /// Write a sysctl value
    fn sysctl_write(&self, key: &str, value: &str) -> io::Result<()> {
        let path = format!("/proc/sys/{}", key.replace('.', "/"));

        // Try direct file write first (faster, no shell)
        match std::fs::write(&path, value) {
            Ok(()) => {
                debug!("sysctl {} = {}", key, value);
                Ok(())
            }
            Err(e) => {
                // Fall back to sysctl command
                debug!("Direct write failed, trying sysctl command: {}", e);
                self.run_command("sysctl", &["-w", &format!("{}={}", key, value)])
            }
        }
    }

    /// Add policy routing rule: fwmark -> table
    fn apply_policy_routing(&self) -> io::Result<()> {
        debug!(
            fwmark = self.fwmark,
            table = self.table_id,
            "Adding policy routing rule"
        );

        // Check if rule already exists
        let check_output = Command::new("ip")
            .args(["rule", "show", "fwmark", &format!("{:#x}", self.fwmark)])
            .output()?;

        if !check_output.stdout.is_empty() {
            debug!("Policy routing rule already exists");
            return Ok(());
        }

        self.run_command(
            "ip",
            &[
                "rule",
                "add",
                "fwmark",
                &format!("{:#x}", self.fwmark),
                "lookup",
                &self.table_id.to_string(),
            ],
        )
    }

    /// Remove policy routing rule
    fn remove_policy_routing(&self) -> io::Result<()> {
        self.run_command(
            "ip",
            &[
                "rule",
                "del",
                "fwmark",
                &format!("{:#x}", self.fwmark),
                "lookup",
                &self.table_id.to_string(),
            ],
        )
    }

    /// Add local route in routing table
    fn apply_local_route(&self) -> io::Result<()> {
        debug!(
            table = self.table_id,
            "Adding local route to table"
        );

        // Check if route already exists
        let check_output = Command::new("ip")
            .args([
                "route",
                "show",
                "table",
                &self.table_id.to_string(),
            ])
            .output()?;

        let output_str = String::from_utf8_lossy(&check_output.stdout);
        if output_str.contains("local") {
            debug!("Local route already exists in table {}", self.table_id);
        } else {
            self.run_command(
                "ip",
                &[
                    "route",
                    "add",
                    "local",
                    "0.0.0.0/0",
                    "dev",
                    "lo",
                    "table",
                    &self.table_id.to_string(),
                ],
            )?;
        }

        // Add TUN subnet route for reply packets
        // This is critical: TPROXY socket replies have fwmark set, so they use this table.
        // Without this route, replies to the TUN client network go to loopback and fail.
        if !output_str.contains(&self.tun_subnet) {
            debug!(
                subnet = %self.tun_subnet,
                iface = %self.tun_iface,
                table = self.table_id,
                "Adding TUN subnet route for reply packets"
            );
            self.run_command(
                "ip",
                &[
                    "route",
                    "add",
                    &self.tun_subnet,
                    "dev",
                    &self.tun_iface,
                    "table",
                    &self.table_id.to_string(),
                ],
            )?;
        } else {
            debug!("TUN subnet route already exists in table {}", self.table_id);
        }

        Ok(())
    }

    /// Remove local route from routing table
    fn remove_local_route(&self) -> io::Result<()> {
        // Remove TUN subnet route first
        let _ = self.run_command(
            "ip",
            &[
                "route",
                "del",
                &self.tun_subnet,
                "dev",
                &self.tun_iface,
                "table",
                &self.table_id.to_string(),
            ],
        );

        // Remove local route
        self.run_command(
            "ip",
            &[
                "route",
                "del",
                "local",
                "0.0.0.0/0",
                "dev",
                "lo",
                "table",
                &self.table_id.to_string(),
            ],
        )
    }

    /// Add TPROXY iptables rules
    fn apply_tproxy_rules(&self) -> io::Result<()> {
        debug!(
            iface = %self.tun_iface,
            port = self.tproxy_port,
            "Adding TPROXY iptables rules"
        );

        // Create DIVERT chain for established connection optimization
        // This avoids TPROXY lookup overhead for packets on existing connections
        self.create_divert_chain()?;

        // Add DIVERT rules for established connections (must come before TPROXY rules)
        self.add_divert_rules()?;

        // TCP TPROXY rule (for new connections)
        self.add_tproxy_rule("tcp")?;

        // UDP TPROXY rule (for new connections)
        self.add_tproxy_rule("udp")?;

        Ok(())
    }

    /// Create DIVERT chain for established connection optimization
    ///
    /// The DIVERT chain marks packets from established transparent socket connections
    /// and accepts them, bypassing the TPROXY target lookup overhead.
    fn create_divert_chain(&self) -> io::Result<()> {
        debug!("Creating DIVERT chain for established connections");

        // Try to create the chain (ignore error if it already exists)
        let create_result = Command::new("iptables")
            .args(["-t", "mangle", "-N", "DIVERT"])
            .output()?;

        if !create_result.status.success() {
            let stderr = String::from_utf8_lossy(&create_result.stderr);
            // Chain already exists is OK
            if !stderr.contains("Chain already exists") {
                debug!("DIVERT chain may already exist: {}", stderr.trim());
            }
        }

        // Flush existing rules in case chain existed with old rules
        let _ = Command::new("iptables")
            .args(["-t", "mangle", "-F", "DIVERT"])
            .output();

        // Add mark rule: mark packets with fwmark
        self.run_command(
            "iptables",
            &[
                "-t", "mangle",
                "-A", "DIVERT",
                "-j", "MARK",
                "--set-mark", &format!("{:#x}", self.fwmark),
            ],
        )?;

        // Add accept rule: accept marked packets (bypass further PREROUTING rules)
        self.run_command(
            "iptables",
            &["-t", "mangle", "-A", "DIVERT", "-j", "ACCEPT"],
        )?;

        Ok(())
    }

    /// Add DIVERT rules for established connections
    ///
    /// These rules catch packets on existing transparent socket connections
    /// and jump to the DIVERT chain, bypassing TPROXY lookup.
    fn add_divert_rules(&self) -> io::Result<()> {
        // TCP DIVERT rule for established connections
        self.add_divert_rule("tcp")?;

        // UDP DIVERT rule for established connections
        self.add_divert_rule("udp")?;

        Ok(())
    }

    /// Add a DIVERT rule for a specific protocol
    fn add_divert_rule(&self, protocol: &str) -> io::Result<()> {
        // Check if rule already exists
        let check = Command::new("iptables")
            .args([
                "-t", "mangle",
                "-C", "PREROUTING",
                "-i", &self.tun_iface,
                "-p", protocol,
                "-m", "socket",
                "--transparent",
                "-j", "DIVERT",
            ])
            .output()?;

        if check.status.success() {
            debug!("DIVERT rule for {} already exists", protocol);
            return Ok(());
        }

        // Insert at beginning of PREROUTING (before TPROXY rules)
        self.run_command(
            "iptables",
            &[
                "-t", "mangle",
                "-I", "PREROUTING", "1",  // Insert at position 1 (first)
                "-i", &self.tun_iface,
                "-p", protocol,
                "-m", "socket",
                "--transparent",
                "-j", "DIVERT",
            ],
        )
    }

    /// Remove DIVERT chain and rules
    fn remove_divert_chain(&self) -> io::Result<()> {
        // Remove DIVERT rules from PREROUTING
        let _ = self.remove_divert_rule("tcp");
        let _ = self.remove_divert_rule("udp");

        // Flush DIVERT chain
        let _ = Command::new("iptables")
            .args(["-t", "mangle", "-F", "DIVERT"])
            .output();

        // Delete DIVERT chain
        let _ = Command::new("iptables")
            .args(["-t", "mangle", "-X", "DIVERT"])
            .output();

        Ok(())
    }

    /// Remove a DIVERT rule for a specific protocol
    fn remove_divert_rule(&self, protocol: &str) -> io::Result<()> {
        self.run_command(
            "iptables",
            &[
                "-t", "mangle",
                "-D", "PREROUTING",
                "-i", &self.tun_iface,
                "-p", protocol,
                "-m", "socket",
                "--transparent",
                "-j", "DIVERT",
            ],
        )
    }

    /// Add a single TPROXY rule for a protocol
    fn add_tproxy_rule(&self, protocol: &str) -> io::Result<()> {
        // Check if rule already exists
        let check = Command::new("iptables")
            .args([
                "-t", "mangle",
                "-C", "PREROUTING",
                "-i", &self.tun_iface,
                "-p", protocol,
                "-j", "TPROXY",
                "--on-ip", "127.0.0.1",
                "--on-port", &self.tproxy_port.to_string(),
                "--tproxy-mark", &format!("{:#x}/{:#x}", self.fwmark, self.fwmark),
            ])
            .output()?;

        if check.status.success() {
            debug!("TPROXY rule for {} already exists", protocol);
            return Ok(());
        }

        self.run_command(
            "iptables",
            &[
                "-t", "mangle",
                "-A", "PREROUTING",
                "-i", &self.tun_iface,
                "-p", protocol,
                "-j", "TPROXY",
                "--on-ip", "127.0.0.1",
                "--on-port", &self.tproxy_port.to_string(),
                "--tproxy-mark", &format!("{:#x}/{:#x}", self.fwmark, self.fwmark),
            ],
        )
    }

    /// Remove TPROXY iptables rules
    fn remove_tproxy_rules(&self) -> io::Result<()> {
        // Remove TCP rule
        let _ = self.remove_tproxy_rule("tcp");

        // Remove UDP rule
        let _ = self.remove_tproxy_rule("udp");

        // Remove DIVERT chain and rules
        let _ = self.remove_divert_chain();

        Ok(())
    }

    /// Remove a single TPROXY rule for a protocol
    fn remove_tproxy_rule(&self, protocol: &str) -> io::Result<()> {
        self.run_command(
            "iptables",
            &[
                "-t", "mangle",
                "-D", "PREROUTING",
                "-i", &self.tun_iface,
                "-p", protocol,
                "-j", "TPROXY",
                "--on-ip", "127.0.0.1",
                "--on-port", &self.tproxy_port.to_string(),
                "--tproxy-mark", &format!("{:#x}/{:#x}", self.fwmark, self.fwmark),
            ],
        )
    }

    /// Run a command and handle errors
    fn run_command(&self, program: &str, args: &[&str]) -> io::Result<()> {
        debug!(
            program = %program,
            args = ?args,
            "Running command"
        );

        let output = Command::new(program)
            .args(args)
            .output()?;

        if output.status.success() {
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            error!(
                program = %program,
                args = ?args,
                stderr = %stderr,
                "Command failed"
            );
            Err(io::Error::new(
                io::ErrorKind::Other,
                format!("{} failed: {}", program, stderr.trim()),
            ))
        }
    }

    /// Get the TUN interface name
    #[must_use]
    pub fn tun_iface(&self) -> &str {
        &self.tun_iface
    }

    /// Get the TUN subnet CIDR
    #[must_use]
    pub fn tun_subnet(&self) -> &str {
        &self.tun_subnet
    }

    /// Get the TPROXY port
    #[must_use]
    pub fn tproxy_port(&self) -> u16 {
        self.tproxy_port
    }

    /// Get the fwmark value
    #[must_use]
    pub fn fwmark(&self) -> u32 {
        self.fwmark
    }

    /// Get the routing table ID
    #[must_use]
    pub fn table_id(&self) -> u32 {
        self.table_id
    }

    /// Check if rules have been applied
    #[must_use]
    pub fn rules_applied(&self) -> bool {
        self.rules_applied
    }

    /// Generate shell commands for manual setup
    ///
    /// This is useful for debugging or documentation. Returns the
    /// commands that would be executed by `apply_rules()`.
    #[must_use]
    pub fn generate_setup_commands(&self) -> String {
        format!(
            r#"# Sysctl settings
sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv4.conf.all.route_localnet=1
sysctl -w net.ipv4.conf.{iface}.route_localnet=1
sysctl -w net.ipv4.conf.{iface}.rp_filter=0
sysctl -w net.ipv4.conf.all.rp_filter=0
sysctl -w net.ipv4.ip_nonlocal_bind=1

# Policy routing
ip rule add fwmark {fwmark:#x} lookup {table}

# Local route for TPROXY
ip route add local 0.0.0.0/0 dev lo table {table}

# TUN subnet route for reply packets
# TPROXY socket replies have fwmark, so they use this table. Without this,
# replies to the TUN client network would go to loopback and fail.
ip route add {tun_subnet} dev {iface} table {table}

# DIVERT chain for established connection optimization
iptables -t mangle -N DIVERT
iptables -t mangle -A DIVERT -j MARK --set-mark {fwmark:#x}
iptables -t mangle -A DIVERT -j ACCEPT

# DIVERT rules for established connections (must come before TPROXY)
iptables -t mangle -I PREROUTING 1 -i {iface} -p tcp -m socket --transparent -j DIVERT
iptables -t mangle -I PREROUTING 2 -i {iface} -p udp -m socket --transparent -j DIVERT

# TPROXY iptables rules (for new connections)
iptables -t mangle -A PREROUTING -i {iface} -p tcp -j TPROXY \
    --on-ip 127.0.0.1 --on-port {port} --tproxy-mark {fwmark:#x}/{fwmark:#x}
iptables -t mangle -A PREROUTING -i {iface} -p udp -j TPROXY \
    --on-ip 127.0.0.1 --on-port {port} --tproxy-mark {fwmark:#x}/{fwmark:#x}
"#,
            iface = self.tun_iface,
            tun_subnet = self.tun_subnet,
            port = self.tproxy_port,
            fwmark = self.fwmark,
            table = self.table_id,
        )
    }

    /// Generate shell commands for manual cleanup
    ///
    /// Returns the commands that would be executed by `cleanup_rules()`.
    #[must_use]
    pub fn generate_cleanup_commands(&self) -> String {
        format!(
            r#"# Remove TPROXY iptables rules
iptables -t mangle -D PREROUTING -i {iface} -p tcp -j TPROXY \
    --on-ip 127.0.0.1 --on-port {port} --tproxy-mark {fwmark:#x}/{fwmark:#x}
iptables -t mangle -D PREROUTING -i {iface} -p udp -j TPROXY \
    --on-ip 127.0.0.1 --on-port {port} --tproxy-mark {fwmark:#x}/{fwmark:#x}

# Remove DIVERT rules
iptables -t mangle -D PREROUTING -i {iface} -p tcp -m socket --transparent -j DIVERT
iptables -t mangle -D PREROUTING -i {iface} -p udp -m socket --transparent -j DIVERT

# Remove DIVERT chain
iptables -t mangle -F DIVERT
iptables -t mangle -X DIVERT

# Remove TUN subnet route
ip route del {tun_subnet} dev {iface} table {table}

# Remove local route
ip route del local 0.0.0.0/0 dev lo table {table}

# Remove policy routing
ip rule del fwmark {fwmark:#x} lookup {table}
"#,
            iface = self.tun_iface,
            tun_subnet = self.tun_subnet,
            port = self.tproxy_port,
            fwmark = self.fwmark,
            table = self.table_id,
        )
    }
}

impl Drop for IptablesManager {
    fn drop(&mut self) {
        if self.rules_applied {
            debug!("IptablesManager dropped with rules applied, cleaning up");
            if let Err(e) = self.cleanup_rules() {
                error!("Failed to cleanup rules on drop: {}", e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let manager = IptablesManager::new("tun-in", "10.25.0.0/24", 7893, 0x1, 100).unwrap();
        assert_eq!(manager.tun_iface(), "tun-in");
        assert_eq!(manager.tun_subnet(), "10.25.0.0/24");
        assert_eq!(manager.tproxy_port(), 7893);
        assert_eq!(manager.fwmark(), 0x1);
        assert_eq!(manager.table_id(), 100);
        assert!(!manager.rules_applied());
    }

    #[test]
    fn test_new_validation_empty_name() {
        let result = IptablesManager::new("", "10.25.0.0/24", 7893, 0x1, 100);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("empty"));
    }

    #[test]
    fn test_new_validation_name_too_long() {
        let result = IptablesManager::new("this-name-is-way-too-long", "10.25.0.0/24", 7893, 0x1, 100);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("too long"));
    }

    #[test]
    fn test_new_validation_invalid_char() {
        let result = IptablesManager::new("tun/bad", "10.25.0.0/24", 7893, 0x1, 100);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("Invalid character"));
    }

    #[test]
    fn test_new_validation_valid_names() {
        // Various valid names
        assert!(IptablesManager::new("tun0", "10.25.0.0/24", 7893, 0x1, 100).is_ok());
        assert!(IptablesManager::new("tun-in", "10.25.0.0/24", 7893, 0x1, 100).is_ok());
        assert!(IptablesManager::new("tun_bridge_0", "10.25.0.0/24", 7893, 0x1, 100).is_ok());
        assert!(IptablesManager::new("eth0", "10.25.0.0/24", 7893, 0x1, 100).is_ok());
        assert!(IptablesManager::new("wg-pia-nyc", "10.25.0.0/24", 7893, 0x1, 100).is_ok());
        // 15 chars exactly (max allowed)
        assert!(IptablesManager::new("123456789012345", "10.25.0.0/24", 7893, 0x1, 100).is_ok());
    }

    #[test]
    fn test_generate_setup_commands() {
        let manager = IptablesManager::new("tun-in", "10.25.0.0/24", 7893, 0x1, 100).unwrap();
        let commands = manager.generate_setup_commands();

        assert!(commands.contains("ip_forward=1"));
        assert!(commands.contains("route_localnet=1"));
        assert!(commands.contains("rp_filter=0"));
        assert!(commands.contains("ip_nonlocal_bind=1"));
        assert!(commands.contains("ip rule add fwmark 0x1 lookup 100"));
        assert!(commands.contains("ip route add local 0.0.0.0/0 dev lo table 100"));
        // TUN subnet route for reply packets
        assert!(commands.contains("ip route add 10.25.0.0/24 dev tun-in table 100"));
        // DIVERT chain
        assert!(commands.contains("iptables -t mangle -N DIVERT"));
        assert!(commands.contains("-j MARK --set-mark 0x1"));
        assert!(commands.contains("-m socket --transparent -j DIVERT"));
        // TPROXY rules
        assert!(commands.contains("iptables -t mangle -A PREROUTING"));
        assert!(commands.contains("-i tun-in"));
        assert!(commands.contains("--on-ip 127.0.0.1"));
        assert!(commands.contains("--on-port 7893"));
        assert!(commands.contains("--tproxy-mark 0x1/0x1"));
    }

    #[test]
    fn test_generate_cleanup_commands() {
        let manager = IptablesManager::new("tun-in", "10.25.0.0/24", 7893, 0x1, 100).unwrap();
        let commands = manager.generate_cleanup_commands();

        assert!(commands.contains("iptables -t mangle -D PREROUTING"));
        assert!(commands.contains("ip route del local"));
        assert!(commands.contains("ip rule del fwmark"));
        // TUN subnet route cleanup
        assert!(commands.contains("ip route del 10.25.0.0/24 dev tun-in table 100"));
        // DIVERT cleanup
        assert!(commands.contains("-m socket --transparent -j DIVERT"));
        assert!(commands.contains("iptables -t mangle -F DIVERT"));
        assert!(commands.contains("iptables -t mangle -X DIVERT"));
    }

    #[test]
    fn test_custom_config() {
        let manager = IptablesManager::new("tun-proxy", "192.168.100.0/24", 8080, 0x100, 200).unwrap();
        let commands = manager.generate_setup_commands();

        assert!(commands.contains("tun-proxy"));
        assert!(commands.contains("--on-port 8080"));
        assert!(commands.contains("0x100"));
        assert!(commands.contains("lookup 200"));
        // Custom TUN subnet route
        assert!(commands.contains("ip route add 192.168.100.0/24 dev tun-proxy table 200"));
    }
}
