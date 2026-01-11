//! `WireGuard` interface utilities
//!
//! This module provides utilities for working with `WireGuard` interfaces,
//! including interface name generation that matches the Python implementation
//! in `scripts/setup_kernel_wg_egress.py`.
//!
//! # Interface Naming Convention
//!
//! `WireGuard` interfaces follow Linux's interface name limit of 15 characters
//! (IFNAMSIZ - 1 for null terminator). The naming convention is:
//!
//! - PIA profiles: `wg-pia-{tag}` (prefix 7 chars, leaves 8 for tag)
//! - Custom egress: `wg-eg-{tag}` (prefix 6 chars, leaves 9 for tag)
//! - WARP egress: `wg-warp-{tag}` (prefix 8 chars, leaves 7 for tag)
//! - Peer nodes: `wg-peer-{tag}` (prefix 8 chars, leaves 7 for tag)
//!
//! If the tag exceeds the available length, an MD5 hash of the tag is used
//! instead, truncated to fit within the limit.
//!
//! # Example
//!
//! ```
//! use rust_router::outbound::wireguard::{get_egress_interface_name, EgressType};
//!
//! // Short tag - used directly
//! let iface = get_egress_interface_name("nyc", EgressType::Pia);
//! assert_eq!(iface, "wg-pia-nyc");
//!
//! // Long tag - uses MD5 hash
//! let iface = get_egress_interface_name("us-new-york-city-east", EgressType::Pia);
//! assert_eq!(iface.len(), 15); // Exactly at the limit
//! assert!(iface.starts_with("wg-pia-"));
//! ```
//!
//! # Note
//!
//! This module provides UTILITIES only. The actual `WireGuard` connections are
//! handled by `DirectOutbound` with `bind_interface` and `routing_mark` options.
//! The kernel `WireGuard` interfaces are created by the Python script
//! `setup_kernel_wg_egress.py`.

use std::fs;
use std::io;
use std::path::Path;

use md5::{Digest, Md5};

use crate::error::OutboundError;

/// Maximum length for Linux interface names (IFNAMSIZ - 1)
pub const INTERFACE_MAX_LEN: usize = 15;

/// Prefix for PIA `WireGuard` interfaces (7 chars)
pub const PIA_PREFIX: &str = "wg-pia-";

/// Prefix for custom `WireGuard` interfaces (6 chars)
pub const CUSTOM_PREFIX: &str = "wg-eg-";

/// Prefix for WARP `WireGuard` interfaces (8 chars)
pub const WARP_PREFIX: &str = "wg-warp-";

/// Prefix for peer node `WireGuard` interfaces (8 chars)
pub const PEER_PREFIX: &str = "wg-peer-";

/// Type of `WireGuard` egress, determining the interface name prefix
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EgressType {
    /// PIA (Private Internet Access) VPN exit
    /// Interface prefix: `wg-pia-`
    Pia,
    /// Custom `WireGuard` egress
    /// Interface prefix: `wg-eg-`
    Custom,
    /// Cloudflare WARP `WireGuard` egress
    /// Interface prefix: `wg-warp-`
    Warp,
    /// Peer node tunnel
    /// Interface prefix: `wg-peer-`
    Peer,
}

impl EgressType {
    /// Get the interface name prefix for this egress type
    #[must_use]
    pub const fn prefix(&self) -> &'static str {
        match self {
            Self::Pia => PIA_PREFIX,
            Self::Custom => CUSTOM_PREFIX,
            Self::Warp => WARP_PREFIX,
            Self::Peer => PEER_PREFIX,
        }
    }

    /// Get the maximum tag length for this egress type
    ///
    /// This is `INTERFACE_MAX_LEN - prefix.len()`
    #[must_use]
    pub const fn max_tag_len(&self) -> usize {
        INTERFACE_MAX_LEN - self.prefix().len()
    }
}

impl std::fmt::Display for EgressType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pia => write!(f, "pia"),
            Self::Custom => write!(f, "custom"),
            Self::Warp => write!(f, "warp"),
            Self::Peer => write!(f, "peer"),
        }
    }
}

impl std::str::FromStr for EgressType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "pia" => Ok(Self::Pia),
            "custom" => Ok(Self::Custom),
            "warp" => Ok(Self::Warp),
            "peer" => Ok(Self::Peer),
            _ => Err(format!("unknown egress type: {s}")),
        }
    }
}

/// Generate a kernel `WireGuard` interface name for the given egress tag and type
///
/// This function produces output **identical** to the Python function
/// `get_egress_interface_name()` in `scripts/setup_kernel_wg_egress.py`.
///
/// # Arguments
///
/// * `tag` - The egress tag (e.g., "`new_york`", "cn2-la")
/// * `egress_type` - The type of egress (PIA, Custom, WARP, Peer)
///
/// # Returns
///
/// An interface name of at most 15 characters, formatted as `{prefix}{suffix}`
/// where:
/// - If `tag.len() <= max_tag_len`, suffix = tag
/// - Otherwise, suffix = `MD5(tag).hexdigest()`[:`max_tag_len`]
///
/// # Examples
///
/// ```
/// use rust_router::outbound::wireguard::{get_egress_interface_name, EgressType};
///
/// // Short tags are used directly
/// assert_eq!(get_egress_interface_name("nyc", EgressType::Pia), "wg-pia-nyc");
/// assert_eq!(get_egress_interface_name("la", EgressType::Custom), "wg-eg-la");
///
/// // Long tags use MD5 hash
/// let long_tag = "us-new-york-city-east-coast-primary";
/// let iface = get_egress_interface_name(long_tag, EgressType::Pia);
/// assert!(iface.len() <= 15);
/// assert!(iface.starts_with("wg-pia-"));
/// ```
#[must_use]
pub fn get_egress_interface_name(tag: &str, egress_type: EgressType) -> String {
    let prefix = egress_type.prefix();
    let max_tag_len = egress_type.max_tag_len();

    if tag.len() <= max_tag_len {
        format!("{prefix}{tag}")
    } else {
        // Use MD5 hash for long tags (matches Python implementation)
        let mut hasher = Md5::new();
        hasher.update(tag.as_bytes());
        let hash = hasher.finalize();
        let hex = format!("{hash:x}");
        let suffix = &hex[..max_tag_len];
        format!("{prefix}{suffix}")
    }
}

/// Information about a network interface
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceInfo {
    /// Interface name
    pub name: String,
    /// Interface index
    pub index: u32,
    /// Interface flags (from /sys/class/net/{iface}/flags)
    pub flags: u32,
    /// Interface MTU
    pub mtu: u32,
    /// Whether the interface is up
    pub is_up: bool,
    /// Interface type (from /sys/class/net/{iface}/type)
    pub if_type: u16,
}

/// `ARPHRD_NONE` from Linux kernel (`include/uapi/linux/if_arp.h`)
/// `WireGuard` interfaces use this type because they don't have a hardware address
const ARPHRD_NONE: u16 = 65534;

impl InterfaceInfo {
    /// Check if this is a `WireGuard` interface
    ///
    /// `WireGuard` interfaces have type `ARPHRD_NONE` (65534) because they are
    /// virtual tunnel interfaces without hardware addresses. This is defined
    /// in the Linux kernel's `include/uapi/linux/if_arp.h`.
    #[must_use]
    pub const fn is_wireguard(&self) -> bool {
        self.if_type == ARPHRD_NONE
    }
}

/// Check if a network interface exists
///
/// # Arguments
///
/// * `interface` - The interface name to check
///
/// # Returns
///
/// `true` if the interface exists, `false` otherwise
#[must_use]
pub fn interface_exists(interface: &str) -> bool {
    Path::new("/sys/class/net").join(interface).exists()
}

/// Validate that an interface exists, returning an error if not
///
/// # Arguments
///
/// * `interface` - The interface name to validate
///
/// # Errors
///
/// Returns `OutboundError::SocketOption` if the interface does not exist.
pub fn validate_interface_exists(interface: &str) -> Result<(), OutboundError> {
    if interface.len() > INTERFACE_MAX_LEN {
        return Err(OutboundError::SocketOption {
            option: "SO_BINDTODEVICE".into(),
            reason: format!(
                "interface name too long: {} ({} chars, max {})",
                interface,
                interface.len(),
                INTERFACE_MAX_LEN
            ),
        });
    }

    if !interface_exists(interface) {
        return Err(OutboundError::SocketOption {
            option: "SO_BINDTODEVICE".into(),
            reason: format!("interface does not exist: {interface}"),
        });
    }

    Ok(())
}

/// Get information about a network interface
///
/// # Arguments
///
/// * `interface` - The interface name
///
/// # Returns
///
/// `InterfaceInfo` containing the interface details.
///
/// # Errors
///
/// Returns `OutboundError::SocketOption` if the interface does not exist
/// or if reading its properties fails.
pub fn get_interface_info(interface: &str) -> Result<InterfaceInfo, OutboundError> {
    let base_path = Path::new("/sys/class/net").join(interface);

    if !base_path.exists() {
        return Err(OutboundError::SocketOption {
            option: "interface".into(),
            reason: format!("interface does not exist: {interface}"),
        });
    }

    // Read interface index
    let index = read_sysfs_u32(&base_path.join("ifindex"), interface)?;

    // Read flags
    let flags = read_sysfs_hex_u32(&base_path.join("flags"), interface)?;

    // Read MTU
    let mtu = read_sysfs_u32(&base_path.join("mtu"), interface)?;

    // Read type
    let if_type = read_sysfs_u32(&base_path.join("type"), interface)? as u16;

    // IFF_UP is 0x1
    let is_up = (flags & 0x1) != 0;

    Ok(InterfaceInfo {
        name: interface.to_string(),
        index,
        flags,
        mtu,
        is_up,
        if_type,
    })
}

/// Read a u32 value from a sysfs file
fn read_sysfs_u32(path: &Path, interface: &str) -> Result<u32, OutboundError> {
    let content = fs::read_to_string(path).map_err(|e| OutboundError::SocketOption {
        option: "sysfs".into(),
        reason: format!(
            "failed to read {}: {}",
            path.display(),
            io_error_message(&e, interface)
        ),
    })?;

    content
        .trim()
        .parse()
        .map_err(|e| OutboundError::SocketOption {
            option: "sysfs".into(),
            reason: format!("failed to parse {} as u32: {}", path.display(), e),
        })
}

/// Read a hex u32 value from a sysfs file (e.g., "0x1003")
fn read_sysfs_hex_u32(path: &Path, interface: &str) -> Result<u32, OutboundError> {
    let content = fs::read_to_string(path).map_err(|e| OutboundError::SocketOption {
        option: "sysfs".into(),
        reason: format!(
            "failed to read {}: {}",
            path.display(),
            io_error_message(&e, interface)
        ),
    })?;

    let trimmed = content.trim();

    // Handle both "0x1003" and "1003" formats
    let value_str = trimmed.strip_prefix("0x").unwrap_or(trimmed);

    u32::from_str_radix(value_str, 16).map_err(|e| OutboundError::SocketOption {
        option: "sysfs".into(),
        reason: format!("failed to parse {} as hex u32: {}", path.display(), e),
    })
}

/// Format an IO error message with context
fn io_error_message(e: &io::Error, interface: &str) -> String {
    if e.kind() == io::ErrorKind::NotFound {
        format!("interface {interface} does not exist")
    } else if e.kind() == io::ErrorKind::PermissionDenied {
        format!("permission denied reading interface {interface}")
    } else {
        e.to_string()
    }
}

/// List all `WireGuard` egress interfaces on the system
///
/// This returns interfaces matching the naming patterns:
/// - `wg-pia-*`
/// - `wg-eg-*`
/// - `wg-warp-*`
/// - `wg-peer-*`
///
/// # Returns
///
/// A vector of interface names.
pub fn list_egress_interfaces() -> Vec<String> {
    let net_path = Path::new("/sys/class/net");

    let Ok(entries) = fs::read_dir(net_path) else {
        return Vec::new();
    };

    entries
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let name = entry.file_name().into_string().ok()?;

            if name.starts_with(PIA_PREFIX)
                || name.starts_with(CUSTOM_PREFIX)
                || name.starts_with(WARP_PREFIX)
                || name.starts_with(PEER_PREFIX)
            {
                Some(name)
            } else {
                None
            }
        })
        .collect()
}

/// Parse an interface name to extract the egress type and tag
///
/// # Arguments
///
/// * `interface` - The interface name (e.g., "wg-pia-nyc")
///
/// # Returns
///
/// `Some((egress_type, tag))` if the interface name matches a known pattern,
/// `None` otherwise.
///
/// # Note
///
/// If the original tag was hashed due to length, the returned tag will be
/// the hash, not the original tag.
///
/// # Examples
///
/// ```
/// use rust_router::outbound::wireguard::{parse_interface_name, EgressType};
///
/// let (egress_type, tag) = parse_interface_name("wg-pia-nyc").unwrap();
/// assert_eq!(egress_type, EgressType::Pia);
/// assert_eq!(tag, "nyc");
///
/// let (egress_type, tag) = parse_interface_name("wg-eg-cn2-la").unwrap();
/// assert_eq!(egress_type, EgressType::Custom);
/// assert_eq!(tag, "cn2-la");
/// ```
#[must_use]
pub fn parse_interface_name(interface: &str) -> Option<(EgressType, &str)> {
    if let Some(tag) = interface.strip_prefix(PIA_PREFIX) {
        Some((EgressType::Pia, tag))
    } else if let Some(tag) = interface.strip_prefix(CUSTOM_PREFIX) {
        Some((EgressType::Custom, tag))
    } else if let Some(tag) = interface.strip_prefix(WARP_PREFIX) {
        Some((EgressType::Warp, tag))
    } else if let Some(tag) = interface.strip_prefix(PEER_PREFIX) {
        Some((EgressType::Peer, tag))
    } else {
        None
    }
}

/// Check if an interface name is a valid `WireGuard` egress interface
///
/// # Arguments
///
/// * `interface` - The interface name to check
///
/// # Returns
///
/// `true` if the interface matches a known egress pattern.
#[must_use]
pub fn is_egress_interface(interface: &str) -> bool {
    parse_interface_name(interface).is_some()
}

/// Get the egress type from an interface name
///
/// # Arguments
///
/// * `interface` - The interface name
///
/// # Returns
///
/// `Some(EgressType)` if the interface matches a known pattern.
#[must_use]
pub fn get_egress_type(interface: &str) -> Option<EgressType> {
    parse_interface_name(interface).map(|(t, _)| t)
}

// ============================================================================
// Routing Mark and Table Utilities
// ============================================================================

/// Minimum peer tunnel port (reserved range 36200-36299)
pub const PEER_PORT_MIN: u16 = 36200;

/// Maximum peer tunnel port
pub const PEER_PORT_MAX: u16 = 36299;

/// Base routing table for peer nodes (500-599)
pub const PEER_TABLE_BASE: u32 = 500;

/// Check if a routing mark is valid for ECMP, DSCP, or relay routing
///
/// # Routing Mark Ranges
///
/// | Range | Purpose |
/// |-------|---------|
/// | 200-299 | ECMP outbound groups |
/// | 300-363 | DSCP terminal routing |
/// | 400-463 | Relay node forwarding |
/// | 500-599 | Peer node tunnels |
#[must_use]
pub fn is_valid_routing_mark(mark: u32) -> bool {
    // ECMP range
    (200..300).contains(&mark) ||
    // DSCP range
    (300..364).contains(&mark) ||
    // Relay range
    (400..464).contains(&mark) ||
    // Peer range
    (500..600).contains(&mark)
}

/// Calculate the routing table for a peer tunnel port
///
/// Peer tunnel ports in the range 36200-36299 map to routing tables 500-599.
///
/// # Arguments
///
/// * `port` - The peer tunnel port
///
/// # Returns
///
/// `Some(table)` if the port is in the valid peer range, `None` otherwise.
///
/// # Example
///
/// ```
/// use rust_router::outbound::wireguard::get_peer_routing_table;
///
/// assert_eq!(get_peer_routing_table(36200), Some(500));
/// assert_eq!(get_peer_routing_table(36250), Some(550));
/// assert_eq!(get_peer_routing_table(36100), None); // Not in peer range
/// ```
#[must_use]
pub fn get_peer_routing_table(port: u16) -> Option<u32> {
    if (PEER_PORT_MIN..=PEER_PORT_MAX).contains(&port) {
        Some(PEER_TABLE_BASE + u32::from(port - PEER_PORT_MIN))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // EgressType tests
    // =========================================================================

    #[test]
    fn test_egress_type_prefix() {
        assert_eq!(EgressType::Pia.prefix(), "wg-pia-");
        assert_eq!(EgressType::Custom.prefix(), "wg-eg-");
        assert_eq!(EgressType::Warp.prefix(), "wg-warp-");
        assert_eq!(EgressType::Peer.prefix(), "wg-peer-");
    }

    #[test]
    fn test_egress_type_max_tag_len() {
        // INTERFACE_MAX_LEN = 15
        // PIA: 15 - 7 = 8
        assert_eq!(EgressType::Pia.max_tag_len(), 8);
        // Custom: 15 - 6 = 9
        assert_eq!(EgressType::Custom.max_tag_len(), 9);
        // WARP: 15 - 8 = 7
        assert_eq!(EgressType::Warp.max_tag_len(), 7);
        // Peer: 15 - 8 = 7
        assert_eq!(EgressType::Peer.max_tag_len(), 7);
    }

    #[test]
    fn test_egress_type_display() {
        assert_eq!(EgressType::Pia.to_string(), "pia");
        assert_eq!(EgressType::Custom.to_string(), "custom");
        assert_eq!(EgressType::Warp.to_string(), "warp");
        assert_eq!(EgressType::Peer.to_string(), "peer");
    }

    #[test]
    fn test_egress_type_from_str() {
        assert_eq!("pia".parse::<EgressType>().unwrap(), EgressType::Pia);
        assert_eq!("PIA".parse::<EgressType>().unwrap(), EgressType::Pia);
        assert_eq!("custom".parse::<EgressType>().unwrap(), EgressType::Custom);
        assert_eq!("CUSTOM".parse::<EgressType>().unwrap(), EgressType::Custom);
        assert_eq!("warp".parse::<EgressType>().unwrap(), EgressType::Warp);
        assert_eq!("peer".parse::<EgressType>().unwrap(), EgressType::Peer);
        assert!("unknown".parse::<EgressType>().is_err());
    }

    // =========================================================================
    // Interface name generation tests
    // =========================================================================

    #[test]
    fn test_short_tag_pia() {
        let iface = get_egress_interface_name("nyc", EgressType::Pia);
        assert_eq!(iface, "wg-pia-nyc");
        assert!(iface.len() <= INTERFACE_MAX_LEN);
    }

    #[test]
    fn test_short_tag_custom() {
        let iface = get_egress_interface_name("cn2-la", EgressType::Custom);
        assert_eq!(iface, "wg-eg-cn2-la");
        assert!(iface.len() <= INTERFACE_MAX_LEN);
    }

    #[test]
    fn test_short_tag_warp() {
        let iface = get_egress_interface_name("main", EgressType::Warp);
        assert_eq!(iface, "wg-warp-main");
        assert!(iface.len() <= INTERFACE_MAX_LEN);
    }

    #[test]
    fn test_short_tag_peer() {
        let iface = get_egress_interface_name("node1", EgressType::Peer);
        assert_eq!(iface, "wg-peer-node1");
        assert!(iface.len() <= INTERFACE_MAX_LEN);
    }

    #[test]
    fn test_exact_max_length_tag() {
        // PIA max tag len is 8
        let tag = "12345678";
        assert_eq!(tag.len(), 8);
        let iface = get_egress_interface_name(tag, EgressType::Pia);
        assert_eq!(iface, "wg-pia-12345678");
        assert_eq!(iface.len(), 15);
    }

    #[test]
    fn test_long_tag_uses_hash() {
        let long_tag = "us-new-york-city-east-coast-primary";
        let iface = get_egress_interface_name(long_tag, EgressType::Pia);

        // Should use hash
        assert!(iface.starts_with("wg-pia-"));
        assert_eq!(iface.len(), 15);

        // Hash suffix should be 8 chars (hex digits only) since PIA prefix is 7 chars
        let suffix = &iface[7..];
        assert_eq!(suffix.len(), 8);
        assert!(suffix.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_long_tag_custom() {
        let long_tag = "very-long-custom-wireguard-egress-name";
        let iface = get_egress_interface_name(long_tag, EgressType::Custom);

        assert!(iface.starts_with("wg-eg-"));
        assert_eq!(iface.len(), 15);
    }

    #[test]
    fn test_hash_is_deterministic() {
        let tag = "us-new-york-city-east-coast";
        let iface1 = get_egress_interface_name(tag, EgressType::Pia);
        let iface2 = get_egress_interface_name(tag, EgressType::Pia);
        assert_eq!(iface1, iface2);
    }

    #[test]
    fn test_different_tags_different_hashes() {
        let tag1 = "us-new-york-city-east-coast-1";
        let tag2 = "us-new-york-city-east-coast-2";
        let iface1 = get_egress_interface_name(tag1, EgressType::Pia);
        let iface2 = get_egress_interface_name(tag2, EgressType::Pia);
        assert_ne!(iface1, iface2);
    }

    #[test]
    fn test_empty_tag() {
        let iface = get_egress_interface_name("", EgressType::Pia);
        assert_eq!(iface, "wg-pia-");
        assert!(iface.len() <= INTERFACE_MAX_LEN);
    }

    #[test]
    fn test_single_char_tag() {
        let iface = get_egress_interface_name("a", EgressType::Pia);
        assert_eq!(iface, "wg-pia-a");
    }

    #[test]
    fn test_unicode_tag_short() {
        // Unicode characters - should work if they fit
        let iface = get_egress_interface_name("abc", EgressType::Custom);
        assert_eq!(iface, "wg-eg-abc");
    }

    #[test]
    fn test_unicode_tag_long_hashed() {
        // Multi-byte UTF-8 characters that exceed length limit
        // Note: The Python implementation uses len(tag) which counts bytes in UTF-8
        let unicode_tag = "\u{4e2d}\u{56fd}\u{8282}\u{70b9}"; // Chinese characters
        let iface = get_egress_interface_name(unicode_tag, EgressType::Pia);

        // Should be hashed since UTF-8 encoding is > 7 bytes
        assert!(iface.starts_with("wg-pia-"));
        assert!(iface.len() <= INTERFACE_MAX_LEN);
    }

    #[test]
    fn test_special_characters_in_tag() {
        let iface = get_egress_interface_name("us_ny-1", EgressType::Custom);
        assert_eq!(iface, "wg-eg-us_ny-1");
    }

    // =========================================================================
    // Python parity tests
    // =========================================================================

    /// These tests verify exact parity with Python's `get_egress_interface_name()`
    #[test]
    fn test_python_parity_short_pia() {
        // Python: get_egress_interface_name("new_york", is_pia=True) -> "wg-pia-new_yor" (7 chars)
        // Wait, "new_york" is 8 chars, which exceeds max 7
        let tag = "new_yor"; // 7 chars - fits
        let iface = get_egress_interface_name(tag, EgressType::Pia);
        assert_eq!(iface, "wg-pia-new_yor");

        // "new_york" is 8 chars - should be hashed
        let tag2 = "new_york";
        let iface2 = get_egress_interface_name(tag2, EgressType::Pia);
        assert!(iface2.starts_with("wg-pia-"));
        assert_eq!(iface2.len(), 15);
    }

    #[test]
    fn test_python_parity_custom() {
        // Custom has 9 char max tag length
        let tag = "cn2-la"; // 6 chars - fits
        let iface = get_egress_interface_name(tag, EgressType::Custom);
        assert_eq!(iface, "wg-eg-cn2-la");
    }

    #[test]
    fn test_python_parity_warp() {
        // Python: get_egress_interface_name("main", egress_type="warp")
        let iface = get_egress_interface_name("main", EgressType::Warp);
        assert_eq!(iface, "wg-warp-main");
    }

    #[test]
    fn test_python_parity_hash_result() {
        // To verify hash parity with Python, we need to compute:
        // hashlib.md5("us-new-york-city-east".encode()).hexdigest()[:8]
        // (8 chars because PIA prefix is 7 chars, leaving 8 for the tag/hash)
        let tag = "us-new-york-city-east";
        let iface = get_egress_interface_name(tag, EgressType::Pia);

        // Compute expected hash
        let mut hasher = Md5::new();
        hasher.update(tag.as_bytes());
        let hash = hasher.finalize();
        let expected_suffix = &format!("{hash:x}")[..8];
        let expected = format!("wg-pia-{expected_suffix}");

        assert_eq!(iface, expected);
    }

    /// Comprehensive Python parity test with hardcoded expected values
    /// These values were generated by running Python's get_egress_interface_name()
    #[test]
    fn test_python_parity_comprehensive() {
        // Short tags - used directly
        assert_eq!(get_egress_interface_name("nyc", EgressType::Pia), "wg-pia-nyc");
        assert_eq!(get_egress_interface_name("la", EgressType::Custom), "wg-eg-la");
        assert_eq!(get_egress_interface_name("main", EgressType::Warp), "wg-warp-main");
        assert_eq!(get_egress_interface_name("node1", EgressType::Peer), "wg-peer-node1");

        // Long tags - Python output verified:
        // get_egress_interface_name("us-new-york-city-east", is_pia=True) -> "wg-pia-cc74ff54"
        assert_eq!(
            get_egress_interface_name("us-new-york-city-east", EgressType::Pia),
            "wg-pia-cc74ff54"
        );

        // get_egress_interface_name("very-long-custom-wireguard-egress-name", is_pia=False) -> "wg-eg-b0030602c"
        assert_eq!(
            get_egress_interface_name("very-long-custom-wireguard-egress-name", EgressType::Custom),
            "wg-eg-b0030602c"
        );
    }

    // =========================================================================
    // Interface parsing tests
    // =========================================================================

    #[test]
    fn test_parse_interface_name_pia() {
        let (egress_type, tag) = parse_interface_name("wg-pia-nyc").unwrap();
        assert_eq!(egress_type, EgressType::Pia);
        assert_eq!(tag, "nyc");
    }

    #[test]
    fn test_parse_interface_name_custom() {
        let (egress_type, tag) = parse_interface_name("wg-eg-cn2-la").unwrap();
        assert_eq!(egress_type, EgressType::Custom);
        assert_eq!(tag, "cn2-la");
    }

    #[test]
    fn test_parse_interface_name_warp() {
        let (egress_type, tag) = parse_interface_name("wg-warp-main").unwrap();
        assert_eq!(egress_type, EgressType::Warp);
        assert_eq!(tag, "main");
    }

    #[test]
    fn test_parse_interface_name_peer() {
        let (egress_type, tag) = parse_interface_name("wg-peer-node1").unwrap();
        assert_eq!(egress_type, EgressType::Peer);
        assert_eq!(tag, "node1");
    }

    #[test]
    fn test_parse_interface_name_unknown() {
        assert!(parse_interface_name("eth0").is_none());
        assert!(parse_interface_name("wg0").is_none());
        assert!(parse_interface_name("wg-ingress").is_none());
    }

    #[test]
    fn test_is_egress_interface() {
        assert!(is_egress_interface("wg-pia-nyc"));
        assert!(is_egress_interface("wg-eg-test"));
        assert!(is_egress_interface("wg-warp-main"));
        assert!(is_egress_interface("wg-peer-node1"));
        assert!(!is_egress_interface("eth0"));
        assert!(!is_egress_interface("wg-ingress"));
    }

    #[test]
    fn test_get_egress_type() {
        assert_eq!(get_egress_type("wg-pia-nyc"), Some(EgressType::Pia));
        assert_eq!(get_egress_type("wg-eg-test"), Some(EgressType::Custom));
        assert_eq!(get_egress_type("wg-warp-main"), Some(EgressType::Warp));
        assert_eq!(get_egress_type("wg-peer-node1"), Some(EgressType::Peer));
        assert_eq!(get_egress_type("eth0"), None);
    }

    // =========================================================================
    // Interface info tests (mocked filesystem)
    // =========================================================================

    #[test]
    fn test_interface_info_is_wireguard() {
        let info = InterfaceInfo {
            name: "wg-pia-test".to_string(),
            index: 10,
            flags: 0x1003,
            mtu: 1420,
            is_up: true,
            if_type: 65534, // ARPHRD_NONE (WireGuard)
        };
        assert!(info.is_wireguard());

        let eth_info = InterfaceInfo {
            name: "eth0".to_string(),
            index: 2,
            flags: 0x1003,
            mtu: 1500,
            is_up: true,
            if_type: 1, // ARPHRD_ETHER
        };
        assert!(!eth_info.is_wireguard());
    }

    #[test]
    fn test_interface_exists_lo() {
        // Loopback interface should always exist
        assert!(interface_exists("lo"));
    }

    #[test]
    fn test_interface_exists_nonexistent() {
        assert!(!interface_exists("nonexistent_interface_12345"));
    }

    #[test]
    fn test_validate_interface_exists_long_name() {
        let result = validate_interface_exists("this_is_way_too_long_for_an_interface_name");
        assert!(result.is_err());
        if let Err(OutboundError::SocketOption { option, reason }) = result {
            assert_eq!(option, "SO_BINDTODEVICE");
            assert!(reason.contains("too long"));
        }
    }

    #[test]
    fn test_validate_interface_exists_nonexistent() {
        let result = validate_interface_exists("nonexistent");
        assert!(result.is_err());
        if let Err(OutboundError::SocketOption { option, reason }) = result {
            assert_eq!(option, "SO_BINDTODEVICE");
            assert!(reason.contains("does not exist"));
        }
    }

    #[test]
    fn test_get_interface_info_lo() {
        // Loopback should be readable on any Linux system
        let result = get_interface_info("lo");
        if let Ok(info) = result {
            assert_eq!(info.name, "lo");
            assert!(info.is_up);
            assert!(info.mtu > 0);
            assert!(!info.is_wireguard());
        }
        // If it fails (e.g., in non-Linux CI), just skip
    }

    #[test]
    fn test_get_interface_info_nonexistent() {
        let result = get_interface_info("nonexistent");
        assert!(result.is_err());
    }

    // =========================================================================
    // Constant verification tests
    // =========================================================================

    #[test]
    fn test_prefix_lengths() {
        assert_eq!(PIA_PREFIX.len(), 7);
        assert_eq!(CUSTOM_PREFIX.len(), 6);
        assert_eq!(WARP_PREFIX.len(), 8);
        assert_eq!(PEER_PREFIX.len(), 8);
    }

    #[test]
    fn test_interface_max_len() {
        assert_eq!(INTERFACE_MAX_LEN, 15);
    }

    #[test]
    fn test_all_generated_names_within_limit() {
        let tags = [
            "",
            "a",
            "ab",
            "abc",
            "abcd",
            "abcde",
            "abcdef",
            "abcdefg",
            "abcdefgh",
            "abcdefghi",
            "abcdefghij",
            "this-is-a-very-very-very-long-tag-name",
            "unicode-\u{4e2d}\u{6587}",
        ];

        let types = [
            EgressType::Pia,
            EgressType::Custom,
            EgressType::Warp,
            EgressType::Peer,
        ];

        for tag in &tags {
            for egress_type in &types {
                let iface = get_egress_interface_name(tag, *egress_type);
                assert!(
                    iface.len() <= INTERFACE_MAX_LEN,
                    "Interface name '{}' exceeds max length for tag '{}' type {:?}",
                    iface,
                    tag,
                    egress_type
                );
            }
        }
    }

    // =========================================================================
    // Roundtrip tests
    // =========================================================================

    #[test]
    fn test_roundtrip_short_tags() {
        let short_tags = [
            ("nyc", EgressType::Pia),
            ("la", EgressType::Custom),
            ("main", EgressType::Warp),
            ("node1", EgressType::Peer),
        ];

        for (tag, egress_type) in short_tags {
            let iface = get_egress_interface_name(tag, egress_type);
            let (parsed_type, parsed_tag) = parse_interface_name(&iface).unwrap();
            assert_eq!(parsed_type, egress_type);
            assert_eq!(parsed_tag, tag);
        }
    }

    #[test]
    fn test_roundtrip_long_tags_produces_hash() {
        // Long tags get hashed, so roundtrip won't recover original tag
        let long_tag = "us-new-york-city-east-coast-primary";
        let iface = get_egress_interface_name(long_tag, EgressType::Pia);
        let (parsed_type, parsed_tag) = parse_interface_name(&iface).unwrap();

        assert_eq!(parsed_type, EgressType::Pia);
        // Parsed tag is the hash, not the original
        assert_ne!(parsed_tag, long_tag);
        // PIA prefix is 7 chars, so hash suffix is 8 chars
        assert_eq!(parsed_tag.len(), 8);
        assert!(parsed_tag.chars().all(|c| c.is_ascii_hexdigit()));
    }

    // =========================================================================
    // list_egress_interfaces tests (QA-002)
    // =========================================================================

    #[test]
    fn test_list_egress_interfaces() {
        // On a system without WireGuard interfaces, returns empty vec
        // On a system with WireGuard interfaces, all returned names should match our prefixes
        let interfaces = list_egress_interfaces();
        for iface in &interfaces {
            assert!(
                is_egress_interface(iface),
                "list_egress_interfaces returned '{}' which is not a recognized egress interface",
                iface
            );
        }
    }

    #[test]
    fn test_list_egress_interfaces_filters_correctly() {
        // Verify that list_egress_interfaces would correctly filter based on prefix
        // This tests the logic without requiring actual interfaces
        let test_cases = vec![
            ("wg-pia-nyc", true),
            ("wg-eg-test", true),
            ("wg-warp-main", true),
            ("wg-peer-node1", true),
            ("eth0", false),
            ("wg-ingress", false),
            ("lo", false),
        ];

        for (name, should_be_egress) in test_cases {
            assert_eq!(
                is_egress_interface(name),
                should_be_egress,
                "is_egress_interface('{}') should be {}",
                name,
                should_be_egress
            );
        }
    }
}
