// Some structs/functions are defined for completeness but not all are used.
#![allow(dead_code)]

//! Linux TUN/TAP ioctl constants and helper functions
//!
//! This module provides the low-level constants needed to interact with
//! Linux TUN/TAP devices via the ioctl interface.
//!
//! # References
//!
//! - Linux kernel: `include/uapi/linux/if_tun.h`
//! - TUN/TAP documentation: `Documentation/networking/tuntap.txt`

// ============================================================================
// TUN/TAP ioctl request codes
// ============================================================================

/// `TUNSETIFF` - Configure the TUN/TAP interface
///
/// This ioctl is used to set the interface flags (TUN vs TAP, PI header, etc.)
/// and optionally specify a device name. The kernel will create the device if
/// it doesn't exist.
///
/// # Value
///
/// The value `0x400454ca` is computed as:
/// - `_IOW('T', 202, int)` where `'T'` = 0x54
/// - Direction: write (0x40000000)
/// - Size: 4 bytes (0x00040000)
/// - Type: 'T' = 0x54 (0x00005400)
/// - Number: 202 = 0xca (0x000000ca)
pub const TUNSETIFF: libc::c_ulong = 0x4004_54ca;

/// `TUNSETPERSIST` - Set TUN/TAP device persistence
///
/// When set, the TUN/TAP device will persist after the file descriptor is closed.
/// This is useful for network namespace scenarios.
pub const TUNSETPERSIST: libc::c_ulong = 0x4004_54cb;

/// `TUNSETOWNER` - Set the owner UID of the TUN/TAP device
pub const TUNSETOWNER: libc::c_ulong = 0x4004_54cc;

/// `TUNSETGROUP` - Set the group GID of the TUN/TAP device
#[allow(dead_code)]
pub const TUNSETGROUP: libc::c_ulong = 0x4004_54ce;

// ============================================================================
// Interface flags for TUNSETIFF
// ============================================================================

/// `IFF_TUN` - TUN device (layer 3, IP packets)
///
/// When this flag is set, the device operates at layer 3 (network layer).
/// Packets read/written are raw IP packets without any Ethernet header.
pub const IFF_TUN: libc::c_short = 0x0001;

/// `IFF_TAP` - TAP device (layer 2, Ethernet frames)
///
/// When this flag is set, the device operates at layer 2 (data link layer).
/// Packets read/written are Ethernet frames with MAC headers.
pub const IFF_TAP: libc::c_short = 0x0002;

/// `IFF_NO_PI` - Do not provide packet information header
///
/// By default, each packet is prefixed with a 4-byte packet information (PI)
/// header containing flags and protocol type. Setting this flag disables
/// the PI header, providing raw packets only.
///
/// **Recommendation**: Always use this flag for TUN devices to simplify
/// packet processing.
pub const IFF_NO_PI: libc::c_short = 0x1000;

/// `IFF_MULTI_QUEUE` - Enable multi-queue support
///
/// When set, multiple file descriptors can be opened for the same TUN/TAP
/// device, enabling parallel packet processing across multiple threads/cores.
///
/// # Requirements
///
/// - Linux kernel 3.8+
/// - All queues must use the same interface name
///
/// # Usage
///
/// 1. Create first queue with `IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE`
/// 2. Create additional queues with same flags and interface name
pub const IFF_MULTI_QUEUE: libc::c_short = 0x0100;

/// `IFF_VNET_HDR` - Include virtio-net header
///
/// When set, packets include a virtio-net header for offloading features
/// like checksum and segmentation offload. Used primarily for VM networking.
pub const IFF_VNET_HDR: libc::c_short = 0x4000;

// ============================================================================
// Socket ioctls for interface configuration
// ============================================================================

/// `SIOCSIFADDR` - Set interface IP address
///
/// Used with a socket fd (not TUN fd) to assign an IP address to an interface.
pub const SIOCSIFADDR: libc::c_ulong = 0x8916;

/// `SIOCSIFNETMASK` - Set interface netmask
///
/// Used with a socket fd to set the network mask for an interface.
pub const SIOCSIFNETMASK: libc::c_ulong = 0x891c;

/// `SIOCSIFMTU` - Set interface MTU
///
/// Used with a socket fd to set the Maximum Transmission Unit.
pub const SIOCSIFMTU: libc::c_ulong = 0x8922;

/// `SIOCSIFFLAGS` - Set interface flags
///
/// Used with a socket fd to set interface flags (IFF_UP, IFF_RUNNING, etc.).
pub const SIOCSIFFLAGS: libc::c_ulong = 0x8914;

/// `SIOCGIFFLAGS` - Get interface flags
///
/// Used with a socket fd to retrieve current interface flags.
pub const SIOCGIFFLAGS: libc::c_ulong = 0x8913;

// ============================================================================
// Interface flags for SIOCSIFFLAGS/SIOCGIFFLAGS
// ============================================================================

/// `IFF_UP` - Interface is up
///
/// When set, the interface is administratively enabled.
pub const IFF_UP: libc::c_short = 0x1;

/// `IFF_RUNNING` - Interface is running
///
/// Indicates the interface has resources allocated and is operational.
pub const IFF_RUNNING: libc::c_short = 0x40;

// ============================================================================
// Device paths
// ============================================================================

/// Path to the TUN device clone interface
///
/// Opening this file and issuing `TUNSETIFF` creates a new TUN/TAP device
/// or attaches to an existing one.
///
/// This is a C string literal (null-terminated) for safe use with libc functions.
pub const TUN_DEV_PATH: &std::ffi::CStr = c"/dev/net/tun";

// ============================================================================
// Interface name constants
// ============================================================================

/// Maximum length of a network interface name (including null terminator)
///
/// From `include/linux/if.h`: `#define IFNAMSIZ 16`
/// The usable name length is 15 characters (16 - 1 for null terminator).
pub const IFNAMSIZ: usize = 16;

/// Maximum usable length for interface names
pub const MAX_INTERFACE_NAME_LEN: usize = IFNAMSIZ - 1; // 15 characters

// ============================================================================
// Helper structures
// ============================================================================

/// Wrapper for `struct sockaddr_in` used with SIOCSIFADDR/SIOCSIFNETMASK
///
/// This provides a safe interface to the libc sockaddr_in structure.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SockAddrIn {
    /// Address family (always AF_INET for IPv4)
    pub sin_family: libc::sa_family_t,
    /// Port in network byte order (unused for interface config, set to 0)
    pub sin_port: u16,
    /// IPv4 address in network byte order
    pub sin_addr: libc::in_addr,
    /// Padding to match sockaddr size (8 bytes)
    _pad: [u8; 8],
}

impl SockAddrIn {
    /// Create a new `SockAddrIn` from an IPv4 address
    ///
    /// # Arguments
    ///
    /// * `addr` - IPv4 address in host byte order (e.g., from Ipv4Addr::into())
    #[must_use]
    pub fn new(addr: u32) -> Self {
        Self {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: 0,
            sin_addr: libc::in_addr {
                s_addr: addr.to_be(),
            },
            _pad: [0; 8],
        }
    }

    /// Create from a `std::net::Ipv4Addr`
    #[must_use]
    pub fn from_ipv4(addr: std::net::Ipv4Addr) -> Self {
        Self::new(u32::from(addr))
    }
}

impl Default for SockAddrIn {
    fn default() -> Self {
        Self {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: 0,
            sin_addr: libc::in_addr { s_addr: 0 },
            _pad: [0; 8],
        }
    }
}

/// Union for the `ifr_ifru` field in `struct ifreq`
///
/// The kernel's `ifreq` uses a union for the second field, which can contain
/// different data types depending on the ioctl being used.
#[repr(C)]
#[derive(Clone, Copy)]
pub union IfReqData {
    /// Interface flags (for TUNSETIFF, SIOCGIFFLAGS, SIOCSIFFLAGS)
    pub ifru_flags: libc::c_short,
    /// Interface MTU (for SIOCSIFMTU)
    pub ifru_mtu: libc::c_int,
    /// Socket address (for SIOCSIFADDR, SIOCSIFNETMASK)
    pub ifru_addr: SockAddrIn,
    /// Raw padding for alignment (24 bytes to match kernel struct)
    _raw: [u8; 24],
}

impl Default for IfReqData {
    fn default() -> Self {
        Self { _raw: [0; 24] }
    }
}

/// Interface request structure for TUN/TAP and socket ioctls
///
/// This is a more complete version of `struct ifreq` that supports multiple
/// ioctl operations including TUNSETIFF, SIOCSIFADDR, SIOCSIFNETMASK,
/// SIOCSIFMTU, and SIOCGIFFLAGS/SIOCSIFFLAGS.
#[repr(C)]
pub struct IfReq {
    /// Interface name (null-terminated, max 15 chars + null)
    pub ifr_name: [libc::c_char; IFNAMSIZ],
    /// Union of different data types depending on the ioctl
    pub ifr_ifru: IfReqData,
}

/// Backward-compatible struct for simple flag operations
///
/// This is the original simplified version kept for backward compatibility
/// with existing code that only uses TUNSETIFF.
#[repr(C)]
#[allow(dead_code)] // Reserved for backward compatibility
pub struct IfReqFlags {
    /// Interface name (null-terminated, max 15 chars + null)
    pub ifr_name: [libc::c_char; IFNAMSIZ],
    /// Interface flags (IFF_TUN, IFF_TAP, IFF_NO_PI, etc.)
    pub ifr_flags: libc::c_short,
    /// Padding to match kernel struct size
    _pad: [u8; 22],
}

impl IfReq {
    /// Create a new `IfReq` with just the interface name
    ///
    /// # Arguments
    ///
    /// * `name` - Interface name (max 15 characters)
    ///
    /// # Panics
    ///
    /// Panics if `name` is longer than 15 characters.
    #[must_use]
    pub fn with_name(name: &str) -> Self {
        assert!(
            name.len() <= MAX_INTERFACE_NAME_LEN,
            "Interface name too long: {} (max {} chars)",
            name.len(),
            MAX_INTERFACE_NAME_LEN
        );

        let mut ifr = Self {
            ifr_name: [0; IFNAMSIZ],
            ifr_ifru: IfReqData::default(),
        };

        // Copy name bytes
        #[allow(clippy::cast_possible_wrap)]
        for (i, byte) in name.bytes().enumerate() {
            ifr.ifr_name[i] = byte as libc::c_char;
        }

        ifr
    }

    /// Create a new `IfReq` with the given name and flags (backward compatible)
    ///
    /// # Arguments
    ///
    /// * `name` - Interface name (max 15 characters)
    /// * `flags` - Interface flags (e.g., `IFF_TUN | IFF_NO_PI`)
    ///
    /// # Panics
    ///
    /// Panics if `name` is longer than 15 characters.
    #[must_use]
    pub fn new(name: &str, flags: libc::c_short) -> Self {
        let mut ifr = Self::with_name(name);
        ifr.ifr_ifru.ifru_flags = flags;
        ifr
    }

    /// Get the interface name as a string
    ///
    /// Returns the name portion of `ifr_name` up to the first null byte.
    #[must_use]
    pub fn name(&self) -> &str {
        let len = self
            .ifr_name
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(IFNAMSIZ);

        // SAFETY: We know the bytes are valid ASCII (kernel guarantees this for
        // interface names). Even if they weren't, we only read up to the null.
        unsafe {
            std::str::from_utf8_unchecked(std::slice::from_raw_parts(
                self.ifr_name.as_ptr().cast::<u8>(),
                len,
            ))
        }
    }

    /// Get the flags from the union (for TUNSETIFF, SIOCGIFFLAGS)
    ///
    /// # Safety
    ///
    /// Only call this after using the struct with a flags-based ioctl.
    #[must_use]
    pub fn flags(&self) -> libc::c_short {
        // SAFETY: Reading from union - caller must ensure correct field was set
        unsafe { self.ifr_ifru.ifru_flags }
    }

    /// Set the flags in the union
    pub fn set_flags(&mut self, flags: libc::c_short) {
        self.ifr_ifru.ifru_flags = flags;
    }

    /// Set the MTU in the union
    pub fn set_mtu(&mut self, mtu: libc::c_int) {
        self.ifr_ifru.ifru_mtu = mtu;
    }

    /// Set the address in the union
    pub fn set_addr(&mut self, addr: SockAddrIn) {
        self.ifr_ifru.ifru_addr = addr;
    }
}

impl Default for IfReq {
    fn default() -> Self {
        Self {
            ifr_name: [0; IFNAMSIZ],
            ifr_ifru: IfReqData::default(),
        }
    }
}

impl IfReqFlags {
    /// Create a new `IfReqFlags` with the given name and flags
    #[must_use]
    pub fn new(name: &str, flags: libc::c_short) -> Self {
        assert!(
            name.len() <= MAX_INTERFACE_NAME_LEN,
            "Interface name too long: {} (max {} chars)",
            name.len(),
            MAX_INTERFACE_NAME_LEN
        );

        let mut ifr = Self {
            ifr_name: [0; IFNAMSIZ],
            ifr_flags: flags,
            _pad: [0; 22],
        };

        #[allow(clippy::cast_possible_wrap)]
        for (i, byte) in name.bytes().enumerate() {
            ifr.ifr_name[i] = byte as libc::c_char;
        }

        ifr
    }

    /// Get the interface name as a string
    #[must_use]
    pub fn name(&self) -> &str {
        let len = self
            .ifr_name
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(IFNAMSIZ);

        unsafe {
            std::str::from_utf8_unchecked(std::slice::from_raw_parts(
                self.ifr_name.as_ptr().cast::<u8>(),
                len,
            ))
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_ioctl_constants() {
        // Verify ioctl values match kernel definitions
        assert_eq!(TUNSETIFF, 0x4004_54ca);
        assert_eq!(TUNSETPERSIST, 0x4004_54cb);
    }

    #[test]
    fn test_socket_ioctl_constants() {
        // Verify socket ioctl values match kernel definitions
        assert_eq!(SIOCSIFADDR, 0x8916);
        assert_eq!(SIOCSIFNETMASK, 0x891c);
        assert_eq!(SIOCSIFMTU, 0x8922);
        assert_eq!(SIOCSIFFLAGS, 0x8914);
        assert_eq!(SIOCGIFFLAGS, 0x8913);
    }

    #[test]
    fn test_interface_flag_constants() {
        assert_eq!(IFF_UP, 0x1);
        assert_eq!(IFF_RUNNING, 0x40);
    }

    #[test]
    fn test_flag_constants() {
        assert_eq!(IFF_TUN, 0x0001);
        assert_eq!(IFF_TAP, 0x0002);
        assert_eq!(IFF_NO_PI, 0x1000);
        assert_eq!(IFF_MULTI_QUEUE, 0x0100);
    }

    #[test]
    fn test_ifreq_creation() {
        let ifr = IfReq::new("tun0", IFF_TUN | IFF_NO_PI);
        assert_eq!(ifr.name(), "tun0");
        assert_eq!(ifr.flags(), IFF_TUN | IFF_NO_PI);
    }

    #[test]
    fn test_ifreq_with_name() {
        let ifr = IfReq::with_name("eth0");
        assert_eq!(ifr.name(), "eth0");
    }

    #[test]
    fn test_ifreq_set_mtu() {
        let mut ifr = IfReq::with_name("tun0");
        ifr.set_mtu(1420);
        // SAFETY: We just set the MTU field
        assert_eq!(unsafe { ifr.ifr_ifru.ifru_mtu }, 1420);
    }

    #[test]
    fn test_ifreq_set_addr() {
        let mut ifr = IfReq::with_name("tun0");
        let addr = SockAddrIn::from_ipv4(Ipv4Addr::new(10, 25, 0, 1));
        ifr.set_addr(addr);
        // SAFETY: We just set the addr field
        let stored = unsafe { ifr.ifr_ifru.ifru_addr };
        assert_eq!(stored.sin_family, libc::AF_INET as libc::sa_family_t);
    }

    #[test]
    fn test_ifreq_max_name() {
        // 15 characters is OK
        let name = "a".repeat(MAX_INTERFACE_NAME_LEN);
        let ifr = IfReq::new(&name, IFF_TUN);
        assert_eq!(ifr.name(), name);
    }

    #[test]
    #[should_panic(expected = "Interface name too long")]
    fn test_ifreq_name_too_long() {
        // 16 characters should panic
        let name = "a".repeat(IFNAMSIZ);
        let _ = IfReq::new(&name, IFF_TUN);
    }

    #[test]
    fn test_ifreq_empty_name() {
        let ifr = IfReq::new("", IFF_TUN);
        assert_eq!(ifr.name(), "");
    }

    #[test]
    fn test_ifreq_size() {
        // IfReq should be 40 bytes to match kernel struct ifreq
        // 16 (name) + 24 (union) = 40 bytes
        assert_eq!(std::mem::size_of::<IfReq>(), 40);
    }

    #[test]
    fn test_ifreq_flags_size() {
        // IfReqFlags should also be 40 bytes (backward compatible struct)
        assert_eq!(std::mem::size_of::<IfReqFlags>(), 40);
    }

    #[test]
    fn test_sockaddrin_creation() {
        let addr = SockAddrIn::new(0x0a19_0001); // 10.25.0.1 in host order
        assert_eq!(addr.sin_family, libc::AF_INET as libc::sa_family_t);
        assert_eq!(addr.sin_port, 0);
        // s_addr should be in network byte order (big endian)
        assert_eq!(addr.sin_addr.s_addr, 0x0a19_0001_u32.to_be());
    }

    #[test]
    fn test_sockaddrin_from_ipv4() {
        let addr = SockAddrIn::from_ipv4(Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(addr.sin_family, libc::AF_INET as libc::sa_family_t);
        // 192.168.1.1 = 0xC0A80101 in host order
        let expected = u32::from(Ipv4Addr::new(192, 168, 1, 1)).to_be();
        assert_eq!(addr.sin_addr.s_addr, expected);
    }

    #[test]
    fn test_sockaddrin_size() {
        // sockaddr_in is 16 bytes
        assert_eq!(std::mem::size_of::<SockAddrIn>(), 16);
    }

    #[test]
    fn test_ifreq_data_size() {
        // Union should be 24 bytes to pad ifreq to 40 total
        assert_eq!(std::mem::size_of::<IfReqData>(), 24);
    }
}
