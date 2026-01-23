//! Tunnel IP allocator
//!
//! This module implements IP address allocation for peer tunnels,
//! ensuring each tunnel endpoint gets a unique IP within the
//! designated subnet.
//!
//! # Subnet Configuration
//!
//! By default, tunnel IPs are allocated from 10.200.200.0/24.
//! The network address (.0) and broadcast address (.255) are
//! reserved and never allocated.
//!
//! # Thread Safety
//!
//! The allocator uses `RwLock` for thread-safe allocation and release
//! of IP addresses across concurrent operations.
//!
use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::sync::RwLock;

/// Default tunnel subnet
pub const DEFAULT_TUNNEL_SUBNET: &str = "10.200.200.0/24";

/// Error types for IP allocation
#[derive(Debug, Clone, thiserror::Error)]
pub enum IpAllocatorError {
    /// No IPs available
    #[error("No available IP addresses in subnet")]
    Exhausted,

    /// IP is already allocated
    #[error("IP address {0} is already allocated")]
    AlreadyAllocated(Ipv4Addr),

    /// IP is reserved (network or broadcast)
    #[error("IP address {0} is reserved")]
    Reserved(Ipv4Addr),

    /// IP is not in subnet
    #[error("IP address {0} is not in configured subnet")]
    OutOfSubnet(Ipv4Addr),

    /// Invalid subnet format
    #[error("Invalid subnet format: {0}")]
    InvalidSubnet(String),
}

/// Tunnel IP allocator
///
/// Manages allocation of unique IP addresses for peer tunnels
/// within a configured subnet.
pub struct TunnelIpAllocator {
    /// Base network address
    network: Ipv4Addr,
    /// Subnet mask (number of bits)
    prefix_len: u8,
    /// Currently allocated IPs
    allocated: RwLock<HashSet<Ipv4Addr>>,
}

impl TunnelIpAllocator {
    /// Create a new IP allocator for the given subnet
    ///
    /// # Arguments
    ///
    /// * `subnet` - Subnet in CIDR notation (e.g., "10.200.200.0/24")
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::peer::ip_allocator::TunnelIpAllocator;
    ///
    /// let allocator = TunnelIpAllocator::new("10.200.200.0/24");
    /// ```
    pub fn new(subnet: &str) -> Self {
        let (network, prefix_len) = Self::parse_subnet(subnet).unwrap_or_else(|_| {
            // Fallback to default
            
            Self::parse_subnet(DEFAULT_TUNNEL_SUBNET).unwrap()
        });

        Self {
            network,
            prefix_len,
            allocated: RwLock::new(HashSet::new()),
        }
    }

    /// Parse a subnet string in CIDR notation
    fn parse_subnet(subnet: &str) -> Result<(Ipv4Addr, u8), IpAllocatorError> {
        let parts: Vec<&str> = subnet.split('/').collect();
        if parts.len() != 2 {
            return Err(IpAllocatorError::InvalidSubnet(subnet.to_string()));
        }

        let ip: Ipv4Addr = parts[0]
            .parse()
            .map_err(|_| IpAllocatorError::InvalidSubnet(subnet.to_string()))?;

        let prefix_len: u8 = parts[1]
            .parse()
            .map_err(|_| IpAllocatorError::InvalidSubnet(subnet.to_string()))?;

        if prefix_len > 32 {
            return Err(IpAllocatorError::InvalidSubnet(subnet.to_string()));
        }

        Ok((ip, prefix_len))
    }

    /// Check if an IP is in the configured subnet
    fn is_in_subnet(&self, ip: Ipv4Addr) -> bool {
        let ip_bits = u32::from(ip);
        let network_bits = u32::from(self.network);
        let mask = if self.prefix_len == 0 {
            0
        } else {
            !0u32 << (32 - self.prefix_len)
        };

        (ip_bits & mask) == (network_bits & mask)
    }

    /// Check if an IP is reserved (network or broadcast)
    ///
    /// # Arguments
    ///
    /// * `ip` - The IP address to check
    ///
    /// # Returns
    ///
    /// `true` if the IP is the network or broadcast address for this subnet.
    pub fn is_reserved(&self, ip: Ipv4Addr) -> bool {
        let ip_bits = u32::from(ip);
        let network_bits = u32::from(self.network);
        let mask = if self.prefix_len == 0 {
            0
        } else {
            !0u32 << (32 - self.prefix_len)
        };

        // Network address (all host bits = 0)
        let network_addr = network_bits & mask;
        // Broadcast address (all host bits = 1)
        let broadcast_addr = network_addr | !mask;

        ip_bits == network_addr || ip_bits == broadcast_addr
    }

    /// Allocate the next available IP address
    ///
    /// # Returns
    ///
    /// The allocated IP address, or an error if none available.
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::peer::ip_allocator::TunnelIpAllocator;
    ///
    /// let allocator = TunnelIpAllocator::new("10.200.200.0/24");
    /// let ip = allocator.allocate().expect("Should allocate IP");
    /// ```
    pub fn allocate(&self) -> Result<Ipv4Addr, IpAllocatorError> {
        let mut allocated = self
            .allocated
            .write()
            .map_err(|_| IpAllocatorError::Exhausted)?;

        let network_bits = u32::from(self.network);
        let mask = if self.prefix_len == 0 {
            0
        } else {
            !0u32 << (32 - self.prefix_len)
        };
        let host_mask = !mask;

        // Iterate through all possible host addresses (skip network and broadcast)
        for host_part in 1..host_mask {
            let ip_bits = (network_bits & mask) | host_part;
            let ip = Ipv4Addr::from(ip_bits);

            if !allocated.contains(&ip) && !self.is_reserved(ip) {
                allocated.insert(ip);
                return Ok(ip);
            }
        }

        Err(IpAllocatorError::Exhausted)
    }

    /// Allocate a specific IP address
    ///
    /// # Arguments
    ///
    /// * `ip` - The IP address to allocate
    ///
    /// # Returns
    ///
    /// Ok if the IP was allocated, or an error if unavailable.
    pub fn allocate_specific(&self, ip: Ipv4Addr) -> Result<(), IpAllocatorError> {
        if !self.is_in_subnet(ip) {
            return Err(IpAllocatorError::OutOfSubnet(ip));
        }

        if self.is_reserved(ip) {
            return Err(IpAllocatorError::Reserved(ip));
        }

        let mut allocated = self
            .allocated
            .write()
            .map_err(|_| IpAllocatorError::Exhausted)?;

        if allocated.contains(&ip) {
            return Err(IpAllocatorError::AlreadyAllocated(ip));
        }

        allocated.insert(ip);
        Ok(())
    }

    /// Allocate a pair of IP addresses for bidirectional tunnels
    ///
    /// # Returns
    ///
    /// A tuple of (`local_ip`, `remote_ip`) or an error if not enough IPs available.
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::peer::ip_allocator::TunnelIpAllocator;
    ///
    /// let allocator = TunnelIpAllocator::new("10.200.200.0/24");
    /// let (local_ip, remote_ip) = allocator.allocate_pair().expect("Should allocate pair");
    /// assert_ne!(local_ip, remote_ip);
    /// ```
    pub fn allocate_pair(&self) -> Result<(Ipv4Addr, Ipv4Addr), IpAllocatorError> {
        let ip1 = self.allocate()?;
        match self.allocate() {
            Ok(ip2) => Ok((ip1, ip2)),
            Err(e) => {
                // Release ip1 if we can't get a second IP
                self.release(ip1);
                Err(e)
            }
        }
    }

    /// Release a previously allocated IP address
    ///
    /// # Arguments
    ///
    /// * `ip` - The IP address to release
    pub fn release(&self, ip: Ipv4Addr) {
        if let Ok(mut allocated) = self.allocated.write() {
            allocated.remove(&ip);
        }
    }

    /// Check if an IP is currently allocated
    ///
    /// # Arguments
    ///
    /// * `ip` - The IP address to check
    ///
    /// # Returns
    ///
    /// `true` if the IP is allocated, `false` otherwise.
    pub fn is_allocated(&self, ip: Ipv4Addr) -> bool {
        self.allocated
            .read()
            .map(|allocated| allocated.contains(&ip))
            .unwrap_or(false)
    }

    /// Get the number of allocated IPs
    pub fn allocated_count(&self) -> usize {
        self.allocated
            .read()
            .map(|allocated| allocated.len())
            .unwrap_or(0)
    }

    /// Get the number of available IPs
    pub fn available_count(&self) -> usize {
        let mask = if self.prefix_len == 0 {
            0
        } else {
            !0u32 << (32 - self.prefix_len)
        };
        let host_bits = !mask;

        // Total hosts minus network and broadcast
        let total = host_bits.saturating_sub(1) as usize;
        total.saturating_sub(self.allocated_count())
    }

    /// Get the subnet in CIDR notation
    pub fn subnet(&self) -> String {
        format!("{}/{}", self.network, self.prefix_len)
    }
}

impl Default for TunnelIpAllocator {
    fn default() -> Self {
        Self::new(DEFAULT_TUNNEL_SUBNET)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allocate_sequential() {
        let allocator = TunnelIpAllocator::new("10.200.200.0/30");

        // /30 has 4 addresses: .0 (network), .1, .2, .3 (broadcast)
        // Only .1 and .2 are usable
        let ip1 = allocator.allocate().unwrap();
        let ip2 = allocator.allocate().unwrap();

        assert_eq!(ip1, Ipv4Addr::new(10, 200, 200, 1));
        assert_eq!(ip2, Ipv4Addr::new(10, 200, 200, 2));

        // Should be exhausted now
        assert!(matches!(
            allocator.allocate(),
            Err(IpAllocatorError::Exhausted)
        ));
    }

    #[test]
    fn test_release_and_reallocate() {
        let allocator = TunnelIpAllocator::new("10.200.200.0/30");

        let ip1 = allocator.allocate().unwrap();
        let _ip2 = allocator.allocate().unwrap();

        // Release first IP
        allocator.release(ip1);

        // Should be able to allocate again
        let ip3 = allocator.allocate().unwrap();
        assert_eq!(ip3, ip1);
    }

    #[test]
    fn test_allocate_specific() {
        let allocator = TunnelIpAllocator::new("10.200.200.0/24");

        let ip = Ipv4Addr::new(10, 200, 200, 50);
        allocator.allocate_specific(ip).unwrap();
        assert!(allocator.is_allocated(ip));

        // Try to allocate same IP again
        assert!(matches!(
            allocator.allocate_specific(ip),
            Err(IpAllocatorError::AlreadyAllocated(_))
        ));

        // Try to allocate reserved
        assert!(matches!(
            allocator.allocate_specific(Ipv4Addr::new(10, 200, 200, 0)),
            Err(IpAllocatorError::Reserved(_))
        ));
        assert!(matches!(
            allocator.allocate_specific(Ipv4Addr::new(10, 200, 200, 255)),
            Err(IpAllocatorError::Reserved(_))
        ));

        // Try to allocate out of subnet
        assert!(matches!(
            allocator.allocate_specific(Ipv4Addr::new(192, 168, 1, 1)),
            Err(IpAllocatorError::OutOfSubnet(_))
        ));
    }

    #[test]
    fn test_allocate_pair() {
        let allocator = TunnelIpAllocator::new("10.200.200.0/24");

        let (ip1, ip2) = allocator.allocate_pair().unwrap();
        assert_ne!(ip1, ip2);
        assert!(allocator.is_allocated(ip1));
        assert!(allocator.is_allocated(ip2));
    }

    #[test]
    fn test_available_count() {
        let allocator = TunnelIpAllocator::new("10.200.200.0/30");

        // /30 has 2 usable addresses
        assert_eq!(allocator.available_count(), 2);
        assert_eq!(allocator.allocated_count(), 0);

        allocator.allocate().unwrap();
        assert_eq!(allocator.available_count(), 1);
        assert_eq!(allocator.allocated_count(), 1);
    }

    #[test]
    fn test_subnet_string() {
        let allocator = TunnelIpAllocator::new("10.200.200.0/24");
        assert_eq!(allocator.subnet(), "10.200.200.0/24");
    }

    #[test]
    fn test_default() {
        let allocator = TunnelIpAllocator::default();
        assert_eq!(allocator.subnet(), DEFAULT_TUNNEL_SUBNET);
    }

    #[test]
    fn test_invalid_subnet() {
        // Should fallback to default
        let allocator = TunnelIpAllocator::new("invalid");
        assert_eq!(allocator.subnet(), DEFAULT_TUNNEL_SUBNET);
    }

    #[test]
    fn test_network_address_never_allocated() {
        // Verify network address (.0) is never allocated via allocate()
        let allocator = TunnelIpAllocator::new("10.200.200.0/24");

        // Allocate all possible IPs
        for _ in 0..254 {
            if allocator.allocate().is_err() {
                break;
            }
        }

        // Network address should never be allocated
        assert!(!allocator.is_allocated(Ipv4Addr::new(10, 200, 200, 0)));
    }

    #[test]
    fn test_broadcast_address_never_allocated() {
        // Verify broadcast address (.255) is never allocated via allocate()
        let allocator = TunnelIpAllocator::new("10.200.200.0/24");

        // Allocate all possible IPs
        for _ in 0..254 {
            if allocator.allocate().is_err() {
                break;
            }
        }

        // Broadcast address should never be allocated
        assert!(!allocator.is_allocated(Ipv4Addr::new(10, 200, 200, 255)));
    }

    #[test]
    fn test_is_reserved_network_and_broadcast() {
        let allocator = TunnelIpAllocator::new("10.200.200.0/24");

        // Network address (.0) is reserved
        assert!(allocator.is_reserved(Ipv4Addr::new(10, 200, 200, 0)));
        // Broadcast address (.255) is reserved
        assert!(allocator.is_reserved(Ipv4Addr::new(10, 200, 200, 255)));
        // Regular host addresses are not reserved
        assert!(!allocator.is_reserved(Ipv4Addr::new(10, 200, 200, 1)));
        assert!(!allocator.is_reserved(Ipv4Addr::new(10, 200, 200, 254)));
    }

    #[test]
    fn test_slash_28_network_broadcast() {
        // /28 subnet: 10.200.200.0/28 has addresses .0-.15
        // Network: .0, Broadcast: .15
        let allocator = TunnelIpAllocator::new("10.200.200.0/28");

        // .0 (network) is reserved
        assert!(matches!(
            allocator.allocate_specific(Ipv4Addr::new(10, 200, 200, 0)),
            Err(IpAllocatorError::Reserved(_))
        ));

        // .15 (broadcast for /28) is reserved
        assert!(matches!(
            allocator.allocate_specific(Ipv4Addr::new(10, 200, 200, 15)),
            Err(IpAllocatorError::Reserved(_))
        ));

        // .1 through .14 are usable (14 addresses)
        assert_eq!(allocator.available_count(), 14);
    }
}
