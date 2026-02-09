//! Tunnel port allocator
//!
//! This module implements port allocation for peer tunnels, ensuring
//! that each tunnel gets a unique port within the designated range.
//!
//! # Port Range
//!
//! Peer tunnel ports are allocated from the range 36200-36299.
//! Reserved ports (36000 for Web UI, 36100 for `WireGuard` ingress)
//! are excluded from allocation.
//!
//! # Thread Safety
//!
//! The allocator uses `RwLock` for thread-safe allocation and release
//! of ports across concurrent operations.
//!
use std::collections::HashSet;
use std::sync::RwLock;

/// Minimum port for peer tunnels
pub const MIN_PEER_PORT: u16 = 36200;

/// Maximum port for peer tunnels
pub const MAX_PEER_PORT: u16 = 36299;

/// Reserved ports that cannot be allocated
pub const RESERVED_PORTS: &[u16] = &[
    36000, // Web UI/API
    36100, // WireGuard ingress
];

/// Error types for port allocation
#[derive(Debug, Clone, thiserror::Error)]
pub enum PortAllocatorError {
    /// No ports available
    #[error("No available ports in range {}-{}", MIN_PEER_PORT, MAX_PEER_PORT)]
    Exhausted,

    /// Port is reserved
    #[error("Port {0} is reserved")]
    Reserved(u16),

    /// Port is already allocated
    #[error("Port {0} is already allocated")]
    AlreadyAllocated(u16),

    /// Port is out of range
    #[error("Port {0} is out of valid range {}-{}", MIN_PEER_PORT, MAX_PEER_PORT)]
    OutOfRange(u16),
}

/// Tunnel port allocator
///
/// Manages allocation of unique ports for peer tunnels within
/// the designated port range.
pub struct TunnelPortAllocator {
    /// Minimum port (inclusive)
    min_port: u16,
    /// Maximum port (inclusive)
    max_port: u16,
    /// Currently allocated ports
    allocated: RwLock<HashSet<u16>>,
    /// Reserved ports that cannot be allocated
    reserved: HashSet<u16>,
}

impl TunnelPortAllocator {
    /// Create a new port allocator
    ///
    /// # Arguments
    ///
    /// * `min_port` - Minimum port number (inclusive)
    /// * `max_port` - Maximum port number (inclusive)
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::peer::port_allocator::TunnelPortAllocator;
    ///
    /// let allocator = TunnelPortAllocator::new(36200, 36299);
    /// ```
    pub fn new(min_port: u16, max_port: u16) -> Self {
        Self {
            min_port,
            max_port,
            allocated: RwLock::new(HashSet::new()),
            reserved: RESERVED_PORTS.iter().copied().collect(),
        }
    }

    /// Allocate the next available port
    ///
    /// # Returns
    ///
    /// The allocated port number, or an error if no ports are available.
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::peer::port_allocator::TunnelPortAllocator;
    ///
    /// let allocator = TunnelPortAllocator::new(36200, 36299);
    /// let port = allocator.allocate().expect("Should allocate port");
    /// assert!(port >= 36200 && port <= 36299);
    /// ```
    pub fn allocate(&self) -> Result<u16, PortAllocatorError> {
        let mut allocated = self
            .allocated
            .write()
            .map_err(|_| PortAllocatorError::Exhausted)?;

        for port in self.min_port..=self.max_port {
            if !allocated.contains(&port) && !self.reserved.contains(&port) {
                allocated.insert(port);
                return Ok(port);
            }
        }

        Err(PortAllocatorError::Exhausted)
    }

    /// Allocate a specific port
    ///
    /// # Arguments
    ///
    /// * `port` - The port number to allocate
    ///
    /// # Returns
    ///
    /// Ok if the port was allocated, or an error if unavailable.
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::peer::port_allocator::TunnelPortAllocator;
    ///
    /// let allocator = TunnelPortAllocator::new(36200, 36299);
    /// allocator.allocate_specific(36250).expect("Should allocate specific port");
    /// ```
    pub fn allocate_specific(&self, port: u16) -> Result<(), PortAllocatorError> {
        // Check range
        if port < self.min_port || port > self.max_port {
            return Err(PortAllocatorError::OutOfRange(port));
        }

        // Check reserved
        if self.reserved.contains(&port) {
            return Err(PortAllocatorError::Reserved(port));
        }

        let mut allocated = self
            .allocated
            .write()
            .map_err(|_| PortAllocatorError::Exhausted)?;

        if allocated.contains(&port) {
            return Err(PortAllocatorError::AlreadyAllocated(port));
        }

        allocated.insert(port);
        Ok(())
    }

    /// Release a previously allocated port
    ///
    /// # Arguments
    ///
    /// * `port` - The port number to release
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::peer::port_allocator::TunnelPortAllocator;
    ///
    /// let allocator = TunnelPortAllocator::new(36200, 36299);
    /// let port = allocator.allocate().unwrap();
    /// allocator.release(port);
    /// ```
    pub fn release(&self, port: u16) {
        if let Ok(mut allocated) = self.allocated.write() {
            allocated.remove(&port);
        }
    }

    /// Check if a port is currently allocated
    ///
    /// # Arguments
    ///
    /// * `port` - The port number to check
    ///
    /// # Returns
    ///
    /// `true` if the port is allocated, `false` otherwise.
    pub fn is_allocated(&self, port: u16) -> bool {
        self.allocated
            .read()
            .map(|allocated| allocated.contains(&port))
            .unwrap_or(false)
    }

    /// Check if a port is reserved
    ///
    /// # Arguments
    ///
    /// * `port` - The port number to check
    ///
    /// # Returns
    ///
    /// `true` if the port is reserved, `false` otherwise.
    pub fn is_reserved(&self, port: u16) -> bool {
        self.reserved.contains(&port)
    }

    /// Get the number of allocated ports
    ///
    /// # Returns
    ///
    /// The count of currently allocated ports.
    pub fn allocated_count(&self) -> usize {
        self.allocated
            .read()
            .map(|allocated| allocated.len())
            .unwrap_or(0)
    }

    /// Get the number of available ports
    ///
    /// # Returns
    ///
    /// The count of ports available for allocation.
    pub fn available_count(&self) -> usize {
        let total = (self.max_port - self.min_port + 1) as usize;
        let reserved_in_range = self
            .reserved
            .iter()
            .filter(|&&p| p >= self.min_port && p <= self.max_port)
            .count();
        total - reserved_in_range - self.allocated_count()
    }
}

impl Default for TunnelPortAllocator {
    fn default() -> Self {
        Self::new(MIN_PEER_PORT, MAX_PEER_PORT)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allocate_sequential() {
        let allocator = TunnelPortAllocator::new(36200, 36202);

        let p1 = allocator.allocate().unwrap();
        let p2 = allocator.allocate().unwrap();
        let p3 = allocator.allocate().unwrap();

        assert_eq!(p1, 36200);
        assert_eq!(p2, 36201);
        assert_eq!(p3, 36202);

        // Should be exhausted now
        assert!(matches!(
            allocator.allocate(),
            Err(PortAllocatorError::Exhausted)
        ));
    }

    #[test]
    fn test_release_and_reallocate() {
        let allocator = TunnelPortAllocator::new(36200, 36201);

        let p1 = allocator.allocate().unwrap();
        let p2 = allocator.allocate().unwrap();

        // Release first port
        allocator.release(p1);

        // Should be able to allocate again
        let p3 = allocator.allocate().unwrap();
        assert_eq!(p3, p1);

        // But p2 should still be allocated
        assert!(allocator.is_allocated(p2));
    }

    #[test]
    fn test_allocate_specific() {
        let allocator = TunnelPortAllocator::new(36200, 36299);

        // Allocate a specific port
        allocator.allocate_specific(36250).unwrap();
        assert!(allocator.is_allocated(36250));

        // Try to allocate same port again
        assert!(matches!(
            allocator.allocate_specific(36250),
            Err(PortAllocatorError::AlreadyAllocated(36250))
        ));

        // Try to allocate out of range
        assert!(matches!(
            allocator.allocate_specific(36100),
            Err(PortAllocatorError::OutOfRange(36100))
        ));
    }

    #[test]
    fn test_reserved_ports() {
        let allocator = TunnelPortAllocator::new(36000, 36100);

        // Reserved ports should be skipped
        assert!(allocator.is_reserved(36000));
        assert!(allocator.is_reserved(36100));

        // Cannot allocate reserved ports
        assert!(matches!(
            allocator.allocate_specific(36000),
            Err(PortAllocatorError::Reserved(36000))
        ));
    }

    #[test]
    fn test_available_count() {
        let allocator = TunnelPortAllocator::new(36200, 36204);

        assert_eq!(allocator.available_count(), 5);
        assert_eq!(allocator.allocated_count(), 0);

        allocator.allocate().unwrap();
        assert_eq!(allocator.available_count(), 4);
        assert_eq!(allocator.allocated_count(), 1);
    }

    #[test]
    fn test_default() {
        let allocator = TunnelPortAllocator::default();
        let port = allocator.allocate().unwrap();
        assert!(port >= MIN_PEER_PORT && port <= MAX_PEER_PORT);
    }
}
