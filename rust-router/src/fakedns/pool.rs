//! FakeIP pool management
//!
//! This module manages the allocation of fake IP addresses from configured pools.
//! It uses cycling iterators to distribute addresses evenly and handles pool exhaustion.

use std::iter::Cycle;
use std::net::{Ipv4Addr, Ipv6Addr};

use ipnet::{Ipv4AddrRange, Ipv4Net, Ipv6AddrRange, Ipv6Net};
use parking_lot::Mutex;

/// IPv4 address pool with cycling allocation
#[derive(Debug)]
pub struct Ipv4Pool {
    /// Cycling iterator over the address range
    cycle: Mutex<Cycle<Ipv4AddrRange>>,
    /// The network range for membership testing
    network: Ipv4Net,
    /// Total number of addresses in the pool
    size: u64,
}

impl Ipv4Pool {
    /// Create a new IPv4 pool from a network range
    #[must_use]
    pub fn new(network: Ipv4Net) -> Self {
        let size = network.hosts().count() as u64;
        Self {
            cycle: Mutex::new(network.hosts().cycle()),
            network,
            size,
        }
    }

    /// Get the next available IPv4 address from the pool
    ///
    /// This uses a cycling iterator, so it will wrap around when
    /// the pool is exhausted. The caller is responsible for checking
    /// if the address is already in use.
    #[must_use]
    pub fn next(&self) -> Ipv4Addr {
        // Cycle::next() always returns Some for non-empty ranges
        self.cycle.lock().next().expect("pool should not be empty")
    }

    /// Check if an IPv4 address is within this pool's range
    #[must_use]
    pub fn contains(&self, addr: Ipv4Addr) -> bool {
        self.network.contains(&addr)
    }

    /// Get the total number of addresses in the pool
    #[must_use]
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Get the network range
    #[must_use]
    pub fn network(&self) -> Ipv4Net {
        self.network
    }
}

/// IPv6 address pool with cycling allocation
#[derive(Debug)]
pub struct Ipv6Pool {
    /// Cycling iterator over the address range
    cycle: Mutex<Cycle<Ipv6AddrRange>>,
    /// The network range for membership testing
    network: Ipv6Net,
    /// Total number of addresses in the pool (capped at u64::MAX for practical purposes)
    size: u64,
}

impl Ipv6Pool {
    /// Create a new IPv6 pool from a network range
    #[must_use]
    pub fn new(network: Ipv6Net) -> Self {
        // For very large IPv6 ranges, we cap the size at u64::MAX
        let prefix_len = network.prefix_len();
        let size = if prefix_len >= 64 {
            1u64 << (128 - prefix_len as u32)
        } else {
            u64::MAX
        };

        Self {
            cycle: Mutex::new(network.hosts().cycle()),
            network,
            size,
        }
    }

    /// Get the next available IPv6 address from the pool
    #[must_use]
    pub fn next(&self) -> Ipv6Addr {
        self.cycle.lock().next().expect("pool should not be empty")
    }

    /// Check if an IPv6 address is within this pool's range
    #[must_use]
    pub fn contains(&self, addr: Ipv6Addr) -> bool {
        self.network.contains(&addr)
    }

    /// Get the total number of addresses in the pool (capped at u64::MAX)
    #[must_use]
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Get the network range
    #[must_use]
    pub fn network(&self) -> Ipv6Net {
        self.network
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_pool_creation() {
        let pool = Ipv4Pool::new("10.0.0.0/24".parse().unwrap());
        // /24 has 254 usable hosts (excluding network and broadcast)
        // Actually ipnet::hosts() returns all 256 addresses for /24
        assert_eq!(pool.size(), 256);
    }

    #[test]
    fn test_ipv4_pool_next() {
        let pool = Ipv4Pool::new("10.0.0.0/30".parse().unwrap());
        // /30 has 4 addresses: 10.0.0.0, 10.0.0.1, 10.0.0.2, 10.0.0.3
        let first = pool.next();
        let second = pool.next();
        let third = pool.next();
        let fourth = pool.next();

        // Should cycle back to first
        let fifth = pool.next();
        assert_eq!(first, fifth);

        // All addresses should be in the pool
        assert!(pool.contains(first));
        assert!(pool.contains(second));
        assert!(pool.contains(third));
        assert!(pool.contains(fourth));
    }

    #[test]
    fn test_ipv4_pool_contains() {
        let pool = Ipv4Pool::new("192.168.1.0/24".parse().unwrap());

        assert!(pool.contains("192.168.1.0".parse().unwrap()));
        assert!(pool.contains("192.168.1.255".parse().unwrap()));
        assert!(!pool.contains("192.168.2.0".parse().unwrap()));
        assert!(!pool.contains("10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn test_ipv6_pool_creation() {
        let pool = Ipv6Pool::new("fc00::/120".parse().unwrap());
        // /120 has 2^8 = 256 addresses
        assert_eq!(pool.size(), 256);
    }

    #[test]
    fn test_ipv6_pool_next() {
        let pool = Ipv6Pool::new("fc00::/126".parse().unwrap());
        // /126 has 4 addresses
        let first = pool.next();
        let second = pool.next();
        let third = pool.next();
        let fourth = pool.next();

        // Should cycle back
        let fifth = pool.next();
        assert_eq!(first, fifth);

        assert!(pool.contains(first));
        assert!(pool.contains(second));
    }

    #[test]
    fn test_ipv6_pool_contains() {
        let pool = Ipv6Pool::new("fc00::/120".parse().unwrap());

        assert!(pool.contains("fc00::1".parse().unwrap()));
        assert!(pool.contains("fc00::ff".parse().unwrap()));
        assert!(!pool.contains("fc00::100".parse().unwrap()));
        assert!(!pool.contains("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn test_concurrent_access() {
        use std::sync::Arc;
        use std::thread;

        let pool = Arc::new(Ipv4Pool::new("10.0.0.0/24".parse().unwrap()));
        let mut handles = vec![];

        for _ in 0..4 {
            let pool = Arc::clone(&pool);
            handles.push(thread::spawn(move || {
                for _ in 0..100 {
                    let addr = pool.next();
                    assert!(pool.contains(addr));
                }
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }
    }
}
