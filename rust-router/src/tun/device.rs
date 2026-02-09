//! TUN device implementation
//!
//! This module provides the `TunDevice` type for creating and interacting with
//! Linux TUN devices using async I/O.
//!
//! # Example
//!
//! ```no_run
//! use rust_router::tun::{TunConfig, TunDevice};
//!
//! # async fn example() -> std::io::Result<()> {
//! // Create a TUN device
//! let config = TunConfig::new("tun-in").with_mtu(1420);
//! let device = TunDevice::create(&config)?;
//!
//! println!("Created TUN device: {}", device.name());
//!
//! // Read packets
//! let mut buf = [0u8; 1500];
//! loop {
//!     let n = device.read_packet(&mut buf).await?;
//!     println!("Read {} bytes", n);
//! }
//! # }
//! ```

use std::io;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use tokio::io::unix::AsyncFd;
use tokio::io::Interest;

use std::net::Ipv4Addr;

use crate::tun::config::TunConfig;
use crate::tun::ioctl::{
    IfReq, SockAddrIn, IFF_MULTI_QUEUE, IFF_NO_PI, IFF_RUNNING, IFF_TUN, IFF_UP,
    SIOCGIFFLAGS, SIOCSIFADDR, SIOCSIFFLAGS, SIOCSIFMTU, SIOCSIFNETMASK, TUN_DEV_PATH, TUNSETIFF,
};

/// A TUN device for reading and writing IP packets
///
/// `TunDevice` provides an async interface for interacting with Linux TUN devices.
/// It wraps a file descriptor in `tokio::io::unix::AsyncFd` to enable non-blocking
/// operations in async contexts.
///
/// # Thread Safety
///
/// `TunDevice` is `Send` but not `Sync`. It can be moved between threads but should
/// not be shared between threads without external synchronization. For multi-threaded
/// packet processing, consider using multi-queue TUN devices (see `TunConfig::multi_queue`).
///
/// # Packet Format
///
/// When created with `IFF_NO_PI` (which is the default), packets read from and
/// written to the device are raw IP packets without any additional headers.
/// The first byte indicates the IP version (4 or 6).
///
/// # Example
///
/// ```no_run
/// use rust_router::tun::{TunConfig, TunDevice};
///
/// # async fn example() -> std::io::Result<()> {
/// let config = TunConfig::new("tun0");
/// let device = TunDevice::create(&config)?;
///
/// // The device is now ready for async read/write operations
/// # Ok(())
/// # }
/// ```
pub struct TunDevice {
    /// Async file descriptor wrapper
    fd: AsyncFd<OwnedFd>,
    /// Device name (may differ from requested name if kernel assigned it)
    name: String,
    /// Configured MTU
    mtu: u16,
}

impl TunDevice {
    /// Create a new TUN device with the given configuration
    ///
    /// This function:
    /// 1. Opens `/dev/net/tun`
    /// 2. Configures the device with `TUNSETIFF` ioctl
    /// 3. Sets the file descriptor to non-blocking mode
    /// 4. Wraps it in `AsyncFd` for async operations
    ///
    /// # Arguments
    ///
    /// * `config` - TUN device configuration
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The configuration is invalid (name too long, MTU zero)
    /// - `/dev/net/tun` cannot be opened (usually permission denied)
    /// - The `TUNSETIFF` ioctl fails
    /// - Setting non-blocking mode fails
    ///
    /// # Permissions
    ///
    /// Creating a TUN device requires either:
    /// - Running as root
    /// - Having `CAP_NET_ADMIN` capability
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rust_router::tun::{TunConfig, TunDevice};
    ///
    /// let config = TunConfig::new("tun-in").with_mtu(1420);
    /// let device = TunDevice::create(&config)?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn create(config: &TunConfig) -> io::Result<Self> {
        // Validate configuration first
        config.validate()?;

        // Open /dev/net/tun
        // SAFETY: We're calling open() with a valid null-terminated path and standard flags.
        // TUN_DEV_PATH is a &CStr, guaranteeing proper null termination.
        // The returned fd is owned by us and will be wrapped in OwnedFd.
        let raw_fd = unsafe {
            libc::open(
                TUN_DEV_PATH.as_ptr(),
                libc::O_RDWR | libc::O_CLOEXEC,
            )
        };

        if raw_fd < 0 {
            let err = io::Error::last_os_error();
            return Err(io::Error::new(
                err.kind(),
                format!("Failed to open {:?}: {err}", TUN_DEV_PATH),
            ));
        }

        // SAFETY: We just opened this fd successfully, so it's valid.
        // OwnedFd takes ownership and will close it on drop.
        let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };

        // Build interface flags
        let mut flags = IFF_TUN | IFF_NO_PI;
        if config.multi_queue {
            flags |= IFF_MULTI_QUEUE;
        }

        // Create and configure ifreq
        let mut ifr = IfReq::new(&config.name, flags);

        // Configure the TUN device with TUNSETIFF
        // SAFETY: We're calling ioctl on a valid fd with a properly initialized ifreq struct.
        // The kernel will modify ifr_name to contain the actual device name.
        let result = unsafe { libc::ioctl(fd.as_raw_fd(), TUNSETIFF, &mut ifr) };

        if result < 0 {
            let err = io::Error::last_os_error();
            return Err(io::Error::new(
                err.kind(),
                format!("TUNSETIFF ioctl failed: {err}"),
            ));
        }

        // Get the actual device name (kernel may have assigned a different name)
        let name = ifr.name().to_string();

        // Set non-blocking mode
        // SAFETY: We're calling fcntl on a valid fd.
        let current_flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
        if current_flags < 0 {
            return Err(io::Error::other("Failed to get fd flags"));
        }

        let result = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, current_flags | libc::O_NONBLOCK) };
        if result < 0 {
            return Err(io::Error::other("Failed to set non-blocking mode"));
        }

        // Wrap in AsyncFd for async operations
        let async_fd = AsyncFd::new(fd)?;

        tracing::info!(
            device = %name,
            mtu = config.mtu,
            multi_queue = config.multi_queue,
            "Created TUN device"
        );

        Ok(Self {
            fd: async_fd,
            name,
            mtu: config.mtu,
        })
    }

    /// Get the device name
    ///
    /// This is the actual device name assigned by the kernel, which may differ
    /// from the requested name if the kernel auto-assigned it.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rust_router::tun::{TunConfig, TunDevice};
    ///
    /// let config = TunConfig::new("tun-test");
    /// let device = TunDevice::create(&config)?;
    /// println!("Device name: {}", device.name());
    /// # Ok::<(), std::io::Error>(())
    /// ```
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the configured MTU
    ///
    /// Note: This returns the MTU specified in the configuration, not the
    /// actual MTU set on the network interface (which may differ).
    #[must_use]
    pub fn mtu(&self) -> u16 {
        self.mtu
    }

    /// Get the raw file descriptor
    ///
    /// This is useful for passing to external APIs that need the fd.
    ///
    /// # Safety
    ///
    /// The returned fd is borrowed and must not be closed or transferred
    /// to another owner.
    #[must_use]
    pub fn raw_fd(&self) -> RawFd {
        self.fd.get_ref().as_raw_fd()
    }

    /// Read a packet from the TUN device (async)
    ///
    /// This method waits for the device to be readable, then reads a single
    /// IP packet into the provided buffer.
    ///
    /// # Arguments
    ///
    /// * `buf` - Buffer to read the packet into. Should be at least MTU bytes.
    ///
    /// # Returns
    ///
    /// The number of bytes read (the packet size).
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The read operation fails
    /// - The device is closed
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rust_router::tun::{TunConfig, TunDevice};
    ///
    /// # async fn example() -> std::io::Result<()> {
    /// let device = TunDevice::create(&TunConfig::new("tun0"))?;
    /// let mut buf = [0u8; 1500];
    ///
    /// let n = device.read_packet(&mut buf).await?;
    /// let ip_version = buf[0] >> 4;
    /// println!("Read {} byte IPv{} packet", n, ip_version);
    /// # Ok(())
    /// # }
    /// ```
    #[allow(clippy::cast_sign_loss)] // libc::read returns isize, we check for < 0
    pub async fn read_packet(&self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            // Wait for the fd to be readable
            let mut guard = self.fd.ready(Interest::READABLE).await?;

            // Try to read
            match guard.try_io(|inner| {
                // SAFETY: We're reading into a valid buffer from a valid fd.
                let result = unsafe {
                    libc::read(
                        inner.get_ref().as_raw_fd(),
                        buf.as_mut_ptr().cast::<libc::c_void>(),
                        buf.len(),
                    )
                };

                if result < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(result as usize)
                }
            }) {
                Ok(result) => return result,
                Err(_would_block) => {
                    // The fd wasn't actually ready, loop and wait again
                }
            }
        }
    }

    /// Write a packet to the TUN device (async)
    ///
    /// This method waits for the device to be writable, then writes a single
    /// IP packet to the device.
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
    /// Returns an error if:
    /// - The write operation fails
    /// - The packet is larger than the MTU (kernel may reject or truncate)
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rust_router::tun::{TunConfig, TunDevice};
    ///
    /// # async fn example() -> std::io::Result<()> {
    /// let device = TunDevice::create(&TunConfig::new("tun0"))?;
    ///
    /// // Write an IP packet (example: minimal IPv4 packet)
    /// let packet = [
    ///     0x45, 0x00, 0x00, 0x14, // IPv4, IHL=5, length=20
    ///     0x00, 0x00, 0x00, 0x00, // ID, flags, fragment
    ///     0x40, 0x06, 0x00, 0x00, // TTL=64, TCP, checksum
    ///     0x0a, 0x00, 0x00, 0x01, // src: 10.0.0.1
    ///     0x0a, 0x00, 0x00, 0x02, // dst: 10.0.0.2
    /// ];
    ///
    /// let n = device.write_packet(&packet).await?;
    /// println!("Wrote {} bytes", n);
    /// # Ok(())
    /// # }
    /// ```
    #[allow(clippy::cast_sign_loss)] // libc::write returns isize, we check for < 0
    pub async fn write_packet(&self, buf: &[u8]) -> io::Result<usize> {
        loop {
            // Wait for the fd to be writable
            let mut guard = self.fd.ready(Interest::WRITABLE).await?;

            // Try to write
            match guard.try_io(|inner| {
                // SAFETY: We're writing from a valid buffer to a valid fd.
                let result = unsafe {
                    libc::write(
                        inner.get_ref().as_raw_fd(),
                        buf.as_ptr().cast::<libc::c_void>(),
                        buf.len(),
                    )
                };

                if result < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(result as usize)
                }
            }) {
                Ok(result) => return result,
                Err(_would_block) => {
                    // The fd wasn't actually ready, loop and wait again
                }
            }
        }
    }

    /// Try to read a packet without blocking
    ///
    /// This method attempts to read a packet immediately. If the device is not
    /// ready (no packet available), it returns `Ok(None)` instead of blocking.
    ///
    /// # Arguments
    ///
    /// * `buf` - Buffer to read the packet into
    ///
    /// # Returns
    ///
    /// - `Ok(Some(n))` - Successfully read `n` bytes
    /// - `Ok(None)` - No packet available (would block)
    /// - `Err(e)` - An error occurred
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rust_router::tun::{TunConfig, TunDevice};
    ///
    /// # fn example() -> std::io::Result<()> {
    /// let device = TunDevice::create(&TunConfig::new("tun0"))?;
    /// let mut buf = [0u8; 1500];
    ///
    /// match device.try_read_packet(&mut buf)? {
    ///     Some(n) => println!("Read {} bytes", n),
    ///     None => println!("No packet available"),
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if the read operation fails for a reason other than
    /// `WouldBlock` (no packet available).
    #[allow(clippy::cast_sign_loss)] // libc::read returns isize, we check for < 0
    pub fn try_read_packet(&self, buf: &mut [u8]) -> io::Result<Option<usize>> {
        // SAFETY: We're reading into a valid buffer from a valid fd.
        let result = unsafe {
            libc::read(
                self.fd.get_ref().as_raw_fd(),
                buf.as_mut_ptr().cast::<libc::c_void>(),
                buf.len(),
            )
        };

        if result < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::WouldBlock {
                Ok(None)
            } else {
                Err(err)
            }
        } else {
            Ok(Some(result as usize))
        }
    }

    /// Try to write a packet without blocking
    ///
    /// This method attempts to write a packet immediately. If the device is not
    /// ready (buffer full), it returns `Ok(None)` instead of blocking.
    ///
    /// # Arguments
    ///
    /// * `buf` - The IP packet to write
    ///
    /// # Returns
    ///
    /// - `Ok(Some(n))` - Successfully wrote `n` bytes
    /// - `Ok(None)` - Device not ready (would block)
    /// - `Err(e)` - An error occurred
    ///
    /// # Errors
    ///
    /// Returns an error if the write operation fails for a reason other than
    /// `WouldBlock` (device not ready).
    #[allow(clippy::cast_sign_loss)] // libc::write returns isize, we check for < 0
    pub fn try_write_packet(&self, buf: &[u8]) -> io::Result<Option<usize>> {
        // SAFETY: We're writing from a valid buffer to a valid fd.
        let result = unsafe {
            libc::write(
                self.fd.get_ref().as_raw_fd(),
                buf.as_ptr().cast::<libc::c_void>(),
                buf.len(),
            )
        };

        if result < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::WouldBlock {
                Ok(None)
            } else {
                Err(err)
            }
        } else {
            Ok(Some(result as usize))
        }
    }

    // ========================================================================
    // Interface Configuration Methods
    // ========================================================================

    /// Bring the interface up (set IFF_UP and IFF_RUNNING flags)
    ///
    /// This sets the `IFF_UP` and `IFF_RUNNING` flags on the interface, making it
    /// ready to send and receive packets.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - A socket cannot be created for the ioctl
    /// - The `SIOCGIFFLAGS` or `SIOCSIFFLAGS` ioctl fails
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rust_router::tun::{TunConfig, TunDevice};
    ///
    /// let device = TunDevice::create(&TunConfig::new("tun0"))?;
    /// device.bring_up()?;
    /// println!("Interface {} is now up", device.name());
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn bring_up(&self) -> io::Result<()> {
        // Create a socket for ioctl operations (TUN fd doesn't support these ioctls)
        let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if sock < 0 {
            return Err(io::Error::last_os_error());
        }

        // Ensure socket is closed on exit using a scope guard pattern
        struct SocketGuard(libc::c_int);
        impl Drop for SocketGuard {
            fn drop(&mut self) {
                unsafe { libc::close(self.0) };
            }
        }
        let _guard = SocketGuard(sock);

        // Get current flags
        let mut ifr = IfReq::with_name(&self.name);
        if unsafe { libc::ioctl(sock, SIOCGIFFLAGS, &mut ifr) } < 0 {
            return Err(io::Error::last_os_error());
        }

        // Set IFF_UP and IFF_RUNNING flags
        let current_flags = ifr.flags();
        ifr.set_flags(current_flags | IFF_UP | IFF_RUNNING);

        if unsafe { libc::ioctl(sock, SIOCSIFFLAGS, &ifr) } < 0 {
            return Err(io::Error::last_os_error());
        }

        tracing::debug!(device = %self.name, "Interface brought up");
        Ok(())
    }

    /// Set the interface IP address and netmask using CIDR notation
    ///
    /// # Arguments
    ///
    /// * `cidr` - IP address with prefix length (e.g., "10.25.0.1/24")
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The CIDR notation is invalid
    /// - A socket cannot be created for the ioctl
    /// - The `SIOCSIFADDR` or `SIOCSIFNETMASK` ioctl fails
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rust_router::tun::{TunConfig, TunDevice};
    ///
    /// let device = TunDevice::create(&TunConfig::new("tun0"))?;
    /// device.set_address("10.25.0.1/24")?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn set_address(&self, cidr: &str) -> io::Result<()> {
        // Parse CIDR notation
        let (ip, prefix_len) = Self::parse_cidr(cidr)?;

        // Create a socket for ioctl operations
        let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if sock < 0 {
            return Err(io::Error::last_os_error());
        }

        struct SocketGuard(libc::c_int);
        impl Drop for SocketGuard {
            fn drop(&mut self) {
                unsafe { libc::close(self.0) };
            }
        }
        let _guard = SocketGuard(sock);

        // Set IP address
        let mut ifr = IfReq::with_name(&self.name);
        ifr.set_addr(SockAddrIn::from_ipv4(ip));

        if unsafe { libc::ioctl(sock, SIOCSIFADDR, &ifr) } < 0 {
            return Err(io::Error::new(
                io::Error::last_os_error().kind(),
                format!("Failed to set IP address on {}: {}", self.name, io::Error::last_os_error()),
            ));
        }

        // Calculate and set netmask from prefix length
        let netmask = Self::prefix_to_netmask(prefix_len);
        let mut ifr = IfReq::with_name(&self.name);
        ifr.set_addr(SockAddrIn::from_ipv4(netmask));

        if unsafe { libc::ioctl(sock, SIOCSIFNETMASK, &ifr) } < 0 {
            return Err(io::Error::new(
                io::Error::last_os_error().kind(),
                format!("Failed to set netmask on {}: {}", self.name, io::Error::last_os_error()),
            ));
        }

        tracing::debug!(device = %self.name, address = %cidr, "Set interface address");
        Ok(())
    }

    /// Apply the configured MTU to the interface
    ///
    /// This sets the MTU that was specified in the `TunConfig` when creating
    /// the device.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - A socket cannot be created for the ioctl
    /// - The `SIOCSIFMTU` ioctl fails
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rust_router::tun::{TunConfig, TunDevice};
    ///
    /// let device = TunDevice::create(&TunConfig::new("tun0").with_mtu(1420))?;
    /// device.apply_mtu()?;
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn apply_mtu(&self) -> io::Result<()> {
        // Create a socket for ioctl operations
        let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if sock < 0 {
            return Err(io::Error::last_os_error());
        }

        struct SocketGuard(libc::c_int);
        impl Drop for SocketGuard {
            fn drop(&mut self) {
                unsafe { libc::close(self.0) };
            }
        }
        let _guard = SocketGuard(sock);

        // Set MTU
        let mut ifr = IfReq::with_name(&self.name);
        ifr.set_mtu(i32::from(self.mtu));

        if unsafe { libc::ioctl(sock, SIOCSIFMTU, &ifr) } < 0 {
            return Err(io::Error::new(
                io::Error::last_os_error().kind(),
                format!("Failed to set MTU on {}: {}", self.name, io::Error::last_os_error()),
            ));
        }

        tracing::debug!(device = %self.name, mtu = self.mtu, "Set interface MTU");
        Ok(())
    }

    /// Configure the interface with address, MTU, and bring it up
    ///
    /// This is a convenience method that calls `set_address`, `apply_mtu`, and
    /// `bring_up` in sequence.
    ///
    /// # Arguments
    ///
    /// * `cidr` - IP address with prefix length (e.g., "10.25.0.1/24")
    ///
    /// # Errors
    ///
    /// Returns an error if any of the configuration steps fail.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rust_router::tun::{TunConfig, TunDevice};
    ///
    /// let device = TunDevice::create(&TunConfig::new("tun0").with_mtu(1420))?;
    /// device.configure("10.25.0.1/24")?;
    /// println!("Interface {} is configured and up", device.name());
    /// # Ok::<(), std::io::Error>(())
    /// ```
    pub fn configure(&self, cidr: &str) -> io::Result<()> {
        self.set_address(cidr)?;
        self.apply_mtu()?;
        self.bring_up()?;
        tracing::info!(
            device = %self.name,
            address = cidr,
            mtu = self.mtu,
            "Interface configured and brought up"
        );
        Ok(())
    }

    // ========================================================================
    // Helper Methods
    // ========================================================================

    /// Parse a CIDR notation string into an IP address and prefix length
    fn parse_cidr(cidr: &str) -> io::Result<(Ipv4Addr, u8)> {
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Invalid CIDR notation: {cidr} (expected format: x.x.x.x/n)"),
            ));
        }

        let ip: Ipv4Addr = parts[0].parse().map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Invalid IP address in CIDR {cidr}: {e}"),
            )
        })?;

        let prefix_len: u8 = parts[1].parse().map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Invalid prefix length in CIDR {cidr}: {e}"),
            )
        })?;

        if prefix_len > 32 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Prefix length {prefix_len} exceeds maximum of 32"),
            ));
        }

        Ok((ip, prefix_len))
    }

    /// Convert a prefix length to a netmask
    ///
    /// # Examples
    ///
    /// - 24 -> 255.255.255.0
    /// - 16 -> 255.255.0.0
    /// - 32 -> 255.255.255.255
    /// - 0 -> 0.0.0.0
    fn prefix_to_netmask(prefix_len: u8) -> Ipv4Addr {
        if prefix_len == 0 {
            return Ipv4Addr::new(0, 0, 0, 0);
        }
        if prefix_len >= 32 {
            return Ipv4Addr::new(255, 255, 255, 255);
        }
        // Create mask by shifting: for prefix 24, we get 0xFFFFFF00
        let mask: u32 = !0u32 << (32 - prefix_len);
        Ipv4Addr::from(mask)
    }
}

impl AsRawFd for TunDevice {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.get_ref().as_raw_fd()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // Note: Most tests require CAP_NET_ADMIN and are marked #[ignore]

    #[test]
    fn test_tun_config_validation() {
        // Valid config
        let config = TunConfig::new("tun0");
        assert!(config.validate().is_ok());

        // Invalid: name too long
        let config = TunConfig::new("this-name-is-way-too-long");
        assert!(config.validate().is_err());

        // Invalid: zero MTU
        let config = TunConfig::new("tun0").with_mtu(0);
        assert!(config.validate().is_err());
    }

    #[test]
    #[ignore = "Requires CAP_NET_ADMIN capability"]
    fn test_tun_device_create() {
        // This test requires root/CAP_NET_ADMIN
        let config = TunConfig::new("tun-test").with_mtu(1420);
        let result = TunDevice::create(&config);

        match result {
            Ok(device) => {
                assert!(!device.name().is_empty());
                assert_eq!(device.mtu(), 1420);
                println!("Created device: {}", device.name());
            }
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                println!("Test skipped: requires CAP_NET_ADMIN");
            }
            Err(e) => {
                panic!("Unexpected error: {}", e);
            }
        }
    }

    #[test]
    #[ignore = "Requires CAP_NET_ADMIN capability"]
    fn test_tun_device_auto_name() {
        // Test kernel auto-assignment of name
        let config = TunConfig::default().with_mtu(1500);
        let result = TunDevice::create(&config);

        match result {
            Ok(device) => {
                assert!(!device.name().is_empty());
                assert!(device.name().starts_with("tun"));
                println!("Kernel assigned name: {}", device.name());
            }
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                println!("Test skipped: requires CAP_NET_ADMIN");
            }
            Err(e) => {
                panic!("Unexpected error: {}", e);
            }
        }
    }

    #[test]
    #[ignore = "Requires CAP_NET_ADMIN capability"]
    fn test_tun_device_multi_queue() {
        let config = TunConfig::new("tun-mq").with_multi_queue(true);
        let result = TunDevice::create(&config);

        match result {
            Ok(device) => {
                println!("Created multi-queue device: {}", device.name());
            }
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                println!("Test skipped: requires CAP_NET_ADMIN");
            }
            Err(e) => {
                panic!("Unexpected error: {}", e);
            }
        }
    }

    #[test]
    fn test_tun_device_path_constant() {
        assert_eq!(TUN_DEV_PATH.to_str().unwrap(), "/dev/net/tun");
    }

    // ========================================================================
    // CIDR Parsing Tests
    // ========================================================================

    #[test]
    fn test_parse_cidr_valid() {
        let (ip, prefix) = TunDevice::parse_cidr("10.25.0.1/24").unwrap();
        assert_eq!(ip, Ipv4Addr::new(10, 25, 0, 1));
        assert_eq!(prefix, 24);
    }

    #[test]
    fn test_parse_cidr_host_route() {
        let (ip, prefix) = TunDevice::parse_cidr("192.168.1.1/32").unwrap();
        assert_eq!(ip, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(prefix, 32);
    }

    #[test]
    fn test_parse_cidr_default_route() {
        let (ip, prefix) = TunDevice::parse_cidr("0.0.0.0/0").unwrap();
        assert_eq!(ip, Ipv4Addr::new(0, 0, 0, 0));
        assert_eq!(prefix, 0);
    }

    #[test]
    fn test_parse_cidr_invalid_no_slash() {
        let result = TunDevice::parse_cidr("10.25.0.1");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid CIDR notation"));
    }

    #[test]
    fn test_parse_cidr_invalid_ip() {
        let result = TunDevice::parse_cidr("300.25.0.1/24");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid IP address"));
    }

    #[test]
    fn test_parse_cidr_invalid_prefix() {
        let result = TunDevice::parse_cidr("10.25.0.1/abc");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid prefix length"));
    }

    #[test]
    fn test_parse_cidr_prefix_too_large() {
        let result = TunDevice::parse_cidr("10.25.0.1/33");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("exceeds maximum"));
    }

    // ========================================================================
    // Netmask Conversion Tests
    // ========================================================================

    #[test]
    fn test_prefix_to_netmask_24() {
        let mask = TunDevice::prefix_to_netmask(24);
        assert_eq!(mask, Ipv4Addr::new(255, 255, 255, 0));
    }

    #[test]
    fn test_prefix_to_netmask_16() {
        let mask = TunDevice::prefix_to_netmask(16);
        assert_eq!(mask, Ipv4Addr::new(255, 255, 0, 0));
    }

    #[test]
    fn test_prefix_to_netmask_8() {
        let mask = TunDevice::prefix_to_netmask(8);
        assert_eq!(mask, Ipv4Addr::new(255, 0, 0, 0));
    }

    #[test]
    fn test_prefix_to_netmask_32() {
        let mask = TunDevice::prefix_to_netmask(32);
        assert_eq!(mask, Ipv4Addr::new(255, 255, 255, 255));
    }

    #[test]
    fn test_prefix_to_netmask_0() {
        let mask = TunDevice::prefix_to_netmask(0);
        assert_eq!(mask, Ipv4Addr::new(0, 0, 0, 0));
    }

    #[test]
    fn test_prefix_to_netmask_25() {
        // /25 = 255.255.255.128 (0xFFFFFF80)
        let mask = TunDevice::prefix_to_netmask(25);
        assert_eq!(mask, Ipv4Addr::new(255, 255, 255, 128));
    }

    #[test]
    fn test_prefix_to_netmask_20() {
        // /20 = 255.255.240.0 (0xFFFFF000)
        let mask = TunDevice::prefix_to_netmask(20);
        assert_eq!(mask, Ipv4Addr::new(255, 255, 240, 0));
    }

    // ========================================================================
    // Interface Configuration Tests (require CAP_NET_ADMIN)
    // ========================================================================

    #[test]
    #[ignore = "Requires CAP_NET_ADMIN capability"]
    fn test_tun_device_configure() {
        let config = TunConfig::new("tun-cfg").with_mtu(1420);
        let result = TunDevice::create(&config);

        match result {
            Ok(device) => {
                // Configure with address and bring up
                let result = device.configure("10.25.0.1/24");
                match result {
                    Ok(()) => {
                        println!("Device {} configured with 10.25.0.1/24", device.name());
                    }
                    Err(e) => {
                        println!("Configure failed (may require root): {}", e);
                    }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                println!("Test skipped: requires CAP_NET_ADMIN");
            }
            Err(e) => {
                panic!("Unexpected error: {}", e);
            }
        }
    }

    #[test]
    #[ignore = "Requires CAP_NET_ADMIN capability"]
    fn test_tun_device_set_address_only() {
        let config = TunConfig::new("tun-addr").with_mtu(1500);
        let result = TunDevice::create(&config);

        match result {
            Ok(device) => {
                let result = device.set_address("192.168.100.1/24");
                match result {
                    Ok(()) => {
                        println!("Device {} address set to 192.168.100.1/24", device.name());
                    }
                    Err(e) => {
                        println!("Set address failed (may require root): {}", e);
                    }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                println!("Test skipped: requires CAP_NET_ADMIN");
            }
            Err(e) => {
                panic!("Unexpected error: {}", e);
            }
        }
    }
}
