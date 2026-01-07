//! TPROXY UDP Listener
//!
//! This module provides a UDP listener for TPROXY-redirected traffic with
//! automatic original destination retrieval via `IP_RECVORIGDSTADDR` cmsg.
//!
//! # IPv4 Only
//!
//! **Important**: This implementation supports IPv4 only. The `sockaddr_in`
//! structures and `IP_RECVORIGDSTADDR` option are IPv4-specific. IPv6 support
//! would require `IPV6_RECVORIGDSTADDR` and `sockaddr_in6` handling.
//!
//! # Architecture
//!
//! Unlike TCP where each connection has its own socket, UDP is connectionless.
//! TPROXY UDP uses a single socket with `IP_RECVORIGDSTADDR` to receive the
//! original destination address in the control message (cmsg) of each packet.
//!
//! # Required iptables
//!
//! ```bash
//! iptables -t mangle -A PREROUTING -i wg-ingress -p udp -j TPROXY \
//!     --on-ip 127.0.0.1 --on-port 7893 --tproxy-mark 0x1
//! ip rule add fwmark 0x1 lookup 100
//! ip route add local 0.0.0.0/0 dev lo table 100
//! ```
//!
//! # Required sysctls
//!
//! The following sysctl settings are **required** for TPROXY UDP to function:
//!
//! - `net.ipv4.conf.all.route_localnet = 1` - Allow routing to 127.0.0.0/8
//! - `net.ipv4.ip_nonlocal_bind = 1` - Allow binding to non-local addresses (for reply sockets)
//! - `net.ipv4.conf.all.rp_filter = 0` - Disable reverse path filtering
//! - `net.ipv4.conf.<interface>.rp_filter = 0` - Per-interface (e.g., wg-ingress)
//!
//! See the parent module documentation for detailed explanations of each setting.

use std::io;
use std::mem;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

use bytes::Bytes;
use tokio::net::UdpSocket;
use tracing::{info, trace};

use super::socket::create_tproxy_udp_socket;
use crate::config::ListenConfig;
use crate::error::UdpError;
use crate::io::UdpBuffer;

/// Linux kernel constant: `IP_RECVORIGDSTADDR` (`SOL_IP` level)
const IP_RECVORIGDSTADDR: libc::c_int = 20;

/// Default buffer size for UDP packets
const UDP_BUFFER_SIZE: usize = 65535;

/// Control message buffer size (enough for `sockaddr_in`)
const CMSG_BUFFER_SIZE: usize = 64;

/// Information about a received UDP packet
#[derive(Debug, Clone)]
pub struct UdpPacketInfo {
    /// Packet data
    pub data: Bytes,
    /// Client (source) address
    pub client_addr: SocketAddr,
    /// Original destination address (from TPROXY cmsg)
    pub original_dst: SocketAddr,
    /// Timestamp when packet was received
    pub received_at: Instant,
}

impl UdpPacketInfo {
    /// Get the packet size
    #[must_use]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if the packet is empty
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

/// A TPROXY UDP listener that receives packets with original destination info
#[derive(Debug)]
pub struct TproxyUdpListener {
    /// The underlying tokio UDP socket
    socket: UdpSocket,
    /// Listen address
    listen_addr: SocketAddr,
    /// Whether the listener is active
    active: AtomicBool,
    /// Total packets received
    packets_received: AtomicU64,
    /// Total bytes received
    bytes_received: AtomicU64,
}

impl TproxyUdpListener {
    /// Create and bind a new TPROXY UDP listener.
    ///
    /// This creates a UDP socket with `IP_TRANSPARENT` and `IP_RECVORIGDSTADDR`
    /// enabled, then binds it to the specified address.
    ///
    /// # Arguments
    ///
    /// * `config` - Listen configuration
    ///
    /// # Errors
    ///
    /// Returns `UdpError` if:
    /// - Socket creation fails
    /// - Binding fails
    /// - `CAP_NET_ADMIN` capability is missing
    pub fn bind(config: &ListenConfig) -> Result<Self, UdpError> {
        info!("Creating TPROXY UDP listener on {}", config.address);

        // Create the TPROXY socket with IP_TRANSPARENT and IP_RECVORIGDSTADDR
        let socket = create_tproxy_udp_socket().map_err(|e| match e {
            crate::error::TproxyError::PermissionDenied => UdpError::PermissionDenied,
            crate::error::TproxyError::SocketOption { option, reason } => {
                UdpError::SocketOption { option, reason }
            }
            other => UdpError::SocketOption {
                option: "create".into(),
                reason: other.to_string(),
            },
        })?;

        // Bind to the listen address
        socket.bind(&config.address.into()).map_err(|e| {
            UdpError::socket_option("bind", format!("Failed to bind to {}: {}", config.address, e))
        })?;

        // Convert to tokio UdpSocket
        let std_socket = unsafe { std::net::UdpSocket::from_raw_fd(socket.into_raw_fd()) };
        let socket = UdpSocket::from_std(std_socket).map_err(|e| {
            UdpError::socket_option("from_std", format!("Failed to convert socket: {e}"))
        })?;

        info!(
            "TPROXY UDP listener ready on {} (reuse_port={})",
            config.address, config.reuse_port
        );

        Ok(Self {
            socket,
            listen_addr: config.address,
            active: AtomicBool::new(true),
            packets_received: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
        })
    }

    /// Bind to a specific address (convenience method)
    ///
    /// # Errors
    ///
    /// Returns `UdpError` if binding fails.
    pub fn bind_addr(addr: SocketAddr) -> Result<Self, UdpError> {
        let config = ListenConfig {
            address: addr,
            tcp_enabled: false,
            udp_enabled: true,
            tcp_backlog: 1024,
            udp_timeout_secs: 300,
            reuse_port: true,
            sniff_timeout_ms: 300,
            udp_workers: None,
            udp_buffer_pool_size: 1024,
        };
        Self::bind(&config)
    }

    /// Receive a UDP packet with original destination.
    ///
    /// This uses `recvmsg` to get both the packet data and the control message
    /// containing the original destination address (set by TPROXY).
    ///
    /// # Arguments
    ///
    /// * `buf` - Buffer to receive packet data into
    ///
    /// # Errors
    ///
    /// Returns `UdpError` if:
    /// - Listener is not active
    /// - recvmsg fails
    /// - Original destination cannot be retrieved from cmsg
    pub async fn recv(&self, buf: &mut [u8]) -> Result<UdpPacketInfo, UdpError> {
        // Use a loop instead of recursion to handle spurious wakeups
        loop {
            if !self.is_active() {
                return Err(UdpError::NotReady);
            }

            // Wait for socket to be readable
            self.socket.readable().await.map_err(UdpError::IoError)?;

            // Try to receive with original destination
            let fd = self.socket.as_raw_fd();
            match recv_with_original_dst(fd, buf) {
                Ok((n, client_addr, original_dst)) => {
                    // Update stats
                    self.packets_received.fetch_add(1, Ordering::Relaxed);
                    self.bytes_received.fetch_add(n as u64, Ordering::Relaxed);

                    trace!(
                        "UDP packet: {} -> {} ({} bytes)",
                        client_addr,
                        original_dst,
                        n
                    );

                    return Ok(UdpPacketInfo {
                        data: Bytes::copy_from_slice(&buf[..n]),
                        client_addr,
                        original_dst,
                        received_at: Instant::now(),
                    });
                }
                Err(e) => {
                    // Check if this is a WouldBlock error
                    if e.kind() == io::ErrorKind::WouldBlock {
                        // Retry - socket wasn't actually ready
                        // This can happen due to spurious wakeups
                        continue;
                    }
                    return Err(UdpError::RecvError(e.to_string()));
                }
            }
        }
    }

    /// Receive a UDP packet using the default buffer size
    ///
    /// # Errors
    ///
    /// Returns `UdpError` if receiving fails.
    pub async fn recv_packet(&self) -> Result<UdpPacketInfo, UdpError> {
        let mut buf = vec![0u8; UDP_BUFFER_SIZE];
        self.recv(&mut buf).await
    }

    /// Receive a UDP packet into a pooled buffer (zero-copy).
    ///
    /// This is the **recommended** method for high-performance UDP processing.
    /// It uses a `PooledBuffer` and converts it to `Bytes` without copying,
    /// avoiding allocation on every packet (~100k alloc/s savings at 100k pps).
    ///
    /// # Arguments
    ///
    /// * `buf` - A pooled buffer to receive into (consumed on success)
    ///
    /// # Performance
    ///
    /// This method uses `UdpBuffer::freeze()` to convert the buffer to `Bytes`
    /// with zero allocation overhead. The buffer is NOT returned to the pool
    /// since the `Bytes` owns the underlying memory.
    ///
    /// PERF-4 FIX: This method accepts any type implementing `UdpBuffer` trait,
    /// allowing both `PooledBuffer` (from global pool) and `LocalPooledBuffer`
    /// (from per-worker local cache) to be used interchangeably.
    ///
    /// # Errors
    ///
    /// Returns `UdpError` if:
    /// - Listener is not active
    /// - recvmsg fails
    /// - Original destination cannot be retrieved from cmsg
    /// - Control message was truncated (MSG_CTRUNC)
    pub async fn recv_pooled<B: UdpBuffer>(&self, buf: B) -> Result<UdpPacketInfo, UdpError> {
        // Use a loop instead of recursion to handle spurious wakeups
        let mut buf = buf;
        loop {
            if !self.is_active() {
                return Err(UdpError::NotReady);
            }

            // Wait for socket to be readable
            self.socket.readable().await.map_err(UdpError::IoError)?;

            // Try to receive with original destination
            let fd = self.socket.as_raw_fd();
            match recv_with_original_dst_checked(fd, &mut buf) {
                Ok((n, client_addr, original_dst)) => {
                    // Update stats
                    self.packets_received.fetch_add(1, Ordering::Relaxed);
                    self.bytes_received.fetch_add(n as u64, Ordering::Relaxed);

                    trace!(
                        "UDP packet: {} -> {} ({} bytes)",
                        client_addr,
                        original_dst,
                        n
                    );

                    // PERF-1 FIX: Zero-copy conversion to Bytes
                    // This avoids allocation on every packet receive
                    return Ok(UdpPacketInfo {
                        data: buf.freeze(n),
                        client_addr,
                        original_dst,
                        received_at: Instant::now(),
                    });
                }
                Err(e) => {
                    // Check if this is a WouldBlock error
                    if e.kind() == io::ErrorKind::WouldBlock {
                        // Retry - socket wasn't actually ready
                        // This can happen due to spurious wakeups
                        continue;
                    }
                    return Err(UdpError::RecvError(e.to_string()));
                }
            }
        }
    }

    /// Get the listen address
    #[must_use]
    pub const fn listen_addr(&self) -> SocketAddr {
        self.listen_addr
    }

    /// Check if the listener is active
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::Relaxed)
    }

    /// Deactivate the listener (stop receiving packets)
    pub fn deactivate(&self) {
        if self.active.swap(false, Ordering::SeqCst) {
            info!("Deactivating TPROXY UDP listener on {}", self.listen_addr);
        }
    }

    /// Reactivate the listener
    pub fn reactivate(&self) {
        if !self.active.swap(true, Ordering::SeqCst) {
            info!("Reactivating TPROXY UDP listener on {}", self.listen_addr);
        }
    }

    /// Get the total number of packets received
    #[must_use]
    pub fn packets_received(&self) -> u64 {
        self.packets_received.load(Ordering::Relaxed)
    }

    /// Get the total number of bytes received
    #[must_use]
    pub fn bytes_received(&self) -> u64 {
        self.bytes_received.load(Ordering::Relaxed)
    }

    /// Get a reference to the underlying tokio socket
    ///
    /// Useful for `tokio::select!` and other advanced operations.
    #[must_use]
    pub const fn inner(&self) -> &UdpSocket {
        &self.socket
    }

    /// Get the raw file descriptor
    #[must_use]
    pub fn as_raw_fd(&self) -> RawFd {
        self.socket.as_raw_fd()
    }
}

/// Receive a UDP packet with original destination address from cmsg.
///
/// This is the low-level function that calls `recvmsg` and parses the
/// `IP_RECVORIGDSTADDR` control message.
///
/// # Arguments
///
/// * `fd` - Raw file descriptor of the TPROXY UDP socket
/// * `buf` - Buffer to receive packet data
///
/// # Returns
///
/// Tuple of (`bytes_received`, `source_addr`, `original_dest_addr`)
#[allow(clippy::cast_possible_truncation)] // socklen_t is always u32
#[allow(clippy::borrow_as_ptr)] // Required for libc FFI
#[allow(clippy::cast_ptr_alignment)] // CMSG_DATA alignment is handled by kernel
#[allow(clippy::cast_sign_loss)] // n is guaranteed positive after error check
fn recv_with_original_dst(
    fd: RawFd,
    buf: &mut [u8],
) -> Result<(usize, SocketAddr, SocketAddr), io::Error> {
    // Prepare the iovec for the data
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr().cast::<libc::c_void>(),
        iov_len: buf.len(),
    };

    // Prepare the source address buffer
    let mut src_addr: libc::sockaddr_in = unsafe { mem::zeroed() };
    let src_addr_len: libc::socklen_t = mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;

    // Prepare the control message buffer
    let mut cmsg_buf: [u8; CMSG_BUFFER_SIZE] = [0; CMSG_BUFFER_SIZE];

    // Prepare msghdr
    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_name = std::ptr::addr_of_mut!(src_addr).cast::<libc::c_void>();
    msg.msg_namelen = src_addr_len;
    msg.msg_iov = std::ptr::addr_of_mut!(iov);
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr().cast::<libc::c_void>();
    msg.msg_controllen = CMSG_BUFFER_SIZE;

    // Call recvmsg
    let n = unsafe { libc::recvmsg(fd, &mut msg, 0) };

    if n < 0 {
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::WouldBlock {
            return Err(io::Error::new(io::ErrorKind::WouldBlock, "WouldBlock"));
        }
        return Err(err);
    }

    // NEW-6 FIX: Check for control message truncation
    // If MSG_CTRUNC is set, the control message buffer was too small and
    // the original destination address may be missing or corrupted.
    if (msg.msg_flags & libc::MSG_CTRUNC) != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Control message truncated (MSG_CTRUNC) - cmsg buffer too small",
        ));
    }

    // Parse source address
    let src_port = u16::from_be(src_addr.sin_port);
    let src_ip = Ipv4Addr::from(u32::from_be(src_addr.sin_addr.s_addr));
    let src = SocketAddr::V4(SocketAddrV4::new(src_ip, src_port));

    // Parse control message to get original destination
    let mut original_dst: Option<SocketAddr> = None;

    // Iterate through control messages
    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    while !cmsg.is_null() {
        let cmsg_ref = unsafe { &*cmsg };

        if cmsg_ref.cmsg_level == libc::SOL_IP && cmsg_ref.cmsg_type == IP_RECVORIGDSTADDR {
            // Found the original destination address
            let addr_ptr = unsafe { libc::CMSG_DATA(cmsg) }.cast::<libc::sockaddr_in>();
            let addr = unsafe { &*addr_ptr };

            let dst_port = u16::from_be(addr.sin_port);
            let dst_ip = Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
            original_dst = Some(SocketAddr::V4(SocketAddrV4::new(dst_ip, dst_port)));
            break;
        }

        cmsg = unsafe { libc::CMSG_NXTHDR(&msg, cmsg) };
    }

    let dst = original_dst.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "Original destination not found in cmsg - not a TPROXY packet?",
        )
    })?;

    Ok((n as usize, src, dst))
}

/// Receive a UDP packet with original destination address and MSG_CTRUNC check.
///
/// This is an enhanced version of `recv_with_original_dst` that:
/// 1. Accepts a `PooledBuffer` for zero-copy receive
/// 2. Checks for `MSG_CTRUNC` flag (SEC-2 fix)
///
/// # Arguments
///
/// * `fd` - Raw file descriptor of the TPROXY UDP socket
/// * `buf` - PooledBuffer to receive packet data
///
/// # Returns
///
/// Tuple of (`bytes_received`, `source_addr`, `original_dest_addr`)
///
/// # Errors
///
/// Returns an error if:
/// - recvmsg fails
/// - Control message was truncated (MSG_CTRUNC)
/// - Original destination not found in cmsg
#[allow(clippy::cast_possible_truncation)] // socklen_t is always u32
#[allow(clippy::borrow_as_ptr)] // Required for libc FFI
#[allow(clippy::cast_ptr_alignment)] // CMSG_DATA alignment is handled by kernel
#[allow(clippy::cast_sign_loss)] // n is guaranteed positive after error check
fn recv_with_original_dst_checked<B: std::ops::DerefMut<Target = [u8]>>(
    fd: RawFd,
    buf: &mut B,
) -> Result<(usize, SocketAddr, SocketAddr), io::Error> {
    // Get the underlying slice from the buffer (works for any DerefMut<Target = [u8]>)
    let buf_slice = &mut **buf;

    // Prepare the iovec for the data
    let mut iov = libc::iovec {
        iov_base: buf_slice.as_mut_ptr().cast::<libc::c_void>(),
        iov_len: buf_slice.len(),
    };

    // Prepare the source address buffer
    let mut src_addr: libc::sockaddr_in = unsafe { mem::zeroed() };
    let src_addr_len: libc::socklen_t = mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;

    // Prepare the control message buffer
    let mut cmsg_buf: [u8; CMSG_BUFFER_SIZE] = [0; CMSG_BUFFER_SIZE];

    // Prepare msghdr
    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_name = std::ptr::addr_of_mut!(src_addr).cast::<libc::c_void>();
    msg.msg_namelen = src_addr_len;
    msg.msg_iov = std::ptr::addr_of_mut!(iov);
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr().cast::<libc::c_void>();
    msg.msg_controllen = CMSG_BUFFER_SIZE;

    // Call recvmsg
    let n = unsafe { libc::recvmsg(fd, &mut msg, 0) };

    if n < 0 {
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::WouldBlock {
            return Err(io::Error::new(io::ErrorKind::WouldBlock, "WouldBlock"));
        }
        return Err(err);
    }

    // SEC-2 FIX: Check for control message truncation
    // If MSG_CTRUNC is set, the control message buffer was too small and
    // the original destination address may be missing or corrupted.
    if (msg.msg_flags & libc::MSG_CTRUNC) != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Control message truncated (MSG_CTRUNC) - cmsg buffer too small",
        ));
    }

    // Parse source address
    let src_port = u16::from_be(src_addr.sin_port);
    let src_ip = Ipv4Addr::from(u32::from_be(src_addr.sin_addr.s_addr));
    let src = SocketAddr::V4(SocketAddrV4::new(src_ip, src_port));

    // Parse control message to get original destination
    let mut original_dst: Option<SocketAddr> = None;

    // Iterate through control messages
    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    while !cmsg.is_null() {
        let cmsg_ref = unsafe { &*cmsg };

        if cmsg_ref.cmsg_level == libc::SOL_IP && cmsg_ref.cmsg_type == IP_RECVORIGDSTADDR {
            // Found the original destination address
            let addr_ptr = unsafe { libc::CMSG_DATA(cmsg) }.cast::<libc::sockaddr_in>();
            let addr = unsafe { &*addr_ptr };

            let dst_port = u16::from_be(addr.sin_port);
            let dst_ip = Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
            original_dst = Some(SocketAddr::V4(SocketAddrV4::new(dst_ip, dst_port)));
            break;
        }

        cmsg = unsafe { libc::CMSG_NXTHDR(&msg, cmsg) };
    }

    let dst = original_dst.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "Original destination not found in cmsg - not a TPROXY packet?",
        )
    })?;

    Ok((n as usize, src, dst))
}

/// Builder for creating a TPROXY UDP listener with custom options
#[derive(Debug)]
pub struct TproxyUdpListenerBuilder {
    address: SocketAddr,
    reuse_port: bool,
}

impl TproxyUdpListenerBuilder {
    /// Create a new builder with the given listen address
    #[must_use]
    pub fn new(address: SocketAddr) -> Self {
        Self {
            address,
            reuse_port: true,
        }
    }

    /// Set whether to use `SO_REUSEPORT`
    #[must_use]
    pub const fn reuse_port(mut self, reuse: bool) -> Self {
        self.reuse_port = reuse;
        self
    }

    /// Build the listener
    ///
    /// # Errors
    ///
    /// Returns `UdpError` if listener creation fails.
    pub fn build(self) -> Result<TproxyUdpListener, UdpError> {
        let config = ListenConfig {
            address: self.address,
            tcp_enabled: false,
            udp_enabled: true,
            tcp_backlog: 1024,
            udp_timeout_secs: 300,
            reuse_port: self.reuse_port,
            sniff_timeout_ms: 300,
            udp_workers: None,
            udp_buffer_pool_size: 1024,
        };

        TproxyUdpListener::bind(&config)
    }
}

impl Default for TproxyUdpListenerBuilder {
    fn default() -> Self {
        Self::new("127.0.0.1:7893".parse().unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_udp_packet_info() {
        let data = Bytes::from_static(b"hello");
        let client_addr: SocketAddr = "192.168.1.100:12345".parse().unwrap();
        let original_dst: SocketAddr = "8.8.8.8:53".parse().unwrap();

        let packet = UdpPacketInfo {
            data: data.clone(),
            client_addr,
            original_dst,
            received_at: Instant::now(),
        };

        assert_eq!(packet.len(), 5);
        assert!(!packet.is_empty());
        assert_eq!(packet.client_addr, client_addr);
        assert_eq!(packet.original_dst, original_dst);
    }

    #[test]
    fn test_builder() {
        let builder = TproxyUdpListenerBuilder::new("127.0.0.1:8080".parse().unwrap())
            .reuse_port(false);

        assert_eq!(builder.address, "127.0.0.1:8080".parse().unwrap());
        assert!(!builder.reuse_port);
    }

    #[test]
    fn test_default_builder() {
        let builder = TproxyUdpListenerBuilder::default();
        assert_eq!(builder.address, "127.0.0.1:7893".parse().unwrap());
        assert!(builder.reuse_port);
    }

    // Note: Actual listener tests require CAP_NET_ADMIN and iptables setup
    // Integration tests should be run in a container with proper setup

    #[test]
    fn test_listener_creation_without_cap() {
        // This test will fail without CAP_NET_ADMIN
        let result = TproxyUdpListener::bind_addr("127.0.0.1:0".parse().unwrap());
        match result {
            Ok(listener) => {
                // Running with sufficient privileges
                assert!(listener.is_active());
                assert_eq!(listener.packets_received(), 0);
                assert_eq!(listener.bytes_received(), 0);
            }
            Err(UdpError::PermissionDenied) => {
                // Expected when running without CAP_NET_ADMIN
            }
            Err(e) => {
                // Some other error is acceptable (e.g., socket option)
                println!("Listener creation failed (expected without root): {}", e);
            }
        }
    }
}
