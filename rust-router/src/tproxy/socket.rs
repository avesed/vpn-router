//! TPROXY socket utilities
//!
//! This module provides low-level socket operations for TPROXY transparent proxying.
//! Key capabilities:
//! - `IP_TRANSPARENT`: Allows binding to non-local addresses and receiving TPROXY traffic
//! - `SO_ORIGINAL_DST`: Retrieves the original destination from TCP TPROXY connections
//! - `IP_RECVORIGDSTADDR`: Enables receiving original destination in UDP cmsg

use std::io;
use std::mem;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::unix::io::{AsRawFd, RawFd};

use socket2::{Domain, Protocol, Socket, Type};
use tracing::debug;

use crate::error::TproxyError;

/// Linux kernel constant: IP_TRANSPARENT socket option (SOL_IP level)
/// Allows the socket to:
/// 1. Bind to non-local addresses
/// 2. Accept TPROXY-redirected connections
pub const IP_TRANSPARENT: libc::c_int = 19;

/// Linux kernel constant: SO_ORIGINAL_DST (SOL_IP level)
/// Used with getsockopt to retrieve the original destination address
/// from a TPROXY-redirected TCP connection.
pub const SO_ORIGINAL_DST: libc::c_int = 80;

/// Linux kernel constant: IP_RECVORIGDSTADDR (SOL_IP level)
/// When enabled, UDP packets include the original destination in ancillary data (cmsg).
pub const IP_RECVORIGDSTADDR: libc::c_int = 20;

/// Create a TCP socket with IP_TRANSPARENT enabled for TPROXY.
///
/// This socket can:
/// - Bind to any address (including non-local)
/// - Accept connections destined for any IP
/// - Retrieve original destination via `get_original_dst()`
///
/// # Errors
///
/// Returns `TproxyError::SocketCreation` if socket creation fails.
/// Returns `TproxyError::SocketOption` if setting IP_TRANSPARENT fails.
pub fn create_tproxy_tcp_socket() -> Result<Socket, TproxyError> {
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))
        .map_err(|e| TproxyError::SocketCreation(e.to_string()))?;

    // Enable IP_TRANSPARENT
    set_ip_transparent(&socket)?;

    // Enable SO_REUSEADDR for quick restart
    socket
        .set_reuse_address(true)
        .map_err(|e| TproxyError::socket_option("SO_REUSEADDR", e.to_string()))?;

    // Enable SO_REUSEPORT for multi-core scaling
    socket
        .set_reuse_port(true)
        .map_err(|e| TproxyError::socket_option("SO_REUSEPORT", e.to_string()))?;

    // Set non-blocking for tokio compatibility
    socket
        .set_nonblocking(true)
        .map_err(|e| TproxyError::socket_option("O_NONBLOCK", e.to_string()))?;

    debug!("Created TPROXY TCP socket with IP_TRANSPARENT enabled");
    Ok(socket)
}

/// Create a UDP socket with IP_TRANSPARENT and IP_RECVORIGDSTADDR enabled.
///
/// # Errors
///
/// Returns `TproxyError` if socket creation or option setting fails.
pub fn create_tproxy_udp_socket() -> Result<Socket, TproxyError> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        .map_err(|e| TproxyError::SocketCreation(e.to_string()))?;

    // Enable IP_TRANSPARENT
    set_ip_transparent(&socket)?;

    // Enable IP_RECVORIGDSTADDR for receiving original destination in cmsg
    set_ip_recvorigdstaddr(&socket)?;

    // Enable SO_REUSEADDR
    socket
        .set_reuse_address(true)
        .map_err(|e| TproxyError::socket_option("SO_REUSEADDR", e.to_string()))?;

    // Enable SO_REUSEPORT
    socket
        .set_reuse_port(true)
        .map_err(|e| TproxyError::socket_option("SO_REUSEPORT", e.to_string()))?;

    // Set non-blocking
    socket
        .set_nonblocking(true)
        .map_err(|e| TproxyError::socket_option("O_NONBLOCK", e.to_string()))?;

    debug!("Created TPROXY UDP socket with IP_TRANSPARENT and IP_RECVORIGDSTADDR");
    Ok(socket)
}

/// Set IP_TRANSPARENT socket option.
///
/// # Errors
///
/// Returns `TproxyError::SocketOption` if setsockopt fails.
/// Returns `TproxyError::PermissionDenied` if CAP_NET_ADMIN is required.
fn set_ip_transparent(socket: &Socket) -> Result<(), TproxyError> {
    let fd = socket.as_raw_fd();
    let one: libc::c_int = 1;

    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_IP,
            IP_TRANSPARENT,
            std::ptr::addr_of!(one).cast::<libc::c_void>(),
            mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };

    if ret != 0 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EPERM) {
            return Err(TproxyError::PermissionDenied);
        }
        return Err(TproxyError::socket_option("IP_TRANSPARENT", err.to_string()));
    }

    Ok(())
}

/// Set IP_RECVORIGDSTADDR socket option for UDP.
fn set_ip_recvorigdstaddr(socket: &Socket) -> Result<(), TproxyError> {
    let fd = socket.as_raw_fd();
    let one: libc::c_int = 1;

    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_IP,
            IP_RECVORIGDSTADDR,
            std::ptr::addr_of!(one).cast::<libc::c_void>(),
            mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };

    if ret != 0 {
        let err = io::Error::last_os_error();
        return Err(TproxyError::socket_option(
            "IP_RECVORIGDSTADDR",
            err.to_string(),
        ));
    }

    Ok(())
}

/// Get the original destination address from a TPROXY TCP connection.
///
/// When iptables TPROXY redirects a connection, the original destination
/// is stored in the socket and can be retrieved using `SO_ORIGINAL_DST`.
///
/// # Arguments
///
/// * `fd` - Raw file descriptor of the accepted TCP connection
///
/// # Errors
///
/// Returns `TproxyError::OriginalDstError` if:
/// - The socket is not a TPROXY connection (ENOPROTOOPT)
/// - getsockopt fails for any other reason
pub fn get_original_dst(fd: RawFd) -> Result<SocketAddr, TproxyError> {
    let mut addr: libc::sockaddr_in = unsafe { mem::zeroed() };
    let mut len: libc::socklen_t = mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;

    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_IP,
            SO_ORIGINAL_DST,
            std::ptr::addr_of_mut!(addr).cast::<libc::c_void>(),
            &mut len,
        )
    };

    if ret != 0 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ENOPROTOOPT) {
            return Err(TproxyError::OriginalDstError(
                "SO_ORIGINAL_DST not available - not a TPROXY connection?".into(),
            ));
        }
        return Err(TproxyError::OriginalDstError(format!(
            "getsockopt SO_ORIGINAL_DST failed: {}",
            err
        )));
    }

    // Convert from C sockaddr_in to Rust SocketAddr
    let port = u16::from_be(addr.sin_port);
    let ip = Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));

    Ok(SocketAddr::V4(SocketAddrV4::new(ip, port)))
}

/// Get the original destination from a TPROXY IPv6 TCP connection.
///
/// Similar to `get_original_dst` but for IPv6 connections.
/// Uses `IP6T_SO_ORIGINAL_DST` (80 at SOL_IPV6 level).
///
/// # Errors
///
/// Returns `TproxyError::OriginalDstError` if retrieval fails.
pub fn get_original_dst_v6(fd: RawFd) -> Result<SocketAddr, TproxyError> {
    use std::net::{Ipv6Addr, SocketAddrV6};

    const IP6T_SO_ORIGINAL_DST: libc::c_int = 80;

    let mut addr: libc::sockaddr_in6 = unsafe { mem::zeroed() };
    let mut len: libc::socklen_t = mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;

    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_IPV6,
            IP6T_SO_ORIGINAL_DST,
            std::ptr::addr_of_mut!(addr).cast::<libc::c_void>(),
            &mut len,
        )
    };

    if ret != 0 {
        let err = io::Error::last_os_error();
        return Err(TproxyError::OriginalDstError(format!(
            "getsockopt IP6T_SO_ORIGINAL_DST failed: {}",
            err
        )));
    }

    let port = u16::from_be(addr.sin6_port);
    let ip = Ipv6Addr::from(addr.sin6_addr.s6_addr);

    Ok(SocketAddr::V6(SocketAddrV6::new(
        ip,
        port,
        addr.sin6_flowinfo,
        addr.sin6_scope_id,
    )))
}

/// Check if the current process has CAP_NET_ADMIN capability.
///
/// TPROXY requires CAP_NET_ADMIN for:
/// - Setting IP_TRANSPARENT socket option
/// - Binding to non-local addresses
#[must_use]
pub fn has_net_admin_capability() -> bool {
    // Try to create a socket with IP_TRANSPARENT as a capability test
    match create_tproxy_tcp_socket() {
        Ok(_) => true,
        Err(TproxyError::PermissionDenied) => false,
        Err(_) => {
            // Other errors don't indicate missing capability
            true
        }
    }
}

/// Check if running as root (effective UID = 0).
#[must_use]
pub fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(IP_TRANSPARENT, 19);
        assert_eq!(SO_ORIGINAL_DST, 80);
        assert_eq!(IP_RECVORIGDSTADDR, 20);
    }

    #[test]
    fn test_is_root() {
        // Just verify it doesn't crash
        let _ = is_root();
    }

    #[test]
    fn test_socket_creation_without_cap() {
        // When not running as root, this should fail with PermissionDenied
        // or succeed if running with CAP_NET_ADMIN
        let result = create_tproxy_tcp_socket();
        match result {
            Ok(_) => {
                // Running with sufficient privileges
            }
            Err(TproxyError::PermissionDenied) => {
                // Expected when running without CAP_NET_ADMIN
            }
            Err(e) => {
                panic!("Unexpected error: {}", e);
            }
        }
    }

    #[test]
    fn test_has_net_admin_capability() {
        // Just verify it returns a boolean without crashing
        let _ = has_net_admin_capability();
    }
}
