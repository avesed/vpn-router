//! TPROXY socket utilities
//!
//! This module provides low-level socket operations for TPROXY transparent proxying.
//! Key capabilities:
//! - `IP_TRANSPARENT`: Allows binding to non-local addresses and receiving TPROXY traffic
//! - `SO_ORIGINAL_DST`: Retrieves the original destination from TCP TPROXY connections
//! - `IP_RECVORIGDSTADDR`: Enables receiving original destination in UDP cmsg
//!
//! # Socket Provider Trait
//!
//! For testability, this module provides a [`SocketProvider`] trait that abstracts
//! socket creation. Production code uses [`RealSocketProvider`], while tests can
//! use mock implementations.

use std::io;
use std::mem;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::Arc;

use socket2::{Domain, Protocol, Socket, Type};
use tracing::debug;

use crate::error::{TproxyError, UdpError};

/// Linux kernel constant: `IP_TRANSPARENT` socket option (`SOL_IP` level)
/// Allows the socket to:
/// 1. Bind to non-local addresses
/// 2. Accept TPROXY-redirected connections
pub const IP_TRANSPARENT: libc::c_int = 19;

/// Linux kernel constant: `SO_ORIGINAL_DST` (`SOL_IP` level)
/// Used with getsockopt to retrieve the original destination address
/// from a TPROXY-redirected TCP connection.
pub const SO_ORIGINAL_DST: libc::c_int = 80;

/// Linux kernel constant: `IP_RECVORIGDSTADDR` (`SOL_IP` level)
/// When enabled, UDP packets include the original destination in ancillary data (cmsg).
pub const IP_RECVORIGDSTADDR: libc::c_int = 20;

// =============================================================================
// Socket Provider Trait
// =============================================================================

/// Trait for abstracting socket creation for dependency injection and testing.
///
/// This trait allows production code to use real TPROXY sockets while tests
/// can substitute mock implementations that don't require `CAP_NET_ADMIN`.
///
/// # Example
///
/// ```ignore
/// use rust_router::tproxy::{SocketProvider, RealSocketProvider};
///
/// // Production code
/// let provider = RealSocketProvider::new();
/// let socket = provider.create_tproxy_udp_socket()?;
///
/// // Test code can use a mock implementation
/// #[cfg(test)]
/// let provider = MockSocketProvider::new();
/// ```
pub trait SocketProvider: Send + Sync {
    /// Create a TPROXY-enabled UDP socket.
    ///
    /// The returned socket should have:
    /// - `IP_TRANSPARENT` enabled
    /// - `IP_RECVORIGDSTADDR` enabled
    /// - `SO_REUSEADDR` and `SO_REUSEPORT` enabled
    /// - Non-blocking mode enabled
    ///
    /// # Errors
    ///
    /// Returns `TproxyError` if socket creation or option setting fails.
    fn create_tproxy_udp_socket(&self) -> Result<Socket, TproxyError>;

    /// Create a reply socket for sending UDP responses with spoofed source.
    ///
    /// The returned socket should have:
    /// - `IP_TRANSPARENT` enabled (to allow binding to non-local addresses)
    /// - `SO_REUSEADDR` enabled
    /// - Non-blocking mode enabled
    ///
    /// # Arguments
    ///
    /// * `bind_addr` - The address to bind to (typically the original destination)
    ///
    /// # Errors
    ///
    /// Returns `UdpError` if socket creation, binding, or option setting fails.
    fn create_reply_socket(&self, bind_addr: SocketAddr) -> Result<Socket, UdpError>;
}

/// Real socket provider that creates actual TPROXY sockets.
///
/// This is the default production implementation that uses the real
/// `IP_TRANSPARENT` socket option and requires `CAP_NET_ADMIN` capability.
#[derive(Debug, Clone, Default)]
pub struct RealSocketProvider;

impl RealSocketProvider {
    /// Create a new real socket provider.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl SocketProvider for RealSocketProvider {
    fn create_tproxy_udp_socket(&self) -> Result<Socket, TproxyError> {
        create_tproxy_udp_socket()
    }

    fn create_reply_socket(&self, bind_addr: SocketAddr) -> Result<Socket, UdpError> {
        // Create UDP socket
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).map_err(|e| {
            UdpError::reply_socket(bind_addr, format!("Failed to create socket: {e}"))
        })?;

        // Set IP_TRANSPARENT to allow binding to non-local addresses
        set_ip_transparent(&socket).map_err(|e| {
            UdpError::reply_socket(bind_addr, format!("Failed to set IP_TRANSPARENT: {e}"))
        })?;

        // Set SO_REUSEADDR
        socket.set_reuse_address(true).map_err(|e| {
            UdpError::reply_socket(bind_addr, format!("Failed to set SO_REUSEADDR: {e}"))
        })?;

        // Bind to the "original destination" (a non-local address)
        socket.bind(&bind_addr.into()).map_err(|e| {
            UdpError::reply_socket(
                bind_addr,
                format!(
                    "Failed to bind to {bind_addr} (need ip_nonlocal_bind=1 and CAP_NET_ADMIN): {e}"
                ),
            )
        })?;

        // Set non-blocking for tokio
        socket.set_nonblocking(true).map_err(|e| {
            UdpError::reply_socket(bind_addr, format!("Failed to set non-blocking: {e}"))
        })?;

        debug!("Created reply socket bound to {}", bind_addr);

        Ok(socket)
    }
}

/// Get the default socket provider (production implementation).
///
/// Returns an `Arc<dyn SocketProvider>` for use in production code.
#[must_use]
pub fn default_socket_provider() -> Arc<dyn SocketProvider> {
    Arc::new(RealSocketProvider::new())
}

// =============================================================================
// Mock Socket Provider (for testing)
// =============================================================================

/// Mock socket provider for testing without `CAP_NET_ADMIN`.
///
/// This provider creates regular UDP sockets without TPROXY options,
/// allowing unit tests to run without elevated privileges.
#[cfg(test)]
#[derive(Debug, Clone, Default)]
pub struct MockSocketProvider {
    /// Whether to simulate permission denied errors
    pub simulate_permission_denied: bool,
}

#[cfg(test)]
impl MockSocketProvider {
    /// Create a new mock socket provider.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            simulate_permission_denied: false,
        }
    }

    /// Create a mock provider that simulates permission denied errors.
    #[must_use]
    pub const fn permission_denied() -> Self {
        Self {
            simulate_permission_denied: true,
        }
    }
}

#[cfg(test)]
impl SocketProvider for MockSocketProvider {
    fn create_tproxy_udp_socket(&self) -> Result<Socket, TproxyError> {
        if self.simulate_permission_denied {
            return Err(TproxyError::PermissionDenied);
        }

        // Create a regular UDP socket (without TPROXY options)
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
            .map_err(|e| TproxyError::SocketCreation(e.to_string()))?;

        socket
            .set_reuse_address(true)
            .map_err(|e| TproxyError::socket_option("SO_REUSEADDR", e.to_string()))?;

        socket
            .set_nonblocking(true)
            .map_err(|e| TproxyError::socket_option("O_NONBLOCK", e.to_string()))?;

        Ok(socket)
    }

    fn create_reply_socket(&self, bind_addr: SocketAddr) -> Result<Socket, UdpError> {
        if self.simulate_permission_denied {
            return Err(UdpError::reply_socket(bind_addr, "Permission denied (mock)"));
        }

        // Create a regular UDP socket bound to 127.0.0.1:0 for testing
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).map_err(|e| {
            UdpError::reply_socket(bind_addr, format!("Failed to create socket: {e}"))
        })?;

        socket.set_reuse_address(true).map_err(|e| {
            UdpError::reply_socket(bind_addr, format!("Failed to set SO_REUSEADDR: {e}"))
        })?;

        // For mock, bind to localhost with port 0 instead of the non-local address
        let mock_bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
        socket.bind(&mock_bind.into()).map_err(|e| {
            UdpError::reply_socket(bind_addr, format!("Failed to bind: {e}"))
        })?;

        socket.set_nonblocking(true).map_err(|e| {
            UdpError::reply_socket(bind_addr, format!("Failed to set non-blocking: {e}"))
        })?;

        Ok(socket)
    }
}

// =============================================================================
// Socket Creation Functions
// =============================================================================

/// Create a TCP socket with `IP_TRANSPARENT` enabled for TPROXY.
///
/// This socket can:
/// - Bind to any address (including non-local)
/// - Accept connections destined for any IP
/// - Retrieve original destination via `get_original_dst()`
///
/// # Errors
///
/// Returns `TproxyError::SocketCreation` if socket creation fails.
/// Returns `TproxyError::SocketOption` if setting `IP_TRANSPARENT` fails.
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

/// Create a UDP socket with `IP_TRANSPARENT` and `IP_RECVORIGDSTADDR` enabled.
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

/// Set `IP_TRANSPARENT` socket option.
///
/// # Errors
///
/// Returns `TproxyError::SocketOption` if setsockopt fails.
/// Returns `TproxyError::PermissionDenied` if `CAP_NET_ADMIN` is required.
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

/// Set `IP_RECVORIGDSTADDR` socket option for UDP.
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
            &raw mut len,
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
            "getsockopt SO_ORIGINAL_DST failed: {err}"
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
/// Uses `IP6T_SO_ORIGINAL_DST` (80 at `SOL_IPV6` level).
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
            &raw mut len,
        )
    };

    if ret != 0 {
        let err = io::Error::last_os_error();
        return Err(TproxyError::OriginalDstError(format!(
            "getsockopt IP6T_SO_ORIGINAL_DST failed: {err}"
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

/// Check if the current process has `CAP_NET_ADMIN` capability.
///
/// TPROXY requires `CAP_NET_ADMIN` for:
/// - Setting `IP_TRANSPARENT` socket option
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
            // Running with sufficient privileges or expected permission denied
            Ok(_) | Err(TproxyError::PermissionDenied) => {}
            Err(e) => {
                panic!("Unexpected error: {e}");
            }
        }
    }

    #[test]
    fn test_has_net_admin_capability() {
        // Just verify it returns a boolean without crashing
        let _ = has_net_admin_capability();
    }

    // =============================================================================
    // SocketProvider Tests
    // =============================================================================

    #[test]
    fn test_real_socket_provider_new() {
        let provider = RealSocketProvider::new();
        // Just verify it can be created
        let _ = provider;
    }

    #[test]
    fn test_real_socket_provider_default() {
        let _provider: RealSocketProvider = RealSocketProvider::default();
    }

    #[test]
    fn test_default_socket_provider() {
        let provider = default_socket_provider();
        // Verify it returns an Arc<dyn SocketProvider>
        let _ = provider;
    }

    #[test]
    fn test_mock_socket_provider_new() {
        let provider = MockSocketProvider::new();
        assert!(!provider.simulate_permission_denied);
    }

    #[test]
    fn test_mock_socket_provider_permission_denied() {
        let provider = MockSocketProvider::permission_denied();
        assert!(provider.simulate_permission_denied);
    }

    #[test]
    fn test_mock_socket_provider_create_udp_socket() {
        let provider = MockSocketProvider::new();
        let result = provider.create_tproxy_udp_socket();
        assert!(result.is_ok(), "Mock socket creation should succeed");
    }

    #[test]
    fn test_mock_socket_provider_create_udp_socket_permission_denied() {
        let provider = MockSocketProvider::permission_denied();
        let result = provider.create_tproxy_udp_socket();
        assert!(matches!(result, Err(TproxyError::PermissionDenied)));
    }

    #[test]
    fn test_mock_socket_provider_create_reply_socket() {
        let provider = MockSocketProvider::new();
        let bind_addr: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let result = provider.create_reply_socket(bind_addr);
        // Mock provider binds to localhost:0 instead, so this should succeed
        assert!(result.is_ok(), "Mock reply socket creation should succeed");
    }

    #[test]
    fn test_mock_socket_provider_create_reply_socket_permission_denied() {
        let provider = MockSocketProvider::permission_denied();
        let bind_addr: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let result = provider.create_reply_socket(bind_addr);
        assert!(matches!(result, Err(UdpError::ReplySocketError { .. })));
    }

    #[test]
    fn test_socket_provider_trait_object() {
        // Verify the trait can be used as a trait object
        fn use_provider(provider: &dyn SocketProvider) -> Result<Socket, TproxyError> {
            provider.create_tproxy_udp_socket()
        }

        let mock = MockSocketProvider::new();
        let result = use_provider(&mock);
        assert!(result.is_ok());
    }

    #[test]
    fn test_socket_provider_arc() {
        // Verify the trait can be used with Arc
        let provider: Arc<dyn SocketProvider> = Arc::new(MockSocketProvider::new());
        let result = provider.create_tproxy_udp_socket();
        assert!(result.is_ok());
    }
}
