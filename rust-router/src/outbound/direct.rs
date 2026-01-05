//! Direct outbound implementation
//!
//! This module provides the `DirectOutbound` type which connects directly
//! to the destination, optionally through a specific interface or with
//! a routing mark.

use std::io;
use std::mem;
use std::net::SocketAddr;
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use socket2::{Domain, Protocol, Socket, TcpKeepalive, Type};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::debug;

use super::traits::{HealthStatus, Outbound, OutboundConnection};
use crate::config::OutboundConfig;
use crate::connection::OutboundStats;
use crate::error::OutboundError;

/// Direct outbound - connects directly to the destination
///
/// Supports:
/// - `bind_interface`: Bind to a specific network interface (SO_BINDTODEVICE)
/// - `bind_address`: Bind to a specific local address
/// - `routing_mark`: Set routing mark for policy routing (SO_MARK)
pub struct DirectOutbound {
    /// Configuration
    config: OutboundConfig,
    /// Connection statistics
    stats: Arc<OutboundStats>,
    /// Whether the outbound is enabled
    enabled: AtomicBool,
    /// Current health status
    health: std::sync::RwLock<HealthStatus>,
}

impl DirectOutbound {
    /// Create a new direct outbound from configuration
    pub fn new(config: OutboundConfig) -> Self {
        Self {
            enabled: AtomicBool::new(config.enabled),
            config,
            stats: Arc::new(OutboundStats::new()),
            health: std::sync::RwLock::new(HealthStatus::Unknown),
        }
    }

    /// Create a simple direct outbound with just a tag
    pub fn simple(tag: impl Into<String>) -> Self {
        Self::new(OutboundConfig::direct(tag))
    }

    /// Create a socket with the configured options
    fn create_socket(&self) -> Result<Socket, OutboundError> {
        let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))
            .map_err(|e| OutboundError::connection_failed("0.0.0.0:0".parse().unwrap(), e.to_string()))?;

        // Set SO_BINDTODEVICE if interface is specified
        if let Some(ref interface) = self.config.bind_interface {
            self.set_bind_device(&socket, interface)?;
        }

        // Set SO_MARK if routing mark is specified
        if let Some(mark) = self.config.routing_mark {
            self.set_routing_mark(&socket, mark)?;
        }

        // Bind to specific address if specified
        if let Some(ref addr) = self.config.bind_address {
            socket.bind(&(*addr).into()).map_err(|e| {
                OutboundError::SocketOption {
                    option: "bind".into(),
                    reason: format!("Failed to bind to {}: {}", addr, e),
                }
            })?;
        }

        // Set non-blocking for tokio
        socket.set_nonblocking(true).map_err(|e| {
            OutboundError::SocketOption {
                option: "O_NONBLOCK".into(),
                reason: e.to_string(),
            }
        })?;

        // Enable TCP keepalive to detect dead peers on long-lived connections
        // - time: 60s idle before first probe
        // - interval: 15s between probes
        let keepalive = TcpKeepalive::new()
            .with_time(Duration::from_secs(60))
            .with_interval(Duration::from_secs(15));

        socket.set_tcp_keepalive(&keepalive).map_err(|e| {
            OutboundError::SocketOption {
                option: "TCP_KEEPALIVE".into(),
                reason: e.to_string(),
            }
        })?;

        Ok(socket)
    }

    /// Set SO_BINDTODEVICE to bind to a specific interface
    fn set_bind_device(&self, socket: &Socket, interface: &str) -> Result<(), OutboundError> {
        // Interface name must be null-terminated and fit in IFNAMSIZ (16 bytes)
        if interface.len() > 15 {
            return Err(OutboundError::SocketOption {
                option: "SO_BINDTODEVICE".into(),
                reason: format!("Interface name too long: {} (max 15 chars)", interface),
            });
        }

        let fd = socket.as_raw_fd();

        // Create null-terminated interface name
        let mut ifname = [0u8; 16];
        ifname[..interface.len()].copy_from_slice(interface.as_bytes());

        let ret = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_BINDTODEVICE,
                ifname.as_ptr().cast::<libc::c_void>(),
                ifname.len() as libc::socklen_t,
            )
        };

        if ret != 0 {
            let err = io::Error::last_os_error();
            return Err(OutboundError::SocketOption {
                option: "SO_BINDTODEVICE".into(),
                reason: format!("Failed to bind to interface {}: {}", interface, err),
            });
        }

        debug!("Bound socket to interface: {}", interface);
        Ok(())
    }

    /// Set SO_MARK for policy routing
    fn set_routing_mark(&self, socket: &Socket, mark: u32) -> Result<(), OutboundError> {
        let fd = socket.as_raw_fd();

        let ret = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_MARK,
                std::ptr::addr_of!(mark).cast::<libc::c_void>(),
                mem::size_of::<u32>() as libc::socklen_t,
            )
        };

        if ret != 0 {
            let err = io::Error::last_os_error();
            return Err(OutboundError::SocketOption {
                option: "SO_MARK".into(),
                reason: format!("Failed to set routing mark {}: {}", mark, err),
            });
        }

        debug!("Set routing mark: {}", mark);
        Ok(())
    }

    /// Update health status based on connection result
    fn update_health(&self, success: bool) {
        let mut health = self.health.write().unwrap();
        if success {
            *health = HealthStatus::Healthy;
        } else {
            *health = match *health {
                HealthStatus::Healthy => HealthStatus::Degraded,
                HealthStatus::Degraded => HealthStatus::Unhealthy,
                _ => HealthStatus::Unhealthy,
            };
        }
    }
}

#[async_trait]
impl Outbound for DirectOutbound {
    async fn connect(
        &self,
        addr: SocketAddr,
        connect_timeout: Duration,
    ) -> Result<OutboundConnection, OutboundError> {
        if !self.is_enabled() {
            return Err(OutboundError::unavailable(
                &self.config.tag,
                "outbound is disabled",
            ));
        }

        self.stats.record_connection();

        // Create socket with configured options
        let socket = self.create_socket()?;

        // Initiate non-blocking connect
        // EINPROGRESS is expected for non-blocking sockets
        match socket.connect(&addr.into()) {
            Ok(()) => {}
            Err(ref e) if e.raw_os_error() == Some(libc::EINPROGRESS) => {}
            Err(e) => {
                // Socket is dropped here, closing the fd
                return Err(OutboundError::connection_failed(addr, e.to_string()));
            }
        }

        // Convert socket to TcpStream immediately after connect initiation
        // This ensures proper ownership - TcpStream will close fd on drop
        let std_stream: std::net::TcpStream = socket.into();
        let stream = TcpStream::from_std(std_stream)
            .map_err(|e| OutboundError::connection_failed(addr, e.to_string()))?;

        // Wait for connection to complete with timeout
        let connect_result = timeout(connect_timeout, async {
            // Wait for socket to become writable (connection complete or failed)
            stream.writable().await
                .map_err(|e| OutboundError::connection_failed(addr, e.to_string()))?;

            // Check for connection errors via SO_ERROR
            match stream.take_error() {
                Ok(Some(e)) => Err(OutboundError::connection_failed(addr, e.to_string())),
                Ok(None) => Ok(()),
                Err(e) => Err(OutboundError::connection_failed(addr, e.to_string())),
            }
        }).await;

        match connect_result {
            Ok(Ok(())) => {
                self.update_health(true);
                debug!(
                    "Direct connection to {} via {} successful",
                    addr, self.config.tag
                );
                Ok(OutboundConnection::new(stream, addr))
            }
            Ok(Err(e)) => {
                self.update_health(false);
                self.stats.record_error();
                // stream is dropped here, closing the fd
                Err(e)
            }
            Err(_) => {
                self.update_health(false);
                self.stats.record_error();
                // stream is dropped here, closing the fd
                Err(OutboundError::Timeout {
                    addr,
                    timeout_secs: connect_timeout.as_secs(),
                })
            }
        }
    }

    fn tag(&self) -> &str {
        &self.config.tag
    }

    fn health_status(&self) -> HealthStatus {
        *self.health.read().unwrap()
    }

    fn stats(&self) -> Arc<OutboundStats> {
        Arc::clone(&self.stats)
    }

    fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    fn outbound_type(&self) -> &str {
        "direct"
    }
}

impl std::fmt::Debug for DirectOutbound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DirectOutbound")
            .field("tag", &self.config.tag)
            .field("bind_interface", &self.config.bind_interface)
            .field("bind_address", &self.config.bind_address)
            .field("routing_mark", &self.config.routing_mark)
            .field("enabled", &self.is_enabled())
            .field("health", &self.health_status())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_direct_outbound_creation() {
        let config = OutboundConfig::direct("test-direct");
        let outbound = DirectOutbound::new(config);

        assert_eq!(outbound.tag(), "test-direct");
        assert!(outbound.is_enabled());
        assert_eq!(outbound.outbound_type(), "direct");
    }

    #[test]
    fn test_simple_creation() {
        let outbound = DirectOutbound::simple("simple");
        assert_eq!(outbound.tag(), "simple");
    }

    #[test]
    fn test_interface_name_validation() {
        let mut config = OutboundConfig::direct("test");
        config.bind_interface = Some("this_is_a_very_long_interface_name".into());

        let outbound = DirectOutbound::new(config);
        let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).unwrap();

        let result = outbound.set_bind_device(&socket, "this_is_a_very_long_interface_name");
        assert!(matches!(result, Err(OutboundError::SocketOption { .. })));
    }

    #[tokio::test]
    async fn test_connect_to_nonexistent() {
        let outbound = DirectOutbound::simple("test");

        // Use TEST-NET-1 (192.0.2.0/24) which is reserved for documentation
        // and should not be routable, ensuring connection failure
        let addr: SocketAddr = "192.0.2.1:12345".parse().unwrap();
        let result = outbound.connect(addr, Duration::from_millis(100)).await;

        // Connection should fail (either timeout or connection refused)
        assert!(result.is_err(), "Expected connection to fail");
    }

    #[test]
    fn test_health_status_transitions() {
        let outbound = DirectOutbound::simple("test");

        // Initial state is Unknown
        assert_eq!(outbound.health_status(), HealthStatus::Unknown);

        // Success makes it Healthy
        outbound.update_health(true);
        assert_eq!(outbound.health_status(), HealthStatus::Healthy);

        // First failure makes it Degraded
        outbound.update_health(false);
        assert_eq!(outbound.health_status(), HealthStatus::Degraded);

        // Second failure makes it Unhealthy
        outbound.update_health(false);
        assert_eq!(outbound.health_status(), HealthStatus::Unhealthy);

        // Success brings it back to Healthy
        outbound.update_health(true);
        assert_eq!(outbound.health_status(), HealthStatus::Healthy);
    }
}
