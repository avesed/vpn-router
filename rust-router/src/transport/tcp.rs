//! Plain TCP transport implementation
//!
//! This module provides a TCP transport for establishing plain (unencrypted)
//! TCP connections with configurable options like keepalive and nodelay.
//!
//! # Example
//!
//! ```no_run
//! use rust_router::transport::{TransportConfig, TcpTransport, Transport};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let transport = TcpTransport;
//! let config = TransportConfig::tcp("example.com", 80);
//! let stream = transport.connect(&config).await?;
//! # Ok(())
//! # }
//! ```

use std::net::{SocketAddr, ToSocketAddrs};
use std::time::Duration;

use async_trait::async_trait;
use socket2::{SockRef, TcpKeepalive};
use tokio::net::TcpStream;
use tokio::time::timeout;

use super::{Transport, TransportConfig, TransportError, TransportStream};

/// TCP transport for plain connections
///
/// This transport establishes plain TCP connections without any encryption.
/// It supports configurable TCP options like keepalive and nodelay.
///
/// # Thread Safety
///
/// `TcpTransport` is `Send + Sync` and can be shared across threads.
#[derive(Debug, Clone, Copy, Default)]
pub struct TcpTransport;

impl TcpTransport {
    /// Create a new TCP transport
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Resolve hostname to socket addresses
    fn resolve_address(address: &str, port: u16) -> Result<Vec<SocketAddr>, TransportError> {
        let addr_str = format!("{address}:{port}");

        // Try to parse as socket address first (handles IP:port)
        if let Ok(addr) = addr_str.parse::<SocketAddr>() {
            return Ok(vec![addr]);
        }

        // Use DNS resolution (blocking, but happens rarely for configured addresses)
        let addrs: Vec<SocketAddr> = addr_str
            .to_socket_addrs()
            .map_err(|e| TransportError::dns_failed(&addr_str, e.to_string()))?
            .collect();

        if addrs.is_empty() {
            return Err(TransportError::dns_failed(
                &addr_str,
                "no addresses returned",
            ));
        }

        Ok(addrs)
    }

    /// Configure TCP socket options
    fn configure_socket(
        stream: &TcpStream,
        config: &TransportConfig,
    ) -> Result<(), TransportError> {
        // Set TCP_NODELAY (disable Nagle's algorithm)
        if config.tcp_nodelay {
            stream
                .set_nodelay(true)
                .map_err(|e| TransportError::socket_option("TCP_NODELAY", e.to_string()))?;
        }

        // Set TCP keepalive
        if config.tcp_keepalive {
            let socket_ref = SockRef::from(stream);
            let keepalive = TcpKeepalive::new()
                .with_time(Duration::from_secs(60))
                .with_interval(Duration::from_secs(20));

            #[cfg(target_os = "linux")]
            let keepalive = keepalive.with_retries(3);

            socket_ref
                .set_tcp_keepalive(&keepalive)
                .map_err(|e| TransportError::socket_option("TCP_KEEPALIVE", e.to_string()))?;
        }

        Ok(())
    }

    /// Connect to a single address with timeout
    async fn connect_to_addr(
        addr: SocketAddr,
        connect_timeout: Duration,
    ) -> Result<TcpStream, TransportError> {
        let connect_future = TcpStream::connect(addr);

        timeout(connect_timeout, connect_future)
            .await
            .map_err(|_| {
                TransportError::timeout(addr.to_string(), connect_timeout.as_millis() as u64)
            })?
            .map_err(|e| TransportError::connection_failed(addr.to_string(), e.to_string()))
    }
}

#[async_trait]
impl Transport for TcpTransport {
    /// Connect to a remote server over TCP
    ///
    /// This method resolves the hostname, attempts connection to each resolved
    /// address in order, and configures the resulting socket.
    ///
    /// # Arguments
    ///
    /// * `config` - Transport configuration with address and options
    ///
    /// # Errors
    ///
    /// Returns `TransportError` if:
    /// - DNS resolution fails
    /// - All connection attempts fail
    /// - Socket configuration fails
    async fn connect(&self, config: &TransportConfig) -> Result<TransportStream, TransportError> {
        // Resolve address to socket addresses
        let addrs = Self::resolve_address(&config.address, config.port)?;

        // Try connecting to each address
        let mut last_error = None;

        for addr in addrs {
            match Self::connect_to_addr(addr, config.connect_timeout).await {
                Ok(stream) => {
                    // Configure socket options
                    Self::configure_socket(&stream, config)?;

                    tracing::debug!(
                        addr = %addr,
                        nodelay = config.tcp_nodelay,
                        keepalive = config.tcp_keepalive,
                        "TCP connection established"
                    );

                    return Ok(TransportStream::Tcp(stream));
                }
                Err(e) => {
                    tracing::debug!(
                        addr = %addr,
                        error = %e,
                        "TCP connection attempt failed"
                    );
                    last_error = Some(e);
                }
            }
        }

        // All addresses failed
        Err(last_error.unwrap_or_else(|| {
            TransportError::connection_failed(
                config.address_string(),
                "no addresses to connect to",
            )
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_tcp_transport_new() {
        let transport = TcpTransport::new();
        // Should be zero-sized
        assert_eq!(std::mem::size_of_val(&transport), 0);
    }

    #[test]
    fn test_tcp_transport_default() {
        let transport = TcpTransport::default();
        assert_eq!(std::mem::size_of_val(&transport), 0);
    }

    #[test]
    fn test_resolve_ipv4() {
        let addrs = TcpTransport::resolve_address("127.0.0.1", 80).unwrap();
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0].ip(), Ipv4Addr::new(127, 0, 0, 1));
        assert_eq!(addrs[0].port(), 80);
    }

    #[test]
    fn test_resolve_ipv6() {
        let addrs = TcpTransport::resolve_address("::1", 443).unwrap();
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0].ip(), Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1));
        assert_eq!(addrs[0].port(), 443);
    }

    #[test]
    fn test_resolve_localhost() {
        let addrs = TcpTransport::resolve_address("localhost", 8080).unwrap();
        assert!(!addrs.is_empty());
        for addr in &addrs {
            assert_eq!(addr.port(), 8080);
        }
    }

    #[test]
    fn test_resolve_invalid_hostname() {
        let result = TcpTransport::resolve_address("this.domain.does.not.exist.invalid", 80);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, TransportError::DnsResolutionFailed { .. }));
    }

    #[tokio::test]
    async fn test_connect_refused() {
        let transport = TcpTransport::new();
        // Port 1 is unlikely to have a service listening
        let config = TransportConfig::tcp("127.0.0.1", 1).with_timeout(Duration::from_millis(100));

        let result = transport.connect(&config).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.is_recoverable());
    }

    #[tokio::test]
    async fn test_connect_timeout() {
        let transport = TcpTransport::new();
        // Use a non-routable address to trigger timeout
        // 10.255.255.1 is a reserved address that won't respond
        let config =
            TransportConfig::tcp("10.255.255.1", 80).with_timeout(Duration::from_millis(50));

        let result = transport.connect(&config).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_connect_invalid_hostname() {
        let transport = TcpTransport::new();
        let config = TransportConfig::tcp("this.domain.does.not.exist.invalid", 80);

        let result = transport.connect(&config).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, TransportError::DnsResolutionFailed { .. }));
    }

    #[test]
    fn test_transport_config_defaults() {
        let config = TransportConfig::tcp("example.com", 80);
        assert!(config.tcp_nodelay);
        assert!(config.tcp_keepalive);
        assert_eq!(config.connect_timeout, Duration::from_secs(30));
    }

    #[test]
    fn test_transport_config_custom_options() {
        let config = TransportConfig::tcp("example.com", 80)
            .with_nodelay(false)
            .with_keepalive(false)
            .with_timeout(Duration::from_secs(60));

        assert!(!config.tcp_nodelay);
        assert!(!config.tcp_keepalive);
        assert_eq!(config.connect_timeout, Duration::from_secs(60));
    }
}
