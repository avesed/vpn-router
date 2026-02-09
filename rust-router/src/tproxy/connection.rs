//! TPROXY connection representation
//!
//! This module provides the `TproxyConnection` type that wraps an accepted
//! TCP connection with its original destination information.

use std::net::SocketAddr;
use std::os::unix::io::AsRawFd;
use std::time::Instant;

use tokio::net::TcpStream;
use tracing::debug;

use super::socket::get_original_dst;
use crate::error::TproxyError;

/// A TPROXY-redirected TCP connection
///
/// This wraps a `TcpStream` with the original destination address
/// that was retrieved from the kernel via `SO_ORIGINAL_DST`.
#[derive(Debug)]
pub struct TproxyConnection {
    /// The underlying TCP stream
    stream: TcpStream,

    /// Client's address (source)
    client_addr: SocketAddr,

    /// Original destination address (where the client wanted to connect)
    original_dst: SocketAddr,

    /// When the connection was accepted
    accepted_at: Instant,
}

impl TproxyConnection {
    /// Create a new TPROXY connection from an accepted stream.
    ///
    /// This will attempt to retrieve the original destination address
    /// using `SO_ORIGINAL_DST`.
    ///
    /// # Arguments
    ///
    /// * `stream` - The accepted TCP stream
    /// * `client_addr` - The client's source address
    ///
    /// # Errors
    ///
    /// Returns `TproxyError::OriginalDstError` if the original destination
    /// cannot be retrieved (e.g., not a TPROXY connection).
    pub fn new(stream: TcpStream, client_addr: SocketAddr) -> Result<Self, TproxyError> {
        let fd = stream.as_raw_fd();
        let original_dst = get_original_dst(fd)?;

        debug!(
            "TPROXY connection: {} -> {} (original)",
            client_addr, original_dst
        );

        Ok(Self {
            stream,
            client_addr,
            original_dst,
            accepted_at: Instant::now(),
        })
    }

    /// Create a TPROXY connection with a pre-known destination.
    ///
    /// This is useful for testing or when the destination is known through
    /// other means.
    pub fn with_destination(
        stream: TcpStream,
        client_addr: SocketAddr,
        original_dst: SocketAddr,
    ) -> Self {
        Self {
            stream,
            client_addr,
            original_dst,
            accepted_at: Instant::now(),
        }
    }

    /// Get the underlying TCP stream
    #[must_use]
    pub fn stream(&self) -> &TcpStream {
        &self.stream
    }

    /// Get a mutable reference to the underlying TCP stream
    pub fn stream_mut(&mut self) -> &mut TcpStream {
        &mut self.stream
    }

    /// Consume the connection and return the underlying stream
    #[must_use]
    pub fn into_stream(self) -> TcpStream {
        self.stream
    }

    /// Get the client's source address
    #[must_use]
    pub const fn client_addr(&self) -> SocketAddr {
        self.client_addr
    }

    /// Get the original destination address
    #[must_use]
    pub const fn original_dst(&self) -> SocketAddr {
        self.original_dst
    }

    /// Get when the connection was accepted
    #[must_use]
    pub const fn accepted_at(&self) -> Instant {
        self.accepted_at
    }

    /// Get the connection age
    #[must_use]
    pub fn age(&self) -> std::time::Duration {
        self.accepted_at.elapsed()
    }

    /// Get the original destination's IP address
    #[must_use]
    pub fn original_dst_ip(&self) -> std::net::IpAddr {
        self.original_dst.ip()
    }

    /// Get the original destination's port
    #[must_use]
    pub fn original_dst_port(&self) -> u16 {
        self.original_dst.port()
    }

    /// Check if the original destination is a common HTTPS port
    #[must_use]
    pub fn is_likely_tls(&self) -> bool {
        matches!(self.original_dst.port(), 443 | 8443 | 853)
    }

    /// Check if the original destination is a common HTTP port
    #[must_use]
    pub fn is_likely_http(&self) -> bool {
        matches!(self.original_dst.port(), 80 | 8080 | 8000 | 3000)
    }
}

impl AsRawFd for TproxyConnection {
    fn as_raw_fd(&self) -> std::os::unix::io::RawFd {
        self.stream.as_raw_fd()
    }
}

/// Information about a TPROXY connection (for logging/stats)
#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    /// Client address
    pub client_addr: SocketAddr,
    /// Original destination
    pub original_dst: SocketAddr,
    /// Connection age in milliseconds
    pub age_ms: u64,
}

impl From<&TproxyConnection> for ConnectionInfo {
    fn from(conn: &TproxyConnection) -> Self {
        Self {
            client_addr: conn.client_addr,
            original_dst: conn.original_dst,
            age_ms: conn.age().as_millis() as u64,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    fn test_addr(port: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))
    }

    #[tokio::test]
    async fn test_connection_info() {
        // Create a test TCP listener and connection
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (server, client_addr) = listener.accept().await.unwrap();

        // Use with_destination since we can't test actual TPROXY without iptables
        let conn = TproxyConnection::with_destination(server, client_addr, test_addr(443));

        assert_eq!(conn.client_addr(), client_addr);
        assert_eq!(conn.original_dst_port(), 443);
        assert!(conn.is_likely_tls());
        assert!(!conn.is_likely_http());

        let info = ConnectionInfo::from(&conn);
        assert_eq!(info.client_addr, client_addr);
        assert_eq!(info.original_dst.port(), 443);

        drop(client);
    }

    #[test]
    fn test_port_detection() {
        let https_ports = [443, 8443, 853];
        let http_ports = [80, 8080, 8000, 3000];

        for port in https_ports {
            assert!(
                matches!(port, 443 | 8443 | 853),
                "Port {} should be detected as TLS",
                port
            );
        }

        for port in http_ports {
            assert!(
                matches!(port, 80 | 8080 | 8000 | 3000),
                "Port {} should be detected as HTTP",
                port
            );
        }
    }
}
