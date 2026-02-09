//! Shadowsocks connection handler
//!
//! This module provides the connection handler for processing incoming Shadowsocks
//! connections. It handles protocol parsing and provides a unified interface for
//! processing authenticated connections.
//!
//! # Connection Flow
//!
//! 1. Accept TCP connection
//! 2. Decrypt Shadowsocks stream
//! 3. Read target address from request header
//! 4. Return connection for forwarding to destination

use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

#[cfg(feature = "shadowsocks")]
use shadowsocks::relay::socks5::Address as SsAddress;

/// A Shadowsocks connection after handshake
///
/// This structure represents a Shadowsocks connection after the handshake
/// has completed and the target address has been extracted.
#[derive(Debug)]
pub struct ShadowsocksConnection<S> {
    /// The underlying decrypted stream
    stream: S,

    /// Destination address from the request header
    destination: ShadowsocksDestination,

    /// Client address
    client_addr: SocketAddr,
}

impl<S> ShadowsocksConnection<S> {
    /// Create a new Shadowsocks connection
    pub fn new(stream: S, destination: ShadowsocksDestination, client_addr: SocketAddr) -> Self {
        Self {
            stream,
            destination,
            client_addr,
        }
    }

    /// Get the destination address
    #[must_use]
    pub fn destination(&self) -> &ShadowsocksDestination {
        &self.destination
    }

    /// Get the client address
    #[must_use]
    pub fn client_addr(&self) -> SocketAddr {
        self.client_addr
    }

    /// Consume the connection and return the underlying stream
    ///
    /// This is useful for forwarding data between the client and destination.
    #[must_use]
    pub fn into_stream(self) -> S {
        self.stream
    }

    /// Get a mutable reference to the underlying stream
    pub fn stream_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    /// Get a reference to the underlying stream
    pub fn stream(&self) -> &S {
        &self.stream
    }
}

/// Shadowsocks destination information
///
/// Represents the target address extracted from a Shadowsocks request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ShadowsocksDestination {
    /// IPv4 address and port
    SocketAddr(SocketAddr),

    /// Domain name and port
    DomainName {
        /// Domain name
        domain: String,
        /// Port number
        port: u16,
    },
}

impl ShadowsocksDestination {
    /// Create a destination from a socket address
    #[must_use]
    pub fn from_socket_addr(addr: SocketAddr) -> Self {
        Self::SocketAddr(addr)
    }

    /// Create a destination from a domain name and port
    #[must_use]
    pub fn from_domain(domain: impl Into<String>, port: u16) -> Self {
        Self::DomainName {
            domain: domain.into(),
            port,
        }
    }

    /// Get the port number
    #[must_use]
    pub fn port(&self) -> u16 {
        match self {
            Self::SocketAddr(addr) => addr.port(),
            Self::DomainName { port, .. } => *port,
        }
    }

    /// Get the host string (IP or domain)
    #[must_use]
    pub fn host(&self) -> String {
        match self {
            Self::SocketAddr(addr) => addr.ip().to_string(),
            Self::DomainName { domain, .. } => domain.clone(),
        }
    }

    /// Convert to a socket address if possible
    ///
    /// Returns `None` for domain names (requires DNS resolution).
    #[must_use]
    pub fn as_socket_addr(&self) -> Option<SocketAddr> {
        match self {
            Self::SocketAddr(addr) => Some(*addr),
            Self::DomainName { .. } => None,
        }
    }
}

impl std::fmt::Display for ShadowsocksDestination {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SocketAddr(addr) => write!(f, "{}", addr),
            Self::DomainName { domain, port } => write!(f, "{}:{}", domain, port),
        }
    }
}

#[cfg(feature = "shadowsocks")]
impl From<SsAddress> for ShadowsocksDestination {
    fn from(addr: SsAddress) -> Self {
        match addr {
            SsAddress::SocketAddress(sa) => Self::SocketAddr(sa),
            SsAddress::DomainNameAddress(domain, port) => Self::DomainName { domain, port },
        }
    }
}

#[cfg(feature = "shadowsocks")]
impl From<ShadowsocksDestination> for SsAddress {
    fn from(dest: ShadowsocksDestination) -> Self {
        match dest {
            ShadowsocksDestination::SocketAddr(addr) => SsAddress::SocketAddress(addr),
            ShadowsocksDestination::DomainName { domain, port } => {
                SsAddress::DomainNameAddress(domain, port)
            }
        }
    }
}

/// Statistics for a Shadowsocks connection
#[derive(Debug, Clone, Default)]
pub struct ConnectionStats {
    /// Bytes received from client
    pub bytes_received: u64,

    /// Bytes sent to client
    pub bytes_sent: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_destination_from_socket_addr() {
        let addr: SocketAddr = "192.168.1.1:443".parse().unwrap();
        let dest = ShadowsocksDestination::from_socket_addr(addr);

        assert_eq!(dest.port(), 443);
        assert_eq!(dest.host(), "192.168.1.1");
        assert_eq!(dest.as_socket_addr(), Some(addr));
        assert_eq!(dest.to_string(), "192.168.1.1:443");
    }

    #[test]
    fn test_destination_from_domain() {
        let dest = ShadowsocksDestination::from_domain("example.com", 443);

        assert_eq!(dest.port(), 443);
        assert_eq!(dest.host(), "example.com");
        assert!(dest.as_socket_addr().is_none());
        assert_eq!(dest.to_string(), "example.com:443");
    }

    #[test]
    fn test_connection_methods() {
        let stream: Cursor<Vec<u8>> = Cursor::new(vec![]);
        let dest = ShadowsocksDestination::from_domain("example.com", 443);
        let client_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();

        let conn = ShadowsocksConnection::new(stream, dest, client_addr);

        assert_eq!(conn.client_addr(), client_addr);
        assert_eq!(conn.destination().port(), 443);
        assert_eq!(conn.destination().to_string(), "example.com:443");
    }

    #[test]
    fn test_connection_into_stream() {
        let data = vec![1, 2, 3, 4, 5];
        let stream = Cursor::new(data.clone());
        let dest = ShadowsocksDestination::from_socket_addr("8.8.8.8:53".parse().unwrap());
        let client_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();

        let conn = ShadowsocksConnection::new(stream, dest, client_addr);
        let recovered_stream = conn.into_stream();

        assert_eq!(recovered_stream.into_inner(), data);
    }

    #[test]
    fn test_destination_serialization() {
        let dest = ShadowsocksDestination::from_domain("test.example.com", 8080);
        let json = serde_json::to_string(&dest).unwrap();

        assert!(json.contains("test.example.com"));
        assert!(json.contains("8080"));

        let deserialized: ShadowsocksDestination = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.to_string(), dest.to_string());
    }

    #[test]
    fn test_connection_stats() {
        let stats = ConnectionStats::default();
        assert_eq!(stats.bytes_received, 0);
        assert_eq!(stats.bytes_sent, 0);
    }
}
