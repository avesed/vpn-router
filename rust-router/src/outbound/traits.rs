//! Outbound trait definitions
//!
//! This module defines the core `Outbound` trait that all outbound types must implement.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::net::TcpStream;

use crate::connection::OutboundStats;
use crate::error::OutboundError;

/// Health status of an outbound
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthStatus {
    /// Outbound is healthy and accepting connections
    Healthy,
    /// Outbound is degraded (some failures)
    Degraded,
    /// Outbound is unhealthy (not accepting connections)
    Unhealthy,
    /// Health status is unknown
    Unknown,
}

impl HealthStatus {
    /// Check if the outbound is available for connections
    #[must_use]
    pub const fn is_available(&self) -> bool {
        matches!(self, Self::Healthy | Self::Degraded | Self::Unknown)
    }
}

impl std::fmt::Display for HealthStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Healthy => write!(f, "healthy"),
            Self::Degraded => write!(f, "degraded"),
            Self::Unhealthy => write!(f, "unhealthy"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

/// Represents an established outbound connection
pub struct OutboundConnection {
    /// The underlying TCP stream
    stream: TcpStream,
    /// Local address of the connection
    local_addr: Option<SocketAddr>,
    /// Remote address
    remote_addr: SocketAddr,
}

impl OutboundConnection {
    /// Create a new outbound connection
    pub fn new(stream: TcpStream, remote_addr: SocketAddr) -> Self {
        let local_addr = stream.local_addr().ok();
        Self {
            stream,
            local_addr,
            remote_addr,
        }
    }

    /// Get the underlying stream
    #[must_use]
    pub fn stream(&self) -> &TcpStream {
        &self.stream
    }

    /// Get mutable reference to the stream
    pub fn stream_mut(&mut self) -> &mut TcpStream {
        &mut self.stream
    }

    /// Consume and return the underlying stream
    #[must_use]
    pub fn into_stream(self) -> TcpStream {
        self.stream
    }

    /// Get the local address
    #[must_use]
    pub const fn local_addr(&self) -> Option<SocketAddr> {
        self.local_addr
    }

    /// Get the remote address
    #[must_use]
    pub const fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }
}

/// Core trait for outbound implementations
///
/// All outbound types (Direct, Block, SOCKS5, etc.) must implement this trait.
#[async_trait]
pub trait Outbound: Send + Sync {
    /// Connect to the target address through this outbound.
    ///
    /// # Arguments
    ///
    /// * `addr` - Target address to connect to
    /// * `timeout` - Connection timeout
    ///
    /// # Errors
    ///
    /// Returns `OutboundError` if the connection fails.
    async fn connect(
        &self,
        addr: SocketAddr,
        timeout: Duration,
    ) -> Result<OutboundConnection, OutboundError>;

    /// Get the unique tag for this outbound
    fn tag(&self) -> &str;

    /// Get the current health status
    fn health_status(&self) -> HealthStatus;

    /// Get connection statistics
    fn stats(&self) -> Arc<OutboundStats>;

    /// Check if this outbound is enabled
    fn is_enabled(&self) -> bool;

    /// Get the outbound type name
    fn outbound_type(&self) -> &str;
}

/// Extension trait for additional outbound functionality
pub trait OutboundExt: Outbound {
    /// Check if this outbound supports the given destination
    fn supports_destination(&self, _addr: SocketAddr) -> bool {
        true
    }

    /// Get the priority for load balancing (higher = preferred)
    fn priority(&self) -> u32 {
        100
    }
}

// Blanket implementation
impl<T: Outbound> OutboundExt for T {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_status() {
        assert!(HealthStatus::Healthy.is_available());
        assert!(HealthStatus::Degraded.is_available());
        assert!(!HealthStatus::Unhealthy.is_available());
        assert!(HealthStatus::Unknown.is_available());
    }

    #[test]
    fn test_health_status_display() {
        assert_eq!(HealthStatus::Healthy.to_string(), "healthy");
        assert_eq!(HealthStatus::Unhealthy.to_string(), "unhealthy");
    }

    #[tokio::test]
    async fn test_outbound_connection() {
        // Create a simple connection for testing
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let connect_task = tokio::spawn(async move { TcpStream::connect(addr).await });

        let (server, _) = listener.accept().await.unwrap();
        let client = connect_task.await.unwrap().unwrap();

        let conn = OutboundConnection::new(client, addr);
        assert_eq!(conn.remote_addr(), addr);
        assert!(conn.local_addr().is_some());

        drop(server);
    }
}
