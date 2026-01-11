//! TPROXY TCP Listener
//!
//! This module provides a high-level listener for accepting TPROXY-redirected
//! TCP connections with automatic original destination retrieval.

use std::net::SocketAddr;
use std::os::unix::io::{FromRawFd, IntoRawFd};

use tokio::net::TcpListener;
use tracing::{debug, info};

use super::connection::TproxyConnection;
use super::socket::create_tproxy_tcp_socket;
use crate::config::ListenConfig;
use crate::error::TproxyError;

/// A TPROXY TCP listener that accepts connections with original destination info
#[derive(Debug)]
pub struct TproxyListener {
    /// The underlying tokio TCP listener
    listener: TcpListener,

    /// Listen address
    listen_addr: SocketAddr,

    /// Whether the listener is active
    active: bool,
}

impl TproxyListener {
    /// Create and bind a new TPROXY listener.
    ///
    /// This creates a TCP socket with `IP_TRANSPARENT` enabled and binds it
    /// to the specified address.
    ///
    /// # Arguments
    ///
    /// * `config` - Listen configuration
    ///
    /// # Errors
    ///
    /// Returns `TproxyError` if:
    /// - Socket creation fails
    /// - Binding fails
    /// - `CAP_NET_ADMIN` capability is missing
    pub fn bind(config: &ListenConfig) -> Result<Self, TproxyError> {
        info!("Creating TPROXY TCP listener on {}", config.address);

        // Create the TPROXY socket
        let socket = create_tproxy_tcp_socket()?;

        // Bind to the listen address
        socket.bind(&config.address.into()).map_err(|e| {
            TproxyError::BindError {
                addr: config.address,
                reason: e.to_string(),
            }
        })?;

        // Start listening with the configured backlog
        socket
            .listen(config.tcp_backlog as i32)
            .map_err(|e| TproxyError::socket_option("listen", e.to_string()))?;

        // Convert to tokio TcpListener
        // Safety: We own the socket and it's a valid listening socket
        let std_listener =
            unsafe { std::net::TcpListener::from_raw_fd(socket.into_raw_fd()) };

        let listener = TcpListener::from_std(std_listener)
            .map_err(|e| TproxyError::SocketCreation(e.to_string()))?;

        info!(
            "TPROXY TCP listener ready on {} (backlog={})",
            config.address, config.tcp_backlog
        );

        Ok(Self {
            listener,
            listen_addr: config.address,
            active: true,
        })
    }

    /// Accept a new TPROXY connection.
    ///
    /// This waits for a new connection and retrieves its original destination
    /// using `SO_ORIGINAL_DST`.
    ///
    /// # Errors
    ///
    /// Returns `TproxyError` if:
    /// - Accept fails
    /// - Original destination retrieval fails
    /// - Listener is not active
    pub async fn accept(&self) -> Result<TproxyConnection, TproxyError> {
        if !self.active {
            return Err(TproxyError::NotReady);
        }

        let (stream, client_addr) = self
            .listener
            .accept()
            .await
            .map_err(|e| TproxyError::AcceptError(e.to_string()))?;

        debug!("Accepted connection from {}", client_addr);

        // Create TproxyConnection which retrieves original destination
        TproxyConnection::new(stream, client_addr)
    }

    /// Get the listen address.
    #[must_use]
    pub const fn listen_addr(&self) -> SocketAddr {
        self.listen_addr
    }

    /// Check if the listener is active.
    #[must_use]
    pub const fn is_active(&self) -> bool {
        self.active
    }

    /// Deactivate the listener (stop accepting new connections).
    pub fn deactivate(&mut self) {
        if self.active {
            info!("Deactivating TPROXY listener on {}", self.listen_addr);
            self.active = false;
        }
    }

    /// Reactivate the listener.
    pub fn reactivate(&mut self) {
        if !self.active {
            info!("Reactivating TPROXY listener on {}", self.listen_addr);
            self.active = true;
        }
    }

    /// Get a reference to the underlying tokio `TcpListener`.
    ///
    /// This can be used for advanced operations like `poll_accept`.
    #[must_use]
    pub const fn inner(&self) -> &TcpListener {
        &self.listener
    }
}

/// Builder for creating a TPROXY listener with custom options
#[derive(Debug)]
pub struct TproxyListenerBuilder {
    address: SocketAddr,
    backlog: u32,
    reuse_port: bool,
}

impl TproxyListenerBuilder {
    /// Create a new builder with the given listen address.
    #[must_use]
    pub fn new(address: SocketAddr) -> Self {
        Self {
            address,
            backlog: 1024,
            reuse_port: true,
        }
    }

    /// Set the TCP backlog.
    #[must_use]
    pub const fn backlog(mut self, backlog: u32) -> Self {
        self.backlog = backlog;
        self
    }

    /// Set whether to use `SO_REUSEPORT`.
    #[must_use]
    pub const fn reuse_port(mut self, reuse: bool) -> Self {
        self.reuse_port = reuse;
        self
    }

    /// Build the listener.
    ///
    /// # Errors
    ///
    /// Returns `TproxyError` if listener creation fails.
    pub fn build(self) -> Result<TproxyListener, TproxyError> {
        let config = ListenConfig {
            address: self.address,
            tcp_enabled: true,
            udp_enabled: false,
            tcp_backlog: self.backlog,
            udp_timeout_secs: 300,
            reuse_port: self.reuse_port,
            sniff_timeout_ms: 300,
            udp_workers: None,
            udp_buffer_pool_size: 1024,
        };

        TproxyListener::bind(&config)
    }
}

impl Default for TproxyListenerBuilder {
    fn default() -> Self {
        Self::new("127.0.0.1:7893".parse().unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder() {
        let builder = TproxyListenerBuilder::new("127.0.0.1:8080".parse().unwrap())
            .backlog(512)
            .reuse_port(true);

        assert_eq!(builder.address, "127.0.0.1:8080".parse().unwrap());
        assert_eq!(builder.backlog, 512);
        assert!(builder.reuse_port);
    }

    #[test]
    fn test_default_builder() {
        let builder = TproxyListenerBuilder::default();
        assert_eq!(builder.address, "127.0.0.1:7893".parse().unwrap());
        assert_eq!(builder.backlog, 1024);
    }

    // Note: Actual listener tests require CAP_NET_ADMIN and iptables setup
    // Integration tests should be run in a container with proper setup
}
