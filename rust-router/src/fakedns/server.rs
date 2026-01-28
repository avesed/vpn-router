//! FakeDNS server
//!
//! This module provides a DNS server that returns fake IP addresses for domain names,
//! enabling transparent domain-based routing.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::task::JoinHandle;
use tracing::info;

use super::config::FakeDnsConfig;
use super::manager::FakeDnsManager;
use super::tcp_server::FakeDnsTcpServer;
use super::udp_server::FakeDnsUdpServer;

/// Builder for creating a FakeDNS server
pub struct FakeDnsBuilder {
    config: FakeDnsConfig,
    listen_addr: SocketAddr,
    enable_tcp: bool,
    enable_udp: bool,
}

impl FakeDnsBuilder {
    /// Create a new FakeDNS builder with the given listen address
    #[must_use]
    pub fn new(listen_addr: SocketAddr) -> Self {
        Self {
            config: FakeDnsConfig::default(),
            listen_addr,
            enable_tcp: true,
            enable_udp: true,
        }
    }

    /// Set the FakeDNS configuration
    #[must_use]
    pub fn config(mut self, config: FakeDnsConfig) -> Self {
        self.config = config;
        self
    }

    /// Enable only TCP server
    #[must_use]
    pub fn tcp_only(mut self) -> Self {
        self.enable_tcp = true;
        self.enable_udp = false;
        self
    }

    /// Enable only UDP server
    #[must_use]
    pub fn udp_only(mut self) -> Self {
        self.enable_tcp = false;
        self.enable_udp = true;
        self
    }

    /// Enable both TCP and UDP servers (default)
    #[must_use]
    pub fn tcp_and_udp(mut self) -> Self {
        self.enable_tcp = true;
        self.enable_udp = true;
        self
    }

    /// Build the FakeDNS server
    ///
    /// # Errors
    /// Returns an error if binding to the listen address fails.
    pub async fn build(self) -> io::Result<FakeDns> {
        let manager = Arc::new(FakeDnsManager::new(&self.config));

        let tcp_server = if self.enable_tcp {
            Some(FakeDnsTcpServer::bind(self.listen_addr, manager.clone()).await?)
        } else {
            None
        };

        let udp_server = if self.enable_udp {
            Some(FakeDnsUdpServer::bind(self.listen_addr, manager.clone()).await?)
        } else {
            None
        };

        Ok(FakeDns {
            tcp_server,
            udp_server,
            manager,
            config: self.config,
        })
    }
}

/// FakeDNS server instance
///
/// Provides both TCP and UDP DNS servers that return fake IP addresses
/// for domain names, enabling transparent domain-based routing.
pub struct FakeDns {
    tcp_server: Option<FakeDnsTcpServer>,
    udp_server: Option<FakeDnsUdpServer>,
    manager: Arc<FakeDnsManager>,
    config: FakeDnsConfig,
}

impl FakeDns {
    /// Create a new FakeDNS builder
    #[must_use]
    pub fn builder(listen_addr: SocketAddr) -> FakeDnsBuilder {
        FakeDnsBuilder::new(listen_addr)
    }

    /// Get the FakeDNS manager
    #[must_use]
    pub fn manager(&self) -> &Arc<FakeDnsManager> {
        &self.manager
    }

    /// Get the FakeDNS configuration
    #[must_use]
    pub fn config(&self) -> &FakeDnsConfig {
        &self.config
    }

    /// Get the TCP server local address (if enabled)
    pub fn tcp_local_addr(&self) -> Option<io::Result<SocketAddr>> {
        self.tcp_server.as_ref().map(FakeDnsTcpServer::local_addr)
    }

    /// Get the UDP server local address (if enabled)
    pub fn udp_local_addr(&self) -> Option<io::Result<SocketAddr>> {
        self.udp_server.as_ref().map(FakeDnsUdpServer::local_addr)
    }

    /// Run the FakeDNS server
    ///
    /// This method runs both TCP and UDP servers (if enabled) until one of them
    /// returns an error or the server is shut down.
    ///
    /// # Errors
    /// Returns an error if any of the servers fail.
    pub async fn run(self) -> io::Result<()> {
        let mut handles: Vec<JoinHandle<io::Result<()>>> = Vec::new();

        if let Some(tcp) = self.tcp_server {
            if let Ok(addr) = tcp.local_addr() {
                info!("FakeDNS TCP server listening on {}", addr);
            }
            handles.push(tokio::spawn(tcp.run()));
        }

        if let Some(udp) = self.udp_server {
            if let Ok(addr) = udp.local_addr() {
                info!("FakeDNS UDP server listening on {}", addr);
            }
            handles.push(tokio::spawn(udp.run()));
        }

        if handles.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "No servers enabled",
            ));
        }

        // Wait for any task to complete (usually means an error)
        let (result, _, _) = futures::future::select_all(handles).await;
        result.map_err(|e| io::Error::other(e))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn test_config() -> FakeDnsConfig {
        FakeDnsConfig::new()
            .with_ipv4_pool("10.0.0.0/24".parse().unwrap())
            .with_max_entries(1000)
            .with_ttl(Duration::from_secs(60))
    }

    #[tokio::test]
    async fn test_builder_creation() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let builder = FakeDns::builder(addr).config(test_config());
        let fakedns = builder.build().await.unwrap();

        assert!(fakedns.tcp_local_addr().is_some());
        assert!(fakedns.udp_local_addr().is_some());
    }

    #[tokio::test]
    async fn test_tcp_only() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let fakedns = FakeDns::builder(addr)
            .config(test_config())
            .tcp_only()
            .build()
            .await
            .unwrap();

        assert!(fakedns.tcp_local_addr().is_some());
        assert!(fakedns.udp_local_addr().is_none());
    }

    #[tokio::test]
    async fn test_udp_only() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let fakedns = FakeDns::builder(addr)
            .config(test_config())
            .udp_only()
            .build()
            .await
            .unwrap();

        assert!(fakedns.tcp_local_addr().is_none());
        assert!(fakedns.udp_local_addr().is_some());
    }

    #[tokio::test]
    async fn test_manager_access() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let fakedns = FakeDns::builder(addr)
            .config(test_config())
            .build()
            .await
            .unwrap();

        // Should be able to use the manager
        let manager = fakedns.manager();
        let (ip, _) = manager.map_domain_ipv4("example.com").unwrap();
        assert!(manager.is_fake_ip(std::net::IpAddr::V4(ip)));
    }
}
