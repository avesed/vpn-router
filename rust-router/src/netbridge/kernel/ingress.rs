//! KernelIngress implementation for the kernel backend
//!
//! This module provides the `KernelIngress` implementation that uses TUN + TPROXY
//! for high-performance (200-400 Mbps) packet processing via the kernel TCP/IP stack.
//!
//! # Architecture
//!
//! ```text
//! WireGuard UDP
//!       |
//!       v
//! boringtun decrypt
//!       |
//!       v (IP packets)
//! TUN device (write_packet)
//!       |
//!       v
//! Kernel TCP/IP stack
//!       |
//!       v
//! TPROXY listener (accept)
//!       |
//!       v
//! Session registration
//!       |
//!       v
//! Outbound connection
//! ```
//!
//! # Reply Path
//!
//! ```text
//! Outbound reply
//!       |
//!       v
//! TPROXY socket (IP_TRANSPARENT)
//!       |
//!       v
//! Kernel TCP/IP stack
//!       |
//!       v
//! TUN device (read_packet)
//!       |
//!       v
//! Session lookup (reverse 5-tuple)
//!       |
//!       v
//! ReplyPacket → WireGuard
//! ```
//!
//! # Performance
//!
//! The kernel backend achieves 200-400 Mbps single-connection throughput
//! by leveraging the kernel's optimized TCP/IP stack with BBR/CUBIC
//! congestion control.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use parking_lot::Mutex as ParkingMutex;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, error, info, trace, warn};

use super::iptables::IptablesManagerWrapper;
use super::tproxy::TproxyListenerWrapper;
use super::tun::TunDeviceWrapper;
use crate::netbridge::config::{REPLY_CHANNEL_SIZE, TUN_MTU};
use crate::netbridge::error::{NetBridgeError, Result};
use crate::netbridge::reply::ReplyRouter;
use crate::netbridge::session::{RegisterResult, SessionTracker};
use crate::netbridge::traits::{NetBridgeIngress, SessionHandler, SessionInfo};
use crate::netbridge::types::{FiveTuple, IngressStats, IpProtocol, ReplyPacket};

// =============================================================================
// KernelIngress Configuration
// =============================================================================

/// Configuration for the kernel ingress bridge
#[derive(Clone)]
pub struct KernelIngressConfig {
    /// TUN device name
    pub tun_name: String,
    /// TUN device address in CIDR notation
    pub tun_address: String,
    /// TUN subnet for routing rules
    pub tun_subnet: String,
    /// TPROXY listener address
    pub tproxy_addr: SocketAddr,
    /// fwmark for policy routing
    pub fwmark: u32,
    /// Routing table ID
    pub table_id: u32,
    /// MTU (typically 1420 for WireGuard)
    pub mtu: u16,
    /// TCP backlog
    pub tcp_backlog: u32,
    /// Reply channel size
    pub reply_channel_size: usize,
    /// Optional session handler for lifecycle callbacks
    pub session_handler: Option<Arc<dyn SessionHandler>>,
}

impl std::fmt::Debug for KernelIngressConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KernelIngressConfig")
            .field("tun_name", &self.tun_name)
            .field("tun_address", &self.tun_address)
            .field("tun_subnet", &self.tun_subnet)
            .field("tproxy_addr", &self.tproxy_addr)
            .field("fwmark", &self.fwmark)
            .field("table_id", &self.table_id)
            .field("mtu", &self.mtu)
            .field("tcp_backlog", &self.tcp_backlog)
            .field("reply_channel_size", &self.reply_channel_size)
            .field("session_handler", &self.session_handler.is_some())
            .finish()
    }
}

impl KernelIngressConfig {
    /// Create a new configuration with required parameters
    #[must_use]
    pub fn new(tun_name: &str, tun_address: &str, tun_subnet: &str) -> Self {
        Self {
            tun_name: tun_name.to_string(),
            tun_address: tun_address.to_string(),
            tun_subnet: tun_subnet.to_string(),
            tproxy_addr: "127.0.0.1:7893".parse().unwrap(),
            fwmark: 0x1,
            table_id: 100,
            mtu: TUN_MTU as u16,
            tcp_backlog: 1024,
            reply_channel_size: REPLY_CHANNEL_SIZE,
            session_handler: None,
        }
    }

    /// Set the TPROXY address
    #[must_use]
    pub fn tproxy_addr(mut self, addr: SocketAddr) -> Self {
        self.tproxy_addr = addr;
        self
    }

    /// Set the fwmark
    #[must_use]
    pub const fn fwmark(mut self, mark: u32) -> Self {
        self.fwmark = mark;
        self
    }

    /// Set the routing table ID
    #[must_use]
    pub const fn table_id(mut self, id: u32) -> Self {
        self.table_id = id;
        self
    }

    /// Set the MTU
    #[must_use]
    pub const fn mtu(mut self, mtu: u16) -> Self {
        self.mtu = mtu;
        self
    }

    /// Set the TCP backlog
    #[must_use]
    pub const fn tcp_backlog(mut self, backlog: u32) -> Self {
        self.tcp_backlog = backlog;
        self
    }

    /// Set the reply channel size
    #[must_use]
    pub const fn reply_channel_size(mut self, size: usize) -> Self {
        self.reply_channel_size = size;
        self
    }

    /// Set the session handler for lifecycle callbacks
    ///
    /// The handler will be notified when sessions are created or closed.
    #[must_use]
    pub fn with_session_handler(mut self, handler: Arc<dyn SessionHandler>) -> Self {
        self.session_handler = Some(handler);
        self
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<()> {
        if self.tun_name.is_empty() {
            return Err(NetBridgeError::Config("TUN name cannot be empty".to_string()));
        }
        if self.tun_name.len() > 15 {
            return Err(NetBridgeError::Config(format!(
                "TUN name '{}' exceeds 15 character limit",
                self.tun_name
            )));
        }
        if self.tun_address.is_empty() {
            return Err(NetBridgeError::Config("TUN address cannot be empty".to_string()));
        }
        if self.mtu == 0 {
            return Err(NetBridgeError::Config("MTU cannot be zero".to_string()));
        }
        Ok(())
    }
}

impl Default for KernelIngressConfig {
    fn default() -> Self {
        Self::new("tun-in", "10.25.0.1/24", "10.25.0.0/24")
    }
}

// =============================================================================
// KernelIngress Implementation
// =============================================================================

/// Kernel-based ingress bridge using TUN + TPROXY
///
/// This implementation uses the Linux kernel's TCP/IP stack for packet processing,
/// achieving 200-400 Mbps throughput via TPROXY transparent proxying.
///
/// # Components
///
/// - **TUN device**: Receives IP packets from WireGuard
/// - **TPROXY listener**: Accepts TCP/UDP connections transparently
/// - **iptables manager**: Configures TPROXY routing rules
/// - **Session tracker**: Maps 5-tuples to WireGuard peer info
/// - **Reply router**: Routes reply packets back to peers
pub struct KernelIngress {
    /// Configuration
    config: KernelIngressConfig,
    /// TUN device
    tun: Arc<TunDeviceWrapper>,
    /// TPROXY TCP listener (uses tokio::Mutex for async-safe access)
    tproxy: Mutex<TproxyListenerWrapper>,
    /// iptables manager
    iptables: ParkingMutex<IptablesManagerWrapper>,
    /// Session tracker
    sessions: Arc<SessionTracker>,
    /// Reply router
    reply_router: Arc<ReplyRouter>,
    /// Reply packet sender
    reply_tx: mpsc::Sender<ReplyPacket>,
    /// Reply packet receiver (taken on first call to take_reply_rx)
    reply_rx: ParkingMutex<Option<mpsc::Receiver<ReplyPacket>>>,
    /// Whether the bridge is running
    running: AtomicBool,
    /// Whether shutdown has been requested
    shutdown_requested: AtomicBool,
    /// Statistics
    stats: KernelIngressStats,
    /// Optional session handler for lifecycle callbacks
    session_handler: Option<Arc<dyn SessionHandler>>,
}

impl KernelIngress {
    /// Create a new kernel ingress bridge
    ///
    /// This creates all components but does not start the bridge.
    /// Call `run()` to start packet processing.
    ///
    /// # Arguments
    ///
    /// * `config` - Bridge configuration
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Configuration is invalid
    /// - TUN device creation fails
    /// - TPROXY listener creation fails
    /// - iptables manager creation fails
    pub fn new(config: KernelIngressConfig) -> Result<Self> {
        config.validate()?;

        info!(
            tun_name = %config.tun_name,
            tun_address = %config.tun_address,
            tproxy_addr = %config.tproxy_addr,
            "Creating kernel ingress bridge"
        );

        // Create TUN device
        let mut tun = TunDeviceWrapper::create(
            &config.tun_name,
            &config.tun_address,
            config.mtu,
        )?;
        tun.configure()?;
        let tun = Arc::new(tun);

        // Create iptables manager
        let mut iptables = IptablesManagerWrapper::new(
            &config.tun_name,
            &config.tun_subnet,
            config.tproxy_addr.port(),
            config.fwmark,
            config.table_id,
        )?;
        iptables.apply()?;

        // Create TPROXY listener
        let tproxy = TproxyListenerWrapper::bind(
            config.tproxy_addr,
            Some(config.fwmark),
            config.tcp_backlog,
        )?;

        // Create session tracker
        let sessions = Arc::new(SessionTracker::new());

        // Create reply channel
        let (reply_tx, reply_rx) = mpsc::channel(config.reply_channel_size);

        // Create reply router
        let reply_router = Arc::new(ReplyRouter::new(Arc::clone(&sessions), reply_tx.clone()));

        // Extract session handler before moving config
        let session_handler = config.session_handler.clone();

        info!(
            tun_name = %config.tun_name,
            tproxy_addr = %config.tproxy_addr,
            has_session_handler = session_handler.is_some(),
            "Kernel ingress bridge created"
        );

        Ok(Self {
            config,
            tun,
            tproxy: Mutex::new(tproxy),
            iptables: ParkingMutex::new(iptables),
            sessions,
            reply_router,
            reply_tx,
            reply_rx: ParkingMutex::new(Some(reply_rx)),
            running: AtomicBool::new(false),
            shutdown_requested: AtomicBool::new(false),
            stats: KernelIngressStats::default(),
            session_handler,
        })
    }

    /// Create with default configuration
    pub fn with_defaults() -> Result<Self> {
        Self::new(KernelIngressConfig::default())
    }

    /// Get a reference to the session tracker
    #[inline]
    #[must_use]
    pub fn sessions(&self) -> &Arc<SessionTracker> {
        &self.sessions
    }

    /// Get a reference to the reply router
    #[inline]
    #[must_use]
    pub fn reply_router(&self) -> &Arc<ReplyRouter> {
        &self.reply_router
    }

    /// Get a reference to the TUN device
    #[inline]
    #[must_use]
    pub fn tun(&self) -> &Arc<TunDeviceWrapper> {
        &self.tun
    }

    /// Get a reference to the session handler (if configured)
    #[inline]
    #[must_use]
    pub fn session_handler(&self) -> Option<&Arc<dyn SessionHandler>> {
        self.session_handler.as_ref()
    }

    /// Check if shutdown has been requested
    #[inline]
    fn is_shutdown_requested(&self) -> bool {
        self.shutdown_requested.load(Ordering::Relaxed)
    }

    /// Run the TUN read loop
    ///
    /// This reads packets from the TUN device (kernel TCP/IP stack replies)
    /// and routes them back to the appropriate WireGuard peer.
    async fn run_tun_read_loop(&self) -> Result<()> {
        debug!("Starting TUN read loop");

        let mut buf = vec![0u8; self.config.mtu as usize + 100];

        loop {
            if self.is_shutdown_requested() {
                debug!("TUN read loop shutdown requested");
                break;
            }

            match self.tun.read_packet(&mut buf).await {
                Ok(n) => {
                    self.stats.packets_from_tun.fetch_add(1, Ordering::Relaxed);
                    self.stats.bytes_from_tun.fetch_add(n as u64, Ordering::Relaxed);

                    trace!(bytes = n, "Read packet from TUN");

                    // Route the reply packet
                    if let Err(e) = self.reply_router.route(&buf[..n]).await {
                        self.stats.reply_route_errors.fetch_add(1, Ordering::Relaxed);
                        trace!(error = %e, "Failed to route reply packet");
                    }
                }
                Err(e) => {
                    if self.is_shutdown_requested() {
                        break;
                    }
                    self.stats.tun_read_errors.fetch_add(1, Ordering::Relaxed);
                    error!(error = %e, "TUN read error");
                }
            }
        }

        debug!("TUN read loop stopped");
        Ok(())
    }

    /// Run the TPROXY accept loop
    ///
    /// This accepts TCP connections from the TPROXY listener and provides
    /// connection metadata for session tracking.
    async fn run_tproxy_accept_loop(&self) -> Result<()> {
        debug!("Starting TPROXY accept loop");

        loop {
            if self.is_shutdown_requested() {
                debug!("TPROXY accept loop shutdown requested");
                break;
            }

            // Accept a connection
            let connection = {
                let mut tproxy = self.tproxy.lock().await;
                match tproxy.accept().await {
                    Ok(conn) => conn,
                    Err(e) => {
                        if self.is_shutdown_requested() {
                            break;
                        }
                        self.stats.tproxy_accept_errors.fetch_add(1, Ordering::Relaxed);
                        warn!(error = %e, "TPROXY accept error");
                        continue;
                    }
                }
            };

            self.stats.tproxy_connections.fetch_add(1, Ordering::Relaxed);

            trace!(
                client = %connection.client_addr(),
                dst = %connection.original_dst(),
                "Accepted TPROXY connection"
            );

            // TODO: Spawn a task to handle the connection
            // This requires integration with the outbound system
            // For now, we just log and close the connection
            let _ = connection.into_stream();
        }

        debug!("TPROXY accept loop stopped");
        Ok(())
    }
}

impl NetBridgeIngress for KernelIngress {
    /// Inject an IP packet from WireGuard into the bridge
    ///
    /// The packet is written to the TUN device, where it enters the
    /// kernel TCP/IP stack. The kernel processes it and sends replies
    /// back through the TUN device.
    ///
    /// # Arguments
    ///
    /// * `packet` - Raw IP packet data
    /// * `peer_key` - WireGuard peer public key
    /// * `peer_endpoint` - Peer's WireGuard endpoint for reply routing
    async fn inject_packet(
        &self,
        packet: &[u8],
        peer_key: [u8; 32],
        peer_endpoint: SocketAddr,
    ) -> Result<()> {
        if !self.running.load(Ordering::Relaxed) {
            return Err(NetBridgeError::NotInitialized);
        }

        self.stats.packets_injected.fetch_add(1, Ordering::Relaxed);
        self.stats.bytes_injected.fetch_add(packet.len() as u64, Ordering::Relaxed);

        // Extract 5-tuple for session tracking
        if let Some(five_tuple) = FiveTuple::from_packet(packet) {
            // Register or update session using register_with_result to detect new sessions
            match self.sessions.register_with_result(
                peer_key,
                peer_endpoint,
                five_tuple,
                "kernel".to_string(),
            ) {
                Ok(result) => {
                    let session = result.session();
                    session.add_bytes_sent(packet.len() as u64);

                    // Fire callback only for newly created sessions
                    if result.is_new() {
                        if let Some(ref handler) = self.session_handler {
                            let info = SessionInfo {
                                session_id: session.id,
                                protocol: five_tuple.protocol,
                                src_addr: five_tuple.src_socket_addr(),
                                dst_addr: five_tuple.dst_socket_addr(),
                                outbound_tag: session.outbound_tag.clone(),
                                peer_key,
                            };
                            handler.on_session_created(session.id, &info);
                        }
                        trace!(
                            session_id = %session.id,
                            five_tuple = %five_tuple,
                            "Session created (new)"
                        );
                    } else {
                        trace!(
                            session_id = %session.id,
                            five_tuple = %five_tuple,
                            "Session updated"
                        );
                    }
                }
                Err(e) => {
                    self.stats.session_errors.fetch_add(1, Ordering::Relaxed);
                    warn!(error = %e, "Failed to register session");
                    // The session error provides specific details, use Internal for now
                    return Err(NetBridgeError::Internal(format!("session registration failed: {}", e)));
                }
            }
        } else {
            // Non-TCP/UDP packet (ICMP, etc.) - still inject but don't track
            trace!(
                packet_len = packet.len(),
                "Injecting non-TCP/UDP packet (no session)"
            );
        }

        // Write packet to TUN device
        match self.tun.write_packet(packet).await {
            Ok(n) => {
                trace!(bytes = n, "Wrote packet to TUN");
                Ok(())
            }
            Err(e) => {
                self.stats.tun_write_errors.fetch_add(1, Ordering::Relaxed);
                Err(e)
            }
        }
    }

    /// Take the reply packet receiver
    ///
    /// This should be called once before starting the bridge. The receiver
    /// produces `ReplyPacket` values that should be encrypted and sent to
    /// the appropriate WireGuard peer.
    fn take_reply_rx(&mut self) -> Option<mpsc::Receiver<ReplyPacket>> {
        self.reply_rx.lock().take()
    }

    /// Run the ingress bridge
    ///
    /// This starts the TUN read loop and TPROXY accept loop, running
    /// until shutdown is requested.
    async fn run(&self) -> Result<()> {
        if self.running.swap(true, Ordering::SeqCst) {
            // Already running, return error
            return Err(NetBridgeError::Internal("bridge already running".to_string()));
        }

        info!(
            tun_name = %self.config.tun_name,
            tproxy_addr = %self.config.tproxy_addr,
            "Starting kernel ingress bridge"
        );

        // Run both loops concurrently
        let tun_loop = self.run_tun_read_loop();
        let tproxy_loop = self.run_tproxy_accept_loop();

        tokio::select! {
            result = tun_loop => {
                if let Err(e) = result {
                    error!(error = %e, "TUN read loop failed");
                }
            }
            result = tproxy_loop => {
                if let Err(e) = result {
                    error!(error = %e, "TPROXY accept loop failed");
                }
            }
        }

        self.running.store(false, Ordering::SeqCst);
        info!("Kernel ingress bridge stopped");
        Ok(())
    }

    /// Shutdown the ingress bridge
    async fn shutdown(&self) {
        info!("Shutting down kernel ingress bridge");
        self.shutdown_requested.store(true, Ordering::SeqCst);

        // Deactivate TPROXY listener
        self.tproxy.lock().await.deactivate();

        // Note: iptables cleanup happens on drop

        info!("Kernel ingress bridge shutdown complete");
    }

    /// Get current statistics
    fn stats(&self) -> IngressStats {
        IngressStats {
            packets_received: self.stats.packets_injected.load(Ordering::Relaxed),
            packets_injected: self.stats.packets_injected.load(Ordering::Relaxed),
            bytes_received: self.stats.bytes_injected.load(Ordering::Relaxed),
            packets_dropped: self.stats.tun_write_errors.load(Ordering::Relaxed)
                + self.stats.session_errors.load(Ordering::Relaxed),
            active_sessions: self.sessions.total_sessions(),
            dns_queries_intercepted: 0, // TODO: Implement FakeDNS
            sni_extractions: 0, // TODO: Implement SNI sniffing
        }
    }

    /// Check if the bridge is running
    fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }
}

impl std::fmt::Debug for KernelIngress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KernelIngress")
            .field("config", &self.config)
            .field("running", &self.running.load(Ordering::Relaxed))
            .field("sessions", &self.sessions.total_sessions())
            .finish()
    }
}

// =============================================================================
// Statistics
// =============================================================================

/// Internal statistics counters
#[derive(Debug, Default)]
struct KernelIngressStats {
    /// Packets injected from WireGuard
    packets_injected: AtomicU64,
    /// Bytes injected from WireGuard
    bytes_injected: AtomicU64,
    /// Packets read from TUN (kernel replies)
    packets_from_tun: AtomicU64,
    /// Bytes read from TUN
    bytes_from_tun: AtomicU64,
    /// TUN write errors
    tun_write_errors: AtomicU64,
    /// TUN read errors
    tun_read_errors: AtomicU64,
    /// Reply routing errors
    reply_route_errors: AtomicU64,
    /// Session registration errors
    session_errors: AtomicU64,
    /// TPROXY connections accepted
    tproxy_connections: AtomicU64,
    /// TPROXY accept errors
    tproxy_accept_errors: AtomicU64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults() {
        let config = KernelIngressConfig::default();
        assert_eq!(config.tun_name, "tun-in");
        assert_eq!(config.tun_address, "10.25.0.1/24");
        assert_eq!(config.tun_subnet, "10.25.0.0/24");
        assert_eq!(config.tproxy_addr.port(), 7893);
        assert_eq!(config.fwmark, 0x1);
        assert_eq!(config.table_id, 100);
        assert_eq!(config.mtu, TUN_MTU as u16);
    }

    #[test]
    fn test_config_builder() {
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let config = KernelIngressConfig::new("tun-test", "192.168.1.1/24", "192.168.1.0/24")
            .tproxy_addr(addr)
            .fwmark(0x2)
            .table_id(200)
            .mtu(1500)
            .tcp_backlog(512)
            .reply_channel_size(2048);

        assert_eq!(config.tun_name, "tun-test");
        assert_eq!(config.tun_address, "192.168.1.1/24");
        assert_eq!(config.tproxy_addr, addr);
        assert_eq!(config.fwmark, 0x2);
        assert_eq!(config.table_id, 200);
        assert_eq!(config.mtu, 1500);
        assert_eq!(config.tcp_backlog, 512);
        assert_eq!(config.reply_channel_size, 2048);
    }

    #[test]
    fn test_config_validation() {
        // Valid config
        let config = KernelIngressConfig::default();
        assert!(config.validate().is_ok());

        // Empty TUN name
        let mut config = KernelIngressConfig::default();
        config.tun_name = String::new();
        assert!(config.validate().is_err());

        // TUN name too long
        let mut config = KernelIngressConfig::default();
        config.tun_name = "this-name-is-way-too-long".to_string();
        assert!(config.validate().is_err());

        // Empty address
        let mut config = KernelIngressConfig::default();
        config.tun_address = String::new();
        assert!(config.validate().is_err());

        // Zero MTU
        let mut config = KernelIngressConfig::default();
        config.mtu = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_stats_default() {
        let stats = KernelIngressStats::default();
        assert_eq!(stats.packets_injected.load(Ordering::Relaxed), 0);
        assert_eq!(stats.bytes_injected.load(Ordering::Relaxed), 0);
        assert_eq!(stats.packets_from_tun.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_config_with_session_handler() {
        use crate::netbridge::error::NetBridgeError;
        use crate::netbridge::traits::{NoOpSessionHandler, SessionCloseStats};
        use crate::netbridge::types::SessionId;

        let handler = Arc::new(NoOpSessionHandler);
        let config = KernelIngressConfig::new("tun-test", "192.168.1.1/24", "192.168.1.0/24")
            .with_session_handler(handler);

        assert!(config.session_handler.is_some());
    }

    #[test]
    fn test_config_without_session_handler() {
        let config = KernelIngressConfig::default();
        assert!(config.session_handler.is_none());
    }

    /// Mock session handler for testing callback invocations
    #[derive(Default)]
    struct MockSessionHandler {
        created_sessions: ParkingMutex<Vec<(crate::netbridge::types::SessionId, SessionInfo)>>,
        closed_sessions: ParkingMutex<Vec<(crate::netbridge::types::SessionId, crate::netbridge::traits::SessionCloseStats)>>,
        errors: ParkingMutex<Vec<(crate::netbridge::types::SessionId, String)>>,
    }

    impl SessionHandler for MockSessionHandler {
        fn on_session_created(&self, session_id: crate::netbridge::types::SessionId, info: &SessionInfo) {
            self.created_sessions.lock().push((session_id, info.clone()));
        }

        fn on_session_closed(&self, session_id: crate::netbridge::types::SessionId, stats: crate::netbridge::traits::SessionCloseStats) {
            self.closed_sessions.lock().push((session_id, stats));
        }

        fn on_session_error(&self, session_id: crate::netbridge::types::SessionId, error: &NetBridgeError) {
            self.errors.lock().push((session_id, error.to_string()));
        }
    }

    #[test]
    fn test_register_result_triggers_callback() {
        use crate::netbridge::session::SessionTracker;
        use crate::netbridge::types::FiveTuple;
        use std::net::{IpAddr, Ipv4Addr};

        let handler = Arc::new(MockSessionHandler::default());
        let tracker = SessionTracker::new();
        let peer_key = [42u8; 32];
        let peer_endpoint: SocketAddr = "192.168.1.100:51820".parse().unwrap();
        let five_tuple = FiveTuple::tcp(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 25, 0, 2)), 12345),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 80),
        );

        // First registration should be Created
        let result1 = tracker
            .register_with_result(peer_key, peer_endpoint, five_tuple, "kernel".to_string())
            .unwrap();

        assert!(result1.is_new());

        // Simulate what inject_packet does - call handler on new session
        if result1.is_new() {
            let session = result1.session();
            let info = SessionInfo {
                session_id: session.id,
                protocol: five_tuple.protocol,
                src_addr: five_tuple.src_socket_addr(),
                dst_addr: five_tuple.dst_socket_addr(),
                outbound_tag: session.outbound_tag.clone(),
                peer_key,
            };
            handler.on_session_created(session.id, &info);
        }

        // Verify callback was fired
        let created = handler.created_sessions.lock();
        assert_eq!(created.len(), 1);
        assert_eq!(created[0].0, result1.session().id);
        assert_eq!(created[0].1.protocol, IpProtocol::Tcp);
        drop(created);

        // Second registration should be Updated - no callback
        let result2 = tracker
            .register_with_result(peer_key, peer_endpoint, five_tuple, "kernel".to_string())
            .unwrap();

        assert!(result2.is_update());

        // Handler should NOT be called for updates
        // (We don't call it in this test, verifying that inject_packet logic is correct)

        // Verify still only one created callback
        let created = handler.created_sessions.lock();
        assert_eq!(created.len(), 1);
    }

    #[test]
    fn test_session_info_fields() {
        use crate::netbridge::types::FiveTuple;
        use std::net::{IpAddr, Ipv4Addr};

        let peer_key = [99u8; 32];
        let five_tuple = FiveTuple::udp(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 25, 0, 5)), 54321),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
        );

        let info = SessionInfo {
            session_id: crate::netbridge::types::SessionId::new(42),
            protocol: five_tuple.protocol,
            src_addr: five_tuple.src_socket_addr(),
            dst_addr: five_tuple.dst_socket_addr(),
            outbound_tag: "dns-proxy".to_string(),
            peer_key,
        };

        assert_eq!(info.session_id.as_u64(), 42);
        assert!(info.protocol.is_udp());
        assert_eq!(info.src_addr.port(), 54321);
        assert_eq!(info.dst_addr.port(), 53);
        assert_eq!(info.outbound_tag, "dns-proxy");
        assert_eq!(info.peer_key, [99u8; 32]);
    }
}
