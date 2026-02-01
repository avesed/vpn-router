//! TUN + TPROXY Ingress Bridge
//!
//! This module provides the main bridge implementation that routes WireGuard
//! decrypted packets through the Linux kernel's TCP/IP stack using TUN + TPROXY.
//!
//! # Architecture
//!
//! ```text
//! WireGuard → inject_packet() → TUN → Kernel → TPROXY → accept_loop() → Outbound
//!                                                                            │
//!                                                                            ▼
//!                                                                  bidirectional copy
//!                                                                            │
//!                                                                            ▼
//! WireGuard ← reply_tx       ← TUN ← Kernel ← tun_read_loop()  ← Outbound replies
//! ```

use bytes::BytesMut;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::time::timeout;
use tracing::{debug, info, trace, warn};

#[cfg(feature = "fakedns")]
use crate::fakedns::FakeDnsManager;
use crate::outbound::{Outbound, OutboundManager};
use crate::rules::engine::{ConnectionInfo, RuleEngine};
use crate::sniff::sniff_tls_sni;
use crate::tproxy::{TproxyConnection, TproxyListener, TproxyListenerBuilder};
use crate::tun::{TunConfig, TunDevice};

use super::iptables::IptablesManager;
use super::session::{FiveTuple, SessionTracker};
use super::{
    MAX_SESSIONS_PER_PEER, MAX_TOTAL_SESSIONS, REPLY_CHANNEL_SIZE,
    SNI_PEEK_BUFFER_SIZE, SNI_PEEK_TIMEOUT_MS, TCP_CONNECT_TIMEOUT_SECS, TCP_SESSION_TIMEOUT_SECS,
    UDP_SESSION_TIMEOUT_SECS,
};

/// Configuration for the TUN + TPROXY ingress bridge
#[derive(Debug, Clone)]
pub struct TunIngressConfig {
    /// TUN device name (e.g., "tun-in")
    pub tun_name: String,
    /// TUN device CIDR (e.g., "10.25.0.1/24")
    pub tun_cidr: String,
    /// TUN device MTU (e.g., 1420)
    pub tun_mtu: u16,
    /// TPROXY listener port
    pub tproxy_port: u16,
    /// fwmark for policy routing
    pub fwmark: u32,
    /// Routing table ID for TPROXY
    pub route_table_id: u32,
    /// FakeDNS manager (optional, for domain routing)
    #[cfg(feature = "fakedns")]
    pub fakedns: Option<Arc<FakeDnsManager>>,
    /// Rule engine for routing decisions
    pub rule_engine: Arc<RuleEngine>,
    /// Outbound manager
    pub outbound_manager: Arc<OutboundManager>,
    /// Maximum sessions per peer
    pub max_sessions_per_peer: usize,
    /// Maximum total sessions
    pub max_total_sessions: usize,
    /// Reply channel capacity
    pub reply_channel_size: usize,
}

impl TunIngressConfig {
    /// Create a new configuration with default values
    #[must_use]
    pub fn new(rule_engine: Arc<RuleEngine>, outbound_manager: Arc<OutboundManager>) -> Self {
        Self {
            tun_name: super::DEFAULT_TUN_NAME.to_string(),
            tun_cidr: super::DEFAULT_TUN_CIDR.to_string(),
            tun_mtu: super::DEFAULT_TUN_MTU,
            tproxy_port: super::DEFAULT_TPROXY_PORT,
            fwmark: super::DEFAULT_FWMARK,
            route_table_id: super::DEFAULT_ROUTE_TABLE_ID,
            #[cfg(feature = "fakedns")]
            fakedns: None,
            rule_engine,
            outbound_manager,
            max_sessions_per_peer: MAX_SESSIONS_PER_PEER,
            max_total_sessions: MAX_TOTAL_SESSIONS,
            reply_channel_size: REPLY_CHANNEL_SIZE,
        }
    }

    /// Set the TUN device name
    #[must_use]
    pub fn with_tun_name(mut self, name: impl Into<String>) -> Self {
        self.tun_name = name.into();
        self
    }

    /// Set the TUN device CIDR
    #[must_use]
    pub fn with_tun_cidr(mut self, cidr: impl Into<String>) -> Self {
        self.tun_cidr = cidr.into();
        self
    }

    /// Set the TUN device MTU
    #[must_use]
    pub fn with_tun_mtu(mut self, mtu: u16) -> Self {
        self.tun_mtu = mtu;
        self
    }

    /// Set the TPROXY port
    #[must_use]
    pub fn with_tproxy_port(mut self, port: u16) -> Self {
        self.tproxy_port = port;
        self
    }

    /// Set the fwmark
    #[must_use]
    pub fn with_fwmark(mut self, fwmark: u32) -> Self {
        self.fwmark = fwmark;
        self
    }

    /// Set the routing table ID
    #[must_use]
    pub fn with_route_table_id(mut self, table_id: u32) -> Self {
        self.route_table_id = table_id;
        self
    }

    /// Set the FakeDNS manager
    #[cfg(feature = "fakedns")]
    #[must_use]
    pub fn with_fakedns(mut self, fakedns: Arc<FakeDnsManager>) -> Self {
        self.fakedns = Some(fakedns);
        self
    }
}

/// Statistics for the TUN ingress bridge
#[derive(Debug, Default)]
pub struct TunIngressStats {
    /// Packets injected into TUN
    pub packets_injected: AtomicU64,
    /// Packets read from TUN (replies)
    pub packets_read: AtomicU64,
    /// TCP connections accepted
    pub tcp_connections_accepted: AtomicU64,
    /// TCP connections active
    pub tcp_connections_active: AtomicU64,
    /// UDP sessions active
    pub udp_sessions_active: AtomicU64,
    /// DNS queries hijacked (FakeDNS)
    pub dns_queries_hijacked: AtomicU64,
    /// Domain resolutions via FakeDNS reverse lookup
    pub fakedns_reverse_hits: AtomicU64,
    /// Domain resolutions via SNI extraction
    pub sni_extractions: AtomicU64,
    /// Connection errors
    pub connection_errors: AtomicU64,
    /// Session limit rejections
    pub session_limit_rejections: AtomicU64,
    /// Bytes sent to outbound
    pub bytes_sent: AtomicU64,
    /// Bytes received from outbound
    pub bytes_received: AtomicU64,
}

impl TunIngressStats {
    /// Create a new stats instance
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

/// Snapshot of statistics (for reporting)
#[derive(Debug, Clone)]
pub struct TunIngressStatsSnapshot {
    pub packets_injected: u64,
    pub packets_read: u64,
    pub tcp_connections_accepted: u64,
    pub tcp_connections_active: u64,
    pub udp_sessions_active: u64,
    pub dns_queries_hijacked: u64,
    pub fakedns_reverse_hits: u64,
    pub sni_extractions: u64,
    pub connection_errors: u64,
    pub session_limit_rejections: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

impl From<&TunIngressStats> for TunIngressStatsSnapshot {
    fn from(stats: &TunIngressStats) -> Self {
        Self {
            packets_injected: stats.packets_injected.load(Ordering::Relaxed),
            packets_read: stats.packets_read.load(Ordering::Relaxed),
            tcp_connections_accepted: stats.tcp_connections_accepted.load(Ordering::Relaxed),
            tcp_connections_active: stats.tcp_connections_active.load(Ordering::Relaxed),
            udp_sessions_active: stats.udp_sessions_active.load(Ordering::Relaxed),
            dns_queries_hijacked: stats.dns_queries_hijacked.load(Ordering::Relaxed),
            fakedns_reverse_hits: stats.fakedns_reverse_hits.load(Ordering::Relaxed),
            sni_extractions: stats.sni_extractions.load(Ordering::Relaxed),
            connection_errors: stats.connection_errors.load(Ordering::Relaxed),
            session_limit_rejections: stats.session_limit_rejections.load(Ordering::Relaxed),
            bytes_sent: stats.bytes_sent.load(Ordering::Relaxed),
            bytes_received: stats.bytes_received.load(Ordering::Relaxed),
        }
    }
}

/// TUN + TPROXY Ingress Bridge
///
/// Bridges WireGuard ingress traffic to outbound connections using the
/// Linux kernel's TCP/IP stack via TUN device and TPROXY.
pub struct TunIngressBridge {
    /// TUN device for packet injection
    tun: Arc<TunDevice>,
    /// TPROXY listener for intercepted TCP connections
    tproxy_listener: TproxyListener,
    /// Session tracker: 5-tuple -> peer info
    session_tracker: Arc<SessionTracker>,
    /// Reply channel sender (for sending packets back to WG)
    reply_tx: mpsc::Sender<(BytesMut, [u8; 32])>,
    /// Reply channel receiver (taken by caller)
    reply_rx: Option<mpsc::Receiver<(BytesMut, [u8; 32])>>,
    /// FakeDNS manager for domain resolution
    #[cfg(feature = "fakedns")]
    fakedns: Option<Arc<FakeDnsManager>>,
    /// Rule engine for routing decisions
    rule_engine: Arc<RuleEngine>,
    /// Outbound manager
    outbound_manager: Arc<OutboundManager>,
    /// iptables manager
    iptables_manager: IptablesManager,
    /// Statistics
    stats: Arc<TunIngressStats>,
    /// Configuration
    config: TunIngressConfig,
}

impl TunIngressBridge {
    /// Create a new TUN + TPROXY ingress bridge
    ///
    /// # Arguments
    ///
    /// * `config` - Bridge configuration
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - TUN device creation fails
    /// - TPROXY listener creation fails
    /// - iptables rule application fails
    pub async fn new(config: TunIngressConfig) -> io::Result<Self> {
        info!(
            tun = %config.tun_name,
            cidr = %config.tun_cidr,
            mtu = config.tun_mtu,
            tproxy_port = config.tproxy_port,
            "Creating TUN + TPROXY ingress bridge"
        );

        // Create TUN device
        let tun_config = TunConfig::new(&config.tun_name).with_mtu(config.tun_mtu);
        let tun = TunDevice::create(&tun_config)?;

        // Configure TUN interface (set IP, MTU, bring up)
        tun.configure(&config.tun_cidr)?;

        info!(
            device = %tun.name(),
            "TUN device created and configured"
        );

        // Create TPROXY listener
        let tproxy_addr: SocketAddr = format!("0.0.0.0:{}", config.tproxy_port)
            .parse()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

        let tproxy_listener = TproxyListenerBuilder::new(tproxy_addr)
            .fwmark(Some(config.fwmark))
            .build()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        info!(
            addr = %tproxy_addr,
            fwmark = config.fwmark,
            "TPROXY listener created"
        );

        // Extract network portion from CIDR for routing
        // e.g., "10.25.0.1/24" -> "10.25.0.0/24"
        let tun_network = Self::cidr_to_network(&config.tun_cidr);

        // Create and apply iptables rules
        let mut iptables_manager = IptablesManager::new(
            tun.name(),
            &tun_network,
            config.tproxy_port,
            config.fwmark,
            config.route_table_id,
        )?;
        iptables_manager.apply_rules()?;

        // Create session tracker
        let session_tracker = Arc::new(SessionTracker::with_limits(
            config.max_sessions_per_peer,
            config.max_total_sessions,
        ));

        // Create reply channel
        let (reply_tx, reply_rx) = mpsc::channel(config.reply_channel_size);

        Ok(Self {
            tun: Arc::new(tun),
            tproxy_listener,
            session_tracker,
            reply_tx,
            reply_rx: Some(reply_rx),
            #[cfg(feature = "fakedns")]
            fakedns: config.fakedns.clone(),
            rule_engine: Arc::clone(&config.rule_engine),
            outbound_manager: Arc::clone(&config.outbound_manager),
            iptables_manager,
            stats: Arc::new(TunIngressStats::new()),
            config,
        })
    }

    /// Inject a WireGuard-decrypted IP packet into the TUN device
    ///
    /// This method:
    /// 1. Parses the IP header to extract the 5-tuple
    /// 2. Registers the session in the session tracker
    /// 3. Writes the packet to the TUN device
    /// 4. The kernel routes it, TPROXY intercepts, and we accept on the listener
    ///
    /// # Arguments
    ///
    /// * `packet` - The decrypted IP packet from WireGuard
    /// * `peer_key` - WireGuard peer public key
    /// * `peer_endpoint` - Peer's WireGuard endpoint (IP:port)
    /// * `outbound_tag` - Pre-matched outbound tag from IP-based rules
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Packet parsing fails
    /// - Session registration fails (limits exceeded)
    /// - TUN write fails
    pub async fn inject_packet(
        &self,
        packet: BytesMut,
        peer_key: [u8; 32],
        peer_endpoint: SocketAddr,
        outbound_tag: &str,
    ) -> io::Result<()> {
        // Parse 5-tuple from packet
        let five_tuple = FiveTuple::from_packet(&packet).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Failed to parse 5-tuple from packet",
            )
        })?;

        // Register session
        let session = self
            .session_tracker
            .register(peer_key, peer_endpoint, five_tuple.clone(), outbound_tag.to_string())
            .ok_or_else(|| {
                self.stats.session_limit_rejections.fetch_add(1, Ordering::Relaxed);
                io::Error::new(io::ErrorKind::Other, "Session limit exceeded")
            })?;

        trace!(
            session_id = session.session_id,
            five_tuple = %five_tuple,
            outbound = %outbound_tag,
            "Session registered for packet injection"
        );

        // Write packet to TUN device
        let written = self.tun.write_packet(&packet).await?;
        self.stats.packets_injected.fetch_add(1, Ordering::Relaxed);

        trace!(bytes = written, "Packet injected into TUN");

        Ok(())
    }

    /// Take the reply receiver
    ///
    /// This should be called once to get the receiver for sending encrypted
    /// packets back to WireGuard peers.
    pub fn take_reply_rx(&mut self) -> Option<mpsc::Receiver<(BytesMut, [u8; 32])>> {
        self.reply_rx.take()
    }

    /// Run the TPROXY accept loop
    ///
    /// This method accepts TCP connections from the TPROXY listener, resolves
    /// domains, matches rules, and establishes outbound connections.
    ///
    /// This should be spawned as a task.
    pub async fn run_accept_loop(self: &Arc<Self>) -> io::Result<()> {
        info!("Starting TPROXY accept loop");

        loop {
            // Accept connection
            let conn = match self.tproxy_listener.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    warn!("TPROXY accept error: {}", e);
                    self.stats.connection_errors.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
            };

            self.stats.tcp_connections_accepted.fetch_add(1, Ordering::Relaxed);
            self.stats.tcp_connections_active.fetch_add(1, Ordering::Relaxed);

            // Spawn handler for this connection
            let bridge = Arc::clone(self);
            tokio::spawn(async move {
                if let Err(e) = bridge.handle_tcp_connection(conn).await {
                    debug!("TCP connection error: {}", e);
                    bridge.stats.connection_errors.fetch_add(1, Ordering::Relaxed);
                }
                bridge.stats.tcp_connections_active.fetch_sub(1, Ordering::Relaxed);
            });
        }
    }

    /// Handle a single TCP connection
    async fn handle_tcp_connection(&self, mut conn: TproxyConnection) -> io::Result<()> {
        let client_addr = conn.client_addr();
        let original_dst = conn.original_dst();

        debug!(
            client = %client_addr,
            dest = %original_dst,
            "Handling TCP connection"
        );

        // Try to resolve domain
        let domain = self.resolve_domain(original_dst.ip(), conn.stream_mut()).await;

        // Build connection info for rule matching
        let conn_info = ConnectionInfo::new("tcp", original_dst.port())
            .with_dest_ip(original_dst.ip());

        let conn_info = if let Some(ref d) = domain {
            conn_info.with_domain(d.clone())
        } else {
            conn_info
        };

        // Match rules
        let match_result = self.rule_engine.match_connection(&conn_info);

        debug!(
            dest = %original_dst,
            domain = ?domain,
            outbound = %match_result.outbound,
            matched_rule = ?match_result.matched_rule,
            "Rule matched"
        );

        // Get outbound
        let outbound = self
            .outbound_manager
            .get(&match_result.outbound)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("Outbound not found: {}", match_result.outbound),
                )
            })?;

        // Connect to destination via outbound
        let connect_timeout = Duration::from_secs(TCP_CONNECT_TIMEOUT_SECS);
        let outbound_conn = timeout(
            connect_timeout,
            outbound.connect(original_dst, connect_timeout),
        )
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Connect timeout"))?
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        debug!(
            dest = %original_dst,
            domain = ?domain,
            outbound = %match_result.outbound,
            "Outbound connection established"
        );

        // Get the underlying stream from the outbound connection
        let outbound_stream = outbound_conn.into_outbound_stream();

        // Bidirectional copy
        let (mut client_read, mut client_write) = tokio::io::split(conn.into_stream());
        let (mut outbound_read, mut outbound_write) = tokio::io::split(outbound_stream);

        let stats = Arc::clone(&self.stats);
        let stats2 = Arc::clone(&self.stats);

        let client_to_outbound = async move {
            let mut buf = [0u8; 16384];
            loop {
                let n = client_read.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                outbound_write.write_all(&buf[..n]).await?;
                stats.bytes_sent.fetch_add(n as u64, Ordering::Relaxed);
            }
            outbound_write.shutdown().await?;
            Ok::<_, io::Error>(())
        };

        let outbound_to_client = async move {
            let mut buf = [0u8; 16384];
            loop {
                let n = outbound_read.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                client_write.write_all(&buf[..n]).await?;
                stats2.bytes_received.fetch_add(n as u64, Ordering::Relaxed);
            }
            client_write.shutdown().await?;
            Ok::<_, io::Error>(())
        };

        // Run both directions concurrently
        let result = tokio::select! {
            r = client_to_outbound => r,
            r = outbound_to_client => r,
        };

        if let Err(e) = result {
            // Connection errors are common (client disconnect, etc.)
            trace!("Connection copy error: {}", e);
        }

        Ok(())
    }

    /// Resolve domain from IP address
    ///
    /// Tries (in order):
    /// 1. FakeDNS reverse lookup
    /// 2. TLS SNI extraction
    async fn resolve_domain(
        &self,
        #[cfg_attr(not(feature = "fakedns"), allow(unused_variables))]
        dest_ip: IpAddr,
        stream: &mut tokio::net::TcpStream,
    ) -> Option<String> {
        // Try FakeDNS reverse lookup first
        #[cfg(feature = "fakedns")]
        if let Some(ref fakedns) = self.fakedns {
            if fakedns.is_fake_ip(dest_ip) {
                if let Some(domain) = fakedns.map_ip_domain(dest_ip) {
                    self.stats.fakedns_reverse_hits.fetch_add(1, Ordering::Relaxed);
                    trace!(ip = %dest_ip, domain = %domain, "FakeDNS reverse lookup hit");
                    return Some(domain);
                }
            }
        }

        // Try SNI extraction by peeking at the TLS ClientHello
        let mut peek_buf = [0u8; SNI_PEEK_BUFFER_SIZE];
        match timeout(
            Duration::from_millis(SNI_PEEK_TIMEOUT_MS),
            stream.peek(&mut peek_buf),
        )
        .await
        {
            Ok(Ok(n)) if n > 0 => {
                if let Some(sni) = sniff_tls_sni(&peek_buf[..n]) {
                    self.stats.sni_extractions.fetch_add(1, Ordering::Relaxed);
                    trace!(sni = %sni, "SNI extracted from TLS ClientHello");
                    return Some(sni.to_string());
                }
            }
            Ok(Ok(_)) => {
                trace!("Peek returned 0 bytes");
            }
            Ok(Err(e)) => {
                trace!("Peek error: {}", e);
            }
            Err(_) => {
                trace!("Peek timeout");
            }
        }

        None
    }

    /// Run the TUN read loop for capturing reply packets
    ///
    /// This method reads packets from the TUN device (reply packets from kernel),
    /// looks up the session to find the peer key, and sends them to the reply channel.
    ///
    /// This should be spawned as a task.
    pub async fn run_tun_read_loop(self: &Arc<Self>) -> io::Result<()> {
        info!("Starting TUN read loop");

        let mut buf = vec![0u8; self.config.tun_mtu as usize + 100]; // Extra space for safety

        loop {
            // Read packet from TUN
            let n = self.tun.read_packet(&mut buf).await?;
            if n == 0 {
                continue;
            }

            self.stats.packets_read.fetch_add(1, Ordering::Relaxed);

            // Parse 5-tuple (this is a reply packet, so src/dst are reversed)
            let Some(reply_tuple) = FiveTuple::from_packet(&buf[..n]) else {
                trace!("Failed to parse 5-tuple from TUN packet");
                continue;
            };

            // Look up session by reversed tuple
            let Some(session) = self.session_tracker.lookup_by_reply(&reply_tuple) else {
                trace!(tuple = %reply_tuple, "No session found for reply packet");
                continue;
            };

            // Update session activity
            session.touch();
            session.add_bytes_received(n as u64);

            // Send to reply channel
            let packet = BytesMut::from(&buf[..n]);
            if let Err(e) = self.reply_tx.send((packet, session.peer_key)).await {
                warn!("Failed to send reply packet: {}", e);
            }

            trace!(
                session_id = session.session_id,
                bytes = n,
                "Reply packet sent to WireGuard"
            );
        }
    }

    /// Run the session cleanup task
    ///
    /// This periodically removes idle sessions.
    pub async fn run_cleanup_loop(self: &Arc<Self>) {
        let mut interval = tokio::time::interval(Duration::from_secs(super::SESSION_CLEANUP_INTERVAL_SECS));

        loop {
            interval.tick().await;

            let removed = self.session_tracker.cleanup_idle(
                Duration::from_secs(TCP_SESSION_TIMEOUT_SECS),
                Duration::from_secs(UDP_SESSION_TIMEOUT_SECS),
            );

            if removed > 0 {
                debug!(removed, "Cleaned up idle sessions");
            }
        }
    }

    /// Get statistics
    pub fn stats(&self) -> &TunIngressStats {
        &self.stats
    }

    /// Get a snapshot of statistics
    #[must_use]
    pub fn stats_snapshot(&self) -> TunIngressStatsSnapshot {
        TunIngressStatsSnapshot::from(self.stats.as_ref())
    }

    /// Get the session tracker
    pub fn session_tracker(&self) -> &Arc<SessionTracker> {
        &self.session_tracker
    }

    /// Get the TUN device
    pub fn tun(&self) -> &TunDevice {
        &self.tun
    }

    /// Get the TUN device name
    #[must_use]
    pub fn tun_name(&self) -> &str {
        self.tun.name()
    }

    /// Get the TPROXY port
    #[must_use]
    pub fn tproxy_port(&self) -> u16 {
        self.config.tproxy_port
    }

    /// Get the fwmark
    #[must_use]
    pub fn fwmark(&self) -> u32 {
        self.config.fwmark
    }

    /// Get the number of active TCP sessions
    #[must_use]
    pub fn tcp_session_count(&self) -> usize {
        self.session_tracker.tcp_session_count()
    }

    /// Get the number of active UDP sessions
    #[must_use]
    pub fn udp_session_count(&self) -> usize {
        self.session_tracker.udp_session_count()
    }

    /// Get the total number of active sessions
    #[must_use]
    pub fn total_sessions(&self) -> usize {
        self.session_tracker.total_sessions()
    }

    /// Convert a CIDR address (e.g., "10.25.0.1/24") to its network form (e.g., "10.25.0.0/24")
    ///
    /// This is used for routing - we need the network address, not the host address.
    fn cidr_to_network(cidr: &str) -> String {
        use std::net::Ipv4Addr;

        // Parse CIDR: "10.25.0.1/24" -> ("10.25.0.1", 24)
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            // Invalid CIDR, return as-is
            return cidr.to_string();
        }

        let ip_str = parts[0];
        let prefix_len = parts[1];

        // Parse IPv4 address
        let ip: Ipv4Addr = match ip_str.parse() {
            Ok(ip) => ip,
            Err(_) => return cidr.to_string(),
        };

        // Parse prefix length
        let prefix: u32 = match prefix_len.parse() {
            Ok(p) if p <= 32 => p,
            _ => return cidr.to_string(),
        };

        // Calculate network mask
        let mask = if prefix == 0 {
            0u32
        } else {
            !0u32 << (32 - prefix)
        };

        // Apply mask to get network address
        let ip_u32 = u32::from(ip);
        let network_u32 = ip_u32 & mask;
        let network = Ipv4Addr::from(network_u32);

        format!("{}/{}", network, prefix)
    }
}

impl Drop for TunIngressBridge {
    fn drop(&mut self) {
        info!("Shutting down TUN + TPROXY ingress bridge");
        // iptables rules are cleaned up automatically by IptablesManager::drop
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_builder() {
        use crate::rules::RoutingSnapshotBuilder;

        // Create minimal rule engine
        let snapshot = RoutingSnapshotBuilder::new()
            .default_outbound("direct")
            .build()
            .unwrap();
        let rule_engine = Arc::new(RuleEngine::new(snapshot));

        // Create minimal outbound manager
        let outbound_manager = Arc::new(OutboundManager::new());

        let config = TunIngressConfig::new(rule_engine, outbound_manager)
            .with_tun_name("tun-test")
            .with_tun_cidr("192.168.100.1/24")
            .with_tun_mtu(1500)
            .with_tproxy_port(8080)
            .with_fwmark(0x100)
            .with_route_table_id(200);

        assert_eq!(config.tun_name, "tun-test");
        assert_eq!(config.tun_cidr, "192.168.100.1/24");
        assert_eq!(config.tun_mtu, 1500);
        assert_eq!(config.tproxy_port, 8080);
        assert_eq!(config.fwmark, 0x100);
        assert_eq!(config.route_table_id, 200);
    }

    #[test]
    fn test_stats_snapshot() {
        let stats = TunIngressStats::new();
        stats.packets_injected.store(100, Ordering::Relaxed);
        stats.packets_read.store(50, Ordering::Relaxed);
        stats.tcp_connections_accepted.store(10, Ordering::Relaxed);

        let snapshot = TunIngressStatsSnapshot::from(&stats);
        assert_eq!(snapshot.packets_injected, 100);
        assert_eq!(snapshot.packets_read, 50);
        assert_eq!(snapshot.tcp_connections_accepted, 10);
    }

    #[test]
    fn test_default_config_values() {
        use crate::rules::RoutingSnapshotBuilder;

        let snapshot = RoutingSnapshotBuilder::new()
            .default_outbound("direct")
            .build()
            .unwrap();
        let rule_engine = Arc::new(RuleEngine::new(snapshot));
        let outbound_manager = Arc::new(OutboundManager::new());

        let config = TunIngressConfig::new(rule_engine, outbound_manager);

        assert_eq!(config.tun_name, super::super::DEFAULT_TUN_NAME);
        assert_eq!(config.tun_cidr, super::super::DEFAULT_TUN_CIDR);
        assert_eq!(config.tun_mtu, super::super::DEFAULT_TUN_MTU);
        assert_eq!(config.tproxy_port, super::super::DEFAULT_TPROXY_PORT);
        assert_eq!(config.fwmark, super::super::DEFAULT_FWMARK);
        assert_eq!(config.route_table_id, super::super::DEFAULT_ROUTE_TABLE_ID);
    }
}
