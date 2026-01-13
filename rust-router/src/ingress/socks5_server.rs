//! SOCKS5 inbound server for accepting proxy connections
//!
//! This module provides a SOCKS5 server that accepts incoming connections (e.g., from Xray)
//! and routes them through the rust-router rule engine for domain-based routing decisions.
//!
//! # Architecture
//!
//! ```text
//! Xray Client (VLESS)          rust-router SOCKS5 Server
//!       |                              |
//!       v                              v
//! +-------------+              +------------------+
//! | v2ray-in    | --SOCKS5-->  | Socks5Server     |
//! | inbound     |              | (this module)    |
//! +-------------+              +------------------+
//!                                      |
//!                              +------------------+
//!                              | IngressProcessor |
//!                              | (rule matching)  |
//!                              +------------------+
//!                                      |
//!                              +------------------+
//!                              | OutboundManager  |
//!                              | (direct/warp/wg) |
//!                              +------------------+
//!                                      |
//!                                      v
//!                                  Internet
//! ```
//!
//! # SOCKS5 Protocol Flow
//!
//! 1. Client connects and sends auth method selection
//! 2. Server replies with no-auth (0x00)
//! 3. Client sends CONNECT request with destination (domain or IP)
//! 4. Server performs rule matching using domain name (if available)
//! 5. Server establishes outbound connection
//! 6. Server replies with success/failure
//! 7. Bidirectional data relay begins

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tracing::{debug, error, info, trace, warn};

use crate::error::OutboundError;
use crate::outbound::socks5_common::{
    ATYP_DOMAIN, ATYP_IPV4, ATYP_IPV6, AUTH_METHOD_NONE, CMD_CONNECT,
    REPLY_ADDRESS_TYPE_NOT_SUPPORTED, REPLY_COMMAND_NOT_SUPPORTED, REPLY_CONNECTION_REFUSED,
    REPLY_GENERAL_FAILURE, REPLY_SUCCEEDED, SOCKS5_VERSION,
};
use crate::outbound::OutboundManager;
use crate::rules::engine::{ConnectionInfo, RuleEngine};

/// SOCKS5 server configuration
#[derive(Debug, Clone)]
pub struct Socks5ServerConfig {
    /// Listen address (e.g., "127.0.0.1:38501")
    pub listen_addr: SocketAddr,
    /// Connection timeout for handshake
    pub handshake_timeout: Duration,
    /// Connect timeout for outbound
    pub connect_timeout: Duration,
}

impl Default for Socks5ServerConfig {
    fn default() -> Self {
        Self {
            listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 38501),
            handshake_timeout: Duration::from_secs(10),
            connect_timeout: Duration::from_secs(30),
        }
    }
}

/// Statistics for the SOCKS5 server
#[derive(Debug, Default)]
pub struct Socks5ServerStats {
    /// Total connections accepted
    pub connections_accepted: AtomicU64,
    /// Total connections completed (successfully relayed)
    pub connections_completed: AtomicU64,
    /// Total connection errors (handshake or connect failures)
    pub connection_errors: AtomicU64,
    /// Total bytes sent to clients
    pub bytes_sent: AtomicU64,
    /// Total bytes received from clients
    pub bytes_received: AtomicU64,
}

impl Socks5ServerStats {
    /// Create a snapshot of current stats
    pub fn snapshot(&self) -> Socks5ServerStatsSnapshot {
        Socks5ServerStatsSnapshot {
            connections_accepted: self.connections_accepted.load(Ordering::Relaxed),
            connections_completed: self.connections_completed.load(Ordering::Relaxed),
            connection_errors: self.connection_errors.load(Ordering::Relaxed),
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of SOCKS5 server statistics
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct Socks5ServerStatsSnapshot {
    pub connections_accepted: u64,
    pub connections_completed: u64,
    pub connection_errors: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

/// SOCKS5 inbound server
pub struct Socks5Server {
    config: Socks5ServerConfig,
    rule_engine: Arc<RuleEngine>,
    outbound_manager: Arc<OutboundManager>,
    stats: Arc<Socks5ServerStats>,
    shutdown_tx: watch::Sender<bool>,
    shutdown_rx: watch::Receiver<bool>,
}

impl Socks5Server {
    /// Create a new SOCKS5 server
    pub fn new(
        config: Socks5ServerConfig,
        rule_engine: Arc<RuleEngine>,
        outbound_manager: Arc<OutboundManager>,
    ) -> Self {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        Self {
            config,
            rule_engine,
            outbound_manager,
            stats: Arc::new(Socks5ServerStats::default()),
            shutdown_tx,
            shutdown_rx,
        }
    }

    /// Get server statistics
    pub fn stats(&self) -> &Arc<Socks5ServerStats> {
        &self.stats
    }

    /// Start the SOCKS5 server
    pub async fn run(&self) -> io::Result<()> {
        let listener = TcpListener::bind(self.config.listen_addr).await?;
        info!(
            addr = %self.config.listen_addr,
            "SOCKS5 inbound server started"
        );

        let mut shutdown_rx = self.shutdown_rx.clone();

        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, peer_addr)) => {
                            self.stats.connections_accepted.fetch_add(1, Ordering::Relaxed);
                            debug!(peer = %peer_addr, "SOCKS5 connection accepted");

                            let rule_engine = Arc::clone(&self.rule_engine);
                            let outbound_manager = Arc::clone(&self.outbound_manager);
                            let stats = Arc::clone(&self.stats);
                            let config = self.config.clone();

                            tokio::spawn(async move {
                                if let Err(e) = handle_connection(
                                    stream,
                                    peer_addr,
                                    rule_engine,
                                    outbound_manager,
                                    stats,
                                    config,
                                ).await {
                                    debug!(peer = %peer_addr, error = %e, "SOCKS5 connection error");
                                }
                            });
                        }
                        Err(e) => {
                            error!(error = %e, "Failed to accept connection");
                        }
                    }
                }
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        info!("SOCKS5 server shutting down");
                        break;
                    }
                }
            }
        }

        Ok(())
    }

    /// Shutdown the server
    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
    }
}

/// Handle a single SOCKS5 connection
async fn handle_connection(
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    rule_engine: Arc<RuleEngine>,
    outbound_manager: Arc<OutboundManager>,
    stats: Arc<Socks5ServerStats>,
    config: Socks5ServerConfig,
) -> io::Result<()> {
    // Set TCP keepalive
    stream.set_nodelay(true)?;

    // Perform SOCKS5 handshake with timeout
    let handshake_result = tokio::time::timeout(
        config.handshake_timeout,
        socks5_handshake(&mut stream),
    )
    .await;

    let (domain, dest_addr) = match handshake_result {
        Ok(Ok(result)) => result,
        Ok(Err(e)) => {
            stats.connection_errors.fetch_add(1, Ordering::Relaxed);
            debug!(peer = %peer_addr, error = %e, "SOCKS5 handshake failed");
            return Err(io::Error::new(io::ErrorKind::Other, e));
        }
        Err(_) => {
            stats.connection_errors.fetch_add(1, Ordering::Relaxed);
            debug!(peer = %peer_addr, "SOCKS5 handshake timeout");
            return Err(io::Error::new(io::ErrorKind::TimedOut, "handshake timeout"));
        }
    };

    // Perform rule matching
    let conn_info = ConnectionInfo {
        source_ip: Some(peer_addr.ip()),
        dest_ip: Some(dest_addr.ip()),
        dest_port: dest_addr.port(),
        protocol: "tcp",
        domain: domain.clone(),
        ..Default::default()
    };

    let match_result = rule_engine.match_connection(&conn_info);
    let outbound_tag = &match_result.outbound;

    debug!(
        peer = %peer_addr,
        dest = %dest_addr,
        domain = ?domain,
        outbound = %outbound_tag,
        rule = ?match_result.matched_rule,
        "SOCKS5 routing decision"
    );

    // Get outbound by tag
    let outbound = match outbound_manager.get(outbound_tag) {
        Some(o) => o,
        None => {
            stats.connection_errors.fetch_add(1, Ordering::Relaxed);
            warn!(outbound = %outbound_tag, "Outbound not found, using default");
            // Try to get "direct" as fallback
            match outbound_manager.get("direct") {
                Some(o) => o,
                None => {
                    send_reply(&mut stream, REPLY_GENERAL_FAILURE, dest_addr).await?;
                    return Err(io::Error::new(io::ErrorKind::NotFound, "No outbound available"));
                }
            }
        }
    };

    // Connect to destination via outbound
    let outbound_conn = match outbound.connect(dest_addr, config.connect_timeout).await {
        Ok(conn) => conn,
        Err(e) => {
            stats.connection_errors.fetch_add(1, Ordering::Relaxed);
            let reply_code = match &e {
                OutboundError::ConnectionFailed { .. } => REPLY_CONNECTION_REFUSED,
                OutboundError::Timeout { .. } => REPLY_GENERAL_FAILURE,
                _ => REPLY_GENERAL_FAILURE,
            };
            send_reply(&mut stream, reply_code, dest_addr).await?;
            return Err(io::Error::new(io::ErrorKind::ConnectionRefused, e.to_string()));
        }
    };

    // Send success reply
    send_reply(&mut stream, REPLY_SUCCEEDED, dest_addr).await?;

    // Get the underlying TcpStream for relay
    let outbound_stream = outbound_conn.into_stream();

    // Bidirectional relay
    let (bytes_sent, bytes_recv) = relay_data(stream, outbound_stream).await?;

    stats.bytes_sent.fetch_add(bytes_sent, Ordering::Relaxed);
    stats.bytes_received.fetch_add(bytes_recv, Ordering::Relaxed);
    stats.connections_completed.fetch_add(1, Ordering::Relaxed);

    debug!(
        peer = %peer_addr,
        dest = %dest_addr,
        sent = bytes_sent,
        recv = bytes_recv,
        "SOCKS5 connection completed"
    );

    Ok(())
}

/// Perform SOCKS5 handshake, returns (optional domain, destination address)
async fn socks5_handshake(
    stream: &mut TcpStream,
) -> Result<(Option<String>, SocketAddr), String> {
    // ========== Phase 1: Auth negotiation ==========
    // Client: VER(1) NMETHODS(1) METHODS(1-255)
    let mut buf = [0u8; 258];
    stream.read_exact(&mut buf[..2]).await.map_err(|e| format!("read auth header: {e}"))?;

    let version = buf[0];
    let nmethods = buf[1] as usize;

    if version != SOCKS5_VERSION {
        return Err(format!("invalid SOCKS version: {version}"));
    }

    if nmethods == 0 || nmethods > 255 {
        return Err(format!("invalid nmethods: {nmethods}"));
    }

    stream.read_exact(&mut buf[..nmethods]).await.map_err(|e| format!("read auth methods: {e}"))?;

    // Check if no-auth is offered
    let has_no_auth = buf[..nmethods].contains(&AUTH_METHOD_NONE);
    if !has_no_auth {
        // Reply with "no acceptable method"
        stream.write_all(&[SOCKS5_VERSION, 0xFF]).await.map_err(|e| format!("write auth reject: {e}"))?;
        return Err("no acceptable auth method".to_string());
    }

    // Reply with no-auth selected
    stream.write_all(&[SOCKS5_VERSION, AUTH_METHOD_NONE]).await.map_err(|e| format!("write auth reply: {e}"))?;

    // ========== Phase 2: Request ==========
    // Client: VER(1) CMD(1) RSV(1) ATYP(1) DST.ADDR(variable) DST.PORT(2)
    stream.read_exact(&mut buf[..4]).await.map_err(|e| format!("read request header: {e}"))?;

    let version = buf[0];
    let cmd = buf[1];
    let _rsv = buf[2];
    let atyp = buf[3];

    if version != SOCKS5_VERSION {
        return Err(format!("invalid SOCKS version in request: {version}"));
    }

    if cmd != CMD_CONNECT {
        // Only CONNECT is supported for now
        send_reply_sync(stream, REPLY_COMMAND_NOT_SUPPORTED).await?;
        return Err(format!("unsupported command: {cmd}"));
    }

    // Parse destination address
    let (domain, dest_ip) = match atyp {
        ATYP_IPV4 => {
            stream.read_exact(&mut buf[..4]).await.map_err(|e| format!("read ipv4 addr: {e}"))?;
            let ip = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
            (None, IpAddr::V4(ip))
        }
        ATYP_DOMAIN => {
            stream.read_exact(&mut buf[..1]).await.map_err(|e| format!("read domain len: {e}"))?;
            let domain_len = buf[0] as usize;
            if domain_len == 0 || domain_len > 255 {
                send_reply_sync(stream, REPLY_ADDRESS_TYPE_NOT_SUPPORTED).await?;
                return Err(format!("invalid domain length: {domain_len}"));
            }
            stream.read_exact(&mut buf[..domain_len]).await.map_err(|e| format!("read domain: {e}"))?;
            let domain = String::from_utf8_lossy(&buf[..domain_len]).to_string();
            
            // Resolve domain to IP for outbound connection
            // For now, use a placeholder IP - the outbound will resolve the domain
            // In practice, we pass the domain to the rule engine and outbound
            let resolved_ip = resolve_domain(&domain).await.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
            (Some(domain), resolved_ip)
        }
        ATYP_IPV6 => {
            stream.read_exact(&mut buf[..16]).await.map_err(|e| format!("read ipv6 addr: {e}"))?;
            let ip = Ipv6Addr::new(
                u16::from_be_bytes([buf[0], buf[1]]),
                u16::from_be_bytes([buf[2], buf[3]]),
                u16::from_be_bytes([buf[4], buf[5]]),
                u16::from_be_bytes([buf[6], buf[7]]),
                u16::from_be_bytes([buf[8], buf[9]]),
                u16::from_be_bytes([buf[10], buf[11]]),
                u16::from_be_bytes([buf[12], buf[13]]),
                u16::from_be_bytes([buf[14], buf[15]]),
            );
            (None, IpAddr::V6(ip))
        }
        _ => {
            send_reply_sync(stream, REPLY_ADDRESS_TYPE_NOT_SUPPORTED).await?;
            return Err(format!("unsupported address type: {atyp}"));
        }
    };

    // Read port
    stream.read_exact(&mut buf[..2]).await.map_err(|e| format!("read port: {e}"))?;
    let port = u16::from_be_bytes([buf[0], buf[1]]);

    let dest_addr = SocketAddr::new(dest_ip, port);

    trace!(
        domain = ?domain,
        dest = %dest_addr,
        "SOCKS5 CONNECT request parsed"
    );

    Ok((domain, dest_addr))
}

/// Send SOCKS5 reply (for error cases during handshake)
async fn send_reply_sync(stream: &mut TcpStream, reply: u8) -> Result<(), String> {
    // VER(1) REP(1) RSV(1) ATYP(1) BND.ADDR(4) BND.PORT(2) = 10 bytes for IPv4
    let reply_buf = [
        SOCKS5_VERSION,
        reply,
        0x00, // RSV
        ATYP_IPV4,
        0, 0, 0, 0, // BND.ADDR (0.0.0.0)
        0, 0, // BND.PORT (0)
    ];
    stream.write_all(&reply_buf).await.map_err(|e| format!("write reply: {e}"))?;
    Ok(())
}

/// Send SOCKS5 reply with bound address
async fn send_reply(stream: &mut TcpStream, reply: u8, bound_addr: SocketAddr) -> io::Result<()> {
    let mut buf = Vec::with_capacity(22);
    buf.push(SOCKS5_VERSION);
    buf.push(reply);
    buf.push(0x00); // RSV

    match bound_addr.ip() {
        IpAddr::V4(ip) => {
            buf.push(ATYP_IPV4);
            buf.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            buf.push(ATYP_IPV6);
            buf.extend_from_slice(&ip.octets());
        }
    }

    buf.extend_from_slice(&bound_addr.port().to_be_bytes());
    stream.write_all(&buf).await
}

/// Relay data bidirectionally between client and outbound
async fn relay_data(
    client: TcpStream,
    outbound: TcpStream,
) -> io::Result<(u64, u64)> {
    let (mut client_read, mut client_write) = client.into_split();
    let (mut outbound_read, mut outbound_write) = outbound.into_split();

    let client_to_outbound = async {
        let mut total = 0u64;
        let mut buf = vec![0u8; 32768];
        loop {
            let n = client_read.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            outbound_write.write_all(&buf[..n]).await?;
            total += n as u64;
        }
        let _ = outbound_write.shutdown().await;
        Ok::<_, io::Error>(total)
    };

    let outbound_to_client = async {
        let mut total = 0u64;
        let mut buf = vec![0u8; 32768];
        loop {
            let n = outbound_read.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            client_write.write_all(&buf[..n]).await?;
            total += n as u64;
        }
        let _ = client_write.shutdown().await;
        Ok::<_, io::Error>(total)
    };

    let (sent_result, recv_result) = tokio::join!(client_to_outbound, outbound_to_client);

    let bytes_sent = sent_result.unwrap_or(0);
    let bytes_recv = recv_result.unwrap_or(0);

    Ok((bytes_sent, bytes_recv))
}

/// Simple DNS resolution (placeholder - uses system resolver)
async fn resolve_domain(domain: &str) -> Option<IpAddr> {
    use tokio::net::lookup_host;
    
    let addr_with_port = format!("{domain}:0");
    match lookup_host(addr_with_port).await {
        Ok(mut addrs) => addrs.next().map(|a| a.ip()),
        Err(e) => {
            debug!(domain = %domain, error = %e, "DNS resolution failed");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Socks5ServerConfig::default();
        assert_eq!(config.listen_addr.port(), 38501);
        assert_eq!(config.handshake_timeout, Duration::from_secs(10));
    }

    #[test]
    fn test_stats_snapshot() {
        let stats = Socks5ServerStats::default();
        stats.connections_accepted.fetch_add(10, Ordering::Relaxed);
        stats.bytes_sent.fetch_add(1000, Ordering::Relaxed);

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.connections_accepted, 10);
        assert_eq!(snapshot.bytes_sent, 1000);
    }
}
