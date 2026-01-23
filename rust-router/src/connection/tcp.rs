//! TCP connection handling
//!
//! This module provides the core logic for handling individual TCP connections,
//! including sniffing, outbound selection, and bidirectional proxying.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::time::timeout;
use tracing::{debug, error, info, warn};

use crate::ecmp::{DestKey, EcmpGroupManager, FiveTuple, LbAlgorithm, Protocol};
use crate::error::{ConnectionError, RustRouterError};
use crate::io::{bidirectional_copy, CopyResult};
use crate::outbound::{Outbound, OutboundManager};
use crate::sniff::sniff_tls_sni;
use crate::tproxy::TproxyConnection;

/// Context for handling a TCP connection
pub struct TcpConnectionContext {
    /// The TPROXY connection
    pub conn: TproxyConnection,

    /// Outbound manager
    pub outbound_manager: Arc<OutboundManager>,

    /// ECMP group manager for load balancing
    pub ecmp_group_manager: Option<Arc<EcmpGroupManager>>,

    /// Sniff timeout
    pub sniff_timeout: Duration,

    /// Connect timeout for outbound connections
    pub connect_timeout: Duration,

    /// Default outbound tag
    pub default_outbound: String,

    /// Buffer size for bidirectional copy
    pub buffer_size: usize,
}

/// Result of handling a TCP connection
#[derive(Debug)]
pub struct TcpConnectionResult {
    /// Client address
    pub client_addr: SocketAddr,
    /// Original destination
    pub original_dst: SocketAddr,
    /// Sniffed SNI (if any)
    pub sni: Option<String>,
    /// Outbound tag used
    pub outbound_tag: String,
    /// Copy result (bytes transferred)
    pub copy_result: Option<CopyResult>,
    /// Error message if failed
    pub error: Option<String>,
}

/// Handle a TCP connection through the proxy.
///
/// This function:
/// 1. Optionally sniffs TLS SNI from the initial data
/// 2. Selects the outbound based on routing rules (currently uses default)
/// 3. Connects to the upstream via the selected outbound
/// 4. Performs bidirectional data copy
///
/// # Arguments
///
/// * `ctx` - Connection context with all necessary configuration
///
/// # Returns
///
/// Returns `TcpConnectionResult` with details about the connection handling.
pub async fn handle_tcp_connection(ctx: TcpConnectionContext) -> TcpConnectionResult {
    let client_addr = ctx.conn.client_addr();
    let original_dst = ctx.conn.original_dst();
    let mut stream = ctx.conn.into_stream();

    let mut result = TcpConnectionResult {
        client_addr,
        original_dst,
        sni: None,
        outbound_tag: ctx.default_outbound.clone(),
        copy_result: None,
        error: None,
    };

    // Try to sniff TLS SNI if this looks like a TLS connection
    if is_tls_port(original_dst.port()) {
        match sniff_sni_with_timeout(&mut stream, ctx.sniff_timeout).await {
            Ok(Some(sni)) => {
                debug!("Sniffed TLS SNI: {} for {}", sni, original_dst);
                result.sni = Some(sni);
            }
            Ok(None) => {
                debug!("No SNI found for {}", original_dst);
            }
            Err(e) => {
                debug!("SNI sniffing failed for {}: {}", original_dst, e);
            }
        }
    }

    // TODO: Route selection based on SNI/destination
    // For now, use default outbound
    let outbound_tag = &ctx.default_outbound;

    // Get the outbound with ECMP group resolution
    // This supports both direct outbounds and ECMP load balancing groups
    // Pass SNI for DestHash algorithm (video streaming session affinity)
    let (outbound, actual_outbound_tag) = match resolve_outbound_with_ecmp(
        outbound_tag,
        client_addr,
        original_dst,
        result.sni.as_deref(),
        &ctx.outbound_manager,
        ctx.ecmp_group_manager.as_ref(),
    ) {
        Some(resolved) => resolved,
        None => {
            error!("Outbound '{}' not found", outbound_tag);
            result.error = Some(format!("Outbound '{outbound_tag}' not found"));
            return result;
        }
    };

    result.outbound_tag = actual_outbound_tag.clone();

    // Connect to upstream
    let upstream = match outbound.connect(original_dst, ctx.connect_timeout).await {
        Ok(conn) => conn,
        Err(e) => {
            warn!(
                "Failed to connect to {} via {}: {}",
                original_dst, outbound_tag, e
            );
            result.error = Some(format!("Upstream connection failed: {e}"));
            return result;
        }
    };

    info!(
        "Proxying {} -> {} via {}",
        client_addr, original_dst, outbound_tag
    );

    // Get the stream from the outbound connection
    let mut upstream_stream = upstream.into_stream();

    // Bidirectional copy
    match bidirectional_copy(&mut stream, &mut upstream_stream).await {
        Ok(copy_result) => {
            info!(
                "Connection closed: {} -> {}, {} up / {} down bytes",
                client_addr,
                original_dst,
                copy_result.client_to_upstream,
                copy_result.upstream_to_client
            );
            result.copy_result = Some(copy_result);
        }
        Err(e) => {
            debug!(
                "Connection error: {} -> {}: {}",
                client_addr, original_dst, e
            );
            result.error = Some(format!("Transfer error: {e}"));
        }
    }

    result
}

/// Sniff TLS SNI with timeout
async fn sniff_sni_with_timeout(
    stream: &mut tokio::net::TcpStream,
    sniff_timeout: Duration,
) -> Result<Option<String>, RustRouterError> {
    // Peek at the initial data
    let mut buf = [0u8; 1024];

    let n = match timeout(sniff_timeout, stream.peek(&mut buf)).await {
        Ok(Ok(n)) => n,
        Ok(Err(e)) => return Err(ConnectionError::from(e).into()),
        Err(_) => {
            // Timeout - just continue without SNI
            return Ok(None);
        }
    };

    if n == 0 {
        return Ok(None);
    }

    // Try to parse TLS ClientHello and extract SNI
    Ok(sniff_tls_sni(&buf[..n]))
}

/// Check if a port is commonly used for TLS
fn is_tls_port(port: u16) -> bool {
    matches!(
        port,
        443   // HTTPS
        | 8443  // Alternative HTTPS
        | 853   // DNS over TLS
        | 993   // IMAPS
        | 995   // POP3S
        | 465   // SMTPS
        | 636   // LDAPS
        | 989   // FTPS data
        | 990   // FTPS control
        | 5061  // SIP over TLS
    )
}

/// Resolve outbound tag to actual outbound, with ECMP group support.
///
/// If the tag refers to an ECMP group, this function selects a member using
/// the configured load balancing algorithm:
/// - `FiveTupleHash` (default): Hash src/dst IP+port for connection affinity
/// - `DestHash`: Hash destination (domain or IP) for session affinity (video streaming)
/// - `DestHashLeastLoad`: Session affinity + intelligent load balancing for new sessions
///
/// # Arguments
///
/// * `tag` - The outbound or group tag to resolve
/// * `client_addr` - Client socket address
/// * `original_dst` - Original destination socket address
/// * `domain` - Optional domain name from TLS SNI (used by DestHash/DestHashLeastLoad)
/// * `outbound_manager` - Manager for direct outbounds
/// * `ecmp_group_manager` - Optional ECMP group manager
///
/// # Returns
///
/// Tuple of (outbound, actual_tag) if found, None otherwise
fn resolve_outbound_with_ecmp(
    tag: &str,
    client_addr: SocketAddr,
    original_dst: SocketAddr,
    domain: Option<&str>,
    outbound_manager: &OutboundManager,
    ecmp_group_manager: Option<&Arc<EcmpGroupManager>>,
) -> Option<(Arc<dyn Outbound>, String)> {
    // Try direct lookup first
    if let Some(outbound) = outbound_manager.get(tag) {
        return Some((outbound, tag.to_string()));
    }

    // Check if it's an ECMP group
    if let Some(ecmp_mgr) = ecmp_group_manager {
        if ecmp_mgr.has_group(tag) {
            // Select member using the group's load balancing algorithm
            if let Some(group) = ecmp_mgr.get_group(tag) {
                // Choose selection method based on algorithm
                let select_result = match group.algorithm() {
                    LbAlgorithm::DestHash => {
                        // DestHash: hash(source_ip + domain/dest_ip) for per-client session affinity
                        // Same client to same domain → same exit; different clients → load balanced
                        let dest_key = DestKey::new(client_addr.ip(), domain, original_dst.ip());
                        debug!(
                            "ECMP group '{}' using DestHash with key: {}",
                            tag, dest_key
                        );
                        group.select_by_dest(&dest_key)
                    }
                    LbAlgorithm::DestHashLeastLoad => {
                        // DestHashLeastLoad: session affinity + intelligent load balancing
                        // New sessions: select least loaded exit; existing: use cached selection
                        let dest_key = DestKey::new(client_addr.ip(), domain, original_dst.ip());
                        debug!(
                            "ECMP group '{}' using DestHashLeastLoad with key: {}",
                            tag, dest_key
                        );
                        group.select_by_dest_least_load(&dest_key)
                    }
                    _ => {
                        // Default: use five-tuple hash for connection affinity
                        let five_tuple = FiveTuple::new(
                            client_addr.ip(),
                            original_dst.ip(),
                            client_addr.port(),
                            original_dst.port(),
                            Protocol::Tcp,
                        );
                        group.select_by_connection(&five_tuple)
                    }
                };

                match select_result {
                    Ok(member_tag) => {
                        debug!(
                            "ECMP group '{}' selected member '{}' for TCP {} -> {} (domain: {:?})",
                            tag, member_tag, client_addr, original_dst, domain
                        );
                        // Recursively resolve the member
                        if let Some(outbound) = outbound_manager.get(&member_tag) {
                            return Some((outbound, member_tag));
                        }
                        warn!(
                            "ECMP member '{}' not found in outbound_manager",
                            member_tag
                        );
                    }
                    Err(e) => {
                        warn!("ECMP group '{}' failed to select member: {}", tag, e);
                    }
                }
            }
        }
    }

    None
}

/// Spawn a task to handle a TCP connection with proper instrumentation
pub fn spawn_tcp_handler(
    ctx: TcpConnectionContext,
    stats: Arc<crate::connection::ConnectionStats>,
) -> tokio::task::JoinHandle<()> {
    let client_addr = ctx.conn.client_addr();
    let original_dst = ctx.conn.original_dst();

    let span = tracing::info_span!(
        "tcp_connection",
        client = %client_addr,
        dst = %original_dst,
    );

    tokio::spawn(async move {
        let _enter = span.enter();

        let result = handle_tcp_connection(ctx).await;

        // Update stats
        if let Some(ref copy_result) = result.copy_result {
            stats.record_completed(copy_result.client_to_upstream, copy_result.upstream_to_client);
        } else {
            stats.record_error();
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_tls_port() {
        assert!(is_tls_port(443));
        assert!(is_tls_port(8443));
        assert!(is_tls_port(853));
        assert!(!is_tls_port(80));
        assert!(!is_tls_port(8080));
    }

    #[test]
    fn test_tcp_connection_result() {
        let result = TcpConnectionResult {
            client_addr: "127.0.0.1:12345".parse().unwrap(),
            original_dst: "8.8.8.8:443".parse().unwrap(),
            sni: Some("example.com".into()),
            outbound_tag: "direct".into(),
            copy_result: Some(CopyResult {
                client_to_upstream: 100,
                upstream_to_client: 200,
            }),
            error: None,
        };

        assert_eq!(result.sni, Some("example.com".into()));
        assert!(result.error.is_none());
    }
}
