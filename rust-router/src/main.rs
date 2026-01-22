//! rust-router: High-performance transparent proxy router
//!
//! This is the main entry point for the production router.
//!
//! # Usage
//!
//! ```bash
//! # Run with default configuration
//! sudo ./rust-router
//!
//! # Run with custom configuration
//! sudo ./rust-router -c /path/to/config.json
//!
//! # Run with environment overrides
//! RUST_ROUTER_LOG_LEVEL=debug sudo ./rust-router
//!
//! # Run with userspace WireGuard (Phase 6)
//! RUST_ROUTER_USERSPACE_WG=true sudo ./rust-router
//! ```

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Instant;

use anyhow::Result;
use tokio::signal;
use tracing::{debug, error, info, warn, Level};
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::EnvFilter;

use rust_router::chain::ChainManager;
use rust_router::config::{load_config_with_env, Config};
use rust_router::connection::{
    run_accept_loop, ConnectionManager, UdpPacketProcessor, UdpProcessorConfig,
    UdpSessionConfig, UdpSessionManager,
};
use rust_router::dns::cache::DnsCache;
use rust_router::dns::client::UpstreamPool;
use rust_router::dns::filter::BlockFilter;
use rust_router::dns::log::QueryLogger;
use rust_router::dns::server::{DnsHandler, DnsRateLimiter, TcpDnsServer, UdpDnsServer};
use rust_router::dns::split::DnsRouter;
use rust_router::dns::{
    BlockingConfig, CacheConfig, DnsConfig, RateLimitConfig, UpstreamConfig, UpstreamProtocol,
};
use rust_router::ecmp::group::EcmpGroupManager;
use rust_router::egress::manager::WgEgressManager;
use rust_router::egress::reply::WgReplyHandler;
use rust_router::ingress::manager::WgIngressManager;
use rust_router::ingress::WgIngressConfig;
use rust_router::ipc::{DnsEngine, IpcHandler, IpcServer};
use rust_router::outbound::{OutboundManager, OutboundManagerBuilder};
use rust_router::peer::manager::PeerManager;
use rust_router::rules::{RuleEngine, RuleEngineRoutingCallback, RoutingSnapshotBuilder};
use rust_router::tproxy::{has_net_admin_capability, is_root, TproxyListener, UdpWorkerPool, UdpWorkerPoolConfig};

/// Command-line arguments
struct Args {
    /// Configuration file path
    config_path: PathBuf,
    /// Generate default configuration
    generate_config: bool,
    /// Check configuration only
    check_config: bool,
}

impl Args {
    fn parse() -> Self {
        let mut args = std::env::args().skip(1);
        let mut config_path = PathBuf::from("/etc/rust-router/config.json");
        let mut generate_config = false;
        let mut check_config = false;

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "-c" | "--config" => {
                    if let Some(path) = args.next() {
                        config_path = PathBuf::from(path);
                    }
                }
                "-g" | "--generate-config" => {
                    generate_config = true;
                }
                "--check" => {
                    check_config = true;
                }
                "-h" | "--help" => {
                    print_help();
                    std::process::exit(0);
                }
                "-v" | "--version" => {
                    println!("rust-router v{}", rust_router::VERSION);
                    std::process::exit(0);
                }
                _ => {
                    eprintln!("Unknown argument: {}", arg);
                    print_help();
                    std::process::exit(1);
                }
            }
        }

        Self {
            config_path,
            generate_config,
            check_config,
        }
    }
}

fn print_help() {
    println!(
        r#"rust-router v{}

High-performance transparent proxy router with TPROXY support.

USAGE:
    rust-router [OPTIONS]

OPTIONS:
    -c, --config <PATH>     Configuration file path [default: /etc/rust-router/config.json]
    -g, --generate-config   Generate default configuration and exit
    --check                 Check configuration and exit
    -h, --help             Print help information
    -v, --version          Print version information

ENVIRONMENT:
    RUST_ROUTER_LISTEN_ADDR      Override listen address
    RUST_ROUTER_LOG_LEVEL        Override log level (trace, debug, info, warn, error)
    RUST_ROUTER_MAX_CONNECTIONS  Override maximum connections
    RUST_ROUTER_IPC_SOCKET       Override IPC socket path

    Phase 6 (Userspace WireGuard):
    RUST_ROUTER_USERSPACE_WG     Enable userspace WireGuard mode (true/false)
    RUST_ROUTER_WG_LISTEN_PORT   WireGuard listen port (default: 36100)
    RUST_ROUTER_WG_PRIVATE_KEY   WireGuard private key (Base64)
    RUST_ROUTER_WG_SUBNET        WireGuard ingress subnet (default: 10.25.0.0/24)
    RUST_ROUTER_NODE_TAG         Local node tag for multi-node peering

REQUIREMENTS:
    - Linux kernel with TPROXY support
    - CAP_NET_ADMIN capability (or root)
    - iptables TPROXY rules configured

EXAMPLE:
    # Configure iptables for TPROXY
    iptables -t mangle -A PREROUTING -i wg-ingress -p tcp -j TPROXY \
        --on-ip 127.0.0.1 --on-port 7893 --tproxy-mark 0x1
    ip rule add fwmark 0x1 lookup 100
    ip route add local 0.0.0.0/0 dev lo table 100

    # Run the router
    sudo rust-router -c /etc/rust-router/config.json

    # Run with userspace WireGuard (Phase 6)
    RUST_ROUTER_USERSPACE_WG=true \
    RUST_ROUTER_WG_PRIVATE_KEY=<base64_key> \
    sudo rust-router -c /etc/rust-router/config.json
"#,
        rust_router::VERSION
    );
}

/// Initialize logging
///
/// Log level priority (highest to lowest):
/// 1. `RUST_LOG` environment variable (standard Rust logging)
/// 2. `RUST_ROUTER_LOG_LEVEL` environment variable
/// 3. Config file `log.level` setting
/// 4. Default: "info"
fn init_logging(config: &Config) {
    let level = match config.log.level.to_lowercase().as_str() {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "info" => Level::INFO,
        "warn" => Level::WARN,
        "error" => Level::ERROR,
        _ => Level::INFO,
    };

    // Build filter: RUST_LOG takes precedence, then config level as default
    // EnvFilter::from_default_env() reads RUST_LOG if set
    let filter = EnvFilter::from_default_env()
        .add_directive(level.into())
        // Reduce noise from dependencies
        .add_directive("hyper=warn".parse().unwrap())
        .add_directive("tokio=warn".parse().unwrap())
        .add_directive("h2=warn".parse().unwrap())
        .add_directive("rustls=warn".parse().unwrap());

    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(config.log.target)
        .with_span_events(FmtSpan::CLOSE);

    if config.log.format == "json" {
        subscriber.json().init();
    } else {
        subscriber.init();
    }
    
    // Log effective configuration
    if std::env::var("RUST_LOG").is_ok() {
        info!("Log level from RUST_LOG environment variable");
    } else {
        info!("Log level: {}", config.log.level);
    }
}

/// Check system prerequisites
fn check_prerequisites() -> Result<()> {
    // Check for root/capabilities
    if !is_root() && !has_net_admin_capability() {
        warn!("Not running as root and CAP_NET_ADMIN not detected");
        warn!("TPROXY requires CAP_NET_ADMIN capability");
        // Don't fail - let the socket creation fail with a clearer error
    }

    Ok(())
}

/// Build outbound manager from configuration
fn build_outbound_manager(config: &Config) -> Arc<OutboundManager> {
    let mut builder = OutboundManagerBuilder::new();
    builder.add_all_from_config(&config.outbounds);
    let manager = builder.build();

    info!(
        "Initialized {} outbounds: {:?}",
        manager.len(),
        manager.tags()
    );

    Arc::new(manager)
}

/// Phase 6 configuration from environment variables
#[derive(Debug)]
struct Phase6Config {
    /// Enable userspace WireGuard mode
    userspace_wg: bool,
    /// WireGuard listen port
    wg_listen_port: u16,
    /// WireGuard private key (Base64)
    wg_private_key: Option<String>,
    /// WireGuard ingress subnet
    wg_subnet: String,
    /// Local node tag for multi-node peering
    node_tag: String,
    /// WireGuard ingress local IP
    wg_local_ip: IpAddr,
    /// Enable batch I/O for userspace WireGuard ingress
    wg_batch_io: bool,
    /// Enable SOCKS5 inbound server for Xray integration
    socks5_inbound_enabled: bool,
    /// SOCKS5 inbound listen port
    socks5_inbound_port: u16,
}

impl Phase6Config {
    /// Load Phase 6 configuration from environment variables
    fn from_env() -> Self {
        let userspace_wg = std::env::var("RUST_ROUTER_USERSPACE_WG")
            .map(|v| v == "true")
            .unwrap_or(false);

        let wg_listen_port = std::env::var("RUST_ROUTER_WG_LISTEN_PORT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(36100);

        let wg_private_key = std::env::var("RUST_ROUTER_WG_PRIVATE_KEY").ok();

        let wg_subnet = std::env::var("RUST_ROUTER_WG_SUBNET")
            .unwrap_or_else(|_| "10.25.0.0/24".to_string());

        let node_tag = std::env::var("RUST_ROUTER_NODE_TAG")
            .unwrap_or_else(|_| hostname::get()
                .map(|h| h.to_string_lossy().to_string())
                .unwrap_or_else(|_| "local-node".to_string()));

        // Default local IP is .1 in the subnet
        let wg_local_ip = std::env::var("RUST_ROUTER_WG_LOCAL_IP")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or_else(|| IpAddr::V4(Ipv4Addr::new(10, 25, 0, 1)));

        // Batch I/O can cause readiness spin with userspace WG; keep default disabled.
        let wg_batch_io = std::env::var("RUST_ROUTER_WG_BATCH_IO")
            .map(|v| v == "true")
            .unwrap_or(false);

        // SOCKS5 inbound for Xray integration (default: disabled)
        let socks5_inbound_enabled = std::env::var("RUST_ROUTER_SOCKS5_INBOUND")
            .map(|v| v == "true")
            .unwrap_or(false);

        let socks5_inbound_port = std::env::var("RUST_ROUTER_SOCKS5_INBOUND_PORT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(38501);

        Self {
            userspace_wg,
            wg_listen_port,
            wg_private_key,
            wg_subnet,
            node_tag,
            wg_local_ip,
            wg_batch_io,
            socks5_inbound_enabled,
            socks5_inbound_port,
        }
    }

    /// Check if userspace WireGuard can be enabled
    fn can_enable_userspace_wg(&self) -> bool {
        self.userspace_wg && self.wg_private_key.is_some()
    }
}

/// Main application entry point
#[tokio::main]
async fn main() -> Result<()> {
    let start_time = Instant::now();

    // Parse arguments
    let args = Args::parse();

    // Handle generate-config
    if args.generate_config {
        rust_router::config::create_default_config(&args.config_path)?;
        println!("Generated default configuration at {:?}", args.config_path);
        return Ok(());
    }

    // Load configuration
    let config = load_config_with_env(&args.config_path)
        .map_err(|e| anyhow::anyhow!("Failed to load configuration from {:?}: {}", args.config_path, e))?;

    // Handle check-config
    if args.check_config {
        println!("Configuration is valid");
        return Ok(());
    }

    // Initialize logging
    init_logging(&config);

    info!("rust-router v{}", rust_router::VERSION);
    info!("Configuration loaded from {:?}", args.config_path);

    // Check prerequisites
    check_prerequisites()?;

    // Build outbound manager
    let outbound_manager = build_outbound_manager(&config);

    // Create rule engine with default routing snapshot
    let routing_snapshot = RoutingSnapshotBuilder::new()
        .default_outbound(&config.default_outbound)
        .version(1)
        .build()
        .expect("Failed to create default routing snapshot");
    let rule_engine = Arc::new(RuleEngine::new(routing_snapshot));

    // Phase 6-Fix.AI: Create EcmpGroupManager early so we can pass it to ConnectionManager
    // This is needed for ECMP load balancing group support in routing
    let ecmp_group_manager = Arc::new(EcmpGroupManager::new());
    debug!("Created EcmpGroupManager for load balancing");

    // Create connection manager with ECMP support
    let mut connection_manager = ConnectionManager::new(
        &config.connection,
        Arc::clone(&outbound_manager),
        config.default_outbound.clone(),
        config.listen.sniff_timeout(),
    );
    connection_manager.set_ecmp_group_manager(Arc::clone(&ecmp_group_manager));
    let connection_manager = Arc::new(connection_manager);

    // Create TPROXY listener (TCP)
    let listener = TproxyListener::bind(&config.listen)
        .map_err(|e| anyhow::anyhow!("Failed to create TPROXY listener: {}", e))?;

    // Create UDP components (if enabled)
    let (udp_session_manager, udp_worker_pool, udp_buffer_pool) = if config.listen.udp_enabled {
        // Note: UdpSessionManager is kept for backwards compatibility with IPC handler interface
        // The actual session tracking happens inside UdpPacketProcessor's handle_cache
        let session_manager = Arc::new(UdpSessionManager::new(UdpSessionConfig::default()));

        // Create UDP packet processor with ECMP group manager
        // Phase 6-Fix.AI: Set ECMP manager for load balancing support
        let processor_config = UdpProcessorConfig::default();
        let mut processor = UdpPacketProcessor::new(processor_config);
        processor.set_ecmp_group_manager(Arc::clone(&ecmp_group_manager));
        let processor = Arc::new(processor);

        // Determine worker count
        let num_workers = config.listen.udp_workers.unwrap_or_else(num_cpus::get);

        // Create worker pool with custom configuration and rule engine integration
        let pool_config = UdpWorkerPoolConfig::default()
            .with_workers(num_workers)
            .with_buffer_pool_capacity(config.listen.udp_buffer_pool_size / num_workers.max(1));

        // Pass rule_engine and outbound_manager for proper UDP routing
        let worker_pool = UdpWorkerPool::with_config(
            &config.listen,
            pool_config,
            processor,
            Arc::clone(&rule_engine),
            Arc::clone(&outbound_manager),
        )
        .map_err(|e| anyhow::anyhow!("Failed to create UDP worker pool: {}", e))?;

        // Get buffer pool from worker pool
        let buffer_pool = Arc::clone(worker_pool.buffer_pool());

        info!(
            "UDP worker pool created with {} workers (rule engine integrated)",
            worker_pool.num_workers()
        );

        // Wrap in Arc for sharing with IPC handler
        let worker_pool_arc = Arc::new(worker_pool);

        (
            Some(session_manager),
            Some(worker_pool_arc),
            Some(buffer_pool),
        )
    } else {
        (None, None, None)
    };

    info!(
        "rust-router ready on {} (TCP: {}, UDP: {}, UDP workers: {})",
        config.listen.address,
        config.listen.tcp_enabled,
        config.listen.udp_enabled,
        config.listen.udp_workers.unwrap_or(0)
    );

    // ========================================================================
    // Phase 6: Load Phase 6 configuration and create managers
    // ========================================================================
    let phase6_config = Phase6Config::from_env();

    info!(
        "Phase 6 config: userspace_wg={}, node_tag={}, wg_port={}",
        phase6_config.userspace_wg,
        phase6_config.node_tag,
        phase6_config.wg_listen_port
    );

    // Create PeerManager (always created for IPC support)
    let peer_manager = Arc::new(PeerManager::new(phase6_config.node_tag.clone()));
    debug!("Created PeerManager with node tag: {}", phase6_config.node_tag);

    // Create ChainManager (always created for IPC support)
    let chain_manager = Arc::new(ChainManager::new(phase6_config.node_tag.clone()));
    debug!("Created ChainManager with node tag: {}", phase6_config.node_tag);

    // Wire up the routing callback so chains register with FwmarkRouter
    let routing_callback = Arc::new(RuleEngineRoutingCallback::new(Arc::clone(&rule_engine)));
    chain_manager.set_routing_callback(routing_callback);
    debug!("Set RuleEngineRoutingCallback on ChainManager");

    // Phase 12-Fix.P: Wire up the network client for 2PC messages
    // This allows ChainManager to send PREPARE/COMMIT/ABORT to remote nodes via WG tunnels
    let network_client = Arc::new(rust_router::chain::ForwardPeerNetworkClient::new(
        Arc::clone(&peer_manager),
        phase6_config.node_tag.clone(),
    ));
    chain_manager.set_network_client(network_client);
    debug!("Set ForwardPeerNetworkClient on ChainManager");

    // Phase 6-Fix.AI: EcmpGroupManager is now created earlier (before ConnectionManager)
    // so it can be passed to both TCP and UDP handlers for load balancing support

    // Create WireGuard egress manager (always created for IPC support)
    // The reply handler forwards decrypted packets back to the ingress reply router
    // For peer tunnels (peer-*), packets go to the peer tunnel processor for chain routing
    let reply_router_tx: Arc<parking_lot::RwLock<Option<tokio::sync::mpsc::Sender<rust_router::ingress::ReplyPacket>>>> =
        Arc::new(parking_lot::RwLock::new(None));
    let peer_tunnel_tx: Arc<parking_lot::RwLock<Option<tokio::sync::mpsc::Sender<rust_router::ingress::ReplyPacket>>>> =
        Arc::new(parking_lot::RwLock::new(None));
    let reply_stats = Arc::new(rust_router::ingress::IngressReplyStats::default());
    let forwarding_stats = Arc::new(rust_router::ingress::ForwardingStats::default());
    let peer_tunnel_stats = Arc::new(rust_router::ingress::PeerTunnelProcessorStats::default());

    let wg_reply_handler = Arc::new(WgReplyHandler::new({
        let reply_router_tx = Arc::clone(&reply_router_tx);
        let peer_tunnel_tx = Arc::clone(&peer_tunnel_tx);
        let reply_stats = Arc::clone(&reply_stats);
        let peer_tunnel_stats = Arc::clone(&peer_tunnel_stats);
        move |packet, tunnel_tag: String| {
            // Route peer tunnel packets (peer-*) to the peer tunnel processor
            // for DSCP-based chain routing on Terminal nodes
            if tunnel_tag.starts_with("peer-") {
                peer_tunnel_stats
                    .packets_received
                    .fetch_add(1, Ordering::Relaxed);

                let maybe_tx = peer_tunnel_tx.read().clone();
                if let Some(tx) = maybe_tx {
                    match tx.try_send(rust_router::ingress::ReplyPacket { packet, tunnel_tag: tunnel_tag.clone() }) {
                        Ok(()) => {
                            // Peer tunnel packet successfully routed to processor
                        }
                        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                            warn!("Peer tunnel processor queue full; dropping packet from '{}'", tunnel_tag);
                        }
                        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                            warn!("Peer tunnel processor unavailable; dropping packet from '{}'", tunnel_tag);
                        }
                    }
                } else {
                    debug!("Peer tunnel processor not ready; dropping packet from '{}'", tunnel_tag);
                }
                return;
            }

            // Regular egress tunnel replies go to the reply router
            reply_stats
                .packets_received
                .fetch_add(1, Ordering::Relaxed);

            let maybe_tx = reply_router_tx.read().clone();
            if let Some(tx) = maybe_tx {
                match tx.try_send(rust_router::ingress::ReplyPacket { packet, tunnel_tag: tunnel_tag.clone() }) {
                    Ok(()) => {
                        reply_stats
                            .packets_enqueued
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    Err(tokio::sync::mpsc::error::TrySendError::Full(reply)) => {
                        reply_stats.queue_full.fetch_add(1, Ordering::Relaxed);
                        warn!(
                            "Reply router queue full; dropping reply from '{}'",
                            reply.tunnel_tag
                        );
                    }
                    Err(tokio::sync::mpsc::error::TrySendError::Closed(reply)) => {
                        reply_stats
                            .router_unavailable
                            .fetch_add(1, Ordering::Relaxed);
                        warn!(
                            "Reply router unavailable; dropping reply from '{}'",
                            reply.tunnel_tag
                        );
                    }
                }
            } else {
                reply_stats
                    .router_unavailable
                    .fetch_add(1, Ordering::Relaxed);
                debug!(
                    "Reply router not ready; dropping reply from '{}'",
                    tunnel_tag
                );
            }
        }
    }));
    let wg_egress_manager = Arc::new(WgEgressManager::new(wg_reply_handler));
    debug!("Created WgEgressManager");

    // Create WireGuard ingress manager (only if userspace mode is enabled and configured)
    let wg_ingress_manager: Option<Arc<WgIngressManager>> = if phase6_config.can_enable_userspace_wg() {
        let private_key = phase6_config.wg_private_key.as_ref().unwrap();
        let listen_addr = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            phase6_config.wg_listen_port,
        );
        let allowed_subnet: ipnet::IpNet = phase6_config.wg_subnet.parse()
            .map_err(|e| anyhow::anyhow!("Invalid WG subnet '{}': {}", phase6_config.wg_subnet, e))?;

        let wg_ingress_config = WgIngressConfig::builder()
            .private_key(private_key)
            .listen_addr(listen_addr)
            .local_ip(phase6_config.wg_local_ip)
            .allowed_subnet(allowed_subnet)
            .use_batch_io(phase6_config.wg_batch_io)
            .build();

        match WgIngressManager::new(wg_ingress_config, Arc::clone(&rule_engine)) {
            Ok(manager) => {
                info!(
                    "Created WgIngressManager (userspace WireGuard on port {})",
                    phase6_config.wg_listen_port
                );
                manager.set_chain_manager(Arc::clone(&chain_manager));
                Some(Arc::new(manager))
            }
            Err(e) => {
                error!("Failed to create WgIngressManager: {}", e);
                warn!("Userspace WireGuard will be disabled");
                None
            }
        }
    } else {
        if phase6_config.userspace_wg {
            warn!(
                "Userspace WireGuard requested but RUST_ROUTER_WG_PRIVATE_KEY not set"
            );
        }
        None
    };

    // Create base IPC handler
    let ipc_handler = if let (Some(session_mgr), Some(worker_pool), Some(buffer_pool)) =
        (&udp_session_manager, &udp_worker_pool, &udp_buffer_pool)
    {
        IpcHandler::new_with_udp(
            Arc::clone(&connection_manager),
            Arc::clone(&outbound_manager),
            Arc::clone(&rule_engine),
            Arc::clone(session_mgr),
            Arc::clone(worker_pool),
            Arc::clone(buffer_pool),
        )
    } else {
        IpcHandler::new(
            Arc::clone(&connection_manager),
            Arc::clone(&outbound_manager),
            Arc::clone(&rule_engine),
        )
    };

    // Wire up Phase 6 managers to IPC handler
    let mut ipc_handler = ipc_handler
        .with_peer_manager(Arc::clone(&peer_manager))
        .with_chain_manager(Arc::clone(&chain_manager), phase6_config.node_tag.clone())
        .with_ecmp_group_manager(Arc::clone(&ecmp_group_manager))
        .with_wg_egress_manager(Arc::clone(&wg_egress_manager));

    // Add WireGuard ingress manager if available
    if let Some(ref ingress_mgr) = wg_ingress_manager {
        ipc_handler = ipc_handler.with_wg_ingress_manager(Arc::clone(ingress_mgr));
        ipc_handler = ipc_handler.with_ingress_stats(
            Arc::clone(&forwarding_stats),
            Arc::clone(&reply_stats),
        );
    }

    // ========================================================================
    // Phase 7: DNS Engine Initialization
    // ========================================================================

    // Create DNS configuration from environment variables with default upstream servers
    let dns_config = DnsConfig::from_env()
        .with_upstream(UpstreamConfig::new("cloudflare", "1.1.1.1:53", UpstreamProtocol::Udp))
        .with_upstream(UpstreamConfig::new("cloudflare-backup", "1.0.0.1:53", UpstreamProtocol::Udp))
        .with_upstream(UpstreamConfig::new("google", "8.8.8.8:53", UpstreamProtocol::Udp))
        .with_cache(CacheConfig::default())
        .with_blocking(BlockingConfig::default())
        .with_rate_limit(RateLimitConfig::default());

    info!(
        "DNS engine configuration: {} upstreams, cache enabled={}, blocking enabled={}",
        dns_config.upstreams.len(),
        dns_config.cache.enabled,
        dns_config.blocking.enabled
    );

    // Create DNS components
    let dns_cache = Arc::new(DnsCache::new(dns_config.cache.clone()));

    // Create upstream clients from configuration
    let mut upstreams: Vec<Box<dyn rust_router::dns::client::DnsUpstream>> = Vec::new();
    for upstream_config in &dns_config.upstreams {
        match rust_router::dns::client::UdpClient::new(upstream_config.clone()) {
            Ok(client) => {
                info!("Created DNS upstream: {} ({})", upstream_config.tag, upstream_config.address);
                upstreams.push(Box::new(client));
            }
            Err(e) => {
                warn!("Failed to create DNS upstream {}: {}", upstream_config.tag, e);
            }
        }
    }

    if upstreams.is_empty() {
        warn!("No DNS upstreams configured - DNS engine will not be able to resolve queries");
    }

    let dns_upstream_pool = Arc::new(UpstreamPool::new(upstreams));
    let dns_block_filter = Arc::new(BlockFilter::new(dns_config.blocking.clone()));
    let dns_router = Arc::new(DnsRouter::new("cloudflare".to_string()));
    let dns_query_logger = Arc::new(QueryLogger::disabled());

    // Create DNS engine for IPC integration
    let dns_engine = Arc::new(DnsEngine::new(
        Arc::clone(&dns_cache),
        Arc::clone(&dns_upstream_pool),
        Arc::clone(&dns_block_filter),
        Arc::clone(&dns_router),
        Arc::clone(&dns_query_logger),
        dns_config.clone(),
    ));

    // Wire up DNS engine to IPC handler
    let ipc_handler = ipc_handler.with_dns_engine(Arc::clone(&dns_engine));

    let ipc_handler = Arc::new(ipc_handler);

    info!(
        "IPC handler configured with Phase 6 managers (peer={}, chain={}, ecmp={}, wg_ingress={}, wg_egress={}) and DNS engine",
        true, true, true,
        wg_ingress_manager.is_some(),
        true
    );

    let ipc_server = IpcServer::new(config.ipc.clone(), Arc::clone(&ipc_handler));
    let ipc_shutdown = ipc_server.shutdown_sender();

    // Spawn IPC server
    let ipc_handle = tokio::spawn(async move {
        if let Err(e) = ipc_server.run().await {
            error!("IPC server error: {}", e);
        }
    });

    // ========================================================================
    // Phase 7: Start DNS Servers (UDP + TCP on 127.0.0.1:7853)
    // ========================================================================

    // Create rate limiter and handler for DNS servers
    let dns_rate_limiter = Arc::new(DnsRateLimiter::new(&dns_config.rate_limit));
    let dns_handler = Arc::new(DnsHandler::with_components(
        Arc::clone(&dns_rate_limiter),
        Arc::clone(&dns_cache),
        Arc::clone(&dns_block_filter),
        Arc::clone(&dns_upstream_pool),
        Arc::clone(&dns_router),
        Arc::clone(&dns_query_logger),
    ));

    // Create shutdown channels for DNS servers
    let (dns_udp_shutdown_tx, dns_udp_shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let (dns_tcp_shutdown_tx, dns_tcp_shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    // Start UDP DNS server
    let dns_udp_addr = dns_config.listen_udp;
    let dns_udp_handle = {
        let handler = Arc::clone(&dns_handler);
        tokio::spawn(async move {
            match UdpDnsServer::bind(dns_udp_addr, handler).await {
                Ok(server) => {
                    info!("DNS UDP server listening on {}", dns_udp_addr);
                    if let Err(e) = server.run_until_shutdown(dns_udp_shutdown_rx).await {
                        error!("DNS UDP server error: {}", e);
                    }
                    info!("DNS UDP server shutdown complete");
                }
                Err(e) => {
                    error!("Failed to start DNS UDP server on {}: {}", dns_udp_addr, e);
                }
            }
        })
    };

    // Start TCP DNS server
    let dns_tcp_addr = dns_config.listen_tcp;
    let dns_tcp_config = dns_config.tcp.clone();
    let dns_tcp_handle = {
        let handler = Arc::clone(&dns_handler);
        tokio::spawn(async move {
            match TcpDnsServer::bind(dns_tcp_addr, handler, dns_tcp_config).await {
                Ok(server) => {
                    info!("DNS TCP server listening on {}", dns_tcp_addr);
                    if let Err(e) = server.run_until_shutdown(dns_tcp_shutdown_rx).await {
                        error!("DNS TCP server error: {}", e);
                    }
                    info!("DNS TCP server shutdown complete");
                }
                Err(e) => {
                    error!("Failed to start DNS TCP server on {}: {}", dns_tcp_addr, e);
                }
            }
        })
    };

    info!(
        "DNS servers started on {} (UDP) and {} (TCP)",
        dns_config.listen_udp, dns_config.listen_tcp
    );

    // ========================================================================
    // SOCKS5 Inbound Server (for Xray integration)
    // ========================================================================
    let socks5_server_handle: Option<tokio::task::JoinHandle<()>> = if phase6_config.socks5_inbound_enabled {
        use rust_router::ingress::{Socks5Server, Socks5ServerConfig};

        let socks5_config = Socks5ServerConfig {
            listen_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), phase6_config.socks5_inbound_port),
            ..Default::default()
        };

        let socks5_server = Socks5Server::new(
            socks5_config,
            Arc::clone(&rule_engine),
            Arc::clone(&outbound_manager),
        );

        info!(
            "SOCKS5 inbound server starting on 127.0.0.1:{}",
            phase6_config.socks5_inbound_port
        );

        let handle = tokio::spawn(async move {
            if let Err(e) = socks5_server.run().await {
                error!("SOCKS5 inbound server error: {}", e);
            }
        });

        Some(handle)
    } else {
        debug!("SOCKS5 inbound server not enabled (set RUST_ROUTER_SOCKS5_INBOUND=true to enable)");
        None
    };

    // ========================================================================
    // Phase 6: Start userspace WireGuard ingress if enabled
    // ========================================================================
    // Track forwarding task handle for graceful shutdown
    let mut forwarding_task_handle: Option<tokio::task::JoinHandle<()>> = None;
    let mut reply_task_handle: Option<tokio::task::JoinHandle<()>> = None;
    let mut peer_tunnel_task_handle: Option<tokio::task::JoinHandle<()>> = None;

    if let Some(ref ingress_mgr) = wg_ingress_manager {
        info!("Starting userspace WireGuard ingress...");

        // Start the manager - this spawns its own internal packet processing task
        if let Err(e) = ingress_mgr.start().await {
            error!("Failed to start WireGuard ingress manager: {}", e);
            // Continue without WireGuard ingress, but log the error
        } else {
            info!(
                "WireGuard ingress started on {} (userspace mode)",
                ingress_mgr.listen_addr()
            );

            // Take the packet receiver and spawn forwarding task
            if let Some(packet_rx) = ingress_mgr.take_packet_receiver().await {
                let tcp_manager = Arc::new(
                    rust_router::ingress::TcpConnectionManager::new(
                        std::time::Duration::from_secs(300), // 5 minute connection timeout
                    ),
                );
                let session_tracker = Arc::new(
                    rust_router::ingress::IngressSessionTracker::new(
                        std::time::Duration::from_secs(300), // 5 minute session TTL
                    ),
                );
                // Clone session_tracker for IPC handler before it's moved to forwarding task
                let session_tracker_for_ipc = Arc::clone(&session_tracker);
                let fwd_stats = Arc::clone(&forwarding_stats);

                // Create IP-to-domain cache for domain-based routing
                // This cache is populated by parsing DNS responses
                let dns_cache = Arc::new(rust_router::ingress::IpDomainCache::new(
                    10000, // Max 10,000 IP-domain mappings
                    300,   // Default TTL: 5 minutes
                ));
                info!("IP-domain cache enabled for WireGuard ingress routing");

                // Set DNS cache on the processor for domain lookups
                ingress_mgr.processor().set_dns_cache(Arc::clone(&dns_cache));

                let (reply_tx, reply_rx) = tokio::sync::mpsc::channel(8192);
                // Clone reply_tx for direct UDP reply handling before storing in reply_router_tx
                let direct_reply_tx = reply_tx.clone();
                *reply_router_tx.write() = Some(reply_tx);

                let reply_handle = rust_router::ingress::spawn_reply_router(
                    reply_rx,
                    Arc::clone(ingress_mgr),
                    Arc::clone(&session_tracker),
                    Arc::clone(&reply_stats),
                    Some(dns_cache), // Pass DNS cache to reply router for parsing DNS responses
                );

                // Spawn peer tunnel processor for chain routing on Terminal nodes
                // This processes packets from peer-* tunnels through the ingress processor
                // to handle DSCP-based routing (e.g., route to exit egress on Terminal nodes)
                let (peer_tx, peer_rx) = tokio::sync::mpsc::channel(8192);
                *peer_tunnel_tx.write() = Some(peer_tx.clone());
                // Phase 12-Fix.P3: Get packet sender for forwarding non-WG egress to main loop
                let forward_tx = ingress_mgr.get_packet_sender();
                let peer_tunnel_handle = rust_router::ingress::spawn_peer_tunnel_processor(
                    peer_rx,
                    Arc::clone(ingress_mgr.processor()),
                    Arc::clone(&wg_egress_manager),
                    Arc::clone(&peer_tunnel_stats),
                    forward_tx, // Forward non-WG egress (direct/SOCKS) to main forwarding loop
                );
                info!("Peer tunnel processor started for chain routing");

                // Phase 12-Fix.P2: Set peer_tunnel_tx on PeerManager for chain traffic routing
                // When peer tunnels receive non-API packets, they forward to peer_tunnel_processor
                peer_manager.set_peer_tunnel_tx(peer_tx);

                let forward_handle = rust_router::ingress::spawn_forwarding_task(
                    packet_rx,
                    Arc::clone(&outbound_manager),
                    Arc::clone(&wg_egress_manager),
                    tcp_manager,
                    session_tracker,
                    Arc::clone(&fwd_stats),
                    Some(direct_reply_tx), // Enable direct UDP reply handling
                    Some(phase6_config.wg_local_ip), // Local IP for responding to pings to gateway
                    Some(Arc::clone(&ecmp_group_manager)), // ECMP group manager for load balancing
                    Some(Arc::clone(&peer_manager)), // Peer manager for peer WireGuard tunnels
                );

                info!("Ingress reply router task started");
                reply_task_handle = Some(reply_handle);
                peer_tunnel_task_handle = Some(peer_tunnel_handle);
                info!("Ingress packet forwarding task started");
                forwarding_task_handle = Some(forward_handle);
                
                // Set session tracker on IPC handler for active connection count reporting
                ipc_handler.set_ingress_session_tracker(session_tracker_for_ipc);
            } else {
                warn!("Failed to take packet receiver from WireGuard ingress - forwarding disabled");
            }
        }
    } else {
        debug!("Userspace WireGuard ingress not enabled");
    }

    info!(
        "Startup complete in {:.2}ms",
        start_time.elapsed().as_secs_f64() * 1000.0
    );

    // Run accept loop with signal handling
    let accept_result = tokio::select! {
        result = run_accept_loop(listener, Arc::clone(&connection_manager)) => {
            result
        }
        _ = signal::ctrl_c() => {
            info!("Received SIGINT, initiating shutdown...");
            Ok(())
        }
        _ = wait_for_sigterm() => {
            info!("Received SIGTERM, initiating shutdown...");
            Ok(())
        }
    };

    // Graceful shutdown
    info!("Shutting down...");

    // Stop accepting new connections
    connection_manager.shutdown().await;

    // Stop IPC server
    let _ = ipc_shutdown.send(());
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        ipc_handle,
    ).await;

    // ========================================================================
    // Phase 7: Shutdown DNS servers
    // ========================================================================
    info!("Shutting down DNS servers...");

    // Send shutdown signals to DNS servers
    let _ = dns_udp_shutdown_tx.send(());
    let _ = dns_tcp_shutdown_tx.send(());

    // Wait for DNS servers to shut down
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        async {
            let _ = dns_udp_handle.await;
            let _ = dns_tcp_handle.await;
        },
    ).await;

    info!("DNS servers shutdown complete");

    // ========================================================================
    // Shutdown SOCKS5 inbound server if running
    // ========================================================================
    if let Some(handle) = socks5_server_handle {
        info!("Shutting down SOCKS5 inbound server...");
        handle.abort();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), handle).await;
        info!("SOCKS5 inbound server shutdown complete");
    }

    // ========================================================================
    // Phase 6: Shutdown WireGuard ingress if running
    // ========================================================================
    if let Some(ref ingress_mgr) = wg_ingress_manager {
        if ingress_mgr.is_running() {
            info!("Shutting down WireGuard ingress manager...");
            if let Err(e) = ingress_mgr.stop().await {
                warn!("Error stopping WireGuard ingress: {}", e);
            }
            info!("WireGuard ingress manager shutdown complete");
        }
    }

    // Shutdown reply router task (drop sender to close channel)
    *reply_router_tx.write() = None;
    if let Some(handle) = reply_task_handle {
        info!("Waiting for reply router task to complete...");
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            handle,
        )
        .await;
        info!("Reply router task shutdown complete");
    }

    // Shutdown peer tunnel processor task (drop sender to close channel)
    *peer_tunnel_tx.write() = None;
    if let Some(handle) = peer_tunnel_task_handle {
        info!("Waiting for peer tunnel processor task to complete...");
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            handle,
        )
        .await;
        info!("Peer tunnel processor task shutdown complete");
    }

    // Shutdown forwarding task (after ingress stops, the channel will close)
    if let Some(handle) = forwarding_task_handle {
        info!("Waiting for forwarding task to complete...");
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            handle,
        )
        .await;
        info!("Forwarding task shutdown complete");
    }

    // Shutdown WireGuard egress manager
    info!("Shutting down WireGuard egress manager...");
    wg_egress_manager.shutdown().await;
    info!("WireGuard egress manager shutdown complete");

    // Shutdown UDP worker pool if enabled
    // We need to drop the IPC handler's reference first by dropping ipc_handler
    drop(ipc_handler);

    if let Some(worker_pool_arc) = udp_worker_pool {
        // Log UDP stats before shutdown
        let udp_stats = worker_pool_arc.stats_snapshot();
        info!(
            "UDP stats: {} packets processed, {} bytes received, {} worker errors",
            udp_stats.packets_processed, udp_stats.bytes_received, udp_stats.worker_errors
        );

        // Try to get exclusive ownership for graceful shutdown
        match Arc::try_unwrap(worker_pool_arc) {
            Ok(mut pool) => {
                info!("Shutting down UDP worker pool...");
                pool.shutdown().await;
            }
            Err(arc) => {
                // Other references exist (shouldn't happen after dropping ipc_handler)
                // Drop will send shutdown signal but won't wait
                warn!(
                    "UDP worker pool has {} references, shutdown signal sent via Drop",
                    Arc::strong_count(&arc)
                );
                drop(arc);
            }
        }
    }

    // Log final TCP stats
    let stats = connection_manager.stats_snapshot();
    info!(
        "Final TCP stats: {} total connections, {} completed, {} errored, {} rejected",
        stats.total_accepted, stats.completed, stats.errored, stats.rejected
    );
    info!(
        "Transferred: {} bytes rx, {} bytes tx",
        stats.bytes_rx, stats.bytes_tx
    );

    info!("Shutdown complete");

    accept_result.map_err(|e| anyhow::anyhow!("Accept loop error: {}", e))
}

/// Wait for SIGTERM signal
#[cfg(unix)]
async fn wait_for_sigterm() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut sigterm = signal(SignalKind::terminate()).expect("Failed to register SIGTERM handler");
    sigterm.recv().await;
}

#[cfg(not(unix))]
async fn wait_for_sigterm() {
    // On non-Unix platforms, just wait forever
    std::future::pending::<()>().await
}
