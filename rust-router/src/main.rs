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
//! ```

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use anyhow::Result;
use tokio::signal;
use tracing::{error, info, warn, Level};
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::EnvFilter;

use rust_router::config::{load_config_with_env, Config};
use rust_router::connection::{
    run_accept_loop, ConnectionManager, UdpPacketProcessor, UdpProcessorConfig,
    UdpSessionConfig, UdpSessionManager,
};
use rust_router::ipc::{IpcHandler, IpcServer};
use rust_router::outbound::{OutboundManager, OutboundManagerBuilder};
use rust_router::rules::{RuleEngine, RoutingSnapshotBuilder};
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
"#,
        rust_router::VERSION
    );
}

/// Initialize logging
fn init_logging(config: &Config) {
    let level = match config.log.level.to_lowercase().as_str() {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "info" => Level::INFO,
        "warn" => Level::WARN,
        "error" => Level::ERROR,
        _ => Level::INFO,
    };

    let filter = EnvFilter::from_default_env()
        .add_directive(level.into())
        .add_directive("hyper=warn".parse().unwrap())
        .add_directive("tokio=warn".parse().unwrap());

    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(config.log.target)
        .with_span_events(FmtSpan::CLOSE);

    if config.log.format == "json" {
        subscriber.json().init();
    } else {
        subscriber.init();
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

    // Create connection manager
    let connection_manager = Arc::new(ConnectionManager::new(
        &config.connection,
        Arc::clone(&outbound_manager),
        config.default_outbound.clone(),
        config.listen.sniff_timeout(),
    ));

    // Create TPROXY listener (TCP)
    let listener = TproxyListener::bind(&config.listen)
        .map_err(|e| anyhow::anyhow!("Failed to create TPROXY listener: {}", e))?;

    // Create UDP components (if enabled)
    let (udp_session_manager, udp_worker_pool, udp_buffer_pool) = if config.listen.udp_enabled {
        // Note: UdpSessionManager is kept for backwards compatibility with IPC handler interface
        // The actual session tracking happens inside UdpPacketProcessor's handle_cache
        let session_manager = Arc::new(UdpSessionManager::new(UdpSessionConfig::default()));

        // Create UDP packet processor
        let processor_config = UdpProcessorConfig::default();
        let processor = Arc::new(UdpPacketProcessor::new(processor_config));

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

    // Create IPC handler with or without UDP components
    let ipc_handler = if let (Some(session_mgr), Some(worker_pool), Some(buffer_pool)) =
        (&udp_session_manager, &udp_worker_pool, &udp_buffer_pool)
    {
        Arc::new(IpcHandler::new_with_udp(
            Arc::clone(&connection_manager),
            Arc::clone(&outbound_manager),
            Arc::clone(&rule_engine),
            Arc::clone(session_mgr),
            Arc::clone(worker_pool),
            Arc::clone(buffer_pool),
        ))
    } else {
        Arc::new(IpcHandler::new(
            Arc::clone(&connection_manager),
            Arc::clone(&outbound_manager),
            Arc::clone(&rule_engine),
        ))
    };

    let ipc_server = IpcServer::new(config.ipc.clone(), Arc::clone(&ipc_handler));
    let ipc_shutdown = ipc_server.shutdown_sender();

    // Spawn IPC server
    let ipc_handle = tokio::spawn(async move {
        if let Err(e) = ipc_server.run().await {
            error!("IPC server error: {}", e);
        }
    });

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
