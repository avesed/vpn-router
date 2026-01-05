//! Connection Manager
//!
//! This module provides centralized connection management including:
//! - Connection limiting via semaphore-based backpressure
//! - Graceful shutdown with connection draining
//! - Statistics collection

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{broadcast, Semaphore};
use tracing::{debug, info, warn};

use super::stats::{ConnectionStats, StatsSnapshot};
use super::tcp::{spawn_tcp_handler, TcpConnectionContext};
use crate::config::ConnectionConfig;
use crate::error::ConnectionError;
use crate::outbound::OutboundManager;
use crate::tproxy::{TproxyConnection, TproxyListener};

/// Connection manager for handling concurrent connections
pub struct ConnectionManager {
    /// Semaphore for connection limiting
    semaphore: Arc<Semaphore>,

    /// Maximum connections allowed
    max_connections: usize,

    /// Connection statistics
    stats: Arc<ConnectionStats>,

    /// Outbound manager
    outbound_manager: Arc<OutboundManager>,

    /// Default outbound tag
    default_outbound: String,

    /// Sniff timeout
    sniff_timeout: Duration,

    /// Connect timeout for outbound connections
    connect_timeout: Duration,

    /// Buffer size
    buffer_size: usize,

    /// Drain timeout for graceful shutdown
    drain_timeout: Duration,

    /// Shutdown signal sender
    shutdown_tx: broadcast::Sender<()>,

    /// Whether shutdown has been initiated
    shutting_down: AtomicBool,
}

impl ConnectionManager {
    /// Create a new connection manager
    pub fn new(
        config: &ConnectionConfig,
        outbound_manager: Arc<OutboundManager>,
        default_outbound: String,
        sniff_timeout: Duration,
    ) -> Self {
        let (shutdown_tx, _) = broadcast::channel(1);

        Self {
            semaphore: Arc::new(Semaphore::new(config.max_connections)),
            max_connections: config.max_connections,
            stats: Arc::new(ConnectionStats::new()),
            outbound_manager,
            default_outbound,
            sniff_timeout,
            connect_timeout: config.connect_timeout(),
            buffer_size: config.buffer_size,
            drain_timeout: config.drain_timeout(),
            shutdown_tx,
            shutting_down: AtomicBool::new(false),
        }
    }

    /// Handle a new connection with backpressure
    ///
    /// This method acquires a permit from the semaphore before handling
    /// the connection, ensuring we don't exceed the maximum connection limit.
    ///
    /// # Errors
    ///
    /// Returns `ConnectionError::LimitReached` if the connection limit is hit
    /// and the semaphore has no available permits.
    pub async fn handle_connection(
        &self,
        conn: TproxyConnection,
    ) -> Result<(), ConnectionError> {
        // Check if shutting down
        if self.shutting_down.load(Ordering::Relaxed) {
            return Err(ConnectionError::ShuttingDown);
        }

        // Try to acquire a permit
        let permit = match self.semaphore.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                self.stats.record_rejected();
                let current = self.max_connections - self.semaphore.available_permits();
                warn!(
                    "Connection limit reached ({}/{}), rejecting connection from {}",
                    current,
                    self.max_connections,
                    conn.client_addr()
                );
                return Err(ConnectionError::limit_reached(current, self.max_connections));
            }
        };

        // Record the accepted connection
        self.stats.record_accepted();

        debug!(
            "Accepted connection from {} (active: {}/{})",
            conn.client_addr(),
            self.stats.active(),
            self.max_connections
        );

        // Create connection context
        let ctx = TcpConnectionContext {
            conn,
            outbound_manager: Arc::clone(&self.outbound_manager),
            sniff_timeout: self.sniff_timeout,
            connect_timeout: self.connect_timeout,
            default_outbound: self.default_outbound.clone(),
            buffer_size: self.buffer_size,
        };

        // Spawn handler task
        let stats = Arc::clone(&self.stats);
        let mut shutdown_rx = self.shutdown_tx.subscribe();

        tokio::spawn(async move {
            // Hold the permit until the connection is done
            let _permit = permit;

            tokio::select! {
                _ = spawn_tcp_handler(ctx, stats) => {}
                _ = shutdown_rx.recv() => {
                    debug!("Connection handler received shutdown signal");
                }
            }
        });

        Ok(())
    }

    /// Get current statistics
    #[must_use]
    pub fn stats(&self) -> &ConnectionStats {
        &self.stats
    }

    /// Get a snapshot of current statistics
    #[must_use]
    pub fn stats_snapshot(&self) -> StatsSnapshot {
        self.stats.snapshot()
    }

    /// Get current active connection count
    #[must_use]
    pub fn active_connections(&self) -> usize {
        self.max_connections - self.semaphore.available_permits()
    }

    /// Get available connection slots
    #[must_use]
    pub fn available_slots(&self) -> usize {
        self.semaphore.available_permits()
    }

    /// Check if at capacity
    #[must_use]
    pub fn at_capacity(&self) -> bool {
        self.semaphore.available_permits() == 0
    }

    /// Initiate graceful shutdown
    ///
    /// This stops accepting new connections and waits for existing
    /// connections to complete (up to drain_timeout).
    pub async fn shutdown(&self) {
        if self
            .shutting_down
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::Relaxed)
            .is_err()
        {
            // Already shutting down
            return;
        }

        info!("Initiating connection manager shutdown");

        // Signal all handlers to stop
        let _ = self.shutdown_tx.send(());

        // Wait for connections to drain
        let drain_start = std::time::Instant::now();
        let check_interval = Duration::from_millis(100);

        while drain_start.elapsed() < self.drain_timeout {
            let active = self.active_connections();
            if active == 0 {
                info!("All connections drained");
                return;
            }

            debug!(
                "Waiting for {} connections to drain ({:.1}s remaining)",
                active,
                (self.drain_timeout - drain_start.elapsed()).as_secs_f64()
            );

            tokio::time::sleep(check_interval).await;
        }

        let remaining = self.active_connections();
        if remaining > 0 {
            warn!(
                "Drain timeout reached with {} connections still active",
                remaining
            );
        }
    }

    /// Check if shutting down
    #[must_use]
    pub fn is_shutting_down(&self) -> bool {
        self.shutting_down.load(Ordering::Relaxed)
    }
}

/// Run the connection accept loop
///
/// This function runs the main accept loop, handling new connections
/// from the TPROXY listener through the connection manager.
pub async fn run_accept_loop(
    listener: TproxyListener,
    manager: Arc<ConnectionManager>,
) -> Result<(), crate::error::RustRouterError> {
    info!(
        "Starting accept loop on {} (max {} connections)",
        listener.listen_addr(),
        manager.max_connections
    );

    loop {
        // Check for shutdown
        if manager.is_shutting_down() {
            info!("Accept loop stopping due to shutdown");
            break;
        }

        // Accept new connection
        match listener.accept().await {
            Ok(conn) => {
                let manager = Arc::clone(&manager);
                tokio::spawn(async move {
                    if let Err(e) = manager.handle_connection(conn).await {
                        debug!("Failed to handle connection: {}", e);
                    }
                });
            }
            Err(e) => {
                if e.is_recoverable() {
                    debug!("Recoverable accept error: {}", e);
                    continue;
                } else {
                    return Err(e.into());
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ConnectionConfig, OutboundConfig};

    fn create_test_manager() -> ConnectionManager {
        let config = ConnectionConfig {
            max_connections: 10,
            idle_timeout_secs: 300,
            connect_timeout_secs: 10,
            buffer_size: 65536,
            drain_timeout_secs: 5,
        };

        let outbound_manager = Arc::new(OutboundManager::new());
        outbound_manager.add(Box::new(crate::outbound::DirectOutbound::new(
            OutboundConfig::direct("direct"),
        )));

        ConnectionManager::new(
            &config,
            outbound_manager,
            "direct".into(),
            Duration::from_millis(300),
        )
    }

    #[test]
    fn test_manager_creation() {
        let manager = create_test_manager();
        assert_eq!(manager.max_connections, 10);
        assert_eq!(manager.active_connections(), 0);
        assert_eq!(manager.available_slots(), 10);
        assert!(!manager.at_capacity());
    }

    #[test]
    fn test_stats_collection() {
        let manager = create_test_manager();
        let stats = manager.stats();

        assert_eq!(stats.total_accepted(), 0);
        assert_eq!(stats.active(), 0);
    }

    #[tokio::test]
    async fn test_shutdown() {
        let manager = create_test_manager();
        assert!(!manager.is_shutting_down());

        manager.shutdown().await;
        assert!(manager.is_shutting_down());

        // Double shutdown should be safe
        manager.shutdown().await;
        assert!(manager.is_shutting_down());
    }
}
