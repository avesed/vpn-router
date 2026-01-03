//! rust-router: High-performance transparent proxy router
//!
//! This is the main entry point for the production router.
//! For Phase 0 validation, use the PoC binaries:
//!   - tproxy_poc: TCP TPROXY validation
//!   - udp_tproxy_poc: UDP TPROXY validation

use anyhow::Result;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .with_target(true)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    info!("rust-router v{}", env!("CARGO_PKG_VERSION"));
    info!("Phase 0: Use tproxy_poc or udp_tproxy_poc for validation");

    // TODO: Phase 1+ implementation
    // - TPROXY listener
    // - Rule engine
    // - Outbound manager
    // - IPC server

    Ok(())
}
