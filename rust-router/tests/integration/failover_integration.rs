//! Failover scenario integration tests
//!
//! This module tests health check responses, IPC communication,
//! graceful shutdown behavior, and connection drain functionality.
//!
//! # Test Categories
//!
//! 1. **Health Check Tests**: Test rust-router health check response
//! 2. **IPC Tests**: Test IPC ping/pong and command handling
//! 3. **Graceful Shutdown Tests**: Test shutdown signaling and drain
//! 4. **Connection Drain Tests**: Test connection drain behavior

use std::sync::Arc;
use std::time::Duration;

use rust_router::config::ConnectionConfig;
use rust_router::connection::ConnectionManager;
use rust_router::ipc::{IpcCommand, IpcHandler, IpcResponse};
use rust_router::outbound::{DirectOutbound, OutboundManager};

// ============================================================================
// Test Helpers
// ============================================================================

fn create_test_connection_manager() -> Arc<ConnectionManager> {
    let outbound_manager = Arc::new(OutboundManager::new());
    outbound_manager.add(Box::new(DirectOutbound::simple("direct")));

    let config = ConnectionConfig::default();
    Arc::new(ConnectionManager::new(
        &config,
        outbound_manager,
        "direct".into(),
        Duration::from_millis(300),
    ))
}

fn create_test_ipc_handler() -> IpcHandler {
    let outbound_manager = Arc::new(OutboundManager::new());
    outbound_manager.add(Box::new(DirectOutbound::simple("direct")));
    outbound_manager.add(Box::new(DirectOutbound::simple("proxy")));

    let conn_config = ConnectionConfig::default();
    let connection_manager = Arc::new(ConnectionManager::new(
        &conn_config,
        Arc::clone(&outbound_manager),
        "direct".into(),
        Duration::from_millis(300),
    ));

    IpcHandler::new_with_default_rules(connection_manager, outbound_manager)
}

// ============================================================================
// Health Check Tests
// ============================================================================

#[tokio::test]
async fn test_health_check_ping_response() {
    let handler = create_test_ipc_handler();

    let response = handler.handle(IpcCommand::Ping).await;
    assert!(matches!(response, IpcResponse::Pong));
}

#[tokio::test]
async fn test_health_check_status_response() {
    let handler = create_test_ipc_handler();

    let response = handler.handle(IpcCommand::Status).await;

    if let IpcResponse::Status(status) = response {
        assert!(!status.version.is_empty());
        assert!(status.uptime_secs < 3600); // Reasonable uptime for test
        assert!(!status.shutting_down);
        assert!(status.accepting);
    } else {
        panic!("Expected Status response");
    }
}

#[tokio::test]
async fn test_health_check_capabilities() {
    let handler = create_test_ipc_handler();

    let response = handler.handle(IpcCommand::GetCapabilities).await;

    if let IpcResponse::Capabilities(caps) = response {
        // Phase 1: TCP only, UDP not yet supported
        assert!(!caps.udp_support, "Phase 1 is TCP only");
        assert!(caps.tls_sniffing);
        assert!(caps.max_connections > 0);
        assert!(!caps.outbound_types.is_empty());
    } else {
        panic!("Expected Capabilities response");
    }
}

#[tokio::test]
async fn test_health_check_stats() {
    let handler = create_test_ipc_handler();

    let response = handler.handle(IpcCommand::GetStats).await;

    if let IpcResponse::Stats(stats) = response {
        // Stats should be valid (zero is OK for fresh instance)
        assert!(stats.total_accepted <= 1_000_000); // Sanity check
    } else {
        panic!("Expected Stats response");
    }
}

#[tokio::test]
async fn test_health_check_outbound_health() {
    let handler = create_test_ipc_handler();

    let response = handler.handle(IpcCommand::GetOutboundHealth).await;

    if let IpcResponse::OutboundHealth(health) = response {
        assert!(!health.outbounds.is_empty());
        // DirectOutbound starts with Unknown health (no connections made yet)
        // Check that all outbounds have a valid health status
        for outbound in &health.outbounds {
            assert!(
                ["healthy", "degraded", "unhealthy", "unknown"].contains(&outbound.health.as_str()),
                "Invalid health status: {}",
                outbound.health
            );
        }
    } else {
        panic!("Expected OutboundHealth response");
    }
}

// ============================================================================
// IPC Ping/Pong Tests
// ============================================================================

#[tokio::test]
async fn test_ipc_ping_latency() {
    let handler = create_test_ipc_handler();

    let start = std::time::Instant::now();
    let response = handler.handle(IpcCommand::Ping).await;
    let elapsed = start.elapsed();

    assert!(matches!(response, IpcResponse::Pong));
    assert!(elapsed < Duration::from_millis(100), "Ping should be fast");
}

#[tokio::test]
async fn test_ipc_multiple_pings() {
    let handler = create_test_ipc_handler();

    for _ in 0..100 {
        let response = handler.handle(IpcCommand::Ping).await;
        assert!(matches!(response, IpcResponse::Pong));
    }
}

#[tokio::test]
async fn test_ipc_concurrent_pings() {
    let handler = Arc::new(create_test_ipc_handler());

    let mut handles = vec![];
    for _ in 0..10 {
        let h = Arc::clone(&handler);
        handles.push(tokio::spawn(async move {
            for _ in 0..10 {
                let response = h.handle(IpcCommand::Ping).await;
                assert!(matches!(response, IpcResponse::Pong));
            }
        }));
    }

    for handle in handles {
        handle.await.unwrap();
    }
}

// ============================================================================
// Graceful Shutdown Tests
// ============================================================================

#[tokio::test]
async fn test_shutdown_command_response() {
    let handler = create_test_ipc_handler();

    let response = handler
        .handle(IpcCommand::Shutdown {
            drain_timeout_secs: Some(30),
        })
        .await;

    // Shutdown command should return success before actually shutting down
    if let IpcResponse::Success { message } = response {
        assert!(message.is_some());
        assert!(message.unwrap().contains("Shutdown"));
    } else {
        panic!("Expected Success response for shutdown");
    }
}

#[tokio::test]
async fn test_shutdown_with_zero_timeout() {
    let handler = create_test_ipc_handler();

    let response = handler
        .handle(IpcCommand::Shutdown {
            drain_timeout_secs: Some(0),
        })
        .await;

    // Should still succeed
    assert!(!response.is_error());
}

#[tokio::test]
async fn test_shutdown_without_timeout() {
    let handler = create_test_ipc_handler();

    let response = handler
        .handle(IpcCommand::Shutdown {
            drain_timeout_secs: None,
        })
        .await;

    // Should use default timeout
    assert!(!response.is_error());
}

// ============================================================================
// Connection Drain Tests
// ============================================================================

#[tokio::test]
async fn test_drain_outbound_success() {
    let handler = create_test_ipc_handler();

    // Drain the "direct" outbound
    let response = handler
        .handle(IpcCommand::DrainOutbound {
            tag: "direct".into(),
            timeout_secs: 5,
        })
        .await;

    if let IpcResponse::DrainResult(result) = response {
        assert!(result.success);
        // No active connections, so should drain immediately
        assert!(result.drain_time_ms < 1000);
    } else {
        panic!("Expected DrainResult response: {:?}", response);
    }
}

#[tokio::test]
async fn test_drain_nonexistent_outbound() {
    let handler = create_test_ipc_handler();

    let response = handler
        .handle(IpcCommand::DrainOutbound {
            tag: "nonexistent".into(),
            timeout_secs: 5,
        })
        .await;

    assert!(response.is_error());
    if let IpcResponse::Error(err) = response {
        assert!(err.message.contains("not found"));
    }
}

#[tokio::test]
async fn test_drain_zero_timeout() {
    let handler = create_test_ipc_handler();

    let response = handler
        .handle(IpcCommand::DrainOutbound {
            tag: "proxy".into(),
            timeout_secs: 0,
        })
        .await;

    if let IpcResponse::DrainResult(result) = response {
        assert!(result.success);
        // Zero timeout should complete immediately
        assert!(result.drain_time_ms < 100);
    } else {
        panic!("Expected DrainResult response");
    }
}

// ============================================================================
// Connection Manager State Tests
// ============================================================================

#[tokio::test]
async fn test_connection_manager_initial_state() {
    let manager = create_test_connection_manager();

    assert!(!manager.is_shutting_down());

    let stats = manager.stats_snapshot();
    assert_eq!(stats.active, 0);
    assert_eq!(stats.total_accepted, 0);
}

#[tokio::test]
async fn test_connection_manager_shutdown_flag() {
    let manager = create_test_connection_manager();

    assert!(!manager.is_shutting_down());

    // Trigger shutdown (async method)
    manager.shutdown().await;

    assert!(manager.is_shutting_down());
}

// ============================================================================
// Outbound Manager State Tests
// ============================================================================

#[tokio::test]
async fn test_outbound_manager_list() {
    let handler = create_test_ipc_handler();

    let response = handler.handle(IpcCommand::ListOutbounds).await;

    if let IpcResponse::OutboundList { outbounds } = response {
        assert!(outbounds.len() >= 2); // direct and proxy
        let tags: Vec<_> = outbounds.iter().map(|o| o.tag.as_str()).collect();
        assert!(tags.contains(&"direct"));
        assert!(tags.contains(&"proxy"));
    } else {
        panic!("Expected OutboundList response");
    }
}

#[tokio::test]
async fn test_outbound_manager_remove() {
    let handler = create_test_ipc_handler();

    // Remove an outbound
    let response = handler
        .handle(IpcCommand::RemoveOutbound {
            tag: "proxy".into(),
        })
        .await;
    assert!(!response.is_error());

    // Verify it's gone
    let response = handler.handle(IpcCommand::ListOutbounds).await;
    if let IpcResponse::OutboundList { outbounds } = response {
        let tags: Vec<_> = outbounds.iter().map(|o| o.tag.as_str()).collect();
        assert!(!tags.contains(&"proxy"));
    }
}

#[tokio::test]
async fn test_outbound_enable_disable() {
    let handler = create_test_ipc_handler();

    // Disable outbound
    let response = handler
        .handle(IpcCommand::DisableOutbound {
            tag: "direct".into(),
        })
        .await;
    assert!(!response.is_error());

    // Enable outbound
    let response = handler
        .handle(IpcCommand::EnableOutbound {
            tag: "direct".into(),
        })
        .await;
    assert!(!response.is_error());
}

// ============================================================================
// Rule Engine State Tests
// ============================================================================

#[tokio::test]
async fn test_rule_stats_initial() {
    let handler = create_test_ipc_handler();

    let response = handler.handle(IpcCommand::GetRuleStats).await;

    if let IpcResponse::RuleStats(stats) = response {
        assert!(stats.config_version >= 1);
        assert_eq!(stats.default_outbound, "direct");
    } else {
        panic!("Expected RuleStats response");
    }
}

#[tokio::test]
async fn test_set_default_outbound() {
    let handler = create_test_ipc_handler();

    // Change default to "proxy"
    let response = handler
        .handle(IpcCommand::SetDefaultOutbound {
            tag: "proxy".into(),
        })
        .await;
    assert!(!response.is_error());

    // Verify change
    let stats_response = handler.handle(IpcCommand::GetRuleStats).await;
    if let IpcResponse::RuleStats(stats) = stats_response {
        assert_eq!(stats.default_outbound, "proxy");
    }
}

// ============================================================================
// Error Recovery Tests
// ============================================================================

#[tokio::test]
async fn test_recovery_from_invalid_command() {
    let handler = create_test_ipc_handler();

    // Send invalid GetOutbound
    let response = handler
        .handle(IpcCommand::GetOutbound {
            tag: "".into(), // empty tag
        })
        .await;

    // Should return error but not crash
    assert!(response.is_error());

    // Should still respond to subsequent commands
    let ping_response = handler.handle(IpcCommand::Ping).await;
    assert!(matches!(ping_response, IpcResponse::Pong));
}

#[tokio::test]
async fn test_recovery_multiple_errors() {
    let handler = create_test_ipc_handler();

    // Trigger multiple errors
    for _ in 0..10 {
        let _ = handler
            .handle(IpcCommand::RemoveOutbound {
                tag: "nonexistent".into(),
            })
            .await;
    }

    // Should still be functional
    let status = handler.handle(IpcCommand::Status).await;
    assert!(matches!(status, IpcResponse::Status(_)));
}
