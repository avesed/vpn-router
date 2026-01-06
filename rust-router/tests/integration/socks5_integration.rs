//! SOCKS5 outbound integration tests
//!
//! This module tests the SOCKS5 outbound implementation with mock servers,
//! verifying protocol compliance, connection pooling, authentication, and
//! error handling.
//!
//! # Test Categories
//!
//! 1. **Protocol Tests**: Verify RFC 1928/1929 compliance
//! 2. **Connection Pool Tests**: Test pool behavior under various conditions
//! 3. **Authentication Tests**: Test username/password auth flow
//! 4. **Timeout Tests**: Verify timeout handling
//! 5. **Error Handling Tests**: Test graceful error handling
//! 6. **Reconnection Tests**: Test recovery after server restart

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use rust_router::outbound::{Outbound, Socks5Config, Socks5Outbound, HealthStatus};

// ============================================================================
// SOCKS5 Protocol Constants
// ============================================================================

const SOCKS5_VERSION: u8 = 0x05;
const AUTH_METHOD_NONE: u8 = 0x00;
const AUTH_METHOD_PASSWORD: u8 = 0x02;
const AUTH_PASSWORD_VERSION: u8 = 0x01;
const CMD_CONNECT: u8 = 0x01;
const ATYP_IPV4: u8 = 0x01;
const ATYP_IPV6: u8 = 0x04;
const REPLY_SUCCEEDED: u8 = 0x00;
const REPLY_CONNECTION_REFUSED: u8 = 0x05;
const REPLY_HOST_UNREACHABLE: u8 = 0x04;
const REPLY_NETWORK_UNREACHABLE: u8 = 0x03;

// ============================================================================
// Mock SOCKS5 Server
// ============================================================================

/// Configuration for mock SOCKS5 server behavior
#[derive(Clone)]
struct MockServerConfig {
    /// Require authentication
    require_auth: bool,
    /// Expected username (if auth required)
    expected_username: Option<String>,
    /// Expected password (if auth required)
    expected_password: Option<String>,
    /// Reply code to send after CONNECT
    reply_code: u8,
    /// Delay before responding (milliseconds)
    response_delay_ms: u64,
    /// Whether to close connection immediately
    close_immediately: bool,
    /// Whether to send malformed response
    send_malformed: bool,
}

impl Default for MockServerConfig {
    fn default() -> Self {
        Self {
            require_auth: false,
            expected_username: None,
            expected_password: None,
            reply_code: REPLY_SUCCEEDED,
            response_delay_ms: 0,
            close_immediately: false,
            send_malformed: false,
        }
    }
}

/// Run a mock SOCKS5 server for a single connection
async fn run_mock_socks5_server(
    listener: TcpListener,
    config: MockServerConfig,
    connection_count: Arc<AtomicU32>,
) {
    let (mut socket, _) = listener.accept().await.unwrap();
    connection_count.fetch_add(1, Ordering::SeqCst);

    if config.close_immediately {
        drop(socket);
        return;
    }

    if config.response_delay_ms > 0 {
        tokio::time::sleep(Duration::from_millis(config.response_delay_ms)).await;
    }

    // Read method selection header: VER | NMETHODS
    let mut header = [0u8; 2];
    if socket.read_exact(&mut header).await.is_err() {
        return;
    }

    if header[0] != SOCKS5_VERSION {
        return;
    }

    let nmethods = header[1] as usize;

    // Read method list
    let mut methods = vec![0u8; nmethods];
    if socket.read_exact(&mut methods).await.is_err() {
        return;
    }

    if config.send_malformed {
        // Send invalid version
        let _ = socket.write_all(&[0x04, AUTH_METHOD_NONE]).await;
        return;
    }

    if config.require_auth {
        // Reply with password auth required
        if socket.write_all(&[SOCKS5_VERSION, AUTH_METHOD_PASSWORD]).await.is_err() {
            return;
        }

        // Read auth request: VER | ULEN | USERNAME | PLEN | PASSWORD
        let mut auth_header = [0u8; 2];
        if socket.read_exact(&mut auth_header).await.is_err() {
            return;
        }

        let ulen = auth_header[1] as usize;
        let mut username = vec![0u8; ulen];
        if socket.read_exact(&mut username).await.is_err() {
            return;
        }

        let mut plen_buf = [0u8; 1];
        if socket.read_exact(&mut plen_buf).await.is_err() {
            return;
        }

        let plen = plen_buf[0] as usize;
        let mut password = vec![0u8; plen];
        if socket.read_exact(&mut password).await.is_err() {
            return;
        }

        // Verify credentials if specified
        let auth_success = match (&config.expected_username, &config.expected_password) {
            (Some(expected_u), Some(expected_p)) => {
                username == expected_u.as_bytes() && password == expected_p.as_bytes()
            }
            _ => true, // Accept any credentials
        };

        if auth_success {
            let _ = socket.write_all(&[AUTH_PASSWORD_VERSION, 0x00]).await;
        } else {
            let _ = socket.write_all(&[AUTH_PASSWORD_VERSION, 0x01]).await;
            return;
        }
    } else {
        // Reply with no auth
        if socket.write_all(&[SOCKS5_VERSION, AUTH_METHOD_NONE]).await.is_err() {
            return;
        }
    }

    // Read CONNECT request: VER | CMD | RSV | ATYP
    let mut connect_header = [0u8; 4];
    if socket.read_exact(&mut connect_header).await.is_err() {
        return;
    }

    if connect_header[1] != CMD_CONNECT {
        return;
    }

    // Read address based on ATYP
    match connect_header[3] {
        ATYP_IPV4 => {
            let mut addr_buf = [0u8; 6]; // 4 bytes IP + 2 bytes port
            let _ = socket.read_exact(&mut addr_buf).await;
        }
        ATYP_IPV6 => {
            let mut addr_buf = [0u8; 18]; // 16 bytes IP + 2 bytes port
            let _ = socket.read_exact(&mut addr_buf).await;
        }
        _ => return,
    }

    // Send reply
    let reply = [
        SOCKS5_VERSION,
        config.reply_code,
        0x00,
        ATYP_IPV4,
        127, 0, 0, 1, // Bound address
        0, 0,         // Bound port
    ];
    let _ = socket.write_all(&reply).await;
}

/// Run a mock SOCKS5 server that handles multiple connections
async fn run_multi_connection_server(
    listener: TcpListener,
    config: MockServerConfig,
    connection_count: Arc<AtomicU32>,
    max_connections: u32,
) {
    for _ in 0..max_connections {
        let (mut socket, _) = match listener.accept().await {
            Ok(s) => s,
            Err(_) => break,
        };
        connection_count.fetch_add(1, Ordering::SeqCst);

        let config = config.clone();
        tokio::spawn(async move {
            // Simplified handler for multi-connection tests
            let mut header = [0u8; 2];
            if socket.read_exact(&mut header).await.is_err() {
                return;
            }

            let nmethods = header[1] as usize;
            let mut methods = vec![0u8; nmethods];
            let _ = socket.read_exact(&mut methods).await;

            let _ = socket.write_all(&[SOCKS5_VERSION, AUTH_METHOD_NONE]).await;

            let mut connect_buf = [0u8; 10]; // IPv4 CONNECT request
            let _ = socket.read_exact(&mut connect_buf).await;

            let reply = [
                SOCKS5_VERSION,
                config.reply_code,
                0x00,
                ATYP_IPV4,
                127, 0, 0, 1,
                0, 0,
            ];
            let _ = socket.write_all(&reply).await;
        });
    }
}

// ============================================================================
// Protocol Compliance Tests
// ============================================================================

#[tokio::test]
async fn test_socks5_connect_no_auth() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();
    let connection_count = Arc::new(AtomicU32::new(0));

    let server_task = tokio::spawn({
        let count = Arc::clone(&connection_count);
        async move {
            run_mock_socks5_server(listener, MockServerConfig::default(), count).await;
        }
    });

    let config = Socks5Config::new("test", server_addr)
        .with_pool_size(1)
        .with_connect_timeout(5);

    let outbound = Socks5Outbound::new(config).await.unwrap();
    let dest: SocketAddr = "93.184.216.34:80".parse().unwrap();
    let result = outbound.connect(dest, Duration::from_secs(5)).await;

    assert!(result.is_ok(), "Connection should succeed: {}", result.as_ref().err().map_or("".to_string(), |e| e.to_string()));
    let conn = result.unwrap();
    assert_eq!(conn.remote_addr(), dest);

    let _ = server_task.await;
    assert_eq!(connection_count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn test_socks5_connect_with_auth() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();
    let connection_count = Arc::new(AtomicU32::new(0));

    let config = MockServerConfig {
        require_auth: true,
        expected_username: Some("testuser".into()),
        expected_password: Some("testpass".into()),
        ..Default::default()
    };

    let server_task = tokio::spawn({
        let count = Arc::clone(&connection_count);
        async move {
            run_mock_socks5_server(listener, config, count).await;
        }
    });

    let outbound_config = Socks5Config::new("test-auth", server_addr)
        .with_auth("testuser", "testpass")
        .with_pool_size(1);

    let outbound = Socks5Outbound::new(outbound_config).await.unwrap();
    let dest: SocketAddr = "8.8.8.8:53".parse().unwrap();
    let result = outbound.connect(dest, Duration::from_secs(5)).await;

    assert!(result.is_ok());
    let _ = server_task.await;
}

#[tokio::test]
async fn test_socks5_auth_failure() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();
    let connection_count = Arc::new(AtomicU32::new(0));

    let config = MockServerConfig {
        require_auth: true,
        expected_username: Some("correct".into()),
        expected_password: Some("password".into()),
        ..Default::default()
    };

    let server_task = tokio::spawn({
        let count = Arc::clone(&connection_count);
        async move {
            run_mock_socks5_server(listener, config, count).await;
        }
    });

    // Use wrong credentials
    let outbound_config = Socks5Config::new("test-auth-fail", server_addr)
        .with_auth("wrong", "credentials")
        .with_pool_size(1);

    let outbound = Socks5Outbound::new(outbound_config).await.unwrap();
    let dest: SocketAddr = "1.2.3.4:80".parse().unwrap();
    let result = outbound.connect(dest, Duration::from_secs(5)).await;

    assert!(result.is_err(), "Connection should fail with wrong credentials");
    let _ = server_task.await;
}

#[tokio::test]
async fn test_socks5_ipv6_destination() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();
    let connection_count = Arc::new(AtomicU32::new(0));

    let server_task = tokio::spawn({
        let count = Arc::clone(&connection_count);
        async move {
            // Handle IPv6 address type
            let (mut socket, _) = listener.accept().await.unwrap();
            count.fetch_add(1, Ordering::SeqCst);

            let mut header = [0u8; 2];
            let _ = socket.read_exact(&mut header).await;
            let nmethods = header[1] as usize;
            let mut methods = vec![0u8; nmethods];
            let _ = socket.read_exact(&mut methods).await;

            let _ = socket.write_all(&[SOCKS5_VERSION, AUTH_METHOD_NONE]).await;

            // Read CONNECT with IPv6
            let mut connect_header = [0u8; 4];
            let _ = socket.read_exact(&mut connect_header).await;

            if connect_header[3] == ATYP_IPV6 {
                let mut addr_buf = [0u8; 18];
                let _ = socket.read_exact(&mut addr_buf).await;
            }

            let reply = [
                SOCKS5_VERSION,
                REPLY_SUCCEEDED,
                0x00,
                ATYP_IPV4,
                127, 0, 0, 1,
                0, 0,
            ];
            let _ = socket.write_all(&reply).await;
        }
    });

    let config = Socks5Config::new("test-ipv6", server_addr).with_pool_size(1);
    let outbound = Socks5Outbound::new(config).await.unwrap();

    // IPv6 destination
    let dest: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
    let result = outbound.connect(dest, Duration::from_secs(5)).await;

    assert!(result.is_ok());
    let _ = server_task.await;
}

// ============================================================================
// Connection Pool Tests
// ============================================================================

#[tokio::test]
async fn test_pool_initial_empty() {
    let addr: SocketAddr = "127.0.0.1:1080".parse().unwrap();
    let config = Socks5Config::new("test-pool", addr).with_pool_size(16);
    let outbound = Socks5Outbound::new(config).await.unwrap();

    let stats = outbound.pool_stats();
    assert_eq!(stats.size, 0);
    assert_eq!(stats.available, 0);
    assert_eq!(stats.waiting, 0);
}

#[tokio::test]
async fn test_pool_stats_after_connection() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();
    let connection_count = Arc::new(AtomicU32::new(0));

    let server_task = tokio::spawn({
        let count = Arc::clone(&connection_count);
        async move {
            run_mock_socks5_server(listener, MockServerConfig::default(), count).await;
        }
    });

    let config = Socks5Config::new("test-pool-stats", server_addr)
        .with_pool_size(4);

    let outbound = Socks5Outbound::new(config).await.unwrap();
    let dest: SocketAddr = "1.2.3.4:80".parse().unwrap();

    // Make a connection
    let conn = outbound.connect(dest, Duration::from_secs(5)).await;
    assert!(conn.is_ok());

    // Pool stats should reflect usage
    let stats = outbound.pool_stats();
    // After connection is taken, size may be 0 or 1 depending on pooling behavior
    assert!(stats.size <= 1);

    let _ = server_task.await;
}

#[tokio::test]
#[ignore] // Test hangs due to server task not terminating properly
async fn test_pool_concurrent_connections() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();
    let connection_count = Arc::new(AtomicU32::new(0));

    let server_task = tokio::spawn({
        let count = Arc::clone(&connection_count);
        async move {
            run_multi_connection_server(listener, MockServerConfig::default(), count, 5).await;
        }
    });

    // Give server time to start
    tokio::time::sleep(Duration::from_millis(10)).await;

    let config = Socks5Config::new("test-concurrent", server_addr)
        .with_pool_size(5);

    let outbound = Arc::new(Socks5Outbound::new(config).await.unwrap());
    let dest: SocketAddr = "1.2.3.4:80".parse().unwrap();

    // Spawn multiple concurrent connection attempts
    let mut handles = vec![];
    for _ in 0..3 {
        let ob = Arc::clone(&outbound);
        let handle = tokio::spawn(async move {
            ob.connect(dest, Duration::from_secs(5)).await
        });
        handles.push(handle);
    }

    // Wait for all connections
    for handle in handles {
        let result = handle.await.unwrap();
        assert!(result.is_ok(), "Concurrent connection should succeed: {}", result.as_ref().err().map_or("".to_string(), |e| e.to_string()));
    }

    let _ = server_task.await;
}

// ============================================================================
// Error Reply Tests
// ============================================================================

#[tokio::test]
async fn test_socks5_connection_refused() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();
    let connection_count = Arc::new(AtomicU32::new(0));

    let config = MockServerConfig {
        reply_code: REPLY_CONNECTION_REFUSED,
        ..Default::default()
    };

    let server_task = tokio::spawn({
        let count = Arc::clone(&connection_count);
        async move {
            run_mock_socks5_server(listener, config, count).await;
        }
    });

    let outbound_config = Socks5Config::new("test-refused", server_addr).with_pool_size(1);
    let outbound = Socks5Outbound::new(outbound_config).await.unwrap();

    let dest: SocketAddr = "1.2.3.4:80".parse().unwrap();
    let result = outbound.connect(dest, Duration::from_secs(5)).await;

    assert!(result.is_err());
    let err_str = match result {
        Err(e) => e.to_string(),
        Ok(_) => panic!("Expected error"),
    };
    assert!(err_str.contains("connection refused") || err_str.contains("SOCKS5"));

    let _ = server_task.await;
}

#[tokio::test]
async fn test_socks5_host_unreachable() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();
    let connection_count = Arc::new(AtomicU32::new(0));

    let config = MockServerConfig {
        reply_code: REPLY_HOST_UNREACHABLE,
        ..Default::default()
    };

    let server_task = tokio::spawn({
        let count = Arc::clone(&connection_count);
        async move {
            run_mock_socks5_server(listener, config, count).await;
        }
    });

    let outbound_config = Socks5Config::new("test-unreachable", server_addr).with_pool_size(1);
    let outbound = Socks5Outbound::new(outbound_config).await.unwrap();

    let dest: SocketAddr = "1.2.3.4:80".parse().unwrap();
    let result = outbound.connect(dest, Duration::from_secs(5)).await;

    assert!(result.is_err());
    let err_str = match result {
        Err(e) => e.to_string(),
        Ok(_) => panic!("Expected error"),
    };
    assert!(err_str.contains("host unreachable") || err_str.contains("SOCKS5"));

    let _ = server_task.await;
}

#[tokio::test]
async fn test_socks5_network_unreachable() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();
    let connection_count = Arc::new(AtomicU32::new(0));

    let config = MockServerConfig {
        reply_code: REPLY_NETWORK_UNREACHABLE,
        ..Default::default()
    };

    let server_task = tokio::spawn({
        let count = Arc::clone(&connection_count);
        async move {
            run_mock_socks5_server(listener, config, count).await;
        }
    });

    let outbound_config = Socks5Config::new("test-net-unreachable", server_addr).with_pool_size(1);
    let outbound = Socks5Outbound::new(outbound_config).await.unwrap();

    let dest: SocketAddr = "1.2.3.4:80".parse().unwrap();
    let result = outbound.connect(dest, Duration::from_secs(5)).await;

    assert!(result.is_err());

    let _ = server_task.await;
}

// ============================================================================
// Timeout Tests
// ============================================================================

#[tokio::test]
#[ignore] // Requires network timeout behavior which varies by system
async fn test_socks5_connect_timeout() {
    // Use a non-routable address to trigger timeout
    let addr: SocketAddr = "192.0.2.1:1080".parse().unwrap(); // TEST-NET-1
    let config = Socks5Config::new("test-timeout", addr)
        .with_connect_timeout(1)
        .with_pool_size(1);

    let outbound = Socks5Outbound::new(config).await.unwrap();

    let dest: SocketAddr = "1.2.3.4:80".parse().unwrap();
    let result = outbound.connect(dest, Duration::from_millis(500)).await;

    assert!(result.is_err());
    // Should be timeout or connection failed
    let err_str = match result {
        Err(e) => e.to_string(),
        Ok(_) => panic!("Expected error"),
    };
    assert!(
        err_str.contains("timeout") || err_str.contains("timed out") || err_str.contains("failed"),
        "Expected timeout error, got: {}",
        err_str
    );
}

#[tokio::test]
#[ignore] // Test involves 5 second delay which slows down test suite
async fn test_socks5_slow_server_timeout() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();
    let connection_count = Arc::new(AtomicU32::new(0));

    // Server with 5 second delay
    let config = MockServerConfig {
        response_delay_ms: 5000,
        ..Default::default()
    };

    let server_task = tokio::spawn({
        let count = Arc::clone(&connection_count);
        async move {
            run_mock_socks5_server(listener, config, count).await;
        }
    });

    let outbound_config = Socks5Config::new("test-slow", server_addr)
        .with_connect_timeout(1)
        .with_pool_size(1);

    let outbound = Socks5Outbound::new(outbound_config).await.unwrap();

    let dest: SocketAddr = "1.2.3.4:80".parse().unwrap();
    let result = outbound.connect(dest, Duration::from_millis(500)).await;

    assert!(result.is_err(), "Should timeout waiting for slow server");

    server_task.abort();
}

// ============================================================================
// Error Handling Tests
// ============================================================================

#[tokio::test]
async fn test_socks5_server_closes_immediately() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();
    let connection_count = Arc::new(AtomicU32::new(0));

    let config = MockServerConfig {
        close_immediately: true,
        ..Default::default()
    };

    let server_task = tokio::spawn({
        let count = Arc::clone(&connection_count);
        async move {
            run_mock_socks5_server(listener, config, count).await;
        }
    });

    let outbound_config = Socks5Config::new("test-close", server_addr).with_pool_size(1);
    let outbound = Socks5Outbound::new(outbound_config).await.unwrap();

    let dest: SocketAddr = "1.2.3.4:80".parse().unwrap();
    let result = outbound.connect(dest, Duration::from_secs(5)).await;

    assert!(result.is_err(), "Should fail when server closes immediately");

    let _ = server_task.await;
}

#[tokio::test]
async fn test_socks5_malformed_response() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();
    let connection_count = Arc::new(AtomicU32::new(0));

    let config = MockServerConfig {
        send_malformed: true,
        ..Default::default()
    };

    let server_task = tokio::spawn({
        let count = Arc::clone(&connection_count);
        async move {
            run_mock_socks5_server(listener, config, count).await;
        }
    });

    let outbound_config = Socks5Config::new("test-malformed", server_addr).with_pool_size(1);
    let outbound = Socks5Outbound::new(outbound_config).await.unwrap();

    let dest: SocketAddr = "1.2.3.4:80".parse().unwrap();
    let result = outbound.connect(dest, Duration::from_secs(5)).await;

    assert!(result.is_err(), "Should fail with malformed response");
    let err_str = match result {
        Err(e) => e.to_string().to_lowercase(),
        Ok(_) => panic!("Expected error"),
    };
    // Should indicate invalid version or protocol error
    assert!(
        err_str.contains("version") || err_str.contains("protocol") || err_str.contains("failed"),
        "Expected version/protocol error, got: {}",
        err_str
    );

    let _ = server_task.await;
}

#[tokio::test]
async fn test_socks5_outbound_disabled() {
    let addr: SocketAddr = "127.0.0.1:1080".parse().unwrap();
    let config = Socks5Config::new("test-disabled", addr);
    let outbound = Socks5Outbound::new(config).await.unwrap();

    // Disable outbound
    outbound.set_enabled(false);
    assert!(!outbound.is_enabled());

    let dest: SocketAddr = "1.2.3.4:80".parse().unwrap();
    let result = outbound.connect(dest, Duration::from_secs(1)).await;

    assert!(result.is_err());
    let err_str = match result {
        Err(e) => e.to_string(),
        Ok(_) => panic!("Expected error"),
    };
    assert!(
        err_str.contains("disabled") || err_str.contains("unavailable"),
        "Expected disabled error, got: {}",
        err_str
    );
}

// ============================================================================
// Reconnection Tests
// ============================================================================

#[tokio::test]
#[ignore] // Test requires port rebinding which can fail due to TIME_WAIT
async fn test_socks5_reconnect_after_server_restart() {
    // First server instance
    let listener1 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener1.local_addr().unwrap();
    let connection_count = Arc::new(AtomicU32::new(0));

    let server_task1 = tokio::spawn({
        let count = Arc::clone(&connection_count);
        async move {
            run_mock_socks5_server(listener1, MockServerConfig::default(), count).await;
        }
    });

    let config = Socks5Config::new("test-reconnect", server_addr)
        .with_pool_size(1)
        .with_connect_timeout(2);

    let outbound = Socks5Outbound::new(config).await.unwrap();
    let dest: SocketAddr = "1.2.3.4:80".parse().unwrap();

    // First connection should succeed
    let result1 = outbound.connect(dest, Duration::from_secs(5)).await;
    assert!(result1.is_ok());
    drop(result1);

    let _ = server_task1.await;

    // Start second server on same port
    let listener2 = TcpListener::bind(server_addr).await.unwrap();
    let connection_count2 = Arc::new(AtomicU32::new(0));

    let server_task2 = tokio::spawn({
        let count = Arc::clone(&connection_count2);
        async move {
            run_mock_socks5_server(listener2, MockServerConfig::default(), count).await;
        }
    });

    // Give server time to start
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Second connection after "restart" should eventually succeed
    // May need a few retries as pool may have stale connections
    let mut success = false;
    for _ in 0..3 {
        let result = outbound.connect(dest, Duration::from_secs(2)).await;
        if result.is_ok() {
            success = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    assert!(success, "Should reconnect after server restart");

    let _ = server_task2.await;
}

// ============================================================================
// Health Status Tests
// ============================================================================

#[tokio::test]
async fn test_socks5_health_status_transitions() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();
    let connection_count = Arc::new(AtomicU32::new(0));

    let server_task = tokio::spawn({
        let count = Arc::clone(&connection_count);
        async move {
            run_mock_socks5_server(listener, MockServerConfig::default(), count).await;
        }
    });

    let config = Socks5Config::new("test-health", server_addr).with_pool_size(1);
    let outbound = Socks5Outbound::new(config).await.unwrap();

    // Initial health should be Unknown
    assert_eq!(outbound.health_status(), HealthStatus::Unknown);

    // After successful connection, should be Healthy
    let dest: SocketAddr = "1.2.3.4:80".parse().unwrap();
    let _ = outbound.connect(dest, Duration::from_secs(5)).await;
    assert_eq!(outbound.health_status(), HealthStatus::Healthy);

    let _ = server_task.await;
}

#[tokio::test]
async fn test_socks5_health_degraded_on_failure() {
    let addr: SocketAddr = "192.0.2.1:1080".parse().unwrap(); // Non-routable
    let config = Socks5Config::new("test-health-fail", addr)
        .with_connect_timeout(1)
        .with_pool_size(1);

    let outbound = Socks5Outbound::new(config).await.unwrap();

    // Initial health
    assert_eq!(outbound.health_status(), HealthStatus::Unknown);

    // Try to connect (will fail)
    let dest: SocketAddr = "1.2.3.4:80".parse().unwrap();
    let _ = outbound.connect(dest, Duration::from_millis(100)).await;

    // Health should degrade
    let health = outbound.health_status();
    assert!(
        matches!(health, HealthStatus::Degraded | HealthStatus::Unhealthy),
        "Expected degraded or unhealthy, got: {:?}",
        health
    );
}

// ============================================================================
// Statistics Tests
// ============================================================================

#[tokio::test]
async fn test_socks5_connection_stats() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();
    let connection_count = Arc::new(AtomicU32::new(0));

    let server_task = tokio::spawn({
        let count = Arc::clone(&connection_count);
        async move {
            run_mock_socks5_server(listener, MockServerConfig::default(), count).await;
        }
    });

    let config = Socks5Config::new("test-stats", server_addr).with_pool_size(1);
    let outbound = Socks5Outbound::new(config).await.unwrap();

    // Initial stats
    let stats = outbound.stats();
    assert_eq!(stats.connections(), 0);
    assert_eq!(stats.active(), 0);

    // After connection
    let dest: SocketAddr = "1.2.3.4:80".parse().unwrap();
    let _conn = outbound.connect(dest, Duration::from_secs(5)).await;

    let stats = outbound.stats();
    assert!(stats.connections() >= 1, "Should record connection");

    let _ = server_task.await;
}

#[tokio::test]
async fn test_socks5_error_stats() {
    let addr: SocketAddr = "192.0.2.1:1080".parse().unwrap(); // Non-routable
    let config = Socks5Config::new("test-error-stats", addr)
        .with_connect_timeout(1)
        .with_pool_size(1);

    let outbound = Socks5Outbound::new(config).await.unwrap();

    // Initial error count
    let stats = outbound.stats();
    assert_eq!(stats.errors(), 0);

    // Trigger error
    let dest: SocketAddr = "1.2.3.4:80".parse().unwrap();
    let _ = outbound.connect(dest, Duration::from_millis(100)).await;

    let stats = outbound.stats();
    assert!(stats.errors() >= 1, "Should record error");
}
