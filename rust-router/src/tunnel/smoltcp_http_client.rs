//! HTTP client over smoltcp TCP socket through WireGuard tunnel
//!
//! This module provides `SmoltcpHttpClient`, which sends HTTP requests through
//! a smoltcp TCP/IP stack bridged to a WireGuard tunnel.
//!
//! # Architecture
//!
//! ```text
//! +------------------+     +-----------------+     +------------------+
//! | SmoltcpHttpClient|     | SmoltcpBridge   |     | WireGuard Tunnel |
//! |                  |     |                 |     |                  |
//! | HTTP request     | --> | TCP socket      | --> | Encrypted UDP    |
//! | HTTP response    | <-- | TCP/IP stack    | <-- | Decrypted IP     |
//! +------------------+     +-----------------+     +------------------+
//! ```
//!
//! # Usage
//!
//! ```ignore
//! use std::net::Ipv4Addr;
//! use std::time::Duration;
//! use rust_router::tunnel::smoltcp_http_client::SmoltcpHttpClient;
//! use rust_router::tunnel::SmoltcpBridge;
//!
//! // Create bridge with local tunnel IP
//! let bridge = SmoltcpBridge::new(Ipv4Addr::new(10, 200, 200, 2), 1420);
//!
//! // Create HTTP client
//! let mut client = SmoltcpHttpClient::new(bridge);
//!
//! // Make a request
//! let response = client.request(
//!     Ipv4Addr::new(10, 200, 200, 1),
//!     36000,
//!     "GET",
//!     "/api/health",
//!     None,
//!     None,
//!     Duration::from_secs(10),
//!     &tx_sender,
//!     &mut rx_receiver,
//! ).await?;
//!
//! println!("Status: {}", response.status_code);
//! ```

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::Duration;

use smoltcp::iface::SocketHandle;
use smoltcp::socket::tcp::State as TcpState;
use smoltcp::wire::{IpAddress, Ipv4Address};
use thiserror::Error;
use tokio::sync::mpsc;
use tokio::time::{sleep, timeout, Instant};
use tracing::{debug, trace};

use crate::tunnel::smoltcp_bridge::SmoltcpBridge;

/// Minimum poll interval to avoid busy-waiting
const MIN_POLL_INTERVAL_MS: u64 = 1;

/// Maximum poll interval
const MAX_POLL_INTERVAL_MS: u64 = 100;

/// Maximum HTTP response size (1 MB)
const MAX_RESPONSE_SIZE: usize = 1024 * 1024;

/// Error types for HTTP client operations
#[derive(Debug, Error)]
pub enum HttpClientError {
    /// Failed to establish TCP connection
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    /// Operation timed out
    #[error("Request timed out")]
    Timeout,

    /// Invalid HTTP response
    #[error("Invalid response: {0}")]
    InvalidResponse(String),

    /// Error from the WireGuard tunnel
    #[error("Tunnel error: {0}")]
    TunnelError(String),

    /// smoltcp socket error
    #[error("Socket error: {0}")]
    SocketError(String),

    /// Response too large
    #[error("Response too large: {0} bytes (max {MAX_RESPONSE_SIZE})")]
    ResponseTooLarge(usize),

    /// Failed to create socket
    #[error("Failed to create socket: socket set full")]
    SocketSetFull,

    /// Connection closed by peer
    #[error("Connection closed by peer")]
    ConnectionClosed,

    /// HTTP parse error
    #[error("HTTP parse error: {0}")]
    ParseError(String),
}

/// HTTP response from the server
#[derive(Debug, Clone)]
pub struct HttpResponse {
    /// HTTP status code (e.g., 200, 404, 500)
    pub status_code: u16,
    /// Response headers
    pub headers: HashMap<String, String>,
    /// Response body as string
    pub body: String,
}

impl HttpResponse {
    /// Check if the response indicates success (2xx status code)
    #[must_use]
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status_code)
    }

    /// Get a header value by name (case-insensitive)
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        let name_lower = name.to_lowercase();
        self.headers
            .iter()
            .find(|(k, _)| k.to_lowercase() == name_lower)
            .map(|(_, v)| v.as_str())
    }

    /// Get the Content-Length header value
    #[must_use]
    pub fn content_length(&self) -> Option<usize> {
        self.header("content-length")
            .and_then(|v| v.parse().ok())
    }
}

/// Authentication headers for tunnel requests
#[derive(Debug, Clone, Default)]
pub struct TunnelAuthHeaders {
    /// Source IP in the tunnel (e.g., "10.200.200.2")
    pub source_ip: Option<String>,
    /// Peer tag identifier
    pub peer_tag: Option<String>,
    /// HMAC authentication signature
    pub auth_signature: Option<String>,
}

impl TunnelAuthHeaders {
    /// Create new empty auth headers
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the source IP
    #[must_use]
    pub fn with_source_ip(mut self, ip: impl Into<String>) -> Self {
        self.source_ip = Some(ip.into());
        self
    }

    /// Set the peer tag
    #[must_use]
    pub fn with_peer_tag(mut self, tag: impl Into<String>) -> Self {
        self.peer_tag = Some(tag.into());
        self
    }

    /// Set the auth signature
    #[must_use]
    pub fn with_auth_signature(mut self, sig: impl Into<String>) -> Self {
        self.auth_signature = Some(sig.into());
        self
    }

    /// Convert to HTTP headers
    #[must_use]
    pub fn to_headers(&self) -> HashMap<String, String> {
        let mut headers = HashMap::new();
        if let Some(ref ip) = self.source_ip {
            headers.insert("X-Tunnel-Source-IP".to_string(), ip.clone());
        }
        if let Some(ref tag) = self.peer_tag {
            headers.insert("X-Tunnel-Peer-Tag".to_string(), tag.clone());
        }
        if let Some(ref sig) = self.auth_signature {
            headers.insert("X-Tunnel-Auth".to_string(), sig.clone());
        }
        headers
    }
}

/// HTTP client that sends requests through smoltcp over WireGuard tunnel
///
/// This client manages a smoltcp bridge and handles the event loop for
/// TCP communication through the tunnel.
///
/// # Thread Safety
///
/// This struct is NOT thread-safe. It should be used from a single async task.
/// Each request creates a new TCP socket and closes it after the response.
pub struct SmoltcpHttpClient {
    /// The smoltcp bridge for TCP/IP stack
    bridge: SmoltcpBridge,
}

impl SmoltcpHttpClient {
    /// Create a new HTTP client with the given smoltcp bridge
    ///
    /// # Arguments
    ///
    /// * `bridge` - The smoltcp bridge connected to the WireGuard tunnel
    #[must_use]
    pub fn new(bridge: SmoltcpBridge) -> Self {
        Self { bridge }
    }

    /// Get a reference to the underlying bridge
    #[must_use]
    pub fn bridge(&self) -> &SmoltcpBridge {
        &self.bridge
    }

    /// Get a mutable reference to the underlying bridge
    #[must_use]
    pub fn bridge_mut(&mut self) -> &mut SmoltcpBridge {
        &mut self.bridge
    }

    /// Send an HTTP request through the tunnel
    ///
    /// This method:
    /// 1. Creates a new TCP socket
    /// 2. Establishes TCP connection (3-way handshake)
    /// 3. Sends the HTTP request
    /// 4. Receives the HTTP response
    /// 5. Closes the connection
    ///
    /// # Arguments
    ///
    /// * `remote_ip` - The remote server's IP address
    /// * `remote_port` - The remote server's port
    /// * `method` - HTTP method (GET, POST, etc.)
    /// * `path` - Request path (e.g., "/api/health")
    /// * `headers` - Optional additional headers
    /// * `body` - Optional request body
    /// * `request_timeout` - Timeout for the entire request
    /// * `tx_sender` - Channel to send packets to the WireGuard tunnel
    /// * `rx_receiver` - Channel to receive packets from the WireGuard tunnel
    ///
    /// # Returns
    ///
    /// The HTTP response from the server
    ///
    /// # Errors
    ///
    /// - `ConnectionFailed` - TCP connection could not be established
    /// - `Timeout` - The request timed out
    /// - `InvalidResponse` - The server returned an invalid HTTP response
    /// - `TunnelError` - Error communicating with the WireGuard tunnel
    /// - `SocketError` - smoltcp socket error
    #[allow(clippy::too_many_arguments)]
    pub async fn request(
        &mut self,
        remote_ip: Ipv4Addr,
        remote_port: u16,
        method: &str,
        path: &str,
        headers: Option<HashMap<String, String>>,
        body: Option<&str>,
        request_timeout: Duration,
        tx_sender: &mpsc::Sender<Vec<u8>>,
        rx_receiver: &mut mpsc::Receiver<Vec<u8>>,
    ) -> Result<HttpResponse, HttpClientError> {
        // Create a TCP socket
        let handle = self
            .bridge
            .create_tcp_socket_default()
            .ok_or(HttpClientError::SocketSetFull)?;

        // Wrap the main logic to ensure cleanup
        let result = timeout(
            request_timeout,
            self.do_request(
                handle,
                remote_ip,
                remote_port,
                method,
                path,
                headers,
                body,
                tx_sender,
                rx_receiver,
            ),
        )
        .await;

        // Always clean up the socket
        self.cleanup_socket(handle, tx_sender, rx_receiver).await;

        match result {
            Ok(inner_result) => inner_result,
            Err(_) => Err(HttpClientError::Timeout),
        }
    }

    /// Internal request implementation
    #[allow(clippy::too_many_arguments)]
    async fn do_request(
        &mut self,
        handle: SocketHandle,
        remote_ip: Ipv4Addr,
        remote_port: u16,
        method: &str,
        path: &str,
        headers: Option<HashMap<String, String>>,
        body: Option<&str>,
        tx_sender: &mpsc::Sender<Vec<u8>>,
        rx_receiver: &mut mpsc::Receiver<Vec<u8>>,
    ) -> Result<HttpResponse, HttpClientError> {
        debug!(
            "HTTP request: {} {} to {}:{}",
            method, path, remote_ip, remote_port
        );

        // Build the HTTP request
        let request_bytes = Self::build_request(method, path, &remote_ip.to_string(), remote_port, headers, body);
        trace!("HTTP request built: {} bytes", request_bytes.len());

        // Connect the socket
        self.connect_socket(handle, remote_ip, remote_port, tx_sender, rx_receiver)
            .await?;

        // Send the request
        self.send_data(handle, &request_bytes, tx_sender, rx_receiver)
            .await?;

        // Receive the response
        let response_bytes = self.receive_response(handle, tx_sender, rx_receiver).await?;

        // Parse the response
        Self::parse_response(&response_bytes)
    }

    /// Establish TCP connection
    async fn connect_socket(
        &mut self,
        handle: SocketHandle,
        remote_ip: Ipv4Addr,
        remote_port: u16,
        tx_sender: &mpsc::Sender<Vec<u8>>,
        rx_receiver: &mut mpsc::Receiver<Vec<u8>>,
    ) -> Result<(), HttpClientError> {
        // Convert to smoltcp address
        let remote_addr = IpAddress::Ipv4(Ipv4Address::new(
            remote_ip.octets()[0],
            remote_ip.octets()[1],
            remote_ip.octets()[2],
            remote_ip.octets()[3],
        ));

        // Get a local port
        let local_port = Self::allocate_local_port();

        // Initiate connection using the bridge's helper method
        self.bridge
            .tcp_connect(handle, remote_addr, remote_port, local_port)
            .map_err(|e| HttpClientError::ConnectionFailed(format!("{:?}", e)))?;

        debug!(
            "TCP connecting to {}:{} from local port {}",
            remote_ip, remote_port, local_port
        );

        // Drive the connection until established
        loop {
            // Process any incoming packets
            self.process_rx_packets(rx_receiver);

            // Poll smoltcp
            self.bridge.poll();

            // Check connection state
            let state = self.bridge.tcp_socket_state(handle);
            match state {
                TcpState::Established => {
                    debug!("TCP connection established");
                    break;
                }
                TcpState::Closed | TcpState::TimeWait => {
                    return Err(HttpClientError::ConnectionFailed(
                        "Connection closed during handshake".to_string(),
                    ));
                }
                _ => {
                    // Still connecting, send any outgoing packets
                    self.send_tx_packets(tx_sender).await?;

                    // Wait based on poll_delay
                    let delay = self.get_poll_delay();
                    sleep(delay).await;
                }
            }
        }

        // Send any remaining packets
        self.send_tx_packets(tx_sender).await?;

        Ok(())
    }

    /// Send data through the TCP socket
    async fn send_data(
        &mut self,
        handle: SocketHandle,
        data: &[u8],
        tx_sender: &mpsc::Sender<Vec<u8>>,
        rx_receiver: &mut mpsc::Receiver<Vec<u8>>,
    ) -> Result<(), HttpClientError> {
        let mut sent = 0;
        let total = data.len();

        while sent < total {
            // Process any incoming packets
            self.process_rx_packets(rx_receiver);

            // Poll smoltcp
            self.bridge.poll();

            // Check if socket is still valid
            let state = self.bridge.tcp_socket_state(handle);
            if state != TcpState::Established {
                return Err(HttpClientError::ConnectionClosed);
            }

            // Try to send data
            if self.bridge.tcp_can_send(handle) {
                let socket = self.bridge.get_tcp_socket_mut(handle);
                match socket.send_slice(&data[sent..]) {
                    Ok(n) => {
                        sent += n;
                        trace!("Sent {} bytes ({}/{})", n, sent, total);
                    }
                    Err(e) => {
                        return Err(HttpClientError::SocketError(format!("{:?}", e)));
                    }
                }
            }

            // Send outgoing packets
            self.send_tx_packets(tx_sender).await?;

            if sent < total {
                // Wait before next iteration
                let delay = self.get_poll_delay();
                sleep(delay).await;
            }
        }

        debug!("HTTP request sent: {} bytes", total);
        Ok(())
    }

    /// Receive the HTTP response
    async fn receive_response(
        &mut self,
        handle: SocketHandle,
        tx_sender: &mpsc::Sender<Vec<u8>>,
        rx_receiver: &mut mpsc::Receiver<Vec<u8>>,
    ) -> Result<Vec<u8>, HttpClientError> {
        let mut response = Vec::new();
        let mut headers_complete = false;
        let mut content_length: Option<usize> = None;
        let mut headers_end_pos = 0;

        loop {
            // Process any incoming packets
            self.process_rx_packets(rx_receiver);

            // Poll smoltcp
            self.bridge.poll();

            // Check connection state
            let state = self.bridge.tcp_socket_state(handle);

            // Try to receive data
            if self.bridge.tcp_can_recv(handle) {
                let socket = self.bridge.get_tcp_socket_mut(handle);
                let mut buf = [0u8; 4096];
                match socket.recv_slice(&mut buf) {
                    Ok(n) if n > 0 => {
                        response.extend_from_slice(&buf[..n]);
                        trace!("Received {} bytes (total: {})", n, response.len());

                        // Check for response size limit
                        if response.len() > MAX_RESPONSE_SIZE {
                            return Err(HttpClientError::ResponseTooLarge(response.len()));
                        }

                        // Check if headers are complete
                        if !headers_complete {
                            if let Some(pos) = Self::find_headers_end(&response) {
                                headers_complete = true;
                                headers_end_pos = pos;

                                // Parse Content-Length from headers
                                let headers_str = String::from_utf8_lossy(&response[..pos]);
                                content_length = Self::extract_content_length(&headers_str);
                                trace!("Headers complete, Content-Length: {:?}", content_length);
                            }
                        }

                        // Check if we have the complete response
                        if headers_complete {
                            let body_received = response.len() - headers_end_pos;
                            if let Some(expected) = content_length {
                                if body_received >= expected {
                                    debug!("Response complete: {} bytes", response.len());
                                    break;
                                }
                            }
                        }
                    }
                    Ok(_) => {
                        // No data available
                    }
                    Err(e) => {
                        return Err(HttpClientError::SocketError(format!("{:?}", e)));
                    }
                }
            }

            // Check if connection closed
            match state {
                TcpState::CloseWait | TcpState::Closed | TcpState::TimeWait => {
                    // Connection closed, check if we have a complete response
                    if headers_complete {
                        debug!("Connection closed, response: {} bytes", response.len());
                        break;
                    } else if !response.is_empty() {
                        // Got some data but headers incomplete
                        return Err(HttpClientError::InvalidResponse(
                            "Connection closed before headers complete".to_string(),
                        ));
                    } else {
                        return Err(HttpClientError::ConnectionClosed);
                    }
                }
                TcpState::Established | TcpState::FinWait1 | TcpState::FinWait2 => {
                    // Still receiving
                }
                _ => {
                    // Unexpected state
                    trace!("TCP state: {:?}", state);
                }
            }

            // Send any outgoing packets (ACKs, etc.)
            self.send_tx_packets(tx_sender).await?;

            // Wait before next iteration
            let delay = self.get_poll_delay();
            sleep(delay).await;
        }

        Ok(response)
    }

    /// Clean up the socket after the request
    async fn cleanup_socket(
        &mut self,
        handle: SocketHandle,
        tx_sender: &mpsc::Sender<Vec<u8>>,
        rx_receiver: &mut mpsc::Receiver<Vec<u8>>,
    ) {
        // Close the socket gracefully
        {
            let socket = self.bridge.get_tcp_socket_mut(handle);
            socket.close();
        }

        // Give it a short time to send FIN
        let deadline = Instant::now() + Duration::from_millis(500);
        while Instant::now() < deadline {
            self.process_rx_packets(rx_receiver);
            self.bridge.poll();

            let state = self.bridge.tcp_socket_state(handle);
            if matches!(state, TcpState::Closed | TcpState::TimeWait) {
                break;
            }

            // Send any outgoing packets
            if self.send_tx_packets(tx_sender).await.is_err() {
                break;
            }

            sleep(Duration::from_millis(10)).await;
        }

        // Remove the socket
        self.bridge.remove_socket(handle);
        trace!("Socket cleaned up");
    }

    /// Process incoming packets from the tunnel
    fn process_rx_packets(&mut self, rx_receiver: &mut mpsc::Receiver<Vec<u8>>) {
        // Non-blocking receive of all available packets
        while let Ok(packet) = rx_receiver.try_recv() {
            self.bridge.feed_rx_packet(packet);
        }
    }

    /// Send outgoing packets to the tunnel
    async fn send_tx_packets(
        &mut self,
        tx_sender: &mpsc::Sender<Vec<u8>>,
    ) -> Result<(), HttpClientError> {
        for packet in self.bridge.drain_tx_packets() {
            tx_sender
                .send(packet)
                .await
                .map_err(|e| HttpClientError::TunnelError(format!("Failed to send packet: {}", e)))?;
        }
        Ok(())
    }

    /// Get the poll delay, bounded by min/max
    fn get_poll_delay(&mut self) -> Duration {
        self.bridge
            .poll_delay()
            .map(|d| {
                d.clamp(
                    Duration::from_millis(MIN_POLL_INTERVAL_MS),
                    Duration::from_millis(MAX_POLL_INTERVAL_MS),
                )
            })
            .unwrap_or(Duration::from_millis(MIN_POLL_INTERVAL_MS))
    }

    /// Allocate a local port for the connection
    fn allocate_local_port() -> u16 {
        // Use ephemeral port range (49152-65535)
        use std::sync::atomic::{AtomicU16, Ordering};
        static PORT_COUNTER: AtomicU16 = AtomicU16::new(49152);

        let port = PORT_COUNTER.fetch_add(1, Ordering::Relaxed);
        if port >= 65535 {
            PORT_COUNTER.store(49152, Ordering::Relaxed);
        }
        port
    }

    /// Build an HTTP/1.1 request
    fn build_request(
        method: &str,
        path: &str,
        host: &str,
        port: u16,
        headers: Option<HashMap<String, String>>,
        body: Option<&str>,
    ) -> Vec<u8> {
        let mut request = String::new();

        // Request line
        request.push_str(method);
        request.push(' ');
        request.push_str(path);
        request.push_str(" HTTP/1.1\r\n");

        // Host header
        if port == 80 {
            request.push_str(&format!("Host: {}\r\n", host));
        } else {
            request.push_str(&format!("Host: {}:{}\r\n", host, port));
        }

        // Default headers
        request.push_str("Connection: close\r\n");
        request.push_str("User-Agent: smoltcp-http-client/1.0\r\n");

        // Custom headers (sanitized to prevent header injection)
        if let Some(ref hdrs) = headers {
            for (key, value) in hdrs {
                // Sanitize key and value to prevent HTTP header injection
                // Remove any CR/LF characters that could inject new headers
                let safe_key = Self::sanitize_header_value(key);
                let safe_value = Self::sanitize_header_value(value);
                if !safe_key.is_empty() {
                    request.push_str(&format!("{}: {}\r\n", safe_key, safe_value));
                }
            }
        }

        // Body handling
        if let Some(body_str) = body {
            request.push_str(&format!("Content-Length: {}\r\n", body_str.len()));
            if !headers
                .as_ref()
                .map_or(false, |h| h.contains_key("Content-Type"))
            {
                request.push_str("Content-Type: application/json\r\n");
            }
            request.push_str("\r\n");
            request.push_str(body_str);
        } else {
            request.push_str("\r\n");
        }

        request.into_bytes()
    }

    /// Sanitize a header key or value to prevent HTTP header injection
    ///
    /// Removes carriage return (\r) and line feed (\n) characters that could
    /// be used to inject additional HTTP headers.
    fn sanitize_header_value(value: &str) -> String {
        value
            .chars()
            .filter(|c| *c != '\r' && *c != '\n')
            .collect()
    }

    /// Find the end of HTTP headers (double CRLF)
    fn find_headers_end(data: &[u8]) -> Option<usize> {
        const CRLF_CRLF: &[u8] = b"\r\n\r\n";
        data.windows(4)
            .position(|w| w == CRLF_CRLF)
            .map(|pos| pos + 4)
    }

    /// Extract Content-Length from headers
    fn extract_content_length(headers: &str) -> Option<usize> {
        for line in headers.lines() {
            let lower = line.to_lowercase();
            if lower.starts_with("content-length:") {
                return line
                    .split(':')
                    .nth(1)
                    .and_then(|v| v.trim().parse().ok());
            }
        }
        None
    }

    /// Parse HTTP response
    fn parse_response(data: &[u8]) -> Result<HttpResponse, HttpClientError> {
        let response_str = String::from_utf8_lossy(data);

        // Find headers end
        let headers_end = Self::find_headers_end(data)
            .ok_or_else(|| HttpClientError::InvalidResponse("No headers end found".to_string()))?;

        let headers_str = &response_str[..headers_end];
        let body_str = &response_str[headers_end..];

        // Parse status line
        let mut lines = headers_str.lines();
        let status_line = lines.next().ok_or_else(|| {
            HttpClientError::InvalidResponse("Empty response".to_string())
        })?;

        let status_code = Self::parse_status_line(status_line)?;

        // Parse headers
        let mut headers = HashMap::new();
        for line in lines {
            let line = line.trim();
            if line.is_empty() {
                break;
            }
            if let Some((key, value)) = line.split_once(':') {
                headers.insert(key.trim().to_string(), value.trim().to_string());
            }
        }

        Ok(HttpResponse {
            status_code,
            headers,
            body: body_str.to_string(),
        })
    }

    /// Parse HTTP status line
    fn parse_status_line(line: &str) -> Result<u16, HttpClientError> {
        // Format: "HTTP/1.1 200 OK"
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            return Err(HttpClientError::ParseError(format!(
                "Invalid status line: {}",
                line
            )));
        }

        if !parts[0].starts_with("HTTP/") {
            return Err(HttpClientError::ParseError(format!(
                "Invalid HTTP version: {}",
                parts[0]
            )));
        }

        parts[1]
            .parse()
            .map_err(|_| HttpClientError::ParseError(format!("Invalid status code: {}", parts[1])))
    }
}

impl std::fmt::Debug for SmoltcpHttpClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SmoltcpHttpClient")
            .field("bridge", &self.bridge)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_response_is_success() {
        let response = HttpResponse {
            status_code: 200,
            headers: HashMap::new(),
            body: String::new(),
        };
        assert!(response.is_success());

        let response = HttpResponse {
            status_code: 404,
            headers: HashMap::new(),
            body: String::new(),
        };
        assert!(!response.is_success());
    }

    #[test]
    fn test_http_response_header() {
        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), "application/json".to_string());
        headers.insert("X-Custom".to_string(), "value".to_string());

        let response = HttpResponse {
            status_code: 200,
            headers,
            body: String::new(),
        };

        assert_eq!(response.header("Content-Type"), Some("application/json"));
        assert_eq!(response.header("content-type"), Some("application/json"));
        assert_eq!(response.header("X-Custom"), Some("value"));
        assert_eq!(response.header("Missing"), None);
    }

    #[test]
    fn test_http_response_content_length() {
        let mut headers = HashMap::new();
        headers.insert("Content-Length".to_string(), "42".to_string());

        let response = HttpResponse {
            status_code: 200,
            headers,
            body: String::new(),
        };

        assert_eq!(response.content_length(), Some(42));
    }

    #[test]
    fn test_tunnel_auth_headers() {
        let auth = TunnelAuthHeaders::new()
            .with_source_ip("10.200.200.2")
            .with_peer_tag("dev")
            .with_auth_signature("abc123");

        let headers = auth.to_headers();
        assert_eq!(headers.get("X-Tunnel-Source-IP"), Some(&"10.200.200.2".to_string()));
        assert_eq!(headers.get("X-Tunnel-Peer-Tag"), Some(&"dev".to_string()));
        assert_eq!(headers.get("X-Tunnel-Auth"), Some(&"abc123".to_string()));
    }

    #[test]
    fn test_build_request_get() {
        let request = SmoltcpHttpClient::build_request(
            "GET",
            "/api/health",
            "10.200.200.1",
            36000,
            None,
            None,
        );

        let request_str = String::from_utf8(request).unwrap();
        assert!(request_str.starts_with("GET /api/health HTTP/1.1\r\n"));
        assert!(request_str.contains("Host: 10.200.200.1:36000\r\n"));
        assert!(request_str.contains("Connection: close\r\n"));
        assert!(request_str.ends_with("\r\n\r\n"));
    }

    #[test]
    fn test_build_request_post_with_body() {
        let mut headers = HashMap::new();
        headers.insert("Authorization".to_string(), "Bearer token".to_string());

        let request = SmoltcpHttpClient::build_request(
            "POST",
            "/api/chains",
            "10.200.200.1",
            36000,
            Some(headers),
            Some(r#"{"tag":"test"}"#),
        );

        let request_str = String::from_utf8(request).unwrap();
        assert!(request_str.starts_with("POST /api/chains HTTP/1.1\r\n"));
        assert!(request_str.contains("Content-Length: 14\r\n"));
        assert!(request_str.contains("Content-Type: application/json\r\n"));
        assert!(request_str.contains("Authorization: Bearer token\r\n"));
        assert!(request_str.ends_with(r#"{"tag":"test"}"#));
    }

    #[test]
    fn test_find_headers_end() {
        let data = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        assert_eq!(SmoltcpHttpClient::find_headers_end(data), Some(38));

        let data = b"HTTP/1.1 200 OK\r\n";
        assert_eq!(SmoltcpHttpClient::find_headers_end(data), None);
    }

    #[test]
    fn test_extract_content_length() {
        let headers = "HTTP/1.1 200 OK\r\nContent-Length: 42\r\n\r\n";
        assert_eq!(SmoltcpHttpClient::extract_content_length(headers), Some(42));

        let headers = "HTTP/1.1 200 OK\r\n\r\n";
        assert_eq!(SmoltcpHttpClient::extract_content_length(headers), None);
    }

    #[test]
    fn test_parse_status_line() {
        assert_eq!(SmoltcpHttpClient::parse_status_line("HTTP/1.1 200 OK").unwrap(), 200);
        assert_eq!(SmoltcpHttpClient::parse_status_line("HTTP/1.0 404 Not Found").unwrap(), 404);
        assert_eq!(SmoltcpHttpClient::parse_status_line("HTTP/1.1 500 Internal Server Error").unwrap(), 500);
    }

    #[test]
    fn test_parse_status_line_invalid() {
        assert!(SmoltcpHttpClient::parse_status_line("INVALID").is_err());
        assert!(SmoltcpHttpClient::parse_status_line("HTTP/1.1").is_err());
        assert!(SmoltcpHttpClient::parse_status_line("HTTP/1.1 abc").is_err());
    }

    #[test]
    fn test_parse_response() {
        let response = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello";
        let parsed = SmoltcpHttpClient::parse_response(response).unwrap();

        assert_eq!(parsed.status_code, 200);
        assert_eq!(parsed.header("Content-Type"), Some("text/plain"));
        assert_eq!(parsed.body, "hello");
    }

    #[test]
    fn test_allocate_local_port() {
        let port1 = SmoltcpHttpClient::allocate_local_port();
        let port2 = SmoltcpHttpClient::allocate_local_port();
        assert!(port1 >= 49152 && port1 < 65535);
        assert!(port2 >= 49152 && port2 < 65535);
        assert_ne!(port1, port2);
    }

    #[test]
    fn test_http_client_error_display() {
        let err = HttpClientError::ConnectionFailed("refused".to_string());
        assert!(err.to_string().contains("refused"));

        let err = HttpClientError::Timeout;
        assert_eq!(err.to_string(), "Request timed out");

        let err = HttpClientError::ResponseTooLarge(2000000);
        assert!(err.to_string().contains("2000000"));
    }

    #[test]
    fn test_sanitize_header_value() {
        // Normal values should pass through unchanged
        assert_eq!(
            SmoltcpHttpClient::sanitize_header_value("normal-value"),
            "normal-value"
        );

        // CR/LF should be stripped to prevent header injection
        assert_eq!(
            SmoltcpHttpClient::sanitize_header_value("value\r\nX-Injected: malicious"),
            "valueX-Injected: malicious"
        );

        // Only CR should be stripped
        assert_eq!(
            SmoltcpHttpClient::sanitize_header_value("value\rinjected"),
            "valueinjected"
        );

        // Only LF should be stripped
        assert_eq!(
            SmoltcpHttpClient::sanitize_header_value("value\ninjected"),
            "valueinjected"
        );

        // Empty string should remain empty
        assert_eq!(SmoltcpHttpClient::sanitize_header_value(""), "");
    }

    #[test]
    fn test_build_request_sanitizes_headers() {
        let mut headers = HashMap::new();
        // Attempt header injection via value
        headers.insert(
            "X-Custom".to_string(),
            "value\r\nX-Injected: malicious".to_string(),
        );

        let request = SmoltcpHttpClient::build_request(
            "GET",
            "/api/test",
            "10.200.200.1",
            36000,
            Some(headers),
            None,
        );

        let request_str = String::from_utf8_lossy(&request);

        // The injected header should NOT appear as a separate header
        assert!(!request_str.contains("X-Injected: malicious\r\n"));
        // The sanitized value should be present (without CR/LF)
        assert!(request_str.contains("X-Custom: valueX-Injected: malicious\r\n"));
    }
}
