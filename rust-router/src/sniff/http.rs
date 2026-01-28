//! HTTP Host header sniffing
//!
//! This module implements extraction of the `Host` header from HTTP/1.x requests
//! to determine the target domain for routing decisions.
//!
//! ## Implementation
//!
//! When the `sni-sniffing` feature is enabled, this module uses the `httparse`
//! crate for robust HTTP parsing. Otherwise, it falls back to a minimal hand-written
//! parser for basic Host extraction.
//!
//! ## HTTP Request Format
//!
//! ```text
//! Method SP Request-URI SP HTTP-Version CRLF
//! Header-Field CRLF
//! ...
//! CRLF
//! [ Message-Body ]
//! ```
//!
//! ## Example
//!
//! ```
//! use rust_router::sniff::http::{sniff_http, sniff_http_host, looks_like_http};
//!
//! let data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
//!
//! if looks_like_http(data) {
//!     if let Some(result) = sniff_http(data) {
//!         println!("HTTP request to: {:?}", result.host);
//!     }
//! }
//! ```

use tracing::trace;

/// HTTP sniffing result
///
/// Contains extracted information from an HTTP request.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HttpSniffResult {
    /// Host header value (without port)
    pub host: Option<String>,
    /// Request method (GET, POST, etc.)
    pub method: Option<String>,
    /// Request path
    pub path: Option<String>,
    /// HTTP version (1 for HTTP/1.1, 0 for HTTP/1.0)
    pub version: Option<u8>,
}

impl HttpSniffResult {
    /// Create an empty result
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Check if any useful information was extracted
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.host.is_none() && self.method.is_none() && self.path.is_none() && self.version.is_none()
    }
}

/// Quick check if data looks like an HTTP request
///
/// This is a fast heuristic that checks for common HTTP method prefixes.
/// Use `sniff_http()` for complete parsing.
///
/// # Arguments
///
/// * `data` - Raw bytes to check
///
/// # Returns
///
/// Returns `true` if the data starts with a known HTTP method.
#[must_use]
pub fn looks_like_http(data: &[u8]) -> bool {
    if data.len() < 4 {
        return false;
    }

    // Check for common HTTP method prefixes
    // GET, POST, PUT, HEAD, DELETE, OPTIONS, PATCH, CONNECT, TRACE
    matches!(
        &data[..4],
        b"GET " | b"POST" | b"PUT " | b"HEAD" | b"DELE" | b"OPTI" | b"PATC" | b"CONN" | b"TRAC"
    )
}

// ============================================================================
// httparse-based implementation (feature: sni-sniffing)
// ============================================================================

#[cfg(feature = "sni-sniffing")]
mod parser_impl {
    use super::{trace, HttpSniffResult};

    /// Maximum number of headers to parse
    const MAX_HEADERS: usize = 64;

    /// Extract HTTP information from data using httparse
    ///
    /// # Arguments
    ///
    /// * `data` - Raw bytes that might contain an HTTP request
    ///
    /// # Returns
    ///
    /// Returns `Some(HttpSniffResult)` if HTTP request headers were detected,
    /// `None` if the data is not a valid HTTP request.
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::sniff::http::sniff_http;
    ///
    /// let data = b"GET /path HTTP/1.1\r\nHost: example.com\r\n\r\n";
    /// if let Some(result) = sniff_http(data) {
    ///     assert_eq!(result.host, Some("example.com".to_string()));
    ///     assert_eq!(result.method, Some("GET".to_string()));
    ///     assert_eq!(result.path, Some("/path".to_string()));
    ///     assert_eq!(result.version, Some(1));
    /// }
    /// ```
    #[must_use]
    pub fn sniff_http(data: &[u8]) -> Option<HttpSniffResult> {
        // Quick sanity check
        if !super::looks_like_http(data) {
            trace!("Data does not look like HTTP");
            return None;
        }

        let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
        let mut req = httparse::Request::new(&mut headers);

        match req.parse(data) {
            Ok(httparse::Status::Complete(_) | httparse::Status::Partial) => {
                // Even partial requests may have useful information
                let mut result = HttpSniffResult::default();

                // Extract method
                if let Some(method) = req.method {
                    result.method = Some(method.to_string());
                    trace!("HTTP method: {}", method);
                }

                // Extract path
                if let Some(path) = req.path {
                    result.path = Some(path.to_string());
                    trace!("HTTP path: {}", path);
                }

                // Extract version
                if let Some(version) = req.version {
                    result.version = Some(version);
                    trace!("HTTP version: 1.{}", version);
                }

                // Find Host header (case-insensitive)
                for header in req.headers.iter() {
                    if header.name.eq_ignore_ascii_case("host") {
                        if let Ok(value) = std::str::from_utf8(header.value) {
                            let host = strip_port(value.trim());
                            if !host.is_empty() && is_valid_hostname(host) {
                                result.host = Some(host.to_string());
                                trace!("HTTP Host: {}", host);
                            }
                        }
                        break;
                    }
                }

                // Only return if we extracted something useful
                if result.is_empty() {
                    trace!("No useful information extracted from HTTP request");
                    None
                } else {
                    Some(result)
                }
            }
            Err(e) => {
                trace!("Failed to parse HTTP request: {:?}", e);
                None
            }
        }
    }

    /// Strip port number from host value
    ///
    /// Handles both `example.com:8080` and `[::1]:8080` (IPv6) formats.
    fn strip_port(host: &str) -> &str {
        // Handle IPv6 addresses in brackets: [::1]:8080
        if host.starts_with('[') {
            if let Some(bracket_end) = host.find(']') {
                // Return the bracketed portion without brackets
                return &host[1..bracket_end];
            }
        }

        // Handle regular host:port
        if let Some(colon_pos) = host.rfind(':') {
            // Make sure it's a port number (all digits after colon)
            let potential_port = &host[colon_pos + 1..];
            if !potential_port.is_empty() && potential_port.chars().all(|c| c.is_ascii_digit()) {
                return &host[..colon_pos];
            }
        }

        host
    }

    /// Validate hostname according to RFC 1123
    fn is_valid_hostname(hostname: &str) -> bool {
        if hostname.is_empty() || hostname.len() > 253 {
            return false;
        }

        // Must be ASCII and not contain null bytes
        if !hostname.is_ascii() || hostname.contains('\0') {
            return false;
        }

        // Allow IP addresses (digits and dots/colons)
        // and hostnames (alphanumeric, hyphens, dots)
        hostname
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == ':')
    }
}

// ============================================================================
// Fallback implementation (no httparse)
// ============================================================================

#[cfg(not(feature = "sni-sniffing"))]
mod parser_impl {
    use super::{trace, HttpSniffResult};

    /// Extract HTTP information from data (fallback implementation)
    ///
    /// This is a minimal hand-written parser used when the `sni-sniffing`
    /// feature is not enabled.
    #[must_use]
    pub fn sniff_http(data: &[u8]) -> Option<HttpSniffResult> {
        // Quick sanity check
        if !super::looks_like_http(data) {
            trace!("Data does not look like HTTP");
            return None;
        }

        // Convert to string for easier parsing
        let text = match std::str::from_utf8(data) {
            Ok(s) => s,
            Err(_) => {
                trace!("HTTP data is not valid UTF-8");
                return None;
            }
        };

        let mut result = HttpSniffResult::default();

        // Parse request line
        let mut lines = text.lines();
        if let Some(request_line) = lines.next() {
            let parts: Vec<&str> = request_line.split_whitespace().collect();
            if parts.len() >= 3 {
                result.method = Some(parts[0].to_string());
                result.path = Some(parts[1].to_string());

                // Parse HTTP version
                if parts[2].starts_with("HTTP/1.") {
                    if let Some(version_char) = parts[2].chars().last() {
                        if let Some(version) = version_char.to_digit(10) {
                            result.version = Some(version as u8);
                        }
                    }
                }
            }
        }

        // Parse headers to find Host
        for line in lines {
            if line.is_empty() {
                // End of headers
                break;
            }

            if let Some(colon_pos) = line.find(':') {
                let header_name = &line[..colon_pos];
                let header_value = line[colon_pos + 1..].trim();

                if header_name.eq_ignore_ascii_case("host") {
                    let host = strip_port(header_value);
                    if !host.is_empty() && is_valid_hostname(host) {
                        result.host = Some(host.to_string());
                        trace!("HTTP Host: {}", host);
                    }
                    break;
                }
            }
        }

        if result.is_empty() {
            None
        } else {
            Some(result)
        }
    }

    /// Strip port number from host value
    fn strip_port(host: &str) -> &str {
        // Handle IPv6 addresses in brackets: [::1]:8080
        if host.starts_with('[') {
            if let Some(bracket_end) = host.find(']') {
                return &host[1..bracket_end];
            }
        }

        // Handle regular host:port
        if let Some(colon_pos) = host.rfind(':') {
            let potential_port = &host[colon_pos + 1..];
            if !potential_port.is_empty() && potential_port.chars().all(|c| c.is_ascii_digit()) {
                return &host[..colon_pos];
            }
        }

        host
    }

    /// Validate hostname according to RFC 1123
    fn is_valid_hostname(hostname: &str) -> bool {
        if hostname.is_empty() || hostname.len() > 253 {
            return false;
        }

        if !hostname.is_ascii() || hostname.contains('\0') {
            return false;
        }

        hostname
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == ':')
    }
}

// Re-export the implementation
pub use parser_impl::sniff_http;

/// Extract HTTP Host header from data (simplified API)
///
/// This function provides a simpler interface when you only need the Host header.
/// For more details about the request, use `sniff_http()`.
///
/// # Arguments
///
/// * `data` - Raw bytes that might contain an HTTP request
///
/// # Returns
///
/// Returns `Some(host)` if Host header was found, `None` otherwise.
/// The port number is stripped if present.
///
/// # Example
///
/// ```
/// use rust_router::sniff::http::sniff_http_host;
///
/// let data = b"GET / HTTP/1.1\r\nHost: example.com:8080\r\n\r\n";
/// assert_eq!(sniff_http_host(data), Some("example.com".to_string()));
/// ```
#[must_use]
pub fn sniff_http_host(data: &[u8]) -> Option<String> {
    sniff_http(data).and_then(|r| r.host)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_looks_like_http_get() {
        assert!(looks_like_http(b"GET / HTTP/1.1\r\n"));
    }

    #[test]
    fn test_looks_like_http_post() {
        assert!(looks_like_http(b"POST /api HTTP/1.1\r\n"));
    }

    #[test]
    fn test_looks_like_http_put() {
        assert!(looks_like_http(b"PUT /resource HTTP/1.1\r\n"));
    }

    #[test]
    fn test_looks_like_http_head() {
        assert!(looks_like_http(b"HEAD / HTTP/1.1\r\n"));
    }

    #[test]
    fn test_looks_like_http_delete() {
        assert!(looks_like_http(b"DELETE /item HTTP/1.1\r\n"));
    }

    #[test]
    fn test_looks_like_http_options() {
        assert!(looks_like_http(b"OPTIONS * HTTP/1.1\r\n"));
    }

    #[test]
    fn test_looks_like_http_patch() {
        assert!(looks_like_http(b"PATCH /item HTTP/1.1\r\n"));
    }

    #[test]
    fn test_looks_like_http_connect() {
        assert!(looks_like_http(b"CONNECT example.com:443 HTTP/1.1\r\n"));
    }

    #[test]
    fn test_looks_like_http_trace() {
        assert!(looks_like_http(b"TRACE / HTTP/1.1\r\n"));
    }

    #[test]
    fn test_looks_like_http_not_http() {
        // TLS ClientHello
        assert!(!looks_like_http(&[0x16, 0x03, 0x01, 0x00]));
        // Random binary
        assert!(!looks_like_http(&[0x00, 0x01, 0x02, 0x03]));
        // Too short
        assert!(!looks_like_http(b"GET"));
    }

    #[test]
    fn test_sniff_http_basic() {
        let data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let result = sniff_http(data).expect("Should parse HTTP");

        assert_eq!(result.host, Some("example.com".to_string()));
        assert_eq!(result.method, Some("GET".to_string()));
        assert_eq!(result.path, Some("/".to_string()));
        assert_eq!(result.version, Some(1));
    }

    #[test]
    fn test_sniff_http_host_with_port() {
        let data = b"GET / HTTP/1.1\r\nHost: example.com:8080\r\n\r\n";
        let result = sniff_http(data).expect("Should parse HTTP");

        assert_eq!(result.host, Some("example.com".to_string()));
    }

    #[test]
    fn test_sniff_http_host_only() {
        let data = b"GET / HTTP/1.1\r\nHost: example.com:8080\r\n\r\n";
        assert_eq!(sniff_http_host(data), Some("example.com".to_string()));
    }

    #[test]
    fn test_sniff_http_host_case_insensitive() {
        let data = b"GET / HTTP/1.1\r\nhOsT: example.com\r\n\r\n";
        let result = sniff_http(data).expect("Should parse HTTP");

        assert_eq!(result.host, Some("example.com".to_string()));
    }

    #[test]
    fn test_sniff_http_no_host_header() {
        let data = b"GET / HTTP/1.1\r\nContent-Type: text/html\r\n\r\n";
        let result = sniff_http(data).expect("Should parse HTTP");

        assert_eq!(result.host, None);
        assert_eq!(result.method, Some("GET".to_string()));
    }

    #[test]
    fn test_sniff_http_post_with_path() {
        let data = b"POST /api/users HTTP/1.1\r\nHost: api.example.com\r\nContent-Type: application/json\r\n\r\n{\"name\":\"test\"}";
        let result = sniff_http(data).expect("Should parse HTTP");

        assert_eq!(result.host, Some("api.example.com".to_string()));
        assert_eq!(result.method, Some("POST".to_string()));
        assert_eq!(result.path, Some("/api/users".to_string()));
    }

    #[test]
    fn test_sniff_http_http10() {
        let data = b"GET / HTTP/1.0\r\nHost: example.com\r\n\r\n";
        let result = sniff_http(data).expect("Should parse HTTP");

        assert_eq!(result.version, Some(0));
    }

    #[test]
    fn test_sniff_http_partial_request() {
        // Partial request (no final CRLF CRLF)
        let data = b"GET / HTTP/1.1\r\nHost: example.com";
        let result = sniff_http(data);

        // Should still extract information from partial request
        if let Some(result) = result {
            assert_eq!(result.method, Some("GET".to_string()));
            // Host may or may not be extracted depending on parser behavior
        }
    }

    #[test]
    fn test_sniff_http_not_http() {
        let data = &[0x16, 0x03, 0x01, 0x00, 0x00]; // TLS record
        assert!(sniff_http(data).is_none());
    }

    #[test]
    fn test_sniff_http_empty_host() {
        let data = b"GET / HTTP/1.1\r\nHost: \r\n\r\n";
        let result = sniff_http(data).expect("Should parse HTTP");

        // Empty host should not be recorded
        assert_eq!(result.host, None);
    }

    #[test]
    fn test_sniff_http_ipv6_host() {
        let data = b"GET / HTTP/1.1\r\nHost: [::1]:8080\r\n\r\n";
        let result = sniff_http(data).expect("Should parse HTTP");

        // Should extract IPv6 address without brackets and port
        assert_eq!(result.host, Some("::1".to_string()));
    }

    #[test]
    fn test_sniff_http_ipv4_host() {
        let data = b"GET / HTTP/1.1\r\nHost: 192.168.1.1:8080\r\n\r\n";
        let result = sniff_http(data).expect("Should parse HTTP");

        assert_eq!(result.host, Some("192.168.1.1".to_string()));
    }

    #[test]
    fn test_sniff_http_subdomain() {
        let data = b"GET / HTTP/1.1\r\nHost: www.subdomain.example.com\r\n\r\n";
        let result = sniff_http(data).expect("Should parse HTTP");

        assert_eq!(result.host, Some("www.subdomain.example.com".to_string()));
    }

    #[test]
    fn test_sniff_http_connect_method() {
        let data = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
        let result = sniff_http(data).expect("Should parse HTTP");

        assert_eq!(result.method, Some("CONNECT".to_string()));
        assert_eq!(result.host, Some("example.com".to_string()));
    }

    #[test]
    fn test_sniff_http_multiple_headers() {
        let data = b"GET / HTTP/1.1\r\nUser-Agent: test\r\nHost: example.com\r\nAccept: */*\r\n\r\n";
        let result = sniff_http(data).expect("Should parse HTTP");

        assert_eq!(result.host, Some("example.com".to_string()));
    }

    #[test]
    fn test_http_sniff_result_empty() {
        let result = HttpSniffResult::empty();
        assert!(result.is_empty());

        let result_with_host = HttpSniffResult {
            host: Some("example.com".to_string()),
            ..Default::default()
        };
        assert!(!result_with_host.is_empty());
    }

    #[test]
    fn test_http_sniff_result_method_only() {
        let result = HttpSniffResult {
            method: Some("GET".to_string()),
            ..Default::default()
        };
        assert!(!result.is_empty());
    }

    #[test]
    fn test_sniff_http_host_whitespace() {
        let data = b"GET / HTTP/1.1\r\nHost:   example.com  \r\n\r\n";
        let result = sniff_http(data).expect("Should parse HTTP");

        assert_eq!(result.host, Some("example.com".to_string()));
    }
}
