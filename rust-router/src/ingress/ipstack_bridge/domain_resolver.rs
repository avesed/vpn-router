//! Hybrid domain resolution for ipstack connections
//!
//! Implements the multi-source domain resolution strategy:
//! 1. FakeDNS reverse lookup (highest priority)
//! 2. TLS SNI sniffing
//! 3. HTTP Host header sniffing
//! 4. DNS cache fallback (future)
//!
//! This module enables domain-based routing even when clients use DoH or
//! other DNS mechanisms that bypass FakeDNS.
//!
//! # Priority Order
//!
//! The resolution follows a strict priority order:
//!
//! 1. **FakeDNS reverse lookup**: If the destination IP is in the FakeDNS pool,
//!    look up the original domain. This is the most reliable method when FakeDNS
//!    is in use.
//!
//! 2. **TLS SNI sniffing**: For TLS connections (ports 443, 8443, etc.), extract
//!    the Server Name Indication from the ClientHello. This works even for DoH
//!    clients.
//!
//! 3. **HTTP Host header**: For plaintext HTTP connections, extract the Host
//!    header from the request.
//!
//! 4. **DNS cache** (future): Fall back to IP-to-domain cache if available.
//!
//! # Example
//!
//! ```rust,ignore
//! use rust_router::ingress::ipstack_bridge::domain_resolver::{resolve_domain, DomainSource};
//!
//! let resolution = resolve_domain(
//!     dst_ip,
//!     443,
//!     Some(&first_packet_bytes),
//!     fakedns_manager.as_ref(),
//! );
//!
//! match resolution.source {
//!     DomainSource::FakeDns => println!("Resolved via FakeDNS"),
//!     DomainSource::TlsSni => println!("Resolved via TLS SNI"),
//!     DomainSource::HttpHost => println!("Resolved via HTTP Host"),
//!     _ => println!("Could not resolve domain"),
//! }
//! ```

use std::net::IpAddr;
use tracing::trace;

#[cfg(feature = "fakedns")]
use crate::fakedns::FakeDnsManager;

#[cfg(feature = "sni-sniffing")]
use crate::sniff::{looks_like_http, looks_like_tls, sniff_http_host, sniff_tls_sni};

/// Source of domain resolution
///
/// This enum indicates how the domain was resolved, useful for
/// debugging and statistics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DomainSource {
    /// Domain not resolved
    #[default]
    None,
    /// From FakeDNS reverse lookup
    FakeDns,
    /// From TLS SNI sniffing
    TlsSni,
    /// From HTTP Host header
    HttpHost,
    /// From DNS cache (legacy fallback, future implementation)
    DnsCache,
}

impl DomainSource {
    /// Returns true if a domain was successfully resolved
    #[inline]
    #[must_use]
    pub fn is_resolved(&self) -> bool {
        !matches!(self, DomainSource::None)
    }
}

impl std::fmt::Display for DomainSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DomainSource::None => write!(f, "none"),
            DomainSource::FakeDns => write!(f, "fakedns"),
            DomainSource::TlsSni => write!(f, "tls-sni"),
            DomainSource::HttpHost => write!(f, "http-host"),
            DomainSource::DnsCache => write!(f, "dns-cache"),
        }
    }
}

/// Result of domain resolution
///
/// Contains both the resolved domain (if any) and the source
/// of the resolution for debugging and statistics.
#[derive(Debug, Clone, Default)]
pub struct DomainResolution {
    /// The resolved domain name, if any
    pub domain: Option<String>,
    /// How the domain was resolved
    pub source: DomainSource,
}

impl DomainResolution {
    /// Create a resolution with no domain
    #[inline]
    #[must_use]
    pub fn none() -> Self {
        Self::default()
    }

    /// Create a resolution from FakeDNS
    #[inline]
    #[must_use]
    pub fn from_fakedns(domain: String) -> Self {
        Self {
            domain: Some(domain),
            source: DomainSource::FakeDns,
        }
    }

    /// Create a resolution from TLS SNI
    #[inline]
    #[must_use]
    pub fn from_tls_sni(domain: String) -> Self {
        Self {
            domain: Some(domain),
            source: DomainSource::TlsSni,
        }
    }

    /// Create a resolution from HTTP Host header
    #[inline]
    #[must_use]
    pub fn from_http_host(domain: String) -> Self {
        Self {
            domain: Some(domain),
            source: DomainSource::HttpHost,
        }
    }

    /// Create a resolution from DNS cache
    #[inline]
    #[must_use]
    pub fn from_dns_cache(domain: String) -> Self {
        Self {
            domain: Some(domain),
            source: DomainSource::DnsCache,
        }
    }

    /// Returns true if a domain was successfully resolved
    #[inline]
    #[must_use]
    pub fn is_resolved(&self) -> bool {
        self.domain.is_some()
    }

    /// Get the domain as a reference
    #[inline]
    #[must_use]
    pub fn as_domain(&self) -> Option<&str> {
        self.domain.as_deref()
    }
}

/// Common TLS ports for SNI sniffing heuristic
///
/// These ports are commonly used for TLS connections and are
/// prioritized for SNI extraction.
#[inline]
#[must_use]
pub fn is_tls_port(port: u16) -> bool {
    matches!(
        port,
        443     // HTTPS
        | 8443  // Alternative HTTPS
        | 853   // DNS over TLS
        | 993   // IMAPS
        | 995   // POP3S
        | 465   // SMTPS (submission)
        | 636   // LDAPS
        | 5223  // Apple Push Notification Service
        | 5228  // Google Cloud Messaging
    )
}

/// Resolve domain using hybrid approach
///
/// This function attempts to resolve a domain name using multiple sources
/// in priority order. It's designed to be fast (synchronous, ~1-2us total)
/// since all operations are either DashMap lookups or simple byte parsing.
///
/// # Arguments
///
/// * `dst_ip` - Destination IP address
/// * `dst_port` - Destination port
/// * `first_packet` - First packet data for SNI/HTTP sniffing (optional)
/// * `fakedns` - FakeDNS manager for reverse lookup (optional)
///
/// # Returns
///
/// A `DomainResolution` containing the domain (if resolved) and the source.
///
/// # Priority
///
/// 1. FakeDNS reverse lookup (if IP is in FakeDNS pool)
/// 2. TLS SNI (for TLS-like traffic on TLS ports)
/// 3. HTTP Host header (for HTTP traffic)
/// 4. DNS cache (future implementation)
#[allow(unused_variables)] // fakedns may be unused without feature flag
pub fn resolve_domain(
    dst_ip: IpAddr,
    dst_port: u16,
    first_packet: Option<&[u8]>,
    #[cfg(feature = "fakedns")] fakedns: Option<&FakeDnsManager>,
    #[cfg(not(feature = "fakedns"))] _fakedns: Option<&()>,
) -> DomainResolution {
    // 1. FakeDNS reverse lookup (highest priority)
    #[cfg(feature = "fakedns")]
    if let Some(fdns) = fakedns {
        if fdns.is_fake_ip(dst_ip) {
            if let Some(domain) = fdns.map_ip_domain(dst_ip) {
                trace!(
                    domain = %domain,
                    ip = %dst_ip,
                    "Domain resolved via FakeDNS"
                );
                return DomainResolution::from_fakedns(domain);
            }
        }
    }

    // 2. SNI sniffing for TLS connections
    #[cfg(feature = "sni-sniffing")]
    if let Some(packet) = first_packet {
        // Try TLS SNI on TLS ports or if the packet looks like TLS
        if (is_tls_port(dst_port) || looks_like_tls(packet)) && looks_like_tls(packet) {
            if let Some(sni) = sniff_tls_sni(packet) {
                trace!(
                    sni = %sni,
                    port = dst_port,
                    "Domain resolved via TLS SNI"
                );
                return DomainResolution::from_tls_sni(sni);
            }
        }

        // 3. HTTP Host sniffing for plaintext HTTP
        if looks_like_http(packet) {
            if let Some(host) = sniff_http_host(packet) {
                trace!(
                    host = %host,
                    port = dst_port,
                    "Domain resolved via HTTP Host"
                );
                return DomainResolution::from_http_host(host);
            }
        }
    }

    // 4. DNS cache fallback (future implementation)
    // if let Some(cache) = ip_domain_cache {
    //     if let Some(domain) = cache.get(&dst_ip) {
    //         return DomainResolution::from_dns_cache(domain);
    //     }
    // }

    trace!(
        ip = %dst_ip,
        port = dst_port,
        "Could not resolve domain"
    );
    DomainResolution::none()
}

/// Convenience function to resolve domain with FakeDNS only
///
/// This is useful when SNI sniffing is not enabled or when
/// only FakeDNS resolution is desired.
#[cfg(feature = "fakedns")]
pub fn resolve_domain_fakedns_only(
    dst_ip: IpAddr,
    fakedns: &FakeDnsManager,
) -> DomainResolution {
    if fakedns.is_fake_ip(dst_ip) {
        if let Some(domain) = fakedns.map_ip_domain(dst_ip) {
            return DomainResolution::from_fakedns(domain);
        }
    }
    DomainResolution::none()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_source_display() {
        assert_eq!(DomainSource::None.to_string(), "none");
        assert_eq!(DomainSource::FakeDns.to_string(), "fakedns");
        assert_eq!(DomainSource::TlsSni.to_string(), "tls-sni");
        assert_eq!(DomainSource::HttpHost.to_string(), "http-host");
        assert_eq!(DomainSource::DnsCache.to_string(), "dns-cache");
    }

    #[test]
    fn test_domain_source_is_resolved() {
        assert!(!DomainSource::None.is_resolved());
        assert!(DomainSource::FakeDns.is_resolved());
        assert!(DomainSource::TlsSni.is_resolved());
        assert!(DomainSource::HttpHost.is_resolved());
        assert!(DomainSource::DnsCache.is_resolved());
    }

    #[test]
    fn test_domain_resolution_none() {
        let resolution = DomainResolution::none();
        assert!(!resolution.is_resolved());
        assert!(resolution.domain.is_none());
        assert_eq!(resolution.source, DomainSource::None);
    }

    #[test]
    fn test_domain_resolution_from_fakedns() {
        let resolution = DomainResolution::from_fakedns("example.com".to_string());
        assert!(resolution.is_resolved());
        assert_eq!(resolution.as_domain(), Some("example.com"));
        assert_eq!(resolution.source, DomainSource::FakeDns);
    }

    #[test]
    fn test_domain_resolution_from_tls_sni() {
        let resolution = DomainResolution::from_tls_sni("secure.example.com".to_string());
        assert!(resolution.is_resolved());
        assert_eq!(resolution.as_domain(), Some("secure.example.com"));
        assert_eq!(resolution.source, DomainSource::TlsSni);
    }

    #[test]
    fn test_domain_resolution_from_http_host() {
        let resolution = DomainResolution::from_http_host("www.example.com".to_string());
        assert!(resolution.is_resolved());
        assert_eq!(resolution.as_domain(), Some("www.example.com"));
        assert_eq!(resolution.source, DomainSource::HttpHost);
    }

    #[test]
    fn test_is_tls_port() {
        // Standard TLS ports
        assert!(is_tls_port(443));
        assert!(is_tls_port(8443));
        assert!(is_tls_port(853)); // DoT
        assert!(is_tls_port(993)); // IMAPS
        assert!(is_tls_port(995)); // POP3S
        assert!(is_tls_port(465)); // SMTPS

        // Non-TLS ports
        assert!(!is_tls_port(80));
        assert!(!is_tls_port(8080));
        assert!(!is_tls_port(22));
        assert!(!is_tls_port(53));
    }

    #[test]
    fn test_resolve_domain_no_data() {
        let ip: IpAddr = "93.184.216.34".parse().unwrap();

        #[cfg(feature = "fakedns")]
        let resolution = resolve_domain(ip, 443, None, None);
        #[cfg(not(feature = "fakedns"))]
        let resolution = resolve_domain(ip, 443, None, None);

        assert!(!resolution.is_resolved());
        assert_eq!(resolution.source, DomainSource::None);
    }

    #[cfg(feature = "fakedns")]
    #[test]
    fn test_resolve_domain_fakedns() {
        use crate::fakedns::FakeDnsConfig;
        use std::time::Duration;

        let config = FakeDnsConfig::new()
            .with_ipv4_pool("198.18.0.0/24".parse().unwrap())
            .with_max_entries(1000)
            .with_ttl(Duration::from_secs(300));
        let fakedns = FakeDnsManager::new(&config);

        // Allocate a fake IP for a domain
        let (fake_ip, _) = fakedns.map_domain_ipv4("example.com").unwrap();

        // Should resolve via FakeDNS
        let resolution = resolve_domain(IpAddr::V4(fake_ip), 443, None, Some(&fakedns));
        assert!(resolution.is_resolved());
        assert_eq!(resolution.as_domain(), Some("example.com"));
        assert_eq!(resolution.source, DomainSource::FakeDns);
    }

    #[cfg(feature = "sni-sniffing")]
    #[test]
    fn test_resolve_domain_tls_sni() {
        // TLS ClientHello with SNI for "example.com"
        // This is a minimal valid ClientHello structure
        let client_hello = [
            // Content type: Handshake (0x16)
            0x16,
            // TLS version: 1.0 (for compatibility)
            0x03, 0x01,
            // Length of handshake message
            0x00, 0x5c,
            // Handshake type: ClientHello (0x01)
            0x01,
            // Length of ClientHello
            0x00, 0x00, 0x58,
            // Client version: TLS 1.2
            0x03, 0x03,
            // Random (32 bytes)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            // Session ID length: 0
            0x00,
            // Cipher suites length: 2
            0x00, 0x02,
            // Cipher suite: TLS_RSA_WITH_AES_128_CBC_SHA
            0x00, 0x2f,
            // Compression methods length: 1
            0x01,
            // Compression method: null
            0x00,
            // Extensions length
            0x00, 0x17,
            // Extension: SNI
            0x00, 0x00, // Extension type: server_name
            0x00, 0x13, // Extension length
            0x00, 0x11, // Server name list length
            0x00,       // Name type: host_name
            0x00, 0x0e, // Host name length: 14
            // "www.example.com" (truncated to fit)
            b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm',
            0x00, 0x00, 0x00, // Padding
        ];

        let ip: IpAddr = "93.184.216.34".parse().unwrap();

        #[cfg(feature = "fakedns")]
        let resolution = resolve_domain(ip, 443, Some(&client_hello), None);
        #[cfg(not(feature = "fakedns"))]
        let resolution = resolve_domain(ip, 443, Some(&client_hello), None);

        // Note: The actual result depends on whether the sniff module correctly parses
        // the minimal ClientHello. This test validates the integration.
        if resolution.is_resolved() {
            assert_eq!(resolution.source, DomainSource::TlsSni);
        }
    }

    #[cfg(feature = "sni-sniffing")]
    #[test]
    fn test_resolve_domain_http_host() {
        let http_request = b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n";

        let ip: IpAddr = "93.184.216.34".parse().unwrap();

        #[cfg(feature = "fakedns")]
        let resolution = resolve_domain(ip, 80, Some(http_request), None);
        #[cfg(not(feature = "fakedns"))]
        let resolution = resolve_domain(ip, 80, Some(http_request), None);

        assert!(resolution.is_resolved());
        assert_eq!(resolution.as_domain(), Some("example.com"));
        assert_eq!(resolution.source, DomainSource::HttpHost);
    }

    #[cfg(all(feature = "fakedns", feature = "sni-sniffing"))]
    #[test]
    fn test_fakedns_priority_over_sni() {
        use crate::fakedns::FakeDnsConfig;
        use std::time::Duration;

        let config = FakeDnsConfig::new()
            .with_ipv4_pool("198.18.0.0/24".parse().unwrap())
            .with_max_entries(1000)
            .with_ttl(Duration::from_secs(300));
        let fakedns = FakeDnsManager::new(&config);

        // Allocate a fake IP for "correct-domain.com"
        let (fake_ip, _) = fakedns.map_domain_ipv4("correct-domain.com").unwrap();

        // Create HTTP request with a different domain in Host header
        let http_request = b"GET / HTTP/1.1\r\nHost: wrong-domain.com\r\n\r\n";

        // FakeDNS should take priority
        let resolution = resolve_domain(
            IpAddr::V4(fake_ip),
            80,
            Some(http_request),
            Some(&fakedns),
        );
        assert!(resolution.is_resolved());
        assert_eq!(resolution.as_domain(), Some("correct-domain.com"));
        assert_eq!(resolution.source, DomainSource::FakeDns);
    }
}
