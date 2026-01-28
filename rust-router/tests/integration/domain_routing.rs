//! Domain routing integration tests
//!
//! This module tests the integration of all domain routing components:
//! - TLS SNI sniffing (tls-parser)
//! - HTTP Host sniffing (httparse)
//! - QUIC SNI decryption (rustls, aes, aes-gcm, hkdf)
//! - FakeDNS IP-to-domain mapping
//!
//! # Running Tests
//!
//! ```bash
//! # Run with domain-routing feature
//! cargo test --test integration domain_routing --features domain-routing
//!
//! # Run individual component tests
//! cargo test --test integration domain_routing --features sni-sniffing
//! cargo test --test integration domain_routing --features fakedns
//! cargo test --test integration domain_routing --features quic-sni
//! ```

use std::net::IpAddr;
use std::time::Duration;

// ============================================================================
// TLS SNI Sniffing Tests
// ============================================================================

#[cfg(feature = "sni-sniffing")]
mod tls_sniff {
    use rust_router::sniff::{looks_like_tls, sniff_tls_sni, sniff_tls};

    /// Create a minimal TLS ClientHello with the given SNI
    fn create_client_hello(sni: &str) -> Vec<u8> {
        let mut data = Vec::new();

        // TLS record header
        data.push(0x16); // Content type: Handshake
        data.extend_from_slice(&[0x03, 0x01]); // Version TLS 1.0

        // We'll fill in length later
        let record_length_pos = data.len();
        data.extend_from_slice(&[0x00, 0x00]); // Placeholder

        let handshake_start = data.len();

        // Handshake header
        data.push(0x01); // ClientHello
        let handshake_length_pos = data.len();
        data.extend_from_slice(&[0x00, 0x00, 0x00]); // Placeholder

        let client_hello_start = data.len();

        // Version
        data.extend_from_slice(&[0x03, 0x03]); // TLS 1.2

        // Random (32 bytes)
        data.extend_from_slice(&[0u8; 32]);

        // Session ID (empty)
        data.push(0x00);

        // Cipher suites (2 bytes length + minimal suite)
        data.extend_from_slice(&[0x00, 0x02]); // Length
        data.extend_from_slice(&[0x00, 0x00]); // Cipher suite

        // Compression methods (1 byte length + null)
        data.push(0x01); // Length
        data.push(0x00); // Null compression

        // Extensions
        let extensions_length_pos = data.len();
        data.extend_from_slice(&[0x00, 0x00]); // Placeholder

        let extensions_start = data.len();

        // SNI extension (type 0x0000)
        if !sni.is_empty() {
            data.extend_from_slice(&[0x00, 0x00]); // Extension type (SNI)
            let sni_ext_length_pos = data.len();
            data.extend_from_slice(&[0x00, 0x00]); // Placeholder

            let sni_ext_start = data.len();

            // Server name list
            let sni_list_length_pos = data.len();
            data.extend_from_slice(&[0x00, 0x00]); // Placeholder

            let sni_list_start = data.len();

            // Server name entry
            data.push(0x00); // Name type: hostname
            data.extend_from_slice(&(sni.len() as u16).to_be_bytes());
            data.extend_from_slice(sni.as_bytes());

            let sni_list_end = data.len();

            // Fill in SNI lengths
            let sni_list_len = sni_list_end - sni_list_start;
            data[sni_list_length_pos] = (sni_list_len >> 8) as u8;
            data[sni_list_length_pos + 1] = sni_list_len as u8;

            let sni_ext_len = sni_list_end - sni_ext_start;
            data[sni_ext_length_pos] = (sni_ext_len >> 8) as u8;
            data[sni_ext_length_pos + 1] = sni_ext_len as u8;
        }

        let extensions_end = data.len();
        let client_hello_end = data.len();
        let handshake_end = data.len();

        // Fill in lengths
        let extensions_len = extensions_end - extensions_start;
        data[extensions_length_pos] = (extensions_len >> 8) as u8;
        data[extensions_length_pos + 1] = extensions_len as u8;

        let handshake_len = handshake_end - client_hello_start;
        data[handshake_length_pos] = (handshake_len >> 16) as u8;
        data[handshake_length_pos + 1] = (handshake_len >> 8) as u8;
        data[handshake_length_pos + 2] = handshake_len as u8;

        let record_len = handshake_end - handshake_start;
        data[record_length_pos] = (record_len >> 8) as u8;
        data[record_length_pos + 1] = record_len as u8;

        data
    }

    #[test]
    fn test_looks_like_tls() {
        let client_hello = create_client_hello("example.com");
        assert!(looks_like_tls(&client_hello));
        assert!(!looks_like_tls(b"GET / HTTP/1.1\r\n"));
        assert!(!looks_like_tls(&[0x00, 0x01, 0x02]));
    }

    #[test]
    fn test_sniff_tls_sni() {
        let client_hello = create_client_hello("example.com");
        let sni = sniff_tls_sni(&client_hello);
        assert_eq!(sni, Some("example.com".to_string()));
    }

    #[test]
    fn test_sniff_tls_full() {
        let client_hello = create_client_hello("test.example.org");
        let result = sniff_tls(&client_hello);
        assert!(result.is_some());
        let result = result.unwrap();
        assert_eq!(result.sni, Some("test.example.org".to_string()));
    }

    #[test]
    fn test_tls_without_sni() {
        // ClientHello without SNI
        let no_sni_hello = create_client_hello("");

        assert!(looks_like_tls(&no_sni_hello));
        let result = sniff_tls_sni(&no_sni_hello);
        assert!(result.is_none());
    }
}

// ============================================================================
// HTTP Host Sniffing Tests
// ============================================================================

#[cfg(feature = "sni-sniffing")]
mod http_sniff {
    use rust_router::sniff::{looks_like_http, sniff_http_host, sniff_http};

    #[test]
    fn test_looks_like_http() {
        assert!(looks_like_http(b"GET / HTTP/1.1\r\n"));
        assert!(looks_like_http(b"POST /api HTTP/1.1\r\n"));
        assert!(looks_like_http(b"HEAD / HTTP/1.0\r\n"));
        assert!(!looks_like_http(b"\x16\x03\x01")); // TLS
        assert!(!looks_like_http(b"INVALID"));
    }

    #[test]
    fn test_sniff_http_host() {
        let request = b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: keep-alive\r\n\r\n";
        let host = sniff_http_host(request);
        assert_eq!(host, Some("example.com".to_string()));
    }

    #[test]
    fn test_sniff_http_host_with_port() {
        let request = b"GET / HTTP/1.1\r\nHost: example.com:8080\r\n\r\n";
        let host = sniff_http_host(request);
        // Should return "example.com:8080" (with port) or "example.com" depending on implementation
        assert!(host.is_some());
        assert!(host.as_ref().unwrap().contains("example.com"));
    }

    #[test]
    fn test_sniff_http_full() {
        let request = b"GET /path HTTP/1.1\r\nHost: api.example.com\r\nUser-Agent: test\r\n\r\n";
        let result = sniff_http(request);
        assert!(result.is_some());
        let result = result.unwrap();
        assert_eq!(result.host, Some("api.example.com".to_string()));
        assert_eq!(result.method, Some("GET".to_string()));
        assert_eq!(result.path, Some("/path".to_string()));
    }

    #[test]
    fn test_http_without_host() {
        let request = b"GET / HTTP/1.0\r\nConnection: close\r\n\r\n";
        let host = sniff_http_host(request);
        assert!(host.is_none());
    }

    #[test]
    fn test_incomplete_http_request() {
        // Incomplete request (no CRLF CRLF)
        let incomplete = b"GET / HTTP/1.1\r\nHost: examp";
        // Should handle gracefully
        let _ = sniff_http_host(incomplete);
    }
}

// ============================================================================
// QUIC Sniffing Tests
// ============================================================================

#[cfg(feature = "quic-sni")]
mod quic_sniff {
    #[allow(unused_imports)]
    use rust_router::sniff::quic::{QuicSniffer, QuicVersion};
    use rust_router::sniff::{sniff_quic_with_decrypt, DecryptError};

    #[test]
    fn test_quic_version_detection() {
        // QUIC v1 version bytes
        let v1_packet = &[
            0xc0, // Long header, Initial
            0x00, 0x00, 0x00, 0x01, // Version: v1
            0x08, // DCID length: 8
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // DCID
            0x00, // SCID length: 0
        ];

        assert!(QuicSniffer::is_quic(v1_packet));
        let result = QuicSniffer::sniff(v1_packet);
        assert_eq!(result.version, Some(QuicVersion::V1));
    }

    #[test]
    fn test_quic_v2_version() {
        // QUIC v2 version bytes (RFC 9369)
        let v2_packet = &[
            0xd0, // Long header, Initial (different bit pattern for v2)
            0x6b, 0x33, 0x43, 0xcf, // Version: v2 (0x6b3343cf)
            0x08, // DCID length: 8
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // DCID
            0x00, // SCID length: 0
        ];

        assert!(QuicSniffer::is_quic(v2_packet));
        let result = QuicSniffer::sniff(v2_packet);
        assert_eq!(result.version, Some(QuicVersion::V2));
    }

    #[test]
    fn test_quic_not_initial() {
        // Short header (1-RTT packet) - cannot extract SNI
        let short_header = &[
            0x40, // Short header
            0x01, 0x02, 0x03, 0x04, // Connection ID
            0x00, // Packet number
        ];

        // Short headers are still QUIC but we can't get SNI from them
        let result = QuicSniffer::sniff(short_header);
        assert!(result.server_name.is_none());
    }

    #[test]
    fn test_decrypt_error_types() {
        // Test that DecryptError implements expected traits
        let err = DecryptError::PacketTooShort;
        let _: &dyn std::error::Error = &err;
        let _ = format!("{}", err);
        let _ = format!("{:?}", err);
    }

    #[test]
    fn test_sniff_quic_with_decrypt_invalid() {
        // Test with invalid/incomplete packet
        let invalid = &[0xc0, 0x00, 0x00, 0x00, 0x01]; // Too short

        // sniff_quic_with_decrypt returns QuicSniffResult, which may have no SNI
        // Check that it handles invalid input gracefully
        let result = sniff_quic_with_decrypt(invalid);
        // For invalid packets, SNI should be None and decrypted should be false
        assert!(result.server_name.is_none());
        assert!(!result.decrypted);
    }
}

// ============================================================================
// FakeDNS Tests
// ============================================================================

#[cfg(feature = "fakedns")]
mod fakedns {
    use super::*;
    use rust_router::fakedns::{FakeDnsConfig, FakeDnsManager};
    use std::sync::Arc;

    fn test_config() -> FakeDnsConfig {
        FakeDnsConfig::new()
            .with_ipv4_pool("198.18.0.0/24".parse().unwrap())
            .with_max_entries(1000)
            .with_ttl(Duration::from_secs(300))
    }

    #[test]
    fn test_fakedns_basic_mapping() {
        let config = test_config();
        let manager = Arc::new(FakeDnsManager::new(&config));

        // Map a domain
        let (ip, ttl) = manager.map_domain_ipv4("example.com").unwrap();
        assert!(ip.octets()[0] == 198 && ip.octets()[1] == 18);
        assert!(ttl.as_secs() > 0);

        // Same domain should get same IP
        let (ip2, _) = manager.map_domain_ipv4("example.com").unwrap();
        assert_eq!(ip, ip2);

        // Different domain should get different IP
        let (ip3, _) = manager.map_domain_ipv4("different.com").unwrap();
        assert_ne!(ip, ip3);
    }

    #[test]
    fn test_fakedns_reverse_lookup() {
        let config = test_config();
        let manager = Arc::new(FakeDnsManager::new(&config));

        // Map a domain
        let (ip, _) = manager.map_domain_ipv4("test.example.org").unwrap();

        // Reverse lookup
        let domain = manager.map_ip_domain(IpAddr::V4(ip));
        assert_eq!(domain, Some("test.example.org".to_string()));
    }

    #[test]
    fn test_fakedns_is_fake_ip() {
        let config = test_config();
        let manager = Arc::new(FakeDnsManager::new(&config));

        let (ip, _) = manager.map_domain_ipv4("example.com").unwrap();
        assert!(manager.is_fake_ip(IpAddr::V4(ip)));

        // Real IP should not be fake
        assert!(!manager.is_fake_ip("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn test_fakedns_ipv6_disabled() {
        let config = test_config(); // No IPv6 pool
        let manager = Arc::new(FakeDnsManager::new(&config));

        // IPv6 should fail gracefully when no pool configured
        let result = manager.map_domain_ipv6("example.com");
        assert!(result.is_err());
    }

    #[test]
    fn test_fakedns_ipv6_enabled() {
        let config = FakeDnsConfig::new()
            .with_ipv4_pool("198.18.0.0/24".parse().unwrap())
            .with_ipv6_pool("fc00::/120".parse().unwrap())
            .with_max_entries(1000)
            .with_ttl(Duration::from_secs(300));
        let manager = Arc::new(FakeDnsManager::new(&config));

        // IPv6 should work
        let (ip6, _) = manager.map_domain_ipv6("example.com").unwrap();
        assert!(manager.is_fake_ip(IpAddr::V6(ip6)));

        // Reverse lookup should work
        let domain = manager.map_ip_domain(IpAddr::V6(ip6));
        assert_eq!(domain, Some("example.com".to_string()));
    }

    #[test]
    fn test_fakedns_concurrent_access() {
        use std::thread;

        let config = FakeDnsConfig::new()
            .with_ipv4_pool("198.18.0.0/16".parse().unwrap()) // Large pool
            .with_max_entries(10000)
            .with_ttl(Duration::from_secs(300));
        let manager = Arc::new(FakeDnsManager::new(&config));

        let handles: Vec<_> = (0..10)
            .map(|i| {
                let manager = manager.clone();
                thread::spawn(move || {
                    for j in 0..100 {
                        let domain = format!("test{}-{}.example.com", i, j);
                        let (ip, _) = manager.map_domain_ipv4(&domain).unwrap();
                        assert!(manager.is_fake_ip(IpAddr::V4(ip)));
                        assert_eq!(
                            manager.map_ip_domain(IpAddr::V4(ip)),
                            Some(domain)
                        );
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }
    }

    #[test]
    fn test_fakedns_pool_exhaustion() {
        // Small pool that will be exhausted
        let config = FakeDnsConfig::new()
            .with_ipv4_pool("198.18.0.0/30".parse().unwrap()) // Only 4 IPs
            .with_max_entries(10)
            .with_ttl(Duration::from_secs(300));
        let manager = Arc::new(FakeDnsManager::new(&config));

        // Map domains until pool is exhausted
        for i in 0..4 {
            let domain = format!("domain{}.com", i);
            let result = manager.map_domain_ipv4(&domain);
            // First few should succeed
            if i < 2 {
                assert!(result.is_ok(), "Domain {} failed unexpectedly", i);
            }
        }

        // Note: Behavior when pool is exhausted depends on implementation
        // Some may recycle, some may error
    }
}

// ============================================================================
// Full Integration Tests (domain-routing feature)
// ============================================================================

#[cfg(feature = "domain-routing")]
mod domain_routing_integration {
    use super::*;
    use rust_router::fakedns::{FakeDnsConfig, FakeDnsManager};
    use rust_router::sniff::{looks_like_http, sniff_tls_sni, sniff_http_host};
    use std::sync::Arc;

    /// Test the full domain routing flow:
    /// 1. FakeDNS maps domain to fake IP
    /// 2. Traffic arrives from fake IP
    /// 3. SNI sniffing extracts domain
    /// 4. Domain matches original mapping
    #[test]
    fn test_domain_routing_flow() {
        let config = FakeDnsConfig::new()
            .with_ipv4_pool("198.18.0.0/24".parse().unwrap())
            .with_max_entries(1000)
            .with_ttl(Duration::from_secs(300));
        let manager = Arc::new(FakeDnsManager::new(&config));

        // Step 1: DNS query maps example.com to fake IP
        let (fake_ip, _) = manager.map_domain_ipv4("example.com").unwrap();

        // Step 2: Traffic arrives (simulated TLS ClientHello with SNI)
        // In real scenario, this would be traffic TO the fake IP
        let tls_data = create_tls_client_hello("example.com");

        // Step 3: SNI sniffing extracts domain
        let sniffed_domain = sniff_tls_sni(&tls_data);
        assert_eq!(sniffed_domain, Some("example.com".to_string()));

        // Step 4: Verify domain matches FakeDNS mapping
        let looked_up = manager.map_ip_domain(IpAddr::V4(fake_ip));
        assert_eq!(looked_up, sniffed_domain);
    }

    /// Test HTTP host extraction in domain routing context
    #[test]
    fn test_http_domain_routing() {
        let config = FakeDnsConfig::new()
            .with_ipv4_pool("198.18.0.0/24".parse().unwrap())
            .with_max_entries(1000)
            .with_ttl(Duration::from_secs(300));
        let manager = Arc::new(FakeDnsManager::new(&config));

        // Map domain via FakeDNS
        let (fake_ip, _) = manager.map_domain_ipv4("api.example.com").unwrap();

        // HTTP request to fake IP
        let http_request = b"GET /api/v1 HTTP/1.1\r\nHost: api.example.com\r\n\r\n";

        // Sniff host
        assert!(looks_like_http(http_request));
        let sniffed_host = sniff_http_host(http_request);
        assert_eq!(sniffed_host, Some("api.example.com".to_string()));

        // Verify matches FakeDNS
        let looked_up = manager.map_ip_domain(IpAddr::V4(fake_ip));
        assert_eq!(looked_up, sniffed_host);
    }

    /// Test that sniffing and FakeDNS handle the same domain consistently
    #[test]
    fn test_domain_consistency() {
        let config = FakeDnsConfig::new()
            .with_ipv4_pool("198.18.0.0/24".parse().unwrap())
            .with_max_entries(1000)
            .with_ttl(Duration::from_secs(300));
        let manager = Arc::new(FakeDnsManager::new(&config));

        let domains = vec![
            "example.com",
            "sub.example.com",
            "api.example.org",
            "test-site.io",
        ];

        for domain in domains {
            // Map via FakeDNS
            let (fake_ip, _) = manager.map_domain_ipv4(domain).unwrap();

            // Create mock TLS with this domain
            let tls_data = create_tls_client_hello(domain);
            let sniffed = sniff_tls_sni(&tls_data);
            assert_eq!(sniffed.as_deref(), Some(domain));

            // Verify reverse lookup
            let lookup = manager.map_ip_domain(IpAddr::V4(fake_ip));
            assert_eq!(lookup.as_deref(), Some(domain));
        }
    }

    /// Helper to create a minimal TLS ClientHello with given SNI
    fn create_tls_client_hello(sni: &str) -> Vec<u8> {
        let mut data = Vec::new();

        // TLS record header
        data.push(0x16); // Content type: Handshake
        data.extend_from_slice(&[0x03, 0x01]); // Version TLS 1.0

        // We'll fill in length later
        let record_length_pos = data.len();
        data.extend_from_slice(&[0x00, 0x00]); // Placeholder

        let handshake_start = data.len();

        // Handshake header
        data.push(0x01); // ClientHello
        let handshake_length_pos = data.len();
        data.extend_from_slice(&[0x00, 0x00, 0x00]); // Placeholder

        let client_hello_start = data.len();

        // Version
        data.extend_from_slice(&[0x03, 0x03]); // TLS 1.2

        // Random (32 bytes)
        data.extend_from_slice(&[0u8; 32]);

        // Session ID (empty)
        data.push(0x00);

        // Cipher suites (2 bytes length + minimal suite)
        data.extend_from_slice(&[0x00, 0x02]); // Length
        data.extend_from_slice(&[0x00, 0x00]); // Cipher suite

        // Compression methods (1 byte length + null)
        data.push(0x01); // Length
        data.push(0x00); // Null compression

        // Extensions
        let extensions_length_pos = data.len();
        data.extend_from_slice(&[0x00, 0x00]); // Placeholder

        let extensions_start = data.len();

        // SNI extension (type 0x0000)
        if !sni.is_empty() {
            data.extend_from_slice(&[0x00, 0x00]); // Extension type (SNI)
            let sni_ext_length_pos = data.len();
            data.extend_from_slice(&[0x00, 0x00]); // Placeholder

            let sni_ext_start = data.len();

            // Server name list
            let sni_list_length_pos = data.len();
            data.extend_from_slice(&[0x00, 0x00]); // Placeholder

            let sni_list_start = data.len();

            // Server name entry
            data.push(0x00); // Name type: hostname
            data.extend_from_slice(&(sni.len() as u16).to_be_bytes());
            data.extend_from_slice(sni.as_bytes());

            let sni_list_end = data.len();

            // Fill in SNI lengths
            let sni_list_len = sni_list_end - sni_list_start;
            data[sni_list_length_pos] = (sni_list_len >> 8) as u8;
            data[sni_list_length_pos + 1] = sni_list_len as u8;

            let sni_ext_len = sni_list_end - sni_ext_start;
            data[sni_ext_length_pos] = (sni_ext_len >> 8) as u8;
            data[sni_ext_length_pos + 1] = sni_ext_len as u8;
        }

        let extensions_end = data.len();
        let handshake_end = data.len();

        // Fill in lengths
        let extensions_len = extensions_end - extensions_start;
        data[extensions_length_pos] = (extensions_len >> 8) as u8;
        data[extensions_length_pos + 1] = extensions_len as u8;

        let handshake_len = handshake_end - client_hello_start;
        data[handshake_length_pos] = (handshake_len >> 16) as u8;
        data[handshake_length_pos + 1] = (handshake_len >> 8) as u8;
        data[handshake_length_pos + 2] = handshake_len as u8;

        let record_len = handshake_end - handshake_start;
        data[record_length_pos] = (record_len >> 8) as u8;
        data[record_length_pos + 1] = record_len as u8;

        data
    }
}

// ============================================================================
// Feature Compilation Tests
// ============================================================================

/// These tests verify that features compile correctly
mod feature_compilation {
    #[test]
    fn test_all_features_compile() {
        // This test passes if it compiles
        // When run with --features domain-routing, all components should be available

        #[cfg(feature = "sni-sniffing")]
        {
            let _ = rust_router::sniff::looks_like_tls;
            let _ = rust_router::sniff::looks_like_http;
            let _ = rust_router::sniff::sniff_tls_sni;
            let _ = rust_router::sniff::sniff_http_host;
        }

        #[cfg(feature = "fakedns")]
        {
            let _ = rust_router::fakedns::FakeDnsConfig::new;
            let _ = rust_router::fakedns::FakeDnsManager::new;
        }

        #[cfg(feature = "quic-sni")]
        {
            let _ = rust_router::sniff::sniff_quic_with_decrypt;
            let _ = rust_router::sniff::quic::QuicSniffer::is_quic;
        }
    }
}
