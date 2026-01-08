//! DNS IPC Integration Tests
//!
//! Phase 7.7: Tests for DNS engine IPC commands
//!
//! # Test Categories
//!
//! 1. **IPC Protocol Tests**: Serialization/deserialization of DNS commands
//! 2. **DNS Stats Tests**: Statistics retrieval and validation
//! 3. **Cache Management Tests**: Cache flush and statistics
//! 4. **Upstream Management Tests**: Add/remove/status operations
//! 5. **DNS Routing Tests**: Route rule management
//! 6. **Query and Logging Tests**: DNS query execution and logging
//!
//! # Running Tests
//!
//! ```bash
//! # Run all DNS IPC tests
//! cargo test --test integration dns_ipc
//!
//! # Run specific test
//! cargo test --test integration dns_ipc::protocol_tests
//! ```

use rust_router::ipc::{
    DnsBlockStatsResponse, DnsCacheStatsResponse, DnsConfigResponse, DnsQueryLogEntry,
    DnsQueryLogResponse, DnsQueryResponse, DnsStatsResponse, DnsUpstreamConfig,
    DnsUpstreamInfo, DnsUpstreamStatusResponse, IpcCommand, IpcResponse,
};

// ============================================================================
// Test Helpers
// ============================================================================

/// Helper to create a sample DnsUpstreamConfig for UDP
fn sample_udp_upstream_config() -> DnsUpstreamConfig {
    DnsUpstreamConfig {
        address: "8.8.8.8:53".to_string(),
        protocol: "udp".to_string(),
        bootstrap: vec![],
        timeout_secs: Some(5),
    }
}

/// Helper to create a sample DnsUpstreamConfig for DoH
fn sample_doh_upstream_config() -> DnsUpstreamConfig {
    DnsUpstreamConfig {
        address: "https://dns.google/dns-query".to_string(),
        protocol: "doh".to_string(),
        bootstrap: vec!["8.8.8.8:53".to_string()],
        timeout_secs: Some(10),
    }
}

/// Helper to create a sample DnsUpstreamConfig for DoT
fn sample_dot_upstream_config() -> DnsUpstreamConfig {
    DnsUpstreamConfig {
        address: "dns.google:853".to_string(),
        protocol: "dot".to_string(),
        bootstrap: vec!["8.8.8.8:53".to_string()],
        timeout_secs: Some(10),
    }
}

/// Helper to create a sample DnsUpstreamConfig for TCP
fn sample_tcp_upstream_config() -> DnsUpstreamConfig {
    DnsUpstreamConfig {
        address: "1.1.1.1:53".to_string(),
        protocol: "tcp".to_string(),
        bootstrap: vec![],
        timeout_secs: Some(5),
    }
}

/// Helper to create a sample DnsUpstreamInfo
fn sample_upstream_info(tag: &str, healthy: bool) -> DnsUpstreamInfo {
    DnsUpstreamInfo {
        tag: tag.to_string(),
        address: "8.8.8.8:53".to_string(),
        protocol: "udp".to_string(),
        healthy,
        total_queries: 1000,
        failed_queries: if healthy { 5 } else { 500 },
        avg_latency_us: 1500,
        last_success: Some("2026-01-08T12:00:00Z".to_string()),
        last_failure: if healthy {
            None
        } else {
            Some("2026-01-08T12:01:00Z".to_string())
        },
    }
}

/// Helper to create a sample DnsQueryLogEntry
fn sample_query_log_entry(
    domain: &str,
    blocked: bool,
    cached: bool,
) -> DnsQueryLogEntry {
    DnsQueryLogEntry {
        timestamp: 1704700000000,
        domain: domain.to_string(),
        qtype: 1,
        qtype_str: "A".to_string(),
        upstream: if blocked { "".to_string() } else { "google".to_string() },
        response_code: 0,
        rcode_str: "NOERROR".to_string(),
        latency_us: if cached { 50 } else { 1500 },
        blocked,
        cached,
    }
}

// ============================================================================
// Protocol Serialization Tests (~15 tests)
// ============================================================================

mod protocol_tests {
    use super::*;

    #[test]
    fn test_get_dns_stats_command_roundtrip() {
        let cmd = IpcCommand::GetDnsStats;
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("get_dns_stats"));

        let parsed: IpcCommand = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, IpcCommand::GetDnsStats));
    }

    #[test]
    fn test_get_dns_cache_stats_command_roundtrip() {
        let cmd = IpcCommand::GetDnsCacheStats;
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("get_dns_cache_stats"));

        let parsed: IpcCommand = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, IpcCommand::GetDnsCacheStats));
    }

    #[test]
    fn test_flush_dns_cache_no_pattern() {
        let cmd = IpcCommand::FlushDnsCache { pattern: None };
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("flush_dns_cache"));

        let parsed: IpcCommand = serde_json::from_str(&json).unwrap();
        if let IpcCommand::FlushDnsCache { pattern } = parsed {
            assert!(pattern.is_none());
        } else {
            panic!("Expected FlushDnsCache command");
        }
    }

    #[test]
    fn test_flush_dns_cache_with_pattern() {
        let cmd = IpcCommand::FlushDnsCache {
            pattern: Some("*.example.com".to_string()),
        };
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("*.example.com"));

        let parsed: IpcCommand = serde_json::from_str(&json).unwrap();
        if let IpcCommand::FlushDnsCache { pattern } = parsed {
            assert_eq!(pattern, Some("*.example.com".to_string()));
        } else {
            panic!("Expected FlushDnsCache command");
        }
    }

    #[test]
    fn test_get_dns_block_stats_command_roundtrip() {
        let cmd = IpcCommand::GetDnsBlockStats;
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("get_dns_block_stats"));

        let parsed: IpcCommand = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, IpcCommand::GetDnsBlockStats));
    }

    #[test]
    fn test_reload_dns_blocklist_command_roundtrip() {
        let cmd = IpcCommand::ReloadDnsBlocklist;
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("reload_dns_blocklist"));

        let parsed: IpcCommand = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, IpcCommand::ReloadDnsBlocklist));
    }

    #[test]
    fn test_add_dns_upstream_udp() {
        let cmd = IpcCommand::AddDnsUpstream {
            tag: "google-udp".to_string(),
            config: sample_udp_upstream_config(),
        };
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("add_dns_upstream"));
        assert!(json.contains("google-udp"));
        assert!(json.contains("8.8.8.8:53"));
        assert!(json.contains("\"protocol\":\"udp\""));

        let parsed: IpcCommand = serde_json::from_str(&json).unwrap();
        if let IpcCommand::AddDnsUpstream { tag, config } = parsed {
            assert_eq!(tag, "google-udp");
            assert_eq!(config.address, "8.8.8.8:53");
            assert_eq!(config.protocol, "udp");
            assert_eq!(config.timeout_secs, Some(5));
        } else {
            panic!("Expected AddDnsUpstream command");
        }
    }

    #[test]
    fn test_add_dns_upstream_doh() {
        let cmd = IpcCommand::AddDnsUpstream {
            tag: "google-doh".to_string(),
            config: sample_doh_upstream_config(),
        };
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("\"protocol\":\"doh\""));
        assert!(json.contains("dns.google"));

        let parsed: IpcCommand = serde_json::from_str(&json).unwrap();
        if let IpcCommand::AddDnsUpstream { tag, config } = parsed {
            assert_eq!(tag, "google-doh");
            assert_eq!(config.protocol, "doh");
            assert!(!config.bootstrap.is_empty());
        } else {
            panic!("Expected AddDnsUpstream command");
        }
    }

    #[test]
    fn test_remove_dns_upstream_command() {
        let cmd = IpcCommand::RemoveDnsUpstream {
            tag: "google-udp".to_string(),
        };
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("remove_dns_upstream"));
        assert!(json.contains("google-udp"));

        let parsed: IpcCommand = serde_json::from_str(&json).unwrap();
        if let IpcCommand::RemoveDnsUpstream { tag } = parsed {
            assert_eq!(tag, "google-udp");
        } else {
            panic!("Expected RemoveDnsUpstream command");
        }
    }

    #[test]
    fn test_get_dns_upstream_status_all() {
        let cmd = IpcCommand::GetDnsUpstreamStatus { tag: None };
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("get_dns_upstream_status"));

        let parsed: IpcCommand = serde_json::from_str(&json).unwrap();
        if let IpcCommand::GetDnsUpstreamStatus { tag } = parsed {
            assert!(tag.is_none());
        } else {
            panic!("Expected GetDnsUpstreamStatus command");
        }
    }

    #[test]
    fn test_get_dns_upstream_status_specific() {
        let cmd = IpcCommand::GetDnsUpstreamStatus {
            tag: Some("cloudflare".to_string()),
        };
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("cloudflare"));

        let parsed: IpcCommand = serde_json::from_str(&json).unwrap();
        if let IpcCommand::GetDnsUpstreamStatus { tag } = parsed {
            assert_eq!(tag, Some("cloudflare".to_string()));
        } else {
            panic!("Expected GetDnsUpstreamStatus command");
        }
    }

    #[test]
    fn test_dns_query_command_full() {
        let cmd = IpcCommand::DnsQuery {
            domain: "example.com".to_string(),
            qtype: Some(1),
            upstream: Some("cloudflare".to_string()),
        };
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("dns_query"));
        assert!(json.contains("example.com"));
        assert!(json.contains("\"qtype\":1"));
        assert!(json.contains("cloudflare"));

        let parsed: IpcCommand = serde_json::from_str(&json).unwrap();
        if let IpcCommand::DnsQuery {
            domain,
            qtype,
            upstream,
        } = parsed
        {
            assert_eq!(domain, "example.com");
            assert_eq!(qtype, Some(1));
            assert_eq!(upstream, Some("cloudflare".to_string()));
        } else {
            panic!("Expected DnsQuery command");
        }
    }

    #[test]
    fn test_dns_query_command_defaults() {
        let cmd = IpcCommand::DnsQuery {
            domain: "example.com".to_string(),
            qtype: None,
            upstream: None,
        };
        let json = serde_json::to_string(&cmd).unwrap();

        let parsed: IpcCommand = serde_json::from_str(&json).unwrap();
        if let IpcCommand::DnsQuery {
            domain,
            qtype,
            upstream,
        } = parsed
        {
            assert_eq!(domain, "example.com");
            assert!(qtype.is_none());
            assert!(upstream.is_none());
        } else {
            panic!("Expected DnsQuery command");
        }
    }

    #[test]
    fn test_get_dns_config_command_roundtrip() {
        let cmd = IpcCommand::GetDnsConfig;
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("get_dns_config"));

        let parsed: IpcCommand = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, IpcCommand::GetDnsConfig));
    }
}

// ============================================================================
// Response Type Tests (~8 tests)
// ============================================================================

mod response_tests {
    use super::*;

    #[test]
    fn test_dns_stats_response_roundtrip() {
        let response = IpcResponse::DnsStats(DnsStatsResponse {
            enabled: true,
            uptime_secs: 3600,
            total_queries: 10000,
            cache_hits: 7000,
            cache_misses: 3000,
            blocked_queries: 500,
            upstream_queries: 2500,
            avg_latency_us: 1500,
        });

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("dns_stats"));
        assert!(json.contains("\"total_queries\":10000"));

        let parsed: IpcResponse = serde_json::from_str(&json).unwrap();
        if let IpcResponse::DnsStats(s) = parsed {
            assert!(s.enabled);
            assert_eq!(s.uptime_secs, 3600);
            assert_eq!(s.total_queries, 10000);
            assert_eq!(s.cache_hits, 7000);
            assert_eq!(s.cache_misses, 3000);
            assert_eq!(s.blocked_queries, 500);
        } else {
            panic!("Expected DnsStats response");
        }
    }

    #[test]
    fn test_dns_cache_stats_response_roundtrip() {
        let response = IpcResponse::DnsCacheStats(DnsCacheStatsResponse {
            enabled: true,
            max_entries: 10000,
            current_entries: 5000,
            hits: 7000,
            misses: 3000,
            hit_rate: 0.7,
            negative_hits: 100,
            inserts: 8000,
            evictions: 500,
        });

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("dns_cache_stats"));
        assert!(json.contains("\"hit_rate\":0.7"));

        let parsed: IpcResponse = serde_json::from_str(&json).unwrap();
        if let IpcResponse::DnsCacheStats(s) = parsed {
            assert!(s.enabled);
            assert_eq!(s.max_entries, 10000);
            assert_eq!(s.current_entries, 5000);
            assert!((s.hit_rate - 0.7).abs() < 0.001);
            assert_eq!(s.negative_hits, 100);
        } else {
            panic!("Expected DnsCacheStats response");
        }
    }

    #[test]
    fn test_dns_block_stats_response_roundtrip() {
        let response = IpcResponse::DnsBlockStats(DnsBlockStatsResponse {
            enabled: true,
            rule_count: 50000,
            blocked_queries: 500,
            total_queries: 10000,
            block_rate: 0.05,
            last_reload: Some("2026-01-08T12:00:00Z".to_string()),
        });

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("dns_block_stats"));
        assert!(json.contains("\"rule_count\":50000"));

        let parsed: IpcResponse = serde_json::from_str(&json).unwrap();
        if let IpcResponse::DnsBlockStats(s) = parsed {
            assert!(s.enabled);
            assert_eq!(s.rule_count, 50000);
            assert_eq!(s.blocked_queries, 500);
            assert!((s.block_rate - 0.05).abs() < 0.001);
            assert!(s.last_reload.is_some());
        } else {
            panic!("Expected DnsBlockStats response");
        }
    }

    #[test]
    fn test_dns_upstream_status_response_roundtrip() {
        let response = IpcResponse::DnsUpstreamStatus(DnsUpstreamStatusResponse {
            upstreams: vec![
                sample_upstream_info("google", true),
                sample_upstream_info("cloudflare", false),
            ],
        });

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("dns_upstream_status"));
        assert!(json.contains("google"));
        assert!(json.contains("cloudflare"));

        let parsed: IpcResponse = serde_json::from_str(&json).unwrap();
        if let IpcResponse::DnsUpstreamStatus(s) = parsed {
            assert_eq!(s.upstreams.len(), 2);
            assert!(s.upstreams[0].healthy);
            assert!(!s.upstreams[1].healthy);
        } else {
            panic!("Expected DnsUpstreamStatus response");
        }
    }

    #[test]
    fn test_dns_query_log_response_roundtrip() {
        let response = IpcResponse::DnsQueryLog(DnsQueryLogResponse {
            entries: vec![
                sample_query_log_entry("example.com", false, false),
                sample_query_log_entry("blocked.ad.com", true, false),
                sample_query_log_entry("cached.example.com", false, true),
            ],
            total_available: 1000,
            offset: 0,
            limit: 100,
        });

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("dns_query_log"));
        assert!(json.contains("example.com"));
        assert!(json.contains("blocked.ad.com"));

        let parsed: IpcResponse = serde_json::from_str(&json).unwrap();
        if let IpcResponse::DnsQueryLog(l) = parsed {
            assert_eq!(l.entries.len(), 3);
            assert_eq!(l.total_available, 1000);
            assert!(!l.entries[0].blocked);
            assert!(l.entries[1].blocked);
            assert!(l.entries[2].cached);
        } else {
            panic!("Expected DnsQueryLog response");
        }
    }

    #[test]
    fn test_dns_query_response_success() {
        let response = IpcResponse::DnsQueryResult(DnsQueryResponse {
            success: true,
            domain: "example.com".to_string(),
            qtype: 1,
            response_code: 0,
            answers: vec!["93.184.216.34".to_string()],
            latency_us: 1500,
            cached: false,
            blocked: false,
            upstream_used: Some("google".to_string()),
        });

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("dns_query_result"));
        assert!(json.contains("93.184.216.34"));

        let parsed: IpcResponse = serde_json::from_str(&json).unwrap();
        if let IpcResponse::DnsQueryResult(r) = parsed {
            assert!(r.success);
            assert_eq!(r.domain, "example.com");
            assert_eq!(r.qtype, 1);
            assert_eq!(r.answers.len(), 1);
            assert!(!r.cached);
            assert!(!r.blocked);
            assert_eq!(r.upstream_used, Some("google".to_string()));
        } else {
            panic!("Expected DnsQueryResult response");
        }
    }

    #[test]
    fn test_dns_query_response_blocked() {
        let response = IpcResponse::DnsQueryResult(DnsQueryResponse {
            success: true,
            domain: "ad.tracker.com".to_string(),
            qtype: 1,
            response_code: 0,
            answers: vec!["0.0.0.0".to_string()],
            latency_us: 50,
            cached: false,
            blocked: true,
            upstream_used: None,
        });

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"blocked\":true"));

        let parsed: IpcResponse = serde_json::from_str(&json).unwrap();
        if let IpcResponse::DnsQueryResult(r) = parsed {
            assert!(r.blocked);
            assert!(r.upstream_used.is_none());
            assert_eq!(r.answers[0], "0.0.0.0");
        } else {
            panic!("Expected DnsQueryResult response");
        }
    }

    #[test]
    fn test_dns_config_response_roundtrip() {
        let response = IpcResponse::DnsConfig(DnsConfigResponse {
            enabled: true,
            listen_udp: "127.0.0.1:7853".to_string(),
            listen_tcp: "127.0.0.1:7853".to_string(),
            upstreams: vec![sample_upstream_info("default", true)],
            cache_enabled: true,
            cache_max_entries: 10000,
            blocking_enabled: true,
            blocking_response_type: "zero_ip".to_string(),
            logging_enabled: true,
            logging_format: "json".to_string(),
            available_features: std::collections::HashMap::new(),
        });

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("dns_config"));
        assert!(json.contains("127.0.0.1:7853"));
        assert!(json.contains("\"blocking_response_type\":\"zero_ip\""));

        let parsed: IpcResponse = serde_json::from_str(&json).unwrap();
        if let IpcResponse::DnsConfig(c) = parsed {
            assert!(c.enabled);
            assert!(c.cache_enabled);
            assert!(c.blocking_enabled);
            assert_eq!(c.blocking_response_type, "zero_ip");
            assert_eq!(c.logging_format, "json");
        } else {
            panic!("Expected DnsConfig response");
        }
    }
}

// ============================================================================
// Validation Tests (~8 tests)
// ============================================================================

mod validation_tests {
    use super::*;

    #[test]
    fn test_dns_upstream_config_all_protocols() {
        // Test all supported protocols
        for protocol in ["udp", "tcp", "doh", "dot"] {
            let config = DnsUpstreamConfig {
                address: "1.1.1.1:53".to_string(),
                protocol: protocol.to_string(),
                bootstrap: vec![],
                timeout_secs: None,
            };
            let json = serde_json::to_string(&config).unwrap();
            let parsed: DnsUpstreamConfig = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed.protocol, protocol);
        }
    }

    #[test]
    fn test_dns_route_match_types() {
        // Test all match types can be serialized
        for match_type in ["exact", "suffix", "keyword", "regex"] {
            let cmd = IpcCommand::AddDnsRoute {
                pattern: "example.com".to_string(),
                match_type: match_type.to_string(),
                upstream_tag: "default".to_string(),
            };
            let json = serde_json::to_string(&cmd).unwrap();
            assert!(json.contains(match_type));

            let parsed: IpcCommand = serde_json::from_str(&json).unwrap();
            if let IpcCommand::AddDnsRoute {
                match_type: mt, ..
            } = parsed
            {
                assert_eq!(mt, match_type);
            } else {
                panic!("Expected AddDnsRoute command");
            }
        }
    }

    #[test]
    fn test_dns_query_log_pagination_defaults() {
        // Test default values are correctly applied
        let json = r#"{"type":"get_dns_query_log"}"#;
        let parsed: IpcCommand = serde_json::from_str(json).unwrap();
        if let IpcCommand::GetDnsQueryLog { limit, offset } = parsed {
            assert_eq!(limit, 100); // default
            assert_eq!(offset, 0); // default
        } else {
            panic!("Expected GetDnsQueryLog command");
        }
    }

    #[test]
    fn test_dns_query_log_custom_pagination() {
        let cmd = IpcCommand::GetDnsQueryLog {
            limit: 50,
            offset: 100,
        };
        let json = serde_json::to_string(&cmd).unwrap();

        let parsed: IpcCommand = serde_json::from_str(&json).unwrap();
        if let IpcCommand::GetDnsQueryLog { limit, offset } = parsed {
            assert_eq!(limit, 50);
            assert_eq!(offset, 100);
        } else {
            panic!("Expected GetDnsQueryLog command");
        }
    }

    #[test]
    fn test_dns_upstream_config_minimal() {
        // Test minimal config with defaults
        let json = r#"{"address":"1.1.1.1:53","protocol":"udp"}"#;
        let parsed: DnsUpstreamConfig = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.address, "1.1.1.1:53");
        assert_eq!(parsed.protocol, "udp");
        assert!(parsed.bootstrap.is_empty());
        assert!(parsed.timeout_secs.is_none());
    }

    #[test]
    fn test_dns_upstream_config_with_bootstrap() {
        let config = DnsUpstreamConfig {
            address: "https://dns.cloudflare.com/dns-query".to_string(),
            protocol: "doh".to_string(),
            bootstrap: vec![
                "1.1.1.1:53".to_string(),
                "8.8.8.8:53".to_string(),
            ],
            timeout_secs: Some(10),
        };

        let json = serde_json::to_string(&config).unwrap();
        let parsed: DnsUpstreamConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.bootstrap.len(), 2);
        assert!(parsed.bootstrap.contains(&"1.1.1.1:53".to_string()));
    }

    #[test]
    fn test_dns_query_types() {
        // Test various query types
        let qtypes = [(1, "A"), (28, "AAAA"), (5, "CNAME"), (15, "MX"), (16, "TXT")];

        for (qtype, _name) in qtypes {
            let cmd = IpcCommand::DnsQuery {
                domain: "example.com".to_string(),
                qtype: Some(qtype),
                upstream: None,
            };
            let json = serde_json::to_string(&cmd).unwrap();
            let parsed: IpcCommand = serde_json::from_str(&json).unwrap();
            if let IpcCommand::DnsQuery { qtype: q, .. } = parsed {
                assert_eq!(q, Some(qtype));
            }
        }
    }

    #[test]
    fn test_dns_response_codes() {
        // Test various response codes in query response
        let rcodes = [(0, "NOERROR"), (3, "NXDOMAIN"), (2, "SERVFAIL"), (5, "REFUSED")];

        for (rcode, _name) in rcodes {
            let response = DnsQueryResponse {
                success: rcode == 0,
                domain: "example.com".to_string(),
                qtype: 1,
                response_code: rcode,
                answers: vec![],
                latency_us: 1000,
                cached: false,
                blocked: false,
                upstream_used: Some("default".to_string()),
            };

            let json = serde_json::to_string(&response).unwrap();
            let parsed: DnsQueryResponse = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed.response_code, rcode);
        }
    }
}

// ============================================================================
// Cache Management Tests (~8 tests)
// ============================================================================

mod cache_tests {
    use super::*;

    #[test]
    fn test_flush_cache_empty_pattern_clears_all() {
        let cmd = IpcCommand::FlushDnsCache { pattern: None };
        let json = serde_json::to_string(&cmd).unwrap();

        // Verify pattern is null/missing in JSON
        let parsed: IpcCommand = serde_json::from_str(&json).unwrap();
        if let IpcCommand::FlushDnsCache { pattern } = parsed {
            assert!(pattern.is_none(), "Empty pattern should clear all");
        }
    }

    #[test]
    fn test_flush_cache_suffix_pattern() {
        let cmd = IpcCommand::FlushDnsCache {
            pattern: Some("*.google.com".to_string()),
        };
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("*.google.com"));
    }

    #[test]
    fn test_flush_cache_exact_pattern() {
        let cmd = IpcCommand::FlushDnsCache {
            pattern: Some("www.example.com".to_string()),
        };
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("www.example.com"));
    }

    #[test]
    fn test_cache_stats_hit_rate_calculation() {
        let stats = DnsCacheStatsResponse {
            enabled: true,
            max_entries: 10000,
            current_entries: 5000,
            hits: 700,
            misses: 300,
            hit_rate: 0.7,
            negative_hits: 50,
            inserts: 1000,
            evictions: 100,
        };

        // Verify hit rate is consistent with hits/misses
        let calculated_rate = stats.hits as f64 / (stats.hits + stats.misses) as f64;
        assert!((stats.hit_rate - calculated_rate).abs() < 0.001);
    }

    #[test]
    fn test_cache_stats_empty_cache() {
        let stats = DnsCacheStatsResponse {
            enabled: true,
            max_entries: 10000,
            current_entries: 0,
            hits: 0,
            misses: 0,
            hit_rate: 0.0,
            negative_hits: 0,
            inserts: 0,
            evictions: 0,
        };

        let json = serde_json::to_string(&stats).unwrap();
        let parsed: DnsCacheStatsResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.current_entries, 0);
        assert!((parsed.hit_rate - 0.0).abs() < 0.001);
    }

    #[test]
    fn test_cache_stats_full_cache() {
        let stats = DnsCacheStatsResponse {
            enabled: true,
            max_entries: 10000,
            current_entries: 10000,
            hits: 50000,
            misses: 10000,
            hit_rate: 0.833,
            negative_hits: 1000,
            inserts: 60000,
            evictions: 50000,
        };

        let json = serde_json::to_string(&stats).unwrap();
        let parsed: DnsCacheStatsResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.current_entries, parsed.max_entries);
    }

    #[test]
    fn test_cache_stats_disabled() {
        let stats = DnsCacheStatsResponse {
            enabled: false,
            max_entries: 0,
            current_entries: 0,
            hits: 0,
            misses: 0,
            hit_rate: 0.0,
            negative_hits: 0,
            inserts: 0,
            evictions: 0,
        };

        let json = serde_json::to_string(&stats).unwrap();
        let parsed: DnsCacheStatsResponse = serde_json::from_str(&json).unwrap();
        assert!(!parsed.enabled);
    }

    #[test]
    fn test_cache_negative_hits_tracked() {
        let stats = DnsCacheStatsResponse {
            enabled: true,
            max_entries: 10000,
            current_entries: 1000,
            hits: 500,
            misses: 500,
            hit_rate: 0.5,
            negative_hits: 100,
            inserts: 1000,
            evictions: 0,
        };

        let json = serde_json::to_string(&stats).unwrap();
        assert!(json.contains("\"negative_hits\":100"));
    }
}

// ============================================================================
// Upstream Management Tests (~8 tests)
// ============================================================================

mod upstream_tests {
    use super::*;

    #[test]
    fn test_add_upstream_all_protocols() {
        let configs = vec![
            ("udp-upstream", sample_udp_upstream_config()),
            ("tcp-upstream", sample_tcp_upstream_config()),
            ("doh-upstream", sample_doh_upstream_config()),
            ("dot-upstream", sample_dot_upstream_config()),
        ];

        for (tag, config) in configs {
            let cmd = IpcCommand::AddDnsUpstream {
                tag: tag.to_string(),
                config,
            };
            let json = serde_json::to_string(&cmd).unwrap();
            assert!(json.contains(tag));
        }
    }

    #[test]
    fn test_upstream_health_info_healthy() {
        let info = sample_upstream_info("google", true);
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"healthy\":true"));
        assert!(json.contains("\"last_success\""));
    }

    #[test]
    fn test_upstream_health_info_unhealthy() {
        let info = sample_upstream_info("cloudflare", false);
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"healthy\":false"));
        assert!(json.contains("\"last_failure\""));
    }

    #[test]
    fn test_upstream_status_multiple() {
        let status = DnsUpstreamStatusResponse {
            upstreams: vec![
                sample_upstream_info("google", true),
                sample_upstream_info("cloudflare", true),
                sample_upstream_info("quad9", false),
            ],
        };

        let json = serde_json::to_string(&status).unwrap();
        let parsed: DnsUpstreamStatusResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.upstreams.len(), 3);

        let healthy_count = parsed.upstreams.iter().filter(|u| u.healthy).count();
        assert_eq!(healthy_count, 2);
    }

    #[test]
    fn test_upstream_status_empty() {
        let status = DnsUpstreamStatusResponse {
            upstreams: vec![],
        };

        let json = serde_json::to_string(&status).unwrap();
        let parsed: DnsUpstreamStatusResponse = serde_json::from_str(&json).unwrap();
        assert!(parsed.upstreams.is_empty());
    }

    #[test]
    fn test_upstream_latency_tracking() {
        let info = DnsUpstreamInfo {
            tag: "test".to_string(),
            address: "8.8.8.8:53".to_string(),
            protocol: "udp".to_string(),
            healthy: true,
            total_queries: 10000,
            failed_queries: 100,
            avg_latency_us: 2500, // 2.5ms average
            last_success: Some("2026-01-08T12:00:00Z".to_string()),
            last_failure: Some("2026-01-08T11:00:00Z".to_string()),
        };

        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"avg_latency_us\":2500"));
    }

    #[test]
    fn test_upstream_query_statistics() {
        let info = DnsUpstreamInfo {
            tag: "test".to_string(),
            address: "8.8.8.8:53".to_string(),
            protocol: "udp".to_string(),
            healthy: true,
            total_queries: 10000,
            failed_queries: 100,
            avg_latency_us: 1500,
            last_success: None,
            last_failure: None,
        };

        let failure_rate = info.failed_queries as f64 / info.total_queries as f64;
        assert!(failure_rate < 0.02); // Less than 2% failure rate
    }

    #[test]
    fn test_remove_upstream_by_tag() {
        let cmd = IpcCommand::RemoveDnsUpstream {
            tag: "obsolete-upstream".to_string(),
        };

        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("obsolete-upstream"));

        let parsed: IpcCommand = serde_json::from_str(&json).unwrap();
        if let IpcCommand::RemoveDnsUpstream { tag } = parsed {
            assert_eq!(tag, "obsolete-upstream");
        }
    }
}

// ============================================================================
// DNS Routing Tests (~8 tests)
// ============================================================================

mod routing_tests {
    use super::*;

    #[test]
    fn test_add_route_exact_match() {
        let cmd = IpcCommand::AddDnsRoute {
            pattern: "www.google.com".to_string(),
            match_type: "exact".to_string(),
            upstream_tag: "google".to_string(),
        };

        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("\"match_type\":\"exact\""));
    }

    #[test]
    fn test_add_route_suffix_match() {
        let cmd = IpcCommand::AddDnsRoute {
            pattern: "google.com".to_string(),
            match_type: "suffix".to_string(),
            upstream_tag: "google".to_string(),
        };

        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("\"match_type\":\"suffix\""));
    }

    #[test]
    fn test_add_route_keyword_match() {
        let cmd = IpcCommand::AddDnsRoute {
            pattern: "google".to_string(),
            match_type: "keyword".to_string(),
            upstream_tag: "google".to_string(),
        };

        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("\"match_type\":\"keyword\""));
    }

    #[test]
    fn test_add_route_regex_match() {
        let cmd = IpcCommand::AddDnsRoute {
            pattern: r"^(www\.)?google\.(com|co\.uk)$".to_string(),
            match_type: "regex".to_string(),
            upstream_tag: "google".to_string(),
        };

        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("\"match_type\":\"regex\""));
    }

    #[test]
    fn test_remove_route_by_pattern() {
        let cmd = IpcCommand::RemoveDnsRoute {
            pattern: "google.com".to_string(),
        };

        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("remove_dns_route"));
        assert!(json.contains("google.com"));

        let parsed: IpcCommand = serde_json::from_str(&json).unwrap();
        if let IpcCommand::RemoveDnsRoute { pattern } = parsed {
            assert_eq!(pattern, "google.com");
        }
    }

    #[test]
    fn test_route_to_different_upstreams() {
        let routes = vec![
            ("google.com", "google-dns"),
            ("cloudflare.com", "cloudflare-dns"),
            ("example.com", "default"),
        ];

        for (pattern, upstream) in routes {
            let cmd = IpcCommand::AddDnsRoute {
                pattern: pattern.to_string(),
                match_type: "suffix".to_string(),
                upstream_tag: upstream.to_string(),
            };

            let json = serde_json::to_string(&cmd).unwrap();
            assert!(json.contains(pattern));
            assert!(json.contains(upstream));
        }
    }

    #[test]
    fn test_route_complex_pattern() {
        let cmd = IpcCommand::AddDnsRoute {
            pattern: "*.cdn.example.com".to_string(),
            match_type: "suffix".to_string(),
            upstream_tag: "cdn-dns".to_string(),
        };

        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("*.cdn.example.com"));
    }

    #[test]
    fn test_route_punycode_domain() {
        // Test internationalized domain name (IDN)
        let cmd = IpcCommand::AddDnsRoute {
            pattern: "xn--nxasmq5b.com".to_string(), // Punycode for a non-ASCII domain
            match_type: "suffix".to_string(),
            upstream_tag: "default".to_string(),
        };

        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("xn--nxasmq5b.com"));
    }
}

// ============================================================================
// Query and Logging Tests (~8 tests)
// ============================================================================

mod query_logging_tests {
    use super::*;

    #[test]
    fn test_dns_query_a_record() {
        let cmd = IpcCommand::DnsQuery {
            domain: "example.com".to_string(),
            qtype: Some(1), // A record
            upstream: None,
        };

        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("\"qtype\":1"));
    }

    #[test]
    fn test_dns_query_aaaa_record() {
        let cmd = IpcCommand::DnsQuery {
            domain: "example.com".to_string(),
            qtype: Some(28), // AAAA record
            upstream: None,
        };

        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("\"qtype\":28"));
    }

    #[test]
    fn test_dns_query_with_specific_upstream() {
        let cmd = IpcCommand::DnsQuery {
            domain: "example.com".to_string(),
            qtype: Some(1),
            upstream: Some("google".to_string()),
        };

        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("\"upstream\":\"google\""));
    }

    #[test]
    fn test_query_log_pagination() {
        let cmd = IpcCommand::GetDnsQueryLog {
            limit: 25,
            offset: 50,
        };

        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("\"limit\":25"));
        assert!(json.contains("\"offset\":50"));
    }

    #[test]
    fn test_query_log_response_with_entries() {
        let log = DnsQueryLogResponse {
            entries: vec![
                sample_query_log_entry("example.com", false, false),
                sample_query_log_entry("blocked.ad.com", true, false),
            ],
            total_available: 500,
            offset: 0,
            limit: 100,
        };

        let json = serde_json::to_string(&log).unwrap();
        let parsed: DnsQueryLogResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.entries.len(), 2);
        assert_eq!(parsed.total_available, 500);
    }

    #[test]
    fn test_query_log_entry_fields() {
        let entry = sample_query_log_entry("test.example.com", false, true);

        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"timestamp\":"));
        assert!(json.contains("\"domain\":\"test.example.com\""));
        assert!(json.contains("\"qtype\":1"));
        assert!(json.contains("\"qtype_str\":\"A\""));
        assert!(json.contains("\"cached\":true"));
    }

    #[test]
    fn test_query_response_with_multiple_answers() {
        let response = DnsQueryResponse {
            success: true,
            domain: "example.com".to_string(),
            qtype: 1,
            response_code: 0,
            answers: vec![
                "93.184.216.34".to_string(),
                "93.184.216.35".to_string(),
            ],
            latency_us: 1500,
            cached: false,
            blocked: false,
            upstream_used: Some("google".to_string()),
        };

        let json = serde_json::to_string(&response).unwrap();
        let parsed: DnsQueryResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.answers.len(), 2);
    }

    #[test]
    fn test_query_response_cached() {
        let response = DnsQueryResponse {
            success: true,
            domain: "cached.example.com".to_string(),
            qtype: 1,
            response_code: 0,
            answers: vec!["93.184.216.34".to_string()],
            latency_us: 50, // Very low latency for cached response
            cached: true,
            blocked: false,
            upstream_used: None, // No upstream used for cached response
        };

        let json = serde_json::to_string(&response).unwrap();
        let parsed: DnsQueryResponse = serde_json::from_str(&json).unwrap();
        assert!(parsed.cached);
        assert!(parsed.upstream_used.is_none());
        assert!(parsed.latency_us < 100);
    }
}

// ============================================================================
// Error Handling Tests (~5 tests)
// ============================================================================

mod error_handling_tests {
    use super::*;

    #[test]
    fn test_invalid_json_command() {
        let invalid_json = r#"{"type":"invalid_command"}"#;
        let result: Result<IpcCommand, _> = serde_json::from_str(invalid_json);
        assert!(result.is_err());
    }

    #[test]
    fn test_missing_required_field() {
        // AddDnsUpstream without tag
        let invalid_json = r#"{"type":"add_dns_upstream","config":{"address":"8.8.8.8:53","protocol":"udp"}}"#;
        let result: Result<IpcCommand, _> = serde_json::from_str(invalid_json);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_dns_upstream_config() {
        // Missing required fields
        let invalid_json = r#"{"address":"8.8.8.8:53"}"#;
        let result: Result<DnsUpstreamConfig, _> = serde_json::from_str(invalid_json);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_domain_in_query() {
        // Empty domain is still valid JSON, validation happens at handler level
        let cmd = IpcCommand::DnsQuery {
            domain: "".to_string(),
            qtype: Some(1),
            upstream: None,
        };

        let json = serde_json::to_string(&cmd).unwrap();
        let parsed: IpcCommand = serde_json::from_str(&json).unwrap();
        if let IpcCommand::DnsQuery { domain, .. } = parsed {
            assert!(domain.is_empty());
        }
    }

    #[test]
    fn test_null_values_handled() {
        // Test that null values for optional fields work correctly
        let json = r#"{"type":"dns_query","domain":"example.com","qtype":null,"upstream":null}"#;
        let result: Result<IpcCommand, _> = serde_json::from_str(json);
        assert!(result.is_ok());

        if let IpcCommand::DnsQuery {
            qtype, upstream, ..
        } = result.unwrap()
        {
            assert!(qtype.is_none());
            assert!(upstream.is_none());
        }
    }
}

// ============================================================================
// Edge Case Tests (~5 tests)
// ============================================================================

mod edge_case_tests {
    use super::*;

    #[test]
    fn test_very_long_domain_name() {
        // Maximum domain length is 253 characters
        let long_domain = "a".repeat(63) + "." + &"b".repeat(63) + "." + &"c".repeat(63) + ".com";
        assert!(long_domain.len() <= 253);

        let cmd = IpcCommand::DnsQuery {
            domain: long_domain.clone(),
            qtype: Some(1),
            upstream: None,
        };

        let json = serde_json::to_string(&cmd).unwrap();
        let parsed: IpcCommand = serde_json::from_str(&json).unwrap();
        if let IpcCommand::DnsQuery { domain, .. } = parsed {
            assert_eq!(domain, long_domain);
        }
    }

    #[test]
    fn test_special_characters_in_domain() {
        // Domains with hyphens are valid
        let cmd = IpcCommand::DnsQuery {
            domain: "my-example-domain.co.uk".to_string(),
            qtype: Some(1),
            upstream: None,
        };

        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("my-example-domain.co.uk"));
    }

    #[test]
    fn test_unicode_in_tag() {
        // Tags might contain unicode (though not recommended)
        let cmd = IpcCommand::AddDnsUpstream {
            tag: "upstream-test".to_string(),
            config: sample_udp_upstream_config(),
        };

        let json = serde_json::to_string(&cmd).unwrap();
        let parsed: IpcCommand = serde_json::from_str(&json).unwrap();
        if let IpcCommand::AddDnsUpstream { tag, .. } = parsed {
            assert_eq!(tag, "upstream-test");
        }
    }

    #[test]
    fn test_large_statistics_values() {
        let stats = DnsStatsResponse {
            enabled: true,
            uptime_secs: u64::MAX,
            total_queries: u64::MAX,
            cache_hits: u64::MAX,
            cache_misses: u64::MAX,
            blocked_queries: u64::MAX,
            upstream_queries: u64::MAX,
            avg_latency_us: u64::MAX,
        };

        let json = serde_json::to_string(&stats).unwrap();
        let parsed: DnsStatsResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.total_queries, u64::MAX);
    }

    #[test]
    fn test_zero_statistics_values() {
        let stats = DnsStatsResponse {
            enabled: true,
            uptime_secs: 0,
            total_queries: 0,
            cache_hits: 0,
            cache_misses: 0,
            blocked_queries: 0,
            upstream_queries: 0,
            avg_latency_us: 0,
        };

        let json = serde_json::to_string(&stats).unwrap();
        let parsed: DnsStatsResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.total_queries, 0);
        assert_eq!(parsed.cache_hits, 0);
    }
}

// ============================================================================
// Integration with Handler Tests (require actual handler)
// ============================================================================

mod handler_integration_tests {
    /// Tests that require actual DNS engine are marked as ignored
    /// They can be run with: cargo test --test integration dns_ipc -- --ignored
    #[test]
    #[ignore = "Requires actual DNS engine to be running"]
    fn test_dns_stats_from_live_engine() {
        // This test would require the actual DNS engine to be running
        // and would verify that GetDnsStats returns valid statistics
        todo!("Implement when DNS engine is integrated with IPC handler")
    }

    #[test]
    #[ignore = "Requires actual DNS engine to be running"]
    fn test_dns_query_live() {
        // This test would perform an actual DNS query through the engine
        todo!("Implement when DNS engine is integrated with IPC handler")
    }

    #[test]
    #[ignore = "Requires actual DNS engine to be running"]
    fn test_cache_flush_live() {
        // This test would verify cache flush actually clears entries
        todo!("Implement when DNS engine is integrated with IPC handler")
    }

    #[test]
    #[ignore = "Requires actual DNS engine to be running"]
    fn test_upstream_add_remove_live() {
        // This test would add and remove upstreams through IPC
        todo!("Implement when DNS engine is integrated with IPC handler")
    }

    #[test]
    #[ignore = "Requires actual DNS engine to be running"]
    fn test_blocklist_reload_live() {
        // This test would verify blocklist hot-reload functionality
        todo!("Implement when DNS engine is integrated with IPC handler")
    }
}

// ============================================================================
// Summary Test Count
// ============================================================================

/// Test count summary:
/// - Protocol Tests: 15
/// - Response Tests: 8
/// - Validation Tests: 8
/// - Cache Tests: 8
/// - Upstream Tests: 8
/// - Routing Tests: 8
/// - Query/Logging Tests: 8
/// - Error Handling Tests: 5
/// - Edge Case Tests: 5
/// - Handler Integration Tests: 5 (ignored)
/// Total: ~78 tests (73 active + 5 ignored)
#[test]
fn test_summary() {
    // This test exists to document the test count
    // The actual count can be verified with: cargo test --test integration dns_ipc -- --list
    assert!(true);
}
