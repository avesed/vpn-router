//! Sniff result types
//!
//! This module defines the types used to represent protocol sniffing results.

use serde::{Deserialize, Serialize};

/// Result of protocol sniffing
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SniffResult {
    /// Detected protocol
    pub protocol: Protocol,
    /// Server Name Indication (for TLS)
    pub sni: Option<String>,
    /// HTTP Host header (for plain HTTP)
    pub http_host: Option<String>,
}

impl SniffResult {
    /// Create a new TLS sniff result with SNI
    pub fn tls(sni: impl Into<String>) -> Self {
        Self {
            protocol: Protocol::Tls,
            sni: Some(sni.into()),
            http_host: None,
        }
    }

    /// Create a TLS result without SNI
    pub fn tls_no_sni() -> Self {
        Self {
            protocol: Protocol::Tls,
            sni: None,
            http_host: None,
        }
    }

    /// Create an HTTP sniff result with Host header
    pub fn http(host: impl Into<String>) -> Self {
        Self {
            protocol: Protocol::Http,
            sni: None,
            http_host: Some(host.into()),
        }
    }

    /// Create a QUIC sniff result with SNI
    pub fn quic(sni: impl Into<String>) -> Self {
        Self {
            protocol: Protocol::Quic,
            sni: Some(sni.into()),
            http_host: None,
        }
    }

    /// Create an unknown protocol result
    pub fn unknown() -> Self {
        Self {
            protocol: Protocol::Unknown,
            sni: None,
            http_host: None,
        }
    }

    /// Get the domain name (SNI or HTTP Host)
    #[must_use]
    pub fn domain(&self) -> Option<&str> {
        self.sni
            .as_deref()
            .or(self.http_host.as_deref())
    }

    /// Check if a domain was detected
    #[must_use]
    pub fn has_domain(&self) -> bool {
        self.sni.is_some() || self.http_host.is_some()
    }
}

/// Detected protocol type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    /// TLS (HTTPS, etc.)
    Tls,
    /// Plain HTTP
    Http,
    /// QUIC (HTTP/3)
    Quic,
    /// Unknown protocol
    Unknown,
}

impl Protocol {
    /// Check if this is an encrypted protocol
    #[must_use]
    pub const fn is_encrypted(&self) -> bool {
        matches!(self, Self::Tls | Self::Quic)
    }

    /// Get protocol name as string
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Tls => "tls",
            Self::Http => "http",
            Self::Quic => "quic",
            Self::Unknown => "unknown",
        }
    }
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sniff_result_tls() {
        let result = SniffResult::tls("example.com");
        assert_eq!(result.protocol, Protocol::Tls);
        assert_eq!(result.sni, Some("example.com".into()));
        assert_eq!(result.domain(), Some("example.com"));
        assert!(result.has_domain());
    }

    #[test]
    fn test_sniff_result_tls_no_sni() {
        let result = SniffResult::tls_no_sni();
        assert_eq!(result.protocol, Protocol::Tls);
        assert!(result.sni.is_none());
        assert!(!result.has_domain());
    }

    #[test]
    fn test_sniff_result_http() {
        let result = SniffResult::http("example.com");
        assert_eq!(result.protocol, Protocol::Http);
        assert_eq!(result.http_host, Some("example.com".into()));
        assert_eq!(result.domain(), Some("example.com"));
    }

    #[test]
    fn test_sniff_result_unknown() {
        let result = SniffResult::unknown();
        assert_eq!(result.protocol, Protocol::Unknown);
        assert!(!result.has_domain());
    }

    #[test]
    fn test_protocol_display() {
        assert_eq!(Protocol::Tls.to_string(), "tls");
        assert_eq!(Protocol::Http.to_string(), "http");
        assert_eq!(Protocol::Quic.to_string(), "quic");
        assert_eq!(Protocol::Unknown.to_string(), "unknown");
    }

    #[test]
    fn test_protocol_encrypted() {
        assert!(Protocol::Tls.is_encrypted());
        assert!(Protocol::Quic.is_encrypted());
        assert!(!Protocol::Http.is_encrypted());
        assert!(!Protocol::Unknown.is_encrypted());
    }

    #[test]
    fn test_serialization() {
        let result = SniffResult::tls("test.com");
        let json = serde_json::to_string(&result).unwrap();
        let parsed: SniffResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, parsed);
    }
}
