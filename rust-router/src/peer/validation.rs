//! Input validation module for peer operations
//!
//! This module provides validation utilities for peer-related operations,
//! including tag validation, `WireGuard` key validation, endpoint parsing,
//! and DSCP value validation.
//!
//! # Validation Rules
//!
//! - **Tags**: Alphanumeric with hyphens and underscores, 1-64 characters
//! - **`WireGuard` Keys**: Base64 encoded, 44 characters (32 bytes)
//! - **Endpoints**: IP:port or hostname:port format
//! - **DSCP Values**: 1-63 (0 and 64+ are reserved)
//!
//! # Examples
//!
//! ```
//! use rust_router::peer::validation::{validate_peer_tag, validate_wg_key, validate_dscp_value};
//!
//! // Validate a peer tag
//! assert!(validate_peer_tag("my-peer-1").is_ok());
//! assert!(validate_peer_tag("").is_err());
//!
//! // Validate a DSCP value
//! assert!(validate_dscp_value(10).is_ok());
//! assert!(validate_dscp_value(0).is_err());  // 0 is reserved
//! assert!(validate_dscp_value(64).is_err()); // Must be 1-63
//! ```

use std::net::{IpAddr, SocketAddr};
use thiserror::Error;

/// `WireGuard` key length in bytes (before Base64 encoding)
pub const WG_KEY_LENGTH: usize = 32;

/// `WireGuard` key Base64 length (32 bytes = 44 chars in Base64 with padding)
pub const WG_KEY_BASE64_LENGTH: usize = 44;

/// Maximum tag length
pub const MAX_TAG_LENGTH: usize = 64;

/// Minimum tag length
pub const MIN_TAG_LENGTH: usize = 1;

/// Maximum description length
pub const MAX_DESCRIPTION_LENGTH: usize = 256;

/// Minimum DSCP value (1-63 valid range)
pub const MIN_DSCP_VALUE: u8 = 1;

/// Maximum DSCP value (1-63 valid range)
pub const MAX_DSCP_VALUE: u8 = 63;

/// Minimum peer tunnel port
pub const MIN_PEER_PORT: u16 = 36200;

/// Maximum peer tunnel port
pub const MAX_PEER_PORT: u16 = 36299;

/// Regex pattern for valid tags (alphanumeric, hyphens, underscores)
pub const TAG_PATTERN: &str = r"^[a-zA-Z0-9][a-zA-Z0-9_-]*$";

/// Regex pattern for `WireGuard` Base64 keys
pub const WG_KEY_PATTERN: &str = r"^[A-Za-z0-9+/]{43}=$";

/// Validation error types
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum ValidationError {
    /// Tag is empty
    #[error("Tag cannot be empty")]
    EmptyTag,

    /// Tag is too long
    #[error("Tag exceeds maximum length of {MAX_TAG_LENGTH} characters: {length}")]
    TagTooLong { length: usize },

    /// Tag contains invalid characters
    #[error("Tag contains invalid characters: must match pattern {TAG_PATTERN}")]
    InvalidTagCharacters,

    /// Tag must start with alphanumeric
    #[error("Tag must start with an alphanumeric character")]
    InvalidTagStart,

    /// `WireGuard` key has invalid length
    #[error("WireGuard key has invalid length: expected {WG_KEY_BASE64_LENGTH}, got {length}")]
    InvalidKeyLength { length: usize },

    /// `WireGuard` key has invalid Base64 encoding
    #[error("WireGuard key has invalid Base64 encoding")]
    InvalidKeyEncoding,

    /// Endpoint is invalid
    #[error("Invalid endpoint format: {message}")]
    InvalidEndpoint { message: String },

    /// DSCP value is out of valid range
    #[error("DSCP value must be between {MIN_DSCP_VALUE} and {MAX_DSCP_VALUE}: got {value}")]
    InvalidDscpValue { value: u8 },

    /// Description is too long
    #[error("Description exceeds maximum length of {MAX_DESCRIPTION_LENGTH} characters")]
    DescriptionTooLong,

    /// Tunnel IP is invalid
    #[error("Invalid tunnel IP address: {message}")]
    InvalidTunnelIp { message: String },

    /// Port is out of valid range
    #[error("Peer tunnel port must be between {MIN_PEER_PORT} and {MAX_PEER_PORT}: got {port}")]
    InvalidPeerPort { port: u16 },

    /// Chain has too few hops
    #[error("Chain must have at least 2 hops (entry and terminal)")]
    ChainTooShort,

    /// Chain has too many hops
    #[error("Chain cannot have more than 10 hops")]
    ChainTooLong,

    /// Missing required field
    #[error("Missing required field: {field}")]
    MissingField { field: String },
}

/// Validate a peer or chain tag
///
/// Tags must:
/// - Be 1-64 characters long
/// - Start with an alphanumeric character
/// - Contain only alphanumeric characters, hyphens, and underscores
///
/// # Examples
///
/// ```
/// use rust_router::peer::validation::validate_peer_tag;
///
/// assert!(validate_peer_tag("peer-node-1").is_ok());
/// assert!(validate_peer_tag("node_a").is_ok());
/// assert!(validate_peer_tag("").is_err());
/// assert!(validate_peer_tag("-invalid").is_err());
/// ```
pub fn validate_peer_tag(tag: &str) -> Result<(), ValidationError> {
    // Check empty
    if tag.is_empty() {
        return Err(ValidationError::EmptyTag);
    }

    // Check length
    if tag.len() > MAX_TAG_LENGTH {
        return Err(ValidationError::TagTooLong { length: tag.len() });
    }

    // Check first character is alphanumeric
    let first_char = tag.chars().next().unwrap();
    if !first_char.is_ascii_alphanumeric() {
        return Err(ValidationError::InvalidTagStart);
    }

    // Check all characters are valid
    for c in tag.chars() {
        if !c.is_ascii_alphanumeric() && c != '-' && c != '_' {
            return Err(ValidationError::InvalidTagCharacters);
        }
    }

    Ok(())
}

/// Validate a chain tag (alias for `validate_peer_tag`)
pub fn validate_chain_tag(tag: &str) -> Result<(), ValidationError> {
    validate_peer_tag(tag)
}

/// Validate a `WireGuard` public or private key
///
/// `WireGuard` keys are 32 bytes encoded as Base64, resulting in 44 characters.
///
/// # Examples
///
/// ```
/// use rust_router::peer::validation::validate_wg_key;
///
/// // Valid Base64-encoded 32-byte key (44 chars, decodes to exactly 32 bytes)
/// assert!(validate_wg_key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").is_ok());
///
/// // Invalid length
/// assert!(validate_wg_key("short").is_err());
/// ```
pub fn validate_wg_key(key: &str) -> Result<(), ValidationError> {
    // Check length
    if key.len() != WG_KEY_BASE64_LENGTH {
        return Err(ValidationError::InvalidKeyLength { length: key.len() });
    }

    // Check Base64 encoding
    // WireGuard keys are exactly 32 bytes, which encodes to 44 Base64 characters
    // The pattern is: 43 Base64 chars + '=' padding
    let bytes = key.as_bytes();

    // Check last char is '='
    if bytes[43] != b'=' {
        return Err(ValidationError::InvalidKeyEncoding);
    }

    // Check first 43 chars are valid Base64
    for &byte in &bytes[..43] {
        let is_valid = byte.is_ascii_alphanumeric() || byte == b'+' || byte == b'/';
        if !is_valid {
            return Err(ValidationError::InvalidKeyEncoding);
        }
    }

    // Optionally verify actual Base64 decoding
    let decoded = base64_decode(key);
    if decoded.is_none() || decoded.as_ref().is_none_or(|v| v.len() != WG_KEY_LENGTH) {
        return Err(ValidationError::InvalidKeyEncoding);
    }

    Ok(())
}

/// Simple Base64 decoding for validation
fn base64_decode(input: &str) -> Option<Vec<u8>> {
    const BASE64_CHARS: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    fn char_to_value(c: u8) -> Option<u8> {
        BASE64_CHARS.iter().position(|&x| x == c).map(|p| p as u8)
    }

    let bytes = input.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return None;
    }

    let mut result = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut i = 0;

    while i < bytes.len() {
        let chunk = &bytes[i..i + 4];

        let a = if chunk[0] == b'=' {
            0
        } else {
            char_to_value(chunk[0])?
        };
        let b = if chunk[1] == b'=' {
            0
        } else {
            char_to_value(chunk[1])?
        };
        let c = if chunk[2] == b'=' {
            0
        } else {
            char_to_value(chunk[2])?
        };
        let d = if chunk[3] == b'=' {
            0
        } else {
            char_to_value(chunk[3])?
        };

        result.push((a << 2) | (b >> 4));
        if chunk[2] != b'=' {
            result.push((b << 4) | (c >> 2));
        }
        if chunk[3] != b'=' {
            result.push((c << 6) | d);
        }

        i += 4;
    }

    Some(result)
}

/// Validate an endpoint (IP:port or hostname:port)
///
/// Endpoints must be in the format `host:port` where:
/// - `host` is an IPv4 address, IPv6 address (in brackets), or hostname
/// - `port` is a valid port number (1-65535)
///
/// # Examples
///
/// ```
/// use rust_router::peer::validation::validate_endpoint;
///
/// assert!(validate_endpoint("192.168.1.1:36200").is_ok());
/// assert!(validate_endpoint("[::1]:36200").is_ok());
/// assert!(validate_endpoint("peer.example.com:36200").is_ok());
/// assert!(validate_endpoint("invalid").is_err());
/// ```
pub fn validate_endpoint(endpoint: &str) -> Result<(), ValidationError> {
    // Try to parse as SocketAddr first
    if let Ok(addr) = endpoint.parse::<SocketAddr>() {
        // Port 0 is invalid
        if addr.port() == 0 {
            return Err(ValidationError::InvalidEndpoint {
                message: "Port cannot be 0".into(),
            });
        }
        return Ok(());
    }

    // Try to parse as [IPv6]:port
    if endpoint.starts_with('[') {
        let close_bracket = endpoint
            .find(']')
            .ok_or_else(|| ValidationError::InvalidEndpoint {
                message: "Missing closing bracket for IPv6 address".into(),
            })?;

        let ip_part = &endpoint[1..close_bracket];
        let port_part = &endpoint[close_bracket + 1..];

        // Validate IPv6
        if ip_part.parse::<std::net::Ipv6Addr>().is_err() {
            return Err(ValidationError::InvalidEndpoint {
                message: format!("Invalid IPv6 address: {ip_part}"),
            });
        }

        // Validate port
        if !port_part.starts_with(':') {
            return Err(ValidationError::InvalidEndpoint {
                message: "Missing port separator after IPv6 address".into(),
            });
        }

        let port: u16 = port_part[1..].parse().map_err(|_| ValidationError::InvalidEndpoint {
            message: format!("Invalid port number: {}", &port_part[1..]),
        })?;

        if port == 0 {
            return Err(ValidationError::InvalidEndpoint {
                message: "Port cannot be 0".into(),
            });
        }

        return Ok(());
    }

    // Try to parse as hostname:port or IPv4:port
    let colon_pos = endpoint.rfind(':').ok_or_else(|| ValidationError::InvalidEndpoint {
        message: "Missing port separator".into(),
    })?;

    let host = &endpoint[..colon_pos];
    let port_str = &endpoint[colon_pos + 1..];

    // Validate port
    let port: u16 = port_str.parse().map_err(|_| ValidationError::InvalidEndpoint {
        message: format!("Invalid port number: {port_str}"),
    })?;

    if port == 0 {
        return Err(ValidationError::InvalidEndpoint {
            message: "Port cannot be 0".into(),
        });
    }

    // Validate host (IPv4 or hostname)
    if host.is_empty() {
        return Err(ValidationError::InvalidEndpoint {
            message: "Host cannot be empty".into(),
        });
    }

    // If it's not a valid IPv4, check if it's a valid hostname
    if host.parse::<std::net::Ipv4Addr>().is_err() {
        // Basic hostname validation
        for label in host.split('.') {
            if label.is_empty() || label.len() > 63 {
                return Err(ValidationError::InvalidEndpoint {
                    message: format!("Invalid hostname label: {label}"),
                });
            }
            if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
                return Err(ValidationError::InvalidEndpoint {
                    message: format!("Invalid hostname characters in: {label}"),
                });
            }
        }
    }

    Ok(())
}

/// Validate a DSCP value
///
/// Valid DSCP values are 1-63. Value 0 is reserved (no DSCP marking),
/// and values 64+ exceed the 6-bit DSCP field.
///
/// # Examples
///
/// ```
/// use rust_router::peer::validation::validate_dscp_value;
///
/// assert!(validate_dscp_value(10).is_ok());
/// assert!(validate_dscp_value(1).is_ok());
/// assert!(validate_dscp_value(63).is_ok());
/// assert!(validate_dscp_value(0).is_err());
/// assert!(validate_dscp_value(64).is_err());
/// ```
pub fn validate_dscp_value(value: u8) -> Result<(), ValidationError> {
    if !(MIN_DSCP_VALUE..=MAX_DSCP_VALUE).contains(&value) {
        return Err(ValidationError::InvalidDscpValue { value });
    }
    Ok(())
}

/// Validate a tunnel IP address
///
/// Tunnel IPs must be valid IPv4 addresses in a private range.
///
/// # Examples
///
/// ```
/// use rust_router::peer::validation::validate_tunnel_ip;
///
/// assert!(validate_tunnel_ip("10.200.200.1").is_ok());
/// assert!(validate_tunnel_ip("192.168.1.1").is_ok());
/// assert!(validate_tunnel_ip("invalid").is_err());
/// ```
pub fn validate_tunnel_ip(ip: &str) -> Result<(), ValidationError> {
    // Strip CIDR notation if present
    let ip_part = ip.split('/').next().unwrap_or(ip);

    ip_part.parse::<IpAddr>().map_err(|e| ValidationError::InvalidTunnelIp {
        message: e.to_string(),
    })?;

    Ok(())
}

/// Validate a peer tunnel port
///
/// Peer tunnel ports must be in the range 36200-36299.
///
/// # Examples
///
/// ```
/// use rust_router::peer::validation::validate_peer_port;
///
/// assert!(validate_peer_port(36200).is_ok());
/// assert!(validate_peer_port(36299).is_ok());
/// assert!(validate_peer_port(36100).is_err());
/// assert!(validate_peer_port(36300).is_err());
/// ```
pub fn validate_peer_port(port: u16) -> Result<(), ValidationError> {
    if !(MIN_PEER_PORT..=MAX_PEER_PORT).contains(&port) {
        return Err(ValidationError::InvalidPeerPort { port });
    }
    Ok(())
}

/// Validate a description string
///
/// Descriptions must be at most 256 characters.
pub fn validate_description(description: &str) -> Result<(), ValidationError> {
    if description.len() > MAX_DESCRIPTION_LENGTH {
        return Err(ValidationError::DescriptionTooLong);
    }
    Ok(())
}

/// Validate chain hop count
///
/// Chains must have 2-10 hops.
pub fn validate_chain_hops_count(count: usize) -> Result<(), ValidationError> {
    if count < 2 {
        return Err(ValidationError::ChainTooShort);
    }
    if count > 10 {
        return Err(ValidationError::ChainTooLong);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // Tag validation tests
    // =========================================================================

    #[test]
    fn test_valid_tags() {
        assert!(validate_peer_tag("peer-1").is_ok());
        assert!(validate_peer_tag("node_a").is_ok());
        assert!(validate_peer_tag("MyPeer123").is_ok());
        assert!(validate_peer_tag("a").is_ok());
        assert!(validate_peer_tag("1").is_ok());
        assert!(validate_peer_tag("peer-node-123_test").is_ok());
    }

    #[test]
    fn test_empty_tag() {
        assert_eq!(validate_peer_tag(""), Err(ValidationError::EmptyTag));
    }

    #[test]
    fn test_tag_too_long() {
        let long_tag = "a".repeat(65);
        assert!(matches!(
            validate_peer_tag(&long_tag),
            Err(ValidationError::TagTooLong { length: 65 })
        ));
    }

    #[test]
    fn test_invalid_tag_start() {
        assert_eq!(validate_peer_tag("-peer"), Err(ValidationError::InvalidTagStart));
        assert_eq!(validate_peer_tag("_peer"), Err(ValidationError::InvalidTagStart));
    }

    #[test]
    fn test_invalid_tag_characters() {
        assert_eq!(
            validate_peer_tag("peer.node"),
            Err(ValidationError::InvalidTagCharacters)
        );
        assert_eq!(
            validate_peer_tag("peer node"),
            Err(ValidationError::InvalidTagCharacters)
        );
        assert_eq!(
            validate_peer_tag("peer@node"),
            Err(ValidationError::InvalidTagCharacters)
        );
    }

    // =========================================================================
    // WireGuard key validation tests
    // =========================================================================

    #[test]
    fn test_valid_wg_key() {
        // Valid 32-byte key in Base64 (exactly 44 chars with padding)
        // This is a real WireGuard key format: 32 bytes -> 44 Base64 chars (43 + '=')
        let valid_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        assert!(validate_wg_key(valid_key).is_ok());
    }

    #[test]
    fn test_wg_key_wrong_length() {
        assert!(matches!(
            validate_wg_key("short"),
            Err(ValidationError::InvalidKeyLength { length: 5 })
        ));
        assert!(matches!(
            validate_wg_key(""),
            Err(ValidationError::InvalidKeyLength { length: 0 })
        ));
    }

    #[test]
    fn test_wg_key_invalid_encoding() {
        // 44 chars but not valid Base64
        let invalid = "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!";
        assert!(matches!(
            validate_wg_key(invalid),
            Err(ValidationError::InvalidKeyEncoding)
        ));
    }

    // =========================================================================
    // Endpoint validation tests
    // =========================================================================

    #[test]
    fn test_valid_endpoints() {
        assert!(validate_endpoint("192.168.1.1:36200").is_ok());
        assert!(validate_endpoint("10.0.0.1:51820").is_ok());
        assert!(validate_endpoint("[::1]:36200").is_ok());
        assert!(validate_endpoint("[2001:db8::1]:443").is_ok());
        assert!(validate_endpoint("peer.example.com:36200").is_ok());
        assert!(validate_endpoint("localhost:8080").is_ok());
    }

    #[test]
    fn test_invalid_endpoints() {
        assert!(validate_endpoint("").is_err());
        assert!(validate_endpoint("192.168.1.1").is_err()); // No port
        assert!(validate_endpoint(":36200").is_err()); // No host
        assert!(validate_endpoint("192.168.1.1:0").is_err()); // Port 0
        assert!(validate_endpoint("192.168.1.1:99999").is_err()); // Port too large
        assert!(validate_endpoint("[::1:36200").is_err()); // Missing closing bracket
    }

    // =========================================================================
    // DSCP value validation tests
    // =========================================================================

    #[test]
    fn test_valid_dscp_values() {
        assert!(validate_dscp_value(1).is_ok());
        assert!(validate_dscp_value(10).is_ok());
        assert!(validate_dscp_value(32).is_ok());
        assert!(validate_dscp_value(63).is_ok());
    }

    #[test]
    fn test_invalid_dscp_values() {
        assert!(matches!(
            validate_dscp_value(0),
            Err(ValidationError::InvalidDscpValue { value: 0 })
        ));
        assert!(matches!(
            validate_dscp_value(64),
            Err(ValidationError::InvalidDscpValue { value: 64 })
        ));
        assert!(matches!(
            validate_dscp_value(255),
            Err(ValidationError::InvalidDscpValue { value: 255 })
        ));
    }

    // =========================================================================
    // Tunnel IP validation tests
    // =========================================================================

    #[test]
    fn test_valid_tunnel_ips() {
        assert!(validate_tunnel_ip("10.200.200.1").is_ok());
        assert!(validate_tunnel_ip("192.168.1.1").is_ok());
        assert!(validate_tunnel_ip("10.200.200.1/32").is_ok()); // With CIDR
        assert!(validate_tunnel_ip("::1").is_ok()); // IPv6
    }

    #[test]
    fn test_invalid_tunnel_ips() {
        assert!(validate_tunnel_ip("invalid").is_err());
        assert!(validate_tunnel_ip("256.1.1.1").is_err());
        assert!(validate_tunnel_ip("").is_err());
    }

    // =========================================================================
    // Peer port validation tests
    // =========================================================================

    #[test]
    fn test_valid_peer_ports() {
        assert!(validate_peer_port(36200).is_ok());
        assert!(validate_peer_port(36250).is_ok());
        assert!(validate_peer_port(36299).is_ok());
    }

    #[test]
    fn test_invalid_peer_ports() {
        assert!(matches!(
            validate_peer_port(36100),
            Err(ValidationError::InvalidPeerPort { port: 36100 })
        ));
        assert!(matches!(
            validate_peer_port(36300),
            Err(ValidationError::InvalidPeerPort { port: 36300 })
        ));
        assert!(matches!(
            validate_peer_port(0),
            Err(ValidationError::InvalidPeerPort { port: 0 })
        ));
    }

    // =========================================================================
    // Chain hops validation tests
    // =========================================================================

    #[test]
    fn test_valid_chain_hops() {
        assert!(validate_chain_hops_count(2).is_ok());
        assert!(validate_chain_hops_count(5).is_ok());
        assert!(validate_chain_hops_count(10).is_ok());
    }

    #[test]
    fn test_invalid_chain_hops() {
        assert!(matches!(
            validate_chain_hops_count(0),
            Err(ValidationError::ChainTooShort)
        ));
        assert!(matches!(
            validate_chain_hops_count(1),
            Err(ValidationError::ChainTooShort)
        ));
        assert!(matches!(
            validate_chain_hops_count(11),
            Err(ValidationError::ChainTooLong)
        ));
    }

    // =========================================================================
    // Description validation tests
    // =========================================================================

    #[test]
    fn test_valid_descriptions() {
        assert!(validate_description("").is_ok());
        assert!(validate_description("My peer node").is_ok());
        assert!(validate_description(&"a".repeat(256)).is_ok());
    }

    #[test]
    fn test_invalid_descriptions() {
        assert!(matches!(
            validate_description(&"a".repeat(257)),
            Err(ValidationError::DescriptionTooLong)
        ));
    }

    // =========================================================================
    // Base64 decode tests
    // =========================================================================

    #[test]
    fn test_base64_decode() {
        // "hello" = "aGVsbG8="
        let result = base64_decode("aGVsbG8=");
        assert_eq!(result, Some(b"hello".to_vec()));

        // Empty
        let result = base64_decode("");
        assert_eq!(result, Some(vec![]));

        // Invalid (wrong length)
        let result = base64_decode("abc");
        assert_eq!(result, None);
    }

    #[test]
    fn test_wg_key_decoded_length() {
        // Valid key decodes to exactly 32 bytes
        let valid_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let decoded = base64_decode(valid_key).unwrap();
        assert_eq!(decoded.len(), WG_KEY_LENGTH);
        assert_eq!(decoded.len(), 32);
    }

    #[test]
    fn test_wg_key_with_plus_and_slash() {
        // Key with + and / characters (valid Base64)
        // Exactly 44 characters (43 base64 chars + '='), decodes to 32 bytes
        // Based on "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" with + at pos 10 and / at pos 25
        let key = "AAAAAAAAAA+AAAAAAAAAAAAAA/AAAAAAAAAAAAAAAAA=";
        assert_eq!(key.len(), 44);
        assert!(validate_wg_key(key).is_ok());
    }

    #[test]
    fn test_wg_key_missing_padding() {
        // Key without '=' padding (invalid for WireGuard)
        let invalid = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="; // Double padding wrong
        assert!(matches!(
            validate_wg_key(invalid),
            Err(ValidationError::InvalidKeyEncoding)
        ));
    }
}
