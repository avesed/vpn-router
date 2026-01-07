//! Common SOCKS5 protocol constants and utilities (RFC 1928, RFC 1929)
//!
//! This module provides shared constants and types used by both the SOCKS5 TCP
//! and UDP implementations. Having a single source of truth for protocol constants
//! ensures consistency and reduces duplication.

// ============================================================================
// Protocol Version
// ============================================================================

/// SOCKS5 protocol version (RFC 1928)
pub const SOCKS5_VERSION: u8 = 0x05;

// ============================================================================
// Authentication Methods (RFC 1928 Section 3)
// ============================================================================

/// No authentication required (0x00)
pub const AUTH_METHOD_NONE: u8 = 0x00;

/// Username/password authentication - RFC 1929 (0x02)
pub const AUTH_METHOD_PASSWORD: u8 = 0x02;

/// No acceptable methods (0xFF) - server rejects all offered methods
pub const AUTH_METHOD_NO_ACCEPTABLE: u8 = 0xFF;

/// Username/password auth sub-negotiation version (RFC 1929)
pub const AUTH_PASSWORD_VERSION: u8 = 0x01;

// ============================================================================
// Commands (RFC 1928 Section 4)
// ============================================================================

/// CONNECT command (0x01) - establish TCP connection
pub const CMD_CONNECT: u8 = 0x01;

/// BIND command (0x02) - bind for incoming TCP connection (rarely used)
pub const CMD_BIND: u8 = 0x02;

/// UDP ASSOCIATE command (0x03) - establish UDP relay
pub const CMD_UDP_ASSOCIATE: u8 = 0x03;

// ============================================================================
// Address Types (RFC 1928 Section 4)
// ============================================================================

/// IPv4 address (4 bytes)
pub const ATYP_IPV4: u8 = 0x01;

/// Domain name (1 byte length + N bytes name)
pub const ATYP_DOMAIN: u8 = 0x03;

/// IPv6 address (16 bytes)
pub const ATYP_IPV6: u8 = 0x04;

// ============================================================================
// Reply Codes (RFC 1928 Section 6)
// ============================================================================

/// Succeeded (0x00)
pub const REPLY_SUCCEEDED: u8 = 0x00;

/// General SOCKS server failure (0x01)
pub const REPLY_GENERAL_FAILURE: u8 = 0x01;

/// Connection not allowed by ruleset (0x02)
pub const REPLY_NOT_ALLOWED: u8 = 0x02;

/// Network unreachable (0x03)
pub const REPLY_NETWORK_UNREACHABLE: u8 = 0x03;

/// Host unreachable (0x04)
pub const REPLY_HOST_UNREACHABLE: u8 = 0x04;

/// Connection refused (0x05)
pub const REPLY_CONNECTION_REFUSED: u8 = 0x05;

/// TTL expired (0x06)
pub const REPLY_TTL_EXPIRED: u8 = 0x06;

/// Command not supported (0x07)
pub const REPLY_COMMAND_NOT_SUPPORTED: u8 = 0x07;

/// Address type not supported (0x08)
pub const REPLY_ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;

// ============================================================================
// UDP Packet Header Sizes (RFC 1928 Section 7)
// ============================================================================

/// RSV field size (2 bytes, must be 0x0000)
pub const UDP_RSV_SIZE: usize = 2;

/// FRAG field size (1 byte)
pub const UDP_FRAG_SIZE: usize = 1;

/// ATYP field size (1 byte)
pub const UDP_ATYP_SIZE: usize = 1;

/// IPv4 address size in bytes
pub const IPV4_ADDR_SIZE: usize = 4;

/// IPv6 address size in bytes
pub const IPV6_ADDR_SIZE: usize = 16;

/// Port field size (2 bytes, network byte order)
pub const PORT_SIZE: usize = 2;

/// Minimum UDP header size for IPv4: RSV(2) + FRAG(1) + ATYP(1) + IPv4(4) + PORT(2) = 10
pub const UDP_HEADER_MIN_SIZE: usize =
    UDP_RSV_SIZE + UDP_FRAG_SIZE + UDP_ATYP_SIZE + IPV4_ADDR_SIZE + PORT_SIZE;

/// UDP header size for IPv6: RSV(2) + FRAG(1) + ATYP(1) + IPv6(16) + PORT(2) = 22
pub const UDP_HEADER_IPV6_SIZE: usize =
    UDP_RSV_SIZE + UDP_FRAG_SIZE + UDP_ATYP_SIZE + IPV6_ADDR_SIZE + PORT_SIZE;

// ============================================================================
// Utility Functions
// ============================================================================

/// Convert reply code to human-readable message
#[must_use]
pub const fn reply_message(code: u8) -> &'static str {
    match code {
        REPLY_SUCCEEDED => "succeeded",
        REPLY_GENERAL_FAILURE => "general SOCKS server failure",
        REPLY_NOT_ALLOWED => "connection not allowed by ruleset",
        REPLY_NETWORK_UNREACHABLE => "network unreachable",
        REPLY_HOST_UNREACHABLE => "host unreachable",
        REPLY_CONNECTION_REFUSED => "connection refused",
        REPLY_TTL_EXPIRED => "TTL expired",
        REPLY_COMMAND_NOT_SUPPORTED => "command not supported",
        REPLY_ADDRESS_TYPE_NOT_SUPPORTED => "address type not supported",
        _ => "unknown error",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_version() {
        assert_eq!(SOCKS5_VERSION, 0x05);
    }

    #[test]
    fn test_auth_methods() {
        assert_eq!(AUTH_METHOD_NONE, 0x00);
        assert_eq!(AUTH_METHOD_PASSWORD, 0x02);
        assert_eq!(AUTH_METHOD_NO_ACCEPTABLE, 0xFF);
        assert_eq!(AUTH_PASSWORD_VERSION, 0x01);
    }

    #[test]
    fn test_commands() {
        assert_eq!(CMD_CONNECT, 0x01);
        assert_eq!(CMD_BIND, 0x02);
        assert_eq!(CMD_UDP_ASSOCIATE, 0x03);
    }

    #[test]
    fn test_address_types() {
        assert_eq!(ATYP_IPV4, 0x01);
        assert_eq!(ATYP_DOMAIN, 0x03);
        assert_eq!(ATYP_IPV6, 0x04);
    }

    #[test]
    fn test_reply_codes() {
        assert_eq!(REPLY_SUCCEEDED, 0x00);
        assert_eq!(REPLY_GENERAL_FAILURE, 0x01);
        assert_eq!(REPLY_NOT_ALLOWED, 0x02);
        assert_eq!(REPLY_NETWORK_UNREACHABLE, 0x03);
        assert_eq!(REPLY_HOST_UNREACHABLE, 0x04);
        assert_eq!(REPLY_CONNECTION_REFUSED, 0x05);
        assert_eq!(REPLY_TTL_EXPIRED, 0x06);
        assert_eq!(REPLY_COMMAND_NOT_SUPPORTED, 0x07);
        assert_eq!(REPLY_ADDRESS_TYPE_NOT_SUPPORTED, 0x08);
    }

    #[test]
    fn test_header_sizes() {
        // RSV(2) + FRAG(1) + ATYP(1) + IPv4(4) + PORT(2) = 10
        assert_eq!(UDP_HEADER_MIN_SIZE, 10);
        // RSV(2) + FRAG(1) + ATYP(1) + IPv6(16) + PORT(2) = 22
        assert_eq!(UDP_HEADER_IPV6_SIZE, 22);
    }

    #[test]
    fn test_reply_message() {
        assert_eq!(reply_message(REPLY_SUCCEEDED), "succeeded");
        assert_eq!(
            reply_message(REPLY_GENERAL_FAILURE),
            "general SOCKS server failure"
        );
        assert_eq!(
            reply_message(REPLY_NOT_ALLOWED),
            "connection not allowed by ruleset"
        );
        assert_eq!(reply_message(REPLY_NETWORK_UNREACHABLE), "network unreachable");
        assert_eq!(reply_message(REPLY_HOST_UNREACHABLE), "host unreachable");
        assert_eq!(reply_message(REPLY_CONNECTION_REFUSED), "connection refused");
        assert_eq!(reply_message(REPLY_TTL_EXPIRED), "TTL expired");
        assert_eq!(
            reply_message(REPLY_COMMAND_NOT_SUPPORTED),
            "command not supported"
        );
        assert_eq!(
            reply_message(REPLY_ADDRESS_TYPE_NOT_SUPPORTED),
            "address type not supported"
        );
        assert_eq!(reply_message(0x99), "unknown error");
    }
}
