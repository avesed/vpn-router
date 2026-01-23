//! DSCP packet modification
//!
//! This module implements DSCP (Differentiated Services Code Point) packet
//! modification for chain routing, including IPv4 header checksum recalculation.
//!
//! # DSCP in IP Headers
//!
//! ## IPv4
//!
//! The TOS (Type of Service) byte in IPv4 contains:
//! - Bits 0-5: DSCP (6 bits)
//! - Bits 6-7: ECN (2 bits)
//!
//! ```text
//! IPv4 Header:
//! +---+---+---+---+---+---+---+---+
//! | Version (4) | IHL (4)        |  Byte 0
//! +---+---+---+---+---+---+---+---+
//! | DSCP (6)    | ECN (2)        |  Byte 1 (TOS)
//! +---+---+---+---+---+---+---+---+
//! | ... Total Length, ID, etc ... |
//! ```
//!
//! ## IPv6
//!
//! The Traffic Class in IPv6 spans bytes 0-1:
//! - Byte 0: Version (4 bits) + TC high (4 bits)
//! - Byte 1: TC low (4 bits) + Flow Label high (4 bits)
//!
//! ```text
//! IPv6 Header:
//! +---+---+---+---+---+---+---+---+---+---+---+---+
//! | Version (4) | TC (8)          | Flow Label (20)  |
//! +---+---+---+---+---+---+---+---+---+---+---+---+
//! ```
//!
//! # Security Considerations
//!
//! - DSCP values may be stripped or modified by intermediate networks
//! - Reserved DSCP values (standard `QoS` classes) are protected from allocation
//!
//! # References
//!
//! - RFC 2474: Definition of the Differentiated Services Field
//! - Implementation Plan: `docs/PHASE6_IMPLEMENTATION_PLAN_v3.2.md` Section 6.6.2

/// Minimum valid DSCP value for chain routing
pub const DSCP_MIN: u8 = 1;

/// Maximum valid DSCP value (6-bit field)
pub const DSCP_MAX: u8 = 63;

/// Minimum IPv4 header length
pub const IPV4_MIN_HEADER_LEN: usize = 20;

/// Minimum IPv6 header length
pub const IPV6_MIN_HEADER_LEN: usize = 40;

/// Error types for DSCP operations
#[derive(Debug, Clone, thiserror::Error)]
pub enum DscpError {
    /// Packet is empty
    #[error("Empty packet")]
    EmptyPacket,

    /// Packet is too short
    #[error("Packet too short: {0} bytes (minimum {1} required)")]
    PacketTooShort(usize, usize),

    /// Invalid IP version
    #[error("Invalid IP version: {0}")]
    InvalidIpVersion(u8),

    /// Invalid DSCP value
    #[error("Invalid DSCP value: {0} (must be 0-63)")]
    InvalidDscpValue(u8),

    /// Checksum calculation failed
    #[error("IPv4 checksum calculation failed: {0}")]
    ChecksumError(String),
}

/// Set DSCP value on an IP packet
///
/// Modifies the packet in place, setting the DSCP field while preserving
/// the ECN bits. For IPv4, the header checksum is recalculated.
///
/// # Arguments
///
/// * `packet` - Mutable reference to the IP packet bytes
/// * `dscp` - DSCP value to set (0-63)
///
/// # Returns
///
/// Ok if successful, or an error describing the failure.
///
/// # Example
///
/// ```
/// use rust_router::chain::dscp::set_dscp;
///
/// // IPv4 packet with minimal header
/// let mut packet = vec![
///     0x45, 0x00, // Version=4, IHL=5, TOS=0x00
///     0x00, 0x14, // Total Length = 20
///     0x00, 0x00, 0x00, 0x00, // ID, Flags, Fragment
///     0x40, 0x01, // TTL=64, Protocol=ICMP
///     0x00, 0x00, // Checksum (placeholder)
///     0x0a, 0x00, 0x00, 0x01, // Source IP
///     0x0a, 0x00, 0x00, 0x02, // Dest IP
/// ];
///
/// // Set DSCP to 10 (0x0A << 2 = 0x28)
/// set_dscp(&mut packet, 10).expect("Should set DSCP");
/// assert_eq!(packet[1] & 0xFC, 0x28); // DSCP bits
/// ```
pub fn set_dscp(packet: &mut [u8], dscp: u8) -> Result<(), DscpError> {
    if packet.is_empty() {
        return Err(DscpError::EmptyPacket);
    }

    // DSCP is 6 bits
    if dscp > DSCP_MAX {
        return Err(DscpError::InvalidDscpValue(dscp));
    }

    let version = packet[0] >> 4;

    match version {
        4 => set_dscp_ipv4(packet, dscp),
        6 => set_dscp_ipv6(packet, dscp),
        _ => Err(DscpError::InvalidIpVersion(version)),
    }
}

/// Set DSCP on an IPv4 packet
fn set_dscp_ipv4(packet: &mut [u8], dscp: u8) -> Result<(), DscpError> {
    if packet.len() < IPV4_MIN_HEADER_LEN {
        return Err(DscpError::PacketTooShort(packet.len(), IPV4_MIN_HEADER_LEN));
    }

    // TOS byte layout: DSCP (6 bits) + ECN (2 bits)
    // Preserve ECN bits (lower 2 bits), set DSCP (upper 6 bits)
    packet[1] = (packet[1] & 0x03) | (dscp << 2);

    // Recalculate IPv4 header checksum
    recalc_ipv4_checksum(packet)?;

    Ok(())
}

/// Set DSCP on an IPv6 packet
fn set_dscp_ipv6(packet: &mut [u8], dscp: u8) -> Result<(), DscpError> {
    if packet.len() < IPV6_MIN_HEADER_LEN {
        return Err(DscpError::PacketTooShort(packet.len(), IPV6_MIN_HEADER_LEN));
    }

    // Traffic Class spans bytes 0-1:
    // Byte 0: Version (4 bits) + TC high (4 bits)
    // Byte 1: TC low (4 bits) + Flow Label high (4 bits)
    //
    // Traffic Class = DSCP (6 bits) + ECN (2 bits)
    // TC = (DSCP << 2) | ECN

    // Extract current Traffic Class to preserve ECN
    let current_tc = ((packet[0] & 0x0F) << 4) | (packet[1] >> 4);
    let ecn = current_tc & 0x03;
    let new_tc = (dscp << 2) | ecn;

    // Update bytes 0-1
    packet[0] = (packet[0] & 0xF0) | (new_tc >> 4);
    packet[1] = ((new_tc & 0x0F) << 4) | (packet[1] & 0x0F);

    // IPv6 has no header checksum - done!

    Ok(())
}

/// Extract DSCP value from an IP packet
///
/// # Arguments
///
/// * `packet` - Reference to the IP packet bytes
///
/// # Returns
///
/// The DSCP value (0-63) or an error.
///
/// # Example
///
/// ```
/// use rust_router::chain::dscp::get_dscp;
///
/// // IPv4 packet with DSCP=10 (TOS=0x28)
/// let packet = vec![
///     0x45, 0x28, // Version=4, IHL=5, TOS=0x28 (DSCP=10)
///     0x00, 0x14, 0x00, 0x00, 0x00, 0x00,
///     0x40, 0x01, 0x00, 0x00,
///     0x0a, 0x00, 0x00, 0x01,
///     0x0a, 0x00, 0x00, 0x02,
/// ];
///
/// let dscp = get_dscp(&packet).expect("Should extract DSCP");
/// assert_eq!(dscp, 10);
/// ```
pub fn get_dscp(packet: &[u8]) -> Result<u8, DscpError> {
    if packet.is_empty() {
        return Err(DscpError::EmptyPacket);
    }

    let version = packet[0] >> 4;

    match version {
        4 => {
            if packet.len() < IPV4_MIN_HEADER_LEN {
                return Err(DscpError::PacketTooShort(packet.len(), IPV4_MIN_HEADER_LEN));
            }
            // DSCP is upper 6 bits of TOS byte
            Ok((packet[1] >> 2) & 0x3F)
        }
        6 => {
            if packet.len() < IPV6_MIN_HEADER_LEN {
                return Err(DscpError::PacketTooShort(packet.len(), IPV6_MIN_HEADER_LEN));
            }
            // Extract Traffic Class, then DSCP
            let tc = ((packet[0] & 0x0F) << 4) | (packet[1] >> 4);
            Ok((tc >> 2) & 0x3F)
        }
        _ => Err(DscpError::InvalidIpVersion(version)),
    }
}

/// Recalculate IPv4 header checksum
///
/// The IPv4 header checksum is the 16-bit one's complement of the
/// one's complement sum of all 16-bit words in the header.
fn recalc_ipv4_checksum(packet: &mut [u8]) -> Result<(), DscpError> {
    // Get IHL (Internet Header Length) in 32-bit words
    let ihl = (packet[0] & 0x0F) as usize;
    let header_len = ihl * 4;

    if packet.len() < header_len {
        return Err(DscpError::ChecksumError(format!(
            "Packet too short for header: {} < {}",
            packet.len(),
            header_len
        )));
    }

    // Zero existing checksum (bytes 10-11)
    packet[10] = 0;
    packet[11] = 0;

    // Calculate sum of 16-bit words
    let mut sum: u32 = 0;
    for i in (0..header_len).step_by(2) {
        let word = if i + 1 < header_len {
            (u32::from(packet[i]) << 8) | u32::from(packet[i + 1])
        } else {
            u32::from(packet[i]) << 8
        };
        sum += word;
    }

    // Fold 32-bit sum to 16 bits (add carry bits)
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // One's complement
    let checksum = !sum as u16;

    // Store checksum in network byte order
    packet[10] = (checksum >> 8) as u8;
    packet[11] = (checksum & 0xFF) as u8;

    Ok(())
}

/// Verify IPv4 header checksum
///
/// # Arguments
///
/// * `packet` - Reference to the IPv4 packet bytes
///
/// # Returns
///
/// `true` if the checksum is valid, `false` otherwise.
#[allow(dead_code)]
pub fn verify_ipv4_checksum(packet: &[u8]) -> bool {
    if packet.len() < IPV4_MIN_HEADER_LEN {
        return false;
    }

    let version = packet[0] >> 4;
    if version != 4 {
        return false;
    }

    let ihl = (packet[0] & 0x0F) as usize;
    let header_len = ihl * 4;

    if packet.len() < header_len {
        return false;
    }

    // Sum all 16-bit words including checksum
    let mut sum: u32 = 0;
    for i in (0..header_len).step_by(2) {
        let word = if i + 1 < header_len {
            (u32::from(packet[i]) << 8) | u32::from(packet[i + 1])
        } else {
            u32::from(packet[i]) << 8
        };
        sum += word;
    }

    // Fold to 16 bits
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // Valid checksum results in 0xFFFF after folding
    sum == 0xFFFF
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_ipv4_packet(dscp: u8) -> Vec<u8> {
        let tos = dscp << 2;
        let mut packet = vec![
            0x45,
            tos, // Version=4, IHL=5, TOS
            0x00,
            0x14, // Total Length = 20
            0x00,
            0x00,
            0x00,
            0x00, // ID, Flags, Fragment
            0x40,
            0x01, // TTL=64, Protocol=ICMP
            0x00,
            0x00, // Checksum (will be calculated)
            0x0a,
            0x00,
            0x00,
            0x01, // Source IP 10.0.0.1
            0x0a,
            0x00,
            0x00,
            0x02, // Dest IP 10.0.0.2
        ];

        // Calculate initial checksum
        recalc_ipv4_checksum(&mut packet).unwrap();
        packet
    }

    fn create_ipv6_packet(dscp: u8) -> Vec<u8> {
        let tc = dscp << 2; // Traffic Class (no ECN)
        let byte0 = 0x60 | (tc >> 4); // Version=6, TC high
        let byte1 = (tc << 4) & 0xF0; // TC low, Flow Label high

        vec![
            byte0,
            byte1, // Version, Traffic Class, Flow Label
            0x00,
            0x00, // Flow Label continued
            0x00,
            0x00, // Payload Length
            0x3a,
            0x40, // Next Header=ICMPv6, Hop Limit
            // Source IPv6 (16 bytes)
            0x20,
            0x01,
            0x0d,
            0xb8,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x01,
            // Dest IPv6 (16 bytes)
            0x20,
            0x01,
            0x0d,
            0xb8,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x02,
        ]
    }

    #[test]
    fn test_get_dscp_ipv4() {
        let packet = create_ipv4_packet(10);
        let dscp = get_dscp(&packet).unwrap();
        assert_eq!(dscp, 10);
    }

    #[test]
    fn test_get_dscp_ipv6() {
        let packet = create_ipv6_packet(20);
        let dscp = get_dscp(&packet).unwrap();
        assert_eq!(dscp, 20);
    }

    #[test]
    fn test_set_dscp_ipv4() {
        let mut packet = create_ipv4_packet(0);

        // Verify checksum is valid before modification
        assert!(verify_ipv4_checksum(&packet));

        // Set DSCP to 42
        set_dscp(&mut packet, 42).unwrap();

        // Verify DSCP was set
        assert_eq!(get_dscp(&packet).unwrap(), 42);

        // Verify checksum is still valid after modification
        assert!(verify_ipv4_checksum(&packet));
    }

    #[test]
    fn test_set_dscp_ipv6() {
        let mut packet = create_ipv6_packet(0);

        // Set DSCP to 42
        set_dscp(&mut packet, 42).unwrap();

        // Verify DSCP was set
        assert_eq!(get_dscp(&packet).unwrap(), 42);
    }

    #[test]
    fn test_ecn_preserved_ipv4() {
        let mut packet = create_ipv4_packet(0);

        // Set ECN bits (lower 2 bits of TOS)
        packet[1] = (packet[1] & 0xFC) | 0x03; // ECN=11
        recalc_ipv4_checksum(&mut packet).unwrap();

        // Set DSCP
        set_dscp(&mut packet, 42).unwrap();

        // Verify ECN is preserved
        assert_eq!(packet[1] & 0x03, 0x03);
        // Verify DSCP is correct
        assert_eq!((packet[1] >> 2) & 0x3F, 42);
    }

    #[test]
    fn test_empty_packet() {
        let packet: Vec<u8> = vec![];
        assert!(matches!(get_dscp(&packet), Err(DscpError::EmptyPacket)));
    }

    #[test]
    fn test_packet_too_short() {
        let packet = vec![0x45, 0x00]; // Only 2 bytes
        assert!(matches!(
            get_dscp(&packet),
            Err(DscpError::PacketTooShort(2, 20))
        ));
    }

    #[test]
    fn test_invalid_version() {
        let mut packet = create_ipv4_packet(0);
        packet[0] = 0x75; // Version = 7

        assert!(matches!(
            get_dscp(&packet),
            Err(DscpError::InvalidIpVersion(7))
        ));
    }

    #[test]
    fn test_invalid_dscp_value() {
        let mut packet = create_ipv4_packet(0);

        assert!(matches!(
            set_dscp(&mut packet, 64),
            Err(DscpError::InvalidDscpValue(64))
        ));
    }

    #[test]
    fn test_all_dscp_values() {
        // Test all valid DSCP values (0-63)
        for dscp in 0..=63 {
            let mut packet = create_ipv4_packet(0);
            set_dscp(&mut packet, dscp).unwrap();
            assert_eq!(get_dscp(&packet).unwrap(), dscp);
            assert!(verify_ipv4_checksum(&packet));
        }
    }
}
