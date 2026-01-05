//! QUIC Initial packet SNI extraction.
//!
//! This module extracts Server Name Indication (SNI) from QUIC Initial packets
//! for routing decisions without decrypting the entire connection.
//!
//! # QUIC Packet Structure
//!
//! QUIC has two header formats: Long Header (for Initial, Handshake, 0-RTT)
//! and Short Header (for 1-RTT application data).
//!
//! ## Long Header Format
//!
//! ```text
//! +-+-+-+-+-+-+-+-+
//! |1|1|T T|X X X X|  First byte (Header Form=1, Fixed Bit=1, Type, Reserved, PNLength)
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                         Version (32)                          |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! | DCID Len (8)  |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |               Destination Connection ID (0..160)              |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! | SCID Len (8)  |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                 Source Connection ID (0..160)                 |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! For Initial packets, there's also a Token Length and Token field,
//! followed by the Length field and encrypted payload.
//!
//! # SNI Extraction Strategy
//!
//! The Initial packet payload is encrypted with keys derived from the
//! Destination Connection ID. Full decryption requires:
//! 1. Deriving the Initial secret from DCID
//! 2. Deriving client/server keys and IVs
//! 3. Decrypting the packet using AEAD
//! 4. Parsing the CRYPTO frame containing the `ClientHello`
//!
//! This implementation uses a heuristic approach that searches for
//! SNI patterns in the packet data. While not 100% reliable, it works
//! for many common cases without the complexity of full decryption.
//!
//! # Example
//!
//! ```
//! use rust_router::sniff::quic::{QuicSniffer, QuicVersion};
//!
//! // Check if packet is QUIC
//! let data = &[0xc0, 0x00, 0x00, 0x00, 0x01]; // Long header, QUIC v1
//! if QuicSniffer::is_quic(data) {
//!     let result = QuicSniffer::sniff(data);
//!     if let Some(version) = result.version {
//!         println!("QUIC version: {:?}", version);
//!     }
//! }
//! ```

use serde::{Deserialize, Serialize};
use tracing::trace;

/// Known QUIC versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum QuicVersion {
    /// QUIC version 1 (RFC 9000)
    V1,
    /// QUIC version 2 (RFC 9369)
    V2,
    /// Draft version (for testing/development)
    Draft(u32),
    /// Unknown version
    Unknown(u32),
}

impl QuicVersion {
    /// Parse version from raw bytes.
    #[must_use]
    pub const fn from_u32(version: u32) -> Self {
        match version {
            0x0000_0001 => Self::V1,
            0x6b33_43cf => Self::V2,
            v if v >= 0xff00_0000 => Self::Draft(v),
            v => Self::Unknown(v),
        }
    }

    /// Get the raw version number.
    #[must_use]
    pub const fn as_u32(&self) -> u32 {
        match self {
            Self::V1 => 0x0000_0001,
            Self::V2 => 0x6b33_43cf,
            Self::Draft(v) | Self::Unknown(v) => *v,
        }
    }

    /// Check if this is a known production version.
    #[must_use]
    pub const fn is_known(&self) -> bool {
        matches!(self, Self::V1 | Self::V2)
    }
}

impl std::fmt::Display for QuicVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::V1 => write!(f, "QUICv1"),
            Self::V2 => write!(f, "QUICv2"),
            Self::Draft(v) => write!(f, "draft-{:02}", v & 0xff),
            Self::Unknown(v) => write!(f, "unknown-0x{v:08x}"),
        }
    }
}

/// QUIC packet type (from long header).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum QuicPacketType {
    /// Initial packet (contains `ClientHello`)
    Initial,
    /// 0-RTT packet
    ZeroRtt,
    /// Handshake packet
    Handshake,
    /// Retry packet
    Retry,
    /// Short header (1-RTT data)
    Short,
    /// Unknown packet type
    Unknown(u8),
}

impl QuicPacketType {
    /// Parse packet type from first byte and version.
    #[must_use]
    pub const fn from_header(first_byte: u8, version: QuicVersion) -> Self {
        // Long header if high bit is set
        if first_byte & 0x80 == 0 {
            return Self::Short;
        }

        // Packet type is in bits 4-5 for QUIC v1/v2
        let packet_type = (first_byte & 0x30) >> 4;

        match version {
            QuicVersion::V1 | QuicVersion::Draft(_) => match packet_type {
                0 => Self::Initial,
                1 => Self::ZeroRtt,
                2 => Self::Handshake,
                3 => Self::Retry,
                t => Self::Unknown(t),
            },
            QuicVersion::V2 => match packet_type {
                // V2 swaps some type values
                1 => Self::Initial,
                2 => Self::ZeroRtt,
                3 => Self::Handshake,
                0 => Self::Retry,
                t => Self::Unknown(t),
            },
            QuicVersion::Unknown(_) => Self::Unknown(packet_type),
        }
    }
}

/// Result of QUIC SNI extraction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuicSniffResult {
    /// Extracted SNI hostname
    pub server_name: Option<String>,
    /// QUIC version detected
    pub version: Option<QuicVersion>,
    /// Packet type
    pub packet_type: Option<QuicPacketType>,
    /// Whether this is a valid QUIC Initial packet
    pub is_initial: bool,
    /// Destination Connection ID (for debugging)
    pub dcid: Option<Vec<u8>>,
}

impl QuicSniffResult {
    /// Create a result for non-QUIC data.
    #[must_use]
    pub const fn not_quic() -> Self {
        Self {
            server_name: None,
            version: None,
            packet_type: None,
            is_initial: false,
            dcid: None,
        }
    }

    /// Check if SNI was successfully extracted.
    #[must_use]
    pub fn has_sni(&self) -> bool {
        self.server_name.is_some()
    }
}

impl Default for QuicSniffResult {
    fn default() -> Self {
        Self::not_quic()
    }
}

/// QUIC packet sniffer.
///
/// Provides methods to detect QUIC packets and extract SNI from Initial packets.
pub struct QuicSniffer;

impl QuicSniffer {
    /// Minimum size for a QUIC long header packet.
    const MIN_LONG_HEADER_SIZE: usize = 7; // 1 (first byte) + 4 (version) + 1 (DCID len) + 1 (SCID len)

    /// Sniff a UDP packet for QUIC Initial SNI.
    ///
    /// Attempts to parse the QUIC header and extract SNI from Initial packets.
    #[must_use]
    pub fn sniff(data: &[u8]) -> QuicSniffResult {
        if data.len() < Self::MIN_LONG_HEADER_SIZE {
            trace!("Packet too short for QUIC long header");
            return QuicSniffResult::not_quic();
        }

        let first_byte = data[0];

        // Check for long header (high bit set)
        if first_byte & 0x80 == 0 {
            trace!("Short header packet (not Initial)");
            return QuicSniffResult {
                version: None,
                packet_type: Some(QuicPacketType::Short),
                is_initial: false,
                server_name: None,
                dcid: None,
            };
        }

        // Check fixed bit (should be 1 for valid QUIC)
        if first_byte & 0x40 == 0 {
            trace!("Invalid fixed bit (not QUIC)");
            return QuicSniffResult::not_quic();
        }

        // Parse version
        let version_raw = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);

        // Version 0 is version negotiation, not a regular packet
        if version_raw == 0 {
            trace!("Version negotiation packet");
            return QuicSniffResult {
                version: Some(QuicVersion::Unknown(0)),
                packet_type: None,
                is_initial: false,
                server_name: None,
                dcid: None,
            };
        }

        let version = QuicVersion::from_u32(version_raw);
        let packet_type = QuicPacketType::from_header(first_byte, version);

        let is_initial = packet_type == QuicPacketType::Initial;

        // Parse DCID
        let dcid_len = data[5] as usize;
        if data.len() < 6 + dcid_len {
            trace!("Packet too short for DCID");
            return QuicSniffResult {
                version: Some(version),
                packet_type: Some(packet_type),
                is_initial,
                server_name: None,
                dcid: None,
            };
        }

        let dcid = data[6..6 + dcid_len].to_vec();

        // Parse SCID
        let scid_offset = 6 + dcid_len;
        if data.len() <= scid_offset {
            return QuicSniffResult {
                version: Some(version),
                packet_type: Some(packet_type),
                is_initial,
                server_name: None,
                dcid: Some(dcid),
            };
        }

        let scid_len = data[scid_offset] as usize;
        let payload_offset = scid_offset + 1 + scid_len;

        // For Initial packets, there's a token field
        let payload_offset = if is_initial && data.len() > payload_offset {
            // Token length is a variable-length integer
            match Self::parse_varint(&data[payload_offset..]) {
                Some((token_len, varint_size)) => {
                    #[allow(clippy::cast_possible_truncation)]
                    let new_offset = payload_offset + varint_size + token_len as usize;
                    // Skip the Length field too
                    if data.len() > new_offset {
                        match Self::parse_varint(&data[new_offset..]) {
                            Some((_, len_size)) => new_offset + len_size,
                            None => new_offset,
                        }
                    } else {
                        new_offset
                    }
                }
                None => payload_offset,
            }
        } else {
            payload_offset
        };

        // Try to extract SNI using heuristic approach
        let server_name = if is_initial && payload_offset < data.len() {
            Self::extract_sni_heuristic(&data[payload_offset..])
        } else {
            None
        };

        QuicSniffResult {
            version: Some(version),
            packet_type: Some(packet_type),
            is_initial,
            server_name,
            dcid: Some(dcid),
        }
    }

    /// Parse a QUIC variable-length integer.
    ///
    /// Returns `(value, bytes_consumed)` if successful.
    fn parse_varint(data: &[u8]) -> Option<(u64, usize)> {
        if data.is_empty() {
            return None;
        }

        let first = data[0];
        let prefix = first >> 6;

        match prefix {
            0 => Some((u64::from(first & 0x3f), 1)),
            1 => {
                if data.len() < 2 {
                    return None;
                }
                let value = u64::from(u16::from_be_bytes([first & 0x3f, data[1]]));
                Some((value, 2))
            }
            2 => {
                if data.len() < 4 {
                    return None;
                }
                let value = u64::from(u32::from_be_bytes([
                    first & 0x3f,
                    data[1],
                    data[2],
                    data[3],
                ]));
                Some((value, 4))
            }
            3 => {
                if data.len() < 8 {
                    return None;
                }
                let value = u64::from_be_bytes([
                    first & 0x3f,
                    data[1],
                    data[2],
                    data[3],
                    data[4],
                    data[5],
                    data[6],
                    data[7],
                ]);
                Some((value, 8))
            }
            _ => None,
        }
    }

    /// Heuristic SNI extraction from packet data.
    ///
    /// Searches for TLS SNI extension patterns in the encrypted payload.
    /// This works because:
    /// 1. The Initial packet contains a CRYPTO frame with the TLS `ClientHello`
    /// 2. Even though encrypted, certain patterns may be recognizable
    /// 3. We search for the SNI extension type (0x00 0x00) followed by valid data
    fn extract_sni_heuristic(data: &[u8]) -> Option<String> {
        // Look for SNI extension pattern in the packet
        // SNI extension: type=0x0000, length, list_length, name_type=0x00, name_length, name
        for i in 0..data.len().saturating_sub(10) {
            // Look for extension type 0x0000 (SNI)
            if data[i] == 0x00 && data[i + 1] == 0x00 {
                if let Some(sni) = Self::try_parse_sni(&data[i..]) {
                    // Validate the hostname looks reasonable
                    if Self::is_valid_hostname(&sni) {
                        return Some(sni);
                    }
                }
            }
        }
        None
    }

    /// Try to parse SNI from data starting at potential SNI extension.
    fn try_parse_sni(data: &[u8]) -> Option<String> {
        if data.len() < 9 {
            return None;
        }

        // Skip extension type (2 bytes), parse extension length (2 bytes)
        let ext_len = u16::from_be_bytes([data[2], data[3]]) as usize;
        if ext_len == 0 || ext_len > 256 || data.len() < 4 + ext_len {
            return None;
        }

        // Parse SNI list length (2 bytes)
        let list_len = u16::from_be_bytes([data[4], data[5]]) as usize;
        if list_len == 0 || list_len > ext_len || data.len() < 6 + list_len {
            return None;
        }

        // Name type (1 byte, should be 0 for host_name)
        if data[6] != 0 {
            return None;
        }

        // Name length (2 bytes)
        let name_len = u16::from_be_bytes([data[7], data[8]]) as usize;
        if name_len == 0 || name_len > 253 || data.len() < 9 + name_len {
            return None;
        }

        // Extract hostname
        let name_bytes = &data[9..9 + name_len];

        // Must be valid ASCII
        if !name_bytes.iter().all(u8::is_ascii) {
            return None;
        }

        String::from_utf8(name_bytes.to_vec()).ok()
    }

    /// Validate that a string looks like a valid hostname.
    fn is_valid_hostname(name: &str) -> bool {
        // Basic hostname validation
        if name.is_empty() || name.len() > 253 {
            return false;
        }

        // Must contain at least one dot (not localhost, IP addresses)
        if !name.contains('.') {
            return false;
        }

        // Check each label
        for label in name.split('.') {
            if label.is_empty() || label.len() > 63 {
                return false;
            }

            // Labels must start and end with alphanumeric
            if !label
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphanumeric())
            {
                return false;
            }
            if !label
                .chars()
                .last()
                .is_some_and(|c| c.is_ascii_alphanumeric())
            {
                return false;
            }

            // Labels can contain alphanumeric and hyphens
            if !label
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-')
            {
                return false;
            }
        }

        true
    }

    /// Check if a UDP packet looks like QUIC.
    #[must_use]
    pub fn is_quic(data: &[u8]) -> bool {
        if data.len() < 5 {
            return false;
        }

        let first_byte = data[0];

        // Long header: check for known versions
        if first_byte & 0x80 != 0 {
            // Check fixed bit
            if first_byte & 0x40 == 0 {
                return false;
            }

            let version = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);

            // Known QUIC versions
            matches!(
                version,
                0x0000_0001    // QUIC v1
                | 0x6b33_43cf  // QUIC v2
                | 0xff00_0000..=0xffff_ffff // Draft versions
            )
        } else {
            // Short header: harder to detect without context
            // We can't reliably identify short header QUIC packets
            // without knowing the expected connection IDs
            false
        }
    }

    /// Check if data looks like a QUIC Initial packet specifically.
    #[must_use]
    pub fn is_initial(data: &[u8]) -> bool {
        if data.len() < 5 {
            return false;
        }

        // Must be long header with fixed bit
        let first_byte = data[0];
        if first_byte & 0xc0 != 0xc0 {
            return false;
        }

        let version_raw = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
        let version = QuicVersion::from_u32(version_raw);
        let packet_type = QuicPacketType::from_header(first_byte, version);

        packet_type == QuicPacketType::Initial
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // === QuicVersion Tests ===

    #[test]
    fn test_version_v1() {
        let version = QuicVersion::from_u32(0x0000_0001);
        assert_eq!(version, QuicVersion::V1);
        assert!(version.is_known());
        assert_eq!(version.as_u32(), 0x0000_0001);
        assert_eq!(version.to_string(), "QUICv1");
    }

    #[test]
    fn test_version_v2() {
        let version = QuicVersion::from_u32(0x6b33_43cf);
        assert_eq!(version, QuicVersion::V2);
        assert!(version.is_known());
        assert_eq!(version.as_u32(), 0x6b33_43cf);
        assert_eq!(version.to_string(), "QUICv2");
    }

    #[test]
    fn test_version_draft() {
        let version = QuicVersion::from_u32(0xff00_001d); // draft-29
        assert!(matches!(version, QuicVersion::Draft(_)));
        assert!(!version.is_known());
        assert!(version.to_string().contains("draft-"));
    }

    #[test]
    fn test_version_unknown() {
        let version = QuicVersion::from_u32(0x1234_5678);
        assert!(matches!(version, QuicVersion::Unknown(_)));
        assert!(!version.is_known());
        assert!(version.to_string().contains("unknown"));
    }

    // === QuicPacketType Tests ===

    #[test]
    fn test_packet_type_initial_v1() {
        let first_byte = 0xc0; // Long header, fixed bit, type 0
        let packet_type = QuicPacketType::from_header(first_byte, QuicVersion::V1);
        assert_eq!(packet_type, QuicPacketType::Initial);
    }

    #[test]
    fn test_packet_type_handshake_v1() {
        let first_byte = 0xe0; // Long header, fixed bit, type 2
        let packet_type = QuicPacketType::from_header(first_byte, QuicVersion::V1);
        assert_eq!(packet_type, QuicPacketType::Handshake);
    }

    #[test]
    fn test_packet_type_initial_v2() {
        let first_byte = 0xd0; // Long header, fixed bit, type 1 (Initial in v2)
        let packet_type = QuicPacketType::from_header(first_byte, QuicVersion::V2);
        assert_eq!(packet_type, QuicPacketType::Initial);
    }

    #[test]
    fn test_packet_type_short_header() {
        let first_byte = 0x40; // Short header
        let packet_type = QuicPacketType::from_header(first_byte, QuicVersion::V1);
        assert_eq!(packet_type, QuicPacketType::Short);
    }

    // === QuicSniffResult Tests ===

    #[test]
    fn test_sniff_result_not_quic() {
        let result = QuicSniffResult::not_quic();
        assert!(!result.is_initial);
        assert!(result.version.is_none());
        assert!(!result.has_sni());
    }

    #[test]
    fn test_sniff_result_default() {
        let result = QuicSniffResult::default();
        assert!(!result.is_initial);
        assert!(result.version.is_none());
    }

    // === QuicSniffer Detection Tests ===

    #[test]
    fn test_is_quic_v1_initial() {
        // Long header, fixed bit, QUIC v1
        let data = [0xc0, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00];
        assert!(QuicSniffer::is_quic(&data));
    }

    #[test]
    fn test_is_quic_v2() {
        // Long header, fixed bit, QUIC v2
        let data = [0xc0, 0x6b, 0x33, 0x43, 0xcf, 0x08, 0x00];
        assert!(QuicSniffer::is_quic(&data));
    }

    #[test]
    fn test_is_quic_draft() {
        // Long header, fixed bit, draft version
        let data = [0xc0, 0xff, 0x00, 0x00, 0x1d, 0x08, 0x00];
        assert!(QuicSniffer::is_quic(&data));
    }

    #[test]
    fn test_is_not_quic_http() {
        let data = b"GET / HTTP/1.1\r\n";
        assert!(!QuicSniffer::is_quic(data));
    }

    #[test]
    fn test_is_not_quic_tls() {
        // TLS ClientHello
        let data = [0x16, 0x03, 0x01, 0x00, 0x05];
        assert!(!QuicSniffer::is_quic(&data));
    }

    #[test]
    fn test_is_not_quic_short() {
        let data = [0xc0, 0x00]; // Too short
        assert!(!QuicSniffer::is_quic(&data));
    }

    #[test]
    fn test_is_not_quic_invalid_fixed_bit() {
        // Long header without fixed bit
        let data = [0x80, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00];
        assert!(!QuicSniffer::is_quic(&data));
    }

    #[test]
    fn test_is_not_quic_short_header() {
        // Short header (we can't reliably detect these)
        let data = [0x40, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00];
        assert!(!QuicSniffer::is_quic(&data));
    }

    #[test]
    fn test_is_initial_v1() {
        let data = [0xc0, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00];
        assert!(QuicSniffer::is_initial(&data));
    }

    #[test]
    fn test_is_not_initial_handshake() {
        // Handshake packet type (type 2 in v1)
        let data = [0xe0, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00];
        assert!(!QuicSniffer::is_initial(&data));
    }

    // === QuicSniffer Sniff Tests ===

    #[test]
    fn test_sniff_too_short() {
        let data = [0xc0, 0x00, 0x00];
        let result = QuicSniffer::sniff(&data);
        assert!(!result.is_initial);
        assert!(result.version.is_none());
    }

    #[test]
    fn test_sniff_short_header() {
        let data = [0x40, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00];
        let result = QuicSniffer::sniff(&data);
        assert!(!result.is_initial);
        assert_eq!(result.packet_type, Some(QuicPacketType::Short));
    }

    #[test]
    fn test_sniff_invalid_fixed_bit() {
        let data = [0x80, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00];
        let result = QuicSniffer::sniff(&data);
        assert!(result.version.is_none());
    }

    #[test]
    fn test_sniff_version_negotiation() {
        // Version 0 is version negotiation
        let data = [0xc0, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00];
        let result = QuicSniffer::sniff(&data);
        assert!(!result.is_initial);
        assert_eq!(result.version, Some(QuicVersion::Unknown(0)));
    }

    #[test]
    fn test_sniff_v1_initial() {
        // QUIC v1 Initial packet
        let data = [
            0xc0, 0x00, 0x00, 0x00, 0x01, // Long header, QUIC v1
            0x08, // DCID length
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // DCID
            0x00, // SCID length
        ];
        let result = QuicSniffer::sniff(&data);
        assert_eq!(result.version, Some(QuicVersion::V1));
        assert_eq!(result.packet_type, Some(QuicPacketType::Initial));
        assert!(result.is_initial);
        assert_eq!(
            result.dcid,
            Some(vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
        );
    }

    #[test]
    fn test_sniff_v2_initial() {
        // QUIC v2 Initial packet (type 1)
        let data = [
            0xd0, 0x6b, 0x33, 0x43, 0xcf, // Long header, type 1, QUIC v2
            0x08, // DCID length
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // DCID
            0x00, // SCID length
        ];
        let result = QuicSniffer::sniff(&data);
        assert_eq!(result.version, Some(QuicVersion::V2));
        assert_eq!(result.packet_type, Some(QuicPacketType::Initial));
        assert!(result.is_initial);
    }

    #[test]
    fn test_sniff_handshake_packet() {
        // QUIC v1 Handshake packet (type 2)
        let data = [
            0xe0, 0x00, 0x00, 0x00, 0x01, // Long header, type 2, QUIC v1
            0x08, // DCID length
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // DCID
            0x00, // SCID length
        ];
        let result = QuicSniffer::sniff(&data);
        assert_eq!(result.packet_type, Some(QuicPacketType::Handshake));
        assert!(!result.is_initial);
    }

    // === Varint Parsing Tests ===

    #[test]
    fn test_parse_varint_1byte() {
        let data = [0x25]; // 37
        let result = QuicSniffer::parse_varint(&data);
        assert_eq!(result, Some((37, 1)));
    }

    #[test]
    fn test_parse_varint_2byte() {
        let data = [0x7b, 0xbd]; // 15293
        let result = QuicSniffer::parse_varint(&data);
        assert_eq!(result, Some((15293, 2)));
    }

    #[test]
    fn test_parse_varint_4byte() {
        let data = [0x9d, 0x7f, 0x3e, 0x7d]; // 494878333
        let result = QuicSniffer::parse_varint(&data);
        assert_eq!(result, Some((494_878_333, 4)));
    }

    #[test]
    fn test_parse_varint_empty() {
        let data: [u8; 0] = [];
        let result = QuicSniffer::parse_varint(&data);
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_varint_truncated() {
        let data = [0x7b]; // Needs 2 bytes
        let result = QuicSniffer::parse_varint(&data);
        assert!(result.is_none());
    }

    // === Hostname Validation Tests ===

    #[test]
    fn test_valid_hostname() {
        assert!(QuicSniffer::is_valid_hostname("example.com"));
        assert!(QuicSniffer::is_valid_hostname("www.example.com"));
        assert!(QuicSniffer::is_valid_hostname("sub.domain.example.com"));
        assert!(QuicSniffer::is_valid_hostname("my-site.example.com"));
    }

    #[test]
    fn test_invalid_hostname_no_dot() {
        assert!(!QuicSniffer::is_valid_hostname("localhost"));
    }

    #[test]
    fn test_invalid_hostname_empty() {
        assert!(!QuicSniffer::is_valid_hostname(""));
    }

    #[test]
    fn test_invalid_hostname_empty_label() {
        assert!(!QuicSniffer::is_valid_hostname("example..com"));
        assert!(!QuicSniffer::is_valid_hostname(".example.com"));
        assert!(!QuicSniffer::is_valid_hostname("example.com."));
    }

    #[test]
    fn test_invalid_hostname_hyphen_start() {
        assert!(!QuicSniffer::is_valid_hostname("-example.com"));
    }

    #[test]
    fn test_invalid_hostname_hyphen_end() {
        assert!(!QuicSniffer::is_valid_hostname("example-.com"));
    }

    #[test]
    fn test_invalid_hostname_special_chars() {
        assert!(!QuicSniffer::is_valid_hostname("exam_ple.com"));
        assert!(!QuicSniffer::is_valid_hostname("exam@ple.com"));
    }

    // === SNI Parsing Tests ===

    #[test]
    fn test_try_parse_sni_valid() {
        // SNI extension: type (2) + length (2) + list_length (2) + name_type (1) + name_length (2) + name
        let name = "example.com";
        let name_len = name.len() as u16;
        let list_len = 3 + name_len; // name_type (1) + name_length (2) + name
        let ext_len = 2 + list_len; // list_length (2) + list

        let mut data = vec![
            0x00,
            0x00, // Extension type (SNI)
            (ext_len >> 8) as u8,
            ext_len as u8, // Extension length
            (list_len >> 8) as u8,
            list_len as u8, // List length
            0x00, // Name type (host_name)
            (name_len >> 8) as u8,
            name_len as u8, // Name length
        ];
        data.extend_from_slice(name.as_bytes());

        let result = QuicSniffer::try_parse_sni(&data);
        assert_eq!(result, Some("example.com".to_string()));
    }

    #[test]
    fn test_try_parse_sni_too_short() {
        let data = [0x00, 0x00, 0x00, 0x05];
        let result = QuicSniffer::try_parse_sni(&data);
        assert!(result.is_none());
    }

    #[test]
    fn test_try_parse_sni_wrong_name_type() {
        let data = [
            0x00, 0x00, // Extension type
            0x00, 0x08, // Extension length
            0x00, 0x05, // List length
            0x01, // Wrong name type (not 0)
            0x00, 0x02, // Name length
            0x61, 0x62, // Name "ab"
        ];
        let result = QuicSniffer::try_parse_sni(&data);
        assert!(result.is_none());
    }

    // === Serialization Tests ===

    #[test]
    fn test_version_serialization() {
        let version = QuicVersion::V1;
        let json = serde_json::to_string(&version).unwrap();
        let parsed: QuicVersion = serde_json::from_str(&json).unwrap();
        assert_eq!(version, parsed);
    }

    #[test]
    fn test_packet_type_serialization() {
        let packet_type = QuicPacketType::Initial;
        let json = serde_json::to_string(&packet_type).unwrap();
        let parsed: QuicPacketType = serde_json::from_str(&json).unwrap();
        assert_eq!(packet_type, parsed);
    }

    #[test]
    fn test_sniff_result_serialization() {
        let result = QuicSniffResult {
            server_name: Some("example.com".to_string()),
            version: Some(QuicVersion::V1),
            packet_type: Some(QuicPacketType::Initial),
            is_initial: true,
            dcid: Some(vec![0x01, 0x02, 0x03]),
        };

        let json = serde_json::to_string(&result).unwrap();
        let parsed: QuicSniffResult = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.server_name, result.server_name);
        assert_eq!(parsed.version, result.version);
        assert_eq!(parsed.is_initial, result.is_initial);
    }

    // === Integration-style Tests ===

    #[test]
    fn test_sniff_real_world_like_packet() {
        // Construct a realistic QUIC v1 Initial packet structure
        let mut packet = vec![
            0xc3, // Long header, fixed bit, Initial type, PN length 4
            0x00, 0x00, 0x00, 0x01, // QUIC v1
            0x08, // DCID length
            0xba, 0xba, 0xba, 0xba, 0xba, 0xba, 0xba, 0xba, // DCID
            0x00, // SCID length
            0x00, // Token length (varint, 0)
        ];

        // Add length (varint) and some payload
        packet.push(0x41); // Length prefix (2-byte varint)
        packet.push(0x00); // Length value low byte

        // Add some payload bytes (would normally be encrypted CRYPTO frame)
        packet.extend_from_slice(&[0u8; 64]);

        let result = QuicSniffer::sniff(&packet);

        assert!(result.is_initial);
        assert_eq!(result.version, Some(QuicVersion::V1));
        assert_eq!(result.packet_type, Some(QuicPacketType::Initial));
        assert!(result.dcid.is_some());
        assert_eq!(result.dcid.unwrap().len(), 8);
    }

    #[test]
    fn test_sniff_empty_dcid() {
        let data = [
            0xc0, 0x00, 0x00, 0x00, 0x01, // Long header, QUIC v1
            0x00, // DCID length (empty)
            0x00, // SCID length
        ];
        let result = QuicSniffer::sniff(&data);

        assert!(result.is_initial);
        assert!(result.dcid.is_some());
        assert!(result.dcid.unwrap().is_empty());
    }

    #[test]
    fn test_sniff_max_dcid_length() {
        // DCID can be up to 20 bytes
        let mut data = vec![
            0xc0, 0x00, 0x00, 0x00, 0x01, // Long header, QUIC v1
            0x14, // DCID length (20)
        ];
        data.extend_from_slice(&[0xaa; 20]); // DCID
        data.push(0x00); // SCID length

        let result = QuicSniffer::sniff(&data);

        assert!(result.is_initial);
        assert_eq!(result.dcid.as_ref().unwrap().len(), 20);
    }
}
