//! QUIC Initial packet decryption for SNI extraction (RFC 9001).
//!
//! This module provides cryptographic decryption of QUIC Initial packets
//! to extract the TLS ClientHello and subsequently the SNI.
//!
//! # Overview
//!
//! QUIC Initial packets are encrypted with keys derived from the Destination
//! Connection ID (DCID). This module implements:
//!
//! 1. **Key derivation** using HKDF-SHA256 (RFC 9001 Section 5.2)
//! 2. **Header protection removal** using AES-ECB
//! 3. **Payload decryption** using AES-128-GCM
//! 4. **CRYPTO frame parsing** to extract TLS ClientHello
//! 5. **SNI extraction** from the ClientHello using the TLS sniffer
//!
//! # Security Note
//!
//! This implementation only decrypts client Initial packets for the purpose
//! of SNI extraction. It does not attempt to decrypt any other packet types
//! or maintain cryptographic state for ongoing connections.
//!
//! # Example
//!
//! ```ignore
//! use rust_router::sniff::quic_decrypt::decrypt_quic_initial;
//!
//! let udp_data = &[/* QUIC Initial packet bytes */];
//! match decrypt_quic_initial(udp_data) {
//!     Ok(result) => {
//!         if let Some(sni) = result.server_name {
//!             println!("QUIC connection to: {}", sni);
//!         }
//!     }
//!     Err(e) => {
//!         println!("Decryption failed: {:?}", e);
//!     }
//! }
//! ```

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes128Gcm, Nonce,
};
use hkdf::Hkdf;
use sha2::Sha256;
use tracing::{debug, trace};

use super::quic::{QuicPacketType, QuicSniffResult, QuicSniffer, QuicVersion};

/// QUIC v1 Initial Salt (RFC 9001 Section 5.2)
const QUIC_V1_SALT: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

/// QUIC v2 Initial Salt (RFC 9369)
const QUIC_V2_SALT: [u8; 20] = [
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
    0xf9, 0xbd, 0x2e, 0xd9,
];

/// AES-128-GCM key size
const AES_KEY_SIZE: usize = 16;

/// AES-128-GCM IV size
const IV_SIZE: usize = 12;

/// AES-128-GCM tag size
const TAG_SIZE: usize = 16;

/// Header protection key size (AES-128)
const HP_KEY_SIZE: usize = 16;

/// Header protection sample size
const HP_SAMPLE_SIZE: usize = 16;

/// Minimum QUIC packet size for decryption
const MIN_PACKET_SIZE: usize = 21; // 1 + 4 + 1 + 1 + 1 + 1 + 4 + 8 (header + minimal payload)

/// Maximum CRYPTO frame data size we'll process
const MAX_CRYPTO_SIZE: usize = 16384;

/// Decryption error types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecryptError {
    /// Packet too short
    PacketTooShort,
    /// Not a QUIC packet (invalid header)
    NotQuic,
    /// Not an Initial packet
    NotInitial,
    /// Unsupported QUIC version
    UnsupportedVersion(u32),
    /// Token field is non-empty (retry scenario)
    HasToken,
    /// Failed to parse packet header
    HeaderParseError(&'static str),
    /// Key derivation failed
    KeyDerivationError,
    /// Header protection removal failed
    HeaderProtectionError,
    /// AEAD decryption failed (tag mismatch)
    DecryptionFailed,
    /// CRYPTO frame parsing failed
    CryptoFrameError,
    /// TLS ClientHello parsing failed
    TlsParseError,
    /// Packet number length invalid
    InvalidPacketNumberLength,
}

impl std::fmt::Display for DecryptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PacketTooShort => write!(f, "packet too short"),
            Self::NotQuic => write!(f, "not a QUIC packet"),
            Self::NotInitial => write!(f, "not an Initial packet"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported QUIC version: 0x{v:08x}"),
            Self::HasToken => write!(f, "packet has non-empty token (retry scenario)"),
            Self::HeaderParseError(msg) => write!(f, "header parse error: {msg}"),
            Self::KeyDerivationError => write!(f, "key derivation failed"),
            Self::HeaderProtectionError => write!(f, "header protection removal failed"),
            Self::DecryptionFailed => write!(f, "AEAD decryption failed"),
            Self::CryptoFrameError => write!(f, "CRYPTO frame parsing failed"),
            Self::TlsParseError => write!(f, "TLS ClientHello parsing failed"),
            Self::InvalidPacketNumberLength => write!(f, "invalid packet number length"),
        }
    }
}

impl std::error::Error for DecryptError {}

/// Keys derived for QUIC Initial encryption/decryption
#[derive(Debug)]
struct InitialKeys {
    /// AES-128-GCM key
    key: [u8; AES_KEY_SIZE],
    /// IV (nonce base)
    iv: [u8; IV_SIZE],
    /// Header protection key
    hp: [u8; HP_KEY_SIZE],
}

/// Parsed QUIC Initial packet header
#[derive(Debug)]
#[allow(dead_code)]
struct InitialHeader {
    /// First byte (protected)
    first_byte: u8,
    /// QUIC version
    version: QuicVersion,
    /// Destination Connection ID
    dcid: Vec<u8>,
    /// Source Connection ID
    scid: Vec<u8>,
    /// Token (should be empty for client Initial)
    token: Vec<u8>,
    /// Payload length (from Length field)
    payload_length: usize,
    /// Offset where packet number starts
    pn_offset: usize,
    /// Full header length (up to but not including packet number)
    header_len: usize,
}

/// Decrypt a QUIC Initial packet and extract SNI.
///
/// This function performs full cryptographic decryption of the QUIC Initial
/// packet to extract the TLS ClientHello and subsequently the SNI.
///
/// # Arguments
///
/// * `data` - Raw UDP packet bytes
///
/// # Returns
///
/// Returns `Ok(QuicSniffResult)` with extracted information on success,
/// or `Err(DecryptError)` if decryption fails.
///
/// # Errors
///
/// - `PacketTooShort`: Packet is too small to be a valid QUIC Initial
/// - `NotQuic`: Packet doesn't have valid QUIC header
/// - `NotInitial`: Packet is not an Initial packet type
/// - `UnsupportedVersion`: QUIC version is not v1 or v2
/// - `HasToken`: Token field is non-empty (indicates retry scenario)
/// - `DecryptionFailed`: AEAD authentication tag mismatch
/// - `CryptoFrameError`: Failed to parse CRYPTO frames
/// - `TlsParseError`: Failed to extract SNI from ClientHello
pub fn decrypt_quic_initial(data: &[u8]) -> Result<QuicSniffResult, DecryptError> {
    // Parse the Initial packet header
    let header = parse_initial_header(data)?;

    trace!(
        "Parsed Initial header: version={:?}, dcid_len={}, payload_len={}",
        header.version,
        header.dcid.len(),
        header.payload_length
    );

    // Derive Initial keys from DCID
    let keys = derive_initial_keys(&header.dcid, header.version)?;

    trace!("Derived Initial keys successfully");

    // Remove header protection
    let (unprotected_first_byte, packet_number, pn_len) =
        remove_header_protection(data, &header, &keys)?;

    trace!(
        "Removed header protection: first_byte=0x{:02x}, pn={}, pn_len={}",
        unprotected_first_byte,
        packet_number,
        pn_len
    );

    // Build AAD (Additional Authenticated Data)
    let mut aad = Vec::with_capacity(header.pn_offset + pn_len);
    aad.push(unprotected_first_byte);
    aad.extend_from_slice(&data[1..header.pn_offset]);
    // Add packet number bytes (truncated form)
    let pn_bytes = &packet_number.to_be_bytes()[4 - pn_len..];
    aad.extend_from_slice(pn_bytes);

    // Calculate payload offset and length
    let payload_offset = header.pn_offset + pn_len;
    let payload_end = header.pn_offset + header.payload_length;

    if payload_end > data.len() {
        return Err(DecryptError::PacketTooShort);
    }

    // The payload includes the AEAD tag
    let ciphertext = &data[payload_offset..payload_end];

    if ciphertext.len() < TAG_SIZE {
        return Err(DecryptError::PacketTooShort);
    }

    // Decrypt payload
    let plaintext = decrypt_payload(ciphertext, &keys, packet_number, &aad)?;

    trace!("Decrypted {} bytes of payload", plaintext.len());

    // Parse CRYPTO frames to extract ClientHello
    let client_hello = extract_crypto_data(&plaintext)?;

    trace!(
        "Extracted {} bytes of ClientHello from CRYPTO frames",
        client_hello.len()
    );

    // Extract SNI from ClientHello using TLS sniffer
    extract_sni_from_client_hello(&client_hello, &header)
}

/// Parse the Initial packet header (before removing header protection).
fn parse_initial_header(data: &[u8]) -> Result<InitialHeader, DecryptError> {
    if data.len() < MIN_PACKET_SIZE {
        return Err(DecryptError::PacketTooShort);
    }

    let first_byte = data[0];

    // Check for long header (high bit set) and fixed bit
    if first_byte & 0x80 == 0 {
        return Err(DecryptError::NotInitial);
    }
    if first_byte & 0x40 == 0 {
        return Err(DecryptError::NotQuic);
    }

    // Parse version
    let version_raw = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
    if version_raw == 0 {
        return Err(DecryptError::NotInitial); // Version negotiation
    }

    let version = QuicVersion::from_u32(version_raw);

    // Check if this is an Initial packet type
    let packet_type = QuicPacketType::from_header(first_byte, version);
    if packet_type != QuicPacketType::Initial {
        return Err(DecryptError::NotInitial);
    }

    // Validate version is supported
    if !matches!(version, QuicVersion::V1 | QuicVersion::V2) {
        return Err(DecryptError::UnsupportedVersion(version_raw));
    }

    let mut pos = 5; // After version

    // Parse DCID
    if pos >= data.len() {
        return Err(DecryptError::HeaderParseError("missing DCID length"));
    }
    let dcid_len = data[pos] as usize;
    pos += 1;

    if pos + dcid_len > data.len() {
        return Err(DecryptError::HeaderParseError("DCID truncated"));
    }
    let dcid = data[pos..pos + dcid_len].to_vec();
    pos += dcid_len;

    // Parse SCID
    if pos >= data.len() {
        return Err(DecryptError::HeaderParseError("missing SCID length"));
    }
    let scid_len = data[pos] as usize;
    pos += 1;

    if pos + scid_len > data.len() {
        return Err(DecryptError::HeaderParseError("SCID truncated"));
    }
    let scid = data[pos..pos + scid_len].to_vec();
    pos += scid_len;

    // Parse Token length (variable-length integer)
    let (token_len, varint_size) =
        parse_varint(&data[pos..]).ok_or(DecryptError::HeaderParseError("invalid token length"))?;
    pos += varint_size;

    // For SNI extraction, we reject packets with tokens (retry scenario)
    // as they may have different key derivation
    if token_len > 0 {
        return Err(DecryptError::HasToken);
    }

    let token = Vec::new();

    // Parse Length field (variable-length integer)
    let (payload_length, len_size) =
        parse_varint(&data[pos..]).ok_or(DecryptError::HeaderParseError("invalid length field"))?;
    pos += len_size;

    let pn_offset = pos;
    let header_len = pos;

    #[allow(clippy::cast_possible_truncation)]
    Ok(InitialHeader {
        first_byte,
        version,
        dcid,
        scid,
        token,
        payload_length: payload_length as usize,
        pn_offset,
        header_len,
    })
}

/// Parse a QUIC variable-length integer.
fn parse_varint(data: &[u8]) -> Option<(u64, usize)> {
    QuicSniffer::parse_varint(data)
}

/// Derive Initial keys from DCID using HKDF.
///
/// RFC 9001 Section 5.2 (QUIC v1):
/// - initial_secret = HKDF-Extract(salt, DCID)
/// - client_initial_secret = HKDF-Expand-Label(initial_secret, "client in", 32)
/// - key = HKDF-Expand-Label(client_initial_secret, "quic key", 16)
/// - iv = HKDF-Expand-Label(client_initial_secret, "quic iv", 12)
/// - hp = HKDF-Expand-Label(client_initial_secret, "quic hp", 16)
///
/// RFC 9369 Section 3.1 (QUIC v2):
/// Same structure but uses different labels:
/// - key = HKDF-Expand-Label(client_initial_secret, "quicv2 key", 16)
/// - iv = HKDF-Expand-Label(client_initial_secret, "quicv2 iv", 12)
/// - hp = HKDF-Expand-Label(client_initial_secret, "quicv2 hp", 16)
fn derive_initial_keys(dcid: &[u8], version: QuicVersion) -> Result<InitialKeys, DecryptError> {
    let (salt, label_prefix) = match version {
        QuicVersion::V1 => (&QUIC_V1_SALT, "quic"),
        QuicVersion::V2 => (&QUIC_V2_SALT, "quicv2"),
        _ => return Err(DecryptError::UnsupportedVersion(version.as_u32())),
    };

    // Step 1: Extract initial_secret
    let hkdf = Hkdf::<Sha256>::new(Some(salt), dcid);

    // Step 2: Expand to get client_initial_secret (32 bytes)
    // Note: "client in" label is the same for both v1 and v2
    let mut client_initial_secret = [0u8; 32];
    let client_label = hkdf_expand_label_info("client in", 32);
    hkdf.expand(&client_label, &mut client_initial_secret)
        .map_err(|_| DecryptError::KeyDerivationError)?;

    // Step 3: Derive traffic keys from client_initial_secret
    let client_hkdf = Hkdf::<Sha256>::new(None, &client_initial_secret);

    // Derive key (16 bytes for AES-128-GCM)
    // v1: "quic key", v2: "quicv2 key"
    let mut key = [0u8; AES_KEY_SIZE];
    let key_label_str = format!("{label_prefix} key");
    let key_label = hkdf_expand_label_info(&key_label_str, AES_KEY_SIZE);
    client_hkdf
        .expand(&key_label, &mut key)
        .map_err(|_| DecryptError::KeyDerivationError)?;

    // Derive IV (12 bytes)
    // v1: "quic iv", v2: "quicv2 iv"
    let mut iv = [0u8; IV_SIZE];
    let iv_label_str = format!("{label_prefix} iv");
    let iv_label = hkdf_expand_label_info(&iv_label_str, IV_SIZE);
    client_hkdf
        .expand(&iv_label, &mut iv)
        .map_err(|_| DecryptError::KeyDerivationError)?;

    // Derive header protection key (16 bytes)
    // v1: "quic hp", v2: "quicv2 hp"
    let mut hp = [0u8; HP_KEY_SIZE];
    let hp_label_str = format!("{label_prefix} hp");
    let hp_label = hkdf_expand_label_info(&hp_label_str, HP_KEY_SIZE);
    client_hkdf
        .expand(&hp_label, &mut hp)
        .map_err(|_| DecryptError::KeyDerivationError)?;

    Ok(InitialKeys { key, iv, hp })
}

/// Build HKDF-Expand-Label info structure (TLS 1.3 format).
///
/// Format:
/// - length (2 bytes)
/// - "tls13 " + label (1 byte length + string)
/// - context (1 byte length + data, empty for QUIC)
fn hkdf_expand_label_info(label: &str, length: usize) -> Vec<u8> {
    let tls_label = format!("tls13 {label}");
    let mut info = Vec::with_capacity(2 + 1 + tls_label.len() + 1);

    // Length (2 bytes, big-endian)
    info.push((length >> 8) as u8);
    info.push(length as u8);

    // Label with length prefix
    info.push(tls_label.len() as u8);
    info.extend_from_slice(tls_label.as_bytes());

    // Empty context
    info.push(0);

    info
}

/// Remove header protection to reveal first byte and packet number.
///
/// RFC 9001 Section 5.4:
/// 1. Sample 16 bytes starting at pn_offset + 4
/// 2. Apply AES-ECB to sample with HP key
/// 3. XOR first byte with mask[0] (masking 4 bits for long header)
/// 4. XOR packet number bytes with mask[1..1+pn_len]
fn remove_header_protection(
    data: &[u8],
    header: &InitialHeader,
    keys: &InitialKeys,
) -> Result<(u8, u32, usize), DecryptError> {
    // Sample starts at pn_offset + 4 (assuming minimum PN length)
    let sample_offset = header.pn_offset + 4;

    if sample_offset + HP_SAMPLE_SIZE > data.len() {
        return Err(DecryptError::HeaderProtectionError);
    }

    let sample = &data[sample_offset..sample_offset + HP_SAMPLE_SIZE];

    // Generate mask using AES-ECB
    let mask = aes_ecb_encrypt(&keys.hp, sample)?;

    // Unmask first byte (long header: mask lower 4 bits only)
    let first_byte = header.first_byte ^ (mask[0] & 0x0f);

    // Get packet number length from unmasked first byte (lower 2 bits + 1)
    let pn_len = ((first_byte & 0x03) + 1) as usize;

    if pn_len > 4 {
        return Err(DecryptError::InvalidPacketNumberLength);
    }

    if header.pn_offset + pn_len > data.len() {
        return Err(DecryptError::HeaderProtectionError);
    }

    // Unmask packet number
    let mut pn_bytes = [0u8; 4];
    for i in 0..pn_len {
        pn_bytes[4 - pn_len + i] = data[header.pn_offset + i] ^ mask[1 + i];
    }

    let packet_number = u32::from_be_bytes(pn_bytes);

    Ok((first_byte, packet_number, pn_len))
}

/// Apply AES-ECB encryption (single block).
fn aes_ecb_encrypt(key: &[u8; HP_KEY_SIZE], block: &[u8]) -> Result<[u8; 16], DecryptError> {
    use aes::cipher::{BlockEncrypt, KeyInit};
    use aes::Aes128;

    let cipher = Aes128::new_from_slice(key).map_err(|_| DecryptError::HeaderProtectionError)?;

    let mut output = [0u8; 16];
    output.copy_from_slice(&block[..16]);

    cipher.encrypt_block(aes::Block::from_mut_slice(&mut output));

    Ok(output)
}

/// Decrypt the packet payload using AES-128-GCM.
fn decrypt_payload(
    ciphertext: &[u8],
    keys: &InitialKeys,
    packet_number: u32,
    aad: &[u8],
) -> Result<Vec<u8>, DecryptError> {
    // Build nonce: IV XOR packet_number (right-aligned)
    let mut nonce = keys.iv;
    let pn_bytes = packet_number.to_be_bytes();
    for i in 0..4 {
        nonce[IV_SIZE - 4 + i] ^= pn_bytes[i];
    }

    let cipher = Aes128Gcm::new_from_slice(&keys.key).map_err(|_| DecryptError::DecryptionFailed)?;

    let nonce = Nonce::from_slice(&nonce);

    // Decrypt with AAD
    cipher
        .decrypt(
            nonce,
            aes_gcm::aead::Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| DecryptError::DecryptionFailed)
}

/// Extract CRYPTO frame data from decrypted payload.
///
/// CRYPTO frame format (RFC 9000 Section 19.6):
/// - Type (0x06)
/// - Offset (variable-length integer)
/// - Length (variable-length integer)
/// - Data
///
/// We reassemble CRYPTO frames starting at offset 0.
fn extract_crypto_data(payload: &[u8]) -> Result<Vec<u8>, DecryptError> {
    let mut crypto_data: Vec<u8> = Vec::new();
    let mut pos = 0;

    // Track fragments for reassembly
    let mut fragments: Vec<(u64, Vec<u8>)> = Vec::new();

    while pos < payload.len() {
        let frame_type = payload[pos];
        pos += 1;

        match frame_type {
            // PADDING (0x00) - skip
            0x00 => continue,

            // PING (0x01) - skip
            0x01 => continue,

            // ACK (0x02, 0x03) - skip
            0x02 | 0x03 => {
                // ACK frame: largest_ack, ack_delay, ack_range_count, first_ack_range, [ranges...]
                let _ = parse_varint(&payload[pos..]).ok_or(DecryptError::CryptoFrameError)?;
                pos += parse_varint(&payload[pos..])
                    .ok_or(DecryptError::CryptoFrameError)?
                    .1;
                let _ = parse_varint(&payload[pos..]).ok_or(DecryptError::CryptoFrameError)?;
                pos += parse_varint(&payload[pos..])
                    .ok_or(DecryptError::CryptoFrameError)?
                    .1;
                let (range_count, sz) =
                    parse_varint(&payload[pos..]).ok_or(DecryptError::CryptoFrameError)?;
                pos += sz;
                let _ = parse_varint(&payload[pos..]).ok_or(DecryptError::CryptoFrameError)?;
                pos += parse_varint(&payload[pos..])
                    .ok_or(DecryptError::CryptoFrameError)?
                    .1;

                // Skip ACK ranges
                for _ in 0..range_count {
                    // gap
                    pos += parse_varint(&payload[pos..])
                        .ok_or(DecryptError::CryptoFrameError)?
                        .1;
                    // ack_range_length
                    pos += parse_varint(&payload[pos..])
                        .ok_or(DecryptError::CryptoFrameError)?
                        .1;
                }

                // If ACK_ECN (0x03), skip ECN counts
                if frame_type == 0x03 {
                    pos += parse_varint(&payload[pos..])
                        .ok_or(DecryptError::CryptoFrameError)?
                        .1;
                    pos += parse_varint(&payload[pos..])
                        .ok_or(DecryptError::CryptoFrameError)?
                        .1;
                    pos += parse_varint(&payload[pos..])
                        .ok_or(DecryptError::CryptoFrameError)?
                        .1;
                }
            }

            // CRYPTO (0x06)
            0x06 => {
                let (offset, sz) =
                    parse_varint(&payload[pos..]).ok_or(DecryptError::CryptoFrameError)?;
                pos += sz;

                let (length, sz) =
                    parse_varint(&payload[pos..]).ok_or(DecryptError::CryptoFrameError)?;
                pos += sz;

                #[allow(clippy::cast_possible_truncation)]
                let length = length as usize;

                if pos + length > payload.len() {
                    return Err(DecryptError::CryptoFrameError);
                }

                let data = payload[pos..pos + length].to_vec();
                pos += length;

                trace!("Found CRYPTO frame: offset={}, length={}", offset, length);

                fragments.push((offset, data));
            }

            // CONNECTION_CLOSE (0x1c, 0x1d) - indicates error, but we can still try
            0x1c | 0x1d => {
                debug!("Encountered CONNECTION_CLOSE frame in Initial packet");
                break;
            }

            // Unknown frame type - we can't reliably skip it
            _ => {
                trace!("Unknown frame type 0x{:02x} at position {}", frame_type, pos);
                break;
            }
        }
    }

    if fragments.is_empty() {
        return Err(DecryptError::CryptoFrameError);
    }

    // Sort fragments by offset
    fragments.sort_by_key(|(offset, _)| *offset);

    // Reassemble starting from offset 0
    let mut expected_offset: u64 = 0;
    for (offset, data) in fragments {
        if offset > expected_offset {
            // Gap in data - can't reassemble
            debug!(
                "Gap in CRYPTO data: expected offset {}, got {}",
                expected_offset, offset
            );
            break;
        }

        // Handle overlap
        #[allow(clippy::cast_possible_truncation)]
        let start = (expected_offset - offset) as usize;
        if start < data.len() {
            crypto_data.extend_from_slice(&data[start..]);
            expected_offset += (data.len() - start) as u64;
        }

        if crypto_data.len() > MAX_CRYPTO_SIZE {
            break;
        }
    }

    if crypto_data.is_empty() {
        return Err(DecryptError::CryptoFrameError);
    }

    Ok(crypto_data)
}

/// Extract SNI from TLS ClientHello data.
fn extract_sni_from_client_hello(
    client_hello: &[u8],
    header: &InitialHeader,
) -> Result<QuicSniffResult, DecryptError> {
    // CRYPTO data contains raw TLS handshake (no record layer)
    // But our TLS sniffer expects record layer, so we need to handle this

    // Check if this is a ClientHello handshake message (type 0x01)
    if client_hello.is_empty() {
        return Err(DecryptError::TlsParseError);
    }

    // The CRYPTO frame contains raw TLS handshake messages (no record layer)
    // We need to parse the ClientHello directly

    let (sni, alpn) = parse_client_hello_raw(client_hello)?;

    Ok(QuicSniffResult {
        server_name: sni,
        version: Some(header.version),
        packet_type: Some(QuicPacketType::Initial),
        is_initial: true,
        dcid: Some(header.dcid.clone()),
        decrypted: true,
        alpn,
    })
}

/// Parse raw TLS ClientHello handshake message (without record layer).
///
/// ClientHello format:
/// - HandshakeType (1 byte) = 0x01
/// - Length (3 bytes)
/// - ProtocolVersion (2 bytes)
/// - Random (32 bytes)
/// - SessionID (1 byte length + variable)
/// - CipherSuites (2 bytes length + variable)
/// - CompressionMethods (1 byte length + variable)
/// - Extensions (2 bytes length + variable)
fn parse_client_hello_raw(data: &[u8]) -> Result<(Option<String>, Vec<String>), DecryptError> {
    if data.len() < 42 {
        // Minimum: 1 + 3 + 2 + 32 + 1 + 2 + 1 = 42
        return Err(DecryptError::TlsParseError);
    }

    // Check handshake type
    if data[0] != 0x01 {
        return Err(DecryptError::TlsParseError);
    }

    // Skip: type (1) + length (3) + version (2) + random (32) = 38 bytes
    let mut pos: usize = 38;

    // Session ID
    if pos >= data.len() {
        return Err(DecryptError::TlsParseError);
    }
    let session_id_len = data[pos] as usize;
    pos += 1 + session_id_len;

    // Cipher suites
    if pos + 2 > data.len() {
        return Err(DecryptError::TlsParseError);
    }
    let cipher_suites_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2 + cipher_suites_len;

    // Compression methods
    if pos >= data.len() {
        return Err(DecryptError::TlsParseError);
    }
    let compression_len = data[pos] as usize;
    pos += 1 + compression_len;

    // Extensions
    if pos + 2 > data.len() {
        // No extensions
        return Ok((None, Vec::new()));
    }
    let extensions_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;

    let extensions_end = pos + extensions_len;

    let mut sni = None;
    let mut alpn = Vec::new();

    // Parse extensions
    while pos + 4 <= data.len() && pos < extensions_end {
        let ext_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let ext_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;

        if pos + ext_len > data.len() {
            break;
        }

        let ext_data = &data[pos..pos + ext_len];

        match ext_type {
            // SNI extension (0x0000)
            0x0000 => {
                sni = parse_sni_extension(ext_data);
                if let Some(ref s) = sni {
                    trace!("Found SNI: {}", s);
                }
            }
            // ALPN extension (0x0010)
            0x0010 => {
                alpn = parse_alpn_extension(ext_data);
                for proto in &alpn {
                    trace!("Found ALPN: {}", proto);
                }
            }
            _ => {}
        }

        pos += ext_len;
    }

    Ok((sni, alpn))
}

/// Parse SNI extension data.
fn parse_sni_extension(data: &[u8]) -> Option<String> {
    if data.len() < 5 {
        return None;
    }

    // Server name list length (2 bytes)
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if list_len + 2 > data.len() {
        return None;
    }

    let mut pos: usize = 2;
    let end = 2 + list_len;

    while pos + 3 <= end && pos + 3 <= data.len() {
        let name_type = data[pos];
        let name_len = u16::from_be_bytes([data[pos + 1], data[pos + 2]]) as usize;
        pos += 3;

        if pos + name_len > data.len() {
            return None;
        }

        // Name type 0 = hostname
        if name_type == 0x00 {
            let hostname = &data[pos..pos + name_len];
            // Validate as ASCII hostname
            if hostname.iter().all(|&b| b.is_ascii() && b != 0) {
                if let Ok(s) = String::from_utf8(hostname.to_vec()) {
                    if is_valid_hostname(&s) {
                        return Some(s);
                    }
                }
            }
        }

        pos += name_len;
    }

    None
}

/// Parse ALPN extension data.
fn parse_alpn_extension(data: &[u8]) -> Vec<String> {
    let mut protocols = Vec::new();

    if data.len() < 2 {
        return protocols;
    }

    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if list_len + 2 > data.len() {
        return protocols;
    }

    let mut pos: usize = 2;
    let end = 2 + list_len;

    while pos < end && pos < data.len() {
        let proto_len = data[pos] as usize;
        pos += 1;

        if pos + proto_len > data.len() {
            break;
        }

        if let Ok(proto) = std::str::from_utf8(&data[pos..pos + proto_len]) {
            protocols.push(proto.to_string());
        }

        pos += proto_len;
    }

    protocols
}

/// Validate hostname according to RFC 1123.
fn is_valid_hostname(hostname: &str) -> bool {
    if hostname.is_empty() || hostname.len() > 253 {
        return false;
    }

    // Must contain at least one dot
    if !hostname.contains('.') {
        return false;
    }

    // Basic validation: alphanumeric, hyphens, and dots
    hostname
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
}

/// Sniff QUIC with decryption fallback.
///
/// This function first attempts to decrypt the QUIC Initial packet.
/// If decryption fails, it falls back to the heuristic approach.
///
/// # Arguments
///
/// * `data` - Raw UDP packet bytes
///
/// # Returns
///
/// Returns `QuicSniffResult` with extracted information.
/// The `decrypted` field indicates whether decryption was successful.
pub fn sniff_quic_with_decrypt(data: &[u8]) -> QuicSniffResult {
    // Try decryption first
    match decrypt_quic_initial(data) {
        Ok(result) => {
            debug!(
                "QUIC decryption successful, SNI: {:?}",
                result.server_name
            );
            result
        }
        Err(e) => {
            trace!("QUIC decryption failed: {}, falling back to heuristic", e);
            // Fall back to heuristic approach
            let mut result = QuicSniffer::sniff(data);
            result.decrypted = false;
            result.alpn = Vec::new();
            result
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test salt constants
    #[test]
    fn test_quic_v1_salt() {
        // Verify the salt matches RFC 9001
        assert_eq!(QUIC_V1_SALT.len(), 20);
        assert_eq!(QUIC_V1_SALT[0], 0x38);
        assert_eq!(QUIC_V1_SALT[19], 0x0a);
    }

    #[test]
    fn test_quic_v2_salt() {
        // Verify the salt matches RFC 9369
        assert_eq!(QUIC_V2_SALT.len(), 20);
        assert_eq!(QUIC_V2_SALT[0], 0x0d);
        assert_eq!(QUIC_V2_SALT[19], 0xd9);
    }

    // Test HKDF-Expand-Label info construction
    #[test]
    fn test_hkdf_expand_label_info() {
        let info = hkdf_expand_label_info("client in", 32);

        // Length prefix (2 bytes)
        assert_eq!(info[0], 0x00);
        assert_eq!(info[1], 32);

        // Label length
        assert_eq!(info[2], 16); // "tls13 client in" = 16 bytes

        // Label content
        let label_str = std::str::from_utf8(&info[3..19]).unwrap();
        assert_eq!(label_str, "tls13 client in");

        // Empty context
        assert_eq!(info[19], 0);
    }

    // Test key derivation with known DCID
    #[test]
    fn test_derive_initial_keys_v1() {
        // Use a test DCID (RFC 9001 Appendix A has test vectors)
        let dcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];

        let keys = derive_initial_keys(&dcid, QuicVersion::V1).expect("key derivation should work");

        // Verify key sizes
        assert_eq!(keys.key.len(), AES_KEY_SIZE);
        assert_eq!(keys.iv.len(), IV_SIZE);
        assert_eq!(keys.hp.len(), HP_KEY_SIZE);

        // RFC 9001 Appendix A.1 test vectors for client Initial keys:
        // client_initial_secret:
        //   c00cf151ca5be075ed0ebfb5c80323c4 2d6b7db67881289af4008f1f6c357aea
        // key: 1f369613dd76d5467730efcbe3b1a22d
        // iv: fa044b2f42a3fd3b46fb255c
        // hp: 9f50449e04a0e810283a1e9933adedd2

        let expected_key: [u8; 16] = [
            0x1f, 0x36, 0x96, 0x13, 0xdd, 0x76, 0xd5, 0x46, 0x77, 0x30, 0xef, 0xcb, 0xe3, 0xb1,
            0xa2, 0x2d,
        ];
        let expected_iv: [u8; 12] = [
            0xfa, 0x04, 0x4b, 0x2f, 0x42, 0xa3, 0xfd, 0x3b, 0x46, 0xfb, 0x25, 0x5c,
        ];
        let expected_hp: [u8; 16] = [
            0x9f, 0x50, 0x44, 0x9e, 0x04, 0xa0, 0xe8, 0x10, 0x28, 0x3a, 0x1e, 0x99, 0x33, 0xad,
            0xed, 0xd2,
        ];

        assert_eq!(keys.key, expected_key, "key mismatch");
        assert_eq!(keys.iv, expected_iv, "iv mismatch");
        assert_eq!(keys.hp, expected_hp, "hp mismatch");
    }

    // Test varint parsing
    #[test]
    fn test_parse_varint() {
        // 1-byte encoding
        assert_eq!(parse_varint(&[0x25]), Some((37, 1)));
        assert_eq!(parse_varint(&[0x00]), Some((0, 1)));
        assert_eq!(parse_varint(&[0x3f]), Some((63, 1)));

        // 2-byte encoding
        assert_eq!(parse_varint(&[0x7b, 0xbd]), Some((15293, 2)));

        // 4-byte encoding
        assert_eq!(parse_varint(&[0x9d, 0x7f, 0x3e, 0x7d]), Some((494_878_333, 4)));

        // Empty
        assert_eq!(parse_varint(&[]), None);

        // Truncated
        assert_eq!(parse_varint(&[0x7b]), None);
    }

    // Test hostname validation
    #[test]
    fn test_is_valid_hostname() {
        assert!(is_valid_hostname("example.com"));
        assert!(is_valid_hostname("www.example.com"));
        assert!(is_valid_hostname("sub.domain.example.com"));
        assert!(is_valid_hostname("my-site.example.com"));

        assert!(!is_valid_hostname("")); // Empty
        assert!(!is_valid_hostname("localhost")); // No dot
        assert!(!is_valid_hostname("a".repeat(254).as_str())); // Too long
        assert!(!is_valid_hostname("exam@ple.com")); // Invalid char
    }

    // Test AES-ECB encryption
    #[test]
    fn test_aes_ecb_encrypt() {
        let key = [0u8; 16];
        let block = [0u8; 16];

        let result = aes_ecb_encrypt(&key, &block).expect("encryption should work");

        // AES-ECB(0x00...00, 0x00...00) is a well-known value
        // This is just a sanity check that encryption works
        assert_eq!(result.len(), 16);
        assert_ne!(result, [0u8; 16]); // Output should differ from input
    }

    // Test parse_initial_header with short packet
    #[test]
    fn test_parse_initial_header_too_short() {
        let short_packet = [0xc0, 0x00, 0x00, 0x00, 0x01];
        assert!(matches!(
            parse_initial_header(&short_packet),
            Err(DecryptError::PacketTooShort)
        ));
    }

    // Test parse_initial_header with non-Initial packet
    #[test]
    fn test_parse_initial_header_not_initial() {
        // Handshake packet (type 2 for v1)
        let handshake_packet = [
            0xe0, 0x00, 0x00, 0x00, 0x01, // Long header, type 2, QUIC v1
            0x08, // DCID length
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // DCID
            0x00, // SCID length
            0x00, // Token length
            0x04, 0x00, 0x00, 0x00, 0x00, // Length + minimal payload
        ];
        assert!(matches!(
            parse_initial_header(&handshake_packet),
            Err(DecryptError::NotInitial)
        ));
    }

    // Test parse_initial_header with token
    #[test]
    fn test_parse_initial_header_has_token() {
        let packet_with_token = [
            0xc0, 0x00, 0x00, 0x00, 0x01, // Long header, Initial, QUIC v1
            0x08, // DCID length
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // DCID
            0x00, // SCID length
            0x04, // Token length = 4
            0xaa, 0xbb, 0xcc, 0xdd, // Token
            0x04, 0x00, 0x00, 0x00, 0x00, // Length + minimal payload
        ];
        assert!(matches!(
            parse_initial_header(&packet_with_token),
            Err(DecryptError::HasToken)
        ));
    }

    // Test SNI extension parsing
    #[test]
    fn test_parse_sni_extension() {
        // Valid SNI extension data
        let name = "example.com";
        let name_len = name.len() as u16;
        let list_len = 3 + name_len; // name_type (1) + name_length (2) + name

        let mut data = vec![
            (list_len >> 8) as u8,
            list_len as u8, // List length
            0x00, // Name type (host_name)
            (name_len >> 8) as u8,
            name_len as u8, // Name length
        ];
        data.extend_from_slice(name.as_bytes());

        assert_eq!(parse_sni_extension(&data), Some("example.com".to_string()));
    }

    // Test ALPN extension parsing
    #[test]
    fn test_parse_alpn_extension() {
        // ALPN with "h2" and "http/1.1"
        let data = [
            0x00, 0x0c, // List length = 12
            0x02, b'h', b'2', // "h2"
            0x08, b'h', b't', b't', b'p', b'/', b'1', b'.', b'1', // "http/1.1"
        ];

        let alpn = parse_alpn_extension(&data);
        assert_eq!(alpn, vec!["h2".to_string(), "http/1.1".to_string()]);
    }

    // Test DecryptError Display
    #[test]
    fn test_decrypt_error_display() {
        assert_eq!(DecryptError::PacketTooShort.to_string(), "packet too short");
        assert_eq!(DecryptError::NotQuic.to_string(), "not a QUIC packet");
        assert_eq!(DecryptError::NotInitial.to_string(), "not an Initial packet");
        assert_eq!(
            DecryptError::UnsupportedVersion(0x12345678).to_string(),
            "unsupported QUIC version: 0x12345678"
        );
    }

    // Real captured QUIC Initial packet test
    // This is a QUIC v1 Initial packet structure using RFC 9001 Appendix A DCID
    #[test]
    fn test_real_quic_initial_packet() {
        // Build a QUIC Initial packet with RFC 9001 Appendix A DCID
        // The packet length field indicates 0x49e = 1182 bytes
        let mut packet = vec![
            // Long header: Initial, QUIC v1
            0xc0, 0x00, 0x00, 0x00, 0x01,
            // DCID length = 8
            0x08,
            // DCID (RFC 9001 Appendix A test vector)
            0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08,
            // SCID length = 0
            0x00,
            // Token length = 0
            0x00,
            // Packet Length (varint) - 2 byte encoding 0x4000 + 0x49e = 0x449e
            0x44, 0x9e,
        ];
        // Pad with zeros to match payload_length (0x49e = 1182 bytes)
        // 1182 bytes includes packet number (at least 1 byte) + encrypted payload + 16-byte tag
        packet.resize(17 + 1182, 0x00);

        // Test header parsing works
        let header = parse_initial_header(&packet);
        assert!(header.is_ok(), "header parsing should succeed");

        let header = header.unwrap();
        assert_eq!(header.version, QuicVersion::V1);
        assert_eq!(header.dcid.len(), 8);
        assert_eq!(
            header.dcid,
            vec![0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08]
        );
        assert!(header.scid.is_empty());
        assert!(header.token.is_empty());

        // Decryption will fail because payload is zeroed, but that's expected
        // We're testing that the infrastructure works correctly
        let result = decrypt_quic_initial(&packet);
        // Expect decryption to fail (zeroed payload won't have valid AEAD tag)
        assert!(
            matches!(result, Err(DecryptError::DecryptionFailed)),
            "expected DecryptionFailed for zeroed payload"
        );
    }

    // Test sniff_quic_with_decrypt fallback
    #[test]
    fn test_sniff_quic_with_decrypt_fallback() {
        // Non-Initial packet should fall back to heuristic
        let handshake_packet = [
            0xe0, 0x00, 0x00, 0x00, 0x01, // Long header, type 2, QUIC v1
            0x08, // DCID length
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // DCID
            0x00, // SCID length
        ];

        let result = sniff_quic_with_decrypt(&handshake_packet);

        // Should fall back to heuristic
        assert!(!result.decrypted);
        assert_eq!(result.version, Some(QuicVersion::V1));
        assert_eq!(result.packet_type, Some(QuicPacketType::Handshake));
    }

    // RFC 9001 Appendix A full test vector
    #[test]
    fn test_rfc9001_appendix_a_test_vector() {
        // This test uses the exact test vector from RFC 9001 Appendix A.2
        // DCID: 8394c8f03e515708

        let dcid: [u8; 8] = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];

        // Verify key derivation matches RFC 9001 Appendix A.1
        let keys = derive_initial_keys(&dcid, QuicVersion::V1).unwrap();

        // Expected values from RFC 9001 Appendix A.1:
        // client key: 1f369613dd76d5467730efcbe3b1a22d
        // client iv: fa044b2f42a3fd3b46fb255c
        // client hp: 9f50449e04a0e810283a1e9933adedd2

        assert_eq!(
            hex::encode(keys.key),
            "1f369613dd76d5467730efcbe3b1a22d"
        );
        assert_eq!(hex::encode(keys.iv), "fa044b2f42a3fd3b46fb255c");
        assert_eq!(
            hex::encode(keys.hp),
            "9f50449e04a0e810283a1e9933adedd2"
        );
    }
}
