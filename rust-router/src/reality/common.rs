//! TLS 1.3 constants and shared utilities for REALITY protocol
//!
//! This module defines TLS constants, record size limits, and utility functions
//! used throughout the REALITY implementation.

use std::io::{self, Error, ErrorKind};

// =============================================================================
// TLS ContentType values (RFC 8446 Section 5.1)
// =============================================================================

/// TLS ContentType: ChangeCipherSpec (dummy in TLS 1.3, kept for compatibility)
pub const CONTENT_TYPE_CHANGE_CIPHER_SPEC: u8 = 0x14;

/// TLS ContentType: Alert
pub const CONTENT_TYPE_ALERT: u8 = 0x15;

/// TLS ContentType: Handshake
pub const CONTENT_TYPE_HANDSHAKE: u8 = 0x16;

/// TLS ContentType: Application Data
pub const CONTENT_TYPE_APPLICATION_DATA: u8 = 0x17;

// =============================================================================
// TLS Alert constants (RFC 8446 Section 6)
// =============================================================================

/// TLS alert level: Warning
pub const ALERT_LEVEL_WARNING: u8 = 0x01;

/// TLS alert level: Fatal
pub const ALERT_LEVEL_FATAL: u8 = 0x02;

/// TLS alert description: close_notify (0)
pub const ALERT_DESC_CLOSE_NOTIFY: u8 = 0x00;

/// TLS alert description: unexpected_message (10)
pub const ALERT_DESC_UNEXPECTED_MESSAGE: u8 = 0x0a;

/// TLS alert description: bad_record_mac (20)
pub const ALERT_DESC_BAD_RECORD_MAC: u8 = 0x14;

/// TLS alert description: record_overflow (22)
pub const ALERT_DESC_RECORD_OVERFLOW: u8 = 0x16;

/// TLS alert description: handshake_failure (40)
pub const ALERT_DESC_HANDSHAKE_FAILURE: u8 = 0x28;

/// TLS alert description: illegal_parameter (47)
pub const ALERT_DESC_ILLEGAL_PARAMETER: u8 = 0x2f;

/// TLS alert description: decode_error (50)
pub const ALERT_DESC_DECODE_ERROR: u8 = 0x32;

/// TLS alert description: decrypt_error (51)
pub const ALERT_DESC_DECRYPT_ERROR: u8 = 0x33;

// =============================================================================
// TLS Version constants
// =============================================================================

/// TLS 1.2 version major byte (0x03) - used in record layer for TLS 1.3 compatibility
pub const VERSION_TLS_1_2_MAJOR: u8 = 0x03;

/// TLS 1.2 version minor byte (0x03)
pub const VERSION_TLS_1_2_MINOR: u8 = 0x03;

/// TLS 1.3 version bytes for supported_versions extension
pub const VERSION_TLS_1_3: [u8; 2] = [0x03, 0x04];

// =============================================================================
// TLS 1.3 Handshake message types (RFC 8446 Section 4)
// =============================================================================

/// Handshake type: ClientHello (1)
pub const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 1;

/// Handshake type: ServerHello (2)
pub const HANDSHAKE_TYPE_SERVER_HELLO: u8 = 2;

/// Handshake type: EncryptedExtensions (8)
pub const HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS: u8 = 8;

/// Handshake type: Certificate (11)
pub const HANDSHAKE_TYPE_CERTIFICATE: u8 = 11;

/// Handshake type: CertificateVerify (15)
pub const HANDSHAKE_TYPE_CERTIFICATE_VERIFY: u8 = 15;

/// Handshake type: Finished (20)
pub const HANDSHAKE_TYPE_FINISHED: u8 = 20;

// =============================================================================
// TLS 1.3 Record size limits (RFC 8446 Section 5.1)
// =============================================================================

/// Maximum TLS 1.3 plaintext payload size per record (2^14 = 16,384 bytes)
///
/// RFC 8446 Section 5.1: "The record layer fragments information blocks into
/// TLSPlaintext records carrying data in chunks of 2^14 bytes or less."
pub const MAX_TLS_PLAINTEXT_LEN: usize = 16384;

/// Maximum TLS 1.3 ciphertext payload size (16,640 bytes)
///
/// This includes:
/// - Plaintext (up to 16,384 bytes)
/// - Content type byte (1 byte)
/// - AEAD tag (16 bytes for AES-GCM)
/// - Optional padding (up to 239 bytes)
///
/// TLS 1.3 limit: 16,384 + 256 = 16,640 bytes
/// (TLS 1.2 allowed 16,384 + 2,048 = 18,432, but TLS 1.3 is stricter)
pub const MAX_TLS_CIPHERTEXT_LEN: usize = MAX_TLS_PLAINTEXT_LEN + 256;

/// TLS record header size: ContentType (1) + ProtocolVersion (2) + Length (2)
pub const TLS_RECORD_HEADER_SIZE: usize = 5;

/// Maximum complete TLS record size (header + ciphertext)
pub const TLS_MAX_RECORD_SIZE: usize = TLS_RECORD_HEADER_SIZE + MAX_TLS_CIPHERTEXT_LEN;

/// AEAD tag size for AES-GCM and ChaCha20-Poly1305 (16 bytes)
pub const AEAD_TAG_SIZE: usize = 16;

/// Nonce/IV size for TLS 1.3 AEAD (12 bytes)
pub const NONCE_SIZE: usize = 12;

// =============================================================================
// Buffer capacity constants
// =============================================================================

/// Buffer capacity for incoming ciphertext (2x max record for safety)
pub const CIPHERTEXT_READ_BUF_CAPACITY: usize = TLS_MAX_RECORD_SIZE * 2;

/// Buffer capacity for decrypted plaintext
pub const PLAINTEXT_READ_BUF_CAPACITY: usize = TLS_MAX_RECORD_SIZE * 2;

/// Buffer capacity for outgoing data (matches rustls DEFAULT_BUFFER_LIMIT)
pub const OUTGOING_BUFFER_LIMIT: usize = 64 * 1024;

// =============================================================================
// X25519 key sizes
// =============================================================================

/// X25519 private key size (32 bytes)
pub const X25519_PRIVATE_KEY_SIZE: usize = 32;

/// X25519 public key size (32 bytes)
pub const X25519_PUBLIC_KEY_SIZE: usize = 32;

/// X25519 shared secret size (32 bytes)
pub const X25519_SHARED_SECRET_SIZE: usize = 32;

// =============================================================================
// REALITY protocol constants
// =============================================================================

/// REALITY authentication info string for HKDF
pub const REALITY_AUTH_INFO: &[u8] = b"REALITY";

/// REALITY short ID size (8 bytes)
pub const REALITY_SHORT_ID_SIZE: usize = 8;

/// REALITY SessionId plaintext size (first 16 bytes)
pub const REALITY_SESSION_ID_PLAINTEXT_SIZE: usize = 16;

/// REALITY SessionId total size (32 bytes: 16 plaintext + 16 GCM tag)
pub const REALITY_SESSION_ID_SIZE: usize = 32;

/// REALITY authentication key size (32 bytes, AES-256)
pub const REALITY_AUTH_KEY_SIZE: usize = 32;

/// REALITY salt size (20 bytes, from ClientHello.Random[0..20])
pub const REALITY_SALT_SIZE: usize = 20;

/// REALITY nonce size (12 bytes, from ClientHello.Random[20..32])
pub const REALITY_NONCE_SIZE: usize = 12;

/// Default maximum timestamp difference for REALITY (60 seconds in milliseconds)
pub const REALITY_DEFAULT_MAX_TIME_DIFF_MS: u64 = 60_000;

// =============================================================================
// Content type handling
// =============================================================================

/// Strip TLS 1.3 content type trailer from decrypted plaintext slice.
///
/// TLS 1.3 format: content || type_byte
/// Returns (content_type, valid_content_length) without modifying the slice.
///
/// This is the zero-allocation version for use with in-place decryption.
///
/// # Arguments
/// * `plaintext` - Decrypted plaintext including content type trailer
///
/// # Returns
/// * `Ok((content_type, content_length))` - Content type and length of actual content
/// * `Err` - If plaintext is empty or has invalid content type
#[inline]
pub fn strip_content_type_slice(plaintext: &[u8]) -> io::Result<(u8, usize)> {
    if plaintext.is_empty() {
        return Err(Error::new(ErrorKind::InvalidData, "Empty plaintext"));
    }

    // Content type is the last byte (no padding in our implementation)
    let content_type = plaintext[plaintext.len() - 1];

    if content_type != CONTENT_TYPE_HANDSHAKE
        && content_type != CONTENT_TYPE_APPLICATION_DATA
        && content_type != CONTENT_TYPE_ALERT
    {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("Invalid content type: 0x{:02x}", content_type),
        ));
    }

    Ok((content_type, plaintext.len() - 1))
}

/// Strip TLS 1.3 content type trailer and optional padding from decrypted plaintext.
///
/// TLS 1.3 format: content || type_byte || padding_zeros
/// Returns the actual content type and modifies plaintext to contain only content.
///
/// Use this for messages from external TLS implementations (e.g., sing-box) that
/// may add optional padding per RFC 8446 Section 5.4.
///
/// # Arguments
/// * `plaintext` - Decrypted plaintext (will be modified in place)
///
/// # Returns
/// * `Ok(content_type)` - The actual content type
/// * `Err` - If plaintext is invalid
pub fn strip_content_type_with_padding(plaintext: &mut Vec<u8>) -> io::Result<u8> {
    if plaintext.is_empty() {
        return Err(Error::new(ErrorKind::InvalidData, "Empty plaintext"));
    }

    // Remove trailing zeros (padding) per RFC 8446 Section 5.4
    while !plaintext.is_empty() && *plaintext.last().unwrap() == 0 {
        plaintext.pop();
    }

    if plaintext.is_empty() {
        return Err(Error::new(ErrorKind::InvalidData, "Plaintext is all zeros"));
    }

    let content_type = plaintext.pop().unwrap();

    if content_type != CONTENT_TYPE_HANDSHAKE
        && content_type != CONTENT_TYPE_APPLICATION_DATA
        && content_type != CONTENT_TYPE_ALERT
    {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("Invalid content type: 0x{:02x}", content_type),
        ));
    }

    Ok(content_type)
}

/// Strip content type from plaintext Vec (for tests and non-performance-critical code)
#[cfg(test)]
pub fn strip_content_type(plaintext: &mut Vec<u8>) -> io::Result<u8> {
    let (content_type, valid_len) = strip_content_type_slice(plaintext)?;
    plaintext.truncate(valid_len);
    Ok(content_type)
}

// =============================================================================
// Utility functions
// =============================================================================

/// Build TLS record header bytes
///
/// # Arguments
/// * `content_type` - TLS content type (e.g., APPLICATION_DATA)
/// * `length` - Length of the record payload
///
/// # Returns
/// 5-byte TLS record header
#[inline]
pub fn build_record_header(content_type: u8, length: u16) -> [u8; TLS_RECORD_HEADER_SIZE] {
    [
        content_type,
        VERSION_TLS_1_2_MAJOR,
        VERSION_TLS_1_2_MINOR,
        (length >> 8) as u8,
        (length & 0xff) as u8,
    ]
}

/// Parse TLS record header
///
/// # Arguments
/// * `header` - 5-byte TLS record header
///
/// # Returns
/// * `Ok((content_type, version, length))` - Parsed header fields
/// * `Err` - If header is invalid
#[inline]
pub fn parse_record_header(header: &[u8]) -> io::Result<(u8, u16, u16)> {
    if header.len() < TLS_RECORD_HEADER_SIZE {
        return Err(Error::new(ErrorKind::InvalidData, "Header too short"));
    }

    let content_type = header[0];
    let version = u16::from_be_bytes([header[1], header[2]]);
    let length = u16::from_be_bytes([header[3], header[4]]);

    // Validate length doesn't exceed maximum
    if length as usize > MAX_TLS_CIPHERTEXT_LEN {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!(
                "Record length {} exceeds maximum {}",
                length, MAX_TLS_CIPHERTEXT_LEN
            ),
        ));
    }

    Ok((content_type, version, length))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_content_type_app_data() {
        let mut plaintext = vec![0x01, 0x02, 0x03, CONTENT_TYPE_APPLICATION_DATA];
        let ct = strip_content_type(&mut plaintext).unwrap();
        assert_eq!(ct, CONTENT_TYPE_APPLICATION_DATA);
        assert_eq!(plaintext, vec![0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_strip_content_type_handshake() {
        let mut plaintext = vec![0xAA, 0xBB, CONTENT_TYPE_HANDSHAKE];
        let ct = strip_content_type(&mut plaintext).unwrap();
        assert_eq!(ct, CONTENT_TYPE_HANDSHAKE);
        assert_eq!(plaintext, vec![0xAA, 0xBB]);
    }

    #[test]
    fn test_strip_content_type_alert() {
        let mut plaintext = vec![0x01, 0x00, CONTENT_TYPE_ALERT];
        let ct = strip_content_type(&mut plaintext).unwrap();
        assert_eq!(ct, CONTENT_TYPE_ALERT);
        assert_eq!(plaintext, vec![0x01, 0x00]);
    }

    #[test]
    fn test_strip_content_type_preserves_zeros() {
        // Trailing zeros in data should be preserved (not treated as padding)
        let mut plaintext = vec![0x01, 0x00, 0x00, CONTENT_TYPE_APPLICATION_DATA];
        let ct = strip_content_type(&mut plaintext).unwrap();
        assert_eq!(ct, CONTENT_TYPE_APPLICATION_DATA);
        assert_eq!(plaintext, vec![0x01, 0x00, 0x00]);
    }

    #[test]
    fn test_strip_content_type_empty() {
        let mut plaintext = Vec::new();
        assert!(strip_content_type(&mut plaintext).is_err());
    }

    #[test]
    fn test_strip_content_type_invalid() {
        let mut plaintext = vec![0x01, 0xFF]; // 0xFF is invalid
        assert!(strip_content_type(&mut plaintext).is_err());
    }

    #[test]
    fn test_strip_with_padding_no_padding() {
        let mut plaintext = vec![0x01, 0x02, CONTENT_TYPE_APPLICATION_DATA];
        let ct = strip_content_type_with_padding(&mut plaintext).unwrap();
        assert_eq!(ct, CONTENT_TYPE_APPLICATION_DATA);
        assert_eq!(plaintext, vec![0x01, 0x02]);
    }

    #[test]
    fn test_strip_with_padding_strips_zeros() {
        // TLS 1.3 format: content || type || padding
        let mut plaintext = vec![0x01, 0x02, CONTENT_TYPE_HANDSHAKE, 0x00, 0x00, 0x00];
        let ct = strip_content_type_with_padding(&mut plaintext).unwrap();
        assert_eq!(ct, CONTENT_TYPE_HANDSHAKE);
        assert_eq!(plaintext, vec![0x01, 0x02]);
    }

    #[test]
    fn test_strip_with_padding_empty() {
        let mut plaintext = Vec::new();
        assert!(strip_content_type_with_padding(&mut plaintext).is_err());
    }

    #[test]
    fn test_strip_with_padding_all_zeros() {
        let mut plaintext = vec![0x00, 0x00, 0x00];
        assert!(strip_content_type_with_padding(&mut plaintext).is_err());
    }

    #[test]
    fn test_build_record_header() {
        let header = build_record_header(CONTENT_TYPE_APPLICATION_DATA, 0x1234);
        assert_eq!(header[0], CONTENT_TYPE_APPLICATION_DATA);
        assert_eq!(header[1], VERSION_TLS_1_2_MAJOR);
        assert_eq!(header[2], VERSION_TLS_1_2_MINOR);
        assert_eq!(header[3], 0x12);
        assert_eq!(header[4], 0x34);
    }

    #[test]
    fn test_parse_record_header() {
        let header = [CONTENT_TYPE_HANDSHAKE, 0x03, 0x03, 0x01, 0x00];
        let (ct, ver, len) = parse_record_header(&header).unwrap();
        assert_eq!(ct, CONTENT_TYPE_HANDSHAKE);
        assert_eq!(ver, 0x0303);
        assert_eq!(len, 256);
    }

    #[test]
    fn test_parse_record_header_too_short() {
        let header = [0x17, 0x03, 0x03];
        assert!(parse_record_header(&header).is_err());
    }

    #[test]
    fn test_constants() {
        // Verify size relationships
        assert!(MAX_TLS_CIPHERTEXT_LEN > MAX_TLS_PLAINTEXT_LEN);
        assert_eq!(TLS_MAX_RECORD_SIZE, TLS_RECORD_HEADER_SIZE + MAX_TLS_CIPHERTEXT_LEN);
        assert_eq!(REALITY_SALT_SIZE + REALITY_NONCE_SIZE, 32); // From ClientHello.Random
    }
}
