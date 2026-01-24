//! TLS 1.3 Message Construction and Parsing
//!
//! This module provides functions for constructing and parsing TLS 1.3 handshake messages
//! as required by the REALITY protocol.

use crate::reality::common::{
    CONTENT_TYPE_HANDSHAKE, HANDSHAKE_TYPE_CERTIFICATE, HANDSHAKE_TYPE_CERTIFICATE_VERIFY,
    HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS, HANDSHAKE_TYPE_FINISHED, HANDSHAKE_TYPE_SERVER_HELLO,
    TLS_RECORD_HEADER_SIZE, VERSION_TLS_1_2_MAJOR, VERSION_TLS_1_2_MINOR,
};
use crate::reality::error::{RealityError, RealityResult};
use ed25519_dalek::{Signer, SigningKey};

/// Default ALPN protocols for REALITY client (matches browser fingerprints)
pub const DEFAULT_ALPN_PROTOCOLS: &[&str] = &["h2", "http/1.1"];

// =============================================================================
// Message Construction
// =============================================================================

/// Construct TLS 1.3 ClientHello message
///
/// Returns handshake message bytes (without TLS record header).
///
/// # Arguments
/// * `client_random` - 32 bytes client random
/// * `session_id` - 32 bytes session ID (contains encrypted REALITY metadata)
/// * `client_public_key` - X25519 public key bytes
/// * `server_name` - SNI hostname
/// * `cipher_suites` - Cipher suite IDs to offer (e.g., &[0x1301, 0x1302, 0x1303])
/// * `alpn_protocols` - ALPN protocols to offer (e.g., &["h2", "http/1.1"])
///
/// # Returns
/// ClientHello handshake message bytes
pub fn construct_client_hello(
    client_random: &[u8; 32],
    session_id: &[u8; 32],
    client_public_key: &[u8],
    server_name: &str,
    cipher_suites: &[u16],
    alpn_protocols: &[&str],
) -> RealityResult<Vec<u8>> {
    let mut hello = Vec::with_capacity(512);

    // Handshake message type: ClientHello (0x01)
    hello.push(0x01);

    // Placeholder for handshake message length (3 bytes)
    let length_offset = hello.len();
    hello.extend_from_slice(&[0u8; 3]);

    // TLS version: 3.3 (TLS 1.2 for compatibility)
    hello.extend_from_slice(&[VERSION_TLS_1_2_MAJOR, VERSION_TLS_1_2_MINOR]);

    // Client random (32 bytes)
    hello.extend_from_slice(client_random);

    // Session ID length (1 byte) + Session ID (32 bytes)
    hello.push(32);
    hello.extend_from_slice(session_id);

    // Cipher suites
    let cipher_suites_len = (cipher_suites.len() * 2) as u16;
    hello.extend_from_slice(&cipher_suites_len.to_be_bytes());
    for &suite in cipher_suites {
        hello.extend_from_slice(&suite.to_be_bytes());
    }

    // Compression methods (1 method: null)
    hello.extend_from_slice(&[0x01, 0x00]);

    // Extensions
    let extensions_offset = hello.len();
    hello.extend_from_slice(&[0u8; 2]); // Placeholder for extensions length

    let mut extensions = Vec::new();

    // server_name extension (type 0)
    {
        let server_name_bytes = server_name.as_bytes();
        let server_name_len = server_name_bytes.len();

        extensions.extend_from_slice(&[0x00, 0x00]); // Extension type: server_name
        let ext_len = 5 + server_name_len;
        extensions.extend_from_slice(&(ext_len as u16).to_be_bytes()); // Extension length
        extensions.extend_from_slice(&((server_name_len + 3) as u16).to_be_bytes()); // Server name list length
        extensions.push(0x00); // Name type: host_name
        extensions.extend_from_slice(&(server_name_len as u16).to_be_bytes()); // Name length
        extensions.extend_from_slice(server_name_bytes); // Server name
    }

    // supported_versions extension (type 43)
    {
        extensions.extend_from_slice(&[0x00, 0x2b]); // Extension type: supported_versions
        extensions.extend_from_slice(&[0x00, 0x03]); // Extension length: 3
        extensions.push(0x02); // Supported versions length: 2
        extensions.extend_from_slice(&[0x03, 0x04]); // TLS 1.3
    }

    // supported_groups extension (type 10)
    {
        extensions.extend_from_slice(&[0x00, 0x0a]); // Extension type: supported_groups
        extensions.extend_from_slice(&[0x00, 0x04]); // Extension length: 4
        extensions.extend_from_slice(&[0x00, 0x02]); // Supported groups length: 2
        extensions.extend_from_slice(&[0x00, 0x1d]); // x25519
    }

    // key_share extension (type 51)
    {
        extensions.extend_from_slice(&[0x00, 0x33]); // Extension type: key_share
        let key_share_len = 2 + 4 + client_public_key.len();
        extensions.extend_from_slice(&(key_share_len as u16).to_be_bytes()); // Extension length
        let key_share_list_len = 4 + client_public_key.len();
        extensions.extend_from_slice(&(key_share_list_len as u16).to_be_bytes()); // Key share list length
        extensions.extend_from_slice(&[0x00, 0x1d]); // Group: x25519
        extensions.extend_from_slice(&(client_public_key.len() as u16).to_be_bytes()); // Key length
        extensions.extend_from_slice(client_public_key); // Public key
    }

    // signature_algorithms extension (type 13)
    {
        extensions.extend_from_slice(&[0x00, 0x0d]); // Extension type: signature_algorithms
        extensions.extend_from_slice(&[0x00, 0x04]); // Extension length: 4
        extensions.extend_from_slice(&[0x00, 0x02]); // Signature algorithms length: 2
        extensions.extend_from_slice(&[0x08, 0x07]); // ed25519
    }

    // ALPN extension (type 16)
    if !alpn_protocols.is_empty() {
        extensions.extend_from_slice(&[0x00, 0x10]); // Extension type: ALPN (16)

        // Calculate total length of protocol list
        let protocols_list_len: usize = alpn_protocols
            .iter()
            .map(|p| 1 + p.len()) // 1 byte length prefix + protocol bytes
            .sum();

        // Extension length = 2 (list length field) + protocols_list_len
        let ext_len = 2 + protocols_list_len;
        extensions.extend_from_slice(&(ext_len as u16).to_be_bytes());

        // Protocol list length
        extensions.extend_from_slice(&(protocols_list_len as u16).to_be_bytes());

        // Each protocol: 1 byte length + protocol string
        for protocol in alpn_protocols {
            extensions.push(protocol.len() as u8);
            extensions.extend_from_slice(protocol.as_bytes());
        }
    }

    // Write extensions length
    let extensions_length = extensions.len();
    hello[extensions_offset..extensions_offset + 2]
        .copy_from_slice(&(extensions_length as u16).to_be_bytes());

    // Append extensions
    hello.extend_from_slice(&extensions);

    // Write handshake message length
    let message_length = hello.len() - 4; // Exclude type (1) and length (3)
    hello[length_offset..length_offset + 3]
        .copy_from_slice(&(message_length as u32).to_be_bytes()[1..]);

    Ok(hello)
}

/// Construct ServerHello message
///
/// # Arguments
/// * `server_random` - 32 bytes of server random
/// * `session_id` - Session ID from ClientHello (for compatibility)
/// * `cipher_suite` - Selected cipher suite (e.g., 0x1301)
/// * `key_share_data` - Server's X25519 public key (32 bytes)
///
/// # Returns
/// ServerHello handshake message bytes
pub fn construct_server_hello(
    server_random: &[u8; 32],
    session_id: &[u8],
    cipher_suite: u16,
    key_share_data: &[u8],
) -> RealityResult<Vec<u8>> {
    let mut server_hello = Vec::new();

    let mut payload = Vec::new();

    // Version: 0x0303 (TLS 1.2 for compatibility)
    payload.extend_from_slice(&[VERSION_TLS_1_2_MAJOR, VERSION_TLS_1_2_MINOR]);

    // Random (32 bytes)
    payload.extend_from_slice(server_random);

    // Session ID
    payload.push(session_id.len() as u8);
    payload.extend_from_slice(session_id);

    // Cipher suite
    payload.extend_from_slice(&cipher_suite.to_be_bytes());

    // Compression method = 0
    payload.push(0x00);

    // Extensions
    let mut extensions = Vec::new();

    // supported_versions extension (type=43)
    extensions.extend_from_slice(&[0x00, 0x2b]); // type = 43
    extensions.extend_from_slice(&[0x00, 0x02]); // length = 2
    extensions.extend_from_slice(&[0x03, 0x04]); // TLS 1.3

    // key_share extension (type=51)
    let key_share_length = 2 + 2 + key_share_data.len(); // group + length + data
    extensions.extend_from_slice(&[0x00, 0x33]); // type = 51
    extensions.extend_from_slice(&(key_share_length as u16).to_be_bytes());
    extensions.extend_from_slice(&[0x00, 0x1d]); // group = X25519 (0x001d)
    extensions.extend_from_slice(&(key_share_data.len() as u16).to_be_bytes());
    extensions.extend_from_slice(key_share_data);

    // Extensions length
    payload.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    payload.extend_from_slice(&extensions);

    // Handshake header
    server_hello.push(HANDSHAKE_TYPE_SERVER_HELLO);

    // Payload length (3 bytes, big-endian)
    let length_bytes = [
        ((payload.len() >> 16) & 0xff) as u8,
        ((payload.len() >> 8) & 0xff) as u8,
        (payload.len() & 0xff) as u8,
    ];
    server_hello.extend_from_slice(&length_bytes);
    server_hello.extend_from_slice(&payload);

    Ok(server_hello)
}

/// Construct EncryptedExtensions message
///
/// # Returns
/// Empty EncryptedExtensions handshake message
pub fn construct_encrypted_extensions() -> RealityResult<Vec<u8>> {
    let mut encrypted_extensions = Vec::new();

    encrypted_extensions.push(HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS);

    // Empty extensions for minimal setup
    let extensions_length: u16 = 0;
    let payload_length = 2; // Just the extensions_length field

    // Payload length (3 bytes)
    encrypted_extensions.extend_from_slice(&[0x00, 0x00, payload_length as u8]);

    // Extensions length (2 bytes)
    encrypted_extensions.extend_from_slice(&extensions_length.to_be_bytes());

    Ok(encrypted_extensions)
}

/// Construct Certificate message with DER-encoded certificate
///
/// # Arguments
/// * `cert_der` - DER-encoded X.509 certificate bytes
///
/// # Returns
/// Certificate handshake message bytes
///
/// # Certificate Structure (TLS 1.3)
/// ```text
/// struct {
///     opaque certificate_request_context<0..2^8-1>;  // empty for server
///     CertificateEntry certificate_list<0..2^24-1>;
/// } Certificate;
///
/// struct {
///     opaque cert_data<1..2^24-1>;  // DER-encoded certificate
///     Extension extensions<0..2^16-1>;  // empty for simplicity
/// } CertificateEntry;
/// ```
pub fn construct_certificate(cert_der: &[u8]) -> RealityResult<Vec<u8>> {
    // Pre-calculate sizes to allocate exact capacity
    // cert_list = 3 (cert_data len) + cert_der.len() + 2 (extensions len)
    let cert_entry_len = 3 + cert_der.len() + 2;
    // payload = 1 (context len) + 3 (list len) + cert_entry_len
    let payload_len = 1 + 3 + cert_entry_len;
    // total = 1 (type) + 3 (payload len) + payload_len
    let total_len = 1 + 3 + payload_len;

    let mut certificate = Vec::with_capacity(total_len);

    // Handshake type: Certificate (0x0B = 11)
    certificate.push(HANDSHAKE_TYPE_CERTIFICATE);

    // Payload length (3 bytes, big-endian)
    certificate.extend_from_slice(&[
        ((payload_len >> 16) & 0xff) as u8,
        ((payload_len >> 8) & 0xff) as u8,
        (payload_len & 0xff) as u8,
    ]);

    // Certificate request context (empty for server certificates)
    certificate.push(0x00);

    // Certificate list length (3 bytes)
    certificate.extend_from_slice(&[
        ((cert_entry_len >> 16) & 0xff) as u8,
        ((cert_entry_len >> 8) & 0xff) as u8,
        (cert_entry_len & 0xff) as u8,
    ]);

    // Certificate entry - cert data length (3 bytes)
    certificate.extend_from_slice(&[
        ((cert_der.len() >> 16) & 0xff) as u8,
        ((cert_der.len() >> 8) & 0xff) as u8,
        (cert_der.len() & 0xff) as u8,
    ]);

    // Certificate DER data
    certificate.extend_from_slice(cert_der);

    // Extensions (empty)
    certificate.extend_from_slice(&[0x00, 0x00]);

    Ok(certificate)
}

/// Construct CertificateVerify message
///
/// Signs the handshake transcript with the server's private key.
///
/// # Arguments
/// * `signing_key` - Ed25519 signing key
/// * `handshake_hash` - Hash of all handshake messages up to this point
///
/// # Returns
/// CertificateVerify handshake message bytes
///
/// # TLS 1.3 CertificateVerify Context
/// The signed content is constructed as:
/// - 64 spaces (0x20)
/// - "TLS 1.3, server CertificateVerify"
/// - 0x00 (separator)
/// - handshake_hash
pub fn construct_certificate_verify(
    signing_key: &SigningKey,
    handshake_hash: &[u8],
) -> RealityResult<Vec<u8>> {
    // Construct the signed content per TLS 1.3 spec (RFC 8446)
    let mut signed_content = Vec::with_capacity(64 + 34 + 1 + handshake_hash.len());
    signed_content.extend_from_slice(&[0x20u8; 64]); // 64 spaces
    signed_content.extend_from_slice(b"TLS 1.3, server CertificateVerify");
    signed_content.push(0x00); // separator
    signed_content.extend_from_slice(handshake_hash);

    // Sign with Ed25519
    let signature = signing_key.sign(&signed_content);
    let signature_bytes = signature.to_bytes();

    let mut payload = Vec::new();

    // Signature algorithm: Ed25519 (0x0807)
    payload.extend_from_slice(&[0x08, 0x07]);

    // Signature length (2 bytes) and data
    payload.extend_from_slice(&(signature_bytes.len() as u16).to_be_bytes());
    payload.extend_from_slice(&signature_bytes);

    let mut certificate_verify = Vec::with_capacity(1 + 3 + payload.len());

    // Handshake type: CertificateVerify (0x0F = 15)
    certificate_verify.push(HANDSHAKE_TYPE_CERTIFICATE_VERIFY);

    // Payload length (3 bytes)
    certificate_verify.extend_from_slice(&[
        ((payload.len() >> 16) & 0xff) as u8,
        ((payload.len() >> 8) & 0xff) as u8,
        (payload.len() & 0xff) as u8,
    ]);
    certificate_verify.extend_from_slice(&payload);

    Ok(certificate_verify)
}

/// Construct Finished message
///
/// # Arguments
/// * `verify_data` - HMAC of handshake transcript (32 bytes for SHA256)
///
/// # Returns
/// Finished handshake message bytes
pub fn construct_finished(verify_data: &[u8]) -> RealityResult<Vec<u8>> {
    let mut finished = Vec::new();

    finished.push(HANDSHAKE_TYPE_FINISHED);

    // Payload length (3 bytes)
    finished.extend_from_slice(&[
        ((verify_data.len() >> 16) & 0xff) as u8,
        ((verify_data.len() >> 8) & 0xff) as u8,
        (verify_data.len() & 0xff) as u8,
    ]);

    finished.extend_from_slice(verify_data);

    Ok(finished)
}

/// Write TLS record header
///
/// # Arguments
/// * `record_type` - TLS record type (0x16 for Handshake, 0x17 for ApplicationData)
/// * `length` - Length of record payload
///
/// # Returns
/// 5-byte TLS record header
pub fn write_record_header(record_type: u8, length: u16) -> Vec<u8> {
    vec![
        record_type,
        VERSION_TLS_1_2_MAJOR,
        VERSION_TLS_1_2_MINOR,
        (length >> 8) as u8,
        (length & 0xff) as u8,
    ]
}

// =============================================================================
// Message Parsing
// =============================================================================

/// Extract server's X25519 public key from ServerHello
///
/// Parses the key_share extension to find the server's ephemeral public key.
///
/// # Arguments
/// * `record` - Complete TLS record (including 5-byte header)
///
/// # Returns
/// 32-byte X25519 public key
pub fn extract_server_public_key(record: &[u8]) -> RealityResult<[u8; 32]> {
    if record.len() < TLS_RECORD_HEADER_SIZE {
        return Err(RealityError::protocol("Record too short"));
    }

    // Skip TLS record header (5 bytes)
    let handshake = &record[TLS_RECORD_HEADER_SIZE..];

    // Parse ServerHello
    // Type (1) + Length (3) + Version (2) + Random (32) + Session ID length (1)
    if handshake.len() < 39 {
        return Err(RealityError::protocol("ServerHello too short"));
    }

    let session_id_len = handshake[38] as usize;
    let base_offset = 39 + session_id_len;

    // Cipher suite (2) + Compression (1) + Extensions length (2)
    if handshake.len() < base_offset + 5 {
        return Err(RealityError::protocol("ServerHello truncated"));
    }

    let extensions_offset = base_offset + 3;
    let extensions_len =
        u16::from_be_bytes([handshake[base_offset + 3], handshake[base_offset + 4]]) as usize;

    let extensions_start = extensions_offset + 2;
    if handshake.len() < extensions_start + extensions_len {
        return Err(RealityError::protocol("Extensions truncated"));
    }

    let extensions = &handshake[extensions_start..extensions_start + extensions_len];

    // Parse extensions to find key_share (type 51 / 0x0033)
    let mut offset = 0;
    while offset + 4 <= extensions.len() {
        let ext_type = u16::from_be_bytes([extensions[offset], extensions[offset + 1]]);
        let ext_len = u16::from_be_bytes([extensions[offset + 2], extensions[offset + 3]]) as usize;

        if offset + 4 + ext_len > extensions.len() {
            break;
        }

        if ext_type == 0x0033 {
            // key_share extension
            // Format: group (2) + key_length (2) + key_data
            let ext_data = &extensions[offset + 4..offset + 4 + ext_len];
            if ext_data.len() >= 4 {
                let group = u16::from_be_bytes([ext_data[0], ext_data[1]]);
                let key_len = u16::from_be_bytes([ext_data[2], ext_data[3]]) as usize;

                if group == 0x001d && key_len == 32 && ext_data.len() >= 4 + 32 {
                    // X25519
                    let mut key = [0u8; 32];
                    key.copy_from_slice(&ext_data[4..36]);
                    return Ok(key);
                }
            }
        }

        offset += 4 + ext_len;
    }

    Err(RealityError::protocol(
        "key_share extension not found in ServerHello",
    ))
}

/// Extract cipher suite from ServerHello
///
/// # Arguments
/// * `record` - Complete TLS record (including 5-byte header)
///
/// # Returns
/// Selected cipher suite ID
pub fn extract_server_cipher_suite(record: &[u8]) -> RealityResult<u16> {
    if record.len() < TLS_RECORD_HEADER_SIZE {
        return Err(RealityError::protocol("Record too short"));
    }

    let handshake = &record[TLS_RECORD_HEADER_SIZE..];

    // Type (1) + Length (3) + Version (2) + Random (32) + Session ID length (1)
    if handshake.len() < 39 {
        return Err(RealityError::protocol("ServerHello too short"));
    }

    let session_id_len = handshake[38] as usize;
    let cipher_suite_offset = 39 + session_id_len;

    if handshake.len() < cipher_suite_offset + 2 {
        return Err(RealityError::protocol("ServerHello truncated at cipher suite"));
    }

    let cipher_suite =
        u16::from_be_bytes([handshake[cipher_suite_offset], handshake[cipher_suite_offset + 1]]);

    Ok(cipher_suite)
}

/// Extract client random from ClientHello (for server-side parsing)
///
/// # Arguments
/// * `client_hello` - ClientHello handshake message (without record header)
///
/// # Returns
/// 32-byte client random
pub fn extract_client_random(client_hello: &[u8]) -> RealityResult<[u8; 32]> {
    // Type (1) + Length (3) + Version (2) + Random (32)
    if client_hello.len() < 38 {
        return Err(RealityError::protocol("ClientHello too short"));
    }

    let mut random = [0u8; 32];
    random.copy_from_slice(&client_hello[6..38]);
    Ok(random)
}

/// Extract session ID from ClientHello (for server-side parsing)
///
/// # Arguments
/// * `client_hello` - ClientHello handshake message (without record header)
///
/// # Returns
/// Session ID bytes (32 bytes for REALITY)
pub fn extract_session_id(client_hello: &[u8]) -> RealityResult<Vec<u8>> {
    // Type (1) + Length (3) + Version (2) + Random (32) + SessionID length (1)
    if client_hello.len() < 39 {
        return Err(RealityError::protocol("ClientHello too short"));
    }

    let session_id_len = client_hello[38] as usize;
    if client_hello.len() < 39 + session_id_len {
        return Err(RealityError::protocol("SessionID truncated"));
    }

    Ok(client_hello[39..39 + session_id_len].to_vec())
}

/// Extract client's X25519 public key from ClientHello key_share extension
///
/// # Arguments
/// * `client_hello` - ClientHello handshake message (without record header)
///
/// # Returns
/// 32-byte X25519 public key
pub fn extract_client_public_key(client_hello: &[u8]) -> RealityResult<[u8; 32]> {
    // Find extensions
    // Type (1) + Length (3) + Version (2) + Random (32) + SessionID length (1)
    if client_hello.len() < 39 {
        return Err(RealityError::protocol("ClientHello too short"));
    }

    let session_id_len = client_hello[38] as usize;
    let mut offset = 39 + session_id_len;

    // Cipher suites length (2)
    if client_hello.len() < offset + 2 {
        return Err(RealityError::protocol("ClientHello truncated at cipher suites"));
    }
    let cipher_suites_len = u16::from_be_bytes([client_hello[offset], client_hello[offset + 1]]) as usize;
    offset += 2 + cipher_suites_len;

    // Compression methods length (1)
    if client_hello.len() < offset + 1 {
        return Err(RealityError::protocol("ClientHello truncated at compression"));
    }
    let compression_len = client_hello[offset] as usize;
    offset += 1 + compression_len;

    // Extensions length (2)
    if client_hello.len() < offset + 2 {
        return Err(RealityError::protocol("ClientHello truncated at extensions length"));
    }
    let extensions_len = u16::from_be_bytes([client_hello[offset], client_hello[offset + 1]]) as usize;
    offset += 2;

    if client_hello.len() < offset + extensions_len {
        return Err(RealityError::protocol("Extensions truncated"));
    }

    let extensions = &client_hello[offset..offset + extensions_len];

    // Parse extensions to find key_share (type 51 / 0x0033)
    let mut ext_offset = 0;
    while ext_offset + 4 <= extensions.len() {
        let ext_type = u16::from_be_bytes([extensions[ext_offset], extensions[ext_offset + 1]]);
        let ext_len = u16::from_be_bytes([extensions[ext_offset + 2], extensions[ext_offset + 3]]) as usize;

        if ext_offset + 4 + ext_len > extensions.len() {
            break;
        }

        if ext_type == 0x0033 {
            // key_share extension
            // Format: length (2) + entries
            let ext_data = &extensions[ext_offset + 4..ext_offset + 4 + ext_len];
            if ext_data.len() >= 2 {
                let _list_len = u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
                let entries = &ext_data[2..];

                // Parse key share entries
                let mut entry_offset = 0;
                while entry_offset + 4 <= entries.len() {
                    let group = u16::from_be_bytes([entries[entry_offset], entries[entry_offset + 1]]);
                    let key_len = u16::from_be_bytes([entries[entry_offset + 2], entries[entry_offset + 3]]) as usize;

                    if group == 0x001d && key_len == 32 && entries.len() >= entry_offset + 4 + 32 {
                        // X25519
                        let mut key = [0u8; 32];
                        key.copy_from_slice(&entries[entry_offset + 4..entry_offset + 4 + 32]);
                        return Ok(key);
                    }

                    entry_offset += 4 + key_len;
                }
            }
        }

        ext_offset += 4 + ext_len;
    }

    Err(RealityError::protocol(
        "X25519 key_share not found in ClientHello",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_construct_client_hello() {
        let client_random = [0x42u8; 32];
        let session_id = [0x99u8; 32];
        let public_key = [0xAAu8; 32];
        let cipher_suites = &[0x1301, 0x1302, 0x1303];

        let result = construct_client_hello(
            &client_random,
            &session_id,
            &public_key,
            "www.google.com",
            cipher_suites,
            DEFAULT_ALPN_PROTOCOLS,
        );

        assert!(result.is_ok());
        let hello = result.unwrap();

        // Check handshake type
        assert_eq!(hello[0], 0x01); // ClientHello

        // Check that we can extract the client random
        let extracted_random = extract_client_random(&hello).unwrap();
        assert_eq!(extracted_random, client_random);

        // Check that we can extract the session ID
        let extracted_session = extract_session_id(&hello).unwrap();
        assert_eq!(extracted_session, session_id);

        // Check that we can extract the public key
        let extracted_key = extract_client_public_key(&hello).unwrap();
        assert_eq!(extracted_key, public_key);
    }

    #[test]
    fn test_construct_server_hello() {
        let server_random = [0x42u8; 32];
        let session_id = vec![0x99u8; 32];
        let cipher_suite = 0x1301;
        let key_share = vec![0xAAu8; 32];

        let result = construct_server_hello(&server_random, &session_id, cipher_suite, &key_share);

        assert!(result.is_ok());
        let msg = result.unwrap();
        assert_eq!(msg[0], HANDSHAKE_TYPE_SERVER_HELLO);
    }

    #[test]
    fn test_extract_server_public_key() {
        let server_random = [0x42u8; 32];
        let session_id = vec![0x99u8; 32];
        let public_key = [0xABu8; 32];

        let server_hello =
            construct_server_hello(&server_random, &session_id, 0x1301, &public_key).unwrap();

        // Add record header
        let mut record = write_record_header(CONTENT_TYPE_HANDSHAKE, server_hello.len() as u16);
        record.extend_from_slice(&server_hello);

        let extracted = extract_server_public_key(&record).unwrap();
        assert_eq!(extracted, public_key);
    }

    #[test]
    fn test_extract_server_cipher_suite() {
        let server_random = [0x42u8; 32];
        let session_id = vec![0x99u8; 32];

        let server_hello =
            construct_server_hello(&server_random, &session_id, 0x1302, &[0u8; 32]).unwrap();

        let mut record = write_record_header(CONTENT_TYPE_HANDSHAKE, server_hello.len() as u16);
        record.extend_from_slice(&server_hello);

        let cipher_suite = extract_server_cipher_suite(&record).unwrap();
        assert_eq!(cipher_suite, 0x1302);
    }

    #[test]
    fn test_construct_encrypted_extensions() {
        let result = construct_encrypted_extensions();
        assert!(result.is_ok());
        let msg = result.unwrap();
        assert_eq!(msg[0], HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS);
    }

    #[test]
    fn test_construct_finished() {
        let verify_data = vec![0xCCu8; 32];
        let result = construct_finished(&verify_data);
        assert!(result.is_ok());
        let msg = result.unwrap();
        assert_eq!(msg[0], HANDSHAKE_TYPE_FINISHED);
        assert_eq!(msg.len(), 1 + 3 + 32); // type + length + verify_data
    }

    #[test]
    fn test_write_record_header() {
        let header = write_record_header(CONTENT_TYPE_HANDSHAKE, 100);
        assert_eq!(header.len(), 5);
        assert_eq!(header[0], 0x16); // Handshake
        assert_eq!(header[1], 0x03); // TLS 1.2
        assert_eq!(header[2], 0x03);
        assert_eq!(u16::from_be_bytes([header[3], header[4]]), 100);
    }

    #[test]
    fn test_client_hello_without_alpn() {
        let client_random = [0x42u8; 32];
        let session_id = [0x99u8; 32];
        let public_key = [0xAAu8; 32];

        // Empty ALPN
        let result = construct_client_hello(
            &client_random,
            &session_id,
            &public_key,
            "example.com",
            &[0x1301],
            &[],
        );

        assert!(result.is_ok());
    }

    #[test]
    fn test_server_hello_with_empty_session_id() {
        let server_random = [0x42u8; 32];
        let session_id = vec![];
        let public_key = [0xABu8; 32];

        let result = construct_server_hello(&server_random, &session_id, 0x1301, &public_key);
        assert!(result.is_ok());

        let server_hello = result.unwrap();
        let mut record = write_record_header(CONTENT_TYPE_HANDSHAKE, server_hello.len() as u16);
        record.extend_from_slice(&server_hello);

        // Should still be able to extract cipher suite and public key
        let cipher_suite = extract_server_cipher_suite(&record).unwrap();
        assert_eq!(cipher_suite, 0x1301);

        let extracted_key = extract_server_public_key(&record).unwrap();
        assert_eq!(extracted_key, public_key);
    }
}
