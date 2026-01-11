//! TLS SNI (Server Name Indication) parsing
//!
//! This module implements parsing of TLS `ClientHello` messages to extract
//! the Server Name Indication extension, which contains the hostname
//! the client is trying to connect to.
//!
//! ## TLS Record Format
//!
//! ```text
//! ContentType (1 byte)
//! ProtocolVersion (2 bytes)
//! Length (2 bytes)
//! Fragment (variable)
//! ```
//!
//! ## `ClientHello` Format (simplified)
//!
//! ```text
//! HandshakeType (1 byte) = 0x01
//! Length (3 bytes)
//! ProtocolVersion (2 bytes)
//! Random (32 bytes)
//! SessionID (1 byte length + variable)
//! CipherSuites (2 bytes length + variable)
//! CompressionMethods (1 byte length + variable)
//! Extensions (2 bytes length + variable)
//! ```
//!
//! ## SNI Extension Format
//!
//! ```text
//! ExtensionType (2 bytes) = 0x0000
//! Length (2 bytes)
//! ServerNameListLength (2 bytes)
//! ServerNameType (1 byte) = 0x00 (host_name)
//! ServerNameLength (2 bytes)
//! ServerName (variable)
//! ```

use tracing::trace;

/// TLS `ContentType` for Handshake
const TLS_CONTENT_TYPE_HANDSHAKE: u8 = 0x16;

/// TLS `HandshakeType` for `ClientHello`
const TLS_HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 0x01;

/// SNI extension type
const TLS_EXTENSION_TYPE_SNI: u16 = 0x0000;

/// SNI name type for hostname
const TLS_SNI_NAME_TYPE_HOSTNAME: u8 = 0x00;

/// Minimum TLS record header size
const TLS_RECORD_HEADER_SIZE: usize = 5;

/// Minimum `ClientHello` size (header + version + random + `session_id` length)
const MIN_CLIENT_HELLO_SIZE: usize = 38;

/// Parse TLS `ClientHello` and extract SNI hostname
///
/// # Arguments
///
/// * `data` - Raw bytes that might contain a TLS `ClientHello`
///
/// # Returns
///
/// Returns `Some(hostname)` if SNI was found, `None` otherwise.
///
/// # Example
///
/// ```
/// use rust_router::sniff::sniff_tls_sni;
///
/// // Example TLS ClientHello with SNI for "example.com"
/// // In practice, this would be actual network data
/// let data = [/* TLS ClientHello bytes */];
/// if let Some(sni) = sniff_tls_sni(&data) {
///     println!("Client wants to connect to: {}", sni);
/// }
/// ```
#[must_use]
pub fn sniff_tls_sni(data: &[u8]) -> Option<String> {
    // Need at least a TLS record header
    if data.len() < TLS_RECORD_HEADER_SIZE {
        trace!("Data too short for TLS record header");
        return None;
    }

    // Check content type (must be Handshake = 0x16)
    if data[0] != TLS_CONTENT_TYPE_HANDSHAKE {
        trace!("Not a TLS Handshake record (got 0x{:02x})", data[0]);
        return None;
    }

    // Check TLS version (should be 0x0301 to 0x0304 for TLS 1.0-1.3)
    // Note: TLS 1.3 still uses 0x0301 in the record layer for compatibility
    let version = u16::from_be_bytes([data[1], data[2]]);
    if !(0x0301..=0x0304).contains(&version) {
        trace!("Invalid TLS version: 0x{:04x}", version);
        return None;
    }

    // Get record length
    let record_length = u16::from_be_bytes([data[3], data[4]]) as usize;

    // Sanity check on record length
    if record_length > 16384 || data.len() < TLS_RECORD_HEADER_SIZE + record_length {
        trace!(
            "Invalid record length: {} (data len: {})",
            record_length,
            data.len()
        );
        // Continue anyway with available data
    }

    // Parse handshake message
    let handshake = &data[TLS_RECORD_HEADER_SIZE..];
    if handshake.is_empty() {
        return None;
    }

    // Check handshake type (must be ClientHello = 0x01)
    if handshake[0] != TLS_HANDSHAKE_TYPE_CLIENT_HELLO {
        trace!("Not a ClientHello (got 0x{:02x})", handshake[0]);
        return None;
    }

    if handshake.len() < MIN_CLIENT_HELLO_SIZE {
        trace!("ClientHello too short");
        return None;
    }

    // Skip: type (1) + length (3) + version (2) + random (32) = 38 bytes
    let mut pos: usize = 38;

    // Session ID
    if pos >= handshake.len() {
        return None;
    }
    let session_id_len = handshake[pos] as usize;
    pos += 1 + session_id_len;

    // Cipher suites
    if pos + 2 > handshake.len() {
        return None;
    }
    let cipher_suites_len = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]) as usize;
    pos += 2 + cipher_suites_len;

    // Compression methods
    if pos >= handshake.len() {
        return None;
    }
    let compression_len = handshake[pos] as usize;
    pos += 1 + compression_len;

    // Extensions
    if pos + 2 > handshake.len() {
        trace!("No extensions present");
        return None;
    }
    let extensions_len = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]) as usize;
    pos += 2;

    let extensions_end = pos + extensions_len;
    if extensions_end > handshake.len() {
        trace!("Extensions length exceeds data");
        // Continue with available data
    }

    // Parse extensions
    while pos + 4 <= handshake.len() && pos < extensions_end {
        let ext_type = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]);
        let ext_len = u16::from_be_bytes([handshake[pos + 2], handshake[pos + 3]]) as usize;
        pos += 4;

        if pos + ext_len > handshake.len() {
            trace!("Extension data exceeds buffer");
            break;
        }

        if ext_type == TLS_EXTENSION_TYPE_SNI {
            // Found SNI extension
            let ext_data = &handshake[pos..pos + ext_len];
            if let Some(sni) = parse_sni_extension(ext_data) {
                trace!("Found SNI: {}", sni);
                return Some(sni);
            }
        }

        pos += ext_len;
    }

    None
}

/// Parse SNI extension data to extract hostname
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

        if name_type == TLS_SNI_NAME_TYPE_HOSTNAME {
            // Found hostname
            let hostname = &data[pos..pos + name_len];
            // Validate as ASCII hostname
            if hostname.iter().all(|&b| b.is_ascii() && b != 0) {
                return String::from_utf8(hostname.to_vec()).ok();
            }
        }

        pos += name_len;
    }

    None
}

/// Check if data looks like TLS `ClientHello`
#[must_use]
pub fn looks_like_tls(data: &[u8]) -> bool {
    if data.len() < TLS_RECORD_HEADER_SIZE {
        return false;
    }

    // Check content type
    if data[0] != TLS_CONTENT_TYPE_HANDSHAKE {
        return false;
    }

    // Check version
    let version = u16::from_be_bytes([data[1], data[2]]);
    if !(0x0300..=0x0304).contains(&version) {
        return false;
    }

    // Check for ClientHello
    if data.len() > TLS_RECORD_HEADER_SIZE {
        data[TLS_RECORD_HEADER_SIZE] == TLS_HANDSHAKE_TYPE_CLIENT_HELLO
    } else {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Minimal TLS ClientHello with SNI "example.com"
    // This is a simplified example for testing
    fn create_test_client_hello(sni: &str) -> Vec<u8> {
        let mut data = Vec::new();

        // TLS record header
        data.push(TLS_CONTENT_TYPE_HANDSHAKE); // Content type
        data.extend_from_slice(&[0x03, 0x01]); // Version TLS 1.0

        // We'll fill in length later
        let record_length_pos = data.len();
        data.extend_from_slice(&[0x00, 0x00]); // Placeholder

        let handshake_start = data.len();

        // Handshake header
        data.push(TLS_HANDSHAKE_TYPE_CLIENT_HELLO);
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

        // SNI extension
        data.extend_from_slice(&[0x00, 0x00]); // Extension type (SNI)
        let sni_ext_length_pos = data.len();
        data.extend_from_slice(&[0x00, 0x00]); // Placeholder

        let sni_ext_start = data.len();

        // Server name list
        let sni_list_length_pos = data.len();
        data.extend_from_slice(&[0x00, 0x00]); // Placeholder

        let sni_list_start = data.len();

        // Server name entry
        data.push(TLS_SNI_NAME_TYPE_HOSTNAME);
        data.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        data.extend_from_slice(sni.as_bytes());

        let sni_list_end = data.len();

        // Fill in lengths
        let sni_list_len = sni_list_end - sni_list_start;
        data[sni_list_length_pos] = (sni_list_len >> 8) as u8;
        data[sni_list_length_pos + 1] = sni_list_len as u8;

        let sni_ext_len = sni_list_end - sni_ext_start;
        data[sni_ext_length_pos] = (sni_ext_len >> 8) as u8;
        data[sni_ext_length_pos + 1] = sni_ext_len as u8;

        let extensions_len = data.len() - extensions_start;
        data[extensions_length_pos] = (extensions_len >> 8) as u8;
        data[extensions_length_pos + 1] = extensions_len as u8;

        let client_hello_len = data.len() - client_hello_start;
        data[handshake_length_pos] = (client_hello_len >> 16) as u8;
        data[handshake_length_pos + 1] = (client_hello_len >> 8) as u8;
        data[handshake_length_pos + 2] = client_hello_len as u8;

        let record_len = data.len() - handshake_start;
        data[record_length_pos] = (record_len >> 8) as u8;
        data[record_length_pos + 1] = record_len as u8;

        data
    }

    #[test]
    fn test_sniff_tls_sni() {
        let data = create_test_client_hello("example.com");
        let sni = sniff_tls_sni(&data);
        assert_eq!(sni, Some("example.com".to_string()));
    }

    #[test]
    fn test_sniff_tls_sni_long_domain() {
        let domain = "very.long.subdomain.example.com";
        let data = create_test_client_hello(domain);
        let sni = sniff_tls_sni(&data);
        assert_eq!(sni, Some(domain.to_string()));
    }

    #[test]
    fn test_sniff_tls_sni_not_tls() {
        let data = b"GET / HTTP/1.1\r\nHost: example.com\r\n";
        let sni = sniff_tls_sni(data);
        assert_eq!(sni, None);
    }

    #[test]
    fn test_sniff_tls_sni_too_short() {
        let data = &[0x16, 0x03, 0x01];
        let sni = sniff_tls_sni(data);
        assert_eq!(sni, None);
    }

    #[test]
    fn test_looks_like_tls() {
        let data = create_test_client_hello("test.com");
        assert!(looks_like_tls(&data));

        let http_data = b"GET / HTTP/1.1\r\n";
        assert!(!looks_like_tls(http_data));

        let short_data = &[0x16, 0x03];
        assert!(!looks_like_tls(short_data));
    }

    #[test]
    fn test_wrong_content_type() {
        let mut data = create_test_client_hello("test.com");
        data[0] = 0x17; // Change to Application Data
        assert!(!looks_like_tls(&data));
        assert_eq!(sniff_tls_sni(&data), None);
    }

    #[test]
    fn test_wrong_handshake_type() {
        let mut data = create_test_client_hello("test.com");
        data[5] = 0x02; // Change to ServerHello
        assert_eq!(sniff_tls_sni(&data), None);
    }
}
