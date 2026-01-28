//! TLS SNI (Server Name Indication) parsing
//!
//! This module implements parsing of TLS `ClientHello` messages to extract
//! the Server Name Indication extension, which contains the hostname
//! the client is trying to connect to.
//!
//! ## Implementation
//!
//! When the `sni-sniffing` feature is enabled, this module uses the `tls-parser`
//! crate for robust TLS parsing. Otherwise, it falls back to a minimal hand-written
//! parser for basic SNI extraction.
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

/// Minimum TLS record header size
const TLS_RECORD_HEADER_SIZE: usize = 5;

// ============================================================================
// New API with tls-parser (feature: sni-sniffing)
// ============================================================================

/// TLS SNI sniffing result
///
/// Contains extracted information from TLS `ClientHello` message.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TlsSniffResult {
    /// Extracted SNI domain name
    pub sni: Option<String>,
    /// Whether Encrypted Client Hello (ECH) was detected
    ///
    /// Note: When ECH is present, the SNI field may contain a public/cover
    /// domain rather than the actual destination.
    pub has_ech: bool,
    /// TLS version from record layer (e.g., 0x0301 = TLS 1.0, 0x0303 = TLS 1.2)
    ///
    /// Note: TLS 1.3 uses 0x0303 in the record layer for compatibility.
    pub version: Option<u16>,
    /// ALPN (Application-Layer Protocol Negotiation) protocol list
    ///
    /// Common values: "h2", "http/1.1", "h3"
    pub alpn: Vec<String>,
}

impl TlsSniffResult {
    /// Create an empty result
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Check if any useful information was extracted
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sni.is_none() && !self.has_ech && self.version.is_none() && self.alpn.is_empty()
    }
}

// ============================================================================
// tls-parser based implementation (feature: sni-sniffing)
// ============================================================================

#[cfg(feature = "sni-sniffing")]
mod parser_impl {
    use super::*;
    use tls_parser::{
        parse_tls_extensions, parse_tls_plaintext, SNIType, TlsExtension, TlsMessage,
        TlsMessageHandshake,
    };

    /// Extract TLS information from data using tls-parser
    ///
    /// # Arguments
    ///
    /// * `data` - Raw bytes that might contain a TLS `ClientHello`
    ///
    /// # Returns
    ///
    /// Returns `Some(TlsSniffResult)` if TLS `ClientHello` was detected,
    /// `None` if the data is not a valid TLS handshake.
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::sniff::tls::sniff_tls;
    ///
    /// let data = [/* TLS ClientHello bytes */];
    /// if let Some(result) = sniff_tls(&data) {
    ///     if let Some(sni) = &result.sni {
    ///         println!("Client wants to connect to: {}", sni);
    ///     }
    ///     if result.has_ech {
    ///         println!("Warning: ECH detected, SNI may be a cover domain");
    ///     }
    ///     for proto in &result.alpn {
    ///         println!("ALPN protocol: {}", proto);
    ///     }
    /// }
    /// ```
    #[must_use]
    pub fn sniff_tls(data: &[u8]) -> Option<TlsSniffResult> {
        // Quick sanity checks before invoking the parser
        if data.len() < TLS_RECORD_HEADER_SIZE {
            trace!("Data too short for TLS record header");
            return None;
        }

        // Check content type (must be Handshake = 0x16)
        if data[0] != TLS_CONTENT_TYPE_HANDSHAKE {
            trace!("Not a TLS Handshake record (got 0x{:02x})", data[0]);
            return None;
        }

        // Parse TLS record using tls-parser
        let (_, record) = match parse_tls_plaintext(data) {
            Ok(result) => result,
            Err(e) => {
                trace!("Failed to parse TLS record: {:?}", e);
                return None;
            }
        };

        // Extract version from record header
        let version = Some(record.hdr.version.0);

        // Find ClientHello in the messages
        for msg in &record.msg {
            if let TlsMessage::Handshake(TlsMessageHandshake::ClientHello(client_hello)) = msg {
                let mut result = TlsSniffResult {
                    version,
                    ..Default::default()
                };

                // Parse extensions if present
                if let Some(ext_data) = client_hello.ext {
                    match parse_tls_extensions(ext_data) {
                        Ok((_, extensions)) => {
                            for ext in extensions {
                            match ext {
                                // SNI extension
                                TlsExtension::SNI(sni_list) => {
                                    for (sni_type, name_bytes) in sni_list {
                                        // SNIType::HostName = 0
                                        if sni_type == SNIType::HostName {
                                            if let Ok(hostname) = std::str::from_utf8(name_bytes) {
                                                // Validate hostname
                                                if is_valid_hostname(hostname) {
                                                    result.sni = Some(hostname.to_string());
                                                    trace!("Found SNI: {}", hostname);
                                                }
                                            }
                                        }
                                    }
                                }

                                // ALPN extension
                                TlsExtension::ALPN(protocols) => {
                                    for proto_bytes in protocols {
                                        if let Ok(proto) = std::str::from_utf8(proto_bytes) {
                                            result.alpn.push(proto.to_string());
                                            trace!("Found ALPN: {}", proto);
                                        }
                                    }
                                }

                                // Encrypted Server Name (ESNI/ECH precursor)
                                // This is the draft-ietf-tls-esni format
                                TlsExtension::EncryptedServerName { .. } => {
                                    result.has_ech = true;
                                    trace!("Detected EncryptedServerName (ESNI)");
                                }

                                // ECH extension type 0xfe0d (65037)
                                // tls-parser may not have explicit support, check Unknown
                                TlsExtension::Unknown(ext_type, _) => {
                                    // ECH extension type: 0xfe0d (65037) or 0xfe0a (65034 draft)
                                    if ext_type.0 == 0xfe0d || ext_type.0 == 0xfe0a {
                                        result.has_ech = true;
                                        trace!("Detected ECH extension (type 0x{:04x})", ext_type.0);
                                    }
                                }

                                _ => {}
                            }
                            }
                        }
                        Err(e) => {
                            trace!("Failed to parse TLS extensions: {:?}", e);
                        }
                    }
                }

                return Some(result);
            }
        }

        None
    }

    /// Validate hostname according to RFC 1123
    fn is_valid_hostname(hostname: &str) -> bool {
        if hostname.is_empty() || hostname.len() > 253 {
            return false;
        }

        // Must be ASCII and not contain null bytes
        if !hostname.is_ascii() || hostname.contains('\0') {
            return false;
        }

        // Basic validation: alphanumeric, hyphens, and dots
        hostname
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
    }
}

// ============================================================================
// Fallback implementation (no tls-parser)
// ============================================================================

#[cfg(not(feature = "sni-sniffing"))]
mod parser_impl {
    use super::*;

    /// SNI extension type
    const TLS_EXTENSION_TYPE_SNI: u16 = 0x0000;

    /// ALPN extension type
    const TLS_EXTENSION_TYPE_ALPN: u16 = 0x0010;

    /// ECH extension type (draft-ietf-tls-esni-18)
    const TLS_EXTENSION_TYPE_ECH: u16 = 0xfe0d;

    /// ECH extension type (older draft-ietf-tls-esni-13)
    const TLS_EXTENSION_TYPE_ECH_DRAFT: u16 = 0xfe0a;

    /// SNI name type for hostname
    const TLS_SNI_NAME_TYPE_HOSTNAME: u8 = 0x00;

    /// Minimum `ClientHello` size (header + version + random + `session_id` length)
    const MIN_CLIENT_HELLO_SIZE: usize = 38;

    /// Extract TLS information from data (fallback implementation)
    ///
    /// This is a minimal hand-written parser used when the `sni-sniffing`
    /// feature is not enabled.
    #[must_use]
    pub fn sniff_tls(data: &[u8]) -> Option<TlsSniffResult> {
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
        let version = u16::from_be_bytes([data[1], data[2]]);
        if !(0x0301..=0x0304).contains(&version) {
            trace!("Invalid TLS version: 0x{:04x}", version);
            return None;
        }

        // Get record length
        let record_length = u16::from_be_bytes([data[3], data[4]]) as usize;

        // Sanity check on record length - RFC 5246 limits TLS record to 16384 bytes
        if record_length > 16384 {
            trace!(
                "Invalid TLS record length exceeds RFC 5246 limit: {} (max: 16384)",
                record_length
            );
            return None;
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

        let mut result = TlsSniffResult {
            version: Some(version),
            ..Default::default()
        };

        // Skip: type (1) + length (3) + version (2) + random (32) = 38 bytes
        let mut pos: usize = 38;

        // Session ID
        if pos >= handshake.len() {
            return Some(result);
        }
        let session_id_len = handshake[pos] as usize;
        pos += 1 + session_id_len;

        // Cipher suites
        if pos + 2 > handshake.len() {
            return Some(result);
        }
        let cipher_suites_len = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]) as usize;
        pos += 2 + cipher_suites_len;

        // Compression methods
        if pos >= handshake.len() {
            return Some(result);
        }
        let compression_len = handshake[pos] as usize;
        pos += 1 + compression_len;

        // Extensions
        if pos + 2 > handshake.len() {
            trace!("No extensions present");
            return Some(result);
        }
        let extensions_len = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]) as usize;
        pos += 2;

        let extensions_end = pos + extensions_len;

        // Parse extensions
        while pos + 4 <= handshake.len() && pos < extensions_end {
            let ext_type = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]);
            let ext_len = u16::from_be_bytes([handshake[pos + 2], handshake[pos + 3]]) as usize;
            pos += 4;

            if pos + ext_len > handshake.len() {
                trace!("Extension data exceeds buffer");
                break;
            }

            let ext_data = &handshake[pos..pos + ext_len];

            match ext_type {
                TLS_EXTENSION_TYPE_SNI => {
                    if let Some(sni) = parse_sni_extension(ext_data) {
                        trace!("Found SNI: {}", sni);
                        result.sni = Some(sni);
                    }
                }
                TLS_EXTENSION_TYPE_ALPN => {
                    result.alpn = parse_alpn_extension(ext_data);
                    for proto in &result.alpn {
                        trace!("Found ALPN: {}", proto);
                    }
                }
                TLS_EXTENSION_TYPE_ECH | TLS_EXTENSION_TYPE_ECH_DRAFT => {
                    result.has_ech = true;
                    trace!("Detected ECH/ESNI extension (type 0x{:04x})", ext_type);
                }
                _ => {}
            }

            pos += ext_len;
        }

        Some(result)
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

    /// Parse ALPN extension data to extract protocol list
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
}

// Re-export the implementation
pub use parser_impl::sniff_tls;

/// Parse TLS `ClientHello` and extract SNI hostname (compatibility API)
///
/// This function provides backward compatibility with the old API.
/// For new code, prefer using `sniff_tls()` which provides more information.
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
    sniff_tls(data).and_then(|r| r.sni)
}

/// Check if data looks like TLS `ClientHello`
///
/// This is a quick heuristic check that does not fully parse the data.
/// Use `sniff_tls()` for complete parsing.
#[must_use]
pub fn looks_like_tls(data: &[u8]) -> bool {
    if data.len() < TLS_RECORD_HEADER_SIZE {
        return false;
    }

    // Check content type
    if data[0] != TLS_CONTENT_TYPE_HANDSHAKE {
        return false;
    }

    // Check version (0x0300 = SSL 3.0 through 0x0304 = TLS 1.3)
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

    /// TLS `ContentType` for Handshake (test helper)
    const TLS_CONTENT_TYPE_HANDSHAKE_TEST: u8 = 0x16;

    /// TLS `HandshakeType` for `ClientHello` (test helper)
    const TLS_HANDSHAKE_TYPE_CLIENT_HELLO_TEST: u8 = 0x01;

    /// SNI name type for hostname (test helper)
    const TLS_SNI_NAME_TYPE_HOSTNAME_TEST: u8 = 0x00;

    // Minimal TLS ClientHello with SNI "example.com"
    // This is a simplified example for testing
    fn create_test_client_hello(sni: &str) -> Vec<u8> {
        create_test_client_hello_with_extensions(sni, &[], false)
    }

    fn create_test_client_hello_with_extensions(
        sni: &str,
        alpn_protocols: &[&str],
        include_ech: bool,
    ) -> Vec<u8> {
        let mut data = Vec::new();

        // TLS record header
        data.push(TLS_CONTENT_TYPE_HANDSHAKE_TEST); // Content type
        data.extend_from_slice(&[0x03, 0x01]); // Version TLS 1.0

        // We'll fill in length later
        let record_length_pos = data.len();
        data.extend_from_slice(&[0x00, 0x00]); // Placeholder

        let handshake_start = data.len();

        // Handshake header
        data.push(TLS_HANDSHAKE_TYPE_CLIENT_HELLO_TEST);
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

        // SNI extension (type 0x0000)
        if !sni.is_empty() {
            data.extend_from_slice(&[0x00, 0x00]); // Extension type (SNI)
            let sni_ext_length_pos = data.len();
            data.extend_from_slice(&[0x00, 0x00]); // Placeholder

            let sni_ext_start = data.len();

            // Server name list
            let sni_list_length_pos = data.len();
            data.extend_from_slice(&[0x00, 0x00]); // Placeholder

            let sni_list_start = data.len();

            // Server name entry
            data.push(TLS_SNI_NAME_TYPE_HOSTNAME_TEST);
            data.extend_from_slice(&(sni.len() as u16).to_be_bytes());
            data.extend_from_slice(sni.as_bytes());

            let sni_list_end = data.len();

            // Fill in SNI lengths
            let sni_list_len = sni_list_end - sni_list_start;
            data[sni_list_length_pos] = (sni_list_len >> 8) as u8;
            data[sni_list_length_pos + 1] = sni_list_len as u8;

            let sni_ext_len = sni_list_end - sni_ext_start;
            data[sni_ext_length_pos] = (sni_ext_len >> 8) as u8;
            data[sni_ext_length_pos + 1] = sni_ext_len as u8;
        }

        // ALPN extension (type 0x0010)
        if !alpn_protocols.is_empty() {
            data.extend_from_slice(&[0x00, 0x10]); // Extension type (ALPN)
            let alpn_ext_length_pos = data.len();
            data.extend_from_slice(&[0x00, 0x00]); // Placeholder

            let alpn_ext_start = data.len();

            // Protocol list
            let alpn_list_length_pos = data.len();
            data.extend_from_slice(&[0x00, 0x00]); // Placeholder

            let alpn_list_start = data.len();

            for proto in alpn_protocols {
                data.push(proto.len() as u8);
                data.extend_from_slice(proto.as_bytes());
            }

            let alpn_list_end = data.len();

            // Fill in ALPN lengths
            let alpn_list_len = alpn_list_end - alpn_list_start;
            data[alpn_list_length_pos] = (alpn_list_len >> 8) as u8;
            data[alpn_list_length_pos + 1] = alpn_list_len as u8;

            let alpn_ext_len = alpn_list_end - alpn_ext_start;
            data[alpn_ext_length_pos] = (alpn_ext_len >> 8) as u8;
            data[alpn_ext_length_pos + 1] = alpn_ext_len as u8;
        }

        // ECH extension (type 0xfe0d)
        if include_ech {
            data.extend_from_slice(&[0xfe, 0x0d]); // Extension type (ECH)
            data.extend_from_slice(&[0x00, 0x04]); // Length
            data.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // Dummy ECH data
        }

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
    fn test_sniff_tls_full_result() {
        let data = create_test_client_hello("example.com");
        let result = sniff_tls(&data).expect("Should parse TLS");

        assert_eq!(result.sni, Some("example.com".to_string()));
        assert!(!result.has_ech);
        assert!(result.version.is_some());
        // Version should be 0x0301 (TLS 1.0) from record layer
        assert_eq!(result.version, Some(0x0301));
    }

    #[test]
    fn test_sniff_tls_with_alpn() {
        let data = create_test_client_hello_with_extensions("example.com", &["h2", "http/1.1"], false);
        let result = sniff_tls(&data).expect("Should parse TLS");

        assert_eq!(result.sni, Some("example.com".to_string()));
        assert_eq!(result.alpn, vec!["h2".to_string(), "http/1.1".to_string()]);
        assert!(!result.has_ech);
    }

    #[test]
    fn test_sniff_tls_with_ech() {
        let data = create_test_client_hello_with_extensions("cover.example.com", &[], true);
        let result = sniff_tls(&data).expect("Should parse TLS");

        assert_eq!(result.sni, Some("cover.example.com".to_string()));
        assert!(result.has_ech);
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

    #[test]
    fn test_tls_sniff_result_empty() {
        let result = TlsSniffResult::empty();
        assert!(result.is_empty());

        let result_with_sni = TlsSniffResult {
            sni: Some("example.com".to_string()),
            ..Default::default()
        };
        assert!(!result_with_sni.is_empty());
    }

    #[test]
    fn test_tls_sniff_result_with_ech_only() {
        let result = TlsSniffResult {
            has_ech: true,
            ..Default::default()
        };
        assert!(!result.is_empty());
    }
}
