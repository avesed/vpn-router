//! TLS traffic detection for XTLS-Vision
//!
//! This module provides functions to detect TLS traffic and determine when
//! XTLS-Vision should switch to zero-copy passthrough mode. The detection
//! is based on analyzing TLS record headers and handshake messages.
//!
//! # TLS Record Structure
//!
//! ```text
//! +------------------+------------------+------------------+
//! | Content Type (1) | Version (2)      | Length (2)       |
//! +------------------+------------------+------------------+
//! | 0x14 ChangeCipher| 0x03 0x01 (1.0)  | Payload length   |
//! | 0x15 Alert       | 0x03 0x02 (1.1)  | (big endian)     |
//! | 0x16 Handshake   | 0x03 0x03 (1.2)  |                  |
//! | 0x17 AppData     | 0x03 0x04 (1.3)  |                  |
//! +------------------+------------------+------------------+
//! ```
//!
//! # Handshake Message Types
//!
//! ```text
//! +------------------+--------------------------------------+
//! | Type (1 byte)    | Description                          |
//! +------------------+--------------------------------------+
//! | 0x01             | ClientHello                          |
//! | 0x02             | ServerHello                          |
//! | 0x0b             | Certificate                          |
//! | 0x0c             | ServerKeyExchange                    |
//! | 0x0d             | CertificateRequest                   |
//! | 0x0e             | ServerHelloDone                      |
//! | 0x0f             | CertificateVerify                    |
//! | 0x10             | ClientKeyExchange                    |
//! | 0x14             | Finished                             |
//! +------------------+--------------------------------------+
//! ```
//!
//! # Vision Mode Detection
//!
//! XTLS-Vision detects inner TLS traffic by examining the first few bytes
//! of application data. When TLS is detected, it switches to zero-copy
//! passthrough mode, eliminating the overhead of encrypting already-encrypted
//! traffic.

use tracing::trace;

// =============================================================================
// TLS Record Type Constants
// =============================================================================

/// TLS record type for Change Cipher Spec
pub const TLS_CHANGE_CIPHER_SPEC: u8 = 0x14;

/// TLS record type for Alert
pub const TLS_ALERT: u8 = 0x15;

/// TLS record type for Handshake
pub const TLS_HANDSHAKE: u8 = 0x16;

/// TLS record type for Application Data
pub const TLS_APPLICATION_DATA: u8 = 0x17;

// =============================================================================
// TLS Handshake Type Constants
// =============================================================================

/// TLS handshake type for ClientHello
pub const HANDSHAKE_CLIENT_HELLO: u8 = 0x01;

/// TLS handshake type for ServerHello
pub const HANDSHAKE_SERVER_HELLO: u8 = 0x02;

/// TLS handshake type for Certificate
pub const HANDSHAKE_CERTIFICATE: u8 = 0x0b;

/// TLS handshake type for ServerKeyExchange
pub const HANDSHAKE_SERVER_KEY_EXCHANGE: u8 = 0x0c;

/// TLS handshake type for CertificateRequest
pub const HANDSHAKE_CERTIFICATE_REQUEST: u8 = 0x0d;

/// TLS handshake type for ServerHelloDone
pub const HANDSHAKE_SERVER_HELLO_DONE: u8 = 0x0e;

/// TLS handshake type for CertificateVerify
pub const HANDSHAKE_CERTIFICATE_VERIFY: u8 = 0x0f;

/// TLS handshake type for ClientKeyExchange
pub const HANDSHAKE_CLIENT_KEY_EXCHANGE: u8 = 0x10;

/// TLS handshake type for Finished
pub const HANDSHAKE_FINISHED: u8 = 0x14;

// =============================================================================
// TLS Version Constants
// =============================================================================

/// TLS version 1.0 (0x0301)
pub const TLS_VERSION_1_0: u16 = 0x0301;

/// TLS version 1.1 (0x0302)
pub const TLS_VERSION_1_1: u16 = 0x0302;

/// TLS version 1.2 (0x0303)
pub const TLS_VERSION_1_2: u16 = 0x0303;

/// TLS version 1.3 (0x0304)
/// Note: TLS 1.3 often uses 0x0303 in record layer for compatibility
pub const TLS_VERSION_1_3: u16 = 0x0304;

/// Minimum TLS version we accept (TLS 1.0)
pub const TLS_VERSION_MIN: u16 = TLS_VERSION_1_0;

/// Maximum TLS version we accept (TLS 1.3)
pub const TLS_VERSION_MAX: u16 = TLS_VERSION_1_3;

// =============================================================================
// Size Constants
// =============================================================================

/// Minimum TLS record header size (content type + version + length)
pub const TLS_RECORD_HEADER_SIZE: usize = 5;

/// Maximum TLS record payload size per RFC 5246
pub const TLS_MAX_RECORD_SIZE: usize = 16384;

/// Minimum size to detect TLS traffic (header + at least 1 byte payload)
pub const TLS_MIN_DETECT_SIZE: usize = TLS_RECORD_HEADER_SIZE + 1;

// =============================================================================
// Vision State Machine
// =============================================================================

/// XTLS-Vision operation state
///
/// The Vision state machine determines how data should be processed:
///
/// - **Inspecting**: Initial state, examining traffic to detect TLS
/// - **Passthrough**: TLS detected, using zero-copy forwarding
/// - **Encrypted**: Non-TLS traffic, using normal VLESS encryption
///
/// # State Transitions
///
/// ```text
///                      +--> Passthrough (TLS detected)
///                     /
/// Inspecting --------+
///                     \
///                      +--> Encrypted (non-TLS detected)
/// ```
///
/// Once the state transitions from `Inspecting`, it never changes back.
/// This ensures consistent handling throughout the connection lifetime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VisionState {
    /// Initial state - inspecting traffic to determine if it's TLS
    ///
    /// In this state, the detector examines incoming data to determine
    /// whether it looks like TLS traffic. The first packet's content
    /// determines the mode for the rest of the connection.
    #[default]
    Inspecting,

    /// TLS traffic detected - using zero-copy passthrough mode
    ///
    /// When inner TLS is detected, Vision switches to passthrough mode
    /// where data is forwarded without additional encryption/decryption.
    /// This eliminates double-encryption overhead for HTTPS traffic.
    Passthrough,

    /// Non-TLS traffic - using normal VLESS encryption
    ///
    /// When the traffic doesn't appear to be TLS, Vision uses standard
    /// VLESS encryption to protect the payload data.
    Encrypted,
}

impl VisionState {
    /// Check if currently inspecting traffic
    #[must_use]
    pub fn is_inspecting(&self) -> bool {
        matches!(self, Self::Inspecting)
    }

    /// Check if in passthrough mode
    #[must_use]
    pub fn is_passthrough(&self) -> bool {
        matches!(self, Self::Passthrough)
    }

    /// Check if in encrypted mode
    #[must_use]
    pub fn is_encrypted(&self) -> bool {
        matches!(self, Self::Encrypted)
    }

    /// Get state name for logging
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Inspecting => "inspecting",
            Self::Passthrough => "passthrough",
            Self::Encrypted => "encrypted",
        }
    }
}

impl std::fmt::Display for VisionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// =============================================================================
// TLS Detection Functions
// =============================================================================

/// Check if the data looks like a valid TLS record header
///
/// This performs a quick check on the first 5 bytes to see if they
/// form a valid TLS record header structure.
///
/// # Arguments
///
/// * `data` - Buffer containing potential TLS data
///
/// # Returns
///
/// `true` if the data appears to be a valid TLS record header
///
/// # Example
///
/// ```
/// use rust_router::vision::{is_tls_traffic, TLS_HANDSHAKE};
///
/// // Valid TLS ClientHello header
/// let tls_header = [TLS_HANDSHAKE, 0x03, 0x01, 0x00, 0x10];
/// assert!(is_tls_traffic(&tls_header));
///
/// // HTTP request (not TLS)
/// let http = b"GET / HTTP/1.1";
/// assert!(!is_tls_traffic(http));
/// ```
#[must_use]
pub fn is_tls_traffic(data: &[u8]) -> bool {
    // Need at least the TLS record header
    if data.len() < TLS_RECORD_HEADER_SIZE {
        trace!("Buffer too small for TLS detection: {} bytes", data.len());
        return false;
    }

    // Check content type (must be a valid TLS record type)
    let content_type = data[0];
    if !is_valid_tls_content_type(content_type) {
        trace!("Invalid TLS content type: 0x{:02x}", content_type);
        return false;
    }

    // Check TLS version
    let version = u16::from_be_bytes([data[1], data[2]]);
    if !is_valid_tls_version(version) {
        trace!("Invalid TLS version: 0x{:04x}", version);
        return false;
    }

    // Check record length is reasonable
    let record_length = u16::from_be_bytes([data[3], data[4]]) as usize;
    if record_length > TLS_MAX_RECORD_SIZE {
        trace!(
            "TLS record length exceeds maximum: {} > {}",
            record_length,
            TLS_MAX_RECORD_SIZE
        );
        return false;
    }

    trace!(
        "Valid TLS record detected: type=0x{:02x}, version=0x{:04x}, len={}",
        content_type,
        version,
        record_length
    );
    true
}

/// Check if the data contains a TLS ClientHello message
///
/// This performs a more specific check to determine if the data
/// is a TLS handshake record containing a ClientHello message.
///
/// # Arguments
///
/// * `data` - Buffer containing potential TLS ClientHello
///
/// # Returns
///
/// `true` if the data appears to be a TLS ClientHello
///
/// # Example
///
/// ```
/// use rust_router::vision::{is_client_hello, TLS_HANDSHAKE, HANDSHAKE_CLIENT_HELLO};
///
/// // Minimal ClientHello header
/// let client_hello = [
///     TLS_HANDSHAKE, 0x03, 0x01, 0x00, 0x10,  // TLS record header
///     HANDSHAKE_CLIENT_HELLO,                  // Handshake type
///     0x00, 0x00, 0x0c,                         // Length (3 bytes)
/// ];
/// assert!(is_client_hello(&client_hello));
/// ```
#[must_use]
pub fn is_client_hello(data: &[u8]) -> bool {
    // First check if it's a valid TLS handshake record
    if !is_tls_traffic(data) {
        return false;
    }

    // Must be a handshake record
    if data[0] != TLS_HANDSHAKE {
        trace!("Not a handshake record: 0x{:02x}", data[0]);
        return false;
    }

    // Need at least the record header + handshake type
    if data.len() < TLS_RECORD_HEADER_SIZE + 1 {
        trace!("Buffer too small for handshake type check");
        return false;
    }

    // Check handshake type
    let handshake_type = data[TLS_RECORD_HEADER_SIZE];
    if handshake_type != HANDSHAKE_CLIENT_HELLO {
        trace!("Not a ClientHello: handshake type 0x{:02x}", handshake_type);
        return false;
    }

    trace!("Valid TLS ClientHello detected");
    true
}

/// Check if the data contains a TLS ServerHello message
///
/// # Arguments
///
/// * `data` - Buffer containing potential TLS ServerHello
///
/// # Returns
///
/// `true` if the data appears to be a TLS ServerHello
#[must_use]
pub fn is_server_hello(data: &[u8]) -> bool {
    if !is_tls_traffic(data) {
        return false;
    }

    if data[0] != TLS_HANDSHAKE {
        return false;
    }

    if data.len() < TLS_RECORD_HEADER_SIZE + 1 {
        return false;
    }

    let handshake_type = data[TLS_RECORD_HEADER_SIZE];
    if handshake_type != HANDSHAKE_SERVER_HELLO {
        trace!("Not a ServerHello: handshake type 0x{:02x}", handshake_type);
        return false;
    }

    trace!("Valid TLS ServerHello detected");
    true
}

/// Check if the data contains TLS Application Data
///
/// Application data records contain the actual encrypted payload
/// after the TLS handshake is complete.
///
/// # Arguments
///
/// * `data` - Buffer containing potential TLS Application Data
///
/// # Returns
///
/// `true` if the data appears to be TLS Application Data
#[must_use]
pub fn is_application_data(data: &[u8]) -> bool {
    if data.len() < TLS_RECORD_HEADER_SIZE {
        return false;
    }

    if data[0] != TLS_APPLICATION_DATA {
        return false;
    }

    let version = u16::from_be_bytes([data[1], data[2]]);
    if !is_valid_tls_version(version) {
        return false;
    }

    trace!("TLS Application Data detected");
    true
}

/// Detect the type of TLS record
///
/// Returns a description of what type of TLS record this appears to be,
/// useful for logging and debugging.
///
/// # Arguments
///
/// * `data` - Buffer containing potential TLS data
///
/// # Returns
///
/// A string describing the detected record type, or `None` if not TLS
#[must_use]
pub fn detect_tls_record_type(data: &[u8]) -> Option<&'static str> {
    if data.len() < TLS_RECORD_HEADER_SIZE {
        return None;
    }

    let version = u16::from_be_bytes([data[1], data[2]]);
    if !is_valid_tls_version(version) {
        return None;
    }

    match data[0] {
        TLS_CHANGE_CIPHER_SPEC => Some("ChangeCipherSpec"),
        TLS_ALERT => Some("Alert"),
        TLS_HANDSHAKE => {
            if data.len() > TLS_RECORD_HEADER_SIZE {
                match data[TLS_RECORD_HEADER_SIZE] {
                    HANDSHAKE_CLIENT_HELLO => Some("Handshake/ClientHello"),
                    HANDSHAKE_SERVER_HELLO => Some("Handshake/ServerHello"),
                    HANDSHAKE_CERTIFICATE => Some("Handshake/Certificate"),
                    HANDSHAKE_SERVER_KEY_EXCHANGE => Some("Handshake/ServerKeyExchange"),
                    HANDSHAKE_CERTIFICATE_REQUEST => Some("Handshake/CertificateRequest"),
                    HANDSHAKE_SERVER_HELLO_DONE => Some("Handshake/ServerHelloDone"),
                    HANDSHAKE_CERTIFICATE_VERIFY => Some("Handshake/CertificateVerify"),
                    HANDSHAKE_CLIENT_KEY_EXCHANGE => Some("Handshake/ClientKeyExchange"),
                    HANDSHAKE_FINISHED => Some("Handshake/Finished"),
                    _ => Some("Handshake/Unknown"),
                }
            } else {
                Some("Handshake")
            }
        }
        TLS_APPLICATION_DATA => Some("ApplicationData"),
        _ => None,
    }
}

/// Parse TLS record header
///
/// Extracts the content type, version, and length from a TLS record header.
///
/// # Arguments
///
/// * `data` - Buffer containing at least `TLS_RECORD_HEADER_SIZE` bytes
///
/// # Returns
///
/// `Some((content_type, version, length))` if valid, `None` otherwise
#[must_use]
pub fn parse_tls_record_header(data: &[u8]) -> Option<(u8, u16, u16)> {
    if data.len() < TLS_RECORD_HEADER_SIZE {
        return None;
    }

    let content_type = data[0];
    let version = u16::from_be_bytes([data[1], data[2]]);
    let length = u16::from_be_bytes([data[3], data[4]]);

    if !is_valid_tls_content_type(content_type) {
        return None;
    }

    if !is_valid_tls_version(version) {
        return None;
    }

    if length as usize > TLS_MAX_RECORD_SIZE {
        return None;
    }

    Some((content_type, version, length))
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Check if a content type byte is a valid TLS record type
#[inline]
#[must_use]
pub fn is_valid_tls_content_type(content_type: u8) -> bool {
    matches!(
        content_type,
        TLS_CHANGE_CIPHER_SPEC | TLS_ALERT | TLS_HANDSHAKE | TLS_APPLICATION_DATA
    )
}

/// Check if a version is a valid TLS version
#[inline]
#[must_use]
pub fn is_valid_tls_version(version: u16) -> bool {
    // Accept TLS 1.0 through TLS 1.3
    // Note: 0x0300 is SSL 3.0, which we don't support
    (TLS_VERSION_MIN..=TLS_VERSION_MAX).contains(&version)
}

/// Check if a handshake type byte is valid
#[inline]
#[must_use]
pub fn is_valid_handshake_type(handshake_type: u8) -> bool {
    matches!(
        handshake_type,
        HANDSHAKE_CLIENT_HELLO
            | HANDSHAKE_SERVER_HELLO
            | HANDSHAKE_CERTIFICATE
            | HANDSHAKE_SERVER_KEY_EXCHANGE
            | HANDSHAKE_CERTIFICATE_REQUEST
            | HANDSHAKE_SERVER_HELLO_DONE
            | HANDSHAKE_CERTIFICATE_VERIFY
            | HANDSHAKE_CLIENT_KEY_EXCHANGE
            | HANDSHAKE_FINISHED
    )
}

/// Get a human-readable name for a TLS content type
#[must_use]
pub fn content_type_name(content_type: u8) -> &'static str {
    match content_type {
        TLS_CHANGE_CIPHER_SPEC => "ChangeCipherSpec",
        TLS_ALERT => "Alert",
        TLS_HANDSHAKE => "Handshake",
        TLS_APPLICATION_DATA => "ApplicationData",
        _ => "Unknown",
    }
}

/// Get a human-readable name for a TLS handshake type
#[must_use]
pub fn handshake_type_name(handshake_type: u8) -> &'static str {
    match handshake_type {
        HANDSHAKE_CLIENT_HELLO => "ClientHello",
        HANDSHAKE_SERVER_HELLO => "ServerHello",
        HANDSHAKE_CERTIFICATE => "Certificate",
        HANDSHAKE_SERVER_KEY_EXCHANGE => "ServerKeyExchange",
        HANDSHAKE_CERTIFICATE_REQUEST => "CertificateRequest",
        HANDSHAKE_SERVER_HELLO_DONE => "ServerHelloDone",
        HANDSHAKE_CERTIFICATE_VERIFY => "CertificateVerify",
        HANDSHAKE_CLIENT_KEY_EXCHANGE => "ClientKeyExchange",
        HANDSHAKE_FINISHED => "Finished",
        _ => "Unknown",
    }
}

/// Get a human-readable name for a TLS version
#[must_use]
pub fn version_name(version: u16) -> &'static str {
    match version {
        TLS_VERSION_1_0 => "TLS 1.0",
        TLS_VERSION_1_1 => "TLS 1.1",
        TLS_VERSION_1_2 => "TLS 1.2",
        TLS_VERSION_1_3 => "TLS 1.3",
        0x0300 => "SSL 3.0",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // =============================================================================
    // TLS Record Detection Tests
    // =============================================================================

    #[test]
    fn test_is_tls_traffic_valid_handshake() {
        // Valid TLS 1.2 ClientHello header
        let data = [TLS_HANDSHAKE, 0x03, 0x03, 0x00, 0x10];
        assert!(is_tls_traffic(&data));
    }

    #[test]
    fn test_is_tls_traffic_valid_application_data() {
        // Valid TLS Application Data
        let data = [TLS_APPLICATION_DATA, 0x03, 0x03, 0x00, 0x20];
        assert!(is_tls_traffic(&data));
    }

    #[test]
    fn test_is_tls_traffic_valid_alert() {
        // Valid TLS Alert
        let data = [TLS_ALERT, 0x03, 0x01, 0x00, 0x02];
        assert!(is_tls_traffic(&data));
    }

    #[test]
    fn test_is_tls_traffic_valid_change_cipher_spec() {
        // Valid Change Cipher Spec
        let data = [TLS_CHANGE_CIPHER_SPEC, 0x03, 0x03, 0x00, 0x01];
        assert!(is_tls_traffic(&data));
    }

    #[test]
    fn test_is_tls_traffic_too_short() {
        let data = [TLS_HANDSHAKE, 0x03, 0x03, 0x00];
        assert!(!is_tls_traffic(&data));
    }

    #[test]
    fn test_is_tls_traffic_invalid_content_type() {
        let data = [0xFF, 0x03, 0x03, 0x00, 0x10];
        assert!(!is_tls_traffic(&data));
    }

    #[test]
    fn test_is_tls_traffic_invalid_version() {
        // SSL 3.0 - not supported
        let data = [TLS_HANDSHAKE, 0x03, 0x00, 0x00, 0x10];
        assert!(!is_tls_traffic(&data));

        // Invalid version
        let data = [TLS_HANDSHAKE, 0x02, 0x00, 0x00, 0x10];
        assert!(!is_tls_traffic(&data));
    }

    #[test]
    fn test_is_tls_traffic_http_request() {
        let data = b"GET / HTTP/1.1\r\nHost: example.com\r\n";
        assert!(!is_tls_traffic(data));
    }

    #[test]
    fn test_is_tls_traffic_record_too_large() {
        // Record length > 16384
        let data = [TLS_HANDSHAKE, 0x03, 0x03, 0x40, 0x01];
        assert!(!is_tls_traffic(&data));
    }

    // =============================================================================
    // ClientHello Detection Tests
    // =============================================================================

    #[test]
    fn test_is_client_hello_valid() {
        let data = [
            TLS_HANDSHAKE,
            0x03,
            0x01,
            0x00,
            0x10,
            HANDSHAKE_CLIENT_HELLO,
            0x00,
            0x00,
            0x0c,
        ];
        assert!(is_client_hello(&data));
    }

    #[test]
    fn test_is_client_hello_wrong_handshake_type() {
        let data = [
            TLS_HANDSHAKE,
            0x03,
            0x01,
            0x00,
            0x10,
            HANDSHAKE_SERVER_HELLO,
        ];
        assert!(!is_client_hello(&data));
    }

    #[test]
    fn test_is_client_hello_wrong_record_type() {
        let data = [
            TLS_APPLICATION_DATA,
            0x03,
            0x01,
            0x00,
            0x10,
            HANDSHAKE_CLIENT_HELLO,
        ];
        assert!(!is_client_hello(&data));
    }

    #[test]
    fn test_is_client_hello_too_short() {
        let data = [TLS_HANDSHAKE, 0x03, 0x01, 0x00, 0x10];
        assert!(!is_client_hello(&data));
    }

    // =============================================================================
    // ServerHello Detection Tests
    // =============================================================================

    #[test]
    fn test_is_server_hello_valid() {
        let data = [
            TLS_HANDSHAKE,
            0x03,
            0x03,
            0x00,
            0x10,
            HANDSHAKE_SERVER_HELLO,
        ];
        assert!(is_server_hello(&data));
    }

    #[test]
    fn test_is_server_hello_wrong_type() {
        let data = [
            TLS_HANDSHAKE,
            0x03,
            0x03,
            0x00,
            0x10,
            HANDSHAKE_CLIENT_HELLO,
        ];
        assert!(!is_server_hello(&data));
    }

    // =============================================================================
    // Application Data Detection Tests
    // =============================================================================

    #[test]
    fn test_is_application_data_valid() {
        let data = [TLS_APPLICATION_DATA, 0x03, 0x03, 0x00, 0x20];
        assert!(is_application_data(&data));
    }

    #[test]
    fn test_is_application_data_wrong_type() {
        let data = [TLS_HANDSHAKE, 0x03, 0x03, 0x00, 0x20];
        assert!(!is_application_data(&data));
    }

    // =============================================================================
    // Record Type Detection Tests
    // =============================================================================

    #[test]
    fn test_detect_tls_record_type() {
        assert_eq!(
            detect_tls_record_type(&[TLS_CHANGE_CIPHER_SPEC, 0x03, 0x03, 0x00, 0x01]),
            Some("ChangeCipherSpec")
        );

        assert_eq!(
            detect_tls_record_type(&[TLS_ALERT, 0x03, 0x03, 0x00, 0x02]),
            Some("Alert")
        );

        assert_eq!(
            detect_tls_record_type(&[
                TLS_HANDSHAKE,
                0x03,
                0x03,
                0x00,
                0x10,
                HANDSHAKE_CLIENT_HELLO
            ]),
            Some("Handshake/ClientHello")
        );

        assert_eq!(
            detect_tls_record_type(&[TLS_APPLICATION_DATA, 0x03, 0x03, 0x00, 0x20]),
            Some("ApplicationData")
        );

        // Not TLS
        assert_eq!(detect_tls_record_type(b"HTTP/1.1"), None);
    }

    // =============================================================================
    // Header Parsing Tests
    // =============================================================================

    #[test]
    fn test_parse_tls_record_header() {
        let data = [TLS_HANDSHAKE, 0x03, 0x03, 0x01, 0x00];
        let result = parse_tls_record_header(&data);
        assert_eq!(result, Some((TLS_HANDSHAKE, 0x0303, 0x0100)));
    }

    #[test]
    fn test_parse_tls_record_header_invalid() {
        // Too short
        assert_eq!(parse_tls_record_header(&[0x16, 0x03]), None);

        // Invalid content type
        assert_eq!(
            parse_tls_record_header(&[0xFF, 0x03, 0x03, 0x00, 0x10]),
            None
        );

        // Invalid version
        assert_eq!(
            parse_tls_record_header(&[0x16, 0x02, 0x00, 0x00, 0x10]),
            None
        );
    }

    // =============================================================================
    // VisionState Tests
    // =============================================================================

    #[test]
    fn test_vision_state_default() {
        let state = VisionState::default();
        assert!(state.is_inspecting());
        assert!(!state.is_passthrough());
        assert!(!state.is_encrypted());
    }

    #[test]
    fn test_vision_state_passthrough() {
        let state = VisionState::Passthrough;
        assert!(!state.is_inspecting());
        assert!(state.is_passthrough());
        assert!(!state.is_encrypted());
    }

    #[test]
    fn test_vision_state_encrypted() {
        let state = VisionState::Encrypted;
        assert!(!state.is_inspecting());
        assert!(!state.is_passthrough());
        assert!(state.is_encrypted());
    }

    #[test]
    fn test_vision_state_display() {
        assert_eq!(VisionState::Inspecting.to_string(), "inspecting");
        assert_eq!(VisionState::Passthrough.to_string(), "passthrough");
        assert_eq!(VisionState::Encrypted.to_string(), "encrypted");
    }

    // =============================================================================
    // Helper Function Tests
    // =============================================================================

    #[test]
    fn test_is_valid_tls_content_type() {
        assert!(is_valid_tls_content_type(TLS_CHANGE_CIPHER_SPEC));
        assert!(is_valid_tls_content_type(TLS_ALERT));
        assert!(is_valid_tls_content_type(TLS_HANDSHAKE));
        assert!(is_valid_tls_content_type(TLS_APPLICATION_DATA));
        assert!(!is_valid_tls_content_type(0x00));
        assert!(!is_valid_tls_content_type(0xFF));
    }

    #[test]
    fn test_is_valid_tls_version() {
        assert!(is_valid_tls_version(TLS_VERSION_1_0));
        assert!(is_valid_tls_version(TLS_VERSION_1_1));
        assert!(is_valid_tls_version(TLS_VERSION_1_2));
        assert!(is_valid_tls_version(TLS_VERSION_1_3));
        assert!(!is_valid_tls_version(0x0300)); // SSL 3.0
        assert!(!is_valid_tls_version(0x0200)); // SSL 2.0
    }

    #[test]
    fn test_is_valid_handshake_type() {
        assert!(is_valid_handshake_type(HANDSHAKE_CLIENT_HELLO));
        assert!(is_valid_handshake_type(HANDSHAKE_SERVER_HELLO));
        assert!(is_valid_handshake_type(HANDSHAKE_FINISHED));
        assert!(!is_valid_handshake_type(0x00));
        assert!(!is_valid_handshake_type(0xFF));
    }

    #[test]
    fn test_content_type_name() {
        assert_eq!(
            content_type_name(TLS_CHANGE_CIPHER_SPEC),
            "ChangeCipherSpec"
        );
        assert_eq!(content_type_name(TLS_ALERT), "Alert");
        assert_eq!(content_type_name(TLS_HANDSHAKE), "Handshake");
        assert_eq!(content_type_name(TLS_APPLICATION_DATA), "ApplicationData");
        assert_eq!(content_type_name(0xFF), "Unknown");
    }

    #[test]
    fn test_handshake_type_name() {
        assert_eq!(handshake_type_name(HANDSHAKE_CLIENT_HELLO), "ClientHello");
        assert_eq!(handshake_type_name(HANDSHAKE_SERVER_HELLO), "ServerHello");
        assert_eq!(handshake_type_name(HANDSHAKE_FINISHED), "Finished");
        assert_eq!(handshake_type_name(0xFF), "Unknown");
    }

    #[test]
    fn test_version_name() {
        assert_eq!(version_name(TLS_VERSION_1_0), "TLS 1.0");
        assert_eq!(version_name(TLS_VERSION_1_1), "TLS 1.1");
        assert_eq!(version_name(TLS_VERSION_1_2), "TLS 1.2");
        assert_eq!(version_name(TLS_VERSION_1_3), "TLS 1.3");
        assert_eq!(version_name(0x0300), "SSL 3.0");
        assert_eq!(version_name(0x0200), "Unknown");
    }
}
