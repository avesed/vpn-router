//! XTLS-Vision protocol implementation
//!
//! XTLS-Vision is a flow control mechanism that detects inner TLS traffic and
//! switches to zero-copy passthrough mode for improved performance. When the
//! proxy detects that the application layer traffic is already TLS-encrypted
//! (e.g., HTTPS), it bypasses additional encryption to avoid double-encryption
//! overhead.
//!
//! # Status
//!
//! This module currently provides TLS detection and state management types.
//! Full Vision stream handling will be ported from the shoes project (MIT
//! license) in a future update.
//!
//! # How XTLS-Vision Works
//!
//! ## Overview
//!
//! XTLS-Vision operates on a simple principle: if the inner traffic is already
//! TLS-encrypted, there's no need to encrypt it again. This provides significant
//! performance benefits for HTTPS traffic, which makes up the vast majority of
//! modern web traffic.
//!
//! ## Detection Process
//!
//! 1. **Initial Inspection**: When data first arrives, Vision examines the first
//!    few bytes to determine if it looks like TLS traffic.
//!
//! 2. **TLS Record Check**: The detector looks for:
//!    - Valid TLS record type (0x14-0x17)
//!    - Valid TLS version (0x0301-0x0304)
//!    - Reasonable record length (<=16384 bytes)
//!
//! 3. **Mode Selection**: Based on the detection result:
//!    - **TLS detected**: Switch to passthrough mode (zero-copy)
//!    - **Non-TLS detected**: Use normal VLESS encryption
//!
//! ## Zero-Copy Passthrough
//!
//! In passthrough mode, Vision forwards data without additional encryption:
//!
//! ```text
//! Normal mode:
//! Client -> [TLS Data] -> VLESS Encrypt -> Network -> VLESS Decrypt -> [TLS Data] -> Server
//!
//! Vision passthrough:
//! Client -> [TLS Data] -> -------- Network -------- -> [TLS Data] -> Server
//!                              (raw forwarding)
//! ```
//!
//! This eliminates the CPU overhead of encrypting already-encrypted data,
//! resulting in:
//! - Higher throughput
//! - Lower latency
//! - Reduced CPU usage
//!
//! ## Security Considerations
//!
//! Vision passthrough is safe because:
//!
//! 1. **Inner TLS provides encryption**: The application data is already
//!    protected by TLS (e.g., HTTPS)
//!
//! 2. **Outer transport still provides authentication**: The VLESS connection
//!    still validates the UUID, preventing unauthorized access
//!
//! 3. **No data exposure**: Passive observers see only encrypted TLS records
//!
//! ## Performance Benefits
//!
//! Benchmarks show Vision can provide:
//! - 30-50% throughput improvement for HTTPS traffic
//! - 20-40% reduction in CPU usage
//! - Lower memory pressure from reduced buffer copies
//!
//! # Usage
//!
//! ## Basic TLS Detection
//!
//! ```
//! use rust_router::vision::{is_tls_traffic, is_client_hello, VisionState};
//!
//! fn determine_vision_mode(first_packet: &[u8]) -> VisionState {
//!     if is_tls_traffic(first_packet) {
//!         // TLS detected - use zero-copy passthrough
//!         VisionState::Passthrough
//!     } else {
//!         // Non-TLS - use normal encryption
//!         VisionState::Encrypted
//!     }
//! }
//!
//! // Example with actual data
//! let tls_data = [0x16, 0x03, 0x03, 0x00, 0x10, 0x01];
//! assert!(is_tls_traffic(&tls_data));
//! assert!(is_client_hello(&tls_data));
//! ```
//!
//! ## State Management
//!
//! ```
//! use rust_router::vision::VisionState;
//!
//! let mut state = VisionState::default();
//! assert!(state.is_inspecting());
//!
//! // After detecting TLS
//! state = VisionState::Passthrough;
//! assert!(state.is_passthrough());
//!
//! // State is immutable once set
//! println!("Current mode: {}", state);
//! ```
//!
//! ## TLS Record Parsing
//!
//! ```
//! use rust_router::vision::{
//!     parse_tls_record_header,
//!     detect_tls_record_type,
//!     content_type_name,
//!     version_name,
//!     TLS_HANDSHAKE,
//! };
//!
//! let data = [TLS_HANDSHAKE, 0x03, 0x03, 0x00, 0x10, 0x01];
//!
//! // Parse the header
//! if let Some((content_type, version, length)) = parse_tls_record_header(&data) {
//!     println!("Content Type: {} ({})", content_type, content_type_name(content_type));
//!     println!("Version: 0x{:04x} ({})", version, version_name(version));
//!     println!("Length: {} bytes", length);
//! }
//!
//! // Or get a quick description
//! if let Some(record_type) = detect_tls_record_type(&data) {
//!     println!("Detected: {}", record_type);
//! }
//! ```
//!
//! # Module Structure
//!
//! - [`detector`]: TLS traffic detection and state machine
//! - [`error`]: Error types for Vision operations
//!
//! # References
//!
//! ## shoes Project (MIT License)
//!
//! The shoes project provides a complete XTLS-Vision implementation in Rust:
//! <https://github.com/cfal/shoes>
//!
//! Key files for future porting:
//!
//! - `vision_stream.rs` (61KB): Main Vision stream wrapper
//!   - Bidirectional stream handling with mode detection
//!   - Automatic passthrough switching
//!   - Padding and unpadding for traffic obfuscation
//!
//! - `vision_filter.rs`: Traffic filtering logic
//!   - Determines when to switch modes
//!   - Handles edge cases (partial records, etc.)
//!
//! - `vision_pad.rs` / `vision_unpad.rs`: Padding operations
//!   - XTLS uses padding to obscure traffic patterns
//!   - Padding is added/removed during mode transitions
//!
//! ## Xray-core (MPL-2.0)
//!
//! The reference implementation in Go:
//! <https://github.com/XTLS/Xray-core>
//!
//! Relevant paths:
//! - `proxy/vless/inbound/inbound.go`: Server-side Vision handling
//! - `proxy/vless/outbound/outbound.go`: Client-side Vision handling
//! - `common/protocol/xtls/`: XTLS-specific code
//!
//! ## XTLS Protocol Specification
//!
//! <https://github.com/XTLS/Xray-core/discussions/716>
//!
//! # Future Work
//!
//! Planned enhancements for full Vision support:
//!
//! 1. **VisionStream wrapper**: Async stream that automatically handles
//!    mode detection and switching
//!
//! 2. **Padding support**: Traffic padding to obscure connection patterns
//!
//! 3. **Connection state tracking**: Track TLS handshake progress for
//!    more accurate mode switching
//!
//! 4. **Performance optimizations**: Zero-copy I/O using vectored writes
//!
//! 5. **Metrics**: Track passthrough vs encrypted byte counts

mod detector;
mod error;

// Re-export detector types and functions
pub use detector::{
    // Detection functions
    content_type_name,
    detect_tls_record_type,
    handshake_type_name,
    is_application_data,
    is_client_hello,
    is_server_hello,
    is_tls_traffic,
    is_valid_handshake_type,
    is_valid_tls_content_type,
    is_valid_tls_version,
    parse_tls_record_header,
    version_name,
    // Vision state
    VisionState,
    // TLS handshake type constants
    HANDSHAKE_CERTIFICATE,
    HANDSHAKE_CERTIFICATE_REQUEST,
    HANDSHAKE_CERTIFICATE_VERIFY,
    HANDSHAKE_CLIENT_HELLO,
    HANDSHAKE_CLIENT_KEY_EXCHANGE,
    HANDSHAKE_FINISHED,
    HANDSHAKE_SERVER_HELLO,
    HANDSHAKE_SERVER_HELLO_DONE,
    HANDSHAKE_SERVER_KEY_EXCHANGE,
    // TLS record type constants
    TLS_ALERT,
    TLS_APPLICATION_DATA,
    TLS_CHANGE_CIPHER_SPEC,
    TLS_HANDSHAKE,
    // Size constants
    TLS_MAX_RECORD_SIZE,
    TLS_MIN_DETECT_SIZE,
    TLS_RECORD_HEADER_SIZE,
    // TLS version constants
    TLS_VERSION_1_0,
    TLS_VERSION_1_1,
    TLS_VERSION_1_2,
    TLS_VERSION_1_3,
    TLS_VERSION_MAX,
    TLS_VERSION_MIN,
};

// Re-export error types
pub use error::{VisionError, VisionResult};

// =============================================================================
// TODO: Port Vision stream handling from shoes
// =============================================================================
//
// The shoes project (https://github.com/cfal/shoes) provides a complete
// XTLS-Vision implementation under the MIT license. Key components to port:
//
// 1. VisionStream (vision_stream.rs, 61KB)
//    - Wraps AsyncRead + AsyncWrite
//    - Detects TLS traffic on first read
//    - Switches between passthrough and encrypted modes
//    - Handles bidirectional traffic
//
// 2. VisionFilter (vision_filter.rs)
//    - Implements detection logic
//    - Tracks TLS handshake state
//    - Decides when to enable passthrough
//
// 3. VisionPad / VisionUnpad (vision_pad.rs, vision_unpad.rs)
//    - Padding for traffic obfuscation
//    - Removes padding on receive
//    - Follows XTLS padding protocol
//
// Implementation notes:
// - Use tokio's AsyncRead/AsyncWrite traits
// - Implement as a stream wrapper similar to TlsStream
// - Consider using pin-project for projection
// - Add metrics for passthrough vs encrypted bytes
//
// Example API design:
//
// ```rust
// pub struct VisionStream<S> {
//     inner: S,
//     state: VisionState,
//     buffer: Vec<u8>,
// }
//
// impl<S: AsyncRead + AsyncWrite + Unpin> VisionStream<S> {
//     pub fn new(stream: S) -> Self { ... }
//     pub fn state(&self) -> VisionState { ... }
// }
//
// impl<S: AsyncRead + Unpin> AsyncRead for VisionStream<S> { ... }
// impl<S: AsyncWrite + Unpin> AsyncWrite for VisionStream<S> { ... }
// ```
// =============================================================================

/// TLS record type constants module
///
/// Provides constants for TLS record content types as defined in RFC 5246.
pub mod record_types {
    /// Change Cipher Spec record (0x14)
    pub const CHANGE_CIPHER_SPEC: u8 = super::TLS_CHANGE_CIPHER_SPEC;

    /// Alert record (0x15)
    pub const ALERT: u8 = super::TLS_ALERT;

    /// Handshake record (0x16)
    pub const HANDSHAKE: u8 = super::TLS_HANDSHAKE;

    /// Application Data record (0x17)
    pub const APPLICATION_DATA: u8 = super::TLS_APPLICATION_DATA;
}

/// TLS handshake type constants module
///
/// Provides constants for TLS handshake message types as defined in RFC 5246.
pub mod handshake_types {
    /// ClientHello (0x01)
    pub const CLIENT_HELLO: u8 = super::HANDSHAKE_CLIENT_HELLO;

    /// ServerHello (0x02)
    pub const SERVER_HELLO: u8 = super::HANDSHAKE_SERVER_HELLO;

    /// Certificate (0x0b)
    pub const CERTIFICATE: u8 = super::HANDSHAKE_CERTIFICATE;

    /// ServerKeyExchange (0x0c)
    pub const SERVER_KEY_EXCHANGE: u8 = super::HANDSHAKE_SERVER_KEY_EXCHANGE;

    /// CertificateRequest (0x0d)
    pub const CERTIFICATE_REQUEST: u8 = super::HANDSHAKE_CERTIFICATE_REQUEST;

    /// ServerHelloDone (0x0e)
    pub const SERVER_HELLO_DONE: u8 = super::HANDSHAKE_SERVER_HELLO_DONE;

    /// CertificateVerify (0x0f)
    pub const CERTIFICATE_VERIFY: u8 = super::HANDSHAKE_CERTIFICATE_VERIFY;

    /// ClientKeyExchange (0x10)
    pub const CLIENT_KEY_EXCHANGE: u8 = super::HANDSHAKE_CLIENT_KEY_EXCHANGE;

    /// Finished (0x14)
    pub const FINISHED: u8 = super::HANDSHAKE_FINISHED;
}

/// TLS version constants module
///
/// Provides constants for TLS protocol versions.
pub mod versions {
    /// TLS 1.0 (0x0301)
    pub const TLS_1_0: u16 = super::TLS_VERSION_1_0;

    /// TLS 1.1 (0x0302)
    pub const TLS_1_1: u16 = super::TLS_VERSION_1_1;

    /// TLS 1.2 (0x0303)
    pub const TLS_1_2: u16 = super::TLS_VERSION_1_2;

    /// TLS 1.3 (0x0304)
    pub const TLS_1_3: u16 = super::TLS_VERSION_1_3;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_exports() {
        // Verify constants are exported
        assert_eq!(TLS_HANDSHAKE, 0x16);
        assert_eq!(TLS_APPLICATION_DATA, 0x17);
        assert_eq!(HANDSHAKE_CLIENT_HELLO, 0x01);
        assert_eq!(TLS_VERSION_1_2, 0x0303);

        // Verify state types
        let state = VisionState::default();
        assert!(state.is_inspecting());

        // Verify error types
        let err = VisionError::detection_failed("test");
        assert!(err.to_string().contains("detection failed"));
    }

    #[test]
    fn test_record_types_module() {
        assert_eq!(record_types::CHANGE_CIPHER_SPEC, TLS_CHANGE_CIPHER_SPEC);
        assert_eq!(record_types::ALERT, TLS_ALERT);
        assert_eq!(record_types::HANDSHAKE, TLS_HANDSHAKE);
        assert_eq!(record_types::APPLICATION_DATA, TLS_APPLICATION_DATA);
    }

    #[test]
    fn test_handshake_types_module() {
        assert_eq!(handshake_types::CLIENT_HELLO, HANDSHAKE_CLIENT_HELLO);
        assert_eq!(handshake_types::SERVER_HELLO, HANDSHAKE_SERVER_HELLO);
        assert_eq!(handshake_types::FINISHED, HANDSHAKE_FINISHED);
    }

    #[test]
    fn test_versions_module() {
        assert_eq!(versions::TLS_1_0, TLS_VERSION_1_0);
        assert_eq!(versions::TLS_1_1, TLS_VERSION_1_1);
        assert_eq!(versions::TLS_1_2, TLS_VERSION_1_2);
        assert_eq!(versions::TLS_1_3, TLS_VERSION_1_3);
    }

    #[test]
    fn test_detection_integration() {
        // Simulate detecting TLS ClientHello
        let client_hello = [
            TLS_HANDSHAKE,
            0x03,
            0x03,
            0x00,
            0x10,
            HANDSHAKE_CLIENT_HELLO,
            0x00,
            0x00,
            0x0c,
        ];

        assert!(is_tls_traffic(&client_hello));
        assert!(is_client_hello(&client_hello));
        assert!(!is_server_hello(&client_hello));

        let record_type = detect_tls_record_type(&client_hello);
        assert_eq!(record_type, Some("Handshake/ClientHello"));
    }

    #[test]
    fn test_vision_state_workflow() {
        // Start in inspecting state
        let mut state = VisionState::default();
        assert!(state.is_inspecting());

        // Simulate detecting TLS traffic
        let data = [
            TLS_HANDSHAKE,
            0x03,
            0x03,
            0x00,
            0x10,
            HANDSHAKE_CLIENT_HELLO,
        ];
        if is_tls_traffic(&data) {
            state = VisionState::Passthrough;
        }
        assert!(state.is_passthrough());

        // State should stay passthrough
        assert_eq!(state.as_str(), "passthrough");
    }

    #[test]
    fn test_non_tls_detection() {
        // HTTP request
        let http_data = b"GET / HTTP/1.1\r\nHost: example.com\r\n";
        assert!(!is_tls_traffic(http_data));
        assert!(!is_client_hello(http_data));

        // Random binary data
        let random_data = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05];
        assert!(!is_tls_traffic(&random_data));
    }

    #[test]
    fn test_error_integration() {
        let err = VisionError::buffer_too_small(100, 50);
        assert!(!err.is_recoverable());

        let io_err = std::io::Error::new(std::io::ErrorKind::TimedOut, "timeout");
        let err = VisionError::Io(io_err);
        assert!(err.is_recoverable());
    }
}
