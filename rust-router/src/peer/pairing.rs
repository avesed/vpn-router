//! Offline pairing protocol for Phase 6
//!
//! This module implements the offline pairing protocol for establishing
//! peer connections between nodes without requiring network connectivity
//! for the initial setup.
//!
//! # Phase 6 Implementation Status
//!
//! - [ ] 6.5.2 Pairing code generation
//! - [ ] 6.5.2 Pairing code import
//! - [ ] 6.5.2 Bidirectional key pre-generation
//! - [ ] 6.5.2 Handshake completion
//!
//! # Protocol Overview
//!
//! The pairing protocol uses a two-phase approach:
//!
//! 1. **Pair Request**: Node A generates a pairing code containing:
//!    - Node metadata (tag, description, endpoint)
//!    - WireGuard public key
//!    - Tunnel IP allocation
//!    - Optional: Pre-generated keys for bidirectional pairing
//!
//! 2. **Pair Response**: Node B imports the code and generates a response:
//!    - Node B's metadata and keys
//!    - Tunnel IP assignments
//!    - Configured WireGuard tunnel
//!
//! 3. **Complete Handshake**: Node A imports the response to finalize
//!
//! # Security Considerations
//!
//! - Pairing codes should be exchanged via secure out-of-band channel
//! - Codes include timestamps to prevent replay attacks
//! - Bidirectional mode pre-generates remote keys for auto-connect
//!
//! # References
//!
//! - Implementation Plan: `docs/PHASE6_IMPLEMENTATION_PLAN_v3.2.md` Section 6.5.2

use std::time::{SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use serde::{Deserialize, Serialize};

use crate::ipc::TunnelType;

/// Protocol version for pairing codes
pub const PAIRING_PROTOCOL_VERSION: u8 = 2;

/// Maximum size of pairing codes (16KB)
pub const MAX_PAIRING_CODE_SIZE: usize = 16 * 1024;

/// Maximum age of pairing codes (7 days)
pub const MAX_PAIRING_CODE_AGE_SECS: u64 = 7 * 24 * 3600;

/// Maximum future timestamp tolerance (5 minutes)
pub const MAX_FUTURE_TIMESTAMP_SECS: u64 = 300;

/// Configuration for generating a pairing request
#[derive(Debug, Clone, Default)]
pub struct PairRequestConfig {
    /// Local node tag
    pub local_tag: String,
    /// Local node description
    pub local_description: String,
    /// Local endpoint (IP:port or hostname:port)
    pub local_endpoint: String,
    /// Local Web API port (default: 36000)
    pub local_api_port: u16,
    /// Whether to enable bidirectional auto-connect
    pub bidirectional: bool,
    /// Tunnel type (WireGuard or Xray)
    pub tunnel_type: TunnelType,
}

/// Default value for pair_request message type
fn default_pair_request_type() -> String {
    "pair_request".to_string()
}

/// Default value for pair_response message type
fn default_pair_response_type() -> String {
    "pair_response".to_string()
}

/// Pairing request structure (encoded in Base64)
///
/// This is the structure that gets serialized into a pairing code.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairRequest {
    /// Message type discriminator for protocol compatibility with Python
    /// Uses serde rename to "type" (Rust keyword) and default for backward compatibility
    #[serde(rename = "type", default = "default_pair_request_type")]
    pub message_type: String,
    /// Protocol version (currently 2 for v3.2)
    pub version: u8,
    /// Node tag identifier
    pub node_tag: String,
    /// Human-readable node description
    pub node_description: String,
    /// WireGuard endpoint (IP:port or hostname:port)
    pub endpoint: String,
    /// Web API port for post-tunnel communication
    pub api_port: u16,
    /// Tunnel type (WireGuard or Xray)
    pub tunnel_type: TunnelType,
    /// Unix timestamp of request generation
    pub timestamp: u64,
    /// Whether this is a bidirectional pairing request
    pub bidirectional: bool,

    // WireGuard-specific fields
    /// WireGuard public key (Base64)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wg_public_key: Option<String>,
    /// Tunnel IP address for this node
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tunnel_ip: Option<String>,

    // Bidirectional pairing: Pre-generated keys and IP for remote node
    /// Pre-allocated tunnel IP for remote node (bidirectional only)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_tunnel_ip: Option<String>,
    /// Pre-generated private key for remote node (bidirectional only)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_wg_private_key: Option<String>,
    /// Pre-generated public key for remote node (bidirectional only)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_wg_public_key: Option<String>,

    // Xray-specific fields
    /// Xray UUID for authentication
    #[serde(skip_serializing_if = "Option::is_none")]
    pub xray_uuid: Option<String>,
    /// Xray server name for SNI
    #[serde(skip_serializing_if = "Option::is_none")]
    pub xray_server_name: Option<String>,
    /// Xray REALITY public key
    #[serde(skip_serializing_if = "Option::is_none")]
    pub xray_public_key: Option<String>,
    /// Xray short ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub xray_short_id: Option<String>,
}

/// Pairing response structure (encoded in Base64)
///
/// This is returned by the importing node to complete the pairing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairResponse {
    /// Message type discriminator for protocol compatibility with Python
    /// Uses serde rename to "type" (Rust keyword) and default for backward compatibility
    #[serde(rename = "type", default = "default_pair_response_type")]
    pub message_type: String,
    /// Protocol version
    pub version: u8,
    /// Tag of the requesting node (for correlation)
    pub request_node_tag: String,
    /// Tag of the responding node
    pub node_tag: String,
    /// Human-readable node description
    pub node_description: String,
    /// WireGuard endpoint (IP:port or hostname:port)
    pub endpoint: String,
    /// Web API port for post-tunnel communication
    pub api_port: u16,
    /// Tunnel type (WireGuard or Xray)
    pub tunnel_type: TunnelType,
    /// Unix timestamp of response generation
    pub timestamp: u64,

    // WireGuard-specific fields
    /// WireGuard public key (Base64)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wg_public_key: Option<String>,
    /// Local tunnel IP for this node
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tunnel_local_ip: Option<String>,
    /// Remote tunnel IP (the requesting node's IP)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tunnel_remote_ip: Option<String>,

    /// Tunnel API endpoint for post-tunnel communication
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tunnel_api_endpoint: Option<String>,

    // Xray-specific fields
    /// Xray UUID for authentication
    #[serde(skip_serializing_if = "Option::is_none")]
    pub xray_uuid: Option<String>,
}

/// Encode a pairing request to Base64
///
/// # Arguments
///
/// * `request` - The pairing request to encode
///
/// # Returns
///
/// Base64-encoded string suitable for QR codes or manual exchange
///
/// # Example
///
/// ```ignore
/// use rust_router::peer::pairing::{encode_pair_request, PairRequest};
///
/// let request = PairRequest { /* ... */ };
/// let code = encode_pair_request(&request)?;
/// // Share this code with the peer via QR code or copy/paste
/// ```
pub fn encode_pair_request(request: &PairRequest) -> Result<String, PairingError> {
    // Serialize to JSON
    let json = serde_json::to_string(request).map_err(|e| PairingError::JsonError(e.to_string()))?;

    // Check size limit
    if json.len() > MAX_PAIRING_CODE_SIZE {
        return Err(PairingError::CodeTooLarge(json.len()));
    }

    // Encode to Base64
    let encoded = BASE64_STANDARD.encode(json.as_bytes());

    Ok(encoded)
}

/// Decode a pairing request from Base64
///
/// # Arguments
///
/// * `code` - Base64-encoded pairing code
///
/// # Returns
///
/// Decoded pairing request with validated timestamp and version
///
/// # Errors
///
/// - `CodeTooLarge` if the decoded content exceeds size limit
/// - `Base64Error` if the Base64 decoding fails
/// - `JsonError` if JSON deserialization fails
/// - `UnsupportedVersion` if the protocol version is not supported
/// - `Expired` if the pairing code is older than 7 days
/// - `FutureTimestamp` if the timestamp is more than 5 minutes in the future
///
/// # Example
///
/// ```ignore
/// use rust_router::peer::pairing::decode_pair_request;
///
/// let request = decode_pair_request(code)?;
/// println!("Received pairing request from: {}", request.node_tag);
/// ```
pub fn decode_pair_request(code: &str) -> Result<PairRequest, PairingError> {
    // Check size limit on encoded data (Base64 expands by ~33%)
    let max_encoded_size = MAX_PAIRING_CODE_SIZE * 4 / 3 + 4;
    if code.len() > max_encoded_size {
        return Err(PairingError::CodeTooLarge(code.len()));
    }

    // Decode Base64
    let json_bytes = BASE64_STANDARD
        .decode(code)
        .map_err(|e| PairingError::Base64Error(e.to_string()))?;

    // Check decoded size
    if json_bytes.len() > MAX_PAIRING_CODE_SIZE {
        return Err(PairingError::CodeTooLarge(json_bytes.len()));
    }

    // Deserialize JSON
    let request: PairRequest =
        serde_json::from_slice(&json_bytes).map_err(|e| PairingError::JsonError(e.to_string()))?;

    // Validate protocol version
    if request.version != PAIRING_PROTOCOL_VERSION {
        return Err(PairingError::UnsupportedVersion(request.version));
    }

    // Validate timestamp
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // Check if timestamp is too far in the future (clock skew tolerance)
    if request.timestamp > now + MAX_FUTURE_TIMESTAMP_SECS {
        return Err(PairingError::FutureTimestamp);
    }

    // Check if expired
    if now > request.timestamp + MAX_PAIRING_CODE_AGE_SECS {
        return Err(PairingError::Expired);
    }

    Ok(request)
}

/// Encode a pairing response to Base64
///
/// # Arguments
///
/// * `response` - The pairing response to encode
///
/// # Returns
///
/// Base64-encoded string suitable for QR codes or manual exchange
pub fn encode_pair_response(response: &PairResponse) -> Result<String, PairingError> {
    // Serialize to JSON
    let json =
        serde_json::to_string(response).map_err(|e| PairingError::JsonError(e.to_string()))?;

    // Check size limit
    if json.len() > MAX_PAIRING_CODE_SIZE {
        return Err(PairingError::CodeTooLarge(json.len()));
    }

    // Encode to Base64
    let encoded = BASE64_STANDARD.encode(json.as_bytes());

    Ok(encoded)
}

/// Decode a pairing response from Base64
///
/// # Arguments
///
/// * `code` - Base64-encoded pairing response
///
/// # Returns
///
/// Decoded pairing response with validated timestamp and version
pub fn decode_pair_response(code: &str) -> Result<PairResponse, PairingError> {
    // Check size limit on encoded data
    let max_encoded_size = MAX_PAIRING_CODE_SIZE * 4 / 3 + 4;
    if code.len() > max_encoded_size {
        return Err(PairingError::CodeTooLarge(code.len()));
    }

    // Decode Base64
    let json_bytes = BASE64_STANDARD
        .decode(code)
        .map_err(|e| PairingError::Base64Error(e.to_string()))?;

    // Check decoded size
    if json_bytes.len() > MAX_PAIRING_CODE_SIZE {
        return Err(PairingError::CodeTooLarge(json_bytes.len()));
    }

    // Deserialize JSON
    let response: PairResponse =
        serde_json::from_slice(&json_bytes).map_err(|e| PairingError::JsonError(e.to_string()))?;

    // Validate protocol version
    if response.version != PAIRING_PROTOCOL_VERSION {
        return Err(PairingError::UnsupportedVersion(response.version));
    }

    // Validate timestamp
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // Check if timestamp is too far in the future
    if response.timestamp > now + MAX_FUTURE_TIMESTAMP_SECS {
        return Err(PairingError::FutureTimestamp);
    }

    // Check if expired
    if now > response.timestamp + MAX_PAIRING_CODE_AGE_SECS {
        return Err(PairingError::Expired);
    }

    Ok(response)
}

/// Error types for pairing operations
#[derive(Debug, thiserror::Error)]
pub enum PairingError {
    /// Pairing code is too large
    #[error("Pairing code exceeds maximum size of {MAX_PAIRING_CODE_SIZE} bytes: {0}")]
    CodeTooLarge(usize),

    /// Pairing code has invalid format
    #[error("Invalid pairing code format: {0}")]
    InvalidFormat(String),

    /// Pairing code timestamp is expired
    #[error("Pairing code has expired")]
    Expired,

    /// Pairing code timestamp is in the future
    #[error("Pairing code timestamp is in the future")]
    FutureTimestamp,

    /// Protocol version mismatch
    #[error("Unsupported pairing protocol version: {0}")]
    UnsupportedVersion(u8),

    /// Missing required field
    #[error("Missing required field: {0}")]
    MissingField(String),

    /// Base64 decoding error
    #[error("Base64 decoding failed: {0}")]
    Base64Error(String),

    /// JSON serialization error
    #[error("JSON error: {0}")]
    JsonError(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pair_request_config_default() {
        let config = PairRequestConfig::default();
        assert!(config.local_tag.is_empty());
        assert_eq!(config.tunnel_type, TunnelType::WireGuard);
        assert!(!config.bidirectional);
    }

    #[test]
    fn test_pair_request_serialization() {
        let request = PairRequest {
            message_type: "pair_request".to_string(),
            version: PAIRING_PROTOCOL_VERSION,
            node_tag: "test-node".to_string(),
            node_description: "Test Node".to_string(),
            endpoint: "192.168.1.1:36200".to_string(),
            api_port: 36000,
            tunnel_type: TunnelType::WireGuard,
            timestamp: 1234567890,
            bidirectional: false,
            wg_public_key: Some("test-key".to_string()),
            tunnel_ip: Some("10.200.200.1".to_string()),
            remote_tunnel_ip: None,
            remote_wg_private_key: None,
            remote_wg_public_key: None,
            xray_uuid: None,
            xray_server_name: None,
            xray_public_key: None,
            xray_short_id: None,
        };

        // Test serialization doesn't panic
        let json = serde_json::to_string(&request).expect("Serialization should succeed");
        assert!(json.contains("test-node"));
        // Verify type field is serialized correctly
        assert!(json.contains("\"type\":\"pair_request\""));

        // Test deserialization
        let decoded: PairRequest = serde_json::from_str(&json).expect("Deserialization should succeed");
        assert_eq!(decoded.node_tag, "test-node");
        assert_eq!(decoded.version, PAIRING_PROTOCOL_VERSION);
        assert_eq!(decoded.message_type, "pair_request");
    }

    #[test]
    fn test_pair_response_serialization() {
        let response = PairResponse {
            message_type: "pair_response".to_string(),
            version: PAIRING_PROTOCOL_VERSION,
            request_node_tag: "request-node".to_string(),
            node_tag: "response-node".to_string(),
            node_description: "Response Node".to_string(),
            endpoint: "192.168.1.2:36201".to_string(),
            api_port: 36000,
            tunnel_type: TunnelType::WireGuard,
            timestamp: 1234567890,
            wg_public_key: Some("response-key".to_string()),
            tunnel_local_ip: Some("10.200.200.2".to_string()),
            tunnel_remote_ip: Some("10.200.200.1".to_string()),
            tunnel_api_endpoint: Some("10.200.200.2:36000".to_string()),
            xray_uuid: None,
        };

        let json = serde_json::to_string(&response).expect("Serialization should succeed");
        // Verify type field is serialized correctly
        assert!(json.contains("\"type\":\"pair_response\""));

        let decoded: PairResponse = serde_json::from_str(&json).expect("Deserialization should succeed");
        assert_eq!(decoded.node_tag, "response-node");
        assert_eq!(decoded.request_node_tag, "request-node");
        assert_eq!(decoded.message_type, "pair_response");
    }

    fn create_test_request() -> PairRequest {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        PairRequest {
            message_type: "pair_request".to_string(),
            version: PAIRING_PROTOCOL_VERSION,
            node_tag: "test-node".to_string(),
            node_description: "Test Node".to_string(),
            endpoint: "192.168.1.1:36200".to_string(),
            api_port: 36000,
            tunnel_type: TunnelType::WireGuard,
            timestamp: now,
            bidirectional: false,
            wg_public_key: Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string()),
            tunnel_ip: Some("10.200.200.1".to_string()),
            remote_tunnel_ip: None,
            remote_wg_private_key: None,
            remote_wg_public_key: None,
            xray_uuid: None,
            xray_server_name: None,
            xray_public_key: None,
            xray_short_id: None,
        }
    }

    fn create_test_response() -> PairResponse {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        PairResponse {
            message_type: "pair_response".to_string(),
            version: PAIRING_PROTOCOL_VERSION,
            request_node_tag: "request-node".to_string(),
            node_tag: "response-node".to_string(),
            node_description: "Response Node".to_string(),
            endpoint: "192.168.1.2:36201".to_string(),
            api_port: 36000,
            tunnel_type: TunnelType::WireGuard,
            timestamp: now,
            wg_public_key: Some("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=".to_string()),
            tunnel_local_ip: Some("10.200.200.2".to_string()),
            tunnel_remote_ip: Some("10.200.200.1".to_string()),
            tunnel_api_endpoint: Some("10.200.200.2:36000".to_string()),
            xray_uuid: None,
        }
    }

    #[test]
    fn test_encode_decode_pair_request_roundtrip() {
        let request = create_test_request();

        // Encode
        let encoded = encode_pair_request(&request).expect("Encoding should succeed");

        // Verify it's valid Base64
        assert!(encoded.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '='));

        // Decode
        let decoded = decode_pair_request(&encoded).expect("Decoding should succeed");

        // Verify fields match
        assert_eq!(decoded.version, request.version);
        assert_eq!(decoded.node_tag, request.node_tag);
        assert_eq!(decoded.endpoint, request.endpoint);
        assert_eq!(decoded.api_port, request.api_port);
        assert_eq!(decoded.tunnel_type, request.tunnel_type);
        assert_eq!(decoded.wg_public_key, request.wg_public_key);
    }

    #[test]
    fn test_encode_decode_pair_response_roundtrip() {
        let response = create_test_response();

        // Encode
        let encoded = encode_pair_response(&response).expect("Encoding should succeed");

        // Decode
        let decoded = decode_pair_response(&encoded).expect("Decoding should succeed");

        // Verify fields match
        assert_eq!(decoded.version, response.version);
        assert_eq!(decoded.node_tag, response.node_tag);
        assert_eq!(decoded.request_node_tag, response.request_node_tag);
        assert_eq!(decoded.endpoint, response.endpoint);
        assert_eq!(decoded.tunnel_local_ip, response.tunnel_local_ip);
    }

    #[test]
    fn test_decode_invalid_base64() {
        let result = decode_pair_request("not valid base64!!!");
        assert!(matches!(result, Err(PairingError::Base64Error(_))));
    }

    #[test]
    fn test_decode_invalid_json() {
        let invalid_json = BASE64_STANDARD.encode(b"not json");
        let result = decode_pair_request(&invalid_json);
        assert!(matches!(result, Err(PairingError::JsonError(_))));
    }

    #[test]
    fn test_decode_wrong_version() {
        let mut request = create_test_request();
        request.version = 99; // Invalid version
        let encoded = BASE64_STANDARD.encode(serde_json::to_string(&request).unwrap().as_bytes());
        let result = decode_pair_request(&encoded);
        assert!(matches!(result, Err(PairingError::UnsupportedVersion(99))));
    }

    #[test]
    fn test_decode_expired_request() {
        let mut request = create_test_request();
        // Set timestamp to 8 days ago (past 7-day expiry)
        request.timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - (8 * 24 * 3600);
        let encoded = BASE64_STANDARD.encode(serde_json::to_string(&request).unwrap().as_bytes());
        let result = decode_pair_request(&encoded);
        assert!(matches!(result, Err(PairingError::Expired)));
    }

    #[test]
    fn test_decode_future_timestamp() {
        let mut request = create_test_request();
        // Set timestamp to 10 minutes in the future (past 5-minute tolerance)
        request.timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 600;
        let encoded = BASE64_STANDARD.encode(serde_json::to_string(&request).unwrap().as_bytes());
        let result = decode_pair_request(&encoded);
        assert!(matches!(result, Err(PairingError::FutureTimestamp)));
    }

    #[test]
    fn test_code_too_large() {
        // Create a very large request
        let mut request = create_test_request();
        request.node_description = "a".repeat(20000); // Exceed 16KB limit
        let result = encode_pair_request(&request);
        assert!(matches!(result, Err(PairingError::CodeTooLarge(_))));
    }

    // =========================================================================
    // Protocol Compatibility Tests (Issue #14 Fix)
    // =========================================================================

    /// Test that Rust-generated pairing code includes "type": "pair_request"
    #[test]
    fn test_rust_generated_code_includes_type_field() {
        let request = create_test_request();
        let code = encode_pair_request(&request).expect("Should encode");

        // Decode the Base64 to JSON
        let json_bytes = BASE64_STANDARD.decode(&code).expect("Should decode Base64");
        let json_str = String::from_utf8(json_bytes).expect("Should be valid UTF-8");

        // Verify the type field exists and is correct
        assert!(json_str.contains("\"type\":\"pair_request\""));
    }

    /// Test that Rust can deserialize Python-generated code WITH type field
    #[test]
    fn test_deserialize_python_code_with_type_field() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Simulate Python-generated JSON with "type" field
        let python_json = format!(
            r#"{{
                "type": "pair_request",
                "version": 2,
                "node_tag": "python-node",
                "node_description": "Python Node",
                "endpoint": "192.168.1.1:36200",
                "api_port": 36000,
                "tunnel_type": "wireguard",
                "timestamp": {},
                "bidirectional": true,
                "wg_public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
            }}"#,
            now
        );

        let encoded = BASE64_STANDARD.encode(python_json.as_bytes());
        let request = decode_pair_request(&encoded).expect("Should decode Python code");

        assert_eq!(request.message_type, "pair_request");
        assert_eq!(request.node_tag, "python-node");
        assert_eq!(request.version, PAIRING_PROTOCOL_VERSION);
    }

    /// Test that Rust can deserialize old codes WITHOUT type field (backward compatibility)
    #[test]
    fn test_deserialize_legacy_code_without_type_field() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Simulate old pairing code WITHOUT "type" field
        let legacy_json = format!(
            r#"{{
                "version": 2,
                "node_tag": "legacy-node",
                "node_description": "Legacy Node",
                "endpoint": "192.168.1.1:36200",
                "api_port": 36000,
                "tunnel_type": "wireguard",
                "timestamp": {},
                "bidirectional": false
            }}"#,
            now
        );

        let encoded = BASE64_STANDARD.encode(legacy_json.as_bytes());
        let request = decode_pair_request(&encoded).expect("Should decode legacy code");

        // Default value should be applied
        assert_eq!(request.message_type, "pair_request");
        assert_eq!(request.node_tag, "legacy-node");
    }

    /// Test round-trip serialization preserves all fields including type
    #[test]
    fn test_roundtrip_serialization_preserves_type() {
        let request = create_test_request();

        // Encode to Base64
        let code = encode_pair_request(&request).expect("Should encode");

        // Decode back
        let decoded = decode_pair_request(&code).expect("Should decode");

        // Verify type field preserved
        assert_eq!(decoded.message_type, "pair_request");
        assert_eq!(decoded.node_tag, request.node_tag);
        assert_eq!(decoded.version, request.version);
    }

    /// Test PairResponse type field serialization
    #[test]
    fn test_pair_response_type_field_serialization() {
        let response = create_test_response();

        // Encode to Base64
        let code = encode_pair_response(&response).expect("Should encode");

        // Decode the Base64 to JSON
        let json_bytes = BASE64_STANDARD.decode(&code).expect("Should decode Base64");
        let json_str = String::from_utf8(json_bytes).expect("Should be valid UTF-8");

        // Verify the type field exists and is correct
        assert!(json_str.contains("\"type\":\"pair_response\""));

        // Decode back and verify
        let decoded = decode_pair_response(&code).expect("Should decode");
        assert_eq!(decoded.message_type, "pair_response");
    }
}
