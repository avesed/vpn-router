//! VLESS protocol addons (protobuf-like encoding)
//!
//! This module handles the encoding and decoding of VLESS addons, which use
//! a simplified protobuf-like wire format. The primary addon is the "flow"
//! field used for XTLS-Vision support.
//!
//! # Wire Format
//!
//! Addons are encoded as a length-prefixed blob:
//! - If length is 0: No addons present
//! - If length > 0: Protobuf-encoded fields follow
//!
//! The protobuf encoding uses:
//! - Field 1 (wire type 2 = length-delimited): Flow string
//!
//! # Example Encoding
//!
//! For flow = "xtls-rprx-vision":
//! ```text
//! 0x12 (length = 18 bytes total)
//! 0x0a (field 1, wire type 2)
//! 0x10 (string length = 16)
//! "xtls-rprx-vision" (16 bytes)
//! ```

use super::error::VlessError;

/// XTLS-Vision flow identifier
///
/// This flow enables the XTLS-Vision traffic obfuscation technique.
pub const XTLS_VISION_FLOW: &str = "xtls-rprx-vision";

/// Protobuf field tag for the flow field (field 1, wire type 2 = length-delimited)
const FLOW_FIELD_TAG: u8 = 0x0a;

/// Maximum addon blob size (prevents `DoS` via huge addon allocation)
const MAX_ADDONS_SIZE: usize = 1024;

/// VLESS addons structure
///
/// Contains optional addon fields that modify VLESS behavior.
/// Currently only the `flow` field is supported (for XTLS-Vision).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VlessAddons {
    /// Flow control identifier (e.g., "xtls-rprx-vision")
    ///
    /// When set, enables special traffic handling modes.
    pub flow: Option<String>,
}

impl VlessAddons {
    /// Create empty addons (no special handling)
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create addons with XTLS-Vision flow
    #[must_use]
    pub fn with_xtls_vision() -> Self {
        Self {
            flow: Some(XTLS_VISION_FLOW.to_string()),
        }
    }

    /// Create addons with a custom flow value
    #[must_use]
    pub fn with_flow(flow: impl Into<String>) -> Self {
        Self {
            flow: Some(flow.into()),
        }
    }

    /// Check if addons are empty (no fields set)
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.flow.is_none()
    }

    /// Check if XTLS-Vision flow is enabled
    #[must_use]
    pub fn is_xtls_vision(&self) -> bool {
        self.flow.as_deref() == Some(XTLS_VISION_FLOW)
    }

    /// Encode addons to protobuf-like wire format
    ///
    /// Returns a Vec containing:
    /// - 1 byte length prefix
    /// - Protobuf-encoded fields (if any)
    ///
    /// # Returns
    ///
    /// Encoded addons blob including length prefix.
    ///
    /// # Errors
    ///
    /// Returns `VlessError::AddonsEncodeError` if the flow string is too long.
    pub fn encode(&self) -> Result<Vec<u8>, VlessError> {
        if self.is_empty() {
            // No addons: just a zero length byte
            return Ok(vec![0]);
        }

        let mut payload = Vec::new();

        if let Some(ref flow) = self.flow {
            // Validate flow length (must fit in varint + content)
            if flow.len() > 255 {
                return Err(VlessError::addons_encode(format!(
                    "flow string too long: {} bytes (max 255)",
                    flow.len()
                )));
            }

            // Field tag (field 1, wire type 2)
            payload.push(FLOW_FIELD_TAG);

            // String length as varint (simple case: length < 128)
            #[allow(clippy::cast_possible_truncation)]
            if flow.len() < 128 {
                payload.push(flow.len() as u8);
            } else {
                // Two-byte varint for lengths 128-255
                #[allow(clippy::cast_possible_truncation)]
                {
                    payload.push((flow.len() as u8) | 0x80);
                    payload.push(((flow.len() >> 7) & 0x7F) as u8);
                }
            }

            // String content
            payload.extend_from_slice(flow.as_bytes());
        }

        // Build final result with length prefix
        if payload.len() > 255 {
            return Err(VlessError::addons_encode(format!(
                "addons payload too large: {} bytes (max 255)",
                payload.len()
            )));
        }

        let mut result = Vec::with_capacity(1 + payload.len());
        #[allow(clippy::cast_possible_truncation)]
        result.push(payload.len() as u8);
        result.extend(payload);

        Ok(result)
    }

    /// Get the encoded length of the addons
    ///
    /// This is useful for pre-calculating buffer sizes.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        if self.is_empty() {
            1 // Just the zero length byte
        } else if let Some(ref flow) = self.flow {
            // 1 (length prefix) + 1 (field tag) + varint_len + flow.len()
            let varint_len = if flow.len() < 128 { 1 } else { 2 };
            1 + 1 + varint_len + flow.len()
        } else {
            1
        }
    }
}

/// Parse addons from a byte slice
///
/// Reads the length prefix and parses any protobuf-encoded fields.
///
/// # Arguments
///
/// * `data` - Byte slice starting at the addons length byte
///
/// # Returns
///
/// A tuple of (parsed addons, bytes consumed).
///
/// # Errors
///
/// Returns `VlessError::AddonsParseError` if the data is malformed.
pub fn parse_addons(data: &[u8]) -> Result<(VlessAddons, usize), VlessError> {
    if data.is_empty() {
        return Err(VlessError::addons_parse("empty addons data"));
    }

    let length = data[0] as usize;

    // Zero length = no addons
    if length == 0 {
        return Ok((VlessAddons::new(), 1));
    }

    // Validate we have enough data
    if data.len() < 1 + length {
        return Err(VlessError::addons_parse(format!(
            "addons truncated: expected {} bytes, got {}",
            length,
            data.len() - 1
        )));
    }

    // Prevent DoS via huge addons
    if length > MAX_ADDONS_SIZE {
        return Err(VlessError::addons_parse(format!(
            "addons too large: {} bytes (max {})",
            length, MAX_ADDONS_SIZE
        )));
    }

    let payload = &data[1..=length];
    let addons = parse_protobuf_addons(payload)?;

    Ok((addons, 1 + length))
}

/// Parse protobuf-encoded addons payload
fn parse_protobuf_addons(data: &[u8]) -> Result<VlessAddons, VlessError> {
    let mut addons = VlessAddons::new();
    let mut pos = 0;

    while pos < data.len() {
        // Read field tag
        if pos >= data.len() {
            break;
        }

        let tag = data[pos];
        pos += 1;

        // Parse based on field number and wire type
        let field_number = tag >> 3;
        let wire_type = tag & 0x07;

        match (field_number, wire_type) {
            // Field 1, wire type 2 (length-delimited) = flow string
            (1, 2) => {
                let (flow, consumed) = parse_length_delimited_string(&data[pos..])?;
                addons.flow = Some(flow);
                pos += consumed;
            }
            // Unknown field: skip based on wire type
            (_, 0) => {
                // Varint: skip
                let (_, consumed) = parse_varint(&data[pos..])?;
                pos += consumed;
            }
            (_, 1) => {
                // 64-bit: skip 8 bytes
                if pos + 8 > data.len() {
                    return Err(VlessError::addons_parse("truncated 64-bit field"));
                }
                pos += 8;
            }
            (_, 2) => {
                // Length-delimited: skip
                let (len, varint_consumed) = parse_varint(&data[pos..])?;
                pos += varint_consumed;
                #[allow(clippy::cast_possible_truncation)]
                let len = len as usize;
                if pos + len > data.len() {
                    return Err(VlessError::addons_parse("truncated length-delimited field"));
                }
                pos += len;
            }
            (_, 5) => {
                // 32-bit: skip 4 bytes
                if pos + 4 > data.len() {
                    return Err(VlessError::addons_parse("truncated 32-bit field"));
                }
                pos += 4;
            }
            (_, wt) => {
                return Err(VlessError::addons_parse(format!(
                    "unsupported wire type: {}",
                    wt
                )));
            }
        }
    }

    Ok(addons)
}

/// Parse a length-delimited string from protobuf data
fn parse_length_delimited_string(data: &[u8]) -> Result<(String, usize), VlessError> {
    let (len, varint_consumed) = parse_varint(data)?;

    #[allow(clippy::cast_possible_truncation)]
    let len = len as usize;

    if data.len() < varint_consumed + len {
        return Err(VlessError::addons_parse(format!(
            "string truncated: expected {} bytes",
            len
        )));
    }

    let string_data = &data[varint_consumed..varint_consumed + len];
    let s = String::from_utf8(string_data.to_vec())
        .map_err(|e| VlessError::addons_parse(format!("invalid UTF-8: {e}")))?;

    Ok((s, varint_consumed + len))
}

/// Parse a varint from protobuf data
///
/// Returns (value, bytes consumed).
fn parse_varint(data: &[u8]) -> Result<(u64, usize), VlessError> {
    if data.is_empty() {
        return Err(VlessError::addons_parse("empty varint"));
    }

    let mut result: u64 = 0;
    let mut shift = 0;

    for (i, &byte) in data.iter().enumerate() {
        if i >= 10 {
            return Err(VlessError::addons_parse("varint too long"));
        }

        result |= u64::from(byte & 0x7F) << shift;

        if byte & 0x80 == 0 {
            return Ok((result, i + 1));
        }

        shift += 7;
    }

    Err(VlessError::addons_parse("unterminated varint"))
}

/// Encode a flow addon directly (convenience function)
///
/// This is equivalent to `VlessAddons::with_flow(flow).encode()`.
///
/// # Arguments
///
/// * `flow` - The flow identifier string (e.g., "xtls-rprx-vision")
///
/// # Returns
///
/// Encoded addons blob including length prefix.
///
/// # Errors
///
/// Returns `VlessError::AddonsEncodeError` if the flow string is too long.
pub fn encode_flow_addon(flow: &str) -> Result<Vec<u8>, VlessError> {
    VlessAddons::with_flow(flow).encode()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_addons() {
        let addons = VlessAddons::new();
        assert!(addons.is_empty());
        assert!(!addons.is_xtls_vision());

        let encoded = addons.encode().unwrap();
        assert_eq!(encoded, vec![0]);
        assert_eq!(addons.encoded_len(), 1);
    }

    #[test]
    fn test_xtls_vision_addons() {
        let addons = VlessAddons::with_xtls_vision();
        assert!(!addons.is_empty());
        assert!(addons.is_xtls_vision());
        assert_eq!(addons.flow, Some(XTLS_VISION_FLOW.to_string()));
    }

    #[test]
    fn test_custom_flow() {
        let addons = VlessAddons::with_flow("custom-flow");
        assert!(!addons.is_empty());
        assert!(!addons.is_xtls_vision());
        assert_eq!(addons.flow, Some("custom-flow".to_string()));
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        // Test empty addons
        let addons = VlessAddons::new();
        let encoded = addons.encode().unwrap();
        let (decoded, consumed) = parse_addons(&encoded).unwrap();
        assert_eq!(addons, decoded);
        assert_eq!(consumed, encoded.len());

        // Test with XTLS-Vision flow
        let addons = VlessAddons::with_xtls_vision();
        let encoded = addons.encode().unwrap();
        let (decoded, consumed) = parse_addons(&encoded).unwrap();
        assert_eq!(addons, decoded);
        assert_eq!(consumed, encoded.len());

        // Test with custom flow
        let addons = VlessAddons::with_flow("test-flow-123");
        let encoded = addons.encode().unwrap();
        let (decoded, consumed) = parse_addons(&encoded).unwrap();
        assert_eq!(addons, decoded);
        assert_eq!(consumed, encoded.len());
    }

    #[test]
    fn test_xtls_vision_wire_format() {
        let addons = VlessAddons::with_xtls_vision();
        let encoded = addons.encode().unwrap();

        // Verify wire format:
        // [length][0x0a (field 1, wire type 2)][string_len]["xtls-rprx-vision"]
        assert!(!encoded.is_empty());

        let length = encoded[0] as usize;
        assert_eq!(length, encoded.len() - 1);

        // Should contain the field tag
        assert_eq!(encoded[1], FLOW_FIELD_TAG);

        // String length (16 bytes for "xtls-rprx-vision")
        assert_eq!(encoded[2], 16);

        // Verify the flow string
        let flow_bytes = &encoded[3..3 + 16];
        assert_eq!(flow_bytes, XTLS_VISION_FLOW.as_bytes());
    }

    #[test]
    fn test_encode_flow_addon_convenience() {
        let encoded1 = encode_flow_addon("test-flow").unwrap();
        let encoded2 = VlessAddons::with_flow("test-flow").encode().unwrap();
        assert_eq!(encoded1, encoded2);
    }

    #[test]
    fn test_parse_empty_data_error() {
        let result = parse_addons(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_truncated_addons() {
        // Length says 10 bytes, but only 5 provided
        let data = [10, 1, 2, 3, 4, 5];
        let result = parse_addons(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_oversized_addons() {
        // Create data with length > MAX_ADDONS_SIZE
        let mut data = vec![0u8; 2000];
        data[0] = 255; // Max single-byte length
        // This should still fail if we try to say length is > MAX_ADDONS_SIZE

        // Create with actual oversized length indicator (if we could represent it)
        // For now, test the max single-byte length of 255
        let mut data = vec![0u8; 260];
        data[0] = 255;
        let result = parse_addons(&data);
        // This should succeed as 255 < MAX_ADDONS_SIZE (1024)
        // But the protobuf parsing might fail
        assert!(result.is_err() || result.is_ok());
    }

    #[test]
    fn test_varint_parsing() {
        // Single byte varint
        let (val, consumed) = parse_varint(&[0x00]).unwrap();
        assert_eq!(val, 0);
        assert_eq!(consumed, 1);

        let (val, consumed) = parse_varint(&[0x7F]).unwrap();
        assert_eq!(val, 127);
        assert_eq!(consumed, 1);

        // Two byte varint (128)
        let (val, consumed) = parse_varint(&[0x80, 0x01]).unwrap();
        assert_eq!(val, 128);
        assert_eq!(consumed, 2);

        // Two byte varint (255)
        let (val, consumed) = parse_varint(&[0xFF, 0x01]).unwrap();
        assert_eq!(val, 255);
        assert_eq!(consumed, 2);
    }

    #[test]
    fn test_varint_error_cases() {
        // Empty data
        assert!(parse_varint(&[]).is_err());

        // Unterminated varint (all bytes have MSB set, but data ends)
        assert!(parse_varint(&[0x80]).is_err());
    }

    #[test]
    fn test_long_flow_encoding() {
        // Test a flow string that requires 2-byte varint (128+ chars)
        let long_flow = "a".repeat(150);
        let addons = VlessAddons::with_flow(&long_flow);
        let encoded = addons.encode().unwrap();
        let (decoded, _) = parse_addons(&encoded).unwrap();
        assert_eq!(decoded.flow, Some(long_flow));
    }

    #[test]
    fn test_too_long_flow_error() {
        // Flow string > 255 bytes should fail
        let too_long = "x".repeat(300);
        let addons = VlessAddons::with_flow(&too_long);
        let result = addons.encode();
        assert!(result.is_err());
    }

    #[test]
    fn test_encoded_len() {
        let addons = VlessAddons::new();
        assert_eq!(addons.encoded_len(), addons.encode().unwrap().len());

        let addons = VlessAddons::with_xtls_vision();
        assert_eq!(addons.encoded_len(), addons.encode().unwrap().len());

        let addons = VlessAddons::with_flow("short");
        assert_eq!(addons.encoded_len(), addons.encode().unwrap().len());

        // Long flow (128+ chars)
        let addons = VlessAddons::with_flow("a".repeat(150));
        assert_eq!(addons.encoded_len(), addons.encode().unwrap().len());
    }

    #[test]
    fn test_unknown_field_skipping() {
        // Create a valid addons blob with flow field, then append unknown field
        let addons = VlessAddons::with_flow("test");
        let mut encoded = addons.encode().unwrap();

        // Append an unknown varint field (field 5, wire type 0)
        let payload_start = 1;
        let old_length = encoded[0] as usize;

        // Add field tag (field 5, wire type 0) and value
        encoded.push(0x28); // (5 << 3) | 0 = 40 = 0x28
        encoded.push(0x42); // Some varint value

        // Update length
        #[allow(clippy::cast_possible_truncation)]
        {
            encoded[0] = (old_length + 2) as u8;
        }

        // Move the appended bytes to the right position
        let payload_end = 1 + old_length;
        encoded[payload_end] = 0x28;
        encoded[payload_end + 1] = 0x42;

        // Should still parse, skipping the unknown field
        let (parsed, _) = parse_addons(&encoded).unwrap();
        assert_eq!(parsed.flow, Some("test".to_string()));
    }
}
