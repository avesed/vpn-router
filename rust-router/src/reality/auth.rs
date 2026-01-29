//! REALITY Authentication
//!
//! This module implements REALITY-specific authentication including:
//! - SessionId structure and encryption
//! - Timestamp validation
//! - Short ID handling
//! - Authentication key derivation

use std::time::{SystemTime, UNIX_EPOCH};

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use hkdf::Hkdf;
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::reality::common::{
    REALITY_AUTH_INFO, REALITY_AUTH_KEY_SIZE,
    REALITY_NONCE_SIZE, REALITY_SALT_SIZE, REALITY_SESSION_ID_PLAINTEXT_SIZE,
    REALITY_SESSION_ID_SIZE, REALITY_SHORT_ID_SIZE,
};
use crate::reality::crypto::perform_ecdh;
use crate::reality::error::{RealityError, RealityResult};

/// REALITY SessionId structure
///
/// The SessionId is a 32-byte value embedded in the TLS ClientHello.
/// The first 16 bytes are encrypted, and the remaining 16 bytes are the GCM tag.
///
/// Plaintext structure (16 bytes):
/// ```text
/// [0..3]   version      - Protocol version (major, minor, patch)
/// [3]      reserved     - Reserved byte (0)
/// [4..8]   timestamp    - Unix timestamp (seconds, big-endian u32)
/// [8..16]  short_id     - Authentication ID (8 bytes)
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionId {
    /// Protocol version (major, minor, patch)
    pub version: [u8; 3],
    /// Reserved byte
    pub reserved: u8,
    /// Unix timestamp (seconds)
    pub timestamp: u32,
    /// Short ID for authentication
    pub short_id: [u8; REALITY_SHORT_ID_SIZE],
}

impl SessionId {
    /// Create a new SessionId with current timestamp
    pub fn new(version: [u8; 3], short_id: [u8; REALITY_SHORT_ID_SIZE]) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as u32)
            .unwrap_or(0);

        Self {
            version,
            reserved: 0,
            timestamp,
            short_id,
        }
    }

    /// Create a SessionId with explicit timestamp (for testing)
    pub fn with_timestamp(
        version: [u8; 3],
        timestamp: u32,
        short_id: [u8; REALITY_SHORT_ID_SIZE],
    ) -> Self {
        Self {
            version,
            reserved: 0,
            timestamp,
            short_id,
        }
    }

    /// Encode SessionId to 16-byte plaintext
    pub fn to_plaintext(&self) -> [u8; REALITY_SESSION_ID_PLAINTEXT_SIZE] {
        let mut plaintext = [0u8; REALITY_SESSION_ID_PLAINTEXT_SIZE];
        plaintext[0] = self.version[0];
        plaintext[1] = self.version[1];
        plaintext[2] = self.version[2];
        plaintext[3] = self.reserved;
        plaintext[4..8].copy_from_slice(&self.timestamp.to_be_bytes());
        plaintext[8..16].copy_from_slice(&self.short_id);
        plaintext
    }

    /// Decode SessionId from 16-byte plaintext
    pub fn from_plaintext(plaintext: &[u8; REALITY_SESSION_ID_PLAINTEXT_SIZE]) -> Self {
        let mut version = [0u8; 3];
        version.copy_from_slice(&plaintext[0..3]);

        let timestamp = u32::from_be_bytes([plaintext[4], plaintext[5], plaintext[6], plaintext[7]]);

        let mut short_id = [0u8; REALITY_SHORT_ID_SIZE];
        short_id.copy_from_slice(&plaintext[8..16]);

        Self {
            version,
            reserved: plaintext[3],
            timestamp,
            short_id,
        }
    }

    /// Validate timestamp is within acceptable range
    ///
    /// # Arguments
    /// * `max_diff_ms` - Maximum allowed time difference in milliseconds
    ///
    /// # Returns
    /// * `Ok(())` if timestamp is valid
    /// * `Err` if timestamp is too old or too far in the future
    pub fn validate_timestamp(&self, max_diff_ms: u64) -> RealityResult<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as u32)
            .unwrap_or(0);

        let max_diff_secs = (max_diff_ms / 1000) as u32;
        let diff = now.abs_diff(self.timestamp);

        if diff > max_diff_secs {
            return Err(RealityError::AuthenticationFailed);
        }

        Ok(())
    }

    /// Validate that short_id matches one of the allowed values
    ///
    /// This uses constant-time comparison to prevent timing side-channel attacks.
    /// An attacker cannot determine which bytes of the short_id are correct
    /// by measuring response times.
    pub fn validate_short_id(&self, allowed: &[[u8; REALITY_SHORT_ID_SIZE]]) -> RealityResult<()> {
        // Use constant-time comparison to prevent timing attacks.
        // We check all allowed IDs regardless of whether we find a match,
        // ensuring the same execution time for valid and invalid short_ids.
        let mut found = subtle::Choice::from(0u8);

        for allowed_id in allowed {
            // Constant-time equality check
            let eq = self.short_id.ct_eq(allowed_id);
            // Accumulate matches using constant-time OR
            found = found | eq;
        }

        if bool::from(found) {
            Ok(())
        } else {
            Err(RealityError::AuthenticationFailed)
        }
    }
}

/// Derive REALITY authentication key using HKDF-SHA256
///
/// # Arguments
/// * `shared_secret` - 32-byte X25519 shared secret
/// * `salt` - 20 bytes from ClientHello.Random[0..20]
/// * `info` - Context string (default: b"REALITY")
///
/// # Returns
/// 32-byte authentication key for AES-256-GCM
pub fn derive_auth_key(
    shared_secret: &[u8; 32],
    salt: &[u8],
    info: &[u8],
) -> RealityResult<[u8; REALITY_AUTH_KEY_SIZE]> {
    if salt.len() != REALITY_SALT_SIZE {
        return Err(RealityError::key_derivation(format!(
            "Invalid salt length: {} (expected {})",
            salt.len(),
            REALITY_SALT_SIZE
        )));
    }

    let hk = Hkdf::<Sha256>::new(Some(salt), shared_secret);

    let mut auth_key = [0u8; REALITY_AUTH_KEY_SIZE];
    hk.expand(info, &mut auth_key)
        .map_err(|e| RealityError::key_derivation(format!("HKDF expand failed: {:?}", e)))?;

    Ok(auth_key)
}

/// Encrypt SessionId using AES-256-GCM
///
/// # Arguments
/// * `plaintext` - 16-byte SessionId plaintext
/// * `auth_key` - 32-byte authentication key
/// * `nonce` - 12-byte nonce from ClientHello.Random[20..32]
/// * `aad` - Additional authenticated data (ClientHello with zeroed SessionId)
///
/// # Returns
/// 32-byte encrypted SessionId (16 ciphertext + 16 tag)
pub fn encrypt_session_id(
    plaintext: &[u8; REALITY_SESSION_ID_PLAINTEXT_SIZE],
    auth_key: &[u8; REALITY_AUTH_KEY_SIZE],
    nonce: &[u8],
    aad: &[u8],
) -> RealityResult<[u8; REALITY_SESSION_ID_SIZE]> {
    if nonce.len() != REALITY_NONCE_SIZE {
        return Err(RealityError::key_derivation(format!(
            "Invalid nonce length: {} (expected {})",
            nonce.len(),
            REALITY_NONCE_SIZE
        )));
    }

    let cipher = Aes256Gcm::new(auth_key.into());
    let nonce_obj = Nonce::from_slice(nonce);

    let ciphertext = cipher
        .encrypt(
            nonce_obj,
            aes_gcm::aead::Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| RealityError::protocol("SessionId encryption failed"))?;

    if ciphertext.len() != REALITY_SESSION_ID_SIZE {
        return Err(RealityError::protocol(format!(
            "Unexpected ciphertext length: {} (expected {})",
            ciphertext.len(),
            REALITY_SESSION_ID_SIZE
        )));
    }

    let mut result = [0u8; REALITY_SESSION_ID_SIZE];
    result.copy_from_slice(&ciphertext);
    Ok(result)
}

/// Decrypt SessionId using AES-256-GCM
///
/// # Arguments
/// * `ciphertext` - 32-byte encrypted SessionId (16 ciphertext + 16 tag)
/// * `auth_key` - 32-byte authentication key
/// * `nonce` - 12-byte nonce from ClientHello.Random[20..32]
/// * `aad` - Additional authenticated data (ClientHello with zeroed SessionId)
///
/// # Returns
/// Decrypted SessionId structure
pub fn decrypt_session_id(
    ciphertext: &[u8; REALITY_SESSION_ID_SIZE],
    auth_key: &[u8; REALITY_AUTH_KEY_SIZE],
    nonce: &[u8],
    aad: &[u8],
) -> RealityResult<SessionId> {
    if nonce.len() != REALITY_NONCE_SIZE {
        return Err(RealityError::key_derivation(format!(
            "Invalid nonce length: {} (expected {})",
            nonce.len(),
            REALITY_NONCE_SIZE
        )));
    }

    let cipher = Aes256Gcm::new(auth_key.into());
    let nonce_obj = Nonce::from_slice(nonce);

    let plaintext = cipher
        .decrypt(
            nonce_obj,
            aes_gcm::aead::Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| RealityError::AuthenticationFailed)?;

    if plaintext.len() != REALITY_SESSION_ID_PLAINTEXT_SIZE {
        return Err(RealityError::protocol("Invalid decrypted SessionId length"));
    }

    let mut plaintext_arr = [0u8; REALITY_SESSION_ID_PLAINTEXT_SIZE];
    plaintext_arr.copy_from_slice(&plaintext);

    Ok(SessionId::from_plaintext(&plaintext_arr))
}

/// Validate complete REALITY authentication
///
/// Performs ECDH, derives auth key, decrypts SessionId, and validates.
///
/// # Arguments
/// * `client_random` - 32-byte ClientHello.Random
/// * `encrypted_session_id` - 32-byte encrypted SessionId from ClientHello
/// * `server_private_key` - Server's X25519 private key
/// * `client_public_key` - Client's X25519 public key (from key_share extension)
/// * `allowed_short_ids` - List of allowed short IDs
/// * `max_time_diff_ms` - Maximum timestamp difference in milliseconds
/// * `client_hello_aad` - ClientHello with zeroed SessionId for AAD
///
/// # Returns
/// * `Ok(SessionId)` if authentication succeeds
/// * `Err(AuthenticationFailed)` if any step fails
pub fn validate_auth(
    client_random: &[u8; 32],
    encrypted_session_id: &[u8; REALITY_SESSION_ID_SIZE],
    server_private_key: &[u8; 32],
    client_public_key: &[u8; 32],
    allowed_short_ids: &[[u8; REALITY_SHORT_ID_SIZE]],
    max_time_diff_ms: u64,
    client_hello_aad: &[u8],
) -> RealityResult<SessionId> {
    // 1. Perform ECDH
    let shared_secret = perform_ecdh(server_private_key, client_public_key)?;

    // 2. Derive auth key
    let salt = &client_random[0..REALITY_SALT_SIZE];
    let auth_key = derive_auth_key(&shared_secret, salt, REALITY_AUTH_INFO)?;

    // 3. Decrypt SessionId
    let nonce = &client_random[REALITY_SALT_SIZE..32];
    let session_id = decrypt_session_id(encrypted_session_id, &auth_key, nonce, client_hello_aad)?;

    // 4. Validate timestamp
    session_id.validate_timestamp(max_time_diff_ms)?;

    // 5. Validate short_id
    session_id.validate_short_id(allowed_short_ids)?;

    Ok(session_id)
}

/// Decode hex-encoded short ID with padding
///
/// Handles short IDs with fewer than 8 bytes by zero-padding on the right.
///
/// # Arguments
/// * `hex_str` - Hex-encoded short ID (up to 16 characters)
///
/// # Returns
/// 8-byte short ID array
pub fn decode_short_id(hex_str: &str) -> RealityResult<[u8; REALITY_SHORT_ID_SIZE]> {
    if hex_str.is_empty() {
        return Err(RealityError::invalid_short_id("Short ID cannot be empty"));
    }

    if hex_str.len() > 16 {
        return Err(RealityError::invalid_short_id(format!(
            "Short ID too long: {} chars (max 16)",
            hex_str.len()
        )));
    }

    let decoded = hex::decode(hex_str)
        .map_err(|e| RealityError::invalid_short_id(format!("Invalid hex: {}", e)))?;

    let mut short_id = [0u8; REALITY_SHORT_ID_SIZE];
    let copy_len = decoded.len().min(REALITY_SHORT_ID_SIZE);
    short_id[..copy_len].copy_from_slice(&decoded[..copy_len]);

    Ok(short_id)
}

/// Get current Unix timestamp in seconds
pub fn current_timestamp() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reality::crypto::{generate_keypair, random_bytes};

    #[test]
    fn test_session_id_encode_decode() {
        let version = [1, 8, 1];
        let short_id = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];

        let session_id = SessionId::with_timestamp(version, 1234567890, short_id);

        let plaintext = session_id.to_plaintext();
        let decoded = SessionId::from_plaintext(&plaintext);

        assert_eq!(decoded.version, version);
        assert_eq!(decoded.timestamp, 1234567890);
        assert_eq!(decoded.short_id, short_id);
        assert_eq!(decoded.reserved, 0);
    }

    #[test]
    fn test_session_id_plaintext_structure() {
        let version = [1, 8, 1];
        let timestamp = 0x12345678u32;
        let short_id = [0xAB; 8];

        let session_id = SessionId::with_timestamp(version, timestamp, short_id);
        let plaintext = session_id.to_plaintext();

        // Check structure
        assert_eq!(plaintext[0], 1); // version major
        assert_eq!(plaintext[1], 8); // version minor
        assert_eq!(plaintext[2], 1); // version patch
        assert_eq!(plaintext[3], 0); // reserved

        // Timestamp (big-endian)
        assert_eq!(
            u32::from_be_bytes([plaintext[4], plaintext[5], plaintext[6], plaintext[7]]),
            timestamp
        );

        // Short ID
        assert_eq!(&plaintext[8..16], &short_id);
    }

    #[test]
    fn test_derive_auth_key() {
        let shared_secret = [0x42u8; 32];
        let salt = [0x43u8; 20];

        let auth_key = derive_auth_key(&shared_secret, &salt, REALITY_AUTH_INFO).unwrap();

        assert_eq!(auth_key.len(), 32);

        // Should be deterministic
        let auth_key2 = derive_auth_key(&shared_secret, &salt, REALITY_AUTH_INFO).unwrap();
        assert_eq!(auth_key, auth_key2);

        // Different salt should produce different key
        let salt2 = [0x44u8; 20];
        let auth_key3 = derive_auth_key(&shared_secret, &salt2, REALITY_AUTH_INFO).unwrap();
        assert_ne!(auth_key, auth_key3);
    }

    #[test]
    fn test_encrypt_decrypt_session_id() {
        let auth_key = [0x42u8; 32];
        let nonce = [0x99u8; 12];
        let aad = b"additional authenticated data";

        let version = [1, 8, 1];
        let short_id = [0xAB; 8];
        let session_id = SessionId::with_timestamp(version, current_timestamp(), short_id);

        let plaintext = session_id.to_plaintext();
        let encrypted = encrypt_session_id(&plaintext, &auth_key, &nonce, aad).unwrap();

        assert_eq!(encrypted.len(), 32);

        let decrypted = decrypt_session_id(&encrypted, &auth_key, &nonce, aad).unwrap();

        assert_eq!(decrypted.version, version);
        assert_eq!(decrypted.short_id, short_id);
        assert_eq!(decrypted.timestamp, session_id.timestamp);
    }

    #[test]
    fn test_decrypt_wrong_key_fails() {
        let auth_key = [0x42u8; 32];
        let wrong_key = [0x43u8; 32];
        let nonce = [0x99u8; 12];
        let aad = b"aad";

        let session_id = SessionId::new([1, 8, 1], [0xAB; 8]);
        let plaintext = session_id.to_plaintext();
        let encrypted = encrypt_session_id(&plaintext, &auth_key, &nonce, aad).unwrap();

        let result = decrypt_session_id(&encrypted, &wrong_key, &nonce, aad);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_wrong_aad_fails() {
        let auth_key = [0x42u8; 32];
        let nonce = [0x99u8; 12];
        let aad = b"correct aad";
        let wrong_aad = b"wrong aad";

        let session_id = SessionId::new([1, 8, 1], [0xAB; 8]);
        let plaintext = session_id.to_plaintext();
        let encrypted = encrypt_session_id(&plaintext, &auth_key, &nonce, aad).unwrap();

        let result = decrypt_session_id(&encrypted, &auth_key, &nonce, wrong_aad);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_timestamp_valid() {
        let now = current_timestamp();
        let session_id = SessionId::with_timestamp([1, 8, 1], now, [0xAB; 8]);

        // Current timestamp should be valid
        assert!(session_id.validate_timestamp(REALITY_DEFAULT_MAX_TIME_DIFF_MS).is_ok());

        // 30 seconds ago should be valid
        let past = SessionId::with_timestamp([1, 8, 1], now - 30, [0xAB; 8]);
        assert!(past.validate_timestamp(REALITY_DEFAULT_MAX_TIME_DIFF_MS).is_ok());

        // 30 seconds in future should be valid
        let future = SessionId::with_timestamp([1, 8, 1], now + 30, [0xAB; 8]);
        assert!(future.validate_timestamp(REALITY_DEFAULT_MAX_TIME_DIFF_MS).is_ok());
    }

    #[test]
    fn test_validate_timestamp_invalid() {
        let now = current_timestamp();

        // 2 minutes ago should fail (default is 60 seconds)
        let old = SessionId::with_timestamp([1, 8, 1], now.saturating_sub(120), [0xAB; 8]);
        assert!(old.validate_timestamp(REALITY_DEFAULT_MAX_TIME_DIFF_MS).is_err());

        // 2 minutes in future should fail
        let future = SessionId::with_timestamp([1, 8, 1], now + 120, [0xAB; 8]);
        assert!(future.validate_timestamp(REALITY_DEFAULT_MAX_TIME_DIFF_MS).is_err());
    }

    #[test]
    fn test_validate_short_id() {
        let short_id = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];
        let session_id = SessionId::new([1, 8, 1], short_id);

        let allowed = vec![
            [0xAA; 8],
            short_id,
            [0xBB; 8],
        ];

        // Should pass - short_id is in allowed list
        assert!(session_id.validate_short_id(&allowed).is_ok());

        // Should fail - short_id not in allowed list
        let not_allowed = vec![[0xAA; 8], [0xBB; 8]];
        assert!(session_id.validate_short_id(&not_allowed).is_err());
    }

    #[test]
    fn test_decode_short_id() {
        // Full 8 bytes
        let result = decode_short_id("1234567890abcdef").unwrap();
        assert_eq!(result, [0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF]);

        // Partial - should be zero-padded
        let result = decode_short_id("1234").unwrap();
        assert_eq!(result, [0x12, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

        // Empty - should fail
        assert!(decode_short_id("").is_err());

        // Too long - should fail
        assert!(decode_short_id("1234567890abcdef0000").is_err());

        // Invalid hex - should fail
        assert!(decode_short_id("xyz").is_err());
    }

    #[test]
    fn test_validate_auth_full_flow() {
        // Generate key pairs
        let server_keypair = generate_keypair();
        let client_keypair = generate_keypair();

        // Create client random
        let client_random: [u8; 32] = random_bytes();

        // Create session ID
        let short_id = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];
        let session_id = SessionId::new([1, 8, 1], short_id);
        let plaintext = session_id.to_plaintext();

        // Derive auth key from client's perspective
        let shared_secret =
            perform_ecdh(&client_keypair.private_key_bytes(), server_keypair.public_key().as_bytes()).unwrap();
        let auth_key = derive_auth_key(&shared_secret, &client_random[0..20], REALITY_AUTH_INFO).unwrap();

        // Encrypt session ID
        let nonce = &client_random[20..32];
        let aad = b"simulated client hello";
        let encrypted_session_id = encrypt_session_id(&plaintext, &auth_key, nonce, aad).unwrap();

        // Validate from server's perspective
        let allowed_short_ids = vec![short_id];
        let result = validate_auth(
            &client_random,
            &encrypted_session_id,
            &server_keypair.private_key_bytes(),
            client_keypair.public_key().as_bytes(),
            &allowed_short_ids,
            REALITY_DEFAULT_MAX_TIME_DIFF_MS,
            aad,
        );

        assert!(result.is_ok());
        let validated = result.unwrap();
        assert_eq!(validated.short_id, short_id);
    }

    #[test]
    fn test_validate_auth_wrong_short_id() {
        let server_keypair = generate_keypair();
        let client_keypair = generate_keypair();
        let client_random: [u8; 32] = random_bytes();

        let short_id = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];
        let session_id = SessionId::new([1, 8, 1], short_id);
        let plaintext = session_id.to_plaintext();

        let shared_secret =
            perform_ecdh(&client_keypair.private_key_bytes(), server_keypair.public_key().as_bytes()).unwrap();
        let auth_key = derive_auth_key(&shared_secret, &client_random[0..20], REALITY_AUTH_INFO).unwrap();

        let nonce = &client_random[20..32];
        let aad = b"client hello";
        let encrypted_session_id = encrypt_session_id(&plaintext, &auth_key, nonce, aad).unwrap();

        // Different allowed short IDs
        let allowed_short_ids = vec![[0xFF; 8]];
        let result = validate_auth(
            &client_random,
            &encrypted_session_id,
            &server_keypair.private_key_bytes(),
            client_keypair.public_key().as_bytes(),
            &allowed_short_ids,
            REALITY_DEFAULT_MAX_TIME_DIFF_MS,
            aad,
        );

        assert!(result.is_err());
    }
}
