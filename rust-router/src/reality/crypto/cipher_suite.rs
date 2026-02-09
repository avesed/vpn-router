//! TLS 1.3 Cipher Suite definitions for REALITY protocol
//!
//! This module defines the CipherSuite type which bundles cipher suite ID
//! with its associated algorithms for AEAD encryption and HKDF key derivation.
//!
//! Supported cipher suites:
//! - TLS_AES_128_GCM_SHA256 (0x1301)
//! - TLS_AES_256_GCM_SHA384 (0x1302)
//! - TLS_CHACHA20_POLY1305_SHA256 (0x1303)

use crate::reality::error::{RealityError, RealityResult};

/// Default TLS 1.3 cipher suites in preference order
pub const DEFAULT_CIPHER_SUITES: &[CipherSuite] = &[
    CipherSuite::AES_128_GCM_SHA256,
    CipherSuite::AES_256_GCM_SHA384,
    CipherSuite::CHACHA20_POLY1305_SHA256,
];

/// TLS 1.3 Cipher Suite with all associated parameters
///
/// This struct bundles the cipher suite ID with its corresponding:
/// - AEAD key length
/// - Hash algorithm (for transcript hashing and HKDF)
/// - Nonce/IV length (always 12 for TLS 1.3)
///
/// Per RFC 8446, different cipher suites require different hash algorithms:
/// - TLS_AES_128_GCM_SHA256 (0x1301): SHA256, 16-byte key
/// - TLS_AES_256_GCM_SHA384 (0x1302): SHA384, 32-byte key
/// - TLS_CHACHA20_POLY1305_SHA256 (0x1303): SHA256, 32-byte key
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CipherSuite {
    id: u16,
    key_len: usize,
    hash_len: usize,
    hash_algorithm: HashAlgorithm,
}

/// Hash algorithm for a cipher suite
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HashAlgorithm {
    Sha256,
    Sha384,
}

impl CipherSuite {
    /// TLS_AES_128_GCM_SHA256 (0x1301)
    pub const AES_128_GCM_SHA256: Self = Self {
        id: 0x1301,
        key_len: 16,
        hash_len: 32,
        hash_algorithm: HashAlgorithm::Sha256,
    };

    /// TLS_AES_256_GCM_SHA384 (0x1302)
    pub const AES_256_GCM_SHA384: Self = Self {
        id: 0x1302,
        key_len: 32,
        hash_len: 48,
        hash_algorithm: HashAlgorithm::Sha384,
    };

    /// TLS_CHACHA20_POLY1305_SHA256 (0x1303)
    pub const CHACHA20_POLY1305_SHA256: Self = Self {
        id: 0x1303,
        key_len: 32,
        hash_len: 32,
        hash_algorithm: HashAlgorithm::Sha256,
    };

    /// Get CipherSuite from wire format ID
    ///
    /// # Arguments
    /// * `id` - TLS cipher suite ID (e.g., 0x1301)
    ///
    /// # Returns
    /// * `Some(CipherSuite)` if ID is supported
    /// * `None` if ID is not a supported TLS 1.3 cipher suite
    #[must_use]
    pub fn from_id(id: u16) -> Option<Self> {
        match id {
            0x1301 => Some(Self::AES_128_GCM_SHA256),
            0x1302 => Some(Self::AES_256_GCM_SHA384),
            0x1303 => Some(Self::CHACHA20_POLY1305_SHA256),
            _ => None,
        }
    }

    /// Get CipherSuite from standard TLS name
    ///
    /// # Arguments
    /// * `name` - Standard TLS cipher suite name
    ///
    /// # Returns
    /// * `Some(CipherSuite)` if name is recognized
    /// * `None` if name is not a supported cipher suite
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "TLS_AES_128_GCM_SHA256" => Some(Self::AES_128_GCM_SHA256),
            "TLS_AES_256_GCM_SHA384" => Some(Self::AES_256_GCM_SHA384),
            "TLS_CHACHA20_POLY1305_SHA256" => Some(Self::CHACHA20_POLY1305_SHA256),
            _ => None,
        }
    }

    /// Get standard TLS name for this cipher suite
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self.id {
            0x1301 => "TLS_AES_128_GCM_SHA256",
            0x1302 => "TLS_AES_256_GCM_SHA384",
            0x1303 => "TLS_CHACHA20_POLY1305_SHA256",
            _ => "UNKNOWN",
        }
    }

    /// Wire format ID (e.g., 0x1301)
    #[inline]
    #[must_use]
    pub fn id(&self) -> u16 {
        self.id
    }

    /// AEAD key length in bytes (16 for AES-128, 32 for AES-256/ChaCha20)
    #[inline]
    #[must_use]
    pub fn key_len(&self) -> usize {
        self.key_len
    }

    /// Nonce/IV length in bytes (always 12 for TLS 1.3)
    #[inline]
    #[must_use]
    pub fn nonce_len(&self) -> usize {
        12
    }

    /// Hash output length in bytes (32 for SHA256, 48 for SHA384)
    #[inline]
    #[must_use]
    pub fn hash_len(&self) -> usize {
        self.hash_len
    }

    /// Get the hash algorithm for this cipher suite
    #[inline]
    #[must_use]
    pub fn hash_algorithm(&self) -> HashAlgorithm {
        self.hash_algorithm
    }

    /// Check if this cipher suite uses AES-GCM
    #[inline]
    #[must_use]
    pub fn is_aes_gcm(&self) -> bool {
        self.id == 0x1301 || self.id == 0x1302
    }

    /// Check if this cipher suite uses ChaCha20-Poly1305
    #[inline]
    #[must_use]
    pub fn is_chacha20(&self) -> bool {
        self.id == 0x1303
    }

    /// Validate a key length for this cipher suite
    pub fn validate_key_len(&self, key: &[u8]) -> RealityResult<()> {
        if key.len() != self.key_len {
            return Err(RealityError::key_derivation(format!(
                "Invalid key length for {:?}: {} (expected {})",
                self,
                key.len(),
                self.key_len
            )));
        }
        Ok(())
    }
}

impl std::fmt::Debug for CipherSuite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl std::fmt::Display for CipherSuite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl std::fmt::LowerHex for CipherSuite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::LowerHex::fmt(&self.id, f)
    }
}

/// Negotiate cipher suite between client and server offerings
///
/// Returns the first cipher suite from `server_preference` that is also
/// in `client_offered`, or None if no common cipher suite exists.
///
/// # Arguments
/// * `client_offered` - Cipher suite IDs offered by client
/// * `server_preference` - Server's preferred cipher suites (in order)
///
/// # Returns
/// * `Some(CipherSuite)` - First mutually supported cipher suite
/// * `None` - No common cipher suite
#[must_use]
pub fn negotiate_cipher_suite(
    client_offered: &[u16],
    server_preference: &[CipherSuite],
) -> Option<CipherSuite> {
    for &server_cs in server_preference {
        if client_offered.contains(&server_cs.id()) {
            return Some(server_cs);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_id() {
        assert_eq!(
            CipherSuite::from_id(0x1301),
            Some(CipherSuite::AES_128_GCM_SHA256)
        );
        assert_eq!(
            CipherSuite::from_id(0x1302),
            Some(CipherSuite::AES_256_GCM_SHA384)
        );
        assert_eq!(
            CipherSuite::from_id(0x1303),
            Some(CipherSuite::CHACHA20_POLY1305_SHA256)
        );
        assert_eq!(CipherSuite::from_id(0x1304), None);
        assert_eq!(CipherSuite::from_id(0x0000), None);
    }

    #[test]
    fn test_from_name() {
        assert_eq!(
            CipherSuite::from_name("TLS_AES_128_GCM_SHA256"),
            Some(CipherSuite::AES_128_GCM_SHA256)
        );
        assert_eq!(
            CipherSuite::from_name("TLS_AES_256_GCM_SHA384"),
            Some(CipherSuite::AES_256_GCM_SHA384)
        );
        assert_eq!(
            CipherSuite::from_name("TLS_CHACHA20_POLY1305_SHA256"),
            Some(CipherSuite::CHACHA20_POLY1305_SHA256)
        );
        assert_eq!(CipherSuite::from_name("TLS_UNKNOWN"), None);
    }

    #[test]
    fn test_name() {
        assert_eq!(
            CipherSuite::AES_128_GCM_SHA256.name(),
            "TLS_AES_128_GCM_SHA256"
        );
        assert_eq!(
            CipherSuite::AES_256_GCM_SHA384.name(),
            "TLS_AES_256_GCM_SHA384"
        );
        assert_eq!(
            CipherSuite::CHACHA20_POLY1305_SHA256.name(),
            "TLS_CHACHA20_POLY1305_SHA256"
        );
    }

    #[test]
    fn test_key_len() {
        assert_eq!(CipherSuite::AES_128_GCM_SHA256.key_len(), 16);
        assert_eq!(CipherSuite::AES_256_GCM_SHA384.key_len(), 32);
        assert_eq!(CipherSuite::CHACHA20_POLY1305_SHA256.key_len(), 32);
    }

    #[test]
    fn test_hash_len() {
        assert_eq!(CipherSuite::AES_128_GCM_SHA256.hash_len(), 32);
        assert_eq!(CipherSuite::AES_256_GCM_SHA384.hash_len(), 48);
        assert_eq!(CipherSuite::CHACHA20_POLY1305_SHA256.hash_len(), 32);
    }

    #[test]
    fn test_nonce_len() {
        // All TLS 1.3 cipher suites use 12-byte nonce
        assert_eq!(CipherSuite::AES_128_GCM_SHA256.nonce_len(), 12);
        assert_eq!(CipherSuite::AES_256_GCM_SHA384.nonce_len(), 12);
        assert_eq!(CipherSuite::CHACHA20_POLY1305_SHA256.nonce_len(), 12);
    }

    #[test]
    fn test_is_aes_gcm() {
        assert!(CipherSuite::AES_128_GCM_SHA256.is_aes_gcm());
        assert!(CipherSuite::AES_256_GCM_SHA384.is_aes_gcm());
        assert!(!CipherSuite::CHACHA20_POLY1305_SHA256.is_aes_gcm());
    }

    #[test]
    fn test_is_chacha20() {
        assert!(!CipherSuite::AES_128_GCM_SHA256.is_chacha20());
        assert!(!CipherSuite::AES_256_GCM_SHA384.is_chacha20());
        assert!(CipherSuite::CHACHA20_POLY1305_SHA256.is_chacha20());
    }

    #[test]
    fn test_validate_key_len() {
        let key_16 = vec![0u8; 16];
        let key_32 = vec![0u8; 32];
        let key_15 = vec![0u8; 15];

        assert!(CipherSuite::AES_128_GCM_SHA256
            .validate_key_len(&key_16)
            .is_ok());
        assert!(CipherSuite::AES_128_GCM_SHA256
            .validate_key_len(&key_32)
            .is_err());

        assert!(CipherSuite::AES_256_GCM_SHA384
            .validate_key_len(&key_32)
            .is_ok());
        assert!(CipherSuite::AES_256_GCM_SHA384
            .validate_key_len(&key_16)
            .is_err());

        assert!(CipherSuite::CHACHA20_POLY1305_SHA256
            .validate_key_len(&key_32)
            .is_ok());
        assert!(CipherSuite::CHACHA20_POLY1305_SHA256
            .validate_key_len(&key_15)
            .is_err());
    }

    #[test]
    fn test_negotiate_cipher_suite() {
        let client_offered = vec![0x1301, 0x1303];

        // Server prefers AES-256, but client doesn't offer it
        let result = negotiate_cipher_suite(
            &client_offered,
            &[
                CipherSuite::AES_256_GCM_SHA384,
                CipherSuite::AES_128_GCM_SHA256,
            ],
        );
        assert_eq!(result, Some(CipherSuite::AES_128_GCM_SHA256));

        // Server prefers ChaCha20, client offers it
        let result = negotiate_cipher_suite(
            &client_offered,
            &[
                CipherSuite::CHACHA20_POLY1305_SHA256,
                CipherSuite::AES_128_GCM_SHA256,
            ],
        );
        assert_eq!(result, Some(CipherSuite::CHACHA20_POLY1305_SHA256));

        // No common cipher suite
        let client_only_256 = vec![0x1302];
        let result = negotiate_cipher_suite(
            &client_only_256,
            &[
                CipherSuite::AES_128_GCM_SHA256,
                CipherSuite::CHACHA20_POLY1305_SHA256,
            ],
        );
        assert_eq!(result, None);
    }

    #[test]
    fn test_default_cipher_suites() {
        assert_eq!(DEFAULT_CIPHER_SUITES.len(), 3);
        assert_eq!(DEFAULT_CIPHER_SUITES[0], CipherSuite::AES_128_GCM_SHA256);
        assert_eq!(DEFAULT_CIPHER_SUITES[1], CipherSuite::AES_256_GCM_SHA384);
        assert_eq!(
            DEFAULT_CIPHER_SUITES[2],
            CipherSuite::CHACHA20_POLY1305_SHA256
        );
    }

    #[test]
    fn test_debug_display() {
        let cs = CipherSuite::AES_128_GCM_SHA256;
        assert_eq!(format!("{:?}", cs), "TLS_AES_128_GCM_SHA256");
        assert_eq!(format!("{}", cs), "TLS_AES_128_GCM_SHA256");
        assert_eq!(format!("{:x}", cs), "1301");
    }

    #[test]
    fn test_hash_algorithm() {
        assert_eq!(
            CipherSuite::AES_128_GCM_SHA256.hash_algorithm(),
            HashAlgorithm::Sha256
        );
        assert_eq!(
            CipherSuite::AES_256_GCM_SHA384.hash_algorithm(),
            HashAlgorithm::Sha384
        );
        assert_eq!(
            CipherSuite::CHACHA20_POLY1305_SHA256.hash_algorithm(),
            HashAlgorithm::Sha256
        );
    }
}
