//! TLS 1.3 AEAD encryption/decryption for REALITY protocol
//!
//! Supports AES-128-GCM, AES-256-GCM, and ChaCha20-Poly1305 using pure Rust crates.
//! Record framing is handled by tls/records.rs.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes128Gcm, Aes256Gcm, Nonce,
};
use chacha20poly1305::ChaCha20Poly1305;

use crate::reality::common::{strip_content_type_with_padding, AEAD_TAG_SIZE, NONCE_SIZE};
use crate::reality::error::{RealityError, RealityResult};

use super::cipher_suite::CipherSuite;

/// AEAD key for TLS 1.3 encryption/decryption.
///
/// Wraps the appropriate cipher based on the cipher suite and provides
/// a unified API for encryption and decryption operations.
///
/// Create once per connection direction and reuse for all records.
pub enum AeadKey {
    Aes128Gcm(Aes128Gcm),
    Aes256Gcm(Aes256Gcm),
    ChaCha20Poly1305(ChaCha20Poly1305),
}

impl AeadKey {
    /// Create a new AEAD key from raw key bytes.
    ///
    /// # Arguments
    /// * `cipher_suite` - The TLS 1.3 cipher suite to use
    /// * `key` - Raw key bytes (must match cipher suite's key length)
    ///
    /// # Returns
    /// * `Ok(AeadKey)` - Ready to use for encryption/decryption
    /// * `Err` - If key length is invalid for the cipher suite
    pub fn new(cipher_suite: CipherSuite, key: &[u8]) -> RealityResult<Self> {
        cipher_suite.validate_key_len(key)?;

        match cipher_suite.id() {
            0x1301 => {
                // TLS_AES_128_GCM_SHA256
                let key_array: [u8; 16] = key
                    .try_into()
                    .map_err(|_| RealityError::key_derivation("Invalid AES-128 key length"))?;
                Ok(Self::Aes128Gcm(Aes128Gcm::new(&key_array.into())))
            }
            0x1302 => {
                // TLS_AES_256_GCM_SHA384
                let key_array: [u8; 32] = key
                    .try_into()
                    .map_err(|_| RealityError::key_derivation("Invalid AES-256 key length"))?;
                Ok(Self::Aes256Gcm(Aes256Gcm::new(&key_array.into())))
            }
            0x1303 => {
                // TLS_CHACHA20_POLY1305_SHA256
                let key_array: [u8; 32] = key
                    .try_into()
                    .map_err(|_| RealityError::key_derivation("Invalid ChaCha20 key length"))?;
                Ok(Self::ChaCha20Poly1305(ChaCha20Poly1305::new(
                    &key_array.into(),
                )))
            }
            id => Err(RealityError::protocol(format!(
                "Unsupported cipher suite: 0x{:04x}",
                id
            ))),
        }
    }

    /// Encrypt plaintext in-place, appending 16-byte auth tag.
    ///
    /// The buffer is modified: plaintext -> ciphertext || tag
    ///
    /// # Arguments
    /// * `buf` - Buffer containing plaintext (will be modified to contain ciphertext + tag)
    /// * `iv` - 12-byte IV/nonce base
    /// * `seq` - Sequence number to XOR with IV
    /// * `aad` - Additional authenticated data
    ///
    /// # Returns
    /// * `Ok(())` - Encryption successful, buf now contains ciphertext
    /// * `Err` - Encryption failed
    #[inline]
    pub fn seal_in_place(
        &self,
        buf: &mut Vec<u8>,
        iv: &[u8],
        seq: u64,
        aad: &[u8],
    ) -> RealityResult<()> {
        let nonce = Self::make_nonce(iv, seq)?;

        let ciphertext = match self {
            Self::Aes128Gcm(cipher) => cipher
                .encrypt(Nonce::from_slice(&nonce), aes_gcm::aead::Payload { msg: buf, aad })
                .map_err(|_| RealityError::protocol("AES-128-GCM encryption failed"))?,
            Self::Aes256Gcm(cipher) => cipher
                .encrypt(Nonce::from_slice(&nonce), aes_gcm::aead::Payload { msg: buf, aad })
                .map_err(|_| RealityError::protocol("AES-256-GCM encryption failed"))?,
            Self::ChaCha20Poly1305(cipher) => cipher
                .encrypt(
                    chacha20poly1305::Nonce::from_slice(&nonce),
                    chacha20poly1305::aead::Payload { msg: buf, aad },
                )
                .map_err(|_| RealityError::protocol("ChaCha20-Poly1305 encryption failed"))?,
        };

        buf.clear();
        buf.extend_from_slice(&ciphertext);
        Ok(())
    }

    /// Encrypt with copy, returning new Vec containing ciphertext || tag.
    ///
    /// Use this for small buffers where allocation overhead doesn't matter.
    ///
    /// # Arguments
    /// * `plaintext` - Data to encrypt
    /// * `iv` - 12-byte IV/nonce base
    /// * `seq` - Sequence number to XOR with IV
    /// * `aad` - Additional authenticated data
    ///
    /// # Returns
    /// * `Ok(Vec<u8>)` - Ciphertext with appended auth tag
    /// * `Err` - Encryption failed
    #[inline]
    pub fn seal(&self, plaintext: &[u8], iv: &[u8], seq: u64, aad: &[u8]) -> RealityResult<Vec<u8>> {
        let mut buf = plaintext.to_vec();
        self.seal_in_place(&mut buf, iv, seq, aad)?;
        Ok(buf)
    }

    /// Decrypt ciphertext in-place, returning plaintext slice.
    ///
    /// # Arguments
    /// * `buf` - Mutable slice containing ciphertext + auth tag
    /// * `iv` - 12-byte IV/nonce base
    /// * `seq` - Sequence number to XOR with IV
    /// * `aad` - Additional authenticated data
    ///
    /// # Returns
    /// * `Ok(&[u8])` - Sub-slice of buf containing decrypted plaintext
    /// * `Err` - Decryption or authentication failed
    #[inline]
    pub fn open_in_place<'a>(
        &self,
        buf: &'a mut [u8],
        iv: &[u8],
        seq: u64,
        aad: &[u8],
    ) -> RealityResult<&'a [u8]> {
        if buf.len() < AEAD_TAG_SIZE {
            return Err(RealityError::protocol("Ciphertext too short for auth tag"));
        }

        let nonce = Self::make_nonce(iv, seq)?;

        let plaintext = match self {
            Self::Aes128Gcm(cipher) => cipher
                .decrypt(Nonce::from_slice(&nonce), aes_gcm::aead::Payload { msg: buf, aad })
                .map_err(|_| RealityError::protocol("AES-128-GCM decryption failed"))?,
            Self::Aes256Gcm(cipher) => cipher
                .decrypt(Nonce::from_slice(&nonce), aes_gcm::aead::Payload { msg: buf, aad })
                .map_err(|_| RealityError::protocol("AES-256-GCM decryption failed"))?,
            Self::ChaCha20Poly1305(cipher) => cipher
                .decrypt(
                    chacha20poly1305::Nonce::from_slice(&nonce),
                    chacha20poly1305::aead::Payload { msg: buf, aad },
                )
                .map_err(|_| RealityError::protocol("ChaCha20-Poly1305 decryption failed"))?,
        };

        // Copy plaintext back to beginning of buffer
        let plaintext_len = plaintext.len();
        buf[..plaintext_len].copy_from_slice(&plaintext);
        Ok(&buf[..plaintext_len])
    }

    /// Decrypt with copy, returning new Vec containing plaintext.
    ///
    /// Used for handshake decryption and tests where allocation is acceptable.
    ///
    /// # Arguments
    /// * `ciphertext` - Data to decrypt (including auth tag)
    /// * `iv` - 12-byte IV/nonce base
    /// * `seq` - Sequence number to XOR with IV
    /// * `aad` - Additional authenticated data
    ///
    /// # Returns
    /// * `Ok(Vec<u8>)` - Decrypted plaintext
    /// * `Err` - Decryption or authentication failed
    #[inline]
    pub fn open(
        &self,
        ciphertext: &[u8],
        iv: &[u8],
        seq: u64,
        aad: &[u8],
    ) -> RealityResult<Vec<u8>> {
        let mut buf = ciphertext.to_vec();
        let plaintext = self.open_in_place(&mut buf, iv, seq, aad)?;
        let plaintext_len = plaintext.len();
        buf.truncate(plaintext_len);
        Ok(buf)
    }

    /// Construct TLS 1.3 nonce: IV XOR sequence_number
    ///
    /// Per RFC 8446, the nonce is constructed by XORing the IV with
    /// the sequence number (padded to 12 bytes, big-endian).
    fn make_nonce(iv: &[u8], seq: u64) -> RealityResult<[u8; NONCE_SIZE]> {
        if iv.len() != NONCE_SIZE {
            return Err(RealityError::key_derivation(format!(
                "Invalid IV length: {} (expected {})",
                iv.len(),
                NONCE_SIZE
            )));
        }

        let mut nonce_bytes = [0u8; NONCE_SIZE];
        nonce_bytes.copy_from_slice(iv);

        // XOR last 8 bytes with sequence number (big-endian)
        let seq_bytes = seq.to_be_bytes();
        for i in 0..8 {
            nonce_bytes[4 + i] ^= seq_bytes[i];
        }

        Ok(nonce_bytes)
    }
}

/// Decrypt a TLS 1.3 handshake message.
///
/// Builds the AAD from the record length and decrypts.
/// Returns plaintext with content type trailer stripped.
///
/// # Arguments
/// * `cipher_suite` - Cipher suite to use
/// * `key` - Raw key bytes
/// * `iv` - 12-byte IV
/// * `seq` - Sequence number
/// * `ciphertext` - Encrypted record payload
/// * `record_len` - Length from TLS record header
///
/// # Returns
/// * `Ok(Vec<u8>)` - Decrypted handshake message (content type stripped)
/// * `Err` - Decryption failed
pub fn decrypt_handshake_message(
    cipher_suite: CipherSuite,
    key: &[u8],
    iv: &[u8],
    seq: u64,
    ciphertext: &[u8],
    record_len: u16,
) -> RealityResult<Vec<u8>> {
    use crate::reality::common::CONTENT_TYPE_APPLICATION_DATA;

    // Build AAD: TLS record header
    let aad = [
        CONTENT_TYPE_APPLICATION_DATA, // ApplicationData (encrypted handshake)
        0x03,
        0x03, // TLS 1.2 version
        (record_len >> 8) as u8,
        (record_len & 0xff) as u8,
    ];

    let aead_key = AeadKey::new(cipher_suite, key)?;
    let mut plaintext = aead_key.open(ciphertext, iv, seq, &aad)?;

    // Strip content type and optional padding (external implementations may pad)
    let _ = strip_content_type_with_padding(&mut plaintext)?;

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CS_AES128: CipherSuite = CipherSuite::AES_128_GCM_SHA256;
    const CS_AES256: CipherSuite = CipherSuite::AES_256_GCM_SHA384;
    const CS_CHACHA: CipherSuite = CipherSuite::CHACHA20_POLY1305_SHA256;

    #[test]
    fn test_aes128_roundtrip() {
        let key = vec![0x42u8; 16];
        let iv = vec![0x99u8; 12];
        let plaintext = b"Hello, TLS 1.3!";
        let aad = b"additional data";

        let aead = AeadKey::new(CS_AES128, &key).unwrap();

        let ciphertext = aead.seal(plaintext, &iv, 0, aad).unwrap();
        assert_eq!(ciphertext.len(), plaintext.len() + AEAD_TAG_SIZE);

        let decrypted = aead.open(&ciphertext, &iv, 0, aad).unwrap();
        assert_eq!(&decrypted[..], plaintext);
    }

    #[test]
    fn test_aes256_roundtrip() {
        let key = vec![0x42u8; 32];
        let iv = vec![0x99u8; 12];
        let plaintext = b"Hello, AES-256!";
        let aad = b"aad";

        let aead = AeadKey::new(CS_AES256, &key).unwrap();

        let ciphertext = aead.seal(plaintext, &iv, 0, aad).unwrap();
        let decrypted = aead.open(&ciphertext, &iv, 0, aad).unwrap();

        assert_eq!(&decrypted[..], plaintext);
    }

    #[test]
    fn test_chacha20_roundtrip() {
        let key = vec![0x42u8; 32];
        let iv = vec![0x99u8; 12];
        let plaintext = b"Hello, ChaCha20!";
        let aad = b"aad";

        let aead = AeadKey::new(CS_CHACHA, &key).unwrap();

        let ciphertext = aead.seal(plaintext, &iv, 0, aad).unwrap();
        let decrypted = aead.open(&ciphertext, &iv, 0, aad).unwrap();

        assert_eq!(&decrypted[..], plaintext);
    }

    #[test]
    fn test_seal_in_place() {
        let key = vec![0x42u8; 16];
        let iv = vec![0x99u8; 12];
        let plaintext = b"Test in-place";
        let aad = b"aad";

        let aead = AeadKey::new(CS_AES128, &key).unwrap();

        let mut buf = plaintext.to_vec();
        aead.seal_in_place(&mut buf, &iv, 0, aad).unwrap();

        // buf now contains ciphertext + tag
        assert_eq!(buf.len(), plaintext.len() + AEAD_TAG_SIZE);

        let decrypted = aead.open(&buf, &iv, 0, aad).unwrap();
        assert_eq!(&decrypted[..], plaintext);
    }

    #[test]
    fn test_different_sequence_numbers() {
        let key = vec![0x42u8; 16];
        let iv = vec![0x99u8; 12];
        let plaintext = b"Test with sequence";
        let aad = b"aad";

        let aead = AeadKey::new(CS_AES128, &key).unwrap();

        // Different sequence numbers produce different ciphertexts
        let cipher1 = aead.seal(plaintext, &iv, 1, aad).unwrap();
        let cipher2 = aead.seal(plaintext, &iv, 2, aad).unwrap();
        let cipher3 = aead.seal(plaintext, &iv, 100, aad).unwrap();

        assert_ne!(cipher1, cipher2);
        assert_ne!(cipher2, cipher3);
        assert_ne!(cipher1, cipher3);

        // But they all decrypt correctly with matching sequence
        let decrypt1 = aead.open(&cipher1, &iv, 1, aad).unwrap();
        let decrypt2 = aead.open(&cipher2, &iv, 2, aad).unwrap();
        let decrypt3 = aead.open(&cipher3, &iv, 100, aad).unwrap();

        assert_eq!(&decrypt1[..], plaintext);
        assert_eq!(&decrypt2[..], plaintext);
        assert_eq!(&decrypt3[..], plaintext);
    }

    #[test]
    fn test_wrong_sequence_fails() {
        let key = vec![0x42u8; 16];
        let iv = vec![0x99u8; 12];
        let plaintext = b"Test sequence";
        let aad = b"aad";

        let aead = AeadKey::new(CS_AES128, &key).unwrap();
        let ciphertext = aead.seal(plaintext, &iv, 5, aad).unwrap();

        // Wrong sequence number should fail
        let result = aead.open(&ciphertext, &iv, 6, aad);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_aad_fails() {
        let key = vec![0x42u8; 16];
        let iv = vec![0x99u8; 12];
        let plaintext = b"Test AAD";
        let aad = b"correct aad";
        let wrong_aad = b"wrong aad";

        let aead = AeadKey::new(CS_AES128, &key).unwrap();
        let ciphertext = aead.seal(plaintext, &iv, 0, aad).unwrap();

        // Wrong AAD should fail
        let result = aead.open(&ciphertext, &iv, 0, wrong_aad);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_key_length() {
        let invalid_key = vec![0x42u8; 15]; // Wrong length

        let result = AeadKey::new(CS_AES128, &invalid_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_iv_length() {
        let key = vec![0x42u8; 16];
        let invalid_iv = vec![0x99u8; 11]; // Wrong length
        let plaintext = b"Test";
        let aad = b"aad";

        let aead = AeadKey::new(CS_AES128, &key).unwrap();
        let result = aead.seal(plaintext, &invalid_iv, 0, aad);
        assert!(result.is_err());
    }

    #[test]
    fn test_corrupted_ciphertext() {
        let key = vec![0x42u8; 16];
        let iv = vec![0x99u8; 12];
        let plaintext = b"Test corruption";
        let aad = b"aad";

        let aead = AeadKey::new(CS_AES128, &key).unwrap();
        let mut ciphertext = aead.seal(plaintext, &iv, 0, aad).unwrap();

        // Corrupt the ciphertext
        ciphertext[5] ^= 0xFF;

        let result = aead.open(&ciphertext, &iv, 0, aad);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_plaintext() {
        let key = vec![0x42u8; 16];
        let iv = vec![0x99u8; 12];
        let plaintext = b"";
        let aad = b"aad";

        let aead = AeadKey::new(CS_AES128, &key).unwrap();
        let ciphertext = aead.seal(plaintext, &iv, 0, aad).unwrap();

        // Should produce ciphertext with just auth tag
        assert_eq!(ciphertext.len(), AEAD_TAG_SIZE);

        let decrypted = aead.open(&ciphertext, &iv, 0, aad).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_large_plaintext() {
        let key = vec![0x42u8; 16];
        let iv = vec![0x99u8; 12];
        let plaintext = vec![0xAB; 16384]; // 16KB
        let aad = b"aad";

        let aead = AeadKey::new(CS_AES128, &key).unwrap();
        let ciphertext = aead.seal(&plaintext, &iv, 42, aad).unwrap();
        let decrypted = aead.open(&ciphertext, &iv, 42, aad).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_handshake_message() {
        use crate::reality::common::CONTENT_TYPE_HANDSHAKE;

        let key = vec![0x42u8; 16];
        let iv = vec![0x99u8; 12];
        let handshake_msg = vec![0xABu8; 100];

        // Build plaintext: handshake_msg || content_type
        let mut plaintext_with_type = handshake_msg.clone();
        plaintext_with_type.push(CONTENT_TYPE_HANDSHAKE);

        // Calculate ciphertext length for AAD
        let ciphertext_len = (plaintext_with_type.len() + AEAD_TAG_SIZE) as u16;

        // Build AAD (TLS record header)
        let aad = [
            0x17, // ApplicationData
            0x03,
            0x03, // TLS 1.2 version
            (ciphertext_len >> 8) as u8,
            (ciphertext_len & 0xff) as u8,
        ];

        // Encrypt
        let aead = AeadKey::new(CS_AES128, &key).unwrap();
        let ciphertext = aead.seal(&plaintext_with_type, &iv, 0, &aad).unwrap();

        // Decrypt using decrypt_handshake_message
        let decrypted =
            decrypt_handshake_message(CS_AES128, &key, &iv, 0, &ciphertext, ciphertext_len)
                .unwrap();

        assert_eq!(decrypted, handshake_msg);
    }

    #[test]
    fn test_nonce_construction() {
        let iv = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b];
        let seq = 1u64;

        let nonce = AeadKey::make_nonce(&iv, seq).unwrap();

        // First 4 bytes unchanged
        assert_eq!(&nonce[..4], &iv[..4]);

        // Last 8 bytes XORed with sequence (big-endian)
        // seq = 1 -> 0x0000000000000001
        // iv[4..12] = [0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b]
        // XOR result: [0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0a]
        assert_eq!(nonce[11], 0x0b ^ 0x01);
    }
}
