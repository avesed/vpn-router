//! TLS 1.3 Record Layer Encryption/Decryption
//!
//! Handles encryption and decryption of TLS 1.3 records with automatic
//! fragmentation for large plaintexts.

use crate::reality::common::{
    build_record_header, strip_content_type_slice, AEAD_TAG_SIZE, CONTENT_TYPE_ALERT,
    CONTENT_TYPE_APPLICATION_DATA, CONTENT_TYPE_HANDSHAKE, MAX_TLS_PLAINTEXT_LEN,
    TLS_RECORD_HEADER_SIZE, ALERT_LEVEL_WARNING, ALERT_DESC_CLOSE_NOTIFY,
};
use crate::reality::crypto::AeadKey;
use crate::reality::error::{RealityError, RealityResult};

/// Record encryptor for TLS 1.3
///
/// Manages write-side operations including:
/// - Sequence number tracking
/// - Plaintext fragmentation into 16KB chunks
/// - Content type trailer addition
/// - In-place encryption
pub struct RecordEncryptor<'a> {
    key: &'a AeadKey,
    iv: &'a [u8],
    seq: &'a mut u64,
}

impl<'a> RecordEncryptor<'a> {
    /// Create a new record encryptor
    pub fn new(key: &'a AeadKey, iv: &'a [u8], seq: &'a mut u64) -> Self {
        Self { key, iv, seq }
    }

    /// Encrypt application data and append to output buffer
    ///
    /// Automatically fragments data exceeding MAX_TLS_PLAINTEXT_LEN into
    /// multiple TLS records.
    ///
    /// # Arguments
    /// * `plaintext_buf` - Source buffer (will be drained)
    /// * `ciphertext_buf` - Destination buffer for encrypted records
    pub fn encrypt_app_data(
        &mut self,
        plaintext_buf: &mut Vec<u8>,
        ciphertext_buf: &mut Vec<u8>,
    ) -> RealityResult<()> {
        while !plaintext_buf.is_empty() {
            // Determine fragment size (max 16KB minus 1 for content type)
            let fragment_size = plaintext_buf.len().min(MAX_TLS_PLAINTEXT_LEN - 1);

            // Build inner plaintext: data + content_type
            let mut inner = plaintext_buf.drain(..fragment_size).collect::<Vec<_>>();
            inner.push(CONTENT_TYPE_APPLICATION_DATA);

            // Encrypt
            let ciphertext_len = inner.len() + AEAD_TAG_SIZE;
            let aad = build_record_header(CONTENT_TYPE_APPLICATION_DATA, ciphertext_len as u16);

            self.key.seal_in_place(&mut inner, self.iv, *self.seq, &aad)?;
            *self.seq += 1;

            // Write record header + ciphertext
            ciphertext_buf.extend_from_slice(&aad);
            ciphertext_buf.extend_from_slice(&inner);
        }

        Ok(())
    }

    /// Encrypt a handshake message
    ///
    /// # Arguments
    /// * `handshake` - Handshake message bytes
    /// * `ciphertext_buf` - Destination buffer
    pub fn encrypt_handshake(
        &mut self,
        handshake: &[u8],
        ciphertext_buf: &mut Vec<u8>,
    ) -> RealityResult<()> {
        // Build inner plaintext: handshake + content_type
        let mut inner = handshake.to_vec();
        inner.push(CONTENT_TYPE_HANDSHAKE);

        let ciphertext_len = inner.len() + AEAD_TAG_SIZE;
        let aad = build_record_header(CONTENT_TYPE_APPLICATION_DATA, ciphertext_len as u16);

        self.key.seal_in_place(&mut inner, self.iv, *self.seq, &aad)?;
        *self.seq += 1;

        ciphertext_buf.extend_from_slice(&aad);
        ciphertext_buf.extend_from_slice(&inner);

        Ok(())
    }

    /// Encrypt a close_notify alert
    pub fn encrypt_close_notify(&mut self, ciphertext_buf: &mut Vec<u8>) -> RealityResult<()> {
        // Build alert: level (1) + description (1) + content_type
        let mut inner = vec![ALERT_LEVEL_WARNING, ALERT_DESC_CLOSE_NOTIFY, CONTENT_TYPE_ALERT];

        let ciphertext_len = inner.len() + AEAD_TAG_SIZE;
        let aad = build_record_header(CONTENT_TYPE_APPLICATION_DATA, ciphertext_len as u16);

        self.key.seal_in_place(&mut inner, self.iv, *self.seq, &aad)?;
        *self.seq += 1;

        ciphertext_buf.extend_from_slice(&aad);
        ciphertext_buf.extend_from_slice(&inner);

        Ok(())
    }

    /// Get current sequence number
    pub fn sequence(&self) -> u64 {
        *self.seq
    }
}

/// Record decryptor for TLS 1.3
///
/// Handles read-side operations with zero-allocation decryption.
pub struct RecordDecryptor<'a> {
    key: &'a AeadKey,
    iv: &'a [u8],
    seq: &'a mut u64,
}

impl<'a> RecordDecryptor<'a> {
    /// Create a new record decryptor
    pub fn new(key: &'a AeadKey, iv: &'a [u8], seq: &'a mut u64) -> Self {
        Self { key, iv, seq }
    }

    /// Decrypt a record in-place
    ///
    /// # Arguments
    /// * `ciphertext` - Mutable slice containing ciphertext (without record header)
    /// * `record_len` - Length from TLS record header
    ///
    /// # Returns
    /// (content_type, plaintext slice)
    pub fn decrypt_record_in_place<'b>(
        &mut self,
        ciphertext: &'b mut [u8],
        record_len: u16,
    ) -> RealityResult<(u8, &'b [u8])> {
        // Build AAD from record header
        let aad = build_record_header(CONTENT_TYPE_APPLICATION_DATA, record_len);

        // Decrypt in-place
        let plaintext = self.key.open_in_place(ciphertext, self.iv, *self.seq, &aad)?;
        *self.seq += 1;

        // Strip content type trailer
        let (content_type, content_len) = strip_content_type_slice(plaintext)?;

        Ok((content_type, &plaintext[..content_len]))
    }

    /// Get current sequence number
    pub fn sequence(&self) -> u64 {
        *self.seq
    }
}

/// Check if sequence number is about to overflow
///
/// TLS 1.3 requires that implementations MUST NOT allow the sequence number
/// to wrap. This function checks if we're approaching the limit.
pub fn check_sequence_overflow(seq: u64) -> RealityResult<()> {
    // RFC 8446 doesn't specify exact limit, but 2^64-1 is the max
    // We check at 2^63 to provide early warning
    if seq >= (1u64 << 63) {
        return Err(RealityError::protocol(
            "Sequence number approaching overflow - rekeying required",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reality::crypto::{AeadKey, CipherSuite};

    const CS: CipherSuite = CipherSuite::AES_128_GCM_SHA256;

    fn create_test_key() -> AeadKey {
        AeadKey::new(CS, &[0x42u8; 16]).unwrap()
    }

    #[test]
    fn test_encrypt_decrypt_app_data() {
        let key = create_test_key();
        let iv = vec![0x99u8; 12];
        let mut write_seq = 0u64;
        let mut read_seq = 0u64;

        let plaintext = b"Hello, TLS 1.3!";
        let mut plaintext_buf = plaintext.to_vec();
        let mut ciphertext_buf = Vec::new();

        // Encrypt
        {
            let mut encryptor = RecordEncryptor::new(&key, &iv, &mut write_seq);
            encryptor.encrypt_app_data(&mut plaintext_buf, &mut ciphertext_buf).unwrap();
        }

        assert!(plaintext_buf.is_empty());
        assert!(ciphertext_buf.len() > plaintext.len() + TLS_RECORD_HEADER_SIZE);

        // Decrypt
        let record_len = u16::from_be_bytes([ciphertext_buf[3], ciphertext_buf[4]]);
        let mut ciphertext_payload = ciphertext_buf[TLS_RECORD_HEADER_SIZE..].to_vec();

        let (content_type, decrypted) = {
            let mut decryptor = RecordDecryptor::new(&key, &iv, &mut read_seq);
            let (ct, pt) = decryptor.decrypt_record_in_place(&mut ciphertext_payload, record_len).unwrap();
            (ct, pt.to_vec())
        };

        assert_eq!(content_type, CONTENT_TYPE_APPLICATION_DATA);
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_handshake() {
        let key = create_test_key();
        let iv = vec![0x99u8; 12];
        let mut write_seq = 0u64;
        let mut read_seq = 0u64;

        // Build a Finished message: type (0x14), length (0x000020), plus 32 bytes data
        let mut handshake = vec![0x14, 0x00, 0x00, 0x20];
        handshake.extend_from_slice(&[0xABu8; 32]);
        let mut ciphertext_buf = Vec::new();

        // Encrypt
        {
            let mut encryptor = RecordEncryptor::new(&key, &iv, &mut write_seq);
            encryptor.encrypt_handshake(&handshake, &mut ciphertext_buf).unwrap();
        }

        // Decrypt
        let record_len = u16::from_be_bytes([ciphertext_buf[3], ciphertext_buf[4]]);
        let mut ciphertext_payload = ciphertext_buf[TLS_RECORD_HEADER_SIZE..].to_vec();

        let (content_type, decrypted) = {
            let mut decryptor = RecordDecryptor::new(&key, &iv, &mut read_seq);
            let (ct, pt) = decryptor.decrypt_record_in_place(&mut ciphertext_payload, record_len).unwrap();
            (ct, pt.to_vec())
        };

        assert_eq!(content_type, CONTENT_TYPE_HANDSHAKE);
        assert_eq!(decrypted, handshake);
    }

    #[test]
    fn test_large_plaintext_fragmentation() {
        let key = create_test_key();
        let iv = vec![0x99u8; 12];
        let mut write_seq = 0u64;

        // Create data larger than MAX_TLS_PLAINTEXT_LEN
        let large_plaintext = vec![0xABu8; MAX_TLS_PLAINTEXT_LEN + 1000];
        let mut plaintext_buf = large_plaintext.clone();
        let mut ciphertext_buf = Vec::new();

        // Encrypt - should produce multiple records
        {
            let mut encryptor = RecordEncryptor::new(&key, &iv, &mut write_seq);
            encryptor.encrypt_app_data(&mut plaintext_buf, &mut ciphertext_buf).unwrap();
        }

        // Should have encrypted all data
        assert!(plaintext_buf.is_empty());

        // Sequence should have incremented multiple times (at least 2 records)
        assert!(write_seq >= 2);

        // Ciphertext should contain multiple records
        // Count record headers
        let mut record_count = 0;
        let mut offset = 0;
        while offset + TLS_RECORD_HEADER_SIZE <= ciphertext_buf.len() {
            let record_len = u16::from_be_bytes([
                ciphertext_buf[offset + 3],
                ciphertext_buf[offset + 4],
            ]) as usize;
            record_count += 1;
            offset += TLS_RECORD_HEADER_SIZE + record_len;
        }

        assert!(record_count >= 2, "Expected multiple records, got {}", record_count);
    }

    #[test]
    fn test_sequence_number_increment() {
        let key = create_test_key();
        let iv = vec![0x99u8; 12];
        let mut seq = 0u64;

        let mut ciphertext_buf = Vec::new();

        // Encrypt multiple messages
        for _ in 0..5 {
            let mut plaintext_buf = b"test".to_vec();
            let mut encryptor = RecordEncryptor::new(&key, &iv, &mut seq);
            encryptor.encrypt_app_data(&mut plaintext_buf, &mut ciphertext_buf).unwrap();
        }

        assert_eq!(seq, 5);
    }

    #[test]
    fn test_encrypt_close_notify() {
        let key = create_test_key();
        let iv = vec![0x99u8; 12];
        let mut write_seq = 0u64;
        let mut read_seq = 0u64;

        let mut ciphertext_buf = Vec::new();

        // Encrypt close_notify
        {
            let mut encryptor = RecordEncryptor::new(&key, &iv, &mut write_seq);
            encryptor.encrypt_close_notify(&mut ciphertext_buf).unwrap();
        }

        // Decrypt
        let record_len = u16::from_be_bytes([ciphertext_buf[3], ciphertext_buf[4]]);
        let mut ciphertext_payload = ciphertext_buf[TLS_RECORD_HEADER_SIZE..].to_vec();

        let (content_type, decrypted) = {
            let mut decryptor = RecordDecryptor::new(&key, &iv, &mut read_seq);
            let (ct, pt) = decryptor.decrypt_record_in_place(&mut ciphertext_payload, record_len).unwrap();
            (ct, pt.to_vec())
        };

        assert_eq!(content_type, CONTENT_TYPE_ALERT);
        assert_eq!(decrypted.len(), 2);
        assert_eq!(decrypted[0], ALERT_LEVEL_WARNING);
        assert_eq!(decrypted[1], ALERT_DESC_CLOSE_NOTIFY);
    }

    #[test]
    fn test_check_sequence_overflow() {
        // Normal sequence - should pass
        assert!(check_sequence_overflow(0).is_ok());
        assert!(check_sequence_overflow(1_000_000).is_ok());
        assert!(check_sequence_overflow((1u64 << 63) - 1).is_ok());

        // Near overflow - should fail
        assert!(check_sequence_overflow(1u64 << 63).is_err());
        assert!(check_sequence_overflow(u64::MAX).is_err());
    }

    #[test]
    fn test_decrypt_wrong_key_fails() {
        let key1 = create_test_key();
        let key2 = AeadKey::new(CS, &[0x43u8; 16]).unwrap(); // Different key
        let iv = vec![0x99u8; 12];
        let mut write_seq = 0u64;
        let mut read_seq = 0u64;

        let mut plaintext_buf = b"secret data".to_vec();
        let mut ciphertext_buf = Vec::new();

        // Encrypt with key1
        {
            let mut encryptor = RecordEncryptor::new(&key1, &iv, &mut write_seq);
            encryptor.encrypt_app_data(&mut plaintext_buf, &mut ciphertext_buf).unwrap();
        }

        // Try to decrypt with key2 - should fail
        let record_len = u16::from_be_bytes([ciphertext_buf[3], ciphertext_buf[4]]);
        let mut ciphertext_payload = ciphertext_buf[TLS_RECORD_HEADER_SIZE..].to_vec();

        let result = {
            let mut decryptor = RecordDecryptor::new(&key2, &iv, &mut read_seq);
            decryptor.decrypt_record_in_place(&mut ciphertext_payload, record_len)
        };

        assert!(result.is_err());
    }
}
