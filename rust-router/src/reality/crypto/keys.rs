//! TLS 1.3 Key Schedule Implementation
//!
//! Implements RFC 8446 key derivation for TLS 1.3 using HKDF.
//! Supports both SHA256 and SHA384 based cipher suites.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha384};

use crate::reality::error::{RealityError, RealityResult};

use super::cipher_suite::{CipherSuite, HashAlgorithm};

/// Intermediate TLS 1.3 keys (handshake secrets + master secret)
///
/// Used for two-phase key derivation where application secrets
/// must be derived after server Finished message.
#[derive(Debug, Clone)]
pub struct Tls13HandshakeKeys {
    /// Client handshake traffic secret
    pub client_handshake_traffic_secret: Vec<u8>,
    /// Server handshake traffic secret
    pub server_handshake_traffic_secret: Vec<u8>,
    /// Master secret (for deriving application secrets later)
    pub master_secret: Vec<u8>,
}

// =============================================================================
// HKDF Operations (RFC 5869)
// =============================================================================

/// HKDF-Extract operation
///
/// PRK = HMAC-Hash(salt, IKM)
fn hkdf_extract(hash_alg: HashAlgorithm, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
    match hash_alg {
        HashAlgorithm::Sha256 => {
            let mut mac = Hmac::<Sha256>::new_from_slice(salt)
                .expect("HMAC can take key of any size");
            mac.update(ikm);
            mac.finalize().into_bytes().to_vec()
        }
        HashAlgorithm::Sha384 => {
            let mut mac = Hmac::<Sha384>::new_from_slice(salt)
                .expect("HMAC can take key of any size");
            mac.update(ikm);
            mac.finalize().into_bytes().to_vec()
        }
    }
}

/// HKDF-Expand operation (RFC 5869 Section 2.3)
///
/// OKM = HKDF-Expand(PRK, info, L)
fn hkdf_expand(
    hash_alg: HashAlgorithm,
    prk: &[u8],
    info: &[u8],
    length: usize,
) -> RealityResult<Vec<u8>> {
    let hash_len = match hash_alg {
        HashAlgorithm::Sha256 => 32,
        HashAlgorithm::Sha384 => 48,
    };

    let n = length.div_ceil(hash_len);
    if n > 255 {
        return Err(RealityError::key_derivation("HKDF output too long"));
    }

    let mut output = Vec::with_capacity(n * hash_len);
    let mut prev = Vec::new();

    for i in 1..=n {
        let block = match hash_alg {
            HashAlgorithm::Sha256 => {
                let mut mac = Hmac::<Sha256>::new_from_slice(prk)
                    .expect("HMAC can take key of any size");
                mac.update(&prev);
                mac.update(info);
                mac.update(&[i as u8]);
                mac.finalize().into_bytes().to_vec()
            }
            HashAlgorithm::Sha384 => {
                let mut mac = Hmac::<Sha384>::new_from_slice(prk)
                    .expect("HMAC can take key of any size");
                mac.update(&prev);
                mac.update(info);
                mac.update(&[i as u8]);
                mac.finalize().into_bytes().to_vec()
            }
        };

        prev = block.clone();
        output.extend_from_slice(&block);
    }

    output.truncate(length);
    Ok(output)
}

/// HKDF-Expand-Label as defined in RFC 8446 Section 7.1
///
/// HKDF-Expand-Label(Secret, Label, Context, Length) =
///     HKDF-Expand(Secret, HkdfLabel, Length)
///
/// Where HkdfLabel is:
/// ```text
/// struct {
///     uint16 length = Length;
///     opaque label<7..255> = "tls13 " + Label;
///     opaque context<0..255> = Context;
/// } HkdfLabel;
/// ```
fn hkdf_expand_label(
    hash_alg: HashAlgorithm,
    secret: &[u8],
    label: &[u8],
    context: &[u8],
    length: usize,
) -> RealityResult<Vec<u8>> {
    // Build HkdfLabel structure
    let mut hkdf_label = Vec::new();

    // Length (2 bytes, big-endian)
    hkdf_label.extend_from_slice(&(length as u16).to_be_bytes());

    // Label: length byte + "tls13 " + Label
    let full_label_len = 6 + label.len(); // "tls13 " is 6 bytes
    hkdf_label.push(full_label_len as u8);
    hkdf_label.extend_from_slice(b"tls13 ");
    hkdf_label.extend_from_slice(label);

    // Context: length byte + Context
    hkdf_label.push(context.len() as u8);
    hkdf_label.extend_from_slice(context);

    hkdf_expand(hash_alg, secret, &hkdf_label, length)
}

/// Derive-Secret as defined in RFC 8446 Section 7.1
///
/// Derive-Secret(Secret, Label, Messages) =
///     HKDF-Expand-Label(Secret, Label, Transcript-Hash(Messages), Hash.length)
fn derive_secret(
    hash_alg: HashAlgorithm,
    hash_len: usize,
    secret: &[u8],
    label: &[u8],
    messages_hash: &[u8],
) -> RealityResult<Vec<u8>> {
    hkdf_expand_label(hash_alg, secret, label, messages_hash, hash_len)
}

/// Compute hash of empty string for the given algorithm
fn empty_hash(hash_alg: HashAlgorithm) -> Vec<u8> {
    match hash_alg {
        HashAlgorithm::Sha256 => {
            let mut hasher = Sha256::new();
            hasher.update(b"");
            hasher.finalize().to_vec()
        }
        HashAlgorithm::Sha384 => {
            let mut hasher = Sha384::new();
            hasher.update(b"");
            hasher.finalize().to_vec()
        }
    }
}

// =============================================================================
// TLS 1.3 Key Derivation Functions
// =============================================================================

/// Derive traffic keys and IV from traffic secret
///
/// Per RFC 8446 Section 7.3:
/// - key = HKDF-Expand-Label(Secret, "key", "", key_length)
/// - iv = HKDF-Expand-Label(Secret, "iv", "", iv_length)
///
/// # Arguments
/// * `traffic_secret` - Traffic secret (hash_len bytes)
/// * `cipher_suite` - CipherSuite with key/IV lengths
///
/// # Returns
/// (key, iv) tuple for AEAD
pub fn derive_traffic_keys(
    traffic_secret: &[u8],
    cipher_suite: CipherSuite,
) -> RealityResult<(Vec<u8>, Vec<u8>)> {
    let key_length = cipher_suite.key_len();
    let iv_length = cipher_suite.nonce_len();
    let hash_alg = cipher_suite.hash_algorithm();

    // key = HKDF-Expand-Label(Secret, "key", "", key_length)
    let key = hkdf_expand_label(hash_alg, traffic_secret, b"key", b"", key_length)?;

    // iv = HKDF-Expand-Label(Secret, "iv", "", iv_length)
    let iv = hkdf_expand_label(hash_alg, traffic_secret, b"iv", b"", iv_length)?;

    Ok((key, iv))
}

/// Derive TLS 1.3 handshake keys and master secret (Phase 1)
///
/// This function derives handshake traffic secrets and the master secret,
/// but NOT the application traffic secrets. Application secrets must be
/// derived separately after the server Finished message is sent (Phase 2).
///
/// # Key Schedule (RFC 8446 Section 7.1):
/// ```text
///             0
///             |
///             v
///   PSK ->  HKDF-Extract = Early Secret
///             |
///             +-----> Derive-Secret(., "ext binder" | "res binder", "")
///             |                     = binder_key
///             |
///             +-----> Derive-Secret(., "c e traffic", ClientHello)
///             |                     = client_early_traffic_secret
///             |
///             +-----> Derive-Secret(., "e exp master", ClientHello)
///             |                     = early_exporter_master_secret
///             v
///       Derive-Secret(., "derived", "")
///             |
///             v
///   (EC)DHE -> HKDF-Extract = Handshake Secret
///             |
///             +-----> Derive-Secret(., "c hs traffic", CH...SH)
///             |                     = client_handshake_traffic_secret
///             |
///             +-----> Derive-Secret(., "s hs traffic", CH...SH)
///             |                     = server_handshake_traffic_secret
///             v
///       Derive-Secret(., "derived", "")
///             |
///             v
///   0 -> HKDF-Extract = Master Secret
/// ```
///
/// # Arguments
/// * `cipher_suite` - CipherSuite with hash algorithm
/// * `shared_secret` - ECDH shared secret (32 bytes for X25519)
/// * `_client_hello_hash` - Unused, kept for API consistency
/// * `server_hello_hash` - Hash of ClientHello...ServerHello
///
/// # Returns
/// Handshake traffic secrets and master secret
pub fn derive_handshake_keys(
    cipher_suite: CipherSuite,
    shared_secret: &[u8],
    _client_hello_hash: &[u8],
    server_hello_hash: &[u8],
) -> RealityResult<Tls13HandshakeKeys> {
    let hash_len = cipher_suite.hash_len();
    let hash_alg = cipher_suite.hash_algorithm();

    // Validate input lengths
    if shared_secret.len() != 32 {
        return Err(RealityError::key_derivation(format!(
            "Invalid shared_secret length: {} (expected 32)",
            shared_secret.len()
        )));
    }
    if server_hello_hash.len() != hash_len {
        return Err(RealityError::key_derivation(format!(
            "Hash length mismatch: {} (expected {})",
            server_hello_hash.len(),
            hash_len
        )));
    }

    // 1. Early Secret = HKDF-Extract(salt=0, IKM=0)
    let zero_salt = vec![0u8; hash_len];
    let early_secret = hkdf_extract(hash_alg, &zero_salt, &zero_salt);

    // 2. Derive-Secret(., "derived", "")
    let empty_hash = empty_hash(hash_alg);
    let derived_secret = derive_secret(hash_alg, hash_len, &early_secret, b"derived", &empty_hash)?;

    // 3. Handshake Secret = HKDF-Extract(salt=derived_secret, IKM=shared_secret)
    let handshake_secret = hkdf_extract(hash_alg, &derived_secret, shared_secret);

    // 4. Client Handshake Traffic Secret
    let client_handshake_traffic_secret = derive_secret(
        hash_alg,
        hash_len,
        &handshake_secret,
        b"c hs traffic",
        server_hello_hash,
    )?;

    // 5. Server Handshake Traffic Secret
    let server_handshake_traffic_secret = derive_secret(
        hash_alg,
        hash_len,
        &handshake_secret,
        b"s hs traffic",
        server_hello_hash,
    )?;

    // 6. Derive-Secret(., "derived", "") from handshake_secret
    let derived_secret_2 =
        derive_secret(hash_alg, hash_len, &handshake_secret, b"derived", &empty_hash)?;

    // 7. Master Secret = HKDF-Extract(salt=derived_secret, IKM=0)
    let master_secret = hkdf_extract(hash_alg, &derived_secret_2, &zero_salt);

    Ok(Tls13HandshakeKeys {
        client_handshake_traffic_secret,
        server_handshake_traffic_secret,
        master_secret,
    })
}

/// Derive TLS 1.3 application traffic secrets (Phase 2)
///
/// This function must be called AFTER the server Finished message is sent,
/// with a transcript hash that includes the Finished message.
///
/// # Arguments
/// * `cipher_suite` - CipherSuite with hash algorithm
/// * `master_secret` - Master secret from Phase 1 (hash_len bytes)
/// * `handshake_hash` - Hash including server Finished (hash_len bytes)
///
/// # Returns
/// (client_application_traffic_secret, server_application_traffic_secret)
pub fn derive_application_secrets(
    cipher_suite: CipherSuite,
    master_secret: &[u8],
    handshake_hash: &[u8],
) -> RealityResult<(Vec<u8>, Vec<u8>)> {
    let hash_len = cipher_suite.hash_len();
    let hash_alg = cipher_suite.hash_algorithm();

    if master_secret.len() != hash_len || handshake_hash.len() != hash_len {
        return Err(RealityError::key_derivation(format!(
            "Master secret and handshake hash must be {} bytes",
            hash_len
        )));
    }

    // Client Application Traffic Secret
    let client_application_traffic_secret = derive_secret(
        hash_alg,
        hash_len,
        master_secret,
        b"c ap traffic",
        handshake_hash,
    )?;

    // Server Application Traffic Secret
    let server_application_traffic_secret = derive_secret(
        hash_alg,
        hash_len,
        master_secret,
        b"s ap traffic",
        handshake_hash,
    )?;

    Ok((
        client_application_traffic_secret,
        server_application_traffic_secret,
    ))
}

/// Compute "Finished" verify data
///
/// Per RFC 8446 Section 4.4.4:
/// - finished_key = HKDF-Expand-Label(BaseKey, "finished", "", Hash.length)
/// - verify_data = HMAC(finished_key, Transcript-Hash(Handshake Context))
///
/// # Arguments
/// * `cipher_suite` - CipherSuite with hash algorithm
/// * `base_key` - Traffic secret (client or server handshake traffic secret)
/// * `handshake_hash` - Transcript hash up to this point
///
/// # Returns
/// verify_data for Finished message
pub fn compute_finished_verify_data(
    cipher_suite: CipherSuite,
    base_key: &[u8],
    handshake_hash: &[u8],
) -> RealityResult<Vec<u8>> {
    let hash_len = cipher_suite.hash_len();
    let hash_alg = cipher_suite.hash_algorithm();

    // finished_key = HKDF-Expand-Label(BaseKey, "finished", "", hash_len)
    let finished_key = hkdf_expand_label(hash_alg, base_key, b"finished", b"", hash_len)?;

    // verify_data = HMAC(finished_key, handshake_hash)
    let verify_data = match hash_alg {
        HashAlgorithm::Sha256 => {
            let mut mac = Hmac::<Sha256>::new_from_slice(&finished_key)
                .expect("HMAC can take key of any size");
            mac.update(handshake_hash);
            mac.finalize().into_bytes().to_vec()
        }
        HashAlgorithm::Sha384 => {
            let mut mac = Hmac::<Sha384>::new_from_slice(&finished_key)
                .expect("HMAC can take key of any size");
            mac.update(handshake_hash);
            mac.finalize().into_bytes().to_vec()
        }
    };

    Ok(verify_data)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CS_SHA256: CipherSuite = CipherSuite::AES_128_GCM_SHA256;
    const CS_SHA384: CipherSuite = CipherSuite::AES_256_GCM_SHA384;

    // Test vectors from RFC 5869 Appendix A
    #[test]
    fn test_hkdf_expand_sha256_rfc_vector() {
        // Test Case 1 from RFC 5869 (using extracted PRK directly)
        let prk = [
            0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf, 0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b,
            0xba, 0x63, 0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31, 0x22, 0xec, 0x84, 0x4a,
            0xd7, 0xc2, 0xb3, 0xe5,
        ];
        let info = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];

        let result = hkdf_expand(HashAlgorithm::Sha256, &prk, &info, 42).unwrap();
        assert_eq!(result.len(), 42);

        // Expected output from RFC 5869
        let expected = [
            0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
            0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
            0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
        ];
        assert_eq!(result, expected);
    }

    #[test]
    fn test_hkdf_expand_empty_info() {
        let prk = vec![0x42u8; 32];
        let result = hkdf_expand(HashAlgorithm::Sha256, &prk, &[], 16);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 16);
    }

    #[test]
    fn test_hkdf_expand_max_length() {
        let prk = vec![0x42u8; 32];
        let info = b"test info";

        // Maximum output length is 255 * hash_len = 8160 bytes for SHA256
        let result = hkdf_expand(HashAlgorithm::Sha256, &prk, info, 8160);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 8160);

        // Should fail for length > 8160
        let result = hkdf_expand(HashAlgorithm::Sha256, &prk, info, 8161);
        assert!(result.is_err());
    }

    #[test]
    fn test_hkdf_expand_label() {
        let secret = vec![0x42u8; 32];
        let result = hkdf_expand_label(HashAlgorithm::Sha256, &secret, b"test", b"", 16);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 16);
    }

    #[test]
    fn test_hkdf_expand_label_with_context() {
        let secret = vec![0x42u8; 32];
        let context = vec![0x11u8; 32];
        let result =
            hkdf_expand_label(HashAlgorithm::Sha256, &secret, b"finished", &context, 32);
        assert!(result.is_ok());
        let output = result.unwrap();
        assert_eq!(output.len(), 32);

        // Result should be deterministic
        let result2 =
            hkdf_expand_label(HashAlgorithm::Sha256, &secret, b"finished", &context, 32).unwrap();
        assert_eq!(output, result2);
    }

    #[test]
    fn test_hkdf_extract() {
        let salt = vec![0x11u8; 32];
        let ikm = vec![0x22u8; 32];

        let result1 = hkdf_extract(HashAlgorithm::Sha256, &salt, &ikm);
        assert_eq!(result1.len(), 32);

        // Should be deterministic
        let result2 = hkdf_extract(HashAlgorithm::Sha256, &salt, &ikm);
        assert_eq!(result1, result2);

        // Different input should give different output
        let ikm2 = vec![0x33u8; 32];
        let result3 = hkdf_extract(HashAlgorithm::Sha256, &salt, &ikm2);
        assert_ne!(result1, result3);
    }

    #[test]
    fn test_derive_traffic_keys_sha256() {
        let traffic_secret = vec![0x99u8; 32];

        let result = derive_traffic_keys(&traffic_secret, CS_SHA256);
        assert!(result.is_ok());
        let (key, iv) = result.unwrap();
        assert_eq!(key.len(), 16); // AES-128
        assert_eq!(iv.len(), 12);
    }

    #[test]
    fn test_derive_traffic_keys_sha384() {
        let traffic_secret = vec![0x99u8; 48];

        let result = derive_traffic_keys(&traffic_secret, CS_SHA384);
        assert!(result.is_ok());
        let (key, iv) = result.unwrap();
        assert_eq!(key.len(), 32); // AES-256
        assert_eq!(iv.len(), 12);
    }

    #[test]
    fn test_derive_handshake_keys() {
        let shared_secret = vec![0x55u8; 32];
        let client_hello_hash = vec![0xAAu8; 32];
        let server_hello_hash = vec![0xBBu8; 32];

        let result = derive_handshake_keys(
            CS_SHA256,
            &shared_secret,
            &client_hello_hash,
            &server_hello_hash,
        );
        assert!(result.is_ok());

        let keys = result.unwrap();
        assert_eq!(keys.client_handshake_traffic_secret.len(), 32);
        assert_eq!(keys.server_handshake_traffic_secret.len(), 32);
        assert_eq!(keys.master_secret.len(), 32);

        // Client and server secrets should be different
        assert_ne!(
            keys.client_handshake_traffic_secret,
            keys.server_handshake_traffic_secret
        );
    }

    #[test]
    fn test_derive_handshake_keys_invalid_shared_secret() {
        let shared_secret = vec![0x55u8; 31]; // Wrong length
        let client_hello_hash = vec![0xAAu8; 32];
        let server_hello_hash = vec![0xBBu8; 32];

        let result = derive_handshake_keys(
            CS_SHA256,
            &shared_secret,
            &client_hello_hash,
            &server_hello_hash,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_derive_application_secrets() {
        let master_secret = vec![0x77u8; 32];
        let handshake_hash = vec![0x88u8; 32];

        let result = derive_application_secrets(CS_SHA256, &master_secret, &handshake_hash);
        assert!(result.is_ok());

        let (client_secret, server_secret) = result.unwrap();
        assert_eq!(client_secret.len(), 32);
        assert_eq!(server_secret.len(), 32);
        assert_ne!(client_secret, server_secret);
    }

    #[test]
    fn test_compute_finished_verify_data() {
        let base_key = vec![0xAAu8; 32];
        let handshake_hash = vec![0xBBu8; 32];

        let result = compute_finished_verify_data(CS_SHA256, &base_key, &handshake_hash);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 32);
    }

    #[test]
    fn test_empty_hash() {
        let hash256 = empty_hash(HashAlgorithm::Sha256);
        assert_eq!(hash256.len(), 32);
        // SHA256 of empty string
        assert_eq!(
            hash256,
            hex::decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
                .unwrap()
        );

        let hash384 = empty_hash(HashAlgorithm::Sha384);
        assert_eq!(hash384.len(), 48);
    }

    #[test]
    fn test_key_derivation_deterministic() {
        let shared_secret = vec![0x42u8; 32];
        let server_hello_hash = vec![0x99u8; 32];

        let keys1 = derive_handshake_keys(CS_SHA256, &shared_secret, &[], &server_hello_hash).unwrap();
        let keys2 = derive_handshake_keys(CS_SHA256, &shared_secret, &[], &server_hello_hash).unwrap();

        assert_eq!(
            keys1.client_handshake_traffic_secret,
            keys2.client_handshake_traffic_secret
        );
        assert_eq!(
            keys1.server_handshake_traffic_secret,
            keys2.server_handshake_traffic_secret
        );
        assert_eq!(keys1.master_secret, keys2.master_secret);
    }
}
