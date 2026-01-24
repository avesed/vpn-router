//! REALITY HMAC Certificate Generation
//!
//! This module generates Ed25519 certificates where the signature is replaced
//! with HMAC-SHA512(auth_key, public_key). This allows REALITY clients to verify
//! the server's identity without relying on CA validation.
//!
//! The certificate structure:
//! - Public key: Real Ed25519 public key
//! - Signature: HMAC-SHA512(auth_key, public_key) instead of actual signature
//!
//! Client verification:
//! 1. Extract Ed25519 public key from certificate
//! 2. Compute HMAC-SHA512(auth_key, public_key)
//! 3. Compare with certificate's signature field
//! 4. Verify CertificateVerify using the Ed25519 public key

use ed25519_dalek::{SigningKey, VerifyingKey};
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rcgen::{KeyPair, RemoteKeyPair, SignatureAlgorithm};
use sha2::Sha512;

use crate::reality::error::{RealityError, RealityResult};

type HmacSha512 = Hmac<Sha512>;

/// A signing key that computes HMAC-SHA512(auth_key, public_key) as the "signature".
///
/// This implements rcgen's RemoteKeyPair trait but ignores the TBS (to-be-signed) data,
/// instead computing the REALITY HMAC. This allows rcgen to place our HMAC directly
/// into the certificate signature field.
struct HmacSigningKey {
    /// HMAC key (auth_key)
    auth_key: [u8; 32],
    /// The Ed25519 public key bytes (32 bytes)
    public_key: [u8; 32],
}

impl RemoteKeyPair for HmacSigningKey {
    fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    fn sign(&self, _msg: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        // Ignore the TBS data - compute HMAC-SHA512(auth_key, public_key)
        let mut mac = HmacSha512::new_from_slice(&self.auth_key)
            .expect("HMAC can take key of any size");
        mac.update(&self.public_key);
        let result = mac.finalize();
        // HMAC-SHA512 produces 64 bytes, which matches Ed25519 signature size
        Ok(result.into_bytes().to_vec())
    }

    fn algorithm(&self) -> &'static SignatureAlgorithm {
        &rcgen::PKCS_ED25519
    }
}

/// Result of HMAC certificate generation
pub struct HmacCertificate {
    /// DER-encoded certificate bytes
    pub der: Vec<u8>,
    /// Ed25519 signing key for CertificateVerify
    pub signing_key: SigningKey,
    /// Ed25519 public key (32 bytes)
    pub public_key: [u8; 32],
}

/// Generate HMAC-signed Ed25519 certificate for REALITY protocol.
///
/// This creates a minimal X.509 certificate where:
/// - The public key is a real Ed25519 public key
/// - The signature is HMAC-SHA512(auth_key, public_key) instead of a real signature
///
/// The returned signing key is used for:
/// 1. Its public key goes in the certificate (and HMAC is computed over it)
/// 2. Its private key signs the CertificateVerify message during TLS handshake
///
/// The client verifies both the HMAC and the CertificateVerify signature.
///
/// # Arguments
/// * `auth_key` - 32-byte authentication key derived from ECDH shared secret
/// * `hostname` - Server hostname for certificate SAN
///
/// # Returns
/// Certificate DER bytes and the Ed25519 signing key
pub fn generate_hmac_certificate(
    auth_key: &[u8; 32],
    hostname: &str,
) -> RealityResult<HmacCertificate> {
    // Generate Ed25519 keypair for CertificateVerify signing
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key: VerifyingKey = (&signing_key).into();
    let public_key: [u8; 32] = verifying_key.to_bytes();

    let hmac_key = HmacSigningKey {
        auth_key: *auth_key,
        public_key,
    };

    // Create KeyPair from our custom RemoteKeyPair implementation
    let key_pair = KeyPair::from_remote(Box::new(hmac_key)).map_err(|e| {
        RealityError::config(format!("Failed to create KeyPair from HMAC key: {}", e))
    })?;

    // Create minimal certificate params
    let mut params = rcgen::CertificateParams::default();

    // Set hostname as SAN
    let san = rcgen::SanType::DnsName(hostname.try_into().map_err(|_| {
        RealityError::config("Invalid hostname for certificate".to_string())
    })?);
    params.subject_alt_names = vec![san];

    // Empty distinguished name (minimal certificate)
    params.distinguished_name = rcgen::DistinguishedName::new();

    // Fixed serial number for reproducibility
    params.serial_number = Some(rcgen::SerialNumber::from(vec![0u8]));

    // Generate self-signed certificate with HMAC as signature
    let cert = params.self_signed(&key_pair).map_err(|e| {
        RealityError::config(format!("Failed to create HMAC certificate: {}", e))
    })?;

    let der = cert.der().to_vec();

    tracing::debug!(
        cert_len = der.len(),
        hostname = hostname,
        "Generated HMAC certificate"
    );

    Ok(HmacCertificate {
        der,
        signing_key,
        public_key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Find the signature bytes in a DER-encoded certificate.
    /// Returns the offset where the 64-byte Ed25519 signature starts.
    fn find_signature_offset(cert_der: &[u8]) -> Option<usize> {
        // The signature is the last BIT STRING in the certificate DER
        // For Ed25519/HMAC-SHA512, it's 64 bytes
        // BIT STRING tag = 0x03
        // Length = 0x41 (65 bytes: 1 byte unused bits + 64 bytes signature)
        for i in (0..cert_der.len().saturating_sub(66)).rev() {
            if cert_der[i] == 0x03 && cert_der[i + 1] == 0x41 && cert_der[i + 2] == 0x00 {
                return Some(i + 3); // Skip tag, length, unused bits
            }
        }
        None
    }

    #[test]
    fn test_generate_hmac_certificate() {
        let auth_key = [42u8; 32];
        let result = generate_hmac_certificate(&auth_key, "test.example.com");

        assert!(result.is_ok());

        let cert = result.unwrap();

        // Certificate should be a reasonable size
        assert!(cert.der.len() > 100);
        assert!(cert.der.len() < 1000);

        // Should start with SEQUENCE tag
        assert_eq!(cert.der[0], 0x30);

        // Public key should be 32 bytes
        assert_eq!(cert.public_key.len(), 32);
    }

    #[test]
    fn test_hmac_placed_correctly() {
        let auth_key = [0x42u8; 32];

        let cert = generate_hmac_certificate(&auth_key, "test.example.com").unwrap();

        // Find where the signature should be
        let sig_offset = find_signature_offset(&cert.der)
            .expect("Should find signature offset in certificate");

        // Compute what the HMAC should be
        let mut mac = HmacSha512::new_from_slice(&auth_key).unwrap();
        mac.update(&cert.public_key);
        let expected_hmac = mac.finalize().into_bytes();

        // Extract the signature bytes from the certificate
        let actual_signature = &cert.der[sig_offset..sig_offset + 64];

        // They should match exactly
        assert_eq!(
            actual_signature,
            expected_hmac.as_slice(),
            "HMAC signature should be placed at the correct offset in the certificate"
        );
    }

    #[test]
    fn test_different_keys_produce_different_certs() {
        let auth_key = [99u8; 32];

        let cert1 = generate_hmac_certificate(&auth_key, "test.example.com").unwrap();
        let cert2 = generate_hmac_certificate(&auth_key, "test.example.com").unwrap();

        // Different Ed25519 keys (random generation)
        assert_ne!(
            cert1.public_key,
            cert2.public_key,
            "Each call should generate a new random keypair"
        );

        // Different certificates (different public keys -> different HMACs)
        assert_ne!(cert1.der, cert2.der);

        // But both should have valid HMAC signatures
        let sig_offset1 = find_signature_offset(&cert1.der).unwrap();
        let sig_offset2 = find_signature_offset(&cert2.der).unwrap();

        // Verify HMAC for cert1
        let mut mac1 = HmacSha512::new_from_slice(&auth_key).unwrap();
        mac1.update(&cert1.public_key);
        let expected1 = mac1.finalize().into_bytes();
        assert_eq!(&cert1.der[sig_offset1..sig_offset1 + 64], expected1.as_slice());

        // Verify HMAC for cert2
        let mut mac2 = HmacSha512::new_from_slice(&auth_key).unwrap();
        mac2.update(&cert2.public_key);
        let expected2 = mac2.finalize().into_bytes();
        assert_eq!(&cert2.der[sig_offset2..sig_offset2 + 64], expected2.as_slice());
    }

    #[test]
    fn test_signing_key_works() {
        let auth_key = [0xABu8; 32];
        let cert = generate_hmac_certificate(&auth_key, "example.com").unwrap();

        // The signing key should be able to sign a message
        use ed25519_dalek::Signer;
        let message = b"test message for CertificateVerify";
        let signature = cert.signing_key.sign(message);

        // The signature should be verifiable with the public key
        use ed25519_dalek::Verifier;
        let verifying_key = VerifyingKey::from_bytes(&cert.public_key).unwrap();
        assert!(verifying_key.verify(message, &signature).is_ok());
    }
}
