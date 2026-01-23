//! X25519 key exchange for REALITY protocol
//!
//! Provides X25519 ECDH key exchange operations for TLS 1.3 and REALITY authentication.

use rand::RngCore;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::reality::common::{X25519_PRIVATE_KEY_SIZE, X25519_PUBLIC_KEY_SIZE, X25519_SHARED_SECRET_SIZE};
use crate::reality::error::{RealityError, RealityResult};

/// X25519 public key wrapper
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct X25519PublicKey([u8; X25519_PUBLIC_KEY_SIZE]);

impl X25519PublicKey {
    /// Create from raw bytes
    pub fn from_bytes(bytes: &[u8; X25519_PUBLIC_KEY_SIZE]) -> Self {
        Self(*bytes)
    }

    /// Create from slice
    pub fn from_slice(slice: &[u8]) -> RealityResult<Self> {
        if slice.len() != X25519_PUBLIC_KEY_SIZE {
            return Err(RealityError::invalid_public_key(format!(
                "Invalid X25519 public key length: {} (expected {})",
                slice.len(),
                X25519_PUBLIC_KEY_SIZE
            )));
        }
        let mut bytes = [0u8; X25519_PUBLIC_KEY_SIZE];
        bytes.copy_from_slice(slice);
        Ok(Self(bytes))
    }

    /// Get raw bytes
    pub fn as_bytes(&self) -> &[u8; X25519_PUBLIC_KEY_SIZE] {
        &self.0
    }

    /// Convert to byte array
    pub fn to_bytes(&self) -> [u8; X25519_PUBLIC_KEY_SIZE] {
        self.0
    }
}

impl AsRef<[u8]> for X25519PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for X25519PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "X25519PublicKey({:02x?})", &self.0[..8])
    }
}

/// X25519 key pair (private + public)
pub struct X25519KeyPair {
    private: StaticSecret,
    public: PublicKey,
}

impl X25519KeyPair {
    /// Generate a new random key pair
    pub fn generate() -> Self {
        let mut rng = rand::thread_rng();
        let private = StaticSecret::random_from_rng(&mut rng);
        let public = PublicKey::from(&private);
        Self { private, public }
    }

    /// Create from raw private key bytes
    pub fn from_private_key(private_bytes: &[u8; X25519_PRIVATE_KEY_SIZE]) -> Self {
        let private = StaticSecret::from(*private_bytes);
        let public = PublicKey::from(&private);
        Self { private, public }
    }

    /// Get private key bytes
    pub fn private_key_bytes(&self) -> [u8; X25519_PRIVATE_KEY_SIZE] {
        self.private.to_bytes()
    }

    /// Get public key
    pub fn public_key(&self) -> X25519PublicKey {
        X25519PublicKey(*self.public.as_bytes())
    }

    /// Get public key bytes
    pub fn public_key_bytes(&self) -> [u8; X25519_PUBLIC_KEY_SIZE] {
        *self.public.as_bytes()
    }

    /// Perform ECDH key exchange with peer's public key
    pub fn diffie_hellman(&self, peer_public: &X25519PublicKey) -> [u8; X25519_SHARED_SECRET_SIZE] {
        let peer = PublicKey::from(peer_public.0);
        *self.private.diffie_hellman(&peer).as_bytes()
    }
}

/// Generate a new X25519 key pair
///
/// # Returns
/// * `X25519KeyPair` - New random key pair
pub fn generate_keypair() -> X25519KeyPair {
    X25519KeyPair::generate()
}

/// Perform X25519 ECDH key exchange
///
/// # Arguments
/// * `private_key` - 32-byte X25519 private key
/// * `public_key` - 32-byte X25519 public key of the peer
///
/// # Returns
/// * `Ok([u8; 32])` - 32-byte shared secret
/// * `Err` - If key exchange fails
pub fn perform_ecdh(
    private_key: &[u8; X25519_PRIVATE_KEY_SIZE],
    public_key: &[u8; X25519_PUBLIC_KEY_SIZE],
) -> RealityResult<[u8; X25519_SHARED_SECRET_SIZE]> {
    let keypair = X25519KeyPair::from_private_key(private_key);
    let peer_public = X25519PublicKey::from_bytes(public_key);
    Ok(keypair.diffie_hellman(&peer_public))
}

/// Decode base64url-encoded public key
///
/// # Arguments
/// * `encoded` - Base64url encoded public key (with or without padding)
///
/// # Returns
/// * `Ok([u8; 32])` - Raw public key bytes
/// * `Err` - If decoding fails or length is wrong
pub fn decode_public_key(encoded: &str) -> RealityResult<[u8; X25519_PUBLIC_KEY_SIZE]> {
    use base64::Engine;

    // Try standard base64 first, then URL-safe
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(encoded))
        .map_err(|e| RealityError::invalid_public_key(format!("Invalid base64: {}", e)))?;

    if decoded.len() != X25519_PUBLIC_KEY_SIZE {
        return Err(RealityError::invalid_public_key(format!(
            "Invalid public key length: {} (expected {})",
            decoded.len(),
            X25519_PUBLIC_KEY_SIZE
        )));
    }

    let mut bytes = [0u8; X25519_PUBLIC_KEY_SIZE];
    bytes.copy_from_slice(&decoded);
    Ok(bytes)
}

/// Decode base64url-encoded private key
///
/// # Arguments
/// * `encoded` - Base64url encoded private key (with or without padding)
///
/// # Returns
/// * `Ok([u8; 32])` - Raw private key bytes
/// * `Err` - If decoding fails or length is wrong
pub fn decode_private_key(encoded: &str) -> RealityResult<[u8; X25519_PRIVATE_KEY_SIZE]> {
    use base64::Engine;

    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(encoded))
        .map_err(|e| RealityError::key_derivation(format!("Invalid base64: {}", e)))?;

    if decoded.len() != X25519_PRIVATE_KEY_SIZE {
        return Err(RealityError::key_derivation(format!(
            "Invalid private key length: {} (expected {})",
            decoded.len(),
            X25519_PRIVATE_KEY_SIZE
        )));
    }

    let mut bytes = [0u8; X25519_PRIVATE_KEY_SIZE];
    bytes.copy_from_slice(&decoded);
    Ok(bytes)
}

/// Encode public key as base64
pub fn encode_public_key(key: &[u8; X25519_PUBLIC_KEY_SIZE]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(key)
}

/// Encode private key as base64
pub fn encode_private_key(key: &[u8; X25519_PRIVATE_KEY_SIZE]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(key)
}

/// Generate random bytes
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let keypair1 = generate_keypair();
        let keypair2 = generate_keypair();

        // Different key pairs should have different public keys
        assert_ne!(keypair1.public_key_bytes(), keypair2.public_key_bytes());
    }

    #[test]
    fn test_ecdh_shared_secret() {
        let alice = generate_keypair();
        let bob = generate_keypair();

        // Alice computes shared secret with Bob's public key
        let alice_shared = alice.diffie_hellman(&bob.public_key());

        // Bob computes shared secret with Alice's public key
        let bob_shared = bob.diffie_hellman(&alice.public_key());

        // Both should arrive at the same shared secret
        assert_eq!(alice_shared, bob_shared);
    }

    #[test]
    fn test_perform_ecdh() {
        let alice_private = random_bytes::<32>();
        let alice_keypair = X25519KeyPair::from_private_key(&alice_private);
        let alice_public = alice_keypair.public_key_bytes();

        let bob_private = random_bytes::<32>();
        let bob_keypair = X25519KeyPair::from_private_key(&bob_private);
        let bob_public = bob_keypair.public_key_bytes();

        let alice_shared = perform_ecdh(&alice_private, &bob_public).unwrap();
        let bob_shared = perform_ecdh(&bob_private, &alice_public).unwrap();

        assert_eq!(alice_shared, bob_shared);
    }

    #[test]
    fn test_from_private_key() {
        let private_bytes = random_bytes::<32>();
        let keypair1 = X25519KeyPair::from_private_key(&private_bytes);
        let keypair2 = X25519KeyPair::from_private_key(&private_bytes);

        // Same private key should produce same public key
        assert_eq!(keypair1.public_key_bytes(), keypair2.public_key_bytes());
    }

    #[test]
    fn test_decode_public_key() {
        // Standard base64 with padding
        let encoded = "UuMBgl7MXTPCQo57FPi4gkLxvkJedeWFWW2oU1hwGDA=";
        let result = decode_public_key(encoded);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 32);
    }

    #[test]
    fn test_decode_public_key_url_safe() {
        // URL-safe base64 without padding
        let keypair = generate_keypair();
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            keypair.public_key_bytes(),
        );

        let result = decode_public_key(&encoded);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), keypair.public_key_bytes());
    }

    #[test]
    fn test_decode_public_key_invalid() {
        // Invalid base64
        let result = decode_public_key("not-valid-base64!!!");
        assert!(result.is_err());

        // Wrong length
        let result = decode_public_key("AAAA"); // Only 3 bytes
        assert!(result.is_err());
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let keypair = generate_keypair();
        let public_bytes = keypair.public_key_bytes();

        let encoded = encode_public_key(&public_bytes);
        let decoded = decode_public_key(&encoded).unwrap();

        assert_eq!(public_bytes, decoded);
    }

    #[test]
    fn test_x25519_public_key_from_slice() {
        let bytes = random_bytes::<32>();
        let pubkey = X25519PublicKey::from_slice(&bytes).unwrap();
        assert_eq!(pubkey.as_bytes(), &bytes);

        // Wrong length should fail
        let short = &bytes[..16];
        assert!(X25519PublicKey::from_slice(short).is_err());
    }

    #[test]
    fn test_random_bytes() {
        let bytes1: [u8; 32] = random_bytes();
        let bytes2: [u8; 32] = random_bytes();

        // Should be different (with overwhelming probability)
        assert_ne!(bytes1, bytes2);
    }

    #[test]
    fn test_private_key_encode_decode() {
        let keypair = generate_keypair();
        let private_bytes = keypair.private_key_bytes();

        let encoded = encode_private_key(&private_bytes);
        let decoded = decode_private_key(&encoded).unwrap();

        assert_eq!(private_bytes, decoded);
    }

    #[test]
    fn test_keypair_consistency() {
        let private_bytes = random_bytes::<32>();
        let keypair = X25519KeyPair::from_private_key(&private_bytes);

        // Getting private bytes should return the original
        assert_eq!(keypair.private_key_bytes(), private_bytes);

        // Public key should be derivable from private key
        let public = keypair.public_key();
        assert_eq!(public.to_bytes(), keypair.public_key_bytes());
    }
}
