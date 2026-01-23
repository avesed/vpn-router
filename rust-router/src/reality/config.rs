//! REALITY protocol configuration types
//!
//! This module defines configuration types for REALITY client connections.
//! REALITY is a TLS 1.3 camouflage protocol that makes VPN connections
//! look like legitimate HTTPS traffic.

use serde::{Deserialize, Serialize};

use super::error::{RealityError, RealityResult};

/// Default fingerprint to impersonate
const DEFAULT_FINGERPRINT: &str = "chrome";

/// REALITY client configuration
///
/// This structure contains all parameters needed to establish a REALITY
/// connection to a server. The configuration includes TLS parameters
/// for camouflage and authentication credentials.
///
/// # Example
///
/// ```
/// use rust_router::reality::RealityConfig;
///
/// let config = RealityConfig::new(
///     "www.google.com",
///     "UuMBgl7MXTPCQo57FPi4gkLxvkJedeWFWW2oU1hwGDA=",
///     "12345678",
/// );
///
/// assert_eq!(config.server_name(), "www.google.com");
/// assert_eq!(config.fingerprint(), "chrome");
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealityConfig {
    /// Server name for SNI (Server Name Indication)
    ///
    /// This should be a legitimate domain that the target server can
    /// impersonate (e.g., "www.google.com", "www.apple.com").
    server_name: String,

    /// Server's X25519 public key (base64 encoded)
    ///
    /// This is the server's REALITY public key, not the TLS certificate
    /// public key. The client uses this to derive shared secrets for
    /// authentication.
    public_key: String,

    /// Short ID for authentication (hex encoded, up to 8 bytes)
    ///
    /// The short ID is used by the server to identify authorized clients.
    /// It must match one of the short IDs configured on the server.
    short_id: String,

    /// Browser fingerprint to impersonate
    ///
    /// Valid values: "chrome", "firefox", "safari", "edge", "random"
    /// The client will mimic the TLS fingerprint of the specified browser.
    fingerprint: String,

    /// Spider URL for probing (optional)
    ///
    /// If specified, the client may use this URL to fetch real TLS
    /// certificates for better camouflage.
    #[serde(skip_serializing_if = "Option::is_none")]
    spider_x: Option<String>,
}

impl RealityConfig {
    /// Create a new REALITY configuration with default fingerprint
    ///
    /// # Arguments
    ///
    /// * `server_name` - The SNI to use (e.g., "www.google.com")
    /// * `public_key` - Server's X25519 public key (base64)
    /// * `short_id` - Authentication short ID (hex, up to 8 bytes)
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::reality::RealityConfig;
    ///
    /// let config = RealityConfig::new(
    ///     "www.google.com",
    ///     "UuMBgl7MXTPCQo57FPi4gkLxvkJedeWFWW2oU1hwGDA=",
    ///     "abcd1234",
    /// );
    /// ```
    #[must_use]
    pub fn new(server_name: &str, public_key: &str, short_id: &str) -> Self {
        Self {
            server_name: server_name.to_string(),
            public_key: public_key.to_string(),
            short_id: short_id.to_string(),
            fingerprint: DEFAULT_FINGERPRINT.to_string(),
            spider_x: None,
        }
    }

    /// Create a new REALITY configuration with all parameters
    ///
    /// # Arguments
    ///
    /// * `server_name` - The SNI to use
    /// * `public_key` - Server's X25519 public key (base64)
    /// * `short_id` - Authentication short ID (hex, up to 8 bytes)
    /// * `fingerprint` - Browser fingerprint to impersonate
    /// * `spider_x` - Optional spider URL for probing
    #[must_use]
    pub fn with_options(
        server_name: &str,
        public_key: &str,
        short_id: &str,
        fingerprint: &str,
        spider_x: Option<&str>,
    ) -> Self {
        Self {
            server_name: server_name.to_string(),
            public_key: public_key.to_string(),
            short_id: short_id.to_string(),
            fingerprint: fingerprint.to_string(),
            spider_x: spider_x.map(String::from),
        }
    }

    /// Get the server name (SNI)
    #[must_use]
    pub fn server_name(&self) -> &str {
        &self.server_name
    }

    /// Get the server's public key
    #[must_use]
    pub fn public_key(&self) -> &str {
        &self.public_key
    }

    /// Get the short ID
    #[must_use]
    pub fn short_id(&self) -> &str {
        &self.short_id
    }

    /// Get the fingerprint
    #[must_use]
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// Get the spider URL
    #[must_use]
    pub fn spider_x(&self) -> Option<&str> {
        self.spider_x.as_deref()
    }

    /// Set the fingerprint
    pub fn set_fingerprint(&mut self, fingerprint: &str) {
        self.fingerprint = fingerprint.to_string();
    }

    /// Set the spider URL
    pub fn set_spider_x(&mut self, url: Option<&str>) {
        self.spider_x = url.map(String::from);
    }

    /// Validate the configuration
    ///
    /// Checks that all required fields are present and properly formatted.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Server name is empty
    /// - Public key is not valid base64 or wrong length
    /// - Short ID is not valid hex or too long
    /// - Fingerprint is not a recognized value
    ///
    /// # Example
    ///
    /// ```
    /// use rust_router::reality::RealityConfig;
    ///
    /// let config = RealityConfig::new(
    ///     "www.google.com",
    ///     "UuMBgl7MXTPCQo57FPi4gkLxvkJedeWFWW2oU1hwGDA=",
    ///     "12345678",
    /// );
    ///
    /// assert!(config.validate().is_ok());
    /// ```
    pub fn validate(&self) -> RealityResult<()> {
        // Validate server name
        if self.server_name.is_empty() {
            return Err(RealityError::invalid_server_name("server name cannot be empty"));
        }

        // Validate public key (should be 32 bytes when decoded)
        self.validate_public_key()?;

        // Validate short ID (up to 8 bytes hex)
        self.validate_short_id()?;

        // Validate fingerprint
        self.validate_fingerprint()?;

        Ok(())
    }

    /// Validate the public key format
    fn validate_public_key(&self) -> RealityResult<()> {
        use base64::Engine;

        if self.public_key.is_empty() {
            return Err(RealityError::invalid_public_key("public key cannot be empty"));
        }

        // Decode base64 and check length
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&self.public_key)
            .map_err(|e| RealityError::invalid_public_key(format!("invalid base64: {e}")))?;

        if decoded.len() != 32 {
            return Err(RealityError::invalid_public_key(format!(
                "expected 32 bytes, got {}",
                decoded.len()
            )));
        }

        Ok(())
    }

    /// Validate the short ID format
    fn validate_short_id(&self) -> RealityResult<()> {
        if self.short_id.is_empty() {
            return Err(RealityError::invalid_short_id("short ID cannot be empty"));
        }

        // Short ID should be hex encoded, up to 8 bytes (16 hex chars)
        if self.short_id.len() > 16 {
            return Err(RealityError::invalid_short_id(format!(
                "short ID too long: {} chars (max 16)",
                self.short_id.len()
            )));
        }

        // Validate hex encoding
        hex::decode(&self.short_id)
            .map_err(|e| RealityError::invalid_short_id(format!("invalid hex: {e}")))?;

        Ok(())
    }

    /// Validate the fingerprint value
    fn validate_fingerprint(&self) -> RealityResult<()> {
        const VALID_FINGERPRINTS: &[&str] =
            &["chrome", "firefox", "safari", "edge", "random", "ios", "android"];

        if !VALID_FINGERPRINTS.contains(&self.fingerprint.as_str()) {
            return Err(RealityError::invalid_fingerprint(format!(
                "unknown fingerprint '{}', valid options: {}",
                self.fingerprint,
                VALID_FINGERPRINTS.join(", ")
            )));
        }

        Ok(())
    }

    /// Decode the public key to raw bytes
    ///
    /// # Errors
    ///
    /// Returns an error if the public key is not valid base64 or wrong length.
    pub fn decode_public_key(&self) -> RealityResult<[u8; 32]> {
        use base64::Engine;

        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&self.public_key)
            .map_err(|e| RealityError::invalid_public_key(format!("invalid base64: {e}")))?;

        decoded
            .try_into()
            .map_err(|_| RealityError::invalid_public_key("expected 32 bytes"))
    }

    /// Decode the short ID to raw bytes
    ///
    /// # Errors
    ///
    /// Returns an error if the short ID is not valid hex.
    pub fn decode_short_id(&self) -> RealityResult<Vec<u8>> {
        hex::decode(&self.short_id)
            .map_err(|e| RealityError::invalid_short_id(format!("invalid hex: {e}")))
    }
}

impl Default for RealityConfig {
    fn default() -> Self {
        Self {
            server_name: String::new(),
            public_key: String::new(),
            short_id: String::new(),
            fingerprint: DEFAULT_FINGERPRINT.to_string(),
            spider_x: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Valid test key (32 bytes base64 encoded, with padding)
    const TEST_PUBLIC_KEY: &str = "UuMBgl7MXTPCQo57FPi4gkLxvkJedeWFWW2oU1hwGDA=";
    const TEST_SHORT_ID: &str = "12345678";
    const TEST_SERVER_NAME: &str = "www.google.com";

    #[test]
    fn test_new() {
        let config = RealityConfig::new(TEST_SERVER_NAME, TEST_PUBLIC_KEY, TEST_SHORT_ID);

        assert_eq!(config.server_name(), TEST_SERVER_NAME);
        assert_eq!(config.public_key(), TEST_PUBLIC_KEY);
        assert_eq!(config.short_id(), TEST_SHORT_ID);
        assert_eq!(config.fingerprint(), DEFAULT_FINGERPRINT);
        assert!(config.spider_x().is_none());
    }

    #[test]
    fn test_with_options() {
        let config = RealityConfig::with_options(
            TEST_SERVER_NAME,
            TEST_PUBLIC_KEY,
            TEST_SHORT_ID,
            "firefox",
            Some("/spider"),
        );

        assert_eq!(config.fingerprint(), "firefox");
        assert_eq!(config.spider_x(), Some("/spider"));
    }

    #[test]
    fn test_validate_success() {
        let config = RealityConfig::new(TEST_SERVER_NAME, TEST_PUBLIC_KEY, TEST_SHORT_ID);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_empty_server_name() {
        let config = RealityConfig::new("", TEST_PUBLIC_KEY, TEST_SHORT_ID);
        let err = config.validate().unwrap_err();
        assert!(matches!(err, RealityError::InvalidServerName(_)));
    }

    #[test]
    fn test_validate_empty_public_key() {
        let config = RealityConfig::new(TEST_SERVER_NAME, "", TEST_SHORT_ID);
        let err = config.validate().unwrap_err();
        assert!(matches!(err, RealityError::InvalidPublicKey(_)));
    }

    #[test]
    fn test_validate_invalid_public_key_base64() {
        let config = RealityConfig::new(TEST_SERVER_NAME, "not-valid-base64!!!", TEST_SHORT_ID);
        let err = config.validate().unwrap_err();
        assert!(matches!(err, RealityError::InvalidPublicKey(_)));
    }

    #[test]
    fn test_validate_wrong_length_public_key() {
        // This is valid base64 but only 16 bytes
        let config = RealityConfig::new(TEST_SERVER_NAME, "AAAAAAAAAAAAAAAAAAAAAA==", TEST_SHORT_ID);
        let err = config.validate().unwrap_err();
        assert!(matches!(err, RealityError::InvalidPublicKey(_)));
        assert!(err.to_string().contains("expected 32 bytes"));
    }

    #[test]
    fn test_validate_empty_short_id() {
        let config = RealityConfig::new(TEST_SERVER_NAME, TEST_PUBLIC_KEY, "");
        let err = config.validate().unwrap_err();
        assert!(matches!(err, RealityError::InvalidShortId(_)));
    }

    #[test]
    fn test_validate_invalid_short_id_hex() {
        let config = RealityConfig::new(TEST_SERVER_NAME, TEST_PUBLIC_KEY, "not-hex");
        let err = config.validate().unwrap_err();
        assert!(matches!(err, RealityError::InvalidShortId(_)));
    }

    #[test]
    fn test_validate_short_id_too_long() {
        let config =
            RealityConfig::new(TEST_SERVER_NAME, TEST_PUBLIC_KEY, "12345678901234567890");
        let err = config.validate().unwrap_err();
        assert!(matches!(err, RealityError::InvalidShortId(_)));
        assert!(err.to_string().contains("too long"));
    }

    #[test]
    fn test_validate_invalid_fingerprint() {
        let mut config = RealityConfig::new(TEST_SERVER_NAME, TEST_PUBLIC_KEY, TEST_SHORT_ID);
        config.set_fingerprint("invalid-browser");
        let err = config.validate().unwrap_err();
        assert!(matches!(err, RealityError::InvalidFingerprint(_)));
    }

    #[test]
    fn test_validate_all_fingerprints() {
        let fingerprints = ["chrome", "firefox", "safari", "edge", "random", "ios", "android"];
        for fp in fingerprints {
            let mut config = RealityConfig::new(TEST_SERVER_NAME, TEST_PUBLIC_KEY, TEST_SHORT_ID);
            config.set_fingerprint(fp);
            assert!(config.validate().is_ok(), "fingerprint '{}' should be valid", fp);
        }
    }

    #[test]
    fn test_decode_public_key() {
        let config = RealityConfig::new(TEST_SERVER_NAME, TEST_PUBLIC_KEY, TEST_SHORT_ID);
        let decoded = config.decode_public_key().unwrap();
        assert_eq!(decoded.len(), 32);
    }

    #[test]
    fn test_decode_short_id() {
        let config = RealityConfig::new(TEST_SERVER_NAME, TEST_PUBLIC_KEY, TEST_SHORT_ID);
        let decoded = config.decode_short_id().unwrap();
        assert_eq!(decoded, vec![0x12, 0x34, 0x56, 0x78]);
    }

    #[test]
    fn test_serde_roundtrip() {
        let config = RealityConfig::with_options(
            TEST_SERVER_NAME,
            TEST_PUBLIC_KEY,
            TEST_SHORT_ID,
            "firefox",
            Some("/spider"),
        );

        let json = serde_json::to_string(&config).unwrap();
        let parsed: RealityConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.server_name(), config.server_name());
        assert_eq!(parsed.public_key(), config.public_key());
        assert_eq!(parsed.short_id(), config.short_id());
        assert_eq!(parsed.fingerprint(), config.fingerprint());
        assert_eq!(parsed.spider_x(), config.spider_x());
    }

    #[test]
    fn test_default() {
        let config = RealityConfig::default();
        assert!(config.server_name().is_empty());
        assert!(config.public_key().is_empty());
        assert!(config.short_id().is_empty());
        assert_eq!(config.fingerprint(), DEFAULT_FINGERPRINT);
        assert!(config.spider_x().is_none());
    }

    #[test]
    fn test_setters() {
        let mut config = RealityConfig::new(TEST_SERVER_NAME, TEST_PUBLIC_KEY, TEST_SHORT_ID);

        config.set_fingerprint("firefox");
        assert_eq!(config.fingerprint(), "firefox");

        config.set_spider_x(Some("/spider"));
        assert_eq!(config.spider_x(), Some("/spider"));

        config.set_spider_x(None);
        assert!(config.spider_x().is_none());
    }
}
