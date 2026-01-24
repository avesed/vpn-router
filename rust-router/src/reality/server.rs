//! REALITY Server Implementation
//!
//! This module implements the server-side REALITY protocol, which provides
//! TLS 1.3 camouflage for incoming VLESS connections.
//!
//! # How Server-Side REALITY Works
//!
//! 1. **Accept TLS Connection**: Server receives a TLS 1.3 ClientHello
//!
//! 2. **Extract Client Info**: Parse ClientHello for:
//!    - session_id (contains encrypted REALITY metadata)
//!    - client_random (contains salt and nonce for decryption)
//!    - client's X25519 public key (from key_share extension)
//!    - SNI server name
//!
//! 3. **Validate REALITY Auth**: Decrypt and validate session_id:
//!    - Derive shared secret using server private key + client public key
//!    - Derive auth key using HKDF
//!    - Decrypt session_id using AES-256-GCM
//!    - Validate short_id is in allowed list
//!    - Validate timestamp is within acceptable range
//!
//! 4. **Complete TLS 1.3 Handshake**:
//!    - Generate server ephemeral X25519 keypair
//!    - Send ServerHello with server's ephemeral public key
//!    - Derive handshake keys using shared secret
//!    - Send encrypted EncryptedExtensions + Finished
//!    - Receive and verify client's Finished
//!    - Derive application traffic keys
//!
//! 5. **Handle Result**:
//!    - If valid: Return encrypted stream for VLESS protocol
//!    - If invalid: Transparently proxy to fallback destination
//!
//! # Example
//!
//! ```no_run
//! use rust_router::reality::server::{RealityServer, RealityServerConfig, RealityAcceptResult};
//! use tokio::net::TcpListener;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = RealityServerConfig {
//!     private_key: [0x42u8; 32],
//!     short_ids: vec![vec![0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0]],
//!     dest: "www.google.com:443".to_string(),
//!     server_names: vec!["www.google.com".to_string()],
//!     max_time_diff_ms: 120_000,
//! };
//!
//! let server = RealityServer::new(config);
//! let listener = TcpListener::bind("0.0.0.0:443").await?;
//!
//! loop {
//!     let (stream, _) = listener.accept().await?;
//!     let server = server.clone();
//!
//!     tokio::spawn(async move {
//!         match server.accept_with_handshake(stream).await {
//!             Ok(RealityAcceptResult::Authenticated { stream, short_id, .. }) => {
//!                 // Valid REALITY client - proceed with VLESS
//!                 println!("Authenticated with short_id: {:?}", short_id);
//!             }
//!             Ok(RealityAcceptResult::Fallback) => {
//!                 // Invalid auth - already proxied to fallback
//!                 println!("Proxied to fallback");
//!             }
//!             Err(e) => {
//!                 eprintln!("Accept error: {}", e);
//!             }
//!         }
//!     });
//! }
//! # }
//! ```

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use sha2::{Digest, Sha256, Sha384};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tracing::{debug, trace, warn};

use crate::reality::auth::{decode_short_id, derive_auth_key, validate_auth};
use crate::reality::certificate::generate_hmac_certificate;
use crate::reality::common::{
    CONTENT_TYPE_APPLICATION_DATA, CONTENT_TYPE_CHANGE_CIPHER_SPEC, CONTENT_TYPE_HANDSHAKE,
    HANDSHAKE_TYPE_FINISHED, REALITY_AUTH_INFO, REALITY_DEFAULT_MAX_TIME_DIFF_MS,
    REALITY_SESSION_ID_SIZE, REALITY_SHORT_ID_SIZE, TLS_RECORD_HEADER_SIZE,
};
use crate::reality::crypto::{
    compute_finished_verify_data, decrypt_handshake_message, derive_application_secrets,
    derive_handshake_keys, derive_traffic_keys, generate_keypair, perform_ecdh, AeadKey,
    CipherSuite, HashAlgorithm, DEFAULT_CIPHER_SUITES,
};
use crate::reality::error::{RealityError, RealityResult};
use crate::reality::tls::{
    construct_certificate, construct_certificate_verify, construct_encrypted_extensions,
    construct_finished, construct_server_hello, extract_client_public_key, extract_client_random,
    extract_session_id, write_record_header, RecordDecryptor, RecordEncryptor,
};

/// Maximum size of ClientHello we'll accept (reasonable limit)
const MAX_CLIENT_HELLO_SIZE: usize = 16384;

/// REALITY server configuration
#[derive(Debug, Clone)]
pub struct RealityServerConfig {
    /// Server private key (X25519, 32 bytes)
    pub private_key: [u8; 32],
    /// Allowed short IDs (each up to 8 bytes)
    pub short_ids: Vec<Vec<u8>>,
    /// Fallback destination (e.g., "www.google.com:443")
    pub dest: String,
    /// Allowed SNI server names
    pub server_names: Vec<String>,
    /// Maximum timestamp difference in milliseconds (default: 120000 = 2 minutes)
    pub max_time_diff_ms: u64,
}

impl RealityServerConfig {
    /// Create a new REALITY server configuration
    ///
    /// # Arguments
    /// * `private_key` - Server's X25519 private key (32 bytes)
    /// * `dest` - Fallback destination address
    pub fn new(private_key: [u8; 32], dest: impl Into<String>) -> Self {
        Self {
            private_key,
            short_ids: Vec::new(),
            dest: dest.into(),
            server_names: Vec::new(),
            max_time_diff_ms: REALITY_DEFAULT_MAX_TIME_DIFF_MS * 2, // 2 minutes
        }
    }

    /// Add an allowed short ID
    #[must_use]
    pub fn with_short_id(mut self, short_id: impl Into<Vec<u8>>) -> Self {
        self.short_ids.push(short_id.into());
        self
    }

    /// Add an allowed short ID from hex string
    ///
    /// # Errors
    /// Returns error if hex string is invalid
    pub fn with_short_id_hex(mut self, hex_str: &str) -> RealityResult<Self> {
        let short_id = decode_short_id(hex_str)?;
        self.short_ids.push(short_id.to_vec());
        Ok(self)
    }

    /// Add an allowed server name
    #[must_use]
    pub fn with_server_name(mut self, name: impl Into<String>) -> Self {
        self.server_names.push(name.into());
        self
    }

    /// Set maximum timestamp difference
    #[must_use]
    pub fn with_max_time_diff_ms(mut self, ms: u64) -> Self {
        self.max_time_diff_ms = ms;
        self
    }

    /// Validate the configuration
    ///
    /// # Errors
    /// Returns error if configuration is invalid
    pub fn validate(&self) -> RealityResult<()> {
        if self.short_ids.is_empty() {
            return Err(RealityError::config("No short IDs configured"));
        }

        for (i, short_id) in self.short_ids.iter().enumerate() {
            if short_id.is_empty() || short_id.len() > REALITY_SHORT_ID_SIZE {
                return Err(RealityError::config(format!(
                    "Short ID {} has invalid length: {} (expected 1-8 bytes)",
                    i,
                    short_id.len()
                )));
            }
        }

        if self.dest.is_empty() {
            return Err(RealityError::config("Fallback destination is empty"));
        }

        if self.server_names.is_empty() {
            return Err(RealityError::config("No server names configured"));
        }

        if self.max_time_diff_ms == 0 {
            return Err(RealityError::config("max_time_diff_ms cannot be zero"));
        }

        Ok(())
    }

    /// Get the server's public key derived from private key
    #[must_use]
    pub fn public_key(&self) -> [u8; 32] {
        use x25519_dalek::{PublicKey, StaticSecret};
        let secret = StaticSecret::from(self.private_key);
        let public = PublicKey::from(&secret);
        *public.as_bytes()
    }

    /// Normalize short IDs to 8-byte arrays for comparison
    fn normalized_short_ids(&self) -> Vec<[u8; REALITY_SHORT_ID_SIZE]> {
        self.short_ids
            .iter()
            .map(|id| {
                let mut arr = [0u8; REALITY_SHORT_ID_SIZE];
                let len = id.len().min(REALITY_SHORT_ID_SIZE);
                arr[..len].copy_from_slice(&id[..len]);
                arr
            })
            .collect()
    }
}

impl Default for RealityServerConfig {
    fn default() -> Self {
        Self {
            private_key: [0u8; 32],
            short_ids: Vec::new(),
            dest: "www.google.com:443".to_string(),
            server_names: vec!["www.google.com".to_string()],
            max_time_diff_ms: REALITY_DEFAULT_MAX_TIME_DIFF_MS * 2,
        }
    }
}

/// Connection result after REALITY validation (without TLS handshake)
///
/// **Deprecated**: Use `RealityHandshakeResult` from `accept_with_handshake()` instead.
/// This result returns the raw TCP stream after REALITY auth validation,
/// but the TLS 1.3 handshake is NOT completed.
#[derive(Debug)]
pub enum RealityAcceptResult<S> {
    /// Valid REALITY auth - proceed with VLESS
    Authenticated {
        /// The authenticated stream (RAW - TLS handshake NOT complete)
        stream: S,
        /// The matched short ID
        short_id: Vec<u8>,
        /// Buffered data after ClientHello (if any)
        buffered: Vec<u8>,
    },
    /// Invalid auth - connection proxied to fallback
    Fallback,
}

/// Connection result after complete REALITY + TLS 1.3 handshake
pub enum RealityHandshakeResult<S: AsyncRead + AsyncWrite + Unpin> {
    /// Valid REALITY auth with completed TLS 1.3 handshake
    Authenticated {
        /// Encrypted stream ready for application data
        stream: RealityServerStream<S>,
        /// The matched short ID
        short_id: Vec<u8>,
    },
    /// Invalid auth - connection proxied to fallback
    Fallback,
}

/// Default cipher suite for REALITY server
const DEFAULT_SERVER_CIPHER_SUITE: CipherSuite = CipherSuite::AES_128_GCM_SHA256;

/// Encrypted stream wrapper for REALITY server connections
///
/// Provides AsyncRead/AsyncWrite over the encrypted TLS 1.3 channel.
pub struct RealityServerStream<T> {
    inner: T,
    cipher_suite: CipherSuite,
    /// Server's application traffic key bytes (for encrypting outbound data)
    server_app_key_bytes: Vec<u8>,
    server_app_iv: Vec<u8>,
    /// Client's application traffic key bytes (for decrypting inbound data)
    client_app_key_bytes: Vec<u8>,
    client_app_iv: Vec<u8>,
    /// Sequence numbers
    write_seq: u64,
    read_seq: u64,
    /// Read buffer for decrypted data
    read_buffer: Vec<u8>,
    read_offset: usize,
    /// Input buffer for accumulating TLS records
    input_buffer: Vec<u8>,
}

impl<T> RealityServerStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    /// Create a new server stream with established keys
    fn new(
        inner: T,
        cipher_suite: CipherSuite,
        server_app_key_bytes: Vec<u8>,
        server_app_iv: Vec<u8>,
        client_app_key_bytes: Vec<u8>,
        client_app_iv: Vec<u8>,
    ) -> Self {
        Self {
            inner,
            cipher_suite,
            server_app_key_bytes,
            server_app_iv,
            client_app_key_bytes,
            client_app_iv,
            write_seq: 0,
            read_seq: 0,
            read_buffer: Vec::new(),
            read_offset: 0,
            input_buffer: Vec::new(),
        }
    }

    /// Get a reference to the underlying transport
    pub fn get_ref(&self) -> &T {
        &self.inner
    }

    /// Get a mutable reference to the underlying transport
    pub fn get_mut(&mut self) -> &mut T {
        &mut self.inner
    }

    /// Consume the stream and return the underlying transport
    pub fn into_inner(self) -> T {
        self.inner
    }
}

impl<T> AsyncRead for RealityServerStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Return buffered data first
        if self.read_offset < self.read_buffer.len() {
            let available = &self.read_buffer[self.read_offset..];
            let to_copy = available.len().min(buf.remaining());
            buf.put_slice(&available[..to_copy]);
            self.read_offset += to_copy;

            if self.read_offset >= self.read_buffer.len() {
                self.read_buffer.clear();
                self.read_offset = 0;
            }

            return Poll::Ready(Ok(()));
        }

        // Read from underlying transport into input_buffer
        let mut read_buf = vec![0u8; 16384];
        let mut tmp_buf = ReadBuf::new(&mut read_buf);

        match Pin::new(&mut self.inner).poll_read(cx, &mut tmp_buf) {
            Poll::Ready(Ok(())) => {
                let n = tmp_buf.filled().len();
                if n == 0 {
                    return Poll::Ready(Ok(())); // EOF
                }

                self.input_buffer.extend_from_slice(&read_buf[..n]);

                // Try to decrypt a complete record
                if self.input_buffer.len() < TLS_RECORD_HEADER_SIZE {
                    // Need more data - wake up again
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }

                let record_len =
                    u16::from_be_bytes([self.input_buffer[3], self.input_buffer[4]]) as usize;
                let total_len = TLS_RECORD_HEADER_SIZE + record_len;

                if self.input_buffer.len() < total_len {
                    // Need more data
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }

                // Extract and decrypt record
                let mut ciphertext: Vec<u8> = self
                    .input_buffer
                    .drain(..total_len)
                    .skip(TLS_RECORD_HEADER_SIZE)
                    .collect();

                // Extract values to avoid borrow conflicts
                let cipher_suite = self.cipher_suite;
                let client_key_bytes = self.client_app_key_bytes.clone();
                let client_iv = self.client_app_iv.clone();

                let client_key = match AeadKey::new(cipher_suite, &client_key_bytes) {
                    Ok(k) => k,
                    Err(e) => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("Failed to create decryption key: {}", e),
                        )));
                    }
                };

                let mut decryptor = RecordDecryptor::new(
                    &client_key,
                    &client_iv,
                    &mut self.read_seq,
                );

                match decryptor.decrypt_record_in_place(&mut ciphertext, record_len as u16) {
                    Ok((content_type, plaintext)) => {
                        if content_type == CONTENT_TYPE_APPLICATION_DATA {
                            let to_copy = plaintext.len().min(buf.remaining());
                            buf.put_slice(&plaintext[..to_copy]);

                            if to_copy < plaintext.len() {
                                self.read_buffer.extend_from_slice(&plaintext[to_copy..]);
                                self.read_offset = 0;
                            }
                        }
                        // Ignore alerts and other content types for now

                        Poll::Ready(Ok(()))
                    }
                    Err(e) => Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("Decryption failed: {}", e),
                    ))),
                }
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<T> AsyncWrite for RealityServerStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // Encrypt the data
        let mut plaintext_buf = buf.to_vec();
        let mut ciphertext_buf = Vec::new();

        // Extract values to avoid borrow conflicts
        let cipher_suite = self.cipher_suite;
        let server_key_bytes = self.server_app_key_bytes.clone();
        let server_iv = self.server_app_iv.clone();

        let server_key = match AeadKey::new(cipher_suite, &server_key_bytes) {
            Ok(k) => k,
            Err(e) => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Failed to create encryption key: {}", e),
                )));
            }
        };

        {
            let mut encryptor = RecordEncryptor::new(
                &server_key,
                &server_iv,
                &mut self.write_seq,
            );
            if let Err(e) = encryptor.encrypt_app_data(&mut plaintext_buf, &mut ciphertext_buf) {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Encryption failed: {}", e),
                )));
            }
        }

        // Write encrypted data
        match Pin::new(&mut self.inner).poll_write(cx, &ciphertext_buf) {
            Poll::Ready(Ok(n)) => {
                if n > 0 {
                    Poll::Ready(Ok(buf.len()))
                } else {
                    Poll::Ready(Ok(0))
                }
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// REALITY server for accepting and validating connections
///
/// This server validates incoming connections against the REALITY protocol.
/// Valid connections are returned for further processing, while invalid
/// connections are transparently proxied to the fallback destination.
#[derive(Clone)]
pub struct RealityServer {
    config: Arc<RealityServerConfig>,
}

impl RealityServer {
    /// Create a new REALITY server
    pub fn new(config: RealityServerConfig) -> Self {
        Self {
            config: Arc::new(config),
        }
    }

    /// Get the server configuration
    #[must_use]
    pub fn config(&self) -> &RealityServerConfig {
        &self.config
    }

    /// Extract hostname from the destination config (strips port)
    ///
    /// For example, "www.google.com:443" returns "www.google.com"
    fn dest_hostname(&self) -> String {
        // Strip port from dest (e.g., "www.google.com:443" -> "www.google.com")
        self.config.dest
            .rsplit_once(':')
            .map(|(host, _port)| host.to_string())
            .unwrap_or_else(|| self.config.dest.clone())
    }

    /// Accept and validate a REALITY connection
    ///
    /// This method reads the ClientHello, validates the REALITY authentication,
    /// and either returns an authenticated connection or proxies to fallback.
    ///
    /// # Arguments
    /// * `stream` - Incoming TCP stream
    ///
    /// # Returns
    /// * `Authenticated` - Valid REALITY client, proceed with VLESS
    /// * `Fallback` - Invalid auth, connection was proxied to fallback
    ///
    /// # Errors
    /// Returns error on I/O failure or if fallback connection fails
    pub async fn accept<S>(&self, mut stream: S) -> RealityResult<RealityAcceptResult<S>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        // Read ClientHello
        let (client_hello, record_data) = self.read_client_hello(&mut stream).await?;

        trace!(
            client_hello_len = client_hello.len(),
            "Received ClientHello"
        );

        // Parse ClientHello
        let parsed = match self.parse_client_hello(&client_hello) {
            Ok(p) => p,
            Err(e) => {
                debug!(error = %e, "Failed to parse ClientHello - proxying to fallback");
                self.proxy_to_fallback(stream, &record_data).await?;
                return Ok(RealityAcceptResult::Fallback);
            }
        };

        // Validate SNI
        if !self.validate_sni(&parsed.sni) {
            debug!(sni = %parsed.sni, "Invalid SNI - proxying to fallback");
            self.proxy_to_fallback(stream, &record_data).await?;
            return Ok(RealityAcceptResult::Fallback);
        }

        // Validate REALITY authentication
        let normalized_short_ids = self.config.normalized_short_ids();
        let client_hello_aad = self.build_client_hello_aad(&client_hello, &parsed.encrypted_session_id);

        match validate_auth(
            &parsed.client_random,
            &parsed.encrypted_session_id,
            &self.config.private_key,
            &parsed.client_public_key,
            &normalized_short_ids,
            self.config.max_time_diff_ms,
            &client_hello_aad,
        ) {
            Ok(session_id) => {
                debug!(short_id = ?session_id.short_id, "REALITY authentication successful");

                Ok(RealityAcceptResult::Authenticated {
                    stream,
                    short_id: session_id.short_id.to_vec(),
                    buffered: Vec::new(),
                })
            }
            Err(e) => {
                debug!(error = %e, "REALITY authentication failed - proxying to fallback");
                self.proxy_to_fallback(stream, &record_data).await?;
                Ok(RealityAcceptResult::Fallback)
            }
        }
    }

    /// Accept a REALITY connection with complete TLS 1.3 handshake
    ///
    /// This method:
    /// 1. Reads and validates the ClientHello
    /// 2. Validates REALITY authentication
    /// 3. Completes the TLS 1.3 handshake (ServerHello, EncryptedExtensions, Finished)
    /// 4. Returns an encrypted stream ready for application data
    ///
    /// # Arguments
    /// * `stream` - Incoming TCP stream
    ///
    /// # Returns
    /// * `Authenticated` - Valid REALITY client with encrypted stream
    /// * `Fallback` - Invalid auth, connection was proxied to fallback
    ///
    /// # Errors
    /// Returns error on I/O failure, handshake failure, or if fallback fails
    pub async fn accept_with_handshake<S>(
        &self,
        mut stream: S,
    ) -> RealityResult<RealityHandshakeResult<S>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        // Read ClientHello
        let (client_hello, record_data) = self.read_client_hello(&mut stream).await?;

        trace!(
            client_hello_len = client_hello.len(),
            "Received ClientHello for handshake"
        );

        // Parse ClientHello
        let parsed = match self.parse_client_hello(&client_hello) {
            Ok(p) => p,
            Err(e) => {
                debug!(error = %e, "Failed to parse ClientHello - proxying to fallback");
                self.proxy_to_fallback(stream, &record_data).await?;
                return Ok(RealityHandshakeResult::Fallback);
            }
        };

        // Validate SNI
        if !self.validate_sni(&parsed.sni) {
            debug!(sni = %parsed.sni, "Invalid SNI - proxying to fallback");
            self.proxy_to_fallback(stream, &record_data).await?;
            return Ok(RealityHandshakeResult::Fallback);
        }

        // Validate REALITY authentication
        let normalized_short_ids = self.config.normalized_short_ids();
        let client_hello_aad =
            self.build_client_hello_aad(&client_hello, &parsed.encrypted_session_id);

        let session_id = match validate_auth(
            &parsed.client_random,
            &parsed.encrypted_session_id,
            &self.config.private_key,
            &parsed.client_public_key,
            &normalized_short_ids,
            self.config.max_time_diff_ms,
            &client_hello_aad,
        ) {
            Ok(sid) => sid,
            Err(e) => {
                debug!(error = %e, "REALITY authentication failed - proxying to fallback");
                self.proxy_to_fallback(stream, &record_data).await?;
                return Ok(RealityHandshakeResult::Fallback);
            }
        };

        debug!(
            short_id = ?session_id.short_id,
            "REALITY authentication successful, completing TLS handshake"
        );

        // === Complete TLS 1.3 Handshake ===

        // 1. Generate server ephemeral key pair
        let server_keypair = generate_keypair();
        let server_ephemeral_public = server_keypair.public_key_bytes();

        // 2. Compute ECDH shared secret for TLS key derivation
        let tls_shared_secret =
            perform_ecdh(&server_keypair.private_key_bytes(), &parsed.client_public_key)?;

        // 3. Use default cipher suite (AES_128_GCM_SHA256)
        let cipher_suite = DEFAULT_SERVER_CIPHER_SUITE;
        let hash_len = cipher_suite.hash_len();

        // 3.5. Derive auth_key for HMAC certificate (same derivation as client)
        let shared_secret_for_auth =
            perform_ecdh(&self.config.private_key, &parsed.client_public_key)?;
        let auth_key = derive_auth_key(
            &shared_secret_for_auth,
            &parsed.client_random[0..20],
            REALITY_AUTH_INFO,
        )?;

        // 3.6. Generate HMAC certificate for REALITY authentication
        let dest_hostname = self.dest_hostname();
        let hmac_cert = generate_hmac_certificate(&auth_key, &dest_hostname)?;

        trace!(
            cert_len = hmac_cert.der.len(),
            hostname = %dest_hostname,
            "Generated HMAC certificate"
        );

        // 4. Build ServerHello
        let server_random: [u8; 32] = crate::reality::crypto::x25519::random_bytes();
        let session_id_echo = parsed.encrypted_session_id.to_vec(); // Echo back client's session ID

        let server_hello =
            construct_server_hello(&server_random, &session_id_echo, cipher_suite.id(), &server_ephemeral_public)?;

        // 5. Compute transcript hash (ClientHello || ServerHello)
        let server_hello_hash = match cipher_suite.hash_algorithm() {
            HashAlgorithm::Sha256 => {
                let mut hasher = Sha256::new();
                hasher.update(&client_hello);
                hasher.update(&server_hello);
                hasher.finalize().to_vec()
            }
            HashAlgorithm::Sha384 => {
                let mut hasher = Sha384::new();
                hasher.update(&client_hello);
                hasher.update(&server_hello);
                hasher.finalize().to_vec()
            }
        };

        // 6. Derive handshake keys
        let hs_keys = derive_handshake_keys(cipher_suite, &tls_shared_secret, &[], &server_hello_hash)?;

        // 7. Derive server handshake traffic keys
        let (server_hs_key_bytes, server_hs_iv) =
            derive_traffic_keys(&hs_keys.server_handshake_traffic_secret, cipher_suite)?;
        let server_hs_key = AeadKey::new(cipher_suite, &server_hs_key_bytes)?;

        // 8. Derive client handshake traffic keys (for receiving client Finished)
        let (client_hs_key_bytes, client_hs_iv) =
            derive_traffic_keys(&hs_keys.client_handshake_traffic_secret, cipher_suite)?;
        let client_hs_key = AeadKey::new(cipher_suite, &client_hs_key_bytes)?;

        // 9. Build encrypted handshake messages: EncryptedExtensions + Certificate + CertificateVerify + Finished
        let encrypted_extensions = construct_encrypted_extensions()?;
        let certificate = construct_certificate(&hmac_cert.der)?;

        // Build transcript up to Certificate for CertificateVerify signature
        let mut transcript_for_cert_verify = client_hello.clone();
        transcript_for_cert_verify.extend_from_slice(&server_hello);
        transcript_for_cert_verify.extend_from_slice(&encrypted_extensions);
        transcript_for_cert_verify.extend_from_slice(&certificate);

        let cert_verify_hash = match cipher_suite.hash_algorithm() {
            HashAlgorithm::Sha256 => {
                let mut hasher = Sha256::new();
                hasher.update(&transcript_for_cert_verify);
                hasher.finalize().to_vec()
            }
            HashAlgorithm::Sha384 => {
                let mut hasher = Sha384::new();
                hasher.update(&transcript_for_cert_verify);
                hasher.finalize().to_vec()
            }
        };

        let certificate_verify = construct_certificate_verify(&hmac_cert.signing_key, &cert_verify_hash)?;

        // Build transcript including CertificateVerify for Finished verify_data
        let mut transcript_for_finished = transcript_for_cert_verify;
        transcript_for_finished.extend_from_slice(&certificate_verify);

        let handshake_hash_for_finished = match cipher_suite.hash_algorithm() {
            HashAlgorithm::Sha256 => {
                let mut hasher = Sha256::new();
                hasher.update(&transcript_for_finished);
                hasher.finalize().to_vec()
            }
            HashAlgorithm::Sha384 => {
                let mut hasher = Sha384::new();
                hasher.update(&transcript_for_finished);
                hasher.finalize().to_vec()
            }
        };

        let server_verify_data = compute_finished_verify_data(
            cipher_suite,
            &hs_keys.server_handshake_traffic_secret,
            &handshake_hash_for_finished,
        )?;
        let server_finished = construct_finished(&server_verify_data)?;

        // 10. Send ServerHello (unencrypted, as TLS record)
        let mut server_hello_record =
            write_record_header(CONTENT_TYPE_HANDSHAKE, server_hello.len() as u16);
        server_hello_record.extend_from_slice(&server_hello);
        stream.write_all(&server_hello_record).await.map_err(|e| {
            RealityError::Io(std::io::Error::new(
                e.kind(),
                format!("Failed to send ServerHello: {}", e),
            ))
        })?;

        trace!("Sent ServerHello");

        // 11. Send ChangeCipherSpec (for compatibility with middleboxes)
        let ccs_record = [0x14, 0x03, 0x03, 0x00, 0x01, 0x01]; // ChangeCipherSpec
        stream.write_all(&ccs_record).await.map_err(|e| {
            RealityError::Io(std::io::Error::new(
                e.kind(),
                format!("Failed to send ChangeCipherSpec: {}", e),
            ))
        })?;

        trace!("Sent ChangeCipherSpec");

        // 12. Encrypt and send EncryptedExtensions + Certificate + CertificateVerify + Finished
        let mut server_hs_seq = 0u64;
        let mut encrypted_output = Vec::new();

        {
            let mut encryptor =
                RecordEncryptor::new(&server_hs_key, &server_hs_iv, &mut server_hs_seq);
            encryptor.encrypt_handshake(&encrypted_extensions, &mut encrypted_output)?;
            encryptor.encrypt_handshake(&certificate, &mut encrypted_output)?;
            encryptor.encrypt_handshake(&certificate_verify, &mut encrypted_output)?;
            encryptor.encrypt_handshake(&server_finished, &mut encrypted_output)?;
        }

        stream.write_all(&encrypted_output).await.map_err(|e| {
            RealityError::Io(std::io::Error::new(
                e.kind(),
                format!("Failed to send encrypted handshake: {}", e),
            ))
        })?;

        trace!(
            encrypted_len = encrypted_output.len(),
            "Sent encrypted EncryptedExtensions + Certificate + CertificateVerify + Finished"
        );

        // 13. Receive client's encrypted Finished
        // First, skip any ChangeCipherSpec from client
        let mut client_hs_seq = 0u64;

        loop {
            let mut header = [0u8; TLS_RECORD_HEADER_SIZE];
            stream.read_exact(&mut header).await.map_err(|e| {
                RealityError::Io(std::io::Error::new(
                    e.kind(),
                    format!("Failed to read client response header: {}", e),
                ))
            })?;

            let record_type = header[0];
            let record_len = u16::from_be_bytes([header[3], header[4]]) as usize;

            let mut record_payload = vec![0u8; record_len];
            stream.read_exact(&mut record_payload).await.map_err(|e| {
                RealityError::Io(std::io::Error::new(
                    e.kind(),
                    format!("Failed to read client response: {}", e),
                ))
            })?;

            // Skip ChangeCipherSpec
            if record_type == CONTENT_TYPE_CHANGE_CIPHER_SPEC {
                trace!("Skipping client ChangeCipherSpec");
                continue;
            }

            // Expect encrypted handshake (ApplicationData type in TLS 1.3)
            if record_type != CONTENT_TYPE_APPLICATION_DATA {
                return Err(RealityError::protocol(format!(
                    "Expected ApplicationData (client Finished), got 0x{:02x}",
                    record_type
                )));
            }

            // Decrypt client Finished
            let plaintext = decrypt_handshake_message(
                cipher_suite,
                &client_hs_key_bytes,
                &client_hs_iv,
                client_hs_seq,
                &record_payload,
                record_len as u16,
            )?;

            client_hs_seq += 1;

            // Verify it's a Finished message
            if plaintext.is_empty() || plaintext[0] != HANDSHAKE_TYPE_FINISHED {
                return Err(RealityError::protocol(format!(
                    "Expected Finished message, got type 0x{:02x}",
                    plaintext.get(0).copied().unwrap_or(0)
                )));
            }

            // Extract verify_data from Finished message
            if plaintext.len() < 4 {
                return Err(RealityError::protocol("Finished message too short"));
            }

            let finished_len = u32::from_be_bytes([0, plaintext[1], plaintext[2], plaintext[3]]) as usize;
            if plaintext.len() < 4 + finished_len {
                return Err(RealityError::protocol("Finished message truncated"));
            }

            let client_verify_data = &plaintext[4..4 + finished_len];

            // Compute expected client verify_data
            // Transcript includes everything up to server Finished (including Cert and CertVerify)
            let mut transcript_for_client_finished = client_hello.clone();
            transcript_for_client_finished.extend_from_slice(&server_hello);
            transcript_for_client_finished.extend_from_slice(&encrypted_extensions);
            transcript_for_client_finished.extend_from_slice(&certificate);
            transcript_for_client_finished.extend_from_slice(&certificate_verify);
            transcript_for_client_finished.extend_from_slice(&server_finished);

            let hash_for_client_finished = match cipher_suite.hash_algorithm() {
                HashAlgorithm::Sha256 => {
                    let mut hasher = Sha256::new();
                    hasher.update(&transcript_for_client_finished);
                    hasher.finalize().to_vec()
                }
                HashAlgorithm::Sha384 => {
                    let mut hasher = Sha384::new();
                    hasher.update(&transcript_for_client_finished);
                    hasher.finalize().to_vec()
                }
            };

            let expected_client_verify_data = compute_finished_verify_data(
                cipher_suite,
                &hs_keys.client_handshake_traffic_secret,
                &hash_for_client_finished,
            )?;

            if client_verify_data != expected_client_verify_data.as_slice() {
                return Err(RealityError::handshake(
                    "Client Finished verify_data mismatch",
                ));
            }

            trace!("Client Finished verified successfully");
            break;
        }

        // 14. Derive application traffic secrets
        // Full transcript hash up to server Finished (including Cert and CertVerify)
        // Note: client Finished is NOT included per RFC 8446 Section 4.4.4
        let mut full_transcript = client_hello.clone();
        full_transcript.extend_from_slice(&server_hello);
        full_transcript.extend_from_slice(&encrypted_extensions);
        full_transcript.extend_from_slice(&certificate);
        full_transcript.extend_from_slice(&certificate_verify);
        full_transcript.extend_from_slice(&server_finished);

        let handshake_hash = match cipher_suite.hash_algorithm() {
            HashAlgorithm::Sha256 => {
                let mut hasher = Sha256::new();
                hasher.update(&full_transcript);
                hasher.finalize().to_vec()
            }
            HashAlgorithm::Sha384 => {
                let mut hasher = Sha384::new();
                hasher.update(&full_transcript);
                hasher.finalize().to_vec()
            }
        };

        let (client_app_secret, server_app_secret) =
            derive_application_secrets(cipher_suite, &hs_keys.master_secret, &handshake_hash)?;

        let (client_app_key_bytes, client_app_iv) =
            derive_traffic_keys(&client_app_secret, cipher_suite)?;
        let (server_app_key_bytes, server_app_iv) =
            derive_traffic_keys(&server_app_secret, cipher_suite)?;

        debug!("TLS 1.3 handshake complete, derived application keys");

        // 15. Create encrypted stream
        let reality_stream = RealityServerStream::new(
            stream,
            cipher_suite,
            server_app_key_bytes,
            server_app_iv,
            client_app_key_bytes,
            client_app_iv,
        );

        Ok(RealityHandshakeResult::Authenticated {
            stream: reality_stream,
            short_id: session_id.short_id.to_vec(),
        })
    }

    /// Read and validate the ClientHello from the stream
    async fn read_client_hello<S>(&self, stream: &mut S) -> RealityResult<(Vec<u8>, Vec<u8>)>
    where
        S: AsyncRead + Unpin,
    {
        // Read TLS record header (5 bytes)
        let mut header = [0u8; TLS_RECORD_HEADER_SIZE];
        stream.read_exact(&mut header).await.map_err(|e| {
            RealityError::Io(std::io::Error::new(
                e.kind(),
                format!("Failed to read TLS record header: {}", e),
            ))
        })?;

        // Validate content type
        if header[0] != CONTENT_TYPE_HANDSHAKE {
            return Err(RealityError::protocol(format!(
                "Expected Handshake record (0x16), got 0x{:02x}",
                header[0]
            )));
        }

        // Extract record length
        let record_len = u16::from_be_bytes([header[3], header[4]]) as usize;

        if record_len > MAX_CLIENT_HELLO_SIZE {
            return Err(RealityError::protocol(format!(
                "ClientHello too large: {} bytes (max {})",
                record_len, MAX_CLIENT_HELLO_SIZE
            )));
        }

        // Read record payload
        let mut payload = vec![0u8; record_len];
        stream.read_exact(&mut payload).await.map_err(|e| {
            RealityError::Io(std::io::Error::new(
                e.kind(),
                format!("Failed to read ClientHello: {}", e),
            ))
        })?;

        // Combine for fallback proxying
        let mut record_data = header.to_vec();
        record_data.extend_from_slice(&payload);

        Ok((payload, record_data))
    }

    /// Parse relevant fields from ClientHello
    fn parse_client_hello(&self, client_hello: &[u8]) -> RealityResult<ParsedClientHello> {
        // Extract client random
        let client_random = extract_client_random(client_hello)?;

        // Extract session ID
        let session_id_bytes = extract_session_id(client_hello)?;
        if session_id_bytes.len() != REALITY_SESSION_ID_SIZE {
            return Err(RealityError::protocol(format!(
                "Invalid session ID length: {} (expected {})",
                session_id_bytes.len(),
                REALITY_SESSION_ID_SIZE
            )));
        }
        let mut encrypted_session_id = [0u8; REALITY_SESSION_ID_SIZE];
        encrypted_session_id.copy_from_slice(&session_id_bytes);

        // Extract client public key
        let client_public_key = extract_client_public_key(client_hello)?;

        // Extract SNI
        let sni = extract_client_sni(client_hello)?;

        Ok(ParsedClientHello {
            client_random,
            encrypted_session_id,
            client_public_key,
            sni,
        })
    }

    /// Validate SNI against allowed server names
    fn validate_sni(&self, sni: &str) -> bool {
        if self.config.server_names.is_empty() {
            // If no server names configured, accept any SNI
            return true;
        }

        self.config.server_names.iter().any(|allowed| {
            allowed.eq_ignore_ascii_case(sni)
        })
    }

    /// Build ClientHello AAD with zeroed session ID
    fn build_client_hello_aad(
        &self,
        client_hello: &[u8],
        _encrypted_session_id: &[u8; REALITY_SESSION_ID_SIZE],
    ) -> Vec<u8> {
        let mut aad = client_hello.to_vec();

        // Find and zero the session ID in the AAD
        // Session ID starts at offset 39 (after type, length, version, random, session_id_len)
        if aad.len() >= 71 {
            aad[39..71].fill(0);
        }

        aad
    }

    /// Proxy the connection to the fallback destination
    async fn proxy_to_fallback<S>(
        &self,
        mut client_stream: S,
        initial_data: &[u8],
    ) -> RealityResult<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        debug!(dest = %self.config.dest, "Proxying to fallback");

        // Connect to fallback destination
        let mut fallback_stream = TcpStream::connect(&self.config.dest)
            .await
            .map_err(|e| {
                RealityError::Io(std::io::Error::new(
                    e.kind(),
                    format!("Failed to connect to fallback {}: {}", self.config.dest, e),
                ))
            })?;

        // Forward the initial ClientHello
        fallback_stream.write_all(initial_data).await.map_err(|e| {
            RealityError::Io(std::io::Error::new(
                e.kind(),
                format!("Failed to forward ClientHello to fallback: {}", e),
            ))
        })?;

        // Bidirectionally proxy all traffic
        let result = tokio::io::copy_bidirectional(&mut client_stream, &mut fallback_stream).await;

        match result {
            Ok((client_to_fallback, fallback_to_client)) => {
                trace!(
                    client_to_fallback,
                    fallback_to_client,
                    "Fallback proxy completed"
                );
            }
            Err(e) => {
                // Connection closed is normal for proxied connections
                if e.kind() != std::io::ErrorKind::ConnectionReset
                    && e.kind() != std::io::ErrorKind::BrokenPipe
                {
                    warn!(error = %e, "Fallback proxy error");
                }
            }
        }

        Ok(())
    }
}

/// Parsed ClientHello fields for REALITY validation
struct ParsedClientHello {
    /// Client random (32 bytes)
    client_random: [u8; 32],
    /// Encrypted session ID (32 bytes)
    encrypted_session_id: [u8; REALITY_SESSION_ID_SIZE],
    /// Client's X25519 public key (32 bytes)
    client_public_key: [u8; 32],
    /// SNI server name
    sni: String,
}

/// Extract SNI from ClientHello
///
/// Parses the server_name extension (type 0) to extract the SNI hostname.
///
/// # Arguments
/// * `client_hello` - ClientHello handshake message (without record header)
///
/// # Returns
/// SNI hostname string
pub fn extract_client_sni(client_hello: &[u8]) -> RealityResult<String> {
    // Find extensions
    // Type (1) + Length (3) + Version (2) + Random (32) + SessionID length (1)
    if client_hello.len() < 39 {
        return Err(RealityError::protocol("ClientHello too short"));
    }

    let session_id_len = client_hello[38] as usize;
    let mut offset = 39 + session_id_len;

    // Cipher suites length (2)
    if client_hello.len() < offset + 2 {
        return Err(RealityError::protocol("ClientHello truncated at cipher suites"));
    }
    let cipher_suites_len = u16::from_be_bytes([client_hello[offset], client_hello[offset + 1]]) as usize;
    offset += 2 + cipher_suites_len;

    // Compression methods length (1)
    if client_hello.len() < offset + 1 {
        return Err(RealityError::protocol("ClientHello truncated at compression"));
    }
    let compression_len = client_hello[offset] as usize;
    offset += 1 + compression_len;

    // Extensions length (2)
    if client_hello.len() < offset + 2 {
        return Err(RealityError::protocol("ClientHello truncated at extensions length"));
    }
    let extensions_len = u16::from_be_bytes([client_hello[offset], client_hello[offset + 1]]) as usize;
    offset += 2;

    if client_hello.len() < offset + extensions_len {
        return Err(RealityError::protocol("Extensions truncated"));
    }

    let extensions = &client_hello[offset..offset + extensions_len];

    // Parse extensions to find server_name (type 0)
    let mut ext_offset = 0;
    while ext_offset + 4 <= extensions.len() {
        let ext_type = u16::from_be_bytes([extensions[ext_offset], extensions[ext_offset + 1]]);
        let ext_len = u16::from_be_bytes([extensions[ext_offset + 2], extensions[ext_offset + 3]]) as usize;

        if ext_offset + 4 + ext_len > extensions.len() {
            break;
        }

        if ext_type == 0x0000 {
            // server_name extension
            let ext_data = &extensions[ext_offset + 4..ext_offset + 4 + ext_len];

            // Parse server name list
            if ext_data.len() >= 2 {
                let _list_len = u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
                let entries = &ext_data[2..];

                // Parse first entry (host_name type = 0)
                if entries.len() >= 3 {
                    let name_type = entries[0];
                    let name_len = u16::from_be_bytes([entries[1], entries[2]]) as usize;

                    if name_type == 0 && entries.len() >= 3 + name_len {
                        let name_bytes = &entries[3..3 + name_len];
                        return String::from_utf8(name_bytes.to_vec())
                            .map_err(|_| RealityError::protocol("Invalid SNI encoding"));
                    }
                }
            }
        }

        ext_offset += 4 + ext_len;
    }

    Err(RealityError::protocol("SNI extension not found in ClientHello"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reality::auth::{derive_auth_key, encrypt_session_id, SessionId};
    use crate::reality::common::REALITY_AUTH_INFO;
    use crate::reality::crypto::{generate_keypair, perform_ecdh, random_bytes, X25519KeyPair};
    use crate::reality::tls::{construct_client_hello, DEFAULT_ALPN_PROTOCOLS};

    fn create_test_config() -> RealityServerConfig {
        let mut private_key = [0u8; 32];
        private_key[0] = 0x42;

        RealityServerConfig {
            private_key,
            short_ids: vec![vec![0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0]],
            dest: "www.google.com:443".to_string(),
            server_names: vec!["www.google.com".to_string()],
            max_time_diff_ms: 120_000,
        }
    }

    #[test]
    fn test_config_new() {
        let config = RealityServerConfig::new([0x42u8; 32], "example.com:443");
        assert_eq!(config.dest, "example.com:443");
        assert!(config.short_ids.is_empty());
    }

    #[test]
    fn test_config_builder() {
        let config = RealityServerConfig::new([0x42u8; 32], "example.com:443")
            .with_short_id(vec![0x12, 0x34])
            .with_server_name("example.com")
            .with_max_time_diff_ms(60_000);

        assert_eq!(config.short_ids.len(), 1);
        assert_eq!(config.server_names.len(), 1);
        assert_eq!(config.max_time_diff_ms, 60_000);
    }

    #[test]
    fn test_config_with_short_id_hex() {
        let config = RealityServerConfig::new([0x42u8; 32], "example.com:443")
            .with_short_id_hex("1234567890abcdef")
            .unwrap();

        assert_eq!(config.short_ids.len(), 1);
        assert_eq!(
            config.short_ids[0],
            vec![0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF]
        );
    }

    #[test]
    fn test_config_validate_success() {
        let config = create_test_config();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_validate_no_short_ids() {
        let config = RealityServerConfig {
            short_ids: vec![],
            ..create_test_config()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_validate_empty_dest() {
        let config = RealityServerConfig {
            dest: String::new(),
            ..create_test_config()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_validate_no_server_names() {
        let config = RealityServerConfig {
            server_names: vec![],
            ..create_test_config()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_public_key() {
        let config = create_test_config();
        let public_key = config.public_key();
        assert_eq!(public_key.len(), 32);
        // Public key should not be all zeros
        assert!(public_key.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_server_new() {
        let config = create_test_config();
        let server = RealityServer::new(config.clone());
        assert_eq!(server.config().dest, config.dest);
    }

    #[test]
    fn test_sni_validation() {
        let config = create_test_config();
        let server = RealityServer::new(config);

        // Exact match
        assert!(server.validate_sni("www.google.com"));

        // Case insensitive
        assert!(server.validate_sni("WWW.GOOGLE.COM"));
        assert!(server.validate_sni("www.Google.Com"));

        // No match
        assert!(!server.validate_sni("example.com"));
        assert!(!server.validate_sni("google.com"));
    }

    #[test]
    fn test_sni_validation_empty_allowed() {
        let config = RealityServerConfig {
            server_names: vec![],
            ..create_test_config()
        };
        // Skip validation since we explicitly test this to see behavior
        let server = RealityServer::new(config);

        // With no server names configured, any SNI is accepted
        assert!(server.validate_sni("anything.example.com"));
    }

    #[test]
    fn test_extract_client_sni() {
        let client_random = [0x42u8; 32];
        let session_id = [0x99u8; 32];
        let public_key = [0xAAu8; 32];
        let cipher_suites = &[0x1301, 0x1302, 0x1303];

        let client_hello = construct_client_hello(
            &client_random,
            &session_id,
            &public_key,
            "www.example.com",
            cipher_suites,
            DEFAULT_ALPN_PROTOCOLS,
        )
        .unwrap();

        let sni = extract_client_sni(&client_hello).unwrap();
        assert_eq!(sni, "www.example.com");
    }

    #[test]
    fn test_extract_client_sni_google() {
        let client_random = [0x42u8; 32];
        let session_id = [0x99u8; 32];
        let public_key = [0xAAu8; 32];
        let cipher_suites = &[0x1301];

        let client_hello = construct_client_hello(
            &client_random,
            &session_id,
            &public_key,
            "www.google.com",
            cipher_suites,
            DEFAULT_ALPN_PROTOCOLS,
        )
        .unwrap();

        let sni = extract_client_sni(&client_hello).unwrap();
        assert_eq!(sni, "www.google.com");
    }

    #[test]
    fn test_normalized_short_ids() {
        let config = RealityServerConfig {
            short_ids: vec![
                vec![0x12, 0x34],  // Shorter than 8 bytes
                vec![0xAB; 8],     // Exactly 8 bytes
            ],
            ..create_test_config()
        };

        let normalized = config.normalized_short_ids();
        assert_eq!(normalized.len(), 2);
        assert_eq!(normalized[0], [0x12, 0x34, 0, 0, 0, 0, 0, 0]);
        assert_eq!(normalized[1], [0xAB; 8]);
    }

    #[test]
    fn test_client_hello_aad_building() {
        let server = RealityServer::new(create_test_config());

        let client_random = [0x42u8; 32];
        let session_id = [0x99u8; 32];
        let public_key = [0xAAu8; 32];

        let client_hello = construct_client_hello(
            &client_random,
            &session_id,
            &public_key,
            "www.google.com",
            &[0x1301],
            DEFAULT_ALPN_PROTOCOLS,
        )
        .unwrap();

        let aad = server.build_client_hello_aad(&client_hello, &session_id);

        // AAD should have zeroed session ID at offset 39-71
        assert_eq!(aad[39..71], [0u8; 32]);

        // Rest should match original
        assert_eq!(aad[0..39], client_hello[0..39]);
        assert_eq!(aad[71..], client_hello[71..]);
    }

    // Integration test for full validation flow
    #[test]
    fn test_full_validation_flow() {
        use x25519_dalek::{PublicKey, StaticSecret};

        // Server setup
        let server_private_key: [u8; 32] = random_bytes();
        let server_secret = StaticSecret::from(server_private_key);
        let server_public_key = PublicKey::from(&server_secret);

        let short_id = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];

        let config = RealityServerConfig {
            private_key: server_private_key,
            short_ids: vec![short_id.to_vec()],
            dest: "www.google.com:443".to_string(),
            server_names: vec!["www.google.com".to_string()],
            max_time_diff_ms: 120_000,
        };

        let server = RealityServer::new(config);

        // Client setup
        let client_keypair = generate_keypair();
        let client_random: [u8; 32] = random_bytes();

        // Derive shared secret and auth key (client side)
        let shared_secret = perform_ecdh(
            &client_keypair.private_key_bytes(),
            server_public_key.as_bytes(),
        )
        .unwrap();

        let auth_key = derive_auth_key(&shared_secret, &client_random[0..20], REALITY_AUTH_INFO).unwrap();

        // Create session ID
        let session_id = SessionId::new([1, 8, 1], short_id);
        let plaintext = session_id.to_plaintext();

        // Build ClientHello with zeroed session ID first (for AAD)
        let mut session_id_for_hello = [0u8; 32];
        let mut client_hello = construct_client_hello(
            &client_random,
            &session_id_for_hello,
            &client_keypair.public_key_bytes(),
            "www.google.com",
            &[0x1301],
            DEFAULT_ALPN_PROTOCOLS,
        )
        .unwrap();

        // Zero session ID in client_hello for AAD
        client_hello[39..71].fill(0);

        // Encrypt session ID
        let nonce = &client_random[20..32];
        let encrypted_session_id = encrypt_session_id(&plaintext, &auth_key, nonce, &client_hello).unwrap();

        // Put encrypted session ID back
        client_hello[39..71].copy_from_slice(&encrypted_session_id);

        // Server validation
        let parsed = server.parse_client_hello(&client_hello).unwrap();

        assert_eq!(parsed.sni, "www.google.com");
        assert_eq!(parsed.client_random, client_random);
        assert_eq!(parsed.client_public_key, client_keypair.public_key_bytes());
        assert_eq!(parsed.encrypted_session_id, encrypted_session_id);

        // Validate SNI
        assert!(server.validate_sni(&parsed.sni));

        // Validate REALITY auth
        let normalized_short_ids = server.config.normalized_short_ids();
        let client_hello_aad = server.build_client_hello_aad(&client_hello, &parsed.encrypted_session_id);

        let result = validate_auth(
            &parsed.client_random,
            &parsed.encrypted_session_id,
            &server.config.private_key,
            &parsed.client_public_key,
            &normalized_short_ids,
            server.config.max_time_diff_ms,
            &client_hello_aad,
        );

        assert!(result.is_ok(), "Validation failed: {:?}", result.err());

        let validated_session = result.unwrap();
        assert_eq!(validated_session.short_id, short_id);
    }

    #[test]
    fn test_validation_wrong_short_id() {
        use x25519_dalek::{PublicKey, StaticSecret};

        let server_private_key: [u8; 32] = random_bytes();
        let server_secret = StaticSecret::from(server_private_key);
        let server_public_key = PublicKey::from(&server_secret);

        // Server only allows short_id 0xFF..
        let config = RealityServerConfig {
            private_key: server_private_key,
            short_ids: vec![vec![0xFF; 8]],
            dest: "www.google.com:443".to_string(),
            server_names: vec!["www.google.com".to_string()],
            max_time_diff_ms: 120_000,
        };

        let server = RealityServer::new(config);

        // Client uses different short_id 0x12..
        let short_id = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];
        let client_keypair = generate_keypair();
        let client_random: [u8; 32] = random_bytes();

        let shared_secret = perform_ecdh(
            &client_keypair.private_key_bytes(),
            server_public_key.as_bytes(),
        )
        .unwrap();

        let auth_key = derive_auth_key(&shared_secret, &client_random[0..20], REALITY_AUTH_INFO).unwrap();

        let session_id = SessionId::new([1, 8, 1], short_id);
        let plaintext = session_id.to_plaintext();

        let mut client_hello = construct_client_hello(
            &client_random,
            &[0u8; 32],
            &client_keypair.public_key_bytes(),
            "www.google.com",
            &[0x1301],
            DEFAULT_ALPN_PROTOCOLS,
        )
        .unwrap();

        client_hello[39..71].fill(0);

        let nonce = &client_random[20..32];
        let encrypted_session_id = encrypt_session_id(&plaintext, &auth_key, nonce, &client_hello).unwrap();
        client_hello[39..71].copy_from_slice(&encrypted_session_id);

        let parsed = server.parse_client_hello(&client_hello).unwrap();
        let normalized_short_ids = server.config.normalized_short_ids();
        let client_hello_aad = server.build_client_hello_aad(&client_hello, &parsed.encrypted_session_id);

        let result = validate_auth(
            &parsed.client_random,
            &parsed.encrypted_session_id,
            &server.config.private_key,
            &parsed.client_public_key,
            &normalized_short_ids,
            server.config.max_time_diff_ms,
            &client_hello_aad,
        );

        // Should fail because short_id doesn't match
        assert!(result.is_err());
    }

    #[test]
    fn test_validation_wrong_server_key() {
        use x25519_dalek::{PublicKey, StaticSecret};

        // Server with one key
        let server_private_key: [u8; 32] = random_bytes();

        // Client encrypts with different public key
        let different_private_key: [u8; 32] = random_bytes();
        let different_secret = StaticSecret::from(different_private_key);
        let different_public_key = PublicKey::from(&different_secret);

        let short_id = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];

        let config = RealityServerConfig {
            private_key: server_private_key,
            short_ids: vec![short_id.to_vec()],
            dest: "www.google.com:443".to_string(),
            server_names: vec!["www.google.com".to_string()],
            max_time_diff_ms: 120_000,
        };

        let server = RealityServer::new(config);

        let client_keypair = generate_keypair();
        let client_random: [u8; 32] = random_bytes();

        // Client uses WRONG public key for key exchange
        let shared_secret = perform_ecdh(
            &client_keypair.private_key_bytes(),
            different_public_key.as_bytes(),  // Wrong key!
        )
        .unwrap();

        let auth_key = derive_auth_key(&shared_secret, &client_random[0..20], REALITY_AUTH_INFO).unwrap();

        let session_id = SessionId::new([1, 8, 1], short_id);
        let plaintext = session_id.to_plaintext();

        let mut client_hello = construct_client_hello(
            &client_random,
            &[0u8; 32],
            &client_keypair.public_key_bytes(),
            "www.google.com",
            &[0x1301],
            DEFAULT_ALPN_PROTOCOLS,
        )
        .unwrap();

        client_hello[39..71].fill(0);

        let nonce = &client_random[20..32];
        let encrypted_session_id = encrypt_session_id(&plaintext, &auth_key, nonce, &client_hello).unwrap();
        client_hello[39..71].copy_from_slice(&encrypted_session_id);

        let parsed = server.parse_client_hello(&client_hello).unwrap();
        let normalized_short_ids = server.config.normalized_short_ids();
        let client_hello_aad = server.build_client_hello_aad(&client_hello, &parsed.encrypted_session_id);

        let result = validate_auth(
            &parsed.client_random,
            &parsed.encrypted_session_id,
            &server.config.private_key,
            &parsed.client_public_key,
            &normalized_short_ids,
            server.config.max_time_diff_ms,
            &client_hello_aad,
        );

        // Should fail because decryption will fail (wrong shared secret)
        assert!(result.is_err());
    }

    /// End-to-end integration test: Client ↔ Server complete handshake
    ///
    /// This test verifies the full REALITY TLS 1.3 handshake between
    /// a RealityClientConnection and RealityServer, followed by
    /// bidirectional encrypted data transfer.
    #[tokio::test]
    async fn test_end_to_end_handshake_and_data_transfer() {
        use crate::reality::client::{RealityClientConfig, RealityClientConnection};
        use crate::reality::common::TLS_RECORD_HEADER_SIZE;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // === Setup: Generate matching client/server configurations ===
        let server_private_key: [u8; 32] = random_bytes();
        let short_id = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];
        let server_name = "www.google.com";

        // Server config
        let server_config = RealityServerConfig {
            private_key: server_private_key,
            short_ids: vec![short_id.to_vec()],
            dest: "www.google.com:443".to_string(),
            server_names: vec![server_name.to_string()],
            max_time_diff_ms: 120_000,
        };
        let server = RealityServer::new(server_config.clone());

        // Client config - needs server's public key
        let server_public_key = server_config.public_key();
        let client_config = RealityClientConfig::new(
            server_public_key,
            short_id,
            server_name.to_string(),
        );

        // === Create duplex stream for testing ===
        let (client_stream, server_stream) = tokio::io::duplex(65536);

        // === Run handshake concurrently ===
        let server_handle = tokio::spawn({
            let server = server.clone();
            async move {
                match server.accept_with_handshake(server_stream).await {
                    Ok(RealityHandshakeResult::Authenticated { stream, short_id }) => {
                        Ok((stream, short_id))
                    }
                    Ok(RealityHandshakeResult::Fallback) => {
                        Err("Unexpected fallback".to_string())
                    }
                    Err(e) => Err(format!("Server handshake failed: {}", e)),
                }
            }
        });

        let client_handle = tokio::spawn(async move {
            let mut conn = RealityClientConnection::new(client_config);

            // Generate and send ClientHello
            let client_hello = conn.start().map_err(|e| format!("start failed: {}", e))?;

            let mut stream = client_stream;
            stream
                .write_all(&client_hello)
                .await
                .map_err(|e| format!("write client_hello failed: {}", e))?;

            // Read and process server messages until handshake complete
            let mut buf = vec![0u8; 16384];
            while conn.is_handshaking() {
                let n = stream
                    .read(&mut buf)
                    .await
                    .map_err(|e| format!("read failed: {}", e))?;
                if n == 0 {
                    return Err("Connection closed during handshake".to_string());
                }

                let result = conn.feed(&buf[..n]).map_err(|e| format!("feed failed: {}", e))?;

                // Send client Finished if needed
                if !result.to_send.is_empty() {
                    stream
                        .write_all(&result.to_send)
                        .await
                        .map_err(|e| format!("write finished failed: {}", e))?;
                }
            }

            assert!(conn.is_established(), "Client should be established");
            Ok((conn, stream))
        });

        // Wait for both sides to complete
        let (server_result, client_result) = tokio::join!(server_handle, client_handle);

        let (mut server_stream, matched_short_id) = server_result
            .expect("server task panicked")
            .expect("server handshake failed");
        let (mut client_conn, mut client_transport) = client_result
            .expect("client task panicked")
            .expect("client handshake failed");

        assert_eq!(matched_short_id, short_id.to_vec(), "Short ID should match");

        // === Test bidirectional data transfer ===

        // Client -> Server
        let client_message = b"Hello from client!";
        let encrypted = client_conn.encrypt(client_message).expect("encrypt failed");
        client_transport.write_all(&encrypted).await.expect("write failed");

        let mut received = vec![0u8; 1024];
        let n = server_stream.read(&mut received).await.expect("read failed");
        assert!(n > 0, "Should receive data");
        assert_eq!(&received[..n], client_message, "Message should match");

        // Server -> Client
        let server_message = b"Hello from server!";
        server_stream.write_all(server_message).await.expect("server write failed");

        // Read the encrypted response on client side
        let mut response_buf = vec![0u8; 16384];
        let n = client_transport.read(&mut response_buf).await.expect("client read failed");
        assert!(n > 0, "Client should receive data");

        let result = client_conn.feed(&response_buf[..n]).expect("client feed failed");
        assert_eq!(result.app_data, server_message, "Server message should match");

        println!("✓ End-to-end REALITY handshake and data transfer successful!");
    }

    /// Test that invalid client authentication falls back correctly
    #[tokio::test]
    async fn test_invalid_auth_triggers_fallback() {
        use crate::reality::client::{RealityClientConfig, RealityClientConnection};
        use tokio::io::AsyncWriteExt;

        // Server with specific short_id
        let server_private_key: [u8; 32] = random_bytes();
        let server_config = RealityServerConfig {
            private_key: server_private_key,
            short_ids: vec![vec![0xFF; 8]], // Only accepts 0xFF short_id
            dest: "127.0.0.1:1".to_string(), // Will fail to connect (that's OK for this test)
            server_names: vec!["www.google.com".to_string()],
            max_time_diff_ms: 120_000,
        };
        let server = RealityServer::new(server_config.clone());

        // Client uses WRONG short_id (0xAB instead of 0xFF)
        let server_public_key = server_config.public_key();
        let wrong_short_id = [0xAB; 8];
        let client_config = RealityClientConfig::new(
            server_public_key,
            wrong_short_id,
            "www.google.com".to_string(),
        );

        let (mut client_stream, server_stream) = tokio::io::duplex(65536);

        // Client sends ClientHello with wrong short_id
        let mut client_conn = RealityClientConnection::new(client_config);
        let client_hello = client_conn.start().expect("start failed");
        client_stream.write_all(&client_hello).await.expect("write failed");
        drop(client_stream); // Close to trigger server processing

        // Server should attempt fallback (which will fail since dest is unreachable)
        // But the important thing is it doesn't authenticate
        let result = server.accept_with_handshake(server_stream).await;

        // Result should be Fallback or error (depending on if fallback connects)
        match result {
            Ok(RealityHandshakeResult::Authenticated { .. }) => {
                panic!("Should NOT authenticate with wrong short_id!");
            }
            Ok(RealityHandshakeResult::Fallback) => {
                println!("✓ Correctly rejected invalid auth and went to fallback");
            }
            Err(_) => {
                // Fallback connection failed (expected since dest is unreachable)
                println!("✓ Correctly rejected invalid auth (fallback connection failed)");
            }
        }
    }
}
