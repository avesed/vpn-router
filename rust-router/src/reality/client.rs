//! REALITY Client Connection
//!
//! Implements a sans-I/O REALITY client connection that handles the TLS 1.3
//! handshake with REALITY authentication.
//!
//! The connection follows the rustls API pattern with separate read/write
//! phases and explicit state management.

use sha2::{Digest, Sha256, Sha384};

use crate::reality::auth::{derive_auth_key, encrypt_session_id, SessionId};
use crate::reality::common::{
    CONTENT_TYPE_ALERT, CONTENT_TYPE_APPLICATION_DATA, CONTENT_TYPE_CHANGE_CIPHER_SPEC,
    CONTENT_TYPE_HANDSHAKE, HANDSHAKE_TYPE_CERTIFICATE, HANDSHAKE_TYPE_CERTIFICATE_VERIFY,
    HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS, HANDSHAKE_TYPE_FINISHED, REALITY_AUTH_INFO,
    TLS_RECORD_HEADER_SIZE, ALERT_DESC_CLOSE_NOTIFY, ALERT_LEVEL_WARNING,
};
use crate::reality::crypto::{
    compute_finished_verify_data, decrypt_handshake_message, derive_application_secrets,
    derive_handshake_keys, derive_traffic_keys, generate_keypair, perform_ecdh, AeadKey,
    CipherSuite, DEFAULT_CIPHER_SUITES,
};
use crate::reality::error::{RealityError, RealityResult};
use crate::reality::tls::{
    construct_client_hello, construct_finished, extract_server_cipher_suite,
    extract_server_public_key, write_record_header, RecordDecryptor, RecordEncryptor,
    DEFAULT_ALPN_PROTOCOLS,
};

/// Configuration for REALITY client connections
#[derive(Clone)]
pub struct RealityClientConfig {
    /// Server's X25519 public key (32 bytes)
    pub server_public_key: [u8; 32],
    /// Short ID for authentication (8 bytes)
    pub short_id: [u8; 8],
    /// Server name for SNI
    pub server_name: String,
    /// Supported TLS 1.3 cipher suites (empty = use defaults)
    pub cipher_suites: Vec<CipherSuite>,
}

impl RealityClientConfig {
    /// Create a new configuration
    pub fn new(server_public_key: [u8; 32], short_id: [u8; 8], server_name: String) -> Self {
        Self {
            server_public_key,
            short_id,
            server_name,
            cipher_suites: Vec::new(),
        }
    }
}

/// Result of feeding data to the connection
#[derive(Debug)]
pub struct FeedResult {
    /// Data to send to the peer
    pub to_send: Vec<u8>,
    /// Decrypted application data received
    pub app_data: Vec<u8>,
}

impl FeedResult {
    fn new() -> Self {
        Self {
            to_send: Vec::new(),
            app_data: Vec::new(),
        }
    }
}

/// Connection state machine
enum ConnectionState {
    /// Initial state - need to generate ClientHello
    Initial,
    /// ClientHello sent, waiting for ServerHello
    AwaitingServerHello {
        client_hello_bytes: Vec<u8>,
        client_private_key: [u8; 32],
        auth_key: [u8; 32],
    },
    /// Processing encrypted handshake messages
    ProcessingHandshake {
        cipher_suite: CipherSuite,
        client_handshake_traffic_secret: Vec<u8>,
        server_handshake_traffic_secret: Vec<u8>,
        master_secret: Vec<u8>,
        transcript_bytes: Vec<u8>,
        handshake_seq: u64,
        accumulated_plaintext: Vec<u8>,
        messages_found: u8,
    },
    /// Handshake complete, ready for application data
    Established {
        cipher_suite: CipherSuite,
        client_app_key: AeadKey,
        client_app_iv: Vec<u8>,
        server_app_key: AeadKey,
        server_app_iv: Vec<u8>,
        write_seq: u64,
        read_seq: u64,
    },
    /// Connection closed
    Closed,
}

/// REALITY client connection (sans-I/O pattern)
///
/// This implements a state machine for the REALITY/TLS 1.3 handshake.
/// Feed network data via `feed()` and get data to send in the result.
pub struct RealityClientConnection {
    config: RealityClientConfig,
    state: ConnectionState,
    input_buffer: Vec<u8>,
    received_close_notify: bool,
}

impl RealityClientConnection {
    /// Create a new REALITY client connection
    pub fn new(config: RealityClientConfig) -> Self {
        Self {
            config,
            state: ConnectionState::Initial,
            input_buffer: Vec::new(),
            received_close_notify: false,
        }
    }

    /// Check if the handshake is complete
    pub fn is_established(&self) -> bool {
        matches!(self.state, ConnectionState::Established { .. })
    }

    /// Check if handshake is still in progress
    pub fn is_handshaking(&self) -> bool {
        !matches!(
            self.state,
            ConnectionState::Established { .. } | ConnectionState::Closed
        )
    }

    /// Check if connection is closed
    pub fn is_closed(&self) -> bool {
        matches!(self.state, ConnectionState::Closed)
    }

    /// Generate initial ClientHello
    ///
    /// Call this before feeding any data to get the initial ClientHello to send.
    pub fn start(&mut self) -> RealityResult<Vec<u8>> {
        if !matches!(self.state, ConnectionState::Initial) {
            return Err(RealityError::protocol("Connection already started"));
        }

        // Generate ephemeral key pair
        let client_keypair = generate_keypair();
        let client_private_key = client_keypair.private_key_bytes();
        let client_public_key = client_keypair.public_key_bytes();

        // Generate client random
        let client_random: [u8; 32] = crate::reality::crypto::x25519::random_bytes();

        // Derive auth key for REALITY authentication
        let shared_secret = perform_ecdh(&client_private_key, &self.config.server_public_key)?;
        let auth_key = derive_auth_key(&shared_secret, &client_random[0..20], REALITY_AUTH_INFO)?;

        // Create session ID with REALITY metadata
        let session_id = SessionId::new([1, 8, 0], self.config.short_id);
        let session_id_plaintext = session_id.to_plaintext();

        // Build ClientHello with zeroed session ID first (for AAD)
        let cipher_suites = if self.config.cipher_suites.is_empty() {
            DEFAULT_CIPHER_SUITES.to_vec()
        } else {
            self.config.cipher_suites.clone()
        };
        let cipher_suite_ids: Vec<u16> = cipher_suites.iter().map(|cs| cs.id()).collect();

        let mut session_id_for_hello = [0u8; 32];
        let mut client_hello = construct_client_hello(
            &client_random,
            &session_id_for_hello,
            &client_public_key,
            &self.config.server_name,
            &cipher_suite_ids,
            DEFAULT_ALPN_PROTOCOLS,
        )?;

        // Zero out session ID in ClientHello for AAD
        client_hello[39..71].fill(0);

        // Encrypt session ID
        let nonce = &client_random[20..32];
        let encrypted_session_id =
            encrypt_session_id(&session_id_plaintext, &auth_key, nonce, &client_hello)?;

        // Put encrypted session ID back into ClientHello
        client_hello[39..71].copy_from_slice(&encrypted_session_id);

        // Build TLS record
        let mut record = write_record_header(CONTENT_TYPE_HANDSHAKE, client_hello.len() as u16);
        record.extend_from_slice(&client_hello);

        // Update state
        self.state = ConnectionState::AwaitingServerHello {
            client_hello_bytes: client_hello,
            client_private_key,
            auth_key,
        };

        Ok(record)
    }

    /// Feed received data and process the handshake/application data
    ///
    /// Returns data to send and any decrypted application data.
    pub fn feed(&mut self, input: &[u8]) -> RealityResult<FeedResult> {
        self.input_buffer.extend_from_slice(input);

        let mut result = FeedResult::new();

        loop {
            let progress = match &self.state {
                ConnectionState::Initial => {
                    return Err(RealityError::protocol(
                        "Must call start() before feeding data",
                    ));
                }
                ConnectionState::AwaitingServerHello { .. } => {
                    self.process_server_hello(&mut result)?
                }
                ConnectionState::ProcessingHandshake { .. } => {
                    self.process_encrypted_handshake(&mut result)?
                }
                ConnectionState::Established { .. } => self.process_application_data(&mut result)?,
                ConnectionState::Closed => break,
            };

            if !progress {
                break;
            }
        }

        Ok(result)
    }

    /// Encrypt application data for sending
    pub fn encrypt(&mut self, plaintext: &[u8]) -> RealityResult<Vec<u8>> {
        let ConnectionState::Established {
            cipher_suite,
            client_app_key,
            client_app_iv,
            write_seq,
            ..
        } = &mut self.state
        else {
            return Err(RealityError::protocol(
                "Cannot encrypt: handshake not complete",
            ));
        };

        let mut output = Vec::new();
        let mut plaintext_buf = plaintext.to_vec();

        let mut encryptor = RecordEncryptor::new(client_app_key, client_app_iv, write_seq);
        encryptor.encrypt_app_data(&mut plaintext_buf, &mut output)?;

        Ok(output)
    }

    /// Generate close_notify alert
    pub fn close_notify(&mut self) -> RealityResult<Vec<u8>> {
        let ConnectionState::Established {
            client_app_key,
            client_app_iv,
            write_seq,
            ..
        } = &mut self.state
        else {
            return Err(RealityError::protocol(
                "Cannot send close_notify: not established",
            ));
        };

        let mut output = Vec::new();
        let mut encryptor = RecordEncryptor::new(client_app_key, client_app_iv, write_seq);
        encryptor.encrypt_close_notify(&mut output)?;

        Ok(output)
    }

    /// Process ServerHello
    fn process_server_hello(&mut self, result: &mut FeedResult) -> RealityResult<bool> {
        if self.input_buffer.len() < TLS_RECORD_HEADER_SIZE {
            return Ok(false);
        }

        let record_len = u16::from_be_bytes([self.input_buffer[3], self.input_buffer[4]]) as usize;
        let total_len = TLS_RECORD_HEADER_SIZE + record_len;

        if self.input_buffer.len() < total_len {
            return Ok(false);
        }

        // Extract state
        let ConnectionState::AwaitingServerHello {
            client_hello_bytes,
            client_private_key,
            auth_key,
        } = std::mem::replace(&mut self.state, ConnectionState::Closed)
        else {
            unreachable!()
        };

        let record: Vec<u8> = self.input_buffer.drain(..total_len).collect();
        let server_hello = &record[TLS_RECORD_HEADER_SIZE..];

        // Extract server's public key and cipher suite
        let server_public_key = extract_server_public_key(&record)?;
        let cipher_suite_id = extract_server_cipher_suite(&record)?;
        let cipher_suite = CipherSuite::from_id(cipher_suite_id).ok_or_else(|| {
            RealityError::protocol(format!("Unsupported cipher suite: 0x{:04x}", cipher_suite_id))
        })?;

        // Compute ECDH shared secret for TLS
        let tls_shared_secret = perform_ecdh(&client_private_key, &server_public_key)?;

        // Compute transcript hash
        let server_hello_hash = match cipher_suite.hash_algorithm() {
            crate::reality::crypto::HashAlgorithm::Sha256 => {
                let mut hasher = Sha256::new();
                hasher.update(&client_hello_bytes);
                hasher.update(server_hello);
                hasher.finalize().to_vec()
            }
            crate::reality::crypto::HashAlgorithm::Sha384 => {
                let mut hasher = Sha384::new();
                hasher.update(&client_hello_bytes);
                hasher.update(server_hello);
                hasher.finalize().to_vec()
            }
        };

        // Derive handshake keys
        let hs_keys =
            derive_handshake_keys(cipher_suite, &tls_shared_secret, &[], &server_hello_hash)?;

        // Build transcript for later
        let mut transcript_bytes = client_hello_bytes;
        transcript_bytes.extend_from_slice(server_hello);

        self.state = ConnectionState::ProcessingHandshake {
            cipher_suite,
            client_handshake_traffic_secret: hs_keys.client_handshake_traffic_secret,
            server_handshake_traffic_secret: hs_keys.server_handshake_traffic_secret,
            master_secret: hs_keys.master_secret,
            transcript_bytes,
            handshake_seq: 0,
            accumulated_plaintext: Vec::new(),
            messages_found: 0,
        };

        Ok(true)
    }

    /// Process encrypted handshake messages
    fn process_encrypted_handshake(&mut self, result: &mut FeedResult) -> RealityResult<bool> {
        if self.input_buffer.len() < TLS_RECORD_HEADER_SIZE {
            return Ok(false);
        }

        let record_type = self.input_buffer[0];
        let record_len = u16::from_be_bytes([self.input_buffer[3], self.input_buffer[4]]) as usize;
        let total_len = TLS_RECORD_HEADER_SIZE + record_len;

        if self.input_buffer.len() < total_len {
            return Ok(false);
        }

        // Skip ChangeCipherSpec (dummy in TLS 1.3)
        if record_type == CONTENT_TYPE_CHANGE_CIPHER_SPEC {
            self.input_buffer.drain(..total_len);
            return Ok(true);
        }

        if record_type != CONTENT_TYPE_APPLICATION_DATA {
            return Err(RealityError::protocol(format!(
                "Expected ApplicationData, got 0x{:02x}",
                record_type
            )));
        }

        // Extract state temporarily
        let ConnectionState::ProcessingHandshake {
            cipher_suite,
            client_handshake_traffic_secret,
            server_handshake_traffic_secret,
            master_secret,
            mut transcript_bytes,
            mut handshake_seq,
            mut accumulated_plaintext,
            mut messages_found,
        } = std::mem::replace(&mut self.state, ConnectionState::Closed)
        else {
            unreachable!()
        };

        // Derive server handshake key
        let (server_hs_key, server_hs_iv) =
            derive_traffic_keys(&server_handshake_traffic_secret, cipher_suite)?;

        // Extract and decrypt record
        let ciphertext: Vec<u8> = self.input_buffer.drain(..total_len).skip(TLS_RECORD_HEADER_SIZE).collect();

        let plaintext = decrypt_handshake_message(
            cipher_suite,
            &server_hs_key,
            &server_hs_iv,
            handshake_seq,
            &ciphertext,
            record_len as u16,
        )?;

        handshake_seq += 1;

        // Accumulate plaintext
        let prev_len = accumulated_plaintext.len();
        accumulated_plaintext.extend_from_slice(&plaintext);

        // Parse handshake messages
        let mut offset = prev_len;
        while offset + 4 <= accumulated_plaintext.len() && messages_found < 4 {
            let msg_type = accumulated_plaintext[offset];
            let msg_len = u32::from_be_bytes([
                0,
                accumulated_plaintext[offset + 1],
                accumulated_plaintext[offset + 2],
                accumulated_plaintext[offset + 3],
            ]) as usize;

            if offset + 4 + msg_len > accumulated_plaintext.len() {
                break;
            }

            messages_found += 1;
            offset += 4 + msg_len;
        }

        // Check if we have all 4 messages (EE, Cert, CV, Finished)
        if messages_found < 4 {
            self.state = ConnectionState::ProcessingHandshake {
                cipher_suite,
                client_handshake_traffic_secret,
                server_handshake_traffic_secret,
                master_secret,
                transcript_bytes,
                handshake_seq,
                accumulated_plaintext,
                messages_found,
            };
            return Ok(true);
        }

        // Complete handshake - compute transcript hash including all handshake messages
        let handshake_hash = match cipher_suite.hash_algorithm() {
            crate::reality::crypto::HashAlgorithm::Sha256 => {
                let mut hasher = Sha256::new();
                hasher.update(&transcript_bytes);
                hasher.update(&accumulated_plaintext);
                hasher.finalize().to_vec()
            }
            crate::reality::crypto::HashAlgorithm::Sha384 => {
                let mut hasher = Sha384::new();
                hasher.update(&transcript_bytes);
                hasher.update(&accumulated_plaintext);
                hasher.finalize().to_vec()
            }
        };

        // Send client Finished
        let client_verify_data =
            compute_finished_verify_data(cipher_suite, &client_handshake_traffic_secret, &handshake_hash)?;
        let client_finished = construct_finished(&client_verify_data)?;

        let (client_hs_key, client_hs_iv) =
            derive_traffic_keys(&client_handshake_traffic_secret, cipher_suite)?;
        let client_hs_aead = AeadKey::new(cipher_suite, &client_hs_key)?;

        let mut client_hs_seq = 0u64;
        let mut encryptor = RecordEncryptor::new(&client_hs_aead, &client_hs_iv, &mut client_hs_seq);
        encryptor.encrypt_handshake(&client_finished, &mut result.to_send)?;

        // Derive application traffic secrets
        let (client_app_secret, server_app_secret) =
            derive_application_secrets(cipher_suite, &master_secret, &handshake_hash)?;

        let (client_app_key_bytes, client_app_iv) =
            derive_traffic_keys(&client_app_secret, cipher_suite)?;
        let (server_app_key_bytes, server_app_iv) =
            derive_traffic_keys(&server_app_secret, cipher_suite)?;

        let client_app_key = AeadKey::new(cipher_suite, &client_app_key_bytes)?;
        let server_app_key = AeadKey::new(cipher_suite, &server_app_key_bytes)?;

        self.state = ConnectionState::Established {
            cipher_suite,
            client_app_key,
            client_app_iv,
            server_app_key,
            server_app_iv,
            write_seq: 0,
            read_seq: 0,
        };

        Ok(true)
    }

    /// Process application data
    fn process_application_data(&mut self, result: &mut FeedResult) -> RealityResult<bool> {
        if self.input_buffer.len() < TLS_RECORD_HEADER_SIZE {
            return Ok(false);
        }

        let record_len = u16::from_be_bytes([self.input_buffer[3], self.input_buffer[4]]) as usize;
        let total_len = TLS_RECORD_HEADER_SIZE + record_len;

        if self.input_buffer.len() < total_len {
            return Ok(false);
        }

        let ConnectionState::Established {
            server_app_key,
            server_app_iv,
            read_seq,
            ..
        } = &mut self.state
        else {
            unreachable!()
        };

        // Extract ciphertext
        let mut ciphertext: Vec<u8> = self.input_buffer.drain(..total_len).skip(TLS_RECORD_HEADER_SIZE).collect();

        // Decrypt
        let mut decryptor = RecordDecryptor::new(server_app_key, server_app_iv, read_seq);
        let (content_type, plaintext) =
            decryptor.decrypt_record_in_place(&mut ciphertext, record_len as u16)?;

        match content_type {
            CONTENT_TYPE_APPLICATION_DATA => {
                result.app_data.extend_from_slice(plaintext);
            }
            CONTENT_TYPE_ALERT => {
                if plaintext.len() >= 2 {
                    let alert_level = plaintext[0];
                    let alert_desc = plaintext[1];

                    if alert_desc == ALERT_DESC_CLOSE_NOTIFY {
                        self.received_close_notify = true;
                        self.state = ConnectionState::Closed;
                        return Ok(false);
                    } else if alert_level != ALERT_LEVEL_WARNING {
                        return Err(RealityError::protocol(format!(
                            "Received fatal alert: {}",
                            alert_desc
                        )));
                    }
                }
            }
            _ => {
                return Err(RealityError::protocol(format!(
                    "Unexpected content type: 0x{:02x}",
                    content_type
                )));
            }
        }

        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reality::crypto::x25519::random_bytes;

    #[test]
    fn test_client_config() {
        let server_public_key: [u8; 32] = random_bytes();
        let short_id = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];

        let config =
            RealityClientConfig::new(server_public_key, short_id, "www.google.com".to_string());

        assert_eq!(config.server_public_key, server_public_key);
        assert_eq!(config.short_id, short_id);
        assert_eq!(config.server_name, "www.google.com");
        assert!(config.cipher_suites.is_empty());
    }

    #[test]
    fn test_connection_initial_state() {
        let config = RealityClientConfig::new([0u8; 32], [0u8; 8], "example.com".to_string());

        let conn = RealityClientConnection::new(config);

        assert!(!conn.is_established());
        assert!(conn.is_handshaking());
        assert!(!conn.is_closed());
    }

    #[test]
    fn test_connection_start_generates_client_hello() {
        let config = RealityClientConfig::new([0x42u8; 32], [0xABu8; 8], "example.com".to_string());

        let mut conn = RealityClientConnection::new(config);
        let client_hello_record = conn.start().unwrap();

        // Should be a TLS record with handshake content type
        assert!(client_hello_record.len() > TLS_RECORD_HEADER_SIZE);
        assert_eq!(client_hello_record[0], CONTENT_TYPE_HANDSHAKE);

        // Should now be awaiting server hello
        assert!(conn.is_handshaking());
    }

    #[test]
    fn test_connection_cannot_start_twice() {
        let config = RealityClientConfig::new([0u8; 32], [0u8; 8], "example.com".to_string());

        let mut conn = RealityClientConnection::new(config);
        conn.start().unwrap();

        // Second start should fail
        let result = conn.start();
        assert!(result.is_err());
    }

    #[test]
    fn test_feed_without_start_fails() {
        let config = RealityClientConfig::new([0u8; 32], [0u8; 8], "example.com".to_string());

        let mut conn = RealityClientConnection::new(config);
        let result = conn.feed(&[0x16, 0x03, 0x03, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05]);

        assert!(result.is_err());
    }

    #[test]
    fn test_feed_partial_record() {
        let config = RealityClientConfig::new([0u8; 32], [0u8; 8], "example.com".to_string());

        let mut conn = RealityClientConnection::new(config);
        conn.start().unwrap();

        // Feed partial data (less than header)
        let result = conn.feed(&[0x16, 0x03]).unwrap();
        assert!(result.to_send.is_empty());
        assert!(result.app_data.is_empty());
    }

    #[test]
    fn test_encrypt_before_established_fails() {
        let config = RealityClientConfig::new([0u8; 32], [0u8; 8], "example.com".to_string());

        let mut conn = RealityClientConnection::new(config);
        conn.start().unwrap();

        let result = conn.encrypt(b"test data");
        assert!(result.is_err());
    }
}
