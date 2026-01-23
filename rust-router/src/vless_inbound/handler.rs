//! VLESS connection handler
//!
//! This module provides the connection handler for processing incoming VLESS
//! connections. It handles authentication, protocol parsing, and provides
//! a unified interface for processing authenticated connections.
//!
//! # Connection Flow
//!
//! 1. Accept TCP connection
//! 2. Optionally perform TLS handshake
//! 3. Read VLESS request header
//! 4. Validate UUID against allowed users
//! 5. Send VLESS response header
//! 6. Return authenticated connection for forwarding

use std::net::SocketAddr;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::net::TcpStream;
use tracing::{debug, trace, warn};

use super::config::VlessUser;
use super::error::{VlessInboundError, VlessInboundResult};
use crate::vless::{
    VlessAccount, VlessAccountManager, VlessAddons, VlessAddress, VlessCommand, VlessError,
    VlessRequestHeader, VlessResponseHeader,
};

/// An authenticated VLESS connection
///
/// This structure represents a VLESS connection after successful authentication.
/// It contains the underlying stream and connection metadata.
#[derive(Debug)]
pub struct VlessConnection<S> {
    /// The underlying stream (TCP or TLS)
    stream: S,

    /// The authenticated user
    user: AuthenticatedUser,

    /// Destination address from the VLESS header
    destination: VlessDestination,

    /// Client address
    client_addr: SocketAddr,
}

impl<S> VlessConnection<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    /// Create a new VLESS connection
    fn new(
        stream: S,
        user: AuthenticatedUser,
        destination: VlessDestination,
        client_addr: SocketAddr,
    ) -> Self {
        Self {
            stream,
            user,
            destination,
            client_addr,
        }
    }

    /// Get the authenticated user
    #[must_use]
    pub fn user(&self) -> &AuthenticatedUser {
        &self.user
    }

    /// Get the destination address and port
    #[must_use]
    pub fn destination(&self) -> &VlessDestination {
        &self.destination
    }

    /// Get the client address
    #[must_use]
    pub fn client_addr(&self) -> SocketAddr {
        self.client_addr
    }

    /// Get the command (TCP, UDP, MUX)
    #[must_use]
    pub fn command(&self) -> VlessCommand {
        self.destination.command
    }

    /// Check if this is a TCP connection
    #[must_use]
    pub fn is_tcp(&self) -> bool {
        self.destination.command.is_tcp()
    }

    /// Check if this is a UDP connection
    #[must_use]
    pub fn is_udp(&self) -> bool {
        self.destination.command.is_udp()
    }

    /// Get the flow control type (if any)
    #[must_use]
    pub fn flow(&self) -> Option<&str> {
        self.destination.addons.flow.as_deref()
    }

    /// Check if XTLS-Vision flow is enabled
    #[must_use]
    pub fn is_xtls_vision(&self) -> bool {
        self.destination.addons.is_xtls_vision()
    }

    /// Consume the connection and return the underlying stream
    ///
    /// This is useful for forwarding data between the client and destination.
    #[must_use]
    pub fn into_stream(self) -> S {
        self.stream
    }

    /// Split the connection into read and write halves
    ///
    /// This is useful for bidirectional forwarding.
    pub fn split(self) -> (tokio::io::ReadHalf<S>, tokio::io::WriteHalf<S>) {
        tokio::io::split(self.stream)
    }

    /// Get a mutable reference to the underlying stream
    pub fn stream_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    /// Get a reference to the underlying stream
    pub fn stream(&self) -> &S {
        &self.stream
    }
}

/// Information about an authenticated user
#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    /// User's UUID bytes
    uuid: [u8; 16],

    /// User's email (if provided)
    email: Option<String>,
}

impl AuthenticatedUser {
    /// Create from a VLESS account
    fn from_account(account: &VlessAccount) -> Self {
        Self {
            uuid: account.id_bytes(),
            email: account.email().map(String::from),
        }
    }

    /// Get the UUID bytes
    #[must_use]
    pub fn uuid(&self) -> &[u8; 16] {
        &self.uuid
    }

    /// Get the email address (if set)
    #[must_use]
    pub fn email(&self) -> Option<&str> {
        self.email.as_deref()
    }

    /// Get the UUID as a hyphenated string
    #[must_use]
    pub fn uuid_string(&self) -> String {
        uuid::Uuid::from_bytes(self.uuid).hyphenated().to_string()
    }
}

/// VLESS destination information
#[derive(Debug, Clone)]
pub struct VlessDestination {
    /// Destination address
    pub address: VlessAddress,

    /// Destination port
    pub port: u16,

    /// Command type (TCP, UDP, MUX)
    pub command: VlessCommand,

    /// Addons (flow control, etc.)
    pub addons: VlessAddons,
}

impl VlessDestination {
    /// Get the destination as a string (address:port)
    #[must_use]
    pub fn to_string(&self) -> String {
        format!("{}:{}", self.address, self.port)
    }
}

impl std::fmt::Display for VlessDestination {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.address, self.port)
    }
}

/// VLESS connection handler
///
/// This handler processes incoming connections, validates VLESS headers,
/// authenticates users, and returns authenticated connections.
pub struct VlessConnectionHandler {
    /// Account manager for UUID validation
    account_manager: VlessAccountManager,

    /// User configurations (for flow validation)
    users: Vec<VlessUser>,
}

impl VlessConnectionHandler {
    /// Create a new connection handler
    ///
    /// # Arguments
    ///
    /// * `account_manager` - Account manager for UUID validation
    /// * `users` - User configurations for additional validation
    #[must_use]
    pub fn new(account_manager: VlessAccountManager, users: Vec<VlessUser>) -> Self {
        Self {
            account_manager,
            users,
        }
    }

    /// Handle an incoming connection
    ///
    /// This method reads the VLESS request header, validates the UUID,
    /// sends the response header, and returns an authenticated connection.
    ///
    /// # Arguments
    ///
    /// * `stream` - The incoming stream (TCP or TLS)
    /// * `client_addr` - The client's address
    ///
    /// # Errors
    ///
    /// Returns `VlessInboundError` if:
    /// - Reading the header fails
    /// - UUID is invalid or unknown
    /// - Flow type doesn't match user configuration
    /// - Sending the response fails
    pub async fn handle<S>(
        &self,
        mut stream: S,
        client_addr: SocketAddr,
    ) -> VlessInboundResult<VlessConnection<S>>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        // Read VLESS request header
        let header = VlessRequestHeader::read_from(&mut stream).await?;

        trace!(
            client = %client_addr,
            uuid = ?header.uuid,
            command = %header.command,
            destination = %header.address,
            port = header.port,
            "Received VLESS request"
        );

        // Validate UUID
        let account = match self.account_manager.validate_uuid(&header.uuid) {
            Some(account) => account,
            None => {
                warn!(
                    client = %client_addr,
                    "Authentication failed: unknown UUID"
                );
                return Err(VlessInboundError::AuthenticationFailed);
            }
        };

        // Validate flow type if user has a specific flow configured
        if let Some(user_config) = self.find_user_config(&header.uuid) {
            if let Some(ref expected_flow) = user_config.flow {
                let actual_flow = header.addons.flow.as_deref().unwrap_or("");
                if actual_flow != expected_flow {
                    warn!(
                        client = %client_addr,
                        expected = %expected_flow,
                        actual = %actual_flow,
                        "Flow type mismatch"
                    );
                    return Err(VlessInboundError::invalid_header(format!(
                        "flow type mismatch: expected '{}', got '{}'",
                        expected_flow, actual_flow
                    )));
                }
            }
        }

        // Send VLESS response header
        let response = VlessResponseHeader::minimal();
        response.write_to(&mut stream).await?;

        debug!(
            client = %client_addr,
            email = account.email().unwrap_or("<none>"),
            destination = %header.address,
            port = header.port,
            command = %header.command,
            "VLESS connection authenticated"
        );

        // Build authenticated connection
        let user = AuthenticatedUser::from_account(account);
        let destination = VlessDestination {
            address: header.address,
            port: header.port,
            command: header.command,
            addons: header.addons,
        };

        Ok(VlessConnection::new(stream, user, destination, client_addr))
    }

    /// Handle a connection with optional first bytes peek
    ///
    /// This method allows peeking at the first bytes to determine if the
    /// connection is a valid VLESS request. If not, the bytes can be used
    /// for fallback handling.
    ///
    /// # Arguments
    ///
    /// * `stream` - The incoming stream
    /// * `client_addr` - The client's address
    /// * `peek_size` - Number of bytes to peek (typically 17 for version + UUID)
    ///
    /// # Returns
    ///
    /// `Ok(Ok(connection))` if VLESS authentication succeeds
    /// `Ok(Err(peeked_bytes))` if the first byte is not VLESS version 0
    /// `Err(error)` if an I/O error occurs
    pub async fn handle_with_peek(
        &self,
        stream: TcpStream,
        client_addr: SocketAddr,
    ) -> VlessInboundResult<Result<VlessConnection<TcpStream>, Vec<u8>>> {
        // Peek at first byte to check VLESS version
        let mut peek_buf = [0u8; 1];

        // We can't easily peek with tokio TcpStream, so we'll read and check
        // For a more sophisticated approach, we'd need to buffer the read
        let mut buf_stream = tokio::io::BufReader::new(stream);

        // Read just the version byte
        let n = buf_stream.read(&mut peek_buf).await?;
        if n == 0 {
            return Err(VlessInboundError::ConnectionClosed);
        }

        // Check if this looks like VLESS (version 0)
        if peek_buf[0] != 0 {
            // Not VLESS - return the peeked byte for fallback
            debug!(
                client = %client_addr,
                first_byte = peek_buf[0],
                "Connection is not VLESS (version != 0), forwarding to fallback"
            );
            return Ok(Err(peek_buf.to_vec()));
        }

        // It's VLESS - continue reading the rest of the header
        // Read UUID (16 bytes)
        let mut uuid = [0u8; 16];
        buf_stream.read_exact(&mut uuid).await?;

        // Read addons length
        let addons_len = buf_stream.read_u8().await? as usize;
        let addons = if addons_len == 0 {
            VlessAddons::new()
        } else {
            let mut addons_buf = vec![0u8; 1 + addons_len];
            #[allow(clippy::cast_possible_truncation)]
            {
                addons_buf[0] = addons_len as u8;
            }
            buf_stream.read_exact(&mut addons_buf[1..]).await?;
            let (addons, _) = crate::vless::parse_addons(&addons_buf)?;
            addons
        };

        // Read command
        let command_byte = buf_stream.read_u8().await?;
        let command = VlessCommand::from_byte(command_byte)?;

        // Read port
        let port = buf_stream.read_u16().await?;

        // Read address type and address
        let atyp = buf_stream.read_u8().await?;
        let address = match atyp {
            1 => {
                // IPv4
                let mut octets = [0u8; 4];
                buf_stream.read_exact(&mut octets).await?;
                VlessAddress::Ipv4(std::net::Ipv4Addr::from(octets))
            }
            2 => {
                // Domain
                let len = buf_stream.read_u8().await? as usize;
                if len == 0 {
                    return Err(VlessError::EmptyDomain.into());
                }
                let mut domain_buf = vec![0u8; len];
                buf_stream.read_exact(&mut domain_buf).await?;
                let domain = String::from_utf8(domain_buf)
                    .map_err(|e| VlessError::InvalidDomainEncoding(e.to_string()))?;
                VlessAddress::Domain(domain)
            }
            3 => {
                // IPv6
                let mut octets = [0u8; 16];
                buf_stream.read_exact(&mut octets).await?;
                VlessAddress::Ipv6(std::net::Ipv6Addr::from(octets))
            }
            _ => return Err(VlessError::InvalidAddressType(atyp).into()),
        };

        // Now validate UUID
        let account = match self.account_manager.validate_uuid(&uuid) {
            Some(account) => account,
            None => {
                warn!(
                    client = %client_addr,
                    "Authentication failed: unknown UUID"
                );
                return Err(VlessInboundError::AuthenticationFailed);
            }
        };

        // Validate flow type
        if let Some(user_config) = self.find_user_config(&uuid) {
            if let Some(ref expected_flow) = user_config.flow {
                let actual_flow = addons.flow.as_deref().unwrap_or("");
                if actual_flow != expected_flow {
                    warn!(
                        client = %client_addr,
                        expected = %expected_flow,
                        actual = %actual_flow,
                        "Flow type mismatch"
                    );
                    return Err(VlessInboundError::invalid_header(format!(
                        "flow type mismatch: expected '{}', got '{}'",
                        expected_flow, actual_flow
                    )));
                }
            }
        }

        // Get the inner stream back from BufReader
        let mut stream = buf_stream.into_inner();

        // Send VLESS response header
        let response = VlessResponseHeader::minimal();
        response.write_to(&mut stream).await?;

        debug!(
            client = %client_addr,
            email = account.email().unwrap_or("<none>"),
            destination = %address,
            port = port,
            command = %command,
            "VLESS connection authenticated"
        );

        let user = AuthenticatedUser::from_account(account);
        let destination = VlessDestination {
            address,
            port,
            command,
            addons,
        };

        Ok(Ok(VlessConnection::new(stream, user, destination, client_addr)))
    }

    /// Find user configuration by UUID bytes
    fn find_user_config(&self, uuid_bytes: &[u8; 16]) -> Option<&VlessUser> {
        let uuid_str = uuid::Uuid::from_bytes(*uuid_bytes).hyphenated().to_string();
        self.users.iter().find(|u| u.uuid == uuid_str)
    }

    /// Get the number of registered users
    #[must_use]
    pub fn user_count(&self) -> usize {
        self.account_manager.len()
    }

    /// Check if a UUID is registered
    #[must_use]
    pub fn is_valid_uuid(&self, uuid_bytes: &[u8; 16]) -> bool {
        self.account_manager.validate_uuid(uuid_bytes).is_some()
    }
}

impl std::fmt::Debug for VlessConnectionHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VlessConnectionHandler")
            .field("user_count", &self.account_manager.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vless::VlessAccount;
    use std::io::Cursor;

    fn create_test_handler() -> VlessConnectionHandler {
        let mut manager = VlessAccountManager::new();
        let account = VlessAccount::from_uuid_str(
            "550e8400-e29b-41d4-a716-446655440000",
            Some("test@example.com".to_string()),
        )
        .unwrap();
        manager.add_account(account);

        let users = vec![VlessUser::new(
            "550e8400-e29b-41d4-a716-446655440000",
            Some("test@example.com"),
        )];

        VlessConnectionHandler::new(manager, users)
    }

    #[test]
    fn test_authenticated_user() {
        let account = VlessAccount::from_uuid_str(
            "550e8400-e29b-41d4-a716-446655440000",
            Some("test@example.com".to_string()),
        )
        .unwrap();

        let user = AuthenticatedUser::from_account(&account);
        assert_eq!(user.email(), Some("test@example.com"));
        assert_eq!(
            user.uuid_string(),
            "550e8400-e29b-41d4-a716-446655440000"
        );
    }

    #[test]
    fn test_vless_destination_display() {
        let dest = VlessDestination {
            address: VlessAddress::domain("example.com"),
            port: 443,
            command: VlessCommand::Tcp,
            addons: VlessAddons::new(),
        };

        assert_eq!(dest.to_string(), "example.com:443");
    }

    #[test]
    fn test_handler_user_count() {
        let handler = create_test_handler();
        assert_eq!(handler.user_count(), 1);
    }

    #[test]
    fn test_handler_is_valid_uuid() {
        let handler = create_test_handler();

        let valid_uuid = uuid::Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000")
            .unwrap()
            .into_bytes();
        assert!(handler.is_valid_uuid(&valid_uuid));

        let invalid_uuid = [0u8; 16];
        assert!(!handler.is_valid_uuid(&invalid_uuid));
    }

    #[tokio::test]
    async fn test_handler_handle_valid_request() {
        let handler = create_test_handler();

        // Build a valid VLESS request
        let uuid = uuid::Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000")
            .unwrap()
            .into_bytes();
        let request = VlessRequestHeader::new(
            uuid,
            VlessCommand::Tcp,
            VlessAddress::domain("example.com"),
            443,
        );
        let encoded = request.encode().unwrap();

        // Create a mock stream with the request
        let mut data = encoded;
        // Add space for response
        data.extend_from_slice(&[0u8; 100]);

        let stream = Cursor::new(data);
        let client_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();

        let result = handler.handle(stream, client_addr).await;
        assert!(result.is_ok());

        let conn = result.unwrap();
        assert_eq!(conn.destination().port, 443);
        assert!(conn.is_tcp());
        assert_eq!(conn.client_addr(), client_addr);
    }

    #[tokio::test]
    async fn test_handler_handle_invalid_uuid() {
        let handler = create_test_handler();

        // Build a request with unknown UUID
        let uuid = [0xFFu8; 16];
        let request = VlessRequestHeader::new(
            uuid,
            VlessCommand::Tcp,
            VlessAddress::domain("example.com"),
            443,
        );
        let encoded = request.encode().unwrap();

        let stream = Cursor::new(encoded);
        let client_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();

        let result = handler.handle(stream, client_addr).await;
        assert!(matches!(result, Err(VlessInboundError::AuthenticationFailed)));
    }

    #[test]
    fn test_vless_connection_methods() {
        let stream = Cursor::new(vec![]);
        let user = AuthenticatedUser {
            uuid: [0u8; 16],
            email: Some("test@example.com".to_string()),
        };
        let destination = VlessDestination {
            address: VlessAddress::domain("example.com"),
            port: 443,
            command: VlessCommand::Tcp,
            addons: VlessAddons::with_xtls_vision(),
        };
        let client_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();

        let conn = VlessConnection::new(stream, user, destination, client_addr);

        assert!(conn.is_tcp());
        assert!(!conn.is_udp());
        assert!(conn.is_xtls_vision());
        assert_eq!(conn.command(), VlessCommand::Tcp);
        assert_eq!(conn.client_addr(), client_addr);
        assert_eq!(conn.user().email(), Some("test@example.com"));
    }
}
