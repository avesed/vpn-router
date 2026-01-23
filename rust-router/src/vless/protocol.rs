//! VLESS wire protocol encoding and decoding
//!
//! This module implements the VLESS protocol wire format for request and response
//! headers. VLESS is a lightweight proxy protocol designed for high performance
//! with minimal overhead.
//!
//! # Wire Protocol
//!
//! ## Request Header
//!
//! ```text
//! +--------+-------+----------+---------+----------+
//! | Version|  UUID |  Addons  | Command | Port+Addr|
//! +--------+-------+----------+---------+----------+
//! |   1B   |  16B  | Variable |   1B    | Variable |
//! +--------+-------+----------+---------+----------+
//! ```
//!
//! ## Response Header
//!
//! ```text
//! +--------+----------+
//! | Version|  Addons  |
//! +--------+----------+
//! |   1B   | Variable |
//! +--------+----------+
//! ```
//!
//! ## Address Encoding
//!
//! Port is encoded first (2 bytes, big-endian), followed by address:
//!
//! - Type 1 (IPv4): 4 bytes
//! - Type 2 (Domain): 1 byte length + string
//! - Type 3 (IPv6): 16 bytes
//!
//! # Example
//!
//! ```no_run
//! use rust_router::vless::{VlessRequestHeader, VlessAddress, VlessCommand, VlessAddons};
//! use tokio::net::TcpStream;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let mut stream = TcpStream::connect("127.0.0.1:443").await?;
//!
//! // Read request header from stream
//! let header = VlessRequestHeader::read_from(&mut stream).await?;
//! println!("Connecting to: {:?}", header.address);
//!
//! // Write response header
//! let response = rust_router::vless::VlessResponseHeader::new(VlessAddons::new());
//! response.write_to(&mut stream).await?;
//! # Ok(())
//! # }
//! ```

use std::net::{Ipv4Addr, Ipv6Addr};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::addons::{parse_addons, VlessAddons};
use super::error::VlessError;

/// VLESS protocol version (always 0)
pub const VLESS_VERSION: u8 = 0;

/// VLESS command types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum VlessCommand {
    /// TCP connection (CONNECT)
    Tcp = 0x01,
    /// UDP packet relay
    Udp = 0x02,
    /// Multiplexed connection (XUDP)
    Mux = 0x03,
}

impl VlessCommand {
    /// Create a command from a byte value
    ///
    /// # Errors
    ///
    /// Returns `VlessError::InvalidCommand` if the byte is not a valid command.
    pub fn from_byte(b: u8) -> Result<Self, VlessError> {
        match b {
            0x01 => Ok(Self::Tcp),
            0x02 => Ok(Self::Udp),
            0x03 => Ok(Self::Mux),
            _ => Err(VlessError::InvalidCommand(b)),
        }
    }

    /// Convert command to byte value
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        self as u8
    }

    /// Check if this is a TCP command
    #[must_use]
    pub const fn is_tcp(self) -> bool {
        matches!(self, Self::Tcp)
    }

    /// Check if this is a UDP command
    #[must_use]
    pub const fn is_udp(self) -> bool {
        matches!(self, Self::Udp)
    }

    /// Check if this is a MUX command
    #[must_use]
    pub const fn is_mux(self) -> bool {
        matches!(self, Self::Mux)
    }
}

impl std::fmt::Display for VlessCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tcp => write!(f, "TCP"),
            Self::Udp => write!(f, "UDP"),
            Self::Mux => write!(f, "MUX"),
        }
    }
}

/// Address type constants
pub mod address_type {
    /// IPv4 address (4 bytes)
    pub const IPV4: u8 = 0x01;
    /// Domain name (length + string)
    pub const DOMAIN: u8 = 0x02;
    /// IPv6 address (16 bytes)
    pub const IPV6: u8 = 0x03;
}

/// VLESS destination address
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VlessAddress {
    /// IPv4 address
    Ipv4(Ipv4Addr),
    /// IPv6 address
    Ipv6(Ipv6Addr),
    /// Domain name
    Domain(String),
}

impl VlessAddress {
    /// Create an IPv4 address
    #[must_use]
    pub const fn ipv4(addr: Ipv4Addr) -> Self {
        Self::Ipv4(addr)
    }

    /// Create an IPv6 address
    #[must_use]
    pub const fn ipv6(addr: Ipv6Addr) -> Self {
        Self::Ipv6(addr)
    }

    /// Create a domain address
    #[must_use]
    pub fn domain(name: impl Into<String>) -> Self {
        Self::Domain(name.into())
    }

    /// Get the address type byte
    #[must_use]
    pub const fn address_type(&self) -> u8 {
        match self {
            Self::Ipv4(_) => address_type::IPV4,
            Self::Domain(_) => address_type::DOMAIN,
            Self::Ipv6(_) => address_type::IPV6,
        }
    }

    /// Get the domain name if this is a domain address
    #[must_use]
    pub fn as_domain(&self) -> Option<&str> {
        match self {
            Self::Domain(d) => Some(d),
            _ => None,
        }
    }

    /// Get the IPv4 address if this is an IPv4 address
    #[must_use]
    pub const fn as_ipv4(&self) -> Option<Ipv4Addr> {
        match self {
            Self::Ipv4(ip) => Some(*ip),
            _ => None,
        }
    }

    /// Get the IPv6 address if this is an IPv6 address
    #[must_use]
    pub const fn as_ipv6(&self) -> Option<Ipv6Addr> {
        match self {
            Self::Ipv6(ip) => Some(*ip),
            _ => None,
        }
    }

    /// Encode the address to bytes (without the type byte)
    ///
    /// The port is NOT included in this encoding.
    fn encode_address_bytes(&self) -> Result<Vec<u8>, VlessError> {
        match self {
            Self::Ipv4(ip) => Ok(ip.octets().to_vec()),
            Self::Ipv6(ip) => Ok(ip.octets().to_vec()),
            Self::Domain(domain) => {
                if domain.is_empty() {
                    return Err(VlessError::EmptyDomain);
                }
                if domain.len() > 255 {
                    return Err(VlessError::DomainTooLong(domain.len()));
                }
                let mut bytes = Vec::with_capacity(1 + domain.len());
                #[allow(clippy::cast_possible_truncation)]
                bytes.push(domain.len() as u8);
                bytes.extend_from_slice(domain.as_bytes());
                Ok(bytes)
            }
        }
    }

    /// Get the encoded length of the address (type byte + address bytes)
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        match self {
            Self::Ipv4(_) => 1 + 4,  // type + 4 bytes
            Self::Ipv6(_) => 1 + 16, // type + 16 bytes
            Self::Domain(d) => 1 + 1 + d.len(), // type + length + string
        }
    }
}

impl std::fmt::Display for VlessAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ipv4(ip) => write!(f, "{ip}"),
            Self::Ipv6(ip) => write!(f, "[{ip}]"),
            Self::Domain(d) => write!(f, "{d}"),
        }
    }
}

/// VLESS request header
///
/// This is sent by the client to initiate a connection.
#[derive(Debug, Clone)]
pub struct VlessRequestHeader {
    /// Protocol version (always 0)
    pub version: u8,

    /// UUID for authentication (16 bytes)
    pub uuid: [u8; 16],

    /// Addons (flow control, etc.)
    pub addons: VlessAddons,

    /// Command type (TCP, UDP, MUX)
    pub command: VlessCommand,

    /// Destination port
    pub port: u16,

    /// Destination address
    pub address: VlessAddress,
}

impl VlessRequestHeader {
    /// Create a new request header
    #[must_use]
    pub fn new(
        uuid: [u8; 16],
        command: VlessCommand,
        address: VlessAddress,
        port: u16,
    ) -> Self {
        Self {
            version: VLESS_VERSION,
            uuid,
            addons: VlessAddons::new(),
            command,
            port,
            address,
        }
    }

    /// Create a request header with addons
    #[must_use]
    pub fn with_addons(
        uuid: [u8; 16],
        addons: VlessAddons,
        command: VlessCommand,
        address: VlessAddress,
        port: u16,
    ) -> Self {
        Self {
            version: VLESS_VERSION,
            uuid,
            addons,
            command,
            port,
            address,
        }
    }

    /// Read a request header from an async reader
    ///
    /// # Errors
    ///
    /// Returns `VlessError` if the header is malformed or I/O fails.
    pub async fn read_from<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Self, VlessError> {
        // Read version (1 byte)
        let version = reader.read_u8().await?;
        if version != VLESS_VERSION {
            return Err(VlessError::InvalidVersion(version));
        }

        // Read UUID (16 bytes)
        let mut uuid = [0u8; 16];
        reader.read_exact(&mut uuid).await?;

        // Read addons (variable length)
        // First read the length byte, then read the payload
        let addons_len = reader.read_u8().await? as usize;
        let addons = if addons_len == 0 {
            VlessAddons::new()
        } else {
            let mut addons_buf = vec![0u8; 1 + addons_len];
            addons_buf[0] = addons_len as u8;
            reader.read_exact(&mut addons_buf[1..]).await?;
            let (addons, _) = parse_addons(&addons_buf)?;
            addons
        };

        // Read command (1 byte)
        let command_byte = reader.read_u8().await?;
        let command = VlessCommand::from_byte(command_byte)?;

        // Read port (2 bytes, big-endian)
        let port = reader.read_u16().await?;

        // Read address type (1 byte)
        let atyp = reader.read_u8().await?;
        let address = match atyp {
            address_type::IPV4 => {
                let mut octets = [0u8; 4];
                reader.read_exact(&mut octets).await?;
                VlessAddress::Ipv4(Ipv4Addr::from(octets))
            }
            address_type::DOMAIN => {
                let len = reader.read_u8().await? as usize;
                if len == 0 {
                    return Err(VlessError::EmptyDomain);
                }
                let mut buf = vec![0u8; len];
                reader.read_exact(&mut buf).await?;
                let domain = String::from_utf8(buf)
                    .map_err(|e| VlessError::InvalidDomainEncoding(e.to_string()))?;
                VlessAddress::Domain(domain)
            }
            address_type::IPV6 => {
                let mut octets = [0u8; 16];
                reader.read_exact(&mut octets).await?;
                VlessAddress::Ipv6(Ipv6Addr::from(octets))
            }
            _ => return Err(VlessError::InvalidAddressType(atyp)),
        };

        Ok(Self {
            version,
            uuid,
            addons,
            command,
            port,
            address,
        })
    }

    /// Write a request header to an async writer
    ///
    /// # Errors
    ///
    /// Returns `VlessError` if encoding fails or I/O fails.
    pub async fn write_to<W: AsyncWrite + Unpin>(&self, writer: &mut W) -> Result<(), VlessError> {
        let encoded = self.encode()?;
        writer.write_all(&encoded).await?;
        Ok(())
    }

    /// Encode the request header to bytes
    ///
    /// # Errors
    ///
    /// Returns `VlessError` if encoding fails (e.g., domain too long).
    pub fn encode(&self) -> Result<Vec<u8>, VlessError> {
        let addons_encoded = self.addons.encode()?;
        let address_bytes = self.address.encode_address_bytes()?;

        // Calculate total size
        let size = 1  // version
            + 16  // uuid
            + addons_encoded.len()  // addons
            + 1  // command
            + 2  // port
            + 1  // address type
            + address_bytes.len();  // address

        let mut buf = Vec::with_capacity(size);

        // Version
        buf.push(self.version);

        // UUID
        buf.extend_from_slice(&self.uuid);

        // Addons
        buf.extend_from_slice(&addons_encoded);

        // Command
        buf.push(self.command.as_byte());

        // Port (big-endian)
        buf.extend_from_slice(&self.port.to_be_bytes());

        // Address type
        buf.push(self.address.address_type());

        // Address bytes
        buf.extend_from_slice(&address_bytes);

        Ok(buf)
    }

    /// Get the encoded length of the header
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        1  // version
        + 16  // uuid
        + self.addons.encoded_len()  // addons
        + 1  // command
        + 2  // port
        + self.address.encoded_len()  // address type + address
    }
}

/// VLESS response header
///
/// This is sent by the server after processing the request.
#[derive(Debug, Clone)]
pub struct VlessResponseHeader {
    /// Protocol version (always 0)
    pub version: u8,

    /// Addons (currently unused in responses)
    pub addons: VlessAddons,
}

impl VlessResponseHeader {
    /// Create a new response header
    #[must_use]
    pub fn new(addons: VlessAddons) -> Self {
        Self {
            version: VLESS_VERSION,
            addons,
        }
    }

    /// Create a minimal response header (no addons)
    #[must_use]
    pub fn minimal() -> Self {
        Self {
            version: VLESS_VERSION,
            addons: VlessAddons::new(),
        }
    }

    /// Read a response header from an async reader
    ///
    /// # Errors
    ///
    /// Returns `VlessError` if the header is malformed or I/O fails.
    pub async fn read_from<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Self, VlessError> {
        // Read version (1 byte)
        let version = reader.read_u8().await?;
        if version != VLESS_VERSION {
            return Err(VlessError::InvalidVersion(version));
        }

        // Read addons
        let addons_len = reader.read_u8().await? as usize;
        let addons = if addons_len == 0 {
            VlessAddons::new()
        } else {
            let mut addons_buf = vec![0u8; 1 + addons_len];
            addons_buf[0] = addons_len as u8;
            reader.read_exact(&mut addons_buf[1..]).await?;
            let (addons, _) = parse_addons(&addons_buf)?;
            addons
        };

        Ok(Self { version, addons })
    }

    /// Write a response header to an async writer
    ///
    /// # Errors
    ///
    /// Returns `VlessError` if I/O fails.
    pub async fn write_to<W: AsyncWrite + Unpin>(&self, writer: &mut W) -> Result<(), VlessError> {
        let encoded = self.encode()?;
        writer.write_all(&encoded).await?;
        Ok(())
    }

    /// Encode the response header to bytes
    ///
    /// # Errors
    ///
    /// Returns `VlessError` if encoding fails.
    pub fn encode(&self) -> Result<Vec<u8>, VlessError> {
        let addons_encoded = self.addons.encode()?;
        let mut buf = Vec::with_capacity(1 + addons_encoded.len());
        buf.push(self.version);
        buf.extend_from_slice(&addons_encoded);
        Ok(buf)
    }

    /// Get the encoded length of the header
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        1 + self.addons.encoded_len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_command_from_byte() {
        assert_eq!(VlessCommand::from_byte(0x01).unwrap(), VlessCommand::Tcp);
        assert_eq!(VlessCommand::from_byte(0x02).unwrap(), VlessCommand::Udp);
        assert_eq!(VlessCommand::from_byte(0x03).unwrap(), VlessCommand::Mux);
        assert!(VlessCommand::from_byte(0x00).is_err());
        assert!(VlessCommand::from_byte(0x04).is_err());
    }

    #[test]
    fn test_command_as_byte() {
        assert_eq!(VlessCommand::Tcp.as_byte(), 0x01);
        assert_eq!(VlessCommand::Udp.as_byte(), 0x02);
        assert_eq!(VlessCommand::Mux.as_byte(), 0x03);
    }

    #[test]
    fn test_command_checks() {
        assert!(VlessCommand::Tcp.is_tcp());
        assert!(!VlessCommand::Tcp.is_udp());
        assert!(!VlessCommand::Tcp.is_mux());

        assert!(!VlessCommand::Udp.is_tcp());
        assert!(VlessCommand::Udp.is_udp());
        assert!(!VlessCommand::Udp.is_mux());

        assert!(!VlessCommand::Mux.is_tcp());
        assert!(!VlessCommand::Mux.is_udp());
        assert!(VlessCommand::Mux.is_mux());
    }

    #[test]
    fn test_command_display() {
        assert_eq!(VlessCommand::Tcp.to_string(), "TCP");
        assert_eq!(VlessCommand::Udp.to_string(), "UDP");
        assert_eq!(VlessCommand::Mux.to_string(), "MUX");
    }

    #[test]
    fn test_address_ipv4() {
        let ip = Ipv4Addr::new(192, 168, 1, 1);
        let addr = VlessAddress::ipv4(ip);
        assert_eq!(addr.address_type(), address_type::IPV4);
        assert_eq!(addr.as_ipv4(), Some(ip));
        assert!(addr.as_ipv6().is_none());
        assert!(addr.as_domain().is_none());
        assert_eq!(addr.to_string(), "192.168.1.1");
        assert_eq!(addr.encoded_len(), 5);
    }

    #[test]
    fn test_address_ipv6() {
        let ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let addr = VlessAddress::ipv6(ip);
        assert_eq!(addr.address_type(), address_type::IPV6);
        assert_eq!(addr.as_ipv6(), Some(ip));
        assert!(addr.as_ipv4().is_none());
        assert!(addr.as_domain().is_none());
        assert_eq!(addr.to_string(), "[2001:db8::1]");
        assert_eq!(addr.encoded_len(), 17);
    }

    #[test]
    fn test_address_domain() {
        let addr = VlessAddress::domain("example.com");
        assert_eq!(addr.address_type(), address_type::DOMAIN);
        assert_eq!(addr.as_domain(), Some("example.com"));
        assert!(addr.as_ipv4().is_none());
        assert!(addr.as_ipv6().is_none());
        assert_eq!(addr.to_string(), "example.com");
        assert_eq!(addr.encoded_len(), 1 + 1 + 11); // type + length + string
    }

    #[test]
    fn test_address_encode() {
        // IPv4
        let addr = VlessAddress::ipv4(Ipv4Addr::new(10, 0, 0, 1));
        let bytes = addr.encode_address_bytes().unwrap();
        assert_eq!(bytes, vec![10, 0, 0, 1]);

        // IPv6
        let addr = VlessAddress::ipv6(Ipv6Addr::LOCALHOST);
        let bytes = addr.encode_address_bytes().unwrap();
        let expected: Vec<u8> = Ipv6Addr::LOCALHOST.octets().to_vec();
        assert_eq!(bytes, expected);

        // Domain
        let addr = VlessAddress::domain("test.com");
        let bytes = addr.encode_address_bytes().unwrap();
        assert_eq!(bytes[0], 8); // length
        assert_eq!(&bytes[1..], b"test.com");
    }

    #[test]
    fn test_address_encode_errors() {
        // Empty domain
        let addr = VlessAddress::domain("");
        assert!(addr.encode_address_bytes().is_err());

        // Too long domain
        let long_domain = "a".repeat(256);
        let addr = VlessAddress::domain(long_domain);
        assert!(addr.encode_address_bytes().is_err());
    }

    #[test]
    fn test_request_header_new() {
        let uuid = [0u8; 16];
        let addr = VlessAddress::ipv4(Ipv4Addr::new(127, 0, 0, 1));
        let header = VlessRequestHeader::new(uuid, VlessCommand::Tcp, addr.clone(), 8080);

        assert_eq!(header.version, VLESS_VERSION);
        assert_eq!(header.uuid, uuid);
        assert_eq!(header.command, VlessCommand::Tcp);
        assert_eq!(header.port, 8080);
        assert_eq!(header.address, addr);
        assert!(header.addons.is_empty());
    }

    #[test]
    fn test_request_header_with_addons() {
        let uuid = [1u8; 16];
        let addons = VlessAddons::with_xtls_vision();
        let addr = VlessAddress::domain("example.com");
        let header = VlessRequestHeader::with_addons(
            uuid,
            addons.clone(),
            VlessCommand::Tcp,
            addr,
            443,
        );

        assert!(header.addons.is_xtls_vision());
    }

    #[tokio::test]
    async fn test_request_header_encode_decode_ipv4() {
        let uuid = [0x55u8; 16];
        let addr = VlessAddress::ipv4(Ipv4Addr::new(8, 8, 8, 8));
        let header = VlessRequestHeader::new(uuid, VlessCommand::Tcp, addr, 53);

        let encoded = header.encode().unwrap();
        let mut cursor = Cursor::new(encoded);
        let decoded = VlessRequestHeader::read_from(&mut cursor).await.unwrap();

        assert_eq!(decoded.version, VLESS_VERSION);
        assert_eq!(decoded.uuid, uuid);
        assert_eq!(decoded.command, VlessCommand::Tcp);
        assert_eq!(decoded.port, 53);
        assert_eq!(decoded.address.as_ipv4(), Some(Ipv4Addr::new(8, 8, 8, 8)));
    }

    #[tokio::test]
    async fn test_request_header_encode_decode_ipv6() {
        let uuid = [0xAAu8; 16];
        let ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let addr = VlessAddress::ipv6(ip);
        let header = VlessRequestHeader::new(uuid, VlessCommand::Udp, addr, 443);

        let encoded = header.encode().unwrap();
        let mut cursor = Cursor::new(encoded);
        let decoded = VlessRequestHeader::read_from(&mut cursor).await.unwrap();

        assert_eq!(decoded.command, VlessCommand::Udp);
        assert_eq!(decoded.address.as_ipv6(), Some(ip));
        assert_eq!(decoded.port, 443);
    }

    #[tokio::test]
    async fn test_request_header_encode_decode_domain() {
        let uuid = [0xBBu8; 16];
        let addr = VlessAddress::domain("www.google.com");
        let header = VlessRequestHeader::new(uuid, VlessCommand::Tcp, addr, 80);

        let encoded = header.encode().unwrap();
        let mut cursor = Cursor::new(encoded);
        let decoded = VlessRequestHeader::read_from(&mut cursor).await.unwrap();

        assert_eq!(decoded.address.as_domain(), Some("www.google.com"));
        assert_eq!(decoded.port, 80);
    }

    #[tokio::test]
    async fn test_request_header_with_addons_roundtrip() {
        let uuid = [0xCCu8; 16];
        let addons = VlessAddons::with_xtls_vision();
        let addr = VlessAddress::domain("secure.example.com");
        let header = VlessRequestHeader::with_addons(uuid, addons, VlessCommand::Tcp, addr, 443);

        let encoded = header.encode().unwrap();
        let mut cursor = Cursor::new(encoded);
        let decoded = VlessRequestHeader::read_from(&mut cursor).await.unwrap();

        assert!(decoded.addons.is_xtls_vision());
        assert_eq!(decoded.address.as_domain(), Some("secure.example.com"));
    }

    #[tokio::test]
    async fn test_request_header_invalid_version() {
        let data = vec![
            1, // Invalid version (should be 0)
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // UUID
            0, // No addons
            1, // TCP command
            0, 80, // Port 80
            1,    // IPv4
            127, 0, 0, 1, // Address
        ];
        let mut cursor = Cursor::new(data);
        let result = VlessRequestHeader::read_from(&mut cursor).await;
        assert!(matches!(result, Err(VlessError::InvalidVersion(1))));
    }

    #[tokio::test]
    async fn test_request_header_invalid_command() {
        let data = vec![
            0, // Version
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // UUID
            0,    // No addons
            0x05, // Invalid command
            0, 80, // Port 80
            1,    // IPv4
            127, 0, 0, 1, // Address
        ];
        let mut cursor = Cursor::new(data);
        let result = VlessRequestHeader::read_from(&mut cursor).await;
        assert!(matches!(result, Err(VlessError::InvalidCommand(0x05))));
    }

    #[tokio::test]
    async fn test_request_header_invalid_address_type() {
        let data = vec![
            0, // Version
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // UUID
            0,    // No addons
            0x01, // TCP
            0, 80, // Port 80
            0x05, // Invalid address type
        ];
        let mut cursor = Cursor::new(data);
        let result = VlessRequestHeader::read_from(&mut cursor).await;
        assert!(matches!(result, Err(VlessError::InvalidAddressType(0x05))));
    }

    #[tokio::test]
    async fn test_request_header_empty_domain() {
        let data = vec![
            0, // Version
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // UUID
            0,    // No addons
            0x01, // TCP
            0, 80, // Port 80
            0x02, // Domain
            0,    // Empty domain length
        ];
        let mut cursor = Cursor::new(data);
        let result = VlessRequestHeader::read_from(&mut cursor).await;
        assert!(matches!(result, Err(VlessError::EmptyDomain)));
    }

    #[test]
    fn test_request_header_encoded_len() {
        let uuid = [0u8; 16];
        let addr = VlessAddress::ipv4(Ipv4Addr::LOCALHOST);
        let header = VlessRequestHeader::new(uuid, VlessCommand::Tcp, addr, 80);

        assert_eq!(header.encoded_len(), header.encode().unwrap().len());

        // With addons
        let addons = VlessAddons::with_xtls_vision();
        let addr = VlessAddress::domain("test.example.com");
        let header = VlessRequestHeader::with_addons(uuid, addons, VlessCommand::Tcp, addr, 443);
        assert_eq!(header.encoded_len(), header.encode().unwrap().len());
    }

    #[test]
    fn test_response_header_new() {
        let addons = VlessAddons::new();
        let header = VlessResponseHeader::new(addons);
        assert_eq!(header.version, VLESS_VERSION);
        assert!(header.addons.is_empty());
    }

    #[test]
    fn test_response_header_minimal() {
        let header = VlessResponseHeader::minimal();
        assert_eq!(header.version, VLESS_VERSION);
        assert!(header.addons.is_empty());
    }

    #[tokio::test]
    async fn test_response_header_encode_decode() {
        let header = VlessResponseHeader::minimal();
        let encoded = header.encode().unwrap();
        let mut cursor = Cursor::new(encoded);
        let decoded = VlessResponseHeader::read_from(&mut cursor).await.unwrap();

        assert_eq!(decoded.version, VLESS_VERSION);
        assert!(decoded.addons.is_empty());
    }

    #[tokio::test]
    async fn test_response_header_with_addons() {
        let addons = VlessAddons::with_xtls_vision();
        let header = VlessResponseHeader::new(addons);
        let encoded = header.encode().unwrap();
        let mut cursor = Cursor::new(encoded);
        let decoded = VlessResponseHeader::read_from(&mut cursor).await.unwrap();

        assert!(decoded.addons.is_xtls_vision());
    }

    #[test]
    fn test_response_header_encoded_len() {
        let header = VlessResponseHeader::minimal();
        assert_eq!(header.encoded_len(), header.encode().unwrap().len());

        let addons = VlessAddons::with_xtls_vision();
        let header = VlessResponseHeader::new(addons);
        assert_eq!(header.encoded_len(), header.encode().unwrap().len());
    }

    #[tokio::test]
    async fn test_response_header_invalid_version() {
        let data = vec![1, 0]; // Version 1, no addons
        let mut cursor = Cursor::new(data);
        let result = VlessResponseHeader::read_from(&mut cursor).await;
        assert!(matches!(result, Err(VlessError::InvalidVersion(1))));
    }

    #[tokio::test]
    async fn test_write_to() {
        // Test request write_to
        let uuid = [0xDDu8; 16];
        let addr = VlessAddress::ipv4(Ipv4Addr::new(10, 0, 0, 1));
        let header = VlessRequestHeader::new(uuid, VlessCommand::Tcp, addr, 3000);

        let mut buf = Vec::new();
        header.write_to(&mut buf).await.unwrap();
        assert_eq!(buf, header.encode().unwrap());

        // Test response write_to
        let response = VlessResponseHeader::minimal();
        let mut buf = Vec::new();
        response.write_to(&mut buf).await.unwrap();
        assert_eq!(buf, response.encode().unwrap());
    }

    #[tokio::test]
    async fn test_mux_command_roundtrip() {
        let uuid = [0xEEu8; 16];
        let addr = VlessAddress::domain("mux.example.com");
        let header = VlessRequestHeader::new(uuid, VlessCommand::Mux, addr, 443);

        let encoded = header.encode().unwrap();
        let mut cursor = Cursor::new(encoded);
        let decoded = VlessRequestHeader::read_from(&mut cursor).await.unwrap();

        assert_eq!(decoded.command, VlessCommand::Mux);
        assert!(decoded.command.is_mux());
    }

    #[tokio::test]
    async fn test_full_wire_format() {
        // Manually construct a known-good wire format and verify parsing
        let mut data = Vec::new();

        // Version
        data.push(0);

        // UUID (16 bytes)
        let uuid = [
            0x55, 0x0e, 0x84, 0x00, 0xe2, 0x9b, 0x41, 0xd4, 0xa7, 0x16, 0x44, 0x66, 0x55, 0x44,
            0x00, 0x00,
        ];
        data.extend_from_slice(&uuid);

        // Addons (0 = none)
        data.push(0);

        // Command (TCP)
        data.push(0x01);

        // Port (443 = 0x01BB)
        data.push(0x01);
        data.push(0xBB);

        // Address type (Domain)
        data.push(0x02);

        // Domain length and content
        let domain = b"example.com";
        data.push(domain.len() as u8);
        data.extend_from_slice(domain);

        let mut cursor = Cursor::new(data);
        let header = VlessRequestHeader::read_from(&mut cursor).await.unwrap();

        assert_eq!(header.uuid, uuid);
        assert_eq!(header.command, VlessCommand::Tcp);
        assert_eq!(header.port, 443);
        assert_eq!(header.address.as_domain(), Some("example.com"));
    }
}
