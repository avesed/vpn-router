//! VLESS UDP frame encoding and decoding
//!
//! This module implements the VLESS UDP-over-TCP framing protocol.
//! Each UDP datagram is encapsulated with length, address, and port information.
//!
//! # Wire Format (Xray-compatible)
//!
//! ```text
//! +--------+---------+----------+--------+----------+
//! | Length |AddrType | Address  |  Port  | Payload  |
//! |   2B   |   1B    | Variable |   2B   | Variable |
//! +--------+---------+----------+--------+----------+
//!
//! Where:
//! - Length (2B): Total length of (AddrType + Address + Port + Payload), big-endian
//! - AddrType (1B): Address type (0x01=IPv4, 0x02=Domain, 0x03=IPv6)
//! - Address: Variable length depending on type
//!   - IPv4: 4 bytes
//!   - Domain: 1 byte length + domain string
//!   - IPv6: 16 bytes
//! - Port (2B): Destination port, big-endian
//! - Payload: The actual UDP data
//! ```

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::smoltcp_utils::{BridgeError, Result};

/// Address type constants (same as VLESS protocol)
pub mod address_type {
    /// IPv4 address (4 bytes)
    pub const IPV4: u8 = 0x01;
    /// Domain name (length + string)
    pub const DOMAIN: u8 = 0x02;
    /// IPv6 address (16 bytes)
    pub const IPV6: u8 = 0x03;
}

/// Maximum UDP payload size (prevent memory exhaustion)
pub const MAX_UDP_PAYLOAD: usize = 65507;

/// Maximum domain name length
pub const MAX_DOMAIN_LEN: usize = 255;

/// Minimum frame size (`Length` + `Port` + `AddrType` + min address)
pub const MIN_FRAME_SIZE: usize = 2 + 2 + 1 + 1; // 6 bytes minimum

/// VLESS UDP frame address
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UdpFrameAddress {
    /// IPv4 address
    Ipv4(Ipv4Addr),
    /// IPv6 address
    Ipv6(Ipv6Addr),
    /// Domain name
    Domain(String),
}

impl UdpFrameAddress {
    /// Create from [`IpAddr`]
    #[must_use]
    pub fn from_ip(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(v4) => Self::Ipv4(v4),
            IpAddr::V6(v6) => Self::Ipv6(v6),
        }
    }

    /// Get address type byte
    #[must_use]
    pub const fn address_type(&self) -> u8 {
        match self {
            Self::Ipv4(_) => address_type::IPV4,
            Self::Domain(_) => address_type::DOMAIN,
            Self::Ipv6(_) => address_type::IPV6,
        }
    }

    /// Get encoded length (type byte + address bytes)
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        1 + match self {
            Self::Ipv4(_) => 4,
            Self::Ipv6(_) => 16,
            Self::Domain(d) => 1 + d.len(),
        }
    }

    /// Encode address to bytes (including type byte)
    #[allow(clippy::cast_possible_truncation)] // Domain length is bounded by MAX_DOMAIN_LEN (255)
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.address_type());
        match self {
            Self::Ipv4(ip) => buf.put_slice(&ip.octets()),
            Self::Ipv6(ip) => buf.put_slice(&ip.octets()),
            Self::Domain(d) => {
                buf.put_u8(d.len() as u8);
                buf.put_slice(d.as_bytes());
            }
        }
    }

    /// Decode address from reader
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - I/O error occurs during read
    /// - Address type is invalid
    /// - Domain name is empty, too long, or invalid UTF-8
    pub async fn decode<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Self> {
        let atyp = reader.read_u8().await?;
        match atyp {
            address_type::IPV4 => {
                let mut octets = [0u8; 4];
                reader.read_exact(&mut octets).await?;
                Ok(Self::Ipv4(Ipv4Addr::from(octets)))
            }
            address_type::DOMAIN => {
                let len = reader.read_u8().await? as usize;
                if len == 0 {
                    return Err(BridgeError::SmoltcpUdp("empty domain".into()));
                }
                if len > MAX_DOMAIN_LEN {
                    return Err(BridgeError::SmoltcpUdp(format!(
                        "domain too long: {len}"
                    )));
                }
                let mut buf = vec![0u8; len];
                reader.read_exact(&mut buf).await?;
                let domain = String::from_utf8(buf)
                    .map_err(|e| BridgeError::SmoltcpUdp(format!("invalid domain: {e}")))?;
                Ok(Self::Domain(domain))
            }
            address_type::IPV6 => {
                let mut octets = [0u8; 16];
                reader.read_exact(&mut octets).await?;
                Ok(Self::Ipv6(Ipv6Addr::from(octets)))
            }
            _ => Err(BridgeError::SmoltcpUdp(format!(
                "invalid address type: 0x{atyp:02x}"
            ))),
        }
    }

    /// Try to convert to [`IpAddr`]
    #[must_use]
    pub fn to_ip_addr(&self) -> Option<IpAddr> {
        match self {
            Self::Ipv4(ip) => Some(IpAddr::V4(*ip)),
            Self::Ipv6(ip) => Some(IpAddr::V6(*ip)),
            Self::Domain(_) => None,
        }
    }
}

impl std::fmt::Display for UdpFrameAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ipv4(ip) => write!(f, "{ip}"),
            Self::Ipv6(ip) => write!(f, "[{ip}]"),
            Self::Domain(d) => write!(f, "{d}"),
        }
    }
}

/// VLESS UDP frame
///
/// Encapsulates a single UDP datagram with destination address information.
#[derive(Debug, Clone)]
pub struct VlessUdpFrame {
    /// Destination address
    pub address: UdpFrameAddress,
    /// Destination port
    pub port: u16,
    /// UDP payload
    pub payload: Bytes,
}

impl VlessUdpFrame {
    /// Create a new UDP frame
    #[must_use]
    pub fn new(address: UdpFrameAddress, port: u16, payload: impl Into<Bytes>) -> Self {
        Self {
            address,
            port,
            payload: payload.into(),
        }
    }

    /// Create from socket address and payload
    #[must_use]
    pub fn from_socket_addr(addr: SocketAddr, payload: impl Into<Bytes>) -> Self {
        Self {
            address: UdpFrameAddress::from_ip(addr.ip()),
            port: addr.port(),
            payload: payload.into(),
        }
    }

    /// Create from IP address, port, and payload
    #[must_use]
    pub fn from_ip(ip: IpAddr, port: u16, payload: impl Into<Bytes>) -> Self {
        Self {
            address: UdpFrameAddress::from_ip(ip),
            port,
            payload: payload.into(),
        }
    }

    /// Get the total encoded length of this frame
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        2  // length field
        + 2  // port
        + self.address.encoded_len()  // address type + address
        + self.payload.len() // payload
    }

    /// Get the "inner" length (everything except the length field itself)
    fn inner_len(&self) -> usize {
        2 + self.address.encoded_len() + self.payload.len()
    }

    /// Read a UDP frame from an async reader
    ///
    /// Returns `Ok(None)` on EOF (clean shutdown).
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - I/O error occurs during read
    /// - Frame length is invalid (too short or too large)
    /// - Address decoding fails
    pub async fn read_from<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Option<Self>> {
        // Read length (2 bytes) - Xray format: length includes AddrType + Address + Port + Payload
        let length = match reader.read_u16().await {
            Ok(len) => len as usize,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e.into()),
        };

        // Validate length (at least AddressType + 1 byte + Port)
        if length < 4 {
            return Err(BridgeError::SmoltcpUdp(format!(
                "frame too short: length={length}"
            )));
        }
        if length > MAX_UDP_PAYLOAD + 2 + 1 + MAX_DOMAIN_LEN + 1 {
            return Err(BridgeError::SmoltcpUdp(format!(
                "frame too large: length={length}"
            )));
        }

        // Read address (type + address) - Xray format: address comes before port
        let address = UdpFrameAddress::decode(reader).await?;

        // Read port (2 bytes) - after address in Xray format
        let port = reader.read_u16().await?;

        // Calculate payload length: length - address.encoded_len() - 2 (port)
        let header_len = address.encoded_len() + 2;
        if length < header_len {
            return Err(BridgeError::SmoltcpUdp(format!(
                "invalid length: {length} < header {header_len}"
            )));
        }
        let payload_len = length - header_len;

        if payload_len > MAX_UDP_PAYLOAD {
            return Err(BridgeError::SmoltcpUdp(format!(
                "payload too large: {payload_len}"
            )));
        }

        // Read payload
        let mut payload = vec![0u8; payload_len];
        reader.read_exact(&mut payload).await?;

        Ok(Some(Self {
            address,
            port,
            payload: Bytes::from(payload),
        }))
    }

    /// Write the UDP frame to an async writer
    ///
    /// # Errors
    ///
    /// Returns an error if I/O error occurs during write.
    pub async fn write_to<W: AsyncWrite + Unpin>(&self, writer: &mut W) -> Result<()> {
        let encoded = self.encode();
        writer.write_all(&encoded).await?;
        Ok(())
    }

    /// Encode the frame to bytes (Xray-compatible format)
    #[must_use]
    #[allow(clippy::cast_possible_truncation)] // inner_len is bounded by MAX_UDP_PAYLOAD + header
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(self.encoded_len());

        // Length (inner length, not including the length field itself)
        buf.put_u16(self.inner_len() as u16);

        // Address (type + address) - Xray format: address before port
        self.address.encode(&mut buf);

        // Port - after address in Xray format
        buf.put_u16(self.port);

        // Payload
        buf.put_slice(&self.payload);

        buf.freeze()
    }

    /// Try to get destination as [`SocketAddr`] (only works for IP addresses)
    #[must_use]
    pub fn socket_addr(&self) -> Option<SocketAddr> {
        self.address
            .to_ip_addr()
            .map(|ip| SocketAddr::new(ip, self.port))
    }
}

/// UDP frame codec for streaming
///
/// This codec handles reading multiple frames from a stream efficiently
/// by maintaining an internal buffer and parsing frames incrementally.
pub struct VlessUdpCodec {
    /// Read buffer
    buffer: BytesMut,
}

impl VlessUdpCodec {
    /// Create a new codec
    #[must_use]
    pub fn new() -> Self {
        Self {
            buffer: BytesMut::with_capacity(65536),
        }
    }

    /// Feed data into the codec
    pub fn feed(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    /// Try to decode a frame from the buffer (Xray-compatible format)
    ///
    /// Returns `Ok(Some(frame))` if a complete frame is available,
    /// `Ok(None)` if more data is needed, or `Err` on parse error.
    ///
    /// # Errors
    ///
    /// Returns an error if the frame data is malformed.
    pub fn decode(&mut self) -> Result<Option<VlessUdpFrame>> {
        if self.buffer.len() < 2 {
            return Ok(None); // Need more data
        }

        // Peek at length without consuming
        let length = u16::from_be_bytes([self.buffer[0], self.buffer[1]]) as usize;

        // Check if we have the complete frame
        let total_len = 2 + length;
        if self.buffer.len() < total_len {
            return Ok(None); // Need more data
        }

        // Consume the length field
        self.buffer.advance(2);

        // Read address type first (Xray format: address before port)
        if self.buffer.is_empty() {
            return Err(BridgeError::SmoltcpUdp("missing address type".into()));
        }
        let atyp = self.buffer.get_u8();

        let address = match atyp {
            address_type::IPV4 => {
                if self.buffer.len() < 4 {
                    return Err(BridgeError::SmoltcpUdp("incomplete IPv4".into()));
                }
                let mut octets = [0u8; 4];
                self.buffer.copy_to_slice(&mut octets);
                UdpFrameAddress::Ipv4(Ipv4Addr::from(octets))
            }
            address_type::DOMAIN => {
                if self.buffer.is_empty() {
                    return Err(BridgeError::SmoltcpUdp("missing domain length".into()));
                }
                let len = self.buffer.get_u8() as usize;
                if self.buffer.len() < len {
                    return Err(BridgeError::SmoltcpUdp("incomplete domain".into()));
                }
                let domain_bytes = self.buffer.copy_to_bytes(len);
                let domain = String::from_utf8(domain_bytes.to_vec())
                    .map_err(|e| BridgeError::SmoltcpUdp(format!("invalid domain: {e}")))?;
                UdpFrameAddress::Domain(domain)
            }
            address_type::IPV6 => {
                if self.buffer.len() < 16 {
                    return Err(BridgeError::SmoltcpUdp("incomplete IPv6".into()));
                }
                let mut octets = [0u8; 16];
                self.buffer.copy_to_slice(&mut octets);
                UdpFrameAddress::Ipv6(Ipv6Addr::from(octets))
            }
            _ => {
                return Err(BridgeError::SmoltcpUdp(format!(
                    "invalid address type: 0x{atyp:02x}"
                )));
            }
        };

        // Read port (after address in Xray format)
        if self.buffer.len() < 2 {
            return Err(BridgeError::SmoltcpUdp("incomplete port".into()));
        }
        let port = self.buffer.get_u16();

        // Calculate remaining payload length: length - address.encoded_len() - 2 (port)
        let header_consumed = address.encoded_len() + 2;
        let payload_len = length - header_consumed;

        if self.buffer.len() < payload_len {
            return Err(BridgeError::SmoltcpUdp("incomplete payload".into()));
        }

        let payload = self.buffer.copy_to_bytes(payload_len);

        Ok(Some(VlessUdpFrame {
            address,
            port,
            payload,
        }))
    }

    /// Check if the buffer is empty
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// Get the current buffer length
    #[must_use]
    pub fn buffered_len(&self) -> usize {
        self.buffer.len()
    }
}

impl Default for VlessUdpCodec {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_address_ipv4() {
        let addr = UdpFrameAddress::Ipv4(Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(addr.address_type(), address_type::IPV4);
        assert_eq!(addr.encoded_len(), 5); // 1 type + 4 bytes
        assert_eq!(addr.to_string(), "192.168.1.1");
        assert_eq!(
            addr.to_ip_addr(),
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))
        );
    }

    #[test]
    fn test_address_ipv6() {
        let addr = UdpFrameAddress::Ipv6(Ipv6Addr::LOCALHOST);
        assert_eq!(addr.address_type(), address_type::IPV6);
        assert_eq!(addr.encoded_len(), 17); // 1 type + 16 bytes
        assert!(addr.to_string().contains("::1"));
    }

    #[test]
    fn test_address_domain() {
        let addr = UdpFrameAddress::Domain("example.com".into());
        assert_eq!(addr.address_type(), address_type::DOMAIN);
        assert_eq!(addr.encoded_len(), 1 + 1 + 11); // type + len + string
        assert_eq!(addr.to_string(), "example.com");
        assert!(addr.to_ip_addr().is_none());
    }

    #[test]
    fn test_address_from_ip() {
        let v4 = UdpFrameAddress::from_ip(IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert!(matches!(v4, UdpFrameAddress::Ipv4(_)));

        let v6 = UdpFrameAddress::from_ip(IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert!(matches!(v6, UdpFrameAddress::Ipv6(_)));
    }

    #[test]
    fn test_address_encode() {
        let addr = UdpFrameAddress::Ipv4(Ipv4Addr::new(8, 8, 8, 8));
        let mut buf = BytesMut::new();
        addr.encode(&mut buf);
        assert_eq!(buf.as_ref(), &[0x01, 8, 8, 8, 8]);

        let addr = UdpFrameAddress::Domain("test.com".into());
        let mut buf = BytesMut::new();
        addr.encode(&mut buf);
        assert_eq!(buf[0], 0x02); // type
        assert_eq!(buf[1], 8); // length
        assert_eq!(&buf[2..], b"test.com");
    }

    #[tokio::test]
    async fn test_address_decode_ipv4() {
        let data = vec![0x01, 10, 0, 0, 1];
        let mut cursor = Cursor::new(data);
        let addr = UdpFrameAddress::decode(&mut cursor).await.unwrap();
        assert_eq!(addr, UdpFrameAddress::Ipv4(Ipv4Addr::new(10, 0, 0, 1)));
    }

    #[tokio::test]
    async fn test_address_decode_domain() {
        let mut data = vec![0x02, 7];
        data.extend_from_slice(b"foo.bar");
        let mut cursor = Cursor::new(data);
        let addr = UdpFrameAddress::decode(&mut cursor).await.unwrap();
        assert_eq!(addr, UdpFrameAddress::Domain("foo.bar".into()));
    }

    #[tokio::test]
    async fn test_address_decode_ipv6() {
        let mut data = vec![0x03];
        data.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        let mut cursor = Cursor::new(data);
        let addr = UdpFrameAddress::decode(&mut cursor).await.unwrap();
        assert_eq!(addr, UdpFrameAddress::Ipv6(Ipv6Addr::LOCALHOST));
    }

    #[test]
    fn test_frame_new() {
        let frame = VlessUdpFrame::new(
            UdpFrameAddress::Ipv4(Ipv4Addr::new(8, 8, 8, 8)),
            53,
            vec![1, 2, 3, 4],
        );
        assert_eq!(frame.port, 53);
        assert_eq!(frame.payload.len(), 4);
    }

    #[test]
    fn test_frame_from_socket_addr() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 8080);
        let frame = VlessUdpFrame::from_socket_addr(addr, vec![0xAB, 0xCD]);
        assert_eq!(frame.port, 8080);
        assert_eq!(frame.socket_addr(), Some(addr));
    }

    #[test]
    fn test_frame_encoded_len() {
        let frame = VlessUdpFrame::new(
            UdpFrameAddress::Ipv4(Ipv4Addr::LOCALHOST),
            53,
            vec![0; 100],
        );
        // 2 (len) + 2 (port) + 1 (type) + 4 (ipv4) + 100 (payload) = 109
        assert_eq!(frame.encoded_len(), 109);
    }

    #[test]
    fn test_frame_encode() {
        let frame = VlessUdpFrame::new(
            UdpFrameAddress::Ipv4(Ipv4Addr::new(8, 8, 8, 8)),
            53,
            vec![0xDE, 0xAD],
        );
        let encoded = frame.encode();

        // Xray format: [Length][AddrType][Address][Port][Payload]
        // Length (inner): 5 (addr) + 2 (port) + 2 (payload) = 9
        assert_eq!(encoded[0], 0);
        assert_eq!(encoded[1], 9);

        // Address type: IPv4 = 0x01
        assert_eq!(encoded[2], 0x01);

        // IPv4: 8.8.8.8
        assert_eq!(&encoded[3..7], &[8, 8, 8, 8]);

        // Port: 53 = 0x0035
        assert_eq!(encoded[7], 0);
        assert_eq!(encoded[8], 53);

        // Payload
        assert_eq!(&encoded[9..], &[0xDE, 0xAD]);
    }

    #[tokio::test]
    async fn test_frame_roundtrip_ipv4() {
        let frame = VlessUdpFrame::new(
            UdpFrameAddress::Ipv4(Ipv4Addr::new(1, 2, 3, 4)),
            12345,
            vec![0x11, 0x22, 0x33, 0x44],
        );

        let encoded = frame.encode();
        let mut cursor = Cursor::new(encoded.to_vec());
        let decoded = VlessUdpFrame::read_from(&mut cursor)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(decoded.address, frame.address);
        assert_eq!(decoded.port, frame.port);
        assert_eq!(decoded.payload, frame.payload);
    }

    #[tokio::test]
    async fn test_frame_roundtrip_ipv6() {
        let frame = VlessUdpFrame::new(
            UdpFrameAddress::Ipv6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            443,
            vec![0xAA; 1000],
        );

        let encoded = frame.encode();
        let mut cursor = Cursor::new(encoded.to_vec());
        let decoded = VlessUdpFrame::read_from(&mut cursor)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(decoded.address, frame.address);
        assert_eq!(decoded.port, frame.port);
        assert_eq!(decoded.payload.len(), 1000);
    }

    #[tokio::test]
    async fn test_frame_roundtrip_domain() {
        let frame = VlessUdpFrame::new(
            UdpFrameAddress::Domain("dns.google.com".into()),
            53,
            vec![0x00, 0x01, 0x02],
        );

        let encoded = frame.encode();
        let mut cursor = Cursor::new(encoded.to_vec());
        let decoded = VlessUdpFrame::read_from(&mut cursor)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(
            decoded.address,
            UdpFrameAddress::Domain("dns.google.com".into())
        );
        assert_eq!(decoded.port, 53);
    }

    #[tokio::test]
    async fn test_frame_read_eof() {
        let mut cursor = Cursor::new(vec![]);
        let result = VlessUdpFrame::read_from(&mut cursor).await.unwrap();
        assert!(result.is_none()); // Clean EOF
    }

    #[tokio::test]
    async fn test_frame_read_invalid_length() {
        // Length = 1 (too short)
        let data = vec![0, 1];
        let mut cursor = Cursor::new(data);
        let result = VlessUdpFrame::read_from(&mut cursor).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_frame_write_to() {
        let frame = VlessUdpFrame::new(
            UdpFrameAddress::Ipv4(Ipv4Addr::LOCALHOST),
            8080,
            vec![0xFF],
        );

        let mut buf = Vec::new();
        frame.write_to(&mut buf).await.unwrap();

        assert_eq!(buf, frame.encode().to_vec());
    }

    #[test]
    fn test_codec_new() {
        let codec = VlessUdpCodec::new();
        assert!(codec.is_empty());
        assert_eq!(codec.buffered_len(), 0);
    }

    #[test]
    fn test_codec_single_frame() {
        let frame = VlessUdpFrame::new(
            UdpFrameAddress::Ipv4(Ipv4Addr::new(8, 8, 8, 8)),
            53,
            vec![0xAB, 0xCD],
        );
        let encoded = frame.encode();

        let mut codec = VlessUdpCodec::new();
        codec.feed(&encoded);

        let decoded = codec.decode().unwrap().unwrap();
        assert_eq!(decoded.port, 53);
        assert_eq!(decoded.payload.as_ref(), &[0xAB, 0xCD]);

        // Buffer should be empty now
        assert!(codec.is_empty());
    }

    #[test]
    fn test_codec_partial_frame() {
        let frame = VlessUdpFrame::new(
            UdpFrameAddress::Ipv4(Ipv4Addr::LOCALHOST),
            80,
            vec![1, 2, 3, 4, 5],
        );
        let encoded = frame.encode();

        let mut codec = VlessUdpCodec::new();

        // Feed partial data
        codec.feed(&encoded[..5]);
        assert!(codec.decode().unwrap().is_none()); // Need more data

        // Feed remaining
        codec.feed(&encoded[5..]);
        let decoded = codec.decode().unwrap().unwrap();
        assert_eq!(decoded.port, 80);
    }

    #[test]
    fn test_codec_multiple_frames() {
        let frame1 = VlessUdpFrame::new(
            UdpFrameAddress::Ipv4(Ipv4Addr::new(1, 1, 1, 1)),
            53,
            vec![0x01],
        );
        let frame2 = VlessUdpFrame::new(
            UdpFrameAddress::Ipv4(Ipv4Addr::new(8, 8, 8, 8)),
            53,
            vec![0x02],
        );

        let mut data = Vec::new();
        data.extend_from_slice(&frame1.encode());
        data.extend_from_slice(&frame2.encode());

        let mut codec = VlessUdpCodec::new();
        codec.feed(&data);

        // Decode first frame
        let d1 = codec.decode().unwrap().unwrap();
        assert_eq!(d1.address, UdpFrameAddress::Ipv4(Ipv4Addr::new(1, 1, 1, 1)));

        // Decode second frame
        let d2 = codec.decode().unwrap().unwrap();
        assert_eq!(d2.address, UdpFrameAddress::Ipv4(Ipv4Addr::new(8, 8, 8, 8)));

        // No more frames
        assert!(codec.decode().unwrap().is_none());
    }

    #[test]
    fn test_codec_default() {
        let codec = VlessUdpCodec::default();
        assert!(codec.is_empty());
    }

    #[test]
    fn test_large_payload() {
        // Test with a reasonably large payload
        let payload = vec![0xAA; 10000];
        let frame = VlessUdpFrame::new(
            UdpFrameAddress::Domain("large.example.com".into()),
            443,
            payload.clone(),
        );

        let mut codec = VlessUdpCodec::new();
        codec.feed(&frame.encode());

        let decoded = codec.decode().unwrap().unwrap();
        assert_eq!(decoded.payload.len(), 10000);
        assert_eq!(decoded.payload.as_ref(), payload.as_slice());
    }
}
