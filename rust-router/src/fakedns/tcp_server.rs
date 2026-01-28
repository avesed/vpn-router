//! FakeDNS TCP server
//!
//! This module provides a TCP DNS server that handles DNS-over-TCP requests,
//! returning fake IP addresses for domain names.

use std::io::{self, ErrorKind};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::BytesMut;
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::serialize::binary::{BinEncodable, BinEncoder, EncodeMode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time;
use tracing::{debug, error, trace};

use super::manager::FakeDnsManager;
use super::processor::handle_dns_request;

/// FakeDNS TCP server
pub struct FakeDnsTcpServer {
    listener: TcpListener,
    manager: Arc<FakeDnsManager>,
}

impl FakeDnsTcpServer {
    /// Bind to the given address and create a new TCP server
    ///
    /// # Errors
    /// Returns an error if binding fails.
    pub async fn bind(addr: SocketAddr, manager: Arc<FakeDnsManager>) -> io::Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        Ok(Self { listener, manager })
    }

    /// Get the local address of the server
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Run the TCP server loop
    ///
    /// This method runs forever, accepting connections and handling DNS requests.
    ///
    /// # Errors
    /// Returns an error if the server encounters a fatal error.
    pub async fn run(self) -> io::Result<()> {
        loop {
            let (stream, peer_addr) = match self.listener.accept().await {
                Ok(s) => s,
                Err(err) => {
                    error!("Failed to accept FakeDNS TCP connection: {}", err);
                    time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
            };

            trace!("FakeDNS TCP accepted client {}", peer_addr);

            let manager = self.manager.clone();
            tokio::spawn(async move {
                if let Err(err) = Self::handle_client(stream, peer_addr, manager).await {
                    debug!("FakeDNS TCP client {} error: {}", peer_addr, err);
                }
            });
        }
    }

    /// Handle a single TCP client connection
    async fn handle_client(
        mut stream: TcpStream,
        peer_addr: SocketAddr,
        manager: Arc<FakeDnsManager>,
    ) -> io::Result<()> {
        let mut length_buf = [0u8; 2];
        let mut message_buf = BytesMut::new();

        loop {
            // Read length prefix (DNS over TCP uses 2-byte length prefix)
            match stream.read_exact(&mut length_buf).await {
                Ok(..) => {}
                Err(ref err) if err.kind() == ErrorKind::UnexpectedEof => break,
                Err(err) => {
                    error!("FakeDNS TCP {} read length error: {}", peer_addr, err);
                    return Err(err);
                }
            }

            let length = u16::from_be_bytes(length_buf) as usize;

            // Validate DNS message length (RFC 1035: max 65535 bytes)
            if length == 0 {
                debug!("FakeDNS TCP {} received zero-length message", peer_addr);
                continue;
            }
            if length > 65535 {
                error!("FakeDNS TCP {} message too large: {} bytes", peer_addr, length);
                return Err(io::Error::new(
                    ErrorKind::InvalidData,
                    "DNS message exceeds maximum size",
                ));
            }

            // Resize buffer with zero-initialization (safe alternative to unsafe advance_mut)
            message_buf.resize(length, 0);

            match stream.read_exact(&mut message_buf).await {
                Ok(..) => {}
                Err(err) => {
                    error!("FakeDNS TCP {} read message error: {}", peer_addr, err);
                    return Err(err);
                }
            }

            let req_message = match Message::from_vec(&message_buf) {
                Ok(m) => m,
                Err(err) => {
                    error!("FakeDNS TCP {} parse error: {}", peer_addr, err);
                    return Err(io::Error::other(err));
                }
            };

            let rsp_message = match handle_dns_request(&req_message, &manager) {
                Ok(m) => m,
                Err(err) => {
                    error!("FakeDNS request error: {}", err);
                    Message::error_msg(
                        req_message.id(),
                        req_message.op_code(),
                        ResponseCode::ServFail,
                    )
                }
            };

            // Encode response with length prefix
            let mut rsp_buffer = Vec::with_capacity(2 + 512);
            rsp_buffer.resize(2, 0); // Reserve space for length prefix
            let mut encoder = BinEncoder::with_offset(&mut rsp_buffer, 2, EncodeMode::Normal);
            rsp_message.emit(&mut encoder)?;

            // Write length prefix
            let rsp_length = (rsp_buffer.len() - 2) as u16;
            rsp_buffer[0..2].copy_from_slice(&rsp_length.to_be_bytes());

            stream.write_all(&rsp_buffer).await?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fakedns::config::FakeDnsConfig;
    use hickory_proto::op::{MessageType, OpCode, Query};
    use hickory_proto::rr::{Name, RecordType};
    use std::str::FromStr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    fn test_manager() -> Arc<FakeDnsManager> {
        let config = FakeDnsConfig::new()
            .with_ipv4_pool("10.0.0.0/24".parse().unwrap())
            .with_max_entries(1000)
            .with_ttl(Duration::from_secs(60));
        Arc::new(FakeDnsManager::new(&config))
    }

    #[tokio::test]
    async fn test_tcp_server_bind() {
        let manager = test_manager();
        let server = FakeDnsTcpServer::bind("127.0.0.1:0".parse().unwrap(), manager)
            .await
            .unwrap();
        assert!(server.local_addr().is_ok());
    }

    #[tokio::test]
    async fn test_tcp_dns_query() {
        let manager = test_manager();
        let server = FakeDnsTcpServer::bind("127.0.0.1:0".parse().unwrap(), manager.clone())
            .await
            .unwrap();
        let addr = server.local_addr().unwrap();

        // Start server in background
        tokio::spawn(server.run());

        // Give server time to start
        time::sleep(Duration::from_millis(10)).await;

        // Connect and send DNS query
        let mut client = TcpStream::connect(addr).await.unwrap();

        // Build a DNS query for example.com A record
        let mut query = Message::new();
        query.set_id(1234);
        query.set_message_type(MessageType::Query);
        query.set_op_code(OpCode::Query);
        query.set_recursion_desired(true);
        query.add_query(Query::query(
            Name::from_str("example.com.").unwrap(),
            RecordType::A,
        ));

        let query_bytes = query.to_vec().unwrap();
        let length = query_bytes.len() as u16;

        // Send with length prefix
        client.write_all(&length.to_be_bytes()).await.unwrap();
        client.write_all(&query_bytes).await.unwrap();

        // Read response
        let mut length_buf = [0u8; 2];
        client.read_exact(&mut length_buf).await.unwrap();
        let rsp_length = u16::from_be_bytes(length_buf) as usize;

        let mut rsp_buf = vec![0u8; rsp_length];
        client.read_exact(&mut rsp_buf).await.unwrap();

        let response = Message::from_vec(&rsp_buf).unwrap();
        assert_eq!(response.id(), 1234);
        assert!(!response.answers().is_empty());

        // Verify the answer is a fake IP
        if let Some(answer) = response.answers().first() {
            if let Some(rdata) = answer.data() {
                if let hickory_proto::rr::RData::A(a) = rdata {
                    assert!(manager.is_fake_ip(std::net::IpAddr::V4(a.0)));
                }
            }
        }
    }
}
