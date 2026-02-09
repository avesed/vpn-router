//! FakeDNS UDP server
//!
//! This module provides a UDP DNS server that handles standard DNS requests,
//! returning fake IP addresses for domain names.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use hickory_proto::op::{Message, ResponseCode};
use tokio::net::UdpSocket;
use tokio::time;
use tracing::{debug, error, trace};

use super::manager::FakeDnsManager;
use super::processor::handle_dns_request;

/// FakeDNS UDP server
pub struct FakeDnsUdpServer {
    socket: UdpSocket,
    manager: Arc<FakeDnsManager>,
}

impl FakeDnsUdpServer {
    /// Bind to the given address and create a new UDP server
    ///
    /// # Errors
    /// Returns an error if binding fails.
    pub async fn bind(addr: SocketAddr, manager: Arc<FakeDnsManager>) -> io::Result<Self> {
        let socket = UdpSocket::bind(addr).await?;
        Ok(Self { socket, manager })
    }

    /// Get the local address of the server
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Run the UDP server loop
    ///
    /// This method runs forever, receiving DNS requests and sending responses.
    ///
    /// # Errors
    /// Returns an error if the server encounters a fatal error.
    pub async fn run(self) -> io::Result<()> {
        // UDP DNS messages are limited to 512 bytes by default,
        // but EDNS allows up to 65535 bytes
        let mut buffer = [0u8; 65535];

        loop {
            let (n, peer_addr) = match self.socket.recv_from(&mut buffer).await {
                Ok(r) => r,
                Err(err) => {
                    error!("FakeDNS UDP recv error: {}", err);
                    time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
            };

            trace!("FakeDNS UDP received {} bytes from {}", n, peer_addr);

            let req_message = match Message::from_vec(&buffer[..n]) {
                Ok(m) => m,
                Err(err) => {
                    debug!("FakeDNS UDP parse error from {}: {}", peer_addr, err);
                    continue;
                }
            };

            let rsp_message = match handle_dns_request(&req_message, &self.manager) {
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

            let rsp_buffer = match rsp_message.to_vec() {
                Ok(buf) => buf,
                Err(err) => {
                    error!("FakeDNS response encode error: {}", err);
                    continue;
                }
            };

            if let Err(err) = self.socket.send_to(&rsp_buffer, peer_addr).await {
                debug!("FakeDNS UDP send error to {}: {}", peer_addr, err);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fakedns::config::FakeDnsConfig;
    use hickory_proto::op::{MessageType, OpCode, Query};
    use hickory_proto::rr::{Name, RecordType};
    use std::str::FromStr;
    use tokio::net::UdpSocket;

    fn test_manager() -> Arc<FakeDnsManager> {
        let config = FakeDnsConfig::new()
            .with_ipv4_pool("10.0.0.0/24".parse().unwrap())
            .with_max_entries(1000)
            .with_ttl(Duration::from_secs(60));
        Arc::new(FakeDnsManager::new(&config))
    }

    #[tokio::test]
    async fn test_udp_server_bind() {
        let manager = test_manager();
        let server = FakeDnsUdpServer::bind("127.0.0.1:0".parse().unwrap(), manager)
            .await
            .unwrap();
        assert!(server.local_addr().is_ok());
    }

    #[tokio::test]
    async fn test_udp_dns_query() {
        let manager = test_manager();
        let server = FakeDnsUdpServer::bind("127.0.0.1:0".parse().unwrap(), manager.clone())
            .await
            .unwrap();
        let server_addr = server.local_addr().unwrap();

        // Start server in background
        tokio::spawn(server.run());

        // Give server time to start
        time::sleep(Duration::from_millis(10)).await;

        // Create client socket
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        // Build a DNS query for example.com A record
        let mut query = Message::new();
        query.set_id(5678);
        query.set_message_type(MessageType::Query);
        query.set_op_code(OpCode::Query);
        query.set_recursion_desired(true);
        query.add_query(Query::query(
            Name::from_str("example.com.").unwrap(),
            RecordType::A,
        ));

        let query_bytes = query.to_vec().unwrap();

        // Send query
        client.send_to(&query_bytes, server_addr).await.unwrap();

        // Receive response
        let mut rsp_buf = [0u8; 512];
        let (n, _) = client.recv_from(&mut rsp_buf).await.unwrap();

        let response = Message::from_vec(&rsp_buf[..n]).unwrap();
        assert_eq!(response.id(), 5678);
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

    #[tokio::test]
    async fn test_udp_aaaa_query_without_ipv6() {
        let manager = test_manager();
        let server = FakeDnsUdpServer::bind("127.0.0.1:0".parse().unwrap(), manager.clone())
            .await
            .unwrap();
        let server_addr = server.local_addr().unwrap();

        // Start server in background
        tokio::spawn(server.run());

        time::sleep(Duration::from_millis(10)).await;

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        // Build a DNS query for example.com AAAA record
        let mut query = Message::new();
        query.set_id(9999);
        query.set_message_type(MessageType::Query);
        query.set_op_code(OpCode::Query);
        query.set_recursion_desired(true);
        query.add_query(Query::query(
            Name::from_str("example.com.").unwrap(),
            RecordType::AAAA,
        ));

        let query_bytes = query.to_vec().unwrap();

        client.send_to(&query_bytes, server_addr).await.unwrap();

        let mut rsp_buf = [0u8; 512];
        let (n, _) = client.recv_from(&mut rsp_buf).await.unwrap();

        let response = Message::from_vec(&rsp_buf[..n]).unwrap();
        assert_eq!(response.id(), 9999);
        // Should return empty answer (IPv6 not enabled)
        assert!(response.answers().is_empty());
    }
}
