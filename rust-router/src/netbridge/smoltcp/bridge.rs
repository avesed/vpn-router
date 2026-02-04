//! SmoltcpBridge - Core smoltcp interface and socket management
//!
//! This module provides the `SmoltcpBridge` struct which wraps the smoltcp
//! `Interface` and `SocketSet`, providing a higher-level API for socket
//! operations.
//!
//! # Thread Safety
//!
//! `SmoltcpBridge` is NOT thread-safe. It should be owned by a single task
//! (typically `SmoltcpShard`) and accessed only from that task.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────┐
//! │                  SmoltcpBridge                       │
//! ├──────────────────────────────────────────────────────┤
//! │  smoltcp::Interface                                  │
//! │  - IP address configuration                          │
//! │  - Routing context                                   │
//! ├──────────────────────────────────────────────────────┤
//! │  smoltcp::SocketSet                                  │
//! │  - TCP sockets                                       │
//! │  - UDP sockets                                       │
//! ├──────────────────────────────────────────────────────┤
//! │  VirtualDevice                                       │
//! │  - RX buffer (WG -> smoltcp)                        │
//! │  - TX buffer (smoltcp -> WG)                        │
//! └──────────────────────────────────────────────────────┘
//! ```

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use smoltcp::iface::{Config as IfaceConfig, Interface, PollResult, SocketHandle, SocketSet};
use smoltcp::socket::tcp::{Socket as TcpSocket, SocketBuffer as TcpSocketBuffer, State as TcpState};
use smoltcp::socket::udp::{
    PacketBuffer as UdpPacketBuffer, PacketMetadata as UdpPacketMetadata, Socket as UdpSocket,
};
use smoltcp::time::Instant as SmoltcpInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint};
use tracing::{debug, trace};

use super::device::VirtualDevice;
use super::{MAX_SOCKETS, TCP_RX_BUFFER, TCP_TX_BUFFER, UDP_PACKET_META, UDP_RX_BUFFER, UDP_TX_BUFFER, WG_MTU};
use crate::netbridge::error::{NetBridgeError, Result};

// =============================================================================
// Bridge Configuration
// =============================================================================

/// Configuration for creating a SmoltcpBridge
#[derive(Debug, Clone)]
pub struct SmoltcpBridgeConfig {
    /// Local IP address for the smoltcp interface
    pub local_ip: IpAddress,
    /// Maximum transmission unit (typically 1420 for WireGuard)
    pub mtu: usize,
    /// TCP receive buffer size per socket
    pub tcp_rx_buffer: usize,
    /// TCP transmit buffer size per socket
    pub tcp_tx_buffer: usize,
    /// UDP receive buffer size per socket
    pub udp_rx_buffer: usize,
    /// UDP transmit buffer size per socket
    pub udp_tx_buffer: usize,
    /// UDP packet metadata count
    pub udp_packet_meta: usize,
    /// Maximum number of sockets
    pub max_sockets: usize,
}

impl SmoltcpBridgeConfig {
    /// Create a new configuration with the given local IP
    #[must_use]
    pub fn new(local_ip: IpAddress) -> Self {
        Self {
            local_ip,
            mtu: WG_MTU,
            tcp_rx_buffer: TCP_RX_BUFFER,
            tcp_tx_buffer: TCP_TX_BUFFER,
            udp_rx_buffer: UDP_RX_BUFFER,
            udp_tx_buffer: UDP_TX_BUFFER,
            udp_packet_meta: UDP_PACKET_META,
            max_sockets: MAX_SOCKETS,
        }
    }

    /// Create a configuration with IPv4 address
    #[must_use]
    pub fn with_ipv4(a: u8, b: u8, c: u8, d: u8) -> Self {
        Self::new(IpAddress::v4(a, b, c, d))
    }

    /// Set custom MTU
    #[must_use]
    pub fn with_mtu(mut self, mtu: usize) -> Self {
        self.mtu = mtu;
        self
    }

    /// Set custom TCP buffer sizes
    #[must_use]
    pub fn with_tcp_buffers(mut self, rx: usize, tx: usize) -> Self {
        self.tcp_rx_buffer = rx;
        self.tcp_tx_buffer = tx;
        self
    }

    /// Set custom UDP buffer sizes
    #[must_use]
    pub fn with_udp_buffers(mut self, rx: usize, tx: usize) -> Self {
        self.udp_rx_buffer = rx;
        self.udp_tx_buffer = tx;
        self
    }
}

impl Default for SmoltcpBridgeConfig {
    fn default() -> Self {
        Self::with_ipv4(10, 200, 200, 2)
    }
}

// =============================================================================
// SmoltcpBridge
// =============================================================================

/// Bridge between smoltcp TCP/IP stack and WireGuard tunnel
///
/// This struct manages:
/// - A smoltcp `Interface` for IP-level packet processing
/// - A `SocketSet` for managing TCP/UDP sockets
/// - A `VirtualDevice` for packet exchange with WireGuard
///
/// # Thread Safety
///
/// This struct is NOT thread-safe. It should be used from a single async task
/// and NOT shared across tasks.
pub struct SmoltcpBridge {
    /// The smoltcp network interface
    iface: Interface,
    /// Socket set for managing connections
    sockets: SocketSet<'static>,
    /// Virtual device for packet exchange
    device: VirtualDevice,
    /// Configuration
    config: SmoltcpBridgeConfig,
    /// Reference instant for smoltcp time
    start_instant: Instant,
}

impl SmoltcpBridge {
    /// Create a new smoltcp bridge with the given configuration
    #[must_use]
    pub fn new(config: SmoltcpBridgeConfig) -> Self {
        let start_instant = Instant::now();
        let smoltcp_now = SmoltcpInstant::from_millis(0);

        // Create virtual device
        let mut device = VirtualDevice::new(config.mtu);

        // Create interface configuration for IP-layer operation (no MAC address)
        let iface_config = IfaceConfig::new(HardwareAddress::Ip);

        // Create the interface
        let mut iface = Interface::new(iface_config, &mut device, smoltcp_now);

        // Configure the local IP address using /32 for point-to-point tunnel
        iface.update_ip_addrs(|addrs| {
            let _ = addrs.push(IpCidr::new(config.local_ip, 32));
        });

        // Create socket set
        let sockets = SocketSet::new(Vec::new());

        debug!(
            local_ip = %config.local_ip,
            mtu = config.mtu,
            "SmoltcpBridge created"
        );

        Self {
            iface,
            sockets,
            device,
            config,
            start_instant,
        }
    }

    /// Create a new bridge with default configuration
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(SmoltcpBridgeConfig::default())
    }

    // =========================================================================
    // Time Management
    // =========================================================================

    /// Get the current smoltcp timestamp
    ///
    /// Uses a monotonic clock relative to bridge creation time.
    #[must_use]
    pub fn now(&self) -> SmoltcpInstant {
        let elapsed = self.start_instant.elapsed();
        SmoltcpInstant::from_millis(elapsed.as_millis() as i64)
    }

    // =========================================================================
    // Device Access
    // =========================================================================

    /// Get mutable reference to the virtual device
    #[must_use]
    pub fn device_mut(&mut self) -> &mut VirtualDevice {
        &mut self.device
    }

    /// Get reference to the virtual device
    #[must_use]
    pub fn device(&self) -> &VirtualDevice {
        &self.device
    }

    /// Push a received IP packet from WireGuard into the bridge
    ///
    /// The packet will be processed by smoltcp on the next `poll()` call.
    ///
    /// # Returns
    ///
    /// `true` if the packet was queued, `false` if the buffer is full
    pub fn feed_rx(&mut self, packet: Vec<u8>) -> bool {
        self.device.push_rx(packet)
    }

    /// Drain all TX packets generated by smoltcp
    ///
    /// These packets should be encrypted and sent through WireGuard.
    #[must_use]
    pub fn drain_tx(&mut self) -> Vec<Vec<u8>> {
        self.device.drain_tx()
    }

    /// Check if there are packets waiting to be sent
    #[must_use]
    pub fn has_tx(&self) -> bool {
        self.device.has_tx()
    }

    /// Check if there are packets waiting to be processed
    #[must_use]
    pub fn has_rx(&self) -> bool {
        self.device.has_rx()
    }

    // =========================================================================
    // Poll and Timing
    // =========================================================================

    /// Poll the smoltcp state machine
    ///
    /// This method drives the smoltcp TCP/IP stack forward, processing
    /// any received packets and generating packets to send.
    ///
    /// # Returns
    ///
    /// `true` if any work was done (packets processed or generated)
    pub fn poll(&mut self) -> bool {
        let timestamp = self.now();
        self.iface.poll(timestamp, &mut self.device, &mut self.sockets) != PollResult::None
    }

    /// Get the delay until the next poll is needed
    ///
    /// This enables event-driven polling instead of fixed-interval polling.
    ///
    /// # Returns
    ///
    /// - `Some(duration)` - Wait this long before the next poll
    /// - `None` - Poll immediately (there's pending work)
    #[must_use]
    pub fn poll_delay(&mut self) -> Option<Duration> {
        let timestamp = self.now();
        self.iface
            .poll_delay(timestamp, &self.sockets)
            .map(|d| Duration::from_micros(d.total_micros()))
    }

    // =========================================================================
    // Socket Management
    // =========================================================================

    /// Get the number of active sockets
    #[must_use]
    pub fn socket_count(&self) -> usize {
        self.sockets.iter().count()
    }

    /// Check if the socket limit has been reached
    #[must_use]
    pub fn is_socket_limit_reached(&self) -> bool {
        self.socket_count() >= self.config.max_sockets
    }

    // =========================================================================
    // TCP Socket Operations
    // =========================================================================

    /// Create a new TCP socket
    ///
    /// # Returns
    ///
    /// The socket handle, or an error if the limit is reached
    pub fn create_tcp_socket(&mut self) -> Result<SocketHandle> {
        self.create_tcp_socket_with_buffers(self.config.tcp_rx_buffer, self.config.tcp_tx_buffer)
    }

    /// Create a new TCP socket with custom buffer sizes
    ///
    /// # Arguments
    ///
    /// * `rx_buffer_size` - Receive buffer size
    /// * `tx_buffer_size` - Transmit buffer size
    ///
    /// # Returns
    ///
    /// The socket handle, or an error if the limit is reached
    pub fn create_tcp_socket_with_buffers(
        &mut self,
        rx_buffer_size: usize,
        tx_buffer_size: usize,
    ) -> Result<SocketHandle> {
        if self.is_socket_limit_reached() {
            return Err(NetBridgeError::SocketLimitReached(self.config.max_sockets));
        }

        let rx_buffer = TcpSocketBuffer::new(vec![0u8; rx_buffer_size]);
        let tx_buffer = TcpSocketBuffer::new(vec![0u8; tx_buffer_size]);
        let mut socket = TcpSocket::new(rx_buffer, tx_buffer);

        // Configure socket for optimal tunnel performance
        socket.set_nagle_enabled(false); // Disable Nagle for low latency
        socket.set_ack_delay(None); // Disable delayed ACKs

        let handle = self.sockets.add(socket);
        trace!(?handle, rx_buffer_size, tx_buffer_size, "TCP socket created");

        Ok(handle)
    }

    /// Get a mutable reference to a TCP socket
    pub fn tcp_socket_mut(&mut self, handle: SocketHandle) -> &mut TcpSocket<'static> {
        self.sockets.get_mut::<TcpSocket>(handle)
    }

    /// Get an immutable reference to a TCP socket
    #[must_use]
    pub fn tcp_socket(&self, handle: SocketHandle) -> &TcpSocket<'static> {
        self.sockets.get::<TcpSocket>(handle)
    }

    /// Connect a TCP socket to a remote endpoint
    ///
    /// # Arguments
    ///
    /// * `handle` - Socket handle
    /// * `remote` - Remote endpoint (IP:port)
    /// * `local_port` - Local ephemeral port
    pub fn tcp_connect(
        &mut self,
        handle: SocketHandle,
        remote: IpEndpoint,
        local_port: u16,
    ) -> Result<()> {
        let local_endpoint = IpEndpoint::new(self.config.local_ip, local_port);
        let cx = self.iface.context();
        let socket = self.sockets.get_mut::<TcpSocket>(handle);

        socket.connect(cx, remote, local_endpoint).map_err(|e| {
            NetBridgeError::from_tcp_connect_error(e)
        })?;

        debug!(
            ?handle,
            ?remote,
            local_port,
            "TCP connect initiated"
        );

        Ok(())
    }

    /// Get the state of a TCP socket
    #[must_use]
    pub fn tcp_state(&self, handle: SocketHandle) -> TcpState {
        self.tcp_socket(handle).state()
    }

    /// Check if a TCP socket can send data
    #[must_use]
    pub fn tcp_can_send(&self, handle: SocketHandle) -> bool {
        self.tcp_socket(handle).can_send()
    }

    /// Check if a TCP socket can receive data
    #[must_use]
    pub fn tcp_can_recv(&self, handle: SocketHandle) -> bool {
        self.tcp_socket(handle).can_recv()
    }

    /// Check if a TCP socket is active (established or connecting)
    #[must_use]
    pub fn tcp_is_active(&self, handle: SocketHandle) -> bool {
        self.tcp_socket(handle).is_active()
    }

    /// Get the remote endpoint of a TCP socket
    #[must_use]
    pub fn tcp_remote_endpoint(&self, handle: SocketHandle) -> Option<IpEndpoint> {
        self.tcp_socket(handle).remote_endpoint()
    }

    /// Send data through a TCP socket
    ///
    /// # Returns
    ///
    /// Number of bytes sent
    pub fn tcp_send(&mut self, handle: SocketHandle, data: &[u8]) -> Result<usize> {
        let socket = self.sockets.get_mut::<TcpSocket>(handle);
        socket.send_slice(data).map_err(|e| {
            NetBridgeError::from_tcp_send_error(e)
        })
    }

    /// Receive data from a TCP socket
    ///
    /// # Arguments
    ///
    /// * `handle` - Socket handle
    /// * `buffer` - Buffer to receive data into
    ///
    /// # Returns
    ///
    /// Number of bytes received
    pub fn tcp_recv(&mut self, handle: SocketHandle, buffer: &mut [u8]) -> Result<usize> {
        let socket = self.sockets.get_mut::<TcpSocket>(handle);
        socket.recv_slice(buffer).map_err(|e| {
            NetBridgeError::from_tcp_recv_error(e)
        })
    }

    /// Close a TCP socket gracefully
    pub fn tcp_close(&mut self, handle: SocketHandle) {
        let socket = self.sockets.get_mut::<TcpSocket>(handle);
        socket.close();
        trace!(?handle, "TCP socket close initiated");
    }

    /// Abort a TCP socket (send RST)
    pub fn tcp_abort(&mut self, handle: SocketHandle) {
        let socket = self.sockets.get_mut::<TcpSocket>(handle);
        socket.abort();
        trace!(?handle, "TCP socket aborted");
    }

    // =========================================================================
    // UDP Socket Operations
    // =========================================================================

    /// Create a new UDP socket
    ///
    /// # Returns
    ///
    /// The socket handle, or an error if the limit is reached
    pub fn create_udp_socket(&mut self) -> Result<SocketHandle> {
        self.create_udp_socket_with_buffers(
            self.config.udp_rx_buffer,
            self.config.udp_tx_buffer,
            self.config.udp_packet_meta,
        )
    }

    /// Create a new UDP socket with custom buffer sizes
    pub fn create_udp_socket_with_buffers(
        &mut self,
        rx_buffer_size: usize,
        tx_buffer_size: usize,
        packet_meta_count: usize,
    ) -> Result<SocketHandle> {
        if self.is_socket_limit_reached() {
            return Err(NetBridgeError::SocketLimitReached(self.config.max_sockets));
        }

        let rx_meta = vec![UdpPacketMetadata::EMPTY; packet_meta_count];
        let rx_buffer = vec![0u8; rx_buffer_size];
        let tx_meta = vec![UdpPacketMetadata::EMPTY; packet_meta_count];
        let tx_buffer = vec![0u8; tx_buffer_size];

        let socket = UdpSocket::new(
            UdpPacketBuffer::new(rx_meta, rx_buffer),
            UdpPacketBuffer::new(tx_meta, tx_buffer),
        );

        let handle = self.sockets.add(socket);
        trace!(?handle, rx_buffer_size, tx_buffer_size, "UDP socket created");

        Ok(handle)
    }

    /// Get a mutable reference to a UDP socket
    pub fn udp_socket_mut(&mut self, handle: SocketHandle) -> &mut UdpSocket<'static> {
        self.sockets.get_mut::<UdpSocket>(handle)
    }

    /// Get an immutable reference to a UDP socket
    #[must_use]
    pub fn udp_socket(&self, handle: SocketHandle) -> &UdpSocket<'static> {
        self.sockets.get::<UdpSocket>(handle)
    }

    /// Bind a UDP socket to a local port
    pub fn udp_bind(&mut self, handle: SocketHandle, port: u16) -> Result<()> {
        let socket = self.sockets.get_mut::<UdpSocket>(handle);
        socket.bind(port).map_err(|e| {
            NetBridgeError::from_udp_bind_error(e)
        })?;
        trace!(?handle, port, "UDP socket bound");
        Ok(())
    }

    /// Send data through a UDP socket
    pub fn udp_send(&mut self, handle: SocketHandle, data: &[u8], remote: IpEndpoint) -> Result<()> {
        let socket = self.sockets.get_mut::<UdpSocket>(handle);
        socket.send_slice(data, remote).map_err(|e| {
            NetBridgeError::from_udp_send_error(e)
        })
    }

    /// Receive data from a UDP socket
    ///
    /// # Returns
    ///
    /// Tuple of (data, remote endpoint)
    pub fn udp_recv(&mut self, handle: SocketHandle) -> Result<(Vec<u8>, IpEndpoint)> {
        let socket = self.sockets.get_mut::<UdpSocket>(handle);
        let (data, metadata) = socket.recv().map_err(|e| {
            NetBridgeError::from_udp_recv_error(e)
        })?;
        Ok((data.to_vec(), metadata.endpoint))
    }

    /// Check if a UDP socket can send
    #[must_use]
    pub fn udp_can_send(&self, handle: SocketHandle) -> bool {
        self.udp_socket(handle).can_send()
    }

    /// Check if a UDP socket can receive
    #[must_use]
    pub fn udp_can_recv(&self, handle: SocketHandle) -> bool {
        self.udp_socket(handle).can_recv()
    }

    /// Check if a UDP socket is open (bound)
    #[must_use]
    pub fn udp_is_open(&self, handle: SocketHandle) -> bool {
        self.udp_socket(handle).is_open()
    }

    /// Close a UDP socket
    pub fn udp_close(&mut self, handle: SocketHandle) {
        let socket = self.sockets.get_mut::<UdpSocket>(handle);
        socket.close();
        trace!(?handle, "UDP socket closed");
    }

    // =========================================================================
    // Socket Removal
    // =========================================================================

    /// Remove a socket from the socket set
    ///
    /// This immediately frees the socket resources.
    pub fn remove_socket(&mut self, handle: SocketHandle) {
        self.sockets.remove(handle);
        debug!(?handle, "Socket removed");
    }

    // =========================================================================
    // Configuration Access
    // =========================================================================

    /// Get the local IP address
    #[must_use]
    pub fn local_ip(&self) -> IpAddress {
        self.config.local_ip
    }

    /// Get the MTU
    #[must_use]
    pub fn mtu(&self) -> usize {
        self.config.mtu
    }

    /// Get the configuration
    #[must_use]
    pub fn config(&self) -> &SmoltcpBridgeConfig {
        &self.config
    }
}

impl std::fmt::Debug for SmoltcpBridge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SmoltcpBridge")
            .field("local_ip", &self.config.local_ip)
            .field("mtu", &self.config.mtu)
            .field("socket_count", &self.socket_count())
            .field("rx_queue_len", &self.device.rx_queue_len())
            .field("tx_queue_len", &self.device.tx_queue_len())
            .finish()
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Convert std::net::SocketAddr to smoltcp IpEndpoint
///
/// # Returns
///
/// `Some(IpEndpoint)` for IPv4, `None` for IPv6 (not supported)
pub fn socket_addr_to_endpoint(addr: SocketAddr) -> Option<IpEndpoint> {
    match addr {
        SocketAddr::V4(v4) => {
            let octets = v4.ip().octets();
            Some(IpEndpoint::new(
                IpAddress::v4(octets[0], octets[1], octets[2], octets[3]),
                v4.port(),
            ))
        }
        SocketAddr::V6(_) => {
            // IPv6 not currently supported
            None
        }
    }
}

/// Convert smoltcp IpEndpoint to std::net::SocketAddr
///
/// # Returns
///
/// `Some(SocketAddr)` for IPv4, `None` for IPv6
pub fn endpoint_to_socket_addr(endpoint: IpEndpoint) -> Option<SocketAddr> {
    match endpoint.addr {
        IpAddress::Ipv4(v4) => {
            Some(SocketAddr::new(
                std::net::IpAddr::V4(v4),
                endpoint.port,
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bridge_config_new() {
        let config = SmoltcpBridgeConfig::with_ipv4(10, 25, 0, 1);
        assert_eq!(config.local_ip, IpAddress::v4(10, 25, 0, 1));
        assert_eq!(config.mtu, WG_MTU);
        assert_eq!(config.tcp_rx_buffer, TCP_RX_BUFFER);
    }

    #[test]
    fn test_bridge_config_with_mtu() {
        let config = SmoltcpBridgeConfig::default().with_mtu(1400);
        assert_eq!(config.mtu, 1400);
    }

    #[test]
    fn test_bridge_new() {
        let bridge = SmoltcpBridge::with_defaults();
        assert_eq!(bridge.socket_count(), 0);
        assert!(!bridge.has_rx());
        assert!(!bridge.has_tx());
    }

    #[test]
    fn test_bridge_feed_rx() {
        let mut bridge = SmoltcpBridge::with_defaults();

        assert!(bridge.feed_rx(vec![1, 2, 3, 4]));
        assert!(bridge.has_rx());
    }

    #[test]
    fn test_bridge_create_tcp_socket() {
        let mut bridge = SmoltcpBridge::with_defaults();

        let handle = bridge.create_tcp_socket().expect("should create");
        assert_eq!(bridge.socket_count(), 1);
        assert_eq!(bridge.tcp_state(handle), TcpState::Closed);
    }

    #[test]
    fn test_bridge_create_udp_socket() {
        let mut bridge = SmoltcpBridge::with_defaults();

        let handle = bridge.create_udp_socket().expect("should create");
        assert_eq!(bridge.socket_count(), 1);
        assert!(!bridge.udp_is_open(handle));

        bridge.udp_bind(handle, 12345).expect("should bind");
        assert!(bridge.udp_is_open(handle));
    }

    #[test]
    fn test_bridge_socket_limit() {
        let config = SmoltcpBridgeConfig::default();
        let max = 5;
        let mut bridge = SmoltcpBridge::new(SmoltcpBridgeConfig {
            max_sockets: max,
            ..config
        });

        // Create max sockets with small buffers
        for _ in 0..max {
            assert!(bridge.create_tcp_socket_with_buffers(1024, 1024).is_ok());
        }

        // Next should fail
        assert!(matches!(
            bridge.create_tcp_socket(),
            Err(NetBridgeError::SocketLimitReached(5))
        ));
    }

    #[test]
    fn test_bridge_remove_socket() {
        let mut bridge = SmoltcpBridge::with_defaults();

        let handle = bridge.create_tcp_socket().expect("should create");
        assert_eq!(bridge.socket_count(), 1);

        bridge.remove_socket(handle);
        assert_eq!(bridge.socket_count(), 0);
    }

    #[test]
    fn test_bridge_poll() {
        let mut bridge = SmoltcpBridge::with_defaults();

        // Poll with no packets should work
        let _result = bridge.poll();

        // Poll delay should return something
        let _delay = bridge.poll_delay();
    }

    #[test]
    fn test_socket_addr_to_endpoint() {
        let addr: SocketAddr = "192.168.1.1:8080".parse().unwrap();
        let endpoint = socket_addr_to_endpoint(addr).expect("should convert");

        assert_eq!(endpoint.port, 8080);
        assert_eq!(endpoint.addr, IpAddress::v4(192, 168, 1, 1));
    }

    #[test]
    fn test_endpoint_to_socket_addr() {
        let endpoint = IpEndpoint::new(IpAddress::v4(10, 0, 0, 1), 443);
        let addr = endpoint_to_socket_addr(endpoint).expect("should convert");

        assert_eq!(addr.port(), 443);
        assert_eq!(addr.ip().to_string(), "10.0.0.1");
    }

    #[test]
    fn test_ipv6_not_supported() {
        let addr: SocketAddr = "[::1]:8080".parse().unwrap();
        assert!(socket_addr_to_endpoint(addr).is_none());
    }

    #[test]
    fn test_bridge_debug() {
        let bridge = SmoltcpBridge::with_defaults();
        let debug_str = format!("{:?}", bridge);
        assert!(debug_str.contains("SmoltcpBridge"));
    }
}
