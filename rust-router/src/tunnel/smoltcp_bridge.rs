//! Async bridge between smoltcp TCP/IP stack and WireGuard tunnel
//!
//! This module provides `SmoltcpBridge`, which manages a smoltcp `Interface`
//! and `SocketSet`, bridging them to the WireGuard tunnel for TCP/UDP communication.
//!
//! # Architecture
//!
//! ```text
//! +------------------+     +-----------------+     +------------------+
//! | SmoltcpBridge    |     | WgTunnelDevice  |     | WireGuard Tunnel |
//! |                  |     |                 |     |                  |
//! | Interface        | <-> | TunnelPacketQ   | <-> | send()/recv()    |
//! | SocketSet        |     |                 |     |                  |
//! +------------------+     +-----------------+     +------------------+
//! ```
//!
//! # Usage
//!
//! ```ignore
//! use std::net::Ipv4Addr;
//! use rust_router::tunnel::smoltcp_bridge::SmoltcpBridge;
//!
//! // Create bridge with local tunnel IP
//! let mut bridge = SmoltcpBridge::new(Ipv4Addr::new(10, 200, 200, 2), 1420);
//!
//! // Feed packets from WireGuard tunnel
//! bridge.feed_rx_packet(decrypted_packet);
//!
//! // Poll the smoltcp state machine
//! bridge.poll();
//!
//! // Get packets to send through WireGuard tunnel
//! for packet in bridge.drain_tx_packets() {
//!     tunnel.send(&packet).await?;
//! }
//! ```
//!
//! # Event-Driven Polling
//!
//! The bridge uses `poll_delay()` to determine when the next poll is needed,
//! enabling event-driven operation instead of fixed-interval polling.

use std::net::Ipv4Addr;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use smoltcp::iface::{Config as IfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::socket::tcp::{Socket as TcpSocket, SocketBuffer, State as TcpState};
use smoltcp::socket::udp::{
    PacketBuffer as UdpPacketBuffer, PacketMetadata as UdpPacketMetadata,
    RecvError as UdpRecvError, SendError as UdpSendError, Socket as UdpSocket,
};
use smoltcp::time::Instant as SmoltcpInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, Ipv4Address};
use tracing::{debug, trace, warn};

use crate::tunnel::smoltcp_device::{TunnelPacketQueue, WgTunnelDevice, DEFAULT_WG_MTU};

/// Default TCP receive buffer size (64 KB)
const DEFAULT_TCP_RX_BUFFER: usize = 65536;

/// Default TCP transmit buffer size (64 KB)
const DEFAULT_TCP_TX_BUFFER: usize = 65536;

/// Maximum number of sockets in the socket set
const MAX_SOCKETS: usize = 1024;

/// TCP Maximum Segment Size
///
/// MSS = MTU (1420) - IP header (20) - TCP header (20) = 1380
/// This ensures TCP segments fit within WireGuard's MTU.
pub const TCP_MSS: u16 = 1380;

/// Default UDP receive buffer size (64 KB)
const DEFAULT_UDP_RX_BUFFER: usize = 65536;

/// Default UDP transmit buffer size (64 KB)
const DEFAULT_UDP_TX_BUFFER: usize = 65536;

/// Default number of UDP packet metadata entries
const DEFAULT_UDP_PACKET_META: usize = 64;

/// Bridge between smoltcp TCP/IP stack and WireGuard tunnel
///
/// This struct manages:
/// - A smoltcp `Interface` for IP-level packet processing
/// - A `SocketSet` for managing TCP/UDP sockets
/// - A `TunnelPacketQueue` for exchanging packets with the WireGuard tunnel
///
/// # Thread Safety
///
/// This struct is NOT thread-safe. It should be used from a single async task
/// and protected by a mutex if shared across tasks.
pub struct SmoltcpBridge {
    /// The smoltcp network interface
    iface: Interface,
    /// Socket set for managing connections
    sockets: SocketSet<'static>,
    /// Virtual device for packet exchange
    device: WgTunnelDevice,
    /// Shared packet queue (also held by device)
    queue: Arc<TunnelPacketQueue>,
    /// Local tunnel IP address
    local_ip: Ipv4Addr,
    /// Maximum transmission unit
    mtu: usize,
}

impl SmoltcpBridge {
    /// Create a new smoltcp bridge
    ///
    /// # Arguments
    ///
    /// * `local_ip` - The local IP address assigned to this end of the tunnel
    /// * `mtu` - Maximum transmission unit (typically 1420 for WireGuard)
    ///
    /// # Example
    ///
    /// ```ignore
    /// let bridge = SmoltcpBridge::new(Ipv4Addr::new(10, 200, 200, 2), 1420);
    /// ```
    #[must_use]
    pub fn new(local_ip: Ipv4Addr, mtu: usize) -> Self {
        let queue = TunnelPacketQueue::new();

        // Create interface configuration for IP-layer operation (no MAC address)
        let config = IfaceConfig::new(HardwareAddress::Ip);

        // Create the interface
        let mut iface = Interface::new(config, &mut WgTunnelDevice::new(queue.clone(), mtu), SmoltcpInstant::from_millis(0));

        // Configure the local IP address using smoltcp's Ipv4Address
        let smoltcp_ip = Ipv4Address::new(
            local_ip.octets()[0],
            local_ip.octets()[1],
            local_ip.octets()[2],
            local_ip.octets()[3],
        );
        iface.update_ip_addrs(|addrs| {
            // Use /32 since this is a point-to-point tunnel
            let _ = addrs.push(IpCidr::new(IpAddress::Ipv4(smoltcp_ip), 32));
        });

        // Create socket storage using Vec (requires alloc feature)
        let sockets = SocketSet::new(Vec::new());

        debug!(
            "SmoltcpBridge created: local_ip={}, mtu={}",
            local_ip, mtu
        );

        Self {
            iface,
            sockets,
            device: WgTunnelDevice::new(queue.clone(), mtu),
            queue,
            local_ip,
            mtu,
        }
    }

    /// Create a new bridge with default MTU (1420)
    ///
    /// # Arguments
    ///
    /// * `local_ip` - The local IP address assigned to this end of the tunnel
    #[must_use]
    pub fn with_default_mtu(local_ip: Ipv4Addr) -> Self {
        Self::new(local_ip, DEFAULT_WG_MTU)
    }

    /// Get the local tunnel IP address
    #[must_use]
    pub fn local_ip(&self) -> Ipv4Addr {
        self.local_ip
    }

    /// Get the configured MTU
    #[must_use]
    pub fn mtu(&self) -> usize {
        self.mtu
    }

    /// Feed a received packet from the WireGuard tunnel
    ///
    /// This method should be called when a decrypted IP packet is received
    /// from the WireGuard tunnel. The packet will be queued for processing
    /// by smoltcp on the next `poll()` call.
    ///
    /// # Arguments
    ///
    /// * `packet` - The decrypted IP packet from the tunnel
    ///
    /// # Returns
    ///
    /// `true` if the packet was queued, `false` if the queue is full
    pub fn feed_rx_packet(&self, packet: Vec<u8>) -> bool {
        debug!("SmoltcpBridge: feeding {} byte packet to RX queue", packet.len());
        let result = self.queue.push_rx(packet);
        if result {
            debug!("SmoltcpBridge: packet queued for smoltcp processing");
        } else {
            warn!("SmoltcpBridge: RX queue full, packet dropped!");
        }
        result
    }

    /// Get the number of packets waiting in the RX queue
    ///
    /// Used for debugging to see if packets are being queued but not processed.
    #[must_use]
    pub fn rx_queue_len(&self) -> usize {
        self.queue.rx_queue_len()
    }

    /// Drain packets that need to be sent through the WireGuard tunnel
    ///
    /// This method returns all packets that smoltcp has produced and need
    /// to be encrypted and sent through the WireGuard tunnel.
    ///
    /// # Returns
    ///
    /// A vector of IP packets to send through the tunnel
    pub fn drain_tx_packets(&self) -> Vec<Vec<u8>> {
        let mut packets = Vec::new();
        while let Some(packet) = self.queue.pop_tx() {
            packets.push(packet);
        }
        if !packets.is_empty() {
            trace!("Drained {} packets from TX queue", packets.len());
        }
        packets
    }

    /// Check if there are packets waiting to be sent
    #[must_use]
    pub fn has_tx_packets(&self) -> bool {
        self.queue.has_tx_packets()
    }

    /// Check if there are packets waiting to be received
    #[must_use]
    pub fn has_rx_packets(&self) -> bool {
        self.queue.has_rx_packets()
    }

    /// Poll the smoltcp state machine
    ///
    /// This method drives the smoltcp TCP/IP stack forward, processing
    /// any received packets and generating packets to send.
    ///
    /// # Returns
    ///
    /// `true` if any work was done (packets processed or generated)
    pub fn poll(&mut self) -> bool {
        let timestamp = Self::current_timestamp();
        // Log RX queue status before poll
        let rx_count_before = self.queue.rx_queue_len();
        let result = self.iface.poll(timestamp, &mut self.device, &mut self.sockets);

        if result {
            debug!("smoltcp poll: work done (had {} RX packets)", rx_count_before);
        }

        result
    }

    /// Get the delay until the next poll is needed
    ///
    /// This enables event-driven polling instead of fixed-interval polling.
    /// The returned duration indicates how long the caller can wait before
    /// the next `poll()` call is required.
    ///
    /// # Returns
    ///
    /// - `Some(duration)` - Wait this long before the next poll
    /// - `None` - Poll immediately (there's pending work)
    #[must_use]
    pub fn poll_delay(&mut self) -> Option<Duration> {
        let timestamp = Self::current_timestamp();
        self.iface.poll_delay(timestamp, &self.sockets).map(|d| {
            Duration::from_micros(d.total_micros())
        })
    }

    /// Create a new TCP socket and return its handle
    ///
    /// # Arguments
    ///
    /// * `rx_buffer_size` - Size of the receive buffer
    /// * `tx_buffer_size` - Size of the transmit buffer
    ///
    /// # Returns
    ///
    /// The socket handle for the new TCP socket, or `None` if the socket
    /// set is full.
    pub fn create_tcp_socket(
        &mut self,
        rx_buffer_size: usize,
        tx_buffer_size: usize,
    ) -> Option<SocketHandle> {
        if self.sockets.iter().count() >= MAX_SOCKETS {
            warn!("Socket set full, cannot create new TCP socket");
            return None;
        }

        let rx_buffer = SocketBuffer::new(vec![0u8; rx_buffer_size]);
        let tx_buffer = SocketBuffer::new(vec![0u8; tx_buffer_size]);
        let mut socket = TcpSocket::new(rx_buffer, tx_buffer);

        // Configure MSS to fit within WireGuard MTU
        // MSS = MTU (1420) - IP header (20) - TCP header (20) = 1380
        // Note: smoltcp determines MSS from interface MTU, but we disable
        // Nagle's algorithm for lower latency in tunnel scenarios.
        socket.set_nagle_enabled(false);

        let handle = self.sockets.add(socket);

        debug!("Created TCP socket: handle={:?}, MSS={}", handle, TCP_MSS);
        Some(handle)
    }

    /// Create a new TCP socket with default buffer sizes
    ///
    /// # Returns
    ///
    /// The socket handle for the new TCP socket, or `None` if the socket
    /// set is full.
    pub fn create_tcp_socket_default(&mut self) -> Option<SocketHandle> {
        self.create_tcp_socket(DEFAULT_TCP_RX_BUFFER, DEFAULT_TCP_TX_BUFFER)
    }

    /// Get a mutable reference to a TCP socket
    ///
    /// # Arguments
    ///
    /// * `handle` - The socket handle
    ///
    /// # Returns
    ///
    /// A mutable reference to the TCP socket
    pub fn get_tcp_socket_mut(&mut self, handle: SocketHandle) -> &mut TcpSocket<'static> {
        self.sockets.get_mut::<TcpSocket>(handle)
    }

    /// Get an immutable reference to a TCP socket
    ///
    /// # Arguments
    ///
    /// * `handle` - The socket handle
    ///
    /// # Returns
    ///
    /// An immutable reference to the TCP socket
    pub fn get_tcp_socket(&self, handle: SocketHandle) -> &TcpSocket<'static> {
        self.sockets.get::<TcpSocket>(handle)
    }

    /// Remove a socket from the socket set
    ///
    /// # Arguments
    ///
    /// * `handle` - The socket handle to remove
    pub fn remove_socket(&mut self, handle: SocketHandle) {
        debug!("Removing socket: handle={:?}", handle);
        self.sockets.remove(handle);
    }

    /// Get the state of a TCP socket
    ///
    /// # Arguments
    ///
    /// * `handle` - The socket handle
    ///
    /// # Returns
    ///
    /// The current TCP state of the socket
    #[must_use]
    pub fn tcp_socket_state(&self, handle: SocketHandle) -> TcpState {
        self.get_tcp_socket(handle).state()
    }

    /// Check if a TCP socket can send data
    ///
    /// # Arguments
    ///
    /// * `handle` - The socket handle
    ///
    /// # Returns
    ///
    /// `true` if the socket can accept data for sending
    #[must_use]
    pub fn tcp_can_send(&self, handle: SocketHandle) -> bool {
        self.get_tcp_socket(handle).can_send()
    }

    /// Check if a TCP socket can receive data
    ///
    /// # Arguments
    ///
    /// * `handle` - The socket handle
    ///
    /// # Returns
    ///
    /// `true` if the socket has data available to read
    #[must_use]
    pub fn tcp_can_recv(&self, handle: SocketHandle) -> bool {
        self.get_tcp_socket(handle).can_recv()
    }

    /// Get the number of active sockets
    #[must_use]
    pub fn socket_count(&self) -> usize {
        self.sockets.iter().count()
    }

    /// Get a reference to the packet queue
    #[must_use]
    pub fn queue(&self) -> &Arc<TunnelPacketQueue> {
        &self.queue
    }

    /// Get the interface context for socket operations
    ///
    /// The context is needed for socket operations like `connect()`.
    /// This returns a mutable reference to the interface's inner context.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let socket = bridge.get_tcp_socket_mut(handle);
    /// socket.connect(bridge.iface_context(), remote_addr, local_port)?;
    /// ```
    pub fn iface_context(&mut self) -> &mut smoltcp::iface::Context {
        self.iface.context()
    }

    /// Connect a TCP socket to a remote endpoint
    ///
    /// This method handles the borrow checker constraints by accessing both
    /// the socket and the interface context within the same method.
    ///
    /// # Arguments
    ///
    /// * `handle` - The socket handle
    /// * `remote_addr` - The remote IP address
    /// * `remote_port` - The remote port
    /// * `local_port` - The local port to use
    ///
    /// # Errors
    ///
    /// Returns an error if the connection cannot be initiated
    pub fn tcp_connect(
        &mut self,
        handle: SocketHandle,
        remote_addr: IpAddress,
        remote_port: u16,
        local_port: u16,
    ) -> Result<(), smoltcp::socket::tcp::ConnectError> {
        let cx = self.iface.context();
        let socket = self.sockets.get_mut::<TcpSocket>(handle);
        socket.connect(cx, (remote_addr, remote_port), local_port)
    }

    /// Start listening on a TCP socket
    ///
    /// This puts the socket into the LISTEN state, ready to accept incoming
    /// connections on the specified port.
    ///
    /// # Arguments
    ///
    /// * `handle` - The socket handle
    /// * `port` - The local port to listen on
    ///
    /// # Errors
    ///
    /// Returns an error if the socket cannot be put into the listen state
    ///
    /// # Example
    ///
    /// ```ignore
    /// let handle = bridge.create_tcp_socket_default().unwrap();
    /// bridge.tcp_listen(handle, 36000)?;
    /// // Socket is now listening for connections
    /// ```
    pub fn tcp_listen(
        &mut self,
        handle: SocketHandle,
        port: u16,
    ) -> Result<(), smoltcp::socket::tcp::ListenError> {
        let socket = self.sockets.get_mut::<TcpSocket>(handle);
        socket.listen(port)
    }

    /// Check if a TCP socket is in the listen state
    ///
    /// # Arguments
    ///
    /// * `handle` - The socket handle
    ///
    /// # Returns
    ///
    /// `true` if the socket is listening for connections
    #[must_use]
    pub fn tcp_is_listening(&self, handle: SocketHandle) -> bool {
        self.get_tcp_socket(handle).state() == TcpState::Listen
    }

    /// Check if a TCP socket has an active connection
    ///
    /// # Arguments
    ///
    /// * `handle` - The socket handle
    ///
    /// # Returns
    ///
    /// `true` if the socket has an established connection
    #[must_use]
    pub fn tcp_is_active(&self, handle: SocketHandle) -> bool {
        self.get_tcp_socket(handle).is_active()
    }

    /// Get the remote endpoint of a TCP socket
    ///
    /// # Arguments
    ///
    /// * `handle` - The socket handle
    ///
    /// # Returns
    ///
    /// The remote endpoint if the socket is connected, or `None`
    #[must_use]
    pub fn tcp_remote_endpoint(&self, handle: SocketHandle) -> Option<smoltcp::wire::IpEndpoint> {
        self.get_tcp_socket(handle).remote_endpoint()
    }

    /// Close a TCP socket gracefully
    ///
    /// This initiates a graceful shutdown of the TCP connection by sending FIN.
    ///
    /// # Arguments
    ///
    /// * `handle` - The socket handle
    pub fn tcp_close(&mut self, handle: SocketHandle) {
        let socket = self.sockets.get_mut::<TcpSocket>(handle);
        socket.close();
    }

    /// Abort a TCP connection
    ///
    /// This immediately closes the connection by sending RST, without waiting
    /// for graceful shutdown.
    ///
    /// # Arguments
    ///
    /// * `handle` - The socket handle
    pub fn tcp_abort(&mut self, handle: SocketHandle) {
        let socket = self.sockets.get_mut::<TcpSocket>(handle);
        socket.abort();
    }

    // =========================================================================
    // UDP Socket Methods
    // =========================================================================

    /// Create a new UDP socket with default buffer sizes
    ///
    /// # Returns
    ///
    /// The socket handle for the new UDP socket, or `None` if the socket
    /// set is full.
    pub fn create_udp_socket(&mut self) -> Option<SocketHandle> {
        self.create_udp_socket_with_buffer(
            DEFAULT_UDP_RX_BUFFER,
            DEFAULT_UDP_TX_BUFFER,
            DEFAULT_UDP_PACKET_META,
        )
    }

    /// Create a new UDP socket with custom buffer sizes
    ///
    /// # Arguments
    ///
    /// * `rx_buffer_size` - Size of the receive buffer
    /// * `tx_buffer_size` - Size of the transmit buffer
    /// * `packet_meta_count` - Number of packet metadata entries for each buffer
    ///
    /// # Returns
    ///
    /// The socket handle for the new UDP socket, or `None` if the socket
    /// set is full.
    pub fn create_udp_socket_with_buffer(
        &mut self,
        rx_buffer_size: usize,
        tx_buffer_size: usize,
        packet_meta_count: usize,
    ) -> Option<SocketHandle> {
        if self.sockets.iter().count() >= MAX_SOCKETS {
            warn!("Socket set full, cannot create new UDP socket");
            return None;
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
        debug!("Created UDP socket: handle={:?}", handle);
        Some(handle)
    }

    /// Bind a UDP socket to a local port
    ///
    /// # Arguments
    ///
    /// * `handle` - The socket handle
    /// * `port` - The local port to bind to
    ///
    /// # Errors
    ///
    /// Returns an error if the socket cannot be bound to the specified port
    pub fn udp_bind(
        &mut self,
        handle: SocketHandle,
        port: u16,
    ) -> Result<(), smoltcp::socket::udp::BindError> {
        let socket = self.sockets.get_mut::<UdpSocket>(handle);
        socket.bind(port)
    }

    /// Send data through a UDP socket
    ///
    /// # Arguments
    ///
    /// * `handle` - The socket handle
    /// * `data` - The data to send
    /// * `remote` - The remote endpoint to send to
    ///
    /// # Errors
    ///
    /// Returns an error if the data cannot be sent
    pub fn udp_send(
        &mut self,
        handle: SocketHandle,
        data: &[u8],
        remote: IpEndpoint,
    ) -> Result<(), UdpSendError> {
        let socket = self.sockets.get_mut::<UdpSocket>(handle);
        socket.send_slice(data, remote)
    }

    /// Receive data from a UDP socket
    ///
    /// # Arguments
    ///
    /// * `handle` - The socket handle
    ///
    /// # Returns
    ///
    /// A tuple of (data, remote endpoint) on success
    ///
    /// # Errors
    ///
    /// Returns an error if no data is available or the socket is not bound
    pub fn udp_recv(&mut self, handle: SocketHandle) -> Result<(Vec<u8>, IpEndpoint), UdpRecvError> {
        let socket = self.sockets.get_mut::<UdpSocket>(handle);
        let (data, metadata) = socket.recv()?;
        let data_vec: Vec<u8> = data.to_vec();
        Ok((data_vec, metadata.endpoint))
    }

    /// Check if a UDP socket can send
    ///
    /// # Arguments
    ///
    /// * `handle` - The socket handle
    ///
    /// # Returns
    ///
    /// `true` if the socket can accept data for sending
    #[must_use]
    pub fn udp_can_send(&self, handle: SocketHandle) -> bool {
        self.sockets.get::<UdpSocket>(handle).can_send()
    }

    /// Check if a UDP socket can receive (has pending data)
    ///
    /// # Arguments
    ///
    /// * `handle` - The socket handle
    ///
    /// # Returns
    ///
    /// `true` if the socket has data available to read
    #[must_use]
    pub fn udp_can_recv(&self, handle: SocketHandle) -> bool {
        self.sockets.get::<UdpSocket>(handle).can_recv()
    }

    /// Get a mutable reference to a UDP socket
    ///
    /// # Arguments
    ///
    /// * `handle` - The socket handle
    ///
    /// # Returns
    ///
    /// A mutable reference to the UDP socket
    pub fn get_udp_socket_mut(&mut self, handle: SocketHandle) -> &mut UdpSocket<'static> {
        self.sockets.get_mut::<UdpSocket>(handle)
    }

    /// Get an immutable reference to a UDP socket
    ///
    /// # Arguments
    ///
    /// * `handle` - The socket handle
    ///
    /// # Returns
    ///
    /// An immutable reference to the UDP socket
    #[must_use]
    pub fn get_udp_socket(&self, handle: SocketHandle) -> &UdpSocket<'static> {
        self.sockets.get::<UdpSocket>(handle)
    }

    /// Check if a UDP socket is open (bound)
    ///
    /// # Arguments
    ///
    /// * `handle` - The socket handle
    ///
    /// # Returns
    ///
    /// `true` if the socket is bound and open
    #[must_use]
    pub fn udp_is_open(&self, handle: SocketHandle) -> bool {
        self.sockets.get::<UdpSocket>(handle).is_open()
    }

    /// Close a UDP socket
    ///
    /// # Arguments
    ///
    /// * `handle` - The socket handle
    pub fn udp_close(&mut self, handle: SocketHandle) {
        let socket = self.sockets.get_mut::<UdpSocket>(handle);
        socket.close();
    }

    // =========================================================================
    // Internal Methods
    // =========================================================================

    /// Get current timestamp for smoltcp
    ///
    /// Uses a monotonic clock relative to process start time, which is more
    /// appropriate for TCP timers than absolute wall-clock time. This avoids
    /// issues with system time adjustments (NTP, manual changes, etc.).
    fn current_timestamp() -> SmoltcpInstant {
        /// Process start time for monotonic timestamp calculation
        static START_TIME: OnceLock<Instant> = OnceLock::new();

        let start = START_TIME.get_or_init(Instant::now);
        let millis = start.elapsed().as_millis() as i64;
        SmoltcpInstant::from_millis(millis)
    }
}

impl std::fmt::Debug for SmoltcpBridge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SmoltcpBridge")
            .field("local_ip", &self.local_ip)
            .field("mtu", &self.mtu)
            .field("socket_count", &self.socket_count())
            .field("rx_queue_len", &self.queue.rx_queue_len())
            .field("tx_queue_len", &self.queue.tx_queue_len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bridge_new() {
        let bridge = SmoltcpBridge::new(Ipv4Addr::new(10, 200, 200, 2), 1420);
        assert_eq!(bridge.local_ip(), Ipv4Addr::new(10, 200, 200, 2));
        assert_eq!(bridge.mtu(), 1420);
        assert_eq!(bridge.socket_count(), 0);
    }

    #[test]
    fn test_bridge_with_default_mtu() {
        let bridge = SmoltcpBridge::with_default_mtu(Ipv4Addr::new(10, 200, 200, 2));
        assert_eq!(bridge.mtu(), DEFAULT_WG_MTU);
    }

    #[test]
    fn test_bridge_feed_rx_packet() {
        let bridge = SmoltcpBridge::new(Ipv4Addr::new(10, 200, 200, 2), 1420);

        assert!(!bridge.has_rx_packets());
        assert!(bridge.feed_rx_packet(vec![1, 2, 3, 4]));
        assert!(bridge.has_rx_packets());
    }

    #[test]
    fn test_bridge_drain_tx_packets() {
        let bridge = SmoltcpBridge::new(Ipv4Addr::new(10, 200, 200, 2), 1420);

        // Initially no TX packets
        assert!(!bridge.has_tx_packets());
        assert!(bridge.drain_tx_packets().is_empty());

        // Push some packets to TX queue directly (simulating smoltcp output)
        bridge.queue.push_tx(vec![1, 2, 3]);
        bridge.queue.push_tx(vec![4, 5, 6]);

        assert!(bridge.has_tx_packets());

        let packets = bridge.drain_tx_packets();
        assert_eq!(packets.len(), 2);
        assert_eq!(packets[0], vec![1, 2, 3]);
        assert_eq!(packets[1], vec![4, 5, 6]);

        // Queue should be empty now
        assert!(!bridge.has_tx_packets());
    }

    #[test]
    fn test_bridge_create_tcp_socket() {
        let mut bridge = SmoltcpBridge::new(Ipv4Addr::new(10, 200, 200, 2), 1420);

        assert_eq!(bridge.socket_count(), 0);

        let handle = bridge.create_tcp_socket_default();
        assert!(handle.is_some());
        assert_eq!(bridge.socket_count(), 1);

        // Socket should be in Closed state initially
        let state = bridge.tcp_socket_state(handle.unwrap());
        assert_eq!(state, TcpState::Closed);
    }

    #[test]
    fn test_bridge_remove_socket() {
        let mut bridge = SmoltcpBridge::new(Ipv4Addr::new(10, 200, 200, 2), 1420);

        let handle = bridge.create_tcp_socket_default().unwrap();
        assert_eq!(bridge.socket_count(), 1);

        bridge.remove_socket(handle);
        assert_eq!(bridge.socket_count(), 0);
    }

    #[test]
    fn test_bridge_max_sockets() {
        let mut bridge = SmoltcpBridge::new(Ipv4Addr::new(10, 200, 200, 2), 1420);

        // Create max sockets using smaller buffers to speed up test
        // (MAX_SOCKETS is 1024, so we use minimal buffer sizes)
        for _ in 0..MAX_SOCKETS {
            assert!(bridge.create_tcp_socket(1024, 1024).is_some());
        }

        // Next should fail
        assert!(bridge.create_tcp_socket(1024, 1024).is_none());
    }

    #[test]
    fn test_bridge_poll() {
        let mut bridge = SmoltcpBridge::new(Ipv4Addr::new(10, 200, 200, 2), 1420);

        // Poll with no packets should work
        let _result = bridge.poll();

        // Poll delay should return something
        let delay = bridge.poll_delay();
        // Delay can be Some or None depending on state
        drop(delay);
    }

    #[test]
    fn test_bridge_debug() {
        let bridge = SmoltcpBridge::new(Ipv4Addr::new(10, 200, 200, 2), 1420);
        let debug_str = format!("{:?}", bridge);
        assert!(debug_str.contains("SmoltcpBridge"));
        assert!(debug_str.contains("10.200.200.2"));
    }

    #[test]
    fn test_bridge_queue_reference() {
        let bridge = SmoltcpBridge::new(Ipv4Addr::new(10, 200, 200, 2), 1420);
        let queue = bridge.queue();

        // Should be able to push through the queue reference
        queue.push_tx(vec![1, 2, 3]);
        assert!(bridge.has_tx_packets());
    }

    #[test]
    fn test_bridge_tcp_listen() {
        let mut bridge = SmoltcpBridge::new(Ipv4Addr::new(10, 200, 200, 2), 1420);

        let handle = bridge.create_tcp_socket_default().unwrap();
        assert!(!bridge.tcp_is_listening(handle));

        // Start listening
        let result = bridge.tcp_listen(handle, 36000);
        assert!(result.is_ok());
        assert!(bridge.tcp_is_listening(handle));
    }

    #[test]
    fn test_bridge_tcp_is_active() {
        let mut bridge = SmoltcpBridge::new(Ipv4Addr::new(10, 200, 200, 2), 1420);

        let handle = bridge.create_tcp_socket_default().unwrap();

        // New socket should not be active
        assert!(!bridge.tcp_is_active(handle));
    }

    #[test]
    fn test_bridge_tcp_remote_endpoint() {
        let mut bridge = SmoltcpBridge::new(Ipv4Addr::new(10, 200, 200, 2), 1420);

        let handle = bridge.create_tcp_socket_default().unwrap();

        // Socket without connection has no remote endpoint
        assert!(bridge.tcp_remote_endpoint(handle).is_none());
    }

    #[test]
    fn test_bridge_tcp_close() {
        let mut bridge = SmoltcpBridge::new(Ipv4Addr::new(10, 200, 200, 2), 1420);

        let handle = bridge.create_tcp_socket_default().unwrap();

        // Close should not panic even on closed socket
        bridge.tcp_close(handle);

        // State should still be closed (already was)
        assert_eq!(bridge.tcp_socket_state(handle), TcpState::Closed);
    }

    #[test]
    fn test_bridge_tcp_abort() {
        let mut bridge = SmoltcpBridge::new(Ipv4Addr::new(10, 200, 200, 2), 1420);

        let handle = bridge.create_tcp_socket_default().unwrap();

        // Start listening first
        bridge.tcp_listen(handle, 36000).unwrap();
        assert!(bridge.tcp_is_listening(handle));

        // Abort should reset the socket
        bridge.tcp_abort(handle);

        // State should be closed after abort
        assert_eq!(bridge.tcp_socket_state(handle), TcpState::Closed);
    }

    // =========================================================================
    // UDP Socket Tests
    // =========================================================================

    #[test]
    fn test_bridge_create_udp_socket() {
        let mut bridge = SmoltcpBridge::new(Ipv4Addr::new(10, 200, 200, 2), 1420);

        let handle = bridge.create_udp_socket();
        assert!(handle.is_some());
        assert_eq!(bridge.socket_count(), 1);
    }

    #[test]
    fn test_bridge_udp_bind() {
        let mut bridge = SmoltcpBridge::new(Ipv4Addr::new(10, 200, 200, 2), 1420);

        let handle = bridge.create_udp_socket().unwrap();
        let result = bridge.udp_bind(handle, 12345);
        assert!(result.is_ok());
        assert!(bridge.udp_is_open(handle));
    }

    #[test]
    fn test_bridge_udp_close() {
        let mut bridge = SmoltcpBridge::new(Ipv4Addr::new(10, 200, 200, 2), 1420);

        let handle = bridge.create_udp_socket().unwrap();
        bridge.udp_bind(handle, 12345).unwrap();
        assert!(bridge.udp_is_open(handle));

        bridge.udp_close(handle);
        assert!(!bridge.udp_is_open(handle));
    }

    #[test]
    fn test_bridge_udp_can_send_recv() {
        let mut bridge = SmoltcpBridge::new(Ipv4Addr::new(10, 200, 200, 2), 1420);

        let handle = bridge.create_udp_socket().unwrap();
        bridge.udp_bind(handle, 12345).unwrap();

        // Bound socket should be able to send
        assert!(bridge.udp_can_send(handle));
        // No data received yet
        assert!(!bridge.udp_can_recv(handle));
    }

    #[test]
    fn test_bridge_max_sockets_udp() {
        let mut bridge = SmoltcpBridge::new(Ipv4Addr::new(10, 200, 200, 2), 1420);

        // Create max sockets (mix of TCP and UDP) using smaller buffers
        for i in 0..MAX_SOCKETS {
            if i % 2 == 0 {
                assert!(bridge.create_tcp_socket(1024, 1024).is_some());
            } else {
                assert!(bridge.create_udp_socket_with_buffer(1024, 1024, 8).is_some());
            }
        }

        // Next should fail (either type)
        assert!(bridge.create_tcp_socket(1024, 1024).is_none());
        assert!(bridge.create_udp_socket_with_buffer(1024, 1024, 8).is_none());
    }

    #[test]
    fn test_bridge_udp_socket_accessors() {
        let mut bridge = SmoltcpBridge::new(Ipv4Addr::new(10, 200, 200, 2), 1420);

        let handle = bridge.create_udp_socket().unwrap();
        bridge.udp_bind(handle, 54321).unwrap();

        // Test immutable accessor
        {
            let socket = bridge.get_udp_socket(handle);
            assert!(socket.is_open());
        }

        // Test mutable accessor
        {
            let socket = bridge.get_udp_socket_mut(handle);
            socket.close();
        }

        assert!(!bridge.udp_is_open(handle));
    }

    #[test]
    fn test_tcp_mss_constant() {
        // Verify the TCP_MSS constant is correctly calculated
        // MSS = MTU (1420) - IP header (20) - TCP header (20) = 1380
        assert_eq!(TCP_MSS, 1380);
    }
}
