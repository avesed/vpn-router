//! smoltcp device adapter for WireGuard tunnel
//!
//! This module provides a virtual network device that bridges smoltcp's TCP/IP
//! stack with the WireGuard tunnel. Packets are exchanged through in-memory
//! queues rather than real network interfaces.
//!
//! # Architecture
//!
//! ```text
//! +----------------+     +------------------+     +-------------------+
//! | smoltcp stack  | <-> | WgTunnelDevice   | <-> | UserspaceWgTunnel |
//! | (TCP/IP)       |     | (packet queues)  |     | (WireGuard)       |
//! +----------------+     +------------------+     +-------------------+
//! ```
//!
//! # Usage
//!
//! ```ignore
//! use rust_router::tunnel::smoltcp_device::{TunnelPacketQueue, WgTunnelDevice};
//!
//! // Create packet queue
//! let queue = TunnelPacketQueue::new();
//!
//! // Create device with 1420 MTU (standard WireGuard MTU)
//! let device = WgTunnelDevice::new(queue.clone(), 1420);
//!
//! // Feed packets from WireGuard tunnel
//! queue.push_rx(decrypted_packet);
//!
//! // Get packets to send through WireGuard tunnel
//! while let Some(packet) = queue.pop_tx() {
//!     tunnel.send(&packet).await?;
//! }
//! ```

use std::collections::VecDeque;
use std::sync::Arc;

use parking_lot::Mutex;
use smoltcp::phy::{Checksum, ChecksumCapabilities, Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::time::Instant as SmoltcpInstant;
use tracing::trace;

/// Default MTU for WireGuard tunnels
///
/// WireGuard typically uses 1420 bytes to account for the outer IP/UDP headers
/// and WireGuard encryption overhead when encapsulated in standard 1500 byte frames.
pub const DEFAULT_WG_MTU: usize = 1420;

/// Maximum packet queue depth to prevent unbounded memory growth
const MAX_QUEUE_DEPTH: usize = 256;

/// Packet queue for exchanging data between smoltcp and WireGuard tunnel
///
/// This queue holds packets in both directions:
/// - RX queue: Packets received from the WireGuard tunnel (decrypted IP packets)
/// - TX queue: Packets to be sent through the WireGuard tunnel (IP packets to encrypt)
///
/// # Thread Safety
///
/// The queue uses `parking_lot::Mutex` for efficient locking and is safe to share
/// across threads using `Arc<TunnelPacketQueue>`.
#[derive(Debug)]
pub struct TunnelPacketQueue {
    /// Packets received from the tunnel (to be processed by smoltcp)
    rx_queue: Mutex<VecDeque<Vec<u8>>>,
    /// Packets to be sent through the tunnel (produced by smoltcp)
    tx_queue: Mutex<VecDeque<Vec<u8>>>,
}

impl TunnelPacketQueue {
    /// Create a new empty packet queue
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            rx_queue: Mutex::new(VecDeque::new()),
            tx_queue: Mutex::new(VecDeque::new()),
        })
    }

    /// Push a packet received from the WireGuard tunnel into the RX queue
    ///
    /// This is called when a decrypted IP packet is received from the tunnel
    /// and needs to be processed by smoltcp.
    ///
    /// # Arguments
    ///
    /// * `packet` - The decrypted IP packet from the tunnel
    ///
    /// # Returns
    ///
    /// `true` if the packet was queued, `false` if the queue is full
    pub fn push_rx(&self, packet: Vec<u8>) -> bool {
        let mut queue = self.rx_queue.lock();
        if queue.len() >= MAX_QUEUE_DEPTH {
            trace!("RX queue full, dropping packet ({} bytes)", packet.len());
            return false;
        }
        trace!("Pushing {} byte packet to RX queue", packet.len());
        queue.push_back(packet);
        true
    }

    /// Pop a packet from the RX queue for smoltcp to process
    ///
    /// Called by the smoltcp device when receiving packets.
    pub fn pop_rx(&self) -> Option<Vec<u8>> {
        self.rx_queue.lock().pop_front()
    }

    /// Push a packet produced by smoltcp into the TX queue
    ///
    /// This is called by smoltcp when it wants to send an IP packet.
    /// The packet will be picked up and sent through the WireGuard tunnel.
    ///
    /// # Arguments
    ///
    /// * `packet` - The IP packet to send through the tunnel
    ///
    /// # Returns
    ///
    /// `true` if the packet was queued, `false` if the queue is full
    pub fn push_tx(&self, packet: Vec<u8>) -> bool {
        let mut queue = self.tx_queue.lock();
        if queue.len() >= MAX_QUEUE_DEPTH {
            trace!("TX queue full, dropping packet ({} bytes)", packet.len());
            return false;
        }
        trace!("Pushing {} byte packet to TX queue", packet.len());
        queue.push_back(packet);
        true
    }

    /// Pop a packet from the TX queue to send through the tunnel
    ///
    /// This is called by the bridge to get packets that smoltcp wants to send.
    pub fn pop_tx(&self) -> Option<Vec<u8>> {
        self.tx_queue.lock().pop_front()
    }

    /// Check if there are packets waiting to be transmitted
    #[must_use]
    pub fn has_tx_packets(&self) -> bool {
        !self.tx_queue.lock().is_empty()
    }

    /// Check if there are packets waiting to be received
    #[must_use]
    pub fn has_rx_packets(&self) -> bool {
        !self.rx_queue.lock().is_empty()
    }

    /// Get the current RX queue depth
    #[must_use]
    pub fn rx_queue_len(&self) -> usize {
        self.rx_queue.lock().len()
    }

    /// Get the current TX queue depth
    #[must_use]
    pub fn tx_queue_len(&self) -> usize {
        self.tx_queue.lock().len()
    }

    /// Clear both queues
    pub fn clear(&self) {
        self.rx_queue.lock().clear();
        self.tx_queue.lock().clear();
    }
}

impl Default for TunnelPacketQueue {
    fn default() -> Self {
        Self {
            rx_queue: Mutex::new(VecDeque::new()),
            tx_queue: Mutex::new(VecDeque::new()),
        }
    }
}

/// Virtual network device for smoltcp that bridges to WireGuard tunnel
///
/// This device implements smoltcp's `Device` trait using `Medium::Ip` since
/// WireGuard operates at the IP layer (no Ethernet framing).
///
/// # Example
///
/// ```ignore
/// let queue = TunnelPacketQueue::new();
/// let device = WgTunnelDevice::new(queue, 1420);
///
/// let mut iface = Interface::new(config, &mut device, smoltcp::time::Instant::now());
/// ```
pub struct WgTunnelDevice {
    /// Shared packet queue for RX/TX
    queue: Arc<TunnelPacketQueue>,
    /// Maximum transmission unit
    mtu: usize,
}

impl WgTunnelDevice {
    /// Create a new WireGuard tunnel device
    ///
    /// # Arguments
    ///
    /// * `queue` - Shared packet queue for exchanging data with the tunnel
    /// * `mtu` - Maximum transmission unit (typically 1420 for WireGuard)
    #[must_use]
    pub fn new(queue: Arc<TunnelPacketQueue>, mtu: usize) -> Self {
        Self { queue, mtu }
    }

    /// Get a reference to the packet queue
    #[must_use]
    pub fn queue(&self) -> &Arc<TunnelPacketQueue> {
        &self.queue
    }
}

impl Device for WgTunnelDevice {
    type RxToken<'a> = WgRxToken where Self: 'a;
    type TxToken<'a> = WgTxToken<'a> where Self: 'a;

    fn receive(&mut self, _timestamp: SmoltcpInstant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        // Check if we have a packet to receive
        if let Some(packet) = self.queue.pop_rx() {
            trace!("Device receive: {} bytes", packet.len());
            Some((
                WgRxToken { packet },
                WgTxToken { queue: &self.queue },
            ))
        } else {
            None
        }
    }

    fn transmit(&mut self, _timestamp: SmoltcpInstant) -> Option<Self::TxToken<'_>> {
        // Always allow transmission (queue handles overflow)
        Some(WgTxToken { queue: &self.queue })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();

        // WireGuard works at IP layer, no Ethernet framing
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;

        // smoltcp should compute checksums since we're a virtual device
        caps.checksum = ChecksumCapabilities::default();
        caps.checksum.ipv4 = Checksum::Tx;
        caps.checksum.tcp = Checksum::Tx;
        caps.checksum.udp = Checksum::Tx;
        caps.checksum.icmpv4 = Checksum::Tx;

        caps
    }
}

/// Receive token for reading a packet from the device
///
/// This token is consumed when smoltcp wants to process a received packet.
pub struct WgRxToken {
    packet: Vec<u8>,
}

impl RxToken for WgRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut packet = self.packet;
        trace!("RxToken consume: {} bytes", packet.len());
        f(&mut packet)
    }
}

/// Transmit token for sending a packet through the device
///
/// This token is consumed when smoltcp wants to send a packet.
pub struct WgTxToken<'a> {
    queue: &'a Arc<TunnelPacketQueue>,
}

impl<'a> TxToken for WgTxToken<'a> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        // Allocate buffer for the packet
        let mut buffer = vec![0u8; len];
        let result = f(&mut buffer);

        trace!("TxToken consume: {} bytes", len);

        // Push the packet to the TX queue
        self.queue.push_tx(buffer);

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_queue_new() {
        let queue = TunnelPacketQueue::new();
        assert_eq!(queue.rx_queue_len(), 0);
        assert_eq!(queue.tx_queue_len(), 0);
        assert!(!queue.has_rx_packets());
        assert!(!queue.has_tx_packets());
    }

    #[test]
    fn test_packet_queue_rx() {
        let queue = TunnelPacketQueue::new();

        // Push some packets
        assert!(queue.push_rx(vec![1, 2, 3]));
        assert!(queue.push_rx(vec![4, 5, 6]));

        assert_eq!(queue.rx_queue_len(), 2);
        assert!(queue.has_rx_packets());

        // Pop in FIFO order
        assert_eq!(queue.pop_rx(), Some(vec![1, 2, 3]));
        assert_eq!(queue.pop_rx(), Some(vec![4, 5, 6]));
        assert_eq!(queue.pop_rx(), None);
    }

    #[test]
    fn test_packet_queue_tx() {
        let queue = TunnelPacketQueue::new();

        // Push some packets
        assert!(queue.push_tx(vec![1, 2, 3]));
        assert!(queue.push_tx(vec![4, 5, 6]));

        assert_eq!(queue.tx_queue_len(), 2);
        assert!(queue.has_tx_packets());

        // Pop in FIFO order
        assert_eq!(queue.pop_tx(), Some(vec![1, 2, 3]));
        assert_eq!(queue.pop_tx(), Some(vec![4, 5, 6]));
        assert_eq!(queue.pop_tx(), None);
    }

    #[test]
    fn test_packet_queue_clear() {
        let queue = TunnelPacketQueue::new();

        queue.push_rx(vec![1, 2, 3]);
        queue.push_tx(vec![4, 5, 6]);

        queue.clear();

        assert_eq!(queue.rx_queue_len(), 0);
        assert_eq!(queue.tx_queue_len(), 0);
    }

    #[test]
    fn test_packet_queue_overflow() {
        let queue = TunnelPacketQueue::new();

        // Fill the queue to max
        for i in 0..MAX_QUEUE_DEPTH {
            assert!(queue.push_rx(vec![i as u8]), "Failed to push packet {i}");
        }

        // Next push should fail
        assert!(!queue.push_rx(vec![255]));

        // Queue length should be at max
        assert_eq!(queue.rx_queue_len(), MAX_QUEUE_DEPTH);
    }

    #[test]
    fn test_device_capabilities() {
        let queue = TunnelPacketQueue::new();
        let device = WgTunnelDevice::new(queue, 1420);

        let caps = device.capabilities();
        assert_eq!(caps.medium, Medium::Ip);
        assert_eq!(caps.max_transmission_unit, 1420);
    }

    #[test]
    fn test_device_receive() {
        let queue = TunnelPacketQueue::new();
        let mut device = WgTunnelDevice::new(queue.clone(), 1420);
        let timestamp = SmoltcpInstant::from_millis(0);

        // No packets, receive should return None
        assert!(device.receive(timestamp).is_none());

        // Add a packet
        queue.push_rx(vec![1, 2, 3, 4]);

        // Now receive should return tokens
        let (rx, _tx) = device.receive(timestamp).expect("Should have packet");

        // Consume the RX token
        let result = rx.consume(|buf| {
            assert_eq!(buf, &[1, 2, 3, 4]);
            buf.len()
        });
        assert_eq!(result, 4);
    }

    #[test]
    fn test_device_transmit() {
        let queue = TunnelPacketQueue::new();
        let mut device = WgTunnelDevice::new(queue.clone(), 1420);
        let timestamp = SmoltcpInstant::from_millis(0);

        // Transmit should always return a token
        let tx = device.transmit(timestamp).expect("Should get TX token");

        // Consume the TX token to send a packet
        tx.consume(4, |buf| {
            buf.copy_from_slice(&[5, 6, 7, 8]);
        });

        // Packet should be in the TX queue
        assert_eq!(queue.pop_tx(), Some(vec![5, 6, 7, 8]));
    }

    #[test]
    fn test_device_queue_reference() {
        let queue = TunnelPacketQueue::new();
        let device = WgTunnelDevice::new(queue.clone(), 1420);

        // Device should hold reference to same queue
        assert!(Arc::ptr_eq(&queue, device.queue()));
    }
}
