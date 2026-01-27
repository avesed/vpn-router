//! PacketChannel - AsyncRead/AsyncWrite adapter for ipstack
//!
//! This module provides an adapter that implements `AsyncRead` and `AsyncWrite`
//! to bridge between the forwarder's packet-based interface and ipstack's
//! stream-based interface.
//!
//! # Design
//!
//! ipstack requires a type that implements both `AsyncRead` and `AsyncWrite`.
//! This adapter converts between:
//! - Incoming IP packets (via mpsc receiver) -> AsyncRead
//! - Outgoing IP packets (via mpsc sender) -> AsyncWrite
//!
//! # Usage
//!
//! ```ignore
//! use rust_router::ingress::ipstack_bridge::PacketChannel;
//!
//! // Create a packet channel with associated sender/receiver
//! let (channel, packet_tx, packet_rx) = PacketChannel::create_pair(1024);
//!
//! // Use packet_tx to inject IP packets into ipstack
//! packet_tx.send(ip_packet).await?;
//!
//! // Use packet_rx to receive IP packets from ipstack for WireGuard
//! let outgoing = packet_rx.recv().await?;
//!
//! // The channel itself is passed to ipstack::IpStack::new()
//! ```

use bytes::BytesMut;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use tokio_util::sync::PollSender;

/// PacketChannel bridges IP packet channels to AsyncRead/AsyncWrite streams.
///
/// ipstack requires a type that implements both `AsyncRead` and `AsyncWrite`.
/// This adapter converts between:
/// - Incoming IP packets (via mpsc receiver) -> AsyncRead
/// - Outgoing IP packets (via mpsc sender) -> AsyncWrite
pub struct PacketChannel {
    /// Receiver for incoming IP packets from WireGuard
    rx: mpsc::Receiver<BytesMut>,
    /// Sender for outgoing IP packets to WireGuard (wrapped for polling)
    tx: PollSender<BytesMut>,
    /// Buffer for partially read packet
    read_buf: Option<BytesMut>,
    /// Current read position in buffer
    read_pos: usize,
}

impl PacketChannel {
    /// Create a new PacketChannel with the given channels.
    ///
    /// # Arguments
    ///
    /// * `rx` - Receiver for incoming IP packets from WireGuard
    /// * `tx` - Sender for outgoing IP packets to WireGuard
    pub fn new(rx: mpsc::Receiver<BytesMut>, tx: mpsc::Sender<BytesMut>) -> Self {
        Self {
            rx,
            tx: PollSender::new(tx),
            read_buf: None,
            read_pos: 0,
        }
    }

    /// Create a pair of channels and return (PacketChannel, sender, receiver).
    ///
    /// - Use `sender` to inject IP packets into ipstack
    /// - Use `receiver` to get IP packets from ipstack for sending to WireGuard
    ///
    /// # Arguments
    ///
    /// * `buffer_size` - Size of the mpsc channel buffers
    ///
    /// # Returns
    ///
    /// A tuple of:
    /// - `PacketChannel` - The channel to pass to ipstack
    /// - `Sender<BytesMut>` - Use this to inject IP packets into ipstack
    /// - `Receiver<BytesMut>` - Use this to receive IP packets from ipstack
    pub fn create_pair(
        buffer_size: usize,
    ) -> (Self, mpsc::Sender<BytesMut>, mpsc::Receiver<BytesMut>) {
        let (in_tx, in_rx) = mpsc::channel(buffer_size);
        let (out_tx, out_rx) = mpsc::channel(buffer_size);
        (Self::new(in_rx, out_tx), in_tx, out_rx)
    }
}

impl AsyncRead for PacketChannel {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;

        // If we have buffered data, return it first
        if let Some(ref packet) = this.read_buf {
            let remaining = packet.len() - this.read_pos;
            let to_copy = remaining.min(buf.remaining());
            buf.put_slice(&packet[this.read_pos..this.read_pos + to_copy]);
            this.read_pos += to_copy;

            // If we've consumed the entire packet, clear the buffer
            if this.read_pos >= packet.len() {
                this.read_buf = None;
                this.read_pos = 0;
            }
            return Poll::Ready(Ok(()));
        }

        // Try to receive the next packet
        match Pin::new(&mut this.rx).poll_recv(cx) {
            Poll::Ready(Some(packet)) => {
                let to_copy = packet.len().min(buf.remaining());
                buf.put_slice(&packet[..to_copy]);

                // If packet is larger than buf, save the rest
                if to_copy < packet.len() {
                    this.read_buf = Some(packet);
                    this.read_pos = to_copy;
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => {
                // Channel closed - return EOF
                Poll::Ready(Ok(()))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for PacketChannel {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;

        // Check if channel has capacity using PollSender
        match this.tx.poll_reserve(cx) {
            Poll::Ready(Ok(())) => {
                let packet = BytesMut::from(buf);
                let len = packet.len();
                // send_item cannot fail after successful reserve
                match this.tx.send_item(packet) {
                    Ok(()) => Poll::Ready(Ok(len)),
                    Err(_) => Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "packet channel closed",
                    ))),
                }
            }
            Poll::Ready(Err(_)) => {
                // Channel closed
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "packet channel closed",
                )))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // mpsc channel doesn't need flushing
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Dropping the sender will close the channel
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn test_packet_channel_roundtrip() {
        let (mut channel, tx, mut rx) = PacketChannel::create_pair(16);

        // Send a packet through the channel
        let packet = BytesMut::from(&b"hello world"[..]);
        tx.send(packet).await.unwrap();

        // Read it from the channel
        let mut buf = [0u8; 32];
        let n = channel.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello world");

        // Write a response
        channel.write_all(b"response").await.unwrap();

        // Receive it
        let response = rx.recv().await.unwrap();
        assert_eq!(&response[..], b"response");
    }

    #[tokio::test]
    async fn test_packet_channel_partial_read() {
        let (mut channel, tx, _rx) = PacketChannel::create_pair(16);

        // Send a large packet
        let packet = BytesMut::from(&b"hello world this is a longer message"[..]);
        tx.send(packet).await.unwrap();

        // Read in small chunks
        let mut buf = [0u8; 10];
        let n1 = channel.read(&mut buf).await.unwrap();
        assert_eq!(n1, 10);
        assert_eq!(&buf[..n1], b"hello worl");

        let n2 = channel.read(&mut buf).await.unwrap();
        assert_eq!(n2, 10);
        assert_eq!(&buf[..n2], b"d this is ");

        let n3 = channel.read(&mut buf).await.unwrap();
        assert_eq!(n3, 10);
        assert_eq!(&buf[..n3], b"a longer m");

        let n4 = channel.read(&mut buf).await.unwrap();
        assert_eq!(n4, 6);
        assert_eq!(&buf[..n4], b"essage");
    }

    #[tokio::test]
    async fn test_packet_channel_multiple_packets() {
        let (mut channel, tx, _rx) = PacketChannel::create_pair(16);

        // Send multiple packets
        tx.send(BytesMut::from(&b"packet1"[..])).await.unwrap();
        tx.send(BytesMut::from(&b"packet2"[..])).await.unwrap();

        // Read them
        let mut buf = [0u8; 32];
        let n1 = channel.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n1], b"packet1");

        let n2 = channel.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n2], b"packet2");
    }

    #[tokio::test]
    async fn test_packet_channel_closed_sender() {
        let (mut channel, tx, _rx) = PacketChannel::create_pair(16);

        // Close the sender
        drop(tx);

        // Read should return EOF (0 bytes)
        let mut buf = [0u8; 32];
        let n = channel.read(&mut buf).await.unwrap();
        assert_eq!(n, 0);
    }

    #[tokio::test]
    async fn test_packet_channel_closed_receiver() {
        let (mut channel, _tx, rx) = PacketChannel::create_pair(16);

        // Close the receiver
        drop(rx);

        // Write should fail
        let result = channel.write_all(b"test").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_packet_channel_flush_is_noop() {
        let (mut channel, _tx, _rx) = PacketChannel::create_pair(16);

        // Flush should succeed immediately
        let result = channel.flush().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_packet_channel_shutdown() {
        let (mut channel, _tx, _rx) = PacketChannel::create_pair(16);

        // Shutdown should succeed
        let result = channel.shutdown().await;
        assert!(result.is_ok());
    }
}
