//! VLESS stream wrapper for deferred response header handling
//!
//! This module provides `VlessStream`, a wrapper that handles the VLESS protocol's
//! "deferred response" behavior where the server only sends the response header
//! after receiving data from the target.
//!
//! # Problem
//!
//! In VLESS protocol:
//! 1. Client sends request header (UUID, destination, etc.)
//! 2. Server connects to the target
//! 3. Server waits for data from target before sending response header
//!
//! This means we cannot wait for the response header during the handshake phase,
//! as it would block indefinitely for protocols like HTTP where the client must
//! send data first.
//!
//! # Solution
//!
//! `VlessStream` wraps the underlying transport stream and:
//! 1. Allows immediate use after sending the request header
//! 2. On first read, consumes the VLESS response header (version + addons)
//! 3. Returns actual data from subsequent reads
//!
//! # Wire Format
//!
//! Response header:
//! ```text
//! +--------+--------+----------+
//! | Version| AddLen |  Addons  |
//! +--------+--------+----------+
//! |   1B   |   1B   | Variable |
//! +--------+--------+----------+
//! ```

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};

use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::{debug, trace, warn};

use crate::transport::TransportStream;
use crate::vless::{VlessError, VLESS_VERSION};

/// Maximum size of VLESS response header (version + addons length + max addons)
const MAX_RESPONSE_HEADER_SIZE: usize = 258; // 1 + 1 + 256

/// A wrapper stream that handles VLESS deferred response header consumption
///
/// This stream transparently consumes the VLESS response header on the first read,
/// then forwards all subsequent I/O directly to the underlying stream.
pub struct VlessStream {
    /// The underlying transport stream
    inner: TransportStream,

    /// Whether the response header has been consumed
    header_consumed: AtomicBool,

    /// Buffer for reading the response header and any extra data
    /// This is used when the first read returns more data than just the header
    read_buffer: BytesMut,

    /// How many bytes of read_buffer have been consumed
    buffer_consumed: usize,
}

impl VlessStream {
    /// Create a new VlessStream wrapping the given transport stream
    ///
    /// The request header should already have been sent on this stream.
    /// The response header will be consumed on the first read.
    #[must_use]
    pub fn new(inner: TransportStream) -> Self {
        Self {
            inner,
            header_consumed: AtomicBool::new(false),
            read_buffer: BytesMut::with_capacity(MAX_RESPONSE_HEADER_SIZE),
            buffer_consumed: 0,
        }
    }

    /// Check if the response header has been consumed
    #[must_use]
    pub fn is_header_consumed(&self) -> bool {
        self.header_consumed.load(Ordering::Acquire)
    }

    /// Consume the VLESS response header from the buffer
    ///
    /// Returns the number of bytes consumed, or an error if the header is invalid.
    fn consume_header(&mut self) -> Result<usize, VlessError> {
        let data = &self.read_buffer[self.buffer_consumed..];

        if data.is_empty() {
            return Err(VlessError::InvalidHeader);
        }

        // Check version (1 byte)
        let version = data[0];
        if version != VLESS_VERSION {
            warn!("Invalid VLESS response version: {} (expected {})", version, VLESS_VERSION);
            return Err(VlessError::InvalidVersion(version));
        }

        if data.len() < 2 {
            // Need more data for addons length
            return Err(VlessError::InvalidHeader);
        }

        // Check addons length (1 byte)
        let addons_len = data[1] as usize;
        let total_header_len = 2 + addons_len;

        if data.len() < total_header_len {
            // Need more data for addons
            return Err(VlessError::InvalidHeader);
        }

        trace!(
            "Consumed VLESS response header: version={}, addons_len={}",
            version, addons_len
        );

        Ok(total_header_len)
    }
}

impl AsyncRead for VlessStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Fast path: header already consumed, just forward to inner stream
        if self.header_consumed.load(Ordering::Acquire) {
            // First, drain any buffered data
            let this = self.get_mut();
            let buffered_remaining = this.read_buffer.len() - this.buffer_consumed;

            if buffered_remaining > 0 {
                let to_copy = buffered_remaining.min(buf.remaining());
                let src = &this.read_buffer[this.buffer_consumed..this.buffer_consumed + to_copy];
                buf.put_slice(src);
                this.buffer_consumed += to_copy;

                // If buffer is fully consumed, clear it
                if this.buffer_consumed >= this.read_buffer.len() {
                    this.read_buffer.clear();
                    this.buffer_consumed = 0;
                }

                return Poll::Ready(Ok(()));
            }

            // No buffered data, read directly from inner stream
            return Pin::new(&mut this.inner).poll_read(cx, buf);
        }

        // Slow path: need to consume response header first
        let this = self.get_mut();

        // Try to read data into our buffer
        let mut temp_buf = [0u8; MAX_RESPONSE_HEADER_SIZE];
        let mut temp_read_buf = ReadBuf::new(&mut temp_buf);

        match Pin::new(&mut this.inner).poll_read(cx, &mut temp_read_buf) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {
                let n = temp_read_buf.filled().len();
                if n == 0 {
                    // EOF before response header
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "Connection closed before VLESS response header",
                    )));
                }

                // Add to our buffer
                this.read_buffer.extend_from_slice(temp_read_buf.filled());
            }
        }

        // Try to parse the header
        match this.consume_header() {
            Ok(header_len) => {
                this.buffer_consumed = header_len;
                this.header_consumed.store(true, Ordering::Release);

                debug!("VLESS response header consumed ({} bytes)", header_len);

                // Return any extra data that came after the header
                let extra_data_len = this.read_buffer.len() - header_len;
                if extra_data_len > 0 {
                    let to_copy = extra_data_len.min(buf.remaining());
                    let src = &this.read_buffer[header_len..header_len + to_copy];
                    buf.put_slice(src);
                    this.buffer_consumed = header_len + to_copy;

                    // If buffer is fully consumed, clear it
                    if this.buffer_consumed >= this.read_buffer.len() {
                        this.read_buffer.clear();
                        this.buffer_consumed = 0;
                    }
                } else {
                    // No extra data, need to read more
                    // Clear buffer and try again
                    this.read_buffer.clear();
                    this.buffer_consumed = 0;

                    // Poll the inner stream for actual data
                    return Pin::new(&mut this.inner).poll_read(cx, buf);
                }

                Poll::Ready(Ok(()))
            }
            Err(VlessError::InvalidHeader) => {
                // Need more data, keep polling
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(e) => {
                // Protocol error
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("VLESS response header error: {}", e),
                )))
            }
        }
    }
}

impl AsyncWrite for VlessStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // Write goes directly to inner stream
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Mock stream for testing
    struct MockStream {
        read_data: Cursor<Vec<u8>>,
        write_data: Vec<u8>,
    }

    impl MockStream {
        fn new(data: Vec<u8>) -> Self {
            Self {
                read_data: Cursor::new(data),
                write_data: Vec::new(),
            }
        }
    }

    impl AsyncRead for MockStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let pos = self.read_data.position() as usize;
            let data = self.read_data.get_ref();
            let remaining = &data[pos..];

            if remaining.is_empty() {
                return Poll::Ready(Ok(()));
            }

            let to_copy = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..to_copy]);
            self.read_data.set_position((pos + to_copy) as u64);

            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for MockStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.write_data.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn test_vless_stream_header_consumption() {
        // VLESS response: version (0) + addons_len (0) + actual data
        let response_data = vec![
            0x00, // version
            0x00, // addons length (no addons)
            b'H', b'e', b'l', b'l', b'o', // actual data
        ];

        // Note: We can't easily test VlessStream without a real TransportStream
        // This test documents the expected behavior

        // The stream should:
        // 1. Consume the first 2 bytes (version + addons_len)
        // 2. Return "Hello" on first read
    }
}
