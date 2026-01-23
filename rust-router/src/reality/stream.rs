//! REALITY Stream Wrappers
//!
//! Provides AsyncRead/AsyncWrite wrappers for REALITY connections,
//! enabling seamless integration with async I/O.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::reality::client::{RealityClientConfig, RealityClientConnection};
use crate::reality::error::RealityResult;

/// Async REALITY stream wrapper
///
/// Wraps an underlying transport (like TcpStream) and provides transparent
/// REALITY encryption/decryption.
pub struct RealityStream<T> {
    inner: T,
    connection: RealityClientConnection,
    read_buffer: Vec<u8>,
    read_offset: usize,
    write_buffer: Vec<u8>,
    handshake_complete: bool,
}

impl<T> RealityStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    /// Create a new REALITY stream and initiate the handshake
    ///
    /// This will generate and send the ClientHello immediately.
    pub async fn new(mut inner: T, config: RealityClientConfig) -> RealityResult<Self> {
        let mut connection = RealityClientConnection::new(config);

        // Generate ClientHello
        let client_hello = connection.start()?;

        // Send it
        use tokio::io::AsyncWriteExt;
        inner
            .write_all(&client_hello)
            .await
            .map_err(|e| crate::reality::error::RealityError::Io(e))?;

        Ok(Self {
            inner,
            connection,
            read_buffer: Vec::new(),
            read_offset: 0,
            write_buffer: Vec::new(),
            handshake_complete: false,
        })
    }

    /// Check if the handshake is complete
    pub fn is_established(&self) -> bool {
        self.connection.is_established()
    }

    /// Get a reference to the underlying transport
    pub fn get_ref(&self) -> &T {
        &self.inner
    }

    /// Get a mutable reference to the underlying transport
    pub fn get_mut(&mut self) -> &mut T {
        &mut self.inner
    }

    /// Consume the stream and return the underlying transport
    pub fn into_inner(self) -> T {
        self.inner
    }

    /// Complete the handshake (blocking on I/O)
    ///
    /// After this returns successfully, application data can be exchanged.
    pub async fn handshake(&mut self) -> RealityResult<()> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        if self.handshake_complete {
            return Ok(());
        }

        let mut buf = vec![0u8; 16384];

        while self.connection.is_handshaking() {
            // Read from transport
            let n = self.inner.read(&mut buf).await.map_err(crate::reality::error::RealityError::Io)?;
            if n == 0 {
                return Err(crate::reality::error::RealityError::handshake(
                    "Connection closed during handshake",
                ));
            }

            // Feed to connection
            let result = self.connection.feed(&buf[..n])?;

            // Send any data the connection wants to send
            if !result.to_send.is_empty() {
                self.inner
                    .write_all(&result.to_send)
                    .await
                    .map_err(crate::reality::error::RealityError::Io)?;
            }

            // Buffer any application data (shouldn't happen during handshake, but just in case)
            if !result.app_data.is_empty() {
                self.read_buffer.extend_from_slice(&result.app_data);
            }
        }

        self.handshake_complete = true;
        Ok(())
    }

    /// Send close_notify and shutdown the connection
    pub async fn shutdown(&mut self) -> io::Result<()> {
        use tokio::io::AsyncWriteExt;

        if let Ok(close_notify) = self.connection.close_notify() {
            self.inner.write_all(&close_notify).await?;
        }

        self.inner.shutdown().await
    }
}

impl<T> AsyncRead for RealityStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // If we have buffered data, return it first
        if self.read_offset < self.read_buffer.len() {
            let available = &self.read_buffer[self.read_offset..];
            let to_copy = available.len().min(buf.remaining());
            buf.put_slice(&available[..to_copy]);
            self.read_offset += to_copy;

            // Clear buffer if fully consumed
            if self.read_offset >= self.read_buffer.len() {
                self.read_buffer.clear();
                self.read_offset = 0;
            }

            return Poll::Ready(Ok(()));
        }

        // Read from underlying transport
        let mut read_buf = vec![0u8; 16384];
        let mut tmp_buf = ReadBuf::new(&mut read_buf);

        match Pin::new(&mut self.inner).poll_read(cx, &mut tmp_buf) {
            Poll::Ready(Ok(())) => {
                let n = tmp_buf.filled().len();
                if n == 0 {
                    return Poll::Ready(Ok(())); // EOF
                }

                // Feed to connection
                match self.connection.feed(&read_buf[..n]) {
                    Ok(result) => {
                        if !result.app_data.is_empty() {
                            // Copy to output buffer
                            let to_copy = result.app_data.len().min(buf.remaining());
                            buf.put_slice(&result.app_data[..to_copy]);

                            // Buffer remainder
                            if to_copy < result.app_data.len() {
                                self.read_buffer.extend_from_slice(&result.app_data[to_copy..]);
                                self.read_offset = 0;
                            }
                        }

                        // If connection wants to send data (during handshake), we need to handle it
                        // This is a limitation of the AsyncRead interface - we can't write here
                        // In practice, handshake should be completed before using AsyncRead

                        Poll::Ready(Ok(()))
                    }
                    Err(e) => Poll::Ready(Err(e.into())),
                }
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<T> AsyncWrite for RealityStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // Encrypt the data
        let encrypted = match self.connection.encrypt(buf) {
            Ok(data) => data,
            Err(e) => return Poll::Ready(Err(e.into())),
        };

        // Write to underlying transport
        match Pin::new(&mut self.inner).poll_write(cx, &encrypted) {
            Poll::Ready(Ok(n)) => {
                // Return the number of plaintext bytes written
                // (we assume all encrypted data is written if any is written)
                if n > 0 {
                    Poll::Ready(Ok(buf.len()))
                } else {
                    Poll::Ready(Ok(0))
                }
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Send close_notify if not already sent
        if !self.connection.is_closed() {
            if let Ok(close_notify) = self.connection.close_notify() {
                self.write_buffer = close_notify;
            }
        }

        // Write any buffered close_notify
        loop {
            if self.write_buffer.is_empty() {
                break;
            }
            // Copy buffer to avoid borrow conflict
            let buf_copy = self.write_buffer.clone();
            match Pin::new(&mut self.inner).poll_write(cx, &buf_copy) {
                Poll::Ready(Ok(n)) => {
                    self.write_buffer.drain(..n);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Builder for configuring REALITY connections
pub struct RealityConnector {
    server_public_key: [u8; 32],
    short_id: [u8; 8],
    server_name: String,
}

impl RealityConnector {
    /// Create a new connector with required parameters
    pub fn new(server_public_key: [u8; 32], short_id: [u8; 8], server_name: impl Into<String>) -> Self {
        Self {
            server_public_key,
            short_id,
            server_name: server_name.into(),
        }
    }

    /// Create a connector from base64-encoded public key and hex-encoded short ID
    pub fn from_encoded(
        public_key_base64: &str,
        short_id_hex: &str,
        server_name: impl Into<String>,
    ) -> RealityResult<Self> {
        use crate::reality::auth::decode_short_id;
        use crate::reality::crypto::x25519::decode_public_key;

        let server_public_key = decode_public_key(public_key_base64)?;
        let short_id = decode_short_id(short_id_hex)?;

        Ok(Self {
            server_public_key,
            short_id,
            server_name: server_name.into(),
        })
    }

    /// Connect to a server using the provided transport
    pub async fn connect<T>(self, transport: T) -> RealityResult<RealityStream<T>>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        let config = RealityClientConfig::new(
            self.server_public_key,
            self.short_id,
            self.server_name,
        );

        let mut stream = RealityStream::new(transport, config).await?;
        stream.handshake().await?;

        Ok(stream)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connector_from_encoded() {
        let result = RealityConnector::from_encoded(
            "UuMBgl7MXTPCQo57FPi4gkLxvkJedeWFWW2oU1hwGDA=",
            "12345678",
            "www.google.com",
        );

        assert!(result.is_ok());
        let connector = result.unwrap();
        assert_eq!(connector.server_name, "www.google.com");
    }

    #[test]
    fn test_connector_invalid_public_key() {
        let result = RealityConnector::from_encoded("invalid-base64!!!", "12345678", "example.com");
        assert!(result.is_err());
    }

    #[test]
    fn test_connector_invalid_short_id() {
        let result = RealityConnector::from_encoded(
            "UuMBgl7MXTPCQo57FPi4gkLxvkJedeWFWW2oU1hwGDA=",
            "xyz-not-hex",
            "example.com",
        );
        assert!(result.is_err());
    }
}
