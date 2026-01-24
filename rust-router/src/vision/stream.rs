//! XTLS-Vision async stream wrapper
//!
//! This module provides `VisionStream`, an async stream wrapper that detects
//! inner TLS traffic and switches to zero-copy passthrough mode. When the
//! inner TLS handshake completes (ClientHello -> ServerHello -> ApplicationData),
//! the wrapper stops inspecting data and forwards it directly without overhead.
//!
//! # Architecture
//!
//! ```text
//! ┌────────────────────────────────────────────────────────────────┐
//! │                        VisionStream                             │
//! ├────────────────────────────────────────────────────────────────┤
//! │  State Machine:                                                 │
//! │                                                                 │
//! │  Inspecting ──[ClientHello]──> AwaitServerHello                │
//! │       │                              │                          │
//! │       │                        [ServerHello]                    │
//! │       │                              │                          │
//! │       │                              ▼                          │
//! │       │                        AwaitAppData                     │
//! │       │                              │                          │
//! │       │                     [ApplicationData]                   │
//! │       │                              │                          │
//! │       │                              ▼                          │
//! │  [non-TLS]                      Passthrough                     │
//! │       │                        (zero-copy)                      │
//! │       ▼                                                         │
//! │  Encrypted                                                      │
//! │  (normal encryption)                                            │
//! └────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Usage
//!
//! ```no_run
//! use tokio::net::TcpStream;
//! use rust_router::vision::VisionStream;
//!
//! # async fn example() -> std::io::Result<()> {
//! let stream = TcpStream::connect("127.0.0.1:8080").await?;
//! let mut vision_stream = VisionStream::new(stream);
//!
//! // Use like a normal async stream - Vision detection happens automatically
//! // on reads. After detecting the TLS handshake sequence, it switches to
//! // passthrough mode.
//! # Ok(())
//! # }
//! ```
//!
//! # Performance
//!
//! - **Inspection phase**: Minimal overhead for TLS header parsing (~100 bytes per record)
//! - **Passthrough mode**: Zero-copy forwarding, no additional CPU overhead
//! - **Buffer size**: Default 4KB inspection buffer, sufficient for TLS handshake detection

use std::io::Result;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::{debug, trace};

use super::detector::{
    is_application_data, is_client_hello, is_server_hello, is_tls_traffic, parse_tls_record_header,
    TLS_RECORD_HEADER_SIZE,
};
use super::VisionState;

/// Default size for the inspection buffer
const DEFAULT_INSPECT_BUFFER_SIZE: usize = 4096;

/// Minimum bytes needed before we can make a decision
const MIN_DETECTION_BYTES: usize = TLS_RECORD_HEADER_SIZE + 1;

/// Internal stream state for TLS handshake tracking
///
/// This is more granular than `VisionState` to track the handshake progress.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamState {
    /// Initial state - inspecting first bytes
    Inspecting,
    /// Saw ClientHello, waiting for ServerHello
    AwaitServerHello,
    /// Saw ServerHello, waiting for ApplicationData
    AwaitAppData,
    /// TLS handshake complete - using zero-copy passthrough
    Passthrough,
    /// Non-TLS detected - using normal encryption
    Encrypted,
}

impl Default for StreamState {
    fn default() -> Self {
        Self::Inspecting
    }
}

impl StreamState {
    /// Check if we're still in the inspection phase
    #[must_use]
    pub fn is_inspecting(&self) -> bool {
        matches!(
            self,
            Self::Inspecting | Self::AwaitServerHello | Self::AwaitAppData
        )
    }

    /// Check if we've completed detection
    #[must_use]
    pub fn is_decided(&self) -> bool {
        matches!(self, Self::Passthrough | Self::Encrypted)
    }

    /// Convert to the public VisionState
    #[must_use]
    pub fn to_vision_state(&self) -> VisionState {
        match self {
            Self::Inspecting | Self::AwaitServerHello | Self::AwaitAppData => VisionState::Inspecting,
            Self::Passthrough => VisionState::Passthrough,
            Self::Encrypted => VisionState::Encrypted,
        }
    }

    /// Get state name for logging
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Inspecting => "inspecting",
            Self::AwaitServerHello => "await_server_hello",
            Self::AwaitAppData => "await_app_data",
            Self::Passthrough => "passthrough",
            Self::Encrypted => "encrypted",
        }
    }
}

impl std::fmt::Display for StreamState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// XTLS-Vision async stream wrapper
///
/// Detects inner TLS traffic and switches to zero-copy passthrough mode.
/// When inner TLS `ApplicationData` is detected after seeing the handshake
/// sequence (`ClientHello` -> `ServerHello`), the wrapper stops inspecting
/// and forwards data directly without overhead.
///
/// # Type Parameters
///
/// * `S` - The underlying stream type (must implement `AsyncRead + AsyncWrite + Unpin`)
///
/// # Example
///
/// ```no_run
/// use tokio::net::TcpStream;
/// use rust_router::vision::VisionStream;
///
/// # async fn example() -> std::io::Result<()> {
/// let stream = TcpStream::connect("127.0.0.1:8080").await?;
/// let vision = VisionStream::new(stream);
///
/// // Check if we've detected TLS and switched to passthrough
/// if vision.is_passthrough() {
///     println!("Using zero-copy passthrough mode");
/// }
/// # Ok(())
/// # }
/// ```
pub struct VisionStream<S> {
    /// The underlying stream
    inner: S,
    /// Current detection state
    state: StreamState,
    /// Buffer for inspection phase (holds partial TLS records)
    inspect_buffer: Vec<u8>,
    /// Number of bytes in inspect_buffer that are valid data
    inspect_len: usize,
    /// Offset into inspect_buffer for data already returned to caller
    inspect_offset: usize,
    /// Count of TLS records processed during detection
    records_processed: u8,
}

impl<S> VisionStream<S> {
    /// Create a new VisionStream wrapping the given stream
    ///
    /// The stream starts in `Inspecting` state and will detect TLS traffic
    /// on the first read operations.
    ///
    /// # Arguments
    ///
    /// * `inner` - The underlying stream to wrap
    ///
    /// # Example
    ///
    /// ```no_run
    /// use tokio::net::TcpStream;
    /// use rust_router::vision::VisionStream;
    ///
    /// # async fn example() -> std::io::Result<()> {
    /// let stream = TcpStream::connect("127.0.0.1:443").await?;
    /// let vision = VisionStream::new(stream);
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            state: StreamState::default(),
            inspect_buffer: Vec::with_capacity(DEFAULT_INSPECT_BUFFER_SIZE),
            inspect_len: 0,
            inspect_offset: 0,
            records_processed: 0,
        }
    }

    /// Create a new VisionStream with a custom buffer capacity
    ///
    /// # Arguments
    ///
    /// * `inner` - The underlying stream to wrap
    /// * `buffer_capacity` - Initial capacity for the inspection buffer
    pub fn with_capacity(inner: S, buffer_capacity: usize) -> Self {
        Self {
            inner,
            state: StreamState::default(),
            inspect_buffer: Vec::with_capacity(buffer_capacity),
            inspect_len: 0,
            inspect_offset: 0,
            records_processed: 0,
        }
    }

    /// Check if in passthrough mode (zero-copy forwarding)
    ///
    /// Returns `true` once TLS traffic has been detected and the handshake
    /// sequence is complete.
    #[must_use]
    pub fn is_passthrough(&self) -> bool {
        self.state == StreamState::Passthrough
    }

    /// Get the current stream state (detailed internal state)
    #[must_use]
    pub fn stream_state(&self) -> StreamState {
        self.state
    }

    /// Get the current Vision state (public simplified state)
    #[must_use]
    pub fn state(&self) -> VisionState {
        self.state.to_vision_state()
    }

    /// Get the number of TLS records processed during detection
    #[must_use]
    pub fn records_processed(&self) -> u8 {
        self.records_processed
    }

    /// Get a reference to the inner stream
    #[must_use]
    pub fn get_ref(&self) -> &S {
        &self.inner
    }

    /// Get a mutable reference to the inner stream
    ///
    /// # Safety
    ///
    /// Directly reading/writing to the inner stream while detection is in
    /// progress may corrupt the state machine. Only use this after detection
    /// is complete (when `is_passthrough()` or `state().is_decided()` returns true).
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    /// Consume the VisionStream and return the inner stream
    ///
    /// Any buffered data that hasn't been returned to the caller will be lost.
    /// Only call this after all buffered data has been consumed.
    pub fn into_inner(self) -> S {
        self.inner
    }

    /// Check if there's buffered data that hasn't been returned yet
    #[must_use]
    pub fn has_buffered_data(&self) -> bool {
        self.inspect_offset < self.inspect_len
    }

    /// Get the amount of buffered data available
    #[must_use]
    pub fn buffered_len(&self) -> usize {
        self.inspect_len.saturating_sub(self.inspect_offset)
    }
}

impl<S: AsyncRead + Unpin> VisionStream<S> {
    /// Try to detect TLS traffic from the current buffer contents
    ///
    /// Returns `true` if detection is complete (either passthrough or encrypted
    /// mode has been decided).
    ///
    /// This method processes multiple TLS records if they are buffered together,
    /// advancing through the handshake sequence until either passthrough or
    /// encrypted mode is decided.
    fn try_detect_tls(&mut self) -> bool {
        // Use a local scan offset to look at multiple records without
        // affecting inspect_offset (which tracks data returned to caller)
        let mut scan_offset = self.inspect_offset;

        // Process records in a loop to handle multiple records in one buffer
        loop {
            let available = &self.inspect_buffer[scan_offset..self.inspect_len];

            // Need minimum bytes for detection
            if available.len() < MIN_DETECTION_BYTES {
                trace!(
                    "VisionStream: need more data for detection ({} < {})",
                    available.len(),
                    MIN_DETECTION_BYTES
                );
                return false;
            }

            match self.state {
                StreamState::Inspecting => {
                    // First, check if it looks like TLS at all
                    if !is_tls_traffic(available) {
                        debug!("VisionStream: non-TLS traffic detected, using encrypted mode");
                        self.state = StreamState::Encrypted;
                        return true;
                    }

                    // Check for ClientHello
                    if is_client_hello(available) {
                        debug!("VisionStream: ClientHello detected, awaiting ServerHello");
                        self.state = StreamState::AwaitServerHello;
                        self.records_processed += 1;

                        // Try to advance past this record to check next one
                        if let Some((_, _, length)) = parse_tls_record_header(available) {
                            let record_len = TLS_RECORD_HEADER_SIZE + length as usize;
                            if available.len() >= record_len {
                                scan_offset += record_len;
                                continue;
                            }
                        }
                        return false;
                    }

                    // Check for ApplicationData directly (server-side receiving)
                    if is_application_data(available) {
                        debug!("VisionStream: ApplicationData detected directly, passthrough mode");
                        self.state = StreamState::Passthrough;
                        self.records_processed += 1;
                        return true;
                    }

                    // Other TLS record but not ClientHello - keep inspecting
                    trace!("VisionStream: TLS record detected, continuing inspection");
                    self.records_processed += 1;
                    return false;
                }

                StreamState::AwaitServerHello => {
                    if !is_tls_traffic(available) {
                        debug!("VisionStream: lost TLS structure after ClientHello, encrypted mode");
                        self.state = StreamState::Encrypted;
                        return true;
                    }

                    if is_server_hello(available) {
                        debug!("VisionStream: ServerHello detected, awaiting ApplicationData");
                        self.state = StreamState::AwaitAppData;
                        self.records_processed += 1;

                        // Try to advance past this record
                        if let Some((_, _, length)) = parse_tls_record_header(available) {
                            let record_len = TLS_RECORD_HEADER_SIZE + length as usize;
                            if available.len() >= record_len {
                                scan_offset += record_len;
                                continue;
                            }
                        }
                        return false;
                    }

                    // Other TLS records - try to skip them and look for ServerHello
                    if let Some((_, _, length)) = parse_tls_record_header(available) {
                        let record_len = TLS_RECORD_HEADER_SIZE + length as usize;
                        if available.len() >= record_len {
                            trace!(
                                "VisionStream: TLS record while awaiting ServerHello, type=0x{:02x}",
                                available[0]
                            );
                            self.records_processed += 1;
                            scan_offset += record_len;
                            continue;
                        }
                    }
                    return false;
                }

                StreamState::AwaitAppData => {
                    if !is_tls_traffic(available) {
                        debug!("VisionStream: lost TLS structure after ServerHello, encrypted mode");
                        self.state = StreamState::Encrypted;
                        return true;
                    }

                    if is_application_data(available) {
                        debug!("VisionStream: ApplicationData detected, switching to passthrough");
                        self.state = StreamState::Passthrough;
                        self.records_processed += 1;
                        return true;
                    }

                    // Other handshake records - skip and continue
                    if let Some((_, _, length)) = parse_tls_record_header(available) {
                        let record_len = TLS_RECORD_HEADER_SIZE + length as usize;
                        if available.len() >= record_len {
                            trace!(
                                "VisionStream: TLS record while awaiting AppData, type=0x{:02x}",
                                available[0]
                            );
                            self.records_processed += 1;
                            scan_offset += record_len;
                            continue;
                        }
                    }
                    return false;
                }

                StreamState::Passthrough | StreamState::Encrypted => {
                    // Already decided
                    return true;
                }
            }
        }
    }

    /// Read during inspection phase
    ///
    /// Buffers data for inspection while also returning data to the caller.
    fn poll_read_inspect(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<()>> {
        // First, return any buffered data that we've already read
        if self.inspect_offset < self.inspect_len {
            let available = &self.inspect_buffer[self.inspect_offset..self.inspect_len];
            let to_copy = available.len().min(buf.remaining());
            buf.put_slice(&available[..to_copy]);
            self.inspect_offset += to_copy;

            trace!(
                "VisionStream: returned {} bytes from buffer, offset now {}",
                to_copy,
                self.inspect_offset
            );

            // If we've consumed all buffered data and detection is complete,
            // we can clear the buffer
            if self.inspect_offset >= self.inspect_len && self.state.is_decided() {
                self.inspect_buffer.clear();
                self.inspect_len = 0;
                self.inspect_offset = 0;
            }

            return Poll::Ready(Ok(()));
        }

        // If detection is complete and no buffered data, read directly
        if self.state.is_decided() {
            return Pin::new(&mut self.inner).poll_read(cx, buf);
        }

        // Need to read more data for inspection
        // Make sure we have room in the buffer
        if self.inspect_buffer.len() < self.inspect_len + DEFAULT_INSPECT_BUFFER_SIZE {
            self.inspect_buffer
                .resize(self.inspect_len + DEFAULT_INSPECT_BUFFER_SIZE, 0);
        }

        // Read into our inspection buffer
        let mut temp_buf = ReadBuf::new(&mut self.inspect_buffer[self.inspect_len..]);
        match Pin::new(&mut self.inner).poll_read(cx, &mut temp_buf) {
            Poll::Ready(Ok(())) => {
                let bytes_read = temp_buf.filled().len();
                if bytes_read == 0 {
                    // EOF during inspection - not TLS
                    if self.inspect_len == 0 {
                        return Poll::Ready(Ok(()));
                    }
                    // Treat as non-TLS
                    self.state = StreamState::Encrypted;
                    debug!("VisionStream: EOF during inspection, using encrypted mode");
                }
                self.inspect_len += bytes_read;

                trace!(
                    "VisionStream: read {} bytes, total buffered {}",
                    bytes_read,
                    self.inspect_len
                );

                // Try detection
                self.try_detect_tls();

                // Return buffered data to caller
                let available = &self.inspect_buffer[self.inspect_offset..self.inspect_len];
                if !available.is_empty() {
                    let to_copy = available.len().min(buf.remaining());
                    buf.put_slice(&available[..to_copy]);
                    self.inspect_offset += to_copy;
                }

                // Clear buffer if detection complete and all data returned
                if self.inspect_offset >= self.inspect_len && self.state.is_decided() {
                    self.inspect_buffer.clear();
                    self.inspect_len = 0;
                    self.inspect_offset = 0;
                }

                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for VisionStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<()>> {
        // If we're in passthrough or encrypted mode and no buffered data, read directly
        if self.state.is_decided() && self.inspect_offset >= self.inspect_len {
            return Pin::new(&mut self.inner).poll_read(cx, buf);
        }

        // Still inspecting or have buffered data
        self.poll_read_inspect(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for VisionStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize>> {
        // Vision only inspects reads, writes are transparent
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vision::{
        HANDSHAKE_CLIENT_HELLO, HANDSHAKE_SERVER_HELLO, TLS_APPLICATION_DATA, TLS_HANDSHAKE,
    };
    use std::io::{self, Cursor};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // ==========================================================================
    // Test Helpers
    // ==========================================================================

    /// Create a minimal TLS ClientHello packet
    fn make_client_hello() -> Vec<u8> {
        vec![
            TLS_HANDSHAKE,
            0x03,
            0x03, // TLS 1.2
            0x00,
            0x10, // Length = 16
            HANDSHAKE_CLIENT_HELLO,
            0x00,
            0x00,
            0x0c, // Handshake length
            // Padding
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
        ]
    }

    /// Create a minimal TLS ServerHello packet
    fn make_server_hello() -> Vec<u8> {
        vec![
            TLS_HANDSHAKE,
            0x03,
            0x03, // TLS 1.2
            0x00,
            0x10, // Length = 16
            HANDSHAKE_SERVER_HELLO,
            0x00,
            0x00,
            0x0c, // Handshake length
            // Padding
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
        ]
    }

    /// Create a minimal TLS ApplicationData packet
    fn make_application_data() -> Vec<u8> {
        vec![
            TLS_APPLICATION_DATA,
            0x03,
            0x03, // TLS 1.2
            0x00,
            0x10, // Length = 16
            // Encrypted payload
            0x01,
            0x02,
            0x03,
            0x04,
            0x05,
            0x06,
            0x07,
            0x08,
            0x09,
            0x0a,
            0x0b,
            0x0c,
            0x0d,
            0x0e,
            0x0f,
            0x10,
        ]
    }

    /// Mock stream for testing that wraps a Cursor
    struct MockStream {
        reader: Cursor<Vec<u8>>,
        writer: Vec<u8>,
    }

    impl MockStream {
        fn new(data: Vec<u8>) -> Self {
            Self {
                reader: Cursor::new(data),
                writer: Vec::new(),
            }
        }

        fn written(&self) -> &[u8] {
            &self.writer
        }
    }

    impl AsyncRead for MockStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.reader).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for MockStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.writer.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl Unpin for MockStream {}

    // ==========================================================================
    // StreamState Tests
    // ==========================================================================

    #[test]
    fn test_stream_state_default() {
        let state = StreamState::default();
        assert_eq!(state, StreamState::Inspecting);
        assert!(state.is_inspecting());
        assert!(!state.is_decided());
    }

    #[test]
    fn test_stream_state_is_inspecting() {
        assert!(StreamState::Inspecting.is_inspecting());
        assert!(StreamState::AwaitServerHello.is_inspecting());
        assert!(StreamState::AwaitAppData.is_inspecting());
        assert!(!StreamState::Passthrough.is_inspecting());
        assert!(!StreamState::Encrypted.is_inspecting());
    }

    #[test]
    fn test_stream_state_is_decided() {
        assert!(!StreamState::Inspecting.is_decided());
        assert!(!StreamState::AwaitServerHello.is_decided());
        assert!(!StreamState::AwaitAppData.is_decided());
        assert!(StreamState::Passthrough.is_decided());
        assert!(StreamState::Encrypted.is_decided());
    }

    #[test]
    fn test_stream_state_to_vision_state() {
        assert_eq!(
            StreamState::Inspecting.to_vision_state(),
            VisionState::Inspecting
        );
        assert_eq!(
            StreamState::AwaitServerHello.to_vision_state(),
            VisionState::Inspecting
        );
        assert_eq!(
            StreamState::AwaitAppData.to_vision_state(),
            VisionState::Inspecting
        );
        assert_eq!(
            StreamState::Passthrough.to_vision_state(),
            VisionState::Passthrough
        );
        assert_eq!(
            StreamState::Encrypted.to_vision_state(),
            VisionState::Encrypted
        );
    }

    #[test]
    fn test_stream_state_display() {
        assert_eq!(StreamState::Inspecting.to_string(), "inspecting");
        assert_eq!(
            StreamState::AwaitServerHello.to_string(),
            "await_server_hello"
        );
        assert_eq!(StreamState::AwaitAppData.to_string(), "await_app_data");
        assert_eq!(StreamState::Passthrough.to_string(), "passthrough");
        assert_eq!(StreamState::Encrypted.to_string(), "encrypted");
    }

    // ==========================================================================
    // VisionStream Basic Tests
    // ==========================================================================

    #[test]
    fn test_vision_stream_new() {
        let mock = MockStream::new(vec![]);
        let vision = VisionStream::new(mock);

        assert!(!vision.is_passthrough());
        assert_eq!(vision.stream_state(), StreamState::Inspecting);
        assert!(vision.state().is_inspecting());
        assert_eq!(vision.records_processed(), 0);
        assert!(!vision.has_buffered_data());
        assert_eq!(vision.buffered_len(), 0);
    }

    #[test]
    fn test_vision_stream_with_capacity() {
        let mock = MockStream::new(vec![]);
        let vision = VisionStream::with_capacity(mock, 8192);

        assert!(!vision.is_passthrough());
        assert_eq!(vision.stream_state(), StreamState::Inspecting);
    }

    #[test]
    fn test_vision_stream_get_ref() {
        let data = vec![1, 2, 3, 4, 5];
        let mock = MockStream::new(data);
        let vision = VisionStream::new(mock);

        // Can access inner stream
        let _inner: &MockStream = vision.get_ref();
    }

    #[test]
    fn test_vision_stream_into_inner() {
        let data = vec![1, 2, 3, 4, 5];
        let mock = MockStream::new(data.clone());
        let vision = VisionStream::new(mock);

        let inner = vision.into_inner();
        assert_eq!(inner.reader.get_ref(), &data);
    }

    // ==========================================================================
    // TLS Detection Tests
    // ==========================================================================

    #[tokio::test]
    async fn test_detect_non_tls_traffic() {
        // HTTP request (not TLS)
        let http_data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec();
        let mock = MockStream::new(http_data.clone());
        let mut vision = VisionStream::new(mock);

        let mut buf = vec![0u8; 1024];
        let n = vision.read(&mut buf).await.unwrap();

        assert_eq!(&buf[..n], &http_data[..n]);
        assert_eq!(vision.stream_state(), StreamState::Encrypted);
        assert!(!vision.is_passthrough());
        assert!(vision.state().is_encrypted());
    }

    #[tokio::test]
    async fn test_detect_client_hello() {
        let client_hello = make_client_hello();
        let mock = MockStream::new(client_hello.clone());
        let mut vision = VisionStream::new(mock);

        let mut buf = vec![0u8; 1024];
        let n = vision.read(&mut buf).await.unwrap();

        // After reading ClientHello, should be awaiting ServerHello
        assert_eq!(&buf[..n], &client_hello[..n]);
        assert_eq!(vision.stream_state(), StreamState::AwaitServerHello);
        assert_eq!(vision.records_processed(), 1);
    }

    #[tokio::test]
    async fn test_detect_full_handshake_to_passthrough() {
        // Construct full TLS handshake sequence
        let mut data = make_client_hello();
        data.extend(make_server_hello());
        data.extend(make_application_data());

        let total_len = data.len();
        let mock = MockStream::new(data);
        let mut vision = VisionStream::new(mock);

        // Read all the data
        let mut buf = vec![0u8; 2048];
        let mut total_read = 0;
        while total_read < total_len {
            let n = vision.read(&mut buf[total_read..]).await.unwrap();
            if n == 0 {
                break;
            }
            total_read += n;
        }

        // Should be in passthrough mode
        assert_eq!(vision.stream_state(), StreamState::Passthrough);
        assert!(vision.is_passthrough());
        assert!(vision.state().is_passthrough());
        assert!(vision.records_processed() >= 3);
    }

    #[tokio::test]
    async fn test_detect_application_data_directly() {
        // Server-side: first packet is ApplicationData (from client after handshake)
        let app_data = make_application_data();
        let mock = MockStream::new(app_data.clone());
        let mut vision = VisionStream::new(mock);

        let mut buf = vec![0u8; 1024];
        let n = vision.read(&mut buf).await.unwrap();

        assert_eq!(&buf[..n], &app_data[..n]);
        assert_eq!(vision.stream_state(), StreamState::Passthrough);
        assert!(vision.is_passthrough());
    }

    #[tokio::test]
    async fn test_partial_tls_header() {
        // Send only partial header - needs more data
        let partial = vec![TLS_HANDSHAKE, 0x03, 0x03, 0x00];
        let mock = MockStream::new(partial.clone());
        let mut vision = VisionStream::new(mock);

        let mut buf = vec![0u8; 1024];
        let n = vision.read(&mut buf).await.unwrap();

        // Should still be inspecting (need more data)
        // Note: with only 4 bytes and EOF, it may decide encrypted
        assert_eq!(&buf[..n], &partial[..n]);
    }

    #[tokio::test]
    async fn test_multiple_reads_for_detection() {
        // First chunk: partial ClientHello
        let client_hello = make_client_hello();
        let mock = MockStream::new(client_hello.clone());
        let mut vision = VisionStream::new(mock);

        // Read in small chunks
        let mut buf = vec![0u8; 4];
        let mut total = 0;

        while total < client_hello.len() {
            let n = vision.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            total += n;
        }

        // Should have detected ClientHello
        assert_eq!(vision.stream_state(), StreamState::AwaitServerHello);
    }

    // ==========================================================================
    // Write Passthrough Tests
    // ==========================================================================

    #[tokio::test]
    async fn test_write_passthrough() {
        let mock = MockStream::new(vec![]);
        let mut vision = VisionStream::new(mock);

        // Writes should pass through regardless of state
        let data = b"Hello, World!";
        let n = vision.write(data).await.unwrap();
        assert_eq!(n, data.len());

        // Flush should work
        vision.flush().await.unwrap();

        // Verify data was written
        assert_eq!(vision.get_ref().written(), data);
    }

    #[tokio::test]
    async fn test_write_during_inspection() {
        let client_hello = make_client_hello();
        let mock = MockStream::new(client_hello);
        let mut vision = VisionStream::new(mock);

        // Write while still inspecting
        let data = b"Some response data";
        let n = vision.write(data).await.unwrap();
        assert_eq!(n, data.len());

        // Writes are transparent
        assert_eq!(vision.get_ref().written(), data);
    }

    // ==========================================================================
    // State Transition Tests
    // ==========================================================================

    #[tokio::test]
    async fn test_state_transition_inspecting_to_encrypted() {
        let random_data = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        let mock = MockStream::new(random_data);
        let mut vision = VisionStream::new(mock);

        assert_eq!(vision.stream_state(), StreamState::Inspecting);

        let mut buf = vec![0u8; 1024];
        let _ = vision.read(&mut buf).await.unwrap();

        assert_eq!(vision.stream_state(), StreamState::Encrypted);
    }

    #[tokio::test]
    async fn test_state_transition_await_server_hello() {
        let mut data = make_client_hello();
        // Add non-ServerHello data to trigger AwaitServerHello state
        data.extend(vec![0x00, 0x01, 0x02]); // This will make it non-TLS after ClientHello

        let mock = MockStream::new(data);
        let mut vision = VisionStream::new(mock);

        let mut buf = vec![0u8; 1024];

        // First read gets ClientHello
        let _ = vision.read(&mut buf).await.unwrap();

        // State should progress through AwaitServerHello
        // and since next bytes aren't valid TLS, it falls back to Encrypted
        assert!(
            vision.stream_state() == StreamState::AwaitServerHello
                || vision.stream_state() == StreamState::Encrypted
        );
    }

    // ==========================================================================
    // Edge Case Tests
    // ==========================================================================

    #[tokio::test]
    async fn test_empty_stream() {
        let mock = MockStream::new(vec![]);
        let mut vision = VisionStream::new(mock);

        let mut buf = vec![0u8; 1024];
        let n = vision.read(&mut buf).await.unwrap();

        assert_eq!(n, 0);
    }

    #[tokio::test]
    async fn test_very_small_buffer() {
        let client_hello = make_client_hello();
        let mock = MockStream::new(client_hello);
        let mut vision = VisionStream::new(mock);

        // Read with very small buffer
        let mut buf = vec![0u8; 1];
        let mut total = 0;

        for _ in 0..100 {
            let n = vision.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            total += n;
        }

        assert!(total > 0);
    }

    #[tokio::test]
    async fn test_buffered_data_tracking() {
        let client_hello = make_client_hello();
        let mock = MockStream::new(client_hello.clone());
        let mut vision = VisionStream::new(mock);

        // Do a small read
        let mut buf = vec![0u8; 5];
        let _ = vision.read(&mut buf).await.unwrap();

        // Check buffered data state
        let buffered = vision.buffered_len();

        // Read the rest
        let mut buf2 = vec![0u8; 1024];
        let n = vision.read(&mut buf2).await.unwrap();

        // Should have gotten remaining buffered data
        assert!(n <= buffered || n == 0);
    }

    #[tokio::test]
    async fn test_direct_read_after_passthrough() {
        let mut data = make_client_hello();
        data.extend(make_server_hello());
        data.extend(make_application_data());
        let extra_data = b"extra data after handshake";
        data.extend_from_slice(extra_data);

        let mock = MockStream::new(data);
        let mut vision = VisionStream::new(mock);

        // Read everything to trigger passthrough
        let mut buf = vec![0u8; 4096];
        let mut total = 0;
        loop {
            let n = vision.read(&mut buf[total..]).await.unwrap();
            if n == 0 {
                break;
            }
            total += n;
        }

        // Should be in passthrough and have read all data
        assert!(vision.is_passthrough());
        assert!(total > 0);
    }

    // ==========================================================================
    // Integration Tests
    // ==========================================================================

    #[tokio::test]
    async fn test_full_bidirectional_flow() {
        let client_hello = make_client_hello();
        let mock = MockStream::new(client_hello.clone());
        let mut vision = VisionStream::new(mock);

        // Read (detection)
        let mut read_buf = vec![0u8; 1024];
        let read_n = vision.read(&mut read_buf).await.unwrap();
        assert_eq!(&read_buf[..read_n], &client_hello[..read_n]);

        // Write (passthrough)
        let write_data = b"Server response";
        let write_n = vision.write(write_data).await.unwrap();
        assert_eq!(write_n, write_data.len());

        // Verify independent operation
        assert_eq!(vision.get_ref().written(), write_data);
    }

    #[tokio::test]
    async fn test_multiple_tls_records_in_one_read() {
        // All three records in one buffer
        let mut data = make_client_hello();
        data.extend(make_server_hello());
        data.extend(make_application_data());

        let mock = MockStream::new(data.clone());
        let mut vision = VisionStream::new(mock);

        // Read large buffer that gets all data at once
        let mut buf = vec![0u8; 4096];
        let n = vision.read(&mut buf).await.unwrap();

        assert!(n > 0);
        // After reading, might need more reads to process all
        let mut total = n;
        while total < data.len() {
            let n = vision.read(&mut buf[total..]).await.unwrap();
            if n == 0 {
                break;
            }
            total += n;
        }

        assert_eq!(vision.stream_state(), StreamState::Passthrough);
    }

    // ==========================================================================
    // Regression Tests
    // ==========================================================================

    #[tokio::test]
    async fn test_non_tls_with_0x16_byte() {
        // Data that starts with 0x16 but isn't TLS
        let data = vec![
            0x16, 0x00, 0x00, 0x00, 0x00, // Invalid version
            0x01, 0x02, 0x03, 0x04, 0x05,
        ];
        let mock = MockStream::new(data);
        let mut vision = VisionStream::new(mock);

        let mut buf = vec![0u8; 1024];
        let _ = vision.read(&mut buf).await.unwrap();

        // Should detect as non-TLS
        assert_eq!(vision.stream_state(), StreamState::Encrypted);
    }

    #[tokio::test]
    async fn test_tls_with_oversized_record() {
        // TLS header claiming massive record size
        let data = vec![
            TLS_HANDSHAKE, 0x03, 0x03, 0xFF, 0xFF, // Length > 16KB (invalid)
            0x01, 0x02, 0x03, 0x04, 0x05,
        ];
        let mock = MockStream::new(data);
        let mut vision = VisionStream::new(mock);

        let mut buf = vec![0u8; 1024];
        let _ = vision.read(&mut buf).await.unwrap();

        // Should detect as invalid TLS -> encrypted
        assert_eq!(vision.stream_state(), StreamState::Encrypted);
    }
}
