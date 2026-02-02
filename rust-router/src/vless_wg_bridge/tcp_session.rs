//! TCP Session State Machine for the VLESS-WG Bridge Event Bus Architecture
//!
//! This module provides the TCP session management for the smoltcp shard. Each
//! `TcpSession` represents a single TCP connection through the smoltcp stack,
//! tracking its state, statistics, and providing a channel for sending replies
//! back to the VLESS handler.
//!
//! # State Machine
//!
//! TCP sessions follow this state machine:
//!
//! ```text
//! Connecting ──(SYN-ACK)──► Established
//!      │                         │
//!      │ (timeout/error)         │ (recv FIN)
//!      ▼                         ▼
//!    Closed              CloseWait
//!                              │
//!                              │ (send FIN)
//!                              ▼
//!                          Closing
//!                              │
//!                              │ (TIME_WAIT/ACK)
//!                              ▼
//!                            Closed
//! ```
//!
//! # Usage
//!
//! ```ignore
//! use rust_router::vless_wg_bridge::tcp_session::{TcpSession, TcpSessionState};
//! use rust_router::smoltcp_utils::ConnId;
//! use tokio::sync::mpsc;
//!
//! let conn_id = ConnId::from_raw(42);
//! let (reply_tx, mut reply_rx) = mpsc::channel(32);
//!
//! let mut session = TcpSession::new(
//!     conn_id,
//!     socket_handle,
//!     "93.184.216.34:80".parse().unwrap(),
//!     reply_tx,
//! );
//!
//! // Connection established
//! session.set_connected();
//! assert!(session.is_connected());
//!
//! // Record some activity
//! session.record_sent(100);
//! session.record_received(200);
//! session.touch();
//!
//! // Check if timed out
//! if session.is_timed_out(Duration::from_secs(300)) {
//!     session.set_closed();
//! }
//! ```

use std::net::SocketAddr;
use std::time::Duration;

use bytes::Bytes;
use smoltcp::iface::SocketHandle;
use tokio::sync::mpsc;
use tokio::time::Instant;

use crate::netbridge::ConnId;

use super::events::TcpReply;

// =============================================================================
// TCP Session State
// =============================================================================

/// TCP connection state machine
///
/// These states track the lifecycle of a TCP connection through smoltcp.
/// The state machine follows RFC 793 but is simplified for proxy use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TcpSessionState {
    /// Connection attempt in progress (SYN sent, waiting for SYN-ACK)
    ///
    /// This is the initial state after creating a TCP socket and calling
    /// `connect()`. The connection will transition to `Established` upon
    /// successful handshake or `Closed` on timeout/error.
    Connecting,

    /// Connection fully established (ESTABLISHED state)
    ///
    /// Data can be sent and received in this state. This is the normal
    /// operating state for the connection.
    Established,

    /// Remote peer closed their write side (received FIN)
    ///
    /// The connection is half-closed: we can still send data, but the
    /// remote will not send any more data. Typically we should finish
    /// sending any pending data and then close our side.
    CloseWait,

    /// We initiated close (sent FIN, waiting for ACK)
    ///
    /// We've finished sending data and sent a FIN. Waiting for the
    /// remote to acknowledge. The connection will transition to `Closed`
    /// when the close handshake completes.
    Closing,

    /// Connection fully closed
    ///
    /// The connection is terminated. All resources should be released.
    /// This is a terminal state.
    Closed,
}

impl TcpSessionState {
    /// Check if this is a terminal state (connection ended)
    ///
    /// Returns `true` only for `Closed` state.
    #[must_use]
    #[inline]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Closed)
    }

    /// Check if data can be sent in this state
    ///
    /// Returns `true` only for `Established` state. In `CloseWait` we
    /// *could* technically send data, but for simplicity we don't allow
    /// new data in that state (should be draining buffers).
    #[must_use]
    #[inline]
    pub const fn can_send(self) -> bool {
        matches!(self, Self::Established)
    }

    /// Check if data can be received in this state
    ///
    /// Returns `true` for `Established` and `CloseWait` states. In
    /// `CloseWait`, the remote may have sent data before the FIN that
    /// we haven't processed yet.
    #[must_use]
    #[inline]
    pub const fn can_receive(self) -> bool {
        matches!(self, Self::Established | Self::CloseWait)
    }

    /// Get a human-readable description of the state
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Connecting => "connecting",
            Self::Established => "established",
            Self::CloseWait => "close-wait",
            Self::Closing => "closing",
            Self::Closed => "closed",
        }
    }
}

impl std::fmt::Display for TcpSessionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl Default for TcpSessionState {
    fn default() -> Self {
        Self::Connecting
    }
}

// =============================================================================
// TCP Session
// =============================================================================

/// A TCP session managed by the smoltcp shard
///
/// Each session represents a single TCP connection from a VLESS client to a
/// remote server, routed through the smoltcp userspace TCP/IP stack.
///
/// # Thread Safety
///
/// `TcpSession` is designed to be owned by a single shard task. The `reply_tx`
/// channel allows asynchronous communication back to the VLESS handler task
/// without requiring shared state.
///
/// # Lifecycle
///
/// 1. Created when `BridgeEvent::TcpConnect` is processed
/// 2. Transitions through states based on TCP handshake progress
/// 3. Removed when connection closes or times out
pub struct TcpSession {
    /// Unique connection identifier
    conn_id: ConnId,
    /// smoltcp socket handle
    socket_handle: SocketHandle,
    /// Destination address (remote server)
    dest_addr: SocketAddr,
    /// Current connection state
    state: TcpSessionState,
    /// Channel for sending replies to the VLESS handler
    reply_tx: mpsc::Sender<TcpReply>,
    /// When the session was created
    created_at: Instant,
    /// Last activity timestamp (data sent/received)
    last_activity: Instant,
    /// Total bytes sent to the remote server
    bytes_sent: u64,
    /// Total bytes received from the remote server
    bytes_received: u64,
    /// Pending data that couldn't be sent due to full buffer
    pending_data: Option<Bytes>,
}

impl TcpSession {
    /// Create a new TCP session
    ///
    /// The session starts in `Connecting` state, waiting for the TCP
    /// handshake to complete.
    ///
    /// # Arguments
    ///
    /// * `conn_id` - Unique connection identifier from `ConnIdAllocator`
    /// * `socket_handle` - smoltcp socket handle for this connection
    /// * `dest_addr` - Remote server address
    /// * `reply_tx` - Channel for sending replies back to VLESS handler
    #[must_use]
    pub fn new(
        conn_id: ConnId,
        socket_handle: SocketHandle,
        dest_addr: SocketAddr,
        reply_tx: mpsc::Sender<TcpReply>,
    ) -> Self {
        let now = Instant::now();
        Self {
            conn_id,
            socket_handle,
            dest_addr,
            state: TcpSessionState::Connecting,
            reply_tx,
            created_at: now,
            last_activity: now,
            bytes_sent: 0,
            bytes_received: 0,
            pending_data: None,
        }
    }

    // -------------------------------------------------------------------------
    // Getters
    // -------------------------------------------------------------------------

    /// Get the connection ID
    #[must_use]
    #[inline]
    pub fn conn_id(&self) -> ConnId {
        self.conn_id
    }

    /// Get the smoltcp socket handle
    #[must_use]
    #[inline]
    pub fn socket_handle(&self) -> SocketHandle {
        self.socket_handle
    }

    /// Get the destination address
    #[must_use]
    #[inline]
    pub fn dest_addr(&self) -> SocketAddr {
        self.dest_addr
    }

    /// Get the current session state
    #[must_use]
    #[inline]
    pub fn state(&self) -> TcpSessionState {
        self.state
    }

    /// Get a reference to the reply channel
    #[must_use]
    #[inline]
    pub fn reply_tx(&self) -> &mpsc::Sender<TcpReply> {
        &self.reply_tx
    }

    /// Get the session creation time
    #[must_use]
    #[inline]
    pub fn created_at(&self) -> Instant {
        self.created_at
    }

    /// Get the last activity time
    #[must_use]
    #[inline]
    pub fn last_activity(&self) -> Instant {
        self.last_activity
    }

    /// Get total bytes sent
    #[must_use]
    #[inline]
    pub fn bytes_sent(&self) -> u64 {
        self.bytes_sent
    }

    /// Get total bytes received
    #[must_use]
    #[inline]
    pub fn bytes_received(&self) -> u64 {
        self.bytes_received
    }

    // -------------------------------------------------------------------------
    // State Queries
    // -------------------------------------------------------------------------

    /// Check if the connection is in the established state
    #[must_use]
    #[inline]
    pub fn is_connected(&self) -> bool {
        self.state == TcpSessionState::Established
    }

    /// Check if the connection is closed (terminal state)
    #[must_use]
    #[inline]
    pub fn is_closed(&self) -> bool {
        self.state.is_terminal()
    }

    /// Check if the connection is still in the connecting phase
    #[must_use]
    #[inline]
    pub fn is_connecting(&self) -> bool {
        self.state == TcpSessionState::Connecting
    }

    /// Check if we can send data (only in Established state)
    #[must_use]
    #[inline]
    pub fn can_send(&self) -> bool {
        self.state.can_send()
    }

    /// Check if we can receive data (Established or CloseWait)
    #[must_use]
    #[inline]
    pub fn can_receive(&self) -> bool {
        self.state.can_receive()
    }

    // -------------------------------------------------------------------------
    // State Transitions
    // -------------------------------------------------------------------------

    /// Transition to connected state (TCP handshake completed)
    ///
    /// Should be called when the smoltcp socket transitions to the
    /// `Established` state after successful SYN-ACK exchange.
    ///
    /// This also updates the last activity timestamp.
    pub fn set_connected(&mut self) {
        if self.state == TcpSessionState::Connecting {
            self.state = TcpSessionState::Established;
            self.last_activity = Instant::now();
        }
    }

    /// Alias for `set_connected()` - transition to established state
    ///
    /// This is an alias to match the smoltcp naming convention.
    pub fn set_established(&mut self) {
        self.set_connected();
    }

    /// Transition to close-wait state (received FIN from remote)
    ///
    /// Should be called when the remote peer sends a FIN, indicating
    /// they won't send any more data. We may still have data to send.
    pub fn set_close_wait(&mut self) {
        if self.state == TcpSessionState::Established {
            self.state = TcpSessionState::CloseWait;
            self.last_activity = Instant::now();
        }
    }

    /// Transition to closing state (we sent FIN)
    ///
    /// Should be called when we initiate close by sending a FIN.
    /// This can happen from either Established or CloseWait states.
    pub fn set_closing(&mut self) {
        if matches!(
            self.state,
            TcpSessionState::Established | TcpSessionState::CloseWait
        ) {
            self.state = TcpSessionState::Closing;
            self.last_activity = Instant::now();
        }
    }

    /// Transition to closed state (connection terminated)
    ///
    /// This is a terminal state. Can be reached from any state due to
    /// errors, timeouts, or normal connection close.
    pub fn set_closed(&mut self) {
        self.state = TcpSessionState::Closed;
        self.last_activity = Instant::now();
    }

    // -------------------------------------------------------------------------
    // Activity Tracking
    // -------------------------------------------------------------------------

    /// Update the last activity timestamp
    ///
    /// Should be called whenever there's activity on the connection
    /// (data sent, data received, state change, etc.)
    pub fn touch(&mut self) {
        self.last_activity = Instant::now();
    }

    /// Record bytes sent and update activity timestamp
    ///
    /// # Arguments
    ///
    /// * `bytes` - Number of bytes sent
    pub fn record_sent(&mut self, bytes: u64) {
        self.bytes_sent = self.bytes_sent.saturating_add(bytes);
        self.last_activity = Instant::now();
    }

    /// Record bytes received and update activity timestamp
    ///
    /// # Arguments
    ///
    /// * `bytes` - Number of bytes received
    pub fn record_received(&mut self, bytes: u64) {
        self.bytes_received = self.bytes_received.saturating_add(bytes);
        self.last_activity = Instant::now();
    }

    // -------------------------------------------------------------------------
    // Pending Data Buffering
    // -------------------------------------------------------------------------

    /// Queue data that couldn't be sent due to full socket buffer
    ///
    /// If there's already pending data, the new data is appended to it.
    /// This is used when `socket.send_slice()` can't send all data or
    /// when the socket can't send at all.
    pub fn queue_pending_data(&mut self, data: Bytes) {
        if let Some(existing) = self.pending_data.take() {
            // Concatenate with existing pending data
            let mut combined = existing.to_vec();
            combined.extend_from_slice(&data);
            self.pending_data = Some(Bytes::from(combined));
        } else {
            self.pending_data = Some(data);
        }
    }

    /// Take the pending data, leaving None in its place
    ///
    /// Returns the pending data if any exists, allowing the caller to
    /// attempt sending it again.
    pub fn take_pending_data(&mut self) -> Option<Bytes> {
        self.pending_data.take()
    }

    /// Check if there's pending data waiting to be sent
    #[must_use]
    pub fn has_pending_data(&self) -> bool {
        self.pending_data.is_some()
    }

    /// Get the amount of pending data in bytes
    #[must_use]
    pub fn pending_data_len(&self) -> usize {
        self.pending_data.as_ref().map_or(0, |d| d.len())
    }

    // -------------------------------------------------------------------------
    // Timeout Handling
    // -------------------------------------------------------------------------

    /// Check if the session has timed out
    ///
    /// # Arguments
    ///
    /// * `timeout` - Maximum allowed idle duration
    ///
    /// # Returns
    ///
    /// `true` if the session has been idle longer than `timeout`
    #[must_use]
    pub fn is_timed_out(&self, timeout: Duration) -> bool {
        self.idle_duration() >= timeout
    }

    /// Get the duration since last activity
    #[must_use]
    pub fn idle_duration(&self) -> Duration {
        self.last_activity.elapsed()
    }

    /// Get the total session age
    #[must_use]
    pub fn age(&self) -> Duration {
        self.created_at.elapsed()
    }

    // -------------------------------------------------------------------------
    // Reply Sending
    // -------------------------------------------------------------------------

    /// Send a reply to the VLESS handler
    ///
    /// This is an async operation that may fail if the receiver has been
    /// dropped (e.g., VLESS connection closed).
    ///
    /// # Arguments
    ///
    /// * `reply` - The reply to send
    ///
    /// # Errors
    ///
    /// Returns `Err` if the channel is closed (receiver dropped).
    pub async fn send_reply(
        &self,
        reply: TcpReply,
    ) -> Result<(), mpsc::error::SendError<TcpReply>> {
        self.reply_tx.send(reply).await
    }

    /// Try to send a reply without blocking
    ///
    /// This is useful in sync contexts or when you don't want to wait
    /// for channel capacity.
    ///
    /// # Arguments
    ///
    /// * `reply` - The reply to send
    ///
    /// # Returns
    ///
    /// `Ok(())` if sent successfully, `Err` with the reply if the channel
    /// is full or closed.
    pub fn try_send_reply(
        &self,
        reply: TcpReply,
    ) -> Result<(), mpsc::error::TrySendError<TcpReply>> {
        self.reply_tx.try_send(reply)
    }

    /// Check if the reply channel is closed
    ///
    /// Returns `true` if the receiver has been dropped.
    #[must_use]
    pub fn is_reply_channel_closed(&self) -> bool {
        self.reply_tx.is_closed()
    }
}

impl std::fmt::Debug for TcpSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TcpSession")
            .field("conn_id", &self.conn_id)
            .field("socket_handle", &self.socket_handle)
            .field("dest_addr", &self.dest_addr)
            .field("state", &self.state)
            .field("bytes_sent", &self.bytes_sent)
            .field("bytes_received", &self.bytes_received)
            .field("age_ms", &self.age().as_millis())
            .field("idle_ms", &self.idle_duration().as_millis())
            .finish_non_exhaustive()
    }
}

impl std::fmt::Display for TcpSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "TcpSession({} -> {}, state={}, tx={}, rx={})",
            self.conn_id,
            self.dest_addr,
            self.state,
            self.bytes_sent,
            self.bytes_received
        )
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use std::net::{Ipv4Addr, SocketAddrV4};

    /// Create a mock socket handle for testing
    fn mock_socket_handle(id: usize) -> SocketHandle {
        // SAFETY: SocketHandle is a transparent wrapper around usize.
        // This is only for testing purposes.
        unsafe { std::mem::transmute(id) }
    }

    fn make_dest_addr() -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(93, 184, 216, 34), 80))
    }

    // -------------------------------------------------------------------------
    // TcpSessionState tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_state_is_terminal() {
        assert!(!TcpSessionState::Connecting.is_terminal());
        assert!(!TcpSessionState::Established.is_terminal());
        assert!(!TcpSessionState::CloseWait.is_terminal());
        assert!(!TcpSessionState::Closing.is_terminal());
        assert!(TcpSessionState::Closed.is_terminal());
    }

    #[test]
    fn test_state_can_send() {
        assert!(!TcpSessionState::Connecting.can_send());
        assert!(TcpSessionState::Established.can_send());
        assert!(!TcpSessionState::CloseWait.can_send());
        assert!(!TcpSessionState::Closing.can_send());
        assert!(!TcpSessionState::Closed.can_send());
    }

    #[test]
    fn test_state_can_receive() {
        assert!(!TcpSessionState::Connecting.can_receive());
        assert!(TcpSessionState::Established.can_receive());
        assert!(TcpSessionState::CloseWait.can_receive());
        assert!(!TcpSessionState::Closing.can_receive());
        assert!(!TcpSessionState::Closed.can_receive());
    }

    #[test]
    fn test_state_as_str() {
        assert_eq!(TcpSessionState::Connecting.as_str(), "connecting");
        assert_eq!(TcpSessionState::Established.as_str(), "established");
        assert_eq!(TcpSessionState::CloseWait.as_str(), "close-wait");
        assert_eq!(TcpSessionState::Closing.as_str(), "closing");
        assert_eq!(TcpSessionState::Closed.as_str(), "closed");
    }

    #[test]
    fn test_state_display() {
        assert_eq!(format!("{}", TcpSessionState::Connecting), "connecting");
        assert_eq!(format!("{}", TcpSessionState::Established), "established");
        assert_eq!(format!("{}", TcpSessionState::CloseWait), "close-wait");
        assert_eq!(format!("{}", TcpSessionState::Closing), "closing");
        assert_eq!(format!("{}", TcpSessionState::Closed), "closed");
    }

    #[test]
    fn test_state_default() {
        assert_eq!(TcpSessionState::default(), TcpSessionState::Connecting);
    }

    #[test]
    fn test_state_eq_hash() {
        use std::collections::HashSet;

        let mut set = HashSet::new();
        set.insert(TcpSessionState::Connecting);
        set.insert(TcpSessionState::Established);

        assert!(set.contains(&TcpSessionState::Connecting));
        assert!(set.contains(&TcpSessionState::Established));
        assert!(!set.contains(&TcpSessionState::Closed));
    }

    // -------------------------------------------------------------------------
    // TcpSession creation tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_session_new() {
        let conn_id = ConnId::from_raw(42);
        let socket_handle = mock_socket_handle(1);
        let dest_addr = make_dest_addr();
        let (reply_tx, _reply_rx) = mpsc::channel(32);

        let session = TcpSession::new(conn_id, socket_handle, dest_addr, reply_tx);

        assert_eq!(session.conn_id(), conn_id);
        assert_eq!(session.socket_handle(), socket_handle);
        assert_eq!(session.dest_addr(), dest_addr);
        assert_eq!(session.state(), TcpSessionState::Connecting);
        assert_eq!(session.bytes_sent(), 0);
        assert_eq!(session.bytes_received(), 0);
        assert!(session.is_connecting());
        assert!(!session.is_connected());
        assert!(!session.is_closed());
    }

    // -------------------------------------------------------------------------
    // State transition tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_session_connecting_to_established() {
        let conn_id = ConnId::from_raw(1);
        let (reply_tx, _reply_rx) = mpsc::channel(32);
        let mut session =
            TcpSession::new(conn_id, mock_socket_handle(1), make_dest_addr(), reply_tx);

        assert!(session.is_connecting());
        assert!(!session.can_send());
        assert!(!session.can_receive());

        session.set_connected();

        assert!(session.is_connected());
        assert!(session.can_send());
        assert!(session.can_receive());
        assert_eq!(session.state(), TcpSessionState::Established);
    }

    #[test]
    fn test_session_established_to_close_wait() {
        let conn_id = ConnId::from_raw(1);
        let (reply_tx, _reply_rx) = mpsc::channel(32);
        let mut session =
            TcpSession::new(conn_id, mock_socket_handle(1), make_dest_addr(), reply_tx);

        session.set_connected();
        assert!(session.is_connected());

        session.set_close_wait();
        assert_eq!(session.state(), TcpSessionState::CloseWait);
        assert!(!session.can_send()); // Simplified: no new sends in CloseWait
        assert!(session.can_receive()); // Can still receive buffered data
    }

    #[test]
    fn test_session_close_wait_to_closing() {
        let conn_id = ConnId::from_raw(1);
        let (reply_tx, _reply_rx) = mpsc::channel(32);
        let mut session =
            TcpSession::new(conn_id, mock_socket_handle(1), make_dest_addr(), reply_tx);

        session.set_connected();
        session.set_close_wait();

        session.set_closing();
        assert_eq!(session.state(), TcpSessionState::Closing);
        assert!(!session.can_send());
        assert!(!session.can_receive());
    }

    #[test]
    fn test_session_closing_to_closed() {
        let conn_id = ConnId::from_raw(1);
        let (reply_tx, _reply_rx) = mpsc::channel(32);
        let mut session =
            TcpSession::new(conn_id, mock_socket_handle(1), make_dest_addr(), reply_tx);

        session.set_connected();
        session.set_close_wait();
        session.set_closing();

        session.set_closed();
        assert!(session.is_closed());
        assert_eq!(session.state(), TcpSessionState::Closed);
    }

    #[test]
    fn test_session_established_to_closing() {
        let conn_id = ConnId::from_raw(1);
        let (reply_tx, _reply_rx) = mpsc::channel(32);
        let mut session =
            TcpSession::new(conn_id, mock_socket_handle(1), make_dest_addr(), reply_tx);

        session.set_connected();

        // Can go directly from Established to Closing (active close)
        session.set_closing();
        assert_eq!(session.state(), TcpSessionState::Closing);
    }

    #[test]
    fn test_session_connecting_to_closed_on_error() {
        let conn_id = ConnId::from_raw(1);
        let (reply_tx, _reply_rx) = mpsc::channel(32);
        let mut session =
            TcpSession::new(conn_id, mock_socket_handle(1), make_dest_addr(), reply_tx);

        // Can go directly from Connecting to Closed on connection failure
        session.set_closed();
        assert!(session.is_closed());
    }

    #[test]
    fn test_state_transition_guards() {
        let conn_id = ConnId::from_raw(1);
        let (reply_tx, _reply_rx) = mpsc::channel(32);
        let mut session =
            TcpSession::new(conn_id, mock_socket_handle(1), make_dest_addr(), reply_tx);

        // Can't go to CloseWait from Connecting
        session.set_close_wait();
        assert_eq!(session.state(), TcpSessionState::Connecting);

        // Can't go to Closing from Connecting
        session.set_closing();
        assert_eq!(session.state(), TcpSessionState::Connecting);

        // set_closed() always works
        session.set_closed();
        assert!(session.is_closed());
    }

    // -------------------------------------------------------------------------
    // Activity tracking tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_session_touch() {
        let conn_id = ConnId::from_raw(1);
        let (reply_tx, _reply_rx) = mpsc::channel(32);
        let mut session =
            TcpSession::new(conn_id, mock_socket_handle(1), make_dest_addr(), reply_tx);

        let initial_activity = session.last_activity();
        std::thread::sleep(std::time::Duration::from_millis(10));
        session.touch();

        assert!(session.last_activity() > initial_activity);
    }

    #[test]
    fn test_session_record_sent() {
        let conn_id = ConnId::from_raw(1);
        let (reply_tx, _reply_rx) = mpsc::channel(32);
        let mut session =
            TcpSession::new(conn_id, mock_socket_handle(1), make_dest_addr(), reply_tx);

        assert_eq!(session.bytes_sent(), 0);

        session.record_sent(100);
        assert_eq!(session.bytes_sent(), 100);

        session.record_sent(50);
        assert_eq!(session.bytes_sent(), 150);
    }

    #[test]
    fn test_session_record_received() {
        let conn_id = ConnId::from_raw(1);
        let (reply_tx, _reply_rx) = mpsc::channel(32);
        let mut session =
            TcpSession::new(conn_id, mock_socket_handle(1), make_dest_addr(), reply_tx);

        assert_eq!(session.bytes_received(), 0);

        session.record_received(200);
        assert_eq!(session.bytes_received(), 200);

        session.record_received(100);
        assert_eq!(session.bytes_received(), 300);
    }

    #[test]
    fn test_session_record_updates_activity() {
        let conn_id = ConnId::from_raw(1);
        let (reply_tx, _reply_rx) = mpsc::channel(32);
        let mut session =
            TcpSession::new(conn_id, mock_socket_handle(1), make_dest_addr(), reply_tx);

        let initial_activity = session.last_activity();
        std::thread::sleep(std::time::Duration::from_millis(10));
        session.record_sent(100);

        assert!(session.last_activity() > initial_activity);

        let sent_activity = session.last_activity();
        std::thread::sleep(std::time::Duration::from_millis(10));
        session.record_received(100);

        assert!(session.last_activity() > sent_activity);
    }

    #[test]
    fn test_session_bytes_saturating() {
        let conn_id = ConnId::from_raw(1);
        let (reply_tx, _reply_rx) = mpsc::channel(32);
        let mut session =
            TcpSession::new(conn_id, mock_socket_handle(1), make_dest_addr(), reply_tx);

        session.record_sent(u64::MAX);
        session.record_sent(1);
        assert_eq!(session.bytes_sent(), u64::MAX); // Saturated

        session.record_received(u64::MAX);
        session.record_received(1);
        assert_eq!(session.bytes_received(), u64::MAX); // Saturated
    }

    // -------------------------------------------------------------------------
    // Timeout tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_session_idle_duration() {
        let conn_id = ConnId::from_raw(1);
        let (reply_tx, _reply_rx) = mpsc::channel(32);
        let session = TcpSession::new(conn_id, mock_socket_handle(1), make_dest_addr(), reply_tx);

        // Immediately after creation, idle duration should be very small
        assert!(session.idle_duration() < Duration::from_millis(100));
    }

    #[test]
    fn test_session_is_timed_out() {
        let conn_id = ConnId::from_raw(1);
        let (reply_tx, _reply_rx) = mpsc::channel(32);
        let session = TcpSession::new(conn_id, mock_socket_handle(1), make_dest_addr(), reply_tx);

        // With zero timeout, should immediately be timed out
        assert!(session.is_timed_out(Duration::ZERO));

        // With long timeout, should not be timed out
        assert!(!session.is_timed_out(Duration::from_secs(3600)));
    }

    #[test]
    fn test_session_age() {
        let conn_id = ConnId::from_raw(1);
        let (reply_tx, _reply_rx) = mpsc::channel(32);
        let session = TcpSession::new(conn_id, mock_socket_handle(1), make_dest_addr(), reply_tx);

        // Age should be at least 0
        assert!(session.age() >= Duration::ZERO);
    }

    // -------------------------------------------------------------------------
    // Reply channel tests
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn test_session_send_reply() {
        let conn_id = ConnId::from_raw(1);
        let (reply_tx, mut reply_rx) = mpsc::channel(32);
        let session = TcpSession::new(conn_id, mock_socket_handle(1), make_dest_addr(), reply_tx);

        // Send a reply
        let result = session.send_reply(TcpReply::Connected).await;
        assert!(result.is_ok());

        // Receive it
        let received = reply_rx.recv().await;
        assert!(matches!(received, Some(TcpReply::Connected)));
    }

    #[tokio::test]
    async fn test_session_send_reply_with_data() {
        let conn_id = ConnId::from_raw(1);
        let (reply_tx, mut reply_rx) = mpsc::channel(32);
        let session = TcpSession::new(conn_id, mock_socket_handle(1), make_dest_addr(), reply_tx);

        // Send data reply
        let data = Bytes::from_static(b"Hello, World!");
        let result = session
            .send_reply(TcpReply::Data { data: data.clone() })
            .await;
        assert!(result.is_ok());

        // Receive it
        let received = reply_rx.recv().await;
        match received {
            Some(TcpReply::Data { data: received_data }) => {
                assert_eq!(received_data, data);
            }
            _ => panic!("Expected Data reply"),
        }
    }

    #[tokio::test]
    async fn test_session_send_reply_closed_channel() {
        let conn_id = ConnId::from_raw(1);
        let (reply_tx, reply_rx) = mpsc::channel(32);
        let session = TcpSession::new(conn_id, mock_socket_handle(1), make_dest_addr(), reply_tx);

        // Drop the receiver
        drop(reply_rx);

        // Send should fail
        let result = session.send_reply(TcpReply::Connected).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_session_try_send_reply() {
        let conn_id = ConnId::from_raw(1);
        let (reply_tx, _reply_rx) = mpsc::channel(32);
        let session = TcpSession::new(conn_id, mock_socket_handle(1), make_dest_addr(), reply_tx);

        // Try send should succeed with available capacity
        let result = session.try_send_reply(TcpReply::Connected);
        assert!(result.is_ok());
    }

    #[test]
    fn test_session_try_send_reply_full_channel() {
        let conn_id = ConnId::from_raw(1);
        let (reply_tx, _reply_rx) = mpsc::channel(1); // Capacity of 1
        let session = TcpSession::new(conn_id, mock_socket_handle(1), make_dest_addr(), reply_tx);

        // First send should succeed
        let result1 = session.try_send_reply(TcpReply::Connected);
        assert!(result1.is_ok());

        // Second send should fail (channel full)
        let result2 = session.try_send_reply(TcpReply::Connected);
        assert!(result2.is_err());
    }

    #[test]
    fn test_session_is_reply_channel_closed() {
        let conn_id = ConnId::from_raw(1);
        let (reply_tx, reply_rx) = mpsc::channel(32);
        let session = TcpSession::new(conn_id, mock_socket_handle(1), make_dest_addr(), reply_tx);

        assert!(!session.is_reply_channel_closed());

        drop(reply_rx);

        assert!(session.is_reply_channel_closed());
    }

    // -------------------------------------------------------------------------
    // Debug and Display tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_session_debug() {
        let conn_id = ConnId::from_raw(42);
        let (reply_tx, _reply_rx) = mpsc::channel(32);
        let session = TcpSession::new(conn_id, mock_socket_handle(1), make_dest_addr(), reply_tx);

        let debug = format!("{:?}", session);
        assert!(debug.contains("TcpSession"));
        assert!(debug.contains("conn_id"));
        assert!(debug.contains("state"));
        assert!(debug.contains("bytes_sent"));
        assert!(debug.contains("bytes_received"));
    }

    #[test]
    fn test_session_display() {
        let conn_id = ConnId::from_raw(42);
        let (reply_tx, _reply_rx) = mpsc::channel(32);
        let mut session = TcpSession::new(
            conn_id,
            mock_socket_handle(1),
            "93.184.216.34:80".parse().unwrap(),
            reply_tx,
        );

        session.set_connected();
        session.record_sent(100);
        session.record_received(200);

        let display = format!("{}", session);
        assert!(display.contains("TcpSession"));
        assert!(display.contains("93.184.216.34:80"));
        assert!(display.contains("established"));
        assert!(display.contains("tx=100"));
        assert!(display.contains("rx=200"));
    }

    // -------------------------------------------------------------------------
    // Full lifecycle test
    // -------------------------------------------------------------------------

    #[tokio::test]
    async fn test_session_full_lifecycle() {
        let conn_id = ConnId::from_raw(1);
        let (reply_tx, mut reply_rx) = mpsc::channel(32);
        let mut session =
            TcpSession::new(conn_id, mock_socket_handle(1), make_dest_addr(), reply_tx);

        // Initial state
        assert!(session.is_connecting());

        // Connected
        session.set_connected();
        session.send_reply(TcpReply::Connected).await.unwrap();
        assert!(session.is_connected());

        // Receive data
        session.record_received(100);
        session
            .send_reply(TcpReply::Data {
                data: Bytes::from_static(b"test"),
            })
            .await
            .unwrap();

        // Send data
        session.record_sent(50);

        // Remote closes
        session.set_close_wait();
        session.send_reply(TcpReply::RemoteClosed).await.unwrap();

        // We close
        session.set_closing();
        session.set_closed();
        session.send_reply(TcpReply::Closed).await.unwrap();

        assert!(session.is_closed());
        assert_eq!(session.bytes_sent(), 50);
        assert_eq!(session.bytes_received(), 100);

        // Verify all replies received
        assert!(matches!(reply_rx.recv().await, Some(TcpReply::Connected)));
        assert!(matches!(reply_rx.recv().await, Some(TcpReply::Data { .. })));
        assert!(matches!(
            reply_rx.recv().await,
            Some(TcpReply::RemoteClosed)
        ));
        assert!(matches!(reply_rx.recv().await, Some(TcpReply::Closed)));
    }
}
