//! RAII guards for smoltcp socket handles
//!
//! Ensures sockets are properly cleaned up on all code paths,
//! including early returns and panics.
//!
//! # Problem
//!
//! Manual socket cleanup is error-prone. Early returns, panics, or forgotten
//! cleanup paths can leak sockets, eventually exhausting the socket pool.
//!
//! # Solution
//!
//! The `TcpSocketGuard` and `UdpSocketGuard` types wrap socket handles and
//! automatically clean them up when dropped. This ensures:
//!
//! - Sockets are always closed (FIN) or aborted (RST)
//! - Socket handles are removed from the socket set
//! - No socket leaks on early returns or panics
//!
//! # Deferred Cleanup
//!
//! When `try_lock()` fails in `Drop`, orphaned sockets are sent to a deferred
//! cleanup channel. A background task (spawned via `spawn_cleanup_task`) processes
//! these orphaned sockets asynchronously, ensuring no socket leaks even under
//! lock contention.
//!
//! # Example
//!
//! ```ignore
//! use std::sync::Arc;
//! use tokio::sync::Mutex;
//! use rust_router::smoltcp_utils::TcpSocketGuard;
//! use rust_router::tunnel::smoltcp_bridge::SmoltcpBridge;
//!
//! async fn handle_connection(bridge: Arc<Mutex<SmoltcpBridge>>) {
//!     let handle = {
//!         let mut b = bridge.lock().await;
//!         b.create_tcp_socket_default().unwrap()
//!     };
//!
//!     // Socket is automatically cleaned up when guard is dropped
//!     let guard = TcpSocketGuard::new(bridge.clone(), handle);
//!
//!     // Even if we return early here, the socket is cleaned up
//!     if some_condition {
//!         return; // guard drops, socket cleaned up
//!     }
//!
//!     // ... use the socket ...
//!
//!     // For graceful close, call close_gracefully()
//!     guard.close_gracefully().await;
//! }
//! ```
//!
//! # Thread Safety
//!
//! Both guard types are `Send + Sync` as they hold `Arc<Mutex<SmoltcpBridge>>`.
//! The `Drop` implementation uses `try_lock()` which may fail if the lock is held
//! elsewhere. In that case, cleanup is deferred to a background task via the
//! cleanup channel.

use std::sync::{Arc, OnceLock};

use smoltcp::iface::SocketHandle;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, trace, warn};

use crate::tunnel::smoltcp_bridge::SmoltcpBridge;

// =============================================================================
// Deferred Cleanup Channel
// =============================================================================

/// Entry for deferred socket cleanup
struct OrphanedSocket {
    /// The smoltcp bridge
    bridge: Arc<Mutex<SmoltcpBridge>>,
    /// The socket handle to clean up
    handle: SocketHandle,
    /// Whether to abort (RST) or close (FIN) for TCP
    abort: bool,
    /// Whether this is a TCP socket (true) or UDP socket (false)
    is_tcp: bool,
}

/// Global cleanup channel sender
static CLEANUP_TX: OnceLock<mpsc::UnboundedSender<OrphanedSocket>> = OnceLock::new();

/// Receiver for orphaned socket cleanup
///
/// This is an opaque wrapper around the channel receiver, used to pass
/// to `run_cleanup_task`. Created by `init_cleanup_channel`.
pub struct SocketCleanupReceiver {
    rx: mpsc::UnboundedReceiver<OrphanedSocket>,
}

/// Initialize the cleanup channel and return the receiver
///
/// This should be called once at startup. Returns the receiver that should
/// be passed to `run_cleanup_task`.
///
/// # Returns
///
/// `Some(receiver)` on first call, `None` on subsequent calls.
#[must_use]
pub fn init_cleanup_channel() -> Option<SocketCleanupReceiver> {
    let (tx, rx) = mpsc::unbounded_channel();
    if CLEANUP_TX.set(tx).is_ok() {
        Some(SocketCleanupReceiver { rx })
    } else {
        None
    }
}

/// Spawn the background cleanup task
///
/// This task processes orphaned sockets that couldn't be cleaned up in `Drop`
/// due to lock contention. Call this once at startup with the receiver from
/// `init_cleanup_channel()`.
///
/// # Example
///
/// ```ignore
/// if let Some(rx) = init_cleanup_channel() {
///     tokio::spawn(run_cleanup_task(rx));
/// }
/// ```
pub async fn run_cleanup_task(receiver: SocketCleanupReceiver) {
    debug!("Socket cleanup task started");
    let mut rx = receiver.rx;

    while let Some(orphan) = rx.recv().await {
        // Acquire lock and clean up
        let mut bridge = orphan.bridge.lock().await;

        if orphan.is_tcp {
            if orphan.abort {
                debug!(
                    "Deferred cleanup: aborting TCP socket {:?} (RST)",
                    orphan.handle
                );
                bridge.tcp_abort(orphan.handle);
            } else {
                debug!(
                    "Deferred cleanup: closing TCP socket {:?} (FIN)",
                    orphan.handle
                );
                bridge.tcp_close(orphan.handle);
            }
        } else {
            debug!("Deferred cleanup: closing UDP socket {:?}", orphan.handle);
            bridge.udp_close(orphan.handle);
        }

        bridge.poll();
        bridge.remove_socket(orphan.handle);
    }

    debug!("Socket cleanup task stopped");
}

/// Send an orphaned socket to the cleanup channel
///
/// Returns true if successfully queued, false if the channel is not initialized
/// or is closed.
fn queue_orphan_cleanup(
    bridge: Arc<Mutex<SmoltcpBridge>>,
    handle: SocketHandle,
    abort: bool,
    is_tcp: bool,
) -> bool {
    if let Some(tx) = CLEANUP_TX.get() {
        let orphan = OrphanedSocket {
            bridge,
            handle,
            abort,
            is_tcp,
        };
        if tx.send(orphan).is_ok() {
            debug!(
                "Queued orphaned {} socket {:?} for deferred cleanup",
                if is_tcp { "TCP" } else { "UDP" },
                handle
            );
            return true;
        }
    }
    false
}

/// RAII guard for TCP socket handles
///
/// Ensures the socket is properly closed (FIN) or aborted (RST) and removed
/// from the socket set when the guard is dropped.
///
/// # Default Behavior
///
/// By default, the socket is **aborted** (RST sent) on drop. This is the safe
/// default because:
///
/// - It immediately releases resources
/// - It signals an error condition to the remote peer
/// - It prevents lingering in intermediate TCP states
///
/// For graceful shutdown (FIN), call `set_graceful_close()` or use
/// `close_gracefully()` to consume the guard.
///
/// # Thread Safety
///
/// The guard holds an `Arc<Mutex<SmoltcpBridge>>` and is `Send + Sync`.
/// However, the `Drop` implementation uses `try_lock()` which may fail
/// if the lock is held elsewhere. In that case, a warning is logged
/// and the socket may be orphaned until smoltcp times it out.
///
/// # Example
///
/// ```ignore
/// use std::sync::Arc;
/// use tokio::sync::Mutex;
/// use rust_router::smoltcp_utils::TcpSocketGuard;
///
/// async fn example(bridge: Arc<Mutex<SmoltcpBridge>>) {
///     let handle = {
///         let mut b = bridge.lock().await;
///         b.create_tcp_socket_default().unwrap()
///     };
///
///     // Default: abort on drop
///     let guard = TcpSocketGuard::new(bridge.clone(), handle);
///
///     // Configure for graceful close
///     let mut guard = TcpSocketGuard::new(bridge.clone(), handle);
///     guard.set_graceful_close();
///
///     // Or use the async method for immediate graceful close
///     guard.close_gracefully().await;
/// }
/// ```
pub struct TcpSocketGuard {
    /// Shared reference to the smoltcp bridge
    bridge: Arc<Mutex<SmoltcpBridge>>,
    /// Socket handle (None if taken)
    handle: Option<SocketHandle>,
    /// Whether to send RST instead of FIN on drop
    abort_on_drop: bool,
}

impl TcpSocketGuard {
    /// Create a new TCP socket guard
    ///
    /// # Arguments
    ///
    /// * `bridge` - Shared reference to the smoltcp bridge
    /// * `handle` - The socket handle to guard
    #[must_use]
    pub fn new(bridge: Arc<Mutex<SmoltcpBridge>>, handle: SocketHandle) -> Self {
        trace!("TcpSocketGuard created for handle {:?}", handle);
        Self {
            bridge,
            handle: Some(handle),
            abort_on_drop: true, // Default to RST for safety
        }
    }

    /// Get the socket handle
    ///
    /// # Panics
    ///
    /// Panics if the handle has already been taken via `take()`.
    #[must_use]
    pub fn handle(&self) -> SocketHandle {
        self.handle.expect("socket handle already taken")
    }

    /// Get the socket handle if it hasn't been taken
    #[must_use]
    pub fn handle_opt(&self) -> Option<SocketHandle> {
        self.handle
    }

    /// Set whether to abort (RST) on drop instead of close (FIN)
    ///
    /// By default, the socket is aborted on drop for safety.
    /// Call `set_graceful_close()` to send FIN instead.
    pub fn set_abort_on_drop(&mut self, abort: bool) {
        self.abort_on_drop = abort;
    }

    /// Configure for graceful close (FIN) on drop
    ///
    /// This changes the default behavior from sending RST to sending FIN
    /// when the guard is dropped.
    pub fn set_graceful_close(&mut self) {
        self.abort_on_drop = false;
    }

    /// Take ownership of the handle, preventing automatic cleanup
    ///
    /// Use this when you need to manually control socket lifecycle.
    /// After calling this, you are responsible for cleanup.
    ///
    /// # Panics
    ///
    /// Panics if the handle has already been taken.
    #[must_use]
    pub fn take(mut self) -> SocketHandle {
        self.handle.take().expect("socket handle already taken")
    }

    /// Close the socket gracefully (send FIN) and remove from socket set
    ///
    /// This consumes the guard and performs a graceful TCP close:
    ///
    /// 1. Sends FIN to the remote peer
    /// 2. Polls smoltcp to transmit the FIN
    /// 3. Waits briefly for the FIN to be processed
    /// 4. Removes the socket from the socket set
    pub async fn close_gracefully(mut self) {
        if let Some(handle) = self.handle.take() {
            debug!(
                "TcpSocketGuard: closing socket {:?} gracefully (FIN)",
                handle
            );
            let mut bridge = self.bridge.lock().await;
            bridge.tcp_close(handle);
            bridge.poll(); // Allow FIN to be sent
            // Give time for FIN to be processed
            drop(bridge);
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            // Now remove the socket
            let mut bridge = self.bridge.lock().await;
            bridge.remove_socket(handle);
        }
    }

    /// Abort the socket (send RST) and remove from socket set
    ///
    /// This consumes the guard and immediately terminates the connection:
    ///
    /// 1. Sends RST to the remote peer
    /// 2. Polls smoltcp to transmit the RST
    /// 3. Removes the socket from the socket set
    pub async fn abort(mut self) {
        if let Some(handle) = self.handle.take() {
            debug!("TcpSocketGuard: aborting socket {:?} (RST)", handle);
            let mut bridge = self.bridge.lock().await;
            bridge.tcp_abort(handle);
            bridge.poll(); // Allow RST to be sent
            bridge.remove_socket(handle);
        }
    }

    /// Get a reference to the bridge
    ///
    /// This allows operations on the bridge while still maintaining
    /// the guard's ownership of the socket handle.
    #[must_use]
    pub fn bridge(&self) -> &Arc<Mutex<SmoltcpBridge>> {
        &self.bridge
    }
}

impl Drop for TcpSocketGuard {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            // We're in a sync context, so we need to use try_lock
            // If we can't get the lock, defer cleanup to the background task
            match self.bridge.try_lock() {
                Ok(mut bridge) => {
                    if self.abort_on_drop {
                        debug!("TcpSocketGuard drop: aborting socket {:?} (RST)", handle);
                        bridge.tcp_abort(handle);
                    } else {
                        debug!("TcpSocketGuard drop: closing socket {:?} (FIN)", handle);
                        bridge.tcp_close(handle);
                    }
                    bridge.poll();
                    bridge.remove_socket(handle);
                }
                Err(_) => {
                    // Can't get lock in sync context - defer to cleanup task
                    if !queue_orphan_cleanup(
                        Arc::clone(&self.bridge),
                        handle,
                        self.abort_on_drop,
                        true,
                    ) {
                        // Cleanup channel not initialized or closed
                        warn!(
                            "TcpSocketGuard: could not acquire lock or queue cleanup for socket {:?}, \
                             socket may be orphaned",
                            handle
                        );
                    }
                }
            }
        }
    }
}

/// RAII guard for UDP socket handles
///
/// Simpler than TCP since UDP has no connection state. The socket is
/// simply closed and removed from the socket set on drop.
///
/// # Thread Safety
///
/// Same considerations as `TcpSocketGuard` - uses `try_lock()` in drop.
///
/// # Example
///
/// ```ignore
/// use std::sync::Arc;
/// use tokio::sync::Mutex;
/// use rust_router::smoltcp_utils::UdpSocketGuard;
///
/// async fn example(bridge: Arc<Mutex<SmoltcpBridge>>) {
///     let handle = {
///         let mut b = bridge.lock().await;
///         b.create_udp_socket().unwrap()
///     };
///
///     let guard = UdpSocketGuard::new(bridge.clone(), handle);
///
///     // ... use the socket ...
///
///     // Socket closed on drop, or explicitly:
///     guard.close().await;
/// }
/// ```
pub struct UdpSocketGuard {
    /// Shared reference to the smoltcp bridge
    bridge: Arc<Mutex<SmoltcpBridge>>,
    /// Socket handle (None if taken)
    handle: Option<SocketHandle>,
}

impl UdpSocketGuard {
    /// Create a new UDP socket guard
    ///
    /// # Arguments
    ///
    /// * `bridge` - Shared reference to the smoltcp bridge
    /// * `handle` - The socket handle to guard
    #[must_use]
    pub fn new(bridge: Arc<Mutex<SmoltcpBridge>>, handle: SocketHandle) -> Self {
        trace!("UdpSocketGuard created for handle {:?}", handle);
        Self {
            bridge,
            handle: Some(handle),
        }
    }

    /// Get the socket handle
    ///
    /// # Panics
    ///
    /// Panics if the handle has already been taken via `take()`.
    #[must_use]
    pub fn handle(&self) -> SocketHandle {
        self.handle.expect("socket handle already taken")
    }

    /// Get the socket handle if it hasn't been taken
    #[must_use]
    pub fn handle_opt(&self) -> Option<SocketHandle> {
        self.handle
    }

    /// Take ownership of the handle, preventing automatic cleanup
    ///
    /// # Panics
    ///
    /// Panics if the handle has already been taken.
    #[must_use]
    pub fn take(mut self) -> SocketHandle {
        self.handle.take().expect("socket handle already taken")
    }

    /// Close the socket and remove from socket set
    ///
    /// This consumes the guard.
    pub async fn close(mut self) {
        if let Some(handle) = self.handle.take() {
            debug!("UdpSocketGuard: closing socket {:?}", handle);
            let mut bridge = self.bridge.lock().await;
            bridge.udp_close(handle);
            bridge.remove_socket(handle);
        }
    }

    /// Get a reference to the bridge
    #[must_use]
    pub fn bridge(&self) -> &Arc<Mutex<SmoltcpBridge>> {
        &self.bridge
    }
}

impl Drop for UdpSocketGuard {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            match self.bridge.try_lock() {
                Ok(mut bridge) => {
                    debug!("UdpSocketGuard drop: closing socket {:?}", handle);
                    bridge.udp_close(handle);
                    bridge.remove_socket(handle);
                }
                Err(_) => {
                    // Can't get lock in sync context - defer to cleanup task
                    if !queue_orphan_cleanup(
                        Arc::clone(&self.bridge),
                        handle,
                        false, // UDP doesn't have abort concept
                        false, // is_tcp = false
                    ) {
                        // Cleanup channel not initialized or closed
                        warn!(
                            "UdpSocketGuard: could not acquire lock or queue cleanup for socket {:?}, \
                             socket may be orphaned",
                            handle
                        );
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn create_test_bridge() -> Arc<Mutex<SmoltcpBridge>> {
        Arc::new(Mutex::new(SmoltcpBridge::new(
            Ipv4Addr::new(10, 0, 0, 1),
            1420,
        )))
    }

    #[tokio::test]
    async fn test_tcp_socket_guard_creation() {
        let bridge = create_test_bridge();
        let handle = {
            let mut b = bridge.lock().await;
            b.create_tcp_socket_default().unwrap()
        };

        let guard = TcpSocketGuard::new(bridge.clone(), handle);
        assert_eq!(guard.handle(), handle);
        assert_eq!(guard.handle_opt(), Some(handle));
    }

    #[tokio::test]
    async fn test_tcp_socket_guard_take() {
        let bridge = create_test_bridge();
        let handle = {
            let mut b = bridge.lock().await;
            b.create_tcp_socket_default().unwrap()
        };

        let guard = TcpSocketGuard::new(bridge.clone(), handle);
        let taken = guard.take();
        assert_eq!(taken, handle);

        // Socket should still exist since we took it
        let b = bridge.lock().await;
        assert_eq!(b.socket_count(), 1);
    }

    #[tokio::test]
    async fn test_tcp_socket_guard_abort() {
        let bridge = create_test_bridge();
        let handle = {
            let mut b = bridge.lock().await;
            b.create_tcp_socket_default().unwrap()
        };

        // Verify socket exists
        {
            let b = bridge.lock().await;
            assert_eq!(b.socket_count(), 1);
        }

        let guard = TcpSocketGuard::new(bridge.clone(), handle);
        guard.abort().await;

        // Socket should be removed
        let b = bridge.lock().await;
        assert_eq!(b.socket_count(), 0);
    }

    #[tokio::test]
    async fn test_tcp_socket_guard_close_gracefully() {
        let bridge = create_test_bridge();
        let handle = {
            let mut b = bridge.lock().await;
            b.create_tcp_socket_default().unwrap()
        };

        let guard = TcpSocketGuard::new(bridge.clone(), handle);
        guard.close_gracefully().await;

        // Socket should be removed
        let b = bridge.lock().await;
        assert_eq!(b.socket_count(), 0);
    }

    #[tokio::test]
    async fn test_tcp_socket_guard_drop() {
        let bridge = create_test_bridge();
        let handle = {
            let mut b = bridge.lock().await;
            b.create_tcp_socket_default().unwrap()
        };

        // Socket count should be 1
        {
            let b = bridge.lock().await;
            assert_eq!(b.socket_count(), 1);
        }

        // Create and drop guard
        {
            let _guard = TcpSocketGuard::new(bridge.clone(), handle);
            // Guard dropped here
        }

        // Socket should be removed by drop
        let b = bridge.lock().await;
        assert_eq!(b.socket_count(), 0);
    }

    #[tokio::test]
    async fn test_tcp_socket_guard_set_graceful_close() {
        let bridge = create_test_bridge();
        let handle = {
            let mut b = bridge.lock().await;
            b.create_tcp_socket_default().unwrap()
        };

        let mut guard = TcpSocketGuard::new(bridge.clone(), handle);

        // Default is abort on drop
        assert!(guard.abort_on_drop);

        // Set graceful close
        guard.set_graceful_close();
        assert!(!guard.abort_on_drop);

        // Set back to abort
        guard.set_abort_on_drop(true);
        assert!(guard.abort_on_drop);
    }

    #[tokio::test]
    async fn test_tcp_socket_guard_bridge_accessor() {
        let bridge = create_test_bridge();
        let handle = {
            let mut b = bridge.lock().await;
            b.create_tcp_socket_default().unwrap()
        };

        let guard = TcpSocketGuard::new(bridge.clone(), handle);

        // Should be able to access bridge through guard
        let b = guard.bridge().lock().await;
        assert_eq!(b.socket_count(), 1);
    }

    #[tokio::test]
    async fn test_udp_socket_guard_creation() {
        let bridge = create_test_bridge();
        let handle = {
            let mut b = bridge.lock().await;
            b.create_udp_socket().unwrap()
        };

        let guard = UdpSocketGuard::new(bridge.clone(), handle);
        assert_eq!(guard.handle(), handle);
        assert_eq!(guard.handle_opt(), Some(handle));
    }

    #[tokio::test]
    async fn test_udp_socket_guard_take() {
        let bridge = create_test_bridge();
        let handle = {
            let mut b = bridge.lock().await;
            b.create_udp_socket().unwrap()
        };

        let guard = UdpSocketGuard::new(bridge.clone(), handle);
        let taken = guard.take();
        assert_eq!(taken, handle);

        // Socket should still exist
        let b = bridge.lock().await;
        assert_eq!(b.socket_count(), 1);
    }

    #[tokio::test]
    async fn test_udp_socket_guard_close() {
        let bridge = create_test_bridge();
        let handle = {
            let mut b = bridge.lock().await;
            b.create_udp_socket().unwrap()
        };

        let guard = UdpSocketGuard::new(bridge.clone(), handle);
        guard.close().await;

        // Socket should be removed
        let b = bridge.lock().await;
        assert_eq!(b.socket_count(), 0);
    }

    #[tokio::test]
    async fn test_udp_socket_guard_drop() {
        let bridge = create_test_bridge();
        let handle = {
            let mut b = bridge.lock().await;
            b.create_udp_socket().unwrap()
        };

        // Create and drop guard
        {
            let _guard = UdpSocketGuard::new(bridge.clone(), handle);
        }

        // Socket should be removed by drop
        let b = bridge.lock().await;
        assert_eq!(b.socket_count(), 0);
    }

    #[tokio::test]
    async fn test_udp_socket_guard_bridge_accessor() {
        let bridge = create_test_bridge();
        let handle = {
            let mut b = bridge.lock().await;
            b.create_udp_socket().unwrap()
        };

        let guard = UdpSocketGuard::new(bridge.clone(), handle);

        // Should be able to access bridge through guard
        let b = guard.bridge().lock().await;
        assert_eq!(b.socket_count(), 1);
    }

    #[tokio::test]
    async fn test_multiple_guards_cleanup() {
        let bridge = create_test_bridge();

        // Create multiple sockets
        let handles: Vec<SocketHandle> = {
            let mut b = bridge.lock().await;
            (0..5)
                .filter_map(|_| b.create_tcp_socket_default())
                .collect()
        };

        assert_eq!(handles.len(), 5);

        // Verify socket count
        {
            let b = bridge.lock().await;
            assert_eq!(b.socket_count(), 5);
        }

        // Create guards and drop them
        {
            let _guards: Vec<TcpSocketGuard> = handles
                .into_iter()
                .map(|h| TcpSocketGuard::new(bridge.clone(), h))
                .collect();
            // All guards drop here
        }

        // All sockets should be cleaned up
        let b = bridge.lock().await;
        assert_eq!(b.socket_count(), 0);
    }

    #[tokio::test]
    async fn test_guard_early_return_cleanup() {
        let bridge = create_test_bridge();

        async fn simulate_early_return(
            bridge: Arc<Mutex<SmoltcpBridge>>,
        ) -> Result<(), &'static str> {
            let handle = {
                let mut b = bridge.lock().await;
                b.create_tcp_socket_default().unwrap()
            };

            let _guard = TcpSocketGuard::new(bridge.clone(), handle);

            // Simulate early return
            return Err("simulated error");

            // Guard drops here, cleaning up the socket
        }

        // Run the function that returns early
        let result = simulate_early_return(bridge.clone()).await;
        assert!(result.is_err());

        // Socket should still be cleaned up
        let b = bridge.lock().await;
        assert_eq!(b.socket_count(), 0);
    }
}
