//! Priority-aware event channel for the VLESS-WG Bridge
//!
//! Provides priority-based event routing using dual tokio mpsc channels.
//! High-priority events (WireGuard packets, DNS) are processed before
//! normal-priority events (TCP, UDP, cleanup).

use tokio::sync::mpsc;

use super::events::BridgeEvent;

/// High priority channel capacity (WG packets, DNS)
pub const HIGH_PRIORITY_CHANNEL_SIZE: usize = 512;

/// Normal priority channel capacity (TCP, UDP, cleanup)
pub const NORMAL_PRIORITY_CHANNEL_SIZE: usize = 2048;

/// Error returned when try_send fails
#[derive(Debug, Clone)]
pub enum TrySendError {
    /// Channel is full
    Full,
    /// Channel is closed
    Closed,
}

impl std::fmt::Display for TrySendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Full => write!(f, "channel full"),
            Self::Closed => write!(f, "channel closed"),
        }
    }
}

impl std::error::Error for TrySendError {}

/// Configuration for the event channel
#[derive(Debug, Clone)]
pub struct EventChannelConfig {
    /// Capacity of the high priority channel
    pub high_priority_capacity: usize,
    /// Capacity of the normal priority channel
    pub normal_priority_capacity: usize,
}

impl Default for EventChannelConfig {
    fn default() -> Self {
        Self {
            high_priority_capacity: HIGH_PRIORITY_CHANNEL_SIZE,
            normal_priority_capacity: NORMAL_PRIORITY_CHANNEL_SIZE,
        }
    }
}

impl EventChannelConfig {
    /// Create a new configuration with custom capacities
    #[must_use]
    pub fn new(high_priority_capacity: usize, normal_priority_capacity: usize) -> Self {
        Self {
            high_priority_capacity,
            normal_priority_capacity,
        }
    }
}

/// Snapshot of event channel statistics (placeholder for API compatibility)
#[derive(Debug, Clone, Default)]
pub struct EventChannelStats {
    pub sent_total: u64,
    pub sent_high_priority: u64,
    pub sent_normal_priority: u64,
    pub dropped_full: u64,
    pub dropped_closed: u64,
    pub dropped_timeout: u64,
    pub received_total: u64,
    pub received_high_priority: u64,
    pub received_normal_priority: u64,
}

/// Sender end of the event channel (clone-able for multiple producers)
#[derive(Clone)]
pub struct EventSender {
    high_tx: mpsc::Sender<BridgeEvent>,
    normal_tx: mpsc::Sender<BridgeEvent>,
}

impl EventSender {
    /// Try to send an event without blocking
    ///
    /// Routes to high or normal priority channel based on event type.
    pub fn try_send(&self, event: BridgeEvent) -> Result<(), TrySendError> {
        let tx = if event.is_high_priority() {
            &self.high_tx
        } else {
            &self.normal_tx
        };

        tx.try_send(event).map_err(|e| match e {
            mpsc::error::TrySendError::Full(_) => TrySendError::Full,
            mpsc::error::TrySendError::Closed(_) => TrySendError::Closed,
        })
    }

    /// Check if the channel is closed
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.high_tx.is_closed() || self.normal_tx.is_closed()
    }
}

impl std::fmt::Debug for EventSender {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventSender")
            .field("is_closed", &self.is_closed())
            .finish()
    }
}

/// Receiver end of the event channel (single consumer)
pub struct EventReceiver {
    high_rx: mpsc::Receiver<BridgeEvent>,
    normal_rx: mpsc::Receiver<BridgeEvent>,
}

impl EventReceiver {
    /// Receive the next event in priority order
    ///
    /// High priority events are always returned before normal priority.
    pub async fn recv(&mut self) -> Option<BridgeEvent> {
        tokio::select! {
            biased;
            Some(event) = self.high_rx.recv() => Some(event),
            Some(event) = self.normal_rx.recv() => Some(event),
            else => None,
        }
    }
}

impl std::fmt::Debug for EventReceiver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventReceiver").finish()
    }
}

/// Create a new priority event channel
#[must_use]
pub fn create_event_channel(config: EventChannelConfig) -> (EventSender, EventReceiver) {
    let (high_tx, high_rx) = mpsc::channel(config.high_priority_capacity);
    let (normal_tx, normal_rx) = mpsc::channel(config.normal_priority_capacity);

    (
        EventSender { high_tx, normal_tx },
        EventReceiver { high_rx, normal_rx },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    #[tokio::test]
    async fn test_priority_ordering() {
        let (tx, mut rx) = create_event_channel(EventChannelConfig::new(8, 8));

        // Send normal priority first, then high priority
        tx.try_send(BridgeEvent::Shutdown).unwrap();
        tx.try_send(BridgeEvent::wg_packet(Bytes::from_static(b"wg")))
            .unwrap();

        // Should receive high priority (WG) first
        let event = rx.recv().await.unwrap();
        assert!(matches!(event, BridgeEvent::WgPacket { .. }));

        // Then normal priority
        let event = rx.recv().await.unwrap();
        assert!(matches!(event, BridgeEvent::Shutdown));
    }

    #[tokio::test]
    async fn test_channel_full() {
        let (tx, _rx) = create_event_channel(EventChannelConfig::new(1, 1));

        // Fill the channel
        tx.try_send(BridgeEvent::wg_packet(Bytes::new())).unwrap();

        // Should fail with Full
        let result = tx.try_send(BridgeEvent::wg_packet(Bytes::new()));
        assert!(matches!(result, Err(TrySendError::Full)));
    }

    #[tokio::test]
    async fn test_channel_closed() {
        let (tx, rx) = create_event_channel(EventChannelConfig::default());
        drop(rx);

        assert!(tx.is_closed());
        let result = tx.try_send(BridgeEvent::Shutdown);
        assert!(matches!(result, Err(TrySendError::Closed)));
    }

    #[tokio::test]
    async fn test_recv_returns_none_when_closed() {
        let (tx, mut rx) = create_event_channel(EventChannelConfig::default());
        drop(tx);

        assert!(rx.recv().await.is_none());
    }
}
