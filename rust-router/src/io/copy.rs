//! Copy result types for bidirectional TCP streams
//!
//! This module provides the `CopyResult` type used to track bytes transferred
//! during bidirectional copy operations. The actual copy implementation uses
//! tokio's optimized `copy_bidirectional` function.

/// Result of a bidirectional copy operation
#[derive(Debug, Clone, Copy)]
pub struct CopyResult {
    /// Bytes transferred from client to upstream
    pub client_to_upstream: u64,
    /// Bytes transferred from upstream to client
    pub upstream_to_client: u64,
}

impl CopyResult {
    /// Total bytes transferred in both directions
    #[must_use]
    pub const fn total(&self) -> u64 {
        self.client_to_upstream + self.upstream_to_client
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_copy_result_total() {
        let result = CopyResult {
            client_to_upstream: 100,
            upstream_to_client: 200,
        };
        assert_eq!(result.total(), 300);
    }
}
