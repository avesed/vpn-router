// WARP registration error types

use thiserror::Error;

#[derive(Debug, Error)]
pub enum WarpError {
    #[error("Key generation failed: {0}")]
    KeyGeneration(String),

    #[error("API request failed: {0}")]
    ApiRequest(String),

    #[error("HTTP error: {0}")]
    Http(#[from] hyper::Error),

    #[error("HTTP request building failed: {0}")]
    HttpBuild(#[from] hyper::http::Error),

    #[error("Rate limited, retry after {0}s")]
    RateLimited(u64),

    #[error("Invalid response: {0}")]
    InvalidResponse(String),

    #[error("Registration quota exceeded")]
    QuotaExceeded,

    #[error("Network unreachable: {0}")]
    NetworkError(String),

    #[error("JSON serialization failed: {0}")]
    JsonSerialize(#[from] serde_json::Error),

    #[error("Base64 decode failed: {0}")]
    Base64Decode(#[from] base64::DecodeError),

    #[error("Invalid reserved bytes: expected 3 bytes, got {0}")]
    InvalidReservedBytes(usize),

    #[error("Invalid endpoint format: {0}")]
    InvalidEndpoint(String),

    #[error("TLS error: {0}")]
    Tls(String),
}

impl WarpError {
    /// Check if the error is recoverable (can retry)
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            WarpError::RateLimited(_) | WarpError::NetworkError(_) | WarpError::ApiRequest(_)
        )
    }

    /// Check if the error is a rate limit error
    pub fn is_rate_limit(&self) -> bool {
        matches!(self, WarpError::RateLimited(_))
    }

    /// Get retry delay in seconds (if applicable)
    pub fn retry_delay(&self) -> Option<u64> {
        match self {
            WarpError::RateLimited(seconds) => Some(*seconds),
            _ => None,
        }
    }
}

pub type Result<T> = std::result::Result<T, WarpError>;
