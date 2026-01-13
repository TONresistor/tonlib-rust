//! Error types for TON Sites operations.

use thiserror::Error;

/// Result type for TON Sites operations.
pub type SiteResult<T> = Result<T, SiteError>;

/// Errors that can occur during TON Sites operations.
#[derive(Debug, Error)]
pub enum SiteError {
    /// Invalid URL format.
    #[error("Invalid URL: {0}")]
    InvalidUrl(String),

    /// Invalid domain (not .ton or .adnl).
    #[error("Invalid domain: {0}. Domain must end with .ton or .adnl")]
    InvalidDomain(String),

    /// Invalid ADNL address format.
    #[error("Invalid ADNL address: {0}")]
    InvalidAdnlAddress(String),

    /// DNS resolution failed.
    #[error("DNS resolution failed: {0}")]
    DnsResolutionFailed(String),

    /// RLDP transfer failed.
    #[error("RLDP transfer failed: {0}")]
    RldpError(String),

    /// HTTP protocol error.
    #[error("HTTP protocol error: {0}")]
    HttpError(String),

    /// Invalid HTTP status code.
    #[error("HTTP error: {status_code} {reason}")]
    HttpStatusError {
        /// The HTTP status code.
        status_code: i32,
        /// The reason phrase.
        reason: String,
    },

    /// Timeout waiting for response.
    #[error("Request timed out")]
    Timeout,

    /// Connection failed.
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    /// Payload transfer error.
    #[error("Payload transfer error: {0}")]
    PayloadError(String),

    /// Invalid response format.
    #[error("Invalid response format: {0}")]
    InvalidResponse(String),

    /// Serialization error.
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Request was cancelled.
    #[error("Request cancelled")]
    Cancelled,

    /// Maximum response size exceeded.
    #[error("Response too large: {size} bytes exceeds maximum {max_size} bytes")]
    ResponseTooLarge {
        /// Actual response size.
        size: usize,
        /// Maximum allowed size.
        max_size: usize,
    },
}

impl From<ton_dns::DnsError> for SiteError {
    fn from(err: ton_dns::DnsError) -> Self {
        SiteError::DnsResolutionFailed(err.to_string())
    }
}

impl From<ton_rldp::RldpError> for SiteError {
    fn from(err: ton_rldp::RldpError) -> Self {
        SiteError::RldpError(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = SiteError::InvalidUrl("missing scheme".to_string());
        assert_eq!(err.to_string(), "Invalid URL: missing scheme");

        let err = SiteError::InvalidDomain("example.com".to_string());
        assert_eq!(
            err.to_string(),
            "Invalid domain: example.com. Domain must end with .ton or .adnl"
        );

        let err = SiteError::HttpStatusError {
            status_code: 404,
            reason: "Not Found".to_string(),
        };
        assert_eq!(err.to_string(), "HTTP error: 404 Not Found");

        let err = SiteError::ResponseTooLarge {
            size: 20_000_000,
            max_size: 10_000_000,
        };
        assert_eq!(
            err.to_string(),
            "Response too large: 20000000 bytes exceeds maximum 10000000 bytes"
        );
    }
}
