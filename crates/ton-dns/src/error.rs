//! Error types for TON DNS operations.

use thiserror::Error;

/// Result type for TON DNS operations.
pub type DnsResult<T> = Result<T, DnsError>;

/// Errors that can occur during TON DNS operations.
#[derive(Debug, Error)]
pub enum DnsError {
    /// Domain name is invalid (empty, too long, or contains invalid characters).
    #[error("Invalid domain name: {0}")]
    InvalidDomain(String),

    /// Domain component is too long (max 126 bytes).
    #[error("Domain component too long: {length} bytes (max 126)")]
    ComponentTooLong { length: usize },

    /// Domain component contains invalid characters (control characters 0-32).
    #[error("Domain component contains invalid character: byte 0x{byte:02x}")]
    InvalidCharacter { byte: u8 },

    /// Domain does not end with .ton.
    #[error("Domain must end with .ton: {0}")]
    InvalidTld(String),

    /// Domain was not found.
    #[error("Domain not found: {0}")]
    DomainNotFound(String),

    /// DNS record has invalid format.
    #[error("Invalid DNS record format: {0}")]
    InvalidRecord(String),

    /// Unknown DNS record type.
    #[error("Unknown DNS record type: prefix 0x{prefix:04x}")]
    UnknownRecordType { prefix: u16 },

    /// Resolution failed (e.g., network error, contract error).
    #[error("Resolution failed: {0}")]
    ResolutionFailed(String),

    /// No next resolver found for partial resolution.
    #[error("No next resolver found")]
    NoNextResolver,

    /// Resolution exceeded maximum depth.
    #[error("Resolution exceeded maximum depth: {0}")]
    MaxDepthExceeded(usize),

    /// Cell operation error.
    #[error("Cell error: {0}")]
    CellError(String),
}

impl From<ton_cell::CellError> for DnsError {
    fn from(err: ton_cell::CellError) -> Self {
        DnsError::CellError(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = DnsError::InvalidDomain("empty".to_string());
        assert_eq!(err.to_string(), "Invalid domain name: empty");

        let err = DnsError::ComponentTooLong { length: 200 };
        assert_eq!(
            err.to_string(),
            "Domain component too long: 200 bytes (max 126)"
        );

        let err = DnsError::InvalidCharacter { byte: 0x1F };
        assert_eq!(
            err.to_string(),
            "Domain component contains invalid character: byte 0x1f"
        );

        let err = DnsError::InvalidTld("example.com".to_string());
        assert_eq!(err.to_string(), "Domain must end with .ton: example.com");

        let err = DnsError::DomainNotFound("test.ton".to_string());
        assert_eq!(err.to_string(), "Domain not found: test.ton");

        let err = DnsError::UnknownRecordType { prefix: 0xABCD };
        assert_eq!(err.to_string(), "Unknown DNS record type: prefix 0xabcd");

        let err = DnsError::MaxDepthExceeded(100);
        assert_eq!(err.to_string(), "Resolution exceeded maximum depth: 100");
    }
}
