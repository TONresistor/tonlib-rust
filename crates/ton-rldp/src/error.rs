//! Error types for RLDP operations.

use thiserror::Error;

/// RLDP error type.
#[derive(Debug, Error, Clone)]
pub enum RldpError {
    /// Transfer timed out.
    #[error("Transfer timed out")]
    Timeout,

    /// Query was cancelled.
    #[error("Query cancelled")]
    Cancelled,

    /// Not enough FEC symbols received to decode.
    #[error("Insufficient symbols: received {received}, need approximately {needed}")]
    InsufficientSymbols { received: usize, needed: usize },

    /// FEC type is not supported.
    #[error("Unsupported FEC type: {0}")]
    UnsupportedFecType(String),

    /// Transfer ID mismatch.
    #[error("Transfer ID mismatch")]
    TransferIdMismatch,

    /// Part number mismatch.
    #[error("Part number mismatch: expected {expected}, got {got}")]
    PartMismatch { expected: i32, got: i32 },

    /// Query ID mismatch in answer.
    #[error("Query ID mismatch")]
    QueryIdMismatch,

    /// Error parsing TL data.
    #[error("Parse error: {0}")]
    ParseError(String),

    /// Error from ADNL layer.
    #[error("ADNL error: {0}")]
    AdnlError(String),

    /// I/O error.
    #[error("I/O error: {0}")]
    IoError(String),

    /// Channel closed.
    #[error("Channel closed")]
    ChannelClosed,

    /// Invalid data size.
    #[error("Invalid data size: {0}")]
    InvalidDataSize(String),
}

/// Result type for RLDP operations.
pub type Result<T> = std::result::Result<T, RldpError>;

impl From<std::io::Error> for RldpError {
    fn from(err: std::io::Error) -> Self {
        RldpError::IoError(err.to_string())
    }
}

impl From<tokio::sync::oneshot::error::RecvError> for RldpError {
    fn from(_: tokio::sync::oneshot::error::RecvError) -> Self {
        RldpError::ChannelClosed
    }
}
