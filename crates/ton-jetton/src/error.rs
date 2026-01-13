//! Error types for Jetton operations.

use thiserror::Error;

/// Errors that can occur during Jetton operations.
#[derive(Debug, Error)]
pub enum JettonError {
    /// Invalid content type in TEP-64 metadata.
    #[error("Invalid content type: 0x{0:02x} (expected 0x00 for off-chain or 0x01 for on-chain)")]
    InvalidContentType(u8),

    /// Invalid snake string format.
    #[error("Invalid snake string format: {0}")]
    InvalidSnakeString(String),

    /// Invalid dictionary format.
    #[error("Invalid dictionary format: {0}")]
    InvalidDictionary(String),

    /// Missing required field.
    #[error("Missing required field: {0}")]
    MissingField(String),

    /// Invalid address format.
    #[error("Invalid address format: {0}")]
    InvalidAddress(String),

    /// Cell operation error.
    #[error("Cell error: {0}")]
    CellError(#[from] ton_cell::CellError),

    /// Get method returned unexpected result.
    #[error("Unexpected get method result: {0}")]
    UnexpectedResult(String),

    /// Get method execution failed.
    #[error("Get method failed with exit code: {0}")]
    GetMethodFailed(i32),

    /// Stack is empty or has insufficient entries.
    #[error("Stack underflow: expected {expected} entries, got {actual}")]
    StackUnderflow { expected: usize, actual: usize },

    /// Invalid stack entry type.
    #[error("Invalid stack entry type: expected {expected}, got {actual}")]
    InvalidStackEntry {
        expected: &'static str,
        actual: String,
    },

    /// ADNL/LiteClient error.
    #[error("Network error: {0}")]
    NetworkError(String),
}

/// Result type for Jetton operations.
pub type JettonResult<T> = Result<T, JettonError>;
