//! Error types for DHT operations.

use thiserror::Error;

/// Errors that can occur during DHT operations.
#[derive(Debug, Error)]
pub enum DhtError {
    /// I/O error from the underlying network.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// ADNL protocol error.
    #[error("ADNL error: {0}")]
    Adnl(#[from] ton_adnl::AdnlError),

    /// TL serialization/deserialization error.
    #[error("TL error: {0}")]
    TlError(String),

    /// Signature verification failed.
    #[error("Signature verification failed: {0}")]
    SignatureVerificationFailed(String),

    /// Invalid DHT key.
    #[error("Invalid DHT key: {0}")]
    InvalidKey(String),

    /// Invalid DHT value.
    #[error("Invalid DHT value: {0}")]
    InvalidValue(String),

    /// Invalid DHT node.
    #[error("Invalid DHT node: {0}")]
    InvalidNode(String),

    /// Value not found in DHT.
    #[error("Value not found")]
    ValueNotFound,

    /// Value has expired (TTL exceeded).
    #[error("Value expired")]
    ValueExpired,

    /// Node not found in routing table.
    #[error("Node not found: {0}")]
    NodeNotFound(String),

    /// Routing table is full.
    #[error("Routing table bucket full")]
    BucketFull,

    /// Query timed out.
    #[error("Query timeout")]
    QueryTimeout,

    /// No response from node.
    #[error("No response from node")]
    NoResponse,

    /// Invalid update rule.
    #[error("Invalid update rule: {0}")]
    InvalidUpdateRule(String),

    /// Cryptographic error.
    #[error("Crypto error: {0}")]
    CryptoError(String),
}

/// Result type alias for DHT operations.
pub type Result<T> = std::result::Result<T, DhtError>;
