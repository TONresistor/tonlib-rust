//! Error types for Overlay Network operations.

use thiserror::Error;

/// Errors that can occur during Overlay operations.
#[derive(Debug, Error)]
pub enum OverlayError {
    /// I/O error from the underlying network.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// ADNL protocol error.
    #[error("ADNL error: {0}")]
    Adnl(#[from] ton_adnl::AdnlError),

    /// DHT error.
    #[error("DHT error: {0}")]
    Dht(#[from] ton_dht::DhtError),

    /// RLDP error.
    #[error("RLDP error: {0}")]
    Rldp(#[from] ton_rldp::RldpError),

    /// TL serialization/deserialization error.
    #[error("TL error: {0}")]
    TlError(String),

    /// Signature verification failed.
    #[error("Signature verification failed: {0}")]
    SignatureVerificationFailed(String),

    /// Invalid overlay ID.
    #[error("Invalid overlay ID: {0}")]
    InvalidOverlayId(String),

    /// Invalid overlay node.
    #[error("Invalid overlay node: {0}")]
    InvalidNode(String),

    /// Node not found in overlay.
    #[error("Node not found: {0}")]
    NodeNotFound(String),

    /// Overlay not found.
    #[error("Overlay not found: {0}")]
    OverlayNotFound(String),

    /// Certificate validation failed.
    #[error("Certificate validation failed: {0}")]
    CertificateValidationFailed(String),

    /// Certificate expired.
    #[error("Certificate expired")]
    CertificateExpired,

    /// Broadcast too large.
    #[error("Broadcast too large: {size} bytes (max: {max})")]
    BroadcastTooLarge { size: usize, max: usize },

    /// Broadcast already seen (duplicate).
    #[error("Broadcast already seen")]
    BroadcastDuplicate,

    /// Broadcast expired.
    #[error("Broadcast expired")]
    BroadcastExpired,

    /// Query timed out.
    #[error("Query timeout")]
    QueryTimeout,

    /// No response from node.
    #[error("No response from node")]
    NoResponse,

    /// Peer not found.
    #[error("Peer not found")]
    PeerNotFound,

    /// Maximum peers reached.
    #[error("Maximum peers reached for overlay")]
    MaxPeersReached,

    /// Cryptographic error.
    #[error("Crypto error: {0}")]
    CryptoError(String),
}

/// Result type alias for Overlay operations.
pub type Result<T> = std::result::Result<T, OverlayError>;
