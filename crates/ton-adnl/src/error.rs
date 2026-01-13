//! Error types for ADNL protocol operations.

use std::io;
use thiserror::Error;

/// Errors that can occur during ADNL operations.
#[derive(Debug, Error)]
pub enum AdnlError {
    /// I/O error from the underlying TCP/UDP connection.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// Connection was closed by the remote peer.
    #[error("Connection closed")]
    ConnectionClosed,

    /// Failed to perform the ADNL handshake.
    #[error("Handshake failed: {0}")]
    HandshakeFailed(String),

    /// Invalid packet format received.
    #[error("Invalid packet: {0}")]
    InvalidPacket(String),

    /// Packet checksum verification failed.
    #[error("Checksum mismatch")]
    ChecksumMismatch,

    /// Packet size exceeds the maximum allowed.
    #[error("Packet too large: {size} bytes (max: {max})")]
    PacketTooLarge { size: usize, max: usize },

    /// Received an unexpected message type.
    #[error("Unexpected message type: 0x{0:08x}")]
    UnexpectedMessageType(u32),

    /// TL serialization/deserialization error.
    #[error("TL error: {0}")]
    TlError(String),

    /// Query timed out waiting for response.
    #[error("Query timeout")]
    QueryTimeout,

    /// No response received for the query.
    #[error("No response for query")]
    NoResponse,

    /// Invalid server public key.
    #[error("Invalid server public key")]
    InvalidServerKey,

    /// Query ID mismatch in response.
    #[error("Query ID mismatch")]
    QueryIdMismatch,

    // UDP-specific errors

    /// Channel not established.
    #[error("Channel not established")]
    ChannelNotEstablished,

    /// Channel creation failed.
    #[error("Channel creation failed: {0}")]
    ChannelCreationFailed(String),

    /// Peer not found.
    #[error("Peer not found: {0}")]
    PeerNotFound(String),

    /// Too many pending queries.
    #[error("Too many pending queries")]
    TooManyPendingQueries,

    /// Message too large for single packet.
    #[error("Message too large: {size} bytes (max: {max})")]
    MessageTooLarge { size: usize, max: usize },

    /// Unknown key ID received.
    #[error("Unknown key ID")]
    UnknownKeyId,

    /// Signature verification failed.
    #[error("Signature verification failed")]
    SignatureVerificationFailed,
}

/// Result type alias for ADNL operations.
pub type Result<T> = std::result::Result<T, AdnlError>;
