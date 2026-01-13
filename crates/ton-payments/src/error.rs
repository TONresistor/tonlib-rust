//! Error types for TON Payment Channels.
//!
//! This module defines all error types that can occur during payment channel operations.

use thiserror::Error;

/// Errors that can occur during payment channel operations.
#[derive(Debug, Error)]
pub enum PaymentError {
    /// Channel is in an invalid state for the requested operation.
    #[error("Invalid channel state: expected {expected}, got {actual}")]
    InvalidState {
        expected: &'static str,
        actual: String,
    },

    /// The channel has not been initialized.
    #[error("Channel not initialized")]
    ChannelNotInitialized,

    /// The channel is already closed.
    #[error("Channel already closed")]
    ChannelClosed,

    /// Insufficient balance for the payment.
    #[error("Insufficient balance: have {available}, need {required}")]
    InsufficientBalance { available: u128, required: u128 },

    /// Invalid signature on a state update.
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    /// Signature verification failed.
    #[error("Signature verification failed")]
    SignatureVerificationFailed,

    /// Invalid sequence number (must be monotonically increasing).
    #[error("Invalid seqno: expected > {expected}, got {actual}")]
    InvalidSeqno { expected: u64, actual: u64 },

    /// State seqno is not newer than current state.
    #[error("State is not newer: current seqno {current}, provided seqno {provided}")]
    StateNotNewer { current: u64, provided: u64 },

    /// Invalid party address.
    #[error("Invalid party: {0}")]
    InvalidParty(String),

    /// The provided address is not a participant in this channel.
    #[error("Address is not a participant in this channel")]
    NotParticipant,

    /// Challenge period has expired.
    #[error("Challenge period expired at {deadline}")]
    ChallengePeriodExpired { deadline: u32 },

    /// Challenge period has not yet expired.
    #[error("Challenge period not expired: deadline is {deadline}, current time is {current}")]
    ChallengePeriodNotExpired { deadline: u32, current: u32 },

    /// Invalid conditional payment.
    #[error("Invalid conditional payment: {0}")]
    InvalidConditional(String),

    /// Conditional payment not found.
    #[error("Conditional payment not found: hash {hash:?}")]
    ConditionalNotFound { hash: [u8; 32] },

    /// Invalid preimage for hash-locked payment.
    #[error("Invalid preimage: hash mismatch")]
    InvalidPreimage,

    /// Conditional payment has expired.
    #[error("Conditional payment expired at {deadline}")]
    ConditionalExpired { deadline: u32 },

    /// Virtual channel error.
    #[error("Virtual channel error: {0}")]
    VirtualChannelError(String),

    /// No route found for virtual payment.
    #[error("No route found to destination")]
    NoRouteFound,

    /// Serialization error.
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Deserialization error.
    #[error("Deserialization error: {0}")]
    DeserializationError(String),

    /// Cryptographic error.
    #[error("Cryptographic error: {0}")]
    CryptoError(String),

    /// Cell error.
    #[error("Cell error: {0}")]
    CellError(String),

    /// Channel ID mismatch.
    #[error("Channel ID mismatch: expected {expected}, got {actual}")]
    ChannelIdMismatch { expected: u128, actual: u128 },

    /// Balance calculation overflow.
    #[error("Balance overflow during calculation")]
    BalanceOverflow,

    /// Minimum balance violation.
    #[error("Balance would go below minimum: balance {balance}, minimum {minimum}")]
    MinimumBalanceViolation { balance: u128, minimum: u128 },

    /// Invalid channel ID (replay attack protection).
    #[error("Invalid channel ID: expected {expected}, got {actual}")]
    InvalidChannelId { expected: u128, actual: u128 },

    /// State not progressing (block height not increasing).
    #[error("State not progressing: block height must increase, current {current}, provided {provided}")]
    StateNotProgressing { current: u32, provided: u32 },

    /// Invalid challenge (replay attack protection).
    #[error("Invalid challenge: challenge mismatch")]
    InvalidChallenge,

    /// Replay attack detected.
    #[error("Replay attack detected: state already seen")]
    ReplayAttackDetected,

    /// State commitment verification failed.
    #[error("State commitment verification failed: {0}")]
    CommitmentVerificationFailed(String),

    /// Invalid state commitment (missing signature).
    #[error("Invalid state commitment: {0}")]
    InvalidCommitment(String),

    /// Duplicate state detected.
    #[error("Duplicate state detected: same state hash")]
    DuplicateState,

    /// Block height not increasing.
    #[error("Block height not increasing: must be greater than {last}, got {current}")]
    BlockHeightNotIncreasing { last: u32, current: u32 },

    /// State history error.
    #[error("State history error: {0}")]
    StateHistoryError(String),

    /// State not found in history.
    #[error("State not found in history")]
    StateNotFound,

    /// Invalid merkle proof.
    #[error("Invalid merkle proof: conditional not found in tree")]
    InvalidMerkleProof,

    /// Merkle root mismatch.
    #[error("Merkle root mismatch: expected {expected:?}, got {actual:?}")]
    MerkleRootMismatch { expected: [u8; 32], actual: [u8; 32] },
}

/// Result type for payment channel operations.
pub type PaymentResult<T> = Result<T, PaymentError>;

impl From<ton_cell::CellError> for PaymentError {
    fn from(err: ton_cell::CellError) -> Self {
        PaymentError::CellError(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = PaymentError::InsufficientBalance {
            available: 100,
            required: 200,
        };
        assert!(err.to_string().contains("100"));
        assert!(err.to_string().contains("200"));
    }

    #[test]
    fn test_invalid_seqno_display() {
        let err = PaymentError::InvalidSeqno {
            expected: 5,
            actual: 3,
        };
        assert!(err.to_string().contains("5"));
        assert!(err.to_string().contains("3"));
    }

    #[test]
    fn test_channel_state_error() {
        let err = PaymentError::InvalidState {
            expected: "Open",
            actual: "Closed".to_string(),
        };
        assert!(err.to_string().contains("Open"));
        assert!(err.to_string().contains("Closed"));
    }
}
