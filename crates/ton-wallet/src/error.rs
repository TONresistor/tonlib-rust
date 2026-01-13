//! Error types for ton-wallet

use thiserror::Error;

/// Wallet error type
#[derive(Error, Debug)]
pub enum WalletError {
    #[error("Cell error: {0}")]
    Cell(#[from] ton_cell::CellError),

    #[error("Invalid mnemonic: {0}")]
    InvalidMnemonic(String),

    #[error("Invalid word in mnemonic: {0}")]
    InvalidWord(String),

    #[error("Wrong word count: expected 24, got {0}")]
    WrongWordCount(usize),

    #[error("Seqno overflow")]
    SeqnoOverflow,

    #[error("Too many transfers: max {max}, got {got}")]
    TooManyTransfers { max: usize, got: usize },

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Message expired")]
    MessageExpired,

    #[error("Invalid plugin address: must be internal address")]
    InvalidPluginAddress,
}

/// Result type alias
pub type WalletResult<T> = Result<T, WalletError>;
