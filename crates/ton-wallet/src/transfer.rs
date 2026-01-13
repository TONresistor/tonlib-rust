//! Transfer message structures

use std::sync::Arc;
use ton_cell::{Cell, MsgAddress};

/// A transfer to be sent from a wallet
#[derive(Debug, Clone)]
pub struct Transfer {
    /// Destination address
    pub to: MsgAddress,
    /// Amount in nanotons
    pub amount: u128,
    /// Optional message payload
    pub payload: Option<Arc<Cell>>,
    /// Bounce flag
    pub bounce: bool,
    /// Send mode (default: 3)
    pub mode: u8,
}

impl Transfer {
    /// Create a simple transfer
    pub fn new(to: MsgAddress, amount: u128) -> Self {
        Self {
            to,
            amount,
            payload: None,
            bounce: true,
            mode: 3, // Pay fees separately + ignore errors
        }
    }

    /// Set payload
    pub fn with_payload(mut self, payload: Cell) -> Self {
        self.payload = Some(Arc::new(payload));
        self
    }

    /// Set bounce flag
    pub fn with_bounce(mut self, bounce: bool) -> Self {
        self.bounce = bounce;
        self
    }

    /// Set send mode
    pub fn with_mode(mut self, mode: u8) -> Self {
        self.mode = mode;
        self
    }
}

/// Build a text comment cell
pub fn build_comment(text: &str) -> ton_cell::CellResult<Cell> {
    use ton_cell::CellBuilder;

    let mut builder = CellBuilder::new();
    builder.store_u32(0)?; // comment op = 0
    builder.store_bytes(text.as_bytes())?;
    builder.build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transfer_builder() {
        let addr = MsgAddress::Null;
        let transfer = Transfer::new(addr, 1_000_000_000)
            .with_bounce(false)
            .with_mode(128);

        assert_eq!(transfer.amount, 1_000_000_000);
        assert!(!transfer.bounce);
        assert_eq!(transfer.mode, 128);
    }

    #[test]
    fn test_build_comment() {
        let cell = build_comment("Hello TON").unwrap();
        assert!(cell.bit_len() > 0);
    }
}
