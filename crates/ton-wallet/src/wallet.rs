//! Wallet trait definition

use crate::error::WalletResult;
use crate::transfer::Transfer;
use std::sync::Arc;
use ton_cell::{Cell, MsgAddress};

/// Common wallet interface
pub trait Wallet: Send + Sync {
    /// Get wallet version name
    fn version(&self) -> &'static str;

    /// Get wallet address
    fn address(&self) -> &MsgAddress;

    /// Get public key
    fn public_key(&self) -> &[u8; 32];

    /// Get workchain
    fn workchain(&self) -> i32;

    /// Get state init cell for deployment
    fn state_init(&self) -> WalletResult<Cell>;

    /// Create unsigned transfer message body
    fn create_transfer_body(
        &self,
        seqno: u32,
        transfers: &[Transfer],
        valid_until: u32,
    ) -> WalletResult<Cell>;

    /// Sign a message body
    fn sign(&self, body: &Cell) -> WalletResult<Cell>;

    /// Create signed external message for sending
    fn create_external_message(&self, signed_body: &Cell) -> WalletResult<Cell> {
        use ton_cell::CellBuilder;

        let state_init = if signed_body.bit_len() == 0 {
            // Include state init for deployment
            Some(self.state_init()?)
        } else {
            None
        };

        // External message: ext_in_msg_info$10 src:MsgAddressExt dest:MsgAddressInt
        let mut builder = CellBuilder::new();

        // ext_in_msg_info$10
        builder.store_bits(&[true, false])?; // 10 prefix

        // src: addr_none$00
        builder.store_bits(&[false, false])?;

        // dest: our address
        builder.store_address(self.address())?;

        // import_fee: 0
        builder.store_coins(0)?;

        // Maybe StateInit
        if let Some(si) = state_init {
            builder.store_bit(true)?; // has state_init
            builder.store_bit(true)?; // state_init in ref
            builder.store_ref(Arc::new(si))?;
        } else {
            builder.store_bit(false)?;
        }

        // Body in ref
        builder.store_bit(true)?;
        builder.store_ref(Arc::new(signed_body.clone()))?;

        builder.build().map_err(Into::into)
    }
}
