//! Wallet V4R2 implementation with plugin support

use crate::codes::wallet_v4r2_code;
use crate::error::{WalletError, WalletResult};
use crate::transfer::Transfer;
use crate::wallet::Wallet;
use std::sync::Arc;
use ton_cell::{Cell, CellBuilder, MsgAddress};
use ton_crypto::Ed25519Keypair;

/// Wallet V4 revision 2 (with plugins)
pub struct WalletV4R2 {
    keypair: Ed25519Keypair,
    workchain: i32,
    subwallet_id: u32,
    address: MsgAddress,
}

impl WalletV4R2 {
    /// Create new wallet
    pub fn new(keypair: Ed25519Keypair, workchain: i32) -> WalletResult<Self> {
        let subwallet_id = 698983191 + workchain as u32;
        Self::with_subwallet(keypair, workchain, subwallet_id)
    }

    /// Create wallet with custom subwallet ID
    pub fn with_subwallet(
        keypair: Ed25519Keypair,
        workchain: i32,
        subwallet_id: u32,
    ) -> WalletResult<Self> {
        let address = Self::calculate_address(&keypair.public_key, workchain, subwallet_id)?;
        Ok(Self {
            keypair,
            workchain,
            subwallet_id,
            address,
        })
    }

    /// Calculate wallet address from public key
    pub fn calculate_address(
        pubkey: &[u8; 32],
        workchain: i32,
        subwallet_id: u32,
    ) -> WalletResult<MsgAddress> {
        let state_init = Self::create_state_init_static(pubkey, subwallet_id)?;
        let hash = state_init.hash();
        Ok(MsgAddress::Internal {
            workchain,
            address: hash,
        })
    }

    fn create_state_init_static(pubkey: &[u8; 32], subwallet_id: u32) -> WalletResult<Cell> {
        let code = wallet_v4r2_code()?;

        // Data: seqno:32 subwallet_id:32 public_key:256 plugins:dict
        let mut data_builder = CellBuilder::new();
        data_builder.store_u32(0)?;
        data_builder.store_u32(subwallet_id)?;
        data_builder.store_bytes(pubkey)?;
        data_builder.store_bit(false)?; // empty plugins dict
        let data = data_builder.build()?;

        // StateInit
        let mut si_builder = CellBuilder::new();
        si_builder.store_bit(false)?;
        si_builder.store_bit(false)?;
        si_builder.store_bit(true)?;
        si_builder.store_ref(code)?;
        si_builder.store_bit(true)?;
        si_builder.store_ref(Arc::new(data))?;
        si_builder.store_bit(false)?;
        si_builder.build().map_err(Into::into)
    }

    /// Get subwallet ID
    pub fn subwallet_id(&self) -> u32 {
        self.subwallet_id
    }

    /// Create external message body to install a plugin
    ///
    /// In V4R2, plugin installation uses op=2 in the signed external message body.
    /// The body format is: subwallet_id:32 valid_until:32 seqno:32 op:8=2 workchain:8 plugin_addr:256 amount:Coins query_id:64
    ///
    /// Reference: https://github.com/ton-blockchain/wallet-contract (v4r2-stable branch)
    pub fn create_install_plugin_body(
        &self,
        seqno: u32,
        valid_until: u32,
        plugin_address: &MsgAddress,
        amount: u128,
        query_id: u64,
    ) -> WalletResult<Cell> {
        let mut builder = CellBuilder::new();
        builder.store_u32(self.subwallet_id)?;
        builder.store_u32(valid_until)?;
        builder.store_u32(seqno)?;
        builder.store_u8(2)?; // op = 2 (install_plugin)

        // Plugin address: workchain:8 address:256
        match plugin_address {
            MsgAddress::Internal { workchain, address } => {
                builder.store_i8(*workchain as i8)?;
                builder.store_bytes(address)?;
            }
            _ => return Err(WalletError::InvalidPluginAddress),
        }

        builder.store_coins(amount)?;
        builder.store_u64(query_id)?;
        builder.build().map_err(Into::into)
    }

    /// Create external message body to remove a plugin
    ///
    /// In V4R2, plugin removal uses op=3 in the signed external message body.
    /// The body format is: subwallet_id:32 valid_until:32 seqno:32 op:8=3 workchain:8 plugin_addr:256
    ///
    /// Reference: https://github.com/ton-blockchain/wallet-contract (v4r2-stable branch)
    pub fn create_remove_plugin_body(
        &self,
        seqno: u32,
        valid_until: u32,
        plugin_address: &MsgAddress,
    ) -> WalletResult<Cell> {
        let mut builder = CellBuilder::new();
        builder.store_u32(self.subwallet_id)?;
        builder.store_u32(valid_until)?;
        builder.store_u32(seqno)?;
        builder.store_u8(3)?; // op = 3 (remove_plugin)

        // Plugin address: workchain:8 address:256
        match plugin_address {
            MsgAddress::Internal { workchain, address } => {
                builder.store_i8(*workchain as i8)?;
                builder.store_bytes(address)?;
            }
            _ => return Err(WalletError::InvalidPluginAddress),
        }

        builder.build().map_err(Into::into)
    }

    fn build_internal_message(&self, transfer: &Transfer) -> WalletResult<Cell> {
        let mut builder = CellBuilder::new();

        builder.store_bit(false)?;
        builder.store_bit(true)?;
        builder.store_bit(transfer.bounce)?;
        builder.store_bit(false)?;

        builder.store_bits(&[false, false])?;
        builder.store_address(&transfer.to)?;
        builder.store_coins(transfer.amount)?;
        builder.store_bit(false)?;

        builder.store_coins(0)?;
        builder.store_coins(0)?;
        builder.store_u64(0)?;
        builder.store_u32(0)?;

        builder.store_bit(false)?;

        if let Some(ref payload) = transfer.payload {
            builder.store_bit(true)?;
            builder.store_ref(payload.clone())?;
        } else {
            builder.store_bit(false)?;
        }

        builder.build().map_err(Into::into)
    }
}

impl Wallet for WalletV4R2 {
    fn version(&self) -> &'static str {
        "v4r2"
    }

    fn address(&self) -> &MsgAddress {
        &self.address
    }

    fn public_key(&self) -> &[u8; 32] {
        &self.keypair.public_key
    }

    fn workchain(&self) -> i32 {
        self.workchain
    }

    fn state_init(&self) -> WalletResult<Cell> {
        Self::create_state_init_static(&self.keypair.public_key, self.subwallet_id)
    }

    fn create_transfer_body(
        &self,
        seqno: u32,
        transfers: &[Transfer],
        valid_until: u32,
    ) -> WalletResult<Cell> {
        if transfers.len() > 4 {
            return Err(WalletError::TooManyTransfers {
                max: 4,
                got: transfers.len(),
            });
        }

        let mut builder = CellBuilder::new();

        // V4 body: subwallet_id:32 valid_until:32 seqno:32 op:8 [mode:8 message:^Cell]*
        builder.store_u32(self.subwallet_id)?;
        builder.store_u32(valid_until)?;
        builder.store_u32(seqno)?;
        builder.store_u8(0)?; // op = 0 (simple send)

        for transfer in transfers {
            builder.store_u8(transfer.mode)?;
            let msg = self.build_internal_message(transfer)?;
            builder.store_ref(Arc::new(msg))?;
        }

        builder.build().map_err(Into::into)
    }

    fn sign(&self, body: &Cell) -> WalletResult<Cell> {
        let body_hash = body.hash();
        let signature = self.keypair.sign(&body_hash);

        let mut builder = CellBuilder::new();
        builder.store_bytes(&signature)?;

        let body_data = body.data();
        for i in 0..body.bit_len() {
            let byte_idx = i / 8;
            let bit_idx = 7 - (i % 8);
            let bit = (body_data[byte_idx] >> bit_idx) & 1 == 1;
            builder.store_bit(bit)?;
        }

        for r in body.references() {
            builder.store_ref(r.clone())?;
        }

        builder.build().map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_wallet_v4() {
        let keypair = Ed25519Keypair::generate();
        let wallet = WalletV4R2::new(keypair, 0).unwrap();
        assert_eq!(wallet.version(), "v4r2");
    }

    #[test]
    fn test_plugin_messages() {
        let keypair = Ed25519Keypair::generate();
        let wallet = WalletV4R2::new(keypair, 0).unwrap();

        // Create internal plugin address
        let plugin_addr = MsgAddress::Internal {
            workchain: 0,
            address: [0u8; 32],
        };

        let install = wallet
            .create_install_plugin_body(0, u32::MAX, &plugin_addr, 0, 0)
            .unwrap();
        let remove = wallet
            .create_remove_plugin_body(0, u32::MAX, &plugin_addr)
            .unwrap();

        assert!(install.bit_len() > 0);
        assert!(remove.bit_len() > 0);

        // Test that Null address fails
        let null_addr = MsgAddress::Null;
        assert!(wallet
            .create_install_plugin_body(0, u32::MAX, &null_addr, 0, 0)
            .is_err());
    }
}
