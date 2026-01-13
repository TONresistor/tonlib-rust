//! Wallet V3R2 implementation

use crate::codes::wallet_v3r2_code;
use crate::error::{WalletError, WalletResult};
use crate::transfer::Transfer;
use crate::wallet::Wallet;
use std::sync::Arc;
use ton_cell::{Cell, CellBuilder, MsgAddress};
use ton_crypto::Ed25519Keypair;

/// Default subwallet ID for workchain 0
pub const DEFAULT_SUBWALLET_ID: u32 = 698983191;

/// Wallet V3 revision 2
pub struct WalletV3R2 {
    keypair: Ed25519Keypair,
    workchain: i32,
    subwallet_id: u32,
    address: MsgAddress,
}

impl WalletV3R2 {
    /// Create new wallet
    pub fn new(keypair: Ed25519Keypair, workchain: i32) -> WalletResult<Self> {
        let subwallet_id = DEFAULT_SUBWALLET_ID + workchain as u32;
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
        let code = wallet_v3r2_code()?;

        // Data: seqno:32 subwallet_id:32 public_key:256
        let mut data_builder = CellBuilder::new();
        data_builder.store_u32(0)?; // seqno = 0
        data_builder.store_u32(subwallet_id)?;
        data_builder.store_bytes(pubkey)?;
        let data = data_builder.build()?;

        // StateInit
        let mut si_builder = CellBuilder::new();
        si_builder.store_bit(false)?; // no split_depth
        si_builder.store_bit(false)?; // no special
        si_builder.store_bit(true)?; // has code
        si_builder.store_ref(code)?;
        si_builder.store_bit(true)?; // has data
        si_builder.store_ref(Arc::new(data))?;
        si_builder.store_bit(false)?; // no library
        si_builder.build().map_err(Into::into)
    }

    /// Get subwallet ID
    pub fn subwallet_id(&self) -> u32 {
        self.subwallet_id
    }

    /// Build internal message cell
    fn build_internal_message(&self, transfer: &Transfer) -> WalletResult<Cell> {
        let mut builder = CellBuilder::new();

        // int_msg_info$0 ihr_disabled:Bool bounce:Bool bounced:Bool
        builder.store_bit(false)?; // 0 prefix (internal)
        builder.store_bit(true)?; // ihr_disabled
        builder.store_bit(transfer.bounce)?;
        builder.store_bit(false)?; // bounced = false

        // src: addr_none (will be filled by contract)
        builder.store_bits(&[false, false])?;

        // dest
        builder.store_address(&transfer.to)?;

        // value
        builder.store_coins(transfer.amount)?;

        // Extra currency = empty dict
        builder.store_bit(false)?;

        // ihr_fee, fwd_fee = 0 (will be computed)
        builder.store_coins(0)?;
        builder.store_coins(0)?;

        // created_lt, created_at = 0 (will be filled)
        builder.store_u64(0)?;
        builder.store_u32(0)?;

        // state_init = none
        builder.store_bit(false)?;

        // body
        if let Some(ref payload) = transfer.payload {
            builder.store_bit(true)?; // body in ref
            builder.store_ref(payload.clone())?;
        } else {
            builder.store_bit(false)?; // empty body
        }

        builder.build().map_err(Into::into)
    }
}

impl Wallet for WalletV3R2 {
    fn version(&self) -> &'static str {
        "v3r2"
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

        // V3 body: subwallet_id:32 valid_until:32 seqno:32 [mode:8 message:^Cell]*
        builder.store_u32(self.subwallet_id)?;
        builder.store_u32(valid_until)?;
        builder.store_u32(seqno)?;

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

        // Signed body: signature:512 body
        let mut builder = CellBuilder::new();
        builder.store_bytes(&signature)?;

        // Copy body bits
        let body_data = body.data();
        for i in 0..body.bit_len() {
            let byte_idx = i / 8;
            let bit_idx = 7 - (i % 8);
            let bit = (body_data[byte_idx] >> bit_idx) & 1 == 1;
            builder.store_bit(bit)?;
        }

        // Copy refs
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
    fn test_create_wallet() {
        let keypair = Ed25519Keypair::generate();
        let wallet = WalletV3R2::new(keypair, 0).unwrap();
        assert_eq!(wallet.version(), "v3r2");
        assert_eq!(wallet.workchain(), 0);
    }

    #[test]
    fn test_address_calculation() {
        let keypair = Ed25519Keypair::generate();
        let wallet = WalletV3R2::new(keypair.clone(), 0).unwrap();

        // Same keypair should give same address
        let wallet2 = WalletV3R2::new(keypair, 0).unwrap();
        assert_eq!(wallet.address(), wallet2.address());
    }

    #[test]
    fn test_create_transfer() {
        let keypair = Ed25519Keypair::generate();
        let wallet = WalletV3R2::new(keypair, 0).unwrap();

        let transfer = Transfer::new(MsgAddress::Null, 1_000_000_000);
        let body = wallet
            .create_transfer_body(0, &[transfer], u32::MAX)
            .unwrap();

        assert!(body.bit_len() > 0);
    }

    #[test]
    fn test_sign_message() {
        let keypair = Ed25519Keypair::generate();
        let wallet = WalletV3R2::new(keypair, 0).unwrap();

        let transfer = Transfer::new(MsgAddress::Null, 1_000_000_000);
        let body = wallet
            .create_transfer_body(0, &[transfer], u32::MAX)
            .unwrap();
        let signed = wallet.sign(&body).unwrap();

        // Signed message should have signature (512 bits) + body
        assert!(signed.bit_len() >= 512);
    }

    #[test]
    fn test_too_many_transfers() {
        let keypair = Ed25519Keypair::generate();
        let wallet = WalletV3R2::new(keypair, 0).unwrap();

        let transfers: Vec<Transfer> = (0..5)
            .map(|_| Transfer::new(MsgAddress::Null, 1_000_000_000))
            .collect();

        let result = wallet.create_transfer_body(0, &transfers, u32::MAX);
        assert!(matches!(result, Err(WalletError::TooManyTransfers { .. })));
    }
}
