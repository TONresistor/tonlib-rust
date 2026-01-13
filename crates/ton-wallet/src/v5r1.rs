//! Wallet V5R1 implementation with extended features
//!
//! V5R1 (W5) is the latest wallet version with:
//! - Extended message signing capabilities
//! - Improved gas efficiency
//! - External signature support

use crate::codes::wallet_v5r1_code;
use crate::error::{WalletError, WalletResult};
use crate::transfer::Transfer;
use crate::wallet::Wallet;
use std::sync::Arc;
use ton_cell::{Cell, CellBuilder, MsgAddress};
use ton_crypto::Ed25519Keypair;

/// V5R1 opcodes
const OP_AUTH_SIGNED: u32 = 0x7369676e; // "sign" in ASCII
#[allow(dead_code)]
const OP_AUTH_EXTENSION: u32 = 0x6578746e; // "extn" in ASCII - for extension auth

/// Network global IDs
pub const NETWORK_MAINNET: i32 = -239;
pub const NETWORK_TESTNET: i32 = -3;

/// Wallet V5 revision 1 (W5)
pub struct WalletV5R1 {
    keypair: Ed25519Keypair,
    workchain: i32,
    wallet_id: i32,
    address: MsgAddress,
}

impl WalletV5R1 {
    /// V5R1 wallet version constant
    const WALLET_VERSION: u8 = 0;

    /// Create new wallet for mainnet
    pub fn new(keypair: Ed25519Keypair, workchain: i32) -> WalletResult<Self> {
        Self::with_network(keypair, workchain, NETWORK_MAINNET, 0)
    }

    /// Create wallet for testnet
    pub fn new_testnet(keypair: Ed25519Keypair, workchain: i32) -> WalletResult<Self> {
        Self::with_network(keypair, workchain, NETWORK_TESTNET, 0)
    }

    /// Create wallet with custom network and subwallet
    pub fn with_network(
        keypair: Ed25519Keypair,
        workchain: i32,
        network_global_id: i32,
        subwallet_number: u32,
    ) -> WalletResult<Self> {
        // Wallet ID format: network_global_id (32 bits) | workchain (8 bits) | version (8 bits) | subwallet (15 bits)
        let wallet_id = Self::compute_wallet_id(network_global_id, workchain, subwallet_number);
        let address = Self::calculate_address(&keypair.public_key, workchain, wallet_id)?;

        Ok(Self {
            keypair,
            workchain,
            wallet_id,
            address,
        })
    }

    /// Compute wallet ID from components
    ///
    /// V5R1 wallet_id is 32-bit signed integer computed as:
    /// `networkGlobalId XOR context`
    ///
    /// Client context format (per official TON W5 specification):
    /// - Bit 31: client_context_flag = 1
    /// - Bits 30-23: workchain (8 bits, signed)
    /// - Bits 22-15: wallet_version (8 bits)
    /// - Bits 14-0: subwallet_number (15 bits)
    ///
    /// Reference: https://github.com/ton-org/ton/blob/main/src/wallets/v5r1/WalletV5R1WalletId.ts
    fn compute_wallet_id(network_global_id: i32, workchain: i32, subwallet_number: u32) -> i32 {
        // Client context: [flag:1][workchain:8][version:8][subwallet:15] (MSB to LSB)
        // Note: We use u32 for context to avoid signed arithmetic issues, then cast to i32
        // IMPORTANT: workchain is signed 8-bit, we must preserve the sign bits correctly
        // by casting through i8 first, then masking to 8 bits
        let workchain_byte = ((workchain as i8) as u32) & 0xFF;
        let context: u32 = (1u32 << 31) // client context flag = 1
            | (workchain_byte << 23) // workchain (8 bits, sign-preserving)
            | ((Self::WALLET_VERSION as u32) << 15) // version (8 bits)
            | (subwallet_number & 0x7FFF); // subwallet (15 bits)

        // wallet_id = networkGlobalId XOR context
        network_global_id ^ (context as i32)
    }

    /// Calculate wallet address from public key
    pub fn calculate_address(
        pubkey: &[u8; 32],
        workchain: i32,
        wallet_id: i32,
    ) -> WalletResult<MsgAddress> {
        let state_init = Self::create_state_init_static(pubkey, wallet_id)?;
        let hash = state_init.hash();
        Ok(MsgAddress::Internal {
            workchain,
            address: hash,
        })
    }

    fn create_state_init_static(pubkey: &[u8; 32], wallet_id: i32) -> WalletResult<Cell> {
        let code = wallet_v5r1_code()?;

        // Data: is_signature_auth:1 seqno:32 wallet_id:32 public_key:256 extensions:dict
        let mut data_builder = CellBuilder::new();
        data_builder.store_bit(true)?; // is_signature_auth = true
        data_builder.store_u32(0)?; // seqno = 0
        data_builder.store_i32(wallet_id)?; // wallet_id (32-bit signed per V5R1 spec)
        data_builder.store_bytes(pubkey)?; // public_key
        data_builder.store_bit(false)?; // empty extensions dict
        let data = data_builder.build()?;

        // StateInit
        let mut si_builder = CellBuilder::new();
        si_builder.store_bit(false)?; // split_depth - absent
        si_builder.store_bit(false)?; // special - absent
        si_builder.store_bit(true)?; // code - present
        si_builder.store_ref(code)?;
        si_builder.store_bit(true)?; // data - present
        si_builder.store_ref(Arc::new(data))?;
        si_builder.store_bit(false)?; // library - absent
        si_builder.build().map_err(Into::into)
    }

    /// Get wallet ID
    pub fn wallet_id(&self) -> i32 {
        self.wallet_id
    }

    /// Build an action list from transfers
    fn build_actions(&self, transfers: &[Transfer]) -> WalletResult<Cell> {
        // Actions are built as a linked list, starting from the last action
        // Each action: action_send_msg#0ec3c86d mode:uint8 out_msg:^MessageRelaxed = OutAction;

        let mut current: Option<Cell> = None;

        for transfer in transfers.iter().rev() {
            let msg = self.build_internal_message(transfer)?;

            let mut action_builder = CellBuilder::new();
            action_builder.store_u32(0x0ec3c86d)?; // action_send_msg tag
            action_builder.store_u8(transfer.mode)?;
            action_builder.store_ref(Arc::new(msg))?;

            if let Some(prev) = current {
                action_builder.store_ref(Arc::new(prev))?;
            }

            current = Some(action_builder.build()?);
        }

        current.ok_or(WalletError::TooManyTransfers { max: 255, got: 0 })
    }

    fn build_internal_message(&self, transfer: &Transfer) -> WalletResult<Cell> {
        let mut builder = CellBuilder::new();

        // int_msg_info$0 ihr_disabled:Bool bounce:Bool bounced:Bool
        builder.store_bit(false)?; // int_msg_info tag
        builder.store_bit(true)?; // ihr_disabled
        builder.store_bit(transfer.bounce)?; // bounce
        builder.store_bit(false)?; // bounced

        // src:MsgAddress dest:MsgAddress
        builder.store_bits(&[false, false])?; // src = addr_none
        builder.store_address(&transfer.to)?;

        // value:CurrencyCollection
        builder.store_coins(transfer.amount)?;
        builder.store_bit(false)?; // other_currencies = empty dict

        // ihr_fee:Grams fwd_fee:Grams created_lt:uint64 created_at:uint32
        builder.store_coins(0)?;
        builder.store_coins(0)?;
        builder.store_u64(0)?;
        builder.store_u32(0)?;

        // init:(Maybe (Either StateInit ^StateInit))
        builder.store_bit(false)?;

        // body:(Either X ^X)
        if let Some(ref payload) = transfer.payload {
            builder.store_bit(true)?; // body in ref
            builder.store_ref(payload.clone())?;
        } else {
            builder.store_bit(false)?; // body inline (empty)
        }

        builder.build().map_err(Into::into)
    }
}

impl Wallet for WalletV5R1 {
    fn version(&self) -> &'static str {
        "v5r1"
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
        Self::create_state_init_static(&self.keypair.public_key, self.wallet_id)
    }

    fn create_transfer_body(
        &self,
        seqno: u32,
        transfers: &[Transfer],
        valid_until: u32,
    ) -> WalletResult<Cell> {
        if transfers.is_empty() {
            return Err(WalletError::TooManyTransfers {
                max: 255,
                got: 0,
            });
        }

        if transfers.len() > 255 {
            return Err(WalletError::TooManyTransfers {
                max: 255,
                got: transfers.len(),
            });
        }

        // Build action list
        let actions = self.build_actions(transfers)?;

        // V5R1 body structure (signed_request):
        // op:32 wallet_id:32 valid_until:32 seqno:32 actions:^Cell
        let mut builder = CellBuilder::new();
        builder.store_u32(OP_AUTH_SIGNED)?;
        builder.store_i32(self.wallet_id)?;
        builder.store_u32(valid_until)?;
        builder.store_u32(seqno)?;
        builder.store_ref(Arc::new(actions))?;

        builder.build().map_err(Into::into)
    }

    fn sign(&self, body: &Cell) -> WalletResult<Cell> {
        let body_hash = body.hash();
        let signature = self.keypair.sign(&body_hash);

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

        // Copy body references
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
    fn test_create_wallet_v5() {
        let keypair = Ed25519Keypair::generate();
        let wallet = WalletV5R1::new(keypair, 0).unwrap();
        assert_eq!(wallet.version(), "v5r1");
    }

    #[test]
    fn test_wallet_id_computation() {
        // Mainnet workchain 0, subwallet 0
        let id = WalletV5R1::compute_wallet_id(NETWORK_MAINNET, 0, 0);
        assert_ne!(id, 0);

        // Testnet should produce different ID
        let id_testnet = WalletV5R1::compute_wallet_id(NETWORK_TESTNET, 0, 0);
        assert_ne!(id, id_testnet);
    }

    #[test]
    fn test_wallet_id_negative_workchain() {
        // Test masterchain (workchain = -1) - critical sign-extension test
        let id_masterchain = WalletV5R1::compute_wallet_id(NETWORK_MAINNET, -1, 0);
        let id_basechain = WalletV5R1::compute_wallet_id(NETWORK_MAINNET, 0, 0);

        // Masterchain and basechain should produce different wallet IDs
        assert_ne!(id_masterchain, id_basechain);

        // Verify workchain byte is correctly embedded (0xFF for -1)
        // Context format: [1:flag][workchain:8][version:8][subwallet:15]
        // For workchain -1: workchain_byte should be 0xFF
        let context_masterchain = (NETWORK_MAINNET ^ id_masterchain) as u32;
        let workchain_byte = (context_masterchain >> 23) & 0xFF;
        assert_eq!(workchain_byte, 0xFF, "Workchain -1 should encode as 0xFF");

        // For workchain 0: workchain_byte should be 0x00
        let context_basechain = (NETWORK_MAINNET ^ id_basechain) as u32;
        let workchain_byte_base = (context_basechain >> 23) & 0xFF;
        assert_eq!(workchain_byte_base, 0x00, "Workchain 0 should encode as 0x00");
    }

    #[test]
    fn test_different_subwallets() {
        let keypair = Ed25519Keypair::generate();
        let wallet1 = WalletV5R1::with_network(keypair.clone(), 0, NETWORK_MAINNET, 0).unwrap();
        let wallet2 = WalletV5R1::with_network(keypair, 0, NETWORK_MAINNET, 1).unwrap();

        // Different subwallets should have different addresses
        assert_ne!(wallet1.address(), wallet2.address());
    }

    #[test]
    fn test_state_init() {
        let keypair = Ed25519Keypair::generate();
        let wallet = WalletV5R1::new(keypair, 0).unwrap();

        let state_init = wallet.state_init().unwrap();
        assert!(state_init.bit_len() > 0);
        assert!(state_init.reference_count() >= 2); // code and data refs
    }

    #[test]
    fn test_transfer_body() {
        let keypair = Ed25519Keypair::generate();
        let wallet = WalletV5R1::new(keypair, 0).unwrap();

        let transfer = Transfer::new(MsgAddress::Null, 1_000_000_000);
        let body = wallet.create_transfer_body(0, &[transfer], u32::MAX).unwrap();

        assert!(body.bit_len() > 0);
    }
}
