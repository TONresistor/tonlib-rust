//! On-chain integration for TON Payment Channels.
//!
//! This module provides functionality to deploy and interact with payment channel
//! smart contracts on the TON blockchain using the LiteClient.
//!
//! # Overview
//!
//! The `OnchainChannelManager` enables:
//! - Deploying new payment channel contracts
//! - Initializing channels with balances
//! - Cooperative and uncooperative close operations
//! - Querying channel state from on-chain contracts
//! - Settling conditional payments on-chain
//!
//! # Payment Channel Smart Contract
//!
//! Based on: https://github.com/ton-blockchain/payment-channels
//!
//! The payment channel contract supports the following operations:
//! - `top_up_balance` - Add funds to the channel
//! - `init_channel` - Initialize channel with balances
//! - `cooperative_close` - Close with mutual agreement
//! - `cooperative_commit` - Commit state update with both signatures
//! - `start_uncooperative_close` - Begin unilateral close (dispute)
//! - `challenge_quarantined_state` - Submit newer state during dispute
//! - `settle_conditionals` - Settle conditional payments
//! - `finish_uncooperative_close` - Complete close after challenge period

use std::sync::Arc;

use ton_cell::{BagOfCells, Cell, CellBuilder, MsgAddress};
use ton_crypto::Ed25519Keypair;

use crate::conditional::ConditionalPayment;
use crate::error::{PaymentError, PaymentResult};
use crate::state::SignedSemiChannel;

// ============================================================================
// Operation Codes (from official payment-channels scheme.tlb)
// https://github.com/ton-blockchain/payment-channels/blob/master/scheme.tlb
// ============================================================================

/// Top up balance operation code.
pub const OP_TOP_UP_BALANCE: u32 = 0x67c7d281;

/// Initialize channel operation code.
/// Official: "init" (0x696e6974) - ASCII encoding
/// Reference: https://github.com/ton-blockchain/payment-channels/blob/master/scheme.tlb
pub const OP_INIT_CHANNEL: u32 = 0x696e6974;

/// Cooperative close operation code.
/// Official: "Clos" (0x436c6f73) - ASCII encoding
pub const OP_COOPERATIVE_CLOSE: u32 = 0x436c6f73;

/// Cooperative commit operation code.
/// Official: "CCmt" (0x43436d74) - ASCII encoding
pub const OP_COOPERATIVE_COMMIT: u32 = 0x43436d74;

/// Start uncooperative close operation code.
/// Official: "UnCl" (0x556e436c) - ASCII encoding
pub const OP_START_UNCOOPERATIVE_CLOSE: u32 = 0x556e436c;

/// Challenge quarantined state operation code.
/// Official: "ChgQ" (0x43686751) - ASCII encoding
pub const OP_CHALLENGE_QUARANTINED_STATE: u32 = 0x43686751;

/// Settle conditionals operation code.
/// Official: "ClCn" (0x436c436e) - from scheme.tlb tag
/// Reference: https://github.com/ton-blockchain/payment-channels/blob/master/scheme.tlb
pub const OP_SETTLE_CONDITIONALS: u32 = 0x436c436e;

/// Finish uncooperative close operation code.
/// Official: "FnCl" (0x466e436c) - ASCII encoding
pub const OP_FINISH_UNCOOPERATIVE_CLOSE: u32 = 0x466e436c;

// ============================================================================
// Message Tags (from official scheme.tlb)
// ============================================================================

/// Tag for init messages: "init" in ASCII as u32
pub const TAG_INIT: u32 = 0x696e6974;

/// Tag for close messages: "Clos" in ASCII as u32
pub const TAG_CLOSE: u32 = 0x436c6f73;

/// Tag for commit messages: "CCmt" in ASCII as u32
pub const TAG_COMMIT: u32 = 0x43436d74;

/// Tag for uncooperative close: "UnCl" in ASCII as u32
pub const TAG_UNCL: u32 = 0x556e436c;

/// Tag for challenge quarantine: "ChgQ" in ASCII as u32
pub const TAG_CHGQ: u32 = 0x43686751;

// ============================================================================
// Get Method Names
// ============================================================================

/// Get method name for channel state.
pub const GET_CHANNEL_STATE: &str = "get_channel_state";

/// Get method name for channel data.
pub const GET_CHANNEL_DATA: &str = "get_channel_data";

// ============================================================================
// Channel State (from contract)
// ============================================================================

/// On-chain channel state as returned by get_channel_state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnchainChannelState {
    /// Channel is uninitialized.
    Uninitialized = 0,
    /// Channel is open and active.
    Open = 1,
    /// Closure has been initiated.
    ClosureStarted = 2,
    /// Channel is in quarantine period.
    Quarantine = 3,
    /// Channel has been settled.
    Settled = 4,
}

impl OnchainChannelState {
    /// Convert from i64 value returned by get method.
    pub fn from_i64(value: i64) -> Option<Self> {
        match value {
            0 => Some(Self::Uninitialized),
            1 => Some(Self::Open),
            2 => Some(Self::ClosureStarted),
            3 => Some(Self::Quarantine),
            4 => Some(Self::Settled),
            _ => None,
        }
    }
}

/// On-chain channel data as returned by get_channel_data.
#[derive(Debug, Clone)]
pub struct OnchainChannelData {
    /// Current channel state.
    pub state: OnchainChannelState,
    /// Balance of party A.
    pub balance_a: u128,
    /// Balance of party B.
    pub balance_b: u128,
    /// Public key of party A.
    pub key_a: [u8; 32],
    /// Public key of party B.
    pub key_b: [u8; 32],
    /// Channel ID.
    pub channel_id: u128,
    /// Closure config (challenge period).
    pub closure_config: u32,
    /// Committed seqno A.
    pub committed_seqno_a: u64,
    /// Committed seqno B.
    pub committed_seqno_b: u64,
    /// Quarantine start time (if in quarantine).
    pub quarantine_started: Option<u32>,
}

// ============================================================================
// Message Builders
// ============================================================================

/// Build the message body for init_channel operation.
///
/// # Arguments
/// * `balance_a` - Initial balance for party A
/// * `balance_b` - Initial balance for party B
/// * `min_a` - Minimum balance party A must maintain
/// * `min_b` - Minimum balance party B must maintain
pub fn build_init_channel_body(
    balance_a: u128,
    balance_b: u128,
    min_a: u128,
    min_b: u128,
) -> PaymentResult<Cell> {
    let mut builder = CellBuilder::new();

    builder
        .store_u32(OP_INIT_CHANNEL)
        .map_err(|e| PaymentError::CellError(e.to_string()))?;

    builder
        .store_coins(balance_a)
        .map_err(|e| PaymentError::CellError(e.to_string()))?;

    builder
        .store_coins(balance_b)
        .map_err(|e| PaymentError::CellError(e.to_string()))?;

    builder
        .store_coins(min_a)
        .map_err(|e| PaymentError::CellError(e.to_string()))?;

    builder
        .store_coins(min_b)
        .map_err(|e| PaymentError::CellError(e.to_string()))?;

    builder
        .build()
        .map_err(|e| PaymentError::CellError(e.to_string()))
}

/// Build the message body for top_up_balance operation.
///
/// # Arguments
/// * `is_party_a` - True if topping up party A's balance
pub fn build_top_up_body(is_party_a: bool) -> PaymentResult<Cell> {
    let mut builder = CellBuilder::new();

    builder
        .store_u32(OP_TOP_UP_BALANCE)
        .map_err(|e| PaymentError::CellError(e.to_string()))?;

    builder
        .store_bit(is_party_a)
        .map_err(|e| PaymentError::CellError(e.to_string()))?;

    builder
        .build()
        .map_err(|e| PaymentError::CellError(e.to_string()))
}

/// Build the message body for cooperative_close operation.
///
/// # Arguments
/// * `signed_state_a` - Signed semi-channel state from party A
/// * `signed_state_b` - Signed semi-channel state from party B
pub fn build_cooperative_close_body(
    signed_state_a: &SignedSemiChannel,
    signed_state_b: &SignedSemiChannel,
) -> PaymentResult<Cell> {
    let state_cell_a = signed_state_a.to_cell()?;
    let state_cell_b = signed_state_b.to_cell()?;

    let mut builder = CellBuilder::new();

    builder
        .store_u32(OP_COOPERATIVE_CLOSE)
        .map_err(|e| PaymentError::CellError(e.to_string()))?;

    builder
        .store_ref(Arc::new(state_cell_a))
        .map_err(|e| PaymentError::CellError(e.to_string()))?;

    builder
        .store_ref(Arc::new(state_cell_b))
        .map_err(|e| PaymentError::CellError(e.to_string()))?;

    builder
        .build()
        .map_err(|e| PaymentError::CellError(e.to_string()))
}

/// Build the message body for cooperative_commit operation.
///
/// # Arguments
/// * `signed_state_a` - Signed semi-channel state from party A
/// * `signed_state_b` - Signed semi-channel state from party B
pub fn build_cooperative_commit_body(
    signed_state_a: &SignedSemiChannel,
    signed_state_b: &SignedSemiChannel,
) -> PaymentResult<Cell> {
    let state_cell_a = signed_state_a.to_cell()?;
    let state_cell_b = signed_state_b.to_cell()?;

    let mut builder = CellBuilder::new();

    builder
        .store_u32(OP_COOPERATIVE_COMMIT)
        .map_err(|e| PaymentError::CellError(e.to_string()))?;

    builder
        .store_ref(Arc::new(state_cell_a))
        .map_err(|e| PaymentError::CellError(e.to_string()))?;

    builder
        .store_ref(Arc::new(state_cell_b))
        .map_err(|e| PaymentError::CellError(e.to_string()))?;

    builder
        .build()
        .map_err(|e| PaymentError::CellError(e.to_string()))
}

/// Build the message body for start_uncooperative_close operation.
///
/// # Arguments
/// * `signed_state` - Our signed semi-channel state
pub fn build_start_uncooperative_close_body(
    signed_state: &SignedSemiChannel,
) -> PaymentResult<Cell> {
    let state_cell = signed_state.to_cell()?;

    let mut builder = CellBuilder::new();

    builder
        .store_u32(OP_START_UNCOOPERATIVE_CLOSE)
        .map_err(|e| PaymentError::CellError(e.to_string()))?;

    builder
        .store_ref(Arc::new(state_cell))
        .map_err(|e| PaymentError::CellError(e.to_string()))?;

    builder
        .build()
        .map_err(|e| PaymentError::CellError(e.to_string()))
}

/// Build the message body for challenge_quarantined_state operation.
///
/// # Arguments
/// * `newer_signed_state` - A signed state with higher seqno
pub fn build_challenge_state_body(
    newer_signed_state: &SignedSemiChannel,
) -> PaymentResult<Cell> {
    let state_cell = newer_signed_state.to_cell()?;

    let mut builder = CellBuilder::new();

    builder
        .store_u32(OP_CHALLENGE_QUARANTINED_STATE)
        .map_err(|e| PaymentError::CellError(e.to_string()))?;

    builder
        .store_ref(Arc::new(state_cell))
        .map_err(|e| PaymentError::CellError(e.to_string()))?;

    builder
        .build()
        .map_err(|e| PaymentError::CellError(e.to_string()))
}

/// Build the message body for settle_conditionals operation.
///
/// # Arguments
/// * `from_a` - True to settle conditionals from party A, false for party B
/// * `conditionals` - The conditional payments to settle
pub fn build_settle_conditionals_body(
    from_a: bool,
    conditionals: &[ConditionalPayment],
) -> PaymentResult<Cell> {
    let conditionals_cell = build_conditionals_cell(conditionals)?;

    let mut builder = CellBuilder::new();

    builder
        .store_u32(OP_SETTLE_CONDITIONALS)
        .map_err(|e| PaymentError::CellError(e.to_string()))?;

    builder
        .store_bit(from_a)
        .map_err(|e| PaymentError::CellError(e.to_string()))?;

    builder
        .store_ref(Arc::new(conditionals_cell))
        .map_err(|e| PaymentError::CellError(e.to_string()))?;

    builder
        .build()
        .map_err(|e| PaymentError::CellError(e.to_string()))
}

/// Build the message body for finish_uncooperative_close operation.
pub fn build_finish_uncooperative_close_body() -> PaymentResult<Cell> {
    let mut builder = CellBuilder::new();

    builder
        .store_u32(OP_FINISH_UNCOOPERATIVE_CLOSE)
        .map_err(|e| PaymentError::CellError(e.to_string()))?;

    builder
        .build()
        .map_err(|e| PaymentError::CellError(e.to_string()))
}

/// Build a cell containing conditional payments.
fn build_conditionals_cell(conditionals: &[ConditionalPayment]) -> PaymentResult<Cell> {
    if conditionals.is_empty() {
        return CellBuilder::new()
            .build()
            .map_err(|e| PaymentError::CellError(e.to_string()));
    }

    let mut current_ref: Option<Arc<Cell>> = None;

    // Build from last to first
    for conditional in conditionals.iter().rev() {
        let conditional_cell = conditional.to_cell()?;

        let mut builder = CellBuilder::new();

        builder
            .store_ref(Arc::new(conditional_cell))
            .map_err(|e| PaymentError::CellError(e.to_string()))?;

        if let Some(next) = current_ref {
            builder
                .store_ref(next)
                .map_err(|e| PaymentError::CellError(e.to_string()))?;
        }

        current_ref = Some(Arc::new(
            builder
                .build()
                .map_err(|e| PaymentError::CellError(e.to_string()))?,
        ));
    }

    current_ref
        .map(|arc| (*arc).clone())
        .ok_or_else(|| PaymentError::CellError("Failed to build conditionals cell".to_string()))
}

// ============================================================================
// Internal Message Builder
// ============================================================================

/// Build an internal message to send to a contract.
///
/// # Arguments
/// * `dest` - Destination address
/// * `value` - Amount of nanotons to send
/// * `body` - Message body cell
/// * `bounce` - Whether the message should bounce on error
pub fn build_internal_message(
    dest: &MsgAddress,
    value: u128,
    body: Cell,
    bounce: bool,
) -> PaymentResult<Cell> {
    let mut builder = CellBuilder::new();

    // int_msg_info$0 ihr_disabled:Bool bounce:Bool bounced:Bool
    // src:MsgAddressInt dest:MsgAddressInt
    // value:CurrencyCollection ihr_fee:Grams fwd_fee:Grams
    // created_lt:uint64 created_at:uint32
    builder
        .store_bit(false) // int_msg_info$0
        .map_err(|e| PaymentError::CellError(e.to_string()))?;

    builder
        .store_bit(true) // ihr_disabled
        .map_err(|e| PaymentError::CellError(e.to_string()))?;

    builder
        .store_bit(bounce) // bounce
        .map_err(|e| PaymentError::CellError(e.to_string()))?;

    builder
        .store_bit(false) // bounced
        .map_err(|e| PaymentError::CellError(e.to_string()))?;

    // src: addr_none$00
    builder
        .store_uint(0b00, 2)
        .map_err(|e| PaymentError::CellError(e.to_string()))?;

    // dest
    builder
        .store_address(dest)
        .map_err(|e| PaymentError::CellError(e.to_string()))?;

    // value (Grams)
    builder
        .store_coins(value)
        .map_err(|e| PaymentError::CellError(e.to_string()))?;

    // extra currencies (empty dict)
    builder
        .store_bit(false)
        .map_err(|e| PaymentError::CellError(e.to_string()))?;

    // ihr_fee
    builder
        .store_coins(0)
        .map_err(|e| PaymentError::CellError(e.to_string()))?;

    // fwd_fee
    builder
        .store_coins(0)
        .map_err(|e| PaymentError::CellError(e.to_string()))?;

    // created_lt
    builder
        .store_u64(0)
        .map_err(|e| PaymentError::CellError(e.to_string()))?;

    // created_at
    builder
        .store_u32(0)
        .map_err(|e| PaymentError::CellError(e.to_string()))?;

    // init: Maybe (Either StateInit ^StateInit)
    builder
        .store_bit(false) // no init
        .map_err(|e| PaymentError::CellError(e.to_string()))?;

    // body: Either X ^X
    builder
        .store_bit(true) // body in ref
        .map_err(|e| PaymentError::CellError(e.to_string()))?;

    builder
        .store_ref(Arc::new(body))
        .map_err(|e| PaymentError::CellError(e.to_string()))?;

    builder
        .build()
        .map_err(|e| PaymentError::CellError(e.to_string()))
}

// ============================================================================
// OnchainChannelManager
// ============================================================================

/// Manager for on-chain payment channel operations.
///
/// This struct provides methods to interact with payment channel smart contracts
/// deployed on the TON blockchain.
///
/// # Example
///
/// ```rust,no_run
/// use ton_payments::onchain::{OnchainChannelManager, build_init_channel_body};
/// use ton_cell::MsgAddress;
///
/// // Create manager (without lite client for building messages)
/// let manager = OnchainChannelManager::new();
///
/// // Build init channel message body
/// let body = build_init_channel_body(
///     1_000_000_000, // 1 TON for party A
///     1_000_000_000, // 1 TON for party B
///     0,             // min balance A
///     0,             // min balance B
/// ).unwrap();
/// ```
#[derive(Clone)]
pub struct OnchainChannelManager {
    /// Our keypair for signing transactions.
    keypair: Option<Ed25519Keypair>,
    /// Our wallet address for sending transactions.
    wallet_address: Option<MsgAddress>,
}

impl std::fmt::Debug for OnchainChannelManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OnchainChannelManager")
            .field("keypair", &self.keypair.as_ref().map(|_| "[keypair present]"))
            .field("wallet_address", &self.wallet_address)
            .finish()
    }
}

impl OnchainChannelManager {
    /// Create a new on-chain channel manager.
    pub fn new() -> Self {
        Self {
            keypair: None,
            wallet_address: None,
        }
    }

    /// Create a manager with keypair and wallet address.
    pub fn with_keypair(keypair: Ed25519Keypair, wallet_address: MsgAddress) -> Self {
        Self {
            keypair: Some(keypair),
            wallet_address: Some(wallet_address),
        }
    }

    /// Set the keypair for signing transactions.
    pub fn set_keypair(&mut self, keypair: Ed25519Keypair) {
        self.keypair = Some(keypair);
    }

    /// Set the wallet address for sending transactions.
    pub fn set_wallet_address(&mut self, address: MsgAddress) {
        self.wallet_address = Some(address);
    }

    /// Get the configured keypair.
    pub fn keypair(&self) -> Option<&Ed25519Keypair> {
        self.keypair.as_ref()
    }

    /// Get the configured wallet address.
    pub fn wallet_address(&self) -> Option<&MsgAddress> {
        self.wallet_address.as_ref()
    }

    /// Build an init channel message.
    ///
    /// # Arguments
    /// * `channel_addr` - Address of the payment channel contract
    /// * `value` - Amount of nanotons to send with the message
    /// * `balance_a` - Initial balance for party A
    /// * `balance_b` - Initial balance for party B
    /// * `min_a` - Minimum balance party A must maintain
    /// * `min_b` - Minimum balance party B must maintain
    pub fn build_init_message(
        &self,
        channel_addr: &MsgAddress,
        value: u128,
        balance_a: u128,
        balance_b: u128,
        min_a: u128,
        min_b: u128,
    ) -> PaymentResult<Cell> {
        let body = build_init_channel_body(balance_a, balance_b, min_a, min_b)?;
        build_internal_message(channel_addr, value, body, true)
    }

    /// Build a cooperative close message.
    ///
    /// # Arguments
    /// * `channel_addr` - Address of the payment channel contract
    /// * `signed_state_a` - Signed semi-channel state from party A
    /// * `signed_state_b` - Signed semi-channel state from party B
    pub fn build_cooperative_close_message(
        &self,
        channel_addr: &MsgAddress,
        signed_state_a: &SignedSemiChannel,
        signed_state_b: &SignedSemiChannel,
    ) -> PaymentResult<Cell> {
        let body = build_cooperative_close_body(signed_state_a, signed_state_b)?;
        build_internal_message(channel_addr, 0, body, true)
    }

    /// Build a start uncooperative close message.
    ///
    /// # Arguments
    /// * `channel_addr` - Address of the payment channel contract
    /// * `signed_state` - Our signed semi-channel state
    pub fn build_start_uncooperative_close_message(
        &self,
        channel_addr: &MsgAddress,
        signed_state: &SignedSemiChannel,
    ) -> PaymentResult<Cell> {
        let body = build_start_uncooperative_close_body(signed_state)?;
        build_internal_message(channel_addr, 0, body, true)
    }

    /// Build a challenge state message.
    ///
    /// # Arguments
    /// * `channel_addr` - Address of the payment channel contract
    /// * `newer_signed_state` - A signed state with higher seqno
    pub fn build_challenge_message(
        &self,
        channel_addr: &MsgAddress,
        newer_signed_state: &SignedSemiChannel,
    ) -> PaymentResult<Cell> {
        let body = build_challenge_state_body(newer_signed_state)?;
        build_internal_message(channel_addr, 0, body, true)
    }

    /// Build a settle conditionals message.
    ///
    /// # Arguments
    /// * `channel_addr` - Address of the payment channel contract
    /// * `from_a` - True to settle conditionals from party A
    /// * `conditionals` - The conditional payments to settle
    pub fn build_settle_conditionals_message(
        &self,
        channel_addr: &MsgAddress,
        from_a: bool,
        conditionals: &[ConditionalPayment],
    ) -> PaymentResult<Cell> {
        let body = build_settle_conditionals_body(from_a, conditionals)?;
        build_internal_message(channel_addr, 0, body, true)
    }

    /// Build a finish uncooperative close message.
    ///
    /// # Arguments
    /// * `channel_addr` - Address of the payment channel contract
    pub fn build_finish_uncooperative_close_message(
        &self,
        channel_addr: &MsgAddress,
    ) -> PaymentResult<Cell> {
        let body = build_finish_uncooperative_close_body()?;
        build_internal_message(channel_addr, 0, body, true)
    }

    /// Serialize a message cell to BoC bytes for sending.
    pub fn serialize_message(&self, message: &Cell) -> PaymentResult<Vec<u8>> {
        let boc = BagOfCells::from_root(message.clone());
        boc.serialize()
            .map_err(|e| PaymentError::CellError(e.to_string()))
    }
}

impl Default for OnchainChannelManager {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::SemiChannelBody;

    #[test]
    fn test_build_init_channel_body() {
        let body = build_init_channel_body(
            1_000_000_000,
            2_000_000_000,
            100_000_000,
            200_000_000,
        )
        .unwrap();

        assert!(body.bit_len() > 0);
    }

    #[test]
    fn test_build_top_up_body() {
        let body_a = build_top_up_body(true).unwrap();
        let body_b = build_top_up_body(false).unwrap();

        assert!(body_a.bit_len() > 0);
        assert!(body_b.bit_len() > 0);
    }

    #[test]
    fn test_build_cooperative_close_body() {
        let keypair_a = Ed25519Keypair::generate();
        let keypair_b = Ed25519Keypair::generate();

        let mut body_a = SemiChannelBody::new();
        body_a.seqno = 5;
        body_a.sent = 100;

        let mut body_b = SemiChannelBody::new();
        body_b.seqno = 3;
        body_b.sent = 50;

        let signed_a = SignedSemiChannel::new(&keypair_a, body_a);
        let signed_b = SignedSemiChannel::new(&keypair_b, body_b);

        let body = build_cooperative_close_body(&signed_a, &signed_b).unwrap();
        assert!(body.bit_len() > 0);
    }

    #[test]
    fn test_build_start_uncooperative_close_body() {
        let keypair = Ed25519Keypair::generate();

        let mut body = SemiChannelBody::new();
        body.seqno = 10;
        body.sent = 500;

        let signed = SignedSemiChannel::new(&keypair, body);
        let msg_body = build_start_uncooperative_close_body(&signed).unwrap();

        assert!(msg_body.bit_len() > 0);
    }

    #[test]
    fn test_build_challenge_state_body() {
        let keypair = Ed25519Keypair::generate();

        let mut body = SemiChannelBody::new();
        body.seqno = 20;
        body.sent = 1000;

        let signed = SignedSemiChannel::new(&keypair, body);
        let msg_body = build_challenge_state_body(&signed).unwrap();

        assert!(msg_body.bit_len() > 0);
    }

    #[test]
    fn test_build_settle_conditionals_body() {
        let hash_lock = ton_crypto::sha256(b"secret");
        let conditional = ConditionalPayment::new(100, hash_lock, 3600);

        let body = build_settle_conditionals_body(true, &[conditional]).unwrap();
        assert!(body.bit_len() > 0);
    }

    #[test]
    fn test_build_finish_uncooperative_close_body() {
        let body = build_finish_uncooperative_close_body().unwrap();
        assert!(body.bit_len() > 0);
    }

    #[test]
    fn test_build_internal_message() {
        let dest = MsgAddress::Internal {
            workchain: 0,
            address: [0xAB; 32],
        };

        let body = build_init_channel_body(1000, 2000, 0, 0).unwrap();
        let message = build_internal_message(&dest, 1_000_000_000, body, true).unwrap();

        assert!(message.bit_len() > 0);
    }

    #[test]
    fn test_onchain_channel_state_from_i64() {
        assert_eq!(
            OnchainChannelState::from_i64(0),
            Some(OnchainChannelState::Uninitialized)
        );
        assert_eq!(
            OnchainChannelState::from_i64(1),
            Some(OnchainChannelState::Open)
        );
        assert_eq!(
            OnchainChannelState::from_i64(2),
            Some(OnchainChannelState::ClosureStarted)
        );
        assert_eq!(
            OnchainChannelState::from_i64(3),
            Some(OnchainChannelState::Quarantine)
        );
        assert_eq!(
            OnchainChannelState::from_i64(4),
            Some(OnchainChannelState::Settled)
        );
        assert_eq!(OnchainChannelState::from_i64(5), None);
    }

    #[test]
    fn test_onchain_channel_manager_new() {
        let manager = OnchainChannelManager::new();
        assert!(manager.keypair().is_none());
        assert!(manager.wallet_address().is_none());
    }

    #[test]
    fn test_onchain_channel_manager_with_keypair() {
        let keypair = Ed25519Keypair::generate();
        let wallet_addr = MsgAddress::Internal {
            workchain: 0,
            address: keypair.public_key,
        };

        let manager = OnchainChannelManager::with_keypair(keypair.clone(), wallet_addr.clone());
        assert!(manager.keypair().is_some());
        assert!(manager.wallet_address().is_some());
    }

    #[test]
    fn test_manager_build_init_message() {
        let manager = OnchainChannelManager::new();
        let channel_addr = MsgAddress::Internal {
            workchain: 0,
            address: [0xCD; 32],
        };

        let message = manager
            .build_init_message(&channel_addr, 2_000_000_000, 1_000_000_000, 1_000_000_000, 0, 0)
            .unwrap();

        assert!(message.bit_len() > 0);

        // Serialize to BoC
        let boc = manager.serialize_message(&message).unwrap();
        assert!(!boc.is_empty());
    }

    #[test]
    fn test_manager_build_cooperative_close_message() {
        let keypair_a = Ed25519Keypair::generate();
        let keypair_b = Ed25519Keypair::generate();

        let mut body_a = SemiChannelBody::new();
        body_a.seqno = 5;
        body_a.sent = 100;

        let mut body_b = SemiChannelBody::new();
        body_b.seqno = 3;
        body_b.sent = 50;

        let signed_a = SignedSemiChannel::new(&keypair_a, body_a);
        let signed_b = SignedSemiChannel::new(&keypair_b, body_b);

        let manager = OnchainChannelManager::new();
        let channel_addr = MsgAddress::Internal {
            workchain: 0,
            address: [0xEF; 32],
        };

        let message = manager
            .build_cooperative_close_message(&channel_addr, &signed_a, &signed_b)
            .unwrap();

        assert!(message.bit_len() > 0);
    }
}
