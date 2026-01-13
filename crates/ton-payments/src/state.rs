//! Signed state types for TON Payment Channels.
//!
//! This module provides structures for signed channel states that can be
//! exchanged between parties and submitted on-chain for dispute resolution.

use crate::conditional::ConditionalPayment;
use crate::error::{PaymentError, PaymentResult};
use std::collections::HashMap;
use std::sync::Arc;
use ton_cell::{Cell, CellBuilder, CellSlice};
use ton_crypto::{sha256, verify_signature, Ed25519Keypair};

/// State commitment containing both signatures from parties A and B
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateCommitment {
    /// SHA256 hash of the serialized state
    pub state_hash: [u8; 32],
    /// Party A's signature on the state hash
    pub signature_a: [u8; 64],
    /// Party B's signature on the state hash
    pub signature_b: [u8; 64],
}

impl StateCommitment {
    /// Create a new state commitment with both signatures
    pub fn new(state_hash: [u8; 32], signature_a: [u8; 64], signature_b: [u8; 64]) -> Self {
        Self {
            state_hash,
            signature_a,
            signature_b,
        }
    }

    /// Verify the commitment against both parties' public keys
    pub fn verify(&self, pk_a: &[u8; 32], pk_b: &[u8; 32]) -> PaymentResult<()> {
        verify_signature(pk_a, &self.state_hash, &self.signature_a)
            .map_err(|_| PaymentError::CommitmentVerificationFailed(
                "Party A signature verification failed".to_string()
            ))?;

        verify_signature(pk_b, &self.state_hash, &self.signature_b)
            .map_err(|_| PaymentError::CommitmentVerificationFailed(
                "Party B signature verification failed".to_string()
            ))?;

        Ok(())
    }
}

/// Merkle tree for conditional payments
#[derive(Debug, Clone)]
pub struct ConditionalsMerkleTree {
    /// Root hash of the merkle tree
    pub root: [u8; 32],
    /// Ordered list of conditional hashes
    conditionals: Vec<[u8; 32]>,
}

impl ConditionalsMerkleTree {
    /// Build a merkle tree from conditional payments
    pub fn build(conditionals: &HashMap<[u8; 32], ConditionalPayment>) -> PaymentResult<Self> {
        if conditionals.is_empty() {
            // Empty tree: root is hash of empty data
            let root = sha256(&[]);
            return Ok(Self {
                root,
                conditionals: Vec::new(),
            });
        }

        // Sort conditional hashes for determinism
        let mut hashes: Vec<[u8; 32]> = conditionals.keys().copied().collect();
        hashes.sort();

        let root = Self::build_merkle_tree(&hashes);

        Ok(Self {
            root,
            conditionals: hashes,
        })
    }

    /// Build merkle tree from sorted hashes
    fn build_merkle_tree(hashes: &[[u8; 32]]) -> [u8; 32] {
        if hashes.is_empty() {
            return sha256(&[]);
        }

        if hashes.len() == 1 {
            return hashes[0];
        }

        let mut current_level: Vec<[u8; 32]> = hashes.to_vec();

        while current_level.len() > 1 {
            let mut next_level = Vec::new();

            for i in (0..current_level.len()).step_by(2) {
                let left = current_level[i];
                let right = if i + 1 < current_level.len() {
                    current_level[i + 1]
                } else {
                    left // Duplicate if odd number of elements
                };

                let mut combined = Vec::with_capacity(64);
                combined.extend_from_slice(&left);
                combined.extend_from_slice(&right);
                let parent = sha256(&combined);
                next_level.push(parent);
            }

            current_level = next_level;
        }

        current_level[0]
    }

    /// Verify a conditional is in the tree
    pub fn verify_conditional(&self, conditional_hash: [u8; 32]) -> PaymentResult<()> {
        if self.conditionals.contains(&conditional_hash) {
            Ok(())
        } else {
            Err(PaymentError::InvalidMerkleProof)
        }
    }

    /// Get the merkle root
    pub fn get_root(&self) -> [u8; 32] {
        self.root
    }

    /// Serialize the merkle tree
    pub fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&self.root);
        data.extend_from_slice(&(self.conditionals.len() as u32).to_be_bytes());
        for hash in &self.conditionals {
            data.extend_from_slice(hash);
        }
        data
    }

    /// Deserialize a merkle tree
    pub fn deserialize(data: &[u8]) -> PaymentResult<Self> {
        if data.len() < 36 {
            return Err(PaymentError::StateHistoryError(
                "Data too short for merkle tree".to_string()
            ));
        }

        let mut root = [0u8; 32];
        root.copy_from_slice(&data[0..32]);

        let count = u32::from_be_bytes(data[32..36].try_into().unwrap()) as usize;

        let expected_len = 36 + count * 32;
        if data.len() < expected_len {
            return Err(PaymentError::StateHistoryError(
                "Data too short for conditionals".to_string()
            ));
        }

        let mut conditionals = Vec::new();
        for i in 0..count {
            let offset = 36 + i * 32;
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&data[offset..offset + 32]);
            conditionals.push(hash);
        }

        Ok(Self {
            root,
            conditionals,
        })
    }
}

/// Accepted state in history
#[derive(Debug, Clone)]
pub struct AcceptedState {
    /// Sequence number
    pub seqno: u64,
    /// State hash
    pub state_hash: [u8; 32],
    /// State commitment
    pub commitment: StateCommitment,
    /// Block height when accepted
    pub accepted_at_block: u32,
    /// Timestamp when accepted
    pub accepted_at_time: u32,
}

impl AcceptedState {
    /// Create a new accepted state
    pub fn new(
        seqno: u64,
        state_hash: [u8; 32],
        commitment: StateCommitment,
        accepted_at_block: u32,
        accepted_at_time: u32,
    ) -> Self {
        Self {
            seqno,
            state_hash,
            commitment,
            accepted_at_block,
            accepted_at_time,
        }
    }
}

/// Immutable state history for dispute resolution
#[derive(Debug, Clone)]
pub struct StateHistory {
    /// Immutable history of accepted states
    states: Vec<AcceptedState>,
}

impl StateHistory {
    /// Create a new empty state history
    pub fn new() -> Self {
        Self {
            states: Vec::new(),
        }
    }

    /// Add a state to history
    pub fn add_state(&mut self, state: AcceptedState) -> PaymentResult<()> {
        // Verify monotonicity
        if !self.states.is_empty() {
            let last = &self.states[self.states.len() - 1];

            // Seqno must be greater
            if state.seqno <= last.seqno {
                return Err(PaymentError::StateNotNewer {
                    current: last.seqno,
                    provided: state.seqno,
                });
            }

            // Hash must be different
            if state.state_hash == last.state_hash {
                return Err(PaymentError::DuplicateState);
            }

            // Block height must increase
            if state.accepted_at_block <= last.accepted_at_block {
                return Err(PaymentError::BlockHeightNotIncreasing {
                    last: last.accepted_at_block,
                    current: state.accepted_at_block,
                });
            }
        }

        self.states.push(state);
        Ok(())
    }

    /// Get a state by seqno
    pub fn get_state(&self, seqno: u64) -> Option<&AcceptedState> {
        self.states.iter().find(|s| s.seqno == seqno)
    }

    /// Get the last state
    pub fn last_state(&self) -> Option<&AcceptedState> {
        self.states.last()
    }

    /// Verify the entire history is valid
    pub fn verify_progression(&self) -> PaymentResult<()> {
        for i in 1..self.states.len() {
            let prev = &self.states[i - 1];
            let curr = &self.states[i];

            // Seqno must increase
            if curr.seqno <= prev.seqno {
                return Err(PaymentError::StateNotNewer {
                    current: prev.seqno,
                    provided: curr.seqno,
                });
            }

            // Hash must differ
            if curr.state_hash == prev.state_hash {
                return Err(PaymentError::DuplicateState);
            }

            // Block height must increase
            if curr.accepted_at_block <= prev.accepted_at_block {
                return Err(PaymentError::BlockHeightNotIncreasing {
                    last: prev.accepted_at_block,
                    current: curr.accepted_at_block,
                });
            }
        }

        Ok(())
    }

    /// Get all states
    pub fn states(&self) -> &[AcceptedState] {
        &self.states
    }

    /// Get state count
    pub fn len(&self) -> usize {
        self.states.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.states.is_empty()
    }
}

impl Default for StateHistory {
    fn default() -> Self {
        Self::new()
    }
}

/// Tag for SemiChannel in TL-B format (official TON).
/// ```tlb
/// semichannel_state#43685374
///   channel_id:uint128
///   data:SemiChannelBody
///   counterparty_data:(Maybe ^SemiChannelBody)
///   = SemiChannel;
/// ```
pub const SEMI_CHANNEL_TAG: u32 = 0x43685374;

/// A semi-channel state according to the official TON TL-B schema.
///
/// ```tlb
/// semichannel_state#43685374
///   channel_id:uint128
///   data:SemiChannelBody
///   counterparty_data:(Maybe ^SemiChannelBody)
///   = SemiChannel;
/// ```
///
/// This structure represents a uni-directional payment channel state,
/// containing our own state (`data`) and optionally the counterparty's
/// last known state (`counterparty_data`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SemiChannel {
    /// Unique channel identifier (128 bits).
    pub channel_id: u128,

    /// Our semi-channel body data.
    pub data: SemiChannelBody,

    /// Counterparty's semi-channel body data (optional).
    /// Stored as a reference cell in TL-B format.
    pub counterparty_data: Option<Box<SemiChannelBody>>,
}

impl SemiChannel {
    /// Create a new SemiChannel with no counterparty data.
    pub fn new(channel_id: u128, data: SemiChannelBody) -> Self {
        Self {
            channel_id,
            data,
            counterparty_data: None,
        }
    }

    /// Create a new SemiChannel with counterparty data.
    pub fn with_counterparty(
        channel_id: u128,
        data: SemiChannelBody,
        counterparty_data: SemiChannelBody,
    ) -> Self {
        Self {
            channel_id,
            data,
            counterparty_data: Some(Box::new(counterparty_data)),
        }
    }

    /// Set the counterparty data.
    pub fn set_counterparty_data(&mut self, counterparty_data: SemiChannelBody) {
        self.counterparty_data = Some(Box::new(counterparty_data));
    }

    /// Clear the counterparty data.
    pub fn clear_counterparty_data(&mut self) {
        self.counterparty_data = None;
    }

    /// Check if counterparty data is present.
    pub fn has_counterparty_data(&self) -> bool {
        self.counterparty_data.is_some()
    }

    /// Serialize the SemiChannel to bytes.
    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Channel ID: 16 bytes
        bytes.extend_from_slice(&self.channel_id.to_be_bytes());

        // Data: serialize the SemiChannelBody
        let data_bytes = self.data.serialize();
        bytes.extend_from_slice(&(data_bytes.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&data_bytes);

        // Counterparty data: Maybe format (1 byte flag + optional data)
        if let Some(ref counterparty) = self.counterparty_data {
            bytes.push(1); // Has counterparty data
            let counterparty_bytes = counterparty.serialize();
            bytes.extend_from_slice(&(counterparty_bytes.len() as u32).to_be_bytes());
            bytes.extend_from_slice(&counterparty_bytes);
        } else {
            bytes.push(0); // No counterparty data
        }

        bytes
    }

    /// Deserialize a SemiChannel from bytes.
    pub fn deserialize(data: &[u8]) -> PaymentResult<Self> {
        if data.len() < 21 {
            return Err(PaymentError::DeserializationError(
                "Data too short for SemiChannel".to_string(),
            ));
        }

        let mut offset = 0;

        // Channel ID: 16 bytes
        let channel_id = u128::from_be_bytes(data[offset..offset + 16].try_into().unwrap());
        offset += 16;

        // Data length: 4 bytes
        let data_len = u32::from_be_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;

        if data.len() < offset + data_len + 1 {
            return Err(PaymentError::DeserializationError(
                "Data too short for SemiChannelBody".to_string(),
            ));
        }

        // Data: SemiChannelBody
        let body = SemiChannelBody::deserialize(&data[offset..offset + data_len])?;
        offset += data_len;

        // Counterparty data flag: 1 byte
        let has_counterparty = data[offset] != 0;
        offset += 1;

        let counterparty_data = if has_counterparty {
            if data.len() < offset + 4 {
                return Err(PaymentError::DeserializationError(
                    "Data too short for counterparty length".to_string(),
                ));
            }

            let counterparty_len =
                u32::from_be_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
            offset += 4;

            if data.len() < offset + counterparty_len {
                return Err(PaymentError::DeserializationError(
                    "Data too short for counterparty data".to_string(),
                ));
            }

            let counterparty = SemiChannelBody::deserialize(&data[offset..offset + counterparty_len])?;
            Some(Box::new(counterparty))
        } else {
            None
        };

        Ok(Self {
            channel_id,
            data: body,
            counterparty_data,
        })
    }

    /// Calculate the hash of this SemiChannel.
    pub fn hash(&self) -> [u8; 32] {
        sha256(&self.serialize())
    }

    /// Serialize to a TON Cell for on-chain submission.
    ///
    /// Cell format (official TON TL-B):
    /// ```tlb
    /// semichannel_state#43685374
    ///   channel_id:uint128
    ///   data:SemiChannelBody
    ///   counterparty_data:(Maybe ^SemiChannelBody)
    ///   = SemiChannel;
    /// ```
    pub fn to_cell(&self) -> PaymentResult<Cell> {
        let mut builder = CellBuilder::new();

        // Store tag (32 bits) - official TON format
        builder
            .store_u32(SEMI_CHANNEL_TAG)
            .map_err(|e| PaymentError::CellError(e.to_string()))?;

        // Store channel_id (128 bits) as two 64-bit values (big-endian)
        let high = (self.channel_id >> 64) as u64;
        let low = self.channel_id as u64;
        builder
            .store_u64(high)
            .map_err(|e| PaymentError::CellError(e.to_string()))?;
        builder
            .store_u64(low)
            .map_err(|e| PaymentError::CellError(e.to_string()))?;

        // Store data as reference Cell (^SemiChannelBody)
        let data_cell = self.data.to_cell()?;
        builder
            .store_ref(Arc::new(data_cell))
            .map_err(|e| PaymentError::CellError(e.to_string()))?;

        // Store counterparty_data as Maybe ^SemiChannelBody
        if let Some(ref counterparty) = self.counterparty_data {
            // Maybe bit = 1 (has value)
            builder
                .store_bit(true)
                .map_err(|e| PaymentError::CellError(e.to_string()))?;

            // Store counterparty data as reference Cell
            let counterparty_cell = counterparty.to_cell()?;
            builder
                .store_ref(Arc::new(counterparty_cell))
                .map_err(|e| PaymentError::CellError(e.to_string()))?;
        } else {
            // Maybe bit = 0 (no value)
            builder
                .store_bit(false)
                .map_err(|e| PaymentError::CellError(e.to_string()))?;
        }

        builder
            .build()
            .map_err(|e| PaymentError::CellError(e.to_string()))
    }

    /// Deserialize from a TON Cell.
    ///
    /// Expects the official TON TL-B format:
    /// ```tlb
    /// semichannel_state#43685374
    ///   channel_id:uint128
    ///   data:SemiChannelBody
    ///   counterparty_data:(Maybe ^SemiChannelBody)
    ///   = SemiChannel;
    /// ```
    pub fn from_cell(cell: &Cell) -> PaymentResult<Self> {
        let mut slice = CellSlice::new(cell);

        // Load and verify tag (32 bits)
        let tag = slice
            .load_u32()
            .map_err(|e| PaymentError::CellError(e.to_string()))?;

        if tag != SEMI_CHANNEL_TAG {
            return Err(PaymentError::CellError(format!(
                "Invalid SemiChannel tag: expected 0x{:08x}, got 0x{:08x}",
                SEMI_CHANNEL_TAG, tag
            )));
        }

        // Load channel_id (128 bits) from two 64-bit values (big-endian)
        let high = slice
            .load_u64()
            .map_err(|e| PaymentError::CellError(e.to_string()))?;
        let low = slice
            .load_u64()
            .map_err(|e| PaymentError::CellError(e.to_string()))?;
        let channel_id = ((high as u128) << 64) | (low as u128);

        // Load data from reference Cell
        let data_cell = slice
            .load_ref()
            .map_err(|e| PaymentError::CellError(e.to_string()))?;
        let data = SemiChannelBody::from_cell(data_cell)?;

        // Load counterparty_data (Maybe ^SemiChannelBody)
        let has_counterparty = slice
            .load_bit()
            .map_err(|e| PaymentError::CellError(e.to_string()))?;

        let counterparty_data = if has_counterparty {
            let counterparty_cell = slice
                .load_ref()
                .map_err(|e| PaymentError::CellError(e.to_string()))?;
            let counterparty = SemiChannelBody::from_cell(counterparty_cell)?;
            Some(Box::new(counterparty))
        } else {
            None
        };

        Ok(Self {
            channel_id,
            data,
            counterparty_data,
        })
    }
}


/// A semi-channel body containing the state of one direction of payments.
///
/// # Official On-Chain TL-B Schema
///
/// The official on-chain format is:
/// ```tlb
/// semi_channel_body$_ seqno:uint64 sent:Coins conditionals:HashmapE 32 ConditionalPayment = SemiChannelBody;
/// ```
///
/// # Off-Chain Extension (tonnet-lib)
///
/// **IMPORTANT**: This implementation extends the official schema with additional
/// fields for off-chain replay attack protection:
/// - `channel_id`: Binds state to specific channel instance
/// - `block_height`: Blockchain context for temporal ordering
/// - `challenge`: Unique challenge per channel instance
///
/// These fields are used exclusively for off-chain state management and signature
/// verification. When submitting states on-chain for dispute resolution, only
/// the standard fields (seqno, sent, conditionals) are serialized to Cell format.
///
/// See [`to_cell()`] for on-chain compatible serialization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemiChannelBody {
    /// Monotonically increasing sequence number.
    /// Each state update must have a higher seqno than the previous one.
    pub seqno: u64,

    /// Total unconditional amount sent through this semi-channel.
    /// This only increases - you cannot "unsend" funds.
    pub sent: u128,

    /// Hash-locked conditional payments pending in this semi-channel.
    /// Key is the SHA256 hash of the condition (usually hash of preimage).
    /// This is stored in counterparty_data Cell on-chain.
    pub conditionals: HashMap<[u8; 32], ConditionalPayment>,

    /// Unique channel identifier for replay protection.
    /// Binds this state to a specific channel instance.
    pub channel_id: u128,

    /// Blockchain block height for temporal ordering.
    /// Prevents replaying old states from different blockchain heights.
    pub block_height: u32,

    /// Unique challenge bound to this channel instance.
    /// Generated randomly when channel is created.
    pub challenge: [u8; 32],
}

impl SemiChannelBody {
    /// Create a new empty semi-channel body with replay protection.
    pub fn new() -> Self {
        Self {
            seqno: 0,
            sent: 0,
            conditionals: HashMap::new(),
            channel_id: 0,
            block_height: 0,
            challenge: [0u8; 32],
        }
    }

    /// Create a new semi-channel body with replay protection context.
    pub fn with_replay_protection(channel_id: u128, block_height: u32, challenge: [u8; 32]) -> Self {
        Self {
            seqno: 0,
            sent: 0,
            conditionals: HashMap::new(),
            channel_id,
            block_height,
            challenge,
        }
    }

    /// Serialize the semi-channel body for signing.
    ///
    /// The serialization format includes (in order):
    /// - seqno (8 bytes, big-endian)
    /// - sent amount (16 bytes, big-endian)
    /// - number of conditionals (4 bytes, big-endian)
    /// - for each conditional: hash (32 bytes) + serialized conditional
    /// - channel_id (16 bytes, big-endian) - for replay protection
    /// - block_height (4 bytes, big-endian) - for temporal ordering
    /// - challenge (32 bytes) - unique per channel instance
    pub fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::new();

        // Seqno: 8 bytes
        data.extend_from_slice(&self.seqno.to_be_bytes());

        // Sent amount: 16 bytes
        data.extend_from_slice(&self.sent.to_be_bytes());

        // Number of conditionals: 4 bytes
        data.extend_from_slice(&(self.conditionals.len() as u32).to_be_bytes());

        // Serialize each conditional (sorted by hash for determinism)
        let mut conditionals: Vec<_> = self.conditionals.iter().collect();
        conditionals.sort_by_key(|(hash, _)| *hash);

        for (hash, conditional) in conditionals {
            data.extend_from_slice(hash);
            data.extend_from_slice(&conditional.serialize());
        }

        // Replay protection fields
        // Channel ID: 16 bytes
        data.extend_from_slice(&self.channel_id.to_be_bytes());

        // Block height: 4 bytes
        data.extend_from_slice(&self.block_height.to_be_bytes());

        // Challenge: 32 bytes
        data.extend_from_slice(&self.challenge);

        data
    }

    /// Deserialize a semi-channel body from bytes.
    ///
    /// Expected format:
    /// - seqno (8 bytes)
    /// - sent (16 bytes)
    /// - num_conditionals (4 bytes)
    /// - conditionals (variable)
    /// - channel_id (16 bytes)
    /// - block_height (4 bytes)
    /// - challenge (32 bytes)
    pub fn deserialize(data: &[u8]) -> PaymentResult<Self> {
        if data.len() < 28 {
            return Err(PaymentError::DeserializationError(
                "Data too short for SemiChannelBody".to_string(),
            ));
        }

        let seqno = u64::from_be_bytes(data[0..8].try_into().unwrap());
        let sent = u128::from_be_bytes(data[8..24].try_into().unwrap());
        let num_conditionals = u32::from_be_bytes(data[24..28].try_into().unwrap()) as usize;

        let mut offset = 28;
        let mut conditionals = HashMap::new();

        for _ in 0..num_conditionals {
            if data.len() < offset + 32 {
                return Err(PaymentError::DeserializationError(
                    "Data too short for conditional hash".to_string(),
                ));
            }

            let mut hash = [0u8; 32];
            hash.copy_from_slice(&data[offset..offset + 32]);
            offset += 32;

            let (conditional, consumed) = ConditionalPayment::deserialize(&data[offset..])?;
            offset += consumed;

            conditionals.insert(hash, conditional);
        }

        // Deserialize replay protection fields
        if data.len() < offset + 52 {
            return Err(PaymentError::DeserializationError(
                "Data too short for replay protection fields (need 52 bytes)".to_string(),
            ));
        }

        let channel_id = u128::from_be_bytes(data[offset..offset + 16].try_into().unwrap());
        offset += 16;

        let block_height = u32::from_be_bytes(data[offset..offset + 4].try_into().unwrap());
        offset += 4;

        let mut challenge = [0u8; 32];
        challenge.copy_from_slice(&data[offset..offset + 32]);

        Ok(Self {
            seqno,
            sent,
            conditionals,
            channel_id,
            block_height,
            challenge,
        })
    }

    /// Calculate the hash of this semi-channel body.
    pub fn hash(&self) -> [u8; 32] {
        sha256(&self.serialize())
    }

    /// Get the total pending conditional amount.
    pub fn total_conditional_amount(&self) -> u128 {
        self.conditionals.values().map(|c| c.amount).sum()
    }

    /// Serialize to a TON Cell for on-chain submission.
    ///
    /// Cell format (official TON TL-B):
    /// ```tlb
    /// semi_channel#43685374 seqno:uint64 sent:Coins counterparty_data:^Cell = SemiChannel;
    /// ```
    ///
    /// The counterparty_data contains conditionals in HashmapE format.
    pub fn to_cell(&self) -> PaymentResult<Cell> {
        let mut builder = CellBuilder::new();

        // Store tag (32 bits) - official TON format
        builder
            .store_u32(SEMI_CHANNEL_TAG)
            .map_err(|e| PaymentError::CellError(e.to_string()))?;

        // Store seqno (64 bits)
        builder
            .store_u64(self.seqno)
            .map_err(|e| PaymentError::CellError(e.to_string()))?;

        // Store sent amount (Coins format)
        builder
            .store_coins(self.sent)
            .map_err(|e| PaymentError::CellError(e.to_string()))?;

        // Store counterparty_data as reference Cell
        // This contains the conditionals hashmap
        let counterparty_data = self.build_counterparty_data_cell()?;
        builder
            .store_ref(Arc::new(counterparty_data))
            .map_err(|e| PaymentError::CellError(e.to_string()))?;

        builder
            .build()
            .map_err(|e| PaymentError::CellError(e.to_string()))
    }

    /// Build the counterparty_data Cell containing conditionals.
    fn build_counterparty_data_cell(&self) -> PaymentResult<Cell> {
        let mut builder = CellBuilder::new();

        // Store conditionals as HashmapE 32
        if self.conditionals.is_empty() {
            // Empty hashmap - just a 0 bit
            builder
                .store_bit(false)
                .map_err(|e| PaymentError::CellError(e.to_string()))?;
        } else {
            // Non-empty hashmap - 1 bit followed by the hashmap root cell
            builder
                .store_bit(true)
                .map_err(|e| PaymentError::CellError(e.to_string()))?;

            let hashmap_cell = self.build_conditionals_hashmap()?;
            builder
                .store_ref(Arc::new(hashmap_cell))
                .map_err(|e| PaymentError::CellError(e.to_string()))?;
        }

        builder
            .build()
            .map_err(|e| PaymentError::CellError(e.to_string()))
    }

    /// Deserialize from a TON Cell.
    ///
    /// Expects the official TON TL-B format:
    /// ```tlb
    /// semi_channel#43685374 seqno:uint64 sent:Coins counterparty_data:^Cell = SemiChannel;
    /// ```
    pub fn from_cell(cell: &Cell) -> PaymentResult<Self> {
        let mut slice = CellSlice::new(cell);

        // Load and verify tag (32 bits)
        let tag = slice
            .load_u32()
            .map_err(|e| PaymentError::CellError(e.to_string()))?;

        if tag != SEMI_CHANNEL_TAG {
            return Err(PaymentError::CellError(format!(
                "Invalid SemiChannel tag: expected 0x{:08x}, got 0x{:08x}",
                SEMI_CHANNEL_TAG, tag
            )));
        }

        // Load seqno (64 bits)
        let seqno = slice
            .load_u64()
            .map_err(|e| PaymentError::CellError(e.to_string()))?;

        // Load sent amount (coins format)
        let sent = slice
            .load_coins()
            .map_err(|e| PaymentError::CellError(e.to_string()))?;

        // Load counterparty_data Cell
        let counterparty_data = slice
            .load_ref()
            .map_err(|e| PaymentError::CellError(e.to_string()))?;

        // Parse conditionals from counterparty_data
        let conditionals = Self::parse_counterparty_data(counterparty_data)?;

        Ok(Self {
            seqno,
            sent,
            conditionals,
            channel_id: 0,
            block_height: 0,
            challenge: [0u8; 32],
        })
    }

    /// Parse the counterparty_data Cell to extract conditionals.
    fn parse_counterparty_data(cell: &Cell) -> PaymentResult<HashMap<[u8; 32], ConditionalPayment>> {
        let mut slice = CellSlice::new(cell);

        // Load conditionals from HashmapE 32
        let has_conditionals = slice
            .load_bit()
            .map_err(|e| PaymentError::CellError(e.to_string()))?;

        if has_conditionals {
            let hashmap_cell = slice
                .load_ref()
                .map_err(|e| PaymentError::CellError(e.to_string()))?;
            Self::parse_conditionals_hashmap(hashmap_cell)
        } else {
            Ok(HashMap::new())
        }
    }

    /// Build a hashmap cell containing the conditional payments.
    ///
    /// This creates a simple serialized list structure for conditionals.
    /// In a full implementation, this would be a proper TON HashmapE.
    fn build_conditionals_hashmap(&self) -> PaymentResult<Cell> {
        // For simplicity, we serialize conditionals as a linked list of cells
        // Each cell: hash (256 bits) + conditional_cell_ref + optional next_ref
        let mut conditionals: Vec<_> = self.conditionals.iter().collect();
        conditionals.sort_by_key(|(hash, _)| *hash);

        let mut current_ref: Option<Arc<Cell>> = None;

        // Build from last to first (reverse order)
        for (hash, conditional) in conditionals.into_iter().rev() {
            let conditional_cell = conditional.to_cell()?;

            let mut builder = CellBuilder::new();

            // Store the hash key (256 bits)
            builder
                .store_bytes(hash)
                .map_err(|e| PaymentError::CellError(e.to_string()))?;

            // Store conditional as reference
            builder
                .store_ref(Arc::new(conditional_cell))
                .map_err(|e| PaymentError::CellError(e.to_string()))?;

            // Store next entry reference if exists
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
            .ok_or_else(|| PaymentError::CellError("Empty conditionals hashmap".to_string()))
    }

    /// Parse a hashmap cell back into conditional payments.
    fn parse_conditionals_hashmap(cell: &Cell) -> PaymentResult<HashMap<[u8; 32], ConditionalPayment>> {
        let mut conditionals = HashMap::new();
        let mut current_cell = cell;

        loop {
            let mut slice = CellSlice::new(current_cell);

            // Load hash key (256 bits = 32 bytes)
            let hash_bytes = slice
                .load_bytes(32)
                .map_err(|e| PaymentError::CellError(e.to_string()))?;
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&hash_bytes);

            // Load conditional from reference
            let conditional_cell = slice
                .load_ref()
                .map_err(|e| PaymentError::CellError(e.to_string()))?;
            let conditional = ConditionalPayment::from_cell(conditional_cell)?;

            conditionals.insert(hash, conditional);

            // Check for next entry
            if slice.refs_left() > 0 {
                current_cell = slice
                    .load_ref()
                    .map_err(|e| PaymentError::CellError(e.to_string()))?;
            } else {
                break;
            }
        }

        Ok(conditionals)
    }
}

impl Default for SemiChannelBody {
    fn default() -> Self {
        Self::new()
    }
}

/// A signed semi-channel state.
///
/// According to TON TL-B:
/// ```tlb
/// signed_semi_channel$_ sig:bits512 state:^SemiChannelBody = SignedSemiChannel;
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedSemiChannel {
    /// Ed25519 signature over the semi-channel body (64 bytes).
    pub signature: [u8; 64],

    /// The semi-channel body that was signed.
    pub state: SemiChannelBody,
}

impl SignedSemiChannel {
    /// Create a new signed semi-channel by signing the state.
    pub fn new(keypair: &Ed25519Keypair, state: SemiChannelBody) -> Self {
        let data = state.serialize();
        let signature = keypair.sign(&data);

        Self { signature, state }
    }

    /// Verify the signature against a public key.
    pub fn verify(&self, public_key: &[u8; 32]) -> PaymentResult<()> {
        let data = self.state.serialize();
        verify_signature(public_key, &data, &self.signature)
            .map_err(|_| PaymentError::SignatureVerificationFailed)
    }

    /// Verify the signature and replay protection context.
    ///
    /// Ensures:
    /// - Signature is valid
    /// - Channel ID matches expected value
    /// - Block height is monotonically increasing (or equal for first state)
    /// - Challenge matches expected value
    pub fn verify_with_replay_protection(
        &self,
        public_key: &[u8; 32],
        expected_channel_id: u128,
        expected_challenge: [u8; 32],
        last_block_height: u32,
    ) -> PaymentResult<()> {
        // Verify signature
        self.verify(public_key)?;

        // Verify channel ID
        if self.state.channel_id != expected_channel_id {
            return Err(PaymentError::InvalidChannelId {
                expected: expected_channel_id,
                actual: self.state.channel_id,
            });
        }

        // Verify block height is monotonically increasing
        // Allow block_height == last_block_height on first state (last_block_height == 0)
        if self.state.block_height < last_block_height ||
           (last_block_height > 0 && self.state.block_height <= last_block_height) {
            return Err(PaymentError::StateNotProgressing {
                current: last_block_height,
                provided: self.state.block_height,
            });
        }

        // Verify challenge matches
        if self.state.challenge != expected_challenge {
            return Err(PaymentError::InvalidChallenge);
        }

        Ok(())
    }


    /// Serialize for transmission.
    pub fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&self.signature);
        data.extend_from_slice(&self.state.serialize());
        data
    }

    /// Deserialize from bytes.
    pub fn deserialize(data: &[u8]) -> PaymentResult<Self> {
        if data.len() < 64 {
            return Err(PaymentError::DeserializationError(
                "Data too short for SignedSemiChannel".to_string(),
            ));
        }

        let mut signature = [0u8; 64];
        signature.copy_from_slice(&data[0..64]);

        let state = SemiChannelBody::deserialize(&data[64..])?;

        Ok(Self { signature, state })
    }

    /// Serialize to a TON Cell for on-chain submission.
    ///
    /// Cell format:
    /// ```tlb
    /// signed_semi_channel$_ sig:bits512 state:^SemiChannelBody = SignedSemiChannel;
    /// ```
    pub fn to_cell(&self) -> PaymentResult<Cell> {
        let state_cell = self.state.to_cell()?;

        let mut builder = CellBuilder::new();

        // Store signature (512 bits = 64 bytes)
        builder
            .store_bytes(&self.signature)
            .map_err(|e| PaymentError::CellError(e.to_string()))?;

        // Store state as reference
        builder
            .store_ref(Arc::new(state_cell))
            .map_err(|e| PaymentError::CellError(e.to_string()))?;

        builder
            .build()
            .map_err(|e| PaymentError::CellError(e.to_string()))
    }

    /// Deserialize from a TON Cell.
    pub fn from_cell(cell: &Cell) -> PaymentResult<Self> {
        let mut slice = CellSlice::new(cell);

        // Load signature (512 bits = 64 bytes)
        let sig_bytes = slice
            .load_bytes(64)
            .map_err(|e| PaymentError::CellError(e.to_string()))?;
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&sig_bytes);

        // Load state from reference
        let state_cell = slice
            .load_ref()
            .map_err(|e| PaymentError::CellError(e.to_string()))?;
        let state = SemiChannelBody::from_cell(state_cell)?;

        Ok(Self { signature, state })
    }
}

/// Full channel state containing both semi-channels.
///
/// This represents the complete state of a payment channel, including
/// both directions of payment. Both semi-channels are bound to the same
/// replay protection context.
#[derive(Debug, Clone)]
pub struct ChannelStateData {
    /// Channel identifier.
    pub channel_id: u128,

    /// Blockchain block height for temporal ordering.
    pub block_height: u32,

    /// Unique challenge bound to this channel instance.
    pub challenge: [u8; 32],

    /// State of semi-channel A (A -> B).
    pub semi_channel_a: SemiChannelBody,

    /// State of semi-channel B (B -> A).
    pub semi_channel_b: SemiChannelBody,
}

impl ChannelStateData {
    /// Create a new channel state.
    pub fn new(channel_id: u128) -> Self {
        Self {
            channel_id,
            block_height: 0,
            challenge: [0u8; 32],
            semi_channel_a: SemiChannelBody::new(),
            semi_channel_b: SemiChannelBody::new(),
        }
    }

    /// Create a new channel state with replay protection context.
    pub fn with_replay_protection(
        channel_id: u128,
        block_height: u32,
        challenge: [u8; 32],
    ) -> Self {
        let semi_channel_a = SemiChannelBody::with_replay_protection(channel_id, block_height, challenge);
        let semi_channel_b = SemiChannelBody::with_replay_protection(channel_id, block_height, challenge);

        Self {
            channel_id,
            block_height,
            challenge,
            semi_channel_a,
            semi_channel_b,
        }
    }

    /// Update block height and challenge in both semi-channels.
    pub fn update_replay_protection(&mut self, block_height: u32, challenge: [u8; 32]) {
        self.block_height = block_height;
        self.challenge = challenge;
        self.semi_channel_a.block_height = block_height;
        self.semi_channel_a.challenge = challenge;
        self.semi_channel_b.block_height = block_height;
        self.semi_channel_b.challenge = challenge;
    }

    /// Serialize the channel state.
    pub fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&self.channel_id.to_be_bytes());
        data.extend_from_slice(&self.block_height.to_be_bytes());
        data.extend_from_slice(&self.challenge);
        data.extend_from_slice(&self.semi_channel_a.serialize());
        data.extend_from_slice(&self.semi_channel_b.serialize());
        data
    }

    /// Calculate the hash of this channel state.
    pub fn hash(&self) -> [u8; 32] {
        sha256(&self.serialize())
    }
}

/// A fully signed channel state with signatures from both parties.
///
/// This can be submitted on-chain for cooperative close.
#[derive(Debug, Clone)]
pub struct SignedChannelState {
    /// Signature from party A.
    pub signature_a: [u8; 64],

    /// Signature from party B.
    pub signature_b: [u8; 64],

    /// The channel state that was signed.
    pub state: ChannelStateData,
}

impl SignedChannelState {
    /// Create a new signed channel state (requires both signatures).
    pub fn new(
        signature_a: [u8; 64],
        signature_b: [u8; 64],
        state: ChannelStateData,
    ) -> Self {
        Self {
            signature_a,
            signature_b,
            state,
        }
    }

    /// Sign the state as party A.
    pub fn sign_as_a(keypair: &Ed25519Keypair, state: &ChannelStateData) -> [u8; 64] {
        let data = state.serialize();
        keypair.sign(&data)
    }

    /// Sign the state as party B.
    pub fn sign_as_b(keypair: &Ed25519Keypair, state: &ChannelStateData) -> [u8; 64] {
        let data = state.serialize();
        keypair.sign(&data)
    }

    /// Verify both signatures.
    pub fn verify(
        &self,
        public_key_a: &[u8; 32],
        public_key_b: &[u8; 32],
    ) -> PaymentResult<()> {
        let data = self.state.serialize();

        verify_signature(public_key_a, &data, &self.signature_a)
            .map_err(|_| PaymentError::InvalidSignature("Party A signature invalid".to_string()))?;

        verify_signature(public_key_b, &data, &self.signature_b)
            .map_err(|_| PaymentError::InvalidSignature("Party B signature invalid".to_string()))?;

        Ok(())
    }

    /// Serialize for transmission.
    pub fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&self.signature_a);
        data.extend_from_slice(&self.signature_b);
        data.extend_from_slice(&self.state.serialize());
        data
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_semi_channel_body_new() {
        let body = SemiChannelBody::new();
        assert_eq!(body.seqno, 0);
        assert_eq!(body.sent, 0);
        assert!(body.conditionals.is_empty());
    }

    #[test]
    fn test_semi_channel_body_serialize_deserialize() {
        let mut body = SemiChannelBody::new();
        body.seqno = 42;
        body.sent = 1_000_000_000;

        let serialized = body.serialize();
        let deserialized = SemiChannelBody::deserialize(&serialized).unwrap();

        assert_eq!(body.seqno, deserialized.seqno);
        assert_eq!(body.sent, deserialized.sent);
        assert_eq!(body.conditionals.len(), deserialized.conditionals.len());
    }

    #[test]
    fn test_semi_channel_body_with_conditionals() {
        let mut body = SemiChannelBody::new();
        body.seqno = 1;
        body.sent = 500;

        let condition_hash = sha256(b"secret");
        let conditional = ConditionalPayment::new(100, condition_hash, 3600);
        body.conditionals.insert(condition_hash, conditional);

        let serialized = body.serialize();
        let deserialized = SemiChannelBody::deserialize(&serialized).unwrap();

        assert_eq!(body.seqno, deserialized.seqno);
        assert_eq!(body.sent, deserialized.sent);
        assert_eq!(body.conditionals.len(), deserialized.conditionals.len());
        assert!(deserialized.conditionals.contains_key(&condition_hash));
    }

    #[test]
    fn test_signed_semi_channel() {
        let keypair = Ed25519Keypair::generate();
        let mut body = SemiChannelBody::new();
        body.seqno = 1;
        body.sent = 100;

        let signed = SignedSemiChannel::new(&keypair, body.clone());

        // Verify with correct public key
        assert!(signed.verify(&keypair.public_key).is_ok());

        // Verify with wrong public key should fail
        let other_keypair = Ed25519Keypair::generate();
        assert!(signed.verify(&other_keypair.public_key).is_err());
    }

    #[test]
    fn test_signed_semi_channel_serialize_deserialize() {
        let keypair = Ed25519Keypair::generate();
        let mut body = SemiChannelBody::new();
        body.seqno = 5;
        body.sent = 1000;

        let signed = SignedSemiChannel::new(&keypair, body);
        let serialized = signed.serialize();
        let deserialized = SignedSemiChannel::deserialize(&serialized).unwrap();

        assert_eq!(signed.signature, deserialized.signature);
        assert_eq!(signed.state.seqno, deserialized.state.seqno);
        assert_eq!(signed.state.sent, deserialized.state.sent);
    }

    #[test]
    fn test_channel_state_data() {
        let state = ChannelStateData::new(12345);
        assert_eq!(state.channel_id, 12345);
        assert_eq!(state.semi_channel_a.seqno, 0);
        assert_eq!(state.semi_channel_b.seqno, 0);
    }

    #[test]
    fn test_signed_channel_state() {
        let keypair_a = Ed25519Keypair::generate();
        let keypair_b = Ed25519Keypair::generate();

        let mut state = ChannelStateData::new(999);
        state.semi_channel_a.seqno = 10;
        state.semi_channel_a.sent = 500;
        state.semi_channel_b.seqno = 8;
        state.semi_channel_b.sent = 300;

        let sig_a = SignedChannelState::sign_as_a(&keypair_a, &state);
        let sig_b = SignedChannelState::sign_as_b(&keypair_b, &state);

        let signed = SignedChannelState::new(sig_a, sig_b, state);

        // Verify with correct keys
        assert!(signed.verify(&keypair_a.public_key, &keypair_b.public_key).is_ok());

        // Verify with swapped keys should fail
        assert!(signed.verify(&keypair_b.public_key, &keypair_a.public_key).is_err());
    }

    #[test]
    fn test_total_conditional_amount() {
        let mut body = SemiChannelBody::new();

        // Add some conditionals
        let hash1 = sha256(b"secret1");
        let hash2 = sha256(b"secret2");

        body.conditionals.insert(hash1, ConditionalPayment::new(100, hash1, 3600));
        body.conditionals.insert(hash2, ConditionalPayment::new(200, hash2, 3600));

        assert_eq!(body.total_conditional_amount(), 300);
    }

    #[test]
    fn test_semi_channel_body_hash_deterministic() {
        let mut body = SemiChannelBody::new();
        body.seqno = 42;
        body.sent = 1000;

        let hash1 = body.hash();
        let hash2 = body.hash();

        assert_eq!(hash1, hash2);
    }

    // ========================================================================
    // Cell Serialization Tests
    // ========================================================================

    #[test]
    fn test_semi_channel_body_to_cell_from_cell_empty() {
        let body = SemiChannelBody::new();

        let cell = body.to_cell().unwrap();
        let deserialized = SemiChannelBody::from_cell(&cell).unwrap();

        assert_eq!(body.seqno, deserialized.seqno);
        assert_eq!(body.sent, deserialized.sent);
        assert!(deserialized.conditionals.is_empty());
    }

    #[test]
    fn test_semi_channel_body_to_cell_from_cell_with_data() {
        let mut body = SemiChannelBody::new();
        body.seqno = 42;
        body.sent = 1_000_000_000;

        let cell = body.to_cell().unwrap();
        let deserialized = SemiChannelBody::from_cell(&cell).unwrap();

        assert_eq!(body.seqno, deserialized.seqno);
        assert_eq!(body.sent, deserialized.sent);
    }

    #[test]
    fn test_semi_channel_body_to_cell_from_cell_with_conditionals() {
        let mut body = SemiChannelBody::new();
        body.seqno = 10;
        body.sent = 5000;

        let hash1 = sha256(b"secret1");
        let hash2 = sha256(b"secret2");

        body.conditionals
            .insert(hash1, ConditionalPayment::new(100, hash1, 3600));
        body.conditionals
            .insert(hash2, ConditionalPayment::new(200, hash2, 7200));

        let cell = body.to_cell().unwrap();
        let deserialized = SemiChannelBody::from_cell(&cell).unwrap();

        assert_eq!(body.seqno, deserialized.seqno);
        assert_eq!(body.sent, deserialized.sent);
        assert_eq!(body.conditionals.len(), deserialized.conditionals.len());

        // Check conditional values
        assert!(deserialized.conditionals.contains_key(&hash1));
        assert!(deserialized.conditionals.contains_key(&hash2));
        assert_eq!(deserialized.conditionals[&hash1].amount, 100);
        assert_eq!(deserialized.conditionals[&hash2].amount, 200);
    }

    #[test]
    fn test_signed_semi_channel_to_cell_from_cell() {
        let keypair = Ed25519Keypair::generate();
        let mut body = SemiChannelBody::new();
        body.seqno = 5;
        body.sent = 1000;

        let signed = SignedSemiChannel::new(&keypair, body);

        let cell = signed.to_cell().unwrap();
        let deserialized = SignedSemiChannel::from_cell(&cell).unwrap();

        assert_eq!(signed.signature, deserialized.signature);
        assert_eq!(signed.state.seqno, deserialized.state.seqno);
        assert_eq!(signed.state.sent, deserialized.state.sent);

        // Verify the deserialized signature still works
        assert!(deserialized.verify(&keypair.public_key).is_ok());
    }

    #[test]
    fn test_signed_semi_channel_to_cell_from_cell_with_conditionals() {
        let keypair = Ed25519Keypair::generate();
        let mut body = SemiChannelBody::new();
        body.seqno = 15;
        body.sent = 2500;

        let hash = sha256(b"my_secret");
        body.conditionals
            .insert(hash, ConditionalPayment::new(500, hash, 86400));

        let signed = SignedSemiChannel::new(&keypair, body);

        let cell = signed.to_cell().unwrap();
        let deserialized = SignedSemiChannel::from_cell(&cell).unwrap();

        assert_eq!(signed.signature, deserialized.signature);
        assert_eq!(signed.state.seqno, deserialized.state.seqno);
        assert_eq!(signed.state.sent, deserialized.state.sent);
        assert_eq!(
            signed.state.conditionals.len(),
            deserialized.state.conditionals.len()
        );
        assert!(deserialized.state.conditionals.contains_key(&hash));

        // Verify signature
        assert!(deserialized.verify(&keypair.public_key).is_ok());
    }

    // ========================================================================
    // Phase 2: State Commitment and Merkle Tree Tests
    // ========================================================================

    #[test]
    fn test_state_commitment_creation() {
        let keypair_a = Ed25519Keypair::generate();
        let keypair_b = Ed25519Keypair::generate();

        let state_hash = sha256(b"test_state");
        let sig_a = keypair_a.sign(b"test_state");
        let sig_b = keypair_b.sign(b"test_state");

        let commitment = StateCommitment::new(state_hash, sig_a, sig_b);

        assert_eq!(commitment.state_hash, state_hash);
        assert_eq!(commitment.signature_a, sig_a);
        assert_eq!(commitment.signature_b, sig_b);
    }

    #[test]
    fn test_state_commitment_verify_valid() {
        let keypair_a = Ed25519Keypair::generate();
        let keypair_b = Ed25519Keypair::generate();

        let state_hash = sha256(b"test_state");
        let sig_a = keypair_a.sign(&state_hash);
        let sig_b = keypair_b.sign(&state_hash);

        let commitment = StateCommitment::new(state_hash, sig_a, sig_b);

        assert!(commitment.verify(&keypair_a.public_key, &keypair_b.public_key).is_ok());
    }

    #[test]
    fn test_state_commitment_verify_invalid_signature_a() {
        let keypair_a = Ed25519Keypair::generate();
        let keypair_b = Ed25519Keypair::generate();

        let state_hash = sha256(b"test_state");
        let sig_a = keypair_a.sign(b"wrong_data");
        let sig_b = keypair_b.sign(&state_hash);

        let commitment = StateCommitment::new(state_hash, sig_a, sig_b);

        assert!(commitment.verify(&keypair_a.public_key, &keypair_b.public_key).is_err());
    }

    #[test]
    fn test_conditionals_merkle_tree_empty() {
        let conditionals = HashMap::new();

        let tree = ConditionalsMerkleTree::build(&conditionals).unwrap();

        // Empty tree should have hash of empty data as root
        let expected_root = sha256(&[]);
        assert_eq!(tree.get_root(), expected_root);
    }

    #[test]
    fn test_conditionals_merkle_tree_single() {
        let mut conditionals = HashMap::new();

        let hash = sha256(b"secret");
        conditionals.insert(hash, ConditionalPayment::new(100, hash, 3600));

        let tree = ConditionalsMerkleTree::build(&conditionals).unwrap();

        // Single element tree should have the element as root
        assert_eq!(tree.get_root(), hash);

        // Verify the conditional is in the tree
        assert!(tree.verify_conditional(hash).is_ok());
    }

    #[test]
    fn test_conditionals_merkle_tree_multiple() {
        let mut conditionals = HashMap::new();

        let hash1 = sha256(b"secret1");
        let hash2 = sha256(b"secret2");
        let hash3 = sha256(b"secret3");

        conditionals.insert(hash1, ConditionalPayment::new(100, hash1, 3600));
        conditionals.insert(hash2, ConditionalPayment::new(200, hash2, 3600));
        conditionals.insert(hash3, ConditionalPayment::new(300, hash3, 3600));

        let tree = ConditionalsMerkleTree::build(&conditionals).unwrap();

        // All conditionals should be verifiable
        assert!(tree.verify_conditional(hash1).is_ok());
        assert!(tree.verify_conditional(hash2).is_ok());
        assert!(tree.verify_conditional(hash3).is_ok());

        // Non-existent conditional should fail
        let fake_hash = sha256(b"fake");
        assert!(tree.verify_conditional(fake_hash).is_err());
    }

    #[test]
    fn test_conditionals_merkle_tree_serialize_deserialize() {
        let mut conditionals = HashMap::new();

        let hash1 = sha256(b"secret1");
        let hash2 = sha256(b"secret2");

        conditionals.insert(hash1, ConditionalPayment::new(100, hash1, 3600));
        conditionals.insert(hash2, ConditionalPayment::new(200, hash2, 3600));

        let tree_1 = ConditionalsMerkleTree::build(&conditionals).unwrap();
        let serialized = tree_1.serialize();
        let tree_2 = ConditionalsMerkleTree::deserialize(&serialized).unwrap();

        // Both trees should have same root
        assert_eq!(tree_1.get_root(), tree_2.get_root());

        // Both should verify same conditionals
        assert!(tree_2.verify_conditional(hash1).is_ok());
        assert!(tree_2.verify_conditional(hash2).is_ok());
    }

    #[test]
    fn test_accepted_state_creation() {
        let keypair_a = Ed25519Keypair::generate();
        let keypair_b = Ed25519Keypair::generate();

        let state_hash = sha256(b"state");
        let sig_a = keypair_a.sign(&state_hash);
        let sig_b = keypair_b.sign(&state_hash);
        let commitment = StateCommitment::new(state_hash, sig_a, sig_b);

        let state = AcceptedState::new(42, state_hash, commitment, 100, 1000);

        assert_eq!(state.seqno, 42);
        assert_eq!(state.state_hash, state_hash);
        assert_eq!(state.accepted_at_block, 100);
        assert_eq!(state.accepted_at_time, 1000);
    }

    #[test]
    fn test_state_history_empty() {
        let history = StateHistory::new();

        assert!(history.is_empty());
        assert_eq!(history.len(), 0);
        assert!(history.last_state().is_none());
    }

    #[test]
    fn test_state_history_add_single() {
        let mut history = StateHistory::new();

        let keypair_a = Ed25519Keypair::generate();
        let keypair_b = Ed25519Keypair::generate();

        let state_hash = sha256(b"state1");
        let sig_a = keypair_a.sign(&state_hash);
        let sig_b = keypair_b.sign(&state_hash);
        let commitment = StateCommitment::new(state_hash, sig_a, sig_b);

        let state = AcceptedState::new(1, state_hash, commitment, 100, 1000);

        assert!(history.add_state(state).is_ok());
        assert_eq!(history.len(), 1);
        assert!(history.last_state().is_some());
    }

    #[test]
    fn test_state_history_monotonicity_seqno() {
        let mut history = StateHistory::new();

        let keypair_a = Ed25519Keypair::generate();
        let keypair_b = Ed25519Keypair::generate();

        // Add state with seqno 1
        let state_hash_1 = sha256(b"state1");
        let sig_a = keypair_a.sign(&state_hash_1);
        let sig_b = keypair_b.sign(&state_hash_1);
        let commitment = StateCommitment::new(state_hash_1, sig_a, sig_b);
        let state = AcceptedState::new(1, state_hash_1, commitment, 100, 1000);
        assert!(history.add_state(state).is_ok());

        // Try to add state with same seqno
        let state_hash_2 = sha256(b"state2");
        let sig_a = keypair_a.sign(&state_hash_2);
        let sig_b = keypair_b.sign(&state_hash_2);
        let commitment = StateCommitment::new(state_hash_2, sig_a, sig_b);
        let state = AcceptedState::new(1, state_hash_2, commitment, 101, 1001);
        assert!(history.add_state(state).is_err());
    }

    #[test]
    fn test_state_history_monotonicity_hash() {
        let mut history = StateHistory::new();

        let keypair_a = Ed25519Keypair::generate();
        let keypair_b = Ed25519Keypair::generate();

        let state_hash = sha256(b"state");
        let sig_a = keypair_a.sign(&state_hash);
        let sig_b = keypair_b.sign(&state_hash);
        let commitment = StateCommitment::new(state_hash, sig_a, sig_b);

        // Add state with hash
        let state = AcceptedState::new(1, state_hash, commitment, 100, 1000);
        assert!(history.add_state(state).is_ok());

        // Try to add different seqno but same hash
        let sig_a = keypair_a.sign(&state_hash);
        let sig_b = keypair_b.sign(&state_hash);
        let commitment = StateCommitment::new(state_hash, sig_a, sig_b);
        let state = AcceptedState::new(2, state_hash, commitment, 101, 1001);
        assert!(history.add_state(state).is_err()); // Same hash not allowed
    }

    #[test]
    fn test_state_history_monotonicity_block_height() {
        let mut history = StateHistory::new();

        let keypair_a = Ed25519Keypair::generate();
        let keypair_b = Ed25519Keypair::generate();

        // Add state at block 100
        let state_hash_1 = sha256(b"state1");
        let sig_a = keypair_a.sign(&state_hash_1);
        let sig_b = keypair_b.sign(&state_hash_1);
        let commitment = StateCommitment::new(state_hash_1, sig_a, sig_b);
        let state = AcceptedState::new(1, state_hash_1, commitment, 100, 1000);
        assert!(history.add_state(state).is_ok());

        // Try to add state at same block height
        let state_hash_2 = sha256(b"state2");
        let sig_a = keypair_a.sign(&state_hash_2);
        let sig_b = keypair_b.sign(&state_hash_2);
        let commitment = StateCommitment::new(state_hash_2, sig_a, sig_b);
        let state = AcceptedState::new(2, state_hash_2, commitment, 100, 1001);
        assert!(history.add_state(state).is_err()); // Block height must increase
    }

    #[test]
    fn test_state_history_verify_progression() {
        let mut history = StateHistory::new();

        let keypair_a = Ed25519Keypair::generate();
        let keypair_b = Ed25519Keypair::generate();

        // Add three valid states
        for i in 1..=3 {
            let data = format!("state_{}", i);
            let hash = sha256(data.as_bytes());
            let sig_a = keypair_a.sign(&hash);
            let sig_b = keypair_b.sign(&hash);
            let commitment = StateCommitment::new(hash, sig_a, sig_b);

            let state = AcceptedState::new(i as u64, hash, commitment, 100 + i as u32, 1000 + i as u32);
            assert!(history.add_state(state).is_ok());
        }

        // Entire history should be valid
        assert!(history.verify_progression().is_ok());
    }

    #[test]
    fn test_state_history_get_state() {
        let mut history = StateHistory::new();

        let keypair_a = Ed25519Keypair::generate();
        let keypair_b = Ed25519Keypair::generate();

        let state_hash = sha256(b"state42");
        let sig_a = keypair_a.sign(&state_hash);
        let sig_b = keypair_b.sign(&state_hash);
        let commitment = StateCommitment::new(state_hash, sig_a, sig_b);

        let state = AcceptedState::new(42, state_hash, commitment, 100, 1000);
        history.add_state(state).unwrap();

        // Should find state by seqno
        let retrieved = history.get_state(42);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().seqno, 42);

        // Non-existent seqno should return None
        assert!(history.get_state(99).is_none());
    }

    #[test]
    fn test_state_history_default() {
        let history = StateHistory::default();
        assert!(history.is_empty());
        assert_eq!(history.len(), 0);
    }

    // ========================================================================
    // SemiChannel Tests (TL-B: semichannel_state#43685374)
    // ========================================================================

    #[test]
    fn test_semi_channel_new() {
        let data = SemiChannelBody::new();
        let semi_channel = SemiChannel::new(12345, data.clone());

        assert_eq!(semi_channel.channel_id, 12345);
        assert_eq!(semi_channel.data.seqno, data.seqno);
        assert!(semi_channel.counterparty_data.is_none());
    }

    #[test]
    fn test_semi_channel_with_counterparty() {
        let mut data = SemiChannelBody::new();
        data.seqno = 10;
        data.sent = 1000;

        let mut counterparty = SemiChannelBody::new();
        counterparty.seqno = 8;
        counterparty.sent = 500;

        let semi_channel = SemiChannel::with_counterparty(99999, data, counterparty.clone());

        assert_eq!(semi_channel.channel_id, 99999);
        assert!(semi_channel.counterparty_data.is_some());
        assert_eq!(semi_channel.counterparty_data.as_ref().unwrap().seqno, 8);
        assert_eq!(semi_channel.counterparty_data.as_ref().unwrap().sent, 500);
    }

    #[test]
    fn test_semi_channel_set_counterparty_data() {
        let data = SemiChannelBody::new();
        let mut semi_channel = SemiChannel::new(100, data);

        assert!(!semi_channel.has_counterparty_data());

        let mut counterparty = SemiChannelBody::new();
        counterparty.seqno = 5;
        counterparty.sent = 250;

        semi_channel.set_counterparty_data(counterparty);

        assert!(semi_channel.has_counterparty_data());
        assert_eq!(semi_channel.counterparty_data.as_ref().unwrap().seqno, 5);
    }

    #[test]
    fn test_semi_channel_clear_counterparty_data() {
        let data = SemiChannelBody::new();
        let counterparty = SemiChannelBody::new();
        let mut semi_channel = SemiChannel::with_counterparty(100, data, counterparty);

        assert!(semi_channel.has_counterparty_data());

        semi_channel.clear_counterparty_data();

        assert!(!semi_channel.has_counterparty_data());
        assert!(semi_channel.counterparty_data.is_none());
    }

    #[test]
    fn test_semi_channel_default() {
        let semi_channel = SemiChannel::default();

        assert_eq!(semi_channel.channel_id, 0);
        assert_eq!(semi_channel.data.seqno, 0);
        assert_eq!(semi_channel.data.sent, 0);
        assert!(semi_channel.counterparty_data.is_none());
    }

    #[test]
    fn test_semi_channel_serialize_deserialize_no_counterparty() {
        let mut data = SemiChannelBody::new();
        data.seqno = 42;
        data.sent = 1_000_000;

        let semi_channel = SemiChannel::new(12345678, data);

        let serialized = semi_channel.serialize();
        let deserialized = SemiChannel::deserialize(&serialized).unwrap();

        assert_eq!(semi_channel.channel_id, deserialized.channel_id);
        assert_eq!(semi_channel.data.seqno, deserialized.data.seqno);
        assert_eq!(semi_channel.data.sent, deserialized.data.sent);
        assert!(deserialized.counterparty_data.is_none());
    }

    #[test]
    fn test_semi_channel_serialize_deserialize_with_counterparty() {
        let mut data = SemiChannelBody::new();
        data.seqno = 100;
        data.sent = 5_000_000;

        let mut counterparty = SemiChannelBody::new();
        counterparty.seqno = 80;
        counterparty.sent = 3_000_000;

        let semi_channel = SemiChannel::with_counterparty(99887766, data, counterparty);

        let serialized = semi_channel.serialize();
        let deserialized = SemiChannel::deserialize(&serialized).unwrap();

        assert_eq!(semi_channel.channel_id, deserialized.channel_id);
        assert_eq!(semi_channel.data.seqno, deserialized.data.seqno);
        assert_eq!(semi_channel.data.sent, deserialized.data.sent);
        assert!(deserialized.counterparty_data.is_some());
        assert_eq!(
            semi_channel.counterparty_data.as_ref().unwrap().seqno,
            deserialized.counterparty_data.as_ref().unwrap().seqno
        );
        assert_eq!(
            semi_channel.counterparty_data.as_ref().unwrap().sent,
            deserialized.counterparty_data.as_ref().unwrap().sent
        );
    }

    #[test]
    fn test_semi_channel_hash_deterministic() {
        let mut data = SemiChannelBody::new();
        data.seqno = 10;
        data.sent = 500;

        let semi_channel = SemiChannel::new(123, data);

        let hash1 = semi_channel.hash();
        let hash2 = semi_channel.hash();

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_semi_channel_to_cell_from_cell_no_counterparty() {
        let mut data = SemiChannelBody::new();
        data.seqno = 55;
        data.sent = 2_500_000;

        let semi_channel = SemiChannel::new(987654321, data);

        let cell = semi_channel.to_cell().unwrap();
        let deserialized = SemiChannel::from_cell(&cell).unwrap();

        assert_eq!(semi_channel.channel_id, deserialized.channel_id);
        assert_eq!(semi_channel.data.seqno, deserialized.data.seqno);
        assert_eq!(semi_channel.data.sent, deserialized.data.sent);
        assert!(deserialized.counterparty_data.is_none());
    }

    #[test]
    fn test_semi_channel_to_cell_from_cell_with_counterparty() {
        let mut data = SemiChannelBody::new();
        data.seqno = 200;
        data.sent = 10_000_000;

        let mut counterparty = SemiChannelBody::new();
        counterparty.seqno = 150;
        counterparty.sent = 7_500_000;

        let semi_channel = SemiChannel::with_counterparty(111222333, data, counterparty);

        let cell = semi_channel.to_cell().unwrap();
        let deserialized = SemiChannel::from_cell(&cell).unwrap();

        assert_eq!(semi_channel.channel_id, deserialized.channel_id);
        assert_eq!(semi_channel.data.seqno, deserialized.data.seqno);
        assert_eq!(semi_channel.data.sent, deserialized.data.sent);
        assert!(deserialized.counterparty_data.is_some());
        assert_eq!(
            semi_channel.counterparty_data.as_ref().unwrap().seqno,
            deserialized.counterparty_data.as_ref().unwrap().seqno
        );
        assert_eq!(
            semi_channel.counterparty_data.as_ref().unwrap().sent,
            deserialized.counterparty_data.as_ref().unwrap().sent
        );
    }

    #[test]
    fn test_semi_channel_to_cell_from_cell_with_conditionals() {
        let mut data = SemiChannelBody::new();
        data.seqno = 50;
        data.sent = 1_000_000;

        let hash1 = sha256(b"condition1");
        data.conditionals
            .insert(hash1, ConditionalPayment::new(100, hash1, 3600));

        let mut counterparty = SemiChannelBody::new();
        counterparty.seqno = 40;
        counterparty.sent = 800_000;

        let hash2 = sha256(b"condition2");
        counterparty
            .conditionals
            .insert(hash2, ConditionalPayment::new(200, hash2, 7200));

        let semi_channel = SemiChannel::with_counterparty(555666777, data, counterparty);

        let cell = semi_channel.to_cell().unwrap();
        let deserialized = SemiChannel::from_cell(&cell).unwrap();

        assert_eq!(semi_channel.channel_id, deserialized.channel_id);
        assert_eq!(semi_channel.data.seqno, deserialized.data.seqno);
        assert_eq!(
            semi_channel.data.conditionals.len(),
            deserialized.data.conditionals.len()
        );
        assert!(deserialized.data.conditionals.contains_key(&hash1));

        assert!(deserialized.counterparty_data.is_some());
        assert_eq!(
            semi_channel.counterparty_data.as_ref().unwrap().conditionals.len(),
            deserialized.counterparty_data.as_ref().unwrap().conditionals.len()
        );
        assert!(deserialized
            .counterparty_data
            .as_ref()
            .unwrap()
            .conditionals
            .contains_key(&hash2));
    }
}
